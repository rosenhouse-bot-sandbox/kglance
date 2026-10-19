//go:build e2e

// Package e2e runs kglance setup and teardown against real clusters.
//
//	KGLANCE_E2E_MGMT_CONTEXT      admin context of a cluster with the CAPI CRDs
//	KGLANCE_E2E_WORKLOAD_CONTEXT  admin context of a workload cluster, which the test stores in a Cluster API kubeconfig Secret on mgmt
//	KGLANCE_E2E_IMAGE             collector image, already present on the workload nodes
//	KGLANCE_E2E_LISTENER_IMAGE    image with busybox httpd (default busybox:1.37)
//
// The admin kubeconfig comes from $KUBECONFIG or ~/.kube/config.
package e2e

import (
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	listenerNS   = "kglance-e2e"
	listenerPort = "18080"
)

var rowFields = []string{"cluster", "node", "role", "ts", "netns", "proto", "local", "peer", "state", "pid", "process", "pod", "container"}

type env struct {
	t                  *testing.T
	bin, dir           string
	mgmtCtx, wlCtx     string
	image, listenerImg string
}

func TestSetupAgentAccessTeardown(t *testing.T) {
	e := newEnv(t)
	e.putKubeconfigSecret()
	e.kglance("teardown", "--context", e.mgmtCtx, "--mgmt-namespace", listenerNS, "--workload", "wl1")
	t.Cleanup(func() {
		if t.Failed() {
			os.Remove(filepath.Join(e.dir, "kglance.state.json"))
			e.kglance("teardown", "--context", e.mgmtCtx, "--mgmt-namespace", listenerNS, "--workload", "wl1")
		}
		for _, ctx := range []string{e.mgmtCtx, e.wlCtx} {
			e.admin(ctx, "delete", "namespace", listenerNS, "--ignore-not-found", "--wait=false")
		}
	})
	e.startListener()

	out := e.mustKglance("setup", "--context", e.mgmtCtx, "--mgmt-namespace", listenerNS, "--workload", "wl1",
		"--ttl", "1h", "-o", "agent.kubeconfig", "--image", e.image, "--interval", "5s")
	nodes := e.nodes()
	cp := 0
	for _, role := range nodes {
		if role == "control-plane" {
			cp++
		}
	}
	for _, want := range []*regexp.Regexp{
		regexp.MustCompile(`wrote \S*agent\.kubeconfig \(contexts: mgmt, wl1; expires \d\d:\d\d UTC\)`),
		regexp.MustCompile(`wrote \S*kglance\.state\.json`),
		regexp.MustCompile(regexp.QuoteMeta(fmt.Sprintf("socket collector running on %d nodes (%d control-plane, %d worker)", len(nodes), cp, len(nodes)-cp))),
	} {
		if !want.MatchString(out) {
			t.Errorf("setup output lacks %q:\n%s", want, out)
		}
	}
	agentKC := filepath.Join(e.dir, "agent.kubeconfig")
	firstKC := e.copyFile(agentKC)

	t.Run("mgmt access", func(t *testing.T) {
		e.allowed(t, agentKC, "mgmt", "-n", listenerNS, "get", "clusters.cluster.x-k8s.io")
		e.allowed(t, agentKC, "mgmt", "-n", listenerNS, "get", "machines.cluster.x-k8s.io")
		e.allowed(t, agentKC, "mgmt", "-n", listenerNS, "get", "events")
		e.allowed(t, agentKC, "mgmt", "-n", listenerNS, "get", "pods,services,deployments")
		e.forbidden(t, agentKC, "mgmt", "get", "clusters.cluster.x-k8s.io", "-A")
		e.forbidden(t, agentKC, "mgmt", "-n", listenerNS, "get", "secrets")
		e.forbidden(t, agentKC, "mgmt", "-n", listenerNS, "logs", "x")
		e.forbidden(t, agentKC, "mgmt", "-n", listenerNS, "exec", "x", "--", "true")
		e.forbidden(t, agentKC, "mgmt", "-n", "kube-system", "get", "secret", "foo")
	})

	t.Run("workload access", func(t *testing.T) {
		e.allowed(t, agentKC, "wl1", "get", "pods", "-A")
		e.allowed(t, agentKC, "wl1", "get", "events", "-A")
		e.allowed(t, agentKC, "wl1", "get", "events.events.k8s.io", "-A")
		e.forbidden(t, agentKC, "wl1", "-n", listenerNS, "logs", "listener")
		e.forbidden(t, agentKC, "wl1", "-n", listenerNS, "exec", "listener", "--", "true")
		e.forbidden(t, agentKC, "wl1", "-n", listenerNS, "delete", "pod", "listener")
		e.forbidden(t, agentKC, "wl1", "get", "secrets", "-A")
		e.forbidden(t, agentKC, "wl1", "-n", "kglance", "create", "configmap", "x")
	})

	t.Run("snapshots", func(t *testing.T) {
		var rows map[string][]map[string]any
		deadline := time.Now().Add(2 * time.Minute)
		for {
			var problems []string
			rows, problems = e.snapshotRows(agentKC, nodes)
			if len(problems) == 0 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("snapshots incomplete:\n%s", strings.Join(problems, "\n"))
			}
			time.Sleep(5 * time.Second)
		}
		for node, rs := range rows {
			t.Logf("%s: %d rows", node, len(rs))
		}
	})

	t.Run("setup rerun from the current context", func(t *testing.T) {
		gen := e.dsGeneration()
		e.mustKglance("setup", "--kubeconfig", e.adminKubeconfigOnMgmt(), "--mgmt-namespace", listenerNS, "--workload", "wl1",
			"--ttl", "1h", "-o", "agent.kubeconfig", "--image", e.image, "--interval", "5s")
		if got := e.dsGeneration(); got != gen {
			t.Errorf("DaemonSet generation %s -> %s", gen, got)
		}
		for _, ctx := range []string{"mgmt", "wl1"} {
			if token(t, firstKC, ctx) == token(t, agentKC, ctx) {
				t.Errorf("%s: setup rerun did not mint a new token", ctx)
			}
		}
		e.allowed(t, agentKC, "wl1", "get", "pods", "-A")
	})

	t.Run("teardown", func(t *testing.T) {
		secondKC := e.copyFile(agentKC)
		out := e.mustKglance("teardown")
		if !regexp.MustCompile(`read \S*kglance\.state\.json: removing kglance from mgmt, wl1 \.\.\. done`).MatchString(out) {
			t.Errorf("teardown output:\n%s", out)
		}
		for _, f := range []string{"agent.kubeconfig", "kglance.state.json"} {
			if _, err := os.Stat(filepath.Join(e.dir, f)); !os.IsNotExist(err) {
				t.Errorf("%s still exists: %v", f, err)
			}
		}
		for _, ctx := range []string{e.mgmtCtx, e.wlCtx} {
			for _, kind := range []string{"clusterroles", "clusterrolebindings"} {
				if out := e.admin(ctx, "get", kind, "-l", "app.kubernetes.io/managed-by=kglance", "-o", "name"); out != "" {
					t.Errorf("%s: leftover %s:\n%s", ctx, kind, out)
				}
			}
		}
		e.waitGone(e.wlCtx, "namespace", "kglance")
		if out := e.admin(e.mgmtCtx, "-n", listenerNS, "get", "serviceaccounts,roles,rolebindings", "-l", "app.kubernetes.io/managed-by=kglance", "-o", "name"); out != "" {
			t.Errorf("mgmt: leftover objects:\n%s", out)
		}
		for _, kc := range []string{firstKC, secondKC} {
			for _, ctx := range []string{"mgmt", "wl1"} {
				e.waitUnauthorized(kc, ctx)
			}
		}
	})
}

func newEnv(t *testing.T) *env {
	e := &env{
		t:           t,
		mgmtCtx:     os.Getenv("KGLANCE_E2E_MGMT_CONTEXT"),
		wlCtx:       os.Getenv("KGLANCE_E2E_WORKLOAD_CONTEXT"),
		image:       os.Getenv("KGLANCE_E2E_IMAGE"),
		listenerImg: cmp.Or(os.Getenv("KGLANCE_E2E_LISTENER_IMAGE"), "busybox:1.37"),
		dir:         t.TempDir(),
	}
	if e.mgmtCtx == "" || e.wlCtx == "" || e.image == "" {
		t.Skip("set KGLANCE_E2E_MGMT_CONTEXT, KGLANCE_E2E_WORKLOAD_CONTEXT and KGLANCE_E2E_IMAGE")
	}
	e.bin = filepath.Join(t.TempDir(), "kglance")
	build := exec.Command("go", "build", "-o", e.bin, "..")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return e
}

// putKubeconfigSecret stores the workload's admin kubeconfig on mgmt the way Cluster API does.
func (e *env) putKubeconfigSecret() {
	kc := filepath.Join(e.dir, "wl1.kubeconfig")
	if err := os.WriteFile(kc, []byte(e.mustAdmin(e.wlCtx, "config", "view", "--minify", "--flatten")), 0o600); err != nil {
		e.t.Fatal(err)
	}
	e.admin(e.mgmtCtx, "create", "namespace", listenerNS)
	e.mustAdmin(e.mgmtCtx, "-n", listenerNS, "delete", "secret", "wl1-kubeconfig", "--ignore-not-found")
	e.mustAdmin(e.mgmtCtx, "-n", listenerNS, "create", "secret", "generic", "wl1-kubeconfig", "--from-file=value="+kc)
}

// adminKubeconfigOnMgmt returns a copy of the admin kubeconfig whose current context is mgmt.
func (e *env) adminKubeconfigOnMgmt() string {
	kc := filepath.Join(e.dir, "admin.kubeconfig")
	if err := os.WriteFile(kc, []byte(e.mustAdmin(e.mgmtCtx, "config", "view", "--flatten")), 0o600); err != nil {
		e.t.Fatal(err)
	}
	if out, err := run([]string{"--kubeconfig", kc, "config", "use-context", e.mgmtCtx}); err != nil {
		e.t.Fatalf("%v %s", err, out)
	}
	return kc
}

// startListener runs a non-root pod with a TCP listener in its own netns.
func (e *env) startListener() {
	manifest := fmt.Sprintf(`apiVersion: v1
kind: Namespace
metadata: {name: %[1]s}
---
apiVersion: v1
kind: Pod
metadata: {name: listener, namespace: %[1]s}
spec:
  terminationGracePeriodSeconds: 1
  securityContext: {runAsUser: 65534, runAsNonRoot: true}
  containers:
  - name: listener
    image: %[2]s
    imagePullPolicy: IfNotPresent
    command: [httpd, -f, -p, "%[3]s"]
`, listenerNS, e.listenerImg, listenerPort)
	cmd := exec.Command("kubectl", "--context", e.wlCtx, "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(manifest)
	if out, err := cmd.CombinedOutput(); err != nil {
		e.t.Fatalf("apply listener: %v\n%s", err, out)
	}
	e.mustAdmin(e.wlCtx, "-n", listenerNS, "wait", "--for=condition=Ready", "pod/listener", "--timeout=120s")
}

// snapshotRows fetches snapshots the way the agent instructions describe and checks them.
func (e *env) snapshotRows(kubeconfig string, nodes map[string]string) (map[string][]map[string]any, []string) {
	out, err := e.agent(kubeconfig, "wl1", "-n", "kglance", "get", "configmaps", "-l", "kglance.rosenhouse-bot-sandbox.github.io/snapshot",
		"-o", `go-template={{range .items}}{{index .data "sockets.jsonl"}}{{end}}`)
	if err != nil {
		return nil, []string{err.Error()}
	}
	var problems []string
	rows := map[string][]map[string]any{}
	for line := range strings.Lines(out) {
		if err := checkKeyOrder(line); err != nil {
			problems = append(problems, err.Error())
			continue
		}
		var r map[string]any
		json.Unmarshal([]byte(line), &r)
		rows[r["node"].(string)] = append(rows[r["node"].(string)], r)
	}
	listener := listenerNS + "/listener"
	for node, role := range nodes {
		rs := rows[node]
		if len(rs) == 0 {
			problems = append(problems, node+": no snapshot rows")
			continue
		}
		ts := rs[0]["ts"]
		if _, err := time.Parse(time.RFC3339, ts.(string)); err != nil {
			problems = append(problems, fmt.Sprintf("%s: ts %v", node, ts))
		}
		for _, r := range rs {
			if r["cluster"] != "wl1" || r["role"] != role || r["ts"] != ts ||
				!slices.Contains([]any{"host", "pod"}, r["netns"]) ||
				!slices.Contains([]any{"tcp", "tcp6", "udp", "udp6"}, r["proto"]) ||
				!(strings.HasPrefix(r["proto"].(string), "tcp") && r["state"] == "LISTEN" || strings.HasPrefix(r["proto"].(string), "udp") && r["state"] == "UNCONN") {
				problems = append(problems, fmt.Sprintf("%s: bad row %v", node, r))
			}
		}
		if !has(rs, map[string]any{"netns": "host", "proto": "tcp", "state": "LISTEN", "process": "kubelet", "pod": "", "container": ""}) {
			problems = append(problems, node+": no kubelet listener")
		}
		if role == "control-plane" && !has(rs, map[string]any{"netns": "host", "process": "kube-apiserver", "pod": "kube-system/kube-apiserver-" + node, "container": "kube-apiserver"}) {
			problems = append(problems, node+": no attributed kube-apiserver listener")
		}
		// busybox httpd binds [::] when the pod has IPv6, else 0.0.0.0.
		listenerRow := map[string]any{"netns": "pod", "state": "LISTEN", "process": "httpd", "pod": listener, "container": "listener"}
		onNode := node == e.listenerNode()
		if onNode != (has(rs, merge(listenerRow, map[string]any{"proto": "tcp", "local": "0.0.0.0:" + listenerPort})) ||
			has(rs, merge(listenerRow, map[string]any{"proto": "tcp6", "local": "[::]:" + listenerPort}))) {
			problems = append(problems, fmt.Sprintf("%s: want listener pod row: %v; rows on port %s: %v", node, onNode, listenerPort, onPort(rs, listenerPort)))
		}
	}
	return rows, problems
}

func checkKeyOrder(line string) error {
	dec := json.NewDecoder(strings.NewReader(line))
	var keys []string
	if _, err := dec.Token(); err != nil {
		return fmt.Errorf("row %q: %v", line, err)
	}
	for dec.More() {
		k, err := dec.Token()
		if err != nil {
			return fmt.Errorf("row %q: %v", line, err)
		}
		keys = append(keys, k.(string))
		var v any
		if err := dec.Decode(&v); err != nil {
			return fmt.Errorf("row %q: %v", line, err)
		}
	}
	if !slices.Equal(keys, rowFields) {
		return fmt.Errorf("row keys %v, want %v", keys, rowFields)
	}
	return nil
}

func merge(a, b map[string]any) map[string]any {
	m := maps.Clone(a)
	maps.Copy(m, b)
	return m
}

func onPort(rows []map[string]any, port string) []map[string]any {
	var on []map[string]any
	for _, r := range rows {
		if strings.HasSuffix(r["local"].(string), ":"+port) {
			on = append(on, r)
		}
	}
	return on
}

func has(rows []map[string]any, want map[string]any) bool {
	return slices.ContainsFunc(rows, func(r map[string]any) bool {
		for k, v := range want {
			if r[k] != v {
				return false
			}
		}
		return pidMatchesProcess(r)
	})
}

func pidMatchesProcess(r map[string]any) bool {
	if r["process"] == "" {
		return r["pid"] == float64(0)
	}
	return r["pid"].(float64) > 0
}

func (e *env) listenerNode() string {
	return e.mustAdmin(e.wlCtx, "-n", listenerNS, "get", "pod", "listener", "-o", "jsonpath={.spec.nodeName}")
}

// nodes maps workload node names to their expected role.
func (e *env) nodes() map[string]string {
	cps := e.mustAdmin(e.wlCtx, "get", "nodes", "-l", "node-role.kubernetes.io/control-plane", "-o", "name")
	all := e.mustAdmin(e.wlCtx, "get", "nodes", "-o", "name")
	nodes := map[string]string{}
	for _, n := range strings.Fields(all) {
		nodes[strings.TrimPrefix(n, "node/")] = "worker"
	}
	for _, n := range strings.Fields(cps) {
		nodes[strings.TrimPrefix(n, "node/")] = "control-plane"
	}
	return nodes
}

func (e *env) dsGeneration() string {
	return e.mustAdmin(e.wlCtx, "-n", "kglance", "get", "daemonset", "kglance-collector", "-o", "jsonpath={.metadata.generation}")
}

func (e *env) waitGone(ctx, kind, name string) {
	deadline := time.Now().Add(3 * time.Minute)
	for {
		out := e.admin(ctx, "get", kind, name, "--ignore-not-found", "-o", "name")
		if out == "" {
			return
		}
		if time.Now().After(deadline) {
			e.t.Errorf("%s: %s/%s still exists", ctx, kind, name)
			return
		}
		time.Sleep(2 * time.Second)
	}
}

func (e *env) waitUnauthorized(kubeconfig, ctx string) {
	deadline := time.Now().Add(time.Minute)
	for {
		_, err := e.agent(kubeconfig, ctx, "get", "namespaces")
		if err != nil && strings.Contains(err.Error(), "Unauthorized") {
			return
		}
		if time.Now().After(deadline) {
			e.t.Errorf("%s: old token still accepted (err %v)", ctx, err)
			return
		}
		time.Sleep(2 * time.Second)
	}
}

func token(t *testing.T, kubeconfig, ctx string) string {
	out, err := exec.Command("kubectl", "--kubeconfig", kubeconfig, "config", "view", "--raw",
		"-o", fmt.Sprintf(`jsonpath={.users[?(@.name=="%s")].user.token}`, ctx)).Output()
	if err != nil || len(out) == 0 {
		t.Fatalf("token for %s in %s: %v", ctx, kubeconfig, err)
	}
	return string(out)
}

func (e *env) copyFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		e.t.Fatal(err)
	}
	f, err := os.CreateTemp(e.t.TempDir(), "kubeconfig")
	if err != nil {
		e.t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write(b); err != nil {
		e.t.Fatal(err)
	}
	return f.Name()
}

func (e *env) kglance(args ...string) (string, error) {
	cmd := exec.Command(e.bin, args...)
	cmd.Dir = e.dir
	out, err := cmd.CombinedOutput()
	e.t.Logf("$ kglance %s\n%s", strings.Join(args, " "), out)
	return string(out), err
}

func (e *env) mustKglance(args ...string) string {
	out, err := e.kglance(args...)
	if err != nil {
		e.t.Fatalf("kglance %s: %v", args[0], err)
	}
	return out
}

func (e *env) admin(ctx string, args ...string) string {
	out, _ := run(append([]string{"--context", ctx}, args...))
	return out
}

func (e *env) mustAdmin(ctx string, args ...string) string {
	out, err := run(append([]string{"--context", ctx}, args...))
	if err != nil {
		e.t.Fatalf("kubectl --context %s %s: %v", ctx, strings.Join(args, " "), err)
	}
	return out
}

// agent runs kubectl with only the agent kubeconfig.
func (e *env) agent(kubeconfig, ctx string, args ...string) (string, error) {
	return run(append([]string{"--kubeconfig", kubeconfig, "--context", ctx}, args...))
}

func run(args []string) (string, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.Command("kubectl", args...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("kubectl %s: %v: %s", strings.Join(args, " "), err, stderr.String())
	}
	return strings.TrimSpace(stdout.String()), nil
}

func (e *env) allowed(t *testing.T, kubeconfig, ctx string, args ...string) {
	t.Helper()
	if _, err := e.agent(kubeconfig, ctx, args...); err != nil {
		t.Error(err)
	}
}

func (e *env) forbidden(t *testing.T, kubeconfig, ctx string, args ...string) {
	t.Helper()
	out, err := e.agent(kubeconfig, ctx, args...)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "forbidden") {
		t.Errorf("want Forbidden, got err=%v out=%q", err, out)
	}
}
