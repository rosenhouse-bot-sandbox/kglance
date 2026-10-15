package setup

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rosenhouse-bot-sandbox/kglance/internal/kube"
	"github.com/rosenhouse-bot-sandbox/kglance/internal/state"
	appsv1 "k8s.io/api/apps/v1"
	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

var now = time.Date(2026, 10, 15, 18, 10, 0, 0, time.UTC)

func caPEM(t *testing.T) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}, NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

type fakeCluster struct {
	cs        *fake.Clientset
	conn      *kube.Conn
	tokenTTLs []int64
	ready     bool
}

func newFakeCluster(t *testing.T, server string, tokenCap time.Duration) *fakeCluster {
	cs := fake.NewClientset(
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "view"}, Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"pods", "pods/log", "configmaps"}, Verbs: []string{"get", "list", "watch"}},
		}},
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "cp", Labels: map[string]string{"node-role.kubernetes.io/control-plane": ""}}},
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "w1"}},
		collectorPod("p1", "cp", true),
		collectorPod("p2", "w1", true),
	)
	fc := &fakeCluster{cs: cs, ready: true, conn: &kube.Conn{Client: cs, Cluster: &clientcmdapi.Cluster{Server: server, CertificateAuthorityData: caPEM(t)}}}
	cs.PrependReactor("create", "serviceaccounts", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if a.GetSubresource() != "token" {
			return false, nil, nil
		}
		ca := a.(k8stesting.CreateActionImpl)
		tr := ca.GetObject().(*authv1.TokenRequest).DeepCopy()
		if ca.Name != kube.AgentSA || ca.Namespace != kube.Namespace {
			return true, nil, fmt.Errorf("token for %s/%s", ca.Namespace, ca.Name)
		}
		fc.tokenTTLs = append(fc.tokenTTLs, *tr.Spec.ExpirationSeconds)
		ttl := time.Duration(*tr.Spec.ExpirationSeconds) * time.Second
		if tokenCap > 0 && ttl > tokenCap {
			ttl = tokenCap
		}
		tr.Status = authv1.TokenRequestStatus{Token: "tok-" + server, ExpirationTimestamp: metav1.NewTime(now.Add(ttl))}
		return true, tr, nil
	})
	cs.PrependReactor("get", "daemonsets", func(a k8stesting.Action) (bool, runtime.Object, error) {
		obj, err := cs.Tracker().Get(appsv1.SchemeGroupVersion.WithResource("daemonsets"), kube.Namespace, kube.CollectorDS)
		if err != nil {
			return true, nil, err
		}
		ds := obj.(*appsv1.DaemonSet).DeepCopy()
		ds.Status = appsv1.DaemonSetStatus{DesiredNumberScheduled: 2, UpdatedNumberScheduled: 2, NumberReady: 1, NumberAvailable: 1}
		if fc.ready {
			ds.Status.NumberReady, ds.Status.NumberAvailable = 2, 2
		}
		return true, ds, nil
	})
	return fc
}

func collectorPod(name, node string, ready bool) *corev1.Pod {
	status := corev1.ConditionFalse
	if ready {
		status = corev1.ConditionTrue
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: kube.Namespace, Labels: map[string]string{"app.kubernetes.io/name": kube.CollectorDS}},
		Spec:       corev1.PodSpec{NodeName: node},
		Status:     corev1.PodStatus{Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: status}}},
	}
}

type harness struct {
	dir      string
	clusters map[string]*fakeCluster
	out, err bytes.Buffer
}

func newHarness(t *testing.T) *harness {
	h := &harness{dir: t.TempDir(), clusters: map[string]*fakeCluster{}}
	h.clusters["mgmt-ctx"] = newFakeCluster(t, "https://mgmt:6443", 0)
	h.clusters["wl1-ctx"] = newFakeCluster(t, "https://wl1:6443", 0)
	h.clusters["wl2-ctx"] = newFakeCluster(t, "https://wl2:6443", 0)
	return h
}

func (h *harness) options(targets ...Target) Options {
	return Options{
		Targets:          targets,
		TTL:              time.Hour,
		KubeconfigPath:   filepath.Join(h.dir, "agent.kubeconfig"),
		StatePath:        filepath.Join(h.dir, "kglance.state.json"),
		InstructionsPath: "",
		Image:            "img:1",
		Interval:         time.Minute,
		Wait:             time.Second,
		PollInterval:     time.Millisecond,
		Now:              func() time.Time { return now },
		Out:              &h.out,
		Err:              &h.err,
		Connect: func(ctxName string) (*kube.Conn, error) {
			c, ok := h.clusters[ctxName]
			if !ok {
				return nil, fmt.Errorf("context %q not found", ctxName)
			}
			conn := *c.conn
			conn.Context = ctxName
			return &conn, nil
		},
	}
}

var (
	mgmt = Target{Name: "mgmt", Role: state.RoleMgmt, Context: "mgmt-ctx"}
	wl1  = Target{Name: "wl1", Role: state.RoleWorkload, Context: "wl1-ctx"}
	wl2  = Target{Name: "wl2", Role: state.RoleWorkload, Context: "wl2-ctx"}
)

func TestRunConfiguresClustersAndWritesOutputs(t *testing.T) {
	h := newHarness(t)
	o := h.options(mgmt, wl1)
	o.InstructionsPath = filepath.Join(h.dir, "instructions.txt")
	if err := Run(context.Background(), o); err != nil {
		t.Fatalf("%v\n%s", err, h.err.String())
	}
	ctx := context.Background()

	m, w := h.clusters["mgmt-ctx"].cs, h.clusters["wl1-ctx"].cs
	if _, err := m.RbacV1().ClusterRoles().Get(ctx, kube.AgentCAPIRole, metav1.GetOptions{}); err != nil {
		t.Error("mgmt: capi role missing")
	}
	if _, err := m.AppsV1().DaemonSets(kube.Namespace).Get(ctx, kube.CollectorDS, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Error("mgmt: collector installed")
	}
	ds, err := w.AppsV1().DaemonSets(kube.Namespace).Get(ctx, kube.CollectorDS, metav1.GetOptions{})
	if err != nil {
		t.Fatal("workload: collector missing")
	}
	env := ds.Spec.Template.Spec.Containers[0].Env
	if ds.Spec.Template.Spec.Containers[0].Image != "img:1" || env[0].Value != "wl1" {
		t.Errorf("ds image/env %+v", ds.Spec.Template.Spec.Containers[0])
	}
	view, err := w.RbacV1().ClusterRoles().Get(ctx, kube.AgentViewRole, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Rules) == 0 || strings.Contains(fmt.Sprint(view.Rules), "pods/log") || !strings.Contains(fmt.Sprint(view.Rules), "configmaps") {
		t.Errorf("view rules %+v", view.Rules)
	}
	if got := h.clusters["wl1-ctx"].tokenTTLs; len(got) != 1 || got[0] != 3600 {
		t.Errorf("token ttls %v", got)
	}

	kc, err := clientcmd.LoadFromFile(o.KubeconfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if kc.Contexts["wl1"] == nil || kc.Contexts["mgmt"] == nil || kc.CurrentContext != "mgmt" {
		t.Fatalf("contexts %+v current %q", kc.Contexts, kc.CurrentContext)
	}
	wc := kc.Contexts["wl1"]
	if kc.AuthInfos[wc.AuthInfo].Token != "tok-https://wl1:6443" || kc.Clusters[wc.Cluster].Server != "https://wl1:6443" ||
		len(kc.Clusters[wc.Cluster].CertificateAuthorityData) == 0 || kc.AuthInfos[wc.AuthInfo].Exec != nil {
		t.Errorf("wl1 entry %+v %+v", kc.Clusters[wc.Cluster], kc.AuthInfos[wc.AuthInfo])
	}
	if fi, _ := os.Stat(o.KubeconfigPath); fi.Mode().Perm() != 0o600 {
		t.Errorf("kubeconfig mode %v", fi.Mode())
	}

	raw, _ := os.ReadFile(o.StatePath)
	if strings.Contains(string(raw), "tok-") {
		t.Error("state contains token")
	}
	st, err := state.Load(o.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if st.Kubeconfig != o.KubeconfigPath || !st.Expiry.Equal(now.Add(time.Hour)) || len(st.Clusters) != 2 {
		t.Fatalf("state %+v", st)
	}
	sw := st.Find("wl1")
	fp, _ := state.Fingerprint(h.clusters["wl1-ctx"].conn.Cluster.CertificateAuthorityData)
	if sw.Role != state.RoleWorkload || sw.Context != "wl1-ctx" || sw.Server != "https://wl1:6443" || sw.CAFingerprint != fp || fp == "" {
		t.Errorf("wl1 record %+v", sw)
	}
	if len(sw.Objects) != 12 || sw.Objects[11] != (state.Object{APIVersion: "apps/v1", Kind: "DaemonSet", Namespace: "kglance", Name: "kglance-collector"}) {
		t.Errorf("objects %+v", sw.Objects)
	}
	if len(st.Find("mgmt").Objects) != 4 {
		t.Errorf("mgmt objects %+v", st.Find("mgmt").Objects)
	}

	out := h.out.String()
	for _, want := range []string{
		"wrote " + o.KubeconfigPath + " (contexts: mgmt, wl1; expires 19:10 UTC)\n",
		"wrote " + o.StatePath + "\n",
		"socket collector running on 2 nodes (1 control-plane, 1 worker)\n",
		"export KUBECONFIG=" + o.KubeconfigPath,
		`kubectl --context wl1 -n kglance get configmaps -l kglance.io/snapshot`,
		"wrote " + o.InstructionsPath + "\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	instr, err := os.ReadFile(o.InstructionsPath)
	if err != nil || !strings.Contains(string(instr), "export KUBECONFIG=") || strings.Contains(string(instr), "wrote ") {
		t.Errorf("instructions %q %v", instr, err)
	}
}

func TestRunWarnsWhenServerShortensToken(t *testing.T) {
	h := newHarness(t)
	h.clusters["wl1-ctx"] = newFakeCluster(t, "https://wl1:6443", 30*time.Minute)
	o := h.options(wl1)
	if err := Run(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(h.err.String(), "wl1: token expires at 18:40 UTC") {
		t.Errorf("stderr %q", h.err.String())
	}
	if !strings.Contains(h.out.String(), "expires 18:40 UTC") {
		t.Errorf("stdout %q", h.out.String())
	}
}

func TestRerunKeepsRecordedClustersNotGivenAgain(t *testing.T) {
	h := newHarness(t)
	if err := Run(context.Background(), h.options(wl1, wl2)); err != nil {
		t.Fatal(err)
	}
	if err := Run(context.Background(), h.options(wl1)); err != nil {
		t.Fatal(err)
	}
	st, _ := state.Load(h.options().StatePath)
	if len(st.Clusters) != 2 || st.Find("wl2") == nil {
		t.Fatalf("clusters %+v", st.Clusters)
	}
	if n := len(st.Find("wl1").Objects); n != 12 {
		t.Errorf("wl1 records %d objects", n)
	}
	if n := len(h.clusters["wl1-ctx"].tokenTTLs); n != 2 {
		t.Errorf("wl1 minted %d tokens", n)
	}
}

func TestRunRefusesClusterRecordedWithDifferentServer(t *testing.T) {
	h := newHarness(t)
	o := h.options(wl1)
	state.Save(o.StatePath, &state.File{Version: state.Version, Clusters: []state.Cluster{{Name: "wl1", Role: state.RoleWorkload, Context: "wl1-ctx", Server: "https://elsewhere:6443"}}})
	err := Run(context.Background(), o)
	if err == nil || !strings.Contains(err.Error(), "wl1") {
		t.Fatalf("err %v", err)
	}
	if _, gerr := h.clusters["wl1-ctx"].cs.CoreV1().Namespaces().Get(context.Background(), kube.Namespace, metav1.GetOptions{}); !apierrors.IsNotFound(gerr) {
		t.Error("objects applied despite mismatch")
	}
}

func TestRunRefusesRoleChange(t *testing.T) {
	h := newHarness(t)
	if err := Run(context.Background(), h.options(wl1)); err != nil {
		t.Fatal(err)
	}
	asMgmt := Target{Name: "wl1", Role: state.RoleMgmt, Context: "wl1-ctx"}
	if err := Run(context.Background(), h.options(asMgmt)); err == nil {
		t.Fatal("expected error")
	}
}

func TestRunRefusesTwoTargetsOnSameCluster(t *testing.T) {
	h := newHarness(t)
	h.clusters["alias-ctx"] = h.clusters["wl1-ctx"]
	err := Run(context.Background(), h.options(wl1, Target{Name: "alias", Role: state.RoleWorkload, Context: "alias-ctx"}))
	if err == nil || !strings.Contains(err.Error(), "same cluster") {
		t.Fatalf("err %v", err)
	}
}

func TestRunReportsCollectorNotReady(t *testing.T) {
	h := newHarness(t)
	h.clusters["wl1-ctx"].ready = false
	o := h.options(wl1)
	o.Wait = 20 * time.Millisecond
	err := Run(context.Background(), o)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(h.err.String(), "wl1: socket collector ready on 1/2 nodes after 20ms") {
		t.Errorf("stderr %q", h.err.String())
	}
	if _, serr := os.Stat(h.options().KubeconfigPath); serr != nil {
		t.Error("kubeconfig not written")
	}
}

func TestRunFailsWithoutViewClusterRole(t *testing.T) {
	h := newHarness(t)
	h.clusters["wl1-ctx"].cs.RbacV1().ClusterRoles().Delete(context.Background(), "view", metav1.DeleteOptions{})
	if err := Run(context.Background(), h.options(wl1)); err == nil || !strings.Contains(err.Error(), "view") {
		t.Fatalf("err %v", err)
	}
}

func TestParseTarget(t *testing.T) {
	cases := []struct {
		in, name, ctx string
		ok            bool
	}{
		{"wl1=kind-t1", "wl1", "kind-t1", true},
		{"kind-t1", "kind-t1", "kind-t1", true},
		{"", "", "", false},
		{"=ctx", "", "", false},
		{"name=", "", "", false},
	}
	for _, c := range cases {
		got, err := ParseTarget(state.RoleWorkload, c.in)
		if (err == nil) != c.ok || (c.ok && (got.Name != c.name || got.Context != c.ctx || got.Role != state.RoleWorkload)) {
			t.Errorf("%q: got %+v %v", c.in, got, err)
		}
	}
}

func TestValidate(t *testing.T) {
	good := Options{Targets: []Target{mgmt, wl1}, TTL: time.Hour, Interval: time.Minute, Image: "i"}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := map[string]func(o *Options){
		"no targets":    func(o *Options) { o.Targets = nil },
		"two mgmt":      func(o *Options) { o.Targets = []Target{mgmt, {Name: "m2", Role: state.RoleMgmt, Context: "x"}} },
		"dup name":      func(o *Options) { o.Targets = []Target{wl1, {Name: "wl1", Role: state.RoleWorkload, Context: "x"}} },
		"ttl too short": func(o *Options) { o.TTL = 9 * time.Minute },
		"ttl too long":  func(o *Options) { o.TTL = 8*time.Hour + time.Second },
		"interval":      func(o *Options) { o.Interval = 0 },
		"image":         func(o *Options) { o.Image = "" },
	}
	for name, mutate := range bad {
		o := good
		mutate(&o)
		if err := o.Validate(); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	edge := good
	edge.TTL = 8 * time.Hour
	if err := edge.Validate(); err != nil {
		t.Error(err)
	}
	edge.TTL = 10 * time.Minute
	if err := edge.Validate(); err != nil {
		t.Error(err)
	}
}

func TestInstructionsForMgmtOnlyOmitSnapshotCommand(t *testing.T) {
	got := Instructions("/k", now, []Target{mgmt})
	if strings.Contains(got, "configmaps") || !strings.Contains(got, "mgmt ") || !strings.Contains(got, "2026-10-15 18:10 UTC") {
		t.Errorf("%s", got)
	}
}

func TestRunWaitsForTerminatingNamespace(t *testing.T) {
	h := newHarness(t)
	fc := h.clusters["wl1-ctx"]
	deleting := metav1.NewTime(now)
	fc.cs.Tracker().Add(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: kube.Namespace, DeletionTimestamp: &deleting, Finalizers: []string{"kubernetes"}}})
	gets := 0
	fc.cs.PrependReactor("get", "namespaces", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if gets++; gets == 3 {
			fc.cs.Tracker().Delete(corev1.SchemeGroupVersion.WithResource("namespaces"), "", kube.Namespace)
		}
		return false, nil, nil
	})
	if err := Run(context.Background(), h.options(wl1)); err != nil {
		t.Fatal(err)
	}
	if gets < 3 || !strings.Contains(h.err.String(), "wl1: waiting for namespace kglance to finish terminating") {
		t.Errorf("gets %d stderr %q", gets, h.err.String())
	}
	ns, err := fc.cs.CoreV1().Namespaces().Get(context.Background(), kube.Namespace, metav1.GetOptions{})
	if err != nil || ns.DeletionTimestamp != nil {
		t.Fatalf("%+v %v", ns, err)
	}
}

func TestInstructionsGiveSnapshotCommandPerWorkload(t *testing.T) {
	got := Instructions("/k", now, []Target{mgmt, wl1, wl2})
	for _, name := range []string{"wl1", "wl2"} {
		if !strings.Contains(got, "kubectl --context "+name+" -n kglance get configmaps") || !strings.Contains(got, "> "+name+"-sockets.jsonl") {
			t.Errorf("missing %s command:\n%s", name, got)
		}
	}
	if !strings.Contains(got, "kglance.io/truncated") {
		t.Errorf("no truncation note:\n%s", got)
	}
	if strings.Contains(got, "--context mgmt") {
		t.Errorf("mgmt command:\n%s", got)
	}
}

func failDaemonSetApply(fc *fakeCluster) {
	fc.cs.PrependReactor("patch", "daemonsets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("denied: hostPID is not allowed")
	})
}

func TestRunRecordsObjectsAppliedBeforeAFailure(t *testing.T) {
	h := newHarness(t)
	failDaemonSetApply(h.clusters["wl1-ctx"])
	o := h.options(wl1)
	err := Run(context.Background(), o)
	if err == nil || !strings.Contains(err.Error(), "hostPID") || !strings.Contains(err.Error(), "kglance teardown") {
		t.Fatalf("err %v", err)
	}
	st, err := state.Load(o.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	rec := st.Find("wl1")
	if rec == nil || len(rec.Objects) != 11 || rec.Objects[0].Kind != "Namespace" || rec.Objects[10].Kind != "RoleBinding" {
		t.Fatalf("record %+v", rec)
	}
}

func TestRerunFailureKeepsPreviouslyRecordedObjects(t *testing.T) {
	h := newHarness(t)
	o := h.options(wl1)
	if err := Run(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	failDaemonSetApply(h.clusters["wl1-ctx"])
	if err := Run(context.Background(), o); err == nil {
		t.Fatal("expected error")
	}
	st, _ := state.Load(o.StatePath)
	if objs := st.Find("wl1").Objects; len(objs) != 12 || objs[11].Kind != "DaemonSet" {
		t.Fatalf("objects %+v", objs)
	}
}

func TestRunRefusesToAdoptObjectsNotManagedByKglance(t *testing.T) {
	cases := map[string]metav1.Object{
		"Namespace kglance":              &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: kube.Namespace}},
		"ClusterRole kglance-agent-view": &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: kube.AgentViewRole, Labels: map[string]string{"x": "y"}}},
		"DaemonSet kglance-collector":    &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: kube.CollectorDS, Namespace: kube.Namespace}},
	}
	for name, existing := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			fc := h.clusters["wl1-ctx"]
			fc.cs.Tracker().Add(existing.(runtime.Object))
			err := Run(context.Background(), h.options(wl1))
			if err == nil || !strings.Contains(err.Error(), name+" exists and is not managed by kglance") {
				t.Fatalf("err %v", err)
			}
			for _, a := range fc.cs.Actions() {
				if p, ok := a.(k8stesting.PatchAction); ok && p.GetName() == existing.GetName() && p.GetNamespace() == existing.GetNamespace() &&
					strings.EqualFold(a.GetResource().Resource, strings.Fields(name)[0]+"s") {
					t.Errorf("patched %s", name)
				}
			}
		})
	}
}

func TestRunRefusesRenamingARecordedCluster(t *testing.T) {
	h := newHarness(t)
	if err := Run(context.Background(), h.options(wl1)); err != nil {
		t.Fatal(err)
	}
	renamed := Target{Name: "renamed", Role: state.RoleWorkload, Context: "wl1-ctx"}
	if err := Run(context.Background(), h.options(renamed)); err == nil || !strings.Contains(err.Error(), "already recorded as wl1") {
		t.Fatalf("err %v", err)
	}
}

func TestRunCountsOnlyReadyCollectorPods(t *testing.T) {
	h := newHarness(t)
	fc := h.clusters["wl1-ctx"]
	fc.cs.Tracker().Add(&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "w2"}})
	fc.cs.Tracker().Add(collectorPod("p3", "w2", false))
	if err := Run(context.Background(), h.options(wl1)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(h.out.String(), "socket collector running on 2 nodes (1 control-plane, 1 worker)") {
		t.Errorf("out %q", h.out.String())
	}
}

func TestRunUsesEarliestTokenExpiry(t *testing.T) {
	h := newHarness(t)
	h.clusters["wl1-ctx"] = newFakeCluster(t, "https://wl1:6443", 30*time.Minute)
	o := h.options(wl1, wl2)
	if err := Run(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	st, _ := state.Load(o.StatePath)
	if !st.Expiry.Equal(now.Add(30*time.Minute)) || !strings.Contains(h.out.String(), "expires 18:40 UTC") {
		t.Errorf("expiry %v out %q", st.Expiry, h.out.String())
	}
}

func TestAgentKubeconfigOmitsAdminKubeconfigExtensions(t *testing.T) {
	h := newHarness(t)
	h.clusters["wl1-ctx"].conn.Cluster.Extensions = map[string]runtime.Object{"admin-ext": &runtime.Unknown{Raw: []byte(`{"secret":"x"}`)}}
	o := h.options(wl1)
	if err := Run(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(o.KubeconfigPath)
	if strings.Contains(string(raw), "admin-ext") {
		t.Errorf("kubeconfig %s", raw)
	}
}
