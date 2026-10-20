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
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rosenhouse-bot-sandbox/kglance/internal/kube"
	"github.com/rosenhouse-bot-sandbox/kglance/internal/state"
	appsv1 "k8s.io/api/apps/v1"
	authv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
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
	tokenNS   string
	ready     bool
	stale     bool
	status    func(*appsv1.DaemonSetStatus)
	// reaper sets the reaper Deployment's status; nil means available.
	reaper func(*appsv1.Deployment)
	// namespaces counts namespace creations, which get UIDs ns-uid-1, ns-uid-2, ...
	namespaces int
	// deny refuses the access reviews it matches; nil allows all.
	deny    func(authzv1.ResourceAttributes) bool
	reviews []authzv1.ResourceAttributes
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
	fc := &fakeCluster{cs: cs, tokenNS: kube.Namespace, ready: true, conn: &kube.Conn{Client: cs, Cluster: &clientcmdapi.Cluster{Server: server, CertificateAuthorityData: caPEM(t)}}}
	cs.PrependReactor("create", "serviceaccounts", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if a.GetSubresource() != "token" {
			return false, nil, nil
		}
		ca := a.(k8stesting.CreateActionImpl)
		tr := ca.GetObject().(*authv1.TokenRequest).DeepCopy()
		if ca.Name != kube.AgentSA || ca.Namespace != fc.tokenNS {
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
	cs.PrependReactor("patch", "namespaces", func(a k8stesting.Action) (bool, runtime.Object, error) {
		name := a.(k8stesting.PatchAction).GetName()
		if _, err := cs.Tracker().Get(corev1.SchemeGroupVersion.WithResource("namespaces"), "", name); apierrors.IsNotFound(err) {
			fc.namespaces++
			uid := types.UID(fmt.Sprintf("ns-uid-%d", fc.namespaces))
			if err := cs.Tracker().Add(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, UID: uid}}); err != nil {
				return true, nil, err
			}
		}
		return false, nil, nil
	})
	cs.PrependReactor("get", "deployments", func(a k8stesting.Action) (bool, runtime.Object, error) {
		obj, err := cs.Tracker().Get(appsv1.SchemeGroupVersion.WithResource("deployments"), kube.Namespace, kube.ReaperDeployment)
		if err != nil {
			return true, nil, err
		}
		d := obj.(*appsv1.Deployment).DeepCopy()
		d.Generation, d.Status = 1, appsv1.DeploymentStatus{ObservedGeneration: 1, Replicas: 1, UpdatedReplicas: 1, ReadyReplicas: 1, AvailableReplicas: 1}
		if fc.reaper != nil {
			fc.reaper(d)
		}
		return true, d, nil
	})
	cs.PrependReactor("create", "selfsubjectaccessreviews", func(a k8stesting.Action) (bool, runtime.Object, error) {
		r := a.(k8stesting.CreateAction).GetObject().(*authzv1.SelfSubjectAccessReview).DeepCopy()
		fc.reviews = append(fc.reviews, *r.Spec.ResourceAttributes)
		r.Status.Allowed = fc.deny == nil || !fc.deny(*r.Spec.ResourceAttributes)
		return true, r, nil
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
		if fc.stale {
			ds.Generation, ds.Status.ObservedGeneration = 2, 1
		}
		if fc.status != nil {
			fc.status(&ds.Status)
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
	t        *testing.T
	dir      string
	clusters map[string]*fakeCluster
	out, err bytes.Buffer
}

func newHarness(t *testing.T) *harness {
	h := &harness{t: t, dir: t.TempDir(), clusters: map[string]*fakeCluster{}}
	h.clusters["mgmt"] = newFakeCluster(t, "https://mgmt:6443", 0)
	h.clusters["mgmt"].tokenNS = "ns1"
	h.addWorkload("wl1", 0)
	h.addWorkload("wl2", 0)
	return h
}

// addWorkload creates a workload cluster and its Cluster API kubeconfig Secret ns1/<name>-kubeconfig on mgmt.
func (h *harness) addWorkload(name string, tokenCap time.Duration) *fakeCluster {
	fc := newFakeCluster(h.t, "https://"+name+":6443", tokenCap)
	h.clusters[name] = fc
	h.putKubeconfigSecret(name, fc)
	return fc
}

func (h *harness) putKubeconfigSecret(name string, fc *fakeCluster) {
	cfg := clientcmdapi.NewConfig()
	cfg.Clusters["c"] = fc.conn.Cluster.DeepCopy()
	cfg.AuthInfos["admin"] = &clientcmdapi.AuthInfo{ClientCertificateData: []byte("cert"), ClientKeyData: []byte("key")}
	cfg.Contexts["admin@c"] = &clientcmdapi.Context{Cluster: "c", AuthInfo: "admin"}
	cfg.CurrentContext = "admin@c"
	data, err := clientcmd.Write(*cfg)
	if err != nil {
		h.t.Fatal(err)
	}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "ns1", Name: name + "-kubeconfig"}, Data: map[string][]byte{"value": data}}
	secrets := h.clusters["mgmt"].cs.CoreV1().Secrets("ns1")
	_, err = secrets.Update(context.Background(), secret, metav1.UpdateOptions{})
	if apierrors.IsNotFound(err) {
		_, err = secrets.Create(context.Background(), secret, metav1.CreateOptions{})
	}
	if err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) options(workloads ...Workload) Options {
	return Options{
		MgmtNamespace:    "ns1",
		Workloads:        workloads,
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
			if ctxName == "" {
				ctxName = "mgmt-ctx"
			}
			if ctxName != "mgmt-ctx" {
				return nil, fmt.Errorf("context %q not found", ctxName)
			}
			conn := *h.clusters["mgmt"].conn
			conn.Context = ctxName
			return &conn, nil
		},
		ConnectKubeconfig: func(data []byte) (*kube.Conn, error) {
			cfg, err := clientcmd.Load(data)
			if err != nil {
				return nil, err
			}
			cluster := cfg.Clusters[cfg.Contexts[cfg.CurrentContext].Cluster]
			for _, fc := range h.clusters {
				if fc.conn.Cluster.Server == cluster.Server {
					return &kube.Conn{Client: fc.cs, Cluster: cluster}, nil
				}
			}
			return nil, fmt.Errorf("no cluster at %s", cluster.Server)
		},
	}
}

var (
	wl1 = Workload{Name: "wl1", Cluster: "wl1"}
	wl2 = Workload{Name: "wl2", Cluster: "wl2"}
)

func TestRunConfiguresClustersAndWritesOutputs(t *testing.T) {
	h := newHarness(t)
	o := h.options(wl1)
	o.InstructionsPath = filepath.Join(h.dir, "instructions.txt")
	if err := Run(context.Background(), o); err != nil {
		t.Fatalf("%v\n%s", err, h.err.String())
	}
	ctx := context.Background()

	m, w := h.clusters["mgmt"].cs, h.clusters["wl1"].cs
	if _, err := m.RbacV1().Roles("ns1").Get(ctx, kube.AgentMgmtRole, metav1.GetOptions{}); err != nil {
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
	if got := h.clusters["wl1"].tokenTTLs; len(got) != 1 || got[0] != 3600 {
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
	if st.Kubeconfig != o.KubeconfigPath || !st.Expiry.Equal(now.Add(time.Hour)) || len(st.Clusters) != 2 || st.Clusters[0].Name != "mgmt" {
		t.Fatalf("state %+v", st)
	}
	sw := st.Find("wl1")
	fp, _ := state.Fingerprint(h.clusters["wl1"].conn.Cluster.CertificateAuthorityData)
	if sw.Role != state.RoleWorkload || sw.Context != "mgmt-ctx" || sw.ClusterRef != "ns1/wl1" || sw.Server != "https://wl1:6443" || sw.CAFingerprint != fp || fp == "" {
		t.Errorf("wl1 record %+v", sw)
	}
	if len(sw.Objects) != 16 || sw.Objects[0].Kind != "Namespace" || sw.Objects[15] != (state.Object{APIVersion: "apps/v1", Kind: "DaemonSet", Namespace: "kglance", Name: "kglance-collector"}) {
		t.Errorf("objects %+v", sw.Objects)
	}
	ns, err := w.CoreV1().Namespaces().Get(ctx, kube.Namespace, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{kube.ExpiresAtAnnotation, kube.TokensExpireAtAnnotation} {
		if at, err := kube.TimeAnnotation(ns, key); err != nil || !at.Equal(now.Add(time.Hour)) {
			t.Errorf("%s %v %v", key, at, err)
		}
	}
	if owners := view.OwnerReferences; len(owners) != 1 || owners[0].UID != ns.UID || ns.UID == "" {
		t.Errorf("agent view ClusterRole owners %+v, namespace UID %q", owners, ns.UID)
	}
	if _, err := w.AppsV1().Deployments(kube.Namespace).Get(ctx, kube.ReaperDeployment, metav1.GetOptions{}); err != nil {
		t.Errorf("reaper: %v", err)
	}
	if sm := st.Find("mgmt"); len(sm.Objects) != 3 || sm.Context != "mgmt-ctx" || sm.ClusterRef != "" {
		t.Errorf("mgmt record %+v", sm)
	}

	out := h.out.String()
	for _, want := range []string{
		"wrote " + o.KubeconfigPath + " (contexts: mgmt, wl1; expires 19:10 UTC)\n",
		"wrote " + o.StatePath + "\n",
		"socket collector running on 2 nodes (1 control-plane, 1 worker)\n",
		"export KUBECONFIG=" + o.KubeconfigPath,
		`kubectl --context wl1 -n kglance get configmaps -l kglance.rosenhouse-bot-sandbox.github.io/snapshot`,
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
	h.addWorkload("wl1", 30*time.Minute)
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
	if len(st.Clusters) != 3 || st.Find("wl2") == nil {
		t.Fatalf("clusters %+v", st.Clusters)
	}
	if n := len(st.Find("wl1").Objects); n != 16 {
		t.Errorf("wl1 records %d objects", n)
	}
	if n := len(h.clusters["wl1"].tokenTTLs); n != 2 {
		t.Errorf("wl1 minted %d tokens", n)
	}
}

func TestRunRefusesClusterRecordedWithDifferentServer(t *testing.T) {
	h := newHarness(t)
	o := h.options(wl1)
	state.Save(o.StatePath, &state.File{Version: state.Version, Clusters: []state.Cluster{{Name: "wl1", Role: state.RoleWorkload, Context: "mgmt-ctx", ClusterRef: "ns1/wl1", Server: "https://elsewhere:6443"}}})
	err := Run(context.Background(), o)
	if err == nil || !strings.Contains(err.Error(), "wl1") {
		t.Fatalf("err %v", err)
	}
	if _, gerr := h.clusters["wl1"].cs.CoreV1().Namespaces().Get(context.Background(), kube.Namespace, metav1.GetOptions{}); !apierrors.IsNotFound(gerr) {
		t.Error("objects applied despite mismatch")
	}
}

func TestRunRefusesRoleChange(t *testing.T) {
	h := newHarness(t)
	o := h.options()
	fp, _ := state.Fingerprint(h.clusters["mgmt"].conn.Cluster.CertificateAuthorityData)
	state.Save(o.StatePath, &state.File{Version: state.Version, Clusters: []state.Cluster{{Name: "mgmt", Role: state.RoleWorkload, Context: "mgmt-ctx", Server: "https://mgmt:6443", CAFingerprint: fp}}})
	if err := Run(context.Background(), o); err == nil || !strings.Contains(err.Error(), "recorded as workload") {
		t.Fatalf("err %v", err)
	}
}

func TestRunRefusesTwoWorkloadsOnSameCluster(t *testing.T) {
	h := newHarness(t)
	h.putKubeconfigSecret("alias", h.clusters["wl1"])
	err := Run(context.Background(), h.options(wl1, Workload{Name: "alias", Cluster: "alias"}))
	if err == nil || !strings.Contains(err.Error(), "same cluster") {
		t.Fatalf("err %v", err)
	}
}

func TestRunReportsCollectorNotReady(t *testing.T) {
	h := newHarness(t)
	h.clusters["wl1"].ready = false
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

func TestRunReportsCollectorNotReadyWhileStatusIsStale(t *testing.T) {
	h := newHarness(t)
	h.clusters["wl1"].stale = true
	o := h.options(wl1)
	o.Wait = 20 * time.Millisecond
	if err := Run(context.Background(), o); err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(h.err.String(), "wl1: socket collector ready on 2/2 nodes after 20ms") {
		t.Errorf("stderr %q", h.err.String())
	}
}

func TestRunReportsCollectorNotReadyWhileOldPodsRemain(t *testing.T) {
	h := newHarness(t)
	h.clusters["wl1"].status = func(s *appsv1.DaemonSetStatus) { s.UpdatedNumberScheduled = 1 }
	o := h.options(wl1)
	o.Wait = 20 * time.Millisecond
	if err := Run(context.Background(), o); err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(h.err.String(), "wl1: socket collector ready on 2/2 nodes after 20ms") {
		t.Errorf("stderr %q", h.err.String())
	}
}

func TestRunReportsCollectorNotReadyWhenScheduledOnNoNodes(t *testing.T) {
	h := newHarness(t)
	h.clusters["wl1"].status = func(s *appsv1.DaemonSetStatus) { *s = appsv1.DaemonSetStatus{} }
	o := h.options(wl1)
	o.Wait = 20 * time.Millisecond
	if err := Run(context.Background(), o); err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(h.err.String(), "wl1: socket collector ready on 0/0 nodes after 20ms") {
		t.Errorf("stderr %q", h.err.String())
	}
}

func TestRunFailsWithoutViewClusterRole(t *testing.T) {
	h := newHarness(t)
	h.clusters["wl1"].cs.RbacV1().ClusterRoles().Delete(context.Background(), "view", metav1.DeleteOptions{})
	if err := Run(context.Background(), h.options(wl1)); err == nil || !strings.Contains(err.Error(), "view") {
		t.Fatalf("err %v", err)
	}
}

func TestParseWorkload(t *testing.T) {
	cases := []struct {
		in, name, cluster string
		ok                bool
	}{
		{"wl1=c1", "wl1", "c1", true},
		{"c1", "c1", "c1", true},
		{"", "", "", false},
		{"=c1", "", "", false},
		{"wl1=", "", "", false},
		{"ns1/c1", "", "", false},
		{"wl1=ns1/c1", "", "", false},
		{"x y=c1", "", "", false},
		{"a=b=c1", "", "", false},
	}
	for _, c := range cases {
		got, err := ParseWorkload(c.in)
		if (err == nil) != c.ok || (c.ok && got != (Workload{Name: c.name, Cluster: c.cluster})) {
			t.Errorf("%q: got %+v %v", c.in, got, err)
		}
	}
}

func TestValidate(t *testing.T) {
	good := Options{MgmtNamespace: "ns1", Workloads: []Workload{wl1}, TTL: time.Hour, Interval: time.Minute, Image: "i"}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := map[string]func(o *Options){
		"dup name":      func(o *Options) { o.Workloads = []Workload{wl1, {Name: "wl1", Cluster: "other"}} },
		"named mgmt":    func(o *Options) { o.Workloads = []Workload{{Name: "mgmt", Cluster: "mgmt"}} },
		"ttl too short": func(o *Options) { o.TTL = 9 * time.Minute },
		"ttl too long":  func(o *Options) { o.TTL = 8*time.Hour + time.Second },
		"interval":      func(o *Options) { o.Interval = 0 },
		"image":         func(o *Options) { o.Image = "" },
		"namespace":     func(o *Options) { o.MgmtNamespace = "Not_A_Name" },
		"no namespace":  func(o *Options) { o.MgmtNamespace = "" },
	}
	for name, mutate := range bad {
		o := good
		mutate(&o)
		if err := o.Validate(); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	mgmtOnly := good
	mgmtOnly.Workloads = nil
	if err := mgmtOnly.Validate(); err != nil {
		t.Error(err)
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
	got := Instructions("/k", now, "ns1", nil)
	if strings.Contains(got, "configmaps") || !strings.Contains(got, "mgmt ") || !strings.Contains(got, "2026-10-15 18:10 UTC") {
		t.Errorf("%s", got)
	}
}

func TestRunWaitsForTerminatingNamespace(t *testing.T) {
	h := newHarness(t)
	fc := h.clusters["wl1"]
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
	got := Instructions("/k", now, "ns1", []Workload{wl1, wl2})
	for _, name := range []string{"wl1", "wl2"} {
		if !strings.Contains(got, "kubectl --context "+name+" -n kglance get configmaps") || !strings.Contains(got, "> "+name+"-sockets.jsonl") {
			t.Errorf("missing %s command:\n%s", name, got)
		}
	}
	if !strings.Contains(got, "kglance.rosenhouse-bot-sandbox.github.io/truncated") {
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
	failDaemonSetApply(h.clusters["wl1"])
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
	if rec == nil || len(rec.Objects) != 15 || rec.Objects[0].Kind != "Namespace" || rec.Objects[14].Kind != "RoleBinding" {
		t.Fatalf("record %+v", rec)
	}
}

func TestRerunFailureKeepsPreviouslyRecordedObjects(t *testing.T) {
	h := newHarness(t)
	o := h.options(wl1)
	if err := Run(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	failDaemonSetApply(h.clusters["wl1"])
	if err := Run(context.Background(), o); err == nil {
		t.Fatal("expected error")
	}
	st, _ := state.Load(o.StatePath)
	if objs := st.Find("wl1").Objects; len(objs) != 16 || objs[15].Kind != "DaemonSet" {
		t.Fatalf("objects %+v", objs)
	}
}

func TestRunRefusesToAdoptObjectsNotManagedByKglance(t *testing.T) {
	cases := map[string]metav1.Object{
		"Namespace kglance":                   &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: kube.Namespace}},
		"ClusterRole kglance-agent-view":      &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: kube.AgentViewRole, Labels: map[string]string{"x": "y"}}},
		"DaemonSet kglance/kglance-collector": &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: kube.CollectorDS, Namespace: kube.Namespace}},
	}
	for name, existing := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			fc := h.clusters["wl1"]
			fc.cs.Tracker().Add(existing.(runtime.Object))
			err := Run(context.Background(), h.options(wl1))
			if err == nil || !strings.Contains(err.Error(), "wl1: apply "+name+": exists and is not managed by kglance") {
				t.Fatalf("err %v", err)
			}
			if appliedNothing := name == "Namespace kglance"; appliedNothing == strings.Contains(err.Error(), "teardown") {
				t.Errorf("teardown hint wrong: %v", err)
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
	renamed := Workload{Name: "renamed", Cluster: "wl1"}
	if err := Run(context.Background(), h.options(renamed)); err == nil || !strings.Contains(err.Error(), "already recorded as wl1") {
		t.Fatalf("err %v", err)
	}
}

func TestRunCountsOnlyReadyCollectorPods(t *testing.T) {
	h := newHarness(t)
	fc := h.clusters["wl1"]
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
	h.addWorkload("wl1", 30*time.Minute)
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
	h.clusters["mgmt"].conn.Cluster.Extensions = map[string]runtime.Object{"admin-ext": &runtime.Unknown{Raw: []byte(`{"secret":"x"}`)}}
	o := h.options(wl1)
	if err := Run(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(o.KubeconfigPath)
	if strings.Contains(string(raw), "admin-ext") {
		t.Errorf("kubeconfig %s", raw)
	}
}

func TestRunRefusesToOverwriteAdminKubeconfig(t *testing.T) {
	for _, field := range []string{"output", "state", "instructions"} {
		t.Run(field, func(t *testing.T) {
			h := newHarness(t)
			admin := filepath.Join(h.dir, "admin")
			if err := os.WriteFile(admin, []byte("admin"), 0o600); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(h.dir, "link")
			if err := os.Symlink(admin, link); err != nil {
				t.Fatal(err)
			}
			o := h.options(wl1)
			o.AdminKubeconfigs = []string{"/nonexistent", admin}
			switch field {
			case "output":
				o.KubeconfigPath = link
			case "state":
				o.StatePath = link
			case "instructions":
				o.InstructionsPath = link
			}
			err := Run(context.Background(), o)
			if err == nil || !strings.Contains(err.Error(), "admin kubeconfig") {
				t.Fatalf("err %v", err)
			}
			if b, _ := os.ReadFile(admin); string(b) != "admin" {
				t.Errorf("admin kubeconfig changed: %q", b)
			}
			if _, err := h.clusters["wl1"].cs.CoreV1().Namespaces().Get(context.Background(), kube.Namespace, metav1.GetOptions{}); err == nil {
				t.Error("applied objects before refusing")
			}
		})
	}
}

func TestRunConnectsToGivenMgmtContext(t *testing.T) {
	h := newHarness(t)
	o := h.options(wl1)
	o.MgmtContext = "other-ctx"
	if err := Run(context.Background(), o); err == nil || !strings.Contains(err.Error(), `"other-ctx"`) {
		t.Fatalf("err %v", err)
	}
}

func TestRunFailsWithoutKubeconfigSecret(t *testing.T) {
	h := newHarness(t)
	err := Run(context.Background(), h.options(wl1, Workload{Name: "missing", Cluster: "missing"}))
	if err == nil || !strings.Contains(err.Error(), "missing: read kubeconfig Secret ns1/missing-kubeconfig") {
		t.Fatalf("err %v", err)
	}
	if _, err := h.clusters["mgmt"].cs.CoreV1().ServiceAccounts("ns1").Get(context.Background(), kube.AgentSA, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Error("applied objects before connecting to every cluster")
	}
}

func TestInstructionsNameEachWorkloadsCluster(t *testing.T) {
	got := Instructions("/k", now, "ns1", []Workload{wl1})
	if !strings.Contains(got, "wl1          workload cluster ns1/wl1:") {
		t.Errorf("%s", got)
	}
}

func TestRunRefusesMgmtObjectsRecordedOutsideTheNamespace(t *testing.T) {
	h := newHarness(t)
	o := h.options()
	if err := Run(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	o.MgmtNamespace = "other"
	err := Run(context.Background(), o)
	if err == nil || !strings.Contains(err.Error(), "mgmt: recorded ServiceAccount ns1/kglance-agent") || !strings.Contains(err.Error(), "run kglance teardown first") {
		t.Fatalf("err %v", err)
	}
}

func TestRunTouchesOnlyMgmtNamespaceOnMgmt(t *testing.T) {
	h := newHarness(t)
	m := h.clusters["mgmt"]
	if err := Run(context.Background(), h.options(wl1)); err != nil {
		t.Fatalf("%v\n%s", err, h.err.String())
	}
	for _, a := range m.cs.Actions() {
		if a.GetNamespace() != "ns1" {
			t.Errorf("mgmt: %s %s in %q", a.GetVerb(), a.GetResource().Resource, a.GetNamespace())
		}
	}
	if !strings.Contains(h.out.String(), "Cluster API and VM Operator objects, pods, services, deployments and events in namespace ns1") {
		t.Errorf("instructions:\n%s", h.out.String())
	}
}

// reaperDeadline reads the tracker directly, so that reactors can call it.
func reaperDeadline(t *testing.T, fc *fakeCluster) time.Time {
	t.Helper()
	obj, err := fc.cs.Tracker().Get(corev1.SchemeGroupVersion.WithResource("namespaces"), "", kube.Namespace)
	if err != nil {
		t.Fatal(err)
	}
	at, err := kube.TimeAnnotation(obj.(*corev1.Namespace), kube.ExpiresAtAnnotation)
	if err != nil {
		t.Fatal(err)
	}
	return at
}

func TestRunSetsReaperDeadlineToTheTokenExpiryFromTheServer(t *testing.T) {
	h := newHarness(t)
	fc := h.addWorkload("wl1", 30*time.Minute)
	var atMint time.Time
	fc.cs.PrependReactor("create", "serviceaccounts", func(a k8stesting.Action) (bool, runtime.Object, error) {
		atMint = reaperDeadline(t, fc)
		return false, nil, nil
	})
	if err := Run(context.Background(), h.options(wl1)); err != nil {
		t.Fatal(err)
	}
	if want := now.Add(h.options().Wait + time.Hour); !atMint.Equal(want) {
		t.Errorf("deadline before minting %v, want %v", atMint, want)
	}
	if got := reaperDeadline(t, fc); !got.Equal(now.Add(30 * time.Minute)) {
		t.Errorf("deadline %v, want token expiry", got)
	}
}

func TestRerunKeepsTheDeadlineOfALongerLivedEarlierToken(t *testing.T) {
	h := newHarness(t)
	o := h.options(wl1)
	o.TTL = 2 * time.Hour
	if err := Run(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	o.TTL = time.Hour
	fc := h.clusters["wl1"]
	for range 2 {
		if err := Run(context.Background(), o); err != nil {
			t.Fatal(err)
		}
		if got := reaperDeadline(t, fc); !got.Equal(now.Add(2 * time.Hour)) {
			t.Errorf("deadline %v", got)
		}
	}
	then := now.Add(90 * time.Minute)
	o.Now = func() time.Time { return then }
	fc.cs.PrependReactor("create", "serviceaccounts", func(a k8stesting.Action) (bool, runtime.Object, error) {
		tr := a.(k8stesting.CreateActionImpl).GetObject().(*authv1.TokenRequest).DeepCopy()
		tr.Status = authv1.TokenRequestStatus{Token: "t", ExpirationTimestamp: metav1.NewTime(then.Add(time.Hour))}
		return true, tr, nil
	})
	if err := Run(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if got := reaperDeadline(t, fc); !got.Equal(then.Add(time.Hour)) {
		t.Errorf("deadline %v, want the new token's expiry", got)
	}
}

func TestRerunAfterAFailedSetupKeepsOnlyTokenExpiries(t *testing.T) {
	h := newHarness(t)
	fc := h.clusters["wl1"]
	long := h.options(wl1)
	long.TTL = 2 * time.Hour
	if err := Run(context.Background(), long); err != nil {
		t.Fatal(err)
	}
	fc.reaper = func(d *appsv1.Deployment) { d.Status.AvailableReplicas = 0 }
	failing := h.options(wl1)
	failing.Wait = 0
	if err := Run(context.Background(), failing); err == nil {
		t.Fatal("setup succeeded without a ready reaper")
	}
	if got := reaperDeadline(t, fc); !got.Equal(now.Add(2 * time.Hour)) {
		t.Errorf("deadline after the failed setup %v, want the first token's expiry", got)
	}
	fc.reaper = nil
	if err := Run(context.Background(), h.options(wl1)); err != nil {
		t.Fatal(err)
	}
	if got := reaperDeadline(t, fc); !got.Equal(now.Add(2 * time.Hour)) {
		t.Errorf("deadline %v, want the first token's expiry", got)
	}
}

func TestRunFailsBeforeMintingTokensWhenTheReaperIsNotReady(t *testing.T) {
	cases := map[string]func(*appsv1.Deployment){
		"unavailable":     func(d *appsv1.Deployment) { d.Status.AvailableReplicas, d.Status.ReadyReplicas = 0, 0 },
		"stale status":    func(d *appsv1.Deployment) { d.Generation = 2 },
		"old pod remains": func(d *appsv1.Deployment) { d.Status.Replicas, d.Status.UpdatedReplicas = 2, 1 },
		"rolling out":     func(d *appsv1.Deployment) { d.Status.UpdatedReplicas = 0 },
	}
	for name, status := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			h.clusters["wl1"].reaper = status
			o := h.options(wl1)
			o.Wait = 20 * time.Millisecond
			err := Run(context.Background(), o)
			if err == nil || !strings.Contains(err.Error(), "wl1: wait for reaper kglance/kglance-reaper: not ready after 20ms") || !strings.Contains(err.Error(), "kglance teardown") {
				t.Fatalf("err %v", err)
			}
			if n := len(h.clusters["wl1"].tokenTTLs) + len(h.clusters["mgmt"].tokenTTLs); n != 0 {
				t.Errorf("minted %d tokens", n)
			}
			if _, err := os.Stat(o.KubeconfigPath); !os.IsNotExist(err) {
				t.Errorf("kubeconfig written: %v", err)
			}
			ctx := context.Background()
			if _, err := h.clusters["wl1"].cs.AppsV1().DaemonSets(kube.Namespace).Get(ctx, kube.CollectorDS, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
				t.Errorf("collector applied: %v", err)
			}
			if _, err := h.clusters["wl1"].cs.RbacV1().ClusterRoles().Get(ctx, kube.AgentViewRole, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
				t.Errorf("agent ClusterRole applied: %v", err)
			}
			if _, err := h.clusters["mgmt"].cs.CoreV1().ServiceAccounts("ns1").Get(ctx, kube.AgentSA, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
				t.Errorf("mgmt ServiceAccount applied: %v", err)
			}
		})
	}
}

// unreadyReaper makes the reaper Deployment unavailable with pods named reaper-0, reaper-1, ...
func unreadyReaper(fc *fakeCluster, pods ...corev1.PodStatus) {
	fc.reaper = func(d *appsv1.Deployment) { d.Status.AvailableReplicas = 0 }
	for i, status := range pods {
		fc.cs.Tracker().Add(&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("reaper-%d", i), Namespace: kube.Namespace, Labels: map[string]string{kube.NameLabel: kube.ReaperDeployment}},
			Status:     status,
		})
	}
}

func reaperEvent(name, pod, reason, message string, at time.Time) *corev1.Event {
	return &corev1.Event{
		ObjectMeta:     metav1.ObjectMeta{Name: name, Namespace: kube.Namespace},
		InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: pod},
		Reason:         reason, Message: message, LastTimestamp: metav1.NewTime(at),
	}
}

func TestRunNamesTheReasonTheReaperIsWaiting(t *testing.T) {
	h := newHarness(t)
	fc := h.clusters["wl1"]
	unreadyReaper(fc, corev1.PodStatus{}, corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{
		State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff", Message: "back-off 10s"}},
	}}})
	fc.cs.Tracker().Add(reaperEvent("a", "reaper-0", "Unhealthy", "Readiness probe failed", now))
	o := h.options(wl1)
	o.Wait = 20 * time.Millisecond
	if err := Run(context.Background(), o); err == nil || !strings.Contains(err.Error(), "; pod reaper-1 is waiting: CrashLoopBackOff: back-off 10s;") {
		t.Fatalf("err %v", err)
	}
}

func TestRunNamesTheReaperCheckFailure(t *testing.T) {
	h := newHarness(t)
	fc := h.clusters["wl1"]
	ready := corev1.PodStatus{Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}
	unreadyReaper(fc, ready, corev1.PodStatus{})
	// The fake lists events by name.
	for _, e := range []*corev1.Event{
		reaperEvent("a", "reaper-1", "Unhealthy", "Readiness probe failed: old", now.Add(-time.Minute)),
		reaperEvent("b", "reaper-1", "Unhealthy", "Readiness probe failed: kglance reap: denied by policy", now),
		reaperEvent("c", "reaper-1", "Unhealthy", "Readiness probe failed: older", now.Add(-2*time.Minute)),
		reaperEvent("d", "reaper-1", "Pulled", "Container image pulled", now.Add(time.Minute)),
		reaperEvent("e", "collector-1", "Unhealthy", "Readiness probe failed: collector", now.Add(time.Minute)),
		reaperEvent("f", "reaper-0", "Unhealthy", "Readiness probe failed: before it was ready", now.Add(time.Minute)),
	} {
		fc.cs.Tracker().Add(e)
	}
	o := h.options(wl1)
	o.Wait = 20 * time.Millisecond
	if err := Run(context.Background(), o); err == nil || !strings.Contains(err.Error(), "; pod reaper-1: Readiness probe failed: kglance reap: denied by policy;") {
		t.Fatalf("err %v", err)
	}
}

func TestRunReportsAnUnreadyReaperWithoutSayingWhyIfItCannotTell(t *testing.T) {
	for _, resource := range []string{"pods", "events"} {
		t.Run(resource, func(t *testing.T) {
			h := newHarness(t)
			fc := h.clusters["wl1"]
			unreadyReaper(fc, corev1.PodStatus{})
			fc.cs.PrependReactor("list", resource, func(k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, errors.New("denied")
			})
			o := h.options(wl1)
			o.Wait = 20 * time.Millisecond
			if err := Run(context.Background(), o); err == nil || !strings.Contains(err.Error(), "not ready after 20ms; run kglance teardown") {
				t.Fatalf("err %v", err)
			}
		})
	}
}

func TestRunStopsWaitingForTheReaperWhenCancelled(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	h.clusters["wl1"].reaper = func(d *appsv1.Deployment) {
		d.Status.AvailableReplicas = 0
		cancel()
	}
	o := h.options(wl1)
	o.Wait = time.Hour
	if err := Run(ctx, o); !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v", err)
	}
}

func TestRunFailsWhenTheNamespaceStartsTerminatingDuringSetup(t *testing.T) {
	h := newHarness(t)
	fc := h.clusters["wl1"]
	fc.cs.PrependReactor("get", "namespaces", func(a k8stesting.Action) (bool, runtime.Object, error) {
		obj, err := fc.cs.Tracker().Get(corev1.SchemeGroupVersion.WithResource("namespaces"), "", kube.Namespace)
		if err != nil {
			return false, nil, nil
		}
		// The reaper deleted the namespace just after setup applied it.
		ns := obj.(*corev1.Namespace).DeepCopy()
		ns.DeletionTimestamp = &metav1.Time{Time: now}
		return true, ns, nil
	})
	err := Run(context.Background(), h.options(wl1))
	if err == nil || !strings.Contains(err.Error(), "wl1: namespace kglance changed during setup") {
		t.Fatalf("err %v", err)
	}
}

func TestRunSuggestsTeardownOnceAnyClusterHasObjects(t *testing.T) {
	h := newHarness(t)
	h.clusters["mgmt"].cs.PrependReactor("patch", "serviceaccounts", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("denied")
	})
	err := Run(context.Background(), h.options(wl1))
	if err == nil || !strings.Contains(err.Error(), "mgmt: apply ServiceAccount ns1/kglance-agent: denied; run kglance teardown") {
		t.Fatalf("err %v", err)
	}
}

func changeNamespaceWhenMinting(t *testing.T, fc *fakeCluster, change func(*corev1.Namespace)) {
	fc.cs.PrependReactor("create", "serviceaccounts", func(k8stesting.Action) (bool, runtime.Object, error) {
		gvr := corev1.SchemeGroupVersion.WithResource("namespaces")
		obj, err := fc.cs.Tracker().Get(gvr, "", kube.Namespace)
		if err != nil {
			t.Fatal(err)
		}
		ns := obj.(*corev1.Namespace).DeepCopy()
		change(ns)
		if err := fc.cs.Tracker().Update(gvr, ns, ""); err != nil {
			t.Fatal(err)
		}
		return false, nil, nil
	})
}

func TestRunDoesNotArmANamespaceThatChangedAfterMinting(t *testing.T) {
	for name, change := range map[string]func(*corev1.Namespace){
		"recreated":   func(ns *corev1.Namespace) { ns.UID = "someone-else" },
		"terminating": func(ns *corev1.Namespace) { ns.DeletionTimestamp = &metav1.Time{Time: now} },
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			fc := h.clusters["wl1"]
			changeNamespaceWhenMinting(t, fc, change)
			o := h.options(wl1)
			err := Run(context.Background(), o)
			if err == nil || !strings.Contains(err.Error(), "wl1: set reaper deadline: namespace kglance changed during setup") {
				t.Fatalf("err %v", err)
			}
			if got := reaperDeadline(t, fc); !got.Equal(now.Add(o.Wait + time.Hour)) {
				t.Errorf("deadline %v", got)
			}
			if _, err := os.Stat(o.KubeconfigPath); !os.IsNotExist(err) {
				t.Errorf("kubeconfig written: %v", err)
			}
		})
	}
}

func TestRunLetsTheReaperRemoveWhatAFailedSetupApplied(t *testing.T) {
	for name, tt := range map[string]struct {
		fail       func(*harness, *Options)
		wantStderr string
	}{
		"collector denied": {fail: func(h *harness, o *Options) { failDaemonSetApply(h.clusters["wl1"]) }},
		"kubeconfig not written": {fail: func(h *harness, o *Options) {
			o.KubeconfigPath = filepath.Join(h.dir, "missing", "agent.kubeconfig")
		}},
		"a later deadline not set": {
			fail: func(h *harness, o *Options) {
				changeNamespaceWhenMinting(h.t, h.clusters["wl2"], func(ns *corev1.Namespace) { ns.UID = "someone-else" })
			},
			wantStderr: "warning: wl2: shorten reaper deadline: namespace kglance changed during setup",
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			o := h.options(wl1, wl2)
			tt.fail(h, &o)
			if err := Run(context.Background(), o); err == nil {
				t.Fatal("setup succeeded")
			}
			fc := h.clusters["wl1"]
			if got := reaperDeadline(t, fc); !got.Equal(now) {
				t.Errorf("deadline %v, want now", got)
			}
			ns, err := fc.cs.CoreV1().Namespaces().Get(context.Background(), kube.Namespace, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if at, ok := ns.Annotations[kube.TokensExpireAtAnnotation]; ok {
				t.Errorf("token expiry %s", at)
			}
			if !strings.Contains(h.err.String(), tt.wantStderr) {
				t.Errorf("stderr %q", h.err.String())
			}
		})
	}
}

func TestRunReadsEveryWorkloadNamespaceBeforeApplyingAnything(t *testing.T) {
	h := newHarness(t)
	h.clusters["wl2"].cs.PrependReactor("get", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("apiserver down")
	})
	if err := Run(context.Background(), h.options(wl1, wl2)); err == nil || err.Error() != "wl2: apiserver down" {
		t.Fatalf("err %v", err)
	}
	for name, fc := range h.clusters {
		for _, a := range fc.cs.Actions() {
			if a.GetVerb() == "patch" {
				t.Errorf("%s: patched %s", name, a.GetResource().Resource)
			}
		}
	}
}

func TestRunWaitsForTheReaper(t *testing.T) {
	h := newHarness(t)
	gets := 0
	h.clusters["wl1"].reaper = func(d *appsv1.Deployment) {
		if gets++; gets < 3 {
			d.Status.AvailableReplicas = 0
		}
	}
	if err := Run(context.Background(), h.options(wl1)); err != nil {
		t.Fatal(err)
	}
	if gets != 3 {
		t.Errorf("reaper checked %d times", gets)
	}
}

func TestRunWaitsForTheCollectors(t *testing.T) {
	h := newHarness(t)
	gets := 0
	h.clusters["wl1"].status = func(s *appsv1.DaemonSetStatus) {
		if gets++; gets < 3 {
			s.NumberReady = 1
		}
	}
	if err := Run(context.Background(), h.options(wl1)); err != nil {
		t.Fatal(err)
	}
	if gets != 3 {
		t.Errorf("collectors checked %d times", gets)
	}
}

func TestRunDoesNotWriteKubeconfigWhenArmingTheReaperFails(t *testing.T) {
	h := newHarness(t)
	fc := h.clusters["wl1"]
	fc.cs.PrependReactor("create", "serviceaccounts", func(k8stesting.Action) (bool, runtime.Object, error) {
		fc.cs.PrependReactor("patch", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("webhook down")
		})
		return false, nil, nil
	})
	o := h.options(wl1)
	err := Run(context.Background(), o)
	if err == nil || !strings.Contains(err.Error(), "wl1: set reaper deadline") || !strings.Contains(err.Error(), "webhook down") {
		t.Fatalf("err %v", err)
	}
	if _, err := os.Stat(o.KubeconfigPath); !os.IsNotExist(err) {
		t.Errorf("kubeconfig written: %v", err)
	}
}

// staleOwners refer to a namespace that garbage collection has not yet seen deleted.
var staleOwners = []metav1.OwnerReference{{APIVersion: "v1", Kind: "Namespace", Name: kube.Namespace, UID: "gone"}}

func addStaleAgentViewRBAC(fc *fakeCluster) {
	managed := map[string]string{kube.ManagedByLabel: kube.ManagedByValue}
	fc.cs.Tracker().Add(&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: kube.AgentViewRole, UID: "cr-1", Labels: managed, OwnerReferences: staleOwners}})
	fc.cs.Tracker().Add(&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: kube.AgentViewRole, UID: "crb-1", Labels: managed, OwnerReferences: staleOwners}})
}

func TestRunReplacesClusterObjectsOwnedByAnEarlierNamespace(t *testing.T) {
	h := newHarness(t)
	fc := h.clusters["wl1"]
	addStaleAgentViewRBAC(fc)
	managed := map[string]string{kube.ManagedByLabel: kube.ManagedByValue}
	for _, obj := range []runtime.Object{
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "kglance-collector", UID: "cr-2", Labels: managed}},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "unrelated", UID: "cr-3", OwnerReferences: staleOwners}},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "owned-by-other-namespace", UID: "cr-4", Labels: managed,
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Namespace", Name: "other", UID: "gone"}}}},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "owned-by-other-kind", UID: "cr-5", Labels: managed,
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "ConfigMap", Name: kube.Namespace, UID: "gone"}}}},
	} {
		fc.cs.Tracker().Add(obj)
	}
	var deleted []string
	for _, res := range []string{"clusterroles", "clusterrolebindings"} {
		fc.cs.PrependReactor("delete", res, func(a k8stesting.Action) (bool, runtime.Object, error) {
			d := a.(k8stesting.DeleteActionImpl)
			if p := d.DeleteOptions.Preconditions; p == nil || p.UID == nil {
				t.Errorf("delete %s without UID precondition", d.Name)
			} else {
				deleted = append(deleted, res+"/"+d.Name+"/"+string(*p.UID))
			}
			return false, nil, nil
		})
	}
	if err := Run(context.Background(), h.options(wl1)); err != nil {
		t.Fatal(err)
	}
	want := []string{"clusterrolebindings/kglance-agent-view/crb-1", "clusterroles/kglance-agent-view/cr-1"}
	if !slices.Equal(deleted, want) {
		t.Errorf("deleted %v, want %v", deleted, want)
	}
	for _, name := range []string{kube.AgentViewRole, "kglance-collector"} {
		cr, err := fc.cs.RbacV1().ClusterRoles().Get(context.Background(), name, metav1.GetOptions{})
		if err != nil || len(cr.OwnerReferences) != 1 || cr.OwnerReferences[0].UID != "ns-uid-1" {
			t.Errorf("%s: %+v %v", name, cr, err)
		}
	}
}

func TestRerunKeepsClusterObjectsOwnedByTheCurrentNamespace(t *testing.T) {
	h := newHarness(t)
	if err := Run(context.Background(), h.options(wl1)); err != nil {
		t.Fatal(err)
	}
	fc := h.clusters["wl1"]
	fc.cs.ClearActions()
	if err := Run(context.Background(), h.options(wl1)); err != nil {
		t.Fatal(err)
	}
	for _, a := range fc.cs.Actions() {
		if a.GetVerb() == "delete" {
			t.Errorf("deleted %s", a.GetResource().Resource)
		}
	}
}

func TestRunToleratesGarbageCollectionDeletingStaleObjectsFirst(t *testing.T) {
	h := newHarness(t)
	fc := h.clusters["wl1"]
	addStaleAgentViewRBAC(fc)
	fc.cs.PrependReactor("delete", "clusterroles", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewNotFound(rbacv1.Resource("clusterroles"), kube.AgentViewRole)
	})
	fc.cs.PrependReactor("delete", "clusterrolebindings", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewConflict(rbacv1.Resource("clusterrolebindings"), kube.AgentViewRole, errors.New("uid changed"))
	})
	if err := Run(context.Background(), h.options(wl1)); err != nil {
		t.Fatal(err)
	}
}

func TestRunFailsWhenStaleObjectsCannotBeRemoved(t *testing.T) {
	for _, res := range []string{"clusterroles", "clusterrolebindings"} {
		for _, verb := range []string{"list", "delete"} {
			t.Run(verb+" "+res, func(t *testing.T) {
				h := newHarness(t)
				fc := h.clusters["wl1"]
				addStaleAgentViewRBAC(fc)
				fc.cs.PrependReactor(verb, res, func(k8stesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("denied")
				})
				if err := Run(context.Background(), h.options(wl1)); err == nil || !strings.Contains(err.Error(), "denied") {
					t.Fatalf("err %v", err)
				}
			})
		}
	}
}

func TestRunFailsWhenTheReaperCannotBeRead(t *testing.T) {
	h := newHarness(t)
	fc := h.clusters["wl1"]
	fc.cs.PrependReactor("get", "deployments", func(k8stesting.Action) (bool, runtime.Object, error) {
		// Fail only after setup applied the reaper, so that its ownership check still passes.
		if _, err := fc.cs.Tracker().Get(appsv1.SchemeGroupVersion.WithResource("deployments"), kube.Namespace, kube.ReaperDeployment); err != nil {
			return false, nil, nil
		}
		return true, nil, errors.New("timeout")
	})
	if err := Run(context.Background(), h.options(wl1)); err == nil || !strings.Contains(err.Error(), "wl1: wait for reaper kglance/kglance-reaper: timeout") {
		t.Fatalf("err %v", err)
	}
}

func TestRunIgnoresATokenExpiryBeyondMaxTTL(t *testing.T) {
	h := newHarness(t)
	fc := h.clusters["wl1"]
	ns := kube.NamespaceObject(now.Add(MaxTTL+time.Second), now.Add(MaxTTL+time.Second))
	ns.UID = "ns-uid-0"
	fc.cs.Tracker().Add(ns)
	if err := Run(context.Background(), h.options(wl1)); err != nil {
		t.Fatal(err)
	}
	if got := reaperDeadline(t, fc); !got.Equal(now.Add(time.Hour)) {
		t.Errorf("deadline %v", got)
	}
}
