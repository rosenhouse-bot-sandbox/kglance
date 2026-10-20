package teardown

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
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

func caPEM(t *testing.T) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}, NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

type fakeCluster struct {
	cs     *fake.Clientset
	server string
	ca     []byte
}

type harness struct {
	dir      string
	mgmt     *fake.Clientset
	clusters map[string]*fakeCluster
	st       *state.File
	out, err bytes.Buffer
}

// newHarness installs kglance on a workload cluster per name, each recorded by its Cluster API reference ns1/<name>.
func newHarness(t *testing.T, names ...string) *harness {
	h := &harness{dir: t.TempDir(), mgmt: fake.NewClientset(), clusters: map[string]*fakeCluster{}}
	h.st = &state.File{Version: state.Version, Kubeconfig: filepath.Join(h.dir, "agent.kubeconfig")}
	os.WriteFile(h.st.Kubeconfig, agentKubeconfig(names...), 0o600)
	for _, name := range names {
		fc := &fakeCluster{
			cs: fake.NewClientset(
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
				&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "unrelated"}},
			),
			server: "https://" + name + ":6443", ca: caPEM(t),
		}
		h.clusters[name] = fc
		rec := state.Cluster{Name: name, Role: state.RoleWorkload, Context: "mgmt-ctx", ClusterRef: "ns1/" + name, Server: fc.server}
		rec.CAFingerprint, _ = state.Fingerprint(fc.ca)
		ns := kube.NamespaceObject(time.Now(), time.Time{})
		for _, o := range slices.Concat([]kube.Object{ns}, kube.ReaperObjects("i"), kube.WorkloadObjects(ns, nil, kube.DaemonSetOptions{Image: "i", Interval: time.Minute})) {
			if err := kube.Apply(context.Background(), fc.cs, o); err != nil {
				t.Fatal(err)
			}
			gvk := o.GetObjectKind().GroupVersionKind()
			rec.Objects = append(rec.Objects, state.Object{APIVersion: gvk.GroupVersion().String(), Kind: gvk.Kind, Namespace: o.GetNamespace(), Name: o.GetName()})
		}
		h.st.Clusters = append(h.st.Clusters, rec)
	}
	return h
}

// writeKubeconfigSecrets stores each workload's current server and CA in its Cluster API kubeconfig Secret on mgmt.
func (h *harness) writeKubeconfigSecrets(t *testing.T) {
	for name, fc := range h.clusters {
		cfg := clientcmdapi.NewConfig()
		cfg.Clusters[name] = &clientcmdapi.Cluster{Server: fc.server, CertificateAuthorityData: fc.ca}
		cfg.AuthInfos["admin"] = &clientcmdapi.AuthInfo{Token: "admin"}
		cfg.Contexts["admin"] = &clientcmdapi.Context{Cluster: name, AuthInfo: "admin"}
		cfg.CurrentContext = "admin"
		data, err := clientcmd.Write(*cfg)
		if err != nil {
			t.Fatal(err)
		}
		h.mgmt.Tracker().Add(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "ns1", Name: name + "-kubeconfig"}, Data: map[string][]byte{"value": data}})
	}
}

func agentKubeconfig(names ...string) []byte {
	cfg := clientcmdapi.NewConfig()
	for _, n := range names {
		cfg.Clusters[n] = &clientcmdapi.Cluster{Server: "https://" + n + ":6443"}
		cfg.AuthInfos[n] = &clientcmdapi.AuthInfo{Token: "tok"}
		cfg.Contexts[n] = &clientcmdapi.Context{Cluster: n, AuthInfo: n}
	}
	b, err := clientcmd.Write(*cfg)
	if err != nil {
		panic(err)
	}
	return b
}

func (h *harness) options(t *testing.T) Options {
	path := filepath.Join(h.dir, "kglance.state.json")
	if err := state.Save(path, h.st); err != nil {
		t.Fatal(err)
	}
	h.writeKubeconfigSecrets(t)
	conn := func(name string, fc *fakeCluster) *kube.Conn {
		return &kube.Conn{Context: name, Client: fc.cs, Cluster: &clientcmdapi.Cluster{Server: fc.server, CertificateAuthorityData: fc.ca}}
	}
	return Options{
		StatePath: path,
		Out:       &h.out,
		Err:       &h.err,
		Connect: func(ctxName string) (*kube.Conn, error) {
			if ctxName == "" || ctxName == "mgmt-ctx" {
				return &kube.Conn{Context: "mgmt-ctx", Client: h.mgmt, Cluster: &clientcmdapi.Cluster{Server: "https://mgmt:6443"}}, nil
			}
			if c, ok := h.clusters[strings.TrimSuffix(ctxName, "-ctx")]; ok {
				return conn(ctxName, c), nil
			}
			return nil, fmt.Errorf("context %q not found", ctxName)
		},
		ConnectKubeconfig: func(data []byte) (*kube.Conn, error) {
			cfg, err := clientcmd.Load(data)
			if err != nil {
				return nil, err
			}
			name := cfg.Contexts[cfg.CurrentContext].Cluster
			c := cfg.Clusters[name]
			return &kube.Conn{Client: h.clusters[name].cs, Cluster: c}, nil
		},
	}
}

func installed(t *testing.T, cs *fake.Clientset) bool {
	ctx := context.Background()
	_, dsErr := cs.AppsV1().DaemonSets(kube.Namespace).Get(ctx, kube.CollectorDS, metav1.GetOptions{})
	_, crErr := cs.RbacV1().ClusterRoles().Get(ctx, kube.AgentViewRole, metav1.GetOptions{})
	_, crbErr := cs.RbacV1().ClusterRoleBindings().Get(ctx, kube.AgentViewRole, metav1.GetOptions{})
	_, saErr := cs.CoreV1().ServiceAccounts(kube.Namespace).Get(ctx, kube.AgentSA, metav1.GetOptions{})
	_, nsErr := cs.CoreV1().Namespaces().Get(ctx, kube.Namespace, metav1.GetOptions{})
	_, reaperErr := cs.AppsV1().Deployments(kube.Namespace).Get(ctx, kube.ReaperDeployment, metav1.GetOptions{})
	errs := []error{dsErr, crErr, crbErr, saErr, nsErr, reaperErr}
	for _, err := range errs {
		if err != nil && !apierrors.IsNotFound(err) {
			t.Fatal(err)
		}
	}
	if !slices.ContainsFunc(errs, func(err error) bool { return err != nil }) {
		return true
	}
	if !slices.ContainsFunc(errs, func(err error) bool { return err == nil }) {
		return false
	}
	t.Fatalf("partially installed: %v", errs)
	return false
}

func unrelatedIntact(t *testing.T, cs *fake.Clientset) {
	ctx := context.Background()
	if _, err := cs.RbacV1().ClusterRoles().Get(ctx, "unrelated", metav1.GetOptions{}); err != nil {
		t.Error("unrelated ClusterRole deleted")
	}
	if _, err := cs.CoreV1().Namespaces().Get(ctx, "default", metav1.GetOptions{}); err != nil {
		t.Error("default namespace deleted")
	}
}

func TestRunRemovesRecordedObjectsAndFiles(t *testing.T) {
	h := newHarness(t, "wl1", "wl2")
	o := h.options(t)
	if err := Run(context.Background(), o); err != nil {
		t.Fatalf("%v\n%s", err, h.err.String())
	}
	for _, c := range h.clusters {
		if installed(t, c.cs) {
			t.Error("still installed")
		}
		unrelatedIntact(t, c.cs)
	}
	if want := "read " + o.StatePath + ": removing kglance from wl1, wl2 ... done\n"; h.out.String() != want {
		t.Errorf("out %q want %q", h.out.String(), want)
	}
	for _, p := range []string{o.StatePath, h.st.Kubeconfig} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s not removed", p)
		}
	}
}

func TestRunIsIdempotentWhenObjectsAlreadyGone(t *testing.T) {
	h := newHarness(t, "wl1")
	o := h.options(t)
	Run(context.Background(), o)
	h.options(t)
	if err := Run(context.Background(), o); err != nil {
		t.Fatal(err)
	}
}

func TestRunRefusesClusterWhoseServerOrCAChanged(t *testing.T) {
	for _, tamper := range []string{"server", "ca"} {
		t.Run(tamper, func(t *testing.T) {
			h := newHarness(t, "wl1", "wl2")
			if tamper == "server" {
				h.clusters["wl1"].server = "https://elsewhere:6443"
			} else {
				h.clusters["wl1"].ca = caPEM(t)
			}
			o := h.options(t)
			err := Run(context.Background(), o)
			if err == nil {
				t.Fatal("expected error")
			}
			if !installed(t, h.clusters["wl1"].cs) {
				t.Error("deleted from tampered cluster")
			}
			if installed(t, h.clusters["wl2"].cs) {
				t.Error("healthy cluster not cleaned")
			}
			if !strings.Contains(h.err.String(), "wl1") || !strings.Contains(h.err.String(), "does not match") {
				t.Errorf("stderr %q", h.err.String())
			}
			st, lerr := state.Load(o.StatePath)
			if lerr != nil || len(st.Clusters) != 1 || st.Clusters[0].Name != "wl1" {
				t.Errorf("state %+v %v", st, lerr)
			}
			if _, err := os.Stat(h.st.Kubeconfig); err != nil {
				t.Error("kubeconfig removed despite failure")
			}
		})
	}
}

func TestRunRefusesUnknownContext(t *testing.T) {
	h := newHarness(t, "wl1")
	h.st.Clusters[0].Context = "gone-ctx"
	if err := Run(context.Background(), h.options(t)); err == nil {
		t.Fatal("expected error")
	}
}

func TestRunWithoutStateFileFails(t *testing.T) {
	o := Options{StatePath: filepath.Join(t.TempDir(), "none.json"), Out: &bytes.Buffer{}, Err: &bytes.Buffer{}}
	if err := Run(context.Background(), o); err == nil || !strings.Contains(err.Error(), "--context") {
		t.Fatalf("err %v", err)
	}
}

func TestRunByLabelDeletesLabelledObjectsOnly(t *testing.T) {
	h := newHarness(t, "wl1", "wl2")
	for _, o := range kube.MgmtObjects("ns1", nil) {
		if err := kube.Apply(context.Background(), h.mgmt, o); err != nil {
			t.Fatal(err)
		}
	}
	h.mgmt.PrependReactor("*", "*", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if a.GetNamespace() != "ns1" {
			return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: a.GetResource().Resource}, "", errors.New("outside ns1"))
		}
		return false, nil, nil
	})
	o := h.options(t)
	os.Remove(o.StatePath)
	o.ByLabel, o.MgmtNamespace, o.Workloads = true, "ns1", []string{"wl1"}
	if err := Run(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if installed(t, h.clusters["wl1"].cs) {
		t.Error("wl1 still installed")
	}
	unrelatedIntact(t, h.clusters["wl1"].cs)
	if !installed(t, h.clusters["wl2"].cs) {
		t.Error("wl2 touched")
	}
	ctx := context.Background()
	_, saErr := h.mgmt.CoreV1().ServiceAccounts("ns1").Get(ctx, kube.AgentSA, metav1.GetOptions{})
	_, rErr := h.mgmt.RbacV1().Roles("ns1").Get(ctx, kube.AgentMgmtRole, metav1.GetOptions{})
	_, rbErr := h.mgmt.RbacV1().RoleBindings("ns1").Get(ctx, kube.AgentMgmtRole, metav1.GetOptions{})
	for _, err := range []error{saErr, rErr, rbErr} {
		if !apierrors.IsNotFound(err) {
			t.Errorf("mgmt: %v", err)
		}
	}
	if want := "removing kglance from context mgmt-ctx ... done\nremoving kglance from Cluster ns1/wl1 ... done\n"; h.out.String() != want {
		t.Errorf("out %q want %q", h.out.String(), want)
	}
}

func TestRunByLabelConnectsToGivenContext(t *testing.T) {
	h := newHarness(t, "wl1")
	o := h.options(t)
	os.Remove(o.StatePath)
	o.ByLabel, o.MgmtContext = true, "other-ctx"
	if err := Run(context.Background(), o); err == nil || !strings.Contains(err.Error(), `"other-ctx"`) {
		t.Fatalf("err %v", err)
	}
}

func TestRunByLabelRefusesWhileStateFileExists(t *testing.T) {
	h := newHarness(t, "wl1")
	o := h.options(t)
	o.ByLabel = true
	if err := Run(context.Background(), o); err == nil || !strings.Contains(err.Error(), "run kglance teardown without --context, --workload or --mgmt-namespace") {
		t.Fatalf("err %v", err)
	}
	if !installed(t, h.clusters["wl1"].cs) {
		t.Error("removed objects")
	}
}

func TestRunByLabelReportsUnreachableCluster(t *testing.T) {
	h := newHarness(t, "wl1")
	o := h.options(t)
	os.Remove(o.StatePath)
	o.ByLabel, o.MgmtNamespace, o.Workloads = true, "ns1", []string{"gone", "wl1"}
	err := Run(context.Background(), o)
	if err == nil || !strings.Contains(err.Error(), "Cluster ns1/gone") || !strings.Contains(h.err.String(), "ns1/gone-kubeconfig") {
		t.Fatalf("err %v stderr %q", err, h.err.String())
	}
	if installed(t, h.clusters["wl1"].cs) {
		t.Error("wl1 not cleaned after an earlier failure")
	}
}

func TestRunRemovesClustersRecordedByWorkloadContext(t *testing.T) {
	h := newHarness(t, "wl1")
	h.st.Clusters[0].Context, h.st.Clusters[0].ClusterRef = "wl1-ctx", ""
	o := h.options(t)
	h.mgmt = nil
	if err := Run(context.Background(), o); err != nil {
		t.Fatalf("%v\n%s", err, h.err.String())
	}
	if installed(t, h.clusters["wl1"].cs) {
		t.Error("still installed")
	}
}

func TestRunKeepsClusterWhoseKubeconfigSecretIsGone(t *testing.T) {
	h := newHarness(t, "wl1")
	o := h.options(t)
	h.mgmt.Tracker().Delete(corev1.SchemeGroupVersion.WithResource("secrets"), "ns1", "wl1-kubeconfig")
	if err := Run(context.Background(), o); err == nil {
		t.Fatal("expected error")
	}
	if !installed(t, h.clusters["wl1"].cs) || !strings.Contains(h.err.String(), "if Cluster ns1/wl1 was deleted, remove its record from "+o.StatePath) {
		t.Errorf("stderr %q", h.err.String())
	}
	if st, err := state.Load(o.StatePath); err != nil || len(st.Clusters) != 1 {
		t.Errorf("state %+v %v", st, err)
	}
}

func TestRunSkipsRecordedObjectsNotManagedByKglance(t *testing.T) {
	h := newHarness(t, "wl1")
	h.st.Clusters[0].Objects = append(h.st.Clusters[0].Objects,
		state.Object{APIVersion: "v1", Kind: "Namespace", Name: "default"},
		state.Object{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRole", Name: "unrelated"})
	if err := Run(context.Background(), h.options(t)); err != nil {
		t.Fatalf("%v\n%s", err, h.err.String())
	}
	cs := h.clusters["wl1"].cs
	unrelatedIntact(t, cs)
	if installed(t, cs) {
		t.Error("still installed")
	}
	if !strings.Contains(h.err.String(), "warning: skipped wl1: Namespace default: not managed by kglance\n") {
		t.Errorf("stderr %q", h.err.String())
	}
}

func TestRunKeepsRecordedKubeconfigThatIsNotAnAgentKubeconfig(t *testing.T) {
	admin := `apiVersion: v1
kind: Config
clusters: [{name: wl1, cluster: {server: "https://wl1:6443"}}]
users: [{name: admin, user: {client-certificate-data: Y2VydA==, client-key-data: a2V5}}]
contexts: [{name: wl1, context: {cluster: wl1, user: admin}}]
`
	for name, content := range map[string]string{"admin": admin, "unparsable": "x", "unrecorded context": string(agentKubeconfig("wl1", "other"))} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, "wl1")
			if err := os.WriteFile(h.st.Kubeconfig, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			o := h.options(t)
			if err := Run(context.Background(), o); err != nil {
				t.Fatal(err)
			}
			if b, _ := os.ReadFile(h.st.Kubeconfig); string(b) != content {
				t.Error("kubeconfig removed")
			}
			if _, err := os.Stat(o.StatePath); !os.IsNotExist(err) {
				t.Error("state not removed")
			}
			if !strings.Contains(h.err.String(), "kept "+h.st.Kubeconfig+": not a kglance agent kubeconfig") {
				t.Errorf("stderr %q", h.err.String())
			}
		})
	}
}
