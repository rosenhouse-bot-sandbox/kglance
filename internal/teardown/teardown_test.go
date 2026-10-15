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
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rosenhouse-bot-sandbox/kglance/internal/kube"
	"github.com/rosenhouse-bot-sandbox/kglance/internal/state"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
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
	clusters map[string]*fakeCluster
	st       *state.File
	out, err bytes.Buffer
}

func newHarness(t *testing.T, names ...string) *harness {
	h := &harness{dir: t.TempDir(), clusters: map[string]*fakeCluster{}}
	h.st = &state.File{Version: state.Version, Kubeconfig: filepath.Join(h.dir, "agent.kubeconfig")}
	os.WriteFile(h.st.Kubeconfig, []byte("x"), 0o600)
	for _, name := range names {
		fc := &fakeCluster{
			cs: fake.NewClientset(
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
				&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "unrelated"}},
			),
			server: "https://" + name + ":6443", ca: caPEM(t),
		}
		h.clusters[name+"-ctx"] = fc
		rec := state.Cluster{Name: name, Role: state.RoleWorkload, Context: name + "-ctx", Server: fc.server}
		rec.CAFingerprint, _ = state.Fingerprint(fc.ca)
		for _, o := range kube.WorkloadObjects(nil, kube.DaemonSetOptions{Image: "i", Interval: time.Minute}) {
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

func (h *harness) options(t *testing.T) Options {
	path := filepath.Join(h.dir, "kglance.state.json")
	if err := state.Save(path, h.st); err != nil {
		t.Fatal(err)
	}
	return Options{
		StatePath: path,
		Out:       &h.out,
		Err:       &h.err,
		Connect: func(ctxName string) (*kube.Conn, error) {
			c, ok := h.clusters[ctxName]
			if !ok {
				return nil, fmt.Errorf("context %q not found", ctxName)
			}
			return &kube.Conn{Context: ctxName, Client: c.cs, Cluster: &clientcmdapi.Cluster{Server: c.server, CertificateAuthorityData: c.ca}}, nil
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
	errs := []error{dsErr, crErr, crbErr, saErr, nsErr}
	for _, err := range errs {
		if err != nil && !apierrors.IsNotFound(err) {
			t.Fatal(err)
		}
	}
	if dsErr == nil && crErr == nil && crbErr == nil && saErr == nil && nsErr == nil {
		return true
	}
	if apierrors.IsNotFound(dsErr) && apierrors.IsNotFound(crErr) && apierrors.IsNotFound(crbErr) && apierrors.IsNotFound(saErr) && apierrors.IsNotFound(nsErr) {
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
				h.clusters["wl1-ctx"].server = "https://elsewhere:6443"
			} else {
				h.clusters["wl1-ctx"].ca = caPEM(t)
			}
			o := h.options(t)
			err := Run(context.Background(), o)
			if err == nil {
				t.Fatal("expected error")
			}
			if !installed(t, h.clusters["wl1-ctx"].cs) {
				t.Error("deleted from tampered cluster")
			}
			if installed(t, h.clusters["wl2-ctx"].cs) {
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

func TestRunByContextDeletesLabelledObjectsOnly(t *testing.T) {
	h := newHarness(t, "wl1", "wl2")
	o := h.options(t)
	os.Remove(o.StatePath)
	o.Contexts = []string{"wl1-ctx"}
	if err := Run(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if installed(t, h.clusters["wl1-ctx"].cs) {
		t.Error("wl1 still installed")
	}
	unrelatedIntact(t, h.clusters["wl1-ctx"].cs)
	if !installed(t, h.clusters["wl2-ctx"].cs) {
		t.Error("wl2 touched")
	}
	if !strings.Contains(h.out.String(), "removing kglance from context wl1-ctx ... done") {
		t.Errorf("out %q", h.out.String())
	}
}
