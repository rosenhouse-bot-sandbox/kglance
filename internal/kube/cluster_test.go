package kube

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

const workloadKubeconfig = `apiVersion: v1
kind: Config
clusters:
- name: wl1
  cluster: {server: "https://10.0.0.9:6443", certificate-authority-data: %s}
users:
- name: wl1-admin
  user: {token: admin-token}
contexts:
- name: wl1-admin@wl1
  context: {cluster: wl1, user: wl1-admin}
current-context: wl1-admin@wl1
`

func TestSplitClusterRef(t *testing.T) {
	ns, name, err := SplitClusterRef("ns1/wl1")
	if err != nil || ns != "ns1" || name != "wl1" {
		t.Fatalf("%q %q %v", ns, name, err)
	}
	for _, bad := range []string{"", "wl1", "ns1/", "/wl1", "a/b/c"} {
		if _, _, err := SplitClusterRef(bad); err == nil {
			t.Errorf("%q: expected error", bad)
		}
	}
}

func TestClusterKubeconfigReadsCAPISecret(t *testing.T) {
	cs := fake.NewClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns1", Name: "wl1-kubeconfig"},
		Data:       map[string][]byte{"value": []byte("kubeconfig")},
	}, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns1", Name: "empty-kubeconfig"},
	})
	got, err := ClusterKubeconfig(context.Background(), cs, "ns1/wl1")
	if err != nil || string(got) != "kubeconfig" {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := ClusterKubeconfig(context.Background(), cs, "ns2/wl1"); err == nil || !strings.Contains(err.Error(), "ns2/wl1-kubeconfig") {
		t.Errorf("missing secret: %v", err)
	}
	if _, err := ClusterKubeconfig(context.Background(), cs, "ns1/empty"); err == nil || !strings.Contains(err.Error(), `"value"`) {
		t.Errorf("empty secret: %v", err)
	}
}
