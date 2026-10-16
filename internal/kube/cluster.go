package kube

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
)

// SplitClusterRef parses a Cluster API Cluster reference "namespace/name".
func SplitClusterRef(ref string) (namespace, name string, err error) {
	namespace, name, _ = strings.Cut(ref, "/")
	if len(validation.IsDNS1123Label(namespace)) > 0 || len(validation.IsDNS1123Subdomain(name)) > 0 {
		return "", "", fmt.Errorf("invalid Cluster %q: want namespace/name", ref)
	}
	return namespace, name, nil
}

// ClusterKubeconfig reads the admin kubeconfig that Cluster API stores in the Secret <name>-kubeconfig.
func ClusterKubeconfig(ctx context.Context, mgmt kubernetes.Interface, ref string) ([]byte, error) {
	namespace, name, err := SplitClusterRef(ref)
	if err != nil {
		return nil, err
	}
	secret := name + "-kubeconfig"
	s, err := mgmt.CoreV1().Secrets(namespace).Get(ctx, secret, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("read kubeconfig Secret %s/%s of Cluster %s: %w", namespace, secret, ref, err)
	}
	data := s.Data["value"]
	if len(data) == 0 {
		return nil, fmt.Errorf("kubeconfig Secret %s/%s has no %q key", namespace, secret, "value")
	}
	return data, nil
}
