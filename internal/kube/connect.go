package kube

import (
	"fmt"
	"os"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// Conn is an admin connection to one kubeconfig context.
type Conn struct {
	Context string
	Client  kubernetes.Interface
	// Cluster is the context's cluster entry with any CA file inlined.
	Cluster *clientcmdapi.Cluster
}

// Connect loads context from kubeconfigPath, or from $KUBECONFIG and the default path when it is empty.
func Connect(kubeconfigPath, context string) (*Conn, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	rules.ExplicitPath = kubeconfigPath
	loader := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{CurrentContext: context})
	raw, err := loader.RawConfig()
	if err != nil {
		return nil, err
	}
	kctx, ok := raw.Contexts[context]
	if !ok {
		return nil, fmt.Errorf("context %q not found in kubeconfig", context)
	}
	cluster, ok := raw.Clusters[kctx.Cluster]
	if !ok {
		return nil, fmt.Errorf("context %q: cluster %q not found in kubeconfig", context, kctx.Cluster)
	}
	cluster = cluster.DeepCopy()
	if cluster.CertificateAuthority != "" {
		data, err := os.ReadFile(cluster.CertificateAuthority)
		if err != nil {
			return nil, fmt.Errorf("context %q: %w", context, err)
		}
		cluster.CertificateAuthorityData, cluster.CertificateAuthority = data, ""
	}
	rc, err := loader.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("context %q: %w", context, err)
	}
	rc.QPS, rc.Burst = 50, 100
	cs, err := kubernetes.NewForConfig(rc)
	if err != nil {
		return nil, err
	}
	return &Conn{Context: context, Client: cs, Cluster: cluster}, nil
}
