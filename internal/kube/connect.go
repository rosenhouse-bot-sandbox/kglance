package kube

import (
	"errors"
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

// Connect loads context, or the current context when it is empty, from kubeconfigPath,
// or from $KUBECONFIG and the default path when kubeconfigPath is empty.
func Connect(kubeconfigPath, context string) (*Conn, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	rules.ExplicitPath = kubeconfigPath
	raw, err := rules.Load()
	if err != nil {
		return nil, err
	}
	if context == "" {
		context = raw.CurrentContext
	}
	if context == "" {
		return nil, errors.New("no current context in kubeconfig; use --context")
	}
	return connect(raw, context)
}

// ConnectKubeconfig connects to the current context of a kubeconfig that came from a cluster,
// refusing settings that would run commands or read local files.
func ConnectKubeconfig(data []byte) (*Conn, error) {
	cfg, err := clientcmd.Load(data)
	if err != nil {
		return nil, err
	}
	if err := refuseLocalAccess(cfg); err != nil {
		return nil, err
	}
	return connect(cfg, cfg.CurrentContext)
}

func refuseLocalAccess(cfg *clientcmdapi.Config) error {
	for name, u := range cfg.AuthInfos {
		for field, set := range map[string]bool{
			"exec":               u.Exec != nil,
			"auth-provider":      u.AuthProvider != nil,
			"client-certificate": u.ClientCertificate != "",
			"client-key":         u.ClientKey != "",
			"tokenFile":          u.TokenFile != "",
		} {
			if set {
				return fmt.Errorf("user %q sets %s, which kglance does not allow in a cluster's kubeconfig", name, field)
			}
		}
	}
	for name, c := range cfg.Clusters {
		if c.CertificateAuthority != "" {
			return fmt.Errorf("cluster %q sets certificate-authority, which kglance does not allow in a cluster's kubeconfig", name)
		}
	}
	return nil
}

func connect(raw *clientcmdapi.Config, context string) (*Conn, error) {
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
	rc, err := clientcmd.NewNonInteractiveClientConfig(*raw, context, &clientcmd.ConfigOverrides{}, nil).ClientConfig()
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
