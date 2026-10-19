package setup

import (
	"fmt"
	"strings"
	"time"

	"github.com/rosenhouse-bot-sandbox/kglance/internal/kube"
)

// Instructions is the short guide handed to the agent with the kubeconfig.
func Instructions(kubeconfig string, expiry time.Time, mgmtNamespace string, workloads []Workload) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Read-only Kubernetes access via kglance. The tokens expire at %s.\n\n", expiry.UTC().Format("2006-01-02 15:04 UTC"))
	fmt.Fprintf(&b, "  export KUBECONFIG=%s\n\nContexts:\n", kubeconfig)
	fmt.Fprintf(&b, "  %-12s management cluster: Cluster API objects and events in namespace %s\n", MgmtName, mgmtNamespace)
	for _, w := range workloads {
		fmt.Fprintf(&b, "  %-12s workload cluster %s/%s: view, events, node socket snapshots\n", w.Name, mgmtNamespace, w.Cluster)
	}
	if len(workloads) > 0 {
		b.WriteString("\nEach workload node publishes its listening TCP/UDP sockets to a ConfigMap. To pull them:\n\n")
		for _, w := range workloads {
			fmt.Fprintf(&b, "  kubectl --context %s -n %s get configmaps -l %s \\\n", w.Name, kube.Namespace, kube.SnapshotLabel)
			fmt.Fprintf(&b, "    -o go-template='{{range .items}}{{index .data \"sockets.jsonl\"}}{{end}}' > %s-sockets.jsonl\n", w.Name)
		}
		b.WriteString("\nEach line is one JSON socket row that names its cluster and node, so files from several clusters concatenate.\n")
		b.WriteString("The raw.txt key holds the same data as an ss-style table.\n")
		fmt.Fprintf(&b, "A ConfigMap annotated %s holds only some of its node's rows.\n", kube.TruncatedAnnotation)
	}
	b.WriteString("\nAccess is read-only. Secrets, pod logs, exec, port-forward and writes are forbidden.\n")
	return b.String()
}
