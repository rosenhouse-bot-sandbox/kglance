package setup

import (
	"fmt"
	"strings"
	"time"

	"github.com/rosenhouse-bot-sandbox/kglance/internal/state"
)

// Instructions is the short guide handed to the agent with the kubeconfig.
func Instructions(kubeconfig string, expiry time.Time, targets []Target) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Read-only Kubernetes access via kglance. The tokens expire at %s.\n\n", expiry.UTC().Format("2006-01-02 15:04 UTC"))
	fmt.Fprintf(&b, "  export KUBECONFIG=%s\n\nContexts:\n", kubeconfig)
	var workload string
	for _, t := range targets {
		desc := "workload cluster: view, events, node socket snapshots"
		if t.Role == state.RoleMgmt {
			desc = "management cluster: Cluster API objects, namespaces, nodes, events"
		} else if workload == "" {
			workload = t.Name
		}
		fmt.Fprintf(&b, "  %-12s %s\n", t.Name, desc)
	}
	if workload != "" {
		b.WriteString("\nEach workload node publishes its listening TCP/UDP sockets to a ConfigMap. To pull them:\n\n")
		fmt.Fprintf(&b, "  kubectl --context %s -n kglance get configmaps -l kglance.io/snapshot \\\n", workload)
		fmt.Fprintf(&b, "    -o go-template='{{range .items}}{{index .data \"sockets.jsonl\"}}{{end}}' > %s-sockets.jsonl\n\n", workload)
		b.WriteString("Each line is one JSON socket row that names its cluster and node, so files from several clusters concatenate.\n")
		b.WriteString("The raw.txt key holds the same data as an ss-style table.\n")
	}
	b.WriteString("\nAccess is read-only. Secrets, pod logs, exec, port-forward and writes are forbidden.\n")
	return b.String()
}
