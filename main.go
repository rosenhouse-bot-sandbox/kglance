package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/rosenhouse-bot-sandbox/kglance/internal/collector"
	"github.com/rosenhouse-bot-sandbox/kglance/internal/kube"
	"github.com/rosenhouse-bot-sandbox/kglance/internal/setup"
	"github.com/rosenhouse-bot-sandbox/kglance/internal/teardown"
	"github.com/rosenhouse-bot-sandbox/kglance/internal/version"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/tools/clientcmd"
)

const usage = `kglance hands an AI agent expiring, read-only kubectl access to Cluster API clusters.

usage:
  kglance setup --mgmt-namespace namespace [--context context] [--workload [name=]cluster]... [flags]
      Creates read-only service accounts, starts the socket collector and writes an agent kubeconfig.
  kglance teardown [--state file | --mgmt-namespace namespace [--context context] [--workload cluster]...]
      Removes everything setup created and revokes the agent's tokens.
  kglance version
      Prints the version and collector image.
Run "kglance setup -h" or "kglance teardown -h" for flags.
`

const setupHelp = `usage: kglance setup --mgmt-namespace namespace [--context context] [--workload [name=]cluster]... [flags]

Creates read-only service accounts on each cluster, starts the socket collector on
workload clusters, writes a kubeconfig and instructions for the agent.
Re-running setup mints fresh tokens without restarting the collector.

--context, or the current context by default, names the Cluster API management cluster.
Setup changes only the existing namespace --mgmt-namespace on it, and the agent can read
only Cluster API objects and events there. Each --workload names a Cluster in that namespace.
Setup reaches that cluster with the admin kubeconfig in the Cluster's <cluster>-kubeconfig Secret.
The agent kubeconfig has a context "mgmt" and one context per workload, named after the
Cluster unless name= is given.

flags:
`

const teardownHelp = `usage: kglance teardown [--state file | --mgmt-namespace namespace [--context context] [--workload cluster]...]

Removes everything setup created and revokes the agent's tokens.
Without a state file, give the --context, --workload and --mgmt-namespace flags that setup used.
Teardown then removes objects labelled app.kubernetes.io/managed-by=kglance from those clusters.

flags:
`

var collect = collector.Main

// errUsage marks errors that already printed usage.
var errUsage = errors.New("usage")

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func versionInfo() string {
	return fmt.Sprintf("kglance %s\ncollector image %s\n", version.String(), version.Image())
}

func run(args []string, out, errOut io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(errOut, usage)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var err error
	switch args[0] {
	case "setup":
		var o setup.Options
		var kubeconfig string
		if o, kubeconfig, err = parseSetup(args[1:], errOut); err == nil {
			o.Connect, o.ConnectKubeconfig = connector(kubeconfig), kube.ConnectKubeconfig
			o.Now, o.Out, o.Err, o.PollInterval = time.Now, out, errOut, 2*time.Second
			err = setup.Run(ctx, o)
		}
	case "teardown":
		var o teardown.Options
		var kubeconfig string
		if o, kubeconfig, err = parseTeardown(args[1:], errOut); err == nil {
			o.Connect, o.ConnectKubeconfig, o.Out, o.Err = connector(kubeconfig), kube.ConnectKubeconfig, out, errOut
			err = teardown.Run(ctx, o)
		}
	case "collect":
		err = collect(ctx, args[1:])
	case "version", "--version":
		fmt.Fprint(out, versionInfo())
		return 0
	case "-h", "--help", "help":
		fmt.Fprint(out, usage)
		return 0
	default:
		fmt.Fprint(errOut, usage)
		return 2
	}
	switch {
	case errors.Is(err, flag.ErrHelp):
		return 0
	case errors.Is(err, errUsage):
		return 2
	case err != nil:
		fmt.Fprintf(errOut, "kglance %s: %v\n", args[0], err)
		return 1
	}
	return 0
}

func connector(kubeconfig string) func(string) (*kube.Conn, error) {
	return func(context string) (*kube.Conn, error) { return kube.Connect(kubeconfig, context) }
}

// parse runs fs.Parse and wraps non-help failures as usage errors.
func parse(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return fmt.Errorf("%w: %v", errUsage, err)
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(fs.Output(), "unexpected argument %q\n", fs.Arg(0))
		fs.Usage()
		return fmt.Errorf("%w: unexpected argument %q", errUsage, fs.Arg(0))
	}
	return nil
}

func absPath(p string) (string, error) {
	if p == "" {
		return "", nil
	}
	return filepath.Abs(p)
}

func newFlagSet(name, help string, errOut io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(errOut)
	fs.Usage = func() {
		fmt.Fprint(errOut, help)
		fs.PrintDefaults()
	}
	return fs
}

func parseSetup(args []string, errOut io.Writer) (setup.Options, string, error) {
	var o setup.Options
	var workloads listFlag
	var kubeconfig string
	fs := newFlagSet("kglance setup", setupHelp, errOut)
	fs.StringVar(&o.MgmtContext, "context", "", "management cluster's admin context (default the current context)")
	fs.StringVar(&o.MgmtNamespace, "mgmt-namespace", "", "existing management cluster namespace that holds the workload Clusters (required)")
	fs.Var(&workloads, "workload", "workload Cluster as [name=]cluster (repeatable)")
	fs.DurationVar(&o.TTL, "ttl", time.Hour, "agent token lifetime (10m to 8h)")
	fs.StringVar(&o.KubeconfigPath, "output", "agent.kubeconfig", "agent kubeconfig path")
	fs.StringVar(&o.KubeconfigPath, "o", "agent.kubeconfig", "shorthand for --output")
	fs.StringVar(&o.StatePath, "state", "kglance.state.json", "state file path")
	fs.StringVar(&o.Image, "image", version.Image(), "collector image")
	fs.DurationVar(&o.Interval, "interval", time.Minute, "socket snapshot interval")
	fs.StringVar(&o.InstructionsPath, "instructions", "", "also write agent instructions to this file")
	fs.DurationVar(&o.Wait, "wait", 2*time.Minute, "how long to wait for collector pods to become ready")
	fs.StringVar(&kubeconfig, "kubeconfig", "", "admin kubeconfig (default $KUBECONFIG or ~/.kube/config)")
	if err := parse(fs, args); err != nil {
		return o, "", err
	}
	var err error
	if o.Workloads, err = parseWorkloads(workloads); err == nil {
		err = o.Validate()
	}
	if err != nil {
		fmt.Fprintln(fs.Output(), err)
		fs.Usage()
		return o, "", fmt.Errorf("%w: %v", errUsage, err)
	}
	if o.KubeconfigPath, err = absPath(o.KubeconfigPath); err != nil {
		return o, "", err
	}
	if o.StatePath, err = absPath(o.StatePath); err != nil {
		return o, "", err
	}
	o.AdminKubeconfigs = adminKubeconfigs(kubeconfig)
	return o, kubeconfig, nil
}

func parseWorkloads(flags []string) ([]setup.Workload, error) {
	var out []setup.Workload
	for _, s := range flags {
		w, err := setup.ParseWorkload(s)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, nil
}

func adminKubeconfigs(explicit string) []string {
	if explicit != "" {
		return []string{explicit}
	}
	return clientcmd.NewDefaultClientConfigLoadingRules().GetLoadingPrecedence()
}

func parseTeardown(args []string, errOut io.Writer) (teardown.Options, string, error) {
	var o teardown.Options
	var workloads listFlag
	var kubeconfig string
	fs := newFlagSet("kglance teardown", teardownHelp, errOut)
	fs.StringVar(&o.StatePath, "state", "kglance.state.json", "state file written by setup")
	fs.StringVar(&o.MgmtContext, "context", "", "without a state file, the management cluster's admin context (default the current context)")
	fs.StringVar(&o.MgmtNamespace, "mgmt-namespace", "", "without a state file, the --mgmt-namespace given to setup")
	fs.Var(&workloads, "workload", "without a state file, a workload Cluster (repeatable)")
	fs.StringVar(&kubeconfig, "kubeconfig", "", "admin kubeconfig (default $KUBECONFIG or ~/.kube/config)")
	if err := parse(fs, args); err != nil {
		return o, "", err
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	o.ByLabel = set["context"] || set["workload"] || set["mgmt-namespace"]
	var err error
	if o.ByLabel && set["state"] {
		err = errors.New("--state cannot be combined with --context, --workload or --mgmt-namespace")
	}
	if o.ByLabel && o.MgmtNamespace == "" {
		err = errors.New("--mgmt-namespace is required without a state file")
	}
	for _, w := range workloads {
		if len(validation.IsDNS1123Subdomain(w)) > 0 {
			err = fmt.Errorf("invalid --workload %q: want cluster", w)
		}
	}
	if err != nil {
		fmt.Fprintln(fs.Output(), err)
		fs.Usage()
		return o, "", fmt.Errorf("%w: %v", errUsage, err)
	}
	o.Workloads = workloads
	return o, kubeconfig, nil
}
