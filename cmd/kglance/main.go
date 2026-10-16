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
	"github.com/rosenhouse-bot-sandbox/kglance/internal/state"
	"github.com/rosenhouse-bot-sandbox/kglance/internal/teardown"
	"github.com/rosenhouse-bot-sandbox/kglance/internal/version"
	"k8s.io/client-go/tools/clientcmd"
)

const usage = `usage:
  kglance setup [--mgmt [name=]context] [--workload [name=]context]... [flags]
  kglance teardown [--state file | --context context...]
  kglance version
Run "kglance setup -h" or "kglance teardown -h" for flags.
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

func versionLine() string {
	return fmt.Sprintf("kglance %s\ncollector image %s\n", version.String(), version.Image())
}

func run(args []string, out, errOut io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(errOut, versionLine()+usage)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var err error
	switch args[0] {
	case "setup":
		var o setup.Options
		var kubeconfig string
		if o, kubeconfig, err = parseSetup(args[1:]); err == nil {
			o.Connect = connector(kubeconfig)
			o.Now, o.Out, o.Err, o.PollInterval = time.Now, out, errOut, 2*time.Second
			err = setup.Run(ctx, o)
		}
	case "teardown":
		var o teardown.Options
		var kubeconfig string
		if o, kubeconfig, err = parseTeardown(args[1:]); err == nil {
			o.Connect, o.Out, o.Err = connector(kubeconfig), out, errOut
			err = teardown.Run(ctx, o)
		}
	case "collect":
		err = collect(ctx, args[1:])
	case "version", "--version":
		fmt.Fprint(out, versionLine())
		return 0
	case "-h", "--help", "help":
		fmt.Fprint(out, versionLine()+usage)
		return 0
	default:
		fmt.Fprint(errOut, versionLine()+usage)
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

func parseSetup(args []string) (setup.Options, string, error) {
	var o setup.Options
	var mgmt, workloads listFlag
	var kubeconfig string
	fs := flag.NewFlagSet("kglance setup", flag.ContinueOnError)
	fs.Var(&mgmt, "mgmt", "management cluster as [name=]context (at most once)")
	fs.Var(&workloads, "workload", "workload cluster as [name=]context (repeatable)")
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
	for _, s := range mgmt {
		t, err := setup.ParseTarget(state.RoleMgmt, s)
		if err != nil {
			return o, "", err
		}
		o.Targets = append(o.Targets, t)
	}
	for _, s := range workloads {
		t, err := setup.ParseTarget(state.RoleWorkload, s)
		if err != nil {
			return o, "", err
		}
		o.Targets = append(o.Targets, t)
	}
	if err := o.Validate(); err != nil {
		fmt.Fprintln(fs.Output(), err)
		fs.Usage()
		return o, "", fmt.Errorf("%w: %v", errUsage, err)
	}
	var err error
	if o.KubeconfigPath, err = absPath(o.KubeconfigPath); err != nil {
		return o, "", err
	}
	if o.StatePath, err = absPath(o.StatePath); err != nil {
		return o, "", err
	}
	o.AdminKubeconfigs = adminKubeconfigs(kubeconfig)
	return o, kubeconfig, nil
}

func adminKubeconfigs(explicit string) []string {
	if explicit != "" {
		return []string{explicit}
	}
	return clientcmd.NewDefaultClientConfigLoadingRules().GetLoadingPrecedence()
}

func parseTeardown(args []string) (teardown.Options, string, error) {
	var o teardown.Options
	var contexts listFlag
	var kubeconfig string
	fs := flag.NewFlagSet("kglance teardown", flag.ContinueOnError)
	fs.StringVar(&o.StatePath, "state", "kglance.state.json", "state file written by setup")
	fs.Var(&contexts, "context", "without a state file, remove objects labelled app.kubernetes.io/managed-by=kglance from this context (repeatable)")
	fs.StringVar(&kubeconfig, "kubeconfig", "", "admin kubeconfig (default $KUBECONFIG or ~/.kube/config)")
	if err := parse(fs, args); err != nil {
		return o, "", err
	}
	o.Contexts = contexts
	return o, kubeconfig, nil
}
