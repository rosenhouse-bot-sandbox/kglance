// Package setup installs kglance objects and mints the agent kubeconfig.
package setup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/rosenhouse-bot-sandbox/kglance/internal/kube"
	"github.com/rosenhouse-bot-sandbox/kglance/internal/state"
	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

const (
	MinTTL = 10 * time.Minute
	MaxTTL = 8 * time.Hour
)

type Target struct {
	Name    string
	Role    string
	Context string
}

// ParseTarget parses "[name=]context".
func ParseTarget(role, s string) (Target, error) {
	name, ctx, found := strings.Cut(s, "=")
	if !found {
		ctx = name
	}
	if name == "" || ctx == "" {
		return Target{}, fmt.Errorf("invalid --%s %q: want [name=]context", role, s)
	}
	return Target{Name: name, Role: role, Context: ctx}, nil
}

type Options struct {
	Targets          []Target
	TTL              time.Duration
	KubeconfigPath   string
	StatePath        string
	InstructionsPath string
	Image            string
	Interval         time.Duration
	Wait             time.Duration
	PollInterval     time.Duration
	Connect          func(context string) (*kube.Conn, error)
	Now              func() time.Time
	Out, Err         io.Writer
}

func (o *Options) Validate() error {
	if len(o.Targets) == 0 {
		return errors.New("at least one --mgmt or --workload is required")
	}
	names, mgmts := map[string]bool{}, 0
	for _, t := range o.Targets {
		if names[t.Name] {
			return fmt.Errorf("duplicate cluster name %q", t.Name)
		}
		names[t.Name] = true
		if t.Role == state.RoleMgmt {
			mgmts++
		}
	}
	if mgmts > 1 {
		return errors.New("at most one --mgmt is allowed")
	}
	if o.TTL < MinTTL || o.TTL > MaxTTL {
		return fmt.Errorf("--ttl must be between %v and %v", MinTTL, MaxTTL)
	}
	if o.Interval <= 0 {
		return errors.New("--interval must be positive")
	}
	if o.Image == "" {
		return errors.New("--image must not be empty")
	}
	return nil
}

type cluster struct {
	Target
	conn   *kube.Conn
	record state.Cluster
	token  string
	expiry time.Time
}

func Run(ctx context.Context, o Options) error {
	if err := o.Validate(); err != nil {
		return err
	}
	st, err := state.Load(o.StatePath)
	if err != nil {
		return err
	}
	clusters, err := connectAll(o, st)
	if err != nil {
		return err
	}
	for _, c := range clusters {
		if err := install(ctx, o, c); err != nil {
			return fmt.Errorf("%s: %w", c.Name, err)
		}
		st.Put(c.record)
		if err := state.Save(o.StatePath, st); err != nil {
			return err
		}
	}
	expiry, err := mintTokens(ctx, o, clusters)
	if err != nil {
		return err
	}
	if err := state.WriteFileAtomic(o.KubeconfigPath, agentKubeconfig(clusters)); err != nil {
		return err
	}
	fmt.Fprintf(o.Out, "wrote %s (contexts: %s; expires %s)\n", o.KubeconfigPath, strings.Join(names(clusters), ", "), clock(expiry))
	st.Kubeconfig, st.Expiry = o.KubeconfigPath, expiry
	if err := state.Save(o.StatePath, st); err != nil {
		return err
	}
	fmt.Fprintf(o.Out, "wrote %s\n", o.StatePath)

	collectorErr := reportCollectors(ctx, o, clusters)

	text := Instructions(o.KubeconfigPath, expiry, o.Targets)
	fmt.Fprint(o.Out, "\n"+text)
	if o.InstructionsPath != "" {
		if err := os.WriteFile(o.InstructionsPath, []byte(text), 0o644); err != nil {
			return err
		}
		fmt.Fprintf(o.Out, "\nwrote %s\n", o.InstructionsPath)
	}
	return collectorErr
}

func names(clusters []*cluster) []string {
	var out []string
	for _, c := range clusters {
		out = append(out, c.Name)
	}
	return out
}

func clock(t time.Time) string { return t.UTC().Format("15:04 UTC") }

// connectAll connects to every target and checks it against the recorded state before anything changes.
func connectAll(o Options, st *state.File) ([]*cluster, error) {
	var out []*cluster
	for _, t := range o.Targets {
		conn, err := o.Connect(t.Context)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", t.Name, err)
		}
		fp, err := state.Fingerprint(conn.Cluster.CertificateAuthorityData)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", t.Name, err)
		}
		c := &cluster{Target: t, conn: conn, record: state.Cluster{
			Name: t.Name, Role: t.Role, Context: t.Context, Server: conn.Cluster.Server, CAFingerprint: fp,
		}}
		for _, prev := range out {
			if prev.record.Server == c.record.Server && prev.record.CAFingerprint == fp {
				return nil, fmt.Errorf("%s and %s point to the same cluster", prev.Name, t.Name)
			}
		}
		for _, rec := range st.Clusters {
			sameCluster := rec.Server == c.record.Server && rec.CAFingerprint == fp
			switch {
			case rec.Name == t.Name && !sameCluster:
				return nil, fmt.Errorf("%s: recorded with server %s but context %s now points to %s; run kglance teardown first", t.Name, rec.Server, t.Context, c.record.Server)
			case rec.Name == t.Name && rec.Role != t.Role:
				return nil, fmt.Errorf("%s: recorded as %s, not %s; run kglance teardown first", t.Name, rec.Role, t.Role)
			case rec.Name != t.Name && sameCluster:
				return nil, fmt.Errorf("%s: same cluster is already recorded as %s", t.Name, rec.Name)
			}
		}
		out = append(out, c)
	}
	return out, nil
}

func install(ctx context.Context, o Options, c *cluster) error {
	objs := kube.MgmtObjects()
	if c.Role == state.RoleWorkload {
		view, err := c.conn.Client.RbacV1().ClusterRoles().Get(ctx, "view", metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("read ClusterRole view: %w", err)
		}
		objs = kube.WorkloadObjects(view.Rules, kube.DaemonSetOptions{Image: o.Image, Cluster: c.Name, Interval: o.Interval})
	}
	for _, obj := range objs {
		if err := kube.Apply(ctx, c.conn.Client, obj); err != nil {
			return err
		}
		gvk := obj.GetObjectKind().GroupVersionKind()
		c.record.Objects = append(c.record.Objects, state.Object{
			APIVersion: gvk.GroupVersion().String(), Kind: gvk.Kind, Namespace: obj.GetNamespace(), Name: obj.GetName(),
		})
	}
	return nil
}

// mintTokens returns the earliest token expiry.
func mintTokens(ctx context.Context, o Options, clusters []*cluster) (time.Time, error) {
	var earliest time.Time
	seconds := int64(o.TTL / time.Second)
	for _, c := range clusters {
		tr, err := c.conn.Client.CoreV1().ServiceAccounts(kube.Namespace).CreateToken(ctx, kube.AgentSA,
			&authv1.TokenRequest{Spec: authv1.TokenRequestSpec{ExpirationSeconds: &seconds}}, metav1.CreateOptions{})
		if err != nil {
			return time.Time{}, fmt.Errorf("%s: request token: %w", c.Name, err)
		}
		c.token, c.expiry = tr.Status.Token, tr.Status.ExpirationTimestamp.Time
		if c.expiry.Before(o.Now().Add(o.TTL - time.Minute)) {
			fmt.Fprintf(o.Err, "warning: %s: token expires at %s; the API server shortened the requested --ttl %v\n", c.Name, clock(c.expiry), o.TTL)
		}
		if earliest.IsZero() || c.expiry.Before(earliest) {
			earliest = c.expiry
		}
	}
	return earliest, nil
}

func agentKubeconfig(clusters []*cluster) []byte {
	cfg := clientcmdapi.NewConfig()
	for _, c := range clusters {
		entry := c.conn.Cluster.DeepCopy()
		entry.LocationOfOrigin, entry.Extensions = "", nil
		cfg.Clusters[c.Name] = entry
		cfg.AuthInfos[c.Name] = &clientcmdapi.AuthInfo{Token: c.token}
		cfg.Contexts[c.Name] = &clientcmdapi.Context{Cluster: c.Name, AuthInfo: c.Name}
	}
	cfg.CurrentContext = clusters[0].Name
	data, err := clientcmd.Write(*cfg)
	if err != nil {
		panic(err)
	}
	return data
}
