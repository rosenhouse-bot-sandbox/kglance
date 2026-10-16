// Package setup installs kglance objects and mints the agent kubeconfig.
package setup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/rosenhouse-bot-sandbox/kglance/internal/kube"
	"github.com/rosenhouse-bot-sandbox/kglance/internal/state"
	authv1 "k8s.io/api/authentication/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

const (
	MinTTL = 10 * time.Minute
	MaxTTL = 8 * time.Hour
)

// MgmtName is the management cluster's context name in the agent kubeconfig.
const MgmtName = "mgmt"

// Workload is a Cluster API Cluster and its context name in the agent kubeconfig.
type Workload struct {
	Name string
	// Cluster is "namespace/name".
	Cluster string
}

// ParseWorkload parses "[name=]namespace/cluster".
func ParseWorkload(s string) (Workload, error) {
	name, ref, found := strings.Cut(s, "=")
	if !found {
		ref = name
	}
	_, cluster, err := kube.SplitClusterRef(ref)
	if !found {
		name = cluster
	}
	if err != nil || len(validation.IsDNS1123Subdomain(name)) > 0 {
		return Workload{}, fmt.Errorf("invalid --workload %q: want [name=]namespace/cluster", s)
	}
	return Workload{Name: name, Cluster: ref}, nil
}

type Options struct {
	// MgmtContext is the management cluster's admin context; empty means the current context.
	MgmtContext      string
	Workloads        []Workload
	TTL              time.Duration
	KubeconfigPath   string
	StatePath        string
	InstructionsPath string
	Image            string
	Interval         time.Duration
	Wait             time.Duration
	PollInterval     time.Duration
	AdminKubeconfigs []string
	Connect          func(context string) (*kube.Conn, error)
	// ConnectKubeconfig connects with a kubeconfig read from a Cluster's Secret.
	ConnectKubeconfig func(data []byte) (*kube.Conn, error)
	Now               func() time.Time
	Out, Err          io.Writer
}

func (o *Options) Validate() error {
	names := map[string]bool{MgmtName: true}
	for _, w := range o.Workloads {
		if names[w.Name] {
			return fmt.Errorf("duplicate cluster name %q", w.Name)
		}
		names[w.Name] = true
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
	Name, Role string
	conn       *kube.Conn
	record     state.Cluster
	token      string
	expiry     time.Time
}

func Run(ctx context.Context, o Options) error {
	if err := o.Validate(); err != nil {
		return err
	}
	if err := o.refuseAdminKubeconfigOutputs(); err != nil {
		return err
	}
	st, err := state.Load(o.StatePath)
	if err != nil {
		return err
	}
	clusters, err := connectAll(ctx, o, st)
	if err != nil {
		return err
	}
	for _, c := range clusters {
		record := func() error {
			st.Put(c.record)
			return state.Save(o.StatePath, st)
		}
		if err := install(ctx, o, c, record); err != nil {
			if len(c.record.Objects) == 0 {
				return fmt.Errorf("%s: %w", c.Name, err)
			}
			return fmt.Errorf("%s: %w; run kglance teardown to remove what was applied", c.Name, err)
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

	text := Instructions(o.KubeconfigPath, expiry, o.Workloads)
	fmt.Fprint(o.Out, "\n"+text)
	if o.InstructionsPath != "" {
		if err := os.WriteFile(o.InstructionsPath, []byte(text), 0o644); err != nil {
			return err
		}
		fmt.Fprintf(o.Out, "\nwrote %s\n", o.InstructionsPath)
	}
	return collectorErr
}

func (o *Options) refuseAdminKubeconfigOutputs() error {
	for _, out := range []string{o.KubeconfigPath, o.StatePath, o.InstructionsPath} {
		outInfo, err := os.Stat(out)
		if err != nil {
			continue
		}
		for _, admin := range o.AdminKubeconfigs {
			if adminInfo, err := os.Stat(admin); err == nil && os.SameFile(outInfo, adminInfo) {
				return fmt.Errorf("refusing to overwrite admin kubeconfig %s", out)
			}
		}
	}
	return nil
}

func names(clusters []*cluster) []string {
	var out []string
	for _, c := range clusters {
		out = append(out, c.Name)
	}
	return out
}

func clock(t time.Time) string { return t.UTC().Format("15:04 UTC") }

// connectAll connects to every cluster and checks it against the recorded state before anything changes.
func connectAll(ctx context.Context, o Options, st *state.File) ([]*cluster, error) {
	mgmt, err := o.Connect(o.MgmtContext)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", MgmtName, err)
	}
	var out []*cluster
	add := func(name, role, ref string, conn *kube.Conn) error {
		fp, err := state.Fingerprint(conn.Cluster.CertificateAuthorityData)
		if err != nil {
			return err
		}
		c := &cluster{Name: name, Role: role, conn: conn, record: state.Cluster{
			Name: name, Role: role, Context: mgmt.Context, ClusterRef: ref, Server: conn.Cluster.Server, CAFingerprint: fp,
		}}
		for _, prev := range out {
			if prev.record.Server == c.record.Server && prev.record.CAFingerprint == fp {
				return fmt.Errorf("%s and %s point to the same cluster", prev.Name, name)
			}
		}
		for _, rec := range st.Clusters {
			sameCluster := rec.Server == c.record.Server && rec.CAFingerprint == fp
			switch {
			case rec.Name == name && !sameCluster:
				return fmt.Errorf("recorded with server %s but now points to %s; run kglance teardown first", rec.Server, c.record.Server)
			case rec.Name == name && rec.Role != role:
				return fmt.Errorf("recorded as %s, not %s; run kglance teardown first", rec.Role, role)
			case rec.Name != name && sameCluster:
				return fmt.Errorf("same cluster is already recorded as %s", rec.Name)
			case rec.Name == name:
				c.record.Objects = slices.Clone(rec.Objects)
			}
		}
		out = append(out, c)
		return nil
	}
	if err := add(MgmtName, state.RoleMgmt, "", mgmt); err != nil {
		return nil, fmt.Errorf("%s: %w", MgmtName, err)
	}
	for _, w := range o.Workloads {
		err := func() error {
			data, err := kube.ClusterKubeconfig(ctx, mgmt.Client, w.Cluster)
			if err != nil {
				return err
			}
			conn, err := o.ConnectKubeconfig(data)
			if err != nil {
				return fmt.Errorf("kubeconfig of Cluster %s: %w", w.Cluster, err)
			}
			return add(w.Name, state.RoleWorkload, w.Cluster, conn)
		}()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", w.Name, err)
		}
	}
	return out, nil
}

// install applies c's objects and calls record after each one so that a partial install is recorded.
func install(ctx context.Context, o Options, c *cluster, record func() error) error {
	if err := waitNamespaceGoneIfTerminating(ctx, o, c); err != nil {
		return err
	}
	objs := kube.MgmtObjects()
	if c.Role == state.RoleWorkload {
		view, err := c.conn.Client.RbacV1().ClusterRoles().Get(ctx, "view", metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("read ClusterRole view: %w", err)
		}
		objs = kube.WorkloadObjects(view.Rules, kube.DaemonSetOptions{Image: o.Image, Cluster: c.Name, Interval: o.Interval})
	}
	for _, obj := range objs {
		kind := obj.GetObjectKind().GroupVersionKind().Kind
		exists, managed, err := kube.Managed(ctx, c.conn.Client, kind, obj.GetNamespace(), obj.GetName())
		if err != nil {
			return err
		}
		if exists && !managed {
			return fmt.Errorf("%s %s exists and is not managed by kglance", kind, obj.GetName())
		}
		if err := kube.Apply(ctx, c.conn.Client, obj); err != nil {
			return err
		}
		gvk := obj.GetObjectKind().GroupVersionKind()
		applied := state.Object{APIVersion: gvk.GroupVersion().String(), Kind: gvk.Kind, Namespace: obj.GetNamespace(), Name: obj.GetName()}
		if !slices.Contains(c.record.Objects, applied) {
			c.record.Objects = append(c.record.Objects, applied)
		}
		if err := record(); err != nil {
			return err
		}
	}
	return nil
}

const terminatingTimeout = 2 * time.Minute

func waitNamespaceGoneIfTerminating(ctx context.Context, o Options, c *cluster) error {
	deadline := time.Now().Add(terminatingTimeout)
	warned := false
	for {
		ns, err := c.conn.Client.CoreV1().Namespaces().Get(ctx, kube.Namespace, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if ns.DeletionTimestamp == nil {
			return nil
		}
		if !warned {
			fmt.Fprintf(o.Err, "%s: waiting for namespace %s to finish terminating\n", c.Name, kube.Namespace)
			warned = true
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("namespace %s still terminating after %v", kube.Namespace, terminatingTimeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(o.PollInterval):
		}
	}
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
		entry.Extensions = nil
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
