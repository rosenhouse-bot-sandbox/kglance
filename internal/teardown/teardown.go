// Package teardown removes what kglance setup installed.
package teardown

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"reflect"
	"slices"
	"strings"

	"github.com/rosenhouse-bot-sandbox/kglance/internal/kube"
	"github.com/rosenhouse-bot-sandbox/kglance/internal/state"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

type Options struct {
	StatePath string
	// ByLabel removes labelled objects from MgmtContext and Workloads instead of reading the state file.
	ByLabel bool
	// MgmtContext is the management cluster's admin context; empty means the current context.
	MgmtContext string
	// Workloads are Cluster API "namespace/name" references.
	Workloads []string
	Connect   func(context string) (*kube.Conn, error)
	// ConnectKubeconfig connects with a kubeconfig read from a Cluster's Secret.
	ConnectKubeconfig func(data []byte) (*kube.Conn, error)
	Out, Err          io.Writer
}

func Run(ctx context.Context, o Options) error {
	if o.ByLabel {
		return byLabel(ctx, o)
	}
	return byState(ctx, o)
}

// connect reaches the cluster at kctx, or the Cluster ref whose kubeconfig Secret is on kctx.
func (o Options) connect(ctx context.Context, kctx, ref string) (*kube.Conn, error) {
	conn, err := o.Connect(kctx)
	if err != nil || ref == "" {
		return conn, err
	}
	return o.connectCluster(ctx, conn, ref)
}

func (o Options) connectCluster(ctx context.Context, mgmt *kube.Conn, ref string) (*kube.Conn, error) {
	data, err := kube.ClusterKubeconfig(ctx, mgmt.Client, ref)
	if err != nil {
		return nil, err
	}
	conn, err := o.ConnectKubeconfig(data)
	if err != nil {
		return nil, fmt.Errorf("kubeconfig of Cluster %s: %w", ref, err)
	}
	return conn, nil
}

func byState(ctx context.Context, o Options) error {
	if _, err := os.Stat(o.StatePath); errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%s not found; use --state, or --context and --workload", o.StatePath)
	}
	st, err := state.Load(o.StatePath)
	if err != nil {
		return err
	}
	var names []string
	for _, c := range st.Clusters {
		names = append(names, c.Name)
	}
	fmt.Fprintf(o.Out, "read %s: removing kglance from %s ... ", o.StatePath, strings.Join(names, ", "))
	var failed []state.Cluster
	var skipped []string
	for _, c := range st.Clusters {
		s, err := removeRecorded(ctx, o, c)
		skipped = append(skipped, s...)
		if apierrors.IsNotFound(err) && c.ClusterRef != "" {
			err = fmt.Errorf("%w; if Cluster %s was deleted, remove its record from %s", err, c.ClusterRef, o.StatePath)
		}
		if err != nil {
			fmt.Fprintf(o.Err, "\n%s: %v", c.Name, err)
			failed = append(failed, c)
		}
	}
	defer func() {
		for _, s := range skipped {
			fmt.Fprintf(o.Err, "warning: skipped %s: not managed by kglance\n", s)
		}
	}()
	if len(failed) > 0 {
		fmt.Fprintln(o.Err)
		fmt.Fprintln(o.Out, "failed")
		st.Clusters = failed
		if err := state.Save(o.StatePath, st); err != nil {
			return err
		}
		return fmt.Errorf("failed on %d of %d clusters; %s still records them", len(failed), len(names), o.StatePath)
	}
	fmt.Fprintln(o.Out, "done")
	files := []string{o.StatePath}
	if st.Kubeconfig != "" {
		if isAgentKubeconfig(st.Kubeconfig, names) {
			files = append(files, st.Kubeconfig)
		} else {
			fmt.Fprintf(o.Err, "warning: kept %s: not a kglance agent kubeconfig\n", st.Kubeconfig)
		}
	}
	for _, p := range files {
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}

// isAgentKubeconfig reports whether path is missing or holds only token users for the given clusters.
func isAgentKubeconfig(path string, clusters []string) bool {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return true
	}
	if err != nil {
		return false
	}
	cfg, err := clientcmd.Load(data)
	if err != nil || len(cfg.Contexts) == 0 {
		return false
	}
	for name, c := range cfg.Contexts {
		if !slices.Contains(clusters, name) || c.Cluster != name || c.AuthInfo != name {
			return false
		}
	}
	for name, u := range cfg.AuthInfos {
		if cfg.Contexts[name] == nil || u.Token == "" || !reflect.DeepEqual(u, &clientcmdapi.AuthInfo{Token: u.Token, Extensions: u.Extensions}) {
			return false
		}
	}
	return true
}

// removeRecorded deletes c's recorded objects and returns those it skipped because kglance does not manage them.
func removeRecorded(ctx context.Context, o Options, c state.Cluster) (skipped []string, err error) {
	conn, err := o.connect(ctx, c.Context, c.ClusterRef)
	if err != nil {
		return nil, err
	}
	fp, err := state.Fingerprint(conn.Cluster.CertificateAuthorityData)
	if err != nil {
		return nil, err
	}
	if conn.Cluster.Server != c.Server || fp != c.CAFingerprint {
		source := "context " + c.Context
		if c.ClusterRef != "" {
			source = "Cluster " + c.ClusterRef
		}
		return nil, fmt.Errorf("%s does not match the recorded cluster (server %s, CA %.12s; now %s, CA %.12s); deleted nothing",
			source, c.Server, c.CAFingerprint, conn.Cluster.Server, fp)
	}
	for _, obj := range slices.Backward(c.Objects) {
		exists, managed, err := kube.Managed(ctx, conn.Client, obj.Kind, obj.Namespace, obj.Name)
		if err != nil {
			return skipped, err
		}
		if exists && !managed {
			skipped = append(skipped, fmt.Sprintf("%s: %s %s", c.Name, obj.Kind, obj.Name))
			continue
		}
		if err := kube.Delete(ctx, conn.Client, obj.Kind, obj.Namespace, obj.Name); err != nil {
			return skipped, err
		}
	}
	return skipped, nil
}

func byLabel(ctx context.Context, o Options) error {
	if _, err := os.Stat(o.StatePath); err == nil {
		return fmt.Errorf("%s exists; run kglance teardown without --context or --workload", o.StatePath)
	}
	mgmt, err := o.Connect(o.MgmtContext)
	if err != nil {
		return err
	}
	var failed []string
	remove := func(name string, conn *kube.Conn, err error) {
		fmt.Fprintf(o.Out, "removing kglance from %s ... ", name)
		if err == nil {
			err = removeLabelled(ctx, conn)
		}
		if err != nil {
			fmt.Fprintln(o.Out, "failed")
			fmt.Fprintf(o.Err, "%s: %v\n", name, err)
			failed = append(failed, name)
			return
		}
		fmt.Fprintln(o.Out, "done")
	}
	remove("context "+mgmt.Context, mgmt, nil)
	for _, ref := range o.Workloads {
		conn, err := o.connectCluster(ctx, mgmt, ref)
		remove("Cluster "+ref, conn, err)
	}
	if len(failed) > 0 {
		return fmt.Errorf("teardown failed on %s", strings.Join(failed, ", "))
	}
	return nil
}

// removeLabelled deletes managed-by=kglance objects of every kind setup creates, namespaced ones first.
func removeLabelled(ctx context.Context, conn *kube.Conn) error {
	cs, ns := conn.Client, kube.Namespace
	sel := metav1.ListOptions{LabelSelector: kube.ManagedByLabel + "=" + kube.ManagedByValue}
	listers := []struct {
		kind string
		list func() (runtime.Object, error)
	}{
		{"DaemonSet", func() (runtime.Object, error) { return cs.AppsV1().DaemonSets(ns).List(ctx, sel) }},
		{"RoleBinding", func() (runtime.Object, error) { return cs.RbacV1().RoleBindings(ns).List(ctx, sel) }},
		{"Role", func() (runtime.Object, error) { return cs.RbacV1().Roles(ns).List(ctx, sel) }},
		{"ClusterRoleBinding", func() (runtime.Object, error) { return cs.RbacV1().ClusterRoleBindings().List(ctx, sel) }},
		{"ClusterRole", func() (runtime.Object, error) { return cs.RbacV1().ClusterRoles().List(ctx, sel) }},
		{"ServiceAccount", func() (runtime.Object, error) { return cs.CoreV1().ServiceAccounts(ns).List(ctx, sel) }},
		{"Namespace", func() (runtime.Object, error) { return cs.CoreV1().Namespaces().List(ctx, sel) }},
	}
	for _, l := range listers {
		list, err := l.list()
		if err != nil {
			return err
		}
		items, err := meta.ExtractList(list)
		if err != nil {
			return err
		}
		for _, item := range items {
			m, err := meta.Accessor(item)
			if err != nil {
				return err
			}
			if err := kube.Delete(ctx, cs, l.kind, m.GetNamespace(), m.GetName()); err != nil {
				return err
			}
		}
	}
	return nil
}
