// Package teardown removes what kglance setup installed.
package teardown

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
	"strings"

	"github.com/rosenhouse-bot-sandbox/kglance/internal/kube"
	"github.com/rosenhouse-bot-sandbox/kglance/internal/state"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Options struct {
	StatePath string
	// Contexts selects label-based cleanup without a state file.
	Contexts []string
	Connect  func(context string) (*kube.Conn, error)
	Out, Err io.Writer
}

func Run(ctx context.Context, o Options) error {
	if len(o.Contexts) > 0 {
		return byLabel(ctx, o)
	}
	return byState(ctx, o)
}

func byState(ctx context.Context, o Options) error {
	if _, err := os.Stat(o.StatePath); errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%s not found; use --state or --context", o.StatePath)
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
	for _, c := range st.Clusters {
		if err := removeRecorded(ctx, o, c); err != nil {
			fmt.Fprintf(o.Err, "\n%s: %v", c.Name, err)
			failed = append(failed, c)
		}
	}
	if len(failed) > 0 {
		fmt.Fprintln(o.Err)
		fmt.Fprintln(o.Out, "failed")
		st.Clusters = failed
		if err := state.Save(o.StatePath, st); err != nil {
			return err
		}
		return fmt.Errorf("teardown failed on %d of %d clusters; %s keeps them", len(failed), len(names), o.StatePath)
	}
	fmt.Fprintln(o.Out, "done")
	for _, p := range []string{o.StatePath, st.Kubeconfig} {
		if p == "" {
			continue
		}
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}

func removeRecorded(ctx context.Context, o Options, c state.Cluster) error {
	conn, err := o.Connect(c.Context)
	if err != nil {
		return err
	}
	fp, err := state.Fingerprint(conn.Cluster.CertificateAuthorityData)
	if err != nil {
		return err
	}
	if conn.Cluster.Server != c.Server || fp != c.CAFingerprint {
		return fmt.Errorf("context %s does not match the recorded cluster (server %s, CA %.12s; now %s, CA %.12s); deleted nothing",
			c.Context, c.Server, c.CAFingerprint, conn.Cluster.Server, fp)
	}
	for _, obj := range slices.Backward(c.Objects) {
		if err := kube.Delete(ctx, conn.Client, obj.Kind, obj.Namespace, obj.Name); err != nil {
			return err
		}
	}
	return nil
}

func byLabel(ctx context.Context, o Options) error {
	var failed []string
	for _, kctx := range o.Contexts {
		fmt.Fprintf(o.Out, "removing kglance from context %s ... ", kctx)
		if err := removeLabelled(ctx, o, kctx); err != nil {
			fmt.Fprintln(o.Out, "failed")
			fmt.Fprintf(o.Err, "%s: %v\n", kctx, err)
			failed = append(failed, kctx)
			continue
		}
		fmt.Fprintln(o.Out, "done")
	}
	if len(failed) > 0 {
		return fmt.Errorf("teardown failed on %s", strings.Join(failed, ", "))
	}
	return nil
}

// removeLabelled deletes managed-by=kglance objects of every kind setup creates, namespaced ones first.
func removeLabelled(ctx context.Context, o Options, kctx string) error {
	conn, err := o.Connect(kctx)
	if err != nil {
		return err
	}
	cs := conn.Client
	sel := metav1.ListOptions{LabelSelector: kube.ManagedByLabel + "=" + kube.ManagedByValue}
	type ref struct{ kind, ns, name string }
	var refs []ref
	add := func(kind string, items []metav1.Object) {
		for _, it := range items {
			refs = append(refs, ref{kind, it.GetNamespace(), it.GetName()})
		}
	}
	if l, err := cs.AppsV1().DaemonSets(kube.Namespace).List(ctx, sel); err == nil {
		add("DaemonSet", ptrs(l.Items))
	} else {
		return err
	}
	if l, err := cs.RbacV1().RoleBindings(kube.Namespace).List(ctx, sel); err == nil {
		add("RoleBinding", ptrs(l.Items))
	} else {
		return err
	}
	if l, err := cs.RbacV1().Roles(kube.Namespace).List(ctx, sel); err == nil {
		add("Role", ptrs(l.Items))
	} else {
		return err
	}
	if l, err := cs.RbacV1().ClusterRoleBindings().List(ctx, sel); err == nil {
		add("ClusterRoleBinding", ptrs(l.Items))
	} else {
		return err
	}
	if l, err := cs.RbacV1().ClusterRoles().List(ctx, sel); err == nil {
		add("ClusterRole", ptrs(l.Items))
	} else {
		return err
	}
	if l, err := cs.CoreV1().ServiceAccounts(kube.Namespace).List(ctx, sel); err == nil {
		add("ServiceAccount", ptrs(l.Items))
	} else {
		return err
	}
	if l, err := cs.CoreV1().Namespaces().List(ctx, sel); err == nil {
		add("Namespace", ptrs(l.Items))
	} else {
		return err
	}
	for _, r := range refs {
		if err := kube.Delete(ctx, cs, r.kind, r.ns, r.name); err != nil {
			return err
		}
	}
	return nil
}

func ptrs[T any, P interface {
	*T
	metav1.Object
}](items []T) []metav1.Object {
	out := make([]metav1.Object, len(items))
	for i := range items {
		out[i] = P(&items[i])
	}
	return out
}
