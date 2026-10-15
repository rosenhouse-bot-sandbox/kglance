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
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
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
		return fmt.Errorf("failed on %d of %d clusters; %s still records them", len(failed), len(names), o.StatePath)
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
