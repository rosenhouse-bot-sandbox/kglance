package setup

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/rosenhouse-bot-sandbox/kglance/internal/kube"
	"github.com/rosenhouse-bot-sandbox/kglance/internal/state"
	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func later(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func available(d *appsv1.Deployment) bool {
	s, want := d.Status, *d.Spec.Replicas
	return s.ObservedGeneration >= d.Generation && s.Replicas == want && s.UpdatedReplicas == want && s.AvailableReplicas == want
}

// waitReapers waits up to o.Wait for every workload reaper to pass its startup check, so that no token outlives a broken reaper.
func waitReapers(ctx context.Context, o Options, clusters []*cluster) error {
	deadline := time.Now().Add(o.Wait)
	for _, c := range clusters {
		if c.Role != state.RoleWorkload {
			continue
		}
		for {
			d, err := c.conn.Client.AppsV1().Deployments(kube.Namespace).Get(ctx, kube.ReaperDeployment, metav1.GetOptions{})
			if err != nil {
				return fmt.Errorf("%s: %w", c.Name, err)
			}
			if available(d) {
				break
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("%s: reaper not ready after %v", c.Name, o.Wait)
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(o.PollInterval):
			}
		}
	}
	return nil
}

// armReapers moves each workload deadline to its new token's expiry, unless an earlier token expires later.
func armReapers(ctx context.Context, clusters []*cluster) error {
	for _, c := range clusters {
		if c.Role != state.RoleWorkload {
			continue
		}
		if err := kube.Apply(ctx, c.conn.Client, kube.NamespaceObject(later(c.reapAt, c.expiry))); err != nil {
			return fmt.Errorf("%s: set reaper deadline: %w", c.Name, err)
		}
	}
	return nil
}

// deleteObjectsOwnedByEarlierNamespace deletes kglance's cluster-scoped objects that a deleted namespace still owns.
// Garbage collection would delete them anyway, possibly just after setup re-applies them.
func deleteObjectsOwnedByEarlierNamespace(ctx context.Context, c *cluster, uid types.UID) error {
	rbac := c.conn.Client.RbacV1()
	sel := metav1.ListOptions{LabelSelector: kube.ManagedByLabel + "=" + kube.ManagedByValue}
	bindings, err := rbac.ClusterRoleBindings().List(ctx, sel)
	if err != nil {
		return err
	}
	for _, b := range bindings.Items {
		if err := deleteIfOwnedByEarlierNamespace(ctx, b.ObjectMeta, uid, rbac.ClusterRoleBindings().Delete); err != nil {
			return err
		}
	}
	roles, err := rbac.ClusterRoles().List(ctx, sel)
	if err != nil {
		return err
	}
	for _, r := range roles.Items {
		if err := deleteIfOwnedByEarlierNamespace(ctx, r.ObjectMeta, uid, rbac.ClusterRoles().Delete); err != nil {
			return err
		}
	}
	return nil
}

func deleteIfOwnedByEarlierNamespace(ctx context.Context, m metav1.ObjectMeta, uid types.UID, del func(context.Context, string, metav1.DeleteOptions) error) error {
	earlier := func(r metav1.OwnerReference) bool {
		return r.Kind == "Namespace" && r.Name == kube.Namespace && r.UID != uid
	}
	if !slices.ContainsFunc(m.OwnerReferences, earlier) {
		return nil
	}
	err := del(ctx, m.Name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &m.UID}})
	if apierrors.IsNotFound(err) || apierrors.IsConflict(err) {
		return nil
	}
	return err
}
