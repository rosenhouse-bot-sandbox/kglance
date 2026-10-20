package setup

import (
	"context"
	"errors"
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

// startReaper applies a workload cluster's namespace and reaper, after deleting cluster-scoped objects that an earlier namespace owns.
// It calls record after each object, so that a partial install is recorded.
func startReaper(ctx context.Context, o Options, c *cluster, record func() error) error {
	if c.Role != state.RoleWorkload {
		// Recording mgmt first keeps the state file, and so teardown, in setup's cluster order.
		return record()
	}
	prev, err := waitNamespaceGoneIfTerminating(ctx, o, c)
	if err != nil {
		return err
	}
	if prev != nil {
		// Setup never mints a token that expires after now + MaxTTL, so it ignores a later expiry.
		if at, err := kube.TimeAnnotation(prev, kube.TokensExpireAtAnnotation); err == nil && !at.After(o.Now().Add(MaxTTL)) {
			c.earlierExpiry = at
		}
	}
	// Until armReapers replaces it, this deadline removes a failed setup.
	// It uses the local clock, so it is long enough to allow for skew with the cluster's.
	if err := applyAll(ctx, c, []kube.Object{kube.NamespaceObject(o.Now().Add(MaxTTL), c.earlierExpiry)}, record); err != nil {
		return err
	}
	c.owner, err = c.conn.Client.CoreV1().Namespaces().Get(ctx, kube.Namespace, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if c.owner.DeletionTimestamp != nil {
		return errNamespaceChanged
	}
	if err := deleteObjectsOwnedByEarlierNamespace(ctx, c); err != nil {
		return err
	}
	return applyAll(ctx, c, kube.ReaperObjects(o.Image), record)
}

var errNamespaceChanged = errors.New("namespace " + kube.Namespace + " changed during setup; run setup again")

// deleteObjectsOwnedByEarlierNamespace deletes kglance's cluster-scoped objects that a deleted namespace still owns.
// Garbage collection would delete them anyway, possibly just after setup re-applies them.
func deleteObjectsOwnedByEarlierNamespace(ctx context.Context, c *cluster) error {
	rbac := c.conn.Client.RbacV1()
	sel := metav1.ListOptions{LabelSelector: kube.ManagedByLabel + "=" + kube.ManagedByValue}
	bindings, err := rbac.ClusterRoleBindings().List(ctx, sel)
	if err != nil {
		return err
	}
	for _, b := range bindings.Items {
		if err := deleteIfOwnedByEarlierNamespace(ctx, b.ObjectMeta, c.owner.UID, rbac.ClusterRoleBindings().Delete); err != nil {
			return err
		}
	}
	roles, err := rbac.ClusterRoles().List(ctx, sel)
	if err != nil {
		return err
	}
	for _, r := range roles.Items {
		if err := deleteIfOwnedByEarlierNamespace(ctx, r.ObjectMeta, c.owner.UID, rbac.ClusterRoles().Delete); err != nil {
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

func deploymentRolledOut(d *appsv1.Deployment) bool {
	s, want := d.Status, *d.Spec.Replicas
	return s.ObservedGeneration >= d.Generation && s.Replicas == want && s.UpdatedReplicas == want && s.AvailableReplicas == want
}

// waitReapers waits up to o.Wait for every workload reaper to pass its check, so that no token outlives a broken reaper.
func waitReapers(ctx context.Context, o Options, clusters []*cluster) error {
	deadline := time.Now().Add(o.Wait)
	for _, c := range clusters {
		if c.Role != state.RoleWorkload {
			continue
		}
		d, err := poll(ctx, o, deadline, func() (*appsv1.Deployment, error) {
			return c.conn.Client.AppsV1().Deployments(kube.Namespace).Get(ctx, kube.ReaperDeployment, metav1.GetOptions{})
		}, deploymentRolledOut)
		if err != nil {
			return fmt.Errorf("%s: %w", c.Name, err)
		}
		if !deploymentRolledOut(d) {
			return fmt.Errorf("%s: reaper not ready after %v%s", c.Name, o.Wait, reaperWaiting(ctx, c))
		}
	}
	return nil
}

// reaperWaiting says why a reaper container is waiting, if one is.
func reaperWaiting(ctx context.Context, c *cluster) string {
	pods, err := c.conn.Client.CoreV1().Pods(kube.Namespace).List(ctx, metav1.ListOptions{LabelSelector: kube.NameLabel + "=" + kube.ReaperDeployment})
	if err != nil {
		return ""
	}
	for _, p := range pods.Items {
		for _, s := range p.Status.ContainerStatuses {
			if w := s.State.Waiting; w != nil {
				return fmt.Sprintf("; pod %s is waiting: %s: %s", p.Name, w.Reason, w.Message)
			}
		}
	}
	return ""
}

// armReapers sets each workload deadline to the latest token expiry, which may be an earlier setup's.
func armReapers(ctx context.Context, clusters []*cluster) error {
	for _, c := range clusters {
		if c.Role != state.RoleWorkload {
			continue
		}
		if err := armReaper(ctx, c); err != nil {
			return fmt.Errorf("%s: set reaper deadline: %w", c.Name, err)
		}
	}
	return nil
}

func armReaper(ctx context.Context, c *cluster) error {
	ns, err := c.conn.Client.CoreV1().Namespaces().Get(ctx, kube.Namespace, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if ns.UID != c.owner.UID || ns.DeletionTimestamp != nil {
		return errNamespaceChanged
	}
	at := later(c.earlierExpiry, c.expiry)
	return kube.Apply(ctx, c.conn.Client, kube.NamespaceObject(at, at))
}
