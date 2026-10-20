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
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// setupMargin covers setup's API calls and clock skew with the cluster.
const setupMargin = time.Hour

func later(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// readEarlierExpiries waits out terminating workload namespaces and reads when earlier setups' tokens expire.
func readEarlierExpiries(ctx context.Context, o Options, clusters []*cluster) error {
	for _, c := range clusters {
		if c.Role != state.RoleWorkload {
			continue
		}
		prev, err := waitNamespaceGoneIfTerminating(ctx, o, c)
		if err != nil {
			return fmt.Errorf("%s: %w", c.Name, err)
		}
		// applyAll refuses a namespace that kglance does not manage, so no earlier setup left it.
		if prev == nil || prev.Labels[kube.ManagedByLabel] != kube.ManagedByValue {
			continue
		}
		c.earlier = prev
		// Setup never mints a token that expires after now + MaxTTL, so it ignores a later expiry.
		if at, err := kube.TimeAnnotation(prev, kube.TokensExpireAtAnnotation); err == nil && !at.After(o.Now().Add(MaxTTL)) {
			c.earlierExpiry = at
		}
	}
	return nil
}

// startReaper applies a workload cluster's namespace and reaper, after deleting cluster-scoped objects that an earlier namespace owns.
// It calls record after each object, so that a partial install is recorded.
func startReaper(ctx context.Context, o Options, c *cluster, record func() error) error {
	if c.Role != state.RoleWorkload {
		// Recording mgmt first keeps the state file, and so teardown, in setup's cluster order.
		return record()
	}
	// If setup dies before it sets or shortens the deadline again, this deadline removes what setup applied.
	provisional := later(c.earlierExpiry, o.Now().Add(o.Wait+setupMargin))
	// Until setup reads the namespace back, shortenDeadlines restores the earlier namespace's deadline.
	c.owner = c.earlier
	if err := applyAll(ctx, o, c, []kube.Object{kube.NamespaceObject(provisional, c.earlierExpiry)}, record); err != nil {
		return err
	}
	ns, err := c.conn.Client.CoreV1().Namespaces().Get(ctx, kube.Namespace, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if ns.DeletionTimestamp != nil {
		return errNamespaceChanged
	}
	c.owner = ns
	if err := deleteObjectsOwnedByEarlierNamespace(ctx, c); err != nil {
		return fmt.Errorf("%s: %w", deleteEarlierStep, err)
	}
	fmt.Fprintf(o.Out, "%s: %s: ok\n", c.Name, deleteEarlierStep)
	return applyAll(ctx, o, c, kube.ReaperObjects(o.Image), record)
}

const (
	deleteEarlierStep = "delete cluster RBAC owned by an earlier namespace"
	waitReaperStep    = "wait for reaper " + kube.Namespace + "/" + kube.ReaperDeployment
)

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
			return fmt.Errorf("%s: %s: %w", c.Name, waitReaperStep, err)
		}
		if !deploymentRolledOut(d) {
			return fmt.Errorf("%s: %s: not ready after %v%s", c.Name, waitReaperStep, o.Wait, reaperProblem(ctx, c))
		}
		fmt.Fprintf(o.Out, "%s: %s: ok\n", c.Name, waitReaperStep)
	}
	return nil
}

// reaperProblem says why a reaper pod is not ready, if its status or latest failed check shows why.
func reaperProblem(ctx context.Context, c *cluster) string {
	core := c.conn.Client.CoreV1()
	pods, err := core.Pods(kube.Namespace).List(ctx, metav1.ListOptions{LabelSelector: kube.NameLabel + "=" + kube.ReaperDeployment})
	if err != nil {
		return ""
	}
	unready := slices.DeleteFunc(pods.Items, func(p corev1.Pod) bool { return podReady(&p) })
	for _, p := range unready {
		for _, s := range p.Status.ContainerStatuses {
			if w := s.State.Waiting; w != nil {
				return fmt.Sprintf("; pod %s is waiting: %s: %s", p.Name, w.Reason, w.Message)
			}
		}
	}
	events, err := core.Events(kube.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return ""
	}
	for _, p := range unready {
		var latest *corev1.Event
		for i, e := range events.Items {
			if e.InvolvedObject.Name == p.Name && e.Reason == "Unhealthy" && (latest == nil || e.LastTimestamp.After(latest.LastTimestamp.Time)) {
				latest = &events.Items[i]
			}
		}
		if latest != nil {
			return fmt.Sprintf("; pod %s: %s", p.Name, latest.Message)
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
		at := later(c.earlierExpiry, c.expiry)
		if err := setDeadline(ctx, c, at, at); err != nil {
			return fmt.Errorf("%s: set reaper deadline: %w", c.Name, err)
		}
	}
	return nil
}

const shortenTimeout = 30 * time.Second

// shortenDeadlines moves each deadline that setup set back to when earlier setups' tokens expire, so that the reaper removes what a failed setup applied.
// It runs even if setup was cancelled.
func shortenDeadlines(o Options, clusters []*cluster) {
	for _, c := range clusters {
		if c.owner == nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), shortenTimeout)
		err := setDeadline(ctx, c, later(c.earlierExpiry, o.Now()), c.earlierExpiry)
		cancel()
		if err != nil {
			fmt.Fprintf(o.Err, "warning: %s: shorten reaper deadline: %v\n", c.Name, err)
		}
	}
}

func setDeadline(ctx context.Context, c *cluster, at, tokensExpireAt time.Time) error {
	ns, err := c.conn.Client.CoreV1().Namespaces().Get(ctx, kube.Namespace, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if ns.UID != c.owner.UID || ns.DeletionTimestamp != nil {
		return errNamespaceChanged
	}
	return kube.Apply(ctx, c.conn.Client, kube.NamespaceObject(at, tokensExpireAt))
}
