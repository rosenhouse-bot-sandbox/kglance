package setup

import (
	"context"
	"fmt"
	"time"

	"github.com/rosenhouse-bot-sandbox/kglance/internal/kube"
	"github.com/rosenhouse-bot-sandbox/kglance/internal/state"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func later(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func reaperRolledOut(d *appsv1.Deployment) bool {
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
			if reaperRolledOut(d) {
				break
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("%s: reaper not ready after %v%s", c.Name, o.Wait, reaperWaiting(ctx, c))
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
