package setup

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rosenhouse-bot-sandbox/kglance/internal/kube"
	"github.com/rosenhouse-bot-sandbox/kglance/internal/state"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const controlPlaneLabel = "node-role.kubernetes.io/control-plane"

func rolledOut(ds *appsv1.DaemonSet) bool {
	s := ds.Status
	return s.ObservedGeneration >= ds.Generation && s.DesiredNumberScheduled > 0 &&
		s.UpdatedNumberScheduled == s.DesiredNumberScheduled && s.NumberReady == s.DesiredNumberScheduled
}

// reportCollectors waits up to o.Wait for every workload collector and prints ready nodes by role.
func reportCollectors(ctx context.Context, o Options, clusters []*cluster) error {
	deadline := time.Now().Add(o.Wait)
	var controlPlane, workers int
	var notReady []string
	any := false
	for _, c := range clusters {
		if c.Role != state.RoleWorkload {
			continue
		}
		any = true
		ds, err := waitRollout(ctx, o, c, deadline)
		if err != nil {
			return fmt.Errorf("%s: %w", c.Name, err)
		}
		if !rolledOut(ds) {
			fmt.Fprintf(o.Err, "warning: %s: socket collector ready on %d/%d nodes after %v\n",
				c.Name, ds.Status.NumberReady, ds.Status.DesiredNumberScheduled, o.Wait)
			notReady = append(notReady, c.Name)
		}
		cp, w, err := readyNodesByRole(ctx, c)
		if err != nil {
			return fmt.Errorf("%s: %w", c.Name, err)
		}
		controlPlane, workers = controlPlane+cp, workers+w
	}
	if !any {
		return nil
	}
	fmt.Fprintf(o.Out, "socket collector running on %d nodes (%d control-plane, %d worker)\n", controlPlane+workers, controlPlane, workers)
	if len(notReady) > 0 {
		return errors.New("socket collector not ready on " + strings.Join(notReady, ", "))
	}
	return nil
}

func waitRollout(ctx context.Context, o Options, c *cluster, deadline time.Time) (*appsv1.DaemonSet, error) {
	for {
		ds, err := c.conn.Client.AppsV1().DaemonSets(kube.Namespace).Get(ctx, kube.CollectorDS, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		if rolledOut(ds) || time.Now().After(deadline) {
			return ds, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(o.PollInterval):
		}
	}
}

func readyNodesByRole(ctx context.Context, c *cluster) (controlPlane, workers int, err error) {
	pods, err := c.conn.Client.CoreV1().Pods(kube.Namespace).List(ctx, metav1.ListOptions{LabelSelector: "app.kubernetes.io/name=" + kube.CollectorDS})
	if err != nil {
		return 0, 0, err
	}
	nodes, err := c.conn.Client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return 0, 0, err
	}
	isControlPlane := map[string]bool{}
	for _, n := range nodes.Items {
		_, isControlPlane[n.Name] = n.Labels[controlPlaneLabel]
	}
	for _, p := range pods.Items {
		if !podReady(&p) {
			continue
		}
		if isControlPlane[p.Spec.NodeName] {
			controlPlane++
		} else {
			workers++
		}
	}
	return controlPlane, workers, nil
}

func podReady(p *corev1.Pod) bool {
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}
