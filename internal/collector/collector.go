// Package collector periodically writes this node's socket snapshot to a ConfigMap.
package collector

import (
	"context"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/rosenhouse-bot-sandbox/kglance/internal/kube"
	"github.com/rosenhouse-bot-sandbox/kglance/internal/sockets"
)

const (
	controlPlaneLabel = "node-role.kubernetes.io/control-plane"
	mirrorAnnotation  = "kubernetes.io/config.mirror"
	// maxDataBytes keeps the ConfigMap under the 1 MiB object limit with room for metadata.
	maxDataBytes = 1_000_000
)

// Main runs the collector inside the DaemonSet pod.
func Main(ctx context.Context, args []string) error {
	fl := flag.NewFlagSet("collect", flag.ContinueOnError)
	interval := fl.Duration("interval", time.Minute, "time between snapshots")
	namespace := fl.String("namespace", kube.Namespace, "namespace for snapshot ConfigMaps")
	if err := fl.Parse(args); err != nil {
		return err
	}
	if *interval <= 0 {
		return fmt.Errorf("--interval must be positive")
	}
	cluster, nodeName := os.Getenv(kube.ClusterEnv), os.Getenv(kube.NodeEnv)
	if cluster == "" {
		return fmt.Errorf("%s is not set", kube.ClusterEnv)
	}
	if nodeName == "" {
		return fmt.Errorf("%s is not set", kube.NodeEnv)
	}
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("in-cluster config: %w", err)
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return err
	}
	c := &Collector{Client: client, Cluster: cluster, Node: nodeName, Namespace: *namespace, Proc: os.DirFS("/proc"), Now: time.Now}
	c.Run(ctx, *interval)
	return nil
}

type Collector struct {
	Client    kubernetes.Interface
	Cluster   string
	Node      string
	Namespace string
	Proc      fs.FS
	Now       func() time.Time
}

// Run takes a snapshot immediately and then every interval until ctx is done.
func (c *Collector) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := c.Snapshot(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Error("snapshot failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (c *Collector) Snapshot(ctx context.Context) error {
	ts := c.Now().UTC().Format(time.RFC3339)
	node, err := c.Client.CoreV1().Nodes().Get(ctx, c.Node, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get node: %w", err)
	}
	role := "worker"
	if _, ok := node.Labels[controlPlaneLabel]; ok {
		role = "control-plane"
	}
	found, err := sockets.Scan(c.Proc)
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}
	// Pods are listed after the scan so that pods started during the scan are known.
	pods, err := c.Client.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		FieldSelector: fields.OneTermEqualSelector("spec.nodeName", c.Node).String(),
	})
	if err != nil {
		return fmt.Errorf("list pods: %w", err)
	}
	idx := newPodIndex(pods.Items)

	rows := make([]sockets.Row, 0, len(found))
	for _, s := range found {
		pod, container := idx.resolve(s.PodUID, s.ContainerID)
		rows = append(rows, sockets.Row{
			Cluster: c.Cluster, Node: c.Node, Role: role, TS: ts, NetNS: s.NetNS,
			Proto: s.Proto, Local: s.Local, Peer: s.Peer, State: s.State,
			PID: s.PID, Process: s.Process, Pod: pod, Container: container,
		})
	}
	jsonl, raw := sockets.Render(rows, maxDataBytes)

	cm := corev1ac.ConfigMap("snapshot-"+c.Node, c.Namespace).
		WithLabels(map[string]string{kube.SnapshotLabel: "true", kube.ManagedByLabel: kube.ManagedByValue}).
		WithData(map[string]string{"sockets.jsonl": jsonl, "raw.txt": raw})
	_, err = c.Client.CoreV1().ConfigMaps(c.Namespace).Apply(ctx, cm, metav1.ApplyOptions{FieldManager: kube.FieldManager, Force: true})
	if err != nil {
		return fmt.Errorf("apply configmap: %w", err)
	}
	slog.Info("snapshot written", "sockets", len(rows))
	return nil
}

type podIndex struct {
	pods       map[string]string
	containers map[string]string
}

func newPodIndex(pods []corev1.Pod) podIndex {
	idx := podIndex{pods: map[string]string{}, containers: map[string]string{}}
	for _, p := range pods {
		name := p.Namespace + "/" + p.Name
		idx.pods[normalizeUID(string(p.UID))] = name
		if hash := p.Annotations[mirrorAnnotation]; hash != "" {
			idx.pods[normalizeUID(hash)] = name
		}
		for _, list := range [][]corev1.ContainerStatus{p.Status.InitContainerStatuses, p.Status.ContainerStatuses, p.Status.EphemeralContainerStatuses} {
			for _, cs := range list {
				if _, id, ok := strings.Cut(cs.ContainerID, "://"); ok {
					idx.containers[id] = cs.Name
				}
			}
		}
	}
	return idx
}

// resolve maps a cgroup pod UID and container ID to "namespace/name" and container name.
func (idx podIndex) resolve(podUID, containerID string) (pod, container string) {
	if podUID == "" {
		return "", ""
	}
	return idx.pods[normalizeUID(podUID)], idx.containers[containerID]
}

func normalizeUID(uid string) string {
	return strings.ReplaceAll(uid, "-", "")
}
