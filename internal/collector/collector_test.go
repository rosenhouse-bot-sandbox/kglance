package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stypes "k8s.io/apimachinery/pkg/types"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/rosenhouse-bot-sandbox/kglance/internal/kube"
	"github.com/rosenhouse-bot-sandbox/kglance/internal/sockets"
)

const (
	hostNS     = "net:[4026531840]"
	podNS      = "net:[4026532469]"
	cidProxy   = "faf022051c28d0a7cf1c1589a086280cf6db0e00a748ddcee59a17634c4ff984"
	cidDNS     = "00de48bc54e7d0b214a962ee3f95e697286c2af5af415ec8aec79552edd15b73"
	cidAPI     = "ee7961aad299322617365e2ae17886986a95e7ce5a8970575edd560dd5d0fcdd"
	uidProxy   = "ba6f01d9-f38f-4fed-832a-6720946f4478"
	uidDNS     = "947e2a0c-454e-4671-858f-7122dacc4048"
	staticHash = "d7074538ef01b4afc0034d2e51859c63"
	tableHead  = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
)

func listen(hexAddr string, inode int) string {
	return fmt.Sprintf("   0: %s 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 %d 1 0000000000000000 100 0 0 10 0\n", hexAddr, inode)
}

func podCgroup(slicePodID, cid string) string {
	return "0::/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-burstable.slice/kubelet-kubepods-burstable-pod" + slicePodID + ".slice/cri-containerd-" + cid + ".scope\n"
}

func addProc(m fstest.MapFS, pid, comm, cgroup, netns string, inodes ...int) {
	m[pid+"/comm"] = &fstest.MapFile{Data: []byte(comm + "\n")}
	m[pid+"/cgroup"] = &fstest.MapFile{Data: []byte(cgroup)}
	m[pid+"/ns/net"] = &fstest.MapFile{Mode: fs.ModeSymlink, Data: []byte(netns)}
	m[pid+"/fd"] = &fstest.MapFile{Mode: fs.ModeDir}
	for i, inode := range inodes {
		m[fmt.Sprintf("%s/fd/%d", pid, i+3)] = &fstest.MapFile{Mode: fs.ModeSymlink, Data: []byte(fmt.Sprintf("socket:[%d]", inode))}
	}
}

func fixtureProc() fstest.MapFS {
	m := fstest.MapFS{}
	addProc(m, "1", "systemd", "0::/init.scope\n", hostNS)
	m["1/net/tcp"] = &fstest.MapFile{Data: []byte(tableHead +
		listen("00000000:2810", 100) + // kube-proxy :10256
		listen("00000000:192B", 101) + // apiserver :6443
		listen("0100007F:2808", 102))} // kubelet :10248
	addProc(m, "300", "kubelet", "0::/kubelet.slice/kubelet.service\n", hostNS, 102)
	addProc(m, "400", "kube-proxy", podCgroup(strings.ReplaceAll(uidProxy, "-", "_"), cidProxy), hostNS, 100)
	addProc(m, "410", "kube-apiserver", podCgroup(staticHash, cidAPI), hostNS, 101)
	addProc(m, "500", "coredns", podCgroup(strings.ReplaceAll(uidDNS, "-", "_"), cidDNS), podNS, 200)
	m["500/net/tcp"] = &fstest.MapFile{Data: []byte(tableHead + listen("00000000:0035", 200))}
	return m
}

func node(name string, controlPlane bool) *corev1.Node {
	n := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{}}}
	if controlPlane {
		n.Labels["node-role.kubernetes.io/control-plane"] = ""
	}
	return n
}

func pod(ns, name, uid, nodeName string, containers map[string]string) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, UID: k8stypes.UID(uid)},
		Spec:       corev1.PodSpec{NodeName: nodeName},
	}
	for cname, cid := range containers {
		p.Status.ContainerStatuses = append(p.Status.ContainerStatuses, corev1.ContainerStatus{Name: cname, ContainerID: "containerd://" + cid})
	}
	return p
}

func fixtureObjects() []runtime.Object {
	api := pod("kube-system", "kube-apiserver-cp1", "4d172768-3f8b-45e7-aa4e-a1171ca30da5", "cp1", nil)
	api.Annotations = map[string]string{"kubernetes.io/config.mirror": staticHash}
	api.Status.InitContainerStatuses = []corev1.ContainerStatus{{Name: "init", ContainerID: "containerd://aaaa"}}
	api.Status.EphemeralContainerStatuses = []corev1.ContainerStatus{{Name: "kube-apiserver", ContainerID: "containerd://" + cidAPI}}
	return []runtime.Object{
		node("cp1", true),
		node("w1", false),
		pod("kube-system", "kube-proxy-x", uidProxy, "cp1", map[string]string{"kube-proxy": cidProxy}),
		pod("kube-system", "coredns-y", uidDNS, "cp1", map[string]string{"coredns": cidDNS, "sidecar": strings.Repeat("b", 64)}),
		api,
	}
}

var fixedTime = time.Date(2026, 10, 15, 18, 42, 7, 123, time.FixedZone("x", 3600))

func newCollector(client *fake.Clientset, nodeName string) *Collector {
	return &Collector{
		Client:    client,
		Cluster:   "wl1",
		Node:      nodeName,
		Namespace: kube.Namespace,
		Proc:      fixtureProc(),
		Now:       func() time.Time { return fixedTime },
	}
}

func readRows(t *testing.T, client *fake.Clientset, nodeName string) (map[string]sockets.Row, *corev1.ConfigMap) {
	t.Helper()
	cm, err := client.CoreV1().ConfigMaps(kube.Namespace).Get(context.Background(), "snapshot-"+nodeName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	rows := map[string]sockets.Row{}
	for line := range strings.Lines(cm.Data["sockets.jsonl"]) {
		var r sockets.Row
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("%q: %v", line, err)
		}
		rows[r.Local] = r
	}
	return rows, cm
}

func TestSnapshotWritesAttributedRows(t *testing.T) {
	client := fake.NewClientset(fixtureObjects()...)
	if err := newCollector(client, "cp1").Snapshot(context.Background()); err != nil {
		t.Fatal(err)
	}
	rows, cm := readRows(t, client, "cp1")

	want := map[string]sockets.Row{
		"0.0.0.0:10256":   {Cluster: "wl1", Node: "cp1", Role: "control-plane", TS: "2026-10-15T17:42:07Z", NetNS: "host", Proto: "tcp", Local: "0.0.0.0:10256", Peer: "0.0.0.0:*", State: "LISTEN", PID: 400, Process: "kube-proxy", Pod: "kube-system/kube-proxy-x", Container: "kube-proxy"},
		"0.0.0.0:6443":    {Cluster: "wl1", Node: "cp1", Role: "control-plane", TS: "2026-10-15T17:42:07Z", NetNS: "host", Proto: "tcp", Local: "0.0.0.0:6443", Peer: "0.0.0.0:*", State: "LISTEN", PID: 410, Process: "kube-apiserver", Pod: "kube-system/kube-apiserver-cp1", Container: "kube-apiserver"},
		"127.0.0.1:10248": {Cluster: "wl1", Node: "cp1", Role: "control-plane", TS: "2026-10-15T17:42:07Z", NetNS: "host", Proto: "tcp", Local: "127.0.0.1:10248", Peer: "0.0.0.0:*", State: "LISTEN", PID: 300, Process: "kubelet"},
		"0.0.0.0:53":      {Cluster: "wl1", Node: "cp1", Role: "control-plane", TS: "2026-10-15T17:42:07Z", NetNS: "pod", Proto: "tcp", Local: "0.0.0.0:53", Peer: "0.0.0.0:*", State: "LISTEN", PID: 500, Process: "coredns", Pod: "kube-system/coredns-y", Container: "coredns"},
	}
	if len(rows) != len(want) {
		t.Errorf("got %d rows, want %d: %v", len(rows), len(want), rows)
	}
	for k, w := range want {
		if rows[k] != w {
			t.Errorf("row %s:\n got  %+v\n want %+v", k, rows[k], w)
		}
	}
	if !strings.Contains(cm.Data["raw.txt"], `users:(("kube-proxy",pid=400))`) {
		t.Errorf("raw.txt: %s", cm.Data["raw.txt"])
	}
	if cm.Labels[kube.SnapshotLabel] != "true" || cm.Labels[kube.ManagedByLabel] != kube.ManagedByValue {
		t.Errorf("labels: %v", cm.Labels)
	}
}

func TestSnapshotListsOnlyPodsOnItsNode(t *testing.T) {
	client := fake.NewClientset(fixtureObjects()...)
	if err := newCollector(client, "cp1").Snapshot(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, a := range client.Actions() {
		if l, ok := a.(k8stesting.ListAction); ok && a.GetResource().Resource == "pods" {
			if got := l.GetListRestrictions().Fields.String(); got != "spec.nodeName=cp1" {
				t.Errorf("field selector %q", got)
			}
			return
		}
	}
	t.Error("pods were not listed")
}

func TestSnapshotWorkerRoleAndUnknownPod(t *testing.T) {
	client := fake.NewClientset(node("w1", false))
	if err := newCollector(client, "w1").Snapshot(context.Background()); err != nil {
		t.Fatal(err)
	}
	rows, _ := readRows(t, client, "w1")
	r := rows["0.0.0.0:10256"]
	if r.Role != "worker" || r.Node != "w1" || r.Pod != "" || r.Container != "" || r.Process != "kube-proxy" {
		t.Errorf("got %+v", r)
	}
}

func TestSnapshotUpdatesExistingConfigMap(t *testing.T) {
	client := fake.NewClientset(fixtureObjects()...)
	c := newCollector(client, "cp1")
	if err := c.Snapshot(context.Background()); err != nil {
		t.Fatal(err)
	}
	later := fixedTime.Add(time.Minute)
	c.Now = func() time.Time { return later }
	if err := c.Snapshot(context.Background()); err != nil {
		t.Fatal(err)
	}
	rows, _ := readRows(t, client, "cp1")
	if got := rows["0.0.0.0:53"].TS; got != "2026-10-15T17:43:07Z" {
		t.Errorf("ts %s", got)
	}
}

func TestSnapshotFailsWhenNodeMissing(t *testing.T) {
	err := newCollector(fake.NewClientset(), "cp1").Snapshot(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRunSnapshotsImmediatelyAndRetriesAfterErrors(t *testing.T) {
	client := fake.NewClientset(fixtureObjects()...)
	var applies atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client.PrependReactor("patch", "configmaps", func(k8stesting.Action) (bool, runtime.Object, error) {
		if applies.Add(1) == 1 {
			return true, nil, errors.New("boom")
		}
		cancel()
		return false, nil, nil
	})
	done := make(chan struct{})
	go func() {
		newCollector(client, "cp1").Run(ctx, 10*time.Millisecond)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
	if applies.Load() != 2 {
		t.Errorf("applies %d", applies.Load())
	}
	readRows(t, client, "cp1")
}

func TestRunStartsWithoutWaitingForInterval(t *testing.T) {
	client := fake.NewClientset(fixtureObjects()...)
	ctx, cancel := context.WithCancel(context.Background())
	client.PrependReactor("patch", "configmaps", func(k8stesting.Action) (bool, runtime.Object, error) {
		cancel()
		return false, nil, nil
	})
	done := make(chan struct{})
	go func() {
		newCollector(client, "cp1").Run(ctx, time.Hour)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("first snapshot was not immediate")
	}
}

func TestMainValidation(t *testing.T) {
	tests := []struct {
		name, cluster, node string
		args                []string
		wantErr             string
	}{
		{"missing node", "wl1", "", nil, kube.NodeEnv},
		{"missing cluster", "", "cp1", nil, kube.ClusterEnv},
		{"bad interval", "wl1", "cp1", []string{"--interval", "0s"}, "interval"},
		{"unknown flag", "wl1", "cp1", []string{"--bogus"}, "bogus"},
		{"not in cluster", "wl1", "cp1", []string{"--interval", "30s"}, "in-cluster"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(kube.ClusterEnv, tt.cluster)
			t.Setenv(kube.NodeEnv, tt.node)
			t.Setenv("KUBERNETES_SERVICE_HOST", "")
			err := Main(context.Background(), tt.args)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("got %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestSnapshotTakesOverFieldsOwnedByOtherManagers(t *testing.T) {
	client := fake.NewClientset(fixtureObjects()...)
	stale := corev1ac.ConfigMap("snapshot-cp1", kube.Namespace).WithData(map[string]string{"sockets.jsonl": "stale\n"})
	if _, err := client.CoreV1().ConfigMaps(kube.Namespace).Apply(context.Background(), stale, metav1.ApplyOptions{FieldManager: "kubectl"}); err != nil {
		t.Fatal(err)
	}
	if err := newCollector(client, "cp1").Snapshot(context.Background()); err != nil {
		t.Fatal(err)
	}
	readRows(t, client, "cp1")
}
