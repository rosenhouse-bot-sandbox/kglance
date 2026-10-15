package sockets

import (
	"errors"
	"fmt"
	"io/fs"
	"reflect"
	"testing"
	"testing/fstest"
)

const (
	hostNS  = "net:[4026531840]"
	podNS   = "net:[4026532469]"
	cidKP   = "faf022051c28d0a7cf1c1589a086280cf6db0e00a748ddcee59a17634c4ff984"
	cidDNS  = "00de48bc54e7d0b214a962ee3f95e697286c2af5af415ec8aec79552edd15b73"
	uidKP   = "ba6f01d9-f38f-4fed-832a-6720946f4478"
	uidDNS  = "947e2a0c-454e-4671-858f-7122dacc4048"
	kubelet = "0::/kubelet.slice/kubelet.service\n"
)

func cgroupV1(uid, cid string) string {
	u := uidUnderscored(uid)
	p := "/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/kubelet-kubepods-besteffort-pod" + u + ".slice/cri-containerd-" + cid + ".scope"
	return "9:name=systemd:" + p + "\n1:cpu:" + p + "\n0::" + p + "\n"
}

func uidUnderscored(uid string) string {
	b := []byte(uid)
	for i := range b {
		if b[i] == '-' {
			b[i] = '_'
		}
	}
	return string(b)
}

type proc struct {
	pid    int
	comm   string
	cgroup string
	netns  string
	fds    map[string]string
	net    map[string]string
}

func procFS(procs ...proc) fstest.MapFS {
	m := fstest.MapFS{}
	for _, p := range procs {
		d := fmt.Sprint(p.pid)
		m[d+"/comm"] = &fstest.MapFile{Data: []byte(p.comm + "\n")}
		m[d+"/cgroup"] = &fstest.MapFile{Data: []byte(p.cgroup)}
		m[d+"/ns/net"] = &fstest.MapFile{Mode: fs.ModeSymlink, Data: []byte(p.netns)}
		m[d+"/fd"] = &fstest.MapFile{Mode: fs.ModeDir}
		for fd, target := range p.fds {
			m[d+"/fd/"+fd] = &fstest.MapFile{Mode: fs.ModeSymlink, Data: []byte(target)}
		}
		for name, data := range p.net {
			m[d+"/net/"+name] = &fstest.MapFile{Data: []byte(data)}
		}
	}
	m["self"] = &fstest.MapFile{Mode: fs.ModeSymlink, Data: []byte("1")}
	return m
}

const header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

func tcpLine(hexAddr string, inode int) string {
	return fmt.Sprintf("   0: %s 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 %d 1 0000000000000000 100 0 0 10 0\n", hexAddr, inode)
}

func udpLine(hexAddr string, inode int) string {
	return fmt.Sprintf("   0: %s 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 %d 2 0000000000000000 0\n", hexAddr, inode)
}

func hostNet() map[string]string {
	return map[string]string{
		"tcp": header + tcpLine("00000000:2810", 100) + tcpLine("0100007F:2808", 101) + tcpLine("0100007F:9999", 102),
		"udp": header + udpLine("0B00007F:B8C0", 103),
	}
}

func podNet() map[string]string {
	return map[string]string{
		"tcp":  header + tcpLine("00000000:0035", 200),
		"udp":  header + udpLine("00000000:0035", 201),
		"tcp6": header + "   0: 00000000000000000000000000000000:23C1 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 202 1 0000000000000000 100 0 0 10 0\n",
		"udp6": header,
	}
}

func TestScan(t *testing.T) {
	fsys := procFS(
		proc{pid: 1, comm: "systemd", cgroup: "0::/init.scope\n", netns: hostNS, net: hostNet()},
		proc{pid: 300, comm: "kubelet", cgroup: kubelet, netns: hostNS, net: hostNet(),
			fds: map[string]string{"0": "/dev/null", "7": "socket:[101]", "8": "pipe:[5]", "9": "socket:[555]"}},
		proc{pid: 400, comm: "kube-proxy", cgroup: cgroupV1(uidKP, cidKP), netns: hostNS, net: hostNet(),
			fds: map[string]string{"3": "socket:[100]"}},
		proc{pid: 500, comm: "coredns", cgroup: cgroupV1(uidDNS, cidDNS), netns: podNS, net: podNet(),
			fds: map[string]string{"5": "socket:[200]", "6": "socket:[201]", "7": "socket:[202]"}},
		proc{pid: 501, comm: "coredns-child", cgroup: cgroupV1(uidDNS, cidDNS), netns: podNS, net: podNet(),
			fds: map[string]string{"5": "socket:[200]"}},
	)
	got, err := Scan(fsys)
	if err != nil {
		t.Fatal(err)
	}
	want := []Socket{
		{NetNS: "host", Proto: "tcp", Local: "0.0.0.0:10256", Peer: "0.0.0.0:*", State: "LISTEN", PID: 400, Process: "kube-proxy", PodUID: uidKP, ContainerID: cidKP},
		{NetNS: "host", Proto: "tcp", Local: "127.0.0.1:10248", Peer: "0.0.0.0:*", State: "LISTEN", PID: 300, Process: "kubelet"},
		{NetNS: "host", Proto: "tcp", Local: "127.0.0.1:39321", Peer: "0.0.0.0:*", State: "LISTEN"},
		{NetNS: "host", Proto: "udp", Local: "127.0.0.11:47296", Peer: "0.0.0.0:*", State: "UNCONN"},
		{NetNS: "pod", Proto: "tcp", Local: "0.0.0.0:53", Peer: "0.0.0.0:*", State: "LISTEN", PID: 500, Process: "coredns", PodUID: uidDNS, ContainerID: cidDNS},
		{NetNS: "pod", Proto: "tcp6", Local: "[::]:9153", Peer: "[::]:*", State: "LISTEN", PID: 500, Process: "coredns", PodUID: uidDNS, ContainerID: cidDNS},
		{NetNS: "pod", Proto: "udp", Local: "0.0.0.0:53", Peer: "0.0.0.0:*", State: "UNCONN", PID: 500, Process: "coredns", PodUID: uidDNS, ContainerID: cidDNS},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got:\n%s\nwant:\n%s", dump(got), dump(want))
	}
}

func dump(ss []Socket) string {
	s := ""
	for _, x := range ss {
		s += fmt.Sprintf("%+v\n", x)
	}
	return s
}

func TestScanMultiplePodNetns(t *testing.T) {
	const otherNS = "net:[4026532600]"
	fsys := procFS(
		proc{pid: 1, comm: "systemd", cgroup: "0::/init.scope\n", netns: hostNS, net: hostNet()},
		proc{pid: 500, comm: "coredns", cgroup: cgroupV1(uidDNS, cidDNS), netns: podNS, net: podNet(),
			fds: map[string]string{"5": "socket:[200]"}},
		proc{pid: 600, comm: "nginx", cgroup: cgroupV1(uidKP, cidKP), netns: otherNS,
			net: map[string]string{"tcp": header + tcpLine("00000000:0050", 300)}, fds: map[string]string{"4": "socket:[300]"}},
	)
	got, err := Scan(fsys)
	if err != nil {
		t.Fatal(err)
	}
	var nginx *Socket
	pod := 0
	for i := range got {
		if got[i].NetNS == "pod" {
			pod++
		}
		if got[i].Local == "0.0.0.0:80" {
			nginx = &got[i]
		}
	}
	if nginx == nil || nginx.Process != "nginx" || nginx.NetNS != "pod" {
		t.Fatalf("nginx socket missing or wrong: %+v", nginx)
	}
	if pod != 4 {
		t.Errorf("got %d pod-netns sockets, want 4:\n%s", pod, dump(got))
	}
}

func TestScanMissingIPv6Files(t *testing.T) {
	fsys := procFS(proc{pid: 1, comm: "systemd", cgroup: "0::/init.scope\n", netns: hostNS, net: hostNet()})
	got, err := Scan(fsys)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Errorf("got %d sockets, want 4:\n%s", len(got), dump(got))
	}
}

// vanishingFS makes the listed paths fail as if their process exited after the /proc listing.
type vanishingFS struct {
	m    fstest.MapFS
	gone map[string]bool
}

func (v vanishingFS) Open(name string) (fs.File, error) {
	if v.gone[name] {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	return v.m.Open(name)
}

func (v vanishingFS) ReadLink(name string) (string, error) {
	if v.gone[name] {
		return "", &fs.PathError{Op: "readlink", Path: name, Err: fs.ErrNotExist}
	}
	return v.m.ReadLink(name)
}

func TestScanToleratesVanishingProcesses(t *testing.T) {
	fsys := vanishingFS{
		m: procFS(
			proc{pid: 1, comm: "systemd", cgroup: "0::/init.scope\n", netns: hostNS, net: hostNet()},
			proc{pid: 300, comm: "kubelet", cgroup: kubelet, netns: hostNS, fds: map[string]string{"7": "socket:[101]"}},
			proc{pid: 450, comm: "gone", cgroup: kubelet, netns: hostNS, fds: map[string]string{"3": "socket:[102]"}},
			proc{pid: 470, comm: "gone-ns", cgroup: kubelet, netns: hostNS},
			proc{pid: 480, comm: "gone-fd", cgroup: kubelet, netns: hostNS, fds: map[string]string{"3": "socket:[100]"}},
			// 490 is the first process seen in podNS but exits before its net files are read; 500 stands in.
			proc{pid: 490, comm: "early", cgroup: cgroupV1(uidDNS, cidDNS), netns: podNS},
			proc{pid: 500, comm: "coredns", cgroup: cgroupV1(uidDNS, cidDNS), netns: podNS, net: podNet(),
				fds: map[string]string{"5": "socket:[200]"}},
		),
		gone: map[string]bool{"450/fd": true, "470/ns/net": true, "480/fd/3": true, "490/net/tcp": true},
	}
	got, err := Scan(fsys)
	if err != nil {
		t.Fatal(err)
	}
	byLocal := map[string]Socket{}
	for _, s := range got {
		byLocal[s.Proto+" "+s.Local] = s
	}
	if s := byLocal["tcp 127.0.0.1:10248"]; s.Process != "kubelet" {
		t.Errorf("kubelet socket: %+v", s)
	}
	if s := byLocal["tcp 127.0.0.1:39321"]; s.PID != 0 {
		t.Errorf("socket of vanished process should be unowned: %+v", s)
	}
	if s := byLocal["tcp 0.0.0.0:53"]; s.Process != "coredns" {
		t.Errorf("pod netns should be read via a surviving process: %+v", s)
	}
}

func TestScanFailsWithoutHostNetns(t *testing.T) {
	_, err := Scan(fstest.MapFS{"self": &fstest.MapFile{Mode: fs.ModeSymlink, Data: []byte("1")}})
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("got %v", err)
	}
}

func (v vanishingFS) Lstat(name string) (fs.FileInfo, error) {
	if v.gone[name] {
		return nil, &fs.PathError{Op: "lstat", Path: name, Err: fs.ErrNotExist}
	}
	return v.m.Lstat(name)
}
