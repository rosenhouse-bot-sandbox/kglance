package sockets

import "testing"

func TestParseCgroup(t *testing.T) {
	const cid = "faf022051c28d0a7cf1c1589a086280cf6db0e00a748ddcee59a17634c4ff984"
	tests := []struct {
		name, cgroup, pod, container string
	}{
		{
			name: "v1 systemd kind",
			cgroup: "9:name=systemd:/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/kubelet-kubepods-besteffort-podba6f01d9_f38f_4fed_832a_6720946f4478.slice/cri-containerd-" + cid + ".scope\n" +
				"8:pids:/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/kubelet-kubepods-besteffort-podba6f01d9_f38f_4fed_832a_6720946f4478.slice/cri-containerd-" + cid + ".scope\n" +
				"0::/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/kubelet-kubepods-besteffort-podba6f01d9_f38f_4fed_832a_6720946f4478.slice/cri-containerd-" + cid + ".scope\n",
			pod: "ba6f01d9-f38f-4fed-832a-6720946f4478", container: cid,
		},
		{
			name:   "v2 systemd guaranteed",
			cgroup: "0::/kubepods.slice/kubepods-pod0f3a2b1c_1111_2222_3333_444455556666.slice/cri-containerd-" + cid + ".scope\n",
			pod:    "0f3a2b1c-1111-2222-3333-444455556666", container: cid,
		},
		{
			name:   "v2 systemd static pod hash uid",
			cgroup: "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podd7074538ef01b4afc0034d2e51859c63.slice/cri-containerd-" + cid + ".scope\n",
			pod:    "d7074538ef01b4afc0034d2e51859c63", container: cid,
		},
		{
			name:   "v2 cgroupns relative path",
			cgroup: "0::/../../kubepods-besteffort-podba6f01d9_f38f_4fed_832a_6720946f4478.slice/cri-containerd-" + cid + ".scope\n",
			pod:    "ba6f01d9-f38f-4fed-832a-6720946f4478", container: cid,
		},
		{
			name:   "cgroupfs containerd",
			cgroup: "0::/kubepods/besteffort/podba6f01d9-f38f-4fed-832a-6720946f4478/" + cid + "\n",
			pod:    "ba6f01d9-f38f-4fed-832a-6720946f4478", container: cid,
		},
		{
			name:   "cgroupfs guaranteed",
			cgroup: "4:memory:/kubepods/podba6f01d9-f38f-4fed-832a-6720946f4478/" + cid + "\n",
			pod:    "ba6f01d9-f38f-4fed-832a-6720946f4478", container: cid,
		},
		{
			name:   "cri-o",
			cgroup: "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podba6f01d9_f38f_4fed_832a_6720946f4478.slice/crio-" + cid + ".scope\n",
			pod:    "ba6f01d9-f38f-4fed-832a-6720946f4478", container: cid,
		},
		{
			name:   "cri-o conmon is not the container",
			cgroup: "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podba6f01d9_f38f_4fed_832a_6720946f4478.slice/crio-conmon-" + cid + ".scope\n",
			pod:    "ba6f01d9-f38f-4fed-832a-6720946f4478", container: "",
		},
		{
			name:   "docker",
			cgroup: "1:name=systemd:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podba6f01d9_f38f_4fed_832a_6720946f4478.slice/docker-" + cid + ".scope\n",
			pod:    "ba6f01d9-f38f-4fed-832a-6720946f4478", container: cid,
		},
		{
			name:   "host service",
			cgroup: "0::/kubelet.slice/kubelet.service\n",
		},
		{
			name:   "pod slice without container",
			cgroup: "0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podba6f01d9_f38f_4fed_832a_6720946f4478.slice\n",
			pod:    "ba6f01d9-f38f-4fed-832a-6720946f4478",
		},
		{name: "empty"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod, container := ParseCgroup(tt.cgroup)
			if pod != tt.pod || container != tt.container {
				t.Errorf("got (%q, %q), want (%q, %q)", pod, container, tt.pod, tt.container)
			}
		})
	}
}
