// Package sockets lists listening TCP and unconnected UDP sockets from a /proc file system.
package sockets

import (
	"cmp"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

type Socket struct {
	NetNS       string
	Proto       string
	Local       string
	Peer        string
	State       string
	PID         int
	Process     string
	PodUID      string
	ContainerID string
}

const (
	NetNSHost = "host"
	NetNSPod  = "pod"
)

// netnsKind is the single place that classifies a network namespace.
func netnsKind(ns, hostNS string) string {
	if ns == hostNS {
		return NetNSHost
	}
	return NetNSPod
}

var protos = []string{"tcp", "tcp6", "udp", "udp6"}

// Scan reads every network namespace visible in proc (rooted at /proc) and attributes sockets to processes.
func Scan(proc fs.FS) ([]Socket, error) {
	hostNS, err := fs.ReadLink(proc, "1/ns/net")
	if err != nil {
		return nil, fmt.Errorf("host network namespace: %w", err)
	}
	pids, err := listPIDs(proc)
	if err != nil {
		return nil, err
	}

	var namespaces []string
	nsPIDs := map[string][]int{}
	owner := map[uint64]int{}
	for _, pid := range pids {
		ns, err := fs.ReadLink(proc, strconv.Itoa(pid)+"/ns/net")
		if err != nil {
			continue
		}
		if _, seen := nsPIDs[ns]; !seen {
			namespaces = append(namespaces, ns)
		}
		nsPIDs[ns] = append(nsPIDs[ns], pid)
		for _, inode := range socketInodes(proc, pid) {
			if _, ok := owner[inode]; !ok {
				owner[inode] = pid
			}
		}
	}

	procs := map[int]Socket{}
	var out []Socket
	for _, ns := range namespaces {
		entries, err := readNetns(proc, nsPIDs[ns])
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			s := Socket{NetNS: netnsKind(ns, hostNS), Proto: e.Proto, Local: e.Local, Peer: e.Peer, State: e.State}
			if pid, ok := owner[e.Inode]; ok {
				p, cached := procs[pid]
				if !cached {
					p = processInfo(proc, pid)
					procs[pid] = p
				}
				s.PID, s.Process, s.PodUID, s.ContainerID = p.PID, p.Process, p.PodUID, p.ContainerID
			}
			out = append(out, s)
		}
	}
	slices.SortStableFunc(out, compareSockets)
	return out, nil
}

func listPIDs(proc fs.FS) ([]int, error) {
	entries, err := fs.ReadDir(proc, ".")
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, e := range entries {
		if pid, err := strconv.Atoi(e.Name()); err == nil {
			pids = append(pids, pid)
		}
	}
	slices.Sort(pids)
	return pids, nil
}

func socketInodes(proc fs.FS, pid int) []uint64 {
	dir := strconv.Itoa(pid) + "/fd"
	fds, err := fs.ReadDir(proc, dir)
	if err != nil {
		return nil
	}
	var inodes []uint64
	for _, fd := range fds {
		target, err := fs.ReadLink(proc, dir+"/"+fd.Name())
		if err != nil {
			continue
		}
		n, ok := strings.CutPrefix(target, "socket:[")
		if !ok {
			continue
		}
		if inode, err := strconv.ParseUint(strings.TrimSuffix(n, "]"), 10, 64); err == nil {
			inodes = append(inodes, inode)
		}
	}
	return inodes
}

// readNetns reads the socket tables of one namespace through the first of its processes that is still alive.
func readNetns(proc fs.FS, pids []int) ([]netEntry, error) {
	for _, pid := range pids {
		dir := strconv.Itoa(pid) + "/net/"
		if _, err := fs.Stat(proc, dir+"tcp"); err != nil {
			continue
		}
		var all []netEntry
		for _, p := range protos {
			data, err := fs.ReadFile(proc, dir+p)
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				return nil, err
			}
			entries, err := parseProcNet(p, data)
			if err != nil {
				return nil, fmt.Errorf("pid %d: %w", pid, err)
			}
			all = append(all, entries...)
		}
		return all, nil
	}
	return nil, nil
}

func processInfo(proc fs.FS, pid int) Socket {
	dir := strconv.Itoa(pid) + "/"
	s := Socket{PID: pid}
	if comm, err := fs.ReadFile(proc, dir+"comm"); err == nil {
		s.Process = strings.TrimSpace(string(comm))
	}
	if cg, err := fs.ReadFile(proc, dir+"cgroup"); err == nil {
		s.PodUID, s.ContainerID = ParseCgroup(string(cg))
	}
	return s
}

func compareSockets(a, b Socket) int {
	return cmp.Or(
		cmp.Compare(a.NetNS, b.NetNS),
		cmp.Compare(a.Proto, b.Proto),
		netip.MustParseAddrPort(portOrZero(a.Local)).Compare(netip.MustParseAddrPort(portOrZero(b.Local))),
		cmp.Compare(a.PID, b.PID),
	)
}

func portOrZero(s string) string {
	if t, ok := strings.CutSuffix(s, ":*"); ok {
		return t + ":0"
	}
	return s
}
