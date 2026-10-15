package sockets

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

type netEntry struct {
	Proto, Local, Peer, State string
	Inode                     uint64
}

const (
	tcpListen   = "0A"
	udpUnconn   = "07"
	fieldLocal  = 1
	fieldRemote = 2
	fieldState  = 3
	fieldInode  = 9
)

// parseProcNet parses /proc/net/{tcp,tcp6,udp,udp6}, keeping listening TCP and unconnected UDP sockets.
func parseProcNet(proto string, data []byte) ([]netEntry, error) {
	want, label := tcpListen, "LISTEN"
	if strings.HasPrefix(proto, "udp") {
		want, label = udpUnconn, "UNCONN"
	}
	var out []netEntry
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		f := strings.Fields(line)
		if i == 0 || len(f) == 0 {
			continue
		}
		if len(f) <= fieldInode {
			return nil, fmt.Errorf("%s line %d: too few fields", proto, i+1)
		}
		local, err := parseHexAddr(f[fieldLocal])
		if err != nil {
			return nil, fmt.Errorf("%s line %d: %w", proto, i+1, err)
		}
		inode, err := strconv.ParseUint(f[fieldInode], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%s line %d: %w", proto, i+1, err)
		}
		if f[fieldState] != want {
			continue
		}
		peer, err := parseHexAddr(f[fieldRemote])
		if err != nil {
			return nil, fmt.Errorf("%s line %d: %w", proto, i+1, err)
		}
		out = append(out, netEntry{Proto: proto, Local: formatAddrPort(local), Peer: formatAddrPort(peer), State: label, Inode: inode})
	}
	return out, nil
}

// parseHexAddr decodes "0100007F:0CEA"; the kernel prints each 32-bit address word in host (little-endian) order.
func parseHexAddr(s string) (netip.AddrPort, error) {
	h, p, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("bad address %q", s)
	}
	raw, err := hex.DecodeString(h)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return netip.AddrPort{}, fmt.Errorf("bad address %q", s)
	}
	port, err := strconv.ParseUint(p, 16, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("bad port %q", s)
	}
	for i := 0; i < len(raw); i += 4 {
		binary.BigEndian.PutUint32(raw[i:], binary.LittleEndian.Uint32(raw[i:]))
	}
	addr, _ := netip.AddrFromSlice(raw)
	return netip.AddrPortFrom(addr, uint16(port)), nil
}

func formatAddrPort(ap netip.AddrPort) string {
	if ap.Port() != 0 {
		return ap.String()
	}
	if ap.Addr().Is4() {
		return ap.Addr().String() + ":*"
	}
	return "[" + ap.Addr().String() + "]:*"
}
