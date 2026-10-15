package sockets

import (
	"regexp"
	"strings"
)

var (
	podUIDPattern      = regexp.MustCompile(`pod([0-9a-f]{8}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{12}|[0-9a-f]{32})(\.slice)?$`)
	containerIDPattern = regexp.MustCompile(`^(?:cri-containerd-|crio-|docker-)?([0-9a-f]{64})(?:\.scope)?$`)
)

// ParseCgroup extracts the pod UID and container ID from /proc/<pid>/cgroup content.
func ParseCgroup(content string) (podUID, containerID string) {
	for line := range strings.Lines(content) {
		_, path, ok := cutLast(strings.TrimSpace(line))
		if !ok {
			continue
		}
		segs := strings.Split(path, "/")
		for i, seg := range segs {
			m := podUIDPattern.FindStringSubmatch(seg)
			if m == nil {
				continue
			}
			podUID = strings.ReplaceAll(m[1], "_", "-")
			if i+1 < len(segs) {
				if c := containerIDPattern.FindStringSubmatch(segs[i+1]); c != nil {
					containerID = c[1]
				}
			}
			return podUID, containerID
		}
	}
	return "", ""
}

// cutLast splits "hierarchy:controllers:path" at the second colon.
func cutLast(line string) (string, string, bool) {
	_, rest, ok := strings.Cut(line, ":")
	if !ok {
		return "", "", false
	}
	return strings.Cut(rest, ":")
}
