package sockets

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"text/tabwriter"
)

type Row struct {
	Cluster   string `json:"cluster"`
	Node      string `json:"node"`
	Role      string `json:"role"`
	TS        string `json:"ts"`
	NetNS     string `json:"netns"`
	Proto     string `json:"proto"`
	Local     string `json:"local"`
	Peer      string `json:"peer"`
	State     string `json:"state"`
	PID       int    `json:"pid"`
	Process   string `json:"process"`
	Pod       string `json:"pod"`
	Container string `json:"container"`
}

const TruncatedMarker = "... truncated to fit the ConfigMap size limit"

// Render returns sockets.jsonl, an ss-style raw.txt whose combined size is at most limit, and the number of rows
// kept in sockets.jsonl. raw.txt is truncated first; sockets.jsonl is cut at a row boundary only if it alone does not fit.
func Render(rows []Row, limit int) (jsonl, raw string, kept int) {
	var j strings.Builder
	for _, r := range rows {
		b, _ := json.Marshal(r)
		j.Write(b)
		j.WriteByte('\n')
	}
	jsonl, raw = j.String(), renderRaw(rows)
	if len(jsonl)+len(raw) <= limit {
		return jsonl, raw, len(rows)
	}
	marker := TruncatedMarker + "\n"
	if len(jsonl) <= limit-len(marker) {
		return jsonl, cutAtLine(raw, limit-len(marker)-len(jsonl)) + marker, len(rows)
	}
	jsonl = cutAtLine(jsonl, limit-len(jsonlMarker(len(rows), len(rows))))
	kept = strings.Count(jsonl, "\n")
	return jsonl, jsonlMarker(kept, len(rows)), kept
}

func jsonlMarker(kept, total int) string {
	return fmt.Sprintf("%s; sockets.jsonl kept %d of %d rows\n", TruncatedMarker, kept, total)
}

func cutAtLine(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if len(s) <= n {
		return s
	}
	return s[:strings.LastIndexByte(s[:n], '\n')+1]
}

func renderRaw(rows []Row) string {
	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 8, 2, ' ', 0)
	fmt.Fprintln(w, "Netid\tState\tLocal Address:Port\tPeer Address:Port\tNetns\tProcess\tPod\tContainer")
	for _, r := range rows {
		process := ""
		if r.PID != 0 {
			process = fmt.Sprintf("users:((%q,pid=%d))", r.Process, r.PID)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", r.Proto, r.State, r.Local, r.Peer, r.NetNS, process, r.Pod, r.Container)
	}
	w.Flush()
	var out strings.Builder
	for line := range strings.Lines(buf.String()) {
		out.WriteString(strings.TrimRight(line, " \n") + "\n")
	}
	return out.String()
}
