package sockets

import (
	"encoding/json"
	"strings"
	"testing"
)

var sampleRows = []Row{
	{Cluster: "wl1", Node: "cp1", Role: "control-plane", TS: "2026-10-15T18:42:00Z", NetNS: "host", Proto: "tcp", Local: "0.0.0.0:6443", Peer: "0.0.0.0:*", State: "LISTEN", PID: 1234, Process: "kube-apiserver", Pod: "kube-system/kube-apiserver-cp1", Container: "kube-apiserver"},
	{Cluster: "wl1", Node: "cp1", Role: "control-plane", TS: "2026-10-15T18:42:00Z", NetNS: "host", Proto: "udp", Local: "127.0.0.11:47296", Peer: "0.0.0.0:*", State: "UNCONN"},
}

func TestRowJSONFieldOrder(t *testing.T) {
	b, err := json.Marshal(sampleRows[0])
	if err != nil {
		t.Fatal(err)
	}
	want := `{"cluster":"wl1","node":"cp1","role":"control-plane","ts":"2026-10-15T18:42:00Z","netns":"host","proto":"tcp","local":"0.0.0.0:6443","peer":"0.0.0.0:*","state":"LISTEN","pid":1234,"process":"kube-apiserver","pod":"kube-system/kube-apiserver-cp1","container":"kube-apiserver"}`
	if string(b) != want {
		t.Errorf("got  %s\nwant %s", b, want)
	}
}

func TestRender(t *testing.T) {
	jsonl, raw, kept := Render(sampleRows, 1<<20)
	if kept != 2 {
		t.Errorf("kept %d", kept)
	}
	lines := strings.Split(strings.TrimSuffix(jsonl, "\n"), "\n")
	if len(lines) != 2 || !strings.HasSuffix(jsonl, "\n") {
		t.Fatalf("jsonl: %q", jsonl)
	}
	var r Row
	if err := json.Unmarshal([]byte(lines[1]), &r); err != nil || r != sampleRows[1] {
		t.Errorf("row 2 round trip: %+v %v", r, err)
	}
	rawLines := strings.Split(strings.TrimSuffix(raw, "\n"), "\n")
	if len(rawLines) != 3 {
		t.Fatalf("raw: %q", raw)
	}
	for _, f := range []string{"Netid", "State", "Local", "Peer", "Process", "Pod", "Container"} {
		if !strings.Contains(rawLines[0], f) {
			t.Errorf("header %q lacks %s", rawLines[0], f)
		}
	}
	for _, f := range []string{"tcp", "LISTEN", "0.0.0.0:6443", `users:(("kube-apiserver",pid=1234))`, "kube-system/kube-apiserver-cp1", "host"} {
		if !strings.Contains(rawLines[1], f) {
			t.Errorf("line %q lacks %s", rawLines[1], f)
		}
	}
	if strings.Contains(rawLines[2], "users:") {
		t.Errorf("unowned socket shows a process: %q", rawLines[2])
	}
}

func TestRenderTruncatesRawFirst(t *testing.T) {
	jsonl, _, _ := Render(sampleRows, 1<<20)
	limit := len(jsonl) + 60
	gotJSONL, raw, kept := Render(sampleRows, limit)
	if gotJSONL != jsonl || kept != 2 {
		t.Errorf("jsonl changed: %q", gotJSONL)
	}
	if len(gotJSONL)+len(raw) > limit {
		t.Errorf("total %d exceeds %d", len(gotJSONL)+len(raw), limit)
	}
	if !strings.HasSuffix(raw, TruncatedMarker+"\n") {
		t.Errorf("raw lacks marker: %q", raw)
	}
}

func TestRenderTruncatesJSONLAtRowBoundary(t *testing.T) {
	one, _, _ := Render(sampleRows[:1], 1<<20)
	jsonl, raw, kept := Render(sampleRows, len(one)+200)
	if jsonl != one || kept != 1 {
		t.Errorf("kept %d jsonl: %q", kept, jsonl)
	}
	if raw != TruncatedMarker+"; sockets.jsonl kept 1 of 2 rows\n" {
		t.Errorf("raw: %q", raw)
	}
}
