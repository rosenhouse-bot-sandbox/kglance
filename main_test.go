package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rosenhouse-bot-sandbox/kglance/internal/setup"
	"github.com/rosenhouse-bot-sandbox/kglance/internal/version"
)

func TestParseSetupDefaults(t *testing.T) {
	o, kc, err := parseSetup(nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	abs := func(p string) string { a, _ := filepath.Abs(p); return a }
	if o.TTL != time.Hour || o.Interval != time.Minute || o.Wait != 2*time.Minute || o.Image != version.Image() ||
		o.KubeconfigPath != abs("agent.kubeconfig") || o.StatePath != abs("kglance.state.json") || o.InstructionsPath != "" || kc != "" {
		t.Fatalf("%+v", o)
	}
	if o.MgmtContext != "" || len(o.Workloads) != 0 {
		t.Fatalf("%+v", o)
	}
}

func TestParseSetupAllFlags(t *testing.T) {
	o, kc, err := parseSetup([]string{"--context", "m-ctx", "--workload", "wl1=ns1/a", "--workload", "ns2/b", "--ttl", "2h", "-o", "x.kubeconfig",
		"--state", "s.json", "--image", "img:2", "--interval", "30s", "--instructions", "i.txt", "--wait", "0s", "--kubeconfig", "/admin"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	want := []setup.Workload{{Name: "wl1", Cluster: "ns1/a"}, {Name: "b", Cluster: "ns2/b"}}
	if o.MgmtContext != "m-ctx" || !slices.Equal(o.Workloads, want) {
		t.Fatalf("%+v", o)
	}
	if o.TTL != 2*time.Hour || filepath.Base(o.KubeconfigPath) != "x.kubeconfig" || !filepath.IsAbs(o.KubeconfigPath) ||
		filepath.Base(o.StatePath) != "s.json" || o.Image != "img:2" || o.Interval != 30*time.Second ||
		o.InstructionsPath != "i.txt" || o.Wait != 0 || kc != "/admin" {
		t.Fatalf("%+v", o)
	}
	o2, _, err := parseSetup([]string{"--output", "y.kubeconfig"}, io.Discard)
	if err != nil || filepath.Base(o2.KubeconfigPath) != "y.kubeconfig" {
		t.Fatalf("--output: %+v %v", o2, err)
	}
}

func TestParseSetupRejectsBadInput(t *testing.T) {
	for _, args := range [][]string{
		{"--workload", "=ns/x"},
		{"--workload", "x"},
		{"--workload", "ns/a", "--workload", "other/a"},
		{"--ttl", "9h"},
		{"--mgmt", "a"},
		{"extra"},
	} {
		if _, _, err := parseSetup(args, io.Discard); err == nil {
			t.Errorf("%v: expected error", args)
		}
	}
}

func TestParseTeardown(t *testing.T) {
	o, kc, err := parseTeardown([]string{"--context", "a", "--workload", "ns1/b", "--workload", "c=ns2/c", "--kubeconfig", "/k"}, io.Discard)
	if err != nil || !o.ByLabel || o.MgmtContext != "a" || !slices.Equal(o.Workloads, []string{"ns1/b", "ns2/c"}) || kc != "/k" || filepath.Base(o.StatePath) != "kglance.state.json" {
		t.Fatalf("%+v %v", o, err)
	}
	o, _, err = parseTeardown([]string{"--workload", "ns1/b"}, io.Discard)
	if err != nil || !o.ByLabel || o.MgmtContext != "" {
		t.Fatalf("%+v %v", o, err)
	}
	o, _, err = parseTeardown([]string{"--state", "s.json"}, io.Discard)
	if err != nil || filepath.Base(o.StatePath) != "s.json" || o.ByLabel {
		t.Fatalf("%+v %v", o, err)
	}
	if _, _, err := parseTeardown([]string{"--workload", "b"}, io.Discard); err == nil {
		t.Fatal("expected error for workload without namespace")
	}
	if _, _, err := parseTeardown([]string{"--state", "s.json", "--context", "a"}, io.Discard); err == nil {
		t.Fatal("expected error for --state with --context")
	}
}

func TestRunDispatch(t *testing.T) {
	var errOut bytes.Buffer
	if code := run([]string{"bogus"}, &bytes.Buffer{}, &errOut); code != 2 || !strings.Contains(errOut.String(), "usage") {
		t.Errorf("bogus: %d %q", code, errOut.String())
	}
	var gotArgs []string
	collect = func(_ context.Context, args []string) error { gotArgs = args; return errors.New("boom") }
	errOut.Reset()
	if code := run([]string{"collect", "--interval", "5s"}, &bytes.Buffer{}, &errOut); code != 1 || !strings.Contains(errOut.String(), "boom") ||
		strings.Join(gotArgs, " ") != "--interval 5s" {
		t.Errorf("collect: %d %q %v", code, errOut.String(), gotArgs)
	}
	errOut.Reset()
	if code := run([]string{"setup", "--workload", "x"}, &bytes.Buffer{}, &errOut); code != 2 {
		t.Errorf("setup with bad workload: %d %q", code, errOut.String())
	}
}

func TestParseSetupRecordsAdminKubeconfigs(t *testing.T) {
	t.Setenv("KUBECONFIG", "/a"+string(os.PathListSeparator)+"/b")
	o, _, err := parseSetup(nil, io.Discard)
	if err != nil || !slices.Equal(o.AdminKubeconfigs, []string{"/a", "/b"}) {
		t.Fatalf("%v %v", o.AdminKubeconfigs, err)
	}
	o, _, err = parseSetup([]string{"--kubeconfig", "/admin"}, io.Discard)
	if err != nil || !slices.Equal(o.AdminKubeconfigs, []string{"/admin"}) {
		t.Fatalf("%v %v", o.AdminKubeconfigs, err)
	}
}

func TestRunPrintsVersion(t *testing.T) {
	want := "kglance dev\ncollector image ghcr.io/rosenhouse-bot-sandbox/kglance:latest\n"
	for _, args := range [][]string{{"version"}, {"--version"}} {
		var out bytes.Buffer
		if code := run(args, &out, &bytes.Buffer{}); code != 0 || out.String() != want {
			t.Errorf("%v: %d %q", args, code, out.String())
		}
	}
}

func TestHelpDescribesCommands(t *testing.T) {
	cases := map[string]string{
		"--help":      "Creates read-only service accounts",
		"-h":          "Removes everything setup created",
		"help":        "Prints the version",
		"setup -h":    "Re-running setup mints fresh tokens",
		"teardown -h": "revokes the agent's tokens",
	}
	for args, want := range cases {
		var out, errOut bytes.Buffer
		if code := run(strings.Fields(args), &out, &errOut); code != 0 || !strings.Contains(out.String()+errOut.String(), want) {
			t.Errorf("%s: %d %q", args, code, out.String()+errOut.String())
		}
	}
	var errOut bytes.Buffer
	if code := run(nil, &bytes.Buffer{}, &errOut); code != 2 || !strings.Contains(errOut.String(), "usage:") {
		t.Errorf("no args: %d %q", code, errOut.String())
	}
}
