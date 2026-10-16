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
	"github.com/rosenhouse-bot-sandbox/kglance/internal/state"
	"github.com/rosenhouse-bot-sandbox/kglance/internal/version"
)

func TestParseSetupDefaults(t *testing.T) {
	o, kc, err := parseSetup([]string{"--workload", "kind-t1"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	abs := func(p string) string { a, _ := filepath.Abs(p); return a }
	if o.TTL != time.Hour || o.Interval != time.Minute || o.Wait != 2*time.Minute || o.Image != version.Image() ||
		o.KubeconfigPath != abs("agent.kubeconfig") || o.StatePath != abs("kglance.state.json") || o.InstructionsPath != "" || kc != "" {
		t.Fatalf("%+v", o)
	}
	if len(o.Targets) != 1 || o.Targets[0] != (setup.Target{Name: "kind-t1", Role: state.RoleWorkload, Context: "kind-t1"}) {
		t.Fatalf("%+v", o.Targets)
	}
}

func TestParseSetupAllFlags(t *testing.T) {
	o, kc, err := parseSetup([]string{"--mgmt", "mgmt=m-ctx", "--workload", "wl1=a", "--workload", "wl2=b", "--ttl", "2h", "-o", "x.kubeconfig",
		"--state", "s.json", "--image", "img:2", "--interval", "30s", "--instructions", "i.txt", "--wait", "0s", "--kubeconfig", "/admin"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	want := []setup.Target{{Name: "mgmt", Role: state.RoleMgmt, Context: "m-ctx"}, {Name: "wl1", Role: state.RoleWorkload, Context: "a"}, {Name: "wl2", Role: state.RoleWorkload, Context: "b"}}
	if len(o.Targets) != 3 || o.Targets[0] != want[0] || o.Targets[1] != want[1] || o.Targets[2] != want[2] {
		t.Fatalf("%+v", o.Targets)
	}
	if o.TTL != 2*time.Hour || filepath.Base(o.KubeconfigPath) != "x.kubeconfig" || !filepath.IsAbs(o.KubeconfigPath) ||
		filepath.Base(o.StatePath) != "s.json" || o.Image != "img:2" || o.Interval != 30*time.Second ||
		o.InstructionsPath != "i.txt" || o.Wait != 0 || kc != "/admin" {
		t.Fatalf("%+v", o)
	}
	o2, _, err := parseSetup([]string{"--workload", "a", "--output", "y.kubeconfig"}, io.Discard)
	if err != nil || filepath.Base(o2.KubeconfigPath) != "y.kubeconfig" {
		t.Fatalf("--output: %+v %v", o2, err)
	}
}

func TestParseSetupRejectsBadInput(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"--workload", "=x"},
		{"--workload", "a", "--ttl", "9h"},
		{"--mgmt", "a", "--mgmt", "b"},
		{"--workload", "a", "extra"},
	} {
		if _, _, err := parseSetup(args, io.Discard); err == nil {
			t.Errorf("%v: expected error", args)
		}
	}
}

func TestParseTeardown(t *testing.T) {
	o, kc, err := parseTeardown([]string{"--context", "a", "--context", "b", "--kubeconfig", "/k"}, io.Discard)
	if err != nil || len(o.Contexts) != 2 || o.Contexts[1] != "b" || kc != "/k" || filepath.Base(o.StatePath) != "kglance.state.json" {
		t.Fatalf("%+v %v", o, err)
	}
	o, _, err = parseTeardown([]string{"--state", "s.json"}, io.Discard)
	if err != nil || filepath.Base(o.StatePath) != "s.json" || len(o.Contexts) != 0 {
		t.Fatalf("%+v %v", o, err)
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
	if code := run([]string{"setup"}, &bytes.Buffer{}, &errOut); code != 2 {
		t.Errorf("setup without targets: %d %q", code, errOut.String())
	}
}

func TestParseSetupRecordsAdminKubeconfigs(t *testing.T) {
	t.Setenv("KUBECONFIG", "/a"+string(os.PathListSeparator)+"/b")
	o, _, err := parseSetup([]string{"--workload", "x"}, io.Discard)
	if err != nil || !slices.Equal(o.AdminKubeconfigs, []string{"/a", "/b"}) {
		t.Fatalf("%v %v", o.AdminKubeconfigs, err)
	}
	o, _, err = parseSetup([]string{"--workload", "x", "--kubeconfig", "/admin"}, io.Discard)
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
	for _, args := range [][]string{{"--help"}, {}} {
		var out, errOut bytes.Buffer
		run(args, &out, &errOut)
		if got := out.String() + errOut.String(); !strings.HasPrefix(got, want) || !strings.Contains(got, "usage:") {
			t.Errorf("%v: %q", args, got)
		}
	}
}

func TestHelpDescribesCommands(t *testing.T) {
	cases := map[string]string{
		"--help":      "Create read-only service accounts",
		"setup -h":    "Re-running setup mints fresh tokens",
		"teardown -h": "revokes the agent's tokens",
	}
	for args, want := range cases {
		var out, errOut bytes.Buffer
		if code := run(strings.Fields(args), &out, &errOut); code != 0 || !strings.Contains(out.String()+errOut.String(), want) {
			t.Errorf("%s: %d %q", args, code, out.String()+errOut.String())
		}
	}
}
