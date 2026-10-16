package version

import "testing"

func TestResolve(t *testing.T) {
	for _, c := range []struct{ ldflag, buildInfo, want string }{
		{"v1.2.3", "", "v1.2.3"},
		{"v1.2.3", "v9.9.9", "v1.2.3"},
		{"", "v1.2.3", "v1.2.3"},
		{"", "v1.2.3-rc.1", "v1.2.3-rc.1"},
		{"", "", Dev},
		{"", "(devel)", Dev},
		{"", "v0.0.0-20261015120000-614b212abcde", Dev},
		{"", "v1.2.4-0.20261015120000-614b212abcde", Dev},
		{"", "v1.2.3-rc.1.0.20261015120000-614b212abcde", Dev},
		{"", "v1.2.3+dirty", Dev},
		{"v1.2", "", Dev},
		{"1.2.3", "", Dev},
		{"vfoo", "v1.2.3", Dev},
	} {
		if got := resolve(c.ldflag, c.buildInfo); got != c.want {
			t.Errorf("resolve(%q, %q) = %q, want %q", c.ldflag, c.buildInfo, got, c.want)
		}
	}
}

func TestImageFor(t *testing.T) {
	if got := imageFor("v1.2.3"); got != "ghcr.io/rosenhouse-bot-sandbox/kglance:v1.2.3" {
		t.Error(got)
	}
	if got := imageFor(Dev); got != "ghcr.io/rosenhouse-bot-sandbox/kglance:latest" {
		t.Error(got)
	}
}
