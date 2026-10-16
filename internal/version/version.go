// Package version reports the kglance release and the collector image built with it.
package version

import (
	"regexp"
	"runtime/debug"
)

const (
	dev  = "dev"
	repo = "ghcr.io/rosenhouse-bot-sandbox/kglance"
)

// tag is set at link time by release builds.
var tag string

var (
	release = regexp.MustCompile(`^v\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$`)
	pseudo  = regexp.MustCompile(`\d{14}-[0-9a-f]{12}$`)
)

// String returns the release tag, or "dev" for builds not made from a tag.
func String() string {
	var buildInfo string
	if bi, ok := debug.ReadBuildInfo(); ok {
		buildInfo = bi.Main.Version
	}
	return resolve(tag, buildInfo)
}

// Image returns the collector image matching String.
func Image() string { return imageFor(String()) }

func resolve(ldflag, buildInfo string) string {
	v := ldflag
	if v == "" {
		v = buildInfo
	}
	if !release.MatchString(v) || pseudo.MatchString(v) {
		return dev
	}
	return v
}

func imageFor(v string) string {
	if v == dev {
		return repo + ":latest"
	}
	return repo + ":" + v
}
