#!/usr/bin/env bash
# Usage: hack/build-release.sh VERSION OUTDIR
# Builds kglance for each release platform and writes SHA256SUMS.
set -euo pipefail
version=$1 out=$2
ldflags="-s -X github.com/rosenhouse-bot-sandbox/kglance/internal/version.tag=$version"
mkdir -p "$out"
for platform in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do
  bin="kglance-${platform%/*}-${platform#*/}"
  CGO_ENABLED=0 GOOS=${platform%/*} GOARCH=${platform#*/} go build -trimpath -ldflags "$ldflags" -o "$out/$bin" .
done
(cd "$out" && sha256sum kglance-* > SHA256SUMS)

got=$("$out/kglance-$(go env GOOS)-$(go env GOARCH)" version)
want="kglance $version
collector image ghcr.io/rosenhouse-bot-sandbox/kglance:$version"
if [[ "$got" != "$want" ]]; then
  echo "built binary reports \"$got\", want \"$want\"" >&2
  exit 1
fi
