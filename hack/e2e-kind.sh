#!/usr/bin/env bash
# Runs the e2e test on Kind clusters kglance-mgmt and kglance-wl, creating them if needed.
# IMAGE must already be built locally. KIND_CONFIG optionally names a kind cluster config.
set -euo pipefail
cd "$(dirname "$0")/.."
image=${IMAGE:-kglance:dev}
node_image=${NODE_IMAGE:-kindest/node:v1.36.4}
listener_image=busybox:1.37
mgmt=${MGMT_CLUSTER:-kglance-mgmt}
wl=${WORKLOAD_CLUSTER:-kglance-wl}

create() {
  kind get clusters | grep -qx "$1" && return
  kind create cluster --name "$1" --image "$node_image" ${KIND_CONFIG:+--config "$KIND_CONFIG"} --wait 2m
}

load() {
  local tar
  tar=$(mktemp)
  docker save --platform linux/amd64 -o "$tar" "$1" 2>/dev/null || docker save -o "$tar" "$1"
  kind load image-archive "$tar" --name "$2"
  rm -f "$tar"
}

create "$mgmt"
create "$wl"
hack/install-capi-crds.sh "kind-$mgmt"
docker image inspect "$listener_image" >/dev/null 2>&1 || docker pull "$listener_image"
load "$image" "$wl"
load "$listener_image" "$wl"

KGLANCE_E2E_MGMT_CONTEXT="kind-$mgmt" KGLANCE_E2E_WORKLOAD_CONTEXT="kind-$wl" \
  KGLANCE_E2E_IMAGE="$image" KGLANCE_E2E_LISTENER_IMAGE="$listener_image" \
  go test -tags e2e -count=1 -v -timeout 15m ./e2e
