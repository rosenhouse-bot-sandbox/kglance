# kglance

kglance gives an AI agent expiring, read-only `kubectl` access to Cluster API management and workload clusters.
It also runs a DaemonSet that snapshots every node's listening TCP/UDP sockets, attributed to pods and containers.
A human with admin access runs kglance. The agent only uses `kubectl`.

## Install

Download a binary from [Releases](https://github.com/rosenhouse-bot-sandbox/kglance/releases), or run:

```bash
go install github.com/rosenhouse-bot-sandbox/kglance@latest
```

`kglance version` prints the version and its collector image, `ghcr.io/rosenhouse-bot-sandbox/kglance:<version>`.
Builds not made from a release tag report `dev` and use the `:latest` image.
Override the image with `setup --image`.

## Usage

```bash
# Human, with the admin kubeconfig
$ kglance setup --mgmt mgmt=mgmt-ctx --workload wl1=wl1-ctx --workload wl2=wl2-ctx --ttl 1h -o agent.kubeconfig
wrote agent.kubeconfig (contexts: mgmt, wl1, wl2; expires 19:10 UTC)
wrote kglance.state.json
socket collector running on 7 nodes (3 control-plane, 4 worker)

# Agent
$ export KUBECONFIG=agent.kubeconfig
$ kubectl --context mgmt get clusters -A
$ kubectl --context wl1 get events -A
$ kubectl --context wl1 -n kglance get configmaps -l kglance.io/snapshot \
    -o go-template='{{range .items}}{{index .data "sockets.jsonl"}}{{end}}' > wl1-sockets.jsonl
$ head -1 wl1-sockets.jsonl
{"cluster":"wl1","node":"wl1-cp-abc12","role":"control-plane","ts":"2026-10-15T18:42:00Z","netns":"host","proto":"tcp","local":"0.0.0.0:6443","peer":"0.0.0.0:*","state":"LISTEN","pid":1234,"process":"kube-apiserver","pod":"kube-system/kube-apiserver-wl1-cp-abc12","container":"kube-apiserver"}

# Human: remove everything and revoke the agent's tokens
$ kglance teardown
read kglance.state.json: removing kglance from mgmt, wl1, wl2 ... done
```

Re-running `setup` mints fresh tokens without restarting the collector.
Without a state file, `kglance teardown --context ctx...` removes objects labelled `app.kubernetes.io/managed-by=kglance`.
Run `kglance setup -h` for all flags.

## Permissions

| Who | Cluster | Access |
|---|---|---|
| Agent | mgmt | get/list/watch on CAPI API groups, namespaces, nodes and events. No secrets. |
| Agent | workload | `view` without logs, exec, attach, port-forward, proxy or secrets, plus events and ConfigMaps in `kglance`. |
| Collector | workload | get/list pods, get nodes, write ConfigMaps in `kglance`. |

Tokens are TokenRequest tokens with a 1h default TTL and an 8h maximum.
The collector pod uses host network and host PID, runs as uid 0 with a read-only root filesystem,
drops all capabilities except `SYS_PTRACE` and `DAC_READ_SEARCH`, and mounts no host paths.

## Development

```bash
go test ./...
docker build -t kglance:dev .
hack/e2e-kind.sh   # creates Kind clusters kglance-mgmt and kglance-wl
```

## Releasing

Push a `vX.Y.Z` tag, or run the `release` workflow on `main`:

```bash
gh workflow run release.yml -f version=vX.Y.Z
```

CI runs the tests, pushes the `vX.Y.Z` image and publishes the binaries as a GitHub Release.
