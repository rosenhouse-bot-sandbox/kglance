# kglance

kglance lets a cluster admin hand an AI agent temporary, read-only `kubectl` access to Cluster API management and workload clusters, then take it back.

The agent receives a plain kubeconfig whose tokens expire, so it never holds admin credentials and never runs kglance itself.
On each workload cluster, kglance also runs a collector that snapshots every node's listening TCP and UDP sockets, attributed to pods, so the agent can see what is exposed without exec or host access.

## Install

```bash
go install github.com/rosenhouse-bot-sandbox/kglance@latest
```

Binaries are also on the [Releases](https://github.com/rosenhouse-bot-sandbox/kglance/releases) page.

## Getting started

Run `setup` with your admin kubeconfig, naming each cluster's context:

```bash
$ kglance setup --mgmt mgmt=mgmt-ctx --workload wl1=wl1-ctx -o agent.kubeconfig
wrote /work/agent.kubeconfig (contexts: mgmt, wl1; expires 19:10 UTC)
wrote /work/kglance.state.json
socket collector running on 4 nodes (1 control-plane, 3 worker)

Read-only Kubernetes access via kglance. The tokens expire at 2026-10-15 19:10 UTC.
...
```

Give the agent `agent.kubeconfig` and the instructions that `setup` prints.
They tell it which context does what and how to pull the socket snapshots.
Tokens last one hour by default; run `setup` again to mint new ones.

When the agent is done, remove everything and revoke its tokens:

```bash
$ kglance teardown
read kglance.state.json: removing kglance from mgmt, wl1 ... done
```

`kglance setup -h` and `kglance teardown -h` describe every flag.

## What the agent can do

| Cluster | Access |
|---|---|
| Management | get, list and watch Cluster API objects, namespaces, nodes and events. No Secrets. |
| Workload | The `view` ClusterRole minus Secrets, logs, exec, attach, port-forward and proxy, plus events and the socket snapshots. |

The collector runs on every workload node, including control-plane nodes.
It uses the host network and PID namespaces with only `SYS_PTRACE` and `DAC_READ_SEARCH`, mounts no host paths and can only read pods and nodes and write its own ConfigMaps.

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

CI runs the tests, pushes the `ghcr.io/rosenhouse-bot-sandbox/kglance:vX.Y.Z` image and publishes the binaries as a GitHub Release.
Each binary defaults to the collector image of its own version; `kglance version` shows both.
