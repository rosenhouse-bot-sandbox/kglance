# kglance

kglance lets a cluster admin hand an AI agent temporary, read-only `kubectl` access to Cluster API management and workload clusters, then take it back.

The agent gets only a kubeconfig with expiring tokens and never sees admin credentials.
An admin runs kglance; the agent runs `kubectl`.
On each workload cluster, kglance also runs a collector that records which ports are listening on every node, attributed to pods and containers, so the agent can see that without exec or host access.

## Install

```bash
go install github.com/rosenhouse-bot-sandbox/kglance@latest
```

Binaries are also on the [Releases](https://github.com/rosenhouse-bot-sandbox/kglance/releases) page.

## Getting started

With your admin context on the management cluster, run `setup`, naming the namespace and each workload cluster's Cluster API `Cluster` in it:

```bash
$ kglance setup --mgmt-namespace my-namespace --workload wl1 -o agent.kubeconfig --instructions agent.md
wrote /home/me/agent.kubeconfig (contexts: mgmt, wl1; expires 19:10 UTC)
wrote /home/me/kglance.state.json
socket collector running on 4 nodes (1 control-plane, 3 worker)
...
```

kglance reaches each workload cluster through the kubeconfig Secret that Cluster API keeps for it, so you don't need a context for it.
Give the agent `agent.kubeconfig` and `agent.md`.
The instructions tell it which context does what and how to pull the socket snapshots.
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
| Management | get, list and watch Cluster API objects and events in `--mgmt-namespace`, but not Secrets |
| Workload | the `view` ClusterRole without Secrets, logs, exec, attach, port-forward or proxy |

The collector runs on every Linux node of each workload cluster, including control-plane nodes.
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

CI runs the unit and e2e tests, pushes the `ghcr.io/rosenhouse-bot-sandbox/kglance:vX.Y.Z` image and publishes the binaries as a GitHub Release.
Each binary defaults to the collector image of its own version; `kglance version` shows both.
