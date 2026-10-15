#!/usr/bin/env bash
# Installs the Cluster API CRDs (no controllers) into a kubectl context.
set -euo pipefail
context=${1:?usage: $0 CONTEXT}
version=${CAPI_VERSION:-v1.14.3}
curl -sSLf "https://github.com/kubernetes-sigs/cluster-api/releases/download/${version}/cluster-api-components.yaml" |
  yq 'select(.kind == "CustomResourceDefinition")' |
  kubectl --context "$context" apply --server-side -f -
kubectl --context "$context" wait --for=condition=Established crd --all --timeout=60s
