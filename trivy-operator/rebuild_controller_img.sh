#!/usr/bin/env bash
set -euo pipefail

IMG="controller:latest"
CLUSTER="trivy-op"
NAMESPACE="velin-todorov-system"
DEPLOYMENT="velin-todorov-controller-manager"

make docker-build IMG="$IMG"
~/go/bin/kind load docker-image "$IMG" --name "$CLUSTER"
kubectl -n velin-todorov-system rollout restart deployment/velin-todorov-controller-manager
