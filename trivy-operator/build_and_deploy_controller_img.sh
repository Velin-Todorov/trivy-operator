#!/usr/bin/env bash

set -euo pipefail

IMG="controller:latest"
CLUSTER="trivy-op"
NAMESPACE="velin-todorov-system"
DEPLOYMENT="velin-todorov-controller-manager"

make docker-build IMG="$IMG"
~/go/bin/kind load docker-image "$IMG" --name "$CLUSTER"
make deploy IMG="$IMG"
kubectl -n "$NAMESPACE" rollout restart "deployment/$DEPLOYMENT"
kubectl -n "$NAMESPACE" rollout status "deployment/$DEPLOYMENT" --timeout=2m
