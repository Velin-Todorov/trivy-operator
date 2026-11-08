#!/usr/bin/env bash
set -euo pipefail

NAME="${1:-imagescan-sample}"

kubectl delete imagescan "$NAME"
kubectl apply -f ./config/samples/security_v1alpha1_imagescan.yaml