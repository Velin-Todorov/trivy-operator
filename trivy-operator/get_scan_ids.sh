#!/usr/bin/env bash
set -euo pipefail

NAME="${1:-imagescan-sample}"

kubectl get imagescan "$NAME" \
  -o jsonpath='{range .status.scanResults[*]}{.imageRef}{"\t"}{.id}{"\t"}{.phase}{"\n"}{end}'
