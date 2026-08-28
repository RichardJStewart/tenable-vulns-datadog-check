#!/usr/bin/env bash
# Creates the Kubernetes Secret referenced by envFrom in
# values-tenable-cluster-check.yaml. Run once (or whenever credentials
# rotate) before `helm upgrade`.
#
# Usage:
#   TENABLE_ACCESS_KEY=... TENABLE_SECRET_KEY=... \
#   DD_API_KEY=... DD_APP_KEY=... \
#   ./create-secret.sh datadog   # <namespace>

set -euo pipefail
NAMESPACE="${1:-datadog}"

: "${TENABLE_ACCESS_KEY:?Set TENABLE_ACCESS_KEY}"
: "${TENABLE_SECRET_KEY:?Set TENABLE_SECRET_KEY}"
: "${DD_API_KEY:?Set DD_API_KEY}"
: "${DD_APP_KEY:?Set DD_APP_KEY}"

kubectl create secret generic tenable-datadog-check-secrets \
  --namespace "${NAMESPACE}" \
  --from-literal=TENABLE_ACCESS_KEY="${TENABLE_ACCESS_KEY}" \
  --from-literal=TENABLE_SECRET_KEY="${TENABLE_SECRET_KEY}" \
  --from-literal=DD_API_KEY="${DD_API_KEY}" \
  --from-literal=DD_APP_KEY="${DD_APP_KEY}" \
  --dry-run=client -o yaml | kubectl apply -f -
