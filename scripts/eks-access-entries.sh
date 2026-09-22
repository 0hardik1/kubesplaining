#!/usr/bin/env bash
#
# Export an EKS cluster's access entries for `kubesplaining scan --eks-access-entries`.
#
# Access entries are the control-plane replacement for the aws-auth ConfigMap.
# They live in the EKS API, not in the cluster, so the collector cannot list
# them; this script gathers them with the AWS CLI and prints one JSON document
# on stdout that internal/eksaccess reads:
#
#   {
#     "cluster": { "name": ..., "accessConfig": { "authenticationMode": ... } },
#     "accessEntries": [
#       { "accessEntry": <describe-access-entry .accessEntry>,
#         "associatedAccessPolicies": <list-associated-access-policies .associatedAccessPolicies> },
#       ...
#     ]
#   }
#
# Usage:
#   scripts/eks-access-entries.sh <cluster-name> [--region <region>] [--profile <profile>] > entries.json
#   kubesplaining scan --eks-access-entries entries.json
#
# Read-only IAM actions required: eks:DescribeCluster, eks:ListAccessEntries,
# eks:DescribeAccessEntry, eks:ListAssociatedAccessPolicies.
#
# `aws` and `jq` resolve from the Hermit-managed bin/ when run from the repo;
# any recent AWS CLI v2 and jq 1.6+ work outside it.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
case ":${PATH}:" in
  *":${ROOT_DIR}/bin:"*) ;;
  *) export PATH="${ROOT_DIR}/bin:${PATH}" ;;
esac

usage() {
  sed -n '2,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
  exit 2
}

CLUSTER=""
AWS_ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --region|--profile)
      [ $# -ge 2 ] || usage
      AWS_ARGS+=("$1" "$2"); shift 2 ;;
    -h|--help) usage ;;
    -*) echo "unknown flag: $1" >&2; usage ;;
    *)
      [ -z "$CLUSTER" ] || usage
      CLUSTER="$1"; shift ;;
  esac
done
[ -n "$CLUSTER" ] || usage

for cmd in aws jq; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "missing required command: $cmd" >&2; exit 1; }
done

aws_eks() { aws eks "$@" "${AWS_ARGS[@]}" --output json; }

cluster_json="$(aws_eks describe-cluster --name "$CLUSTER" \
  | jq '{name: .cluster.name, accessConfig: (.cluster.accessConfig // {})}')"

mode="$(jq -r '.accessConfig.authenticationMode // "unknown"' <<<"$cluster_json")"
echo "cluster ${CLUSTER}: authenticationMode=${mode}" >&2

# list-access-entries paginates on nextToken; the CLI handles that when
# --no-paginate is not passed, so one call returns every principal.
principals="$(aws_eks list-access-entries --cluster-name "$CLUSTER" | jq -r '.accessEntries[]')"

entries="[]"
count=0
while IFS= read -r principal; do
  [ -n "$principal" ] || continue
  entry="$(aws_eks describe-access-entry --cluster-name "$CLUSTER" --principal-arn "$principal" | jq '.accessEntry')"
  policies="$(aws_eks list-associated-access-policies --cluster-name "$CLUSTER" --principal-arn "$principal" \
    | jq '.associatedAccessPolicies // []')"
  entries="$(jq -n --argjson all "$entries" --argjson e "$entry" --argjson p "$policies" \
    '$all + [{accessEntry: $e, associatedAccessPolicies: $p}]')"
  count=$((count + 1))
done <<<"$principals"

echo "exported ${count} access entries" >&2

jq -n --argjson cluster "$cluster_json" --argjson entries "$entries" \
  '{cluster: $cluster, accessEntries: $entries}'
