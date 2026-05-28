#!/usr/bin/env bash
#
# Tears down the kubesplaining EKS live demo (`make eks-demo-down`).
#
# Removes (in reverse order, tolerant of "already gone" at each step):
#   - Demo K8s workloads (in case the cluster is still up)
#   - aws-auth iamidentitymapping
#   - S3 bucket (contents first, then bucket)
#   - IAM role + inline policy
#   - EKS cluster (eksctl delete cluster --wait, ~10 minutes)
#   - kubeconfig contexts added by the PoC
#
# Reads its state from .tmp/eks-demo-state.json (written by setup.sh). If the
# state file is missing, accept --cluster / --region / --role / --bucket flags.
# `--keep-iam` skips IAM + S3 deletion so the operator can rerun the PoC
# without recreating IAM trust + permissions.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "${SCRIPT_DIR}/common.sh"

ASSUME_YES=0
KEEP_IAM=0
OVERRIDE_CLUSTER=""
OVERRIDE_REGION=""
OVERRIDE_ROLE=""
OVERRIDE_BUCKET=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes|-y)        ASSUME_YES=1; shift ;;
    --keep-iam)      KEEP_IAM=1; shift ;;
    --cluster)       OVERRIDE_CLUSTER="$2"; shift 2 ;;
    --region)        OVERRIDE_REGION="$2"; shift 2 ;;
    --role)          OVERRIDE_ROLE="$2"; shift 2 ;;
    --bucket)        OVERRIDE_BUCKET="$2"; shift 2 ;;
    --help|-h)
      cat <<EOF
usage: scripts/eks-demo/teardown.sh [--yes] [--keep-iam] \\
         [--cluster <name>] [--region <region>] [--role <name>] [--bucket <name>]

Removes everything setup.sh created. Reads .tmp/eks-demo-state.json by default;
override values via flags when the state file is missing (e.g. for partial-state
recovery after an aborted setup).

Flags:
  --yes, -y    Skip the destruction confirmation prompt (also via EKS_DEMO_ASSUME_YES=1).
  --keep-iam   Skip IAM role + S3 bucket deletion (useful when re-running the PoC).
  --cluster    Override cluster name (default: from state file).
  --region     Override region.
  --role       Override IAM role name.
  --bucket     Override S3 bucket name.
EOF
      exit 0
      ;;
    *)
      err "unknown argument: $1"
      exit 2
      ;;
  esac
done
export ASSUME_YES

step "Pre-flight: tool checks and state resolution"
require_cmd aws    "Run \`./bin/hermit install awscli\` from the repo root."
require_cmd eksctl "Run \`./bin/hermit install eksctl\` from the repo root."
require_cmd kubectl

STATE_BUCKET=""
STATE_CREATED_AT=""
if state_load; then
  ok "loaded state from ${STATE_FILE}"
else
  warn "operating from flags / defaults only"
fi

# Apply overrides; fall back to module defaults if neither state nor flags set.
[[ -n "${OVERRIDE_CLUSTER}" ]] && CLUSTER_NAME="${OVERRIDE_CLUSTER}"
[[ -n "${OVERRIDE_REGION}" ]]  && AWS_REGION="${OVERRIDE_REGION}"
[[ -n "${OVERRIDE_ROLE}" ]]    && ROLE_NAME="${OVERRIDE_ROLE}"
if [[ -z "${AWS_REGION:-}" ]]; then resolve_region; fi
if [[ -z "${ACCOUNT_ID:-}" ]]; then require_aws_creds; fi
BUCKET="${OVERRIDE_BUCKET:-${STATE_BUCKET:-$(bucket_name)}}"
ROLE_ARN="$(role_arn)"

ok "Cluster:   ${CLUSTER_NAME}"
ok "Region:    ${AWS_REGION}"
ok "Role:      ${ROLE_NAME}"
ok "Bucket:    ${BUCKET}"

if [[ -n "${STATE_CREATED_AT}" ]]; then
  # Best-effort uptime print. macOS `date -j` and GNU `date -d` have different
  # flags so we fall back gracefully if the parse fails.
  if HOURS=$(python3 -c "
import datetime, sys
t = datetime.datetime.strptime('${STATE_CREATED_AT}', '%Y-%m-%dT%H:%M:%SZ')
delta = datetime.datetime.utcnow() - t
print(int(delta.total_seconds() // 3600))
" 2>/dev/null); then
    COST=$(python3 -c "print(round(${HOURS} * 0.21, 2))")
    ok "Uptime:    ${HOURS} hours (approximately \$${COST} in AWS spend so far)"
  fi
fi

if [[ "${KEEP_IAM}" == "1" ]]; then
  warn "--keep-iam: IAM role and S3 bucket will NOT be deleted"
fi

if ! confirm "Destroy all of the above? This is irreversible."; then
  err "aborted by user"
  exit 1
fi

# --- Phase 3: K8s workloads -------------------------------------------------
step "Deleting Kubernetes workloads"
if kubectl cluster-info >/dev/null 2>&1; then
  sed -e "s|__ACCOUNT_ID__|${ACCOUNT_ID}|g" \
    "${ROOT_DIR}/testdata/eks-demo/k8s-manifests.yaml" \
    | kubectl delete -f - --ignore-not-found 2>&1 | prefix_ok || true
  kubectl delete pod attacker -n "${NAMESPACE_DEV}" --ignore-not-found 2>&1 | prefix_ok || true
  ok "K8s workloads removed (or were already gone)"
else
  warn "kubectl cannot reach a cluster; skipping K8s workload deletion"
fi

# --- Phase 4: iamidentitymapping --------------------------------------------
step "Removing aws-auth iamidentitymapping"
eksctl delete iamidentitymapping --cluster "${CLUSTER_NAME}" --region "${AWS_REGION}" \
  --arn "${ROLE_ARN}" 2>&1 | prefix_ok || warn "no mapping to remove (already gone)"

# --- Phase 5+6: S3 + IAM (optional via --keep-iam) --------------------------
if [[ "${KEEP_IAM}" != "1" ]]; then
  step "Emptying and deleting S3 bucket ${BUCKET}"
  if aws s3api head-bucket --bucket "${BUCKET}" 2>/dev/null; then
    aws s3 rm "s3://${BUCKET}" --recursive 2>&1 | prefix_ok || true
    aws s3api delete-bucket --bucket "${BUCKET}" 2>&1 | prefix_ok || warn "bucket deletion failed (manual cleanup may be required)"
    ok "bucket deleted"
  else
    ok "bucket already gone"
  fi

  step "Deleting IAM role ${ROLE_NAME}"
  if aws iam get-role --role-name "${ROLE_NAME}" >/dev/null 2>&1; then
    aws iam delete-role-policy --role-name "${ROLE_NAME}" \
      --policy-name HolySplainProdDataPipelinePerms 2>&1 | prefix_ok || true
    aws iam delete-role --role-name "${ROLE_NAME}" 2>&1 | prefix_ok || true
    ok "role deleted"
  else
    ok "role already gone"
  fi
fi

# --- Phase 7: EKS cluster ---------------------------------------------------
step "Deleting EKS cluster ${CLUSTER_NAME} (this takes ~10 minutes)"
if eksctl get cluster --name "${CLUSTER_NAME}" --region "${AWS_REGION}" >/dev/null 2>&1; then
  eksctl delete cluster --name "${CLUSTER_NAME}" --region "${AWS_REGION}" --wait 2>&1 | prefix_ok
  ok "cluster deleted"
else
  ok "cluster already gone"
fi

# --- Phase 8: kubeconfig context cleanup ------------------------------------
step "Cleaning up kubeconfig contexts added by the PoC"
kubectl config delete-context "${CONTEXT_ATTACKER}"        2>/dev/null && ok "removed context ${CONTEXT_ATTACKER}"        || ok "context ${CONTEXT_ATTACKER} was not present"
kubectl config delete-user    holy-splain-dev-deployer-sa  2>/dev/null && ok "removed user holy-splain-dev-deployer-sa"   || ok "user holy-splain-dev-deployer-sa was not present"
kubectl config delete-context "${CONTEXT_ADMIN_LOOPBACK}"  2>/dev/null && ok "removed context ${CONTEXT_ADMIN_LOOPBACK}"  || ok "context ${CONTEXT_ADMIN_LOOPBACK} was not present"

# Remove the state file so a future re-up starts fresh.
rm -f "${STATE_FILE}"
ok "state file removed"

# --- Final banner -----------------------------------------------------------
RULE="═══════════════════════════════════════════════════════════════════════"
printf "\n%s%s%s\n" "${C_BOLD}${C_GREEN}" "${RULE}" "${C_RESET}"
printf "  %s✓ holy-splain teardown complete%s\n" "${C_BOLD}${C_GREEN}" "${C_RESET}"
printf "%s%s%s\n\n" "${C_BOLD}${C_GREEN}" "${RULE}" "${C_RESET}"

printf "  %sVerify nothing is left behind${C_RESET}\n" "${C_BOLD}"
printf "    %saws eks list-clusters --region ${AWS_REGION} | grep ${CLUSTER_NAME}${C_RESET}\n" "${C_DIM}"
printf "    %saws iam list-roles --query \"Roles[?starts_with(RoleName, \\\`HolySplain\\\`)].RoleName\"${C_RESET}\n" "${C_DIM}"
printf "    %saws s3 ls | grep holysplain${C_RESET}\n" "${C_DIM}"
printf "    %skubectl config get-contexts | grep holy-splain${C_RESET}\n\n" "${C_DIM}"
