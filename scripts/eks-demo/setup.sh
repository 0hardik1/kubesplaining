#!/usr/bin/env bash
#
# Provisions the kubesplaining EKS live demo (`make eks-demo-up`).
#
# Creates: an EKS cluster named holy-splain in the operator's AWS account, an
# IAM role HolySplainProdDataPipelineAdministrator federated via the cluster's OIDC
# provider to a specific Kubernetes ServiceAccount, an S3 bucket with a fake
# flag, the Kubernetes workloads that exercise both privesc chains, and an
# aws-auth entry mapping the IAM role to system:masters. Total wall-clock:
# ~12 minutes for first-run.
#
# Idempotent: re-running against an existing cluster is a no-op for the
# cluster itself (eksctl detects the existing CloudFormation stack) and
# refreshes IAM trust + permissions and the aws-auth mapping in place. See
# docs/eks-demo.md for details.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "${SCRIPT_DIR}/common.sh"

ASSUME_YES=0
for arg in "$@"; do
  case "${arg}" in
    --yes|-y) ASSUME_YES=1 ;;
    --help|-h)
      cat <<EOF
usage: scripts/eks-demo/setup.sh [--yes]

Provisions the kubesplaining EKS demo against the AWS account resolved by
your local credentials. See docs/eks-demo.md for the full walkthrough.

Flags:
  --yes, -y   Skip the interactive confirmation prompt (also via EKS_DEMO_ASSUME_YES=1).
  --help, -h  Show this message.

Environment:
  AWS_REGION / AWS_DEFAULT_REGION   Override region resolution.
  EKS_DEMO_ASSUME_YES=1             Same as --yes.
EOF
      exit 0
      ;;
    *)
      err "unknown argument: ${arg}"
      exit 2
      ;;
  esac
done
export ASSUME_YES

step "Pre-flight: tool checks and AWS context"
require_cmd aws    "Run \`./bin/hermit install awscli\` from the repo root."
require_cmd eksctl "Run \`./bin/hermit install eksctl\` from the repo root."
require_cmd kubectl
require_aws_creds
resolve_region
BUCKET="$(bucket_name)"
ROLE_ARN="$(role_arn)"
ok "AWS identity:  ${CALLER_ARN}"
ok "AWS account:   ${ACCOUNT_ID}"
ok "AWS region:    ${AWS_REGION}"
ok "Cluster name:  ${CLUSTER_NAME}"
ok "IAM role:      ${ROLE_NAME}"
ok "S3 bucket:     ${BUCKET}"

cat <<EOF

${C_BOLD}This will create real AWS resources in account ${ACCOUNT_ID} (${AWS_REGION}):${C_RESET}
  - EKS cluster:        ${CLUSTER_NAME} (eksctl-managed CloudFormation stack)
  - Managed nodegroup:  2x t3.small
  - IAM role:           ${ROLE_NAME} (OIDC-federated to a K8s ServiceAccount)
  - S3 bucket:          ${BUCKET}
  - aws-auth mapping:   IAM role -> system:masters

${C_BOLD}Estimated cost:${C_RESET} ~\$0.10/hr cluster + ~\$0.04/hr nodes + NAT/data ~\$0.05/hr
                 ~\$5/day if left running. Run \`make eks-demo-down\` to remove.

${C_DIM}Set EKS_DEMO_ASSUME_YES=1 or pass --yes to skip this prompt in CI.${C_RESET}
EOF

if ! confirm "Proceed with cluster creation?"; then
  err "aborted by user"
  exit 1
fi

# --- Phase 2: Cluster + OIDC + nodegroup -------------------------------------
step "Creating EKS cluster ${CLUSTER_NAME} (this takes ~12 minutes)"
# We pipe an inline ClusterConfig to `eksctl create cluster -f -` rather than
# templating a file. The config is short and only used here; keeping it inline
# means the script is self-contained.
#
# accessConfig.authenticationMode is load-bearing: without it, future eksctl
# versions defaulting to API-only mode would silently neuter aws-auth so the
# PoC's final loop-back step (`aws eks update-kubeconfig --role-arn`) would
# fail. We assert the mode again post-create as belt-and-suspenders.
if eksctl get cluster --name "${CLUSTER_NAME}" --region "${AWS_REGION}" >/dev/null 2>&1; then
  warn "cluster ${CLUSTER_NAME} already exists in ${AWS_REGION}; skipping create"
  ok "existing cluster reused (re-run will refresh IAM, aws-auth, K8s manifests in place)"
else
  eksctl create cluster -f - <<EOF | prefix_ok
apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig
metadata:
  name: ${CLUSTER_NAME}
  region: ${AWS_REGION}
  tags:
    kubesplaining.demo: holy-splain
iam:
  withOIDC: true
accessConfig:
  authenticationMode: API_AND_CONFIG_MAP
  bootstrapClusterCreatorAdminPermissions: true
managedNodeGroups:
  - name: default
    instanceType: t3.small
    desiredCapacity: 2
    minSize: 2
    maxSize: 2
    labels:
      kubesplaining.demo: holy-splain
    tags:
      kubesplaining.demo: holy-splain
EOF
fi
ok "cluster created"

step "Verifying authenticationMode"
AUTH_MODE="$(aws eks describe-cluster --name "${CLUSTER_NAME}" --region "${AWS_REGION}" \
  --query 'cluster.accessConfig.authenticationMode' --output text 2>/dev/null || echo UNKNOWN)"
case "${AUTH_MODE}" in
  API_AND_CONFIG_MAP|CONFIG_MAP)
    ok "authenticationMode=${AUTH_MODE} (aws-auth ConfigMap is load-bearing)"
    ;;
  *)
    err "authenticationMode=${AUTH_MODE} but the PoC requires API_AND_CONFIG_MAP or CONFIG_MAP."
    err "Update the cluster: aws eks update-cluster-config --name ${CLUSTER_NAME} --region ${AWS_REGION} \\"
    err "  --access-config authenticationMode=API_AND_CONFIG_MAP"
    exit 1
    ;;
esac

step "Retrieving OIDC issuer for IRSA trust policy"
OIDC_ISSUER_FULL="$(aws eks describe-cluster --name "${CLUSTER_NAME}" --region "${AWS_REGION}" \
  --query 'cluster.identity.oidc.issuer' --output text)"
# The IAM trust policy condition key uses the issuer without the https:// prefix.
OIDC_ISSUER="${OIDC_ISSUER_FULL#https://}"
export OIDC_ISSUER
ok "OIDC issuer: ${OIDC_ISSUER}"

# --- Phase 5: S3 bucket + flag.txt -------------------------------------------
step "Creating S3 bucket ${BUCKET}"
if aws s3api head-bucket --bucket "${BUCKET}" 2>/dev/null; then
  ok "bucket already exists; reusing"
else
  # us-east-1 must NOT pass LocationConstraint, every other region must.
  if [[ "${AWS_REGION}" == "us-east-1" ]]; then
    aws s3api create-bucket --bucket "${BUCKET}" --region "${AWS_REGION}" >/dev/null
  else
    aws s3api create-bucket --bucket "${BUCKET}" --region "${AWS_REGION}" \
      --create-bucket-configuration "LocationConstraint=${AWS_REGION}" >/dev/null
  fi
  ok "bucket created"
fi
aws s3api put-public-access-block --bucket "${BUCKET}" \
  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true >/dev/null
aws s3api put-bucket-tagging --bucket "${BUCKET}" \
  --tagging 'TagSet=[{Key=kubesplaining.demo,Value=holy-splain}]' >/dev/null
printf 'you found the kubesplaining demo flag\n' \
  | aws s3 cp - "s3://${BUCKET}/flag.txt" >/dev/null
ok "flag.txt staged in s3://${BUCKET}/flag.txt"

# --- Phase 6: IAM role HolySplainProdDataPipelineAdministrator -----------------------
step "Creating IAM role ${ROLE_NAME}"
TRUST_FILE="${TMP_DIR}/eks-demo-trust.json"
PERMS_FILE="${TMP_DIR}/eks-demo-perms.json"
sed \
  -e "s|__ACCOUNT_ID__|${ACCOUNT_ID}|g" \
  -e "s|__OIDC_ISSUER__|${OIDC_ISSUER}|g" \
  "${ROOT_DIR}/testdata/eks-demo/iam/data-pipeline-trust.json" > "${TRUST_FILE}"
sed -e "s|__BUCKET__|${BUCKET}|g" \
  "${ROOT_DIR}/testdata/eks-demo/iam/data-pipeline-perms.json" > "${PERMS_FILE}"

if aws iam get-role --role-name "${ROLE_NAME}" >/dev/null 2>&1; then
  ok "role exists; refreshing trust + permissions in place"
  aws iam update-assume-role-policy --role-name "${ROLE_NAME}" \
    --policy-document "file://${TRUST_FILE}" >/dev/null
else
  aws iam create-role --role-name "${ROLE_NAME}" \
    --assume-role-policy-document "file://${TRUST_FILE}" \
    --description "kubesplaining holy-splain demo: prod-data-pipeline IRSA role" \
    --tags Key=kubesplaining.demo,Value=holy-splain >/dev/null
  ok "role created"
fi
aws iam put-role-policy --role-name "${ROLE_NAME}" \
  --policy-name HolySplainProdDataPipelinePerms \
  --policy-document "file://${PERMS_FILE}" >/dev/null
ok "inline permissions policy applied"

# IAM propagation lag: AssumeRoleWithWebIdentity can return InvalidIdentityToken
# for ~10-30s after the role's trust policy is written. The PoC's step 7 also
# retries, but we sleep here so the rest of setup doesn't race the propagation.
sleep 15
ok "IAM propagation delay (15s) absorbed"

# --- Phase 7: Apply K8s manifests --------------------------------------------
step "Applying Kubernetes manifests"
# kubectl uses the current context, which eksctl set to the new cluster.
sed -e "s|__ACCOUNT_ID__|${ACCOUNT_ID}|g" \
  "${ROOT_DIR}/testdata/eks-demo/k8s-manifests.yaml" \
  | kubectl apply -f - | prefix_ok
ok "manifests applied"

step "Waiting for prod-data-processor DaemonSet to roll out"
# Without the wait, poc.sh step 5 (token harvest) can race the kubelet's
# projected-token volume mount and find an empty /var/lib/kubelet entry.
kubectl rollout status daemonset/prod-data-processor -n prod-data --timeout=5m | prefix_ok
ok "DaemonSet ready: one prod-data-pipeline-sa pod per node"

# --- Phase 8: aws-auth -> system:masters mapping -----------------------------
step "Mapping ${ROLE_NAME} -> system:masters via aws-auth"
# eksctl is the supported owner of the aws-auth ConfigMap. Using `kubectl edit`
# works once but subsequent eksctl operations that touch identity mapping
# (e.g. nodegroup ops) would clobber an ad-hoc edit.
if eksctl get iamidentitymapping --cluster "${CLUSTER_NAME}" --region "${AWS_REGION}" --arn "${ROLE_ARN}" 2>/dev/null | grep -q "${ROLE_ARN}"; then
  ok "iamidentitymapping already present for ${ROLE_NAME}"
else
  eksctl create iamidentitymapping \
    --cluster "${CLUSTER_NAME}" --region "${AWS_REGION}" \
    --arn "${ROLE_ARN}" \
    --group system:masters \
    --username "${ROLE_USERNAME}" 2>&1 | prefix_ok
fi

step "Sanity-checking aws-auth ConfigMap"
if kubectl get configmap aws-auth -n kube-system -o yaml | grep -q "${ROLE_NAME}"; then
  ok "aws-auth contains the ${ROLE_NAME} mapping"
else
  err "aws-auth ConfigMap does not reference ${ROLE_NAME} after iamidentitymapping create"
  err "Inspect: kubectl get configmap aws-auth -n kube-system -o yaml"
  exit 1
fi

# --- Phase 10: persist state ---------------------------------------------------
state_save
ok "state written to ${STATE_FILE}"

# --- Final banner ------------------------------------------------------------
RULE="═══════════════════════════════════════════════════════════════════════"
printf "\n%s%s%s\n" "${C_BOLD}${C_GREEN}" "${RULE}" "${C_RESET}"
printf "  %s✓ holy-splain EKS demo is ready%s\n" "${C_BOLD}${C_GREEN}" "${C_RESET}"
printf "%s%s%s\n\n" "${C_BOLD}${C_GREEN}" "${RULE}" "${C_RESET}"

printf "  %sNext steps%s\n" "${C_BOLD}" "${C_RESET}"
printf "    %s1.%s  %smake eks-demo-scan%s\n" "${C_DIM}" "${C_RESET}" "${C_BLUE}" "${C_RESET}"
printf "        %sproduces .tmp/eks-demo-snapshot.json + .tmp/eks-demo-report/report.html${C_RESET}\n" "${C_DIM}"
printf "    %s2.%s  %smake eks-demo-poc%s              %s(dry-run, prints all steps)${C_RESET}\n" "${C_DIM}" "${C_RESET}" "${C_BLUE}" "${C_RESET}" "${C_DIM}"
printf "        %sthen ${C_BLUE}./scripts/eks-demo/poc.sh --execute${C_RESET}  %sto actually run them${C_RESET}\n" "${C_DIM}" "${C_DIM}"
printf "    %s3.%s  %smake eks-demo-down%s             %s(removes cluster + IAM + S3)${C_RESET}\n\n" "${C_DIM}" "${C_RESET}" "${C_BLUE}" "${C_RESET}" "${C_DIM}"

printf "  %sCost reminder%s\n" "${C_BOLD}" "${C_RESET}"
printf "    %s~\$5/day while running. Set an AWS Budget for safety.${C_RESET}\n\n" "${C_DIM}"
