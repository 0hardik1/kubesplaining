#!/usr/bin/env bash
#
# Shared helpers for the kubesplaining EKS live demo (`make eks-demo-*`).
# Sourced by setup.sh, teardown.sh, and poc.sh; not directly executable.
#
# Loaded variables / functions:
#   - C_* color constants and step / ok / warn / err / prefix_ok printers
#   - require_cmd, require_aws_creds, resolve_region
#   - ACCOUNT_ID, CALLER_ARN, AWS_REGION populated by resolve_aws_context
#   - Demo constants (cluster name, role name, namespaces, ARNs)
#   - state_save / state_load for .tmp/eks-demo-state.json

set -euo pipefail

# Resolve the repo root from wherever this file is sourced. scripts/eks-demo/*.sh
# all sit two levels under the root.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Prepend the Hermit-managed bin/ so eksctl, aws, kubectl resolve to the pinned
# versions even when the shell has not sourced ./bin/activate-hermit. Matches
# the Makefile's `export PATH := $(CURDIR)/bin:$(PATH)` so direct script
# invocation behaves identically to `make eks-demo-*`.
case ":${PATH}:" in
  *":${ROOT_DIR}/bin:"*) ;;
  *) export PATH="${ROOT_DIR}/bin:${PATH}" ;;
esac

# .tmp is the kubesplaining convention for ephemeral state (shared with the
# kind e2e and the Makefile's GOCACHE).
TMP_DIR="${ROOT_DIR}/.tmp"
mkdir -p "${TMP_DIR}"

STATE_FILE="${TMP_DIR}/eks-demo-state.json"

# Demo constants. None of these contain personally-identifying information so
# the same script reproduces identically across operators and accounts.
CLUSTER_NAME="holy-splain"
ROLE_NAME="HolySplainProdDataPipelineAdministrator"
ROLE_USERNAME="holy-splain-prod-data-pipeline-administrator"
NAMESPACE_DEV="dev-team"
NAMESPACE_PROD="prod-data"
SA_DEV="dev-deployer-sa"
SA_PROD="prod-data-pipeline-sa"
CONTEXT_ATTACKER="holy-splain-attacker"
CONTEXT_ADMIN_LOOPBACK="holy-splain-via-prod-irsa"
ATTACKER_IMAGE="public.ecr.aws/aws-cli/aws-cli:latest"

# ANSI colors when stdout is a terminal and NO_COLOR is not set; plain text under CI / pipes.
# Mirrors the kind-e2e.sh palette for visual consistency across demos.
if [[ -t 1 ]] && [[ -z "${NO_COLOR:-}" ]]; then
  C_RESET=$'\e[0m'
  C_BOLD=$'\e[1m'
  C_DIM=$'\e[2m'
  C_GREEN=$'\e[32m'
  C_YELLOW=$'\e[33m'
  C_BLUE=$'\e[34m'
  C_CYAN=$'\e[36m'
  C_RED=$'\e[31m'
else
  C_RESET=""; C_BOLD=""; C_DIM=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_CYAN=""; C_RED=""
fi

step()      { printf "\n%s▶ %s%s\n" "${C_BOLD}${C_CYAN}" "$*" "${C_RESET}"; }
ok()        { printf "  %s✓%s %s\n" "${C_GREEN}" "${C_RESET}" "$*"; }
warn()      { printf "  %s!%s %s\n" "${C_YELLOW}" "${C_RESET}" "$*" >&2; }
err()       { printf "  %s✗%s %s\n" "${C_RED}" "${C_RESET}" "$*" >&2; }
prefix_ok() { sed "s/^/  ${C_GREEN}✓${C_RESET} /"; }
prefix_dim(){ sed "s/^/  ${C_DIM}/" | sed "s/$/${C_RESET}/"; }

# require_cmd <name> [<install-hint>]
# Exits the script if the command is not on PATH, with a clear hint pointing
# at the Hermit-managed install path used by this repo.
require_cmd() {
  local name="$1"
  local hint="${2:-Run \`./bin/hermit install ${name}\` from the repo root.}"
  if ! command -v "$name" >/dev/null 2>&1; then
    err "missing required command: ${name}"
    err "  ${hint}"
    exit 1
  fi
}

# require_aws_creds
# Verifies that an AWS identity can be resolved from whatever credential chain
# the user has locally (env vars, AWS_PROFILE, instance profile, etc.).
# Exports ACCOUNT_ID and CALLER_ARN on success.
require_aws_creds() {
  local id_json
  if ! id_json="$(aws sts get-caller-identity --output json 2>/dev/null)"; then
    err "could not resolve AWS credentials."
    err "  Check that one of these is set: AWS_PROFILE, AWS_ACCESS_KEY_ID, or an instance profile."
    err "  Run 'aws sts get-caller-identity' standalone to see the error."
    exit 1
  fi
  ACCOUNT_ID="$(printf '%s' "${id_json}" | sed -nE 's/.*"Account": *"([0-9]+)".*/\1/p')"
  CALLER_ARN="$(printf '%s' "${id_json}" | sed -nE 's/.*"Arn": *"([^"]+)".*/\1/p')"
  if [[ -z "${ACCOUNT_ID:-}" || -z "${CALLER_ARN:-}" ]]; then
    err "AWS identity returned but could not be parsed: ${id_json}"
    exit 1
  fi
  export ACCOUNT_ID CALLER_ARN
}

# resolve_region
# Resolves the AWS region from (in order): AWS_REGION env, AWS_DEFAULT_REGION
# env, `aws configure get region`, fallback us-east-1. Exports AWS_REGION.
resolve_region() {
  if [[ -n "${AWS_REGION:-}" ]]; then
    :
  elif [[ -n "${AWS_DEFAULT_REGION:-}" ]]; then
    AWS_REGION="${AWS_DEFAULT_REGION}"
  else
    AWS_REGION="$(aws configure get region 2>/dev/null || true)"
    if [[ -z "${AWS_REGION}" ]]; then
      warn "no region resolved from AWS_REGION, AWS_DEFAULT_REGION, or aws config; defaulting to us-east-1"
      AWS_REGION="us-east-1"
    fi
  fi
  export AWS_REGION
}

# bucket_name
# Stable, account-and-region-scoped bucket name so re-runs against the same
# account never collide and so we never need a random-id file to remember
# between runs.
bucket_name() {
  printf '%s' "kubesplaining-holysplain-secrets-${ACCOUNT_ID}-${AWS_REGION}"
}

role_arn() {
  printf '%s' "arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}"
}

# confirm <prompt>
# Interactive y/N. Honors --yes flag and EKS_DEMO_ASSUME_YES env for non-interactive runs.
confirm() {
  local prompt="$1"
  if [[ "${EKS_DEMO_ASSUME_YES:-0}" == "1" ]] || [[ "${ASSUME_YES:-0}" == "1" ]]; then
    return 0
  fi
  local reply
  printf '\n%s%s%s [y/N]: ' "${C_BOLD}" "${prompt}" "${C_RESET}"
  read -r reply
  case "${reply}" in
    y|Y|yes|YES) return 0 ;;
    *)           return 1 ;;
  esac
}

# state_save
# Writes the current run's metadata to .tmp/eks-demo-state.json. Hand-rolled
# JSON (no jq dependency); fields are simple strings so escaping is trivial.
state_save() {
  local created_at
  created_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  cat > "${STATE_FILE}" <<EOF
{
  "cluster_name": "${CLUSTER_NAME}",
  "region": "${AWS_REGION}",
  "account_id": "${ACCOUNT_ID}",
  "role_name": "${ROLE_NAME}",
  "role_arn": "$(role_arn)",
  "bucket_name": "$(bucket_name)",
  "oidc_issuer": "${OIDC_ISSUER:-}",
  "created_at": "${created_at}"
}
EOF
}

# state_load
# Loads field values from .tmp/eks-demo-state.json into shell variables.
# Tolerant of missing file (teardown supports partial-state recovery via flags).
state_load() {
  if [[ ! -f "${STATE_FILE}" ]]; then
    warn "no state file at ${STATE_FILE}; falling back to defaults / flags"
    return 1
  fi
  CLUSTER_NAME="$(sed -nE 's/.*"cluster_name": *"([^"]+)".*/\1/p' "${STATE_FILE}")"
  AWS_REGION="$(sed -nE 's/.*"region": *"([^"]+)".*/\1/p' "${STATE_FILE}")"
  ACCOUNT_ID="$(sed -nE 's/.*"account_id": *"([0-9]+)".*/\1/p' "${STATE_FILE}")"
  ROLE_NAME="$(sed -nE 's/.*"role_name": *"([^"]+)".*/\1/p' "${STATE_FILE}")"
  STATE_BUCKET="$(sed -nE 's/.*"bucket_name": *"([^"]+)".*/\1/p' "${STATE_FILE}")"
  STATE_CREATED_AT="$(sed -nE 's/.*"created_at": *"([^"]+)".*/\1/p' "${STATE_FILE}")"
  export CLUSTER_NAME AWS_REGION ACCOUNT_ID ROLE_NAME STATE_BUCKET STATE_CREATED_AT
}
