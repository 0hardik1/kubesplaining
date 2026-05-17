#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-kubesplaining-e2e}"
KUBECONFIG_PATH="${KUBECONFIG:-${ROOT_DIR}/.tmp/kubeconfig}"
KEEP_CLUSTER="${KEEP_CLUSTER:-1}"
USER_KUBECONFIG="${USER_KUBECONFIG:-${HOME}/.kube/config}"

# ANSI colors when stdout is a terminal and NO_COLOR is not set; plain text under CI / pipes.
if [[ -t 1 ]] && [[ -z "${NO_COLOR:-}" ]]; then
  C_RESET=$'\e[0m'
  C_BOLD=$'\e[1m'
  C_DIM=$'\e[2m'
  C_GREEN=$'\e[32m'
  C_BLUE=$'\e[34m'
  C_CYAN=$'\e[36m'
else
  C_RESET=""; C_BOLD=""; C_DIM=""; C_GREEN=""; C_BLUE=""; C_CYAN=""
fi

step()      { printf "\n%s▶ %s%s\n" "${C_BOLD}${C_CYAN}" "$*" "${C_RESET}"; }
ok()        { printf "  %s✓%s %s\n" "${C_GREEN}" "${C_RESET}" "$*"; }
prefix_ok() { sed "s/^/  ${C_GREEN}✓${C_RESET} /"; }

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

require_cmd docker
require_cmd kind
require_cmd kubectl
require_cmd rg

if ! docker info >/dev/null 2>&1; then
  echo "docker daemon is not reachable; start Docker and rerun make e2e" >&2
  exit 1
fi

mkdir -p "${ROOT_DIR}/.tmp"

cleanup() {
  if [[ "${KEEP_CLUSTER}" != "1" ]]; then
    kind delete cluster --name "${KIND_CLUSTER_NAME}" >/dev/null 2>&1 || true
    if [[ -f "${USER_KUBECONFIG}" ]]; then
      KUBECONFIG="${USER_KUBECONFIG}" kind delete cluster --name "${KIND_CLUSTER_NAME}" >/dev/null 2>&1 || true
    fi
  fi
}

trap cleanup EXIT

step "Creating kind cluster: ${KIND_CLUSTER_NAME}"
# Always start fresh: tear down any prior cluster of the same name, including
# the stale entry in the user's default kubeconfig from a previous run.
kind delete cluster --name "${KIND_CLUSTER_NAME}" >/dev/null 2>&1 || true
if [[ -f "${USER_KUBECONFIG}" ]]; then
  KUBECONFIG="${USER_KUBECONFIG}" kind delete cluster --name "${KIND_CLUSTER_NAME}" >/dev/null 2>&1 || true
fi
# Stream kind's progress (it already prints `✓ Ensuring node image`, `✓ Preparing
# nodes`, etc.), indented under our section header. We strip kind's trailing
# marketing block — we set the kubectl context ourselves further down, and the
# "Have a question / Thanks" lines are noise in this script.
kind create cluster --name "${KIND_CLUSTER_NAME}" --kubeconfig "${KUBECONFIG_PATH}" --wait 90s 2>&1 \
  | sed -E -e '/^Set kubectl context/d' \
            -e '/^You can now use/d' \
            -e '/^kubectl cluster-info/d' \
            -e '/^Have a question/d' \
            -e '/^Thanks/d' \
            -e '/^[[:space:]]*$/d' \
            -e 's/^/    /'
ok "cluster ready"

step "Stamping EKS node labels so DetectCloudProvider classifies as eks"
# Slot #15 covers Cloud Provider Integration (EKS). The kind nodes do not
# carry the AWS-managed eks.amazonaws.com/nodegroup label on their own, so
# the collector would classify the cluster as "unknown" and skip every
# KUBE-CLOUD-* rule. Stamping the label here is the minimum touch needed
# to drive the cloud analyzers from the e2e fixtures; the labels are
# harmless for every other slot (no analyzer keys off them).
kubectl --kubeconfig "${KUBECONFIG_PATH}" label nodes --all \
  eks.amazonaws.com/nodegroup=kind-test --overwrite >/dev/null
ok "kind nodes labeled eks.amazonaws.com/nodegroup=kind-test"

step "Applying vulnerable manifests"
# `kubectl apply -f <dir>` recurses through the directory and applies every
# YAML/JSON file in lexical order. Each Wave 1 analyzer slot adds its own
# testdata/e2e/vulnerable/NN-<feature>.yaml shard without editing this script
# or 00-baseline.yaml — zero merge conflicts at the fixture layer.
kubectl --kubeconfig "${KUBECONFIG_PATH}" apply -f "${ROOT_DIR}/testdata/e2e/vulnerable/" | prefix_ok

step "Waiting for workloads to roll out"
# Each *.rollout file under testdata/e2e/expectations/ lists one
# "<kind>/<name>:<namespace>" entry per line. The baseline file ships the set
# of workloads applied by 00-baseline.yaml; Wave 1 slots that introduce new
# workloads drop their own <feature>.rollout alongside the matching
# <feature>.yaml. Lines starting with '#' and blank lines are skipped.
ROLLOUTS=()
shopt -s nullglob
for f in "${ROOT_DIR}/testdata/e2e/expectations/"*.rollout; do
  while IFS= read -r line; do
    line="${line%%#*}"            # strip trailing comments
    line="${line#"${line%%[![:space:]]*}"}"  # ltrim
    line="${line%"${line##*[![:space:]]}"}"  # rtrim
    [[ -z "${line}" ]] && continue
    ROLLOUTS+=("${line}")
  done < "${f}"
done
shopt -u nullglob
for entry in "${ROLLOUTS[@]}"; do
  obj="${entry%%:*}"
  ns="${entry##*:}"
  kubectl --kubeconfig "${KUBECONFIG_PATH}" rollout status "${obj}" -n "${ns}" --timeout=120s >/dev/null
  ok "${obj} (${ns})"
done

step "Tightening psa-suppressed namespace to PSA enforce=restricted"
# Apply the label after the deployment rolled out so the privileged pod is already
# running. PSA checks creates and updates only, so the existing pod stays — this
# mirrors the production case where a namespace was labeled retroactively.
kubectl --kubeconfig "${KUBECONFIG_PATH}" label namespace psa-suppressed \
  pod-security.kubernetes.io/enforce=restricted --overwrite | prefix_ok

step "Capturing snapshot"
"${ROOT_DIR}/bin/kubesplaining" download \
  --kubeconfig "${KUBECONFIG_PATH}" \
  --output-file "${ROOT_DIR}/.tmp/e2e-snapshot.json" | prefix_ok

step "Synthesizing audit log for least-privilege fixtures"
# kind does not surface kube-apiserver audit logs by default, so we synthesize a
# small one with timestamps anchored to "now" - that keeps every event inside the
# scan's --audit-window-days window regardless of when the e2e is run. The events
# target three SAs the lp-fixtures namespace mounts:
#
#   sa-lp-narrow    - exercises get + list on configmaps (granted 7 verbs) -> UNUSED-VERB
#   sa-lp-wildcard  - exercises get on secrets (granted verbs:["*"])       -> WILDCARD-USED-PARTIAL
#   sa-lp-orphan    - no events at all                                     -> UNUSED-ROLE
AUDIT_LOG="${ROOT_DIR}/.tmp/e2e-audit.log"
TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
cat > "${AUDIT_LOG}" <<EOF
{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"Metadata","auditID":"lp-narrow-1","stage":"ResponseComplete","verb":"get","user":{"username":"system:serviceaccount:lp-fixtures:sa-lp-narrow"},"objectRef":{"apiVersion":"v1","resource":"configmaps","namespace":"lp-fixtures"},"responseStatus":{"code":200},"requestReceivedTimestamp":"${TS}","stageTimestamp":"${TS}"}
{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"Metadata","auditID":"lp-narrow-2","stage":"ResponseComplete","verb":"list","user":{"username":"system:serviceaccount:lp-fixtures:sa-lp-narrow"},"objectRef":{"apiVersion":"v1","resource":"configmaps","namespace":"lp-fixtures"},"responseStatus":{"code":200},"requestReceivedTimestamp":"${TS}","stageTimestamp":"${TS}"}
{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"Metadata","auditID":"lp-wildcard-1","stage":"ResponseComplete","verb":"get","user":{"username":"system:serviceaccount:lp-fixtures:sa-lp-wildcard"},"objectRef":{"apiVersion":"v1","resource":"secrets","namespace":"lp-fixtures"},"responseStatus":{"code":200},"requestReceivedTimestamp":"${TS}","stageTimestamp":"${TS}"}
EOF
ok "wrote ${AUDIT_LOG} (3 events)"

step "Running kubesplaining scan (default --max-findings=20)"
# Use the default "standard" exclusions preset so the e2e mirrors how users run
# the tool: built-in kube-system / system:* / kubeadm:* noise is suppressed.
# This invocation uses default flags so the e2e demonstrates the user-facing
# default truncation behavior. Rule-ID coverage assertions further down run
# against a separate --all-findings scan into .tmp/e2e-report-full.
SCAN_LOG="${ROOT_DIR}/.tmp/e2e-scan.log"
"${ROOT_DIR}/bin/kubesplaining" scan \
  --input-file "${ROOT_DIR}/.tmp/e2e-snapshot.json" \
  --audit-log "${AUDIT_LOG}" \
  --output-dir "${ROOT_DIR}/.tmp/e2e-report" \
  --output-format html,json,csv | tee "${SCAN_LOG}" | prefix_ok

step "Verifying default truncation behavior"
# The fixture deliberately produces > 20 findings, so the default cap must fire.
TRUNC_SIDECAR="${ROOT_DIR}/.tmp/e2e-report/truncation-info.json"
if [[ ! -f "${TRUNC_SIDECAR}" ]]; then
  echo "missing: truncation-info.json should exist when default --max-findings=20 cap fires" >&2
  exit 1
fi
if ! rg -q '"truncated":\s*true' "${TRUNC_SIDECAR}"; then
  echo "expected truncation-info.json to record truncated=true" >&2
  exit 1
fi
if ! rg -q '"shown":\s*20' "${TRUNC_SIDECAR}"; then
  echo "expected truncation-info.json to record shown=20" >&2
  exit 1
fi
DEFAULT_FINDING_COUNT=$(rg -c '"rule_id"' "${ROOT_DIR}/.tmp/e2e-report/findings.json" || echo 0)
if [[ "${DEFAULT_FINDING_COUNT}" != "20" ]]; then
  echo "expected exactly 20 findings under default cap, got ${DEFAULT_FINDING_COUNT}" >&2
  exit 1
fi
if ! rg -q 'class="truncation-banner"' "${ROOT_DIR}/.tmp/e2e-report/report.html"; then
  echo "expected HTML report to render the truncation-banner div" >&2
  exit 1
fi
ok "default cap produced 20 findings, sidecar + HTML banner present"

step "Running kubesplaining scan --all-findings (assertion coverage)"
# All rule-ID assertions and regression checks below run against the full,
# uncapped findings list so we can verify every expected rule fired. The
# default-cap scan above already covers the user-visible banner UX.
"${ROOT_DIR}/bin/kubesplaining" scan \
  --input-file "${ROOT_DIR}/.tmp/e2e-snapshot.json" \
  --audit-log "${AUDIT_LOG}" \
  --output-dir "${ROOT_DIR}/.tmp/e2e-report-full" \
  --all-findings \
  --output-format html,json,csv | prefix_ok
SUMMARY_LINE=$(grep -m1 "^findings:" "${SCAN_LOG}" 2>/dev/null || echo "")

step "Running kubesplaining scan --exclusions-preset=minimal (cloud-rule coverage)"
# Slot #15 (Cloud Provider Integration: EKS) lands rules whose canonical
# Resource lives in kube-system (the aws-auth ConfigMap). The default
# "standard" exclusions preset drops every kube-system-anchored finding, so
# we re-scan with the "minimal" preset for the cloud assertions only. The
# preset still excludes system:* / kubeadm:* subjects so the privesc-graph
# regression tests against the standard-preset scan above remain stable.
"${ROOT_DIR}/bin/kubesplaining" scan \
  --input-file "${ROOT_DIR}/.tmp/e2e-snapshot.json" \
  --output-dir "${ROOT_DIR}/.tmp/e2e-report-minimal" \
  --exclusions-preset minimal \
  --all-findings \
  --output-format json >/dev/null
ok "minimal-preset scan written for cloud-rule assertions"

step "Verifying expected rule IDs"
# Each *.expect file under testdata/e2e/expectations/ lists rule IDs one per
# line. The baseline file carries the set 00-baseline.yaml produces; Wave 1
# analyzer slots add their own <feature>.expect alongside the workload shard.
# Lines starting with '#' and blank lines are skipped.
#
# Cloud-eks assertions (slot #15) route against the minimal-preset scan so
# the aws-auth ConfigMap finding (anchored in kube-system) is not dropped.
# Every other expectation file routes against the standard-preset scan.
#
# Historically excluded by the baseline fixture (kept for reviewers landing
# new shards): KUBE-PODSEC-PROCMOUNT-001 — K8s 1.32+ requires hostUsers: false
# to apply procMount: Unmasked, and pods with hostUsers: false do not start
# on kind (mount-product-files.sh hits a permission-denied under the remapped
# UID). Detection is covered by analyzer unit tests in
# internal/analyzer/podsec/analyzer_test.go.
collect_rules() {
  # collect_rules <path-to-.expect-file> appends each non-blank, non-comment
  # rule-ID line to the provided array variable name.
  local file="$1" var="$2" line
  while IFS= read -r line; do
    line="${line%%#*}"
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -z "${line}" ]] && continue
    eval "${var}+=(\"\${line}\")"
  done < "${file}"
}

STD_RULES=()
CLOUD_RULES=()
shopt -s nullglob
for f in "${ROOT_DIR}/testdata/e2e/expectations/"*.expect; do
  base="$(basename "${f}" .expect)"
  if [[ "${base}" == "cloud-eks" ]]; then
    collect_rules "${f}" CLOUD_RULES
  else
    collect_rules "${f}" STD_RULES
  fi
done
shopt -u nullglob

missing=()
for rule in "${STD_RULES[@]}"; do
  if ! rg -q "\"rule_id\":\s*\"${rule}\"" "${ROOT_DIR}/.tmp/e2e-report-full/findings.json"; then
    missing+=("${rule}")
  fi
done
for rule in "${CLOUD_RULES[@]}"; do
  if ! rg -q "\"rule_id\":\s*\"${rule}\"" "${ROOT_DIR}/.tmp/e2e-report-minimal/findings.json"; then
    missing+=("${rule} (minimal-preset scan)")
  fi
done
if (( ${#missing[@]} > 0 )); then
  echo "missing expected rules in findings.json:" >&2
  printf '  - %s\n' "${missing[@]}" >&2
  exit 1
fi
ok "all $(( ${#STD_RULES[@]} + ${#CLOUD_RULES[@]} )) expected rule IDs present"

# Regression guard for issue #48: a namespace-scoped RoleBinding granting
# `create rolebindings` MUST NOT produce a cluster-admin path finding. The
# finding ID concatenates ruleID + subject Key + target, so a single grep
# pinpoints the exact false positive without needing jq.
NS_SUBJECT_KEY="ServiceAccount/rbac-ns-fixtures/sa-ns-rolebinding-mutate"
NS_FP_ID_PREFIX="KUBE-PRIVESC-PATH-CLUSTER-ADMIN:${NS_SUBJECT_KEY}:"
if rg -q "\"id\":\s*\"${NS_FP_ID_PREFIX}" "${ROOT_DIR}/.tmp/e2e-report-full/findings.json"; then
  echo "regression: namespace-scoped RoleBinding produced KUBE-PRIVESC-PATH-CLUSTER-ADMIN (issue #48)" >&2
  exit 1
fi
ok "no cluster-admin false positive for namespace-scoped RoleBinding"

# Phase 2 posture finding: KUBE-ADMISSION-NO-POLICY-ENGINE-001 must NOT fire in
# this fixture because the psa-suppressed namespace carries
# pod-security.kubernetes.io/enforce=restricted (set above), and PSAState.HasEnforce()
# returns true for any baseline-or-stricter level. Asserting the absence is more
# valuable than asserting presence: it locks in that the posture finding correctly
# suppresses itself when *any* admission control is in place.
if rg -q "\"rule_id\":\s*\"KUBE-ADMISSION-NO-POLICY-ENGINE-001\"" "${ROOT_DIR}/.tmp/e2e-report-full/findings.json"; then
  echo "regression: KUBE-ADMISSION-NO-POLICY-ENGINE-001 fired despite psa-suppressed namespace having enforce=restricted" >&2
  exit 1
fi
ok "no policy-engine posture finding (correctly suppressed by psa-suppressed enforce label)"

# The same fixture must instead produce KUBE-PRIVESC-PATH-NAMESPACE-ADMIN, naming
# the namespace it can take over. The finding ID encodes the target namespace as
# the last segment after a fourth `:`.
NS_OK_ID="KUBE-PRIVESC-PATH-NAMESPACE-ADMIN:${NS_SUBJECT_KEY}:namespace_admin:rbac-ns-fixtures"
if ! rg -q "\"id\":\s*\"${NS_OK_ID}\"" "${ROOT_DIR}/.tmp/e2e-report-full/findings.json"; then
  echo "missing: namespace-scoped RoleBinding did not produce expected KUBE-PRIVESC-PATH-NAMESPACE-ADMIN finding for ${NS_SUBJECT_KEY} → rbac-ns-fixtures" >&2
  exit 1
fi
ok "namespace-admin path emitted for namespace-scoped RoleBinding"

# Default --admission-mode=suppress must drop the privileged-pod finding for the
# psa-suppressed namespace because its enforce=restricted label would block the spec.
PSA_FINDING_ID="KUBE-ESCAPE-001:Deployment:psa-suppressed:psa-priv-app"
if rg -q "\"id\":\s*\"${PSA_FINDING_ID}" "${ROOT_DIR}/.tmp/e2e-report-full/findings.json"; then
  echo "regression: --admission-mode=suppress did not drop ${PSA_FINDING_ID}" >&2
  exit 1
fi
ok "default suppress mode dropped privileged finding in psa-suppressed namespace"

# admission-summary.json must record the suppression count and the per-namespace breakdown.
if ! rg -q "\"suppressed\":\s*[1-9]" "${ROOT_DIR}/.tmp/e2e-report-full/admission-summary.json"; then
  echo "missing: admission-summary.json should record suppressed >= 1" >&2
  exit 1
fi
if ! rg -q "psa-suppressed" "${ROOT_DIR}/.tmp/e2e-report-full/admission-summary.json"; then
  echo "missing: admission-summary.json should mention psa-suppressed namespace" >&2
  exit 1
fi
ok "admission-summary.json records the suppressed psa-suppressed finding"

step "Re-running scan with --admission-mode=attenuate"
"${ROOT_DIR}/bin/kubesplaining" scan \
  --input-file "${ROOT_DIR}/.tmp/e2e-snapshot.json" \
  --output-dir "${ROOT_DIR}/.tmp/e2e-report-attenuate" \
  --admission-mode attenuate \
  --all-findings \
  --output-format json >/dev/null

# Attenuate keeps the finding visible but with the admission tag applied.
if ! rg -q "\"id\":\s*\"${PSA_FINDING_ID}" "${ROOT_DIR}/.tmp/e2e-report-attenuate/findings.json"; then
  echo "missing: attenuate mode should keep ${PSA_FINDING_ID} visible" >&2
  exit 1
fi
if ! rg -q "admission:mitigated-psa-restricted" "${ROOT_DIR}/.tmp/e2e-report-attenuate/findings.json"; then
  echo "missing: attenuate mode should tag findings with admission:mitigated-psa-restricted" >&2
  exit 1
fi
ok "attenuate mode tagged the privileged finding with admission:mitigated-psa-restricted"

step "Re-running scan with --remediation-patches"
# Asserts the opt-in remediation-hint flag actually wires through the engine
# and at least one analyzer emits a hint into the JSON output. Without the
# flag, hint emission is stripped by the engine post-process pass; with the
# flag, every module's per-finding RemediationHint passes through.
"${ROOT_DIR}/bin/kubesplaining" scan \
  --input-file "${ROOT_DIR}/.tmp/e2e-snapshot.json" \
  --output-dir "${ROOT_DIR}/.tmp/e2e-report-remediation" \
  --remediation-patches \
  --all-findings \
  --output-format json >/dev/null
if ! rg -q '"remediation_hint"' "${ROOT_DIR}/.tmp/e2e-report-remediation/findings.json"; then
  echo "missing: --remediation-patches should produce at least one remediation_hint in findings.json" >&2
  exit 1
fi
ok "remediation hints present under --remediation-patches"

# Confirm the inverse: without the flag, no hints should leak through.
if rg -q '"remediation_hint"' "${ROOT_DIR}/.tmp/e2e-report-full/findings.json"; then
  echo "regression: default scan (no --remediation-patches) should not emit remediation_hint" >&2
  exit 1
fi
ok "default scan correctly omits remediation_hint"

if [[ "${KEEP_CLUSTER}" == "1" ]]; then
  step "Wiring kubectl context"
  mkdir -p "$(dirname "${USER_KUBECONFIG}")"
  touch "${USER_KUBECONFIG}"
  KUBECONFIG="${USER_KUBECONFIG}" kind export kubeconfig --name "${KIND_CLUSTER_NAME}" >/dev/null
  ok "kubectl context: kind-${KIND_CLUSTER_NAME}"
  ok "kubeconfig: ${USER_KUBECONFIG}"
fi

REPORT_HTML="${ROOT_DIR}/.tmp/e2e-report/report.html"
REPORT_REL="${REPORT_HTML#"${ROOT_DIR}/"}"
REPORT_URL="file://${REPORT_HTML}"
REPORT_FULL_HTML="${ROOT_DIR}/.tmp/e2e-report-full/report.html"
REPORT_FULL_REL="${REPORT_FULL_HTML#"${ROOT_DIR}/"}"
REPORT_FULL_URL="file://${REPORT_FULL_HTML}"
RULE="═══════════════════════════════════════════════════════════════════════"

printf "\n%s%s%s\n" "${C_BOLD}${C_GREEN}" "${RULE}" "${C_RESET}"
printf "  %s✓ kubesplaining e2e complete%s\n" "${C_BOLD}${C_GREEN}" "${C_RESET}"
if [[ -n "${SUMMARY_LINE}" ]]; then
  printf "  %s%s%s\n" "${C_DIM}" "${SUMMARY_LINE}" "${C_RESET}"
fi
printf "%s%s%s\n\n" "${C_BOLD}${C_GREEN}" "${RULE}" "${C_RESET}"

printf "  %sOpen the HTML report (default top-20 cap)%s\n" "${C_BOLD}" "${C_RESET}"
printf "    %s%s%s\n" "${C_BLUE}" "${REPORT_URL}" "${C_RESET}"
printf "    %sopen %s%s\n\n" "${C_DIM}" "${REPORT_REL}" "${C_RESET}"

printf "  %sOpen the full report (uncapped, includes Least Privilege tab)%s\n" "${C_BOLD}" "${C_RESET}"
printf "    %s%s%s\n" "${C_BLUE}" "${REPORT_FULL_URL}" "${C_RESET}"
printf "    %sopen %s%s\n\n" "${C_DIM}" "${REPORT_FULL_REL}" "${C_RESET}"

printf "  %sPoke at the cluster%s\n" "${C_BOLD}" "${C_RESET}"
printf "    %skubectl get pods -A%s\n" "${C_DIM}" "${C_RESET}"
printf "    %skubectl --context kind-%s get clusterrolebindings%s\n\n" "${C_DIM}" "${KIND_CLUSTER_NAME}" "${C_RESET}"

printf "  %sTear it down%s\n" "${C_BOLD}" "${C_RESET}"
printf "    %smake delete%s\n" "${C_DIM}" "${C_RESET}"
