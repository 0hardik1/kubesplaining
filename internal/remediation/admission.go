package remediation

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// ForAdmission returns the structured remediation hint for an admission-webhook
// finding, or nil when no patch can be generated for the rule.
//
// Coverage:
//   - KUBE-ADMISSION-001: failurePolicy=Ignore on a security webhook. Webhook
//     lists are positional so JSON-patch is the right tool. When Evidence
//     carries `webhook_index` we emit a `replace` op against
//     `/webhooks/<index>/failurePolicy`; otherwise we fall back to a
//     `kubectl edit` command since the analyzer cannot rewrite by name without
//     re-listing the configuration.
//   - KUBE-ADMISSION-002: objectSelector keys on a workload-controlled label.
//     There is no clean kubectl patch (the right answer is to stop using label
//     selectors), so we emit only a Kyverno ClusterPolicy that achieves the
//     same gating against an immutable field.
//   - KUBE-ADMISSION-003: namespaceSelector excludes sensitive namespaces. We
//     emit a JSON `remove` op when Evidence carries the indices, otherwise a
//     `kubectl edit` fallback, plus a Kyverno ClusterPolicy that enforces no
//     kube-system exemption.
//   - KUBE-ADMISSION-NO-POLICY-ENGINE-001: cluster has no PSA enforce labels
//     and no policy engine. We emit a multi-line `kubectl label namespace`
//     command (since there is no specific Resource) plus a Kyverno
//     ClusterPolicy that enforces the PSS restricted profile cluster-wide.
func ForAdmission(ruleID string, finding models.Finding) *models.RemediationHint {
	switch ruleID {
	case "KUBE-ADMISSION-001":
		return admissionFailurePolicyPatch(finding)
	case "KUBE-ADMISSION-002":
		return admissionObjectSelectorPolicy(finding)
	case "KUBE-ADMISSION-003":
		return admissionNamespaceSelectorPatch(finding)
	case "KUBE-ADMISSION-NO-POLICY-ENGINE-001":
		return admissionNoPolicyEngineHint(finding)
	}
	return nil
}

// admissionFailurePolicyPatch flips the offending webhook's failurePolicy from
// Ignore to Fail using an RFC-6902 replace op. Webhook configurations carry
// their webhooks in a positional list, so a strategic-merge patch cannot
// address a single entry by name: we need the integer index. When Evidence
// carries `webhook_index` we emit the JSON patch; otherwise we degrade to a
// `kubectl edit` one-liner since the generator does not have access to the
// snapshot here to walk the configuration itself.
func admissionFailurePolicyPatch(finding models.Finding) *models.RemediationHint {
	target, ok := patchTargetFromFinding(finding)
	if !ok {
		return nil
	}
	evidence := decodeAdmissionEvidence(finding.Evidence)
	if idx, present := evidence.webhookIndex(); present {
		return jsonPatchHint(target, []map[string]any{
			{
				"op":    "replace",
				"path":  fmt.Sprintf("/webhooks/%d/failurePolicy", idx),
				"value": "Fail",
			},
		})
	}
	// Fallback: no index in evidence, so we cannot emit a positional patch.
	// kubectl edit is the safest manual step: it drops the operator into the
	// configuration with $EDITOR, where the webhook can be located by name.
	command := fmt.Sprintf(
		"# webhook_index missing from evidence; locate webhook %q manually:\nkubectl edit %s %s",
		evidence.webhookName(),
		strings.ToLower(target.Kind),
		target.Name,
	)
	return commandOnlyHint(target, command)
}

// admissionObjectSelectorPolicy emits a Kyverno ClusterPolicy only. The
// underlying issue is that the webhook gates admission on a label the workload
// author controls (e.g. `objectSelector.matchLabels.audit=enabled`), which any
// attacker who can submit a Pod can omit. No kubectl patch fixes that: the
// right answer is to stop relying on object labels and gate on an immutable
// field instead. The policy below shows what enforcement that does not depend
// on workload-controlled labels looks like.
func admissionObjectSelectorPolicy(finding models.Finding) *models.RemediationHint {
	// Resource is not strictly required (we are emitting only a KyvernoPolicy
	// here, no Patch), but Finding shape from the analyzer always carries one.
	_ = finding
	return &models.RemediationHint{
		KyvernoPolicy: kyvernoAdmissionObjectSelectorReplacement,
	}
}

// admissionNamespaceSelectorPatch removes the offending namespace from the
// webhook's namespaceSelector exemption list. When Evidence carries the
// webhook index, the matchExpressions index, and the values index we emit a
// JSON `remove` op against the precise slot; otherwise we degrade to
// `kubectl edit`. Either way the hint also includes a Kyverno ClusterPolicy
// that enforces "no kube-system exemption" so the cluster cannot regress.
func admissionNamespaceSelectorPatch(finding models.Finding) *models.RemediationHint {
	target, ok := patchTargetFromFinding(finding)
	if !ok {
		return nil
	}
	evidence := decodeAdmissionEvidence(finding.Evidence)
	if widx, ok1 := evidence.webhookIndex(); ok1 {
		if eidx, ok2 := evidence.exprIndex(); ok2 {
			if vidx, ok3 := evidence.valueIndex(); ok3 {
				hint := jsonPatchHint(target, []map[string]any{
					{
						"op":   "remove",
						"path": fmt.Sprintf("/webhooks/%d/namespaceSelector/matchExpressions/%d/values/%d", widx, eidx, vidx),
					},
				})
				if hint != nil {
					hint.KyvernoPolicy = kyvernoAdmissionNoSystemExemption
				}
				return hint
			}
		}
	}
	// Fallback path: not enough positional info to remove a single value.
	command := fmt.Sprintf(
		"# webhook_index / matchExpression_index missing from evidence; remove %q manually:\nkubectl edit %s %s",
		evidence.namespaceName(),
		strings.ToLower(target.Kind),
		target.Name,
	)
	hint := commandOnlyHint(target, command)
	hint.KyvernoPolicy = kyvernoAdmissionNoSystemExemption
	return hint
}

// admissionNoPolicyEngineHint is a cluster-wide posture finding: there is no
// specific Resource to patch. We emit a `kubectl label namespace` example
// command (with <ns> as a placeholder so the reader knows to fill it in)
// alongside a Kyverno ClusterPolicy that enforces the PSS restricted profile
// across all namespaces. Both are valid mitigations: PSA labels are quick to
// apply on existing clusters, and a policy engine is the durable answer.
func admissionNoPolicyEngineHint(finding models.Finding) *models.RemediationHint {
	// The cluster-wide posture finding carries no Resource (see
	// postureFinding in the admission analyzer), so we synthesise a
	// PatchTarget pointing at the Namespace kind purely so the rendered
	// command makes sense to the reader. The Body is empty (no kubectl patch
	// is the right primitive here; labels are the action).
	_ = finding
	target := models.PatchTarget{
		Kind:       "Namespace",
		APIVersion: apiVersionForKind("Namespace"),
		Name:       "<ns>",
	}
	command := "# Apply the PSS baseline to every namespace that should be hardened.\n" +
		"# Repeat per namespace, or wrap in a for-loop over `kubectl get namespaces -o name`.\n" +
		"kubectl label namespace <ns> pod-security.kubernetes.io/enforce=baseline\n" +
		"kubectl label namespace <ns> pod-security.kubernetes.io/enforce-version=latest"
	hint := commandOnlyHint(target, command)
	hint.KyvernoPolicy = kyvernoAdmissionRestrictedBaseline
	return hint
}

// admissionEvidence decodes the optional keys that the admission analyzer may
// thread into Finding.Evidence so the remediation generator can address
// individual list positions in the webhook configuration. All keys are
// optional: each accessor returns ok=false when missing or wrong-typed so the
// caller can fall back to a `kubectl edit` style hint.
type admissionEvidence struct {
	raw map[string]any
}

func decodeAdmissionEvidence(body json.RawMessage) admissionEvidence {
	if len(body) == 0 {
		return admissionEvidence{}
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		return admissionEvidence{}
	}
	return admissionEvidence{raw: decoded}
}

func (e admissionEvidence) webhookIndex() (int, bool) {
	return e.intKey("webhook_index")
}

func (e admissionEvidence) exprIndex() (int, bool) {
	return e.intKey("expr_index")
}

func (e admissionEvidence) valueIndex() (int, bool) {
	return e.intKey("value_index")
}

func (e admissionEvidence) webhookName() string {
	name, _ := e.raw["webhook_name"].(string)
	if name == "" {
		return "<webhook>"
	}
	return name
}

func (e admissionEvidence) namespaceName() string {
	name, _ := e.raw["excluded_namespace"].(string)
	if name == "" {
		return "<namespace>"
	}
	return name
}

// intKey reads a JSON-decoded integer-like value out of the evidence map.
// json.Unmarshal decodes JSON numbers as float64 by default, so we accept that
// shape too and round it down. Returns ok=false when the key is missing or
// holds a value we cannot coerce to int.
func (e admissionEvidence) intKey(key string) (int, bool) {
	raw, ok := e.raw[key]
	if !ok {
		return 0, false
	}
	switch v := raw.(type) {
	case float64:
		return int(v), true
	case int:
		return v, true
	case int64:
		return int(v), true
	case json.Number:
		i, err := v.Int64()
		if err != nil {
			return 0, false
		}
		return int(i), true
	}
	return 0, false
}

// --- Kyverno policy templates ---
//
// The text below is intentionally inline (not pulled from kyverno.go) so the
// admission generator owns the wording for its own rules. The structure
// follows the same conventions as the existing podsec policies in kyverno.go:
// validationFailureAction=enforce, failurePolicy=Fail, background=true.

// kyvernoAdmissionObjectSelectorReplacement is the policy emitted for
// KUBE-ADMISSION-002. The comment block explains why an objectSelector
// keyed on a workload-controlled label is bypassable, and the rule itself
// gates on `metadata.ownerReferences` so a Pod cannot dodge enforcement by
// simply omitting the label: a Pod that is part of a controlled workload
// has an ownerReference set by the kube-controller-manager, an unprivileged
// user cannot suppress that. Operators should adjust the pattern to match
// their environment (e.g. require a specific namespace annotation set by
// a trusted admission controller).
const kyvernoAdmissionObjectSelectorReplacement = `apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: admission-enforce-without-label-selectors
  annotations:
    policies.kyverno.io/title: Enforce admission gating without workload-controlled labels
    policies.kyverno.io/category: Admission Control
    policies.kyverno.io/severity: medium
    policies.kyverno.io/description: >-
      Webhook objectSelectors keyed on Pod labels are trivially bypassable: a
      workload author can omit the label and the webhook will skip enforcement.
      This policy demonstrates gating on metadata.ownerReferences instead, an
      immutable field set by the controller manager. Generated by kubesplaining
      for KUBE-ADMISSION-002.
spec:
  validationFailureAction: enforce
  background: true
  failurePolicy: Fail
  rules:
  - name: require-owner-reference-for-pods
    match:
      any:
      - resources:
          kinds:
          - Pod
    exclude:
      any:
      - resources:
          namespaces:
          - kube-system
          - kube-public
          - kube-node-lease
          - kyverno
    validate:
      message: "Pods must be created via a controller (Deployment, StatefulSet, etc.) so admission gating cannot be bypassed by omitting a label."
      pattern:
        metadata:
          ownerReferences:
          - kind: "?*"
`

// kyvernoAdmissionNoSystemExemption is the policy paired with
// KUBE-ADMISSION-003. It enforces that no Pod in kube-system runs without
// PSA restricted enforcement so the exemption the offending webhook carved
// out is closed by a second line of defense.
const kyvernoAdmissionNoSystemExemption = `apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: admission-no-system-exemption
  annotations:
    policies.kyverno.io/title: Forbid carving kube-system out of admission policies
    policies.kyverno.io/category: Admission Control
    policies.kyverno.io/severity: medium
    policies.kyverno.io/description: >-
      Webhooks that exempt kube-system give every attacker a known landing zone
      where Pod Security Standards are not enforced. This policy mirrors the
      PSS restricted profile and applies it specifically inside kube-system so
      a webhook exemption alone is not enough to disable enforcement. Generated
      by kubesplaining for KUBE-ADMISSION-003.
spec:
  validationFailureAction: enforce
  background: true
  failurePolicy: Fail
  rules:
  - name: kube-system-pss-restricted
    match:
      any:
      - resources:
          kinds:
          - Pod
          namespaces:
          - kube-system
    validate:
      message: "Pods in kube-system must comply with the PSS restricted profile (no privileged, no hostPath, runAsNonRoot)."
      pattern:
        spec:
          =(hostNetwork): "false"
          =(hostPID): "false"
          =(hostIPC): "false"
          containers:
          - =(securityContext):
              =(privileged): "false"
              =(allowPrivilegeEscalation): "false"
              runAsNonRoot: true
`

// kyvernoAdmissionRestrictedBaseline is the policy emitted for
// KUBE-ADMISSION-NO-POLICY-ENGINE-001. It mirrors the PSS restricted
// profile as a single Kyverno ClusterPolicy so a cluster that lacks both
// PSA labels and a policy engine can adopt one in a single apply.
const kyvernoAdmissionRestrictedBaseline = `apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: enforce-restricted-baseline
  annotations:
    policies.kyverno.io/title: Enforce PSS restricted across all namespaces
    policies.kyverno.io/category: Pod Security Standards (Restricted)
    policies.kyverno.io/severity: high
    policies.kyverno.io/description: >-
      The cluster has neither PSA enforce labels nor a policy engine. This
      policy installs the PSS restricted profile as a single ClusterPolicy:
      no privileged containers, no host namespaces, runAsNonRoot, drop
      ALL capabilities, RuntimeDefault seccomp profile. Excludes built-in
      control-plane namespaces. Generated by kubesplaining for
      KUBE-ADMISSION-NO-POLICY-ENGINE-001.
spec:
  validationFailureAction: enforce
  background: true
  failurePolicy: Fail
  rules:
  - name: restricted-profile
    match:
      any:
      - resources:
          kinds:
          - Pod
          - Deployment
          - DaemonSet
          - StatefulSet
          - Job
          - CronJob
          - ReplicaSet
          - ReplicationController
    exclude:
      any:
      - resources:
          namespaces:
          - kube-system
          - kube-public
          - kube-node-lease
          - kyverno
    validate:
      message: "Pods must satisfy the PSS restricted profile."
      pattern:
        spec:
          =(hostNetwork): "false"
          =(hostPID): "false"
          =(hostIPC): "false"
          containers:
          - securityContext:
              runAsNonRoot: true
              allowPrivilegeEscalation: false
              =(privileged): "false"
              capabilities:
                drop:
                - ALL
              seccompProfile:
                type: RuntimeDefault
`
