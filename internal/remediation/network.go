package remediation

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// ForNetwork returns the structured remediation hint for a network-policy
// finding, or nil when the rule has no automated patch (e.g. an evidence shape
// we don't recognise). The seven rules below cover every NetworkPolicy
// finding the network analyzer emits today:
//
//   - KUBE-NETPOL-COVERAGE-001: namespace has no NetworkPolicies at all.
//   - KUBE-NETPOL-COVERAGE-002: workload is not selected by any policy.
//   - KUBE-NETPOL-COVERAGE-003: namespace ingress is policy-controlled but egress is not.
//   - KUBE-NETPOL-WEAKNESS-001: a policy allows ingress from an empty namespace selector.
//   - KUBE-NETPOL-WEAKNESS-002: a policy allows egress to 0.0.0.0/0 (or ::/0).
//   - KUBE-NETPOL-IMDS-001: a workload's egress can reach the cloud IMDS endpoint.
//   - KUBE-NETPOL-CROSSNS-001: a policy bridges a sensitive namespace.
//
// The returned hint always carries a *KubectlPatch (either a structured body
// or a command-only fallback). The COVERAGE-001 and WEAKNESS-002 rules also
// carry a KyvernoPolicy that prevents the same shape at admission time, so
// operators can both fix the live cluster and lock down future drift.
func ForNetwork(ruleID string, finding models.Finding) *models.RemediationHint {
	switch ruleID {
	case "KUBE-NETPOL-COVERAGE-001":
		return netpolCoverageNoPolicies(finding)
	case "KUBE-NETPOL-COVERAGE-002":
		return netpolCoverageUncoveredWorkload(finding)
	case "KUBE-NETPOL-COVERAGE-003":
		return netpolCoverageNoEgress(finding)
	case "KUBE-NETPOL-WEAKNESS-001":
		return netpolWeaknessAllNamespacesIngress(finding)
	case "KUBE-NETPOL-WEAKNESS-002":
		return netpolWeaknessInternetEgress(finding)
	case "KUBE-NETPOL-IMDS-001":
		return netpolIMDSReachable(finding)
	case "KUBE-NETPOL-CROSSNS-001":
		return netpolCrossNamespace(finding)
	}
	return nil
}

// netpolCoverageNoPolicies emits a command-only hint that drops a
// "default-deny" NetworkPolicy into the namespace via a `kubectl apply -f -`
// heredoc. We pair it with a Kyverno ClusterPolicy that audits any namespace
// that lacks at least one NetworkPolicy so future drift is caught at the
// cluster level. The Patch.Target points at the offending Namespace; the
// apply heredoc creates a NetworkPolicy inside it, so the target Kind stays
// Namespace (the operator's mental model is "the namespace needs fixing")
// even though the body acts on a NetworkPolicy.
func netpolCoverageNoPolicies(finding models.Finding) *models.RemediationHint {
	target, ok := patchTargetFromFinding(finding)
	if !ok {
		return nil
	}
	namespace := target.Name
	if namespace == "" {
		namespace = target.Namespace
	}
	if namespace == "" {
		return nil
	}
	command := fmt.Sprintf(`# Apply a default-deny NetworkPolicy to %s so unselected pods are blocked by default.
# Operators must layer follow-up policies that explicitly allow the traffic each workload needs.
cat <<'EOF' | kubectl apply -n %s -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: %s
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
EOF`, namespace, namespace, namespace)
	hint := commandOnlyHint(target, command)
	hint.KyvernoPolicy = kyvernoRequireNetworkPolicy
	return hint
}

// netpolCoverageUncoveredWorkload emits a strategic-merge body that creates a
// new NetworkPolicy whose podSelector picks the workload by its labels.
// When the analyzer's evidence does not carry pod labels (defensive branch:
// the analyzer always populates them today, but we accept any shape from
// upstream) we fall back to a command-only hint that walks the operator
// through reading the labels off the live workload with kubectl.
func netpolCoverageUncoveredWorkload(finding models.Finding) *models.RemediationHint {
	target, ok := patchTargetFromFinding(finding)
	if !ok {
		return nil
	}
	if target.Namespace == "" {
		return nil
	}
	workloadLabels := workloadLabelsFromEvidence(finding.Evidence)
	policyName := fmt.Sprintf("allow-%s", strings.ToLower(target.Name))
	if len(workloadLabels) == 0 {
		// No labels in evidence: walk the operator through reading them.
		command := fmt.Sprintf(`# Evidence did not include the workload's labels. Read them off the live object first,
# then craft a NetworkPolicy that selects the workload via spec.podSelector.matchLabels.
kubectl get %s %s -n %s -o jsonpath='{.spec.template.metadata.labels}'

# Then apply a policy with a matching podSelector:
cat <<'EOF' | kubectl apply -n %s -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: %s
  namespace: %s
spec:
  podSelector:
    matchLabels: {} # <- replace with the labels printed above
  policyTypes:
  - Ingress
  - Egress
EOF`, strings.ToLower(target.Kind), target.Name, target.Namespace, target.Namespace, policyName, target.Namespace)
		return commandOnlyHint(target, command)
	}
	// We have labels: emit a strategic-merge body for a new NetworkPolicy.
	// The patch target shifts to the NetworkPolicy that should exist; the
	// pre-rendered command stays a heredoc because `kubectl patch` cannot
	// create a resource, only modify one. Operators paste the heredoc to
	// create the policy, then rely on the structured Body field for
	// machine-readable consumers.
	policyTarget := models.PatchTarget{
		Kind:       "NetworkPolicy",
		APIVersion: apiVersionForKind("NetworkPolicy"),
		Namespace:  target.Namespace,
		Name:       policyName,
	}
	body := map[string]any{
		"apiVersion": "networking.k8s.io/v1",
		"kind":       "NetworkPolicy",
		"metadata": map[string]any{
			"name":      policyName,
			"namespace": target.Namespace,
		},
		"spec": map[string]any{
			"podSelector": map[string]any{
				"matchLabels": workloadLabels,
			},
			"policyTypes": []string{"Ingress", "Egress"},
		},
	}
	hint := strategicHintRaw(policyTarget, body)
	if hint != nil && hint.Patch != nil {
		// Override the auto-rendered patch command because the resource does not
		// exist yet: a heredoc that creates it is the actionable invocation.
		bodyBytes, _ := json.Marshal(body)
		hint.Patch.Command = fmt.Sprintf(`# Apply a NetworkPolicy that selects this workload via its labels.
cat <<'EOF' | kubectl apply -n %s -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: %s
  namespace: %s
spec:
  podSelector:
    matchLabels:
%s
  policyTypes:
  - Ingress
  - Egress
EOF
# Equivalent JSON body for machine consumers: %s`,
			target.Namespace, policyName, target.Namespace,
			indentLabels(workloadLabels, "      "),
			string(bodyBytes))
	}
	return hint
}

// netpolCoverageNoEgress emits a merge-patch that appends an empty egress
// rule (`egress: []`) plus the Egress policyType to the offending policy,
// flipping the namespace from "egress is unrestricted" to "egress is
// default-deny". When the Resource refers to a Namespace rather than a
// specific policy (the analyzer emits the finding at namespace scope today),
// we fall back to a command-only hint that creates a fresh default-deny
// egress policy.
func netpolCoverageNoEgress(finding models.Finding) *models.RemediationHint {
	target, ok := patchTargetFromFinding(finding)
	if !ok {
		return nil
	}
	if target.Kind == "NetworkPolicy" {
		body := map[string]any{
			"spec": map[string]any{
				"policyTypes": []string{"Ingress", "Egress"},
				"egress":      []any{},
			},
		}
		return mergeHint(target, body)
	}
	// Namespace-scoped finding (the current emit site). Operator action is
	// to apply a new default-deny-egress policy.
	namespace := target.Name
	if namespace == "" {
		namespace = target.Namespace
	}
	if namespace == "" {
		return nil
	}
	command := fmt.Sprintf(`# Add a default-deny egress policy to %s so no pod can exfiltrate without an explicit allow.
cat <<'EOF' | kubectl apply -n %s -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-egress
  namespace: %s
spec:
  podSelector: {}
  policyTypes:
  - Egress
EOF`, namespace, namespace, namespace)
	return commandOnlyHint(target, command)
}

// netpolWeaknessAllNamespacesIngress emits a command-only hint because no
// automatic fix is safe here: the rule fires when a policy admits ingress
// from every namespace, but the analyzer cannot guess which namespaces the
// operator actually intended to allow. The command points the operator at
// `kubectl edit` so they can replace the empty selector with explicit
// matchLabels covering only the trusted peers.
func netpolWeaknessAllNamespacesIngress(finding models.Finding) *models.RemediationHint {
	target, ok := patchTargetFromFinding(finding)
	if !ok {
		return nil
	}
	command := fmt.Sprintf(`# The policy admits ingress from every namespace because the namespaceSelector is empty ({}).
# kubectl-patch cannot rewrite this safely: only you know which peers should be allowed.
# Edit the policy and replace the empty selector with an explicit matchLabels block, e.g.:
#
#   ingress:
#   - from:
#     - namespaceSelector:
#         matchLabels:
#           kubernetes.io/metadata.name: trusted-tenant
#
kubectl edit networkpolicy %s -n %s`, target.Name, target.Namespace)
	return commandOnlyHint(target, command)
}

// netpolWeaknessInternetEgress emits a command-only hint that points the
// operator at `kubectl edit` (because the safe fix depends on knowing which
// external endpoints the workload legitimately needs) and pairs it with a
// Kyverno ClusterPolicy that requires every 0.0.0.0/0 egress entry to carry
// an `except:` carveout. The Kyverno comment surfaces the IMDS angle: the
// most common consequence of a wide-open egress is a pod stealing cloud-IAM
// credentials from the metadata service.
func netpolWeaknessInternetEgress(finding models.Finding) *models.RemediationHint {
	target, ok := patchTargetFromFinding(finding)
	if !ok {
		return nil
	}
	cidr := stringFieldFromEvidence(finding.Evidence, "cidr")
	if cidr == "" {
		cidr = "0.0.0.0/0"
	}
	command := fmt.Sprintf(`# The policy allows egress to %s, i.e. the entire IPv4 (or IPv6) internet.
# Edit the policy and replace the wide ipBlock with a narrow allowlist, or add an except:
# carveout for the cloud metadata service to break the credential-theft chain:
#
#   egress:
#   - to:
#     - ipBlock:
#         cidr: %s
#         except:
#         - 169.254.169.254/32
#         - 169.254.0.0/16
#
kubectl edit networkpolicy %s -n %s`, cidr, cidr, target.Name, target.Namespace)
	hint := commandOnlyHint(target, command)
	hint.KyvernoPolicy = kyvernoRequireEgressExcept
	return hint
}

// netpolIMDSReachable handles both shapes the analyzer emits:
//
//   - explicit-allow: a policy's ipBlock contains 169.254.169.254 without an
//     except. We emit a merge patch that overwrites the offending policy's
//     egress with the same shape plus an except: carveout. Target shifts to
//     the offending NetworkPolicy named in evidence (the finding's Resource
//     is the workload, not the policy).
//   - no-egress-policy: no policy selects the workload, so Kubernetes leaves
//     it allow-all. We emit a heredoc that creates a default-deny-egress
//     policy with a tiny IMDS-only exception, so the workload can reach the
//     services it needs after the operator layers on follow-up allows.
//
// Either way we attach a Kyverno ClusterPolicy that audits any ipBlock that
// includes 169.254.169.254 without an except. This is the
// highest-leverage rule we own and the one most worth a defence-in-depth
// admission control.
func netpolIMDSReachable(finding models.Finding) *models.RemediationHint {
	target, ok := patchTargetFromFinding(finding)
	if !ok {
		return nil
	}
	evidence := decodeEvidence(finding.Evidence)
	reason, _ := evidence["reason"].(string)

	switch reason {
	case "explicit-allow":
		policyName, policyNamespace := offenderPolicyFromEvidence(evidence)
		if policyName == "" || policyNamespace == "" {
			return nil
		}
		cidr, _ := evidence["offender_cidr"].(string)
		if cidr == "" {
			cidr = "0.0.0.0/0"
		}
		policyTarget := models.PatchTarget{
			Kind:       "NetworkPolicy",
			APIVersion: apiVersionForKind("NetworkPolicy"),
			Namespace:  policyNamespace,
			Name:       policyName,
		}
		body := map[string]any{
			"spec": map[string]any{
				"egress": []map[string]any{
					{
						"to": []map[string]any{
							{
								"ipBlock": map[string]any{
									"cidr":   cidr,
									"except": []string{"169.254.169.254/32"},
								},
							},
						},
					},
				},
			},
		}
		hint := mergeHint(policyTarget, body)
		if hint != nil {
			hint.KyvernoPolicy = kyvernoBlockIMDSEgress
		}
		return hint
	default:
		// no-egress-policy (or unknown reason): drop in a default-deny-egress
		// policy carved for the workload, leaving DNS reachable but blocking
		// the cloud IMDS endpoint explicitly so an operator can layer on
		// the actual allows their workload needs from there.
		if target.Namespace == "" {
			return nil
		}
		policyName := fmt.Sprintf("default-deny-egress-%s", strings.ToLower(target.Name))
		workloadLabels := workloadLabelsFromEvidence(finding.Evidence)
		labelsBlock := "    {} # <- narrow this to the offending workload's labels"
		if len(workloadLabels) > 0 {
			labelsBlock = "    matchLabels:\n" + indentLabels(workloadLabels, "      ")
		}
		command := fmt.Sprintf(`# %s/%s has no egress policy, so it can reach the cloud IMDS endpoint
# (169.254.169.254) and mint cloud-IAM credentials. Apply a default-deny-egress
# policy with an explicit DNS allow so the workload can still resolve names,
# then add narrow allows for each external endpoint it actually needs.
cat <<'EOF' | kubectl apply -n %s -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: %s
  namespace: %s
spec:
  podSelector:
%s
  policyTypes:
  - Egress
  egress:
  # Allow DNS so name resolution still works.
  - to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
      podSelector:
        matchLabels:
          k8s-app: kube-dns
    ports:
    - protocol: UDP
      port: 53
  # Allow everything except the cloud metadata service.
  - to:
    - ipBlock:
        cidr: 0.0.0.0/0
        except:
        - 169.254.169.254/32
        - 169.254.0.0/16
EOF`, target.Kind, target.Name, target.Namespace, policyName, target.Namespace, labelsBlock)
		hint := commandOnlyHint(target, command)
		hint.KyvernoPolicy = kyvernoBlockIMDSEgress
		return hint
	}
}

// netpolCrossNamespace emits a command-only hint that walks the operator
// through tightening the cross-namespace peer to a narrow
// matchLabels + podSelector pair. Like WEAKNESS-001, we cannot rewrite this
// automatically because the safe replacement depends on which exact peer
// the operator intended to allow.
func netpolCrossNamespace(finding models.Finding) *models.RemediationHint {
	target, ok := patchTargetFromFinding(finding)
	if !ok {
		return nil
	}
	evidence := decodeEvidence(finding.Evidence)
	sourceNS, _ := evidence["source_namespace"].(string)
	targetNS, _ := evidence["target_namespace"].(string)
	direction, _ := evidence["direction"].(string)
	if direction == "" {
		direction = "ingress"
	}
	source := sourceNS
	if source == "" {
		source = "<peer-namespace>"
	}
	dest := targetNS
	if dest == "" {
		dest = "<policy-namespace>"
	}
	command := fmt.Sprintf(`# The policy bridges a sensitive namespace boundary (%s -> %s) via the %s rule.
# Replace the empty / wide peer selector with an explicit matchLabels + podSelector pair
# that names exactly the namespace and pod set you trust. For example:
#
#   %s:
#   - from:                       # or "to:" for egress
#     - namespaceSelector:
#         matchLabels:
#           kubernetes.io/metadata.name: %s
#       podSelector:
#         matchLabels:
#           app: <expected-peer-app>
#
kubectl edit networkpolicy %s -n %s`,
		source, dest, direction, direction, source, target.Name, target.Namespace)
	return commandOnlyHint(target, command)
}

// workloadLabelsFromEvidence pulls the "labels" key out of the analyzer's
// JSON evidence blob. The COVERAGE-002 emission shape is
// `{"labels": {"app": "frontend"}}`. Returns an empty map (not nil) when the
// field is missing so callers can range over it safely; the surrounding
// generator branches on len(...) == 0 to decide whether to fall back to a
// command-only patch.
func workloadLabelsFromEvidence(evidence json.RawMessage) map[string]string {
	out := map[string]string{}
	decoded := decodeEvidence(evidence)
	raw, ok := decoded["labels"].(map[string]any)
	if !ok {
		return out
	}
	for k, v := range raw {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}

// offenderPolicyFromEvidence pulls the (namespace, name) of the offending
// NetworkPolicy out of an IMDS-001 explicit-allow finding's evidence. The
// analyzer emits this as a single "offender_policy" string in
// "namespace/name" form; we split it and return (name, namespace) so the
// caller can build a PatchTarget directly.
func offenderPolicyFromEvidence(evidence map[string]any) (string, string) {
	raw, _ := evidence["offender_policy"].(string)
	if raw == "" {
		return "", ""
	}
	parts := strings.SplitN(raw, "/", 2)
	if len(parts) != 2 {
		return "", ""
	}
	return parts[1], parts[0]
}

// stringFieldFromEvidence is a small helper that decodes evidence JSON and
// fetches a top-level string field, returning the empty string when missing
// or malformed. Used by the WEAKNESS-002 generator to pull the offending
// CIDR out of evidence without needing a typed accessor for each field.
func stringFieldFromEvidence(evidence json.RawMessage, key string) string {
	decoded := decodeEvidence(evidence)
	value, _ := decoded[key].(string)
	return value
}

// decodeEvidence is the shared accessor that turns a Finding.Evidence blob
// (which may be nil or invalid JSON for hand-fabricated test findings) into a
// map[string]any. Returns an empty map on any failure so callers can index it
// safely.
func decodeEvidence(evidence json.RawMessage) map[string]any {
	if len(evidence) == 0 {
		return map[string]any{}
	}
	var decoded map[string]any
	if err := json.Unmarshal(evidence, &decoded); err != nil {
		return map[string]any{}
	}
	return decoded
}

// indentLabels renders a label map as YAML key:value pairs indented by the
// given prefix. The keys are sorted to keep the rendered output deterministic
// across runs (Go's map iteration is randomized). Used to splice workload
// labels into the heredoc bodies emitted by COVERAGE-002 and IMDS-001.
func indentLabels(labels map[string]string, indent string) string {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	lines := make([]string, 0, len(keys))
	for _, k := range keys {
		lines = append(lines, fmt.Sprintf("%s%s: %s", indent, k, labels[k]))
	}
	return strings.Join(lines, "\n")
}

// --- Kyverno ClusterPolicy templates ---

// kyvernoRequireNetworkPolicy mandates that every non-system namespace carry
// at least one NetworkPolicy. Kyverno's `validate.foreach` over the
// namespace context lets us assert presence of a NetworkPolicy in the
// admitted namespace without writing a generate-on-create rule (which would
// silently create policies, masking the underlying drift).
const kyvernoRequireNetworkPolicy = `apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-networkpolicy-per-namespace
  annotations:
    policies.kyverno.io/title: Require at least one NetworkPolicy per namespace
    policies.kyverno.io/category: Network
    policies.kyverno.io/severity: high
    policies.kyverno.io/description: >-
      Without a default-deny NetworkPolicy, every pod in the namespace can
      reach every other pod and the wider internet. This policy blocks the
      creation of a namespace that does not already have a NetworkPolicy,
      and audits existing namespaces on policy install (background: true).
      Generated by kubesplaining for KUBE-NETPOL-COVERAGE-001.
spec:
  validationFailureAction: enforce
  background: true
  failurePolicy: Fail
  rules:
  - name: require-netpol
    match:
      any:
      - resources:
          kinds:
          - Namespace
    exclude:
      any:
      - resources:
          names:
          - kube-system
          - kube-public
          - kube-node-lease
          - kyverno
    context:
    - name: netpolCount
      apiCall:
        urlPath: "/apis/networking.k8s.io/v1/namespaces/{{request.object.metadata.name}}/networkpolicies"
        jmesPath: "items | length(@)"
    validate:
      message: "Namespace {{request.object.metadata.name}} must have at least one NetworkPolicy."
      deny:
        conditions:
          all:
          - key: "{{netpolCount}}"
            operator: Equals
            value: 0
`

// kyvernoRequireEgressExcept blocks any NetworkPolicy egress rule whose
// ipBlock includes 0.0.0.0/0 (or ::/0) without an `except:` list. The
// rationale is the same as the WEAKNESS-002 finding text: a wide-open egress
// is rarely intentional, and the most common consequence is a pod stealing
// cloud-IAM credentials by hitting the metadata service.
const kyvernoRequireEgressExcept = `apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-egress-except
  annotations:
    policies.kyverno.io/title: Require except list on wide egress ipBlocks
    policies.kyverno.io/category: Network
    policies.kyverno.io/severity: high
    policies.kyverno.io/description: >-
      NetworkPolicy egress rules with ipBlock 0.0.0.0/0 (or ::/0) must declare
      an except: list, at minimum covering the cloud Instance Metadata Service
      (169.254.169.254/32). Without the carveout, any pod selected by the
      policy can mint cloud IAM credentials and pivot to full account
      compromise. Generated by kubesplaining for KUBE-NETPOL-WEAKNESS-002.
spec:
  validationFailureAction: enforce
  background: true
  failurePolicy: Fail
  rules:
  - name: egress-except-required
    match:
      any:
      - resources:
          kinds:
          - NetworkPolicy
    validate:
      message: "NetworkPolicy egress with ipBlock 0.0.0.0/0 must declare an except: list."
      foreach:
      - list: "request.object.spec.egress[]"
        deny:
          conditions:
            all:
            - key: "{{element.to[?ipBlock.cidr == '0.0.0.0/0' && length(ipBlock.except || []) == ` + "`0`" + `] | length(@)}}"
              operator: GreaterThan
              value: 0
`

// kyvernoBlockIMDSEgress is the highest-leverage admission policy in this
// file: it rejects any NetworkPolicy whose egress permits 169.254.169.254
// without an except. Paired with the IMDS-001 patch above, it closes the
// loop on the SSRF -> cloud-IAM-credential-theft chain.
const kyvernoBlockIMDSEgress = `apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: block-imds-egress
  annotations:
    policies.kyverno.io/title: Block egress to the cloud Instance Metadata Service
    policies.kyverno.io/category: Network
    policies.kyverno.io/severity: critical
    policies.kyverno.io/description: >-
      The link-local 169.254.169.254 endpoint is the cloud Instance Metadata
      Service. A pod that can reach it can mint cloud IAM credentials via the
      node's instance role and pivot from container RCE to full
      cloud-account compromise (see blog.christophetd.fr's EKS walkthrough).
      This policy blocks any NetworkPolicy that admits 169.254.169.254 without
      an explicit except: carveout. Generated by kubesplaining for
      KUBE-NETPOL-IMDS-001.
spec:
  validationFailureAction: enforce
  background: true
  failurePolicy: Fail
  rules:
  - name: imds-must-be-blocked
    match:
      any:
      - resources:
          kinds:
          - NetworkPolicy
    validate:
      message: "NetworkPolicy egress may not include 169.254.169.254 without an except: carveout."
      foreach:
      - list: "request.object.spec.egress[].to[]"
        deny:
          conditions:
            all:
            - key: "{{element.ipBlock.cidr || ''}}"
              operator: AnyIn
              value:
              - "0.0.0.0/0"
              - "169.254.0.0/16"
              - "169.254.169.254/32"
            - key: "{{length(element.ipBlock.except || ` + "`[]`" + `)}}"
              operator: Equals
              value: 0
`
