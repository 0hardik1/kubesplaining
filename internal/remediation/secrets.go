// Per-rule remediation generators for the secrets + configmap analyzer module.
//
// Coverage:
//
//   - KUBE-CONFIGMAP-CREDS-001 (single high-confidence credential key in a
//     ConfigMap) emits a JSON-patch `remove` op against `/data/<key>`.
//   - KUBE-CONFIGMAP-001 (lower-severity heuristic, possibly multiple matched
//     keys) emits a JSON-patch `remove` op for each matched key.
//   - KUBE-SECRETS-001 (legacy service-account token Secret) emits a
//     command-only delete plus a Kyverno ClusterPolicy that blocks future
//     legacy SA-token secrets.
//   - KUBE-SECRETS-002 (Opaque secret in kube-system) emits a command-only
//     pipeline that moves the secret to a non-system namespace, plus a
//     Kyverno ClusterPolicy that blocks future Opaque secrets in kube-system.
//   - KUBE-SECRETS-STALE-001 (secret unreferenced) emits a command-only
//     `kubectl delete` with prose warning about out-of-snapshot consumers.
//   - KUBE-SECRETS-TLS-EXPIRY-001 (TLS secret expiring) emits a command-only
//     `cmctl renew` for cert-manager users, plus prose explaining manual
//     rotation for everyone else.
//   - KUBE-CONFIGMAP-002 (CoreDNS Corefile has risky rewrite / forward
//     directive) emits a Kyverno ClusterPolicy only — the safe fix requires
//     operator review and no automated patch is possible.
//   - KUBE-SECRETS-CROSSNS-001 (a workload SA can read secrets in another
//     namespace) is a pure RBAC fix. Rather than thread the snapshot through
//     to call ForRBACDangerous (which expects RBAC evidence keys this finding
//     does not carry), we emit a command-only hint pointing the operator at
//     the matching RoleBinding from the finding's evidence and an inline
//     TODO documenting the snapshot-aware variant that would synthesise a
//     proper RBAC diff.
//
// ForSecrets deliberately does not take a snapshot: the SECRETS-CROSSNS-001
// fallback above avoids the only case that would need one. Keeping the
// signature parameter-free matches ForPodsec / ForKyverno and keeps wiring
// at the appendUnique call site mechanical.
package remediation

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// ForSecrets returns the structured remediation hint for a secrets / configmap
// finding, or nil when no patch can be generated for the rule (unknown rule
// IDs, missing Resource pointer, malformed evidence).
func ForSecrets(ruleID string, finding models.Finding) *models.RemediationHint {
	target, ok := patchTargetFromFinding(finding)
	if !ok {
		return nil
	}

	switch ruleID {
	case "KUBE-CONFIGMAP-CREDS-001":
		return configMapRemoveSingleKey(target, finding)
	case "KUBE-CONFIGMAP-001":
		return configMapRemoveMatchedKeys(target, finding)
	case "KUBE-CONFIGMAP-002":
		return corednsKyvernoOnly(target)
	case "KUBE-SECRETS-001":
		return legacySATokenSecretDeletion(target)
	case "KUBE-SECRETS-002":
		return opaqueKubeSystemMove(target)
	case "KUBE-SECRETS-STALE-001":
		return staleSecretDeletion(target)
	case "KUBE-SECRETS-TLS-EXPIRY-001":
		return tlsExpiryRenewal(target, finding)
	case "KUBE-SECRETS-CROSSNS-001":
		return crossNSCommandOnly(target, finding)
	}
	return nil
}

// configMapRemoveSingleKey produces a JSON-patch `remove` op against
// `/data/<key>` for the KUBE-CONFIGMAP-CREDS-001 finding. The credential-key
// detector emits one finding per matched key, so a single-op patch is the
// right shape (multi-key removal lives on KUBE-CONFIGMAP-001 below).
func configMapRemoveSingleKey(target models.PatchTarget, finding models.Finding) *models.RemediationHint {
	key := singleMatchedKeyFromEvidence(finding.Evidence)
	if key == "" {
		return nil
	}
	ops := []map[string]any{
		{
			"op":   "remove",
			"path": "/data/" + jsonPointerEscape(key),
		},
	}
	return jsonPatchHint(target, ops)
}

// configMapRemoveMatchedKeys produces a JSON-patch with one `remove` op per
// matched key for the KUBE-CONFIGMAP-001 finding. The lower-severity heuristic
// emits a single finding per ConfigMap that aggregates every credential-shaped
// key into Evidence.matched_keys, so we expand that into one op apiece.
func configMapRemoveMatchedKeys(target models.PatchTarget, finding models.Finding) *models.RemediationHint {
	keys := matchedKeysFromEvidence(finding.Evidence)
	if len(keys) == 0 {
		return nil
	}
	ops := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		ops = append(ops, map[string]any{
			"op":   "remove",
			"path": "/data/" + jsonPointerEscape(k),
		})
	}
	return jsonPatchHint(target, ops)
}

// corednsKyvernoOnly returns a Kyverno-only hint for KUBE-CONFIGMAP-002. The
// CoreDNS Corefile's safe shape depends on the cluster's DNS policy (which
// upstreams are allowed, whether rewrites are intentional, etc.), so the only
// useful structured artefact is an admission policy that prevents future
// non-control-plane mutations to the ConfigMap.
func corednsKyvernoOnly(_ models.PatchTarget) *models.RemediationHint {
	return &models.RemediationHint{
		KyvernoPolicy: kyvernoCoreDNSCorefileGuard,
	}
}

// legacySATokenSecretDeletion returns a command-only delete plus a Kyverno
// policy blocking future legacy SA-token secrets. The right answer is
// projected token volumes (the BoundServiceAccountTokenVolume feature), but
// switching to those is a workload-level change the operator must perform.
func legacySATokenSecretDeletion(target models.PatchTarget) *models.RemediationHint {
	cmd := fmt.Sprintf(
		"# Switch the workload to a projected ServiceAccount token volume\n"+
			"# (BoundServiceAccountTokenVolume) and then remove the legacy secret:\n"+
			"kubectl delete secret %s -n %s",
		target.Name, target.Namespace,
	)
	hint := commandOnlyHint(target, cmd)
	hint.KyvernoPolicy = kyvernoBlockLegacySATokenSecret
	return hint
}

// opaqueKubeSystemMove returns a command-only shell pipeline that copies the
// Opaque secret into a non-system namespace and deletes the original from
// kube-system, plus a Kyverno policy blocking future Opaque secrets in
// kube-system. We do not emit a kubectl patch because Secret.type and
// Secret.namespace are both immutable: the only way to "move" a secret is to
// recreate it elsewhere.
func opaqueKubeSystemMove(target models.PatchTarget) *models.RemediationHint {
	cmd := fmt.Sprintf(
		"# Move the secret out of kube-system into an application namespace.\n"+
			"# Replace <new-ns> with the namespace that owns the workload using this secret.\n"+
			"kubectl get secret %s -n kube-system -o yaml | sed 's/namespace: kube-system/namespace: <new-ns>/' | kubectl apply -f -\n"+
			"kubectl delete secret %s -n kube-system",
		target.Name, target.Name,
	)
	hint := commandOnlyHint(target, cmd)
	hint.KyvernoPolicy = kyvernoBlockOpaqueSecretsInKubeSystem
	return hint
}

// staleSecretDeletion returns a command-only delete with prose warning about
// out-of-snapshot consumers (Jobs that have not run yet, GitOps controllers
// out of sync, external clients with cached credentials). We do not emit a
// Kyverno policy: a stale secret is a hygiene issue, not a misconfiguration
// admission can prevent.
func staleSecretDeletion(target models.PatchTarget) *models.RemediationHint {
	cmd := fmt.Sprintf(
		"# Confirm no out-of-snapshot consumer references this Secret before deleting:\n"+
			"# kubectl get pods,deployments,daemonsets,statefulsets,jobs,cronjobs --all-namespaces -o yaml | grep -i %s\n"+
			"# kubectl get serviceaccounts --all-namespaces -o yaml | grep -i %s\n"+
			"kubectl delete secret %s -n %s",
		target.Name, target.Name, target.Name, target.Namespace,
	)
	return commandOnlyHint(target, cmd)
}

// tlsExpiryRenewal returns a command-only hint that prefers cert-manager's
// cmctl renew (the canonical rotation for cert-manager-issued TLS certs).
// For TLS secrets the cluster manages outside cert-manager, the prose
// explains the manual rotation flow: re-issue from the upstream CA, then
// kubectl apply the updated tls.crt / tls.key.
func tlsExpiryRenewal(target models.PatchTarget, _ models.Finding) *models.RemediationHint {
	cmd := fmt.Sprintf(
		"# cert-manager users:\n"+
			"cmctl renew %s -n %s\n"+
			"\n"+
			"# Non-cert-manager users: reissue from your upstream CA, then:\n"+
			"# kubectl create secret tls %s --cert=path/to/new.crt --key=path/to/new.key -n %s --dry-run=client -o yaml | kubectl apply -f -",
		target.Name, target.Namespace, target.Name, target.Namespace,
	)
	return commandOnlyHint(target, cmd)
}

// crossNSCommandOnly returns a command-only hint pointing the operator at the
// RoleBinding (or ClusterRoleBinding) named in the finding's evidence so they
// can narrow it to only the namespace they need.
//
// TODO: the fully correct fix would consult the snapshot to synthesise the
// exact RBAC diff (drop the cross-namespace subject from the binding, or
// scope the binding to the workload's own namespace). Doing that here would
// require threading models.Snapshot through ForSecrets, which complicates the
// appendUnique wiring. The command-only hint is a deliberate pragmatic choice;
// the Subject + Resource on the finding already tell the operator which SA to
// look at.
func crossNSCommandOnly(target models.PatchTarget, finding models.Finding) *models.RemediationHint {
	roleKind, roleName, bindingKind, bindingName, bindingNs := crossNSRoleEvidence(finding.Evidence)
	subjectNs := target.Namespace
	subjectName := target.Name

	var cmd strings.Builder
	cmd.WriteString("# The cross-namespace secret read comes from this RBAC grant:\n")
	if roleKind != "" && roleName != "" {
		fmt.Fprintf(&cmd, "#   %s/%s\n", roleKind, roleName)
	}
	if bindingKind != "" && bindingName != "" {
		if bindingNs != "" {
			fmt.Fprintf(&cmd, "#   bound by %s/%s in namespace %s\n", bindingKind, bindingName, bindingNs)
		} else {
			fmt.Fprintf(&cmd, "#   bound by %s/%s (cluster-scoped)\n", bindingKind, bindingName)
		}
	}
	cmd.WriteString("#\n")
	cmd.WriteString("# Narrow the binding so the workload SA can no longer reach the foreign namespace.\n")
	cmd.WriteString("# Two common shapes:\n")
	cmd.WriteString("#  1. Drop the cross-namespace subject from the binding's subjects: list\n")
	cmd.WriteString("#     (preferred when other subjects still need the grant).\n")
	cmd.WriteString("#  2. Replace the ClusterRoleBinding with a namespaced RoleBinding in only\n")
	cmd.WriteString("#     the namespace the workload actually needs to read.\n")
	cmd.WriteString("#\n")

	if bindingKind != "" && bindingName != "" {
		cmd.WriteString("kubectl edit ")
		cmd.WriteString(strings.ToLower(bindingKind))
		cmd.WriteString(" ")
		cmd.WriteString(bindingName)
		if bindingNs != "" {
			cmd.WriteString(" -n ")
			cmd.WriteString(bindingNs)
		}
		cmd.WriteString("\n")
	} else {
		fmt.Fprintf(&cmd, "# Inspect the bindings that reach this ServiceAccount:\n")
		fmt.Fprintf(&cmd, "kubectl get rolebindings,clusterrolebindings --all-namespaces -o yaml | grep -B5 'name: %s'\n", subjectName)
	}
	_ = subjectNs
	return commandOnlyHint(target, cmd.String())
}

// singleMatchedKeyFromEvidence pulls the `key` or `matched_key` field off
// the finding's Evidence JSON. KUBE-CONFIGMAP-CREDS-001 emits `matched_key`
// (the heuristics analyzer's convention); we also accept the bare `key`
// alias in case a future analyzer change uses it.
func singleMatchedKeyFromEvidence(evidence json.RawMessage) string {
	if len(evidence) == 0 {
		return ""
	}
	var decoded map[string]any
	if err := json.Unmarshal(evidence, &decoded); err != nil {
		return ""
	}
	if v, ok := decoded["matched_key"].(string); ok && v != "" {
		return v
	}
	if v, ok := decoded["key"].(string); ok && v != "" {
		return v
	}
	return ""
}

// matchedKeysFromEvidence pulls the `matched_keys` array off the finding's
// Evidence JSON for the KUBE-CONFIGMAP-001 aggregated-finding shape. Falls
// back to the single-key accessor so callers using the singular shape still
// get a one-element slice.
func matchedKeysFromEvidence(evidence json.RawMessage) []string {
	if len(evidence) == 0 {
		return nil
	}
	var decoded map[string]any
	if err := json.Unmarshal(evidence, &decoded); err != nil {
		return nil
	}
	raw, ok := decoded["matched_keys"].([]any)
	if ok {
		out := make([]string, 0, len(raw))
		for _, v := range raw {
			if s, ok := v.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	if single := singleMatchedKeyFromEvidence(evidence); single != "" {
		return []string{single}
	}
	return nil
}

// crossNSRoleEvidence unpacks the RBAC-grant fields from a CROSSNS finding's
// Evidence. The crossns analyzer emits `source_role` and `source_binding` as
// strings (see crossNSFinding in internal/analyzer/secrets/crossns.go); we
// best-effort parse "Kind/name" tuples when present and fall back to bare
// names otherwise.
func crossNSRoleEvidence(evidence json.RawMessage) (roleKind, roleName, bindingKind, bindingName, bindingNs string) {
	if len(evidence) == 0 {
		return
	}
	var ev struct {
		SourceRole    string `json:"source_role"`
		SourceBinding string `json:"source_binding"`
		BindingNs     string `json:"binding_namespace"`
		TargetNs      string `json:"target_namespace"`
	}
	if err := json.Unmarshal(evidence, &ev); err != nil {
		return
	}
	roleKind, roleName = splitKindName(ev.SourceRole, "ClusterRole")
	bindingKind, bindingName = splitKindName(ev.SourceBinding, "ClusterRoleBinding")
	bindingNs = ev.BindingNs
	if bindingNs == "" && ev.TargetNs != "" {
		// Best-effort: a namespaced RoleBinding lives in the namespace the rule
		// resolves to; we use TargetNs when no explicit binding namespace was
		// surfaced. ClusterRoleBindings will simply not match this branch.
		if bindingKind == "RoleBinding" {
			bindingNs = ev.TargetNs
		}
	}
	return
}

// splitKindName parses an "Kind/name" string. Falls back to defaultKind for
// the kind and the whole input for the name when no slash is present, so
// callers always get usable strings even from older / partial evidence shapes.
func splitKindName(value, defaultKind string) (kind, name string) {
	if value == "" {
		return "", ""
	}
	if idx := strings.Index(value, "/"); idx > 0 {
		return value[:idx], value[idx+1:]
	}
	return defaultKind, value
}

// jsonPointerEscape rewrites a string into its RFC 6901 JSON-Pointer-safe
// form. `~` becomes `~0`, `/` becomes `~1`. ConfigMap keys can in principle
// contain `/` (e.g. `app.kubernetes.io/name` is allowed as a key in valid
// ConfigMap data), so we escape both characters per the JSON Pointer spec.
func jsonPointerEscape(key string) string {
	out := strings.ReplaceAll(key, "~", "~0")
	out = strings.ReplaceAll(out, "/", "~1")
	return out
}

// kyvernoBlockOpaqueSecretsInKubeSystem is the Kyverno ClusterPolicy paired
// with KUBE-SECRETS-002. It blocks `Opaque` Secret creates / updates in the
// kube-system namespace so future operators are pushed to put application
// secrets in their own namespaces (where namespace-scoped RBAC can guard them).
const kyvernoBlockOpaqueSecretsInKubeSystem = `apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-opaque-secrets-in-kube-system
  annotations:
    policies.kyverno.io/title: Disallow Opaque Secrets in kube-system
    policies.kyverno.io/category: Secrets Hygiene
    policies.kyverno.io/severity: medium
    policies.kyverno.io/description: >-
      Application Opaque secrets should live in application namespaces, not in
      kube-system. kube-system is a privileged namespace where many subjects
      (controllers, the kubelet's bootstrap path) have broad read access, so
      storing application credentials there expands their blast radius.
      Generated by kubesplaining for KUBE-SECRETS-002.
spec:
  validationFailureAction: enforce
  background: true
  failurePolicy: Fail
  rules:
  - name: no-opaque-secrets-in-kube-system
    match:
      any:
      - resources:
          kinds:
          - Secret
          namespaces:
          - kube-system
    validate:
      message: "Opaque secrets are not allowed in kube-system; place them in an application namespace."
      pattern:
        type: "!Opaque"
`

// kyvernoBlockLegacySATokenSecret is the Kyverno ClusterPolicy paired with
// KUBE-SECRETS-001. It blocks Secret creates whose `type` is the legacy
// `kubernetes.io/service-account-token`. Modern workloads should consume
// projected tokens (BoundServiceAccountTokenVolume) instead, which kubelet
// rotates automatically and which never sit in a long-lived secret.
const kyvernoBlockLegacySATokenSecret = `apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-legacy-sa-token-secrets
  annotations:
    policies.kyverno.io/title: Disallow legacy ServiceAccount token secrets
    policies.kyverno.io/category: Secrets Hygiene
    policies.kyverno.io/severity: high
    policies.kyverno.io/description: >-
      Long-lived ServiceAccount-token Secrets (type kubernetes.io/service-account-token)
      are the legacy token shape; modern workloads use projected token volumes
      (BoundServiceAccountTokenVolume) which kubelet rotates automatically.
      Generated by kubesplaining for KUBE-SECRETS-001.
spec:
  validationFailureAction: enforce
  background: true
  failurePolicy: Fail
  rules:
  - name: no-legacy-sa-token-secrets
    match:
      any:
      - resources:
          kinds:
          - Secret
    validate:
      message: "Legacy ServiceAccount token Secrets are not allowed; use projected token volumes instead."
      pattern:
        type: "!kubernetes.io/service-account-token"
`

// kyvernoCoreDNSCorefileGuard is the Kyverno ClusterPolicy paired with
// KUBE-CONFIGMAP-002. It blocks writes to the kube-system/coredns ConfigMap
// by subjects other than the cluster's recognised control-plane principals
// (the CoreDNS controller, the kubeadm bootstrap path). The right list of
// allowed subjects varies by distribution; the policy defaults to allowing
// system: subjects only and surfaces the others for an operator-tailored
// allowlist.
const kyvernoCoreDNSCorefileGuard = `apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: protect-coredns-corefile
  annotations:
    policies.kyverno.io/title: Restrict writes to the CoreDNS Corefile ConfigMap
    policies.kyverno.io/category: DNS Hygiene
    policies.kyverno.io/severity: high
    policies.kyverno.io/description: >-
      The kube-system/coredns ConfigMap's Corefile drives every in-cluster DNS
      resolution. A rewrite or external forward there can silently re-route
      traffic to an attacker-controlled endpoint. This policy restricts writes
      to recognised control-plane subjects; tailor the allowlist to your
      cluster's CoreDNS deployment owner. Generated by kubesplaining for
      KUBE-CONFIGMAP-002.
spec:
  validationFailureAction: enforce
  background: false
  failurePolicy: Fail
  rules:
  - name: protect-coredns-configmap
    match:
      any:
      - resources:
          kinds:
          - ConfigMap
          names:
          - coredns
          namespaces:
          - kube-system
    exclude:
      any:
      - subjects:
        - kind: User
          name: system:admin
      - subjects:
        - kind: Group
          name: system:masters
      - clusterRoles:
        - system:kube-controller-manager
    validate:
      message: "Writes to the kube-system/coredns ConfigMap are restricted to control-plane subjects; review the change manually."
      deny: {}
`
