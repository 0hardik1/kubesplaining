package remediation

// ServiceAccount remediation generators sit at the intersection of two distinct
// "fix" shapes:
//
//  1. The SA-PRIVILEGED-001 / SA-PRIVILEGED-002 / SA-DEFAULT-002 rules are
//     ultimately RBAC mis-configurations: a binding granted the wrong verbs to a
//     ServiceAccount. The right answer is to edit the (Cluster)Role whose rule
//     the binding pulls in. We do *not* delegate to ForRBACDangerous here because
//     the SA analyzer's evidence shape differs from the rbac analyzer's: the SA
//     finding's Resource is the ServiceAccount itself (not the RBACRule), and the
//     dangerous rule lives under a nested "rules" array inside evidence keyed by
//     (verbs, resources, source_role, source_binding, namespace). We pick the
//     first dangerous rule from that nested list, reconstruct the Role-shaped
//     target, and emit the same shape of unified-diff + kubectl-edit command the
//     rbac generator does for KUBE-PRIVESC-* rules. Falling back to a
//     command-only hint when the evidence is too thin to pin a role.
//
//  2. SA-DAEMONSET-001 has a workload-level fix (set
//     `automountServiceAccountToken: false` on the DaemonSet's pod template) so
//     the kubelet stops projecting the SA token onto every node. The SA finding's
//     Resource points at the ServiceAccount, not the DaemonSet, so we extract
//     the DaemonSet identity from evidence.workloads and build a strategic-merge
//     patch directly against it: we cannot use patchTargetFromFinding because
//     that would target the SA object, which is the wrong place to set
//     automount.
//
// Returns nil when the rule ID is outside the SA module's surface, or when
// evidence is too sparse for either path to produce a useful hint. Both
// degenerate paths keep the analyzer side a one-liner: the caller can
// unconditionally assign the return value to Finding.RemediationHint.

import (
	"encoding/json"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/permissions"
)

// ForServiceAccount returns the structured remediation for a ServiceAccount-
// analyzer finding, or nil when the rule ID is unsupported or evidence is
// insufficient. The snapshot parameter is currently unused but kept on the
// signature for symmetry with the RBAC / privesc generators and to leave room
// for future snapshot-aware lookups (e.g. cross-referencing the workload's
// existing automountServiceAccountToken value).
func ForServiceAccount(ruleID string, finding models.Finding, _ models.Snapshot) *models.RemediationHint {
	switch ruleID {
	case "KUBE-SA-PRIVILEGED-001":
		return serviceAccountWildcardHint(finding)
	case "KUBE-SA-PRIVILEGED-002":
		return serviceAccountDangerousHint(finding)
	case "KUBE-SA-DEFAULT-002":
		return serviceAccountDefaultHint(finding)
	case "KUBE-SA-DAEMONSET-001":
		return serviceAccountDaemonSetHint(finding)
	}
	return nil
}

// saEvidenceRule mirrors the inner shape of evidence.rules[] emitted by the SA
// analyzer's summarizeRules helper. JSON tags match analyzer.go's evidence
// builder exactly so the unmarshal is direct. APIGroups and ResourceNames are
// required for isDangerousSARule to stay in lockstep with the analyzer's
// apiGroup- and resourceNames-aware matching.
type saEvidenceRule struct {
	Namespace     string   `json:"namespace"`
	APIGroups     []string `json:"api_groups"`
	Resources     []string `json:"resources"`
	ResourceNames []string `json:"resource_names"`
	Verbs         []string `json:"verbs"`
	SourceRole    string   `json:"source_role"`
	SourceBinding string   `json:"source_binding"`
}

// saEvidenceWorkload mirrors the workloadRef shape (kind/name/namespace) used by
// the SA analyzer's collectUsage helper. We pull workloads off evidence to find
// the DaemonSet target for SA-DAEMONSET-001.
type saEvidenceWorkload struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// saEvidenceEnvelope decodes the top-level evidence object the SA analyzer
// emits. Each field is optional: SA-PRIVILEGED-002 has dangerous_permissions
// but no rules array; SA-DAEMONSET-001 has workloads and maybe rules.
type saEvidenceEnvelope struct {
	Rules                []saEvidenceRule     `json:"rules"`
	Workloads            []saEvidenceWorkload `json:"workloads"`
	DangerousPermissions []string             `json:"dangerous_permissions"`
}

// decodeSAEvidence unmarshals a SA finding's evidence into the envelope,
// returning a zero envelope on any error so callers can branch on empty fields
// rather than handle a nil pointer.
func decodeSAEvidence(evidence json.RawMessage) saEvidenceEnvelope {
	var env saEvidenceEnvelope
	if len(evidence) == 0 {
		return env
	}
	_ = json.Unmarshal(evidence, &env)
	return env
}

// pickWildcardRule finds the first rule inside the evidence whose verbs and
// resources both contain "*". The SA-PRIVILEGED-001 detector fires whenever any
// effective rule for the SA has that shape, so picking the first match is
// good enough: the user will need to inspect each wildcard rule on the role
// before the remediation lands, and the diff illustrates the fix.
func pickWildcardRule(rules []saEvidenceRule) (saEvidenceRule, bool) {
	for _, rule := range rules {
		if saContainsString(rule.Verbs, "*") && saContainsString(rule.Resources, "*") {
			return rule, true
		}
	}
	return saEvidenceRule{}, false
}

// pickDangerousRule walks the evidence rules and returns the first one that
// matches any of the dangerous patterns the SA analyzer's
// dangerousCapabilities helper checks: secret reads, pod create, workload
// mutation, binding/escalate, impersonate, nodes/proxy. We mirror the
// analyzer's logic here rather than threading the matched rule through
// evidence; the alternative (carrying the rule on every SA-PRIVILEGED-002
// finding) would inflate JSON output for every workload that mounts a flagged
// SA without buying additional clarity.
func pickDangerousRule(rules []saEvidenceRule) (saEvidenceRule, bool) {
	for _, rule := range rules {
		if isDangerousSARule(rule) {
			return rule, true
		}
	}
	return saEvidenceRule{}, false
}

// saDangerousTargets are the (apiGroup, resource) + verb checks the SA analyzer's
// dangerousCapabilities helper flags. Kept here as a table so isDangerousSARule
// runs through the exact same permissions.Grants matcher the analyzer uses -
// apiGroup-aware and resourceNames-aware - instead of a diverging bare-name copy.
var saDangerousTargets = []struct {
	targets []permissions.ResourceTarget
	verbs   []string
}{
	{[]permissions.ResourceTarget{permissions.Core("secrets")}, []string{"get", "list", "watch"}},
	{[]permissions.ResourceTarget{permissions.Core("pods")}, []string{"create"}},
	{[]permissions.ResourceTarget{permissions.InGroup("apps", "deployments"), permissions.InGroup("apps", "daemonsets"), permissions.InGroup("apps", "statefulsets"), permissions.InGroup("batch", "jobs"), permissions.InGroup("batch", "cronjobs")}, []string{"create", "update", "patch"}},
	{[]permissions.ResourceTarget{permissions.InGroup("rbac.authorization.k8s.io", "rolebindings"), permissions.InGroup("rbac.authorization.k8s.io", "clusterrolebindings")}, []string{"create", "update", "patch"}},
	{[]permissions.ResourceTarget{permissions.InGroup("rbac.authorization.k8s.io", "roles"), permissions.InGroup("rbac.authorization.k8s.io", "clusterroles")}, []string{"bind", "escalate"}},
	{[]permissions.ResourceTarget{permissions.Core("users"), permissions.Core("groups"), permissions.Core("serviceaccounts")}, []string{"impersonate"}},
	{[]permissions.ResourceTarget{permissions.Core("nodes/proxy")}, []string{"get"}},
}

// isDangerousSARule reports whether an evidence rule grants one of the high-risk
// capabilities the SA analyzer's dangerousCapabilities helper flags, using the
// same permissions.Grants matcher (apiGroup- and resourceNames-aware) so the
// remediation diff highlights exactly the rule the analyzer counted - never a
// name-scoped or wrong-apiGroup rule the analyzer discounted.
func isDangerousSARule(rule saEvidenceRule) bool {
	for _, check := range saDangerousTargets {
		if permissions.Grants(rule.APIGroups, rule.Resources, rule.Verbs, rule.ResourceNames, check.targets, check.verbs) {
			return true
		}
	}
	return false
}

// saContainsString is a small slices.Contains alias kept local so this file
// doesn't have to import "slices" (and to keep the surface of helpers obvious).
func saContainsString(values []string, needle string) bool {
	for _, v := range values {
		if v == needle {
			return true
		}
	}
	return false
}

// roleTargetFromSAEvidence reconstructs the (Cluster)Role kind/name/namespace
// the dangerous rule was inherited from. The SA analyzer carries the role
// name on each evidence rule entry but not the kind; we infer the kind from
// the rule's namespace (a namespace-scoped binding sources a Role; a cluster-
// scoped binding sources a ClusterRole, by RBAC invariant).
func roleTargetFromSAEvidence(rule saEvidenceRule) (kind, name, namespace string, ok bool) {
	if rule.SourceRole == "" {
		return "", "", "", false
	}
	if rule.Namespace != "" {
		return "Role", rule.SourceRole, rule.Namespace, true
	}
	return "ClusterRole", rule.SourceRole, "", true
}

// serviceAccountRoleEditHint is the shared tail end of the three SA-RBAC
// generators: build a PatchTarget for the source (Cluster)Role, build the
// before / after YAML pair, render the unified diff, and return a hint whose
// Patch carries a kubectl-edit command (no JSON body: editing the role by hand
// is the canonical fix because the live role likely has other rules the SA
// finding cannot enumerate from evidence alone).
func serviceAccountRoleEditHint(rule saEvidenceRule) *models.RemediationHint {
	kind, name, namespace, ok := roleTargetFromSAEvidence(rule)
	if !ok {
		return nil
	}
	target := models.PatchTarget{
		Kind:       kind,
		APIVersion: "rbac.authorization.k8s.io/v1",
		Name:       name,
		Namespace:  namespace,
	}
	if len(rule.Verbs) == 0 && len(rule.Resources) == 0 {
		// No verbs or resources to show in the diff means we cannot draw a
		// meaningful before/after. Fall back to a command-only hint so the
		// operator still sees the kubectl edit recipe.
		return commandOnlyHint(target, buildKubectlEditCommand(target))
	}
	diff := removeRuleDiff(kind, name, namespace, rule.APIGroups, rule.Resources, rule.Verbs)
	cmd := buildKubectlEditCommand(target)
	return &models.RemediationHint{
		Patch: &models.KubectlPatch{
			Type:    "merge",
			Target:  target,
			Command: cmd,
		},
		RBACDiff: diff,
	}
}

// serviceAccountWildcardHint handles SA-PRIVILEGED-001: the SA is bound to a
// role with a wildcard `*:*:*` rule. The fix is to replace the wildcard with a
// least-privilege allowlist. We pick the first wildcard rule from the SA's
// aggregated rules and emit a diff that shows it removed, plus a `kubectl edit
// (cluster)role` command so the operator can write the replacement rules
// against the live role.
func serviceAccountWildcardHint(finding models.Finding) *models.RemediationHint {
	env := decodeSAEvidence(finding.Evidence)
	rule, ok := pickWildcardRule(env.Rules)
	if !ok {
		return serviceAccountFallbackHint(finding)
	}
	return serviceAccountRoleEditHint(rule)
}

// serviceAccountDangerousHint handles SA-PRIVILEGED-002: the SA holds a
// dangerous capability and is actively mounted by workloads. The fix is the
// same shape as SA-PRIVILEGED-001 (edit the source role, remove the
// offending rule). We surface the first dangerous rule from the evidence.
func serviceAccountDangerousHint(finding models.Finding) *models.RemediationHint {
	env := decodeSAEvidence(finding.Evidence)
	rule, ok := pickDangerousRule(env.Rules)
	if !ok {
		return serviceAccountFallbackHint(finding)
	}
	return serviceAccountRoleEditHint(rule)
}

// serviceAccountDefaultHint handles SA-DEFAULT-002: the namespace's default SA
// has explicit RBAC. The fix is to identify the bindings that grant rights to
// `default` and remove them (then migrate consumers to dedicated SAs). We
// surface the first aggregated rule and emit the same edit-role shape; the
// operator should also delete the corresponding binding once consumers move.
func serviceAccountDefaultHint(finding models.Finding) *models.RemediationHint {
	env := decodeSAEvidence(finding.Evidence)
	if len(env.Rules) == 0 {
		return serviceAccountFallbackHint(finding)
	}
	return serviceAccountRoleEditHint(env.Rules[0])
}

// serviceAccountDaemonSetHint handles SA-DAEMONSET-001: the SA is mounted by a
// DaemonSet so its token lives on every node. The fix is to set
// `automountServiceAccountToken: false` on the DaemonSet's pod template (the
// SA-level setting is too broad because other workloads may legitimately need
// the token). We extract the first DaemonSet workload from evidence and
// build a strategic-merge patch against it; the Finding.Resource itself
// points at the SA, so patchTargetFromFinding would target the wrong object.
func serviceAccountDaemonSetHint(finding models.Finding) *models.RemediationHint {
	env := decodeSAEvidence(finding.Evidence)
	for _, workload := range env.Workloads {
		if workload.Kind != "DaemonSet" || workload.Name == "" {
			continue
		}
		target := models.PatchTarget{
			Kind:       "DaemonSet",
			APIVersion: apiVersionForKind("DaemonSet"),
			Name:       workload.Name,
			Namespace:  workload.Namespace,
		}
		body, err := wrapPodPatch(target.Kind, map[string]any{
			"automountServiceAccountToken": false,
		})
		if err != nil {
			return nil
		}
		return &models.RemediationHint{
			Patch: &models.KubectlPatch{
				Type:    "strategic",
				Target:  target,
				Body:    body,
				Command: renderKubectlPatchCommand(target, "strategic", body),
			},
		}
	}
	return nil
}

// serviceAccountFallbackHint returns a command-only hint pointing at the SA
// itself for the cases where we cannot pin a source role: the SA's Resource
// gives us name+namespace, so the operator at least gets an actionable
// `kubectl get rolebindings,clusterrolebindings -A` recipe to find the
// bindings that grant rights to this SA.
func serviceAccountFallbackHint(finding models.Finding) *models.RemediationHint {
	if finding.Resource == nil {
		return nil
	}
	target := models.PatchTarget{
		Kind:       "ServiceAccount",
		APIVersion: apiVersionForKind("ServiceAccount"),
		Name:       finding.Resource.Name,
		Namespace:  finding.Resource.Namespace,
	}
	cmd := strings.Builder{}
	cmd.WriteString("# Inspect the bindings that grant rights to this ServiceAccount,\n")
	cmd.WriteString("# then `kubectl edit (cluster)role <name>` to prune the offending rule.\n")
	cmd.WriteString("kubectl get rolebindings,clusterrolebindings -A -o json | jq '.items[] | select(.subjects[]? | .kind == \"ServiceAccount\" and .name == \"")
	cmd.WriteString(target.Name)
	cmd.WriteString("\"")
	if target.Namespace != "" {
		cmd.WriteString(" and .namespace == \"")
		cmd.WriteString(target.Namespace)
		cmd.WriteString("\"")
	}
	cmd.WriteString(")'")
	return commandOnlyHint(target, cmd.String())
}
