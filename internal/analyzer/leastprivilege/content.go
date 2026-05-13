package leastprivilege

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/permissions"
	"github.com/0hardik1/kubesplaining/internal/usage"
)

// content is the same shape as rbac.ruleContent but private to this package. We don't
// reuse rbac's type because importing across analyzer modules would invert the dependency
// direction and the field set is small enough to duplicate.
// SuggestedRoleYAML, when non-empty, is rendered as a dedicated <pre><code> block by the
// Least Privilege tab and by the evidence renderer (for the regular Findings tab). It is
// kept off RemediationSteps because that renderer only handles inline backticks and would
// chew the fenced code block into a row of inline code spans.
type content struct {
	Title             string
	Scope             models.Scope
	Description       string
	Impact            string
	AttackScenario    []string
	Remediation       string
	RemediationSteps  []string
	SuggestedRoleYAML string
	LearnMore         []models.Reference
}

var refRBACGoodPractices = models.Reference{
	Title: "Kubernetes - RBAC Good Practices",
	URL:   "https://kubernetes.io/docs/concepts/security/rbac-good-practices/",
}

var refAccessAdvisor = models.Reference{
	Title: "AWS - IAM Access Advisor (analog of this analyzer)",
	URL:   "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_access-advisor.html",
}

var refAuditPolicy = models.Reference{
	Title: "Kubernetes - Auditing",
	URL:   "https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/",
}

// windowSummary turns the index's window into a single human-readable string like
// "30 days (2026-04-13 → 2026-05-13, 4,217 events)". Used in every rule's Description
// so the reader always knows what data backed the verdict.
func windowSummary(idx *usage.UsageIndex) string {
	if idx == nil {
		return "(no audit data)"
	}
	days := int(idx.WindowEnd.Sub(idx.WindowStart).Hours() / 24)
	return fmt.Sprintf("%d days (%s → %s, %d events)",
		days,
		idx.WindowStart.Format("2006-01-02"),
		idx.WindowEnd.Format("2006-01-02"),
		idx.EventsProcessed,
	)
}

// subjectPhrase formats a subject in the prose voice the rest of the report uses.
func subjectPhrase(subj models.SubjectRef) string {
	if subj.Namespace != "" {
		return fmt.Sprintf("ServiceAccount `%s/%s`", subj.Namespace, subj.Name)
	}
	return fmt.Sprintf("%s `%s`", subj.Kind, subj.Name)
}

// scopeForSubject derives a scope from the subject's namespace. Subjects bound only via
// RoleBindings are namespace-scoped; cluster-scoped subjects fall through to cluster.
func scopeForSubject(subj models.SubjectRef) models.Scope {
	if subj.Namespace != "" {
		return models.Scope{Level: models.ScopeNamespace, Detail: fmt.Sprintf("Namespace `%s`", subj.Namespace)}
	}
	return models.Scope{Level: models.ScopeCluster, Detail: "Cluster-wide"}
}

// contentUnusedRole is the KUBE-RBAC-UNUSED-ROLE-001 copy. The subject has zero
// observations across the entire audit window but a workload still references it -
// strongest signal that the whole binding is dead.
func contentUnusedRole(subj models.SubjectRef, roleName string, idx *usage.UsageIndex) content {
	subjStr := subjectPhrase(subj)
	return content{
		Title: fmt.Sprintf("Role `%s` granted to %s but never exercised", roleName, subjStr),
		Scope: scopeForSubject(subj),
		Description: fmt.Sprintf(
			"Audit logs covering %s show **zero** API calls from %s. The Role `%s` is bound to this subject "+
				"but every grant inside it is unused. A workload still mounts this ServiceAccount, so the grant "+
				"is latent privesc surface - an attacker who compromises the pod gets capabilities the workload "+
				"demonstrably does not need.",
			windowSummary(idx), subjStr, roleName,
		),
		Impact: fmt.Sprintf("If the pod is compromised, the attacker inherits every permission in `%s` even though the application has not used any of them.", roleName),
		AttackScenario: []string{
			fmt.Sprintf("Attacker compromises a pod running as %s (e.g. via an RCE in the application).", subjStr),
			fmt.Sprintf("Pod's projected token at /var/run/secrets/kubernetes.io/serviceaccount/token is the credential for %s.", subjStr),
			fmt.Sprintf("Attacker uses the token to invoke every API grant in `%s` - none of which the legitimate workload uses, so the activity is anomalous and detectable in audit logs.", roleName),
		},
		Remediation: fmt.Sprintf("Remove the binding that grants `%s` to %s, or replace the Role with a no-op placeholder until the workload is retired.", roleName, subjStr),
		RemediationSteps: []string{
			"Confirm the audit-log observation window is long enough to cover any periodic / on-demand uses of this Role (monthly jobs, disaster-recovery scripts).",
			fmt.Sprintf("Find the binding: `kubectl get rolebindings,clusterrolebindings -A -o json | jq '.items[] | select(.roleRef.name == \"%s\") | {kind, ns: .metadata.namespace, name: .metadata.name}'`", roleName),
			"Delete the binding (preferred) or scope it down by replacing it with a binding that grants no resources to verify nothing breaks before final removal.",
		},
		LearnMore: []models.Reference{refRBACGoodPractices, refAccessAdvisor, refAuditPolicy},
	}
}

// contentUnusedRule is the KUBE-RBAC-UNUSED-RULE-001 copy. Every triple in the Role is
// unused, but the subject is otherwise active - so the workload is alive but this
// particular Role contributes nothing.
func contentUnusedRule(subj models.SubjectRef, roleName string, unused []triple, idx *usage.UsageIndex) content {
	subjStr := subjectPhrase(subj)
	listing := formatTripleList(unused, 12)
	return content{
		Title: fmt.Sprintf("Role `%s` granted to %s - every rule unused", roleName, subjStr),
		Scope: scopeForSubject(subj),
		Description: fmt.Sprintf(
			"Over %s, %s actively called the Kubernetes API - but none of those calls match the grants in Role `%s`. "+
				"Every (verb, resource) triple this Role contributes is unused: %s.",
			windowSummary(idx), subjStr, roleName, listing,
		),
		Impact:      "The binding contributes latent capability without observed need. Removing it shrinks the workload's blast radius without affecting its known behavior.",
		Remediation: fmt.Sprintf("Drop the binding that links %s to `%s`.", subjStr, roleName),
		RemediationSteps: []string{
			"Re-confirm the audit window covers the workload's full usage cycle (a 30-day window can miss quarterly batch jobs).",
			fmt.Sprintf("Delete the binding: `kubectl delete rolebinding/clusterrolebinding <name>` after identifying it via `kubectl get rolebindings,clusterrolebindings -A | grep %s`.", roleName),
			"Re-scan with kubesplaining after the change to confirm the workload's other Roles still cover its real usage.",
		},
		LearnMore: []models.Reference{refRBACGoodPractices, refAuditPolicy},
	}
}

// contentUnusedVerbs is the KUBE-RBAC-UNUSED-VERB-001 copy. The Role is partially used:
// some verbs were exercised, others weren't. The suggested replacement YAML rides on
// SuggestedRoleYAML so the renderer can place it in a proper code block.
func contentUnusedVerbs(subj models.SubjectRef, roleName string, unused []triple, idx *usage.UsageIndex) content {
	subjStr := subjectPhrase(subj)
	listing := formatTripleList(unused, 12)
	return content{
		Title: fmt.Sprintf("Role `%s` has %d unused verb-grants for %s", roleName, len(unused), subjStr),
		Scope: scopeForSubject(subj),
		Description: fmt.Sprintf(
			"Over %s, %s exercised some of the verbs in `%s` but not others. Unused: %s. The Role can be safely "+
				"narrowed to drop the verbs the workload has never needed.",
			windowSummary(idx), subjStr, roleName, listing,
		),
		Impact:      "Each unused verb is an additional permission an attacker inherits if the workload is compromised, without the application needing it for normal operation.",
		Remediation: fmt.Sprintf("Replace `%s` with a narrower Role that lists only the verbs the workload actually exercises.", roleName),
		RemediationSteps: []string{
			"Confirm the audit window is long enough to capture rare-but-legitimate operations (monthly cron jobs, error-only code paths).",
			fmt.Sprintf("Edit `%s` to drop the unused verbs, or apply the suggested replacement below.", roleName),
		},
		SuggestedRoleYAML: suggestedNarrowYAML(roleName, unused),
		LearnMore:         []models.Reference{refRBACGoodPractices, refAccessAdvisor},
	}
}

// contentWildcardNarrowing is the KUBE-RBAC-WILDCARD-USED-PARTIAL-001 copy. The Role
// grants `verbs: ["*"]` on at least one (apiGroup, resource), but the subject has only
// exercised a strict subset of verbs there.
func contentWildcardNarrowing(subj models.SubjectRef, roleName string, wildcards []wildcardEntry, idx *usage.UsageIndex) content {
	subjStr := subjectPhrase(subj)
	lines := make([]string, 0, len(wildcards))
	for _, w := range wildcards {
		lines = append(lines, fmt.Sprintf("`%s` (apiGroup `%s`) observed: %s", w.Resource, displayGroup(w.APIGroup), strings.Join(w.ObservedVerbs, ", ")))
	}
	return content{
		Title: fmt.Sprintf("Role `%s` grants `verbs: [\"*\"]` to %s, only a subset is used", roleName, subjStr),
		Scope: scopeForSubject(subj),
		Description: fmt.Sprintf(
			"Over %s, %s exercised a narrow subset of the wildcard `verbs: [\"*\"]` grants in `%s`:\n\n- %s\n\n"+
				"The wildcard implicitly includes `create`, `update`, `patch`, `delete`, `deletecollection`, "+
				"`bind`, `escalate`, `impersonate`, and any future verb Kubernetes introduces. Replacing the "+
				"wildcard with the observed verb set shrinks blast radius without affecting known behavior.",
			windowSummary(idx), subjStr, roleName, strings.Join(lines, "\n- "),
		),
		Impact:      "Wildcard verbs grant whatever Kubernetes invents next, including verbs designed for cluster-admin operations the workload should never perform.",
		Remediation: fmt.Sprintf("Replace `verbs: [\"*\"]` in `%s` with the observed verb set.", roleName),
		RemediationSteps: []string{
			"Verify the observation window covers rare administrative actions (monthly cleanup, post-incident recovery).",
			"Apply the narrower Role shown in the snippet below.",
			"Re-scan after the change to confirm no UNUSED-VERB findings emerge: those would indicate the new verb list is itself broader than the workload needs.",
		},
		SuggestedRoleYAML: suggestedNarrowYAMLFromWildcards(roleName, wildcards),
		LearnMore:         []models.Reference{refRBACGoodPractices, refAccessAdvisor, refAuditPolicy},
	}
}

// formatTripleList renders a triple slice into a short prose listing. Caps the visible
// entries at `max` and appends "(+N more)" when truncated.
func formatTripleList(ts []triple, maxItems int) string {
	if len(ts) == 0 {
		return "(none)"
	}
	parts := make([]string, 0, len(ts))
	limit := len(ts)
	if limit > maxItems {
		limit = maxItems
	}
	for i := 0; i < limit; i++ {
		t := ts[i]
		parts = append(parts, fmt.Sprintf("`%s %s` (apiGroup `%s`)", t.Verb, t.Resource, displayGroup(t.APIGroup)))
	}
	out := strings.Join(parts, ", ")
	if len(ts) > maxItems {
		out += fmt.Sprintf(" (+%d more)", len(ts)-maxItems)
	}
	return out
}

func displayGroup(g string) string {
	if g == "" {
		return "core"
	}
	return g
}

// suggestedNarrowYAML emits a Role/ClusterRole skeleton that drops the unused verbs,
// grouped by (apiGroup, resource). The output is illustrative - operators are expected to
// merge it with the existing Role's other rules, not blindly apply it.
func suggestedNarrowYAML(roleName string, unused []triple) string {
	// Build the "still needed" view by inverting unused: we know what was unused but we
	// don't know the full granted set inside this helper, so the YAML uses a comment
	// pointing the operator at the missing piece. This is more honest than fabricating.
	verbsByGRP := map[string]map[string]struct{}{}
	for _, t := range unused {
		key := fmt.Sprintf("%s|%s", t.APIGroup, t.Resource)
		if verbsByGRP[key] == nil {
			verbsByGRP[key] = map[string]struct{}{}
		}
		verbsByGRP[key][t.Verb] = struct{}{}
	}
	keys := make([]string, 0, len(verbsByGRP))
	for k := range verbsByGRP {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	fmt.Fprintf(&b, "# Drop the following from Role/ClusterRole `%s`:\n", roleName)
	for _, k := range keys {
		parts := strings.SplitN(k, "|", 2)
		group, resource := parts[0], parts[1]
		verbs := make([]string, 0, len(verbsByGRP[k]))
		for v := range verbsByGRP[k] {
			verbs = append(verbs, v)
		}
		sort.Strings(verbs)
		fmt.Fprintf(&b, "#   apiGroup `%s`, resource `%s`: %s\n", displayGroup(group), resource, strings.Join(verbs, ", "))
	}
	fmt.Fprintf(&b, "# Replacement Role: keep only the verbs the workload actually uses (visible in your audit log).\n")
	return b.String()
}

// suggestedNarrowYAMLFromWildcards emits a concrete narrowed-Role snippet using the
// observed verb sets - for wildcard narrowing we DO have the full replacement.
func suggestedNarrowYAMLFromWildcards(roleName string, wildcards []wildcardEntry) string {
	var b strings.Builder
	fmt.Fprintf(&b, "apiVersion: rbac.authorization.k8s.io/v1\n")
	fmt.Fprintf(&b, "kind: ClusterRole  # or Role, matching the existing definition\n")
	fmt.Fprintf(&b, "metadata:\n  name: %s-narrowed\n", roleName)
	fmt.Fprintf(&b, "rules:\n")
	for _, w := range wildcards {
		fmt.Fprintf(&b, "  - apiGroups: [%q]\n", w.APIGroup)
		fmt.Fprintf(&b, "    resources: [%q]\n", w.Resource)
		quoted := make([]string, 0, len(w.ObservedVerbs))
		for _, v := range w.ObservedVerbs {
			quoted = append(quoted, fmt.Sprintf("%q", v))
		}
		fmt.Fprintf(&b, "    verbs: [%s]\n", strings.Join(quoted, ", "))
	}
	return b.String()
}

// (Imports referenced by signatures but not used elsewhere.) Linker silencing pattern -
// keep imports we *use* in this file (time / permissions) when they aren't visible after
// the function bodies above shift around in future edits. This block is currently a no-op
// but documents the intentional dependency on these packages.
var _ = time.Time{}
var _ permissions.EffectiveRule
