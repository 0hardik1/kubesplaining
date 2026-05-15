// Package leastprivilege flags RBAC grants that look broader than the subject's actual
// usage. It is the analyzer-side counterpart to internal/usage: granted permissions come
// from permissions.Aggregate(snapshot); observed permissions come from a UsageIndex built
// from audit logs; this module diffs them.
//
// The output is "least-privilege opportunities" - recommendations, not exploitable
// findings. Severity tops out at Medium so they don't compete with real privesc paths
// in the global sort order. Empty UsageIndex (no audit data) yields zero findings,
// keeping the module a no-op when the operator hasn't supplied audit data.
package leastprivilege

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/permissions"
	"github.com/0hardik1/kubesplaining/internal/usage"
)

// Analyzer is the least-privilege module. It is constructed via New with the UsageIndex
// produced from the audit-log loader.
type Analyzer struct {
	idx *usage.UsageIndex
}

// New returns a least-privilege analyzer that diffs grants against idx. A nil index is
// permitted - the module emits zero findings, which is the right behavior when no
// `--audit-log` was supplied (the CLI pre-flight check in scan.go handles the
// `--least-privilege-only` case where audit data is required).
func New(idx *usage.UsageIndex) *Analyzer {
	return &Analyzer{idx: idx}
}

// Name returns the module identifier used by --only-modules / --skip-modules.
func (a *Analyzer) Name() string {
	return "leastprivilege"
}

// Analyze walks every subject's effective permissions and emits one finding per
// (subject, SourceRole) for each least-privilege opportunity detected. Grouping per Role
// (not per (verb,resource) triple) keeps the report scannable - a Role with five unused
// verbs becomes one finding listing those verbs, not five separate findings.
//
// No-ops when no audit data was supplied. The CLI wires LoadAuditLog with an empty path
// list to a non-nil but zero-event index (it carries the window metadata for the report
// header even when empty), so we must check EventsProcessed - not just idx == nil - to
// avoid emitting "every mounted SA looks unused!" findings on a plain `scan` without
// `--audit-log`. The pre-flight in scan.go rejects `--least-privilege-only` without an
// audit log, so a zero-event index here means "user wanted other analyzers, not us".
func (a *Analyzer) Analyze(_ context.Context, snapshot models.Snapshot) ([]models.Finding, error) {
	if a.idx == nil || a.idx.EventsProcessed == 0 {
		return nil, nil
	}
	perms := permissions.Aggregate(snapshot)
	mounted := mountedServiceAccounts(snapshot)

	findings := make([]models.Finding, 0)
	for _, subjectPerms := range perms {
		// Skip built-in / control-plane subjects. The standard exclusions preset drops
		// these later too, but skipping here avoids producing the findings at all so
		// the leastprivilege tab's count badge stays accurate.
		if strings.HasPrefix(subjectPerms.Subject.Name, "system:") || subjectPerms.Subject.Kind != "ServiceAccount" {
			continue
		}

		// Only analyze SAs a workload actually mounts. Unmounted SAs are a separate
		// concern handled by KUBE-RBAC-STALE-* in the rbac module - firing here would
		// duplicate that signal without adding usage-aware data.
		if !mounted[subjectPerms.Subject.Key()] {
			continue
		}

		// Whole-role dead grant: mounted subject with zero observed events anywhere in
		// the window. Emit one finding per distinct SourceRole.
		if !a.idx.HasAnyEventsFor(subjectPerms.Subject) {
			roles := distinctSourceRoles(subjectPerms.Rules)
			for _, role := range roles {
				findings = append(findings, a.findingForRole(subjectPerms.Subject, role, subjectPerms.Rules))
			}
			continue
		}

		// Per-role narrowing: group rules by SourceRole, compute granted vs observed
		// triples per group, emit one finding when the diff is non-empty.
		byRole := groupRulesByRole(subjectPerms.Rules)
		roleNames := make([]string, 0, len(byRole))
		for name := range byRole {
			roleNames = append(roleNames, name)
		}
		sort.Strings(roleNames) // deterministic test/diff output

		for _, roleName := range roleNames {
			rules := byRole[roleName]
			unused, used, allUnused, wildcardObserved := a.analyzeRoleForSubject(subjectPerms.Subject, rules)
			if len(unused) == 0 && len(wildcardObserved) == 0 {
				continue
			}
			switch {
			case allUnused:
				// Every (verb, resource) triple in this Role is unused → suggest
				// removing the whole Rule block, not just trimming verbs.
				findings = append(findings, a.findingForUnusedRule(subjectPerms.Subject, roleName, rules, unused))
			case len(wildcardObserved) > 0:
				findings = append(findings, a.findingForWildcardNarrowing(subjectPerms.Subject, roleName, rules, wildcardObserved))
			default:
				findings = append(findings, a.findingForUnusedVerbs(subjectPerms.Subject, roleName, rules, unused, used))
			}
		}
	}
	return findings, nil
}

// triple is one (apiGroup, resource, verb) coordinate. We use it as a value key so two
// rules contributing the same triple dedupe naturally via a set.
type triple struct {
	APIGroup string
	Resource string
	Verb     string
}

// wildcardEntry pairs a granted Role coordinate with the verbs the subject was actually
// observed exercising on that coordinate - the data behind a "you have *, narrow to
// these N verbs" recommendation.
type wildcardEntry struct {
	APIGroup       string
	Resource       string
	ObservedVerbs  []string
	WildcardOnVerb bool // true when the rule used verbs: ["*"]
}

// analyzeRoleForSubject returns the unused/used triples and any wildcard-narrowing
// opportunities for a single (subject, role) pair.
//
// allUnused is true when every observed-comparable triple is unused - i.e. the rule
// contributes no useful capability to this subject. The wildcard list is returned
// separately because narrowing a `*` is a different recommendation than dropping a
// concrete verb. The used list lets the report's Role-to-verbs table show "used vs
// unused" side by side so an operator can sanity-check the narrowing recommendation
// against what the workload actually does.
func (a *Analyzer) analyzeRoleForSubject(subj models.SubjectRef, rules []permissions.EffectiveRule) (unused []triple, used []triple, allUnused bool, wildcards []wildcardEntry) {
	// Concrete granted triples: (apiGroup, resource, verb) sets with no wildcards. These
	// drive the UNUSED-VERB / UNUSED-RULE recommendations.
	granted := map[triple]struct{}{}
	hasWildcardVerb := false
	for _, r := range rules {
		// Expand the cartesian product of the rule's apiGroups × resources × verbs. RBAC
		// semantics: a rule "grants every verb in Verbs on every resource in Resources
		// in every apiGroup in APIGroups." Empty slices contribute nothing.
		for _, group := range r.APIGroups {
			for _, resource := range r.Resources {
				if resource == "*" {
					continue // can't enumerate against snapshot - handled by wildcard path below
				}
				for _, verb := range r.Verbs {
					if verb == "*" {
						hasWildcardVerb = true
						continue
					}
					granted[triple{APIGroup: normalizeGroup(group), Resource: resource, Verb: strings.ToLower(verb)}] = struct{}{}
				}
			}
		}
	}

	// Diff granted vs observed. Subject's observed verbs come from the index; we keep a
	// triple in the unused list when the subject did not exercise it, and the used list
	// when it did. Both lists are exposed to the report so the operator sees what the
	// workload actually does next to what we recommend dropping.
	keptUnused := make([]triple, 0)
	keptUsed := make([]triple, 0)
	for t := range granted {
		observed := a.idx.Observed(subj, t.APIGroup, t.Resource)
		if observed.Contains(t.Verb) {
			keptUsed = append(keptUsed, t)
		} else {
			keptUnused = append(keptUnused, t)
		}
	}
	sortTriples(keptUnused)
	sortTriples(keptUsed)

	allUnused = len(granted) > 0 && len(keptUnused) == len(granted)

	// Wildcard narrowing: when any rule used verbs: ["*"], compute the observed-verb set
	// per (apiGroup, resource) coordinate the rule actually grants on. We never propose
	// narrowing on a (group, resource) where the subject observed zero events - that's a
	// candidate for UNUSED-RULE, not WILDCARD-NARROW.
	if hasWildcardVerb {
		seen := map[triple]struct{}{}
		for _, r := range rules {
			if !containsWildcard(r.Verbs) {
				continue
			}
			for _, group := range r.APIGroups {
				ng := normalizeGroup(group)
				for _, resource := range r.Resources {
					if resource == "*" {
						continue
					}
					key := triple{APIGroup: ng, Resource: resource}
					if _, ok := seen[key]; ok {
						continue
					}
					seen[key] = struct{}{}
					observed := a.idx.Observed(subj, ng, resource).Sorted()
					if len(observed) == 0 {
						continue
					}
					wildcards = append(wildcards, wildcardEntry{
						APIGroup:       ng,
						Resource:       resource,
						ObservedVerbs:  observed,
						WildcardOnVerb: true,
					})
				}
			}
		}
		sort.Slice(wildcards, func(i, j int) bool {
			if wildcards[i].APIGroup != wildcards[j].APIGroup {
				return wildcards[i].APIGroup < wildcards[j].APIGroup
			}
			return wildcards[i].Resource < wildcards[j].Resource
		})
	}

	return keptUnused, keptUsed, allUnused, wildcards
}

// windowEvidence returns a base evidence map containing the four fields every
// least-privilege finding needs (source_role + the audit-window context), with any
// extras merged in. Callers append rule-specific fields like unused_triples or
// suggested_role_yaml via `extras`. encoding/json sorts map keys alphabetically, so
// the resulting JSON output is independent of insertion order.
func (a *Analyzer) windowEvidence(roleName string, extras map[string]any) json.RawMessage {
	out := map[string]any{
		"source_role":      roleName,
		"window_start":     a.idx.WindowStart,
		"window_end":       a.idx.WindowEnd,
		"events_processed": a.idx.EventsProcessed,
	}
	for k, v := range extras {
		out[k] = v
	}
	encoded, _ := json.Marshal(out)
	return encoded
}

// findingForRole emits KUBE-RBAC-UNUSED-ROLE-001 - the strongest signal, fired when the
// subject has zero observed events in the window and a workload still references it.
func (a *Analyzer) findingForRole(subj models.SubjectRef, roleName string, rules []permissions.EffectiveRule) models.Finding {
	c := contentUnusedRole(subj, roleName, a.idx)
	res := &models.ResourceRef{Kind: roleKindFor(rules, roleName), Name: roleName, APIGroup: "rbac.authorization.k8s.io"}
	evidence := a.windowEvidence(roleName, map[string]any{
		"signal": "no_observed_events_for_subject",
	})
	return buildFinding(
		"KUBE-RBAC-UNUSED-ROLE-001",
		models.SeverityMedium,
		5.0,
		subj,
		res,
		evidence,
		c,
	)
}

// findingForUnusedRule emits KUBE-RBAC-UNUSED-RULE-001 - every (verb, resource) triple in
// the Role is unused, but the subject is otherwise active (so the role is dead, not the
// workload).
func (a *Analyzer) findingForUnusedRule(subj models.SubjectRef, roleName string, rules []permissions.EffectiveRule, unused []triple) models.Finding {
	c := contentUnusedRule(subj, roleName, unused, a.idx)
	res := &models.ResourceRef{Kind: roleKindFor(rules, roleName), Name: roleName, APIGroup: "rbac.authorization.k8s.io"}
	evidence := a.windowEvidence(roleName, map[string]any{
		"unused_triples": tripleListJSON(unused),
	})
	return buildFinding(
		"KUBE-RBAC-UNUSED-RULE-001",
		models.SeverityLow,
		3.5,
		subj,
		res,
		evidence,
		c,
	)
}

// findingForUnusedVerbs emits KUBE-RBAC-UNUSED-VERB-001: some verbs in the Role were
// exercised, but others were not. The suggested-replacement YAML rides on the content
// struct so the LP tab and the evidence renderer can both pull it out and render it as
// a proper <pre><code> block. used_triples is the complement of unused_triples for the
// same granted set - the report's verb table renders both side by side so the operator
// can sanity-check "drop these" against "keep these".
func (a *Analyzer) findingForUnusedVerbs(subj models.SubjectRef, roleName string, rules []permissions.EffectiveRule, unused, used []triple) models.Finding {
	c := contentUnusedVerbs(subj, roleName, unused, a.idx)
	res := &models.ResourceRef{Kind: roleKindFor(rules, roleName), Name: roleName, APIGroup: "rbac.authorization.k8s.io"}
	evidence := a.windowEvidence(roleName, map[string]any{
		"unused_triples":      tripleListJSON(unused),
		"used_triples":        tripleListJSON(used),
		"suggested_role_yaml": c.SuggestedRoleYAML,
	})
	return buildFinding(
		"KUBE-RBAC-UNUSED-VERB-001",
		models.SeverityLow,
		3.0,
		subj,
		res,
		evidence,
		c,
	)
}

// findingForWildcardNarrowing emits KUBE-RBAC-WILDCARD-USED-PARTIAL-001: the Role
// grants verbs: ["*"] on a coordinate the subject only exercises a subset of.
func (a *Analyzer) findingForWildcardNarrowing(subj models.SubjectRef, roleName string, rules []permissions.EffectiveRule, wildcards []wildcardEntry) models.Finding {
	c := contentWildcardNarrowing(subj, roleName, wildcards, a.idx)
	res := &models.ResourceRef{Kind: roleKindFor(rules, roleName), Name: roleName, APIGroup: "rbac.authorization.k8s.io"}
	wildcardsJSON := make([]map[string]any, 0, len(wildcards))
	for _, w := range wildcards {
		wildcardsJSON = append(wildcardsJSON, map[string]any{
			"api_group":      w.APIGroup,
			"resource":       w.Resource,
			"observed_verbs": w.ObservedVerbs,
		})
	}
	evidence := a.windowEvidence(roleName, map[string]any{
		"wildcards":           wildcardsJSON,
		"suggested_role_yaml": c.SuggestedRoleYAML,
	})
	return buildFinding(
		"KUBE-RBAC-WILDCARD-USED-PARTIAL-001",
		models.SeverityMedium,
		5.5,
		subj,
		res,
		evidence,
		c,
	)
}

// buildFinding assembles a Finding with the common fields. ID encodes RuleID + subject +
// role so two opportunities on the same subject from two different Roles dedupe
// independently.
func buildFinding(ruleID string, sev models.Severity, score float64, subj models.SubjectRef, res *models.ResourceRef, evidence json.RawMessage, c content) models.Finding {
	id := fmt.Sprintf("%s:%s:%s", ruleID, subj.Key(), res.Name)
	refs := make([]string, 0, len(c.LearnMore))
	for _, r := range c.LearnMore {
		refs = append(refs, r.URL)
	}
	return models.Finding{
		ID:               id,
		RuleID:           ruleID,
		Severity:         sev,
		Score:            score,
		Category:         models.CategoryPrivilegeEscalation, // latent privesc surface
		Title:            c.Title,
		Description:      c.Description,
		Subject:          &subj,
		Resource:         res,
		Namespace:        subj.Namespace,
		Scope:            c.Scope,
		Impact:           c.Impact,
		AttackScenario:   c.AttackScenario,
		Evidence:         evidence,
		Remediation:      c.Remediation,
		RemediationSteps: c.RemediationSteps,
		References:       refs,
		LearnMore:        c.LearnMore,
		MitreTechniques:  nil, // recommendations, no ATT&CK mapping
		Tags:             []string{"module:leastprivilege", "category:least_privilege"},
	}
}

// --- small helpers ---------------------------------------------------------

// mountedServiceAccounts mirrors rbac.usedServiceAccounts: a SA key is "in use" when
// some Pod references it. Reused via reimplementation rather than imported because the
// rbac package's symbol is unexported and adding a public accessor solely for this is
// premature.
func mountedServiceAccounts(snapshot models.Snapshot) map[string]bool {
	out := map[string]bool{}
	for _, pod := range snapshot.Resources.Pods {
		sa := pod.Spec.ServiceAccountName
		if sa == "" {
			sa = "default"
		}
		out[models.SubjectRef{Kind: "ServiceAccount", Name: sa, Namespace: pod.Namespace}.Key()] = true
	}
	return out
}

func distinctSourceRoles(rules []permissions.EffectiveRule) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0)
	for _, r := range rules {
		if r.SourceRole == "" {
			continue
		}
		if _, ok := seen[r.SourceRole]; ok {
			continue
		}
		seen[r.SourceRole] = struct{}{}
		out = append(out, r.SourceRole)
	}
	sort.Strings(out)
	return out
}

func groupRulesByRole(rules []permissions.EffectiveRule) map[string][]permissions.EffectiveRule {
	out := map[string][]permissions.EffectiveRule{}
	for _, r := range rules {
		out[r.SourceRole] = append(out[r.SourceRole], r)
	}
	return out
}

// roleKindFor returns "Role" if any contributing rule was bound in a namespace, else
// "ClusterRole". We don't preserve the original RoleRef kind in permissions.EffectiveRule
// so this is a heuristic - namespace-scoped contributions can only come from a Role-shaped
// binding path (Role or ClusterRole bound via a RoleBinding).
func roleKindFor(rules []permissions.EffectiveRule, roleName string) string {
	for _, r := range rules {
		if r.SourceRole != roleName {
			continue
		}
		if r.Namespace != "" {
			return "Role"
		}
	}
	return "ClusterRole"
}

func containsWildcard(values []string) bool {
	for _, v := range values {
		if v == "*" {
			return true
		}
	}
	return false
}

// normalizeGroup folds Kubernetes's two ways of spelling the core API group (empty string
// vs "core") to the canonical empty string. Both forms appear in audit logs and RBAC rule
// definitions; without this normalization, `get pods` in the core group would never match
// a Role that explicitly listed `apiGroups: [""]`.
func normalizeGroup(g string) string {
	if g == "core" {
		return ""
	}
	return g
}

func sortTriples(ts []triple) {
	sort.Slice(ts, func(i, j int) bool {
		if ts[i].APIGroup != ts[j].APIGroup {
			return ts[i].APIGroup < ts[j].APIGroup
		}
		if ts[i].Resource != ts[j].Resource {
			return ts[i].Resource < ts[j].Resource
		}
		return ts[i].Verb < ts[j].Verb
	})
}

func tripleListJSON(ts []triple) []map[string]any {
	out := make([]map[string]any, 0, len(ts))
	for _, t := range ts {
		out = append(out, map[string]any{
			"api_group": t.APIGroup,
			"resource":  t.Resource,
			"verb":      t.Verb,
		})
	}
	return out
}
