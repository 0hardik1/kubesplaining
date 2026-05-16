// Package rbac analyzes Role/ClusterRole bindings and flags subjects whose
// effective permissions enable privilege escalation or data exfiltration.
package rbac

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/scoring"
	rbacv1 "k8s.io/api/rbac/v1"
)

// Analyzer produces RBAC-focused findings from a snapshot.
type Analyzer struct{}

// effectiveRule is a flattened policy rule tagged with where it came from so findings can point back at it.
//
// SourceRole / SourceBinding hold the raw object names (used in Evidence JSON, where
// machine-readable identifiers are correct). The Kind/Namespace fields let prose
// renderers qualify those names with their resource Kind — e.g. "ClusterRoleBinding
// `crb-nodes-proxy`" instead of an opaque "`crb-nodes-proxy`" — which is what the
// Findings tab needs to be readable for someone who hasn't memorized the cluster.
type effectiveRule struct {
	Namespace              string
	APIGroups              []string
	Resources              []string
	Verbs                  []string
	SourceRole             string
	SourceRoleKind         string
	SourceRoleNamespace    string
	SourceBinding          string
	SourceBindingKind      string
	SourceBindingNamespace string
}

// formattedBinding returns the binding rendered as "ClusterRoleBinding `name`" or
// "RoleBinding `ns/name`" for inclusion in finding prose. See formatBindingRef.
func (r effectiveRule) formattedBinding() string {
	return formatBindingRef(r.SourceBindingKind, r.SourceBindingNamespace, r.SourceBinding)
}

// formattedRole mirrors formattedBinding for the Role/ClusterRole side.
func (r effectiveRule) formattedRole() string {
	return formatRoleRef(r.SourceRoleKind, r.SourceRoleNamespace, r.SourceRole)
}

// effectivePermissions collects every effectiveRule that resolves to a given subject.
type effectivePermissions struct {
	Subject models.SubjectRef
	Rules   []effectiveRule
}

// New returns a new RBAC analyzer.
func New() *Analyzer {
	return &Analyzer{}
}

// Name returns the module identifier used by the engine.
func (a *Analyzer) Name() string {
	return "rbac"
}

// Analyze walks role and cluster role bindings, resolves each subject's effective permissions,
// and emits findings for wildcard access, secret reads, impersonation, bind/escalate, and similar risks.
func (a *Analyzer) Analyze(_ context.Context, snapshot models.Snapshot) ([]models.Finding, error) {
	roleRules := make(map[string][]rbacv1.PolicyRule, len(snapshot.Resources.Roles))
	for _, role := range snapshot.Resources.Roles {
		roleRules[fmt.Sprintf("%s/%s", role.Namespace, role.Name)] = role.Rules
	}

	clusterRoleRules := make(map[string][]rbacv1.PolicyRule, len(snapshot.Resources.ClusterRoles))
	for _, clusterRole := range snapshot.Resources.ClusterRoles {
		clusterRoleRules[clusterRole.Name] = clusterRole.Rules
	}

	subjects := map[string]*effectivePermissions{}

	for _, binding := range snapshot.Resources.RoleBindings {
		rules := referencedRules(binding.RoleRef, binding.Namespace, roleRules, clusterRoleRules)
		// A RoleBinding's RoleRef.Kind is "Role" (same namespace) or "ClusterRole" (cluster-scoped).
		// Roles are always co-located with their RoleBinding, so the role's namespace mirrors
		// binding.Namespace; ClusterRoles have no namespace.
		roleNamespace := ""
		if binding.RoleRef.Kind == "Role" {
			roleNamespace = binding.Namespace
		}
		for _, subject := range binding.Subjects {
			ref := subjectRef(subject, binding.Namespace)
			perms := getSubject(subjects, ref)
			for _, rule := range rules {
				perms.Rules = append(perms.Rules, effectiveRule{
					Namespace:              binding.Namespace,
					APIGroups:              append([]string(nil), rule.APIGroups...),
					Resources:              append([]string(nil), rule.Resources...),
					Verbs:                  append([]string(nil), rule.Verbs...),
					SourceRole:             binding.RoleRef.Name,
					SourceRoleKind:         binding.RoleRef.Kind,
					SourceRoleNamespace:    roleNamespace,
					SourceBinding:          binding.Name,
					SourceBindingKind:      "RoleBinding",
					SourceBindingNamespace: binding.Namespace,
				})
			}
		}
	}

	for _, binding := range snapshot.Resources.ClusterRoleBindings {
		rules := referencedRules(binding.RoleRef, "", roleRules, clusterRoleRules)
		// ClusterRoleBindings can only reference ClusterRoles; both are cluster-scoped.
		for _, subject := range binding.Subjects {
			ref := subjectRef(subject, "")
			perms := getSubject(subjects, ref)
			for _, rule := range rules {
				perms.Rules = append(perms.Rules, effectiveRule{
					APIGroups:         append([]string(nil), rule.APIGroups...),
					Resources:         append([]string(nil), rule.Resources...),
					Verbs:             append([]string(nil), rule.Verbs...),
					SourceRole:        binding.RoleRef.Name,
					SourceRoleKind:    binding.RoleRef.Kind,
					SourceBinding:     binding.Name,
					SourceBindingKind: "ClusterRoleBinding",
				})
			}
		}
	}

	usedServiceAccounts := usedServiceAccounts(snapshot)
	seen := map[string]struct{}{}
	findings := make([]models.Finding, 0)

	for _, perms := range subjects {
		for _, rule := range perms.Rules {
			// Score multipliers (applied to each rule's base score below):
			//   blastRadius     - cluster-scoped grants reach every namespace, so we bump them 20%
			//                     over namespace-scoped grants of the same permission.
			//   exploitability  - a ServiceAccount that is actually mounted by a pod can be reached
			//                     by an attacker who lands in that pod; an unused SA is a paper risk
			//                     until something starts mounting it, so the mounted ones get +20%.
			blastRadius := 1.0
			if rule.Namespace == "" {
				blastRadius = 1.2
			}
			exploitability := 1.0
			if perms.Subject.Kind == "ServiceAccount" && usedServiceAccounts[perms.Subject.Key()] {
				exploitability = 1.2
			}
			// scaledScore captures the per-rule multipliers above so each case below
			// only has to declare its base score - the formula is named once instead of
			// duplicated nine times.
			scaledScore := func(base float64) float64 {
				return scoring.Clamp(base * exploitability * blastRadius)
			}

			bindingRef := rule.formattedBinding()
			roleRef := rule.formattedRole()

			// Each case detects one privilege-escalation primitive and emits the matching
			// finding. switch (not if/else chain) so a rule that matches several cases
			// only fires the first - we prefer the most specific framing and let dedupe
			// merge cross-module overlaps later.
			switch {
			case hasWildcard(rule.Verbs) && hasWildcard(rule.Resources) && hasWildcard(rule.APIGroups):
				findings = appendFinding(findings, seen, findingFromContent(perms.Subject, rule,
					"KUBE-PRIVESC-017", models.SeverityCritical, models.CategoryPrivilegeEscalation,
					scaledScore(9.8),
					contentPrivesc017(rule.Namespace, perms.Subject, bindingRef, roleRef)))
			case hasResource(rule.Resources, "secrets") && hasAnyVerb(rule.Verbs, "get", "list", "watch"):
				findings = appendFinding(findings, seen, findingFromContent(perms.Subject, rule,
					"KUBE-PRIVESC-005", models.SeverityHigh, models.CategoryDataExfiltration,
					scaledScore(8.2),
					contentPrivesc005(rule.Namespace, perms.Subject, bindingRef, roleRef)))
			case hasResource(rule.Resources, "pods") && hasAnyVerb(rule.Verbs, "create"):
				findings = appendFinding(findings, seen, findingFromContent(perms.Subject, rule,
					"KUBE-PRIVESC-001", models.SeverityHigh, models.CategoryPrivilegeEscalation,
					scaledScore(8.4),
					contentPrivesc001(rule.Namespace, perms.Subject, bindingRef, roleRef)))
			case hasAnyResource(rule.Resources, []string{"deployments", "daemonsets", "statefulsets", "jobs", "cronjobs"}) &&
				hasAnyVerb(rule.Verbs, "create", "update", "patch"):
				findings = appendFinding(findings, seen, findingFromContent(perms.Subject, rule,
					"KUBE-PRIVESC-003", models.SeverityHigh, models.CategoryPrivilegeEscalation,
					scaledScore(8.1),
					contentPrivesc003(rule.Namespace, perms.Subject, bindingRef, roleRef)))
			case hasAnyResource(rule.Resources, []string{"users", "groups", "serviceaccounts"}) && hasAnyVerb(rule.Verbs, "impersonate"):
				findings = appendFinding(findings, seen, findingFromContent(perms.Subject, rule,
					"KUBE-PRIVESC-008", models.SeverityCritical, models.CategoryPrivilegeEscalation,
					scaledScore(9.4),
					contentPrivesc008(rule.Namespace, perms.Subject, bindingRef, roleRef)))
			case hasAnyResource(rule.Resources, []string{"roles", "clusterroles"}) && hasAnyVerb(rule.Verbs, "bind", "escalate"):
				findings = appendFinding(findings, seen, findingFromContent(perms.Subject, rule,
					"KUBE-PRIVESC-009", models.SeverityCritical, models.CategoryPrivilegeEscalation,
					scaledScore(9.2),
					contentPrivesc009(rule.Namespace, perms.Subject, bindingRef, roleRef)))
			case hasAnyResource(rule.Resources, []string{"rolebindings", "clusterrolebindings"}) &&
				hasAnyVerb(rule.Verbs, "create", "update", "patch"):
				findings = appendFinding(findings, seen, findingFromContent(perms.Subject, rule,
					"KUBE-PRIVESC-010", models.SeverityCritical, models.CategoryPrivilegeEscalation,
					scaledScore(9.0),
					contentPrivesc010(rule.Namespace, perms.Subject, bindingRef, roleRef)))
			case hasResource(rule.Resources, "nodes/proxy") && hasAnyVerb(rule.Verbs, "get"):
				findings = appendFinding(findings, seen, findingFromContent(perms.Subject, rule,
					"KUBE-PRIVESC-012", models.SeverityCritical, models.CategoryPrivilegeEscalation,
					scaledScore(9.3),
					contentPrivesc012(rule.Namespace, perms.Subject, bindingRef, roleRef)))
			case hasResource(rule.Resources, "serviceaccounts/token") && hasAnyVerb(rule.Verbs, "create"):
				findings = appendFinding(findings, seen, findingFromContent(perms.Subject, rule,
					"KUBE-PRIVESC-014", models.SeverityHigh, models.CategoryPrivilegeEscalation,
					scaledScore(8.0),
					contentPrivesc014(rule.Namespace, perms.Subject, bindingRef, roleRef)))
			}
		}

		// KUBE-PRIVESC-011 — CSR-mint primitive. Detection requires correlating two
		// separate rules on the same subject: cluster-scoped `create` on
		// `certificatesigningrequests` AND cluster-scoped `update`/`patch` on
		// `certificatesigningrequests/approval`. Held together, the subject can
		// submit a CSR carrying `O=system:masters` (or any principal it picks) in
		// its Subject DN and self-approve it. The kubelet-signed cert then
		// authenticates as cluster-admin.
		//
		// We do this as a per-subject pass after the per-rule switch above so we
		// can union both halves across the subject's entire effective-rule set,
		// then emit one finding (anchored to the create rule for evidence) when
		// both halves are present.
		var createRule, approveRule *effectiveRule
		for i := range perms.Rules {
			r := &perms.Rules[i]
			if r.Namespace != "" {
				continue // CSRs are cluster-scoped; namespace-scoped grants are dead RBAC
			}
			if matchesCSRCreate(*r) && createRule == nil {
				createRule = r
			}
			if matchesCSRApprove(*r) && approveRule == nil {
				approveRule = r
			}
		}
		if createRule != nil && approveRule != nil {
			blastRadius := 1.2 // CSRs are cluster-scoped, always blast-radius=1.2
			exploitability := 1.0
			if perms.Subject.Kind == "ServiceAccount" && usedServiceAccounts[perms.Subject.Key()] {
				exploitability = 1.2
			}
			scaledScore := func(base float64) float64 {
				return scoring.Clamp(base * exploitability * blastRadius)
			}
			findings = appendFinding(findings, seen, findingFromContent(perms.Subject, *createRule,
				"KUBE-PRIVESC-011", models.SeverityHigh, models.CategoryPrivilegeEscalation,
				scaledScore(7.0), // base 7.0 × 1.2 blast = 8.4 (clamped if SA is mounted)
				contentPrivesc011(perms.Subject, createRule.formattedBinding(), createRule.formattedRole(), approveRule.formattedBinding(), approveRule.formattedRole())))
		}
	}

	for _, binding := range snapshot.Resources.ClusterRoleBindings {
		if binding.RoleRef.Kind == "ClusterRole" && binding.RoleRef.Name == "cluster-admin" {
			for _, subject := range binding.Subjects {
				ref := subjectRef(subject, "")
				if strings.HasPrefix(ref.Name, "system:") {
					continue
				}
				findings = appendFinding(findings, seen, findingFromContent(
					ref,
					effectiveRule{
						SourceBinding:     binding.Name,
						SourceBindingKind: "ClusterRoleBinding",
						SourceRole:        binding.RoleRef.Name,
						SourceRoleKind:    binding.RoleRef.Kind,
					},
					"KUBE-RBAC-OVERBROAD-001", models.SeverityCritical, models.CategoryPrivilegeEscalation, 10,
					contentRBACOverbroad001(ref, binding.Name)))
			}
		}
	}

	// Third pass — stale / dangling bindings.
	//
	// A (Cluster)RoleBinding whose roleRef points at a Role/ClusterRole that no
	// longer exists in the snapshot grants no permissions today, but reactivates
	// with whatever permissions the role contains the moment anyone re-creates
	// the role with the same name — without the binding being re-reviewed. That's
	// the KUBE-RBAC-STALE-001 case.
	//
	// Likewise, a binding whose subjects include a ServiceAccount that does not
	// exist in the snapshot becomes a live grant the moment a SA with that
	// namespace+name is (re-)created (an attacker with `create serviceaccounts`,
	// or a routine redeploy). That's KUBE-RBAC-STALE-002. User and Group subjects
	// cannot be validated this way: Kubernetes maintains no inventory of
	// Users/Groups (they are authenticated externally and asserted per request),
	// so the snapshot cannot tell us whether they "exist".
	serviceAccountSet := make(map[string]struct{}, len(snapshot.Resources.ServiceAccounts))
	for _, sa := range snapshot.Resources.ServiceAccounts {
		serviceAccountSet[fmt.Sprintf("%s/%s", sa.Namespace, sa.Name)] = struct{}{}
	}
	for _, binding := range snapshot.Resources.RoleBindings {
		findings = analyzeStaleBinding(findings, seen, binding.Name, "RoleBinding", binding.Namespace, binding.RoleRef, binding.Subjects, roleRules, clusterRoleRules, serviceAccountSet)
	}
	for _, binding := range snapshot.Resources.ClusterRoleBindings {
		findings = analyzeStaleBinding(findings, seen, binding.Name, "ClusterRoleBinding", "", binding.RoleRef, binding.Subjects, roleRules, clusterRoleRules, serviceAccountSet)
	}

	return findings, nil
}

// analyzeStaleBinding emits KUBE-RBAC-STALE-001 / -002 findings for a single
// (Cluster)RoleBinding. See the third-pass comment in Analyze for the rule
// semantics. When the roleRef is missing we emit -001 for every subject and
// skip the -002 check for that subject — a missing role already captures the
// drift, so adding -002 for any missing SA subjects on the same binding would
// just inflate the finding count.
func analyzeStaleBinding(
	findings []models.Finding,
	seen map[string]struct{},
	bindingName, bindingKind, bindingNamespace string,
	roleRef rbacv1.RoleRef,
	subjects []rbacv1.Subject,
	roleRules, clusterRoleRules map[string][]rbacv1.PolicyRule,
	serviceAccountSet map[string]struct{},
) []models.Finding {
	refs := make([]models.SubjectRef, 0, len(subjects))
	for _, s := range subjects {
		refs = append(refs, subjectRef(s, bindingNamespace))
	}
	bindingRefStr := formatBindingRef(bindingKind, bindingNamespace, bindingName)
	roleNamespace := roleRefNamespaceFor(roleRef, bindingNamespace)
	roleRefStr := formatRoleRef(roleRef.Kind, roleNamespace, roleRef.Name)
	roleExists := isBuiltinClusterRole(roleRef) || lookupRoleExists(roleRef, bindingNamespace, roleRules, clusterRoleRules)

	for i, subject := range subjects {
		ref := refs[i]
		if !roleExists {
			others := append([]models.SubjectRef{}, refs[:i]...)
			others = append(others, refs[i+1:]...)
			ctx := staleContext{
				BindingRef:       bindingRefStr,
				BindingNamespace: bindingNamespace,
				RoleRef:          roleRefStr,
				RoleName:         roleRef.Name,
				RoleKind:         roleRef.Kind,
				Subject:          ref,
				OtherSubjects:    others,
			}
			evidence, _ := json.Marshal(map[string]any{
				"source_binding":      bindingName,
				"source_binding_kind": bindingKind,
				"binding_namespace":   bindingNamespace,
				"missing_role":        roleRef.Name,
				"missing_role_kind":   roleRef.Kind,
				"other_subjects":      others,
			})
			findings = appendFinding(findings, seen, staleFinding(
				"KUBE-RBAC-STALE-001",
				models.SeverityMedium,
				5.0,
				ref,
				&models.ResourceRef{Kind: roleRef.Kind, Name: roleRef.Name, Namespace: roleNamespace, APIGroup: "rbac.authorization.k8s.io"},
				bindingNamespace, bindingName, bindingKind,
				evidence,
				contentRBACStale001(ctx),
				"stale:roleref",
			))
			continue
		}
		// -002 only applies to ServiceAccount subjects. User/Group existence
		// cannot be verified from the snapshot — see third-pass docstring above.
		if subject.Kind != "ServiceAccount" {
			continue
		}
		if _, ok := serviceAccountSet[fmt.Sprintf("%s/%s", ref.Namespace, ref.Name)]; ok {
			continue
		}
		ctx := staleContext{
			BindingRef:       bindingRefStr,
			BindingNamespace: bindingNamespace,
			RoleRef:          roleRefStr,
			RoleName:         roleRef.Name,
			RoleKind:         roleRef.Kind,
			Subject:          ref,
		}
		evidence, _ := json.Marshal(map[string]any{
			"source_binding":      bindingName,
			"source_binding_kind": bindingKind,
			"binding_namespace":   bindingNamespace,
			"source_role":         roleRef.Name,
			"source_role_kind":    roleRef.Kind,
		})
		findings = appendFinding(findings, seen, staleFinding(
			"KUBE-RBAC-STALE-002",
			models.SeverityLow,
			3.5,
			ref,
			&models.ResourceRef{Kind: roleRef.Kind, Name: roleRef.Name, Namespace: roleNamespace, APIGroup: "rbac.authorization.k8s.io"},
			bindingNamespace, bindingName, bindingKind,
			evidence,
			contentRBACStale002(ctx),
			"stale:subject",
		))
	}
	return findings
}

// isBuiltinClusterRole reports whether roleRef names one of the four user-facing
// ClusterRoles every Kubernetes distribution ships: `cluster-admin`, `admin`,
// `edit`, `view`. A snapshot that omits these (scan-resource of a single
// manifest, or a collection that hit RBAC-list permission errors) is still
// describing a real cluster where these roles exist — so we must not flag
// bindings to them as stale just because they're missing from the snapshot.
//
// We deliberately do NOT add `system:*` here: the standard exclusions preset
// drops findings whose subjects are `system:*` Users/Groups/SAs, so orphan
// findings involving a `system:*` subject disappear at the exclusions stage
// anyway. Conversely, a non-`system:*` subject bound to a missing `system:*`
// role is still a legitimate cleanup signal worth keeping.
func isBuiltinClusterRole(roleRef rbacv1.RoleRef) bool {
	if roleRef.Kind != "ClusterRole" {
		return false
	}
	switch roleRef.Name {
	case "cluster-admin", "admin", "edit", "view":
		return true
	}
	return false
}

// lookupRoleExists reports whether roleRef resolves to a known Role/ClusterRole
// in the supplied lookup maps. Unknown roleRef.Kind values are treated as
// existing (conservative — we don't flag what we can't categorize).
func lookupRoleExists(roleRef rbacv1.RoleRef, bindingNamespace string, roleRules, clusterRoleRules map[string][]rbacv1.PolicyRule) bool {
	switch roleRef.Kind {
	case "Role":
		_, ok := roleRules[fmt.Sprintf("%s/%s", bindingNamespace, roleRef.Name)]
		return ok
	case "ClusterRole":
		_, ok := clusterRoleRules[roleRef.Name]
		return ok
	}
	return true
}

// roleRefNamespaceFor returns the namespace component of a RoleRef for prose
// rendering. RoleBinding → Role inherits the binding's namespace; everything
// else (RoleBinding → ClusterRole, ClusterRoleBinding → ClusterRole) is
// cluster-scoped.
func roleRefNamespaceFor(roleRef rbacv1.RoleRef, bindingNamespace string) string {
	if roleRef.Kind == "Role" {
		return bindingNamespace
	}
	return ""
}

// staleFinding assembles a KUBE-RBAC-STALE-* Finding. It mirrors
// findingFromContent but specialises Evidence and Resource to the stale-binding
// shape (Resource = the role itself, not "RBACRule"; no per-rule verb/resource
// fields). The Finding.ID encodes the binding, so two stale findings on the
// same subject from two different bindings dedupe independently.
func staleFinding(
	ruleID string,
	severity models.Severity,
	score float64,
	subject models.SubjectRef,
	resource *models.ResourceRef,
	bindingNamespace, bindingName, bindingKind string,
	evidence json.RawMessage,
	content ruleContent,
	extraTag string,
) models.Finding {
	id := fmt.Sprintf("%s:%s:%s/%s/%s", ruleID, subject.Key(), bindingKind, bindingNamespace, bindingName)
	references := make([]string, 0, len(content.LearnMore))
	for _, ref := range content.LearnMore {
		references = append(references, ref.URL)
	}
	tags := []string{"module:rbac"}
	if extraTag != "" {
		tags = append(tags, extraTag)
	}
	return models.Finding{
		ID:               id,
		RuleID:           ruleID,
		Severity:         severity,
		Score:            score,
		Category:         models.CategoryPrivilegeEscalation,
		Title:            content.Title,
		Description:      content.Description,
		Subject:          &subject,
		Resource:         resource,
		Namespace:        bindingNamespace,
		Scope:            content.Scope,
		Impact:           content.Impact,
		AttackScenario:   content.AttackScenario,
		Evidence:         evidence,
		Remediation:      content.Remediation,
		RemediationSteps: content.RemediationSteps,
		References:       references,
		LearnMore:        content.LearnMore,
		MitreTechniques:  content.MitreTechniques,
		Tags:             tags,
	}
}

// appendFinding adds finding to the slice unless its ID has already been seen (deduplication keyed by Finding.ID).
func appendFinding(findings []models.Finding, seen map[string]struct{}, finding models.Finding) []models.Finding {
	if _, ok := seen[finding.ID]; ok {
		return findings
	}
	seen[finding.ID] = struct{}{}
	return append(findings, finding)
}

// findingFromContent materializes a models.Finding using the enriched ruleContent (Scope, Impact,
// AttackScenario, RemediationSteps, LearnMore, MitreTechniques) plus the runtime context (subject,
// originating rule, severity/score/category bucket). Evidence keeps the same shape as before so
// existing consumers continue to work.
func findingFromContent(subject models.SubjectRef, rule effectiveRule, ruleID string, severity models.Severity, category models.RiskCategory, score float64, content ruleContent) models.Finding {
	evidenceBytes, _ := json.Marshal(map[string]any{
		"source_role":         rule.SourceRole,
		"source_binding":      rule.SourceBinding,
		"source_binding_kind": rule.SourceBindingKind,
		"api_groups":          rule.APIGroups,
		"resources":           rule.Resources,
		"verbs":               rule.Verbs,
		"namespace":           rule.Namespace,
		"scope":               string(content.Scope.Level),
	})

	resource := &models.ResourceRef{
		Kind:      "RBACRule",
		Name:      rule.SourceRole,
		Namespace: rule.Namespace,
		APIGroup:  "rbac.authorization.k8s.io",
	}

	id := fmt.Sprintf("%s:%s:%s:%s", ruleID, subject.Key(), rule.Namespace, strings.Join(rule.Resources, ","))
	references := make([]string, 0, len(content.LearnMore))
	for _, ref := range content.LearnMore {
		references = append(references, ref.URL)
	}
	return models.Finding{
		ID:               id,
		RuleID:           ruleID,
		Severity:         severity,
		Score:            score,
		Category:         category,
		Title:            content.Title,
		Description:      content.Description,
		Subject:          &subject,
		Resource:         resource,
		Namespace:        rule.Namespace,
		Scope:            content.Scope,
		Impact:           content.Impact,
		AttackScenario:   content.AttackScenario,
		Evidence:         evidenceBytes,
		Remediation:      content.Remediation,
		RemediationSteps: content.RemediationSteps,
		References:       references,
		LearnMore:        content.LearnMore,
		MitreTechniques:  content.MitreTechniques,
		Tags:             []string{"module:rbac"},
	}
}

// referencedRules returns the PolicyRules that roleRef points at, handling both Role and ClusterRole references.
func referencedRules(
	roleRef rbacv1.RoleRef,
	namespace string,
	roleRules map[string][]rbacv1.PolicyRule,
	clusterRoleRules map[string][]rbacv1.PolicyRule,
) []rbacv1.PolicyRule {
	if roleRef.Kind == "Role" {
		return roleRules[fmt.Sprintf("%s/%s", namespace, roleRef.Name)]
	}
	return clusterRoleRules[roleRef.Name]
}

// getSubject fetches or creates the effectivePermissions entry for ref.
func getSubject(subjects map[string]*effectivePermissions, ref models.SubjectRef) *effectivePermissions {
	key := ref.Key()
	if subjects[key] == nil {
		subjects[key] = &effectivePermissions{Subject: ref}
	}
	return subjects[key]
}

// subjectRef normalizes a binding subject into models.SubjectRef, defaulting ServiceAccount namespace when unset.
func subjectRef(subject rbacv1.Subject, fallbackNamespace string) models.SubjectRef {
	ref := models.SubjectRef{
		Kind: subject.Kind,
		Name: subject.Name,
	}
	if subject.Kind == "ServiceAccount" {
		ref.Namespace = subject.Namespace
		if ref.Namespace == "" {
			ref.Namespace = fallbackNamespace
		}
	}
	return ref
}

func hasWildcard(values []string) bool {
	return slices.Contains(values, "*")
}

func hasAnyVerb(values []string, wanted ...string) bool {
	if hasWildcard(values) {
		return true
	}
	for _, value := range wanted {
		if slices.Contains(values, value) {
			return true
		}
	}
	return false
}

func hasResource(values []string, wanted string) bool {
	if hasWildcard(values) {
		return true
	}
	return slices.Contains(values, wanted)
}

func hasAnyResource(values []string, wanted []string) bool {
	if hasWildcard(values) {
		return true
	}
	for _, value := range wanted {
		if slices.Contains(values, value) {
			return true
		}
	}
	return false
}

// matchesCSRCreate reports whether rule grants `create` on the cluster-scoped
// `certificatesigningrequests` resource. Cluster scope is the caller's
// responsibility (rule.Namespace == "").
func matchesCSRCreate(rule effectiveRule) bool {
	return hasResource(rule.Resources, "certificatesigningrequests") && hasAnyVerb(rule.Verbs, "create")
}

// matchesCSRApprove reports whether rule grants `update` or `patch` on the
// `certificatesigningrequests/approval` subresource. The /approval subresource
// is the only RBAC gate on CSR approval — the parent CSR object's `update` verb
// does not allow approval — so this check is narrow on resource and broad on
// the two verbs `kubectl certificate approve` could use.
func matchesCSRApprove(rule effectiveRule) bool {
	return hasResource(rule.Resources, "certificatesigningrequests/approval") && hasAnyVerb(rule.Verbs, "update", "patch")
}

// usedServiceAccounts returns the set of ServiceAccounts actually mounted by pods, used to bump exploitability scoring.
func usedServiceAccounts(snapshot models.Snapshot) map[string]bool {
	result := make(map[string]bool)
	for _, pod := range snapshot.Resources.Pods {
		sa := pod.Spec.ServiceAccountName
		if sa == "" {
			sa = "default"
		}
		result[models.SubjectRef{
			Kind:      "ServiceAccount",
			Name:      sa,
			Namespace: pod.Namespace,
		}.Key()] = true
	}
	return result
}
