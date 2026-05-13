// Package report - Least Privilege tab section builder. Filters findings down to the
// LP rule-ID set, groups them by subject, and packages window summary + counts for the
// template. Pure data layer; the HTML markup lives in report.html.tmpl.
package report

import (
	"encoding/json"
	"fmt"
	"html/template"
	"sort"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/analyzer/leastprivilege"
	"github.com/0hardik1/kubesplaining/internal/models"
)

// buildLeastPrivilegeSection filters findings to the LP rule set, populates two top-of-
// tab summary tables (one for unused/stale RBAC resources, one for the Role -> unused
// verbs mapping), and groups the same findings per-subject for the detailed cards. The
// tables and cards share the same underlying finding slice; the tables are a denser view
// for triage, the cards carry the full prose + remediation YAML.
func buildLeastPrivilegeSection(findings []models.Finding, usageInfo *UsageInfo) LeastPrivilegeSection {
	section := LeastPrivilegeSection{}
	if usageInfo != nil {
		section.HasAuditData = true
		section.WindowStart = usageInfo.WindowStart.Format("2006-01-02")
		section.WindowEnd = usageInfo.WindowEnd.Format("2006-01-02")
		section.WindowDays = usageInfo.WindowDays()
		section.EventsProcessed = usageInfo.EventsProcessed
		section.NonSAUsernames = usageInfo.NonSAUsernames
	}

	bySubject := map[string]*LeastPrivilegeGroup{}
	order := []string{}
	for _, f := range findings {
		if !leastprivilege.IsLeastPrivilegeRule(f.RuleID) {
			continue
		}
		section.Total++

		// Both summary tables are populated alongside the per-subject grouping. A
		// finding can contribute to one or both tables depending on its rule ID; the
		// helpers decide.
		if row, ok := unusedResourceRowFor(f); ok {
			section.UnusedResources = append(section.UnusedResources, row)
		}
		if row, ok := roleVerbRowFor(f); ok {
			section.RoleVerbMap = append(section.RoleVerbMap, row)
		}

		key := subjectGroupKey(f.Subject)
		if _, ok := bySubject[key]; !ok {
			g := &LeastPrivilegeGroup{
				SubjectLabel: subjectGroupLabel(f.Subject),
			}
			if f.Subject != nil {
				g.SubjectKind = f.Subject.Kind
				g.SubjectName = f.Subject.Name
				g.SubjectNs = f.Subject.Namespace
			}
			bySubject[key] = g
			order = append(order, key)
		}
		bySubject[key].Cards = append(bySubject[key].Cards, newCard(f))
	}

	// Sort each group's cards by severity rank then ruleID. Compute summary off the
	// underlying findings so the per-group severity-pill badges line up with the cards.
	for _, g := range bySubject {
		sort.SliceStable(g.Cards, func(i, j int) bool {
			if g.Cards[i].Finding.Severity.Rank() != g.Cards[j].Finding.Severity.Rank() {
				return g.Cards[i].Finding.Severity.Rank() > g.Cards[j].Finding.Severity.Rank()
			}
			if g.Cards[i].Finding.Score != g.Cards[j].Finding.Score {
				return g.Cards[i].Finding.Score > g.Cards[j].Finding.Score
			}
			return g.Cards[i].Finding.RuleID < g.Cards[j].Finding.RuleID
		})
		gFindings := make([]models.Finding, len(g.Cards))
		for i, c := range g.Cards {
			gFindings[i] = c.Finding
		}
		g.Summary = BuildSummary(gFindings)
	}

	// Sort groups by per-group severity weight so the worst opportunities surface first.
	sort.SliceStable(order, func(i, j int) bool {
		gi, gj := bySubject[order[i]], bySubject[order[j]]
		return compareSummaries(gi.Summary, gj.Summary, gi.SubjectLabel, gj.SubjectLabel)
	})
	section.Groups = make([]LeastPrivilegeGroup, 0, len(order))
	for _, k := range order {
		section.Groups = append(section.Groups, *bySubject[k])
	}

	// Stable order for the summary tables: severity rank then resource/role name. Keeps
	// the worst opportunities at the top of each table.
	sort.SliceStable(section.UnusedResources, func(i, j int) bool {
		if section.UnusedResources[i].Severity.Rank() != section.UnusedResources[j].Severity.Rank() {
			return section.UnusedResources[i].Severity.Rank() > section.UnusedResources[j].Severity.Rank()
		}
		return section.UnusedResources[i].Resource < section.UnusedResources[j].Resource
	})
	sort.SliceStable(section.RoleVerbMap, func(i, j int) bool {
		if section.RoleVerbMap[i].Severity.Rank() != section.RoleVerbMap[j].Severity.Rank() {
			return section.RoleVerbMap[i].Severity.Rank() > section.RoleVerbMap[j].Severity.Rank()
		}
		if section.RoleVerbMap[i].Role != section.RoleVerbMap[j].Role {
			return section.RoleVerbMap[i].Role < section.RoleVerbMap[j].Role
		}
		return section.RoleVerbMap[i].Subject < section.RoleVerbMap[j].Subject
	})

	return section
}

// newCard wraps a Finding with extracted per-tab presentation data. SuggestedRoleYAML
// is pulled out of Evidence so the template can render it as a proper <pre><code> block.
func newCard(f models.Finding) LeastPrivilegeFindingCard {
	return LeastPrivilegeFindingCard{
		Finding:           f,
		SuggestedRoleYAML: extractEvidenceString(f.Evidence, "suggested_role_yaml"),
	}
}

// unusedResourceRowFor builds the "Unused RBAC resources" table row for findings that
// describe an entire resource (Role, ClusterRole, binding) as unused or stale. Returns
// ok=false for findings that don't fit this table (per-verb narrowing, wildcard).
//
// Resource is rendered as "<Kind>/<name>" so the table doesn't need a separate Kind
// column. For OVERBROAD-001 the rbac analyzer sets Resource.Kind to the synthetic
// "RBACRule" label (not a real k8s kind), so we override with "ClusterRole" - the rule
// only fires on ClusterRoleBinding -> cluster-admin grants.
//
// Action carries the concrete "what to delete" instruction with the binding name pulled
// from evidence so an operator can act on the row without expanding the card. The
// underlying Role/ClusterRole stays - we never recommend deleting a built-in.
func unusedResourceRowFor(f models.Finding) (LPUnusedResourceRow, bool) {
	row := LPUnusedResourceRow{
		RuleID:    f.RuleID,
		Severity:  f.Severity,
		FindingID: f.ID,
	}
	row.Subject = compactSubject(f.Subject)
	kind, name := resourceKindAndName(f)
	ev := decodeEvidence(f.Evidence)
	switch f.RuleID {
	case "KUBE-RBAC-UNUSED-ROLE-001":
		row.Why = "No observed API calls in the audit window"
		row.Action = actionDeleteRole(kind, name)
	case "KUBE-RBAC-UNUSED-RULE-001":
		row.Why = "Every rule in this Role is unused"
		row.Action = actionDeleteRole(kind, name)
	case "KUBE-RBAC-STALE-001":
		row.Why = "Binding references a Role/ClusterRole that does not exist"
		row.Action = actionDeleteBinding(ev, "target Role missing")
	case "KUBE-RBAC-STALE-002":
		row.Why = "Binding lists a ServiceAccount subject that does not exist"
		row.Action = actionDeleteBinding(ev, "subject missing")
	case "KUBE-RBAC-OVERBROAD-001":
		row.Why = "Direct binding to cluster-admin"
		// findingFromContent labels the resource as "RBACRule" - a placeholder, not a
		// real Kind. cluster-admin is always a ClusterRole, so override here rather
		// than across the rbac analyzer where other reports rely on the existing shape.
		kind = "ClusterRole"
		row.Action = actionDeleteBinding(ev, "scope down to a narrower ClusterRole")
	default:
		return LPUnusedResourceRow{}, false
	}
	if kind != "" && name != "" {
		row.Resource = kind + "/" + name
	} else {
		row.Resource = name
	}
	return row, true
}

// decodeEvidence is a forgiving JSON unmarshaller used by the row builders for action
// text. Returns an empty map on any miss so callers can use lookups directly.
func decodeEvidence(raw json.RawMessage) map[string]any {
	if len(raw) == 0 {
		return map[string]any{}
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return map[string]any{}
	}
	return obj
}

// evidenceString pulls a string field out of a decoded evidence map. Empty on miss.
func evidenceString(ev map[string]any, key string) string {
	v, ok := ev[key]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

// actionDeleteBinding renders the actionable "delete this binding" instruction with the
// binding kind (RoleBinding / ClusterRoleBinding) and namespace-qualified name pulled
// from the finding's evidence. Falls back to a generic message when the binding name
// isn't carried (defensive - all current rules carry it).
func actionDeleteBinding(ev map[string]any, note string) template.HTML {
	bindingName := evidenceString(ev, "source_binding")
	bindingKind := evidenceString(ev, "source_binding_kind")
	bindingNs := evidenceString(ev, "binding_namespace")
	if bindingKind == "" {
		bindingKind = "Binding"
	}
	if bindingName == "" {
		return template.HTML(`<span>Delete the binding (` + template.HTMLEscapeString(note) + `)</span>`)
	}
	label := bindingKind + "/"
	if bindingNs != "" {
		label += bindingNs + "/"
	}
	label += bindingName
	return template.HTML(`<span class="lp-action-verb">Delete</span> <code class="lp-action-target">` +
		template.HTMLEscapeString(label) + `</code> <span class="lp-action-note">(` +
		template.HTMLEscapeString(note) + `)</span>`)
}

// actionDeleteRole renders the actionable "delete this Role and its bindings" instruction
// for findings where the whole Role is unused.
func actionDeleteRole(kind, name string) template.HTML {
	if kind == "" {
		kind = "Role"
	}
	if name == "" {
		return template.HTML(`<span>Delete the Role and its bindings</span>`)
	}
	label := kind + "/" + name
	return template.HTML(`<span class="lp-action-verb">Delete</span> <code class="lp-action-target">` +
		template.HTMLEscapeString(label) + `</code> <span class="lp-action-note">(and its bindings)</span>`)
}

// resourceKindAndName pulls the kind/name pair that should display in the LP summary
// tables. Prefers the Finding.Resource pair, falling back to evidence for findings that
// don't carry a typed Resource (older rules, defensive).
func resourceKindAndName(f models.Finding) (kind, name string) {
	if f.Resource != nil {
		kind = f.Resource.Kind
		name = f.Resource.Name
	}
	return kind, name
}

// roleVerbRowFor builds the "Role -> unused verbs" table row for findings that describe
// a verb-level narrowing opportunity. Returns ok=false for findings that don't fit.
//
// Role displays as "<Kind>/<name>" for consistency with the other LP table; the LP
// analyzer already sets Resource.Kind to the real k8s kind via roleKindFor(). UsedVerbs
// + UnusedVerbs render side by side so the operator can see "what's actually exercised"
// next to "what to drop"; Action spells out the edit.
func roleVerbRowFor(f models.Finding) (LPRoleVerbRow, bool) {
	row := LPRoleVerbRow{
		RuleID:    f.RuleID,
		Severity:  f.Severity,
		FindingID: f.ID,
		Subject:   compactSubject(f.Subject),
	}
	kind, name := resourceKindAndName(f)
	roleLabel := name
	if kind != "" && name != "" {
		roleLabel = kind + "/" + name
	}
	row.Role = roleLabel
	switch f.RuleID {
	case "KUBE-RBAC-UNUSED-VERB-001":
		unused := extractEvidenceTriples(f.Evidence, "unused_triples")
		used := extractEvidenceTriples(f.Evidence, "used_triples")
		row.UnusedVerbs = formatVerbList(unused)
		row.UsedVerbs = formatVerbList(used)
		row.Action = actionDropVerbs(roleLabel, len(unused))
	case "KUBE-RBAC-UNUSED-RULE-001":
		// Every rule in the Role is unused - no used set to render. The action is to
		// drop the rule(s) entirely rather than trim verbs.
		unused := extractEvidenceTriples(f.Evidence, "unused_triples")
		row.UnusedVerbs = formatVerbList(unused)
		row.UsedVerbs = formatVerbsNone()
		row.Action = actionDropAllRules(roleLabel)
	case "KUBE-RBAC-WILDCARD-USED-PARTIAL-001":
		// The wildcard rule fires because verbs: ["*"] grants the entire standard verb
		// set, of which the SA only exercised a few. Showing both sides lets the
		// operator see "here's what's actually used; here's the over-grant" without
		// having to reason about what `*` means on this resource.
		used, unused := wildcardTriples(f.Evidence)
		row.UsedVerbs = renderVerbsGrouped(used)
		row.UnusedVerbs = renderVerbsGrouped(unused)
		row.Action = actionNarrowWildcard(roleLabel)
	default:
		return LPRoleVerbRow{}, false
	}
	if row.UnusedVerbs == "" {
		return LPRoleVerbRow{}, false
	}
	return row, true
}

// formatVerbsNone renders the empty-state for the Used column when every granted verb is
// unused.
func formatVerbsNone() template.HTML {
	return template.HTML(`<span class="lp-verb-none">none observed</span>`)
}

// actionDropVerbs renders the actionable instruction for UNUSED-VERB-001: drop the
// listed verbs from the Role and apply the suggested YAML on the card below.
func actionDropVerbs(roleLabel string, n int) template.HTML {
	plural := "verb"
	if n != 1 {
		plural = "verbs"
	}
	return template.HTML(`<span class="lp-action-verb">Drop</span> the <strong>` +
		fmt.Sprintf("%d", n) + ` unused ` + plural +
		`</strong> from <code class="lp-action-target">` + template.HTMLEscapeString(roleLabel) +
		`</code> <span class="lp-action-note">(use the suggested YAML below)</span>`)
}

// actionDropAllRules renders the action for UNUSED-RULE-001: every granted (verb,
// resource) triple in this Role is unused, so the whole rule block goes.
func actionDropAllRules(roleLabel string) template.HTML {
	return template.HTML(`<span class="lp-action-verb">Delete the rule block</span> in <code class="lp-action-target">` +
		template.HTMLEscapeString(roleLabel) + `</code> <span class="lp-action-note">(every granted verb is unused)</span>`)
}

// actionNarrowWildcard renders the action for WILDCARD-USED-PARTIAL-001: replace the
// wildcard verbs list with the concrete observed verbs.
func actionNarrowWildcard(roleLabel string) template.HTML {
	return template.HTML(`<span class="lp-action-verb">Replace</span> <code class="lp-action-target">verbs: ["*"]</code> in <code class="lp-action-target">` +
		template.HTMLEscapeString(roleLabel) + `</code> <span class="lp-action-note">with the observed verbs (see YAML below)</span>`)
}

// subjectGroupKey is the stable per-subject grouping key. Findings with no subject (rare
// in least-privilege findings, but defensive) collapse into a single "(no subject)" bucket
// so the tab never silently drops a finding.
func subjectGroupKey(s *models.SubjectRef) string {
	if s == nil {
		return "__none"
	}
	return s.Key()
}

// subjectGroupLabel is the display label shown in the tab heading.
func subjectGroupLabel(s *models.SubjectRef) string {
	if s == nil {
		return "(no subject)"
	}
	if s.Namespace != "" {
		return fmt.Sprintf("%s %s/%s", s.Kind, s.Namespace, s.Name)
	}
	return fmt.Sprintf("%s %s", s.Kind, s.Name)
}

// compactSubject is the short row-friendly subject label for the summary tables.
func compactSubject(s *models.SubjectRef) string {
	if s == nil {
		return ""
	}
	if s.Namespace != "" {
		return fmt.Sprintf("%s/%s", s.Namespace, s.Name)
	}
	return s.Name
}

// extractEvidenceString pulls a single string field out of an analyzer-emitted Evidence
// JSON blob. Returns "" on any miss (malformed JSON, missing key, non-string value) so
// callers can use the result as a "render this when non-empty" gate.
func extractEvidenceString(raw json.RawMessage, key string) string {
	if len(raw) == 0 {
		return ""
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return ""
	}
	v, ok := obj[key]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

// extractEvidenceTriples decodes the analyzer's "unused_triples" array into a flat
// []string suitable for the summary table. Each entry renders as "verb resource".
func extractEvidenceTriples(raw json.RawMessage, key string) []map[string]string {
	if len(raw) == 0 {
		return nil
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil
	}
	arr, ok := obj[key].([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]string, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		entry := map[string]string{}
		if v, ok := m["verb"].(string); ok {
			entry["verb"] = v
		}
		if v, ok := m["resource"].(string); ok {
			entry["resource"] = v
		}
		if v, ok := m["api_group"].(string); ok {
			entry["api_group"] = v
		}
		out = append(out, entry)
	}
	return out
}

// verbResource is one (verb, resource) coordinate used by the renderer. We intentionally
// drop api_group here because surfacing it in the cell adds noise without much value:
// operators recognize "deployments" without needing "apps/v1" prefixed every time. The
// per-card YAML below still carries the fully-qualified rule for editing.
type verbResource struct {
	Verb     string
	Resource string
}

// standardVerbs is the canonical set of verbs every RBAC rule can grant. Used to compute
// "what verbs does a wildcard expose that this subject never used?" - the universe is
// resource-dependent (some resources also accept bind/escalate/impersonate/use), but for
// summary-table display this list is honest enough: every entry shown here is a verb the
// SA could exercise tomorrow without anyone reviewing the binding.
var standardVerbs = []string{"get", "list", "watch", "create", "update", "patch", "delete", "deletecollection"}

// triplesToVR converts the extractEvidenceTriples shape (map[string]string with verb,
// resource, api_group keys) into the renderer's verbResource shape. Empty verb or
// resource entries are dropped.
func triplesToVR(triples []map[string]string) []verbResource {
	out := make([]verbResource, 0, len(triples))
	for _, t := range triples {
		v := strings.TrimSpace(t["verb"])
		r := strings.TrimSpace(t["resource"])
		if v == "" || r == "" {
			continue
		}
		out = append(out, verbResource{Verb: v, Resource: r})
	}
	return out
}

// renderVerbsGrouped renders verb/resource pairs grouped by verb: one row per verb with
// the resources it applies to stacked vertically inside a single resource chip. The
// "one chip per verb" shape keeps each verb's blast radius visually grouped instead of
// scattered across many separate chips. Caps at 8 verbs with "+N more" overflow; empty
// input returns the "none" placeholder so the column never goes blank.
func renderVerbsGrouped(items []verbResource) template.HTML {
	if len(items) == 0 {
		return formatVerbsNone()
	}
	byVerb := map[string][]string{}
	order := []string{}
	for _, it := range items {
		if _, seen := byVerb[it.Verb]; !seen {
			order = append(order, it.Verb)
		}
		byVerb[it.Verb] = append(byVerb[it.Verb], it.Resource)
	}
	sort.Strings(order)

	limit := len(order)
	if limit > 8 {
		limit = 8
	}
	var b strings.Builder
	b.WriteString(`<ul class="lp-verb-list">`)
	for i := 0; i < limit; i++ {
		verb := order[i]
		resources := dedupeStrings(byVerb[verb])
		sort.Strings(resources)
		// Single chip per verb: the verb label leads, the resources stack below.
		// Keeping them in one bordered <code> visually anchors each verb's blast
		// radius to one cell rather than two adjacent chips that could be mistaken
		// for unrelated grants.
		b.WriteString(`<li><code class="lp-verb-chip"><span class="lp-verb-label">`)
		b.WriteString(template.HTMLEscapeString(verb))
		b.WriteString(`:</span>`)
		for j, r := range resources {
			if j > 0 {
				b.WriteString(`<span class="lp-resource-sep">|</span>`)
			}
			b.WriteString(template.HTMLEscapeString(r))
		}
		b.WriteString(`</code></li>`)
	}
	b.WriteString(`</ul>`)
	if len(order) > limit {
		fmt.Fprintf(&b, `<div class="lp-verb-more">+%d more verbs</div>`, len(order)-limit)
	}
	return template.HTML(b.String())
}

// dedupeStrings returns the input with duplicates removed, preserving first-seen order.
func dedupeStrings(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// formatVerbList is the public entry point for UNUSED-VERB / UNUSED-RULE rendering: it
// hands off to renderVerbsGrouped after the row builder has already pulled the triples
// out of evidence. Kept as a thin wrapper so the row builder reads cleanly.
func formatVerbList(triples []map[string]string) template.HTML {
	return renderVerbsGrouped(triplesToVR(triples))
}

// wildcardTriples decodes a WILDCARD-USED-PARTIAL evidence payload into used/unused
// (verb, resource) sets. used = observed_verbs from the audit; unused = standardVerbs
// minus observed - the verbs the wildcard grant exposes that the subject never used.
// This is the data behind the "you have `*`, narrow to these N verbs" recommendation.
func wildcardTriples(raw json.RawMessage) (used, unused []verbResource) {
	if len(raw) == 0 {
		return nil, nil
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, nil
	}
	arr, ok := obj["wildcards"].([]any)
	if !ok {
		return nil, nil
	}
	for _, item := range arr {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		resource, _ := m["resource"].(string)
		if resource == "" {
			continue
		}
		observedRaw, _ := m["observed_verbs"].([]any)
		observed := map[string]struct{}{}
		for _, v := range observedRaw {
			s, ok := v.(string)
			if !ok {
				continue
			}
			observed[s] = struct{}{}
			used = append(used, verbResource{Verb: s, Resource: resource})
		}
		for _, sv := range standardVerbs {
			if _, ok := observed[sv]; ok {
				continue
			}
			unused = append(unused, verbResource{Verb: sv, Resource: resource})
		}
	}
	return used, unused
}
