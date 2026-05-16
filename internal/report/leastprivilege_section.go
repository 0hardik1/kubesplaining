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
	"github.com/0hardik1/kubesplaining/internal/permissions"
)

// buildLeastPrivilegeSection filters findings to the LP rule set, populates two top-of-
// tab summary tables (one for unused/stale RBAC resources, one for the Role -> unused
// verbs mapping), and groups the same findings per-subject for the detailed cards. The
// tables and cards share the same underlying finding slice; the tables are a denser view
// for triage, the cards carry the full prose + remediation YAML.
func buildLeastPrivilegeSection(snapshot models.Snapshot, findings []models.Finding, usageInfo *UsageInfo) LeastPrivilegeSection {
	section := LeastPrivilegeSection{}
	if usageInfo != nil {
		section.HasAuditData = true
		section.WindowStart = usageInfo.WindowStart.Format("2006-01-02")
		section.WindowEnd = usageInfo.WindowEnd.Format("2006-01-02")
		section.WindowDays = usageInfo.WindowDays()
		section.EventsProcessed = usageInfo.EventsProcessed
		section.NonSAUsernames = usageInfo.NonSAUsernames
	}
	section.ClusterAdminInventory = buildClusterAdminInventory(snapshot)

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
// column. cluster-admin bindings are handled by the dedicated inventory table built
// from the snapshot, not this row builder, so OVERBROAD-001 is intentionally absent.
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
		// having to reason about what `*` means on this resource. The unused side is
		// synthetic — (standard verbs) x (resources on the rule) — so it gets capped
		// per-verb with a footnote that names the wildcard as the source of the bloat.
		used, unused := wildcardTriples(f.Evidence)
		row.UsedVerbs = renderVerbsGrouped(used)
		row.UnusedVerbs = renderVerbsGroupedOpts(unused, verbRenderOpts{
			ResourceCapPerVerb: 4,
			FootNote:           `Truncated — verbs: ["*"] expands to every standard verb the wildcard covers, multiplied by every resource on the matching rule.`,
		})
		row.Action = actionNarrowWildcard(roleLabel)
	default:
		return LPRoleVerbRow{}, false
	}
	if row.UnusedVerbs == "" {
		return LPRoleVerbRow{}, false
	}
	return row, true
}

// buildClusterAdminInventory walks every ClusterRoleBinding that targets the built-in
// cluster-admin ClusterRole and emits one row per subject. system:* subjects are kept
// because the inventory exists for visibility, not narrowing — operators need to see the
// built-in grants alongside the discretionary ones to recognize "what's expected" vs.
// "what someone added". Sorting puts non-system rows first so the entries operators
// actually act on surface at the top of the table.
func buildClusterAdminInventory(snapshot models.Snapshot) []LPClusterAdminRow {
	var rows []LPClusterAdminRow
	for _, binding := range snapshot.Resources.ClusterRoleBindings {
		if binding.RoleRef.Kind != "ClusterRole" || binding.RoleRef.Name != "cluster-admin" {
			continue
		}
		for _, subject := range binding.Subjects {
			isSystem := strings.HasPrefix(subject.Name, "system:") ||
				(subject.Kind == "Group" && strings.HasPrefix(subject.Name, "system:"))
			rows = append(rows, LPClusterAdminRow{
				Binding:     binding.Name,
				SubjectKind: subject.Kind,
				SubjectNs:   subject.Namespace,
				SubjectName: subject.Name,
				IsSystem:    isSystem,
			})
		}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].IsSystem != rows[j].IsSystem {
			return !rows[i].IsSystem
		}
		if rows[i].SubjectKind != rows[j].SubjectKind {
			return rows[i].SubjectKind < rows[j].SubjectKind
		}
		if rows[i].SubjectNs != rows[j].SubjectNs {
			return rows[i].SubjectNs < rows[j].SubjectNs
		}
		if rows[i].SubjectName != rows[j].SubjectName {
			return rows[i].SubjectName < rows[j].SubjectName
		}
		return rows[i].Binding < rows[j].Binding
	})
	return rows
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

// extractEvidenceString is the one-shot form of decodeEvidence + evidenceString for callers
// that only need one field and don't care to keep the decoded map around. Returns "" on
// any miss (malformed JSON, missing key, non-string value) so callers can use the result
// as a "render this when non-empty" gate.
func extractEvidenceString(raw json.RawMessage, key string) string {
	return evidenceString(decodeEvidence(raw), key)
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

// verbRenderOpts controls optional sizing and explanatory copy for renderVerbsGroupedOpts.
// The zero value reproduces the original uncapped, footnote-less rendering.
type verbRenderOpts struct {
	// ResourceCapPerVerb truncates each chip to its first N resources with a
	// "+M more resources" tail. 0 means unlimited.
	ResourceCapPerVerb int
	// FootNote renders once below the chip list when at least one chip was capped.
	FootNote string
}

// renderVerbsGrouped is the unoptioned form: every resource shown, no footnote. Used by
// formatVerbList (UNUSED-VERB / UNUSED-RULE) and by the Used side of WILDCARD-USED-PARTIAL.
func renderVerbsGrouped(items []verbResource) template.HTML {
	return renderVerbsGroupedOpts(items, verbRenderOpts{})
}

// renderVerbsGroupedOpts groups (verb, resource) pairs by verb into one bordered chip per
// verb. Single-resource verbs render inline ("list: pods") so the common case stays on one
// line; verbs with 2+ resources stack each resource on its own block-level line beneath
// the label so a wildcard-expanded list does not force the cell to scroll horizontally.
// opts.ResourceCapPerVerb caps each chip with a "+M more resources" tail; opts.FootNote,
// if set, is rendered once under the chip list when any chip got capped. Caps at 8 verbs
// total with a "+N more verbs" overflow; empty input returns the "none" placeholder.
func renderVerbsGroupedOpts(items []verbResource, opts verbRenderOpts) template.HTML {
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
	anyCapped := false
	for i := 0; i < limit; i++ {
		verb := order[i]
		resources := dedupeStrings(byVerb[verb])
		sort.Strings(resources)
		b.WriteString(`<li><code class="lp-verb-chip"><span class="lp-verb-label">`)
		b.WriteString(template.HTMLEscapeString(verb))
		b.WriteString(`:</span>`)
		if len(resources) == 1 {
			b.WriteString(` `)
			b.WriteString(template.HTMLEscapeString(resources[0]))
		} else {
			show := len(resources)
			if opts.ResourceCapPerVerb > 0 && show > opts.ResourceCapPerVerb {
				show = opts.ResourceCapPerVerb
			}
			for j := 0; j < show; j++ {
				b.WriteString(`<span class="lp-verb-resource">`)
				b.WriteString(template.HTMLEscapeString(resources[j]))
				b.WriteString(`</span>`)
			}
			if show < len(resources) {
				fmt.Fprintf(&b, `<span class="lp-verb-resource-more">+%d more resources</span>`, len(resources)-show)
				anyCapped = true
			}
		}
		b.WriteString(`</code></li>`)
	}
	b.WriteString(`</ul>`)
	if len(order) > limit {
		fmt.Fprintf(&b, `<div class="lp-verb-more">+%d more verbs</div>`, len(order)-limit)
	}
	if anyCapped && opts.FootNote != "" {
		b.WriteString(`<div class="lp-verb-foot-note">`)
		b.WriteString(template.HTMLEscapeString(opts.FootNote))
		b.WriteString(`</div>`)
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

// buildPerSubjectCapabilities composes one SubjectCapabilityCard per RBAC subject
// (STRATEGY.md:32, plan slot W1 #7). The card answers "what can this principal
// actually do AND where does it lead": aggregated EffectiveRules from
// permissions.Aggregate (collapsed by resource for readability), the bindings the
// subject is granted via, and any privesc paths the analyzer detected as
// originating from this subject. ChainAmplified mirrors the engine's chain-modifier
// signal so the template can surface a badge for subjects whose grants compose
// into an exploitable path.
//
// Filter: we only emit a card for subjects that appear in at least one finding OR
// hold a "cluster-admin equivalent" grant (cluster-scoped wildcard verb, or direct
// binding to the built-in cluster-admin ClusterRole). This keeps the section
// focused on the principals an operator should review without flooding the tab
// with every default ServiceAccount in every namespace.
func buildPerSubjectCapabilities(snapshot models.Snapshot, findings []models.Finding) []SubjectCapabilityCard {
	if len(snapshot.Resources.RoleBindings)+len(snapshot.Resources.ClusterRoleBindings) == 0 {
		return nil
	}
	effective := permissions.Aggregate(snapshot)
	if len(effective) == 0 {
		return nil
	}

	// Index findings by subject key so each card carries only the findings about
	// its own principal. Build the privesc summary + highest severity in the same
	// pass — both views are derived from the same finding slice.
	type subjectIndex struct {
		highest   models.Severity
		hasFind   bool
		privescs  []string
		amplified bool
	}
	idx := map[string]*subjectIndex{}
	for _, f := range findings {
		if f.Subject == nil {
			continue
		}
		key := f.Subject.Key()
		entry := idx[key]
		if entry == nil {
			entry = &subjectIndex{}
			idx[key] = entry
		}
		entry.hasFind = true
		if f.Severity.Rank() > entry.highest.Rank() {
			entry.highest = f.Severity
		}
		if strings.HasPrefix(f.RuleID, "KUBE-PRIVESC-PATH-") {
			entry.privescs = append(entry.privescs, summarizePrivescPath(f))
			entry.amplified = true
		}
		for _, tag := range f.Tags {
			if tag == "chain:amplified" {
				entry.amplified = true
				break
			}
		}
	}

	// Build the per-subject binding list once so each card can pull from it. The
	// permissions package already gave us source bindings via EffectiveRule, but
	// re-walking bindings here lets us include bindings whose Role has no rules
	// (still visible to operators as "bound to <Role>") and preserves the
	// distinction between RoleBinding and ClusterRoleBinding.
	bindingsBySubject := map[string][]string{}
	for _, rb := range snapshot.Resources.RoleBindings {
		for _, s := range rb.Subjects {
			ref := permissions.SubjectRef(s, rb.Namespace)
			label := fmt.Sprintf("RoleBinding/%s/%s -> %s/%s", rb.Namespace, rb.Name, rb.RoleRef.Kind, rb.RoleRef.Name)
			bindingsBySubject[ref.Key()] = append(bindingsBySubject[ref.Key()], label)
		}
	}
	for _, crb := range snapshot.Resources.ClusterRoleBindings {
		for _, s := range crb.Subjects {
			ref := permissions.SubjectRef(s, "")
			label := fmt.Sprintf("ClusterRoleBinding/%s -> %s/%s", crb.Name, crb.RoleRef.Kind, crb.RoleRef.Name)
			bindingsBySubject[ref.Key()] = append(bindingsBySubject[ref.Key()], label)
		}
	}

	cards := make([]SubjectCapabilityCard, 0, len(effective))
	for key, perms := range effective {
		entry := idx[key]
		hasFinding := entry != nil && entry.hasFind
		hasClusterAdmin := subjectHoldsClusterAdmin(perms, bindingsBySubject[key])
		if !hasFinding && !hasClusterAdmin {
			continue
		}

		card := SubjectCapabilityCard{
			SubjectKind:  perms.Subject.Kind,
			SubjectName:  perms.Subject.Name,
			SubjectNs:    perms.Subject.Namespace,
			SubjectLabel: subjectGroupLabel(&perms.Subject),
		}
		card.EffectiveVerbs, card.EffectiveRules = collapseEffectiveRules(perms.Rules)
		card.Bindings = dedupeStrings(bindingsBySubject[key])
		sort.Strings(card.Bindings)
		if entry != nil {
			card.PrivescPaths = entry.privescs
			card.ChainAmplified = entry.amplified
			card.HighestSeverity = entry.highest
		}
		cards = append(cards, card)
	}

	// Cards with privesc paths first (they're the actionable ones), then by
	// highest severity, then by subject label for stable output.
	sort.SliceStable(cards, func(i, j int) bool {
		if cards[i].ChainAmplified != cards[j].ChainAmplified {
			return cards[i].ChainAmplified
		}
		if cards[i].HighestSeverity.Rank() != cards[j].HighestSeverity.Rank() {
			return cards[i].HighestSeverity.Rank() > cards[j].HighestSeverity.Rank()
		}
		return cards[i].SubjectLabel < cards[j].SubjectLabel
	})

	return cards
}

// summarizePrivescPath turns a KUBE-PRIVESC-PATH-* finding into the one-line chain
// summary shown on the card. Falls back to a sink-only summary when EscalationPath
// is empty (the privesc analyzer sometimes emits paths with no hop slice for
// degenerate sink edges); the sink label is always derivable from the RuleID.
func summarizePrivescPath(f models.Finding) string {
	hops := len(f.EscalationPath)
	sink := strings.TrimPrefix(f.RuleID, "KUBE-PRIVESC-PATH-")
	sink = strings.ToLower(strings.ReplaceAll(sink, "-", "_"))
	suffix := fmt.Sprintf("%s (%s, %d %s)", sink, f.Severity, hops, pluralizeHops(hops))
	if hops == 0 {
		return suffix
	}
	first := f.EscalationPath[0]
	last := f.EscalationPath[hops-1]
	// Some sinks ("kube_system_secrets", "node_escape") are synthetic and the
	// privesc analyzer leaves their ToSubject Kind/Name empty. Falling back to
	// the rule's sink slug keeps the chain summary readable in those cases.
	toLabel := subjectGroupLabel(&last.ToSubject)
	if last.ToSubject.Kind == "" && last.ToSubject.Name == "" {
		toLabel = sink
	}
	return fmt.Sprintf("%s -> %s via %s -> %s",
		subjectGroupLabel(&first.FromSubject),
		toLabel,
		first.Action,
		suffix,
	)
}

// pluralizeHops returns "hop" or "hops" based on count.
func pluralizeHops(n int) string {
	if n == 1 {
		return "hop"
	}
	return "hops"
}

// collapseEffectiveRules turns the granular permissions.EffectiveRule list into
// (uniqueVerbs, perResourceRows). Each row reads "verb,verb,... on resource@apiGroup"
// so the card stays scannable: operators want to know "this SA can delete pods" not
// "this SA has 13 separate rules". Wildcards stay verbatim ("*") so the threat is
// obvious. Empty inputs yield nil for both, keeping the template gates honest.
func collapseEffectiveRules(rules []permissions.EffectiveRule) ([]string, []string) {
	if len(rules) == 0 {
		return nil, nil
	}
	type bucket struct {
		apiGroup string
		resource string
		verbs    map[string]struct{}
	}
	buckets := map[string]*bucket{}
	order := []string{}
	verbsAll := map[string]struct{}{}
	for _, r := range rules {
		for _, ag := range zeroOrSelf(r.APIGroups) {
			for _, res := range zeroOrSelf(r.Resources) {
				key := ag + "|" + res
				b, ok := buckets[key]
				if !ok {
					b = &bucket{apiGroup: ag, resource: res, verbs: map[string]struct{}{}}
					buckets[key] = b
					order = append(order, key)
				}
				for _, v := range r.Verbs {
					b.verbs[v] = struct{}{}
					verbsAll[v] = struct{}{}
				}
			}
		}
	}

	verbs := make([]string, 0, len(verbsAll))
	for v := range verbsAll {
		verbs = append(verbs, v)
	}
	sort.Strings(verbs)

	rows := make([]string, 0, len(order))
	for _, k := range order {
		b := buckets[k]
		verbList := make([]string, 0, len(b.verbs))
		for v := range b.verbs {
			verbList = append(verbList, v)
		}
		sort.Strings(verbList)
		ag := b.apiGroup
		if ag == "" {
			ag = "core"
		}
		rows = append(rows, fmt.Sprintf("%s on %s@%s", strings.Join(verbList, ","), b.resource, ag))
	}
	sort.Strings(rows)
	return verbs, rows
}

// zeroOrSelf returns a single empty-string slice when the input is empty so the
// "core" apiGroup or untyped resource still produces one bucket. Otherwise it
// returns the input verbatim.
func zeroOrSelf(in []string) []string {
	if len(in) == 0 {
		return []string{""}
	}
	return in
}

// subjectHoldsClusterAdmin returns true when the subject either holds a wildcard
// grant (`*` verbs on `*` resources in `*` apiGroups) or is directly bound to the
// built-in cluster-admin ClusterRole. Either case means "this principal is one
// kubectl command from total cluster control"; we surface the card unconditionally
// so the operator sees it. The bindings slice is pre-computed in
// buildPerSubjectCapabilities to avoid a second walk.
func subjectHoldsClusterAdmin(perms *permissions.EffectivePermissions, bindings []string) bool {
	for _, b := range bindings {
		if strings.Contains(b, "ClusterRole/cluster-admin") {
			return true
		}
	}
	for _, r := range perms.Rules {
		if hasWildcard(r.Verbs) && hasWildcard(r.Resources) && hasWildcardOrEmpty(r.APIGroups) {
			return true
		}
	}
	return false
}

// hasWildcard returns true when the slice contains "*".
func hasWildcard(in []string) bool {
	for _, s := range in {
		if s == "*" {
			return true
		}
	}
	return false
}

// hasWildcardOrEmpty returns true when the slice is empty (some RBAC authors treat
// `apiGroups: []` as "all") or contains "*".
func hasWildcardOrEmpty(in []string) bool {
	if len(in) == 0 {
		return true
	}
	return hasWildcard(in)
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
