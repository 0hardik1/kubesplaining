// Package report - "Top 5 fixes" panel builder. Groups findings by the principal or
// resource that owns them, sums per-group scores, and ranks the resulting buckets so
// the operator sees the single highest-leverage cleanup at the top of the report.
// One ServiceAccount with overbroad RBAC plus a privesc path will typically dominate
// the cluster's risk index; collapsing those rows into a single "delete this binding"
// recommendation turns the report from a 200-row triage list into a five-step plan.
package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// maxTopFixes caps the panel at the highest-leverage five buckets so the hero
// section stays scannable. Keeping it as a package-level constant lets the test
// file pin the cap without re-deriving it.
const maxTopFixes = 5

// buildTopFixes groups findings by Subject (or, when Subject is nil, by Resource)
// and surfaces the five buckets whose collective score would drop most if the
// underlying object were removed or pared back. The ranking key is the sum of
// per-finding scores within a bucket: a single ServiceAccount carrying eight
// medium findings plus one critical privesc path beats a single critical finding
// elsewhere because deleting that one binding clears all nine rows at once.
//
// The returned slice carries pre-rendered presentation fields (Rank, Action,
// FindingsCount, ScoreImpact, Subjects, RuleIDs). The template consumes these
// directly; no further formatting happens at render time. Returns nil when no
// findings have a Subject or Resource (so the {{ if .TopFixes }} template gate
// keeps the section absent for empty inputs).
func buildTopFixes(findings []models.Finding) []TopFix {
	if len(findings) == 0 {
		return nil
	}

	// bucket aggregates the findings that share an owning Subject (preferred) or
	// Resource (fallback). targetKind / targetLabel drive the suggested action
	// string; subjects retains the original display key so the row can list it
	// even when grouping fell back to Resource.
	type bucket struct {
		key         string
		targetKind  string // "Subject" | "Resource"
		targetLabel string // pre-rendered "Kind/[ns/]name" string
		subjectRef  *models.SubjectRef
		resourceRef *models.ResourceRef
		score       float64
		ruleIDs     []string
		ruleSeen    map[string]bool
		subjects    []string
		subjSeen    map[string]bool
		order       int // first-seen index, used as a stable tiebreaker
	}

	buckets := make(map[string]*bucket)
	order := 0
	for _, f := range findings {
		var key, kind, label string
		var subjRef *models.SubjectRef
		var resRef *models.ResourceRef
		switch {
		case f.Subject != nil:
			label = subjectDisplay(f.Subject)
			if label == "" || label == "-" {
				// subjectDisplay returns "-" only when Subject is nil; this branch
				// guards the Kind="" Name="" degenerate case that some hand-built
				// fixtures expose.
				if f.Resource != nil {
					label = resourceDisplay(f.Resource)
					kind = "Resource"
					resRef = f.Resource
				} else {
					continue
				}
			} else {
				kind = "Subject"
				subjRef = f.Subject
			}
			key = kind + "::" + label
		case f.Resource != nil:
			label = resourceDisplay(f.Resource)
			if label == "" || label == "-" {
				continue
			}
			kind = "Resource"
			resRef = f.Resource
			key = kind + "::" + label
		default:
			// No owner to fix: a cluster-wide observation (e.g. missing admission
			// policy engine) belongs in the cluster-level section rather than a
			// per-target top-fix row, so we skip it.
			continue
		}

		b, ok := buckets[key]
		if !ok {
			b = &bucket{
				key:         key,
				targetKind:  kind,
				targetLabel: label,
				subjectRef:  subjRef,
				resourceRef: resRef,
				ruleSeen:    map[string]bool{},
				subjSeen:    map[string]bool{},
				order:       order,
			}
			buckets[key] = b
			order++
		}
		b.score += f.Score
		if f.RuleID != "" && !b.ruleSeen[f.RuleID] {
			b.ruleSeen[f.RuleID] = true
			b.ruleIDs = append(b.ruleIDs, f.RuleID)
		}
		// Track the subject display even when grouping is by Resource so the
		// rendered row can disambiguate "Resource Deployment/api" with the
		// affected principal when one exists.
		if f.Subject != nil {
			subjLabel := subjectDisplay(f.Subject)
			if subjLabel != "" && subjLabel != "-" && !b.subjSeen[subjLabel] {
				b.subjSeen[subjLabel] = true
				b.subjects = append(b.subjects, subjLabel)
			}
		}
	}

	if len(buckets) == 0 {
		return nil
	}

	ranked := make([]*bucket, 0, len(buckets))
	for _, b := range buckets {
		ranked = append(ranked, b)
	}
	// Sort by total score desc, then count desc, then first-seen order so the
	// rendering stays deterministic across runs against the same snapshot.
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].score != ranked[j].score {
			return ranked[i].score > ranked[j].score
		}
		if len(ranked[i].ruleIDs) != len(ranked[j].ruleIDs) {
			return len(ranked[i].ruleIDs) > len(ranked[j].ruleIDs)
		}
		return ranked[i].order < ranked[j].order
	})
	if len(ranked) > maxTopFixes {
		ranked = ranked[:maxTopFixes]
	}

	out := make([]TopFix, 0, len(ranked))
	for i, b := range ranked {
		// Keep the per-row rule list stable so two runs produce byte-identical
		// HTML: sort the deduped slice alphabetically before emitting.
		sort.Strings(b.ruleIDs)
		sort.Strings(b.subjects)
		out = append(out, TopFix{
			Rank:          i + 1,
			Action:        suggestedFixAction(b.targetKind, b.targetLabel, b.subjectRef, b.resourceRef, b.ruleIDs),
			ScoreImpact:   b.score,
			FindingsCount: len(b.ruleIDs),
			Subjects:      append([]string(nil), b.subjects...),
			RuleIDs:       append([]string(nil), b.ruleIDs...),
		})
	}
	return out
}

// suggestedFixAction renders a one-line "what to do" string for a TopFix row.
// The wording matches the kind of object the operator actually edits: a binding
// is deleted, an overbroad Role gets its wildcard verb pared back, a workload's
// hostPath volume is removed. The rule-prefix hints below cover the common
// dominant-rule cases; everything else falls back to a generic "review" so the
// row is still actionable.
func suggestedFixAction(targetKind, targetLabel string, subj *models.SubjectRef, res *models.ResourceRef, ruleIDs []string) string {
	dominant := dominantRulePrefix(ruleIDs)

	switch targetKind {
	case "Subject":
		// Subject is the most common owner: an over-privileged ServiceAccount or
		// a User/Group bound to cluster-admin. The dominant-prefix branches
		// surface the specific binding-level edit; the default is generic.
		who := subjectFriendly(subj, targetLabel)
		switch dominant {
		case "KUBE-PRIVESC-PATH":
			return fmt.Sprintf("Sever privilege-escalation paths from %s by dropping the offending RoleBinding or pruning the bound Role's verbs", who)
		case "KUBE-PRIVESC":
			return fmt.Sprintf("Drop the dangerous RBAC verbs (impersonate / bind / escalate / token-create / pod-exec) granted to %s", who)
		case "KUBE-RBAC-OVERBROAD":
			return fmt.Sprintf("Pare back the overbroad Role bound to %s by replacing `*` verbs / resources with an explicit allowlist", who)
		case "KUBE-RBAC-STALE":
			return fmt.Sprintf("Delete the stale (Cluster)RoleBindings granting %s, the principal or referenced role no longer exists", who)
		case "KUBE-SA-DEFAULT":
			return fmt.Sprintf("Set `automountServiceAccountToken: false` on workloads still using %s, or replace it with a least-privileged ServiceAccount", who)
		case "KUBE-SA-PRIVILEGED":
			return fmt.Sprintf("Remove cluster-admin (or equivalent) bindings from %s and grant the minimum verbs the workload actually uses", who)
		case "KUBE-LP-UNUSED", "KUBE-LP-WILDCARD-USED-PARTIAL":
			return fmt.Sprintf("Apply the Least Privilege tab's suggested Role for %s (drop unused verbs / resources observed via audit)", who)
		}
		return fmt.Sprintf("Review every (Cluster)RoleBinding targeting %s and trim it to the minimum verbs the workload requires", who)

	case "Resource":
		// Resource is the fallback owner: typically a workload (Deployment,
		// Pod, DaemonSet) that triggers pod-security findings even though no
		// RBAC subject is attached.
		what := resourceFriendly(res, targetLabel)
		switch dominant {
		case "KUBE-PODSEC-ROOT":
			return fmt.Sprintf("Drop `securityContext.runAsRoot` / `privileged: true` from %s and pin a non-root UID", what)
		case "KUBE-PODSEC-APE":
			return fmt.Sprintf("Set `allowPrivilegeEscalation: false` and drop dangerous capabilities on every container in %s", what)
		case "KUBE-PODSEC-READONLY":
			return fmt.Sprintf("Set `readOnlyRootFilesystem: true` on every container in %s and mount writable paths explicitly via emptyDir or PV", what)
		case "KUBE-PODSEC-SECCOMP":
			return fmt.Sprintf("Apply `seccompProfile: { type: RuntimeDefault }` to every container in %s to block uncommon syscalls", what)
		case "KUBE-HOSTPATH":
			return fmt.Sprintf("Remove the hostPath volume mount from %s and replace it with a PersistentVolume or emptyDir", what)
		case "KUBE-IMAGE-LATEST":
			return fmt.Sprintf("Replace the `:latest` image tag in %s with a pinned digest (e.g. `image@sha256:...`)", what)
		case "KUBE-CONTAINERD-SOCKET":
			return fmt.Sprintf("Unmount the container-runtime socket from %s; it is functionally equivalent to root on the node", what)
		case "KUBE-ESCAPE":
			return fmt.Sprintf("Tighten the Pod Security context on %s to deny host namespaces, hostPath, and privileged containers", what)
		case "KUBE-NETPOL-COVERAGE":
			return fmt.Sprintf("Add a default-deny NetworkPolicy to %s and explicitly allow only the ingress / egress flows the workloads need", what)
		case "KUBE-NETPOL-WEAKNESS":
			return fmt.Sprintf("Tighten %s by replacing wildcard selectors and `0.0.0.0/0` egress with narrow pod / namespace selectors", what)
		case "KUBE-SECRETS":
			return fmt.Sprintf("Rotate and narrow the Secret referenced by %s, restricting the consuming workloads via RBAC and pod-level mounts", what)
		case "KUBE-CONFIGMAP":
			return fmt.Sprintf("Move credential-shaped keys out of the ConfigMap referenced by %s into a Secret with tight RBAC", what)
		case "KUBE-ADMISSION":
			return fmt.Sprintf("Replace `failurePolicy: Ignore` on the admission webhook attached to %s with `Fail`, or scope it down via namespaceSelector", what)
		}
		return fmt.Sprintf("Review %s and apply the per-finding remediation steps listed under the matching rule cards", what)
	}
	return fmt.Sprintf("Review %s and apply the per-finding remediation steps", targetLabel)
}

// dominantRulePrefix returns the most frequent "KUBE-AREA" stem across the
// supplied rule IDs. Ties prefer the longest (most specific) prefix, then the
// alphabetically-first prefix, so two runs produce identical wording. A single
// KUBE-PRIVESC-PATH-CLUSTER-ADMIN finding alongside a KUBE-PRIVESC-005 finding
// resolves to KUBE-PRIVESC-PATH (length: 17) rather than the more generic
// KUBE-PRIVESC (length: 12). Returns an empty string when no rule IDs follow
// the KUBE-AREA- naming convention.
func dominantRulePrefix(ruleIDs []string) string {
	if len(ruleIDs) == 0 {
		return ""
	}
	counts := map[string]int{}
	for _, id := range ruleIDs {
		prefix := rulePrefix(id)
		if prefix == "" {
			continue
		}
		counts[prefix]++
	}
	if len(counts) == 0 {
		return ""
	}
	best := ""
	bestCount := -1
	for prefix, n := range counts {
		switch {
		case n > bestCount:
			best, bestCount = prefix, n
		case n == bestCount && len(prefix) > len(best):
			best = prefix
		case n == bestCount && len(prefix) == len(best) && prefix < best:
			best = prefix
		}
	}
	return best
}

// rulePrefix extracts the "KUBE-<AREA>" stem from a rule ID. For privesc graph
// rules the area is the multi-segment "PRIVESC-PATH" since the suffix is the
// sink name, not a number; that's why the helper looks at the third dash too.
// Returns an empty string when the input does not follow the convention.
func rulePrefix(ruleID string) string {
	parts := strings.Split(ruleID, "-")
	if len(parts) < 3 {
		return ""
	}
	// KUBE-PRIVESC-PATH-CLUSTER-ADMIN → keep "KUBE-PRIVESC-PATH" so the topfix
	// suggestion can distinguish graph paths from the static KUBE-PRIVESC-001
	// style rules.
	if len(parts) >= 4 && parts[0] == "KUBE" && parts[1] == "PRIVESC" && parts[2] == "PATH" {
		return "KUBE-PRIVESC-PATH"
	}
	// KUBE-LP-UNUSED-VERB-001 → "KUBE-LP-UNUSED"; KUBE-LP-WILDCARD-USED-PARTIAL-001 → "KUBE-LP-WILDCARD-USED-PARTIAL".
	if len(parts) >= 4 && parts[0] == "KUBE" && parts[1] == "LP" {
		// Strip the trailing numeric component if present so suffixes group together.
		stem := parts[:len(parts)-1]
		if !isNumericSegment(parts[len(parts)-1]) {
			stem = parts
		}
		return strings.Join(stem, "-")
	}
	// Fallback: keep KUBE-AREA without the trailing numeric / sub-numeric suffix.
	// Multi-segment areas like KUBE-PODSEC-APE-001 collapse to "KUBE-PODSEC-APE".
	stem := parts[:len(parts)-1]
	if !isNumericSegment(parts[len(parts)-1]) {
		stem = parts
	}
	return strings.Join(stem, "-")
}

// isNumericSegment reports whether a rule-ID segment is a pure numeric tail
// (e.g. "001"). Used by rulePrefix to know whether the trailing segment is the
// rule's instance counter or part of its area.
func isNumericSegment(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// subjectFriendly returns a slightly humanized label for a Subject. The bare
// "Kind/[ns/]name" string is fine for code spans but the topfix action reads
// better when the kind is spelled out as "ServiceAccount default/builder"
// rather than "ServiceAccount/default/builder".
func subjectFriendly(subj *models.SubjectRef, fallback string) string {
	if subj == nil {
		return fallback
	}
	name := subj.Name
	if name == "" {
		name = fallback
	}
	if subj.Namespace != "" {
		return fmt.Sprintf("%s `%s/%s`", subj.Kind, subj.Namespace, name)
	}
	return fmt.Sprintf("%s `%s`", subj.Kind, name)
}

// resourceFriendly mirrors subjectFriendly for ResourceRef.
func resourceFriendly(res *models.ResourceRef, fallback string) string {
	if res == nil {
		return fallback
	}
	name := res.Name
	if name == "" {
		name = fallback
	}
	if res.Namespace != "" {
		return fmt.Sprintf("%s `%s/%s`", res.Kind, res.Namespace, name)
	}
	return fmt.Sprintf("%s `%s`", res.Kind, name)
}
