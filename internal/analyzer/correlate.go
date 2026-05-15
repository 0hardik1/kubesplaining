package analyzer

import (
	"fmt"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/scoring"
)

// leastPrivilegeAdvisoryPrefixes lists rule-ID prefixes that emit *recommendations*, not
// exploitable findings. The correlate pass must not bump these via chain amplification -
// boosting a "consider narrowing this Role" recommendation because the same SA appears
// in a privesc path would distort the priority ordering operators rely on.
var leastPrivilegeAdvisoryPrefixes = []string{
	"KUBE-RBAC-UNUSED-",
	"KUBE-RBAC-WILDCARD-USED-PARTIAL-",
}

// isLeastPrivilegeAdvisory reports whether ruleID names an advisory (recommendation)
// finding that should bypass the chain-amplification bump.
func isLeastPrivilegeAdvisory(ruleID string) bool {
	for _, p := range leastPrivilegeAdvisoryPrefixes {
		if strings.HasPrefix(ruleID, p) {
			return true
		}
	}
	return false
}

// correlate applies chain-modifier bumps to non-privesc findings whose Subject appears as a source in a privilege-escalation path.
// It picks the highest-severity sink reachable from the subject and adds scoring.ChainModifier(sinkSev) to the finding's Score,
// clamped to [0, 10]. A "chain:amplified" tag is added so report consumers can explain the bump.
func correlate(findings []models.Finding) []models.Finding {
	best := map[string]models.Severity{} // subject key → highest-severity sink reachable
	for _, finding := range findings {
		if len(finding.EscalationPath) == 0 || finding.Subject == nil {
			continue
		}
		key := finding.Subject.Key()
		if finding.Severity.Rank() > best[key].Rank() {
			best[key] = finding.Severity
		}
	}
	if len(best) == 0 {
		return findings
	}

	for i := range findings {
		if len(findings[i].EscalationPath) > 0 {
			continue // privesc findings already reflect chain length in their own scoring
		}
		if findings[i].Subject == nil {
			continue
		}
		if isLeastPrivilegeAdvisory(findings[i].RuleID) {
			continue // advisory recommendations skip the amplification bump
		}
		bump := scoring.ChainModifier(best[findings[i].Subject.Key()])
		if bump == 0 {
			continue
		}
		findings[i].Score = scoring.Clamp(findings[i].Score + bump)
		findings[i].Tags = append(findings[i].Tags, "chain:amplified")
	}
	return findings
}

// dedupe collapses findings that describe the same (RuleID, Subject, Resource) combination across modules,
// keeping the one with the highest Score and merging tags. Within-module ID collisions are already handled by analyzers.
func dedupe(findings []models.Finding) []models.Finding {
	// indexByKey maps each dedupe key to the index in `out` where its winning finding lives.
	// We keep an index (rather than a *models.Finding) because the slice may grow and
	// reallocate as we append, invalidating any stored pointer.
	indexByKey := map[string]int{}
	out := make([]models.Finding, 0, len(findings))
	for _, finding := range findings {
		key := dedupeKey(finding)
		if key == "" {
			out = append(out, finding)
			continue
		}
		if prevIdx, ok := indexByKey[key]; ok {
			if finding.Score > out[prevIdx].Score {
				out[prevIdx].Score = finding.Score
				out[prevIdx].Severity = finding.Severity
			}
			out[prevIdx].Tags = mergeTags(out[prevIdx].Tags, finding.Tags)
			continue
		}
		indexByKey[key] = len(out)
		out = append(out, finding)
	}
	return out
}

// dedupeKey returns the cross-module dedup key, or empty when the finding lacks enough context to merge safely.
func dedupeKey(f models.Finding) string {
	if f.Subject == nil && f.Resource == nil {
		return ""
	}
	var subjKey, resKey string
	if f.Subject != nil {
		subjKey = f.Subject.Key()
	}
	if f.Resource != nil {
		resKey = f.Resource.Key()
	}
	return fmt.Sprintf("%s|%s|%s", f.RuleID, subjKey, resKey)
}

// mergeTags unions two tag slices in order, dropping duplicates.
func mergeTags(a, b []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(a)+len(b))
	for _, tag := range a {
		if _, ok := seen[tag]; ok {
			continue
		}
		seen[tag] = struct{}{}
		out = append(out, tag)
	}
	for _, tag := range b {
		if _, ok := seen[tag]; ok {
			continue
		}
		seen[tag] = struct{}{}
		out = append(out, tag)
	}
	return out
}
