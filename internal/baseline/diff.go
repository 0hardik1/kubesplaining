package baseline

import (
	"sort"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// Result is the classification of two findings slices into three disjoint
// buckets keyed on Finding.ID. Resolved findings carry the OLD finding
// (so the caller can render its title/severity); Unchanged carries the NEW
// finding (so the caller sees the freshest data when re-rendering).
type Result struct {
	Added     []models.Finding
	Resolved  []models.Finding
	Unchanged []models.Finding
}

// Diff partitions old and new findings into Added (in new, not in old),
// Resolved (in old, not in new), and Unchanged (in both, keyed by ID).
//
// The result's three slices are sorted by (Severity rank desc, Score desc,
// RuleID asc, ID asc) so the output order is deterministic across runs
// regardless of input ordering. This matches the report writer's global
// priority comparator and keeps `diff` output stable for diff-of-diffs
// use cases (e.g. PR comments that get re-rendered on every push).
//
// When both slices are nil/empty the result is the zero value; when they
// are identical (same ID set) Added and Resolved are both empty and
// Unchanged carries every NEW finding.
func Diff(oldFindings, newFindings []models.Finding) Result {
	oldByID := indexByID(oldFindings)
	newByID := indexByID(newFindings)

	var result Result

	for _, f := range newFindings {
		if _, present := oldByID[f.ID]; present {
			result.Unchanged = append(result.Unchanged, f)
		} else {
			result.Added = append(result.Added, f)
		}
	}

	for _, f := range oldFindings {
		if _, present := newByID[f.ID]; !present {
			result.Resolved = append(result.Resolved, f)
		}
	}

	sortFindings(result.Added)
	sortFindings(result.Resolved)
	sortFindings(result.Unchanged)

	return result
}

// indexByID returns a presence-only map keyed on Finding.ID. We don't
// need the value side for diff classification, only set membership.
func indexByID(findings []models.Finding) map[string]struct{} {
	out := make(map[string]struct{}, len(findings))
	for _, f := range findings {
		out[f.ID] = struct{}{}
	}
	return out
}

// sortFindings mirrors the global priority comparator used by the report
// writer (severity rank desc, score desc, RuleID asc, ID asc). The final
// ID tiebreaker makes the order fully deterministic even when two findings
// share a rule and a score.
func sortFindings(findings []models.Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		return a.ID < b.ID
	})
}

// Summary is a small severity-tally view over a Result, used by the text
// and markdown writers to compose the one-line headline. It mirrors the
// shape of report.Summary so the rendered counts read the same in both
// surfaces (and so a future migration to report.Summary stays mechanical).
type Summary struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
	Total    int
}

// SummarizeSeverities counts findings by severity bucket.
func SummarizeSeverities(findings []models.Finding) Summary {
	s := Summary{Total: len(findings)}
	for _, f := range findings {
		switch f.Severity {
		case models.SeverityCritical:
			s.Critical++
		case models.SeverityHigh:
			s.High++
		case models.SeverityMedium:
			s.Medium++
		case models.SeverityLow:
			s.Low++
		default:
			s.Info++
		}
	}
	return s
}

// CountNewPrivescPaths returns the number of Added findings that look like
// privilege-escalation graph paths (RuleID prefix "KUBE-PRIVESC-PATH-").
// These get highlighted in the text/markdown summary because a new
// privesc path is the highest-signal regression a diff can surface.
func CountNewPrivescPaths(added []models.Finding) int {
	const prefix = "KUBE-PRIVESC-PATH-"
	n := 0
	for _, f := range added {
		if len(f.RuleID) >= len(prefix) && f.RuleID[:len(prefix)] == prefix {
			n++
		}
	}
	return n
}
