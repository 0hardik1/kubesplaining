// Package report: builder for the "Attack paths" HTML tab.
//
// The privesc graph the engine computes already emits one KUBE-PRIVESC-PATH-*
// finding per (source subject, sink) pair, each carrying the full ordered hop
// chain on Finding.EscalationPath. This tab groups every path by the target it
// reaches, sorted worst-first, and gives each target one graph (attack_paths.go)
// plus a list of its paths. The Summary tab's "What an attacker can reach" table
// reads the same groups. The sink-priority and label helpers (heroSinkSlug /
// heroSinkLabel / heroSinkPriority / heroChainSummary) live in narratives.go.
package report

import (
	"sort"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// buildPrivescPaths assembles the Privilege-Escalation Paths tab from the
// KUBE-PRIVESC-PATH-* findings. Paths are bucketed by the sink they reach
// (cluster_admin, node_escape, ...); groups are ordered by sink danger then
// bucket size, and the cards within each group by severity then score then
// fewest hops, so the most dangerous, most direct chain to each sink surfaces
// first. Returns a zero-value section (empty Groups) when no privesc paths
// exist; the template gates the tab on len(.PrivescPaths.Groups) > 0.
func buildPrivescPaths(findings []models.Finding) PrivescPathsSection {
	sinks, total := groupPathsBySink(findings)
	if total == 0 {
		return PrivescPathsSection{}
	}

	paths := make([]models.Finding, 0, total)
	groups := make([]PrivescSinkGroup, 0, len(sinks))
	for _, sp := range sinks {
		sink, group := sp.Slug, sp.Findings
		paths = append(paths, group...)

		cards := make([]PrivescPathCard, 0, len(group))
		for i, f := range group {
			terminal, terminalFull := pathTerminal(sink, f)
			cards = append(cards, PrivescPathCard{
				Index:        i,
				Steps:        buildPathSteps(f.EscalationPath),
				Terminal:     terminal,
				TerminalFull: terminalFull,
				Source:       subjectDisplay(f.Subject),
				SinkLabel:    heroSinkLabel(sink),
				Severity:     f.Severity,
				SevClass:     severityClass(f.Severity),
				Score:        f.Score,
				HopCount:     len(f.EscalationPath),
				Summary:      heroChainSummary(f, sink),
				Hops:         f.EscalationPath,
				AltHops:      f.AlternateEscalationPath,
				RuleID:       f.RuleID,
				Anchor:       "finding-" + f.RuleID,
			})
		}

		// Cards are sorted worst-first, so the first card's class is the group's
		// worst severity — drives the group header stripe without a second pass.
		sevClass := "info"
		if len(cards) > 0 {
			sevClass = cards[0].SevClass
		}
		groups = append(groups, PrivescSinkGroup{
			SinkSlug:  sink,
			SinkLabel: heroSinkLabel(sink),
			SinkTitle: sinkTitle(sink),
			Blurb:     sinkBlurb(sink),
			SevClass:  sevClass,
			Count:     len(group),
			Summary:   BuildSummary(group),
			Cards:     cards,
			Graph:     buildSinkGraph(sink, sinkTitle(sink), group),
		})
	}

	return PrivescPathsSection{
		Total:   len(paths),
		Summary: BuildSummary(paths),
		Groups:  groups,
	}
}

// sinkPaths is the set of attack-path findings that end at one sink.
type sinkPaths struct {
	Slug     string
	Findings []models.Finding
}

// groupPathsBySink buckets the attack-path findings (see IsAttackPath) by the sink they
// reach and returns the buckets in display order, plus the number of paths.
// Inside a bucket the order is severity, then score, then fewest hops, so the
// first finding is the most dangerous, most direct chain to that sink. Buckets
// are ordered by sink danger, then size, then label. The HTML Attack paths tab
// and the terminal summary both read this, so they always agree.
func groupPathsBySink(findings []models.Finding) ([]sinkPaths, int) {
	bySink := map[string][]models.Finding{}
	sinkOrder := make([]string, 0)
	total := 0
	for _, f := range findings {
		if !IsAttackPath(f) {
			continue
		}
		total++
		sink := heroSinkSlug(f)
		if _, ok := bySink[sink]; !ok {
			sinkOrder = append(sinkOrder, sink)
		}
		bySink[sink] = append(bySink[sink], f)
	}

	out := make([]sinkPaths, 0, len(sinkOrder))
	for _, sink := range sinkOrder {
		group := bySink[sink]
		sort.SliceStable(group, func(i, j int) bool {
			if ri, rj := group[i].Severity.Rank(), group[j].Severity.Rank(); ri != rj {
				return ri > rj
			}
			if group[i].Score != group[j].Score {
				return group[i].Score > group[j].Score
			}
			if hi, hj := len(group[i].EscalationPath), len(group[j].EscalationPath); hi != hj {
				return hi < hj
			}
			return group[i].ID < group[j].ID
		})
		out = append(out, sinkPaths{Slug: sink, Findings: group})
	}

	sort.SliceStable(out, func(i, j int) bool {
		if pi, pj := heroSinkPriority(out[i].Slug), heroSinkPriority(out[j].Slug); pi != pj {
			return pi < pj
		}
		if len(out[i].Findings) != len(out[j].Findings) {
			return len(out[i].Findings) > len(out[j].Findings)
		}
		return heroSinkLabel(out[i].Slug) < heroSinkLabel(out[j].Slug)
	})
	return out, total
}

// AttackPathOverview is one row of the terminal summary that `scan` prints:
// one sink, how many identities reach it, and the most direct chain to it.
type AttackPathOverview struct {
	// Sink is the short sink name, as on the report's target picker
	// ("cluster-admin", "Node root").
	Sink string
	// Paths is the number of attack paths that end at this sink.
	Paths int
	// Identities is the number of distinct identities those paths start from.
	Identities int
	// Source is the identity at the start of the most direct chain.
	Source string
	// Actions are the hop actions of that chain, in order.
	Actions []string
}

// AttackPathOverviews summarizes the attack paths in findings, one row per
// sink, in the same order as the HTML Attack paths tab. It returns nil when
// findings holds no attack path.
func AttackPathOverviews(findings []models.Finding) []AttackPathOverview {
	sinks, total := groupPathsBySink(findings)
	if total == 0 {
		return nil
	}
	out := make([]AttackPathOverview, 0, len(sinks))
	for _, sp := range sinks {
		identities := map[string]struct{}{}
		for _, f := range sp.Findings {
			if f.Subject != nil {
				identities[f.Subject.Key()] = struct{}{}
			}
		}
		best := sp.Findings[0]
		row := AttackPathOverview{
			Sink:       sinkTitle(sp.Slug),
			Paths:      len(sp.Findings),
			Identities: len(identities),
		}
		if best.Subject != nil {
			row.Source = best.Subject.Key()
		}
		for _, hop := range best.EscalationPath {
			row.Actions = append(row.Actions, hop.Action)
		}
		out = append(out, row)
	}
	return out
}
