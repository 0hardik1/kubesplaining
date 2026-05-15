// Package report — Compliance Coverage tab data assembly. Takes the already-decorated
// findings (compliance.Apply ran during analysis) and re-projects them into a
// ComplianceSection that groups by framework → control. Hidden by the template when there
// are no findings with any compliance tag, so the tab disappears for snapshots whose rules
// happen to lack a mapping rather than rendering an empty shell.
package report

import (
	"sort"

	"github.com/0hardik1/kubesplaining/internal/compliance"
	"github.com/0hardik1/kubesplaining/internal/models"
)

// buildComplianceSection projects findings into per-framework / per-control rollups for
// the Compliance Coverage tab. Each (framework, control) pair carries the deduped
// findings that map to it; one finding mapped to multiple controls appears once per
// matching control. UnmappedCount counts findings with zero compliance tags so the tab
// can surface "N findings are not yet mapped" honestly.
func buildComplianceSection(findings []models.Finding) ComplianceSection {
	section := ComplianceSection{}
	if len(findings) == 0 {
		return section
	}

	// Per-framework state: ordered control list, per-control finding accumulator, and a
	// dedup set on Finding.ID so a single finding does not double-count under the same
	// control when analyzers happen to emit similar tags.
	type ctrlAcc struct {
		row     ComplianceControlRow
		seen    map[string]struct{}
		members []models.Finding
	}
	type frameAcc struct {
		view     ComplianceFrameworkView
		controls map[string]*ctrlAcc
		seen     map[string]struct{}
	}

	frames := map[string]*frameAcc{}

	// Seed framework metadata so the controls table is keyed consistently with the
	// registered slugs (and so the slug → display name lookup is one place).
	registered := compliance.Frameworks()
	for _, info := range registered {
		frames[info.Slug] = &frameAcc{
			view: ComplianceFrameworkView{
				Slug:      info.Slug,
				Name:      info.Name,
				ShortName: info.ShortName,
				URL:       info.URL,
				CSSKey:    complianceFrameworkCSSKey(info.Slug),
			},
			controls: map[string]*ctrlAcc{},
			seen:     map[string]struct{}{},
		}
	}

	unmapped := 0
	tagged := 0
	for _, f := range findings {
		if len(f.Frameworks) == 0 {
			unmapped++
			continue
		}
		tagged++
		for _, ref := range f.Frameworks {
			frame, ok := frames[ref.Framework]
			if !ok {
				// An unknown framework slug — register a passthrough frame using the
				// ref itself so consumers do not silently drop the entry. This keeps the
				// table honest if someone hand-edits a finding's Frameworks.
				frame = &frameAcc{
					view: ComplianceFrameworkView{
						Slug:      ref.Framework,
						Name:      ref.Framework,
						ShortName: ref.Framework,
						URL:       ref.URL,
					},
					controls: map[string]*ctrlAcc{},
					seen:     map[string]struct{}{},
				}
				frames[ref.Framework] = frame
			}
			if _, seen := frame.seen[f.ID]; !seen {
				frame.seen[f.ID] = struct{}{}
				frame.view.Summary = sumAddSeverity(frame.view.Summary, f.Severity)
			}
			ctrl, ok := frame.controls[ref.Control]
			if !ok {
				ctrl = &ctrlAcc{
					row: ComplianceControlRow{
						Control: ref.Control,
						Title:   ref.Title,
						URL:     ref.URL,
					},
					seen: map[string]struct{}{},
				}
				frame.controls[ref.Control] = ctrl
			}
			if _, dup := ctrl.seen[f.ID]; dup {
				continue
			}
			ctrl.seen[f.ID] = struct{}{}
			ctrl.members = append(ctrl.members, f)
			ctrl.row.Summary = sumAddSeverity(ctrl.row.Summary, f.Severity)
		}
	}

	section.Total = tagged
	section.UnmappedCount = unmapped

	// Render frames in the canonical display order (CIS first, NSA second, then any
	// passthrough frames sorted alphabetically). Empty frames are omitted so the tab does
	// not list a framework with zero control hits.
	orderedSlugs := make([]string, 0, len(frames))
	for _, info := range registered {
		orderedSlugs = append(orderedSlugs, info.Slug)
	}
	extras := []string{}
	for slug := range frames {
		known := false
		for _, info := range registered {
			if info.Slug == slug {
				known = true
				break
			}
		}
		if !known {
			extras = append(extras, slug)
		}
	}
	sort.Strings(extras)
	orderedSlugs = append(orderedSlugs, extras...)

	for _, slug := range orderedSlugs {
		frame := frames[slug]
		if frame == nil || len(frame.controls) == 0 {
			continue
		}
		// Sort controls within a framework by severity weight then count then control ID
		// so the operator sees "what's worst" at the top.
		rows := make([]ComplianceControlRow, 0, len(frame.controls))
		for _, ctrl := range frame.controls {
			// Sort findings inside the control by severity then score then rule ID.
			sort.SliceStable(ctrl.members, func(i, j int) bool {
				a, b := ctrl.members[i], ctrl.members[j]
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
			ctrl.row.Findings = ctrl.members
			// TopSeverity is the highest severity among the finalized members; precomputed
			// here rather than re-derived from Summary in the template.
			top := models.SeverityInfo
			for _, m := range ctrl.members {
				if m.Severity.Rank() > top.Rank() {
					top = m.Severity
				}
			}
			ctrl.row.TopSeverity = top
			rows = append(rows, ctrl.row)
		}
		sort.SliceStable(rows, func(i, j int) bool {
			return compareSummaries(rows[i].Summary, rows[j].Summary, rows[i].Control, rows[j].Control)
		})
		frame.view.Controls = rows
		section.Frameworks = append(section.Frameworks, frame.view)
	}

	return section
}

// complianceFrameworkCSSKey returns the short CSS-class suffix used by the Compliance tab
// template to apply framework-specific accent colors. Unknown slugs map to "other" so a
// hand-added framework still renders with a neutral palette.
func complianceFrameworkCSSKey(slug string) string {
	switch slug {
	case compliance.FrameworkCIS19:
		return "cis"
	case compliance.FrameworkNSA:
		return "nsa"
	default:
		return "other"
	}
}

// sumAddSeverity bumps the right severity counter on a Summary. Used inline so we don't
// re-walk a per-control finding slice twice.
func sumAddSeverity(s Summary, sev models.Severity) Summary {
	s.Total++
	switch sev {
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
	return s
}
