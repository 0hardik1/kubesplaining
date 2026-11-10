// Package report renders scanner output in the formats users consume: a human-friendly HTML dashboard,
// machine-readable findings JSON, a triage CSV, and SARIF for IDE/CI tooling. It is a pure render step
// and does not mutate findings.
package report

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// Write emits the requested formats (html, json, csv, sarif) to outputDir along with the snapshot metadata side-file.
// It always writes metadata.json; unsupported format names return an error without partial cleanup.
func Write(outputDir string, formats []string, snapshot models.Snapshot, findings []models.Finding) ([]string, error) {
	return WriteWithAdmission(outputDir, formats, snapshot, findings, models.AdmissionSummary{}, models.TruncationInfo{})
}

// WriteWithAdmission is Write plus an AdmissionSummary that is rendered into the HTML
// header banner, written as a sidecar admission-summary.json alongside the metadata file
// (so `kubesplaining report` can re-render the banner without re-running analysis), and
// embedded in the SARIF run properties for downstream CI consumers.
//
// The TruncationInfo argument carries the --max-findings cap state. When
// truncation.Truncated is true, a banner is rendered in the HTML report, the info
// is embedded in the SARIF run properties, and a truncation-info.json sidecar is
// written so `kubesplaining report` can re-render the banner without re-running
// analysis. When false (the zero value), nothing is rendered.
func WriteWithAdmission(outputDir string, formats []string, snapshot models.Snapshot, findings []models.Finding, admission models.AdmissionSummary, truncation models.TruncationInfo) ([]string, error) {
	return WriteWithOptions(outputDir, formats, snapshot, findings, admission, truncation, Options{})
}

// WriteWithOptions extends WriteWithAdmission with Options that control which HTML tab
// loads by default (used by --least-privilege-only) and the audit-log window summary
// rendered into the Least Privilege tab header.
//
// When opts.HTMLFindings is set, findings is the complete list and the cap in
// truncation applies to the HTML report only: findings.json, the CSV, and the
// SARIF file carry every finding, and report.html lists opts.HTMLFindings. A
// program that reads the machine outputs then never works from a sample. See
// SelectForHTML for how the HTML subset is chosen.
func WriteWithOptions(outputDir string, formats []string, snapshot models.Snapshot, findings []models.Finding, admission models.AdmissionSummary, truncation models.TruncationInfo, opts Options) ([]string, error) {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return nil, fmt.Errorf("create output directory: %w", err)
	}

	written := make([]string, 0, len(formats))
	metadataPath, err := WriteMetadata(outputDir, snapshot.Metadata)
	if err != nil {
		return written, err
	}
	written = append(written, metadataPath)

	if admission.Mode != "" {
		admissionPath, err := WriteAdmissionSummary(outputDir, admission)
		if err != nil {
			return written, err
		}
		written = append(written, admissionPath)
	}

	if truncation.Truncated {
		truncPath, err := WriteTruncationInfo(outputDir, truncation)
		if err != nil {
			return written, err
		}
		written = append(written, truncPath)
	} else if err := removeStaleTruncationInfo(outputDir); err != nil {
		return written, err
	}

	for _, format := range dedupeFormats(formats) {
		switch format {
		case "json":
			path := filepath.Join(outputDir, "findings.json")
			if err := writeJSON(path, findings); err != nil {
				return written, err
			}
			written = append(written, path)
		case "html":
			path := filepath.Join(outputDir, "report.html")
			listed := findings
			if opts.HTMLFindings != nil {
				listed = opts.HTMLFindings
			}
			if err := writeHTMLWithOptions(path, snapshot, listed, admission, truncation, opts); err != nil {
				return written, err
			}
			written = append(written, path)
		case "csv":
			path := filepath.Join(outputDir, "triage.csv")
			if err := writeCSV(path, findings); err != nil {
				return written, err
			}
			written = append(written, path)
		case "sarif":
			path := filepath.Join(outputDir, "findings.sarif")
			// A cap that shortened only the HTML report leaves the SARIF file
			// complete, so it must not be described as truncated there.
			sarifTruncation := truncation
			if truncation.Scope == models.TruncationScopeHTML {
				sarifTruncation = models.TruncationInfo{}
			}
			if err := writeSARIF(path, findings, admission, sarifTruncation); err != nil {
				return written, err
			}
			written = append(written, path)
		default:
			return written, fmt.Errorf("unsupported output format %q", format)
		}
	}

	return written, nil
}

// IsAttackPath reports whether a finding is an attack path: a chain of hops
// from one identity to a sink such as cluster-admin, emitted by the privesc
// module under a KUBE-PRIVESC-PATH-* rule ID. These are the findings that the
// HTML Attack paths tab draws and that the terminal summary counts, and this
// function is the one definition both use, so the numbers always agree.
//
// A KUBE-CONFUSED-DEPUTY-001 finding also carries hops, but it is listed with
// the flat findings and is not drawn on the Attack paths tab, so it is not an
// attack path here.
func IsAttackPath(f models.Finding) bool {
	return strings.HasPrefix(f.RuleID, "KUBE-PRIVESC-PATH-")
}

// SelectForHTML picks the findings that report.html lists under the
// --max-findings cap: every attack path, plus the top `limit` of the other
// findings chosen with the same category-balanced draw as Truncate. The input
// order (the engine's severity, score, rule ID order) is kept.
//
// Attack paths are exempt from the cap for two reasons. They are the result
// that the other findings only hint at, and they rank below the flat findings
// that amplify them, so a plain top-N drops them first: on a dense cluster a
// top-20 draw holds no attack path at all. The report's tabs also link into
// each other (a path card opens its finding for the fix), so a path that is
// drawn must also be listed.
//
// The cap is for the HTML report only. Callers pass the complete list to the
// machine-readable writers; see WriteWithOptions. The returned info has
// Scope TruncationScopeHTML so a reader of truncation-info.json can tell that
// findings.json beside it is complete.
//
// When allFindings is true, limit <= 0, or the cap does not remove anything,
// the input is returned unchanged with a zero-value info.
func SelectForHTML(findings []models.Finding, limit int, allFindings bool) ([]models.Finding, models.TruncationInfo) {
	if allFindings || limit <= 0 {
		return findings, models.TruncationInfo{}
	}

	rest := make([]models.Finding, 0, len(findings))
	restPos := make([]int, 0, len(findings))
	keep := make([]bool, len(findings))
	paths := 0
	for i := range findings {
		if IsAttackPath(findings[i]) {
			keep[i] = true
			paths++
			continue
		}
		rest = append(rest, findings[i])
		restPos = append(restPos, i)
	}
	if len(rest) <= limit {
		return findings, models.TruncationInfo{}
	}

	for _, p := range diverseTopNPositions(rest, limit) {
		keep[restPos[p]] = true
	}
	listed := make([]models.Finding, 0, paths+limit)
	for i := range findings {
		if keep[i] {
			listed = append(listed, findings[i])
		}
	}
	return listed, models.TruncationInfo{
		Truncated:   true,
		Original:    len(findings),
		Shown:       len(listed),
		Limit:       limit,
		Scope:       models.TruncationScopeHTML,
		AttackPaths: paths,
	}
}

// Truncate caps an already-sorted findings slice to the top `limit` entries
// while preserving category diversity. The analyzer engine emits findings
// sorted by severity rank → score → ruleID; Truncate honors that order both
// as the input ranking signal and as the output ordering.
//
// When the cap fires, findings are grouped by RiskCategory (preserving each
// category's internal order) and selected round-robin, so a single dominant
// category (e.g. privilege_escalation in clusters with sprawling RBAC) cannot
// crowd out smaller categories like data_exfiltration or defense_evasion.
// The selection is then re-sorted by the same global priority comparator so
// the visible order is still severity-first — diversity affects which
// findings appear, not the order they appear in.
//
// When allFindings is true, limit <= 0, or len(findings) <= limit, the input
// is returned unchanged with a zero-value (Truncated=false) info — callers
// can use that as a "do nothing" gate without re-checking the flags. The
// underlying array is not mutated.
//
// `--max-findings=0` is treated as "no cap" rather than "show zero findings"
// so an absent or zero flag never produces an empty report directory.
func Truncate(findings []models.Finding, limit int, allFindings bool) ([]models.Finding, models.TruncationInfo) {
	if allFindings || limit <= 0 || len(findings) <= limit {
		return findings, models.TruncationInfo{}
	}
	return diverseTopN(findings, limit), models.TruncationInfo{
		Truncated: true,
		Original:  len(findings),
		Shown:     limit,
		Limit:     limit,
	}
}

// diverseTopN selects up to `limit` findings using a category-balanced
// round-robin draw, then re-sorts the selection by the global priority
// comparator (severity rank → score → ruleID → title). The input MUST
// already be sorted by that comparator: this preserves each category's
// internal priority and keeps the absolute top-1 finding in the output.
//
// Round-robin guarantees that every category present in the input appears in
// the output (subject to the cap), so a long tail of low-severity privesc
// findings cannot push out higher-severity-but-rarer findings from other
// categories. If only one category has findings, the function degenerates to
// a simple `findings[:limit]` slice.
func diverseTopN(findings []models.Finding, limit int) []models.Finding {
	if limit <= 0 || len(findings) <= limit {
		return findings
	}

	// With one category there is nothing to diversify across, and the input
	// is already in priority order: return the prefix untouched.
	oneCategory := true
	for i := range findings {
		if findings[i].Category != findings[0].Category {
			oneCategory = false
			break
		}
	}
	if oneCategory {
		return findings[:limit]
	}

	positions := diverseTopNPositions(findings, limit)
	result := make([]models.Finding, 0, len(positions))
	for _, p := range positions {
		result = append(result, findings[p])
	}

	sort.SliceStable(result, func(i, j int) bool {
		if result[i].Severity.Rank() != result[j].Severity.Rank() {
			return result[i].Severity.Rank() > result[j].Severity.Rank()
		}
		if result[i].Score != result[j].Score {
			return result[i].Score > result[j].Score
		}
		if result[i].RuleID != result[j].RuleID {
			return result[i].RuleID < result[j].RuleID
		}
		return result[i].Title < result[j].Title
	})

	return result
}

// diverseTopNPositions is the draw behind diverseTopN: it returns the
// positions in findings of the up-to-limit selection, in pick order. Callers
// that must keep the input order (SelectForHTML) use the positions as a set;
// diverseTopN re-sorts the picked findings by the global priority comparator.
func diverseTopNPositions(findings []models.Finding, limit int) []int {
	if limit <= 0 {
		return nil
	}
	if len(findings) <= limit {
		limit = len(findings)
	}

	// Group positions by category. order tracks first-seen category order so
	// the highest-priority category (whose first finding is the global top-1)
	// gets the first round-robin pick, which keeps the absolute top finding in
	// the selection.
	groups := make(map[models.RiskCategory][]int)
	var order []models.RiskCategory
	for i := range findings {
		cat := findings[i].Category
		if _, ok := groups[cat]; !ok {
			order = append(order, cat)
		}
		groups[cat] = append(groups[cat], i)
	}

	result := make([]int, 0, limit)
	if len(order) <= 1 {
		// Nothing to diversify across.
		for i := 0; i < limit; i++ {
			result = append(result, i)
		}
		return result
	}

	indices := make(map[models.RiskCategory]int, len(order))
	for len(result) < limit {
		progress := false
		for _, cat := range order {
			i := indices[cat]
			if i >= len(groups[cat]) {
				continue
			}
			result = append(result, groups[cat][i])
			indices[cat] = i + 1
			progress = true
			if len(result) == limit {
				break
			}
		}
		if !progress {
			break
		}
	}
	return result
}

// dedupeFormats lower-cases, trims, and deduplicates the requested format list; an empty input defaults to html+json.
func dedupeFormats(formats []string) []string {
	if len(formats) == 0 {
		return []string{"html", "json"}
	}

	seen := map[string]struct{}{}
	result := make([]string, 0, len(formats))
	for _, format := range formats {
		format = strings.ToLower(strings.TrimSpace(format))
		if format == "" {
			continue
		}
		if _, ok := seen[format]; ok {
			continue
		}
		seen[format] = struct{}{}
		result = append(result, format)
	}

	sort.Strings(result)
	return result
}
