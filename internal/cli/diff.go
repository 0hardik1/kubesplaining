package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/baseline"
	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/spf13/cobra"
)

// NewDiffCmd returns the "diff" subcommand, which compares two findings JSON
// files emitted by `scan` (or anything that produces the same shape) and
// prints / writes a delta report classifying each finding as Added,
// Resolved, or Unchanged. The diff is keyed on Finding.ID, which the
// analyzer pipeline guarantees is deterministic across runs of the same
// cluster ("RULE:ns:name").
//
// Output formats:
//
//	text     : default; summary headline + per-section bullet list
//	markdown : same content as text but with ## headings and tables
//	sarif    : SARIF 2.1.0 run containing only Added findings, with
//	           level=warning and a properties.delta marker so downstream
//	           tooling can distinguish a delta upload from a full scan
//
// When --output-dir is set the rendered diff is written to <dir>/diff.{txt,md,sarif}
// instead of stdout. The diff command never re-runs analysis; it only
// reads the two JSON files it's pointed at.
func NewDiffCmd() *cobra.Command {
	var (
		outputFormat string
		outputDir    string
	)

	cmd := &cobra.Command{
		Use:   "diff <old.json> <new.json>",
		Short: "Compare two findings JSON files and emit a delta report",
		Long: "diff classifies findings as Added, Resolved, or Unchanged keyed on the deterministic Finding.ID. " +
			"Use it in CI to surface only the findings that appeared since a baseline scan, or locally to see what changed between two snapshots.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, err := parseDiffFormat(outputFormat)
			if err != nil {
				return err
			}

			oldFindings, err := baseline.LoadFindings(args[0])
			if err != nil {
				return fmt.Errorf("read old findings %s: %w", args[0], err)
			}
			newFindings, err := baseline.LoadFindings(args[1])
			if err != nil {
				return fmt.Errorf("read new findings %s: %w", args[1], err)
			}

			result := baseline.Diff(oldFindings, newFindings)

			if outputDir != "" {
				path, err := writeDiff(outputDir, format, result)
				if err != nil {
					return err
				}
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", path)
				return err
			}

			return renderDiff(cmd.OutOrStdout(), format, result)
		},
	}

	cmd.Flags().StringVar(&outputFormat, "output-format", "text", "Output format: text|markdown|sarif")
	cmd.Flags().StringVar(&outputDir, "output-dir", "", "Optional directory to write diff.{txt,md,sarif} into; stdout when unset")

	return cmd
}

// diffFormat is the parsed --output-format value. Text and markdown share most
// of their rendering pipeline (diffSummaryLine + bullet/table sections); sarif
// is a distinct JSON document.
type diffFormat string

const (
	diffFormatText     diffFormat = "text"
	diffFormatMarkdown diffFormat = "markdown"
	diffFormatSARIF    diffFormat = "sarif"
)

// parseDiffFormat normalizes and validates the --output-format flag.
func parseDiffFormat(value string) (diffFormat, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "text", "txt":
		return diffFormatText, nil
	case "markdown", "md":
		return diffFormatMarkdown, nil
	case "sarif":
		return diffFormatSARIF, nil
	default:
		return "", fmt.Errorf("invalid --output-format %q (must be text, markdown, or sarif)", value)
	}
}

// renderDiff writes the rendered output for format into w. The file-writing
// path (writeDiff) reuses the same renderer so both code paths produce
// identical bytes.
func renderDiff(w io.Writer, format diffFormat, result baseline.Result) error {
	switch format {
	case diffFormatText:
		return renderDiffText(w, result)
	case diffFormatMarkdown:
		return renderDiffMarkdown(w, result)
	case diffFormatSARIF:
		return renderDiffSARIF(w, result)
	default:
		return fmt.Errorf("unsupported diff format %q", format)
	}
}

// writeDiff creates outputDir if needed and writes diff.{txt,md,sarif} into it.
// Returns the absolute path of the written file so the caller can print it.
func writeDiff(outputDir string, format diffFormat, result baseline.Result) (string, error) {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return "", fmt.Errorf("create diff output directory: %w", err)
	}

	var filename string
	switch format {
	case diffFormatText:
		filename = "diff.txt"
	case diffFormatMarkdown:
		filename = "diff.md"
	case diffFormatSARIF:
		filename = "diff.sarif"
	default:
		return "", fmt.Errorf("unsupported diff format %q", format)
	}

	path := filepath.Join(outputDir, filename)
	file, err := os.Create(path)
	if err != nil {
		return "", fmt.Errorf("create diff file: %w", err)
	}
	defer func() { _ = file.Close() }()

	if err := renderDiff(file, format, result); err != nil {
		return "", err
	}
	return path, nil
}

// diffHeadline builds the single-line headline used by both text and markdown
// renderers. It surfaces the four numbers a CI reviewer cares about first:
// new criticals, total resolved, and any new privesc paths (the latter is
// the highest-signal regression this tool can flag).
func diffHeadline(result baseline.Result) string {
	added := baseline.SummarizeSeverities(result.Added)
	resolved := baseline.SummarizeSeverities(result.Resolved)
	newPaths := baseline.CountNewPrivescPaths(result.Added)

	var parts []string
	if added.Critical > 0 {
		parts = append(parts, fmt.Sprintf("%d new critical %s", added.Critical, pluralFindings(added.Critical)))
	}
	if added.High > 0 {
		parts = append(parts, fmt.Sprintf("%d new high %s", added.High, pluralFindings(added.High)))
	}
	if added.Total-added.Critical-added.High > 0 {
		other := added.Total - added.Critical - added.High
		parts = append(parts, fmt.Sprintf("%d other new %s", other, pluralFindings(other)))
	}
	if resolved.Total > 0 {
		parts = append(parts, fmt.Sprintf("%d resolved", resolved.Total))
	}
	if newPaths > 0 {
		parts = append(parts, fmt.Sprintf("%d new privesc %s", newPaths, pluralPath(newPaths)))
	}

	if len(parts) == 0 {
		return "no changes since baseline"
	}
	return strings.Join(parts, ", ")
}

// pluralFindings returns "finding" or "findings" depending on n.
func pluralFindings(n int) string {
	if n == 1 {
		return "finding"
	}
	return "findings"
}

// pluralPath returns "path" or "paths" depending on n.
func pluralPath(n int) string {
	if n == 1 {
		return "path"
	}
	return "paths"
}

// renderDiffText writes a plain-text delta report: a one-line headline,
// counts row, then per-section bullet lists with one bullet per finding.
// Designed to read well on a terminal and inside a wrapped GitHub Action
// log line.
func renderDiffText(w io.Writer, result baseline.Result) error {
	added := baseline.SummarizeSeverities(result.Added)
	resolved := baseline.SummarizeSeverities(result.Resolved)
	unchanged := baseline.SummarizeSeverities(result.Unchanged)

	if _, err := fmt.Fprintf(w, "diff: %s\n", diffHeadline(result)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "counts: added=%d resolved=%d unchanged=%d\n", added.Total, resolved.Total, unchanged.Total); err != nil {
		return err
	}

	if err := writeBulletSection(w, "Added", result.Added); err != nil {
		return err
	}
	if err := writeBulletSection(w, "Resolved", result.Resolved); err != nil {
		return err
	}
	return nil
}

// writeBulletSection writes a "Added (n):" / "Resolved (n):" heading and
// a bullet per finding. Empty sections still render their header so readers
// can confirm "zero resolved" rather than "section missing".
func writeBulletSection(w io.Writer, label string, findings []models.Finding) error {
	if _, err := fmt.Fprintf(w, "\n%s (%d):\n", label, len(findings)); err != nil {
		return err
	}
	if len(findings) == 0 {
		_, err := fmt.Fprintln(w, "  (none)")
		return err
	}
	for _, f := range findings {
		if _, err := fmt.Fprintf(w, "  - [%s] %s :: %s%s\n",
			f.Severity, f.RuleID, f.Title, subjectSuffix(f)); err != nil {
			return err
		}
	}
	return nil
}

// subjectSuffix returns a human-readable " (subject Kind/ns/name)" suffix
// when the finding has a Subject or Resource, or "" otherwise.
func subjectSuffix(f models.Finding) string {
	switch {
	case f.Subject != nil:
		return " (subject " + f.Subject.Key() + ")"
	case f.Resource != nil:
		return " (resource " + f.Resource.Key() + ")"
	default:
		return ""
	}
}

// renderDiffMarkdown writes a Markdown delta report. Sections use ## headings,
// findings inside a section render as a pipe-separated table so the GitHub
// Action's "Job summary" view tabulates them. The headline doubles as a
// blockquote for visual emphasis.
func renderDiffMarkdown(w io.Writer, result baseline.Result) error {
	added := baseline.SummarizeSeverities(result.Added)
	resolved := baseline.SummarizeSeverities(result.Resolved)
	unchanged := baseline.SummarizeSeverities(result.Unchanged)

	if _, err := fmt.Fprintf(w, "# kubesplaining diff\n\n> %s\n\n", diffHeadline(result)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "| | count |\n|---|---:|\n| Added | %d |\n| Resolved | %d |\n| Unchanged | %d |\n\n",
		added.Total, resolved.Total, unchanged.Total); err != nil {
		return err
	}

	if err := writeMarkdownSection(w, "Added", result.Added); err != nil {
		return err
	}
	if err := writeMarkdownSection(w, "Resolved", result.Resolved); err != nil {
		return err
	}
	return nil
}

// writeMarkdownSection writes a "## Added (n)" / "## Resolved (n)" heading
// and either an empty-state line or a 4-column table. Severity column
// values are wrapped in backticks so they retain their bucketed look in
// a Markdown renderer that strips ANSI styling.
func writeMarkdownSection(w io.Writer, label string, findings []models.Finding) error {
	if _, err := fmt.Fprintf(w, "## %s (%d)\n\n", label, len(findings)); err != nil {
		return err
	}
	if len(findings) == 0 {
		_, err := fmt.Fprintln(w, "_None._")
		_, _ = fmt.Fprintln(w)
		return err
	}
	if _, err := fmt.Fprintln(w, "| Severity | Rule | Subject/Resource | Title |"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "|---|---|---|---|"); err != nil {
		return err
	}
	for _, f := range findings {
		subject := "-"
		if f.Subject != nil {
			subject = f.Subject.Key()
		} else if f.Resource != nil {
			subject = f.Resource.Key()
		}
		if _, err := fmt.Fprintf(w, "| `%s` | `%s` | `%s` | %s |\n",
			f.Severity, f.RuleID, subject, escapePipe(f.Title)); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintln(w)
	return err
}

// escapePipe replaces literal `|` characters with `\|` so finding titles
// containing pipes do not break the Markdown table column count.
func escapePipe(s string) string {
	return strings.ReplaceAll(s, "|", `\|`)
}

// diffSARIFReport is the subset of SARIF 2.1.0 the diff command emits.
// We intentionally do not re-use the report package's sarifReport types
// to keep the diff command's surface independent of report internals;
// the schema fields are small enough that duplication beats coupling.
type diffSARIFReport struct {
	Schema  string         `json:"$schema"`
	Version string         `json:"version"`
	Runs    []diffSARIFRun `json:"runs"`
}

type diffSARIFRun struct {
	Tool       diffSARIFTool     `json:"tool"`
	Results    []diffSARIFResult `json:"results"`
	Properties map[string]any    `json:"properties,omitempty"`
}

type diffSARIFTool struct {
	Driver diffSARIFDriver `json:"driver"`
}

type diffSARIFDriver struct {
	Name           string          `json:"name"`
	InformationURI string          `json:"informationUri,omitempty"`
	Rules          []diffSARIFRule `json:"rules,omitempty"`
}

type diffSARIFRule struct {
	ID               string                   `json:"id"`
	Name             string                   `json:"name,omitempty"`
	ShortDescription diffSARIFTextDescription `json:"shortDescription,omitempty"`
}

type diffSARIFTextDescription struct {
	Text string `json:"text"`
}

type diffSARIFResult struct {
	RuleID     string                   `json:"ruleId"`
	Level      string                   `json:"level"`
	Message    diffSARIFTextDescription `json:"message"`
	Kind       string                   `json:"kind,omitempty"`
	Properties map[string]any           `json:"properties,omitempty"`
}

// renderDiffSARIF writes a SARIF 2.1.0 document whose results are exactly
// the Added findings (Resolved and Unchanged are intentionally omitted:
// SARIF is consumed as "new issues" by GitHub code-scanning, so loading
// resolved-finding entries would produce stale alerts).
//
// Every result is emitted at level=warning regardless of the underlying
// severity. The rationale: a delta upload should not duplicate the full
// scan's error-level results in code-scanning, but it still needs to be
// visible. Consumers that care about the original severity can read it
// from properties.severity.
//
// Each result and the enclosing run get a `properties.delta: true`
// marker so downstream tooling can distinguish a diff upload from a
// full scan.
func renderDiffSARIF(w io.Writer, result baseline.Result) error {
	rules := buildDiffSARIFRules(result.Added)
	results := buildDiffSARIFResults(result.Added)

	doc := diffSARIFReport{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []diffSARIFRun{
			{
				Tool: diffSARIFTool{
					Driver: diffSARIFDriver{
						Name:           "kubesplaining-diff",
						InformationURI: "https://github.com/0hardik1/kubesplaining",
						Rules:          rules,
					},
				},
				Results: results,
				Properties: map[string]any{
					"delta":           true,
					"added_count":     len(result.Added),
					"resolved_count":  len(result.Resolved),
					"unchanged_count": len(result.Unchanged),
				},
			},
		},
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(doc); err != nil {
		return fmt.Errorf("encode diff sarif: %w", err)
	}
	return nil
}

// buildDiffSARIFRules projects unique RuleIDs from findings into rule
// metadata entries, deduplicated by ID and emitted in ID-ascending order
// so the SARIF document is byte-stable across runs.
func buildDiffSARIFRules(findings []models.Finding) []diffSARIFRule {
	seen := make(map[string]models.Finding)
	for _, f := range findings {
		if _, ok := seen[f.RuleID]; !ok {
			seen[f.RuleID] = f
		}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	out := make([]diffSARIFRule, 0, len(ids))
	for _, id := range ids {
		f := seen[id]
		out = append(out, diffSARIFRule{
			ID:               id,
			Name:             f.Title,
			ShortDescription: diffSARIFTextDescription{Text: f.Description},
		})
	}
	return out
}

// buildDiffSARIFResults converts each Added finding into a SARIF result.
// Level is fixed at "warning" (see renderDiffSARIF docstring).
func buildDiffSARIFResults(findings []models.Finding) []diffSARIFResult {
	out := make([]diffSARIFResult, 0, len(findings))
	for _, f := range findings {
		props := map[string]any{
			"delta":    true,
			"severity": f.Severity,
			"score":    f.Score,
			"category": f.Category,
		}
		if f.Namespace != "" {
			props["namespace"] = f.Namespace
		}
		if f.Subject != nil {
			props["subject"] = f.Subject
		}
		if f.Resource != nil {
			props["resource"] = f.Resource
		}
		out = append(out, diffSARIFResult{
			RuleID:     f.RuleID,
			Level:      "warning",
			Kind:       "fail",
			Message:    diffSARIFTextDescription{Text: f.Title + ": " + f.Description},
			Properties: props,
		})
	}
	return out
}
