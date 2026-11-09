package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/0hardik1/kubesplaining/internal/compliance"
	"github.com/0hardik1/kubesplaining/internal/exclusions"
	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/report"
	"github.com/0hardik1/kubesplaining/internal/scoring"
	"github.com/spf13/cobra"
)

// NewReportCmd returns the "report" subcommand, which regenerates HTML/JSON/CSV/SARIF
// artifacts from a previously produced findings JSON file without re-running analysis.
func NewReportCmd() *cobra.Command {
	var (
		inputFile          string
		outputDir          string
		outputFormats      []string
		severityThreshold  string
		exclusionsFile     string
		exclusionsPreset   string
		metadataFile       string
		maxFindings        int
		allFindings        bool
		complianceFilters  []string
		remediationPatches bool
	)

	cmd := &cobra.Command{
		Use:   "report",
		Short: "Regenerate reports from a findings JSON file",
		RunE: func(cmd *cobra.Command, args []string) error {
			if inputFile == "" {
				return fmt.Errorf("--input-file is required")
			}

			threshold, err := models.ParseSeverity(severityThreshold)
			if err != nil {
				return err
			}

			findings, err := report.ReadFindings(inputFile)
			if err != nil {
				return err
			}

			// Mirror the engine: structured remediation hints are opt-in. An
			// input JSON produced with --remediation-patches will carry them;
			// strip on regen when the operator did not pass the flag here so
			// the regenerated HTML/SARIF/JSON match what scan would emit at
			// the same flag setting.
			if !remediationPatches {
				for i := range findings {
					findings[i].RemediationHint = nil
				}
			}

			filtered := make([]models.Finding, 0, len(findings))
			for _, finding := range findings {
				if scoring.AboveThreshold(finding, threshold) {
					filtered = append(filtered, finding)
				}
			}

			cfg, err := loadExclusions(exclusionsPreset, exclusionsFile)
			if err != nil {
				return err
			}
			filtered, _ = exclusions.Apply(cfg, filtered)

			// Re-apply the compliance mapping in case the input JSON pre-dates the
			// Frameworks field (older scans). compliance.Apply is idempotent so
			// re-running on already-tagged findings is a no-op.
			filtered = compliance.Apply(filtered)
			complianceSlugs, err := parseComplianceFilter(complianceFilters)
			if err != nil {
				return err
			}
			filtered = applyComplianceFilter(filtered, complianceSlugs)

			// As in scan: the cap shortens report.html only, and the other
			// formats get every finding that passed the filters above.
			listed, truncation := report.SelectForHTML(filtered, maxFindings, allFindings)

			snapshot := models.NewSnapshot()
			snapshot.Metadata.ClusterName = "report-regeneration"
			metadataPath := metadataFile
			if metadataPath == "" {
				guessed := report.GuessMetadataPath(inputFile)
				if _, err := os.Stat(guessed); err == nil {
					metadataPath = guessed
				}
			}
			if metadataPath != "" {
				metadata, err := report.ReadMetadata(metadataPath)
				if err != nil {
					return err
				}
				snapshot.Metadata = metadata
			}

			if outputDir == "" {
				outputDir = filepath.Join(".", "kubesplaining-report")
			}

			admissionSummary := models.AdmissionSummary{}
			if path := report.GuessAdmissionSummaryPath(inputFile); path != "" {
				if _, err := os.Stat(path); err == nil {
					admissionSummary, err = report.ReadAdmissionSummary(path)
					if err != nil {
						return err
					}
				}
			}

			warnIfSampledFindings(cmd.ErrOrStderr(), inputFile)

			written, err := report.WriteWithOptions(outputDir, outputFormats, snapshot, filtered, admissionSummary, truncation, report.Options{HTMLFindings: listed})
			if err != nil {
				return err
			}

			summary := report.BuildSummary(filtered)
			if err := printScanResults(cmd.OutOrStdout(), written, summary, report.AttackPathOverviews(filtered)); err != nil {
				return err
			}
			printTruncationNotice(cmd.ErrOrStderr(), truncation)

			return nil
		},
	}

	cmd.Flags().StringVar(&inputFile, "input-file", "", "Path to a findings JSON file")
	cmd.Flags().StringVar(&outputDir, "output-dir", filepath.Join(".", "kubesplaining-report"), "Directory for regenerated report output")
	cmd.Flags().StringSliceVar(&outputFormats, "output-format", []string{"html", "json"}, "Output formats: html,json,csv,sarif")
	cmd.Flags().StringVar(&severityThreshold, "severity-threshold", "low", "Minimum severity to include: critical,high,medium,low,info")
	cmd.Flags().StringVar(&exclusionsFile, "exclusions-file", "", "Path to a user-supplied exclusions YAML file (merged on top of --exclusions-preset)")
	cmd.Flags().StringVar(&exclusionsPreset, "exclusions-preset", "standard", "Built-in exclusions preset: standard|minimal|strict|none")
	cmd.Flags().StringVar(&metadataFile, "metadata-file", "", "Optional path to scan metadata JSON")
	cmd.Flags().IntVar(&maxFindings, "max-findings", 0, "Shorten the regenerated report.html: list every attack path plus the top N of the other findings by severity/score. 0, the default, lists every finding. JSON, CSV, and SARIF output always get every finding.")
	cmd.Flags().BoolVar(&allFindings, "all-findings", false, "List every finding in the regenerated report.html. This is the default; the flag overrides --max-findings and stays for scripts that pass it.")
	cmd.Flags().StringSliceVar(&complianceFilters, "compliance", nil, "Filter findings to those mapped to one or more frameworks (repeatable / comma-separated). Supported: cis, nsa.")
	cmd.Flags().BoolVar(&remediationPatches, "remediation-patches", false, "Preserve structured remediation hints in the regenerated report. Off by default; pass the flag when regenerating a scan that was run with --remediation-patches.")

	return cmd
}
