package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// ReadFindings decodes a findings.json file written by Write into a slice of models.Finding.
func ReadFindings(path string) ([]models.Finding, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open findings file: %w", err)
	}
	defer func() { _ = file.Close() }()

	var findings []models.Finding
	if err := json.NewDecoder(file).Decode(&findings); err != nil {
		return nil, fmt.Errorf("decode findings file: %w", err)
	}

	return findings, nil
}

// WriteMetadata writes scan-metadata.json alongside the findings so future `report` invocations can reconstruct snapshot context.
func WriteMetadata(outputDir string, metadata models.SnapshotMetadata) (string, error) {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return "", fmt.Errorf("create metadata directory: %w", err)
	}

	path := filepath.Join(outputDir, "scan-metadata.json")
	file, err := os.Create(path)
	if err != nil {
		return "", fmt.Errorf("create metadata file: %w", err)
	}
	defer func() { _ = file.Close() }()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(metadata); err != nil {
		return "", fmt.Errorf("encode metadata file: %w", err)
	}

	return path, nil
}

// ReadMetadata decodes a scan-metadata.json file back into a SnapshotMetadata value.
func ReadMetadata(path string) (models.SnapshotMetadata, error) {
	file, err := os.Open(path)
	if err != nil {
		return models.SnapshotMetadata{}, fmt.Errorf("open metadata file: %w", err)
	}
	defer func() { _ = file.Close() }()

	var metadata models.SnapshotMetadata
	if err := json.NewDecoder(file).Decode(&metadata); err != nil {
		return models.SnapshotMetadata{}, fmt.Errorf("decode metadata file: %w", err)
	}

	return metadata, nil
}

// GuessMetadataPath returns the default scan-metadata.json location for a findings file in the same directory.
func GuessMetadataPath(findingsPath string) string {
	return filepath.Join(filepath.Dir(findingsPath), "scan-metadata.json")
}

// WriteAdmissionSummary writes admission-summary.json alongside scan-metadata.json so the
// `kubesplaining report` subcommand can re-render the HTML banner without re-running analysis.
func WriteAdmissionSummary(outputDir string, summary models.AdmissionSummary) (string, error) {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return "", fmt.Errorf("create admission summary directory: %w", err)
	}

	path := filepath.Join(outputDir, "admission-summary.json")
	file, err := os.Create(path)
	if err != nil {
		return "", fmt.Errorf("create admission summary file: %w", err)
	}
	defer func() { _ = file.Close() }()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(summary); err != nil {
		return "", fmt.Errorf("encode admission summary file: %w", err)
	}

	return path, nil
}

// ReadAdmissionSummary decodes an admission-summary.json file. Missing-file errors propagate;
// callers should os.Stat first if absent files are acceptable.
func ReadAdmissionSummary(path string) (models.AdmissionSummary, error) {
	file, err := os.Open(path)
	if err != nil {
		return models.AdmissionSummary{}, fmt.Errorf("open admission summary file: %w", err)
	}
	defer func() { _ = file.Close() }()

	var summary models.AdmissionSummary
	if err := json.NewDecoder(file).Decode(&summary); err != nil {
		return models.AdmissionSummary{}, fmt.Errorf("decode admission summary file: %w", err)
	}

	return summary, nil
}

// GuessAdmissionSummaryPath returns the default admission-summary.json location for a findings file.
func GuessAdmissionSummaryPath(findingsPath string) string {
	return filepath.Join(filepath.Dir(findingsPath), "admission-summary.json")
}

// WriteTruncationInfo writes truncation-info.json alongside scan-metadata.json so the
// `kubesplaining report` subcommand (and other consumers) can surface a "showing top N
// of M" banner without having to re-run analysis. Only call this when the cap actually
// fired; an empty (Truncated=false) sidecar would just be noise.
func WriteTruncationInfo(outputDir string, info models.TruncationInfo) (string, error) {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return "", fmt.Errorf("create truncation info directory: %w", err)
	}

	path := filepath.Join(outputDir, "truncation-info.json")
	file, err := os.Create(path)
	if err != nil {
		return "", fmt.Errorf("create truncation info file: %w", err)
	}
	defer func() { _ = file.Close() }()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(info); err != nil {
		return "", fmt.Errorf("encode truncation info file: %w", err)
	}

	return path, nil
}

// ReadTruncationInfo decodes a truncation-info.json file. Missing-file errors propagate;
// callers should os.Stat first if absent files are acceptable.
func ReadTruncationInfo(path string) (models.TruncationInfo, error) {
	file, err := os.Open(path)
	if err != nil {
		return models.TruncationInfo{}, fmt.Errorf("open truncation info file: %w", err)
	}
	defer func() { _ = file.Close() }()

	var info models.TruncationInfo
	if err := json.NewDecoder(file).Decode(&info); err != nil {
		return models.TruncationInfo{}, fmt.Errorf("decode truncation info file: %w", err)
	}

	return info, nil
}

// GuessTruncationInfoPath returns the default truncation-info.json location for a findings file.
func GuessTruncationInfoPath(findingsPath string) string {
	return filepath.Join(filepath.Dir(findingsPath), "truncation-info.json")
}
