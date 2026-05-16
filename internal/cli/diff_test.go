package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// writeFindings is a small test helper that serializes findings as the bare
// JSON array shape the report writer emits, so the diff command can ingest
// it via baseline.LoadFindings.
func writeFindings(t *testing.T, dir, name string, findings []models.Finding) string {
	t.Helper()
	path := filepath.Join(dir, name)
	payload, err := json.Marshal(findings)
	if err != nil {
		t.Fatalf("marshal findings: %v", err)
	}
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("write findings: %v", err)
	}
	return path
}

func TestDiffCmd_TextSummary(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	old := []models.Finding{
		{ID: "A", RuleID: "KUBE-PODSEC-PRIV-001", Severity: models.SeverityHigh, Score: 8.0, Title: "privileged container"},
		{ID: "B", RuleID: "KUBE-RBAC-OVERBROAD-001", Severity: models.SeverityCritical, Score: 9.5, Title: "wildcard role"},
	}
	newRun := []models.Finding{
		{ID: "A", RuleID: "KUBE-PODSEC-PRIV-001", Severity: models.SeverityHigh, Score: 8.0, Title: "privileged container"},
		{ID: "C", RuleID: "KUBE-PRIVESC-PATH-CLUSTER-ADMIN", Severity: models.SeverityCritical, Score: 9.8, Title: "default SA reaches cluster-admin"},
	}
	oldPath := writeFindings(t, tmp, "old.json", old)
	newPath := writeFindings(t, tmp, "new.json", newRun)

	cmd := NewDiffCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs([]string{oldPath, newPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	out := stdout.String()
	// One added (C, critical), one resolved (B, critical), one unchanged (A, high).
	if !strings.Contains(out, "1 new critical") {
		t.Errorf("expected '1 new critical' in output, got:\n%s", out)
	}
	if !strings.Contains(out, "1 resolved") {
		t.Errorf("expected '1 resolved' in output, got:\n%s", out)
	}
	if !strings.Contains(out, "1 new privesc path") {
		t.Errorf("expected '1 new privesc path' in output, got:\n%s", out)
	}
	if !strings.Contains(out, "Added (1)") {
		t.Errorf("expected 'Added (1)' header, got:\n%s", out)
	}
	if !strings.Contains(out, "Resolved (1)") {
		t.Errorf("expected 'Resolved (1)' header, got:\n%s", out)
	}
	if !strings.Contains(out, "KUBE-PRIVESC-PATH-CLUSTER-ADMIN") {
		t.Errorf("expected new finding's RuleID in output, got:\n%s", out)
	}
}

func TestDiffCmd_NoChangesIdenticalInputs(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	findings := []models.Finding{
		{ID: "A", RuleID: "KUBE-PODSEC-PRIV-001", Severity: models.SeverityHigh, Score: 8.0, Title: "privileged container"},
	}
	oldPath := writeFindings(t, tmp, "old.json", findings)
	newPath := writeFindings(t, tmp, "new.json", findings)

	cmd := NewDiffCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs([]string{oldPath, newPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, "no changes since baseline") {
		t.Errorf("expected 'no changes since baseline' in output, got:\n%s", out)
	}
	if !strings.Contains(out, "added=0 resolved=0 unchanged=1") {
		t.Errorf("expected 'added=0 resolved=0 unchanged=1' counts, got:\n%s", out)
	}
}

func TestDiffCmd_MarkdownOutput(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	old := []models.Finding{}
	newRun := []models.Finding{
		{ID: "X", RuleID: "KUBE-PODSEC-PRIV-001", Severity: models.SeverityHigh, Score: 8.0, Title: "privileged container | pipe"},
	}
	oldPath := writeFindings(t, tmp, "old.json", old)
	newPath := writeFindings(t, tmp, "new.json", newRun)

	cmd := NewDiffCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs([]string{"--output-format", "markdown", oldPath, newPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, "# kubesplaining diff") {
		t.Errorf("expected H1 title, got:\n%s", out)
	}
	if !strings.Contains(out, "## Added (1)") {
		t.Errorf("expected '## Added (1)' header, got:\n%s", out)
	}
	if !strings.Contains(out, `\|`) {
		t.Errorf("expected pipe characters in titles to be escaped, got:\n%s", out)
	}
}

func TestDiffCmd_SARIFOutputAddedOnly(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	old := []models.Finding{
		{ID: "Resolved-1", RuleID: "KUBE-RBAC-OVERBROAD-001", Severity: models.SeverityCritical, Score: 9.5, Title: "resolved rule"},
	}
	newRun := []models.Finding{
		{ID: "Added-1", RuleID: "KUBE-PRIVESC-PATH-CLUSTER-ADMIN", Severity: models.SeverityCritical, Score: 9.8, Title: "new privesc path", Description: "BFS from default SA"},
	}
	oldPath := writeFindings(t, tmp, "old.json", old)
	newPath := writeFindings(t, tmp, "new.json", newRun)

	cmd := NewDiffCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs([]string{"--output-format", "sarif", oldPath, newPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("decode sarif: %v\noutput:\n%s", err, stdout.String())
	}
	runs, ok := doc["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("expected one run, got: %v", doc["runs"])
	}
	run := runs[0].(map[string]any)
	props := run["properties"].(map[string]any)
	if props["delta"] != true {
		t.Errorf("expected properties.delta=true in run, got %v", props["delta"])
	}
	results := run["results"].([]any)
	if len(results) != 1 {
		t.Fatalf("expected exactly 1 result (Added only), got %d", len(results))
	}
	res := results[0].(map[string]any)
	if res["ruleId"] != "KUBE-PRIVESC-PATH-CLUSTER-ADMIN" {
		t.Errorf("expected Added finding's ruleId in result, got %v", res["ruleId"])
	}
	if res["level"] != "warning" {
		t.Errorf("expected level=warning for delta SARIF, got %v", res["level"])
	}

	// Resolved findings must not appear in SARIF.
	if strings.Contains(stdout.String(), "KUBE-RBAC-OVERBROAD-001") {
		t.Errorf("SARIF must omit Resolved findings; got:\n%s", stdout.String())
	}
}

func TestDiffCmd_OutputDirWritesFile(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	findings := []models.Finding{
		{ID: "A", RuleID: "KUBE-PODSEC-PRIV-001", Severity: models.SeverityHigh, Score: 8.0, Title: "x"},
	}
	oldPath := writeFindings(t, tmp, "old.json", findings)
	newPath := writeFindings(t, tmp, "new.json", findings)

	outDir := filepath.Join(tmp, "out")
	cmd := NewDiffCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs([]string{"--output-dir", outDir, "--output-format", "markdown", oldPath, newPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	written := filepath.Join(outDir, "diff.md")
	body, err := os.ReadFile(written)
	if err != nil {
		t.Fatalf("read written diff: %v", err)
	}
	if !strings.Contains(string(body), "# kubesplaining diff") {
		t.Errorf("expected markdown content in %s, got:\n%s", written, string(body))
	}
	if !strings.Contains(stdout.String(), written) {
		t.Errorf("expected stdout to mention %s, got:\n%s", written, stdout.String())
	}
}

func TestDiffCmd_InvalidFormat(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	findings := []models.Finding{
		{ID: "A", RuleID: "KUBE-PODSEC-PRIV-001", Severity: models.SeverityHigh, Score: 8.0, Title: "x"},
	}
	oldPath := writeFindings(t, tmp, "old.json", findings)
	newPath := writeFindings(t, tmp, "new.json", findings)

	cmd := NewDiffCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	cmd.SetArgs([]string{"--output-format", "yaml", oldPath, newPath})

	err := cmd.Execute()
	if err == nil {
		t.Fatalf("expected error for invalid output format")
	}
	if !strings.Contains(err.Error(), "yaml") {
		t.Errorf("expected error mentioning yaml, got: %v", err)
	}
}
