package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
)

const (
	riskySnapshot = "../../testdata/snapshots/minimal-risky.json"
	riskyManifest = "../../testdata/manifests/risky-resource.yaml"
)

// runRoot executes the root command with args and returns stdout, stderr, and
// the error the command returned.
func runRoot(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	cmd := NewRootCmd(BuildInfo{Version: "test"})
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return stdout.String(), stderr.String(), err
}

var countsLine = regexp.MustCompile(`findings: total=(\d+) critical=(\d+) high=(\d+)`)

// parseCounts reads the total, critical, and high counts from the
// `findings:` line that scan prints.
func parseCounts(t *testing.T, stdout string) (total, critical, high int) {
	t.Helper()
	m := countsLine.FindStringSubmatch(stdout)
	if m == nil {
		t.Fatalf("no findings: line in output:\n%s", stdout)
	}
	total, _ = strconv.Atoi(m[1])
	critical, _ = strconv.Atoi(m[2])
	high, _ = strconv.Atoi(m[3])
	return total, critical, high
}

func readFindingsFile(t *testing.T, path string) []models.Finding {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var findings []models.Finding
	if err := json.Unmarshal(raw, &findings); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
	return findings
}

// TestScanCapShortensOnlyTheHTMLReport runs scan with a cap of one finding.
// The privesc module is off so the cap leaves exactly one finding in the HTML
// report. The counts line, findings.json, and the CI gate must still see all
// of them: with a budget of one critical finding less than the cluster has,
// a gate that counted the capped list (at most one finding) would pass.
func TestScanCapShortensOnlyTheHTMLReport(t *testing.T) {
	t.Parallel()

	fullDir := t.TempDir()
	stdout, _, err := runRoot(t, "scan", "--input-file", riskySnapshot, "--output-dir", fullDir,
		"--skip-modules", "privesc", "--all-findings")
	if err != nil {
		t.Fatalf("uncapped scan: %v", err)
	}
	total, critical, _ := parseCounts(t, stdout)
	if critical < 2 {
		t.Fatalf("fixture has %d critical findings without privesc; this test needs at least 2", critical)
	}

	cappedDir := t.TempDir()
	stdout, stderr, err := runRoot(t, "scan", "--input-file", riskySnapshot, "--output-dir", cappedDir,
		"--skip-modules", "privesc", "--max-findings", "1",
		"--ci-mode", "--ci-max-critical", strconv.Itoa(critical-1), "--ci-max-high", "100000")

	if err == nil {
		t.Fatalf("gate passed with %d critical findings and a budget of %d: it did not count every finding", critical, critical-1)
	}
	if got := ExitCode(err); got != ExitGateExceeded {
		t.Errorf("ExitCode = %d, want %d for a gate result (error: %v)", got, ExitGateExceeded, err)
	}

	gotTotal, gotCritical, _ := parseCounts(t, stdout)
	if gotTotal != total || gotCritical != critical {
		t.Errorf("counts line with the cap = total %d critical %d, want the complete total %d critical %d", gotTotal, gotCritical, total, critical)
	}
	if got := len(readFindingsFile(t, filepath.Join(cappedDir, "findings.json"))); got != total {
		t.Errorf("findings.json has %d findings with the cap, want all %d", got, total)
	}
	if !strings.Contains(stderr, "report.html lists 1 of "+strconv.Itoa(total)+" findings") {
		t.Errorf("stderr does not say that only report.html is shortened:\n%s", stderr)
	}
}

// TestDefaultRunCutsNothing checks the default of each command that has the
// flag: no cut. A first run must show the user every finding, and must leave no
// file that says the report is a sample.
func TestDefaultRunCutsNothing(t *testing.T) {
	t.Parallel()

	root := NewRootCmd(BuildInfo{Version: "test"})
	for _, name := range []string{"scan", "report", "scan-resource"} {
		cmd, _, err := root.Find([]string{name})
		if err != nil {
			t.Fatalf("find %s: %v", name, err)
		}
		flag := cmd.Flags().Lookup("max-findings")
		if flag == nil {
			t.Fatalf("%s has no --max-findings flag", name)
		}
		if flag.DefValue != "0" {
			t.Errorf("%s --max-findings default = %s, want 0 (no cut)", name, flag.DefValue)
		}
	}

	dir := t.TempDir()
	stdout, stderr, err := runRoot(t, "scan", "--input-file", riskySnapshot, "--output-dir", dir)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	total, _, _ := parseCounts(t, stdout)
	if total <= 20 {
		t.Fatalf("fixture has %d findings, need more than 20 for this test to mean anything", total)
	}
	if strings.Contains(stderr, "report.html lists") || strings.Contains(stderr, "showing top") {
		t.Errorf("a default run printed a cut notice:\n%s", stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, "truncation-info.json")); !os.IsNotExist(err) {
		t.Errorf("a default run wrote truncation-info.json (stat error: %v)", err)
	}
	html, err := os.ReadFile(filepath.Join(dir, "report.html"))
	if err != nil {
		t.Fatalf("read report.html: %v", err)
	}
	if strings.Contains(string(html), `class="truncation-banner"`) {
		t.Errorf("the default report.html has the cut banner")
	}
	if got := len(readFindingsFile(t, filepath.Join(dir, "findings.json"))); got != total {
		t.Errorf("findings.json has %d findings, the counts line says %d", got, total)
	}

	// The table of scan-resource is not cut by default.
	stdout, stderr, err = runRoot(t, "scan-resource", "--input-file", riskyManifest)
	if err != nil {
		t.Fatalf("scan-resource: %v", err)
	}
	if strings.Contains(stdout+stderr, "showing top") {
		t.Errorf("a default scan-resource run cut the table:\n%s%s", stdout, stderr)
	}
}

// TestScanPrintsAttackPaths checks that the terminal shows the attack paths,
// and that a cap low enough to drop them from a plain top-N list does not.
func TestScanPrintsAttackPaths(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	stdout, stderr, err := runRoot(t, "scan", "--input-file", riskySnapshot, "--output-dir", dir, "--max-findings", "1")
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if !strings.Contains(stdout, "attack paths: total=") {
		t.Fatalf("stdout has no attack paths block:\n%s", stdout)
	}
	if !strings.Contains(stdout, "shortest: ServiceAccount/") {
		t.Errorf("attack paths block names no source identity:\n%s", stdout)
	}
	if !strings.Contains(stderr, "every attack path and the top 1 of the rest") {
		t.Errorf("stderr does not explain what report.html lists:\n%s", stderr)
	}

	// Every attack path is in the complete findings.json, and the same count
	// is on the terminal.
	paths := 0
	for _, f := range readFindingsFile(t, filepath.Join(dir, "findings.json")) {
		if strings.HasPrefix(f.RuleID, "KUBE-PRIVESC-PATH-") {
			paths++
		}
	}
	if paths == 0 {
		t.Fatalf("fixture produced no attack path")
	}
	if !strings.Contains(stdout, "attack paths: total="+strconv.Itoa(paths)+" ") {
		t.Errorf("terminal attack path total does not match the %d paths in findings.json:\n%s", paths, stdout)
	}

	html, err := os.ReadFile(filepath.Join(dir, "report.html"))
	if err != nil {
		t.Fatalf("read report.html: %v", err)
	}
	if !strings.Contains(string(html), `id="tabbtn-paths"`) {
		t.Errorf("report.html has no Attack paths tab with --max-findings 1")
	}
}

// TestBaselineAgainstOwnOutputAddsNothing compares a capped scan with the
// findings.json of an identical capped scan. With complete files on both
// sides nothing is added or resolved, so a delta gate with zero budgets passes.
func TestBaselineAgainstOwnOutputAddsNothing(t *testing.T) {
	t.Parallel()

	baseDir := t.TempDir()
	if _, _, err := runRoot(t, "scan", "--input-file", riskySnapshot, "--output-dir", baseDir, "--max-findings", "1"); err != nil {
		t.Fatalf("baseline scan: %v", err)
	}

	stdout, stderr, err := runRoot(t, "scan", "--input-file", riskySnapshot, "--output-dir", t.TempDir(), "--max-findings", "1",
		"--baseline", filepath.Join(baseDir, "findings.json"), "--ci-mode")
	if err != nil {
		t.Fatalf("delta gate failed against an identical baseline: %v\nstdout:\n%s", err, stdout)
	}
	if strings.Contains(stderr, "warning:") {
		t.Errorf("unexpected warning for a baseline written by this version:\n%s", stderr)
	}
}

func TestToolErrorIsNotAGateResult(t *testing.T) {
	t.Parallel()

	_, _, err := runRoot(t, "scan", "--input-file", filepath.Join(t.TempDir(), "missing.json"), "--output-dir", t.TempDir())
	if err == nil {
		t.Fatalf("scan of a missing snapshot did not fail")
	}
	if got := ExitCode(err); got != ExitFailure {
		t.Errorf("ExitCode = %d, want %d for a tool error", got, ExitFailure)
	}
	if got := ExitCode(nil); got != 0 {
		t.Errorf("ExitCode(nil) = %d, want 0", got)
	}
}

// TestWarnIfSampledFindings covers the three states of the sidecar beside a
// findings file: written by an older version (the file is a sample), written
// by this version (only the HTML report is cut), and absent.
func TestWarnIfSampledFindings(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		sidecar  string
		wantWarn bool
	}{
		{name: "older version cut every output", sidecar: `{"truncated":true,"original":811,"shown":20,"limit":20}`, wantWarn: true},
		{name: "this version cut the HTML report only", sidecar: `{"truncated":true,"original":811,"shown":316,"limit":20,"scope":"html","attack_paths":296}`},
		{name: "sidecar says not truncated", sidecar: `{"truncated":false,"original":12,"shown":12,"limit":20}`},
		{name: "no sidecar"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			findingsPath := writeFindings(t, dir, "findings.json", nil)
			if tc.sidecar != "" {
				if err := os.WriteFile(filepath.Join(dir, "truncation-info.json"), []byte(tc.sidecar), 0o600); err != nil {
					t.Fatalf("write sidecar: %v", err)
				}
			}
			var out bytes.Buffer
			warnIfSampledFindings(&out, findingsPath)
			if got := strings.Contains(out.String(), "warning:"); got != tc.wantWarn {
				t.Errorf("warning printed = %v, want %v (output: %q)", got, tc.wantWarn, out.String())
			}
			if tc.wantWarn && !strings.Contains(out.String(), "top 20 of 811") {
				t.Errorf("warning does not give the sample size: %q", out.String())
			}
		})
	}
}

// TestScanResourceJSONIsComplete checks the split for the manifest command:
// JSON carries every finding, the table is capped and says so.
func TestScanResourceJSONIsComplete(t *testing.T) {
	t.Parallel()

	stdout, stderr, err := runRoot(t, "scan-resource", "--input-file", riskyManifest, "--output-format", "json", "--all-findings")
	if err != nil {
		t.Fatalf("uncapped scan-resource: %v", err)
	}
	var all []models.Finding
	if err := json.Unmarshal([]byte(stdout), &all); err != nil {
		t.Fatalf("unmarshal JSON output: %v\n%s", err, stdout)
	}
	if len(all) < 2 {
		t.Fatalf("fixture produced %d findings; this test needs at least 2", len(all))
	}
	_ = stderr

	stdout, stderr, err = runRoot(t, "scan-resource", "--input-file", riskyManifest, "--output-format", "json", "--max-findings", "1")
	if err != nil {
		t.Fatalf("capped scan-resource (json): %v", err)
	}
	var capped []models.Finding
	if err := json.Unmarshal([]byte(stdout), &capped); err != nil {
		t.Fatalf("unmarshal capped JSON output: %v\n%s", err, stdout)
	}
	if len(capped) != len(all) {
		t.Errorf("JSON output with --max-findings 1 has %d findings, want all %d", len(capped), len(all))
	}
	if strings.Contains(stderr, "showing top") {
		t.Errorf("JSON output is complete, so no cap notice is expected:\n%s", stderr)
	}

	stdout, stderr, err = runRoot(t, "scan-resource", "--input-file", riskyManifest, "--output-format", "table", "--max-findings", "1")
	if err != nil {
		t.Fatalf("capped scan-resource (table): %v", err)
	}
	if rows := strings.Count(strings.TrimSpace(stdout), "\n"); rows != 1 {
		t.Errorf("table has %d data rows with --max-findings 1, want 1:\n%s", rows, stdout)
	}
	if !strings.Contains(stderr, "showing top 1 of "+strconv.Itoa(len(all))) {
		t.Errorf("table output is capped, so a notice is expected:\n%s", stderr)
	}
}
