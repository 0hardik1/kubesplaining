package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/analyzer"
	"github.com/0hardik1/kubesplaining/internal/collector"
	"github.com/0hardik1/kubesplaining/internal/exclusions"
	"github.com/0hardik1/kubesplaining/internal/models"
)

const minimalRisky = "../../testdata/snapshots/minimal-risky.json"

// runPaths runs the paths command and returns stdout, stderr, and the error.
func runPaths(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	cmd := NewPathsCmd(BuildInfo{})
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return stdout.String(), stderr.String(), err
}

// runPathsJSON runs the command with JSON output and decodes the answer.
func runPathsJSON(t *testing.T, args ...string) pathsOutput {
	t.Helper()
	stdout, stderr, err := runPaths(t, append(args, "--output-format", "json")...)
	if err != nil {
		t.Fatalf("paths %v: %v", args, err)
	}
	if stderr != "" {
		t.Errorf("paths %v wrote to stderr in JSON mode: %q", args, stderr)
	}
	var out pathsOutput
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("paths %v: output is not JSON: %v\n%s", args, err, stdout)
	}
	return out
}

// With no filter, paths must list the attack paths that a default scan reports:
// same IDs, same severity, same score. The scan side here is the engine with the
// options that `scan` passes by default, then the standard exclusions.
func TestPathsMatchesScanOnEveryFixture(t *testing.T) {
	t.Parallel()

	files, err := filepath.Glob("../../testdata/snapshots/*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("no snapshot fixtures found (err=%v)", err)
	}
	cfg, err := exclusions.Preset("standard")
	if err != nil {
		t.Fatalf("standard preset: %v", err)
	}

	compared := 0
	for _, file := range files {
		snapshot, err := collector.ReadSnapshot(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		result, err := analyzer.NewWithConfig(analyzer.Config{MaxPrivescDepth: 5}).Analyze(context.Background(), snapshot, analyzer.Options{
			Threshold:     models.SeverityLow,
			AdmissionMode: analyzer.AdmissionModeSuppress,
		})
		if err != nil {
			t.Fatalf("%s: Analyze: %v", file, err)
		}
		scanned, _ := exclusions.Apply(cfg, result.Findings)

		want := map[string]string{}
		for _, finding := range scanned {
			if len(finding.EscalationPath) == 0 {
				continue
			}
			want[finding.ID] = string(finding.Severity) + " " + formatScore(finding.Score)
		}

		out := runPathsJSON(t, "--input-file", file)
		got := map[string]string{}
		for _, path := range out.Paths {
			got[path.ID] = path.Severity + " " + formatScore(path.Score)
		}
		if out.Total != len(want) || out.Returned != len(want) {
			t.Errorf("%s: total=%d returned=%d, want %d", file, out.Total, out.Returned, len(want))
		}
		for id, wantValue := range want {
			if got[id] != wantValue {
				t.Errorf("%s: path %s = %q, want %q", file, id, got[id], wantValue)
			}
		}
		for id := range got {
			if _, ok := want[id]; !ok {
				t.Errorf("%s: paths lists %s, which the scan does not report", file, id)
			}
		}
		compared += len(want)
	}
	if compared == 0 {
		t.Fatal("no fixture produced an attack path, so the test compared nothing")
	}
}

func TestPathsToKeepsOneTarget(t *testing.T) {
	t.Parallel()

	all := runPathsJSON(t, "--input-file", minimalRisky)
	want := 0
	for _, path := range all.Paths {
		if path.Target == string(models.TargetKubeSystemSecrets) {
			want++
		}
	}
	if want == 0 || want == all.Total {
		t.Fatalf("fixture must have kube-system-secrets paths and other paths, got %d of %d", want, all.Total)
	}

	// Each spelling of the target must select the same paths.
	for _, to := range []string{"kube-system-secrets", "kube_system_secrets", "Kube-System-Secrets"} {
		out := runPathsJSON(t, "--input-file", minimalRisky, "--to", to)
		if out.Total != want {
			t.Errorf("--to %s: total=%d, want %d", to, out.Total, want)
		}
		for _, path := range out.Paths {
			if path.Target != string(models.TargetKubeSystemSecrets) {
				t.Errorf("--to %s returned a path to %s", to, path.Target)
			}
		}
	}
}

func TestPathsFromOneSubject(t *testing.T) {
	t.Parallel()

	// The same subject in the two forms that --from accepts.
	for _, from := range []string{"ServiceAccount/default/reader", "sa/default/reader", "system:serviceaccount:default:reader"} {
		out := runPathsJSON(t, "--input-file", minimalRisky, "--from", from)
		if out.Total == 0 {
			t.Fatalf("--from %s: no paths", from)
		}
		for _, path := range out.Paths {
			if path.Source != "ServiceAccount/default/reader" {
				t.Errorf("--from %s returned a path from %s", from, path.Source)
			}
			if len(path.Hops) == 0 || path.Hops[0].From != path.Source {
				t.Errorf("--from %s: path %s does not start at the source: %+v", from, path.ID, path.Hops)
			}
		}
	}
}

// A subject that is not in the cluster must be an error. An empty answer would
// read as "this identity reaches nothing", which is false for a mistyped name.
func TestPathsFromUnknownSubjectIsAnError(t *testing.T) {
	t.Parallel()

	stdout, _, err := runPaths(t, "--input-file", minimalRisky, "--from", "ServiceAccount/elsewhere/reader")
	if err == nil {
		t.Fatalf("want an error for an unknown subject, got output:\n%s", stdout)
	}
	if !strings.Contains(err.Error(), "was not found") {
		t.Errorf("error does not say that the subject was not found: %v", err)
	}
	// The ServiceAccount of the same name in a different namespace is the likely intent.
	if !strings.Contains(err.Error(), "ServiceAccount/default/reader") {
		t.Errorf("error does not suggest the subject with the same name: %v", err)
	}
	if stdout != "" {
		t.Errorf("an error must print no paths, got:\n%s", stdout)
	}
}

func TestPathsRejectsBadFlags(t *testing.T) {
	t.Parallel()

	cases := [][]string{
		{"--from", "reader"},
		{"--from", "Pod/default/web"},
		{"--to", "admin"},
		{"--to", "node-escape:worker-1"},
		{"--output-format", "yaml"},
		{"--limit", "-1"},
		{"--id", "KUBE-PRIVESC-PATH-CLUSTER-ADMIN:User/nobody:cluster_admin_equivalent"},
	}
	for _, args := range cases {
		if _, _, err := runPaths(t, append([]string{"--input-file", minimalRisky}, args...)...); err == nil {
			t.Errorf("paths %v: want an error", args)
		}
	}
}

func TestPathsLimitReportsTheTotal(t *testing.T) {
	t.Parallel()

	all := runPathsJSON(t, "--input-file", minimalRisky)
	if all.Total < 2 {
		t.Fatalf("fixture must have 2 or more paths, got %d", all.Total)
	}
	out := runPathsJSON(t, "--input-file", minimalRisky, "--limit", "1")
	if out.Total != all.Total || out.Returned != 1 || len(out.Paths) != 1 {
		t.Fatalf("--limit 1: total=%d returned=%d paths=%d, want total=%d returned=1", out.Total, out.Returned, len(out.Paths), all.Total)
	}
	// The limit keeps the head of the ordered list: highest severity and score.
	if out.Paths[0].ID != all.Paths[0].ID {
		t.Errorf("--limit 1 returned %s, want the first path %s", out.Paths[0].ID, all.Paths[0].ID)
	}
	if !sort.SliceIsSorted(all.Paths, func(i, j int) bool {
		a, b := all.Paths[i], all.Paths[j]
		ra, _ := models.ParseSeverity(a.Severity)
		rb, _ := models.ParseSeverity(b.Severity)
		if ra.Rank() != rb.Rank() {
			return ra.Rank() > rb.Rank()
		}
		return a.Score > b.Score
	}) {
		t.Errorf("paths are not ordered by severity, then score: %+v", all.Paths)
	}
}

func TestPathsIDSelectsOnePath(t *testing.T) {
	t.Parallel()

	all := runPathsJSON(t, "--input-file", minimalRisky)
	want := all.Paths[len(all.Paths)-1]
	out := runPathsJSON(t, "--input-file", minimalRisky, "--id", want.ID, "--verbose")
	if out.Total != 1 || out.Paths[0].ID != want.ID {
		t.Fatalf("--id %s returned %+v", want.ID, out.Paths)
	}
	got := out.Paths[0]
	if got.Remediation == "" {
		t.Error("--verbose JSON has no remediation")
	}
	if got.RBACDiff == "" && got.FixCommand == "" {
		t.Error("--verbose JSON has no structured fix (rbac_diff or fix_command)")
	}
	if got.Hops[0].Gains == "" {
		t.Error("--verbose JSON has no gains on the hop")
	}
	// The compact form leaves the prose out.
	if want.Remediation != "" || want.RBACDiff != "" || want.Hops[0].Gains != "" {
		t.Errorf("the compact record carries verbose fields: %+v", want)
	}
}

func TestPathsTableAndVerboseText(t *testing.T) {
	t.Parallel()

	stdout, stderr, err := runPaths(t, "--input-file", minimalRisky)
	if err != nil {
		t.Fatalf("paths: %v", err)
	}
	for _, want := range []string{"SEVERITY", "CHAIN", "ServiceAccount/default/reader", "kube-system-secrets", "read_secrets"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("table output lacks %q:\n%s", want, stdout)
		}
	}
	if !strings.Contains(stderr, "2 attack paths.") || !strings.Contains(stderr, "--verbose") {
		t.Errorf("footer lacks the count or the --verbose hint:\n%s", stderr)
	}

	stdout, _, err = runPaths(t, "--input-file", minimalRisky, "--to", "kube-system-secrets", "--verbose")
	if err != nil {
		t.Fatalf("paths --verbose: %v", err)
	}
	for _, want := range []string{
		"ServiceAccount/default/reader -> kube-system-secrets",
		"id: KUBE-PRIVESC-PATH-KUBE-SYSTEM-SECRETS:ServiceAccount/default/reader:kube_system_secrets",
		"1. read_secrets",
		"granted by: ClusterRoleBinding reader-role",
		"fix:",
		"kubectl edit clusterrolebinding reader-role",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("verbose output lacks %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "`") || strings.Contains(stdout, "**") {
		t.Errorf("verbose output carries Markdown marks:\n%s", stdout)
	}
}

func TestPathsNoMatchSaysSo(t *testing.T) {
	t.Parallel()

	stdout, stderr, err := runPaths(t, "--input-file", minimalRisky, "--from", "ServiceAccount/default/reader", "--to", "cluster-admin")
	if err != nil {
		t.Fatalf("an empty answer is not an error: %v", err)
	}
	if stdout != "" {
		t.Errorf("stdout must be empty, got:\n%s", stdout)
	}
	if want := "No attack paths from ServiceAccount/default/reader to cluster-admin within 5 hops."; !strings.Contains(stderr, want) {
		t.Errorf("stderr lacks %q:\n%s", want, stderr)
	}

	out := runPathsJSON(t, "--input-file", minimalRisky, "--from", "ServiceAccount/default/reader", "--to", "cluster-admin")
	if out.Total != 0 || out.Paths == nil || len(out.Paths) != 0 {
		t.Errorf("JSON for an empty answer must have total 0 and an empty paths array, got %+v", out)
	}
}

// The default listing follows the exclusions, as scan does, and says how many
// paths they hide. A path that the user names with --from is never hidden.
func TestPathsFromIgnoresExclusions(t *testing.T) {
	t.Parallel()

	file := filepath.Join(t.TempDir(), "exclusions.yaml")
	if err := os.WriteFile(file, []byte("global:\n  exclude_service_accounts:\n    - \"default:reader\"\n"), 0o600); err != nil {
		t.Fatalf("write exclusions: %v", err)
	}

	hidden := runPathsJSON(t, "--input-file", minimalRisky, "--exclusions-file", file)
	if hidden.Total != 0 {
		t.Fatalf("the exclusions file must hide the paths of default/reader, got %d", hidden.Total)
	}
	if len(hidden.Notes) != 1 || !strings.Contains(hidden.Notes[0], "hide 2 attack paths") {
		t.Errorf("want one note that counts the hidden paths, got %q", hidden.Notes)
	}

	named := runPathsJSON(t, "--input-file", minimalRisky, "--exclusions-file", file, "--from", "ServiceAccount/default/reader")
	if named.Total != 2 {
		t.Errorf("--from must ignore the exclusions: total=%d, want 2", named.Total)
	}
}

func TestParseTargetSelector(t *testing.T) {
	t.Parallel()

	valid := map[string]targetSelector{
		"cluster-admin":            {target: models.TargetClusterAdmin},
		"cluster_admin":            {target: models.TargetClusterAdmin},
		"cluster_admin_equivalent": {target: models.TargetClusterAdmin},
		"CLUSTER-ADMIN":            {target: models.TargetClusterAdmin},
		"system-masters":           {target: models.TargetSystemMasters},
		"system:masters":           {target: models.TargetSystemMasters},
		"kube-system-secrets":      {target: models.TargetKubeSystemSecrets},
		"node-escape":              {target: models.TargetNodeEscape},
		"node-root":                {target: models.TargetNodeEscape},
		"namespace-admin":          {target: models.TargetNamespaceAdmin},
		"namespace_admin:dev":      {target: models.TargetNamespaceAdmin, detail: "dev"},
		"token-mint":               {target: models.TargetTokenMint},
		"aws-iam-role":             {target: models.TargetAWSIAMRole},
		"aws-iam-role:arn:aws:iam::123456789012:role/Admin": {target: models.TargetAWSIAMRole, detail: "arn:aws:iam::123456789012:role/Admin"},
		"traffic-intercept": {target: models.TargetTrafficIntercept},
		"node-identity":     {target: models.TargetNodeIdentity},
	}
	for value, want := range valid {
		got, err := parseTargetSelector(value)
		if err != nil || got != want {
			t.Errorf("parseTargetSelector(%q) = %+v, %v; want %+v", value, got, err, want)
		}
	}
	for _, value := range []string{"", "admin", "cluster-admin:dev", "node-escape:worker-1", "secrets"} {
		if got, err := parseTargetSelector(value); err == nil {
			t.Errorf("parseTargetSelector(%q) = %+v, want an error", value, got)
		}
	}

	// The name that the table prints must be a name that --to accepts, for each
	// target, with and without a namespace or a role.
	for _, target := range pathTargets {
		for _, detail := range []string{"", "x"} {
			if detail != "" && target != models.TargetNamespaceAdmin && target != models.TargetAWSIAMRole {
				continue
			}
			label := targetLabel(target, detail)
			got, err := parseTargetSelector(label)
			if err != nil || got.target != target || got.detail != detail {
				t.Errorf("parseTargetSelector(targetLabel(%s, %q) = %q) = %+v, %v", target, detail, label, got, err)
			}
		}
	}
}
