package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// selectionFixture builds a findings list in the engine's order: `flat`
// flat findings spread over three categories with falling scores, then `paths`
// attack paths that all score below every flat finding. That is the shape of
// a dense cluster, where flat findings amplified to score 10 outrank the paths
// they are part of.
func selectionFixture(flat, paths int) []models.Finding {
	categories := []models.RiskCategory{
		models.CategoryPrivilegeEscalation,
		models.CategoryDataExfiltration,
		models.CategoryLateralMovement,
	}
	out := make([]models.Finding, 0, flat+paths)
	for i := 0; i < flat; i++ {
		out = append(out, models.Finding{
			ID:       fmt.Sprintf("flat-%03d", i),
			RuleID:   fmt.Sprintf("KUBE-TEST-%03d", i%7),
			Severity: models.SeverityCritical,
			Score:    10 - float64(i)*0.01,
			Category: categories[i%len(categories)],
			Title:    fmt.Sprintf("flat finding %d", i),
		})
	}
	for i := 0; i < paths; i++ {
		subject := models.SubjectRef{Kind: "ServiceAccount", Namespace: "apps", Name: fmt.Sprintf("sa-%d", i)}
		out = append(out, models.Finding{
			ID:       fmt.Sprintf("path-%03d", i),
			RuleID:   "KUBE-PRIVESC-PATH-CLUSTER-ADMIN",
			Severity: models.SeverityCritical,
			Score:    5 - float64(i)*0.01,
			Category: models.CategoryPrivilegeEscalation,
			Title:    fmt.Sprintf("path %d", i),
			Subject:  &subject,
			Tags:     []string{"target:cluster_admin_equivalent"},
			EscalationPath: []models.EscalationHop{{
				Step:        1,
				Action:      "bound_to_cluster_admin",
				FromSubject: subject,
			}},
		})
	}
	return out
}

func TestSelectForHTMLKeepsEveryAttackPath(t *testing.T) {
	t.Parallel()

	findings := selectionFixture(60, 9)

	// The plain top-N draw is why attack paths need the exemption: they rank
	// below the flat findings, so it keeps none of them.
	plain, _ := Truncate(findings, 20, false)
	for _, f := range plain {
		if IsAttackPath(f) {
			t.Fatalf("fixture is wrong: the plain top-20 draw kept attack path %s", f.ID)
		}
	}

	listed, info := SelectForHTML(findings, 20, false)

	paths, flat := 0, 0
	for _, f := range listed {
		if IsAttackPath(f) {
			paths++
		} else {
			flat++
		}
	}
	if paths != 9 {
		t.Errorf("listed attack paths = %d, want all 9", paths)
	}
	if flat != 20 {
		t.Errorf("listed flat findings = %d, want the cap of 20", flat)
	}

	want := models.TruncationInfo{
		Truncated:   true,
		Original:    69,
		Shown:       29,
		Limit:       20,
		Scope:       models.TruncationScopeHTML,
		AttackPaths: 9,
	}
	if info != want {
		t.Errorf("info = %+v, want %+v", info, want)
	}

	// The input order is kept: each listed finding sits after the one before
	// it in the input.
	pos := map[string]int{}
	for i, f := range findings {
		pos[f.ID] = i
	}
	for i := 1; i < len(listed); i++ {
		if pos[listed[i-1].ID] >= pos[listed[i].ID] {
			t.Fatalf("listed order differs from input order at %s, %s", listed[i-1].ID, listed[i].ID)
		}
	}

	// The absolute top finding is always in the selection.
	if listed[0].ID != findings[0].ID {
		t.Errorf("first listed = %s, want the top finding %s", listed[0].ID, findings[0].ID)
	}
}

func TestSelectForHTMLDoesNothingWhenTheCapRemovesNothing(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		findings    []models.Finding
		limit       int
		allFindings bool
	}{
		// 20 flat findings fit the cap; the 50 attack paths do not count toward it.
		{name: "flat findings fit", findings: selectionFixture(20, 50), limit: 20},
		{name: "all findings requested", findings: selectionFixture(60, 9), limit: 20, allFindings: true},
		{name: "cap disabled", findings: selectionFixture(60, 9), limit: 0},
		{name: "empty", findings: nil, limit: 20},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			listed, info := SelectForHTML(tc.findings, tc.limit, tc.allFindings)
			if len(listed) != len(tc.findings) {
				t.Errorf("listed %d findings, want all %d", len(listed), len(tc.findings))
			}
			if info != (models.TruncationInfo{}) {
				t.Errorf("info = %+v, want the zero value", info)
			}
		})
	}
}

// TestWriteKeepsMachineOutputsComplete is the contract that a program reading
// the report directory depends on: the cap shortens report.html and nothing
// else.
func TestWriteKeepsMachineOutputsComplete(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	snapshot := models.NewSnapshot()
	snapshot.Metadata.ClusterName = "complete-outputs"

	findings := selectionFixture(60, 9)
	listed, truncation := SelectForHTML(findings, 20, false)

	written, err := WriteWithOptions(tmpDir, []string{"html", "json", "csv", "sarif"}, snapshot, findings,
		models.AdmissionSummary{}, truncation, Options{HTMLFindings: listed})
	if err != nil {
		t.Fatalf("WriteWithOptions() error = %v", err)
	}

	// findings.json: every finding.
	var fromJSON []models.Finding
	raw, err := os.ReadFile(filepath.Join(tmpDir, "findings.json"))
	if err != nil {
		t.Fatalf("read findings.json: %v", err)
	}
	if err := json.Unmarshal(raw, &fromJSON); err != nil {
		t.Fatalf("unmarshal findings.json: %v", err)
	}
	if len(fromJSON) != len(findings) {
		t.Errorf("findings.json has %d findings, want all %d", len(fromJSON), len(findings))
	}

	// findings.sarif: every finding, and no claim that it is truncated.
	var sarif struct {
		Runs []struct {
			Results    []json.RawMessage          `json:"results"`
			Properties map[string]json.RawMessage `json:"properties"`
		} `json:"runs"`
	}
	raw, err = os.ReadFile(filepath.Join(tmpDir, "findings.sarif"))
	if err != nil {
		t.Fatalf("read findings.sarif: %v", err)
	}
	if err := json.Unmarshal(raw, &sarif); err != nil {
		t.Fatalf("unmarshal findings.sarif: %v", err)
	}
	if len(sarif.Runs) != 1 {
		t.Fatalf("sarif runs = %d, want 1", len(sarif.Runs))
	}
	if got := len(sarif.Runs[0].Results); got != len(findings) {
		t.Errorf("findings.sarif has %d results, want all %d", got, len(findings))
	}
	if _, ok := sarif.Runs[0].Properties["truncation"]; ok {
		t.Errorf("findings.sarif is complete and must not carry a truncation property")
	}

	// triage.csv: a header row plus one row per finding.
	raw, err = os.ReadFile(filepath.Join(tmpDir, "triage.csv"))
	if err != nil {
		t.Fatalf("read triage.csv: %v", err)
	}
	if rows := strings.Count(strings.TrimRight(string(raw), "\n"), "\n"); rows != len(findings) {
		t.Errorf("triage.csv has %d data rows, want all %d", rows, len(findings))
	}

	// truncation-info.json: says that only the HTML report is cut.
	sidecar := ""
	for _, p := range written {
		if filepath.Base(p) == "truncation-info.json" {
			sidecar = p
		}
	}
	if sidecar == "" {
		t.Fatalf("expected truncation-info.json in written artifacts: %v", written)
	}
	info, err := ReadTruncationInfo(sidecar)
	if err != nil {
		t.Fatalf("ReadTruncationInfo() error = %v", err)
	}
	if info.Scope != models.TruncationScopeHTML {
		t.Errorf("sidecar scope = %q, want %q", info.Scope, models.TruncationScopeHTML)
	}

	// report.html: the short list, all attack paths, and a banner that says so.
	raw, err = os.ReadFile(filepath.Join(tmpDir, "report.html"))
	if err != nil {
		t.Fatalf("read report.html: %v", err)
	}
	html := string(raw)
	for _, want := range []string{
		"This report lists 29 of 69 findings",
		"every attack path (9)",
		"<code>findings.json</code> holds all 69",
		`id="tabbtn-paths"`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("report.html does not contain %q", want)
		}
	}
	if strings.Contains(html, "flat finding 59") {
		t.Errorf("report.html lists the lowest flat finding, so the cap did not apply to the HTML report")
	}
}

func TestSARIFCarriesEscalationPath(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	snapshot := models.NewSnapshot()
	findings := selectionFixture(1, 1)
	findings[1].AlternateEscalationPath = []models.EscalationHop{{Step: 1, Action: "impersonate_user"}}

	if _, err := Write(tmpDir, []string{"sarif"}, snapshot, findings); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(tmpDir, "findings.sarif"))
	if err != nil {
		t.Fatalf("read findings.sarif: %v", err)
	}
	var sarif struct {
		Runs []struct {
			Results []struct {
				RuleID     string `json:"ruleId"`
				Properties struct {
					EscalationPath          []models.EscalationHop `json:"escalation_path"`
					AlternateEscalationPath []models.EscalationHop `json:"alternate_escalation_path"`
				} `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &sarif); err != nil {
		t.Fatalf("unmarshal findings.sarif: %v", err)
	}
	if len(sarif.Runs) != 1 || len(sarif.Runs[0].Results) != 2 {
		t.Fatalf("unexpected sarif shape: %s", raw)
	}
	flat, path := sarif.Runs[0].Results[0], sarif.Runs[0].Results[1]
	if len(flat.Properties.EscalationPath) != 0 {
		t.Errorf("flat finding carries an escalation_path")
	}
	if len(path.Properties.EscalationPath) != 1 || path.Properties.EscalationPath[0].Action != "bound_to_cluster_admin" {
		t.Errorf("escalation_path = %+v, want the one bound_to_cluster_admin hop", path.Properties.EscalationPath)
	}
	if len(path.Properties.AlternateEscalationPath) != 1 || path.Properties.AlternateEscalationPath[0].Action != "impersonate_user" {
		t.Errorf("alternate_escalation_path = %+v, want the one impersonate_user hop", path.Properties.AlternateEscalationPath)
	}
}

func TestAttackPathOverviews(t *testing.T) {
	t.Parallel()

	if got := AttackPathOverviews(selectionFixture(5, 0)); got != nil {
		t.Fatalf("AttackPathOverviews() with no attack path = %+v, want nil", got)
	}

	sa := func(name string) *models.SubjectRef {
		return &models.SubjectRef{Kind: "ServiceAccount", Namespace: "apps", Name: name}
	}
	hops := func(actions ...string) []models.EscalationHop {
		out := make([]models.EscalationHop, 0, len(actions))
		for i, a := range actions {
			out = append(out, models.EscalationHop{Step: i + 1, Action: a})
		}
		return out
	}
	findings := []models.Finding{
		// Node root: two paths from one identity do not count as two identities.
		{ID: "n1", RuleID: "KUBE-PRIVESC-PATH-NODE-ESCAPE", Severity: models.SeverityCritical, Score: 9.4, Subject: sa("builder"), Tags: []string{"target:node_escape"}, EscalationPath: hops("pod_create_privileged_escape")},
		// cluster-admin: the 1-hop chain beats the 3-hop chain of the same score.
		{ID: "c1", RuleID: "KUBE-PRIVESC-PATH-CLUSTER-ADMIN", Severity: models.SeverityCritical, Score: 9.0, Subject: sa("long"), Tags: []string{"target:cluster_admin_equivalent"}, EscalationPath: hops("token_request", "impersonate_user", "wildcard_permission")},
		{ID: "c2", RuleID: "KUBE-PRIVESC-PATH-CLUSTER-ADMIN", Severity: models.SeverityCritical, Score: 9.0, Subject: sa("short"), Tags: []string{"target:cluster_admin_equivalent"}, EscalationPath: hops("bound_to_cluster_admin")},
		{ID: "n2", RuleID: "KUBE-PRIVESC-PATH-NODE-ESCAPE", Severity: models.SeverityHigh, Score: 8.0, Subject: sa("builder"), Tags: []string{"target:node_escape"}, EscalationPath: hops("exec_pod", "pod_host_escape")},
		// A flat finding is not an attack path.
		{ID: "f1", RuleID: "KUBE-PRIVESC-017", Severity: models.SeverityCritical, Score: 10},
	}

	got := AttackPathOverviews(findings)
	if len(got) != 2 {
		t.Fatalf("got %d rows, want 2: %+v", len(got), got)
	}
	// cluster-admin is the most dangerous sink, so it is first, as in the HTML tab.
	if got[0].Sink != "cluster-admin" || got[0].Paths != 2 || got[0].Identities != 2 {
		t.Errorf("row 0 = %+v, want cluster-admin with 2 paths from 2 identities", got[0])
	}
	if got[0].Source != "ServiceAccount/apps/short" || strings.Join(got[0].Actions, ",") != "bound_to_cluster_admin" {
		t.Errorf("row 0 chain = %s via %v, want the 1-hop chain from ServiceAccount/apps/short", got[0].Source, got[0].Actions)
	}
	if got[1].Sink != "Node root" || got[1].Paths != 2 || got[1].Identities != 1 {
		t.Errorf("row 1 = %+v, want Node root with 2 paths from 1 identity", got[1])
	}
}
