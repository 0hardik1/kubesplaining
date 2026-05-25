package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// pathFinding builds a KUBE-PRIVESC-PATH-* finding for the section tests. The
// target sink is carried on a "target:<slug>" tag exactly as the privesc
// analyzer emits it, so heroSinkSlug resolves it the same way in tests as in
// production.
func pathFinding(ruleID, sinkTag, subjName string, sev models.Severity, score float64, hops []models.EscalationHop) models.Finding {
	return models.Finding{
		ID:             ruleID + ":ServiceAccount/default/" + subjName + ":" + sinkTag,
		RuleID:         ruleID,
		Severity:       sev,
		Score:          score,
		Category:       models.CategoryPrivilegeEscalation,
		Title:          "Privilege-escalation path",
		Subject:        &models.SubjectRef{Kind: "ServiceAccount", Name: subjName, Namespace: "default"},
		Tags:           []string{"module:privesc", "target:" + sinkTag},
		EscalationPath: hops,
	}
}

func TestBuildPrivescPathsGroupsAndOrders(t *testing.T) {
	t.Parallel()

	from := models.SubjectRef{Kind: "ServiceAccount", Name: "deployer", Namespace: "default"}
	findings := []models.Finding{
		// node_escape: HIGH, two hops.
		pathFinding("KUBE-PRIVESC-PATH-NODE-ESCAPE", "node_escape", "deployer", models.SeverityHigh, 8.0, []models.EscalationHop{
			{Step: 1, Action: "pod_create_privileged_escape", FromSubject: from, Permission: "create pods"},
			{Step: 2, Action: "pod_host_escape", FromSubject: from, Gains: "node root"},
		}),
		// cluster_admin: CRITICAL, one hop — must sort to the front (sink priority 0).
		pathFinding("KUBE-PRIVESC-PATH-CLUSTER-ADMIN", "cluster_admin_equivalent", "imp", models.SeverityCritical, 9.8, []models.EscalationHop{
			{Step: 1, Action: "impersonate", FromSubject: models.SubjectRef{Kind: "ServiceAccount", Name: "imp", Namespace: "default"}, Permission: "impersonate users"},
		}),
		// A non-path finding that must be ignored entirely.
		{ID: "x", RuleID: "KUBE-PRIVESC-006", Severity: models.SeverityHigh, Score: 7.6, Category: models.CategoryDataExfiltration},
	}

	sec := buildPrivescPaths(findings)

	if sec.Total != 2 {
		t.Fatalf("Total = %d, want 2 (non-PATH finding must be excluded)", sec.Total)
	}
	if len(sec.Groups) != 2 {
		t.Fatalf("len(Groups) = %d, want 2", len(sec.Groups))
	}

	// cluster-admin (priority 0) sorts ahead of node-escape (priority 3).
	if got := sec.Groups[0].SinkSlug; got != "cluster_admin_equivalent" {
		t.Errorf("Groups[0].SinkSlug = %q, want cluster_admin_equivalent", got)
	}
	if got := sec.Groups[0].SinkLabel; got != "cluster-admin" {
		t.Errorf("Groups[0].SinkLabel = %q, want cluster-admin", got)
	}
	if got := sec.Groups[0].SevClass; got != "crit" {
		t.Errorf("Groups[0].SevClass = %q, want crit", got)
	}
	if got := sec.Groups[0].Cards[0].RuleID; got != "KUBE-PRIVESC-PATH-CLUSTER-ADMIN" {
		t.Errorf("Groups[0] first card RuleID = %q, want KUBE-PRIVESC-PATH-CLUSTER-ADMIN", got)
	}
	if got := sec.Groups[0].Cards[0].Anchor; got != "finding-KUBE-PRIVESC-PATH-CLUSTER-ADMIN" {
		t.Errorf("card Anchor = %q, want finding-KUBE-PRIVESC-PATH-CLUSTER-ADMIN", got)
	}
	if got := sec.Groups[0].Cards[0].HopCount; got != 1 {
		t.Errorf("cluster-admin card HopCount = %d, want 1", got)
	}

	if got := sec.Groups[1].SinkSlug; got != "node_escape" {
		t.Errorf("Groups[1].SinkSlug = %q, want node_escape", got)
	}
	if got := sec.Groups[1].Cards[0].Source; got != "ServiceAccount/default/deployer" {
		t.Errorf("node-escape card Source = %q, want ServiceAccount/default/deployer", got)
	}
}

func TestBuildPrivescPathsEmpty(t *testing.T) {
	t.Parallel()
	sec := buildPrivescPaths([]models.Finding{
		{ID: "x", RuleID: "KUBE-PRIVESC-006", Severity: models.SeverityHigh},
	})
	if sec.Total != 0 || len(sec.Groups) != 0 {
		t.Fatalf("expected zero-value section, got Total=%d Groups=%d", sec.Total, len(sec.Groups))
	}
}

func TestHTMLReportRendersPrivescPathsTab(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	snapshot := models.NewSnapshot()
	from := models.SubjectRef{Kind: "ServiceAccount", Name: "risky", Namespace: "default"}
	findings := []models.Finding{
		pathFinding("KUBE-PRIVESC-PATH-CLUSTER-ADMIN", "cluster_admin_equivalent", "risky", models.SeverityCritical, 9.8, []models.EscalationHop{
			{Step: 1, Action: "impersonate", FromSubject: from, Permission: "impersonate users", Gains: "cluster-admin"},
		}),
	}

	if _, err := Write(tmpDir, []string{"html"}, snapshot, findings); err != nil {
		t.Fatalf("Write html: %v", err)
	}
	htmlBytes, err := os.ReadFile(filepath.Join(tmpDir, "report.html"))
	if err != nil {
		t.Fatalf("read report.html: %v", err)
	}
	html := string(htmlBytes)

	mustContain := []string{
		`data-tab="privesc"`,                              // tab button + section both carry this
		`id="tabbtn-privesc"`,                             // the tab button
		`id="tab-privesc"`,                                // the section
		`Privilege-Escalation Paths`,                      // hero heading
		`class="pp-card-source"`,                          // a path card rendered
		`class="pp-card-summary"`,                         // card body rendered
		`href="#finding-KUBE-PRIVESC-PATH-CLUSTER-ADMIN"`, // deep-link into Findings tab
		`cluster-admin`,                                   // sink label
	}
	for _, needle := range mustContain {
		if !strings.Contains(html, needle) {
			t.Errorf("rendered HTML missing %q", needle)
		}
	}
}

func TestHTMLReportOmitsPrivescTabWhenNoPaths(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	snapshot := models.NewSnapshot()
	findings := []models.Finding{
		{
			ID:       "f1",
			RuleID:   "KUBE-PRIVESC-006",
			Severity: models.SeverityHigh,
			Score:    7.6,
			Category: models.CategoryDataExfiltration,
			Title:    "Secret read",
			Subject:  &models.SubjectRef{Kind: "ServiceAccount", Name: "reader", Namespace: "default"},
			Tags:     []string{"module:rbac"},
		},
	}

	if _, err := Write(tmpDir, []string{"html"}, snapshot, findings); err != nil {
		t.Fatalf("Write html: %v", err)
	}
	htmlBytes, err := os.ReadFile(filepath.Join(tmpDir, "report.html"))
	if err != nil {
		t.Fatalf("read report.html: %v", err)
	}
	html := string(htmlBytes)

	for _, needle := range []string{`id="tab-privesc"`, `id="tabbtn-privesc"`} {
		if strings.Contains(html, needle) {
			t.Errorf("expected no privesc tab markup when there are no paths, but found %q", needle)
		}
	}
}
