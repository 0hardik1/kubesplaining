package report

import (
	"testing"

	"github.com/0hardik1/kubesplaining/internal/compliance"
	"github.com/0hardik1/kubesplaining/internal/models"
)

func TestBuildComplianceSection_EmptyInput(t *testing.T) {
	got := buildComplianceSection(nil)
	if got.Total != 0 || got.UnmappedCount != 0 || len(got.Frameworks) != 0 {
		t.Errorf("expected zero section for empty input, got %+v", got)
	}
}

func TestBuildComplianceSection_GroupsByFrameworkAndControl(t *testing.T) {
	findings := compliance.Apply([]models.Finding{
		{ID: "RULE:1", RuleID: "KUBE-PRIVESC-008", Severity: models.SeverityCritical, Score: 9.8},
		{ID: "RULE:2", RuleID: "KUBE-PRIVESC-009", Severity: models.SeverityCritical, Score: 9.6},
		{ID: "RULE:3", RuleID: "KUBE-CONFIGMAP-002", Severity: models.SeverityHigh, Score: 7.5},
		{ID: "RULE:4", RuleID: "KUBE-INVENTED-001", Severity: models.SeverityLow, Score: 2.0}, // unmapped
	})

	got := buildComplianceSection(findings)

	if got.UnmappedCount != 1 {
		t.Errorf("UnmappedCount = %d, want 1", got.UnmappedCount)
	}
	if got.Total != 3 {
		t.Errorf("Total = %d, want 3", got.Total)
	}

	var cis, nsa *ComplianceFrameworkView
	for i := range got.Frameworks {
		switch got.Frameworks[i].Slug {
		case compliance.FrameworkCIS19:
			cis = &got.Frameworks[i]
		case compliance.FrameworkNSA:
			nsa = &got.Frameworks[i]
		}
	}
	if cis == nil {
		t.Fatal("expected CIS framework view")
	}
	if nsa == nil {
		t.Fatal("expected NSA framework view")
	}

	// Both KUBE-PRIVESC-008 and -009 map to CIS 5.1.8, so the control should aggregate.
	var found5_1_8 *ComplianceControlRow
	for i := range cis.Controls {
		if cis.Controls[i].Control == "5.1.8" {
			found5_1_8 = &cis.Controls[i]
			break
		}
	}
	if found5_1_8 == nil {
		t.Fatal("expected CIS 5.1.8 control row")
	}
	if found5_1_8.Summary.Total != 2 {
		t.Errorf("CIS 5.1.8 should aggregate both findings; got Total=%d", found5_1_8.Summary.Total)
	}
}

func TestBuildComplianceSection_FindingsSortedInControl(t *testing.T) {
	findings := compliance.Apply([]models.Finding{
		{ID: "RULE:LOW", RuleID: "KUBE-PRIVESC-008", Severity: models.SeverityLow, Score: 2.0},
		{ID: "RULE:HIGH", RuleID: "KUBE-PRIVESC-008", Severity: models.SeverityHigh, Score: 7.0},
		{ID: "RULE:CRIT", RuleID: "KUBE-PRIVESC-008", Severity: models.SeverityCritical, Score: 9.5},
	})

	got := buildComplianceSection(findings)
	if len(got.Frameworks) == 0 {
		t.Fatal("expected at least one framework")
	}
	row := got.Frameworks[0].Controls[0]
	if len(row.Findings) != 3 {
		t.Fatalf("expected 3 findings under the control, got %d", len(row.Findings))
	}
	if row.Findings[0].Severity != models.SeverityCritical {
		t.Errorf("expected critical first, got %s", row.Findings[0].Severity)
	}
	if row.Findings[2].Severity != models.SeverityLow {
		t.Errorf("expected low last, got %s", row.Findings[2].Severity)
	}
}

func TestBuildComplianceSection_DedupesFindingAcrossSameControl(t *testing.T) {
	// Same finding ID under the same control should count once.
	findings := compliance.Apply([]models.Finding{
		{ID: "RULE:DUPE", RuleID: "KUBE-PRIVESC-008", Severity: models.SeverityHigh, Score: 7.0},
	})
	// Manually duplicate the FrameworkRef so a single finding shows two refs for the same control.
	findings[0].Frameworks = append(findings[0].Frameworks, findings[0].Frameworks[0])
	got := buildComplianceSection(findings)
	for _, fr := range got.Frameworks {
		for _, ctrl := range fr.Controls {
			if len(ctrl.Findings) != 1 {
				t.Errorf("dedupe failed: control %q has %d findings, want 1", ctrl.Control, len(ctrl.Findings))
			}
		}
	}
}
