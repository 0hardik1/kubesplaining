package compliance

import (
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
)

func TestApply_PopulatesFrameworksForMappedRule(t *testing.T) {
	findings := []models.Finding{{RuleID: "KUBE-PRIVESC-008"}}

	out := Apply(findings)

	if len(out) != 1 {
		t.Fatalf("len(out) = %d, want 1", len(out))
	}
	if len(out[0].Frameworks) == 0 {
		t.Fatal("expected frameworks to be populated for KUBE-PRIVESC-008")
	}
	var sawCIS, sawNSA bool
	for _, ref := range out[0].Frameworks {
		switch ref.Framework {
		case FrameworkCIS19:
			sawCIS = true
		case FrameworkNSA:
			sawNSA = true
		}
	}
	if !sawCIS || !sawNSA {
		t.Errorf("expected both CIS and NSA refs; got %+v", out[0].Frameworks)
	}
}

func TestApply_LeavesUnmappedRuleEmpty(t *testing.T) {
	findings := []models.Finding{{RuleID: "KUBE-NONEXISTENT-999"}}

	out := Apply(findings)

	if len(out[0].Frameworks) != 0 {
		t.Errorf("expected empty Frameworks for unmapped rule, got %+v", out[0].Frameworks)
	}
}

func TestApply_IsIdempotent(t *testing.T) {
	findings := []models.Finding{{RuleID: "KUBE-PRIVESC-008"}}

	first := Apply(findings)
	gotN := len(first[0].Frameworks)

	second := Apply(findings)
	if len(second[0].Frameworks) != gotN {
		t.Errorf("Apply not idempotent: %d → %d", gotN, len(second[0].Frameworks))
	}
}

func TestApply_DoesNotShareSliceAcrossFindings(t *testing.T) {
	findings := []models.Finding{
		{RuleID: "KUBE-PRIVESC-008"},
		{RuleID: "KUBE-PRIVESC-008"},
	}
	out := Apply(findings)
	// Mutating one finding's slice must not leak into the other or the source table.
	out[0].Frameworks[0].Title = "mutated"
	if out[1].Frameworks[0].Title == "mutated" {
		t.Fatal("Apply leaked the same slice across findings; copies must be independent")
	}
	if ControlsFor("KUBE-PRIVESC-008")[0].Title == "mutated" {
		t.Fatal("Apply leaked into the static mapping table")
	}
}

func TestResolveFramework(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"cis", FrameworkCIS19},
		{"CIS", FrameworkCIS19},
		{"cis-1.9", FrameworkCIS19},
		{"CIS-1.9", FrameworkCIS19},
		{"nsa", FrameworkNSA},
		{"NSA-CISA-1.2", FrameworkNSA},
		{"hardening-guide", FrameworkNSA},
		{"", ""},
		{"unknown-framework", ""},
	}
	for _, c := range cases {
		got := ResolveFramework(c.in)
		if got != c.want {
			t.Errorf("ResolveFramework(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestFilterByFramework(t *testing.T) {
	all := Apply([]models.Finding{
		{RuleID: "KUBE-PRIVESC-008"},         // CIS + NSA
		{RuleID: "KUBE-CONFIGMAP-002"},       // NSA only
		{RuleID: "KUBE-IMAGE-LATEST-001"},    // NSA only
		{RuleID: "KUBE-NETPOL-COVERAGE-001"}, // CIS + NSA
	})

	if got := FilterByFramework(all, nil); len(got) != len(all) {
		t.Errorf("empty filter dropped findings: %d → %d", len(all), len(got))
	}
	cis := FilterByFramework(all, []string{FrameworkCIS19})
	if len(cis) != 2 {
		t.Errorf("CIS filter: got %d, want 2", len(cis))
	}
	nsa := FilterByFramework(all, []string{FrameworkNSA})
	if len(nsa) != 4 {
		t.Errorf("NSA filter: got %d, want 4", len(nsa))
	}
	multi := FilterByFramework(all, []string{FrameworkCIS19, FrameworkNSA})
	if len(multi) != 4 {
		t.Errorf("CIS+NSA filter: got %d, want 4", len(multi))
	}
	bogus := FilterByFramework(all, []string{"NOT-A-FRAMEWORK"})
	if len(bogus) != 0 {
		t.Errorf("unknown framework filter: got %d, want 0", len(bogus))
	}
}

func TestFrameworks_DeclaresExpectedSlugs(t *testing.T) {
	want := map[string]bool{FrameworkCIS19: false, FrameworkNSA: false}
	for _, f := range Frameworks() {
		if _, ok := want[f.Slug]; !ok {
			t.Errorf("unexpected framework slug: %q", f.Slug)
		}
		want[f.Slug] = true
	}
	for slug, present := range want {
		if !present {
			t.Errorf("missing framework slug: %q", slug)
		}
	}
}
