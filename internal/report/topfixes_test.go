package report

import (
	"strings"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
)

func TestBuildTopFixes_EmptyAndOwnerless(t *testing.T) {
	t.Parallel()

	if got := buildTopFixes(nil); got != nil {
		t.Errorf("nil input should produce nil slice, got %#v", got)
	}

	// Findings with neither Subject nor Resource have no owner to fix, so they
	// belong in the cluster-level section and should be skipped here.
	if got := buildTopFixes([]models.Finding{
		{ID: "f1", RuleID: "KUBE-ADMISSION-001", Score: 7.0},
	}); got != nil {
		t.Errorf("ownerless findings should produce nil slice, got %#v", got)
	}
}

func TestBuildTopFixes_GroupsBySubjectAndSumsScores(t *testing.T) {
	t.Parallel()

	subjA := &models.SubjectRef{Kind: "ServiceAccount", Name: "builder", Namespace: "default"}
	subjB := &models.SubjectRef{Kind: "ServiceAccount", Name: "reader", Namespace: "default"}

	findings := []models.Finding{
		// subjA: dominant prefix KUBE-PRIVESC-PATH, sum 9.5 + 7.5 = 17.0
		{ID: "1", RuleID: "KUBE-PRIVESC-PATH-CLUSTER-ADMIN", Score: 9.5, Subject: subjA},
		{ID: "2", RuleID: "KUBE-PRIVESC-005", Score: 7.5, Subject: subjA},
		// subjB: dominant prefix KUBE-RBAC-OVERBROAD, sum 8.0
		{ID: "3", RuleID: "KUBE-RBAC-OVERBROAD-001", Score: 8.0, Subject: subjB},
	}

	got := buildTopFixes(findings)
	if len(got) != 2 {
		t.Fatalf("expected 2 top-fix rows, got %d: %+v", len(got), got)
	}

	if got[0].Rank != 1 {
		t.Errorf("first row Rank = %d, want 1", got[0].Rank)
	}
	if got[1].Rank != 2 {
		t.Errorf("second row Rank = %d, want 2", got[1].Rank)
	}

	// subjA wins on summed score.
	if got[0].ScoreImpact != 17.0 {
		t.Errorf("top score = %v, want 17.0", got[0].ScoreImpact)
	}
	if got[0].FindingsCount != 2 {
		t.Errorf("top FindingsCount = %d, want 2", got[0].FindingsCount)
	}
	// The action should reference the dominant rule prefix (privesc-path) for subjA.
	if !strings.Contains(got[0].Action, "privilege-escalation") {
		t.Errorf("top action should mention privilege escalation for subjA, got: %q", got[0].Action)
	}
	if !strings.Contains(got[0].Action, "builder") {
		t.Errorf("top action should name the subject (builder), got: %q", got[0].Action)
	}

	// subjB shows up second with the overbroad-role messaging.
	if got[1].ScoreImpact != 8.0 {
		t.Errorf("second score = %v, want 8.0", got[1].ScoreImpact)
	}
	if !strings.Contains(got[1].Action, "overbroad") {
		t.Errorf("second action should mention overbroad role for subjB, got: %q", got[1].Action)
	}
}

func TestBuildTopFixes_FallsBackToResourceWhenSubjectMissing(t *testing.T) {
	t.Parallel()

	res := &models.ResourceRef{Kind: "Deployment", Name: "risky", Namespace: "default"}
	findings := []models.Finding{
		{ID: "1", RuleID: "KUBE-PODSEC-ROOT-001", Score: 7.0, Resource: res},
		{ID: "2", RuleID: "KUBE-HOSTPATH-001", Score: 6.5, Resource: res},
	}

	got := buildTopFixes(findings)
	if len(got) != 1 {
		t.Fatalf("expected 1 row from a single Resource bucket, got %d", len(got))
	}
	if got[0].ScoreImpact != 13.5 {
		t.Errorf("ScoreImpact = %v, want 13.5", got[0].ScoreImpact)
	}
	// Dominant prefix is podsec-root (alphabetically lower than hostpath); the
	// action should reference the deployment by name.
	if !strings.Contains(got[0].Action, "risky") {
		t.Errorf("action should name the resource (risky), got: %q", got[0].Action)
	}
	if len(got[0].RuleIDs) != 2 {
		t.Errorf("expected both unique rule IDs, got %v", got[0].RuleIDs)
	}
}

func TestBuildTopFixes_CapsAtFive(t *testing.T) {
	t.Parallel()

	findings := make([]models.Finding, 0, 7)
	for i := 0; i < 7; i++ {
		subj := &models.SubjectRef{Kind: "ServiceAccount", Name: string(rune('a' + i)), Namespace: "ns"}
		// Use decreasing scores so the ranking is stable and the row order is
		// trivially verifiable.
		findings = append(findings, models.Finding{
			ID:      string(rune('1' + i)),
			RuleID:  "KUBE-RBAC-OVERBROAD-001",
			Score:   float64(7 - i),
			Subject: subj,
		})
	}

	got := buildTopFixes(findings)
	if len(got) != maxTopFixes {
		t.Fatalf("expected %d rows (cap), got %d", maxTopFixes, len(got))
	}
	if got[0].ScoreImpact != 7.0 || got[len(got)-1].ScoreImpact != 3.0 {
		t.Errorf("rows out of order: first=%v last=%v", got[0].ScoreImpact, got[len(got)-1].ScoreImpact)
	}
}

func TestBuildTopFixes_DeterministicRuleIDOrder(t *testing.T) {
	t.Parallel()

	subj := &models.SubjectRef{Kind: "ServiceAccount", Name: "builder", Namespace: "default"}
	findings := []models.Finding{
		{ID: "1", RuleID: "KUBE-RBAC-OVERBROAD-001", Score: 5.0, Subject: subj},
		{ID: "2", RuleID: "KUBE-PRIVESC-005", Score: 5.0, Subject: subj},
		{ID: "3", RuleID: "KUBE-SA-DEFAULT-001", Score: 5.0, Subject: subj},
	}

	got := buildTopFixes(findings)
	if len(got) != 1 {
		t.Fatalf("expected 1 row, got %d", len(got))
	}
	want := []string{"KUBE-PRIVESC-005", "KUBE-RBAC-OVERBROAD-001", "KUBE-SA-DEFAULT-001"}
	if len(got[0].RuleIDs) != len(want) {
		t.Fatalf("expected %d rule IDs, got %d", len(want), len(got[0].RuleIDs))
	}
	for i, w := range want {
		if got[0].RuleIDs[i] != w {
			t.Errorf("RuleIDs[%d] = %q, want %q", i, got[0].RuleIDs[i], w)
		}
	}
}

func TestBuildTopFixes_DeduplicatesRuleIDsAcrossInstances(t *testing.T) {
	t.Parallel()

	subj := &models.SubjectRef{Kind: "ServiceAccount", Name: "builder", Namespace: "default"}
	// Same rule fires three times against three distinct resources owned by the
	// same subject. The topfix row should sum every score but list the rule once.
	findings := []models.Finding{
		{ID: "1", RuleID: "KUBE-RBAC-OVERBROAD-001", Score: 8.0, Subject: subj},
		{ID: "2", RuleID: "KUBE-RBAC-OVERBROAD-001", Score: 7.0, Subject: subj},
		{ID: "3", RuleID: "KUBE-RBAC-OVERBROAD-001", Score: 6.0, Subject: subj},
	}

	got := buildTopFixes(findings)
	if len(got) != 1 {
		t.Fatalf("expected 1 row, got %d", len(got))
	}
	if got[0].ScoreImpact != 21.0 {
		t.Errorf("ScoreImpact = %v, want 21.0", got[0].ScoreImpact)
	}
	if got[0].FindingsCount != 1 {
		t.Errorf("FindingsCount = %d, want 1 (deduped)", got[0].FindingsCount)
	}
	if len(got[0].RuleIDs) != 1 {
		t.Errorf("RuleIDs should be deduped to 1 entry, got %v", got[0].RuleIDs)
	}
}

func TestBuildTopFixes_TracksSubjectsWhenResourceBucket(t *testing.T) {
	t.Parallel()

	subjA := &models.SubjectRef{Kind: "ServiceAccount", Name: "alpha", Namespace: "ns"}
	subjB := &models.SubjectRef{Kind: "ServiceAccount", Name: "beta", Namespace: "ns"}
	resource := &models.ResourceRef{Kind: "Deployment", Name: "shared", Namespace: "ns"}

	findings := []models.Finding{
		{ID: "1", RuleID: "KUBE-PODSEC-ROOT-001", Score: 6.0, Resource: resource, Subject: subjA},
		{ID: "2", RuleID: "KUBE-PODSEC-ROOT-001", Score: 5.0, Resource: resource, Subject: subjB},
	}

	got := buildTopFixes(findings)
	// Both findings have a Subject so they group by subject (alpha and beta),
	// producing two separate rows. The Subjects slice on each row carries the
	// subject display string for context.
	if len(got) != 2 {
		t.Fatalf("expected 2 subject rows, got %d", len(got))
	}
	foundAlpha, foundBeta := false, false
	for _, row := range got {
		for _, s := range row.Subjects {
			switch {
			case strings.Contains(s, "alpha"):
				foundAlpha = true
			case strings.Contains(s, "beta"):
				foundBeta = true
			}
		}
	}
	if !foundAlpha || !foundBeta {
		t.Errorf("expected both subjects to appear across rows, got alpha=%v beta=%v: %+v", foundAlpha, foundBeta, got)
	}
}

func TestRulePrefix_Variants(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in, want string
	}{
		{"KUBE-PRIVESC-PATH-CLUSTER-ADMIN", "KUBE-PRIVESC-PATH"},
		{"KUBE-PRIVESC-PATH-NODE-ESCAPE", "KUBE-PRIVESC-PATH"},
		{"KUBE-PRIVESC-005", "KUBE-PRIVESC"},
		{"KUBE-RBAC-OVERBROAD-001", "KUBE-RBAC-OVERBROAD"},
		{"KUBE-PODSEC-APE-001", "KUBE-PODSEC-APE"},
		{"KUBE-LP-UNUSED-VERB-001", "KUBE-LP-UNUSED-VERB"},
		{"KUBE-LP-WILDCARD-USED-PARTIAL-001", "KUBE-LP-WILDCARD-USED-PARTIAL"},
		{"too-short", ""},
		{"", ""},
	}
	for _, tc := range cases {
		if got := rulePrefix(tc.in); got != tc.want {
			t.Errorf("rulePrefix(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestDominantRulePrefix_TiebreakPrefersLongerThenAlphabetical(t *testing.T) {
	t.Parallel()

	// Longer prefix wins on a length tie because it's strictly more specific:
	// KUBE-PRIVESC-PATH (17 chars) beats KUBE-PRIVESC (12 chars) at equal count.
	if got := dominantRulePrefix([]string{"KUBE-PRIVESC-005", "KUBE-PRIVESC-PATH-CLUSTER-ADMIN"}); got != "KUBE-PRIVESC-PATH" {
		t.Errorf("longer-prefix tiebreak: got %q, want KUBE-PRIVESC-PATH", got)
	}
	// Equal-length tie falls through to alphabetical.
	if got := dominantRulePrefix([]string{"KUBE-RBAC-STALE-001", "KUBE-RBAC-OVERBROAD-001"}); got != "KUBE-RBAC-OVERBROAD" {
		t.Errorf("alphabetical-tiebreak: got %q, want KUBE-RBAC-OVERBROAD", got)
	}
}
