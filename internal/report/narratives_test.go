package report

import (
	"strings"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// TestBuildHeroChainsEmpty asserts the section disappears when no privesc paths exist.
func TestBuildHeroChainsEmpty(t *testing.T) {
	t.Parallel()
	out := buildHeroChains([]models.Finding{
		{RuleID: "KUBE-PODSEC-PRIV-001", Severity: models.SeverityHigh, Score: 8.0},
		{RuleID: "KUBE-RBAC-OVERBROAD-001", Severity: models.SeverityMedium, Score: 6.0},
	})
	if out != nil {
		t.Fatalf("expected nil for non-privesc findings, got %d cards", len(out))
	}
}

// TestBuildHeroChainsRanksClusterAdminFirst confirms the sink-priority bucket
// pushes a cluster-admin path above a kube-system-secrets path even when the
// secrets path scores higher numerically.
func TestBuildHeroChainsRanksClusterAdminFirst(t *testing.T) {
	t.Parallel()
	findings := []models.Finding{
		{
			ID:       "KUBE-PRIVESC-PATH-KUBE-SYSTEM-SECRETS:ServiceAccount/default/reader:kube_system_secrets",
			RuleID:   "KUBE-PRIVESC-PATH-KUBE-SYSTEM-SECRETS",
			Severity: models.SeverityHigh,
			Score:    9.5,
			Title:    "ServiceAccount/default/reader can read kube-system secrets",
			Subject:  &models.SubjectRef{Kind: "ServiceAccount", Name: "reader", Namespace: "default"},
			Tags:     []string{"module:privesc", "target:kube_system_secrets"},
			EscalationPath: []models.EscalationHop{
				{Step: 1, Action: "read_secrets", FromSubject: models.SubjectRef{Kind: "ServiceAccount", Name: "reader", Namespace: "default"}, ToSubject: models.SubjectRef{Kind: "Sink", Name: "kube-system-secrets"}, Permission: "get,list secrets"},
			},
		},
		{
			ID:       "KUBE-PRIVESC-PATH-CLUSTER-ADMIN:ServiceAccount/default/builder:cluster_admin_equivalent",
			RuleID:   "KUBE-PRIVESC-PATH-CLUSTER-ADMIN",
			Severity: models.SeverityCritical,
			Score:    8.0,
			Title:    "ServiceAccount/default/builder can reach cluster-admin",
			Subject:  &models.SubjectRef{Kind: "ServiceAccount", Name: "builder", Namespace: "default"},
			Tags:     []string{"module:privesc", "target:cluster_admin_equivalent"},
			EscalationPath: []models.EscalationHop{
				{Step: 1, Action: "bind_escalate", FromSubject: models.SubjectRef{Kind: "ServiceAccount", Name: "builder", Namespace: "default"}, ToSubject: models.SubjectRef{Kind: "ClusterRole", Name: "cluster-admin"}, Permission: "rbac/clusterrolebindings:create"},
				{Step: 2, Action: "use_role", FromSubject: models.SubjectRef{Kind: "ClusterRole", Name: "cluster-admin"}, ToSubject: models.SubjectRef{Kind: "Sink", Name: "cluster-admin"}, Permission: "*"},
			},
		},
	}
	out := buildHeroChains(findings)
	if len(out) != 2 {
		t.Fatalf("expected 2 hero cards, got %d", len(out))
	}
	if out[0].RuleID != "KUBE-PRIVESC-PATH-CLUSTER-ADMIN" {
		t.Fatalf("expected cluster-admin path first, got %s", out[0].RuleID)
	}
	if out[0].Sink != string(models.TargetClusterAdmin) {
		t.Fatalf("expected first sink %s, got %s", models.TargetClusterAdmin, out[0].Sink)
	}
	if out[0].Anchor != "finding-KUBE-PRIVESC-PATH-CLUSTER-ADMIN" {
		t.Fatalf("anchor mismatch: %s", out[0].Anchor)
	}
	if len(out[0].Hops) != 2 {
		t.Fatalf("expected 2 hops on first card, got %d", len(out[0].Hops))
	}
	if !strings.Contains(out[0].Summary, "cluster-admin") {
		t.Fatalf("expected cluster-admin in summary, got %q", out[0].Summary)
	}
	if !strings.Contains(out[0].Summary, "builder") {
		t.Fatalf("expected subject name in summary, got %q", out[0].Summary)
	}
}

// TestBuildHeroChainsCapsAtThree confirms the slate is bounded so the panel never
// pushes the rest of the report off-screen.
func TestBuildHeroChainsCapsAtThree(t *testing.T) {
	t.Parallel()
	var findings []models.Finding
	for i := 0; i < 8; i++ {
		findings = append(findings, models.Finding{
			ID:       "KUBE-PRIVESC-PATH-CLUSTER-ADMIN:ServiceAccount/default/sa-" + string(rune('a'+i)) + ":cluster_admin_equivalent",
			RuleID:   "KUBE-PRIVESC-PATH-CLUSTER-ADMIN",
			Severity: models.SeverityCritical,
			Score:    9.5,
			Title:    "Path " + string(rune('a'+i)),
			Subject:  &models.SubjectRef{Kind: "ServiceAccount", Name: "sa-" + string(rune('a'+i)), Namespace: "default"},
			Tags:     []string{"module:privesc", "target:cluster_admin_equivalent"},
			EscalationPath: []models.EscalationHop{
				{Step: 1, Action: "bind_escalate"},
			},
		})
	}
	out := buildHeroChains(findings)
	if len(out) != 3 {
		t.Fatalf("expected hero cap at 3, got %d", len(out))
	}
}

// TestBuildHeroChainsFavorsShorterChains: at the same sink and severity, a 1-hop
// path should be ranked above a 4-hop path because shorter chains are more
// directly exploitable.
func TestBuildHeroChainsFavorsShorterChains(t *testing.T) {
	t.Parallel()
	long := models.Finding{
		ID:       "long",
		RuleID:   "KUBE-PRIVESC-PATH-CLUSTER-ADMIN",
		Severity: models.SeverityCritical,
		Score:    8.5,
		Title:    "Long chain",
		Subject:  &models.SubjectRef{Kind: "ServiceAccount", Name: "long", Namespace: "default"},
		Tags:     []string{"module:privesc", "target:cluster_admin_equivalent"},
		EscalationPath: []models.EscalationHop{
			{Step: 1}, {Step: 2}, {Step: 3}, {Step: 4},
		},
	}
	short := models.Finding{
		ID:       "short",
		RuleID:   "KUBE-PRIVESC-PATH-CLUSTER-ADMIN",
		Severity: models.SeverityCritical,
		Score:    8.5,
		Title:    "Short chain",
		Subject:  &models.SubjectRef{Kind: "ServiceAccount", Name: "short", Namespace: "default"},
		Tags:     []string{"module:privesc", "target:cluster_admin_equivalent"},
		EscalationPath: []models.EscalationHop{
			{Step: 1, Action: "impersonate"},
		},
	}
	out := buildHeroChains([]models.Finding{long, short})
	if len(out) != 2 {
		t.Fatalf("expected 2 hero cards, got %d", len(out))
	}
	if out[0].Title != "Short chain" {
		t.Fatalf("expected short chain ranked first, got %q", out[0].Title)
	}
}

// TestHeroSinkLabel renders a few sink slugs into the human-readable phrase used
// inside HeroChainCard.Summary, so a regression in the labeling table is caught
// without re-running the whole hero builder.
func TestHeroSinkLabel(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		string(models.TargetClusterAdmin):      "cluster-admin",
		string(models.TargetSystemMasters):     "the system:masters group",
		string(models.TargetKubeSystemSecrets): "kube-system secrets",
		string(models.TargetNodeEscape):        "node root (container escape)",
		string(models.TargetNamespaceAdmin):    "namespace-admin",
		"":                                     "a sensitive sink",
	}
	for slug, want := range cases {
		if got := heroSinkLabel(slug); got != want {
			t.Errorf("heroSinkLabel(%q) = %q, want %q", slug, got, want)
		}
	}
}
