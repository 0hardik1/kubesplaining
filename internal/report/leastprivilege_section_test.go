package report

import (
	"strings"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/permissions"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestRenderVerbsGroupedSingleResourceInline(t *testing.T) {
	got := string(renderVerbsGrouped([]verbResource{
		{Verb: "list", Resource: "pods"},
	}))
	if !strings.Contains(got, `<span class="lp-verb-label">list:</span> pods`) {
		t.Fatalf("expected single-resource inline form, got: %s", got)
	}
	if strings.Contains(got, `lp-verb-resource`) {
		t.Fatalf("single-resource verb should not use block resource spans, got: %s", got)
	}
	if strings.Contains(got, `lp-resource-sep`) {
		t.Fatalf("pipe separator should be gone, got: %s", got)
	}
}

func TestRenderVerbsGroupedMultiResourceStacks(t *testing.T) {
	got := string(renderVerbsGrouped([]verbResource{
		{Verb: "get", Resource: "deployments"},
		{Verb: "get", Resource: "pods"},
		{Verb: "get", Resource: "services"},
	}))
	for _, r := range []string{
		`<span class="lp-verb-resource">deployments</span>`,
		`<span class="lp-verb-resource">pods</span>`,
		`<span class="lp-verb-resource">services</span>`,
	} {
		if !strings.Contains(got, r) {
			t.Fatalf("expected stacked resource %q in: %s", r, got)
		}
	}
	if strings.Contains(got, `lp-resource-sep`) || strings.Contains(got, "|</span>") {
		t.Fatalf("pipe separator should be gone, got: %s", got)
	}
	if strings.Contains(got, `lp-verb-resource-more`) {
		t.Fatalf("no cap requested, should not see overflow tail: %s", got)
	}
}

func TestRenderVerbsGroupedCapTruncatesAndFootnoteFires(t *testing.T) {
	got := string(renderVerbsGroupedOpts([]verbResource{
		{Verb: "get", Resource: "configmaps"},
		{Verb: "get", Resource: "deployments"},
		{Verb: "get", Resource: "nodes"},
		{Verb: "get", Resource: "pods"},
		{Verb: "get", Resource: "secrets"},
		{Verb: "get", Resource: "services"},
	}, verbRenderOpts{
		ResourceCapPerVerb: 4,
		FootNote:           `Truncated — verbs: ["*"] expands to every standard verb the wildcard covers.`,
	}))
	for _, r := range []string{"configmaps", "deployments", "nodes", "pods"} {
		if !strings.Contains(got, `<span class="lp-verb-resource">`+r+`</span>`) {
			t.Fatalf("expected capped chip to keep %q, got: %s", r, got)
		}
	}
	for _, r := range []string{"secrets", "services"} {
		if strings.Contains(got, `<span class="lp-verb-resource">`+r+`</span>`) {
			t.Fatalf("expected %q to be hidden behind the cap, got: %s", r, got)
		}
	}
	if !strings.Contains(got, `<span class="lp-verb-resource-more">+2 more resources</span>`) {
		t.Fatalf("expected +2 more resources tail, got: %s", got)
	}
	if !strings.Contains(got, `<div class="lp-verb-foot-note">Truncated`) {
		t.Fatalf("expected footnote when cap fires, got: %s", got)
	}
}

func TestRenderVerbsGroupedFootnoteSuppressedWithoutTruncation(t *testing.T) {
	got := string(renderVerbsGroupedOpts([]verbResource{
		{Verb: "get", Resource: "pods"},
		{Verb: "get", Resource: "services"},
	}, verbRenderOpts{
		ResourceCapPerVerb: 4,
		FootNote:           `should not appear`,
	}))
	if strings.Contains(got, "lp-verb-foot-note") {
		t.Fatalf("footnote should be hidden when nothing got capped, got: %s", got)
	}
	if strings.Contains(got, "lp-verb-resource-more") {
		t.Fatalf("overflow tail should be hidden when nothing got capped, got: %s", got)
	}
}

func TestRenderVerbsGroupedEmpty(t *testing.T) {
	got := string(renderVerbsGrouped(nil))
	if !strings.Contains(got, "none observed") {
		t.Fatalf("empty input should render the 'none observed' placeholder, got: %s", got)
	}
}

func TestBuildClusterAdminInventory(t *testing.T) {
	snap := models.Snapshot{
		Resources: models.SnapshotResources{
			ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "cluster-admin"},
					RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
					Subjects: []rbacv1.Subject{
						{Kind: "Group", Name: "system:masters"},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "ops-admin"},
					RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
					Subjects: []rbacv1.Subject{
						{Kind: "User", Name: "alice@example.com"},
						{Kind: "ServiceAccount", Namespace: "ops", Name: "deployer"},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "view-binding"},
					RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "view"},
					Subjects:   []rbacv1.Subject{{Kind: "User", Name: "bob@example.com"}},
				},
			},
		},
	}

	rows := buildClusterAdminInventory(snap)
	if len(rows) != 3 {
		t.Fatalf("expected 3 cluster-admin rows (the view binding should be ignored), got %d: %+v", len(rows), rows)
	}
	// Non-system entries must come first.
	if rows[0].IsSystem || rows[1].IsSystem {
		t.Fatalf("expected non-system rows first, got: %+v", rows)
	}
	if !rows[2].IsSystem {
		t.Fatalf("expected the system:masters row last, got: %+v", rows)
	}
	if rows[2].SubjectName != "system:masters" {
		t.Fatalf("expected last row to be system:masters, got %+v", rows[2])
	}
	// Among non-system rows, ServiceAccount (kind alpha-first) precedes User.
	if rows[0].SubjectKind != "ServiceAccount" || rows[1].SubjectKind != "User" {
		t.Fatalf("expected ServiceAccount then User ordering among non-system rows, got: %+v", rows)
	}
}

func TestBuildClusterAdminInventoryEmpty(t *testing.T) {
	if rows := buildClusterAdminInventory(models.Snapshot{}); rows != nil {
		t.Fatalf("empty snapshot should produce no rows, got: %+v", rows)
	}
}

// snapshotWithReaderSA is a small fixture used by the per-subject capability
// tests: one ServiceAccount bound to a ClusterRole that grants get/list on
// secrets and create on pods, plus a User bound to cluster-admin so we can
// assert the "holds cluster-admin equivalent" filter fires for that case too.
func snapshotWithReaderSA() models.Snapshot {
	return models.Snapshot{
		Resources: models.SnapshotResources{
			ClusterRoles: []rbacv1.ClusterRole{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "reader-role"},
					Rules: []rbacv1.PolicyRule{
						{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get", "list"}},
						{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"create"}},
					},
				},
			},
			ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "reader-binding"},
					RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "reader-role"},
					Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "default", Name: "reader"}},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "ops-admin"},
					RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
					Subjects:   []rbacv1.Subject{{Kind: "User", Name: "alice@example.com"}},
				},
			},
		},
	}
}

func TestBuildPerSubjectCapabilitiesIncludesFindingSubject(t *testing.T) {
	snap := snapshotWithReaderSA()
	findings := []models.Finding{
		{
			ID:       "X:1",
			RuleID:   "KUBE-PRIVESC-PATH-KUBE-SYSTEM-SECRETS",
			Severity: models.SeverityHigh,
			Subject:  &models.SubjectRef{Kind: "ServiceAccount", Namespace: "default", Name: "reader"},
			EscalationPath: []models.EscalationHop{
				{
					Step:        1,
					Action:      "read_secrets",
					FromSubject: models.SubjectRef{Kind: "ServiceAccount", Namespace: "default", Name: "reader"},
					ToSubject:   models.SubjectRef{}, // sink — empty by design
					Permission:  "get,list secrets",
				},
			},
		},
	}
	cards := buildPerSubjectCapabilities(snap, findings)
	if len(cards) == 0 {
		t.Fatalf("expected at least one card, got 0")
	}
	// Reader SA (chain-amplified) must come first because of the privesc finding.
	if cards[0].SubjectName != "reader" || cards[0].SubjectKind != "ServiceAccount" {
		t.Fatalf("expected reader SA card first, got %+v", cards[0])
	}
	if !cards[0].ChainAmplified {
		t.Fatalf("expected reader card to be chain-amplified, got %+v", cards[0])
	}
	if len(cards[0].PrivescPaths) != 1 {
		t.Fatalf("expected 1 privesc summary, got %d: %+v", len(cards[0].PrivescPaths), cards[0].PrivescPaths)
	}
	if !strings.Contains(cards[0].PrivescPaths[0], "kube_system_secrets") {
		t.Fatalf("expected privesc summary to mention sink, got %q", cards[0].PrivescPaths[0])
	}
	if len(cards[0].EffectiveRules) != 2 {
		t.Fatalf("expected 2 collapsed effective-rule rows, got %d: %+v", len(cards[0].EffectiveRules), cards[0].EffectiveRules)
	}
	// Effective rules collapse verb-by-resource: "create on pods" and "get,list on secrets".
	gotRules := strings.Join(cards[0].EffectiveRules, "|")
	if !strings.Contains(gotRules, "create on pods@core") || !strings.Contains(gotRules, "get,list on secrets@core") {
		t.Fatalf("expected collapsed rules, got %q", gotRules)
	}
	if len(cards[0].Bindings) != 1 || !strings.Contains(cards[0].Bindings[0], "ClusterRoleBinding/reader-binding") {
		t.Fatalf("expected reader binding label, got %+v", cards[0].Bindings)
	}
}

func TestBuildPerSubjectCapabilitiesIncludesClusterAdminWithoutFinding(t *testing.T) {
	snap := snapshotWithReaderSA()
	cards := buildPerSubjectCapabilities(snap, nil)
	// No findings at all: only the User bound to cluster-admin should produce a
	// card (the reader SA's grants don't include any cluster-admin-equivalent
	// rules, so it gets filtered out when there's no finding either).
	if len(cards) != 1 {
		t.Fatalf("expected 1 card (the cluster-admin User), got %d: %+v", len(cards), cards)
	}
	if cards[0].SubjectKind != "User" || cards[0].SubjectName != "alice@example.com" {
		t.Fatalf("expected cluster-admin User card, got %+v", cards[0])
	}
	if cards[0].ChainAmplified {
		t.Fatalf("cluster-admin User has no finding-based chain, should not be amplified, got %+v", cards[0])
	}
}

func TestBuildPerSubjectCapabilitiesFiltersUnboundSubjects(t *testing.T) {
	// Snapshot with no bindings → no cards regardless of findings.
	if cards := buildPerSubjectCapabilities(models.Snapshot{}, nil); cards != nil {
		t.Fatalf("expected nil cards for empty snapshot, got %+v", cards)
	}
}

func TestCollapseEffectiveRulesCollapsesByResource(t *testing.T) {
	rules := []permissions.EffectiveRule{
		{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list"}},
		{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"watch"}},
		{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"create"}},
	}
	verbs, rows := collapseEffectiveRules(rules)
	wantVerbs := []string{"create", "get", "list", "watch"}
	if !equalStrings(verbs, wantVerbs) {
		t.Fatalf("expected dedup verbs %v, got %v", wantVerbs, verbs)
	}
	want := []string{
		"create on deployments@apps",
		"get,list,watch on pods@core",
	}
	if !equalStrings(rows, want) {
		t.Fatalf("expected collapsed rows %v, got %v", want, rows)
	}
}

func TestSubjectHoldsClusterAdminViaBinding(t *testing.T) {
	perms := &permissions.EffectivePermissions{}
	bindings := []string{"ClusterRoleBinding/foo -> ClusterRole/cluster-admin"}
	if !subjectHoldsClusterAdmin(perms, bindings) {
		t.Fatalf("expected cluster-admin binding to match")
	}
}

func TestSubjectHoldsClusterAdminViaWildcard(t *testing.T) {
	perms := &permissions.EffectivePermissions{
		Rules: []permissions.EffectiveRule{
			{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}},
		},
	}
	if !subjectHoldsClusterAdmin(perms, nil) {
		t.Fatalf("expected wildcard-on-everything to match")
	}
	// Narrowed rule must not match.
	perms.Rules = []permissions.EffectiveRule{
		{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
	}
	if subjectHoldsClusterAdmin(perms, nil) {
		t.Fatalf("expected non-wildcard rule to not match")
	}
}

func TestSummarizePrivescPathSinkFallback(t *testing.T) {
	f := models.Finding{
		RuleID:   "KUBE-PRIVESC-PATH-KUBE-SYSTEM-SECRETS",
		Severity: models.SeverityHigh,
		EscalationPath: []models.EscalationHop{
			{
				Action:      "read_secrets",
				FromSubject: models.SubjectRef{Kind: "ServiceAccount", Namespace: "default", Name: "reader"},
				ToSubject:   models.SubjectRef{}, // empty sink
			},
		},
	}
	got := summarizePrivescPath(f)
	if !strings.Contains(got, "kube_system_secrets") {
		t.Fatalf("expected sink name in summary, got %q", got)
	}
	if !strings.Contains(got, "ServiceAccount default/reader") {
		t.Fatalf("expected source label in summary, got %q", got)
	}
	if !strings.Contains(got, "1 hop") {
		t.Fatalf("expected hop count in summary, got %q", got)
	}
}

// equalStrings reports whether two string slices are element-wise equal. Inline
// because the tests file would otherwise depend on a third-party comparator and
// the slices here are tiny.
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
