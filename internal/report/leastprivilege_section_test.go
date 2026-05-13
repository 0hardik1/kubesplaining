package report

import (
	"strings"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
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
