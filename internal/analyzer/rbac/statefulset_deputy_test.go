package rbac

import (
	"context"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
	rbacv1 "k8s.io/api/rbac/v1"
)

// deputyRoleSnapshot mirrors clusterRoleSnapshot but pins a server version and
// grants write on the given apps resources through a namespaced Role+RoleBinding —
// the namespace-scoped shape CVE-2026-2270 actually exploits.
func deputyRoleSnapshot(version string, resources ...string) models.Snapshot {
	s := models.Snapshot{}
	s.Metadata.ClusterVersion = version
	s.Resources.Roles = []rbacv1.Role{{
		ObjectMeta: metav1ObjectMeta("sts-writer", "app"),
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{"apps"},
			Resources: resources,
			Verbs:     []string{"create", "update", "patch"},
		}},
	}}
	s.Resources.RoleBindings = []rbacv1.RoleBinding{{
		ObjectMeta: metav1ObjectMeta("sts-writer-binding", "app"),
		RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "sts-writer"},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "writer", Namespace: "app"}},
	}}
	return s
}

// TestStatefulSetDeputyFindingRequiresBothHalvesAndVersion covers
// KUBE-VERSION-CVE-2026-2270: it fires only when a subject holds write on BOTH
// statefulsets and controllerrevisions AND the server version is affected.
func TestStatefulSetDeputyFindingRequiresBothHalvesAndVersion(t *testing.T) {
	t.Parallel()
	const rule = "KUBE-VERSION-CVE-2026-2270"

	// Both halves + affected version: fires.
	findings, err := New().Analyze(context.Background(), deputyRoleSnapshot("v1.36.4", "statefulsets", "controllerrevisions"))
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	assertRulePresent(t, findings, rule)

	// Both halves but patched version: quiet.
	findings, err = New().Analyze(context.Background(), deputyRoleSnapshot("v1.36.5", "statefulsets", "controllerrevisions"))
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	assertRuleAbsent(t, findings, rule)

	// Affected version but only one half: quiet.
	findings, err = New().Analyze(context.Background(), deputyRoleSnapshot("v1.36.4", "statefulsets"))
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	assertRuleAbsent(t, findings, rule)

	findings, err = New().Analyze(context.Background(), deputyRoleSnapshot("v1.36.4", "controllerrevisions"))
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	assertRuleAbsent(t, findings, rule)

	// Unknown version: fail-closed, quiet even with both halves.
	findings, err = New().Analyze(context.Background(), deputyRoleSnapshot("", "statefulsets", "controllerrevisions"))
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	assertRuleAbsent(t, findings, rule)
}

// TestStatefulSetDeputyFindingSeverityAndCategory pins the finding to MEDIUM /
// privilege-escalation so the CVSS-aligned severity does not drift.
func TestStatefulSetDeputyFindingSeverityAndCategory(t *testing.T) {
	t.Parallel()
	findings, err := New().Analyze(context.Background(), deputyRoleSnapshot("v1.34.11", "statefulsets", "controllerrevisions"))
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	var found bool
	for _, f := range findings {
		if f.RuleID != "KUBE-VERSION-CVE-2026-2270" {
			continue
		}
		found = true
		if f.Severity != models.SeverityMedium {
			t.Errorf("severity = %q, want MEDIUM", f.Severity)
		}
		if f.Category != models.CategoryPrivilegeEscalation {
			t.Errorf("category = %q, want privilege escalation", f.Category)
		}
	}
	if !found {
		t.Fatal("KUBE-VERSION-CVE-2026-2270 not emitted for v1.34.11")
	}
}

// TestStatefulSetDeputyFindingSkipsFullWildcard: a *//*/* holder is already
// cluster-admin (KUBE-PRIVESC-017), so the deputy finding does not also fire.
func TestStatefulSetDeputyFindingSkipsFullWildcard(t *testing.T) {
	t.Parallel()
	s := deputyRoleSnapshot("v1.36.4")
	s.Resources.Roles[0].Rules = []rbacv1.PolicyRule{{
		APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"},
	}}
	findings, err := New().Analyze(context.Background(), s)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	assertRuleAbsent(t, findings, "KUBE-VERSION-CVE-2026-2270")
}
