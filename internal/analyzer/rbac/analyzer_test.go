package rbac

import (
	"context"
	"strings"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestAnalyzerFindsSecretAndPodCreationAccess(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Pods: []corev1.Pod{
				{
					ObjectMeta: metav1ObjectMeta("reader-pod", "default"),
					Spec: corev1.PodSpec{
						ServiceAccountName: "reader",
					},
				},
			},
			ClusterRoles: []rbacv1.ClusterRole{
				{
					ObjectMeta: metav1ObjectMeta("reader-role", ""),
					Rules: []rbacv1.PolicyRule{
						{
							APIGroups: []string{""},
							Resources: []string{"secrets"},
							Verbs:     []string{"get", "list"},
						},
						{
							APIGroups: []string{""},
							Resources: []string{"pods"},
							Verbs:     []string{"create"},
						},
					},
				},
			},
			ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
				{
					ObjectMeta: metav1ObjectMeta("reader-role", ""),
					RoleRef: rbacv1.RoleRef{
						Kind: "ClusterRole",
						Name: "reader-role",
					},
					Subjects: []rbacv1.Subject{
						{
							Kind:      "ServiceAccount",
							Name:      "reader",
							Namespace: "default",
						},
					},
				},
			},
		},
	}

	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	assertRulePresent(t, findings, "KUBE-PRIVESC-005")
	assertRulePresent(t, findings, "KUBE-PRIVESC-001")
}

func TestAnalyzerFlagsClusterAdminBinding(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
				{
					ObjectMeta: metav1ObjectMeta("admins", ""),
					RoleRef: rbacv1.RoleRef{
						Kind: "ClusterRole",
						Name: "cluster-admin",
					},
					Subjects: []rbacv1.Subject{
						{
							Kind: "User",
							Name: "alice@example.com",
						},
					},
				},
			},
		},
	}

	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	assertRulePresent(t, findings, "KUBE-RBAC-OVERBROAD-001")
}

func TestDescriptionsQualifyBindingAndRoleByKind(t *testing.T) {
	t.Parallel()

	// Mix of cluster-scoped (CRB → CR) and namespace-scoped (RB → Role) so we exercise both helper branches.
	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			ClusterRoles: []rbacv1.ClusterRole{
				{
					ObjectMeta: metav1ObjectMeta("cr-secrets", ""),
					Rules: []rbacv1.PolicyRule{
						{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}},
					},
				},
			},
			Roles: []rbacv1.Role{
				{
					ObjectMeta: metav1ObjectMeta("r-pods", "team-a"),
					Rules: []rbacv1.PolicyRule{
						{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"create"}},
					},
				},
			},
			ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
				{
					ObjectMeta: metav1ObjectMeta("crb-secrets", ""),
					RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "cr-secrets"},
					Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "snoop", Namespace: "team-a"}},
				},
			},
			RoleBindings: []rbacv1.RoleBinding{
				{
					ObjectMeta: metav1ObjectMeta("rb-pods", "team-a"),
					RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "r-pods"},
					Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "deployer", Namespace: "team-a"}},
				},
			},
		},
	}

	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	requireDescriptionContains(t, findings, "KUBE-PRIVESC-005", "ClusterRoleBinding `crb-secrets`")
	requireDescriptionContains(t, findings, "KUBE-PRIVESC-005", "ClusterRole `cr-secrets`")
	requireDescriptionContains(t, findings, "KUBE-PRIVESC-001", "RoleBinding `team-a/rb-pods`")
	requireDescriptionContains(t, findings, "KUBE-PRIVESC-001", "Role `team-a/r-pods`")
}

func TestFormatHelpersRenderKindAndNamespace(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		kind    string
		ns      string
		objName string
		want    string
	}{
		{"clusterrolebinding", "ClusterRoleBinding", "", "crb-foo", "ClusterRoleBinding `crb-foo`"},
		{"clusterrole", "ClusterRole", "", "cr-foo", "ClusterRole `cr-foo`"},
		{"rolebinding", "RoleBinding", "team-a", "rb-foo", "RoleBinding `team-a/rb-foo`"},
		{"role", "Role", "team-a", "r-foo", "Role `team-a/r-foo`"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := formatBindingRef(tc.kind, tc.ns, tc.objName)
			if got != tc.want {
				t.Errorf("formatBindingRef(%q,%q,%q) = %q, want %q", tc.kind, tc.ns, tc.objName, got, tc.want)
			}
		})
	}
}

func requireDescriptionContains(t *testing.T, findings []models.Finding, ruleID, want string) {
	t.Helper()
	for _, f := range findings {
		if f.RuleID == ruleID && strings.Contains(f.Description, want) {
			return
		}
	}
	t.Fatalf("expected rule %s description to contain %q; not found in %d findings", ruleID, want, len(findings))
}

func assertRulePresent(t *testing.T, findings []models.Finding, ruleID string) {
	t.Helper()

	for _, finding := range findings {
		if finding.RuleID == ruleID {
			return
		}
	}

	t.Fatalf("expected rule %s to be present, findings=%v", ruleID, findings)
}

func metav1ObjectMeta(name, namespace string) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Name:      name,
		Namespace: namespace,
	}
}

// TestStaleRoleRef covers KUBE-RBAC-STALE-001: a (Cluster)RoleBinding whose
// roleRef points at a Role/ClusterRole missing from the snapshot. Verifies the
// rule fires for both cluster- and namespace-scoped bindings, that -002 is
// suppressed when -001 already covers the binding, and that the resulting
// finding's Scope matches the binding's scope.
func TestStaleRoleRef(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			ServiceAccounts: []corev1.ServiceAccount{
				{ObjectMeta: metav1ObjectMeta("sa-foo", "default")},
				{ObjectMeta: metav1ObjectMeta("sa-bar", "team-a")},
			},
			ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
				{
					ObjectMeta: metav1ObjectMeta("crb-orphan", ""),
					RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "deleted-role"},
					Subjects: []rbacv1.Subject{
						{Kind: "ServiceAccount", Name: "sa-foo", Namespace: "default"},
					},
				},
			},
			RoleBindings: []rbacv1.RoleBinding{
				{
					ObjectMeta: metav1ObjectMeta("rb-orphan", "team-a"),
					RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "r-missing"},
					Subjects: []rbacv1.Subject{
						{Kind: "ServiceAccount", Name: "sa-bar", Namespace: "team-a"},
					},
				},
			},
		},
	}

	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	assertRulePresent(t, findings, "KUBE-RBAC-STALE-001")
	assertRuleAbsent(t, findings, "KUBE-RBAC-STALE-002")

	clusterScopedFound, namespaceScopedFound := false, false
	for _, f := range findings {
		if f.RuleID != "KUBE-RBAC-STALE-001" {
			continue
		}
		switch f.Scope.Level {
		case models.ScopeCluster:
			clusterScopedFound = true
		case models.ScopeNamespace:
			if f.Namespace != "team-a" {
				t.Errorf("namespace-scoped stale finding has Namespace=%q, want team-a", f.Namespace)
			}
			namespaceScopedFound = true
		}
	}
	if !clusterScopedFound {
		t.Error("expected one KUBE-RBAC-STALE-001 finding with cluster scope (from crb-orphan)")
	}
	if !namespaceScopedFound {
		t.Error("expected one KUBE-RBAC-STALE-001 finding with namespace scope (from rb-orphan)")
	}
}

// TestStaleSubject covers KUBE-RBAC-STALE-002: a binding whose subject is a
// ServiceAccount missing from the snapshot. Verifies the rule fires only for
// ServiceAccount subjects (User and Group subjects must be ignored — Kubernetes
// has no User/Group inventory) and that the existing role is captured in
// Resource for triage context.
func TestStaleSubject(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Roles: []rbacv1.Role{
				{
					ObjectMeta: metav1ObjectMeta("r-valid", "team-a"),
					Rules: []rbacv1.PolicyRule{
						{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get"}},
					},
				},
			},
			// Note: "ghost-sa" is intentionally NOT in ServiceAccounts. The other
			// subjects below — alice (User), team-readers (Group) — must not
			// produce any -002 findings even though they aren't in any inventory.
			RoleBindings: []rbacv1.RoleBinding{
				{
					ObjectMeta: metav1ObjectMeta("rb-ghost", "team-a"),
					RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "r-valid"},
					Subjects: []rbacv1.Subject{
						{Kind: "ServiceAccount", Name: "ghost-sa", Namespace: "team-a"},
						{Kind: "User", Name: "alice@example.com"},
						{Kind: "Group", Name: "team-readers"},
					},
				},
			},
		},
	}

	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	assertRulePresent(t, findings, "KUBE-RBAC-STALE-002")
	assertRuleAbsent(t, findings, "KUBE-RBAC-STALE-001")

	stale002Count := 0
	for _, f := range findings {
		if f.RuleID != "KUBE-RBAC-STALE-002" {
			continue
		}
		stale002Count++
		if f.Subject == nil || f.Subject.Kind != "ServiceAccount" || f.Subject.Name != "ghost-sa" {
			t.Errorf("STALE-002 fired for non-ServiceAccount subject %+v", f.Subject)
		}
		if f.Resource == nil || f.Resource.Name != "r-valid" || f.Resource.Kind != "Role" {
			t.Errorf("STALE-002 Resource = %+v, want Role/r-valid", f.Resource)
		}
	}
	if stale002Count != 1 {
		t.Errorf("expected exactly one KUBE-RBAC-STALE-002 finding (only the ghost-sa subject qualifies), got %d", stale002Count)
	}
}

// TestStaleBuiltinRolesNotFlagged guards the built-in-role allowlist. The four
// user-facing ClusterRoles (cluster-admin/admin/edit/view) are guaranteed by
// every distribution; bindings to them must not produce -001 even when the
// snapshot omits the role definitions (which happens for scan-resource or
// partial collections).
func TestStaleBuiltinRolesNotFlagged(t *testing.T) {
	t.Parallel()

	for _, roleName := range []string{"cluster-admin", "admin", "edit", "view"} {
		roleName := roleName
		t.Run(roleName, func(t *testing.T) {
			t.Parallel()
			snapshot := models.Snapshot{
				Resources: models.SnapshotResources{
					ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
						{
							ObjectMeta: metav1ObjectMeta("crb-builtin", ""),
							RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: roleName},
							Subjects:   []rbacv1.Subject{{Kind: "User", Name: "alice@example.com"}},
						},
					},
				},
			}
			findings, err := New().Analyze(context.Background(), snapshot)
			if err != nil {
				t.Fatalf("Analyze() error = %v", err)
			}
			assertRuleAbsent(t, findings, "KUBE-RBAC-STALE-001")
		})
	}
}

func assertRuleAbsent(t *testing.T, findings []models.Finding, ruleID string) {
	t.Helper()
	for _, f := range findings {
		if f.RuleID == ruleID {
			t.Fatalf("expected rule %s to be absent; found finding %+v", ruleID, f)
		}
	}
}
