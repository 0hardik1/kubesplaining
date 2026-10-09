package rbac

import (
	"context"
	appsv1 "k8s.io/api/apps/v1"
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

	// cr-secrets grants `get` only, so the finding is KUBE-PRIVESC-006 (Secret
	// Read); list/watch would be -005 (Secret Listing).
	requireDescriptionContains(t, findings, "KUBE-PRIVESC-006", "ClusterRoleBinding `crb-secrets`")
	requireDescriptionContains(t, findings, "KUBE-PRIVESC-006", "ClusterRole `cr-secrets`")
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

// TestCSRMintPrimitive covers KUBE-PRIVESC-011: a subject must hold BOTH
// cluster-scoped `create csr` AND cluster-scoped `update csr/approval` for the
// rule to fire. Either half alone is insufficient.
func TestCSRMintPrimitive(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		rules  []rbacv1.PolicyRule
		fires  bool
		reason string
	}{
		{
			name: "create only — no finding",
			rules: []rbacv1.PolicyRule{
				{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"certificatesigningrequests"}, Verbs: []string{"create"}},
			},
			fires:  false,
			reason: "create alone cannot self-approve, so no escalation primitive",
		},
		{
			name: "approve only — no finding",
			rules: []rbacv1.PolicyRule{
				{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"certificatesigningrequests/approval"}, Verbs: []string{"update"}},
			},
			fires:  false,
			reason: "approve alone has nothing to approve",
		},
		{
			name: "both halves on the same role — fires",
			rules: []rbacv1.PolicyRule{
				{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"certificatesigningrequests"}, Verbs: []string{"create"}},
				{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"certificatesigningrequests/approval"}, Verbs: []string{"update"}},
			},
			fires: true,
		},
		{
			name: "both halves with patch instead of update — fires",
			rules: []rbacv1.PolicyRule{
				{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"certificatesigningrequests"}, Verbs: []string{"create"}},
				{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"certificatesigningrequests/approval"}, Verbs: []string{"patch"}},
			},
			fires: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			snapshot := models.Snapshot{
				Resources: models.SnapshotResources{
					ClusterRoles: []rbacv1.ClusterRole{
						{ObjectMeta: metav1ObjectMeta("csr-role", ""), Rules: tc.rules},
					},
					ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
						{
							ObjectMeta: metav1ObjectMeta("csr-binding", ""),
							RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "csr-role"},
							Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "csr-sa", Namespace: "default"}},
						},
					},
				},
			}
			findings, err := New().Analyze(context.Background(), snapshot)
			if err != nil {
				t.Fatalf("Analyze() error = %v", err)
			}
			var sawCSR bool
			for _, f := range findings {
				if f.RuleID == "KUBE-PRIVESC-011" && f.Subject != nil && f.Subject.Name == "csr-sa" {
					sawCSR = true
					if f.Severity != models.SeverityHigh {
						t.Errorf("KUBE-PRIVESC-011 expected severity HIGH, got %q", f.Severity)
					}
					if f.Scope.Level != models.ScopeCluster {
						t.Errorf("KUBE-PRIVESC-011 expected cluster scope, got %q", f.Scope.Level)
					}
					if !strings.Contains(f.Description, "system:masters") {
						t.Errorf("KUBE-PRIVESC-011 description should explain the system:masters mechanism: %q", f.Description)
					}
					// The copy must lead an operator to the claim that actually works on a
					// modern cluster. CertificateSubjectRestriction blocks the system:masters
					// Organization for the kube-apiserver-client signer, so a reproduction that
					// only tries that form wrongly reads as "not exploitable"; the Common Name
					// route (any identity string, including a ServiceAccount's) is unguarded.
					if !strings.Contains(f.Description, "CertificateSubjectRestriction") {
						t.Errorf("KUBE-PRIVESC-011 description must say system:masters is blocked by CertificateSubjectRestriction: %q", f.Description)
					}
					if !strings.Contains(f.Description, "CN=system:serviceaccount:kube-system:<sa>") {
						t.Errorf("KUBE-PRIVESC-011 description must show the ServiceAccount-CN variant that is not blocked: %q", f.Description)
					}
				}
			}
			if sawCSR != tc.fires {
				t.Fatalf("fires=%v, sawCSR=%v (%s)", tc.fires, sawCSR, tc.reason)
			}
		})
	}
}

// TestCSRMintPrimitiveNamespaceScopeIgnored guards that namespace-scoped grants
// (impossible in practice for CSRs, which are cluster-scoped, but possible to
// declare in a Role) do NOT fire the rule. CSRs are cluster-scoped resources,
// so a RoleBinding granting these verbs is dead RBAC and should not produce a
// privesc finding.
func TestCSRMintPrimitiveNamespaceScopeIgnored(t *testing.T) {
	t.Parallel()
	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Roles: []rbacv1.Role{
				{
					ObjectMeta: metav1ObjectMeta("csr-role-ns", "team-a"),
					Rules: []rbacv1.PolicyRule{
						{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"certificatesigningrequests"}, Verbs: []string{"create"}},
						{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"certificatesigningrequests/approval"}, Verbs: []string{"update"}},
					},
				},
			},
			RoleBindings: []rbacv1.RoleBinding{
				{
					ObjectMeta: metav1ObjectMeta("csr-rb", "team-a"),
					RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "csr-role-ns"},
					Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "csr-sa-ns", Namespace: "team-a"}},
				},
			},
		},
	}
	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	for _, f := range findings {
		if f.RuleID == "KUBE-PRIVESC-011" {
			t.Fatalf("namespace-scoped CSR grants must not produce KUBE-PRIVESC-011; got %+v", f)
		}
	}
}

// TestResourceNamesAndAPIGroupPrecision covers the precision fixes: matching on
// (apiGroup, resource, verb) rather than the bare resource name, and honoring a
// rule's resourceNames so a name-scoped grant stops firing the "read/create the
// whole resource type" primitives.
func TestResourceNamesAndAPIGroupPrecision(t *testing.T) {
	t.Parallel()

	find := func(findings []models.Finding, ruleID string) *models.Finding {
		for i := range findings {
			if findings[i].RuleID == ruleID {
				return &findings[i]
			}
		}
		return nil
	}
	analyze := func(t *testing.T, rule rbacv1.PolicyRule) []models.Finding {
		t.Helper()
		findings, err := New().Analyze(context.Background(), clusterRoleSnapshot("role", "sa", rule))
		if err != nil {
			t.Fatalf("Analyze() error = %v", err)
		}
		return findings
	}

	t.Run("custom-group secrets does not match core secrets", func(t *testing.T) {
		t.Parallel()
		findings := analyze(t, rbacv1.PolicyRule{APIGroups: []string{"example.com"}, Resources: []string{"secrets"}, Verbs: []string{"get", "list"}})
		assertRuleAbsent(t, findings, "KUBE-PRIVESC-005")
		assertRuleAbsent(t, findings, "KUBE-PRIVESC-006")
	})

	t.Run("name-scoped list secrets cannot enumerate", func(t *testing.T) {
		t.Parallel()
		findings := analyze(t, rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"list", "watch"}, ResourceNames: []string{"tls-cert"}})
		assertRuleAbsent(t, findings, "KUBE-PRIVESC-005")
		assertRuleAbsent(t, findings, "KUBE-PRIVESC-006")
	})

	t.Run("name-scoped create pods is voided", func(t *testing.T) {
		t.Parallel()
		findings := analyze(t, rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"create"}, ResourceNames: []string{"only-this-pod"}})
		assertRuleAbsent(t, findings, "KUBE-PRIVESC-001")
	})

	t.Run("name-scoped get secrets fires scoped and attenuated", func(t *testing.T) {
		t.Parallel()
		scoped := find(analyze(t, rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}, ResourceNames: []string{"tls-cert"}}), "KUBE-PRIVESC-006")
		if scoped == nil {
			t.Fatal("name-scoped get secrets should still surface KUBE-PRIVESC-006 (a real, scoped read)")
		}
		if !strings.Contains(strings.Join(scoped.Tags, ","), "scope:resource-names") {
			t.Errorf("expected scope:resource-names tag, got %v", scoped.Tags)
		}
		unrestricted := find(analyze(t, rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}}), "KUBE-PRIVESC-006")
		if unrestricted == nil {
			t.Fatal("unrestricted get secrets should surface KUBE-PRIVESC-006")
		}
		if !(scoped.Score < unrestricted.Score) {
			t.Errorf("name-scoped grant should score below unrestricted: scoped=%v unrestricted=%v", scoped.Score, unrestricted.Score)
		}
	})

	t.Run("name-scoped impersonate still fires (named target still dangerous)", func(t *testing.T) {
		t.Parallel()
		findings := analyze(t, rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"groups"}, Verbs: []string{"impersonate"}, ResourceNames: []string{"system:masters"}})
		assertRulePresent(t, findings, "KUBE-PRIVESC-008")
	})
}

// clusterRoleSnapshot builds a snapshot with one ClusterRole (carrying rules)
// bound cluster-wide to default/<saName>. Helper for the single-permission
// technique tests below.
func clusterRoleSnapshot(roleName, saName string, rules ...rbacv1.PolicyRule) models.Snapshot {
	return models.Snapshot{
		Resources: models.SnapshotResources{
			ClusterRoles: []rbacv1.ClusterRole{
				{ObjectMeta: metav1ObjectMeta(roleName, ""), Rules: rules},
			},
			ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
				{
					ObjectMeta: metav1ObjectMeta(roleName+"-binding", ""),
					RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: roleName},
					Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: saName, Namespace: "default"}},
				},
			},
		},
	}
}

// TestSinglePermissionPrivescTechniques covers the switch-case techniques added
// for the remaining KUBE-PRIVESC IDs: -004 (exec/attach), -005 vs -006 (secret
// list vs get), -013 (ephemeral containers), -015 (port-forward).
func TestSinglePermissionPrivescTechniques(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		rule     rbacv1.PolicyRule
		wantRule string
		absent   string // optional rule that must NOT fire
	}{
		{"pods/exec create -> 004", rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"pods/exec"}, Verbs: []string{"create"}}, "KUBE-PRIVESC-004", ""},
		{"pods/attach get -> 004", rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"pods/attach"}, Verbs: []string{"get"}}, "KUBE-PRIVESC-004", ""},
		{"secrets list -> 005", rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"list"}}, "KUBE-PRIVESC-005", "KUBE-PRIVESC-006"},
		{"secrets get -> 006", rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}}, "KUBE-PRIVESC-006", "KUBE-PRIVESC-005"},
		{"ephemeralcontainers patch -> 013", rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"pods/ephemeralcontainers"}, Verbs: []string{"patch"}}, "KUBE-PRIVESC-013", ""},
		{"portforward create -> 015", rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"pods/portforward"}, Verbs: []string{"create"}}, "KUBE-PRIVESC-015", ""},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			findings, err := New().Analyze(context.Background(), clusterRoleSnapshot("role", "binder", tc.rule))
			if err != nil {
				t.Fatalf("Analyze() error = %v", err)
			}
			assertRulePresent(t, findings, tc.wantRule)
			if tc.absent != "" {
				assertRuleAbsent(t, findings, tc.absent)
			}
		})
	}
}

// TestSecretCreationTokenTheft covers KUBE-PRIVESC-007: create + get on secrets
// held by the same subject (in composing scopes). Either half alone is
// insufficient.
func TestSecretCreationTokenTheft(t *testing.T) {
	t.Parallel()

	both := clusterRoleSnapshot("minter", "minter-sa",
		rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"create", "get"}})
	findings, err := New().Analyze(context.Background(), both)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	assertRulePresent(t, findings, "KUBE-PRIVESC-007")

	createOnly := clusterRoleSnapshot("creator", "creator-sa",
		rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"create"}})
	findings, err = New().Analyze(context.Background(), createOnly)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	assertRuleAbsent(t, findings, "KUBE-PRIVESC-007")
}

// TestNodeMigration covers KUBE-PRIVESC-016: delete pods + cluster-scoped node
// manipulation (nodes/status write or delete nodes). Delete-pods alone must not
// fire.
func TestNodeMigration(t *testing.T) {
	t.Parallel()

	both := clusterRoleSnapshot("drainer", "drainer-sa",
		rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"delete"}},
		rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"nodes/status"}, Verbs: []string{"update"}})
	findings, err := New().Analyze(context.Background(), both)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	assertRulePresent(t, findings, "KUBE-PRIVESC-016")

	podsOnly := clusterRoleSnapshot("deleter", "deleter-sa",
		rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"delete"}})
	findings, err = New().Analyze(context.Background(), podsOnly)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	assertRuleAbsent(t, findings, "KUBE-PRIVESC-016")
}

// TestMutatingAdmissionPolicyInjection covers KUBE-PRIVESC-019: write access to
// BOTH mutatingadmissionpolicies AND their bindings is a cluster-takeover primitive.
// Either half alone must not fire, and a namespace-scoped grant (dead RBAC on a
// cluster-scoped resource) must not fire either.
func TestMutatingAdmissionPolicyInjection(t *testing.T) {
	t.Parallel()

	group := "admissionregistration.k8s.io"
	policyWrite := rbacv1.PolicyRule{APIGroups: []string{group}, Resources: []string{"mutatingadmissionpolicies"}, Verbs: []string{"create"}}
	bindingWrite := rbacv1.PolicyRule{APIGroups: []string{group}, Resources: []string{"mutatingadmissionpolicybindings"}, Verbs: []string{"create"}}

	both := clusterRoleSnapshot("map-injector", "map-sa", policyWrite, bindingWrite)
	findings, err := New().Analyze(context.Background(), both)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	assertRulePresent(t, findings, "KUBE-PRIVESC-019")

	// One rule granting both resources at once is the same capability.
	combined := clusterRoleSnapshot("map-injector-2", "map-sa-2",
		rbacv1.PolicyRule{APIGroups: []string{group}, Resources: []string{"mutatingadmissionpolicies", "mutatingadmissionpolicybindings"}, Verbs: []string{"create", "update", "patch"}})
	findings, err = New().Analyze(context.Background(), combined)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	assertRulePresent(t, findings, "KUBE-PRIVESC-019")

	// Policy write alone (no binding write) must not fire.
	policyOnly := clusterRoleSnapshot("map-policy-only", "map-sa-3", policyWrite)
	findings, err = New().Analyze(context.Background(), policyOnly)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	assertRuleAbsent(t, findings, "KUBE-PRIVESC-019")

	// A wildcard on the admissionregistration group satisfies both halves.
	wildcard := clusterRoleSnapshot("map-wild", "map-sa-4",
		rbacv1.PolicyRule{APIGroups: []string{group}, Resources: []string{"*"}, Verbs: []string{"*"}})
	findings, err = New().Analyze(context.Background(), wildcard)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	assertRulePresent(t, findings, "KUBE-PRIVESC-019")
}

// TestPodCreatePrivilegedEscape covers KUBE-PRIVESC-002: create pods in a
// namespace whose Pod Security Admission posture does not block privileged pods.
// A Restricted-enforced namespace must suppress it.
func TestPodCreatePrivilegedEscape(t *testing.T) {
	t.Parallel()

	withNamespace := func(enforce string) models.Snapshot {
		snap := clusterRoleSnapshot("pod-creator", "creator-sa",
			rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"create"}})
		labels := map[string]string{}
		if enforce != "" {
			labels["pod-security.kubernetes.io/enforce"] = enforce
		}
		snap.Resources.Namespaces = []corev1.Namespace{
			{ObjectMeta: metav1.ObjectMeta{Name: "dev", Labels: labels}},
		}
		return snap
	}

	findings, err := New().Analyze(context.Background(), withNamespace(""))
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	assertRulePresent(t, findings, "KUBE-PRIVESC-002")
	assertRulePresent(t, findings, "KUBE-PRIVESC-001") // -002 is additive, -001 still fires

	findings, err = New().Analyze(context.Background(), withNamespace("restricted"))
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	assertRuleAbsent(t, findings, "KUBE-PRIVESC-002")
}

// csrSignerSnapshot builds a one-subject snapshot from a rule set, for the
// signer-half tests below.
func csrSignerSnapshot(rules []rbacv1.PolicyRule) models.Snapshot {
	return models.Snapshot{
		Resources: models.SnapshotResources{
			ClusterRoles: []rbacv1.ClusterRole{
				{ObjectMeta: metav1ObjectMeta("signer-role", ""), Rules: rules},
			},
			ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
				{
					ObjectMeta: metav1ObjectMeta("signer-binding", ""),
					RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "signer-role"},
					Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "signer-sa", Namespace: "default"}},
				},
			},
		},
	}
}

// TestCSRMintSignerHalf covers the third gate on KUBE-PRIVESC-011. Since 1.19 the
// CertificateApproval admission plugin also requires `approve` on the CSR's signer,
// so the two CSR verbs alone are a latent escalation (HIGH) while the same subject
// holding the signer verb has every gate the apiserver enforces already satisfied
// (CRITICAL). Detection still fires either way: the plugin is disableable and the
// /approval verb is the grant an operator audits.
func TestCSRMintSignerHalf(t *testing.T) {
	t.Parallel()

	csrHalves := []rbacv1.PolicyRule{
		{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"certificatesigningrequests"}, Verbs: []string{"create"}},
		{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"certificatesigningrequests/approval"}, Verbs: []string{"update"}},
	}

	cases := []struct {
		name         string
		extra        []rbacv1.PolicyRule
		wantSeverity models.Severity
		wantPhrase   string
	}{
		{
			name:         "no signer verb — latent, HIGH",
			wantSeverity: models.SeverityHigh,
			wantPhrase:   "does NOT currently hold `approve` on any signer",
		},
		{
			name: "approve on the apiserver-client signer — fully authorized, CRITICAL",
			extra: []rbacv1.PolicyRule{
				{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"signers"}, Verbs: []string{"approve"}, ResourceNames: []string{"kubernetes.io/kube-apiserver-client"}},
			},
			wantSeverity: models.SeverityCritical,
			wantPhrase:   "ALSO holds `approve` on",
		},
		{
			name: "approve pinned to a third-party signer — still latent",
			extra: []rbacv1.PolicyRule{
				{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"signers"}, Verbs: []string{"approve"}, ResourceNames: []string{"example.com/my-signer"}},
			},
			wantSeverity: models.SeverityHigh,
			wantPhrase:   "does NOT currently hold `approve` on any signer",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			findings, err := New().Analyze(context.Background(), csrSignerSnapshot(append(append([]rbacv1.PolicyRule{}, csrHalves...), tc.extra...)))
			if err != nil {
				t.Fatalf("Analyze() error = %v", err)
			}
			var found bool
			for _, f := range findings {
				if f.RuleID != "KUBE-PRIVESC-011" {
					continue
				}
				found = true
				if f.Severity != tc.wantSeverity {
					t.Errorf("severity = %q, want %q", f.Severity, tc.wantSeverity)
				}
				if !strings.Contains(f.Description, tc.wantPhrase) {
					t.Errorf("description missing %q: %q", tc.wantPhrase, f.Description)
				}
			}
			if !found {
				t.Fatal("KUBE-PRIVESC-011 must fire regardless of the signer half")
			}
		})
	}
}

// TestCSRSignerControl covers KUBE-PRIVESC-024: `sign` on an apiserver-trusted
// signer PLUS the `certificatesigningrequests/status` write. That pair is what the
// apiserver enforces for being a signer, and it skips the approval path entirely.
// Either half alone issues nothing, and a grant scoped to a third-party signer is
// not an apiserver credential at all.
func TestCSRSignerControl(t *testing.T) {
	t.Parallel()

	statusWrite := rbacv1.PolicyRule{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"certificatesigningrequests/status"}, Verbs: []string{"update"}}

	cases := []struct {
		name         string
		rules        []rbacv1.PolicyRule
		fires        bool
		wantSeverity models.Severity
		reason       string
	}{
		{
			name:   "sign only — no finding",
			rules:  []rbacv1.PolicyRule{{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"signers"}, Verbs: []string{"sign"}}},
			fires:  false,
			reason: "without the status write there is nowhere to put an issued certificate",
		},
		{
			name:   "status write only — no finding",
			rules:  []rbacv1.PolicyRule{statusWrite},
			fires:  false,
			reason: "the CertificateSigning admission plugin rejects the write without the sign verb",
		},
		{
			name: "sign on kube-apiserver-client + status — CRITICAL",
			rules: []rbacv1.PolicyRule{
				{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"signers"}, Verbs: []string{"sign"}, ResourceNames: []string{"kubernetes.io/kube-apiserver-client"}},
				statusWrite,
			},
			fires:        true,
			wantSeverity: models.SeverityCritical,
		},
		{
			name: "sign on the kubelet signer only + status — HIGH",
			rules: []rbacv1.PolicyRule{
				{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"signers"}, Verbs: []string{"sign"}, ResourceNames: []string{"kubernetes.io/kube-apiserver-client-kubelet"}},
				statusWrite,
			},
			fires:        true,
			wantSeverity: models.SeverityHigh,
			reason:       "kubelet signers mint node identities, a serious but bounded gain",
		},
		{
			name: "sign scoped to a third-party signer — no finding",
			rules: []rbacv1.PolicyRule{
				{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"signers"}, Verbs: []string{"sign"}, ResourceNames: []string{"example.com/my-signer"}},
				statusWrite,
			},
			fires:  false,
			reason: "that CA is not in the apiserver's --client-ca-file, so its certs authenticate no one",
		},
		{
			name: "namespaced grant — no finding",
			rules: []rbacv1.PolicyRule{
				{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"signers"}, Verbs: []string{"sign"}},
				statusWrite,
			},
			fires:  false,
			reason: "signers and CSRs are cluster-scoped; a namespaced grant is dead RBAC",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			snapshot := csrSignerSnapshot(tc.rules)
			if tc.name == "namespaced grant — no finding" {
				// Same rules, bound through a namespaced RoleBinding instead.
				snapshot = models.Snapshot{
					Resources: models.SnapshotResources{
						Roles: []rbacv1.Role{{ObjectMeta: metav1ObjectMeta("signer-role", "team-a"), Rules: tc.rules}},
						RoleBindings: []rbacv1.RoleBinding{
							{
								ObjectMeta: metav1ObjectMeta("signer-rb", "team-a"),
								RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "signer-role"},
								Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "signer-sa", Namespace: "team-a"}},
							},
						},
					},
				}
			}
			findings, err := New().Analyze(context.Background(), snapshot)
			if err != nil {
				t.Fatalf("Analyze() error = %v", err)
			}
			var found bool
			for _, f := range findings {
				if f.RuleID != "KUBE-PRIVESC-024" {
					continue
				}
				found = true
				if f.Severity != tc.wantSeverity {
					t.Errorf("severity = %q, want %q", f.Severity, tc.wantSeverity)
				}
				if f.Scope.Level != models.ScopeCluster {
					t.Errorf("scope = %q, want cluster", f.Scope.Level)
				}
				if !strings.Contains(f.Description, "--client-ca-file") {
					t.Errorf("description must state the CA-key condition that makes an issued cert authenticate: %q", f.Description)
				}
			}
			if found != tc.fires {
				t.Fatalf("fires=%v, found=%v (%s)", tc.fires, found, tc.reason)
			}
		})
	}
}

// findRule returns the first finding with ruleID, or nil.
func findRule(findings []models.Finding, ruleID string) *models.Finding {
	for i := range findings {
		if findings[i].RuleID == ruleID {
			return &findings[i]
		}
	}
	return nil
}

// TestNodeMigrationHalves covers every grant each KUBE-PRIVESC-016 half accepts, and
// that the description names the grants that matched. `kubectl cordon` and `kubectl
// taint` patch the main `nodes` resource, not `nodes/status`; the Eviction API is
// `create pods/eviction`; `deletecollection` removes every pod in scope. A namespaced
// node grant is dead RBAC, and a name-scoped deletecollection authorizes nothing.
func TestNodeMigrationHalves(t *testing.T) {
	t.Parallel()

	core := func(resource string, verbs ...string) rbacv1.PolicyRule {
		return rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{resource}, Verbs: verbs}
	}
	scopedDeleteCollection := core("pods", "deletecollection")
	scopedDeleteCollection.ResourceNames = []string{"victim"}

	cases := []struct {
		name     string
		rules    []rbacv1.PolicyRule
		wantPod  string // "" means the rule must not fire
		wantNode string
	}{
		{name: "patch nodes is cordon/taint", rules: []rbacv1.PolicyRule{core("pods", "delete"), core("nodes", "patch")}, wantPod: "delete pods", wantNode: "patch nodes"},
		{name: "update nodes", rules: []rbacv1.PolicyRule{core("pods", "delete"), core("nodes", "update", "patch")}, wantPod: "delete pods", wantNode: "update nodes"},
		{name: "the first rule holding a node grant names the half", rules: []rbacv1.PolicyRule{core("pods", "delete"), core("nodes", "patch"), core("nodes/status", "update")}, wantPod: "delete pods", wantNode: "patch nodes"},
		{name: "eviction is a delete-pod equivalent", rules: []rbacv1.PolicyRule{core("pods/eviction", "create"), core("nodes/status", "patch")}, wantPod: "create pods/eviction", wantNode: "patch nodes/status"},
		{name: "deletecollection is a delete-pod equivalent", rules: []rbacv1.PolicyRule{core("pods", "deletecollection"), core("nodes", "delete")}, wantPod: "deletecollection pods", wantNode: "delete nodes"},
		{name: "*/status covers nodes/status", rules: []rbacv1.PolicyRule{core("pods", "delete"), core("*/status", "update")}, wantPod: "delete pods", wantNode: "update nodes/status"},
		{name: "name-scoped deletecollection authorizes nothing", rules: []rbacv1.PolicyRule{scopedDeleteCollection, core("nodes", "patch")}},
		{name: "reading nodes is not node control", rules: []rbacv1.PolicyRule{core("pods", "delete"), core("nodes", "get", "list", "watch")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			findings, err := New().Analyze(context.Background(), clusterRoleSnapshot("migrator", "migrator-sa", tc.rules...))
			if err != nil {
				t.Fatalf("Analyze() error = %v", err)
			}
			if tc.wantPod == "" {
				assertRuleAbsent(t, findings, "KUBE-PRIVESC-016")
				return
			}
			requireDescriptionContains(t, findings, "KUBE-PRIVESC-016", "can `"+tc.wantPod+"`")
			requireDescriptionContains(t, findings, "KUBE-PRIVESC-016", "also `"+tc.wantNode+"`")
		})
	}

	t.Run("namespaced node grant is dead RBAC", func(t *testing.T) {
		t.Parallel()
		snapshot := models.Snapshot{Resources: models.SnapshotResources{
			Roles: []rbacv1.Role{{ObjectMeta: metav1ObjectMeta("migrator", "apps"), Rules: []rbacv1.PolicyRule{core("pods", "delete"), core("nodes", "patch")}}},
			RoleBindings: []rbacv1.RoleBinding{{
				ObjectMeta: metav1ObjectMeta("migrator", "apps"),
				RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "migrator"},
				Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "migrator-sa", Namespace: "apps"}},
			}},
		}}
		findings, err := New().Analyze(context.Background(), snapshot)
		if err != nil {
			t.Fatalf("Analyze() error = %v", err)
		}
		assertRuleAbsent(t, findings, "KUBE-PRIVESC-016")
	})
}

// TestSubresourceWildcardFiresTechniques pins that the "*/sub" resource form reaches
// the per-rule techniques: "*/exec" is `pods/exec` (KUBE-PRIVESC-004) and "*/token" is
// `serviceaccounts/token` (KUBE-PRIVESC-014). "pods/*" is not a Kubernetes wildcard.
func TestSubresourceWildcardFiresTechniques(t *testing.T) {
	t.Parallel()

	analyze := func(t *testing.T, rule rbacv1.PolicyRule) []models.Finding {
		t.Helper()
		findings, err := New().Analyze(context.Background(), clusterRoleSnapshot("role", "sa", rule))
		if err != nil {
			t.Fatalf("Analyze() error = %v", err)
		}
		return findings
	}
	assertRulePresent(t, analyze(t, rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"*/exec"}, Verbs: []string{"create"}}), "KUBE-PRIVESC-004")
	assertRulePresent(t, analyze(t, rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"*/token"}, Verbs: []string{"create"}}), "KUBE-PRIVESC-014")
	assertRuleAbsent(t, analyze(t, rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"pods/*"}, Verbs: []string{"create"}}), "KUBE-PRIVESC-004")
}

// TestImpersonationForms covers the three shapes of KUBE-PRIVESC-008. Legacy
// `impersonate` on users/groups/serviceaccounts is CRITICAL. Legacy `impersonate` on
// the identity attributes (`uids`, `userextras/<key>` in authentication.k8s.io) and the
// KEP-5284 constrained verbs are HIGH, because each one's reach depends on something
// the grant alone does not give. A bare `userextras` (no key) matches no request the
// apiserver makes.
func TestImpersonationForms(t *testing.T) {
	t.Parallel()

	auth := func(resources []string, verbs ...string) rbacv1.PolicyRule {
		return rbacv1.PolicyRule{APIGroups: []string{"authentication.k8s.io"}, Resources: resources, Verbs: verbs}
	}
	cases := []struct {
		name         string
		rule         rbacv1.PolicyRule
		wantSeverity models.Severity // "" means the rule must not fire
		wantText     string
	}{
		{name: "legacy groups", rule: rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"groups"}, Verbs: []string{"impersonate"}}, wantSeverity: models.SeverityCritical, wantText: "system:masters"},
		{name: "uids", rule: auth([]string{"uids"}, "impersonate"), wantSeverity: models.SeverityHigh, wantText: "`uids`"},
		{name: "a named user extra", rule: auth([]string{"userextras/scopes"}, "impersonate"), wantSeverity: models.SeverityHigh, wantText: "`userextras/scopes`"},
		{name: "a literal userextras/*", rule: auth([]string{"userextras/*"}, "impersonate"), wantSeverity: models.SeverityHigh, wantText: "`userextras/*`"},
		{name: "wildcard resource in the group", rule: auth([]string{"*"}, "impersonate"), wantSeverity: models.SeverityHigh, wantText: "`userextras/<any key>`"},
		{name: "bare userextras matches nothing", rule: auth([]string{"userextras"}, "impersonate")},
		{name: "uids in the core group is not the impersonation target", rule: rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"uids"}, Verbs: []string{"impersonate"}}},
		{name: "constrained user-info", rule: auth([]string{"users"}, "impersonate:user-info"), wantSeverity: models.SeverityHigh, wantText: "constrained form"},
		{name: "constrained user-info on an extra", rule: auth([]string{"userextras/example.com/team"}, "impersonate:user-info"), wantSeverity: models.SeverityHigh, wantText: "`impersonate:user-info`"},
		{name: "constrained serviceaccount", rule: auth([]string{"serviceaccounts"}, "impersonate:serviceaccount"), wantSeverity: models.SeverityHigh, wantText: "`impersonate:serviceaccount`"},
		{name: "constrained arbitrary node", rule: auth([]string{"nodes"}, "impersonate:arbitrary-node"), wantSeverity: models.SeverityHigh, wantText: "`impersonate:arbitrary-node`"},
		{name: "constrained associated node", rule: auth([]string{"nodes"}, "impersonate:associated-node"), wantSeverity: models.SeverityHigh, wantText: "`impersonate:associated-node`"},
		{name: "constrained verb on the wrong resource", rule: auth([]string{"nodes"}, "impersonate:serviceaccount")},
		{name: "constrained verb in the core group", rule: rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"users"}, Verbs: []string{"impersonate:user-info"}}},
		{name: "impersonate-on alone is the action half only", rule: rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"impersonate-on:user-info:list"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			findings, err := New().Analyze(context.Background(), clusterRoleSnapshot("imp", "imp-sa", tc.rule))
			if err != nil {
				t.Fatalf("Analyze() error = %v", err)
			}
			if tc.wantSeverity == "" {
				assertRuleAbsent(t, findings, "KUBE-PRIVESC-008")
				return
			}
			f := findRule(findings, "KUBE-PRIVESC-008")
			if f == nil {
				t.Fatalf("want KUBE-PRIVESC-008, got none in %d findings", len(findings))
			}
			if f.Severity != tc.wantSeverity {
				t.Errorf("severity = %s, want %s", f.Severity, tc.wantSeverity)
			}
			requireDescriptionContains(t, findings, "KUBE-PRIVESC-008", tc.wantText)
			if f.RemediationHint == nil {
				t.Error("want the structured remediation hint attached")
			}
		})
	}
}

// TestPodUpdateImageSwap covers KUBE-PRIVESC-034: `update`/`patch` on the main
// `pods` resource. A grant that also carries `create` keeps the -001 framing
// (first matching case wins), and read verbs fire nothing from this family.
func TestPodUpdateImageSwap(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		rule    rbacv1.PolicyRule
		present []string
		absent  []string
	}{
		{"pods patch -> 034", rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"patch"}}, []string{"KUBE-PRIVESC-034"}, []string{"KUBE-PRIVESC-001"}},
		{"pods update -> 034", rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"update"}}, []string{"KUBE-PRIVESC-034"}, []string{"KUBE-PRIVESC-001"}},
		{"pods create+patch -> 001 only", rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"create", "patch"}}, []string{"KUBE-PRIVESC-001"}, []string{"KUBE-PRIVESC-034"}},
		{"pods get/list -> neither", rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list"}}, nil, []string{"KUBE-PRIVESC-001", "KUBE-PRIVESC-034"}},
		{"pods patch in apps group -> neither", rbacv1.PolicyRule{APIGroups: []string{"apps"}, Resources: []string{"pods"}, Verbs: []string{"patch"}}, nil, []string{"KUBE-PRIVESC-034"}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			findings, err := New().Analyze(context.Background(), clusterRoleSnapshot("role", "binder", tc.rule))
			if err != nil {
				t.Fatalf("Analyze() error = %v", err)
			}
			for _, id := range tc.present {
				assertRulePresent(t, findings, id)
			}
			for _, id := range tc.absent {
				assertRuleAbsent(t, findings, id)
			}
		})
	}

	findings, err := New().Analyze(context.Background(), clusterRoleSnapshot("role", "binder",
		rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"patch"}}))
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	f := findRule(findings, "KUBE-PRIVESC-034")
	if f == nil {
		t.Fatal("expected KUBE-PRIVESC-034")
	}
	if f.Severity != models.SeverityHigh {
		t.Errorf("severity = %s, want HIGH", f.Severity)
	}
	if f.RemediationHint == nil || f.RemediationHint.Patch == nil {
		t.Error("expected a structured remediation hint removing the pods write rule")
	}
	if !strings.Contains(f.Description, "image") {
		t.Errorf("description should explain the image swap, got %q", f.Description)
	}
}

// TestNamespaceLabelFlip covers KUBE-PRIVESC-035: update/patch on the Namespace
// object plus pod creation in a namespace whose PSA label blocks privileged pods.
func TestNamespaceLabelFlip(t *testing.T) {
	t.Parallel()

	restricted := map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}
	build := func(nsLabels map[string]string, rules ...rbacv1.PolicyRule) models.Snapshot {
		return models.Snapshot{
			Resources: models.SnapshotResources{
				Namespaces: []corev1.Namespace{
					{ObjectMeta: metav1.ObjectMeta{Name: "locked", Labels: nsLabels}},
				},
				Roles: []rbacv1.Role{{
					ObjectMeta: metav1.ObjectMeta{Name: "ns-writer", Namespace: "locked"},
					Rules:      rules,
				}},
				RoleBindings: []rbacv1.RoleBinding{{
					ObjectMeta: metav1.ObjectMeta{Name: "ns-writer-binding", Namespace: "locked"},
					RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "ns-writer"},
					Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "flipper", Namespace: "locked"}},
				}},
			},
		}
	}
	nsPatch := rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"namespaces"}, Verbs: []string{"patch"}}
	podCreate := rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"create"}}

	findings, err := New().Analyze(context.Background(), build(restricted, nsPatch, podCreate))
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	f := findRule(findings, "KUBE-PRIVESC-035")
	if f == nil {
		t.Fatal("namespaced patch namespaces + create pods in a restricted namespace: expected KUBE-PRIVESC-035")
	}
	if f.Severity != models.SeverityHigh {
		t.Errorf("severity = %s, want HIGH", f.Severity)
	}
	if !strings.Contains(f.Description, "`locked`") || !strings.Contains(f.Description, "pod-security.kubernetes.io/enforce") {
		t.Errorf("description should name the namespace and the PSA label, got %q", f.Description)
	}
	if f.RemediationHint == nil || f.RemediationHint.Patch == nil {
		t.Error("expected a structured remediation hint removing the namespaces write rule")
	}
	// The finding is anchored on the namespace write, the half to remove.
	if !strings.Contains(string(f.Evidence), `"namespaces"`) {
		t.Errorf("evidence should carry the namespaces rule, got %s", f.Evidence)
	}
	// -001 still fires on the pod half; -002 does not, PSA blocks privileged here.
	assertRulePresent(t, findings, "KUBE-PRIVESC-001")
	assertRuleAbsent(t, findings, "KUBE-PRIVESC-002")

	for name, snapshot := range map[string]models.Snapshot{
		"namespace write alone":                          build(restricted, nsPatch),
		"pod create alone":                               build(restricted, podCreate),
		"unlabeled namespace":                            build(nil, nsPatch, podCreate),
		"privileged namespace":                           build(map[string]string{"pod-security.kubernetes.io/enforce": "privileged"}, nsPatch, podCreate),
		"namespaces read only":                           build(restricted, rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"namespaces"}, Verbs: []string{"get", "list"}}, podCreate),
		"other namespace named":                          build(restricted, rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"namespaces"}, Verbs: []string{"patch"}, ResourceNames: []string{"elsewhere"}}, podCreate),
		"job create is a pod half but role write is not": build(restricted, nsPatch, rbacv1.PolicyRule{APIGroups: []string{"rbac.authorization.k8s.io"}, Resources: []string{"roles"}, Verbs: []string{"create"}}),
	} {
		findings, err := New().Analyze(context.Background(), snapshot)
		if err != nil {
			t.Fatalf("%s: Analyze() error = %v", name, err)
		}
		if findRule(findings, "KUBE-PRIVESC-035") != nil {
			t.Errorf("%s: unexpected KUBE-PRIVESC-035", name)
		}
	}

	// A workload create grant counts as the pod half; an update grant counts only
	// when such a workload exists in the namespace.
	deployUpdate := rbacv1.PolicyRule{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"patch"}}
	findings, err = New().Analyze(context.Background(), build(restricted, nsPatch, deployUpdate))
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	assertRuleAbsent(t, findings, "KUBE-PRIVESC-035")
	withDeploy := build(restricted, nsPatch, deployUpdate)
	withDeploy.Resources.Deployments = []appsv1.Deployment{{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "locked"}}}
	findings, err = New().Analyze(context.Background(), withDeploy)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	assertRulePresent(t, findings, "KUBE-PRIVESC-035")
}

// TestPodBindingPlacement covers KUBE-PRIVESC-030: `create` on `pods/binding` (or
// the legacy `bindings` resource) is MEDIUM alone and HIGH when the same subject
// can also create pods, and read verbs on the subresource fire nothing.
func TestPodBindingPlacement(t *testing.T) {
	t.Parallel()

	bind := rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"pods/binding"}, Verbs: []string{"create"}}
	legacy := rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"bindings"}, Verbs: []string{"create"}}
	podCreate := rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"create"}}

	findings, err := New().Analyze(context.Background(), clusterRoleSnapshot("role", "binder", bind))
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	f := findRule(findings, "KUBE-PRIVESC-030")
	if f == nil {
		t.Fatal("create pods/binding: expected KUBE-PRIVESC-030")
	}
	if f.Severity != models.SeverityMedium {
		t.Errorf("binding alone: severity = %s, want MEDIUM", f.Severity)
	}
	if !strings.Contains(f.Description, "NoSchedule") {
		t.Errorf("description should explain the taint bypass, got %q", f.Description)
	}
	if f.RemediationHint == nil || f.RemediationHint.Patch == nil {
		t.Error("expected a structured remediation hint removing the binding rule")
	}

	findings, err = New().Analyze(context.Background(), clusterRoleSnapshot("role", "binder", legacy, podCreate))
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	f = findRule(findings, "KUBE-PRIVESC-030")
	if f == nil {
		t.Fatal("create bindings + create pods: expected KUBE-PRIVESC-030")
	}
	if f.Severity != models.SeverityHigh {
		t.Errorf("binding + pod create: severity = %s, want HIGH", f.Severity)
	}
	if !strings.Contains(f.Description, "can also create pods") {
		t.Errorf("description should name the pod-creation pairing, got %q", f.Description)
	}
	// The finding is anchored on the binding rule, the half to remove.
	if !strings.Contains(string(f.Evidence), `"bindings"`) {
		t.Errorf("evidence should carry the bindings rule, got %s", f.Evidence)
	}

	for name, rule := range map[string]rbacv1.PolicyRule{
		"pods/binding get":          {APIGroups: []string{""}, Resources: []string{"pods/binding"}, Verbs: []string{"get"}},
		"bindings in another group": {APIGroups: []string{"example.io"}, Resources: []string{"bindings"}, Verbs: []string{"create"}},
	} {
		findings, err := New().Analyze(context.Background(), clusterRoleSnapshot("role", "binder", rule))
		if err != nil {
			t.Fatalf("%s: Analyze() error = %v", name, err)
		}
		assertRuleAbsent(t, findings, "KUBE-PRIVESC-030")
	}
}

// TestPodStatusWrite covers KUBE-PRIVESC-036: update/patch on pods/status.
func TestPodStatusWrite(t *testing.T) {
	t.Parallel()

	findings, err := New().Analyze(context.Background(), clusterRoleSnapshot("role", "binder",
		rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"pods/status"}, Verbs: []string{"patch"}}))
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	f := findRule(findings, "KUBE-PRIVESC-036")
	if f == nil {
		t.Fatal("patch pods/status: expected KUBE-PRIVESC-036")
	}
	if f.Severity != models.SeverityMedium || f.Category != models.CategoryLateralMovement {
		t.Errorf("severity/category = %s/%s, want MEDIUM/lateral movement", f.Severity, f.Category)
	}
	if f.RemediationHint == nil || f.RemediationHint.Patch == nil {
		t.Error("expected a structured remediation hint")
	}
	assertRuleAbsent(t, findings, "KUBE-PRIVESC-034")

	findings, err = New().Analyze(context.Background(), clusterRoleSnapshot("role", "binder",
		rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"pods/status"}, Verbs: []string{"get", "list"}}))
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	assertRuleAbsent(t, findings, "KUBE-PRIVESC-036")
}
