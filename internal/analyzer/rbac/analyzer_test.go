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
