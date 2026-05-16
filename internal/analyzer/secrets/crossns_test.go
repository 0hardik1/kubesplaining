package secrets

import (
	"context"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestAnalyzeCrossNSEmitsForCrossNamespaceSecretRead(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Pods: []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "team-a"},
					Spec:       corev1.PodSpec{ServiceAccountName: "team-a-sa"},
				},
			},
			ServiceAccounts: []corev1.ServiceAccount{
				{ObjectMeta: metav1.ObjectMeta{Name: "team-a-sa", Namespace: "team-a"}},
			},
			Roles: []rbacv1.Role{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "secret-reader", Namespace: "team-b"},
					Rules: []rbacv1.PolicyRule{
						{Verbs: []string{"get", "list"}, Resources: []string{"secrets"}, APIGroups: []string{""}},
					},
				},
			},
			RoleBindings: []rbacv1.RoleBinding{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "team-a-can-read-team-b", Namespace: "team-b"},
					RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "secret-reader"},
					Subjects: []rbacv1.Subject{
						{Kind: "ServiceAccount", Name: "team-a-sa", Namespace: "team-a"},
					},
				},
			},
		},
	}

	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	if got := countByRule(findings, "KUBE-SECRETS-CROSSNS-001"); got != 1 {
		t.Fatalf("expected exactly 1 KUBE-SECRETS-CROSSNS-001 finding, got %d", got)
	}
	if !findingHasSubject(findings, "KUBE-SECRETS-CROSSNS-001", "ServiceAccount", "team-a-sa", "team-a") {
		t.Fatalf("expected finding subject to be team-a/team-a-sa")
	}
}

func TestAnalyzeCrossNSSkipsIntraNamespaceGrants(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Pods: []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "team-a"},
					Spec:       corev1.PodSpec{ServiceAccountName: "team-a-sa"},
				},
			},
			Roles: []rbacv1.Role{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "secret-reader", Namespace: "team-a"},
					Rules: []rbacv1.PolicyRule{
						{Verbs: []string{"get"}, Resources: []string{"secrets"}, APIGroups: []string{""}},
					},
				},
			},
			RoleBindings: []rbacv1.RoleBinding{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "intra-ns", Namespace: "team-a"},
					RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "secret-reader"},
					Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "team-a-sa", Namespace: "team-a"}},
				},
			},
		},
	}

	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	if countByRule(findings, "KUBE-SECRETS-CROSSNS-001") != 0 {
		t.Fatalf("did not expect cross-ns finding for intra-namespace RoleBinding")
	}
}

func TestAnalyzeCrossNSEmitsForClusterWideGrant(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Pods: []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "team-a"},
					Spec:       corev1.PodSpec{ServiceAccountName: "team-a-sa"},
				},
			},
			ClusterRoles: []rbacv1.ClusterRole{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "cluster-secret-reader"},
					Rules: []rbacv1.PolicyRule{
						{Verbs: []string{"get", "list"}, Resources: []string{"secrets"}, APIGroups: []string{""}},
					},
				},
			},
			ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "team-a-cluster-secrets"},
					RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-secret-reader"},
					Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "team-a-sa", Namespace: "team-a"}},
				},
			},
		},
	}

	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	// One finding emitted for the cluster-wide grant; the target_namespace
	// will be "" rendered as "*" in the finding ID.
	if got := countByRule(findings, "KUBE-SECRETS-CROSSNS-001"); got != 1 {
		t.Fatalf("expected exactly 1 KUBE-SECRETS-CROSSNS-001 finding, got %d", got)
	}
	want := "KUBE-SECRETS-CROSSNS-001:ServiceAccount/team-a/team-a-sa:*"
	if !findingHasID(findings, want) {
		t.Fatalf("expected finding ID %q, got %v", want, findingIDs(findings, "KUBE-SECRETS-CROSSNS-001"))
	}
}

func TestAnalyzeCrossNSDeduplicatesByTargetNamespace(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Pods: []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "team-a"},
					Spec:       corev1.PodSpec{ServiceAccountName: "team-a-sa"},
				},
			},
			Roles: []rbacv1.Role{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "r1", Namespace: "team-b"},
					Rules:      []rbacv1.PolicyRule{{Verbs: []string{"get"}, Resources: []string{"secrets"}, APIGroups: []string{""}}},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "r2", Namespace: "team-b"},
					Rules:      []rbacv1.PolicyRule{{Verbs: []string{"list"}, Resources: []string{"secrets"}, APIGroups: []string{""}}},
				},
			},
			RoleBindings: []rbacv1.RoleBinding{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "rb1", Namespace: "team-b"},
					RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "r1"},
					Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "team-a-sa", Namespace: "team-a"}},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "rb2", Namespace: "team-b"},
					RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "r2"},
					Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "team-a-sa", Namespace: "team-a"}},
				},
			},
		},
	}

	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	if got := countByRule(findings, "KUBE-SECRETS-CROSSNS-001"); got != 1 {
		t.Fatalf("expected exactly 1 KUBE-SECRETS-CROSSNS-001 finding (per (subject, target_namespace) pair), got %d", got)
	}
}

func findingHasSubject(findings []models.Finding, ruleID, kind, name, namespace string) bool {
	for _, f := range findings {
		if f.RuleID != ruleID || f.Subject == nil {
			continue
		}
		if f.Subject.Kind == kind && f.Subject.Name == name && f.Subject.Namespace == namespace {
			return true
		}
	}
	return false
}

func findingHasID(findings []models.Finding, id string) bool {
	for _, f := range findings {
		if f.ID == id {
			return true
		}
	}
	return false
}

func findingIDs(findings []models.Finding, ruleID string) []string {
	out := make([]string, 0)
	for _, f := range findings {
		if f.RuleID == ruleID {
			out = append(out, f.ID)
		}
	}
	return out
}
