package permissions

import (
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestIsAdminEquivalentClusterRoleBuiltin(t *testing.T) {
	if !IsAdminEquivalentClusterRole("cluster-admin", nil) {
		t.Fatal("built-in cluster-admin name must always be admin-equivalent")
	}
}

func TestIsAdminEquivalentClusterRoleTripleWildcard(t *testing.T) {
	roles := []rbacv1.ClusterRole{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "super-admin"},
			Rules: []rbacv1.PolicyRule{
				{Verbs: []string{"*"}, Resources: []string{"*"}, APIGroups: []string{"*"}},
			},
		},
	}
	if !IsAdminEquivalentClusterRole("super-admin", roles) {
		t.Fatal("a ClusterRole with triple-wildcard rule should be admin-equivalent")
	}
}

func TestIsAdminEquivalentClusterRoleVerbWildcardOnly(t *testing.T) {
	roles := []rbacv1.ClusterRole{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "secret-reader"},
			Rules: []rbacv1.PolicyRule{
				{Verbs: []string{"*"}, Resources: []string{"secrets"}, APIGroups: []string{""}},
			},
		},
	}
	if IsAdminEquivalentClusterRole("secret-reader", roles) {
		t.Fatal("wildcard verbs on narrow resources is not cluster-admin equivalent")
	}
}

func TestIsAdminEquivalentClusterRoleUnknown(t *testing.T) {
	if IsAdminEquivalentClusterRole("missing", []rbacv1.ClusterRole{}) {
		t.Fatal("unknown role name must return false rather than assuming admin reach")
	}
}

func TestClusterRoleHasTripleWildcardAcrossMultipleRules(t *testing.T) {
	cr := rbacv1.ClusterRole{
		Rules: []rbacv1.PolicyRule{
			{Verbs: []string{"get", "list"}, Resources: []string{"pods"}, APIGroups: []string{""}},
			{Verbs: []string{"*"}, Resources: []string{"*"}, APIGroups: []string{"*"}},
		},
	}
	if !ClusterRoleHasTripleWildcard(cr) {
		t.Fatal("a ClusterRole containing a triple-wildcard rule should be recognized regardless of position")
	}
}
