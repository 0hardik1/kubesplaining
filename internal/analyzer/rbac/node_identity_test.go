package rbac

import (
	"context"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func kubeadmAutoApproveBinding() rbacv1.ClusterRoleBinding {
	return rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "kubeadm:node-autoapprove-bootstrap"},
		Subjects:   []rbacv1.Subject{{Kind: "Group", Name: "system:bootstrappers:kubeadm:default-node-token"}},
		RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "system:certificates.k8s.io:certificatesigningrequests:nodeclient"},
	}
}

func TestNodeClientAutoApprove(t *testing.T) {
	t.Parallel()

	snapshot := backendRBACSnapshot()
	addClusterRole(&snapshot, "apps", "joiner", "csr-submitter",
		rbacv1.PolicyRule{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"certificatesigningrequests"}, Verbs: []string{"create"}})
	addClusterRole(&snapshot, "apps", "joiner", "nodeclient",
		rbacv1.PolicyRule{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"certificatesigningrequests/nodeclient"}, Verbs: []string{"create"}})
	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	f := findRule(findings, "KUBE-PRIVESC-037")
	if f == nil {
		t.Fatal("CSR create + nodeclient create: expected KUBE-PRIVESC-037")
	}
	if f.Severity != models.SeverityHigh {
		t.Errorf("severity = %s, want HIGH", f.Severity)
	}
	if f.RemediationHint == nil || f.RemediationHint.Patch == nil {
		t.Error("expected a structured remediation hint")
	}

	// The nodeclient subresource alone: silent.
	snapshot = backendRBACSnapshot()
	addClusterRole(&snapshot, "apps", "half", "nodeclient",
		rbacv1.PolicyRule{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"certificatesigningrequests/nodeclient"}, Verbs: []string{"create"}})
	findings, err = New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	assertRuleAbsent(t, findings, "KUBE-PRIVESC-037")

	// The kubeadm bootstrap group holding both is the designed configuration.
	snapshot = backendRBACSnapshot()
	snapshot.Resources.ClusterRoles = append(snapshot.Resources.ClusterRoles,
		rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "system:node-bootstrapper"}, Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"certificatesigningrequests"}, Verbs: []string{"create", "get", "list", "watch"}},
		}},
		rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "system:certificates.k8s.io:certificatesigningrequests:nodeclient"}, Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"certificatesigningrequests/nodeclient"}, Verbs: []string{"create"}},
		}},
	)
	snapshot.Resources.ClusterRoleBindings = append(snapshot.Resources.ClusterRoleBindings,
		kubeadmAutoApproveBinding(),
		rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "kubeadm:kubelet-bootstrap"},
			Subjects:   []rbacv1.Subject{{Kind: "Group", Name: "system:bootstrappers:kubeadm:default-node-token"}},
			RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "system:node-bootstrapper"},
		},
	)
	findings, err = New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	assertRuleAbsent(t, findings, "KUBE-PRIVESC-037")
}

func TestBootstrapTokenMint(t *testing.T) {
	t.Parallel()

	rule := rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"create"}}

	// Without the kubeadm binding: silent.
	snapshot := backendRBACSnapshot()
	snapshot.Resources.Namespaces = append(snapshot.Resources.Namespaces, corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}})
	addRole(&snapshot, "kube-system", "installer", "secret-writer", rule)
	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	assertRuleAbsent(t, findings, "KUBE-PRIVESC-026")

	// With it: HIGH.
	snapshot.Resources.ClusterRoleBindings = append(snapshot.Resources.ClusterRoleBindings, kubeadmAutoApproveBinding())
	findings, err = New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	f := findRule(findings, "KUBE-PRIVESC-026")
	if f == nil {
		t.Fatal("kube-system Secret write with kubeadm auto-approval: expected KUBE-PRIVESC-026")
	}
	if f.Severity != models.SeverityHigh {
		t.Errorf("severity = %s, want HIGH", f.Severity)
	}

	// A Secret write in a tenant namespace does not reach kube-system.
	snapshot = backendRBACSnapshot()
	snapshot.Resources.ClusterRoleBindings = append(snapshot.Resources.ClusterRoleBindings, kubeadmAutoApproveBinding())
	addRole(&snapshot, "apps", "tenant", "secret-writer", rule)
	findings, err = New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	assertRuleAbsent(t, findings, "KUBE-PRIVESC-026")
}
