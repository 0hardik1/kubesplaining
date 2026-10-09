package rbac

import (
	"context"
	"strings"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// backendRBACSnapshot returns a cluster whose `hooks` namespace hosts a mutating
// webhook backend (pods CREATE, caBundle set) and whose `apps` namespace hosts
// nothing the API server calls.
func backendRBACSnapshot() models.Snapshot {
	hook := admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "sidecar-injector"},
		Webhooks: []admissionregistrationv1.MutatingWebhook{{
			Name: "inject.example.com",
			ClientConfig: admissionregistrationv1.WebhookClientConfig{
				Service:  &admissionregistrationv1.ServiceReference{Namespace: "hooks", Name: "injector"},
				CABundle: []byte("ca"),
			},
			Rules: []admissionregistrationv1.RuleWithOperations{{
				Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
				Rule:       admissionregistrationv1.Rule{APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"pods"}},
			}},
		}},
	}
	return models.Snapshot{Resources: models.SnapshotResources{
		Namespaces: []corev1.Namespace{
			{ObjectMeta: metav1.ObjectMeta{Name: "hooks"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "apps"}},
		},
		Services: []corev1.Service{
			{ObjectMeta: metav1.ObjectMeta{Name: "injector", Namespace: "hooks"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "apps"}},
		},
		MutatingWebhookConfigs: []admissionregistrationv1.MutatingWebhookConfiguration{hook},
	}}
}

func addRole(snapshot *models.Snapshot, ns, sa, role string, rules ...rbacv1.PolicyRule) {
	snapshot.Resources.Roles = append(snapshot.Resources.Roles, rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: role, Namespace: ns}, Rules: rules,
	})
	snapshot.Resources.RoleBindings = append(snapshot.Resources.RoleBindings, rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: role + "-binding", Namespace: ns},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: sa, Namespace: ns}},
		RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: role},
	})
}

func addClusterRole(snapshot *models.Snapshot, ns, sa, role string, rules ...rbacv1.PolicyRule) {
	snapshot.Resources.ClusterRoles = append(snapshot.Resources.ClusterRoles, rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: role}, Rules: rules,
	})
	snapshot.Resources.ClusterRoleBindings = append(snapshot.Resources.ClusterRoleBindings, rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: role + "-binding"},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: sa, Namespace: ns}},
		RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: role},
	})
}

func TestAPIServiceWrite(t *testing.T) {
	t.Parallel()

	snapshot := backendRBACSnapshot()
	addClusterRole(&snapshot, "apps", "installer", "apiservice-editor",
		rbacv1.PolicyRule{APIGroups: []string{"apiregistration.k8s.io"}, Resources: []string{"apiservices"}, Verbs: []string{"update"}})
	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	f := findRule(findings, "KUBE-PRIVESC-020")
	if f == nil {
		t.Fatal("unscoped update apiservices: expected KUBE-PRIVESC-020")
	}
	if f.Severity != models.SeverityCritical {
		t.Errorf("unscoped grant severity = %s, want CRITICAL", f.Severity)
	}
	if f.RemediationHint == nil || f.RemediationHint.Patch == nil {
		t.Error("expected a structured remediation hint")
	}

	// Scoped to an aggregated registration: HIGH.
	snapshot = backendRBACSnapshot()
	addClusterRole(&snapshot, "apps", "metrics", "metrics-apiservice",
		rbacv1.PolicyRule{APIGroups: []string{"apiregistration.k8s.io"}, Resources: []string{"apiservices"}, Verbs: []string{"patch"}, ResourceNames: []string{"v1beta1.metrics.k8s.io"}})
	findings, err = New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if f = findRule(findings, "KUBE-PRIVESC-020"); f == nil || f.Severity != models.SeverityHigh {
		t.Fatalf("aggregated-scoped grant: want HIGH finding, got %+v", f)
	}
	if !strings.Contains(f.Description, "v1beta1.metrics.k8s.io") {
		t.Errorf("description should name the registration: %s", f.Description)
	}

	// Read-only verbs: nothing.
	snapshot = backendRBACSnapshot()
	addClusterRole(&snapshot, "apps", "reader", "apiservice-reader",
		rbacv1.PolicyRule{APIGroups: []string{"apiregistration.k8s.io"}, Resources: []string{"apiservices"}, Verbs: []string{"get", "list"}})
	findings, err = New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	assertRuleAbsent(t, findings, "KUBE-PRIVESC-020")
}

func TestEndpointSliceWrite(t *testing.T) {
	t.Parallel()

	snapshot := backendRBACSnapshot()
	addRole(&snapshot, "apps", "slicer", "slicer",
		rbacv1.PolicyRule{APIGroups: []string{"discovery.k8s.io"}, Resources: []string{"endpointslices"}, Verbs: []string{"create"}})
	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	f := findRule(findings, "KUBE-PRIVESC-021")
	if f == nil {
		t.Fatal("create endpointslices: expected KUBE-PRIVESC-021")
	}
	if f.Severity != models.SeverityMedium || f.Category != models.CategoryLateralMovement {
		t.Errorf("tenant namespace: severity/category = %s/%s, want MEDIUM/lateral movement", f.Severity, f.Category)
	}
	assertRuleAbsent(t, findings, "KUBE-PRIVESC-038")

	// Same grant in the webhook namespace: HIGH, and the namespace is named.
	snapshot = backendRBACSnapshot()
	addRole(&snapshot, "hooks", "slicer", "slicer",
		rbacv1.PolicyRule{APIGroups: []string{"discovery.k8s.io"}, Resources: []string{"endpointslices"}, Verbs: []string{"patch"}})
	findings, err = New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if f = findRule(findings, "KUBE-PRIVESC-021"); f == nil || f.Severity != models.SeverityHigh {
		t.Fatalf("backend namespace: want HIGH finding, got %+v", f)
	}
	if !strings.Contains(f.Description, "`hooks`") {
		t.Errorf("description should name the backend namespace: %s", f.Description)
	}
	// Core endpoints writes are not the same primitive and must not fire it.
	snapshot = backendRBACSnapshot()
	addRole(&snapshot, "hooks", "ep", "ep",
		rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"endpoints"}, Verbs: []string{"create", "update"}})
	findings, err = New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	assertRuleAbsent(t, findings, "KUBE-PRIVESC-021")
}

func TestServiceWriteGating(t *testing.T) {
	t.Parallel()

	// A tenant's own namespace without a backend: silent (edit role noise).
	snapshot := backendRBACSnapshot()
	addRole(&snapshot, "apps", "dev", "svc-editor",
		rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"services"}, Verbs: []string{"update", "patch"}})
	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	assertRuleAbsent(t, findings, "KUBE-PRIVESC-022")

	// Cluster-wide: MEDIUM... HIGH, because a backend namespace exists in the cluster.
	snapshot = backendRBACSnapshot()
	addClusterRole(&snapshot, "apps", "wide", "svc-editor-wide",
		rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"services"}, Verbs: []string{"update"}})
	findings, err = New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	f := findRule(findings, "KUBE-PRIVESC-022")
	if f == nil || f.Severity != models.SeverityHigh {
		t.Fatalf("cluster-wide with a backend namespace present: want HIGH, got %+v", f)
	}

	// Cluster-wide with no backends anywhere: MEDIUM.
	snapshot = backendRBACSnapshot()
	snapshot.Resources.MutatingWebhookConfigs = nil
	addClusterRole(&snapshot, "apps", "wide", "svc-editor-wide",
		rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"services"}, Verbs: []string{"update"}})
	findings, err = New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if f = findRule(findings, "KUBE-PRIVESC-022"); f == nil || f.Severity != models.SeverityMedium {
		t.Fatalf("cluster-wide without backends: want MEDIUM, got %+v", f)
	}
}

func TestControlPlaneBackendHijack(t *testing.T) {
	t.Parallel()

	// Routing half and TLS half from two different Roles in the webhook namespace.
	snapshot := backendRBACSnapshot()
	addRole(&snapshot, "hooks", "operator", "svc-editor",
		rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"services"}, Verbs: []string{"patch"}})
	addRole(&snapshot, "hooks", "operator", "secret-reader",
		rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}})
	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	f := findRule(findings, "KUBE-PRIVESC-038")
	if f == nil {
		t.Fatal("routing + TLS halves in a backend namespace: expected KUBE-PRIVESC-038")
	}
	if f.Severity != models.SeverityCritical {
		t.Errorf("mutating webhook on pods CREATE: severity = %s, want CRITICAL", f.Severity)
	}
	if !strings.Contains(f.Description, "secret-reader") || !strings.Contains(f.Description, "svc-editor") {
		t.Errorf("description should name both bindings: %s", f.Description)
	}
	if f.RemediationHint == nil || f.RemediationHint.Patch == nil {
		t.Error("expected a structured remediation hint")
	}

	// Routing half alone: no conjunction finding.
	snapshot = backendRBACSnapshot()
	addRole(&snapshot, "hooks", "router", "svc-editor",
		rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"services"}, Verbs: []string{"patch"}})
	findings, err = New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	assertRuleAbsent(t, findings, "KUBE-PRIVESC-038")

	// Both halves, but the webhook has no caBundle: verified against system roots,
	// not hijackable from in-cluster material.
	snapshot = backendRBACSnapshot()
	snapshot.Resources.MutatingWebhookConfigs[0].Webhooks[0].ClientConfig.CABundle = nil
	addRole(&snapshot, "hooks", "operator", "editor",
		rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"services"}, Verbs: []string{"patch"}},
		rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}})
	findings, err = New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	assertRuleAbsent(t, findings, "KUBE-PRIVESC-038")

	// The same two halves in a namespace that hosts no backend: silent.
	snapshot = backendRBACSnapshot()
	addRole(&snapshot, "apps", "operator", "editor",
		rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"services"}, Verbs: []string{"patch"}},
		rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}})
	findings, err = New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	assertRuleAbsent(t, findings, "KUBE-PRIVESC-038")

	// An aggregated APIService with insecureSkipTLSVerify: routing half alone is
	// enough, and the result is HIGH (not a pod-rewriting or native position).
	snapshot = backendRBACSnapshot()
	snapshot.Resources.MutatingWebhookConfigs = nil
	snapshot.Resources.Namespaces = append(snapshot.Resources.Namespaces, corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "metrics"}})
	snapshot.Resources.APIServices = []models.APIServiceSummary{{
		Name: "v1beta1.metrics.k8s.io", Group: "metrics.k8s.io", Version: "v1beta1",
		ServiceNamespace: "metrics", ServiceName: "metrics-server", InsecureSkipTLSVerify: true,
	}}
	addRole(&snapshot, "metrics", "ci", "slicer",
		rbacv1.PolicyRule{APIGroups: []string{"discovery.k8s.io"}, Resources: []string{"endpointslices"}, Verbs: []string{"create"}})
	findings, err = New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if f = findRule(findings, "KUBE-PRIVESC-038"); f == nil || f.Severity != models.SeverityHigh {
		t.Fatalf("insecure aggregated APIService: want HIGH finding from the routing half alone, got %+v", f)
	}
}
