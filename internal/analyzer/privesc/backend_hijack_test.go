package privesc

import (
	"strings"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// backendSnapshot builds a cluster with one application namespace (`apps`, a
// Service and a running pod) and one webhook namespace (`hooks`) hosting a
// mutating webhook on pods CREATE with a caBundle, plus a privileged namespace so
// the mutating-webhook sink resolves to node_escape.
func backendSnapshot() models.Snapshot {
	privileged := corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "sandbox", Labels: map[string]string{"pod-security.kubernetes.io/enforce": "privileged"}}}
	hooks := corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "hooks"}}
	apps := corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "apps"}}
	svc := corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "apps"},
		Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "api"}},
	}
	hookSvc := corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "injector", Namespace: "hooks"},
		Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "injector"}},
	}
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "api-0", Namespace: "apps", Labels: map[string]string{"app": "api"}},
		Spec:       corev1.PodSpec{ServiceAccountName: "api", NodeName: "n1"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
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
		Namespaces:             []corev1.Namespace{privileged, hooks, apps},
		Services:               []corev1.Service{svc, hookSvc},
		Pods:                   []corev1.Pod{pod},
		MutatingWebhookConfigs: []admissionregistrationv1.MutatingWebhookConfiguration{hook},
	}}
}

func bindSA(snapshot *models.Snapshot, ns, sa, role string, rules []rbacv1.PolicyRule) {
	snapshot.Resources.Roles = append(snapshot.Resources.Roles, rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: role, Namespace: ns},
		Rules:      rules,
	})
	snapshot.Resources.RoleBindings = append(snapshot.Resources.RoleBindings, rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: role + "-binding", Namespace: ns},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: sa, Namespace: ns}},
		RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: role},
	})
}

func bindClusterSA(snapshot *models.Snapshot, ns, sa, role string, rules []rbacv1.PolicyRule) {
	snapshot.Resources.ClusterRoles = append(snapshot.Resources.ClusterRoles, rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: role},
		Rules:      rules,
	})
	snapshot.Resources.ClusterRoleBindings = append(snapshot.Resources.ClusterRoleBindings, rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: role + "-binding"},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: sa, Namespace: ns}},
		RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: role},
	})
}

// actionEdges returns the edges of one action leaving the subject with the given
// key (`Kind/ns/name`).
func actionEdges(graph *models.EscalationGraph, from string, action string) []*models.EscalationEdge {
	var out []*models.EscalationEdge
	for _, e := range graph.Edges {
		if e.From == "subject:"+from && e.Action == action {
			out = append(out, e)
		}
	}
	return out
}

func TestEndpointSliceWriteEdge(t *testing.T) {
	snapshot := backendSnapshot()
	bindSA(&snapshot, "apps", "slicer", "slicer", []rbacv1.PolicyRule{{
		APIGroups: []string{"discovery.k8s.io"}, Resources: []string{"endpointslices"}, Verbs: []string{"create"},
	}})
	graph := BuildGraph(snapshot)
	from := "ServiceAccount/apps/slicer"
	edges := actionEdges(graph, from, "endpointslice_write")
	if len(edges) != 1 {
		t.Fatalf("expected one endpointslice_write edge, got %d", len(edges))
	}
	if edges[0].To != sinkTrafficIntercept {
		t.Fatalf("edge should lead to traffic_intercept, got %s", edges[0].To)
	}
	if edges[0].Technique != "KUBE-PRIVESC-021" || !strings.Contains(edges[0].Description, "apps") {
		t.Fatalf("unexpected edge: %+v", edges[0])
	}
	// A namespace with no Services yields no edge.
	snapshot2 := backendSnapshot()
	bindSA(&snapshot2, "sandbox", "slicer", "slicer", []rbacv1.PolicyRule{{
		APIGroups: []string{"discovery.k8s.io"}, Resources: []string{"endpointslices"}, Verbs: []string{"create"},
	}})
	if got := actionEdges(BuildGraph(snapshot2), "ServiceAccount/sandbox/slicer", "endpointslice_write"); len(got) != 0 {
		t.Fatalf("no Services in sandbox, expected no edge, got %d", len(got))
	}
}

func TestServiceRewriteEdgeGating(t *testing.T) {
	// A tenant with update services in its own namespace, which hosts no backend:
	// no generic edge (the `edit` role carries this verb everywhere).
	snapshot := backendSnapshot()
	rule := []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"services"}, Verbs: []string{"update"}}}
	bindSA(&snapshot, "apps", "tenant", "svc-editor", rule)
	if got := actionEdges(BuildGraph(snapshot), "ServiceAccount/apps/tenant", "service_backend_rewrite"); len(got) != 0 {
		t.Fatalf("tenant namespace without a backend should emit no service_backend_rewrite edge, got %d", len(got))
	}
	// Cluster-wide: edge to traffic_intercept.
	snapshot = backendSnapshot()
	bindClusterSA(&snapshot, "apps", "wide", "svc-editor-wide", rule)
	got := actionEdges(BuildGraph(snapshot), "ServiceAccount/apps/wide", "service_backend_rewrite")
	if len(got) != 1 || got[0].To != sinkTrafficIntercept || got[0].Technique != "KUBE-PRIVESC-022" {
		t.Fatalf("cluster-wide update services should reach traffic_intercept, got %+v", got)
	}
	// In the webhook namespace: generic edge, and no hijack edge without a TLS half.
	snapshot = backendSnapshot()
	bindSA(&snapshot, "hooks", "router", "svc-editor", rule)
	graph := BuildGraph(snapshot)
	if got := actionEdges(graph, "ServiceAccount/hooks/router", "service_backend_rewrite"); len(got) != 1 {
		t.Fatalf("backend namespace should emit the generic edge, got %d", len(got))
	}
	if got := actionEdges(graph, "ServiceAccount/hooks/router", "control_plane_backend_hijack"); len(got) != 0 {
		t.Fatalf("routing half alone must not produce a hijack edge, got %d", len(got))
	}
}

func TestControlPlaneBackendHijackEdge(t *testing.T) {
	snapshot := backendSnapshot()
	// Routing half (update services) in one Role, TLS half (get secrets) in another:
	// the edge must carry both bindings as cut breakers.
	bindSA(&snapshot, "hooks", "operator", "svc-editor", []rbacv1.PolicyRule{{
		APIGroups: []string{""}, Resources: []string{"services"}, Verbs: []string{"patch"},
	}})
	bindSA(&snapshot, "hooks", "operator", "secret-reader", []rbacv1.PolicyRule{{
		APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"},
	}})
	graph := BuildGraph(snapshot)
	from := "ServiceAccount/hooks/operator"
	edges := actionEdges(graph, from, "control_plane_backend_hijack")
	if len(edges) != 1 {
		t.Fatalf("expected one hijack edge, got %d", len(edges))
	}
	e := edges[0]
	if e.To != sinkNodeEscape {
		t.Fatalf("mutating webhook on pods CREATE with a privileged namespace should lead to node_escape, got %s", e.To)
	}
	if e.Technique != "KUBE-PRIVESC-038" || !strings.Contains(e.Description, "sidecar-injector/inject.example.com") {
		t.Fatalf("unexpected edge: %+v", e)
	}
	if len(e.CutBreakers) != 2 {
		t.Fatalf("expected both halves as cut breakers, got %+v", e.CutBreakers)
	}
	if !strings.Contains(e.Permission, "write services") || !strings.Contains(e.Permission, "read secrets") {
		t.Fatalf("permission should name both halves, got %q", e.Permission)
	}

	// A finding reaches the node_escape sink with the hijack as its hop.
	findings, err := New().Analyze(t.Context(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range findings {
		if strings.HasPrefix(f.ID, "KUBE-PRIVESC-PATH-NODE-ESCAPE:ServiceAccount/hooks/operator:") {
			found = true
			if f.Severity != models.SeverityCritical && f.Severity != models.SeverityHigh {
				t.Fatalf("unexpected severity %s", f.Severity)
			}
		}
	}
	if !found {
		t.Fatalf("expected a node-escape path finding for hooks/operator; got %d findings", len(findings))
	}
}

func TestControlPlaneBackendHijackSkipsSystemRootsWebhook(t *testing.T) {
	snapshot := backendSnapshot()
	snapshot.Resources.MutatingWebhookConfigs[0].Webhooks[0].ClientConfig.CABundle = nil
	bindSA(&snapshot, "hooks", "operator", "editor", []rbacv1.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"services"}, Verbs: []string{"patch"}},
		{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}},
	})
	if got := actionEdges(BuildGraph(snapshot), "ServiceAccount/hooks/operator", "control_plane_backend_hijack"); len(got) != 0 {
		t.Fatalf("webhook verified against system roots must not be hijackable, got %d edges", len(got))
	}
}

func TestControlPlaneBackendHijackAPIService(t *testing.T) {
	snapshot := backendSnapshot()
	snapshot.Resources.MutatingWebhookConfigs = nil
	snapshot.Resources.Namespaces = append(snapshot.Resources.Namespaces, corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "metrics"}})
	snapshot.Resources.Services = append(snapshot.Resources.Services, corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "metrics-server", Namespace: "metrics"}})
	snapshot.Resources.APIServices = []models.APIServiceSummary{
		{Name: "v1beta1.metrics.k8s.io", Group: "metrics.k8s.io", Version: "v1beta1", ServiceNamespace: "metrics", ServiceName: "metrics-server", InsecureSkipTLSVerify: true},
		{Name: "v1.apps", Group: "apps", Version: "v1", Automanaged: "onstart"},
	}
	// insecureSkipTLSVerify: the routing half alone suffices, aggregated group means
	// traffic_intercept.
	bindSA(&snapshot, "metrics", "ci", "slicer", []rbacv1.PolicyRule{{
		APIGroups: []string{"discovery.k8s.io"}, Resources: []string{"endpointslices"}, Verbs: []string{"create"},
	}})
	graph := BuildGraph(snapshot)
	got := actionEdges(graph, "ServiceAccount/metrics/ci", "control_plane_backend_hijack")
	if len(got) != 1 || got[0].To != sinkTrafficIntercept {
		t.Fatalf("insecure aggregated APIService should be hijackable from the routing half alone into traffic_intercept, got %+v", got)
	}
	if len(got[0].CutBreakers) != 1 {
		t.Fatalf("expected a single routing cut breaker, got %+v", got[0].CutBreakers)
	}
	// A native-group APIService pointed at a Service leads to cluster_admin.
	snapshot.Resources.APIServices[0] = models.APIServiceSummary{Name: "v1.authentication.k8s.io", Group: "authentication.k8s.io", Version: "v1", ServiceNamespace: "metrics", ServiceName: "metrics-server", HasCABundle: true}
	bindSA(&snapshot, "metrics", "ci", "secrets", []rbacv1.PolicyRule{{
		APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"list"},
	}})
	got = actionEdges(BuildGraph(snapshot), "ServiceAccount/metrics/ci", "control_plane_backend_hijack")
	if len(got) != 1 || got[0].To != sinkClusterAdmin {
		t.Fatalf("native-group APIService backend should lead to cluster_admin, got %+v", got)
	}
}

func TestAPIServiceTakeoverEdge(t *testing.T) {
	snapshot := backendSnapshot()
	snapshot.Resources.APIServices = []models.APIServiceSummary{
		{Name: "v1beta1.metrics.k8s.io", Group: "metrics.k8s.io", Version: "v1beta1", ServiceNamespace: "metrics", ServiceName: "metrics-server"},
	}
	// Unscoped: cluster_admin.
	bindClusterSA(&snapshot, "apps", "installer", "apiservice-editor", []rbacv1.PolicyRule{{
		APIGroups: []string{"apiregistration.k8s.io"}, Resources: []string{"apiservices"}, Verbs: []string{"update"},
	}})
	got := actionEdges(BuildGraph(snapshot), "ServiceAccount/apps/installer", "apiservice_takeover")
	if len(got) != 1 || got[0].To != sinkClusterAdmin || got[0].Technique != "KUBE-PRIVESC-020" {
		t.Fatalf("unscoped apiservices update should reach cluster_admin, got %+v", got)
	}
	// Name-scoped to an aggregated registration: traffic_intercept.
	snapshot = backendSnapshot()
	snapshot.Resources.APIServices = []models.APIServiceSummary{
		{Name: "v1beta1.metrics.k8s.io", Group: "metrics.k8s.io", Version: "v1beta1", ServiceNamespace: "metrics", ServiceName: "metrics-server"},
	}
	bindClusterSA(&snapshot, "apps", "metrics", "metrics-apiservice", []rbacv1.PolicyRule{{
		APIGroups: []string{"apiregistration.k8s.io"}, Resources: []string{"apiservices"}, Verbs: []string{"patch"}, ResourceNames: []string{"v1beta1.metrics.k8s.io"},
	}})
	got = actionEdges(BuildGraph(snapshot), "ServiceAccount/apps/metrics", "apiservice_takeover")
	if len(got) != 1 || got[0].To != sinkTrafficIntercept {
		t.Fatalf("name-scoped aggregated apiservices patch should reach traffic_intercept, got %+v", got)
	}
	// Name-scoped to a native registration: cluster_admin.
	snapshot = backendSnapshot()
	bindClusterSA(&snapshot, "apps", "rbacsvc", "rbac-apiservice", []rbacv1.PolicyRule{{
		APIGroups: []string{"apiregistration.k8s.io"}, Resources: []string{"apiservices"}, Verbs: []string{"patch"}, ResourceNames: []string{"v1.rbac.authorization.k8s.io"},
	}})
	got = actionEdges(BuildGraph(snapshot), "ServiceAccount/apps/rbacsvc", "apiservice_takeover")
	if len(got) != 1 || got[0].To != sinkClusterAdmin {
		t.Fatalf("name-scoped native apiservices patch should reach cluster_admin, got %+v", got)
	}
}
