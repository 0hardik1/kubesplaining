package privesc

import (
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

// fluxSnapshot builds a snapshot where a tenant SA can create Flux Kustomizations.
// installController controls whether the reconciling controller SA actually exists,
// which is the precision gate for the whole edge family.
func fluxSnapshot(installController bool) models.Snapshot {
	snapshot := models.Snapshot{}
	snapshot.Resources.Namespaces = []corev1.Namespace{
		{ObjectMeta: objectMeta("tenant", "")},
		{ObjectMeta: objectMeta("flux-system", "")},
	}
	snapshot.Resources.Roles = []rbacv1.Role{{
		ObjectMeta: objectMeta("gitops", "tenant"),
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{"kustomize.toolkit.fluxcd.io"},
			Resources: []string{"kustomizations"},
			Verbs:     []string{"create", "patch"},
		}},
	}}
	snapshot.Resources.RoleBindings = []rbacv1.RoleBinding{{
		ObjectMeta: objectMeta("gitops-rb", "tenant"),
		RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "gitops"},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "dev-deployer", Namespace: "tenant"}},
	}}
	if installController {
		snapshot.Resources.ServiceAccounts = []corev1.ServiceAccount{
			{ObjectMeta: objectMeta("kustomize-controller", "flux-system")},
		}
		snapshot.Resources.ClusterRoleBindings = []rbacv1.ClusterRoleBinding{{
			ObjectMeta: objectMeta("flux-crb", ""),
			RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
			Subjects: []rbacv1.Subject{
				{Kind: "ServiceAccount", Name: "kustomize-controller", Namespace: "flux-system"},
			},
		}}
	}
	return snapshot
}

// TestConfusedDeputyBridgesToControllerSA proves a tenant holding no dangerous
// Kubernetes verb of its own still reaches cluster-admin by steering a reconciler.
func TestConfusedDeputyBridgesToControllerSA(t *testing.T) {
	t.Parallel()

	graph := BuildGraph(fluxSnapshot(true))
	paths := FindPaths(graph, 5)

	var found bool
	for _, p := range paths {
		if p.Source.Name == "dev-deployer" && p.Target == models.TargetClusterAdmin &&
			len(p.Hops) >= 2 && p.Hops[0].Action == "operator_reconcile" {
			found = true
		}
	}
	if !found {
		t.Fatalf("want dev-deployer -> kustomize-controller -> cluster_admin; paths: %+v", paths)
	}
}

// TestConfusedDeputyRequiresInstalledController is the precision gate: a stray RBAC
// grant on a CRD that no operator serves must produce nothing.
func TestConfusedDeputyRequiresInstalledController(t *testing.T) {
	t.Parallel()

	graph := BuildGraph(fluxSnapshot(false))
	for _, edge := range graph.Edges {
		if edge.Action == "operator_reconcile" {
			t.Fatalf("emitted an operator_reconcile edge with no controller SA installed: %+v", edge)
		}
	}
}

// TestConfusedDeputyEmitsBridgePerBinding is the same property for the operator bridge:
// one subject granted write on a catalogued custom resource by two bindings must produce
// two operator_reconcile edges, so the cut-resilient pass sees the second binding still
// steers the controller when the first is cut.
func TestConfusedDeputyEmitsBridgePerBinding(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{}
	snapshot.Resources.Namespaces = []corev1.Namespace{
		{ObjectMeta: objectMeta("tenant", "")},
		{ObjectMeta: objectMeta("flux-system", "")},
	}
	snapshot.Resources.ServiceAccounts = []corev1.ServiceAccount{
		{ObjectMeta: objectMeta("kustomize-controller", "flux-system")},
	}
	snapshot.Resources.ClusterRoleBindings = []rbacv1.ClusterRoleBinding{{
		ObjectMeta: objectMeta("flux-crb", ""),
		RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
		Subjects: []rbacv1.Subject{
			{Kind: "ServiceAccount", Name: "kustomize-controller", Namespace: "flux-system"},
		},
	}}
	snapshot.Resources.Roles = []rbacv1.Role{
		{
			ObjectMeta: objectMeta("gitops-a", "tenant"),
			Rules: []rbacv1.PolicyRule{{
				APIGroups: []string{"kustomize.toolkit.fluxcd.io"},
				Resources: []string{"kustomizations"},
				Verbs:     []string{"create"},
			}},
		},
		{
			ObjectMeta: objectMeta("gitops-b", "tenant"),
			Rules: []rbacv1.PolicyRule{{
				APIGroups: []string{"kustomize.toolkit.fluxcd.io"},
				Resources: []string{"kustomizations"},
				Verbs:     []string{"patch"},
			}},
		},
	}
	snapshot.Resources.RoleBindings = []rbacv1.RoleBinding{
		{
			ObjectMeta: objectMeta("gitops-rb-a", "tenant"),
			RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "gitops-a"},
			Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "dev-deployer", Namespace: "tenant"}},
		},
		{
			ObjectMeta: objectMeta("gitops-rb-b", "tenant"),
			RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "gitops-b"},
			Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "dev-deployer", Namespace: "tenant"}},
		},
	}

	graph := BuildGraph(snapshot)

	const subjectID = "subject:ServiceAccount/tenant/dev-deployer"
	const controllerID = "subject:ServiceAccount/flux-system/kustomize-controller"
	bindings := map[string]bool{}
	var count int
	for _, edge := range graph.Edges {
		if edge.From != subjectID || edge.To != controllerID || edge.Action != "operator_reconcile" {
			continue
		}
		count++
		bindings[edge.SourceBinding] = true
	}
	if count != 2 {
		t.Fatalf("want 2 operator_reconcile edges, got %d (edges=%+v)", count, graph.Edges)
	}
	for _, want := range []string{"gitops-rb-a", "gitops-rb-b"} {
		if !bindings[want] {
			t.Errorf("no operator_reconcile edge stamped with binding %q; got %v", want, bindings)
		}
	}
}

// TestConfusedDeputyKyvernoPolicyWriter pins the Kyverno catalog entry: a tenant
// that can write kyverno.io Policies in its own namespace bridges to the Kyverno
// background controller when that controller is installed, and to nothing when
// Kyverno is absent. Generate rules in a namespaced Policy still run with the
// controller's identity, so the namespaced grant is the one that matters.
func TestConfusedDeputyKyvernoPolicyWriter(t *testing.T) {
	t.Parallel()

	build := func(installed bool) models.Snapshot {
		snapshot := models.Snapshot{}
		snapshot.Resources.Namespaces = []corev1.Namespace{
			{ObjectMeta: objectMeta("tenant", "")},
			{ObjectMeta: objectMeta("kyverno", "")},
		}
		snapshot.Resources.Roles = []rbacv1.Role{{
			ObjectMeta: objectMeta("policy-author", "tenant"),
			Rules: []rbacv1.PolicyRule{{
				APIGroups: []string{"kyverno.io"},
				Resources: []string{"policies"},
				Verbs:     []string{"create"},
			}},
		}}
		snapshot.Resources.RoleBindings = []rbacv1.RoleBinding{{
			ObjectMeta: objectMeta("policy-author-rb", "tenant"),
			RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "policy-author"},
			Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "tenant-dev", Namespace: "tenant"}},
		}}
		if installed {
			snapshot.Resources.ServiceAccounts = []corev1.ServiceAccount{
				{ObjectMeta: objectMeta("kyverno-background-controller", "kyverno")},
			}
			snapshot.Resources.ClusterRoleBindings = []rbacv1.ClusterRoleBinding{{
				ObjectMeta: objectMeta("kyverno-crb", ""),
				RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
				Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "kyverno-background-controller", Namespace: "kyverno"}},
			}}
		}
		return snapshot
	}

	paths := FindPaths(BuildGraph(build(true)), 5)
	var found bool
	for _, p := range paths {
		if p.Source.Name == "tenant-dev" && p.Target == models.TargetClusterAdmin &&
			len(p.Hops) >= 2 && p.Hops[0].Action == "operator_reconcile" &&
			p.Hops[0].ToSubject.Name == "kyverno-background-controller" {
			found = true
		}
	}
	if !found {
		t.Fatalf("want tenant-dev -> kyverno-background-controller -> cluster_admin; paths: %+v", paths)
	}

	for _, p := range FindPaths(BuildGraph(build(false)), 5) {
		if p.Source.Name == "tenant-dev" {
			t.Fatalf("Kyverno not installed: unexpected path %+v", p)
		}
	}
}
