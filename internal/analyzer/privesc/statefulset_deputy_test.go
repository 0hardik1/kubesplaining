package privesc

import (
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// deputySnapshot builds a snapshot where the ServiceAccount attacker/writer in
// namespace "app" is granted the given resources with write verbs via one Role, on
// the given server version. A privileged-admitting kube-system SA ("controller")
// exists so a node-escape target is present, and a distinct SA lives in a namespace
// the writer has no access to, so the cross-namespace fan-out has somewhere to reach.
func deputySnapshot(version string, resources ...string) models.Snapshot {
	snapshot := models.Snapshot{}
	snapshot.Metadata.ClusterVersion = version
	snapshot.Resources.Namespaces = []corev1.Namespace{
		{ObjectMeta: metav1.ObjectMeta{Name: "app"}},    // unlabeled -> admits privileged
		{ObjectMeta: metav1.ObjectMeta{Name: "victim"}}, // unlabeled
	}
	snapshot.Resources.ServiceAccounts = []corev1.ServiceAccount{
		{ObjectMeta: metav1.ObjectMeta{Name: "writer", Namespace: "app"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "victim-sa", Namespace: "victim"}},
	}
	snapshot.Resources.Roles = []rbacv1.Role{{
		ObjectMeta: metav1.ObjectMeta{Name: "sts-writer", Namespace: "app"},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{"apps"},
			Resources: resources,
			Verbs:     []string{"create", "update", "patch"},
		}},
	}}
	snapshot.Resources.RoleBindings = []rbacv1.RoleBinding{{
		ObjectMeta: metav1.ObjectMeta{Name: "sts-writer-binding", Namespace: "app"},
		RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "sts-writer"},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "writer", Namespace: "app"}},
	}}
	return snapshot
}

func hasDeputyEdge(g *models.EscalationGraph) bool {
	for _, edge := range g.Edges {
		if edge.Action == "statefulset_cross_namespace_pod" {
			return true
		}
	}
	return false
}

func hasDeputyEdgeTo(g *models.EscalationGraph, to string) bool {
	for _, edge := range g.Edges {
		if edge.Action == "statefulset_cross_namespace_pod" && edge.To == to {
			return true
		}
	}
	return false
}

// TestStatefulSetDeputyEdgeRequiresBothHalves: only a subject holding write on BOTH
// statefulsets and controllerrevisions gets the edge, and only on an affected version.
func TestStatefulSetDeputyEdgeRequiresBothHalves(t *testing.T) {
	if !hasDeputyEdge(BuildGraph(deputySnapshot("v1.36.4", "statefulsets", "controllerrevisions"))) {
		t.Error("both halves + affected version: expected a statefulset_cross_namespace_pod edge")
	}
	if hasDeputyEdge(BuildGraph(deputySnapshot("v1.36.4", "statefulsets"))) {
		t.Error("statefulsets write alone: unexpected deputy edge")
	}
	if hasDeputyEdge(BuildGraph(deputySnapshot("v1.36.4", "controllerrevisions"))) {
		t.Error("controllerrevisions write alone: unexpected deputy edge")
	}
}

// TestStatefulSetDeputyEdgeVersionGated: a patched or unknown version stays quiet
// even when both write halves are present.
func TestStatefulSetDeputyEdgeVersionGated(t *testing.T) {
	both := []string{"statefulsets", "controllerrevisions"}
	if hasDeputyEdge(BuildGraph(deputySnapshot("v1.36.5", both...))) {
		t.Error("patched version v1.36.5: expected no deputy edge")
	}
	if hasDeputyEdge(BuildGraph(deputySnapshot("", both...))) {
		t.Error("empty version: expected no deputy edge (fail-closed)")
	}
	if hasDeputyEdge(BuildGraph(deputySnapshot("v1.37.1", both...))) {
		t.Error("patched version v1.37.1: expected no deputy edge")
	}
}

// TestStatefulSetDeputyEdgeReachesCrossNamespaceAndNodeEscape: the edge fans out to
// a ServiceAccount in a namespace the writer cannot access, and reaches node escape
// because an unrestricted namespace admits a privileged pod. Both are rated hard.
func TestStatefulSetDeputyEdgeReachesCrossNamespaceAndNodeEscape(t *testing.T) {
	g := BuildGraph(deputySnapshot("v1.35.8", "statefulsets", "controllerrevisions"))

	victim := nodeID(models.SubjectRef{Kind: "ServiceAccount", Name: "victim-sa", Namespace: "victim"})
	if !hasDeputyEdgeTo(g, victim) {
		t.Error("expected a cross-namespace token-theft edge to victim/victim-sa")
	}
	if !hasDeputyEdgeTo(g, sinkNodeEscape) {
		t.Error("expected a node-escape edge (unrestricted namespace admits a privileged pod)")
	}
	for _, edge := range g.Edges {
		if edge.Action == "statefulset_cross_namespace_pod" && edge.Difficulty != difficultyHard {
			t.Errorf("deputy edge to %s rated %q, want %q", edge.To, edge.Difficulty, difficultyHard)
		}
	}
}

// TestStatefulSetDeputyEdgeSkipsFullWildcard: a *//*/* holder is already
// cluster-admin (KUBE-PRIVESC-017), so it draws no separate deputy edge.
func TestStatefulSetDeputyEdgeSkipsFullWildcard(t *testing.T) {
	snapshot := deputySnapshot("v1.36.4")
	snapshot.Resources.Roles[0].Rules = []rbacv1.PolicyRule{{
		APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"},
	}}
	if hasDeputyEdge(BuildGraph(snapshot)) {
		t.Error("full wildcard subject: expected no separate deputy edge")
	}
}

// TestStatefulSetDeputyEdgeCarriesCutBreakers: the edge records which binding cuts it,
// so the cut-resilient pass can model removing the grant.
func TestStatefulSetDeputyEdgeCarriesCutBreakers(t *testing.T) {
	g := BuildGraph(deputySnapshot("v1.36.4", "statefulsets", "controllerrevisions"))
	for _, edge := range g.Edges {
		if edge.Action != "statefulset_cross_namespace_pod" {
			continue
		}
		if len(edge.CutBreakers) == 0 {
			t.Fatalf("deputy edge to %s carries no CutBreakers", edge.To)
		}
		if edge.CutBreakers[0].Name != "sts-writer-binding" {
			t.Errorf("CutBreakers[0] = %q, want sts-writer-binding", edge.CutBreakers[0].Name)
		}
	}
}
