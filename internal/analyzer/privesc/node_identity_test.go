package privesc

import (
	"strings"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// nodeIdentitySnapshot builds a cluster with two nodes, a kube-system pod that
// mounts a Secret, and an application pod whose ServiceAccount can read
// kube-system Secrets (so the fan-out has a sink to reach).
func nodeIdentitySnapshot() models.Snapshot {
	snapshot := models.Snapshot{Resources: models.SnapshotResources{
		Namespaces: []corev1.Namespace{
			{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "apps"}},
		},
		Nodes: []corev1.Node{
			{ObjectMeta: metav1.ObjectMeta{Name: "cp-1"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "worker-1"}},
		},
		Pods: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "kube-controller-manager-cp-1", Namespace: "kube-system"},
				Spec: corev1.PodSpec{NodeName: "cp-1", ServiceAccountName: "default", Volumes: []corev1.Volume{{
					Name: "creds", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "cloud-creds"}},
				}}},
				Status: corev1.PodStatus{Phase: corev1.PodRunning},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "backup-0", Namespace: "apps"},
				Spec:       corev1.PodSpec{NodeName: "worker-1", ServiceAccountName: "backup"},
				Status:     corev1.PodStatus{Phase: corev1.PodRunning},
			},
		},
	}}
	// backup can read kube-system Secrets: the node identity fan-out reaches it,
	// and from it the kube_system_secrets sink.
	bindSA(&snapshot, "kube-system", "backup", "ks-secret-reader", []rbacv1.PolicyRule{{
		APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get", "list"},
	}})
	// The binding above lives in kube-system but names the apps/backup SA.
	snapshot.Resources.RoleBindings[len(snapshot.Resources.RoleBindings)-1].Subjects[0].Namespace = "apps"
	return snapshot
}

func TestNodeClientAutoApproveEdge(t *testing.T) {
	snapshot := nodeIdentitySnapshot()
	bindClusterSA(&snapshot, "apps", "joiner", "csr-submitter", []rbacv1.PolicyRule{{
		APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"certificatesigningrequests"}, Verbs: []string{"create", "get"},
	}})
	bindClusterSA(&snapshot, "apps", "joiner", "nodeclient-approver", []rbacv1.PolicyRule{{
		APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"certificatesigningrequests/nodeclient"}, Verbs: []string{"create"},
	}})
	graph := BuildGraph(snapshot)
	edges := actionEdges(graph, "ServiceAccount/apps/joiner", "csr_nodeclient_autoapprove")
	if len(edges) != 1 || edges[0].To != sinkNodeIdentity || edges[0].Technique != "KUBE-PRIVESC-037" {
		t.Fatalf("expected one csr_nodeclient_autoapprove edge into node_identity, got %+v", edges)
	}
	if len(edges[0].CutBreakers) != 2 {
		t.Fatalf("expected both bindings as cut breakers, got %+v", edges[0].CutBreakers)
	}
	// Fan-out: node_identity reaches the backup SA (token-mounting pod on a node)
	// and kube_system_secrets (kube-system pod referencing a Secret).
	fan := map[string]bool{}
	for _, e := range graph.Edges {
		if e.From == sinkNodeIdentity {
			fan[e.Action+"->"+e.To] = true
		}
	}
	if !fan["node_token_request->subject:ServiceAccount/apps/backup"] {
		t.Fatalf("expected node_token_request fan-out to apps/backup, got %v", fan)
	}
	if !fan["node_secret_read->"+sinkKubeSystemSecrets] {
		t.Fatalf("expected node_secret_read fan-out to kube_system_secrets, got %v", fan)
	}

	findings, err := New().Analyze(t.Context(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var nodeIdentity, viaNode bool
	for _, f := range findings {
		if strings.HasPrefix(f.ID, "KUBE-PRIVESC-PATH-NODE-IDENTITY:ServiceAccount/apps/joiner:") {
			nodeIdentity = true
			if f.Severity != models.SeverityHigh {
				t.Errorf("node identity path severity = %s, want HIGH", f.Severity)
			}
		}
		if strings.HasPrefix(f.ID, "KUBE-PRIVESC-PATH-KUBE-SYSTEM-SECRETS:ServiceAccount/apps/joiner:") {
			viaNode = true
		}
	}
	if !nodeIdentity {
		t.Fatalf("expected a node identity path finding for apps/joiner")
	}
	if !viaNode {
		t.Fatalf("expected the traversable sink to carry apps/joiner on to kube_system_secrets")
	}

	// The nodeclient subresource alone (no CSR create) is not enough.
	snapshot = nodeIdentitySnapshot()
	bindClusterSA(&snapshot, "apps", "half", "nodeclient-approver", []rbacv1.PolicyRule{{
		APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"certificatesigningrequests/nodeclient"}, Verbs: []string{"create"},
	}})
	if got := actionEdges(BuildGraph(snapshot), "ServiceAccount/apps/half", "csr_nodeclient_autoapprove"); len(got) != 0 {
		t.Fatalf("nodeclient without CSR create must not produce an edge, got %d", len(got))
	}
}

func TestBootstrapTokenMintEdgeGate(t *testing.T) {
	rule := []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"create"}}}
	// Without the kubeadm auto-approval binding: no edge.
	snapshot := nodeIdentitySnapshot()
	bindSA(&snapshot, "kube-system", "installer", "secret-writer", rule)
	if got := actionEdges(BuildGraph(snapshot), "ServiceAccount/kube-system/installer", "bootstrap_token_mint"); len(got) != 0 {
		t.Fatalf("no kubeadm binding: expected no bootstrap_token_mint edge, got %d", len(got))
	}
	// With it: the edge into node_identity.
	snapshot = nodeIdentitySnapshot()
	snapshot.Resources.ClusterRoleBindings = append(snapshot.Resources.ClusterRoleBindings, rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "kubeadm:node-autoapprove-bootstrap"},
		Subjects:   []rbacv1.Subject{{Kind: "Group", Name: "system:bootstrappers:kubeadm:default-node-token"}},
		RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "system:certificates.k8s.io:certificatesigningrequests:nodeclient"},
	})
	bindSA(&snapshot, "kube-system", "installer", "secret-writer", rule)
	got := actionEdges(BuildGraph(snapshot), "ServiceAccount/kube-system/installer", "bootstrap_token_mint")
	if len(got) != 1 || got[0].To != sinkNodeIdentity || got[0].Technique != "KUBE-PRIVESC-026" {
		t.Fatalf("expected bootstrap_token_mint edge into node_identity, got %+v", got)
	}
	// A Secret write in another namespace does not reach kube-system.
	bindSA(&snapshot, "apps", "tenant", "secret-writer", rule)
	if got := actionEdges(BuildGraph(snapshot), "ServiceAccount/apps/tenant", "bootstrap_token_mint"); len(got) != 0 {
		t.Fatalf("apps-scoped Secret write must not mint bootstrap tokens, got %d", len(got))
	}
}

func TestImpersonateNodeEdge(t *testing.T) {
	snapshot := nodeIdentitySnapshot()
	bindClusterSA(&snapshot, "apps", "proxy", "node-impersonator", []rbacv1.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"users"}, Verbs: []string{"impersonate"}},
		{APIGroups: []string{""}, Resources: []string{"groups"}, Verbs: []string{"impersonate"}, ResourceNames: []string{"system:nodes"}},
	})
	graph := BuildGraph(snapshot)
	got := actionEdges(graph, "ServiceAccount/apps/proxy", "impersonate_node")
	if len(got) != 1 || got[0].To != sinkNodeIdentity {
		t.Fatalf("expected impersonate_node edge into node_identity, got %+v", got)
	}
	// The scoped groups grant must not also reach system_masters.
	if masters := actionEdges(graph, "ServiceAccount/apps/proxy", "impersonate_system_masters"); len(masters) != 0 {
		t.Fatalf("groups scoped to system:nodes must not reach system_masters, got %d", len(masters))
	}
}
