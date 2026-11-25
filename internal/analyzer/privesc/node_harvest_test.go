package privesc

import (
	"slices"
	"strings"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// runningPod is a live pod bound to node, running as sa.
func runningPod(name, namespace, node, sa string) corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec:       corev1.PodSpec{NodeName: node, ServiceAccountName: sa},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

func privilegedPod(name, namespace, node, sa string) corev1.Pod {
	pod := runningPod(name, namespace, node, sa)
	privileged := true
	pod.Spec.Containers = []corev1.Container{{Name: "c", SecurityContext: &corev1.SecurityContext{Privileged: &privileged}}}
	return pod
}

// wizChainSnapshot models the ARTEX-Harvester chain Wiz Research reported on
// 2026-11-23. apps/web holds `create pods` in a namespace with no Pod Security
// label. cert-manager shares worker-2 with nothing, and Argo CD's application
// controller (bound to cluster-admin) runs on worker-1. A cluster-admin-bound
// ServiceAccount also runs on a control-plane node tainted for its role, which an
// attacker pod is not modeled as reaching.
func wizChainSnapshot() models.Snapshot {
	snapshot := models.Snapshot{Resources: models.SnapshotResources{
		Namespaces: []corev1.Namespace{
			{ObjectMeta: metav1.ObjectMeta{Name: "apps"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "cert-manager", Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}}},
			{ObjectMeta: metav1.ObjectMeta{Name: "argocd", Labels: map[string]string{"pod-security.kubernetes.io/enforce": "baseline"}}},
			{ObjectMeta: metav1.ObjectMeta{Name: "platform"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}},
		},
		Nodes: []corev1.Node{
			{ObjectMeta: metav1.ObjectMeta{Name: "worker-1"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "worker-2"}},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "cp-1", Labels: map[string]string{"node-role.kubernetes.io/control-plane": ""}},
				Spec: corev1.NodeSpec{Taints: []corev1.Taint{{
					Key: "node-role.kubernetes.io/control-plane", Effect: corev1.TaintEffectNoSchedule,
				}}},
			},
		},
		ServiceAccounts: []corev1.ServiceAccount{
			{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "apps"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "cert-manager", Namespace: "cert-manager"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "argocd-application-controller", Namespace: "argocd"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "cp-operator", Namespace: "platform"}},
		},
		Pods: []corev1.Pod{
			runningPod("web-0", "apps", "worker-1", "web"),
			runningPod("cert-manager-0", "cert-manager", "worker-2", "cert-manager"),
			runningPod("argocd-application-controller-0", "argocd", "worker-1", "argocd-application-controller"),
			runningPod("cp-operator-0", "platform", "cp-1", "cp-operator"),
		},
	}}
	bindSA(&snapshot, "apps", "web", "pod-creator", []rbacv1.PolicyRule{{
		APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"create", "get", "list"},
	}})
	bindClusterSA(&snapshot, "cert-manager", "cert-manager", "cert-manager-controller", []rbacv1.PolicyRule{{
		APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get", "list", "watch", "create", "update"},
	}})
	for _, sa := range []struct{ ns, name string }{{"argocd", "argocd-application-controller"}, {"platform", "cp-operator"}} {
		snapshot.Resources.ClusterRoleBindings = append(snapshot.Resources.ClusterRoleBindings, rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: sa.name + "-admin"},
			Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: sa.name, Namespace: sa.ns}},
			RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
		})
	}
	return snapshot
}

func harvestTargets(graph *models.EscalationGraph) map[string]bool {
	out := map[string]bool{}
	for _, e := range graph.Edges {
		if e.From == sinkNodeEscape && e.Action == "node_token_harvest" {
			out[e.To] = true
		}
	}
	return out
}

// TestNodeTokenHarvestWizChain walks the reported chain end to end: a pod-create
// token in a namespace without baseline enforcement reaches cluster-admin through
// the strongest token on a node, and the findings rank that route first.
func TestNodeTokenHarvestWizChain(t *testing.T) {
	t.Parallel()
	snapshot := wizChainSnapshot()
	graph := BuildGraph(snapshot)

	if !graph.Nodes[sinkNodeEscape].Traversable {
		t.Fatal("node_escape should be traversable when token-mounting pods run on reachable nodes")
	}
	targets := harvestTargets(graph)
	for _, want := range []string{
		"subject:ServiceAccount/cert-manager/cert-manager",
		"subject:ServiceAccount/argocd/argocd-application-controller",
		"subject:ServiceAccount/apps/web",
	} {
		if !targets[want] {
			t.Errorf("expected a node_token_harvest edge to %s, got %v", want, targets)
		}
	}
	if targets["subject:ServiceAccount/platform/cp-operator"] {
		t.Error("a pod on a control-plane node tainted for its role must not be harvested from a chosen node")
	}
	for _, e := range graph.Edges {
		if e.From == sinkNodeEscape && e.Action == "node_token_harvest" {
			if e.Needs != models.FootholdNodeOfChoice || e.Grants != models.FootholdIdentity|models.FootholdToken {
				t.Fatalf("harvest edge footholds: needs %b grants %b", e.Needs, e.Grants)
			}
			if e.Difficulty != difficultyEasy || e.Technique != nodeHarvestTechnique {
				t.Fatalf("harvest edge rating: %+v", e)
			}
		}
	}

	paths := FindPaths(graph, 5)
	got, ok := pathActions(paths, "ServiceAccount/apps/web", models.TargetClusterAdmin)
	want := []string{"pod_create_privileged_escape", "node_token_harvest", "bound_to_cluster_admin"}
	if !ok || !slices.Equal(got, want) {
		t.Fatalf("apps/web -> cluster-admin = %v (found %v), want %v", got, ok, want)
	}
	// cert-manager's token carries the chain on to its own targets.
	if got, ok := pathActions(paths, "ServiceAccount/apps/web", models.TargetKubeSystemSecrets); !ok || !slices.Contains(got, "node_token_harvest") {
		t.Fatalf("apps/web -> kube-system secrets via cert-manager = %v (found %v)", got, ok)
	}

	findings, err := New().Analyze(t.Context(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var top *models.Finding
	for i := range findings {
		f := &findings[i]
		if !strings.Contains(f.ID, ":ServiceAccount/apps/web:") || !strings.HasPrefix(f.RuleID, "KUBE-PRIVESC-PATH-") {
			continue
		}
		if top == nil || f.Score > top.Score {
			top = f
		}
	}
	if top == nil || top.RuleID != "KUBE-PRIVESC-PATH-CLUSTER-ADMIN" || top.Severity != models.SeverityCritical {
		t.Fatalf("highest-scored path finding for apps/web = %+v, want a CRITICAL cluster-admin path", top)
	}
}

// TestNodeTokenHarvestNeedsAPermissiveNamespace: with baseline enforced where the
// pod-create grant lives, no privileged pod is admitted, so nothing is harvested.
func TestNodeTokenHarvestNeedsAPermissiveNamespace(t *testing.T) {
	t.Parallel()
	snapshot := wizChainSnapshot()
	snapshot.Resources.Namespaces[0].Labels = map[string]string{"pod-security.kubernetes.io/enforce": "baseline"}
	paths := FindPaths(BuildGraph(snapshot), 5)
	if got, ok := pathActions(paths, "ServiceAccount/apps/web", models.TargetClusterAdmin); ok {
		t.Fatalf("baseline namespace: expected no cluster-admin path for apps/web, got %v", got)
	}
}

// TestNodeTokenHarvestExistingPodStaysOnItsNode: a pod that already runs
// privileged reaches node_escape but not the chosen-node fan-out; it harvests only
// the ServiceAccounts whose pods share its own node.
func TestNodeTokenHarvestExistingPodStaysOnItsNode(t *testing.T) {
	t.Parallel()
	snapshot := wizChainSnapshot()
	snapshot.Resources.Pods = append(snapshot.Resources.Pods, privilegedPod("agent-x", "apps", "worker-2", "agent"))

	graph := BuildGraph(snapshot)
	paths := FindPaths(graph, 5)
	if _, ok := pathActions(paths, "ServiceAccount/apps/agent", models.TargetNodeEscape); !ok {
		t.Fatal("the privileged pod should still reach node_escape")
	}
	if got, ok := pathActions(paths, "ServiceAccount/apps/agent", models.TargetClusterAdmin); ok {
		t.Fatalf("worker-2 holds no cluster-admin token, so apps/agent must not reach cluster-admin, got %v", got)
	}
	edges := actionEdges(graph, "ServiceAccount/apps/agent", "node_token_harvest")
	if len(edges) != 1 || edges[0].To != "subject:ServiceAccount/cert-manager/cert-manager" || edges[0].Needs != models.FootholdPod {
		t.Fatalf("expected one same-node harvest edge to cert-manager needing FootholdPod, got %+v", edges)
	}

	// Moved onto worker-1, beside the Argo CD controller, it reaches cluster-admin.
	snapshot.Resources.Pods[len(snapshot.Resources.Pods)-1].Spec.NodeName = "worker-1"
	paths = FindPaths(BuildGraph(snapshot), 5)
	got, ok := pathActions(paths, "ServiceAccount/apps/agent", models.TargetClusterAdmin)
	if !ok || !slices.Equal(got, []string{"node_token_harvest", "bound_to_cluster_admin"}) {
		t.Fatalf("apps/agent on worker-1 -> cluster-admin = %v (found %v)", got, ok)
	}
}

// TestNodeTokenHarvestSkipsPodsWithoutAPIToken: a pod that opts out of the token
// mount leaves nothing on disk to read.
func TestNodeTokenHarvestSkipsPodsWithoutAPIToken(t *testing.T) {
	t.Parallel()
	snapshot := wizChainSnapshot()
	off := false
	for i := range snapshot.Resources.Pods {
		if snapshot.Resources.Pods[i].Namespace == "argocd" {
			snapshot.Resources.Pods[i].Spec.AutomountServiceAccountToken = &off
		}
	}
	if harvestTargets(BuildGraph(snapshot))["subject:ServiceAccount/argocd/argocd-application-controller"] {
		t.Fatal("a pod with automountServiceAccountToken=false must not be harvested")
	}
}

func TestHostTokenAccess(t *testing.T) {
	t.Parallel()
	hostPath := func(p string) corev1.Pod {
		pod := runningPod("p", "apps", "n", "sa")
		pod.Spec.Volumes = []corev1.Volume{{Name: "h", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: p}}}}
		return pod
	}
	hostPID := runningPod("p", "apps", "n", "sa")
	hostPID.Spec.HostPID = true
	hostNetwork := runningPod("p", "apps", "n", "sa")
	hostNetwork.Spec.HostNetwork = true

	tests := []struct {
		name string
		pod  corev1.Pod
		want bool
	}{
		{"privileged", privilegedPod("p", "apps", "n", "sa"), true},
		{"hostPath root", hostPath("/"), true},
		{"hostPath /var", hostPath("/var"), true},
		{"hostPath kubelet dir", hostPath("/var/lib/kubelet"), true},
		{"hostPath kubelet pods dir with slash", hostPath("/var/lib/kubelet/pods/"), true},
		{"containerd socket", hostPath("/run/containerd/containerd.sock"), true},
		{"hostPath /var/log", hostPath("/var/log"), false},
		{"hostPath /etc", hostPath("/etc"), false},
		{"hostPath one pod's dir", hostPath("/var/lib/kubelet/pods/abc"), false},
		{"hostPID alone", hostPID, false},
		{"hostNetwork alone", hostNetwork, false},
		{"plain pod", runningPod("p", "apps", "n", "sa"), false},
	}
	for _, tc := range tests {
		if got := hostTokenAccess(tc.pod) != ""; got != tc.want {
			t.Errorf("%s: hostTokenAccess = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestHarvestUnreachableNodes(t *testing.T) {
	t.Parallel()
	snapshot := models.Snapshot{Resources: models.SnapshotResources{Nodes: []corev1.Node{
		{ObjectMeta: metav1.ObjectMeta{Name: "worker"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "fargate-ip-10-0-0-1"}, Spec: corev1.NodeSpec{ProviderID: fargateProviderIDPrefix + "us-east-1a/abc"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "win", Labels: map[string]string{corev1.LabelOSStable: "windows"}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "cp-open", Labels: map[string]string{"node-role.kubernetes.io/control-plane": ""}}},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "cp-tainted", Labels: map[string]string{"node-role.kubernetes.io/control-plane": ""}},
			Spec:       corev1.NodeSpec{Taints: []corev1.Taint{{Key: "node-role.kubernetes.io/control-plane", Effect: corev1.TaintEffectNoSchedule}}},
		},
		{
			// A dedicated worker pool: the taint steers the scheduler, but the
			// attacker's pod sets spec.nodeName and tolerations, so it stays reachable.
			ObjectMeta: metav1.ObjectMeta{Name: "prod-pool"},
			Spec:       corev1.NodeSpec{Taints: []corev1.Taint{{Key: "dedicated", Value: "prod", Effect: corev1.TaintEffectNoSchedule}}},
		},
	}}}
	got := harvestUnreachableNodes(snapshot)
	want := map[string]bool{"fargate-ip-10-0-0-1": true, "win": true, "cp-tainted": true}
	if len(got) != len(want) {
		t.Fatalf("unreachable = %v, want %v", got, want)
	}
	for n := range want {
		if !got[n] {
			t.Fatalf("unreachable = %v, want %v", got, want)
		}
	}
}

// TestNodeOfChoiceFootholdStampedOnlyOnAuthoredEscapes pins which edges into
// node_escape carry the foothold the chosen-node fan-out needs.
func TestNodeOfChoiceFootholdStampedOnlyOnAuthoredEscapes(t *testing.T) {
	t.Parallel()
	snapshot := wizChainSnapshot()
	snapshot.Resources.Pods = append(snapshot.Resources.Pods, privilegedPod("agent-x", "apps", "worker-2", "agent"))
	for _, e := range BuildGraph(snapshot).Edges {
		if e.To != sinkNodeEscape {
			continue
		}
		has := edgeGrants(e)&models.FootholdNodeOfChoice != 0
		if has != nodeOfChoiceEscapes[e.Action] {
			t.Errorf("edge %s -> node_escape: FootholdNodeOfChoice = %v", e.Action, has)
		}
		if edgeGrants(e)&models.FootholdIdentity == 0 {
			t.Errorf("edge %s -> node_escape lost FootholdIdentity, which the control-plane continuation needs", e.Action)
		}
	}
}
