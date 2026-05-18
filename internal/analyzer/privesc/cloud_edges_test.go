package privesc

import (
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// findEdge returns the first edge in the graph matching the (from, to, action)
// triple, or nil if no edge matches. Test helper kept local because the
// production code never iterates edges by action.
func findEdge(graph *models.EscalationGraph, from, to, action string) *models.EscalationEdge {
	for _, edge := range graph.Edges {
		if edge.From == from && edge.To == to && edge.Action == action {
			return edge
		}
	}
	return nil
}

// hasNode reports whether the graph has a node with the given ID.
func hasNode(graph *models.EscalationGraph, id string) bool {
	_, ok := graph.Nodes[id]
	return ok
}

func TestAddCloudEdgesIRSAOnly(t *testing.T) {
	t.Parallel()

	// Stub addCloudEdges' input: install a fake cloud identity directly in the
	// snapshot's ServiceAccount annotations. The real cloud.CloudIdentitiesForSnapshot
	// reads the IRSA annotation to build CloudIdentity entries, so populating
	// the SA annotation drives the end-to-end behavior in BuildGraph.
	snapshot := models.Snapshot{
		Metadata: models.SnapshotMetadata{CloudProvider: "eks"},
		Resources: models.SnapshotResources{
			Namespaces: []corev1.Namespace{
				{ObjectMeta: objectMeta("apps", "")},
			},
			ServiceAccounts: []corev1.ServiceAccount{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "app-sa",
						Namespace: "apps",
						Annotations: map[string]string{
							"eks.amazonaws.com/role-arn": "arn:aws:iam::123456789012:role/AppRole",
						},
					},
				},
			},
		},
	}

	graph := BuildGraph(snapshot)
	externalID := externalAWSIAMNodeID("arn:aws:iam::123456789012:role/AppRole")
	saNodeID := "subject:ServiceAccount/apps/app-sa"

	if !hasNode(graph, externalID) {
		t.Fatalf("expected external AWS IAM node %q to be created", externalID)
	}
	node := graph.Nodes[externalID]
	if !node.IsExternal {
		t.Errorf("external node should have IsExternal=true; got %+v", node)
	}
	if !node.IsSink {
		t.Errorf("external node should be a sink (terminal for IRSA paths); got IsSink=false")
	}
	if node.Target != models.TargetAWSIAMRole {
		t.Errorf("external node Target = %q, want %q", node.Target, models.TargetAWSIAMRole)
	}

	edge := findEdge(graph, saNodeID, externalID, "irsa_assume_role")
	if edge == nil {
		t.Fatalf("expected irsa_assume_role edge from %s to %s; edges=%+v", saNodeID, externalID, graph.Edges)
	}
	if edge.Technique != "KUBE-CLOUD-IRSA-001" {
		t.Errorf("IRSA edge Technique = %q, want %q", edge.Technique, "KUBE-CLOUD-IRSA-001")
	}
}

func TestAddCloudEdgesAWSAuthSystemMasters(t *testing.T) {
	t.Parallel()

	// aws-auth ConfigMap lives in kube-system with name "aws-auth". Its mapRoles
	// YAML key holds the role-to-group mapping the cluster authenticator reads
	// at JWT-validation time. The cloud-identity loader consumes that YAML.
	const mapRoles = "" +
		"- rolearn: arn:aws:iam::123456789012:role/AdminRole\n" +
		"  username: admin-user\n" +
		"  groups:\n" +
		"    - system:masters\n"
	snapshot := models.Snapshot{
		Metadata: models.SnapshotMetadata{CloudProvider: "eks"},
		Resources: models.SnapshotResources{
			ConfigMaps: []models.ConfigMapSnapshot{
				{
					Name:      "aws-auth",
					Namespace: "kube-system",
					Data:      map[string]string{"mapRoles": mapRoles},
				},
			},
		},
	}

	graph := BuildGraph(snapshot)
	externalID := externalAWSIAMNodeID("arn:aws:iam::123456789012:role/AdminRole")
	if !hasNode(graph, externalID) {
		t.Fatalf("expected external IAM node %q to be created", externalID)
	}
	edge := findEdge(graph, externalID, sinkSystemMasters, "aws_auth_admin")
	if edge == nil {
		t.Fatalf("expected aws_auth_admin edge from %s to %s; edges=%+v", externalID, sinkSystemMasters, graph.Edges)
	}
	if edge.Technique != "KUBE-CLOUD-AWSAUTH-001" {
		t.Errorf("aws-auth edge Technique = %q, want %q", edge.Technique, "KUBE-CLOUD-AWSAUTH-001")
	}
}

func TestAddCloudEdgesAWSAuthCustomGroupBoundToClusterAdmin(t *testing.T) {
	t.Parallel()

	const mapRoles = "" +
		"- rolearn: arn:aws:iam::123456789012:role/TenantAdmin\n" +
		"  username: tenant-admin\n" +
		"  groups:\n" +
		"    - tenant-admins\n"
	snapshot := models.Snapshot{
		Metadata: models.SnapshotMetadata{CloudProvider: "eks"},
		Resources: models.SnapshotResources{
			ConfigMaps: []models.ConfigMapSnapshot{
				{
					Name:      "aws-auth",
					Namespace: "kube-system",
					Data:      map[string]string{"mapRoles": mapRoles},
				},
			},
			ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
				{
					ObjectMeta: objectMeta("tenant-admins-binding", ""),
					RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
					Subjects: []rbacv1.Subject{
						{Kind: "Group", Name: "tenant-admins"},
					},
				},
			},
		},
	}

	graph := BuildGraph(snapshot)
	externalID := externalAWSIAMNodeID("arn:aws:iam::123456789012:role/TenantAdmin")
	if !hasNode(graph, externalID) {
		t.Fatalf("expected external IAM node %q to be created", externalID)
	}
	edge := findEdge(graph, externalID, sinkClusterAdmin, "aws_auth_admin")
	if edge == nil {
		t.Fatalf("expected aws_auth_admin edge from %s to %s; edges=%+v", externalID, sinkClusterAdmin, graph.Edges)
	}
	if edge.Technique != "KUBE-CLOUD-AWSAUTH-001" {
		t.Errorf("aws-auth edge Technique = %q, want %q", edge.Technique, "KUBE-CLOUD-AWSAUTH-001")
	}
}

// TestAddCloudEdgesAWSAuthCustomWildcardClusterRole proves the privesc graph
// also follows aws-auth groups bound to CUSTOM admin-equivalent ClusterRoles,
// not just the literal "cluster-admin" name. Without this, an IAM principal
// mapped through a custom super-admin role would silently miss the cluster_admin
// sink in the BFS.
func TestAddCloudEdgesAWSAuthCustomWildcardClusterRole(t *testing.T) {
	t.Parallel()

	const mapRoles = "" +
		"- rolearn: arn:aws:iam::123456789012:role/PlatformAdmin\n" +
		"  username: platform-admin\n" +
		"  groups:\n" +
		"    - platform-admins\n"
	snapshot := models.Snapshot{
		Metadata: models.SnapshotMetadata{CloudProvider: "eks"},
		Resources: models.SnapshotResources{
			ConfigMaps: []models.ConfigMapSnapshot{
				{Name: "aws-auth", Namespace: "kube-system", Data: map[string]string{"mapRoles": mapRoles}},
			},
			ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
				{
					ObjectMeta: objectMeta("platform-admin-binding", ""),
					RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "platform-super-admin"},
					Subjects:   []rbacv1.Subject{{Kind: "Group", Name: "platform-admins"}},
				},
			},
			ClusterRoles: []rbacv1.ClusterRole{
				{
					ObjectMeta: objectMeta("platform-super-admin", ""),
					Rules: []rbacv1.PolicyRule{
						{Verbs: []string{"*"}, Resources: []string{"*"}, APIGroups: []string{"*"}},
					},
				},
			},
		},
	}

	graph := BuildGraph(snapshot)
	externalID := externalAWSIAMNodeID("arn:aws:iam::123456789012:role/PlatformAdmin")
	edge := findEdge(graph, externalID, sinkClusterAdmin, "aws_auth_admin")
	if edge == nil {
		t.Fatalf("expected aws_auth_admin edge to sinkClusterAdmin via custom wildcard ClusterRole; edges=%+v", graph.Edges)
	}
	// The edge's permission string should name the actual ClusterRole so the
	// chain card can show "via custom platform-super-admin" instead of
	// implying built-in cluster-admin.
	if edge.Permission == "" || edge.Description == "" {
		t.Fatalf("edge permission/description must be populated: %+v", edge)
	}
	// Sanity: a narrow ClusterRole MUST NOT trigger this edge. Re-run the
	// same fixture with verbs:[*] on secrets only and confirm the edge stays
	// absent (negative companion to the test above).
	snapshot.Resources.ClusterRoles[0].Rules = []rbacv1.PolicyRule{
		{Verbs: []string{"*"}, Resources: []string{"secrets"}, APIGroups: []string{""}},
	}
	graph2 := BuildGraph(snapshot)
	if e := findEdge(graph2, externalID, sinkClusterAdmin, "aws_auth_admin"); e != nil {
		t.Fatalf("expected no aws_auth_admin edge for narrow custom ClusterRole (verbs:[*] on secrets only); got %+v", e)
	}
}

func TestAddCloudEdgesCombinedIRSAAndAWSAuth(t *testing.T) {
	t.Parallel()

	const arn = "arn:aws:iam::123456789012:role/SharedRole"
	const mapRoles = "" +
		"- rolearn: arn:aws:iam::123456789012:role/SharedRole\n" +
		"  username: shared-user\n" +
		"  groups:\n" +
		"    - system:masters\n"
	snapshot := models.Snapshot{
		Metadata: models.SnapshotMetadata{CloudProvider: "eks"},
		Resources: models.SnapshotResources{
			Namespaces: []corev1.Namespace{
				{ObjectMeta: objectMeta("apps", "")},
			},
			ServiceAccounts: []corev1.ServiceAccount{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:        "app-sa",
						Namespace:   "apps",
						Annotations: map[string]string{"eks.amazonaws.com/role-arn": arn},
					},
				},
			},
			ConfigMaps: []models.ConfigMapSnapshot{
				{
					Name:      "aws-auth",
					Namespace: "kube-system",
					Data:      map[string]string{"mapRoles": mapRoles},
				},
			},
		},
	}

	graph := BuildGraph(snapshot)
	externalID := externalAWSIAMNodeID(arn)
	saNodeID := "subject:ServiceAccount/apps/app-sa"

	if !hasNode(graph, externalID) {
		t.Fatalf("expected external IAM node %q to be created", externalID)
	}
	if e := findEdge(graph, saNodeID, externalID, "irsa_assume_role"); e == nil {
		t.Errorf("expected IRSA edge SA -> external IAM role")
	}
	if e := findEdge(graph, externalID, sinkSystemMasters, "aws_auth_admin"); e == nil {
		t.Errorf("expected aws-auth edge external IAM role -> sinkSystemMasters")
	}

	// The combined chain should be SA -> external -> sinkSystemMasters when the
	// pathfinder runs. The IRSA edge ensures the SA is reachable, and the
	// aws-auth edge carries the path onward through the (non-sink) external node.
	paths := FindPaths(graph, 5)
	var foundSharedChain bool
	for _, path := range paths {
		if path.Source.Key() != "ServiceAccount/apps/app-sa" {
			continue
		}
		if path.Target != models.TargetSystemMasters {
			continue
		}
		if len(path.Hops) < 2 {
			continue
		}
		first := path.Hops[0]
		last := path.Hops[len(path.Hops)-1]
		if first.Action == "irsa_assume_role" && last.Action == "aws_auth_admin" {
			foundSharedChain = true
			break
		}
	}
	if !foundSharedChain {
		var summaries []string
		for _, p := range paths {
			summaries = append(summaries, p.Source.Key()+"->"+string(p.Target))
		}
		t.Fatalf("expected SA -> external -> sinkSystemMasters chain via IRSA + aws-auth; got paths=%v", summaries)
	}
}

func TestAddCloudEdgesIMDSPivot(t *testing.T) {
	t.Parallel()

	// Non-Fargate EKS node carrying the eks.amazonaws.com/compute-type=ec2 label.
	// The pod schedules onto it, has no IRSA annotation on its SA, and there is
	// no NetworkPolicy blocking egress to IMDS, so the pivot edge fires.
	snapshot := models.Snapshot{
		Metadata: models.SnapshotMetadata{CloudProvider: "eks"},
		Resources: models.SnapshotResources{
			Namespaces: []corev1.Namespace{
				{ObjectMeta: objectMeta("apps", "")},
			},
			Nodes: []corev1.Node{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "ip-10-0-0-1.ec2.internal",
						Labels: map[string]string{"eks.amazonaws.com/compute-type": "ec2"},
					},
				},
			},
			ServiceAccounts: []corev1.ServiceAccount{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "app-sa",
						Namespace: "apps",
					},
				},
			},
			Pods: []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "app-pod",
						Namespace: "apps",
						Labels:    map[string]string{"app": "demo"},
					},
					Spec: corev1.PodSpec{
						NodeName:           "ip-10-0-0-1.ec2.internal",
						ServiceAccountName: "app-sa",
						Containers: []corev1.Container{
							{Name: "app", Image: "demo:1"},
						},
					},
				},
			},
		},
	}

	graph := BuildGraph(snapshot)
	saNodeID := "subject:ServiceAccount/apps/app-sa"
	edge := findEdge(graph, saNodeID, sinkNodeEscape, "imds_node_role_pivot")
	if edge == nil {
		t.Fatalf("expected imds_node_role_pivot edge from %s to %s; edges=%+v", saNodeID, sinkNodeEscape, graph.Edges)
	}
	if edge.Technique != "KUBE-CLOUD-IMDS-PIVOT-001" {
		t.Errorf("IMDS-pivot edge Technique = %q, want %q", edge.Technique, "KUBE-CLOUD-IMDS-PIVOT-001")
	}
}

func TestAddCloudEdgesIMDSPivotSuppressedOnFargate(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Metadata: models.SnapshotMetadata{CloudProvider: "eks"},
		Resources: models.SnapshotResources{
			Namespaces: []corev1.Namespace{
				{ObjectMeta: objectMeta("apps", "")},
			},
			Nodes: []corev1.Node{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "fargate-ip-10-0-0-9.fargate",
						Labels: map[string]string{"eks.amazonaws.com/compute-type": "fargate"},
					},
				},
			},
			ServiceAccounts: []corev1.ServiceAccount{
				{ObjectMeta: metav1.ObjectMeta{Name: "fg-sa", Namespace: "apps"}},
			},
			Pods: []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "fg-pod", Namespace: "apps"},
					Spec: corev1.PodSpec{
						NodeName:           "fargate-ip-10-0-0-9.fargate",
						ServiceAccountName: "fg-sa",
						Containers:         []corev1.Container{{Name: "app", Image: "demo:1"}},
					},
				},
			},
		},
	}

	graph := BuildGraph(snapshot)
	saNodeID := "subject:ServiceAccount/apps/fg-sa"
	if edge := findEdge(graph, saNodeID, sinkNodeEscape, "imds_node_role_pivot"); edge != nil {
		t.Fatalf("Fargate-scheduled pod should NOT produce imds_node_role_pivot edge; got %+v", *edge)
	}
}

func TestAddCloudEdgesEmptySnapshot(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{}
	graph := BuildGraph(snapshot)

	for _, edge := range graph.Edges {
		switch edge.Action {
		case "irsa_assume_role", "aws_auth_admin", "imds_node_role_pivot":
			t.Fatalf("empty snapshot produced cloud edge: %+v", *edge)
		}
	}
	for id, node := range graph.Nodes {
		if node.IsExternal {
			t.Fatalf("empty snapshot produced external node %q: %+v", id, *node)
		}
	}
}
