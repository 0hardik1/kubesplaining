package privesc

import (
	"strings"
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
	if edge.Technique != "KUBE-CLOUD-IRSA" {
		t.Errorf("IRSA edge Technique = %q, want %q", edge.Technique, "KUBE-CLOUD-IRSA")
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
	if edge.Technique != "KUBE-CLOUD-AWSAUTH" {
		t.Errorf("aws-auth edge Technique = %q, want %q", edge.Technique, "KUBE-CLOUD-AWSAUTH")
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
	if edge.Technique != "KUBE-CLOUD-AWSAUTH" {
		t.Errorf("aws-auth edge Technique = %q, want %q", edge.Technique, "KUBE-CLOUD-AWSAUTH")
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

func TestAddCloudEdgesAccessEntries(t *testing.T) {
	t.Parallel()
	const (
		adminARN   = "arn:aws:iam::123456789012:role/PlatformAdmin"
		secretsARN = "arn:aws:iam::123456789012:role/NsAdmin"
		groupARN   = "arn:aws:iam::123456789012:role/Devs"
		viewARN    = "arn:aws:iam::123456789012:role/Viewer"
	)
	snapshot := models.Snapshot{
		Metadata: models.SnapshotMetadata{CloudProvider: "eks"},
		Cloud: models.CloudSnapshot{EKS: &models.EKSCloudState{
			AuthenticationMode: models.EKSAuthModeAPI,
			AccessEntries: []models.EKSAccessEntry{
				{PrincipalARN: adminARN, AccessPolicies: []models.EKSAccessPolicyAssociation{{PolicyARN: "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy", ScopeType: "cluster"}}},
				{PrincipalARN: secretsARN, AccessPolicies: []models.EKSAccessPolicyAssociation{{PolicyARN: "arn:aws:eks::aws:cluster-access-policy/AmazonEKSAdminPolicy", ScopeType: "cluster"}}},
				{PrincipalARN: groupARN, KubernetesGroups: []string{"platform-admins"}},
				{PrincipalARN: viewARN, AccessPolicies: []models.EKSAccessPolicyAssociation{{PolicyARN: "arn:aws:eks::aws:cluster-access-policy/AmazonEKSAdminPolicy", ScopeType: "namespace", Namespaces: []string{"a"}}}},
			},
		}},
		Resources: models.SnapshotResources{
			ClusterRoleBindings: []rbacv1.ClusterRoleBinding{{
				ObjectMeta: metav1.ObjectMeta{Name: "platform-admins-crb"},
				RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
				Subjects:   []rbacv1.Subject{{Kind: "Group", Name: "platform-admins"}},
			}},
		},
	}
	graph := BuildGraph(snapshot)

	if e := findEdge(graph, externalAWSIAMNodeID(adminARN), sinkClusterAdmin, "access_entry_admin"); e == nil {
		t.Errorf("expected access_entry_admin edge to cluster_admin for %s", adminARN)
	} else if e.Technique != "KUBE-CLOUD-ACCESSENTRY" || e.Difficulty != difficultyModerate {
		t.Errorf("edge = %+v", e)
	}
	if findEdge(graph, externalAWSIAMNodeID(secretsARN), sinkKubeSystemSecrets, "access_entry_secrets_read") == nil {
		t.Errorf("expected access_entry_secrets_read edge to kube_system_secrets for %s", secretsARN)
	}
	if findEdge(graph, externalAWSIAMNodeID(groupARN), sinkClusterAdmin, "access_entry_admin") == nil {
		t.Errorf("expected access_entry_admin edge via admin-bound group for %s", groupARN)
	}
	if hasNode(graph, externalAWSIAMNodeID(viewARN)) {
		for _, e := range graph.Edges {
			if e.From == externalAWSIAMNodeID(viewARN) {
				t.Errorf("namespace-scoped admin policy must add no edge: %+v", e)
			}
		}
	}
}

// TestCloudEdgeFootholds pins what each cloud edge needs at the ServiceAccount. IMDS
// answers a network position, so it needs code in a pod: a shell in the SA's pod or
// a new pod created as it, never a minted token or an impersonation. IRSA needs a
// presentable credential, not the ability to act as the SA against the Kubernetes
// API: a minted token reaches the role (the TokenRequest API can carry the sts
// audience), and a shell in a pod reaches it (the web-identity token is projected
// whatever automountServiceAccountToken says, so both pods here opt out), but bare
// impersonation does not. Both pods opting out of the API token is what makes the
// exec case meaningful, and the impersonate case is what proves act-as is not a
// credential.
func TestCloudEdgeFootholds(t *testing.T) {
	t.Parallel()

	const roleARN = "arn:aws:iam::123456789012:role/AppRole"
	no := false
	pod := func(name, sa string) corev1.Pod {
		return corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "apps", Labels: map[string]string{"app": name}},
			Spec: corev1.PodSpec{
				NodeName:                     "ip-10-0-0-1.ec2.internal",
				ServiceAccountName:           sa,
				AutomountServiceAccountToken: &no,
				Containers:                   []corev1.Container{{Name: "app", Image: "demo:1"}},
			},
		}
	}
	snapshotWith := func(rule rbacv1.PolicyRule) models.Snapshot {
		return models.Snapshot{
			Metadata: models.SnapshotMetadata{CloudProvider: "eks"},
			Resources: models.SnapshotResources{
				// Restricted keeps pod_create_privileged_escape out, so node escape
				// can only come from the IMDS pivot.
				Namespaces: []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "apps", Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}}}},
				Nodes: []corev1.Node{{ObjectMeta: metav1.ObjectMeta{
					Name: "ip-10-0-0-1.ec2.internal", Labels: map[string]string{"eks.amazonaws.com/compute-type": "ec2"},
				}}},
				ServiceAccounts: []corev1.ServiceAccount{
					{ObjectMeta: metav1.ObjectMeta{Name: "imds-sa", Namespace: "apps"}},
					{ObjectMeta: metav1.ObjectMeta{Name: "irsa-sa", Namespace: "apps", Annotations: map[string]string{"eks.amazonaws.com/role-arn": roleARN}}},
				},
				Pods:  []corev1.Pod{pod("imds-pod", "imds-sa"), pod("irsa-pod", "irsa-sa")},
				Roles: []rbacv1.Role{{ObjectMeta: objectMeta("grant", "apps"), Rules: []rbacv1.PolicyRule{rule}}},
				RoleBindings: []rbacv1.RoleBinding{{
					ObjectMeta: objectMeta("grant", "apps"),
					RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "grant"},
					Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "deployer", Namespace: "apps"}},
				}},
			},
		}
	}
	core := func(resource, verb string) rbacv1.PolicyRule {
		return rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{resource}, Verbs: []string{verb}}
	}

	cases := []struct {
		name       string
		rule       rbacv1.PolicyRule
		wantEscape string // node-escape hop actions, "" for none
		wantRole   string // aws_iam_role hop actions, "" when the case does not assert it
	}{
		{name: "exec", rule: core("pods/exec", "create"), wantEscape: "pod_exec,imds_node_role_pivot", wantRole: "pod_exec,irsa_assume_role"},
		{name: "pod create", rule: core("pods", "create"), wantEscape: "pod_create_token_theft,imds_node_role_pivot", wantRole: "pod_create_token_theft,irsa_assume_role"},
		{name: "token request", rule: core("serviceaccounts/token", "create"), wantRole: "token_request,irsa_assume_role"},
		{name: "impersonate", rule: core("serviceaccounts", "impersonate")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := map[models.EscalationTarget]string{}
			for _, p := range FindPaths(BuildGraph(snapshotWith(tc.rule)), 5) {
				if p.Source.Name != "deployer" {
					continue
				}
				var actions []string
				for _, hop := range p.Hops {
					actions = append(actions, hop.Action)
				}
				got[p.Target] = strings.Join(actions, ",")
			}
			if got[models.TargetNodeEscape] != tc.wantEscape {
				t.Errorf("node-escape path = %q, want %q", got[models.TargetNodeEscape], tc.wantEscape)
			}
			if got[models.TargetAWSIAMRole] != tc.wantRole {
				t.Errorf("aws_iam_role path = %q, want %q", got[models.TargetAWSIAMRole], tc.wantRole)
			}
		})
	}
}

// TestConfusedDeputyDoesNotReachIRSA pins the identity/token split for the operator
// bridge. Steering a controller runs it on your behalf but hands you no token, so a
// tenant that can only steer an IRSA-annotated controller does not reach its AWS
// role, even though the controller reaches that role from its own workload. This is
// the operator_reconcile counterpart to TestCloudEdgeFootholds' impersonate case:
// both grant bare FootholdIdentity, which is not a presentable credential.
func TestConfusedDeputyDoesNotReachIRSA(t *testing.T) {
	t.Parallel()

	const roleARN = "arn:aws:iam::123456789012:role/FluxRole"
	snapshot := models.Snapshot{
		Metadata: models.SnapshotMetadata{CloudProvider: "eks"},
		Resources: models.SnapshotResources{
			Namespaces: []corev1.Namespace{{ObjectMeta: objectMeta("flux-system", "")}, {ObjectMeta: objectMeta("tenant", "")}},
			ServiceAccounts: []corev1.ServiceAccount{
				{ObjectMeta: metav1.ObjectMeta{Name: "kustomize-controller", Namespace: "flux-system", Annotations: map[string]string{"eks.amazonaws.com/role-arn": roleARN}}},
				{ObjectMeta: objectMeta("deployer", "tenant")},
			},
			Roles: []rbacv1.Role{{ObjectMeta: objectMeta("gitops", "tenant"), Rules: []rbacv1.PolicyRule{
				{APIGroups: []string{"kustomize.toolkit.fluxcd.io"}, Resources: []string{"kustomizations"}, Verbs: []string{"create", "patch"}},
			}}},
			RoleBindings: []rbacv1.RoleBinding{{
				ObjectMeta: objectMeta("gitops", "tenant"),
				RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "gitops"},
				Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "deployer", Namespace: "tenant"}},
			}},
		},
	}
	graph := BuildGraph(snapshot)

	if findEdge(graph, "subject:ServiceAccount/tenant/deployer", "subject:ServiceAccount/flux-system/kustomize-controller", "operator_reconcile") == nil {
		t.Fatal("fixture: expected an operator_reconcile bridge from deployer to the controller")
	}

	controllerReaches, deployerReaches := false, false
	for _, p := range FindPaths(graph, 5) {
		if p.Target != models.TargetAWSIAMRole {
			continue
		}
		switch p.Source.Name {
		case "kustomize-controller":
			controllerReaches = true
		case "deployer":
			deployerReaches = true
		}
	}
	if !controllerReaches {
		t.Error("the controller should reach its own IRSA role from its workload")
	}
	if deployerReaches {
		t.Error("steering the controller must not reach its IRSA role: operator_reconcile hands over no token")
	}
}
