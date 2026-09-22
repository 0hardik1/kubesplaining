package privesc

import (
	"slices"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

// groupGrantSnapshot binds one ClusterRole holding rule to group through a
// ClusterRoleBinding. Two namespaces each hold one ServiceAccount, and the User
// alice is bound to a harmless role so she exists as a graph node.
func groupGrantSnapshot(group string, rule rbacv1.PolicyRule) models.Snapshot {
	snapshot := models.Snapshot{}
	snapshot.Resources.Namespaces = []corev1.Namespace{
		{ObjectMeta: objectMeta("team-a", "")},
		{ObjectMeta: objectMeta("team-b", "")},
	}
	snapshot.Resources.ServiceAccounts = []corev1.ServiceAccount{
		{ObjectMeta: objectMeta("app", "team-a")},
		{ObjectMeta: objectMeta("app", "team-b")},
	}
	snapshot.Resources.ClusterRoles = []rbacv1.ClusterRole{
		{ObjectMeta: objectMeta("group-grant", ""), Rules: []rbacv1.PolicyRule{rule}},
		{ObjectMeta: objectMeta("harmless", ""), Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get"},
		}}},
	}
	snapshot.Resources.ClusterRoleBindings = []rbacv1.ClusterRoleBinding{
		{
			ObjectMeta: objectMeta("group-grant-crb", ""),
			RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "group-grant"},
			Subjects:   []rbacv1.Subject{{Kind: "Group", Name: group}},
		},
		{
			ObjectMeta: objectMeta("alice-crb", ""),
			RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "harmless"},
			Subjects:   []rbacv1.Subject{{Kind: "User", Name: "alice"}},
		},
	}
	return snapshot
}

var (
	wildcardRule    = rbacv1.PolicyRule{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}
	listSecretsRule = rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"list"}}
)

// pathActions returns the hop actions of the path from source (a subject key) to
// target, and whether such a path exists.
func pathActions(paths []models.EscalationPath, source string, target models.EscalationTarget) ([]string, bool) {
	for _, p := range paths {
		if p.Source.Key() != source || p.Target != target {
			continue
		}
		actions := make([]string, 0, len(p.Hops))
		for _, hop := range p.Hops {
			actions = append(actions, hop.Action)
		}
		return actions, true
	}
	return nil, false
}

// TestImplicitGroupGrantReachesMembers pins who inherits a grant to each implicit
// group. system:serviceaccounts reaches every ServiceAccount and no User;
// system:serviceaccounts:<ns> reaches only that namespace's ServiceAccounts;
// system:authenticated reaches Users and ServiceAccounts alike. The group itself is
// never a source: its reach is reported on each member.
func TestImplicitGroupGrantReachesMembers(t *testing.T) {
	t.Parallel()

	saA := models.SubjectRef{Kind: "ServiceAccount", Name: "app", Namespace: "team-a"}.Key()
	saB := models.SubjectRef{Kind: "ServiceAccount", Name: "app", Namespace: "team-b"}.Key()
	alice := models.SubjectRef{Kind: "User", Name: "alice"}.Key()

	cases := []struct {
		group string
		want  []string
		deny  []string
	}{
		{group: "system:serviceaccounts", want: []string{saA, saB}, deny: []string{alice}},
		{group: "system:serviceaccounts:team-a", want: []string{saA}, deny: []string{saB, alice}},
		{group: "system:authenticated", want: []string{saA, saB, alice}},
	}
	for _, tc := range cases {
		t.Run(tc.group, func(t *testing.T) {
			t.Parallel()
			graph := BuildGraph(groupGrantSnapshot(tc.group, wildcardRule))
			groupNode := graph.Nodes[nodeID(models.SubjectRef{Kind: "Group", Name: tc.group})]
			if groupNode == nil || groupNode.IsSystem || !groupNode.IsImplicitGroup {
				t.Fatalf("group node must exist, be traversable, and be flagged implicit: %+v", groupNode)
			}

			paths := FindPaths(graph, 5)
			for _, source := range tc.want {
				actions, ok := pathActions(paths, source, models.TargetClusterAdmin)
				if !ok {
					t.Errorf("%s: want a cluster-admin path through %s", source, tc.group)
					continue
				}
				if !slices.Equal(actions, []string{"implicit_group_membership", "wildcard_permission"}) {
					t.Errorf("%s: want [implicit_group_membership wildcard_permission], got %v", source, actions)
				}
			}
			for _, source := range tc.deny {
				if _, ok := pathActions(paths, source, models.TargetClusterAdmin); ok {
					t.Errorf("%s is not a member of %s and must not reach cluster-admin", source, tc.group)
				}
			}
			for _, p := range paths {
				if p.Source.Kind == "Group" && p.Source.Name == tc.group {
					t.Errorf("implicit group %s must not be seeded as a source", tc.group)
				}
			}
		})
	}
}

// TestImplicitGroupHopCarriesTheGroupBinding pins the provenance remediation reads:
// hop 1 (membership) names no binding, and hop 2 names the binding that lists the
// group, so the fix drops the group from it.
func TestImplicitGroupHopCarriesTheGroupBinding(t *testing.T) {
	t.Parallel()

	paths := FindPaths(BuildGraph(groupGrantSnapshot("system:serviceaccounts", listSecretsRule)), 5)
	source := models.SubjectRef{Kind: "ServiceAccount", Name: "app", Namespace: "team-a"}.Key()
	for _, p := range paths {
		if p.Source.Key() != source || p.Target != models.TargetKubeSystemSecrets {
			continue
		}
		if len(p.Hops) != 2 {
			t.Fatalf("want 2 hops, got %+v", p.Hops)
		}
		if p.Hops[0].SourceBinding != "" {
			t.Errorf("membership hop must carry no binding, got %q", p.Hops[0].SourceBinding)
		}
		if p.Hops[0].ToSubject.Name != "system:serviceaccounts" || p.Hops[1].FromSubject.Name != "system:serviceaccounts" {
			t.Errorf("want the chain to run through the group, got %+v", p.Hops)
		}
		if p.Hops[1].SourceBinding != "group-grant-crb" {
			t.Errorf("want hop 2 to name group-grant-crb, got %q", p.Hops[1].SourceBinding)
		}
		return
	}
	t.Fatalf("no kube-system-secrets path from %s; paths: %+v", source, paths)
}

// TestImplicitGroupContinuesAChain proves a member reached mid-chain carries its
// groups: an attacker who can create pods in team-a takes a ServiceAccount's token,
// and that token is also a member of system:serviceaccounts:team-a.
func TestImplicitGroupContinuesAChain(t *testing.T) {
	t.Parallel()

	snapshot := groupGrantSnapshot("system:serviceaccounts:team-a", listSecretsRule)
	snapshot.Resources.Roles = []rbacv1.Role{{
		ObjectMeta: objectMeta("pod-maker", "team-a"),
		Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"create"}}},
	}}
	snapshot.Resources.RoleBindings = []rbacv1.RoleBinding{{
		ObjectMeta: objectMeta("pod-maker-rb", "team-a"),
		RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "pod-maker"},
		Subjects:   []rbacv1.Subject{{Kind: "User", Name: "bob"}},
	}}

	actions, ok := pathActions(FindPaths(BuildGraph(snapshot), 5), models.SubjectRef{Kind: "User", Name: "bob"}.Key(), models.TargetKubeSystemSecrets)
	if !ok {
		t.Fatal("want bob to reach kube-system secrets through a team-a ServiceAccount's group")
	}
	want := []string{"pod_create_token_theft", "implicit_group_membership", "read_secrets"}
	if !slices.Equal(actions, want) {
		t.Fatalf("want %v, got %v", want, actions)
	}
}

// TestImplicitGroupNeedsIdentity proves membership is not walked from a shell in a
// pod that mounts no API token: without a token the attacker cannot authenticate as
// the ServiceAccount, so the requests carry none of its groups.
func TestImplicitGroupNeedsIdentity(t *testing.T) {
	t.Parallel()

	noToken := false
	snapshot := groupGrantSnapshot("system:serviceaccounts:team-a", listSecretsRule)
	snapshot.Resources.Pods = []corev1.Pod{{
		ObjectMeta: objectMeta("web", "team-a"),
		Spec:       corev1.PodSpec{ServiceAccountName: "app", AutomountServiceAccountToken: &noToken},
	}}
	snapshot.Resources.Roles = []rbacv1.Role{{
		ObjectMeta: objectMeta("exec", "team-a"),
		Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods/exec"}, Verbs: []string{"create"}}},
	}}
	snapshot.Resources.RoleBindings = []rbacv1.RoleBinding{{
		ObjectMeta: objectMeta("exec-rb", "team-a"),
		RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "exec"},
		Subjects:   []rbacv1.Subject{{Kind: "User", Name: "bob"}},
	}}
	bob := models.SubjectRef{Kind: "User", Name: "bob"}.Key()

	if _, ok := pathActions(FindPaths(BuildGraph(snapshot), 5), bob, models.TargetKubeSystemSecrets); ok {
		t.Fatal("a shell in a pod with no API token must not use the ServiceAccount's group grants")
	}

	// Control: the same pod with the token mounted does carry the group.
	snapshot.Resources.Pods[0].Spec.AutomountServiceAccountToken = nil
	if _, ok := pathActions(FindPaths(BuildGraph(snapshot), 5), bob, models.TargetKubeSystemSecrets); !ok {
		t.Fatal("control: with the token mounted, exec must reach the group's grant")
	}
}

// TestUnauthenticatedGroupIsNotAMembership pins the deliberate omission:
// system:unauthenticated is carried only by anonymous requests, which no subject in
// the graph makes, so it stays a system subject and gives no member a path.
func TestUnauthenticatedGroupIsNotAMembership(t *testing.T) {
	t.Parallel()

	graph := BuildGraph(groupGrantSnapshot("system:unauthenticated", wildcardRule))
	node := graph.Nodes[nodeID(models.SubjectRef{Kind: "Group", Name: "system:unauthenticated"})]
	if node == nil || !node.IsSystem || node.IsImplicitGroup {
		t.Fatalf("system:unauthenticated must stay a system subject, got %+v", node)
	}
	for _, p := range FindPaths(graph, 5) {
		if p.Target == models.TargetClusterAdmin {
			t.Errorf("no subject is a member of system:unauthenticated, got a path from %s", p.Source.Key())
		}
	}
}

// TestNoMembershipEdgeToADeadEndGroup proves the default discovery bindings add
// nothing: a group with no outbound edge gets no membership edges.
func TestNoMembershipEdgeToADeadEndGroup(t *testing.T) {
	t.Parallel()

	selfReview := rbacv1.PolicyRule{
		APIGroups: []string{"authorization.k8s.io"},
		Resources: []string{"selfsubjectaccessreviews"},
		Verbs:     []string{"create"},
	}
	graph := BuildGraph(groupGrantSnapshot("system:authenticated", selfReview))
	for _, edge := range graph.Edges {
		if edge.Action == "implicit_group_membership" {
			t.Fatalf("want no membership edge to a group that leads nowhere, got %s -> %s", edge.From, edge.To)
		}
	}
}
