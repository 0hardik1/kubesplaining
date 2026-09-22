package privesc

import (
	"slices"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

// workloadSnapshot is a two-namespace cluster where team-a/powerful is bound to
// cluster-admin and bob holds the given rules through RoleBinding bob-rb in team-a.
func workloadSnapshot(rules ...rbacv1.PolicyRule) models.Snapshot {
	snapshot := models.Snapshot{}
	snapshot.Resources.Namespaces = []corev1.Namespace{
		{ObjectMeta: objectMeta("team-a", "")},
		{ObjectMeta: objectMeta("team-b", "")},
	}
	snapshot.Resources.ServiceAccounts = []corev1.ServiceAccount{
		{ObjectMeta: objectMeta("powerful", "team-a")},
		{ObjectMeta: objectMeta("powerful", "team-b")},
	}
	snapshot.Resources.Roles = []rbacv1.Role{{ObjectMeta: objectMeta("bob-role", "team-a"), Rules: rules}}
	snapshot.Resources.RoleBindings = []rbacv1.RoleBinding{{
		ObjectMeta: objectMeta("bob-rb", "team-a"),
		RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "bob-role"},
		Subjects:   []rbacv1.Subject{{Kind: "User", Name: "bob"}},
	}}
	snapshot.Resources.ClusterRoleBindings = []rbacv1.ClusterRoleBinding{{
		ObjectMeta: objectMeta("powerful-crb", ""),
		RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
		Subjects: []rbacv1.Subject{
			{Kind: "ServiceAccount", Name: "powerful", Namespace: "team-a"},
			{Kind: "ServiceAccount", Name: "powerful", Namespace: "team-b"},
		},
	}}
	return snapshot
}

func appsRule(resource string, verbs ...string) rbacv1.PolicyRule {
	return rbacv1.PolicyRule{APIGroups: []string{"apps"}, Resources: []string{resource}, Verbs: verbs}
}

func deployment(name, namespace, serviceAccount string) appsv1.Deployment {
	d := appsv1.Deployment{ObjectMeta: objectMeta(name, namespace)}
	d.Spec.Template.Spec.ServiceAccountName = serviceAccount
	return d
}

var bobKey = models.SubjectRef{Kind: "User", Name: "bob"}.Key()

// TestWorkloadCreateReachesNamespaceServiceAccounts pins the create edge: a
// namespaced `create deployments` reaches every ServiceAccount in that namespace and
// none outside it, exactly like `create pods`.
func TestWorkloadCreateReachesNamespaceServiceAccounts(t *testing.T) {
	t.Parallel()

	paths := FindPaths(BuildGraph(workloadSnapshot(appsRule("deployments", "create"))), 5)
	actions, ok := pathActions(paths, bobKey, models.TargetClusterAdmin)
	if !ok {
		t.Fatal("want bob to reach cluster-admin by creating a Deployment that runs as team-a/powerful")
	}
	if want := []string{"workload_create_token_theft", "bound_to_cluster_admin"}; !slices.Equal(actions, want) {
		t.Fatalf("want %v, got %v", want, actions)
	}
	for _, p := range paths {
		for _, hop := range p.Hops {
			if hop.ToSubject.Namespace == "team-b" {
				t.Fatalf("a team-a grant must not reach team-b, got %+v", p.Hops)
			}
		}
	}
}

// TestPodEdgeStaysPrimaryWhenBothGranted proves the workload edges do not displace
// an existing pod route: when one binding grants both, the pod edge is reported.
func TestPodEdgeStaysPrimaryWhenBothGranted(t *testing.T) {
	t.Parallel()

	snapshot := workloadSnapshot(
		appsRule("deployments", "create"),
		rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"create"}},
	)
	paths := FindPaths(BuildGraph(snapshot), 5)
	actions, ok := pathActions(paths, bobKey, models.TargetClusterAdmin)
	if !ok || actions[0] != "pod_create_token_theft" {
		t.Fatalf("want the pod edge as hop 1, got %v", actions)
	}
	for _, p := range paths {
		if p.Source.Key() == bobKey && len(p.AlternateHops) > 0 {
			t.Fatalf("one binding grants both, so cutting it closes both; got alternate %+v", p.AlternateHops)
		}
	}
}

// TestWorkloadCreateSurvivesCuttingThePodBinding proves the reason the edge matters
// even when a pod edge exists: a second binding granting `create deployments` keeps
// the route open after the pod binding is cut.
func TestWorkloadCreateSurvivesCuttingThePodBinding(t *testing.T) {
	t.Parallel()

	snapshot := workloadSnapshot(rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"create"}})
	snapshot.Resources.Roles = append(snapshot.Resources.Roles, rbacv1.Role{
		ObjectMeta: objectMeta("deployer", "team-a"),
		Rules:      []rbacv1.PolicyRule{appsRule("deployments", "create")},
	})
	snapshot.Resources.RoleBindings = append(snapshot.Resources.RoleBindings, rbacv1.RoleBinding{
		ObjectMeta: objectMeta("deployer-rb", "team-a"),
		RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "deployer"},
		Subjects:   []rbacv1.Subject{{Kind: "User", Name: "bob"}},
	})

	for _, p := range FindPaths(BuildGraph(snapshot), 5) {
		if p.Source.Key() != bobKey || p.Target != models.TargetClusterAdmin {
			continue
		}
		if p.Hops[0].Action != "pod_create_token_theft" || p.Hops[0].SourceBinding != "bob-rb" {
			t.Fatalf("want primary hop 1 pod_create_token_theft via bob-rb, got %+v", p.Hops[0])
		}
		if len(p.AlternateHops) == 0 || p.AlternateHops[0].Action != "workload_create_token_theft" || p.AlternateHops[0].SourceBinding != "deployer-rb" {
			t.Fatalf("want an alternate through deployer-rb's create deployments, got %+v", p.AlternateHops)
		}
		return
	}
	t.Fatal("want a cluster-admin path from bob")
}

// TestWorkloadPrivilegedEscapeFollowsPodSecurity pins the node-escape edge for both
// create and update to the namespace's Pod Security enforce level.
func TestWorkloadPrivilegedEscapeFollowsPodSecurity(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		rule    rbacv1.PolicyRule
		enforce string
		want    bool
	}{
		{name: "create, unlabeled", rule: appsRule("deployments", "create"), want: true},
		{name: "create, baseline", rule: appsRule("deployments", "create"), enforce: "baseline"},
		{name: "patch, unlabeled", rule: appsRule("deployments", "patch"), want: true},
		{name: "patch, restricted", rule: appsRule("deployments", "patch"), enforce: "restricted"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			snapshot := workloadSnapshot(tc.rule)
			snapshot.Resources.Deployments = []appsv1.Deployment{deployment("web", "team-a", "")}
			if tc.enforce != "" {
				snapshot.Resources.Namespaces[0].Labels = map[string]string{"pod-security.kubernetes.io/enforce": tc.enforce}
			}
			actions, ok := pathActions(FindPaths(BuildGraph(snapshot), 5), bobKey, models.TargetNodeEscape)
			if ok != tc.want {
				t.Fatalf("want node-escape path %v, got %v (%v)", tc.want, ok, actions)
			}
			if ok && !slices.Equal(actions, []string{"workload_privileged_escape"}) {
				t.Fatalf("want [workload_privileged_escape], got %v", actions)
			}
		})
	}
}

// TestWorkloadUpdateNeedsAWorkloadInScope proves update/patch reaches nothing without
// an existing object to rewrite, honors resourceNames, and ignores Jobs, whose pod
// template the API server does not let anyone change.
func TestWorkloadUpdateNeedsAWorkloadInScope(t *testing.T) {
	t.Parallel()

	named := appsRule("deployments", "patch")
	named.ResourceNames = []string{"web"}
	jobs := rbacv1.PolicyRule{APIGroups: []string{"batch"}, Resources: []string{"jobs"}, Verbs: []string{"update", "patch"}}

	cases := []struct {
		name        string
		rule        rbacv1.PolicyRule
		deployments []appsv1.Deployment
		jobs        []batchv1.Job
		want        bool
	}{
		{name: "no workload", rule: appsRule("deployments", "patch")},
		{name: "workload in another namespace", rule: appsRule("deployments", "patch"), deployments: []appsv1.Deployment{deployment("web", "team-b", "")}},
		{name: "workload in scope", rule: appsRule("deployments", "patch"), deployments: []appsv1.Deployment{deployment("web", "team-a", "")}, want: true},
		{name: "resourceNames names it", rule: named, deployments: []appsv1.Deployment{deployment("web", "team-a", "")}, want: true},
		{name: "resourceNames names another", rule: named, deployments: []appsv1.Deployment{deployment("api", "team-a", "")}},
		{name: "job template is immutable", rule: jobs, jobs: []batchv1.Job{{ObjectMeta: objectMeta("batch", "team-a")}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			snapshot := workloadSnapshot(tc.rule)
			// Pod Security blocks the privileged-escape edge so only the hijack route counts.
			snapshot.Resources.Namespaces[0].Labels = map[string]string{"pod-security.kubernetes.io/enforce": "baseline"}
			snapshot.Resources.Deployments = tc.deployments
			snapshot.Resources.Jobs = tc.jobs
			actions, ok := pathActions(FindPaths(BuildGraph(snapshot), 5), bobKey, models.TargetClusterAdmin)
			if ok != tc.want {
				t.Fatalf("want cluster-admin path %v, got %v (%v)", tc.want, ok, actions)
			}
			if ok && !slices.Equal(actions, []string{"workload_hijack", "bound_to_cluster_admin"}) {
				t.Fatalf("want [workload_hijack bound_to_cluster_admin], got %v", actions)
			}
		})
	}
}

// TestWorkloadHijackKeepsTheWorkloadsHostAccess pins the one thing update reaches
// that create does not: rewriting a DaemonSet whose template already has host access
// puts the attacker's code in pods with that access. It is claimed only when the
// template itself carries the access and Pod Security admits it. kube-system is the
// realistic case, and namespacesAllowingPrivileged skips it, so the create-style
// escape edge never fires there.
func TestWorkloadHijackKeepsTheWorkloadsHostAccess(t *testing.T) {
	t.Parallel()

	privileged := true
	hostSpec := corev1.PodSpec{
		ServiceAccountName: "node-agent",
		Containers:         []corev1.Container{{Name: "agent", SecurityContext: &corev1.SecurityContext{Privileged: &privileged}}},
	}
	build := func(templateSpec corev1.PodSpec, enforce string) models.Snapshot {
		snapshot := models.Snapshot{}
		ns := corev1.Namespace{ObjectMeta: objectMeta("kube-system", "")}
		if enforce != "" {
			ns.Labels = map[string]string{"pod-security.kubernetes.io/enforce": enforce}
		}
		snapshot.Resources.Namespaces = []corev1.Namespace{ns}
		snapshot.Resources.ServiceAccounts = []corev1.ServiceAccount{{ObjectMeta: objectMeta("node-agent", "kube-system")}}
		ds := appsv1.DaemonSet{ObjectMeta: objectMeta("node-agent", "kube-system")}
		ds.Spec.Template.Spec = templateSpec
		snapshot.Resources.DaemonSets = []appsv1.DaemonSet{ds}
		// A running privileged pod of the same ServiceAccount, so the pod escape
		// edge exists either way and only the hijack's foothold decides the path.
		snapshot.Resources.Pods = []corev1.Pod{{ObjectMeta: objectMeta("node-agent-x1", "kube-system"), Spec: hostSpec}}
		snapshot.Resources.Roles = []rbacv1.Role{{
			ObjectMeta: objectMeta("ds-editor", "kube-system"),
			Rules:      []rbacv1.PolicyRule{appsRule("daemonsets", "patch")},
		}}
		snapshot.Resources.RoleBindings = []rbacv1.RoleBinding{{
			ObjectMeta: objectMeta("ds-editor-rb", "kube-system"),
			RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "ds-editor"},
			Subjects:   []rbacv1.Subject{{Kind: "User", Name: "bob"}},
		}}
		return snapshot
	}

	actions, ok := pathActions(FindPaths(BuildGraph(build(hostSpec, "")), 5), bobKey, models.TargetNodeEscape)
	if !ok || !slices.Equal(actions, []string{"workload_hijack", "pod_host_escape"}) {
		t.Fatalf("want [workload_hijack pod_host_escape], got %v (found %v)", actions, ok)
	}

	unprivileged := corev1.PodSpec{ServiceAccountName: "node-agent", Containers: []corev1.Container{{Name: "agent"}}}
	if actions, ok := pathActions(FindPaths(BuildGraph(build(unprivileged, "")), 5), bobKey, models.TargetNodeEscape); ok {
		t.Fatalf("a template with no host access must not claim a pod with host access, got %v", actions)
	}
	if actions, ok := pathActions(FindPaths(BuildGraph(build(hostSpec, "baseline")), 5), bobKey, models.TargetNodeEscape); ok {
		t.Fatalf("Pod Security baseline rejects the rewritten privileged pods, got %v", actions)
	}
}
