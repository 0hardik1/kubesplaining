// Package privesc: workload-controller edges. A Deployment, DaemonSet, StatefulSet,
// Job, or CronJob carries a pod template, and its controller creates pods from it on
// the writer's behalf. Writing the template therefore reaches what writing a pod
// reaches, and the rbac module's KUBE-PRIVESC-003 finding had no graph edge behind it.
package privesc

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/permissions"
	corev1 "k8s.io/api/core/v1"
)

// workloadKind is one pod-template-carrying resource the graph models.
type workloadKind struct {
	group    string
	resource string
	kind     string // display Kind, e.g. "Deployment"
}

// createWorkloadKinds are the resources whose create makes the controller create
// pods. They match the rbac module's KUBE-PRIVESC-003 target set, so a graph edge
// always has a flat finding for the correlation pass to amplify.
var createWorkloadKinds = []workloadKind{
	{group: "apps", resource: "deployments", kind: "Deployment"},
	{group: "apps", resource: "daemonsets", kind: "DaemonSet"},
	{group: "apps", resource: "statefulsets", kind: "StatefulSet"},
	{group: "batch", resource: "jobs", kind: "Job"},
	{group: "batch", resource: "cronjobs", kind: "CronJob"},
}

// updateWorkloadKinds are the resources whose pod template can be rewritten after
// creation. Jobs are left out on purpose: the API server rejects changes to a Job's
// spec.template (only scheduling fields of a suspended Job are mutable), so update
// or patch on a Job cannot change the image, command, or ServiceAccount its pods run.
var updateWorkloadKinds = []workloadKind{
	{group: "apps", resource: "deployments", kind: "Deployment"},
	{group: "apps", resource: "daemonsets", kind: "DaemonSet"},
	{group: "apps", resource: "statefulsets", kind: "StatefulSet"},
	{group: "batch", resource: "cronjobs", kind: "CronJob"},
}

// workload is one existing object from updateWorkloadKinds, reduced to what the
// update edges read: where it is, and the pod template its controller stamps out.
type workload struct {
	kind      workloadKind
	namespace string
	name      string
	template  corev1.PodSpec
}

// serviceAccount returns the ServiceAccount the workload's pods run as, applying the
// API server's "default" fallback.
func (w workload) serviceAccount() models.SubjectRef {
	pod := corev1.Pod{Spec: w.template}
	pod.Namespace = w.namespace
	return podServiceAccount(pod)
}

func (w workload) label() string {
	return fmt.Sprintf("%s %s/%s", w.kind.kind, w.namespace, w.name)
}

// updatableWorkloads lists the snapshot's workloads whose pod template can be
// rewritten, sorted by namespace, kind, then name so edge order stays deterministic
// (BFS breaks ties on edge insertion order, see podCreateTargets).
func updatableWorkloads(snapshot models.Snapshot) []workload {
	var out []workload
	for _, d := range snapshot.Resources.Deployments {
		out = append(out, workload{kind: updateWorkloadKinds[0], namespace: d.Namespace, name: d.Name, template: d.Spec.Template.Spec})
	}
	for _, d := range snapshot.Resources.DaemonSets {
		out = append(out, workload{kind: updateWorkloadKinds[1], namespace: d.Namespace, name: d.Name, template: d.Spec.Template.Spec})
	}
	for _, s := range snapshot.Resources.StatefulSets {
		out = append(out, workload{kind: updateWorkloadKinds[2], namespace: s.Namespace, name: s.Name, template: s.Spec.Template.Spec})
	}
	for _, c := range snapshot.Resources.CronJobs {
		out = append(out, workload{kind: updateWorkloadKinds[3], namespace: c.Namespace, name: c.Name, template: c.Spec.JobTemplate.Spec.Template.Spec})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].namespace != out[j].namespace {
			return out[i].namespace < out[j].namespace
		}
		if out[i].kind.resource != out[j].kind.resource {
			return out[i].kind.resource < out[j].kind.resource
		}
		return out[i].name < out[j].name
	})
	return out
}

// namespacesAdmittingPrivileged reports, for every namespace in the snapshot, whether
// Pod Security Admission would admit a privileged pod there: no `enforce` label, or
// `enforce: privileged`. Unlike namespacesAllowingPrivileged it keeps the system
// namespaces, because a workload that already runs in kube-system with host access
// keeps that access when its template is rewritten, and kube-system is normally
// unlabeled. A namespace missing from the snapshot is not assumed to admit anything.
func namespacesAdmittingPrivileged(snapshot models.Snapshot) map[string]bool {
	out := map[string]bool{}
	for _, ns := range snapshot.Resources.Namespaces {
		switch ns.Labels["pod-security.kubernetes.io/enforce"] {
		case "", "privileged":
			out[ns.Name] = true
		}
	}
	return out
}

// workloadTargets returns the ResourceTargets for a kind list.
func workloadTargets(kinds []workloadKind) []permissions.ResourceTarget {
	targets := make([]permissions.ResourceTarget, 0, len(kinds))
	for _, k := range kinds {
		targets = append(targets, permissions.ResourceTarget{Group: k.group, Resource: k.resource})
	}
	return targets
}

// grantedWorkloadKinds returns the resource names of the kinds a rule grants any of
// verbs on, in kind order, for the edge's Permission string.
func grantedWorkloadKinds(rule permissions.EffectiveRule, kinds []workloadKind, verbs ...string) []string {
	var granted []string
	for _, k := range kinds {
		if rule.Grants([]permissions.ResourceTarget{{Group: k.group, Resource: k.resource}}, verbs...) {
			granted = append(granted, k.resource)
		}
	}
	return granted
}

// ruleReachesWorkload reports whether rule authorizes update or patch on w: the kind
// and namespace have to match, and a resourceNames-scoped rule has to name w.
func ruleReachesWorkload(rule permissions.EffectiveRule, w workload) bool {
	if rule.Namespace != "" && rule.Namespace != w.namespace {
		return false
	}
	if !rule.Grants([]permissions.ResourceTarget{{Group: w.kind.group, Resource: w.kind.resource}}, "update", "patch") {
		return false
	}
	if rule.NameScoped() && !slices.Contains(rule.ResourceNames, "*") && !slices.Contains(rule.ResourceNames, w.name) {
		return false
	}
	return true
}

// addWorkloadEdges emits the KUBE-PRIVESC-003 edges for one subject.
//
// Create on a workload kind reaches what create on pods reaches: the template names
// any ServiceAccount in scope (the ServiceAccount admission plugin checks only that
// it exists, never that the writer may use it), and in a namespace where Pod Security
// Admission admits privileged pods, the template can be privileged.
//
// Update or patch on an existing workload reaches the same, starting from that
// workload's namespace: the writer can point the template at any ServiceAccount
// there. It also reaches one thing create does not. The rewritten template keeps the
// workload's own spec, so when that spec already has host access and PSA admits it,
// the writer's code runs with that access, as the workload's ServiceAccount.
// A grant with no existing workload in scope to rewrite reaches nothing.
//
// Edges are emitted once per distinct granting binding, for the reason given in
// addPrivilegedPodCreateEdges. This builder runs after the per-rule edges, so when a
// subject can both create pods and create a Deployment, the pod edge is inserted
// first and stays the reported route; the workload edge still counts when the
// cut-resilient pass bans the pod edge's binding.
func addWorkloadEdges(
	graph *models.EscalationGraph,
	subject models.SubjectRef,
	rules []permissions.EffectiveRule,
	subjectsByNs map[string][]models.SubjectRef,
	workloads []workload,
	privilegedNamespaces map[string]bool,
	admitsPrivileged map[string]bool,
) {
	from := nodeID(subject)
	emitted := map[string]bool{}
	add := func(to string, rule permissions.EffectiveRule, edge *models.EscalationEdge) {
		key := fmt.Sprintf("%s|%s|%s|%s", edge.Action, to, rule.SourceBinding, rule.Namespace)
		if emitted[key] {
			return
		}
		emitted[key] = true
		edge.Technique = "KUBE-PRIVESC-003"
		edge.SourceBinding = rule.SourceBinding
		edge.SourceRole = rule.SourceRole
		edge.BindingNamespace = rule.Namespace
		ensureSubjectNode(graph, subject)
		addEdge(graph, from, to, edge)
	}

	createTargets := workloadTargets(createWorkloadKinds)
	for _, rule := range rules {
		// A full `*/*/*` holder is already cluster-admin in one hop (KUBE-PRIVESC-017).
		if isFullWildcardRule(rule) || !rule.Grants(createTargets, "create") {
			continue
		}
		clusterScope := rule.Namespace == ""
		permission := "create " + strings.Join(grantedWorkloadKinds(rule, createWorkloadKinds, "create"), "/")
		for _, target := range podCreateTargets(clusterScope, rule.Namespace, subjectsByNs) {
			if target.Key() == subject.Key() {
				continue
			}
			ensureSubjectNode(graph, target)
			add(nodeID(target), rule, &models.EscalationEdge{
				Action:      "workload_create_token_theft",
				Permission:  permission,
				Description: fmt.Sprintf("can create a workload whose pods run as ServiceAccount %s/%s", target.Namespace, target.Name),
				// Same position as pod_create_token_theft: a new pod the writer's
				// template defines, with the ServiceAccount's token mounted.
				Grants: models.FootholdIdentity | models.FootholdToken | models.FootholdNewPod,
			})
		}
		if podCreateAllowsPrivileged(clusterScope, rule.Namespace, privilegedNamespaces) {
			add(sinkNodeEscape, rule, &models.EscalationEdge{
				Action:      "workload_privileged_escape",
				Permission:  permission + " (Pod Security Admission does not block privileged)",
				Description: "can create a workload whose pod template is privileged, and escape to the node from its pods",
			})
		}
	}

	for _, rule := range rules {
		if isFullWildcardRule(rule) {
			continue
		}
		var inScope []workload
		for _, w := range workloads {
			if ruleReachesWorkload(rule, w) {
				inScope = append(inScope, w)
			}
		}
		if len(inScope) == 0 {
			continue
		}
		permission := verbResource(rule, strings.Join(grantedWorkloadKinds(rule, updateWorkloadKinds, "update", "patch"), "/"))

		// The ServiceAccounts the in-scope workloads already run as, with the
		// workload to name in the edge. The first workload in sorted order wins so
		// the description is stable.
		runsAs := map[string]workload{}
		hostAccess := map[string]bool{}
		firstInNamespace := map[string]workload{}
		var namespaces []string
		for _, w := range inScope {
			sa := w.serviceAccount().Key()
			if _, ok := runsAs[sa]; !ok {
				runsAs[sa] = w
			}
			// FootholdPod is the claim that the writer's code runs with the
			// workload's own spec. Only claim it when that spec has host access to
			// offer and PSA will admit the rewritten pods that carry it.
			if admitsPrivileged[w.namespace] && len(podEscapeReasons(corev1.Pod{Spec: w.template})) > 0 {
				hostAccess[sa] = true
			}
			if _, ok := firstInNamespace[w.namespace]; !ok {
				firstInNamespace[w.namespace] = w
				namespaces = append(namespaces, w.namespace)
			}
		}

		for _, namespace := range namespaces {
			for _, target := range workloadUpdateTargets(namespace, subjectsByNs, inScope) {
				if target.Key() == subject.Key() {
					continue
				}
				grants := models.FootholdIdentity | models.FootholdToken | models.FootholdNewPod
				description := fmt.Sprintf("can rewrite the pod template of %s to run as ServiceAccount %s/%s", firstInNamespace[namespace].label(), target.Namespace, target.Name)
				if w, ok := runsAs[target.Key()]; ok {
					description = fmt.Sprintf("can rewrite the pod template of %s, whose pods run as ServiceAccount %s/%s", w.label(), target.Namespace, target.Name)
					if hostAccess[target.Key()] {
						grants |= models.FootholdPod
						description += " with host access"
					}
				}
				ensureSubjectNode(graph, target)
				add(nodeID(target), rule, &models.EscalationEdge{
					Action:      "workload_hijack",
					Permission:  permission,
					Description: description,
					Grants:      grants,
				})
			}
			if privilegedNamespaces[namespace] {
				add(sinkNodeEscape, rule, &models.EscalationEdge{
					Action:      "workload_privileged_escape",
					Permission:  permission + " (Pod Security Admission does not block privileged)",
					Description: fmt.Sprintf("can rewrite the pod template of %s to be privileged, and escape to the node from its pods", firstInNamespace[namespace].label()),
				})
			}
		}
	}
}

// workloadUpdateTargets returns the ServiceAccounts a rewritten template in namespace
// can run as: every known ServiceAccount there, plus any in-scope workload's own
// ServiceAccount that the snapshot holds no object for (a partial snapshot), so the
// workload's current identity is never dropped from its own edge set.
func workloadUpdateTargets(namespace string, subjectsByNs map[string][]models.SubjectRef, inScope []workload) []models.SubjectRef {
	targets := append([]models.SubjectRef(nil), subjectsByNs[namespace]...)
	for _, w := range inScope {
		if w.namespace != namespace {
			continue
		}
		sa := w.serviceAccount()
		if !slices.ContainsFunc(targets, func(ref models.SubjectRef) bool { return ref.Key() == sa.Key() }) {
			targets = append(targets, sa)
		}
	}
	return targets
}
