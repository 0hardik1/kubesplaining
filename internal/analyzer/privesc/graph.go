package privesc

import (
	"fmt"
	"slices"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/permissions"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

const (
	sinkClusterAdmin         = "sink:cluster_admin"
	sinkKubeSystemSecrets    = "sink:kube_system_secrets"
	sinkNodeEscape           = "sink:node_escape"
	sinkSystemMasters        = "sink:system_masters"
	sinkTokenMint            = "sink:token_mint"
	sinkNamespaceAdminPrefix = "sink:namespace_admin:"
)

// csrAnnotation tags a subject with one of the two halves of the CSR-approval
// privesc primitive. A subject that accumulates both halves (after every rule
// has been processed) gets an edge to the system_masters sink in finalizeCSRApprovals.
type csrAnnotation int

const (
	csrAnnotationCreate csrAnnotation = 1 << iota
	csrAnnotationApprove
)

// nodeID returns the canonical graph-node ID for a subject.
func nodeID(ref models.SubjectRef) string {
	return "subject:" + ref.Key()
}

// BuildGraph constructs the privilege-escalation graph: subjects become nodes,
// sensitive outcomes become sinks, and permissions or pod escape conditions become edges.
func BuildGraph(snapshot models.Snapshot) *models.EscalationGraph {
	graph := &models.EscalationGraph{
		Nodes: map[string]*models.EscalationNode{},
	}

	addSink(graph, sinkClusterAdmin, models.TargetClusterAdmin)
	addSink(graph, sinkKubeSystemSecrets, models.TargetKubeSystemSecrets)
	addSink(graph, sinkNodeEscape, models.TargetNodeEscape)
	addSink(graph, sinkSystemMasters, models.TargetSystemMasters)
	addSink(graph, sinkTokenMint, models.TargetTokenMint)

	subjectsByNs := serviceAccountsByNamespace(snapshot)
	podSAsByNs := podServiceAccountsByNamespace(snapshot)

	// csrCapabilities accumulates the two CSR-approval halves (create CSRs +
	// approve at the /approval subresource) per subject. Both verbs across the
	// subject's effective rules are required before an edge to system_masters is
	// emitted, so collection runs across the per-rule loop and the finalize step
	// emits the edge once both halves are present.
	csrCapabilities := map[string]csrAnnotation{}

	effective := permissions.Aggregate(snapshot)
	for _, perms := range effective {
		ensureSubjectNode(graph, perms.Subject)
		for _, rule := range perms.Rules {
			addEdgesForRule(graph, perms.Subject, rule, subjectsByNs, podSAsByNs, csrCapabilities)
		}
	}

	finalizeCSRApprovals(graph, csrCapabilities)

	for _, pod := range snapshot.Resources.Pods {
		addPodEscapeEdges(graph, pod)
	}

	for _, binding := range snapshot.Resources.ClusterRoleBindings {
		if binding.RoleRef.Kind != "ClusterRole" || binding.RoleRef.Name != "cluster-admin" {
			continue
		}
		for _, subject := range binding.Subjects {
			ref := subjectRef(subject, "")
			if ref.Name == "" {
				continue
			}
			ensureSubjectNode(graph, ref)
			addEdge(graph, nodeID(ref), sinkClusterAdmin, &models.EscalationEdge{
				Technique:   "KUBE-RBAC-OVERBROAD-001",
				Action:      "bound_to_cluster_admin",
				Permission:  "cluster-admin",
				Description: fmt.Sprintf("bound to cluster-admin via %s", binding.Name),
			})
		}
	}

	addCloudEdges(graph, snapshot)

	return graph
}

// finalizeCSRApprovals emits a csr_approve edge from any subject that holds both
// halves of the CSR-mint primitive (create on certificatesigningrequests AND
// update/patch on certificatesigningrequests/approval, both cluster-scoped) to
// the system_masters sink. The CSR mint primitive is the only one in the model
// today that requires correlating two separate RBAC rules on the same subject,
// hence the two-pass build.
func finalizeCSRApprovals(graph *models.EscalationGraph, caps map[string]csrAnnotation) {
	const both = csrAnnotationCreate | csrAnnotationApprove
	for subjectKey, ann := range caps {
		if ann&both != both {
			continue
		}
		from := "subject:" + subjectKey
		// Defensive: the subject node may not yet exist if the caller stored an
		// annotation without first walking effective rules. ensureSubjectNode is
		// keyed on SubjectRef, so we parse the key back; the graph builder is
		// the only writer of caps, so this branch is effectively unreachable but
		// kept simple in case future code paths short-circuit.
		if _, ok := graph.Nodes[from]; !ok {
			continue
		}
		addEdge(graph, from, sinkSystemMasters, &models.EscalationEdge{
			Technique:   "KUBE-PRIVESC-011",
			Action:      "csr_approve",
			Permission:  "create certificatesigningrequests + update certificatesigningrequests/approval",
			Description: "can submit a CSR with system:masters in its Subject and self-approve it, minting a kubelet-signed cluster-admin client cert",
		})
	}
}

// annotateSubjectCSR records that subject holds one of the two CSR-approval halves.
// Stored on a side map (passed in by BuildGraph) because addEdgesForRule sees one
// rule at a time; the edge is only safe to emit once we've confirmed both halves
// landed across the subject's full effective rule set.
func annotateSubjectCSR(caps map[string]csrAnnotation, subject models.SubjectRef, half csrAnnotation) {
	caps[subject.Key()] |= half
}

// addEdgesForRule inspects one aggregated RBAC rule and emits the graph edges it enables (to sinks or to impersonable subjects).
// csrCapabilities accumulates the per-subject CSR-mint halves across rules so finalizeCSRApprovals
// can emit the csr_approve edge once both halves are present.
func addEdgesForRule(
	graph *models.EscalationGraph,
	subject models.SubjectRef,
	rule permissions.EffectiveRule,
	subjectsByNs map[string][]models.SubjectRef,
	podSAsByNs map[string][]models.SubjectRef,
	csrCapabilities map[string]csrAnnotation,
) {
	from := nodeID(subject)
	clusterScope := rule.Namespace == ""

	if hasAll(rule.Verbs, "*") && hasAll(rule.Resources, "*") && hasAll(rule.APIGroups, "*") {
		addEdge(graph, from, sinkClusterAdmin, &models.EscalationEdge{
			Technique:   "KUBE-PRIVESC-017",
			Action:      "wildcard_permission",
			Permission:  "*:*:*",
			Description: "wildcard verbs on wildcard resources in wildcard API groups",
		})
		return
	}

	// modify_role_binding: cluster-scoped grants reach cluster-admin (write to any (Cluster)RoleBinding
	// → bind to any role anywhere). Namespace-scoped grants on `rolebindings` reach namespace-admin in
	// the binding's namespace (the subject can RoleBind itself to any ClusterRole, scoped to that ns).
	// Namespace-scoped grants on `clusterrolebindings` are dead RBAC (clusterrolebindings is a
	// cluster-scoped resource and the authorizer never allows the verb to succeed via a RoleBinding).
	if clusterScope && matchesResourceVerb(rule, []string{"rolebindings", "clusterrolebindings"}, []string{"create", "update", "patch"}) {
		addEdge(graph, from, sinkClusterAdmin, &models.EscalationEdge{
			Technique:   "KUBE-PRIVESC-010",
			Action:      "modify_role_binding",
			Permission:  verbResource(rule, "rolebindings|clusterrolebindings"),
			Description: "can create or mutate role bindings to grant itself any role",
		})
	}
	if !clusterScope && matchesResourceVerb(rule, []string{"rolebindings"}, []string{"create", "update", "patch"}) {
		sink := ensureNamespaceAdminSink(graph, rule.Namespace)
		addEdge(graph, from, sink, &models.EscalationEdge{
			Technique:   "KUBE-PRIVESC-010",
			Action:      "modify_role_binding",
			Permission:  verbResource(rule, "rolebindings"),
			Description: fmt.Sprintf("can create or mutate RoleBindings in namespace %s to grant itself any role within %s", rule.Namespace, rule.Namespace),
		})
	}

	// bind/escalate on (cluster)roles: same scope reasoning as modify_role_binding. Namespace-scoped
	// grants on `roles` let the subject bind any ClusterRole inside the binding's namespace; on
	// `clusterroles` they're dead RBAC.
	if clusterScope && matchesResourceVerb(rule, []string{"roles", "clusterroles"}, []string{"bind", "escalate"}) {
		addEdge(graph, from, sinkClusterAdmin, &models.EscalationEdge{
			Technique:   "KUBE-PRIVESC-009",
			Action:      "bind_or_escalate",
			Permission:  verbResource(rule, "roles|clusterroles"),
			Description: "can bypass RBAC escalation checks via bind/escalate",
		})
	}
	if !clusterScope && matchesResourceVerb(rule, []string{"roles"}, []string{"bind", "escalate"}) {
		sink := ensureNamespaceAdminSink(graph, rule.Namespace)
		addEdge(graph, from, sink, &models.EscalationEdge{
			Technique:   "KUBE-PRIVESC-009",
			Action:      "bind_or_escalate",
			Permission:  verbResource(rule, "roles"),
			Description: fmt.Sprintf("can bypass RBAC escalation checks via bind/escalate within namespace %s", rule.Namespace),
		})
	}

	// impersonate users/groups: users and groups are not namespaced K8s objects, so a RoleBinding
	// granting these verbs is dead RBAC (the authorizer never lets it succeed). Only emit the
	// cluster-admin edge for cluster-scoped grants.
	if clusterScope && matchesResourceVerb(rule, []string{"users", "groups"}, []string{"impersonate"}) {
		addEdge(graph, from, sinkClusterAdmin, &models.EscalationEdge{
			Technique:   "KUBE-PRIVESC-008",
			Action:      "impersonate",
			Permission:  verbResource(rule, "users|groups"),
			Description: "can impersonate another identity",
		})
	}

	if clusterScope && matchesResourceVerb(rule, []string{"groups"}, []string{"impersonate"}) {
		addEdge(graph, from, sinkSystemMasters, &models.EscalationEdge{
			Technique:   "KUBE-PRIVESC-008",
			Action:      "impersonate_system_masters",
			Permission:  verbResource(rule, "groups"),
			Description: "can impersonate the system:masters group, bypassing all RBAC",
		})
	}

	// impersonate serviceaccounts: cluster-scoped grants reach any SA cluster-wide (including
	// kube-system controllers), so we treat that as cluster-admin. Namespace-scoped grants only
	// reach SAs in the binding's namespace — model those as per-target edges so multi-hop chains
	// can still surface a real path if one of those SAs reaches a sink.
	if matchesResourceVerb(rule, []string{"serviceaccounts"}, []string{"impersonate"}) {
		if clusterScope {
			addEdge(graph, from, sinkClusterAdmin, &models.EscalationEdge{
				Technique:   "KUBE-PRIVESC-008",
				Action:      "impersonate",
				Permission:  verbResource(rule, "serviceaccounts"),
				Description: "can impersonate any ServiceAccount cluster-wide",
			})
		} else {
			for _, target := range podCreateTargets(false, rule.Namespace, subjectsByNs) {
				if target.Key() == subject.Key() {
					continue
				}
				ensureSubjectNode(graph, target)
				addEdge(graph, from, nodeID(target), &models.EscalationEdge{
					Technique:   "KUBE-PRIVESC-008",
					Action:      "impersonate_serviceaccount",
					Permission:  verbResource(rule, "serviceaccounts"),
					Description: fmt.Sprintf("can impersonate ServiceAccount %s/%s", target.Namespace, target.Name),
				})
			}
		}
	}

	if matchesResourceVerb(rule, []string{"secrets"}, []string{"get", "list", "watch"}) {
		if clusterScope || rule.Namespace == "kube-system" {
			addEdge(graph, from, sinkKubeSystemSecrets, &models.EscalationEdge{
				Technique:   "KUBE-PRIVESC-005",
				Action:      "read_secrets",
				Permission:  verbResource(rule, "secrets"),
				Description: "can read secrets in kube-system or cluster-wide",
			})
		}
	}

	if matchesResourceVerb(rule, []string{"nodes/proxy"}, []string{"get"}) {
		addEdge(graph, from, sinkNodeEscape, &models.EscalationEdge{
			Technique:   "KUBE-PRIVESC-012",
			Action:      "nodes_proxy",
			Permission:  "get nodes/proxy",
			Description: "can reach kubelet API via nodes/proxy WebSocket verb confusion",
		})
	}

	if matchesResourceVerb(rule, []string{"pods"}, []string{"create"}) {
		targets := podCreateTargets(clusterScope, rule.Namespace, subjectsByNs)
		for _, target := range targets {
			if target.Key() == subject.Key() {
				continue
			}
			ensureSubjectNode(graph, target)
			addEdge(graph, from, nodeID(target), &models.EscalationEdge{
				Technique:   "KUBE-PRIVESC-001",
				Action:      "pod_create_token_theft",
				Permission:  "create pods",
				Description: fmt.Sprintf("can create pods that mount ServiceAccount %s/%s", target.Namespace, target.Name),
			})
		}
	}

	if matchesResourceVerb(rule, []string{"pods/exec", "pods/attach"}, []string{"create", "get"}) {
		targets := podCreateTargets(clusterScope, rule.Namespace, podSAsByNs)
		for _, target := range targets {
			if target.Key() == subject.Key() {
				continue
			}
			ensureSubjectNode(graph, target)
			addEdge(graph, from, nodeID(target), &models.EscalationEdge{
				Technique:   "KUBE-PRIVESC-004",
				Action:      "pod_exec",
				Permission:  verbResource(rule, "pods/exec|pods/attach"),
				Description: fmt.Sprintf("can exec into pods running as ServiceAccount %s/%s", target.Namespace, target.Name),
			})
		}
	}

	if matchesResourceVerb(rule, []string{"serviceaccounts/token"}, []string{"create"}) {
		targets := podCreateTargets(clusterScope, rule.Namespace, subjectsByNs)
		for _, target := range targets {
			if target.Key() == subject.Key() {
				continue
			}
			ensureSubjectNode(graph, target)
			addEdge(graph, from, nodeID(target), &models.EscalationEdge{
				Technique:   "KUBE-PRIVESC-014",
				Action:      "token_request",
				Permission:  "create serviceaccounts/token",
				Description: fmt.Sprintf("can mint tokens for ServiceAccount %s/%s", target.Namespace, target.Name),
			})
		}
	}

	if clusterScope && matchesResourceVerb(rule, []string{"serviceaccounts/token"}, []string{"create"}) {
		addEdge(graph, from, sinkTokenMint, &models.EscalationEdge{
			Technique:   "KUBE-PRIVESC-014",
			Action:      "mint_arbitrary_token",
			Permission:  "create serviceaccounts/token (cluster-wide)",
			Description: "can mint a service-account token for any ServiceAccount in any namespace",
		})
	}

	// CSR approval → system:masters. A subject that can both `create
	// certificatesigningrequests` AND `update certificatesigningrequests/approval`
	// can issue a client cert whose Subject carries `O=system:masters` (or any
	// principal it chooses) and authenticate as cluster-admin. CSRs are cluster-
	// scoped, so this edge requires cluster-scoped grants for both verbs.
	//
	// We need to see both verbs across the same subject's effective rules, but
	// addEdgesForRule sees one rule at a time. The simplest correct treatment is
	// to emit a candidate edge whenever EITHER verb is held cluster-scoped, then
	// drop the candidate in a graph-wide pass if the other verb is missing. That
	// pass lives in BuildGraph after every rule has been processed.
	if clusterScope && matchesResourceVerb(rule, []string{"certificatesigningrequests"}, []string{"create"}) {
		annotateSubjectCSR(csrCapabilities, subject, csrAnnotationCreate)
	}
	if clusterScope && matchesResourceVerb(rule, []string{"certificatesigningrequests/approval"}, []string{"update", "patch"}) {
		annotateSubjectCSR(csrCapabilities, subject, csrAnnotationApprove)
	}
}

// addPodEscapeEdges links a pod's ServiceAccount to the node-escape sink when the pod has host-escape-enabling settings.
func addPodEscapeEdges(graph *models.EscalationGraph, pod corev1.Pod) {
	reasons := podEscapeReasons(pod)
	if len(reasons) == 0 {
		return
	}
	saName := pod.Spec.ServiceAccountName
	if saName == "" {
		saName = "default"
	}
	ref := models.SubjectRef{Kind: "ServiceAccount", Name: saName, Namespace: pod.Namespace}
	ensureSubjectNode(graph, ref)
	addEdge(graph, nodeID(ref), sinkNodeEscape, &models.EscalationEdge{
		Technique:   "KUBE-ESCAPE",
		Action:      "pod_host_escape",
		Permission:  strings.Join(reasons, ","),
		Description: fmt.Sprintf("runs in pod %s/%s with %s", pod.Namespace, pod.Name, strings.Join(reasons, ", ")),
	})
}

// podEscapeReasons lists the reasons a pod could be used to escape to the node (host namespaces, privileged, sensitive hostPath).
func podEscapeReasons(pod corev1.Pod) []string {
	var reasons []string
	if pod.Spec.HostPID {
		reasons = append(reasons, "hostPID")
	}
	if pod.Spec.HostNetwork {
		reasons = append(reasons, "hostNetwork")
	}
	if pod.Spec.HostIPC {
		reasons = append(reasons, "hostIPC")
	}
	for _, container := range append(append([]corev1.Container{}, pod.Spec.InitContainers...), pod.Spec.Containers...) {
		if container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
			reasons = append(reasons, "privileged")
			break
		}
	}
	for _, volume := range pod.Spec.Volumes {
		if volume.HostPath == nil {
			continue
		}
		if isSensitiveHostPath(volume.HostPath.Path) {
			reasons = append(reasons, "hostPath:"+volume.HostPath.Path)
		}
	}
	return reasons
}

// isSensitiveHostPath reports whether a hostPath value is one of the well-known escape-enabling mounts.
func isSensitiveHostPath(path string) bool {
	sensitive := []string{
		"/",
		"/etc",
		"/etc/kubernetes",
		"/var/run/docker.sock",
		"/var/run/containerd/containerd.sock",
		"/var/run/crio/crio.sock",
		"/var/lib/kubelet",
		"/var/lib/etcd",
		"/var/log",
	}
	for _, s := range sensitive {
		if path == s {
			return true
		}
	}
	return false
}

// addSink registers a terminal target node in the graph.
func addSink(graph *models.EscalationGraph, id string, target models.EscalationTarget) {
	graph.Nodes[id] = &models.EscalationNode{ID: id, IsSink: true, Target: target}
}

// ensureNamespaceAdminSink lazily registers (and returns the ID of) the per-namespace
// "namespace-admin in <ns>" sink. Each namespace gets its own sink node so a subject
// with namespace-scoped grants in multiple namespaces produces one finding per namespace.
func ensureNamespaceAdminSink(graph *models.EscalationGraph, namespace string) string {
	id := sinkNamespaceAdminPrefix + namespace
	if _, ok := graph.Nodes[id]; !ok {
		graph.Nodes[id] = &models.EscalationNode{
			ID:              id,
			IsSink:          true,
			Target:          models.TargetNamespaceAdmin,
			TargetNamespace: namespace,
		}
	}
	return id
}

// ensureSubjectNode inserts a subject node into the graph if it does not already exist.
func ensureSubjectNode(graph *models.EscalationGraph, ref models.SubjectRef) {
	id := nodeID(ref)
	if _, ok := graph.Nodes[id]; ok {
		return
	}
	graph.Nodes[id] = &models.EscalationNode{
		ID:       id,
		Subject:  ref,
		IsSystem: isSystemSubject(ref),
	}
}

// isSystemSubject flags built-in control-plane subjects so path search does not traverse them.
// Note: external cloud-IAM nodes carry IDs prefixed "external:aws-iam:" (see
// cloud_edges.go) and never flow through ensureSubjectNode, so isSystemSubject
// is never asked about them. The "external:" prefix is therefore non-system by
// construction; the pathfinder skips them by checking node.IsExternal directly.
func isSystemSubject(ref models.SubjectRef) bool {
	if strings.HasPrefix(ref.Name, "system:") {
		return true
	}
	if ref.Kind == "ServiceAccount" && (ref.Namespace == "kube-system" || ref.Namespace == "kube-public" || ref.Namespace == "kube-node-lease") {
		return true
	}
	return false
}

// addEdge sets the endpoints on edge and appends it to the graph.
func addEdge(graph *models.EscalationGraph, from, to string, edge *models.EscalationEdge) {
	edge.From = from
	edge.To = to
	graph.Edges = append(graph.Edges, edge)
}

// podCreateTargets returns the candidate service accounts a subject can mount by creating pods: all SAs when cluster-scoped, or namespace-local otherwise.
func podCreateTargets(clusterScope bool, namespace string, subjectsByNs map[string][]models.SubjectRef) []models.SubjectRef {
	if clusterScope {
		var all []models.SubjectRef
		for _, refs := range subjectsByNs {
			all = append(all, refs...)
		}
		return all
	}
	return subjectsByNs[namespace]
}

// serviceAccountsByNamespace indexes known ServiceAccounts and guarantees each namespace has a "default" entry.
func serviceAccountsByNamespace(snapshot models.Snapshot) map[string][]models.SubjectRef {
	result := map[string][]models.SubjectRef{}
	for _, sa := range snapshot.Resources.ServiceAccounts {
		ref := models.SubjectRef{Kind: "ServiceAccount", Name: sa.Name, Namespace: sa.Namespace}
		result[sa.Namespace] = append(result[sa.Namespace], ref)
	}
	for _, ns := range snapshot.Resources.Namespaces {
		if !containsSubject(result[ns.Name], "default") {
			result[ns.Name] = append(result[ns.Name], models.SubjectRef{Kind: "ServiceAccount", Name: "default", Namespace: ns.Name})
		}
	}
	return result
}

// podServiceAccountsByNamespace indexes the distinct ServiceAccounts that pods actually mount, used as exec-target candidates.
func podServiceAccountsByNamespace(snapshot models.Snapshot) map[string][]models.SubjectRef {
	result := map[string][]models.SubjectRef{}
	seen := map[string]struct{}{}
	for _, pod := range snapshot.Resources.Pods {
		sa := pod.Spec.ServiceAccountName
		if sa == "" {
			sa = "default"
		}
		ref := models.SubjectRef{Kind: "ServiceAccount", Name: sa, Namespace: pod.Namespace}
		if _, ok := seen[ref.Key()]; ok {
			continue
		}
		seen[ref.Key()] = struct{}{}
		result[pod.Namespace] = append(result[pod.Namespace], ref)
	}
	return result
}

// containsSubject reports whether the slice already has a SubjectRef with the given name.
func containsSubject(refs []models.SubjectRef, name string) bool {
	for _, ref := range refs {
		if ref.Name == name {
			return true
		}
	}
	return false
}

// matchesResourceVerb reports whether a rule covers any of the given resources and any of the given verbs (wildcards match all).
func matchesResourceVerb(rule permissions.EffectiveRule, resources, verbs []string) bool {
	return hasAnyValue(rule.Resources, resources) && hasAnyValue(rule.Verbs, verbs)
}

// hasAnyValue reports whether values contains any of the wanted tokens, treating "*" in values as a match-all wildcard.
func hasAnyValue(values []string, wanted []string) bool {
	if slices.Contains(values, "*") {
		return true
	}
	for _, w := range wanted {
		if slices.Contains(values, w) {
			return true
		}
	}
	return false
}

// hasAll reports whether every expected value is present in values (or values contains a wildcard).
func hasAll(values []string, expected ...string) bool {
	if slices.Contains(values, "*") {
		return true
	}
	for _, e := range expected {
		if !slices.Contains(values, e) {
			return false
		}
	}
	return true
}

// verbResource formats a rule's verbs together with a resource label for display in edge Permission strings.
func verbResource(rule permissions.EffectiveRule, resourceLabel string) string {
	verbs := strings.Join(rule.Verbs, ",")
	return fmt.Sprintf("%s %s", verbs, resourceLabel)
}

// subjectRef converts an rbacv1.Subject to a SubjectRef, defaulting an empty ServiceAccount namespace to fallbackNamespace.
func subjectRef(subject rbacv1.Subject, fallbackNamespace string) models.SubjectRef {
	ref := models.SubjectRef{Kind: subject.Kind, Name: subject.Name}
	if subject.Kind == "ServiceAccount" {
		ref.Namespace = subject.Namespace
		if ref.Namespace == "" {
			ref.Namespace = fallbackNamespace
		}
	}
	return ref
}
