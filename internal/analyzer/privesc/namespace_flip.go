// Package privesc: the Pod Security Admission label-flip edge. Pod Security
// Admission reads the standard it enforces from labels on the Namespace object,
// and nothing in-tree protects those labels: a subject that can update or patch
// the namespace rewrites `pod-security.kubernetes.io/enforce` to `privileged`, and
// from then on PSA admits a privileged pod there. The label write alone escalates
// nothing; together with a way to create pods in that namespace it is a node
// escape in a namespace the operator believed PSA had locked down.
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

const namespaceFlipTechnique = "KUBE-PRIVESC-035"

// psaEnforceLabel is the namespace label Pod Security Admission reads to choose
// the standard it enforces. Mirrors the rbac analyzer's constant; the two packages
// do not import each other.
const psaEnforceLabel = "pod-security.kubernetes.io/enforce"

// namespaceWriteReaches reports whether rule lets the subject update or patch the
// Namespace object named ns. Namespaces are cluster-scoped objects, but the request
// path `/api/v1/namespaces/<ns>` carries <ns> as the request's namespace
// (RequestInfoFactory in k8s.io/apiserver/pkg/endpoints/request), so RBAC
// evaluates a RoleBinding in <ns> against it: a namespaced Role granting
// `patch namespaces` reaches its own namespace object, and only that one. A
// cluster-scoped grant reaches every namespace its resourceNames do not exclude.
func namespaceWriteReaches(rule permissions.EffectiveRule, ns string) bool {
	if !matchesResourceVerb(rule, []string{"namespaces"}, []string{"update", "patch"}) {
		return false
	}
	if rule.Namespace != "" && rule.Namespace != ns {
		return false
	}
	if rule.NameScoped() && !slices.Contains(rule.ResourceNames, ns) {
		return false
	}
	return true
}

// podCreationReaches reports how rule lets the subject get a pod of its own design
// running in ns once PSA admits privileged pods there: `create pods`, `create` on a
// pod-template-carrying workload, or `update`/`patch` on a workload that already
// exists in ns (its template can be rewritten to a privileged one). Returns the
// grant that matched, for the edge's Permission string, or "" when none does.
func podCreationReaches(rule permissions.EffectiveRule, ns string, workloads []workload) string {
	if rule.Namespace != "" && rule.Namespace != ns {
		return ""
	}
	if matchesResourceVerb(rule, []string{"pods"}, []string{"create"}) {
		return "create pods"
	}
	if kinds := grantedWorkloadKinds(rule, createWorkloadKinds, "create"); len(kinds) > 0 {
		return "create " + strings.Join(kinds, "/")
	}
	for _, w := range workloads {
		if w.namespace == ns && ruleReachesWorkload(rule, w) {
			return "update/patch " + w.kind.resource
		}
	}
	return ""
}

// namespacesEnforcingPSA returns the names of the namespaces whose PSA `enforce`
// label currently blocks privileged pods (`baseline` or `restricted`), sorted.
// These are the only namespaces where flipping the label changes anything: an
// unlabeled or `privileged` namespace already admits a privileged pod, and that
// direct route is the pod_create_privileged_escape edge.
func namespacesEnforcingPSA(namespaces []corev1.Namespace) []string {
	var out []string
	for _, ns := range namespaces {
		switch ns.Labels[psaEnforceLabel] {
		case "baseline", "restricted":
			out = append(out, ns.Name)
		}
	}
	sort.Strings(out)
	return out
}

// addNamespaceLabelFlipEdges emits the KUBE-PRIVESC-035 edge for one subject: for
// a namespace whose PSA `enforce` label currently blocks privileged pods, the
// subject holds both a write on that Namespace object and a way to create pods in
// it. Both halves are required. Either alone is inert or already modeled: a
// pod-create grant into a restricted namespace is the token-theft edge only
// (pod_create_privileged_escape needs PSA to admit privileged), and a namespace
// write with nothing to create there escalates nothing.
//
// Namespaces reached through exactly the same granting bindings for both halves
// are grouped into one edge, so a cluster-wide holder does not fan out one edge
// per restricted namespace. The CutBreakers are identical for every namespace in
// a group, which is what makes the grouping sound for the cut-resilient pass.
// This builder runs after the pod and workload edges, so a subject whose
// pod-create grant already lands somewhere PSA does not restrict keeps that
// direct route as its reported one.
//
// A full `*/*/*` holder is skipped: it is already cluster-admin via
// KUBE-PRIVESC-017.
func addNamespaceLabelFlipEdges(
	graph *models.EscalationGraph,
	subject models.SubjectRef,
	rules []permissions.EffectiveRule,
	namespaces []corev1.Namespace,
	workloads []workload,
) {
	type flipGroup struct {
		namespaces []string
		breakers   []models.BindingRef
		nsGrant    string
		podGrant   string
	}
	groups := map[string]*flipGroup{}
	var order []string

	for _, ns := range namespacesEnforcingPSA(namespaces) {
		nsWrite, podCreate := map[cutKey]bool{}, map[cutKey]bool{}
		nsGrant, podGrant := "", ""
		for _, rule := range rules {
			if isFullWildcardRule(rule) {
				continue
			}
			key := cutKey{binding: rule.SourceBinding, namespace: rule.Namespace}
			if namespaceWriteReaches(rule, ns) {
				nsWrite[key] = true
				if nsGrant == "" {
					nsGrant = "update namespaces"
					if matchesResourceVerb(rule, []string{"namespaces"}, []string{"patch"}) {
						nsGrant = "patch namespaces"
					}
				}
			}
			if grant := podCreationReaches(rule, ns, workloads); grant != "" {
				podCreate[key] = true
				if podGrant == "" {
					podGrant = grant
				}
			}
		}
		if len(nsWrite) == 0 || len(podCreate) == 0 {
			continue
		}
		sig := cutKeySignature(nsWrite) + "|" + cutKeySignature(podCreate)
		g, ok := groups[sig]
		if !ok {
			g = &flipGroup{breakers: cutBreakers(nsWrite, podCreate), nsGrant: nsGrant, podGrant: podGrant}
			groups[sig] = g
			order = append(order, sig)
		}
		g.namespaces = append(g.namespaces, ns)
	}
	if len(order) == 0 {
		return
	}

	from := nodeID(subject)
	ensureSubjectNode(graph, subject)
	for _, sig := range order {
		g := groups[sig]
		list := namespaceList(g.namespaces)
		addEdge(graph, from, sinkNodeEscape, &models.EscalationEdge{
			Technique:   namespaceFlipTechnique,
			Action:      "namespace_psa_label_flip",
			Permission:  fmt.Sprintf("%s + %s (%s)", g.nsGrant, g.podGrant, list),
			Description: fmt.Sprintf("can relabel namespace %s to pod-security enforce=privileged, then run a privileged pod there and escape to the node", list),
			CutBreakers: g.breakers,
		})
	}
}

// cutKeySignature renders a half's granting bindings as a stable string so two
// namespaces reached through the same bindings land in the same edge.
func cutKeySignature(half map[cutKey]bool) string {
	parts := make([]string, 0, len(half))
	for key := range half {
		parts = append(parts, key.namespace+"/"+key.binding)
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// namespaceList renders up to three namespace names, then a count of the rest.
func namespaceList(names []string) string {
	if len(names) <= 3 {
		return strings.Join(names, ", ")
	}
	return fmt.Sprintf("%s, +%d more", strings.Join(names[:3], ", "), len(names)-3)
}
