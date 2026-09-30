// Package privesc: the CVE-2026-2270 StatefulSet confused-deputy edge. A subject
// that can write both StatefulSets and ControllerRevisions steers
// kube-controller-manager into creating a pod in a namespace the subject cannot
// touch: before the fix, the StatefulSet controller's ApplyRevision restored the
// whole StatefulSet (metadata, including namespace) from a ControllerRevision, not
// just its .Spec, so an attacker-authored revision let the controller stamp out a
// pod with an attacker-chosen namespace, ServiceAccount, and spec. Unlike the
// generic workload edges (KUBE-PRIVESC-003), this one is version-gated: BuildGraph
// only calls it when the server version falls in the affected band.
package privesc

import (
	"fmt"

	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/permissions"
)

const statefulSetDeputyTechnique = "KUBE-VERSION-CVE-2026-2270"

// The two halves of the CVE-2026-2270 primitive, pinned to the apps API group so a
// custom resource reusing the name "statefulsets" / "controllerrevisions" cannot
// trip the check.
var (
	targetStatefulSets        = []permissions.ResourceTarget{permissions.InGroup("apps", "statefulsets")}
	targetControllerRevisions = []permissions.ResourceTarget{permissions.InGroup("apps", "controllerrevisions")}
)

// deputyWriteVerbs are the write verbs on either object that let a subject drive the
// controller: create a StatefulSet, or overwrite the ControllerRevision the
// controller adopts and applies.
var deputyWriteVerbs = []string{"create", "update", "patch"}

// addStatefulSetDeputyEdges emits the CVE-2026-2270 edges for one subject, but only
// when BuildGraph has already established the server version is affected (this
// builder does not re-check the version; see kubeversion.StatefulSetControllerRevisionDeputy
// and the gate in BuildGraph).
//
// Both halves are required, and neither escalates on its own: a StatefulSet write
// with no ControllerRevision write cannot inject the cross-namespace metadata the
// bug restores, and a ControllerRevision write with no StatefulSet to attach it to
// reconciles nothing. This is the same two-verb-conjunction shape as
// KUBE-PRIVESC-019 (mutating policy) and KUBE-PRIVESC-010 (binding write + bind),
// so it uses the same cutKey / cutBreakers machinery: an edge is broken by cutting
// the sole binding behind either half.
//
// The gain is cluster-wide pod creation with an attacker-chosen namespace and
// ServiceAccount, so the edges mirror cluster-scoped pod creation:
//
//   - a token-theft fan-out to every ServiceAccount in the cluster (the attacker's
//     pod mounts that SA's token in its own namespace), and
//   - a node-escape edge when at least one namespace admits privileged pods (the
//     attacker's pod is privileged and escapes to the node).
//
// Every edge is rated `hard` (see actionDifficulty): beyond holding both grants the
// attacker must author a ControllerRevision whose strategic-merge patch reproduces
// the target namespace/spec, and, to keep the pod alive past garbage collection,
// forge a valid StatefulSet OwnerReference (the advisory's own caveat). The path
// scorer therefore attenuates any chain through this edge and drops it a severity
// bucket, which is the honest weight for a conditional, version-specific primitive.
//
// A full `*/*/*` holder is skipped: it is already cluster-admin via
// KUBE-PRIVESC-017, so re-deriving this route would only add noise.
func addStatefulSetDeputyEdges(
	graph *models.EscalationGraph,
	subject models.SubjectRef,
	rules []permissions.EffectiveRule,
	subjectsByNs map[string][]models.SubjectRef,
	privilegedNamespaces map[string]bool,
) {
	stsWrite, crWrite := map[cutKey]bool{}, map[cutKey]bool{}
	for _, rule := range rules {
		if isFullWildcardRule(rule) {
			continue
		}
		key := cutKey{binding: rule.SourceBinding, namespace: rule.Namespace}
		if rule.Grants(targetStatefulSets, deputyWriteVerbs...) {
			stsWrite[key] = true
		}
		if rule.Grants(targetControllerRevisions, deputyWriteVerbs...) {
			crWrite[key] = true
		}
	}
	if len(stsWrite) == 0 || len(crWrite) == 0 {
		return
	}
	breakers := cutBreakers(stsWrite, crWrite)
	from := nodeID(subject)
	ensureSubjectNode(graph, subject)

	// Token theft in any namespace: the confused deputy can place the attacker's pod
	// in a namespace they have no access to, mounting any ServiceAccount there.
	for _, target := range podCreateTargets(true, "", subjectsByNs) {
		if target.Key() == subject.Key() {
			continue
		}
		ensureSubjectNode(graph, target)
		addEdge(graph, from, nodeID(target), &models.EscalationEdge{
			Technique:   statefulSetDeputyTechnique,
			Action:      "statefulset_cross_namespace_pod",
			Permission:  "write statefulsets + controllerrevisions (apps)",
			Description: fmt.Sprintf("can steer kube-controller-manager (CVE-2026-2270) into creating a pod as ServiceAccount %s/%s in a namespace it cannot access", target.Namespace, target.Name),
			// A new pod the attacker's revision defines, with the SA's token mounted:
			// same position as workload_create_token_theft, minus the pod's own
			// privileged spec (that route is the node_escape edge below).
			Grants:      models.FootholdIdentity | models.FootholdToken | models.FootholdNewPod,
			CutBreakers: breakers,
		})
	}

	// Privileged pod cross-namespace: land it wherever PSA does not block privileged.
	if len(privilegedNamespaces) > 0 {
		addEdge(graph, from, sinkNodeEscape, &models.EscalationEdge{
			Technique:   statefulSetDeputyTechnique,
			Action:      "statefulset_cross_namespace_pod",
			Permission:  "write statefulsets + controllerrevisions (Pod Security Admission does not block privileged somewhere)",
			Description: "can steer kube-controller-manager (CVE-2026-2270) into creating a privileged pod in a namespace PSA does not restrict, and escape to the node",
			CutBreakers: breakers,
		})
	}
}
