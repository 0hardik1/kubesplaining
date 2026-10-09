// Package privesc: the node_identity sink.
//
// A kubelet client identity is `system:node:<name>` in the group `system:nodes`.
// The Node authorizer grants it, for the node it names, every Secret, ConfigMap,
// and PersistentVolumeClaim referenced by a pod bound to that node and a
// TokenRequest for the ServiceAccount of any such pod. Nothing in the Node
// authorizer checks that the name is a node that exists or that the caller is a
// kubelet, so a way to obtain a node identity for a name of the holder's choosing
// is a way to the credentials of every pod on every node. The sink models that
// union: one traversable node, fanning out to the ServiceAccounts whose pods mount
// an API token on some node.
package privesc

import (
	"fmt"
	"sort"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/permissions"
	corev1 "k8s.io/api/core/v1"
)

const (
	sinkNodeIdentity = "sink:node_identity"

	nodeClientTechnique     = "KUBE-PRIVESC-037"
	bootstrapTokenTechnique = "KUBE-PRIVESC-026"
	nodeAuthorizerTechnique = "KUBE-NODE-AUTHZ"

	groupNodes      = "system:nodes"
	nodeUserPrefix  = "system:node:"
	bootstrapSecret = corev1.SecretType("bootstrap.kubernetes.io/token")
)

// addNodeIdentitySink registers the traversable node_identity sink.
func addNodeIdentitySink(graph *models.EscalationGraph) {
	addSink(graph, sinkNodeIdentity, models.TargetNodeIdentity)
	graph.Nodes[sinkNodeIdentity].Traversable = true
}

// addNodeIdentityEdges emits, for one subject, the edges into node_identity:
//
//   - csr_nodeclient_autoapprove (KUBE-PRIVESC-037): cluster-scoped `create
//     certificatesigningrequests` together with `create
//     certificatesigningrequests/nodeclient`. The controller manager's CSR
//     approver auto-approves a kubelet client CSR when a SubjectAccessReview
//     says the requester holds the nodeclient subresource, and nothing ties the
//     requested node name to the requester, so the certificate names any node.
//   - bootstrap_token_mint (KUBE-PRIVESC-026): a Secret write reaching kube-system
//     on a cluster whose bootstrap group auto-approves kubelet client CSRs. A
//     Secret of type bootstrap.kubernetes.io/token is a bootstrap token, which
//     authenticates as a member of that group. Gated on the kubeadm binding
//     because a cluster without it has no path from token to node identity.
//   - impersonate_node: cluster-scoped `impersonate users` reaching a
//     `system:node:` name together with `impersonate groups` reaching
//     `system:nodes`. The Node authorizer requires both. An unscoped `impersonate
//     groups` already leads to system_masters, so this edge matters for the grant
//     scoped to the nodes group by resourceNames.
//
// A full `*/*/*` holder is skipped: it is already cluster-admin.
func addNodeIdentityEdges(graph *models.EscalationGraph, subject models.SubjectRef, rules []permissions.EffectiveRule, snapshot models.Snapshot) {
	if isSystemSubject(subject) {
		return
	}
	from := nodeID(subject)
	csrCreate, nodeClient := map[cutKey]bool{}, map[cutKey]bool{}
	impUsers, impGroups := map[cutKey]bool{}, map[cutKey]bool{}
	var csrRule, nodeClientRule, bootstrapRule, impUsersRule *permissions.EffectiveRule
	kubeadm := models.KubeadmBootstrapAutoApproval(snapshot)

	for i := range rules {
		rule := &rules[i]
		if isFullWildcardRule(*rule) {
			continue
		}
		key := cutKey{binding: rule.SourceBinding, namespace: rule.Namespace}
		if rule.Namespace == "" {
			if matchesResourceVerb(*rule, []string{"certificatesigningrequests"}, []string{"create"}) {
				csrCreate[key] = true
				if csrRule == nil {
					csrRule = rule
				}
			}
			if matchesResourceVerb(*rule, []string{"certificatesigningrequests/nodeclient"}, []string{"create"}) {
				nodeClient[key] = true
				if nodeClientRule == nil {
					nodeClientRule = rule
				}
			}
			if matchesResourceVerb(*rule, []string{"users"}, []string{"impersonate"}) && reachesNodeUser(*rule) {
				impUsers[key] = true
				if impUsersRule == nil {
					impUsersRule = rule
				}
			}
			if matchesResourceVerb(*rule, []string{"groups"}, []string{"impersonate"}) && rule.NameScoped() && containsString(rule.ResourceNames, groupNodes) {
				impGroups[key] = true
			}
		}
		if kubeadm && bootstrapRule == nil && (rule.Namespace == "" || rule.Namespace == metav1NamespaceSystem) &&
			!rule.NameScoped() && matchesResourceVerb(*rule, []string{"secrets"}, []string{"create", "update", "patch"}) {
			bootstrapRule = rule
		}
	}

	if csrRule != nil && nodeClientRule != nil {
		ensureSubjectNode(graph, subject)
		addEdge(graph, from, sinkNodeIdentity, &models.EscalationEdge{
			Technique:        nodeClientTechnique,
			Action:           "csr_nodeclient_autoapprove",
			Permission:       "create certificatesigningrequests + create certificatesigningrequests/nodeclient",
			Description:      "can submit a kubelet client CSR for any node name, which the controller manager auto-approves for holders of the nodeclient subresource",
			CutBreakers:      cutBreakers(csrCreate, nodeClient),
			SourceBinding:    nodeClientRule.SourceBinding,
			SourceRole:       nodeClientRule.SourceRole,
			BindingNamespace: nodeClientRule.Namespace,
		})
	}
	if bootstrapRule != nil {
		ensureSubjectNode(graph, subject)
		addEdge(graph, from, sinkNodeIdentity, &models.EscalationEdge{
			Technique:        bootstrapTokenTechnique,
			Action:           "bootstrap_token_mint",
			Permission:       verbResource(*bootstrapRule, "secrets") + " in kube-system",
			Description:      "can write a bootstrap-token Secret in kube-system, minting a token that this cluster's bootstrap group turns into an auto-approved kubelet client certificate for any node name",
			SourceBinding:    bootstrapRule.SourceBinding,
			SourceRole:       bootstrapRule.SourceRole,
			BindingNamespace: bootstrapRule.Namespace,
		})
	}
	if impUsersRule != nil && len(impGroups) > 0 {
		ensureSubjectNode(graph, subject)
		addEdge(graph, from, sinkNodeIdentity, &models.EscalationEdge{
			Technique:        "KUBE-PRIVESC-008",
			Action:           "impersonate_node",
			Permission:       "impersonate users (system:node:*) + impersonate groups (system:nodes)",
			Description:      "can impersonate a node identity, system:node:<name> in system:nodes, for any node name",
			CutBreakers:      cutBreakers(impUsers, impGroups),
			SourceBinding:    impUsersRule.SourceBinding,
			SourceRole:       impUsersRule.SourceRole,
			BindingNamespace: impUsersRule.Namespace,
		})
	}
}

// metav1NamespaceSystem is kube-system, spelled out to keep the import list short.
const metav1NamespaceSystem = "kube-system"

// reachesNodeUser reports whether an impersonate-users grant reaches a
// `system:node:` name: unscoped, or resourceNames naming one.
func reachesNodeUser(rule permissions.EffectiveRule) bool {
	if !rule.NameScoped() {
		return true
	}
	for _, name := range rule.ResourceNames {
		if strings.HasPrefix(name, nodeUserPrefix) {
			return true
		}
	}
	return false
}

func containsString(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

// addNodeIdentityFanOut emits the edges out of node_identity, once per graph:
//
//   - node_token_request: to every ServiceAccount with a pod bound to a node that
//     mounts an API token for it. The Node authorizer lets a node request a token
//     for the ServiceAccount of any pod bound to it, and the identity names any
//     node, so the union over nodes is every such ServiceAccount.
//   - node_secret_read: to kube_system_secrets when a kube-system pod bound to a
//     node references a Secret (a volume, an env source, or a pull secret). The
//     Node authorizer lets a node read the Secrets its pods reference.
//
// System ServiceAccounts are kept as targets here: a node identity reaching
// kube-system's controllers is the point of the fan-out, and the pathfinder stops
// at them as it does for every system node.
func addNodeIdentityFanOut(graph *models.EscalationGraph, snapshot models.Snapshot, tokenMounted map[string]bool) {
	targets := map[string]models.SubjectRef{}
	nodesByTarget := map[string]map[string]bool{}
	kubeSystemSecretRef := false
	for _, pod := range snapshot.Resources.Pods {
		if pod.Spec.NodeName == "" || !livePod(pod) {
			continue
		}
		ref := podServiceAccount(pod)
		if tokenMounted[ref.Key()] {
			targets[ref.Key()] = ref
			if nodesByTarget[ref.Key()] == nil {
				nodesByTarget[ref.Key()] = map[string]bool{}
			}
			nodesByTarget[ref.Key()][pod.Spec.NodeName] = true
		}
		if pod.Namespace == metav1NamespaceSystem && podReferencesSecret(pod) {
			kubeSystemSecretRef = true
		}
	}
	keys := make([]string, 0, len(targets))
	for k := range targets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		target := targets[k]
		if _, ok := graph.Nodes[nodeID(target)]; !ok {
			ensureSubjectNode(graph, target)
		}
		nodes := make([]string, 0, len(nodesByTarget[k]))
		for n := range nodesByTarget[k] {
			nodes = append(nodes, n)
		}
		sort.Strings(nodes)
		addEdge(graph, sinkNodeIdentity, nodeID(target), &models.EscalationEdge{
			Technique:   nodeAuthorizerTechnique,
			Action:      "node_token_request",
			Permission:  "node authorizer: create serviceaccounts/token for pods bound to the node",
			Description: fmt.Sprintf("as the node identity for %s, can request a token for ServiceAccount %s/%s, whose pod is bound there", namespaceList(nodes), target.Namespace, target.Name),
			Grants:      models.FootholdToken | models.FootholdIdentity,
		})
	}
	if kubeSystemSecretRef {
		addEdge(graph, sinkNodeIdentity, sinkKubeSystemSecrets, &models.EscalationEdge{
			Technique:   nodeAuthorizerTechnique,
			Action:      "node_secret_read",
			Permission:  "node authorizer: get secrets referenced by pods bound to the node",
			Description: "as the node identity for a node running kube-system pods, can read the Secrets those pods reference",
		})
	}
}

// podReferencesSecret reports whether a pod references any Secret through a
// volume, an environment source, or an image pull secret.
func podReferencesSecret(pod corev1.Pod) bool {
	for _, v := range pod.Spec.Volumes {
		if v.Secret != nil {
			return true
		}
		if v.Projected != nil {
			for _, src := range v.Projected.Sources {
				if src.Secret != nil {
					return true
				}
			}
		}
	}
	containers := append(append([]corev1.Container{}, pod.Spec.InitContainers...), pod.Spec.Containers...)
	for _, c := range containers {
		for _, env := range c.Env {
			if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
				return true
			}
		}
		for _, src := range c.EnvFrom {
			if src.SecretRef != nil {
				return true
			}
		}
	}
	return len(pod.Spec.ImagePullSecrets) > 0
}
