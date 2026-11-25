// Package privesc: node token harvest, the step out of node_escape.
//
// The kubelet writes every projected ServiceAccount token it mounts into a pod
// under /var/lib/kubelet/pods/<uid>/volumes on the pod's node, so root on a node
// is the union of every co-scheduled pod's ServiceAccount. That includes an IRSA
// token, which works from outside AWS. RBAC review never sees this hop: it runs
// through the node, not a RoleBinding. Wiz Research described it in the wild on
// 2026-11-23 ("Agentic Attacks in the Wild: ARTEX & Offensive AI Frameworks"): a
// stolen application ServiceAccount token created a privileged pod with the
// node's root filesystem mounted, a collector pod took the kubelet PKI and every
// projected token on the node, and a cert-manager token among them led to
// cluster-admin.
//
// Two edge families carry it, both action node_token_harvest:
//
//   - node_escape -> ServiceAccount, for every ServiceAccount whose live pod
//     mounts an API token on a node an attacker-authored pod can land on. These
//     need FootholdNodeOfChoice, which only the escapes whose holder writes the
//     pod spec grant (see nodeOfChoiceEscapes): such a pod names its node in
//     spec.nodeName, which bypasses the scheduler, and tolerates any taint.
//   - ServiceAccount -> ServiceAccount, from a pod that already runs with full
//     host access to every other ServiceAccount whose pod shares its node. These
//     need FootholdPod: the escape uses that pod's own spec, on its own node.
package privesc

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
	corev1 "k8s.io/api/core/v1"
)

const nodeHarvestTechnique = "KUBE-ESCAPE-NODE-TOKENS-001"

// kubeletPodsDir is where the kubelet materializes pod volumes, projected
// ServiceAccount tokens included.
const kubeletPodsDir = "/var/lib/kubelet/pods"

// nodeOfChoiceEscapes lists the actions into node_escape whose holder runs code
// they wrote as root on a node they pick, because they author the pod spec (or,
// for nodes_proxy, reach every kubelet's exec endpoint). addEdge stamps
// FootholdNodeOfChoice on these when they target node_escape.
//
// Left out on purpose: pod_host_escape (an existing pod, fixed to its node),
// imds_node_role_pivot (the node's IAM role, not root on it), and
// node_drain_migrate (moves chosen pods to the attacker's node, so which tokens
// arrive depends on what they evict, which the graph does not model).
var nodeOfChoiceEscapes = map[string]bool{
	"pod_create_privileged_escape":    true,
	"workload_privileged_escape":      true,
	"mutating_policy_inject":          true,
	"namespace_psa_label_flip":        true,
	"control_plane_backend_hijack":    true,
	"statefulset_cross_namespace_pod": true,
	"nodes_proxy":                     true,
}

// nodeTokenPod is one live pod that mounts an API token for its ServiceAccount.
type nodeTokenPod struct {
	pod corev1.Pod
	sa  models.SubjectRef
}

// addNodeTokenHarvestEdges emits both node_token_harvest families and makes
// node_escape traversable when the first family has any edge.
func addNodeTokenHarvestEdges(graph *models.EscalationGraph, snapshot models.Snapshot) {
	saAutomount := serviceAccountAutomount(snapshot)
	unreachable := harvestUnreachableNodes(snapshot)

	byNode := map[string][]nodeTokenPod{}
	for _, pod := range snapshot.Resources.Pods {
		if pod.Spec.NodeName == "" || !livePod(pod) {
			continue
		}
		ref := podServiceAccount(pod)
		if !podMountsAPIToken(pod, saAutomount[ref.Key()]) {
			continue
		}
		byNode[pod.Spec.NodeName] = append(byNode[pod.Spec.NodeName], nodeTokenPod{pod: pod, sa: ref})
	}
	nodes := make([]string, 0, len(byNode))
	for n := range byNode {
		nodes = append(nodes, n)
	}
	sort.Strings(nodes)

	addChosenNodeHarvest(graph, byNode, nodes, unreachable)
	addSameNodeHarvest(graph, snapshot, byNode)
}

// addChosenNodeHarvest emits node_escape -> ServiceAccount for every ServiceAccount
// with a token-mounting pod on a node an attacker-authored pod can reach.
func addChosenNodeHarvest(graph *models.EscalationGraph, byNode map[string][]nodeTokenPod, nodes []string, unreachable map[string]bool) {
	sink, ok := graph.Nodes[sinkNodeEscape]
	if !ok {
		return
	}
	targets := map[string]models.SubjectRef{}
	nodesByTarget := map[string][]string{}
	for _, n := range nodes {
		if unreachable[n] {
			continue
		}
		for _, p := range byNode[n] {
			k := p.sa.Key()
			targets[k] = p.sa
			if l := nodesByTarget[k]; len(l) == 0 || l[len(l)-1] != n {
				nodesByTarget[k] = append(nodesByTarget[k], n)
			}
		}
	}
	if len(targets) == 0 {
		return
	}
	sink.Traversable = true
	keys := make([]string, 0, len(targets))
	for k := range targets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		target := targets[k]
		ensureSubjectNode(graph, target)
		addEdge(graph, sinkNodeEscape, nodeID(target), &models.EscalationEdge{
			Technique:  nodeHarvestTechnique,
			Action:     "node_token_harvest",
			Permission: "root on a node the attacker's pod can name in spec.nodeName",
			Description: fmt.Sprintf("as root on %s, can read the projected token of ServiceAccount %s/%s from its pod's volume under %s",
				namespaceList(nodesByTarget[k]), target.Namespace, target.Name, kubeletPodsDir),
			Needs:  models.FootholdNodeOfChoice,
			Grants: models.FootholdIdentity | models.FootholdToken,
		})
	}
}

// addSameNodeHarvest emits ServiceAccount -> ServiceAccount from each pod that
// already runs with host filesystem access to every other ServiceAccount whose
// token-mounting pod shares its node. One edge per (from, to) pair; the first
// escaping pod in snapshot order names it.
func addSameNodeHarvest(graph *models.EscalationGraph, snapshot models.Snapshot, byNode map[string][]nodeTokenPod) {
	seen := map[string]bool{}
	for _, pod := range snapshot.Resources.Pods {
		if pod.Spec.NodeName == "" || !livePod(pod) {
			continue
		}
		reason := hostTokenAccess(pod)
		if reason == "" {
			continue
		}
		from := podServiceAccount(pod)
		for _, p := range byNode[pod.Spec.NodeName] {
			if p.sa.Key() == from.Key() {
				continue
			}
			key := from.Key() + "|" + p.sa.Key()
			if seen[key] {
				continue
			}
			seen[key] = true
			ensureSubjectNode(graph, from)
			ensureSubjectNode(graph, p.sa)
			addEdge(graph, nodeID(from), nodeID(p.sa), &models.EscalationEdge{
				Technique:  nodeHarvestTechnique,
				Action:     "node_token_harvest",
				Permission: reason + " on node " + pod.Spec.NodeName,
				Description: fmt.Sprintf("from pod %s/%s (%s), can read the projected token of ServiceAccount %s/%s, whose pod %s/%s shares node %s",
					pod.Namespace, pod.Name, reason, p.sa.Namespace, p.sa.Name, p.pod.Namespace, p.pod.Name, pod.Spec.NodeName),
				Needs:  models.FootholdPod,
				Grants: models.FootholdIdentity | models.FootholdToken,
			})
		}
	}
}

// hostTokenAccess names the setting that lets code in pod read other pods'
// token volumes on its node, or returns "" when it has none. That takes more
// than podEscapeReasons: hostNetwork, hostIPC, or hostPID alone reach no files.
// It does take one of
//
//   - a privileged container, which can mount the host's disks,
//   - a hostPath at or above the kubelet's pods directory, or
//   - a container runtime socket, which starts a privileged container on demand.
func hostTokenAccess(pod corev1.Pod) string {
	for _, c := range append(append([]corev1.Container{}, pod.Spec.InitContainers...), pod.Spec.Containers...) {
		if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
			return "privileged"
		}
	}
	for _, v := range pod.Spec.Volumes {
		if v.HostPath == nil {
			continue
		}
		p := path.Clean(v.HostPath.Path)
		if p == "/" || strings.HasPrefix(kubeletPodsDir+"/", p+"/") {
			return "hostPath:" + v.HostPath.Path
		}
		switch p {
		case "/var/run/docker.sock", "/run/docker.sock",
			"/var/run/containerd/containerd.sock", "/run/containerd/containerd.sock",
			"/var/run/crio/crio.sock", "/run/crio/crio.sock":
			return "hostPath:" + v.HostPath.Path
		}
	}
	return ""
}

// harvestUnreachableNodes returns the nodes an attacker-authored privileged pod
// does not run on, so their pods' tokens are not harvested from a chosen node:
//
//   - control-plane nodes with a NoSchedule or NoExecute taint for their role,
//     matching the gate on the control-plane continuation (a schedulable
//     control-plane node is already reported through control_plane_pki_theft);
//   - EKS Fargate nodes, which run one pod each in its own micro-VM;
//   - Windows nodes, where a Linux privileged pod does not run.
//
// A pod bound to a node the snapshot does not list is treated as reachable.
func harvestUnreachableNodes(snapshot models.Snapshot) map[string]bool {
	out := fargateNodeNames(snapshot)
	for _, node := range snapshot.Resources.Nodes {
		if isControlPlaneNode(node) && hasControlPlaneNoScheduleTaint(node) {
			out[node.Name] = true
		}
		if node.Labels[corev1.LabelOSStable] == "windows" {
			out[node.Name] = true
		}
	}
	return out
}

// serviceAccountAutomount maps each ServiceAccount key to its
// automountServiceAccountToken setting, nil where it is unset.
func serviceAccountAutomount(snapshot models.Snapshot) map[string]*bool {
	out := map[string]*bool{}
	for _, sa := range snapshot.Resources.ServiceAccounts {
		ref := models.SubjectRef{Kind: "ServiceAccount", Name: sa.Name, Namespace: sa.Namespace}
		out[ref.Key()] = sa.AutomountServiceAccountToken
	}
	return out
}
