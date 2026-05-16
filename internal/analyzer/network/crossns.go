// Cross-namespace NetworkPolicy analysis. Looks at every NetworkPolicy and reports
// when its peer rules explicitly grant ingress or egress that crosses a namespace
// boundary involving a sensitive namespace (kube-system, kube-public, kube-node-lease,
// default). The intent is to surface the soft-tenancy violations that look fine in
// "kubectl get netpol" — a policy in `team-a` that allows traffic from `kube-system`
// is structurally suspicious because it pierces the cluster's strongest cheap
// isolation boundary.
//
// Detection model. For each NetworkPolicy P in namespace `polNS`:
//   - For each ingress.from peer:
//   - If peer.namespaceSelector matches a namespace `peerNS` other than `polNS`,
//     the pair is (peerNS -> polNS) ingress.
//   - If peer.namespaceSelector is empty (`{}`), it matches every namespace, so
//     the pair is (any -> polNS) ingress (we surface this as `*` in the source).
//   - For each egress.to peer:
//   - Symmetric: matched namespace becomes the destination, polNS the source.
//
// We emit a finding only when at least one of `polNS` or the peer namespace is
// sensitive. The shared isSystemNamespace helper in analyzer.go enumerates the
// system set; we add `default` here because user-created workloads land there
// when no explicit namespace is set, so any rule that bridges `default` to a
// tenant namespace deserves a note.
//
// Severity: MEDIUM. Cross-namespace allow rules are sometimes legitimate
// (a logging sidecar in kube-system scraping app namespaces) but they are
// almost always worth a second look in a multi-tenant cluster, so we lean
// toward surfacing rather than suppressing.
package network

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/scoring"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// crossNSDirection enumerates ingress vs egress so the finding ID and prose
// can both render the direction crisply.
type crossNSDirection string

const (
	directionIngress crossNSDirection = "ingress"
	directionEgress  crossNSDirection = "egress"
)

// crossNSPair is one (sourceNS, targetNS, direction) tuple emitted as a finding.
// SourceNS may be "*" when the peer's namespaceSelector is empty (matches all).
type crossNSPair struct {
	PolicyNamespace string
	PolicyName      string
	SourceNS        string
	TargetNS        string
	Direction       crossNSDirection
}

// findCrossNamespacePairs walks every NetworkPolicy and returns the deduplicated
// (sourceNS, targetNS, direction) tuples whose endpoints involve a sensitive
// namespace. The returned slice is sorted for determinism so finding IDs are
// stable across runs.
func findCrossNamespacePairs(snapshot models.Snapshot) []crossNSPair {
	namespacesByLabels := indexNamespaces(snapshot.Resources.Namespaces)
	seen := map[string]struct{}{}
	out := make([]crossNSPair, 0)

	for _, policy := range snapshot.Resources.NetworkPolicies {
		polNS := policy.Namespace

		for _, ingress := range policy.Spec.Ingress {
			for _, peer := range ingress.From {
				for _, ns := range peerNamespaces(peer, namespacesByLabels) {
					if !isCrossNamespace(ns, polNS) {
						continue
					}
					if !pairTouchesSensitive(ns, polNS) {
						continue
					}
					pair := crossNSPair{
						PolicyNamespace: polNS,
						PolicyName:      policy.Name,
						SourceNS:        ns,
						TargetNS:        polNS,
						Direction:       directionIngress,
					}
					key := pairKey(pair)
					if _, ok := seen[key]; ok {
						continue
					}
					seen[key] = struct{}{}
					out = append(out, pair)
				}
			}
		}

		for _, egress := range policy.Spec.Egress {
			for _, peer := range egress.To {
				for _, ns := range peerNamespaces(peer, namespacesByLabels) {
					if !isCrossNamespace(ns, polNS) {
						continue
					}
					if !pairTouchesSensitive(ns, polNS) {
						continue
					}
					pair := crossNSPair{
						PolicyNamespace: polNS,
						PolicyName:      policy.Name,
						SourceNS:        polNS,
						TargetNS:        ns,
						Direction:       directionEgress,
					}
					key := pairKey(pair)
					if _, ok := seen[key]; ok {
						continue
					}
					seen[key] = struct{}{}
					out = append(out, pair)
				}
			}
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].PolicyNamespace != out[j].PolicyNamespace {
			return out[i].PolicyNamespace < out[j].PolicyNamespace
		}
		if out[i].PolicyName != out[j].PolicyName {
			return out[i].PolicyName < out[j].PolicyName
		}
		if out[i].Direction != out[j].Direction {
			return out[i].Direction < out[j].Direction
		}
		if out[i].SourceNS != out[j].SourceNS {
			return out[i].SourceNS < out[j].SourceNS
		}
		return out[i].TargetNS < out[j].TargetNS
	})

	return out
}

// peerNamespaces returns the namespace name(s) that peer.namespaceSelector
// resolves to. The returned slice contains:
//   - "*" when the namespaceSelector is non-nil but empty (matches every namespace
//     in the cluster, the documented "all namespaces" form).
//   - One entry per namespace whose labels match a populated namespaceSelector.
//   - An empty slice when peer.namespaceSelector is nil (peer is "same namespace
//     plus optional podSelector"; not a cross-NS edge by definition).
//
// IPBlock peers do not move us across a namespace boundary at the L7 NetworkPolicy
// level (they escape to L3) so they are intentionally not considered here. The
// IMDS check in imds_egress.go handles the cloud-metadata IPBlock case.
func peerNamespaces(peer networkingv1.NetworkPolicyPeer, namespacesByLabels []corev1.Namespace) []string {
	if peer.NamespaceSelector == nil {
		return nil
	}
	if isAllNamespaces(peer.NamespaceSelector) {
		return []string{"*"}
	}
	selector, err := metav1.LabelSelectorAsSelector(peer.NamespaceSelector)
	if err != nil {
		return nil
	}
	matches := make([]string, 0)
	for _, ns := range namespacesByLabels {
		if selector.Matches(labels.Set(ns.Labels)) {
			matches = append(matches, ns.Name)
		}
	}
	return matches
}

// indexNamespaces returns a deterministic slice of namespaces (sorted by name)
// so callers get stable iteration order.
func indexNamespaces(namespaces []corev1.Namespace) []corev1.Namespace {
	out := make([]corev1.Namespace, len(namespaces))
	copy(out, namespaces)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// isCrossNamespace reports whether the source namespace differs from the policy
// namespace (i.e., the rule reaches across a namespace boundary). The "*" sentinel
// (any namespace) is always considered cross-NS.
func isCrossNamespace(sourceNS, policyNS string) bool {
	if sourceNS == "*" {
		return true
	}
	return sourceNS != policyNS
}

// sensitiveCrossNSNamespaces lists namespaces whose involvement in any cross-NS
// allow rule warrants surfacing the rule. kube-system / kube-public / kube-node-lease
// are the standard control-plane namespaces; `default` is included because workloads
// frequently land there when no explicit namespace is set, so allow rules bridging
// `default` are nearly always misconfigurations rather than intent.
var sensitiveCrossNSNamespaces = map[string]struct{}{
	"kube-system":       {},
	"kube-public":       {},
	"kube-node-lease":   {},
	"default":           {},
	"gatekeeper-system": {},
}

// pairTouchesSensitive reports whether either endpoint of the (source, target)
// pair is in the sensitive set. The wildcard "*" is treated as sensitive because
// it crosses into every namespace, including the sensitive ones.
func pairTouchesSensitive(a, b string) bool {
	if a == "*" || b == "*" {
		return true
	}
	if _, ok := sensitiveCrossNSNamespaces[a]; ok {
		return true
	}
	_, ok := sensitiveCrossNSNamespaces[b]
	return ok
}

// pairKey returns a stable map key for deduplicating identical findings emitted
// from distinct policies in the same namespace.
func pairKey(p crossNSPair) string {
	return fmt.Sprintf("%s|%s|%s|%s|%s", p.PolicyNamespace, p.PolicyName, p.Direction, p.SourceNS, p.TargetNS)
}

// emitCrossNSFindings materializes one finding per cross-NS pair returned by
// findCrossNamespacePairs.
func emitCrossNSFindings(pairs []crossNSPair) []models.Finding {
	out := make([]models.Finding, 0, len(pairs))
	for _, pair := range pairs {
		evidence := map[string]any{
			"policy_namespace": pair.PolicyNamespace,
			"policy_name":      pair.PolicyName,
			"source_namespace": pair.SourceNS,
			"target_namespace": pair.TargetNS,
			"direction":        string(pair.Direction),
		}
		evidenceBytes, _ := json.Marshal(evidence)

		content := contentNetpolCrossNS001(pair)

		out = append(out, models.Finding{
			ID:          fmt.Sprintf("KUBE-NETPOL-CROSSNS-001:%s:%s:%s:%s:%s", pair.PolicyNamespace, pair.PolicyName, pair.Direction, pair.SourceNS, pair.TargetNS),
			RuleID:      "KUBE-NETPOL-CROSSNS-001",
			Severity:    models.SeverityMedium,
			Score:       scoring.Clamp(5.4),
			Category:    models.CategoryLateralMovement,
			Title:       content.Title,
			Description: content.Description,
			Namespace:   pair.PolicyNamespace,
			Resource: &models.ResourceRef{
				Kind:      "NetworkPolicy",
				Name:      pair.PolicyName,
				Namespace: pair.PolicyNamespace,
				APIGroup:  networkingv1.GroupName,
			},
			Scope:            content.Scope,
			Impact:           content.Impact,
			AttackScenario:   content.AttackScenario,
			Evidence:         evidenceBytes,
			Remediation:      content.Remediation,
			RemediationSteps: content.RemediationSteps,
			References:       referencesFromContent(content),
			LearnMore:        content.LearnMore,
			MitreTechniques:  content.MitreTechniques,
			Tags:             []string{"module:network_policy", "check:crossNamespaceAllow", "direction:" + string(pair.Direction)},
		})
	}
	return out
}
