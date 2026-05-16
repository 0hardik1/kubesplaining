// IMDS (Instance Metadata Service) egress reachability analysis.
//
// The link-local endpoint 169.254.169.254 (the AWS/Azure/GCP cloud Instance
// Metadata Service) is the single most attacked egress destination in modern
// cloud Kubernetes clusters. A pod that can reach it can mint cloud-provider
// IAM credentials and pivot from container RCE to full cloud-account
// compromise. Compare blog.christophetd.fr's EKS worker-node IAM walkthrough.
//
// This module asks one question per pod / workload: "can this pod's egress
// reach 169.254.169.254/32?" We answer it by walking the pod's namespace's
// NetworkPolicies in egress mode:
//
//  1. If no NetworkPolicy with policyTypes:[Egress] selects the pod, Kubernetes
//     leaves the pod non-isolated for egress (allow-all), so IMDS is reachable.
//     Fire KUBE-NETPOL-IMDS-001 with the "no-egress-policy" reason.
//
//  2. If at least one egress policy selects the pod, compute the union of its
//     allowed peers. If any allowed peer is an ipBlock whose CIDR contains
//     169.254.169.254 AND whose `except:` list does not carve out the IMDS IP,
//     fire KUBE-NETPOL-IMDS-001 with the "explicit-allow" reason. Common
//     offenders here: ipBlock 0.0.0.0/0 (the universal allow), 169.254.0.0/16
//     (the entire link-local range), or 169.254.169.254/32 itself.
//
//  3. If every selecting policy either does not include IMDS in its ipBlock
//     reach OR carves it out via `except:`, the pod is fine and no finding fires.
//
// The check is intentionally conservative on the "default-deny saves us" case:
// if a pod has any egress policy at all whose peers do not include a
// 169.254-containing ipBlock, we trust the deny-by-default semantic and stay
// quiet. This avoids drowning operators who have done the right thing.
//
// Severity: HIGH. The SSRF -> cloud-creds chain is one of the highest-impact
// real-world attack patterns in cloud Kubernetes; score 7.8.
package network

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"

	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/scoring"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// imdsIP is the AWS/Azure/GCP link-local cloud metadata service endpoint. GCP
// also surfaces it at the DNS name `metadata.google.internal`, but every cloud
// uses 169.254.169.254 as the L3 address, so a pod that can reach the IP can
// reach IMDS regardless of provider.
const imdsIP = "169.254.169.254"

// imdsReason captures why a particular pod / workload fired KUBE-NETPOL-IMDS-001.
// Helps the report and tests distinguish the two structural causes.
type imdsReason string

const (
	imdsReasonNoEgressPolicy imdsReason = "no-egress-policy"
	imdsReasonExplicitAllow  imdsReason = "explicit-allow"
)

// imdsFinding is one workload-level IMDS-reachability finding before it is
// materialized into a models.Finding. Keeping the intermediate struct makes
// the analyzer testable without poking at the models.Finding JSON shape.
type imdsFinding struct {
	Workload                workload
	Reason                  imdsReason
	OffenderCIDR            string // populated when Reason == imdsReasonExplicitAllow; the CIDR that admits IMDS
	OffenderPolicyNamespace string
	OffenderPolicyName      string
}

// findImdsReachable returns one imdsFinding per workload whose effective egress
// posture allows reaching 169.254.169.254. The result is deterministically
// ordered by (namespace, kind, name) so finding IDs are stable.
func findImdsReachable(snapshot models.Snapshot, workloads []workload) []imdsFinding {
	policiesByNS := policiesByNamespace(snapshot.Resources.NetworkPolicies)
	out := make([]imdsFinding, 0)

	for _, wl := range workloads {
		if isSystemNamespace(wl.Namespace) {
			continue
		}
		policies := policiesByNS[wl.Namespace]
		egressPolicies := egressPoliciesSelectingWorkload(policies, wl.Labels)

		if len(egressPolicies) == 0 {
			// No policy with policyTypes:[Egress] selects this pod, so Kubernetes
			// applies the allow-all default. IMDS is reachable.
			out = append(out, imdsFinding{
				Workload: wl,
				Reason:   imdsReasonNoEgressPolicy,
			})
			continue
		}

		// At least one egress policy selects this pod. Check whether the union
		// of its allowed peers admits IMDS via any ipBlock that doesn't carve
		// the IMDS IP out via `except:`.
		offender, offenderPolicy := findIMDSAllow(egressPolicies)
		if offender != "" {
			out = append(out, imdsFinding{
				Workload:                wl,
				Reason:                  imdsReasonExplicitAllow,
				OffenderCIDR:            offender,
				OffenderPolicyNamespace: offenderPolicy.Namespace,
				OffenderPolicyName:      offenderPolicy.Name,
			})
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Workload.Namespace != out[j].Workload.Namespace {
			return out[i].Workload.Namespace < out[j].Workload.Namespace
		}
		if out[i].Workload.Kind != out[j].Workload.Kind {
			return out[i].Workload.Kind < out[j].Workload.Kind
		}
		return out[i].Workload.Name < out[j].Workload.Name
	})
	return out
}

// egressPoliciesSelectingWorkload returns the subset of policies whose podSelector
// matches the workload's labels AND whose effective PolicyTypes include Egress.
// A workload is egress-isolated only when at least one such policy exists.
func egressPoliciesSelectingWorkload(policies []networkingv1.NetworkPolicy, workloadLabels map[string]string) []networkingv1.NetworkPolicy {
	out := make([]networkingv1.NetworkPolicy, 0)
	for _, policy := range policies {
		if !policyTypesContains(effectivePolicyTypes(policy), networkingv1.PolicyTypeEgress) {
			continue
		}
		selector, err := metav1.LabelSelectorAsSelector(&policy.Spec.PodSelector)
		if err != nil {
			continue
		}
		if selector.Matches(labels.Set(workloadLabels)) {
			out = append(out, policy)
		}
	}
	return out
}

// policyTypesContains reports whether the slice includes the given PolicyType.
func policyTypesContains(types []networkingv1.PolicyType, target networkingv1.PolicyType) bool {
	for _, t := range types {
		if t == target {
			return true
		}
	}
	return false
}

// findIMDSAllow inspects the union of egress peers across the given policies and
// returns the first ipBlock CIDR that admits 169.254.169.254 without carving it
// out via `except:`. Returns ("", policy{}) when every policy correctly excludes
// IMDS or simply does not mention any IMDS-containing CIDR.
//
// Note on the semantic: NetworkPolicy egress rules with PolicyTypes:[Egress] are
// strictly additive. A policy that allows ipBlock:10.0.0.0/8 does not allow
// 169.254.169.254 — the allow-list does not include IMDS. We only fire when an
// ipBlock explicitly contains 169.254.169.254.
func findIMDSAllow(policies []networkingv1.NetworkPolicy) (string, networkingv1.NetworkPolicy) {
	imdsAddr := net.ParseIP(imdsIP)
	for _, policy := range policies {
		for _, egress := range policy.Spec.Egress {
			for _, peer := range egress.To {
				if peer.IPBlock == nil {
					continue
				}
				_, cidrNet, err := net.ParseCIDR(peer.IPBlock.CIDR)
				if err != nil {
					continue
				}
				if !cidrNet.Contains(imdsAddr) {
					continue
				}
				if exceptCoversIMDS(peer.IPBlock.Except, imdsAddr) {
					continue
				}
				return peer.IPBlock.CIDR, policy
			}
		}
	}
	return "", networkingv1.NetworkPolicy{}
}

// exceptCoversIMDS reports whether any entry in the `except:` list of an ipBlock
// contains the IMDS address (so the broad ipBlock is correctly carved out).
func exceptCoversIMDS(except []string, addr net.IP) bool {
	for _, e := range except {
		_, exceptNet, err := net.ParseCIDR(e)
		if err != nil {
			continue
		}
		if exceptNet.Contains(addr) {
			return true
		}
	}
	return false
}

// emitImdsFindings materializes one models.Finding per imdsFinding returned by
// findImdsReachable.
func emitImdsFindings(items []imdsFinding) []models.Finding {
	out := make([]models.Finding, 0, len(items))
	for _, item := range items {
		evidence := map[string]any{
			"workload_kind":      item.Workload.Kind,
			"workload_name":      item.Workload.Name,
			"workload_namespace": item.Workload.Namespace,
			"reason":             string(item.Reason),
		}
		if item.OffenderCIDR != "" {
			evidence["offender_cidr"] = item.OffenderCIDR
			evidence["offender_policy"] = fmt.Sprintf("%s/%s", item.OffenderPolicyNamespace, item.OffenderPolicyName)
		}
		evidenceBytes, _ := json.Marshal(evidence)

		content := contentNetpolIMDS001(item)

		out = append(out, models.Finding{
			ID:          fmt.Sprintf("KUBE-NETPOL-IMDS-001:%s:%s:%s", item.Workload.Kind, item.Workload.Namespace, item.Workload.Name),
			RuleID:      "KUBE-NETPOL-IMDS-001",
			Severity:    models.SeverityHigh,
			Score:       scoring.Clamp(7.8),
			Category:    models.CategoryDataExfiltration,
			Title:       content.Title,
			Description: content.Description,
			Namespace:   item.Workload.Namespace,
			Resource: &models.ResourceRef{
				Kind:      item.Workload.Kind,
				Name:      item.Workload.Name,
				Namespace: item.Workload.Namespace,
				APIGroup:  workloadAPIGroup(item.Workload.Kind),
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
			Tags:             []string{"module:network_policy", "check:imdsReachable", "reason:" + string(item.Reason)},
		})
	}
	return out
}
