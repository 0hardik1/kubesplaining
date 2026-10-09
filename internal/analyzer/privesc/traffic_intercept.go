// Package privesc: edges into the traffic_intercept sink. A Service's backends are
// derived from the IPs its selected pods report in their status, and that status is
// an ordinary subresource. A subject that can write `pods/status` for a selected pod
// rewrites its podIP; the EndpointSlice controller republishes the address and
// kube-proxy re-points the Service at it within a second, so every client of that
// Service, bearer tokens included, talks to an address the attacker chose until the
// pod's kubelet writes the real IP back on its next status sync.
package privesc

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/permissions"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
)

const podStatusInterceptTechnique = "KUBE-PRIVESC-036"

// interceptableService is one Service whose backend list a pods/status writer can
// steer, with the fact the difficulty rating turns on.
type interceptableService struct {
	namespace string
	name      string
	// durable is true when the Service publishes not-ready addresses and selects a
	// pod with no node: no kubelet owns that pod's status, so a spoofed address is
	// never corrected, and the controller publishes it as ready anyway.
	durable bool
}

func (s interceptableService) label() string { return s.namespace + "/" + s.name }

// livePod reports whether a pod's status still feeds Service backends: not
// finished, and not being deleted.
func livePod(pod corev1.Pod) bool {
	if pod.DeletionTimestamp != nil {
		return false
	}
	switch pod.Status.Phase {
	case corev1.PodSucceeded, corev1.PodFailed:
		return false
	}
	return true
}

// interceptableServices returns, sorted and deduplicated, the Services whose
// selector matches a live pod that rule's `pods/status` write reaches. A cluster-
// scoped rule reaches pods in every namespace, a namespaced rule only its own, and
// resourceNames restrict it to the named pods (the name of a pod, as with exec).
// A Service with no selector has no pod-derived backends and is skipped.
func interceptableServices(rule permissions.EffectiveRule, clusterScope bool, snapshot models.Snapshot) []interceptableService {
	byNamespace := map[string][]corev1.Service{}
	for _, svc := range snapshot.Resources.Services {
		if len(svc.Spec.Selector) == 0 {
			continue
		}
		byNamespace[svc.Namespace] = append(byNamespace[svc.Namespace], svc)
	}
	seen := map[string]int{}
	var out []interceptableService
	for _, pod := range snapshot.Resources.Pods {
		if !livePod(pod) {
			continue
		}
		if !clusterScope && pod.Namespace != rule.Namespace {
			continue
		}
		if rule.NameScoped() && !slices.Contains(rule.ResourceNames, pod.Name) {
			continue
		}
		podLabels := labels.Set(pod.Labels)
		for _, svc := range byNamespace[pod.Namespace] {
			if !labels.SelectorFromSet(svc.Spec.Selector).Matches(podLabels) {
				continue
			}
			entry := interceptableService{
				namespace: svc.Namespace,
				name:      svc.Name,
				durable:   svc.Spec.PublishNotReadyAddresses && pod.Spec.NodeName == "",
			}
			key := entry.label()
			if i, ok := seen[key]; ok {
				out[i].durable = out[i].durable || entry.durable
				continue
			}
			seen[key] = len(out)
			out = append(out, entry)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].label() < out[j].label() })
	return out
}

// addPodStatusInterceptEdges emits the KUBE-PRIVESC-036 edge for one subject: an
// `update`/`patch` grant on `pods/status` that reaches a live pod some Service
// selects. The pod status validator checks only that podIPs are well-formed
// addresses, and NodeRestriction constrains node callers only, so the write is
// authorized like any other RBAC write. One edge is emitted per granting rule, with
// that rule's provenance, so the cut-resilient pass can ban it per binding.
//
// The edge is `hard` by default: the pod's kubelet rewrites the status on its next
// sync (10 s), so the spoofed address holds only while the attacker keeps writing
// it. It is `moderate` when one of the Services publishes not-ready addresses and
// selects a pod that has no node, because then no kubelet corrects the write and the
// controller publishes the spoofed address as a ready backend indefinitely.
//
// Node identities and full `*/*/*` holders are skipped: the kubelet's write is the
// legitimate one, and a wildcard holder is already cluster-admin.
func addPodStatusInterceptEdges(
	graph *models.EscalationGraph,
	subject models.SubjectRef,
	rules []permissions.EffectiveRule,
	snapshot models.Snapshot,
) {
	if isSystemSubject(subject) {
		return
	}
	from := nodeID(subject)
	emitted := map[cutKey]bool{}
	for _, rule := range rules {
		if isFullWildcardRule(rule) {
			continue
		}
		if !matchesResourceVerb(rule, []string{"pods/status"}, []string{"update", "patch"}) {
			continue
		}
		key := cutKey{binding: rule.SourceBinding, namespace: rule.Namespace}
		if emitted[key] {
			continue
		}
		clusterScope := rule.Namespace == ""
		services := interceptableServices(rule, clusterScope, snapshot)
		if len(services) == 0 {
			continue
		}
		emitted[key] = true
		difficulty := difficultyHard
		for _, svc := range services {
			if svc.durable {
				difficulty = difficultyModerate
				break
			}
		}
		ensureSubjectNode(graph, subject)
		addEdge(graph, from, sinkTrafficIntercept, &models.EscalationEdge{
			Technique:        podStatusInterceptTechnique,
			Action:           "pod_status_ip_spoof",
			Permission:       verbResource(rule, "pods/status"),
			Description:      fmt.Sprintf("can rewrite the pod IP in the status of pods selected by Service %s, redirecting that Service's traffic to an address it chooses until the kubelet corrects the status", serviceList(services)),
			Difficulty:       difficulty,
			SourceBinding:    rule.SourceBinding,
			SourceRole:       rule.SourceRole,
			BindingNamespace: rule.Namespace,
		})
	}
}

// serviceList renders up to three Service names, then a count of the rest.
func serviceList(services []interceptableService) string {
	names := make([]string, 0, len(services))
	for _, svc := range services {
		names = append(names, svc.label())
	}
	if len(names) <= 3 {
		return strings.Join(names, ", ")
	}
	return fmt.Sprintf("%s, +%d more", strings.Join(names[:3], ", "), len(names)-3)
}
