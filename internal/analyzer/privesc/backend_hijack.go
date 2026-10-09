// Package privesc: Service backend steering and control-plane backend namespaces.
//
// A Service's backends come from the EndpointSlices that carry its
// `kubernetes.io/service-name` label, and kube-proxy consumes every such slice
// whatever its `managed-by` label says. The EndpointSlice controller reconciles
// only the slices it manages, so a foreign slice an attacker creates survives, and
// the Service's own selector and ports are plain spec fields. Writing any of them
// steers the Service's traffic.
//
// Where the Service is one the API server itself calls (an admission webhook
// backend or an aggregated API server), steering it plus presenting its serving
// certificate puts the attacker in the API server's request path. The namespace
// hosting such a Service is a control-plane backend namespace, and ordinary
// namespace-level grants there (`edit`, `admin`, or any pod-create plus
// secrets-read pairing) are a control-plane compromise, not a tenant-scoped one.
package privesc

import (
	"fmt"
	"sort"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/permissions"
)

const (
	endpointSliceWriteTechnique = "KUBE-PRIVESC-021"
	serviceRewriteTechnique     = "KUBE-PRIVESC-022"
	apiServiceTechnique         = "KUBE-PRIVESC-020"
	backendHijackTechnique      = "KUBE-PRIVESC-038"
)

var (
	endpointSliceWriteVerbs = []string{"create", "update", "patch"}
	serviceWriteVerbs       = []string{"update", "patch"}
)

// backendsByNamespace indexes the snapshot's control-plane backends by the
// namespace that hosts them.
func backendsByNamespace(snapshot models.Snapshot) map[string][]models.ControlPlaneBackend {
	out := map[string][]models.ControlPlaneBackend{}
	for _, b := range models.ControlPlaneBackends(snapshot) {
		out[b.Namespace] = append(out[b.Namespace], b)
	}
	return out
}

// servicesByNamespace indexes Service names by namespace, sorted.
func servicesByNamespace(snapshot models.Snapshot) map[string][]string {
	out := map[string][]string{}
	for _, svc := range snapshot.Resources.Services {
		out[svc.Namespace] = append(out[svc.Namespace], svc.Name)
	}
	for ns := range out {
		sort.Strings(out[ns])
	}
	return out
}

// namespacesInScope lists the namespaces a rule reaches: every namespace in the
// index for a cluster-scoped rule, its own for a namespaced one, sorted.
func namespacesInScope(rule permissions.EffectiveRule, index map[string][]string) []string {
	if rule.Namespace != "" {
		if _, ok := index[rule.Namespace]; ok {
			return []string{rule.Namespace}
		}
		return nil
	}
	out := make([]string, 0, len(index))
	for ns := range index {
		out = append(out, ns)
	}
	sort.Strings(out)
	return out
}

// routingHalf reports how rule lets its holder steer the traffic of Services in
// namespace ns, or "" when it does not: a write on EndpointSlices (a foreign slice
// joins the Service), a write on the Service itself (selector, ports, type), or a
// pod the holder controls joining the Service by label (a new pod, or a label patch
// on an existing one).
func routingHalf(rule permissions.EffectiveRule, ns string, workloads []workload) string {
	if rule.Namespace != "" && rule.Namespace != ns {
		return ""
	}
	if matchesResourceVerb(rule, []string{"endpointslices"}, endpointSliceWriteVerbs) {
		return "write endpointslices"
	}
	if matchesResourceVerb(rule, []string{"services"}, serviceWriteVerbs) {
		return "write services"
	}
	if grant := podCreationReaches(rule, ns, workloads); grant != "" {
		return grant
	}
	if matchesResourceVerb(rule, []string{"pods"}, []string{"update", "patch"}) {
		return "patch pods"
	}
	return ""
}

// tlsHalf reports how rule lets its holder present the backend Service's serving
// certificate in namespace ns, or "" when it does not: read the serving Secret, run a
// pod that mounts it, or run code in the backend's own pods (exec, an ephemeral
// container, or an image swap).
func tlsHalf(rule permissions.EffectiveRule, ns string, workloads []workload) string {
	if rule.Namespace != "" && rule.Namespace != ns {
		return ""
	}
	if matchesResourceVerb(rule, []string{"secrets"}, []string{"get", "list", "watch"}) {
		return "read secrets"
	}
	if grant := podCreationReaches(rule, ns, workloads); grant != "" {
		return grant
	}
	if matchesResourceVerb(rule, []string{"pods/exec", "pods/attach"}, []string{"create", "get"}) {
		return "exec pods"
	}
	if matchesResourceVerb(rule, []string{"pods/ephemeralcontainers"}, []string{"update", "patch"}) {
		return "patch pods/ephemeralcontainers"
	}
	if matchesResourceVerb(rule, []string{"pods"}, []string{"update", "patch"}) {
		return "patch pods"
	}
	return ""
}

// backendSink is where a hijacked control-plane backend leads. A mutating webhook
// on pods CREATE rewrites every new pod, which is a node escape wherever Pod
// Security admits a privileged pod (the same gate as mutating_policy_inject). A
// native-group APIService serves a core API group in the API server's stead, which
// is cluster-admin. Everything else is the API server's request stream for that
// backend: traffic interception.
func backendSink(b models.ControlPlaneBackend, privilegedNamespaces map[string]bool) string {
	switch {
	case b.Kind == "APIService" && b.Native:
		return sinkClusterAdmin
	case b.MatchesPodCreate && len(privilegedNamespaces) > 0:
		return sinkNodeEscape
	default:
		return sinkTrafficIntercept
	}
}

// addBackendEdges emits, for one subject, the Service-steering edges:
//
//   - endpointslice_write (KUBE-PRIVESC-021): create/update/patch on EndpointSlices
//     in a namespace that has Services, to traffic_intercept. Rare outside
//     controllers, so it is emitted for every namespace in scope.
//   - service_backend_rewrite (KUBE-PRIVESC-022): update/patch on Services, to
//     traffic_intercept. The `edit` ClusterRole carries this verb for every tenant,
//     so the generic edge is emitted only for a cluster-scoped grant or a namespace
//     that hosts a control-plane backend; the namespaced tenant case is the
//     backend-hijack edge below when it applies, and no edge otherwise.
//   - control_plane_backend_hijack (KUBE-PRIVESC-038): in a namespace that hosts a
//     control-plane backend, a routing half and a TLS half held together, to the
//     sink the backend's kind decides. A backend verified against system roots (no
//     caBundle) is skipped, because no in-cluster Secret satisfies that check; an
//     APIService with insecureSkipTLSVerify needs no TLS half. Both halves get
//     CutBreakers so the cut-resilient pass bans the edge when either is cut.
//   - apiservice_takeover (KUBE-PRIVESC-020): cluster-scoped update/patch on
//     APIServices, to cluster_admin when the grant can reach a native-group
//     registration (unscoped, or resourceNames naming one), else to
//     traffic_intercept when it names an aggregated registration in the snapshot.
//
// A full `*/*/*` holder is skipped: it is already cluster-admin.
func addBackendEdges(
	graph *models.EscalationGraph,
	subject models.SubjectRef,
	rules []permissions.EffectiveRule,
	snapshot models.Snapshot,
	workloads []workload,
	privilegedNamespaces map[string]bool,
) {
	if isSystemSubject(subject) {
		return
	}
	from := nodeID(subject)
	services := servicesByNamespace(snapshot)
	backends := backendsByNamespace(snapshot)
	emitted := map[string]bool{}
	add := func(to string, rule permissions.EffectiveRule, edge *models.EscalationEdge) {
		key := fmt.Sprintf("%s|%s|%s|%s", edge.Action, to, rule.SourceBinding, rule.Namespace)
		if emitted[key] {
			return
		}
		emitted[key] = true
		edge.SourceBinding = rule.SourceBinding
		edge.SourceRole = rule.SourceRole
		edge.BindingNamespace = rule.Namespace
		ensureSubjectNode(graph, subject)
		addEdge(graph, from, to, edge)
	}

	for _, rule := range rules {
		if isFullWildcardRule(rule) {
			continue
		}
		if matchesResourceVerb(rule, []string{"endpointslices"}, endpointSliceWriteVerbs) {
			if scope := namespacesInScope(rule, services); len(scope) > 0 {
				add(sinkTrafficIntercept, rule, &models.EscalationEdge{
					Technique:   endpointSliceWriteTechnique,
					Action:      "endpointslice_write",
					Permission:  verbResource(rule, "endpointslices"),
					Description: fmt.Sprintf("can add or rewrite EndpointSlices for Services in %s, steering their traffic to addresses it chooses", namespaceList(scope)),
				})
			}
		}
		if matchesResourceVerb(rule, []string{"services"}, serviceWriteVerbs) {
			scope := namespacesInScope(rule, services)
			if rule.Namespace != "" && len(backends[rule.Namespace]) == 0 {
				scope = nil
			}
			if len(scope) > 0 {
				add(sinkTrafficIntercept, rule, &models.EscalationEdge{
					Technique:   serviceRewriteTechnique,
					Action:      "service_backend_rewrite",
					Permission:  verbResource(rule, "services"),
					Description: fmt.Sprintf("can rewrite the selector, ports, or type of Services in %s, steering their traffic to backends it chooses", namespaceList(scope)),
				})
			}
		}
		if rule.Namespace == "" && matchesResourceVerb(rule, []string{"apiservices"}, []string{"update", "patch"}) {
			addAPIServiceEdge(graph, from, rule, snapshot, add)
		}
	}

	addControlPlaneBackendHijackEdges(graph, from, rules, backends, workloads, privilegedNamespaces)
}

// addAPIServiceEdge emits the KUBE-PRIVESC-020 edge for one cluster-scoped
// update/patch grant on APIServices.
func addAPIServiceEdge(
	graph *models.EscalationGraph,
	from string,
	rule permissions.EffectiveRule,
	snapshot models.Snapshot,
	add func(string, permissions.EffectiveRule, *models.EscalationEdge),
) {
	if !rule.NameScoped() {
		add(sinkClusterAdmin, rule, &models.EscalationEdge{
			Technique:   apiServiceTechnique,
			Action:      "apiservice_takeover",
			Permission:  verbResource(rule, "apiservices"),
			Description: "can re-point any API group's registration, native groups included, at a Service it controls, so the API server forwards that group's requests and its own credentials there",
		})
		return
	}
	var native, aggregated []string
	for _, name := range rule.ResourceNames {
		_, group := models.APIServiceGroupFromName(name)
		if models.BuiltinAPIGroups[group] {
			native = append(native, name)
			continue
		}
		for _, api := range snapshot.Resources.APIServices {
			if api.Name == name && api.Backend() {
				aggregated = append(aggregated, name)
				break
			}
		}
	}
	sort.Strings(native)
	sort.Strings(aggregated)
	if len(native) > 0 {
		add(sinkClusterAdmin, rule, &models.EscalationEdge{
			Technique:   apiServiceTechnique,
			Action:      "apiservice_takeover",
			Permission:  verbResource(rule, "apiservices") + " (" + strings.Join(native, ", ") + ")",
			Description: fmt.Sprintf("can re-point the native API registration %s at a Service it controls, so the API server forwards that group's requests and its own credentials there", strings.Join(native, ", ")),
		})
		return
	}
	if len(aggregated) > 0 {
		add(sinkTrafficIntercept, rule, &models.EscalationEdge{
			Technique:   apiServiceTechnique,
			Action:      "apiservice_takeover",
			Permission:  verbResource(rule, "apiservices") + " (" + strings.Join(aggregated, ", ") + ")",
			Description: fmt.Sprintf("can re-point the aggregated API registration %s at a Service it controls, receiving every request the API server forwards for that group", strings.Join(aggregated, ", ")),
		})
	}
}

// addControlPlaneBackendHijackEdges emits the KUBE-PRIVESC-038 edges for one
// subject: per namespace that hosts a control-plane backend, the routing and TLS
// halves held together, one edge per distinct sink.
func addControlPlaneBackendHijackEdges(
	graph *models.EscalationGraph,
	from string,
	rules []permissions.EffectiveRule,
	backends map[string][]models.ControlPlaneBackend,
	workloads []workload,
	privilegedNamespaces map[string]bool,
) {
	namespaces := make([]string, 0, len(backends))
	for ns := range backends {
		namespaces = append(namespaces, ns)
	}
	sort.Strings(namespaces)

	for _, ns := range namespaces {
		routing, tls := map[cutKey]bool{}, map[cutKey]bool{}
		routingGrant, tlsGrant := "", ""
		for _, rule := range rules {
			if isFullWildcardRule(rule) {
				continue
			}
			key := cutKey{binding: rule.SourceBinding, namespace: rule.Namespace}
			if g := routingHalf(rule, ns, workloads); g != "" {
				routing[key] = true
				if routingGrant == "" {
					routingGrant = g
				}
			}
			if g := tlsHalf(rule, ns, workloads); g != "" {
				tls[key] = true
				if tlsGrant == "" {
					tlsGrant = g
				}
			}
		}
		if len(routing) == 0 {
			continue
		}
		// Group the namespace's backends by the sink they lead to, keeping only
		// those whose TLS check the subject can satisfy.
		type group struct {
			names    []string
			needsTLS bool
		}
		groups := map[string]*group{}
		var sinks []string
		for _, b := range backends[ns] {
			needsTLS := !b.InsecureTLS
			if needsTLS && !b.HasCABundle {
				// Verified against system roots: an in-cluster serving Secret cannot
				// satisfy it, so steering the Service yields a TLS failure, not a hijack.
				continue
			}
			if needsTLS && len(tls) == 0 {
				continue
			}
			sink := backendSink(b, privilegedNamespaces)
			g, ok := groups[sink]
			if !ok {
				g = &group{}
				groups[sink] = g
				sinks = append(sinks, sink)
			}
			g.names = append(g.names, b.Label())
			g.needsTLS = g.needsTLS || needsTLS
		}
		for _, sink := range sinks {
			g := groups[sink]
			permission := fmt.Sprintf("%s in %s", routingGrant, ns)
			breakers := cutBreakers(routing)
			if g.needsTLS {
				permission = fmt.Sprintf("%s + %s in %s", routingGrant, tlsGrant, ns)
				breakers = cutBreakers(routing, tls)
			}
			names := g.names
			if len(names) > 3 {
				names = append(append([]string{}, names[:3]...), fmt.Sprintf("+%d more", len(names)-3))
			}
			addEdge(graph, from, sink, &models.EscalationEdge{
				Technique:   backendHijackTechnique,
				Action:      "control_plane_backend_hijack",
				Permission:  permission,
				Description: fmt.Sprintf("can take over the backend of %s in namespace %s, which the API server calls with its own credentials", strings.Join(names, ", "), ns),
				CutBreakers: breakers,
			})
		}
	}
}
