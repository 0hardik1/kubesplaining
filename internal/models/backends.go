package models

import (
	"sort"
	"strings"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// BuiltinAPIGroups are the API groups the kube-apiserver serves itself. An
// APIService for one of these groups is registered by the API server at startup
// (label `kube-aggregator.kubernetes.io/automanaged`) and has no spec.service; one
// that points at a Service re-routes a native group to that Service. The list is
// explicit on purpose: a `*.k8s.io` suffix would also match third-party groups such
// as metrics.k8s.io and snapshot.storage.k8s.io.
var BuiltinAPIGroups = map[string]bool{
	"":                             true,
	"admissionregistration.k8s.io": true,
	"apiextensions.k8s.io":         true,
	"apiregistration.k8s.io":       true,
	"apps":                         true,
	"authentication.k8s.io":        true,
	"authorization.k8s.io":         true,
	"autoscaling":                  true,
	"batch":                        true,
	"certificates.k8s.io":          true,
	"coordination.k8s.io":          true,
	"discovery.k8s.io":             true,
	"events.k8s.io":                true,
	"flowcontrol.apiserver.k8s.io": true,
	"internal.apiserver.k8s.io":    true,
	"networking.k8s.io":            true,
	"node.k8s.io":                  true,
	"policy":                       true,
	"rbac.authorization.k8s.io":    true,
	"resource.k8s.io":              true,
	"scheduling.k8s.io":            true,
	"storage.k8s.io":               true,
	"storagemigration.k8s.io":      true,
}

// APIServiceGroupFromName splits an APIService name, `<version>.<group>`, and
// returns the group (`""` for the core group's `v1.`). The version never contains a
// dot, so the first dot is the separator.
func APIServiceGroupFromName(name string) (version, group string) {
	version, group, _ = strings.Cut(name, ".")
	return version, group
}

// APIServiceSummaryFromObject reduces an unstructured apiregistration.k8s.io
// APIService (from the dynamic client or a decoded manifest) to the fields the
// analyzers read.
func APIServiceSummaryFromObject(raw map[string]any) APIServiceSummary {
	obj := unstructured.Unstructured{Object: raw}
	summary := APIServiceSummary{Name: obj.GetName()}
	summary.Group, _, _ = unstructured.NestedString(raw, "spec", "group")
	summary.Version, _, _ = unstructured.NestedString(raw, "spec", "version")
	if summary.Group == "" && summary.Version == "" {
		summary.Version, summary.Group = APIServiceGroupFromName(summary.Name)
	}
	summary.ServiceNamespace, _, _ = unstructured.NestedString(raw, "spec", "service", "namespace")
	summary.ServiceName, _, _ = unstructured.NestedString(raw, "spec", "service", "name")
	// The port arrives as int64 from the dynamic client, and as int or float64 from a
	// decoded manifest, so a type switch rather than NestedInt64.
	if port, ok, _ := unstructured.NestedFieldNoCopy(raw, "spec", "service", "port"); ok {
		switch v := port.(type) {
		case int64:
			summary.ServicePort = int32(v)
		case int32:
			summary.ServicePort = v
		case int:
			summary.ServicePort = int32(v)
		case float64:
			summary.ServicePort = int32(v)
		}
	}
	summary.InsecureSkipTLSVerify, _, _ = unstructured.NestedBool(raw, "spec", "insecureSkipTLSVerify")
	if ca, _, _ := unstructured.NestedString(raw, "spec", "caBundle"); ca != "" {
		summary.HasCABundle = true
	}
	summary.Automanaged = obj.GetLabels()["kube-aggregator.kubernetes.io/automanaged"]
	return summary
}

// ControlPlaneBackend is one Service the API server itself calls: an admission
// webhook's backend, or an aggregated API server. The namespace that hosts it is a
// control-plane backend namespace: whoever can steer that Service's traffic, and
// present its serving certificate, receives requests the API server sends with its
// own credentials.
type ControlPlaneBackend struct {
	// Kind is "MutatingWebhookConfiguration", "ValidatingWebhookConfiguration", or
	// "APIService".
	Kind string
	// Name is the configuration's name, with the webhook's own name appended for a
	// webhook (`cfg/webhook`), or the APIService name.
	Name      string
	Namespace string
	Service   string
	// MatchesPodCreate is true for a mutating webhook whose rules cover pods CREATE:
	// its replacement can rewrite every new pod, which is the mutating-policy
	// position (KUBE-PRIVESC-019).
	MatchesPodCreate bool
	// Native is true for an APIService in a BuiltinAPIGroups group: its replacement
	// serves a native API group, including RBAC or authentication, in the API
	// server's stead.
	Native bool
	// InsecureTLS is true when the API server does not verify the backend's serving
	// certificate (APIService spec.insecureSkipTLSVerify).
	InsecureTLS bool
	// HasCABundle is true when the API server verifies the backend against a CA
	// bundle in the configuration. A webhook with no bundle is verified against the
	// host's system roots, which an in-cluster serving Secret cannot satisfy, so its
	// replacement needs a publicly trusted certificate for the Service's DNS name.
	HasCABundle bool
}

// Label renders the backend for descriptions.
func (b ControlPlaneBackend) Label() string {
	return b.Kind + " " + b.Name
}

// ControlPlaneBackends lists every in-cluster Service the API server calls, from the
// webhook configurations and APIServices in the snapshot, sorted by namespace,
// service, kind, and name. Webhooks with a URL and no Service, and local
// APIServices, are not backends.
func ControlPlaneBackends(snapshot Snapshot) []ControlPlaneBackend {
	var out []ControlPlaneBackend
	for _, cfg := range snapshot.Resources.MutatingWebhookConfigs {
		for _, hook := range cfg.Webhooks {
			svc := hook.ClientConfig.Service
			if svc == nil || svc.Namespace == "" || svc.Name == "" {
				continue
			}
			out = append(out, ControlPlaneBackend{
				Kind:             "MutatingWebhookConfiguration",
				Name:             cfg.Name + "/" + hook.Name,
				Namespace:        svc.Namespace,
				Service:          svc.Name,
				MatchesPodCreate: rulesMatchPodCreate(hook.Rules),
				HasCABundle:      len(hook.ClientConfig.CABundle) > 0,
			})
		}
	}
	for _, cfg := range snapshot.Resources.ValidatingWebhookConfigs {
		for _, hook := range cfg.Webhooks {
			svc := hook.ClientConfig.Service
			if svc == nil || svc.Namespace == "" || svc.Name == "" {
				continue
			}
			out = append(out, ControlPlaneBackend{
				Kind:        "ValidatingWebhookConfiguration",
				Name:        cfg.Name + "/" + hook.Name,
				Namespace:   svc.Namespace,
				Service:     svc.Name,
				HasCABundle: len(hook.ClientConfig.CABundle) > 0,
			})
		}
	}
	for _, api := range snapshot.Resources.APIServices {
		if !api.Backend() {
			continue
		}
		out = append(out, ControlPlaneBackend{
			Kind:        "APIService",
			Name:        api.Name,
			Namespace:   api.ServiceNamespace,
			Service:     api.ServiceName,
			Native:      BuiltinAPIGroups[api.Group],
			InsecureTLS: api.InsecureSkipTLSVerify,
			HasCABundle: api.HasCABundle,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		if out[i].Service != out[j].Service {
			return out[i].Service < out[j].Service
		}
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// rulesMatchPodCreate reports whether a webhook's rules cover pods CREATE in the
// core group.
func rulesMatchPodCreate(rules []admissionregistrationv1.RuleWithOperations) bool {
	for _, rule := range rules {
		ops, groups, resources := false, false, false
		for _, op := range rule.Operations {
			if op == admissionregistrationv1.Create || op == admissionregistrationv1.OperationAll {
				ops = true
			}
		}
		for _, g := range rule.APIGroups {
			if g == "" || g == "*" {
				groups = true
			}
		}
		for _, r := range rule.Resources {
			if r == "pods" || r == "*" || r == "*/*" {
				resources = true
			}
		}
		if ops && groups && resources {
			return true
		}
	}
	return false
}
