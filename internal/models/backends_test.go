package models

import (
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestAPIServiceSummaryFromObject(t *testing.T) {
	raw := map[string]any{
		"apiVersion": "apiregistration.k8s.io/v1",
		"kind":       "APIService",
		"metadata": map[string]any{
			"name":   "v1beta1.metrics.k8s.io",
			"labels": map[string]any{"kube-aggregator.kubernetes.io/automanaged": "onstart"},
		},
		"spec": map[string]any{
			"group":                 "metrics.k8s.io",
			"version":               "v1beta1",
			"insecureSkipTLSVerify": true,
			"caBundle":              "Zm9v",
			"service":               map[string]any{"namespace": "kube-system", "name": "metrics-server", "port": int64(443)},
		},
	}
	got := APIServiceSummaryFromObject(raw)
	want := APIServiceSummary{
		Name: "v1beta1.metrics.k8s.io", Group: "metrics.k8s.io", Version: "v1beta1",
		ServiceNamespace: "kube-system", ServiceName: "metrics-server", ServicePort: 443,
		InsecureSkipTLSVerify: true, HasCABundle: true, Automanaged: "onstart",
	}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	if !got.Backend() {
		t.Fatal("expected Backend() true")
	}

	local := APIServiceSummaryFromObject(map[string]any{
		"metadata": map[string]any{"name": "v1."},
		"spec":     map[string]any{"group": "", "version": "v1"},
	})
	if local.Backend() {
		t.Fatal("local APIService must not be a backend")
	}
	// Name fallback when spec is absent.
	fallback := APIServiceSummaryFromObject(map[string]any{"metadata": map[string]any{"name": "v1.apps"}})
	if fallback.Version != "v1" || fallback.Group != "apps" {
		t.Fatalf("name fallback failed: %+v", fallback)
	}
}

func TestControlPlaneBackends(t *testing.T) {
	ignore := admissionregistrationv1.Ignore
	snapshot := Snapshot{Resources: SnapshotResources{
		MutatingWebhookConfigs: []admissionregistrationv1.MutatingWebhookConfiguration{{
			ObjectMeta: metav1.ObjectMeta{Name: "mwh"},
			Webhooks: []admissionregistrationv1.MutatingWebhook{
				{
					Name:         "pods.example.com",
					ClientConfig: admissionregistrationv1.WebhookClientConfig{Service: &admissionregistrationv1.ServiceReference{Namespace: "hooks", Name: "injector"}, CABundle: []byte("x")},
					Rules: []admissionregistrationv1.RuleWithOperations{{
						Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
						Rule:       admissionregistrationv1.Rule{APIGroups: []string{"*"}, Resources: []string{"*"}},
					}},
					FailurePolicy: &ignore,
				},
				{
					Name:         "url.example.com",
					ClientConfig: admissionregistrationv1.WebhookClientConfig{URL: strPtr("https://example.com")},
				},
			},
		}},
		ValidatingWebhookConfigs: []admissionregistrationv1.ValidatingWebhookConfiguration{{
			ObjectMeta: metav1.ObjectMeta{Name: "vwh"},
			Webhooks: []admissionregistrationv1.ValidatingWebhook{{
				Name:         "validate.example.com",
				ClientConfig: admissionregistrationv1.WebhookClientConfig{Service: &admissionregistrationv1.ServiceReference{Namespace: "hooks", Name: "validator"}},
			}},
		}},
		APIServices: []APIServiceSummary{
			{Name: "v1.apps", Group: "apps", Version: "v1", Automanaged: "onstart"},
			{Name: "v1beta1.metrics.k8s.io", Group: "metrics.k8s.io", Version: "v1beta1", ServiceNamespace: "metrics", ServiceName: "metrics-server", InsecureSkipTLSVerify: true},
			{Name: "v1.authentication.k8s.io", Group: "authentication.k8s.io", Version: "v1", ServiceNamespace: "evil", ServiceName: "authn", HasCABundle: true},
		},
	}}
	got := ControlPlaneBackends(snapshot)
	if len(got) != 4 {
		t.Fatalf("expected 4 backends (url webhook and local APIService excluded), got %d: %+v", len(got), got)
	}
	// Sorted by namespace: evil, hooks (injector, validator), metrics.
	if got[0].Namespace != "evil" || !got[0].Native || got[0].Kind != "APIService" {
		t.Fatalf("expected native APIService backend first, got %+v", got[0])
	}
	if got[1].Service != "injector" || !got[1].MatchesPodCreate || !got[1].HasCABundle {
		t.Fatalf("mutating webhook backend wrong: %+v", got[1])
	}
	if got[2].Service != "validator" || got[2].MatchesPodCreate || got[2].HasCABundle {
		t.Fatalf("validating webhook backend wrong: %+v", got[2])
	}
	if got[3].Namespace != "metrics" || !got[3].InsecureTLS || got[3].Native {
		t.Fatalf("aggregated APIService backend wrong: %+v", got[3])
	}
	if got[1].Label() != "MutatingWebhookConfiguration mwh/pods.example.com" {
		t.Fatalf("unexpected label %q", got[1].Label())
	}
}

func strPtr(s string) *string { return &s }
