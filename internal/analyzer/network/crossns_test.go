package network

import (
	"context"
	"strings"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestCrossNSEmitsForSensitiveIngress verifies that a NetworkPolicy in a tenant
// namespace that admits ingress from kube-system surfaces a KUBE-NETPOL-CROSSNS-001
// finding pointing at the (kube-system -> tenant) pair.
func TestCrossNSEmitsForSensitiveIngress(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Namespaces: []corev1.Namespace{
				{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", Labels: map[string]string{"kubernetes.io/metadata.name": "kube-system"}}},
				{ObjectMeta: metav1.ObjectMeta{Name: "team-a", Labels: map[string]string{"kubernetes.io/metadata.name": "team-a"}}},
			},
			NetworkPolicies: []networkingv1.NetworkPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "allow-from-kube-system", Namespace: "team-a"},
					Spec: networkingv1.NetworkPolicySpec{
						PodSelector: metav1.LabelSelector{},
						Ingress: []networkingv1.NetworkPolicyIngressRule{
							{
								From: []networkingv1.NetworkPolicyPeer{
									{NamespaceSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kube-system"},
									}},
								},
							},
						},
					},
				},
			},
		},
	}

	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	if !hasRule(findings, "KUBE-NETPOL-CROSSNS-001") {
		t.Fatalf("expected KUBE-NETPOL-CROSSNS-001 to fire when policy admits ingress from kube-system, got %v", ruleIDs(findings))
	}

	got := findRule(findings, "KUBE-NETPOL-CROSSNS-001")
	if !strings.Contains(string(got.Evidence), `"source_namespace":"kube-system"`) {
		t.Fatalf("expected source_namespace=kube-system in evidence, got %s", string(got.Evidence))
	}
	if !strings.Contains(string(got.Evidence), `"target_namespace":"team-a"`) {
		t.Fatalf("expected target_namespace=team-a in evidence, got %s", string(got.Evidence))
	}
	if !strings.Contains(string(got.Evidence), `"direction":"ingress"`) {
		t.Fatalf("expected direction=ingress in evidence, got %s", string(got.Evidence))
	}
}

// TestCrossNSEmitsForWildcardSelector covers the namespaceSelector:{} wildcard
// case (matches every namespace) which must always fire because the wildcard
// pierces every namespace boundary including the sensitive ones.
func TestCrossNSEmitsForWildcardSelector(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Namespaces: []corev1.Namespace{
				{ObjectMeta: metav1.ObjectMeta{Name: "team-a"}},
			},
			NetworkPolicies: []networkingv1.NetworkPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "open-ingress", Namespace: "team-a"},
					Spec: networkingv1.NetworkPolicySpec{
						PodSelector: metav1.LabelSelector{},
						Ingress: []networkingv1.NetworkPolicyIngressRule{
							{From: []networkingv1.NetworkPolicyPeer{{NamespaceSelector: &metav1.LabelSelector{}}}},
						},
					},
				},
			},
		},
	}

	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	if !hasRule(findings, "KUBE-NETPOL-CROSSNS-001") {
		t.Fatalf("expected KUBE-NETPOL-CROSSNS-001 to fire on wildcard namespaceSelector, got %v", ruleIDs(findings))
	}
	got := findRule(findings, "KUBE-NETPOL-CROSSNS-001")
	if !strings.Contains(string(got.Evidence), `"source_namespace":"*"`) {
		t.Fatalf("expected source_namespace=* for wildcard, got %s", string(got.Evidence))
	}
}

// TestCrossNSEmitsForEgress mirrors the ingress case for egress: a tenant policy
// whose egress allows traffic into kube-system surfaces a finding with
// direction=egress and source=tenant, target=kube-system.
func TestCrossNSEmitsForEgress(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Namespaces: []corev1.Namespace{
				{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", Labels: map[string]string{"kubernetes.io/metadata.name": "kube-system"}}},
				{ObjectMeta: metav1.ObjectMeta{Name: "team-a", Labels: map[string]string{"kubernetes.io/metadata.name": "team-a"}}},
			},
			NetworkPolicies: []networkingv1.NetworkPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "egress-to-kube-system", Namespace: "team-a"},
					Spec: networkingv1.NetworkPolicySpec{
						PodSelector: metav1.LabelSelector{},
						PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
						Egress: []networkingv1.NetworkPolicyEgressRule{
							{To: []networkingv1.NetworkPolicyPeer{
								{NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kube-system"}}},
							}},
						},
					},
				},
			},
		},
	}

	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	got := findRule(findings, "KUBE-NETPOL-CROSSNS-001")
	if got.RuleID == "" {
		t.Fatalf("expected KUBE-NETPOL-CROSSNS-001 to fire on egress to kube-system, got %v", ruleIDs(findings))
	}
	if !strings.Contains(string(got.Evidence), `"direction":"egress"`) {
		t.Fatalf("expected direction=egress for egress rule, got %s", string(got.Evidence))
	}
	if !strings.Contains(string(got.Evidence), `"source_namespace":"team-a"`) {
		t.Fatalf("expected source_namespace=team-a (policy namespace) for egress rule, got %s", string(got.Evidence))
	}
	if !strings.Contains(string(got.Evidence), `"target_namespace":"kube-system"`) {
		t.Fatalf("expected target_namespace=kube-system for egress rule, got %s", string(got.Evidence))
	}
}

// TestCrossNSSuppressesInsensitivePair makes sure a cross-namespace allow rule
// between two non-sensitive tenant namespaces does NOT fire (this is the noisy
// false-positive case the rule is designed to avoid).
func TestCrossNSSuppressesInsensitivePair(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Namespaces: []corev1.Namespace{
				{ObjectMeta: metav1.ObjectMeta{Name: "team-a", Labels: map[string]string{"tenancy": "a"}}},
				{ObjectMeta: metav1.ObjectMeta{Name: "team-b", Labels: map[string]string{"tenancy": "b"}}},
			},
			NetworkPolicies: []networkingv1.NetworkPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "team-a-to-team-b", Namespace: "team-a"},
					Spec: networkingv1.NetworkPolicySpec{
						PodSelector: metav1.LabelSelector{},
						PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
						Egress: []networkingv1.NetworkPolicyEgressRule{
							{To: []networkingv1.NetworkPolicyPeer{
								{NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"tenancy": "b"}}},
							}},
						},
					},
				},
			},
		},
	}

	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if hasRule(findings, "KUBE-NETPOL-CROSSNS-001") {
		t.Fatalf("expected KUBE-NETPOL-CROSSNS-001 to STAY SILENT for tenant<->tenant cross-NS rule, got %v", ruleIDs(findings))
	}
}

// TestCrossNSIgnoresSameNamespace covers the negative case where a namespaceSelector
// matches the policy's own namespace; that's not a cross-NS edge and must not fire.
func TestCrossNSIgnoresSameNamespace(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Namespaces: []corev1.Namespace{
				{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", Labels: map[string]string{"name": "kube-system"}}},
			},
			NetworkPolicies: []networkingv1.NetworkPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "self-ingress", Namespace: "kube-system"},
					Spec: networkingv1.NetworkPolicySpec{
						PodSelector: metav1.LabelSelector{},
						Ingress: []networkingv1.NetworkPolicyIngressRule{
							{From: []networkingv1.NetworkPolicyPeer{
								{NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"name": "kube-system"}}},
							}},
						},
					},
				},
			},
		},
	}

	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if hasRule(findings, "KUBE-NETPOL-CROSSNS-001") {
		t.Fatalf("expected KUBE-NETPOL-CROSSNS-001 NOT to fire for same-namespace selector, got %v", ruleIDs(findings))
	}
}

// hasRule reports whether any finding has the given RuleID.
func hasRule(findings []models.Finding, ruleID string) bool {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

// findRule returns the first finding with the given RuleID, or zero value when absent.
func findRule(findings []models.Finding, ruleID string) models.Finding {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return f
		}
	}
	return models.Finding{}
}

// ruleIDs is a small helper used in test failure messages.
func ruleIDs(findings []models.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.RuleID)
	}
	return out
}
