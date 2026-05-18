package network

import (
	"context"
	"strings"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestIMDSEmitsForNoEgressPolicy verifies the allow-all default fires the rule
// with reason=no-egress-policy when a workload has no selecting egress policy.
func TestIMDSEmitsForNoEgressPolicy(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Namespaces: []corev1.Namespace{
				{ObjectMeta: metav1.ObjectMeta{Name: "apps"}},
			},
			Deployments: []appsv1.Deployment{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "apps"},
					Spec: appsv1.DeploymentSpec{
						Template: corev1.PodTemplateSpec{
							ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "api"}},
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
	got := findRule(findings, "KUBE-NETPOL-IMDS-001")
	if got.RuleID == "" {
		t.Fatalf("expected KUBE-NETPOL-IMDS-001 to fire when no egress policy applies, got %v", ruleIDs(findings))
	}
	if !strings.Contains(string(got.Evidence), `"reason":"no-egress-policy"`) {
		t.Fatalf("expected reason=no-egress-policy, got %s", string(got.Evidence))
	}
	if got.Severity != models.SeverityHigh {
		t.Fatalf("expected severity HIGH, got %s", got.Severity)
	}
}

// TestIMDSEmitsForExplicitAllow asserts that an egress policy whose ipBlock contains
// the IMDS endpoint (e.g., 0.0.0.0/0) fires the rule with reason=explicit-allow.
func TestIMDSEmitsForExplicitAllow(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Namespaces: []corev1.Namespace{
				{ObjectMeta: metav1.ObjectMeta{Name: "apps"}},
			},
			Deployments: []appsv1.Deployment{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "apps"},
					Spec: appsv1.DeploymentSpec{
						Template: corev1.PodTemplateSpec{
							ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "api"}},
						},
					},
				},
			},
			NetworkPolicies: []networkingv1.NetworkPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "allow-everywhere", Namespace: "apps"},
					Spec: networkingv1.NetworkPolicySpec{
						PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
						PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
						Egress: []networkingv1.NetworkPolicyEgressRule{
							{To: []networkingv1.NetworkPolicyPeer{
								{IPBlock: &networkingv1.IPBlock{CIDR: "0.0.0.0/0"}},
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
	got := findRule(findings, "KUBE-NETPOL-IMDS-001")
	if got.RuleID == "" {
		t.Fatalf("expected KUBE-NETPOL-IMDS-001 to fire when ipBlock 0.0.0.0/0 allows IMDS, got %v", ruleIDs(findings))
	}
	if !strings.Contains(string(got.Evidence), `"reason":"explicit-allow"`) {
		t.Fatalf("expected reason=explicit-allow, got %s", string(got.Evidence))
	}
	if !strings.Contains(string(got.Evidence), `"offender_cidr":"0.0.0.0/0"`) {
		t.Fatalf("expected offender_cidr=0.0.0.0/0, got %s", string(got.Evidence))
	}
}

// TestIMDSSuppressesWhenExceptCarvesOutIMDS proves an operator who correctly adds
// `except: [169.254.169.254/32]` to a broad ipBlock is no longer flagged. This is
// the most important false-positive guard.
func TestIMDSSuppressesWhenExceptCarvesOutIMDS(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Namespaces: []corev1.Namespace{
				{ObjectMeta: metav1.ObjectMeta{Name: "apps"}},
			},
			Deployments: []appsv1.Deployment{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "apps"},
					Spec: appsv1.DeploymentSpec{
						Template: corev1.PodTemplateSpec{
							ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "api"}},
						},
					},
				},
			},
			NetworkPolicies: []networkingv1.NetworkPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "allow-internet-not-imds", Namespace: "apps"},
					Spec: networkingv1.NetworkPolicySpec{
						PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
						PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
						Egress: []networkingv1.NetworkPolicyEgressRule{
							{To: []networkingv1.NetworkPolicyPeer{
								{IPBlock: &networkingv1.IPBlock{CIDR: "0.0.0.0/0", Except: []string{"169.254.169.254/32"}}},
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
	if hasRule(findings, "KUBE-NETPOL-IMDS-001") {
		t.Fatalf("expected KUBE-NETPOL-IMDS-001 to STAY SILENT when ipBlock carves out IMDS, got %v", ruleIDs(findings))
	}
}

// TestIMDSSuppressesWhenEgressPolicyOmitsIMDS verifies the conservative semantic:
// a workload covered by an egress policy whose peers do not include IMDS is fine.
// (No fire.)
func TestIMDSSuppressesWhenEgressPolicyOmitsIMDS(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Namespaces: []corev1.Namespace{
				{ObjectMeta: metav1.ObjectMeta{Name: "apps"}},
			},
			Deployments: []appsv1.Deployment{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "apps"},
					Spec: appsv1.DeploymentSpec{
						Template: corev1.PodTemplateSpec{
							ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "api"}},
						},
					},
				},
			},
			NetworkPolicies: []networkingv1.NetworkPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "allow-10-only", Namespace: "apps"},
					Spec: networkingv1.NetworkPolicySpec{
						PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
						PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
						Egress: []networkingv1.NetworkPolicyEgressRule{
							{To: []networkingv1.NetworkPolicyPeer{
								{IPBlock: &networkingv1.IPBlock{CIDR: "10.0.0.0/8"}},
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
	if hasRule(findings, "KUBE-NETPOL-IMDS-001") {
		t.Fatalf("expected KUBE-NETPOL-IMDS-001 to STAY SILENT when egress policy does not include IMDS, got %v", ruleIDs(findings))
	}
}

// TestIMDSEmitsForLinkLocalRange covers the 169.254.0.0/16 case: any ipBlock that
// includes the link-local range admits IMDS and must fire.
func TestIMDSEmitsForLinkLocalRange(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Namespaces: []corev1.Namespace{
				{ObjectMeta: metav1.ObjectMeta{Name: "apps"}},
			},
			Deployments: []appsv1.Deployment{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "apps"},
					Spec: appsv1.DeploymentSpec{
						Template: corev1.PodTemplateSpec{
							ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "api"}},
						},
					},
				},
			},
			NetworkPolicies: []networkingv1.NetworkPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "link-local", Namespace: "apps"},
					Spec: networkingv1.NetworkPolicySpec{
						PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
						PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
						Egress: []networkingv1.NetworkPolicyEgressRule{
							{To: []networkingv1.NetworkPolicyPeer{
								{IPBlock: &networkingv1.IPBlock{CIDR: "169.254.0.0/16"}},
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
	if !hasRule(findings, "KUBE-NETPOL-IMDS-001") {
		t.Fatalf("expected KUBE-NETPOL-IMDS-001 to fire on link-local 169.254.0.0/16, got %v", ruleIDs(findings))
	}
}

// TestIMDSEmitsForHostNetworkWithDenyAllEgress proves the most important
// false-negative fix in this slot: a hostNetwork pod in a namespace whose
// NetworkPolicy denies egress to everything STILL fires the rule because
// host-network pods ride the node netns and NetPol does not apply to them.
// Before this guard, kubesplaining would report "IMDS unreachable" while the
// pod was effectively one curl away from the node IAM role.
func TestIMDSEmitsForHostNetworkWithDenyAllEgress(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Namespaces: []corev1.Namespace{
				{ObjectMeta: metav1.ObjectMeta{Name: "monitoring"}},
			},
			DaemonSets: []appsv1.DaemonSet{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "node-exporter", Namespace: "monitoring"},
					Spec: appsv1.DaemonSetSpec{
						Template: corev1.PodTemplateSpec{
							ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "node-exporter"}},
							Spec:       corev1.PodSpec{HostNetwork: true},
						},
					},
				},
			},
			NetworkPolicies: []networkingv1.NetworkPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "default-deny-egress", Namespace: "monitoring"},
					Spec: networkingv1.NetworkPolicySpec{
						PodSelector: metav1.LabelSelector{},
						PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
					},
				},
			},
		},
	}

	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	got := findRule(findings, "KUBE-NETPOL-IMDS-001")
	if got.RuleID == "" {
		t.Fatalf("expected KUBE-NETPOL-IMDS-001 to fire on hostNetwork DaemonSet despite deny-all egress, got %v", ruleIDs(findings))
	}
	if !strings.Contains(string(got.Evidence), `"reason":"host-network"`) {
		t.Fatalf("expected reason=host-network for hostNetwork workload, got %s", string(got.Evidence))
	}
}

// TestIMDSReachableReturnsHostNetworkReasonViaPublicAPI guards the exported
// IMDSReachable wrapper that the cloud module calls into. When the wrapper is
// invoked with hostNetwork=true, the reason MUST be "host-network" so the
// IMDS-pivot rule and downstream consumers do not silently fall back to one
// of the NetPol-flavored reasons.
func TestIMDSReachableReturnsHostNetworkReasonViaPublicAPI(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Namespaces: []corev1.Namespace{
				{ObjectMeta: metav1.ObjectMeta{Name: "monitoring"}},
			},
			NetworkPolicies: []networkingv1.NetworkPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "default-deny-egress", Namespace: "monitoring"},
					Spec: networkingv1.NetworkPolicySpec{
						PodSelector: metav1.LabelSelector{},
						PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
					},
				},
			},
		},
	}

	reachable, reason, _, _ := IMDSReachable(snapshot, "Pod", "node-exporter", "monitoring", map[string]string{"app": "node-exporter"}, true)
	if !reachable {
		t.Fatalf("expected IMDSReachable to report reachable=true for hostNetwork pod, got reachable=false")
	}
	if reason != "host-network" {
		t.Fatalf("expected reason=host-network, got %q", reason)
	}
}

// TestIMDSSkipsSystemNamespaces verifies that system namespaces (kube-system,
// kube-public, kube-node-lease) are NOT scanned for IMDS reachability. Control
// plane components routinely need IMDS access and would otherwise drown the
// scan in noise.
func TestIMDSSkipsSystemNamespaces(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			Namespaces: []corev1.Namespace{
				{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}},
			},
			Deployments: []appsv1.Deployment{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "metrics-server", Namespace: "kube-system"},
					Spec: appsv1.DeploymentSpec{
						Template: corev1.PodTemplateSpec{
							ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "metrics-server"}},
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
	if hasRule(findings, "KUBE-NETPOL-IMDS-001") {
		t.Fatalf("expected KUBE-NETPOL-IMDS-001 NOT to fire on kube-system workloads, got %v", ruleIDs(findings))
	}
}
