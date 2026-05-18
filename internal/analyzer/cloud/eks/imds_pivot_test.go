package eks

import (
	"strings"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Test table for KUBE-CLOUD-IMDS-PIVOT-001. The rule combines three signals
// (IMDS reachability via network.IMDSReachable, IRSA annotation presence on the
// SA, Fargate-vs-EC2 scheduling) plus the EKS provider gate. Each case toggles
// exactly one signal so failures point at the responsible branch.
func TestAnalyzeIMDSPivot(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name           string
		snapshot       models.Snapshot
		wantFires      bool
		wantReason     string // checked only when wantFires == true
		wantResource   string // "Kind/ns/name" of the resource the finding points at
		wantResourceNS string
	}{
		{
			name:           "reachable pod, no IRSA, eks, non-Fargate node fires",
			snapshot:       snapEKSPodReachableNoIRSA("ec2-node-1", false),
			wantFires:      true,
			wantReason:     "no-egress-policy",
			wantResource:   "Pod",
			wantResourceNS: "apps",
		},
		{
			name:      "reachable pod, IRSA-bound SA, eks stays silent",
			snapshot:  snapEKSPodReachableWithIRSA(),
			wantFires: false,
		},
		{
			name:      "reachable pod scheduled to Fargate node stays silent",
			snapshot:  snapEKSPodReachableNoIRSA("fargate-node-1", true),
			wantFires: false,
		},
		{
			name:      "unreachable pod (egress-deny NetworkPolicy) stays silent",
			snapshot:  snapEKSPodUnreachable(),
			wantFires: false,
		},
		{
			name:      "non-eks provider (gke) stays silent",
			snapshot:  snapNonEKSPodReachable(),
			wantFires: false,
		},
		{
			name:           "reachable pod with explicit-allow 0.0.0.0/0 egress fires with explicit-allow reason",
			snapshot:       snapEKSPodExplicitAllowEgress(),
			wantFires:      true,
			wantReason:     "explicit-allow",
			wantResource:   "Pod",
			wantResourceNS: "apps",
		},
		{
			name:           "Deployment with controlled pods emits ONE finding scoped to the Deployment",
			snapshot:       snapEKSDeploymentReachableNoIRSA(),
			wantFires:      true,
			wantReason:     "no-egress-policy",
			wantResource:   "Deployment",
			wantResourceNS: "apps",
		},
		{
			name:           "hostNetwork pod under deny-all egress fires with host-network reason",
			snapshot:       snapEKSHostNetworkDaemonSetDenyAll(),
			wantFires:      true,
			wantReason:     "host-network",
			wantResource:   "DaemonSet",
			wantResourceNS: "monitoring",
		},
		{
			name:      "pod scheduled to node with Fargate ProviderID stays silent even when label says ec2",
			snapshot:  snapEKSPodFargateProviderIDOnly(),
			wantFires: false,
		},
		{
			name:           "pod scheduled to EC2 ProviderID with attacker-spoofed Fargate LABEL still fires",
			snapshot:       snapEKSPodFargateLabelSpoofedEC2ProviderID(),
			wantFires:      true,
			wantReason:     "no-egress-policy",
			wantResource:   "Pod",
			wantResourceNS: "apps",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			findings := AnalyzeIMDSPivot(tc.snapshot)
			matches := filterByRule(findings, "KUBE-CLOUD-IMDS-PIVOT-001")
			if tc.wantFires {
				if len(matches) == 0 {
					t.Fatalf("expected KUBE-CLOUD-IMDS-PIVOT-001 to fire; got %d findings (all rule IDs: %v)", len(findings), ruleIDsOf(findings))
				}
				if len(matches) != 1 {
					t.Fatalf("expected exactly 1 KUBE-CLOUD-IMDS-PIVOT-001 finding, got %d (resources: %v)", len(matches), resourcesOf(matches))
				}
				f := matches[0]
				if !strings.Contains(string(f.Evidence), `"reason":"`+tc.wantReason+`"`) {
					t.Fatalf("expected reason=%q in evidence, got %s", tc.wantReason, string(f.Evidence))
				}
				if tc.wantResource != "" && f.Resource.Kind != tc.wantResource {
					t.Fatalf("expected resource kind=%s, got %s", tc.wantResource, f.Resource.Kind)
				}
				if tc.wantResourceNS != "" && f.Resource.Namespace != tc.wantResourceNS {
					t.Fatalf("expected resource namespace=%s, got %s", tc.wantResourceNS, f.Resource.Namespace)
				}
				if f.Severity != models.SeverityHigh {
					t.Fatalf("expected severity HIGH, got %s", f.Severity)
				}
				if f.Subject == nil || f.Subject.Kind != "ServiceAccount" {
					t.Fatalf("expected Subject.Kind=ServiceAccount, got %+v", f.Subject)
				}
				if !hasTag(f, "provider:eks") {
					t.Fatalf("expected tag provider:eks, got %v", f.Tags)
				}
				if !hasTag(f, "check:imdsPivot") {
					t.Fatalf("expected tag check:imdsPivot, got %v", f.Tags)
				}
			} else {
				if len(matches) != 0 {
					t.Fatalf("expected KUBE-CLOUD-IMDS-PIVOT-001 to stay silent, got %d (resources: %v)", len(matches), resourcesOf(matches))
				}
			}
		})
	}
}

// --- snapshot fixtures -------------------------------------------------------

// snapEKSPodReachableNoIRSA builds a snapshot with a single pod that has no
// selecting egress policy (so network.IMDSReachable returns reachable, reason=
// no-egress-policy) and a SA without the IRSA annotation. nodeName controls
// scheduling, isFargate marks the node as Fargate-backed.
func snapEKSPodReachableNoIRSA(nodeName string, isFargate bool) models.Snapshot {
	snap := models.NewSnapshot()
	snap.Metadata.CloudProvider = "eks"
	snap.Resources.Namespaces = []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "apps"}}}
	snap.Resources.ServiceAccounts = []corev1.ServiceAccount{
		{ObjectMeta: metav1.ObjectMeta{Name: "api-sa", Namespace: "apps"}},
	}
	snap.Resources.Pods = []corev1.Pod{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "apps", Labels: map[string]string{"app": "api"}},
			Spec:       corev1.PodSpec{ServiceAccountName: "api-sa", NodeName: nodeName},
		},
	}
	nodeLabels := map[string]string{}
	if isFargate {
		nodeLabels[fargateComputeTypeLabel] = fargateComputeTypeValue
	}
	snap.Resources.Nodes = []corev1.Node{
		{ObjectMeta: metav1.ObjectMeta{Name: nodeName, Labels: nodeLabels}},
	}
	return snap
}

// snapEKSPodReachableWithIRSA mirrors the reachable-pod case but adds the
// eks.amazonaws.com/role-arn annotation to the SA, which must suppress the
// finding (the IRSA short-circuit means STS, not node IAM).
func snapEKSPodReachableWithIRSA() models.Snapshot {
	snap := snapEKSPodReachableNoIRSA("ec2-node-1", false)
	snap.Resources.ServiceAccounts = []corev1.ServiceAccount{
		{ObjectMeta: metav1.ObjectMeta{
			Name:        "api-sa",
			Namespace:   "apps",
			Annotations: map[string]string{irsaAnnotation: "arn:aws:iam::123456789012:role/api"},
		}},
	}
	return snap
}

// snapEKSPodUnreachable applies an egress NetworkPolicy that selects the pod
// but allows only 10.0.0.0/8, so the network module reports the pod as not
// reachable.
func snapEKSPodUnreachable() models.Snapshot {
	snap := snapEKSPodReachableNoIRSA("ec2-node-1", false)
	snap.Resources.NetworkPolicies = []networkingv1.NetworkPolicy{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "allow-internal-only", Namespace: "apps"},
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
	}
	return snap
}

// snapNonEKSPodReachable builds the same shape as the reachable-no-IRSA case
// but flips the provider to gke. The rule must not fire on non-EKS providers.
func snapNonEKSPodReachable() models.Snapshot {
	snap := snapEKSPodReachableNoIRSA("ec2-node-1", false)
	snap.Metadata.CloudProvider = "gke"
	return snap
}

// snapEKSPodExplicitAllowEgress applies an egress policy that includes
// 0.0.0.0/0 in its ipBlock, which network.IMDSReachable reports as reachable
// with reason=explicit-allow.
func snapEKSPodExplicitAllowEgress() models.Snapshot {
	snap := snapEKSPodReachableNoIRSA("ec2-node-1", false)
	snap.Resources.NetworkPolicies = []networkingv1.NetworkPolicy{
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
	}
	return snap
}

// snapEKSDeploymentReachableNoIRSA builds a Deployment with two controlled
// replica pods (owner.controller=true). The analyzer must skip the controlled
// pods and emit exactly one finding scoped to the Deployment.
func snapEKSDeploymentReachableNoIRSA() models.Snapshot {
	snap := models.NewSnapshot()
	snap.Metadata.CloudProvider = "eks"
	snap.Resources.Namespaces = []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "apps"}}}
	snap.Resources.ServiceAccounts = []corev1.ServiceAccount{
		{ObjectMeta: metav1.ObjectMeta{Name: "api-sa", Namespace: "apps"}},
	}
	snap.Resources.Deployments = []appsv1.Deployment{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "apps"},
			Spec: appsv1.DeploymentSpec{
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "api"}},
					Spec:       corev1.PodSpec{ServiceAccountName: "api-sa"},
				},
			},
		},
	}
	truthy := true
	snap.Resources.Pods = []corev1.Pod{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "api-abc-1",
				Namespace: "apps",
				Labels:    map[string]string{"app": "api"},
				OwnerReferences: []metav1.OwnerReference{
					{Controller: &truthy, Kind: "ReplicaSet", Name: "api-abc"},
				},
			},
			Spec: corev1.PodSpec{ServiceAccountName: "api-sa", NodeName: "ec2-node-1"},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "api-abc-2",
				Namespace: "apps",
				Labels:    map[string]string{"app": "api"},
				OwnerReferences: []metav1.OwnerReference{
					{Controller: &truthy, Kind: "ReplicaSet", Name: "api-abc"},
				},
			},
			Spec: corev1.PodSpec{ServiceAccountName: "api-sa", NodeName: "ec2-node-1"},
		},
	}
	snap.Resources.Nodes = []corev1.Node{
		{ObjectMeta: metav1.ObjectMeta{Name: "ec2-node-1"}},
	}
	return snap
}

// snapEKSHostNetworkDaemonSetDenyAll proves the hostNetwork bypass: a DaemonSet
// with hostNetwork: true sits in a namespace where a default-deny-egress
// NetworkPolicy is in place. Pre-fix, the rule was silent because IMDSReachable
// trusted the NetPol verdict. Post-fix, the rule fires with reason=host-network
// because NetPol does not gate host-network pods.
func snapEKSHostNetworkDaemonSetDenyAll() models.Snapshot {
	snap := models.NewSnapshot()
	snap.Metadata.CloudProvider = "eks"
	snap.Resources.Namespaces = []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "monitoring"}}}
	snap.Resources.ServiceAccounts = []corev1.ServiceAccount{
		{ObjectMeta: metav1.ObjectMeta{Name: "node-exporter", Namespace: "monitoring"}},
	}
	snap.Resources.DaemonSets = []appsv1.DaemonSet{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "node-exporter", Namespace: "monitoring"},
			Spec: appsv1.DaemonSetSpec{
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "node-exporter"}},
					Spec: corev1.PodSpec{
						ServiceAccountName: "node-exporter",
						HostNetwork:        true,
					},
				},
			},
		},
	}
	snap.Resources.NetworkPolicies = []networkingv1.NetworkPolicy{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "default-deny-egress", Namespace: "monitoring"},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			},
		},
	}
	snap.Resources.Nodes = []corev1.Node{
		{ObjectMeta: metav1.ObjectMeta{Name: "ec2-node-1"}, Spec: corev1.NodeSpec{ProviderID: "aws:///us-west-2a/i-0abc"}},
	}
	return snap
}

// snapEKSPodFargateProviderIDOnly proves the trustworthy Fargate signal: a
// pod scheduled to a node whose Spec.ProviderID starts with aws:///fargate/
// must be carved out, even when the eks.amazonaws.com/compute-type label is
// absent (or, here, set to "ec2"). The rule must NOT fire.
func snapEKSPodFargateProviderIDOnly() models.Snapshot {
	snap := snapEKSPodReachableNoIRSA("fargate-node-1", false)
	snap.Resources.Nodes = []corev1.Node{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "fargate-node-1",
				Labels: map[string]string{fargateComputeTypeLabel: "ec2"},
			},
			Spec: corev1.NodeSpec{ProviderID: "aws:///fargate/fa-0123456789abcdef0"},
		},
	}
	return snap
}

// snapEKSPodFargateLabelSpoofedEC2ProviderID covers the attacker-evasion case:
// an EC2 node has been mis-labeled with eks.amazonaws.com/compute-type=fargate
// (which any nodes/patch holder can do), but its providerID still reveals
// aws:///<az>/<instance-id>. The rule must fire because the providerID is the
// trustworthy signal and the label is ignored in favor of it. This is the
// blast-radius reduction the providerID change buys.
func snapEKSPodFargateLabelSpoofedEC2ProviderID() models.Snapshot {
	snap := snapEKSPodReachableNoIRSA("ec2-node-1", false)
	snap.Resources.Nodes = []corev1.Node{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "ec2-node-1",
				Labels: map[string]string{fargateComputeTypeLabel: fargateComputeTypeValue},
			},
			Spec: corev1.NodeSpec{ProviderID: "aws:///us-west-2a/i-0123456789abcdef0"},
		},
	}
	return snap
}

// --- helpers -----------------------------------------------------------------

// filterByRule returns the subset of findings with the given RuleID.
func filterByRule(findings []models.Finding, ruleID string) []models.Finding {
	out := make([]models.Finding, 0)
	for _, f := range findings {
		if f.RuleID == ruleID {
			out = append(out, f)
		}
	}
	return out
}

// ruleIDsOf returns the rule IDs of every finding, for failure messages.
func ruleIDsOf(findings []models.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.RuleID)
	}
	return out
}

// resourcesOf returns "Kind/ns/name" for each finding's resource, for failure messages.
func resourcesOf(findings []models.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		if f.Resource == nil {
			out = append(out, "<nil>")
			continue
		}
		out = append(out, f.Resource.Kind+"/"+f.Resource.Namespace+"/"+f.Resource.Name)
	}
	return out
}

// hasTag reports whether the finding carries the given tag.
func hasTag(f models.Finding, tag string) bool {
	for _, t := range f.Tags {
		if t == tag {
			return true
		}
	}
	return false
}
