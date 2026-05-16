package remediation

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// makeNetworkFinding builds a minimal network-style Finding suitable for
// feeding into ForNetwork. We keep this distinct from podsec_test.go's
// makeFinding because the network analyzer attaches network-policy-specific
// metadata (Category, Tags) the podsec helper does not, and so the test
// reads more naturally next to its assertions.
func makeNetworkFinding(t *testing.T, ruleID, kind, namespace, name string, evidence map[string]any) models.Finding {
	t.Helper()
	body, err := json.Marshal(evidence)
	if err != nil {
		t.Fatalf("marshal evidence: %v", err)
	}
	return models.Finding{
		ID:       ruleID + ":" + kind + ":" + namespace + ":" + name,
		RuleID:   ruleID,
		Severity: models.SeverityMedium,
		Resource: &models.ResourceRef{
			Kind:      kind,
			Namespace: namespace,
			Name:      name,
		},
		Evidence: body,
	}
}

// TestForNetworkUnknownRuleReturnsNil documents that the dispatcher is closed
// over the seven network rules; anything else gets nil so callers fall back
// to the prose Remediation field.
func TestForNetworkUnknownRuleReturnsNil(t *testing.T) {
	t.Parallel()
	finding := makeNetworkFinding(t, "KUBE-RBAC-OVERBROAD-001", "ClusterRole", "", "admin", nil)
	if hint := ForNetwork("KUBE-RBAC-OVERBROAD-001", finding); hint != nil {
		t.Errorf("expected nil hint for non-network rule, got %+v", hint)
	}
}

// TestForNetworkNilResourceReturnsNil exercises the defensive branch in
// patchTargetFromFinding shared with the podsec generator.
func TestForNetworkNilResourceReturnsNil(t *testing.T) {
	t.Parallel()
	f := models.Finding{RuleID: "KUBE-NETPOL-COVERAGE-001"}
	if hint := ForNetwork("KUBE-NETPOL-COVERAGE-001", f); hint != nil {
		t.Errorf("expected nil hint for finding without Resource, got %+v", hint)
	}
}

// TestForNetworkCoverage001 covers the "no policies in namespace" case. The
// hint must carry a heredoc that applies a default-deny NetworkPolicy and a
// Kyverno policy that audits namespaces missing NetworkPolicies.
func TestForNetworkCoverage001(t *testing.T) {
	t.Parallel()
	finding := makeNetworkFinding(t, "KUBE-NETPOL-COVERAGE-001", "Namespace", "team-a", "team-a", map[string]any{
		"namespace": "team-a",
	})
	hint := ForNetwork("KUBE-NETPOL-COVERAGE-001", finding)
	if hint == nil || hint.Patch == nil {
		t.Fatalf("expected non-nil hint and patch, got %+v", hint)
	}
	if hint.Patch.Target.Kind != "Namespace" {
		t.Errorf("Patch.Target.Kind = %q, want Namespace", hint.Patch.Target.Kind)
	}
	if hint.Patch.Target.Name != "team-a" {
		t.Errorf("Patch.Target.Name = %q, want team-a", hint.Patch.Target.Name)
	}
	if len(hint.Patch.Body) != 0 {
		t.Errorf("Patch.Body should be empty for command-only hint, got %s", string(hint.Patch.Body))
	}
	for _, want := range []string{
		"kubectl apply",
		"kind: NetworkPolicy",
		"name: default-deny",
		"podSelector: {}",
		"policyTypes:",
	} {
		if !strings.Contains(hint.Patch.Command, want) {
			t.Errorf("Patch.Command missing %q\ncommand: %s", want, hint.Patch.Command)
		}
	}
	if hint.KyvernoPolicy == "" {
		t.Fatal("KyvernoPolicy should be populated for COVERAGE-001")
	}
	if !strings.Contains(hint.KyvernoPolicy, "require-networkpolicy-per-namespace") {
		t.Errorf("KyvernoPolicy missing expected ClusterPolicy name\npolicy:\n%s", hint.KyvernoPolicy)
	}
}

// TestForNetworkCoverage002WithLabels exercises the happy path where the
// analyzer evidence carries the workload's labels: we should get a
// strategic-merge body referencing the labels via spec.podSelector.matchLabels.
func TestForNetworkCoverage002WithLabels(t *testing.T) {
	t.Parallel()
	finding := makeNetworkFinding(t, "KUBE-NETPOL-COVERAGE-002", "Deployment", "apps", "api", map[string]any{
		"labels": map[string]any{"app": "api", "tier": "backend"},
	})
	hint := ForNetwork("KUBE-NETPOL-COVERAGE-002", finding)
	if hint == nil || hint.Patch == nil {
		t.Fatalf("expected non-nil hint and patch, got %+v", hint)
	}
	if hint.Patch.Type != "strategic" {
		t.Errorf("Patch.Type = %q, want strategic", hint.Patch.Type)
	}
	if hint.Patch.Target.Kind != "NetworkPolicy" {
		t.Errorf("Patch.Target.Kind = %q, want NetworkPolicy", hint.Patch.Target.Kind)
	}
	if hint.Patch.Target.Namespace != "apps" {
		t.Errorf("Patch.Target.Namespace = %q, want apps", hint.Patch.Target.Namespace)
	}
	if hint.Patch.Target.APIVersion != "networking.k8s.io/v1" {
		t.Errorf("Patch.Target.APIVersion = %q, want networking.k8s.io/v1", hint.Patch.Target.APIVersion)
	}
	var decoded map[string]any
	if err := json.Unmarshal(hint.Patch.Body, &decoded); err != nil {
		t.Fatalf("Patch.Body parse: %v", err)
	}
	spec, _ := decoded["spec"].(map[string]any)
	podSelector, _ := spec["podSelector"].(map[string]any)
	matchLabels, _ := podSelector["matchLabels"].(map[string]any)
	if matchLabels["app"] != "api" || matchLabels["tier"] != "backend" {
		t.Errorf("matchLabels = %+v, want app=api tier=backend", matchLabels)
	}
	for _, want := range []string{"kubectl apply", "app: api", "tier: backend"} {
		if !strings.Contains(hint.Patch.Command, want) {
			t.Errorf("Patch.Command missing %q\ncommand: %s", want, hint.Patch.Command)
		}
	}
}

// TestForNetworkCoverage002WithoutLabels exercises the fallback branch when
// the analyzer evidence does not carry labels: we should get a command-only
// hint that walks the operator through reading them with kubectl jsonpath.
func TestForNetworkCoverage002WithoutLabels(t *testing.T) {
	t.Parallel()
	finding := makeNetworkFinding(t, "KUBE-NETPOL-COVERAGE-002", "Deployment", "apps", "api", nil)
	hint := ForNetwork("KUBE-NETPOL-COVERAGE-002", finding)
	if hint == nil || hint.Patch == nil {
		t.Fatalf("expected non-nil hint and patch, got %+v", hint)
	}
	if len(hint.Patch.Body) != 0 {
		t.Errorf("Patch.Body should be empty for fallback command-only hint, got %s", string(hint.Patch.Body))
	}
	for _, want := range []string{"kubectl get deployment api", "jsonpath", "kubectl apply"} {
		if !strings.Contains(hint.Patch.Command, want) {
			t.Errorf("Patch.Command missing %q\ncommand: %s", want, hint.Patch.Command)
		}
	}
}

// TestForNetworkCoverage003OnNamespace exercises the COVERAGE-003 path against
// a Namespace-targeted finding (the analyzer's current emit site). We expect a
// command-only heredoc that creates a default-deny-egress policy.
func TestForNetworkCoverage003OnNamespace(t *testing.T) {
	t.Parallel()
	finding := makeNetworkFinding(t, "KUBE-NETPOL-COVERAGE-003", "Namespace", "apps", "apps", map[string]any{
		"namespace": "apps",
	})
	hint := ForNetwork("KUBE-NETPOL-COVERAGE-003", finding)
	if hint == nil || hint.Patch == nil {
		t.Fatalf("expected non-nil hint and patch, got %+v", hint)
	}
	if len(hint.Patch.Body) != 0 {
		t.Errorf("Patch.Body should be empty for command-only hint, got %s", string(hint.Patch.Body))
	}
	for _, want := range []string{"kubectl apply", "default-deny-egress", "policyTypes:", "Egress"} {
		if !strings.Contains(hint.Patch.Command, want) {
			t.Errorf("Patch.Command missing %q\ncommand: %s", want, hint.Patch.Command)
		}
	}
}

// TestForNetworkCoverage003OnPolicy exercises the COVERAGE-003 path when the
// Resource happens to be a NetworkPolicy directly: we expect a merge patch
// that appends an empty egress rule to the policy.
func TestForNetworkCoverage003OnPolicy(t *testing.T) {
	t.Parallel()
	finding := makeNetworkFinding(t, "KUBE-NETPOL-COVERAGE-003", "NetworkPolicy", "apps", "ingress-only", nil)
	hint := ForNetwork("KUBE-NETPOL-COVERAGE-003", finding)
	if hint == nil || hint.Patch == nil {
		t.Fatalf("expected non-nil hint and patch, got %+v", hint)
	}
	if hint.Patch.Type != "merge" {
		t.Errorf("Patch.Type = %q, want merge", hint.Patch.Type)
	}
	var decoded map[string]any
	if err := json.Unmarshal(hint.Patch.Body, &decoded); err != nil {
		t.Fatalf("Patch.Body parse: %v", err)
	}
	spec, _ := decoded["spec"].(map[string]any)
	if _, ok := spec["egress"]; !ok {
		t.Errorf("Patch.Body should set spec.egress; got %s", string(hint.Patch.Body))
	}
	types, _ := spec["policyTypes"].([]any)
	if len(types) == 0 {
		t.Errorf("Patch.Body should set spec.policyTypes; got %s", string(hint.Patch.Body))
	}
}

// TestForNetworkWeakness001 covers the empty-namespaceSelector case. The
// remediation is intentionally command-only because no safe automated patch
// exists: only the operator knows which peers should actually be allowed.
func TestForNetworkWeakness001(t *testing.T) {
	t.Parallel()
	finding := makeNetworkFinding(t, "KUBE-NETPOL-WEAKNESS-001", "NetworkPolicy", "apps", "allow-broad", map[string]any{
		"policy": "allow-broad",
	})
	hint := ForNetwork("KUBE-NETPOL-WEAKNESS-001", finding)
	if hint == nil || hint.Patch == nil {
		t.Fatalf("expected non-nil hint and patch, got %+v", hint)
	}
	if len(hint.Patch.Body) != 0 {
		t.Errorf("Patch.Body should be empty for command-only hint, got %s", string(hint.Patch.Body))
	}
	for _, want := range []string{"kubectl edit networkpolicy allow-broad", "-n apps", "matchLabels"} {
		if !strings.Contains(hint.Patch.Command, want) {
			t.Errorf("Patch.Command missing %q\ncommand: %s", want, hint.Patch.Command)
		}
	}
}

// TestForNetworkWeakness002 covers the 0.0.0.0/0 egress case. We expect a
// kubectl edit recipe plus a Kyverno policy requiring an except: list on any
// wide ipBlock egress.
func TestForNetworkWeakness002(t *testing.T) {
	t.Parallel()
	finding := makeNetworkFinding(t, "KUBE-NETPOL-WEAKNESS-002", "NetworkPolicy", "apps", "allow-broad", map[string]any{
		"policy": "allow-broad",
		"cidr":   "0.0.0.0/0",
	})
	hint := ForNetwork("KUBE-NETPOL-WEAKNESS-002", finding)
	if hint == nil || hint.Patch == nil {
		t.Fatalf("expected non-nil hint and patch, got %+v", hint)
	}
	if len(hint.Patch.Body) != 0 {
		t.Errorf("Patch.Body should be empty for command-only hint, got %s", string(hint.Patch.Body))
	}
	for _, want := range []string{
		"kubectl edit networkpolicy allow-broad",
		"-n apps",
		"169.254.169.254/32",
		"0.0.0.0/0",
	} {
		if !strings.Contains(hint.Patch.Command, want) {
			t.Errorf("Patch.Command missing %q\ncommand: %s", want, hint.Patch.Command)
		}
	}
	if hint.KyvernoPolicy == "" {
		t.Fatal("KyvernoPolicy should be populated for WEAKNESS-002")
	}
	if !strings.Contains(hint.KyvernoPolicy, "require-egress-except") {
		t.Errorf("KyvernoPolicy missing expected ClusterPolicy name\npolicy:\n%s", hint.KyvernoPolicy)
	}
}

// TestForNetworkIMDS001ExplicitAllow covers the "the workload has a policy
// that admits IMDS" branch. The patch must target the offending NetworkPolicy
// named in evidence and merge in an except: carveout.
func TestForNetworkIMDS001ExplicitAllow(t *testing.T) {
	t.Parallel()
	finding := makeNetworkFinding(t, "KUBE-NETPOL-IMDS-001", "Deployment", "apps", "api", map[string]any{
		"workload_kind":      "Deployment",
		"workload_name":      "api",
		"workload_namespace": "apps",
		"reason":             "explicit-allow",
		"offender_cidr":      "0.0.0.0/0",
		"offender_policy":    "apps/wide-egress",
	})
	hint := ForNetwork("KUBE-NETPOL-IMDS-001", finding)
	if hint == nil || hint.Patch == nil {
		t.Fatalf("expected non-nil hint and patch, got %+v", hint)
	}
	if hint.Patch.Type != "merge" {
		t.Errorf("Patch.Type = %q, want merge", hint.Patch.Type)
	}
	if hint.Patch.Target.Kind != "NetworkPolicy" {
		t.Errorf("Patch.Target.Kind = %q, want NetworkPolicy", hint.Patch.Target.Kind)
	}
	if hint.Patch.Target.Name != "wide-egress" {
		t.Errorf("Patch.Target.Name = %q, want wide-egress", hint.Patch.Target.Name)
	}
	if hint.Patch.Target.Namespace != "apps" {
		t.Errorf("Patch.Target.Namespace = %q, want apps", hint.Patch.Target.Namespace)
	}
	if !strings.Contains(string(hint.Patch.Body), "169.254.169.254/32") {
		t.Errorf("Patch.Body should contain IMDS carveout, got %s", string(hint.Patch.Body))
	}
	if !strings.Contains(string(hint.Patch.Body), `"except"`) {
		t.Errorf("Patch.Body should contain an except list, got %s", string(hint.Patch.Body))
	}
	if !strings.Contains(hint.Patch.Command, "kubectl patch networkpolicy wide-egress") {
		t.Errorf("Patch.Command missing the patch invocation; got: %s", hint.Patch.Command)
	}
	if hint.KyvernoPolicy == "" {
		t.Fatal("KyvernoPolicy should be populated for IMDS-001")
	}
	if !strings.Contains(hint.KyvernoPolicy, "block-imds-egress") {
		t.Errorf("KyvernoPolicy missing expected ClusterPolicy name\npolicy:\n%s", hint.KyvernoPolicy)
	}
}

// TestForNetworkIMDS001NoEgressPolicy covers the second IMDS-001 shape: the
// workload has no egress policy at all, so Kubernetes leaves it allow-all
// and IMDS is implicitly reachable. The fix is a heredoc creating a
// default-deny-egress carved for the workload.
func TestForNetworkIMDS001NoEgressPolicy(t *testing.T) {
	t.Parallel()
	finding := makeNetworkFinding(t, "KUBE-NETPOL-IMDS-001", "Deployment", "apps", "api", map[string]any{
		"workload_kind":      "Deployment",
		"workload_name":      "api",
		"workload_namespace": "apps",
		"reason":             "no-egress-policy",
	})
	hint := ForNetwork("KUBE-NETPOL-IMDS-001", finding)
	if hint == nil || hint.Patch == nil {
		t.Fatalf("expected non-nil hint and patch, got %+v", hint)
	}
	if len(hint.Patch.Body) != 0 {
		t.Errorf("Patch.Body should be empty for command-only hint, got %s", string(hint.Patch.Body))
	}
	for _, want := range []string{
		"kubectl apply",
		"default-deny-egress",
		"169.254.169.254/32",
		"169.254.0.0/16",
		"kube-dns",
	} {
		if !strings.Contains(hint.Patch.Command, want) {
			t.Errorf("Patch.Command missing %q\ncommand: %s", want, hint.Patch.Command)
		}
	}
	if hint.KyvernoPolicy == "" {
		t.Fatal("KyvernoPolicy should be populated for IMDS-001 no-egress shape")
	}
}

// TestForNetworkCrossNS001 covers the cross-namespace bridging case. The
// remediation is command-only because the safe replacement depends on which
// exact peers the operator intended to allow.
func TestForNetworkCrossNS001(t *testing.T) {
	t.Parallel()
	finding := makeNetworkFinding(t, "KUBE-NETPOL-CROSSNS-001", "NetworkPolicy", "team-a", "allow-system", map[string]any{
		"policy_namespace": "team-a",
		"policy_name":      "allow-system",
		"source_namespace": "kube-system",
		"target_namespace": "team-a",
		"direction":        "ingress",
	})
	hint := ForNetwork("KUBE-NETPOL-CROSSNS-001", finding)
	if hint == nil || hint.Patch == nil {
		t.Fatalf("expected non-nil hint and patch, got %+v", hint)
	}
	if len(hint.Patch.Body) != 0 {
		t.Errorf("Patch.Body should be empty for command-only hint, got %s", string(hint.Patch.Body))
	}
	for _, want := range []string{
		"kubectl edit networkpolicy allow-system",
		"-n team-a",
		"kube-system",
		"team-a",
		"ingress",
	} {
		if !strings.Contains(hint.Patch.Command, want) {
			t.Errorf("Patch.Command missing %q\ncommand: %s", want, hint.Patch.Command)
		}
	}
}
