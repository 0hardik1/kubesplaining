package remediation

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// makeSAFinding builds a ServiceAccount-shaped Finding suitable for feeding to
// ForServiceAccount. Mirrors the shape that the SA analyzer's newFinding
// helper produces in production: Resource is the SA itself (not the source
// role), Subject is the same SA, and Evidence carries the analyzer's
// serialised "rules" / "workloads" / "dangerous_permissions" envelope.
func makeSAFinding(t *testing.T, ruleID, saNamespace, saName string, evidence map[string]any) models.Finding {
	t.Helper()
	body, err := json.Marshal(evidence)
	if err != nil {
		t.Fatalf("marshal evidence: %v", err)
	}
	subject := models.SubjectRef{Kind: "ServiceAccount", Name: saName, Namespace: saNamespace}
	return models.Finding{
		ID:       ruleID + ":" + subject.Key(),
		RuleID:   ruleID,
		Severity: models.SeverityHigh,
		Subject:  &subject,
		Resource: &models.ResourceRef{
			Kind:      "ServiceAccount",
			Name:      saName,
			Namespace: saNamespace,
		},
		Evidence: body,
	}
}

// TestForServiceAccountPrivileged001 covers the wildcard-rule branch. The
// generator must pick the wildcard rule out of evidence.rules[] and emit both
// a unified diff (showing the rule removed) and a kubectl-edit command
// pointing at the source ClusterRole.
func TestForServiceAccountPrivileged001(t *testing.T) {
	t.Parallel()

	finding := makeSAFinding(t, "KUBE-SA-PRIVILEGED-001", "app", "worker", map[string]any{
		"rules": []map[string]any{
			{
				"namespace":      "",
				"api_groups":     []string{"*"},
				"resources":      []string{"*"},
				"verbs":          []string{"*"},
				"source_role":    "cluster-admin",
				"source_binding": "worker-binding",
			},
		},
	})

	hint := ForServiceAccount("KUBE-SA-PRIVILEGED-001", finding, models.Snapshot{})
	if hint == nil {
		t.Fatal("ForServiceAccount returned nil")
	}
	if hint.RBACDiff == "" {
		t.Fatal("RBACDiff is empty: expected wildcard rule to be diffed out")
	}
	if !strings.Contains(hint.RBACDiff, "kind: ClusterRole") {
		t.Errorf("RBACDiff should target ClusterRole; got:\n%s", hint.RBACDiff)
	}
	if !strings.Contains(hint.RBACDiff, "name: cluster-admin") {
		t.Errorf("RBACDiff should name the source role; got:\n%s", hint.RBACDiff)
	}
	if !strings.Contains(hint.RBACDiff, "-  verbs: [\"*\"]") {
		t.Errorf("RBACDiff should remove the wildcard verbs line; got:\n%s", hint.RBACDiff)
	}
	if hint.Patch == nil {
		t.Fatal("Patch is nil")
	}
	if hint.Patch.Target.Kind != "ClusterRole" {
		t.Errorf("Patch.Target.Kind = %q, want ClusterRole", hint.Patch.Target.Kind)
	}
	if !strings.Contains(hint.Patch.Command, "kubectl edit clusterrole cluster-admin") {
		t.Errorf("Patch.Command should include kubectl edit recipe; got:\n%s", hint.Patch.Command)
	}
}

// TestForServiceAccountPrivileged002 covers the dangerous-capability branch.
// The generator picks the first dangerous rule out of evidence.rules[] (here:
// secrets:get) and emits the same diff + edit-command shape as the wildcard
// branch, just scoped to the smaller-namespaced Role.
func TestForServiceAccountPrivileged002(t *testing.T) {
	t.Parallel()

	finding := makeSAFinding(t, "KUBE-SA-PRIVILEGED-002", "app", "worker", map[string]any{
		"workloads":             []map[string]any{{"kind": "Deployment", "name": "web", "namespace": "app"}},
		"dangerous_permissions": []string{"secrets (app)"},
		"rules": []map[string]any{
			{
				"namespace":      "app",
				"api_groups":     []string{""},
				"resources":      []string{"secrets"},
				"verbs":          []string{"get", "list"},
				"source_role":    "app-reader",
				"source_binding": "app-reader-rb",
			},
		},
	})

	hint := ForServiceAccount("KUBE-SA-PRIVILEGED-002", finding, models.Snapshot{})
	if hint == nil {
		t.Fatal("ForServiceAccount returned nil")
	}
	if hint.RBACDiff == "" {
		t.Fatal("RBACDiff is empty")
	}
	if !strings.Contains(hint.RBACDiff, "kind: Role") {
		t.Errorf("RBACDiff should target Role (namespaced); got:\n%s", hint.RBACDiff)
	}
	if !strings.Contains(hint.RBACDiff, "namespace: app") {
		t.Errorf("RBACDiff should carry the binding namespace; got:\n%s", hint.RBACDiff)
	}
	if !strings.Contains(hint.RBACDiff, "resources: [\"secrets\"]") {
		t.Errorf("RBACDiff should reference the dangerous resource; got:\n%s", hint.RBACDiff)
	}
	if hint.Patch == nil {
		t.Fatal("Patch is nil")
	}
	if hint.Patch.Target.Namespace != "app" {
		t.Errorf("Patch.Target.Namespace = %q, want app", hint.Patch.Target.Namespace)
	}
	if !strings.Contains(hint.Patch.Command, "kubectl edit role app-reader") {
		t.Errorf("Patch.Command should include kubectl edit recipe; got:\n%s", hint.Patch.Command)
	}
}

// TestForServiceAccountDefault002 covers the default-SA-has-bindings branch.
// The generator emits the same shape as the dangerous-rule path; the SA being
// `default` is reflected by the Finding.Subject, not by the patch target.
func TestForServiceAccountDefault002(t *testing.T) {
	t.Parallel()

	finding := makeSAFinding(t, "KUBE-SA-DEFAULT-002", "team-a", "default", map[string]any{
		"rules": []map[string]any{
			{
				"namespace":      "",
				"api_groups":     []string{""},
				"resources":      []string{"pods"},
				"verbs":          []string{"create"},
				"source_role":    "pod-creator",
				"source_binding": "default-pod-creator",
			},
		},
	})

	hint := ForServiceAccount("KUBE-SA-DEFAULT-002", finding, models.Snapshot{})
	if hint == nil {
		t.Fatal("ForServiceAccount returned nil")
	}
	if hint.RBACDiff == "" {
		t.Fatal("RBACDiff is empty")
	}
	if !strings.Contains(hint.RBACDiff, "name: pod-creator") {
		t.Errorf("RBACDiff should name source role; got:\n%s", hint.RBACDiff)
	}
	if hint.Patch == nil {
		t.Fatal("Patch is nil")
	}
	if !strings.Contains(hint.Patch.Command, "kubectl edit clusterrole pod-creator") {
		t.Errorf("Patch.Command should reference the source ClusterRole; got:\n%s", hint.Patch.Command)
	}
}

// TestForServiceAccountDaemonSet001 covers the workload-level fix. The
// generator must build a strategic-merge patch targeting the DaemonSet (not
// the SA itself) and the body must place automountServiceAccountToken=false
// inside spec.template.spec (the apps/v1 envelope).
func TestForServiceAccountDaemonSet001(t *testing.T) {
	t.Parallel()

	finding := makeSAFinding(t, "KUBE-SA-DAEMONSET-001", "observability", "agent", map[string]any{
		"workloads": []map[string]any{
			{"kind": "DaemonSet", "name": "node-agent", "namespace": "observability"},
		},
		"rules": []map[string]any{},
	})

	hint := ForServiceAccount("KUBE-SA-DAEMONSET-001", finding, models.Snapshot{})
	if hint == nil || hint.Patch == nil {
		t.Fatalf("expected non-nil hint with Patch, got %+v", hint)
	}
	if hint.Patch.Type != "strategic" {
		t.Errorf("Patch.Type = %q, want strategic", hint.Patch.Type)
	}
	if hint.Patch.Target.Kind != "DaemonSet" {
		t.Errorf("Patch.Target.Kind = %q, want DaemonSet", hint.Patch.Target.Kind)
	}
	if hint.Patch.Target.Name != "node-agent" {
		t.Errorf("Patch.Target.Name = %q, want node-agent", hint.Patch.Target.Name)
	}
	if hint.Patch.Target.Namespace != "observability" {
		t.Errorf("Patch.Target.Namespace = %q, want observability", hint.Patch.Target.Namespace)
	}
	if hint.Patch.Target.APIVersion != "apps/v1" {
		t.Errorf("Patch.Target.APIVersion = %q, want apps/v1", hint.Patch.Target.APIVersion)
	}

	var decoded map[string]any
	if err := json.Unmarshal(hint.Patch.Body, &decoded); err != nil {
		t.Fatalf("Patch.Body invalid JSON: %v\nbody: %s", err, string(hint.Patch.Body))
	}
	spec, _ := decoded["spec"].(map[string]any)
	template, _ := spec["template"].(map[string]any)
	podSpec, _ := template["spec"].(map[string]any)
	if podSpec == nil {
		t.Fatalf("body missing spec.template.spec envelope: %s", string(hint.Patch.Body))
	}
	if podSpec["automountServiceAccountToken"] != false {
		t.Errorf("spec.template.spec.automountServiceAccountToken = %v, want false", podSpec["automountServiceAccountToken"])
	}

	if !strings.Contains(hint.Patch.Command, "kubectl patch daemonset node-agent") {
		t.Errorf("Patch.Command should reference daemonset; got:\n%s", hint.Patch.Command)
	}
	if !strings.Contains(hint.Patch.Command, "-n observability") {
		t.Errorf("Patch.Command should include namespace; got:\n%s", hint.Patch.Command)
	}
}

// TestForServiceAccountDaemonSetWithoutDaemonSetReturnsNil guards the
// defensive branch: if the workloads list doesn't include a DaemonSet (e.g.
// because the analyzer's DaemonSet detection drifted from the remediation's
// evidence schema) we get nil rather than a patch targeting the wrong kind.
func TestForServiceAccountDaemonSetWithoutDaemonSetReturnsNil(t *testing.T) {
	t.Parallel()

	finding := makeSAFinding(t, "KUBE-SA-DAEMONSET-001", "default", "agent", map[string]any{
		"workloads": []map[string]any{
			{"kind": "Deployment", "name": "web", "namespace": "default"},
		},
	})

	if hint := ForServiceAccount("KUBE-SA-DAEMONSET-001", finding, models.Snapshot{}); hint != nil {
		t.Errorf("expected nil hint when no DaemonSet in evidence; got %+v", hint)
	}
}

// TestForServiceAccountFallback covers the path where the rules array is
// missing or none of the entries match the dangerous patterns: the generator
// should still return a non-nil hint with a `kubectl get rolebindings` recipe
// so the operator has something actionable to follow.
func TestForServiceAccountFallback(t *testing.T) {
	t.Parallel()

	finding := makeSAFinding(t, "KUBE-SA-PRIVILEGED-001", "app", "worker", map[string]any{
		// No "rules" key: simulates a finding constructed before the analyzer
		// learned to emit the array (defensive: should not happen in
		// production, but we degrade gracefully).
	})

	hint := ForServiceAccount("KUBE-SA-PRIVILEGED-001", finding, models.Snapshot{})
	if hint == nil || hint.Patch == nil {
		t.Fatalf("expected fallback hint with Patch, got %+v", hint)
	}
	if hint.Patch.Target.Kind != "ServiceAccount" {
		t.Errorf("fallback Patch.Target.Kind = %q, want ServiceAccount", hint.Patch.Target.Kind)
	}
	if !strings.Contains(hint.Patch.Command, "kubectl get rolebindings,clusterrolebindings") {
		t.Errorf("fallback Command should suggest a binding scan; got:\n%s", hint.Patch.Command)
	}
	if !strings.Contains(hint.Patch.Command, "\"worker\"") {
		t.Errorf("fallback Command should reference the SA name; got:\n%s", hint.Patch.Command)
	}
}

// TestForServiceAccountUnknownRuleReturnsNil documents the closed-set
// contract: rules outside the SA module's surface return nil so the call
// site stays a one-liner.
func TestForServiceAccountUnknownRuleReturnsNil(t *testing.T) {
	t.Parallel()

	finding := makeSAFinding(t, "KUBE-RBAC-OVERBROAD-001", "default", "x", nil)
	if hint := ForServiceAccount("KUBE-RBAC-OVERBROAD-001", finding, models.Snapshot{}); hint != nil {
		t.Errorf("expected nil hint for non-SA rule, got %+v", hint)
	}
}
