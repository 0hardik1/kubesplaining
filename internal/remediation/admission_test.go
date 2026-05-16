package remediation

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// makeAdmissionFinding builds a minimal admission-style Finding suitable for
// feeding into ForAdmission. The Resource pointer is mandatory for the
// webhook-targeted rules (001 / 002 / 003); NO-POLICY-ENGINE-001 carries no
// Resource at all (passing kind="" leaves it nil), mirroring the analyzer's
// postureFinding shape.
func makeAdmissionFinding(t *testing.T, ruleID, kind, name string, evidence map[string]any) models.Finding {
	t.Helper()
	body, err := json.Marshal(evidence)
	if err != nil {
		t.Fatalf("marshal evidence: %v", err)
	}
	f := models.Finding{
		ID:       ruleID + ":" + name,
		RuleID:   ruleID,
		Severity: models.SeverityHigh,
		Evidence: body,
	}
	if kind != "" {
		f.Resource = &models.ResourceRef{Kind: kind, Name: name}
	}
	return f
}

// TestForAdmissionFailurePolicyWithIndex covers the happy path for
// KUBE-ADMISSION-001 where Evidence carries the webhook position, so the
// generator emits a JSON-patch replace op against the exact /webhooks/<idx>
// slot.
func TestForAdmissionFailurePolicyWithIndex(t *testing.T) {
	t.Parallel()
	finding := makeAdmissionFinding(t, "KUBE-ADMISSION-001", "ValidatingWebhookConfiguration", "risky-cfg", map[string]any{
		"webhook_index": 2,
		"webhook_name":  "mutate.example.com",
	})
	hint := ForAdmission("KUBE-ADMISSION-001", finding)
	if hint == nil || hint.Patch == nil {
		t.Fatalf("expected non-nil hint, got %+v", hint)
	}
	if hint.Patch.Type != "json" {
		t.Errorf("Patch.Type = %q, want json", hint.Patch.Type)
	}
	if !strings.Contains(hint.Patch.Command, "kubectl patch") {
		t.Errorf("Command missing kubectl patch: %s", hint.Patch.Command)
	}
	if !strings.Contains(hint.Patch.Command, "--type=json") {
		t.Errorf("Command missing --type=json: %s", hint.Patch.Command)
	}
	var ops []map[string]any
	if err := json.Unmarshal(hint.Patch.Body, &ops); err != nil {
		t.Fatalf("Patch.Body is not valid JSON-patch: %v\nbody: %s", err, string(hint.Patch.Body))
	}
	if len(ops) != 1 {
		t.Fatalf("expected exactly one op, got %d (body=%s)", len(ops), string(hint.Patch.Body))
	}
	op := ops[0]
	if op["op"] != "replace" {
		t.Errorf("op = %v, want replace", op["op"])
	}
	if op["path"] != "/webhooks/2/failurePolicy" {
		t.Errorf("path = %v, want /webhooks/2/failurePolicy", op["path"])
	}
	if op["value"] != "Fail" {
		t.Errorf("value = %v, want Fail", op["value"])
	}
}

// TestForAdmissionFailurePolicyWithoutIndex covers the fallback path: Evidence
// omits webhook_index, so the generator cannot emit a positional JSON patch
// and instead falls back to a kubectl edit command-only hint.
func TestForAdmissionFailurePolicyWithoutIndex(t *testing.T) {
	t.Parallel()
	finding := makeAdmissionFinding(t, "KUBE-ADMISSION-001", "MutatingWebhookConfiguration", "fallback-cfg", map[string]any{
		"webhook_name": "mutate.example.com",
	})
	hint := ForAdmission("KUBE-ADMISSION-001", finding)
	if hint == nil || hint.Patch == nil {
		t.Fatalf("expected non-nil hint, got %+v", hint)
	}
	if hint.Patch.Type != "merge" {
		t.Errorf("Patch.Type = %q, want merge (command-only hint uses merge)", hint.Patch.Type)
	}
	if !strings.Contains(hint.Patch.Command, "kubectl edit") {
		t.Errorf("Command missing kubectl edit: %s", hint.Patch.Command)
	}
	if !strings.Contains(hint.Patch.Command, "mutatingwebhookconfiguration") {
		t.Errorf("Command missing target kind: %s", hint.Patch.Command)
	}
	if !strings.Contains(hint.Patch.Command, "fallback-cfg") {
		t.Errorf("Command missing target name: %s", hint.Patch.Command)
	}
}

// TestForAdmissionObjectSelectorEmitsKyvernoOnly verifies that ADMISSION-002
// surfaces a Kyverno policy as its only remediation: an objectSelector keyed
// on a workload-controlled label cannot be patched in place.
func TestForAdmissionObjectSelectorEmitsKyvernoOnly(t *testing.T) {
	t.Parallel()
	finding := makeAdmissionFinding(t, "KUBE-ADMISSION-002", "ValidatingWebhookConfiguration", "bypass-cfg", map[string]any{
		"webhook_index": 0,
	})
	hint := ForAdmission("KUBE-ADMISSION-002", finding)
	if hint == nil {
		t.Fatalf("expected non-nil hint")
	}
	if hint.Patch != nil {
		t.Errorf("ADMISSION-002 should not emit a kubectl patch, got %+v", hint.Patch)
	}
	if hint.KyvernoPolicy == "" {
		t.Errorf("expected a Kyverno policy body for ADMISSION-002")
	}
	if !strings.Contains(hint.KyvernoPolicy, "apiVersion: kyverno.io/v1") {
		t.Errorf("KyvernoPolicy does not look like a Kyverno ClusterPolicy: %s", hint.KyvernoPolicy)
	}
	if !strings.Contains(hint.KyvernoPolicy, "ownerReferences") {
		t.Errorf("expected KyvernoPolicy to reference ownerReferences as the gating field, got: %s", hint.KyvernoPolicy)
	}
}

// TestForAdmissionNamespaceSelectorWithIndices covers the happy path for
// KUBE-ADMISSION-003: Evidence carries webhook_index, expr_index, and
// value_index so the generator emits a JSON `remove` op against the precise
// values slot.
func TestForAdmissionNamespaceSelectorWithIndices(t *testing.T) {
	t.Parallel()
	finding := makeAdmissionFinding(t, "KUBE-ADMISSION-003", "ValidatingWebhookConfiguration", "exempt-cfg", map[string]any{
		"webhook_index":      1,
		"expr_index":         0,
		"value_index":        2,
		"excluded_namespace": "kube-system",
	})
	hint := ForAdmission("KUBE-ADMISSION-003", finding)
	if hint == nil || hint.Patch == nil {
		t.Fatalf("expected non-nil hint with patch, got %+v", hint)
	}
	if hint.Patch.Type != "json" {
		t.Errorf("Patch.Type = %q, want json", hint.Patch.Type)
	}
	if !strings.Contains(hint.Patch.Command, "kubectl patch") {
		t.Errorf("Command missing kubectl patch: %s", hint.Patch.Command)
	}
	var ops []map[string]any
	if err := json.Unmarshal(hint.Patch.Body, &ops); err != nil {
		t.Fatalf("Patch.Body is not valid JSON-patch: %v\nbody: %s", err, string(hint.Patch.Body))
	}
	if len(ops) != 1 {
		t.Fatalf("expected exactly one op, got %d", len(ops))
	}
	op := ops[0]
	if op["op"] != "remove" {
		t.Errorf("op = %v, want remove", op["op"])
	}
	want := "/webhooks/1/namespaceSelector/matchExpressions/0/values/2"
	if op["path"] != want {
		t.Errorf("path = %v, want %s", op["path"], want)
	}
	if hint.KyvernoPolicy == "" {
		t.Errorf("expected paired KyvernoPolicy for ADMISSION-003")
	}
}

// TestForAdmissionNamespaceSelectorFallback covers the partial-evidence path
// for ADMISSION-003: webhook_index is present but expr/value indices are
// missing (e.g. DoesNotExist operator with no values list), so the generator
// falls back to a kubectl edit command but still pairs it with the Kyverno
// policy.
func TestForAdmissionNamespaceSelectorFallback(t *testing.T) {
	t.Parallel()
	finding := makeAdmissionFinding(t, "KUBE-ADMISSION-003", "MutatingWebhookConfiguration", "exempt-cfg", map[string]any{
		"webhook_index":      0,
		"excluded_namespace": "(any namespace label)",
	})
	hint := ForAdmission("KUBE-ADMISSION-003", finding)
	if hint == nil || hint.Patch == nil {
		t.Fatalf("expected non-nil hint, got %+v", hint)
	}
	if hint.Patch.Type != "merge" {
		t.Errorf("Patch.Type = %q, want merge (command-only)", hint.Patch.Type)
	}
	if !strings.Contains(hint.Patch.Command, "kubectl edit") {
		t.Errorf("Command missing kubectl edit fallback: %s", hint.Patch.Command)
	}
	if hint.KyvernoPolicy == "" {
		t.Errorf("expected KyvernoPolicy alongside fallback command")
	}
}

// TestForAdmissionNoPolicyEngine verifies the cluster-wide posture hint: no
// Resource on the Finding (posture findings are cluster-wide), but the
// generator still returns a command-only kubectl label example plus a
// Kyverno restricted-baseline policy.
func TestForAdmissionNoPolicyEngine(t *testing.T) {
	t.Parallel()
	finding := makeAdmissionFinding(t, "KUBE-ADMISSION-NO-POLICY-ENGINE-001", "", "", nil)
	hint := ForAdmission("KUBE-ADMISSION-NO-POLICY-ENGINE-001", finding)
	if hint == nil || hint.Patch == nil {
		t.Fatalf("expected non-nil hint, got %+v", hint)
	}
	if hint.Patch.Type != "merge" {
		t.Errorf("Patch.Type = %q, want merge (command-only hint)", hint.Patch.Type)
	}
	if !strings.Contains(hint.Patch.Command, "kubectl label namespace") {
		t.Errorf("Command missing kubectl label invocation: %s", hint.Patch.Command)
	}
	if !strings.Contains(hint.Patch.Command, "pod-security.kubernetes.io/enforce") {
		t.Errorf("Command missing PSA enforce label: %s", hint.Patch.Command)
	}
	if !strings.Contains(hint.Patch.Command, "<ns>") {
		t.Errorf("Command missing <ns> placeholder: %s", hint.Patch.Command)
	}
	if hint.KyvernoPolicy == "" {
		t.Errorf("expected KyvernoPolicy for NO-POLICY-ENGINE-001")
	}
	if !strings.Contains(hint.KyvernoPolicy, "restricted") {
		t.Errorf("expected restricted-baseline KyvernoPolicy, got: %s", hint.KyvernoPolicy)
	}
}

// TestForAdmissionUnknownRuleReturnsNil documents that the table is closed:
// rules outside the admission set get nil so callers fall back to the prose
// Remediation field.
func TestForAdmissionUnknownRuleReturnsNil(t *testing.T) {
	t.Parallel()
	finding := makeAdmissionFinding(t, "KUBE-RBAC-OVERBROAD-001", "ClusterRole", "admin", nil)
	if hint := ForAdmission("KUBE-RBAC-OVERBROAD-001", finding); hint != nil {
		t.Errorf("expected nil hint for non-admission rule, got %+v", hint)
	}
}

// TestForAdmissionNilResourceReturnsNilForWebhookRules guards the defensive
// branch in patchTargetFromFinding: webhook-targeted rules require a Resource
// so the JSON-patch can address it. NO-POLICY-ENGINE-001 is the exception, as
// covered by TestForAdmissionNoPolicyEngine.
func TestForAdmissionNilResourceReturnsNilForWebhookRules(t *testing.T) {
	t.Parallel()
	for _, rule := range []string{"KUBE-ADMISSION-001", "KUBE-ADMISSION-003"} {
		rule := rule
		t.Run(rule, func(t *testing.T) {
			t.Parallel()
			f := models.Finding{RuleID: rule}
			if hint := ForAdmission(rule, f); hint != nil {
				t.Errorf("expected nil hint for %s without Resource, got %+v", rule, hint)
			}
		})
	}
}

// TestAdmissionEvidenceIntKeyAcceptsFloat64 documents the JSON-decoded shape
// our generator must accept: encoding/json decodes JSON integers as float64
// by default, so the int accessor has to handle both. This guards against a
// regression where the accessor only matched the int branch.
func TestAdmissionEvidenceIntKeyAcceptsFloat64(t *testing.T) {
	t.Parallel()
	body, err := json.Marshal(map[string]any{"webhook_index": 7})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	ev := decodeAdmissionEvidence(body)
	got, ok := ev.webhookIndex()
	if !ok {
		t.Fatalf("webhookIndex() returned ok=false after JSON round-trip")
	}
	if got != 7 {
		t.Errorf("webhookIndex() = %d, want 7", got)
	}
}
