package remediation

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// makeSecretFinding builds a minimal Finding suitable for feeding into
// ForSecrets. Mirrors makeFinding in podsec_test.go but defaults the kind to
// Secret so the more common case is one line shorter.
func makeSecretFinding(t *testing.T, ruleID, kind, namespace, name string, evidence map[string]any) models.Finding {
	t.Helper()
	body, err := json.Marshal(evidence)
	if err != nil {
		t.Fatalf("marshal evidence: %v", err)
	}
	return models.Finding{
		ID:       ruleID + ":" + namespace + ":" + name,
		RuleID:   ruleID,
		Severity: models.SeverityHigh,
		Resource: &models.ResourceRef{
			Kind:      kind,
			Namespace: namespace,
			Name:      name,
		},
		Evidence: body,
	}
}

// TestForSecretsConfigMapCreds asserts the high-confidence configmap
// credential rule emits a JSON-patch remove op against the matched key.
func TestForSecretsConfigMapCreds(t *testing.T) {
	t.Parallel()

	finding := makeSecretFinding(t, "KUBE-CONFIGMAP-CREDS-001", "ConfigMap", "default", "app-config", map[string]any{
		"matched_key": "password",
		"namespace":   "default",
	})
	hint := ForSecrets("KUBE-CONFIGMAP-CREDS-001", finding)
	if hint == nil || hint.Patch == nil {
		t.Fatalf("expected non-nil hint with patch, got %+v", hint)
	}
	if hint.Patch.Type != "json" {
		t.Errorf("Patch.Type = %q, want json", hint.Patch.Type)
	}
	if hint.Patch.Target.Kind != "ConfigMap" || hint.Patch.Target.APIVersion != "v1" {
		t.Errorf("Patch.Target = %+v, want ConfigMap/v1", hint.Patch.Target)
	}
	var ops []map[string]any
	if err := json.Unmarshal(hint.Patch.Body, &ops); err != nil {
		t.Fatalf("Patch.Body not JSON: %v", err)
	}
	if len(ops) != 1 {
		t.Fatalf("expected 1 op, got %d: %s", len(ops), string(hint.Patch.Body))
	}
	if ops[0]["op"] != "remove" {
		t.Errorf(`op = %v, want "remove"`, ops[0]["op"])
	}
	if ops[0]["path"] != "/data/password" {
		t.Errorf(`path = %v, want "/data/password"`, ops[0]["path"])
	}
}

// TestForSecretsConfigMapCredsEscapesPointer ensures keys that contain `/`
// or `~` get RFC-6901 JSON-Pointer-escaped so the patch path is well-formed.
func TestForSecretsConfigMapCredsEscapesPointer(t *testing.T) {
	t.Parallel()

	finding := makeSecretFinding(t, "KUBE-CONFIGMAP-CREDS-001", "ConfigMap", "default", "cfg", map[string]any{
		"matched_key": "app/secret~v1",
	})
	hint := ForSecrets("KUBE-CONFIGMAP-CREDS-001", finding)
	if hint == nil || hint.Patch == nil {
		t.Fatalf("expected hint, got nil")
	}
	var ops []map[string]any
	if err := json.Unmarshal(hint.Patch.Body, &ops); err != nil {
		t.Fatalf("Patch.Body parse: %v", err)
	}
	// `~` -> `~0`, `/` -> `~1`; do `~` first.
	if ops[0]["path"] != "/data/app~1secret~0v1" {
		t.Errorf("path = %v, want pointer-escaped form", ops[0]["path"])
	}
}

// TestForSecretsConfigMap001 covers the aggregated multi-key shape: one op
// per element of Evidence.matched_keys.
func TestForSecretsConfigMap001(t *testing.T) {
	t.Parallel()

	finding := makeSecretFinding(t, "KUBE-CONFIGMAP-001", "ConfigMap", "default", "app-config", map[string]any{
		"matched_keys": []string{"db_password", "api_key"},
	})
	hint := ForSecrets("KUBE-CONFIGMAP-001", finding)
	if hint == nil || hint.Patch == nil {
		t.Fatalf("expected hint, got nil")
	}
	if hint.Patch.Type != "json" {
		t.Errorf("Patch.Type = %q, want json", hint.Patch.Type)
	}
	var ops []map[string]any
	if err := json.Unmarshal(hint.Patch.Body, &ops); err != nil {
		t.Fatalf("Patch.Body parse: %v", err)
	}
	if len(ops) != 2 {
		t.Fatalf("expected 2 ops, got %d", len(ops))
	}
	seen := map[string]bool{}
	for _, op := range ops {
		if op["op"] != "remove" {
			t.Errorf(`op = %v, want "remove"`, op["op"])
		}
		seen[op["path"].(string)] = true
	}
	for _, want := range []string{"/data/db_password", "/data/api_key"} {
		if !seen[want] {
			t.Errorf("missing remove op for %q (got: %v)", want, seen)
		}
	}
}

// TestForSecretsConfigMap002 confirms the CoreDNS rule produces a Kyverno-only
// hint: no kubectl patch (the safe fix needs operator judgement) but a
// ClusterPolicy that locks down future writes.
func TestForSecretsConfigMap002(t *testing.T) {
	t.Parallel()

	finding := makeSecretFinding(t, "KUBE-CONFIGMAP-002", "ConfigMap", "kube-system", "coredns", map[string]any{
		"name": "coredns",
	})
	hint := ForSecrets("KUBE-CONFIGMAP-002", finding)
	if hint == nil {
		t.Fatal("expected hint, got nil")
	}
	if hint.Patch != nil {
		t.Errorf("expected nil Patch (CoreDNS fix is policy-only), got %+v", hint.Patch)
	}
	if hint.KyvernoPolicy == "" {
		t.Fatal("KyvernoPolicy is empty")
	}
	if !strings.Contains(hint.KyvernoPolicy, "kind: ClusterPolicy") {
		t.Errorf("KyvernoPolicy missing kind: ClusterPolicy\n%s", hint.KyvernoPolicy)
	}
	if !strings.Contains(hint.KyvernoPolicy, "coredns") {
		t.Errorf("KyvernoPolicy should mention coredns\n%s", hint.KyvernoPolicy)
	}
}

// TestForSecrets001 asserts the legacy SA-token-secret rule emits a
// command-only delete plus a Kyverno policy.
func TestForSecrets001(t *testing.T) {
	t.Parallel()

	finding := makeSecretFinding(t, "KUBE-SECRETS-001", "Secret", "default", "legacy-token", map[string]any{
		"type": "kubernetes.io/service-account-token",
	})
	hint := ForSecrets("KUBE-SECRETS-001", finding)
	if hint == nil || hint.Patch == nil {
		t.Fatalf("expected non-nil hint with patch, got %+v", hint)
	}
	if len(hint.Patch.Body) != 0 {
		t.Errorf("Patch.Body should be empty for command-only hint, got %s", string(hint.Patch.Body))
	}
	if !strings.Contains(hint.Patch.Command, "kubectl delete secret legacy-token") {
		t.Errorf("Patch.Command missing delete invocation: %s", hint.Patch.Command)
	}
	if !strings.Contains(hint.Patch.Command, "-n default") {
		t.Errorf("Patch.Command missing namespace: %s", hint.Patch.Command)
	}
	if hint.KyvernoPolicy == "" || !strings.Contains(hint.KyvernoPolicy, "kind: ClusterPolicy") {
		t.Errorf("KyvernoPolicy missing kind: ClusterPolicy:\n%s", hint.KyvernoPolicy)
	}
	if !strings.Contains(hint.KyvernoPolicy, "service-account-token") {
		t.Errorf("KyvernoPolicy should target legacy SA token shape:\n%s", hint.KyvernoPolicy)
	}
}

// TestForSecrets002 asserts the kube-system Opaque secret rule emits a 3-line
// shell pipeline that copies the secret out and then deletes the original,
// paired with a Kyverno ClusterPolicy.
func TestForSecrets002(t *testing.T) {
	t.Parallel()

	finding := makeSecretFinding(t, "KUBE-SECRETS-002", "Secret", "kube-system", "infra-creds", map[string]any{
		"type": "Opaque",
	})
	hint := ForSecrets("KUBE-SECRETS-002", finding)
	if hint == nil || hint.Patch == nil {
		t.Fatalf("expected non-nil hint with patch, got %+v", hint)
	}
	if len(hint.Patch.Body) != 0 {
		t.Errorf("Patch.Body should be empty for command-only hint, got %s", string(hint.Patch.Body))
	}
	for _, want := range []string{
		"kubectl get secret infra-creds -n kube-system",
		"kubectl apply -f -",
		"kubectl delete secret infra-creds -n kube-system",
	} {
		if !strings.Contains(hint.Patch.Command, want) {
			t.Errorf("Patch.Command missing %q\ncommand: %s", want, hint.Patch.Command)
		}
	}
	if hint.KyvernoPolicy == "" || !strings.Contains(hint.KyvernoPolicy, "kind: ClusterPolicy") {
		t.Errorf("KyvernoPolicy missing kind: ClusterPolicy:\n%s", hint.KyvernoPolicy)
	}
	if !strings.Contains(hint.KyvernoPolicy, "kube-system") {
		t.Errorf("KyvernoPolicy should mention kube-system:\n%s", hint.KyvernoPolicy)
	}
}

// TestForSecretsCrossNS confirms the cross-namespace secret-read rule emits a
// command-only hint (no body) that points the operator at the offending
// RoleBinding.
func TestForSecretsCrossNS(t *testing.T) {
	t.Parallel()

	finding := makeSecretFinding(t, "KUBE-SECRETS-CROSSNS-001", "ServiceAccount", "team-a", "team-a-sa", map[string]any{
		"target_namespace": "team-b",
		"verbs":            []string{"get", "list"},
		"source_role":      "Role/secret-reader",
		"source_binding":   "RoleBinding/team-a-can-read-team-b",
	})
	hint := ForSecrets("KUBE-SECRETS-CROSSNS-001", finding)
	if hint == nil || hint.Patch == nil {
		t.Fatalf("expected non-nil hint with patch, got %+v", hint)
	}
	if len(hint.Patch.Body) != 0 {
		t.Errorf("Patch.Body should be empty for command-only hint, got %s", string(hint.Patch.Body))
	}
	if !strings.Contains(hint.Patch.Command, "kubectl edit rolebinding team-a-can-read-team-b") {
		t.Errorf("Patch.Command missing edit invocation: %s", hint.Patch.Command)
	}
}

// TestForSecretsCrossNSFallback exercises the fallback prose when the
// finding's Evidence does not name a single binding (older evidence shape).
func TestForSecretsCrossNSFallback(t *testing.T) {
	t.Parallel()

	finding := makeSecretFinding(t, "KUBE-SECRETS-CROSSNS-001", "ServiceAccount", "team-a", "team-a-sa", map[string]any{
		"target_namespace": "team-b",
	})
	hint := ForSecrets("KUBE-SECRETS-CROSSNS-001", finding)
	if hint == nil || hint.Patch == nil {
		t.Fatalf("expected non-nil hint with patch, got %+v", hint)
	}
	if !strings.Contains(hint.Patch.Command, "name: team-a-sa") {
		t.Errorf("Patch.Command missing fallback grep on SA name: %s", hint.Patch.Command)
	}
}

// TestForSecretsTLSExpiry confirms the TLS-expiry rule emits a command-only
// hint that prefers cmctl renew and documents the manual rotation flow.
func TestForSecretsTLSExpiry(t *testing.T) {
	t.Parallel()

	finding := makeSecretFinding(t, "KUBE-SECRETS-TLS-EXPIRY-001", "Secret", "edge", "edge-tls", map[string]any{
		"type":           "kubernetes.io/tls",
		"days_to_expiry": "7d",
	})
	hint := ForSecrets("KUBE-SECRETS-TLS-EXPIRY-001", finding)
	if hint == nil || hint.Patch == nil {
		t.Fatalf("expected non-nil hint with patch, got %+v", hint)
	}
	if len(hint.Patch.Body) != 0 {
		t.Errorf("Patch.Body should be empty for command-only hint, got %s", string(hint.Patch.Body))
	}
	if !strings.Contains(hint.Patch.Command, "cmctl renew edge-tls -n edge") {
		t.Errorf("Patch.Command missing cmctl renew: %s", hint.Patch.Command)
	}
	if !strings.Contains(hint.Patch.Command, "kubectl create secret tls") {
		t.Errorf("Patch.Command should include manual rotation flow: %s", hint.Patch.Command)
	}
}

// TestForSecretsStale confirms the unreferenced-secret rule emits a
// command-only delete with prose warning about out-of-snapshot consumers.
func TestForSecretsStale(t *testing.T) {
	t.Parallel()

	finding := makeSecretFinding(t, "KUBE-SECRETS-STALE-001", "Secret", "default", "leftover", map[string]any{
		"type": "Opaque",
	})
	hint := ForSecrets("KUBE-SECRETS-STALE-001", finding)
	if hint == nil || hint.Patch == nil {
		t.Fatalf("expected non-nil hint with patch, got %+v", hint)
	}
	if len(hint.Patch.Body) != 0 {
		t.Errorf("Patch.Body should be empty for command-only hint, got %s", string(hint.Patch.Body))
	}
	if !strings.Contains(hint.Patch.Command, "kubectl delete secret leftover -n default") {
		t.Errorf("Patch.Command missing delete invocation: %s", hint.Patch.Command)
	}
	if !strings.Contains(hint.Patch.Command, "Confirm no out-of-snapshot consumer") {
		t.Errorf("Patch.Command missing out-of-snapshot warning: %s", hint.Patch.Command)
	}
}

// TestForSecretsNilResource guards the defensive branch in
// patchTargetFromFinding: callers that hand us a Finding with no Resource
// should get nil back rather than a panic.
func TestForSecretsNilResource(t *testing.T) {
	t.Parallel()
	f := models.Finding{RuleID: "KUBE-SECRETS-001"}
	if hint := ForSecrets("KUBE-SECRETS-001", f); hint != nil {
		t.Errorf("expected nil hint for finding without Resource, got %+v", hint)
	}
}

// TestForSecretsUnknownRule documents that the table is closed.
func TestForSecretsUnknownRule(t *testing.T) {
	t.Parallel()
	f := makeSecretFinding(t, "KUBE-RBAC-OVERBROAD-001", "ClusterRole", "", "admin", nil)
	if hint := ForSecrets("KUBE-RBAC-OVERBROAD-001", f); hint != nil {
		t.Errorf("expected nil hint for non-secrets rule, got %+v", hint)
	}
}

// TestForSecretsConfigMapCredsMissingKey covers the defensive branch when
// evidence does not carry a `matched_key` (which the analyzer always does
// today, but the generator should degrade gracefully).
func TestForSecretsConfigMapCredsMissingKey(t *testing.T) {
	t.Parallel()
	f := makeSecretFinding(t, "KUBE-CONFIGMAP-CREDS-001", "ConfigMap", "default", "cfg", map[string]any{})
	if hint := ForSecrets("KUBE-CONFIGMAP-CREDS-001", f); hint != nil {
		t.Errorf("expected nil hint when matched_key absent, got %+v", hint)
	}
}
