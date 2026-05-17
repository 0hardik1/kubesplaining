package remediation

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// makeCloudFinding builds a minimal cloud-style Finding suitable for feeding
// into ForCloud. The cloud analyzer attaches both Subject (the IAM principal
// or annotated SA) and Resource (the ConfigMap / SA / workload), plus an
// evidence map with the "arn" / "sa" / "viaBinding" keys. We accept all of
// those as optional inputs so each test can shape the finding it needs.
func makeCloudFinding(t *testing.T, ruleID string, subject *models.SubjectRef, resource *models.ResourceRef, evidence map[string]any) models.Finding {
	t.Helper()
	var body json.RawMessage
	if evidence != nil {
		b, err := json.Marshal(evidence)
		if err != nil {
			t.Fatalf("marshal evidence: %v", err)
		}
		body = b
	}
	return models.Finding{
		ID:       ruleID + ":test",
		RuleID:   ruleID,
		Severity: models.SeverityHigh,
		Subject:  subject,
		Resource: resource,
		Evidence: body,
	}
}

// TestForCloudUnknownRuleReturnsNil documents that the dispatcher is closed
// over the five KUBE-CLOUD-* rules it knows about; anything else gets nil so
// callers fall back to the prose Remediation field.
func TestForCloudUnknownRuleReturnsNil(t *testing.T) {
	t.Parallel()
	f := makeCloudFinding(t, "KUBE-RBAC-OVERBROAD-001", nil, nil, nil)
	if hint := ForCloud("KUBE-RBAC-OVERBROAD-001", f); hint != nil {
		t.Errorf("expected nil hint for non-cloud rule, got %+v", hint)
	}
}

// TestForCloudProviderUnknownReturnsNil documents that the informational
// PROVIDER-UNKNOWN rule has no automated fix; the analyzer's prose handles it.
func TestForCloudProviderUnknownReturnsNil(t *testing.T) {
	t.Parallel()
	f := makeCloudFinding(t, "KUBE-CLOUD-PROVIDER-UNKNOWN-001", nil, nil, nil)
	if hint := ForCloud("KUBE-CLOUD-PROVIDER-UNKNOWN-001", f); hint != nil {
		t.Errorf("expected nil hint for PROVIDER-UNKNOWN, got %+v", hint)
	}
}

// TestForCloudAWSAuthSystemMasters covers the happy path: the IAM principal's
// ARN is in evidence, the command must surface it in a comment and point the
// operator at kubectl edit configmap aws-auth in kube-system.
func TestForCloudAWSAuthSystemMasters(t *testing.T) {
	t.Parallel()
	arn := "arn:aws:iam::123456789012:role/admin-pwn"
	f := makeCloudFinding(t,
		"KUBE-CLOUD-AWSAUTH-SYSTEM-MASTERS-001",
		&models.SubjectRef{Kind: "User", Name: arn},
		&models.ResourceRef{Kind: "ConfigMap", Namespace: "kube-system", Name: "aws-auth"},
		map[string]any{"arn": arn, "entryType": "mapRoles"},
	)
	hint := ForCloud("KUBE-CLOUD-AWSAUTH-SYSTEM-MASTERS-001", f)
	if hint == nil || hint.Patch == nil {
		t.Fatalf("expected non-nil hint with Patch, got %+v", hint)
	}
	if hint.Patch.Target.Name != "aws-auth" || hint.Patch.Target.Namespace != "kube-system" {
		t.Errorf("Target = %+v, want kube-system/aws-auth", hint.Patch.Target)
	}
	for _, want := range []string{
		"kubectl -n kube-system edit configmap aws-auth",
		arn,
		"system:masters",
	} {
		if !strings.Contains(hint.Patch.Command, want) {
			t.Errorf("Command missing %q\nCommand was: %s", want, hint.Patch.Command)
		}
	}
}

// TestForCloudAWSAuthOverbroad confirms the "viaBinding" evidence key flows
// into the hint so the operator can audit the binding mentioned in the chain.
func TestForCloudAWSAuthOverbroad(t *testing.T) {
	t.Parallel()
	arn := "arn:aws:iam::123456789012:user/legacy-ops"
	f := makeCloudFinding(t,
		"KUBE-CLOUD-AWSAUTH-OVERBROAD-001",
		&models.SubjectRef{Kind: "User", Name: arn},
		&models.ResourceRef{Kind: "ConfigMap", Namespace: "kube-system", Name: "aws-auth"},
		map[string]any{"arn": arn, "viaBinding": "legacy-cluster-admins"},
	)
	hint := ForCloud("KUBE-CLOUD-AWSAUTH-OVERBROAD-001", f)
	if hint == nil || hint.Patch == nil {
		t.Fatalf("expected non-nil hint with Patch, got %+v", hint)
	}
	if !strings.Contains(hint.Patch.Command, "legacy-cluster-admins") {
		t.Errorf("Command should surface viaBinding, got: %s", hint.Patch.Command)
	}
	if !strings.Contains(hint.Patch.Command, arn) {
		t.Errorf("Command should surface the ARN, got: %s", hint.Patch.Command)
	}
}

// TestForCloudIRSAAdminRole confirms the hint surfaces the SA namespace/name,
// includes a sample trust policy with the SA-scoped sub condition, and ends
// with the kubectl annotate command.
func TestForCloudIRSAAdminRole(t *testing.T) {
	t.Parallel()
	f := makeCloudFinding(t,
		"KUBE-CLOUD-IRSA-ADMIN-ROLE-001",
		&models.SubjectRef{Kind: "ServiceAccount", Namespace: "payments", Name: "checkout"},
		&models.ResourceRef{Kind: "ServiceAccount", Namespace: "payments", Name: "checkout"},
		map[string]any{"sa": "payments/checkout", "arn": "arn:aws:iam::123:role/admin"},
	)
	hint := ForCloud("KUBE-CLOUD-IRSA-ADMIN-ROLE-001", f)
	if hint == nil || hint.Patch == nil {
		t.Fatalf("expected non-nil hint with Patch, got %+v", hint)
	}
	for _, want := range []string{
		"kubectl annotate sa checkout -n payments",
		"eks.amazonaws.com/role-arn",
		"system:serviceaccount:payments:checkout",
		"sts:AssumeRoleWithWebIdentity",
	} {
		if !strings.Contains(hint.Patch.Command, want) {
			t.Errorf("Command missing %q\nCommand was: %s", want, hint.Patch.Command)
		}
	}
}

// TestForCloudIRSAMissing confirms the hint emits the same annotate command
// (mirror of IRSA-ADMIN's structural fix) plus the trust-policy template.
func TestForCloudIRSAMissing(t *testing.T) {
	t.Parallel()
	f := makeCloudFinding(t,
		"KUBE-CLOUD-IRSA-MISSING-001",
		&models.SubjectRef{Kind: "ServiceAccount", Namespace: "data", Name: "etl"},
		&models.ResourceRef{Kind: "Deployment", Namespace: "data", Name: "etl-runner"},
		map[string]any{"sa": "data/etl"},
	)
	hint := ForCloud("KUBE-CLOUD-IRSA-MISSING-001", f)
	if hint == nil || hint.Patch == nil {
		t.Fatalf("expected non-nil hint with Patch, got %+v", hint)
	}
	for _, want := range []string{
		"kubectl annotate sa etl -n data",
		"eks.amazonaws.com/role-arn",
		"sts:AssumeRoleWithWebIdentity",
	} {
		if !strings.Contains(hint.Patch.Command, want) {
			t.Errorf("Command missing %q\nCommand was: %s", want, hint.Patch.Command)
		}
	}
}

// TestForCloudIMDSPivot confirms the composite hint carries both halves of the
// fix: the deny-imds-egress NetworkPolicy + the kubectl annotate command.
func TestForCloudIMDSPivot(t *testing.T) {
	t.Parallel()
	f := makeCloudFinding(t,
		"KUBE-CLOUD-IMDS-PIVOT-001",
		&models.SubjectRef{Kind: "ServiceAccount", Namespace: "ingress", Name: "nginx"},
		&models.ResourceRef{Kind: "Deployment", Namespace: "ingress", Name: "nginx"},
		map[string]any{"sa": "ingress/nginx"},
	)
	hint := ForCloud("KUBE-CLOUD-IMDS-PIVOT-001", f)
	if hint == nil || hint.Patch == nil {
		t.Fatalf("expected non-nil hint with Patch, got %+v", hint)
	}
	for _, want := range []string{
		"kind: NetworkPolicy",
		"name: deny-imds-egress",
		"169.254.169.254/32",
		"kubectl annotate sa nginx -n ingress",
		"eks.amazonaws.com/role-arn",
	} {
		if !strings.Contains(hint.Patch.Command, want) {
			t.Errorf("Command missing %q\nCommand was: %s", want, hint.Patch.Command)
		}
	}
}

// TestForCloudIMDSPivotWithoutSAEvidence checks the defensive branch: when no
// SA evidence is supplied, the hint still renders with placeholder values
// rather than returning nil. Operators get a usable scaffold either way.
func TestForCloudIMDSPivotWithoutSAEvidence(t *testing.T) {
	t.Parallel()
	f := makeCloudFinding(t, "KUBE-CLOUD-IMDS-PIVOT-001", nil, nil, nil)
	hint := ForCloud("KUBE-CLOUD-IMDS-PIVOT-001", f)
	if hint == nil || hint.Patch == nil {
		t.Fatalf("expected non-nil hint with Patch even without evidence, got %+v", hint)
	}
	if !strings.Contains(hint.Patch.Command, "<service-account>") {
		t.Errorf("Command should fall back to placeholder, got: %s", hint.Patch.Command)
	}
	if !strings.Contains(hint.Patch.Command, "169.254.169.254/32") {
		t.Errorf("Command should still include IMDS deny, got: %s", hint.Patch.Command)
	}
}
