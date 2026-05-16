package secrets

import (
	"context"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
	corev1 "k8s.io/api/core/v1"
)

func TestAnalyzerFindsSecretAndConfigMapRisks(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			SecretsMetadata: []models.SecretMetadata{
				{
					Name:      "legacy-token",
					Namespace: "default",
					Type:      corev1.SecretTypeServiceAccountToken,
				},
				{
					Name:      "infra-creds",
					Namespace: "kube-system",
					Type:      corev1.SecretTypeOpaque,
				},
			},
			ConfigMaps: []models.ConfigMapSnapshot{
				{
					Name:      "app-config",
					Namespace: "default",
					Data: map[string]string{
						"db_password": "",
						"username":    "",
					},
				},
				{
					Name:      "coredns",
					Namespace: "kube-system",
					Data: map[string]string{
						"Corefile": ".:53 {\n    rewrite name exact example.com evil.internal\n}\n",
					},
				},
			},
		},
	}

	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	assertRulePresent(t, findings, "KUBE-SECRETS-001")
	assertRulePresent(t, findings, "KUBE-SECRETS-002")
	assertRulePresent(t, findings, "KUBE-CONFIGMAP-001")
	assertRulePresent(t, findings, "KUBE-CONFIGMAP-002")

	// The remediation package is wired through appendUnique so every emitted
	// finding picks up a structured RemediationHint. Spot-check each of the
	// four rules surfaced above has one attached.
	for _, ruleID := range []string{"KUBE-SECRETS-001", "KUBE-SECRETS-002", "KUBE-CONFIGMAP-001", "KUBE-CONFIGMAP-002"} {
		assertHasRemediationHint(t, findings, ruleID)
	}
}

// assertHasRemediationHint walks the findings slice and fails the test when
// the first finding matching ruleID has a nil RemediationHint. The wave that
// landed this assertion wired remediation.ForSecrets through the analyzer's
// appendUnique helper; this guards against an accidental future revert.
func assertHasRemediationHint(t *testing.T, findings []models.Finding, ruleID string) {
	t.Helper()
	for _, finding := range findings {
		if finding.RuleID != ruleID {
			continue
		}
		if finding.RemediationHint == nil {
			t.Fatalf("expected RemediationHint on %s finding, got nil", ruleID)
		}
		return
	}
	t.Fatalf("no finding with rule %s to assert RemediationHint on", ruleID)
}

func TestMatchedCredentialKeys(t *testing.T) {
	t.Parallel()

	keys := matchedCredentialKeys(map[string]string{
		"db_password": "",
		"dsn":         "",
		"username":    "",
	})

	if len(keys) != 2 {
		t.Fatalf("expected 2 matched keys, got %v", keys)
	}
}

func assertRulePresent(t *testing.T, findings []models.Finding, ruleID string) {
	t.Helper()
	for _, finding := range findings {
		if finding.RuleID == ruleID {
			return
		}
	}
	t.Fatalf("expected rule %s to be present, findings=%v", ruleID, findings)
}
