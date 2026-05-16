package secrets

import (
	"context"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
)

func TestAnalyzeConfigMapHeuristicsEmitsPerKey(t *testing.T) {
	t.Parallel()

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			ConfigMaps: []models.ConfigMapSnapshot{
				{
					Name:      "app-config",
					Namespace: "team-a",
					Data: map[string]string{
						"db_password":           "",
						"jwt_token":             "",
						"aws_secret_access_key": "",
						"username":              "", // not credential-shaped
						"feature_flag":          "", // not credential-shaped
					},
				},
			},
		},
	}

	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	// Three high-confidence matches: db_password, jwt_token, aws_secret_access_key.
	if got := countByRule(findings, "KUBE-CONFIGMAP-CREDS-001"); got != 3 {
		t.Fatalf("expected 3 KUBE-CONFIGMAP-CREDS-001 findings (one per matching key), got %d", got)
	}

	wantIDs := []string{
		"KUBE-CONFIGMAP-CREDS-001:team-a:app-config:aws_secret_access_key",
		"KUBE-CONFIGMAP-CREDS-001:team-a:app-config:db_password",
		"KUBE-CONFIGMAP-CREDS-001:team-a:app-config:jwt_token",
	}
	for _, id := range wantIDs {
		if !findingHasID(findings, id) {
			t.Errorf("expected finding with ID %q, got %v", id, findingIDs(findings, "KUBE-CONFIGMAP-CREDS-001"))
		}
	}
}

func TestAnalyzeConfigMapHeuristicsSkipsKeyOnlyMatches(t *testing.T) {
	t.Parallel()

	// `cache_key` and `primary_key` should NOT match the high-confidence
	// list (the bare token `key` is intentionally absent).
	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			ConfigMaps: []models.ConfigMapSnapshot{
				{
					Name:      "app-config",
					Namespace: "team-a",
					Data: map[string]string{
						"cache_key":          "",
						"primary_key":        "",
						"license_key_format": "",
					},
				},
			},
		},
	}

	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	if got := countByRule(findings, "KUBE-CONFIGMAP-CREDS-001"); got != 0 {
		t.Fatalf("did not expect KUBE-CONFIGMAP-CREDS-001 for *_key-only matches, got %d", got)
	}
}

func TestIsHighConfidenceCredentialKeyCaseInsensitive(t *testing.T) {
	t.Parallel()

	for _, key := range []string{"PASSWORD", "DB_PASSWD", "ApiKey", "AWS_SECRET_ACCESS_KEY", "client.secret"} {
		if !isHighConfidenceCredentialKey(key) {
			t.Errorf("expected %q to match high-confidence list", key)
		}
	}

	for _, key := range []string{"username", "feature_flag", "cache_key", "key_name"} {
		if isHighConfidenceCredentialKey(key) {
			t.Errorf("did not expect %q to match high-confidence list", key)
		}
	}
}
