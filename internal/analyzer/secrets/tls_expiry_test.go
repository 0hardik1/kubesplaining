package secrets

import (
	"context"
	"testing"
	"time"

	"github.com/0hardik1/kubesplaining/internal/models"
	corev1 "k8s.io/api/core/v1"
)

func TestAnalyzeTLSExpiryFiresWithinWindow(t *testing.T) {
	frozenNow := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	withFrozenClock(t, frozenNow)

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			SecretsMetadata: []models.SecretMetadata{
				{
					Name: "ingress-cert", Namespace: "edge", Type: corev1.SecretTypeTLS,
					Annotations: map[string]string{
						"cert-manager.io/not-after": frozenNow.Add(15 * 24 * time.Hour).Format(time.RFC3339),
					},
				},
				{
					Name: "fresh-cert", Namespace: "edge", Type: corev1.SecretTypeTLS,
					Annotations: map[string]string{
						"cert-manager.io/not-after": frozenNow.Add(90 * 24 * time.Hour).Format(time.RFC3339),
					},
				},
			},
		},
	}

	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	if got := countByRule(findings, "KUBE-SECRETS-TLS-EXPIRY-001"); got != 1 {
		t.Fatalf("expected exactly 1 KUBE-SECRETS-TLS-EXPIRY-001 finding, got %d", got)
	}
	if !findingHasResource(findings, "KUBE-SECRETS-TLS-EXPIRY-001", "edge", "ingress-cert") {
		t.Fatalf("expected ingress-cert to be flagged for upcoming expiry")
	}
	if findingHasResource(findings, "KUBE-SECRETS-TLS-EXPIRY-001", "edge", "fresh-cert") {
		t.Fatalf("did not expect fresh-cert (90d out) to be flagged")
	}
}

func TestAnalyzeTLSExpiryFiresWhenExpired(t *testing.T) {
	frozenNow := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	withFrozenClock(t, frozenNow)

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			SecretsMetadata: []models.SecretMetadata{
				{
					Name: "expired-cert", Namespace: "edge", Type: corev1.SecretTypeTLS,
					Annotations: map[string]string{
						"cert-manager.io/not-after": frozenNow.Add(-7 * 24 * time.Hour).Format(time.RFC3339),
					},
				},
			},
		},
	}

	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	if countByRule(findings, "KUBE-SECRETS-TLS-EXPIRY-001") != 1 {
		t.Fatalf("expected exactly 1 KUBE-SECRETS-TLS-EXPIRY-001 finding for expired cert")
	}
}

func TestAnalyzeTLSExpirySkipsWithoutAnnotations(t *testing.T) {
	frozenNow := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	withFrozenClock(t, frozenNow)

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			SecretsMetadata: []models.SecretMetadata{
				{Name: "no-annotations", Namespace: "edge", Type: corev1.SecretTypeTLS},
				{Name: "unparseable", Namespace: "edge", Type: corev1.SecretTypeTLS, Annotations: map[string]string{
					"cert-manager.io/not-after": "not-a-timestamp",
				}},
			},
		},
	}

	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	if got := countByRule(findings, "KUBE-SECRETS-TLS-EXPIRY-001"); got != 0 {
		t.Fatalf("did not expect TLS expiry finding for secrets without parseable expiry annotation, got %d", got)
	}
}

func TestAnalyzeTLSExpirySkipsNonTLSSecret(t *testing.T) {
	frozenNow := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	withFrozenClock(t, frozenNow)

	snapshot := models.Snapshot{
		Resources: models.SnapshotResources{
			SecretsMetadata: []models.SecretMetadata{
				{
					Name: "opaque-with-expiry", Namespace: "edge", Type: corev1.SecretTypeOpaque,
					Annotations: map[string]string{
						"cert-manager.io/not-after": frozenNow.Add(5 * 24 * time.Hour).Format(time.RFC3339),
					},
				},
			},
		},
	}

	findings, err := New().Analyze(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	if countByRule(findings, "KUBE-SECRETS-TLS-EXPIRY-001") != 0 {
		t.Fatalf("did not expect TLS expiry finding for non-TLS secret type")
	}
}

func TestParseTLSExpiryAcceptsAlternateAnnotationKeys(t *testing.T) {
	t.Parallel()

	cases := []struct {
		key string
	}{
		{"cert-manager.io/not-after"},
		{"cert-manager.io/notafter"},
		{"cert-manager.io/expiration"},
	}
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			ts := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
			notAfter, ok := parseTLSExpiry(map[string]string{tc.key: ts.Format(time.RFC3339)})
			if !ok {
				t.Fatalf("expected to parse %q, got !ok", tc.key)
			}
			if !notAfter.Equal(ts) {
				t.Fatalf("expected %v, got %v", ts, notAfter)
			}
		})
	}
}

// withFrozenClock pins nowForTLSExpiry to a deterministic value for the
// duration of one test, restoring the original clock on test exit.
func withFrozenClock(t *testing.T, frozen time.Time) {
	t.Helper()
	prev := nowForTLSExpiry
	nowForTLSExpiry = func() time.Time { return frozen }
	t.Cleanup(func() { nowForTLSExpiry = prev })
}
