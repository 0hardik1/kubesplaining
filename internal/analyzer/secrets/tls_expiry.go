// TLS-secret expiry detection: a `kubernetes.io/tls` Secret whose annotation
// metadata reports a certificate NotAfter within 30 days or already in the
// past. The collector's privacy contract (see CLAUDE.md) means raw Secret
// values are never read, so we cannot inspect tls.crt directly. Instead we
// rely on cert-manager's annotation conventions:
//
//   - cert-manager.io/not-after        (canonical, set by cert-manager v1.5+)
//   - cert-manager.io/notafter          (legacy/alternate spelling)
//   - cert-manager.io/expiration        (older convention seen in third-party
//     ACME controllers)
//
// Secrets without any of those annotations are silently skipped: the rule
// degrades to a no-op rather than firing on every TLS Secret in the cluster.
// The remediation prose is explicit about the best-effort framing.
package secrets

import (
	"context"
	"fmt"
	"time"

	"github.com/0hardik1/kubesplaining/internal/models"
	corev1 "k8s.io/api/core/v1"
)

// tlsExpiryWarningWindow is how far in advance of NotAfter we surface the
// finding. 30 days matches cert-manager's default renewBefore (≈ 360h, 15d)
// plus a one-week buffer that gives the platform team time to investigate
// renewal failures before the cert actually expires.
const tlsExpiryWarningWindow = 30 * 24 * time.Hour

// tlsExpiryAnnotationKeys lists the cert-manager-style annotation keys we
// will parse for a NotAfter timestamp, in priority order. The first one that
// exists and parses as RFC3339 wins.
var tlsExpiryAnnotationKeys = []string{
	"cert-manager.io/not-after",
	"cert-manager.io/notafter",
	"cert-manager.io/expiration",
}

// nowForTLSExpiry is overridable in tests so we can assert the 30-day boundary
// deterministically without freezing the system clock.
var nowForTLSExpiry = func() time.Time { return time.Now().UTC() }

// analyzeTLSExpiry emits one finding per TLS Secret whose annotation reports a
// NotAfter within the warning window or already in the past. Secrets without a
// parseable expiry annotation are silently skipped.
func (a *Analyzer) analyzeTLSExpiry(_ context.Context, snapshot models.Snapshot, findings []models.Finding, seen map[string]struct{}) []models.Finding {
	now := nowForTLSExpiry()
	cutoff := now.Add(tlsExpiryWarningWindow)

	for _, secret := range snapshot.Resources.SecretsMetadata {
		if secret.Type != corev1.SecretTypeTLS {
			continue
		}
		notAfter, ok := parseTLSExpiry(secret.Annotations)
		if !ok {
			continue
		}
		if notAfter.After(cutoff) {
			continue
		}
		expired := notAfter.Before(now)
		daysToExpiry := humanizeDuration(now, notAfter)
		findings = appendUnique(findings, seen, secretFinding(secret,
			"KUBE-SECRETS-TLS-EXPIRY-001", models.SeverityMedium, 5.6,
			map[string]any{
				"type":           secret.Type,
				"not_after":      notAfter.UTC().Format(time.RFC3339),
				"expired":        expired,
				"days_to_expiry": daysToExpiry,
			},
			"tlsExpiry",
			contentSecretsTLSExpiry001(secret, notAfter.UTC().Format(time.RFC3339), daysToExpiry, expired)))
	}

	return findings
}

// parseTLSExpiry returns the parsed NotAfter timestamp from any supported
// cert-manager annotation, or (zero, false) when no annotation is present /
// parseable. Both RFC3339 (cert-manager's canonical format) and the older
// time.RFC1123 fallback are tried.
func parseTLSExpiry(annotations map[string]string) (time.Time, bool) {
	if len(annotations) == 0 {
		return time.Time{}, false
	}
	for _, key := range tlsExpiryAnnotationKeys {
		raw, ok := annotations[key]
		if !ok || raw == "" {
			continue
		}
		for _, layout := range []string{time.RFC3339, time.RFC3339Nano, time.RFC1123, time.RFC1123Z} {
			if t, err := time.Parse(layout, raw); err == nil {
				return t.UTC(), true
			}
		}
	}
	return time.Time{}, false
}

// humanizeDuration renders the gap between now and notAfter as a short
// "<N>d" / "<H>h" / "<M>m" string suitable for the finding title and
// remediation prose. We round down to the dominant unit so a 29.9-day gap
// reads as "29d" rather than "29d 21h".
func humanizeDuration(now, notAfter time.Time) string {
	gap := notAfter.Sub(now)
	if gap < 0 {
		gap = -gap
	}
	switch {
	case gap >= 24*time.Hour:
		return fmt.Sprintf("%dd", int(gap/(24*time.Hour)))
	case gap >= time.Hour:
		return fmt.Sprintf("%dh", int(gap/time.Hour))
	case gap >= time.Minute:
		return fmt.Sprintf("%dm", int(gap/time.Minute))
	default:
		return "<1m"
	}
}
