// ConfigMap credential-key detection (per-key, high-confidence variant).
//
// The existing KUBE-CONFIGMAP-001 rule emits a single finding per ConfigMap
// listing every credential-shaped key (uses a permissive substring list
// including "key", which catches many false positives). This rule
// (KUBE-CONFIGMAP-CREDS-001) instead emits one finding per (ConfigMap, key)
// pair using a *high-confidence* token list: keys that are almost always
// real credentials when they appear in a config, e.g. `password`, `passwd`,
// `secret`, `token`, `apikey` / `api_key`, `dsn`, `connection_string`,
// `aws_secret_access_key`. Severity is HIGH because matches are rarely false
// positives (in contrast to KUBE-CONFIGMAP-001's MEDIUM, which has to live
// with `key`-style false positives).
//
// Per the privacy contract in CLAUDE.md, the collector blanks ConfigMap
// values to empty strings; this rule operates on key names only.
package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// highConfidenceCredentialKeys lists key-name fragments that, when seen
// anywhere in a ConfigMap key, almost always indicate a real credential.
// We deliberately omit the bare token "key" (which produces false positives
// like "cache_key", "primary_key", "license_key_format") because that case
// is already covered by KUBE-CONFIGMAP-001's permissive list.
var highConfidenceCredentialKeys = []string{
	"password",
	"passwd",
	"secret",
	"token",
	"apikey",
	"api_key",
	"aws_secret_access_key",
	"dsn",
	"connection_string",
	"client_secret",
	"private_key",
	"access_key",
}

// analyzeConfigMapHeuristics emits one finding per (ConfigMap, matching key)
// pair. Multiple matches on the same ConfigMap surface as multiple findings
// so the operator can triage them individually.
func (a *Analyzer) analyzeConfigMapHeuristics(_ context.Context, snapshot models.Snapshot, findings []models.Finding, seen map[string]struct{}) []models.Finding {
	for _, configMap := range snapshot.Resources.ConfigMaps {
		if len(configMap.Data) == 0 {
			continue
		}
		matchedKeys := highConfidenceMatches(configMap.Data)
		for _, key := range matchedKeys {
			findingID := fmt.Sprintf("KUBE-CONFIGMAP-CREDS-001:%s:%s:%s", configMap.Namespace, configMap.Name, key)
			if _, ok := seen[findingID]; ok {
				continue
			}
			findings = appendUnique(findings, seen, configMapHeuristicFinding(configMap, key, findingID))
		}
	}
	return findings
}

// highConfidenceMatches returns the sorted list of ConfigMap data keys whose
// normalized name contains a high-confidence credential token. Sorting
// guarantees deterministic finding emission order.
func highConfidenceMatches(data map[string]string) []string {
	matches := make([]string, 0)
	for key := range data {
		if isHighConfidenceCredentialKey(key) {
			matches = append(matches, key)
		}
	}
	sort.Strings(matches)
	return matches
}

// isHighConfidenceCredentialKey reports whether a single key name matches
// any high-confidence credential token. Comparison is case-insensitive and
// uses a normalized form so `dbPasswd`, `DB_PASSWD`, and `db.passwd` all
// match the `passwd` token.
func isHighConfidenceCredentialKey(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	for _, token := range highConfidenceCredentialKeys {
		if strings.Contains(normalized, token) {
			return true
		}
	}
	return false
}

// configMapHeuristicFinding builds the per-key configmap finding. We can't
// reuse configMapFinding because that helper produces a deterministic ID
// keyed only on (namespace, name); per-key emission needs the key in the ID
// to stay unique.
func configMapHeuristicFinding(configMap models.ConfigMapSnapshot, matchedKey, findingID string) models.Finding {
	content := contentConfigMapCreds001(configMap, matchedKey)
	evidence := map[string]any{
		"matched_key": matchedKey,
		"namespace":   configMap.Namespace,
	}
	evidenceBytes, _ := json.Marshal(evidence)
	return models.Finding{
		ID:          findingID,
		RuleID:      "KUBE-CONFIGMAP-CREDS-001",
		Severity:    models.SeverityHigh,
		Score:       7.4,
		Category:    models.CategoryDataExfiltration,
		Title:       content.Title,
		Description: content.Description,
		Namespace:   configMap.Namespace,
		Resource: &models.ResourceRef{
			Kind:      "ConfigMap",
			Name:      configMap.Name,
			Namespace: configMap.Namespace,
		},
		Scope:            content.Scope,
		Impact:           content.Impact,
		AttackScenario:   content.AttackScenario,
		Evidence:         evidenceBytes,
		Remediation:      content.Remediation,
		RemediationSteps: content.RemediationSteps,
		References:       referencesFromContent(content),
		LearnMore:        content.LearnMore,
		MitreTechniques:  content.MitreTechniques,
		Tags:             []string{"module:secrets", "check:configMapHighConfidenceCredential"},
	}
}
