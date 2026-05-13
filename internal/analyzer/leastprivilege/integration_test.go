package leastprivilege_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/0hardik1/kubesplaining/internal/analyzer"
	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/usage"
)

// TestIntegration_MinimalRiskySnapshot_EKSAudit pairs the shared minimal-risky snapshot
// fixture with a small EKS-shaped audit log and runs the full engine, asserting that the
// least-privilege module emits the expected verbs-unused finding.
//
// Fixture story:
//   - Snapshot has SA `default/reader` mounted in a Pod.
//   - ClusterRole `reader-role` grants `[get, list]` on secrets + `[create]` on pods.
//   - EKS audit fixture shows `reader` only ever doing `get secrets` (list never observed,
//     create pods is 403 → must NOT count as usage).
//   - Expected: KUBE-RBAC-UNUSED-VERB-001 for reader-role listing `list secrets` and
//     `create pods` as unused.
func TestIntegration_MinimalRiskySnapshot_EKSAudit(t *testing.T) {
	snapPath := repoRoot(t) + "/testdata/snapshots/minimal-risky.json"
	auditPath := repoRoot(t) + "/testdata/audit/eks/minimal-risky-eks-audit.json"

	snapBytes, err := os.ReadFile(snapPath)
	if err != nil {
		t.Fatal(err)
	}
	var snap models.Snapshot
	if err := json.Unmarshal(snapBytes, &snap); err != nil {
		t.Fatalf("decode snapshot: %v", err)
	}

	// Anchor "now" at the end of the audit-log day so the fixture's 2026-05-13 events
	// fall inside the 30-day window deterministically regardless of when the test runs.
	now := time.Date(2026, 5, 14, 0, 0, 0, 0, time.UTC)
	idx, warns, err := usage.LoadAuditLog([]string{auditPath}, usage.SourceEKS, 30*24*time.Hour, now)
	if err != nil {
		t.Fatalf("LoadAuditLog: %v", err)
	}
	if len(warns) != 0 {
		t.Logf("usage warnings (non-fatal): %v", warns)
	}
	if idx.EventsProcessed < 1 {
		t.Fatalf("expected at least one processed audit event, got %d (skipped=%d nonSA=%d)", idx.EventsProcessed, idx.EventsSkipped, idx.NonSAUsernames)
	}

	engine := analyzer.NewWithConfig(analyzer.Config{})
	result, err := engine.Analyze(context.Background(), snap, analyzer.Options{
		Threshold:  models.SeverityInfo,
		UsageIndex: idx,
	})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	var lpFinding *models.Finding
	for i := range result.Findings {
		if result.Findings[i].RuleID == "KUBE-RBAC-UNUSED-VERB-001" {
			lpFinding = &result.Findings[i]
			break
		}
	}
	if lpFinding == nil {
		t.Fatalf("expected KUBE-RBAC-UNUSED-VERB-001 finding, got rule IDs: %v", ruleIDs(result.Findings))
	}
	if lpFinding.Subject == nil || lpFinding.Subject.Name != "reader" {
		t.Errorf("finding Subject = %+v, want reader", lpFinding.Subject)
	}
	// Evidence should call out both unused verbs: `list secrets` and `create pods`.
	// The denied (403) create pods event must not have suppressed the finding.
	if got := string(lpFinding.Evidence); !contains(got, "secrets") || !contains(got, "pods") {
		t.Errorf("evidence missing unused triples; got: %s", got)
	}
	if got := string(lpFinding.Evidence); !contains(got, `"verb":"list"`) {
		t.Errorf("evidence should call out unused `list`; got: %s", got)
	}
	if got := string(lpFinding.Evidence); !contains(got, `"verb":"create"`) {
		t.Errorf("evidence should call out unused `create`; got: %s", got)
	}
}

func ruleIDs(fs []models.Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.RuleID
	}
	return out
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// repoRoot walks up from the test's working directory to find the repo root (the
// directory containing go.mod). Lets fixture paths work regardless of where `go test` is
// invoked from.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find go.mod walking up from " + dir)
		}
		dir = parent
	}
}
