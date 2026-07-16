package corpus

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestCorpusPrecisionRecall runs every labeled case under testdata/corpus/
// through the analyzer engine and fails if any case drops below its precision
// or recall gate, or trips a deny rule. This is the deterministic (Docker-free)
// counterpart to the live-kind e2e: it measures precision/recall, which the
// shell harness cannot, and it runs as part of `go test ./...`.
func TestCorpusPrecisionRecall(t *testing.T) {
	root, err := FindRepoRoot(".")
	if err != nil {
		t.Fatalf("locate repo root: %v", err)
	}
	corpusDir := filepath.Join(root, "testdata", "corpus")
	cases, err := LoadCases(corpusDir)
	if err != nil {
		t.Fatalf("load corpus cases from %s: %v", corpusDir, err)
	}
	if len(cases) == 0 {
		t.Fatalf("no corpus cases found under %s", corpusDir)
	}

	for _, c := range cases {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			res, err := c.Run(context.Background(), root)
			if err != nil {
				t.Fatalf("run case: %v", err)
			}
			// Always log the scorecard so `go test -v ./internal/corpus/...`
			// prints precision/recall even on a pass.
			t.Log("\n" + res.Report())

			for _, v := range res.DenyViolations {
				t.Errorf("deny violation: %s", v)
			}
			if res.Precision < c.MinPrecision() {
				t.Errorf("precision %.3f below gate %.3f; %d new false positive(s): %v",
					res.Precision, c.MinPrecision(), len(res.FalsePositives), res.FalsePositives)
			}
			if res.Recall < c.MinRecall() {
				t.Errorf("recall %.3f below gate %.3f; %d expected finding(s) missing: %v",
					res.Recall, c.MinRecall(), len(res.Missed), res.Missed)
			}
		})
	}
}

// TestScore covers the precision/recall/deny math without touching a snapshot,
// so the scoring contract is pinned independently of any fixture's output.
func TestScore(t *testing.T) {
	minHalf := 0.5
	cases := []struct {
		name          string
		c             Case
		actual        []string
		wantTP        int
		wantFP        int
		wantFN        int
		wantPrecision float64
		wantRecall    float64
		wantDeny      int
	}{
		{
			name:          "perfect match",
			c:             Case{Expected: []string{"A:x", "B:y"}},
			actual:        []string{"A:x", "B:y"},
			wantTP:        2,
			wantPrecision: 1.0,
			wantRecall:    1.0,
		},
		{
			name:          "one false positive",
			c:             Case{Expected: []string{"A:x"}},
			actual:        []string{"A:x", "C:z"},
			wantTP:        1,
			wantFP:        1,
			wantPrecision: 0.5,
			wantRecall:    1.0,
		},
		{
			name:          "one recall miss",
			c:             Case{Expected: []string{"A:x", "B:y"}},
			actual:        []string{"A:x"},
			wantTP:        1,
			wantFN:        1,
			wantPrecision: 1.0,
			wantRecall:    0.5,
		},
		{
			name:          "empty expected and actual is perfect",
			c:             Case{Expected: nil},
			actual:        nil,
			wantPrecision: 1.0,
			wantRecall:    1.0,
		},
		{
			name:          "deny by bare rule id bans every instance",
			c:             Case{Expected: []string{"A:x"}, Deny: []string{"A"}},
			actual:        []string{"A:x"},
			wantTP:        1,
			wantPrecision: 1.0,
			wantRecall:    1.0,
			wantDeny:      1,
		},
		{
			name:          "deny prefix bans one instance, not a sibling",
			c:             Case{Expected: []string{"A:ns:keep"}, Deny: []string{"A:ns:ban"}},
			actual:        []string{"A:ns:keep", "A:ns:ban:sink"},
			wantTP:        1,
			wantFP:        1, // A:ns:ban:sink is not expected
			wantPrecision: 0.5,
			wantRecall:    1.0,
			wantDeny:      1,
		},
		{
			name:          "min gates honored via nil default",
			c:             Case{Expected: []string{"A:x", "B:y"}, MinPrecisionGate: &minHalf, MinRecallGate: &minHalf},
			actual:        []string{"A:x"},
			wantTP:        1,
			wantFN:        1,
			wantPrecision: 1.0,
			wantRecall:    0.5,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := score(tc.c, tc.actual)
			if r.TP != tc.wantTP || r.FP != tc.wantFP || r.FN != tc.wantFN {
				t.Errorf("TP/FP/FN = %d/%d/%d, want %d/%d/%d", r.TP, r.FP, r.FN, tc.wantTP, tc.wantFP, tc.wantFN)
			}
			if r.Precision != tc.wantPrecision {
				t.Errorf("precision = %.3f, want %.3f", r.Precision, tc.wantPrecision)
			}
			if r.Recall != tc.wantRecall {
				t.Errorf("recall = %.3f, want %.3f", r.Recall, tc.wantRecall)
			}
			if len(r.DenyViolations) != tc.wantDeny {
				t.Errorf("deny violations = %d, want %d (%v)", len(r.DenyViolations), tc.wantDeny, r.DenyViolations)
			}
		})
	}
}

func TestFindRepoRoot(t *testing.T) {
	root, err := FindRepoRoot(".")
	if err != nil {
		t.Fatalf("FindRepoRoot: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Errorf("returned root %q has no go.mod: %v", root, err)
	}
}
