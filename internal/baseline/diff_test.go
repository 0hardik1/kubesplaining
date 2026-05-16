package baseline

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
)

func newFinding(id, ruleID string, severity models.Severity, score float64) models.Finding {
	return models.Finding{
		ID:       id,
		RuleID:   ruleID,
		Severity: severity,
		Score:    score,
		Title:    ruleID,
	}
}

func ids(findings []models.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.ID)
	}
	return out
}

func TestDiff(t *testing.T) {
	t.Parallel()

	a := newFinding("KUBE-PODSEC-PRIV-001:default:a", "KUBE-PODSEC-PRIV-001", models.SeverityHigh, 8.0)
	b := newFinding("KUBE-RBAC-OVERBROAD-001:cluster:b", "KUBE-RBAC-OVERBROAD-001", models.SeverityCritical, 9.5)
	c := newFinding("KUBE-PRIVESC-PATH-CLUSTER-ADMIN:default:c", "KUBE-PRIVESC-PATH-CLUSTER-ADMIN", models.SeverityCritical, 9.8)
	d := newFinding("KUBE-NETPOL-COVERAGE-001:default:d", "KUBE-NETPOL-COVERAGE-001", models.SeverityMedium, 5.0)

	tests := []struct {
		name              string
		old               []models.Finding
		new               []models.Finding
		wantAdded         []string
		wantResolved      []string
		wantUnchanged     []string
		wantPrivescPaths  int
		wantAddedCritical int
	}{
		{
			name:              "empty inputs",
			old:               nil,
			new:               nil,
			wantAdded:         nil,
			wantResolved:      nil,
			wantUnchanged:     nil,
			wantPrivescPaths:  0,
			wantAddedCritical: 0,
		},
		{
			name:              "identical inputs are all unchanged",
			old:               []models.Finding{a, b},
			new:               []models.Finding{a, b},
			wantAdded:         nil,
			wantResolved:      nil,
			wantUnchanged:     []string{b.ID, a.ID}, // sorted by severity rank desc then score desc
			wantPrivescPaths:  0,
			wantAddedCritical: 0,
		},
		{
			name:              "all added when old is empty",
			old:               nil,
			new:               []models.Finding{a, b, c},
			wantAdded:         []string{c.ID, b.ID, a.ID}, // critical (9.8), critical (9.5), high (8.0)
			wantResolved:      nil,
			wantUnchanged:     nil,
			wantPrivescPaths:  1,
			wantAddedCritical: 2,
		},
		{
			name:              "all resolved when new is empty",
			old:               []models.Finding{a, b},
			new:               nil,
			wantAdded:         nil,
			wantResolved:      []string{b.ID, a.ID},
			wantUnchanged:     nil,
			wantPrivescPaths:  0,
			wantAddedCritical: 0,
		},
		{
			name:              "mixed added resolved unchanged",
			old:               []models.Finding{a, b, d}, // a, b, d
			new:               []models.Finding{a, c},    // a unchanged, c added, b+d resolved
			wantAdded:         []string{c.ID},
			wantResolved:      []string{b.ID, d.ID}, // critical, medium
			wantUnchanged:     []string{a.ID},
			wantPrivescPaths:  1,
			wantAddedCritical: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := Diff(tc.old, tc.new)

			if !equalIDs(ids(got.Added), tc.wantAdded) {
				t.Errorf("Added IDs = %v, want %v", ids(got.Added), tc.wantAdded)
			}
			if !equalIDs(ids(got.Resolved), tc.wantResolved) {
				t.Errorf("Resolved IDs = %v, want %v", ids(got.Resolved), tc.wantResolved)
			}
			if !equalIDs(ids(got.Unchanged), tc.wantUnchanged) {
				t.Errorf("Unchanged IDs = %v, want %v", ids(got.Unchanged), tc.wantUnchanged)
			}

			if n := CountNewPrivescPaths(got.Added); n != tc.wantPrivescPaths {
				t.Errorf("CountNewPrivescPaths = %d, want %d", n, tc.wantPrivescPaths)
			}

			if s := SummarizeSeverities(got.Added); s.Critical != tc.wantAddedCritical {
				t.Errorf("Added Critical count = %d, want %d", s.Critical, tc.wantAddedCritical)
			}
		})
	}
}

func TestDiff_DeterministicOrder(t *testing.T) {
	t.Parallel()

	// Two findings with identical severity/score must sort by RuleID asc, then ID asc.
	f1 := newFinding("BBB", "KUBE-RBAC-OVERBROAD-001", models.SeverityHigh, 7.0)
	f2 := newFinding("AAA", "KUBE-PODSEC-PRIV-001", models.SeverityHigh, 7.0)
	f3 := newFinding("CCC", "KUBE-PODSEC-PRIV-001", models.SeverityHigh, 7.0)

	got := Diff(nil, []models.Finding{f1, f2, f3})

	// Expected order: PODSEC < RBAC (rule asc), then within PODSEC AAA < CCC (ID asc).
	wantOrder := []string{"AAA", "CCC", "BBB"}
	if !equalIDs(ids(got.Added), wantOrder) {
		t.Errorf("Added order = %v, want %v", ids(got.Added), wantOrder)
	}
}

func TestLoadFindings(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()

	f := newFinding("X:default:a", "KUBE-PODSEC-PRIV-001", models.SeverityHigh, 8.0)
	arrayPayload, err := json.Marshal([]models.Finding{f})
	if err != nil {
		t.Fatalf("marshal array: %v", err)
	}
	arrayPath := filepath.Join(tmp, "array.json")
	if err := os.WriteFile(arrayPath, arrayPayload, 0o600); err != nil {
		t.Fatalf("write array: %v", err)
	}

	wrapped, err := json.Marshal(map[string]any{
		"findings": []models.Finding{f},
		"metadata": map[string]string{"cluster": "x"},
	})
	if err != nil {
		t.Fatalf("marshal wrapped: %v", err)
	}
	wrappedPath := filepath.Join(tmp, "wrapped.json")
	if err := os.WriteFile(wrappedPath, wrapped, 0o600); err != nil {
		t.Fatalf("write wrapped: %v", err)
	}

	emptyPath := filepath.Join(tmp, "empty.json")
	if err := os.WriteFile(emptyPath, []byte("   \n\t  "), 0o600); err != nil {
		t.Fatalf("write empty: %v", err)
	}

	bogusPath := filepath.Join(tmp, "bogus.json")
	if err := os.WriteFile(bogusPath, []byte("\"not an object or array\""), 0o600); err != nil {
		t.Fatalf("write bogus: %v", err)
	}

	cases := []struct {
		name    string
		path    string
		wantLen int
		wantErr bool
	}{
		{"bare array", arrayPath, 1, false},
		{"object wrapper", wrappedPath, 1, false},
		{"empty file", emptyPath, 0, true},
		{"scalar JSON", bogusPath, 0, true},
		{"missing file", filepath.Join(tmp, "missing.json"), 0, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := LoadFindings(tc.path)
			if (err != nil) != tc.wantErr {
				t.Fatalf("LoadFindings err = %v, wantErr = %v", err, tc.wantErr)
			}
			if !tc.wantErr && len(got) != tc.wantLen {
				t.Errorf("len(got) = %d, want %d", len(got), tc.wantLen)
			}
		})
	}
}

// equalIDs compares two ID slices, treating a nil and an empty slice as equal.
func equalIDs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
