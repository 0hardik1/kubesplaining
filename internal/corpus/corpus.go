// Package corpus scores the analyzer engine against labeled ground-truth
// snapshots so precision and recall become measurable, and so a regression in
// either direction (a new false positive, or a lost true finding) fails the
// build.
//
// Each case is a testdata/corpus/<name>/labels.json file that names a
// deterministic snapshot, the complete set of finding IDs that SHOULD fire (the
// positive ground truth), and a deny list of finding-ID prefixes that must
// never fire (benign resources the tool must not over-flag). The engine runs
// in-process, and analyzers never touch the network (collector -> snapshot ->
// analyzer), so scoring is bit-deterministic and needs no cluster: the same
// snapshot always yields the same finding-ID set.
//
// Precision and recall are computed against Expected as the *complete* correct
// set for the snapshot:
//
//	TP = actual ∩ expected      FP = actual \ expected      FN = expected \ actual
//	precision = TP / (TP + FP)  recall = TP / (TP + FN)
//
// A false positive is therefore any finding the engine emits that the ground
// truth did not sanction; a recall miss is any sanctioned finding the engine
// dropped. The independently-authored Deny list is a second, stricter guard: it
// catches known false-positive shapes even if someone lazily regenerates
// Expected straight from current output.
package corpus

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/analyzer"
	"github.com/0hardik1/kubesplaining/internal/collector"
	"github.com/0hardik1/kubesplaining/internal/models"
)

// Case is one labeled corpus entry loaded from a labels.json file.
type Case struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	// Snapshot is a repo-root-relative path to the snapshot JSON the engine
	// runs against. Cases reference the shared testdata/snapshots fixtures so
	// there is a single source of truth rather than a per-case copy that can
	// drift.
	Snapshot string  `json:"snapshot"`
	Options  Options `json:"options"`
	// Expected is the complete set of finding IDs that SHOULD fire for this
	// snapshot (the positive ground truth). Anything the engine emits that is
	// not here counts as a false positive.
	Expected []string `json:"expected"`
	// Deny lists finding-ID prefixes that must never appear. A deny entry
	// matches a finding when its ID equals the entry or begins with the entry
	// followed by ':' — so a bare rule ID bans every instance of that rule,
	// while a rule:subject prefix bans one specific instance.
	Deny []string `json:"deny"`
	// MinPrecisionGate / MinRecallGate are the per-case gates. nil defaults to
	// 1.0: these snapshots are small and fully understood, so any drift should
	// fail. Read them through the MinPrecision / MinRecall accessors.
	MinPrecisionGate *float64 `json:"min_precision"`
	MinRecallGate    *float64 `json:"min_recall"`

	// dir is the directory labels.json was loaded from; used for error context.
	dir string
}

// Options mirrors the subset of analyzer.Options a corpus case needs to pin so
// a run is reproducible. Zero values reproduce the CLI defaults (privesc depth
// 5, admission mode "suppress").
type Options struct {
	MaxPrivescDepth int    `json:"max_privesc_depth"`
	AdmissionMode   string `json:"admission_mode"`
}

// Result is the outcome of scoring one case against the live engine output.
type Result struct {
	Case      Case
	Actual    []string // sorted finding IDs the engine emitted
	TP        int
	FP        int
	FN        int
	Precision float64
	Recall    float64
	F1        float64
	// FalsePositives is actual \ expected (sorted); Missed is expected \ actual
	// (sorted); DenyViolations is every actual ID that matched a Deny entry.
	FalsePositives []string
	Missed         []string
	DenyViolations []string
}

// MinPrecision returns the case's precision gate, defaulting to 1.0.
func (c Case) MinPrecision() float64 {
	if c.MinPrecisionGate != nil {
		return *c.MinPrecisionGate
	}
	return 1.0
}

// MinRecall returns the case's recall gate, defaulting to 1.0.
func (c Case) MinRecall() float64 {
	if c.MinRecallGate != nil {
		return *c.MinRecallGate
	}
	return 1.0
}

// Pass reports whether the result clears both gates and trips no deny rule.
func (r Result) Pass() bool {
	return len(r.DenyViolations) == 0 &&
		r.Precision >= r.Case.MinPrecision() &&
		r.Recall >= r.Case.MinRecall()
}

// FindRepoRoot walks up from start until it finds a directory containing go.mod,
// returning that directory. Tests use it to resolve repo-root-relative paths
// regardless of the working directory the test binary runs in.
func FindRepoRoot(start string) (string, error) {
	dir, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found above %s", start)
		}
		dir = parent
	}
}

// LoadCases reads every <name>/labels.json under corpusDir and returns the cases
// sorted by name. A directory without a labels.json is skipped silently so the
// corpus dir can also hold a README or shared fixtures.
func LoadCases(corpusDir string) ([]Case, error) {
	entries, err := os.ReadDir(corpusDir)
	if err != nil {
		return nil, err
	}
	var cases []Case
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		path := filepath.Join(corpusDir, e.Name(), "labels.json")
		raw, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		var c Case
		if err := json.Unmarshal(raw, &c); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		c.dir = filepath.Join(corpusDir, e.Name())
		if c.Name == "" {
			c.Name = e.Name()
		}
		cases = append(cases, c)
	}
	sort.Slice(cases, func(i, j int) bool { return cases[i].Name < cases[j].Name })
	return cases, nil
}

// Run loads the case's snapshot, runs the analyzer engine in-process with the
// same defaults as the CLI, and scores the emitted finding IDs against the
// case's Expected and Deny sets. repoRoot resolves the case's snapshot path.
//
// The engine runs with no exclusions applied and the lowest severity threshold,
// so the score reflects raw analyzer behavior; exclusion presets are a separate
// concern and would only mask what the corpus is meant to measure.
func (c Case) Run(ctx context.Context, repoRoot string) (Result, error) {
	snapshot, err := collector.ReadSnapshot(filepath.Join(repoRoot, filepath.FromSlash(c.Snapshot)))
	if err != nil {
		return Result{}, fmt.Errorf("case %s: read snapshot: %w", c.Name, err)
	}

	mode, err := parseAdmissionMode(c.Options.AdmissionMode)
	if err != nil {
		return Result{}, fmt.Errorf("case %s: %w", c.Name, err)
	}

	engine := analyzer.NewWithConfig(analyzer.Config{MaxPrivescDepth: c.Options.MaxPrivescDepth})
	analysis, err := engine.Analyze(ctx, snapshot, analyzer.Options{
		Threshold:     models.SeverityInfo, // lowest rank -> keep every finding
		AdmissionMode: mode,
	})
	if err != nil {
		return Result{}, fmt.Errorf("case %s: analyze: %w", c.Name, err)
	}

	actual := make([]string, 0, len(analysis.Findings))
	for _, f := range analysis.Findings {
		actual = append(actual, f.ID)
	}
	sort.Strings(actual)

	return score(c, actual), nil
}

// parseAdmissionMode maps the labels.json string to an analyzer.AdmissionMode,
// treating the empty string as the engine default rather than an error.
func parseAdmissionMode(s string) (analyzer.AdmissionMode, error) {
	if strings.TrimSpace(s) == "" {
		return "", nil // engine defaults to suppress
	}
	mode, ok := analyzer.ParseAdmissionMode(s)
	if !ok {
		return "", fmt.Errorf("invalid admission_mode %q", s)
	}
	return mode, nil
}

// score computes precision/recall/F1 and deny violations for one case given the
// engine's actual finding-ID set. Split out from Run so it is unit-testable
// without a snapshot.
func score(c Case, actual []string) Result {
	expectedSet := make(map[string]bool, len(c.Expected))
	for _, id := range c.Expected {
		expectedSet[id] = true
	}
	actualSet := make(map[string]bool, len(actual))
	for _, id := range actual {
		actualSet[id] = true
	}

	res := Result{Case: c, Actual: actual}
	for _, id := range actual {
		if expectedSet[id] {
			res.TP++
		} else {
			res.FP++
			res.FalsePositives = append(res.FalsePositives, id)
		}
		if d := matchDeny(id, c.Deny); d != "" {
			res.DenyViolations = append(res.DenyViolations, fmt.Sprintf("%s (deny: %s)", id, d))
		}
	}
	for _, id := range c.Expected {
		if !actualSet[id] {
			res.FN++
			res.Missed = append(res.Missed, id)
		}
	}
	sort.Strings(res.FalsePositives)
	sort.Strings(res.Missed)
	sort.Strings(res.DenyViolations)

	res.Precision = ratio(res.TP, res.TP+res.FP)
	res.Recall = ratio(res.TP, res.TP+res.FN)
	if res.Precision+res.Recall > 0 {
		res.F1 = 2 * res.Precision * res.Recall / (res.Precision + res.Recall)
	}
	return res
}

// ratio returns num/den, treating 0/0 as 1.0: a case that expects nothing and
// finds nothing is perfectly precise and complete, not undefined.
func ratio(num, den int) float64 {
	if den == 0 {
		return 1.0
	}
	return float64(num) / float64(den)
}

// matchDeny returns the deny entry a finding ID trips, or "" if none. An entry
// matches when the ID equals it or begins with it followed by ':', so a bare
// rule ID bans every instance and a rule:subject prefix bans one instance.
func matchDeny(id string, deny []string) string {
	for _, d := range deny {
		if id == d || strings.HasPrefix(id, d+":") {
			return d
		}
	}
	return ""
}

// Report renders a one-line summary plus, when the case fails, the specific IDs
// that drove the failure. It is written for a test log: actionable, greppable,
// no color.
func (r Result) Report() string {
	var b strings.Builder
	status := "PASS"
	if !r.Pass() {
		status = "FAIL"
	}
	fmt.Fprintf(&b, "%s  %-22s P=%.3f R=%.3f F1=%.3f  (TP=%d FP=%d FN=%d deny=%d, gate P>=%.2f R>=%.2f)",
		status, r.Case.Name, r.Precision, r.Recall, r.F1,
		r.TP, r.FP, r.FN, len(r.DenyViolations), r.Case.MinPrecision(), r.Case.MinRecall())
	for _, v := range r.DenyViolations {
		fmt.Fprintf(&b, "\n    deny-violation: %s", v)
	}
	for _, fp := range r.FalsePositives {
		fmt.Fprintf(&b, "\n    false-positive: %s", fp)
	}
	for _, m := range r.Missed {
		fmt.Fprintf(&b, "\n    recall-miss:    %s", m)
	}
	return b.String()
}
