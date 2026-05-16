// Package analyzer orchestrates the individual security analysis modules (rbac, podsec,
// network, admission, secrets, serviceaccount, privesc), runs them in parallel against a
// snapshot, filters by severity threshold, and returns a sorted finding list.
package analyzer

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"sync"

	"github.com/0hardik1/kubesplaining/internal/analyzer/admission"
	"github.com/0hardik1/kubesplaining/internal/analyzer/leastprivilege"
	"github.com/0hardik1/kubesplaining/internal/analyzer/network"
	"github.com/0hardik1/kubesplaining/internal/analyzer/podsec"
	"github.com/0hardik1/kubesplaining/internal/analyzer/privesc"
	"github.com/0hardik1/kubesplaining/internal/analyzer/rbac"
	"github.com/0hardik1/kubesplaining/internal/analyzer/secrets"
	"github.com/0hardik1/kubesplaining/internal/analyzer/serviceaccount"
	"github.com/0hardik1/kubesplaining/internal/compliance"
	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/scoring"
	"github.com/0hardik1/kubesplaining/internal/usage"
)

// Module is the contract each analysis module implements.
type Module interface {
	Name() string
	Analyze(ctx context.Context, snapshot models.Snapshot) ([]models.Finding, error)
}

// Options selects which modules run, sets a severity floor, tunes privesc path depth,
// chooses how the engine reacts to namespace-level admission controls, and threads the
// audit-log-derived usage index into the leastprivilege module.
type Options struct {
	OnlyModules     []string
	SkipModules     []string
	Threshold       models.Severity
	MaxPrivescDepth int
	// AdmissionMode controls the admission-aware reweight stage. Empty defaults to suppress.
	AdmissionMode AdmissionMode
	// UsageIndex carries the audit-log observations consumed by the leastprivilege
	// module. nil disables the module (it emits nothing); the CLI pre-flight in
	// scan.go errors out before we get here when --least-privilege-only is set
	// without --audit-log.
	UsageIndex *usage.UsageIndex
}

// Engine holds the set of registered analysis modules to run.
type Engine struct {
	modules []Module
}

// New returns an Engine configured with default module settings.
func New() *Engine {
	return NewWithConfig(Config{})
}

// Config tunes engine construction parameters like the privesc graph search depth.
type Config struct {
	MaxPrivescDepth int
}

// NewWithConfig constructs an Engine with the default module set, applying cfg to tunable
// modules. The leastprivilege module is registered with a nil UsageIndex here; Analyze
// rebinds it from opts.UsageIndex on each invocation so the same engine can serve runs
// with and without audit data.
func NewWithConfig(cfg Config) *Engine {
	privescMod := privesc.New()
	if cfg.MaxPrivescDepth > 0 {
		privescMod.MaxDepth = cfg.MaxPrivescDepth
	}
	return &Engine{
		modules: []Module{
			rbac.New(),
			podsec.New(),
			network.New(),
			admission.New(),
			secrets.New(),
			serviceaccount.New(),
			privescMod,
			leastprivilege.New(nil),
		},
	}
}

// Analyze runs the selected modules in parallel, applies admission-aware reweighting,
// correlates and dedupes the results, filters at or above the severity threshold, and
// returns them sorted by severity then score along with an AdmissionSummary describing
// what the reweight stage did.
//
// The pipeline is broken into four named stages below so a first-time reader can follow
// the data flow: snapshot → selected modules → raw findings → reweighted/correlated/
// deduped findings → sorted slice ready for the report writer.
func (e *Engine) Analyze(ctx context.Context, snapshot models.Snapshot, opts Options) (AnalyzeResult, error) {
	mode := opts.AdmissionMode
	if mode == "" {
		mode = AdmissionModeSuppress
	}

	selected, err := e.selectModules(opts)
	if err != nil {
		return AnalyzeResult{}, err
	}

	findings, firstErr := runModulesInParallel(ctx, snapshot, selected)

	findings, admissionSummary := postProcess(findings, snapshot, mode)

	filtered := filterByThreshold(findings, opts.Threshold)
	sortFindings(filtered)

	return AnalyzeResult{Findings: filtered, Admission: admissionSummary}, firstErr
}

// selectModules applies the --only-modules / --skip-modules filters and rebinds the
// leastprivilege module with the per-call UsageIndex. The engine itself is stateless on
// options; rebinding here keeps the module's audit data scoped to one Analyze call.
func (e *Engine) selectModules(opts Options) ([]Module, error) {
	selected := make([]Module, 0, len(e.modules))
	for _, module := range e.modules {
		if len(opts.OnlyModules) > 0 && !slices.Contains(opts.OnlyModules, module.Name()) {
			continue
		}
		if slices.Contains(opts.SkipModules, module.Name()) {
			continue
		}
		if module.Name() == "leastprivilege" {
			module = leastprivilege.New(opts.UsageIndex)
		}
		selected = append(selected, module)
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("no analysis modules selected")
	}
	return selected, nil
}

// runModulesInParallel fans out each module to its own goroutine, waits for all of them,
// and returns the merged findings slice. If any module returns an error, only the first
// one is reported; the other modules' findings still come back so a single misbehaving
// analyzer can't blank the whole report.
func runModulesInParallel(ctx context.Context, snapshot models.Snapshot, modules []Module) ([]models.Finding, error) {
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		findings []models.Finding
		firstErr error
	)
	for _, module := range modules {
		module := module
		wg.Add(1)
		go func() {
			defer wg.Done()
			moduleFindings, err := module.Analyze(ctx, snapshot)
			mu.Lock()
			defer mu.Unlock()
			if err != nil && firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", module.Name(), err)
			}
			findings = append(findings, moduleFindings...)
		}()
	}
	wg.Wait()
	return findings, firstErr
}

// postProcess runs the cross-module passes that need every module's output in one place:
// admission-aware reweighting, policy-engine presence tagging, chain-amplification
// correlation, and cross-module deduplication. Returns the surviving findings and the
// AdmissionSummary describing what the reweight stage did.
func postProcess(findings []models.Finding, snapshot models.Snapshot, mode AdmissionMode) ([]models.Finding, models.AdmissionSummary) {
	findings, admissionSummary := applyAdmissionMitigations(findings, snapshot, mode)
	findings, admissionSummary = applyPolicyEnginePresenceTags(findings, snapshot, admissionSummary, mode)
	findings = correlate(findings)
	findings = dedupe(findings)
	findings = compliance.Apply(findings)
	return findings, admissionSummary
}

// filterByThreshold drops findings whose severity falls below the operator-supplied
// threshold. We reuse the input slice's backing array (findings[:0]) because the input
// is no longer needed after this point - this avoids an allocation but is only safe
// because no later code reads the pre-filter slice.
func filterByThreshold(findings []models.Finding, threshold models.Severity) []models.Finding {
	filtered := findings[:0]
	for _, finding := range findings {
		if scoring.AboveThreshold(finding, threshold) {
			filtered = append(filtered, finding)
		}
	}
	return filtered
}

// sortFindings sorts in place by severity (descending), then score (descending), then
// rule ID (ascending), then title (ascending). Stable ordering matters: tests, golden
// files, and SARIF consumers all depend on the same input yielding the same output.
func sortFindings(findings []models.Finding) {
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Severity.Rank() != findings[j].Severity.Rank() {
			return findings[i].Severity.Rank() > findings[j].Severity.Rank()
		}
		if findings[i].Score != findings[j].Score {
			return findings[i].Score > findings[j].Score
		}
		if findings[i].RuleID != findings[j].RuleID {
			return findings[i].RuleID < findings[j].RuleID
		}
		return findings[i].Title < findings[j].Title
	})
}
