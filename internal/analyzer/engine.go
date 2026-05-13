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
func (e *Engine) Analyze(ctx context.Context, snapshot models.Snapshot, opts Options) (AnalyzeResult, error) {
	mode := opts.AdmissionMode
	if mode == "" {
		mode = AdmissionModeSuppress
	}

	selected := make([]Module, 0, len(e.modules))
	for _, module := range e.modules {
		if len(opts.OnlyModules) > 0 && !slices.Contains(opts.OnlyModules, module.Name()) {
			continue
		}
		if slices.Contains(opts.SkipModules, module.Name()) {
			continue
		}
		// Rebind the leastprivilege module with the per-call UsageIndex. The engine
		// itself is stateless on options; this keeps the module's audit data scoped
		// to one Analyze call.
		if module.Name() == "leastprivilege" {
			module = leastprivilege.New(opts.UsageIndex)
		}
		selected = append(selected, module)
	}

	if len(selected) == 0 {
		return AnalyzeResult{}, fmt.Errorf("no analysis modules selected")
	}

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		findings []models.Finding
		firstErr error
	)

	for _, module := range selected {
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

	findings, admissionSummary := applyAdmissionMitigations(findings, snapshot, mode)
	findings, admissionSummary = applyPolicyEnginePresenceTags(findings, snapshot, admissionSummary, mode)
	findings = correlate(findings)
	findings = dedupe(findings)

	filtered := findings[:0]
	for _, finding := range findings {
		if scoring.AboveThreshold(finding, opts.Threshold) {
			filtered = append(filtered, finding)
		}
	}

	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].Severity.Rank() != filtered[j].Severity.Rank() {
			return filtered[i].Severity.Rank() > filtered[j].Severity.Rank()
		}
		if filtered[i].Score != filtered[j].Score {
			return filtered[i].Score > filtered[j].Score
		}
		if filtered[i].RuleID != filtered[j].RuleID {
			return filtered[i].RuleID < filtered[j].RuleID
		}
		return filtered[i].Title < filtered[j].Title
	})

	return AnalyzeResult{Findings: filtered, Admission: admissionSummary}, firstErr
}
