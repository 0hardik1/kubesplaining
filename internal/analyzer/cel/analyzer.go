package cel

import (
	"context"

	"github.com/0hardik1/kubesplaining/internal/models"
	celrules "github.com/0hardik1/kubesplaining/internal/rules/cel"
)

// Analyzer is the engine-facing wrapper around the CEL custom-rules pipeline.
// It loads rules once at construction and replays them against every snapshot
// the engine hands to Analyze, so a long-running scan loop (which is not yet a
// shipping feature but is on the roadmap, per STRATEGY.md §9) avoids
// re-reading and re-compiling the rules file on every iteration.
type Analyzer struct {
	rulesDir string
	rules    []celrules.Rule
	loadErr  error
}

// New constructs an Analyzer pointed at rulesDir. If rulesDir == "" the
// analyzer becomes a no-op: Analyze returns (nil, nil) and the engine treats
// it like any other module that found nothing.
//
// A load error is recorded on the Analyzer rather than returned so the engine
// can construct the module without context. Analyze surfaces the error on the
// first invocation; the engine's runModulesInParallel reports the first error
// without dropping other modules' findings, so a broken rules pack does not
// hide an otherwise clean scan.
func New(rulesDir string) *Analyzer {
	a := &Analyzer{rulesDir: rulesDir}
	if rulesDir == "" {
		return a
	}
	rules, err := celrules.LoadDir(rulesDir)
	if err != nil {
		a.loadErr = err
		return a
	}
	a.rules = rules
	return a
}

// Name returns the module identifier surfaced to --only-modules /
// --skip-modules. The operator-facing name is "custom-rules" so the CLI flag
// reads naturally ("--skip-modules custom-rules") even though the package
// itself is "cel".
func (a *Analyzer) Name() string {
	return "custom-rules"
}

// Analyze applies every loaded rule to snapshot and returns the resulting
// findings. The first call after construction surfaces any load error
// recorded by New; subsequent calls just replay the evaluation, so a single
// engine instance can be reused across multiple snapshots.
func (a *Analyzer) Analyze(_ context.Context, snapshot models.Snapshot) ([]models.Finding, error) {
	if a.loadErr != nil {
		return nil, a.loadErr
	}
	if len(a.rules) == 0 {
		return nil, nil
	}
	return celrules.Evaluate(a.rules, snapshot)
}
