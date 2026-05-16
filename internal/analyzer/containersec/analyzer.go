package containersec

import (
	"context"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// Analyzer is the container-security module. The Wave 0 stub registers a no-op
// implementation in the engine's module slice so Wave 1 can fill in the rules
// without touching engine.go again. Returning (nil, nil) from Analyze keeps the
// finding count, JSON output, and HTML report byte-identical to a build without
// the stub registered.
type Analyzer struct{}

// New returns a container-security analyzer (currently a no-op stub).
func New() *Analyzer {
	return &Analyzer{}
}

// Name returns the module identifier used by --only-modules / --skip-modules
// and by the engine's module factory registry in internal/analyzer/modules.go.
func (a *Analyzer) Name() string {
	return "containersec"
}

// Analyze is a no-op stub for Wave 0. Wave 1 slot #9 will populate it with the
// container-hardening checks listed in the package doc comment.
func (a *Analyzer) Analyze(_ context.Context, _ models.Snapshot) ([]models.Finding, error) {
	return nil, nil
}
