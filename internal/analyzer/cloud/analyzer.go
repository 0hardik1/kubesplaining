// Package cloud emits cloud-provider-aware findings. It dispatches by
// snapshot.Metadata.CloudProvider; this slot ships EKS detectors. Other providers
// are accepted but no-op.
package cloud

import (
	"context"

	"github.com/0hardik1/kubesplaining/internal/analyzer/cloud/eks"
	"github.com/0hardik1/kubesplaining/internal/models"
)

// _ references the foundation content helper so the `unused` linter stays
// happy while Units 1-3 land their per-rule helpers. Drop once a real rule
// consumes contentProviderUnknown (or replace with the new helpers).
var _ = contentProviderUnknown

// _ references the IMDS-pivot content helper (KUBE-CLOUD-IMDS-PIVOT-001). The
// rule is detected in internal/analyzer/cloud/eks/imds_pivot.go; the cloud-side
// helper holds the shared prose so a future coordinator can consume it without
// the eks sub-package needing to import its parent (which would create a cycle
// since cloud → eks). Drop once the coordinator wires content through.
var _ = contentImdsPivot001

// Analyzer dispatches cloud-provider-specific detectors based on the snapshot's
// detected (or operator-overridden) CloudProvider metadata field.
type Analyzer struct{}

// New constructs a cloud Analyzer. The returned value is stateless; callers can
// hold onto it for the lifetime of an engine and share it across scans.
func New() *Analyzer { return &Analyzer{} }

// Name is the short identifier the engine's --only-modules / --skip-modules
// flags match against.
func (a *Analyzer) Name() string { return "cloud" }

// Analyze inspects the snapshot's CloudProvider metadata and routes to the
// matching provider sub-package. Unknown / empty / "none" providers are silent
// no-ops so the module can stay registered everywhere without churning output.
func (a *Analyzer) Analyze(ctx context.Context, snapshot models.Snapshot) ([]models.Finding, error) {
	_ = ctx
	provider := snapshot.Metadata.CloudProvider
	var findings []models.Finding
	switch provider {
	case "eks":
		findings = append(findings, eks.Analyze(snapshot)...)
	case "gke", "aks":
		// reserved for future slots; intentional no-op
	case "", "none":
		// no provider context to act on; emit nothing.
	default:
		// unknown provider string; ignore silently
	}
	return findings, nil
}
