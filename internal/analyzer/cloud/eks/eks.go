// Package eks holds EKS-specific cloud analyzers. Future slots add gke/ and aks/
// sibling packages with the same shape.
package eks

import "github.com/0hardik1/kubesplaining/internal/models"

// Analyze runs all EKS-specific analyzers and returns the combined findings.
// Currently a no-op skeleton; Units 1, 2, 3 populate it.
func Analyze(snapshot models.Snapshot) []models.Finding {
	_ = snapshot
	var findings []models.Finding
	// future: append aws-auth, IRSA, IMDS-pivot findings here
	return findings
}
