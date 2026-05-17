// Package eks holds EKS-specific cloud analyzers. Future slots add gke/ and aks/
// sibling packages with the same shape.
package eks

import "github.com/0hardik1/kubesplaining/internal/models"

// Analyze runs all EKS-specific analyzers and returns the combined findings.
// Each sub-analyzer is self-gating: aws-auth returns nil when the aws-auth
// ConfigMap is absent; IRSA emits per-SA findings only when the annotation is
// present; IMDS-pivot is provider-gated and Fargate-aware. The dispatcher in
// internal/analyzer/cloud/analyzer.go is responsible for the outer provider gate.
func Analyze(snapshot models.Snapshot) []models.Finding {
	var findings []models.Finding
	findings = append(findings, AnalyzeAWSAuth(snapshot)...)
	findings = append(findings, AnalyzeIRSA(snapshot)...)
	findings = append(findings, AnalyzeIMDSPivot(snapshot)...)
	return findings
}
