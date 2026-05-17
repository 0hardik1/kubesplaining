// Package cloud - per-rule prose content. Each helper returns the title, description,
// impact, remediation prose, ordered remediation steps, MITRE techniques, and learn-more
// references for one rule ID. Units 1-3 append per-rule helpers below; this file
// currently holds only the shared ruleContent shape and the PROVIDER-UNKNOWN
// content placeholder so the cloud module compiles in isolation.
package cloud

import "github.com/0hardik1/kubesplaining/internal/models"

// ruleContent mirrors the shape used by the other analyzer packages (e.g.
// internal/analyzer/network/content.go) so report-layer renderers can treat
// cloud findings the same as any other. Keep the field set in sync when
// new content axes (e.g. compliance mappings) are added cluster-wide.
type ruleContent struct {
	Title            string
	Scope            models.Scope
	Description      string
	Impact           string
	AttackScenario   []string
	Remediation      string
	RemediationSteps []string
	LearnMore        []models.Reference
	MitreTechniques  []models.MitreTechnique
}

// contentProviderUnknown is the placeholder ruleContent for the
// "cloud provider could not be auto-detected" rule. Reserved for a future
// slot; included here so the package has one concrete helper and the
// ruleContent type is exercised (keeps the linter from flagging it dead).
func contentProviderUnknown() ruleContent {
	return ruleContent{
		Title: "Cloud provider could not be auto-detected from the snapshot",
		Scope: models.Scope{
			Level:  models.ScopeCluster,
			Detail: "Cluster-wide: no node labels or kube-system ConfigMaps matched a known cloud provider signature",
		},
		Description: "Kubesplaining inspects node labels (eks.amazonaws.com/*, cloud.google.com/gke-*, kubernetes.azure.com/*) and the aws-auth ConfigMap in kube-system to identify the cluster's cloud provider. None of these signals were present in this snapshot, so provider-specific detectors did not run. If the cluster is hosted on a managed Kubernetes service, pass --cloud-provider explicitly to enable the matching rules.",
		Impact:      "Provider-specific findings (aws-auth misconfigurations, IRSA over-permissioning, IMDS pivot risk, ...) are silently skipped, leaving cloud-side privilege escalation paths uncovered.",
		Remediation: "Re-run with --cloud-provider=eks|gke|aks if the cluster is on a managed service, or accept that the snapshot is genuinely from a self-managed control plane.",
		RemediationSteps: []string{
			"Identify the cloud provider hosting the cluster (kubectl get nodes -o yaml | grep -i provider).",
			"Re-run `kubesplaining scan` with `--cloud-provider=<eks|gke|aks>` to opt into provider-specific detectors.",
			"If the cluster is genuinely self-managed, pass `--cloud-provider=none` to make the auto-detection skip explicit.",
		},
		LearnMore:       []models.Reference{},
		MitreTechniques: []models.MitreTechnique{},
	}
}
