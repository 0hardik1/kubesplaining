// Package eks - EKS Access Entries analysis. Access entries are the control-plane
// replacement for the aws-auth ConfigMap: each one binds an IAM principal to
// Kubernetes groups and to AWS-managed access policies. They are not Kubernetes
// objects, so they reach the snapshot only through `scan --eks-access-entries`
// (see internal/eksaccess). This file emits the KUBE-CLOUD-ACCESSENTRY-* family:
// two shape rules over the loaded entries, and one coverage rule that fires when
// an EKS snapshot carries no export at all, so a cluster migrated off aws-auth
// reports "not evaluated" instead of reporting clean.
package eks

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/scoring"
)

const (
	ruleAccessEntryClusterAdmin = "KUBE-CLOUD-ACCESSENTRY-CLUSTER-ADMIN-001"
	ruleAccessEntryOverbroad    = "KUBE-CLOUD-ACCESSENTRY-OVERBROAD-001"
	ruleAccessEntryNotEvaluated = "KUBE-CLOUD-ACCESSENTRY-NOT-EVALUATED-001"

	// AWS-managed access policy names, matched on the ARN suffix so the
	// aws-cn and aws-us-gov partitions resolve the same way.
	policyClusterAdmin = "AmazonEKSClusterAdminPolicy"
	policyAdmin        = "AmazonEKSAdminPolicy"
	policyAdminView    = "AmazonEKSAdminViewPolicy"

	accessScopeCluster = "cluster"
)

// AccessPolicyName returns the bare policy name from an EKS access policy ARN
// (arn:aws:eks::aws:cluster-access-policy/<name>), or the input unchanged when
// it carries no slash.
func AccessPolicyName(policyARN string) string {
	if i := strings.LastIndex(policyARN, "/"); i >= 0 {
		return policyARN[i+1:]
	}
	return policyARN
}

// ClusterAdminPolicy reports whether the association grants
// AmazonEKSClusterAdminPolicy at cluster scope: the exact equivalent of a
// ClusterRoleBinding to cluster-admin. EKS only allows this policy at cluster
// scope, but the scope is checked anyway so a hand-edited export cannot
// promote a namespace grant.
func ClusterAdminPolicy(p models.EKSAccessPolicyAssociation) bool {
	return AccessPolicyName(p.PolicyARN) == policyClusterAdmin && p.ScopeType == accessScopeCluster
}

// clusterWideSecretsPolicy reports whether the association grants a policy
// that reads Secrets in every namespace (AmazonEKSAdminPolicy maps to the
// `admin` ClusterRole, AmazonEKSAdminViewPolicy to `view` plus secrets) at
// cluster scope. No cluster-scoped resource is reachable, but every
// ServiceAccount token in kube-system is, which is the same end state.
func clusterWideSecretsPolicy(p models.EKSAccessPolicyAssociation) bool {
	if p.ScopeType != accessScopeCluster {
		return false
	}
	switch AccessPolicyName(p.PolicyARN) {
	case policyAdmin, policyAdminView:
		return true
	}
	return false
}

// AnalyzeAccessEntries returns the KUBE-CLOUD-ACCESSENTRY-* findings for the
// snapshot. With no export loaded it returns the single NOT-EVALUATED finding;
// with one loaded it evaluates every entry.
func AnalyzeAccessEntries(snapshot models.Snapshot) []models.Finding {
	state := snapshot.Cloud.EKS
	if state == nil {
		return []models.Finding{notEvaluatedFinding(snapshot)}
	}

	crbsByGroup := indexClusterRoleBindingsByGroup(snapshot.Resources.ClusterRoleBindings, snapshot.Resources.ClusterRoles)

	var findings []models.Finding
	for _, entry := range state.AccessEntries {
		if entry.PrincipalARN == "" {
			continue
		}
		if policy, ok := clusterAdminAssociation(entry); ok {
			findings = append(findings, accessEntryClusterAdminFinding(state, entry, policy))
			continue
		}
		if containsGroup(entry.KubernetesGroups, groupSystemMaster) {
			// EKS refuses system:* group names on the API, so this only
			// appears in a hand-edited export. Treat it as what it claims.
			findings = append(findings, accessEntryClusterAdminFinding(state, entry, models.EKSAccessPolicyAssociation{}))
			continue
		}
		if policy, ok := secretsAssociation(entry); ok {
			findings = append(findings, accessEntryOverbroadFinding(state, entry, overbroadVia{Policy: policy}))
			continue
		}
		for _, group := range entry.KubernetesGroups {
			match, hit := crbsByGroup[group]
			if !hit {
				continue
			}
			findings = append(findings, accessEntryOverbroadFinding(state, entry, overbroadVia{Group: group, Binding: match}))
			break
		}
	}
	return findings
}

func clusterAdminAssociation(entry models.EKSAccessEntry) (models.EKSAccessPolicyAssociation, bool) {
	for _, p := range entry.AccessPolicies {
		if ClusterAdminPolicy(p) {
			return p, true
		}
	}
	return models.EKSAccessPolicyAssociation{}, false
}

func secretsAssociation(entry models.EKSAccessEntry) (models.EKSAccessPolicyAssociation, bool) {
	for _, p := range entry.AccessPolicies {
		if clusterWideSecretsPolicy(p) {
			return p, true
		}
	}
	return models.EKSAccessPolicyAssociation{}, false
}

// overbroadVia records which of the two overbroad shapes matched: a
// cluster-scoped secrets-reading policy, or a Kubernetes group that a
// ClusterRoleBinding ties to an admin-equivalent ClusterRole.
type overbroadVia struct {
	Policy  models.EKSAccessPolicyAssociation
	Group   string
	Binding adminGroupBinding
}

func accessEntryTags() []string {
	return []string{"module:cloud", "module:rbac", "provider:eks", "check:accessEntries"}
}

func accessEntryResource(entry models.EKSAccessEntry) *models.ResourceRef {
	return &models.ResourceRef{Kind: "AccessEntry", Name: entry.PrincipalARN}
}

func accessEntryClusterAdminFinding(state *models.EKSCloudState, entry models.EKSAccessEntry, policy models.EKSAccessPolicyAssociation) models.Finding {
	content := contentAccessEntryClusterAdmin()
	evidence := map[string]any{
		"arn":                entry.PrincipalARN,
		"entryType":          entry.Type,
		"mappedUsername":     entry.Username,
		"kubernetesGroups":   entry.KubernetesGroups,
		"policyArn":          policy.PolicyARN,
		"accessScope":        policy.ScopeType,
		"clusterName":        state.ClusterName,
		"authenticationMode": state.AuthenticationMode,
		"source":             state.Source,
	}
	evidenceBytes, _ := json.Marshal(evidence)
	return models.Finding{
		ID:               fmt.Sprintf("%s:%s", ruleAccessEntryClusterAdmin, sanitizeARN(entry.PrincipalARN)),
		RuleID:           ruleAccessEntryClusterAdmin,
		Severity:         models.SeverityHigh,
		Score:            scoring.Clamp(8.6),
		Category:         models.CategoryPrivilegeEscalation,
		Title:            content.Title,
		Description:      content.Description,
		Subject:          &models.SubjectRef{Kind: "User", Name: entry.PrincipalARN},
		Resource:         accessEntryResource(entry),
		Scope:            content.Scope,
		Impact:           content.Impact,
		AttackScenario:   content.AttackScenario,
		Evidence:         evidenceBytes,
		Remediation:      content.Remediation,
		RemediationSteps: content.RemediationSteps,
		References:       learnMoreURLs(content.LearnMore),
		LearnMore:        content.LearnMore,
		MitreTechniques:  content.MitreTechniques,
		Tags:             accessEntryTags(),
	}
}

func accessEntryOverbroadFinding(state *models.EKSCloudState, entry models.EKSAccessEntry, via overbroadVia) models.Finding {
	content := contentAccessEntryOverbroad()
	evidence := map[string]any{
		"arn":                entry.PrincipalARN,
		"entryType":          entry.Type,
		"mappedUsername":     entry.Username,
		"kubernetesGroups":   entry.KubernetesGroups,
		"clusterName":        state.ClusterName,
		"authenticationMode": state.AuthenticationMode,
		"source":             state.Source,
	}
	if via.Policy.PolicyARN != "" {
		evidence["reason"] = "cluster-scoped-secrets-policy"
		evidence["policyArn"] = via.Policy.PolicyARN
		evidence["accessScope"] = via.Policy.ScopeType
	} else {
		evidence["reason"] = "group-bound-to-admin-clusterrole"
		evidence["mappedGroups"] = []string{via.Group}
		evidence["viaBinding"] = via.Binding.BindingName
		evidence["viaClusterRole"] = via.Binding.RoleName
	}
	evidenceBytes, _ := json.Marshal(evidence)
	return models.Finding{
		ID:               fmt.Sprintf("%s:%s", ruleAccessEntryOverbroad, sanitizeARN(entry.PrincipalARN)),
		RuleID:           ruleAccessEntryOverbroad,
		Severity:         models.SeverityMedium,
		Score:            scoring.Clamp(6.2),
		Category:         models.CategoryPrivilegeEscalation,
		Title:            content.Title,
		Description:      content.Description,
		Subject:          &models.SubjectRef{Kind: "User", Name: entry.PrincipalARN},
		Resource:         accessEntryResource(entry),
		Scope:            content.Scope,
		Impact:           content.Impact,
		AttackScenario:   content.AttackScenario,
		Evidence:         evidenceBytes,
		Remediation:      content.Remediation,
		RemediationSteps: content.RemediationSteps,
		References:       learnMoreURLs(content.LearnMore),
		LearnMore:        content.LearnMore,
		MitreTechniques:  content.MitreTechniques,
		Tags:             accessEntryTags(),
	}
}

// notEvaluatedFinding is the coverage gap. It is always LOW, never INFO: the
// default --severity-threshold is low, and a finding whose whole job is to
// say "this scan could not see the IAM mappings" must survive the default
// filter or the report is silent in exactly the case it exists for. The
// score and the wording still distinguish the two situations: aws-auth
// absent (no IAM-to-RBAC rule ran at all) scores higher than aws-auth
// analyzed (only the access-entry half is unknown).
func notEvaluatedFinding(snapshot models.Snapshot) models.Finding {
	_, hasAWSAuth := findAWSAuthConfigMap(snapshot)
	content := contentAccessEntryNotEvaluated(hasAWSAuth)
	severity, score := models.SeverityLow, 2.5
	if hasAWSAuth {
		score = 2.0
	}
	evidence := map[string]any{
		"awsAuthConfigMapPresent": hasAWSAuth,
		"accessEntriesLoaded":     false,
		"hint":                    "scripts/eks-access-entries.sh <cluster> > entries.json && kubesplaining scan --eks-access-entries entries.json",
	}
	evidenceBytes, _ := json.Marshal(evidence)
	return models.Finding{
		ID:               ruleAccessEntryNotEvaluated,
		RuleID:           ruleAccessEntryNotEvaluated,
		Severity:         severity,
		Score:            scoring.Clamp(score),
		Category:         models.CategoryPrivilegeEscalation,
		Title:            content.Title,
		Description:      content.Description,
		Scope:            content.Scope,
		Impact:           content.Impact,
		AttackScenario:   content.AttackScenario,
		Evidence:         evidenceBytes,
		Remediation:      content.Remediation,
		RemediationSteps: content.RemediationSteps,
		References:       learnMoreURLs(content.LearnMore),
		LearnMore:        content.LearnMore,
		MitreTechniques:  content.MitreTechniques,
		Tags:             []string{"module:cloud", "provider:eks", "check:accessEntries", "coverage:gap"},
	}
}
