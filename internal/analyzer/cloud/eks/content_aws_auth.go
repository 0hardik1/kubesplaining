// Package eks - aws-auth per-rule content helpers. Each helper returns a
// ruleContent value that mirrors internal/analyzer/cloud/content.go's
// ruleContent shape field-for-field. The copy lives in the eks sub-package
// (instead of internal/analyzer/cloud) to avoid a circular import: the
// parent cloud package already imports this sub-package via its dispatcher.
//
// Sources: AWS EKS user guide (add-user-role), AWS EKS Best Practices Guide
// (security/iam), MITRE ATT&CK T1078 Valid Accounts and T1098 Account
// Manipulation.
package eks

import "github.com/0hardik1/kubesplaining/internal/models"

// ruleContent is the per-rule content payload used by the eks emitters.
// Fields mirror the unexported ruleContent in internal/analyzer/cloud/
// content.go so report-layer renderers see the same shape regardless of
// which provider emitted the finding.
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

// awsAuth* learn-more references reused across both rules in this file.
var (
	refAWSAuthAddRole = models.Reference{
		Title: "AWS EKS - Manage users or IAM roles for your cluster (aws-auth)",
		URL:   "https://docs.aws.amazon.com/eks/latest/userguide/add-user-role.html",
	}
	refEKSBestPracticesIAM = models.Reference{
		Title: "AWS EKS Best Practices Guide - Identity and Access Management",
		URL:   "https://aws.github.io/aws-eks-best-practices/security/docs/iam/",
	}
)

var (
	mitreT1078AWSAuth = models.MitreTechnique{
		ID:   "T1078",
		Name: "Valid Accounts",
		URL:  "https://attack.mitre.org/techniques/T1078/",
	}
	mitreT1098AWSAuth = models.MitreTechnique{
		ID:   "T1098",
		Name: "Account Manipulation",
		URL:  "https://attack.mitre.org/techniques/T1098/",
	}
)

// contentAWSAuthSystemMasters returns the prose / scope / remediation copy
// for KUBE-CLOUD-AWSAUTH-SYSTEM-MASTERS-001 (aws-auth maps an IAM principal
// directly to system:masters, which the apiserver hard-codes as cluster
// admin).
func contentAWSAuthSystemMasters() ruleContent {
	return ruleContent{
		Title: "An IAM principal is mapped to system:masters via aws-auth, granting full cluster-admin",
		Scope: models.Scope{
			Level:  models.ScopeCluster,
			Detail: "Cluster-wide: any IAM principal in this entry authenticates to the apiserver as a member of system:masters, which is wired to cluster-admin.",
		},
		Description: "EKS authenticates IAM principals through the aws-auth ConfigMap in kube-system. When an entry under mapRoles or mapUsers includes the group `system:masters`, the apiserver treats every kubectl call from that principal as cluster-admin (system:masters is hard-coded in the RBAC bootstrap, so it cannot be revoked by editing ClusterRoleBindings). Compromise of the corresponding AWS IAM role or user (leaked access keys, an over-permissive sts:AssumeRole policy, an EC2 instance whose role chain reaches this ARN) becomes immediate, irreversible cluster ownership.",
		Impact:      "Full cluster-admin for anyone able to assume the IAM principal: read every Secret, create privileged pods on every node, alter admission webhooks, persist via DaemonSets.",
		AttackScenario: []string{
			"Attacker phishes / exfiltrates AWS credentials for the mapped IAM role (or finds an EC2 role chain that can assume it).",
			"They run `aws eks update-kubeconfig` and then any `kubectl` command. The apiserver resolves them to system:masters.",
			"`kubectl get secrets -A` returns every Secret in the cluster: cloud credentials, database passwords, service-account tokens.",
			"They deploy a DaemonSet with hostPath / privileged true on every node, persisting access independent of the IAM credential.",
		},
		Remediation: "Remove the system:masters group from the aws-auth entry and grant only the specific ClusterRole the principal needs, ideally via a custom RBAC group.",
		RemediationSteps: []string{
			"Edit the ConfigMap: `kubectl -n kube-system edit configmap aws-auth` and remove `system:masters` from the offending mapRoles / mapUsers entry.",
			"If the principal needs broad read access, map it to a custom group (e.g. `eks-cluster-readers`) and bind that group to the `view` ClusterRole. Never reuse system:masters.",
			"Tighten the AWS side: scope the IAM role's trust policy (sts:AssumeRole) to the smallest principal set possible and require MFA. Audit CloudTrail for who has assumed it.",
			"Wire an admission policy (Kyverno / Gatekeeper) that rejects future edits adding `system:masters` to aws-auth, and consider migrating to EKS Access Entries which deprecate the ConfigMap entirely.",
		},
		LearnMore: []models.Reference{
			refAWSAuthAddRole,
			refEKSBestPracticesIAM,
		},
		MitreTechniques: []models.MitreTechnique{
			mitreT1078AWSAuth,
			mitreT1098AWSAuth,
		},
	}
}

// contentAWSAuthOverbroad returns the prose / scope / remediation copy for
// KUBE-CLOUD-AWSAUTH-OVERBROAD-001 (aws-auth maps an IAM principal to a
// custom group that itself has a ClusterRoleBinding to cluster-admin, so
// the principal inherits cluster-admin indirectly).
func contentAWSAuthOverbroad() ruleContent {
	return ruleContent{
		Title: "An IAM principal mapped via aws-auth inherits cluster-admin through an overbroad group binding",
		Scope: models.Scope{
			Level:  models.ScopeCluster,
			Detail: "Cluster-wide: the principal's Kubernetes group is bound to the cluster-admin ClusterRole, so every API operation succeeds for it.",
		},
		Description: "The aws-auth ConfigMap maps this IAM principal to a custom Kubernetes group (not system:masters), but a ClusterRoleBinding grants that group the built-in `cluster-admin` ClusterRole. The end-state is identical to a direct system:masters mapping: every API verb on every resource in every namespace is permitted. The misconfiguration is one step removed (group plus binding instead of a bare system:masters tag), so it tends to slip past reviewers who only audit the aws-auth file.",
		Impact:      "Indirect but complete cluster-admin: the principal can read every Secret, alter every workload, and persist via privileged DaemonSets.",
		AttackScenario: []string{
			"Reviewer approves an aws-auth change because the listed group looks innocuous (e.g. `developers`).",
			"Unbeknownst to the reviewer, a ClusterRoleBinding ties that group to cluster-admin (often a legacy bootstrap binding from a Terraform module).",
			"Attacker compromises the IAM principal, authenticates to the cluster, and inherits cluster-admin transitively.",
			"They read every Secret and deploy a privileged DaemonSet for persistence, just as in the direct system:masters case.",
		},
		Remediation: "Either remove the group from the aws-auth entry, or remove the ClusterRoleBinding that grants it cluster-admin. Replace with a narrowly-scoped Role/ClusterRole.",
		RemediationSteps: []string{
			"Identify the offending binding via `kubectl get clusterrolebindings -o yaml | yq '.items[] | select(.roleRef.name == \"cluster-admin\")'` and confirm the group on the Subjects list.",
			"Decide: either drop the group from the aws-auth entry (`kubectl -n kube-system edit configmap aws-auth`) or delete / rebind the ClusterRoleBinding to a least-privilege ClusterRole.",
			"Bound the underlying IAM role: tighten its trust policy and audit CloudTrail for prior AssumeRole events.",
			"Add a CI check (Kyverno, conftest, OPA) that rejects new ClusterRoleBindings to `cluster-admin` whose Subjects include Group entries, and prefer EKS Access Entries over aws-auth for new principals.",
		},
		LearnMore: []models.Reference{
			refAWSAuthAddRole,
			refEKSBestPracticesIAM,
		},
		MitreTechniques: []models.MitreTechnique{
			mitreT1078AWSAuth,
			mitreT1098AWSAuth,
		},
	}
}
