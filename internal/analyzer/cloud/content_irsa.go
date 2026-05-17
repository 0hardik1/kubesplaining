// Package cloud: per-rule prose content for the IRSA detectors.
//
// Each helper returns the title, description, impact, attack scenario,
// remediation, references, and MITRE technique list for one rule ID. The
// per-rule helpers live in a sibling file (content_irsa.go) rather than
// content.go because the rule files in the eks/ subpackage today don't read
// these helpers (Unit 2 embeds prose inline to keep the cross-package surface
// small); the helpers exist so a follow-up wire-up step can swap the inline
// strings for these structured forms without churning the analyzers' Findings.
package cloud

import "github.com/0hardik1/kubesplaining/internal/models"

// contentIRSAAdminRole returns the structured content for
// KUBE-CLOUD-IRSA-ADMIN-ROLE-001.
func contentIRSAAdminRole() ruleContent {
	return ruleContent{
		Title: "ServiceAccount bound to admin-flavored IAM role via IRSA",
		Scope: models.Scope{
			Level:  models.ScopeWorkload,
			Detail: "ServiceAccount and every pod that mounts it",
		},
		Description: "IRSA (IAM Roles for Service Accounts) projects a short-lived IAM session into any pod that uses the annotated ServiceAccount. When the underlying IAM role is admin-flavored (Administrator, FullAccess, PowerUserAccess, or the AWS-managed AdministratorAccess SSO permission set), any pod that mounts this SA can call AWS APIs as a cloud-account administrator. A compromised pod compromises the whole AWS account.",
		Impact:      "Any process inside a pod using this SA can read or modify every resource in the AWS account: stop production, exfiltrate S3 buckets, pivot through IAM PassRole, or destroy infrastructure.",
		AttackScenario: []string{
			"Attacker compromises a pod that mounts this ServiceAccount (RCE in app code, dependency takeover, exec into pod via abusive RBAC).",
			"Pod reads the projected IRSA token from /var/run/secrets/eks.amazonaws.com/serviceaccount/token.",
			"Attacker calls sts:AssumeRoleWithWebIdentity using the token to receive admin AWS credentials.",
			"Attacker uses the admin credentials to read every secret, modify infrastructure, or pivot into other accounts via cross-account roles.",
		},
		Remediation: "Replace the admin IAM role with a least-privilege role scoped to the API actions and resources the workload actually needs.",
		RemediationSteps: []string{
			"Audit the workload's AWS API calls (CloudTrail, AWS access analyzer) to enumerate the minimal action set it needs.",
			"Create a new IAM role with an inline policy granting only those actions on the specific resource ARNs the workload touches.",
			"Update the ServiceAccount annotation `eks.amazonaws.com/role-arn` to point at the new role.",
			"Restart pods mounting the SA so they pick up new IRSA tokens.",
			"Detach the AdministratorAccess (or other admin-flavored) policy from the old role, then delete the old role once nothing depends on it.",
		},
		LearnMore: []models.Reference{
			{Title: "EKS: IAM Roles for Service Accounts", URL: "https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html"},
			{Title: "AWS IAM: Least-privilege permissions", URL: "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege"},
		},
		MitreTechniques: []models.MitreTechnique{
			{ID: "T1078.004", Name: "Valid Accounts: Cloud Accounts", URL: "https://attack.mitre.org/techniques/T1078/004/"},
		},
	}
}

// contentIRSAMissing returns the structured content for
// KUBE-CLOUD-IRSA-MISSING-001.
func contentIRSAMissing() ruleContent {
	return ruleContent{
		Title: "Pod talks to AWS but its ServiceAccount has no IRSA annotation",
		Scope: models.Scope{
			Level:  models.ScopeWorkload,
			Detail: "Workload and every pod it spawns",
		},
		Description: "The pod's container images, environment variables, or both indicate it uses the AWS SDK or CLI, yet its ServiceAccount carries no `eks.amazonaws.com/role-arn` annotation. Without IRSA, AWS SDKs fall back to the EC2 instance metadata service (IMDS) on the node, picking up the node's EC2 instance-profile role. Every workload on the same node then shares one AWS identity, and that identity is typically much broader than any single pod should hold.",
		Impact:      "Pod gains the node's AWS privileges instead of a least-privilege per-workload role. A compromised pod can call any AWS API the node role allows: read EC2 metadata, assume cross-account roles, list S3, and so on.",
		AttackScenario: []string{
			"Attacker compromises a pod that uses the AWS SDK / CLI but has no IRSA SA.",
			"AWS SDK falls back to the IMDS endpoint (169.254.169.254) for credentials.",
			"IMDS returns the EC2 instance-profile credentials for the node (often a broad EKS node role).",
			"Attacker uses the node-level credentials to pivot into AWS: describe instances, list buckets, mint cross-account sessions via PassRole.",
		},
		Remediation: "Create a least-privilege IAM role for the workload and annotate its ServiceAccount with `eks.amazonaws.com/role-arn`.",
		RemediationSteps: []string{
			"Define an IAM role with an inline policy granting only the AWS API actions and resource ARNs this workload uses.",
			"Configure the role's trust policy to allow the EKS OIDC provider for this specific namespace+SA pair.",
			"Annotate the ServiceAccount with `eks.amazonaws.com/role-arn: arn:aws:iam::<account>:role/<role-name>`.",
			"Restart pods to pick up the new IRSA token mount.",
			"Tighten the node instance profile by removing broad permissions the workloads no longer need.",
		},
		LearnMore: []models.Reference{
			{Title: "EKS: IAM Roles for Service Accounts", URL: "https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html"},
			{Title: "EKS: restrict IMDS access from pods", URL: "https://docs.aws.amazon.com/eks/latest/userguide/best-practices-security.html"},
		},
		MitreTechniques: []models.MitreTechnique{
			{ID: "T1552.005", Name: "Unsecured Credentials: Cloud Instance Metadata API", URL: "https://attack.mitre.org/techniques/T1552/005/"},
		},
	}
}

// Keep the package's `unused` linter happy until a wire-up step calls these
// helpers from a Finding factory. Mirrors the `_ = contentProviderUnknown`
// pattern in analyzer.go.
var (
	_ = contentIRSAAdminRole
	_ = contentIRSAMissing
)
