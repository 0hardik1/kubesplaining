// Package cloud - per-rule content for the IMDS pivot rule (KUBE-CLOUD-IMDS-PIVOT-001).
// Kept in its own file so that future rules can land their content helpers in sibling
// files without inflating content.go. Mirrors the per-rule content pattern used by
// the network and rbac packages.
package cloud

import "github.com/0hardik1/kubesplaining/internal/models"

// contentImdsPivot001 returns the static prose, remediation, MITRE mappings, and
// learn-more references for KUBE-CLOUD-IMDS-PIVOT-001. The detection lives in
// internal/analyzer/cloud/eks/imds_pivot.go; this helper is referenced from there
// when materializing a models.Finding.
//
// Editorial stance: the rule is intentionally HIGH severity because the SSRF
// to cloud-credentials chain on EKS EC2 nodegroups is one of the highest-impact
// real-world Kubernetes attack patterns. The remediation guidance prefers IRSA
// (IAM Roles for Service Accounts) over IMDSv2-only hardening because IRSA gives
// each workload its own scoped role; IMDSv2 enforcement is a secondary defense
// that limits which pods can complete the metadata-service handshake.
func contentImdsPivot001() ruleContent {
	return ruleContent{
		Title: "Pod can reach IMDS without IRSA carve-out (EKS node-IAM pivot)",
		Scope: models.Scope{
			Level:  models.ScopeWorkload,
			Detail: "Workload-scoped: this pod (or its controlling workload) can reach 169.254.169.254 and its ServiceAccount has no IRSA binding, so a compromise falls back to the worker node's IAM role.",
		},
		Description: "On EKS clusters backed by EC2 nodegroups, every node carries an IAM instance profile that the kubelet (and any pod with raw network reach to the metadata service) can assume. A pod whose ServiceAccount lacks the `eks.amazonaws.com/role-arn` annotation has no IRSA binding, so any SSRF, RCE, or token-theft in that pod can curl 169.254.169.254 and inherit the worker node's IAM role. Node IAM roles are typically broader than per-workload roles (they need to register the node, pull images, attach EBS volumes), which turns container compromise into AWS-account pivot. This rule fires only on EKS, and only when the pod is not scheduled to a Fargate node (Fargate has no IMDS exposure).",
		Impact:      "AWS account compromise via worker node IAM role: an attacker who lands code execution in the pod inherits the node instance profile and pivots to whatever AWS APIs that profile is authorized for.",
		AttackScenario: []string{
			"Attacker achieves RCE in the pod (vulnerable app, dependency CVE, SSRF, ...).",
			"From inside the pod, attacker `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/` to enumerate the EC2 instance profile.",
			"Attacker fetches the role's temporary credentials and uses `aws sts get-caller-identity` to confirm scope.",
			"Attacker calls the AWS APIs the node IAM role is authorized for (commonly: read S3, describe EC2, decrypt KMS, push images to ECR) and pivots laterally in the AWS account.",
		},
		Remediation: "Bind the pod's ServiceAccount to a least-privileged IRSA role AND apply an egress NetworkPolicy that blocks 169.254.169.254.",
		RemediationSteps: []string{
			"Create an IAM role with the workload's required permissions and the EKS OIDC trust policy, then annotate the ServiceAccount: `kubectl annotate sa <sa> eks.amazonaws.com/role-arn=arn:aws:iam::<acct>:role/<role>`.",
			"Apply a namespace-scoped egress NetworkPolicy that explicitly carves IMDS out of any 0.0.0.0/0 allow rule: `to: [{ ipBlock: { cidr: 0.0.0.0/0, except: [169.254.169.254/32] } }]`.",
			"Enforce IMDSv2 on the EKS managed nodegroup (`--metadata-options HttpTokens=required HttpPutResponseHopLimit=1`) so even reachable IMDS requires session tokens that pods cannot easily obtain.",
			"Audit the node IAM role and tighten it to the minimum kubelet / node-controller surface (drop S3 / EC2 / KMS / Secrets Manager permissions unless the node itself genuinely needs them).",
		},
		LearnMore: []models.Reference{
			{Title: "Christophe Tafani-Dereeper: AWS IAM privilege escalation in EKS", URL: "https://blog.christophetd.fr/"},
			{Title: "AWS EKS Best Practices: IAM", URL: "https://aws.github.io/aws-eks-best-practices/security/docs/iam/"},
			{Title: "AWS EC2: Configuring the instance metadata service (IMDSv2)", URL: "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html"},
		},
		MitreTechniques: []models.MitreTechnique{
			{ID: "T1552.005", Name: "Cloud Instance Metadata API", URL: "https://attack.mitre.org/techniques/T1552/005/"},
			{ID: "T1078.004", Name: "Valid Accounts: Cloud Accounts", URL: "https://attack.mitre.org/techniques/T1078/004/"},
		},
	}
}
