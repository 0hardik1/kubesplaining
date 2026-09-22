// Package eks - access-entry per-rule content helpers, mirroring
// content_aws_auth.go for the KUBE-CLOUD-ACCESSENTRY-* family.
//
// Sources: AWS EKS user guide (access-entries, access-policies), AWS EKS Best
// Practices Guide (security/iam), MITRE ATT&CK T1078 Valid Accounts.
package eks

import "github.com/0hardik1/kubesplaining/internal/models"

var (
	refEKSAccessEntries = models.Reference{
		Title: "AWS EKS - Grant IAM users access to Kubernetes with EKS access entries",
		URL:   "https://docs.aws.amazon.com/eks/latest/userguide/access-entries.html",
	}
	refEKSAccessPolicies = models.Reference{
		Title: "AWS EKS - Associate access policies with access entries",
		URL:   "https://docs.aws.amazon.com/eks/latest/userguide/access-policies.html",
	}
)

func contentAccessEntryClusterAdmin() ruleContent {
	return ruleContent{
		Title: "An EKS access entry grants an IAM principal AmazonEKSClusterAdminPolicy, which is cluster-admin",
		Scope: models.Scope{
			Level:  models.ScopeCluster,
			Detail: "Cluster-wide: the access policy is the exact equivalent of a ClusterRoleBinding to the cluster-admin ClusterRole, applied at cluster scope.",
		},
		Description: "EKS access entries map IAM principals to Kubernetes identities in the EKS control plane, outside the cluster. AmazonEKSClusterAdminPolicy associated at cluster scope grants the principal every verb on every resource in every namespace, the same as the built-in cluster-admin ClusterRole. The grant is invisible to `kubectl get clusterrolebindings` and to the aws-auth ConfigMap: it exists only in the EKS API, so an in-cluster RBAC audit cannot see who holds it. Compromise of the IAM principal (leaked keys, an over-permissive sts:AssumeRole trust policy, an instance whose role chain reaches it) is immediate cluster ownership.",
		Impact:      "Full cluster-admin for anyone able to authenticate as the IAM principal: read every Secret, run privileged pods on every node, rewrite admission control, persist via DaemonSets.",
		AttackScenario: []string{
			"Attacker obtains credentials for the IAM principal, or a path to assume it, through an AWS-side weakness.",
			"They run `aws eks update-kubeconfig` for the cluster. The EKS authenticator resolves the access entry and its cluster-scoped AmazonEKSClusterAdminPolicy.",
			"`kubectl auth can-i '*' '*' --all-namespaces` returns yes. Every Secret, every workload, every node is theirs.",
			"They persist with a privileged DaemonSet, so revoking the IAM credential later does not remove them.",
		},
		Remediation: "Disassociate AmazonEKSClusterAdminPolicy from the access entry and associate a narrower policy (AmazonEKSEditPolicy or AmazonEKSViewPolicy, namespace-scoped where possible), or delete the entry if the principal does not need cluster access.",
		RemediationSteps: []string{
			"List what the entry holds: `aws eks list-associated-access-policies --cluster-name <cluster> --principal-arn <arn>`.",
			"Remove the admin policy: `aws eks disassociate-access-policy --cluster-name <cluster> --principal-arn <arn> --policy-arn arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy`.",
			"Grant the least-privilege replacement: `aws eks associate-access-policy ... --policy-arn .../AmazonEKSEditPolicy --access-scope type=namespace,namespaces=<ns>`, or bind a custom Kubernetes group via `--kubernetes-groups` to a scoped (Cluster)Role.",
			"Tighten the AWS side: scope the IAM role's trust policy, require MFA for humans, and alert on `AssociateAccessPolicy` / `CreateAccessEntry` events in CloudTrail.",
		},
		LearnMore:       []models.Reference{refEKSAccessEntries, refEKSAccessPolicies, refEKSBestPracticesIAM},
		MitreTechniques: []models.MitreTechnique{mitreT1078AWSAuth, mitreT1098AWSAuth},
	}
}

func contentAccessEntryOverbroad() ruleContent {
	return ruleContent{
		Title: "An EKS access entry gives an IAM principal admin-equivalent reach through a cluster-scoped policy or an overbroad group binding",
		Scope: models.Scope{
			Level:  models.ScopeCluster,
			Detail: "Cluster-wide: either the access policy reads Secrets in every namespace, or the entry's Kubernetes group is bound to an admin-equivalent ClusterRole.",
		},
		Description: "This access entry does not carry AmazonEKSClusterAdminPolicy, but its effective reach is the same. Two shapes trigger the rule. First, AmazonEKSAdminPolicy or AmazonEKSAdminViewPolicy associated at cluster scope: neither touches cluster-scoped resources, but both read Secrets in every namespace, which includes every ServiceAccount token in kube-system, and admin also writes RoleBindings. Second, the entry's `kubernetesGroups` list names a group that a ClusterRoleBinding ties to `cluster-admin` or to a custom ClusterRole with a `*/*/*` rule. In both cases the grant is one step removed from an obvious admin mapping, so it passes review that only checks for the ClusterAdmin policy.",
		Impact:      "Indirect but complete cluster takeover: token theft from kube-system controllers or a direct admin binding gives the principal every permission in the cluster.",
		AttackScenario: []string{
			"Reviewer approves the access entry because the listed policy or group looks scoped (`AmazonEKSAdminPolicy`, `developers`).",
			"The policy reads Secrets cluster-wide, or a legacy ClusterRoleBinding ties the group to cluster-admin.",
			"Attacker compromises the IAM principal, authenticates with `aws eks update-kubeconfig`, and either reads a kube-system controller token or acts as cluster-admin directly.",
			"They persist with a privileged workload and revoke nothing, so the IAM-side fix alone does not evict them.",
		},
		Remediation: "Scope the access policy to the namespaces the principal needs (`--access-scope type=namespace`), or replace it with AmazonEKSEditPolicy / AmazonEKSViewPolicy; for the group shape, drop the group from the entry or rebind the group to a least-privilege ClusterRole.",
		RemediationSteps: []string{
			"Inspect the entry: `aws eks describe-access-entry --cluster-name <cluster> --principal-arn <arn>` and `aws eks list-associated-access-policies ...`.",
			"Policy shape: `aws eks disassociate-access-policy ... --policy-arn <policy>` then re-associate at namespace scope, or with a narrower policy.",
			"Group shape: `aws eks update-access-entry --cluster-name <cluster> --principal-arn <arn> --kubernetes-groups <groups-without-the-admin-group>`, or fix the ClusterRoleBinding named in the evidence.",
			"Add a CI check that rejects cluster-scoped AmazonEKSAdminPolicy associations and ClusterRoleBindings to cluster-admin whose subjects include Group entries.",
		},
		LearnMore:       []models.Reference{refEKSAccessEntries, refEKSAccessPolicies, refEKSBestPracticesIAM},
		MitreTechniques: []models.MitreTechnique{mitreT1078AWSAuth, mitreT1098AWSAuth},
	}
}

func contentAccessEntryNotEvaluated(hasAWSAuth bool) ruleContent {
	description := "This snapshot is from an EKS cluster, but no access-entries export was supplied (`scan --eks-access-entries <file>`). EKS access entries are the control-plane replacement for the aws-auth ConfigMap and the default for clusters created since late 2023; they live in the EKS API, so the collector cannot read them from inside the cluster. Every IAM-to-Kubernetes mapping made through an access entry, including AmazonEKSClusterAdminPolicy grants, is therefore unknown to this scan."
	impact := "IAM principals holding cluster-admin through access entries are not reported. The aws-auth ConfigMap was analyzed, so mappings made there are covered."
	if !hasAWSAuth {
		description += " The kube-system/aws-auth ConfigMap is absent as well, so the cluster is most likely in API authentication mode and no IAM-to-RBAC rule has been evaluated at all: an empty KUBE-CLOUD-AWSAUTH-* / KUBE-CLOUD-ACCESSENTRY-* result here means no data, not no findings."
		impact = "No IAM-to-Kubernetes mapping was evaluated. Any IAM principal mapped to cluster-admin through an access entry is invisible to this report."
	}
	return ruleContent{
		Title: "EKS access entries were not evaluated: IAM-to-Kubernetes mappings are unknown to this scan",
		Scope: models.Scope{
			Level:  models.ScopeCluster,
			Detail: "Cluster-wide coverage gap: the EKS access-entry half of IAM authentication was not available to the analyzer.",
		},
		Description: description,
		Impact:      impact,
		AttackScenario: []string{
			"An IAM principal is granted AmazonEKSClusterAdminPolicy through an access entry during onboarding and never reviewed.",
			"The cluster is scanned from inside only. The grant is not a Kubernetes object, so the report shows no overbroad IAM mapping.",
			"The principal's credentials leak. The attacker is cluster-admin, and the last clean report is cited as evidence nothing was wrong.",
		},
		Remediation: "Export the cluster's access entries with `scripts/eks-access-entries.sh <cluster> > entries.json` (read-only: eks:DescribeCluster, eks:ListAccessEntries, eks:DescribeAccessEntry, eks:ListAssociatedAccessPolicies) and re-run with `--eks-access-entries entries.json`.",
		RemediationSteps: []string{
			"Run `scripts/eks-access-entries.sh <cluster> [--region <region>] > entries.json` with credentials that can describe the cluster.",
			"Re-run `kubesplaining scan --eks-access-entries entries.json ...`. The KUBE-CLOUD-ACCESSENTRY-* rules then evaluate every entry and this finding disappears.",
			"If the export cannot be produced, audit the entries AWS-side: `aws eks list-access-entries`, AWS Config rule `eks-access-entry-no-admin`, or Prowler's EKS checks.",
		},
		LearnMore:       []models.Reference{refEKSAccessEntries, refEKSAccessPolicies},
		MitreTechniques: []models.MitreTechnique{mitreT1078AWSAuth},
	}
}
