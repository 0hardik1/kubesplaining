// Package models - CloudIdentity captures an external cloud-IAM identity that has
// some bearing on Kubernetes access. The privesc graph reaches it via IRSA edges;
// the cloud analyzer module emits findings about its shape. EKS is the only
// provider populated this slot; GKE / AKS are reserved.
package models

// CloudIdentityKind enumerates the shapes of cloud identities tracked.
type CloudIdentityKind string

const (
	CloudIdentityKindAWSIAMRole CloudIdentityKind = "aws_iam_role"
	CloudIdentityKindAWSIAMUser CloudIdentityKind = "aws_iam_user"
)

// IRSABinding describes how a cluster ServiceAccount is linked to a cloud identity.
type IRSABinding struct {
	ServiceAccountRef SubjectRef `json:"service_account"`
	Audience          string     `json:"audience,omitempty"`
}

// CloudIdentity is a parsed external cloud-IAM identity discovered in a Snapshot.
type CloudIdentity struct {
	Provider     string            `json:"provider"`
	Kind         CloudIdentityKind `json:"kind"`
	AccountID    string            `json:"account_id,omitempty"`
	ARN          string            `json:"arn"`
	RoleName     string            `json:"role_name,omitempty"`
	MappedGroups []string          `json:"mapped_groups,omitempty"`
	IRSA         *IRSABinding      `json:"irsa,omitempty"`
	// AccessEntry is set when the principal has an EKS Access Entry in the
	// operator-supplied export. Its KubernetesGroups are kept separate from
	// MappedGroups (aws-auth) because the two sources have different
	// remediations and, in API authentication mode, only this one is live.
	AccessEntry  *EKSAccessEntry `json:"access_entry,omitempty"`
	DetectedFrom string          `json:"detected_from,omitempty"`
}

// EKSAccessEntry is one EKS Access Entry: the control-plane replacement for an
// aws-auth ConfigMap row. It lives in the EKS API, not in the cluster, so the
// collector never sees it; the `scan --eks-access-entries` flag loads an export
// produced by scripts/eks-access-entries.sh (aws eks describe-access-entry +
// list-associated-access-policies per principal).
type EKSAccessEntry struct {
	PrincipalARN string `json:"principal_arn"`
	// Type is STANDARD for human / automation principals, or one of the node
	// types (EC2_LINUX, EC2_WINDOWS, FARGATE_LINUX, HYBRID_LINUX, EC2) whose
	// groups and policies EKS fixes and the API refuses to change.
	Type     string `json:"type,omitempty"`
	Username string `json:"username,omitempty"`
	// KubernetesGroups are the RBAC groups the principal authenticates into.
	// EKS rejects names that start with system:, so system:masters cannot be
	// granted here; cluster-admin arrives through AccessPolicies instead.
	KubernetesGroups []string                     `json:"kubernetes_groups,omitempty"`
	AccessPolicies   []EKSAccessPolicyAssociation `json:"access_policies,omitempty"`
}

// EKSAccessPolicyAssociation is one AWS-managed access policy attached to an
// access entry, with the scope it applies at. Cluster scope means every
// namespace plus cluster-scoped resources; namespace scope lists the namespaces.
type EKSAccessPolicyAssociation struct {
	PolicyARN  string   `json:"policy_arn"`
	ScopeType  string   `json:"scope_type,omitempty"`
	Namespaces []string `json:"namespaces,omitempty"`
}

// EKSCloudState is the AWS-side view of an EKS cluster that the Kubernetes
// API cannot return. Present only when the operator supplied an access-entries
// export; its absence is itself a signal (KUBE-CLOUD-ACCESSENTRY-NOT-EVALUATED-001).
type EKSCloudState struct {
	ClusterName string `json:"cluster_name,omitempty"`
	// AuthenticationMode is cluster.accessConfig.authenticationMode: API,
	// API_AND_CONFIG_MAP, or CONFIG_MAP. In API mode the apiserver ignores the
	// aws-auth ConfigMap, so the KUBE-CLOUD-AWSAUTH-* rules stand down.
	AuthenticationMode string `json:"authentication_mode,omitempty"`
	// Source records the file the entries were loaded from, for the report.
	Source        string           `json:"source,omitempty"`
	AccessEntries []EKSAccessEntry `json:"access_entries,omitempty"`
}

// CloudSnapshot carries provider control-plane state that is not a Kubernetes
// object. Only EKS is populated today.
type CloudSnapshot struct {
	EKS *EKSCloudState `json:"eks,omitempty"`
}

// Access-entry authentication modes as returned by aws eks describe-cluster.
const (
	EKSAuthModeAPI             = "API"
	EKSAuthModeAPIAndConfigMap = "API_AND_CONFIG_MAP"
	EKSAuthModeConfigMap       = "CONFIG_MAP"
)

// AWSAuthIgnored reports whether the cluster's authentication mode makes the
// apiserver ignore the aws-auth ConfigMap. Unknown modes are treated as
// honoring it, so a missing export never silences the ConfigMap rules.
func (s *EKSCloudState) AWSAuthIgnored() bool {
	return s != nil && s.AuthenticationMode == EKSAuthModeAPI
}
