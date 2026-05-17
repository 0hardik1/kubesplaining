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
	DetectedFrom string            `json:"detected_from,omitempty"`
}
