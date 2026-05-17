// Package eks: provider-specific detection helpers shared by the EKS analyzers
// (aws-auth, IRSA, IMDS-pivot). These are deliberately small, pure functions so
// each analyzer file can compose them without re-implementing ARN parsing or
// node-label sniffing. Higher-level decisions (severity, evidence shape) live in
// the per-rule files; this file only does pattern matching and string parsing.
package eks

import (
	"path"
	"regexp"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// reservedSSOAdminPattern matches AWS SSO permission-set roles whose name says
// they grant the AdministratorAccess managed policy. The hex suffix is the
// account-and-permission-set hash that AWS appends to materialized SSO roles.
var reservedSSOAdminPattern = regexp.MustCompile(`^AWSReservedSSO_AdministratorAccess_[a-f0-9]+$`)

// adminSubstringPattern (case-insensitive) catches the three common
// admin-equivalent keywords that show up in IRSA role names operators hand-roll.
// Anchored matching would miss `MyAppFullAccess`, so this is a substring search.
var adminSubstringPattern = regexp.MustCompile(`(?i)Administrator|FullAccess|PowerUserAccess`)

// awsSDKImageBasenames lists the image basename tokens that strongly suggest
// the workload talks to AWS APIs (so an absent IRSA SA is a credential-source
// mystery worth flagging). All matches are case-insensitive and applied to the
// path-stripped basename (the part after the final "/" and before the ":tag").
var awsSDKImageBasenames = []string{"aws-cli", "awscli", "aws-sdk"}

// awsSDKImagePrefix is the canonical "official AWS images" prefix on Docker Hub
// and ECR Public; anything starting with this is treated as an AWS SDK hint.
const awsSDKImagePrefix = "amazon/aws-"

// excludedAWSEnvVars are AWS_-prefixed env names that do NOT indicate credentials
// (they're just region pickers). Anything else starting with AWS_ is treated as
// a hint that the workload expects to talk to AWS.
var excludedAWSEnvVars = map[string]struct{}{
	"AWS_REGION":         {},
	"AWS_DEFAULT_REGION": {},
}

// ParseARN takes an AWS ARN string and returns (accountID, resourceKind,
// resourceName, ok). It accepts the canonical 6-segment form
// "arn:aws:iam::ACCOUNT:RESOURCE/NAME" plus the "RESOURCE:NAME" variant the
// IAM ARN docs allow for some resource types. The resourceKind for an IAM
// role is "role"; for an IAM user it's "user". `ok` is false on any parse
// failure; callers should treat that as "skip, not error".
func ParseARN(arn string) (accountID, kind, name string, ok bool) {
	parts := strings.Split(arn, ":")
	if len(parts) < 6 || parts[0] != "arn" {
		return "", "", "", false
	}
	accountID = parts[4]
	resource := strings.Join(parts[5:], ":")
	// Allow either "role/Name" or "role:Name".
	if slash := strings.IndexAny(resource, "/:"); slash >= 0 {
		kind = resource[:slash]
		name = resource[slash+1:]
	} else {
		kind = resource
		name = ""
	}
	if kind == "" {
		return "", "", "", false
	}
	return accountID, kind, name, true
}

// ARNAdminLikely reports whether the role-name part of an ARN matches a known
// admin-flavored pattern. reason is "reserved-sso-admin" (highest signal: AWS's
// own AdministratorAccess SSO permission set) or "admin-substring" (operator
// chose a role name like "AdministratorAccess" or "MyAppFullAccess"). keyword
// is the matched fragment for evidence display.
func ARNAdminLikely(arn string) (matched bool, reason, keyword string) {
	_, _, name, ok := ParseARN(arn)
	if !ok || name == "" {
		return false, "", ""
	}
	if reservedSSOAdminPattern.MatchString(name) {
		return true, "reserved-sso-admin", "AWSReservedSSO_AdministratorAccess"
	}
	if loc := adminSubstringPattern.FindStringIndex(name); loc != nil {
		return true, "admin-substring", name[loc[0]:loc[1]]
	}
	return false, "", ""
}

// IsEKSNode reports whether the node carries EKS-specific labels. Either the
// AWS-managed node-role label (eks.amazonaws.com/nodegroup) or the
// compute-type label (Fargate / EC2) is enough; both are added by the AWS
// node bootstrapper / Fargate fleet and don't appear on self-managed nodes.
func IsEKSNode(node corev1.Node) bool {
	if node.Labels == nil {
		return false
	}
	if _, ok := node.Labels["eks.amazonaws.com/nodegroup"]; ok {
		return true
	}
	if _, ok := node.Labels["eks.amazonaws.com/compute-type"]; ok {
		return true
	}
	return false
}

// IsFargateNode reports whether the node is EKS-Fargate. Fargate nodes carry
// the label eks.amazonaws.com/compute-type=fargate; EC2-backed managed nodes
// either omit the label or carry compute-type=ec2.
func IsFargateNode(node corev1.Node) bool {
	if node.Labels == nil {
		return false
	}
	return node.Labels["eks.amazonaws.com/compute-type"] == "fargate"
}

// AWSSDKImageHint returns the matched hint string when the image's basename
// (path-stripped, tag-stripped) suggests an AWS SDK / CLI workload. Returns
// "" if no hint matches. The returned string is intended for the finding's
// evidence payload so a reader can see *why* this image flagged.
func AWSSDKImageHint(image string) string {
	if image == "" {
		return ""
	}
	// Strip a tag or digest before basename extraction. Order matters: digest
	// uses "@", tag uses ":", and a registry port has ":" too. Split on the
	// LAST "/" first to isolate the repo+tag, then strip everything after the
	// first "@" or ":" in that suffix.
	suffix := image
	if i := strings.LastIndex(suffix, "/"); i >= 0 {
		suffix = suffix[i+1:]
	}
	if i := strings.IndexAny(suffix, "@:"); i >= 0 {
		suffix = suffix[:i]
	}
	lower := strings.ToLower(suffix)
	for _, token := range awsSDKImageBasenames {
		if lower == token || strings.Contains(lower, token) {
			return token
		}
	}
	// Also check the full image (case-insensitive) against the "amazon/aws-*"
	// prefix; the basename alone isn't enough to spot the "amazon/" owner.
	clean := strings.ToLower(path.Clean(image))
	if strings.HasPrefix(clean, awsSDKImagePrefix) {
		return awsSDKImagePrefix + "*"
	}
	return ""
}

// AWSSDKEnvHint returns the matched env-var name when it starts with AWS_
// excluding the region-only variants. Returns "" when no hint matches.
// The check is case-sensitive: AWS_* is the documented prefix and we don't
// want to match application-defined "aws_db_url".
func AWSSDKEnvHint(envName string) string {
	if !strings.HasPrefix(envName, "AWS_") {
		return ""
	}
	if _, excluded := excludedAWSEnvVars[envName]; excluded {
		return ""
	}
	return envName
}
