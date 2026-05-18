// Package remediation — cloud module generator. Translates KUBE-CLOUD-* finding
// IDs into structured RemediationHint payloads (kubectl patches, kubectl annotate
// snippets, IAM trust-policy templates, composite NetworkPolicy + IRSA snippets).
//
// All hints here are command-only: cloud findings span a cross-API boundary
// (Kubernetes ConfigMap edits + AWS IAM trust-policy edits), and a single
// strategic-merge patch cannot express both sides. The hint Body is left empty;
// the Command is a multi-line shell snippet the operator pastes into a terminal.
// Per-rule generators decline (return nil) for findings where Resource / Subject
// is missing so the analyzer can fall back to the prose Remediation field on
// the Finding.
package remediation

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// ForCloud returns a remediation hint for KUBE-CLOUD-* rule IDs, or nil for unknown rules.
//
// Coverage:
//   - KUBE-CLOUD-AWSAUTH-SYSTEM-MASTERS-001: remove the offending mapRoles /
//     mapUsers entry from kube-system/aws-auth that grants the IAM principal
//     system:masters. We emit a kubectl-edit command because the value is a
//     YAML blob embedded in ConfigMap.data and a structured JSON-patch on
//     /data/<key> would replace the whole blob (not just one entry).
//   - KUBE-CLOUD-AWSAUTH-OVERBROAD-001: same surface, plus a hint to either
//     remove the mapping outright or rebind the group to a least-privileged
//     ClusterRole instead of cluster-admin.
//   - KUBE-CLOUD-IRSA-ADMIN-ROLE-001: the IAM role attached to the SA carries
//     admin-flavored policies; the kubectl side does not change (the SA stays
//     annotated), the fix is in AWS IAM. We emit a sample replacement trust
//     policy and a kubectl annotate command for the operator to point the SA
//     at the newly scoped role.
//   - KUBE-CLOUD-IRSA-MISSING-001: workload uses AWS SDKs but its SA lacks an
//     eks.amazonaws.com/role-arn annotation, so the SDK falls back to IMDS-
//     stolen node-role credentials. We emit the annotate command plus the
//     sample trust policy that lets the SA assume the new role.
//   - KUBE-CLOUD-IMDS-PIVOT-001: composite hint. The hint body carries (a) a
//     default-deny egress NetworkPolicy with an explicit deny on
//     169.254.169.254/32 to block IMDS access from pods, plus (b) the IRSA
//     annotation command so the workload uses scoped credentials instead.
//
// IRSA-MISSING and PROVIDER-UNKNOWN return nil because the analyzer's prose
// Remediation is already the appropriate "go set X up" guidance for those
// rules (PROVIDER-UNKNOWN is purely informational; IRSA-MISSING is handled
// above and is the same shape).
func ForCloud(ruleID string, finding models.Finding) *models.RemediationHint {
	switch ruleID {
	case "KUBE-CLOUD-AWSAUTH-SYSTEM-MASTERS-001":
		return cloudAWSAuthSystemMastersHint(finding)
	case "KUBE-CLOUD-AWSAUTH-OVERBROAD-001":
		return cloudAWSAuthOverbroadHint(finding)
	case "KUBE-CLOUD-IRSA-ADMIN-ROLE-001":
		return cloudIRSAAdminRoleHint(finding)
	case "KUBE-CLOUD-IRSA-MISSING-001":
		return cloudIRSAMissingHint(finding)
	case "KUBE-CLOUD-IMDS-PIVOT-001":
		return cloudIMDSPivotHint(finding)
	}
	return nil
}

// cloudAWSAuthSystemMastersHint emits a kubectl-edit command that points the
// operator at the aws-auth ConfigMap with the offending ARN called out in a
// comment. We deliberately avoid a JSON patch on /data/mapRoles: the value is
// a YAML blob (a serialized list), so patching that key replaces the whole
// list rather than removing one entry, which is too easy to fat-finger into a
// cluster-admin lockout. The edit-in-place flow is safer.
func cloudAWSAuthSystemMastersHint(finding models.Finding) *models.RemediationHint {
	arn := awsAuthARNFromFinding(finding)
	target := awsAuthPatchTarget(finding)
	command := fmt.Sprintf(`# Remove the mapRoles / mapUsers entry whose rolearn / userarn is:
#   %s
# That entry currently maps the IAM principal into the system:masters group, which
# the EKS apiserver hard-codes as cluster-admin. Editing aws-auth applies live:
# back up the current ConfigMap first.
kubectl -n kube-system get configmap aws-auth -o yaml > aws-auth.backup.yaml
kubectl -n kube-system edit configmap aws-auth`, arnDisplay(arn))
	return commandOnlyHint(target, command)
}

// cloudAWSAuthOverbroadHint emits a kubectl-edit command + a second branch the
// operator can take: rebind the group to a narrower ClusterRole instead of
// pulling the IAM principal out of aws-auth entirely. The "viaBinding" evidence
// key names the ClusterRoleBinding that grants cluster-admin to the group; we
// surface it so the operator can audit the binding directly.
func cloudAWSAuthOverbroadHint(finding models.Finding) *models.RemediationHint {
	arn := awsAuthARNFromFinding(finding)
	target := awsAuthPatchTarget(finding)
	via := stringFromEvidence(finding.Evidence, "viaBinding")
	viaLine := ""
	if via != "" {
		viaLine = fmt.Sprintf("\n# The cluster-admin reach comes from ClusterRoleBinding %q.", via)
	}
	command := fmt.Sprintf(`# The IAM principal:
#   %s
# is mapped via aws-auth to a Kubernetes group that is itself bound to cluster-admin.%s
# Two fixes, pick one:
#   1) Drop the mapRoles / mapUsers entry from kube-system/aws-auth so the IAM
#      principal stops authenticating to the cluster at all.
#   2) Rebind the group to a narrower ClusterRole (or replace it with a Role in
#      one namespace) so the IAM principal keeps API access but loses cluster-admin.
kubectl -n kube-system get configmap aws-auth -o yaml > aws-auth.backup.yaml
kubectl -n kube-system edit configmap aws-auth
# If you take option 2, audit the binding above and replace its roleRef:
#   kubectl edit clusterrolebinding <name>`, arnDisplay(arn), viaLine)
	return commandOnlyHint(target, command)
}

// cloudIRSAAdminRoleHint emits guidance for tightening the IAM role's
// permissions. The kubectl side does not change: the SA still uses IRSA, just
// with a less-privileged role. We emit a sample trust policy showing how to
// scope assume-role to the specific SA (so a different namespace cannot reuse
// the role), plus a kubectl annotate one-liner the operator runs after the new
// role is provisioned in AWS.
func cloudIRSAAdminRoleHint(finding models.Finding) *models.RemediationHint {
	target := irsaPatchTarget(finding)
	saNs, saName := saFromFinding(finding)
	command := fmt.Sprintf(`# ServiceAccount %s/%s is annotated to assume an admin-flavored IAM role via IRSA.
# The fix is in AWS IAM: scope the role's permissions down to the API actions
# the workload actually needs, and lock its trust policy to this exact SA so a
# different namespace cannot reuse it.
#
# Sample trust policy (AssumeRoleWithWebIdentity, locked to the SA):
# {
#   "Version": "2012-10-17",
#   "Statement": [{
#     "Effect": "Allow",
#     "Principal": { "Federated": "arn:aws:iam::<account>:oidc-provider/<oidc-issuer>" },
#     "Action": "sts:AssumeRoleWithWebIdentity",
#     "Condition": {
#       "StringEquals": {
#         "<oidc-issuer>:sub": "system:serviceaccount:%s:%s",
#         "<oidc-issuer>:aud": "sts.amazonaws.com"
#       }
#     }
#   }]
# }
#
# After provisioning the new role in AWS, point the SA at it:
kubectl annotate sa %s -n %s eks.amazonaws.com/role-arn=arn:aws:iam::<account>:role/<scoped-role> --overwrite`,
		saNs, saName, saNs, saName, saName, saNs)
	return commandOnlyHint(target, command)
}

// cloudIRSAMissingHint emits the kubectl annotate command + the sample trust
// policy needed to provision the IAM role in AWS. This is the structural
// counterpart to IRSA-ADMIN: same fields, but for a workload that has no IRSA
// at all today (so it falls back to node-role credentials via IMDS).
func cloudIRSAMissingHint(finding models.Finding) *models.RemediationHint {
	target := irsaPatchTarget(finding)
	saNs, saName := saFromFinding(finding)
	command := fmt.Sprintf(`# ServiceAccount %s/%s mounts pods that use AWS SDKs but is not annotated for IRSA.
# Without an eks.amazonaws.com/role-arn annotation, the SDK falls back to the
# EC2 node role credentials fetched from IMDS, which is typically much broader
# than what the workload needs.
#
# Step 1: provision a dedicated IAM role in AWS with a trust policy bound to
# this SA. Sample (replace <account>, <oidc-issuer>, and the permissions policy):
# {
#   "Version": "2012-10-17",
#   "Statement": [{
#     "Effect": "Allow",
#     "Principal": { "Federated": "arn:aws:iam::<account>:oidc-provider/<oidc-issuer>" },
#     "Action": "sts:AssumeRoleWithWebIdentity",
#     "Condition": {
#       "StringEquals": {
#         "<oidc-issuer>:sub": "system:serviceaccount:%s:%s",
#         "<oidc-issuer>:aud": "sts.amazonaws.com"
#       }
#     }
#   }]
# }
#
# Step 2: annotate the SA so pods using it receive an IRSA-projected token.
kubectl annotate sa %s -n %s eks.amazonaws.com/role-arn=arn:aws:iam::<account>:role/<role-name> --overwrite`,
		saNs, saName, saNs, saName, saName, saNs)
	return commandOnlyHint(target, command)
}

// cloudIMDSPivotHint is the composite hint: a NetworkPolicy that blocks egress
// to 169.254.169.254/32 (the IMDS endpoint) so a compromised pod cannot steal
// node-role credentials, paired with the IRSA annotate command so the workload
// has a legitimate path to scoped AWS credentials instead. The command body
// uses a heredoc to apply the policy and a follow-up kubectl annotate for the
// SA; both are required for a real fix (NetworkPolicy alone breaks workloads
// that legitimately need AWS, IRSA alone leaves the IMDS pivot reachable).
func cloudIMDSPivotHint(finding models.Finding) *models.RemediationHint {
	target := irsaPatchTarget(finding)
	saNs, saName := saFromFinding(finding)
	if saNs == "" {
		saNs = "<namespace>"
	}
	if saName == "" {
		saName = "<service-account>"
	}
	command := fmt.Sprintf(`# A compromised pod in %s can reach IMDS (169.254.169.254) and steal the EC2
# node-role credentials. Fix in two parts: (1) block IMDS egress with a
# NetworkPolicy, (2) give the workload its own IRSA role so it has a scoped
# alternative to the stolen node role.
#
# Part 1: block IMDS egress (allow DNS + intra-cluster traffic, deny IMDS).
cat <<'EOF' | kubectl apply -n %s -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-imds-egress
  namespace: %s
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - ipBlock:
        cidr: 0.0.0.0/0
        except:
        - 169.254.169.254/32
        - 169.254.170.0/24
  - to:
    - namespaceSelector: {}
  - ports:
    - protocol: UDP
      port: 53
    - protocol: TCP
      port: 53
EOF
#
# Part 2: annotate the SA for IRSA so the workload assumes a scoped AWS role
# instead of inheriting the node role from IMDS.
kubectl annotate sa %s -n %s eks.amazonaws.com/role-arn=arn:aws:iam::<account>:role/<scoped-role> --overwrite`,
		saNs, saNs, saNs, saName, saNs)
	return commandOnlyHint(target, command)
}

// awsAuthPatchTarget returns a PatchTarget pointed at kube-system/aws-auth.
// We do not rely on patchTargetFromFinding because the cloud analyzer attaches
// the offending ARN as the Resource (or sets Resource to the ConfigMap), and
// either way the operator command always edits kube-system/aws-auth.
func awsAuthPatchTarget(finding models.Finding) models.PatchTarget {
	if t, ok := patchTargetFromFinding(finding); ok && t.Kind == "ConfigMap" {
		return t
	}
	return models.PatchTarget{
		Kind:       "ConfigMap",
		APIVersion: "v1",
		Namespace:  "kube-system",
		Name:       "aws-auth",
	}
}

// irsaPatchTarget returns the patch target for the offending ServiceAccount.
// The cloud analyzer sets Resource.Kind = "ServiceAccount" on IRSA findings and
// Resource.Kind = the workload kind (Pod / Deployment / ...) on IRSA-MISSING /
// IMDS-PIVOT findings. We always want the SA: annotating the workload would
// drift the SA back on the next rollout.
func irsaPatchTarget(finding models.Finding) models.PatchTarget {
	saNs, saName := saFromFinding(finding)
	if saName == "" {
		// Fall back to the finding's Resource: the operator at least gets a
		// reasonable target name in the kubectl Command rendering.
		if t, ok := patchTargetFromFinding(finding); ok {
			return t
		}
	}
	return models.PatchTarget{
		Kind:       "ServiceAccount",
		APIVersion: "v1",
		Namespace:  saNs,
		Name:       saName,
	}
}

// saFromFinding pulls the (namespace, name) of the ServiceAccount the finding
// is about. Looks at the Finding's Subject (cloud analyzer sets Kind=ServiceAccount
// for IRSA findings) first, then Resource, then the "sa" evidence key the
// IRSA-MISSING / IMDS-PIVOT generators emit. Returns empty strings when nothing
// matches so callers can degrade to a placeholder.
func saFromFinding(finding models.Finding) (string, string) {
	if finding.Subject != nil && finding.Subject.Kind == "ServiceAccount" {
		return finding.Subject.Namespace, finding.Subject.Name
	}
	if finding.Resource != nil && finding.Resource.Kind == "ServiceAccount" {
		return finding.Resource.Namespace, finding.Resource.Name
	}
	if raw := stringFromEvidence(finding.Evidence, "sa"); raw != "" {
		if i := strings.Index(raw, "/"); i > 0 {
			return raw[:i], raw[i+1:]
		}
	}
	return "", ""
}

// awsAuthARNFromFinding pulls the IAM principal ARN out of the finding. The
// cloud analyzer sets it both on Subject.Name (for graph attribution) and in
// the "arn" evidence key; we prefer the evidence key because it survives
// rebuilds, and fall back to the Subject for older snapshots.
func awsAuthARNFromFinding(finding models.Finding) string {
	if arn := stringFromEvidence(finding.Evidence, "arn"); arn != "" {
		return arn
	}
	if finding.Subject != nil && finding.Subject.Name != "" {
		return finding.Subject.Name
	}
	return ""
}

// arnDisplay returns the ARN string for inline rendering. When no ARN is known
// (defensive: the analyzer always populates it today) we surface a placeholder
// so the comment line stays readable instead of collapsing into ":".
func arnDisplay(arn string) string {
	if arn == "" {
		return "<arn-from-evidence>"
	}
	return arn
}

// stringFromEvidence extracts a string field from a Finding's JSON evidence.
// Returns "" when the key is absent, the JSON is malformed, or the value is
// not a string. Cloud-specific cousin of network.go's stringFieldFromEvidence;
// duplicated to keep the cloud generator self-contained.
func stringFromEvidence(evidence json.RawMessage, key string) string {
	if len(evidence) == 0 {
		return ""
	}
	var decoded map[string]any
	if err := json.Unmarshal(evidence, &decoded); err != nil {
		return ""
	}
	if v, ok := decoded[key].(string); ok {
		return v
	}
	return ""
}
