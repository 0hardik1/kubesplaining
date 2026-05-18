// Package eks: IRSA (IAM Roles for Service Accounts) analyzers.
//
// Two rules live here:
//
//   - KUBE-CLOUD-IRSA-ADMIN-ROLE-001: a ServiceAccount is bound (via the
//     `eks.amazonaws.com/role-arn` annotation) to an IAM role whose name
//     screams "admin": either AWS's reserved SSO AdministratorAccess
//     permission-set roles, or operator-chosen names containing
//     `Administrator`, `FullAccess`, or `PowerUserAccess`. The IRSA token any
//     pod using that SA gets is, effectively, an AWS admin token.
//
//   - KUBE-CLOUD-IRSA-MISSING-001: a pod looks like it talks to AWS (AWS
//     SDK / CLI image, AWS_-prefixed env vars), but its ServiceAccount has
//     no IRSA annotation. The pod is probably falling back to the node's
//     IMDS / EC2 instance profile, which leaks node-level AWS privileges
//     to every workload on that node.
package eks

import (
	"encoding/json"
	"fmt"

	"github.com/0hardik1/kubesplaining/internal/models"
	corev1 "k8s.io/api/core/v1"
)

// IRSAAnnotation is the well-known EKS annotation that binds a Kubernetes
// ServiceAccount to an AWS IAM role. The annotation value is the role's ARN.
const IRSAAnnotation = "eks.amazonaws.com/role-arn"

// AnalyzeIRSA returns all IRSA-related findings for the snapshot. It is safe
// to call regardless of CloudProvider: on a non-EKS snapshot it finds no IRSA
// annotations and emits nothing.
func AnalyzeIRSA(snapshot models.Snapshot) []models.Finding {
	var findings []models.Finding
	findings = append(findings, analyzeIRSAAdminRole(snapshot)...)
	findings = append(findings, analyzeIRSAMissing(snapshot)...)
	return findings
}

// analyzeIRSAAdminRole emits KUBE-CLOUD-IRSA-ADMIN-ROLE-001 for each
// ServiceAccount whose IRSA role-ARN matches an admin-like pattern.
func analyzeIRSAAdminRole(snapshot models.Snapshot) []models.Finding {
	var findings []models.Finding
	for _, sa := range snapshot.Resources.ServiceAccounts {
		arn, ok := sa.Annotations[IRSAAnnotation]
		if !ok || arn == "" {
			continue
		}
		matched, reason, keyword := ARNAdminLikely(arn)
		if !matched {
			continue
		}
		score := 7.8
		if reason == "reserved-sso-admin" {
			score = 9.2
		}
		evidence := map[string]any{
			"sa":             fmt.Sprintf("%s/%s", sa.Namespace, sa.Name),
			"arn":            arn,
			"matchedKeyword": keyword,
			"reason":         reason,
		}
		evidenceBytes, _ := json.Marshal(evidence)
		findings = append(findings, models.Finding{
			ID:          fmt.Sprintf("KUBE-CLOUD-IRSA-ADMIN-ROLE-001:%s:%s", sa.Namespace, sa.Name),
			RuleID:      "KUBE-CLOUD-IRSA-ADMIN-ROLE-001",
			Severity:    models.SeverityHigh,
			Score:       score,
			Category:    models.CategoryPrivilegeEscalation,
			Title:       "ServiceAccount bound to admin-flavored IAM role via IRSA",
			Description: fmt.Sprintf("ServiceAccount %s/%s is annotated with %s=%s; the role name matches an admin pattern (%s). Any pod using this SA receives an IRSA token that authenticates to AWS as that role.", sa.Namespace, sa.Name, IRSAAnnotation, arn, reason),
			Namespace:   sa.Namespace,
			Subject: &models.SubjectRef{
				Kind:      "ServiceAccount",
				Name:      sa.Name,
				Namespace: sa.Namespace,
			},
			Resource: &models.ResourceRef{
				Kind:      "ServiceAccount",
				Name:      sa.Name,
				Namespace: sa.Namespace,
			},
			Scope: models.Scope{
				Level:  models.ScopeWorkload,
				Detail: fmt.Sprintf("ServiceAccount %s/%s and every pod that mounts it", sa.Namespace, sa.Name),
			},
			Evidence:    evidenceBytes,
			Remediation: "Replace the admin role with a least-privilege IAM role scoped to the API actions the workload actually needs.",
			Tags:        []string{"module:cloud", "provider:eks", "check:irsaAdmin"},
		})
	}
	return findings
}

// analyzeIRSAMissing emits KUBE-CLOUD-IRSA-MISSING-001 for each (uncontrolled)
// pod or workload that shows AWS hints but whose SA lacks the IRSA annotation.
func analyzeIRSAMissing(snapshot models.Snapshot) []models.Finding {
	// Index SAs by (namespace, name) for fast lookup; SA without IRSA
	// annotation is treated as "missing", which is exactly the case we want
	// to flag (so a nil lookup also counts as missing).
	saIndex := make(map[string]corev1.ServiceAccount, len(snapshot.Resources.ServiceAccounts))
	for _, sa := range snapshot.Resources.ServiceAccounts {
		saIndex[saKey(sa.Namespace, sa.Name)] = sa
	}

	var findings []models.Finding

	// Bare pods (skip controller-owned: they're represented by their workload).
	for _, pod := range snapshot.Resources.Pods {
		if isControlledPod(pod.ObjectMeta) {
			continue
		}
		if finding, ok := buildMissingFinding(pod.Spec, pod.Namespace, pod.Name, "Pod", pod.Name, saIndex); ok {
			findings = append(findings, finding)
		}
	}

	// Workloads: their pod template's SA + container spec is the unit we judge.
	for _, deployment := range snapshot.Resources.Deployments {
		if finding, ok := buildMissingFinding(deployment.Spec.Template.Spec, deployment.Namespace, deployment.Name, "Deployment", deployment.Name, saIndex); ok {
			findings = append(findings, finding)
		}
	}
	for _, ds := range snapshot.Resources.DaemonSets {
		if finding, ok := buildMissingFinding(ds.Spec.Template.Spec, ds.Namespace, ds.Name, "DaemonSet", ds.Name, saIndex); ok {
			findings = append(findings, finding)
		}
	}
	for _, ss := range snapshot.Resources.StatefulSets {
		if finding, ok := buildMissingFinding(ss.Spec.Template.Spec, ss.Namespace, ss.Name, "StatefulSet", ss.Name, saIndex); ok {
			findings = append(findings, finding)
		}
	}
	for _, job := range snapshot.Resources.Jobs {
		if finding, ok := buildMissingFinding(job.Spec.Template.Spec, job.Namespace, job.Name, "Job", job.Name, saIndex); ok {
			findings = append(findings, finding)
		}
	}
	for _, cj := range snapshot.Resources.CronJobs {
		if finding, ok := buildMissingFinding(cj.Spec.JobTemplate.Spec.Template.Spec, cj.Namespace, cj.Name, "CronJob", cj.Name, saIndex); ok {
			findings = append(findings, finding)
		}
	}

	return findings
}

// buildMissingFinding inspects a pod spec for AWS hints and returns a
// Rule #4 finding if (a) at least one hint matches and (b) the SA it would
// run as lacks the IRSA annotation. The owner-kind / owner-name pair is used
// for the Resource ref so the finding points at the workload (or pod) the
// operator actually edits.
func buildMissingFinding(spec corev1.PodSpec, namespace, podName, ownerKind, ownerName string, saIndex map[string]corev1.ServiceAccount) (models.Finding, bool) {
	saName := spec.ServiceAccountName
	if saName == "" {
		saName = "default"
	}
	sa, found := saIndex[saKey(namespace, saName)]
	if found {
		if _, hasIRSA := sa.Annotations[IRSAAnnotation]; hasIRSA {
			return models.Finding{}, false
		}
	}
	hint, hintKind := firstAWSHint(spec)
	if hint == "" {
		return models.Finding{}, false
	}
	evidence := map[string]any{
		"pod":         fmt.Sprintf("%s/%s", namespace, podName),
		"sa":          fmt.Sprintf("%s/%s", namespace, saName),
		"matchedHint": hint,
		"hintKind":    hintKind,
	}
	evidenceBytes, _ := json.Marshal(evidence)
	return models.Finding{
		ID:          fmt.Sprintf("KUBE-CLOUD-IRSA-MISSING-001:%s:%s:%s", namespace, ownerKind, ownerName),
		RuleID:      "KUBE-CLOUD-IRSA-MISSING-001",
		Severity:    models.SeverityLow,
		Score:       3.5,
		Category:    models.CategoryPrivilegeEscalation,
		Title:       "Pod talks to AWS but its ServiceAccount has no IRSA annotation",
		Description: fmt.Sprintf("Pod %s/%s shows AWS-SDK hints (%s: %s) but its ServiceAccount %s/%s carries no %s annotation. Without IRSA, AWS SDKs typically fall back to the node's IMDS-served instance profile, which gives every workload on that node the same AWS privileges.", namespace, podName, hintKind, hint, namespace, saName, IRSAAnnotation),
		Namespace:   namespace,
		Subject: &models.SubjectRef{
			Kind:      "ServiceAccount",
			Name:      saName,
			Namespace: namespace,
		},
		Resource: &models.ResourceRef{
			Kind:      ownerKind,
			Name:      ownerName,
			Namespace: namespace,
		},
		Scope: models.Scope{
			Level:  models.ScopeWorkload,
			Detail: fmt.Sprintf("Workload %s/%s/%s", namespace, ownerKind, ownerName),
		},
		Evidence:    evidenceBytes,
		Remediation: "Create a least-privilege IAM role for the workload and annotate its ServiceAccount with eks.amazonaws.com/role-arn.",
		Tags:        []string{"module:cloud", "provider:eks", "check:irsaMissing"},
	}, true
}

// firstAWSHint returns the first matching AWS-SDK hint (and its kind: "image"
// or "env") seen in the pod spec's containers + init containers. The first
// match wins so evidence stays small; the rule fires at most once per pod.
func firstAWSHint(spec corev1.PodSpec) (string, string) {
	for _, c := range append(append([]corev1.Container{}, spec.InitContainers...), spec.Containers...) {
		if hint := AWSSDKImageHint(c.Image); hint != "" {
			return hint, "image"
		}
		for _, env := range c.Env {
			if hint := AWSSDKEnvHint(env.Name); hint != "" {
				return hint, "env"
			}
		}
	}
	return "", ""
}

// saKey and isControlledPod live in imds_pivot.go (Unit 3); reused here.
