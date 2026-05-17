// Package eks - IMDS pivot analyzer.
// Correlates network reachability of 169.254.169.254 with absence of IRSA binding
// on EKS clusters. Emits KUBE-CLOUD-IMDS-PIVOT-001 when a compromised pod would
// fall back to the worker node's IAM role via the EC2 IMDS endpoint.
//
// Design: eks lives below cloud (cloud/analyzer.go imports cloud/eks), so this
// sub-package cannot import its parent without creating an import cycle. The
// per-rule prose is mirrored in internal/analyzer/cloud/content_imds.go so a
// future coordinator can centralize it; for now both sites declare their own
// content so each package compiles standalone.
package eks

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/0hardik1/kubesplaining/internal/analyzer/network"
	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/scoring"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// irsaAnnotation is the EKS-specific annotation on a ServiceAccount that
// binds it to an IAM role via OIDC. When present, the pod's AWS SDK calls
// short-circuit to STS AssumeRoleWithWebIdentity instead of falling back to
// the node's instance-profile credentials, so the IMDS-pivot story disappears.
const irsaAnnotation = "eks.amazonaws.com/role-arn"

// fargateComputeTypeLabel is the node label EKS attaches to Fargate-backed
// nodes. Fargate nodes do not expose IMDS to pods, so pods scheduled there
// have no IMDS-pivot story.
const (
	fargateComputeTypeLabel = "eks.amazonaws.com/compute-type"
	fargateComputeTypeValue = "fargate"
)

// imdsPivotWorkload is a label-bearing reference to a pod or controlling workload.
// Mirrors the unexported `workload` type in internal/analyzer/network/analyzer.go
// but lives here so this package compiles without depending on that internal type.
type imdsPivotWorkload struct {
	Kind           string
	Name           string
	Namespace      string
	Labels         map[string]string
	SANamespace    string // ServiceAccount namespace (always == Namespace for now; kept explicit for clarity)
	SAName         string // ServiceAccount name; defaults to "default" when unset
	NodeName       string // populated only for Pod workloads when scheduled
	IsScheduledPod bool   // true only when Kind == "Pod" AND NodeName != ""
}

// AnalyzeIMDSPivot emits KUBE-CLOUD-IMDS-PIVOT-001 findings for the snapshot.
// Returns nil when snapshot.Metadata.CloudProvider != "eks" (the rule is
// EKS-specific because the IRSA + node-IAM pivot story is AWS-shaped).
func AnalyzeIMDSPivot(snapshot models.Snapshot) []models.Finding {
	if snapshot.Metadata.CloudProvider != "eks" {
		return nil
	}

	workloads := collectIMDSPivotWorkloads(snapshot)
	saIndex := indexServiceAccounts(snapshot.Resources.ServiceAccounts)
	fargateNodes := fargateNodeSet(snapshot.Resources.Nodes)

	out := make([]models.Finding, 0)
	for _, wl := range workloads {
		reachable, reason, offenderCIDR, _ := network.IMDSReachable(snapshot, wl.Kind, wl.Name, wl.Namespace, wl.Labels)
		if !reachable {
			continue
		}

		sa, ok := saIndex[saKey(wl.SANamespace, wl.SAName)]
		if ok {
			if _, irsa := sa.Annotations[irsaAnnotation]; irsa {
				// IRSA-bound SA: AWS SDK calls hit STS, not the node IAM role.
				continue
			}
		}

		// Fargate carve-out: scheduled Pod whose node is Fargate-labeled has
		// no IMDS exposure. Unscheduled pods (no NodeName) MUST still emit:
		// they could be scheduled onto an EC2 node later. Controlling workloads
		// (Deployment/etc.) also still emit because we cannot know in advance
		// where the replicas will land.
		if wl.IsScheduledPod && fargateNodes[wl.NodeName] {
			continue
		}

		content := contentIMDSPivotEKS()
		evidence := map[string]any{
			"pod":          fmt.Sprintf("%s/%s", wl.Namespace, wl.Name),
			"workload":     fmt.Sprintf("%s/%s/%s", wl.Kind, wl.Namespace, wl.Name),
			"sa":           fmt.Sprintf("%s/%s", wl.SANamespace, wl.SAName),
			"reason":       reason,
			"offenderCIDR": offenderCIDR,
			"fallbackTo":   "node-iam-role",
		}
		evidenceBytes, _ := json.Marshal(evidence)

		out = append(out, models.Finding{
			ID:          fmt.Sprintf("KUBE-CLOUD-IMDS-PIVOT-001:%s:%s:%s", wl.Kind, wl.Namespace, wl.Name),
			RuleID:      "KUBE-CLOUD-IMDS-PIVOT-001",
			Severity:    models.SeverityHigh,
			Score:       scoring.Clamp(8.2),
			Category:    models.CategoryPrivilegeEscalation,
			Title:       content.Title,
			Description: content.Description,
			Namespace:   wl.Namespace,
			Subject: &models.SubjectRef{
				Kind:      "ServiceAccount",
				Name:      wl.SAName,
				Namespace: wl.SANamespace,
			},
			Resource: &models.ResourceRef{
				Kind:      wl.Kind,
				Name:      wl.Name,
				Namespace: wl.Namespace,
				APIGroup:  workloadAPIGroup(wl.Kind),
			},
			Scope:            content.Scope,
			Impact:           content.Impact,
			AttackScenario:   content.AttackScenario,
			Evidence:         evidenceBytes,
			Remediation:      content.Remediation,
			RemediationSteps: content.RemediationSteps,
			References:       referencesFromContent(content),
			LearnMore:        content.LearnMore,
			MitreTechniques:  content.MitreTechniques,
			Tags:             []string{"module:cloud", "module:network_policy", "provider:eks", "check:imdsPivot"},
		})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		if out[i].Resource.Kind != out[j].Resource.Kind {
			return out[i].Resource.Kind < out[j].Resource.Kind
		}
		return out[i].Resource.Name < out[j].Resource.Name
	})
	return out
}

// collectIMDSPivotWorkloads flattens the snapshot's pod-spec sources into the
// local imdsPivotWorkload type. Mirrors network.collectWorkloads exactly: Pods
// owned by a controller are dropped in favor of the controlling workload so
// findings are not duplicated per replica. The (namespace, kind, name, labels)
// tuple is forwarded to network.IMDSReachable to reuse the existing
// NetworkPolicy semantics.
func collectIMDSPivotWorkloads(snapshot models.Snapshot) []imdsPivotWorkload {
	out := make([]imdsPivotWorkload, 0, len(snapshot.Resources.Pods)+len(snapshot.Resources.Deployments))

	for _, pod := range snapshot.Resources.Pods {
		if isControlledPod(pod.ObjectMeta) {
			continue
		}
		saName := pod.Spec.ServiceAccountName
		if saName == "" {
			saName = "default"
		}
		out = append(out, imdsPivotWorkload{
			Kind:           "Pod",
			Name:           pod.Name,
			Namespace:      pod.Namespace,
			Labels:         pod.Labels,
			SANamespace:    pod.Namespace,
			SAName:         saName,
			NodeName:       pod.Spec.NodeName,
			IsScheduledPod: pod.Spec.NodeName != "",
		})
	}
	for _, deployment := range snapshot.Resources.Deployments {
		out = append(out, workloadFromTemplate("Deployment", deployment.Name, deployment.Namespace, deployment.Spec.Template))
	}
	for _, ds := range snapshot.Resources.DaemonSets {
		out = append(out, workloadFromTemplate("DaemonSet", ds.Name, ds.Namespace, ds.Spec.Template))
	}
	for _, ss := range snapshot.Resources.StatefulSets {
		out = append(out, workloadFromTemplate("StatefulSet", ss.Name, ss.Namespace, ss.Spec.Template))
	}
	for _, job := range snapshot.Resources.Jobs {
		out = append(out, workloadFromTemplate("Job", job.Name, job.Namespace, job.Spec.Template))
	}
	for _, cronJob := range snapshot.Resources.CronJobs {
		out = append(out, workloadFromTemplate("CronJob", cronJob.Name, cronJob.Namespace, cronJob.Spec.JobTemplate.Spec.Template))
	}

	return out
}

// workloadFromTemplate builds an imdsPivotWorkload from a controller's pod
// template, defaulting the ServiceAccount to "default" when unset (which is
// the Kubernetes admission default).
func workloadFromTemplate(kind, name, namespace string, template corev1.PodTemplateSpec) imdsPivotWorkload {
	saName := template.Spec.ServiceAccountName
	if saName == "" {
		saName = "default"
	}
	return imdsPivotWorkload{
		Kind:        kind,
		Name:        name,
		Namespace:   namespace,
		Labels:      template.Labels,
		SANamespace: namespace,
		SAName:      saName,
	}
}

// isControlledPod reports whether a pod is controller-owned so the workload
// type is analyzed instead of the pod itself. Mirrors network.isControlledPod.
func isControlledPod(meta metav1.ObjectMeta) bool {
	for _, owner := range meta.OwnerReferences {
		if owner.Controller != nil && *owner.Controller {
			return true
		}
	}
	return false
}

// indexServiceAccounts builds a (namespace/name) -> ServiceAccount lookup so
// the analyzer can resolve a workload's SA in O(1).
func indexServiceAccounts(serviceAccounts []corev1.ServiceAccount) map[string]corev1.ServiceAccount {
	out := make(map[string]corev1.ServiceAccount, len(serviceAccounts))
	for _, sa := range serviceAccounts {
		out[saKey(sa.Namespace, sa.Name)] = sa
	}
	return out
}

// saKey is the canonical "namespace/name" key for ServiceAccount lookups.
func saKey(namespace, name string) string {
	return namespace + "/" + name
}

// fargateNodeSet returns a set of node names that carry the Fargate compute-type
// label. Used to skip pods that are already scheduled onto a Fargate node, since
// Fargate does not expose IMDS to pods.
func fargateNodeSet(nodes []corev1.Node) map[string]bool {
	out := make(map[string]bool)
	for _, node := range nodes {
		if node.Labels[fargateComputeTypeLabel] == fargateComputeTypeValue {
			out[node.Name] = true
		}
	}
	return out
}

// workloadAPIGroup returns the Kubernetes API group for a workload kind.
// Mirrors network.workloadAPIGroup so the resource ref is well-formed.
func workloadAPIGroup(kind string) string {
	switch kind {
	case "Deployment", "DaemonSet", "StatefulSet":
		return appsv1.GroupName
	case "Job", "CronJob":
		return batchv1.GroupName
	default:
		return ""
	}
}

// imdsPivotContent is the local mirror of cloud.contentImdsPivot001's shape.
// Kept private to this package so each cloud sub-package can ship its own
// per-rule prose without an import cycle on the parent. The fields match
// cloud.ruleContent verbatim; future coordinator refactors will collapse them.
type imdsPivotContent struct {
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

// contentIMDSPivotEKS returns the EKS-specific prose for KUBE-CLOUD-IMDS-PIVOT-001.
// Mirrors cloud.contentImdsPivot001; keep the two in sync until a coordinator
// can wire one through the other.
func contentIMDSPivotEKS() imdsPivotContent {
	return imdsPivotContent{
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

// referencesFromContent flattens content.LearnMore into a []string of URLs for
// the legacy References field. Mirrors the helper of the same name in the
// network package; kept local to avoid leaking the network package's
// unexported ruleContent shape.
func referencesFromContent(content imdsPivotContent) []string {
	urls := make([]string, 0, len(content.LearnMore))
	for _, ref := range content.LearnMore {
		urls = append(urls, ref.URL)
	}
	return urls
}
