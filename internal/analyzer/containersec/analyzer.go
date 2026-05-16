package containersec

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/remediation"
	"github.com/0hardik1/kubesplaining/internal/scoring"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Analyzer is the container-security module. It surfaces container-template settings
// that weaken runtime hardening without granting RBAC: missing resource limits /
// requests, missing liveness / readiness probes, lifecycle exec hooks, and image
// references that disable digest pinning. Findings aggregate per workload (controller-
// owned pods are skipped to avoid duplicating the workload finding).
type Analyzer struct{}

// target is a normalized workload reference carrying its pod template for uniform inspection.
type target struct {
	Kind      string
	Name      string
	Namespace string
	PodSpec   corev1.PodSpec
}

// New returns a new container-security analyzer.
func New() *Analyzer {
	return &Analyzer{}
}

// Name returns the module identifier used by --only-modules / --skip-modules and by
// the engine's module factory registry in internal/analyzer/modules.go.
func (a *Analyzer) Name() string {
	return "containersec"
}

// Analyze iterates each pod template in the snapshot and emits findings for missing
// resource limits/requests, missing probes, lifecycle exec hooks, and non-digest image
// references. Each rule is per-container, so the per-finding ID includes the container
// name suffix to avoid collisions when a workload has multiple containers.
func (a *Analyzer) Analyze(_ context.Context, snapshot models.Snapshot) ([]models.Finding, error) {
	findings := make([]models.Finding, 0)
	seen := map[string]struct{}{}

	for _, t := range collectTargets(snapshot) {
		for _, container := range allContainers(t.PodSpec) {
			if missing := missingResourceFields(container); missing.any() {
				content := contentLimits001(t.Kind, t.Namespace, t.Name, container.Name,
					missing.CPULimit, missing.MemLimit, missing.CPUReq, missing.MemReq)
				evidence := map[string]any{
					"container":         container.Name,
					"missing_cpu_limit": missing.CPULimit,
					"missing_mem_limit": missing.MemLimit,
					"missing_cpu_req":   missing.CPUReq,
					"missing_mem_req":   missing.MemReq,
				}
				findings = appendUnique(findings, seen, newFinding(t, container.Name,
					"KUBE-CONTAINER-LIMITS-001", models.SeverityMedium,
					models.CategoryInfrastructureModification, scoring.Clamp(5.0),
					evidence, "missingResources", content))
			}

			if missingProbes(container) {
				content := contentProbe001(t.Kind, t.Namespace, t.Name, container.Name)
				evidence := map[string]any{
					"container":               container.Name,
					"missing_liveness_probe":  true,
					"missing_readiness_probe": true,
				}
				findings = appendUnique(findings, seen, newFinding(t, container.Name,
					"KUBE-CONTAINER-PROBE-001", models.SeverityLow,
					models.CategoryDefenseEvasion, scoring.Clamp(3.5),
					evidence, "missingProbes", content))
			}

			if hook, command, ok := lifecycleExecHook(container); ok {
				content := contentLifecycle001(t.Kind, t.Namespace, t.Name, container.Name, hook, command)
				evidence := map[string]any{
					"container": container.Name,
					"hook":      hook,
					"command":   command,
				}
				findings = appendUnique(findings, seen, newFinding(t, container.Name,
					"KUBE-CONTAINER-LIFECYCLE-001", models.SeverityMedium,
					models.CategoryDefenseEvasion, scoring.Clamp(5.5),
					evidence, "lifecycleExec", content))
			}

			if needsDigestPin(container) {
				policy := ""
				if container.ImagePullPolicy != "" {
					policy = string(container.ImagePullPolicy)
				}
				content := contentImage001(t.Kind, t.Namespace, t.Name, container.Name, container.Image, policy)
				evidence := map[string]any{
					"container":         container.Name,
					"image":             container.Image,
					"image_pull_policy": policy,
					"digest_pinned":     false,
				}
				findings = appendUnique(findings, seen, newFinding(t, container.Name,
					"KUBE-CONTAINER-IMAGE-001", models.SeverityMedium,
					models.CategoryDefenseEvasion, scoring.Clamp(5.0),
					evidence, "imageDigestPin", content))
			}
		}
	}

	return findings, nil
}

// missingResources records which of the four resource fields (CPU/memory × requests/limits)
// the container omits. The analyzer fires on *any* missing field rather than requiring
// the full quartet so partial QoS misconfigurations (e.g. limits set, no requests) still
// surface.
type missingResources struct {
	CPULimit, MemLimit, CPUReq, MemReq bool
}

// any reports whether at least one of the resource fields is missing.
func (m missingResources) any() bool {
	return m.CPULimit || m.MemLimit || m.CPUReq || m.MemReq
}

// missingResourceFields inspects the container's Resources map and records which of
// the four request/limit slots are not declared. ResourceList is a map keyed by the
// resource name; a present key with a zero value still counts as "set" by the kubelet,
// so we only check key presence here.
func missingResourceFields(c corev1.Container) missingResources {
	out := missingResources{
		CPULimit: !hasResource(c.Resources.Limits, corev1.ResourceCPU),
		MemLimit: !hasResource(c.Resources.Limits, corev1.ResourceMemory),
		CPUReq:   !hasResource(c.Resources.Requests, corev1.ResourceCPU),
		MemReq:   !hasResource(c.Resources.Requests, corev1.ResourceMemory),
	}
	return out
}

// hasResource reports whether the given ResourceList declares the named resource.
func hasResource(list corev1.ResourceList, name corev1.ResourceName) bool {
	if list == nil {
		return false
	}
	_, ok := list[name]
	return ok
}

// missingProbes reports whether the container declares neither a liveness nor a
// readiness probe. A startup probe alone does not satisfy this check: startup is a
// one-shot gate, while liveness and readiness drive ongoing restart and load-balancing.
func missingProbes(c corev1.Container) bool {
	return c.LivenessProbe == nil && c.ReadinessProbe == nil
}

// lifecycleExecHook reports whether the container declares a postStart or preStop exec
// hook with a non-trivial command. Returns the hook name (`postStart` or `preStop`),
// the rendered command string for evidence/title, and a boolean.
//
// A non-trivial command is anything other than a simple `sleep` invocation: a number
// of upstream charts (Istio, Argo, NGINX ingress) ship `preStop: ["sh","-c","sleep 5"]`
// as a graceful-shutdown delay, which is benign. Anything else surfaces.
func lifecycleExecHook(c corev1.Container) (hook, command string, ok bool) {
	if c.Lifecycle == nil {
		return "", "", false
	}
	if c.Lifecycle.PostStart != nil && c.Lifecycle.PostStart.Exec != nil {
		cmd := strings.Join(c.Lifecycle.PostStart.Exec.Command, " ")
		if !isTrivialSleep(c.Lifecycle.PostStart.Exec.Command) {
			return "postStart", cmd, true
		}
	}
	if c.Lifecycle.PreStop != nil && c.Lifecycle.PreStop.Exec != nil {
		cmd := strings.Join(c.Lifecycle.PreStop.Exec.Command, " ")
		if !isTrivialSleep(c.Lifecycle.PreStop.Exec.Command) {
			return "preStop", cmd, true
		}
	}
	return "", "", false
}

// isTrivialSleep reports whether an exec command is just `sleep <duration>` (with or
// without a shell wrapper). Graceful-shutdown sleeps are a common, benign pattern that
// would otherwise generate constant noise on every well-formed Helm chart.
func isTrivialSleep(cmd []string) bool {
	if len(cmd) == 0 {
		return true
	}
	if len(cmd) >= 1 && cmd[0] == "sleep" {
		return true
	}
	// Shell wrappers: `sh -c "sleep N"` or `/bin/sh -c "sleep N"`.
	if len(cmd) >= 3 && (cmd[0] == "sh" || cmd[0] == "/bin/sh" || cmd[0] == "bash" || cmd[0] == "/bin/bash") && cmd[1] == "-c" {
		body := strings.TrimSpace(cmd[2])
		if strings.HasPrefix(body, "sleep") {
			rest := strings.TrimSpace(strings.TrimPrefix(body, "sleep"))
			// Reject anything chained beyond the duration argument (`&&`, `;`, `|`).
			if !strings.ContainsAny(rest, "|;&") {
				return true
			}
		}
	}
	return false
}

// needsDigestPin reports whether the container's image reference is mutable (no
// `@sha256:` digest) and would silently swap on the next pod start. The rule is
// intentionally scoped to digest-pinning (not just `:latest`) so it does *not*
// duplicate KUBE-IMAGE-LATEST-001 in the podsec module, which fires on mutable tags
// alone. This rule fires when:
//
//   - the image is not digest-pinned, AND
//   - the pull policy is `Always` (explicit or the kubelet default for `:latest`), so
//     the next pod start re-resolves the tag from the registry.
//
// If the image is digest-pinned, or if pull policy is `IfNotPresent` / `Never` and the
// tag is immutable (e.g. `:v1.2.3` with `IfNotPresent`), this rule does not fire even
// though podsec's KUBE-IMAGE-LATEST-001 still flags the underlying mutable tag.
func needsDigestPin(c corev1.Container) bool {
	if strings.Contains(c.Image, "@sha256:") {
		return false
	}
	policy := c.ImagePullPolicy
	if policy == "" {
		// Kubernetes default: Always when tag is :latest or omitted, IfNotPresent otherwise.
		if usesMutableTag(c.Image) {
			policy = corev1.PullAlways
		} else {
			policy = corev1.PullIfNotPresent
		}
	}
	return policy == corev1.PullAlways
}

// usesMutableTag reports whether the image reference is mutable (no `@sha256:` digest,
// either `:latest` or no explicit tag).
func usesMutableTag(image string) bool {
	if strings.Contains(image, "@sha256:") {
		return false
	}
	// A colon after the last `/` separates the repo from the tag. No colon means
	// the implicit `:latest` tag.
	idx := strings.LastIndex(image, "/")
	rest := image
	if idx >= 0 {
		rest = image[idx+1:]
	}
	if !strings.Contains(rest, ":") {
		return true
	}
	return strings.HasSuffix(image, ":latest")
}

// collectTargets flattens bare pods (skipping controller-managed ones to avoid
// duplicate findings, matching the podsec module's pattern) and every workload-kind
// pod template into target entries. ReplicaSets are not iterated because they are
// always owned by a Deployment.
func collectTargets(snapshot models.Snapshot) []target {
	targets := make([]target, 0, len(snapshot.Resources.Pods)+len(snapshot.Resources.Deployments))

	for _, pod := range snapshot.Resources.Pods {
		if isControlledPod(pod.ObjectMeta) {
			continue
		}
		targets = append(targets, target{
			Kind:      "Pod",
			Name:      pod.Name,
			Namespace: pod.Namespace,
			PodSpec:   pod.Spec,
		})
	}
	for _, d := range snapshot.Resources.Deployments {
		targets = append(targets, target{Kind: "Deployment", Name: d.Name, Namespace: d.Namespace, PodSpec: d.Spec.Template.Spec})
	}
	for _, ds := range snapshot.Resources.DaemonSets {
		targets = append(targets, target{Kind: "DaemonSet", Name: ds.Name, Namespace: ds.Namespace, PodSpec: ds.Spec.Template.Spec})
	}
	for _, ss := range snapshot.Resources.StatefulSets {
		targets = append(targets, target{Kind: "StatefulSet", Name: ss.Name, Namespace: ss.Namespace, PodSpec: ss.Spec.Template.Spec})
	}
	for _, j := range snapshot.Resources.Jobs {
		targets = append(targets, target{Kind: "Job", Name: j.Name, Namespace: j.Namespace, PodSpec: j.Spec.Template.Spec})
	}
	for _, cj := range snapshot.Resources.CronJobs {
		targets = append(targets, target{Kind: "CronJob", Name: cj.Name, Namespace: cj.Namespace, PodSpec: cj.Spec.JobTemplate.Spec.Template.Spec})
	}

	return targets
}

// isControlledPod reports whether a pod is owned by a controller (Deployment via
// ReplicaSet, DaemonSet, StatefulSet, Job, CronJob). The analyzer defers to the
// workload kind so each finding fires once per workload, not once per replica.
func isControlledPod(meta metav1.ObjectMeta) bool {
	for _, owner := range meta.OwnerReferences {
		if owner.Controller != nil && *owner.Controller {
			return true
		}
	}
	return false
}

// allContainers returns init and runtime containers in a single slice for uniform
// iteration. Init containers can be just as dangerous when missing resource limits
// (they share the pod's QoS classification) or running lifecycle exec hooks (init
// containers cannot, but the analyzer relies on the kube-apiserver to reject those).
func allContainers(spec corev1.PodSpec) []corev1.Container {
	items := make([]corev1.Container, 0, len(spec.InitContainers)+len(spec.Containers))
	items = append(items, spec.InitContainers...)
	items = append(items, spec.Containers...)
	return items
}

// newFinding materializes a containersec Finding using the enriched ruleContent plus
// the runtime context. The Finding.ID always carries the container suffix so multiple
// containers in the same workload produce distinct findings.
func newFinding(t target, container, ruleID string, severity models.Severity, category models.RiskCategory, score float64, evidence map[string]any, check string, content ruleContent) models.Finding {
	evidenceBytes, _ := json.Marshal(evidence)
	resource := &models.ResourceRef{
		Kind:      t.Kind,
		Name:      t.Name,
		Namespace: t.Namespace,
		APIGroup:  resourceAPIGroup(t.Kind),
	}
	references := make([]string, 0, len(content.LearnMore))
	for _, ref := range content.LearnMore {
		references = append(references, ref.URL)
	}
	return models.Finding{
		ID:               fmt.Sprintf("%s:%s:%s:%s:%s", ruleID, t.Kind, t.Namespace, t.Name, container),
		RuleID:           ruleID,
		Severity:         severity,
		Score:            score,
		Category:         category,
		Title:            content.Title,
		Description:      content.Description,
		Namespace:        t.Namespace,
		Resource:         resource,
		Scope:            content.Scope,
		Impact:           content.Impact,
		AttackScenario:   content.AttackScenario,
		Evidence:         evidenceBytes,
		Remediation:      content.Remediation,
		RemediationSteps: content.RemediationSteps,
		References:       references,
		LearnMore:        content.LearnMore,
		MitreTechniques:  content.MitreTechniques,
		Tags:             []string{"module:container_security", "check:" + check},
	}
}

// appendUnique deduplicates by Finding.ID before appending. The ID already carries
// rule + workload + container so collisions only happen on a re-evaluation, but the
// guard is cheap and matches the podsec / network modules. The structured
// RemediationHint is attached here (rather than at every call site) so the analyzer's
// per-rule blocks stay focused on detection: the moment we know we are emitting a
// finding, ask the remediation generator for the matching kubectl patch.
func appendUnique(findings []models.Finding, seen map[string]struct{}, finding models.Finding) []models.Finding {
	if _, ok := seen[finding.ID]; ok {
		return findings
	}
	seen[finding.ID] = struct{}{}
	finding.RemediationHint = remediation.ForContainerSec(finding.RuleID, finding)
	return append(findings, finding)
}

// resourceAPIGroup returns the Kubernetes API group for a workload kind. Matches the
// podsec module's helper; kept local so the package stays self-contained.
func resourceAPIGroup(kind string) string {
	switch kind {
	case "Deployment", "DaemonSet", "StatefulSet":
		return appsv1.GroupName
	case "Job", "CronJob":
		return batchv1.GroupName
	default:
		return ""
	}
}
