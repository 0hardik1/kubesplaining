// Package podsec analyzes pod specs (and their controlling workloads) for
// container-runtime security issues like privileged containers, host namespace
// sharing, sensitive hostPath mounts, and insecure image tags.
package podsec

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/scoring"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Analyzer produces pod-security findings from a snapshot.
type Analyzer struct{}

// target is a normalized workload reference carrying its pod template for uniform inspection.
type target struct {
	Kind      string
	Name      string
	Namespace string
	PodSpec   corev1.PodSpec
}

// New returns a new pod-security analyzer.
func New() *Analyzer {
	return &Analyzer{}
}

// Name returns the module identifier used by the engine.
func (a *Analyzer) Name() string {
	return "podsec"
}

// Analyze iterates each pod template in the snapshot and emits findings for
// dangerous PodSpec-level settings, hostPath mounts, and container SecurityContext gaps.
func (a *Analyzer) Analyze(_ context.Context, snapshot models.Snapshot) ([]models.Finding, error) {
	findings := make([]models.Finding, 0)
	seen := map[string]struct{}{}

	for _, target := range collectTargets(snapshot) {
		serviceAccount := target.PodSpec.ServiceAccountName
		if serviceAccount == "" {
			serviceAccount = "default"
		}

		if serviceAccount == "default" && !strings.HasPrefix(target.Namespace, "kube-") {
			content := contentSADefault001(target.Kind, target.Namespace, target.Name, serviceAccount)
			findings = appendFinding(findings, seen, newFindingFromContent(target, "KUBE-SA-DEFAULT-001",
				models.SeverityMedium, models.CategoryPrivilegeEscalation, scoring.Clamp(5.4),
				map[string]any{"service_account": serviceAccount}, "defaultServiceAccount", content).as())
		}

		if target.PodSpec.HostNetwork {
			content := contentEscape003(target.Kind, target.Namespace, target.Name)
			findings = appendFinding(findings, seen, newFindingFromContent(target, "KUBE-ESCAPE-003",
				models.SeverityHigh, models.CategoryLateralMovement, scoring.Clamp(8.1),
				map[string]any{"hostNetwork": true}, "hostNetwork", content).as())
		}

		if target.PodSpec.HostPID {
			content := contentEscape002(target.Kind, target.Namespace, target.Name)
			findings = appendFinding(findings, seen, newFindingFromContent(target, "KUBE-ESCAPE-002",
				models.SeverityCritical, models.CategoryPrivilegeEscalation, scoring.Clamp(9.0),
				map[string]any{"hostPID": true}, "hostPID", content).as())
		}

		if target.PodSpec.HostIPC {
			content := contentEscape004(target.Kind, target.Namespace, target.Name)
			findings = appendFinding(findings, seen, newFindingFromContent(target, "KUBE-ESCAPE-004",
				models.SeverityHigh, models.CategoryPrivilegeEscalation, scoring.Clamp(8.0),
				map[string]any{"hostIPC": true}, "hostIPC", content).as())
		}

		for _, volume := range target.PodSpec.Volumes {
			if volume.HostPath == nil {
				continue
			}

			score := 7.6
			ruleID := "KUBE-HOSTPATH-001"
			var content ruleContent

			switch volume.HostPath.Path {
			case "/":
				score = 10
				ruleID = "KUBE-ESCAPE-006"
				content = contentEscape006(target.Kind, target.Namespace, target.Name, volume.Name)
			case "/var/run/docker.sock":
				score = 10
				ruleID = "KUBE-ESCAPE-005"
				content = contentEscape005(target.Kind, target.Namespace, target.Name, volume.Name)
			case "/var/run/containerd/containerd.sock":
				score = 9.8
				ruleID = "KUBE-CONTAINERD-SOCKET-001"
				content = contentContainerdSocket001(target.Kind, target.Namespace, target.Name, volume.Name)
			case "/var/log":
				score = 8.5
				ruleID = "KUBE-ESCAPE-008"
				content = contentEscape008(target.Kind, target.Namespace, target.Name, volume.Name)
			default:
				content = contentHostPath001(target.Kind, target.Namespace, target.Name, volume.Name, volume.HostPath.Path)
			}

			findings = appendFinding(findings, seen, newFindingFromContent(target, ruleID,
				scoring.SeverityForScore(score), models.CategoryPrivilegeEscalation, scoring.Clamp(score),
				map[string]any{"volume": volume.Name, "path": volume.HostPath.Path}, "hostPath", content).withSuffix(":"+volume.Name))
		}

		for _, container := range allContainers(target.PodSpec) {
			if container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
				content := contentEscape001(target.Kind, target.Namespace, target.Name, container.Name)
				findings = appendFinding(findings, seen, newFindingFromContent(target, "KUBE-ESCAPE-001",
					models.SeverityCritical, models.CategoryPrivilegeEscalation, scoring.Clamp(9.9),
					map[string]any{"container": container.Name}, "privileged", content).withSuffix(":"+container.Name))
			}

			if container.SecurityContext == nil || container.SecurityContext.AllowPrivilegeEscalation == nil || *container.SecurityContext.AllowPrivilegeEscalation {
				content := contentPodSecAPE001(target.Kind, target.Namespace, target.Name, container.Name)
				findings = appendFinding(findings, seen, newFindingFromContent(target, "KUBE-PODSEC-APE-001",
					models.SeverityHigh, models.CategoryPrivilegeEscalation, scoring.Clamp(7.8),
					map[string]any{"container": container.Name}, "allowPrivilegeEscalation", content).withSuffix(":"+container.Name))
			}

			if runsAsRoot(target.PodSpec, container) {
				content := contentPodSecRoot001(target.Kind, target.Namespace, target.Name, container.Name)
				findings = appendFinding(findings, seen, newFindingFromContent(target, "KUBE-PODSEC-ROOT-001",
					models.SeverityMedium, models.CategoryPrivilegeEscalation, scoring.Clamp(6.0),
					map[string]any{"container": container.Name}, "runAsRoot", content).withSuffix(":"+container.Name))
			}

			if usesLatestTag(container.Image) {
				content := contentImageLatest001(target.Kind, target.Namespace, target.Name, container.Name, container.Image)
				findings = appendFinding(findings, seen, newFindingFromContent(target, "KUBE-IMAGE-LATEST-001",
					models.SeverityLow, models.CategoryDefenseEvasion, scoring.Clamp(2.5),
					map[string]any{"container": container.Name, "image": container.Image}, "imageTag", content).withSuffix(":"+container.Name))
			}

			if container.SecurityContext == nil || container.SecurityContext.ReadOnlyRootFilesystem == nil || !*container.SecurityContext.ReadOnlyRootFilesystem {
				content := contentPodSecReadonly001(target.Kind, target.Namespace, target.Name, container.Name)
				findings = appendFinding(findings, seen, newFindingFromContent(target, "KUBE-PODSEC-READONLY-001",
					models.SeverityMedium, models.CategoryPrivilegeEscalation, scoring.Clamp(5.5),
					map[string]any{"container": container.Name}, "readOnlyRootFilesystem", content).withSuffix(":"+container.Name))
			}

			if seccompUnconfined(target.PodSpec, container) {
				content := contentPodSecSeccomp001(target.Kind, target.Namespace, target.Name, container.Name)
				findings = appendFinding(findings, seen, newFindingFromContent(target, "KUBE-PODSEC-SECCOMP-001",
					models.SeverityMedium, models.CategoryPrivilegeEscalation, scoring.Clamp(5.5),
					map[string]any{"container": container.Name}, "seccompProfile", content).withSuffix(":"+container.Name))
			}

			if container.SecurityContext != nil && container.SecurityContext.ProcMount != nil && *container.SecurityContext.ProcMount == corev1.UnmaskedProcMount {
				content := contentPodSecProcmount001(target.Kind, target.Namespace, target.Name, container.Name)
				findings = appendFinding(findings, seen, newFindingFromContent(target, "KUBE-PODSEC-PROCMOUNT-001",
					models.SeverityHigh, models.CategoryPrivilegeEscalation, scoring.Clamp(7.5),
					map[string]any{"container": container.Name, "procMount": "Unmasked"}, "procMount", content).withSuffix(":"+container.Name))
			}

			for _, cap := range dangerousAddedCapabilities(container) {
				content := contentPodSecCaps001(target.Kind, target.Namespace, target.Name, container.Name, cap)
				score := scoring.Clamp(dangerousCapabilities[cap].Score)
				findings = appendFinding(findings, seen, newFindingFromContent(target, "KUBE-PODSEC-CAPS-001",
					scoring.SeverityForScore(score), models.CategoryPrivilegeEscalation, score,
					map[string]any{"container": container.Name, "capability": cap}, "capabilities", content).withSuffix(":"+container.Name+":"+cap))
			}
		}
	}

	return findings, nil
}

// capabilityRisk pairs a base score with a one-line justification for why a Linux
// capability is dangerous in a container. The score feeds into scoring.SeverityForScore
// so a single CAPS-001 rule emits findings across the Critical/High/Medium severity
// buckets without per-capability hard-coded severities.
type capabilityRisk struct {
	Score  float64
	Reason string
}

// dangerousCapabilities lists Linux capabilities that grant container-escape or
// credential-theft primitives on their own. Each entry carries a short justification
// for the score: capabilities that allow direct host takeover (kernel module load,
// raw I/O, arbitrary mknod) score Critical; capabilities that defeat in-container
// hardening (ptrace, DAC_OVERRIDE) score High; lower-risk audit/chroot capabilities
// score Medium. SYS_ADMIN and NET_ADMIN are the canonical escape primitives and are
// always Critical. The Pod Security Standards Baseline profile forbids every cap on
// this list except NET_BIND_SERVICE (deliberately omitted).
var dangerousCapabilities = map[string]capabilityRisk{
	// CAP_SYS_ADMIN is "the new root": mount, pivot_root, unshare, BPF program load,
	// and dozens of other syscalls. Every public container escape from the last decade
	// either had SYS_ADMIN or worked around its absence.
	"SYS_ADMIN": {Score: 9.5, Reason: "kernel-equivalent privilege: mount, unshare, bpf, pivot_root; almost every container-escape requires it"},
	// CAP_SYS_MODULE allows insmod/init_module: load arbitrary kernel modules and
	// own the host kernel outright. Always Critical.
	"SYS_MODULE": {Score: 9.7, Reason: "loads kernel modules via init_module; direct host-kernel takeover"},
	// CAP_SYS_RAWIO allows direct I/O port and /dev/mem access: read kernel memory,
	// inject code into running processes, bypass DMA protections.
	"SYS_RAWIO": {Score: 9.0, Reason: "raw I/O port and /dev/mem access; read kernel memory and bypass DMA"},
	// CAP_NET_ADMIN allows iptables/nftables rewrites, traffic interception,
	// promiscuous mode, and tunnel creation. In multi-tenant clusters this is
	// lateral-movement primitive #1.
	"NET_ADMIN": {Score: 8.5, Reason: "network configuration: redirect traffic, intercept service IPs, manipulate firewall"},
	// CAP_BPF (split out from SYS_ADMIN in kernel 5.8) lets a container load eBPF
	// programs. Combined with CAP_PERFMON or CAP_SYS_RESOURCE this includes
	// kernel-tracing and credential snooping.
	"BPF": {Score: 8.5, Reason: "load eBPF programs; kernel-side tracing, credential snooping, packet manipulation"},
	// CAP_SYS_PTRACE allows ptrace() on any process in the same PID namespace,
	// including reading /proc/*/mem. Combined with hostPID this leaks every
	// credential held by every workload on the node.
	"SYS_PTRACE": {Score: 8.0, Reason: "ptrace any process; read /proc/*/mem to steal credentials in-pod (and host-wide under hostPID)"},
	// CAP_DAC_OVERRIDE bypasses Unix DAC permission checks on file reads/writes.
	// A container with DAC_OVERRIDE can read /etc/shadow inside the container and
	// any sensitive hostPath mount regardless of the mode bits.
	"DAC_OVERRIDE": {Score: 7.5, Reason: "bypass file DAC checks; read root-owned files in container and hostPath mounts"},
	// CAP_MKNOD allows creating device files via mknod(). With access to /dev,
	// an attacker can recreate /dev/sda1 and read the host disk directly.
	"MKNOD": {Score: 7.5, Reason: "create device nodes (mknod /dev/sda1); read host block devices directly"},
	// CAP_SYS_CHROOT allows chroot(). On its own it's a sandbox-escape primitive
	// when combined with a writeable rootfs and a SUID binary.
	"SYS_CHROOT": {Score: 6.5, Reason: "chroot() and break out of pivot_root sandboxes when paired with a writeable rootfs"},
	// CAP_NET_RAW allows AF_PACKET sockets and raw ICMP. Enables ARP spoofing,
	// DHCP starvation, and traffic sniffing across pods sharing a node-local
	// bridge (CNI-dependent).
	"NET_RAW": {Score: 6.0, Reason: "raw sockets and packet sniffing; ARP spoof or DHCP starvation across pods on the same node"},
	// CAP_AUDIT_WRITE lets a container forge entries in the kernel audit log.
	// Lower direct risk; primary value is covering tracks of an in-progress attack.
	"AUDIT_WRITE": {Score: 5.5, Reason: "forge entries in the kernel audit log; defense-evasion primitive"},
}

// dangerousAddedCapabilities returns the deduplicated list of dangerous capabilities
// granted via securityContext.capabilities.add for a single container. The output is
// stable-ordered by the dangerousCapabilities map's insertion-equivalent key sort so
// finding IDs are deterministic across runs.
func dangerousAddedCapabilities(container corev1.Container) []string {
	if container.SecurityContext == nil || container.SecurityContext.Capabilities == nil {
		return nil
	}
	caps := container.SecurityContext.Capabilities
	seen := map[string]struct{}{}
	for _, c := range caps.Add {
		normalized := normalizeCapability(string(c))
		if normalized == "ALL" {
			// capabilities.add: ["ALL"] grants every capability; surface each
			// dangerous one individually so the finding count, scoring, and
			// remediation advice match what an attacker can do.
			for name := range dangerousCapabilities {
				seen[name] = struct{}{}
			}
			continue
		}
		if _, ok := dangerousCapabilities[normalized]; ok {
			seen[normalized] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// normalizeCapability strips the conventional CAP_ prefix (Linux kernel writes
// capabilities with it; Kubernetes manifests usually omit it) and uppercases so
// the comparison against dangerousCapabilities is case- and prefix-insensitive.
func normalizeCapability(name string) string {
	n := strings.ToUpper(strings.TrimSpace(name))
	return strings.TrimPrefix(n, "CAP_")
}

// collectTargets flattens bare pods (skipping controller-managed ones to avoid duplicate findings) and every workload-kind pod template into target entries.
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

	for _, deployment := range snapshot.Resources.Deployments {
		targets = append(targets, workloadTarget("Deployment", deployment.Name, deployment.Namespace, deployment.Spec.Template.Spec))
	}
	for _, daemonSet := range snapshot.Resources.DaemonSets {
		targets = append(targets, workloadTarget("DaemonSet", daemonSet.Name, daemonSet.Namespace, daemonSet.Spec.Template.Spec))
	}
	for _, statefulSet := range snapshot.Resources.StatefulSets {
		targets = append(targets, workloadTarget("StatefulSet", statefulSet.Name, statefulSet.Namespace, statefulSet.Spec.Template.Spec))
	}
	for _, job := range snapshot.Resources.Jobs {
		targets = append(targets, workloadTarget("Job", job.Name, job.Namespace, job.Spec.Template.Spec))
	}
	for _, cronJob := range snapshot.Resources.CronJobs {
		targets = append(targets, workloadTarget("CronJob", cronJob.Name, cronJob.Namespace, cronJob.Spec.JobTemplate.Spec.Template.Spec))
	}

	return targets
}

// workloadTarget builds a target from a workload's embedded pod template.
func workloadTarget(kind, name, namespace string, spec corev1.PodSpec) target {
	return target{Kind: kind, Name: name, Namespace: namespace, PodSpec: spec}
}

// isControlledPod reports whether a pod is owned by a controller so that analysis can defer to the owning workload instead.
func isControlledPod(meta metav1.ObjectMeta) bool {
	for _, owner := range meta.OwnerReferences {
		if owner.Controller != nil && *owner.Controller {
			return true
		}
	}
	return false
}

// allContainers returns init and runtime containers in a single slice for uniform iteration.
func allContainers(spec corev1.PodSpec) []corev1.Container {
	items := make([]corev1.Container, 0, len(spec.InitContainers)+len(spec.Containers))
	items = append(items, spec.InitContainers...)
	items = append(items, spec.Containers...)
	return items
}

// runsAsRoot reports whether the container is configured to run as UID 0 or explicitly disables runAsNonRoot.
func runsAsRoot(podSpec corev1.PodSpec, container corev1.Container) bool {
	if container.SecurityContext != nil {
		if container.SecurityContext.RunAsUser != nil && *container.SecurityContext.RunAsUser == 0 {
			return true
		}
		if container.SecurityContext.RunAsNonRoot != nil && !*container.SecurityContext.RunAsNonRoot {
			return true
		}
	}

	if podSpec.SecurityContext != nil {
		if podSpec.SecurityContext.RunAsUser != nil && *podSpec.SecurityContext.RunAsUser == 0 {
			return true
		}
		if podSpec.SecurityContext.RunAsNonRoot != nil && !*podSpec.SecurityContext.RunAsNonRoot {
			return true
		}
	}

	return false
}

// seccompUnconfined reports whether the container is running without a seccomp filter.
// True when both container- and pod-level SecurityContext omit SeccompProfile (kernel runs
// unfiltered), or when either explicitly sets Type=Unconfined. Container-level overrides
// take precedence over pod-level; PSS Restricted only accepts RuntimeDefault or Localhost.
func seccompUnconfined(podSpec corev1.PodSpec, container corev1.Container) bool {
	if container.SecurityContext != nil && container.SecurityContext.SeccompProfile != nil {
		return container.SecurityContext.SeccompProfile.Type == corev1.SeccompProfileTypeUnconfined
	}
	if podSpec.SecurityContext != nil && podSpec.SecurityContext.SeccompProfile != nil {
		return podSpec.SecurityContext.SeccompProfile.Type == corev1.SeccompProfileTypeUnconfined
	}
	return true
}

// usesLatestTag reports whether image uses a mutable tag such as :latest or no tag at all (digest references are considered immutable).
func usesLatestTag(image string) bool {
	if strings.Contains(image, "@sha256:") {
		return false
	}
	if !strings.Contains(image, ":") {
		return true
	}
	return strings.HasSuffix(image, ":latest")
}

// findingWithID wraps a Finding so analyzer call-sites can apply a per-container ID suffix
// (different containers in the same workload should each produce a unique finding ID).
type findingWithID models.Finding

// withSuffix appends suffix to the Finding.ID and returns the result. Used so per-container
// findings (privileged, runAsRoot, etc.) inside the same workload don't collide on ID.
func (f findingWithID) withSuffix(suffix string) models.Finding {
	out := models.Finding(f)
	out.ID = out.ID + suffix
	return out
}

// as returns the underlying Finding without an ID suffix. Used at call sites that don't need
// per-container disambiguation.
func (f findingWithID) as() models.Finding {
	return models.Finding(f)
}

// newFindingFromContent materializes a pod-security Finding using the enriched ruleContent
// (Scope, Impact, AttackScenario, RemediationSteps, LearnMore, MitreTechniques) plus the
// runtime context. Returns findingWithID so per-container variants can use .withSuffix().
func newFindingFromContent(target target, ruleID string, severity models.Severity, category models.RiskCategory, score float64, evidence map[string]any, check string, content ruleContent) findingWithID {
	evidenceBytes, _ := json.Marshal(evidence)
	resource := &models.ResourceRef{
		Kind:      target.Kind,
		Name:      target.Name,
		Namespace: target.Namespace,
		APIGroup:  resourceAPIGroup(target.Kind),
	}
	references := make([]string, 0, len(content.LearnMore))
	for _, ref := range content.LearnMore {
		references = append(references, ref.URL)
	}
	return findingWithID(models.Finding{
		ID:               fmt.Sprintf("%s:%s:%s:%s", ruleID, target.Kind, target.Namespace, target.Name),
		RuleID:           ruleID,
		Severity:         severity,
		Score:            score,
		Category:         category,
		Title:            content.Title,
		Description:      content.Description,
		Namespace:        target.Namespace,
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
		Tags:             []string{"module:pod_security", "check:" + check},
	})
}

// appendFinding deduplicates by Finding.ID before appending.
func appendFinding(findings []models.Finding, seen map[string]struct{}, finding models.Finding) []models.Finding {
	if _, ok := seen[finding.ID]; ok {
		return findings
	}
	seen[finding.ID] = struct{}{}
	return append(findings, finding)
}

// resourceAPIGroup returns the Kubernetes API group for a workload kind.
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
