package podsec

import (
	"fmt"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/scoring"
	corev1 "k8s.io/api/core/v1"
)

// sensitivePVHostPathPaths is the list of host paths whose presence as a backing
// PV's hostPath source means a Pod that mounts the corresponding PVC obtains the
// same node-takeover primitive that Pod Security Admission would normally block
// at the PodSpec level. Pod Security Admission inspects the PodSpec only: it
// cannot follow PVC -> PV indirection, so this analyzer closes that gap.
//
// Mirror the prefix list in podsec/analyzer.go's hostPath switch (and a few
// extra well-known credential dirs that are covered by the generic case there).
// The match is exact path or path prefix (so `/var/lib/kubelet/...` matches
// `/var/lib/kubelet`).
var sensitivePVHostPathPaths = []string{
	"/",
	"/etc",
	"/proc",
	"/sys",
	"/root",
	"/var/run/docker.sock",
	"/var/run/containerd/containerd.sock",
	"/run/containerd/containerd.sock",
	"/var/lib/kubelet",
	"/var/lib/docker",
	"/var/lib/containerd",
	"/var/log",
}

// isSensitivePVHostPath reports whether path is one of (or under) the
// well-known sensitive node directories that turn a PVC mount into a node
// takeover primitive. An empty path is never sensitive.
func isSensitivePVHostPath(path string) bool {
	if path == "" {
		return false
	}
	// Normalise trailing slashes ("/etc/" -> "/etc") but preserve the bare "/"
	// case: TrimRight("/", "/") returns "", which would never match. Treat any
	// all-slashes input as the root.
	clean := strings.TrimRight(path, "/")
	if clean == "" {
		clean = "/"
	}
	for _, sensitive := range sensitivePVHostPathPaths {
		if clean == sensitive {
			return true
		}
		// Treat anything under a sensitive directory as sensitive too (e.g.
		// `/var/lib/kubelet/pods` is just as bad as `/var/lib/kubelet`). The
		// exception is `/`, which trivially matches everything, but it's
		// already covered by the equality check above.
		if sensitive != "/" && strings.HasPrefix(clean, sensitive+"/") {
			return true
		}
	}
	return false
}

// pvHostPathBindings indexes PVCs and PVs so analyzePVHostPath can resolve a
// pod's PVC mount to the PV that backs it without re-walking the snapshot per
// pod.
type pvHostPathBindings struct {
	// pvByName maps PV name to the PV (cluster-scoped resource).
	pvByName map[string]corev1.PersistentVolume
	// pvcByKey maps "namespace/name" to the PVC.
	pvcByKey map[string]corev1.PersistentVolumeClaim
}

// buildPVHostPathBindings returns a populated pvHostPathBindings. Always returns
// a non-nil struct; the caller's lookups return zero-value when the index is
// empty.
func buildPVHostPathBindings(snapshot models.Snapshot) pvHostPathBindings {
	idx := pvHostPathBindings{
		pvByName: make(map[string]corev1.PersistentVolume, len(snapshot.Resources.PersistentVolumes)),
		pvcByKey: make(map[string]corev1.PersistentVolumeClaim, len(snapshot.Resources.PersistentVolumeClaims)),
	}
	for _, pv := range snapshot.Resources.PersistentVolumes {
		idx.pvByName[pv.Name] = pv
	}
	for _, pvc := range snapshot.Resources.PersistentVolumeClaims {
		idx.pvcByKey[pvc.Namespace+"/"+pvc.Name] = pvc
	}
	return idx
}

// resolvePVForPVC returns the backing PV for a PVC reference originating in
// namespace `ns`. The lookup follows pvc.Spec.VolumeName when present; the
// boolean ok is false when no PVC or no bound PV is found.
func (idx pvHostPathBindings) resolvePVForPVC(ns, claimName string) (corev1.PersistentVolume, bool) {
	pvc, ok := idx.pvcByKey[ns+"/"+claimName]
	if !ok {
		return corev1.PersistentVolume{}, false
	}
	if pvc.Spec.VolumeName == "" {
		return corev1.PersistentVolume{}, false
	}
	pv, ok := idx.pvByName[pvc.Spec.VolumeName]
	return pv, ok
}

// analyzePVHostPath emits one KUBE-PV-HOSTPATH-001 finding per (workload,
// volume) pair where the workload mounts a PVC whose backing PV is a
// sensitive hostPath PV. Returns the augmented findings slice.
func analyzePVHostPath(targets []target, snapshot models.Snapshot, findings []models.Finding, seen map[string]struct{}) []models.Finding {
	if len(snapshot.Resources.PersistentVolumes) == 0 || len(snapshot.Resources.PersistentVolumeClaims) == 0 {
		return findings
	}

	idx := buildPVHostPathBindings(snapshot)

	for _, t := range targets {
		for _, vol := range t.PodSpec.Volumes {
			if vol.PersistentVolumeClaim == nil || vol.PersistentVolumeClaim.ClaimName == "" {
				continue
			}
			pv, ok := idx.resolvePVForPVC(t.Namespace, vol.PersistentVolumeClaim.ClaimName)
			if !ok {
				continue
			}
			if pv.Spec.HostPath == nil {
				continue
			}
			path := pv.Spec.HostPath.Path
			if !isSensitivePVHostPath(path) {
				continue
			}

			content := contentPVHostPath001(t.Kind, t.Namespace, t.Name, vol.Name, vol.PersistentVolumeClaim.ClaimName, pv.Name, path)
			finding := newFindingFromContent(t, "KUBE-PV-HOSTPATH-001",
				models.SeverityHigh, models.CategoryPrivilegeEscalation, scoring.Clamp(8.6),
				map[string]any{
					"volume":     vol.Name,
					"claim_name": vol.PersistentVolumeClaim.ClaimName,
					"pv_name":    pv.Name,
					"path":       path,
				}, "pvHostPath", content,
			).withSuffix(":" + vol.Name)
			findings = appendFinding(findings, seen, finding)
		}
	}
	return findings
}

// contentPVHostPath001 returns the enriched ruleContent for a PVC whose backing
// PV exposes a sensitive hostPath. The narrative emphasizes the Pod Security
// Admission bypass: PSA blocks `volumes.hostPath` on the PodSpec but does not
// follow PVC -> PV indirection, so a sensitive hostPath PV becomes an undetected
// node-takeover primitive in any namespace whose PSA enforce label would
// otherwise block direct hostPath mounts.
func contentPVHostPath001(kind, namespace, name, volumeName, claimName, pvName, path string) ruleContent {
	scope := scopeForWorkload(kind, namespace, name)
	return ruleContent{
		Title: fmt.Sprintf("Pod-mounted PVC `%s` is backed by a sensitive hostPath PV `%s`", claimName, pvName),
		Scope: scope,
		Description: fmt.Sprintf("Workload `%s/%s/%s` mounts PersistentVolumeClaim `%s` via volume `%s`. The bound PersistentVolume `%s` uses `spec.hostPath.path: %s`, a sensitive node directory. Because Pod Security Admission inspects the PodSpec only and never follows the PVC -> PV indirection, this is a real Baseline/Restricted bypass: a namespace labeled `pod-security.kubernetes.io/enforce=baseline` (or `restricted`) would block a direct `volumes.hostPath`, but happily admits a Pod that mounts an equivalent path through a PVC.\n\n"+
			"Once mounted, the host directory is reachable from inside the container with the same blast radius as a direct hostPath: read kubelet credentials under `/var/lib/kubelet`, write SUID binaries via `/`, drop sshd authorized_keys via `/root`, leak `/etc/shadow` or kubeadm config from `/etc`, talk to the container runtime through `/var/run/{docker,containerd}.sock`. The PSA label gives a false sense of safety; the cluster operator typically discovers the bypass only when an unauthorized pod has already escaped to the node.\n\n"+
			"Real-world: a tenant with permission to create PVCs in their own namespace, plus cluster-wide pre-provisioned hostPath PVs (a common pattern for local-path-provisioner without scope restrictions), can claim the sensitive PV by name and mount it from a Baseline-enforced namespace. The Pod admits cleanly; the breakout follows.",
			kind, namespace, name, claimName, volumeName, pvName, path),
		Impact: "Same as a direct hostPath mount of " + path + " (node takeover, kubelet credential theft, lateral movement to every other pod on the node). PSA enforce labels do not block this path, so attenuation does not apply.",
		AttackScenario: []string{
			"Attacker has create-pod and create-pvc rights in a namespace that has `pod-security.kubernetes.io/enforce=baseline` or `restricted`.",
			fmt.Sprintf("They list pre-provisioned PersistentVolumes (`kubectl get pv`) and identify `%s`, which uses `hostPath: %s`.", pvName, path),
			fmt.Sprintf("They create a PersistentVolumeClaim referencing `%s` by `volumeName`. The PVC binds.", pvName),
			"They create a Pod that mounts the PVC at a known mount point. PSA admits the pod because the PodSpec has no `hostPath` volume - only `persistentVolumeClaim`.",
			"From inside the container, they read/write the host directory with full container-process privilege. From `/var/lib/kubelet` they extract `kubelet-client-current.pem`; from `/` they `chroot` and pivot to the node.",
		},
		Remediation: fmt.Sprintf("Remove the hostPath from PV `%s`, restrict who can create hostPath PVs, and stop the Pod from claiming this PV.", pvName),
		RemediationSteps: []string{
			fmt.Sprintf("Replace `spec.hostPath` on PersistentVolume `%s` with a CSI driver, an `nfs`/`iscsi` source, or a strictly-scoped `local` volume on a labeled node. The hostPath PV pattern is brittle for any workload, not just from a security angle.", pvName),
			"Restrict who can create cluster-scoped PersistentVolumes (PVs are non-namespaced) and who can create hostPath-typed PVs specifically. A Kyverno/Gatekeeper ClusterPolicy can deny `spec.hostPath` PVs outright, or whitelist only paths under `/var/lib/your-app/`.",
			fmt.Sprintf("Delete or unbind the PVC `%s/%s` so the workload stops consuming the sensitive PV. If the workload genuinely needs node-local state, use a `local` volume with `nodeAffinity` and a strict `path` allowlist instead.", namespace, claimName),
			fmt.Sprintf("Validate: `kubectl get pv %s -o jsonpath='{.spec.hostPath.path}'` returns empty.", pvName),
		},
		LearnMore: []models.Reference{
			{Title: "Kubernetes - Volumes (hostPath)", URL: "https://kubernetes.io/docs/concepts/storage/volumes/#hostpath"},
			{Title: "Kubernetes - Pod Security Standards", URL: "https://kubernetes.io/docs/concepts/security/pod-security-standards/"},
			{Title: "Kubernetes - Pod Security Admission", URL: "https://kubernetes.io/docs/concepts/security/pod-security-admission/"},
			{Title: "Quarkslab - Kubernetes and HostPath: a Love-Hate Relationship", URL: "https://blog.quarkslab.com/kubernetes-and-hostpath-a-love-hate-relationship.html"},
			{Title: "PSA does not see through PVC -> PV (kubernetes/kubernetes #112744)", URL: "https://github.com/kubernetes/kubernetes/issues/112744"},
		},
		MitreTechniques: []models.MitreTechnique{
			{ID: "T1611", Name: "Escape to Host", URL: "https://attack.mitre.org/techniques/T1611/"},
			{ID: "T1078", Name: "Valid Accounts", URL: "https://attack.mitre.org/techniques/T1078/"},
		},
	}
}
