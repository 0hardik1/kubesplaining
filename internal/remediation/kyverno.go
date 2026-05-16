// Package remediation generates structured fix payloads (kubectl patches, Kyverno
// ClusterPolicies, Gatekeeper ConstraintTemplates, RBAC diffs) that analyzers attach
// to findings via Finding.RemediationHint. Each generator is rule-keyed and pure: it
// takes a rule ID plus the finding context and returns raw YAML / JSON / diff text
// (or empty string when no mapping exists).
//
// This file owns the Kyverno ClusterPolicy mapping table. Slot #18 in
// /Users/hardik/.claude/plans/use-plan-md-strategy-md-and-think-frolicking-waffle.md.
// Wired from the podsec / rbac analyzer call sites by slots #16 and #17; until those
// land, this generator is standalone (ForKyverno returns YAML; callers ignore unset
// rules by checking for an empty string).
package remediation

import (
	"github.com/0hardik1/kubesplaining/internal/models"
)

// ForKyverno returns a raw YAML Kyverno ClusterPolicy that would prevent the
// configuration the finding flagged, if a mapping exists for ruleID. Returns an empty
// string when no policy template is defined (e.g. KUBE-PRIVESC-PATH-* rules don't map
// cleanly to admission policies — caller stores "" without surfacing it).
//
// Every emitted policy:
//   - sets validationFailureAction: enforce (Kyverno blocks; not Audit)
//   - has spec.failurePolicy: Fail (no silent webhook fallback)
//   - has spec.background: true (catches pre-existing offenders on policy install)
//   - excludes built-in namespaces (kube-system, kube-public, kyverno) so the policy
//     doesn't break the cluster components that legitimately need the flagged feature
//   - targets the broadest set of pod-bearing kinds (Pod, Deployment, DaemonSet,
//     StatefulSet, Job, CronJob, ReplicaSet, ReplicationController) for podsec rules
//
// The finding parameter is reserved for future per-finding customization (e.g.
// allowlisting the offender's namespace into the policy); today the policy bodies
// are static templates so the parameter is accepted but only used where a Sprintf
// would meaningfully tailor the output.
func ForKyverno(ruleID string, _ models.Finding) string {
	if policy, ok := kyvernoPolicyByRuleID[ruleID]; ok {
		return policy
	}
	return ""
}

// kyvernoPolicyByRuleID maps a rule identifier to its raw YAML ClusterPolicy text.
// Keep alphabetically grouped by rule ID prefix; each policy is one ClusterPolicy
// document (no `---` separators) so the HTML report's <pre> renders cleanly.
var kyvernoPolicyByRuleID = map[string]string{
	"KUBE-CONTAINERD-SOCKET-001": kyvernoBlockHostPathContainerdSock,
	"KUBE-ESCAPE-001":            kyvernoDisallowPrivileged,
	"KUBE-ESCAPE-002":            kyvernoDisallowHostPID,
	"KUBE-ESCAPE-003":            kyvernoDisallowHostNetwork,
	"KUBE-ESCAPE-004":            kyvernoDisallowHostIPC,
	"KUBE-ESCAPE-005":            kyvernoBlockHostPathDockerSock,
	"KUBE-ESCAPE-006":            kyvernoBlockHostPathRoot,
	"KUBE-ESCAPE-008":            kyvernoBlockHostPathVarLog,
	"KUBE-HOSTPATH-001":          kyvernoDisallowHostPath,
	"KUBE-IMAGE-LATEST-001":      kyvernoDisallowLatestTag,
	"KUBE-PODSEC-APE-001":        kyvernoDisallowAllowPrivilegeEscalation,
	"KUBE-PODSEC-PROCMOUNT-001":  kyvernoDisallowUnmaskedProcMount,
	"KUBE-PODSEC-READONLY-001":   kyvernoRequireReadOnlyRootFilesystem,
	"KUBE-PODSEC-ROOT-001":       kyvernoDisallowRunAsRoot,
	"KUBE-PODSEC-SECCOMP-001":    kyvernoRequireSeccompProfile,
	"KUBE-RBAC-OVERBROAD-001":    kyvernoBlockClusterAdminBinding,
}

// podMatch is the standard match block used by every pod-targeting policy below. It
// covers bare Pods plus every workload controller that embeds a PodSpec. CronJob's
// pod template lives at .spec.jobTemplate.spec.template.spec, which Kyverno's
// `autogen` feature expands for you — listing CronJob here is belt-and-braces, the
// generated rule still covers it via auto-gen even if removed.
const podMatch = `    match:
      any:
      - resources:
          kinds:
          - Pod
          - Deployment
          - DaemonSet
          - StatefulSet
          - Job
          - CronJob
          - ReplicaSet
          - ReplicationController
`

// excludeSystemNamespaces is appended to every pod-targeting policy so kube-system,
// kube-public, and kyverno itself stay reachable. Without this, a strict policy can
// brick the cluster (CNI / kube-proxy / coredns legitimately need hostNetwork etc.).
const excludeSystemNamespaces = `    exclude:
      any:
      - resources:
          namespaces:
          - kube-system
          - kube-public
          - kube-node-lease
          - kyverno
`

// --- Privileged / host-namespace policies ---

const kyvernoDisallowPrivileged = `apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-privileged-containers
  annotations:
    policies.kyverno.io/title: Disallow privileged containers
    policies.kyverno.io/category: Pod Security Standards (Baseline)
    policies.kyverno.io/severity: critical
    policies.kyverno.io/description: >-
      Privileged containers disable nearly all container isolation. A privileged
      container can mount the host filesystem, load kernel modules, and access
      every device. Generated by kubesplaining for KUBE-ESCAPE-001.
spec:
  validationFailureAction: enforce
  background: true
  failurePolicy: Fail
  rules:
  - name: privileged-containers
` + podMatch + excludeSystemNamespaces + `    validate:
      message: "Privileged containers are not allowed."
      pattern:
        spec:
          =(initContainers):
          - =(securityContext):
              =(privileged): "false"
          =(ephemeralContainers):
          - =(securityContext):
              =(privileged): "false"
          containers:
          - =(securityContext):
              =(privileged): "false"
`

const kyvernoDisallowHostNetwork = `apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-host-network
  annotations:
    policies.kyverno.io/title: Disallow hostNetwork
    policies.kyverno.io/category: Pod Security Standards (Baseline)
    policies.kyverno.io/severity: high
    policies.kyverno.io/description: >-
      hostNetwork=true shares the host's network namespace with the pod, which
      bypasses NetworkPolicy and exposes node-local services (kubelet 10250,
      etcd peers). Generated by kubesplaining for KUBE-ESCAPE-003.
spec:
  validationFailureAction: enforce
  background: true
  failurePolicy: Fail
  rules:
  - name: host-network
` + podMatch + excludeSystemNamespaces + `    validate:
      message: "hostNetwork is not allowed."
      pattern:
        spec:
          =(hostNetwork): "false"
`

const kyvernoDisallowHostPID = `apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-host-pid
  annotations:
    policies.kyverno.io/title: Disallow hostPID
    policies.kyverno.io/category: Pod Security Standards (Baseline)
    policies.kyverno.io/severity: critical
    policies.kyverno.io/description: >-
      hostPID=true lets a container see every process on the node. With CAP_SYS_PTRACE
      (often default) the container can attach to and read memory of node-level
      processes like kubelet. Generated by kubesplaining for KUBE-ESCAPE-002.
spec:
  validationFailureAction: enforce
  background: true
  failurePolicy: Fail
  rules:
  - name: host-pid
` + podMatch + excludeSystemNamespaces + `    validate:
      message: "hostPID is not allowed."
      pattern:
        spec:
          =(hostPID): "false"
`

const kyvernoDisallowHostIPC = `apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-host-ipc
  annotations:
    policies.kyverno.io/title: Disallow hostIPC
    policies.kyverno.io/category: Pod Security Standards (Baseline)
    policies.kyverno.io/severity: high
    policies.kyverno.io/description: >-
      hostIPC=true shares the host's IPC namespace, exposing semaphores, message
      queues, and shared memory used by node services. Generated by kubesplaining
      for KUBE-ESCAPE-004.
spec:
  validationFailureAction: enforce
  background: true
  failurePolicy: Fail
  rules:
  - name: host-ipc
` + podMatch + excludeSystemNamespaces + `    validate:
      message: "hostIPC is not allowed."
      pattern:
        spec:
          =(hostIPC): "false"
`

// --- hostPath policies ---
//
// Generic hostPath rejection (KUBE-HOSTPATH-001) is the broad catch-all. The four
// "specific dangerous mount" rules (KUBE-ESCAPE-005/006/008, KUBE-CONTAINERD-SOCKET-001)
// each emit a targeted deny so an operator who wants to allow most hostPath mounts but
// block the truly dangerous ones can apply just those three without the generic deny.

const kyvernoDisallowHostPath = `apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-host-path
  annotations:
    policies.kyverno.io/title: Disallow hostPath volumes
    policies.kyverno.io/category: Pod Security Standards (Baseline)
    policies.kyverno.io/severity: high
    policies.kyverno.io/description: >-
      hostPath volumes mount node directories into the container, which is a common
      escape primitive. Use emptyDir, PVC, or projected volumes instead. Generated
      by kubesplaining for KUBE-HOSTPATH-001.
spec:
  validationFailureAction: enforce
  background: true
  failurePolicy: Fail
  rules:
  - name: host-path-volumes
` + podMatch + excludeSystemNamespaces + `    validate:
      message: "hostPath volumes are not allowed."
      pattern:
        spec:
          =(volumes):
          - X(hostPath): "null"
`

const kyvernoBlockHostPathRoot = `apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: block-host-path-root
  annotations:
    policies.kyverno.io/title: Block hostPath / mount
    policies.kyverno.io/category: Pod Security Standards (Restricted)
    policies.kyverno.io/severity: critical
    policies.kyverno.io/description: >-
      Mounting the node root filesystem ("/") gives the container read/write access
      to every node file, including kubelet credentials and the static-pod
      manifest directory. Generated by kubesplaining for KUBE-ESCAPE-006.
spec:
  validationFailureAction: enforce
  background: true
  failurePolicy: Fail
  rules:
  - name: deny-host-path-root
` + podMatch + excludeSystemNamespaces + `    validate:
      message: 'hostPath "/" is not allowed.'
      pattern:
        spec:
          =(volumes):
          - =(hostPath):
              X(path): "!/"
`

const kyvernoBlockHostPathDockerSock = `apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: block-host-path-docker-sock
  annotations:
    policies.kyverno.io/title: Block hostPath docker.sock
    policies.kyverno.io/category: Pod Security Standards (Restricted)
    policies.kyverno.io/severity: critical
    policies.kyverno.io/description: >-
      Mounting /var/run/docker.sock hands the container the Docker daemon's API,
      which is equivalent to root on the node. Generated by kubesplaining for
      KUBE-ESCAPE-005.
spec:
  validationFailureAction: enforce
  background: true
  failurePolicy: Fail
  rules:
  - name: deny-host-path-docker-sock
` + podMatch + excludeSystemNamespaces + `    validate:
      message: "Mounting /var/run/docker.sock is not allowed."
      pattern:
        spec:
          =(volumes):
          - =(hostPath):
              X(path): "!/var/run/docker.sock"
`

const kyvernoBlockHostPathContainerdSock = `apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: block-host-path-containerd-sock
  annotations:
    policies.kyverno.io/title: Block hostPath containerd.sock
    policies.kyverno.io/category: Pod Security Standards (Restricted)
    policies.kyverno.io/severity: critical
    policies.kyverno.io/description: >-
      Mounting /var/run/containerd/containerd.sock hands the container the
      containerd CRI socket, which is equivalent to root on the node (can pull
      images, create containers, exec into host pods). Generated by kubesplaining
      for KUBE-CONTAINERD-SOCKET-001.
spec:
  validationFailureAction: enforce
  background: true
  failurePolicy: Fail
  rules:
  - name: deny-host-path-containerd-sock
` + podMatch + excludeSystemNamespaces + `    validate:
      message: "Mounting /var/run/containerd/containerd.sock is not allowed."
      pattern:
        spec:
          =(volumes):
          - =(hostPath):
              X(path): "!/var/run/containerd/containerd.sock"
`

const kyvernoBlockHostPathVarLog = `apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: block-host-path-var-log
  annotations:
    policies.kyverno.io/title: Block hostPath /var/log
    policies.kyverno.io/category: Pod Security Standards (Restricted)
    policies.kyverno.io/severity: high
    policies.kyverno.io/description: >-
      Mounting /var/log exposes container logs that may contain ServiceAccount
      tokens, kubelet logs, and audit logs. A symlink swap from inside the
      container can lure the kubelet into reading arbitrary host files.
      Generated by kubesplaining for KUBE-ESCAPE-008.
spec:
  validationFailureAction: enforce
  background: true
  failurePolicy: Fail
  rules:
  - name: deny-host-path-var-log
` + podMatch + excludeSystemNamespaces + `    validate:
      message: "Mounting /var/log is not allowed."
      pattern:
        spec:
          =(volumes):
          - =(hostPath):
              X(path): "!/var/log"
`

// --- SecurityContext hardening policies ---

const kyvernoDisallowAllowPrivilegeEscalation = `apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-allow-privilege-escalation
  annotations:
    policies.kyverno.io/title: Disallow allowPrivilegeEscalation
    policies.kyverno.io/category: Pod Security Standards (Restricted)
    policies.kyverno.io/severity: high
    policies.kyverno.io/description: >-
      allowPrivilegeEscalation=true (the default) lets a process gain more
      privileges than its parent via setuid/setcap binaries. Restricted PSS
      requires this be false on every container. Generated by kubesplaining for
      KUBE-PODSEC-APE-001.
spec:
  validationFailureAction: enforce
  background: true
  failurePolicy: Fail
  rules:
  - name: deny-allow-privilege-escalation
` + podMatch + excludeSystemNamespaces + `    validate:
      message: "allowPrivilegeEscalation must be set to false."
      pattern:
        spec:
          =(initContainers):
          - securityContext:
              allowPrivilegeEscalation: "false"
          =(ephemeralContainers):
          - securityContext:
              allowPrivilegeEscalation: "false"
          containers:
          - securityContext:
              allowPrivilegeEscalation: "false"
`

const kyvernoDisallowRunAsRoot = `apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-run-as-root
  annotations:
    policies.kyverno.io/title: Disallow containers running as root
    policies.kyverno.io/category: Pod Security Standards (Restricted)
    policies.kyverno.io/severity: medium
    policies.kyverno.io/description: >-
      Containers should not run as UID 0. Set runAsNonRoot=true and a non-zero
      runAsUser at pod or container level. Generated by kubesplaining for
      KUBE-PODSEC-ROOT-001.
spec:
  validationFailureAction: enforce
  background: true
  failurePolicy: Fail
  rules:
  - name: require-run-as-non-root
` + podMatch + excludeSystemNamespaces + `    validate:
      message: "runAsNonRoot must be set to true."
      anyPattern:
      - spec:
          securityContext:
            runAsNonRoot: true
      - spec:
          =(initContainers):
          - securityContext:
              runAsNonRoot: true
          =(ephemeralContainers):
          - securityContext:
              runAsNonRoot: true
          containers:
          - securityContext:
              runAsNonRoot: true
`

const kyvernoRequireReadOnlyRootFilesystem = `apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-read-only-root-filesystem
  annotations:
    policies.kyverno.io/title: Require readOnlyRootFilesystem
    policies.kyverno.io/category: Pod Security Standards (Restricted)
    policies.kyverno.io/severity: medium
    policies.kyverno.io/description: >-
      A writable root filesystem lets an attacker drop binaries, modify config,
      and persist across restarts. Set readOnlyRootFilesystem=true and mount
      tmpfs/emptyDir for /tmp and any other writable path. Generated by
      kubesplaining for KUBE-PODSEC-READONLY-001.
spec:
  validationFailureAction: enforce
  background: true
  failurePolicy: Fail
  rules:
  - name: require-read-only-root-filesystem
` + podMatch + excludeSystemNamespaces + `    validate:
      message: "readOnlyRootFilesystem must be set to true."
      pattern:
        spec:
          =(initContainers):
          - securityContext:
              readOnlyRootFilesystem: true
          =(ephemeralContainers):
          - securityContext:
              readOnlyRootFilesystem: true
          containers:
          - securityContext:
              readOnlyRootFilesystem: true
`

const kyvernoRequireSeccompProfile = `apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-seccomp-profile
  annotations:
    policies.kyverno.io/title: Require seccomp profile (RuntimeDefault or Localhost)
    policies.kyverno.io/category: Pod Security Standards (Restricted)
    policies.kyverno.io/severity: medium
    policies.kyverno.io/description: >-
      Unconfined or missing seccomp profile leaves the full syscall surface
      exposed. Restricted PSS requires either RuntimeDefault or Localhost at the
      pod or container level. Generated by kubesplaining for
      KUBE-PODSEC-SECCOMP-001.
spec:
  validationFailureAction: enforce
  background: true
  failurePolicy: Fail
  rules:
  - name: require-seccomp-runtime-default
` + podMatch + excludeSystemNamespaces + `    validate:
      message: "seccompProfile.type must be RuntimeDefault or Localhost."
      anyPattern:
      - spec:
          securityContext:
            seccompProfile:
              type: "RuntimeDefault | Localhost"
      - spec:
          =(initContainers):
          - securityContext:
              seccompProfile:
                type: "RuntimeDefault | Localhost"
          =(ephemeralContainers):
          - securityContext:
              seccompProfile:
                type: "RuntimeDefault | Localhost"
          containers:
          - securityContext:
              seccompProfile:
                type: "RuntimeDefault | Localhost"
`

const kyvernoDisallowUnmaskedProcMount = `apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-unmasked-proc-mount
  annotations:
    policies.kyverno.io/title: Disallow procMount=Unmasked
    policies.kyverno.io/category: Pod Security Standards (Restricted)
    policies.kyverno.io/severity: high
    policies.kyverno.io/description: >-
      procMount=Unmasked exposes the full /proc inside the container, including
      paths the runtime would normally mask (e.g. /proc/kcore, /proc/sysrq-trigger).
      Only Default is allowed. Generated by kubesplaining for
      KUBE-PODSEC-PROCMOUNT-001.
spec:
  validationFailureAction: enforce
  background: true
  failurePolicy: Fail
  rules:
  - name: deny-unmasked-proc-mount
` + podMatch + excludeSystemNamespaces + `    validate:
      message: "procMount=Unmasked is not allowed; use Default."
      pattern:
        spec:
          =(initContainers):
          - =(securityContext):
              =(procMount): "Default"
          =(ephemeralContainers):
          - =(securityContext):
              =(procMount): "Default"
          containers:
          - =(securityContext):
              =(procMount): "Default"
`

// --- Image-tag policy ---

const kyvernoDisallowLatestTag = `apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-latest-tag
  annotations:
    policies.kyverno.io/title: Disallow :latest and untagged images
    policies.kyverno.io/category: Best Practices
    policies.kyverno.io/severity: low
    policies.kyverno.io/description: >-
      Mutable tags like :latest (or no tag) defeat the audit trail and let a
      compromised registry silently roll a new image into the pod on every
      restart. Pin to an immutable tag or a digest. Generated by kubesplaining
      for KUBE-IMAGE-LATEST-001.
spec:
  validationFailureAction: enforce
  background: true
  failurePolicy: Fail
  rules:
  - name: deny-latest-tag
` + podMatch + excludeSystemNamespaces + `    validate:
      message: "Image tag :latest (or no tag) is not allowed. Pin to an immutable tag or digest."
      pattern:
        spec:
          =(initContainers):
          - image: "!*:latest"
          =(ephemeralContainers):
          - image: "!*:latest"
          containers:
          - image: "!*:latest"
  - name: deny-untagged-image
` + podMatch + excludeSystemNamespaces + `    validate:
      message: "Image must include a tag or digest."
      pattern:
        spec:
          =(initContainers):
          - image: "*:*"
          =(ephemeralContainers):
          - image: "*:*"
          containers:
          - image: "*:*"
`

// --- RBAC policy ---
//
// Kyverno cannot un-bind an existing ClusterRoleBinding from inside an admission
// webhook (the binding is already in place when a workload tries to assume the
// SA), but it CAN block future ClusterRoleBindings that grant cluster-admin (the
// "cluster-admin" ClusterRole or "*" verbs on "*" resources). This policy covers
// the future-creation half; the kubectl-patch generator in slot #17 covers the
// already-installed half by emitting a `kubectl delete` for the offending binding.

const kyvernoBlockClusterAdminBinding = `apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: block-cluster-admin-bindings
  annotations:
    policies.kyverno.io/title: Block (Cluster)RoleBindings to cluster-admin
    policies.kyverno.io/category: RBAC Best Practices
    policies.kyverno.io/severity: critical
    policies.kyverno.io/description: >-
      A binding to the cluster-admin ClusterRole grants its subjects unrestricted
      access to every resource in every namespace. Outside of bootstrap, no
      service account or user should hold cluster-admin. Generated by
      kubesplaining for KUBE-RBAC-OVERBROAD-001.
spec:
  validationFailureAction: enforce
  background: false
  failurePolicy: Fail
  rules:
  - name: deny-cluster-admin-binding
    match:
      any:
      - resources:
          kinds:
          - ClusterRoleBinding
          - RoleBinding
    exclude:
      any:
      - clusterRoles:
        - cluster-admin
      - resources:
          namespaces:
          - kube-system
    validate:
      message: "Bindings to the cluster-admin ClusterRole are not allowed."
      pattern:
        roleRef:
          name: "!cluster-admin"
`
