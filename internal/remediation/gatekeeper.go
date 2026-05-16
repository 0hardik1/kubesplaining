// Package remediation builds structured remediation artifacts (kubectl patches,
// Kyverno ClusterPolicies, OPA Gatekeeper ConstraintTemplates + Constraints, and
// minimal RBAC diffs) for findings emitted by the analyzers. Each generator is a
// pure function over (ruleID, finding) returning a string payload that the
// caller stores on Finding.RemediationHint; analyzers do not import this
// package directly so the analyzer→models→scoring core stays free of
// remediation-rendering concerns.
package remediation

import (
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// ForGatekeeper returns a concatenated YAML document (`ConstraintTemplate`
// followed by `---` and a `Constraint`) that prevents the configuration the
// given finding flagged. Returns the empty string when no template is mapped
// for the rule. The output is intended to be stored on
// Finding.RemediationHint.GatekeeperPolicy for the HTML report and JSON
// output; the YAML is static per rule, so it is safe to inline in the report
// regardless of which workload the finding fired on.
//
// Coverage mirrors the Kyverno generator (slot #18): the podsec rules
// (privileged, runAsRoot, hostNetwork, hostPID, hostIPC, hostPath family,
// allowPrivilegeEscalation, readOnlyRootFilesystem, seccomp, procMount),
// KUBE-IMAGE-LATEST-001 (mutable image tags), and KUBE-RBAC-OVERBROAD-001
// (cluster-admin binding). Privesc graph findings (KUBE-PRIVESC-PATH-*) do
// not map to admission-time prevention cleanly: they describe a path that
// already exists in RBAC, not a single new manifest, so they are skipped.
//
// Every returned ConstraintTemplate carries:
//   - spec.crd.spec.names.kind: the Kind the Constraint will reference.
//   - spec.targets[].target: admission.k8s.gatekeeper.sh.
//   - spec.targets[].rego: a `violation[{...}]` rule (Gatekeeper's Rego v1
//     dialect; one violation per offending container or resource).
//
// Every returned Constraint:
//   - apiVersion: constraints.gatekeeper.sh/v1beta1.
//   - kind: the same Kind from the template's spec.crd.spec.names.kind.
//   - spec.match.kinds: the API group + Kind list the policy applies to
//     (Pods + workload controllers for podsec rules, ClusterRoleBinding for
//     KUBE-RBAC-OVERBROAD-001).
//
// Operators copy-paste the YAML into a cluster running Gatekeeper to enforce
// the rule going forward; the Constraint defaults to `enforcementAction:
// deny` so it blocks new violators while existing offenders surface in the
// audit results (Gatekeeper's standard rollout pattern).
func ForGatekeeper(ruleID string, _ models.Finding) string {
	yaml, ok := gatekeeperPolicies[ruleID]
	if !ok {
		return ""
	}
	return yaml
}

// gatekeeperPolicies is the rule → YAML lookup table. Each value is a
// fully-rendered, self-contained ConstraintTemplate + Constraint pair. The
// table is built once at process start so ForGatekeeper is a constant-time
// map lookup; the generator never touches the finding's runtime context
// because the policy is preventive (cluster-wide), not diagnostic
// (per-instance).
var gatekeeperPolicies = func() map[string]string {
	out := map[string]string{}
	for _, p := range allGatekeeperPolicies() {
		out[p.ruleID] = p.yaml
	}
	return out
}()

// gatekeeperPolicy is a (ruleID, fully-rendered-YAML) tuple used internally
// to assemble the lookup table.
type gatekeeperPolicy struct {
	ruleID string
	yaml   string
}

// allGatekeeperPolicies returns every supported rule's ConstraintTemplate +
// Constraint pair. New entries plug in here.
func allGatekeeperPolicies() []gatekeeperPolicy {
	// All podsec-family hostPath rules share the same template body (deny
	// any hostPath mount); the Constraint's match.kinds list is identical
	// across them, so each rule just stores a copy of the same YAML. The
	// rule prefixes are preserved so the report renders rule-specific copy.
	hostPathYAML := constraintPair(
		"KubesplainingPodsecHostPath",
		`Disallow hostPath volume mounts. Any pod-spec volume with a non-nil hostPath escapes the container filesystem onto the node.`,
		podWorkloadKinds(),
		regoHostPath,
	)

	return []gatekeeperPolicy{
		// ---- Pod security: PodSpec-level dangerous settings ----

		{ruleID: "KUBE-ESCAPE-001", yaml: constraintPair(
			"KubesplainingPodsecPrivileged",
			`Disallow privileged containers. A privileged container shares the kernel namespace with the host and is equivalent to root on the node.`,
			podWorkloadKinds(),
			regoPrivileged,
		)},

		{ruleID: "KUBE-ESCAPE-002", yaml: constraintPair(
			"KubesplainingPodsecHostPID",
			`Disallow pods that share the host PID namespace. hostPID lets a container see and signal every process on the node.`,
			podWorkloadKinds(),
			podSpecBoolRego("hostpid", "hostPID", "hostPID=true is not allowed"),
		)},

		{ruleID: "KUBE-ESCAPE-003", yaml: constraintPair(
			"KubesplainingPodsecHostNetwork",
			`Disallow pods that share the host network namespace. hostNetwork bypasses NetworkPolicy and exposes node-local services.`,
			podWorkloadKinds(),
			podSpecBoolRego("hostnetwork", "hostNetwork", "hostNetwork=true is not allowed"),
		)},

		{ruleID: "KUBE-ESCAPE-004", yaml: constraintPair(
			"KubesplainingPodsecHostIPC",
			`Disallow pods that share the host IPC namespace. hostIPC lets a container read shared memory belonging to other pods or host processes.`,
			podWorkloadKinds(),
			podSpecBoolRego("hostipc", "hostIPC", "hostIPC=true is not allowed"),
		)},

		// ---- HostPath family: same template body, separate rule IDs so the
		// report renders rule-specific copy + each can be excluded
		// independently.

		{ruleID: "KUBE-HOSTPATH-001", yaml: hostPathYAML},
		{ruleID: "KUBE-ESCAPE-005", yaml: hostPathYAML},
		{ruleID: "KUBE-ESCAPE-006", yaml: hostPathYAML},
		{ruleID: "KUBE-ESCAPE-008", yaml: hostPathYAML},
		{ruleID: "KUBE-CONTAINERD-SOCKET-001", yaml: hostPathYAML},

		// ---- Container-level SecurityContext + image checks ----

		{ruleID: "KUBE-PODSEC-APE-001", yaml: constraintPair(
			"KubesplainingPodsecAllowPrivilegeEscalation",
			`Require allowPrivilegeEscalation=false on every container. The default true lets a child process gain privileges beyond its parent via setuid binaries.`,
			podWorkloadKinds(),
			regoAllowPrivilegeEscalation,
		)},

		{ruleID: "KUBE-PODSEC-ROOT-001", yaml: constraintPair(
			"KubesplainingPodsecRunAsNonRoot",
			`Require runAsNonRoot=true (or runAsUser != 0) on every container. Root inside the container is the prerequisite for most container escapes.`,
			podWorkloadKinds(),
			regoRunAsNonRoot,
		)},

		{ruleID: "KUBE-PODSEC-READONLY-001", yaml: constraintPair(
			"KubesplainingPodsecReadOnlyRootFs",
			`Require readOnlyRootFilesystem=true on every container. A writable root FS lets an attacker who lands code execution drop persistent payloads.`,
			podWorkloadKinds(),
			regoReadOnlyRootFs,
		)},

		{ruleID: "KUBE-PODSEC-SECCOMP-001", yaml: constraintPair(
			"KubesplainingPodsecSeccomp",
			`Require an explicit seccomp profile (RuntimeDefault or Localhost) at pod or container level. Without it the kernel runs unfiltered syscalls.`,
			podWorkloadKinds(),
			regoSeccomp,
		)},

		{ruleID: "KUBE-PODSEC-PROCMOUNT-001", yaml: constraintPair(
			"KubesplainingPodsecProcMount",
			`Disallow procMount=Unmasked. Unmasking /proc exposes host-level interfaces like /proc/sys that the default mask hides for a reason.`,
			podWorkloadKinds(),
			regoProcMount,
		)},

		// ---- Image policy ----

		{ruleID: "KUBE-IMAGE-LATEST-001", yaml: constraintPair(
			"KubesplainingPodsecImmutableImageTag",
			`Require an immutable image reference: pinned tag other than :latest, or a digest reference (image@sha256:...). Mutable tags break supply-chain integrity.`,
			podWorkloadKinds(),
			regoImmutableImageTag,
		)},

		// ---- RBAC ----

		{ruleID: "KUBE-RBAC-OVERBROAD-001", yaml: constraintPair(
			"KubesplainingRbacOverbroadClusterAdmin",
			`Disallow ClusterRoleBindings that grant the built-in cluster-admin ClusterRole to non-system subjects.`,
			[]matchKinds{{APIGroups: []string{"rbac.authorization.k8s.io"}, Kinds: []string{"ClusterRoleBinding"}}},
			regoClusterAdminBinding,
		)},
	}
}

// matchKinds is the YAML shape Gatekeeper expects under
// spec.match.kinds[]: an apiGroups + kinds tuple.
type matchKinds struct {
	APIGroups []string
	Kinds     []string
}

// podWorkloadKinds returns the standard set of pod-bearing API objects a
// PodSecurity-style constraint should match: bare Pods plus every workload
// controller that embeds a pod template. Matching both the controller and
// its generated Pod is intentional: Gatekeeper webhooks fire on every
// CREATE, and a user who applies a raw Pod (no controller) must still be
// blocked.
func podWorkloadKinds() []matchKinds {
	return []matchKinds{
		{APIGroups: []string{""}, Kinds: []string{"Pod"}},
		{APIGroups: []string{"apps"}, Kinds: []string{"Deployment", "DaemonSet", "StatefulSet", "ReplicaSet"}},
		{APIGroups: []string{"batch"}, Kinds: []string{"Job", "CronJob"}},
	}
}

// constraintPair renders a fully-formed ConstraintTemplate + `---` separator
// + Constraint YAML document for one rule. Inputs:
//
//   - kind: the user-facing Kind shared by the template + the constraint
//     (UpperCamel, e.g. KubesplainingPodsecPrivileged). Becomes
//     spec.crd.spec.names.kind on the template and the apiVersion-less Kind on
//     the Constraint instance.
//   - description: free-text shown to the report reader; rendered into both
//     the Constraint metadata.annotations.description and the template
//     metadata.annotations.description.
//   - match: the apiGroups+kinds list the Constraint should match. Defaults
//     to pod-bearing kinds for podsec rules and ClusterRoleBinding for the
//     rbac rule.
//   - rego: the Rego body. Must declare `package <pkg>` and at least one
//     `violation contains {"msg": ...} if {...}` rule. Indented as a YAML
//     block scalar; the surrounding `|` literal preserves the rego byte-for-byte
//     (whitespace + comments preserved).
//
// The output is deterministic for the same inputs, so it can be diffed and
// pinned in golden files.
func constraintPair(kind, description string, match []matchKinds, rego string) string {
	var b strings.Builder

	// ---- ConstraintTemplate ----
	b.WriteString("apiVersion: templates.gatekeeper.sh/v1\n")
	b.WriteString("kind: ConstraintTemplate\n")
	b.WriteString("metadata:\n")
	b.WriteString("  name: " + strings.ToLower(kind) + "\n")
	b.WriteString("  annotations:\n")
	b.WriteString("    description: " + yamlString(description) + "\n")
	b.WriteString("spec:\n")
	b.WriteString("  crd:\n")
	b.WriteString("    spec:\n")
	b.WriteString("      names:\n")
	b.WriteString("        kind: " + kind + "\n")
	b.WriteString("  targets:\n")
	b.WriteString("    - target: admission.k8s.gatekeeper.sh\n")
	b.WriteString("      rego: |\n")
	for _, line := range strings.Split(strings.TrimRight(rego, "\n"), "\n") {
		if line == "" {
			b.WriteString("\n")
			continue
		}
		b.WriteString("        " + line + "\n")
	}

	b.WriteString("---\n")

	// ---- Constraint ----
	b.WriteString("apiVersion: constraints.gatekeeper.sh/v1beta1\n")
	b.WriteString("kind: " + kind + "\n")
	b.WriteString("metadata:\n")
	b.WriteString("  name: " + strings.ToLower(kind) + "-default\n")
	b.WriteString("  annotations:\n")
	b.WriteString("    description: " + yamlString(description) + "\n")
	b.WriteString("spec:\n")
	b.WriteString("  enforcementAction: deny\n")
	b.WriteString("  match:\n")
	b.WriteString("    kinds:\n")
	for _, m := range match {
		b.WriteString("      - apiGroups:\n")
		for _, g := range m.APIGroups {
			b.WriteString("          - " + yamlString(g) + "\n")
		}
		b.WriteString("        kinds:\n")
		for _, k := range m.Kinds {
			b.WriteString("          - " + yamlString(k) + "\n")
		}
	}

	return b.String()
}

// podSpecBoolRego returns a Rego body for the standard "deny when
// podSpec.<field>=true" template (hostNetwork / hostPID / hostIPC). Covers
// both bare Pods (.spec.<field>) and workload controllers
// (.spec.template.spec.<field>). pkgSuffix is the lowercase suffix appended
// to the package name (no characters Rego rejects); field is the JSON name
// of the spec property; msg is the message rendered into the denial.
func podSpecBoolRego(pkgSuffix, field, msg string) string {
	return "package k8spodsec" + pkgSuffix + "\n\n" +
		"import future.keywords.contains\n" +
		"import future.keywords.if\n\n" +
		"violation contains {\"msg\": msg} if {\n" +
		"  input.review.object.kind == \"Pod\"\n" +
		"  input.review.object.spec." + field + " == true\n" +
		"  msg := \"" + escapeRegoString(msg) + "\"\n" +
		"}\n\n" +
		"violation contains {\"msg\": msg} if {\n" +
		"  input.review.object.kind != \"Pod\"\n" +
		"  input.review.object.spec.template.spec." + field + " == true\n" +
		"  msg := \"" + escapeRegoString(msg) + "\"\n" +
		"}\n"
}

// escapeRegoString quotes a Go string for embedding inside a Rego string
// literal. Rego shares Go's escape syntax for the characters we care about
// (backslash, double-quote, newline), so this is a thin wrapper.
func escapeRegoString(s string) string {
	r := strings.NewReplacer(
		`\`, `\\`,
		`"`, `\"`,
		"\n", `\n`,
		"\r", `\r`,
		"\t", `\t`,
	)
	return r.Replace(s)
}

// yamlString returns s formatted as a YAML scalar safe for inline emission.
// Every string is wrapped in double quotes (including metadata.name fields
// and apiGroups list items) so that future strings containing colons,
// leading dashes, or YAML-reserved tokens don't silently reparse to
// something else. Standard YAML escape rules apply: backslash and double
// quote get backslash-escaped.
func yamlString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// ---- Rego bodies --------------------------------------------------------
//
// Each constant below is a complete Rego v1 module that Gatekeeper compiles
// at ConstraintTemplate install time. The shared `all_containers/1` helper
// is duplicated across modules because Gatekeeper's `targets.rego` field is
// a single string — there is no `import data.lib.foo` story without a
// separate ConstraintTemplate library. Duplication keeps each template
// standalone and copy-pastable.
//
// `all_containers` returns the concatenation of init + runtime + ephemeral
// containers for both bare Pod objects (.spec.containers) and workload
// controllers (.spec.template.spec.containers).

const allContainersHelperRego = `all_containers(obj) := containers if {
  obj.kind == "Pod"
  containers := array.concat(
    array.concat(
      object.get(obj.spec, "initContainers", []),
      obj.spec.containers,
    ),
    object.get(obj.spec, "ephemeralContainers", []),
  )
}

all_containers(obj) := containers if {
  obj.kind != "Pod"
  containers := array.concat(
    array.concat(
      object.get(obj.spec.template.spec, "initContainers", []),
      obj.spec.template.spec.containers,
    ),
    object.get(obj.spec.template.spec, "ephemeralContainers", []),
  )
}
`

const regoPrivileged = `package k8spodsecprivileged

import future.keywords.contains
import future.keywords.if
import future.keywords.in

violation contains {"msg": msg} if {
  some c in all_containers(input.review.object)
  c.securityContext.privileged == true
  msg := sprintf("privileged container is not allowed: %q", [c.name])
}

` + allContainersHelperRego

const regoAllowPrivilegeEscalation = `package k8spodsecallowprivilegeescalation

import future.keywords.contains
import future.keywords.if
import future.keywords.in

violation contains {"msg": msg} if {
  some c in all_containers(input.review.object)
  not c.securityContext.allowPrivilegeEscalation == false
  msg := sprintf("container %q must set securityContext.allowPrivilegeEscalation=false", [c.name])
}

` + allContainersHelperRego

const regoRunAsNonRoot = `package k8spodsecrunasnonroot

import future.keywords.contains
import future.keywords.if
import future.keywords.in

violation contains {"msg": msg} if {
  some c in all_containers(input.review.object)
  not container_runs_as_non_root(input.review.object, c)
  msg := sprintf("container %q must set runAsNonRoot=true or runAsUser>0 (pod- or container-level)", [c.name])
}

container_runs_as_non_root(_, c) if {
  c.securityContext.runAsNonRoot == true
}
container_runs_as_non_root(_, c) if {
  c.securityContext.runAsUser > 0
}
container_runs_as_non_root(obj, c) if {
  not c.securityContext.runAsNonRoot
  not c.securityContext.runAsUser
  pod_runs_as_non_root(obj)
}

pod_runs_as_non_root(obj) if {
  obj.kind == "Pod"
  obj.spec.securityContext.runAsNonRoot == true
}
pod_runs_as_non_root(obj) if {
  obj.kind == "Pod"
  obj.spec.securityContext.runAsUser > 0
}
pod_runs_as_non_root(obj) if {
  obj.kind != "Pod"
  obj.spec.template.spec.securityContext.runAsNonRoot == true
}
pod_runs_as_non_root(obj) if {
  obj.kind != "Pod"
  obj.spec.template.spec.securityContext.runAsUser > 0
}

` + allContainersHelperRego

const regoReadOnlyRootFs = `package k8spodsecreadonlyrootfs

import future.keywords.contains
import future.keywords.if
import future.keywords.in

violation contains {"msg": msg} if {
  some c in all_containers(input.review.object)
  not c.securityContext.readOnlyRootFilesystem == true
  msg := sprintf("container %q must set securityContext.readOnlyRootFilesystem=true", [c.name])
}

` + allContainersHelperRego

const regoSeccomp = `package k8spodsecseccomp

import future.keywords.contains
import future.keywords.if
import future.keywords.in

violation contains {"msg": msg} if {
  some c in all_containers(input.review.object)
  not container_has_seccomp(input.review.object, c)
  msg := sprintf("container %q must set seccompProfile.type to RuntimeDefault or Localhost (pod- or container-level)", [c.name])
}

container_has_seccomp(_, c) if {
  c.securityContext.seccompProfile.type == "RuntimeDefault"
}
container_has_seccomp(_, c) if {
  c.securityContext.seccompProfile.type == "Localhost"
}
container_has_seccomp(obj, c) if {
  not c.securityContext.seccompProfile
  pod_has_seccomp(obj)
}

pod_has_seccomp(obj) if {
  obj.kind == "Pod"
  obj.spec.securityContext.seccompProfile.type == "RuntimeDefault"
}
pod_has_seccomp(obj) if {
  obj.kind == "Pod"
  obj.spec.securityContext.seccompProfile.type == "Localhost"
}
pod_has_seccomp(obj) if {
  obj.kind != "Pod"
  obj.spec.template.spec.securityContext.seccompProfile.type == "RuntimeDefault"
}
pod_has_seccomp(obj) if {
  obj.kind != "Pod"
  obj.spec.template.spec.securityContext.seccompProfile.type == "Localhost"
}

` + allContainersHelperRego

const regoProcMount = `package k8spodsecprocmount

import future.keywords.contains
import future.keywords.if
import future.keywords.in

violation contains {"msg": msg} if {
  some c in all_containers(input.review.object)
  c.securityContext.procMount == "Unmasked"
  msg := sprintf("container %q must not set procMount=Unmasked", [c.name])
}

` + allContainersHelperRego

const regoHostPath = `package k8spodsechostpath

import future.keywords.contains
import future.keywords.if
import future.keywords.in

violation contains {"msg": msg} if {
  input.review.object.kind == "Pod"
  some volume in input.review.object.spec.volumes
  volume.hostPath
  msg := sprintf("hostPath volumes are not allowed: volume %q mounts host path %q", [volume.name, volume.hostPath.path])
}

violation contains {"msg": msg} if {
  input.review.object.kind != "Pod"
  some volume in input.review.object.spec.template.spec.volumes
  volume.hostPath
  msg := sprintf("hostPath volumes are not allowed: volume %q mounts host path %q", [volume.name, volume.hostPath.path])
}
`

const regoImmutableImageTag = `package k8spodsecimmutableimagetag

import future.keywords.contains
import future.keywords.if
import future.keywords.in

violation contains {"msg": msg} if {
  some c in all_containers(input.review.object)
  not is_immutable_image(c.image)
  msg := sprintf("container %q image %q must use an immutable tag (pinned tag or @sha256: digest)", [c.name, c.image])
}

is_immutable_image(image) if {
  contains(image, "@sha256:")
}
is_immutable_image(image) if {
  contains(image, ":")
  not endswith(image, ":latest")
  not contains(image, "@sha256:")
}

` + allContainersHelperRego

const regoClusterAdminBinding = `package k8srbacoverbroadclusteradmin

import future.keywords.contains
import future.keywords.if
import future.keywords.in

violation contains {"msg": msg} if {
  input.review.object.roleRef.kind == "ClusterRole"
  input.review.object.roleRef.name == "cluster-admin"
  some subject in input.review.object.subjects
  not startswith(subject.name, "system:")
  msg := sprintf("ClusterRoleBinding %q grants cluster-admin to non-system subject %q (kind=%q)", [input.review.object.metadata.name, subject.name, subject.kind])
}
`
