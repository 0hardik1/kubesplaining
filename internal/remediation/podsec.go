package remediation

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// ForPodsec returns the structured remediation hint for a podsec finding, or
// nil when no patch can be generated for the rule (e.g. mutable image tags,
// where the right answer requires knowing the desired digest). The Finding's
// Resource pointer must be non-nil; container-scoped rules also expect
// "container" / "volume" entries inside Finding.Evidence (the podsec
// analyzer always populates them).
//
// The returned RemediationHint always carries a *KubectlPatch with a
// pre-rendered Command string, except for KUBE-IMAGE-LATEST-001 where the
// patch is comment-only because there is no safe automated rewrite.
//
// Coverage: privileged, runAsNonRoot, hostNetwork / hostPID / hostIPC,
// hostPath family (KUBE-HOSTPATH-001 + KUBE-ESCAPE-005/006/008 +
// KUBE-CONTAINERD-SOCKET-001), allowPrivilegeEscalation,
// readOnlyRootFilesystem, seccomp profile, procMount.
func ForPodsec(ruleID string, finding models.Finding) *models.RemediationHint {
	target, ok := patchTargetFromFinding(finding)
	if !ok {
		return nil
	}

	switch ruleID {
	case "KUBE-ESCAPE-001":
		return privilegedPatch(target, finding)
	case "KUBE-PODSEC-ROOT-001":
		return runAsNonRootPatch(target, finding)
	case "KUBE-PODSEC-APE-001":
		return allowPrivilegeEscalationPatch(target, finding)
	case "KUBE-PODSEC-READONLY-001":
		return readOnlyRootFilesystemPatch(target, finding)
	case "KUBE-PODSEC-SECCOMP-001":
		return seccompProfilePatch(target, finding)
	case "KUBE-PODSEC-PROCMOUNT-001":
		return procMountPatch(target, finding)
	case "KUBE-ESCAPE-003":
		return hostBoolPatch(target, "hostNetwork")
	case "KUBE-ESCAPE-002":
		return hostBoolPatch(target, "hostPID")
	case "KUBE-ESCAPE-004":
		return hostBoolPatch(target, "hostIPC")
	case "KUBE-HOSTPATH-001",
		"KUBE-ESCAPE-005",
		"KUBE-ESCAPE-006",
		"KUBE-ESCAPE-008",
		"KUBE-CONTAINERD-SOCKET-001":
		return hostPathRemovalPatch(target, finding)
	case "KUBE-IMAGE-LATEST-001":
		return imageLatestSuggestion(target, finding)
	}
	return nil
}

// privilegedPatch returns a strategic-merge patch that flips the offending
// container's securityContext.privileged to false. The rule fires only when
// privileged was explicitly true, so this is the minimal change that brings
// the workload back to the safe default without otherwise rewriting the
// container's securityContext.
func privilegedPatch(target models.PatchTarget, finding models.Finding) *models.RemediationHint {
	container := containerNameFromEvidence(finding.Evidence)
	if container == "" {
		return nil
	}
	fragment := containerSecurityContextPatch(container, map[string]any{
		"privileged": false,
	})
	return strategicHint(target, fragment)
}

// runAsNonRootPatch sets the offending container's securityContext to enforce
// non-root execution: runAsNonRoot=true plus a sentinel runAsUser=1000 so the
// kubelet has a UID to actually use when no explicit user exists in the
// image. Operators should treat the 1000 as a placeholder and replace it
// with a project-appropriate UID.
func runAsNonRootPatch(target models.PatchTarget, finding models.Finding) *models.RemediationHint {
	container := containerNameFromEvidence(finding.Evidence)
	if container == "" {
		return nil
	}
	fragment := containerSecurityContextPatch(container, map[string]any{
		"runAsNonRoot": true,
		"runAsUser":    1000,
	})
	return strategicHint(target, fragment)
}

// allowPrivilegeEscalationPatch sets the container's securityContext field
// to false, blocking the no_new_privs bypass that lets a process gain extra
// capabilities via setuid binaries after exec.
func allowPrivilegeEscalationPatch(target models.PatchTarget, finding models.Finding) *models.RemediationHint {
	container := containerNameFromEvidence(finding.Evidence)
	if container == "" {
		return nil
	}
	fragment := containerSecurityContextPatch(container, map[string]any{
		"allowPrivilegeEscalation": false,
	})
	return strategicHint(target, fragment)
}

// readOnlyRootFilesystemPatch flips the offending container's
// securityContext.readOnlyRootFilesystem to true. Workloads that legitimately
// need a writable path should mount an emptyDir for that path; that is out of
// scope for an automated patch and is documented in the prose remediation.
func readOnlyRootFilesystemPatch(target models.PatchTarget, finding models.Finding) *models.RemediationHint {
	container := containerNameFromEvidence(finding.Evidence)
	if container == "" {
		return nil
	}
	fragment := containerSecurityContextPatch(container, map[string]any{
		"readOnlyRootFilesystem": true,
	})
	return strategicHint(target, fragment)
}

// seccompProfilePatch sets seccompProfile.type to RuntimeDefault on the
// offending container, which applies the container runtime's stock seccomp
// profile (cri-o, containerd, docker all ship one). RuntimeDefault is what
// PSS Restricted requires; teams that need a stricter Localhost profile
// should follow up manually.
func seccompProfilePatch(target models.PatchTarget, finding models.Finding) *models.RemediationHint {
	container := containerNameFromEvidence(finding.Evidence)
	if container == "" {
		return nil
	}
	fragment := containerSecurityContextPatch(container, map[string]any{
		"seccompProfile": map[string]any{
			"type": "RuntimeDefault",
		},
	})
	return strategicHint(target, fragment)
}

// procMountPatch sets procMount back to the safe Default. We deliberately do
// not use a JSON 6902 `remove` op here: setting it to Default is byte-equal
// to the K8s default behaviour, easier to apply (works against either
// strategic-merge or merge), and reads as an explicit refusal of the
// Unmasked opt-in rather than a silent unset.
func procMountPatch(target models.PatchTarget, finding models.Finding) *models.RemediationHint {
	container := containerNameFromEvidence(finding.Evidence)
	if container == "" {
		return nil
	}
	fragment := containerSecurityContextPatch(container, map[string]any{
		"procMount": "Default",
	})
	return strategicHint(target, fragment)
}

// hostBoolPatch returns a strategic-merge patch that flips a top-level
// pod-spec boolean (hostNetwork, hostPID, hostIPC) to false. The K8s default
// for all three is false, so this is the minimal "undo the explicit opt-in"
// change.
func hostBoolPatch(target models.PatchTarget, field string) *models.RemediationHint {
	fragment := map[string]any{field: false}
	return strategicHint(target, fragment)
}

// hostPathRemovalPatch deletes the offending hostPath volume from the pod
// template using a strategic-merge `$patch: delete` directive on the named
// list. We do not also strip volumeMounts referencing the volume — kubectl's
// strategic-merge handling of named lists tolerates a dangling reference at
// patch time and surfaces the validation error at admission, which gives the
// operator a clear pointer to the second edit they need to make. (A full
// fix that also strips matching volumeMounts would require knowing every
// container that mounts the volume, which the analyzer does not currently
// thread through Finding.Evidence.)
func hostPathRemovalPatch(target models.PatchTarget, finding models.Finding) *models.RemediationHint {
	volume := volumeNameFromEvidence(finding.Evidence)
	if volume == "" {
		return nil
	}
	fragment := map[string]any{
		"volumes": []map[string]any{
			{
				"name":   volume,
				"$patch": "delete",
			},
		},
	}
	return strategicHint(target, fragment)
}

// imageLatestSuggestion returns a Patch with no Body (no automated rewrite is
// possible without knowing the desired digest) but with a Command string
// carrying a `# TODO:` comment that documents the manual fix. The HTML report
// renders the Command verbatim, so users see actionable guidance even though
// no patch can be applied.
func imageLatestSuggestion(target models.PatchTarget, finding models.Finding) *models.RemediationHint {
	container := containerNameFromEvidence(finding.Evidence)
	if container == "" {
		return nil
	}
	command := fmt.Sprintf(
		"# TODO: pin image to an immutable digest, e.g.\n"+
			"# kubectl set image %s/%s %s=%s@sha256:<digest> -n %s",
		strings.ToLower(target.Kind), target.Name, container, imageRepoFromEvidence(finding.Evidence), target.Namespace,
	)
	return &models.RemediationHint{
		Patch: &models.KubectlPatch{
			Type:    "merge",
			Target:  target,
			Body:    json.RawMessage("{}"),
			Command: command,
		},
	}
}

// imageRepoFromEvidence pulls the "image" key off the finding evidence and
// strips the `:tag` (or `@digest`) suffix so the TODO command points at the
// repository the user should re-pin. Falls back to an obvious placeholder
// when the field is missing or unparseable.
func imageRepoFromEvidence(evidence json.RawMessage) string {
	const fallback = "<repo>"
	if len(evidence) == 0 {
		return fallback
	}
	var decoded map[string]any
	if err := json.Unmarshal(evidence, &decoded); err != nil {
		return fallback
	}
	image, _ := decoded["image"].(string)
	if image == "" {
		return fallback
	}
	if idx := strings.LastIndex(image, "@"); idx > 0 {
		return image[:idx]
	}
	if idx := strings.LastIndex(image, ":"); idx > 0 {
		return image[:idx]
	}
	return image
}

// strategicHint is the shared tail end of every podsec generator: wrap the
// pod-spec fragment in the workload-kind envelope, attach the rendered
// kubectl command, and return the populated RemediationHint. Returns nil
// when wrapping fails (which would only happen on an unrepresentable map).
func strategicHint(target models.PatchTarget, podSpecFragment map[string]any) *models.RemediationHint {
	body, err := wrapPodPatch(target.Kind, podSpecFragment)
	if err != nil {
		return nil
	}
	return &models.RemediationHint{
		Patch: &models.KubectlPatch{
			Type:    "strategic",
			Target:  target,
			Body:    body,
			Command: renderKubectlPatchCommand(target, "strategic", body),
		},
	}
}
