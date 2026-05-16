package remediation

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// ForContainerSec returns the structured remediation hint for a containersec
// finding, or nil when no patch can be generated for the rule. The Finding's
// Resource pointer must be non-nil; every rule in this module expects a
// "container" entry inside Finding.Evidence because the containersec analyzer
// aggregates per workload and tags each finding with the container name.
//
// Coverage: KUBE-CONTAINER-LIMITS-001 (no requests / limits), PROBE-001 (no
// liveness or readiness probes), IMAGE-001 (mutable tag with Always pull),
// LIFECYCLE-001 (non-trivial postStart / preStop exec hook).
//
// The two structural rules (LIMITS, PROBE) emit a strategic-merge patch built
// off the standard pod-spec envelope; IMAGE has no safe automated rewrite
// because the right digest is unknown, so it falls back to a `kubectl set
// image` placeholder command; LIFECYCLE cannot be expressed as a clean
// strategic-merge or JSON-patch remove without a container index we do not
// reliably have, so it falls back to a `kubectl edit` command with prose
// guidance.
func ForContainerSec(ruleID string, finding models.Finding) *models.RemediationHint {
	target, ok := patchTargetFromFinding(finding)
	if !ok {
		return nil
	}

	switch ruleID {
	case "KUBE-CONTAINER-LIMITS-001":
		return resourceLimitsPatch(target, finding)
	case "KUBE-CONTAINER-PROBE-001":
		return readinessProbePatch(target, finding)
	case "KUBE-CONTAINER-IMAGE-001":
		return imageDigestPinSuggestion(target, finding)
	case "KUBE-CONTAINER-LIFECYCLE-001":
		return lifecycleEditSuggestion(target, finding)
	}
	return nil
}

// resourceLimitsPatch emits a strategic-merge patch that overlays a baseline
// requests / limits block onto the offending container. The numbers below are
// a starter sizing only: operators should replace them with values derived
// from observed CPU / memory usage (e.g. via `kubectl top` or a metrics
// pipeline) before applying. Blindly committing these defaults can either
// starve the workload (limits too low) or break bin-packing (limits too
// high), so the rendered command should be treated as a template rather than
// a drop-in fix.
func resourceLimitsPatch(target models.PatchTarget, finding models.Finding) *models.RemediationHint {
	container := containerNameFromEvidence(finding.Evidence)
	if container == "" {
		return nil
	}
	fragment := containerResourcesPatch(container, map[string]any{
		"requests": map[string]any{
			"cpu":    "250m",
			"memory": "128Mi",
		},
		"limits": map[string]any{
			"cpu":    "500m",
			"memory": "256Mi",
		},
	})
	return strategicHintContainer(target, fragment)
}

// readinessProbePatch emits a strategic-merge patch that adds a minimal
// readinessProbe scaffold to the offending container. The exec command is a
// PLACEHOLDER: `sleep 1` always succeeds, which defeats the purpose of a
// readiness probe (it would mark the pod ready before its real dependencies
// are reachable). Operators MUST replace this with a real dependency check
// (`httpGet` against a /healthz endpoint, `tcpSocket` against the service
// port, or an `exec` that pings the upstream the container actually needs).
// We still emit the scaffold because materializing the field with a stub is
// strictly better than leaving the container with no probe at all: the next
// reviewer at least sees the shape that needs filling in.
func readinessProbePatch(target models.PatchTarget, finding models.Finding) *models.RemediationHint {
	container := containerNameFromEvidence(finding.Evidence)
	if container == "" {
		return nil
	}
	fragment := map[string]any{
		"containers": []map[string]any{
			{
				"name": container,
				"readinessProbe": map[string]any{
					"exec": map[string]any{
						"command": []string{"sleep", "1"},
					},
				},
			},
		},
	}
	return strategicHintContainer(target, fragment)
}

// imageDigestPinSuggestion returns a command-only hint that documents the
// `kubectl set image` invocation needed to repin the container to an
// immutable digest. We cannot synthesize the digest ourselves (it depends on
// what the operator actually wants to deploy), so the placeholder DIGEST
// literal is left in the command for the user to substitute. The repo prefix
// is preserved from the existing image reference so the user only has to
// fill in the digest, not the whole pull path.
func imageDigestPinSuggestion(target models.PatchTarget, finding models.Finding) *models.RemediationHint {
	container := containerNameFromEvidence(finding.Evidence)
	if container == "" {
		return nil
	}
	repo := imageRepoFromEvidence(finding.Evidence)
	command := fmt.Sprintf(
		"kubectl set image %s/%s %s=%s@sha256:<DIGEST>",
		strings.ToLower(target.Kind), target.Name, container, repo,
	)
	if target.Namespace != "" {
		command += " -n " + target.Namespace
	}
	return commandOnlyHint(target, command)
}

// lifecycleEditSuggestion returns a command-only hint that opens the
// workload in `kubectl edit` and instructs the operator to remove the
// offending lifecycle hook. JSON-patch could only target the hook by
// container index (which we do not reliably know once init containers and
// reorderings come into play), and strategic-merge cannot express a `remove`
// on a named-list child field without rewriting the whole container entry.
// `kubectl edit` is the pragmatic answer: surface the file in the user's
// $EDITOR, point them at the field, and let them strip it. The hook name
// from Evidence is included in the command's comment so the user knows
// which entry (postStart vs preStop) to delete.
func lifecycleEditSuggestion(target models.PatchTarget, finding models.Finding) *models.RemediationHint {
	container := containerNameFromEvidence(finding.Evidence)
	hook := hookNameFromEvidence(finding.Evidence)
	parts := []string{"kubectl", "edit", strings.ToLower(target.Kind), target.Name}
	if target.Namespace != "" {
		parts = append(parts, "-n", target.Namespace)
	}
	command := strings.Join(parts, " ")
	if container != "" || hook != "" {
		descriptor := strings.TrimSpace(container + " " + hook)
		command += fmt.Sprintf("  # remove spec.containers[%s].lifecycle hook", descriptor)
	} else {
		command += "  # remove the lifecycle.postStart / lifecycle.preStop exec block"
	}
	return commandOnlyHint(target, command)
}

// hookNameFromEvidence pulls the "hook" key (set to "postStart" or "preStop"
// by the containersec analyzer) off the finding evidence so the lifecycle
// suggestion can point the operator at the specific hook to delete. Returns
// the empty string when missing or unparseable; the caller degrades to a
// generic message.
func hookNameFromEvidence(evidence json.RawMessage) string {
	if len(evidence) == 0 {
		return ""
	}
	var decoded map[string]any
	if err := json.Unmarshal(evidence, &decoded); err != nil {
		return ""
	}
	name, _ := decoded["hook"].(string)
	return name
}

// containerResourcesPatch mirrors containerSecurityContextPatch in common.go
// but overlays the container's `resources` block instead of
// `securityContext`. Kept local to containersec.go because no other module
// patches resource requests / limits; promoting it to common.go would add a
// helper with exactly one caller. `containers` is a strategic-merge named
// list keyed by `name`, so kubectl merges the patch into the existing
// container with that name without disturbing any other containers in the
// pod template.
func containerResourcesPatch(containerName string, resources map[string]any) map[string]any {
	return map[string]any{
		"containers": []map[string]any{
			{
				"name":      containerName,
				"resources": resources,
			},
		},
	}
}

// strategicHintContainer is the shared tail for the two strategic-merge
// container-scoped rules in this module: wrap the pod-spec fragment in the
// workload-kind envelope, attach the rendered kubectl command, and return
// the populated RemediationHint. Mirrors `strategicHint` in podsec.go but
// kept local so containersec.go does not depend on the podsec generator's
// internals.
func strategicHintContainer(target models.PatchTarget, podSpecFragment map[string]any) *models.RemediationHint {
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
