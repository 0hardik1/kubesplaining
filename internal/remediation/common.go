// Package remediation generates structured fix payloads (kubectl patches,
// Kyverno / Gatekeeper policies, RBAC diffs) for findings emitted by the
// analyzer modules. Each per-module entrypoint (e.g. ForPodsec) takes a rule ID
// + a constructed Finding and returns a *models.RemediationHint, which the
// analyzers attach to the Finding before emitting it. Every field on the hint
// is optional, so generators that only know how to build one surface (a
// kubectl patch, say) leave the others nil and the HTML / JSON / SARIF outputs
// render only what was supplied.
package remediation

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// shellSingleQuote wraps body in POSIX single quotes, escaping any embedded
// single quotes by closing-the-quote, inserting a backslash-escaped quote, and
// reopening the quote. The result is safe to paste into a bash / zsh shell as
// the argument to a flag like `kubectl patch ... -p '<this>'`. Single quotes
// are used (not double) because shells do no expansion inside them, so the
// JSON braces / dollar signs in patch bodies are passed through verbatim.
func shellSingleQuote(body string) string {
	return "'" + strings.ReplaceAll(body, "'", `'\''`) + "'"
}

// renderKubectlPatchCommand pre-renders the kubectl invocation that applies
// the given patch. The result is a single-line string suitable for HTML
// display with a copy button (e.g. `kubectl patch deployment foo -n bar
// --type=strategic -p '{...}'`). For cluster-scoped objects (no Namespace),
// the `-n` flag is omitted; for the default namespace it is still printed so
// users do not paste the command without realising which namespace is
// implicit.
func renderKubectlPatchCommand(target models.PatchTarget, patchType string, body json.RawMessage) string {
	kind := strings.ToLower(target.Kind)
	parts := []string{"kubectl", "patch", kind, target.Name}
	if target.Namespace != "" {
		parts = append(parts, "-n", target.Namespace)
	}
	parts = append(parts, "--type="+patchType, "-p", shellSingleQuote(string(body)))
	return strings.Join(parts, " ")
}

// patchTargetFromFinding pulls the kind / namespace / name off the Finding's
// Resource pointer and resolves the apiVersion from the kind. Returns the
// zero PatchTarget and false when Resource is nil — callers should skip the
// remediation in that case rather than panic.
func patchTargetFromFinding(finding models.Finding) (models.PatchTarget, bool) {
	if finding.Resource == nil {
		return models.PatchTarget{}, false
	}
	return models.PatchTarget{
		Kind:       finding.Resource.Kind,
		APIVersion: apiVersionForKind(finding.Resource.Kind),
		Namespace:  finding.Resource.Namespace,
		Name:       finding.Resource.Name,
	}, true
}

// apiVersionForKind returns the apiVersion string we expect for each workload
// kind the podsec analyzer emits findings against. Pods are core/v1; the apps
// kinds are apps/v1; the batch kinds are batch/v1. Anything unknown returns
// the empty string so JSON consumers can spot the gap.
func apiVersionForKind(kind string) string {
	switch kind {
	case "Pod":
		return "v1"
	case "Deployment", "DaemonSet", "StatefulSet", "ReplicaSet":
		return "apps/v1"
	case "Job", "CronJob":
		return "batch/v1"
	default:
		return ""
	}
}

// containerNameFromEvidence pulls the "container" key out of a finding's
// Evidence JSON blob so the remediation generator knows which container in
// the pod template to patch. The podsec analyzer always sets this for
// container-scoped findings (privileged, runAsRoot, allowPrivilegeEscalation,
// readOnlyRootFilesystem, seccomp, procMount, image-tag); returns the empty
// string when the field is absent or the JSON is malformed (defensive — the
// generator falls back to a no-container patch).
func containerNameFromEvidence(evidence json.RawMessage) string {
	if len(evidence) == 0 {
		return ""
	}
	var decoded map[string]any
	if err := json.Unmarshal(evidence, &decoded); err != nil {
		return ""
	}
	name, _ := decoded["container"].(string)
	return name
}

// volumeNameFromEvidence pulls the "volume" key out of a finding's Evidence
// JSON blob. Used by hostPath-removal patches so the strategic-merge body
// only deletes the offending volume and not the entire `volumes` slice.
func volumeNameFromEvidence(evidence json.RawMessage) string {
	if len(evidence) == 0 {
		return ""
	}
	var decoded map[string]any
	if err := json.Unmarshal(evidence, &decoded); err != nil {
		return ""
	}
	name, _ := decoded["volume"].(string)
	return name
}

// wrapPodPatch returns a strategic-merge patch body that places the given
// pod-spec fragment (e.g. `{"hostNetwork": false}` or a containers list)
// under the correct workload-kind wrapper. The wrapper depth is what changes:
//
//   - Pod                         spec.<fragment>
//   - Deployment / DaemonSet /
//     StatefulSet / Job           spec.template.spec.<fragment>
//   - CronJob                     spec.jobTemplate.spec.template.spec.<fragment>
//
// Returns the raw JSON bytes and an error when marshalling fails (which
// should never happen for the structured maps we build).
func wrapPodPatch(kind string, podSpecFragment map[string]any) (json.RawMessage, error) {
	var body any
	switch kind {
	case "Pod":
		body = map[string]any{"spec": podSpecFragment}
	case "CronJob":
		body = map[string]any{
			"spec": map[string]any{
				"jobTemplate": map[string]any{
					"spec": map[string]any{
						"template": map[string]any{
							"spec": podSpecFragment,
						},
					},
				},
			},
		}
	default:
		// Deployment / DaemonSet / StatefulSet / Job all use spec.template.spec.
		body = map[string]any{
			"spec": map[string]any{
				"template": map[string]any{
					"spec": podSpecFragment,
				},
			},
		}
	}
	bytes, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal pod patch: %w", err)
	}
	return bytes, nil
}

// containerSecurityContextPatch builds a strategic-merge patch fragment that
// targets one container by name and overlays its securityContext with the
// given fields. `containers` is a strategic-merge "named list" keyed by
// `name`, so kubectl will merge the patch into the existing container with
// that name without disturbing any other containers in the pod template.
func containerSecurityContextPatch(containerName string, securityContext map[string]any) map[string]any {
	return map[string]any{
		"containers": []map[string]any{
			{
				"name":            containerName,
				"securityContext": securityContext,
			},
		},
	}
}
