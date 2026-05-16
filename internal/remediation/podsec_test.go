package remediation

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// makeFinding builds a minimal podsec-style Finding suitable for feeding into
// ForPodsec. The Resource pointer is mandatory for every covered rule; the
// evidence map is marshalled to JSON so the generator's evidence accessors
// see exactly the shape the podsec analyzer produces in production.
func makeFinding(t *testing.T, ruleID, kind, namespace, name string, evidence map[string]any) models.Finding {
	t.Helper()
	body, err := json.Marshal(evidence)
	if err != nil {
		t.Fatalf("marshal evidence: %v", err)
	}
	return models.Finding{
		ID:       ruleID + ":" + kind + ":" + namespace + ":" + name,
		RuleID:   ruleID,
		Severity: models.SeverityHigh,
		Resource: &models.ResourceRef{
			Kind:      kind,
			Namespace: namespace,
			Name:      name,
		},
		Evidence: body,
	}
}

// expectStrategicPatch is a shared assertion that runs the same shape checks
// against every strategic-merge generator: the hint must be non-nil, the
// patch type must be "strategic", the target fields must match the input,
// the body must be parseable JSON, and the command string must include
// `kubectl patch`, the kind, the name, and the body. Each rule-specific
// test then layers on its own assertion against the parsed body.
func expectStrategicPatch(t *testing.T, hint *models.RemediationHint, kind, namespace, name string) map[string]any {
	t.Helper()
	if hint == nil || hint.Patch == nil {
		t.Fatalf("expected non-nil RemediationHint and Patch, got %+v", hint)
	}
	if hint.Patch.Type != "strategic" {
		t.Errorf("Patch.Type = %q, want strategic", hint.Patch.Type)
	}
	if hint.Patch.Target.Kind != kind || hint.Patch.Target.Namespace != namespace || hint.Patch.Target.Name != name {
		t.Errorf("Patch.Target = %+v, want kind=%q ns=%q name=%q",
			hint.Patch.Target, kind, namespace, name)
	}
	if hint.Patch.Target.APIVersion == "" {
		t.Errorf("Patch.Target.APIVersion is empty for kind %q", kind)
	}
	var decoded map[string]any
	if err := json.Unmarshal(hint.Patch.Body, &decoded); err != nil {
		t.Fatalf("Patch.Body is not valid JSON: %v\nbody: %s", err, string(hint.Patch.Body))
	}
	if hint.Patch.Command == "" {
		t.Fatalf("Patch.Command is empty")
	}
	for _, want := range []string{"kubectl patch", strings.ToLower(kind), name} {
		if !strings.Contains(hint.Patch.Command, want) {
			t.Errorf("Patch.Command missing %q\ncommand: %s", want, hint.Patch.Command)
		}
	}
	if namespace != "" && !strings.Contains(hint.Patch.Command, "-n "+namespace) {
		t.Errorf("Patch.Command missing namespace flag %q\ncommand: %s", "-n "+namespace, hint.Patch.Command)
	}
	return decoded
}

// containerSecCtx walks the wrapped strategic-merge body down to the named
// container's securityContext and returns it. Helper exists to make
// per-rule tests assert exactly the field they care about without
// re-traversing the same template envelope every time.
func containerSecCtx(t *testing.T, decoded map[string]any, kind, container string) map[string]any {
	t.Helper()
	containers := podSpecField(t, decoded, kind, "containers")
	containerList, ok := containers.([]any)
	if !ok {
		t.Fatalf("containers is %T, want []any", containers)
	}
	for _, raw := range containerList {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if entry["name"] != container {
			continue
		}
		sc, ok := entry["securityContext"].(map[string]any)
		if !ok {
			t.Fatalf("container %q has no securityContext map: %+v", container, entry)
		}
		return sc
	}
	t.Fatalf("container %q not found in patch body", container)
	return nil
}

// podSpecField unwraps the workload-kind envelope (Pod vs Deployment vs
// CronJob) and returns the requested field from the embedded pod spec.
// Mirrors the logic in wrapPodPatch in reverse so the tests stay in sync if
// the wrapping ever changes.
func podSpecField(t *testing.T, decoded map[string]any, kind, field string) any {
	t.Helper()
	spec, ok := decoded["spec"].(map[string]any)
	if !ok {
		t.Fatalf("decoded.spec is %T, want map", decoded["spec"])
	}
	switch kind {
	case "Pod":
		return spec[field]
	case "CronJob":
		jobTemplate, _ := spec["jobTemplate"].(map[string]any)
		jobSpec, _ := jobTemplate["spec"].(map[string]any)
		template, _ := jobSpec["template"].(map[string]any)
		podSpec, _ := template["spec"].(map[string]any)
		return podSpec[field]
	default:
		template, _ := spec["template"].(map[string]any)
		podSpec, _ := template["spec"].(map[string]any)
		return podSpec[field]
	}
}

func TestForPodsecPrivileged(t *testing.T) {
	t.Parallel()
	finding := makeFinding(t, "KUBE-ESCAPE-001", "Deployment", "default", "risky", map[string]any{
		"container": "app",
	})
	hint := ForPodsec("KUBE-ESCAPE-001", finding)
	body := expectStrategicPatch(t, hint, "Deployment", "default", "risky")
	sc := containerSecCtx(t, body, "Deployment", "app")
	if sc["privileged"] != false {
		t.Errorf("securityContext.privileged = %v, want false", sc["privileged"])
	}
}

func TestForPodsecRunAsNonRoot(t *testing.T) {
	t.Parallel()
	finding := makeFinding(t, "KUBE-PODSEC-ROOT-001", "Deployment", "default", "rooty", map[string]any{
		"container": "app",
	})
	hint := ForPodsec("KUBE-PODSEC-ROOT-001", finding)
	body := expectStrategicPatch(t, hint, "Deployment", "default", "rooty")
	sc := containerSecCtx(t, body, "Deployment", "app")
	if sc["runAsNonRoot"] != true {
		t.Errorf("securityContext.runAsNonRoot = %v, want true", sc["runAsNonRoot"])
	}
}

func TestForPodsecAllowPrivilegeEscalation(t *testing.T) {
	t.Parallel()
	finding := makeFinding(t, "KUBE-PODSEC-APE-001", "DaemonSet", "kube-system", "ds", map[string]any{
		"container": "agent",
	})
	hint := ForPodsec("KUBE-PODSEC-APE-001", finding)
	body := expectStrategicPatch(t, hint, "DaemonSet", "kube-system", "ds")
	sc := containerSecCtx(t, body, "DaemonSet", "agent")
	if sc["allowPrivilegeEscalation"] != false {
		t.Errorf("securityContext.allowPrivilegeEscalation = %v, want false", sc["allowPrivilegeEscalation"])
	}
}

func TestForPodsecReadOnlyRootFilesystem(t *testing.T) {
	t.Parallel()
	finding := makeFinding(t, "KUBE-PODSEC-READONLY-001", "Pod", "default", "p", map[string]any{
		"container": "c",
	})
	hint := ForPodsec("KUBE-PODSEC-READONLY-001", finding)
	body := expectStrategicPatch(t, hint, "Pod", "default", "p")
	sc := containerSecCtx(t, body, "Pod", "c")
	if sc["readOnlyRootFilesystem"] != true {
		t.Errorf("securityContext.readOnlyRootFilesystem = %v, want true", sc["readOnlyRootFilesystem"])
	}
}

func TestForPodsecSeccompProfile(t *testing.T) {
	t.Parallel()
	finding := makeFinding(t, "KUBE-PODSEC-SECCOMP-001", "StatefulSet", "default", "sts", map[string]any{
		"container": "main",
	})
	hint := ForPodsec("KUBE-PODSEC-SECCOMP-001", finding)
	body := expectStrategicPatch(t, hint, "StatefulSet", "default", "sts")
	sc := containerSecCtx(t, body, "StatefulSet", "main")
	profile, ok := sc["seccompProfile"].(map[string]any)
	if !ok {
		t.Fatalf("securityContext.seccompProfile = %v, want map", sc["seccompProfile"])
	}
	if profile["type"] != "RuntimeDefault" {
		t.Errorf("seccompProfile.type = %v, want RuntimeDefault", profile["type"])
	}
}

func TestForPodsecProcMount(t *testing.T) {
	t.Parallel()
	finding := makeFinding(t, "KUBE-PODSEC-PROCMOUNT-001", "Job", "batch", "j", map[string]any{
		"container": "worker",
	})
	hint := ForPodsec("KUBE-PODSEC-PROCMOUNT-001", finding)
	body := expectStrategicPatch(t, hint, "Job", "batch", "j")
	sc := containerSecCtx(t, body, "Job", "worker")
	if sc["procMount"] != "Default" {
		t.Errorf("securityContext.procMount = %v, want Default", sc["procMount"])
	}
}

func TestForPodsecHostNetwork(t *testing.T) {
	t.Parallel()
	finding := makeFinding(t, "KUBE-ESCAPE-003", "Deployment", "default", "host-net", nil)
	hint := ForPodsec("KUBE-ESCAPE-003", finding)
	body := expectStrategicPatch(t, hint, "Deployment", "default", "host-net")
	if got := podSpecField(t, body, "Deployment", "hostNetwork"); got != false {
		t.Errorf("hostNetwork = %v, want false", got)
	}
}

func TestForPodsecHostPID(t *testing.T) {
	t.Parallel()
	finding := makeFinding(t, "KUBE-ESCAPE-002", "Deployment", "default", "host-pid", nil)
	hint := ForPodsec("KUBE-ESCAPE-002", finding)
	body := expectStrategicPatch(t, hint, "Deployment", "default", "host-pid")
	if got := podSpecField(t, body, "Deployment", "hostPID"); got != false {
		t.Errorf("hostPID = %v, want false", got)
	}
}

func TestForPodsecHostIPC(t *testing.T) {
	t.Parallel()
	finding := makeFinding(t, "KUBE-ESCAPE-004", "Deployment", "default", "host-ipc", nil)
	hint := ForPodsec("KUBE-ESCAPE-004", finding)
	body := expectStrategicPatch(t, hint, "Deployment", "default", "host-ipc")
	if got := podSpecField(t, body, "Deployment", "hostIPC"); got != false {
		t.Errorf("hostIPC = %v, want false", got)
	}
}

// TestForPodsecHostPathVariants exercises every rule the hostPath family can
// emit so the volume-removal patch wires up consistently for the generic
// hostPath, the docker socket, the rootfs mount, the log directory, and the
// containerd socket.
func TestForPodsecHostPathVariants(t *testing.T) {
	t.Parallel()
	cases := []struct {
		ruleID string
		volume string
	}{
		{"KUBE-HOSTPATH-001", "data"},
		{"KUBE-ESCAPE-005", "docker-sock"},
		{"KUBE-ESCAPE-006", "rootfs"},
		{"KUBE-ESCAPE-008", "varlog"},
		{"KUBE-CONTAINERD-SOCKET-001", "containerd-sock"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.ruleID, func(t *testing.T) {
			t.Parallel()
			finding := makeFinding(t, tc.ruleID, "Deployment", "default", "hp", map[string]any{
				"volume": tc.volume,
				"path":   "/some/path",
			})
			hint := ForPodsec(tc.ruleID, finding)
			body := expectStrategicPatch(t, hint, "Deployment", "default", "hp")
			volumes, ok := podSpecField(t, body, "Deployment", "volumes").([]any)
			if !ok || len(volumes) == 0 {
				t.Fatalf("volumes is %v (%T), want non-empty slice", podSpecField(t, body, "Deployment", "volumes"), podSpecField(t, body, "Deployment", "volumes"))
			}
			entry, _ := volumes[0].(map[string]any)
			if entry["name"] != tc.volume {
				t.Errorf("volumes[0].name = %v, want %q", entry["name"], tc.volume)
			}
			if entry["$patch"] != "delete" {
				t.Errorf(`volumes[0]["$patch"] = %v, want "delete"`, entry["$patch"])
			}
		})
	}
}

// TestForPodsecImageLatest verifies the comment-only TODO patch still
// renders a runnable shape: a non-nil hint, an empty JSON body, and a
// Command string carrying the placeholder repo.
func TestForPodsecImageLatest(t *testing.T) {
	t.Parallel()
	finding := makeFinding(t, "KUBE-IMAGE-LATEST-001", "Deployment", "default", "imgapp", map[string]any{
		"container": "app",
		"image":     "nginx:latest",
	})
	hint := ForPodsec("KUBE-IMAGE-LATEST-001", finding)
	if hint == nil || hint.Patch == nil {
		t.Fatalf("expected non-nil hint, got %+v", hint)
	}
	if hint.Patch.Type != "merge" {
		t.Errorf("Patch.Type = %q, want merge", hint.Patch.Type)
	}
	if string(hint.Patch.Body) != "{}" {
		t.Errorf("Patch.Body = %s, want empty object", string(hint.Patch.Body))
	}
	if !strings.Contains(hint.Patch.Command, "# TODO:") {
		t.Errorf("Patch.Command missing TODO marker: %s", hint.Patch.Command)
	}
	if !strings.Contains(hint.Patch.Command, "nginx") {
		t.Errorf("Patch.Command missing image repo: %s", hint.Patch.Command)
	}
}

// TestForPodsecCronJobWrapping checks that CronJob targets get the deeper
// envelope (spec.jobTemplate.spec.template.spec) instead of the generic
// spec.template.spec.
func TestForPodsecCronJobWrapping(t *testing.T) {
	t.Parallel()
	finding := makeFinding(t, "KUBE-PODSEC-APE-001", "CronJob", "default", "nightly", map[string]any{
		"container": "app",
	})
	hint := ForPodsec("KUBE-PODSEC-APE-001", finding)
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

// TestForPodsecPodWrapping checks that Pod targets get the shallow envelope
// (spec.<fragment>) rather than the workload spec.template.spec.
func TestForPodsecPodWrapping(t *testing.T) {
	t.Parallel()
	finding := makeFinding(t, "KUBE-ESCAPE-003", "Pod", "default", "p", nil)
	hint := ForPodsec("KUBE-ESCAPE-003", finding)
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
	if spec["hostNetwork"] != false {
		t.Errorf("spec.hostNetwork = %v, want false", spec["hostNetwork"])
	}
}

// TestForPodsecNilResourceReturnsNil guards the defensive branch in
// patchTargetFromFinding: callers that hand us a Finding with no Resource
// should get nil back rather than a panic.
func TestForPodsecNilResourceReturnsNil(t *testing.T) {
	t.Parallel()
	f := models.Finding{RuleID: "KUBE-ESCAPE-001"}
	if hint := ForPodsec("KUBE-ESCAPE-001", f); hint != nil {
		t.Errorf("expected nil hint for finding without Resource, got %+v", hint)
	}
}

// TestForPodsecUnknownRuleReturnsNil documents that the table is closed:
// rules outside the covered set get nil rather than a default patch, so
// callers know to fall back to the prose Remediation field.
func TestForPodsecUnknownRuleReturnsNil(t *testing.T) {
	t.Parallel()
	f := makeFinding(t, "KUBE-RBAC-OVERBROAD-001", "ClusterRole", "", "admin", nil)
	if hint := ForPodsec("KUBE-RBAC-OVERBROAD-001", f); hint != nil {
		t.Errorf("expected nil hint for non-podsec rule, got %+v", hint)
	}
}

// TestForPodsecMissingContainerReturnsNil checks the defensive branch in
// container-scoped generators: when Evidence.container is missing we cannot
// produce a sensible patch, so we return nil instead of a patch that targets
// the wrong (empty) container name.
func TestForPodsecMissingContainerReturnsNil(t *testing.T) {
	t.Parallel()
	f := makeFinding(t, "KUBE-ESCAPE-001", "Deployment", "default", "x", map[string]any{
		// no container key
	})
	if hint := ForPodsec("KUBE-ESCAPE-001", f); hint != nil {
		t.Errorf("expected nil hint when container missing from evidence, got %+v", hint)
	}
}

// TestForPodsecCommandShellSafe forces a single-quote into a target name to
// confirm shellSingleQuote escapes it correctly so the rendered Command can
// still be pasted into a POSIX shell without breaking out of the body
// argument. Real K8s names cannot contain quotes, but the function should
// still degrade safely if the contract is ever violated upstream.
func TestForPodsecCommandShellSafe(t *testing.T) {
	t.Parallel()
	body := json.RawMessage(`{"key":"o'malley"}`)
	got := renderKubectlPatchCommand(models.PatchTarget{Kind: "Pod", Name: "p", Namespace: "ns"}, "merge", body)
	if !strings.Contains(got, `'{"key":"o'\''malley"}'`) {
		t.Errorf("command did not escape single quote correctly: %s", got)
	}
}
