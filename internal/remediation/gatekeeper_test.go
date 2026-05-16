package remediation

import (
	"strings"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
	"gopkg.in/yaml.v3"
)

// expectedCoveredRules is the canonical list of rules the slot-#19 generator
// must cover. Mirrors the Kyverno generator (slot #18) so the two stay in
// lockstep: every podsec rule that admission can prevent, the mutable-image
// tag check, and the single high-leverage RBAC rule
// (KUBE-RBAC-OVERBROAD-001 = cluster-admin binding). Privesc graph paths
// are deliberately excluded because they describe a multi-hop relationship
// that admission can't see in a single object.
var expectedCoveredRules = []string{
	"KUBE-ESCAPE-001",            // privileged
	"KUBE-ESCAPE-002",            // hostPID
	"KUBE-ESCAPE-003",            // hostNetwork
	"KUBE-ESCAPE-004",            // hostIPC
	"KUBE-ESCAPE-005",            // docker socket hostPath
	"KUBE-ESCAPE-006",            // root hostPath
	"KUBE-ESCAPE-008",            // /var/log hostPath
	"KUBE-CONTAINERD-SOCKET-001", // containerd socket
	"KUBE-HOSTPATH-001",          // arbitrary hostPath
	"KUBE-IMAGE-LATEST-001",      // mutable image tags
	"KUBE-PODSEC-APE-001",        // allowPrivilegeEscalation
	"KUBE-PODSEC-PROCMOUNT-001",  // procMount=Unmasked
	"KUBE-PODSEC-READONLY-001",   // readOnlyRootFilesystem
	"KUBE-PODSEC-ROOT-001",       // runAsNonRoot
	"KUBE-PODSEC-SECCOMP-001",    // seccomp profile
	"KUBE-RBAC-OVERBROAD-001",    // cluster-admin binding
}

// TestForGatekeeperReturnsEmptyForUnknownRule guards the contract that
// callers can blindly call ForGatekeeper on every finding without a
// pre-check; unknown rules return the empty string and the caller leaves
// Finding.RemediationHint.GatekeeperPolicy empty.
func TestForGatekeeperReturnsEmptyForUnknownRule(t *testing.T) {
	t.Parallel()
	got := ForGatekeeper("KUBE-DOES-NOT-EXIST-999", models.Finding{})
	if got != "" {
		t.Fatalf("expected empty string for unknown rule, got %d bytes", len(got))
	}
}

// TestForGatekeeperCoversExpectedRules asserts each rule in the coverage
// list produces a non-empty payload. Catches accidental deletions from
// gatekeeperPolicies and is the load-bearing canary for slot #18 / #19
// staying in lockstep.
func TestForGatekeeperCoversExpectedRules(t *testing.T) {
	t.Parallel()
	for _, rule := range expectedCoveredRules {
		rule := rule
		t.Run(rule, func(t *testing.T) {
			t.Parallel()
			out := ForGatekeeper(rule, models.Finding{RuleID: rule})
			if out == "" {
				t.Fatalf("ForGatekeeper(%q) returned empty string; expected a ConstraintTemplate + Constraint pair", rule)
			}
		})
	}
}

// TestForGatekeeperYAMLStructure asserts every generated payload (a) parses
// as two YAML documents, (b) the first is a ConstraintTemplate with both
// spec.crd.spec.names.kind and spec.targets[].rego populated, and (c) the
// second is a Constraint whose Kind matches the template's
// spec.crd.spec.names.kind. This is the load-bearing schema validation: a
// Gatekeeper installation will silently reject any template missing either
// field and the operator copy-paste fails opaquely.
func TestForGatekeeperYAMLStructure(t *testing.T) {
	t.Parallel()
	for _, rule := range expectedCoveredRules {
		rule := rule
		t.Run(rule, func(t *testing.T) {
			t.Parallel()
			yamlText := ForGatekeeper(rule, models.Finding{RuleID: rule})
			template, constraint := splitTwoDocs(t, yamlText)
			assertConstraintTemplate(t, rule, template)
			assertConstraintMatchesTemplate(t, rule, template, constraint)
		})
	}
}

// TestForGatekeeperHostPathRulesShareTemplate documents the intentional
// deduplication: every hostPath-family rule (KUBE-HOSTPATH-001 plus its
// four high-severity sibling rules) reuses the same ConstraintTemplate /
// Constraint pair because admission has no signal to differentiate between
// "container escape via /var/run/docker.sock" and "container escape via
// arbitrary hostPath" beyond the path string itself, and the prevention
// rule is identical.
func TestForGatekeeperHostPathRulesShareTemplate(t *testing.T) {
	t.Parallel()
	base := ForGatekeeper("KUBE-HOSTPATH-001", models.Finding{})
	for _, rule := range []string{"KUBE-ESCAPE-005", "KUBE-ESCAPE-006", "KUBE-ESCAPE-008", "KUBE-CONTAINERD-SOCKET-001"} {
		if got := ForGatekeeper(rule, models.Finding{}); got != base {
			t.Fatalf("%s should share the hostPath template body with KUBE-HOSTPATH-001; got divergent YAML", rule)
		}
	}
}

// TestForGatekeeperClusterAdminMatchKindsTargetsRBAC asserts the
// KUBE-RBAC-OVERBROAD-001 Constraint targets ClusterRoleBinding (not Pod /
// workload kinds) so it actually prevents the right thing. Easy to break
// in a copy-paste refactor.
func TestForGatekeeperClusterAdminMatchKindsTargetsRBAC(t *testing.T) {
	t.Parallel()
	yamlText := ForGatekeeper("KUBE-RBAC-OVERBROAD-001", models.Finding{})
	_, constraint := splitTwoDocs(t, yamlText)
	groups, kinds := matchKindsFromConstraint(t, constraint)
	if !containsString(groups, "rbac.authorization.k8s.io") {
		t.Fatalf("KUBE-RBAC-OVERBROAD-001 constraint missing rbac.authorization.k8s.io apiGroup; got %v", groups)
	}
	if !containsString(kinds, "ClusterRoleBinding") {
		t.Fatalf("KUBE-RBAC-OVERBROAD-001 constraint missing ClusterRoleBinding kind; got %v", kinds)
	}
}

// TestForGatekeeperPodsecRulesMatchPodWorkloads asserts each podsec
// Constraint matches at least Pod + Deployment (the two kinds the e2e
// fixture exercises). Lets us add new podsec rules without forgetting to
// list every workload-controller kind they should apply to.
func TestForGatekeeperPodsecRulesMatchPodWorkloads(t *testing.T) {
	t.Parallel()
	podsecRules := []string{
		"KUBE-ESCAPE-001", "KUBE-ESCAPE-002", "KUBE-ESCAPE-003", "KUBE-ESCAPE-004",
		"KUBE-PODSEC-APE-001", "KUBE-PODSEC-ROOT-001", "KUBE-PODSEC-READONLY-001",
		"KUBE-PODSEC-SECCOMP-001", "KUBE-PODSEC-PROCMOUNT-001",
		"KUBE-HOSTPATH-001", "KUBE-IMAGE-LATEST-001",
	}
	for _, rule := range podsecRules {
		rule := rule
		t.Run(rule, func(t *testing.T) {
			t.Parallel()
			yamlText := ForGatekeeper(rule, models.Finding{})
			_, constraint := splitTwoDocs(t, yamlText)
			_, kinds := matchKindsFromConstraint(t, constraint)
			if !containsString(kinds, "Pod") {
				t.Fatalf("%s constraint should match Pod; got %v", rule, kinds)
			}
			if !containsString(kinds, "Deployment") {
				t.Fatalf("%s constraint should match Deployment; got %v", rule, kinds)
			}
		})
	}
}

// ---- helpers ----

// splitTwoDocs splits the concatenated YAML payload at the `---` separator
// and parses both halves through yaml.v3. Fails the test if either half
// fails to parse, so a malformed quote or stray tab anywhere in the
// generator surfaces in CI rather than at copy-paste time.
func splitTwoDocs(t *testing.T, yamlText string) (templateDoc, constraintDoc map[string]any) {
	t.Helper()
	parts := strings.Split(yamlText, "\n---\n")
	if len(parts) != 2 {
		t.Fatalf("expected exactly two YAML docs separated by `---`, got %d", len(parts))
	}
	if err := yaml.Unmarshal([]byte(parts[0]), &templateDoc); err != nil {
		t.Fatalf("ConstraintTemplate doc failed to parse: %v\n----\n%s", err, parts[0])
	}
	if err := yaml.Unmarshal([]byte(parts[1]), &constraintDoc); err != nil {
		t.Fatalf("Constraint doc failed to parse: %v\n----\n%s", err, parts[1])
	}
	return templateDoc, constraintDoc
}

// assertConstraintTemplate validates the load-bearing fields of a
// ConstraintTemplate: kind, spec.crd.spec.names.kind, and at least one
// spec.targets[].rego. Gatekeeper rejects templates missing any of these
// with cryptic "no targets" / "no kind" admission errors.
func assertConstraintTemplate(t *testing.T, rule string, doc map[string]any) {
	t.Helper()
	if got, _ := doc["kind"].(string); got != "ConstraintTemplate" {
		t.Fatalf("%s: expected first doc kind=ConstraintTemplate, got %q", rule, got)
	}

	spec, ok := doc["spec"].(map[string]any)
	if !ok {
		t.Fatalf("%s: ConstraintTemplate missing spec", rule)
	}
	crd, ok := spec["crd"].(map[string]any)
	if !ok {
		t.Fatalf("%s: ConstraintTemplate missing spec.crd", rule)
	}
	crdSpec, ok := crd["spec"].(map[string]any)
	if !ok {
		t.Fatalf("%s: ConstraintTemplate missing spec.crd.spec", rule)
	}
	names, ok := crdSpec["names"].(map[string]any)
	if !ok {
		t.Fatalf("%s: ConstraintTemplate missing spec.crd.spec.names", rule)
	}
	kind, _ := names["kind"].(string)
	if kind == "" {
		t.Fatalf("%s: ConstraintTemplate missing spec.crd.spec.names.kind", rule)
	}

	targets, ok := spec["targets"].([]any)
	if !ok || len(targets) == 0 {
		t.Fatalf("%s: ConstraintTemplate missing spec.targets", rule)
	}
	for i, raw := range targets {
		target, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("%s: ConstraintTemplate spec.targets[%d] is not a map", rule, i)
		}
		rego, _ := target["rego"].(string)
		if !strings.Contains(rego, "violation") {
			t.Fatalf("%s: ConstraintTemplate spec.targets[%d].rego must declare a violation rule; got %q", rule, i, rego)
		}
		if !strings.Contains(rego, "package ") {
			t.Fatalf("%s: ConstraintTemplate spec.targets[%d].rego missing package declaration; got %q", rule, i, rego)
		}
	}
}

// assertConstraintMatchesTemplate checks the Constraint document's Kind
// equals the ConstraintTemplate's spec.crd.spec.names.kind. If the two
// drift, Gatekeeper accepts the template but rejects the Constraint with
// "no CRD" because the generated CRD's name was derived from
// names.kind and the Constraint references a non-existent CRD.
func assertConstraintMatchesTemplate(t *testing.T, rule string, template, constraint map[string]any) {
	t.Helper()
	templateKind := dig(t, template, "spec", "crd", "spec", "names", "kind").(string)
	constraintKind, _ := constraint["kind"].(string)
	if templateKind != constraintKind {
		t.Fatalf("%s: Constraint kind %q must equal ConstraintTemplate spec.crd.spec.names.kind %q", rule, constraintKind, templateKind)
	}
	apiVersion, _ := constraint["apiVersion"].(string)
	if !strings.HasPrefix(apiVersion, "constraints.gatekeeper.sh/") {
		t.Fatalf("%s: Constraint apiVersion must be under constraints.gatekeeper.sh/*; got %q", rule, apiVersion)
	}
	enforcement := dig(t, constraint, "spec", "enforcementAction")
	if enforcement != "deny" {
		t.Fatalf("%s: Constraint spec.enforcementAction must be \"deny\"; got %v", rule, enforcement)
	}
}

// matchKindsFromConstraint flattens the constraint's spec.match.kinds entries
// into a single (apiGroups, kinds) pair for assertion.
func matchKindsFromConstraint(t *testing.T, constraint map[string]any) (apiGroups, kinds []string) {
	t.Helper()
	matchSlice, ok := dig(t, constraint, "spec", "match", "kinds").([]any)
	if !ok {
		t.Fatalf("Constraint spec.match.kinds is not a list")
	}
	for _, raw := range matchSlice {
		entry, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("spec.match.kinds entry is not a map: %v", raw)
		}
		for _, g := range entry["apiGroups"].([]any) {
			apiGroups = append(apiGroups, g.(string))
		}
		for _, k := range entry["kinds"].([]any) {
			kinds = append(kinds, k.(string))
		}
	}
	return apiGroups, kinds
}

// dig walks a nested map[string]any by string keys and fails the test if
// any intermediate key is missing. Saves the per-field "ok, exists" dance.
func dig(t *testing.T, root map[string]any, keys ...string) any {
	t.Helper()
	cur := any(root)
	for i, key := range keys {
		m, ok := cur.(map[string]any)
		if !ok {
			t.Fatalf("dig: expected map at depth %d (key %q), got %T", i, key, cur)
		}
		cur, ok = m[key]
		if !ok {
			t.Fatalf("dig: missing key %q at depth %d", key, i)
		}
	}
	return cur
}

// containsString returns true when needle is in haystack.
func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
