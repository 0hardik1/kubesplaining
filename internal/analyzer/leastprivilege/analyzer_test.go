package leastprivilege

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/usage"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// observation is one (subject, apiGroup, resource, verbs) tuple - the input to
// makeIndexCombined which materializes a tiny audit log on disk and loads it through the
// real usage parser. Going through the parser keeps the test honest about
// keep()/SubjectFromUsername edge cases without needing access to UsageIndex internals.
type observation struct {
	subj     models.SubjectRef
	apiGroup string
	resource string
	verbs    []string
}

// makeIndexCombined writes a single JSONL audit log containing every observation, then
// loads it through the public usage.LoadAuditLog path. Each call uses its own temp dir
// so tests don't share state.
func makeIndexCombined(t *testing.T, obs []observation) *usage.UsageIndex {
	t.Helper()
	now := time.Now().UTC()
	recent := now.Add(-1 * time.Hour).Format(time.RFC3339)
	var b strings.Builder
	for _, o := range obs {
		for _, v := range o.verbs {
			b.WriteString(`{"verb":"`)
			b.WriteString(v)
			b.WriteString(`","user":{"username":"system:serviceaccount:`)
			b.WriteString(o.subj.Namespace)
			b.WriteString(`:`)
			b.WriteString(o.subj.Name)
			b.WriteString(`"},"objectRef":{"apiGroup":"`)
			b.WriteString(o.apiGroup)
			b.WriteString(`","resource":"`)
			b.WriteString(o.resource)
			b.WriteString(`"},"responseStatus":{"code":200},"requestReceivedTimestamp":"`)
			b.WriteString(recent)
			b.WriteString(`"}` + "\n")
		}
	}
	path := t.TempDir() + "/audit.log"
	f, err := osCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(b.String()); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	idx, _, err := usage.LoadAuditLog([]string{path}, usage.SourceNative, 30*24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	return idx
}

// snapshotWithBinding builds the smallest snapshot that the analyzer needs: one Role,
// one binding, one ServiceAccount, optionally one mounted Pod.
func snapshotWithBinding(roleName, ns, saName string, rules []rbacv1.PolicyRule, mounted bool) models.Snapshot {
	snap := models.Snapshot{}
	snap.Resources.Roles = []rbacv1.Role{{
		ObjectMeta: metav1.ObjectMeta{Name: roleName, Namespace: ns},
		Rules:      rules,
	}}
	snap.Resources.RoleBindings = []rbacv1.RoleBinding{{
		ObjectMeta: metav1.ObjectMeta{Name: roleName + "-bind", Namespace: ns},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: saName, Namespace: ns}},
		RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: roleName},
	}}
	snap.Resources.ServiceAccounts = []corev1.ServiceAccount{{
		ObjectMeta: metav1.ObjectMeta{Name: saName, Namespace: ns},
	}}
	if mounted {
		snap.Resources.Pods = []corev1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: saName + "-pod", Namespace: ns},
			Spec:       corev1.PodSpec{ServiceAccountName: saName},
		}}
	}
	return snap
}

// TestUnusedVerb_PartialUsage covers the bread-and-butter case: a Role grants
// [get, list, create, delete] on pods, the SA only ever did get + list, expect
// KUBE-RBAC-UNUSED-VERB-001 with the unused verbs in evidence.
func TestUnusedVerb_PartialUsage(t *testing.T) {
	subj := models.SubjectRef{Kind: "ServiceAccount", Namespace: "default", Name: "builder"}
	rules := []rbacv1.PolicyRule{{
		APIGroups: []string{""},
		Resources: []string{"pods"},
		Verbs:     []string{"get", "list", "create", "delete"},
	}}
	snap := snapshotWithBinding("pod-manager", "default", "builder", rules, true)

	idx := makeIndexCombined(t, []observation{
		{subj: subj, apiGroup: "", resource: "pods", verbs: []string{"get", "list"}},
	})

	got, err := New(idx).Analyze(context.Background(), snap)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d (%+v)", len(got), ruleIDs(got))
	}
	if got[0].RuleID != "KUBE-RBAC-UNUSED-VERB-001" {
		t.Errorf("RuleID = %s, want KUBE-RBAC-UNUSED-VERB-001", got[0].RuleID)
	}
	if !strings.Contains(got[0].Description, "create") || !strings.Contains(got[0].Description, "delete") {
		t.Errorf("Description should call out unused verbs `create` and `delete`; got: %s", got[0].Description)
	}
	// Suggested replacement YAML rides on Evidence (not RemediationSteps) so the renderer
	// can place it in a proper code block.
	if !strings.Contains(string(got[0].Evidence), "suggested_role_yaml") {
		t.Errorf("expected suggested_role_yaml in evidence; got: %s", string(got[0].Evidence))
	}
	if !strings.Contains(string(got[0].Evidence), "pod-manager") {
		t.Errorf("expected role name in suggested YAML; got: %s", string(got[0].Evidence))
	}
}

// TestUnusedRole_WholeRoleDead covers the strongest signal: zero observed events for a
// mounted SA. Expect KUBE-RBAC-UNUSED-ROLE-001.
func TestUnusedRole_WholeRoleDead(t *testing.T) {
	rules := []rbacv1.PolicyRule{{
		APIGroups: []string{""},
		Resources: []string{"secrets"},
		Verbs:     []string{"get"},
	}}
	snap := snapshotWithBinding("secrets-reader", "default", "ghost", rules, true)

	// Index built with an unrelated SA's events - `ghost` has nothing.
	other := models.SubjectRef{Kind: "ServiceAccount", Namespace: "default", Name: "someone-else"}
	idx := makeIndexCombined(t, []observation{
		{subj: other, apiGroup: "", resource: "pods", verbs: []string{"get"}},
	})

	got, err := New(idx).Analyze(context.Background(), snap)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(got) != 1 || got[0].RuleID != "KUBE-RBAC-UNUSED-ROLE-001" {
		t.Fatalf("expected one KUBE-RBAC-UNUSED-ROLE-001, got %+v", ruleIDs(got))
	}
}

// TestUnusedRole_OnlyWhenMounted ensures we don't emit an "unused role" finding for a
// SA that no Pod references - that's a different concern handled by the rbac module's
// stale-binding rule, and emitting both would be noise.
func TestUnusedRole_OnlyWhenMounted(t *testing.T) {
	rules := []rbacv1.PolicyRule{{
		APIGroups: []string{""},
		Resources: []string{"secrets"},
		Verbs:     []string{"get"},
	}}
	snap := snapshotWithBinding("secrets-reader", "default", "ghost", rules, false)

	idx := makeIndexCombined(t, nil)
	got, err := New(idx).Analyze(context.Background(), snap)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected no findings for unmounted SA, got %+v", ruleIDs(got))
	}
}

// TestWildcardNarrowing covers verbs: ["*"] on a coordinate where the subject only
// observed a few verbs. Expect KUBE-RBAC-WILDCARD-USED-PARTIAL-001 with a concrete
// narrowed-Role YAML snippet.
func TestWildcardNarrowing(t *testing.T) {
	subj := models.SubjectRef{Kind: "ServiceAccount", Namespace: "default", Name: "wildcard-user"}
	rules := []rbacv1.PolicyRule{{
		APIGroups: []string{""},
		Resources: []string{"configmaps"},
		Verbs:     []string{"*"},
	}}
	snap := snapshotWithBinding("cm-wild", "default", "wildcard-user", rules, true)

	idx := makeIndexCombined(t, []observation{
		{subj: subj, apiGroup: "", resource: "configmaps", verbs: []string{"get", "list"}},
	})

	got, err := New(idx).Analyze(context.Background(), snap)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(got) != 1 || got[0].RuleID != "KUBE-RBAC-WILDCARD-USED-PARTIAL-001" {
		t.Fatalf("expected KUBE-RBAC-WILDCARD-USED-PARTIAL-001, got %+v", ruleIDs(got))
	}
	// Suggested replacement YAML rides on Evidence (not RemediationSteps). The evidence
	// payload JSON-escapes the inner quotes, so check for the escaped form.
	if !strings.Contains(string(got[0].Evidence), `\"get\", \"list\"`) {
		t.Errorf("expected suggested YAML with observed verbs in evidence, got: %s", string(got[0].Evidence))
	}
}

// TestNilIndex_NoFindings ensures the module is a no-op when the operator hasn't
// supplied audit data. CLI pre-flight handles the --least-privilege-only case;
// elsewhere we silently produce nothing.
func TestNilIndex_NoFindings(t *testing.T) {
	rules := []rbacv1.PolicyRule{{
		APIGroups: []string{""},
		Resources: []string{"pods"},
		Verbs:     []string{"get"},
	}}
	snap := snapshotWithBinding("pod-reader", "default", "builder", rules, true)
	got, err := New(nil).Analyze(context.Background(), snap)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("nil index should produce no findings, got %+v", ruleIDs(got))
	}
}

func ruleIDs(fs []models.Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.RuleID
	}
	return out
}
