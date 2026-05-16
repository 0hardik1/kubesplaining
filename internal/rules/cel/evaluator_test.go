package cel

import (
	"path/filepath"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestEvaluateEmptyRulesReturnsNoFindings(t *testing.T) {
	t.Parallel()
	got, err := Evaluate(nil, models.Snapshot{})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected no findings, got %d", len(got))
	}
}

func TestEvaluateFlagsResourceWhenExpressionIsTrue(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeRule(t, dir, "default-ns.cel.yaml", `
id: CUSTOM-DEFAULT-NS
title: Workload in default namespace
severity: medium
description: workloads should not be deployed to the default namespace
remediation: move the workload to a dedicated namespace
match:
  kinds: [Pod]
expression: resource.metadata.namespace == "default"
`)
	rules, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}

	snap := snapshotWithPods(
		pod("a", "default"),
		pod("b", "team-x"),
		pod("c", "default"),
	)

	findings, err := Evaluate(rules, snap)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %+v", len(findings), findings)
	}
	for _, f := range findings {
		if f.RuleID != "CUSTOM-DEFAULT-NS" {
			t.Errorf("RuleID = %q, want CUSTOM-DEFAULT-NS", f.RuleID)
		}
		if f.Resource == nil || f.Resource.Kind != "Pod" {
			t.Errorf("expected Pod resource, got %+v", f.Resource)
		}
	}
}

func TestEvaluateMatchKindsFiltersResources(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeRule(t, dir, "pods-only.cel.yaml", `
id: CUSTOM-PODS-ONLY
title: All pods are suspect
severity: low
match:
  kinds: [Pod]
expression: "true"
`)
	rules, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}

	snap := snapshotWithPods(pod("p", "ns1"))
	snap.Resources.Namespaces = []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "ns1"}}}

	findings, err := Evaluate(rules, snap)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (Pod only), got %d", len(findings))
	}
	if findings[0].Resource.Kind != "Pod" {
		t.Errorf("expected Pod, got %q", findings[0].Resource.Kind)
	}
}

func TestEvaluateMatchNamespacesFiltersResources(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeRule(t, dir, "ns-filter.cel.yaml", `
id: CUSTOM-NS-FILTER
title: NS filter
severity: low
match:
  namespaces: [prod]
expression: "true"
`)
	rules, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	snap := snapshotWithPods(pod("a", "dev"), pod("b", "prod"), pod("c", "staging"))

	findings, err := Evaluate(rules, snap)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Namespace != "prod" {
		t.Errorf("expected prod ns, got %q", findings[0].Namespace)
	}
}

func TestEvaluateExposesSnapshotVariable(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeRule(t, dir, "many-pods.cel.yaml", `
id: CUSTOM-MANY-PODS
title: More than 1 pod
severity: low
match:
  kinds: [Namespace]
expression: size(snapshot.resources.pods) > 1
`)
	rules, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}

	snap := snapshotWithPods(pod("a", "x"), pod("b", "y"))
	snap.Resources.Namespaces = []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "x"}}}

	findings, err := Evaluate(rules, snap)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (snapshot.resources.pods has 2 entries), got %d", len(findings))
	}
}

func TestEvaluateGracefullySkipsMalformedResources(t *testing.T) {
	t.Parallel()

	// This rule indexes into a field that doesn't exist on some resources
	// (containers on a Namespace). The evaluator must continue past the
	// error, not propagate it.
	dir := t.TempDir()
	writeRule(t, dir, "rough.cel.yaml", `
id: CUSTOM-ROUGH
title: Anything with containers
severity: low
expression: has(resource.spec.containers)
`)
	rules, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}

	snap := snapshotWithPods(pod("p", "x"))
	snap.Resources.Namespaces = []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "x"}}}

	findings, err := Evaluate(rules, snap)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Resource.Kind != "Pod" {
		t.Errorf("expected Pod, got %q", findings[0].Resource.Kind)
	}
}

func TestEvaluateFindingIDIsDeterministic(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeRule(t, dir, "ok.cel.yaml", `
id: CUSTOM-DET
title: matched
severity: medium
match:
  kinds: [Pod]
expression: "true"
`)
	rules, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}

	snap := snapshotWithPods(pod("foo", "team"))

	a, err := Evaluate(rules, snap)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Evaluate(rules, snap)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("expected exactly 1 finding both times, got %d / %d", len(a), len(b))
	}
	if a[0].ID != b[0].ID {
		t.Errorf("Finding.ID not deterministic: %q vs %q", a[0].ID, b[0].ID)
	}
	if a[0].ID != "CUSTOM-DET:Pod:team:foo" {
		t.Errorf("Finding.ID = %q, want CUSTOM-DET:Pod:team:foo", a[0].ID)
	}
}

func TestFlattenSnapshotSortsByKindNamespaceName(t *testing.T) {
	t.Parallel()

	snap := snapshotWithPods(pod("b", "ns2"), pod("a", "ns2"), pod("z", "ns1"))
	entries, err := flattenSnapshot(snap)
	if err != nil {
		t.Fatalf("flattenSnapshot: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	wantOrder := []string{"ns1/z", "ns2/a", "ns2/b"}
	for i, want := range wantOrder {
		got := entries[i].Namespace + "/" + entries[i].Name
		if got != want {
			t.Errorf("entry[%d] = %q, want %q", i, got, want)
		}
	}
}

func TestRuleSourceTagPointsAtSourceFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "my.cel.yaml")
	writeRule(t, dir, "my.cel.yaml", validRule("CUSTOM-SRC"))

	rules, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	snap := snapshotWithPods(pod("p", "x"))
	findings, err := Evaluate(rules, snap)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	want := "rule_source:" + path
	got := findings[0].Tags
	found := false
	for _, tag := range got {
		if tag == want {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected tag %q, got %v", want, got)
	}
}

// helpers

func pod(name, namespace string) corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "main", Image: "nginx"}},
		},
	}
}

func snapshotWithPods(pods ...corev1.Pod) models.Snapshot {
	return models.Snapshot{
		Resources: models.SnapshotResources{
			Pods: pods,
		},
	}
}
