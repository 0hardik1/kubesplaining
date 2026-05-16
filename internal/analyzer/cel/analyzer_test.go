package cel

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestAnalyzerNameIsCustomRules(t *testing.T) {
	t.Parallel()
	if got := New("").Name(); got != "custom-rules" {
		t.Errorf("Name() = %q, want custom-rules", got)
	}
}

func TestAnalyzerEmptyDirReturnsNoFindings(t *testing.T) {
	t.Parallel()
	a := New("")
	got, err := a.Analyze(context.Background(), models.Snapshot{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no findings, got %d", len(got))
	}
}

func TestAnalyzerLoadErrorSurfacedOnAnalyze(t *testing.T) {
	t.Parallel()
	a := New(filepath.Join(t.TempDir(), "does-not-exist"))
	_, err := a.Analyze(context.Background(), models.Snapshot{})
	if err == nil {
		t.Fatal("expected load error on Analyze")
	}
}

func TestAnalyzerFiresAgainstSnapshot(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	body := `
id: CUSTOM-DEFAULT-NS
title: Workload in default namespace
severity: medium
match:
  kinds: [Pod]
expression: resource.metadata.namespace == "default"
`
	if err := os.WriteFile(filepath.Join(dir, "rule.cel.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	a := New(dir)
	snap := models.Snapshot{
		Resources: models.SnapshotResources{
			Pods: []corev1.Pod{
				{ObjectMeta: metav1.ObjectMeta{Name: "p1", Namespace: "default"}},
				{ObjectMeta: metav1.ObjectMeta{Name: "p2", Namespace: "team-x"}},
			},
		},
	}
	got, err := a.Analyze(context.Background(), snap)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got[0].RuleID != "CUSTOM-DEFAULT-NS" {
		t.Errorf("RuleID = %q", got[0].RuleID)
	}
}
