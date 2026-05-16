package cel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
)

func TestLoadDirReturnsEmptyOnEmptyPath(t *testing.T) {
	t.Parallel()

	rules, err := LoadDir("")
	if err != nil {
		t.Fatalf("LoadDir(\"\"): %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("expected no rules, got %d", len(rules))
	}
}

func TestLoadDirErrorsOnMissingDirectory(t *testing.T) {
	t.Parallel()

	_, err := LoadDir(filepath.Join(t.TempDir(), "missing"))
	if err == nil {
		t.Fatal("expected error for missing directory")
	}
}

func TestLoadDirErrorsWhenPathIsFile(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "a.cel.yaml")
	if err := os.WriteFile(path, []byte("id: x"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadDir(path)
	if err == nil {
		t.Fatal("expected error when path is a file")
	}
	if !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("expected 'not a directory' error, got %v", err)
	}
}

func TestLoadDirLoadsValidRule(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeRule(t, dir, "ok.cel.yaml", `
id: CUSTOM-OK-001
title: Forbid foo
severity: high
description: pods named foo are not allowed
remediation: rename the pod
match:
  kinds: [Pod]
expression: resource.metadata.name == "foo"
`)

	rules, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	got := rules[0]
	if got.ID != "CUSTOM-OK-001" {
		t.Errorf("ID = %q, want CUSTOM-OK-001", got.ID)
	}
	if got.Severity != models.SeverityHigh {
		t.Errorf("Severity = %q, want HIGH", got.Severity)
	}
	if got.Program == nil {
		t.Error("Program is nil; expected compiled CEL program")
	}
	if !equalStringSlice(got.Match.Kinds, []string{"Pod"}) {
		t.Errorf("Match.Kinds = %v, want [Pod]", got.Match.Kinds)
	}
}

func TestLoadDirSortsByFilename(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeRule(t, dir, "b.cel.yaml", validRule("CUSTOM-B"))
	writeRule(t, dir, "a.cel.yaml", validRule("CUSTOM-A"))

	rules, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}
	if rules[0].ID != "CUSTOM-A" || rules[1].ID != "CUSTOM-B" {
		t.Errorf("expected [A,B] ordering, got [%s,%s]", rules[0].ID, rules[1].ID)
	}
}

func TestLoadDirIgnoresUnrelatedFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeRule(t, dir, "ok.cel.yaml", validRule("CUSTOM-OK"))
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("not a rule"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "policy.yaml"), []byte("kind: Something"), 0o644); err != nil {
		t.Fatal(err)
	}

	rules, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
}

func TestLoadDirAcceptsYmlExtension(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeRule(t, dir, "ok.cel.yml", validRule("CUSTOM-YML"))

	rules, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule loaded from .cel.yml, got %d", len(rules))
	}
}

func TestLoadDirRejectsDuplicateRuleID(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeRule(t, dir, "first.cel.yaml", validRule("CUSTOM-DUP"))
	writeRule(t, dir, "second.cel.yaml", validRule("CUSTOM-DUP"))

	_, err := LoadDir(dir)
	if err == nil {
		t.Fatal("expected duplicate id error")
	}
	if !strings.Contains(err.Error(), "defined twice") {
		t.Errorf("expected duplicate-id error, got %v", err)
	}
}

func TestLoadDirRejectsMissingFields(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		yaml string
		want string
	}{
		{"missing id", "title: x\nseverity: high\nexpression: \"true\"", "missing id"},
		{"missing title", "id: X\nseverity: high\nexpression: \"true\"", "missing title"},
		{"missing expression", "id: X\ntitle: x\nseverity: high", "missing expression"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			writeRule(t, dir, "bad.cel.yaml", tc.yaml)
			_, err := LoadDir(dir)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want substring %q", err, tc.want)
			}
		})
	}
}

func TestLoadDirRejectsBadSeverity(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeRule(t, dir, "bad.cel.yaml", `
id: CUSTOM-BAD
title: x
severity: extreme
expression: "true"
`)
	_, err := LoadDir(dir)
	if err == nil {
		t.Fatal("expected severity error")
	}
}

func TestLoadDirRejectsNonBoolExpression(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeRule(t, dir, "bad.cel.yaml", `
id: CUSTOM-BAD
title: x
severity: high
expression: resource.metadata.name
`)
	_, err := LoadDir(dir)
	if err == nil {
		t.Fatal("expected non-bool error")
	}
	if !strings.Contains(err.Error(), "must return bool") {
		t.Errorf("error = %q, want substring 'must return bool'", err)
	}
}

func TestLoadDirRejectsCompileError(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeRule(t, dir, "bad.cel.yaml", `
id: CUSTOM-BAD
title: x
severity: high
expression: this is not CEL
`)
	_, err := LoadDir(dir)
	if err == nil {
		t.Fatal("expected compile error")
	}
}

func TestParseCategoryFallsBackToDefenseEvasion(t *testing.T) {
	t.Parallel()
	if parseCategory("") != models.CategoryDefenseEvasion {
		t.Errorf("empty category should default to defense_evasion")
	}
	if parseCategory("nonsense") != models.CategoryDefenseEvasion {
		t.Errorf("unknown category should default to defense_evasion")
	}
	if parseCategory("privilege_escalation") != models.CategoryPrivilegeEscalation {
		t.Errorf("known category should be parsed")
	}
}

// helpers

func writeRule(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func validRule(id string) string {
	return `
id: ` + id + `
title: example
severity: medium
description: example rule
remediation: do the thing
expression: "true"
`
}

func equalStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
