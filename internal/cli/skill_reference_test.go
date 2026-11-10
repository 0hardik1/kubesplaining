package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

const skillDir = "../../plugins/kubesplaining/skills/attack-paths"

// The agent skill explains each target and each hop action to an agent that
// reads `paths` output. This test fails when the graph builder gets an action
// that the skill does not explain, or when the skill explains one that is gone,
// so the two lists cannot drift apart.
func TestSkillReferenceMatchesTheGraph(t *testing.T) {
	t.Parallel()

	reference := readSkillFile(t, "references/reference.md")

	sources, err := filepath.Glob("../analyzer/privesc/*.go")
	if err != nil || len(sources) == 0 {
		t.Fatalf("no privesc sources found (err=%v)", err)
	}
	actionInCode := regexp.MustCompile(`Action:\s+"([a-z_]+)"`)
	inCode := map[string]bool{}
	for _, source := range sources {
		if strings.HasSuffix(source, "_test.go") {
			continue
		}
		content, err := os.ReadFile(source)
		if err != nil {
			t.Fatalf("read %s: %v", source, err)
		}
		for _, match := range actionInCode.FindAllStringSubmatch(string(content), -1) {
			inCode[match[1]] = true
		}
	}
	if len(inCode) < 20 {
		t.Fatalf("found only %d actions in the privesc sources, so the pattern no longer matches how edges are written", len(inCode))
	}

	_, actionTables, found := strings.Cut(reference, "## Hop actions")
	if !found {
		t.Fatal("reference.md has no \"## Hop actions\" section")
	}
	actionInDoc := regexp.MustCompile("(?m)^\\| `([a-z_]+)` \\|")
	inDoc := map[string]bool{}
	for _, match := range actionInDoc.FindAllStringSubmatch(actionTables, -1) {
		inDoc[match[1]] = true
	}

	for _, action := range sortedKeys(inCode) {
		if !inDoc[action] {
			t.Errorf("the graph builder emits the action %q, and reference.md does not explain it", action)
		}
	}
	for _, action := range sortedKeys(inDoc) {
		if !inCode[action] {
			t.Errorf("reference.md explains the action %q, and the graph builder does not emit it", action)
		}
	}

	// Each target, in the form --to accepts and in the form JSON output has.
	skill := readSkillFile(t, "SKILL.md")
	for _, target := range pathTargets {
		for _, name := range []string{targetName(target), string(target)} {
			if !strings.Contains(reference, "`"+name) {
				t.Errorf("reference.md does not list the target %q", name)
			}
		}
		if !strings.Contains(skill, "`"+targetName(target)) {
			t.Errorf("SKILL.md does not list the target %q for --to", targetName(target))
		}
	}
}

// The limits of the Agent Skills format that a reader can check without a tool:
// the name equals the directory name, the description has 1024 characters or
// less, and the file has less than 500 lines.
func TestSkillFileFollowsTheFormat(t *testing.T) {
	t.Parallel()

	skill := readSkillFile(t, "SKILL.md")
	rest, found := strings.CutPrefix(skill, "---\n")
	if !found {
		t.Fatal("SKILL.md must start with YAML frontmatter")
	}
	frontmatter, body, found := strings.Cut(rest, "\n---\n")
	if !found {
		t.Fatal("SKILL.md frontmatter has no closing line")
	}

	fields := map[string]string{}
	for _, line := range strings.Split(frontmatter, "\n") {
		if key, value, ok := strings.Cut(line, ": "); ok && !strings.HasPrefix(line, " ") {
			fields[key] = value
		}
	}
	if got, want := fields["name"], filepath.Base(skillDir); got != want {
		t.Errorf("name = %q, want the directory name %q", got, want)
	}
	if n := len(fields["description"]); n == 0 || n > 1024 {
		t.Errorf("description has %d characters, want 1 to 1024", n)
	}
	if n := len(fields["compatibility"]); n > 500 {
		t.Errorf("compatibility has %d characters, want 500 or less", n)
	}
	if lines := strings.Count(skill, "\n"); lines >= 500 {
		t.Errorf("SKILL.md has %d lines, want less than 500", lines)
	}
	// Each command that the skill tells an agent to run must exist.
	for _, command := range []string{"kubesplaining paths", "kubesplaining download", "kubesplaining scan-resource", "kubesplaining scan "} {
		if !strings.Contains(body, command) {
			t.Errorf("SKILL.md no longer mentions %q", command)
		}
	}
	root := NewRootCmd(BuildInfo{})
	for _, name := range []string{"paths", "download", "scan-resource", "scan"} {
		if found, _, err := root.Find([]string{name}); err != nil || found.Name() != name {
			t.Errorf("SKILL.md tells the agent to run %q, and the CLI has no such command", name)
		}
	}
	// Each flag that the skill uses with paths must exist on the command.
	paths := NewPathsCmd(BuildInfo{})
	for _, flag := range []string{"input-file", "from", "to", "verbose", "output-format", "limit"} {
		if !strings.Contains(body, "--"+flag) {
			t.Errorf("SKILL.md no longer mentions --%s", flag)
		}
		if paths.Flags().Lookup(flag) == nil {
			t.Errorf("SKILL.md uses --%s, and paths has no such flag", flag)
		}
	}
}

func readSkillFile(t *testing.T, name string) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(skillDir, name))
	if err != nil {
		t.Fatalf("read skill file: %v", err)
	}
	return string(content)
}

func sortedKeys(set map[string]bool) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
