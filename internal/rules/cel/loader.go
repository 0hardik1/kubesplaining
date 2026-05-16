package cel

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
	celgo "github.com/google/cel-go/cel"
	"gopkg.in/yaml.v3"
)

// ruleFile is the on-disk representation of a single *.cel.yaml rule. The
// frontmatter mirrors the shape of a Finding (id, title, severity, description,
// remediation) so report consumers see a structurally identical finding whether
// the rule shipped with the tool or with the operator. The Match block scopes
// which snapshot resources the Expression is evaluated against; an empty
// Match.Kinds means "every workload-like resource in the snapshot".
type ruleFile struct {
	ID          string      `yaml:"id"`
	Title       string      `yaml:"title"`
	Severity    string      `yaml:"severity"`
	Description string      `yaml:"description"`
	Remediation string      `yaml:"remediation"`
	Category    string      `yaml:"category,omitempty"`
	Match       matchConfig `yaml:"match"`
	Expression  string      `yaml:"expression"`
}

// matchConfig narrows the resource set a rule's expression is invoked against.
// Both lists are case-sensitive Kubernetes Kinds / namespace names. Empty lists
// mean "all of that axis". The evaluator handles the filtering; the loader only
// records the configuration.
type matchConfig struct {
	Kinds      []string `yaml:"kinds,omitempty"`
	Namespaces []string `yaml:"namespaces,omitempty"`
}

// Rule is a loaded, compiled custom rule ready for evaluation. The compiled
// CEL program is cached on the Rule so the evaluator can fan out across
// resources without recompiling. Path is the source file the rule was loaded
// from, preserved for error messages and dedupe.
type Rule struct {
	ID          string
	Title       string
	Severity    models.Severity
	Description string
	Remediation string
	Category    models.RiskCategory
	Match       Match
	Program     celgo.Program
	Source      string
	Path        string
}

// Match is the loader's parsed view of matchConfig: an Allow-list-style filter
// the evaluator consults before evaluating a rule against a resource.
type Match struct {
	Kinds      []string
	Namespaces []string
}

// LoadDir walks dir (non-recursively) and loads every *.cel.yaml file into a
// compiled Rule. Returns an empty slice (and nil error) when dir == "" so
// callers can disable custom rules by leaving the flag unset. Returns an error
// for any unreadable file, malformed YAML, missing required field, unsupported
// severity, or CEL compilation failure: a single bad rule fails the whole load
// so operators get an immediate signal rather than a silently-skipped rule.
//
// File order is deterministic (sorted by filename) so two runs against the
// same directory produce findings in the same order.
func LoadDir(dir string) ([]Rule, error) {
	if dir == "" {
		return nil, nil
	}

	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("custom rules: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("custom rules: %q is not a directory", dir)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("custom rules: %w", err)
	}

	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".cel.yaml") && !strings.HasSuffix(name, ".cel.yml") {
			continue
		}
		paths = append(paths, filepath.Join(dir, name))
	}
	sort.Strings(paths)

	env, err := newEnv()
	if err != nil {
		return nil, fmt.Errorf("custom rules: build CEL env: %w", err)
	}

	rules := make([]Rule, 0, len(paths))
	seen := map[string]string{}
	for _, path := range paths {
		rule, err := loadFile(env, path)
		if err != nil {
			return nil, err
		}
		if prev, dup := seen[rule.ID]; dup {
			return nil, fmt.Errorf("custom rules: rule id %q defined twice (%s and %s)", rule.ID, prev, path)
		}
		seen[rule.ID] = path
		rules = append(rules, rule)
	}
	return rules, nil
}

// loadFile is the per-file half of LoadDir: read YAML, validate, compile CEL.
// Splitting it out keeps the LoadDir loop readable and lets the unit tests
// exercise per-file errors without juggling temporary directories.
func loadFile(env *celgo.Env, path string) (Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Rule{}, fmt.Errorf("custom rules: read %s: %w", path, err)
	}

	var rf ruleFile
	if err := yaml.Unmarshal(data, &rf); err != nil {
		return Rule{}, fmt.Errorf("custom rules: parse %s: %w", path, err)
	}

	rf.ID = strings.TrimSpace(rf.ID)
	rf.Title = strings.TrimSpace(rf.Title)
	rf.Expression = strings.TrimSpace(rf.Expression)

	if rf.ID == "" {
		return Rule{}, fmt.Errorf("custom rules: %s missing id", path)
	}
	if rf.Title == "" {
		return Rule{}, fmt.Errorf("custom rules: %s missing title", path)
	}
	if rf.Expression == "" {
		return Rule{}, fmt.Errorf("custom rules: %s missing expression", path)
	}

	severity, err := models.ParseSeverity(rf.Severity)
	if err != nil {
		return Rule{}, fmt.Errorf("custom rules: %s: %w", path, err)
	}

	category := parseCategory(rf.Category)

	ast, issues := env.Compile(rf.Expression)
	if issues != nil && issues.Err() != nil {
		return Rule{}, fmt.Errorf("custom rules: %s: compile: %w", path, issues.Err())
	}

	// Insist the expression evaluates to a bool. Otherwise an operator who
	// accidentally writes `resource.metadata.name` (a string) would silently
	// match nothing instead of getting an error at load time.
	if ast.OutputType() != celgo.BoolType {
		return Rule{}, fmt.Errorf("custom rules: %s: expression must return bool, got %s", path, ast.OutputType())
	}

	program, err := env.Program(ast)
	if err != nil {
		return Rule{}, fmt.Errorf("custom rules: %s: program: %w", path, err)
	}

	return Rule{
		ID:          rf.ID,
		Title:       rf.Title,
		Severity:    severity,
		Description: rf.Description,
		Remediation: rf.Remediation,
		Category:    category,
		Match: Match{
			Kinds:      rf.Match.Kinds,
			Namespaces: rf.Match.Namespaces,
		},
		Program: program,
		Source:  rf.Expression,
		Path:    path,
	}, nil
}

// parseCategory maps the YAML category string to a models.RiskCategory.
// Unknown / empty inputs fall through to CategoryDefenseEvasion, which is the
// least specific bucket and the most neutral default for "I wrote a custom
// rule and forgot to set this".
func parseCategory(s string) models.RiskCategory {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "privilege_escalation":
		return models.CategoryPrivilegeEscalation
	case "data_exfiltration":
		return models.CategoryDataExfiltration
	case "lateral_movement":
		return models.CategoryLateralMovement
	case "infrastructure_modification":
		return models.CategoryInfrastructureModification
	case "defense_evasion", "":
		return models.CategoryDefenseEvasion
	default:
		return models.CategoryDefenseEvasion
	}
}

// newEnv builds the CEL environment shared by every loaded rule. Two variables
// are exposed: `resource` (the per-iteration object) and `snapshot` (the whole
// Snapshot). Both are typed as DynType so the operator can drill into nested
// fields by JSON path (`resource.spec.containers[0].image`) without us having
// to declare every K8s schema field.
//
// The default stdlib (cel.StdLib via NewEnv default options) brings in
// string ops, size(), `in`, list/map helpers, etc. — enough for the kind of
// rule the README aims at.
func newEnv() (*celgo.Env, error) {
	return celgo.NewEnv(
		celgo.Variable("resource", celgo.DynType),
		celgo.Variable("snapshot", celgo.DynType),
	)
}
