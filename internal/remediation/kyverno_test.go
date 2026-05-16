package remediation

import (
	"strings"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
	"gopkg.in/yaml.v3"
)

// coveredRules is the canonical list of rule IDs the Kyverno generator is expected to
// know about. If you add a new entry to kyvernoPolicyByRuleID, add it here too; the
// TestForKyvernoCoverage test below uses this list to assert there is no drift between
// the documented coverage (slot #18 plan + CLAUDE.md) and the actual map.
var coveredRules = []string{
	// podsec: privileged / host namespaces
	"KUBE-ESCAPE-001",
	"KUBE-ESCAPE-002",
	"KUBE-ESCAPE-003",
	"KUBE-ESCAPE-004",
	// podsec: hostPath family
	"KUBE-HOSTPATH-001",
	"KUBE-ESCAPE-005",
	"KUBE-ESCAPE-006",
	"KUBE-ESCAPE-008",
	"KUBE-CONTAINERD-SOCKET-001",
	// podsec: SecurityContext hardening
	"KUBE-PODSEC-APE-001",
	"KUBE-PODSEC-ROOT-001",
	"KUBE-PODSEC-READONLY-001",
	"KUBE-PODSEC-SECCOMP-001",
	"KUBE-PODSEC-PROCMOUNT-001",
	// podsec: image
	"KUBE-IMAGE-LATEST-001",
	// rbac
	"KUBE-RBAC-OVERBROAD-001",
}

func TestForKyvernoCoverage(t *testing.T) {
	t.Parallel()

	for _, ruleID := range coveredRules {
		policy := ForKyverno(ruleID, models.Finding{RuleID: ruleID})
		if policy == "" {
			t.Errorf("ForKyverno(%q) returned empty string; expected a ClusterPolicy", ruleID)
		}
	}

	// And the reverse: every entry in the map should be in coveredRules. Catches the
	// case where someone adds a policy without updating documentation.
	covered := make(map[string]struct{}, len(coveredRules))
	for _, ruleID := range coveredRules {
		covered[ruleID] = struct{}{}
	}
	for ruleID := range kyvernoPolicyByRuleID {
		if _, ok := covered[ruleID]; !ok {
			t.Errorf("kyvernoPolicyByRuleID has entry %q not listed in coveredRules", ruleID)
		}
	}
}

func TestForKyvernoUnknownRule(t *testing.T) {
	t.Parallel()

	got := ForKyverno("KUBE-PRIVESC-PATH-CLUSTER-ADMIN", models.Finding{RuleID: "KUBE-PRIVESC-PATH-CLUSTER-ADMIN"})
	if got != "" {
		t.Errorf("ForKyverno for an unmapped rule should return \"\", got %q", got)
	}

	got = ForKyverno("", models.Finding{})
	if got != "" {
		t.Errorf("ForKyverno for empty rule ID should return \"\", got %q", got)
	}
}

// TestKyvernoPoliciesParse asserts every generated policy is well-formed YAML and
// parses into the minimal shape Kyverno expects (apiVersion / kind / metadata.name /
// spec.rules[].validate). This is the closest we can get to a kubectl-dry-run
// without bringing in the Kyverno schema as a Go dep.
func TestKyvernoPoliciesParse(t *testing.T) {
	t.Parallel()

	for _, ruleID := range coveredRules {
		ruleID := ruleID
		t.Run(ruleID, func(t *testing.T) {
			t.Parallel()
			raw := ForKyverno(ruleID, models.Finding{RuleID: ruleID})
			if raw == "" {
				t.Fatalf("no policy for %s", ruleID)
			}

			var policy kyvernoClusterPolicy
			if err := yaml.Unmarshal([]byte(raw), &policy); err != nil {
				t.Fatalf("yaml.Unmarshal failed for %s: %v\n---\n%s", ruleID, err, raw)
			}

			if policy.APIVersion != "kyverno.io/v1" {
				t.Errorf("%s: apiVersion = %q, want kyverno.io/v1", ruleID, policy.APIVersion)
			}
			if policy.Kind != "ClusterPolicy" {
				t.Errorf("%s: kind = %q, want ClusterPolicy", ruleID, policy.Kind)
			}
			if policy.Metadata.Name == "" {
				t.Errorf("%s: metadata.name is empty", ruleID)
			}
			if policy.Spec.ValidationFailureAction != "enforce" {
				t.Errorf("%s: spec.validationFailureAction = %q, want enforce", ruleID, policy.Spec.ValidationFailureAction)
			}
			if len(policy.Spec.Rules) == 0 {
				t.Fatalf("%s: spec.rules is empty", ruleID)
			}
			for i, rule := range policy.Spec.Rules {
				if rule.Name == "" {
					t.Errorf("%s: spec.rules[%d].name is empty", ruleID, i)
				}
				if rule.Validate == nil {
					t.Errorf("%s: spec.rules[%d].validate is missing; the plan requires validate (not mutate)", ruleID, i)
					continue
				}
				if rule.Validate.Message == "" {
					t.Errorf("%s: spec.rules[%d].validate.message is empty", ruleID, i)
				}
				if rule.Validate.Pattern == nil && rule.Validate.AnyPattern == nil {
					t.Errorf("%s: spec.rules[%d].validate has neither pattern nor anyPattern", ruleID, i)
				}
				if rule.Match.Any == nil {
					t.Errorf("%s: spec.rules[%d].match.any is missing", ruleID, i)
				}
			}
		})
	}
}

// TestKyvernoPolicyAnnotatesRuleID — every policy's description should mention the
// originating rule ID so a Kyverno admin who finds the policy in their cluster can
// trace it back to a kubesplaining finding without grepping our source.
func TestKyvernoPolicyAnnotatesRuleID(t *testing.T) {
	t.Parallel()

	for _, ruleID := range coveredRules {
		raw := ForKyverno(ruleID, models.Finding{RuleID: ruleID})
		if !strings.Contains(raw, ruleID) {
			t.Errorf("policy for %s does not mention the rule ID in its annotations / description", ruleID)
		}
	}
}

// TestKyvernoExcludesSystemNamespaces — every pod-targeting policy must exclude
// kube-system (and friends), otherwise applying the policy bricks the cluster's
// own control plane components that legitimately use hostNetwork / hostPath etc.
func TestKyvernoExcludesSystemNamespaces(t *testing.T) {
	t.Parallel()

	// Pod-targeting rule IDs (everything except the RBAC policy which targets
	// ClusterRoleBindings, not Pods).
	podRuleIDs := []string{}
	for _, ruleID := range coveredRules {
		if ruleID == "KUBE-RBAC-OVERBROAD-001" {
			continue
		}
		podRuleIDs = append(podRuleIDs, ruleID)
	}

	for _, ruleID := range podRuleIDs {
		raw := ForKyverno(ruleID, models.Finding{RuleID: ruleID})
		if !strings.Contains(raw, "kube-system") {
			t.Errorf("policy for %s does not exclude kube-system; will break the control plane on apply", ruleID)
		}
	}
}

// kyvernoClusterPolicy is the minimal Kyverno schema we need to assert the generated
// YAML is shaped right. Kept here (not exported) because it's a test-only shape.
type kyvernoClusterPolicy struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name        string            `yaml:"name"`
		Annotations map[string]string `yaml:"annotations"`
	} `yaml:"metadata"`
	Spec struct {
		ValidationFailureAction string             `yaml:"validationFailureAction"`
		Background              bool               `yaml:"background"`
		FailurePolicy           string             `yaml:"failurePolicy"`
		Rules                   []kyvernoRuleShape `yaml:"rules"`
	} `yaml:"spec"`
}

type kyvernoRuleShape struct {
	Name  string `yaml:"name"`
	Match struct {
		Any []map[string]any `yaml:"any"`
	} `yaml:"match"`
	Exclude struct {
		Any []map[string]any `yaml:"any"`
	} `yaml:"exclude"`
	Validate *struct {
		Message    string `yaml:"message"`
		Pattern    any    `yaml:"pattern"`
		AnyPattern any    `yaml:"anyPattern"`
	} `yaml:"validate"`
}
