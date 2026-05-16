package cel

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"

	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/scoring"
)

// resourceEntry is the per-instance unit the evaluator feeds to each rule. We
// pre-flatten the Snapshot into a single slice of these so a rule with no
// `match.kinds` constraint can iterate "everything" without each rule
// re-walking the Snapshot structure. Kind / Namespace / Name come from
// metadata at flatten-time so we can match against them without poking through
// the raw object map.
type resourceEntry struct {
	Kind      string
	APIGroup  string
	Namespace string
	Name      string
	Object    map[string]any
}

// Evaluate runs every loaded Rule against snapshot and returns one Finding per
// (rule, matched resource). Empty rules → empty findings, nil error.
//
// The evaluator does the iteration so each rule's CEL Program just answers
// "true / false for this resource"; this keeps rule files small and means
// expressions cannot accidentally access state from previous evaluations.
//
// Snapshot is serialized to a map[string]any exactly once and reused as the
// `snapshot` CEL variable across every rule × resource pair so the JSON round
// trip is paid once, not once per evaluation.
func Evaluate(rules []Rule, snapshot models.Snapshot) ([]models.Finding, error) {
	if len(rules) == 0 {
		return nil, nil
	}

	snapshotMap, err := toMap(snapshot)
	if err != nil {
		return nil, fmt.Errorf("custom rules: snapshot serialize: %w", err)
	}

	entries, err := flattenSnapshot(snapshot)
	if err != nil {
		return nil, fmt.Errorf("custom rules: flatten snapshot: %w", err)
	}

	findings := make([]models.Finding, 0)
	for _, rule := range rules {
		ruleFindings, err := evaluateRule(rule, entries, snapshotMap)
		if err != nil {
			return nil, err
		}
		findings = append(findings, ruleFindings...)
	}
	return findings, nil
}

// evaluateRule applies one Rule to the entire (pre-filtered by match) entry
// set. Returning the slice rather than appending to a shared one keeps the
// per-rule branch independently testable (`evaluator_test.go`).
func evaluateRule(rule Rule, entries []resourceEntry, snapshotMap map[string]any) ([]models.Finding, error) {
	out := make([]models.Finding, 0)
	for _, entry := range entries {
		if !ruleMatches(rule.Match, entry) {
			continue
		}
		input := map[string]any{
			"resource": entry.Object,
			"snapshot": snapshotMap,
		}
		val, _, err := rule.Program.Eval(input)
		if err != nil {
			// One bad resource (e.g. a field a rule expected isn't present)
			// should not poison the whole evaluation. Skip and continue.
			continue
		}
		matched, ok := val.Value().(bool)
		if !ok || !matched {
			continue
		}
		out = append(out, buildFinding(rule, entry))
	}
	return out, nil
}

// ruleMatches checks the Kind / Namespace allow-lists. An empty list on either
// axis is interpreted as "match anything" so the simple case ("flag every Pod
// with X") is a one-line `match.kinds: [Pod]` and the simpler case ("flag
// anything matching the expression") needs no match block at all.
func ruleMatches(m Match, entry resourceEntry) bool {
	if len(m.Kinds) > 0 && !slices.Contains(m.Kinds, entry.Kind) {
		return false
	}
	if len(m.Namespaces) > 0 && !slices.Contains(m.Namespaces, entry.Namespace) {
		return false
	}
	return true
}

// buildFinding constructs a models.Finding for one (rule, entry) match. The ID
// is deterministic so re-running the analyzer against an unchanged snapshot
// yields the same Finding.ID, which keeps baseline diff and exclusions stable
// across runs.
//
// Tags include the source filename so an operator browsing the report can tell
// which rules file produced the finding (e.g. when a vendored rules pack and
// an in-house rules pack are both loaded).
func buildFinding(rule Rule, entry resourceEntry) models.Finding {
	resourceKey := fmt.Sprintf("%s:%s:%s", entry.Kind, entry.Namespace, entry.Name)
	if entry.Namespace == "" {
		resourceKey = fmt.Sprintf("%s:%s", entry.Kind, entry.Name)
	}
	id := fmt.Sprintf("%s:%s", rule.ID, resourceKey)

	evidence, _ := json.Marshal(map[string]any{
		"matched_resource": map[string]string{
			"kind":      entry.Kind,
			"name":      entry.Name,
			"namespace": entry.Namespace,
			"apiGroup":  entry.APIGroup,
		},
		"rule_source": rule.Path,
	})

	return models.Finding{
		ID:          id,
		RuleID:      rule.ID,
		Severity:    rule.Severity,
		Score:       scoreFromSeverity(rule.Severity),
		Category:    rule.Category,
		Title:       rule.Title,
		Description: rule.Description,
		Resource: &models.ResourceRef{
			Kind:      entry.Kind,
			Name:      entry.Name,
			Namespace: entry.Namespace,
			APIGroup:  entry.APIGroup,
		},
		Namespace:   entry.Namespace,
		Evidence:    evidence,
		Remediation: rule.Remediation,
		Tags: []string{
			"module:custom-rules",
			"rule_source:" + rule.Path,
		},
	}
}

// scoreFromSeverity derives a representative score for a custom rule from its
// declared severity bucket. We pick the lower bound of the bucket so the
// finding sits next to other findings of the same severity in the report's
// score-ordered listing rather than always sorting last (Score=0). Operators
// who need a finer-grained score can override the rule's severity to one bucket
// higher or lower.
func scoreFromSeverity(s models.Severity) float64 {
	return scoring.MinScoreForSeverity(s)
}

// flattenSnapshot converts the typed Snapshot into a flat slice of
// resourceEntry. We add every collected workload-like resource (pods,
// deployments, ...) plus a representative subset of cluster-scoped ones
// (namespaces, nodes, cluster roles). Anything missing here can still be
// reached via the `snapshot` variable; only the *iteration* axis is fixed.
//
// The metadata reads use JSON round-trip via toMap so we don't have to repeat
// the `metadata.name` / `metadata.namespace` extraction logic per Kind.
func flattenSnapshot(snapshot models.Snapshot) ([]resourceEntry, error) {
	entries := make([]resourceEntry, 0)

	addAll := func(kind, apiGroup string, items []any) error {
		for _, item := range items {
			obj, err := toMap(item)
			if err != nil {
				return err
			}
			name, namespace := metaNameNamespace(obj)
			entries = append(entries, resourceEntry{
				Kind:      kind,
				APIGroup:  apiGroup,
				Namespace: namespace,
				Name:      name,
				Object:    obj,
			})
		}
		return nil
	}

	if err := addAll("Pod", "", asAny(snapshot.Resources.Pods)); err != nil {
		return nil, err
	}
	if err := addAll("Deployment", "apps", asAny(snapshot.Resources.Deployments)); err != nil {
		return nil, err
	}
	if err := addAll("DaemonSet", "apps", asAny(snapshot.Resources.DaemonSets)); err != nil {
		return nil, err
	}
	if err := addAll("StatefulSet", "apps", asAny(snapshot.Resources.StatefulSets)); err != nil {
		return nil, err
	}
	if err := addAll("Job", "batch", asAny(snapshot.Resources.Jobs)); err != nil {
		return nil, err
	}
	if err := addAll("CronJob", "batch", asAny(snapshot.Resources.CronJobs)); err != nil {
		return nil, err
	}
	if err := addAll("ServiceAccount", "", asAny(snapshot.Resources.ServiceAccounts)); err != nil {
		return nil, err
	}
	if err := addAll("Service", "", asAny(snapshot.Resources.Services)); err != nil {
		return nil, err
	}
	if err := addAll("Namespace", "", asAny(snapshot.Resources.Namespaces)); err != nil {
		return nil, err
	}
	if err := addAll("Node", "", asAny(snapshot.Resources.Nodes)); err != nil {
		return nil, err
	}
	if err := addAll("Role", "rbac.authorization.k8s.io", asAny(snapshot.Resources.Roles)); err != nil {
		return nil, err
	}
	if err := addAll("ClusterRole", "rbac.authorization.k8s.io", asAny(snapshot.Resources.ClusterRoles)); err != nil {
		return nil, err
	}
	if err := addAll("RoleBinding", "rbac.authorization.k8s.io", asAny(snapshot.Resources.RoleBindings)); err != nil {
		return nil, err
	}
	if err := addAll("ClusterRoleBinding", "rbac.authorization.k8s.io", asAny(snapshot.Resources.ClusterRoleBindings)); err != nil {
		return nil, err
	}
	if err := addAll("NetworkPolicy", "networking.k8s.io", asAny(snapshot.Resources.NetworkPolicies)); err != nil {
		return nil, err
	}
	if err := addAll("ConfigMap", "", asAny(snapshot.Resources.ConfigMaps)); err != nil {
		return nil, err
	}
	if err := addAll("Secret", "", asAny(snapshot.Resources.SecretsMetadata)); err != nil {
		return nil, err
	}

	// Stable ordering: sort by Kind, then Namespace, then Name so test
	// assertions can rely on the output. Sorting once after flatten is cheaper
	// than maintaining per-Kind ordering during insert.
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Kind != entries[j].Kind {
			return entries[i].Kind < entries[j].Kind
		}
		if entries[i].Namespace != entries[j].Namespace {
			return entries[i].Namespace < entries[j].Namespace
		}
		return entries[i].Name < entries[j].Name
	})

	return entries, nil
}

// asAny converts a typed slice to []any so addAll can iterate without
// generics gymnastics. The cost is one allocation per Kind, which is dwarfed
// by the per-entry JSON round trip.
func asAny[T any](items []T) []any {
	out := make([]any, len(items))
	for i := range items {
		out[i] = items[i]
	}
	return out
}

// toMap renders any Snapshot-derived value as a generic map[string]any via
// JSON. CEL's DynType happily indexes into nested maps and slices, which means
// every field a Kubernetes object exposes via its JSON tags is reachable from
// a rule expression without us having to declare types.
func toMap(value any) (map[string]any, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// metaNameNamespace reads metadata.name and metadata.namespace from the
// already-marshaled object. Most Snapshot types use the upstream
// `metav1.ObjectMeta` which JSON-tags as `metadata`, so this is uniform across
// Pods, Deployments, etc. The collector's lightweight types (SecretMetadata,
// ConfigMapSnapshot) tag name/namespace directly at the top level, so we
// check both shapes.
func metaNameNamespace(obj map[string]any) (string, string) {
	if obj == nil {
		return "", ""
	}
	if meta, ok := obj["metadata"].(map[string]any); ok {
		return strField(meta, "name"), strField(meta, "namespace")
	}
	return strField(obj, "name"), strField(obj, "namespace")
}

// strField returns the string-valued field at key, or "" if it's missing or
// the wrong type. CEL-evaluated rules treat missing fields as null, so the
// same defensive default is fine here.
func strField(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}
