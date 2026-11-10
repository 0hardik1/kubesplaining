// Package overlay applies Kubernetes manifests on top of a snapshot in memory.
// The result is the cluster state as it would be after the change, so the
// analyzers can answer "does this RoleBinding open an attack path?" or "does
// this fix close the path?" before anyone changes the cluster.
//
// An overlay object replaces the snapshot object that has the same kind,
// namespace, and name, or is added when there is none. That is what
// `kubectl apply` does with a complete manifest. A delete removes one object.
//
// The overlay handles the kinds that the privilege-escalation graph reads
// directly: Role, ClusterRole, RoleBinding, ClusterRoleBinding, ServiceAccount,
// Namespace, and Pod. Other kinds are skipped with a warning. A workload kind
// (a Deployment, for example) is skipped on purpose: in a cluster, its
// controller creates the pods, and an overlay has no controller, so a new
// Deployment would add no pod for the graph to see.
package overlay

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// Options says what to change.
type Options struct {
	// Paths are manifest files or directories. A directory is read recursively
	// for .yaml, .yml, and .json files. "-" reads Stdin, which lets a rendered
	// chart be piped in.
	Paths []string
	// Deletes are objects to remove, each as Kind/name for a cluster-scoped kind
	// or Kind/namespace/name for a namespaced kind.
	Deletes []string
	// DefaultNamespace is the namespace of a namespaced object that has no
	// metadata.namespace. Without it, such an object is an error: the tool cannot
	// know which namespace `kubectl apply` would use.
	DefaultNamespace string
	// Stdin is read when Paths has "-".
	Stdin io.Reader
}

// Empty reports whether the options change nothing.
func (o Options) Empty() bool {
	return len(o.Paths) == 0 && len(o.Deletes) == 0
}

// Result says what Apply did.
type Result struct {
	// Added, Replaced, and Deleted hold the objects in Kind/[namespace/]name form.
	Added    []string
	Replaced []string
	Deleted  []string
	// Warnings are things the caller must show: skipped kinds, skipped
	// documents, and aggregated roles that could not be derived again.
	Warnings []string
}

// Summary is one line that counts the changes.
func (r Result) Summary() string {
	return fmt.Sprintf("%d added, %d replaced, %d deleted", len(r.Added), len(r.Replaced), len(r.Deleted))
}

const rbacGroupPrefix = "rbac.authorization.k8s.io/"

// Apply returns a copy of snapshot with the overlay applied. It does not change
// snapshot, so a caller can compare the two.
//
// Manifests are applied first, then deletes. After a change to any ClusterRole,
// the rules of each aggregated ClusterRole are derived again (see reaggregate).
func Apply(snapshot models.Snapshot, opts Options) (models.Snapshot, Result, error) {
	out := snapshot
	res := &out.Resources
	// Clone each list that Apply can change, so the caller's snapshot keeps its
	// own backing arrays.
	res.Roles = slices.Clone(res.Roles)
	res.ClusterRoles = slices.Clone(res.ClusterRoles)
	res.RoleBindings = slices.Clone(res.RoleBindings)
	res.ClusterRoleBindings = slices.Clone(res.ClusterRoleBindings)
	res.ServiceAccounts = slices.Clone(res.ServiceAccounts)
	res.Namespaces = slices.Clone(res.Namespaces)
	res.Pods = slices.Clone(res.Pods)

	a := &applier{opts: opts, res: res, skippedKinds: map[string]int{}, touchedClusterRoles: map[string]bool{}}
	derivable := derivableAggregates(res.ClusterRoles)

	objects, err := readObjects(opts, &a.result)
	if err != nil {
		return models.Snapshot{}, Result{}, err
	}
	for _, object := range objects {
		if err := a.apply(object); err != nil {
			return models.Snapshot{}, Result{}, err
		}
	}
	for _, value := range opts.Deletes {
		if err := a.delete(value); err != nil {
			return models.Snapshot{}, Result{}, err
		}
	}

	if len(a.skippedKinds) > 0 {
		kinds := make([]string, 0, len(a.skippedKinds))
		for kind, count := range a.skippedKinds {
			kinds = append(kinds, fmt.Sprintf("%s (%d)", kind, count))
		}
		sort.Strings(kinds)
		a.result.Warnings = append(a.result.Warnings, fmt.Sprintf(
			"The overlay skipped these kinds: %s. It applies Role, ClusterRole, RoleBinding, ClusterRoleBinding, ServiceAccount, Namespace, and Pod. A workload such as a Deployment adds no pod here, because no controller runs.",
			strings.Join(kinds, ", ")))
	}

	if len(a.touchedClusterRoles) > 0 {
		a.result.Warnings = append(a.result.Warnings, reaggregate(res.ClusterRoles, derivable, a.touchedClusterRoles)...)
	}

	return out, a.result, nil
}

// rawObject is one decoded manifest document and where it came from.
type rawObject struct {
	source string
	fields map[string]any
}

// readObjects reads each path in opts and returns the objects in order.
func readObjects(opts Options, result *Result) ([]rawObject, error) {
	var objects []rawObject
	for _, path := range opts.Paths {
		if path == "-" {
			if opts.Stdin == nil {
				return nil, errors.New("overlay: \"-\" reads standard input, and none is available")
			}
			data, err := io.ReadAll(opts.Stdin)
			if err != nil {
				return nil, fmt.Errorf("overlay: read standard input: %w", err)
			}
			decoded, err := decodeObjects("standard input", data, result)
			if err != nil {
				return nil, err
			}
			objects = append(objects, decoded...)
			continue
		}

		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("overlay: %w", err)
		}
		files := []string{path}
		if info.IsDir() {
			files, err = manifestFiles(path)
			if err != nil {
				return nil, err
			}
			if len(files) == 0 {
				return nil, fmt.Errorf("overlay: directory %s has no .yaml, .yml, or .json file", path)
			}
		}
		for _, file := range files {
			data, err := os.ReadFile(file)
			if err != nil {
				return nil, fmt.Errorf("overlay: %w", err)
			}
			decoded, err := decodeObjects(file, data, result)
			if err != nil {
				return nil, err
			}
			objects = append(objects, decoded...)
		}
	}
	return objects, nil
}

// manifestFiles lists the manifest files under dir in lexical order.
func manifestFiles(dir string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".yaml", ".yml", ".json":
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("overlay: %w", err)
	}
	return files, nil
}

// decodeObjects splits data into documents and flattens List kinds. A document
// with no kind (a Helm values file, for example) is skipped with a warning.
func decodeObjects(source string, data []byte, result *Result) ([]rawObject, error) {
	var objects []rawObject
	noKind := 0
	decoder := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
	for {
		var fields map[string]any
		if err := decoder.Decode(&fields); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("overlay: decode %s: %w (a Helm or Kustomize source must be rendered first, for example with `helm template`)", source, err)
		}
		if len(fields) == 0 {
			continue
		}
		kind, _ := fields["kind"].(string)
		if kind == "" {
			noKind++
			continue
		}
		if items, ok := fields["items"].([]any); ok && strings.HasSuffix(kind, "List") {
			for _, item := range items {
				if itemFields, ok := item.(map[string]any); ok {
					objects = append(objects, rawObject{source: source, fields: itemFields})
				}
			}
			continue
		}
		objects = append(objects, rawObject{source: source, fields: fields})
	}
	if noKind > 0 {
		result.Warnings = append(result.Warnings, fmt.Sprintf("The overlay skipped %d document(s) in %s that have no kind.", noKind, source))
	}
	return objects, nil
}

// applier holds the state of one Apply call.
type applier struct {
	opts                Options
	res                 *models.SnapshotResources
	result              Result
	skippedKinds        map[string]int
	touchedClusterRoles map[string]bool
}

// apply adds or replaces one object.
func (a *applier) apply(object rawObject) error {
	kind, _ := object.fields["kind"].(string)
	apiVersion, _ := object.fields["apiVersion"].(string)
	isRBAC := strings.HasPrefix(apiVersion, rbacGroupPrefix)
	isCore := apiVersion == "v1"

	switch {
	case kind == "ClusterRole" && isRBAC:
		var obj rbacv1.ClusterRole
		if err := decodeInto(object, &obj); err != nil {
			return err
		}
		if err := requireName(object, obj.Name); err != nil {
			return err
		}
		a.touchedClusterRoles[obj.Name] = true
		a.res.ClusterRoles = upsert(a, a.res.ClusterRoles, obj, objectKey(kind, "", obj.Name), func(o rbacv1.ClusterRole) bool { return o.Name == obj.Name })
	case kind == "ClusterRoleBinding" && isRBAC:
		var obj rbacv1.ClusterRoleBinding
		if err := decodeInto(object, &obj); err != nil {
			return err
		}
		if err := requireName(object, obj.Name); err != nil {
			return err
		}
		a.res.ClusterRoleBindings = upsert(a, a.res.ClusterRoleBindings, obj, objectKey(kind, "", obj.Name), func(o rbacv1.ClusterRoleBinding) bool { return o.Name == obj.Name })
	case kind == "Role" && isRBAC:
		var obj rbacv1.Role
		if err := decodeInto(object, &obj); err != nil {
			return err
		}
		if err := a.setNamespace(object, obj.Name, &obj.Namespace); err != nil {
			return err
		}
		a.res.Roles = upsert(a, a.res.Roles, obj, objectKey(kind, obj.Namespace, obj.Name), func(o rbacv1.Role) bool { return o.Namespace == obj.Namespace && o.Name == obj.Name })
	case kind == "RoleBinding" && isRBAC:
		var obj rbacv1.RoleBinding
		if err := decodeInto(object, &obj); err != nil {
			return err
		}
		if err := a.setNamespace(object, obj.Name, &obj.Namespace); err != nil {
			return err
		}
		a.res.RoleBindings = upsert(a, a.res.RoleBindings, obj, objectKey(kind, obj.Namespace, obj.Name), func(o rbacv1.RoleBinding) bool { return o.Namespace == obj.Namespace && o.Name == obj.Name })
	case kind == "ServiceAccount" && isCore:
		var obj corev1.ServiceAccount
		if err := decodeInto(object, &obj); err != nil {
			return err
		}
		if err := a.setNamespace(object, obj.Name, &obj.Namespace); err != nil {
			return err
		}
		a.res.ServiceAccounts = upsert(a, a.res.ServiceAccounts, obj, objectKey(kind, obj.Namespace, obj.Name), func(o corev1.ServiceAccount) bool { return o.Namespace == obj.Namespace && o.Name == obj.Name })
	case kind == "Pod" && isCore:
		var obj corev1.Pod
		if err := decodeInto(object, &obj); err != nil {
			return err
		}
		if err := a.setNamespace(object, obj.Name, &obj.Namespace); err != nil {
			return err
		}
		a.res.Pods = upsert(a, a.res.Pods, obj, objectKey(kind, obj.Namespace, obj.Name), func(o corev1.Pod) bool { return o.Namespace == obj.Namespace && o.Name == obj.Name })
	case kind == "Namespace" && isCore:
		var obj corev1.Namespace
		if err := decodeInto(object, &obj); err != nil {
			return err
		}
		if err := requireName(object, obj.Name); err != nil {
			return err
		}
		a.res.Namespaces = upsert(a, a.res.Namespaces, obj, objectKey(kind, "", obj.Name), func(o corev1.Namespace) bool { return o.Name == obj.Name })
	default:
		a.skippedKinds[kind]++
	}
	return nil
}

func decodeInto(object rawObject, target any) error {
	payload, err := json.Marshal(object.fields)
	if err != nil {
		return fmt.Errorf("overlay: %s: %w", object.source, err)
	}
	if err := json.Unmarshal(payload, target); err != nil {
		kind, _ := object.fields["kind"].(string)
		return fmt.Errorf("overlay: %s: %s is not valid: %w", object.source, kind, err)
	}
	return nil
}

func requireName(object rawObject, name string) error {
	if name == "" {
		kind, _ := object.fields["kind"].(string)
		return fmt.Errorf("overlay: %s: a %s has no metadata.name", object.source, kind)
	}
	return nil
}

// setNamespace fills the namespace of a namespaced object from DefaultNamespace
// when the manifest has none.
func (a *applier) setNamespace(object rawObject, name string, namespace *string) error {
	if err := requireName(object, name); err != nil {
		return err
	}
	if *namespace != "" {
		return nil
	}
	if a.opts.DefaultNamespace == "" {
		kind, _ := object.fields["kind"].(string)
		return fmt.Errorf("overlay: %s: %s/%s has no metadata.namespace. Set it in the manifest, or pass --overlay-namespace to give the namespace that `kubectl apply -n` would use", object.source, kind, name)
	}
	*namespace = a.opts.DefaultNamespace
	return nil
}

// upsert replaces the item that same matches, or appends obj, and records which
// of the two it did.
func upsert[T any](a *applier, items []T, obj T, key string, same func(T) bool) []T {
	for i := range items {
		if same(items[i]) {
			items[i] = obj
			a.result.Replaced = append(a.result.Replaced, key)
			return items
		}
	}
	a.result.Added = append(a.result.Added, key)
	return append(items, obj)
}

// objectKey prints Kind/[namespace/]name.
func objectKey(kind, namespace, name string) string {
	if namespace == "" {
		return kind + "/" + name
	}
	return kind + "/" + namespace + "/" + name
}

// deletableKinds maps the lower-case kind a user types to the kind and to
// whether it is namespaced. Namespace is not in the list: a namespace delete
// removes each object in it, and the overlay does not model that.
var deletableKinds = map[string]struct {
	kind       string
	namespaced bool
}{
	"clusterrole":        {"ClusterRole", false},
	"clusterrolebinding": {"ClusterRoleBinding", false},
	"role":               {"Role", true},
	"rolebinding":        {"RoleBinding", true},
	"serviceaccount":     {"ServiceAccount", true},
	"sa":                 {"ServiceAccount", true},
	"pod":                {"Pod", true},
}

// delete removes the one object that value names. An object that is not there
// is an error: a delete with a wrong name would otherwise look like a fix that
// changed nothing.
func (a *applier) delete(value string) error {
	parts := strings.Split(strings.TrimSpace(value), "/")
	const forms = "use Kind/name for a ClusterRole or a ClusterRoleBinding, and Kind/namespace/name for a Role, a RoleBinding, a ServiceAccount, or a Pod"
	if len(parts) < 2 || len(parts) > 3 || slices.Contains(parts, "") {
		return fmt.Errorf("overlay: invalid --overlay-delete %q: %s", value, forms)
	}
	entry, ok := deletableKinds[strings.ToLower(parts[0])]
	if !ok {
		return fmt.Errorf("overlay: invalid --overlay-delete %q: the kind %q cannot be deleted; %s", value, parts[0], forms)
	}

	var namespace, name string
	switch {
	case !entry.namespaced && len(parts) == 2:
		name = parts[1]
	case entry.namespaced && len(parts) == 3:
		namespace, name = parts[1], parts[2]
	case entry.namespaced && len(parts) == 2 && a.opts.DefaultNamespace != "":
		namespace, name = a.opts.DefaultNamespace, parts[1]
	case entry.namespaced:
		return fmt.Errorf("overlay: invalid --overlay-delete %q: a %s needs a namespace (%s/<namespace>/%s)", value, entry.kind, entry.kind, parts[1])
	default:
		return fmt.Errorf("overlay: invalid --overlay-delete %q: a %s has no namespace (%s/%s)", value, entry.kind, entry.kind, parts[len(parts)-1])
	}

	removed := false
	switch entry.kind {
	case "ClusterRole":
		a.res.ClusterRoles, removed = remove(a.res.ClusterRoles, func(o rbacv1.ClusterRole) bool { return o.Name == name })
		a.touchedClusterRoles[name] = true
	case "ClusterRoleBinding":
		a.res.ClusterRoleBindings, removed = remove(a.res.ClusterRoleBindings, func(o rbacv1.ClusterRoleBinding) bool { return o.Name == name })
	case "Role":
		a.res.Roles, removed = remove(a.res.Roles, func(o rbacv1.Role) bool { return o.Namespace == namespace && o.Name == name })
	case "RoleBinding":
		a.res.RoleBindings, removed = remove(a.res.RoleBindings, func(o rbacv1.RoleBinding) bool { return o.Namespace == namespace && o.Name == name })
	case "ServiceAccount":
		a.res.ServiceAccounts, removed = remove(a.res.ServiceAccounts, func(o corev1.ServiceAccount) bool { return o.Namespace == namespace && o.Name == name })
	case "Pod":
		a.res.Pods, removed = remove(a.res.Pods, func(o corev1.Pod) bool { return o.Namespace == namespace && o.Name == name })
	}
	key := objectKey(entry.kind, namespace, name)
	if !removed {
		return fmt.Errorf("overlay: cannot delete %s: no such object in the snapshot", key)
	}
	a.result.Deleted = append(a.result.Deleted, key)
	return nil
}

// remove drops the first item that match accepts.
func remove[T any](items []T, match func(T) bool) ([]T, bool) {
	for i := range items {
		if match(items[i]) {
			return slices.Delete(items, i, i+1), true
		}
	}
	return items, false
}

// derivableAggregates returns the names of the aggregated ClusterRoles whose
// rules in the snapshot are exactly what deriveRules gives for them. For those
// roles, deriving the rules again after a change gives what the API server
// would give.
//
// A role fails this test when the snapshot does not hold every role it
// aggregates from, or when the cluster aggregates in a way this package does
// not model. Deriving such a role again would drop rules that it really has, and
// an attack path would then seem to close when it does not.
func derivableAggregates(roles []rbacv1.ClusterRole) map[string]bool {
	derivable := map[string]bool{}
	for i := range roles {
		if roles[i].AggregationRule == nil {
			continue
		}
		if sameRuleSet(roles[i].Rules, deriveRules(roles, i)) {
			derivable[roles[i].Name] = true
		}
	}
	return derivable
}

// reaggregate derives the rules of each aggregated ClusterRole again, and
// repeats until nothing changes, because an aggregated role can feed a second
// one (edit feeds admin).
//
// The API server copies rules into a role such as `admin` from each ClusterRole
// that carries a matching aggregation label. A snapshot holds the result of that
// copy. An overlay that adds, changes, or deletes a labeled ClusterRole does not
// redo the copy, so without this step the tool can answer "no new path" for a
// change that adds one.
//
// A role is derived again when it was derivable before the change, or when the
// overlay itself supplied it. Each other aggregated role keeps its rules, and a
// warning names it.
func reaggregate(roles []rbacv1.ClusterRole, derivable, touched map[string]bool) []string {
	var warnings []string
	eligible := make([]bool, len(roles))
	for i := range roles {
		if roles[i].AggregationRule == nil {
			continue
		}
		if derivable[roles[i].Name] || touched[roles[i].Name] {
			eligible[i] = true
			continue
		}
		warnings = append(warnings, fmt.Sprintf(
			"ClusterRole %s is an aggregated role, and the roles in the snapshot do not explain its rules. The overlay left its rules as they are, so a change to a role that it aggregates is not in the result.",
			roles[i].Name))
	}

	// One pass can change a role that an earlier role in the list reads, so
	// repeat. The pass count has a limit so that two roles that select each
	// other cannot loop without end.
	for pass := 0; pass <= len(roles); pass++ {
		changed := false
		for i := range roles {
			if !eligible[i] {
				continue
			}
			rules := deriveRules(roles, i)
			if !sameRuleSet(roles[i].Rules, rules) {
				roles[i].Rules = rules
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	return warnings
}

// deriveRules returns the union of the rules of each ClusterRole that the
// aggregation rule of roles[index] selects, in role-name order and without
// duplicates. This is what the cluster role aggregation controller writes.
func deriveRules(roles []rbacv1.ClusterRole, index int) []rbacv1.PolicyRule {
	aggregate := &roles[index]
	selectors := make([]labels.Selector, 0, len(aggregate.AggregationRule.ClusterRoleSelectors))
	for i := range aggregate.AggregationRule.ClusterRoleSelectors {
		selector, err := metav1.LabelSelectorAsSelector(&aggregate.AggregationRule.ClusterRoleSelectors[i])
		if err != nil {
			continue
		}
		selectors = append(selectors, selector)
	}

	order := make([]int, 0, len(roles))
	for i := range roles {
		if i != index {
			order = append(order, i)
		}
	}
	sort.SliceStable(order, func(a, b int) bool { return roles[order[a]].Name < roles[order[b]].Name })

	rules := []rbacv1.PolicyRule{}
	for _, i := range order {
		selected := false
		for _, selector := range selectors {
			if selector.Matches(labels.Set(roles[i].Labels)) {
				selected = true
				break
			}
		}
		if !selected {
			continue
		}
		for _, rule := range roles[i].Rules {
			if !containsRule(rules, rule) {
				rules = append(rules, rule)
			}
		}
	}
	return rules
}

func containsRule(rules []rbacv1.PolicyRule, rule rbacv1.PolicyRule) bool {
	for i := range rules {
		if apiequality.Semantic.DeepEqual(rules[i], rule) {
			return true
		}
	}
	return false
}

// sameRuleSet reports whether a and b hold the same rules in any order.
func sameRuleSet(a, b []rbacv1.PolicyRule) bool {
	for _, rule := range a {
		if !containsRule(b, rule) {
			return false
		}
	}
	for _, rule := range b {
		if !containsRule(a, rule) {
			return false
		}
	}
	return true
}
