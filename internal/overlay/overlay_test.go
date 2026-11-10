package overlay

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/0hardik1/kubesplaining/internal/models"
)

func meta(name, namespace string) metav1.ObjectMeta {
	return metav1.ObjectMeta{Name: name, Namespace: namespace}
}

var readPods = rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list"}}
var readSecrets = rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get", "list"}}

// baseSnapshot has one of each kind the overlay handles.
func baseSnapshot() models.Snapshot {
	snapshot := models.Snapshot{}
	snapshot.Resources.Namespaces = []corev1.Namespace{{ObjectMeta: meta("dev", "")}}
	snapshot.Resources.ServiceAccounts = []corev1.ServiceAccount{{ObjectMeta: meta("ci", "dev")}}
	snapshot.Resources.Pods = []corev1.Pod{{ObjectMeta: meta("web", "dev")}}
	snapshot.Resources.ClusterRoles = []rbacv1.ClusterRole{{ObjectMeta: meta("reader", ""), Rules: []rbacv1.PolicyRule{readPods}}}
	snapshot.Resources.ClusterRoleBindings = []rbacv1.ClusterRoleBinding{{
		ObjectMeta: meta("ci-reader", ""),
		RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "reader"},
		Subjects: []rbacv1.Subject{
			{Kind: "ServiceAccount", Name: "ci", Namespace: "dev"},
			{Kind: "User", Name: "alice"},
		},
	}}
	snapshot.Resources.Roles = []rbacv1.Role{{ObjectMeta: meta("editor", "dev"), Rules: []rbacv1.PolicyRule{readPods}}}
	snapshot.Resources.RoleBindings = []rbacv1.RoleBinding{{
		ObjectMeta: meta("ci-editor", "dev"),
		RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "editor"},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "ci", Namespace: "dev"}},
	}}
	return snapshot
}

// writeManifest writes content to a new file and returns the path.
func writeManifest(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	return path
}

const adminBinding = `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ci-admin
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: ServiceAccount
    name: ci
    namespace: dev
`

// The same binding as in baseSnapshot, with alice removed: the usual shape of a fix.
const readerBindingWithoutAlice = `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ci-reader
roleRef:
  kind: ClusterRole
  name: reader
subjects:
  - kind: ServiceAccount
    name: ci
    namespace: dev
`

func TestApplyAddsAndReplacesWholeObjects(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	base := baseSnapshot()
	out, result, err := Apply(base, Options{Paths: []string{
		writeManifest(t, dir, "add.yaml", adminBinding),
		writeManifest(t, dir, "replace.yaml", readerBindingWithoutAlice),
	}})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if got, want := result.Added, []string{"ClusterRoleBinding/ci-admin"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Added = %v, want %v", got, want)
	}
	if got, want := result.Replaced, []string{"ClusterRoleBinding/ci-reader"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Replaced = %v, want %v", got, want)
	}
	if got := len(out.Resources.ClusterRoleBindings); got != 2 {
		t.Fatalf("ClusterRoleBindings = %d, want 2 (one replaced in place, one added)", got)
	}
	replaced := out.Resources.ClusterRoleBindings[0]
	if replaced.Name != "ci-reader" || len(replaced.Subjects) != 1 || replaced.Subjects[0].Name != "ci" {
		t.Errorf("replaced binding = %+v, want ci-reader with the one subject of the manifest", replaced)
	}
	if added := out.Resources.ClusterRoleBindings[1]; added.Name != "ci-admin" || added.RoleRef.Name != "cluster-admin" {
		t.Errorf("added binding = %+v", added)
	}

	// The caller's snapshot must keep its content: `paths --diff` compares the two.
	if !reflect.DeepEqual(base, baseSnapshot()) {
		t.Errorf("Apply changed its input:\n got: %+v\nwant: %+v", base.Resources.ClusterRoleBindings, baseSnapshot().Resources.ClusterRoleBindings)
	}
}

// An overlay is "the state after the change", so a second application must
// change nothing more.
func TestApplyTwiceGivesTheSameSnapshot(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	opts := Options{Paths: []string{
		writeManifest(t, dir, "add.yaml", adminBinding),
		writeManifest(t, dir, "replace.yaml", readerBindingWithoutAlice),
	}}
	once, _, err := Apply(baseSnapshot(), opts)
	if err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	twice, result, err := Apply(once, opts)
	if err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	if !reflect.DeepEqual(once.Resources, twice.Resources) {
		t.Errorf("a second Apply changed the snapshot")
	}
	if len(result.Added) != 0 || len(result.Replaced) != 2 {
		t.Errorf("second Apply: Added=%v Replaced=%v, want 0 added and 2 replaced", result.Added, result.Replaced)
	}
}

func TestApplyEachKind(t *testing.T) {
	t.Parallel()

	manifest := `apiVersion: v1
kind: List
items:
  - apiVersion: v1
    kind: Namespace
    metadata: {name: prod, labels: {pod-security.kubernetes.io/enforce: restricted}}
  - apiVersion: v1
    kind: ServiceAccount
    metadata: {name: deployer, namespace: prod}
  - apiVersion: v1
    kind: Pod
    metadata: {name: web, namespace: dev, labels: {changed: "yes"}}
    spec: {serviceAccountName: ci, containers: [{name: app, image: nginx}]}
  - apiVersion: rbac.authorization.k8s.io/v1
    kind: Role
    metadata: {name: editor, namespace: prod}
    rules: [{apiGroups: [""], resources: [pods], verbs: [create]}]
  - apiVersion: rbac.authorization.k8s.io/v1
    kind: RoleBinding
    metadata: {name: deployer-editor, namespace: prod}
    roleRef: {kind: Role, name: editor}
    subjects: [{kind: ServiceAccount, name: deployer, namespace: prod}]
  - apiVersion: rbac.authorization.k8s.io/v1
    kind: ClusterRole
    metadata: {name: reader}
    rules: [{apiGroups: [""], resources: [secrets], verbs: [get]}]
`
	out, result, err := Apply(baseSnapshot(), Options{Paths: []string{writeManifest(t, t.TempDir(), "all.yaml", manifest)}})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	wantAdded := []string{"Namespace/prod", "ServiceAccount/prod/deployer", "Role/prod/editor", "RoleBinding/prod/deployer-editor"}
	if !reflect.DeepEqual(result.Added, wantAdded) {
		t.Errorf("Added = %v, want %v", result.Added, wantAdded)
	}
	wantReplaced := []string{"Pod/dev/web", "ClusterRole/reader"}
	if !reflect.DeepEqual(result.Replaced, wantReplaced) {
		t.Errorf("Replaced = %v, want %v", result.Replaced, wantReplaced)
	}
	if len(result.Warnings) != 0 {
		t.Errorf("Warnings = %v, want none", result.Warnings)
	}
	res := out.Resources
	if len(res.Namespaces) != 2 || len(res.ServiceAccounts) != 2 || len(res.Pods) != 1 || len(res.Roles) != 2 || len(res.RoleBindings) != 2 || len(res.ClusterRoles) != 1 {
		t.Errorf("counts after Apply: ns=%d sa=%d pods=%d roles=%d rb=%d cr=%d", len(res.Namespaces), len(res.ServiceAccounts), len(res.Pods), len(res.Roles), len(res.RoleBindings), len(res.ClusterRoles))
	}
	if res.Pods[0].Spec.ServiceAccountName != "ci" || res.Pods[0].Labels["changed"] != "yes" {
		t.Errorf("the Pod was not replaced with the manifest: %+v", res.Pods[0])
	}
	if got := res.ClusterRoles[0].Rules[0].Resources; !reflect.DeepEqual(got, []string{"secrets"}) {
		t.Errorf("the ClusterRole was not replaced with the manifest: %+v", res.ClusterRoles[0].Rules)
	}
}

// A namespaced manifest with no namespace must not be guessed: the result would
// be for a namespace the user did not mean.
func TestApplyNamespaceDefault(t *testing.T) {
	t.Parallel()

	manifest := `apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: alice-editor}
roleRef: {kind: Role, name: editor}
subjects: [{kind: User, name: alice}]
`
	path := writeManifest(t, t.TempDir(), "rb.yaml", manifest)

	if _, _, err := Apply(baseSnapshot(), Options{Paths: []string{path}}); err == nil || !strings.Contains(err.Error(), "--overlay-namespace") {
		t.Fatalf("want an error that names --overlay-namespace, got %v", err)
	}

	out, result, err := Apply(baseSnapshot(), Options{Paths: []string{path}, DefaultNamespace: "dev"})
	if err != nil {
		t.Fatalf("Apply with a default namespace: %v", err)
	}
	if got, want := result.Added, []string{"RoleBinding/dev/alice-editor"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Added = %v, want %v", got, want)
	}
	if got := out.Resources.RoleBindings[1].Namespace; got != "dev" {
		t.Errorf("namespace = %q, want dev", got)
	}
}

func TestApplyDelete(t *testing.T) {
	t.Parallel()

	out, result, err := Apply(baseSnapshot(), Options{Deletes: []string{
		"ClusterRoleBinding/ci-reader",
		"rolebinding/dev/ci-editor",
		"sa/dev/ci",
		"Pod/web",
	}, DefaultNamespace: "dev"})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	want := []string{"ClusterRoleBinding/ci-reader", "RoleBinding/dev/ci-editor", "ServiceAccount/dev/ci", "Pod/dev/web"}
	if !reflect.DeepEqual(result.Deleted, want) {
		t.Errorf("Deleted = %v, want %v", result.Deleted, want)
	}
	res := out.Resources
	if len(res.ClusterRoleBindings)+len(res.RoleBindings)+len(res.ServiceAccounts)+len(res.Pods) != 0 {
		t.Errorf("objects left after delete: crb=%d rb=%d sa=%d pods=%d", len(res.ClusterRoleBindings), len(res.RoleBindings), len(res.ServiceAccounts), len(res.Pods))
	}
	if len(res.Roles) != 1 || len(res.ClusterRoles) != 1 {
		t.Errorf("delete removed objects it was not asked to remove")
	}
}

// A delete that removes nothing is an error. If it passed, a fix check with a
// wrong name would report "no path added" for a change that did nothing.
func TestApplyDeleteErrors(t *testing.T) {
	t.Parallel()

	for value, want := range map[string]string{
		"ClusterRoleBinding/nope":    "no such object",
		"RoleBinding/prod/ci-editor": "no such object",
		"Role/editor":                "needs a namespace",
		"ClusterRole/dev/reader":     "has no namespace",
		"Namespace/dev":              "cannot be deleted",
		"Deployment/dev/web":         "cannot be deleted",
		"reader":                     "invalid --overlay-delete",
		"ClusterRole/":               "invalid --overlay-delete",
	} {
		_, _, err := Apply(baseSnapshot(), Options{Deletes: []string{value}})
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("delete %q: error = %v, want one that contains %q", value, err, want)
		}
	}
}

func TestApplyReadsDirectoriesAndStdinAndSkipsWhatItCannotUse(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeManifest(t, dir, "rbac/binding.yaml", adminBinding)
	writeManifest(t, dir, "values.yaml", "replicaCount: 2\n")
	writeManifest(t, dir, "notes.txt", "not a manifest")
	writeManifest(t, dir, "workload.json", `{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"web","namespace":"dev"}}`)
	// A kind with a name the overlay knows, from an API group it does not.
	writeManifest(t, dir, "other-role.yaml", "apiVersion: example.com/v1\nkind: Role\nmetadata: {name: x, namespace: dev}\n")

	out, result, err := Apply(baseSnapshot(), Options{
		Paths: []string{dir, "-"},
		Stdin: strings.NewReader(readerBindingWithoutAlice),
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got, want := result.Added, []string{"ClusterRoleBinding/ci-admin"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Added = %v, want %v", got, want)
	}
	if got, want := result.Replaced, []string{"ClusterRoleBinding/ci-reader"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Replaced = %v, want %v (from standard input)", got, want)
	}
	if len(out.Resources.Roles) != 1 {
		t.Errorf("a Role from a different API group was applied")
	}
	warnings := strings.Join(result.Warnings, "\n")
	for _, want := range []string{"Deployment (1)", "Role (1)", "no kind"} {
		if !strings.Contains(warnings, want) {
			t.Errorf("warnings lack %q:\n%s", want, warnings)
		}
	}

	if _, _, err := Apply(baseSnapshot(), Options{Paths: []string{writeManifest(t, t.TempDir(), "tpl.yaml", "kind: {{ .Values.kind }}\n")}}); err == nil {
		t.Error("a template that is not rendered must be an error")
	}
	if _, _, err := Apply(baseSnapshot(), Options{Paths: []string{t.TempDir()}}); err == nil {
		t.Error("a directory with no manifest must be an error")
	}
	if _, _, err := Apply(baseSnapshot(), Options{Paths: []string{filepath.Join(dir, "missing.yaml")}}); err == nil {
		t.Error("a missing file must be an error")
	}
}

// aggregatedSnapshot models the built-in chain: a labeled role feeds view, and
// view feeds edit.
func aggregatedSnapshot() models.Snapshot {
	selector := func(label string) *rbacv1.AggregationRule {
		return &rbacv1.AggregationRule{ClusterRoleSelectors: []metav1.LabelSelector{{MatchLabels: map[string]string{label: "true"}}}}
	}
	snapshot := models.Snapshot{}
	snapshot.Resources.ClusterRoles = []rbacv1.ClusterRole{
		{
			ObjectMeta:      metav1.ObjectMeta{Name: "edit"},
			AggregationRule: selector("aggregate-to-edit"),
			Rules:           []rbacv1.PolicyRule{readPods},
		},
		{
			ObjectMeta:      metav1.ObjectMeta{Name: "view", Labels: map[string]string{"aggregate-to-edit": "true"}},
			AggregationRule: selector("aggregate-to-view"),
			Rules:           []rbacv1.PolicyRule{readPods},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "system:aggregate-to-view", Labels: map[string]string{"aggregate-to-view": "true"}},
			Rules:      []rbacv1.PolicyRule{readPods},
		},
	}
	return snapshot
}

const secretsAddon = `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: view-secrets
  labels: {aggregate-to-view: "true"}
rules:
  - apiGroups: [""]
    resources: [secrets]
    verbs: [get, list]
`

func rulesOf(snapshot models.Snapshot, name string) []rbacv1.PolicyRule {
	for _, role := range snapshot.Resources.ClusterRoles {
		if role.Name == name {
			return role.Rules
		}
	}
	return nil
}

// A snapshot holds the rules that the API server copied into each aggregated
// role. An overlay that adds a labeled role must redo that copy, through each
// level, or the tool reports "no new path" for a change that adds one.
func TestApplyDerivesAggregatedRolesAgain(t *testing.T) {
	t.Parallel()

	path := writeManifest(t, t.TempDir(), "addon.yaml", secretsAddon)
	out, result, err := Apply(aggregatedSnapshot(), Options{Paths: []string{path}})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(result.Warnings) != 0 {
		t.Errorf("Warnings = %v, want none", result.Warnings)
	}
	for _, name := range []string{"view", "edit"} {
		if !containsRule(rulesOf(out, name), readSecrets) {
			t.Errorf("%s did not get the rule of the new labeled role: %+v", name, rulesOf(out, name))
		}
		if !containsRule(rulesOf(out, name), readPods) {
			t.Errorf("%s lost the rule it had: %+v", name, rulesOf(out, name))
		}
	}

	// A delete of the labeled role takes the rule out again, at each level.
	back, _, err := Apply(out, Options{Deletes: []string{"ClusterRole/view-secrets"}})
	if err != nil {
		t.Fatalf("Apply delete: %v", err)
	}
	for _, name := range []string{"view", "edit"} {
		if containsRule(rulesOf(back, name), readSecrets) {
			t.Errorf("%s kept the rule of a deleted role: %+v", name, rulesOf(back, name))
		}
	}
}

// When the roles in the snapshot do not explain the rules of an aggregated
// role, a new derivation would drop rules that the role really has, and paths
// would seem to close. Such a role must keep its rules, with a warning.
func TestApplyLeavesAnAggregatedRoleItCannotExplain(t *testing.T) {
	t.Parallel()

	snapshot := aggregatedSnapshot()
	// view holds a rule that no labeled role in the snapshot supplies.
	snapshot.Resources.ClusterRoles[1].Rules = []rbacv1.PolicyRule{readPods, readSecrets}
	// edit reads view, so the snapshot does explain edit.
	snapshot.Resources.ClusterRoles[0].Rules = []rbacv1.PolicyRule{readPods, readSecrets}

	path := writeManifest(t, t.TempDir(), "other.yaml", "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata: {name: unrelated}\nrules: []\n")
	out, result, err := Apply(snapshot, Options{Paths: []string{path}})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !containsRule(rulesOf(out, "view"), readSecrets) {
		t.Errorf("view lost a rule that the snapshot gave it: %+v", rulesOf(out, "view"))
	}
	if len(result.Warnings) != 1 || !strings.Contains(result.Warnings[0], "ClusterRole view") {
		t.Errorf("want one warning that names ClusterRole view, got %v", result.Warnings)
	}
}

// An overlay that changes no ClusterRole must not touch aggregated rules at all.
func TestApplyWithoutAClusterRoleChangeKeepsAggregatedRules(t *testing.T) {
	t.Parallel()

	snapshot := aggregatedSnapshot()
	snapshot.Resources.ClusterRoles[1].Rules = []rbacv1.PolicyRule{readPods, readSecrets}
	out, result, err := Apply(snapshot, Options{Paths: []string{writeManifest(t, t.TempDir(), "crb.yaml", adminBinding)}})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !reflect.DeepEqual(out.Resources.ClusterRoles, snapshot.Resources.ClusterRoles) || len(result.Warnings) != 0 {
		t.Errorf("ClusterRoles changed, or a warning was given, with no ClusterRole in the overlay: %v", result.Warnings)
	}
}
