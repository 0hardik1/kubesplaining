package cli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/collector"
	"github.com/0hardik1/kubesplaining/internal/overlay"
)

// A ClusterRoleBinding that makes a new ServiceAccount cluster-admin.
const overlayAdminBinding = `apiVersion: v1
kind: ServiceAccount
metadata:
  name: deployer
  namespace: ci
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ci-deployer-admin
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: ServiceAccount
    name: deployer
    namespace: ci
`

func writeOverlay(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "overlay.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write overlay: %v", err)
	}
	return path
}

// runPathsDiffJSON runs `paths --diff` with JSON output. It returns the decoded
// diff and the command error, which is the gate result when the change adds a
// path.
func runPathsDiffJSON(t *testing.T, args ...string) (pathsDiffOutput, error) {
	t.Helper()
	stdout, _, err := runPaths(t, append(args, "--diff", "--output-format", "json")...)
	var out pathsDiffOutput
	if decodeErr := json.Unmarshal([]byte(stdout), &out); decodeErr != nil {
		t.Fatalf("paths --diff %v: output is not JSON (command error: %v): %v\n%s", args, err, decodeErr, stdout)
	}
	return out, err
}

// The check for a pull request that changes RBAC: a binding that opens a path
// must be reported, and the command must exit with the gate code, not with the
// code of a tool failure.
func TestPathsDiffReportsAPathThatAChangeAdds(t *testing.T) {
	t.Parallel()

	out, err := runPathsDiffJSON(t, "--input-file", minimalRisky, "--overlay", writeOverlay(t, overlayAdminBinding))
	if err == nil {
		t.Fatal("want an error when the change adds a path")
	}
	if got := ExitCode(err); got != ExitGateExceeded {
		t.Errorf("exit code = %d, want %d (a result, not a tool failure)", got, ExitGateExceeded)
	}

	added := map[string]string{}
	for _, path := range out.Added {
		added[path.Source] = path.Target
	}
	if added["ServiceAccount/ci/deployer"] != "cluster_admin_equivalent" {
		t.Errorf("the new ServiceAccount's path to cluster-admin is not in added: %+v", out.Added)
	}
	// The second consequence is the one a reviewer does not see in the manifest:
	// default/reader can create pods, so it can now run a pod as the new admin.
	if added["ServiceAccount/default/reader"] != "cluster_admin_equivalent" {
		t.Errorf("the path that the new binding opens for an existing ServiceAccount is not in added: %+v", out.Added)
	}
	if len(out.Removed) != 0 || len(out.Changed) != 0 || out.Unchanged != 2 {
		t.Errorf("removed=%d changed=%d unchanged=%d, want 0, 0, 2", len(out.Removed), len(out.Changed), out.Unchanged)
	}
	if len(out.Notes) == 0 || !strings.Contains(out.Notes[0], "what-if overlay") {
		t.Errorf("the output must say that it includes an overlay, got notes %q", out.Notes)
	}
}

// The check for a fix: delete the binding behind the paths, and they are gone.
func TestPathsDiffReportsPathsThatAFixRemoves(t *testing.T) {
	t.Parallel()

	out, err := runPathsDiffJSON(t, "--input-file", minimalRisky, "--overlay-delete", "ClusterRoleBinding/reader-role")
	if err != nil {
		t.Fatalf("a change that only removes paths is not an error: %v", err)
	}
	if len(out.Removed) != 2 || len(out.Added) != 0 || len(out.Changed) != 0 || out.Unchanged != 0 {
		t.Errorf("added=%d removed=%d changed=%d unchanged=%d, want 0, 2, 0, 0", len(out.Added), len(out.Removed), len(out.Changed), out.Unchanged)
	}
}

func TestPathsDiffOfAChangeThatIsUndone(t *testing.T) {
	t.Parallel()

	out, err := runPathsDiffJSON(t, "--input-file", minimalRisky,
		"--overlay", writeOverlay(t, overlayAdminBinding),
		"--overlay-delete", "ClusterRoleBinding/ci-deployer-admin")
	if err != nil {
		t.Fatalf("paths --diff: %v", err)
	}
	if len(out.Added)+len(out.Removed)+len(out.Changed) != 0 || out.Unchanged != 2 {
		t.Errorf("a binding that is added and deleted must change nothing: %+v", out)
	}
}

// A fix that removes one binding while a second route to the same target stays
// open must not read as "path removed". The path keeps its ID, so it shows as
// changed, with the route that is left.
func TestPathsDiffShowsARouteThatSurvivesTheFix(t *testing.T) {
	t.Parallel()

	// Two bindings give default/reader cluster-admin. Build that cluster as a
	// snapshot file, then delete one of the two.
	base, err := collector.ReadSnapshot(minimalRisky)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	twoBindings := ""
	for _, name := range []string{"reader-admin-a", "reader-admin-b"} {
		twoBindings += "---\napiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata: {name: " + name + "}\n" +
			"roleRef: {kind: ClusterRole, name: cluster-admin}\nsubjects: [{kind: ServiceAccount, name: reader, namespace: default}]\n"
	}
	withBoth, _, err := overlay.Apply(base, overlay.Options{Paths: []string{writeOverlay(t, twoBindings)}})
	if err != nil {
		t.Fatalf("build the two-binding snapshot: %v", err)
	}
	payload, err := json.Marshal(withBoth)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	snapshotFile := filepath.Join(t.TempDir(), "snapshot.json")
	if err := os.WriteFile(snapshotFile, payload, 0o600); err != nil {
		t.Fatalf("write snapshot: %v", err)
	}

	out, err := runPathsDiffJSON(t, "--input-file", snapshotFile, "--to", "cluster-admin", "--overlay-delete", "ClusterRoleBinding/reader-admin-a")
	if err != nil {
		t.Fatalf("paths --diff: %v", err)
	}
	if len(out.Removed) != 0 || len(out.Added) != 0 {
		t.Fatalf("added=%d removed=%d, want 0 and 0: the path is still there through the second binding", len(out.Added), len(out.Removed))
	}
	if len(out.Changed) != 1 {
		t.Fatalf("changed=%d, want 1: %+v", len(out.Changed), out)
	}
	change := out.Changed[0]
	if got := change.Before.Hops[0].SourceBinding; got != "reader-admin-a" {
		t.Errorf("before: first hop binding = %q, want reader-admin-a", got)
	}
	if !change.Before.SurvivesFirstFix {
		t.Error("before: the path must be marked as one that survives the first fix")
	}
	if got := change.After.Hops[0].SourceBinding; got != "reader-admin-b" {
		t.Errorf("after: first hop binding = %q, want reader-admin-b (the route that is left)", got)
	}

	// The text form names the binding behind each route. The two routes have the
	// same action, so the binding is the one thing that tells them apart.
	stdout, stderr, err := runPaths(t, "--input-file", snapshotFile, "--to", "cluster-admin", "--overlay-delete", "ClusterRoleBinding/reader-admin-a", "--diff")
	if err != nil {
		t.Fatalf("paths --diff (text): %v", err)
	}
	for _, want := range []string{
		"CHANGED (1): still open, by a different route",
		"ServiceAccount/default/reader -> cluster-admin",
		"before: bound_to_cluster_admin [ClusterRoleBinding reader-admin-a (role cluster-admin)]",
		"also: bound_to_cluster_admin [ClusterRoleBinding reader-admin-b (role cluster-admin)]",
		"after:  bound_to_cluster_admin [ClusterRoleBinding reader-admin-b (role cluster-admin)]",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, stdout)
		}
	}
	if !strings.Contains(stderr, "adds 0 attack paths, removes 0, and changes 1") {
		t.Errorf("stderr lacks the counts:\n%s", stderr)
	}

	// Delete both, and the path is removed.
	out, err = runPathsDiffJSON(t, "--input-file", snapshotFile, "--to", "cluster-admin",
		"--overlay-delete", "ClusterRoleBinding/reader-admin-a", "--overlay-delete", "ClusterRoleBinding/reader-admin-b")
	if err != nil {
		t.Fatalf("paths --diff: %v", err)
	}
	if len(out.Removed) != 1 || len(out.Changed) != 0 {
		t.Errorf("removed=%d changed=%d, want 1 and 0", len(out.Removed), len(out.Changed))
	}
}

// --from can name a subject that only the change brings into the cluster.
func TestPathsDiffFromASubjectThatTheChangeAdds(t *testing.T) {
	t.Parallel()

	file := writeOverlay(t, overlayAdminBinding)
	out, err := runPathsDiffJSON(t, "--input-file", minimalRisky, "--overlay", file, "--from", "ServiceAccount/ci/deployer")
	if ExitCode(err) != ExitGateExceeded {
		t.Fatalf("exit code = %d (err %v), want %d", ExitCode(err), err, ExitGateExceeded)
	}
	if len(out.Added) == 0 {
		t.Fatal("no added path for the new ServiceAccount")
	}
	notes := strings.Join(out.Notes, "\n")
	if !strings.Contains(notes, "is not in the cluster before the change") {
		t.Errorf("notes do not say that the subject is new: %q", out.Notes)
	}

	// A subject on neither side is still an error, and a tool failure, not a gate result.
	_, _, err = runPaths(t, "--input-file", minimalRisky, "--overlay", file, "--from", "ServiceAccount/ci/nobody", "--diff")
	if err == nil || ExitCode(err) != ExitFailure {
		t.Errorf("unknown subject: err=%v exit=%d, want an error with exit code %d", err, ExitCode(err), ExitFailure)
	}
}

func TestPathsDiffText(t *testing.T) {
	t.Parallel()

	stdout, stderr, err := runPaths(t, "--input-file", minimalRisky, "--overlay", writeOverlay(t, overlayAdminBinding), "--diff")
	if ExitCode(err) != ExitGateExceeded {
		t.Fatalf("exit code = %d (err %v), want %d", ExitCode(err), err, ExitGateExceeded)
	}
	if !strings.Contains(err.Error(), "the change adds 2 attack paths") {
		t.Errorf("error = %q", err)
	}
	for _, want := range []string{"ADDED (2)", "ServiceAccount/ci/deployer", "bound_to_cluster_admin"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "REMOVED") || strings.Contains(stdout, "CHANGED") {
		t.Errorf("stdout has a section with nothing in it:\n%s", stdout)
	}
	for _, want := range []string{"The change adds 2 attack paths, removes 0, and changes 0. 2 stay the same.", "what-if overlay (2 added, 0 replaced, 0 deleted)"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, stderr)
		}
	}
}

func TestPathsOverlayFlagErrors(t *testing.T) {
	t.Parallel()

	file := writeOverlay(t, overlayAdminBinding)
	cases := map[string][]string{
		"needs --overlay":           {"--diff"},
		"--limit cannot be used":    {"--overlay", file, "--diff", "--limit", "5"},
		"no such object":            {"--overlay-delete", "ClusterRoleBinding/nope", "--diff"},
		"invalid --overlay-delete":  {"--overlay-delete", "reader-role"},
		"no such file or directory": {"--overlay", filepath.Join(t.TempDir(), "missing.yaml")},
	}
	for want, args := range cases {
		_, _, err := runPaths(t, append([]string{"--input-file", minimalRisky}, args...)...)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("paths %v: error = %v, want one that contains %q", args, err, want)
			continue
		}
		if ExitCode(err) != ExitFailure {
			t.Errorf("paths %v: exit code = %d, want %d (a tool failure)", args, ExitCode(err), ExitFailure)
		}
	}
}

// Without --diff, an overlay gives a plain listing of the cluster after the
// change, and the output says that it is a what-if result.
func TestPathsOverlayWithoutDiffListsTheStateAfterTheChange(t *testing.T) {
	t.Parallel()

	out := runPathsJSON(t, "--input-file", minimalRisky, "--overlay", writeOverlay(t, overlayAdminBinding), "--to", "cluster-admin")
	if out.Total != 2 {
		t.Errorf("total = %d, want the 2 paths to cluster-admin that the binding opens", out.Total)
	}
	if len(out.Notes) == 0 || !strings.Contains(out.Notes[0], "does not exist yet") {
		t.Errorf("notes do not say that this is a what-if result: %q", out.Notes)
	}
}

// scan takes the same flags, and its report must carry the what-if warning.
func TestScanWithOverlayMarksTheReport(t *testing.T) {
	t.Parallel()

	outputDir := t.TempDir()
	cmd := NewScanCmd(BuildInfo{})
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	var stdout, stderr strings.Builder
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"--input-file", minimalRisky, "--overlay", writeOverlay(t, overlayAdminBinding), "--output-dir", outputDir, "--output-format", "json", "--all-findings"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if !strings.Contains(stderr.String(), "overlay: This result includes a what-if overlay") {
		t.Errorf("stderr does not say that the scan includes an overlay:\n%s", stderr.String())
	}
	findings, err := os.ReadFile(filepath.Join(outputDir, "findings.json"))
	if err != nil {
		t.Fatalf("read findings: %v", err)
	}
	if !strings.Contains(string(findings), "KUBE-PRIVESC-PATH-CLUSTER-ADMIN:ServiceAccount/ci/deployer:cluster_admin_equivalent") {
		t.Error("findings.json does not have the path that the overlay opens")
	}
	metadata, err := os.ReadFile(filepath.Join(outputDir, "scan-metadata.json"))
	if err != nil {
		t.Fatalf("read metadata: %v", err)
	}
	if !strings.Contains(string(metadata), "what-if overlay") {
		t.Errorf("scan-metadata.json does not record the overlay:\n%s", metadata)
	}
}

func TestDiffExitCodes(t *testing.T) {
	t.Parallel()

	if got := ExitCode(nil); got != 0 {
		t.Errorf("ExitCode(nil) = %d, want 0", got)
	}
	if got := ExitCode(errors.New("unreadable file")); got != ExitFailure {
		t.Errorf("ExitCode(plain error) = %d, want %d", got, ExitFailure)
	}
	if got := ExitCode(asGateError(errors.New("the change adds 1 attack path"))); got != ExitGateExceeded {
		t.Errorf("ExitCode(gate error) = %d, want %d", got, ExitGateExceeded)
	}
	if asGateError(nil) != nil {
		t.Error("asGateError(nil) must be nil")
	}
}
