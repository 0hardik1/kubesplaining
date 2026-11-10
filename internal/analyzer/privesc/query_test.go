package privesc

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/0hardik1/kubesplaining/internal/collector"
	"github.com/0hardik1/kubesplaining/internal/models"
)

// fixtureSnapshots loads every snapshot under testdata/snapshots.
func fixtureSnapshots(t *testing.T) map[string]models.Snapshot {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "..", "..", "testdata", "snapshots", "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no snapshot fixtures found (err=%v)", err)
	}
	out := map[string]models.Snapshot{}
	for _, file := range files {
		snapshot, err := collector.ReadSnapshot(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		out[filepath.Base(file)] = snapshot
	}
	return out
}

// A query for one source must give the paths that the scan gives for that
// source: same sinks, same hops, same alternates, same order.
func TestPathsFromMatchesFindPathsForEachSource(t *testing.T) {
	t.Parallel()

	sawPaths := false
	for name, snapshot := range fixtureSnapshots(t) {
		graph := BuildGraph(snapshot)
		bySource := map[string][]models.EscalationPath{}
		for _, path := range FindPaths(graph, DefaultMaxDepth) {
			bySource[path.Source.Key()] = append(bySource[path.Source.Key()], path)
		}
		for key, want := range bySource {
			sawPaths = true
			got, ok := PathsFrom(graph, want[0].Source, DefaultMaxDepth)
			if !ok {
				t.Errorf("%s: PathsFrom(%s) reported no node", name, key)
				continue
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("%s: PathsFrom(%s) differs from the FindPaths result for that source\n got: %+v\nwant: %+v", name, key, got, want)
			}
		}
	}
	if !sawPaths {
		t.Fatal("no fixture produced a path, so the test compared nothing")
	}
}

func TestPathsFromUnknownSubject(t *testing.T) {
	t.Parallel()

	graph := BuildGraph(groupGrantSnapshot("devs", wildcardRule))
	paths, ok := PathsFrom(graph, models.SubjectRef{Kind: "User", Name: "nobody"}, DefaultMaxDepth)
	if ok || paths != nil {
		t.Fatalf("PathsFrom(unknown) = %v, %v; want nil, false", paths, ok)
	}
}

// The scan never starts a search at a built-in system identity. A query that
// names one must still answer.
func TestPathsFromSystemSubject(t *testing.T) {
	t.Parallel()

	masters := models.SubjectRef{Kind: "Group", Name: "system:masters"}
	graph := BuildGraph(groupGrantSnapshot(masters.Name, wildcardRule))

	for _, path := range FindPaths(graph, DefaultMaxDepth) {
		if path.Source == masters {
			t.Fatalf("FindPaths seeded the system subject %s", masters.Key())
		}
	}

	node, ok := SubjectNode(graph, masters)
	if !ok || !node.IsSystem {
		t.Fatalf("SubjectNode(%s) = %+v, %v; want a system node", masters.Key(), node, ok)
	}
	paths, ok := PathsFrom(graph, masters, DefaultMaxDepth)
	if !ok {
		t.Fatalf("PathsFrom(%s) reported no node", masters.Key())
	}
	if !hasTarget(paths, models.TargetClusterAdmin) {
		t.Fatalf("PathsFrom(%s) = %+v; want a path to cluster-admin", masters.Key(), paths)
	}
}

// A ServiceAccount that no binding names still has a node, and it holds the
// grants of its implicit groups. A query for it must show that reach: this is
// the `default` ServiceAccount of most namespaces.
func TestPathsFromServiceAccountWithNoBinding(t *testing.T) {
	t.Parallel()

	graph := BuildGraph(groupGrantSnapshot("system:serviceaccounts", listSecretsRule))
	app := models.SubjectRef{Kind: "ServiceAccount", Namespace: "team-a", Name: "app"}
	paths, ok := PathsFrom(graph, app, DefaultMaxDepth)
	if !ok {
		t.Fatalf("PathsFrom(%s) reported no node: BuildGraph must make a node for each ServiceAccount in the snapshot", app.Key())
	}
	for _, path := range paths {
		if path.Target != models.TargetKubeSystemSecrets {
			continue
		}
		if got := path.Hops[0].Action; got != "implicit_group_membership" {
			t.Errorf("first hop action = %q, want implicit_group_membership", got)
		}
		return
	}
	t.Fatalf("PathsFrom(%s) = %+v; want a path to kube-system secrets through system:serviceaccounts", app.Key(), paths)
}

// Analyze and FindingsFromPaths must stay one code path, so a queried path has
// the ID, score, and hops of the finding a scan reports.
func TestFindingsFromPathsMatchesAnalyze(t *testing.T) {
	t.Parallel()

	for name, snapshot := range fixtureSnapshots(t) {
		want, err := New().Analyze(context.Background(), snapshot)
		if err != nil {
			t.Fatalf("%s: Analyze: %v", name, err)
		}
		got := FindingsFromPaths(FindPaths(BuildGraph(snapshot), DefaultMaxDepth), snapshot)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: FindingsFromPaths differs from Analyze (%d vs %d findings)", name, len(got), len(want))
		}
	}
}

// FindingTarget must read back the sink that findingFromPath wrote, for every
// target kind, including the two that carry a namespace or a role.
func TestFindingTargetReadsBackTheSink(t *testing.T) {
	t.Parallel()

	snapshots := fixtureSnapshots(t)
	snapshots["two-irsa-roles"] = twoIRSARoleSnapshot()
	// A Role that may write Roles in its own namespace and holds `escalate`:
	// namespace-admin there.
	namespaceAdmin := rbacWriteSnapshot()
	bindSA(&namespaceAdmin, "team-a", "attacker", "role-writer", []rbacv1.PolicyRule{{
		APIGroups: []string{"rbac.authorization.k8s.io"}, Resources: []string{"roles"}, Verbs: []string{"create", "update", "patch", "escalate"},
	}})
	snapshots["namespace-admin"] = namespaceAdmin

	seen := map[models.EscalationTarget]bool{}
	for name, snapshot := range snapshots {
		for _, path := range FindPaths(BuildGraph(snapshot), DefaultMaxDepth) {
			finding := findingFromPath(path)
			target, detail, ok := FindingTarget(finding)
			if !ok {
				t.Fatalf("%s: FindingTarget(%s) reported no target", name, finding.ID)
			}
			if target != path.Target {
				t.Errorf("%s: %s: target = %q, want %q", name, finding.ID, target, path.Target)
			}
			wantDetail := ""
			switch path.Target {
			case models.TargetNamespaceAdmin:
				wantDetail = path.TargetNamespace
			case models.TargetAWSIAMRole:
				wantDetail = path.Hops[len(path.Hops)-1].ToSubject.Name
			}
			if detail != wantDetail {
				t.Errorf("%s: %s: detail = %q, want %q", name, finding.ID, detail, wantDetail)
			}
			if (path.Target == models.TargetNamespaceAdmin || path.Target == models.TargetAWSIAMRole) && detail == "" {
				t.Errorf("%s: %s: a %s path must name its namespace or role", name, finding.ID, path.Target)
			}
			seen[target] = true
		}
	}
	for _, target := range []models.EscalationTarget{models.TargetClusterAdmin, models.TargetNamespaceAdmin, models.TargetAWSIAMRole} {
		if !seen[target] {
			t.Errorf("no fixture produced a %s path, so that case is not covered", target)
		}
	}

	if _, _, ok := FindingTarget(models.Finding{RuleID: "KUBE-RBAC-OVERBROAD-001", Tags: []string{"target:cluster_admin_equivalent"}}); ok {
		t.Error("FindingTarget accepted a finding that has no hops")
	}
}

func hasTarget(paths []models.EscalationPath, target models.EscalationTarget) bool {
	for _, path := range paths {
		if path.Target == target {
			return true
		}
	}
	return false
}
