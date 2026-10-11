package report

import (
	"strconv"
	"strings"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
)

func apSA(name string) models.SubjectRef {
	return models.SubjectRef{Kind: "ServiceAccount", Name: name, Namespace: "apps"}
}

// apPath builds a path finding whose hops walk the given subjects in order and
// end at the target. actions[i] is the action of hop i.
func apPath(sev models.Severity, subjects []models.SubjectRef, actions []string) models.Finding {
	hops := make([]models.EscalationHop, len(subjects))
	for i, s := range subjects {
		hops[i] = models.EscalationHop{Step: i + 1, FromSubject: s, Action: actions[i], Difficulty: "easy"}
		if i+1 < len(subjects) {
			hops[i].ToSubject = subjects[i+1]
		}
	}
	return models.Finding{RuleID: "KUBE-PRIVESC-PATH-CLUSTER-ADMIN", Severity: sev, EscalationPath: hops}
}

func nodeByTitle(t *testing.T, g SinkGraph, title string) PathNode {
	t.Helper()
	for _, n := range g.Nodes {
		if n.Title == title {
			return n
		}
	}
	t.Fatalf("no node titled %q in %+v", title, g.Nodes)
	return PathNode{}
}

// TestBuildSinkGraphColumnsByHopsAway checks that each identity sits in the
// column for its distance to the target, and that nodes and edges carry the
// indexes of the paths through them.
func TestBuildSinkGraphColumnsByHopsAway(t *testing.T) {
	t.Parallel()

	paths := []models.Finding{
		// Path 0: a -> b -> target (2 hops).
		apPath(models.SeverityCritical, []models.SubjectRef{apSA("a"), apSA("b")}, []string{"pod_create_token_theft", "wildcard_permission"}),
		// Path 1: c -> target (1 hop).
		apPath(models.SeverityHigh, []models.SubjectRef{apSA("c")}, []string{"impersonate"}),
	}
	g := buildSinkGraph("cluster_admin_equivalent", "cluster-admin", paths)
	if g.Skipped {
		t.Fatal("small graph was skipped")
	}

	var labels []string
	for _, c := range g.Columns {
		labels = append(labels, c.Label)
	}
	if got, want := strings.Join(labels, "|"), "2 hops away|1 hop away|Target"; got != want {
		t.Fatalf("column labels = %q, want %q", got, want)
	}

	a, b, c := nodeByTitle(t, g, "a"), nodeByTitle(t, g, "b"), nodeByTitle(t, g, "c")
	target := nodeByTitle(t, g, "cluster-admin")
	if a.X >= b.X || b.X != c.X || c.X >= target.X {
		t.Errorf("columns out of order: a.X=%d b.X=%d c.X=%d target.X=%d", a.X, b.X, c.X, target.X)
	}
	if a.Kind != "source" || b.Kind != "via" || c.Kind != "source" || target.Kind != "target" {
		t.Errorf("kinds = %s/%s/%s/%s, want source/via/source/target", a.Kind, b.Kind, c.Kind, target.Kind)
	}
	if a.Sub != "SA · apps" {
		t.Errorf("a.Sub = %q, want %q", a.Sub, "SA · apps")
	}
	if b.Paths != "0" || c.Paths != "1" || target.Paths != "0 1" {
		t.Errorf("node paths: b=%q c=%q target=%q", b.Paths, c.Paths, target.Paths)
	}
	if target.Sub != "2 paths" {
		t.Errorf("target.Sub = %q, want %q", target.Sub, "2 paths")
	}
	if a.SevClass != "crit" || c.SevClass != "high" {
		t.Errorf("severity classes: a=%q c=%q", a.SevClass, c.SevClass)
	}
	if len(g.Edges) != 3 {
		t.Fatalf("got %d edges, want 3", len(g.Edges))
	}
	for _, e := range g.Edges {
		if e.Paths == "" || e.D == "" || e.Short == "" {
			t.Errorf("edge missing data: %+v", e)
		}
	}
	if g.Width <= target.X || g.Height <= target.Y {
		t.Errorf("canvas %dx%d does not contain the target at %d,%d", g.Width, g.Height, target.X, target.Y)
	}
}

// TestBuildSinkGraphGroupsIdenticalSources checks that three or more sources
// with the same first hop collapse into one group node with one thick edge,
// while two do not.
func TestBuildSinkGraphGroupsIdenticalSources(t *testing.T) {
	t.Parallel()

	var paths []models.Finding
	for _, name := range []string{"s1", "s2", "s3"} {
		paths = append(paths, apPath(models.SeverityHigh, []models.SubjectRef{apSA(name)}, []string{"secret_read"}))
	}
	g := buildSinkGraph("kube_system_secrets", "kube-system secrets", paths)
	if len(g.Nodes) != 2 {
		t.Fatalf("got %d nodes, want a group and the target: %+v", len(g.Nodes), g.Nodes)
	}
	group := nodeByTitle(t, g, "3 ServiceAccounts")
	if group.Kind != "group" || group.Count != 3 || group.Sub != "in apps" {
		t.Errorf("group = %+v", group)
	}
	if group.Paths != "0 1 2" {
		t.Errorf("group.Paths = %q, want %q", group.Paths, "0 1 2")
	}
	if !strings.Contains(group.Members, "ServiceAccount/apps/s1") {
		t.Errorf("group tooltip does not name its members: %q", group.Members)
	}
	if len(g.Edges) != 1 {
		t.Fatalf("got %d edges, want 1", len(g.Edges))
	}
	if e := g.Edges[0]; !strings.Contains(e.Label, "(3 identities)") || e.Width == "1.6" {
		t.Errorf("group edge = %+v", e)
	}

	g = buildSinkGraph("kube_system_secrets", "kube-system secrets", paths[:2])
	if len(g.Nodes) != 3 {
		t.Errorf("two identical sources should stay separate, got %d nodes", len(g.Nodes))
	}
}

// TestBuildSinkGraphSkipsHugeGraphs checks the node cap: past apMaxNodes the
// diagram is dropped and only the path list renders.
func TestBuildSinkGraphSkipsHugeGraphs(t *testing.T) {
	t.Parallel()

	var paths []models.Finding
	for i := 0; i <= apMaxNodes; i++ {
		// A distinct action per source, so no two sources group together.
		paths = append(paths, apPath(models.SeverityLow, []models.SubjectRef{apSA("s" + strconv.Itoa(i))}, []string{"action_" + strconv.Itoa(i)}))
	}
	g := buildSinkGraph("cluster_admin_equivalent", "cluster-admin", paths)
	if !g.Skipped {
		t.Fatal("expected the graph to be skipped")
	}
	if g.TotalNodes != apMaxNodes+2 {
		t.Errorf("TotalNodes = %d, want %d", g.TotalNodes, apMaxNodes+2)
	}
}

func TestBuildPathSteps(t *testing.T) {
	t.Parallel()

	f := apPath(models.SeverityCritical, []models.SubjectRef{apSA("a"), apSA("b")}, []string{"pod_create_token_theft", "wildcard_permission"})
	steps := buildPathSteps(f.EscalationPath)
	if len(steps) != 2 {
		t.Fatalf("got %d steps, want 2", len(steps))
	}
	if steps[0].Label != "a" || steps[0].Full != "ServiceAccount/apps/a" || steps[0].Difficulty != "easy" {
		t.Errorf("step 0 = %+v", steps[0])
	}
	if steps[0].Action == "" || steps[0].Action == "pod_create_token_theft" {
		t.Errorf("step 0 action should be a readable title, got %q", steps[0].Action)
	}
}

// edgeEndpoints parses the x of the first and last points of an edge's path data.
func edgeEndpoints(t *testing.T, d string) (x1, x2 int) {
	t.Helper()
	fields := strings.Fields(d)
	if len(fields) < 2 {
		t.Fatalf("edge path too short: %q", d)
	}
	parseX := func(s string) int {
		s = strings.TrimLeft(s, "MCL")
		n, err := strconv.Atoi(strings.SplitN(s, ",", 2)[0])
		if err != nil {
			t.Fatalf("bad point %q in %q: %v", s, d, err)
		}
		return n
	}
	return parseX(fields[0]), parseX(fields[len(fields)-1])
}

// TestBuildSinkGraphEveryEdgePointsRight covers the case shortest-distance
// layering got wrong: an identity with both a direct hop to the target and a
// longer chain through another identity. Columns come from the longest chain,
// so the two sit in different columns and every edge runs left to right; the
// direct hop skips a column and is routed through a reserved slot there.
func TestBuildSinkGraphEveryEdgePointsRight(t *testing.T) {
	t.Parallel()

	paths := []models.Finding{
		apPath(models.SeverityCritical, []models.SubjectRef{apSA("a"), apSA("b")}, []string{"pod_create_token_theft", "wildcard_permission"}),
		apPath(models.SeverityCritical, []models.SubjectRef{apSA("a")}, []string{"impersonate"}),
	}
	g := buildSinkGraph("cluster_admin_equivalent", "cluster-admin", paths)
	a, b := nodeByTitle(t, g, "a"), nodeByTitle(t, g, "b")
	target := nodeByTitle(t, g, "cluster-admin")
	if a.X >= b.X || b.X >= target.X {
		t.Fatalf("expected a left of b left of the target, got a.X=%d b.X=%d target.X=%d", a.X, b.X, target.X)
	}
	if len(g.Edges) != 3 {
		t.Fatalf("got %d edges, want 3", len(g.Edges))
	}
	var direct *PathEdge
	for i := range g.Edges {
		e := &g.Edges[i]
		x1, x2 := edgeEndpoints(t, e.D)
		if x2 <= x1 {
			t.Errorf("edge %q points left: %s", e.Label, e.D)
		}
		if e.Label == actionTitle("impersonate") {
			direct = e
		}
	}
	if direct == nil {
		t.Fatal("no direct edge from a to the target")
	}
	if !strings.Contains(direct.D, " L") {
		t.Errorf("direct edge should run straight through b's column, got %s", direct.D)
	}
	if direct.LX < b.X || direct.LX > b.X+b.W {
		t.Errorf("direct edge label at x=%d, want inside b's column [%d,%d]", direct.LX, b.X, b.X+b.W)
	}
}

// TestBuildSinkGraphRoutesThroughIntermediateSinks checks that a hop into an
// intermediate target (namespace admin, whose destination has no subject) gets
// its own waypoint box, and that the chain continues from that box rather
// than looping back into the identity that reached it.
func TestBuildSinkGraphRoutesThroughIntermediateSinks(t *testing.T) {
	t.Parallel()

	hops := []models.EscalationHop{
		{Step: 1, FromSubject: apSA("binder"), Action: "modify_role_binding", Difficulty: "easy", BindingNamespace: "apps"},
		{Step: 2, FromSubject: apSA("binder"), ToSubject: apSA("deployer"), Action: "colocated_sa_token_theft", Difficulty: "easy"},
		{Step: 3, FromSubject: apSA("deployer"), Action: "bound_to_cluster_admin", Difficulty: "easy"},
	}
	f := models.Finding{RuleID: "KUBE-PRIVESC-PATH-CLUSTER-ADMIN", Severity: models.SeverityCritical, EscalationPath: hops}
	g := buildSinkGraph("cluster_admin_equivalent", "cluster-admin", []models.Finding{f})

	way := nodeByTitle(t, g, "Namespace admin")
	if way.Kind != "sink" || way.Sub != "in apps" || way.Icon != "ns" {
		t.Errorf("waypoint = %+v", way)
	}
	binder, deployer := nodeByTitle(t, g, "binder"), nodeByTitle(t, g, "deployer")
	target := nodeByTitle(t, g, "cluster-admin")
	if binder.X >= way.X || way.X >= deployer.X || deployer.X >= target.X {
		t.Errorf("chain out of order: binder=%d waypoint=%d deployer=%d target=%d", binder.X, way.X, deployer.X, target.X)
	}
	var labels []string
	for _, c := range g.Columns {
		labels = append(labels, c.Label)
	}
	if got, want := strings.Join(labels, "|"), "3 hops away|2 hops away|1 hop away|Target"; got != want {
		t.Errorf("column labels = %q, want %q", got, want)
	}
	if len(g.Edges) != 3 {
		t.Errorf("got %d edges, want 3 (one per hop)", len(g.Edges))
	}
	if target.PathCount != 1 || target.Sub != "1 path" {
		t.Errorf("target = %+v, want exactly one path", target)
	}
}

// TestBuildSinkGraphLandsNamedSinkOnTarget checks that a path whose last hop
// names its sink (an external IAM role) still ends on the target box, with the
// role named on the target's tooltip rather than drawn as a separate node.
func TestBuildSinkGraphLandsNamedSinkOnTarget(t *testing.T) {
	t.Parallel()

	arn := "arn:aws:iam::123456789012:role/AdministratorAccess"
	hops := []models.EscalationHop{
		{Step: 1, FromSubject: apSA("irsa"), ToSubject: models.SubjectRef{Kind: "User", Name: arn}, Action: "irsa_assume_role", Difficulty: "moderate"},
	}
	f := models.Finding{RuleID: "KUBE-PRIVESC-PATH-AWS-IAM-ROLE", Severity: models.SeverityHigh, EscalationPath: hops}
	g := buildSinkGraph("aws_iam_role", "AWS IAM role", []models.Finding{f})
	if len(g.Nodes) != 2 || len(g.Edges) != 1 {
		t.Fatalf("got %d nodes and %d edges, want 2 and 1: %+v", len(g.Nodes), len(g.Edges), g.Nodes)
	}
	target := nodeByTitle(t, g, "AWS IAM role")
	if target.Icon != "cloud" || !strings.Contains(target.KindLabel, "AdministratorAccess") {
		t.Errorf("target = %+v, want the cloud icon and the role name on the tooltip", target)
	}
	if x1, x2 := edgeEndpoints(t, g.Edges[0].D); x2 <= x1 {
		t.Errorf("edge points left: %s", g.Edges[0].D)
	}
	if short, full := pathTerminal("aws_iam_role", f); short != "AdministratorAccess" || full != arn {
		t.Errorf("pathTerminal = %q, %q", short, full)
	}
}

func TestPathTerminalNamespaceAdmin(t *testing.T) {
	t.Parallel()

	f := models.Finding{
		ID:             "KUBE-PRIVESC-PATH-NAMESPACE-ADMIN:ServiceAccount/apps/x:namespace_admin:apps",
		EscalationPath: []models.EscalationHop{{FromSubject: apSA("x"), Action: "modify_role_binding", BindingNamespace: "apps"}},
	}
	if short, full := pathTerminal("namespace_admin", f); short != "apps" || full != "apps" {
		t.Errorf("from the hop: %q, %q", short, full)
	}
	f.EscalationPath[0].BindingNamespace = ""
	if short, _ := pathTerminal("namespace_admin", f); short != "apps" {
		t.Errorf("from the finding ID: %q", short)
	}
	if short, full := pathTerminal("cluster_admin_equivalent", f); short != "" || full != "" {
		t.Errorf("a single-thing target has no terminal, got %q, %q", short, full)
	}
}

// TestBuildSinkGraphSpreadsPorts checks that several edges into one box land
// on different rows of its left side instead of one point.
func TestBuildSinkGraphSpreadsPorts(t *testing.T) {
	t.Parallel()

	var paths []models.Finding
	for i, name := range []string{"s1", "s2", "s3"} {
		paths = append(paths, apPath(models.SeverityHigh, []models.SubjectRef{apSA(name), apSA("via")}, []string{"action_" + strconv.Itoa(i), "wildcard_permission"}))
	}
	g := buildSinkGraph("cluster_admin_equivalent", "cluster-admin", paths)
	via := nodeByTitle(t, g, "via")
	rows := map[string]bool{}
	for _, e := range g.Edges {
		// Arrow paths start "M<x>,<y> ..." at the destination port.
		head := strings.TrimPrefix(strings.Fields(e.Arrow)[0], "M")
		xy := strings.SplitN(head, ",", 2)
		if x, _ := strconv.Atoi(xy[0]); x == via.X {
			rows[xy[1]] = true
		}
	}
	if len(rows) != 3 {
		t.Errorf("three edges into via should use three ports, got rows %v", rows)
	}
}
