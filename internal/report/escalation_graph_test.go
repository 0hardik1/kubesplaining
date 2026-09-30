package report

import (
	"strings"
	"testing"

	"github.com/0hardik1/kubesplaining/internal/models"
)

func egFindByID(v EscalationGraphView, id string) (egNode, bool) {
	for _, n := range v.Nodes {
		if n.ID == id {
			return n, true
		}
	}
	return egNode{}, false
}

// TestBuildEscalationGraphViewUnionAndLayout: two chains that share an intermediate
// subject collapse onto one node, the sink is shared, and the columns run
// sources → intermediate → sink left to right.
func TestBuildEscalationGraphViewUnionAndLayout(t *testing.T) {
	writer := models.SubjectRef{Kind: "ServiceAccount", Name: "writer", Namespace: "app"}
	victim := models.SubjectRef{Kind: "ServiceAccount", Name: "victim-sa", Namespace: "victim"}

	findings := []models.Finding{
		// writer → victim-sa → kube-system secrets (two hops; the CVE edge then a read)
		pathFinding("KUBE-PRIVESC-PATH-KUBE-SYSTEM-SECRETS", "kube_system_secrets", "writer", models.SeverityMedium, 4.0, []models.EscalationHop{
			{Step: 1, Action: "statefulset_cross_namespace_pod", Difficulty: "hard", FromSubject: writer, ToSubject: victim},
			{Step: 2, Action: "read_secrets", Difficulty: "easy", FromSubject: victim},
		}),
		// victim-sa → kube-system secrets (one hop) — shares the victim node and the sink
		pathFinding("KUBE-PRIVESC-PATH-KUBE-SYSTEM-SECRETS", "kube_system_secrets", "victim-sa", models.SeverityHigh, 7.6, []models.EscalationHop{
			{Step: 1, Action: "read_secrets", Difficulty: "easy", FromSubject: victim},
		}),
		// a non-path finding that must be ignored
		{ID: "z", RuleID: "KUBE-PRIVESC-006", Severity: models.SeverityHigh},
	}

	v := buildEscalationGraphView(findings)

	if v.SubjectCount != 2 {
		t.Errorf("SubjectCount = %d, want 2 (writer + victim-sa, deduped)", v.SubjectCount)
	}
	if v.SinkCount != 1 {
		t.Errorf("SinkCount = %d, want 1 (shared kube-system sink)", v.SinkCount)
	}
	if v.EdgeCount != 2 {
		t.Errorf("EdgeCount = %d, want 2 (the two read_secrets hops dedupe)", v.EdgeCount)
	}

	writerN, ok := egFindByID(v, "subj:ServiceAccount/app/writer")
	if !ok {
		t.Fatal("writer node missing")
	}
	if writerN.Kind != "source" {
		t.Errorf("writer Kind = %q, want source (never a hop destination)", writerN.Kind)
	}
	victimN, ok := egFindByID(v, "subj:ServiceAccount/victim/victim-sa")
	if !ok {
		t.Fatal("victim node missing")
	}
	if victimN.Kind != "intermediate" {
		t.Errorf("victim Kind = %q, want intermediate", victimN.Kind)
	}
	sinkN, ok := egFindByID(v, "sink:kube_system_secrets")
	if !ok {
		t.Fatal("sink node missing")
	}
	if sinkN.Kind != "sink" {
		t.Errorf("sink Kind = %q, want sink", sinkN.Kind)
	}
	// Left-to-right ordering: source X < intermediate X < sink X.
	if writerN.X >= victimN.X || victimN.X >= sinkN.X {
		t.Errorf("columns not ordered source<intermediate<sink: writer=%d victim=%d sink=%d", writerN.X, victimN.X, sinkN.X)
	}
	// The sink keeps the strongest coloring across the two chains (HIGH beats MEDIUM).
	if sinkN.SevClass != "high" {
		t.Errorf("sink SevClass = %q, want high (strongest of the reaching chains)", sinkN.SevClass)
	}
	// The hard hop is classed hard; nodes/edges stay within the canvas.
	var sawHard bool
	for _, e := range v.Edges {
		if e.Difficulty == "hard" {
			sawHard = true
		}
		if !strings.HasPrefix(e.D, "M") {
			t.Errorf("edge %s has malformed path %q", e.ID, e.D)
		}
	}
	if !sawHard {
		t.Error("expected one hard edge (statefulset_cross_namespace_pod)")
	}
	for _, n := range v.Nodes {
		if n.X < 0 || n.Y < 0 || n.X+n.W > v.Width || n.Y+n.H > v.Height {
			t.Errorf("node %s out of canvas bounds (%d,%d %dx%d in %dx%d)", n.ID, n.X, n.Y, n.W, n.H, v.Width, v.Height)
		}
	}
}

// TestBuildEscalationGraphViewEmpty: no path findings → zero-value view (the tab gates on this).
func TestBuildEscalationGraphViewEmpty(t *testing.T) {
	v := buildEscalationGraphView([]models.Finding{
		{ID: "a", RuleID: "KUBE-PRIVESC-006", Severity: models.SeverityHigh},
		{ID: "b", RuleID: "KUBE-NETPOL-COVERAGE-001", Severity: models.SeverityHigh},
	})
	if len(v.Nodes) != 0 || len(v.Edges) != 0 {
		t.Errorf("expected empty view, got %d nodes / %d edges", len(v.Nodes), len(v.Edges))
	}
}

// TestBuildEscalationGraphViewTruncates: a graph past the node cap returns Truncated
// with no drawn nodes, so the template shows the pointer note instead of an unusable SVG.
func TestBuildEscalationGraphViewTruncates(t *testing.T) {
	var findings []models.Finding
	for i := 0; i < egMaxNodes+5; i++ {
		src := models.SubjectRef{Kind: "ServiceAccount", Name: "s" + itoa(i), Namespace: "ns"}
		findings = append(findings, pathFinding("KUBE-PRIVESC-PATH-CLUSTER-ADMIN", "cluster_admin_equivalent", "s"+itoa(i), models.SeverityCritical, 9.0, []models.EscalationHop{
			{Step: 1, Action: "impersonate", Difficulty: "easy", FromSubject: src},
		}))
	}
	v := buildEscalationGraphView(findings)
	if !v.Truncated {
		t.Error("expected Truncated for an oversized graph")
	}
	if len(v.Nodes) != 0 {
		t.Errorf("truncated view should draw no nodes, got %d", len(v.Nodes))
	}
	if v.TotalNodes <= egMaxNodes {
		t.Errorf("TotalNodes = %d, want > %d", v.TotalNodes, egMaxNodes)
	}
}

// itoa avoids importing strconv just for the truncation test.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
