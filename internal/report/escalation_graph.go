// Package report — whole escalation-graph layout. Unlike the curated 3-column
// attack graph (buildAttackGraph, capped at 10 capabilities) and the static,
// exhaustive Escalation-paths list, this renders the WHOLE escalation graph the
// scan discovered as one interactive node-link diagram: the union of every
// KUBE-PRIVESC-PATH-* finding's hop chain, so each subject → … → sink route is a
// connected component and shared intermediates (a controller SA several subjects
// can reach) show up as the fan-in they are.
//
// It is derived purely from findings, like every other report builder — it does
// not re-run privesc.BuildGraph — so it shows exactly the edges that actually
// reach a sink (no dead-end RBAC that leads nowhere), which is the honest attack
// surface rather than a raw adjacency dump. Coordinates are precomputed here in a
// deterministic left-to-right layered layout (sources on the left, sinks pinned to
// the right lane), so the template emits raw SVG and the inline JS only toggles
// highlight classes.
package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// Layout geometry. Kept as named constants so the Go layout and the SVG the
// template emits agree by construction.
const (
	egNodeW     = 178
	egNodeH     = 46
	egColStride = 244 // egNodeW + horizontal gap for edge routing
	egRowStride = 66  // egNodeH + vertical gap
	egMarginX   = 28
	egMarginTop = 30
	egMarginBot = 28
	egMaxNodes  = 240 // safety cap: beyond this the SVG is unwieldy; see buildEscalationGraphView
)

// egNode is one laid-out node in the whole-graph view.
type egNode struct {
	ID        string // "subj:<SubjectRef.Key()>" or "sink:<slug>"
	Kind      string // "source" | "intermediate" | "sink"
	X, Y      int
	W, H      int
	Title     string // primary label (subject name, or sink phrase)
	Sub       string // secondary label (namespace / kind, or blank for sinks)
	SevClass  string // sink coloring: crit | high | med
	AriaLabel string

	col     int
	subject bool
}

// egEdge is one laid-out directed edge (one hop) between two nodes.
type egEdge struct {
	ID         string
	From       string
	To         string
	D          string // cubic-bezier path data
	Difficulty string // easy | moderate | hard (drives stroke color / dashing)
	Label      string // human-readable action title, used as the SVG <title> tooltip
}

// EscalationGraphView is the precomputed model for the "Escalation graph" tab.
type EscalationGraphView struct {
	Width, Height int
	Nodes         []egNode
	Edges         []egEdge
	// Counts shown in the tab header and used to gate the tab (Nodes empty → no tab).
	SubjectCount int
	SinkCount    int
	EdgeCount    int
	// Truncated is set when the graph exceeded egMaxNodes and was not rendered;
	// the template shows a note pointing at the exhaustive Escalation-paths tab.
	Truncated  bool
	TotalNodes int
}

// egNodeBuild is the mutable accumulator used while collecting nodes before layout.
type egNodeBuild struct {
	kind     string
	title    string
	sub      string
	sevClass string
	subject  bool
	isTarget bool // appeared as the destination of some hop (so: not a pure source)
}

// buildEscalationGraphView assembles the whole-graph view from the KUBE-PRIVESC-PATH-*
// findings. Returns the zero value (empty Nodes) when there are no paths, which both
// the tab button and the section gate on.
func buildEscalationGraphView(findings []models.Finding) EscalationGraphView {
	nodes := map[string]*egNodeBuild{}
	order := []string{} // stable first-seen node order, so layout ties break deterministically

	ensure := func(id string) *egNodeBuild {
		if n, ok := nodes[id]; ok {
			return n
		}
		n := &egNodeBuild{}
		nodes[id] = n
		order = append(order, id)
		return n
	}

	type edgeRec struct {
		from, to, difficulty, label string
	}
	edgeSeen := map[string]bool{}
	var edges []edgeRec
	// adjacency among SUBJECT nodes only, for longest-path ranking.
	subjAdj := map[string][]string{}
	subjPred := map[string][]string{}

	for _, f := range findings {
		if len(f.EscalationPath) == 0 || !strings.HasPrefix(f.RuleID, "KUBE-PRIVESC-PATH-") {
			continue
		}
		sinkSlug := heroSinkSlug(f)
		sinkID := "sink:" + sinkSlug
		sn := ensure(sinkID)
		sn.kind = "sink"
		sn.title = heroSinkLabel(sinkSlug)
		sn.isTarget = true
		if sc := sinkSevClass(f.Severity); severityRank(sc) > severityRank(sn.sevClass) {
			sn.sevClass = sc
		}

		for _, hop := range f.EscalationPath {
			fromID := "subj:" + hop.FromSubject.Key()
			fn := ensure(fromID)
			fn.subject = true
			if fn.title == "" {
				fn.title, fn.sub = subjectNodeLabels(hop.FromSubject)
			}

			var toID string
			if hop.ToSubject.Name != "" {
				toID = "subj:" + hop.ToSubject.Key()
				tn := ensure(toID)
				tn.subject = true
				tn.isTarget = true
				if tn.title == "" {
					tn.title, tn.sub = subjectNodeLabels(hop.ToSubject)
				}
				subjAdj[fromID] = append(subjAdj[fromID], toID)
				subjPred[toID] = append(subjPred[toID], fromID)
			} else {
				toID = sinkID
			}

			key := fromID + "\x00" + toID + "\x00" + hop.Action
			if edgeSeen[key] {
				continue
			}
			edgeSeen[key] = true
			edges = append(edges, edgeRec{from: fromID, to: toID, difficulty: hop.Difficulty, label: actionTitle(hop.Action)})
		}
	}

	if len(order) == 0 {
		return EscalationGraphView{}
	}

	// Classify subject nodes: a subject that is never a hop destination is a source.
	for _, n := range nodes {
		if !n.subject {
			continue
		}
		if n.isTarget {
			n.kind = "intermediate"
		} else {
			n.kind = "source"
		}
	}

	if len(order) > egMaxNodes {
		return EscalationGraphView{Truncated: true, TotalNodes: len(order)}
	}

	// Longest-path rank for every subject over the subject-only subgraph. Sources
	// (no subject predecessor) rank 0; a cycle guard keeps a mutual-impersonation
	// pair from looping forever.
	rank := map[string]int{}
	inProgress := map[string]bool{}
	var computeRank func(id string) int
	computeRank = func(id string) int {
		if r, ok := rank[id]; ok {
			return r
		}
		if inProgress[id] {
			return 0 // break a cycle: treat this predecessor as rank 0
		}
		inProgress[id] = true
		r := 0
		for _, pred := range subjPred[id] {
			if pr := computeRank(pred) + 1; pr > r {
				r = pr
			}
		}
		delete(inProgress, id)
		rank[id] = r
		return r
	}
	maxSubjectRank := 0
	for id, n := range nodes {
		if n.subject {
			if r := computeRank(id); r > maxSubjectRank {
				maxSubjectRank = r
			}
		}
	}
	sinkCol := maxSubjectRank + 1

	// Assign each node to a column, then order and place nodes within each column.
	byCol := map[int][]string{}
	col := map[string]int{}
	for _, id := range order {
		n := nodes[id]
		c := sinkCol
		if n.subject {
			c = rank[id]
		}
		col[id] = c
		byCol[c] = append(byCol[c], id)
	}

	view := EscalationGraphView{}
	laid := map[string]*egNode{}
	maxRows := 0
	for c := 0; c <= sinkCol; c++ {
		ids := byCol[c]
		if len(ids) == 0 {
			continue
		}
		sort.SliceStable(ids, func(i, j int) bool {
			a, b := nodes[ids[i]], nodes[ids[j]]
			if !a.subject && !b.subject {
				// sinks: most dangerous first
				pa, pb := heroSinkPriority(strings.TrimPrefix(ids[i], "sink:")), heroSinkPriority(strings.TrimPrefix(ids[j], "sink:"))
				if pa != pb {
					return pa < pb
				}
			}
			if a.title != b.title {
				return a.title < b.title
			}
			return ids[i] < ids[j]
		})
		if len(ids) > maxRows {
			maxRows = len(ids)
		}
	}

	// Vertically center each column's nodes against the tallest column so the graph
	// reads as a balanced flow rather than everything pinned to the top.
	tallestHeight := maxRows * egRowStride
	for c := 0; c <= sinkCol; c++ {
		ids := byCol[c]
		if len(ids) == 0 {
			continue
		}
		colHeight := len(ids) * egRowStride
		offset := (tallestHeight - colHeight) / 2
		for i, id := range ids {
			n := nodes[id]
			ln := &egNode{
				ID:       id,
				Kind:     n.kind,
				X:        egMarginX + c*egColStride,
				Y:        egMarginTop + offset + i*egRowStride,
				W:        egNodeW,
				H:        egNodeH,
				Title:    truncLabel(n.title, 24),
				Sub:      truncLabel(n.sub, 26),
				SevClass: n.sevClass,
				col:      c,
				subject:  n.subject,
			}
			ln.AriaLabel = escNodeAria(n)
			laid[id] = ln
		}
	}

	// Emit nodes in a stable order (by column, then Y) for deterministic output.
	for c := 0; c <= sinkCol; c++ {
		ids := byCol[c]
		for _, id := range ids {
			if ln := laid[id]; ln != nil {
				view.Nodes = append(view.Nodes, *ln)
				if ln.subject {
					view.SubjectCount++
				} else {
					view.SinkCount++
				}
			}
		}
	}

	// Edges: cubic bezier from the right edge of the source node to the left edge of
	// the destination. Deterministic order (by from, to) for stable output.
	sort.SliceStable(edges, func(i, j int) bool {
		if edges[i].from != edges[j].from {
			return edges[i].from < edges[j].from
		}
		if edges[i].to != edges[j].to {
			return edges[i].to < edges[j].to
		}
		return edges[i].label < edges[j].label
	})
	for i, e := range edges {
		fn, tn := laid[e.from], laid[e.to]
		if fn == nil || tn == nil {
			continue
		}
		view.Edges = append(view.Edges, egEdge{
			ID:         fmt.Sprintf("egedge-%d", i),
			From:       e.from,
			To:         e.to,
			D:          escEdgePath(fn, tn),
			Difficulty: escDifficultyClass(e.difficulty),
			Label:      e.label,
		})
	}
	view.EdgeCount = len(view.Edges)

	width := egMarginX*2 + sinkCol*egColStride + egNodeW
	height := egMarginTop + tallestHeight + egMarginBot
	if height < egMarginTop+egRowStride+egMarginBot {
		height = egMarginTop + egRowStride + egMarginBot
	}
	view.Width = width
	view.Height = height
	return view
}

// escEdgePath returns a cubic-bezier "d" from the right-middle of from to the
// left-middle of to. Horizontal control points give the flow a left-to-right lean
// even when the two nodes sit in the same column (a rare same-rank hop).
func escEdgePath(from, to *egNode) string {
	x1 := from.X + from.W
	y1 := from.Y + from.H/2
	x2 := to.X
	y2 := to.Y + to.H/2
	dx := (x2 - x1) / 2
	if dx < 40 {
		dx = 40
	}
	return fmt.Sprintf("M%d,%d C%d,%d %d,%d %d,%d", x1, y1, x1+dx, y1, x2-dx, y2, x2, y2)
}

// subjectNodeLabels splits a subject into a primary name and a secondary
// kind/namespace line for the node card.
func subjectNodeLabels(s models.SubjectRef) (title, sub string) {
	title = s.Name
	if title == "" {
		title = "(unknown)"
	}
	kind := s.Kind
	if kind == "" {
		kind = "Subject"
	}
	if s.Namespace != "" {
		sub = kind + " · " + s.Namespace
	} else {
		sub = kind
	}
	return title, sub
}

// escNodeAria builds the accessible name for a node <g>.
func escNodeAria(n *egNodeBuild) string {
	switch {
	case !n.subject:
		return "Sink: " + n.title
	case n.kind == "source":
		return "Source subject " + n.title + " (" + n.sub + ")"
	default:
		return "Subject " + n.title + " (" + n.sub + ")"
	}
}

// truncLabel shortens a label to fit a node card, keeping the full text available
// on the node's aria-label. SVG <text> does not wrap, so an over-long ServiceAccount
// name would otherwise spill past the card.
func truncLabel(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	if max <= 1 {
		return "…"
	}
	return string(r[:max-1]) + "…"
}

// escDifficultyClass normalizes a hop difficulty to the CSS class the template uses,
// defaulting unknown values to moderate (matching the graph's own default).
func escDifficultyClass(d string) string {
	switch d {
	case "easy", "moderate", "hard":
		return d
	default:
		return "moderate"
	}
}

// sinkSevClass maps a finding severity to the sink node's color class.
func sinkSevClass(s models.Severity) string {
	switch s {
	case models.SeverityCritical:
		return "crit"
	case models.SeverityHigh:
		return "high"
	default:
		return "med"
	}
}

// severityRank orders the sink color classes so a sink reached by several chains
// keeps the most severe coloring.
func severityRank(class string) int {
	switch class {
	case "crit":
		return 3
	case "high":
		return 2
	case "med":
		return 1
	default:
		return 0
	}
}
