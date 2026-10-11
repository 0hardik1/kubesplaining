// Package report: per-target attack-path graph for the "Attack paths" tab.
//
// The tab shows one escalation target at a time (cluster-admin, node root,
// kube-system secrets, ...). For the selected target it draws every identity
// that can reach it as a left-to-right node-link diagram, with one column per
// "hops away from the target", and lists the same paths below the diagram.
//
// Three choices keep the picture readable where a whole-cluster graph turns
// into a hairball:
//
//   - One target per graph. Paths to different targets never share a canvas,
//     so every edge in view leads to the one node on the right.
//   - Grouping. Pure sources (identities nothing else reaches) that take the
//     exact same first step to the exact same next node collapse into one
//     "N identities" node. Forty ServiceAccounts that can all create pods in a
//     privileged namespace are one node with one thick edge, not forty rows.
//   - Layered layout. Columns come from the longest chain to the target, so
//     every edge points right; an edge that skips a column is routed through
//     a reserved slot in that column instead of across its boxes, and columns
//     are ordered and shifted to keep edges short and straight.
//
// The layout is computed here, deterministically, so the template emits plain
// SVG and the inline JS only toggles highlight classes. Each node and edge
// carries the indexes of the paths that pass through it, so the JS can focus a
// node and filter the path list without walking the graph itself.
package report

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// Layout geometry, shared by the Go layout and the SVG the template emits.
const (
	apNodeW       = 180
	apNodeH       = 50
	apTargetW     = 206
	apTargetH     = 66
	apVirtualH    = 10 // height reserved for an edge passing through a column
	apRowGap      = 14
	apVirtualGap  = 6
	apMarginX     = 28
	apMarginTop   = 58 // room for the column headers
	apMarginBot   = 26
	apMinStride   = 250 // minimum distance between column left edges
	apMaxStride   = 420 // columns never spread further apart than this
	apFitWidth    = 1120
	apLanePad     = 14
	apTileSize    = 26
	apPortInset   = 10  // ports stay this far from a box's top and bottom edges
	apPortGap     = 6   // vertical distance between neighbouring ports on one side
	apGroupMin    = 3   // smallest set of identical sources that collapses into one node
	apMaxNodes    = 150 // past this the diagram is skipped and only the list renders
	apTipMembers  = 12  // members named in a group node's tooltip before "and N more"
	apTitleRunes  = 18
	apSubRunes    = 22
	apTargetTitle = 20
	apLabelRunes  = 28
	apLabelCharW  = 6.0 // average glyph width of the 10.5px label font
	apLabelPad    = 16
	apSweeps      = 4 // barycenter ordering passes (alternating direction)
)

// SinkGraph is the laid-out diagram for one escalation target.
type SinkGraph struct {
	Width, Height int
	Columns       []GraphColumn
	Nodes         []PathNode
	Edges         []PathEdge
	// Skipped is set when the target has more than apMaxNodes nodes after
	// grouping. The template then shows a note and only the path list.
	Skipped    bool
	TotalNodes int
}

// GraphColumn is one column lane ("2 hops away", "Target"): X and W give the
// lane rectangle, the label is centered on it.
type GraphColumn struct {
	X, W  int
	Label string
}

// PathNode is one box in the diagram.
type PathNode struct {
	ID        string // stable within one SinkGraph
	Kind      string // source | via | group | sink | target
	Col       int    // column index from the left; drives the entrance stagger
	X, Y      int
	W, H      int
	Icon      string // glyph symbol suffix: sa | user | group | cloud | ns | crown | server | key | net | target
	Title     string // truncated to fit the box
	Sub       string // truncated second line
	Tip       string // full identity, for aria-label and the tooltip heading
	KindLabel string // tooltip second line ("ServiceAccount in namespace apps")
	Members   string // group nodes: the members named in the tooltip
	Paths     string // space-separated indexes of the paths through this node
	PathCount int
	SevClass  string // worst severity of those paths: crit | high | med | low
	Count     int    // group nodes: number of identities collapsed into this node
	// Text baselines and the icon tile position, precomputed so the template
	// stays free of arithmetic.
	TileY, TextX, TitleY, SubY int
}

// PathEdge is one directed hop between two boxes.
type PathEdge struct {
	D          string // path data: a bezier, or bezier/line segments through reserved slots
	Arrow      string // path data for the arrowhead at the destination
	Difficulty string // easy | moderate | hard
	Label      string // action title, for the hover tooltip
	Paths      string // space-separated indexes of the paths that take this hop
	Width      string // stroke width; group edges are drawn thicker
	Weight     int    // identities taking this hop (1 unless it leaves a group)
	// LX, LY place the action label pill, LW is the pill width, and Short is
	// the label text cut to fit. The label shows only while the edge is lit.
	LX, LY, LW int
	Short      string
}

// PathStep is one link in the compact chain shown on each path row:
// "<Label> -Action->" repeated, then the target.
type PathStep struct {
	Label      string // short subject name
	Full       string // Kind/namespace/name, for the title attribute
	Action     string // human-readable technique title
	Difficulty string
}

// apNode is the mutable accumulator for one node while the graph is built.
type apNode struct {
	key      string
	kind     string // source | via | group | sink | target | virtual
	icon     string
	title    string
	sub      string
	tip      string
	kindLbl  string
	paths    map[int]bool
	minPath  int // lowest path index through the node; paths are sorted worst-first
	inDeg    int
	out      []string // edge keys, in first-seen order
	members  []string // group nodes: member identities
	col      int
	x, y     int
	w, h     int
	subject  models.SubjectRef
	isTarget bool
	virtual  bool
	// Segment adjacency: an edge that spans one column is one segment, a
	// longer edge is a chain of segments through virtual nodes. Ordering and
	// vertical placement only ever look at adjacent columns.
	segOut, segIn []apSegment
}

// apSegment is one column-to-column piece of an edge.
type apSegment struct {
	node string // the node at the other end
	edge string // the edge this segment belongs to
}

type apEdge struct {
	key        string
	from, to   string
	action     string
	label      string
	difficulty string
	paths      map[int]bool
	weight     int
	via        []string // virtual node keys, left to right, for an edge spanning several columns
	// Port positions, assigned after vertical placement.
	y1, y2 int
}

// graphBuilder accumulates nodes and edges in first-seen order so the layout
// is deterministic for a given set of paths.
type graphBuilder struct {
	nodes     map[string]*apNode
	nodeOrder []string
	edges     map[string]*apEdge
	edgeOrder []string
}

func newGraphBuilder() *graphBuilder {
	return &graphBuilder{nodes: map[string]*apNode{}, edges: map[string]*apEdge{}}
}

func (b *graphBuilder) ensure(key string) *apNode {
	if n, ok := b.nodes[key]; ok {
		return n
	}
	n := &apNode{key: key, paths: map[int]bool{}, minPath: -1, w: apNodeW, h: apNodeH}
	b.nodes[key] = n
	b.nodeOrder = append(b.nodeOrder, key)
	return n
}

func (b *graphBuilder) subjectNode(s models.SubjectRef) *apNode {
	n := b.ensure("s:" + s.Key())
	n.subject = s
	return n
}

// waypointNode is an intermediate sink on a path: a hop whose destination is
// not an identity but a position (namespace admin in some namespace) that the
// next hop builds on. It is keyed on the action and namespace so two paths
// through the same position share one box.
func (b *graphBuilder) waypointNode(hop models.EscalationHop) *apNode {
	ns := hop.BindingNamespace
	if ns == "" {
		ns = hop.FromSubject.Namespace
	}
	n := b.ensure("w:" + hop.Action + ":" + ns)
	if n.kind == "" {
		n.kind = "sink"
		n.icon = "ns"
		if ns != "" {
			n.title = "Namespace admin"
			n.sub = "in " + ns
			n.tip = "Namespace admin in " + ns
			n.kindLbl = "An intermediate target: admin rights in the namespace, which the next hop builds on."
		} else {
			n.title = "Intermediate target"
			n.sub = actionTitle(hop.Action)
			n.tip = n.title + ": " + n.sub
			n.kindLbl = "A position the next hop builds on."
		}
	}
	return n
}

func (b *graphBuilder) touch(n *apNode, i int) {
	n.paths[i] = true
	if n.minPath < 0 || i < n.minPath {
		n.minPath = i
	}
}

func (b *graphBuilder) addEdge(from, to *apNode, hop models.EscalationHop, i int) {
	ek := from.key + "\x00" + to.key + "\x00" + hop.Action
	e, ok := b.edges[ek]
	if !ok {
		e = &apEdge{key: ek, from: from.key, to: to.key, action: hop.Action, label: actionTitle(hop.Action),
			difficulty: escDifficultyClass(hop.Difficulty), paths: map[int]bool{}, weight: 1}
		b.edges[ek] = e
		b.edgeOrder = append(b.edgeOrder, ek)
		from.out = append(from.out, ek)
		to.inDeg++
	}
	e.paths[i] = true
}

// buildSinkGraph lays out the paths to one target. paths must already be in
// display order (worst first): the index of a path in that slice is the index
// the template gives its row in the path list.
func buildSinkGraph(sinkSlug, sinkTitle string, paths []models.Finding) SinkGraph {
	b := newGraphBuilder()
	target := b.ensure("target")
	target.isTarget = true
	target.kind = "target"
	target.icon = targetIcon(sinkSlug)
	target.w, target.h = apTargetW, apTargetH

	terminals := map[string]bool{}
	var terminalOrder []string
	for i, f := range paths {
		b.touch(target, i)
		hops := f.EscalationPath
		// cur is where the attacker stands before the hop: the previous hop's
		// destination, which for an intermediate sink is the waypoint box.
		var cur *apNode
		for hi, hop := range hops {
			from := cur
			if from == nil || (from.kind != "sink" && from.subject.Key() != hop.FromSubject.Key()) {
				from = b.subjectNode(hop.FromSubject)
			}
			var to *apNode
			switch {
			case hi == len(hops)-1:
				// The last hop always lands on the target, even when the sink has
				// a name of its own (an external IAM role); the name goes on the
				// target's tooltip and the path row instead.
				to = target
			case hop.ToSubject.Name != "":
				to = b.subjectNode(hop.ToSubject)
			default:
				to = b.waypointNode(hop)
			}
			b.touch(from, i)
			b.touch(to, i)
			if from != to {
				b.addEdge(from, to, hop, i)
			}
			cur = to
		}
		if _, full := pathTerminal(sinkSlug, f); full != "" && !terminals[full] {
			terminals[full] = true
			terminalOrder = append(terminalOrder, full)
		}
	}

	for _, key := range b.nodeOrder {
		n := b.nodes[key]
		if n.isTarget || n.kind == "sink" {
			continue
		}
		n.title, n.sub = pathNodeLabels(n.subject)
		n.tip = subjectTip(n.subject)
		n.kindLbl = subjectKindLabel(n.subject)
		n.icon = subjectIcon(n.subject)
		if n.inDeg == 0 {
			n.kind = "source"
		} else {
			n.kind = "via"
		}
	}
	target.title = sinkTitle
	target.sub = pluralCount(len(paths), "path", "paths")
	target.tip = sinkTitle
	target.kindLbl = target.sub + " end here."
	if noun := terminalNoun(sinkSlug, len(terminalOrder)); noun != "" {
		shorts := make([]string, len(terminalOrder))
		for i, full := range terminalOrder {
			shorts[i] = shortTerminal(full)
		}
		target.kindLbl = fmt.Sprintf("%s %s: %s.", strconv.Itoa(len(terminalOrder)), noun, strings.Join(shorts, ", "))
	}

	b.groupIdenticalSources()

	if len(b.nodeOrder) > apMaxNodes {
		return SinkGraph{Skipped: true, TotalNodes: len(b.nodeOrder)}
	}

	maxCol := b.layer()
	b.virtualize()
	byCol := b.order(maxCol)
	height := b.place(byCol)
	b.assignPorts()

	stride := apMinStride
	if maxCol > 0 {
		stride = (apFitWidth - 2*apMarginX - apTargetW) / maxCol
		stride = max(apMinStride, min(apMaxStride, stride))
	}
	xOf := func(col int) int { return apMarginX + col*stride }
	for _, key := range b.nodeOrder {
		n := b.nodes[key]
		n.x = xOf(n.col)
	}

	g := SinkGraph{
		Width:  2*apMarginX + maxCol*stride + apTargetW,
		Height: height,
	}
	for c := 0; c <= maxCol; c++ {
		w := apNodeW
		if c == maxCol {
			w = apTargetW
		}
		g.Columns = append(g.Columns, GraphColumn{X: xOf(c) - apLanePad, W: w + 2*apLanePad, Label: hopsAwayLabel(maxCol - c)})
	}

	ids := map[string]string{}
	for c, col := range byCol {
		for _, key := range col {
			n := b.nodes[key]
			if n.virtual {
				continue
			}
			id := "n" + strconv.Itoa(len(g.Nodes))
			ids[key] = id
			pn := PathNode{
				ID:        id,
				Kind:      n.kind,
				Col:       c,
				X:         n.x,
				Y:         n.y,
				W:         n.w,
				H:         n.h,
				Icon:      n.icon,
				Title:     truncLabel(n.title, apTitleRunes),
				Sub:       truncLabel(n.sub, apSubRunes),
				Tip:       n.tip,
				KindLabel: n.kindLbl,
				Paths:     pathIndexList(n.paths),
				PathCount: len(n.paths),
				SevClass:  severityClass(paths[n.minPath].Severity),
				Count:     len(n.members),
				TileY:     (n.h - apTileSize) / 2,
				TextX:     11 + apTileSize + 10,
				TitleY:    n.h/2 - 3,
				SubY:      n.h/2 + 12,
			}
			if n.isTarget {
				pn.Title = truncLabel(sinkTitle, apTargetTitle)
			}
			if n.kind == "group" {
				pn.Members = groupTip(n.members)
			}
			g.Nodes = append(g.Nodes, pn)
		}
	}

	edgeOrder := append([]string(nil), b.edgeOrder...)
	sort.SliceStable(edgeOrder, func(i, j int) bool {
		a, c := b.edges[edgeOrder[i]], b.edges[edgeOrder[j]]
		if ids[a.from] != ids[c.from] {
			return nodeIndex(ids[a.from]) < nodeIndex(ids[c.from])
		}
		if ids[a.to] != ids[c.to] {
			return nodeIndex(ids[a.to]) < nodeIndex(ids[c.to])
		}
		return a.action < c.action
	})
	for _, ek := range edgeOrder {
		e := b.edges[ek]
		from, to := b.nodes[e.from], b.nodes[e.to]
		width := "1.6"
		if e.weight > 1 {
			width = strconv.FormatFloat(min(5.0, 1.6+float64(e.weight)/4), 'f', 1, 64)
		}
		label := e.label
		if e.weight > 1 {
			label = fmt.Sprintf("%s (%d identities)", e.label, e.weight)
		}
		x1, y1 := from.x+from.w, e.y1
		x2, y2 := to.x, e.y2
		d, lx, ly := b.edgePath(e, x1, y1, x2, y2)
		short := truncLabel(e.label, apLabelRunes)
		g.Edges = append(g.Edges, PathEdge{
			D:          d,
			Arrow:      fmt.Sprintf("M%d,%d l-7,-3.6 v7.2 z", x2, y2),
			Difficulty: e.difficulty,
			Label:      label,
			Paths:      pathIndexList(e.paths),
			Width:      width,
			Weight:     e.weight,
			LX:         lx,
			LY:         ly,
			LW:         int(float64(len([]rune(short)))*apLabelCharW) + apLabelPad,
			Short:      short,
		})
	}
	return g
}

// groupIdenticalSources collapses pure sources that share an identical set of
// outgoing hops (same action to the same next node) into one group node, when
// at least apGroupMin of them do. It rewrites the builder's nodes and edges in
// place.
func (b *graphBuilder) groupIdenticalSources() {
	bySig := map[string][]string{}
	var sigOrder []string
	for _, key := range b.nodeOrder {
		n := b.nodes[key]
		if n.kind != "source" {
			continue
		}
		outs := make([]string, 0, len(n.out))
		for _, ek := range n.out {
			e := b.edges[ek]
			outs = append(outs, e.to+"\x00"+e.action)
		}
		sort.Strings(outs)
		sig := strings.Join(outs, "\x01")
		if _, ok := bySig[sig]; !ok {
			sigOrder = append(sigOrder, sig)
		}
		bySig[sig] = append(bySig[sig], key)
	}

	removedNodes := map[string]bool{}
	removedEdges := map[string]bool{}
	var addedNodes, addedEdges []string
	for gi, sig := range sigOrder {
		members := bySig[sig]
		if len(members) < apGroupMin {
			continue
		}
		gkey := "g:" + strconv.Itoa(gi)
		group := &apNode{key: gkey, kind: "group", paths: map[int]bool{}, minPath: -1, w: apNodeW, h: apNodeH}
		kinds := map[string]bool{}
		namespaces := map[string]bool{}
		merged := map[string]*apEdge{}
		var mergedOrder []string
		for _, mk := range members {
			m := b.nodes[mk]
			removedNodes[mk] = true
			group.members = append(group.members, m.tip)
			kinds[m.subject.Kind] = true
			if m.subject.Namespace != "" {
				namespaces[m.subject.Namespace] = true
			}
			for p := range m.paths {
				group.paths[p] = true
			}
			if group.minPath < 0 || m.minPath < group.minPath {
				group.minPath = m.minPath
			}
			for _, ek := range m.out {
				e := b.edges[ek]
				removedEdges[ek] = true
				mkey := gkey + "\x00" + e.to + "\x00" + e.action
				me, ok := merged[mkey]
				if !ok {
					me = &apEdge{key: mkey, from: gkey, to: e.to, action: e.action, label: e.label,
						difficulty: e.difficulty, paths: map[int]bool{}}
					merged[mkey] = me
					mergedOrder = append(mergedOrder, mkey)
					group.out = append(group.out, mkey)
				}
				me.weight++
				for p := range e.paths {
					me.paths[p] = true
				}
			}
		}
		group.title, group.sub = groupLabels(len(members), kinds, namespaces)
		group.tip = group.title + " " + group.sub
		group.kindLbl = "Each of these identities takes the same first step."
		group.icon = "group"
		if len(kinds) == 1 {
			for k := range kinds {
				group.icon = subjectIcon(models.SubjectRef{Kind: k})
			}
		}
		b.nodes[gkey] = group
		addedNodes = append(addedNodes, gkey)
		for _, mkey := range mergedOrder {
			b.edges[mkey] = merged[mkey]
			addedEdges = append(addedEdges, mkey)
		}
	}

	if len(addedNodes) == 0 {
		return
	}
	newNodes := make([]string, 0, len(b.nodeOrder))
	for _, key := range b.nodeOrder {
		if !removedNodes[key] {
			newNodes = append(newNodes, key)
		}
	}
	newEdges := make([]string, 0, len(b.edgeOrder))
	for _, ek := range b.edgeOrder {
		if !removedEdges[ek] {
			newEdges = append(newEdges, ek)
		}
	}
	b.nodeOrder = append(newNodes, addedNodes...)
	b.edgeOrder = append(newEdges, addedEdges...)
}

// layer assigns every node a column from the length of the longest chain
// between it and the target (Kahn's algorithm over reverse edges), so every
// edge points right. Returns the index of the target column. Nodes on a cycle
// never drain from the queue; they keep the deepest layer they were given,
// which can leave an edge inside one column, drawn as a loop.
func (b *graphBuilder) layer() int {
	succ := map[string]map[string]bool{}
	pred := map[string][]string{}
	for _, ek := range b.edgeOrder {
		e := b.edges[ek]
		if succ[e.from] == nil {
			succ[e.from] = map[string]bool{}
		}
		if !succ[e.from][e.to] {
			succ[e.from][e.to] = true
			pred[e.to] = append(pred[e.to], e.from)
		}
	}
	remaining := map[string]int{}
	layer := map[string]int{}
	var queue []string
	for _, key := range b.nodeOrder {
		remaining[key] = len(succ[key])
		if remaining[key] == 0 {
			queue = append(queue, key)
		}
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, p := range pred[cur] {
			if layer[cur]+1 > layer[p] {
				layer[p] = layer[cur] + 1
			}
			remaining[p]--
			if remaining[p] == 0 {
				queue = append(queue, p)
			}
		}
	}
	maxLayer := 0
	for _, key := range b.nodeOrder {
		if remaining[key] > 0 && layer[key] == 0 {
			layer[key] = 1
		}
		if layer[key] > maxLayer {
			maxLayer = layer[key]
		}
	}
	for _, key := range b.nodeOrder {
		b.nodes[key].col = maxLayer - layer[key]
	}
	return maxLayer
}

// virtualize splits every edge into column-to-column segments. An edge that
// skips columns gets a virtual node in each column it passes, which reserves
// vertical room there so the edge is routed between boxes instead of across
// them. Edges that do not point right (cycles) get no segments and are drawn
// as loops.
func (b *graphBuilder) virtualize() {
	for _, ek := range b.edgeOrder {
		e := b.edges[ek]
		from, to := b.nodes[e.from], b.nodes[e.to]
		span := to.col - from.col
		if span < 1 {
			continue
		}
		prev := e.from
		for c := from.col + 1; c < to.col; c++ {
			vk := "v:" + ek + ":" + strconv.Itoa(c)
			v := &apNode{key: vk, kind: "virtual", virtual: true, col: c, paths: e.paths, minPath: from.minPath, title: from.title, w: apNodeW, h: apVirtualH}
			b.nodes[vk] = v
			b.nodeOrder = append(b.nodeOrder, vk)
			e.via = append(e.via, vk)
			b.segment(prev, vk, ek)
			prev = vk
		}
		b.segment(prev, e.to, ek)
	}
}

func (b *graphBuilder) segment(from, to, edge string) {
	b.nodes[from].segOut = append(b.nodes[from].segOut, apSegment{node: to, edge: edge})
	b.nodes[to].segIn = append(b.nodes[to].segIn, apSegment{node: from, edge: edge})
}

// order arranges each column top to bottom. It starts worst-path-first, then
// runs alternating barycenter sweeps (each node moves next to the average
// position of its neighbours in the column it was sorted against) and keeps
// the ordering with the fewest edge crossings. Nodes that feed the same next
// node end up adjacent, which is what makes a fan-in graph readable.
func (b *graphBuilder) order(maxCol int) [][]string {
	byCol := make([][]string, maxCol+1)
	for _, key := range b.nodeOrder {
		n := b.nodes[key]
		byCol[n.col] = append(byCol[n.col], key)
	}
	tie := func(x, y *apNode) bool {
		if x.minPath != y.minPath {
			return x.minPath < y.minPath
		}
		if x.title != y.title {
			return x.title < y.title
		}
		return x.key < y.key
	}
	for _, col := range byCol {
		sort.SliceStable(col, func(i, j int) bool { return tie(b.nodes[col[i]], b.nodes[col[j]]) })
	}

	clone := func(cols [][]string) [][]string {
		out := make([][]string, len(cols))
		for i, c := range cols {
			out[i] = append([]string(nil), c...)
		}
		return out
	}
	positions := func(cols [][]string) map[string]float64 {
		pos := map[string]float64{}
		for _, col := range cols {
			for i, key := range col {
				pos[key] = (float64(i) + 0.5) / float64(len(col))
			}
		}
		return pos
	}
	sortCol := func(c int, bySucc bool) {
		col := byCol[c]
		pos := positions(byCol)
		bary := map[string]float64{}
		for _, key := range col {
			n := b.nodes[key]
			segs := n.segOut
			if !bySucc {
				segs = n.segIn
			}
			sum, cnt := 0.0, 0
			for _, s := range segs {
				sum += pos[s.node]
				cnt++
			}
			if cnt == 0 {
				bary[key] = pos[key] // nothing to align with: hold position
			} else {
				bary[key] = sum / float64(cnt)
			}
		}
		sort.SliceStable(col, func(i, j int) bool {
			if bary[col[i]] != bary[col[j]] {
				return bary[col[i]] < bary[col[j]]
			}
			return tie(b.nodes[col[i]], b.nodes[col[j]])
		})
	}

	best, bestX := clone(byCol), b.crossings(byCol)
	for sweep := 0; sweep < apSweeps; sweep++ {
		if sweep%2 == 0 {
			for c := maxCol - 1; c >= 0; c-- {
				sortCol(c, true)
			}
		} else {
			for c := 1; c <= maxCol; c++ {
				sortCol(c, false)
			}
		}
		if x := b.crossings(byCol); x < bestX {
			best, bestX = clone(byCol), x
		}
	}
	return best
}

// crossings counts pairs of segments between adjacent columns that cross.
func (b *graphBuilder) crossings(byCol [][]string) int {
	index := map[string]int{}
	for _, col := range byCol {
		for i, key := range col {
			index[key] = i
		}
	}
	total := 0
	for c := 0; c+1 < len(byCol); c++ {
		type seg struct{ a, z int }
		var segs []seg
		for _, key := range byCol[c] {
			for _, s := range b.nodes[key].segOut {
				segs = append(segs, seg{index[key], index[s.node]})
			}
		}
		for i := 0; i < len(segs); i++ {
			for j := i + 1; j < len(segs); j++ {
				if (segs[i].a < segs[j].a && segs[i].z > segs[j].z) || (segs[i].a > segs[j].a && segs[i].z < segs[j].z) {
					total++
				}
			}
		}
	}
	return total
}

// place stacks each column, then shifts whole columns so their edges to the
// columns already placed are as straight as possible on average, working
// outward from the tallest column. Every column stays within the tallest one's
// vertical extent, so the canvas height is set by the tallest column alone.
// Returns the canvas height.
func (b *graphBuilder) place(byCol [][]string) int {
	colH := make([]int, len(byCol))
	for c, col := range byCol {
		y := 0
		for i, key := range col {
			n := b.nodes[key]
			if i > 0 {
				y += gapBetween(b.nodes[col[i-1]], n)
			}
			n.y = y
			y += n.h
		}
		colH[c] = y
	}
	anchor := 0
	for c, h := range colH {
		if h > colH[anchor] {
			anchor = c
		}
	}
	tallest := colH[anchor]
	shift := make([]int, len(byCol))
	placed := map[int]bool{anchor: true}
	for d := 1; d < len(byCol); d++ {
		for _, c := range []int{anchor + d, anchor - d} {
			if c < 0 || c >= len(byCol) {
				continue
			}
			sum, cnt := 0.0, 0
			for _, key := range byCol[c] {
				n := b.nodes[key]
				segs := append(append([]apSegment(nil), n.segOut...), n.segIn...)
				for _, s := range segs {
					nb := b.nodes[s.node]
					if !placed[nb.col] {
						continue
					}
					sum += float64(nb.y+shift[nb.col]+nb.h/2) - float64(n.y+n.h/2)
					cnt++
				}
			}
			s := (tallest - colH[c]) / 2
			if cnt > 0 {
				s = int(math.Round(sum / float64(cnt)))
			}
			shift[c] = max(0, min(tallest-colH[c], s))
			placed[c] = true
		}
	}
	for c, col := range byCol {
		for _, key := range col {
			b.nodes[key].y += shift[c] + apMarginTop
		}
	}
	return apMarginTop + tallest + apMarginBot
}

// gapBetween is the vertical gap between two stacked slots: boxes keep the
// full row gap, a reserved edge slot needs less.
func gapBetween(a, c *apNode) int {
	if a.virtual || c.virtual {
		return apVirtualGap
	}
	return apRowGap
}

// assignPorts spreads the edges that share one side of a box along that side,
// ordered by where the other end sits, so arrowheads and tails never pile onto
// one point. Virtual nodes are pass-through points and keep their center.
func (b *graphBuilder) assignPorts() {
	center := func(n *apNode) int { return n.y + n.h/2 }
	for _, key := range b.nodeOrder {
		n := b.nodes[key]
		if n.virtual {
			continue
		}
		// Edges leaving this box, ordered by the row of their first stop.
		outs := append([]apSegment(nil), n.segOut...)
		sort.SliceStable(outs, func(i, j int) bool { return center(b.nodes[outs[i].node]) < center(b.nodes[outs[j].node]) })
		for i, s := range outs {
			b.edges[s.edge].y1 = portY(n, i, len(outs))
		}
		ins := append([]apSegment(nil), n.segIn...)
		sort.SliceStable(ins, func(i, j int) bool { return center(b.nodes[ins[i].node]) < center(b.nodes[ins[j].node]) })
		for i, s := range ins {
			b.edges[s.edge].y2 = portY(n, i, len(ins))
		}
	}
	// Loops (edges that do not point right) have no segments: use the centers.
	for _, ek := range b.edgeOrder {
		e := b.edges[ek]
		from, to := b.nodes[e.from], b.nodes[e.to]
		if to.col-from.col < 1 {
			e.y1, e.y2 = center(from), center(to)
		}
	}
}

// portY is the y of port idx of count on one side of a box: centered for one
// port, otherwise spread apPortGap apart around the center, never closer than
// apPortInset to the box's edge.
func portY(n *apNode, idx, count int) int {
	mid := n.y + n.h/2
	if count <= 1 {
		return mid
	}
	span := min(apPortGap*(count-1), n.h-2*apPortInset)
	return mid - span/2 + span*idx/(count-1)
}

// edgePath draws an edge from its source port (x1,y1) to its destination port
// (x2,y2) and returns the path data plus the label anchor. An edge that spans
// several columns runs straight through its reserved slots and curves only in
// the gaps between columns; a loop (an edge that does not point right) bulges
// out and back.
func (b *graphBuilder) edgePath(e *apEdge, x1, y1, x2, y2 int) (d string, lx, ly int) {
	if x2 <= x1 {
		d = fmt.Sprintf("M%d,%d C%d,%d %d,%d %d,%d", x1, y1, x1+90, y1, x2-90, y2, x2, y2)
		return d, (x1 + x2) / 2, (y1 + y2) / 2
	}
	pts := [][2]int{{x1, y1}}
	for _, vk := range e.via {
		v := b.nodes[vk]
		vy := v.y + v.h/2
		pts = append(pts, [2]int{v.x, vy}, [2]int{v.x + v.w, vy})
	}
	pts = append(pts, [2]int{x2, y2})
	var sb strings.Builder
	fmt.Fprintf(&sb, "M%d,%d", pts[0][0], pts[0][1])
	for i := 0; i+1 < len(pts); i++ {
		a, z := pts[i], pts[i+1]
		if i%2 == 1 {
			fmt.Fprintf(&sb, " L%d,%d", z[0], z[1])
			continue
		}
		dx := max(30, (z[0]-a[0])/2)
		fmt.Fprintf(&sb, " C%d,%d %d,%d %d,%d", a[0]+dx, a[1], z[0]-dx, z[1], z[0], z[1])
	}
	if len(e.via) > 0 {
		v := b.nodes[e.via[0]]
		return sb.String(), v.x + v.w/2, v.y + v.h/2
	}
	// A cubic bezier with mirrored horizontal control points passes through
	// the midpoint of its endpoints at t=0.5.
	return sb.String(), (x1 + x2) / 2, (y1 + y2) / 2
}

// buildPathSteps renders a path's hops as the compact chain shown on its row.
func buildPathSteps(hops []models.EscalationHop) []PathStep {
	steps := make([]PathStep, 0, len(hops))
	for _, hop := range hops {
		label, _ := pathNodeLabels(hop.FromSubject)
		steps = append(steps, PathStep{
			Label:      label,
			Full:       subjectTip(hop.FromSubject),
			Action:     actionTitle(hop.Action),
			Difficulty: escDifficultyClass(hop.Difficulty),
		})
	}
	return steps
}

// pathTerminal names the specific place a path ends when the target is a
// family rather than one thing: the IAM role for aws_iam_role, the namespace
// for namespace_admin. Returns the short display form and the full name, both
// empty for targets that are one thing.
func pathTerminal(sinkSlug string, f models.Finding) (short, full string) {
	n := len(f.EscalationPath)
	if n == 0 {
		return "", ""
	}
	last := f.EscalationPath[n-1]
	if last.ToSubject.Name != "" {
		return shortTerminal(last.ToSubject.Name), last.ToSubject.Name
	}
	if sinkSlug == string(models.TargetNamespaceAdmin) {
		if last.BindingNamespace != "" {
			return last.BindingNamespace, last.BindingNamespace
		}
		const marker = ":namespace_admin:"
		if i := strings.LastIndex(f.ID, marker); i >= 0 {
			ns := f.ID[i+len(marker):]
			return ns, ns
		}
	}
	return "", ""
}

// shortTerminal trims an ARN or other slash-qualified name to its last segment.
func shortTerminal(full string) string {
	if i := strings.LastIndex(full, "/"); i >= 0 && i+1 < len(full) {
		return full[i+1:]
	}
	return full
}

// terminalNoun is the plural-aware noun for a family target's members.
func terminalNoun(sinkSlug string, n int) string {
	switch sinkSlug {
	case string(models.TargetAWSIAMRole):
		if n == 1 {
			return "IAM role"
		}
		return "IAM roles"
	case string(models.TargetNamespaceAdmin):
		if n == 1 {
			return "namespace"
		}
		return "namespaces"
	}
	return ""
}

// isAWSARN reports whether a subject is an external AWS identity, which the
// privesc graph models as a User named by its ARN.
func isAWSARN(s models.SubjectRef) bool {
	return strings.HasPrefix(s.Name, "arn:aws:")
}

// pathNodeLabels splits a subject into the box title (its name) and a short
// second line: the namespace for a ServiceAccount, the kind otherwise. An AWS
// IAM ARN shows its role name with the ARN kept for the tooltip.
func pathNodeLabels(s models.SubjectRef) (title, sub string) {
	title = s.Name
	if title == "" {
		title = "(unknown)"
	}
	switch {
	case isAWSARN(s):
		title = shortTerminal(s.Name)
		sub = "AWS IAM"
	case s.Kind == "ServiceAccount" && s.Namespace != "":
		sub = "SA · " + s.Namespace
	case s.Kind == "":
		sub = "Subject"
	case s.Namespace != "":
		sub = s.Kind + " · " + s.Namespace
	default:
		sub = s.Kind
	}
	return title, sub
}

// subjectTip is the full identity for tooltips and aria-labels.
func subjectTip(s models.SubjectRef) string {
	if isAWSARN(s) {
		return s.Name
	}
	return s.Key()
}

// subjectKindLabel is the tooltip's second line: what kind of identity this is
// and where it lives.
func subjectKindLabel(s models.SubjectRef) string {
	switch {
	case isAWSARN(s):
		return "AWS IAM identity, outside the cluster"
	case s.Kind == "ServiceAccount" && s.Namespace != "":
		return "ServiceAccount in namespace " + s.Namespace
	case s.Kind == "User":
		return "User (authenticated outside Kubernetes)"
	case s.Kind == "Group":
		return "Group of users or ServiceAccounts"
	case s.Kind != "" && s.Namespace != "":
		return s.Kind + " in namespace " + s.Namespace
	case s.Kind != "":
		return s.Kind
	}
	return ""
}

// subjectIcon picks the glyph drawn on a subject's box.
func subjectIcon(s models.SubjectRef) string {
	switch {
	case isAWSARN(s):
		return "cloud"
	case s.Kind == "ServiceAccount":
		return "sa"
	case s.Kind == "Group":
		return "group"
	default:
		return "user"
	}
}

// targetIcon picks the glyph drawn on the target box.
func targetIcon(slug string) string {
	switch slug {
	case string(models.TargetClusterAdmin), "cluster_admin", string(models.TargetSystemMasters):
		return "crown"
	case string(models.TargetNodeEscape), string(models.TargetNodeIdentity):
		return "server"
	case string(models.TargetKubeSystemSecrets), string(models.TargetTokenMint):
		return "key"
	case string(models.TargetAWSIAMRole):
		return "cloud"
	case string(models.TargetNamespaceAdmin):
		return "ns"
	case string(models.TargetTrafficIntercept):
		return "net"
	default:
		return "target"
	}
}

// groupLabels names a group node: "12 ServiceAccounts" / "in 5 namespaces".
func groupLabels(n int, kinds, namespaces map[string]bool) (title, sub string) {
	noun := "identities"
	if len(kinds) == 1 {
		for k := range kinds {
			switch k {
			case "ServiceAccount":
				noun = "ServiceAccounts"
			case "User":
				noun = "users"
			case "Group":
				noun = "groups"
			}
		}
	}
	title = fmt.Sprintf("%d %s", n, noun)
	switch len(namespaces) {
	case 0:
		sub = "cluster-scoped"
	case 1:
		for ns := range namespaces {
			sub = "in " + ns
		}
	default:
		sub = fmt.Sprintf("in %d namespaces", len(namespaces))
	}
	return title, sub
}

// groupTip lists a group's members for its tooltip, capped at apTipMembers.
func groupTip(members []string) string {
	sorted := append([]string(nil), members...)
	sort.Strings(sorted)
	if len(sorted) <= apTipMembers {
		return strings.Join(sorted, ", ")
	}
	return strings.Join(sorted[:apTipMembers], ", ") + fmt.Sprintf(", and %d more", len(sorted)-apTipMembers)
}

func hopsAwayLabel(d int) string {
	switch d {
	case 0:
		return "Target"
	case 1:
		return "1 hop away"
	default:
		return fmt.Sprintf("%d hops away", d)
	}
}

func pluralCount(n int, singular, plural string) string {
	if n == 1 {
		return "1 " + singular
	}
	return strconv.Itoa(n) + " " + plural
}

// pathIndexList renders a set of path indexes as a sorted, space-separated list.
func pathIndexList(set map[int]bool) string {
	idx := make([]int, 0, len(set))
	for i := range set {
		idx = append(idx, i)
	}
	sort.Ints(idx)
	parts := make([]string, len(idx))
	for i, v := range idx {
		parts[i] = strconv.Itoa(v)
	}
	return strings.Join(parts, " ")
}

// nodeIndex recovers the numeric part of a "n<idx>" node ID for sorting.
func nodeIndex(id string) int {
	n, _ := strconv.Atoi(strings.TrimPrefix(id, "n"))
	return n
}

// sinkTitle is the short target name used on the target picker and the target
// node: shorter than heroSinkLabel, which reads as part of a sentence.
func sinkTitle(slug string) string {
	switch slug {
	case string(models.TargetClusterAdmin), "cluster_admin":
		return "cluster-admin"
	case string(models.TargetSystemMasters):
		return "system:masters"
	case string(models.TargetKubeSystemSecrets):
		return "kube-system secrets"
	case string(models.TargetNodeEscape):
		return "Node root"
	case string(models.TargetNamespaceAdmin):
		return "Namespace admin"
	case string(models.TargetTokenMint):
		return "Token minting"
	case string(models.TargetAWSIAMRole):
		return "AWS IAM role"
	case string(models.TargetTrafficIntercept):
		return "Traffic interception"
	case string(models.TargetNodeIdentity):
		return "Node identity"
	case "":
		return "Other"
	default:
		return strings.ReplaceAll(slug, "_", " ")
	}
}

// sinkBlurb is one sentence on what reaching the target gives an attacker,
// shown above the target's graph.
func sinkBlurb(slug string) string {
	switch slug {
	case string(models.TargetClusterAdmin), "cluster_admin":
		return "Full control of the cluster: every resource, every namespace, every Secret."
	case string(models.TargetSystemMasters):
		return "Membership of system:masters, which bypasses RBAC entirely and cannot be revoked by editing bindings."
	case string(models.TargetKubeSystemSecrets):
		return "Read access to kube-system Secrets, which usually hold credentials for cluster-admin-level controllers."
	case string(models.TargetNodeEscape):
		return "Root on a node, which exposes every pod, Secret, and kubelet credential on that node."
	case string(models.TargetNamespaceAdmin):
		return "Admin rights inside a namespace: every workload and Secret in it."
	case string(models.TargetTokenMint):
		return "The ability to mint tokens for ServiceAccounts, and act as them."
	case string(models.TargetAWSIAMRole):
		return "Credentials for an AWS IAM role, which reaches outside the cluster into the cloud account."
	case string(models.TargetTrafficIntercept):
		return "A position on the wire for one or more Services: their clients send traffic to the attacker."
	case string(models.TargetNodeIdentity):
		return "A kubelet identity, which can read the Secrets and tokens of pods on the node it names."
	default:
		return ""
	}
}

// truncLabel shortens a label to fit a node box. The full text stays on the
// node's tooltip and aria-label, because SVG <text> does not wrap.
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

// escDifficultyClass normalizes a hop difficulty to the CSS class the template
// uses, defaulting unknown values to moderate (matching the graph's own default).
func escDifficultyClass(d string) string {
	switch d {
	case "easy", "moderate", "hard":
		return d
	default:
		return "moderate"
	}
}

// severityClass maps a severity to the short CSS class key used by the template.
func severityClass(s models.Severity) string {
	switch s {
	case models.SeverityCritical:
		return "crit"
	case models.SeverityHigh:
		return "high"
	case models.SeverityMedium:
		return "med"
	case models.SeverityLow:
		return "low"
	default:
		return "info"
	}
}
