package privesc

import (
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/remediation"
)

// This file is the query surface of the graph: the functions a caller uses to
// ask one question ("what does this identity reach?") without a full scan.
// The `paths` command is the caller. Everything here goes through the same
// search and the same finding builder as Analyzer.Analyze, so a path that a
// query prints has the same ID, score, and hops as the finding a scan reports.

// SubjectNode returns the graph node for an RBAC subject. BuildGraph makes a
// node for each ServiceAccount in the snapshot and for each subject that a
// binding names, so the false return means that the cluster has no such
// ServiceAccount and that no binding names the subject.
func SubjectNode(graph *models.EscalationGraph, ref models.SubjectRef) (*models.EscalationNode, bool) {
	node, ok := graph.Nodes[nodeID(ref)]
	if !ok || node.IsSink || node.IsExternal {
		return nil, false
	}
	return node, true
}

// PathsFrom returns one path for each sink that source reaches within maxDepth
// hops, in the same order as FindPaths. The false return means that source has
// no node in the graph (see SubjectNode).
//
// FindPaths does not start a search at a built-in system identity, a
// control-plane ServiceAccount, or an implicit group, because a scan that
// reported each of them would be noise on every cluster. PathsFrom has no such
// filter: the caller named the subject, so the caller gets its paths.
//
// For a built-in system identity the result is a lower bound. Three edge
// builders (Service backend hijack, node identity, traffic interception) add no
// edge for a system subject. The search also does not walk through a system
// subject in the middle of a chain.
func PathsFrom(graph *models.EscalationGraph, source models.SubjectRef, maxDepth int) ([]models.EscalationPath, bool) {
	if _, ok := SubjectNode(graph, source); !ok {
		return nil, false
	}
	if maxDepth <= 0 {
		maxDepth = DefaultMaxDepth
	}
	paths := pathsFromSource(graph, adjacency(graph), nodeID(source), maxDepth)
	sortPaths(paths)
	return paths, true
}

// FindingsFromPaths turns each path into the finding that a scan reports for it,
// with the structured remediation hint attached. Two paths that give the same
// finding ID yield one finding: the first in the input order.
func FindingsFromPaths(paths []models.EscalationPath, snapshot models.Snapshot) []models.Finding {
	findings := make([]models.Finding, 0, len(paths))
	seen := map[string]struct{}{}
	for _, path := range paths {
		finding := findingFromPath(path)
		if _, ok := seen[finding.ID]; ok {
			continue
		}
		finding.RemediationHint = remediation.ForPrivescPath(finding, snapshot)
		seen[finding.ID] = struct{}{}
		findings = append(findings, finding)
	}
	return findings
}

// targetTagPrefix is the tag that findingFromPath puts on each path finding to
// name its sink.
const targetTagPrefix = "target:"

// FindingTarget reads the sink back from a path finding: the target, and for the
// two targets that have more than one sink node, which one. The detail is the
// namespace for namespace_admin and the role ARN for aws_iam_role, and is empty
// for every other target. The false return means that the finding is not a path
// finding.
//
// It reads the fields that findingFromPath writes, so it also works on a
// finding loaded from findings.json.
func FindingTarget(f models.Finding) (target models.EscalationTarget, detail string, ok bool) {
	if len(f.EscalationPath) == 0 {
		return "", "", false
	}
	for _, tag := range f.Tags {
		if name, found := strings.CutPrefix(tag, targetTagPrefix); found {
			target = models.EscalationTarget(name)
			break
		}
	}
	if target == "" {
		return "", "", false
	}
	switch target {
	case models.TargetNamespaceAdmin:
		detail = f.Namespace
	case models.TargetAWSIAMRole:
		detail = f.EscalationPath[len(f.EscalationPath)-1].ToSubject.Name
	}
	return target, detail, true
}
