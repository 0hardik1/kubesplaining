// Package remediation generates structured fix payloads (kubectl patches, RBAC
// diffs, Kyverno / Gatekeeper policy snippets) for findings. Each per-analyzer
// generator lives in its own file (rbac.go, podsec.go, kyverno.go, gatekeeper.go)
// and is invoked from the corresponding analyzer's Finding-construction site.
//
// The package never mutates a Finding directly. It returns a
// *models.RemediationHint that the caller assigns to Finding.RemediationHint, so
// the generators stay pure and trivially testable.
package remediation

import (
	"fmt"
	"strings"
)

// unifiedDiff renders a textbook unified-diff hunk for a single before / after
// pair of YAML / text blobs. We hand-roll the format because (a) the only
// alternative in the Go stdlib is `internal/diff` which is not importable, and
// (b) we want the output deterministic across runs so test golden files are
// stable. The result matches `diff -u` shape closely enough that GitHub /
// editors render it as a syntax-highlighted patch.
//
// The header lines (`--- a/path`, `+++ b/path`) reference fromPath / toPath so
// the consumer can produce a `git apply`-able blob if it wants to. The single
// hunk covers the entire file (`@@ -1,L +1,M @@` where L and M are line counts)
// because the inputs are short YAML snippets: multi-hunk minimisation buys
// nothing for 20 line files.
//
// Lines that differ are rendered as `-old` / `+new` blocks; identical context
// lines as ` line`. The implementation uses a simple longest-common-subsequence
// (LCS) walk so removed and added blocks line up the way an operator expects
// to read them.
func unifiedDiff(fromPath, toPath, from, to string) string {
	fromLines := splitLines(from)
	toLines := splitLines(to)

	header := fmt.Sprintf("--- a/%s\n+++ b/%s\n@@ -1,%d +1,%d @@\n",
		fromPath, toPath, len(fromLines), len(toLines))

	var body strings.Builder
	ops := lcsDiff(fromLines, toLines)
	for _, op := range ops {
		switch op.kind {
		case opEqual:
			body.WriteString(" ")
			body.WriteString(op.line)
			body.WriteString("\n")
		case opDelete:
			body.WriteString("-")
			body.WriteString(op.line)
			body.WriteString("\n")
		case opInsert:
			body.WriteString("+")
			body.WriteString(op.line)
			body.WriteString("\n")
		}
	}
	return header + body.String()
}

// splitLines is strings.Split with the empty trailing element stripped so that
// `"a\n"` produces `["a"]` rather than `["a", ""]`. The diff routines assume
// every element is a real line; trailing-newline noise breaks the LCS table.
func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	lines := strings.Split(s, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// diffOp is one line in the rendered diff: equal context, a deletion, or an insertion.
type diffOp struct {
	kind diffKind
	line string
}

type diffKind int

const (
	opEqual diffKind = iota
	opDelete
	opInsert
)

// lcsDiff computes the longest-common-subsequence between two line slices and
// returns the diff operations needed to transform `a` into `b`. Time / space
// is O(len(a) * len(b)); fine for the 20-100 line YAML snippets we feed it.
//
// The walk backtracks through the LCS table to produce diff ops in forward
// order: equal lines surface as `opEqual`, removed-from-a lines as
// `opDelete`, added-from-b lines as `opInsert`. When a deletion and an
// insertion are adjacent, they form a "modified line" block in the rendered
// diff; we deliberately do not collapse them into a single op because the
// unified-diff format distinguishes the two anyway.
func lcsDiff(a, b []string) []diffOp {
	la, lb := len(a), len(b)
	// table[i][j] = length of LCS of a[i:] and b[j:].
	table := make([][]int, la+1)
	for i := range table {
		table[i] = make([]int, lb+1)
	}
	for i := la - 1; i >= 0; i-- {
		for j := lb - 1; j >= 0; j-- {
			if a[i] == b[j] {
				table[i][j] = table[i+1][j+1] + 1
			} else if table[i+1][j] >= table[i][j+1] {
				table[i][j] = table[i+1][j]
			} else {
				table[i][j] = table[i][j+1]
			}
		}
	}

	var ops []diffOp
	i, j := 0, 0
	for i < la && j < lb {
		switch {
		case a[i] == b[j]:
			ops = append(ops, diffOp{kind: opEqual, line: a[i]})
			i++
			j++
		case table[i+1][j] >= table[i][j+1]:
			ops = append(ops, diffOp{kind: opDelete, line: a[i]})
			i++
		default:
			ops = append(ops, diffOp{kind: opInsert, line: b[j]})
			j++
		}
	}
	for i < la {
		ops = append(ops, diffOp{kind: opDelete, line: a[i]})
		i++
	}
	for j < lb {
		ops = append(ops, diffOp{kind: opInsert, line: b[j]})
		j++
	}
	return ops
}
