package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
	"github.com/0hardik1/kubesplaining/internal/report"
)

// isTTY reports whether w is a terminal-attached *os.File so ANSI styling is safe.
// Anything else (pipes, files, captured stdout under `make e2e`'s `tee`) gets plain text.
func isTTY(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	stat, err := f.Stat()
	if err != nil {
		return false
	}
	return stat.Mode()&os.ModeCharDevice != 0
}

type styler struct{ on bool }

func (s styler) wrap(code, text string) string {
	if !s.on {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}

func (s styler) green(t string) string  { return s.wrap("32", t) }
func (s styler) blue(t string) string   { return s.wrap("34", t) }
func (s styler) bold(t string) string   { return s.wrap("1", t) }
func (s styler) dim(t string) string    { return s.wrap("2", t) }
func (s styler) bgreen(t string) string { return s.wrap("1;32", t) }

// printScanResults emits the per-file lines, the machine-readable summary, and
// (TTY only) a banner pointing at the HTML report. When stdout is piped or
// redirected, the original `wrote %s` / `findings: total=...` format is preserved
// so CI parsers and the e2e script keep working.
//
// paths is the per-sink attack-path overview (see report.AttackPathOverviews).
// It prints after the `findings:` line in both modes, so the result that sets
// this tool apart is visible without opening the HTML report. Nothing prints
// when it is empty.
func printScanResults(w io.Writer, written []string, summary report.Summary, paths []report.AttackPathOverview) error {
	s := styler{on: isTTY(w)}

	for _, path := range written {
		var line string
		if s.on {
			line = fmt.Sprintf("  %s %s\n", s.green("✓"), path)
		} else {
			line = fmt.Sprintf("wrote %s\n", path)
		}
		if _, err := fmt.Fprint(w, line); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "findings: total=%d critical=%d high=%d medium=%d low=%d info=%d\n",
		summary.Total, summary.Critical, summary.High, summary.Medium, summary.Low, summary.Info); err != nil {
		return err
	}
	if err := printAttackPaths(w, s, paths); err != nil {
		return err
	}
	if !s.on {
		return nil
	}

	rule := strings.Repeat("═", 71)
	counts := fmt.Sprintf("%d findings · %d critical · %d high · %d medium · %d low · %d info",
		summary.Total, summary.Critical, summary.High, summary.Medium, summary.Low, summary.Info)

	var b strings.Builder
	fmt.Fprintf(&b, "\n%s\n", s.bgreen(rule))
	fmt.Fprintf(&b, "  %s\n", s.bgreen("✓ Scan complete"))
	fmt.Fprintf(&b, "  %s\n", s.dim(counts))
	fmt.Fprintf(&b, "%s\n", s.bgreen(rule))

	htmlPath := ""
	for _, p := range written {
		if strings.HasSuffix(p, "report.html") {
			htmlPath = p
			break
		}
	}
	if htmlPath != "" {
		abs, err := filepath.Abs(htmlPath)
		if err != nil {
			abs = htmlPath
		}
		fmt.Fprintf(&b, "\n  %s\n", s.bold("Open the HTML report"))
		fmt.Fprintf(&b, "    %s\n", s.blue("file://"+abs))
		fmt.Fprintf(&b, "    %s\n", s.dim("open "+htmlPath))
	}
	if _, err := fmt.Fprint(w, b.String()); err != nil {
		return err
	}
	return nil
}

// printAttackPaths prints one line per sink: how many identities reach it and
// the most direct chain. The hop actions are the same slugs that findings.json
// carries in escalation_path[].action, so a reader can search for them.
func printAttackPaths(w io.Writer, s styler, paths []report.AttackPathOverview) error {
	if len(paths) == 0 {
		return nil
	}
	total := 0
	width := 0
	for _, p := range paths {
		total += p.Paths
		if len(p.Sink) > width {
			width = len(p.Sink)
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "attack paths: total=%d targets=%d\n", total, len(paths))
	for _, p := range paths {
		who := fmt.Sprintf("%d %s", p.Identities, plural(p.Identities, "identity", "identities"))
		chain := p.Source
		if len(p.Actions) > 0 {
			chain += " via " + strings.Join(p.Actions, " > ")
		}
		fmt.Fprintf(&b, "  %s  %s  %s\n",
			s.bold(fmt.Sprintf("%-*s", width, p.Sink)),
			fmt.Sprintf("%-14s", who),
			s.dim("shortest: "+chain))
	}
	_, err := fmt.Fprint(w, b.String())
	return err
}

// plural picks the singular or plural noun for n.
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// printTruncationNotice writes a one-line notice to w when the --max-findings
// cap fired. It is meant for stderr so it never collides with JSON output on
// stdout or the parseable `findings: total=...` line that CI scripts grep.
// No-op when info.Truncated is false.
func printTruncationNotice(w io.Writer, info models.TruncationInfo) {
	if !info.Truncated {
		return
	}
	// Stderr write failures are not actionable from a CLI helper, so swallow
	// the error rather than propagate it through three call sites.
	if info.Scope == models.TruncationScopeHTML {
		what := fmt.Sprintf("the top %d", info.Limit)
		if info.AttackPaths > 0 {
			what = fmt.Sprintf("every attack path and the top %d of the rest", info.Limit)
		}
		_, _ = fmt.Fprintf(w, "report.html lists %d of %d findings (%s); findings.json, CSV, and SARIF hold all %d. Run again without --max-findings to list all in the HTML report.\n",
			info.Shown, info.Original, what, info.Original)
		return
	}
	_, _ = fmt.Fprintf(w, "showing top %d of %d findings (run again without --max-findings to include all)\n",
		info.Shown, info.Original)
}

// warnIfSampledFindings prints a warning when findingsPath was written by a
// version that cut every output to the top N findings. Such a file is a sample.
// A comparison against it reports wrong "added" and "resolved" findings (a
// finding outside the sample looks new when it enters and resolved when it
// leaves), and a report regenerated from it shows the sample as the result. The evidence is the truncation-info.json beside the file. Current
// versions write that sidecar with scope "html" (only the HTML report is cut),
// which is not a sample and gives no warning.
func warnIfSampledFindings(w io.Writer, findingsPath string) {
	sidecar := report.GuessTruncationInfoPath(findingsPath)
	if _, err := os.Stat(sidecar); err != nil {
		return
	}
	info, err := report.ReadTruncationInfo(sidecar)
	if err != nil || !info.Truncated || info.Scope == models.TruncationScopeHTML {
		return
	}
	_, _ = fmt.Fprintf(w, "warning: %s holds only the top %d of %d findings (written by an older version, see %s). A comparison or a report made from it covers that sample only. Create the file again with this version.\n",
		findingsPath, info.Shown, info.Original, sidecar)
}
