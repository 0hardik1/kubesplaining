package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

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
func printScanResults(w io.Writer, written []string, summary report.Summary) error {
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
