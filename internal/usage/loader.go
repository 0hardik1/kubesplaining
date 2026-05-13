package usage

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Source identifies the audit-log format used to produce paths.
type Source string

const (
	SourceNative Source = "native"
	SourceEKS    Source = "eks"
)

// ParseSource maps the CLI flag to a Source value. Empty defaults to native.
func ParseSource(value string) (Source, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "native":
		return SourceNative, true
	case "eks":
		return SourceEKS, true
	}
	return "", false
}

// LoadAuditLog ingests one or more audit-log paths into a UsageIndex restricted to events
// within the last `window` duration. Paths may be individual files or directories; when
// a directory is supplied, every regular file inside (one level deep) is consumed.
// `.gz`-suffixed files are streamed through a gzip decoder so rotated logs work out of
// the box.
//
// Permission/format errors on individual files are surfaced as warnings appended to the
// returned warnings slice and never abort the load - this mirrors the collector's
// "partial snapshots are still useful" posture. A nil paths slice or zero window yields
// an empty index without error so callers can dispatch on the resulting state.
func LoadAuditLog(paths []string, source Source, window time.Duration, now time.Time) (*UsageIndex, []string, error) {
	idx := EmptyIndex()
	idx.WindowEnd = now
	idx.WindowStart = now.Add(-window)
	var warnings []string

	files, err := expandPaths(paths)
	if err != nil {
		return idx, warnings, err
	}
	if len(files) == 0 {
		return idx, warnings, nil
	}

	for _, p := range files {
		if err := ingestFile(p, source, idx); err != nil {
			warnings = append(warnings, fmt.Sprintf("usage: skip %s: %v", p, err))
			continue
		}
	}
	return idx, warnings, nil
}

// expandPaths walks each input path. Files are kept verbatim; directories contribute
// every regular file at the top level (we don't recurse - rotated audit logs are flat,
// and recursion would surprise users who happen to point at /var/log).
func expandPaths(paths []string) ([]string, error) {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		info, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("stat %s: %w", p, err)
		}
		if !info.IsDir() {
			out = append(out, p)
			continue
		}
		entries, err := os.ReadDir(p)
		if err != nil {
			return nil, fmt.Errorf("read dir %s: %w", p, err)
		}
		for _, entry := range entries {
			if entry.IsDir() || entry.Name() == "" || entry.Name()[0] == '.' {
				continue
			}
			out = append(out, filepath.Join(p, entry.Name()))
		}
	}
	sort.Strings(out)
	return out, nil
}

// ingestFile opens path, optionally unwraps gzip, and dispatches to the parser for source.
// Per-event filtering (denied responses, out-of-window timestamps, non-SA usernames) lives
// here so both parsers share the same kept/skipped/non-SA accounting.
func ingestFile(path string, source Source, idx *UsageIndex) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	var r io.Reader = f
	if strings.HasSuffix(strings.ToLower(path), ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return fmt.Errorf("gunzip: %w", err)
		}
		defer func() { _ = gz.Close() }()
		r = gz
	}

	emit := func(ev AuditEvent) {
		if !ev.keep(idx.WindowStart, idx.WindowEnd) {
			idx.EventsSkipped++
			return
		}
		subj, ok := SubjectFromUsername(ev.Username)
		if !ok {
			idx.NonSAUsernames++
			return
		}
		idx.record(subj, ev.APIGroup, ev.Resource, ev.Verb)
		idx.EventsProcessed++
	}
	onSkip := func() { idx.EventsSkipped++ }

	switch source {
	case SourceEKS:
		return parseEKSReader(r, emit, onSkip)
	default:
		return parseNativeReader(r, emit, onSkip)
	}
}
