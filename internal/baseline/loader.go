// Package baseline loads previously emitted findings.json files and computes a
// delta against a freshly produced findings slice. The diff is keyed on
// Finding.ID, which the analyzer pipeline guarantees is deterministic per
// instance ("RULE:ns:name"), so two scans of the same cluster surface the
// same set of IDs and an Added / Resolved / Unchanged classification falls
// out cleanly.
//
// The loader accepts either of two on-disk shapes so callers can point the
// flag at whichever artifact they happen to have saved:
//
//	[ {...finding...}, {...finding...} ]                 // bare array  (writeJSON output)
//	{ "findings": [ {...finding...}, ... ], ... }        // wrapper object (forward-compat)
//
// Detection is by first non-whitespace byte, not by filename suffix, so
// renamed files (findings.json, report.json, baseline.json) all work.
package baseline

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// wrappedFindings is the object-shape variant the loader accepts. The
// `findings` key is the only required field; anything else in the wrapper
// is ignored so future callers can stash metadata alongside without
// breaking the loader.
type wrappedFindings struct {
	Findings []models.Finding `json:"findings"`
}

// LoadFindings reads a JSON file at path and returns its findings slice.
// The file may be a bare JSON array (the shape written by the existing
// report writer) or a wrapper object containing a `findings` array; the
// shape is detected from the first non-whitespace byte. An empty file is
// an error.
func LoadFindings(path string) ([]models.Finding, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("open baseline file: %w", err)
	}

	trimmed := bytes.TrimLeft(raw, " \t\r\n")
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("baseline file %s is empty", path)
	}

	switch trimmed[0] {
	case '[':
		var findings []models.Finding
		if err := json.Unmarshal(raw, &findings); err != nil {
			return nil, fmt.Errorf("decode baseline findings array: %w", err)
		}
		return findings, nil
	case '{':
		var wrapper wrappedFindings
		if err := json.Unmarshal(raw, &wrapper); err != nil {
			return nil, fmt.Errorf("decode baseline findings object: %w", err)
		}
		return wrapper.Findings, nil
	default:
		return nil, fmt.Errorf("baseline file %s: unrecognized JSON shape (expected array or object)", path)
	}
}
