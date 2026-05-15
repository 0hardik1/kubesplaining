package cli

import (
	"fmt"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/compliance"
	"github.com/0hardik1/kubesplaining/internal/models"
)

// parseComplianceFilter normalizes user-supplied --compliance values into the canonical
// framework slugs used by FilterByFramework. An empty input returns nil so callers can
// pass through to the no-filter path. Unknown values surface as an explicit error
// listing the supported slugs — silently dropping a typo would mask "I asked for cis
// but got an empty filter."
func parseComplianceFilter(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	resolved := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, v := range values {
		// `StringSliceVar` splits on comma but does not trim — handle both shapes so
		// `--compliance=cis,nsa` and `--compliance=cis --compliance=nsa` behave the same.
		for _, part := range strings.Split(v, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			slug := compliance.ResolveFramework(part)
			if slug == "" {
				return nil, fmt.Errorf("unknown --compliance framework %q (supported: cis, nsa)", part)
			}
			if _, ok := seen[slug]; ok {
				continue
			}
			seen[slug] = struct{}{}
			resolved = append(resolved, slug)
		}
	}
	return resolved, nil
}

// applyComplianceFilter drops findings without any tag from the requested frameworks.
// Returns the input unchanged when the framework list is empty so the call site does
// not need to branch.
func applyComplianceFilter(findings []models.Finding, frameworks []string) []models.Finding {
	return compliance.FilterByFramework(findings, frameworks)
}
