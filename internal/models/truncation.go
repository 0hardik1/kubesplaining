package models

// TruncationInfo records that the report's findings list was capped before
// being written. It is rendered as a banner in the HTML report, surfaced as a
// one-line stderr notice during scans, embedded in the SARIF run properties,
// and persisted as truncation-info.json so `kubesplaining report` can
// re-render the banner without re-running analysis.
//
// Truncated is the gate flag: when false (the zero value), the struct carries
// no information and downstream renderers treat it as "no cap was applied."
type TruncationInfo struct {
	// Truncated is true only when the cap actually fired (Original > Limit
	// and AllFindings was not set).
	Truncated bool `json:"truncated"`
	// Original is the size of the findings slice before the cap was applied,
	// after exclusions and severity filtering.
	Original int `json:"original"`
	// Shown is min(Original, Limit) when Truncated; equals Original otherwise.
	Shown int `json:"shown"`
	// Limit is the --max-findings value that produced this state. Zero when
	// --all-findings was passed.
	Limit int `json:"limit"`
}
