package models

// TruncationInfo records that the --max-findings cap shortened a findings
// list. It is rendered as a banner in the HTML report, surfaced as a one-line
// stderr notice during scans, and persisted as truncation-info.json so a
// reader of the output directory can tell what was shortened (see Scope).
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
	// Scope says which outputs the cap shortened. TruncationScopeHTML means
	// only report.html lists a subset: findings.json, the CSV, and the SARIF
	// file beside it hold every finding. Empty is the older behavior, where
	// every output in the directory was cut to the same subset. A reader that
	// compares two findings files must treat an empty scope on a truncated
	// file as "this file is a sample".
	Scope string `json:"scope,omitempty"`
	// AttackPaths is how many of the Shown findings are attack paths that are
	// listed no matter what the cap is. Zero when the selection does not
	// treat attack paths in a special way.
	AttackPaths int `json:"attack_paths,omitempty"`
}

// TruncationScopeHTML is the TruncationInfo.Scope value for a cap that
// shortened the HTML report only.
const TruncationScopeHTML = "html"
