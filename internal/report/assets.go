package report

import _ "embed"

// htmlTemplate is the Go html/template source for the HTML dashboard. Kept in a sibling
// file so editors can syntax-highlight HTML/CSS; embedded into the binary at build time so
// reports can be generated without runtime assets.
//
//go:embed assets/report.html.tmpl
var htmlTemplate string

// kpGraphScript is the JavaScript that powers the interactive attack graph in the HTML
// report. Kept in a sibling .js file for editor support; injected via template.JS in
// BuildHTMLData so the report stays self-contained.
//
//go:embed assets/graph.js
var kpGraphScript string
