package report

import _ "embed"

// htmlTemplate is the Go html/template source for the HTML dashboard. Kept in a sibling
// file so editors can syntax-highlight HTML/CSS; embedded into the binary at build time so
// reports can be generated without runtime assets.
//
//go:embed assets/report.html.tmpl
var htmlTemplate string

// reportScript is the JavaScript for the HTML report: tab routing, findings filters,
// the attack-path graph highlights, and glossary hovers. Kept in a sibling .js file for
// editor support; injected via template.JS in BuildHTMLData so the report stays
// self-contained.
//
//go:embed assets/report.js
var reportScript string
