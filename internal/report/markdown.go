// Package report — markdown rendering for finding titles, descriptions, impacts,
// scenarios, and remediations. Supports a tiny subset (paragraphs, line breaks, inline
// `code`, **bold**) so finding text can be authored once and rendered safely in HTML.
package report

import (
	"html/template"
	"strings"
)

// renderParagraphs splits text on blank lines into <p> blocks and inline-renders backtick spans
// as <code>. Each paragraph is HTML-escaped before backtick substitution so analyzer-supplied
// content cannot inject markup. Returns a string ready to be wrapped in template.HTML.
func renderParagraphs(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	var b strings.Builder
	for para := range strings.SplitSeq(text, "\n\n") {
		para = strings.TrimSpace(para)
		if para == "" {
			continue
		}
		b.WriteString("<p>")
		b.WriteString(renderInlineCode(para))
		b.WriteString("</p>")
	}
	return b.String()
}

// stripMarkdown removes markdown markers (backticks, **bold**) so a string can be
// rendered into a context that has no markup support — primarily SVG <text> elements
// in the attack graph. Content stays intact; only the delimiter characters are dropped.
func stripMarkdown(text string) string {
	if text == "" {
		return text
	}
	out := strings.ReplaceAll(text, "**", "")
	out = strings.ReplaceAll(out, "`", "")
	return out
}

// renderInlineCode HTML-escapes text and converts the small inline-markdown subset
// analyzer-supplied finding text uses:
//
//	`code`   → <code>
//	**bold** → <strong>
//
// Single newlines outside code spans become <br> for natural line breaks. Mirrors
// the JS renderInlineHTML in graph_script.go so popup tooltips and the static
// Findings tab render the same markdown.
func renderInlineCode(text string) string {
	escaped := template.HTMLEscapeString(text)
	var b strings.Builder
	b.Grow(len(escaped) + 16)
	for i := 0; i < len(escaped); {
		c := escaped[i]
		if c == '`' {
			end := strings.IndexByte(escaped[i+1:], '`')
			if end < 0 { // unmatched backtick — render rest as plain text
				b.WriteString(escaped[i+1:])
				return b.String()
			}
			b.WriteString("<code>")
			b.WriteString(escaped[i+1 : i+1+end])
			b.WriteString("</code>")
			i += 1 + end + 1
			continue
		}
		if c == '*' && i+1 < len(escaped) && escaped[i+1] == '*' {
			rest := escaped[i+2:]
			end := strings.Index(rest, "**")
			if end < 0 { // unmatched bold — render rest as plain text
				b.WriteString(escaped[i:])
				return b.String()
			}
			b.WriteString("<strong>")
			b.WriteString(rest[:end])
			b.WriteString("</strong>")
			i += 2 + end + 2
			continue
		}
		if c == '\n' {
			b.WriteString("<br>")
			i++
			continue
		}
		b.WriteByte(c)
		i++
	}
	return b.String()
}
