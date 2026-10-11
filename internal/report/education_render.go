// Package report: combined educational block for the static Findings tab.
// renderRuleEducation pulls relevant Glossary entries (subject kind, resource kind)
// and the Techniques entry for a rule's findings, then renders them as a collapsible
// "Background" block on the rule card, so a reader learns what a ServiceAccount is or
// what the impersonate verb does without leaving the finding.
//
// All HTML is constructed from in-process Glossary/Techniques values whose Long/Plain
// fields are already template.HTML. Subject/resource keys come from analyzer-supplied
// SubjectRef/ResourceRef but are routed through HTMLEscapeString before composing.
package report

import (
	"html/template"
	"strings"

	"github.com/0hardik1/kubesplaining/internal/models"
)

// renderRuleEducation returns a "Background" HTML block listing the glossary and
// technique definitions that apply to a rule's findings. It renders once per rule
// card, not once per affected object: instances of one rule usually share the same
// subject kind, resource kind, and technique, so a per-instance block repeated the
// same paragraphs dozens of times. Entries are unioned across instances so a rule
// that fires on both a ServiceAccount and a User still explains both. Returns ""
// when nothing applies; the template gates the wrapper on this.
//
// Dedupe rule: when a finding has an EscalationPath, the per-hop chain cards already
// render Techniques[hop.Action].Plain for each step, so its technique entry is left
// out here. Non-chain findings still get the technique entry so RBAC, podsec,
// admission, and similar findings carry the same explainer a privesc finding has.
func renderRuleEducation(findings []models.Finding) template.HTML {
	var blocks []string
	seen := map[string]bool{}
	add := func(label, key, title string, body template.HTML, docURL string) {
		id := label + "\x00" + key
		if seen[id] {
			return
		}
		seen[id] = true
		blocks = append(blocks, educationCard(title, label, body, docURL))
	}

	for _, f := range findings {
		// Subject (ServiceAccount, User, Group, system:masters).
		if key := GlossaryKeyForSubject(f.Subject); key != "" {
			if entry, ok := Glossary[key]; ok {
				add("Subject", key, entry.Title, entry.Long, entry.DocURL)
			}
		}
		// Resource (Pod, Secret, ConfigMap, Role, ClusterRoleBinding, ...).
		if key := GlossaryKeyForResource(f.Resource); key != "" {
			if entry, ok := Glossary[key]; ok {
				add("Resource", key, entry.Title, entry.Long, entry.DocURL)
			}
		}
		// Technique, only when the chain section will not already explain it per hop.
		if len(f.EscalationPath) == 0 {
			if key := TechniqueKeyForFinding(f); key != "" {
				if entry, ok := Techniques[key]; ok {
					add("Technique", key, entry.Title, entry.Plain, "")
				}
			}
		}
	}

	if len(blocks) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString(`<div class="education"><div class="edu-cards">`)
	for _, blk := range blocks {
		b.WriteString(blk)
	}
	b.WriteString(`</div></div>`)
	return template.HTML(b.String())
}

// educationCard renders one definition: a label badge, a title, the body HTML, and
// an optional Kubernetes-docs link. Title and label are HTML-escaped; body is already
// trusted template.HTML from the in-process Glossary/Techniques maps.
func educationCard(title, label string, body template.HTML, docURL string) string {
	var b strings.Builder
	b.WriteString(`<div class="edu-card"><div class="edu-hd"><span class="edu-label">`)
	b.WriteString(template.HTMLEscapeString(label))
	b.WriteString(`</span><span class="edu-title">`)
	b.WriteString(template.HTMLEscapeString(title))
	b.WriteString(`</span></div><div class="edu-body">`)
	b.WriteString(string(body))
	b.WriteString(`</div>`)
	if docURL != "" {
		b.WriteString(`<a class="edu-doc" href="`)
		b.WriteString(template.HTMLEscapeString(docURL))
		b.WriteString(`" target="_blank" rel="noopener noreferrer">Kubernetes docs ↗</a>`)
	}
	b.WriteString(`</div>`)
	return b.String()
}
