// SPDX-License-Identifier: Apache-2.0

// Package output renders results as text, JSON, YAML, templates, HTML, SARIF or CSV.
package output

import (
	"fmt"
	"html/template"
	"io"
	"strings"

	"github.com/giterlizzi/secdb-cli/internal/audit"
	"github.com/giterlizzi/secdb-cli/internal/weblink"

	"github.com/Masterminds/sprig/v3"
)

// Format is an output format selector.
type Format string

// Supported output formats.
const (
	JSON     Format = "json"
	Template Format = "template"
	HTML     Format = "html"
	YAML     Format = "yaml"
)

// Options holds renderer options for the template/HTML formats.
type Options struct {
	TemplateFile       string
	TemplateExpression string
}

// SourceLocation maps a PURL to the manifest file and line it came from, for
// SARIF attribution.
type SourceLocation struct {
	PURL string
	File string
	Line int
}

// unsafeTemplateFuncs are Sprig functions capable of reading environment
// variables or making network calls. They are stripped from funcMap so that
// user-supplied templates (--template / --template-file) cannot exfiltrate
// secrets such as SECDB_API_KEY (e.g. via getHostByName(env "SECDB_API_KEY")).
var unsafeTemplateFuncs = []string{"env", "expandenv", "getHostByName"}

func funcMap() template.FuncMap {
	fm := sprig.FuncMap()
	for _, name := range unsafeTemplateFuncs {
		delete(fm, name)
	}
	fm["severity"] = SeverityMarkdown
	fm["ssvc_decision"] = SSVCDecisionMarkdown
	fm["cve_url"] = weblink.CVE
	fm["cwe_url"] = weblink.CWE
	fm["advisory_url"] = weblink.Advisory
	return fm
}

// Render writes data to w in the given format.
func Render(w io.Writer, data any, format Format, opts Options) error {
	switch format {
	case JSON:
		return renderJSON(w, data)
	case YAML:
		return renderYAML(w, data)
	case Template:
		return renderTemplate(w, data, opts)
	case HTML:
		return renderHTML(w, data, opts)
	default:
		return fmt.Errorf("unknown renderer: %q (json, yaml, template, html)", format)
	}
}

// SeverityMarkdown returns a colored emoji badge for a severity, for text/Markdown output.
func SeverityMarkdown(severity string) string {
	var emoji string

	if severity == "" {
		return "-"
	}

	switch audit.NormalizeSeverity(severity) {
	case "critical", "high":
		emoji = "🔴"
	case "medium":
		emoji = "🟠"
	case "low":
		emoji = "🟡"
	default:
		emoji = "⚪"
	}

	return fmt.Sprintf("%s **%s**", emoji, strings.ToUpper(severity))
}

// SSVCDecisionMarkdown returns a colored emoji badge for an SSVC decision, for text/Markdown output.
func SSVCDecisionMarkdown(decision string) string {
	var emoji string
	switch decision {
	case "act":
		emoji = "🔴"
	case "attend":
		emoji = "🟠"
	case "track*":
		emoji = "🟡"
	case "track":
		emoji = "🟢"
	default:
		return decision
	}
	return fmt.Sprintf("%s **%s**", emoji, strings.ToUpper(decision))
}
