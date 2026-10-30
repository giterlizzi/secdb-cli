// SPDX-License-Identifier: Apache-2.0

// Package output renders results as text, JSON, YAML, templates, HTML, SARIF or CSV.
package output

import (
	"encoding/json"
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

// Options holds renderer options: the user template (template/html formats)
// and the --jq expression (json format).
type Options struct {
	TemplateFile       string
	TemplateExpression string

	// JQ, when set, filters the json output (see ParseJQ).
	JQ *JQ
}

// Subject is what an audit report is about, the CycloneDX metadata.component
// that depends on the affected packages. Type is a CycloneDX component type
// (application, file, operating-system, container); a zero Subject (no Name)
// leaves the report without one.
type Subject struct {
	Type    string
	Name    string
	Version string
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
	fm["path_url"] = weblink.Path
	// Sprig's abbrev and trunc count bytes and can cut a character in two.
	fm["abbrev"] = abbrev
	fm["trunc"] = trunc
	return fm
}

// abbrev is Sprig's abbrev counting characters, not bytes: s cut to width
// characters, the last three replaced by "...". A width under 4 leaves s as is.
func abbrev(width int, s string) string {
	r := []rune(s)
	if width < 4 || len(r) <= width {
		return s
	}
	return string(r[:width-3]) + "..."
}

// trunc is Sprig's trunc counting characters, not bytes: the first n
// characters of s, or the last -n when n is negative.
func trunc(n int, s string) string {
	r := []rune(s)
	switch {
	case n >= 0 && len(r) > n:
		return string(r[:n])
	case n < 0 && len(r) > -n:
		return string(r[len(r)+n:])
	}
	return s
}

// Render writes data to w in the given format.
func Render(w io.Writer, data any, format Format, opts Options) error {
	if format == JSON && opts.JQ == nil {
		return renderJSON(w, data)
	}

	// yaml, templates and --jq see the data as -o json shows it, with the
	// API's field names (.base_score, .purl), not the Go ones (.BaseScore,
	// .PURL): yaml.v3 ignores the json tags and a template reads the Go fields.
	data, err := jsonValue(data)
	if err != nil {
		return err
	}
	switch format {
	case JSON:
		return opts.JQ.write(w, data)
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

// jsonValue returns data as the generic value (maps, slices, strings, float64,
// ...) its JSON encoding decodes to.
func jsonValue(data any) (any, error) {
	b, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("JSON encode: %w", err)
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("JSON decode: %w", err)
	}
	return v, nil
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
