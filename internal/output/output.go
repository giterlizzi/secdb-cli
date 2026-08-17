// SPDX-License-Identifier: Apache-2.0

package output

import (
	"fmt"
	"html/template"
	"io"
	"strings"

	"github.com/Masterminds/sprig/v3"
)

type Format string

const (
	JSON     Format = "json"
	Template Format = "template"
	HTML     Format = "html"
	YAML     Format = "yaml"
)

type Options struct {
	TemplateFile       string
	TemplateExpression string
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
	return fm
}

func Render(w io.Writer, data interface{}, format Format, opts Options) error {
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

func SeverityMarkdown(severity string) string {
	var emoji string

	switch strings.ToLower(severity) {
	case "critical", "important", "urgent", "severe", "high":
		emoji = "🔴"
	case "medium", "moderate":
		emoji = "🟠"
	case "low":
		emoji = "🟡"
	default:
		emoji = "⚪"
	}

	if severity == "" {
		return "-"
	}

	return fmt.Sprintf("%s **%s**", emoji, strings.ToUpper(severity))
}
