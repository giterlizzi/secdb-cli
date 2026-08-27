// SPDX-License-Identifier: Apache-2.0

package output

import (
	"bytes"
	"embed"
	"fmt"
	"io"
	"os"
	"text/template"

	"github.com/charmbracelet/glamour"
	"golang.org/x/term"
)

//go:embed templates/*.tmpl
var templatesFS embed.FS

// RenderText renders the named template through Glamour. The optional wrap is
// the word-wrap column width; omitted (or 0) means no wrapping, so wide tables
// (audit, ssvc) keep their natural width. Pass a width for prose-heavy,
// table-free output (e.g. cve) so paragraphs and lists wrap with a correct
// hanging indent instead of being pre-wrapped in the template.
func RenderText(w io.Writer, data interface{}, name string, wrap ...int) error {
	width := 0
	if len(wrap) > 0 {
		width = wrap[0]
	}

	tmpl, err := template.New(name).Funcs(funcMap()).ParseFS(templatesFS, "templates/*.tmpl")
	if err != nil {
		return fmt.Errorf("embedded template %q: %w", name, err)
	}

	var buf bytes.Buffer

	if err := tmpl.ExecuteTemplate(&buf, name+".tmpl", data); err != nil {
		return fmt.Errorf("template %q execution: %w", name, err)
	}

	return writeMarkdown(w, buf.String(), width)

}

// RenderTextPlain executes the named embedded template directly to w,
// without the Glamour Markdown pass. It is for machine-readable formats whose
// layout lives entirely in a template (e.g. csv.tmpl).
func RenderTextPlain(w io.Writer, data interface{}, name string) error {
	tmpl, err := template.New(name).Funcs(funcMap()).ParseFS(templatesFS, "templates/*.tmpl")
	if err != nil {
		return fmt.Errorf("embedded template %q: %w", name, err)
	}
	return tmpl.ExecuteTemplate(w, name+".tmpl", data)
}

func writeMarkdown(w io.Writer, markdown string, wrap int) error {

	if !isTerminal(w) || os.Getenv("NO_COLOR") != "" {
		_, err := io.WriteString(w, markdown)
		return err
	}

	rendered, err := renderMarkdown(markdown, wrap)
	if err != nil {
		// fallback to raw markdown rather than failing the whole render
		_, werr := io.WriteString(w, markdown)
		return werr
	}

	_, err = io.WriteString(w, rendered)
	return err
}

// TerminalWrap returns a Markdown word-wrap width: the current stdout terminal
// width, capped at max. It falls back to max when the width can't be determined
// (e.g. stdout isn't a terminal, in which case raw Markdown is emitted anyway).
func TerminalWrap(max int) int {
	if w, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil && w > 0 && w < max {
		return w
	}
	return max
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)

	if !ok {
		return false
	}

	return term.IsTerminal(int(f.Fd()))
}

func renderMarkdown(markdown string, wrap int) (string, error) {
	r, err := glamour.NewTermRenderer(
		glamour.WithAutoStyle(),
		glamour.WithWordWrap(wrap),
	)

	if err != nil {
		return "", fmt.Errorf("markdown renderer: %w", err)
	}

	return r.Render(markdown)
}
