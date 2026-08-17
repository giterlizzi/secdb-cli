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

func RenderText(w io.Writer, data interface{}, name string) error {
	tmpl, err := template.New(name+".tmpl").Funcs(funcMap()).ParseFS(templatesFS, "templates/"+name+".tmpl")
	if err != nil {
		return fmt.Errorf("embedded template %q: %w", name, err)
	}

	var buf bytes.Buffer

	if err := tmpl.Execute(&buf, data); err != nil {
		return fmt.Errorf("template %q execution: %w", name, err)
	}

	return writeMarkdown(w, buf.String())

}

func writeMarkdown(w io.Writer, markdown string) error {

	if !isTerminal(w) || os.Getenv("NO_COLOR") != "" {
		_, err := io.WriteString(w, markdown)
		return err
	}

	rendered, err := renderMarkdown(markdown)
	if err != nil {
		// degrade to raw markdown rather than failing the whole render
		_, werr := io.WriteString(w, markdown)
		return werr
	}

	_, err = io.WriteString(w, rendered)
	return err
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)

	if !ok {
		return false
	}

	return term.IsTerminal(int(f.Fd()))
}

func renderMarkdown(markdown string) (string, error) {
	r, err := glamour.NewTermRenderer(
		glamour.WithAutoStyle(),
		glamour.WithWordWrap(0),
	)

	if err != nil {
		return "", fmt.Errorf("markdown renderer: %w", err)
	}

	return r.Render(markdown)
}
