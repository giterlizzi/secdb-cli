// SPDX-License-Identifier: Apache-2.0

package output

import (
	"fmt"
	"html/template"
	"io"
)

func renderHTML(w io.Writer, data interface{}, opts Options) error {
	src, err := templateSource(opts)
	if err != nil {
		return err
	}

	tmpl, err := template.New("output").Funcs(funcMap()).Parse(src)
	if err != nil {
		return fmt.Errorf("invalid HTML template: %w", err)
	}

	if err := tmpl.Execute(w, data); err != nil {
		return fmt.Errorf("HTML template execution: %w", err)
	}

	return nil
}
