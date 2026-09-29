// SPDX-License-Identifier: Apache-2.0

package output

import (
	"errors"
	"fmt"
	"io"
	"os"
	"text/template"
)

func renderTemplate(w io.Writer, data any, opts Options) error {
	src, err := templateSource(opts)
	if err != nil {
		return err
	}

	tmpl, err := template.New("output").Funcs(funcMap()).Parse(src)
	if err != nil {
		return fmt.Errorf("invalid template: %w", err)
	}

	if err := tmpl.Execute(w, data); err != nil {
		return fmt.Errorf("template execution: %w", err)
	}

	_, err = fmt.Fprintln(w)
	return err
}

func templateSource(opts Options) (string, error) {
	if opts.TemplateFile != "" {
		content, err := os.ReadFile(opts.TemplateFile)
		if err != nil {
			return "", fmt.Errorf("failed to read template-file: %w", err)
		}
		return string(content), nil
	}
	if opts.TemplateExpression != "" {
		return opts.TemplateExpression, nil
	}
	return "", errors.New("--template=STRING or --template-file=PATH is required with --output=template")
}
