// SPDX-License-Identifier: Apache-2.0

package output

import (
	"io"

	"github.com/giterlizzi/secdb-cli/internal/report"
)

// WriteCSV renders a report as CSV using the embedded templates/*.tmpl. The
// whole CSV layout (columns, quoting, formatting) lives in that template, so
// it can be changed without touching Go code.
func WriteCSV(w io.Writer, r report.Report, template string) error {
	return RenderTextPlain(w, r, template)
}
