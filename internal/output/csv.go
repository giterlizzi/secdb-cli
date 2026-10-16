// SPDX-License-Identifier: Apache-2.0

package output

import (
	"io"

	"github.com/giterlizzi/secdb-cli/internal/audit"
)

// WriteCSV writes the advisories as CSV, one row per advisory. The whole layout
// (columns, quoting, formatting) lives in the audit-details-csv template, so it
// can be changed without touching Go code.
func WriteCSV(w io.Writer, advisories []audit.AdvisoryResult) error {
	return RenderTextPlain(w, advisories, "audit-details-csv")
}
