// SPDX-License-Identifier: Apache-2.0

package audit

import "github.com/giterlizzi/secdb-cli/internal/finding"

// Findings converts a shaped advisory result into the source-agnostic finding
// model.
func (a AdvisoryResult) Findings() []finding.Finding {
	base := finding.Finding{
		Source:      "secdb-audit",
		SourceID:    a.ID,
		Name:        a.Title,
		Severity:    a.Severity,
		Summary:     a.Summary,
		Description: a.Description,
		CVEs:        a.CVEs,
		CWEs:        a.CWEs,
		CVSSScore:   a.CVSSScore, // TODO
	}
	if a.URL != "" {
		base.References = []string{a.URL}
	}

	if len(a.PURLs) == 0 {
		return []finding.Finding{base}
	}

	out := make([]finding.Finding, 0, len(a.PURLs))
	for i, purl := range a.PURLs {
		f := base
		f.PURL = purl
		if i < len(a.Packages) {
			f.Package = a.Packages[i]
		}
		out = append(out, f)
	}
	return out
}
