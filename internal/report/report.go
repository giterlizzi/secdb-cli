// SPDX-License-Identifier: Apache-2.0

// Package report defines the generic shape the text renderer consumes: a
// metadata header plus shaped results. It is deliberately domain-agnostic and
// imports nothing of ours, so any producer can return a report.Report without
// depending on a specific domain package.
package report

// MetaItem is one label/value row of the metadata header shown above a report
// in text output (e.g. "Target: local", "Packages scanned: 2669").
type MetaItem struct {
	Label string
	Value string
}

// Report carries a metadata header plus the shaped results. It holds no
// report-specific logic - producers fill Results and any pre-computed Meta, and
// the caller merges in its own context meta. Only the text renderer uses it;
// the json/yaml/sarif paths keep rendering the raw API data unchanged.
type Report struct {
	Meta    []MetaItem
	Results any
	BaseURL string // SecDB web-GUI URL (client.WebURL), for the permalinks and footer
}

// PrependMeta inserts items before the existing Meta, so caller-supplied
// context rows (Source, PURLs scanned, ...) lead and producer-computed rows
// (Ignored, ...) follow.
func (r *Report) PrependMeta(items ...MetaItem) {
	r.Meta = append(items, r.Meta...)
}

// AddMeta appends items after the existing Meta.
func (r *Report) AddMeta(items ...MetaItem) {
	r.Meta = append(r.Meta, items...)
}

// AddResults add report results
func (r *Report) AddResults(results any) {
	r.Results = results
}

// MetaValue returns the value of the first meta row matching one of labels,
// or "" if none match. Used to reuse the human-readable provenance each audit
// command already computes for the text header.
func (r *Report) MetaValue(labels ...string) string {
	for _, want := range labels {
		for _, m := range r.Meta {
			if m.Label == want {
				return m.Value
			}
		}
	}
	return ""
}
