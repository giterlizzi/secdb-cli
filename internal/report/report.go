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

// Report carries a metadata header plus the shaped results, for the text
// templates; the json/yaml/sarif/csv outputs don't use it.
type Report struct {
	Meta    []MetaItem
	Results any
	BaseURL string // SecDB web-GUI URL (client.WebURL), for the permalinks and footer
}
