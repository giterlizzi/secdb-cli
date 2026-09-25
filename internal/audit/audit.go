// SPDX-License-Identifier: Apache-2.0

// Package audit shapes and filters audit results and handles PURL input.
package audit

import (
	"log/slog"
	"maps"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/giterlizzi/secdb-cli/internal/client"
	"github.com/giterlizzi/secdb-cli/internal/report"
)

// PackageResult is the per-package summary row (--view=summary).
type PackageResult struct {
	Package       string   `json:"package"`
	CVEs          []string `json:"cves"`
	CWEs          []string `json:"cwes"`
	AdvisoryCount int      `json:"advisory_count"`
	MaxSeverity   string   `json:"max_severity"`
}

// AdvisoryResult is the per-advisory shaping (--view=details, SARIF, CSV), with
// the packages it affects and ignore/unfixed annotations.
type AdvisoryResult struct {
	ID           string
	Title        string
	Summary      string
	Description  string
	Severity     string
	Packages     []string
	PURLs        []string
	CVEs         []string
	CWEs         []string
	CVSSScore    float64
	URL          string
	Ignored      bool
	IgnoreReason string
	Unfixed      bool
}

// SeverityLevels ranks severities so they can be compared and sorted.
var SeverityLevels = map[string]int{
	"critical": 5, "high": 4, "medium": 3, "moderate": 3, "low": 2, "info": 1, "unknown": 1, "": 0,
}

// hideUnfixed reports whether adv must be hidden from the audit output for
// purl: an unfixed advisory is hidden unless showUnfixed is set. It centralizes
// the default-hide-unfixed rule (and its debug log) shared by
// SummarizePURLAudit, GroupByAdvisory and OverallSeverity.
func hideUnfixed(purl string, adv client.Advisory, showUnfixed bool) bool {
	if !showUnfixed && IsUnfixed(purl, adv) {
		slog.Debug("unfixed", "purl", purl, "advisory", adv.ID)
		return true
	}
	return false
}

// cweIDs returns the CWE IDs of an advisory's weaknesses.
func cweIDs(adv client.Advisory) []string {
	ids := make([]string, 0, len(adv.Weaknesses))
	for _, w := range adv.Weaknesses {
		ids = append(ids, w.ID)
	}
	return ids
}

// latestCVSSScore returns the base score of the advisory's highest available
// CVSS version (e.g. prefers 4.0 over 3.1), or 0 when it carries no CVSS data.
func latestCVSSScore(adv client.Advisory) float64 {
	var version, score float64
	for _, c := range adv.CVSS {
		if c.Version >= version {
			version = c.Version
			score = c.BaseScore
		}
	}
	return score
}

// OverallSeverity returns the highest severity across the results, skipping
// ignored and (unless showUnfixed) unfixed advisories.
func OverallSeverity(results []client.AuditItem, ignoreFile *IgnoreFile, showUnfixed bool) string {
	maxSeverity := ""

	for _, r := range results {
		for _, adv := range r.Advisories {

			if hideUnfixed(r.PURL, adv, showUnfixed) {
				continue
			}

			if ignored, _ := ignoreFile.IsIgnored(adv.ID, adv.CVEs, r.PURL); ignored {
				slog.Debug("ignored", "advisory", adv.ID, "cves", adv.CVEs, "purl", r.PURL)
				continue
			}

			severity := strings.ToLower(adv.Severity)
			if SeverityLevels[severity] > SeverityLevels[maxSeverity] {
				maxSeverity = severity
			}
		}
	}
	return maxSeverity
}

// SummarizePURLAudit shapes the results into one summary row per package.
func SummarizePURLAudit(results []client.AuditItem, showUnfixed bool) []PackageResult {
	out := make([]PackageResult, 0, len(results))

	for _, r := range results {
		cveSeen := make(map[string]bool)
		cweSeen := make(map[string]bool)
		maxSeverity := ""
		advisoryCount := 0

		for _, adv := range r.Advisories {

			if hideUnfixed(r.PURL, adv, showUnfixed) {
				continue
			}

			advisoryCount++

			severity := strings.ToLower(adv.Severity)
			if SeverityLevels[severity] > SeverityLevels[maxSeverity] {
				maxSeverity = severity
			}

			for _, id := range adv.CVEs {
				cveSeen[id] = true
			}

			for _, cwe := range adv.Weaknesses {
				cweSeen[cwe.ID] = true
			}
		}

		// Every advisory was filtered out (e.g. all unfixed): skip the package so
		// the summary doesn't show a row with no visible findings.
		if advisoryCount == 0 {
			continue
		}

		cves := slices.Collect(maps.Keys(cveSeen))
		cwes := slices.Collect(maps.Keys(cweSeen))

		sort.Slice(cves, func(i, j int) bool { return cves[i] > cves[j] })
		sort.Slice(cwes, func(i, j int) bool { return cwes[i] > cwes[j] })

		out = append(out, PackageResult{
			Package:       r.Package,
			CVEs:          cves,
			CWEs:          cwes,
			AdvisoryCount: advisoryCount,
			MaxSeverity:   maxSeverity,
		})
	}
	return out
}

// GroupByAdvisory shapes the results into one row per advisory (severity-sorted),
// annotating each with its affected packages and ignore/unfixed status.
func GroupByAdvisory(results []client.AuditItem, ignoreFile *IgnoreFile, showUnfixed bool) report.Report {
	byID := make(map[string]*AdvisoryResult)
	var order []string
	var ignoredCount int

	rep := report.Report{}

	for _, r := range results {
		for _, adv := range r.Advisories {

			unfixed := IsUnfixed(r.PURL, adv)

			if hideUnfixed(r.PURL, adv, showUnfixed) {
				continue
			}

			if _, exists := byID[adv.ID]; !exists {
				ignored, reason := ignoreFile.IsIgnored(adv.ID, adv.CVEs, r.PURL)

				if ignored {
					ignoredCount++
				}

				byID[adv.ID] = &AdvisoryResult{
					ID:           adv.ID,
					Title:        adv.Title,
					Summary:      adv.Summary,
					Description:  adv.Description,
					URL:          adv.URL,
					Severity:     strings.ToLower(adv.Severity),
					CVEs:         adv.CVEs,
					CWEs:         cweIDs(adv),
					CVSSScore:    latestCVSSScore(adv),
					Ignored:      ignored,
					IgnoreReason: reason,
					Unfixed:      unfixed,
				}

				order = append(order, adv.ID)
			}

			byID[adv.ID].Packages = append(byID[adv.ID].Packages, r.Package)
			byID[adv.ID].PURLs = append(byID[adv.ID].PURLs, r.PURL)

			if unfixed {
				byID[adv.ID].Unfixed = true
			}
		}
	}

	out := make([]AdvisoryResult, 0, len(order))
	for _, id := range order {
		out = append(out, *byID[id])
	}

	// Most severe first (then higher CVSS, then ID) so the details view leads
	// with what matters; ties keep a stable, deterministic order.
	sort.SliceStable(out, func(i, j int) bool {
		si, sj := SeverityLevels[out[i].Severity], SeverityLevels[out[j].Severity]
		if si != sj {
			return si > sj
		}
		if out[i].CVSSScore != out[j].CVSSScore {
			return out[i].CVSSScore > out[j].CVSSScore
		}
		return out[i].ID < out[j].ID
	})

	rep.Results = out

	if ignoredCount > 0 {
		rep.AddMeta(report.MetaItem{Label: "Ignored", Value: strconv.Itoa(ignoredCount)})
	}

	return rep
}

// UnfixedCount returns how many advisories are hidden because no fix is
// available for the audited package (remediation "none_available"). An
// advisory is counted once even when several audited packages reference it. It
// lets the caller warn that findings were hidden and hint at --show-unfixed.
func UnfixedCount(results []client.AuditItem) int {
	seen := make(map[string]bool)
	for _, r := range results {
		for _, adv := range r.Advisories {
			if IsUnfixed(r.PURL, adv) {
				seen[adv.ID] = true
			}
		}
	}
	return len(seen)
}
