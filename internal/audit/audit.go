// SPDX-License-Identifier: Apache-2.0

// Package audit shapes and filters audit results and handles PURL input.
package audit

import (
	"cmp"
	"fmt"
	"log/slog"
	"maps"
	"slices"
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
	IgnoredPURLs map[string]string
	Unfixed      bool
}

// SeverityLevels ranks the canonical severities (see NormalizeSeverity) so they
// can be compared and sorted; "" (no severity) ranks lowest.
var SeverityLevels = map[string]int{
	"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "": 0,
}

// severityAliases maps the vendor-specific severity names the feeds use (e.g.
// GitHub/Red Hat/SUSE "moderate", Red Hat "important") to a canonical one.
var severityAliases = map[string]string{
	"moderate":  "medium",
	"important": "high",
	"urgent":    "high",
	"severe":    "high",
	"unknown":   "info",
}

// NormalizeSeverity lowercases a severity and maps its aliases to one of the
// canonical values ranked by SeverityLevels, so every consumer (fail-on,
// notifications, SARIF, templates) sees the same vocabulary. An unrecognized
// value is returned lowercased and ranks like "" (no severity).
func NormalizeSeverity(severity string) string {
	s := strings.ToLower(strings.TrimSpace(severity))
	if alias, ok := severityAliases[s]; ok {
		return alias
	}
	return s
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

			severity := NormalizeSeverity(adv.Severity)
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

			severity := NormalizeSeverity(adv.Severity)
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

		// Descending, as before (e.g. newest CVE year first).
		slices.SortFunc(cves, func(a, b string) int { return cmp.Compare(b, a) })
		slices.SortFunc(cwes, func(a, b string) int { return cmp.Compare(b, a) })

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

	rep := report.Report{}

	for _, r := range results {
		for _, adv := range r.Advisories {

			unfixed := IsUnfixed(r.PURL, adv)

			if hideUnfixed(r.PURL, adv, showUnfixed) {
				continue
			}

			if _, exists := byID[adv.ID]; !exists {
				byID[adv.ID] = &AdvisoryResult{
					ID:          adv.ID,
					Title:       adv.Title,
					Summary:     adv.Summary,
					Description: adv.Description,
					URL:         adv.URL,
					Severity:    NormalizeSeverity(adv.Severity),
					CVEs:        adv.CVEs,
					CWEs:        cweIDs(adv),
					CVSSScore:   latestCVSSScore(adv),
					Unfixed:     unfixed,
				}

				order = append(order, adv.ID)
			}

			res := byID[adv.ID]
			res.Packages = append(res.Packages, r.Package)
			res.PURLs = append(res.PURLs, r.PURL)

			if unfixed {
				res.Unfixed = true
			}

			// Evaluated per package, like OverallSeverity: a rule scoped to one
			// package must not accept the advisory for the others.
			if ignored, reason := ignoreFile.IsIgnored(adv.ID, adv.CVEs, r.PURL); ignored {
				if res.IgnoredPURLs == nil {
					res.IgnoredPURLs = make(map[string]string)
				}
				res.IgnoredPURLs[r.PURL] = reason
			}
		}
	}

	var ignoredCount, partiallyIgnored int
	out := make([]AdvisoryResult, 0, len(order))
	for _, id := range order {
		res := byID[id]
		switch {
		case len(res.IgnoredPURLs) == 0:
		case res.ignoredForAll():
			res.Ignored = true
			res.IgnoreReason = res.IgnoredPURLs[res.PURLs[0]]
			ignoredCount++
		default:
			partiallyIgnored++
		}
		out = append(out, *res)
	}

	// Most severe first (then higher CVSS, then ID) so the details view leads
	// with what matters; ties keep a stable, deterministic order.
	slices.SortStableFunc(out, func(a, b AdvisoryResult) int {
		return cmp.Or(
			cmp.Compare(SeverityLevels[b.Severity], SeverityLevels[a.Severity]),
			cmp.Compare(b.CVSSScore, a.CVSSScore),
			cmp.Compare(a.ID, b.ID),
		)
	})

	rep.Results = out

	if ignoredCount > 0 || partiallyIgnored > 0 {
		value := strconv.Itoa(ignoredCount)
		switch {
		case partiallyIgnored > 0 && ignoredCount == 0:
			value = fmt.Sprintf("%d for some packages only", partiallyIgnored)
		case partiallyIgnored > 0:
			value += fmt.Sprintf(" (+%d for some packages only)", partiallyIgnored)
		}
		rep.AddMeta(report.MetaItem{Label: "Ignored", Value: value})
	}

	return rep
}

// IgnoredFor reports whether an ignore rule accepts the advisory for purl, and
// the rule's reason. A result built with Ignored but no per-package matches
// (e.g. by hand) counts as ignored for every package.
func (a AdvisoryResult) IgnoredFor(purl string) (bool, string) {
	if reason, ok := a.IgnoredPURLs[purl]; ok {
		return true, reason
	}
	if a.Ignored {
		return true, a.IgnoreReason
	}
	return false, ""
}

// ignoredForAll reports whether every affected package has an ignore match.
func (a AdvisoryResult) ignoredForAll() bool {
	for _, purl := range a.PURLs {
		if _, ok := a.IgnoredPURLs[purl]; !ok {
			return false
		}
	}
	return len(a.PURLs) > 0
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
