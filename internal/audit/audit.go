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
	overall := ""
	for _, r := range results {
		for _, adv := range r.Advisories {
			if hideUnfixed(r.PURL, adv, showUnfixed) {
				continue
			}
			if ignored, _ := ignoreFile.IsIgnored(adv.ID, adv.CVEs, r.PURL); ignored {
				slog.Debug("ignored", "advisory", adv.ID, "cves", adv.CVEs, "purl", r.PURL)
				continue
			}
			overall = maxSeverity(overall, NormalizeSeverity(adv.Severity))
		}
	}
	return overall
}

// maxSeverity returns the more severe of two canonical severities (a on a tie).
func maxSeverity(a, b string) string {
	if SeverityLevels[b] > SeverityLevels[a] {
		return b
	}
	return a
}

// SummarizePURLAudit shapes the results into one summary row per package.
func SummarizePURLAudit(results []client.AuditItem, showUnfixed bool) []PackageResult {
	out := make([]PackageResult, 0, len(results))
	for _, r := range results {
		// A package whose advisories were all filtered out (e.g. all unfixed) is
		// skipped, so the summary doesn't show a row with no visible findings.
		if row := summarizePackage(r, showUnfixed); row.AdvisoryCount > 0 {
			out = append(out, row)
		}
	}
	return out
}

// summarizePackage builds the summary row of one audited package from its
// visible advisories.
func summarizePackage(r client.AuditItem, showUnfixed bool) PackageResult {
	row := PackageResult{Package: r.Package}
	cves, cwes := make(map[string]bool), make(map[string]bool)
	for _, adv := range r.Advisories {
		if hideUnfixed(r.PURL, adv, showUnfixed) {
			continue
		}
		row.AdvisoryCount++
		row.MaxSeverity = maxSeverity(row.MaxSeverity, NormalizeSeverity(adv.Severity))
		for _, id := range adv.CVEs {
			cves[id] = true
		}
		for _, id := range cweIDs(adv) {
			cwes[id] = true
		}
	}
	row.CVEs, row.CWEs = sortedDesc(cves), sortedDesc(cwes)
	return row
}

// sortedDesc returns the set's members in descending order (e.g. newest CVE
// year first), or nil for an empty set.
func sortedDesc(set map[string]bool) []string {
	out := slices.Sorted(maps.Keys(set))
	slices.Reverse(out)
	return out
}

// GroupByAdvisory shapes the results into one row per advisory (severity-sorted),
// annotating each with its affected packages and ignore/unfixed status.
func GroupByAdvisory(results []client.AuditItem, ignoreFile *IgnoreFile, showUnfixed bool) report.Report {
	byID := make(map[string]*AdvisoryResult)
	var grouped []*AdvisoryResult // first-seen order, sorted by advisoryReport

	for _, r := range results {
		for _, adv := range r.Advisories {
			if hideUnfixed(r.PURL, adv, showUnfixed) {
				continue
			}

			res, ok := byID[adv.ID]
			if !ok {
				res = newAdvisoryResult(adv)
				byID[adv.ID] = res
				grouped = append(grouped, res)
			}
			// Without showUnfixed an unfixed advisory was hidden above.
			res.addPackage(r, adv, showUnfixed && IsUnfixed(r.PURL, adv), ignoreFile)
		}
	}
	return advisoryReport(grouped)
}

// addPackage records an affected package on the grouped row, with its unfixed
// status and its own ignore match: evaluated per package, like OverallSeverity,
// since a rule scoped to one package must not accept the advisory for the others.
func (a *AdvisoryResult) addPackage(r client.AuditItem, adv client.Advisory, unfixed bool, ignoreFile *IgnoreFile) {
	a.Packages = append(a.Packages, r.Package)
	a.PURLs = append(a.PURLs, r.PURL)
	a.Unfixed = a.Unfixed || unfixed

	if ignored, reason := ignoreFile.IsIgnored(adv.ID, adv.CVEs, r.PURL); ignored {
		if a.IgnoredPURLs == nil {
			a.IgnoredPURLs = make(map[string]string)
		}
		a.IgnoredPURLs[r.PURL] = reason
	}
}

// newAdvisoryResult starts the grouped row of an advisory, without packages.
func newAdvisoryResult(adv client.Advisory) *AdvisoryResult {
	return &AdvisoryResult{
		ID:          adv.ID,
		Title:       adv.Title,
		Summary:     adv.Summary,
		Description: adv.Description,
		URL:         adv.URL,
		Severity:    NormalizeSeverity(adv.Severity),
		CVEs:        adv.CVEs,
		CWEs:        cweIDs(adv),
		CVSSScore:   latestCVSSScore(adv),
	}
}

// advisoryReport finalizes the grouped advisories: it resolves each one's
// whole-advisory ignore status, sorts them and adds the "Ignored" header row.
func advisoryReport(grouped []*AdvisoryResult) report.Report {
	var full, partial int
	out := make([]AdvisoryResult, 0, len(grouped))
	for _, res := range grouped {
		switch {
		case len(res.IgnoredPURLs) == 0:
		case res.ignoredForAll():
			res.Ignored, res.IgnoreReason = true, res.IgnoredPURLs[res.PURLs[0]]
			full++
		default:
			partial++
		}
		out = append(out, *res)
	}
	sortAdvisories(out)

	rep := report.Report{Results: out}
	if item, ok := ignoredMeta(full, partial); ok {
		rep.AddMeta(item)
	}
	return rep
}

// sortAdvisories orders the advisories most severe first (then higher CVSS,
// then ID), so the details view leads with what matters; ties keep a stable,
// deterministic order.
func sortAdvisories(out []AdvisoryResult) {
	slices.SortStableFunc(out, func(a, b AdvisoryResult) int {
		return cmp.Or(
			cmp.Compare(SeverityLevels[b.Severity], SeverityLevels[a.Severity]),
			cmp.Compare(b.CVSSScore, a.CVSSScore),
			cmp.Compare(a.ID, b.ID),
		)
	})
}

// ignoredMeta is the text header's "Ignored" row: the fully ignored advisories,
// plus those accepted for some packages only (false when there are none).
func ignoredMeta(full, partial int) (report.MetaItem, bool) {
	var value string
	switch {
	case full == 0 && partial == 0:
		return report.MetaItem{}, false
	case partial == 0:
		value = strconv.Itoa(full)
	case full == 0:
		value = fmt.Sprintf("%d for some packages only", partial)
	default:
		value = fmt.Sprintf("%d (+%d for some packages only)", full, partial)
	}
	return report.MetaItem{Label: "Ignored", Value: value}, true
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
