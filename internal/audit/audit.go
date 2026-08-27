// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"fmt"
	"log/slog"
	"maps"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/giterlizzi/secdb-cli/internal/client"
	"github.com/giterlizzi/secdb-cli/internal/report"

	cdx "github.com/CycloneDX/cyclonedx-go"
	packageurl "github.com/package-url/packageurl-go"
)

type PackageResult struct {
	Package       string   `json:"package"`
	CVEs          []string `json:"cves"`
	CWEs          []string `json:"cwes"`
	AdvisoryCount int      `json:"advisory_count"`
	MaxSeverity   string   `json:"max_severity"`
}

type AdvisoryResult struct {
	ID           string
	Title        string
	Summary      string
	Description  string
	Severity     string
	Packages     []string
	CVEs         []string
	CWEs         []string
	CVSSScore    float64
	URL          string
	Ignored      bool
	IgnoreReason string
}

var SeverityLevels = map[string]int{
	"critical": 5, "high": 4, "medium": 3, "moderate": 3, "low": 2, "info": 1, "unknown": 1, "": 0,
}

func OverallSeverity(results []client.AuditItem, ignoreFile *IgnoreFile) string {
	maxSeverity := ""

	for _, r := range results {
		for _, adv := range r.Advisories {

			if ignoreFile != nil {
				if ignored, _ := ignoreFile.IsIgnored(adv.ID, adv.CVEs, r.Package); ignored {
					continue
				}
			}

			severity := strings.ToLower(adv.Severity)
			if SeverityLevels[severity] > SeverityLevels[maxSeverity] {
				maxSeverity = severity
			}
		}
	}
	return maxSeverity
}

func SummarizePURLAudit(results []client.AuditItem) []PackageResult {
	out := make([]PackageResult, 0, len(results))

	for _, r := range results {
		cveSeen := make(map[string]bool)
		cweSeen := make(map[string]bool)
		maxSeverity := ""

		for _, adv := range r.Advisories {
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

		cves := slices.Collect(maps.Keys(cveSeen))
		cwes := slices.Collect(maps.Keys(cweSeen))

		sort.Slice(cves, func(i, j int) bool { return cves[i] > cves[j] })
		sort.Slice(cwes, func(i, j int) bool { return cwes[i] > cwes[j] })

		out = append(out, PackageResult{
			Package:       r.Package,
			CVEs:          cves,
			CWEs:          cwes,
			AdvisoryCount: len(r.Advisories),
			MaxSeverity:   maxSeverity,
		})
	}
	return out
}

func GroupByAdvisory(results []client.AuditItem, ignoreFile *IgnoreFile) report.Report {
	byID := make(map[string]*AdvisoryResult)
	var order []string
	var ignoredCount int

	r := report.Report{}

	for _, res := range results {
		for _, adv := range res.Advisories {

			if _, exists := byID[adv.ID]; !exists {
				cwesRaw := adv.Weaknesses
				cwes := make([]string, 0, len(cwesRaw))

				cvssArray := adv.CVSS
				cvssScore := 0.0
				cvssVersion := 0.0

				for _, w := range cwesRaw {
					cwes = append(cwes, w.ID)
				}

				for _, cvss := range cvssArray {
					// Keep the score of the highest CVSS version available.
					if cvss.Version >= cvssVersion {
						cvssVersion = cvss.Version
						cvssScore = cvss.BaseScore
					}
				}

				ignored, reason := ignoreFile.IsIgnored(adv.ID, adv.CVEs, res.Package)

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
					CWEs:         cwes,
					CVSSScore:    cvssScore,
					Ignored:      ignored,
					IgnoreReason: reason,
				}

				order = append(order, adv.ID)
			}
			byID[adv.ID].Packages = append(byID[adv.ID].Packages, res.Package)
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

	r.Results = out
	r.AddMeta(report.MetaItem{Label: "Ignored", Value: strconv.Itoa(ignoredCount)})

	return r
}

func ValidatePURLs(purls []string) []string {
	valid := []string{}

	for _, p := range purls {
		purl, err := packageurl.FromString(p)
		if err != nil {
			slog.Debug("skipping invalid PURL", "value", p, "error", err)
			continue
		}
		slog.Debug("found PURL", "purl", purl.ToString())
		valid = append(valid, purl.ToString())
	}

	return valid
}

func ReadPURLsFromSBOM(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open SBOM %s: %w", path, err)
	}
	defer f.Close()

	bom := new(cdx.BOM)
	decoder := cdx.NewBOMDecoder(f, cdx.BOMFileFormatJSON)

	if err := decoder.Decode(bom); err != nil {
		return nil, fmt.Errorf("failed to decode SBOM %s: %w", path, err)
	}

	if bom.Components == nil {
		return nil, fmt.Errorf("no Components found in SBOM file")
	}

	purls := []string{}

	var walk func(components *[]cdx.Component)

	walk = func(components *[]cdx.Component) {
		if components == nil {
			return
		}

		for _, c := range *components {
			if c.PackageURL != "" {
				purls = append(purls, c.PackageURL)
				slog.Debug("found PURL in CycloneDX SBOM component", slog.String("purl", c.PackageURL))
			}
			walk(c.Components)
		}
	}

	walk(bom.Components)

	return purls, nil
}
