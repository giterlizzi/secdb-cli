// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"fmt"
	"log/slog"
	"maps"
	"os"
	"slices"
	"sort"
	"strings"

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

func OverallSeverity(rawResults []map[string]interface{}, ignoreFile *IgnoreFile) string {
	maxSeverity := ""

	for _, r := range rawResults {
		pkg, _ := r["package"].(string)
		advisories, _ := r["advisories"].([]interface{})

		for _, a := range advisories {
			adv, ok := a.(map[string]interface{})

			if !ok {
				continue
			}

			severity := strings.ToLower(fmt.Sprint(adv["severity"]))

			if ignoreFile != nil {
				id := adv["id"].(string)

				cvesRaw, _ := adv["cves"].([]interface{})
				cves := make([]string, 0, len(cvesRaw))
				for _, c := range cvesRaw {
					cves = append(cves, c.(string))
				}

				if ignored, _ := ignoreFile.IsIgnored(id, cves, pkg); ignored {
					continue
				}

			}

			if SeverityLevels[severity] > SeverityLevels[maxSeverity] {
				maxSeverity = severity
			}
		}
	}
	return maxSeverity
}

func SummarizePURLAudit(rawResults []map[string]interface{}) []PackageResult {
	out := make([]PackageResult, 0, len(rawResults))

	for _, r := range rawResults {
		pkg, _ := r["package"].(string)
		advisories, _ := r["advisories"].([]interface{})

		cveSeen := make(map[string]bool)
		cweSeen := make(map[string]bool)
		maxSeverity := ""

		for _, a := range advisories {
			adv, ok := a.(map[string]interface{})

			if !ok {
				continue
			}

			severity := strings.ToLower(fmt.Sprint(adv["severity"]))
			if SeverityLevels[severity] > SeverityLevels[maxSeverity] {
				maxSeverity = severity
			}

			cvesRaw, _ := adv["cves"].([]interface{})
			cwesRaw, _ := adv["weaknesses"].([]map[string]interface{})

			for _, cve := range cvesRaw {
				cveSeen[cve.(string)] = true
			}

			for _, cwe := range cwesRaw {
				cweSeen[cwe["id"].(string)] = true
			}
		}

		cves := slices.Collect(maps.Keys(cveSeen))
		cwes := slices.Collect(maps.Keys(cweSeen))

		sort.Slice(cves, func(i, j int) bool { return cves[i] > cves[j] })
		sort.Slice(cwes, func(i, j int) bool { return cwes[i] > cwes[j] })

		out = append(out, PackageResult{
			Package:       pkg,
			CVEs:          cves,
			CWEs:          cwes,
			AdvisoryCount: len(advisories),
			MaxSeverity:   maxSeverity,
		})
	}
	return out
}

func GroupByAdvisory(rawResults []map[string]interface{}, ignoreFile *IgnoreFile) []AdvisoryResult {
	byID := make(map[string]*AdvisoryResult)
	var order []string

	for _, r := range rawResults {
		pkg, _ := r["package"].(string)
		advisories, _ := r["advisories"].([]interface{})

		for _, a := range advisories {
			adv, ok := a.(map[string]interface{})
			if !ok {
				continue
			}

			id, _ := adv["id"].(string)
			if id == "" {
				continue
			}

			if _, exists := byID[id]; !exists {
				title, _ := adv["title"].(string)
				summary, _ := adv["summary"].(string)
				description, _ := adv["description"].(string)
				url, _ := adv["url"].(string)
				severity, _ := adv["severity"].(string)

				cvesRaw, _ := adv["cves"].([]interface{})
				cves := make([]string, 0, len(cvesRaw))

				cwesRaw, _ := adv["weaknesses"].([]map[string]interface{})
				cwes := make([]string, 0, len(cwesRaw))

				cvssArray, _ := adv["cvss"].([]map[string]interface{})
				cvssScore := 0.0
				cvssVersion := 0.0

				for _, c := range cvesRaw {
					cves = append(cves, c.(string))
				}

				for _, w := range cwesRaw {
					cwes = append(cwes, w["id"].(string))
				}

				for _, cvss := range cvssArray {
					score := cvss["base_score"].(float64)
					version := cvss["version"].(float64)
					if cvssVersion < version {
						cvssScore = score
					}
				}

				sort.Slice(cves, func(i, j int) bool { return cves[i] > cves[j] })
				sort.Slice(cwes, func(i, j int) bool { return cwes[i] > cwes[j] })

				ignored, reason := ignoreFile.IsIgnored(id, cves, pkg)

				byID[id] = &AdvisoryResult{
					ID:           id,
					Title:        title,
					Summary:      summary,
					Description:  description,
					URL:          url,
					Severity:     strings.ToLower(severity),
					CVEs:         cves,
					CWEs:         cwes,
					CVSSScore:    cvssScore,
					Ignored:      ignored,
					IgnoreReason: reason,
				}

				order = append(order, id)
			}
			byID[id].Packages = append(byID[id].Packages, pkg)
		}
	}

	out := make([]AdvisoryResult, 0, len(order))
	for _, id := range order {
		out = append(out, *byID[id])
	}
	return out
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
