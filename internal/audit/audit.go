// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

type PackageResult struct {
	Package       string   `json:"package"`
	CVEs          []string `json:"cves"`
	AdvisoryCount int      `json:"advisory_count"`
	MaxSeverity   string   `json:"max_severity"`
}

type AdvisoryResult struct {
	ID       string
	Title    string
	Severity string
	Packages []string
	CVEs     []string
}

var SeverityLevels = map[string]int{
	"critical": 5, "high": 4, "medium": 3, "moderate": 3, "low": 2, "info": 1, "unknown": 1, "": 0,
}

func OverallSeverity(rawResults []map[string]interface{}) string {
	maxSeverity := ""

	for _, r := range rawResults {
		advisories, _ := r["advisories"].([]interface{})

		for _, a := range advisories {
			advisory, ok := a.(map[string]interface{})

			if !ok {
				continue
			}

			severity := strings.ToLower(fmt.Sprint(advisory["severity"]))
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

		cveSet := make(map[string]bool)
		maxSeverity := ""

		for _, a := range advisories {
			advisory, ok := a.(map[string]interface{})

			if !ok {
				continue
			}

			severity := strings.ToLower(fmt.Sprint(advisory["severity"]))
			if SeverityLevels[severity] > SeverityLevels[maxSeverity] {
				maxSeverity = severity
			}

			cvesRaw, _ := advisory["cves"].([]interface{})

			for _, c := range cvesRaw {
				if s, ok := c.(string); ok {
					cveSet[s] = true
				}
			}
		}

		cves := make([]string, 0, len(cveSet))

		for cve := range cveSet {
			cves = append(cves, cve)
		}

		sort.Slice(cves, func(i, j int) bool { return cves[i] > cves[j] })

		out = append(out, PackageResult{
			Package:       pkg,
			CVEs:          cves,
			AdvisoryCount: len(advisories),
			MaxSeverity:   maxSeverity,
		})
	}
	return out
}

func GroupByAdvisory(rawResults []map[string]interface{}) []AdvisoryResult {
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
				severity, _ := adv["severity"].(string)

				cvesRaw, _ := adv["cves"].([]interface{})
				cves := make([]string, 0, len(cvesRaw))

				for _, c := range cvesRaw {
					if s, ok := c.(string); ok {
						cves = append(cves, s)
					}
				}

				byID[id] = &AdvisoryResult{
					ID:       id,
					Title:    title,
					Severity: strings.ToLower(severity),
					CVEs:     cves,
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

func ReadPURLsFromFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	return ReadPURLs(f)
}

func ReadPURLs(r io.Reader) ([]string, error) {
	purls := []string{}
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		purls = append(purls, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading input: %w", err)
	}

	return purls, nil
}

func DeduplicatePURLs(purls []string) []string {
	seen := make(map[string]bool, len(purls))
	unique := []string{}

	for _, p := range purls {
		if !seen[p] {
			seen[p] = true
			unique = append(unique, p)
		}
	}

	return unique
}
