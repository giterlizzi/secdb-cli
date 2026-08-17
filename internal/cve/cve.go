// SPDX-License-Identifier: Apache-2.0

package cve

import (
	"regexp"
	"sort"
	"strings"
)

type vendorCount struct {
	Vendor string
	Count  int
}

func IsValidCVE(cveID string) bool {
	cveIDPattern := regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
	return cveIDPattern.MatchString(strings.ToUpper(cveID))
}

func SummarizeAffectedProducts(data map[string]interface{}) {
	raw, ok := data["affected_products"].([]interface{})
	if !ok {
		return
	}

	counts := map[string]int{}
	var affectedTotal, notAffectedTotal int

	for _, item := range raw {
		entry, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		vulnerable, _ := entry["vulnerable"].(bool)
		vendor, _ := entry["vendor"].(string)

		if vulnerable {
			counts[vendor]++
			affectedTotal++
		} else {
			notAffectedTotal++
		}
	}

	summary := make([]vendorCount, 0, len(counts))
	for vendor, count := range counts {
		summary = append(summary, vendorCount{Vendor: vendor, Count: count})
	}
	sort.Slice(summary, func(i, j int) bool {
		if summary[i].Count != summary[j].Count {
			return summary[i].Count > summary[j].Count
		}
		return summary[i].Vendor < summary[j].Vendor
	})

	data["affected_vendors_summary"] = summary
	data["affected_total"] = affectedTotal
	data["not_affected_total"] = notAffectedTotal
}
