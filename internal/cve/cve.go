// SPDX-License-Identifier: Apache-2.0

// Package cve provides CVE enrichment.
package cve

import (
	"cmp"
	"slices"
)

type vendorCount struct {
	Vendor string
	Count  int
}

// SummarizeAffectedProducts enriches the raw CVE data map in place with
// affected-vendor and affected/not-affected totals.
func SummarizeAffectedProducts(data map[string]any) {
	raw, ok := data["affected_products"].([]any)
	if !ok {
		return
	}

	counts := map[string]int{}
	var affectedTotal, notAffectedTotal int

	for _, item := range raw {
		entry, ok := item.(map[string]any)
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
	// Most affected products first, then by vendor name.
	slices.SortFunc(summary, func(a, b vendorCount) int {
		return cmp.Or(cmp.Compare(b.Count, a.Count), cmp.Compare(a.Vendor, b.Vendor))
	})

	data["affected_vendors_summary"] = summary
	data["affected_total"] = affectedTotal
	data["not_affected_total"] = notAffectedTotal
}
