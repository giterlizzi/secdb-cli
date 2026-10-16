// SPDX-License-Identifier: Apache-2.0

package cve

import (
	"fmt"
	"regexp"
	"strings"
)

var idPattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// IsValidID reports whether id is a well-formed CVE identifier, in any case
// (CVE-2021-44228, cve-2021-44228).
func IsValidID(id string) bool {
	return idPattern.MatchString(strings.ToUpper(id))
}

// NormalizeIDs returns the CVE identifiers uppercased and without duplicates,
// in first-seen order, or an error naming the first malformed one.
func NormalizeIDs(ids []string) ([]string, error) {
	out := make([]string, 0, len(ids))
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if !IsValidID(id) {
			return nil, fmt.Errorf("invalid CVE identifier: %q (expected format: CVE-YYYY-NNNN)", id)
		}
		id = strings.ToUpper(id)
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out, nil
}
