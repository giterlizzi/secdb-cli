// SPDX-License-Identifier: Apache-2.0

package notify

import "strings"

// Severity presentation shared by the notification providers. The colors are a
// rendering concern (Slack attachment color, HTML mail), so they live here
// rather than in the domain packages; the order is the display order, most
// severe first. Providers whose format has no arbitrary color (Teams Adaptive
// Card) map the severity to their own fixed palette instead.

// severityColor maps a severity to a hex color used by providers that render a
// colored accent from an arbitrary hex value (Slack attachment bar, ...). An
// unknown severity yields "", so the provider omits the color rather than
// guessing.
var severityColor = map[string]string{
	"critical": "#b00020",
	"high":     "#d32f2f",
	"medium":   "#f57c00",
	"low":      "#fbc02d",
	"info":     "#0288d1",
}

// severityOrder is the display order (most severe first), so a rendered message
// is stable regardless of Go's map iteration order.
var severityOrder = []string{"critical", "high", "medium", "low", "info"}

// severityCount is a per-severity count ready to render: a title-cased label
// ("High") and how many findings had that severity.
type severityCount struct {
	Label string
	Count int
}

// severityCountsSorted turns per-severity counts into an ordered slice, most
// severe first and skipping zero counts, so every provider renders the same
// stable set of counts (Slack fields, Teams facts, ...).
func severityCountsSorted(counts map[string]int) []severityCount {
	var sorted []severityCount
	for _, sev := range severityOrder {
		if n := counts[sev]; n > 0 {
			sorted = append(sorted, severityCount{
				Label: strings.ToUpper(sev[:1]) + sev[1:],
				Count: n,
			})
		}
	}
	return sorted
}
