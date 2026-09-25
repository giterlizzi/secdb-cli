// SPDX-License-Identifier: Apache-2.0

package notify

// Severity presentation shared by the notification providers. The colors are a
// rendering concern (Slack attachment color, Teams themeColor, HTML mail), so
// they live here rather than in the domain packages; the order is the display
// order, most severe first.

// severityColor maps a severity to a hex color used by providers that render a
// colored accent (Slack attachment bar, Teams themeColor, ...).
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

// colorFor returns the accent color for a severity, or empty when unknown (a
// provider then omits the color rather than guessing).
func colorFor(severity string) string {
	return severityColor[severity]
}
