// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"fmt"
	"strings"
	"time"

	"github.com/giterlizzi/secdb-cli/internal/ci"
	"github.com/giterlizzi/secdb-cli/internal/finding"
)

// maxFindings caps how many findings a Message carries so a provider payload
// (Slack attachment, Teams card) stays within provider size limits; the overflow
// count is reported in Truncated, so a provider can render "and N more" with a
// link to the full results.
const maxFindings = 20

// Message is the provider-agnostic notification payload. It is built once from
// the audit results (see NewMessage) and rendered into each provider's own
// format (Slack attachment, Teams Adaptive Card, email HTML, generic webhook
// JSON), so a provider never has to reshape or recompute anything.
type Message struct {
	Title     string            `json:"title"`               // headline, e.g. "SecDB audit: high severity (3 findings)"
	Source    string            `json:"source"`              // what was scanned: manifest path, "SBOM (bom.json)", linux target
	Overall   string            `json:"overall"`             // highest severity (lowercase), drives color/emoji
	Total     int               `json:"total"`               // total findings, before capping
	Counts    map[string]int    `json:"counts"`              // findings per severity, e.g. {"critical":1,"high":2}
	Findings  []finding.Finding `json:"findings"`            // severity-sorted, capped to maxFindings
	Truncated int               `json:"truncated,omitempty"` // findings omitted beyond the cap (0 = none)

	CI      ci.Env    `json:"ci,omitzero"`        // CI provenance (omitted outside CI)
	BaseURL string    `json:"base_url,omitempty"` // SecDB web-GUI url (client.WebURL)
	Time    time.Time `json:"time"`               // when the notification was generated
}

// NewMessage builds a Message from the full, severity-sorted findings of an
// audit: it computes Total and Counts over all of them, then caps Findings to
// maxFindings and records the overflow in Truncated. The caller fills in the
// context it owns (CI, BaseURL).
func NewMessage(source, overall string, findings []finding.Finding) Message {
	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}

	total := len(findings)
	var truncated int
	if total > maxFindings {
		truncated = total - maxFindings
		findings = findings[:maxFindings]
	}

	return Message{
		Title:     fmt.Sprintf("SecDB audit: %s severity (%d findings)", overall, total),
		Source:    source,
		Overall:   overall,
		Total:     total,
		Counts:    counts,
		Findings:  findings,
		Truncated: truncated,
		Time:      time.Now(),
	}
}

// detailsURL is where a provider's "view details" link should point: the CI
// run when the audit ran in CI, otherwise the SecDB instance (empty when
// neither is known, so the provider omits the link).
func (msg Message) detailsURL() string {
	if msg.CI.RunURL != "" {
		return msg.CI.RunURL
	}
	return msg.BaseURL
}

// summary is the "<source> (<N> findings)" subtitle shown under the title
// (Slack attachment title, Teams card subtitle), with N the total before
// capping. It is shared so every provider words it the same way.
func (msg Message) summary() string {
	return fmt.Sprintf("%s (%d findings)", msg.Source, msg.Total)
}

// renderFindings renders the (already capped) findings as one line each, in the
// form "name (CVE-YYYY-NNNNN, ...) - purl", with a trailing "... and N more"
// when the message was truncated. It is shared by the providers that render a
// plain-text finding list (Slack, Teams).
func (msg Message) renderFindings() []string {
	lines := make([]string, 0, len(msg.Findings)+1)
	for _, f := range msg.Findings {
		line := f.Name
		if len(f.CVEs) > 0 {
			line += " (" + strings.Join(f.CVEs, ", ") + ")"
		}
		if f.PURL != "" {
			line += " - " + f.PURL
		} else if f.Package != "" {
			line += " - " + f.Package
		}
		lines = append(lines, line)
	}
	if msg.Truncated > 0 {
		lines = append(lines, fmt.Sprintf("... and %d more", msg.Truncated))
	}
	return lines
}
