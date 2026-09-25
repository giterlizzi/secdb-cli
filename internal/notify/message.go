// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"time"

	"github.com/giterlizzi/secdb-cli/internal/ci"
	"github.com/giterlizzi/secdb-cli/internal/finding"
)

// MaxFindings caps how many findings a Message carries so a provider payload
// (Slack blocks, Teams card) stays within provider size limits; the overflow
// count is reported in Truncated, so a provider can render "and N more" with a
// link to the full results.
const MaxFindings = 20

// Message is the provider-agnostic notification payload. It is built once from
// the audit results and rendered into each provider's own format (Slack Block
// Kit, Teams Adaptive Card, email HTML, generic webhook JSON), so a provider
// never has to reshape or recompute anything.
type Message struct {
	Title     string            `json:"title"`               // headline, e.g. "SecDB audit: 3 high-severity vulnerabilities"
	Source    string            `json:"source"`              // what was scanned: manifest path, "SBOM (bom.json)", linux target
	Overall   string            `json:"overall"`             // highest severity (lowercase), drives color/emoji
	Total     int               `json:"total"`               // total findings, before capping
	Counts    map[string]int    `json:"counts"`              // findings per severity, e.g. {"critical":1,"high":2}
	Findings  []finding.Finding `json:"findings"`            // severity-sorted, capped to MaxFindings
	Truncated int               `json:"truncated,omitempty"` // findings omitted beyond the cap (0 = none)

	CI      ci.Env    `json:"ci,omitzero"`        // CI provenance (omitted outside CI)
	BaseURL string    `json:"base_url,omitempty"` // SecDB instance url
	Time    time.Time `json:"time"`               // when the notification was generated
}
