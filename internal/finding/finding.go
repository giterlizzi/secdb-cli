// SPDX-License-Identifier: Apache-2.0

// Package finding is the source-agnostic, flat security-finding model shared by
// every producer and every consumer (notifications, reports, etc.)
package finding

import "time"

// Finding is one normalized security finding: one (source test, target) pair.
// The `db` tags map to the VulnMgmt table columns; the `json` tags are the
// webhook/export contract.
type Finding struct {
	Source   string    `db:"source" json:"source"`
	SourceID string    `db:"source_id" json:"source_id"`
	UUID     string    `db:"uuid" json:"uuid,omitempty"`
	ScanTime time.Time `db:"scan_time" json:"scan_time,omitzero"`

	Name        string   `db:"name" json:"name,omitempty"`
	Severity    string   `db:"severity" json:"severity"`
	Summary     string   `db:"summary" json:"summary,omitempty"`
	Description string   `db:"description" json:"description,omitempty"`
	Mitigation  string   `db:"mitigation" json:"mitigation,omitempty"`
	Impact      string   `db:"impact" json:"impact,omitempty"`
	References  []string `db:"references" json:"references,omitempty"`

	// Network / web target
	IPAddress string `db:"ip_address" json:"ip_address,omitempty"`
	Hostname  string `db:"hostname" json:"hostname,omitempty"`
	Protocol  string `db:"protocol" json:"protocol,omitempty"`
	Port      int    `db:"port" json:"port,omitempty"`
	URL       string `db:"url" json:"url,omitempty"`
	Service   string `db:"service" json:"service,omitempty"`

	// Dependency / SCA target
	Package string `db:"package" json:"package,omitempty"`
	PURL    string `db:"purl" json:"purl,omitempty"`
	File    string `db:"file" json:"file,omitempty"`
	Line    int    `db:"line" json:"line,omitempty"`

	CVEs []string `db:"cve" json:"cves,omitempty"`
	CWEs []string `db:"cwe" json:"cwes,omitempty"`
	CPEs []string `db:"cpe" json:"cpes,omitempty"`

	// Scoring, per CVSS version
	CVSSScore   float64 `db:"cvss_score" json:"cvss_score,omitempty"`
	CVSSVector  string  `db:"cvss_vector" json:"cvss_vector,omitempty"`
	CVSS3Score  float64 `db:"cvss3_score" json:"cvss3_score,omitempty"`
	CVSS3Vector string  `db:"cvss3_vector" json:"cvss3_vector,omitempty"`
	CVSS4Score  float64 `db:"cvss4_score" json:"cvss4_score,omitempty"`
	CVSS4Vector string  `db:"cvss4_vector" json:"cvss4_vector,omitempty"`
}
