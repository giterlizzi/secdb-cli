// SPDX-License-Identifier: Apache-2.0

// This file holds the request/response models (DTOs) of the ZEN SecDB API. They
// are plain data shapes with no behaviour; the transport lives in client.go and
// the domain logic that interprets them (e.g. "is this advisory unfixed?")
// lives in internal/audit.
package client

import "time"

type purlAuditRequest struct {
	Purls []string `json:"purls"`
}

type linuxAuditRequest struct {
	OS       string   `json:"os"`
	Version  string   `json:"version"`
	Arch     string   `json:"arch,omitempty"`
	Packages []string `json:"packages"`
}

type AuditItem struct {
	Package    string                 `json:"package"`
	PURL       string                 `json:"purl"`
	Software   map[string]interface{} `json:"software,omitempty"`
	CVEs       []string               `json:"cves"`
	Advisories []Advisory             `json:"advisories"`
}

type Timestamp struct {
	time.Time
}

func (t *Timestamp) UnmarshalJSON(b []byte) (err error) {
	date, err := time.Parse(`"2006-01-02T15:04:05"`, string(b))
	if err != nil {
		return err
	}
	t.Time = date
	return
}

type Advisory struct {
	ID             string    `json:"id"`
	Type           string    `json:"type"`
	Published      Timestamp `json:"published"`
	Modified       Timestamp `json:"modified"`
	Title          string    `json:"title"`
	Summary        string    `json:"summary,omitempty"`
	Description    string    `json:"description,omitempty"`
	Solution       string    `json:"solution,omitempty"`
	Rights         string    `json:"rights"`
	URL            string    `json:"url"`
	Severity       string    `json:"severity,omitempty"`
	SeveritySource string    `json:"severity_source,omitempty"`
	Tags           []string  `json:"tags"`
	Impacts        []string  `json:"impacts"`
	CVEs           []string  `json:"cves"`
	Weaknesses     []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"weaknesses"`
	CVSS []struct {
		Version      float64 `json:"version"`
		BaseScore    float64 `json:"base_score"`
		BaseSeverity string  `json:"base_severity"`
		VectorString string  `json:"vector_string"`
	} `json:"cvss"`
	References []struct {
		Name   string `json:"name,omitempty"`
		RefID  string `json:"ref_id,omitempty"`
		Source string `json:"source,omitempty"`
		URL    string `json:"url"`
	} `json:"references"`
	Packages []struct {
		Status      string `json:"status"`
		PURL        string `json:"purl"`
		VERS        string `json:"vers"`
		Remediation string `json:"remediation"`
	} `json:"packages"`
}

type ssvcBulkRequest struct {
	CVEs                  []string `json:"cves"`
	MissionPrevalence     string   `json:"mission_prevalence"`
	PublicWellBeingImpact string   `json:"public_well_being_impact"`
}

type SSVCBulkResponse struct {
	CVE struct {
		ID    string `json:"id" yaml:"id"`
		Title string `json:"title" yaml:"title"`
	} `json:"cve" yaml:"cve"`
	SSVC   SSVCResponse `json:"ssvc" yaml:"ssvc"`
	Status string       `json:"status" yaml:"status"`

	VectorString string `json:"vector_string" yaml:"vector_string"`
}

type SSVCResponse struct {
	Exploitation           string `json:"exploitation" yaml:"exploitation"`
	Automatable            string `json:"automatable" yaml:"automatable"`
	TechnicalImpact        string `json:"technical_impact" yaml:"technical_impact"`
	MissionPrevalence      string `json:"mission_prevalence" yaml:"mission_prevalence"`
	PublicWellBeingImpact  string `json:"public_well_being_impact" yaml:"public_well_being_impact"`
	MissionWellBeingImpact string `json:"mission_well_being_impact" yaml:"mission_well_being_impact"`
	Decision               string `json:"decision" yaml:"decision"`
}
