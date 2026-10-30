// SPDX-License-Identifier: Apache-2.0

package output

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"regexp"
	"slices"
	"strings"

	"github.com/giterlizzi/secdb-cli/internal/audit"
	"github.com/giterlizzi/secdb-cli/internal/meta"
	"github.com/giterlizzi/secdb-cli/internal/weblink"

	packageurl "github.com/package-url/packageurl-go"
)

// DefectDojoOptions describes the audited source of a DefectDojo report.
type DefectDojoOptions struct {
	// WebURL is the web-GUI base of the advisory permalinks.
	WebURL string

	// File is the location of every finding (the SBOM, the OS), unless Sources
	// has the finding's PURL.
	File string

	// Sources maps a PURL to the manifest file and line that declares it.
	Sources map[string]SourceLocation
}

// ddReport is the DefectDojo "Generic Findings Import" JSON. DefectDojo rejects
// a finding with a key outside its allowlist, so ddFinding holds only allowed
// keys.
type ddReport struct {
	Name     string      `json:"name"`
	Version  string      `json:"version"`
	Findings []ddFinding `json:"findings"`
}

type ddFinding struct {
	Title            string   `json:"title"`
	Severity         string   `json:"severity"`
	Description      string   `json:"description"`
	Mitigation       string   `json:"mitigation,omitempty"`
	References       string   `json:"references,omitempty"`
	Date             string   `json:"date,omitempty"`
	VulnerabilityIDs []string `json:"vulnerability_ids,omitempty"`
	CWEs             []string `json:"cwes,omitempty"`
	CVSSv3           string   `json:"cvssv3,omitempty"`
	CVSSv3Score      float64  `json:"cvssv3_score,omitempty"`
	CVSSv4           string   `json:"cvssv4,omitempty"`
	CVSSv4Score      float64  `json:"cvssv4_score,omitempty"`
	ComponentName    string   `json:"component_name,omitempty"`
	ComponentVersion string   `json:"component_version,omitempty"`
	FilePath         string   `json:"file_path,omitempty"`
	Line             int      `json:"line,omitempty"`
	StaticFinding    bool     `json:"static_finding"`
	UniqueIDFromTool string   `json:"unique_id_from_tool"`
	VulnIDFromTool   string   `json:"vuln_id_from_tool"`
	FixAvailable     *bool    `json:"fix_available,omitempty"`
	RiskAccepted     bool     `json:"risk_accepted,omitempty"`
	EPSSScore        float64  `json:"epss_score,omitempty"`
	EPSSPercentile   float64  `json:"epss_percentile,omitempty"`
	KnownExploited   bool     `json:"known_exploited,omitempty"`
	KEVDate          string   `json:"kev_date,omitempty"`
	RansomwareUsed   bool     `json:"ransomware_used,omitempty"`
	Tags             []string `json:"tags,omitempty"`
}

// cweIDRe matches the CWE ids DefectDojo can store ("CWE-79"); feed
// placeholders such as "NVD-CWE-noinfo" are left out.
var cweIDRe = regexp.MustCompile(`^CWE-\d+$`)

// WriteDefectDojo writes the advisories as a DefectDojo Generic Findings
// Import report, one finding per (advisory, package), for import-scan and
// reimport-scan. unique_id_from_tool is a hash of the advisory and the PURL
// (ddUniqueID), so a reimport matches the same finding; an ignore rule marks the finding
// risk_accepted, an advisory with no fix sets fix_available false, the
// highest EPSS of its CVEs sets epss_score and epss_percentile, a CVE in the
// CISA KEV catalog sets known_exploited, kev_date (the earliest added date)
// and, when the catalog says "Known", ransomware_used.
func WriteDefectDojo(w io.Writer, advisories []audit.AdvisoryResult, opts DefectDojoOptions) error {
	rep := ddReport{Name: "secdb-cli", Version: meta.Version, Findings: []ddFinding{}}
	for _, adv := range advisories {
		for i, purl := range adv.PURLs {
			pkg := purl
			if i < len(adv.Packages) && adv.Packages[i] != "" {
				pkg = adv.Packages[i]
			}
			rep.Findings = append(rep.Findings, ddFindingFor(adv, purl, pkg, opts))
		}
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

// ddFindingFor maps one (advisory, package) pair to a DefectDojo finding.
func ddFindingFor(adv audit.AdvisoryResult, purl, pkg string, opts DefectDojoOptions) ddFinding {
	f := ddFinding{
		Title:            adv.ID + ": " + pkg,
		Severity:         ddSeverity(adv.Severity),
		Description:      ddDescription(adv),
		Mitigation:       adv.Solution,
		References:       strings.Join(ddReferences(adv, opts.WebURL), "\n"),
		VulnerabilityIDs: adv.CVEs,
		StaticFinding:    true,
		UniqueIDFromTool: ddUniqueID(adv.ID, purl),
		VulnIDFromTool:   adv.ID,
		Tags:             []string{"secdb"},
	}
	if !adv.Published.IsZero() {
		f.Date = adv.Published.Format("2006-01-02")
	}
	if adv.EPSS != nil {
		f.EPSSScore, f.EPSSPercentile = adv.EPSS.Score, adv.EPSS.Percentile
	}
	for _, k := range adv.KEV {
		f.KnownExploited = true
		if date := k.Added.Format("2006-01-02"); !k.Added.IsZero() && (f.KEVDate == "" || date < f.KEVDate) {
			f.KEVDate = date
		}
		f.RansomwareUsed = f.RansomwareUsed || k.Ransomware == "Known"
	}
	for _, id := range adv.CWEs {
		if cweIDRe.MatchString(id) {
			f.CWEs = append(f.CWEs, id)
		}
	}
	for _, c := range adv.CVSS {
		switch {
		case strings.HasPrefix(c.Vector, "CVSS:3.") && c.Score >= f.CVSSv3Score:
			f.CVSSv3, f.CVSSv3Score = c.Vector, c.Score
		case strings.HasPrefix(c.Vector, "CVSS:4.") && c.Score >= f.CVSSv4Score:
			f.CVSSv4, f.CVSSv4Score = c.Vector, c.Score
		}
	}
	if p, err := packageurl.FromString(purl); err == nil {
		f.ComponentName = strings.TrimPrefix(p.Namespace+"/"+p.Name, "/")
		f.ComponentVersion = p.Version
	}
	f.FilePath, f.Line = locate(purl, opts.File, opts.Sources)
	if adv.UnfixedFor(purl) {
		fixAvailable := false
		f.FixAvailable = &fixAvailable
	}
	if ignored, reason := adv.IgnoredFor(purl); ignored {
		f.RiskAccepted = true
		if reason != "" {
			f.Description += "\n\n**Accepted in .secdbignore:** " + reason
		}
	}
	return f
}

// ddUniqueID is the stable id of an (advisory, package) finding: a SHA-256 of
// both, 64 hex characters whatever the PURL's length (DefectDojo allows 500).
// The file is left out, so moving a manifest keeps the id. Changing this
// formula changes every id, and a reimport then closes and recreates all the
// findings.
func ddUniqueID(advisoryID, purl string) string {
	sum := sha256.Sum256([]byte(advisoryID + "\x00" + purl))
	return hex.EncodeToString(sum[:])
}

// ddSeverity maps a canonical severity to DefectDojo's (Critical, High,
// Medium, Low, Info).
func ddSeverity(severity string) string {
	switch audit.NormalizeSeverity(severity) {
	case "critical":
		return "Critical"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	default:
		return "Info"
	}
}

// ddDescription is the advisory title, then its summary and description.
func ddDescription(adv audit.AdvisoryResult) string {
	parts := []string{"**" + adv.Title + "**"}
	if d := buildFullDescription(adv); d != "" {
		parts = append(parts, d)
	}
	return strings.Join(parts, "\n\n")
}

// ddReferences lists the ZEN SecDB permalink, the advisory URL and its
// references, without repeats.
func ddReferences(adv audit.AdvisoryResult, webURL string) []string {
	var out []string
	for _, u := range append([]string{weblink.Advisory(webURL, adv.ID), adv.URL}, adv.References...) {
		if u != "" && !slices.Contains(out, u) {
			out = append(out, u)
		}
	}
	return out
}
