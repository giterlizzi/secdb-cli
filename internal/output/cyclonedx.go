// SPDX-License-Identifier: Apache-2.0

package output

import (
	"io"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/giterlizzi/secdb-cli/internal/audit"
	"github.com/giterlizzi/secdb-cli/internal/meta"
	"github.com/giterlizzi/secdb-cli/internal/weblink"

	cdx "github.com/CycloneDX/cyclonedx-go"
	packageurl "github.com/package-url/packageurl-go"
)

// CycloneDXOptions describes a CycloneDX report.
type CycloneDXOptions struct {
	// WebURL is the web-GUI base of the advisory permalinks.
	WebURL string
}

// WriteCycloneDX writes the advisories as a CycloneDX 1.6 vulnerability
// disclosure report (VDR): the affected packages as components, and one
// vulnerability per advisory, affecting its packages. The analysis belongs to
// the whole vulnerability, so an advisory whose packages differ in it (an
// ignore rule scoped to one package, a fix missing for one) is split into one
// vulnerability per analysis. An ignore rule becomes state exploitable with
// response will_not_fix and the rule's reason as detail (CycloneDX has no
// "risk accepted"; not_affected would claim something else), an advisory with
// no fix the response can_not_fix; any other is in_triage.
func WriteCycloneDX(w io.Writer, advisories []audit.AdvisoryResult, opts CycloneDXOptions) error {
	bom := cdx.NewBOM()
	bom.Metadata = &cdx.Metadata{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Tools: &cdx.ToolsChoice{Components: &[]cdx.Component{{
			Type:    cdx.ComponentTypeApplication,
			Name:    "secdb-cli",
			Version: meta.Version,
		}}},
	}

	components := []cdx.Component{}
	vulns := []cdx.Vulnerability{}
	seen := map[string]bool{}
	for _, adv := range advisories {
		for _, purl := range adv.PURLs {
			if !seen[purl] {
				seen[purl] = true
				components = append(components, cdxComponent(purl))
			}
		}
		for _, g := range groupByAnalysis(adv) {
			vulns = append(vulns, cdxVulnerability(adv, g.purls, g.analysis, opts.WebURL))
		}
	}
	bom.Components = &components
	bom.Vulnerabilities = &vulns

	enc := cdx.NewBOMEncoder(w, cdx.BOMFileFormatJSON)
	enc.SetPretty(true)
	return enc.EncodeVersion(bom, cdx.SpecVersion1_6)
}

// cdxComponent is the library component of an audited PURL, referenced by it.
func cdxComponent(purl string) cdx.Component {
	c := cdx.Component{BOMRef: purl, Type: cdx.ComponentTypeLibrary, Name: purl, PackageURL: purl}
	if p, err := packageurl.FromString(purl); err == nil {
		c.Group, c.Name, c.Version = p.Namespace, p.Name, p.Version
	}
	return c
}

// analysisGroup is the packages of an advisory that share one analysis.
type analysisGroup struct {
	analysis *cdx.VulnerabilityAnalysis
	purls    []string
}

// groupByAnalysis groups the advisory's packages by their analysis, in the
// order the packages come: usually a single group.
func groupByAnalysis(adv audit.AdvisoryResult) []analysisGroup {
	var groups []analysisGroup
	for _, purl := range adv.PURLs {
		a := cdxAnalysis(adv, purl)
		i := slices.IndexFunc(groups, func(g analysisGroup) bool { return reflect.DeepEqual(g.analysis, a) })
		if i < 0 {
			groups = append(groups, analysisGroup{analysis: a})
			i = len(groups) - 1
		}
		groups[i].purls = append(groups[i].purls, purl)
	}
	return groups
}

// cdxVulnerability maps an advisory, affecting purls with one analysis.
func cdxVulnerability(adv audit.AdvisoryResult, purls []string, analysis *cdx.VulnerabilityAnalysis, webURL string) cdx.Vulnerability {
	affects := make([]cdx.Affects, 0, len(purls))
	for _, purl := range purls {
		affects = append(affects, cdx.Affects{Ref: purl})
	}
	v := cdx.Vulnerability{
		ID:             adv.ID,
		Source:         &cdx.Source{Name: "ZEN SecDB", URL: weblink.Advisory(webURL, adv.ID)},
		Description:    buildFullDescription(adv),
		Recommendation: adv.Solution,
		Affects:        &affects,
		Analysis:       analysis,
	}
	if !adv.Published.IsZero() {
		v.Published = adv.Published.UTC().Format(time.RFC3339)
	}

	ratings := []cdx.VulnerabilityRating{}
	for _, c := range adv.CVSS {
		score := c.Score
		ratings = append(ratings, cdx.VulnerabilityRating{
			Score:    &score,
			Severity: cvssSeverity(c.Score),
			Method:   cvssMethod(c.Version),
			Vector:   c.Vector,
		})
	}
	if len(ratings) == 0 && adv.Severity != "" {
		ratings = append(ratings, cdx.VulnerabilityRating{
			Severity: cdx.Severity(audit.NormalizeSeverity(adv.Severity)),
			Method:   cdx.ScoringMethodOther,
		})
	}
	if len(ratings) > 0 {
		v.Ratings = &ratings
	}

	var cwes []int
	for _, id := range adv.CWEs {
		if n, err := strconv.Atoi(strings.TrimPrefix(id, "CWE-")); err == nil && cweIDRe.MatchString(id) {
			cwes = append(cwes, n)
		}
	}
	if len(cwes) > 0 {
		v.CWEs = &cwes
	}

	var refs []cdx.VulnerabilityReference
	for _, cve := range adv.CVEs {
		refs = append(refs, cdx.VulnerabilityReference{
			ID:     cve,
			Source: &cdx.Source{Name: "NVD", URL: "https://nvd.nist.gov/vuln/detail/" + cve},
		})
	}
	if len(refs) > 0 {
		v.References = &refs
	}

	var advisories []cdx.Advisory
	for _, u := range append([]string{adv.URL}, adv.References...) {
		if u != "" {
			advisories = append(advisories, cdx.Advisory{URL: u})
		}
	}

	// CycloneDX has no KEV field: a property per CVE in the catalog, and the
	// catalog entry among the advisories for a reader.
	var props []cdx.Property
	for _, k := range adv.KEV {
		props = append(props, cdx.Property{Name: "secdb:cisa_kev", Value: k.CVE})
		advisories = append(advisories, cdx.Advisory{
			Title: "CISA KEV: " + k.CVE,
			URL:   "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=" + k.CVE,
		})
	}
	if len(props) > 0 {
		v.Properties = &props
	}
	if len(advisories) > 0 {
		v.Advisories = &advisories
	}
	return v
}

// cdxAnalysis is the VEX analysis of the pair: the ignore rule and the
// missing fix, else in_triage.
func cdxAnalysis(adv audit.AdvisoryResult, purl string) *cdx.VulnerabilityAnalysis {
	a := &cdx.VulnerabilityAnalysis{State: cdx.IASInTriage}
	var responses []cdx.ImpactAnalysisResponse
	if ignored, reason := adv.IgnoredFor(purl); ignored {
		a.State = cdx.IASExploitable
		a.Detail = strings.TrimSpace("Accepted in .secdbignore. " + reason)
		responses = append(responses, cdx.IARWillNotFix)
	}
	if adv.UnfixedFor(purl) {
		responses = append(responses, cdx.IARCanNotFix)
	}
	if len(responses) > 0 {
		a.Response = &responses
	}
	return a
}

// cvssMethod maps a CVSS version to its CycloneDX scoring method.
func cvssMethod(version float64) cdx.ScoringMethod {
	switch {
	case version >= 4:
		return cdx.ScoringMethodCVSSv4
	case version >= 3.1:
		return cdx.ScoringMethodCVSSv31
	case version >= 3:
		return cdx.ScoringMethodCVSSv3
	case version >= 2:
		return cdx.ScoringMethodCVSSv2
	default:
		return cdx.ScoringMethodOther
	}
}

// cvssSeverity is the CVSS qualitative rating of a base score.
func cvssSeverity(score float64) cdx.Severity {
	switch {
	case score >= 9:
		return cdx.SeverityCritical
	case score >= 7:
		return cdx.SeverityHigh
	case score >= 4:
		return cdx.SeverityMedium
	case score > 0:
		return cdx.SeverityLow
	default:
		return cdx.SeverityNone
	}
}
