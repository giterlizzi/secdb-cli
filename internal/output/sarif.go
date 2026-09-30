// SPDX-License-Identifier: Apache-2.0

package output

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/giterlizzi/secdb-cli/internal/audit"
	"github.com/giterlizzi/secdb-cli/internal/meta"

	"github.com/owenrumney/go-sarif/v3/pkg/report"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
)

// WriteSARIF writes the advisories as a SARIF 2.1.0 report, attributing each
// finding to its source file/line when known via sources.
func WriteSARIF(w io.Writer, advisories []audit.AdvisoryResult, sourceFile string, sources map[string]SourceLocation) error {
	sarifReport := report.NewV210Report()

	run := sarif.NewRunWithInformationURI("secdb-cli", "https://github.com/giterlizzi/secdb-cli")
	run.Tool.Driver.WithVersion(meta.Version)
	run.AutomationDetails = sarif.NewRunAutomationDetails().WithID("secdb-cli/audit-purl")

	for _, adv := range advisories {
		for _, purl := range adv.PURLs {
			file, line := sourceFile, 0
			if loc, ok := sources[purl]; ok {
				file, line = loc.File, loc.Line
			}
			addFinding(run, adv, purl, file, line)
		}
	}

	sarifReport.AddRun(run)
	return sarifReport.PrettyWrite(w)
}

// addFinding adds the rule and the result of one (advisory, package) pair to
// run, located at file (and line, when known) and suppressed when an ignore
// rule accepts the advisory for that package.
func addFinding(run *sarif.Run, adv audit.AdvisoryResult, purl, file string, line int) {
	ruleID := fmt.Sprintf("%s-%s", adv.ID, purl)
	resultTitle := fmt.Sprintf("A %s vulnerability in %s was found: %s", adv.Severity, purl, adv.Title)

	fullDescription := buildFullDescription(adv)
	shortDescription := fmt.Sprintf("[%s] %s vulnerability for %s package", adv.ID, adv.Severity, purl)

	rule := run.AddRule(ruleID)
	rule.WithName(ruleID)
	rule.WithDescription(shortDescription)
	rule.WithHelpURI(adv.URL)

	if fullDescription != "" {
		rule.WithFullDescription(sarif.NewMultiformatMessageString().
			WithText(fullDescription))
	}

	rule.Properties = sarif.NewPropertyBag().
		Add("security-severity", severityToScore(adv)).
		Add("purls", []string{purl}).
		Add("tags", buildTags(adv))

	phys := sarif.NewPhysicalLocation().
		WithArtifactLocation(sarif.NewSimpleArtifactLocation(file))
	if line > 0 {
		phys.WithRegion(sarif.NewRegion().WithStartLine(line))
	}

	result := run.CreateResultForRule(ruleID)
	result.WithLevel(severityToSARIFLevel(adv)).
		WithMessage(sarif.NewTextMessage(resultTitle)).
		WithLocations([]*sarif.Location{
			sarif.NewLocationWithPhysicalLocation(phys),
		})

	result.WithPartialFingerprints(map[string]string{
		"primaryLocationLineHash": buildFingerprint(file, adv.ID, purl),
	})

	if ignored, reason := adv.IgnoredFor(purl); ignored {
		result.AddSuppression(buildSuppression(reason))
	}
}

func buildSuppression(justification string) *sarif.Suppression {
	if justification == "" {
		justification = "Ignored via .secdbignore"
	}

	return sarif.NewSuppression().
		WithKind("external").
		WithStatus("accepted").
		WithJustification(justification)
}

func buildFingerprint(sourceFile string, advisoryID string, pkg string) string {
	fingerprint := fmt.Sprintf("%s:%s:%s", sourceFile, advisoryID, pkg)
	hash := sha256.Sum256([]byte(fingerprint))
	return hex.EncodeToString(hash[:])
}

func buildTags(advisory audit.AdvisoryResult) []string {
	tags := []string{"security", "vulnerability"}
	for _, cwe := range advisory.CWEs {
		tags = append(tags, "external/cwe/"+strings.ToLower(cwe))
	}
	tags = append(tags, advisory.CVEs...)
	return tags
}

func buildFullDescription(advisory audit.AdvisoryResult) string {
	summary := advisory.Summary
	description := advisory.Description

	switch {
	case summary != "" && description != "":
		return summary + "\n\n" + description
	case description != "":
		return description
	default:
		return summary
	}
}

func severityToSARIFLevel(advisory audit.AdvisoryResult) string {
	switch audit.NormalizeSeverity(advisory.Severity) {
	case "critical", "high":
		return sarif.LevelError
	case "medium":
		return sarif.LevelWarning
	default:
		return sarif.LevelNote
	}
}

func severityToScore(advisory audit.AdvisoryResult) string {
	if advisory.CVSSScore > 0 {
		return fmt.Sprintf("%.1f", advisory.CVSSScore)
	}

	switch audit.NormalizeSeverity(advisory.Severity) {
	case "critical":
		return "9.5"
	case "high":
		return "7.5"
	case "medium":
		return "5.0"
	case "low":
		return "2.0"
	default:
		return "0.0"
	}
}
