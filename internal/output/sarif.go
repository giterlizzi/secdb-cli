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

func WriteSARIF(w io.Writer, advisories []audit.AdvisoryResult, sourceFile string) error {
	sarifReport := report.NewV210Report()

	run := sarif.NewRunWithInformationURI("secdb-cli", "https://github.com/giterlizzi/secdb-cli")
	run.Tool.Driver.WithVersion(meta.Version)
	run.AutomationDetails = sarif.NewRunAutomationDetails().WithID("secdb-cli/audit-purl")

	for _, adv := range advisories {
		for _, pkg := range adv.Packages {
			ruleId := fmt.Sprintf("%s-%s", adv.ID, pkg)
			resultTitle := fmt.Sprintf("A %s vulnerability in %s was found: %s", adv.Severity, pkg, adv.Title)

			fullDescription := buildFullDescription(adv)
			shortDescription := fmt.Sprintf("[%s] %s vulnerability for %s package", adv.ID, adv.Severity, pkg)

			rule := run.AddRule(ruleId)
			rule.WithName(ruleId)
			rule.WithDescription(shortDescription)
			rule.WithHelpURI(adv.URL)

			if fullDescription != "" {
				rule.WithFullDescription(sarif.NewMultiformatMessageString().WithText(fullDescription))
			}

			rule.Properties = sarif.NewPropertyBag().
				Add("security-severity", severityToScore(adv)).
				Add("purls", []string{pkg}).
				Add("tags", buildTags(adv))

			result := run.CreateResultForRule(ruleId)
			result.WithLevel(severityToSARIFLevel(adv)).
				WithMessage(sarif.NewTextMessage(resultTitle)).
				WithLocations([]*sarif.Location{
					sarif.NewLocationWithPhysicalLocation(
						sarif.NewPhysicalLocation().
							WithArtifactLocation(sarif.NewSimpleArtifactLocation(sourceFile)),
					),
				})

			result.WithPartialFingerprints(map[string]string{
				"primaryLocationLineHash": buildFingerprint(sourceFile, adv.ID, pkg),
			})

			if adv.Ignored {
				result.AddSuppression(buildSuppression(adv))
			}

		}

	}

	sarifReport.AddRun(run)
	return sarifReport.PrettyWrite(w)
}

func buildSuppression(advisory audit.AdvisoryResult) *sarif.Suppression {
	justification := advisory.IgnoreReason
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
	for _, cve := range advisory.CVEs {
		tags = append(tags, cve)
	}
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
	switch advisory.Severity {
	case "critical", "high":
		return sarif.LevelError
	case "medium", "moderate":
		return sarif.LevelWarning
	default:
		return sarif.LevelNote
	}
}

func severityToScore(advisory audit.AdvisoryResult) string {
	if advisory.CVSSScore > 0 {
		return fmt.Sprintf("%.1f", advisory.CVSSScore)
	}

	switch advisory.Severity {
	case "critical":
		return "9.5"
	case "high":
		return "7.5"
	case "medium", "moderate":
		return "5.0"
	case "low":
		return "2.0"
	default:
		return "0.0"
	}
}
