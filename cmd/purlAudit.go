// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/giterlizzi/secdb-cli/internal/audit"
	"github.com/giterlizzi/secdb-cli/internal/output"
	"github.com/giterlizzi/secdb-cli/internal/report"
	"github.com/giterlizzi/secdb-cli/internal/util"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/spf13/cobra"
)

var (
	purlFile       string
	sbomFile       string
	auditView      string
	failOnSeverity string
	ignoreFilePath string
	showUnfixed    bool
)

var purlAuditCmd = &cobra.Command{
	Use: "purl <PURL...>",
	Example: heredoc.Doc(`
		Simple:
		  	secdb audit purl pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1

		From file:
		  	secdb audit purl --file=purls.txt

		From STDIN:
		  	secdb audit purl < purls.txt

		From pipe:
		  	command | secdb audit purl

		Using CycloneDX SBOM file (JSON):
		  	syft packages dir:. -o cyclonedx-json > bom.json && secdb audit purl --sbom bom.json
		  	cdxgen -o bom.json . && secdb audit purl --sbom bom.json

		CI:
		  	secdb audit purl --sbom bom.json --fail-on=high

		SARIF (e.g. for GitHub Code Scanning):
		  	secdb audit purl --sbom bom.json --output=sarif > results.sarif
	`),
	Short: "Audit PURLs against ZEN SecDB",
	Long: heredoc.Doc(`
		Package URLs (PURLs) are a standardized way to identify software packages.
		This command allows you to audit one or more PURLs against the ZEN SecDB to
		check for known vulnerabilities and security issues.

		You can provide PURLs directly as command-line arguments, read them from a
		file using the --file flag, extract them from a CycloneDX BOM (JSON) using
		the --sbom flag, or pipe them in via standard input.

		If more than one input method is provided, only one is used, in this order
		of precedence: --sbom, arguments, --file, standard input.

		Use --output=sarif to produce a SARIF 2.1.0 report suitable for GitHub Code
		Scanning or other SARIF consumers. The artifact location in the report is
		taken from --sbom, so pair --output=sarif with --sbom for a meaningful
		report; without --sbom the artifact location is left empty. Findings matched
		by --ignore-file are still included in the report, but as a suppressed
		result (kind: external, status: accepted) so SARIF consumers like GitHub
		Code Scanning don't open a new alert for them.
	`),
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {

		var purls []string
		var source string
		var err error

		switch {
		case sbomFile != "":
			purls, err = audit.ReadPURLsFromSBOM(sbomFile)
			source = "SBOM (" + sbomFile + ")"
		default:
			purls, err = util.ReadIdentifiers(args, purlFile)
			switch {
			case len(args) > 0:
				source = "arguments"
			case purlFile != "":
				source = "file (" + purlFile + ")"
			default:
				source = "stdin"
			}
		}
		if err != nil {
			return err
		}

		purls = audit.ValidatePURLs(util.Deduplicate(purls))

		if len(purls) == 0 {
			return fmt.Errorf("no PURLs provided: pass them as arguments, with --sbom, with --file, or via stdin")
		}

		ignoreFile, err := audit.LoadIgnoreFile(ignoreFilePath)
		if err != nil {
			return err
		}

		client := newSecDbClient()
		data, err := client.PURLAudit(purls)
		if err != nil {
			return err
		}

		switch outputFormat {
		case "text":
			meta := []report.MetaItem{
				{Label: "Source", Value: source},
				{Label: "PURLs scanned", Value: strconv.Itoa(len(purls))},
			}

			if !showUnfixed {
				if n := audit.UnfixedCount(data); n > 0 {
					meta = append(meta, report.MetaItem{
						Label: "Unfixed",
						Value: fmt.Sprintf("⚠️ %d hidden (run with --show-unfixed to list them)", n),
					})
				}
			}

			switch auditView {
			case "summary":
				r := report.Report{Results: audit.SummarizePURLAudit(data, showUnfixed)}
				r.PrependMeta(meta...)
				if err := output.RenderText(os.Stdout, r, "audit-purl-summary"); err != nil {
					return fmt.Errorf("failed to render summary: %w", err)
				}
			case "details":
				r := audit.GroupByAdvisory(data, ignoreFile, showUnfixed)
				r.BaseURL = client.BaseURL()
				r.PrependMeta(meta...)
				if err := output.RenderText(os.Stdout, r, "audit-purl-details"); err != nil {
					return fmt.Errorf("failed to render details: %w", err)
				}
			default:
				return fmt.Errorf("invalid --view option: %q (valid options: summary, details)", auditView)
			}
		case "sarif":
			r := audit.GroupByAdvisory(data, ignoreFile, showUnfixed)
			return output.WriteSARIF(os.Stdout, r.Results.([]audit.AdvisoryResult), sbomFile)
		case "csv":
			r := audit.GroupByAdvisory(data, ignoreFile, showUnfixed)
			return output.WriteCSV(os.Stdout, r, "audit-details-csv")
		default:
			if err := output.Render(os.Stdout, data, output.Format(outputFormat), newOutputOptions()); err != nil {
				return fmt.Errorf("failed to render output: %w", err)
			}
		}

		if failOnSeverity != "" {
			threshold := strings.ToLower(failOnSeverity)
			if _, ok := audit.SeverityLevels[threshold]; !ok {
				return fmt.Errorf("invalid --fail-on severity: %q (valid options: critical, high, medium, low, info)", failOnSeverity)
			}

			if maxSeverity := audit.OverallSeverity(data, ignoreFile, showUnfixed); maxSeverity != "" {
				if audit.SeverityLevels[maxSeverity] >= audit.SeverityLevels[threshold] {
					fmt.Fprintf(os.Stderr, "audit failed: package has a vulnerability with severity %q (fail-on=%q)\n", maxSeverity, failOnSeverity)
					os.Exit(2)
				}
			}
		}

		return nil

	},
}

func init() {
	auditCmd.AddCommand(purlAuditCmd)

	purlAuditCmd.Flags().StringVarP(&purlFile, "file", "f", "",
		"Read PURL from file (one PURL per line) instead of arguments/stdin")
	purlAuditCmd.Flags().StringVarP(&sbomFile, "sbom", "", "",
		"Read PURLs from CycloneDX SBOM file (JSON) instead of arguments/stdin/file")
	purlAuditCmd.Flags().StringVarP(&auditView, "view", "v", "summary",
		"View mode for audit results (summary, details)")
	purlAuditCmd.Flags().StringVarP(&failOnSeverity, "fail-on", "", "",
		"Fail the audit if any package has a vulnerability with the specified severity (critical, high, medium, low, info)")
	purlAuditCmd.Flags().StringVar(&ignoreFilePath, "ignore-file", ".secdbignore",
		"YAML file of ignore rules for --fail-on (doesn't hide findings from the report, only from the exit code)")
	purlAuditCmd.Flags().BoolVar(&showUnfixed, "show-unfixed", false,
		"Also report vulnerabilities that have no fix available (hidden by default)")
}
