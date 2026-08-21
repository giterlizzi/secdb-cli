// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/giterlizzi/secdb-cli/internal/audit"
	"github.com/giterlizzi/secdb-cli/internal/output"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/spf13/cobra"
)

var purlFile string
var sbomFile string
var auditView string
var failOnSeverity string

var purlAuditCmd = &cobra.Command{
	Use: "purl <purl1> <purl2> ...",
	Example: heredoc.Doc(`
		secdb audit purl pkg:maven/org.apache.logging.log4j/log4j-core@2.17.0
		secdb audit purl --file=purls.txt
		secdb audit purl < purls.txt
		command | secdb audit purl
		secdb audit purl --file=purls.txt --fail-on=high
		cdxgen -o bom.json . && secdb audit purl --sbom bom.json
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
	`),
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {

		var purls []string
		var err error

		switch {
		case sbomFile != "":
			purls, err = audit.ReadPURLsFromSBOM(sbomFile)
		case len(args) > 0:
			purls = args
		case purlFile != "":
			purls, err = audit.ReadPURLsFromFile(purlFile)
		default:
			purls, err = audit.ReadPURLs(os.Stdin)
		}
		if err != nil {
			return err
		}

		if len(purls) == 0 {
			return fmt.Errorf("no PURLs provided: pass them as arguments, with --sbom, with --file, or via stdin")
		}

		purls = audit.DeduplicatePURLs(purls)

		client := newSecDbClient()
		data, err := client.PURLAudit(purls)
		if err != nil {
			return err
		}

		if outputFormat == "text" {
			switch auditView {
			case "summary":
				if err := output.RenderText(os.Stdout, audit.SummarizePURLAudit(data), "audit-purl-summary"); err != nil {
					return fmt.Errorf("failed to render summary: %w", err)
				}
			case "details":
				if err := output.RenderText(os.Stdout, audit.GroupByAdvisory(data), "audit-purl-details"); err != nil {
					return fmt.Errorf("failed to render details: %w", err)
				}
			default:
				return fmt.Errorf("invalid --view option: %q (valid options: summary, details)", auditView)
			}
		} else {
			if err := output.Render(os.Stdout, data, output.Format(outputFormat), newOutputOptions()); err != nil {
				return fmt.Errorf("failed to render output: %w", err)
			}
		}

		if failOnSeverity != "" {
			threshold := strings.ToLower(failOnSeverity)
			if _, ok := audit.SeverityLevels[threshold]; !ok {
				return fmt.Errorf("invalid --fail-on severity: %q (valid options: critical, high, medium, low, info)", failOnSeverity)
			}

			if maxSeverity := audit.OverallSeverity(data); maxSeverity != "" {
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
	purlAuditCmd.Flags().StringVarP(&purlFile, "file", "f", "", "Read PURL from file (one PURL per line) instead of arguments/stdin")
	purlAuditCmd.Flags().StringVarP(&sbomFile, "sbom", "", "", "Read PURLs from CycloneDX SBOM file (JSON) instead of arguments/stdin/file")
	purlAuditCmd.Flags().StringVarP(&auditView, "view", "v", "summary", "View mode for audit results (summary, details)")
	purlAuditCmd.Flags().StringVarP(&failOnSeverity, "fail-on", "", "", "Fail the audit if any package has a vulnerability with the specified severity (critical, high, medium, low, info)")
}
