// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/giterlizzi/secdb-cli/internal/audit"
	"github.com/giterlizzi/secdb-cli/internal/report"
	"github.com/giterlizzi/secdb-cli/internal/util"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/spf13/cobra"
)

var (
	sbomAuditFile string
	sbomOpts      auditOptions
)

var sbomAuditCmd = &cobra.Command{
	Use: "sbom --file <FILE>",
	Example: heredoc.Doc(`
		From a CycloneDX SBOM (JSON):
			secdb audit sbom --file bom.json

		Generate then audit:
			syft packages dir:. -o cyclonedx-json > bom.json && secdb audit sbom --file bom.json
			cdxgen -o bom.json . && secdb audit sbom --file bom.json

		CI (fail on high or critical):
			secdb audit sbom --file bom.json --fail-on=high

		SARIF (e.g. for GitHub Code Scanning):
			secdb audit sbom --file bom.json --output=sarif > results.sarif
	`),
	Short: "Audit a CycloneDX SBOM against ZEN SecDB",
	Long: heredoc.Doc(`
		Extract the package URLs (PURLs) from a CycloneDX BOM (JSON) and audit
		them against the ZEN SecDB for known vulnerabilities.

		This is a convenience front-end for "audit purl --sbom": the PURLs are
		collected from the BOM's components (recursively), then shaped and
		rendered exactly like "audit purl" (--view, --fail-on, --ignore-file,
		--show-unfixed and --output=sarif/csv all behave the same way).
	`),
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if sbomAuditFile == "" {
			return errors.New("--file is required: pass the path to a CycloneDX SBOM (JSON)")
		}

		purls, err := audit.ReadPURLsFromSBOM(sbomAuditFile)
		if err != nil {
			return err
		}

		purls = audit.ValidatePURLs(util.Deduplicate(purls))
		if len(purls) == 0 {
			return fmt.Errorf("no PURLs found in %s", sbomAuditFile)
		}

		ignoreFile, err := audit.LoadIgnoreFile(sbomOpts.ignoreFile)
		if err != nil {
			return err
		}

		client := newSecDbClient()
		data, err := client.PURLAudit(purls)
		if err != nil {
			return err
		}

		return renderAudit(auditRenderConfig{
			data:       data,
			opts:       &sbomOpts,
			ignoreFile: ignoreFile,
			baseURL:    client.BaseURL(),
			template:   "audit-purl",
			source:     sbomAuditFile,
			meta: []report.MetaItem{
				{Label: "Source", Value: "SBOM (" + sbomAuditFile + ")"},
				{Label: "PURLs scanned", Value: strconv.Itoa(len(purls))},
			},
		})
	},
}

func init() {
	auditCmd.AddCommand(sbomAuditCmd)

	sbomAuditCmd.Flags().StringVarP(&sbomAuditFile, "file", "f", "",
		"Path to the CycloneDX SBOM (JSON) to audit")

	sbomOpts.addFlags(sbomAuditCmd)
}
