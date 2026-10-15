// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"strconv"

	"github.com/giterlizzi/secdb-cli/internal/audit"
	"github.com/giterlizzi/secdb-cli/internal/report"
	"github.com/giterlizzi/secdb-cli/internal/util"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/spf13/cobra"
)

// purlOptions are the flags of "audit purl".
type purlOptions struct {
	file  string
	sbom  string
	audit auditOptions
}

var purlOpts purlOptions

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

		CI:
			secdb audit purl --file=purls.txt --fail-on=high

		Notify a webhook on high-severity findings:
			SECDB_WEBHOOK_URL=https://... secdb audit purl --file=purls.txt --notify --notify-on=high

		SARIF (e.g. for GitHub Code Scanning):
			secdb audit purl --file=purls.txt --output=sarif > results.sarif

		For a CycloneDX SBOM, use "secdb audit sbom --file bom.json".
	`),
	Short: "Audit PURLs against ZEN SecDB",
	Long: heredoc.Doc(`
		Package URLs (PURLs) are a standardized way to identify software packages.
		This command allows you to audit one or more PURLs against the ZEN SecDB to
		check for known vulnerabilities and security issues.

		You can provide PURLs directly as command-line arguments, read them from a
		file using the --file flag, or pipe them in via standard input. To audit a
		CycloneDX BOM (JSON), use "secdb audit sbom" (the --sbom flag of this
		command is deprecated).

		If more than one input method is provided, only one is used, in this order
		of precedence: arguments, --file, standard input.

		Use --output=sarif to produce a SARIF 2.1.0 report suitable for GitHub Code
		Scanning or other SARIF consumers. A plain PURL list has no source file, so
		the artifact location in the report is left empty; "secdb audit sbom" and
		"secdb audit manifest" set it to the audited file. Findings matched
		by --ignore-file are still included in the report, but as a suppressed
		result (kind: external, status: accepted) so SARIF consumers like GitHub
		Code Scanning don't open a new alert for them.
	`),
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		purls, source, err := purlOpts.readPURLs(args)
		if err != nil {
			return err
		}

		return runPURLAudit(purls, &purlOpts.audit, auditTarget{
			source:    source,
			sarifFile: purlOpts.sbom,
			meta: []report.MetaItem{
				{Label: "Source", Value: source},
				{Label: "PURLs scanned", Value: strconv.Itoa(len(purls))},
			},
		})
	},
}

func init() {
	auditCmd.AddCommand(purlAuditCmd)
	purlOpts.addFlags(purlAuditCmd)
}

func (o *purlOptions) addFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&o.file, "file", "f", "",
		"Read PURL from file (one PURL per line) instead of arguments/stdin")
	cmd.Flags().StringVarP(&o.sbom, "sbom", "", "",
		"Read PURLs from CycloneDX SBOM file (JSON) instead of arguments/stdin/file")
	// Superseded by "audit sbom --file"; still accepted, hidden from the help.
	_ = cmd.Flags().MarkDeprecated("sbom", "use 'secdb audit sbom --file' instead")

	o.audit.addFlags(cmd)
}

// readPURLs returns the PURLs to audit, valid and de-duplicated, from the one
// input in use (--sbom, the arguments, --file or stdin, in this order of
// precedence), and that input's description for the report header.
func (o *purlOptions) readPURLs(args []string) (purls []string, source string, err error) {
	switch {
	case o.sbom != "":
		purls, err = audit.ReadPURLsFromSBOM(o.sbom)
		source = "SBOM (" + o.sbom + ")"
	case len(args) > 0:
		purls, source = args, "arguments"
	case o.file != "":
		purls, err = util.ReadIdentifiers(nil, o.file)
		source = "file (" + o.file + ")"
	default:
		purls, err = util.ReadIdentifiers(nil, "")
		source = "stdin"
	}
	if err != nil {
		return nil, "", err
	}

	purls = audit.NormalizePURLs(purls)
	if len(purls) == 0 {
		return nil, "", errors.New("no PURLs provided: pass them as arguments, with --file, or via stdin")
	}
	return purls, source, nil
}
