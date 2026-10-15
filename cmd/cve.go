// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"os"
	"strings"

	"github.com/giterlizzi/secdb-cli/internal/cve"
	"github.com/giterlizzi/secdb-cli/internal/output"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/spf13/cobra"
)

var cveCmd = &cobra.Command{
	Use:     "cve <id>",
	GroupID: groupIntel,
	Short:   "Fetch CVE info from ZEN SecDB",
	Long: heredoc.Doc(`
		Prints the ZEN SecDB record of a CVE: CVSS v2/v3/v4, SSVC, EPSS, CISA KEV
		status, weaknesses, exploit maturity, the affected vendors and products,
		the advisories and the references, with links to the ZEN SecDB web GUI.
		--output json or yaml prints the whole record.
	`),
	Example: heredoc.Doc(`
		secdb cve CVE-2021-44228
	`),
	Args: exactArgs(1, "Specify a CVE identifier"),
	RunE: func(cmd *cobra.Command, args []string) error {

		cveID := strings.ToUpper(args[0])

		if !cve.IsValidID(cveID) {
			return errors.New("invalid CVE identifier")
		}

		client := global.newClient()
		data, err := client.GetCVE(cveID, "affected_products", "advisories", "references")
		if err != nil {
			return err
		}

		if global.output == "text" {
			data["secdb_url"] = client.WebURL()
			cve.SummarizeAffectedProducts(data)

			return output.RenderText(os.Stdout, data, "cve", output.TerminalWrap(100))
		}

		return output.Render(os.Stdout, data, output.Format(global.output), global.outputOptions())
	},
}

func init() {
	rootCmd.AddCommand(cveCmd)
}
