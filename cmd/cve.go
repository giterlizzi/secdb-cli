// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/giterlizzi/secdb-cli/internal/cve"
	"github.com/giterlizzi/secdb-cli/internal/output"
	"github.com/giterlizzi/secdb-cli/internal/util"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/spf13/cobra"
)

var cveCmd = &cobra.Command{
	Use:   "cve <id>",
	Short: "Fetch CVE info from ZEN SecDB",
	Long: heredoc.Doc(`
		This command allows you to fetch information about a specific CVE (Common 
		Vulnerabilities and Exposures) identifier from the ZEN SecDB.

		You can provide a CVE identifier as a command-line argument, and the command 
		will retrieve relevant information about that CVE, including affected products 
		and advisories.
	`),
	Example: heredoc.Doc(`
		secdb cve CVE-2021-44228
	`),
	Args: util.ExactArgs(1, "Specify a CVE identifier"),
	RunE: func(cmd *cobra.Command, args []string) error {

		cveID := strings.ToUpper(args[0])

		if !cve.IsValidCVE(cveID) {
			return fmt.Errorf("invalid CVE identifier")
		}

		client := newSecDbClient()
		data, err := client.GetCVE(cveID, "affected_products", "advisories")
		if err != nil {
			return err
		}

		cve.SummarizeAffectedProducts(data)

		if outputFormat == "text" {
			return output.RenderText(os.Stdout, data, "cve")
		}

		return output.Render(os.Stdout, data, output.Format(outputFormat), newOutputOptions())
	},
}

func init() {
	rootCmd.AddCommand(cveCmd)
}
