// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/MakeNowJust/heredoc/v2"
	"github.com/spf13/cobra"
)

var ssvcCmd = &cobra.Command{
	Use:   "ssvc",
	Short: "SSVC (Stakeholder-Specific Vulnerability Categorization) tools",
	Long: heredoc.Doc(`
		Stakeholder-Specific Vulnerability Categorization (SSVC), per the CISA
		methodology, combines a vulnerability's exploitation status and technical
		impact with stakeholder-supplied context (mission prevalence, public
		well-being impact) to produce an actionable decision: track, track*,
		attend, or act.

		See the subcommands below for the supported SSVC operations.
	`),
}

func init() {
	rootCmd.AddCommand(ssvcCmd)
}
