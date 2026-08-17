// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/MakeNowJust/heredoc/v2"
	"github.com/spf13/cobra"
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Audit software packages and dependencies",
	Long: heredoc.Doc(`
		Audit software packages and dependencies against the ZEN SecDB to
		identify known vulnerabilities and security issues.

		See the subcommands below for the supported audit targets (e.g. PURLs).
	`),
}

func init() {
	rootCmd.AddCommand(auditCmd)
}
