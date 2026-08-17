// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/giterlizzi/secdb-cli/internal/meta"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:     "version",
	Aliases: []string{"v"},
	Short:   "Show version information for ZEN SecDB CLI",
	Long: heredoc.Doc(`
			Prints the installed secdb version and the commit it was built from.
			Include this information when reporting a bug.
		`),
	Example: heredoc.Doc(`
			secdb version`),
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error { return nil },
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("secdb %s (commit %s (%s), built %s)\n",
			meta.Version, meta.CommitHash, meta.Branch, meta.BuildDate)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
