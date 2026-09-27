// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"

	"github.com/giterlizzi/secdb-cli/internal/meta"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:     "version",
	GroupID: groupOther,
	Short:   "Show version and build information",
	Long: heredoc.Doc(`
		Prints the installed secdb version and the commit it was built from.
		Include this information when reporting a bug.
	`),
	Example: heredoc.Doc(`
		secdb version
	`),
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
