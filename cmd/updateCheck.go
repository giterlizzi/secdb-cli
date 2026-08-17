// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"

	"github.com/giterlizzi/secdb-cli/internal/meta"
	"github.com/giterlizzi/secdb-cli/internal/update"
	"github.com/giterlizzi/secdb-cli/internal/util"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/spf13/cobra"
	"golang.org/x/mod/semver"
)

var updateCheckCmd = &cobra.Command{
	Use:     "check-update",
	Aliases: []string{"update"},
	Short:   "Check for the latest secdb-cli version.",
	Long: heredoc.Doc(`
		Compares the currently installed secdb-cli version against the latest
		release published on GitHub.

		The result is cached locally for 24 hours, so this command may report
		a cached result instead of hitting the network every time it runs.
	`),
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error { return nil },
	RunE: func(cmd *cobra.Command, args []string) error {

		if meta.Version == "v0.0.0" || !semver.IsValid(meta.Version) {
			fmt.Println("(!) Running a development build.")
			return nil
		}

		isAvailable, releaseInfo, err := update.UpdateIsAvailable(meta.Version)

		if err != nil {
			fmt.Printf("%s\n", err)
			return nil
		}

		if isAvailable {
			fmt.Printf("A new version is available: %s (current: %s)\n", releaseInfo.Version, meta.Version)
			fmt.Printf("Released: %s (%s)\n", releaseInfo.PublishedAt.Format("2006-01-02"), util.TimeAgo(releaseInfo.PublishedAt))
			fmt.Printf("Release notes: %s\n", releaseInfo.URL)
		} else {
			fmt.Printf("You're already on the latest version (%s).\n", meta.Version)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(updateCheckCmd)
}
