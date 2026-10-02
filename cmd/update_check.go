// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/giterlizzi/secdb-cli/internal/meta"
	"github.com/giterlizzi/secdb-cli/internal/output"
	"github.com/giterlizzi/secdb-cli/internal/update"
	"github.com/giterlizzi/secdb-cli/internal/util"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/spf13/cobra"
	"golang.org/x/mod/semver"
)

var updateCheckCmd = &cobra.Command{
	Use:     "check-update",
	GroupID: groupOther,
	Short:   "Check for a newer secdb release",
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

		isAvailable, releaseInfo, err := update.IsAvailable(meta.Version)

		if err != nil {
			fmt.Printf("%s\n", err)
			return nil
		}

		if isAvailable {
			releaseNotes, err := update.FetchReleaseNotes(releaseInfo.Version)
			if err != nil {
				slog.Debug("release notes unavailable", "err", err)
			}

			data := map[string]any{
				"Latest":   releaseInfo.Version,
				"Current":  meta.Version,
				"Released": fmt.Sprintf("%s (%s)", releaseInfo.PublishedAt.Format("2006-01-02"), util.TimeAgo(releaseInfo.PublishedAt)),
				"URL":      releaseInfo.URL,
				"Notes":    update.ReleaseNotesAfterVersion(releaseNotes, meta.Version),
			}

			return output.RenderText(os.Stdout, data, "check-update", output.TerminalWrap(100))

		}

		fmt.Printf("You're already on the latest version (%s).\n", meta.Version)

		return nil
	},
}

func init() {
	rootCmd.AddCommand(updateCheckCmd)
}
