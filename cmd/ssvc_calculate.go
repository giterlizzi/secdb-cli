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

var (
	cvesFile              string
	missionPrevalence     string
	publicWellBeingImpact string
)

var (
	validMissionPrevalence = map[string]bool{"minimal": true, "support": true, "essential": true}
	validPublicWellBeing   = map[string]bool{"minimal": true, "material": true, "irreversible": true}
)

var ssvcCalculateCmd = &cobra.Command{
	Use:   "calculate <CVE-ID...>",
	Short: "Calculate SSVC (CISA methodology) for one or more known CVEs (bulk)",
	Long: heredoc.Doc(`
		Calculates the SSVC decision (track, track*, attend, act) for one or more
		known CVE identifiers, combining exploitation status and technical impact
		(from ZEN SecDB) with the mission prevalence and public well-being impact
		you provide.

		You can provide CVE identifiers as command-line arguments, read them from
		a file using the --file flag, or pipe them in via standard input. If more
		than one input method is provided, only one is used, in this order of
		precedence: arguments, --file, standard input.
	`),
	Example: heredoc.Doc(`
		Single CVE:
			secdb ssvc calculate CVE-2021-44228 --mission-prevalence essential --public-well-being-impact material

		Multiple CVEs from input file:
			secdb ssvc calculate --file cves.txt --mission-prevalence support --public-well-being-impact minimal

		Multiple CVEs from CLI:
			secdb ssvc calculate CVE-2021-44228 CVE-2023-4863 --mission-prevalence support --public-well-being-impact minimal
	`),
	RunE: func(cmd *cobra.Command, args []string) error {
		if !validMissionPrevalence[missionPrevalence] {
			return fmt.Errorf("invalid --mission-prevalence: %q (valid options: minimal, support, essential)", missionPrevalence)
		}
		if !validPublicWellBeing[publicWellBeingImpact] {
			return fmt.Errorf("invalid --public-well-being-impact: %q (valid options: minimal, material, irreversible)", publicWellBeingImpact)
		}

		cveIDs, err := util.ReadIdentifiers(args, cvesFile)
		if err != nil {
			return err
		}
		if len(cveIDs) == 0 {
			return fmt.Errorf("no CVEs provided: pass them as arguments, with --file, or via stdin")
		}

		for i, id := range cveIDs {
			id = strings.ToUpper(id)
			if !cve.IsValidCVE(id) {
				return fmt.Errorf("invalid CVE identifier: %q (expected format: CVE-YYYY-NNNN)", cveIDs[i])
			}
			cveIDs[i] = id
		}
		cveIDs = util.Deduplicate(cveIDs)

		client := newSecDbClient()
		data, err := client.SSVCBulk(cveIDs, missionPrevalence, publicWellBeingImpact)
		if err != nil {
			return err
		}

		if outputFormat == "text" {
			return output.RenderText(os.Stdout, data, "ssvc-calculate")
		}
		return output.Render(os.Stdout, data, output.Format(outputFormat), newOutputOptions())
	},
}

func init() {
	ssvcCmd.AddCommand(ssvcCalculateCmd)

	ssvcCalculateCmd.Flags().StringVarP(&cvesFile, "file", "f", "",
		"Read CVEs from a file instead of arguments/stdin")
	ssvcCalculateCmd.Flags().StringVar(&missionPrevalence, "mission-prevalence", "",
		"Mission prevalence: minimal, support, or essential (required)")
	ssvcCalculateCmd.Flags().StringVar(&publicWellBeingImpact, "public-well-being-impact", "",
		"Public well-being impact: minimal, material, or irreversible (required)")

	ssvcCalculateCmd.MarkFlagRequired("mission-prevalence")
	ssvcCalculateCmd.MarkFlagRequired("public-well-being-impact")
}
