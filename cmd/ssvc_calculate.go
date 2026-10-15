// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/giterlizzi/secdb-cli/internal/cve"
	"github.com/giterlizzi/secdb-cli/internal/output"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/spf13/cobra"
)

// ssvcOptions are the flags of "ssvc calculate".
type ssvcOptions struct {
	file                  string
	missionPrevalence     string
	publicWellBeingImpact string
}

var ssvcOpts ssvcOptions

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

		The CVEs are read from the arguments, else from --file (one per line, "#"
		starts a comment), else from standard input. Duplicates are removed, and a
		CVE that isn't found is listed with its status instead of failing the
		whole run.
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
		cveIDs, err := ssvcOpts.request(args)
		if err != nil {
			return err
		}

		client := global.newClient()
		data, err := client.SSVCBulk(cveIDs, ssvcOpts.missionPrevalence, ssvcOpts.publicWellBeingImpact)
		if err != nil {
			return err
		}

		if global.output == "text" {
			return output.RenderText(os.Stdout, data, "ssvc-calculate")
		}
		return output.Render(os.Stdout, data, output.Format(global.output), global.outputOptions())
	},
}

func init() {
	ssvcCmd.AddCommand(ssvcCalculateCmd)
	ssvcOpts.addFlags(ssvcCalculateCmd)
}

func (o *ssvcOptions) addFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&o.file, "file", "f", "",
		"Read CVEs from a file instead of arguments/stdin")
	cmd.Flags().StringVar(&o.missionPrevalence, "mission-prevalence", "",
		"Mission prevalence: minimal, support, or essential (required)")
	cmd.Flags().StringVar(&o.publicWellBeingImpact, "public-well-being-impact", "",
		"Public well-being impact: minimal, material, or irreversible (required)")

	// Errors here only occur if the flag name is wrong (a programming bug), and
	// this runs in init(), so ignore them explicitly.
	_ = cmd.MarkFlagRequired("mission-prevalence")
	_ = cmd.MarkFlagRequired("public-well-being-impact")
}

// request validates the flags, then reads the CVEs to calculate (arguments,
// --file or stdin, in this order of precedence) and returns them uppercased,
// valid and de-duplicated, before any API call.
func (o *ssvcOptions) request(args []string) ([]string, error) {
	if !validMissionPrevalence[o.missionPrevalence] {
		return nil, fmt.Errorf("invalid --mission-prevalence: %q (valid options: minimal, support, essential)", o.missionPrevalence)
	}
	if !validPublicWellBeing[o.publicWellBeingImpact] {
		return nil, fmt.Errorf("invalid --public-well-being-impact: %q (valid options: minimal, material, irreversible)", o.publicWellBeingImpact)
	}

	ids, err := readIdentifiers(args, o.file)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, errors.New("no CVEs provided: pass them as arguments, with --file, or via stdin")
	}
	return cve.NormalizeIDs(ids)
}
