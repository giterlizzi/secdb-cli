// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/giterlizzi/secdb-cli/internal/audit"
	"github.com/giterlizzi/secdb-cli/internal/inventory"
	"github.com/giterlizzi/secdb-cli/internal/output"
	"github.com/giterlizzi/secdb-cli/internal/report"
	"github.com/giterlizzi/secdb-cli/internal/util"

	"github.com/spf13/cobra"
)

// addPackageAuditFlags registers the flags shared by the inventory-based audit
// subcommands (audit linux, audit docker): --view, --fail-on and --ignore-file.
func addPackageAuditFlags(cmd *cobra.Command, view, failOn, ignoreFile *string, showUnfixed *bool) {
	cmd.Flags().StringVarP(view, "view", "v", "summary",
		"View mode for audit results (summary, details)")
	cmd.Flags().StringVar(failOn, "fail-on", "",
		"Fail the audit if any package has a vulnerability with the specified severity (critical, high, medium, low, info)")
	cmd.Flags().StringVar(ignoreFile, "ignore-file", ".secdbignore",
		"YAML file of ignore rules for --fail-on (doesn't hide findings from the report, only from the exit code)")
	cmd.Flags().BoolVar(showUnfixed, "show-unfixed", false,
		"Also report vulnerabilities that have no fix available (hidden by default)")
}

// runPackageAudit collects the OS/package inventory of the target, audits it
// against ZEN SecDB, renders the result in the requested format, and applies
// --fail-on. It is the shared body of the audit linux and audit docker commands;
// they differ only in how they build the inventory.Target.
func runPackageAudit(target inventory.Target, view, failOn, ignoreFilePath string, showUnfixed bool) error {
	info, err := inventory.Collect(target)
	if err != nil {
		return err
	}

	ignoreFile, err := audit.LoadIgnoreFile(ignoreFilePath)
	if err != nil {
		return err
	}

	util.Statusf("Detected %s %s %s (%d packages)\n", info.OS, info.Version, info.Arch, len(info.Packages))
	util.Statusf("Auditing %d packages against ZEN SecDB...\n", len(info.Packages))

	client := newSecDbClient()
	data, err := client.LinuxAudit(info.OS, info.Version, info.Arch, info.Packages)
	if err != nil {
		return err
	}

	switch outputFormat {
	case "text":
		meta := []report.MetaItem{
			{Label: "Target", Value: target.Describe()},
			{Label: "OS", Value: strings.TrimSpace(info.OS + " " + info.Version)},
			{Label: "Arch", Value: info.Arch},
			{Label: "Packages scanned", Value: strconv.Itoa(len(info.Packages))},
		}

		if !showUnfixed {
			if n := audit.UnfixedCount(data); n > 0 {
				meta = append(meta, report.MetaItem{
					Label: "Unfixed",
					Value: fmt.Sprintf("⚠️ %d hidden (run with --show-unfixed to list them)", n),
				})
			}
		}

		switch view {
		case "summary":
			r := report.Report{Results: audit.SummarizePURLAudit(data, showUnfixed)}
			r.PrependMeta(meta...)
			if err := output.RenderText(os.Stdout, r, "audit-linux-summary"); err != nil {
				return fmt.Errorf("failed to render summary: %w", err)
			}
		case "details":
			r := audit.GroupByAdvisory(data, ignoreFile, showUnfixed)
			r.BaseURL = client.BaseURL()
			r.PrependMeta(meta...)
			if err := output.RenderText(os.Stdout, r, "audit-linux-details"); err != nil {
				return fmt.Errorf("failed to render details: %w", err)
			}
		default:
			return fmt.Errorf("invalid --view option: %q (valid options: summary, details)", view)
		}
	case "sarif":
		r := audit.GroupByAdvisory(data, ignoreFile, showUnfixed)
		return output.WriteSARIF(os.Stdout, r.Results.([]audit.AdvisoryResult), info.OS+"/"+info.Version)
	case "csv":
		r := audit.GroupByAdvisory(data, ignoreFile, showUnfixed)
		return output.WriteCSV(os.Stdout, r, "audit-details-csv")
	default:
		if err := output.Render(os.Stdout, data, output.Format(outputFormat), newOutputOptions()); err != nil {
			return fmt.Errorf("failed to render output: %w", err)
		}
	}

	if failOn != "" {
		threshold := strings.ToLower(failOn)
		if _, ok := audit.SeverityLevels[threshold]; !ok {
			return fmt.Errorf("invalid --fail-on severity: %q (valid options: critical, high, medium, low, info)", failOn)
		}

		if maxSeverity := audit.OverallSeverity(data, ignoreFile, showUnfixed); maxSeverity != "" {
			if audit.SeverityLevels[maxSeverity] >= audit.SeverityLevels[threshold] {
				fmt.Fprintf(os.Stderr, "audit failed: a package has a vulnerability with severity %q (fail-on=%q)\n", maxSeverity, failOn)
				os.Exit(2)
			}
		}
	}

	return nil
}
