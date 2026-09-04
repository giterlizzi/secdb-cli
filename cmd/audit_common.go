// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/giterlizzi/secdb-cli/internal/audit"
	"github.com/giterlizzi/secdb-cli/internal/client"
	"github.com/giterlizzi/secdb-cli/internal/inventory"
	"github.com/giterlizzi/secdb-cli/internal/output"
	"github.com/giterlizzi/secdb-cli/internal/report"
	"github.com/giterlizzi/secdb-cli/internal/util"

	"github.com/spf13/cobra"
)

type auditOptions struct {
	view        string
	failOn      string
	ignoreFile  string
	showUnfixed bool
}

type auditRenderConfig struct {
	data        []client.AuditItem
	opts        *auditOptions
	ignoreFile  *audit.IgnoreFile
	baseURL     string
	meta        []report.MetaItem
	template    string
	sarifSource string
}

// addFlags register the shared flags
func (o *auditOptions) addFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&o.view, "view", "v", "summary",
		"View mode for audit results (summary, details)")
	cmd.Flags().StringVar(&o.failOn, "fail-on", "",
		"Fail the audit if any package or dependency has a vulnerability with the specified severity (critical, high, medium, low, info)")
	cmd.Flags().StringVar(&o.ignoreFile, "ignore-file", ".secdbignore",
		"YAML file of ignore rules for --fail-on (doesn't hide findings from the report, only from the exit code)")
	cmd.Flags().BoolVar(&o.showUnfixed, "show-unfixed", false,
		"Also report vulnerabilities that have no fix available (hidden by default)")
}

// runPackageAudit collects the OS/package inventory of the target, audits it
// against ZEN SecDB, renders the result in the requested format, and applies
// --fail-on. It is the shared body of the audit linux and audit docker commands;
// they differ only in how they build the inventory.Target.
func runPackageAudit(target inventory.Target, opts *auditOptions) error {
	info, err := inventory.Collect(target)
	if err != nil {
		return err
	}

	ignoreFile, err := audit.LoadIgnoreFile(opts.ignoreFile)
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

	return renderAudit(auditRenderConfig{
		data:       data,
		opts:       opts,
		ignoreFile: ignoreFile,
		baseURL:    client.BaseURL(),
		meta: []report.MetaItem{
			{Label: "Target", Value: target.Describe()},
			{Label: "OS", Value: fmt.Sprintf("%s %s", info.OS, info.Version)},
			{Label: "Arch", Value: info.Arch},
			{Label: "Packages scanned", Value: strconv.Itoa(len(info.Packages))},
		},
		template:    "audit-linux",
		sarifSource: fmt.Sprintf("%s/%s", info.OS, info.Version),
	})
}

func renderAudit(cfg auditRenderConfig) error {
	meta := cfg.meta

	// display a warning in "text" output
	if !cfg.opts.showUnfixed {
		if n := audit.UnfixedCount(cfg.data); n > 0 {
			meta = append(meta, report.MetaItem{
				Label: "Unfixed",
				Value: fmt.Sprintf("⚠️ %d hidden (run with --show-unfixed to list them)", n),
			})
		}
	}

	switch outputFormat {
	case "text":
		switch cfg.opts.view {
		case "summary":
			r := report.Report{Results: audit.SummarizePURLAudit(cfg.data, cfg.opts.showUnfixed)}
			r.PrependMeta(meta...)
			if err := output.RenderText(os.Stdout, r, cfg.template+"-summary"); err != nil {
				return fmt.Errorf("failed to render summary: %w", err)
			}
		case "details":
			r := audit.GroupByAdvisory(cfg.data, cfg.ignoreFile, cfg.opts.showUnfixed)
			r.BaseURL = cfg.baseURL
			r.PrependMeta(meta...)
			if err := output.RenderText(os.Stdout, r, cfg.template+"-details"); err != nil {
				return fmt.Errorf("failed to render details: %w", err)
			}
		default:
			return fmt.Errorf("invalid --view option: %q (valid options: summary, details)", cfg.opts.view)
		}
	case "sarif":
		r := audit.GroupByAdvisory(cfg.data, cfg.ignoreFile, cfg.opts.showUnfixed)
		return output.WriteSARIF(os.Stdout, r.Results.([]audit.AdvisoryResult), cfg.sarifSource)
	case "csv":
		r := audit.GroupByAdvisory(cfg.data, cfg.ignoreFile, cfg.opts.showUnfixed)
		return output.WriteCSV(os.Stdout, r, "audit-details-csv")
	default:
		if err := output.Render(os.Stdout, cfg.data, output.Format(outputFormat), newOutputOptions()); err != nil {
			return fmt.Errorf("failed to render output: %w", err)
		}
	}

	if cfg.opts.failOn != "" {
		threshold := strings.ToLower(cfg.opts.failOn)
		if _, ok := audit.SeverityLevels[threshold]; !ok {
			return fmt.Errorf("invalid --fail-on severity: %q (valid options: critical, high, medium, low, info)", cfg.opts.failOn)
		}

		if maxSeverity := audit.OverallSeverity(cfg.data, cfg.ignoreFile, cfg.opts.showUnfixed); maxSeverity != "" {
			if audit.SeverityLevels[maxSeverity] >= audit.SeverityLevels[threshold] {
				fmt.Fprintf(os.Stderr, "audit failed: a package has a vulnerability with severity %q (fail-on=%q)\n", maxSeverity, cfg.opts.failOn)
				os.Exit(2)
			}
		}
	}

	return nil
}
