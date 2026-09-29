// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"

	"github.com/giterlizzi/secdb-cli/internal/audit"
	"github.com/giterlizzi/secdb-cli/internal/ci"
	"github.com/giterlizzi/secdb-cli/internal/client"
	"github.com/giterlizzi/secdb-cli/internal/finding"
	"github.com/giterlizzi/secdb-cli/internal/inventory"
	"github.com/giterlizzi/secdb-cli/internal/notify"
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
	notify      bool
	providers   []string
	notifyOn    string
}

type auditRenderConfig struct {
	data       []client.AuditItem
	opts       *auditOptions
	ignoreFile *audit.IgnoreFile
	baseURL    string
	meta       []report.MetaItem
	template   string
	sources    map[string]output.SourceLocation
	source     string
}

// addFlags registers the shared audit flags on cmd, and validates them in its
// PreRunE, so a bad value fails before any inventory or API call.
func (o *auditOptions) addFlags(cmd *cobra.Command) {
	cmd.PreRunE = func(*cobra.Command, []string) error { return o.validate() }

	cmd.Flags().StringVarP(&o.view, "view", "v", "summary",
		"View mode for audit results (summary, details)")
	cmd.Flags().StringVar(&o.failOn, "fail-on", "",
		"Fail the audit if any package or dependency has a vulnerability with the specified severity (critical, high, medium, low, info)")
	cmd.Flags().StringVar(&o.ignoreFile, "ignore-file", ".secdbignore",
		"YAML file of ignore rules for --fail-on (doesn't hide findings from the report, only from the exit code)")
	cmd.Flags().BoolVar(&o.showUnfixed, "show-unfixed", false,
		"Also report vulnerabilities that have no fix available (hidden by default)")

	cmd.Flags().BoolVar(&o.notify, "notify", false,
		"Send the audit result to the configured notification providers")
	cmd.Flags().StringSliceVar(&o.providers, "providers", nil,
		"Notification providers to use (comma-separated); default: all configured")
	cmd.Flags().StringVar(&o.notifyOn, "notify-on", "high",
		"Notify only on a vulnerability at or above this severity (critical, high, medium, low, info)")
}

// validate checks the shared audit flags and normalizes the severities to
// lowercase, so renderAudit can trust them. The notification flags are only
// checked with --notify, as they are unused otherwise.
func (o *auditOptions) validate() error {
	if o.view != "summary" && o.view != "details" {
		return fmt.Errorf("invalid --view option: %q (valid options: summary, details)", o.view)
	}

	if o.failOn != "" {
		sev, err := parseSeverity("--fail-on", o.failOn)
		if err != nil {
			return err
		}
		o.failOn = sev
	}

	if o.notify {
		sev, err := parseSeverity("--notify-on", o.notifyOn)
		if err != nil {
			return err
		}
		o.notifyOn = sev

		if _, err := notify.Resolve(o.providers); err != nil {
			return err
		}
	}
	return nil
}

// parseSeverity normalizes a severity flag value (so an alias like "moderate"
// is accepted) and checks it is known.
func parseSeverity(flag, value string) (string, error) {
	sev := audit.NormalizeSeverity(value)
	if _, ok := audit.SeverityLevels[sev]; !ok || sev == "" {
		return "", fmt.Errorf("invalid %s severity: %q (valid options: critical, high, medium, low, info)", flag, value)
	}
	return sev, nil
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
		template:   "audit-linux",
		source:     fmt.Sprintf("%s/%s", info.OS, info.Version),
		meta: []report.MetaItem{
			{Label: "Target", Value: target.Describe()},
			{Label: "OS", Value: fmt.Sprintf("%s %s", info.OS, info.Version)},
			{Label: "Arch", Value: info.Arch},
			{Label: "Packages scanned", Value: strconv.Itoa(len(info.Packages))},
		},
	})
}

func renderAudit(cfg auditRenderConfig) error {
	meta := cfg.meta

	overall := audit.OverallSeverity(cfg.data, cfg.ignoreFile, cfg.opts.showUnfixed)

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
		// --view is validated up front (auditOptions.validate): summary or details.
		var r report.Report
		if cfg.opts.view == "details" {
			r = audit.GroupByAdvisory(cfg.data, cfg.ignoreFile, cfg.opts.showUnfixed)
		} else {
			r.Results = audit.SummarizePURLAudit(cfg.data, cfg.opts.showUnfixed)
		}

		r.BaseURL = cfg.baseURL
		r.PrependMeta(meta...)

		templateName := fmt.Sprintf("%s-%s", cfg.template, cfg.opts.view)

		if err := output.RenderText(os.Stdout, r, templateName); err != nil {
			return fmt.Errorf("failed to render details: %w", err)
		}
	case "sarif":
		r := audit.GroupByAdvisory(cfg.data, cfg.ignoreFile, cfg.opts.showUnfixed)
		if err := output.WriteSARIF(os.Stdout, r.Results.([]audit.AdvisoryResult), cfg.source, cfg.sources); err != nil {
			return err
		}
	case "csv":
		r := audit.GroupByAdvisory(cfg.data, cfg.ignoreFile, cfg.opts.showUnfixed)
		if err := output.WriteCSV(os.Stdout, r, "audit-details-csv"); err != nil {
			return err
		}
	default:
		if err := output.Render(os.Stdout, cfg.data, output.Format(outputFormat), newOutputOptions()); err != nil {
			return fmt.Errorf("failed to render output: %w", err)
		}
	}

	if cfg.opts.notify {
		if err := sendNotifications(cfg, overall); err != nil {
			return err
		}
	}

	// --fail-on is validated and lowercased up front (auditOptions.validate).
	if cfg.opts.failOn != "" && overall != "" {
		if audit.SeverityLevels[overall] >= audit.SeverityLevels[cfg.opts.failOn] {
			fmt.Fprintf(os.Stderr, "audit failed: a package has a vulnerability with severity %q (fail-on=%q)\n", overall, cfg.opts.failOn)
			os.Exit(2)
		}
	}

	return nil
}

func buildNotifyMessage(cfg auditRenderConfig, rep report.Report, overall string) notify.Message {
	var findings []finding.Finding
	advisories, _ := rep.Results.([]audit.AdvisoryResult)
	for _, adv := range advisories {
		if !adv.Ignored {
			findings = append(findings, adv.Findings()...)
		}
	}

	// The Source/Target context rows live in cfg.meta (renderAudit prepends them
	// to the text report), not in the GroupByAdvisory report passed as rep.
	source := (&report.Report{Meta: cfg.meta}).MetaValue("Source", "Target")
	if source == "" {
		source = "audit"
	}

	msg := notify.NewMessage(source, overall, findings)
	msg.CI = ci.Detect()
	msg.BaseURL = cfg.baseURL
	return msg
}

func sendNotifications(cfg auditRenderConfig, overall string) error {
	// --notify-on and --providers are validated up front (auditOptions.validate).
	if overall == "" || audit.SeverityLevels[overall] < audit.SeverityLevels[cfg.opts.notifyOn] {
		return nil
	}
	providers, err := notify.Resolve(cfg.opts.providers)
	if err != nil {
		return err
	}
	rep := audit.GroupByAdvisory(cfg.data, cfg.ignoreFile, cfg.opts.showUnfixed)
	msg := buildNotifyMessage(cfg, rep, overall)
	for _, e := range notify.Send(providers, msg) {
		slog.Warn("notification failed", "error", e)
	}
	return nil
}
