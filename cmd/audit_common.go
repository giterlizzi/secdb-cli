// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strconv"

	"github.com/giterlizzi/secdb-cli/internal/audit"
	"github.com/giterlizzi/secdb-cli/internal/ci"
	"github.com/giterlizzi/secdb-cli/internal/client"
	"github.com/giterlizzi/secdb-cli/internal/finding"
	"github.com/giterlizzi/secdb-cli/internal/inventory"
	"github.com/giterlizzi/secdb-cli/internal/notify"
	"github.com/giterlizzi/secdb-cli/internal/output"
	"github.com/giterlizzi/secdb-cli/internal/report"

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

	// ignore is the parsed --ignore-file, loaded by validate.
	ignore *audit.IgnoreFile
}

// auditTarget describes what an audit command audited, for the report.
type auditTarget struct {
	// source names it for the notifications, e.g. "SBOM (bom.json)".
	source string

	// meta are the rows of the text report header, e.g. "PURLs scanned: 3".
	meta []report.MetaItem

	// template is the family of the text templates and of the SARIF
	// automation ID: "audit-purl" or "audit-linux" (set by runPURLAudit and
	// runPackageAudit).
	template string

	// sarifFile is the SARIF location of every finding (the SBOM, the OS),
	// unless sarifSources has the finding's PURL (audit manifest).
	sarifFile    string
	sarifSources map[string]output.SourceLocation
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
		"Notification providers to use (comma-separated); default: all")
	cmd.Flags().StringVar(&o.notifyOn, "notify-on", "high",
		"Notify only on a vulnerability at or above this severity (critical, high, medium, low, info)")
}

// validate checks the shared audit flags, normalizes the severities and loads
// the --ignore-file, so renderAudit can trust them and a malformed ignore file
// fails before any inventory collection (SSH, Docker) or API call. The
// notification flags are only checked with --notify, as they are unused
// otherwise.
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

	ignore, err := audit.LoadIgnoreFile(o.ignoreFile)
	if err != nil {
		return err
	}
	o.ignore = ignore

	slog.Debug("audit options",
		"view", o.view,
		"fail_on", o.failOn,
		"ignore_file", o.ignoreFile,
		"ignore_rules", len(ignore.Ignore),
		"show_unfixed", o.showUnfixed,
		"notify", o.notify,
		"providers", o.providers,
		"notify_on", o.notifyOn,
	)
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
// against ZEN SecDB and reports the result. It is the shared body of the audit
// linux and audit docker commands; they differ only in how they build the
// inventory.Target.
func runPackageAudit(target inventory.Target, opts *auditOptions) error {
	slog.Debug("audit target", "target", target)

	info, err := inventory.Collect(target)
	if err != nil {
		return err
	}

	statusf("Detected %s %s %s (%d packages)\n", info.OS, info.Version, info.Arch, len(info.Packages))
	statusf("Auditing %d packages against ZEN SecDB...\n", len(info.Packages))

	client := global.newClient()
	items, err := client.LinuxAudit(info.OS, info.Version, info.Arch, info.Packages)
	if err != nil {
		return err
	}

	return reportAudit(items, opts, client.WebURL(), auditTarget{
		source:    target.Describe(),
		template:  "audit-linux",
		sarifFile: fmt.Sprintf("%s/%s", info.OS, info.Version),
		meta: []report.MetaItem{
			{Label: "Target", Value: target.Describe()},
			{Label: "OS", Value: fmt.Sprintf("%s %s", info.OS, info.Version)},
			{Label: "Arch", Value: info.Arch},
			{Label: "Packages scanned", Value: strconv.Itoa(len(info.Packages))},
		},
	})
}

// runPURLAudit audits purls against ZEN SecDB and reports the result with the
// audit-purl templates. It is the shared tail of the audit purl, sbom and
// manifest commands, which describe what they read in target.
func runPURLAudit(purls []string, opts *auditOptions, target auditTarget) error {
	client := global.newClient()
	items, err := client.PURLAudit(purls)
	if err != nil {
		return err
	}

	target.template = "audit-purl"
	return reportAudit(items, opts, client.WebURL(), target)
}

// reportAudit is the pipeline every audit command ends with: it shapes the
// items once, writes them in the --output format, sends the notifications
// (--notify), then applies --fail-on. webURL is the web-GUI base of the
// permalinks, the report footer and the notifications. All flags were
// validated up front (auditOptions.validate).
func reportAudit(items []client.AuditItem, opts *auditOptions, webURL string, target auditTarget) error {
	res := audit.Analyze(items, opts.ignore, opts.showUnfixed)

	if err := writeAuditOutput(res, opts, webURL, target); err != nil {
		return err
	}

	if opts.notify {
		if err := sendNotifications(res, opts, webURL, target.source); err != nil {
			return err
		}
	}

	return failOnError(opts.failOn, res.Overall)
}

// writeAuditOutput writes the audit result to stdout in the --output format.
func writeAuditOutput(res audit.Result, opts *auditOptions, webURL string, target auditTarget) error {
	switch global.output {
	case "text":
		return writeAuditText(res, opts, webURL, target)
	case "sarif":
		return output.WriteSARIF(os.Stdout, res.Advisories, output.SARIFOptions{
			AutomationID: "secdb-cli/" + target.template,
			File:         target.sarifFile,
			Sources:      target.sarifSources,
		})
	case "csv":
		return output.WriteCSV(os.Stdout, res.Advisories)
	case "defectdojo":
		return output.WriteDefectDojo(os.Stdout, res.Advisories, output.DefectDojoOptions{
			WebURL:  webURL,
			File:    target.sarifFile,
			Sources: target.sarifSources,
		})
	case "cyclonedx":
		return output.WriteCycloneDX(os.Stdout, res.Advisories, output.CycloneDXOptions{WebURL: webURL})
	default:
		if err := output.Render(os.Stdout, res.Items, output.Format(global.output), global.outputOptions()); err != nil {
			return fmt.Errorf("failed to render output: %w", err)
		}
		return nil
	}
}

// writeAuditText renders the --view (summary or details) text report. Its
// header has the command's rows, the CI run, a warning when unfixed
// vulnerabilities were hidden (pointing at --show-unfixed) and, in the details
// view, how many advisories the ignore file accepts.
func writeAuditText(res audit.Result, opts *auditOptions, webURL string, target auditTarget) error {
	r := report.Report{
		Meta:    slices.Concat(target.meta, ciMeta(ci.Detect())),
		Results: res.Packages,
		BaseURL: webURL,
	}
	if !opts.showUnfixed && res.Unfixed > 0 {
		r.Meta = append(r.Meta, report.MetaItem{
			Label: "Unfixed",
			Value: fmt.Sprintf("⚠️ %d hidden (run with --show-unfixed to list them)", res.Unfixed),
		})
	}
	if opts.view == "details" {
		r.Results = res.Advisories
		if item, ok := ignoredMeta(res.Ignored, res.PartlyIgnored); ok {
			r.Meta = append(r.Meta, item)
		}
	}

	templateName := target.template + "-" + opts.view
	if err := output.RenderText(os.Stdout, r, templateName); err != nil {
		return fmt.Errorf("failed to render details: %w", err)
	}
	return nil
}

// ignoredMeta is the text header's "Ignored" row: the fully ignored advisories,
// plus those accepted for some packages only (false when there are none).
func ignoredMeta(full, partial int) (report.MetaItem, bool) {
	var value string
	switch {
	case full == 0 && partial == 0:
		return report.MetaItem{}, false
	case partial == 0:
		value = strconv.Itoa(full)
	case full == 0:
		value = fmt.Sprintf("%d for some packages only", partial)
	default:
		value = fmt.Sprintf("%d (+%d for some packages only)", full, partial)
	}
	return report.MetaItem{Label: "Ignored", Value: value}, true
}

// ciMeta returns the text-report header rows describing the CI run the audit
// is part of (none outside CI): the run summary and a link to it.
func ciMeta(env ci.Env) []report.MetaItem {
	summary := env.Summary()
	if summary == "" {
		return nil
	}
	items := []report.MetaItem{{Label: "CI", Value: summary}}
	if env.RunURL != "" {
		items = append(items, report.MetaItem{Label: "CI run", Value: "<" + env.RunURL + ">"})
	}
	return items
}

// failOnError returns the exitError that ends the command with status 2 when
// the overall severity reaches the --fail-on threshold, or nil.
func failOnError(failOn, overall string) error {
	if failOn == "" || overall == "" || audit.SeverityLevels[overall] < audit.SeverityLevels[failOn] {
		return nil
	}
	return &exitError{
		code: 2,
		msg:  fmt.Sprintf("audit failed: a package has a vulnerability with severity %q (fail-on=%q)", overall, failOn),
	}
}

// sendNotifications notifies the --providers when the overall severity
// reaches --notify-on. Delivery is best-effort: a failed provider is only
// logged.
func sendNotifications(res audit.Result, opts *auditOptions, webURL, source string) error {
	if res.Overall == "" || audit.SeverityLevels[res.Overall] < audit.SeverityLevels[opts.notifyOn] {
		return nil
	}
	providers, err := notify.Resolve(opts.providers)
	if err != nil {
		return err
	}
	msg := buildNotifyMessage(res.Advisories, res.Overall, webURL, source)
	for _, e := range notify.Send(providers, msg) {
		slog.Warn("notification failed", "error", e)
	}
	return nil
}

// buildNotifyMessage turns the advisories into the notification message: one
// finding per affected package, except the packages an ignore rule accepts.
func buildNotifyMessage(advisories []audit.AdvisoryResult, overall, webURL, source string) notify.Message {
	var findings []finding.Finding
	for _, adv := range advisories {
		for _, f := range adv.Findings() {
			if ignored, _ := adv.IgnoredFor(f.PURL); !ignored {
				findings = append(findings, f)
			}
		}
	}
	if source == "" {
		source = "audit"
	}

	msg := notify.NewMessage(source, overall, findings)
	msg.CI = ci.Detect()
	msg.BaseURL = webURL
	return msg
}
