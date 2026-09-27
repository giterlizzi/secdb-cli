// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/MakeNowJust/heredoc/v2"
	"github.com/spf13/cobra"
)

var auditCmd = &cobra.Command{
	Use:     "audit",
	GroupID: groupAudit,
	Short:   "Audit software packages and dependencies",
	Long: heredoc.Doc(`
		Audit software packages and dependencies against the ZEN SecDB to
		identify known vulnerabilities and security issues.

		See the subcommands below for the supported audit targets (e.g. PURLs).

		Notifications:
		  Every audit subcommand can push its result to external destinations with
		  --notify. Use --providers to pick which ones (comma-separated; default:
		  all configured), and --notify-on to set the minimum severity that
		  triggers a notification (critical, high, medium, low, info; default:
		  high). Delivery is best-effort and never fails the audit.

		  Providers are configured from the environment:
		    webhook  POSTs the result as JSON to SECDB_WEBHOOK_URL
		    slack    posts a colored message to the Slack Incoming Webhook in
		             SECDB_SLACK_WEBHOOK
		    teams    posts an Adaptive Card to the Microsoft Teams (Power Automate
		             Workflows) webhook in SECDB_TEAMS_WEBHOOK
	`),
}

func init() {
	rootCmd.AddCommand(auditCmd)
}
