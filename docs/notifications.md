# Notifications

Every `audit` subcommand (`purl`, `manifest`, `sbom`, `linux`, `docker`) can push its result to one or more notification destinations with `--notify`. This is meant for CI: fail the build **and** post the findings to a chat channel or an automation endpoint in the same run.

```bash
# Post to Slack when the audit finds a high or critical vulnerability
SECDB_SLACK_WEBHOOK=https://hooks.slack.com/services/... \
  secdb audit sbom --file bom.json --notify --notify-on=high
```

Providers are configured entirely from the environment (a provider with no URL set is skipped, it is never an error):

| Provider  | Environment variable  | Format |
|-----------|-----------------------|--------|
| `webhook` | `SECDB_WEBHOOK_URL`   | The [notification payload](#notification-payload) as JSON (for custom receivers and automation tools like n8n or Zapier) |
| `slack`   | `SECDB_SLACK_WEBHOOK` | A colored [Slack Incoming Webhook](https://api.slack.com/messaging/webhooks) attachment |
| `teams`   | `SECDB_TEAMS_WEBHOOK` | A Microsoft Teams [Adaptive Card](https://learn.microsoft.com/en-us/power-automate/create-flow-microsoft-teams-webhook) posted to a Power Automate **Workflows** webhook (the successor to the retired Office 365 connectors) |

By default `--notify` sends to **every configured provider**. Use `--providers` to pick a subset (comma-separated), and `--notify-on` to set the minimum severity that triggers a notification.

```bash
# Only Slack, and only when a critical vulnerability is present
secdb audit sbom --file bom.json --notify --providers=slack --notify-on=critical
```

| Flag | Description |
|---|---|
| `--notify` | Send the audit result to the configured notification providers |
| `--providers` | Providers to notify (comma-separated: `webhook`, `slack`, `teams`); default: all configured |
| `--notify-on` | Notify only when a vulnerability at or above this severity is found (`critical`, `high`, `medium`, `low`, `info`; default: `high`) |

Delivery is **best-effort**: every selected provider is tried, failures are logged as warnings (with the endpoint URL redacted, so a secret-bearing webhook URL never reaches the logs), and a broken endpoint never fails the audit or blocks the other providers. The `--fail-on` exit code is unaffected by `--notify`.

When the audit runs inside **GitHub Actions** or **GitLab CI**, the notification is automatically enriched with the pipeline context (repository, branch, commit, author) and its "view details" link points at the CI run; outside CI it points at the ZEN SecDB instance.

## Notification payload

The `webhook` provider POSTs this JSON (the `slack`/`teams` providers render the same data into their own card format). The findings list is capped, with `truncated` reporting how many were omitted:

```json
{
  "title": "SecDB audit: high severity (7 findings)",
  "source": "SBOM (bom.json)",
  "overall": "high",
  "total": 7,
  "counts": { "high": 2, "medium": 5 },
  "findings": [
    {
      "source": "secdb-audit",
      "source_id": "ZEN-...",
      "name": "Advisory title",
      "severity": "high",
      "cves": ["CVE-2024-..."],
      "purl": "pkg:maven/org.example/lib@1.2.3"
    }
  ],
  "truncated": 0,
  "ci": { "name": "github", "project": "org/repo", "run_url": "https://github.com/org/repo/actions/runs/..." },
  "base_url": "https://secdb.nttzen.cloud/",
  "time": "2026-09-26T10:00:00Z"
}
```
