# Notifications

Every `audit` subcommand (`purl`, `manifest`, `sbom`, `linux`, `docker`) can send its result to a webhook, Slack or Microsoft Teams with `--notify`, typically from CI, next to `--fail-on`.

```bash
# Post to Slack when the audit finds a high or critical vulnerability
SECDB_SLACK_WEBHOOK=https://hooks.slack.com/services/... \
  secdb audit sbom --file bom.json --notify --notify-on=high
```

Each provider is configured with an environment variable:

| Provider  | Environment variable  | Format |
|-----------|-----------------------|--------|
| `webhook` | `SECDB_WEBHOOK_URL`   | The [payload](#payload) below, as JSON (for your own receiver, n8n, Zapier, ...) |
| `slack`   | `SECDB_SLACK_WEBHOOK` | A colored attachment for a [Slack Incoming Webhook](https://api.slack.com/messaging/webhooks) |
| `teams`   | `SECDB_TEAMS_WEBHOOK` | An [Adaptive Card](https://learn.microsoft.com/en-us/power-automate/create-flow-microsoft-teams-webhook) for a Power Automate Workflows webhook. The old Office 365 connectors are retired and not supported |

Without `--providers`, `--notify` tries every provider, and each one whose variable is not set prints a warning; `--providers` picks the ones to use.

```bash
# Only Slack, and only for critical vulnerabilities
secdb audit sbom --file bom.json --notify --providers=slack --notify-on=critical
```

| Flag | Description |
|---|---|
| `--notify` | Send the result to the notification providers |
| `--providers` | Providers to use, comma-separated (`webhook`, `slack`, `teams`); default: all |
| `--notify-on` | Send only when a vulnerability is at or above this severity (`critical`, `high`, `medium`, `low`, `info`; default `high`) |

The findings accepted in the [ignore file](audit.md#accepted-risks-secdbignore), and the unfixed ones unless `--show-unfixed` is given, are left out, as for `--fail-on`.

A failed delivery is printed as a warning and doesn't change the exit status, nor stop the other providers. The webhook URL is removed from the error, since it often contains a secret token.

In GitHub Actions, GitLab CI and Gitea Actions the message also carries the project, branch, commit and author, and its "view details" link opens the CI run. Elsewhere the link opens ZEN SecDB.

## Payload

The `webhook` provider POSTs this JSON; Slack and Teams get the same data in their own format. At most 20 findings are included: `total` and `counts` cover all of them, `truncated` says how many were left out.

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
  "base_url": "https://secdb.nttzen.cloud",
  "time": "2026-09-26T10:00:00Z"
}
```
