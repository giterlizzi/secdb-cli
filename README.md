# ZEN SecDB CLI

[![CI](https://github.com/giterlizzi/secdb-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/giterlizzi/secdb-cli/actions/workflows/ci.yml)
[![release](https://github.com/giterlizzi/secdb-cli/actions/workflows/release.yml/badge.svg)](https://github.com/giterlizzi/secdb-cli/actions/workflows/release.yml)
[![GitHub release](https://img.shields.io/github/v/release/giterlizzi/secdb-cli)](https://github.com/giterlizzi/secdb-cli/releases)
[![License](https://img.shields.io/github/license/giterlizzi/secdb-cli)](LICENSE)

Command-line client for the [ZEN SecDB](https://secdb.nttzen.cloud) API.

## Installation

```bash
go install github.com/giterlizzi/secdb-cli@latest
```

Or clone and build locally (requires Go 1.26+):

```bash
git clone https://github.com/giterlizzi/secdb-cli
cd secdb-cli
make build
```

Pre-built binaries for Linux, macOS and Windows (amd64/arm64) are published on the [Releases](https://github.com/giterlizzi/secdb-cli/releases) page via GoReleaser.

## Configuration

| Environment variable    | Purpose                                                                 |
|-------------------------|-------------------------------------------------------------------------|
| `SECDB_API_KEY`         | API key sent as the `X-API-KEY` header on every request                 |
| `SECDB_DEBUG`           | Set to any value to enable debug logging to stderr (same as `--debug`)  |
| `SECDB_NO_UPDATE_CHECK` | Set to any value to disable the background update check                 |
| `NO_COLOR`              | Print raw Markdown instead of ANSI-styled `text` output                 |
| `CI`                    | Automatically disables the background update check when set             |
| `SECDB_WEBHOOK_URL`     | Generic webhook endpoint for `--notify` (see [Notifications](docs/notifications.md)) |
| `SECDB_SLACK_WEBHOOK`   | Slack Incoming Webhook URL for `--notify`                               |
| `SECDB_TEAMS_WEBHOOK`   | Microsoft Teams (Power Automate Workflows) webhook URL for `--notify`   |

`--base-url` changes the API address (default `https://secdb.nttzen.cloud`). It can include a path, e.g. a proxy at `https://gateway.example.com/secdb`.

The links printed by the CLI (CVE, CWE and advisory pages, the report footer, the notifications, the editor diagnostics) go to the ZEN SecDB web interface, which is normally on the API host. If you reach the API through a proxy, set `--web-url` to the web interface address so the links don't point to the proxy:

```bash
secdb --base-url https://gateway.example.com/secdb --web-url https://secdb.nttzen.cloud cve CVE-2021-44228
```

## Usage

### Look up a CVE

```bash
secdb cve CVE-2021-44228
```

Prints the CVE with CVSS v2/v3/v4, SSVC, EPSS, CISA KEV status, weaknesses, exploit maturity, affected vendors and products, and advisories. The report is Markdown, rendered with colors in a terminal.

![secdb cve example output](docs/cve-example.png)

### Output formats

`-o` / `--output` selects the format: `text` (the default Markdown report), `json`, `yaml`, `template` and `html` (your own Go templates), and `sarif` and `csv` for the `audit` commands.

```bash
secdb cve CVE-2021-44228 -o json
secdb cve CVE-2021-44228 -o template --template '{{.severity}}: {{.score}}'
```

See [Output formats](docs/output.md) for the template functions.

### Audit packages against known vulnerabilities

```bash
# Package URLs, from arguments, a file or stdin
secdb audit purl pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1

# A dependency manifest, or every manifest under a directory
secdb audit manifest --file go.mod
secdb audit manifest --directory .

# A CycloneDX SBOM
secdb audit sbom --file bom.json

# A Linux host (local or over SSH), a Docker image or container (EXPERIMENTAL)
secdb audit linux --host server.example.com --user ops
secdb audit docker --image debian:12

# CI: fail on high or critical, export SARIF for GitHub Code Scanning
secdb audit sbom --file bom.json --fail-on=high --output=sarif > results.sarif
```

All the `audit` commands take the same options: `--view summary|details`, `--fail-on`, accepted risks in a `.secdbignore` file, `--show-unfixed`, SARIF and CSV output, and [notifications](docs/notifications.md). [Auditing](docs/audit.md) covers each command, the supported manifests and distributions.

### Editor integration (Language Server)

`secdb lsp` is a [Language Server](https://microsoft.github.io/language-server-protocol/) that audits the manifests you open in the editor and shows the vulnerabilities on the dependency lines. It works with Kate, KDevelop, Sublime Text, Neovim and Zed; [Editor integration](docs/lsp.md) has the configuration for each.

### Send notifications

`--notify` sends the result of an `audit` command to a webhook, Slack or Microsoft Teams, e.g. from CI:

```bash
SECDB_SLACK_WEBHOOK=https://hooks.slack.com/services/... \
  secdb audit sbom --file bom.json --notify --notify-on=high
```

See [Notifications](docs/notifications.md) for the providers and the webhook payload.

### Calculate SSVC

[SSVC](https://www.cisa.gov/ssvc-calculator) (Stakeholder-Specific Vulnerability Categorization, from CISA) gives a CVE one of four decisions: `track`, `track*`, `attend` or `act`. ZEN SecDB knows the exploitation status and the technical impact; you supply the other two inputs with the flags below.

```bash
secdb ssvc calculate CVE-2021-44228 --mission-prevalence essential --public-well-being-impact material

# Several CVEs, from arguments, a file or stdin
secdb ssvc calculate CVE-2021-44228 CVE-2023-4863 --mission-prevalence support --public-well-being-impact minimal
secdb ssvc calculate --file cves.txt --mission-prevalence support --public-well-being-impact minimal
secdb ssvc calculate --mission-prevalence support --public-well-being-impact minimal < cves.txt
```

The CVEs are read from the arguments, else from `--file`/`-f` (one per line, `#` starts a comment), else from stdin. Duplicates are removed, and a CVE that isn't found is listed with its status instead of failing the whole run.

| Flag | Description |
|---|---|
| `-f`, `--file` | Read CVEs from a file instead of arguments/stdin |
| `--mission-prevalence` | *(required)* `minimal`, `support`, or `essential` |
| `--public-well-being-impact` | *(required)* `minimal`, `material`, or `irreversible` |

### Check for a new version

```bash
secdb check-update
```

If a newer release exists, it prints the release notes of the versions after yours, from `CHANGELOG.md`. If the notes can't be downloaded, it prints only the new version and the link to its release page.

Every command also checks for a new version in the background, at most once a day, and prints a one-line notice when there is one. The check stays silent if it fails, and is skipped in CI or when `SECDB_NO_UPDATE_CHECK` is set.

## Documentation

- [Auditing](docs/audit.md): the `audit` commands and their options
- [Editor integration](docs/lsp.md): `secdb lsp`
- [Notifications](docs/notifications.md): `--notify`
- [Output formats](docs/output.md): formats and templates

## License

[Apache License 2.0](LICENSE).

Third-party dependency attributions are listed in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
