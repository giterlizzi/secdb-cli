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
| `SECDB_WEBHOOK_URL`     | Generic webhook endpoint for `--notify` (see [Send notifications](#send-notifications)) |
| `SECDB_SLACK_WEBHOOK`   | Slack Incoming Webhook URL for `--notify`                               |
| `SECDB_TEAMS_WEBHOOK`   | Microsoft Teams (Power Automate Workflows) webhook URL for `--notify`   |

`--base-url` overrides the API endpoint (default: `https://secdb.nttzen.cloud/`).

## Usage

### Look up a CVE

```bash
secdb cve CVE-2021-44228
```

Renders a curated, human-readable report (CVSS v2/v3/v4, SSVC, EPSS, CISA KEV status, weaknesses, exploit maturity, affected vendors/products and advisories) as Markdown, syntax-highlighted in an interactive terminal.

![secdb cve example output](docs/cve-example.png)

### Output formats

Supports `-o` / `--output`:

| Format | Description |
|---|---|
| `text` *(default)* | Curated Markdown report, rendered with ANSI styling in a terminal, printed raw when piped/redirected |
| `yaml` | Raw API response as YAML |
| `json` | Raw API response as JSON |
| `template` | Custom [Go template](https://pkg.go.dev/text/template) via `--template` (inline) or `--template-file` |
| `html` | Custom HTML via `--template`/`--template-file`, rendered with `html/template` (safe escaping) |
| `sarif` | SARIF 2.1.0 report (`audit` commands only, see below) |
| `csv` | CSV of the per-advisory audit details, one row per advisory (`audit` commands only, see below) |

```bash
secdb cve CVE-2021-44228 -o json
secdb cve CVE-2021-44228 -o template --template '{{.severity}}: {{.score}}'
```

Templates have access to [Sprig](https://masterminds.github.io/sprig/) functions (string manipulation, math, lists, dates, ...) in addition to the Go template built-ins. The `env`, `expandenv`, and `getHostByName` functions are disabled to prevent untrusted templates from reading environment variables (e.g. `SECDB_API_KEY`) or exfiltrating data over the network.

### Audit PURLs against known vulnerabilities

**Simple**

```bash
secdb audit purl pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1
```

**From file**

```bash
secdb audit purl --file=purls.txt
```

**From STDIN**

```bash
secdb audit purl < purls.txt
```

**From pipe**

```bash
command | secdb audit purl
```

**Using CycloneDX SBOM file (JSON)**

```bash
syft packages dir:. -o cyclonedx-json > bom.json && secdb audit sbom --file bom.json
cdxgen -o bom.json . && secdb audit sbom --file bom.json
```

**CI**

Useful in CI pipelines to fail the build when high/critical vulnerabilities are found.

```bash
secdb audit sbom --file bom.json --fail-on=high
```

**SARIF report (e.g. for GitHub Code Scanning)**

```bash
secdb audit sbom --file bom.json --output=sarif > results.sarif
```

Produces a [SARIF 2.1.0](https://sarifweb.azurewebsites.net/) report - one rule/result per (advisory, affected package) pair, with severity, CVEs, CWEs and a CVSS-derived `security-severity` score. The artifact location in the report is the audited file (`audit sbom`, `audit manifest`); a plain PURL list (`audit purl`) has no source file, so it is left empty. A finding matched by `--ignore-file` is still included in the report, but carries a SARIF `suppressions` entry (`kind: external`, `status: accepted`, with the rule's `reason` as justification), so consumers like GitHub Code Scanning don't open a new alert for it.

**CSV report (for spreadsheets)**

```bash
secdb audit sbom --file bom.json --output=csv > report.csv
```

Emits one row per advisory with the columns `ID, Title, Severity, CVSS, CVEs, CWEs, Packages, URL, Ignored, Ignore Reason`. The list columns (CVEs, CWEs, packages) are flattened into a single cell each, joined by `"; "`, and every text field is quoted per RFC 4180 so commas and quotes in titles/reasons don't break the columns. Like `sarif`, the `csv` output always uses the details shape (the `--view` flag doesn't affect it) and is only supported by the `audit` commands.

**Tips:** The layout is a Go template, so if you need different columns you can supply your own template instead: `--output=template --template-file my-csv.tmpl`.

**Ignoring accepted-risk findings**

```bash
secdb audit sbom --file bom.json --fail-on=high --ignore-file=/path-of/.secdbignore
```

`--ignore-file` (default: `.secdbignore`) points to a YAML file of accepted-risk rules. A matching rule never hides a finding from the report; it only excludes it from the `--fail-on` exit-code check (and, for `--output=sarif`, marks the result as suppressed instead of removing it):

```yaml
ignore:
  - vulnerability: CVE-2021-44228
    reason: "Not reachable in our usage of this library"

  - vulnerability: CVE-2024-33333
    reason: "Fixed upstream, upgrade planned"
    package:
      name: some-package
      version: 1.0.0    # optional: without it, the rule matches every version of the package
    expires: 2026-12-31 # optional: rule stops applying after this date (inclusive)
```

A rule matches on `vulnerability` (advisory ID or CVE) and, optionally, narrows to a specific `package.name`/`package.version`. It's a no-op if the audit result doesn't already have a matching, non-expired rule.

**Showing vulnerabilities with no available fix**

An advisory can affect a package for which no fix has been released yet (CSAF remediation status `none_available`). By default these "unfixed" findings are **hidden** from every view (`summary`, `details`, `sarif`, `csv`) and excluded from the `--fail-on` check, so the report focuses on actionable vulnerabilities. When any are hidden, the `--output=text` header shows a warning row with their count:

```
Unfixed: ⚠️ 98 hidden (run with --show-unfixed to list them)
```

Pass `--show-unfixed` to include them; in the `details` view each such advisory is marked `Fix: ❌ No fix available for the affected package`.

```bash
secdb audit sbom --file bom.json --show-unfixed
```

The `--output=text` report (both `--view` modes) is preceded by a short metadata header: the input source (arguments / `--file` / stdin) and the number of PURLs scanned. The header is text-only; it never appears in `json`/`yaml`/`sarif` output.

Package URLs ([PURLs](https://github.com/package-url/purl-spec)) can be passed as arguments, read from a file with `--file`/`-f` (one PURL per line, `#` for comments), or piped via stdin. For a CycloneDX SBOM use [`audit sbom`](#audit-a-cyclonedx-sbom).

| Flag | Description |
|---|---|
| `-f`, `--file` | Read PURLs from a file instead of arguments/stdin |
| `--sbom` | *(deprecated, use [`audit sbom --file`](#audit-a-cyclonedx-sbom))* Read PURLs from CycloneDX SBOM file (JSON) |
| `-v`, `--view` | `summary` *(default)*, one row per package, or `details`, one row per advisory (only applies to `--output=text`) |
| `--fail-on` | Exit with status `2` if any package has a vulnerability at or above the given severity (`critical`, `high`, `medium`, `low`, `info`) |
| `--ignore-file` | YAML file of accepted-risk rules that exclude matching findings from `--fail-on` (default `.secdbignore`) |
| `--show-unfixed` | Also report vulnerabilities that have no fix available (hidden by default) |

### Audit a dependency manifest

Parse a project's dependency manifest, resolve its packages to PURLs, and audit them against ZEN SecDB. The format is detected from the file name. Pass a single manifest with `--file`, or scan a directory with `--directory` to recursively discover and audit every supported manifest under it.

```bash
secdb audit manifest --file go.mod
secdb audit manifest --file package-lock.json
secdb audit manifest --file requirements.txt --view details
secdb audit manifest --file Gemfile.lock --fail-on=high
secdb audit manifest --file pom.xml
secdb audit manifest --file composer.lock

# Discover and audit every manifest under a directory (recursively)
secdb audit manifest --directory .
secdb audit manifest --directory ./services --max-depth 3 --fail-on=high
```

| Ecosystem | Files |
|---|---|
| Go | `go.mod` |
| npm | `package-lock.json`, `yarn.lock` |
| Python | `requirements*.txt` |
| Ruby | `Gemfile.lock` |
| Java (Maven) | `pom.xml` |
| PHP (Composer) | `composer.lock` |

For Python range specifiers that aren't an exact version (`>=2.28`), the leading version is audited; entries with no resolvable version (unpinned Python requirements, Maven versions supplied by a parent POM or an imported BOM, Composer platform requirements like `php`/`ext-*`) are skipped. The npm parser uses the lockfiles' resolved versions, so npm findings reflect what's actually installed. The Maven parser reads a single `pom.xml` and resolves `${...}` properties and versions declared in `<dependencyManagement>`, but does not follow parent POMs or transitive dependencies. Results are shaped and rendered exactly like `audit purl`: `--view`, `--fail-on`, `--ignore-file`, `--show-unfixed` and `--output=sarif`/`--output=csv` all behave the same way.

With `--directory`, discovery prunes noise directories (`.git`, `node_modules`, `vendor`, `target`, `dist`, `build`, `testdata`, ...) and does not follow symlinks; `--max-depth` caps how deep the walk descends. A manifest that fails to parse is skipped with a warning instead of aborting the scan, and all discovered dependencies are audited together in a single report. (With `--output=sarif`, findings from a `--directory` scan are not yet attributed to their individual source files.)

| Flag | Description |
|---|---|
| `-f`, `--file` | Path to a single dependency manifest to audit (mutually exclusive with `--directory`) |
| `-d`, `--directory` | Directory to recursively discover and audit manifests in (mutually exclusive with `--file`) |
| `--max-depth` | Max directory depth to descend with `--directory` (`0` = unlimited) |
| `-v`, `--view` | `summary` *(default)* or `details` (only applies to `--output=text`) |
| `--fail-on` | Exit with status `2` at or above the given severity |
| `--ignore-file` | YAML file of accepted-risk rules (default `.secdbignore`) |
| `--show-unfixed` | Also report vulnerabilities that have no fix available (hidden by default) |

Support for more manifest formats can be added over time.

### Editor integration (Language Server)

`secdb lsp` starts a [Language Server](https://microsoft.github.io/language-server-protocol/) that audits dependency manifests **as you open and edit them**, reporting known vulnerabilities inline as editor diagnostics, each linking to its ZEN SecDB advisory. It reuses the same engine as [`audit manifest`](#audit-a-dependency-manifest), so it recognizes the same files (`go.mod`, `package-lock.json`, `yarn.lock`, `requirements*.txt`, `Gemfile.lock`, `pom.xml`, `composer.lock`) and honors the same `SECDB_API_KEY` and `--base-url` configuration.

The server speaks JSON-RPC over stdin/stdout and is meant to be launched by an editor's LSP client, not run by hand (in a plain terminal it just waits for input). It debounces edits, so it audits shortly after you stop typing rather than on every keystroke. Set `SECDB_DEBUG=1` (or pass `--debug`) to log to stderr.

On startup the server also **discovers and audits every supported manifest in the workspace**, so findings show up without opening each file (noise directories like `node_modules`, `vendor`, `target`, `dist`, `build` and `testdata` are skipped, and symlinks aren't followed). Discovery skips files you already have open (they're kept fresh by the edit path) and audits the rest sequentially. Pass `--no-discovery` to audit only files as they are opened.

<details>
<summary><strong>Kate</strong> (Settings &gt; LSP Client &gt; User Server Settings)</summary>

```json
{
  "servers": {
    "secdb": {
      "command": ["secdb", "lsp"],
      "commandDebug": ["secdb", "lsp", "--debug"],
      "rootIndicationFileNames": ["go.mod", "package-lock.json", "yarn.lock", "requirements.txt", "Gemfile.lock", "pom.xml", "composer.lock"],
      "highlightingModeRegex": "^(Go|JSON|Python|Ruby|XML)$"
    }
  }
}
```
</details>

<details>
<summary><strong>Sublime Text</strong> (Preferences &gt; Package Settings &gt; LSP &gt; Settings, requires the <code>LSP</code> package)</summary>

```json
{
  "clients": {
    "secdb": {
      "enabled": true,
      "command": ["secdb", "lsp"],
      "selector": "source.go-mod | source.json | text.plain | text.xml | text.xml.dtd"
    }
  }
}
```
</details>

<details>
<summary><strong>Neovim</strong> (0.10+, native LSP client, no plugin)</summary>

Neovim has a built-in LSP client. Since `secdb` isn't a preconfigured server, start it from an autocommand keyed on the manifest file names (this sidesteps filetype detection, which is inconsistent for `yarn.lock`/`Gemfile.lock`). Add to your `init.lua`:

```lua
vim.api.nvim_create_autocmd({ "BufReadPost", "BufNewFile" }, {
  pattern = {
    "go.mod", "package-lock.json", "yarn.lock",
    "requirements*.txt", "Gemfile.lock", "pom.xml",
    "composer.lock",
  },
  callback = function(args)
    vim.lsp.start({
      name = "secdb",
      cmd = { "secdb", "lsp" },
      root_dir = vim.fs.root(args.buf, { ".git", "go.mod", "package.json", "pom.xml" }),
    })
  end,
})
```

`secdb` must be on your `PATH`. `vim.lsp.start` reuses one server per project root, and Neovim shows the reported vulnerabilities as diagnostics automatically.
</details>

<details>
<summary><strong>Zed</strong> (companion extension)</summary>

Unlike Kate and Sublime, Zed can't point at an arbitrary LSP binary from its settings: a language server must be provided by an extension. Install the companion [**secdb Zed extension**](https://github.com/giterlizzi/secdb-zed) and, once enabled, Zed starts `secdb lsp` automatically on the recognized manifests (make sure `secdb` is on your `PATH`). Zed launches the server lazily, on opening the first recognized file; workspace discovery then audits the rest of the project.
</details>

A few files aren't recognized as a distinct language by every editor, so the server may not start on them out of the box: Sublime scopes `go.mod` as `text.xml.dtd` (hence the entry in the selector above), and `requirements.txt`, `Gemfile.lock` and `yarn.lock` are plain text. The server itself detects the format from the file name regardless; it's only the editor's trigger that needs the scope/language hint.

### Audit a CycloneDX SBOM

Extract the PURLs from a CycloneDX BOM (JSON) and audit them against ZEN SecDB. It supersedes the deprecated `audit purl --sbom` (still accepted, with the same output).

```bash
secdb audit sbom --file bom.json

# generate then audit
syft packages dir:. -o cyclonedx-json > bom.json && secdb audit sbom --file bom.json
cdxgen -o bom.json . && secdb audit sbom --file bom.json

# CI (fail on high or critical)
secdb audit sbom --file bom.json --fail-on=high

# SARIF (e.g. for GitHub Code Scanning)
secdb audit sbom --file bom.json --output=sarif > results.sarif
```

The PURLs are collected from the BOM's `components` (recursively). Results are shaped and rendered exactly like `audit purl`: `--view`, `--fail-on`, `--ignore-file`, `--show-unfixed` and `--output=sarif`/`--output=csv` all behave the same way.

| Flag | Description |
|---|---|
| `-f`, `--file` | *(required)* Path to the CycloneDX SBOM (JSON) to audit |
| `-v`, `--view` | `summary` *(default)* or `details` (only applies to `--output=text`) |
| `--fail-on` | Exit with status `2` at or above the given severity |
| `--ignore-file` | YAML file of accepted-risk rules (default `.secdbignore`) |
| `--show-unfixed` | Also report vulnerabilities that have no fix available (hidden by default) |

### Audit a Linux system (EXPERIMENTAL)

Audits the installed packages of a Linux host against ZEN SecDB. By default it audits the **local machine** (local auditing is only supported on Linux); it can also target a remote host over SSH. To audit a Docker image or container, use [`audit docker`](#audit-a-docker-image-or-container-experimental).

**Local system**

```bash
secdb audit linux
```

**Remote host over SSH**

```bash
secdb audit linux --host server.example.com --user ops

# or the ssh:// URI shorthand (user, host and port in one argument)
secdb audit linux ssh://ops@server.example.com:2222
```

The `ssh://user@host:port` argument is a shorthand: the user, host and port it carries override the `--host`/`--user`/`--port` flags, while `--identity-file`/`--ssh-config`/`--sudo` still apply. Uses your system `ssh` client, so `~/.ssh/config`, the SSH agent and `known_hosts` all apply (host-key checking stays enabled).

The command runs only fixed, read-only commands on the target: reading `/etc/os-release`, `uname -m`, and the distribution's package-list command (`dpkg-query` / `rpm` / `apk` / Slackware `/var/log/packages`). Supported distributions include Debian/Ubuntu, RHEL/Rocky Linux/AlmaLinux/Oracle Linux/Amazon Linux/Fedora/SUSE, Alpine Linux and Slackware Linux.

`--view`, `--fail-on`, `--output=sarif`/`--output=csv`, `--ignore-file` and `--show-unfixed` work exactly as for `audit purl`. The `--output=text` report is preceded by a metadata header showing the target (`local`, `user @ host:port`, or the Docker image/container), OS/version, architecture, and packages scanned. Progress lines (`Detected ...`, `Auditing ...`) are written to stderr only when it's a terminal, so piped/redirected output stays clean.

| Flag | Description |
|---|---|
| `--host` | Audit a remote host over SSH (default: local machine) |
| `--user`, `--port` | SSH user and port |
| `--identity-file` | SSH identity (private key) file |
| `--ssh-config` | SSH config file (when set, host-key policy is left to it) |
| `--sudo` | Prefix the package-list command with `sudo -n` |
| `-v`, `--view` | `summary` *(default)* or `details` (only applies to `--output=text`) |
| `--fail-on` | Exit with status `2` at or above the given severity |
| `--ignore-file` | YAML file of accepted-risk rules (default `.secdbignore`) |
| `--show-unfixed` | Also report vulnerabilities that have no fix available (hidden by default) |

### Audit a Docker image or container (EXPERIMENTAL)

Audits the installed packages of a Docker image or container. Provide exactly one of `--image` (run the package-list command in an ephemeral `docker run --rm` container) or `--container` (exec it in a running container). The `docker` CLI must be available and able to reach the daemon.

```bash
secdb audit docker --image debian:12
secdb audit docker --container my-running-container
```

The same read-only collection, distribution support, and `--view` / `--fail-on` / `--output=sarif` / `--output=csv` / `--ignore-file` / `--show-unfixed` behavior as `audit linux` apply.

| Flag | Description |
|---|---|
| `--image` | Audit a local Docker image (run ephemerally) |
| `--container` | Audit a running local Docker container |
| `-v`, `--view` | `summary` *(default)* or `details` (only applies to `--output=text`) |
| `--fail-on` | Exit with status `2` at or above the given severity |
| `--ignore-file` | YAML file of accepted-risk rules (default `.secdbignore`) |
| `--show-unfixed` | Also report vulnerabilities that have no fix available (hidden by default) |

### Send notifications

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

#### Notification payload

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

### Calculate SSVC

[Stakeholder-Specific Vulnerability Categorization (SSVC)](https://www.cisa.gov/ssvc-calculator), per the CISA methodology, combines a CVE's exploitation status and technical impact (from ZEN SecDB) with stakeholder-supplied context to produce an actionable decision: `track`, `track*`, `attend`, or `act`.

**Simple**

```bash
secdb ssvc calculate CVE-2021-44228 --mission-prevalence essential --public-well-being-impact material
```

**Bulk, multiple CVEs**

```bash
secdb ssvc calculate CVE-2021-44228 CVE-2023-4863 --mission-prevalence support --public-well-being-impact minimal
```

**From file**

```bash
secdb ssvc calculate --file cves.txt --mission-prevalence support --public-well-being-impact minimal
```

**From STDIN**

```bash
secdb ssvc calculate --mission-prevalence support --public-well-being-impact minimal < cves.txt
```

CVE identifiers can be passed as arguments, read from a file with `--file`/`-f` (one CVE per line, `#` for comments), or piped via stdin (same precedence as `audit purl`: arguments, then `--file`, then stdin). Duplicate CVEs are deduplicated; a CVE that can't be found still appears in the report with its status instead of failing the whole batch.

| Flag | Description |
|---|---|
| `-f`, `--file` | Read CVEs from a file instead of arguments/stdin |
| `--mission-prevalence` | *(required)* `minimal`, `support`, or `essential` |
| `--public-well-being-impact` | *(required)* `minimal`, `material`, or `irreversible` |

### Check for a new version

```bash
secdb check-update
```

A lightweight background check also runs automatically on every command (cooldown: 24h, silent on failure, skipped in CI or with `SECDB_NO_UPDATE_CHECK` set).

## License

[Apache License 2.0](LICENSE).

Third-party dependency attributions are listed in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
