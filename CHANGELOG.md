# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `audit manifest` and `secdb lsp` read more lockfiles: `gradle.lockfile`
  (Gradle dependency locking), `Cargo.lock` (Rust), `poetry.lock`, `uv.lock`
  (and a script's `*.py.lock`), `pdm.lock` and `pylock.toml` (Python), and
  `gems.locked` (Ruby, like `Gemfile.lock`). Every resolved dependency is
  audited, transitive, test and dev ones included, with its lines for the
  editor diagnostics and SARIF; your own workspace packages and the ones from
  git, a local path or a URL are skipped.
- `audit` commands: `--output=defectdojo` writes the findings for a
  DefectDojo import (Generic Findings Import, one finding per advisory and
  package, ready for `reimport-scan`), and `--output=cyclonedx` writes a
  CycloneDX 1.6 vulnerability report. Both carry the manifest location, the
  accepted risks of the ignore file, the EPSS score, the CVEs in the CISA
  KEV catalog and, with `--show-unfixed`, the missing fixes. The CycloneDX
  report also names what was audited (the project, the SBOM file, the
  distribution or the container) as its subject, depending on the affected
  packages.
- `audit` commands: the `json` and `yaml` output (and `--jq`) include each
  advisory's `cisa_kev`, its CVEs in the CISA Known Exploited Vulnerabilities
  catalog (`cve_id`, `added_date`, `due_date`,
  `known_ransomware_campaign_use`), and `epss`, the EPSS score of its CVEs
  (`cve_id`, `score`, `percentile`, `date`; the scores are numbers).
- `SECDB_BASE_URL` sets the API base URL, like `--base-url` (the flag wins
  when both are set): handy for editors, CI and hosts behind a proxy.

### Changed

- The links in the output (CVE, CWE and advisory pages, report footer,
  notifications, editor diagnostics) go to the public ZEN SecDB web GUI by
  default, also with `--base-url`: behind a proxy `--web-url` is no longer
  needed. For another SecDB instance, set `--web-url` too.
- `secdb lsp`: the diagnostics of a `pom.xml` are now on the `<dependency>`
  element they refer to, instead of all on the first line.

### Fixed

- `search`: the result links stay correct when the API returns absolute
  URLs instead of paths; they still follow `--web-url`.
- `audit linux` with `--host localhost` or `--host 127.0.0.1` (or an
  `ssh://user@127.0.0.1:2222` URI) audited the local machine, ignoring the SSH
  user and port. An explicit host now always means SSH, loopback included (VMs
  and containers reached through a forwarded port); without a host the audit
  stays local.
- `secdb lsp` on Windows: the workspace discovery failed (only in the debug
  log) and the `.secdbignore` was never found, so ignored advisories stayed
  warnings. File URIs (`file:///C:/...`) are now turned into Windows paths,
  and every document URI is normalized (`file:///c%3A/...` and
  `file:///C:/...` are the same file), so a file is never audited or reported
  under two URIs.
- `ssvc calculate`: the `Track*` entry of the decision legend is no longer
  rendered as broken bold text.

### Security

- Built with Go 1.26.10, which fixes GO-2026-6809 in `crypto/x509`, reached
  by the HTTPS calls; `golang.org/x/net` updated to v0.62.0.

## [0.7.0] - 2026-10-16

### Added

- `secdb search`: full-text search across ZEN SecDB (CVEs, CWEs, advisories,
  NASL plugins, ExploitDB entries), narrowed by record type (`--type`, a
  comma-separated list) and last-modified window (`--since 30d`), paged with
  `--page`/`--per-page`. The `text` output links each result to the web GUI and
  ends with the totals by type and severity; `json`/`yaml`/`template` print the
  results with their API field names, the counts by type, severity and source,
  and a `pagination` object.
- Template function `path_url`, the web-GUI link for a path returned by the API
  (such as a search hit's `web_url`).
- `--jq <expression>`: filter the JSON output of any command with a jq
  expression, without installing `jq` (e.g. `secdb search log4shell --jq
  '.hits[].id'`). It implies `--output=json`; strings are printed without
  quotes, one result per line, and an invalid expression fails before the API
  call.

### Changed

- The SARIF report of `audit linux` and `audit docker` has its own automation
  ID, `secdb-cli/audit-linux` (it was `secdb-cli/audit-purl`, as for the
  PURL-based audits): GitHub Code Scanning shows their alerts in a separate
  category.
- `audit linux` over SSH runs `ssh -vvv` with `--debug` (or `SECDB_DEBUG`), so
  the connection log shows up in the debug output.
- `--debug` (or `SECDB_DEBUG`) logs the effective configuration: the global
  options (whether an API key is set, never the key itself), the audit options
  and the audited target.

### Fixed

- `-o yaml`, `-o template` and `-o html` use the API field names, as `-o json`
  shows them, for every command: before, `audit` and `ssvc calculate` exposed
  the Go names to templates (`{{.PURL}}` instead of `{{.purl}}`) and lowercased
  them in YAML (`basescore` instead of `base_score`).
- The `text` output drops the control characters found in the data (titles and
  descriptions come from third-party feeds), so an escape sequence in a record
  can no longer reach the terminal.
- The template functions `abbrev` and `trunc` count characters, not bytes, so
  they no longer cut a multi-byte character in two.
- Notifications count the findings with no severity as `unknown`: the webhook
  `counts` had an empty `""` key for them, and Slack and Teams left them out,
  so their counts didn't add up to the number of findings in the title.

### Security

- Built with Go 1.26.9 and `golang.org/x/net` v0.60.0, which fix
  vulnerabilities in `net/http`, HTTP/2, `crypto/tls` and `html/template`.

## [0.6.0] - 2026-10-07

### Added

- In CI, the header of the audit `text` report (summary and details) shows
  the CI, project, branch or tag, commit and a link to the run (GitHub Actions,
  GitLab CI, Gitea Actions; any other CI that sets `CI` by name only).

- `--web-url`: the ZEN SecDB web GUI address used for the links in the output
  (CVE/CWE/advisory permalinks, report footer, notifications, LSP diagnostics),
  when it differs from the API `--base-url`, e.g. when the API is reached through
  a proxy (`--base-url https://gateway.example.com/secdb`). It defaults to
  `--base-url`, so nothing changes without it.
- Notifications for the audit commands: pass `--notify` to send a summary of the
  results (overall severity, per-severity counts, up to 20 findings with a count
  of the rest) to one or more providers, configured from the environment:
  - `webhook`: the summary as JSON, POSTed to `SECDB_WEBHOOK_URL` (custom
    receivers, n8n, Zapier, ...);
  - `slack`: a colored attachment, posted to the Slack Incoming Webhook in
    `SECDB_SLACK_WEBHOOK`;
  - `teams`: an Adaptive Card, posted to the Microsoft Teams (Power Automate
    Workflows) webhook in `SECDB_TEAMS_WEBHOOK`.

  `--providers` picks which ones (default: all) and `--notify-on` sets the
  minimum severity that triggers a notification (default: `high`). Delivery is
  best-effort: a failing or unconfigured provider is reported as a warning and
  never fails the command, and webhook URLs are redacted from every error.
  Notifications are independent of `--fail-on`. In GitHub Actions, GitLab CI and Gitea
  Actions the summary also carries the pipeline context (project, branch, commit, run
  link), and the "view details" link points to the CI run.
- `lsp`: the server options can be set from the editor, which matters where the
  editor owns the server command (e.g. Zed). The settings `discovery`,
  `showUnfixed` and `ignoreFile` mirror the flags (and override them), and
  `discoverySummary`/`updateNotice` turn off the two messages. They're read
  from a `secdb` section of the editor's LSP settings (`workspace/configuration`,
  re-read when they change, so no restart is needed) or, flat, from
  `initializationOptions`.
- `lsp`: the server tells you when a newer `secdb` release is available, with a
  "Release notes" button where the editor supports it (same check as the CLI,
  so `SECDB_NO_UPDATE_CHECK` and CI turn it off).
- `lsp`: a `secdb/dependencies` notification with each manifest's dependencies
  and their advisory counts, for clients that build a dependency view (e.g. an
  editor extension). It's sent only to clients that declare the experimental
  capability `secdbDependencies`, first right after parsing (without counts,
  so the list shows up even if the audit fails) and again once the audit is
  done.
- `audit linux` accepts the SSH target as an argument, a shortcut for `--host`,
  `--user` and `--port`: `ssh://[user@]host[:port]`, or the same without the
  `ssh://` prefix (e.g. `secdb audit linux ops@server.example.com:2222`).
- `check-update` shows the release notes of every version newer than the
  installed one (newest first), taken from the `CHANGELOG.md` of the latest
  release, so you see what changes before updating, including the versions in
  between. If the notes can't be fetched, the update message is shown as
  before.

### Changed

- An invalid `--base-url` is now an error (exit status 1) instead of a warning
  followed by a silent fallback to the default instance. The value must be an
  absolute `http`/`https` URL with a host, without credentials, query or
  fragment (e.g. `https://secdb.example.com`). A plain `http` URL still works,
  but prints a warning when an API key is set and the host isn't the local
  machine, since the key would travel unencrypted.
- `check-update` output is now Markdown, rendered on a terminal: when it is
  piped or redirected, the lines are Markdown text (e.g.
  `**A new version is available:** ...`) instead of plain text.

- The audit flags (`--view`, `--fail-on`, `--notify-on`, `--providers`) are now
  validated before any inventory collection or API call, so a typo fails fast
  instead of after the report is printed.
- `--output=sarif` and `--output=csv` are rejected up front outside the `audit`
  commands (previously they failed only after the API call).
- An error no longer prints the full command usage below it, so the message is
  not buried.
- The root help groups the commands by purpose (vulnerability intelligence,
  auditing, integrations, other).
- Severity aliases used by the feeds are normalized: `moderate` is reported as
  `medium` and `important` as `high` in every audit output (text, SARIF, CSV,
  notifications, `--fail-on`), so the same finding always has the same
  severity. `--fail-on` and `--notify-on` accept the aliases too.
- `lsp` now follows the same rules as the audit commands: vulnerabilities with
  no fix available are hidden (`--show-unfixed` to show them), and a finding
  matched by the nearest `.secdbignore` (or `--ignore-file`) is reported as a
  hint with the rule's reason instead of an error or warning.
- `--fail-on` now ends the command through the regular error path: the
  message is printed as `Error: audit failed: ...` and the update notice is no
  longer skipped. The exit status is still `2`.
- An ignore rule with an invalid `expires` date is now an error when the
  ignore file is loaded, instead of a warning repeated for every advisory and
  a rule silently dropped (which re-enabled the finding for `--fail-on`).
- Clearer API errors: a `401` hints at `SECDB_API_KEY`, a `429` says when to
  retry, and an unexpected error response (e.g. a proxy's HTML page) is quoted
  only in part instead of flooding the terminal.

### Deprecated

- `audit purl --sbom`: use `audit sbom --file` instead. The flag still works,
  prints a deprecation warning and is hidden from the help.

### Removed

- The `update` alias of `check-update` (it only checks for a new release, it
  doesn't update) and the `v` alias of `version`.

### Fixed

- `audit manifest` and the LSP reported a Yarn 2+ (berry) `yarn.lock`, or a
  `Gemfile.lock` with CRLF line endings or trailing blanks, as free of
  vulnerabilities: no package was read from it.
- npm and Yarn aliases (`string-width-cjs@npm:string-width`) are audited as the
  real package; workspace, local, git and URL entries are skipped (a workspace
  package was audited as an unrelated npm package named after its path).
- Direct dependencies (LSP `secdb/dependencies`): npm marked hoisted packages
  as direct. Direct now means declared by the project or a workspace
  (`package-lock.json` v2/v3, Yarn 2+) or listed under `DEPENDENCIES`
  (`Gemfile.lock`); the formats that don't record it (`package-lock.json` v1,
  classic `yarn.lock`, `composer.lock`) report none.
- `--fail-on` was ignored with `--output=sarif` and `--output=csv`: the command
  always exited with status `0`, even with findings at or above the threshold.
- A vulnerability that has a fix could be hidden as "unfixed" (and so excluded
  from the report and from `--fail-on`) when another package listed in the same
  advisory had no fix available, e.g. `lodash` because of `lodash.trim`, or
  `openssl` because of `edk2` on Debian. Only the audited package's own
  remediation status is considered now.
- An ignore rule scoped to one package (`package.name`) could accept the whole
  advisory, depending on which affected package came first: the SARIF report
  then suppressed it for every package and notifications dropped it, while
  `--fail-on` still counted the other packages. The rule now applies only to
  the package it names, and the details view lists the packages it accepts.
- An ignore rule's `expires` date was read as UTC midnight, so around midnight
  a rule could stay active a few hours after its day ended (east of UTC, e.g.
  until 02:00 in Italy in summer) or stop a few hours early (west of UTC). The
  date now ends at midnight local time.
- The update check reported "already on the latest version" on the run that
  actually contacted GitHub (the first one, then once every 24 hours), so a
  new release was announced only from the following run. This affected
  `check-update`, the notice printed after the other commands and the `lsp`
  notification.
- `requirements.txt`: a specifier that excludes a version or is only an upper
  bound (`!=1.0`, `<2.0`, `<=2.0`, `>1.0`) was audited as if that version were
  installed. Only `==`/`===` and the lower bound of `>=`/`~=` are audited now,
  also when they come after another specifier (`<5,>=4.2`); a wildcard
  (`==2.*`) is skipped.
- `Gemfile.lock`: gems from a `GIT` or `PATH` source were audited as the
  rubygems.org gem with the same name, so a fork or a local gem got that gem's
  advisories; they are skipped now. A platform-specific gem
  (`nokogiri (1.15.4-x86_64-linux)`) kept the platform in its version and
  matched no advisory; it is audited at its version now.
- `check-update` exited with status 0 when the check failed, and ignored
  `--debug`/`SECDB_DEBUG`.
- `audit docker --image` failed on images with an `ENTRYPOINT` binary, since
  the package-list commands were passed to it as arguments. The image now runs
  with `/bin/sh` as entrypoint, and without network.
- `lsp`: opening a manifest blocked the server until the audit returned (up to
  the 120 s timeout on a slow API). The audit now runs in the background, like
  the one after an edit.

### Security

- The API key could reach another host: after an HTTP redirect to a
  different host or scheme, `X-API-KEY` was sent to the new location (Go only
  strips `Authorization` and `Cookie`), in clear text after a redirect from
  `https` to `http`. It is now dropped on such redirects.
- `--output=csv`: a cell starting with `=`, `+`, `-` or `@` (e.g. an advisory
  title or an ignore reason) could run as a formula when the file was opened
  in a spreadsheet. Such cells now start with `'`.
- `golang.org/x/crypto` upgraded to 0.56.0 (GO-2026-6354, GO-2026-6355). It
  comes in through Sprig's bcrypt, which `secdb` doesn't call.

- `audit docker` rejects an `--image` or `--container` value starting with
  `-`. The name was never passed through a shell, but docker would parse such
  a value as one of its own options (e.g. `--image=--volume=/:/host`), which
  matters when a pipeline takes the image name from untrusted input.

## [0.5.0] - 2026-09-17

### Added

- `audit manifest --directory <DIR>` (`-d`): recursively discover and audit every
  supported manifest under a directory, instead of a single `--file`. Discovery
  prunes noise directories (`.git`, `node_modules`, `vendor`, `target`, `dist`,
  `build`, `testdata`, `site-packages`, ...) and does not follow symlinks;
  `--max-depth` caps how deep the walk descends. A manifest that fails to parse is
  skipped with a warning instead of aborting the scan.
- `lsp`: the Language Server now discovers and audits every supported manifest in
  the workspace on startup, so findings appear without opening each file (files
  already open are audited by the edit path, not twice). Pass `--no-discovery` to
  audit only files as they are opened.
- SARIF export now attributes each finding to its source manifest, with a line
  number where the parser tracks it (`go.mod`, `yarn.lock`, `requirements*.txt`,
  `Gemfile.lock`), for `audit manifest` (including `--directory` scans).

### Changed

- `--base-url` is now validated: a value without a scheme and host is rejected
  with a warning and the default is used instead.
- The HTTP client timeout was raised from 60s to 120s to tolerate slower API
  responses on large audits.

## [0.4.0] - 2026-09-08

### Added

- `audit manifest --file <FILE>`: audit a project's dependency manifest directly.
  The file format is detected by name and its packages are resolved to PURLs and
  checked against ZEN SecDB. Supported today: Go (`go.mod`), npm
  (`package-lock.json`, `yarn.lock`), Python (`requirements*.txt`), Ruby
  (`Gemfile.lock`), Java/Maven (`pom.xml`) and PHP/Composer (`composer.lock`),
  with an extensible engine so more ecosystems can be added.
  Reuses the same `--view`, `--fail-on`, `--ignore-file`, `--show-unfixed` and
  `--output=sarif`/`csv` behavior as `audit purl`.
- `audit sbom --file <FILE>`: audit a CycloneDX BOM (JSON) directly, a `--file`
  front-end for `audit purl --sbom`. The PURLs are collected from the BOM's
  components (recursively) and checked against ZEN SecDB, with the same `--view`,
  `--fail-on`, `--ignore-file`, `--show-unfixed` and `--output=sarif`/`csv`
  behavior as `audit purl`.
- `lsp` command: a Language Server (LSP over stdio) that audits dependency
  manifests against ZEN SecDB as you open and edit them, reporting known
  vulnerabilities inline as editor diagnostics (with a link to the advisory).
  Reuses the same manifest engine as `audit manifest`; the help text carries
  ready-to-paste Kate and Sublime Text configuration snippets.
- `SECDB_DEBUG` environment variable: enable debug logging to stderr (equivalent
  to `--debug`) without passing the flag, handy for enabling it from an editor's
  LSP integration.

## [0.3.1] - 2026-09-03

### Changed

- Internal: the audit render/`--fail-on` pipeline, previously duplicated across
  the `audit purl`, `linux` and `docker` subcommands, is now a single shared
  renderer (no user-facing change).

## [0.3.0] - 2026-09-01

### Added

- `ssvc calculate <CVE-ID...>` command: compute SSVC decisions in bulk following
  the CISA methodology (Track / Track* / Attend / Act), with a decision legend in
  the text report. Reads CVEs from arguments, `--file` or stdin.
- `audit linux` and `audit docker` commands (EXPERIMENTAL): audit the installed
  packages of a Linux system (local or over SSH) or a Docker image/container.
  Collection runs a fixed, read-only command set and supports Debian/Ubuntu,
  the RHEL family, SUSE, Alpine and Slackware.
- SARIF 2.1.0 export for the audit commands (`--output=sarif`), suitable for
  GitHub Code Scanning and other SARIF consumers.
- CSV export of the per-advisory audit details (`--output=csv`) for spreadsheets.
- Accepted-risk ignore file (`.secdbignore`, `--ignore-file`): exclude findings
  from the `--fail-on` exit code (and mark them as suppressed in SARIF) without
  removing them from the report.
- `--fail-on=<severity>`: exit non-zero when a vulnerability at or above the given
  severity is found, for use in CI pipelines.
- `--show-unfixed`: vulnerabilities that have no available fix are hidden by
  default (the report warns how many were hidden); this flag lists them and marks
  each advisory as having no fix available.

### Changed

- The audit details view (`--view=details`) is now one card per advisory,
  severity-sorted and with a provenance footer, instead of a wide table.
- Richer `cve` text report: web permalinks to the SecDB GUI, a References section,
  and prose word-wrapped to the terminal width.
- Audit text reports now lead with a metadata header (input source, packages
  scanned, target) and print progress to stderr only when attached to a terminal.
- Internal: the HTTP client was reorganized and a generic report container now
  backs the text renderers (no user-facing change).

## [0.2.0] - 2026-08-23

### Added

- CycloneDX SBOM input for `audit purl` via `--sbom` (JSON): every package URL in
  the BOM is collected and audited.
- Package URL validation: malformed PURLs are detected and skipped.
- Global `--debug` flag for structured logging to stderr.

## [0.1.0] - 2026-08-17

Initial public release of the ZEN SecDB CLI.

### Added

- `cve <CVE-ID>` command: a curated, human-readable vulnerability report (CVSS,
  weaknesses, affected products and advisories).
- `audit purl <PURL...>` command: audit one or more Package URLs against ZEN
  SecDB, from arguments, `--file` or stdin.
- Output formats: `text` (ANSI-styled Markdown in a terminal), `json`, `yaml`,
  and custom `template`/`html` via Go templates.
- Automatic background update check and a `version` command.

[Unreleased]: https://github.com/giterlizzi/secdb-cli/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/giterlizzi/secdb-cli/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/giterlizzi/secdb-cli/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/giterlizzi/secdb-cli/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/giterlizzi/secdb-cli/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/giterlizzi/secdb-cli/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/giterlizzi/secdb-cli/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/giterlizzi/secdb-cli/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/giterlizzi/secdb-cli/releases/tag/v0.1.0
