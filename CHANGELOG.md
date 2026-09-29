# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
  Notifications are independent of `--fail-on`. In GitHub Actions and GitLab CI
  the summary also carries the pipeline context (project, branch, commit, run
  link), and the "view details" link points to the CI run.
- `audit linux` accepts the SSH target as an argument, a shortcut for `--host`,
  `--user` and `--port`: `ssh://[user@]host[:port]`, or the same without the
  `ssh://` prefix (e.g. `secdb audit linux ops@server.example.com:2222`).

### Changed

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

### Security

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

[Unreleased]: https://github.com/giterlizzi/secdb-cli/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/giterlizzi/secdb-cli/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/giterlizzi/secdb-cli/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/giterlizzi/secdb-cli/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/giterlizzi/secdb-cli/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/giterlizzi/secdb-cli/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/giterlizzi/secdb-cli/releases/tag/v0.1.0
