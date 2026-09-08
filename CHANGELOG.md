# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/giterlizzi/secdb-cli/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/giterlizzi/secdb-cli/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/giterlizzi/secdb-cli/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/giterlizzi/secdb-cli/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/giterlizzi/secdb-cli/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/giterlizzi/secdb-cli/releases/tag/v0.1.0
