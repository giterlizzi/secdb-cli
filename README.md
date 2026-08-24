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

| Environment variable    | Purpose                                                                |
|-------------------------|------------------------------------------------------------------------|
| `SECDB_API_KEY`         | API key sent as the `X-API-KEY` header on every request                |
| `SECDB_NO_UPDATE_CHECK` | Set to any value to disable the background update check                |
| `NO_COLOR`              | Print raw Markdown instead of ANSI-styled `text` output                |
| `CI`                    | Automatically disables the background update check when set            |

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
| `sarif` | SARIF 2.1.0 report (`audit purl` only, see below) |

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
syft packages dir:. -o cyclonedx-json > bom.json && secdb audit purl --sbom bom.json
cdxgen -o bom.json . && secdb audit purl --sbom bom.json
```

**CI**

Useful in CI pipelines to fail the build when high/critical vulnerabilities are found.

```bash
secdb audit purl --sbom bom.json --fail-on=high
```

**SARIF report (e.g. for GitHub Code Scanning)**

```bash
secdb audit purl --sbom bom.json --output=sarif > results.sarif
```

Produces a [SARIF 2.1.0](https://sarifweb.azurewebsites.net/) report — one rule/result per (advisory, affected package) pair, with severity, CVEs, CWEs and a CVSS-derived `security-severity` score. The artifact location in the report comes from `--sbom`, so pair `--output=sarif` with `--sbom` for a meaningful report; without `--sbom` the artifact location is left empty. `--output=sarif` is only supported by `audit purl`. A finding matched by `--ignore-file` is still included in the report, but carries a SARIF `suppressions` entry (`kind: external`, `status: accepted`, with the rule's `reason` as justification), so consumers like GitHub Code Scanning don't open a new alert for it.

**Ignoring accepted-risk findings**

```bash
secdb audit purl --sbom bom.json --fail-on=high --ignore-file=.secdbignore
```

`--ignore-file` (default: `.secdbignore`) points to a YAML file of accepted-risk rules. A matching rule never hides a finding from the report — it only excludes it from the `--fail-on` exit-code check (and, for `--output=sarif`, marks the result as suppressed instead of removing it):

```yaml
ignore:
  - vulnerability: CVE-2021-44228
    reason: "Not reachable in our usage of this library"

  - vulnerability: CVE-2024-33333
    reason: "Fixed upstream, upgrade planned"
    package:
      name: some-package
      version: 1.0.0   # optional: without it, the rule matches every version of the package
    expires: 2026-12-31 # optional: rule stops applying after this date (inclusive)
```

A rule matches on `vulnerability` (advisory ID or CVE) and, optionally, narrows to a specific `package.name`/`package.version`. It's a no-op if the audit result doesn't already have a matching, non-expired rule.

Package URLs ([PURLs](https://github.com/package-url/purl-spec)) can be passed as arguments, read from a file with `--file`/`-f` (one PURL per line, `#` for comments), from CycloneDX `--sbom` file, or piped via stdin.

| Flag | Description |
|---|---|
| `-f`, `--file` | Read PURLs from a file instead of arguments/stdin |
| `--sbom` | Read PURLs from CycloneDX SBOM file (JSON) instead of arguments/stdin/file |
| `-v`, `--view` | `summary` *(default)* — one row per package, or `details` — one row per advisory (only applies to `--output=text`) |
| `--fail-on` | Exit with status `2` if any package has a vulnerability at or above the given severity (`critical`, `high`, `medium`, `low`, `info`) |
| `--ignore-file` | YAML file of accepted-risk rules that exclude matching findings from `--fail-on` (default `.secdbignore`) |

### Calculate SSVC (bulk)

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

CVE identifiers can be passed as arguments, read from a file with `--file`/`-f` (one CVE per line, `#` for comments), or piped via stdin — same precedence as `audit purl`: arguments, then `--file`, then stdin. Duplicate CVEs are deduplicated; a CVE that can't be found still appears in the report with its status instead of failing the whole batch.

| Flag | Description |
|---|---|
| `-f`, `--file` | Read CVEs from a file instead of arguments/stdin |
| `--mission-prevalence` | *(required)* `minimal`, `support`, or `essential` |
| `--public-well-being-impact` | *(required)* `minimal`, `material`, or `irreversible` |

### Check for a new version

```bash
secdb check-update   # alias: secdb update
```

A lightweight background check also runs automatically on every command (cooldown: 24h, silent on failure, skipped in CI or with `SECDB_NO_UPDATE_CHECK` set).

## License

[Apache License 2.0](LICENSE).

Third-party dependency attributions are listed in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
