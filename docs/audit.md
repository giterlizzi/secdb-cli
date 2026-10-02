# Auditing

The `audit` subcommands check packages against the known vulnerabilities in ZEN SecDB:

| Command | Audits |
|---|---|
| [`audit purl`](#audit-purls) | Package URLs from arguments, a file or stdin |
| [`audit manifest`](#audit-a-dependency-manifest) | A dependency manifest (`go.mod`, `package-lock.json`, ...) or a whole directory |
| [`audit sbom`](#audit-a-cyclonedx-sbom) | A CycloneDX SBOM (JSON) |
| [`audit linux`](#audit-a-linux-system-experimental) | The installed packages of the local machine or a host over SSH |
| [`audit docker`](#audit-a-docker-image-or-container-experimental) | The installed packages of a Docker image or container |

They share the same results pipeline, so [failing the build](#fail-the-build-ci), [SARIF](#sarif-report-eg-for-github-code-scanning) and [CSV](#csv-report-for-spreadsheets) reports, [ignore rules](#ignoring-accepted-risk-findings), [unfixed vulnerabilities](#showing-vulnerabilities-with-no-available-fix) and [notifications](notifications.md) behave the same way for all of them.

## Audit PURLs

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

## Audit a dependency manifest

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

For Python range specifiers that aren't an exact version (`>=2.28`), the leading version is audited; entries with no resolvable version (unpinned Python requirements, Maven versions supplied by a parent POM or an imported BOM, Composer platform requirements like `php`/`ext-*`) are skipped. The npm parser uses the lockfiles' resolved versions, so npm findings reflect what's actually installed. The Maven parser reads a single `pom.xml` and resolves `${...}` properties and versions declared in `<dependencyManagement>`, but does not follow parent POMs or transitive dependencies. Results are shaped and rendered exactly like [`audit purl`](#audit-purls): `--view`, `--fail-on`, `--ignore-file`, `--show-unfixed` and `--output=sarif`/`--output=csv` all behave the same way.

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

## Audit a CycloneDX SBOM

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

## Audit a Linux system (EXPERIMENTAL)

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

## Audit a Docker image or container (EXPERIMENTAL)

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

## Common options

### Fail the build (CI)

Useful in CI pipelines to fail the build when high/critical vulnerabilities are found.

```bash
secdb audit sbom --file bom.json --fail-on=high
```

### SARIF report (e.g. for GitHub Code Scanning)

```bash
secdb audit sbom --file bom.json --output=sarif > results.sarif
```

Produces a [SARIF 2.1.0](https://sarifweb.azurewebsites.net/) report - one rule/result per (advisory, affected package) pair, with severity, CVEs, CWEs and a CVSS-derived `security-severity` score. The artifact location in the report is the audited file (`audit sbom`, `audit manifest`); a plain PURL list (`audit purl`) has no source file, so it is left empty. A finding matched by `--ignore-file` is still included in the report, but carries a SARIF `suppressions` entry (`kind: external`, `status: accepted`, with the rule's `reason` as justification), so consumers like GitHub Code Scanning don't open a new alert for it.

### CSV report (for spreadsheets)

```bash
secdb audit sbom --file bom.json --output=csv > report.csv
```

Emits one row per advisory with the columns `ID, Title, Severity, CVSS, CVEs, CWEs, Packages, URL, Ignored, Ignore Reason`. The list columns (CVEs, CWEs, packages) are flattened into a single cell each, joined by `"; "`, and every text field is quoted per RFC 4180 so commas and quotes in titles/reasons don't break the columns. Like `sarif`, the `csv` output always uses the details shape (the `--view` flag doesn't affect it) and is only supported by the `audit` commands.

**Tips:** The layout is a Go template, so if you need different columns you can supply your own template instead: `--output=template --template-file my-csv.tmpl`.

### Ignoring accepted-risk findings

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
    expires: 2026-12-31 # optional: rule stops applying after this date (inclusive, local time)
```

A rule matches on `vulnerability` (advisory ID or CVE) and, optionally, narrows to a specific `package.name`/`package.version`. It's a no-op if the audit result doesn't already have a matching, non-expired rule. An `expires` value that isn't a valid `YYYY-MM-DD` date is an error: the command stops instead of silently dropping the rule.

### Showing vulnerabilities with no available fix

An advisory can affect a package for which no fix has been released yet (CSAF remediation status `none_available`). By default these "unfixed" findings are **hidden** from every view (`summary`, `details`, `sarif`, `csv`) and excluded from the `--fail-on` check, so the report focuses on actionable vulnerabilities. When any are hidden, the `--output=text` header shows a warning row with their count:

```
Unfixed: ⚠️ 98 hidden (run with --show-unfixed to list them)
```

Pass `--show-unfixed` to include them; in the `details` view each such advisory is marked `Fix: ❌ No fix available for the affected package`.

```bash
secdb audit sbom --file bom.json --show-unfixed
```
