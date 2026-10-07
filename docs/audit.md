# Auditing

The `audit` subcommands check packages against the vulnerabilities known to ZEN SecDB:

| Command | Audits |
|---|---|
| [`audit purl`](#audit-purls) | Package URLs from arguments, a file or stdin |
| [`audit manifest`](#audit-a-dependency-manifest) | A dependency manifest (`go.mod`, `package-lock.json`, ...) or every manifest under a directory |
| [`audit sbom`](#audit-a-cyclonedx-sbom) | A CycloneDX SBOM (JSON) |
| [`audit linux`](#audit-a-linux-system-experimental) | The installed packages of the local machine or of a host over SSH |
| [`audit docker`](#audit-a-docker-image-or-container-experimental) | The installed packages of a Docker image or container |

All of them accept the [common options](#common-options): `--view`, `--fail-on`, `--ignore-file`, `--show-unfixed`, the SARIF and CSV output and the [notifications](notifications.md).

## Audit PURLs

```bash
# From arguments
secdb audit purl pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1

# From a file, one PURL per line ("#" starts a comment)
secdb audit purl --file=purls.txt

# From stdin
secdb audit purl < purls.txt
command | secdb audit purl
```

[Package URLs](https://github.com/package-url/purl-spec) are read from the arguments, else from `--file`/`-f`, else from stdin. Invalid PURLs are skipped and duplicates are removed. For a CycloneDX SBOM use [`audit sbom`](#audit-a-cyclonedx-sbom).

In `text` output the report starts with a short header: where the PURLs came from (arguments, file or stdin) and how many were scanned. The header is not part of the `json`, `yaml` or `sarif` output.

| Flag | Description |
|---|---|
| `-f`, `--file` | Read the PURLs from a file instead of the arguments or stdin |
| `--sbom` | *(deprecated, use [`audit sbom --file`](#audit-a-cyclonedx-sbom))* Read the PURLs from a CycloneDX SBOM (JSON) |

## Audit a dependency manifest

Reads a dependency manifest, turns its packages into PURLs and audits them. The format is chosen by file name. Use `--file` for a single manifest, or `--directory` to find and audit every supported manifest under a directory.

```bash
secdb audit manifest --file go.mod
secdb audit manifest --file package-lock.json
secdb audit manifest --file requirements.txt --view details
secdb audit manifest --file Gemfile.lock --fail-on=high

# Every manifest under a directory
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

What gets audited:

- npm, Ruby and Composer: the versions resolved in the lockfile, i.e. what is actually installed.
- Ruby: only the gems from a gem server (the `GEM` sections of `Gemfile.lock`). Gems from a git repository or a local path (`GIT`, `PATH`) are skipped, since they may be a fork or an unrelated gem with the same name as a public one. A platform-specific gem (`nokogiri (1.15.4-x86_64-linux)`) is audited at its version (1.15.4).
- Python: the version written in the requirement: the exact one (`==2.28.0`), otherwise the lower bound of `>=` or `~=` (`>=2.28` audits 2.28). A requirement with only `!=`, `<`, `<=`, `>`, a wildcard (`==2.*`) or no version is skipped.
- Maven: a single `pom.xml`. `${...}` properties and the versions in `<dependencyManagement>` are resolved; parent POMs, imported BOMs and transitive dependencies are not, so a dependency whose version comes from them is skipped.
- Composer platform requirements (`php`, `ext-*`) are skipped.

With `--directory`, the walk skips directories such as `.git`, `node_modules`, `vendor`, `target`, `dist`, `build` and `testdata`, and does not follow symlinks. A manifest that can't be parsed is skipped with a warning. All the dependencies found go into a single report.

| Flag | Description |
|---|---|
| `-f`, `--file` | The manifest to audit (excludes `--directory`) |
| `-d`, `--directory` | Audit every manifest under this directory (excludes `--file`) |
| `--max-depth` | How many directory levels to descend with `--directory` (`0` = no limit) |

## Audit a CycloneDX SBOM

Collects the PURLs of a CycloneDX BOM (JSON), including nested components, and audits them. It replaces `audit purl --sbom`, which still works and gives the same output.

```bash
secdb audit sbom --file bom.json

# Generate the SBOM, then audit it
syft packages dir:. -o cyclonedx-json > bom.json && secdb audit sbom --file bom.json
cdxgen -o bom.json . && secdb audit sbom --file bom.json
```

| Flag | Description |
|---|---|
| `-f`, `--file` | *(required)* The CycloneDX SBOM (JSON) to audit |

## Audit a Linux system (EXPERIMENTAL)

Audits the installed packages of a Linux system: the local machine by default (only on Linux), or a remote host over SSH. For Docker images and containers see [`audit docker`](#audit-a-docker-image-or-container-experimental).

```bash
# Local machine
secdb audit linux

# Remote host
secdb audit linux --host server.example.com --user ops
secdb audit linux ssh://ops@server.example.com:2222
```

The `ssh://user@host:port` argument (the `ssh://` prefix is optional) is a shorthand for `--host`, `--user` and `--port`, and takes precedence over them. The connection uses your `ssh` client, so `~/.ssh/config`, the SSH agent and `known_hosts` apply, and host keys are always checked.

On the target the command runs only read-only commands: `cat /etc/os-release`, `uname -m` and the package list of the distribution (`dpkg-query`, `rpm`, `apk`, or `/var/log/packages` on Slackware). Supported distributions: Debian, Ubuntu, RHEL, Rocky Linux, AlmaLinux, Oracle Linux, Amazon Linux, Fedora, SUSE, Alpine and Slackware.

The `text` report starts with the target (`local`, `user @ host:port`, or the Docker image or container), the OS and version, the architecture and the number of packages. While it works, the command prints `Detected ...` and `Auditing ...` on stderr, only when stderr is a terminal.

| Flag | Description |
|---|---|
| `--host` | Remote host to audit over SSH (default: the local machine) |
| `--user`, `--port` | SSH user and port |
| `--identity-file` | SSH private key |
| `--ssh-config` | SSH config file; when set, the host key policy is the one in that file |
| `--sudo` | Run the package list with `sudo -n` |

## Audit a Docker image or container (EXPERIMENTAL)

Audits the installed packages of a Docker image or of a running container. The `docker` CLI must be installed and able to reach the daemon.

```bash
secdb audit docker --image debian:12
secdb audit docker --container my-running-container
```

With `--image` the commands run in a temporary container (`docker run --rm`, pulling the image if needed), with no network and with `/bin/sh` in place of the image's entrypoint. With `--container` they run in the existing container (`docker exec`). Commands, supported distributions and report are the same as for `audit linux`.

| Flag | Description |
|---|---|
| `--image` | Docker image to audit |
| `--container` | Running Docker container to audit |

Exactly one of the two is required.

## Common options

| Flag | Description |
|---|---|
| `-v`, `--view` | `summary` *(default)*, one row per package, or `details`, one card per advisory. Only for `text` output |
| `--fail-on` | Exit with status `2` when a vulnerability is at or above this severity (`critical`, `high`, `medium`, `low`, `info`) |
| `--ignore-file` | YAML file of [accepted risks](#accepted-risks-secdbignore) (default `.secdbignore`) |
| `--show-unfixed` | Also report the vulnerabilities [with no fix](#vulnerabilities-with-no-fix) |
| `--notify`, `--providers`, `--notify-on` | Send the result to Slack, Teams or a webhook, see [Notifications](notifications.md) |

When the audit runs in CI, the header of the `text` report also says where: the CI, the project, the branch or tag with the commit, and a link to the run. Project, branch and link are known for GitHub Actions, GitLab CI and Gitea Actions; another CI that sets `CI` is shown only by name.

### Fail the build

```bash
secdb audit sbom --file bom.json --fail-on=high
```

The report is printed first, in any output format, then the command exits with status `2` if a vulnerability reaches the threshold. Findings accepted in the ignore file and hidden unfixed vulnerabilities don't count. Any other error exits with `1`.

### SARIF

```bash
secdb audit sbom --file bom.json --output=sarif > results.sarif
```

Writes a [SARIF 2.1.0](https://sarifweb.azurewebsites.net/) report for GitHub Code Scanning and similar tools: one rule and one result for each (advisory, package) pair, with severity, CVEs, CWEs and a `security-severity` score taken from CVSS.

Each result points at what was audited: the SBOM file for `audit sbom`, the manifest file and line for `audit manifest` (also with `--directory`), `OS/version` for `audit linux` and `audit docker`. `audit purl` has no file, so the location is empty.

A finding accepted in the ignore file stays in the report with a `suppressions` entry (`kind: external`, `status: accepted`, the rule's `reason` as justification), so Code Scanning doesn't open an alert for it.

### CSV

```bash
secdb audit sbom --file bom.json --output=csv > report.csv
```

One row per advisory, with the columns `ID, Title, Severity, CVSS, CVEs, CWEs, Packages, URL, Ignored, Ignore Reason`. CVEs, CWEs and packages are joined with `"; "` in a single cell, and the text cells are quoted as in RFC 4180. A cell that starts with `=`, `+`, `-` or `@` gets a leading `'`, so a spreadsheet doesn't run it as a formula. `--view` has no effect on it.

The columns are fixed. A custom layout can be written with `--output=template --template-file my.tmpl`, but note that the template receives the raw API response (one item per package with its `advisories`), not the per-advisory rows of the CSV.

### Accepted risks (.secdbignore)

```bash
secdb audit sbom --file bom.json --fail-on=high --ignore-file=path/to/.secdbignore
```

The ignore file (default `.secdbignore` in the current directory, silently skipped when missing) lists the findings you have accepted:

```yaml
ignore:
  - vulnerability: CVE-2021-44228
    reason: "Not reachable in our usage of this library"

  - vulnerability: CVE-2024-33333
    reason: "Fixed upstream, upgrade planned"
    package:
      name: some-package
      version: 1.0.0    # optional: without it, every version of the package matches
    expires: 2026-12-31 # optional: the rule applies through this day (local time)
```

A rule matches an advisory by its ID or by one of its CVEs. With `package` it matches only that package: `name` is compared with the PURL name, without namespace or type, so `name: core` matches both `@angular/core` and `@babel/core`.

An accepted finding is not removed from the report. It is:

- left out of `--fail-on` and of the notifications;
- marked as suppressed in SARIF, and as `Ignored` in CSV and in the `details` view, with the reason;
- shown as a hint, instead of an error or warning, by the [editor integration](lsp.md).

The rules are checked per package: when an advisory affects several packages and a rule accepts only some of them, the others still count.

An `expires` that isn't a valid `YYYY-MM-DD` date is an error, so a typo can't silently turn a rule off.

### Vulnerabilities with no fix

Some advisories affect a package for which no fix exists yet (CSAF remediation `none_available`). By default these are hidden from every view (`summary`, `details`, `sarif`, `csv`) and don't count for `--fail-on`. When some are hidden, the `text` header says how many:

```
Unfixed: ⚠️ 98 hidden (run with --show-unfixed to list them)
```

`--show-unfixed` includes them; in the `details` view each one is marked `Fix: ❌ No fix available for the affected package`.

```bash
secdb audit sbom --file bom.json --show-unfixed
```
