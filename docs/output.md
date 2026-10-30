# Output formats

`-o` / `--output` selects the format:

| Format | Description |
|---|---|
| `text` *(default)* | A Markdown report, rendered with colors in a terminal and printed as plain Markdown when piped or redirected |
| `json` | The API response as JSON |
| `yaml` | The API response as YAML |
| `template` | Your own [Go template](https://pkg.go.dev/text/template), from `--template` (inline) or `--template-file` |
| `html` | Like `template`, but executed with `html/template`, which escapes the values for HTML |
| `sarif` | SARIF 2.1.0, `audit` commands only (see [Auditing](audit.md#sarif)) |
| `csv` | One row per advisory, `audit` commands only (see [Auditing](audit.md#csv)) |
| `defectdojo` | DefectDojo Generic Findings Import, `audit` commands only (see [Auditing](audit.md#defectdojo)) |
| `cyclonedx` | CycloneDX 1.6 vulnerability report, `audit` commands only (see [Auditing](audit.md#cyclonedx)) |

```bash
secdb cve CVE-2021-44228 -o json
secdb cve CVE-2021-44228 -o template --template '{{.severity}}: {{.score}}'
```

`json`, `yaml`, `template` and `html` all work on the API response (for `cve`, with a few summary fields added: `affected_vendors_summary`, `affected_total`, `not_affected_total`; for `search`, a `pagination` object), so a template can use any of its fields; `-o json` shows them.

Templates can use the [Sprig](https://masterminds.github.io/sprig/) functions besides the Go built-ins, except `env`, `expandenv` and `getHostByName`: they are removed so that a template from someone else can't read environment variables (such as `SECDB_API_KEY`) or send them over the network. The CLI also adds:

| Function | Description |
|---|---|
| `severity` | A severity as a colored badge, e.g. `🔴 **HIGH**` |
| `ssvc_decision` | An SSVC decision as a colored badge |
| `cve_url`, `cwe_url`, `advisory_url` | The ZEN SecDB page of a CVE, CWE or advisory: `{{cve_url "https://secdb.nttzen.cloud" "CVE-2021-44228"}}` |
| `path_url` | A ZEN SecDB page from a path the API returns, such as a search hit's `web_url`: `{{path_url "https://secdb.nttzen.cloud" .web_url}}` |

## Filtering JSON with `--jq`

`--jq` filters the JSON output with a [jq](https://jqlang.org/manual/) expression, without installing `jq`. It implies `-o json` (with any other `--output` it's an error), and works with every command that prints JSON:

```bash
# One search hit id per line
secdb search log4shell --jq '.hits[].id'

# The date a CVE entered the CISA KEV catalog
secdb cve CVE-2021-44228 --jq '.cisa_kev.added_date // "not in KEV"'

# The advisories of an audit with a CVE in the CISA KEV catalog
secdb audit purl pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1 --jq '.[].advisories[] | select(.cisa_kev | length > 0) | .id'

# The advisories of an audit, as severity and id
secdb audit purl pkg:npm/lodash@4.17.20 --jq '.[].advisories[] | "\(.severity)\t\(.id)"'

# Page through all the results: the next page, empty on the last one
secdb search apache --jq '.pagination.next_page // empty'
```

Each result is printed on its own line: a string as is, without quotes (like `jq -r`), anything else as indented JSON. The expression sees the same field names as `-o json`, and an invalid one fails before the API is called. An expression can't read environment variables (`env` and `$ENV` are empty), so one copied from someone else can't print `SECDB_API_KEY`.

With the `audit` commands, `--fail-on` still applies: the command prints the filtered output, then exits with status 2 when the threshold is reached.

`NO_COLOR` set to any value prints the `text` output as plain Markdown in a terminal too.
