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

```bash
secdb cve CVE-2021-44228 -o json
secdb cve CVE-2021-44228 -o template --template '{{.severity}}: {{.score}}'
```

`json`, `yaml`, `template` and `html` all work on the API response (for `cve`, with a few summary fields added: `affected_vendors_summary`, `affected_total`, `not_affected_total`), so a template can use any of its fields; `-o json` shows them.

Templates can use the [Sprig](https://masterminds.github.io/sprig/) functions besides the Go built-ins, except `env`, `expandenv` and `getHostByName`: they are removed so that a template from someone else can't read environment variables (such as `SECDB_API_KEY`) or send them over the network. The CLI also adds:

| Function | Description |
|---|---|
| `severity` | A severity as a colored badge, e.g. `🔴 **HIGH**` |
| `ssvc_decision` | An SSVC decision as a colored badge |
| `cve_url`, `cwe_url`, `advisory_url` | The ZEN SecDB page of a CVE, CWE or advisory: `{{cve_url "https://secdb.nttzen.cloud" "CVE-2021-44228"}}` |

`NO_COLOR` set to any value prints the `text` output as plain Markdown in a terminal too.
