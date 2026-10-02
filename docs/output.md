# Output formats

Supports `-o` / `--output`:

| Format | Description |
|---|---|
| `text` *(default)* | Curated Markdown report, rendered with ANSI styling in a terminal, printed raw when piped/redirected |
| `yaml` | Raw API response as YAML |
| `json` | Raw API response as JSON |
| `template` | Custom [Go template](https://pkg.go.dev/text/template) via `--template` (inline) or `--template-file` |
| `html` | Custom HTML via `--template`/`--template-file`, rendered with `html/template` (safe escaping) |
| `sarif` | SARIF 2.1.0 report (`audit` commands only, see [Auditing](audit.md#sarif-report-eg-for-github-code-scanning)) |
| `csv` | CSV of the per-advisory audit details, one row per advisory (`audit` commands only, see [Auditing](audit.md#csv-report-for-spreadsheets)) |

```bash
secdb cve CVE-2021-44228 -o json
secdb cve CVE-2021-44228 -o template --template '{{.severity}}: {{.score}}'
```

Templates have access to [Sprig](https://masterminds.github.io/sprig/) functions (string manipulation, math, lists, dates, ...) in addition to the Go template built-ins. The `env`, `expandenv`, and `getHostByName` functions are disabled to prevent untrusted templates from reading environment variables (e.g. `SECDB_API_KEY`) or exfiltrating data over the network.
