# Search

`secdb search` runs a full-text search across ZEN SecDB: CVEs, CWEs, security
advisories, NASL plugins and ExploitDB entries.

```bash
secdb search log4j
```

## Query

The arguments are joined into one query, and every term must match:

```bash
secdb search gitea xss          # records about both gitea and xss
```

A term prefixed with `-` is excluded. Put it after `--`, otherwise it's read as
a flag:

```bash
secdb search log4j -- -maven    # log4j, without the records that mention maven
```

`OR` between terms matches either side. `AND` binds tighter, so `a b OR c` is
`(a AND b) OR c`; parentheses aren't supported:

```bash
secdb search xss OR csrf             # records about xss, csrf or both
secdb search log4j xss OR csrf       # log4j and xss, or csrf
```

An exact phrase goes in double quotes. Wrap it in single quotes so the shell
passes the double quotes on:

```bash
secdb search '"remote code execution"'           # the words in this order
secdb search log4j -- '-"remote code execution"' # log4j, without the phrase
```

A term can target a field:

| Term | Matches |
|---|---|
| `CVE-2021-44228` (same as `cve:CVE-2021-44228`) | every record about that CVE: the CVE itself, advisories, NASL plugins, exploits |
| `CWE-79` (same as `cwe:CWE-79`) | every record classified with that CWE |
| `title:"remote code execution"` | the phrase in the title (also `description:`) |
| `id:CVE-2021-44228` | the record with that id; for an id with a prefix, quote it: `id:"MS:CVE-2021-44228"` |
| `type:cve` | only CVEs (same as `--type cve`) |

CVE and CWE ids are case-insensitive. Like any term, several ids must all match:

```bash
secdb search CVE-2021-44228 --type advisory      # the advisories about Log4Shell
secdb search CVE-2021-44228 CVE-2022-22965       # records about both CVEs
secdb search CVE-2021-44228 OR CVE-2021-45046    # records about either CVE
secdb search log4j -- -CVE-2021-44228            # log4j, but not about Log4Shell
```

For the full report of one CVE, use [`secdb cve`](../README.md#look-up-a-cve).

## Options

| Flag | Description |
|---|---|
| `--type` | Only these record types, comma-separated: `cve`, `cwe`, `advisory`, `nasl`, `exploitdb` |
| `--since` | Only the records modified within this window: a number followed by `d` (days), `w` (weeks), `m` (months) or `y` (years), e.g. `30d`, `2w`, `6m`, `1y` |
| `--page` | Page number (default 1) |
| `--per-page` | Results per page (default 100) |

```bash
secdb search gitea xss --type cve,advisory --since 30d
secdb search apache --page 2 --per-page 50
```

## Output

The `text` output lists one result per line: severity, type, id, the well-known
name (such as `Log4Shell`), a 🔥 **KEV** mark for the CVEs in the CISA Known
Exploited Vulnerabilities catalog and the title, then the start of the
description, the last-modified date and the link to the record in the ZEN SecDB
web GUI (`--web-url`, see [Configuration](../README.md#configuration)).
A footer shows how many results there are, the page, the option for the next
page, and the results by type and by severity (the feeds' severity names, such
as `moderate` or `important`, are counted under `medium` and `high`).

`json` and `yaml` print the results (`hits`), the result counts by type,
severity and source (`facets`) and the paging state (`pagination`):

```json
{
  "hits": [ { "type": "cve", "id": "CVE-2021-44228", "alias": "Log4Shell", "kev": true, "...": "..." } ],
  "facets": { "type": { "advisory": 267, "cve": 29 } },
  "pagination": { "total": 713, "total_pages": 8, "page": 1, "per_page": 100, "next_page": 2 }
}
```

A result has only the fields that apply to its type: `type`, `id`, `title`,
`source`, `web_url` and `api_url` always, then `description`, `summary`,
`severity`, `published`, `modified`, `cve` and `cwe` (lists of ids) where
available; a CVE also has `status`, `cvss_score`, `attack_vector`, `alias` (a
well-known name, such as `Log4Shell`) and `kev` (in the CISA Known Exploited
Vulnerabilities catalog). `_score` is the relevance of the result to the query.

`web_url` (the record's page in the web GUI) and `api_url` (the full record in
the API) are paths without the server, to append to the web GUI and API
addresses: `/cve/detail/CVE-2021-44228` and `/api/v1/feed/cve/CVE-2021-44228`
become `https://secdb.nttzen.cloud/cve/detail/CVE-2021-44228` and so on. Append
them, keeping any path the address has (a gateway at
`https://gateway.example.com/secdb` gives
`https://gateway.example.com/secdb/cve/detail/…`); in a template, `path_url`
does it.

`next_page` is absent on the last page. To fetch every page in a script, loop
until it's missing:

```bash
page=1
while [ -n "$page" ]; do
  secdb search log4j --type cve --page "$page" -o json > "page-$page.json"
  page=$(jq -r '.pagination.next_page // empty' "page-$page.json")
done
```

Requests without `SECDB_API_KEY` get a lower rate limit; a long loop may hit it
(`rate limit exceeded (retry in Ns)`).
