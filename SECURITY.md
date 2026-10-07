# Security Policy

## Supported versions

Security fixes go into the latest release only. `secdb check-update` tells you
whether a newer one is available.

## Reporting a vulnerability

Please don't open a public issue. Use GitHub's
[private vulnerability reporting](https://github.com/giterlizzi/secdb-cli/security/advisories/new)
instead, with the `secdb version` output, the command you ran and how to
reproduce the problem (remove any API key, token or webhook URL first).

This is a personal open source project: reports are handled on a best-effort
basis, and a confirmed issue is fixed in a new release with a GitHub Security
Advisory.

## Scope

This policy covers the `secdb` CLI and its Language Server, i.e. the code in
this repository. Not in scope:

- the ZEN SecDB service (API and web GUI), and the vulnerability data it returns:
  report those to the operator of the service;
- a CVE in a dependency, unless you show that `secdb` can actually reach the
  vulnerable code (e.g. with [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck)
  or a proof of concept).
