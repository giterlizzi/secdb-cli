// SPDX-License-Identifier: Apache-2.0

// Package weblink builds the permalinks to the ZEN SecDB web GUI pages. Each
// function takes the web-GUI base URL (client.WebURL(), which may carry a path)
// and the record id.
package weblink

import "net/url"

func join(webURL string, path ...string) string {
	u, _ := url.JoinPath(webURL, path...)
	return u
}

// CVE returns the permalink to a CVE detail page.
func CVE(webURL, id string) string {
	return join(webURL, "cve", "detail", id)
}

// CWE returns the permalink to a CWE detail page.
func CWE(webURL, id string) string {
	return join(webURL, "cwe", "detail", id)
}

// Advisory returns the permalink to a security advisory detail page.
func Advisory(webURL, id string) string {
	return join(webURL, "security-advisory", "detail", id)
}
