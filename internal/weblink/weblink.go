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

// Path returns the permalink to a web-GUI page the API already built, such as
// a search hit's web_url (e.g. "/cve/detail/CVE-2021-44228"); empty when link
// is. Only the path and query of link are kept, whether the API sent a path or
// an absolute URL, so the permalink always follows webURL (--web-url).
func Path(webURL, link string) string {
	if link == "" {
		return ""
	}
	u, err := url.Parse(link)
	if err != nil {
		return join(webURL, link)
	}
	p := join(webURL, u.Path)
	if u.RawQuery != "" {
		p += "?" + u.RawQuery
	}
	return p
}
