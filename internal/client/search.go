// SPDX-License-Identifier: Apache-2.0

package client

import (
	"maps"
	"net/url"
	"strconv"
)

// SearchTypes are the record types the search can be narrowed to (the API's
// `type` parameter, a comma-separated list of these).
var SearchTypes = []string{"cve", "cwe", "advisory", "nasl", "exploitdb"}

// SearchHit is one document returned by a search. The fields depend on the
// record type: a cve carries status, CVSS, attack vector, CWEs, alias and KEV;
// a cwe has no dates nor severity; an exploitdb entry has no description.
type SearchHit struct {
	Type         string   `json:"type"`
	ID           string   `json:"id"`
	Title        string   `json:"title"`
	Alias        string   `json:"alias,omitempty"` // a well-known name, e.g. Log4Shell
	Summary      string   `json:"summary,omitempty"`
	Description  string   `json:"description,omitempty"`
	Severity     string   `json:"severity,omitempty"`
	Source       string   `json:"source,omitempty"`
	WebURL       string   `json:"web_url,omitempty"` // GUI page, a path to append to the web URL: /cve/detail/{id}
	APIURL       string   `json:"api_url,omitempty"` // full record, a path to append to the base URL: /api/v1/feed/cve/{id}
	Published    string   `json:"published,omitempty"`
	Modified     string   `json:"modified,omitempty"`
	Status       string   `json:"status,omitempty"` // e.g. analyzed, modified
	KEV          bool     `json:"kev,omitempty"`    // in the CISA KEV catalog
	CVSSScore    float64  `json:"cvss_score,omitempty"`
	AttackVector string   `json:"attack_vector,omitempty"`
	CVEs         []string `json:"cve,omitempty"`
	CWEs         []string `json:"cwe,omitempty"`
	Score        float64  `json:"_score,omitempty"`
}

// SearchPagination is the paging state, read from the X-* response headers.
type SearchPagination struct {
	Total      int `json:"total"`
	TotalPages int `json:"total_pages"`
	Page       int `json:"page"`
	PerPage    int `json:"per_page"`
	NextPage   int `json:"next_page,omitempty"`
}

// SearchResult is a page of search hits, with the pagination the API returns
// in headers. The json tags are also the field names of the search command's
// json/yaml/template output.
type SearchResult struct {
	Hits       []SearchHit               `json:"hits"`
	Facets     map[string]map[string]int `json:"facets"` // hit counts by type, severity and source
	Pagination SearchPagination          `json:"pagination"`
}

// Search runs the full-text query q, narrowed by params (type, since, page,
// per_page), and returns one page of hits.
func (c *Client) Search(q string, params url.Values) (*SearchResult, error) {
	// A copy, so the caller's params are left as they are.
	params = maps.Clone(params)
	if params == nil {
		params = url.Values{}
	}
	params.Set("q", q)

	res, err := c.get("/api/v1/search?" + params.Encode())
	if err != nil {
		return nil, err
	}

	result, err := decodeJSON[SearchResult](res)
	if err != nil {
		return nil, err
	}

	atoi := func(name string) int {
		n, _ := strconv.Atoi(res.header.Get(name))
		return n
	}
	result.Pagination = SearchPagination{
		Total:      atoi("X-Total"),
		TotalPages: atoi("X-Total-Pages"),
		Page:       atoi("X-Page"),
		PerPage:    atoi("X-Per-Page"),
		NextPage:   atoi("X-Next-Page"),
	}
	return &result, nil
}
