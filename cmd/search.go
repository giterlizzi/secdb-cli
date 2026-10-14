// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"maps"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/giterlizzi/secdb-cli/internal/audit"
	"github.com/giterlizzi/secdb-cli/internal/client"
	"github.com/giterlizzi/secdb-cli/internal/output"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/spf13/cobra"
)

var (
	searchType    string
	searchSince   string
	searchPage    int
	searchPerPage int
)

var searchCmd = &cobra.Command{
	Use:     "search <query>...",
	GroupID: groupIntel,
	Short:   "Full-text search across ZEN SecDB (CVE, CWE, advisories, ...)",
	Long: heredoc.Doc(`
		Full-text search across ZEN SecDB: CVEs, CWEs, security advisories, NASL
		plugins and ExploitDB entries. The arguments are joined into one query, and
		every term must match. Prefix a term with "-" to exclude it, after "--" so
		it isn't read as a flag: secdb search log4j -- -maven. OR between terms
		matches either side (AND binds tighter: a b OR c is (a AND b) OR c). An
		exact phrase goes in double quotes, inside single quotes so the shell
		keeps them: secdb search '"remote code execution"'.

		A CVE or CWE id finds every record about it (CVE-2021-44228 is the same as
		cve:CVE-2021-44228, CWE-79 as cwe:CWE-79). Other fields: id:CVE-2021-44228
		finds a record by its id, type:cve narrows the record type (same as --type).

		Narrow the scope with --type, keep only the records modified recently with
		--since, and page through the results with --page/--per-page. The text
		output links each result to the ZEN SecDB web GUI; --output json/yaml prints
		the hits and facets with a "pagination" object (total, page, per_page,
		total_pages, next_page).
	`),
	Example: heredoc.Doc(`
		Simple:
			secdb search log4j

		Both terms, only CVEs and advisories modified in the last 30 days:
			secdb search gitea xss --type cve,advisory --since 30d

		Excluding a term:
			secdb search log4j -- -maven

		Either term:
			secdb search xss OR csrf

		An exact phrase, in the title only:
			secdb search 'title:"remote code execution"'

		The advisories about a CVE:
			secdb search CVE-2021-44228 --type advisory

		A record by its id:
			secdb search id:CVE-2021-44228

		Second page of 50 results, as JSON:
			secdb search apache --page 2 --per-page 50 --output json
	`),
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		term, params, err := searchRequest(cmd, args)
		if err != nil {
			return err
		}

		secdb := newSecDbClient()
		result, err := secdb.Search(term, params)
		if err != nil {
			return fmt.Errorf("search: %w", err)
		}

		if outputFormat == "text" {
			return output.RenderText(os.Stdout, newSearchReport(result, secdb.WebURL()), "search")
		}

		return output.Render(os.Stdout, result, output.Format(outputFormat), newOutputOptions())
	},
}

// searchReport is the data of the search text template: the result page, the
// web-GUI base URL for the permalinks and the facets as sorted counts.
type searchReport struct {
	*client.SearchResult
	BaseURL    string
	Types      []facetCount
	Severities []facetCount
}

// facetCount is one value of a facet and its number of hits.
type facetCount struct {
	Name  string
	Count int
}

// searchRequest validates the query and the flags and returns them as the
// query and parameters of the search request, before any API call.
func searchRequest(cmd *cobra.Command, args []string) (string, url.Values, error) {
	term := strings.TrimSpace(strings.Join(args, " "))
	if len(term) < 3 {
		return "", nil, errors.New("search query must be at least 3 characters long")
	}

	params := url.Values{}

	types, err := searchTypes(searchType)
	if err != nil {
		return "", nil, err
	}
	if types != "" {
		params.Set("type", types)
	}

	since, err := searchDuration(searchSince)
	if err != nil {
		return "", nil, err
	}
	if since != "" {
		params.Set("since", since)
	}

	if cmd.Flags().Changed("page") {
		if searchPage < 1 {
			return "", nil, errors.New("invalid --page (must be 1 or more)")
		}
		params.Set("page", strconv.Itoa(searchPage))
	}

	if cmd.Flags().Changed("per-page") {
		if searchPerPage < 1 {
			return "", nil, errors.New("invalid --per-page (must be 1 or more)")
		}
		params.Set("per_page", strconv.Itoa(searchPerPage))
	}

	return term, params, nil
}

func newSearchReport(result *client.SearchResult, baseURL string) searchReport {
	types := facetCounts(result.Facets["type"], nil)
	slices.SortStableFunc(types, func(a, b facetCount) int { return b.Count - a.Count })

	// The feeds' severity names (moderate, important, ...) merge into the
	// canonical ones, most severe first; unknown values follow by name.
	severities := facetCounts(result.Facets["severity"], audit.NormalizeSeverity)
	slices.SortStableFunc(severities, func(a, b facetCount) int {
		return audit.SeverityLevels[b.Name] - audit.SeverityLevels[a.Name]
	})

	return searchReport{SearchResult: result, BaseURL: baseURL, Types: types, Severities: severities}
}

// facetCounts turns a facet into counts sorted by name, merging the values
// that normalize (when not nil) maps to the same name.
func facetCounts(facet map[string]int, normalize func(string) string) []facetCount {
	merged := map[string]int{}
	for name, n := range facet {
		if normalize != nil {
			name = normalize(name)
		}
		merged[name] += n
	}
	counts := make([]facetCount, 0, len(merged))
	for _, name := range slices.Sorted(maps.Keys(merged)) {
		counts = append(counts, facetCount{Name: name, Count: merged[name]})
	}
	return counts
}

// searchTypes validates a comma-separated --type list against client.SearchTypes
// and returns it normalized (lowercase, trimmed, de-duplicated).
func searchTypes(value string) (string, error) {
	if strings.TrimSpace(value) == "" {
		return "", nil
	}
	var types []string
	for _, t := range strings.Split(value, ",") {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" {
			continue
		}
		if !slices.Contains(client.SearchTypes, t) {
			return "", fmt.Errorf("invalid --type: %q (want a comma-separated list of %s)", t, strings.Join(client.SearchTypes, ", "))
		}
		if !slices.Contains(types, t) {
			types = append(types, t)
		}
	}
	return strings.Join(types, ","), nil
}

var (
	shortDuration = regexp.MustCompile(`^(\d+)([dwmy])$`)
	isoDuration   = regexp.MustCompile(`^P(\d+)([DWMY])$`)
)

// searchDuration converts the --since window to the ISO-8601 duration the API
// expects: "30d" (or 2w, 6m, 1y; m is months) becomes "P30D"; an ISO duration
// such as "P30D" passes through. The window must be at least 1.
func searchDuration(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	iso := strings.ToUpper(value)
	if m := shortDuration.FindStringSubmatch(strings.ToLower(value)); m != nil {
		iso = "P" + m[1] + strings.ToUpper(m[2])
	}
	m := isoDuration.FindStringSubmatch(iso)
	if m == nil {
		return "", fmt.Errorf("invalid --since: %q (want a number of days, weeks, months or years, e.g. 30d, 2w, 6m, 1y)", value)
	}
	if n, err := strconv.Atoi(m[1]); err != nil || n < 1 {
		return "", fmt.Errorf("invalid --since: %q (want a window of at least 1, e.g. 30d)", value)
	}
	return iso, nil
}

func init() {
	rootCmd.AddCommand(searchCmd)

	searchCmd.Flags().StringVar(&searchType, "type", "",
		"Only these record types, comma-separated: "+strings.Join(client.SearchTypes, ", "))
	searchCmd.Flags().StringVar(&searchSince, "since", "",
		"Only the records modified within this window (e.g. 30d, 2w, 6m, 1y)")
	searchCmd.Flags().IntVar(&searchPage, "page", 0,
		"Page number (default 1)")
	searchCmd.Flags().IntVar(&searchPerPage, "per-page", 0,
		"Results per page (default 100)")
}
