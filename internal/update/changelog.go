// SPDX-License-Identifier: Apache-2.0

package update

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

var (
	changelogURL     = "https://raw.githubusercontent.com/giterlizzi/secdb-cli/refs/tags/%s/CHANGELOG.md"
	changelogHeading = regexp.MustCompile(`^## \[([^\]]+)\] - (\d{4}-\d{2}-\d{2})`)
	changelogLinkRef = regexp.MustCompile(`^\[[^\]]+\]:\s`)
)

// ChangelogRelease is one dated version section of CHANGELOG.md.
type ChangelogRelease struct {
	Version string
	Date    string
	Notes   string
}

// FetchReleaseNotes downloads CHANGELOG.md at the given release tag (a semver
// tag such as "v0.5.0", rejected otherwise) and splits it into its version
// sections (see ReleaseNotes). A non-200 response is an error, so a missing
// tag or file never yields an empty list as if it were a valid changelog.
func FetchReleaseNotes(tag string) ([]ChangelogRelease, error) {
	if !semver.IsValid(tag) {
		return nil, fmt.Errorf("invalid release tag %q", tag)
	}

	client := &http.Client{Timeout: 10 * time.Second}

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf(changelogURL, tag), nil)
	if err != nil {
		return nil, err
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch changelog %s: status %d", tag, res.StatusCode)
	}

	body, err := io.ReadAll(res.Body)

	if err != nil {
		return nil, err
	}

	return ReleaseNotes(string(body)), nil
}

// ReleaseNotes splits a Keep a Changelog file into its dated version sections,
// in file order (newest first); [Unreleased] and the trailing link reference
// definitions are skipped.
func ReleaseNotes(changelog string) []ChangelogRelease {
	var entries []ChangelogRelease
	lastRelease := -1

	for line := range strings.SplitSeq(changelog, "\n") {
		if changelogLinkRef.MatchString(line) {
			break
		}

		if match := changelogHeading.FindStringSubmatch(line); match != nil {
			entries = append(entries, ChangelogRelease{
				Version: "v" + match[1],
				Date:    match[2],
			})
			lastRelease++
			continue
		}

		if lastRelease >= 0 {
			entries[lastRelease].Notes = entries[lastRelease].Notes + "\n" + line
		}
	}

	return entries
}

// ReleaseNotesAfterVersion returns the releases newer than version, keeping
// their order.
func ReleaseNotesAfterVersion(releases []ChangelogRelease, version string) []ChangelogRelease {
	var entries []ChangelogRelease
	for _, r := range releases {
		if semver.Compare(r.Version, version) > 0 {
			entries = append(entries, r)
		}
	}
	return entries
}
