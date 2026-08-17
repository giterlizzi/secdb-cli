// SPDX-License-Identifier: Apache-2.0

package update

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/mod/semver"
)

type State struct {
	LastChecked       time.Time `json:"last_checked"`
	LatestVersion     string    `json:"latest_version"`
	LatestURL         string    `json:"latest_url"`
	LatestPublishedAt time.Time `json:"latest_published_at"`
}

type ReleaseInfo struct {
	Version     string    `json:"tag_name"`
	URL         string    `json:"html_url"`
	PublishedAt time.Time `json:"published_at"`
}

const releaseURL = "https://api.github.com/repos/giterlizzi/secdb-cli/releases/latest"

func stateFilePath() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}

	appDir := filepath.Join(dir, "secdb-cli")
	if err := os.MkdirAll(appDir, 0755); err != nil {
		return "", err
	}

	return filepath.Join(appDir, "update-check.json"), nil
}

func loadState() *State {
	path, err := stateFilePath()
	if err != nil {
		return &State{}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return &State{}
	}

	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return &State{}
	}

	return &s
}

func (s *State) save() error {
	path, err := stateFilePath()
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0o644)
}

func fetchLatest() (*ReleaseInfo, error) {
	client := &http.Client{Timeout: 10 * time.Second}

	req, err := http.NewRequest(http.MethodGet, releaseURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, fmt.Errorf("no release published on GitHub")
	default:
		return nil, fmt.Errorf("GitHub API error (status %d): %s", resp.StatusCode, string(body))
	}

	var release ReleaseInfo

	if err := json.Unmarshal(body, &release); err != nil {
		return nil, fmt.Errorf("GitHub response: %w", err)
	}

	return &release, nil
}

func UpdateIsAvailable(currentVersion string) (bool, *ReleaseInfo, error) {

	const updateCheckInterval = 24 * time.Hour

	state := loadState()

	existsUpdate := state.LatestVersion != "" && semver.IsValid(state.LatestVersion) && semver.Compare(state.LatestVersion, currentVersion) > 0

	if time.Since(state.LastChecked) > updateCheckInterval && !existsUpdate {
		release, err := fetchLatest()
		if err == nil {
			state.LastChecked = time.Now()
			state.LatestVersion = release.Version
			state.LatestURL = release.URL
			state.LatestPublishedAt = release.PublishedAt
			_ = state.save()
		}
		return false, nil, err
	}

	if semver.IsValid(state.LatestVersion) && semver.Compare(state.LatestVersion, currentVersion) > 0 {
		return true, &ReleaseInfo{
			Version:     state.LatestVersion,
			URL:         state.LatestURL,
			PublishedAt: state.LatestPublishedAt,
		}, nil
	}

	return false, nil, nil
}
