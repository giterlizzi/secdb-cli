// SPDX-License-Identifier: Apache-2.0

package update

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func withTempCache(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", dir)
}

func writeState(t *testing.T, s State) {
	t.Helper()

	state := &State{
		LastChecked:       s.LastChecked,
		LatestVersion:     s.LatestVersion,
		LatestURL:         "http://localhost",
		LatestPublishedAt: time.Now(),
	}

	err := state.save()

	if err != nil {
		t.Fatalf("writeState: %v", err)
	}
}

func TestUpdateIsAvailable_CachedNewerVersion(t *testing.T) {
	withTempCache(t)

	writeState(t, State{
		LastChecked:   time.Now(),
		LatestVersion: "v2.0.0",
	})

	available, releaseInfo, err := IsAvailable("v1.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !available {
		t.Error("expected update to be available")
	}
	if releaseInfo.Version != "v2.0.0" {
		t.Errorf("expected v2.0.0, got %q", releaseInfo.Version)
	}
}

func TestUpdateIsAvailable_AlreadyLatest(t *testing.T) {
	withTempCache(t)

	writeState(t, State{
		LastChecked:   time.Now(),
		LatestVersion: "v1.0.0",
	})

	available, release, err := IsAvailable("v1.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if available {
		t.Error("expected no update available")
	}
	if release != nil {
		t.Errorf("expected empty release, got %+v", release)
	}
}

// withReleaseServer points releaseURL at a test server answering with status
// and, on 200, a release JSON for version.
func withReleaseServer(t *testing.T, status int, version string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		if status == http.StatusOK {
			fmt.Fprintf(w, `{"tag_name":%q,"html_url":"https://example/releases/tag/%s","published_at":"2026-09-17T00:00:00Z"}`, version, version)
		}
	}))
	t.Cleanup(srv.Close)

	orig := releaseURL
	releaseURL = srv.URL
	t.Cleanup(func() { releaseURL = orig })
}

// A stale cache (or none) must report a newer release on the very check that
// fetches it, not only on the next run.
func TestUpdateIsAvailable_FetchedNewerVersion(t *testing.T) {
	for name, last := range map[string]time.Time{
		"no cache":    {},
		"stale cache": time.Now().Add(-25 * time.Hour),
	} {
		t.Run(name, func(t *testing.T) {
			withTempCache(t)
			withReleaseServer(t, http.StatusOK, "v2.0.0")
			if !last.IsZero() {
				writeState(t, State{LastChecked: last, LatestVersion: "v1.0.0"})
			}

			available, release, err := IsAvailable("v1.0.0")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !available || release == nil || release.Version != "v2.0.0" {
				t.Fatalf("expected v2.0.0 available, got %v %+v", available, release)
			}
			if s := loadState(); s.LatestVersion != "v2.0.0" || time.Since(s.LastChecked) > time.Minute {
				t.Errorf("state not refreshed: %+v", s)
			}
		})
	}
}

func TestUpdateIsAvailable_FetchedSameVersion(t *testing.T) {
	withTempCache(t)
	withReleaseServer(t, http.StatusOK, "v1.0.0")

	available, release, err := IsAvailable("v1.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if available || release != nil {
		t.Errorf("expected no update, got %v %+v", available, release)
	}
}

func TestUpdateIsAvailable_FetchError(t *testing.T) {
	withTempCache(t)
	withReleaseServer(t, http.StatusInternalServerError, "")

	available, release, err := IsAvailable("v1.0.0")
	if err == nil {
		t.Fatal("expected an error")
	}
	if available || release != nil {
		t.Errorf("expected no update on error, got %v %+v", available, release)
	}
	if s := loadState(); !s.LastChecked.IsZero() {
		t.Errorf("a failed check must not refresh the cache: %+v", s)
	}
}

func TestStateFilePath(t *testing.T) {
	withTempCache(t)

	path, err := stateFilePath()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if filepath.Base(path) != "update-check.json" {
		t.Errorf("unexpected file name: %s", filepath.Base(path))
	}
}

func TestStateSaveAndLoad(t *testing.T) {
	withTempCache(t)

	s := &State{
		LastChecked:   time.Now().Truncate(time.Second),
		LatestVersion: "v1.2.3",
	}
	if err := s.save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded := loadState()
	if loaded.LatestVersion != s.LatestVersion {
		t.Errorf("expected %q, got %q", s.LatestVersion, loaded.LatestVersion)
	}
}

func TestLoadState_MissingFile(t *testing.T) {
	withTempCache(t)

	s := loadState()
	if s.LatestVersion != "" {
		t.Errorf("expected empty state, got %+v", s)
	}
}
