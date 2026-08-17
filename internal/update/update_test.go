// SPDX-License-Identifier: Apache-2.0

package update

import (
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

	available, releaseInfo, err := UpdateIsAvailable("v1.0.0")
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

	available, release, err := UpdateIsAvailable("v1.0.0")
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
