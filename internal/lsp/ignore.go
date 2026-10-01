// SPDX-License-Identifier: Apache-2.0

package lsp

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/giterlizzi/secdb-cli/internal/audit"
)

// ignoreFileName is the ignore file looked up next to a manifest, the same
// default as the audit commands' --ignore-file.
const ignoreFileName = ".secdbignore"

// loadIgnoreFile returns the ignore rules for the manifest at filename: the
// explicit one (the ignoreFile setting), or else the nearest .secdbignore found
// walking up from the manifest's directory to its workspace root. It is re-read on
// every audit, so an edit to the ignore file applies on the next one. A
// malformed file is logged and ignored rather than blocking the diagnostics.
func (s *Server) loadIgnoreFile(filename string) *audit.IgnoreFile {
	path := s.currentSettings().IgnoreFile
	if path == "" {
		path = findIgnoreFile(filename, s.roots)
	}
	if path == "" {
		return nil
	}
	f, err := audit.LoadIgnoreFile(path)
	if err != nil {
		slog.Warn("ignoring invalid ignore file", "file", path, "error", err)
		return nil
	}
	return f
}

// findIgnoreFile looks for .secdbignore from filename's directory up to the
// workspace root that contains it (only that directory when the file is
// outside every root), returning its path or "".
func findIgnoreFile(filename string, roots []string) string {
	dir := filepath.Dir(filename)
	stop := dir
	for _, r := range roots {
		rel, err := filepath.Rel(r, dir)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			stop = r
			break
		}
	}
	for {
		candidate := filepath.Join(dir, ignoreFileName)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if dir == stop || parent == dir {
			return ""
		}
		dir = parent
	}
}
