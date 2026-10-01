// SPDX-License-Identifier: Apache-2.0

package lsp

import (
	"encoding/json"
	"log/slog"

	"github.com/tliron/glsp"
	protocol "github.com/tliron/glsp/protocol_3_16"
)

// settingsSection is the configuration section the server asks for with
// workspace/configuration, and reads from a pushed
// workspace/didChangeConfiguration ({"settings": {"secdb": {...}}}).
const settingsSection = "secdb"

// settings are the user preferences the client can change without restarting
// the server. They start from the command-line Options, are overridden by the
// initializationOptions sent in initialize, and then by the "secdb" section
// pulled with workspace/configuration (on initialized and on every
// didChangeConfiguration), or pushed in didChangeConfiguration by a client
// that can't be asked. Absent fields (and a null section) keep their value.
type settings struct {
	// Discovery audits every manifest in the workspace on startup (read once,
	// in initialized: changing it later has no effect).
	Discovery bool `json:"discovery"`

	// ShowUnfixed also reports vulnerabilities with no fix available.
	ShowUnfixed bool `json:"showUnfixed"`

	// IgnoreFile is an explicit ignore file; when empty, the nearest
	// .secdbignore up to the workspace root is used.
	IgnoreFile string `json:"ignoreFile"`

	// DiscoverySummary shows the end-of-discovery summary message.
	DiscoverySummary bool `json:"discoverySummary"`

	// UpdateNotice shows the "new version available" message.
	UpdateNotice bool `json:"updateNotice"`
}

// defaultSettings returns the settings implied by the command-line options.
func defaultSettings(opts Options) settings {
	return settings{
		Discovery:        opts.Discovery,
		ShowUnfixed:      opts.ShowUnfixed,
		IgnoreFile:       opts.IgnoreFile,
		DiscoverySummary: true,
		UpdateNotice:     true,
	}
}

// merge returns cur overridden by the fields present in raw (any JSON-able
// value, as decoded by the LSP library). A nil or invalid raw is logged and
// leaves cur unchanged.
func (cur settings) merge(raw any) settings {
	if raw == nil {
		return cur
	}
	b, err := json.Marshal(raw)
	if err != nil {
		slog.Warn("ignoring invalid settings", "error", err)
		return cur
	}
	next := cur
	if err := json.Unmarshal(b, &next); err != nil {
		slog.Warn("ignoring invalid settings", "settings", string(b), "error", err)
		return cur
	}
	return next
}

// section returns the "secdb" section of a didChangeConfiguration payload, or
// nil when there is none.
func section(raw any) any {
	if m, ok := raw.(map[string]any); ok {
		return m[settingsSection]
	}
	return nil
}

// hasExperimental reports whether the client declares the boolean experimental
// capability name (capabilities.experimental.<name>: true).
func hasExperimental(experimental any, name string) bool {
	m, ok := experimental.(map[string]any)
	if !ok {
		return false
	}
	v, _ := m[name].(bool)
	return v
}

// didChangeConfiguration applies the new settings, taking effect on the next
// audit. A client that answers workspace/configuration often sends no settings
// here (just the signal), so they are pulled again; otherwise the "secdb"
// section of the pushed settings is applied.
func (s *Server) didChangeConfiguration(ctx *glsp.Context, params *protocol.DidChangeConfigurationParams) error {
	if s.pullConfig {
		go s.pullSettings(ctx)
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.settings = s.settings.merge(section(params.Settings))
	slog.Debug("settings changed", "settings", s.settings)
	return nil
}

// pullSettings asks the client for the "secdb" settings section
// (workspace/configuration) and applies it, when the client supports it. It
// blocks on the response, so it must not run inside a handler. glsp's Call
// only logs a failure, which leaves the result empty and the settings unchanged.
func (s *Server) pullSettings(ctx *glsp.Context) {
	if !s.pullConfig {
		return
	}
	sec := settingsSection
	var result []any
	ctx.Call(protocol.ServerWorkspaceConfiguration, protocol.ConfigurationParams{
		Items: []protocol.ConfigurationItem{{Section: &sec}},
	}, &result)
	if len(result) == 0 {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.settings = s.settings.merge(result[0])
	slog.Debug("settings pulled", "settings", s.settings)
}

// currentSettings returns a snapshot of the user preferences.
func (s *Server) currentSettings() settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.settings
}
