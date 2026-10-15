// SPDX-License-Identifier: Apache-2.0

// Package lsp implements a Language Server that audits dependency manifests.
package lsp

import (
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/giterlizzi/secdb-cli/internal/client"
	"github.com/giterlizzi/secdb-cli/internal/meta"

	"github.com/tliron/glsp"
	protocol "github.com/tliron/glsp/protocol_3_16"
	"github.com/tliron/glsp/server"
)

const serverName = "secdb-lsp"

// Server is the secdb Language Server: it audits dependency manifests as they
// are opened/edited and reports vulnerabilities as diagnostics.
type Server struct {
	// client calls the ZEN SecDB API (built by cmd from the global flags).
	client *client.Client

	// opts are the command-line options; settings start from them.
	opts Options

	// handler maps the LSP methods to the Server's methods (see NewServer).
	handler protocol.Handler

	// mu guards settings, timers and open, which the message handlers, the
	// debounce timers and the workspace discovery use from different
	// goroutines. Take it in a small named method (currentSettings, isOpen,
	// markOpen, forget, ...), never across an API call or a ctx.Call.
	mu sync.Mutex

	// settings are the user preferences: the client can change them at
	// runtime with workspace/didChangeConfiguration.
	settings settings

	// timers holds the pending (debounced) audit of each edited document.
	timers map[protocol.DocumentUri]*time.Timer

	// open is the set of documents the editor has open: the workspace
	// discovery skips them, since the edit path keeps them fresh.
	open map[string]bool

	// roots are the workspace folders, read from initialize.
	roots []string

	// The client capabilities, read once in initialize.

	// showDocument is set when the client can open a URL (window/showDocument).
	showDocument bool

	// pullConfig is set when the client answers workspace/configuration.
	pullConfig bool

	// sendDependencies is set when the client declares the experimental
	// capability secdbDependencies, i.e. it handles secdb/dependencies.
	sendDependencies bool
}

// Options configures the server. The zero value audits files as they are
// opened only, with the same defaults as the audit commands (unfixed
// vulnerabilities hidden, .secdbignore discovered next to the manifest).
type Options struct {
	// Discovery audits every manifest in the workspace on startup.
	Discovery bool

	// ShowUnfixed also reports vulnerabilities with no fix available.
	ShowUnfixed bool

	// IgnoreFile is an explicit ignore file; when empty, the nearest
	// .secdbignore from the manifest's directory up to its workspace root is used.
	IgnoreFile string

	// Update channel
	UpdateAvailable <-chan string
}

// NewServer wires the LSP handler. The client is built by the caller (cmd), so
// this package never imports cmd (which would be an import cycle).
func NewServer(c *client.Client, opts Options) *Server {
	s := &Server{
		client:   c,
		opts:     opts,
		settings: defaultSettings(opts),
		timers:   make(map[protocol.DocumentUri]*time.Timer),
		open:     make(map[string]bool),
	}

	s.handler = protocol.Handler{
		Initialize:                      s.initialize,
		Initialized:                     s.initialized,
		Shutdown:                        s.shutdown,
		TextDocumentDidOpen:             s.didOpen,
		TextDocumentDidChange:           s.didChange,
		TextDocumentDidClose:            s.didClose,
		TextDocumentDidSave:             s.didSave,
		WorkspaceDidChangeConfiguration: s.didChangeConfiguration,
	}
	return s
}

// Run starts the server on stdio and blocks until the client disconnects.
func (s *Server) Run() error {
	return server.NewServer(&s.handler, serverName, false).RunStdio()
}

func (s *Server) initialize(ctx *glsp.Context, params *protocol.InitializeParams) (any, error) {
	slog.Debug("Initialize Language Server...")

	caps := s.handler.CreateServerCapabilities()
	caps.TextDocumentSync = protocol.TextDocumentSyncKindFull

	version := strings.TrimPrefix(meta.Version, "v")

	for _, f := range params.WorkspaceFolders {
		if p, err := uriToFilename(f.URI); err == nil {
			s.roots = append(s.roots, p)
		}
	}
	if len(s.roots) == 0 && params.RootURI != nil {
		if p, err := uriToFilename(*params.RootURI); err == nil {
			s.roots = append(s.roots, p)
		}
	}

	slog.Debug("workspace directories", "roots", s.roots)

	if w := params.Capabilities.Window; w != nil && w.ShowDocument != nil {
		s.showDocument = w.ShowDocument.Support
	}
	if w := params.Capabilities.Workspace; w != nil && w.Configuration != nil {
		s.pullConfig = *w.Configuration
	}
	s.sendDependencies = hasExperimental(params.Capabilities.Experimental, dependenciesCapability)

	slog.Debug("client capabilities", "pull", s.pullConfig, "dependencies", s.sendDependencies, "show_document", s.showDocument)
	s.mergeSettings(params.InitializationOptions, "initialize")

	return protocol.InitializeResult{
		Capabilities: caps,
		ServerInfo: &protocol.InitializeResultServerInfo{
			Name:    serverName,
			Version: &version,
		},
	}, nil
}

func (s *Server) initialized(ctx *glsp.Context, params *protocol.InitializedParams) error {
	slog.Debug("Initialized Language Server")

	// In a goroutine: the handlers run one at a time, so a request to the client
	// made from inside one would never read its response.
	go func() {
		// The settings decide whether to run the discovery, so pull them first.
		s.pullSettings(ctx)
		if s.currentSettings().Discovery {
			s.discoverWorkspace(ctx)
		}
	}()

	if ch := s.opts.UpdateAvailable; ch != nil {
		go func() {
			if v, ok := <-ch; ok && v != "" && s.currentSettings().UpdateNotice {
				s.notifyUpdate(ctx, v)
			}
		}()
	}

	return nil
}

func (s *Server) shutdown(ctx *glsp.Context) error {
	slog.Debug("Shutdown Language Server...")
	return nil
}

func uriToFilename(uri protocol.DocumentUri) (string, error) {
	u, err := url.Parse(uri)

	if err != nil {
		return "", err
	}

	return u.Path, nil
}

func filenameToURI(path string) protocol.DocumentUri {
	return (&url.URL{Scheme: "file", Path: path}).String()
}
