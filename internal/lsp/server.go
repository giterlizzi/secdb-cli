// SPDX-License-Identifier: Apache-2.0

// Package lsp implements a Language Server that audits dependency manifests.
package lsp

import (
	"log/slog"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/giterlizzi/secdb-cli/internal/audit"
	"github.com/giterlizzi/secdb-cli/internal/client"
	"github.com/giterlizzi/secdb-cli/internal/manifest"
	"github.com/giterlizzi/secdb-cli/internal/meta"
	"github.com/giterlizzi/secdb-cli/internal/util"

	"github.com/tliron/glsp"
	protocol "github.com/tliron/glsp/protocol_3_16"
	"github.com/tliron/glsp/server"
)

const (
	serverName = "secdb-lsp"
	sourceName = "secdb"
	delay      = 400 * time.Millisecond
)

// Server is the secdb Language Server: it audits dependency manifests as they
// are opened/edited and reports vulnerabilities as diagnostics.
type Server struct {
	client    *client.Client
	handler   protocol.Handler
	mu        sync.Mutex
	timers    map[protocol.DocumentUri]*time.Timer
	roots     []string
	discovery bool
	open      map[string]bool
}

// NewServer wires the LSP handler. The client is built by the caller (cmd), so
// this package never imports cmd (which would be an import cycle).
func NewServer(c *client.Client, discovery bool) *Server {
	s := &Server{
		client:    c,
		timers:    make(map[protocol.DocumentUri]*time.Timer),
		discovery: discovery,
		open:      make(map[string]bool),
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
	if s.discovery {
		go s.discoverWorkspace(ctx)
	}
	return nil
}

func (s *Server) shutdown(ctx *glsp.Context) error {
	slog.Debug("Shutdown Language Server...")
	return nil
}

func (s *Server) didChangeConfiguration(ctx *glsp.Context, params *protocol.DidChangeConfigurationParams) error {
	return nil
}

func (s *Server) didOpen(ctx *glsp.Context, params *protocol.DidOpenTextDocumentParams) error {
	uri := params.TextDocument.URI
	slog.Debug("didOpen", "uri", uri)

	s.mu.Lock()
	s.open[uri] = true
	s.mu.Unlock()

	if err := s.auditManifest(ctx, uri, []byte(params.TextDocument.Text)); err != nil {
		slog.Debug("audit failed", "error", err)
	}
	return nil
}

func (s *Server) didChange(ctx *glsp.Context, params *protocol.DidChangeTextDocumentParams) error {
	if len(params.ContentChanges) == 0 {
		return nil
	}

	change, ok := params.ContentChanges[0].(protocol.TextDocumentContentChangeEventWhole)
	if !ok {
		return nil
	}

	uri := params.TextDocument.URI

	s.delayAuditManifest(ctx, uri, []byte(change.Text))
	slog.Debug("didChange", "uri", uri)

	return nil
}

func (s *Server) didClose(ctx *glsp.Context, params *protocol.DidCloseTextDocumentParams) error {
	s.mu.Lock()

	uri := params.TextDocument.URI

	if t, ok := s.timers[uri]; ok {
		t.Stop()
		delete(s.timers, uri)
		delete(s.open, uri)
	}
	s.mu.Unlock()

	publishDiagnostics(ctx, uri, nil)

	return nil
}

func (s *Server) didSave(ctx *glsp.Context, params *protocol.DidSaveTextDocumentParams) error {
	return nil
}

func (s *Server) delayAuditManifest(ctx *glsp.Context, uri protocol.DocumentUri, content []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if t, ok := s.timers[uri]; ok {
		t.Stop()
	}
	s.timers[uri] = time.AfterFunc(delay, func() {
		if err := s.auditManifest(ctx, uri, content); err != nil {
			slog.Debug("audit failed", "error", err)
		}
	})
}

func (s *Server) auditManifest(ctx *glsp.Context, uri protocol.DocumentUri, content []byte) error {

	filename, err := uriToFilename(uri)
	if err != nil {
		return err
	}

	slog.Debug("audit", "filename", filename)

	deps, err := manifest.Parse(filename, content)
	if err != nil {
		return err
	}

	purls := make([]string, 0, len(deps))
	for _, d := range deps {
		if d.PURL != "" {
			slog.Debug("found dependency", "file", filename, "dependency", d)
			purls = append(purls, d.PURL)
		}
	}
	purls = audit.ValidatePURLs(purls)
	if len(purls) == 0 {
		slog.Debug("no auditable dependencies found", "filename", filename)
		publishDiagnostics(ctx, uri, nil)
		return nil
	}

	data, err := s.client.PURLAudit(purls)
	if err != nil {
		return err
	}

	diags := buildDiagnostics(deps, data, s.client.BaseURL())
	publishDiagnostics(ctx, uri, diags)

	return nil
}

func (s *Server) discoverWorkspace(ctx *glsp.Context) {
	for _, root := range s.roots {
		files, err := manifest.Discover(root, nil, 0)
		if err != nil {
			slog.Debug("workspace discovery failed", "root", root, "error", err)
			continue
		}
		slog.Debug("workspace discovery", "root", root, "manifests", len(files))
		for _, f := range files {

			s.mu.Lock()
			isOpen := s.open[filenameToURI(f)]
			s.mu.Unlock()

			if isOpen {
				slog.Debug("discovery: skip open file", "file", f)
				continue
			}

			content, err := os.ReadFile(f)
			if err != nil {
				slog.Debug("discovery: failed to read manifest", "file", f, "error", err)
				continue
			}

			if err := s.auditManifest(ctx, filenameToURI(f), content); err != nil {
				slog.Debug("discovery: audit failed", "file", f, "error", err)
			}
		}
	}
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

func buildDiagnostics(deps []manifest.Dependency, items []client.AuditItem, baseURL string) []protocol.Diagnostic {
	byPURL := make(map[string][]client.Advisory, len(items))
	for _, it := range items {
		byPURL[it.PURL] = it.Advisories
	}

	var diags []protocol.Diagnostic
	source := sourceName
	for _, d := range deps {
		for _, adv := range byPURL[d.PURL] {
			diags = append(diags, protocol.Diagnostic{
				Range:           toRange(d.Range),
				Severity:        toDiagnosticSeverity(adv.Severity),
				Message:         adv.ID + ": " + adv.Title,
				Source:          &source,
				Code:            &protocol.IntegerOrString{Value: adv.ID},
				CodeDescription: &protocol.CodeDescription{HRef: util.AdvisoryURL(baseURL, adv.ID)},
			})
		}
	}
	return diags
}

func toRange(r manifest.Range) protocol.Range {
	line := fixLine(r.Start.Line)
	return protocol.Range{
		Start: protocol.Position{Line: line, Character: 0},
		End:   protocol.Position{Line: line, Character: 1024},
	}
}

func fixLine(n int) protocol.UInteger {
	if n > 0 {
		return protocol.UInteger(n - 1)
	}
	return 0
}

func publishDiagnostics(ctx *glsp.Context, uri protocol.DocumentUri, diags []protocol.Diagnostic) {
	if diags == nil {
		diags = []protocol.Diagnostic{}
	}
	ctx.Notify(protocol.ServerTextDocumentPublishDiagnostics, protocol.PublishDiagnosticsParams{
		URI:         uri,
		Diagnostics: diags,
	})
}

func toDiagnosticSeverity(severity string) *protocol.DiagnosticSeverity {
	var s protocol.DiagnosticSeverity

	switch strings.ToLower(severity) {
	case "critical", "important", "urgent", "severe", "high":
		s = protocol.DiagnosticSeverityError
	case "medium", "moderate":
		s = protocol.DiagnosticSeverityWarning
	case "low":
		s = protocol.DiagnosticSeverityInformation
	default:
		s = protocol.DiagnosticSeverityHint
	}
	return &s
}
