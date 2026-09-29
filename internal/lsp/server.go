// SPDX-License-Identifier: Apache-2.0

// Package lsp implements a Language Server that audits dependency manifests.
package lsp

import (
	"log/slog"
	"math"
	"net/url"
	"os"
	"path/filepath"
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

	// ignoreFileName is the ignore file looked up next to a manifest, the same
	// default as the audit commands' --ignore-file.
	ignoreFileName = ".secdbignore"
)

// Server is the secdb Language Server: it audits dependency manifests as they
// are opened/edited and reports vulnerabilities as diagnostics.
type Server struct {
	client  *client.Client
	opts    Options
	handler protocol.Handler
	mu      sync.Mutex
	timers  map[protocol.DocumentUri]*time.Timer
	roots   []string
	open    map[string]bool
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
}

// NewServer wires the LSP handler. The client is built by the caller (cmd), so
// this package never imports cmd (which would be an import cycle).
func NewServer(c *client.Client, opts Options) *Server {
	s := &Server{
		client: c,
		opts:   opts,
		timers: make(map[protocol.DocumentUri]*time.Timer),
		open:   make(map[string]bool),
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
	if s.opts.Discovery {
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
	}
	delete(s.open, uri)
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

	diags := buildDiagnostics(deps, data, s.client.BaseURL(), s.loadIgnoreFile(filename), s.opts.ShowUnfixed)
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
			s.auditDiscovered(ctx, f)
		}
	}
}

// auditDiscovered audits a manifest found by the workspace discovery, unless the
// editor has it open: open files are kept fresh by the edit path.
func (s *Server) auditDiscovered(ctx *glsp.Context, filename string) {
	uri := filenameToURI(filename)
	if s.isOpen(uri) {
		slog.Debug("discovery: skip open file", "file", filename)
		return
	}

	content, err := os.ReadFile(filename)
	if err != nil {
		slog.Debug("discovery: failed to read manifest", "file", filename, "error", err)
		return
	}
	if err := s.auditManifest(ctx, uri, content); err != nil {
		slog.Debug("discovery: audit failed", "file", filename, "error", err)
	}
}

// isOpen reports whether the editor has the document open.
func (s *Server) isOpen(uri protocol.DocumentUri) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.open[uri]
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

// loadIgnoreFile returns the ignore rules for the manifest at filename: the
// explicit Options.IgnoreFile, or else the nearest .secdbignore found walking
// up from the manifest's directory to its workspace root. It is re-read on
// every audit, so an edit to the ignore file applies on the next one. A
// malformed file is logged and ignored rather than blocking the diagnostics.
func (s *Server) loadIgnoreFile(filename string) *audit.IgnoreFile {
	path := s.opts.IgnoreFile
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

// buildDiagnostics maps every (dependency, advisory) pair to a diagnostic at
// the dependency's range, with the same rules as the audit commands: an
// unfixed advisory is skipped unless showUnfixed, and an ignored one is kept
// but downgraded to a hint carrying the ignore reason (an ignore rule never
// hides a finding, it accepts it).
func buildDiagnostics(deps []manifest.Dependency, items []client.AuditItem, baseURL string, ignore *audit.IgnoreFile, showUnfixed bool) []protocol.Diagnostic {
	byPURL := make(map[string][]client.Advisory, len(items))
	for _, it := range items {
		byPURL[it.PURL] = it.Advisories
	}

	var diags []protocol.Diagnostic
	for _, d := range deps {
		for _, adv := range byPURL[d.PURL] {
			unfixed := audit.IsUnfixed(d.PURL, adv)
			if !unfixed || showUnfixed {
				diags = append(diags, diagnosticFor(d, adv, baseURL, ignore, unfixed))
			}
		}
	}
	return diags
}

// diagnosticFor builds the diagnostic of one advisory on one dependency: an
// unfixed advisory says so in the message, and one accepted by the ignore file
// is downgraded to a hint that carries the rule's reason.
func diagnosticFor(d manifest.Dependency, adv client.Advisory, baseURL string, ignore *audit.IgnoreFile, unfixed bool) protocol.Diagnostic {
	message := adv.ID + ": " + adv.Title
	if unfixed {
		message += " (no fix available)"
	}
	severity := toDiagnosticSeverity(adv.Severity)
	if ignored, reason := ignore.IsIgnored(adv.ID, adv.CVEs, d.PURL); ignored {
		hint := protocol.DiagnosticSeverityHint
		severity = &hint
		message += " (ignored: " + reason + ")"
	}

	source := sourceName
	return protocol.Diagnostic{
		Range:           toRange(d.Range),
		Severity:        severity,
		Message:         message,
		Source:          &source,
		Code:            &protocol.IntegerOrString{Value: adv.ID},
		CodeDescription: &protocol.CodeDescription{HRef: util.AdvisoryURL(baseURL, adv.ID)},
	}
}

func toRange(r manifest.Range) protocol.Range {
	line := fixLine(r.Start.Line)
	return protocol.Range{
		Start: protocol.Position{Line: line, Character: 0},
		End:   protocol.Position{Line: line, Character: 1024},
	}
}

// fixLine converts a 1-based manifest line to a 0-based LSP line, clamped to
// the uint32 range the protocol uses (0 when the line is unknown).
func fixLine(n int) protocol.UInteger {
	if n <= 0 {
		return 0
	}
	if n-1 > math.MaxUint32 {
		return math.MaxUint32
	}
	return protocol.UInteger(n - 1)
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

	switch audit.NormalizeSeverity(severity) {
	case "critical", "high":
		s = protocol.DiagnosticSeverityError
	case "medium":
		s = protocol.DiagnosticSeverityWarning
	case "low":
		s = protocol.DiagnosticSeverityInformation
	default:
		s = protocol.DiagnosticSeverityHint
	}
	return &s
}
