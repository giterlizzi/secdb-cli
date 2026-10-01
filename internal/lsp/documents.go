// SPDX-License-Identifier: Apache-2.0

package lsp

import (
	"log/slog"
	"time"

	"github.com/tliron/glsp"
	protocol "github.com/tliron/glsp/protocol_3_16"
)

// delay debounces the audit of a document being edited.
const delay = 400 * time.Millisecond

func (s *Server) didOpen(ctx *glsp.Context, params *protocol.DidOpenTextDocumentParams) error {
	uri := params.TextDocument.URI
	slog.Debug("didOpen", "uri", uri)

	s.mu.Lock()
	s.open[uri] = true
	s.mu.Unlock()

	if _, err := s.auditManifest(ctx, uri, []byte(params.TextDocument.Text)); err != nil {
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
		if _, err := s.auditManifest(ctx, uri, content); err != nil {
			slog.Debug("audit failed", "error", err)
		}
	})
}

// isOpen reports whether the editor has the document open.
func (s *Server) isOpen(uri protocol.DocumentUri) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.open[uri]
}
