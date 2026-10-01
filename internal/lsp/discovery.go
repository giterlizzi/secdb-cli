// SPDX-License-Identifier: Apache-2.0

package lsp

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/giterlizzi/secdb-cli/internal/manifest"

	"github.com/tliron/glsp"
	protocol "github.com/tliron/glsp/protocol_3_16"
)

func (s *Server) discoverWorkspace(ctx *glsp.Context) {

	auditedManifests := 0
	failedManifests := 0
	totalFindings := 0
	var firstErr error

	for _, root := range s.roots {
		files, err := manifest.Discover(root, nil, 0)
		if err != nil {
			slog.Debug("workspace discovery failed", "root", root, "error", err)
			continue
		}

		slog.Debug("workspace discovery", "root", root, "manifests", len(files))
		for _, f := range files {
			audited, findings, err := s.auditDiscovered(ctx, f)

			switch {
			case err != nil:
				failedManifests++
				if firstErr == nil {
					firstErr = err
				}
			case audited:
				auditedManifests++
				totalFindings += findings
			}
		}
	}

	if (auditedManifests+failedManifests) > 0 && s.currentSettings().DiscoverySummary {
		msgType, msg := discoverySummary(auditedManifests, totalFindings, failedManifests, firstErr)
		ctx.Notify(protocol.ServerWindowShowMessage, protocol.ShowMessageParams{
			Type:    msgType,
			Message: msg,
		})
	}
}

// discoverySummary builds the end-of-discovery message, typed by its worst
// outcome: Error if any manifest failed, Warning if there are findings, else Info.
func discoverySummary(audited, findings, failed int, firstErr error) (protocol.MessageType, string) {
	msg := fmt.Sprintf("SecDB: %d manifests audited, %d findings", audited, findings)

	switch {
	case failed > 0:
		return protocol.MessageTypeError, fmt.Sprintf("%s, %d failed: %v", msg, failed, firstErr)
	case findings > 0:
		return protocol.MessageTypeWarning, msg
	default:
		return protocol.MessageTypeInfo, msg
	}
}

// auditDiscovered audits a manifest found by the workspace discovery, unless the
// editor has it open: open files are kept fresh by the edit path. A skipped file
// returns (false, 0, nil); a failed one returns the error.
func (s *Server) auditDiscovered(ctx *glsp.Context, filename string) (audited bool, findings int, err error) {
	uri := filenameToURI(filename)
	if s.isOpen(uri) {
		slog.Debug("discovery: skip open file", "file", filename)
		return false, 0, nil
	}

	content, err := os.ReadFile(filename)
	if err != nil {
		slog.Debug("discovery: failed to read manifest", "file", filename, "error", err)
		return false, 0, err
	}

	total, err := s.auditManifest(ctx, uri, content)
	if err != nil {
		slog.Debug("discovery: audit failed", "file", filename, "error", err)
		return false, 0, err
	}

	return true, total, nil
}
