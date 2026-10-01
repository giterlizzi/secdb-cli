// SPDX-License-Identifier: Apache-2.0

package lsp

import (
	"fmt"
	"log/slog"

	"github.com/giterlizzi/secdb-cli/internal/meta"

	"github.com/tliron/glsp"
	protocol "github.com/tliron/glsp/protocol_3_16"
)

// notifyUpdate tells the user a newer secdb release is available. When the
// client can open URLs (window/showDocument) it offers a button to the release
// page; otherwise the URL goes in the message text.
func (s *Server) notifyUpdate(ctx *glsp.Context, version string) {
	releaseURL := meta.RepoURL + "/releases/tag/" + version
	msg := fmt.Sprintf("SecDB: new version %s available (current %s)", version, meta.Version)

	if !s.showDocument {
		ctx.Notify(protocol.ServerWindowShowMessage, protocol.ShowMessageParams{
			Type:    protocol.MessageTypeInfo,
			Message: msg + ": " + releaseURL,
		})
		return
	}

	const releaseNotes = "Release notes"

	// Blocks until the user picks the action or dismisses the message (nil).
	var choice *protocol.MessageActionItem
	ctx.Call(protocol.ServerWindowShowMessageRequest, protocol.ShowMessageRequestParams{
		Type:    protocol.MessageTypeInfo,
		Message: msg,
		Actions: []protocol.MessageActionItem{{Title: releaseNotes}},
	}, &choice)
	if choice == nil || choice.Title != releaseNotes {
		return
	}

	var result protocol.ShowDocumentResult
	ctx.Call(protocol.ServerWindowShowDocument, protocol.ShowDocumentParams{
		URI:      releaseURL,
		External: &protocol.True,
	}, &result)
	if !result.Success {
		slog.Debug("failed to open the release page", "url", releaseURL)
	}
}
