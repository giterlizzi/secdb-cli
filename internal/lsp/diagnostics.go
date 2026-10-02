// SPDX-License-Identifier: Apache-2.0

package lsp

import (
	"math"

	"github.com/giterlizzi/secdb-cli/internal/audit"
	"github.com/giterlizzi/secdb-cli/internal/client"
	"github.com/giterlizzi/secdb-cli/internal/manifest"
	"github.com/giterlizzi/secdb-cli/internal/weblink"

	"github.com/tliron/glsp"
	protocol "github.com/tliron/glsp/protocol_3_16"
)

// sourceName is the source of every diagnostic.
const sourceName = "secdb"

// buildDiagnostics maps every (dependency, advisory) pair of the manifest at
// filename to a diagnostic at the dependency's range, with the same rules as
// the audit commands: an unfixed advisory is skipped unless the showUnfixed
// setting is on, and one matched by the manifest's ignore file is kept but
// downgraded to a hint carrying the ignore reason (an ignore rule never hides a
// finding, it accepts it). It also returns the number of advisories reported
// per PURL, counted once even when a PURL is declared more than once.
func (s *Server) buildDiagnostics(deps []manifest.Dependency, items []client.AuditItem, filename string) ([]protocol.Diagnostic, map[string]int) {
	showUnfixed := s.currentSettings().ShowUnfixed
	ignore := s.loadIgnoreFile(filename)
	webURL := s.client.WebURL()

	byPURL := make(map[string][]client.Advisory, len(items))
	for _, it := range items {
		byPURL[it.PURL] = it.Advisories
	}

	var diags []protocol.Diagnostic
	counts := make(map[string]int)
	seen := make(map[string]bool)

	for _, d := range deps {
		first := !seen[d.PURL]
		seen[d.PURL] = true

		for _, adv := range byPURL[d.PURL] {
			unfixed := audit.IsUnfixed(d.PURL, adv)
			if !unfixed || showUnfixed {
				diags = append(diags, diagnosticFor(d, adv, webURL, ignore, unfixed))
				if first {
					counts[d.PURL]++
				}
			}
		}
	}

	return diags, counts
}

// diagnosticFor builds the diagnostic of one advisory on one dependency: an
// unfixed advisory says so in the message, and one accepted by the ignore file
// is downgraded to a hint that carries the rule's reason.
func diagnosticFor(d manifest.Dependency, adv client.Advisory, webURL string, ignore *audit.IgnoreFile, unfixed bool) protocol.Diagnostic {
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
		CodeDescription: &protocol.CodeDescription{HRef: weblink.Advisory(webURL, adv.ID)},
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
