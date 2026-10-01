// SPDX-License-Identifier: Apache-2.0

package lsp

import (
	"log/slog"

	"github.com/giterlizzi/secdb-cli/internal/audit"
	"github.com/giterlizzi/secdb-cli/internal/manifest"

	"github.com/tliron/glsp"
	protocol "github.com/tliron/glsp/protocol_3_16"
)

func (s *Server) auditManifest(ctx *glsp.Context, uri protocol.DocumentUri, content []byte) (int, error) {

	filename, err := uriToFilename(uri)
	if err != nil {
		return 0, err
	}

	slog.Debug("audit", "filename", filename)

	deps, err := manifest.Parse(filename, content)
	if err != nil {
		return 0, err
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
		s.publishDependencies(ctx, uri, deps, map[string]int{})
		return 0, nil
	}

	// The dependencies don't depend on the audit: send them right away (without
	// counts), so the client has them even when the API is slow or fails.
	s.publishDependencies(ctx, uri, deps, nil)

	data, err := s.client.PURLAudit(purls)
	if err != nil {
		return 0, err
	}

	diags, advisories := s.buildDiagnostics(deps, data, filename)
	publishDiagnostics(ctx, uri, diags)
	s.publishDependencies(ctx, uri, deps, advisories)

	return len(diags), nil
}
