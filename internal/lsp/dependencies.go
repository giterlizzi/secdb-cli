// SPDX-License-Identifier: Apache-2.0

package lsp

import (
	"github.com/giterlizzi/secdb-cli/internal/manifest"

	"github.com/tliron/glsp"
	protocol "github.com/tliron/glsp/protocol_3_16"
)

// dependenciesMethod is the custom server-to-client notification carrying a
// manifest's dependencies, the way publishDiagnostics carries its findings. It
// is sent twice per audit: once right after parsing (no advisory counts), then
// again with the counts if the audit succeeds. Only clients that declare the
// experimental capability {"secdbDependencies": true} receive it (e.g. the VS
// Code extension's dependency tree): other clients never get a method they
// don't know.
const (
	dependenciesMethod     = "secdb/dependencies"
	dependenciesCapability = "secdbDependencies"
)

type dependenciesParams struct {
	URI          protocol.DocumentUri `json:"uri"`
	Dependencies []dependencyInfo     `json:"dependencies"`
}

type dependencyInfo struct {
	PURL      string `json:"purl"`
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Direct    bool   `json:"direct"`
	Line      int    `json:"line,omitempty"`

	// Advisories is absent while the manifest isn't audited yet (or the audit
	// failed); 0 means audited and clean.
	Advisories *int `json:"advisories,omitempty"`
}

// publishDependencies sends the manifest's dependencies, with their advisory
// counts keyed by PURL (nil when not audited, so the counts are omitted), to a
// client that declared the capability.
func (s *Server) publishDependencies(ctx *glsp.Context, uri protocol.DocumentUri, deps []manifest.Dependency, advisories map[string]int) {
	if !s.sendDependencies {
		return
	}
	infos := make([]dependencyInfo, 0, len(deps))
	for _, d := range deps {
		var count *int
		if advisories != nil {
			n := advisories[d.PURL]
			count = &n
		}
		infos = append(infos, dependencyInfo{
			PURL:       d.PURL,
			Ecosystem:  d.Ecosystem,
			Name:       d.Name,
			Version:    d.Version,
			Direct:     d.Direct,
			Line:       d.Range.Start.Line,
			Advisories: count,
		})
	}
	ctx.Notify(dependenciesMethod, dependenciesParams{URI: uri, Dependencies: infos})
}
