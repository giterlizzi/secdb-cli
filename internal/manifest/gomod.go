// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"strings"

	packageurl "github.com/package-url/packageurl-go"
	"golang.org/x/mod/modfile"
)

// goModParser handles go.mod. It uses golang.org/x/mod/modfile, which yields the
// exact source line of every require directive for free, so Go dependencies get
// precise ranges (unlike the JSON lock files).
type goModParser struct{}

func (goModParser) Ecosystem() string  { return "go" }
func (goModParser) Patterns() []string { return []string{"go.mod"} }

func (goModParser) Parse(filename string, content []byte) ([]Dependency, error) {
	m, err := modfile.ParseLax(filename, content, nil)
	if err != nil {
		return nil, err
	}

	deps := make([]Dependency, 0, len(m.Require))
	for _, r := range m.Require {
		namespace, name := splitGoModule(r.Mod.Path)
		version := strings.TrimPrefix(r.Mod.Version, "v")

		d := Dependency{
			PURL:      packageurl.NewPackageURL("golang", namespace, name, version, nil, "").ToString(),
			Ecosystem: "go",
			Name:      r.Mod.Path,
			Version:   version,
			Direct:    !r.Indirect,
		}
		if r.Syntax != nil {
			d.Range = Range{
				Start: Position{Line: r.Syntax.Start.Line, Column: r.Syntax.Start.LineRune},
				End:   Position{Line: r.Syntax.End.Line, Column: r.Syntax.End.LineRune},
			}
		}
		deps = append(deps, d)
	}
	return deps, nil
}

// splitGoModule splits a Go module path into the PURL namespace (everything but
// the last segment) and name (the last segment): "github.com/foo/bar" becomes
// ("github.com/foo", "bar").
func splitGoModule(path string) (namespace, name string) {
	if i := strings.LastIndex(path, "/"); i >= 0 {
		return path[:i], path[i+1:]
	}
	return "", path
}
