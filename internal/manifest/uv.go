// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	packageurl "github.com/package-url/packageurl-go"
)

// uvParser handles uv.lock: the packages with a `source = { registry = ... }`
// (PyPI or a private index). The project itself (editable, virtual) and the
// git, path, directory and url sources are skipped. Direct is not computed
// yet: the root package lists its dependencies in a multi-line array.
type uvParser struct{}

func (uvParser) Ecosystem() string  { return "python" }
func (uvParser) Patterns() []string { return []string{"uv.lock"} }

func (uvParser) Parse(filename string, content []byte) ([]Dependency, error) {
	var deps []Dependency

	for _, p := range tomlPackages(content) {
		name, version := p.fields["name"], p.fields["version"]

		if name == "" || version == "" || p.fields["source.registry"] == "" {
			continue
		}

		deps = append(deps, Dependency{
			PURL:      packageurl.NewPackageURL("pypi", "", pep503Normalize(name), version, nil, "").ToString(),
			Ecosystem: "python",
			Name:      name,
			Version:   version,
			Range:     linesRange(p.start, p.end),
		})
	}

	return deps, nil
}
