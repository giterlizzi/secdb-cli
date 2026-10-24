// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	packageurl "github.com/package-url/packageurl-go"
)

// poetryParser handles poetry.lock: the packages from a package index, PyPI
// (no [package.source]) or a private one; git, directory, file and url
// sources are skipped. Every group is audited, dev included; the lock doesn't
// record which dependencies pyproject.toml declares, so none is Direct.
type poetryParser struct{}

func (poetryParser) Ecosystem() string  { return "python" }
func (poetryParser) Patterns() []string { return []string{"poetry.lock"} }

func (poetryParser) Parse(filename string, content []byte) ([]Dependency, error) {
	var deps []Dependency

	for _, p := range tomlPackages(content) {
		name, version := p.fields["name"], p.fields["version"]

		if name == "" || version == "" || !isPoetryIndex(p.fields["source.type"]) {
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

// isPoetryIndex reports whether a package comes from a package index: PyPI
// (no [package.source]) or a private one (legacy, explicit, supplemental).
// git, directory, file and url sources are code that isn't on PyPI as such.
func isPoetryIndex(sourceType string) bool {
	switch sourceType {
	case "git", "directory", "file", "url":
		return false
	}
	return true
}
