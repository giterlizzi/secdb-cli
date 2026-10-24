// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"strings"

	packageurl "github.com/package-url/packageurl-go"
)

type cargoParser struct{}

func (cargoParser) Ecosystem() string  { return "cargo" }
func (cargoParser) Patterns() []string { return []string{"Cargo.lock"} }

func (cargoParser) Parse(filename string, content []byte) ([]Dependency, error) {
	var deps []Dependency

	for _, p := range tomlPackages(content) {
		name, version := p.fields["name"], p.fields["version"]

		if name == "" || version == "" || !isCargoRegistry(p.fields["source"]) {
			continue
		}

		deps = append(deps, Dependency{
			PURL:      packageurl.NewPackageURL("cargo", "", name, version, nil, "").ToString(),
			Ecosystem: "cargo",
			Name:      name,
			Version:   version,
			Range:     linesRange(p.start, p.end),
		})
	}

	return deps, nil
}

// isCargoRegistry reports whether a package comes from a registry: workspace
// members have no source, git and path dependencies another prefix.
func isCargoRegistry(source string) bool {
	return strings.HasPrefix(source, "registry+") || strings.HasPrefix(source, "sparse+")
}
