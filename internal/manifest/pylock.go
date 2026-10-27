// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	packageurl "github.com/package-url/packageurl-go"
)

// pylockParser handles pylock.toml and pylock.<name>.toml (PEP 751): the
// [[packages]] entries from an index. The ones from a VCS, a local directory
// or an archive are skipped, and so are the ones with no version (a source
// tree). [[packages.wheels]], [packages.sdist] and the other sub-tables stay
// in their entry, [tool.x] ends it. Direct is not recorded by the format.
type pylockParser struct{}

func (pylockParser) Ecosystem() string  { return "python" }
func (pylockParser) Patterns() []string { return []string{"pylock.*.toml", "pylock.toml"} }

func (pylockParser) Parse(filename string, content []byte) ([]Dependency, error) {
	var deps []Dependency

	for _, p := range tomlPackages(content, "packages") {
		name, version := p.fields["name"], p.fields["version"]

		if name == "" || version == "" || !isPylockIndex(p.fields) {
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

// isPylockIndex reports whether a [[packages]] entry comes from an index:
// the ones from a VCS, a local directory or an archive are skipped.
func isPylockIndex(fields map[string]string) bool {
	return fields["vcs.type"] == "" && fields["directory.path"] == "" &&
		fields["archive.url"] == "" && fields["archive.path"] == ""
}
