// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	packageurl "github.com/package-url/packageurl-go"
)

// pdmParser handles pdm.lock: the packages from a package index (PyPI or a
// private one, which leave no trace in the entry); git, local path and direct
// URL dependencies are skipped. A package locked with extras repeats as a
// second entry, de-duplicated later by audit.NormalizePURLs. Every group is
// audited, dev included; the lock doesn't record which dependencies
// pyproject.toml declares, so none is Direct.
type pdmParser struct{}

func (pdmParser) Ecosystem() string  { return "python" }
func (pdmParser) Patterns() []string { return []string{"pdm.lock"} }

func (pdmParser) Parse(filename string, content []byte) ([]Dependency, error) {
	var deps []Dependency

	for _, p := range tomlPackages(content, "package") {
		name, version := p.fields["name"], p.fields["version"]

		if name == "" || version == "" || !isPDMIndex(p.fields) {
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

// isPDMIndex reports whether a pdm.lock entry comes from a package index:
// PyPI or a private one leave no trace, while git, local path and direct
// URL dependencies record a key of their own.
func isPDMIndex(fields map[string]string) bool {
	return fields["git"] == "" && fields["path"] == "" && fields["url"] == ""
}
