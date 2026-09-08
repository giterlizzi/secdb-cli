// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"regexp"
	"strings"

	packageurl "github.com/package-url/packageurl-go"
)

// PythonParser handles requirements*.txt. It's line-based, so every dependency
// records its source line. "-r"/"-c" includes and option lines are skipped (no
// cross-file resolution); a dependency is emitted only when the line pins a
// version.
type PythonParser struct{}

func (PythonParser) Ecosystem() string  { return "python" }
func (PythonParser) Patterns() []string { return []string{"requirements*.txt"} }

// pyRequirementRe captures the name, an optional "[extras]", a comparison
// operator, and a version from a requirement line (e.g. "Django[argon2]>=4.2").
var pyRequirementRe = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?:===|==|~=|!=|>=|<=|>|<)?\s*([A-Za-z0-9][A-Za-z0-9.-]*)?`)

var pep503Re = regexp.MustCompile(`[-_.]+`)

func (PythonParser) Parse(filename string, content []byte) ([]Dependency, error) {
	var deps []Dependency

	for i, raw := range strings.Split(string(content), "\n") {
		line := raw
		if idx := strings.Index(line, "#"); idx >= 0 { // inline comment
			line = line[:idx]
		}
		if idx := strings.Index(line, ";"); idx >= 0 { // environment marker
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		// Skip blanks and option lines ("-r other.txt", "-e .", "--hash=...").
		if line == "" || strings.HasPrefix(line, "-") {
			continue
		}

		m := pyRequirementRe.FindStringSubmatch(line)
		if m == nil || m[2] == "" {
			continue // no pinned version: nothing auditable
		}

		name, version := m[1], m[2]
		deps = append(deps, Dependency{
			PURL:      packageurl.NewPackageURL("pypi", "", pep503Normalize(name), version, nil, "").ToString(),
			Ecosystem: "python",
			Name:      name,
			Version:   version,
			Direct:    true,
			Range:     lineRange(i + 1),
		})
	}
	return deps, nil
}

// pep503Normalize applies PEP 503 name normalization (runs of "-", "_" and "."
// collapse to a single "-", lowercased), the form the pypi PURL type expects.
//
// https://peps.python.org/pep-0503/
func pep503Normalize(name string) string {
	return strings.ToLower(pep503Re.ReplaceAllString(name, "-"))
}
