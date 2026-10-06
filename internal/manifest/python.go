// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"regexp"
	"strings"

	packageurl "github.com/package-url/packageurl-go"
)

// pythonParser handles requirements*.txt. It's line-based, so every dependency
// records its source line. "-r"/"-c" includes and option lines are skipped (no
// cross-file resolution). The audited version comes from the specifiers (see
// auditedVersion); a line without a usable one is skipped.
type pythonParser struct{}

func (pythonParser) Ecosystem() string  { return "python" }
func (pythonParser) Patterns() []string { return []string{"requirements*.txt"} }

// pyRequirementRe captures the name and the specifiers of a requirement line,
// dropping the optional "[extras]" (e.g. "Django[argon2]>=4.2,<5").
var pyRequirementRe = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$`)

// pySpecifierRe captures the operator and the version of one specifier.
var pySpecifierRe = regexp.MustCompile(`^\s*(===|==|~=|!=|>=|<=|>|<)\s*([A-Za-z0-9][A-Za-z0-9.*+!-]*)\s*$`)

var pep503Re = regexp.MustCompile(`[-_.]+`)

func (pythonParser) Parse(filename string, content []byte) ([]Dependency, error) {
	var deps []Dependency

	for i, raw := range splitLines(content) {
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
		if m == nil {
			continue
		}
		version := auditedVersion(m[2])
		if version == "" {
			continue // no usable version: nothing auditable
		}

		name := m[1]
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

// auditedVersion picks the version to audit from comma-separated specifiers:
// the exact one ("==", "==="), else the lower bound of ">=" or "~=". The other
// operators ("!=", "<", "<=", ">") name a version that is excluded or only a
// bound, and a wildcard ("==2.*") isn't a version, so they give nothing on
// their own.
func auditedVersion(specifiers string) string {
	var lowerBound string
	for spec := range strings.SplitSeq(specifiers, ",") {
		m := pySpecifierRe.FindStringSubmatch(spec)
		if m == nil || strings.Contains(m[2], "*") {
			continue
		}
		switch m[1] {
		case "==", "===":
			return m[2]
		case ">=", "~=":
			if lowerBound == "" {
				lowerBound = m[2]
			}
		}
	}
	return lowerBound
}

// pep503Normalize applies PEP 503 name normalization (runs of "-", "_" and "."
// collapse to a single "-", lowercased), the form the pypi PURL type expects.
//
// https://peps.python.org/pep-0503/
func pep503Normalize(name string) string {
	return strings.ToLower(pep503Re.ReplaceAllString(name, "-"))
}
