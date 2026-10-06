// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"regexp"
	"strings"

	packageurl "github.com/package-url/packageurl-go"
)

// rubyParser handles Gemfile.lock. Inside the "specs:" section, a gem resolved
// to a concrete version is indented exactly four spaces with the version in
// parentheses ("    rails (7.0.4)"); its own dependency constraints are indented
// six spaces and are skipped. The DEPENDENCIES section lists what the Gemfile
// declares ("  rails (~> 7.0)", "  mygem!" for a git/path source): those gems
// are direct, the rest of the specs transitive.
type rubyParser struct{}

func (rubyParser) Ecosystem() string  { return "ruby" }
func (rubyParser) Patterns() []string { return []string{"Gemfile.lock"} }

var gemSpecRe = regexp.MustCompile(`^    ([A-Za-z0-9._-]+) \(([^)]+)\)$`)

func (rubyParser) Parse(filename string, content []byte) ([]Dependency, error) {
	lines := splitLines(content)
	direct := gemfileDeclared(lines)

	var deps []Dependency
	inSpecs := false

	for i, raw := range lines {
		// A non-indented, non-empty line starts a new top-level section (GEM,
		// PLATFORMS, DEPENDENCIES, ...), ending any specs block.
		if raw != "" && !strings.HasPrefix(raw, " ") {
			inSpecs = false
			continue
		}
		if strings.TrimSpace(raw) == "specs:" {
			inSpecs = true
			continue
		}
		if !inSpecs {
			continue
		}

		m := gemSpecRe.FindStringSubmatch(raw)
		if m == nil {
			continue
		}
		name, version := m[1], m[2]
		deps = append(deps, Dependency{
			PURL:      packageurl.NewPackageURL("gem", "", name, version, nil, "").ToString(),
			Ecosystem: "ruby",
			Name:      name,
			Version:   version,
			Direct:    direct[name],
			Range:     lineRange(i + 1),
		})
	}
	return deps, nil
}

// gemfileDeclared returns the gem names of the DEPENDENCIES section, two-space
// indented: "  rails (~> 7.0)" -> rails, "  mygem!" -> mygem.
func gemfileDeclared(lines []string) map[string]bool {
	declared := make(map[string]bool)
	inDeps := false
	for _, line := range lines {
		switch {
		case line != "" && !strings.HasPrefix(line, " "):
			inDeps = line == "DEPENDENCIES"
		case inDeps && strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "   "):
			if fields := strings.Fields(line); len(fields) > 0 {
				declared[strings.TrimSuffix(fields[0], "!")] = true
			}
		}
	}
	return declared
}
