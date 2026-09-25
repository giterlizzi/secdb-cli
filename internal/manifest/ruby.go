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
// six spaces and are skipped.
type rubyParser struct{}

func (rubyParser) Ecosystem() string  { return "ruby" }
func (rubyParser) Patterns() []string { return []string{"Gemfile.lock"} }

var gemSpecRe = regexp.MustCompile(`^    ([A-Za-z0-9._-]+) \(([^)]+)\)$`)

func (rubyParser) Parse(filename string, content []byte) ([]Dependency, error) {
	var deps []Dependency
	inSpecs := false

	for i, raw := range strings.Split(string(content), "\n") {
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
			Direct:    true,
			Range:     lineRange(i + 1),
		})
	}
	return deps, nil
}
