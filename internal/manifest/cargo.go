// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"regexp"
	"strings"

	packageurl "github.com/package-url/packageurl-go"
)

type cargoParser struct{}

func (cargoParser) Ecosystem() string  { return "cargo" }
func (cargoParser) Patterns() []string { return []string{"Cargo.lock"} }

var cargoLockRe = regexp.MustCompile(`^(name|version|source) = "([^"]*)"$`)

func (cargoParser) Parse(filename string, content []byte) ([]Dependency, error) {
	var deps []Dependency
	var name, version, source string
	start, end := 0, 0

	flush := func() {
		if start > 0 && name != "" && version != "" && isCargoRegistry(source) {
			deps = append(deps, Dependency{
				PURL:      packageurl.NewPackageURL("cargo", "", name, version, nil, "").ToString(),
				Ecosystem: "cargo",
				Name:      name,
				Version:   version,
				Range:     linesRange(start, end),
			})
		}
		name, version, source, start, end = "", "", "", 0, 0
	}

	for i, line := range splitLines(content) {
		if strings.HasPrefix(line, "[") {
			flush()
			if line == "[[package]]" {
				start, end = i+1, i+1
			}
			continue
		}

		if start == 0 {
			continue
		}

		if line != "" {
			end = i + 1
		}

		if m := cargoLockRe.FindStringSubmatch(line); m != nil {
			switch m[1] {
			case "name":
				name = m[2]
			case "version":
				version = m[2]
			case "source":
				source = m[2]
			}
		}
	}

	flush()
	return deps, nil
}

// isCargoRegistry reports whether a package comes from a registry: workspace
// members have no source, git and path dependencies another prefix.
func isCargoRegistry(source string) bool {
	return strings.HasPrefix(source, "registry+") || strings.HasPrefix(source, "sparse+")
}
