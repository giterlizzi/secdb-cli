// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"regexp"
	"strings"

	packageurl "github.com/package-url/packageurl-go"
)

// gradleParser handles gradle.lockfile, written by Gradle 6.4+ dependency
// locking: one resolved dependency per line, transitive ones included,
// "group:artifact:version=configuration,..." ("empty=..." lists the
// configurations without dependencies; "#" lines are comments). The lock
// doesn't record what build.gradle declares, so none is reported as direct.
// Test-only dependencies are audited too, as the dev dependencies of the other
// lock files.
type gradleParser struct{}

func (gradleParser) Ecosystem() string  { return "maven" }
func (gradleParser) Patterns() []string { return []string{"gradle.lockfile"} }

var gradleLockRe = regexp.MustCompile(`^([^:=\s]+):([^:=\s]+):([^:=\s]+)=`)

func (gradleParser) Parse(filename string, content []byte) ([]Dependency, error) {
	var deps []Dependency

	for i, line := range splitLines(content) {
		if strings.HasPrefix(line, "#") {
			continue
		}

		matches := gradleLockRe.FindStringSubmatch(line)

		if matches != nil {
			group, artifact, version := matches[1], matches[2], matches[3]

			deps = append(deps, Dependency{
				PURL:      packageurl.NewPackageURL("maven", group, artifact, version, nil, "").ToString(),
				Ecosystem: "maven",
				Name:      group + ":" + artifact,
				Version:   version,
				Range:     lineRange(i + 1),
			})
		}
	}
	return deps, nil
}
