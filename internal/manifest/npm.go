// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"cmp"
	"slices"
	"strings"

	packageurl "github.com/package-url/packageurl-go"
)

// npmParser handles the resolved npm lockfiles: package-lock.json
// (npm_lock.go) and yarn.lock (yarn_lock.go). package-lock.json isn't parsed
// with position tracking, so its dependencies carry an empty Range; yarn.lock is
// line-based, so it does record the header line of each entry. package.json is
// intentionally not handled: its version ranges describe what's allowed, not
// what's installed, so auditing it would be imprecise.
type npmParser struct{}

func (npmParser) Ecosystem() string { return "npm" }
func (npmParser) Patterns() []string {
	return []string{"package-lock.json", "yarn.lock"}
}

func (npmParser) Parse(filename string, content []byte) ([]Dependency, error) {
	if filename == "yarn.lock" {
		return parseYarnLock(content)
	}
	return parseNpmLock(content)
}

// npmPURL builds a pkg:npm PURL, mapping a scoped name "@scope/pkg" onto the
// PURL namespace ("@scope") and name ("pkg"); packageurl-go percent-encodes the
// leading "@".
func npmPURL(name, version string) string {
	namespace := ""
	if strings.HasPrefix(name, "@") {
		if ns, rest, ok := strings.Cut(name, "/"); ok {
			namespace, name = ns, rest
		}
	}
	return packageurl.NewPackageURL("npm", namespace, name, version, nil, "").ToString()
}

// npmCollector gathers the dependencies of a package-lock.json or yarn.lock in
// insertion order, de-duplicated by PURL (the same name@version can be installed
// at several paths, or listed as a package and as its patched version): a
// package is direct if any of its occurrences is, and keeps the first one's Range.
type npmCollector struct {
	deps  []Dependency
	index map[string]int // PURL -> position in deps
}

func newNpmCollector() *npmCollector {
	return &npmCollector{index: make(map[string]int)}
}

func (c *npmCollector) add(name, version string, direct bool, rng Range) {
	if name == "" || version == "" {
		return
	}
	purl := npmPURL(name, version)
	if i, ok := c.index[purl]; ok {
		c.deps[i].Direct = c.deps[i].Direct || direct
		return
	}
	c.index[purl] = len(c.deps)
	c.deps = append(c.deps, Dependency{
		PURL:      purl,
		Ecosystem: "npm",
		Name:      name,
		Version:   version,
		Direct:    direct,
		Range:     rng,
	})
}

func sortDeps(deps []Dependency) {
	slices.SortFunc(deps, func(a, b Dependency) int { return cmp.Compare(a.PURL, b.PURL) })
}
