// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"cmp"
	"encoding/json"
	"slices"
	"strings"

	packageurl "github.com/package-url/packageurl-go"
)

// npmParser handles the resolved npm lockfiles. package-lock.json isn't parsed
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

// --- package-lock.json ---

type npmLock struct {
	// v2/v3: a flat map keyed by install path ("node_modules/foo").
	Packages map[string]npmLockPackage `json:"packages"`
	// v1: a nested tree.
	Dependencies map[string]npmLockDep `json:"dependencies"`
}

type npmLockPackage struct {
	Version string `json:"version"`
}

type npmLockDep struct {
	Version      string                `json:"version"`
	Dependencies map[string]npmLockDep `json:"dependencies"`
}

func parseNpmLock(content []byte) ([]Dependency, error) {
	var lock npmLock
	if err := json.Unmarshal(content, &lock); err != nil {
		return nil, err
	}

	c := npmCollector{seen: make(map[string]bool)}
	if len(lock.Packages) > 0 {
		c.addInstallPaths(lock.Packages) // v2/v3
	} else {
		c.addTree(lock.Dependencies, true) // v1
	}

	sortDeps(c.deps)
	return c.deps, nil
}

// npmCollector gathers the dependencies of a package-lock.json, de-duplicated
// by PURL (the same name@version can be installed at several paths).
type npmCollector struct {
	deps []Dependency
	seen map[string]bool
}

func (c *npmCollector) add(name, version string, direct bool) {
	if name == "" || version == "" {
		return
	}
	purl := npmPURL(name, version)
	if c.seen[purl] {
		return
	}
	c.seen[purl] = true
	c.deps = append(c.deps, Dependency{
		PURL:      purl,
		Ecosystem: "npm",
		Name:      name,
		Version:   version,
		Direct:    direct,
	})
}

// addInstallPaths adds the v2/v3 flat "packages" map, keyed by install path
// ("node_modules/foo", "node_modules/foo/node_modules/bar").
func (c *npmCollector) addInstallPaths(packages map[string]npmLockPackage) {
	for path, pkg := range packages {
		if path == "" { // the root project itself
			continue
		}
		name := path[strings.LastIndex(path, "node_modules/")+len("node_modules/"):]
		// A top-level install path (single node_modules segment) is a direct
		// dependency; anything nested deeper is transitive.
		direct := !strings.Contains(strings.TrimPrefix(path, "node_modules/"), "node_modules/")
		c.add(name, pkg.Version, direct)
	}
}

// addTree adds the v1 nested "dependencies" tree; only its first level is direct.
func (c *npmCollector) addTree(tree map[string]npmLockDep, direct bool) {
	for name, d := range tree {
		c.add(name, d.Version, direct)
		c.addTree(d.Dependencies, false)
	}
}

// --- yarn.lock ---

func parseYarnLock(content []byte) ([]Dependency, error) {
	var deps []Dependency

	currentName := ""
	currentLine := 0

	for i, raw := range strings.Split(string(content), "\n") {
		lineNo := i + 1

		if strings.TrimSpace(raw) == "" || strings.HasPrefix(raw, "#") {
			continue
		}

		if !strings.HasPrefix(raw, " ") && !strings.HasPrefix(raw, "\t") {
			// Header line: one or more comma-separated "name@range" specs, ":"-terminated.
			currentName = yarnNameFromHeader(strings.TrimSuffix(strings.TrimSpace(raw), ":"))
			currentLine = lineNo
			continue
		}

		trimmed := strings.TrimSpace(raw)
		if !strings.HasPrefix(trimmed, "version") || currentName == "" {
			continue
		}
		version := strings.Trim(strings.TrimSpace(strings.TrimPrefix(trimmed, "version")), `"`)
		// Skip the yarn-berry "__metadata:" block (its "version" is a schema number).
		if version == "" || strings.HasPrefix(currentName, "__") {
			currentName = ""
			continue
		}

		deps = append(deps, Dependency{
			PURL:      npmPURL(currentName, version),
			Ecosystem: "npm",
			Name:      currentName,
			Version:   version,
			Direct:    false,
			Range:     lineRange(currentLine),
		})
		currentName = ""
	}
	return deps, nil
}

// yarnNameFromHeader extracts the package name from a yarn.lock header, dropping
// the version range: `"lodash@^4.17.0"` -> "lodash",
// `"@scope/pkg@npm:^1.0.0"` -> "@scope/pkg".
func yarnNameFromHeader(header string) string {
	if i := strings.Index(header, ","); i >= 0 {
		header = header[:i]
	}
	header = strings.Trim(strings.TrimSpace(header), `"`)
	// The range is everything after the last "@"; a leading "@" (scope) is kept.
	if at := strings.LastIndex(header, "@"); at > 0 {
		header = header[:at]
	}
	return header
}

func sortDeps(deps []Dependency) {
	slices.SortFunc(deps, func(a, b Dependency) int { return cmp.Compare(a.PURL, b.PURL) })
}
