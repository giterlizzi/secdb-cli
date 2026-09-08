// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"encoding/json"
	"sort"
	"strings"

	packageurl "github.com/package-url/packageurl-go"
)

// NPMParser handles the resolved npm lockfiles. package-lock.json isn't parsed
// with position tracking, so its dependencies carry an empty Range; yarn.lock is
// line-based, so it does record the header line of each entry. package.json is
// intentionally not handled: its version ranges describe what's allowed, not
// what's installed, so auditing it would be imprecise.
type NPMParser struct{}

func (NPMParser) Ecosystem() string { return "npm" }
func (NPMParser) Patterns() []string {
	return []string{"package-lock.json", "yarn.lock"}
}

func (NPMParser) Parse(filename string, content []byte) ([]Dependency, error) {
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
		if i := strings.Index(name, "/"); i >= 0 {
			namespace, name = name[:i], name[i+1:]
		}
	}
	return packageurl.NewPackageURL("npm", namespace, name, version, nil, "").ToString()
}

// --- package-lock.json ---

type npmLock struct {
	// v2/v3: a flat map keyed by install path ("node_modules/foo").
	Packages map[string]struct {
		Version string `json:"version"`
	} `json:"packages"`
	// v1: a nested tree.
	Dependencies map[string]npmLockDep `json:"dependencies"`
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

	var deps []Dependency
	seen := make(map[string]bool)
	add := func(name, version string, direct bool) {
		if name == "" || version == "" {
			return
		}
		purl := npmPURL(name, version)
		if seen[purl] {
			return
		}
		seen[purl] = true
		deps = append(deps, Dependency{
			PURL:      purl,
			Ecosystem: "npm",
			Name:      name,
			Version:   version,
			Direct:    direct,
		})
	}

	if len(lock.Packages) > 0 { // v2/v3
		for path, pkg := range lock.Packages {
			if path == "" { // the root project itself
				continue
			}
			rel := path[strings.LastIndex(path, "node_modules/")+len("node_modules/"):]
			// A top-level install path (single node_modules segment) is a
			// direct dependency; anything nested deeper is transitive.
			direct := !strings.Contains(strings.TrimPrefix(path, "node_modules/"), "node_modules/")
			add(rel, pkg.Version, direct)
		}
	} else { // v1
		var walk func(m map[string]npmLockDep, direct bool)
		walk = func(m map[string]npmLockDep, direct bool) {
			for name, d := range m {
				add(name, d.Version, direct)
				walk(d.Dependencies, false)
			}
		}
		walk(lock.Dependencies, true)
	}

	sortDeps(deps)
	return deps, nil
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
	sort.Slice(deps, func(i, j int) bool { return deps[i].PURL < deps[j].PURL })
}
