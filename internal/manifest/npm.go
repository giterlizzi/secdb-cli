// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"cmp"
	"encoding/json"
	"net/url"
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
//
// Two formats share the file name. Classic (Yarn 1):
//
//	lodash@^4.17.0, lodash@^4.17.21:
//	  version "4.17.21"
//
// Berry (Yarn 2+), YAML-like, which also records the resolved package:
//
//	"lodash@npm:^4.17.0, lodash@npm:^4.17.21":
//	  version: 4.17.21
//	  resolution: "lodash@npm:4.17.21"

// yarnEntry is one top-level block of a yarn.lock: its header line and the
// fields of its first indentation level (nested blocks such as "dependencies"
// are ignored).
type yarnEntry struct {
	header     string
	line       int
	version    string
	resolution string
}

func parseYarnLock(content []byte) ([]Dependency, error) {
	c := yarnCollector{seen: make(map[string]bool)}
	var cur *yarnEntry

	for i, raw := range strings.Split(string(content), "\n") {
		raw = strings.TrimRight(raw, "\r")
		switch {
		case strings.TrimSpace(raw) == "" || strings.HasPrefix(raw, "#"):
		case raw[0] != ' ' && raw[0] != '\t':
			// Header line: one or more comma-separated specs, ":"-terminated.
			c.add(cur)
			cur = &yarnEntry{header: strings.TrimSuffix(strings.TrimSpace(raw), ":"), line: i + 1}
		case cur != nil && strings.HasPrefix(raw, "  ") && raw[2] != ' ':
			key, value := yarnField(raw)
			switch key {
			case "version":
				cur.version = value
			case "resolution":
				cur.resolution = value
			}
		}
	}
	c.add(cur)
	return c.deps, nil
}

// yarnCollector gathers the yarn.lock dependencies in file order, de-duplicated
// by PURL (e.g. a patched package and the original it patches).
type yarnCollector struct {
	deps []Dependency
	seen map[string]bool
}

func (c *yarnCollector) add(e *yarnEntry) {
	if e == nil {
		return
	}
	name, version, ok := e.pkg()
	if !ok {
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
		Direct:    false,
		Range:     lineRange(e.line),
	})
}

// pkg returns the registry package an entry resolves to; ok is false for the
// berry "__metadata" block and for anything that isn't a registry package
// (workspaces, local links and files, git, tarball URLs).
func (e *yarnEntry) pkg() (name, version string, ok bool) {
	if e.resolution != "" {
		return berryResolution(e.resolution)
	}
	name, ok = yarnNameFromHeader(e.header)
	return name, e.version, ok && e.version != ""
}

// yarnField splits an entry field in either format, `version "4.17.21"` or
// `version: 4.17.21`, into its key and unquoted value.
func yarnField(line string) (key, value string) {
	line = strings.TrimSpace(line)
	i := strings.IndexAny(line, " :")
	if i < 0 {
		return line, ""
	}
	return line[:i], strings.Trim(strings.TrimLeft(line[i:], ": "), `"`)
}

// berryResolution reads the package a yarn berry "resolution" points to:
// "lodash@npm:4.17.21" is lodash 4.17.21, the alias
// "string-width-cjs@npm:string-width@4.2.3" is string-width 4.2.3, and the patch
// "resolve@patch:resolve@npm%3A1.22.1#..." is the package it patches (resolve
// 1.22.1, audited as such: the patch may not fix anything). Any other protocol
// (workspace:, link:, portal:, file:, git, tarball URLs) isn't a registry
// package, so ok is false.
func berryResolution(res string) (name, version string, ok bool) {
	ident, ref, found := cutYarnIdent(res)
	if !found {
		return "", "", false
	}
	switch {
	case strings.HasPrefix(ref, "npm:"):
		ref = strings.TrimPrefix(ref, "npm:")
		if alias, v, isAlias := cutYarnIdent(ref); isAlias {
			return alias, v, v != ""
		}
		return ident, ref, ref != ""
	case strings.HasPrefix(ref, "patch:"):
		inner, _, _ := strings.Cut(strings.TrimPrefix(ref, "patch:"), "#")
		inner, err := url.PathUnescape(inner)
		if err != nil {
			return "", "", false
		}
		return berryResolution(inner)
	}
	return "", "", false
}

// yarnNameFromHeader extracts the package name from a classic yarn.lock header,
// dropping the version range: `"lodash@^4.17.0"` -> "lodash",
// `"@scope/pkg@npm:^1.0.0"` -> "@scope/pkg", and the alias
// `"string-width-cjs@npm:string-width@^4.2.0"` -> "string-width". ok is false
// when the range isn't a registry one (file:, link:, git, URLs) or there's no
// "@" (e.g. the berry "__metadata" block).
func yarnNameFromHeader(header string) (string, bool) {
	spec, _, _ := strings.Cut(header, ",")
	spec = strings.Trim(strings.TrimSpace(spec), `"`)
	name, ref, ok := cutYarnIdent(spec)
	if !ok {
		return "", false
	}
	ref = strings.TrimPrefix(ref, "npm:")
	if alias, aliasRef, isAlias := cutYarnIdent(ref); isAlias {
		name, ref = alias, aliasRef
	}
	// A registry range ("^1.2.0", "1.x || 2.x", "latest") has no protocol and no
	// path; anything else ("file:../x", "user/repo", "https://...") isn't audited.
	return name, !strings.ContainsAny(ref, ":/")
}

// cutYarnIdent splits "name@rest" at the "@" that ends the package name,
// skipping the leading "@" of a scoped name: "@scope/pkg@npm:1.0.0" ->
// "@scope/pkg", "npm:1.0.0".
func cutYarnIdent(s string) (name, rest string, ok bool) {
	if len(s) < 2 {
		return "", "", false
	}
	i := strings.Index(s[1:], "@")
	if i < 0 {
		return "", "", false
	}
	return s[:i+1], s[i+2:], true
}

func sortDeps(deps []Dependency) {
	slices.SortFunc(deps, func(a, b Dependency) int { return cmp.Compare(a.PURL, b.PURL) })
}
