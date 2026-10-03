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
	// v2/v3: a flat map keyed by install path ("node_modules/foo"); the "" key is
	// the project itself, a key without node_modules a workspace package.
	Packages map[string]npmLockPackage `json:"packages"`
	// v1: a nested tree.
	Dependencies map[string]npmLockDep `json:"dependencies"`
}

type npmLockPackage struct {
	// Name is set when it differs from the install path: an alias
	// ("node_modules/string-width-cjs" installing string-width) or a workspace.
	Name    string `json:"name"`
	Version string `json:"version"`
	// Link marks a symlink to a workspace package, which isn't a registry package.
	Link bool `json:"link"`

	// What the project or a workspace declares, as in its package.json.
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
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

	c := newNpmCollector()
	if len(lock.Packages) > 0 {
		c.addInstallPaths(lock.Packages) // v2/v3
	} else {
		c.addTree(lock.Dependencies) // v1
	}

	sortDeps(c.deps)
	return c.deps, nil
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

// addInstallPaths adds the v2/v3 flat "packages" map, keyed by install path
// ("node_modules/foo", "node_modules/foo/node_modules/bar",
// "packages/lib/node_modules/baz"). The project ("") and the workspace
// packages ("packages/lib") are local code, not dependencies: they only tell
// which dependencies are direct.
func (c *npmCollector) addInstallPaths(packages map[string]npmLockPackage) {
	direct := npmDeclared(packages)
	for path, pkg := range packages {
		owner, installed, ok := cutNodeModules(path)
		if !ok || pkg.Link {
			continue
		}
		name := installed
		if pkg.Name != "" {
			name = pkg.Name
		}
		// npm hoists packages to the top-level node_modules, so a top-level
		// install isn't necessarily direct: it is when the project or a workspace
		// declares it and it's installed for one of them (not nested in a package).
		c.add(name, pkg.Version, direct[installed] && isLocalPath(packages, owner), Range{})
	}
}

// isLocalPath reports whether path is the project ("") or a workspace package,
// as opposed to a package installed under node_modules.
func isLocalPath(packages map[string]npmLockPackage, path string) bool {
	_, ok := packages[path]
	return ok && !strings.Contains(path, "node_modules/")
}

// npmDeclared returns the names the project and its workspaces declare, in
// any dependency field: those are the direct dependencies.
func npmDeclared(packages map[string]npmLockPackage) map[string]bool {
	declared := make(map[string]bool)
	for path, pkg := range packages {
		if !isLocalPath(packages, path) {
			continue
		}
		for _, deps := range []map[string]string{pkg.Dependencies, pkg.DevDependencies, pkg.OptionalDependencies, pkg.PeerDependencies} {
			for name := range deps {
				declared[name] = true
			}
		}
	}
	return declared
}

// cutNodeModules splits an install path at its last "node_modules/" segment:
// "packages/lib/node_modules/@scope/x" -> "packages/lib", "@scope/x".
// ok is false for a path with no node_modules (the project or a workspace).
func cutNodeModules(path string) (owner, name string, ok bool) {
	i := strings.LastIndex(path, "node_modules/")
	if i < 0 {
		return "", "", false
	}
	return strings.TrimSuffix(path[:i], "/"), path[i+len("node_modules/"):], true
}

// addTree adds the v1 nested "dependencies" tree. v1 doesn't record what the
// project declares and its top level is hoisted (it holds transitive packages
// too), so every dependency is reported as not direct rather than guessed.
func (c *npmCollector) addTree(tree map[string]npmLockDep) {
	for name, d := range tree {
		c.add(name, d.Version, false, Range{})
		c.addTree(d.Dependencies)
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

// yarnEntry is one top-level block of a yarn.lock: its header line, the fields
// of its first indentation level and the specs its "dependencies" block lists
// (other nested blocks are ignored).
type yarnEntry struct {
	header     string
	line       int
	version    string
	resolution string
	deps       []string // "ms@npm:^2.1.3", the form a header spec takes
}

// parseYarnLock reads the entries first, then adds them: a berry workspace
// entry lists the workspace's direct dependencies (devDependencies included)
// and can come after them in the file. Classic lockfiles have no such entry,
// so their dependencies are never direct.
func parseYarnLock(content []byte) ([]Dependency, error) {
	entries := readYarnEntries(content)

	direct := make(map[string]bool)
	for _, e := range entries {
		if e.isWorkspace() {
			for _, spec := range e.deps {
				direct[spec] = true
			}
		}
	}

	c := newNpmCollector()
	for _, e := range entries {
		if name, version, ok := e.pkg(); ok {
			c.add(name, version, e.declaredIn(direct), lineRange(e.line))
		}
	}
	return c.deps, nil
}

func readYarnEntries(content []byte) []*yarnEntry {
	var entries []*yarnEntry
	var cur *yarnEntry
	inDeps := false

	for i, raw := range strings.Split(string(content), "\n") {
		raw = strings.TrimRight(raw, "\r")
		indent := len(raw) - len(strings.TrimLeft(raw, " \t"))
		switch {
		case strings.TrimSpace(raw) == "" || strings.HasPrefix(raw, "#"):
		case indent == 0:
			// Header line: one or more comma-separated specs, ":"-terminated.
			cur = &yarnEntry{header: strings.TrimSuffix(strings.TrimSpace(raw), ":"), line: i + 1}
			entries = append(entries, cur)
			inDeps = false
		case cur == nil:
		case indent == 2:
			key, value := yarnField(raw)
			cur.set(key, value)
			inDeps = key == "dependencies"
		case indent == 4 && inDeps:
			name, rng := yarnField(raw)
			cur.deps = append(cur.deps, name+"@"+rng)
		}
	}
	return entries
}

func (e *yarnEntry) set(key, value string) {
	switch key {
	case "version":
		e.version = value
	case "resolution":
		e.resolution = value
	}
}

// specs returns the header's specs: `"lodash@npm:^4.17.0, lodash@npm:^4.17.21"`
// -> "lodash@npm:^4.17.0", "lodash@npm:^4.17.21".
func (e *yarnEntry) specs() []string {
	specs := strings.Split(e.header, ",")
	for i, spec := range specs {
		specs[i] = strings.Trim(strings.TrimSpace(spec), `"`)
	}
	return specs
}

// isWorkspace reports whether the entry is a berry workspace (the project or
// one of its packages): `resolution: "my-app@workspace:."`.
func (e *yarnEntry) isWorkspace() bool {
	_, ref, ok := cutYarnIdent(e.resolution)
	return ok && strings.HasPrefix(ref, "workspace:")
}

// declaredIn reports whether a workspace declares one of the entry's specs.
func (e *yarnEntry) declaredIn(direct map[string]bool) bool {
	for _, spec := range e.specs() {
		if direct[spec] {
			return true
		}
	}
	return false
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
