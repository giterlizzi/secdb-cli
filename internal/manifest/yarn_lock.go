// SPDX-License-Identifier: Apache-2.0

package manifest

// yarn.lock, in its two formats. Each top-level block starts with a header
// listing one or more specs ("name@range") and has its fields indented below.
//
// Classic (Yarn 1):
//
//	lodash@^4.17.0, lodash@^4.17.21:
//	  version "4.17.21"
//
// Berry (Yarn 2+), YAML-like; "resolution" names the package actually
// installed, and the project and its workspaces get a block of their own
// listing what they declare (devDependencies included):
//
//	"lodash@npm:^4.17.0, lodash@npm:^4.17.21":
//	  version: 4.17.21
//	  resolution: "lodash@npm:4.17.21"
//
//	"my-app@workspace:.":
//	  resolution: "my-app@workspace:."
//	  dependencies:
//	    lodash: "npm:^4.17.21"
//
// What gets audited, by the part after the name (see splitYarnSpec):
//
//	^4.17.0, 4.17.21          a registry package
//	npm:string-width@^4.2.0   an alias: the real package (string-width)
//	patch:resolve@npm%3A...   berry: the package it patches
//	workspace:, link:, portal:, file:, git, URLs   skipped (not a registry package)
//
// A berry package is direct when a workspace block lists one of its header
// specs; classic lockfiles don't record it, so their packages never are.

import (
	"net/url"
	"strings"
)

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

// parseYarnLock reads the entries first, then adds them: a workspace block can
// come after the packages it declares.
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

	for i, raw := range splitLines(content) {
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

// specs returns the header's specs: `"lodash@npm:^4.17.0, lodash@npm:^4.17.21"`
// -> "lodash@npm:^4.17.0", "lodash@npm:^4.17.21".
func (e *yarnEntry) specs() []string {
	specs := strings.Split(e.header, ",")
	for i, spec := range specs {
		specs[i] = strings.Trim(strings.TrimSpace(spec), `"`)
	}
	return specs
}

// pkg returns the registry package an entry resolves to: from "resolution" in
// berry ("lodash@npm:4.17.21"), from the first header spec and the "version"
// field in classic. ok is false for the berry "__metadata" block and for
// anything that isn't a registry package.
func (e *yarnEntry) pkg() (name, version string, ok bool) {
	if e.resolution == "" {
		name, ref, ok := splitYarnSpec(e.specs()[0])
		return name, e.version, ok && isRegistryRef(ref) && e.version != ""
	}

	name, ref, ok := splitYarnSpec(e.resolution)
	if patched, isPatch := strings.CutPrefix(ref, "patch:"); isPatch {
		// "resolve@patch:resolve@npm%3A1.22.1#...": the package it patches,
		// audited as such (the patch may not fix anything).
		patched, _, _ = strings.Cut(patched, "#")
		patched, err := url.PathUnescape(patched)
		if err != nil {
			return "", "", false
		}
		return (&yarnEntry{resolution: patched}).pkg()
	}
	return name, ref, ok && isRegistryRef(ref) && ref != ""
}

// isWorkspace reports whether the entry is the project or one of its
// workspaces (berry): `resolution: "my-app@workspace:."`.
func (e *yarnEntry) isWorkspace() bool {
	_, ref, ok := splitYarnSpec(e.resolution)
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

// splitYarnSpec splits a header spec or a resolution into the package name and
// what follows it, dropping the "npm:" protocol and following an alias:
//
//	"lodash@^4.17.0"                           -> "lodash", "^4.17.0"
//	"@scope/pkg@npm:1.2.3"                     -> "@scope/pkg", "1.2.3"
//	"string-width-cjs@npm:string-width@^4.2.0" -> "string-width", "^4.2.0"
//	"my-app@workspace:."                       -> "my-app", "workspace:."
//
// ok is false when no "@" follows the name (e.g. "__metadata").
func splitYarnSpec(spec string) (name, ref string, ok bool) {
	name, ref, ok = cutYarnIdent(spec)
	if !ok {
		return "", "", false
	}
	if rest, isNpm := strings.CutPrefix(ref, "npm:"); isNpm {
		ref = rest
		if alias, aliasRef, isAlias := cutYarnIdent(rest); isAlias {
			name, ref = alias, aliasRef
		}
	}
	return name, ref, true
}

// isRegistryRef reports whether what follows a package name (see splitYarnSpec)
// is a registry version or range ("4.17.21", "^1.2.0", "1.x || 2.x", "latest"):
// a protocol or a path ("workspace:.", "file:../x", "user/repo", "https://...")
// isn't.
func isRegistryRef(ref string) bool {
	return !strings.ContainsAny(ref, ":/")
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
