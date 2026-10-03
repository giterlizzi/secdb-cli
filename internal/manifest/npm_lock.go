// SPDX-License-Identifier: Apache-2.0

package manifest

// package-lock.json, as written by npm.
//
// v2/v3 (npm 7+) have a flat "packages" map keyed by install path:
//
//	""                                        the project; its dependency fields are what it declares
//	"packages/lib"                            a workspace package (local code, not audited)
//	"node_modules/express"                    an installed package
//	"node_modules/express/node_modules/debug" a copy installed for express only
//	"node_modules/@acme/lib"                  {"link": true}: a symlink to a workspace (not audited)
//	"node_modules/string-width-cjs"           {"name": "string-width"}: an npm alias
//
// A package is direct when the project or a workspace declares it and it's
// installed for one of them. Being in the top-level node_modules isn't enough:
// npm hoists transitive packages there too.
//
// v1 (npm 5/6) has a nested "dependencies" tree and doesn't record what the
// project declares, so its packages are never reported as direct.

import (
	"encoding/json"
	"strings"
)

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
