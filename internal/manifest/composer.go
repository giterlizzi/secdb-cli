// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"encoding/json"
	"strings"

	packageurl "github.com/package-url/packageurl-go"
)

type composerLock struct {
	Packages    []composerLockPkg `json:"packages"`
	PackagesDev []composerLockPkg `json:"packages-dev"`
}

type composerLockPkg struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// composerParser handles PHP composer.lock file.
type composerParser struct{}

func (composerParser) Ecosystem() string  { return "composer" }
func (composerParser) Patterns() []string { return []string{"composer.lock"} }

func (composerParser) Parse(filename string, content []byte) ([]Dependency, error) {
	var lock composerLock
	if err := json.Unmarshal(content, &lock); err != nil {
		return nil, err
	}

	var deps []Dependency

	addDeps := func(pkgs []composerLockPkg) {
		for _, pkg := range pkgs {
			name := pkg.Name
			version := strings.TrimPrefix(pkg.Version, "v")
			purl := composerPURL(name, version)

			if purl == "" || version == "" || strings.HasPrefix(version, "dev-") {
				continue
			}

			deps = append(deps, Dependency{
				PURL:      purl,
				Ecosystem: "composer",
				Name:      name,
				Version:   version,
				Direct:    true,
			})
		}
	}

	addDeps(lock.Packages)
	addDeps(lock.PackagesDev)

	return deps, nil
}

// composerPURL builds a pkg:composer PURL from a "vendor/package" name.
func composerPURL(name, version string) string {
	vendor, pkg, ok := strings.Cut(name, "/")
	if !ok {
		return ""
	}
	return packageurl.NewPackageURL("composer", vendor, pkg, version, nil, "").ToString()
}
