// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"os"
	"slices"
	"strings"
	"testing"
)

// depByPURL returns the dependency with the given PURL, or a zero Dependency.
func depByPURL(deps []Dependency, purl string) (Dependency, bool) {
	for _, d := range deps {
		if d.PURL == purl {
			return d, true
		}
	}
	return Dependency{}, false
}

func TestParse_Unsupported(t *testing.T) {
	// package.json is intentionally not handled (its version ranges aren't
	// resolved versions), so it must be reported as unsupported.
	if _, err := Parse("package.json", []byte("{}")); err == nil {
		t.Fatal("expected an error for an unsupported manifest, got nil")
	}
}

func TestParseGoMod(t *testing.T) {
	src := `module example.com/app

go 1.26

require (
	github.com/spf13/cobra v1.10.2
	golang.org/x/mod v0.40.0 // indirect
)

require github.com/single/dep v1.0.0
`
	deps, err := Parse("go.mod", []byte(src))
	if err != nil {
		t.Fatalf("Parse go.mod: %v", err)
	}
	if len(deps) != 3 {
		t.Fatalf("expected 3 deps, got %d: %+v", len(deps), deps)
	}

	cobra, ok := depByPURL(deps, "pkg:golang/github.com/spf13/cobra@1.10.2")
	if !ok {
		t.Fatalf("cobra PURL not found in %+v", deps)
	}
	if !cobra.Direct {
		t.Error("cobra should be a direct dependency")
	}
	if cobra.Range.Start.Line != 6 {
		t.Errorf("cobra should be on line 6, got %d", cobra.Range.Start.Line)
	}

	xmod, ok := depByPURL(deps, "pkg:golang/golang.org/x/mod@0.40.0")
	if !ok {
		t.Fatalf("x/mod PURL not found in %+v", deps)
	}
	if xmod.Direct {
		t.Error("x/mod is marked // indirect, should not be Direct")
	}
}

func TestParseNpmLockV2(t *testing.T) {
	src := `{
	  "name": "app",
	  "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "app", "version": "1.0.0"},
	    "node_modules/lodash": {"version": "4.17.21"},
	    "node_modules/@scope/pkg": {"version": "2.3.4"},
	    "node_modules/lodash/node_modules/nested": {"version": "0.1.0"}
	  }
	}`
	deps, err := Parse("package-lock.json", []byte(src))
	if err != nil {
		t.Fatalf("Parse package-lock.json: %v", err)
	}

	if _, ok := depByPURL(deps, "pkg:npm/lodash@4.17.21"); !ok {
		t.Errorf("lodash PURL not found in %+v", deps)
	}
	if _, ok := depByPURL(deps, "pkg:npm/%40scope/pkg@2.3.4"); !ok {
		t.Errorf("scoped PURL not found in %+v", deps)
	}
	nested, ok := depByPURL(deps, "pkg:npm/nested@0.1.0")
	if !ok {
		t.Fatalf("nested PURL not found in %+v", deps)
	}
	if nested.Direct {
		t.Error("a nested (node_modules/.../node_modules/...) package should be transitive")
	}
	// The root project ("" key) must not appear as a dependency.
	for _, d := range deps {
		if d.Version == "1.0.0" && d.Name == "app" {
			t.Errorf("root project leaked into deps: %+v", d)
		}
	}
}

func TestParseNpmLockV1(t *testing.T) {
	src := `{
	  "name": "app",
	  "lockfileVersion": 1,
	  "dependencies": {
	    "lodash": {"version": "4.17.21"},
	    "chalk": {"version": "5.0.0", "dependencies": {"ansi": {"version": "6.0.0"}}}
	  }
	}`
	deps, err := Parse("package-lock.json", []byte(src))
	if err != nil {
		t.Fatalf("Parse v1: %v", err)
	}
	for _, want := range []string{"pkg:npm/lodash@4.17.21", "pkg:npm/chalk@5.0.0", "pkg:npm/ansi@6.0.0"} {
		if _, ok := depByPURL(deps, want); !ok {
			t.Errorf("%s not found in %+v", want, deps)
		}
	}
}

func TestParseYarnLock(t *testing.T) {
	src := `# yarn lockfile v1

lodash@^4.17.0, lodash@^4.17.21:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"

"@scope/pkg@npm:^1.0.0":
  version "1.2.3"

__metadata:
  version: 6
`
	deps, err := Parse("yarn.lock", []byte(src))
	if err != nil {
		t.Fatalf("Parse yarn.lock: %v", err)
	}

	lodash, ok := depByPURL(deps, "pkg:npm/lodash@4.17.21")
	if !ok {
		t.Fatalf("lodash not found in %+v", deps)
	}
	if lodash.Range.Start.Line != 3 {
		t.Errorf("lodash header should be line 3, got %d", lodash.Range.Start.Line)
	}
	if _, ok := depByPURL(deps, "pkg:npm/%40scope/pkg@1.2.3"); !ok {
		t.Errorf("scoped yarn dep not found in %+v", deps)
	}
	// The __metadata block must not become a dependency.
	for _, d := range deps {
		if d.Name == "__metadata" {
			t.Errorf("__metadata leaked into deps: %+v", d)
		}
	}
}

// TestParseYarnLockBerry checks the yarn berry (v2+) format against a realistic
// lockfile: versions written as "version: x" (not "x"), the package taken from
// "resolution" (aliases resolve to the real name, a patch to the package it
// patches), non-registry entries skipped, nested fields ignored.
func TestParseYarnLockBerry(t *testing.T) {
	src, err := os.ReadFile("testdata/yarn-berry.lock")
	if err != nil {
		t.Fatal(err)
	}
	deps, err := Parse("yarn.lock", src)
	if err != nil {
		t.Fatalf("Parse yarn.lock: %v", err)
	}

	want := []struct {
		purl string
		line int
	}{
		{"pkg:npm/%40babel/code-frame@7.24.7", 8},
		{"pkg:npm/express@4.17.1", 18},
		{"pkg:npm/lodash@4.17.21", 26},
		{"pkg:npm/resolve@1.22.1", 40}, // the patch entry is the same package, de-duplicated
		{"pkg:npm/string-width@4.2.3", 52},
	}
	if len(deps) != len(want) {
		t.Fatalf("got %d deps, want %d: %+v", len(deps), len(want), deps)
	}
	for i, w := range want {
		if deps[i].PURL != w.purl || deps[i].Range.Start.Line != w.line {
			t.Errorf("dep %d = %s (line %d), want %s (line %d)", i, deps[i].PURL, deps[i].Range.Start.Line, w.purl, w.line)
		}
	}
}

// TestParseYarnLockClassicEdgeCases covers the classic format's aliases, the
// non-registry ranges, a nested field named like "version" and CRLF line endings.
func TestParseYarnLockClassicEdgeCases(t *testing.T) {
	src := strings.ReplaceAll(`# yarn lockfile v1

"string-width-cjs@npm:string-width@^4.2.0":
  version "4.2.3"
  resolved "https://registry.yarnpkg.com/string-width/-/string-width-4.2.3.tgz"

express@^4.17.1:
  version "4.17.1"
  dependencies:
    version-guard "^1.1.1"

local-lib@file:../local-lib:
  version "1.0.0"

left-pad@left-pad/left-pad#v1.3.0:
  version "1.3.0"
`, "\n", "\r\n")

	deps, err := Parse("yarn.lock", []byte(src))
	if err != nil {
		t.Fatalf("Parse yarn.lock: %v", err)
	}
	var got []string
	for _, d := range deps {
		got = append(got, d.PURL)
	}
	want := []string{"pkg:npm/string-width@4.2.3", "pkg:npm/express@4.17.1"}
	if !slices.Equal(got, want) {
		t.Errorf("PURLs = %v, want %v", got, want)
	}
}

func TestParseRequirements(t *testing.T) {
	src := `# app requirements
Django==4.2.1
requests>=2.28.0  # pinned lower bound
Flask[async]==2.3.2
urllib3  # unpinned, dropped
-r base.txt
--hash=sha256:abc
example ; python_version < "3.8"
`
	deps, err := Parse("requirements.txt", []byte(src))
	if err != nil {
		t.Fatalf("Parse requirements.txt: %v", err)
	}

	django, ok := depByPURL(deps, "pkg:pypi/django@4.2.1")
	if !ok {
		t.Fatalf("Django should normalize to pypi/django, got %+v", deps)
	}
	if django.Range.Start.Line != 2 {
		t.Errorf("Django should be on line 2, got %d", django.Range.Start.Line)
	}
	if _, ok := depByPURL(deps, "pkg:pypi/requests@2.28.0"); !ok {
		t.Errorf("requests lower bound should resolve to 2.28.0, got %+v", deps)
	}
	if _, ok := depByPURL(deps, "pkg:pypi/flask@2.3.2"); !ok {
		t.Errorf("Flask[async] should drop extras and normalize, got %+v", deps)
	}
	for _, d := range deps {
		if d.Name == "urllib3" || d.Name == "example" {
			t.Errorf("unpinned/marker-only line should have been dropped: %+v", d)
		}
	}
}

func TestParseGemfileLock(t *testing.T) {
	src := `GEM
  remote: https://rubygems.org/
  specs:
    rails (7.0.4)
      actionpack (= 7.0.4)
    nokogiri (1.14.2)

PLATFORMS
  ruby

DEPENDENCIES
  rails
`
	deps, err := Parse("Gemfile.lock", []byte(src))
	if err != nil {
		t.Fatalf("Parse Gemfile.lock: %v", err)
	}
	if len(deps) != 2 {
		t.Fatalf("expected 2 gems (constraints skipped), got %d: %+v", len(deps), deps)
	}
	rails, ok := depByPURL(deps, "pkg:gem/rails@7.0.4")
	if !ok {
		t.Fatalf("rails not found in %+v", deps)
	}
	if rails.Range.Start.Line != 4 {
		t.Errorf("rails should be on line 4, got %d", rails.Range.Start.Line)
	}
	// The 6-space "actionpack" constraint line must not become a dependency.
	for _, d := range deps {
		if d.Name == "actionpack" {
			t.Errorf("nested constraint leaked into deps: %+v", d)
		}
	}
}

func TestParserFor(t *testing.T) {
	cases := map[string]string{
		"go.mod":               "go",
		"package-lock.json":    "npm",
		"yarn.lock":            "npm",
		"requirements.txt":     "python",
		"requirements-dev.txt": "python",
		"Gemfile.lock":         "ruby",
		"pom.xml":              "maven",
		"composer.lock":        "composer",
		"/some/path/go.mod":    "go",
	}
	for path, want := range cases {
		p := ParserFor(path)
		if p == nil {
			t.Errorf("ParserFor(%q) = nil, want ecosystem %q", path, want)
			continue
		}
		if p.Ecosystem() != want {
			t.Errorf("ParserFor(%q) ecosystem = %q, want %q", path, p.Ecosystem(), want)
		}
	}
	// package.json is intentionally not handled.
	if p := ParserFor("package.json"); p != nil {
		t.Errorf("ParserFor(package.json) = %q, want nil (not handled)", p.Ecosystem())
	}
}
