// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"maps"
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

// TestParseNpmLockV3Workspaces checks a v3 monorepo lockfile: direct means
// declared by the project or a workspace (not "installed at the top level",
// which npm's hoisting breaks), an alias is audited as the real package, the
// workspace packages and their links aren't dependencies, and the result is the
// same on every run (the "packages" map has no order).
func TestParseNpmLockV3Workspaces(t *testing.T) {
	src, err := os.ReadFile("testdata/package-lock-v3.json")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{ // PURL -> direct
		"pkg:npm/chalk@4.1.2":        true,  // declared by the workspace, hoisted
		"pkg:npm/debug@2.6.9":        false, // hoisted, but only express needs it
		"pkg:npm/dup@1.0.0":          true,  // also nested under express: still direct
		"pkg:npm/express@4.17.1":     true,
		"pkg:npm/left-pad@1.3.0":     true,  // declared by the workspace, installed in it
		"pkg:npm/lodash@4.17.20":     false, // express's own copy
		"pkg:npm/lodash@4.17.21":     true,
		"pkg:npm/string-width@4.2.3": true, // the alias string-width-cjs
	}

	for run := 0; run < 20; run++ {
		deps, err := Parse("package-lock.json", src)
		if err != nil {
			t.Fatalf("Parse package-lock.json: %v", err)
		}
		got := make(map[string]bool, len(deps))
		for _, d := range deps {
			got[d.PURL] = d.Direct
		}
		if !maps.Equal(got, want) {
			t.Fatalf("run %d: PURL -> direct =\n%v\nwant\n%v", run, got, want)
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
		// The workspace (my-app) declares only express.
		if wantDirect := w.purl == "pkg:npm/express@4.17.1"; deps[i].Direct != wantDirect {
			t.Errorf("%s direct = %v, want %v", deps[i].PURL, deps[i].Direct, wantDirect)
		}
	}
}

// TestParseYarnLockBerryDirect checks the direct dependencies against a lockfile
// generated by Yarn 4.9.2 for a project with a workspace (packages/lib): direct
// means listed by a workspace entry, devDependencies included, matched on the
// exact spec, so is-number@7 (declared) is direct and is-number@6 (needed by
// is-odd) isn't.
func TestParseYarnLockBerryDirect(t *testing.T) {
	src, err := os.ReadFile("testdata/yarn-berry-workspaces.lock")
	if err != nil {
		t.Fatal(err)
	}
	deps, err := Parse("yarn.lock", src)
	if err != nil {
		t.Fatalf("Parse yarn.lock: %v", err)
	}

	want := map[string]bool{ // PURL -> direct
		"pkg:npm/ansi-regex@5.0.1":              false,
		"pkg:npm/emoji-regex@8.0.0":             false,
		"pkg:npm/is-fullwidth-code-point@3.0.0": false,
		"pkg:npm/is-number@6.0.0":               false,
		"pkg:npm/is-number@7.0.0":               true, // root devDependency
		"pkg:npm/is-odd@3.0.1":                  true, // workspace devDependency
		"pkg:npm/left-pad@1.3.0":                true, // workspace dependency
		"pkg:npm/ms@2.1.3":                      true,
		"pkg:npm/strip-ansi@6.0.1":              false,
		"pkg:npm/string-width@4.2.3":            true, // the alias sw-alias
	}
	got := make(map[string]bool, len(deps))
	for _, d := range deps {
		got[d.PURL] = d.Direct
	}
	if !maps.Equal(got, want) {
		t.Errorf("PURL -> direct =\n%v\nwant\n%v", got, want)
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
	for _, d := range deps {
		if d.Direct {
			t.Errorf("%s is direct, but a classic lockfile doesn't record it", d.PURL)
		}
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

// TestParseGemfileLockDirectAndCRLF checks that direct means listed under
// DEPENDENCIES (rack is only needed by rails; "mygem!" is a git/path source) and
// that a lockfile saved with Windows line endings or with trailing blanks gives
// the same result: the "\r" (or a trailing space) used to break the spec regex,
// so such a file audited clean, and the "DEPENDENCIES" heading match.
func TestParseGemfileLockDirectAndCRLF(t *testing.T) {
	src := `GEM
  remote: https://rubygems.org/
  specs:
    mygem (0.1.0)
    rack (2.2.3)
    rails (7.0.4)
      rack (>= 2.2)

PLATFORMS
  ruby

DEPENDENCIES
  mygem!
  rails (~> 7.0)

BUNDLED WITH
   2.4.10
`
	want := map[string]bool{ // PURL -> direct
		"pkg:gem/mygem@0.1.0": true,
		"pkg:gem/rack@2.2.3":  false,
		"pkg:gem/rails@7.0.4": true,
	}
	for name, eol := range map[string]string{
		"LF":              "\n",
		"CRLF":            "\r\n",
		"trailing blanks": "  \t\n",
		"CRLF + blanks":   " \r\n",
	} {
		deps, err := Parse("Gemfile.lock", []byte(strings.ReplaceAll(src, "\n", eol)))
		if err != nil {
			t.Fatalf("%s: Parse Gemfile.lock: %v", name, err)
		}
		got := make(map[string]bool, len(deps))
		for _, d := range deps {
			got[d.PURL] = d.Direct
		}
		if !maps.Equal(got, want) {
			t.Errorf("%s: PURL -> direct =\n%v\nwant\n%v", name, got, want)
		}
	}
}

// TestParseComposerLock checks the PURLs (vendor as namespace, "v" prefix
// dropped, dev branches skipped) and that no package is direct: composer.lock
// doesn't record what composer.json requires.
func TestParseComposerLock(t *testing.T) {
	src := `{
	  "packages": [
	    {"name": "monolog/monolog", "version": "2.9.1"},
	    {"name": "psr/log", "version": "v1.1.4"},
	    {"name": "acme/wip", "version": "dev-main"}
	  ],
	  "packages-dev": [
	    {"name": "phpunit/phpunit", "version": "9.6.13"}
	  ]
	}`
	deps, err := Parse("composer.lock", []byte(src))
	if err != nil {
		t.Fatalf("Parse composer.lock: %v", err)
	}
	var got []string
	for _, d := range deps {
		got = append(got, d.PURL)
		if d.Direct {
			t.Errorf("%s is direct, but composer.lock doesn't record it", d.PURL)
		}
	}
	want := []string{"pkg:composer/monolog/monolog@2.9.1", "pkg:composer/psr/log@1.1.4", "pkg:composer/phpunit/phpunit@9.6.13"}
	if !slices.Equal(got, want) {
		t.Errorf("PURLs = %v, want %v", got, want)
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
