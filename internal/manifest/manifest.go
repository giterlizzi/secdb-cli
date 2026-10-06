// SPDX-License-Identifier: Apache-2.0

// Package manifest turns a dependency manifest (go.mod, package-lock.json,
// requirements.txt, Gemfile.lock, ...) into a list of PURL-resolved
// dependencies. It's the shared engine behind the "audit manifest" command and
// the future "lsp" server: each parser records the source Range of every
// dependency, which the CLI ignores but the LSP uses to attach diagnostics.
package manifest

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Position is a 1-based location in a manifest file. A zero Line means the
// position is unknown: some formats (e.g. the JSON lock files) aren't parsed
// with position tracking, so their dependencies carry an empty Range.
type Position struct {
	Line   int
	Column int
}

// Range is the span in the manifest where a dependency is declared. Consumers
// that need positions (the LSP server) read it; the CLI audit ignores it.
type Range struct {
	Start Position
	End   Position
}

// Dependency is a single package declared in a manifest, resolved to a PURL and
// (when the format allows) the source Range where it's declared.
type Dependency struct {
	PURL      string
	Ecosystem string
	Name      string
	Version   string
	Direct    bool
	Range     Range
}

// Parser turns the contents of one manifest format into dependencies. filename
// is the base name of the file being parsed (an ecosystem parser that handles
// several files, e.g. npm, dispatches on it); parsers that handle a single
// format ignore it.
type Parser interface {
	// Ecosystem is the short ecosystem name (e.g. "go", "npm", "python", "ruby").
	Ecosystem() string
	// Patterns are the manifest base-name globs this parser handles, matched
	// with filepath.Match (e.g. "go.mod", "requirements*.txt").
	Patterns() []string
	// Parse extracts the dependencies from the manifest content.
	Parse(filename string, content []byte) ([]Dependency, error)
}

// DefaultSkipDirs are directory base names pruned from a workspace walk.
var DefaultSkipDirs = map[string]bool{
	// VCS
	".git": true, ".hg": true, ".svn": true,

	// NPM
	"node_modules": true, ".next": true, ".angular": true, ".svelte-kit": true,

	// Python
	"site-packages": true, ".venv": true, "venv": true, "__pycache__": true, "env": true,

	// Common
	"vendor": true, "target": true, "dist": true, "build": true, "out": true, "tmp": true,

	// IDE
	".idea": true, ".vscode": true,

	// Test
	"testdata": true, "coverage": true,
}

var parsers = []Parser{
	composerParser{},
	goModParser{},
	mavenParser{},
	npmParser{},
	pythonParser{},
	rubyParser{},
}

// ParserFor returns the parser that handles path (matched by base name), or nil
// if the format is unsupported.
func ParserFor(path string) Parser {
	base := filepath.Base(path)
	for _, p := range parsers {
		for _, pat := range p.Patterns() {
			if ok, _ := filepath.Match(pat, base); ok {
				return p
			}
		}
	}
	return nil
}

// Parse dispatches by filename (base name) and parses the given content. It's
// the position-aware entry point the LSP uses with in-memory buffers; ParseFile
// is the disk-reading convenience for the CLI.
func Parse(filename string, content []byte) ([]Dependency, error) {
	base := filepath.Base(filename)
	p := ParserFor(base)
	if p == nil {
		return nil, fmt.Errorf("unsupported manifest %q (supported: %s)", base, strings.Join(SupportedPatterns(), ", "))
	}
	deps, err := p.Parse(base, content)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", base, err)
	}
	return deps, nil
}

// ParseFile reads the manifest at path and parses it with the matching parser.
func ParseFile(path string) ([]Dependency, error) {
	if ParserFor(path) == nil {
		return nil, fmt.Errorf("unsupported manifest %q (supported: %s)", filepath.Base(path), strings.Join(SupportedPatterns(), ", "))
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(path, content)
}

// SupportedPatterns lists every manifest glob the registry handles, sorted and
// de-duplicated, for help text and error messages.
func SupportedPatterns() []string {
	var out []string
	for _, p := range parsers {
		out = append(out, p.Patterns()...)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// Discover walks root recursively and returns the paths of every supported
// manifest file. Directories named in skip (defaults to DefaultSkipDirs when
// nil) are pruned; maxDepth limits how many directory levels below root to
// descend (0 = unlimited). Symlinks are not followed (WalkDir default).
func Discover(root string, skip map[string]bool, maxDepth int) ([]string, error) {
	if skip == nil {
		skip = DefaultSkipDirs
	}
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case d.IsDir() && path != root && (skip[d.Name()] || tooDeep(root, path, maxDepth)):
			return filepath.SkipDir
		case !d.IsDir() && ParserFor(path) != nil:
			out = append(out, path)
		}
		return nil
	})
	slices.Sort(out)
	return out, err
}

// tooDeep reports whether dir is more than maxDepth levels below root
// (0 = no limit).
func tooDeep(root, dir string, maxDepth int) bool {
	if maxDepth <= 0 {
		return false
	}
	rel, err := filepath.Rel(root, dir)
	return err == nil && strings.Count(rel, string(os.PathSeparator))+1 > maxDepth
}

// splitLines splits a line-based manifest into its lines, without the line
// terminators and the trailing whitespace: a file saved on Windows ("\r\n") or
// hand-edited with trailing blanks gives the same lines as a clean one. Leading
// indentation is kept, since some formats (Gemfile.lock, yarn.lock) give it a
// meaning. Every line-based parser goes through it, so none has to remember.
func splitLines(content []byte) []string {
	lines := strings.Split(string(content), "\n")
	for i, line := range lines {
		lines[i] = strings.TrimRight(line, " \t\r")
	}
	return lines
}

func lineRange(line int) Range {
	return Range{Start: Position{Line: line, Column: 1}, End: Position{Line: line, Column: 1}}
}
