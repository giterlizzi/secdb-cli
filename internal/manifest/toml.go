// SPDX-License-Identifier: Apache-2.0

package manifest

import (
	"regexp"
	"strings"
)

// tomlPackage is one [[package]] entry of a TOML lockfile written by a tool
// (Cargo.lock, poetry.lock, uv.lock): its `key = "string"` values, the ones
// of a [package.x] sub-table or of an inline table (`x = { k = "v" }`, first
// key only) prefixed with "x." (e.g. "source.type", "source.registry"), and
// the lines it spans, from [[package]] to its last non-blank line.
type tomlPackage struct {
	fields     map[string]string
	start, end int
}

var (
	tomlKeyValueRe    = regexp.MustCompile(`^([A-Za-z0-9_-]+) = "([^"]*)"$`)
	tomlInlineTableRe = regexp.MustCompile(`^([A-Za-z0-9_-]+) = \{ ([A-Za-z0-9_-]+) = "([^"]*)"`)
)

// tomlPackages reads the [[name]] entries (name is "package" for Cargo.lock,
// poetry.lock, uv.lock and pdm.lock, "packages" for pylock.toml) line by line,
// with no TOML library: these files have a fixed layout, one `key = "value"`
// or `key = { k = "value", ... }` per line. A [name.x] or [[name.x]] header
// opens a sub-table of the entry (e.g. [package.source], [[packages.wheels]]);
// any other table header ([metadata], [[patch.unused]], [manifest], [tool.x])
// ends it. Multi-line arrays (files, wheels, dependencies) are indented, so
// their lines never match a key.
func tomlPackages(content []byte, name string) []tomlPackage {
	header := "[[" + name + "]]"
	tablePrefix := "[" + name + "."
	tableArrayPrefix := "[[" + name + "."

	var pkgs []tomlPackage

	fields := map[string]string{}
	table, start, end := "", 0, 0

	flush := func() {
		if len(fields) > 0 {
			pkgs = append(pkgs, tomlPackage{fields: fields, start: start, end: end})
		}
		fields, table, start, end = map[string]string{}, "", 0, 0
	}

	for i, line := range splitLines(content) {
		switch {
		case line == header:
			flush()
			start, end = i+1, i+1
			continue
		case strings.HasPrefix(line, tablePrefix) || strings.HasPrefix(line, tableArrayPrefix):
			table = strings.Trim(line, "[]")[len(name)+1:] + "."
		case strings.HasPrefix(line, "["):
			flush()
			continue
		}

		if start == 0 {
			continue
		}

		if line != "" {
			end = i + 1
		}

		if m := tomlKeyValueRe.FindStringSubmatch(line); m != nil {
			fields[table+m[1]] = m[2]
		} else if m := tomlInlineTableRe.FindStringSubmatch(line); m != nil {
			fields[table+m[1]+"."+m[2]] = m[3]
		}
	}

	flush()
	return pkgs
}
