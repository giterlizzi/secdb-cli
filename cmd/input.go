// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// readIdentifiers returns the identifiers (CVEs, PURLs, ...) to process from
// the arguments, else the file, else stdin, in this order of precedence.
func readIdentifiers(args []string, file string) ([]string, error) {
	switch {
	case len(args) > 0:
		return args, nil
	case file != "":
		return readFileLines(file)
	default:
		return readStdinLines()
	}
}

// readFileLines returns the lines of a file, as readLines does.
func readFileLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	return readLines(f)
}

// readStdinLines returns the lines piped to stdin, as readLines does. An
// interactive terminal is an error rather than a wait for typed input.
func readStdinLines() ([]string, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, errors.New("no input provided")
	}
	return readLines(os.Stdin)
}

// readLines returns the trimmed lines of r, skipping blank lines and # comments.
func readLines(r io.Reader) ([]string, error) {
	items := []string{}
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		items = append(items, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading input: %w", err)
	}

	return items, nil
}
