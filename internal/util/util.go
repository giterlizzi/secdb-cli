// SPDX-License-Identifier: Apache-2.0

package util

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/spf13/cobra"
)

func ExactArgs(n int, message string) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) != n {
			return fmt.Errorf("%s", message)
		}
		return nil
	}
}

func TimeAgo(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%d minutes ago", int(d.Minutes()))
	case int(d.Hours()/1) == 1:
		return "1 hour ago"
	case d < 24*time.Hour:
		return fmt.Sprintf("%d hours ago", int(d.Hours()))
	case int(d.Hours()/24) == 1:
		return "1 day ago"
	default:
		return fmt.Sprintf("%d days ago", int(d.Hours()/24))
	}
}

func Deduplicate(items []string) []string {
	seen := make(map[string]bool, len(items))
	unique := []string{}

	for _, s := range items {
		if !seen[s] {
			seen[s] = true
			unique = append(unique, s)
		}
	}

	return unique
}

func ReadIdentifiers(args []string, filePath string) ([]string, error) {
	switch {
	case len(args) > 0:
		return args, nil
	case filePath != "":
		f, err := os.Open(filePath)
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", filePath, err)
		}
		defer f.Close()
		return readLines(f)
	default:
		if term.IsTerminal(int(os.Stdin.Fd())) {
			return nil, fmt.Errorf("no input provided")
		}
		return readLines(os.Stdin)
	}
}

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

// Statusf writes an interactive progress message to stderr. It is a no-op when
// stderr isn't a terminal (pipe, redirect, CI), so it never pollutes the
// result on stdout nor clutters logs.
func Statusf(format string, args ...interface{}) {
	if term.IsTerminal(int(os.Stderr.Fd())) {
		fmt.Fprintf(os.Stderr, format, args...)
	}
}
