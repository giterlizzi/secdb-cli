// SPDX-License-Identifier: Apache-2.0

// Package cmd implements the secdb command-line interface.
package cmd

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/giterlizzi/secdb-cli/internal/client"
	"github.com/giterlizzi/secdb-cli/internal/meta"
	"github.com/giterlizzi/secdb-cli/internal/output"
	"github.com/giterlizzi/secdb-cli/internal/update"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// globalOptions are the root flags, shared by every command, plus the API key
// read from SECDB_API_KEY.
type globalOptions struct {
	apiKey  string
	baseURL string
	webURL  string

	debug bool

	output       string
	template     string
	templateFile string
	jq           string

	// jqQuery is the compiled --jq, set by validate.
	jqQuery *output.JQ
}

var global globalOptions

// updateCheckCh delivers the newer version found by the background update
// check (see startBackgroundUpdateCheck), if any.
var updateCheckCh <-chan string

var rootCmd = &cobra.Command{
	Use:   "secdb",
	Short: "CLI for ZEN SecDB",
	// An error message (API failure, bad flag value, ...) is enough on its own;
	// the full usage block would bury it.
	SilenceUsage: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		global.apiKey = os.Getenv("SECDB_API_KEY")

		if baseURL := os.Getenv("SECDB_BASE_URL"); baseURL != "" && !cmd.Flags().Changed("base-url") {
			global.baseURL = baseURL
		}

		startBackgroundUpdateCheck(cmd)
		setupLogging()

		return global.validate(cmd)
	},
}

func (g *globalOptions) addFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&g.baseURL, "base-url", "",
		"ZEN SecDB API base URL, or SECDB_BASE_URL (default: https://secdb.nttzen.cloud/)")

	cmd.PersistentFlags().StringVar(&g.webURL, "web-url", "",
		"ZEN SecDB web GUI URL for the links in the output (default: https://secdb.nttzen.cloud/, even with --base-url)")

	cmd.PersistentFlags().StringVarP(&g.output, "output", "o", "text",
		"Output format: text, json, yaml, template, html, sarif, csv (sarif/csv: audit only)")

	cmd.PersistentFlags().StringVar(&g.template, "template", "",
		"Inline Go Template, with --output=template or --output=html")

	cmd.PersistentFlags().StringVar(&g.templateFile, "template-file", "",
		"External template path file, with --output=template or --output=html")

	cmd.PersistentFlags().StringVar(&g.jq, "jq", "",
		"Filter the JSON output with a jq expression (implies --output=json), e.g. '.hits[].id'")

	cmd.PersistentFlags().BoolVar(&g.debug, "debug", false,
		"Enable debug logging to stderr")
}

// validate checks --jq and the --output format against the command and
// normalizes --base-url and --web-url, before any API call.
func (g *globalOptions) validate(cmd *cobra.Command) error {
	// --jq filters the JSON output: it selects -o json, and conflicts with any
	// other format given explicitly. A bad expression fails here, before any
	// API call.
	if g.jq != "" {
		if cmd.Flags().Changed("output") && g.output != "json" {
			return fmt.Errorf("--jq filters the JSON output: it can't be used with --output=%s", g.output)
		}
		g.output = "json"

		q, err := output.ParseJQ(g.jq)
		if err != nil {
			return err
		}
		g.jqQuery = q
	}

	switch g.output {
	case "json", "yaml", "text", "template", "html", "sarif", "csv":
	default:
		return fmt.Errorf("invalid --output: %s (want json|yaml|text|html|template|sarif|csv)", g.output)
	}
	// sarif/csv have the advisory shape only the audit subcommands produce, so
	// reject them up front elsewhere instead of failing after the API call.
	if (g.output == "sarif" || g.output == "csv") && cmd.Parent() != auditCmd {
		return fmt.Errorf("--output=%s is only supported by the audit commands", g.output)
	}

	u, err := client.ValidateBaseURL(g.baseURL)
	if err != nil {
		return fmt.Errorf("invalid base URL %q (--base-url or SECDB_BASE_URL): %w", g.baseURL, err)
	}
	g.baseURL = u

	w, err := client.ValidateBaseURL(g.webURL)
	if err != nil {
		return fmt.Errorf("invalid --web-url %q: %w", g.webURL, err)
	}
	g.webURL = w

	// The API key travels in a header: warn when it would cross the network in
	// clear text (a local dev server is fine).
	if g.apiKey != "" && strings.HasPrefix(g.baseURL, "http://") && !client.IsLoopback(g.baseURL) {
		slog.Warn("the base URL uses plain http: the API key is sent unencrypted", "base_url", g.baseURL)
	}

	// The effective values, after the defaults; the API key itself never goes
	// to the log, only whether one is set.
	c := g.newClient()
	slog.Debug("configuration",
		"command", cmd.CommandPath(),
		"base_url", c.BaseURL(),
		"web_url", c.WebURL(),
		"api_key", g.apiKey != "",
		"output", g.output,
		"template", g.template,
		"template_file", g.templateFile,
		"jq", g.jq,
	)
	return nil
}

// newClient returns the SecDB API client for the global options.
func (g *globalOptions) newClient() *client.Client {
	return client.New(client.Config{
		BaseURL: g.baseURL,
		WebURL:  g.webURL,
		APIKey:  g.apiKey,
	})
}

// outputOptions returns the options of the json/yaml/template/html renderers:
// the user template and the compiled --jq.
func (g *globalOptions) outputOptions() output.Options {
	return output.Options{
		TemplateExpression: g.template,
		TemplateFile:       g.templateFile,
		JQ:                 g.jqQuery,
	}
}

func init() {
	global.addFlags(rootCmd)

	// Help groups: each command sets its GroupID to one of these.
	rootCmd.AddGroup(
		&cobra.Group{ID: groupIntel, Title: "Vulnerability intelligence:"},
		&cobra.Group{ID: groupAudit, Title: "Auditing:"},
		&cobra.Group{ID: groupIntegrations, Title: "Integrations:"},
		&cobra.Group{ID: groupOther, Title: "Other:"},
	)
	rootCmd.SetCompletionCommandGroupID(groupIntegrations)
	rootCmd.SetHelpCommandGroupID(groupOther)
}

// Command group IDs for the root help (see rootCmd.AddGroup).
const (
	groupIntel        = "intel"
	groupAudit        = "audit"
	groupIntegrations = "integrations"
	groupOther        = "other"
)

// setupLogging sends the log to stderr, at debug level with --debug or
// SECDB_DEBUG (any value), else warnings only.
func setupLogging() {
	if os.Getenv("SECDB_DEBUG") != "" {
		global.debug = true
	}
	level := slog.LevelWarn
	if global.debug {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
}

func startBackgroundUpdateCheck(cmd *cobra.Command) {
	if cmd.Name() != "check-update" && os.Getenv("CI") == "" && os.Getenv("SECDB_NO_UPDATE_CHECK") == "" {
		updateCheckCh = checkUpdateInBackground()
	}
}

func checkUpdateInBackground() <-chan string {
	ch := make(chan string, 1)

	if meta.Version == "v0.0.0" {
		close(ch)
		return ch
	}

	go func() {
		defer close(ch)
		available, releaseInfo, err := update.IsAvailable(meta.Version)
		if err != nil || !available {
			return
		}
		ch <- releaseInfo.Version
	}()
	return ch
}

func printUpdateNoticeIfReady() {
	if updateCheckCh == nil {
		return
	}

	if !term.IsTerminal(int(os.Stderr.Fd())) {
		return
	}

	select {
	case v, ok := <-updateCheckCh:
		if ok && v != "" {
			fmt.Fprintf(os.Stderr, "\nA new version is available: %s (current: %s) -- run `secdb check-update` for details.\n", v, meta.Version)
		}
	case <-time.After(1500 * time.Millisecond):
		// don't block the command output waiting for the background update check
	}
}

// exactArgs is cobra.ExactArgs with a message of our own: it requires exactly
// n positional arguments.
func exactArgs(n int, message string) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) != n {
			return errors.New(message)
		}
		return nil
	}
}

// statusf writes a progress message to stderr, only when stderr is a terminal:
// it never mixes with the result on stdout, nor clutters a CI log.
func statusf(format string, args ...any) {
	if term.IsTerminal(int(os.Stderr.Fd())) {
		fmt.Fprintf(os.Stderr, format, args...)
	}
}

// exitError is returned by a command that must end with a specific exit
// status (e.g. --fail-on → 2) after writing its output. Commands return it
// instead of calling os.Exit, so Execute still prints the update notice, and a
// test can check the status.
type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }

// Execute runs the root command and exits non-zero on error: with the
// exitError's code when a command returned one, 1 otherwise.
func Execute() {
	err := rootCmd.Execute()
	printUpdateNoticeIfReady()

	if err == nil {
		return
	}
	if e, ok := errors.AsType[*exitError](err); ok {
		os.Exit(e.code)
	}
	os.Exit(1)
}
