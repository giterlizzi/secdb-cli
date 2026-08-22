// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/giterlizzi/secdb-cli/internal/client"
	"github.com/giterlizzi/secdb-cli/internal/meta"
	"github.com/giterlizzi/secdb-cli/internal/output"
	"github.com/giterlizzi/secdb-cli/internal/update"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	apiKey  string
	baseURL string

	debug bool

	outputFormat       string
	templateExpression string
	templateFile       string

	updateCheckCh <-chan string
)

var rootCmd = &cobra.Command{
	Use:   "secdb",
	Short: "CLI for ZEN SecDB",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		apiKey = os.Getenv("SECDB_API_KEY")

		switch outputFormat {
		case "json", "yaml", "text", "template", "html":
		default:
			return fmt.Errorf("invalid --output: %s (want json|yaml|text|html|template)", outputFormat)
		}

		startBackgroundUpdateCheck(cmd)

		level := slog.LevelWarn
		if debug {
			level = slog.LevelDebug
		}
		logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
		slog.SetDefault(logger)

		return nil
	},
}

func init() {
	rootCmd.PersistentFlags().StringVar(&baseURL, "base-url", "",
		"ZEN SecDB API base URL (default: https://secdb.nttzen.cloud/)")

	rootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "text",
		"Output format: text, json, template, html")

	rootCmd.PersistentFlags().StringVar(&templateExpression, "template", "",
		"Inline Go Template, with --output=template or --output=html")

	rootCmd.PersistentFlags().StringVar(&templateFile, "template-file", "",
		"External template path file, with --output=template or --output=html")

	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false,
		"Enable debug logging to stderr")
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
		available, releaseInfo, err := update.UpdateIsAvailable(meta.Version)
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

func newSecDbClient() *client.Client {
	c := client.NewClient(apiKey)
	if baseURL != "" {
		return c.WithBaseURL(baseURL)
	}
	return c
}

func newOutputOptions() output.Options {
	return output.Options{
		TemplateExpression: templateExpression,
		TemplateFile:       templateFile,
	}
}

func Execute() {
	err := rootCmd.Execute()
	printUpdateNoticeIfReady()

	if err != nil {
		os.Exit(1)
	}
}
