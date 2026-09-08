// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/giterlizzi/secdb-cli/internal/audit"
	"github.com/giterlizzi/secdb-cli/internal/manifest"
	"github.com/giterlizzi/secdb-cli/internal/report"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/spf13/cobra"
)

var (
	manifestFile string
	manifestOpts auditOptions
)

var manifestAuditCmd = &cobra.Command{
	Use: "manifest --file <FILE>",
	Example: heredoc.Doc(`
		Go modules:
		  	secdb audit manifest --file go.mod

		npm (lockfiles):
		  	secdb audit manifest --file package-lock.json
		  	secdb audit manifest --file yarn.lock

		Python / Ruby:
		  	secdb audit manifest --file requirements.txt
		  	secdb audit manifest --file Gemfile.lock

		Java / PHP:
		  	secdb audit manifest --file pom.xml
		  	secdb audit manifest --file composer.lock

		CI (fail on high or critical):
		  	secdb audit manifest --file go.mod --fail-on=high
	`),
	Short: "Audit a dependency manifest against ZEN SecDB",
	Long: heredoc.Doc(`
		Parse a dependency manifest, resolve its packages to PURLs, and audit
		them against the ZEN SecDB for known vulnerabilities.

		The manifest format is detected from the file name. Supported files:
		  - go.mod                                      (Go modules)
		  - package-lock.json, yarn.lock                (npm)
		  - requirements*.txt                           (Python)
		  - Gemfile.lock                                (Ruby)
		  - pom.xml                                     (Maven)
		  - composer.lock                               (PHP / Composer)

		Results are shaped and rendered exactly like "audit purl": --view,
		--fail-on, --ignore-file, --show-unfixed and --output=sarif/csv all
		behave the same way.
	`),
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if manifestFile == "" {
			return fmt.Errorf("--file is required: pass the path to a dependency manifest (supported: %s)",
				strings.Join(manifest.SupportedPatterns(), ", "))
		}

		deps, err := manifest.ParseFile(manifestFile)
		if err != nil {
			return err
		}

		purls := make([]string, 0, len(deps))
		for _, d := range deps {
			if d.PURL != "" {
				slog.Debug("found dependency", "file", manifestFile, "dependency", d)
				purls = append(purls, d.PURL)
			}
		}
		purls = audit.ValidatePURLs(purls)
		if len(purls) == 0 {
			return fmt.Errorf("no auditable dependencies found in %s", manifestFile)
		}

		ignoreFile, err := audit.LoadIgnoreFile(manifestOpts.ignoreFile)
		if err != nil {
			return err
		}

		client := newSecDbClient()
		data, err := client.PURLAudit(purls)
		if err != nil {
			return err
		}

		return renderAudit(auditRenderConfig{
			data:        data,
			opts:        &manifestOpts,
			ignoreFile:  ignoreFile,
			baseURL:     client.BaseURL(),
			template:    "audit-purl",
			sarifSource: manifestFile,
			meta: []report.MetaItem{
				{Label: "Source", Value: fmt.Sprintf("manifest (%s)", manifestFile)},
				{Label: "Dependencies scanned", Value: strconv.Itoa(len(purls))},
			},
		})
	},
}

func init() {
	auditCmd.AddCommand(manifestAuditCmd)

	manifestAuditCmd.Flags().StringVarP(&manifestFile, "file", "f", "",
		"Path to the dependency manifest to audit (go.mod, package-lock.json, requirements.txt, Gemfile.lock, ...)")

	manifestOpts.addFlags(manifestAuditCmd)
}
