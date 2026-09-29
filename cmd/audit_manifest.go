// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"log/slog"
	"strconv"

	"github.com/giterlizzi/secdb-cli/internal/audit"
	"github.com/giterlizzi/secdb-cli/internal/manifest"
	"github.com/giterlizzi/secdb-cli/internal/output"
	"github.com/giterlizzi/secdb-cli/internal/report"
	"github.com/giterlizzi/secdb-cli/internal/util"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/spf13/cobra"
)

var (
	maxDepth     int
	manifestFile string
	manifestDir  string
	manifestOpts auditOptions
)

var manifestAuditCmd = &cobra.Command{
	Use: "manifest (--file <FILE> | --directory <DIR>)",
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

		Discover and audit every manifest under a directory (recursively):
			secdb audit manifest --directory .
			secdb audit manifest --directory ./services --max-depth 3

		CI (fail on high or critical):
			secdb audit manifest --file go.mod --fail-on=high
	`),
	Short: "Audit a dependency manifest against ZEN SecDB",
	Long: heredoc.Doc(`
		Parse a dependency manifest, resolve its packages to PURLs, and audit
		them against the ZEN SecDB for known vulnerabilities.

		Pass a single manifest with --file, or scan a directory with --directory
		to recursively discover and audit every supported manifest under it (the
		two flags are mutually exclusive). Discovery prunes noise directories
		(.git, node_modules, vendor, target, dist, build, testdata, ...) and does
		not follow symlinks; --max-depth limits how deep the walk descends
		(0 = unlimited). A manifest that fails to parse is skipped with a warning
		rather than aborting the whole scan; all discovered dependencies are
		audited together in a single report.

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
		var (
			files []string
			err   error
		)

		// Exactly one of --file/--directory is set (enforced by the flag groups
		// registered in init).
		if manifestDir != "" {
			files, err = manifest.Discover(manifestDir, nil, maxDepth)
			if err != nil {
				return err
			}
			if len(files) == 0 {
				return fmt.Errorf("no supported manifests found under %s", manifestDir)
			}
		} else {
			files = []string{manifestFile}
		}

		var purls []string
		sources := map[string]output.SourceLocation{}

		for _, f := range files {
			deps, err := manifest.ParseFile(f)
			if err != nil {
				slog.Warn("skipping manifest", "file", f, "error", err)
				continue
			}
			for _, d := range deps {
				if d.PURL != "" {
					slog.Debug("found dependency", "file", f, "dependency", d)
					purls = append(purls, d.PURL)
					if _, ok := sources[d.PURL]; !ok {
						sources[d.PURL] = output.SourceLocation{File: f, Line: d.Range.Start.Line}
					}
				}
			}
		}

		source := manifestFile
		if manifestDir != "" {
			source = manifestDir
		}

		purls = util.Deduplicate(audit.ValidatePURLs(purls))
		if len(purls) == 0 {
			return fmt.Errorf("no auditable dependencies found in %s", source)
		}

		return runPURLAudit(purls, &manifestOpts, auditRenderConfig{
			sources: sources,
			meta: []report.MetaItem{
				{Label: "Source", Value: fmt.Sprintf("manifest (%s)", source)},
				{Label: "Dependencies scanned", Value: strconv.Itoa(len(purls))},
			},
		})
	},
}

func init() {
	auditCmd.AddCommand(manifestAuditCmd)

	manifestAuditCmd.Flags().StringVarP(&manifestFile, "file", "f", "",
		"Path to the dependency manifest to audit (go.mod, package-lock.json, requirements.txt, Gemfile.lock, ...)")
	manifestAuditCmd.Flags().StringVarP(&manifestDir, "directory", "d", "",
		"Directory to recursively discover and audit manifests in (mutually exclusive with --file)")
	manifestAuditCmd.Flags().IntVar(&maxDepth, "max-depth", 0,
		"Max directory depth to descend with --directory (0 = unlimited)")
	manifestAuditCmd.MarkFlagsMutuallyExclusive("file", "directory")
	manifestAuditCmd.MarkFlagsOneRequired("file", "directory")

	manifestOpts.addFlags(manifestAuditCmd)
}
