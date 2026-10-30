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

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/spf13/cobra"
)

// manifestOptions are the flags of "audit manifest".
type manifestOptions struct {
	file     string
	dir      string
	maxDepth int
	audit    auditOptions
}

var manifestOpts manifestOptions

var manifestAuditCmd = &cobra.Command{
	Use: "manifest (--file <FILE> | --directory <DIR>)",
	Example: heredoc.Doc(`
		Go modules:
			secdb audit manifest --file go.mod

		npm (lockfiles):
			secdb audit manifest --file package-lock.json
			secdb audit manifest --file yarn.lock

		Python:
			secdb audit manifest --file requirements.txt
			secdb audit manifest --file poetry.lock
			secdb audit manifest --file uv.lock
			secdb audit manifest --file pdm.lock
			secdb audit manifest --file pylock.toml

		Ruby / PHP / Rust:
			secdb audit manifest --file Gemfile.lock
			secdb audit manifest --file composer.lock
			secdb audit manifest --file Cargo.lock

		Java:
			secdb audit manifest --file pom.xml
			secdb audit manifest --file gradle.lockfile

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
		  - poetry.lock, uv.lock, pdm.lock              (Python)
		  - pylock.toml, pylock.*.toml, *.py.lock       (Python)
		  - Gemfile.lock, gems.locked                   (Ruby)
		  - pom.xml                                     (Maven)
		  - gradle.lockfile                             (Gradle)
		  - Cargo.lock                                  (Rust / Cargo)
		  - composer.lock                               (PHP / Composer)

		Results are shaped and rendered exactly like "audit purl": --view,
		--fail-on, --ignore-file, --show-unfixed and
		--output=sarif/csv/defectdojo/cyclonedx all behave the same way.
	`),
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		files, err := manifestOpts.files()
		if err != nil {
			return err
		}

		purls, sources := manifestPURLs(files)
		if len(purls) == 0 {
			return fmt.Errorf("no auditable dependencies found in %s", manifestOpts.source())
		}

		source := fmt.Sprintf("manifest (%s)", manifestOpts.source())
		return runPURLAudit(purls, &manifestOpts.audit, auditTarget{
			source:       source,
			sarifSources: sources,
			meta: []report.MetaItem{
				{Label: "Source", Value: source},
				{Label: "Dependencies scanned", Value: strconv.Itoa(len(purls))},
			},
		})
	},
}

func init() {
	auditCmd.AddCommand(manifestAuditCmd)
	manifestOpts.addFlags(manifestAuditCmd)
}

func (o *manifestOptions) addFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&o.file, "file", "f", "",
		"Path to the dependency manifest to audit (go.mod, package-lock.json, requirements.txt, Gemfile.lock, ...)")
	cmd.Flags().StringVarP(&o.dir, "directory", "d", "",
		"Directory to recursively discover and audit manifests in (mutually exclusive with --file)")
	cmd.Flags().IntVar(&o.maxDepth, "max-depth", 0,
		"Max directory depth to descend with --directory (0 = unlimited)")
	cmd.MarkFlagsMutuallyExclusive("file", "directory")
	cmd.MarkFlagsOneRequired("file", "directory")

	o.audit.addFlags(cmd)
}

// source is what the audit reads: the --directory or the --file (exactly one is
// set, enforced by the flag groups in addFlags).
func (o *manifestOptions) source() string {
	if o.dir != "" {
		return o.dir
	}
	return o.file
}

// files returns the manifests to audit: the --file, or the supported manifests
// discovered under --directory.
func (o *manifestOptions) files() ([]string, error) {
	if o.dir == "" {
		return []string{o.file}, nil
	}
	files, err := manifest.Discover(o.dir, nil, o.maxDepth)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no supported manifests found under %s", o.dir)
	}
	return files, nil
}

// manifestPURLs parses the manifests and returns the PURLs of their
// dependencies, normalized and de-duplicated, with where each one is first
// declared (for the SARIF report). A manifest that fails to parse is skipped
// with a warning.
func manifestPURLs(files []string) ([]string, map[string]output.SourceLocation) {
	var purls []string
	sources := map[string]output.SourceLocation{}

	for _, f := range files {
		deps, err := manifest.ParseFile(f)
		if err != nil {
			slog.Warn("skipping manifest", "file", f, "error", err)
			continue
		}
		purls = append(purls, manifest.PURLs(deps)...)
		for _, d := range deps {
			if _, ok := sources[d.PURL]; d.PURL != "" && !ok {
				sources[d.PURL] = output.SourceLocation{File: f, Line: d.Range.Start.Line}
			}
		}
	}
	return audit.NormalizePURLs(purls), sources
}
