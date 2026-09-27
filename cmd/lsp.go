// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/giterlizzi/secdb-cli/internal/lsp"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/spf13/cobra"
)

var lspNoDiscovery bool

var lspCmd = &cobra.Command{
	Use:     "lsp",
	GroupID: groupIntegrations,
	Short:   "Start the Language Server (LSP) for editor integration",
	Long: heredoc.Doc(`
		Start a Language Server Protocol (LSP) server that audits dependency
		manifests against the ZEN SecDB as you open and edit them, reporting
		known vulnerabilities inline as editor diagnostics.

		The manifest format is detected from the file name. Supported files:
		  - go.mod                                      (Go modules)
		  - package-lock.json, yarn.lock                (npm)
		  - requirements*.txt                           (Python)
		  - Gemfile.lock                                (Ruby)
		  - pom.xml                                     (Maven)
		  - composer.lock                               (PHP / Composer)

		On startup the server also discovers and audits every supported manifest
		in the workspace, so findings show up without opening each file (noise
		directories like node_modules/vendor/target are skipped). Pass
		--no-discovery to audit only files as they are opened.

		The server speaks JSON-RPC over stdin/stdout, so it is meant to be
		launched by an editor's LSP client, not run interactively (in a plain
		terminal it just waits for input). It honors the same SECDB_API_KEY and
		--base-url configuration as the other commands.
	`),
	Example: heredoc.Doc(`
		Run the server (usually done by the editor, not by hand):
	        
			secdb lsp

		Kate (Settings > LSP Client > User Server Settings):

		  {
		    "servers": {
		      "secdb": {
		        "command": ["secdb", "lsp"],
		        "commandDebug": ["secdb", "lsp", "--debug"],
		        "rootIndicationFileNames": ["go.mod", "package-lock.json", "yarn.lock", "requirements.txt", "Gemfile.lock", "pom.xml", "composer.lock"],
		        "highlightingModeRegex": "^(Go|JSON|Python|Ruby|XML)$"
		      }
		    }
		  }

		Sublime Text (Preferences > Package Settings > LSP > Settings), requires the "LSP" package:

		  {
		    "clients": {
		      "secdb": {
		        "enabled": true,
		        "command": ["secdb", "lsp"],
		        "selector": "source.go-mod | source.json | text.plain | text.xml | text.xml.dtd"
		      }
		    }
		  }

		Neovim (0.10+, native LSP client), in init.lua:

		  vim.api.nvim_create_autocmd({ "BufReadPost", "BufNewFile" }, {
		    pattern = { "go.mod", "package-lock.json", "yarn.lock",
		                "requirements*.txt", "Gemfile.lock", "pom.xml",
		                "composer.lock" },
		    callback = function(args)
		      vim.lsp.start({
		        name = "secdb",
		        cmd = { "secdb", "lsp" },
		        root_dir = vim.fs.root(args.buf, { ".git", "go.mod", "package.json", "pom.xml" }),
		      })
		    end,
		  })

		Zed (companion extension: github.com/giterlizzi/secdb-zed):

		  Zed can't point at an arbitrary LSP binary from settings; install the
		  extension and Zed starts "secdb lsp" on the recognized manifests. Note
		  that Zed launches the server lazily, on opening the first recognized
		  file; discovery then audits the rest of the workspace.
	`),
	RunE: func(cmd *cobra.Command, args []string) error {
		return lsp.NewServer(newSecDbClient(), !lspNoDiscovery).Run()
	},
}

func init() {
	lspCmd.Flags().BoolVar(&lspNoDiscovery, "no-discovery", false,
		"Disable workspace discovery (only audit manifests as they are opened)")

	rootCmd.AddCommand(lspCmd)
}
