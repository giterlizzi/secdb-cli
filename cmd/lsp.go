// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/giterlizzi/secdb-cli/internal/lsp"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/spf13/cobra"
)

var lspCmd = &cobra.Command{
	Use:   "lsp",
	Short: "Start the Language Server (LSP) for editor integration",
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
		        "rootIndicationFileNames": ["go.mod", "package-lock.json", "requirements.txt", "Gemfile.lock", "pom.xml", "composer.lock"],
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
	`),
	RunE: func(cmd *cobra.Command, args []string) error {
		return lsp.NewServer(newSecDbClient()).Run()
	},
}

func init() {
	rootCmd.AddCommand(lspCmd)
}
