# Editor integration (Language Server)

`secdb lsp` is a [Language Server](https://microsoft.github.io/language-server-protocol/): it audits the dependency manifests you open in the editor and shows the vulnerabilities as diagnostics on the dependency lines, each linking to its ZEN SecDB advisory. It uses the same parsers as [`audit manifest`](audit.md#audit-a-dependency-manifest), so it reads the same files (`go.mod`, `package-lock.json`, `yarn.lock`, `requirements*.txt`, `Gemfile.lock`, `pom.xml`, `composer.lock`), and the same `SECDB_API_KEY`, `--base-url` and `--web-url`.

The editor starts the server and talks to it over stdin/stdout; run by hand in a terminal it just waits for input. While you type, the audit waits until you stop for a moment. `SECDB_DEBUG=1` or `--debug` writes a log to stderr.

At startup the server also audits every supported manifest in the workspace, one after the other, so the findings appear without opening each file. Directories such as `node_modules`, `vendor`, `target`, `dist`, `build` and `testdata` are skipped, symlinks are not followed, and files already open in the editor are left to the editor. `--no-discovery` turns this off.

The rules are the ones of the `audit` commands. Vulnerabilities with no fix are hidden unless `--show-unfixed` is given. A finding accepted in the ignore file is still shown, as a hint with the rule's reason (e.g. `(ignored: not reachable)`). The ignore file is the one given with `--ignore-file`, or else the nearest `.secdbignore` going up from the manifest's directory to the workspace root; it is read again at every audit, so a change applies on the next one.

| Flag | Description |
|---|---|
| `--no-discovery` | Don't audit the workspace at startup, only the files you open |
| `--show-unfixed` | Also report vulnerabilities with no fix (hidden by default) |
| `--ignore-file` | YAML file of accepted risks (default: the nearest `.secdbignore` up to the workspace root) |

## Editor settings

Some editors (e.g. Zed) don't let you change the server command, so the same options can be set in the editor's LSP settings, in a `secdb` section. They take precedence over the flags; a key you leave out keeps the flag's value.

| Setting | Default | Description |
|---|---|---|
| `discovery` | `true` | Audit the workspace at startup (`--no-discovery`) |
| `showUnfixed` | `false` | Also report vulnerabilities with no fix (`--show-unfixed`) |
| `ignoreFile` | nearest `.secdbignore` | YAML file of accepted risks (`--ignore-file`) |
| `discoverySummary` | `true` | Show a message with the result of the startup audit |
| `updateNotice` | `true` | Show a message when a new version is available |

The server reads them from the editor (`workspace/configuration`) at startup and every time you change them, and the new values apply from the next audit, without a restart. For editors without `workspace/configuration`, the same keys can be passed as `initializationOptions`, without the `secdb` section.

When a newer `secdb` release is available, the server says so once, with a **Release notes** button where the editor supports it. `updateNotice: false` or `SECDB_NO_UPDATE_CHECK` turns the message off, as for the CLI.

## Editor configuration

<details>
<summary><strong>Kate / KDevelop</strong> (Settings &gt; LSP Client &gt; User Server Settings)</summary>

```json
{
  "servers": {
    "secdb": {
      "command": ["secdb", "lsp"],
      "commandDebug": ["secdb", "lsp", "--debug"],
      "rootIndicationFileNames": ["go.mod", "package-lock.json", "yarn.lock", "requirements.txt", "Gemfile.lock", "pom.xml", "composer.lock"],
      "highlightingModeRegex": "^(Go|JSON|Python|Ruby|XML)$",
      "settings": { "secdb": { "showUnfixed": true } }
    }
  }
}
```
</details>

<details>
<summary><strong>Sublime Text</strong> (Preferences &gt; Package Settings &gt; LSP &gt; Settings, requires the <code>LSP</code> package)</summary>

```json
{
  "clients": {
    "secdb": {
      "enabled": true,
      "command": ["secdb", "lsp"],
      "selector": "source.go-mod | source.json | text.plain | text.xml | text.xml.dtd"
    }
  }
}
```
</details>

<details>
<summary><strong>Neovim</strong> (0.10+, native LSP client, no plugin)</summary>

`secdb` is not among Neovim's preconfigured servers, so start it from an autocommand on the manifest file names (filetype detection is unreliable for `yarn.lock` and `Gemfile.lock`). In `init.lua`:

```lua
vim.api.nvim_create_autocmd({ "BufReadPost", "BufNewFile" }, {
  pattern = {
    "go.mod", "package-lock.json", "yarn.lock",
    "requirements*.txt", "Gemfile.lock", "pom.xml",
    "composer.lock",
  },
  callback = function(args)
    vim.lsp.start({
      name = "secdb",
      cmd = { "secdb", "lsp" },
      root_dir = vim.fs.root(args.buf, { ".git", "go.mod", "package.json", "pom.xml" }),
      settings = { secdb = { showUnfixed = true } },
    })
  end,
})
```

`secdb` must be on your `PATH`. `vim.lsp.start` reuses the same server for files under the same root.
</details>

<details>
<summary><strong>Zed</strong> (companion extension)</summary>

In Zed a language server must come from an extension, so install the [secdb Zed extension](https://github.com/giterlizzi/secdb-zed): Zed then starts `secdb lsp` (which must be on your `PATH`) when you open the first supported manifest, and the startup audit covers the rest of the project.

Settings go in Zed's `settings.json`:

```json
{
  "lsp": {
    "secdb": {
      "settings": { "secdb": { "showUnfixed": true, "discoverySummary": true } }
    }
  }
}
```
</details>

Not every editor gives these files a language of their own, and the editor needs one to decide when to start the server: Sublime treats `go.mod` as `text.xml.dtd` (hence that entry in the selector above), and `requirements.txt`, `Gemfile.lock` and `yarn.lock` as plain text. The server itself recognizes the files by name.
