# Editor integration (Language Server)

`secdb lsp` starts a [Language Server](https://microsoft.github.io/language-server-protocol/) that audits dependency manifests **as you open and edit them**, reporting known vulnerabilities inline as editor diagnostics, each linking to its ZEN SecDB advisory. It reuses the same engine as [`audit manifest`](audit.md#audit-a-dependency-manifest), so it recognizes the same files (`go.mod`, `package-lock.json`, `yarn.lock`, `requirements*.txt`, `Gemfile.lock`, `pom.xml`, `composer.lock`) and honors the same `SECDB_API_KEY`, `--base-url` and `--web-url` configuration.

The server speaks JSON-RPC over stdin/stdout and is meant to be launched by an editor's LSP client, not run by hand (in a plain terminal it just waits for input). It debounces edits, so it audits shortly after you stop typing rather than on every keystroke. Set `SECDB_DEBUG=1` (or pass `--debug`) to log to stderr.

On startup the server also **discovers and audits every supported manifest in the workspace**, so findings show up without opening each file (noise directories like `node_modules`, `vendor`, `target`, `dist`, `build` and `testdata` are skipped, and symlinks aren't followed). Discovery skips files you already have open (they're kept fresh by the edit path) and audits the rest sequentially. Pass `--no-discovery` to audit only files as they are opened.

Findings follow the same rules as the `audit` commands. Vulnerabilities with no fix available are hidden unless you pass `--show-unfixed`. A finding matched by an ignore rule is still reported, as a **hint** that carries the rule's reason (e.g. `(ignored: not reachable)`), rather than an error or a warning. The ignore file is the nearest `.secdbignore` from the manifest's directory up to the workspace root, or the file given with `--ignore-file`; it's re-read on every audit, so an edited rule applies on the next one.

| Flag | Description |
|---|---|
| `--no-discovery` | Don't audit the whole workspace on startup, only the files you open |
| `--show-unfixed` | Also report vulnerabilities that have no fix available (hidden by default) |
| `--ignore-file` | YAML file of accepted-risk rules (default: the nearest `.secdbignore` up to the workspace root) |

**Editor settings.** Since some editors (e.g. Zed) don't let you change the server command, the same options can be set from the editor's LSP settings, under a `secdb` section. They override the flags, and a key you leave out keeps the flag's value:

| Setting | Default | Description |
|---|---|---|
| `discovery` | `true` | Audit the whole workspace on startup (`--no-discovery`) |
| `showUnfixed` | `false` | Also report vulnerabilities with no fix available (`--show-unfixed`) |
| `ignoreFile` | nearest `.secdbignore` | YAML file of accepted-risk rules (`--ignore-file`) |
| `discoverySummary` | `true` | Show the end-of-discovery summary message |
| `updateNotice` | `true` | Show the "new version available" message |

The server asks the editor for them (`workspace/configuration`) on startup and again whenever you change them, so a new value applies from the next audit without restarting the server. The same keys are also accepted, flat (without the `secdb` section), as `initializationOptions`, for editors that don't support `workspace/configuration`.

When a newer `secdb` release is available, the server says so once with a message (with a **Release notes** button where the editor supports it). Turn it off with `updateNotice: false`, or with `SECDB_NO_UPDATE_CHECK`, like the CLI.

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

Neovim has a built-in LSP client. Since `secdb` isn't a preconfigured server, start it from an autocommand keyed on the manifest file names (this sidesteps filetype detection, which is inconsistent for `yarn.lock`/`Gemfile.lock`). Add to your `init.lua`:

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

`secdb` must be on your `PATH`. `vim.lsp.start` reuses one server per project root, and Neovim shows the reported vulnerabilities as diagnostics automatically.
</details>

<details>
<summary><strong>Zed</strong> (companion extension)</summary>

Unlike Kate, KDevelop and Sublime, Zed can't point at an arbitrary LSP binary from its settings: a language server must be provided by an extension. Install the companion [**secdb Zed extension**](https://github.com/giterlizzi/secdb-zed) and, once enabled, Zed starts `secdb lsp` automatically on the recognized manifests (make sure `secdb` is on your `PATH`). Zed launches the server lazily, on opening the first recognized file; workspace discovery then audits the rest of the project.

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

A few files aren't recognized as a distinct language by every editor, so the server may not start on them out of the box: Sublime scopes `go.mod` as `text.xml.dtd` (hence the entry in the selector above), and `requirements.txt`, `Gemfile.lock` and `yarn.lock` are plain text. The server itself detects the format from the file name regardless; it's only the editor's trigger that needs the scope/language hint.
