# Claude Tooling Runbook

Operational documentation for the two developer tools that appear inside Claude
Code sessions and depend on this repository:

- **Janitor MCP** — `/home/ghrammr/dev/the-janitor/tools/mcp-wrapper.sh`
  (stdio JSON-RPC server, repo-managed)
- **rust-analyzer-lsp** — `claude-plugins-official/rust-analyzer-lsp`
  (third-party Claude Code plugin, environment-dependent)

## Fast path: run the diagnostic

```bash
./tools/claude-tooling-diag.sh
```

The script prints a `PASS` / `FAIL` / `NOTE` row for every check and exits
non-zero on any required failure. Use it as the first triage step every time
either tool misbehaves.

## 1. Janitor MCP

### What it is

`tools/mcp-wrapper.sh` is the stdio bridge Claude Code launches whenever it
detects this repo's `.mcp.json`. The wrapper:

1. Verifies a UDS daemon is listening on `/tmp/janitor.sock`.
2. If absent, spawns the daemon via `target/release/janitor serve` and waits
   1 s for it to bind.
3. Execs `target/release/janitor mcp` to bridge Claude Code's stdio to the
   JSON-RPC 2.0 server.

The MCP server exposes seven tools (`janitor_scan`, `janitor_dedup`,
`janitor_clean`, `janitor_dep_check`, `janitor_bounce`, `janitor_silo_audit`,
`janitor_provenance`) plus the visualizer / Z3 / WOPR helpers.

### Common failure signatures

| Symptom | Cause | Remediation |
| --- | --- | --- |
| Claude says "MCP server unavailable" or tool calls return InputValidationError | Claude Code has not reloaded since binary rebuild | Run `/restart` in Claude Code, or kill+restart the Claude Code process |
| Wrapper script exits immediately | Release binary is missing or not executable | Run `just build` (alias for `cargo build --release -p cli`) |
| Wrapper hangs at startup | UDS daemon failed to bind to `/tmp/janitor.sock` | `rm -f /tmp/janitor.sock` and retry; if still hung, check `lsof /tmp/janitor.sock` |
| `initialize` handshake returns non-JSON | Binary version mismatch (server emitted plain-text error before MCP framing) | Recompile and reload Claude Code |
| Tool calls succeed but mutate the wrong repo | UDS daemon was started from a different working directory | Stop the daemon (`pkill -f 'janitor serve'`), re-launch from this repo |

### Restart sequence

```bash
# 1. Stop any running daemon.
pkill -f 'janitor serve' || true
rm -f /tmp/janitor.sock

# 2. Refresh the binary if source has changed.
just build

# 3. Verify the wrapper handshakes correctly.
./tools/claude-tooling-diag.sh

# 4. Reload Claude Code.
#    From inside Claude Code: type "/restart"
#    Or kill the Claude Code process and re-launch.
```

### Expected diagnostic output (healthy state)

```
[1] Janitor MCP server
  [PASS] release binary present and executable
  [PASS] mcp wrapper script executable
  [PASS] .mcp.json present at repo root
  [PASS] .mcp.json points at the expected wrapper
  [PASS] binary --version returns: janitor <version>
  [PASS] 'janitor mcp' subcommand is registered
  [PASS] 'janitor serve' subcommand is registered
  [PASS|NOTE] UDS daemon listening (or note: wrapper auto-resurrects)
  [PASS] MCP initialize handshake returned a valid JSON-RPC response
```

### Escalation

If `./tools/claude-tooling-diag.sh` reports all `PASS` / `NOTE` rows but
Claude Code still cannot reach the server, the issue is on the Claude Code
side (not this repo). Open an issue at
<https://github.com/anthropics/claude-code/issues> with the diagnostic output
attached.

## 2. rust-analyzer-lsp (third-party plugin)

### What it is

`rust-analyzer-lsp` is a Claude Code plugin maintained by the
`claude-plugins-official` organization. It binds Claude Code's IDE-like surface
(go-to-definition, hover, symbol search) to a local `rust-analyzer` process.
**This repo does not ship or maintain that plugin.** The runbook documents
operational checks only.

### Common failure signatures

| Symptom | Cause | Remediation |
| --- | --- | --- |
| Hovering Rust code returns no info | `rust-analyzer` not in `PATH` | `rustup component add rust-analyzer` |
| Plugin appears disabled in Claude Code | `enabledPlugins` flag flipped off | Edit `~/.claude/settings.json` to set `"rust-analyzer-lsp@claude-plugins-official": true` |
| Plugin enabled but never starts | Plugin directory missing | Re-install via the Claude Code Plugin Marketplace UI |
| `rust-analyzer` runs but returns no symbols | Cargo cache is stale or corrupt | `cargo clean && cargo check` to repopulate |
| Plugin starts but project takes 5+ minutes to index | First-time `rust-analyzer` indexing on this 23-grammar workspace is naturally slow | Wait — subsequent loads are warm |

### Restart sequence

```bash
# 1. Verify rust-analyzer itself is healthy.
rust-analyzer --version

# 2. Verify Claude Code has the plugin enabled.
grep -A3 enabledPlugins ~/.claude/settings.json

# 3. Reload Claude Code (forces plugin re-init).
#    Type "/restart" inside Claude Code.

# 4. If still broken, re-install the plugin from the Marketplace UI.
```

### Expected diagnostic output (healthy state)

```
[2] rust-analyzer-lsp (third-party Claude plugin)
  [PASS] rust-analyzer binary in PATH: rust-analyzer <version>
  [PASS] Claude Code settings present
  [PASS] rust-analyzer-lsp plugin appears enabled in settings.json
  [PASS|NOTE] rust-analyzer-lsp plugin directory present (or note if absent)
```

### Escalation

The plugin is third-party. If the diagnostic shows `rust-analyzer` works
standalone but the Claude Code integration still fails, file an issue at
<https://github.com/anthropics/claude-code/issues> tagged `plugins`. Include:
- the diagnostic script output,
- contents of `~/.claude/settings.json` with secrets redacted,
- the Claude Code version (`claude --version`).

## Cross-tool observations

- **Both tools require restarting Claude Code after a binary or plugin
  reinstall.** Claude Code does not hot-reload either category.
- **Both tools degrade gracefully when broken.** The MCP server simply doesn't
  appear in the available-tools list; rust-analyzer features simply don't
  fire. Code edits and Bash commands still work.
- **Neither failure blocks `just audit`, `just release`, or any CI workflow.**
  These tools are interactive-session conveniences, not load-bearing CI
  components.

## Janitor formal toolchain preflight

Kani, Z3, and ShellCheck are load-bearing Janitor tooling, not interactive
Claude conveniences. They must live in durable paths and pass:

```bash
just toolchain-preflight
```

Expected stable paths:

- `cargo-kani`: `~/.cargo/bin/cargo-kani`.
- `z3`: `~/.local/share/janitor-tools/z3-venv/bin/z3`, exposed through
  `~/.local/bin/z3`.
- `shellcheck`: `~/.local/bin/shellcheck` or a system package path.

Temporary `/tmp` paths are rejected. Install Z3 with:

```bash
python3 -m venv ~/.local/share/janitor-tools/z3-venv
~/.local/share/janitor-tools/z3-venv/bin/python -m pip install --upgrade pip z3-solver
ln -sf ~/.local/share/janitor-tools/z3-venv/bin/z3 ~/.local/bin/z3
```

## Fly deployment preflight

Governor deploys are blocked until Fly authentication is visible to the agent:

```bash
/home/ghrammr/.fly/bin/flyctl auth whoami
```

Expected healthy output is the authenticated Fly account email. If it fails or
prints `no access token available`, invoke Crossroads Waiting with Option A as
the recommended default and include this external recovery command inside the
native popup:

```bash
/home/ghrammr/.fly/bin/flyctl auth login
```

If the host does not expose the native popup in the current mode, record that
the popup was unavailable, emit the same A/B/C checkpoint as a non-terminal
fallback, and resume the deploy immediately after the operator confirms the
login is complete.

## Adding new checks

The diagnostic script is intentionally short and grep-friendly. To add a check:

1. Append a new `ok` / `no` / `note` block in the appropriate Section.
2. Document the check + remediation in this runbook's failure-signature table.
3. Run the script and confirm it exits 0 on a healthy host.

Do not add network calls — the diagnostic must run offline so it works inside
hardened CI runners and air-gapped operator workstations.
