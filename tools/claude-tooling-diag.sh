#!/usr/bin/env bash
set -euo pipefail
# Claude Code tooling diagnostic — pass/fail health checks for the two
# operator-facing developer tools that depend on this repo.
#
# 1. Janitor MCP (this repo's stdio JSON-RPC server)
# 2. rust-analyzer-lsp (Claude plugin; environment-dependent)
#
# Exits 0 when ALL checks pass.  Exits 1 when any required check fails.
# Documents non-repo state with NOTE rows so the operator sees the full picture.
#
# Runbook:  docs/claude-tooling-runbook.md

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BINARY="${REPO_ROOT}/target/release/janitor"
WRAPPER="${REPO_ROOT}/tools/mcp-wrapper.sh"
SOCK="/tmp/janitor.sock"

PASS=0
FAIL=0

green() { printf '\033[1;32mPASS\033[0m'; }
red()   { printf '\033[1;31mFAIL\033[0m'; }
amber() { printf '\033[1;33mNOTE\033[0m'; }

ok() {
    printf '  [%s] %s\n' "$(green)" "$1"
    PASS=$((PASS + 1))
}
no() {
    printf '  [%s] %s\n' "$(red)" "$1"
    FAIL=$((FAIL + 1))
}
note() {
    printf '  [%s] %s\n' "$(amber)" "$1"
}

echo
echo "════════════════════════════════════════════════════════════"
echo " Claude Tooling Health Check"
echo "════════════════════════════════════════════════════════════"

# -----------------------------------------------------------------
# Section 1 — Janitor MCP server (repo-managed)
# -----------------------------------------------------------------
echo
echo "[1] Janitor MCP server"
echo "    -----------------------------------------------------"

if [ -x "${BINARY}" ]; then
    ok "release binary present and executable: ${BINARY}"
else
    no "release binary missing or not executable: ${BINARY}"
    note "remediation: cargo build --release -p cli"
fi

if [ -x "${WRAPPER}" ]; then
    ok "mcp wrapper script executable: ${WRAPPER}"
else
    no "mcp wrapper missing or not executable: ${WRAPPER}"
fi

if [ -f "${REPO_ROOT}/.mcp.json" ]; then
    ok ".mcp.json present at repo root"
    if grep -q '"command"' "${REPO_ROOT}/.mcp.json" \
        && grep -q "${WRAPPER}" "${REPO_ROOT}/.mcp.json"; then
        ok ".mcp.json points at the expected wrapper"
    else
        no ".mcp.json does not reference the wrapper at ${WRAPPER}"
    fi
else
    no ".mcp.json missing at repo root (Claude Code cannot discover the server)"
fi

# Skip subcommand checks if binary missing.
if [ -x "${BINARY}" ]; then
    if "${BINARY}" --version >/dev/null 2>&1; then
        VER="$("${BINARY}" --version 2>/dev/null | head -1)"
        ok "binary --version returns: ${VER}"
    else
        no "binary --version fails to execute"
    fi

    if "${BINARY}" mcp --help >/dev/null 2>&1; then
        ok "'janitor mcp' subcommand is registered"
    else
        no "'janitor mcp' subcommand missing — recompile required"
    fi

    if "${BINARY}" serve --help >/dev/null 2>&1; then
        ok "'janitor serve' subcommand is registered"
    else
        no "'janitor serve' subcommand missing — UDS daemon path broken"
    fi
fi

# UDS daemon listening check (best-effort).
if command -v ss >/dev/null 2>&1; then
    if ss -lx 2>/dev/null | grep -qF "${SOCK}"; then
        ok "UDS daemon is listening on ${SOCK}"
    else
        note "UDS daemon not listening — wrapper auto-resurrects it on first MCP call"
    fi
else
    note "'ss' utility unavailable; cannot verify UDS daemon state"
fi

# Wrapper handshake test — write a JSON-RPC initialize and read back capabilities.
if [ -x "${WRAPPER}" ] && [ -x "${BINARY}" ]; then
    REQ='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"diag","version":"0"}}}'
    RESP="$(printf '%s\n' "${REQ}" | timeout 5 "${WRAPPER}" 2>/dev/null | head -1 || true)"
    if printf '%s' "${RESP}" | grep -q '"jsonrpc":"2.0"'; then
        ok "MCP initialize handshake returned a valid JSON-RPC response"
    else
        no "MCP initialize handshake produced no JSON-RPC response"
        note "remediation: launch 'just build' to refresh the binary, then /restart Claude Code"
    fi
fi

# -----------------------------------------------------------------
# Section 2 — rust-analyzer-lsp (Claude plugin, environment-dependent)
# -----------------------------------------------------------------
echo
echo "[2] rust-analyzer-lsp (third-party Claude plugin)"
echo "    -----------------------------------------------------"

if command -v rust-analyzer >/dev/null 2>&1; then
    # Tolerate pipefail when rust-analyzer is in PATH but --version fails for
    # any reason (older builds, broken cargo cache, missing toolchain).
    RA_VER="$(rust-analyzer --version 2>/dev/null | head -1 || true)"
    if [ -n "${RA_VER}" ]; then
        ok "rust-analyzer binary in PATH: ${RA_VER}"
    else
        note "rust-analyzer in PATH but --version returned no output"
    fi
else
    note "rust-analyzer not in PATH — install via: rustup component add rust-analyzer"
fi

CLAUDE_SETTINGS="${HOME}/.claude/settings.json"
if [ -f "${CLAUDE_SETTINGS}" ]; then
    ok "Claude Code settings present: ${CLAUDE_SETTINGS}"
    if grep -q 'rust-analyzer-lsp' "${CLAUDE_SETTINGS}"; then
        ok "rust-analyzer-lsp plugin appears enabled in settings.json"
    else
        note "rust-analyzer-lsp plugin not referenced in settings.json"
        note "remediation: enable via Claude Code Plugin Marketplace UI"
    fi
else
    note "Claude Code settings not found at ${CLAUDE_SETTINGS}"
fi

if [ -d "${HOME}/.claude/plugins/claude-plugins-official/rust-analyzer-lsp" ]; then
    ok "rust-analyzer-lsp plugin directory present"
else
    note "rust-analyzer-lsp plugin not installed in ~/.claude/plugins/"
fi

# -----------------------------------------------------------------
# Summary
# -----------------------------------------------------------------
echo
echo "════════════════════════════════════════════════════════════"
echo " Result: ${PASS} pass, ${FAIL} fail"
echo "════════════════════════════════════════════════════════════"
echo

if [ "${FAIL}" -gt 0 ]; then
    echo "One or more required checks failed."
    echo "See: docs/claude-tooling-runbook.md"
    exit 1
fi
echo "All required checks passed."
echo "See docs/claude-tooling-runbook.md for restart / escalation steps."
exit 0
