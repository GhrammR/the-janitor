# Rule: Pre-Commit Integrity (Law III)

Before finalizing any commit, execute in order:

## Step 1 — `janitor_bounce` (MCP)

Run against `git diff HEAD` or the patch being committed.

- If `slop_score > 0`: read `antipattern_details`, remediate each finding,
  re-run until clean.
- A non-zero score is a **hard block**. Do not commit.

## Step 2 — `janitor_silo_audit` (MCP)

Run any time `Cargo.toml` or `Cargo.lock` is modified.

- New silos introduced by a dependency upgrade must be documented or resolved
  before commit.

## Step 3 — `just audit`

Must exit 0. This is the Definition of Done. No exceptions.

`just audit` runs: `cargo fmt --check` + `cargo clippy -- -D warnings` +
`cargo check` + `cargo test`.

**A task is only COMPLETE if `just audit` passes AND at least one new unit
test validates the specific change.**  Passing audit without a new test is
a partial completion — the change has no regression coverage and will be
treated as incomplete by the pre-commit gate.

## Step 4 — Signed Commit Handoff

If `git commit` fails because GPG cannot access the signing key or passphrase:

- Do not retry with `--no-gpg-sign`.
- Do not end the release flow as blocked without asking the operator for the
  unlock handoff.
- Ask exactly: `Run gpg-unlock, enter the passphrase in the terminal, then reply "continue".`
- Preserve the staged index.
- After the operator confirms unlock, retry the same signed commit and continue
  the push/PR/merge sequence.

## Law III-E — Detector-Sink Keywords MUST NOT Appear as Test Input Strings

Test functions in `#[cfg(test)]` blocks that pass string literals to utility functions
(e.g., `hash_pattern(b"...")`, `ingest_pattern(...)`, `AhoCorasick::build(...)`)
**MUST** use abstract names — never actual detector sink keywords.

**Why:** The CI diff includes full file content for new modules. `janitor bounce` on CI
uses the RELEASED binary and flags detector sink keywords regardless of whether they appear
in test code or production code.  A `security:` finding from a false-positive causes
`is_critical=true`, which turns any Governor POST connectivity failure into a hard crash
(`governor POST failed — critical threat intercept blocked`).

**Forbidden pattern:**
```rust
hash_pattern(b"copy_from_user")       // fires security:kernel_oob_write
hash_pattern(b"kmalloc")              // fires security:kernel_heap_spray
hash_pattern(b"call_usermodehelper")  // fires security:kernel_rce_usermode_helper
hash_pattern(b"kfree")               // fires security:kernel_uaf
hash_pattern(b"modprobe_path")        // fires security:kernel_privilege_path_write
hash_pattern(b"SELECT * FROM users")  // fires security:sql_injection
hash_pattern(b"eval(request.body)")   // fires security:code_injection
```

**Required pattern:**
```rust
hash_pattern(b"oob_pattern_alpha")    // abstract — never matches any detector sink
hash_pattern(b"heap_pattern_beta")
hash_pattern(b"rce_pattern_gamma")
hash_pattern(b"uaf_pattern_delta")
hash_pattern(b"privesc_pattern_epsilon")
```

**Root cause (Sprint 179, 2026-05-28):** `immunity.rs` tests used `b"copy_from_user"`,
`b"kmalloc_heap_spray"`, `b"call_usermodehelper"`, `b"kfree_use_after_free"`,
`b"modprobe_path_write"` as test inputs.  The v10.2.10 kernel.rs detector fired on all
four kernel sink keywords, emitting `security:` findings in the CI diff.  `is_critical=true`
turned the transient Governor POST connectivity error into a hard crash (PR #185 blocked).

## Law III-F — Pre-Commit Bounce Must Use Current Binary; Restart MCP Server After Release

The `janitor_bounce` MCP tool runs with the binary that was compiled when the MCP server
**started**.  After `just release`, the MCP server binary is stale — it predates all
detectors added in the just-released sprint.  CI uses the newly released binary.

**Consequence:** New detectors fire in CI but not in the local MCP bounce — the pre-commit
gate returns `slop_score = 0` while CI returns `security:` findings.

**Required action after every `just release`:**
1. Restart the MCP server so the pre-commit bounce uses the same binary version as CI.
2. Verify version parity: `janitor --version` (binary) vs the version in `Cargo.toml`.

**Root cause (Sprint 179, 2026-05-28):** MCP server was running a pre-kernel.rs binary.
`immunity.rs` test strings containing kernel sink keywords passed the local bounce but
triggered 4 `security:kernel_*` findings in the CI diff, blocking PR #185.

## Hard rules

- Never use `--no-verify` to skip hooks.
- Never use `--no-gpg-sign` to bypass provenance.
- Never amend a published commit.
- Never append `Co-authored-by:` trailers. Sole author: Riley Ghramm.
