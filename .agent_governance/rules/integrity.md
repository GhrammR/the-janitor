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

## Hard rules

- Never use `--no-verify` to skip hooks.
- Never use `--no-gpg-sign` to bypass provenance.
- Never amend a published commit.
- Never append `Co-authored-by:` trailers. Sole author: Riley Ghramm.
