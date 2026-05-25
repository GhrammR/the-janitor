# Release Discipline

## Law I — Bare Version in `just release`

`just release` accepts a **bare semver** (no `v` prefix).
The recipe internally prepends `v` for git tags and GH Release names.

```bash
# CORRECT
just release 10.2.3

# WRONG — causes version = "v10.2.3" in Cargo.toml and vv10.2.3 in docs
just release v10.2.3
```

**Pre-release verification:**
```bash
grep '^version' Cargo.toml | head -1
# Must match: version = "X.Y.Z"  (no leading v)
```

## Law I-B — Release on the Correct Branch

`just release` commits and pushes from whichever branch is CURRENTLY CHECKED OUT.
Always ensure `main` is the active branch before running a release.
**Never run `just release` as a background task** — branch switches during the run
corrupt the release commit (it lands on the wrong branch, Cargo.toml reverts, etc.).

```bash
# Pre-release check — MUST be on main, no background jobs modifying working tree
git branch --show-current   # Must print: main
git status --short           # Must be clean
```

## Law I-C — No Concurrent Working-Tree Mutations

`just release` modifies Cargo.toml, README.md, docs/index.md, and Cargo.lock in
the working tree. Running it in the background while doing `git checkout`, `git stash`,
or `git commit` in the foreground corrupts the release commit (race condition on the
working tree files).

**Required**: run `just release` in the FOREGROUND, on `main`, with no other git
operations in progress.

## Law II — Bootstrap Dependency

The Structural Firewall bootstraps from the **latest published GH Release binary**.
Any new feature added to the gate engine (slop_filter.rs, policy.rs, etc.)
cannot be validated by the gate itself until a new release is cut.

**Required sequence when a gate feature is added in a PR:**

1. Ship the feature in a minimal hotfix PR (no clone issues, no .janitor artifacts).
2. Merge the hotfix → cut a new release (this session: v10.2.3).
3. Only then can the full feature PR pass CI (the new binary reads the new config).

**Pre-push gate check for any gate-engine change:**
```bash
git diff --name-only origin/main...HEAD | grep -E "slop_filter|policy\.rs"
# If non-empty: plan a hotfix release before the main feature PR.
```

## Law II-B — CDN Propagation Window

After `just release` completes, GitHub's release asset CDN takes **2–5 minutes** to
propagate the new binary to all edge nodes. The Structural Firewall downloads the
binary from CDN on cache miss. If CI starts within this window, the download returns
404 and the run fails.

**Required after any release**: wait ≥5 minutes before pushing any PR that will
trigger a cache-miss Structural Firewall run (i.e., the first CI run with the new
release version).

**Verification**:
```bash
curl --fail --silent --location \
  "https://github.com/janitor-security/the-janitor/releases/download/v<VER>/janitor.sha384"
# Must return the SHA-384 hex string (not empty / not error) before pushing.
```

## Law II-C — Use `gh release download` for Release Asset Fetches

The Structural Firewall `action.yml` **must** use `gh release download` (not raw
`curl`) to fetch release binaries.  Raw curl follows GitHub's 302 redirect to S3.
S3's URL-signed token specifies `X-Amz-SignedHeaders=host` — any additional request
header (e.g., `Authorization: token`) breaks the HMAC-SHA256 signature check and
returns 401/403 (manifests as exit code 127 in Actions logs).  `gh release download`
uses the GitHub API endpoint and handles the auth+redirect correctly without
forwarding the token to S3.

**Invariant** (check any action.yml modification):
```bash
grep 'gh release download' action.yml
# Must return matches for both the current and bootstrap binary downloads.
grep 'curl.*releases/download' action.yml
# Must return NO matches — curl must not be used for release asset downloads.
```

If `action.yml` is ever modified, verify both invariants before merging.

## Law II-D — Release Binary Must Use Standard glibc Interpreter

The release binary **must** link against standard glibc (`/lib64/ld-linux-x86-64.so.2`),
not a Nix store glibc (`/nix/store/.../ld-linux-x86-64.so.2`).  A Nix-linked binary
cannot execute on GitHub Actions Ubuntu runners and causes "cannot execute: required
file not found" exit code 127 in the Structural Firewall.

**Root cause**: Nix-managed Rust toolchains (`/nix/store/.../cargo`) produce binaries
that embed Nix store library paths.  The build MUST run in a Docker container with a
standard glibc Rust image:

```bash
# Required build command for releases (run from workspace root):
docker run --rm \
  -v "$(pwd)":/workspace \
  -v "$HOME/.cargo/registry":/usr/local/cargo/registry \
  -w /workspace \
  rust:1.92-slim-bookworm \
  bash -c "apt-get update -q && apt-get install -y -q libgit2-dev libssl-dev pkg-config \
    && cargo build -p cli --release"
# Then copy the binary from target/release/janitor (inside Docker → /workspace/target/release/)
```

**Pre-release verification** (run after build, before uploading):
```bash
readelf -l target/release/janitor | grep "interpreter"
# Must NOT contain /nix/store — must show /lib64/ld-linux-x86-64.so.2
```

## Law II-E — Gate Configuration Surface is `janitor.toml`, NOT `.janitor/policy.toml`

`JanitorPolicy::load(root)` reads `janitor.toml` at the repository root.
The file `.janitor/policy.toml` does **not** exist as a config surface — writing
gate configuration there silently has no effect.

**Root cause of a real incident (Sprint 170):** `clone_exempt_paths` was written
to `.janitor/policy.toml` instead of `janitor.toml [forge]`.  The gate read empty
`ForgeConfig`, scored 34 structurally-identical Kani predicate functions as logic
clones, and blocked PR #130 with slop_score 170 for multiple CI cycles.

**Invariant** (check any `[forge]` config change):
```bash
grep 'clone_exempt_paths\|require_pinned_dependencies' janitor.toml
# Must appear in janitor.toml — never in .janitor/policy.toml
ls .janitor/policy.toml 2>/dev/null && echo "ERROR: wrong policy surface" || echo "ok"
```

## Law III — PR Rebase After Hotfix

After any hotfix merges to main, ALL open feature PRs are BEHIND.
Auto-merge will not fire on a BEHIND PR.

**Required actions:**
1. `git fetch origin && git rebase origin/main` on each open feature branch.
2. `git push --force-with-lease origin <branch>`.
3. Monitor CI at 1min, 5min, 9min after push.

**Verification:**
```bash
gh pr list --json headRefName,mergeStateStatus | jq '.[] | select(.mergeStateStatus == "BEHIND")'
# Must be empty before marking any directive complete.
```

## Law II-F — CLI Builder Must Chain All Policy Fields

When `JanitorPolicy::load` is used to load policy in `cmd_bounce`, ALL
`ForgeConfig` fields that are used by `PatchBouncer` must be explicitly
wired via builder methods.  The raw constructor
`for_workspace_with_deep_scan_and_suppressions` does NOT auto-load any
fields; `for_workspace()` does.

**Invariant** (check before adding any new `ForgeConfig` field that affects bounce):
```bash
grep 'with_clone_exempt_paths\|with_require_pinned_dependencies' crates/cli/src/main.rs
# Both must be present — every ForgeConfig field used by PatchBouncer must be wired here
```

**Root cause of Sprint 170 incident**: `clone_exempt_paths` was added to
`ForgeConfig` and `PatchBouncer` but the CLI's `cmd_bounce` was not updated
to chain `.with_clone_exempt_paths(...)`.  Result: 34 Kani predicates in
`proof_obligation.rs` scored as logic clones (slop_score 170, PR #130 blocked
for multiple CI cycles).

## Law II-H — Release PRs Are Exempt from Topology Checks

`release/v*` branches are machine-generated by `just fast-release` and produce a single
atomic version-bump commit that legitimately spans all layers: `crates/`, `docs/`,
`Cargo.toml`, `Cargo.lock`, `README.md`, `mkdocs.yml`, `justfile`, `action.yml`, etc.
This will always exceed 5 top-level directories and always mix docs with engine changes.

**The PR Resolution Audit exempts `release/v*` branches** from blast-radius and
docs-isolation checks. No manual stripping or secondary docs PRs are required.

**No action needed from the operator.** `just fast-release` produces a release branch;
the audit passes it through automatically. The Structural Firewall and Janitor Integrity
Check still apply (and pass, since release commits have no slop).

**Root cause of previous workaround (Sprint 170, PR #140):** The audit lacked the
`release/v*` exemption. Fixed in Sprint 171 (PR #147) — `is_release_branch` guard
added to `pr-resolution-audit.yml`.
