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
