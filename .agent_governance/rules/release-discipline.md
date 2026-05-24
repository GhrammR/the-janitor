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
