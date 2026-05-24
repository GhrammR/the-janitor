# Governance Sync Skill

## Trigger

**Auto-activate on every completed fix, feature, or sprint directive.**

After any task that resolves a bug, implements a feature, or closes a
P-tier item, run this checklist before closing the directive.

## Checklist

For each issue fixed or feature implemented, answer all four questions:

### 1. Does a rule prevent this class of issue from reoccurring?

Check `.agent_governance/rules/` for a document that structurally forbids
the root cause.  If none exists, create one.

- Bug from blast radius? → `rules/pr-topology.md`
- Bug from logic clone accumulation? → `rules/pr-topology.md` (Logic Clone Law)
- Bug from missing CI monitoring? → `rules/pr-topology.md` (CI Monitoring Cadence)
- Bug from unsafe code pattern? → `rules/failure-modes.md`
- Bug from missing proof gate? → `rules/evolution.md`
- Bug from gate bootstrap dependency (new gate feature can't self-validate)? → `rules/release-discipline.md`
- Bug from wrong `just release` invocation (version with `v` prefix)? → `rules/release-discipline.md`

### 2. Does a skill auto-enforce the rule?

Check `.agent_governance/skills/` for a skill that fires automatically
when the triggering condition occurs.  If none exists, create one.

- PR creation → `skills/pr-resolution/` must exist and include blast-radius pre-check
- New classifier added → `skills/crucible-enforcement/` must require `classify_one_proof` registration
- New detector added → `skills/crucible-enforcement/` must require a Crucible test

### 3. Is the fix reflected in the CLAUDE.md index?

Update `.agent_governance/` table in `CLAUDE.md` if a new rule or skill
was added.

### 4. Is there a local verification command?

Every rule must have a `just <command>` or inline shell snippet that can
be run locally to verify compliance BEFORE pushing.

## Required Actions by Issue Class

### Blast Radius Violation

**Rule**: `rules/pr-topology.md`
**Pre-push verification**:
```bash
git diff --name-only origin/main...HEAD | sed 's|/.*||' | sort -u
# Count must be ≤ 5
```
**Skill**: `skills/pre-commit-gate/SKILL.md` — must include blast-radius check.

### Logic Clone Accumulation

**Rule**: `rules/pr-topology.md` (Logic Clone Law section)
**Pre-push verification**:
```bash
grep -c 'else if finding\.id\.contains' crates/cli/src/hunt.rs
# Must be 0 — all dispatch goes through classify_one_proof
```
**Policy**: `.janitor/policy.toml` must list `clone_exempt_paths` for
classifier-registry files with intentional predicate repetition.

### CI Failure Not Caught Locally

**Rule**: `rules/pr-topology.md` (CI Monitoring Cadence)
**Pre-push verification**:
```bash
just audit  # Must exit 0 before any git push
```
**Post-push monitoring**: Check `gh pr checks <N>` at 1 min, 5 min, 9 min.

### Gate Engine Bootstrap Dependency

**Rule**: `rules/release-discipline.md` (Law II)
**Pre-push verification** (when touching gate engine files):
```bash
git diff --name-only origin/main...HEAD | grep -E "slop_filter|policy\.rs"
# If non-empty: create a minimal hotfix PR first, release it, then push the feature PR
```
**Sequence**: hotfix PR (no clone issues) → merge → release → feature PR CI uses new binary.

### Release Version Format

**Rule**: `rules/release-discipline.md` (Law I)
**Verification**:
```bash
just release 10.2.3   # CORRECT — bare version
just release v10.2.3  # WRONG — causes version = "v10.2.3" in Cargo.toml
```
**Post-release check**:
```bash
grep '^version' Cargo.toml | head -1
# Must be: version = "X.Y.Z" (no v prefix)
```

### PR BEHIND After Hotfix Merge

**Rule**: `rules/release-discipline.md` (Law III)
**Verification**:
```bash
gh pr list --json headRefName,mergeStateStatus | jq '.[] | select(.mergeStateStatus == "BEHIND")'
# Must be empty before closing any directive
```
**Fix**: `git rebase origin/main && git push --force-with-lease origin <branch>`

### Missing Governance Update (this skill's own trigger)

After every sprint directive, before marking complete:
1. Run this checklist.
2. If any of the 4 questions above answer "no", create/update the missing
   governance artifact in `.agent_governance/`.
3. Include the governance updates in the `sprint*/infra` PR, not the code PR.

## Governance Artifact Ownership

| Artifact | Scope | PR target |
|---|---|---|
| `.agent_governance/rules/*.md` | Durable rules | `sprint*/infra` |
| `.agent_governance/skills/*/SKILL.md` | Auto-enforcement | `sprint*/infra` |
| `.janitor/policy.toml` | Gate configuration | `sprint*/code` |
| `CLAUDE.md` index | Navigation | `sprint*/infra` |
