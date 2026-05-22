# Rule: PR Resolution Terminality

## Purpose

A pull request that is dirty, structurally oversized, self-review blocked, or
red on app-owned gates is not a sprint target. It is a routing failure. The
agent must stop adding implementation phases to that PR and create a concrete
replacement plan.

## Required Evidence

Before any final answer or next-sprint prompt says a PR should be fixed,
merged, closed, superseded, or auto-merge armed, collect current GitHub state:

```bash
gh api user --jq '{login,id}'
gh pr view <pr> --json author,headRefName,headRefOid,baseRefName,reviewDecision,mergeStateStatus,statusCheckRollup,url
gh pr checks <pr>
gh api repos/<owner>/<repo>/branches/<default_branch>/protection --jq '{required_pull_request_reviews,enforce_admins}'
```

For GitHub-visible documentation, also verify the rendered surfaces separately:

```bash
git show origin/<head_branch>:README.md | head -40
git show origin/<default_branch>:README.md | head -40
gh api repos/<owner>/<repo> --jq '{description,homepage,default_branch}'
```

## Terminal Failure Conditions

Treat a PR as **external-review-required** when all of these are true:

1. Required branch protection has `required_approving_review_count > 0`.
2. `reviewDecision=REVIEW_REQUIRED`.
3. The authenticated operator authored the PR.
4. No different write-access reviewer has approved it.

This state is not mergeable and not resolved. Arming `gh pr merge --auto` may
be useful, but it is not completion because auto-merge cannot satisfy the
missing human approval. The final answer must say `EXTERNAL_REVIEW_REQUIRED`
and name the exact review blocker.

Treat a PR as **supersede-only** when any of these are true:

1. `mergeStateStatus` is `DIRTY`, `CONFLICTING`, or `UNKNOWN` after refresh.
2. `reviewDecision=REVIEW_REQUIRED`, the authenticated operator authored the
   PR, and the PR is also dirty, gate-blocked, structurally oversized, or
   mixed-scope. Self-review by itself is `review-blocked`, not mergeable.
3. `Janitor Integrity Check`, `Structural Firewall`, or another app-owned gate
   is `FAILURE`, `TIMED_OUT`, or repeatedly pending beyond 10 minutes.
4. The Structural Firewall reports blast radius across more than five
   top-level directories, generated `.janitor/**` artifacts, clone bursts, or
   source-overwrite rows.
5. The PR tries to deliver GitHub-visible documentation together with engine,
   campaign, workflow, or generated-artifact changes.

## Required Action

For an external-review-required PR:

1. Do **not** report the PR as merged, mergeable, or resolved.
2. Do **not** use `ENABLE_AUTO_MERGE_AFTER_REVIEW`; that action class is
   reserved for bot-authored dependency PRs after review has been supplied or
   requested by a different write-access actor.
3. Request an external approving review from a write-access reviewer when one
   is known.
4. If no external reviewer is available, ask the operator for exactly one
   explicit choice: provide a reviewer, close/supersede the PR, or authorize a
   temporary branch-protection bypass.
5. A bypass is allowed only with explicit operator approval, all required
   checks green, immediate restoration of the original review count, and final
   proof that branch protection is back to its original state.

For a supersede-only PR:

1. Do **not** add more commits to the broken branch.
2. Comment that the PR is superseded and name the current blocker.
3. Close the PR when it is self-authored or explicitly superseded by a newer
   narrow branch.
4. Recreate work from `origin/main` in narrow branches:
   - docs/public surface only: `README.md`, `docs/index.md`,
     `docs/security.md`, repository metadata sync, and required changelog entry.
   - engine proof only: `crates/**`, `.INNOVATION_LOG.md`, `docs/CHANGELOG.md`.
   - campaign ledger only: `tools/campaign/**`.
   - platform workflow only: `.github/**`, `action.yml`, and owned workflow docs.
5. New next-sprint prompts must include phases for the current blocker first:
   dirty branch, review deadlock, failing app gate, or blast-radius split.
   They must not keep repeating generic “fix PR #<n>” phases.

## Merge / Close Decision Table

| PR state | Action |
|----------|--------|
| green checks + approved + clean merge state | merge or enable auto-merge |
| green checks + review required + bot-authored dependency PR | request/perform write-access review, then enable auto-merge |
| self-authored + review required + required review count > 0 | `EXTERNAL_REVIEW_REQUIRED`; external approval or explicit bypass required |
| dirty/conflicting | rebase/recreate from `origin/main`; do not merge |
| app-owned gate failed/timed out | inspect gate artifact; if PR-wide policy failure, split/close |
| stale feature PR superseded by narrower work | comment and close |

Branch protection must never be weakened except for a docs-only emergency merge
with explicit operator approval, all required checks green, immediate restoration
of the original review count, and final branch-protection proof.
