# Skill: PR Resolution Gate

**Trigger:** Use when a directive mentions an existing PR, asks why a PR is not
mergeable, asks to merge/close PRs, or asks for a next prompt that includes PR
work.

## Protocol

1. Read `.agent_governance/rules/pr-resolution.md`.
2. Resolve live state:
   - `gh api user --jq '{login,id}'`
   - `gh pr view <pr> --json author,headRefName,headRefOid,baseRefName,reviewDecision,mergeStateStatus,statusCheckRollup,url`
   - `gh pr checks <pr>`
   - `gh api repos/<owner>/<repo>/branches/<default_branch>/protection --jq '{required_pull_request_reviews,enforce_admins}'`
3. Classify the PR:
   - **mergeable**: clean merge state, approved or no review required, required checks green.
   - **review-blocked**: checks green or still running, but review is required.
   - **external-review-required**: checks are green or auto-merge is armed, but
     branch protection requires review and the authenticated operator authored
     the PR. This is not resolved.
   - **gate-blocked**: app-owned check failed, timed out, or is still pending past 10 minutes.
   - **dirty**: merge state is `DIRTY`, `CONFLICTING`, or stale/unknown after refresh.
   - **supersede-only**: dirty plus gate-blocked, self-review plus another
     terminal blocker, Structural Firewall blast radius, or mixed
     GitHub-visible docs/engine/campaign/workflow work.
4. Act by class:
   - mergeable: merge or enable auto-merge.
   - review-blocked bot dependency: approve only after checking diff/checks, then enable auto-merge.
   - external-review-required: request a different write-access approving
     reviewer, or ask the operator to choose external review, close/supersede,
     or explicit temporary branch-protection bypass. Do not describe auto-merge
     as completion.
   - gate-blocked: inspect artifact/log once and report exact invariant.
   - dirty: recreate from `origin/main`; do not push more commits to the dirty branch.
   - supersede-only: comment, close if self-authored/superseded, and create narrow replacement branch.
5. When generating a Sovereign Directive prompt, mirror the live blocker as the
   first phase. Do not write a generic “fix PR” phase that ignores dirty state,
   review requirement, failed checks, or default-branch visibility.

## Output Contract

Report each PR as one of:

- `MERGE`
- `ENABLE_AUTO_MERGE_AFTER_REVIEW`
- `EXTERNAL_REVIEW_REQUIRED`
- `BYPASS_REQUIRES_EXPLICIT_APPROVAL`
- `WAIT_FOR_CHECKS`
- `REBASE_OR_RECREATE`
- `CLOSE_SUPERSEDED`
- `LEAVE_OPEN`

For each non-mergeable PR, name exactly one blocker and one next action.
