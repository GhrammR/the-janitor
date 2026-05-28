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
   - `gh api repos/<owner>/<repo>/branches/<default_branch>/protection/required_status_checks --jq '{strict,contexts,checks}'`
   - `gh api repos/<owner>/<repo>/code-scanning/alerts -X GET -f state=open -f ref=refs/heads/main -F per_page=100`
3. Classify the PR:
   - **mergeable**: clean merge state, approved or no review required, required checks green.
   - **auto-merge-waiting**: clean merge state, no review required, checks
     pending, and auto-merge is armed or can be armed.
   - **solo-review-policy-drift**: branch protection requires review and the
     authenticated operator authored the PR. This is not a real review need in
     a solo-maintainer repository; restore zero required reviews.
   - **solo-required-checks-drift**: required status check contexts are empty
     or missing any expected always-on PR gate. This can allow auto-merge to
     merge before checks finish.
   - **code-scanning-baseline-open**: open alerts already exist on
     `refs/heads/main`; report count/severity/rule/path in telemetry.
   - **code-scanning-new-alerts**: the PR ref has more open alerts than the
     main baseline, or the Code Scanning Alert Audit reports net-new alerts.
   - **code-scanning-api-unavailable**: local and workflow inspection cannot
     read code-scanning alerts.
   - **gate-blocked**: app-owned check failed, timed out, or is still pending past 10 minutes.
   - **dirty**: merge state is `DIRTY`, `CONFLICTING`, or stale/unknown after refresh.
   - **supersede-only**: dirty plus gate-blocked, self-review plus another
     terminal blocker, Structural Firewall blast radius, or mixed
     GitHub-visible docs/engine/campaign/workflow work.
   - **release-branch-contaminated**: PR diff includes release artifacts
     (`janitor.cdx.json`, version-bumped `Cargo.toml`, `docs/index.md`,
     `README.md`) because the branch was cut from a `release/vX.Y.Z` branch
     rather than `origin/main`. Fix: `git rebase origin/main` (auto-skips
     the squash-merged release commit), then `git push --force-with-lease`.
     Remove any docs files mixed into the commit before pushing.
4. Act by class:
   - mergeable: merge or enable auto-merge.
   - review-blocked bot dependency: approve only after checking diff/checks, then enable auto-merge.
   - auto-merge-waiting: keep or enable `gh pr merge <pr> --auto --squash
     --delete-branch`, then run the 1m/5m/9m Post-Push Auto-Merge Watch.
   - solo-review-policy-drift: restore branch protection to
     `required_approving_review_count=0` if admin permission exists, verify
     branch protection, re-arm auto-merge, then run the watch cadence. If admin
     permission is missing, report the policy drift and ask the operator to
     change branch protection; do not request fake external review.
   - solo-required-checks-drift: restore expected required status checks if
     admin permission exists, verify `strict=true` and the context list, then
     re-evaluate the PR before arming auto-merge.
   - code-scanning-baseline-open: preserve as telemetry and continue PR
     resolution unless the PR modifies the alerted file/rule.
   - code-scanning-new-alerts: block auto-merge and remediate the new alert.
   - code-scanning-api-unavailable: require a successful
     `Code Scanning Alert Audit` check before finalizing PR state. The audit
     must cover immediate, +1 minute, +5 minutes, and +9 minutes samples, not
     just an early pre-CodeQL API read.
   - gate-blocked: inspect artifact/log once and report exact invariant.
   - dirty: recreate from `origin/main`; do not push more commits to the dirty branch.
   - supersede-only: comment, close if self-authored/superseded, and create narrow replacement branch.
5. When generating a Sovereign Directive prompt, mirror the live blocker as the
   first phase. Do not write a generic “fix PR” phase that ignores dirty state,
   review requirement, failed checks, or default-branch visibility.

## Post-Push Auto-Merge Watch

After every commit/push/PR-create flow, and after every push to an existing PR:

1. **Immediate check**: run `gh pr view <pr>` and `gh pr checks <pr>`.
   Also verify branch protection required status checks are non-empty and
   include the expected always-on PR gates from
   `.agent_governance/rules/pr-resolution.md`.
   Query open code-scanning alerts on `refs/heads/main`; if local permissions
   deny access, defer to the `Code Scanning Alert Audit` workflow and report
   that local code-scanning API access was unavailable.
2. **+1 minute check**: repeat both commands; report only changed blockers.
3. **+5 minute check**: repeat both commands; report only changed blockers.
4. **Final +9 minute check**: repeat both commands after the Governor/Janitor
   Integrity window. Expected terminal duration is approximately `9m2s`.
   Include code-scanning alert state in the final check.
   **If `Janitor Integrity Check` shows `timed_out`**: the Governor created a
   check run but the analysis never reported back. Immediately re-dispatch:
   ```bash
   gh workflow run janitor-pr-gate.yml \
     --repo janitor-security/the-janitor \
     --ref <head-branch> \
     -f pr_number=<N>
   ```
   Then repeat the 9-minute check window. Do NOT close the PR or push new
   commits — re-dispatch is always the correct first response to `timed_out`.
   Report as `GOVERNOR_CHECK_TIMED_OUT` until the re-dispatched run resolves.
5. If all required checks are green and auto-merge is not armed, run
   `gh pr merge <pr> --auto --squash --delete-branch`.
6. If the PR merged, verify with `gh pr view <pr> --json state,mergedAt`.
7. If the PR remains blocked, return exactly one action class and blocker.

## Output Contract

Report each PR as one of:

- `MERGE`
- `AUTO_MERGE_ARMED_WAITING_FOR_CHECKS`
- `SOLO_REVIEW_POLICY_DRIFT`
- `SOLO_REQUIRED_CHECKS_DRIFT`
- `CODE_SCANNING_BASELINE_OPEN`
- `CODE_SCANNING_NEW_ALERTS`
- `CODE_SCANNING_API_UNAVAILABLE`
- `WAIT_FOR_CHECKS`
- `GOVERNOR_CHECK_TIMED_OUT`
- `REBASE_OR_RECREATE`
- `RELEASE_BRANCH_CONTAMINATION`
- `CLOSE_SUPERSEDED`
- `LEAVE_OPEN`

For each non-mergeable PR, name exactly one blocker and one next action.
