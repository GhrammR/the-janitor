# Rule: PR Resolution Terminality

## Purpose

A pull request that is dirty, structurally oversized, blocked by impossible
solo-maintainer review policy, or red on app-owned gates is not a sprint
target. It is a routing failure. The agent must stop adding implementation
phases to that PR and create a concrete replacement plan.

## Solo Maintainer Mode

This repository is operated by a solo maintainer. Branch protection must use
required status checks as the merge authority, not required human review.

Required steady state:

1. `required_approving_review_count == 0`
2. `enforce_admins.enabled == true`
3. Required status checks are non-empty and include the expected always-on PR
   gates:
   - `PR Resolution Audit`
   - `Code Scanning Alert Audit`
   - `Janitor Integrity Check`
   - `Structural Firewall`
   - `MSRV — Rust 1.92.0`
   - `Dependency Review`
   - `Analyze (actions)`
   - `Analyze (javascript-typescript)`
   - `Analyze (python)`
   - `Analyze (rust)`
4. Signed commits remain mandatory by local policy.

If `reviewDecision=REVIEW_REQUIRED` on a human-authored PR in this solo repo,
classify it as `SOLO_REVIEW_POLICY_DRIFT`. Do not ask for external review as
the normal path. Restore the solo-maintainer branch-protection policy, verify
the policy, arm auto-merge, and then watch checks to completion.

If `required_status_checks.contexts` is empty or missing any expected always-on
PR gate, classify it as `SOLO_REQUIRED_CHECKS_DRIFT`. Do not arm auto-merge.
Restore the expected contexts first, verify branch protection, then re-evaluate
the PR.

## Code Scanning Alert Review

Every PR inspection must include GitHub code-scanning state. A passing CodeQL
check only proves that the current PR did not produce a failing CodeQL job; it
does not prove that the repository has no open code-scanning alerts on `main`.

Required code-scanning evidence:

```bash
gh api repos/<owner>/<repo>/code-scanning/alerts \
  -X GET -f state=open -f ref=refs/heads/main -F per_page=100 \
  --jq '[.[] | {number,rule:.rule.id,severity:(.rule.security_severity_level // .rule.severity),tool:.tool.name,path:.most_recent_instance.location.path,line:.most_recent_instance.location.start_line}]'
```

If the local token returns `403` or `404`, do not assume there are no alerts.
Report `CODE_SCANNING_API_UNAVAILABLE` and rely on the GitHub Actions
`Code Scanning Alert Audit` workflow, which runs with `security-events: read`.
That workflow is not a single early sample. It must sample code-scanning state
at `immediate`, `+1 minute`, `+5 minutes`, and `+9 minutes`, so delayed CodeQL
SARIF ingestion can surface before auto-merge completes.

Open baseline alerts on `main` must be reported as backlog telemetry on every
PR inspection. Existing baseline alerts do not block unrelated PRs by default.
New or increased alerts on a PR ref block the PR as `CODE_SCANNING_NEW_ALERTS`.

## Required Evidence

Before any final answer or next-sprint prompt says a PR should be fixed,
merged, closed, superseded, or auto-merge armed, collect current GitHub state:

```bash
gh api user --jq '{login,id}'
gh pr view <pr> --json author,headRefName,headRefOid,baseRefName,reviewDecision,mergeStateStatus,statusCheckRollup,url
gh pr checks <pr>
gh api repos/<owner>/<repo>/branches/<default_branch>/protection --jq '{required_pull_request_reviews,enforce_admins}'
gh api repos/<owner>/<repo>/branches/<default_branch>/protection/required_status_checks --jq '{strict,contexts,checks}'
gh api repos/<owner>/<repo>/code-scanning/alerts -X GET -f state=open -f ref=refs/heads/main -F per_page=100
```

For GitHub-visible documentation, also verify the rendered surfaces separately:

```bash
git show origin/<head_branch>:README.md | head -40
git show origin/<default_branch>:README.md | head -40
gh api repos/<owner>/<repo> --jq '{description,homepage,default_branch}'
```

## Terminal Failure Conditions

Treat a PR as **solo-review-policy-drift** when all of these are true:

1. Required branch protection has `required_approving_review_count > 0`.
2. `reviewDecision=REVIEW_REQUIRED`.
3. The authenticated operator authored the PR.

This state is not mergeable and not resolved. It is a repository policy drift,
not a request for an external reviewer. The final answer must say
`SOLO_REVIEW_POLICY_DRIFT` until branch protection is restored to zero required
approvals and the PR is rechecked.

Treat a PR as **solo-required-checks-drift** when either is true:

1. `required_status_checks.contexts` is empty.
2. Any expected always-on PR gate from Solo Maintainer Mode is absent.

This state is not mergeable and not resolved. Auto-merge may merge too early if
required contexts are empty. The final answer must say
`SOLO_REQUIRED_CHECKS_DRIFT` until the expected contexts are restored.

Treat a PR as **code-scanning-new-alerts** when the PR ref has more open
code-scanning alerts than `refs/heads/main`, or when the Code Scanning Alert
Audit workflow reports new high/critical findings attributable to the PR.

Treat a PR as **code-scanning-api-unavailable** when neither local inspection
nor the GitHub Actions audit can read code-scanning alerts. This is a telemetry
failure; the PR must not be called fully inspected.

Treat a PR as **supersede-only** when any of these are true:

1. `mergeStateStatus` is `DIRTY`, `CONFLICTING`, or `UNKNOWN` after refresh.
2. `reviewDecision=REVIEW_REQUIRED`, the authenticated operator authored the
   PR, and the PR is also dirty, gate-blocked, structurally oversized, or
   mixed-scope.
3. `Janitor Integrity Check`, `Structural Firewall`, or another app-owned gate
   is `FAILURE`, `TIMED_OUT`, or repeatedly pending beyond 10 minutes.
4. The Structural Firewall reports blast radius across more than five
   top-level directories, generated `.janitor/**` artifacts, clone bursts, or
   source-overwrite rows.
5. The PR tries to deliver GitHub-visible documentation together with engine,
   campaign, workflow, or generated-artifact changes.

## Required Action

For a solo-review-policy-drift PR:

1. Do **not** report the PR as merged, mergeable, or resolved.
2. Restore branch protection to `required_approving_review_count=0` if admin
   permission exists, preserving required checks and `enforce_admins`.
3. Verify branch protection after the update.
4. Re-arm auto-merge with `gh pr merge <pr> --auto --squash --delete-branch`.
5. Run the Post-Push Auto-Merge Watch cadence below.
6. If admin permission is missing, report `SOLO_REVIEW_POLICY_DRIFT` and ask
   the operator to update branch protection; do not ask for fake external
   review.

For a solo-required-checks-drift PR:

1. Do **not** arm auto-merge.
2. Restore the expected required status check contexts listed in Solo
   Maintainer Mode if admin permission exists.
3. Verify `required_status_checks.strict == true` and that all expected
   contexts are present.
4. Re-arm auto-merge only after this verification.
5. If admin permission is missing, report `SOLO_REQUIRED_CHECKS_DRIFT` and ask
   the operator to restore required checks.

For code-scanning issues:

1. If only baseline `main` alerts exist, report the count, severity, rule, and
   file/line in telemetry; do not block unrelated PRs.
2. If PR alerts exceed baseline, block the PR as `CODE_SCANNING_NEW_ALERTS`.
3. If the API is unavailable locally, require the `Code Scanning Alert Audit`
   workflow result before finalizing the PR state.
4. If both local and workflow audit are unavailable, report
   `CODE_SCANNING_API_UNAVAILABLE` and do not call the PR fully inspected.

## Post-Push Auto-Merge Watch

After every commit/push/PR-create flow, and after every push to an open PR:

1. Immediately collect `gh pr view <pr>`, `gh pr checks <pr>`, branch
   protection status-check contexts, and code-scanning alert state.
2. At `+1 minute`, collect the same state and report only changed blockers.
3. At `+5 minutes`, collect the same state and report only changed blockers.
4. At the final Governor window (`+9 minutes`; expected Janitor Integrity
   terminal duration is approximately `9m2s`), collect final PR state and
   code-scanning alert state.
5. If all expected checks pass and auto-merge is not armed, arm it.
6. If the PR merged, verify the merge and stop.
7. If the PR is still blocked after the final window, classify it using this
   rule and name exactly one blocker.

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
| green checks + clean merge state + no review required | merge or enable auto-merge |
| checks pending + clean merge state + no review required | `AUTO_MERGE_ARMED_WAITING_FOR_CHECKS`; run 1m/5m/9m watch |
| self-authored + review required + required review count > 0 | `SOLO_REVIEW_POLICY_DRIFT`; restore zero required reviews |
| required status checks empty or missing expected contexts | `SOLO_REQUIRED_CHECKS_DRIFT`; restore required check contexts |
| new PR code-scanning alerts above baseline | `CODE_SCANNING_NEW_ALERTS`; block and remediate |
| code-scanning API unavailable locally and in workflow | `CODE_SCANNING_API_UNAVAILABLE`; do not call fully inspected |
| dirty/conflicting | rebase/recreate from `origin/main`; do not merge |
| app-owned gate failed/timed out | inspect gate artifact; if PR-wide policy failure, split/close |
| stale feature PR superseded by narrower work | comment and close |

Branch protection must not be weakened by removing required status checks or
admin enforcement. In this solo-maintainer repository, setting required human
review count to zero is not a bypass; it is the steady-state policy that lets
status checks and auto-merge do their job.
