# Skill: Pre-Commit Gate (Auto-Invoked)

**Trigger:** Whenever the user asks to commit, stage files, or finalize changes.

## Protocol

1. **Run `janitor_bounce` (MCP)** against the current diff:
   - Input: output of `git diff HEAD` (or the staged patch)
   - If `slop_score > 0`:
     - Read `antipattern_details` from the response
     - Report each violation to the user
     - **ABORT** — do not proceed with the commit
     - Ask the user to remediate each finding and re-invoke

   **Before running the bounce, check Law III-E (integrity.md):** scan the diff
   for `#[cfg(test)]` blocks. If any test function passes a string literal to
   `hash_pattern()`, `ingest_pattern()`, or similar utilities, verify that string
   does NOT match any detector sink keyword (kernel API names, SQL keywords,
   credential patterns, shell-injection strings, etc.). Replace with abstract names
   (`oob_pattern_alpha`, `heap_pattern_beta`, etc.) before bouncing.

   **Also verify Law III-F:** if the sprint added or modified detectors in `crates/forge/src/`,
   confirm the MCP server was restarted after the most recent `just release`. A stale MCP
   server binary will miss detectors added in the current release, giving a false `slop_score = 0`
   that CI (using the released binary) will contradict.

2. **If `slop_score == 0`**, proceed to:
   - Run `just audit` (or confirm it has already passed in this session)
   - Only then finalize the commit
   - If the finalized work is pushed to a pull request, invoke
     `.agent_governance/skills/pr-resolution/SKILL.md` and run its Post-Push
     Auto-Merge Watch at immediate, +1 minute, +5 minutes, and final +9
     minutes.

2a. **Pre-`gh pr create` gate — run ALL three checks before opening any PR:**

   **Check 1 — Blast radius (≤5 top-level dirs):**
   ```bash
   git diff --name-only origin/main...HEAD | sed 's|/.*||' | sort -u | wc -l
   ```
   If count > 5: split the PR by topic (Code / Infrastructure / Docs) per `pr-topology.md` before proceeding.

   **Check 2 — Docs isolation (Law II-H):**
   ```bash
   git diff --name-only origin/main...HEAD | grep -E '^(README\.md|docs/)' && \
   git diff --name-only origin/main...HEAD | grep -E '^(crates/|tools/|\.github/)'
   ```
   If BOTH match: docs files are mixed with engine/workflow files. Remove the docs files from the commit (restore with `git checkout origin/main -- <docs-file>`) and carry them in a separate docs-only PR.

   **Check 3 — Branch source (never from release/vX.Y.Z):**
   ```bash
   git log --oneline origin/main..$(git merge-base HEAD origin/main) 2>/dev/null | head -3
   ```
   If this shows release-commit artifacts (`chore: release`, SBOM diffs, `Cargo.toml` version bump), the branch was cut from a release branch. Rebase with `git rebase origin/main` before opening the PR.

   **Only proceed to `gh pr create` after all three checks pass.**

2b. **PR Gate Presence Check (60 s after `gh pr create`):**
   ```bash
   gh pr checks <N> 2>&1 | grep -q "Janitor PR Gate"
   ```
   If `Janitor PR Gate` is absent from the output after 60 seconds:
   1. Immediately re-dispatch:
      ```bash
      gh workflow run janitor-pr-gate.yml \
        --repo janitor-security/the-janitor \
        --ref <head-branch> \
        -f pr_number=<N>
      ```
   2. Wait 90 s, then verify `gh pr checks <N> --watch` shows Janitor PR Gate running.
   3. Log the event: GitHub silently dropped the `pull_request.opened` event —
      re-dispatch via `workflow_dispatch` is the recovery path.
   **Never proceed to merge-readiness checks until Janitor PR Gate is confirmed queued.**

2b. **Before pushing follow-on work — check if current branch PR was squash-merged:**
   ```bash
   gh pr list --head $(git branch --show-current) --state merged --json mergeCommit --jq '.[0].mergeCommit.oid'
   ```
   If a merge commit SHA is returned, the branch was already squash-merged into main.
   **Do NOT push additional commits to this branch.** Instead:
   1. `git fetch origin main && git checkout main && git pull`
   2. `git checkout -b <new-sprint-branch>`
   3. Cherry-pick or recommit the new work onto the fresh branch
   4. Open a new PR against main
   Violating this creates a PR whose Governor analysis spans the full squash + new
   diff, inflating the analysis surface and triggering `timed_out` on large diffs.
   This is Law PT-IV in `.agent_governance/rules/pr-topology.md`.

3. **If signed commit creation fails because GPG is locked**:
   - Stop before any fallback commit attempt.
   - Prompt the operator exactly: `Run gpg-unlock, enter the passphrase in the terminal, then reply "continue".`
   - Keep the staged diff intact.
   - After the operator confirms unlock, retry the same signed commit without
     re-planning or ending the release flow.

## Abort conditions

| Condition | Action |
|-----------|--------|
| `slop_score > 0` | Abort, report violations, request remediation |
| `just audit` fails | Abort, report failing check, do not commit |
| Test strings contain detector sink keywords (Law III-E) | Rename before bouncing — abstract names only |
| New detectors in crates/forge + MCP server not restarted (Law III-F) | Restart MCP server to sync binary version with CI |
| GPG signing key locked | Prompt for `gpg-unlock`, wait for operator confirmation, then resume the same signed commit |
| Pushed PR is blocked by human review in solo mode | Restore zero required reviews, verify branch protection, arm auto-merge, and run the PR watch cadence |
| Branch protection has empty required checks | Restore expected required check contexts before arming auto-merge |
| Code-scanning alert inspection is unavailable | Require the Code Scanning Alert Audit workflow result before finalizing PR state |

## Notes

- This skill fires on every commit request without exception.
- The user may not bypass this gate by saying "skip the check" or "just commit."
- After remediation, re-run the full gate from Step 1.
