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

2. **If `slop_score == 0`**, proceed to:
   - Run `just audit` (or confirm it has already passed in this session)
   - Only then finalize the commit
   - If the finalized work is pushed to a pull request, invoke
     `.agent_governance/skills/pr-resolution/SKILL.md` and run its Post-Push
     Auto-Merge Watch at immediate, +1 minute, +5 minutes, and final +9
     minutes.

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
| GPG signing key locked | Prompt for `gpg-unlock`, wait for operator confirmation, then resume the same signed commit |
| Pushed PR is blocked by human review in solo mode | Restore zero required reviews, verify branch protection, arm auto-merge, and run the PR watch cadence |

## Notes

- This skill fires on every commit request without exception.
- The user may not bypass this gate by saying "skip the check" or "just commit."
- After remediation, re-run the full gate from Step 1.
