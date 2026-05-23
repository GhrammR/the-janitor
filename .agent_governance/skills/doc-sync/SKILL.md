# Skill: Documentation Integrity (Auto-Invoked)

**Trigger:** Before finalizing any commit that modifies files in the
Mapping Matrix below.

## Mapping Matrix

| Changed path pattern | Document to audit |
|----------------------|-------------------|
| `README.md` | GitHub public repository surface: repo metadata description, default-branch README, and remote branch README |
| `crates/**` | `SOVEREIGN_BRIEFING.md` |
| `justfile` | `RUNBOOK.md` |
| Any new or modified CLI flag | `RUNBOOK.md` |
| `action.yml` | `docs/setup.md` |

## Protocol

1. **Scan the staged diff** for files matching the Mapping Matrix patterns:
   - `git diff --name-only HEAD` (or the staged patch)

2. **For each triggered document**, verify that it reflects the new functional
   reality of the code change:

   | Trigger | Verification checklist |
   |---------|----------------------|
   | `README.md` changed | Was the commit pushed, does `origin/<branch>:README.md` contain the intended text, does `origin/<default_branch>:README.md` contain the public landing-page text or explicitly require merge, and does GitHub repository metadata `description` match the intended public positioning? |
   | `crates/**` changed | Does `SOVEREIGN_BRIEFING.md` reflect the new module, struct, or public API? |
   | `justfile` changed | Does `RUNBOOK.md` list the new/modified recipe with correct syntax? |
   | CLI flag added/renamed | Does `RUNBOOK.md` show the updated flag name and description? |
   | `action.yml` changed | Does `docs/setup.md` show the new input, step, or behavior? |

3. **If the document is stale** (code changed, doc not updated):
   - Report the specific gap: which document, which section, what is missing.
   - Update the document **in the same commit** as the code change.
   - Re-run the pre-commit gate after the update.

4. **If the document is current**: proceed to commit.

5. **If the change is intended to be visible on GitHub** (`README.md`,
   `docs/index.md`, repository metadata, or documentation landing pages):
   - Run the PR Resolution Gate before finalizing the sprint.
   - If the current PR is dirty, blocked by solo-review policy drift,
     app-gate failed, or structurally oversized, do not continue pushing
     documentation commits to that PR.
   - Create a docs-only replacement branch from `origin/main` and route the
     broken PR to `CLOSE_SUPERSEDED` or `REBASE_OR_RECREATE`.
   - If the PR is clean, arm auto-merge and run the PR Resolution Gate
     immediate/+1m/+5m/+9m watch cadence so README/default-branch visibility is
     not reported as complete before the PR actually merges.
   - Include code-scanning alert telemetry in the same cadence. GitHub-visible
     docs/workflow changes can create Scorecard alerts after merge; baseline
     alerts must be reported, and net-new PR alerts must block completion.

## Abort conditions

| Condition | Action |
|-----------|--------|
| Mapping Matrix triggered, document not updated | Block commit, report gap, update document |
| Document updated but factually incorrect | Block commit, correct the content |

## Scope

This skill audits for **functional accuracy** — command names, flag names,
API shapes, and module names.  It does not enforce prose style or completeness
of prose explanations.

## Notes

- `SOVEREIGN_BRIEFING.md` is the sole technical architecture specification.
  No other architecture document should exist at the root.
- `RUNBOOK.md` is the sole command manual.
  No other operations manual should exist at the root.
- If a new crate or tool is added, a corresponding section in
  `SOVEREIGN_BRIEFING.md` is mandatory before the commit is finalized.
