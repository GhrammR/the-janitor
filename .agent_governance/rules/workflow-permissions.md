# Workflow Permissions — Least Privilege

## Law W-I — Top-Level `permissions: read-all`; Write Scopes at Job Level Only

Every `.github/workflows/*.yml` file MUST set the top-level block to `read-all`
(or `contents: read`) and declare any required write permissions at the **job**
level where they are consumed.  Write permissions at the top level are inherited
by every job including any future jobs added by human error, expanding blast radius
on token compromise.

```yaml
# CORRECT
permissions: read-all
jobs:
  publish:
    permissions:
      contents: write    # only this job needs it
      packages: write
    steps: ...

# WRONG — write permissions bleed into all jobs
permissions:
  contents: write
  security-events: write
```

**Verification** (run before opening any PR that touches `.github/`):
```bash
for f in .github/workflows/*.yml; do
  python3 - "$f" <<'PY'
import sys, yaml
doc = yaml.safe_load(open(sys.argv[1]))
top = doc.get('permissions', {})
if isinstance(top, dict):
    bad = [k for k, v in top.items() if v == 'write']
    if bad:
        print(f"FAIL {sys.argv[1]}: top-level write permissions: {bad}")
    else:
        print(f"ok   {sys.argv[1]}")
else:
    print(f"ok   {sys.argv[1]} (string shorthand: {top})")
PY
done
# All lines must start with "ok"
```

**Root cause (Alert #65, 2026-05-24):** `registry-watch.yml` declared
`security-events: write` at the top level (line 9). Scorecard flagged it as
High severity. Fixed by adding `permissions: read-all` at top level and moving
`contents: read`, `issues: write`, `security-events: write` to the job block.

## Law W-II — Scan Report Files Must Be Written to $GITHUB_WORKSPACE and Uploaded as Artifacts

Runner storage outside `$GITHUB_WORKSPACE` (e.g. `/tmp/`) is ephemeral and
invisible to `hashFiles()`. Any report written there will cause upload-artifact
and upload-sarif steps to silently skip — even when findings exist — because
`hashFiles('/tmp/report.json')` always returns `''`.

**Required pattern** (see also Law W-CLI-IV):
```yaml
- name: Run scan
  run: |
    REPORT="${GITHUB_WORKSPACE}/report.json"
    janitor <subcommand> > "${REPORT}" ...

- name: Upload report artifact
  if: always() && hashFiles('report.json') != ''
  uses: actions/upload-artifact@... # pinned SHA
  with:
    name: report-${{ github.run_id }}
    path: report.json          # bare filename — workspace-relative
    retention-days: 30
```

Issue bodies must reference the artifact by run ID, not by any filesystem path.

**Root cause (Issue #152, 2026-05-25):** Report written to `/tmp/rw_report.json`.
`hashFiles('/tmp/rw_report.json')` always returned `''`; upload steps were skipped
even when genuine findings existed. Issue filed with no downloadable artifact —
triage was impossible. Fixed by moving reports to `$GITHUB_WORKSPACE` (PR #153).

## Law W-III — Issue Filing Must Trigger on Detected Findings, Not Step Failure

`if: failure()` fires when any prior step fails — including unrelated infra
failures (artifact upload 404, SARIF schema error, etc.).  This causes spurious
issues.

**Required pattern**: use a named step output to signal real findings.

```yaml
- name: Run scan
  id: scan
  run: |
    janitor <subcommand> ... > "${GITHUB_WORKSPACE}/report.json" || {
      echo "findings=false" >> "$GITHUB_OUTPUT"
      exit 0
    }
    if [ -s "${GITHUB_WORKSPACE}/report.json" ]; then
      echo "findings=true" >> "$GITHUB_OUTPUT"
    else
      echo "findings=false" >> "$GITHUB_OUTPUT"
    fi

- name: File issue on detection
  if: steps.scan.outputs.findings == 'true'
  ...
```

**Root cause (Issue #141, 2026-05-24):** `upload-sarif` failed (no `.sarif`
file) which triggered `if: failure()`, filing a spurious issue with no real
detection. Fixed by gating on a named step output.

## Law W-IV — Branch Protection Required Checks Must Match Actual Workflow Job Names

Required status checks in branch protection must be verified against the actual
job `name:` fields in `.github/workflows/*.yml` after any workflow matrix change.
Stale entries (jobs that no longer exist or languages no longer analyzed) block
every PR silently — the check is required but can never be satisfied.

**Verification** (run after any CodeQL, MSRV, or CI matrix change):
```bash
# Extract all job names from workflows
grep -h '^    name:' .github/workflows/*.yml | sed 's/.*name: *//' | sort -u

# Compare against branch protection required checks
gh api repos/{owner}/{repo}/branches/main/protection \
  --jq '.required_status_checks.contexts[]' | sort
```

Every entry in the branch protection list must have a matching `name:` in an
active workflow job. Any entry with no match must be removed.

**Required action** after removing a workflow job or language from a matrix:
```bash
gh api --method PATCH repos/{owner}/{repo}/branches/main/protection/required_status_checks \
  --field 'contexts[]=<only-the-checks-that-still-exist>'
```

**Root cause (Sprint 173, 2026-05-25):** CodeQL matrix was reduced from
`['rust', 'actions', 'javascript-typescript', 'python']` to `['rust', 'actions']`
but `Analyze (javascript-typescript)` and `Analyze (python)` remained as required
checks. All dependabot PRs were blocked — the checks could never pass because the
jobs that would produce them no longer existed.

## Law W-V — `gh run rerun` Replays the Original Workflow; It Does Not Pick Up Changes Merged to main

`gh run rerun <id> --failed` re-executes the failed steps using the **workflow
definition from the original run's commit SHA**, not from the current `main`.
A workflow fix merged to `main` will NOT be used by a rerun of an old failed run.

**Required recovery pattern** when a workflow bug is fixed and merged:

For `pull_request`-triggered workflows:
```bash
# The workflow file is resolved from the BASE branch (main) for same-repo PRs.
# Trigger a new pull_request event by commenting via Dependabot:
gh pr comment <number> --body "@dependabot recreate"
# OR close and reopen IF the triggering actor matches the workflow's `if:` condition.
```

**Anti-pattern** (does not pick up the fix):
```bash
gh run rerun <old-run-id> --failed   # WRONG — uses original workflow SHA
```

**Root cause (Sprint 173, 2026-05-25):** `dependabot-automerge.yml` was missing
`contents: write`. After PR #163 fixed it and merged to `main`, manual reruns of
the old failed runs still used the old (broken) workflow definition. The fix only
took effect when new `pull_request` events were generated.

**Corollary — close/reopen by a human breaks `dependabot[bot]` actor guards:**
`dependabot-automerge.yml` has `if: github.actor == 'dependabot[bot]'`. When a
human closes and reopens a dependabot PR, `github.actor` is the human's login,
the job is SKIPPED, and auto-merge is never armed. Use `@dependabot recreate`
to get a Dependabot-actor event instead.
