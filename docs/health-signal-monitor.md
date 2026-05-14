# Systems Health Signal Monitor

Operational documentation for `.github/workflows/health-signal.yml`.

## What it does

Watches a fixed list of mission-critical workflows. When any one of them fails
for two or more consecutive completed runs, the monitor opens a single
deduplicated tracking issue tagged with a `health-signal/<workflow-slug>`
label. The issue auto-closes the next time that workflow returns a `success`
conclusion.

Without this monitor a workflow could fail silently for weeks (the 2026-Q1
CISA KEV outage went six consecutive weeks before manual triage). The signal
turns "missing email digest" into a tracked, dated, linkable artifact.

## Lifecycle of a health signal

```
   [run completes]
        │
        ▼
   conclusion = success?  ──yes──▶  open tracker exists?
        │                                  │
        │ no                               ├── yes ─▶ comment "recovered" + close
        ▼                                  └── no  ─▶ no-op
   count consecutive failures
   from most-recent run backwards
        │
        ▼
   N >= THRESHOLD (default 2)?  ──no──▶  no-op
        │
        ▼ yes
   open tracker exists?
        │
        ├── yes ─▶  comment "still failing — N runs"
        └── no  ─▶  open new tracker
```

## Tuning

### Change the threshold

Edit the `THRESHOLD` env in `.github/workflows/health-signal.yml`. Valid range
is `1`–`10`. Setting it to `1` opens an issue on every single failure (noisy
but useful for short-fuse workflows). Setting it to `3+` reduces false alarms
on flaky test suites.

```yaml
env:
  THRESHOLD: '3'   # was '2'
```

### Add or remove monitored workflows

The `on.workflow_run.workflows` array lists workflows by their **display name**
(the `name:` field at the top of each workflow file, NOT the file path).

```yaml
on:
  workflow_run:
    workflows:
      - "CISA KEV Weekly Sync"
      - "CodeQL"
      - "OpenSSF Scorecard"
      - "MSRV Sync"
      - "Janitor Self-Audit"
      - "My New Workflow"        # ← add here
```

GitHub silently drops names that don't match any workflow on the default
branch, so a typo will simply fail to fire — there is no error.

### Change the auto-close behavior

Recovery auto-closes the tracker on any `success` run. To require, e.g., two
consecutive successes before closing, replace the `MOST_RECENT_CONCLUSION` check
with a similar consecutive-success counter. (Not currently implemented because
flapping has not been a problem in practice.)

## Disabling

Two ways:

1. **Temporary** (one-off pause): comment out the `on:` block and force the
   monitor to never trigger. This preserves the file for later re-enabling.
2. **Permanent**: delete `.github/workflows/health-signal.yml`. Open trackers
   will persist as ordinary issues — close them manually if desired.

Closing all open `health-signal/*` issues without disabling the workflow is
safe — the monitor will simply re-open them on the next failure run.

## Permissions

The job runs with `issues: write` and `actions: read`. It does **not** have
write access to source. The minimum-privilege design means a compromised run
cannot push code, modify protected branches, or alter CI configuration.

## Failure modes

| Symptom | Cause | Remediation |
| --- | --- | --- |
| Issue not opened despite repeated failures | Workflow display name doesn't match the `workflows:` list (renames break the link) | Update the `on.workflow_run.workflows` array |
| Issue opened with empty title | The triggering workflow has no `name:` field | Add a `name:` to the upstream workflow |
| Multiple issues for the same workflow | Manually-edited label on a tracker breaks the dedup query | Re-apply the canonical `health-signal/<slug>` label |
| Issue never auto-closes after recovery | The recovering run was a `cancelled` or `skipped`, not `success` | Issue must be closed manually; cancellations don't count as recovery |
| Toolchain outage issue opened | Kani, Z3, or ShellCheck is missing from a durable path | Run `just toolchain-preflight`; install Z3 under `~/.local/share/janitor-tools/z3-venv`, not `/tmp` |

## Verification

Manually dispatch a known-failing workflow twice in a row to verify a tracker
is opened, then trigger a successful run to verify auto-close. The default
`workflow_dispatch` trigger on most monitored workflows makes this fast.

```bash
gh workflow run cisa-kev-sync.yml
# wait for completion, repeat to reach threshold
gh issue list --label "health-signal/cisa-kev-weekly-sync"
```
