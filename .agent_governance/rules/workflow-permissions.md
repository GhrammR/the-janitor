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

## Law W-II — Registry Watch Reports Must Persist as Artifacts

`janitor registry-watch` writes findings to `/tmp/rw_report.json` on the runner.
Runner `/tmp` is ephemeral — the file is gone when the job ends. Issue bodies
that reference `/tmp/rw_report.json` are unresolvable.

**Required pattern**: upload the report as a workflow artifact in the same job,
before filing any issue.

```yaml
- name: Upload report artifact
  if: always() && hashFiles('/tmp/rw_report.json') != ''
  uses: actions/upload-artifact@... # pinned SHA
  with:
    name: rw-report-${{ github.run_id }}
    path: /tmp/rw_report.json
    retention-days: 30
```

Issue bodies must reference the artifact by run ID, not by `/tmp` path.

**Root cause (Issue #141, 2026-05-24):** Issue was filed with body
"Review /tmp/rw_report.json." — a path that does not survive job completion.
Fixed by adding the artifact upload step and rewriting the issue template.

## Law W-III — Issue Filing Must Trigger on Detected Findings, Not Step Failure

`if: failure()` fires when any prior step fails — including unrelated infra
failures (artifact upload 404, SARIF schema error, etc.).  This causes spurious
issues.

**Required pattern**: use a named step output to signal real findings.

```yaml
- name: Run registry watch scan
  id: scan
  run: |
    EXIT=0
    janitor registry-watch ... || EXIT=$?
    echo "findings=$( [ "${EXIT}" -ne 0 ] && echo true || echo false )" >> "$GITHUB_OUTPUT"

- name: File issue on detection
  if: steps.scan.outputs.findings == 'true'
  ...
```

**Root cause (Issue #141, 2026-05-24):** `upload-sarif` failed (no `.sarif`
file) which triggered `if: failure()`, filing a spurious issue with no real
detection. Fixed by gating on a named step output.
