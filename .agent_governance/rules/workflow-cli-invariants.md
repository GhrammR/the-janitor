# Workflow CLI Invariants

## Law W-CLI-I — Verify Subcommand Existence Before Committing Workflow

Any `.github/workflows/*.yml` or `action.yml` file that invokes `janitor <subcommand>`
**must** have the subcommand verified against the live binary before the commit is made.

**Verification** (run before staging any workflow file that calls `janitor`):
```bash
# List every janitor subcommand call in the changed workflow files:
git diff --name-only HEAD | grep -E '\.github/workflows/|action\.yml' | \
  xargs grep -h 'janitor ' | grep -oP 'janitor \K[a-z][a-z-]+' | sort -u

# Verify each against the binary:
./target/release/janitor <subcommand> --help >/dev/null 2>&1 && echo "ok" || echo "MISSING"
```

**Root cause of incident (Sprint 172, issue #149):** `registry-watch.yml` called
`janitor registry-watch` — a subcommand that does not exist. The correct subcommand is
`janitor watch-registries`. The binary returned "unrecognized subcommand" (exit 1),
which the workflow incorrectly treated as "findings detected" and filed a false-positive
issue (#149). The SARIF and artifact upload steps were both skipped because no output
files were created.

## Law W-CLI-II — Findings Detection Must Be Content-Based, Not Exit-Code-Based

Workflow steps that distinguish "suspicious findings present" from "tool error" **must**
check for the presence and non-emptiness of the output file, not the exit code alone.

**Required pattern:**
```bash
janitor <subcommand> ... > "${GITHUB_WORKSPACE}/report.json" 2>"${GITHUB_WORKSPACE}/scan.log" || {
  echo "::warning::subcommand failed — not a findings signal"
  echo "findings=false" >> "$GITHUB_OUTPUT"
  exit 0
}
if [ -s "${GITHUB_WORKSPACE}/report.json" ]; then
  echo "findings=true" >> "$GITHUB_OUTPUT"
else
  echo "findings=false" >> "$GITHUB_OUTPUT"
fi
```

**Forbidden pattern** (equates any non-zero exit with findings):
```bash
# WRONG — command errors (unrecognized subcommand, network failure) create false issues
EXIT=0
janitor <subcommand> ... || EXIT=$?
if [ "${EXIT}" -ne 0 ]; then
  echo "findings=true" >> "$GITHUB_OUTPUT"
fi
```

**Why:** Binary errors (unrecognized subcommand, segfault, OOM) and network failures all
return non-zero. Only non-empty output files reliably indicate actual findings.

## Law W-CLI-III — Issue Filing Must Be Gated on Output File Existence

A "File issue on detection" workflow step **must** be conditioned on both
`steps.<id>.outputs.findings == 'true'` AND the report file being non-empty.
The `findings` output variable must only be set to `'true'` when actual report
content was produced (Law W-CLI-II above).

**Invariant** (check any workflow that files issues on janitor findings):
```bash
grep -A 3 "File issue on detection" .github/workflows/*.yml | grep "findings == 'true'"
# Must be present. findings=true must only be set when output file is non-empty.
```

## Law W-CLI-IV — Report Files Must Be Written to $GITHUB_WORKSPACE

`hashFiles()` in GitHub Actions evaluates glob patterns **relative to `$GITHUB_WORKSPACE`**.
Paths outside the workspace (e.g. `/tmp/report.json`) always return empty string — the
`hashFiles` condition evaluates false, and dependent upload/SARIF steps are silently skipped
even when findings exist.

**Required:** All report files written by CI scan steps must use workspace-relative paths:
```bash
REPORT="${GITHUB_WORKSPACE}/rw_report.json"
SARIF="${GITHUB_WORKSPACE}/rw_report.sarif"
```

And `hashFiles` / `upload-artifact` `path:` must use the bare filename (no leading `/`):
```yaml
if: always() && hashFiles('rw_report.json') != ''
# ...
path: rw_report.json   # workspace-relative, not /tmp/rw_report.json
```

**Root cause of incident (Sprint 173, issue #152):** Scan step wrote reports to `/tmp/`.
`hashFiles('/tmp/rw_report.json')` always returned `''`. Upload steps were skipped even
when genuine findings existed. Issue was filed but contained no downloadable artifact —
triage was impossible.

## Law W-CLI-V — gh API Calls Under set -euo pipefail Must Have Fallback Defaults

Any `gh` CLI call whose output is assigned to a variable under `set -euo pipefail` **must**
have a `|| echo '<default>'` fallback. `gh run list`, `gh issue list`, and `gh pr list` all
return non-zero when the target resource does not exist, is rate-limited, or the workflow
path is a GitHub-hosted dynamic path (e.g. `dynamic/github-code-scanning/codeql`).

**Required pattern:**
```bash
RUNS_JSON=$(gh run list --workflow="${WORKFLOW_PATH}" ... 2>/dev/null || echo '[]')
ISSUE_NUM=$(gh issue list --label "${LABEL}" ... 2>/dev/null || echo '')
pr_json=$(gh pr list ... 2>/dev/null || echo '[]')
```

**Forbidden pattern:**
```bash
# WRONG — gh run list exits 1 for dynamic/github-hosted workflow paths;
# set -euo pipefail traps before any null-guard can fire.
RUNS_JSON=$(gh run list --workflow="${WORKFLOW_PATH}" ...)
if [ -z "${RUNS_JSON}" ]; then exit 0; fi   # never reached on gh failure
```

**Informational-only steps must also carry `continue-on-error: true`:**
```yaml
- name: Build ranked operational issue queue
  continue-on-error: true   # failure here is never a hard signal
```

**Root cause of incident (Sprint 175, issue #174):** `health-signal.yml` step 1
called `gh run list --workflow="dynamic/github-code-scanning/codeql"` (a GitHub-hosted
path). `gh` exited 1; `set -euo pipefail` propagated before the `RUNS_JSON` null-guard.
Every `workflow_run` CodeQL success trigger caused health-signal to exit 1, which cascaded
into a false consecutive-failure count and spurious issue creation.

## Law W-CLI-VI — Governor Curl Calls Must Be Resilient to 429 Rate Limits

Any `curl` call to the Governor (`/v1/resolve-id`, `/v1/analysis-token`) under
`set -euo pipefail` **must** handle HTTP 429 without aborting the gate.

**Required pattern for optional endpoints (resolve-id):**
```bash
# Omit --fail so curl exits 0 on HTTP errors; fall back to '{}' for valid JSON.
_RESOLVE_BODY=$(curl --show-error --silent --connect-timeout 5 --max-time 30 \
    -X POST "${GOVERNOR}/v1/resolve-id" \
    -H "Content-Type: application/json" \
    -d "{\"repo_slug\":\"${REPO}\"}" 2>/dev/null || echo '{}')
RESOLVED=$(printf '%s\n' "${_RESOLVE_BODY}" | jq -r '.installation_id // 0' 2>/dev/null || echo '0')
```

**Required pattern for mandatory endpoints (analysis-token):**
```bash
ANALYSIS_TOKEN=$(curl "${GOVERNOR_CURL_OPTS[@]}" --retry 3 --retry-delay 10 -X POST \
  "${GOVERNOR}/v1/analysis-token" \
  -H "Content-Type: application/json" \
  -d "$TOKEN_PAYLOAD" | jq -er '.token')
```

**Why `--retry` works for 429:** curl (≥7.77) treats HTTP 429 as a transient error
and retries it automatically when `--retry N` is set. `--retry 3 --retry-delay 10`
gives 30 s of back-off, sufficient for burst rate-limit windows.

**Root cause of incident (Sprint 175):** Rapid `workflow_dispatch` retriggers
(8+ calls within 30 min) exhausted the Governor's per-installation rate limit.
`resolve-id` returned 429; `RESOLVED=$(curl --fail ...)` exited 22; `set -euo pipefail`
aborted before the `analysis-token` call. All subsequent retries hit the same limit.
The fix: remove `--fail` from `resolve-id` (it is best-effort; installation_id=0 is
a valid fallback), and add `--retry 3 --retry-delay 10` to `analysis-token`.

## Law W-CLI-VII — Registry Watch SARIF Triage Protocol

`registry-watch.yml` uploads SARIF findings to GitHub Security on every daily
run. Open alerts on `main` are surfaced as `CODE_SCANNING_BASELINE_OPEN` notices
by the `Code Scanning Alert Audit` workflow — they do NOT block unrelated PRs.
However, they accumulate and should be triaged periodically.

**Triage cadence:** Dismiss open alerts within 3 business days of the issue
being filed. Close the auto-generated issue after dismissal.

**Dismissal command (batch):**
```bash
for alert_number in <N1> <N2> ...; do
  gh api "repos/${REPO}/code-scanning/alerts/${alert_number}" \
    -X PATCH \
    -f state=dismissed \
    -f dismissed_reason="won't fix" \
    -f dismissed_comment="Registry-watch output: external package flagged in the wild. Not a vulnerability in this repository. Triaged $(date +%Y-%m-%d)."
done
```

**Triage decision table:**

| Pattern | Verdict | Reason |
|---------|---------|--------|
| Timestamped name or version (e.g. `pkg-27052026_140843`) | True positive | Likely malware probe; dismiss "won't fix" |
| Namespace squatting on hot brand/protocol (e.g. `mcp-*`, `openai-*`) | True positive | Supply-chain risk; dismiss "won't fix" |
| Unknown crate family with v0.x versions, no prior history | Suspicious — flag | Dismiss "won't fix" after manual crates.io check |
| Known maintained project with verifiable upstream (e.g. Google JAX packages) | False positive | Dismiss "false positive" |

**After dismissal**, close the auto-filed issue with a triage comment summarising
the package list and decision rationale.

**Root cause of incident (Sprint 176):** 11 SARIF alerts accumulated on `main`
with no documented triage procedure. The `Code Scanning Alert Audit` workflow
reported them as baseline notices on every PR inspection, creating noise.
Fix: dismiss via API + close the filed issue within 3 business days.

## Law W-CLI-VIII — Dependency Review `fetch failed` Is Expected and Non-Blocking

`dependency-review.yml` sets `continue-on-error: true` at the job level. The
`fetch failed` error it emits occurs when `dependency-review-action` cannot resolve
the PR merge-ref (`refs/pull/<N>/merge`) — GitHub's pre-computed merge commit.

**Structural fix (required in `dependency-review.yml`):**
```yaml
- name: Checkout
  uses: actions/checkout@...
  with:
    fetch-depth: 0  # shallow clone cannot resolve refs/pull/N/merge pack object
```
Without `fetch-depth: 0`, `git fetch --depth=1` cannot resolve the merge commit SHA
as a pack object and fails with `fetch failed` on every single run.

**This is NOT a blocker.** `Dependency Review` is intentionally absent from
branch-protection `required_status_checks`.  The Structural Firewall
(`janitor-pr-gate.yml`) is the sole blocking integrity check.

**Correct triage:**

| Symptom | Action |
|---------|--------|
| `fetch failed` only | Non-blocking. `continue-on-error: true` absorbs it. No action needed. |
| License violation or high-severity CVE | Blocker. Remediate before merge. |
| `fetch failed` on EVERY run after structural fix applied | Investigate GitHub Dependency Graph API availability. |

**Do not re-run** `Dependency Review` to clear the failure — `gh run rerun` on a
`continue-on-error: true` job changes nothing about merge-readiness.  Only the
Structural Firewall and Janitor Integrity Check results determine whether auto-merge
can proceed.

**Root cause of incident (Sprint 179, 2026-05-28):** Dependency Review `fetch failed`
on 6+ consecutive runs of PR #185.  Root cause: checkout used default `fetch-depth: 1`
(shallow clone).  `dependency-review-action` internally fetches `refs/pull/N/merge`;
the shallow clone cannot resolve the merge-ref pack object.  Fix: `fetch-depth: 0` in
`dependency-review.yml` checkout (structural fix, not just tolerated failure).

## Law W-CLI-IX — Registry Watch Issue Filing Must Deduplicate Against Open Triage Issues

The `File issue on detection` step in `registry-watch.yml` **must** check for an
existing open triage issue before creating a new one.  Without this gate, daily runs
unconditionally file a new issue even when all SARIF alerts from yesterday's run are
already dismissed — producing one new issue per day as long as the registry has any
churn.

**Required pattern (in `actions/github-script`):**
```javascript
const TRIAGE_TITLE = 'Registry Watch: suspicious package detected';
const existing = await github.rest.issues.listForRepo({
  owner: context.repo.owner,
  repo: context.repo.repo,
  state: 'open',
  per_page: 20,
}).catch(() => ({ data: [] }));
const alreadyOpen = existing.data.some(i => i.title === TRIAGE_TITLE);
if (alreadyOpen) {
  core.info('Open triage issue already exists — skipping duplicate creation (Law W-CLI-IX).');
  return;
}
// ... proceed with issue creation
```

**Forbidden pattern:**
```javascript
// WRONG — no deduplication check; fires unconditionally every day
github.rest.issues.create({ title: '...', body: '...' })
```

**Root cause of incident (Sprint 175, issue #184):** `registry-watch.yml` filed a new
triage issue (issue #184) the day after the previous triage issue (#177) was closed and
all 11 SARIF alerts were already dismissed.  The issue-filing step had no check for an
existing open issue, so every day with any registry churn produces a new issue regardless
of triage state.
