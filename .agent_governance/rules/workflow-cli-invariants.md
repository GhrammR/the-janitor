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
