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
janitor <subcommand> ... > /tmp/report.json 2>/tmp/scan.log || {
  echo "::warning::subcommand failed — not a findings signal"
  echo "findings=false" >> "$GITHUB_OUTPUT"
  exit 0
}
if [ -s /tmp/report.json ]; then
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
