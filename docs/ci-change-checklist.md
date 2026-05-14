# CI Change Checklist

A short, mandatory checklist for any PR that modifies
`.github/workflows/*` or `action.yml`. The recurring failure mode of CI
changes is "passes review, breaks the moment it runs against `main`" — this
list eliminates the most common preventable causes.

## Pre-merge checklist

Tick each item before requesting review:

- [ ] **Structural slice is narrow.** If a PR touches governance, workflows,
  detector code, docs, and ledgers at once, split it before review. The
  Structural Firewall intentionally rejects broad diffs because high blast
  radius hides proof loss and makes check-run terminality harder to reason
  about.
- [ ] **YAML parses.** Run `python3 -c "import yaml; yaml.safe_load(open('<file>'))"` against every changed file.
- [ ] **actionlint clean.** Run `actionlint .github/workflows/*.yml` (the Workflow Lint job runs this on every PR — green = sufficient). `action.yml` is YAML-validated separately because it is a composite-action schema, not a workflow schema.
- [ ] **All `uses:` are SHA-pinned or `./`.** Major-version floats (`@v4`, `@main`) are rejected by the Workflow Lint job's SHA-pin step.
- [ ] **Dogfood path** (`uses: ./`): if you reference the action in this same workflow, sanity-check that empty `github.action_ref` is handled. The fallback exists in `action.yml` — don't break it.
- [ ] **`set -euo pipefail`** at the top of every multi-line `run:` block. Without it, a failed `gh run download --pattern` returns 0 and tanks downstream steps silently.
- [ ] **Optional asset patterns** (`gh release download --pattern "..."`): if the asset may be absent on older releases, swallow the non-zero exit and `[ -f ... ]`-guard the consumer.
- [ ] **Egress allow-list** (workflows using `step-security/harden-runner` with `egress-policy: block`): every host the engine and your `run:` blocks reach must be listed in `allowed-endpoints`. Typo → silent block → opaque failure mode.
- [ ] **Permissions are minimum-privilege.** Workflow-level: `contents: read`. Job-level: only what the job actually needs. Audit: `contents: write` requires either a published-asset use case or a justifying comment in the workflow.
- [ ] **No co-authorship trailers** in any commit message produced by the workflow. The repo policy is sole-author Riley Ghramm.
- [ ] **Manual dispatch tested** when changing workflows that already had a `workflow_dispatch:` trigger. Trigger one, observe the run, link it in the PR description.

## What the Workflow Lint job already enforces

The `.github/workflows/workflow-lint.yml` job runs on every PR that touches
workflow files:

1. **YAML syntax** — Python `yaml.safe_load`.
2. **actionlint** — full static analysis via the official 1.7.7 release.
3. **SHA-pin discipline** — rejects `@v<major>` / `@main` / `@master` /
   `@latest`.

You do **not** need to run these locally — the PR check is authoritative —
but running them locally catches issues before pushing.

## Structural Gate Slicing Protocol

Keep the structural gate strict. Tune thresholds only after a detector produces
a reproducible false positive on a narrow PR. Split instead when a change spans
two or more of these surfaces:

- GitHub workflow or action behavior.
- Governance rules or response-format law.
- Rust detector, witness, or ledger-routing code.
- Public website content or MkDocs navigation.
- Campaign ledgers or target selection state.

Evidence from the 2026-05-13 incident: broad all-at-once branches triggered
`architecture:blast_radius_violation` while staged, single-purpose slices passed
with stable Merkle roots. The standard operating method is PR slicing, not
weakening the firewall.

## Local validation script

```bash
# YAML syntax
for f in .github/workflows/*.yml action.yml; do
    python3 -c "import yaml,sys; yaml.safe_load(open('$f'))" || echo "FAIL: $f"
done

# SHA-pin scan
grep -rEn '^\s*-?\s*uses:\s*[^./].*@(v[0-9]+(\.[0-9]+)?|main|master|latest)\s*$' \
    .github/workflows/ action.yml || echo "OK: all SHA-pinned"

# actionlint (one-time install)
go install github.com/rhysd/actionlint/cmd/actionlint@v1.7.7
actionlint .github/workflows/*.yml
```

## Deliberate exceptions

- `actions/checkout@<sha>` is the canonical pin and always allowed.
- `step-security/harden-runner@<sha>` is mandatory on hardened jobs.
- A `# v<major.minor.patch>` comment **next to** the SHA is encouraged for
  human readability; the SHA is what enforces integrity.

## When a workflow is acceptable to land "broken"

Almost never. The two narrow cases:

1. **You are explicitly fixing the workflow.** Land the fix as a PR; the
   first run on `main` proves it. Add a follow-up PR if regressions appear.
2. **The workflow is being deleted.** A deletion PR removes the file; no
   future runs, no breakage to verify.

In every other case, prefer to land workflow changes in their own PR with a
linked manual-dispatch run that proves green. CI changes batched into a
feature PR have a 4× higher rate of post-merge surprises in this repo's
historical data.
