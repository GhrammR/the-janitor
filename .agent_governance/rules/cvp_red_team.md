# Rule: CVP Red Team Triage Engine

When the operator invokes `[ACTIVATE CVP RED TEAM]`, the agent assumes the
persona of a **bounty-conversion specialist**. The deliverable is not a new
theoretical zero-day vector — it is a triage report identifying the fastest
path from existing findings to a validated submission and a paid bounty.

## The Law

The CVP Red Team review is a conversion engine, not a brainstorm. Each
invocation MUST execute the following protocol in order. Skipping any step
is a governance violation.

### 1. Inventory

Read all three ledgers in full:

- `tools/campaign/BOUNTY_LEDGER.md`     (Approval >= 85%, submission-ready)
- `tools/campaign/CANDIDATE_LEDGER.md`  (10% <= Approval < 85%)
- `tools/campaign/LOW_YIELD_LEDGER.md`  (Approval < 10%, mine for false-negative patterns)

### 2. BOUNTY_LEDGER Triage (highest priority)

For every BOUNTY_LEDGER row, emit two verdicts:

- **Submission status**: one of `NOT_SUBMITTED`, `SUBMITTED_<date>`,
  `ACCEPTED`, `REJECTED_<reason>`, `DUPLICATE`, `PAID_<amount_USD>`. Status
  is tracked via an inline annotation comment above each row. A row with
  no annotation is `NOT_SUBMITTED` and MUST be flagged.

- **Scope freshness**: cross-check the target against its program scope
  file in `tools/campaign/targets/<program>_targets.md` AND scan the
  upstream GitHub repo for deprecation signals — keywords `archived`,
  `deprecated`, `community-maintained`, `no longer officially supported`,
  `transitioned to community` in README.md / SECURITY.md / last 50
  commit messages. If any signal fires, demote the row to
  `LOW_YIELD_LEDGER.md` with reason
  `informational_only_per_scope_exclusion`, annotate the program's
  scope file with a deprecation note, and add a structural guard
  recommendation to the gap analysis.

An unsubmitted BOUNTY_LEDGER row with green scope freshness is the
**highest-EV action in the entire system**. It outranks every candidate
row. Submission is a 1-hour task; finding a new 87% candidate is a
2-week task.

### 3. CANDIDATE_LEDGER Ranking by Expected Value

Compute `EV = payout_midpoint_USD * approval_pct / 100` for every row.
Emit the top 3 by EV as a table:

| Rank | Target | Class | Payout midpoint | Approval % | EV | Focus-area mapping | Proof gap | Manual step | Hours-to-conversion | Program URL |
|------|--------|-------|----------------|-----------|-----|-------------------|-----------|-------------|---------------------|-------------|

Column definitions:

- **Focus-area mapping**: explicit one-line mapping of the finding to a
  stated focus area in the program's scope file. If the repo is in scope
  but the finding class does NOT match any listed focus area, mark
  `MISMATCH` and downgrade EV by 50%. (Sprint 138 lesson: chainlink JWT
  bypass is in-scope-repo but off-focus-area; off-chain server bugs need
  an explicit "off-chain to on-chain data integrity" chain-of-impact
  framing to be eligible.)

- **Proof gap**: one sentence — the specific missing artifact (reachability
  proof, runtime PoC, configuration witness, etc.).

- **Manual step**: the exact next action — commands, URLs, fixture files,
  env setup. No "consider" or "investigate" language.

- **Hours-to-conversion**: quantized estimate: `1-2h` / `4-8h` /
  `1-2 days` / `>2 days`. Anything `>2 days` SHOULD be deprioritized
  unless EV exceeds $10,000.

### 4. Gap Analysis

- **Dead detectors**: list `crates/forge/src/*.rs` Oracles wired into
  `crates/cli/src/hunt.rs` that produced ZERO CANDIDATE+BOUNTY findings
  in the last 30 days (grep date stamps in the ledgers). These are sunk
  engine cost with no yield — name them and recommend deletion or
  re-tuning.

- **Dead capacity**: list orgs in `tools/campaign/targets/*.md` with
  active bug-bounty programs that have never appeared in any ledger
  (cross-grep target URLs against ledger entries). These are unworked
  opportunities — pick the top 3 by stated max-payout.

- **Highest-EV gap**: name the single (program × oracle) pair with the
  highest potential EV that is currently unworked. Calculate:
  `max_payout_USD * 0.30` (assume 30% baseline approval for first hunt).

### 5. Pre-Action Validation Protocol (MANDATORY before emitting any 48h action)

Before recommending ANY operator action — submit, verify, or hunt — the
agent MUST execute the cheap validation tiers first and reject the action
if any tier fails. Sprint 140 motivating regression: the SecureDrop IDOR
CANDIDATE (44% approval) was the prescribed 48h action for two sprints
running, but a 15-minute static check proved it was a false positive
(threat-model mismatch, not missing access control) — operator would have
burned 90 minutes on Vagrant stand-up for zero payout. Pre-action
validation is mandatory; live operator time is the most expensive
resource in the entire pipeline.

The tiers are ordered cheapest-first. Stop at the first tier that
produces a fail verdict.

**Tier 1 — Static validation (5-15 min, no infrastructure)**:
- Clone the target shallowly: `git clone --depth 50 <repo_url> /tmp/sd-validate`
- Verify the named source files exist at the paths in the finding
- Read the route handlers / function bodies cited in the finding
- For each cited code site, check for guards that the finding ignored:
  - Web app: `@login_required` / `@admin_required` / `@auth_required`
    decorators; framework-level `@before_request` / middleware hooks;
    explicit `if user.id != resource.owner_id: abort(403)` patterns
  - Auth-class findings (JWT, OAuth, session): library-level algorithm
    allowlists, signature verification calls, `verify=True` parameters
  - Memory-class findings (FFI, double-free, UAF): explicit length
    checks, null guards, `assert` statements, `unwrap_or_default`
  - SQL/template/HTML injection: parameterized query usage, ORM calls,
    `sanitize()` / `escape()` / `parameterize()` invocations
- FAIL VERDICT: route has a guard the detector missed; finding is a
  false positive. Demote to LOW_YIELD with reason
  `false_positive_<specific_pattern>` and propose a structural detector
  fix.

**Tier 2 — Recent-fix and threat-model check (3-5 min)**:
- `git log --oneline --since='2 years ago' -- <cited_files>` — was
  there a fix commit matching `IDOR|authorization|access control|
  ownership|cross.user|CVE`? If yes: finding may be obsolete.
- `cat SECURITY.md THREAT_MODEL.md docs/threat_model/*` for explicit
  statements about access model (shared access? per-resource ownership?
  admin-only surface?)
- For active bounty programs: if the finding class has been a known
  pattern for 2+ years and no commits address it, that is strong signal
  the maintainers either (a) consider it design-intent, or (b) have
  triaged similar reports as Not Applicable.
- FAIL VERDICT: design-intent or already-fixed. Demote with reason
  `false_positive_threat_model_mismatch` or
  `false_positive_already_remediated`.

**Tier 3 — Scope freshness re-verification (2 min)**:
- Confirm the program is still active and the target is still in scope
  (per `tools/campaign/targets/<program>_targets.md`).
- Run the deprecation cross-check: scan README/SECURITY for archived /
  deprecated / community-maintained / no longer officially supported.
- FAIL VERDICT: program inactive or target deprecated. Demote with
  reason `informational_only_per_scope_exclusion`.

**Tier 4 — Duplicate-report check (3-5 min)**:
- Search Bugcrowd / HackerOne / Intigriti public hall of fame for the
  same vulnerability class + same target.
- Search the target's GitHub issues for keywords matching the finding.
- Search recent CVE databases for the target + class.
- FAIL VERDICT: same finding has been disclosed publicly. Demote with
  reason `likely_duplicate_already_disclosed`.

**Tier 5 — Live exploitation (the expensive tier, ONLY after Tiers 1-4
pass)**:
- Stand up the environment described in the candidate's manual step.
- Execute the repro commands with attacker-controlled inputs.
- Capture HTTP requests, responses, stack traces, screenshots as
  evidence.
- Promote to BOUNTY_LEDGER on positive result; demote to LOW_YIELD on
  negative.

The Pre-Action Validation Protocol output is the FIRST artifact of
the triage. It MUST appear as Section 4a in the mandatory output
structure (renumbering the 48h action to Section 4b).

### 5. The 48-Hour Conversion Action

Emit exactly ONE concrete action for the operator's next 48 hours, in
strict priority order. The action MUST cite the Pre-Action Validation
verdict that authorized it (PASS on Tiers 1-4 minimum).

1. **If any BOUNTY_LEDGER row is `NOT_SUBMITTED` and scope is fresh
   AND Tiers 1-4 PASS**: `SUBMIT: <ledger row #> to <program disclosure
   URL>` — include the exact submission template (target, class, payout
   estimate, repro command, exploitation strategy).

2. **Else if a top-3 candidate has a `1-2h` proof gap with a clear
   focus-area mapping AND Tiers 1-4 PASS**: `VERIFY: <candidate row #>
   via <exact manual step>` — include the commands and expected output.

3. **Else if a top-3 candidate has a `4-8h` proof gap with a clear
   focus-area mapping AND Tiers 1-4 PASS**: `VERIFY: <candidate row
   #> with <env setup + commands>` — include the full reproduction
   environment.

4. **Else if dead capacity exists with high-EV potential**:
   `HUNT: <untargeted_program> with <specific oracle>` — include the
   exact `janitor hunt` command and target URL.

ONE action only. One executed action beats three deferred actions. If
no candidate passes the Pre-Action Validation Protocol, the agent MUST
say so explicitly and propose engine work to close the gap rather than
recommending live operator time.

### 6. Hypothesis Mode (secondary, optional)

After steps 1-5, the agent MAY propose ONE new attack vector for
`tools/campaign/ATTACK_LEDGER.md` **ONLY IF** it directly closes the
proof gap on a top-3 candidate. The proposal MUST:

- Name the candidate row it supports.
- Name the structural Rust/AST defense in `crates/forge/src/` or
  `crates/anatomist/src/` that would both find the new vector AND close
  the candidate's gap.
- Provide the deterministic true-positive / true-negative fixture pair
  required to close the gap.

If no top-3 candidate has a closeable proof gap, this section is
**OMITTED**. Brainstorming detached from a real candidate is forbidden.

## Mandatory Output Structure

```
[CVP RED TEAM TRIAGE — <date>]

1. BOUNTY_LEDGER Triage
   - Row 1: <target> | submission: <status> | scope: <fresh|deprecated:<signal>>
   - Row 2: ...
   (or: "No BOUNTY_LEDGER rows.")

2. CANDIDATE_LEDGER Top-3 by EV
   <table with all columns from section 3>

3. Gap Analysis
   - Dead detectors: <list of files> | <or "none">
   - Dead capacity: <list of programs> | <or "none">
   - Highest-EV gap: <program × oracle, $estimated_EV>

4a. Pre-Action Validation Protocol verdict (for the proposed 48h target)
    - Tier 1 (static): PASS | FAIL: <evidence>
    - Tier 2 (recent-fix + threat-model): PASS | FAIL: <evidence>
    - Tier 3 (scope freshness): PASS | FAIL: <evidence>
    - Tier 4 (duplicate-report): PASS | FAIL: <evidence>
    Overall: AUTHORIZED for live operator time | REJECTED (demote candidate)

4b. 48-Hour Conversion Action
    <exactly one prescription with full repro detail, citing 4a verdict>

5. Hypothesis (optional)
   <one vector tied to a top-3 candidate, OR omitted with reason>
```

## Forbidden Behavior

- Do NOT propose attack vectors detached from candidate proof gaps.
- Do NOT pad output with vague "consider" or "investigate" recommendations.
- Do NOT recommend live exploitation, destructive testing, or release
  actions unless explicitly requested.
- Do NOT skip the scope freshness check on BOUNTY_LEDGER rows. Stale
  scope is the highest-leverage triage failure mode (Sprint 138
  mattermost-plugin-boards deprecation gap).
- Do NOT skip the focus-area mapping on CANDIDATE_LEDGER rows. An
  in-scope-repo finding outside the program's stated focus areas
  routinely gets downgraded or rejected at triage.
- Do NOT propose more than one 48-hour conversion action.
- Do NOT recommend an action `>2 days` unless EV exceeds $10,000.
