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

### 5. The 48-Hour Conversion Action

Emit exactly ONE concrete action for the operator's next 48 hours, in
strict priority order:

1. **If any BOUNTY_LEDGER row is `NOT_SUBMITTED` and scope is fresh**:
   `SUBMIT: <ledger row #> to <program disclosure URL>` — include the
   exact submission template (target, class, payout estimate, repro
   command, exploitation strategy).

2. **Else if a top-3 candidate has a `1-2h` proof gap with a clear
   focus-area mapping**: `VERIFY: <candidate row #> via <exact manual
   step>` — include the commands and expected output.

3. **Else if a top-3 candidate has a `4-8h` proof gap with a clear
   focus-area mapping**: `VERIFY: <candidate row #> with <env setup +
   commands>` — include the full reproduction environment.

4. **Else if dead capacity exists with high-EV potential**:
   `HUNT: <untargeted_program> with <specific oracle>` — include the
   exact `janitor hunt` command and target URL.

ONE action only. One executed action beats three deferred actions.

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

4. 48-Hour Conversion Action
   <exactly one prescription with full repro detail>

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
