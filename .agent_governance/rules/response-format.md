# Rule: Mandatory Response Format

Every final response to an operator directive MUST follow the strict four-part
summary plus terminal-only translation structure below. No other top-level
structure is acceptable.

## The Law

During active execution (reading files, compiling, fixing bugs, waiting on
tests, or patching), agents MAY use natural, concise status updates such as
`Running tests...`, `Failed on line 12. Patching...`, or `Release push in
progress.`  These interim updates must stay brief and operational.

Long-running command discipline is mandatory. After starting a known long
command (`just audit`, `cargo test --workspace`, `/release`, `/strike`, or any
build/test expected to exceed 60 seconds):

1. **Run commands sequentially, not in parallel.** Never launch multiple
   `cargo`/`just`/`rustc` processes simultaneously. Build lock contention
   multiplies wall-clock time and wastes tokens on error recovery.
2. **Poll at most once every 5 minutes (300 seconds).** A single status read
   per 5-minute window is the hard ceiling. Emit one concise update and stop.
3. **Prefer foreground blocking calls.** Run long commands as a single
   foreground `Bash` call with `timeout: 600000`. The tool blocks until done
   and returns the full result — no polling required at all.
4. **Trust the task-notification system.** If a command is started with
   `run_in_background: true`, do NOT poll the output file. Wait silently for
   the `<task-notification>` system message.

Constant polling is token waste and is a governance violation. The operator
has explicitly reinforced this rule: check at most once per 5 minutes,
run sequentially, and trust the notification system.

The four-part structure below is reserved strictly for the **final summary**
after the directive is complete and any requested `/release` has been triggered.
Do **not** use it for intermediate execution updates.

You are mathematically forbidden from emitting raw tool-call artifacts (e.g.,
`::git-stage`, `::git-commit`, `<function_calls>`) in the final terminal
output. Translate all tool results into human-readable telemetry.

All final substantive summaries (implementation, release, audit, research) must
be organized into the following named sections, in order:

```
[EXECUTION STATUS]
Pass / Fail summary of the directive. One sentence per task. Mark each
sub-task with ✓ (completed), ✗ (failed), or ⏳ (pending / in-progress).

[CHANGES STAGED]
Table of all files modified, created, staged, or committed in this session.

| File | Action | Description |
|------|--------|-------------|
| path/to/file | modified | brief description |

If no code was staged or committed (research-only session), state "No code
staged."

If the directive involved a GitHub pull request, this section must classify the
PR using `.agent_governance/rules/pr-resolution.md`: `MERGE`,
`ENABLE_AUTO_MERGE_AFTER_REVIEW`, `WAIT_FOR_CHECKS`, `REBASE_OR_RECREATE`,
`CLOSE_SUPERSEDED`, or `LEAVE_OPEN`. A PR with `mergeStateStatus=DIRTY`,
`reviewDecision=REVIEW_REQUIRED`, or failed/timed-out app-owned gates must not
be described as mergeable.

[TELEMETRY]
Direct-triage backlog changes logged this session. Format:
- P0/P1/P2 item created, compacted, or completed with one-line rationale
If none: <!-- no triage changes this session -->

[NEXT RECOMMENDED ACTION]
Emit exactly ONE fully formatted, copy-pasteable `Sovereign Directive` prompt
for the operator to feed back into the agent for the next sprint.

The generated prompt MUST be wrapped in quadruple backticks using the exact
outer fence form below so nested markdown inside the prompt cannot terminate
the fence early:

````text
agent "You are executing a Sovereign Directive: ..."
````

The generated `[NEXT RECOMMENDED ACTION]` prompt MUST strictly use
`### Phase X:` headers to delineate the implementation steps, making the prompt
directly trackable for the operator.

**Anti-Context-Drift Mandate**: The first line of every generated Sovereign
Directive prompt MUST be:

```
Governing Law: Before outputting your final response, read
.agent_governance/rules/response-format.md and produce the mandatory
[EXECUTION STATUS] / [CHANGES STAGED] / [TELEMETRY] / [NEXT RECOMMENDED
ACTION] / [SOVEREIGN TRANSLATION] / [OPERATOR INTELLIGENCE] /
[SHOWCASE ATTESTATION] structure. This is non-negotiable.
```

This line must appear verbatim inside the quadruple-backtick fence so the
receiving agent cannot skip the format even after context compaction.

The prompt MUST:
1. Begin with `agent "You are executing a Sovereign Directive:` and end with a
   closing `"`.
2. Name the next two highest-TAM items from `.INNOVATION_LOG.md`, with Item 1
   as the absolute highest commercial-priority frontier (highest
   TAM × severity × addressable language market share) and Item 2 as an
   orthogonal or synergistic follow-on that fits the same sprint.
3. State, inside the prompt, the exact file to modify, function to change, and
   command to begin for each selected item.
4. Command the next sprint to run `janitor hunt` against the next 3
   `tools/campaign/target_ledger.json` targets, with all three selected from
   distinct organizations or projects rather than three variants of the same
   repository family.
5. Reassert all existing UAP laws by name: Eradication, Structural Guard,
   Triage Empathy, and Tri-Ledger.
6. Include one strategic operator tip that maximizes revenue / impact.
7. **Mirror all actionable `[OPERATOR INTELLIGENCE]` tips as explicit phases.**
   Every tip from the current session's `[OPERATOR INTELLIGENCE]` section that
   describes a concrete, implementable fix MUST appear as a numbered `### Phase X:`
   block inside the sovereign directive prompt — verbatim enough for the next agent
   to execute without re-reading the operator section. Apply this rule to:
   - **Entropy Modulator Tip**: if it names a specific file, function, or struct to
     change, include it as a phase with the exact edit described.
   - **Systems Health Signal**: if it names a remediation step (not just an
     observation), include it as a phase with the exact file and change.
   - **Platform Expansion Tip**: always include as a phase. It invariably names an
     exact command, workflow file, or API operation — surface it directly so the
     next agent executes it rather than re-deriving it.
   Tips that are purely observational (e.g., "no anomaly detected", queue-state
   reports, blocked ARTICLE_REVIEW entries) are exempt — only tips with a concrete
   next-step action become phases.
8. **Inline Skill Quotation Rule (Sprint 140)**. Every `### Phase X:` block in
   the Sovereign Directive prompt that depends on a rule, skill, protocol, or
   detector module MUST quote the relevant text INLINE inside the
   quadruple-backtick fence, not just reference the source file by path. The
   next agent receives the prompt at a context reset — any
   `.agent_governance/rules/*.md` or `.agent_governance/skills/*.md` file the
   prompt expects to be re-read may be unavailable, compacted away, or modified
   between sprints. A phase that says "apply the Pre-Action Validation Protocol
   from cvp_red_team.md" is governance-invalid; the phase must reproduce the
   full 5-tier protocol text inside the prompt, so the receiving agent can
   execute Tier 1 without opening a file.

   The exception: `response-format.md` itself is referenced (not inlined) on
   the Governing Law line because the mandatory output structure it defines is
   the format the receiving agent uses to compose its OWN response — it is
   universal scaffolding, not phase-specific instruction.

   Rules over 50 lines MAY be summarized to their decision-relevant content
   when inlined, but the summary must be complete enough to execute without
   source access. When in doubt, prefer the longer prompt over the brittle one.

9. Include one **Architectural Oracle Tip** derived from a dynamic `rg` scan of
   legacy infrastructure such as `crates/cli/src/daemon.rs`,
   `crates/common/src/physarum.rs`, and `action.yml`. The tip must scan across
   ALL of the following drift categories and report the highest-priority find:
   - **Legacy code drift**: outdated API calls, deprecated trait bounds,
     `String::clone()` hot-path clones, `#[allow(dead_code)]` suppressors,
     unused `mod` declarations, unreachable arms.
   - **Governance Bloat**: stale `.cargo/config.toml` sections, orphaned
     justfile targets with no callers, outdated MSRV pins in `rust-toolchain.toml`.
   - **Dead workflow files**: `.github/workflows/` actions pinned to EOL
     versions (`@v1`, `@v2`) or workflows whose `on:` triggers reference
     deleted branches.
   - **Dead Rust modules**: `pub mod` declarations in `lib.rs` with no external
     callers (verify with `rg 'use forge::<module>'`).
   The tip must name the exact file and line of the drift pocket and provide the
   precise `rm <file>`, `sed -i 's/old/new/' <file>`, or one-line code-deletion
   command that eliminates it — not a vague "consider" suggestion.
10. If the prompt includes any phase for an existing PR, it MUST quote the live
   blocker from `gh pr view` / `gh pr checks` and use the PR Resolution Gate
   action class. Dirty, self-review-blocked, or app-gate-failed PRs must be
   superseded or split first; the prompt must not keep appending unrelated work
   to the same broken branch.

**Architectural Oracle Execution Law**: If the Architectural Oracle Tip
identifies a legacy drift or optimization that requires fewer than 50 lines of
code to fix, the agent receiving that tip MUST implement the fix in the CURRENT
sprint. Trivial optimizations (e.g., eliminating a `String::clone()`, pinning a
deprecated action version, collapsing a redundant loop) MUST NOT be deferred to
a future sprint.

**Mirroring Pre-Emission Checklist** (run BEFORE sealing the NRA prompt):

Before writing the closing `"` of the sovereign directive, explicitly verify
each of the following. A missing mirror is a governance violation — add the
phase rather than emit and rationalize the omission.

1. **Systems Health Signal mirror**: Did the `[OPERATOR INTELLIGENCE]` Systems
   Health Signal name a remediation step (not a pure observation)? If yes, is
   there a `### Phase N:` block in the prompt with the exact file and change?
   If no phase exists, ADD IT before sealing.
2. **Platform Expansion Tip mirror**: The Platform Expansion Tip ALWAYS names
   a concrete next-step command or workflow file. Is there a `### Phase N:`
   block in the prompt that reproduces that command verbatim? If no phase
   exists, ADD IT before sealing.
3. **Entropy Modulator mirror**: Did the Entropy Modulator Tip name a specific
   file, function, or struct to change? If yes, is there a `### Phase N:` block
   with the exact edit? If no phase exists, ADD IT before sealing.
4. **Already-shipped exemption**: A fix applied DURING THE CURRENT SESSION is
   exempt from mirroring — the next sprint need not repeat completed work.
   Verify the tip's described fix has not already been applied before claiming
   the exemption. Applying a fix in-session and then omitting it from the NRA
   is CORRECT behavior. Omitting a fix that was NOT applied and was NOT
   included in the NRA is a governance violation.

5. **Inline Skill Quotation verification (Sprint 140)**: For every
   `### Phase X:` block in the prompt, identify any rule, skill, protocol, or
   detector module the phase invokes. Verify the FULL text (or a complete
   decision-relevant summary for >50-line rules) is reproduced inside the
   quadruple-backtick fence. A phase whose execution requires the next agent
   to open a file in `.agent_governance/` or read source code in `crates/`
   (other than to apply edits described in the phase itself) is governance-
   invalid. Add the inline text before sealing. The lone exception is the
   Governing Law boilerplate referencing `response-format.md` itself.

The section must be operator-ready text, not analysis about the text. Do not
emit vague "consider" language. Do not suggest manual git commands, staging,
signing, `/compact`, or other workflow rituals outside the quoted Sovereign
Directive prompt.

**Pre-flight — Absolute Eradication Law**: before writing this section,
verify `.INNOVATION_LOG.md` contains ZERO completion markers
(`[COMPLETED]`, `[COMPLETE]`, `[RESOLVED]`, `[DONE]`, `[SHIPPED]`,
`[FIXED]`, `[LANDED]`, or `~~strikethrough~~`). If any remain from the
current session's shipped work, physically delete those blocks first,
then re-read the log to select the true highest-value frontier. See
`.agent_governance/rules/log_hygiene.md`. By construction, every entry
still in the log is unbuilt — the NRA selects from open frontiers only.

[SOVEREIGN TRANSLATION]
A terminal-only operator brief. Never write this section into markdown logs or
backlog files. It must explain the implementation in layman's executive terms
and explicitly answer:
1. What did we just build?
2. Why does the CISO care?
3. How does this make money or crush competitors?

[OPERATOR INTELLIGENCE]
A human-directed operator brief. It must contain one **Entropy Modulator Tip**
derived from the last 3 sprint entries in `docs/CHANGELOG.md`, one **Systems
Health Signal** covering holistic operational awareness beyond pure revenue, one
**ARTICLE_REVIEW Summary**, AND one **Platform Expansion Tip** covering the next
best GitHub capability upgrade.

**Mirroring contract**: every tip in this section that names a concrete,
implementable fix MUST also appear as an explicit `### Phase X:` block inside
the `[NEXT RECOMMENDED ACTION]` sovereign directive prompt. Write each tip here
for the operator's situational awareness AND write it there for the next agent's
execution. The two representations must be consistent: the operator section
explains the why; the NRA phase provides the exact file, function, and command.

Entropy Modulator protocol:
1. Inspect the last 3 completed sprints in `docs/CHANGELOG.md`.
2. Classify whether those sprints concentrated on Web/AI surfaces or on
   Systems/CLI/Build infrastructure.
3. Deliberately pivot the tip to the opposite surface area.
4. Name one specific refactor, token-optimization, or procedural bottleneck the
   human operator should address next.
5. Keep it concise, direct, and addressed to the human, not the next agent.

Systems Health Signal protocol:
1. Report on one of the following if any signal is present; otherwise state "No
   active health anomaly detected":
   - **CI/CD anomaly**: persistent workflow failures, flaky test patterns, or
     a workflow that has not run successfully in the last 5 commits.
   - **Operational knowledge gap**: a critical crate with zero doc comments on
     its public API, or a justfile target with no description comment.
   - **Active Deception posture**: whether `.janitor/audit_reports/` or
     `.janitor/hunt_reports/` contain adversarial decoy seeds that could be
     used to fingerprint attacker reconnaissance tools.
   - **Hardware constraint alert**: any new P-tier item in `.INNOVATION_LOG.md`
     that violates the 8GB Law (JVM, Ghidra, fat LTO, local LLM inference)
   and must be flagged before the operator queues it.

ARTICLE_REVIEW Summary protocol:
1. State how many URLs were processed from `ARTICLE_REVIEW.md` this session and
   how many remain queued.
2. Name each processed disposition bucket used this session:
   `already_defended`, `mapped_innovation_item`, `new_innovation_item`, or
   `attack_ledger_update`.
3. Include the highest-confidence integration action and the weakest source
   quality score observed.
4. If ARTICLE_REVIEW was requested but blocked, state the exact blocker and the
   preserved queue state.

Platform Expansion Tip protocol:
1. Tie the tip to one measurable GitHub capability upgrade: Integrity check
   quality, PR gate hardening, marketplace action adoption, multi-repo rollout
   readiness, Atlassian track, or GitLab track.
2. Include the exact next-step command, workflow file, or GitHub API operation.
3. State the measurable success condition, e.g. "all app-owned checks terminal
   within 10 minutes", "dependency PRs auto-merge after CodeQL + integrity
   green", or "same PR gate deployed to one external pilot repository".
4. Do not use vague capability-roadmap language.

[SHOWCASE ATTESTATION]
Mandatory grant-readiness evaluation. Runs AFTER [OPERATOR INTELLIGENCE] and BEFORE
the response is finalised. Governed by `.agent_governance/rules/grant-readiness.md`.

Protocol:
1. Read `README.md` and `docs/index.md` (first 60 lines of each suffice).
2. Evaluate against the three grant mission profiles: OpenAI Researcher Access,
   Google Cloud/AI Futures Fund, Anthropic alignment.
3. Check for all five degradation triggers defined in the Grant Readiness Law.
4. Report one of two verdicts per program:

   **PASS** — repository presentation satisfies this program's reviewer criteria.
   State which specific sections or capabilities provide the evidence.

   **FAIL** — name the exact degradation trigger that fired, the exact file and
   section that is deficient, and the one-paragraph fix. If FAIL, a
   `### Phase N: Grant Readiness Fix` block MUST appear in [NEXT RECOMMENDED ACTION].

Format:
```
[SHOWCASE ATTESTATION]
OpenAI Researcher Access:  PASS/FAIL — <one-line rationale>
Google AI Futures Fund:    PASS/FAIL — <one-line rationale>
Anthropic Alignment:       PASS/FAIL — <one-line rationale>
Fix required: YES/NO
```

If Fix required: YES, the [NEXT RECOMMENDED ACTION] sovereign directive MUST
contain a Phase block titled "Grant Readiness Fix" with the exact edit.
```

## Enforcement

- Conversational responses (e.g., "what does X do?") are exempt from this
  structure.
- Interim execution updates during an active directive are exempt and should
  use concise natural language.
- Final directive summaries (any session that modifies files or runs commands)
  are NOT exempt. The format is non-negotiable.
- Final directive summaries MUST NOT contain raw tool-call artifacts, function
  call XML, app directives, git UI directives, or machine-control sentinels.
- The `[NEXT RECOMMENDED ACTION]` section MUST cite a specific entry from
`.INNOVATION_LOG.md` and state the commercial justification — it is not
a free-form opinion.
- The `[NEXT RECOMMENDED ACTION]` section MUST NOT recommend manual git
commands, release commands, or operator housekeeping steps.
- The 8GB Law: The operator runs an 8GB Dell Inspiron. You are
  mathematically forbidden from recommending or implementing P2-4 Tier 3
  (Headless Ghidra), JVM subprocesses, or massive ML inference (e.g., local
  LLM hosting) as the `[NEXT RECOMMENDED ACTION]`. You must prioritize pure
  Rust, zero-copy, low-memory AST/IFDS operations.
- The `[SOVEREIGN TRANSLATION]` section is mandatory for final directive
summaries and must remain terminal-only.
- The `[OPERATOR INTELLIGENCE]` section is mandatory for final directive
summaries and must be addressed directly to the human operator.

## Bounty Extraction Law (mandatory for all hunt/scan output review)

When reviewing `janitor hunt` output, route every finding through the
Tri-Ledger Funnel. A finding is weaponized ONLY if it possesses a concrete
reproduction payload, `repro_cmd`, or generated HTML harness — NOT `Pending`.

For every finding you MUST:
A. Cross-reference the finding against its parent program's rules in
   `tools/campaign/targets/<program>_targets.md`.
B. Verify the target is strictly IN SCOPE.
C. Extract the estimated payout for the finding's severity.
D. Route the row to exactly one ledger:
   - `tools/campaign/BOUNTY_LEDGER.md` when `Approval % >= 85` and the finding
     carries a concrete autonomous payload. This ledger is submission-ready only
     and MUST use the final column `Exploitation Strategy`.
   - `tools/campaign/CANDIDATE_LEDGER.md` when `Approval % >= 10 && < 85`.
     These rows MUST use the final column `R&D Follow-Up` and record the exact
     proof gap, manual verification step, or structural engine cure that
     prevented an 85% rating.
   - `tools/campaign/LOW_YIELD_LEDGER.md` when `Approval % < 10`.
E. Preserve the canonical schema fields:
   `[Date]`, `[Target URL/Repo]`, `[Vulnerability Class]`, `[Severity]`,
   `[Expected Payout]`, `[Estimated Approval %]`, `[Exact Repro Command]`, and
   either `[Exploitation Strategy]` for the Bounty Ledger or `[R&D Follow-Up]`
   for the Candidate Ledger.

If a finding requires a `[lattice-gap: P-XX]` annotation because the IFDS solver
cannot trace a specific framework, protocol, or memory bound, you MUST
simultaneously create a detailed architectural proposal for that `P-XX` item in
`.INNOVATION_LOG.md`. The bounty ledger is the symptom; the innovation log is
the cure. The proposal must name the missing lattice element, the Rust module to
extend, the deterministic proof strategy, and the true-positive / true-negative
fixture pair required to close the gap.

### Mathematical Certainty Law (Sprint Batch 97)

When authoring core security logic — taint scoring, HMAC/signature generation,
cryptographic serialization boundaries — unit tests alone are **insufficient**.
You MUST author a `#[kani::proof]` harness (gated under `#[cfg(kani)]`) that
injects symbolic inputs via `kani::any::<T>()` and proves the absence of panics,
integer overflows, and undefined behaviour across all possible input states up
to a defined bound. The harness lives in `crates/forge/src/reflexive_assurance.rs`.
Shipping a new security-critical function without this harness is a governance
violation.

### Delivery Guarantee Law (Sprint Batch 98)

Web ExploitWitness rendering MUST assume a WAF is present. Z3-backed witness
generation must assert negative constraints for common XSS and SQL injection
signatures before model extraction, and must render only verifier-safe canaries.
Raw bypass payloads, guaranteed bypass claims, live exploit command synthesis,
and "100% bypass probability" language are not valid final output.

### Dual-Ledger Mandate (Sprint Batch 96)

Whenever a finding is logged with `Approval % < 85%` due to a **missing engine
capability**, you MUST author BOTH: (1) a manual Exploitation Strategy in the
Candidate Ledger AND (2) a corresponding P-tier architectural proposal in
`.INNOVATION_LOG.md` that automates that strategy. Logging a capability gap in
the candidate ledger without a corresponding innovation log entry is a governance
violation. The bounty ledger records the failure; the innovation log records the
cure. Both entries are mandatory and must be authored in the same session.

Any new architectural feature added to `.INNOVATION_LOG.md` MUST be assigned a
strict, sequential P-tier ID (for example `P1-15` or `P3-9`). Non-sequential,
alphabetic, or section-only identifiers are governance-invalid.

### Ledger Hydration Law (Sprint Batch 119)

During EVERY sprint, you MUST read the `R&D Follow-Up` columns in
`tools/campaign/CANDIDATE_LEDGER.md` and `tools/campaign/LOW_YIELD_LEDGER.md`.
If an R&D task is listed but does not already have a corresponding strict
P-tier entry in `.INNOVATION_LOG.md`, you MUST elevate it into a formal
strict P-tier item immediately, and that item MUST append explicit instructions
to re-hunt the affected targets once the feature is built.

### Git Sync Law (Sprint Batch 124)

You must execute `git push origin main` after every successful local commit in a
sprint, UNLESS explicitly instructed otherwise by the operator. The local and
remote state must remain synchronized to trigger CI/CD pipelines.

### Threat Model Awareness (mandatory threat model pre-filter)

You MUST evaluate the **Taint Source Origin** and **Actor Privilege Level** BEFORE
logging any finding to the Bounty Ledger or including it in a hunt report.

- A finding that requires **local config modification**, **env var control**, or
  **Admin privileges** is NOT remotely exploitable. `Approval % < 10%`.
- A finding in **client-side TypeScript/JavaScript** where the sink is a
  `fetch()` / `XMLHttpRequest` / `axios` call is NOT server-side SSRF. Client-side
  HTTP calls are blocked by SOP/CORS. Requires proof of a **server-side execution
  path** (SSR, Next.js API route, Node.js backend). Without it: `Approval % < 10%`.
- **Self-XSS** (victim must trigger the payload themselves without any third-party
  attack vector): `Approval % < 10%`.

For every entry with `Approval % < 10%`, route the row to
`tools/campaign/LOW_YIELD_LEDGER.md` instead of deleting it. Preserve the target,
finding class, approval estimate, reason routed, and R&D follow-up so Omni-Audits
can mine it for future AEG templates or AST suppressions.
`tools/campaign/BOUNTY_LEDGER.md` remains reserved for findings with
`Approval % >= 85%`; `tools/campaign/CANDIDATE_LEDGER.md` owns the `10%..84%`
band.

## Structural Eradication Law (mandatory for all hunt/scan output review)

You are mathematically forbidden from appending Markdown notes or prose to explain
away a False Positive in a hunt report.  Suppress a Commercial False Positive ONLY
by writing a deterministic Rust AST/path guard in `crates/cli/src/hunt.rs` or
`crates/forge/src/slop_hunter.rs` that eradicates the finding from the output.
The report must be completely devoid of the suppressed finding — no footnotes, no
`---` suppression blocks, no explanatory prose.

Required action on a Commercial False Positive:
1. Write an `is_excluded_hunt_entry` path guard or a detector-level context filter
   in `slop_hunter.rs` that prevents the finding from being emitted.
2. Re-run `janitor hunt` and confirm the finding is absent.
3. Never append a suppression explanation to the report.

The exception: `security:credential_leak` in any directory is always billable — a
secret in a repo is a secret in a repo.

## Ledger Synchronization Law

Whenever a structural AST guard suppresses a vulnerability class that already
exists in `tools/campaign/BOUNTY_LEDGER.md`, you MUST proactively open the
ledger and physically DELETE the disproven rows in the same session. A false
positive may not survive as historical noise once the engine has mathematically
eradicated it.

## Anti-Recency-Bias Law (mandatory for `[NEXT RECOMMENDED ACTION]`)

You MUST scan the **entire** `.INNOVATION_LOG.md` — P0, P1, and P2 — before
selecting the next action.  Do NOT default to the section you just edited or the
last file you touched.

**Selection criterion:** the single entry with the highest commercial Total
Addressable Market (TAM) expansion, Total Economic Impact (TEI), or most
critical enterprise compliance upgrade. TEI is assessed as:
(detection severity × addressable language market share × number of open CVEs
in class). A KevCritical rule in Go or Python outranks a P2 ergonomics fix in
every scenario unless the P2 item unlocks materially larger market access.

**Hard rule:** if the current session touched a P1 or P2 item, the next action
MUST still be the highest-value P0 entry that remains in the log. Recency is
not a selection criterion. Under the Absolute Eradication Law, a P0 entry
that has been completed is already deleted from the log, not tagged — so the
selection universe at any moment is exactly the set of open P-entries
present in the file.

## Cash-Flow Priority Override

If a `P-tier` item in `.INNOVATION_LOG.md` was explicitly generated to solve a
proof gap for a finding currently sitting in `tools/campaign/CANDIDATE_LEDGER.md`,
it automatically outranks broader architectural features. The fastest path to a
validated Bugcrowd submission is the absolute priority.

## Absolute Eradication Pre-Flight (reminder)

Before emitting `[NEXT RECOMMENDED ACTION]`, perform the check defined in
`.agent_governance/rules/log_hygiene.md`:

1. Did the current session ship any feature that is still described in
   `.INNOVATION_LOG.md`?
2. If yes, physically delete the corresponding block(s) in the same
   commit that ships the feature. Do NOT tag, strikethrough, or comment
   them out. Hard-delete only.
3. Re-read the purged log before selecting the next action.

A `[NEXT RECOMMENDED ACTION]` authored over a log that still contains
tombstoned completed work is a governance violation. The log and the
recommendation are a single atomic artifact.
