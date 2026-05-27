# Hunt Discipline Laws

Read this file whenever reviewing `janitor hunt` or `janitor scan` output,
routing findings to ledgers, or authoring security proofs.

---

## Bounty Extraction Law

Route every finding through the Tri-Ledger Funnel. A finding is weaponized
ONLY if it has a concrete `repro_cmd`, reproduction payload, or generated HTML
harness — NOT `Pending`.

For every finding:
A. Cross-reference against `tools/campaign/targets/<program>_targets.md`.
B. Verify the target is strictly IN SCOPE.
C. Extract the estimated payout for the finding's severity.
D. Route to exactly one ledger:
   - `BOUNTY_LEDGER.md` — `Approval % >= 85` + concrete autonomous payload.
     Final column: `Exploitation Strategy`. Submission-ready only.
   - `CANDIDATE_LEDGER.md` — `10% <= Approval % < 85`.
     Final column: `R&D Follow-Up` naming the exact proof gap or engine cure.
   - `LOW_YIELD_LEDGER.md` — `Approval % < 10`.
E. Preserve canonical schema: `[Date]`, `[Target URL/Repo]`, `[Vulnerability Class]`,
   `[Severity]`, `[Expected Payout]`, `[Estimated Approval %]`, `[Exact Repro Command]`,
   and either `[Exploitation Strategy]` or `[R&D Follow-Up]`.

If a finding requires a `[lattice-gap: P-XX]` annotation, simultaneously create
the P-tier architectural proposal in `.INNOVATION_LOG.md` naming the missing
lattice element, Rust module to extend, proof strategy, and TP/TN fixture pair.

### Dual-Ledger Mandate

When `Approval % < 85%` due to a **missing engine capability**: author BOTH a
manual Exploitation Strategy in the Candidate Ledger AND a P-tier proposal in
`.INNOVATION_LOG.md`. Logging a gap without the innovation entry is a
governance violation.

All new `.INNOVATION_LOG.md` entries MUST use a strict sequential P-tier ID
(`P1-15`, `P3-9`, etc.). Non-sequential or section-only identifiers are invalid.

### Ledger Hydration Law

During every sprint, read the `R&D Follow-Up` columns in `CANDIDATE_LEDGER.md`
and `LOW_YIELD_LEDGER.md`. Any R&D task without a corresponding P-tier entry in
`.INNOVATION_LOG.md` MUST be elevated immediately, with instructions to re-hunt
once the feature is built.

### Ledger Synchronization Law

When a structural AST guard suppresses a vulnerability class already in
`BOUNTY_LEDGER.md`, physically DELETE the disproven rows in the same session.
A false positive may not survive as historical noise.

---

## Threat Model Pre-Filter (mandatory before logging any finding)

Evaluate **Taint Source Origin** and **Actor Privilege Level** BEFORE routing:

- Requires **local config modification**, **env var control**, or **Admin
  privileges** → NOT remotely exploitable → `Approval % < 10%`.
- **Client-side TypeScript/JavaScript** where the sink is `fetch()` /
  `XMLHttpRequest` / `axios` → NOT server-side SSRF (blocked by SOP/CORS).
  Requires proof of an SSR/Node.js execution path. Without it: `Approval % < 10%`.
- **Self-XSS** (victim must trigger their own payload) → `Approval % < 10%`.

Route every sub-10% entry to `LOW_YIELD_LEDGER.md` with target, finding class,
approval estimate, reason, and R&D follow-up.

---

## Structural Eradication Law

Suppress a Commercial False Positive ONLY by writing a deterministic Rust
AST/path guard in `crates/cli/src/hunt.rs` or `crates/forge/src/slop_hunter.rs`.
The report must be devoid of the suppressed finding — no footnotes, no prose explanations.

Required steps:
1. Write an `is_excluded_hunt_entry` path guard or detector-level context filter.
2. Re-run `janitor hunt` and confirm the finding is absent.
3. Never append a suppression explanation to the report.

Exception: `security:credential_leak` in any directory is always billable.

---

## Mathematical Certainty Law

When authoring core security logic (taint scoring, HMAC/signature generation,
cryptographic serialization), unit tests alone are **insufficient**. Author a
`#[kani::proof]` harness in `crates/forge/src/reflexive_assurance.rs` that
uses `kani::any::<T>()` to prove absence of panics, integer overflows, and UB
across all input states. Shipping a security-critical function without this
harness is a governance violation.

---

## Delivery Guarantee Law

Web ExploitWitness rendering MUST assume a WAF is present. Z3-backed witness
generation must assert negative constraints for common XSS/SQL injection
signatures before model extraction, and must render only verifier-safe canaries.
Forbidden output: raw bypass payloads, "100% bypass probability" claims, live
exploit synthesis.
