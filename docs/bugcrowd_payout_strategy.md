# Bugcrowd Payout Strategy

This is an internal execution guide. It is intentionally excluded from the
public MkDocs build.

## Target Selection Rubric

Score every candidate target before running `janitor hunt`:

| Signal | Weight | Pass Condition |
|--------|--------|----------------|
| Authenticated SaaS or AI-copilot surface | 35 | Multi-tenant objects, admin APIs, PR bots, RAG/vector search, or agent tools are in scope. |
| Program payout clarity | 25 | Public scope documents define authorization, data exposure, or supply-chain impact payouts. |
| Autonomous witness viability | 25 | A deterministic `repro_cmd`, browser harness, `AuthorizationWitness`, or `WebProofArtifact` can prove impact without manual guessing. |
| Noise suppression maturity | 15 | Existing detector has TP/TN fixtures and known test/mock suppressions for the target language. |

Only route a finding to `tools/campaign/BOUNTY_LEDGER.md` when approval is at
least 85% and the witness is concrete. Anything below that belongs in
`tools/campaign/CANDIDATE_LEDGER.md` with the exact proof gap preserved.

## Witness Quality Threshold

Submission-ready evidence must include:

- in-scope target URL or repository;
- exact affected file and line;
- one vulnerability class, not a cluster of loosely related findings;
- deterministic reproduction payload, `repro_cmd`, generated HTML harness,
  `AuthorizationWitness`, or `WebProofArtifact`;
- data-flow or invariant proof that names source, sink, boundary, and missing
  guard;
- remediation that is specific enough for an engineer to patch;
- no placeholder payloads, no "Pending" reproduction, and no speculative impact.

## Reproducibility Checklist

1. Re-run the exact `janitor hunt` command against a clean clone.
2. Confirm the finding survives deduplication.
3. Confirm the target is listed as in scope in `tools/campaign/targets/`.
4. Confirm the witness has no network side effects beyond read-only proof.
5. Confirm `cargo test` for the owning detector passes.
6. Confirm the generated submission contains target, severity, impact,
   reproduction, remediation, and scope rationale.
7. Route through Tri-Ledger before any external submission.

## Submission Package Template

```text
Title:
  <Target>: <vulnerability class> in <component>

Severity:
  <Program severity + payout bracket>

Target:
  <In-scope URL or repository>

Summary:
  <One paragraph describing the broken boundary>

Evidence:
  File: <path>:<line>
  Source: <attacker-controlled input or tenant/user A object>
  Sink: <privileged operation or tenant/user B object>
  Boundary: <missing ownership/authz/filter/provenance guard>

Reproduction:
  <repro_cmd / AuthorizationWitness / WebProofArtifact / HTML harness>

Impact:
  <Concrete data exposure, privilege escalation, supply-chain compromise, or
  tenant isolation break accepted by the program>

Remediation:
  <Specific guard, allowlist, ownership check, sanitizer, or provenance pin>
```

## First-Payout 30/60/90 Plan

| Window | Weekly KPI | Engineering Output |
|--------|------------|--------------------|
| 30 days | 3 authenticated SaaS targets scanned weekly; 1 candidate promoted weekly if proof reaches 85%. | Stabilize `AuthorizationWitness`, vector-filter polymorphism, and proof-summary routing; close any pending app-owned integrity checks before dependency merges. |
| 60 days | 2 submission-ready packages produced; 1 external triage response received. | Add target-specific suppressions from triager feedback; require proof summaries in every Critical report. |
| 90 days | 1 accepted or paid report; 3 reusable proof fixtures added from real triage outcomes. | Convert the winning class into a repeatable detector lane and add it to the grant evidence pack. |

Fastest conversion lane: authenticated authorization and tenant-isolation
witnesses for SaaS/admin APIs, followed by AI-agent tool-intent deception where
the program explicitly accepts AI/supply-chain impact.
