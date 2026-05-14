# Grant Strategy

Target funders: Anthropic, OpenAI, Google.

## Positioning Narrative

The Janitor is an open-source structural PR gate for AI-generated and
AI-assisted code. It converts static findings into deterministic witnesses,
routes weak evidence into ledgers instead of submissions, and preserves
enterprise/FedRAMP viability through air-gapped execution, zero-upload scanning,
cryptographic provenance, and bounded resource use.

The thesis: AI threat-hardening requires proof-carrying automation. The fastest
revenue and grant path is authenticated SaaS and AI-copilot defense: tenant
isolation, authorization replay, RAG/vector-store boundary proofs, agent
deception controls, and CI gates that prevent ambiguous AI changes from merging.

## 30/60/90 Engineering Milestones

| Window | Milestone | Measurement |
|--------|-----------|-------------|
| 30 days | Authenticated SaaS witness lane | `security:missing_ownership_check` emits `AuthorizationWitness`; two-user deterministic fixture passes; at least three candidate findings rerouted with explicit replay verdicts. |
| 30 days | Vector filter polymorphism lane | P2-15 detector ships with TP/TN fixtures; `cargo test -p forge vector_ -- --test-threads=1` remains green; false-positive `.query(` class suppressed. |
| 60 days | Agent deception proof suite | Prompt/tool deception detectors emit IFDS-backed witnesses; ARTICLE_REVIEW queue maps external AI-agent incidents into defended/new/mapped innovation states. |
| 60 days | Enterprise evidence pack | Public security posture, threat model, deployment docs, SBOM, SLSA provenance, and Check Run terminality proofs bundled for procurement. |
| 90 days | Air-gap/FedRAMP pilot | Offline workflow runs against a representative monorepo under 100MB active RAM policy; no network upload; signed report and reproducible audit logs generated. |
| 90 days | Commercial conversion | Three design-partner demos focused on tenant isolation and AI-copilot PR gating; at least one paid pilot or grant-funded evaluation agreement. |

## Evidence-Pack Checklist

- Public repository, license, and contribution posture.
- `SECURITY.md` and live [security posture](https://thejanitor.app/security/).
- CI green proofs: workflow lint, dependency review, PR gate, CodeQL, integrity
  check, `just audit`.
- Deterministic witness tests for vector filters and authorization replay.
- Tri-Ledger samples: bounty, candidate, low-yield, and target-ledger updates.
- Resource envelope evidence: 8GB Law, zero-copy hot paths, bounded curl/action
  timeouts, no unbounded report generation.
- Cryptographic provenance story: public verifying key only, signed artifacts,
  no private key material in repo.
- Demo repository and replay script for authenticated cross-tenant witness.
- Roadmap entries tied to formal models: Z3, Kani, IFDS, and deterministic
  fixtures.
- ARTICLE_REVIEW evidence that maps external AI workflow claims into concrete
  defended/mapped/new innovation states with source quality and confidence.
- Systems Health Signal queue showing stuck checks, stale PRs, missing
  toolchains, and docs drift with exact remediation commands.

## Outreach Package

### One-Page Brief

Problem: AI-generated code and autonomous agents create plausible but ambiguous
security changes that ordinary PR checks cannot classify. Enterprises need a
local structural firewall that blocks dangerous deltas, explains proof gaps, and
keeps evidence inside their boundary.

Solution: The Janitor runs as a CI PR gate and offline scanner. It emits
deterministic witnesses for high-value classes, routes underproved evidence to
ledgers, and provides enterprise-grade provenance without source upload.

Ask: grant or pilot funding for authenticated SaaS/AI-copilot witness lanes,
air-gap packaging, and external evaluation against real multi-tenant codebases.

### Technical Appendix

- Architecture: Rust workspace with forge detectors, CLI hunt pipeline,
  crucible regression harness, and campaign ledgers.
- Formal methods: IFDS source-to-sink reachability, Z3 path predicates, Kani
  invariants for memory/proof-state guards.
- Current differentiators: structural PR gate, vector filter polymorphism
  witness, authorization witness, public security posture, and Tri-Ledger
  evidence discipline.
- Risk controls: 100MB active RAM target, bounded subprocesses, deterministic
  tests, static-only assertion messages, and no co-authored commit trailers.

### Demo Script

1. Show `https://thejanitor.app/security/` and `SECURITY.md` cross-links.
2. Run `cargo test -p forge vector_ -- --test-threads=1`.
3. Run `cargo test -p cli replay -- --test-threads=1`.
4. Demonstrate a PR gate run that terminates with a signed pass/fail verdict.
5. Open candidate and low-yield ledger rows to show proof-gap routing instead
   of inflated claims.
6. Run an authenticated two-user fixture and show `AuthorizationWitness` replay
   verdict updates.
7. Show an AI-agent tool-intent finding that carries `ToolIntentWitness`,
   `ProofSummary`, and a safe local reproduction command.
