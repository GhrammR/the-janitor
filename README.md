# The Janitor

> **Research status (2026-06-01):** Commercial validation phase concluded.
> Continuing as a public security-research artifact. See the
> [post-mortem](https://news.ycombinator.com/item?id=48176168) for outcomes.

## What this is

A static-analysis security research platform built in Rust: interprocedural
taint analysis (IFDS + Z3 SMT), post-quantum provenance attestation
(ML-DSA-65 + SHA-384), and automated exploit-witness synthesis across 23
grammars. Built as a solo experiment to measure how far current AI-assisted
tooling can push the boundary of automated vulnerability discovery.

- 128,504 lines of Rust across 15 workspace crates
- 1,407 deterministic unit tests, 14 Kani formal-verification harnesses
- 23 tree-sitter grammars, IFDS taint solver across 14 languages
- 194 bug-bounty programs hunted across Bugcrowd, HackerOne, Immunefi

## Research Findings

**Finding 1 — Syntactic pattern matching is insufficient for triage-quality results.** The engine reliably produced findings that matched vulnerability patterns and reliably failed Tier-1 validation. The gap: detectors matched syntax but did not reason about surrounding context — auth decorators, sanitizer helpers, framework middleware pipelines, and scope rules.

**Finding 2 — Structural context resolution requires interprocedural dataflow.** Three oracle modules (`forge::threat_model_oracle`, `forge::jwt_keyfunc_oracle`, `forge::sql_sanitizer_oracle`) shipped to catch the highest-volume false-positive classes with deterministic AST guards. The structural approach is necessary and sufficient for known FP patterns; it does not surface previously-unknown paths.

**Finding 3 — Proof-class annotation is the critical missing layer.** Seven candidate findings failed because the engine could not provide a mandatory `ReachabilityProof`, `InvariantViolationProof`, or `LatticeGapProposal`. The proof-obligation framework (Sprint 148) addresses this gap systematically; the full IFDS + Z3 path-feasibility pipeline is the production-grade cure.

## Sunset terms

| Item | Status after 2026-06-01 |
| --- | --- |
| New releases | None planned |
| Issue triage | None |
| PR review | None |
| Feature requests | Not accepted |
| Security reports | Not triaged — please report to upstream targets directly |
| GitHub Action Marketplace listing | Remains listed (use at your own risk; no support after sunset) |
| Repository visibility | Public, read-only |
| License | Unchanged; fork freely |

Active work may continue against this repository between now and
2026-06-01. After that date, the repository is permanently quiescent.

## If you are considering building something like this

Please read the [HackerNews post-mortem](https://news.ycombinator.com/item?id=48176168)
before you start. The next four months of your life are worth more than
this.

---

*Built 2026-02 through 2026-05. Sunsetted 2026-06-01.*
