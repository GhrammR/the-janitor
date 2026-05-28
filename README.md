# The Janitor

**v10.2.11 — Rust static-analysis research across 23 grammars. IFDS + Z3 SMT + Kani proof obligations. Dual-PQC attestation. Zero-upload. On-device.**

> *82% of open Godot Engine pull requests contain no issue link. 20% introduce language antipatterns. Zero comment scanners caught it. The Janitor did — across 50 live PRs, in under 90 seconds.*

## What This Is

The Janitor is an active Rust security-research project. It explores how far a
local static-analysis engine can push vulnerability discovery when syntactic
pattern matching is paired with interprocedural dataflow, formal proof
obligations, exploit-witness synthesis, and cryptographic provenance.

- 128,504 lines of Rust across 15 workspace crates
- 1,400+ deterministic unit tests and Kani formal-verification harnesses
- 23 tree-sitter grammars, IFDS taint solver across 14 languages
- public security targets analyzed across Bugcrowd, HackerOne, and Immunefi

## Research Foundation

The Janitor is an active security research platform spanning four technical frontiers:

- **Interprocedural Taint Analysis (IFDS)** — full context-sensitive dataflow across 14 languages with sanitizer-registry suppression and Z3 SMT path-feasibility refinement.
- **Formal Verification (Kani + Z3)** — every security-critical predicate ships with a `#[kani::proof]` harness proving absence of panics and integer overflow across all symbolic inputs. Z3-backed exploit witnesses synthesize `curl`-form reproduction commands from model-extracted payloads.
- **Post-Quantum Provenance (ML-DSA-65 + SHA-384)** — all findings are sealed into SLSA Level 4 `DecisionCapsule` records with dual-PQC attestation, verifiable offline without source upload.
- **Proof-Obligation Framework** — every KevCritical finding must carry a `ReachabilityProof`, `InvariantViolationProof`, or `LatticeGapProposal` before reaching the bounty ledger. This eliminates unprovable critical reports at triage time.

## Current Research Questions

- Can a small local engine reliably distinguish exploitable findings from
  framework noise before a human writes a report?
- Which proof obligations are sufficient to turn a syntactic detector into a
  reproducible vulnerability claim?
- How much evidence can be generated without uploading source code to a hosted
  scanner or model provider?
- Where do static detectors need formal predicates, symbolic constraints, or
  explicit lattice-gap proposals instead of another rule string?

## Cloud Reproducibility Track

Janitor findings can be reproduced in GitHub Actions and mapped onto Google
Cloud Build and Artifact Registry provenance without uploading source code.
A reproducibility run emits structured findings, proof-class decisions, SARIF,
and SHA-384 provenance metadata that can be mirrored into Cloud Build
attestations or Artifact Registry records while keeping repository contents
inside the operator-controlled build environment. No source upload is required
at any step — the GitHub Actions runner executes the full analysis pipeline
locally and pushes only signed attestation records to Cloud infrastructure.

## Adversarial Robustness and Tool-Intent Safety

The Janitor treats prompt injection, MCP/tool dispatch, agentic origin, and
untrusted-context transposition as security research surfaces. The engine tests
these paths with deterministic proof obligations for prompt/tool
non-interference, confused-deputy dispatch, agentic-origin classification, and
retrieval-context trust before findings reach audit ledgers.

## Research Findings

**Finding 1 — Syntactic pattern matching is insufficient for triage-quality results.** The engine reliably produced findings that matched vulnerability patterns and reliably failed Tier-1 validation. The gap: detectors matched syntax but did not reason about surrounding context — auth decorators, sanitizer helpers, framework middleware pipelines, and scope rules.

**Finding 2 — Structural context resolution requires interprocedural dataflow.** Three oracle modules (`forge::threat_model_oracle`, `forge::jwt_keyfunc_oracle`, `forge::sql_sanitizer_oracle`) shipped to catch the highest-volume false-positive classes with deterministic AST guards. The structural approach is necessary and sufficient for known FP patterns; it does not surface previously-unknown paths.

**Finding 3 — Proof-class annotation is the critical missing layer.** Candidate findings failed because the engine could not provide a mandatory `ReachabilityProof`, `InvariantViolationProof`, or `LatticeGapProposal`. The proof-obligation framework (Sprint 148–151) addresses this gap systematically with Kani-verified predicate harnesses for every new proof class.

## Reproduce Locally

```bash
cargo test -p forge -- proof_obligation --test-threads=2
cargo test -p forge -- reflexive_assurance --test-threads=2
cargo run -p cli -- hunt /path/to/repository --concurrency 4
```

The default workflow is local and file-system scoped. Findings are ordinary
structured records; research notes and implementation history live in
`docs/CHANGELOG.md` and `.INNOVATION_LOG.md`.

## If you are considering building on this research

The architecture and approach are documented in `docs/` and the innovation log.
The project is under active development; peer review, research collaboration,
and reproducibility feedback are welcome. Contact: reghramm@gmail.com.

The most important lessons from building this platform — particularly around IFDS solver design, proof-class annotation at scale, and false-positive classification on polyglot codebases — are documented in `docs/CHANGELOG.md` as session-by-session implementation notes.
