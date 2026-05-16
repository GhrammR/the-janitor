# Rule: Grant Readiness Law

## Mission Profiles (Evaluated Every Sprint)

### OpenAI Researcher Access Program
- Focus: alignment, fairness/representation, societal impact, interdisciplinary research,
  interpretability/transparency, misuse potential (red teaming), robustness.
- Reviewer signal: responsible AI deployment, adversarial input resilience, bias detection.
- Funding: up to $1,000 API credits per researcher. Quarterly review (Mar/Jun/Sep/Dec).
- Key presentation requirement: academic rigor, clearly stated research question, measurable
  safety outcome.

### Google Cloud for Startups / AI Futures Fund
- Focus: practical AI-powered innovation, measurable business outcomes, advanced model
  integration (Gemini, Veo, Imagen), cloud-native architecture.
- Reviewer signal: demonstrated traction, technical depth, clear use of Google cloud/AI APIs.
- Key presentation requirement: startup framing, quantified impact (cost savings, scale),
  clear go-to-market, evidence of model integration.

### Anthropic (implied — AI safety alignment)
- Focus: AI safety research, constitutional AI, interpretability, red teaming, model
  behavior auditing, multi-agent safety.
- Reviewer signal: mechanistic understanding of model failures, detection of prompt injection
  and tool misuse, formal verification of safety properties.
- Key presentation requirement: safety-first framing, formal proofs or empirical evidence of
  reduced harm, alignment with responsible deployment.

## The Grant Readiness Law

At the end of every sprint, **before generating the final `[SOVEREIGN TRANSLATION]` section**,
you MUST evaluate the current state of the following files against all three mission profiles
above:

- `README.md` — public-facing first impression for grant reviewers
- `docs/index.md` — documentation landing page and technical depth signal
- `.INNOVATION_LOG.md` — evidence of research frontier (ZK attestation, IFDS, formal
  verification, AI safety detectors)

### Degradation Triggers (any one fires the law)

1. **Academic framing absent**: `README.md` or `docs/index.md` lacks a clear research
   problem statement, a formal methodology section, or a citation-ready capability list.
2. **Safety narrative gap**: No mention of prompt injection detection, agent tool-intent
   guard, or adversarial robustness in the primary documentation.
3. **Alignment surface missing**: The repository presents purely as a commercial tool with
   no visible alignment/safety research contribution.
4. **Formal verification invisible**: `README.md` does not surface Kani formal proofs,
   IFDS taint analysis, or Z3 path feasibility as first-class capabilities.
5. **Grant-critical metrics stale**: Benchmark claims (scan speed, detector coverage,
   grammar count) have not been updated in the last 3 sprints.

### Mandatory Response

If any degradation trigger fires, you MUST append a `### Phase N: Grant Readiness Fix`
block to the `[NEXT RECOMMENDED ACTION]` sovereign directive prompt. The phase MUST:
- Name the exact file to edit (`README.md`, `docs/index.md`, etc.)
- Quote the specific section heading to add or update
- Provide a one-paragraph draft of the content that satisfies the grant reviewer criterion
- State which grant program(s) the fix targets

## Enforcement

This law runs BEFORE the `[SHOWCASE ATTESTATION]` section is written. The attestation
section records the outcome of this evaluation — pass or fail, with evidence.

A sprint summary that omits the `[SHOWCASE ATTESTATION]` section is a governance violation
equivalent to omitting `[TELEMETRY]`.
