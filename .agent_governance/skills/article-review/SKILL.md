# ARTICLE_REVIEW Skill

Use this skill when the operator asks to process `ARTICLE_REVIEW.md`, review
security/AI articles, map external claims into Janitor defenses, or update
innovation/attack ledgers from article evidence.

## Inputs

- `ARTICLE_REVIEW.md` is the queue.
- `.INNOVATION_LOG.md` is the append-only frontier log.
- `tools/campaign/*.md` and `tools/campaign/target_ledger.json` are the attack
  ledgers.

## Workflow

1. Read `.agent_governance/rules/article-review.md`.
2. Parse every URL from `ARTICLE_REVIEW.md`.
3. For each URL:
   - Fetch the URL externally and record status/final URL/title/timestamp.
   - Run corroborating internet searches using the article's core claim,
     vulnerability identifier, product, or named technique.
   - Prefer primary sources over commentary.
   - Score source quality from 1 to 5.
   - Score conclusion confidence from 0.0 to 1.0.
   - Map to `already_defended`, `mapped_innovation_item`,
     `new_innovation_item`, or `attack_ledger_update`.
   - Append a sequential finding to `.INNOVATION_LOG.md`.
4. When an article creates a detector or proof gap, the appended innovation item
   must include:
   - invariant/proof gap;
   - Rust module;
   - Z3/Kani/IFDS model;
   - deterministic TP/TN fixtures;
   - commercial unlock.
5. When an article affects hunting, update the correct ledger with exact target,
   reason, confidence, and follow-up.
6. Propose at least one novel follow-up search concept per run.

## Non-Negotiables

- No pretending: inaccessible pages remain inaccessible evidence.
- No bulk narrative without ledger or innovation mapping.
- No raw TEI or ROI hand-computation; use authoritative ledgers/tools when the
  operator asks for executive or actuarial summaries.
