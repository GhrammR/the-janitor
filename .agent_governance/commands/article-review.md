# /article-review

Run ARTICLE_REVIEW against `ARTICLE_REVIEW.md`.

## Procedure

1. Load `.agent_governance/skills/article-review/SKILL.md`.
2. Read `ARTICLE_REVIEW.md`.
3. Extract URLs and any adjacent operator prompts.
4. Verify real URL access externally.
5. Search the internet for corroborating or contradicting sources.
6. Classify each article into one ARTICLE_REVIEW disposition.
7. Append sequential findings to `.INNOVATION_LOG.md`.
8. Update campaign or attack ledgers only when the evidence justifies a
   machine-readable target, detector, or low-yield change.
9. Finish with a compact table: URL, disposition, confidence, source quality,
   files changed, and next search concept.

## Failure Rule

If a URL cannot be reached, do not summarize it from title memory. Record the
failed access evidence and move to the next URL.
