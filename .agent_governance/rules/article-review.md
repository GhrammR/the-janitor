# ARTICLE_REVIEW Rule

ARTICLE_REVIEW turns external security and AI-engineering articles into
defensive engineering deltas. It is not a summarization workflow.

## Mandatory Inputs

- Read `ARTICLE_REVIEW.md`.
- Extract only real URLs from the file.
- Treat inline operator questions beside a URL as review prompts for that URL.

## Evidence Requirements

1. Verify each URL is reachable with an external HTTP request or browser fetch.
   Record status, final URL after redirects, title or canonical page marker, and
   retrieval timestamp. Do not infer access from memory.
2. Run at least one additional internet search per article family to corroborate
   the claim, identify primary sources, or find dissenting technical evidence.
3. Prefer primary sources: advisories, CVEs, vendor posts, patches, specs,
   academic papers, incident reports, and source repositories.
4. Assign source quality:
   - 5: primary technical source with patch/advisory/proof.
   - 4: reputable security reporting with named technical evidence.
   - 3: credible industry analysis without primary artifacts.
   - 2: commentary, marketing, or unverifiable secondary reporting.
   - 1: inaccessible, paywalled without extractable evidence, or unsupported.
5. Assign conclusion confidence from 0.0 to 1.0 based on source quality,
   corroboration, and proximity to Janitor detector scope.

## Mapping Contract

Every article maps to exactly one disposition:

- `already_defended`: existing detector, workflow, governance law, or ledger
  entry covers the class.
- `mapped_innovation_item`: an existing `.INNOVATION_LOG.md` item covers the
  gap; add a source note to that item or append a linked continuation.
- `new_innovation_item`: append a new numbered item to `.INNOVATION_LOG.md`
  with invariant/proof gap, Rust module, formal model, deterministic fixtures,
  and commercial unlock.
- `attack_ledger_update`: mutate the appropriate campaign, candidate, bounty,
  or low-yield ledger with a machine-readable reason.

## Output Contract

For each processed article append a sequential finding to `.INNOVATION_LOG.md`
with:

- URL.
- Access evidence.
- Corroborating sources.
- Disposition.
- Confidence.
- Source-quality score.
- Janitor module or ledger touched.
- Follow-up search concept.

If no ledger mutation is justified, state `ledger_update: none` in the appended
finding. Never pretend a URL was read. Abort the item if access fails and record
the failure as source quality 1.
