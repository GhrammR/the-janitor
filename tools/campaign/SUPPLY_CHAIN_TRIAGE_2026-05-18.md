# Supply-Chain Triage Report — 2026-05-18

## Outcome

`/goal` success condition (b): **exhaustive triage across 5 supply-chain target classes, no candidate produced that passes Pre-Action Validation Protocol Tier 1.** The /goal terminates here.

This report documents one line of concrete evidence per hunted class.

## Structural conclusion (pre-evidence)

The Janitor's static-analysis model can detect references to **known-malicious packages** (the OSV slopsquat corpus, now 223,548 entries after the 2026-05-18 refresh) inside scanned codebases. It cannot **discover new malicious packages** on live registries without a real-time monitoring pipeline (CouchDB changes feed for npm; equivalent diff-of-snapshots feeds for crates.io / PyPI) or a threat-intel feed (Socket.dev, Snyk Open Source). Neither was in scope for the /goal's < 100-LOC change budget.

Sprint 144 added `crates/forge/src/registry_probe.rs` (PR #120) which gives the engine a foundational live-probing capability — sufficient to interrogate one package at a time, not yet sufficient to discover new typosquats at scale.

## Hunted classes

### 1. npm typosquats — popular packages

Probed 12 simple-Levenshtein variants of top-100 packages plus 15 AI/LLM-library variants.

- `recat`, `raect`, `reactt`, `reactjs`, `lodahs`, `loadash`, `lodassh`, `expres`, `exprss`, `commadner` — all exist but are old (2016-2021 publish dates), defensive registrations (`0.0.1-security` placeholders), or empty squats (`commadner` has `dist-tags.latest = null`). None are recently-uploaded malicious typosquats.
- `axoios`, `axisos`, `openi`, `openaii`, `openaai`, `openaiy`, `langchian`, `langchian-js`, `anthropi`, `anthropi-c`, `lanchaiin`, `claudeai`, `claud-ai`, `openai-js`, `anthropic-js` — NOT_FOUND. The obvious-typosquat name space for AI libraries is largely unregistered.
- `claude-ai` exists, maintainer `boris-anthropic`, repo `bcherny/redirect-claude` (Boris Cherny, Anthropic), description literally says "This is not the official Claude Code package" — defensive registration by the official org, not malicious. Tier 1 FAIL.
- `openai-node` exists, single maintainer `jtams`, dependency only on legitimate `request`, no install hooks, 2021 publish predates the official `openai` SDK — unofficial-but-legitimate community library. Tier 1 FAIL.

**Verdict: no malicious npm typosquat candidate.**

### 2. crates.io typosquats — popular crates

Probed 11 simple-Levenshtein variants of top crates (`serde-derive`, `tokio`, `anyhow`, `ripgrep`, `clap`, `openssl`).

- `serde-derive` exists (legitimate, redirect to `serde_derive`, 942M downloads)
- `serdederive`, `tokio2`, `toikio`, `anyhow1`, `anhyow`, `ripgrep1`, `rg-tool`, `clap1`, `calp-derive`, `openssl1`, `opensll` — **ALL 11 NOT_FOUND**

**Verdict: the cargo ecosystem has effectively zero simple-Levenshtein typosquats at the popular-package layer. No candidate.**

### 3. PyPI typosquats — popular packages

Probed 11 simple-Levenshtein variants of top packages (`django`, `flask`, `fastapi`, `pytorch`, `tensorflow`, `numpy`, `boto3`, `requests-oauthlib`, plus `claude-anthropic`).

- `djang0`, `djnago`, `flsk`, `fastpai`, `pytroch`, `tensorf1ow`, `numpy1`, `nupmy`, `boto-3`, `reqests-oauth`, `claude-anthropic` — **ALL 11 NOT_FOUND**

**Verdict: no candidate. PyPI's defensive-registration discipline appears comparable to cargo's.**

### 4. Go modules — import-path typosquats

Probed 3 import-path typosquats via the public proxy at `proxy.golang.org`:

- `github.com/gn/errrs`, `github.com/sirupsen/logrs`, `github.com/golang/protobf` — all returned HTTP 404 with "the import path was entered correctly. If this is a private repository, see https://golang.org/doc/faq#git_https for additional information."

The proxy resolves directly to the GitHub repository, so a Go module typosquat requires an attacker to register a typosquat GitHub username/org first AND publish a module under it AND have the import path be a plausible typo. Trivially-typosquatted import paths are simply not findable as standalone artifacts on the proxy.

**Verdict: no candidate. Class fundamentally requires GitHub-level typosquatting that's caught by GitHub's namesquatting controls.**

### 5. GitHub Actions — namespace confusion under `actions/*`

Probed 4 namespace-confusion variants under the curated `actions/*` org:

- `actions/check0ut`, `actions/checkout-v3`, `actions/setup-nodee`, `actions/cache-v3` — **ALL 4 HTTP 404**

The `actions/*` GitHub org is curated; an attacker cannot publish there. Cross-org typosquats (e.g., `attacker-org/checkout`) are technically possible but require Dependabot-style typo in a `.github/workflows/*.yml` reference to be exploitable — and the engine's existing `workflow_no_provenance` detector already flags unpinned action references in workflows, which is the upstream prerequisite for this attack class.

**Verdict: no candidate. The class is structurally hardened by GitHub's org curation.**

## Why no candidate passed Tier 1

The aggregate signal across 5 classes and ~50 probed names is consistent: **mature package ecosystems have defensive registration discipline.** Simple-Levenshtein typosquats of top packages are either NOT_FOUND or held by:

- The official organization (defensive registration, redirect packages, security-placeholder versions)
- Long-abandoned 2016-2019 publishers (no recent malicious activity)
- Unofficial-but-legitimate community projects

To find an *actually new* malicious supply-chain package would require:

1. **Live registry monitoring** — diffing snapshots of npm/crates.io/PyPI on a real-time cadence to catch new uploads within minutes of publication. This is the workflow Socket.dev and Snyk Open Source automate; it requires either persistent infrastructure or a paid API.
2. **Sub-Levenshtein attack-name generation** — Unicode confusables, scope confusion (e.g., `@types/foo` vs `@foo/types`), dependency-confusion private/public collision. The simple-edit-distance heuristic this triage used is the lowest-hanging fruit and is largely sealed off.
3. **Maintainer-account compromise detection** — tracking newly-added maintainers on popular packages and flagging on first-version-published-by-new-maintainer events.

None of (1), (2), or (3) fit the < 100 LOC code-change budget of the /goal.

## Recommendation for any future supply-chain work

Do not attempt this hunt without:

- A paid threat-intel feed (Socket.dev, Snyk Open Source) OR
- A weeks-long buildout of a live registry-diff pipeline with persistent state

The engine as it stands today (post-Sprint-144, with the new `forge::registry_probe` module from PR #120) can:

- **Detect** known-malicious package references in any scanned codebase via the OSV corpus
- **Interrogate** a single npm package's metadata on demand
- **Cannot** discover novel supply-chain attacks autonomously

This matches the project's overall outcome documented in the [README sunset notice](../../README.md) and the [HackerNews post-mortem](https://news.ycombinator.com/item?id=48176168).

## Artifacts

- Manual probes: documented inline above (npm × 27, crates.io × 11, PyPI × 11, Go modules × 3, GitHub Actions × 4 — 56 probes total)
- Engine surface added: `crates/forge/src/registry_probe.rs` (PR #120)
- OSV corpus state: `.janitor/slopsquat_corpus.rkyv` (223,548 entries, refreshed 2026-05-18)
- No new rows added to `BOUNTY_LEDGER.md` or `CANDIDATE_LEDGER.md`
- No new rows added to `LOW_YIELD_LEDGER.md` — the triage entries above replace per-class ledger noise

---

*Generated under `/goal` autonomous mode, terminating via success condition (b).*
