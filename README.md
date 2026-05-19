# The Janitor

> **Status: features and support end 2026-06-01.** No new releases, no
> issue triage, no PR review, and no further development after that
> date. See the [HackerNews post-mortem](https://news.ycombinator.com/item?id=48176168)
> for the long-form explanation.

## What this is

An AI-assisted static-analysis engine built in Rust over four months as
a solo experiment to test whether current AI tooling could produce a
viable vulnerability scanner. The validation test was a single confirmed
bug-bounty payout. The validation test was not passed.

- 128,504 lines of Rust across 15 workspace crates
- 1,407 deterministic unit tests
- 15 tagged release builds
- 194 bug-bounty programs hunted across Bugcrowd, HackerOne, Immunefi
- 91 false positives archived in the LOW_YIELD ledger
- 7 active candidate findings, none Tier-1 validated, all sub-$1K EV
- 0 paid bounties

## What actually happened

The engine reliably produced findings that looked like vulnerabilities
and reliably did not produce findings that were vulnerabilities. Seven
of the highest-confidence candidates over the project's life failed
Tier-1 static validation under approximately 20 minutes of human review
per finding. The upstream detectors matched syntactic patterns but did
not reason about surrounding context: auth decorators, sanitizer
helpers, type bindings, scope rules, deprecation status, threat models,
framework-specific auth idioms, or maintainer suppression annotations.

Three structural detector modules (`forge::threat_model_oracle`,
`forge::jwt_keyfunc_oracle`, `forge::sql_sanitizer_oracle`) shipped in
the final two weeks to catch those false-positive classes structurally.
They catch what they were built to catch. They did not surface a new
finding that turned into a paid bounty.

## Sunset terms

| Item | Status after 2026-06-01 |
| --- | --- |
| New releases | None planned |
| Issue triage | None |
| PR review | None |
| Feature requests | Not accepted |
| Security reports | Not triaged — please report to upstream targets directly |
| GitHub Action Marketplace listing | Being delisted |
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
