# Bounty Ledger

Weaponized findings from `janitor hunt` campaigns, cross-referenced against
program scope and severity tiers. Only findings with a concrete `repro_cmd`,
reproduction payload, or generated HTML harness are entered.

Threat Model Awareness law applied: client-side `fetch()`/XHR calls are NOT
server-side SSRF. This ledger is reserved strictly for submission-ready
findings with `Approval % >= 85`.

| Date | Target Repo | Vulnerability Class | Severity | Expected Payout | Approval % | Exact Repro Command | Exploitation Strategy |
|------|-------------|---------------------|----------|-----------------|------------|---------------------|-----------------------|

_No current submission-ready findings. The previous mattermost-plugin-boards XSS row (87%, dated 2026-05-08) was demoted to LOW_YIELD on 2026-05-16: target deprecated to community-only status in late 2023, falls under scope file exclusion (informational only, no bounty). See `tools/campaign/CANDIDATE_LEDGER.md` for in-progress findings._
