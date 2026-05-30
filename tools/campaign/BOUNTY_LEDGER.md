# Bounty Ledger

Weaponized findings from `janitor hunt` campaigns, cross-referenced against
program scope and severity tiers. Only findings with a concrete `repro_cmd`,
reproduction payload, or generated HTML harness are entered.

Threat Model Awareness law applied: client-side `fetch()`/XHR calls are NOT
server-side SSRF. This ledger is reserved strictly for submission-ready
findings with `Approval % >= 85`.

## Submission Status Annotation Schema (Sprint 139)

Every row in this ledger MUST be preceded by an HTML comment in the canonical
form below so `.agent_governance/rules/cvp_red_team.md` triage protocol has a
stable parser target. The same schema applies to `CANDIDATE_LEDGER.md` rows
that have been routed toward submission attempts.

```
<!-- submission_status: NOT_SUBMITTED -->
<!-- submission_status: SUBMITTED_YYYY-MM-DD -->
<!-- submission_status: ACCEPTED -->
<!-- submission_status: REJECTED_<one-word-reason> -->
<!-- submission_status: DUPLICATE -->
<!-- submission_status: PAID_<amount_USD> -->
```

A row without any `submission_status` comment is treated as `NOT_SUBMITTED`
by the triage engine and flagged as the highest-EV operator action.

| Date | Target Repo | Vulnerability Class | Severity | Expected Payout | Approval % | Exact Repro Command | Exploitation Strategy |
|------|-------------|---------------------|----------|-----------------|------------|---------------------|-----------------------|
