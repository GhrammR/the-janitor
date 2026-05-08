# Bounty Ledger

Weaponized findings from `janitor hunt` campaigns, cross-referenced against
program scope and severity tiers. Only findings with a concrete `repro_cmd`,
reproduction payload, or generated HTML harness are entered.

Threat Model Awareness law applied: client-side `fetch()`/XHR calls are NOT
server-side SSRF. This ledger is reserved strictly for submission-ready
findings with `Approval % >= 85`.

| Date | Target Repo | Vulnerability Class | Severity | Expected Payout | Approval % | Exact Repro Command | Exploitation Strategy |
|------|-------------|---------------------|----------|-----------------|------------|---------------------|-----------------------|
| 2026-05-08 | https://github.com/mattermost/mattermost-plugin-boards | security:react_xss_dangerous_html — 9 dangerouslySetInnerHTML sinks across block editor components (`webapp/src/components/blocksEditor/blocks/checkbox/index.tsx`, `text/index.tsx`, `h1/index.tsx`, `h2/index.tsx`, `h3/index.tsx`, `quote/index.tsx`, `text-dev/index.tsx`, `rhsChannelBoardItem.tsx`, `boardsUnfurl.tsx`) | P2/Severe | $500–$1500 | 87% | P2-5 dual-frame harness: Frame 1 (attacker): `fetch('/api/save', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({content: '<img src=x data-janitor-witness="blake3:probe" onerror="document.title=JANITOR_XSS_CANARY">'})})` → Frame 2 (victim): visit board endpoint; observe `document.title === 'JANITOR_XSS_CANARY'` | Create board card with XSS payload via REST API; any user viewing the board card triggers the stored payload. Block editor renders `dangerouslySetInnerHTML={{__html: html}}` from database-stored markdown without DOMPurify sanitization. Autonomous repro: dual-frame HTML harness with JANITOR_XSS_CANARY canary token and `data-janitor-witness` non-repudiation attribute; `schema_taint:proven stored:cross_user_render` evidence marker set. Promoted from CANDIDATE by P2-5 witness pack. |
