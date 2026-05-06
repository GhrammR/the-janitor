# Bounty Ledger

Weaponized findings from `janitor hunt` campaigns, cross-referenced against
program scope and severity tiers. Only findings with a concrete `repro_cmd`,
reproduction payload, or generated HTML harness are entered.

Threat Model Awareness law applied: client-side `fetch()`/XHR calls are NOT
server-side SSRF. Entries with `Approval % < 10%` must include an Exploitation
Strategy or be deleted.

| Date | Target Repo | Vulnerability Class | Severity | Expected Payout | Approval % | Exact Repro Command | Exploitation Strategy |
|------|-------------|---------------------|----------|-----------------|------------|---------------------|-----------------------|
| 2026-05-01 | mattermost/mattermost-plugin-boards | Stored XSS via dangerouslySetInnerHTML — block editor ×9 components | P2/Severe | $500–$1500 | 70% | Create board block with payload `<img src=x onerror=alert(document.cookie)>` via boards API; payload renders in victim browser | Stored XSS: content submitted by one user renders in another user's browser via `dangerouslySetInnerHTML` in block editor. No admin required — any board member can inject. |
| 2026-05-01 | mattermost/mattermost-plugin-boards | DOM XSS — webapp/src/utils.ts:143 | P2/Severe | $500–$1000 | 55% | HTML harness — `python3 -m http.server 8765` | Utility `innerHTML` assignment — elevation path: trace whether this is called from a route handler processing user-supplied channel/board names. Mattermost channel names allow special characters; confirm end-to-end taint from channel name → utils.ts:143. |
| 2026-05-01 | ClickHouse/ClickHouse | Unsafe string function — src/Functions/printf.cpp (×6 sprintf calls in SQL printf implementation) | P3/Medium | $100–$600 | 25% | Build ClickHouse from source with ASAN; execute SQL `SELECT printf('%s', repeat('A', 65536))` against a local test instance; observe ASAN stack trace | Printf SQL function passes user-supplied format operands through internal C++ buffer via `sprintf`; elevation path: identify whether a printf operand can overflow the intermediate formatting buffer without bounds check. Confirm with ASAN build — must show stack-smashing or buffer overflow in `src/Functions/printf.cpp`. [lattice-gap: P1-8] |
| 2026-05-01 | ClickHouse/ClickHouse | Raw pointer dereference — rust/workspace/prql/src/lib.rs (FFI boundary) | P4/Low | $50–$100 | 15% | Run `cargo test` in `rust/workspace/prql/` with MIRI enabled; observe UB on pointer deref | Rust PRQL workspace contains raw pointer deref at FFI boundary; elevation: demonstrate attacker-controlled SQL PRQL expression triggers the unsafe deref path. Requires PRQL feature flag enabled in ClickHouse build. [lattice-gap: P1-8] |
| 2026-05-02 | openai/codex | Intent Divergence — codex-rs/model-provider/src/auth.rs:58 UnauthenticatedAuthProvider skips all auth headers | P3/Medium | $500–$2000 | 40% | `grep -n UnauthenticatedAuthProvider /tmp/sprint94_codex/codex-rs/model-provider/src/auth.rs`; confirm reachable via non-test `ModelProviderInfo` with `requires_openai_auth = false` | `UnauthenticatedAuthProvider::add_auth_headers` sends NO Authorization headers; elevation: identify whether a user-configured `modelProvider` with `requires_openai_auth = false` can route requests through an attacker-controlled endpoint receiving unguarded API calls. If Codex forwards sensitive context (codebase content) to an unauthenticated endpoint by design, this may be a data exfiltration misconfiguration. |
| 2026-05-05 | auth0/auth0.js | Re-evaluation (Sprint 103) — no new findings from engine upgrades; existing DOM XSS entries unchanged; swarm_exfil detector: no markers found | — | — | — | Re-scan with v10.2.0-rc.1 engine (P6-9 swarm_exfil Phase A added). No changes to existing ledger entries. Schema Taint Verification ceiling still applies to captcha.js and username-password.js entries. | No new exploitation pathways identified. |
| 2026-05-05 | openai/codex | Re-evaluation (Sprint 103) — UnauthenticatedAuthProvider finding confirmed present in current HEAD | P3/Medium | $500–$2000 | 40% | `grep -n UnauthenticatedAuthProvider /tmp/codex/codex-rs/model-provider/src/auth.rs` | No change. Finding persists in current HEAD. P1-3 Command Execution witnesses do not apply (no command execution sink in this auth path). Approval ceiling same as prior sprint. |
| 2026-05-05 | smartcontractkit/chainlink | Unpinned asset / supply-chain drift — `deployment/ccip/shared/bindings/usd_stablecoin/usd_stablecoin_metadata.go:7` | Critical | up to $100,000 | 41% | `curl -fsSL "<remote-url>" -o /tmp/janitor_asset_probe && sha256sum /tmp/janitor_asset_probe` | Live-fire `janitor hunt --submit-check` generated `SUBMISSION_security_unpinned_asset.md`. Elevation path: prove the fetched artifact is mutable under a stable URL without checksum or immutable digest pinning; if upstream asset rotation is permitted, downstream builds silently ingest attacker-replaced bytes. |

## Triage Proxy — mattermost/mattermost-plugin-boards

### Stored XSS via dangerouslySetInnerHTML — block editor ×9 components

**Triage Defense:** This is not a generic markdown-rendering hypothesis; the taint path is concrete and persisted. The attacker-controlled parameter is the block editor `text` value submitted from the client editor. `mutator.changeBlockTitle(block.boardId, block.id, block.title, text, ...)` forwards that exact user-supplied `text` into `octoClient.patchBlock(boardId, blockId, {title: newTitle})`, which issues `PATCH /api/v2/boards/{boardId}/blocks/{blockId}` and stores the payload as the block `title`. On subsequent renders, multiple display components convert that stored `title` back into HTML with `Utils.htmlFromMarkdown(...)` and inject it through React `dangerouslySetInnerHTML`, including the board text renderer and the board unfurl flow after `getBlocksWithBlockID(...)` reloads the content. The sink is therefore linked to a specific Mattermost API parameter (`title` on the block patch request), not merely to local UI state. Any board member capable of editing a block can persist a payload that renders in another viewer’s browser.

### DOM XSS — webapp/src/utils.ts:143

**Triage Defense:** The original ledger row references a generic DOM helper, but current HEAD no longer proves an end-to-end attacker-controlled call into that helper from static analysis alone. The only surviving helper-shaped sink is `Utils.htmlToElement(html)`, and it is presently not called anywhere in the checked tree. That means the finding is not submission-grade on code shape alone. The remaining triage question is whether a runtime-only reflection path still feeds attacker-controlled board or channel content into an equivalent HTML helper after bundling or plugin composition. Until that reflection is observed, the approval ceiling should stay below direct-submission threshold.

**Interrogation Script:** Run the following Node script against a local Mattermost + Boards instance. It uses the same API family the client already uses to write `board.description`, plants a deterministic canary, and prints the exact manual check needed to confirm or falsify reflection in the rendered UI.

```js
#!/usr/bin/env node
const baseUrl = process.env.MM_BASE_URL;
const token = process.env.MM_TOKEN;
const boardId = process.env.MM_BOARD_ID;

if (!baseUrl || !token || !boardId) {
  console.error("Set MM_BASE_URL, MM_TOKEN, and MM_BOARD_ID.");
  process.exit(1);
}

const canary = 'JANITOR_CANARY_<img src=x onerror=console.log("JANITOR_DOM_XSS")>';

async function patchBoardDescription() {
  const response = await fetch(
    `${baseUrl.replace(/\\/$/, "")}/plugins/focalboard/api/v2/boards/${boardId}`,
    {
      method: "PATCH",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({description: canary}),
    },
  );

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`PATCH failed: ${response.status} ${body}`);
  }

  const body = await response.json();
  console.log("Stored description:", body.description);
  console.log(
    `Open ${baseUrl.replace(/\\/$/, "")}/boards/${boardId} and any RHS/preview surface that renders the board description. ` +
      "If the literal canary is converted into a live <img> node or executes the onerror handler, the reflection path is confirmed."
  );
}

patchBoardDescription().catch((error) => {
  console.error(error);
  process.exit(1);
});
```
