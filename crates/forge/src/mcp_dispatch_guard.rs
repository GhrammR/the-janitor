//! P2-24 MCP Confused-Deputy Tool-Dispatch Detector.
//!
//! Detects MCP (Model Context Protocol) server implementations that route
//! tool-call dispatch by a caller-supplied `id` without binding the call to
//! a per-session secret.  A multi-tenant MCP server with this gap is
//! vulnerable to a confused-deputy attack: a malicious agent injects a
//! `tools/call` frame whose `id` resolves to a victim session's context,
//! executing tools under the victim's grant list.
//!
//! # Detection model
//!
//! 1. **Dispatch sink**: any session-resolution call — `sessions.get(`,
//!    `session_map.get(`, `handlers.get(`, `clients.get(`,
//!    `connections.get(`.
//! 2. **Suppressor**: within ±10 lines of the resolution call, any of
//!    `secret`, `hmac`, `verify`, `authenticate`, `token_check`,
//!    `validate_session` must appear.
//! 3. If a dispatch sink appears without a suppressor in the surrounding
//!    window → emit `security:mcp_confused_deputy_dispatch`.
//!
//! # Kani predicate
//!
//! `session_dispatch_missing_secret_check(has_dispatch, has_secret_verify)`
//! is a pure boolean predicate suitable for formal verification.  The Kani
//! harness in `reflexive_assurance.rs` proves it is an exact conjunction.

use aho_corasick::{AhoCorasick, MatchKind};
use common::slop::StructuredFinding;

// ── Pattern tables ────────────────────────────────────────────────────────────

const DISPATCH_SINKS: &[&str] = &[
    "sessions.get(",
    "session_map.get(",
    "handlers.get(",
    "clients.get(",
    "connections.get(",
    "session_store.get(",
    "active_sessions.get(",
    "peer_map.get(",
];

const SECRET_SUPPRESSORS: &[&str] = &[
    "secret",
    ".hmac(",
    "hmac::",
    "verify_session",
    "validate_session",
    "authenticate(",
    "token_check",
    "session_token",
    "check_auth",
    "assert_authorized",
];

// ── Pure predicate (Kani-provable) ────────────────────────────────────────────

/// Returns `true` when a session dispatch site lacks a secret-verification
/// suppressor — the core confused-deputy invariant.
///
/// This function is deliberately extracted as a pure predicate so that
/// `reflexive_assurance.rs` can prove it is an exact conjunction under all
/// possible boolean inputs without requiring the full AhoCorasick machinery.
pub fn session_dispatch_missing_secret_check(has_dispatch: bool, has_secret_verify: bool) -> bool {
    has_dispatch && !has_secret_verify
}

// ── Source extractor ──────────────────────────────────────────────────────────

/// Scan `source` for MCP session-dispatch sinks.  For each sink, check
/// whether a secret-verification suppressor appears within `window` lines.
/// Returns a vec of 1-indexed line numbers where the unguarded dispatch occurs.
fn find_unguarded_dispatch_lines(source: &str, window: usize) -> Vec<u32> {
    let sink_ac = AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostFirst)
        .build(DISPATCH_SINKS)
        .expect("static DISPATCH_SINKS are valid patterns");
    let supp_ac = AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostFirst)
        .build(SECRET_SUPPRESSORS)
        .expect("static SECRET_SUPPRESSORS are valid patterns");

    let lines: Vec<&str> = source.lines().collect();
    let mut hits: Vec<u32> = Vec::new();

    for (line_idx, line) in lines.iter().enumerate() {
        if sink_ac.is_match(line) {
            let lo = line_idx.saturating_sub(window);
            let hi = (line_idx + window + 1).min(lines.len());
            let window_text = lines[lo..hi].join("\n");
            if !supp_ac.is_match(&window_text) {
                hits.push(line_idx as u32 + 1); // 1-indexed
            }
        }
    }
    hits
}

// ── Finding emitter ───────────────────────────────────────────────────────────

/// Scan `source` (the full content of a file at `file`) for unguarded MCP
/// session-dispatch patterns.  Returns one `StructuredFinding` per violation.
pub fn emit_mcp_confused_deputy_findings(source: &str, file: &str) -> Vec<StructuredFinding> {
    find_unguarded_dispatch_lines(source, 10)
        .into_iter()
        .map(|line_no| StructuredFinding {
            id: "security:mcp_confused_deputy_dispatch".to_string(),
            severity: Some("KevCritical".to_string()),
            file: Some(file.to_string()),
            line: Some(line_no),
            remediation: Some(
                "MCP session dispatch resolves by caller-supplied id without \
per-call secret verification. Add a HMAC or session-secret check immediately \
after session lookup: `sessions.get(req.id).filter(|s| verify(s.secret, \
req.presented_secret))`. Without this guard, any connected agent can execute \
tools in another tenant's session context (confused deputy)."
                    .to_string(),
            ),
            ..Default::default()
        })
        .collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Pure predicate ────────────────────────────────────────────────────────

    #[test]
    fn predicate_fires_only_when_dispatch_without_verify() {
        assert!(session_dispatch_missing_secret_check(true, false));
        assert!(!session_dispatch_missing_secret_check(true, true));
        assert!(!session_dispatch_missing_secret_check(false, false));
        assert!(!session_dispatch_missing_secret_check(false, true));
    }

    // ── TP: unguarded sessions.get() → finding emitted ───────────────────────
    #[test]
    fn tp_unguarded_session_get_emits_finding() {
        let src = r#"
async fn handle_tool_call(req: ToolRequest) -> ToolResponse {
    let session = sessions.get(req.id).expect("session not found");
    session.invoke(req.tool, req.args).await
}
"#;
        let findings = emit_mcp_confused_deputy_findings(src, "server.rs");
        assert_eq!(findings.len(), 1, "must emit exactly one finding");
        assert_eq!(findings[0].id, "security:mcp_confused_deputy_dispatch");
        assert_eq!(findings[0].severity.as_deref(), Some("KevCritical"));
        assert_eq!(findings[0].line, Some(3));
    }

    // ── TN: sessions.get() guarded by secret verify → no finding ─────────────
    #[test]
    fn tn_guarded_session_get_no_finding() {
        let src = r#"
async fn handle_tool_call(req: ToolRequest) -> ToolResponse {
    let session = sessions.get(req.id)
        .filter(|s| verify_session(s.secret, &req.presented_secret))
        .expect("unauthorized");
    session.invoke(req.tool, req.args).await
}
"#;
        let findings = emit_mcp_confused_deputy_findings(src, "server.rs");
        assert!(
            findings.is_empty(),
            "guarded dispatch must not produce a finding"
        );
    }

    // ── TN: session_map.get() with hmac suppressor nearby ────────────────────
    #[test]
    fn tn_hmac_suppressor_within_window() {
        let src = r#"
fn dispatch(req: &Request, session_map: &SessionMap) -> Result<()> {
    let token = req.auth_token.as_deref().ok_or(Error::Unauthorized)?;
    let hmac_ok = hmac::verify(token, &session_map.signing_key);
    ensure!(hmac_ok, "invalid session token");
    let sess = session_map.get(req.session_id);
    sess.run(req.method)
}
"#;
        let findings = emit_mcp_confused_deputy_findings(src, "dispatch.rs");
        assert!(
            findings.is_empty(),
            "hmac suppressor must silence the finding"
        );
    }

    // ── TP: multiple unguarded sinks → one finding per line ──────────────────
    #[test]
    fn tp_multiple_sinks_emit_multiple_findings() {
        let src = r#"
fn route(req: &Req) {
    let a = sessions.get(req.a);
    let b = handlers.get(req.b);
    let c = clients.get(req.c);
}
"#;
        let findings = emit_mcp_confused_deputy_findings(src, "router.rs");
        assert_eq!(findings.len(), 3, "three unguarded sinks → three findings");
    }

    // ── TN: non-MCP code with .get() on unrelated maps → no finding ──────────
    #[test]
    fn tn_unrelated_map_get_not_flagged() {
        let src = r#"
fn load_config(cfg_map: &HashMap<String, Value>, key: &str) -> Option<&Value> {
    cfg_map.get(key)
}
fn fetch_user(users: &HashMap<u64, User>, uid: u64) -> Option<&User> {
    users.get(&uid)
}
"#;
        let findings = emit_mcp_confused_deputy_findings(src, "config.rs");
        assert!(
            findings.is_empty(),
            "generic HashMap::get calls must not trigger MCP guard"
        );
    }

    // ── TP: authenticate suppressor outside window → still fires ─────────────
    #[test]
    fn tp_suppressor_outside_window_still_fires() {
        let mut src = String::from("fn prelude() {\n    authenticate(ctx);\n}\n");
        // Add 15 blank lines to push the suppressor outside the ±10 window.
        for _ in 0..15 {
            src.push('\n');
        }
        src.push_str("fn dispatch(req: Req) {\n    let s = sessions.get(req.id);\n}\n");
        let findings = emit_mcp_confused_deputy_findings(&src, "far_apart.rs");
        assert!(
            !findings.is_empty(),
            "suppressor >10 lines away must not block the finding"
        );
    }
}
