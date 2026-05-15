//! P2-27 Unauthenticated Debug API Endpoint Detector.
//!
//! Detects route registrations for debug/diagnostic/actuator paths in Python,
//! Java, JavaScript/TypeScript, and Go that lack an authentication middleware
//! or annotation within ±15 lines.  A debug endpoint with no auth gate is
//! directly exploitable for CVSS 9.8+ information disclosure, remote code
//! execution (Spring Actuator → heapdump/loggers), and privilege escalation.
//!
//! # Detection model
//!
//! 1. **Route sink**: any route registration containing a debug-path segment —
//!    `/debug/`, `/actuator/`, `/diagnostic/`, `/devops/`, `/inspect/`,
//!    `debug=True`, `app.run(debug`.
//! 2. **Auth suppressor**: within ±15 lines, any of `@login_required`,
//!    `@Secured`, `@PreAuthorize`, `require_auth`, `authenticate(`,
//!    `auth_required`, `@authenticated`, `middleware.auth`, `is_authenticated`
//!    must appear.
//! 3. If a route sink appears without a suppressor → emit
//!    `security:unauthenticated_debug_endpoint` at KevCritical.
//!
//! # Kani predicate
//!
//! `debug_endpoint_missing_auth(has_debug_route, has_auth_middleware)` is a
//! pure boolean predicate suitable for formal verification.  The Kani harness
//! in `reflexive_assurance.rs` proves it is an exact conjunction.

use aho_corasick::{AhoCorasick, MatchKind};
use common::slop::StructuredFinding;

// ── Pattern tables ────────────────────────────────────────────────────────────

const DEBUG_ROUTE_SINKS: &[&str] = &[
    "/debug/",
    "/actuator/",
    "/diagnostic/",
    "/devops/",
    "/inspect/",
    "debug=True",
    "app.run(debug",
    "/_debug",
    "/admin/debug",
    "/health/debug",
];

const AUTH_SUPPRESSORS: &[&str] = &[
    "@login_required",
    "@Secured",
    "@PreAuthorize",
    "require_auth",
    "authenticate(",
    "auth_required",
    "@authenticated",
    "middleware.auth",
    "is_authenticated",
    "check_auth",
    "verify_token",
    "require_permission",
    "@require_http_auth",
    "BasicAuth",
    "BearerAuth",
];

// ── Pure predicate (Kani-provable) ────────────────────────────────────────────

/// Returns `true` when a debug route is registered without an auth middleware
/// suppressor — the core unauthenticated-endpoint invariant.
///
/// Extracted as a pure predicate so `reflexive_assurance.rs` can prove it is
/// an exact conjunction under all possible boolean inputs.
pub fn debug_endpoint_missing_auth(has_debug_route: bool, has_auth_middleware: bool) -> bool {
    has_debug_route && !has_auth_middleware
}

// ── Source extractor ──────────────────────────────────────────────────────────

/// Scan `source` for debug route registrations.  For each match, check whether
/// an auth suppressor appears within `window` lines.  Returns 1-indexed line
/// numbers where unguarded debug routes occur.
fn find_unguarded_debug_routes(source: &str, window: usize) -> Vec<u32> {
    let sink_ac = AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostFirst)
        .build(DEBUG_ROUTE_SINKS)
        .expect("static DEBUG_ROUTE_SINKS are valid patterns");
    let supp_ac = AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostFirst)
        .build(AUTH_SUPPRESSORS)
        .expect("static AUTH_SUPPRESSORS are valid patterns");

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

/// Scan `source` (full content of file at `file`) for unauthenticated debug
/// route registrations.  Returns one `StructuredFinding` per violation.
pub fn emit_debug_endpoint_findings(source: &str, file: &str) -> Vec<StructuredFinding> {
    find_unguarded_debug_routes(source, 15)
        .into_iter()
        .map(|line_no| StructuredFinding {
            id: "security:unauthenticated_debug_endpoint".to_string(),
            severity: Some("KevCritical".to_string()),
            file: Some(file.to_string()),
            line: Some(line_no),
            remediation: Some(
                "Debug/actuator route registered without authentication middleware. \
Add `@login_required` (Flask), `@Secured` / `@PreAuthorize` (Spring), or an \
equivalent auth guard immediately before or on the handler. For Spring Actuator, \
set `management.endpoints.web.exposure.include` to an explicit allowlist and \
require ROLE_ACTUATOR. Without a gate, any unauthenticated caller can reach \
heap dumps, log levels, env vars, and thread info."
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
    fn predicate_fires_only_when_route_without_auth() {
        assert!(debug_endpoint_missing_auth(true, false));
        assert!(!debug_endpoint_missing_auth(true, true));
        assert!(!debug_endpoint_missing_auth(false, false));
        assert!(!debug_endpoint_missing_auth(false, true));
    }

    // ── TP: Flask debug route without @login_required → finding emitted ───────
    #[test]
    fn tp_flask_debug_route_no_auth() {
        let src = r#"
from flask import Flask
app = Flask(__name__)

@app.route('/debug/method')
def debug_method():
    return {"heap": get_heap_snapshot()}
"#;
        let findings = emit_debug_endpoint_findings(src, "app.py");
        assert_eq!(findings.len(), 1, "must emit exactly one finding");
        assert_eq!(findings[0].id, "security:unauthenticated_debug_endpoint");
        assert_eq!(findings[0].severity.as_deref(), Some("KevCritical"));
        assert_eq!(findings[0].line, Some(5));
    }

    // ── TN: Flask debug route with @login_required → no finding ──────────────
    #[test]
    fn tn_flask_debug_route_with_login_required() {
        let src = r#"
from flask import Flask
from flask_login import login_required
app = Flask(__name__)

@login_required
@app.route('/debug/method')
def debug_method():
    return {"heap": get_heap_snapshot()}
"#;
        let findings = emit_debug_endpoint_findings(src, "app.py");
        assert!(
            findings.is_empty(),
            "guarded route must not produce a finding"
        );
    }

    // ── TP: Spring Actuator endpoint without @PreAuthorize ────────────────────
    #[test]
    fn tp_spring_actuator_no_preauthorize() {
        let src = r#"
@RestController
@RequestMapping("/actuator/")
public class ActuatorController {
    @GetMapping("/heapdump")
    public ResponseEntity<byte[]> heapdump() {
        return heapDumpService.dump();
    }
}
"#;
        let findings = emit_debug_endpoint_findings(src, "ActuatorController.java");
        assert!(
            !findings.is_empty(),
            "actuator route without auth must fire"
        );
        assert_eq!(findings[0].id, "security:unauthenticated_debug_endpoint");
    }

    // ── TN: Spring endpoint with @Secured ─────────────────────────────────────
    #[test]
    fn tn_spring_actuator_with_secured() {
        let src = r#"
@RestController
@Secured("ROLE_ACTUATOR")
@RequestMapping("/actuator/")
public class ActuatorController {
    @GetMapping("/heapdump")
    public ResponseEntity<byte[]> heapdump() {
        return heapDumpService.dump();
    }
}
"#;
        let findings = emit_debug_endpoint_findings(src, "ActuatorController.java");
        assert!(
            findings.is_empty(),
            "@Secured must suppress actuator finding"
        );
    }

    // ── TP: debug=True in app.run() ────────────────────────────────────────────
    #[test]
    fn tp_flask_debug_true_run() {
        let src = r#"
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
"#;
        let findings = emit_debug_endpoint_findings(src, "server.py");
        assert!(!findings.is_empty(), "app.run(debug=True) must fire");
    }

    // ── TN: non-debug route → no finding ──────────────────────────────────────
    #[test]
    fn tn_normal_route_not_flagged() {
        let src = r#"
@app.route('/api/v1/users')
def list_users():
    return jsonify(User.query.all())
"#;
        let findings = emit_debug_endpoint_findings(src, "api.py");
        assert!(
            findings.is_empty(),
            "normal route must not trigger debug guard"
        );
    }

    // ── TP: suppressor outside window still fires ─────────────────────────────
    #[test]
    fn tp_auth_outside_window_still_fires() {
        let mut src = String::from("@login_required\ndef unrelated():\n    pass\n");
        for _ in 0..20 {
            src.push('\n');
        }
        src.push_str("@app.route('/debug/trace')\ndef trace():\n    return debug_info()\n");
        let findings = emit_debug_endpoint_findings(&src, "views.py");
        assert!(
            !findings.is_empty(),
            "auth suppressor >15 lines away must not block the finding"
        );
    }

    // ── TN: authenticate( suppressor near route ───────────────────────────────
    #[test]
    fn tn_authenticate_call_near_route() {
        let src = r#"
def diagnostic_view(request):
    authenticate(request)
    if request.path.startswith('/diagnostic/'):
        return DiagnosticResponse()
"#;
        let findings = emit_debug_endpoint_findings(src, "views.py");
        assert!(
            findings.is_empty(),
            "authenticate( within window must suppress"
        );
    }
}
