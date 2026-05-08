//! # P1-17 — Service Mesh Confused Deputy Detection
//!
//! Detects cross-service authorization boundary confusion in Kubernetes service
//! meshes (Istio, Linkerd, Consul Connect) where a non-re-stamping
//! external-facing proxy enables transitive privilege escalation through
//! mesh-propagated identity headers.
//!
//! ## Threat Model
//!
//! 1. An external-facing service (Istio `Gateway`, Linkerd ingress `Server`,
//!    Consul `ingress` Listener) forwards traffic to an internal service.
//! 2. The internal service's `AuthorizationPolicy` / `Server` binding grants
//!    access based on the external service's mesh identity (SPIFFE SVID /
//!    `source.principals` / `MeshTLSAuthentication`).
//! 3. The external proxy does NOT re-stamp the identity (`X-Forwarded-Client-Cert`
//!    stripping absent, no SPIFFE workload API re-fetch).
//! 4. An attacker spoofs or leverages the external service's propagated identity
//!    to reach privileged paths (`/admin/*`, `/internal/*`, `/_management/*`).
//!
//! ## Detection Strategy
//!
//! Operates on unified-diff patch text.  Two AhoCorasick passes scan added lines:
//!
//! 1. **External-facing indicator**: Istio `Gateway`, Linkerd `Server` with
//!    `gateway.linkerd.io`, or Consul `ingress` listener kind — marks that a
//!    service is reachable from outside the mesh.
//! 2. **Authorization binding**: Istio `AuthorizationPolicy` with
//!    `source.principals`, Linkerd `Server` policy binding with
//!    `MeshTLSAuthentication`, or Consul `service-intentions` with `sources`.
//! 3. **Privileged path**: `/admin`, `/internal`, `/_management`, or
//!    `security: admin` annotation.
//! 4. **Re-stamping absent**: no `X-Forwarded-Client-Cert` header manipulation,
//!    no `clearOnForward` / `removeHeader` directive for the cert header.
//!
//! When an external gateway indicator AND a principal-based authorization binding
//! AND a privileged path appear in the same diff without a re-stamping guard,
//! the detector emits `security:service_mesh_confused_deputy` at `KevCritical`
//! with a curl-form AEG repro template.

use std::sync::OnceLock;

use aho_corasick::{AhoCorasick, AhoCorasickKind, MatchKind};

use crate::metadata::DOMAIN_ALL;
use crate::slop_hunter::{Severity, SlopFinding};

// ---------------------------------------------------------------------------
// AhoCorasick pattern groups
// ---------------------------------------------------------------------------

/// External-facing service indicators — signals the mesh perimeter boundary.
static EXTERNAL_INDICATOR_AC: OnceLock<AhoCorasick> = OnceLock::new();
/// Authorization binding patterns — mesh identity-based access control.
static AUTHZ_BINDING_AC: OnceLock<AhoCorasick> = OnceLock::new();
/// Privileged path patterns — high-value internal endpoints.
static PRIVILEGED_PATH_AC: OnceLock<AhoCorasick> = OnceLock::new();
/// Re-stamping guard patterns — signals the proxy strips and re-issues identity.
static RESTAMP_GUARD_AC: OnceLock<AhoCorasick> = OnceLock::new();

fn external_indicator_ac() -> &'static AhoCorasick {
    EXTERNAL_INDICATOR_AC.get_or_init(|| {
        AhoCorasick::builder()
            .ascii_case_insensitive(false)
            .match_kind(MatchKind::LeftmostFirst)
            .kind(Some(AhoCorasickKind::DFA))
            .build([
                // Istio Gateway kind
                "kind: Gateway",
                "kind: VirtualService",
                // Linkerd ingress server
                "gateway.linkerd.io",
                "kind: HTTPRoute",
                // Consul ingress listener
                "Kind = \"ingress-gateway\"",
                "kind = \"ingress-gateway\"",
                "Kind: ingress-gateway",
                // Generic ingress marker
                "external: true",
                "ingress: true",
            ])
            .unwrap()
    })
}

fn authz_binding_ac() -> &'static AhoCorasick {
    AUTHZ_BINDING_AC.get_or_init(|| {
        AhoCorasick::builder()
            .ascii_case_insensitive(false)
            .match_kind(MatchKind::LeftmostFirst)
            .kind(Some(AhoCorasickKind::DFA))
            .build([
                // Istio AuthorizationPolicy principal binding
                "kind: AuthorizationPolicy",
                "source.principals",
                "source.namespaces",
                // Linkerd Server policy
                "kind: Server",
                "kind: MeshTLSAuthentication",
                "kind: NetworkAuthentication",
                // Consul service intentions
                "Kind = \"service-intentions\"",
                "kind = \"service-intentions\"",
                "intentions",
            ])
            .unwrap()
    })
}

fn privileged_path_ac() -> &'static AhoCorasick {
    PRIVILEGED_PATH_AC.get_or_init(|| {
        AhoCorasick::builder()
            .ascii_case_insensitive(false)
            .match_kind(MatchKind::LeftmostFirst)
            .kind(Some(AhoCorasickKind::DFA))
            .build([
                "/admin",
                "/internal",
                "/_management",
                "/management",
                "security: admin",
                "x-admin",
                "admin-only",
            ])
            .unwrap()
    })
}

fn restamp_guard_ac() -> &'static AhoCorasick {
    RESTAMP_GUARD_AC.get_or_init(|| {
        AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::LeftmostFirst)
            .kind(Some(AhoCorasickKind::DFA))
            .build([
                // Header stripping/clearing guards
                "X-Forwarded-Client-Cert",
                "clearOnForward",
                "removeHeader",
                "remove_header",
                // SPIFFE workload API re-fetch markers
                "workload.api",
                "svid.Fetch",
                "SPIFFE_ENDPOINT_SOCKET",
                // Explicit identity re-stamping annotations
                "re-stamp",
                "restamp",
                "reissue-identity",
            ])
            .unwrap()
    })
}

// ---------------------------------------------------------------------------
// Diff walker (reuse same approach as toolchain_degradation)
// ---------------------------------------------------------------------------

struct DiffWalker<'a> {
    lines: std::str::Lines<'a>,
    current_file: Option<&'a str>,
}

impl<'a> DiffWalker<'a> {
    fn new(patch: &'a str) -> Self {
        Self {
            lines: patch.lines(),
            current_file: None,
        }
    }

    fn added_lines(mut self) -> Vec<(&'a str, &'a str)> {
        let mut out = Vec::new();
        for line in self.lines.by_ref() {
            if let Some(rest) = line.strip_prefix("+++ b/") {
                self.current_file = Some(rest.trim());
            } else if let Some(rest) = line.strip_prefix("+++ ") {
                self.current_file = Some(rest.trim());
            } else if let Some(added) = line.strip_prefix('+') {
                if let Some(file) = self.current_file {
                    out.push((file, added));
                }
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// File classifier
// ---------------------------------------------------------------------------

fn is_mesh_config_file(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    p.ends_with(".yaml")
        || p.ends_with(".yml")
        || p.ends_with(".hcl")
        || p.contains("istio")
        || p.contains("linkerd")
        || p.contains("consul")
        || p.contains("mesh")
        || p.contains("gateway")
        || p.contains("policy")
        || p.contains("authorizationpolicy")
        || p.contains("network-policy")
        || p.contains("service-mesh")
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Detect service mesh confused deputy patterns in a unified-diff `patch`.
///
/// Returns zero or more [`SlopFinding`] items.  A finding is emitted when
/// the diff simultaneously introduces:
/// 1. An external-facing mesh boundary (Gateway / ingress Listener).
/// 2. A principal-based authorization binding for an internal service.
/// 3. A privileged path in scope of that binding.
/// 4. No identity re-stamping guard (`X-Forwarded-Client-Cert` stripping).
///
/// The finding fires at `KevCritical` and embeds a curl AEG template in
/// the description so the analyst can prove the bypass without manual setup.
pub fn detect_service_mesh_deputy(patch: &str) -> Vec<SlopFinding> {
    let added = DiffWalker::new(patch).added_lines();

    let mut external_hit = false;
    let mut authz_hit = false;
    let mut privileged_hit = false;
    let mut restamp_present = false;
    let mut external_file = "";
    let mut authz_file = "";
    let mut privileged_path = "";

    for (file, line) in &added {
        if !is_mesh_config_file(file) {
            continue;
        }
        let bytes = line.as_bytes();

        if external_indicator_ac().is_match(bytes) {
            external_hit = true;
            if external_file.is_empty() {
                external_file = file;
            }
        }
        if authz_binding_ac().is_match(bytes) {
            authz_hit = true;
            if authz_file.is_empty() {
                authz_file = file;
            }
        }
        if privileged_path_ac().is_match(bytes) {
            privileged_hit = true;
            if privileged_path.is_empty() {
                privileged_path = line.trim();
            }
        }
        if restamp_guard_ac().is_match(bytes) {
            restamp_present = true;
        }
    }

    if external_hit && authz_hit && privileged_hit && !restamp_present {
        let curl = format!(
            "curl -X GET https://<ingress-host>{path} \\\n  \
             -H 'X-Forwarded-Client-Cert: By=spiffe://cluster.local/ns/<ns>/sa/<external-sa>;Hash=<hash>' \\\n  \
             -H 'Host: <internal-service>'  # Confused-deputy: gateway identity propagated without re-stamping",
            path = if privileged_path.contains('/') {
                privileged_path.split('/').find(|s| s.starts_with("admin") || s.starts_with("internal") || s.starts_with("_management"))
                    .map(|s| format!("/{s}"))
                    .unwrap_or_else(|| "/admin".to_string())
            } else {
                "/admin".to_string()
            }
        );

        return vec![SlopFinding {
            start_byte: 0,
            end_byte: 0,
            description: format!(
                "security:service_mesh_confused_deputy — external-facing mesh boundary \
                 ({external_file}) routes to a principal-authorized internal service \
                 ({authz_file}) at privileged path `{privileged_path}` without \
                 X-Forwarded-Client-Cert stripping or SPIFFE identity re-stamping; \
                 an external attacker reaches the internal service bearing the \
                 gateway's mesh identity. repro_cmd: `{curl}`"
            ),
            domain: DOMAIN_ALL,
            severity: Severity::KevCritical,
        }];
    }

    vec![]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_patch(file: &str, added_lines: &[&str]) -> String {
        let mut patch = format!("--- a/{file}\n+++ b/{file}\n@@ -1,3 +1,8 @@\n");
        for line in added_lines {
            patch.push('+');
            patch.push_str(line);
            patch.push('\n');
        }
        patch
    }

    fn two_file_patch(file_a: &str, lines_a: &[&str], file_b: &str, lines_b: &[&str]) -> String {
        let mut p = make_patch(file_a, lines_a);
        p.push_str(&make_patch(file_b, lines_b));
        p
    }

    // ── TP 1: Istio Gateway + AuthorizationPolicy + privileged path ──────────

    #[test]
    fn tp_istio_gateway_authz_policy_no_restamp() {
        let patch = two_file_patch(
            "deploy/istio/gateway.yaml",
            &["kind: Gateway", "spec:", "  servers:"],
            "deploy/istio/authz.yaml",
            &[
                "kind: AuthorizationPolicy",
                "spec:",
                "  rules:",
                "  - from:",
                "    - source:",
                "        principals: [\"cluster.local/ns/default/sa/frontend\"]",
                "  to:",
                "  - operation:",
                "      paths: [\"/admin/*\"]",
            ],
        );
        let findings = detect_service_mesh_deputy(&patch);
        assert!(
            !findings.is_empty(),
            "Istio gateway + AuthorizationPolicy without restamp must fire"
        );
        assert!(findings[0]
            .description
            .contains("service_mesh_confused_deputy"));
        assert!(matches!(findings[0].severity, Severity::KevCritical));
        assert!(findings[0].description.contains("repro_cmd"));
    }

    // ── TP 2: Linkerd Server + privileged path + no re-stamp ────────────────

    #[test]
    fn tp_linkerd_server_no_restamp() {
        let patch = two_file_patch(
            "deploy/linkerd/ingress-server.yaml",
            &["kind: Server", "  gateway.linkerd.io/access: allow"],
            "deploy/linkerd/policy.yaml",
            &[
                "kind: MeshTLSAuthentication",
                "spec:",
                "  identities: [\"serviceaccount.default.svc.cluster.local\"]",
                "paths: [\"/internal/metrics\"]",
            ],
        );
        let findings = detect_service_mesh_deputy(&patch);
        assert!(
            !findings.is_empty(),
            "Linkerd Server binding without restamp must fire"
        );
        assert!(findings[0]
            .description
            .contains("service_mesh_confused_deputy"));
    }

    // ── TN 1: Gateway present but X-Forwarded-Client-Cert strip guard added ─

    #[test]
    fn tn_gateway_with_restamp_guard() {
        let patch = two_file_patch(
            "deploy/istio/gateway.yaml",
            &["kind: Gateway", "spec:"],
            "deploy/istio/authz.yaml",
            &[
                "kind: AuthorizationPolicy",
                "source.principals: [\"cluster.local/ns/default/sa/frontend\"]",
                "paths: [\"/admin/*\"]",
                "X-Forwarded-Client-Cert: clearOnForward",
            ],
        );
        let findings = detect_service_mesh_deputy(&patch);
        assert!(
            findings.is_empty(),
            "Re-stamp guard must suppress the finding"
        );
    }

    // ── TN 2: Non-mesh YAML (no gateway/authz indicators) ───────────────────

    #[test]
    fn tn_plain_deployment_yaml() {
        let patch = make_patch(
            "deploy/k8s/deployment.yaml",
            &[
                "kind: Deployment",
                "  replicas: 3",
                "  image: my-app:latest",
            ],
        );
        let findings = detect_service_mesh_deputy(&patch);
        assert!(findings.is_empty(), "Plain Deployment YAML must not fire");
    }

    // ── TN 3: Authz policy without external gateway boundary ────────────────

    #[test]
    fn tn_authz_only_no_gateway() {
        let patch = make_patch(
            "deploy/istio/authz-only.yaml",
            &[
                "kind: AuthorizationPolicy",
                "source.principals: [\"cluster.local/ns/default/sa/svc-a\"]",
                "paths: [\"/admin/*\"]",
            ],
        );
        let findings = detect_service_mesh_deputy(&patch);
        assert!(
            findings.is_empty(),
            "AuthorizationPolicy without a co-introduced external gateway must not fire"
        );
    }

    // ── TN 4: Privileged path without authz binding ──────────────────────────

    #[test]
    fn tn_gateway_plus_privileged_path_no_authz_binding() {
        let patch = two_file_patch(
            "deploy/istio/gateway.yaml",
            &["kind: Gateway"],
            "deploy/app/routes.yaml",
            &["path: /admin/users"],
        );
        let findings = detect_service_mesh_deputy(&patch);
        assert!(
            findings.is_empty(),
            "Gateway + privileged path without authz binding must not fire"
        );
    }

    // ── TP: Smuggling combo — mesh deputy + eval() secondary payload ─────────

    #[test]
    fn tp_smuggling_mesh_deputy_plus_eval() {
        let patch = {
            let mut p = two_file_patch(
                "deploy/mesh/gateway.yaml",
                &["kind: Gateway", "  external: true"],
                "deploy/mesh/policy.yaml",
                &[
                    "kind: AuthorizationPolicy",
                    "source.principals: [\"cluster.local/ns/prod/sa/api-gw\"]",
                    "paths: [\"/internal/admin\"]",
                ],
            );
            p.push_str(&make_patch("src/handler.js", &["eval(userInput)"]));
            p
        };
        let mesh_findings = detect_service_mesh_deputy(&patch);
        assert!(
            !mesh_findings.is_empty(),
            "Mesh deputy must still fire even when a secondary payload is present"
        );
    }
}
