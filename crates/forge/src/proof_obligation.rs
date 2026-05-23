//! False-positive proof obligation gate for critical findings.

use std::fs;
use std::path::Path;

use common::slop::{finding_has_required_proof_class, ProofClass, StructuredFinding};

const INNOVATION_LOG_PATH: &str = ".INNOVATION_LOG.md";

/// Suppress critical findings that lack a mandated proof class and append the
/// missing mathematical cure to `.INNOVATION_LOG.md`.
pub fn enforce_false_positive_proof_obligation(
    findings: &[StructuredFinding],
) -> Vec<StructuredFinding> {
    let mut kept = Vec::with_capacity(findings.len());
    let mut proposals = Vec::new();

    for finding in findings {
        if !requires_proof_obligation(finding) {
            kept.push(finding.clone());
            continue;
        }
        if let Some(upgraded) = upgrade_implicit_reachability_proof(finding) {
            kept.push(upgraded);
            continue;
        }
        if proof_obligation_missing(true, finding_has_required_proof_class(finding)) {
            proposals.push(proposal_block_for(finding));
            continue;
        }
        kept.push(finding.clone());
    }

    if !proposals.is_empty() {
        let _ = append_gap_proposals_to(Path::new(INNOVATION_LOG_PATH), &proposals);
    }

    kept
}

/// Pure helper for tests and formal assurance.
pub fn proof_obligation_missing(requires_proof: bool, has_proof_class: bool) -> bool {
    requires_proof && !has_proof_class
}

/// Exact source/sink/guard predicate used by proof-obligation classifiers.
pub fn guarded_reachability_conjunction(
    has_sink: bool,
    has_untrusted_origin: bool,
    has_guard: bool,
) -> bool {
    has_sink && has_untrusted_origin && !has_guard
}

/// Classify `security:oauth_excessive_scope` proof quality.
pub fn classify_oauth_excessive_scope_proof(
    source: &str,
    finding: &StructuredFinding,
) -> ProofClass {
    let path = finding
        .file
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let lower = source.to_ascii_lowercase();

    if is_nonproduction_context(&path) || is_admin_manifest_context(&path, &lower) {
        return ProofClass::InvariantViolationProof;
    }

    let has_oauth_context = contains_any(
        &lower,
        &[
            "oauth",
            "github",
            "access_token",
            "scopedtoken",
            "permissions:",
            "scope",
        ],
    );
    let has_privileged_scope = contains_any(
        &lower,
        &[
            "admin:org",
            "admin:enterprise",
            "id-token: write",
            "id-token:write",
            "write-all",
            "contents: write",
            "repo,",
            "repo ",
            "\"repo\"",
            "'repo'",
            "repo:*",
            "*:*",
        ],
    );
    let has_untrusted_origin = contains_any(
        &lower,
        &[
            "request",
            "req.",
            "req_",
            "headers",
            "query",
            "params",
            "body",
            "user",
            "input",
            "client_id",
            "app_id",
            "automation",
            "workflow_dispatch",
        ],
    );
    let has_scope_constraint = contains_any(
        &lower,
        &[
            "audience",
            "resource",
            "allowed_scope",
            "allowedscopes",
            "scope_allowlist",
            "scopeallowlist",
            "least_privilege",
            "least-privilege",
            "repo:status",
            "read-all",
            "contents: read",
        ],
    );

    if !has_oauth_context || !has_privileged_scope {
        return ProofClass::LatticeGapProposal;
    }
    if guarded_reachability_conjunction(
        has_privileged_scope,
        has_untrusted_origin,
        has_scope_constraint,
    ) {
        ProofClass::ReachabilityProof
    } else if has_scope_constraint {
        ProofClass::InvariantViolationProof
    } else {
        ProofClass::LatticeGapProposal
    }
}

/// Classify `security:java_deser_allowlist_bypass` proof quality.
pub fn classify_java_deser_allowlist_bypass_proof(
    source: &str,
    finding: &StructuredFinding,
) -> ProofClass {
    let path = finding
        .file
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let lower = source.to_ascii_lowercase();

    if is_nonproduction_context(&path) {
        return ProofClass::InvariantViolationProof;
    }

    let has_deser_sink = contains_any(
        &lower,
        &[
            "objectinputstream",
            ".readobject(",
            " readobject(",
            "resolveclass",
            "java.io.serializable",
        ],
    );
    let has_untrusted_origin = contains_any(
        &lower,
        &[
            "httpservletrequest",
            "@requestbody",
            "request.getinputstream",
            "request.getreader",
            "servletinputstream",
            "headers",
            "session",
            "message",
            "jms",
            "kafka",
            "upload",
            "body",
        ],
    );
    let has_allowlist_filter = contains_any(
        &lower,
        &[
            "objectinputfilter",
            "serialfilter",
            "allowlist",
            "allowedclasses",
            "allowed_classes",
            "whitelist",
            "sealed",
            "fixedtype",
            "fixed type",
        ],
    );

    if !has_deser_sink {
        return ProofClass::LatticeGapProposal;
    }
    if guarded_reachability_conjunction(has_deser_sink, has_untrusted_origin, has_allowlist_filter)
    {
        ProofClass::ReachabilityProof
    } else if has_allowlist_filter {
        ProofClass::InvariantViolationProof
    } else {
        ProofClass::LatticeGapProposal
    }
}

fn requires_proof_obligation(finding: &StructuredFinding) -> bool {
    matches!(
        finding.severity.as_deref(),
        Some("KevCritical") | Some("Critical")
    )
}

fn upgrade_implicit_reachability_proof(finding: &StructuredFinding) -> Option<StructuredFinding> {
    if finding_has_required_proof_class(finding) {
        return None;
    }
    let mut upgraded = finding.clone();
    upgraded.proof_class = Some(if finding.exploit_witness.is_some() {
        ProofClass::ReachabilityProof
    } else if is_self_proving_invariant(finding) {
        ProofClass::InvariantViolationProof
    } else {
        return None;
    });
    Some(upgraded)
}

fn is_self_proving_invariant(finding: &StructuredFinding) -> bool {
    let id = finding.id.to_ascii_lowercase();
    [
        "credential",
        "secret",
        "api_key",
        "command_injection",
        "runtime_exec",
        "shell_exec",
        "tls_verification_bypass",
        "optimizer_phantom_authority",
        "clock_skew_auth_split_brain",
        "dma_revocation_shadow_access",
        "probabilistic_llm_hijack",
    ]
    .iter()
    .any(|needle| id.contains(needle))
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

fn is_nonproduction_context(path: &str) -> bool {
    contains_any(
        path,
        &[
            "/test",
            "_test.",
            ".test.",
            ".spec.",
            "/tests/",
            "/fixtures/",
            "/generated/",
            "generated",
            "/migrations/",
            "/docs/",
            "/examples/",
            "/scripts/",
        ],
    )
}

fn is_admin_manifest_context(path: &str, source: &str) -> bool {
    path.starts_with(".github/workflows/")
        || contains_any(
            source,
            &[
                "admin-only",
                "operator config",
                "local config",
                "maintainer only",
                "manual approval",
            ],
        )
}

fn proposal_block_for(finding: &StructuredFinding) -> String {
    let finding_id = finding.id.trim();
    let safe_slug = finding_id.replace(':', "_");
    let location = match (finding.file.as_deref(), finding.line) {
        (Some(file), Some(line)) => format!("{file}:{line}"),
        (Some(file), None) => file.to_string(),
        _ => "unknown_location".to_string(),
    };
    format!(
        "\n### P17-3A — Proof Obligation Cure for {finding_id}\n\n\
**The gap**: `{finding_id}` reached triage at `{location}` without a mandatory \
`ReachabilityProof`, `InvariantViolationProof`, or `LatticeGapProposal`, so the \
engine could emit a plausible but unprovable critical report.\n\n\
**Build**: Extend `crates/forge/src/proof_obligation.rs` and the owning detector \
for `{safe_slug}` so the finding carries exactly one proof class before it reaches \
ledger routing. If the detector cannot prove reachability or invariant failure, \
it must synthesize a deterministic `LatticeGapProposal` instead of surfacing the \
finding.\n\n\
**Rust mathematics**: proof-state typestates for finding emission, sealed \
evidence enums, monotonic suppression before ledger serialization, and a \
deterministic fixture pair proving both suppression-without-proof and \
preservation-with-proof.\n"
    )
}

fn append_gap_proposals_to(path: &Path, proposals: &[String]) -> std::io::Result<()> {
    let mut content = fs::read_to_string(path).unwrap_or_default();
    let mut changed = false;

    for proposal in proposals {
        let Some(heading) = proposal
            .lines()
            .find(|line| line.starts_with("### P17-3A — Proof Obligation Cure for "))
        else {
            continue;
        };
        if content.contains(heading) {
            continue;
        }
        content.push_str(proposal);
        changed = true;
    }

    if changed {
        fs::write(path, content)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        append_gap_proposals_to, classify_java_deser_allowlist_bypass_proof,
        classify_oauth_excessive_scope_proof, enforce_false_positive_proof_obligation,
        guarded_reachability_conjunction, proof_obligation_missing,
    };
    use common::slop::{ExploitWitness, ProofClass, StructuredFinding};
    use tempfile::NamedTempFile;

    #[test]
    fn suppresses_critical_finding_without_proof_class() {
        let findings = vec![StructuredFinding {
            id: "security:ssrf_dynamic_url".to_string(),
            severity: Some("Critical".to_string()),
            ..Default::default()
        }];

        let filtered = enforce_false_positive_proof_obligation(&findings);
        assert!(filtered.is_empty());
    }

    #[test]
    fn preserves_critical_finding_with_proof_class() {
        let findings = vec![StructuredFinding {
            id: "security:ssrf_dynamic_url".to_string(),
            severity: Some("Critical".to_string()),
            proof_class: Some(ProofClass::ReachabilityProof),
            ..Default::default()
        }];

        let filtered = enforce_false_positive_proof_obligation(&findings);
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn upgrades_implicit_exploit_witness_to_reachability_proof() {
        let findings = vec![StructuredFinding {
            id: "security:ssrf_dynamic_url".to_string(),
            severity: Some("Critical".to_string()),
            exploit_witness: Some(ExploitWitness::default()),
            ..Default::default()
        }];

        let filtered = enforce_false_positive_proof_obligation(&findings);
        assert_eq!(filtered[0].proof_class, Some(ProofClass::ReachabilityProof));
    }

    #[test]
    fn upgrades_self_proving_credential_finding_to_invariant_proof() {
        let findings = vec![StructuredFinding {
            id: "security:credential_exposure".to_string(),
            severity: Some("Critical".to_string()),
            ..Default::default()
        }];

        let filtered = enforce_false_positive_proof_obligation(&findings);
        assert_eq!(
            filtered[0].proof_class,
            Some(ProofClass::InvariantViolationProof)
        );
    }

    #[test]
    fn appends_gap_once_per_heading() {
        let file = NamedTempFile::new().unwrap();
        std::fs::write(file.path(), "# Log\n").unwrap();
        let proposal =
            "\n### P17-3A — Proof Obligation Cure for security:test\n\nbody\n".to_string();

        append_gap_proposals_to(file.path(), &[proposal.clone()]).unwrap();
        append_gap_proposals_to(file.path(), &[proposal]).unwrap();

        let content = std::fs::read_to_string(file.path()).unwrap();
        assert_eq!(
            content
                .matches("### P17-3A — Proof Obligation Cure for security:test")
                .count(),
            1
        );
    }

    #[test]
    fn helper_tracks_missing_requirement() {
        assert!(proof_obligation_missing(true, false));
        assert!(!proof_obligation_missing(true, true));
        assert!(!proof_obligation_missing(false, false));
    }

    #[test]
    fn preserves_kev_critical_finding_with_lattice_gap_proof_class() {
        // Regression: lcm.rs and agent_intent.rs emit LatticeGapProposal.
        // Verify the gate passes them through rather than suppressing.
        let findings = vec![StructuredFinding {
            id: "security:ffi_unsafe_deref_unguarded".to_string(),
            severity: Some("KevCritical".to_string()),
            proof_class: Some(ProofClass::LatticeGapProposal),
            ..Default::default()
        }];

        let filtered = enforce_false_positive_proof_obligation(&findings);
        assert_eq!(filtered.len(), 1);
        assert_eq!(
            filtered[0].proof_class,
            Some(ProofClass::LatticeGapProposal)
        );
    }

    #[test]
    fn suppresses_kev_critical_finding_without_any_proof_class() {
        let findings = vec![StructuredFinding {
            id: "security:ffi_unsafe_deref_unguarded".to_string(),
            severity: Some("KevCritical".to_string()),
            ..Default::default()
        }];

        let filtered = enforce_false_positive_proof_obligation(&findings);
        assert!(filtered.is_empty());
    }

    #[test]
    fn oauth_excessive_scope_reachability_requires_untrusted_privileged_scope() {
        let finding = StructuredFinding {
            id: "security:oauth_excessive_scope".to_string(),
            file: Some("server/oauth/token.go".to_string()),
            ..Default::default()
        };
        let source = r#"
            func issue(req Request) {
                scope := req.Query("scope")
                if scope == "repo admin:org" {
                    mintGithubAccessToken(scope)
                }
            }
        "#;
        assert_eq!(
            classify_oauth_excessive_scope_proof(source, &finding),
            ProofClass::ReachabilityProof
        );
    }

    #[test]
    fn oauth_excessive_scope_guarded_by_audience_is_invariant() {
        let finding = StructuredFinding {
            id: "security:oauth_excessive_scope".to_string(),
            file: Some("server/oauth/token.go".to_string()),
            ..Default::default()
        };
        let source = r#"
            let scope = request.body.scope;
            let allowed_scope = scope_allowlist.for_audience(audience);
            mint_github_token(scope.intersection(allowed_scope), "repo");
        "#;
        assert_eq!(
            classify_oauth_excessive_scope_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn oauth_excessive_scope_workflow_manifest_is_invariant() {
        let finding = StructuredFinding {
            id: "security:oauth_excessive_scope".to_string(),
            file: Some(".github/workflows/release.yml".to_string()),
            ..Default::default()
        };
        let source = "permissions:\n  id-token: write\n  contents: read\n";
        assert_eq!(
            classify_oauth_excessive_scope_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn java_deser_allowlist_bypass_reachability_requires_request_body() {
        let finding = StructuredFinding {
            id: "security:java_deser_allowlist_bypass".to_string(),
            file: Some("src/main/java/app/ImportServlet.java".to_string()),
            ..Default::default()
        };
        let source = r#"
            void doPost(HttpServletRequest request) {
                ObjectInputStream in = new ObjectInputStream(request.getInputStream());
                Object value = in.readObject();
            }
        "#;
        assert_eq!(
            classify_java_deser_allowlist_bypass_proof(source, &finding),
            ProofClass::ReachabilityProof
        );
    }

    #[test]
    fn java_deser_allowlist_filter_is_invariant() {
        let finding = StructuredFinding {
            id: "security:java_deser_allowlist_bypass".to_string(),
            file: Some("src/main/java/app/ImportServlet.java".to_string()),
            ..Default::default()
        };
        let source = r#"
            void doPost(HttpServletRequest request) {
                ObjectInputStream in = new ObjectInputStream(request.getInputStream());
                in.setObjectInputFilter(ObjectInputFilter.Config.createFilter("com.acme.Safe;!*"));
                Object value = in.readObject();
            }
        "#;
        assert_eq!(
            classify_java_deser_allowlist_bypass_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn java_deser_unknown_origin_stays_lattice_gap() {
        let finding = StructuredFinding {
            id: "security:java_deser_allowlist_bypass".to_string(),
            file: Some("src/main/java/app/CacheReader.java".to_string()),
            ..Default::default()
        };
        let source = r#"
            ObjectInputStream in = new ObjectInputStream(localCacheStream);
            Object value = in.readObject();
        "#;
        assert_eq!(
            classify_java_deser_allowlist_bypass_proof(source, &finding),
            ProofClass::LatticeGapProposal
        );
    }

    #[test]
    fn proof_predicates_are_exact_conjunctions() {
        assert!(guarded_reachability_conjunction(true, true, false));
        assert!(!guarded_reachability_conjunction(true, true, true));
        assert!(!guarded_reachability_conjunction(true, false, false));
        assert!(!guarded_reachability_conjunction(false, true, false));
    }
}
