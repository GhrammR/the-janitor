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

/// Pure boolean predicate for Kani verification of intent-divergence proof logic.
///
/// Returns `true` iff the zero-auth indicator is present in a non-test path,
/// meaning the `UnauthenticatedAuthProvider` path is production-reachable.
pub fn intent_divergence_is_reachable(has_unauth_indicator: bool, in_test_path: bool) -> bool {
    has_unauth_indicator && !in_test_path
}

/// Pure boolean predicate for Kani verification of FFI deref proof classification.
///
/// | `has_null_guard` | `has_extern_c` | returns                    |
/// |---|---|---|
/// | `true`  | any    | `InvariantViolationProof`  |
/// | `false` | `true` | `ReachabilityProof`        |
/// | `false` | `false`| `LatticeGapProposal`       |
pub fn ffi_deref_guard_classification(has_null_guard: bool, has_extern_c: bool) -> ProofClass {
    if has_null_guard {
        return ProofClass::InvariantViolationProof;
    }
    if has_extern_c {
        ProofClass::ReachabilityProof
    } else {
        ProofClass::LatticeGapProposal
    }
}

/// Classify the proof state for a `security:intent_divergence` finding.
///
/// Inspects the source file for zero-auth provider indicators outside test
/// contexts. Returns [`ProofClass::ReachabilityProof`] when production-reachable
/// indicators are present, [`ProofClass::LatticeGapProposal`] otherwise.
pub fn classify_intent_divergence_proof(finding: &StructuredFinding, source: &str) -> ProofClass {
    let has_unauth_indicator = source.contains("requires_openai_auth: false")
        || source.contains("UnauthenticatedAuthProvider");
    let in_test_path = finding
        .file
        .as_deref()
        .map(|p| p.contains("test") || p.ends_with("_test.rs") || p.contains("spec"))
        .unwrap_or(false);
    if intent_divergence_is_reachable(has_unauth_indicator, in_test_path) {
        ProofClass::ReachabilityProof
    } else {
        ProofClass::LatticeGapProposal
    }
}

/// Classify the proof state for a `security:ffi_unsafe_deref_unguarded` finding.
///
/// Scans a ±5-line window around `finding_line` for a null-guard pattern and a
/// ±10-line window for `extern "C"` reachability. See [`ffi_deref_guard_classification`]
/// for the classification table. When `InvariantViolationProof` is returned, the
/// caller should suppress the finding (null guard makes it safe).
pub fn classify_ffi_deref_proof(source: &str, finding_line: usize) -> ProofClass {
    let lines: Vec<&str> = source.lines().collect();
    if lines.is_empty() {
        return ProofClass::LatticeGapProposal;
    }
    let target = finding_line.saturating_sub(1).min(lines.len().saturating_sub(1));

    let guard_start = target.saturating_sub(5);
    let guard_end = (target + 6).min(lines.len());
    let has_null_guard = lines[guard_start..guard_end].iter().any(|l| {
        let t = l.trim();
        t.contains(".is_null()") || t.contains("is_null(ptr") || t.contains("ptr::null()")
    });

    let ext_start = target.saturating_sub(10);
    let ext_end = (target + 11).min(lines.len());
    let has_extern_c = lines[ext_start..ext_end].iter().any(|l| {
        let t = l.trim();
        t.contains("extern \"C\"") || t.starts_with("pub extern")
    });

    ffi_deref_guard_classification(has_null_guard, has_extern_c)
}

/// Pure boolean predicate for Kani verification of LCM double-free proof logic.
///
/// Returns `true` when the allocation site is reachable from an external call
/// path without a dominance-verified free guard.
pub fn lcm_double_free_is_reachable(has_free_guard: bool, in_test_path: bool) -> bool {
    !has_free_guard && !in_test_path
}

/// Classify proof class for `security:lcm_double_free` findings.
///
/// Searches ±5 lines for a null/guard check before the free call
/// (`InvariantViolationProof` → suppress as FP). Searches ±10 lines for an
/// extern function wrapper or known-exported symbol (`ReachabilityProof`).
/// Falls back to `LatticeGapProposal`.
pub fn classify_lcm_double_free_proof(source: &str, finding_line: usize) -> ProofClass {
    let lines: Vec<&str> = source.lines().collect();
    if lines.is_empty() {
        return ProofClass::LatticeGapProposal;
    }
    let target = finding_line.saturating_sub(1).min(lines.len().saturating_sub(1));
    let guard_start = target.saturating_sub(5);
    let guard_end = (target + 6).min(lines.len());
    let has_free_guard = lines[guard_start..guard_end].iter().any(|l| {
        let t = l.trim();
        (t.contains("if (") && (t.contains("!= NULL") || t.contains("!= 0") || t.contains("freed")))
            || t.contains("assert(")
    });
    let ext_start = target.saturating_sub(10);
    let ext_end = (target + 11).min(lines.len());
    let has_extern = lines[ext_start..ext_end].iter().any(|l| {
        let t = l.trim();
        t.starts_with("static ") || t.contains("SECP256K1_API") || t.contains("lcm_")
    });
    if has_free_guard {
        ProofClass::InvariantViolationProof
    } else if has_extern {
        ProofClass::ReachabilityProof
    } else {
        ProofClass::LatticeGapProposal
    }
}

/// Pure boolean predicate for Kani verification of timing-comparison proof logic.
///
/// Returns `true` when a non-constant-time comparison is on a secret path
/// (MAC, HMAC, session key, signature) NOT in a test or benchmark context.
pub fn timing_comparison_is_sensitive(has_secret_marker: bool, in_bench_or_test: bool) -> bool {
    has_secret_marker && !in_bench_or_test
}

/// Classify proof class for `security:non_constant_time_comparison` findings.
///
/// Returns `ReachabilityProof` when the source contains HMAC/session-key markers
/// and the finding is not in a test or benchmark file; otherwise `LatticeGapProposal`.
pub fn classify_timing_comparison_proof(source: &str, finding: &StructuredFinding) -> ProofClass {
    let in_test_path = finding
        .file
        .as_deref()
        .map(|p| p.contains("test") || p.ends_with("_test.go") || p.contains("bench"))
        .unwrap_or(false);
    let has_secret_marker = source.contains("hmac")
        || source.contains("HMAC")
        || source.contains("session_key")
        || source.contains("auth_tag")
        || source.contains("nonce");
    if timing_comparison_is_sensitive(has_secret_marker, in_test_path) {
        ProofClass::ReachabilityProof
    } else {
        ProofClass::LatticeGapProposal
    }
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
        append_gap_proposals_to, enforce_false_positive_proof_obligation, proof_obligation_missing,
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
    fn intent_divergence_non_test_path_yields_reachability_proof() {
        let finding = StructuredFinding {
            id: "security:intent_divergence".to_string(),
            file: Some("codex-rs/model-provider/src/auth.rs".to_string()),
            ..Default::default()
        };
        let source = "pub struct UnauthenticatedAuthProvider; fn build() { requires_openai_auth: false }";
        assert_eq!(
            super::classify_intent_divergence_proof(&finding, source),
            ProofClass::ReachabilityProof
        );
    }

    #[test]
    fn intent_divergence_test_path_yields_lattice_gap() {
        let finding = StructuredFinding {
            id: "security:intent_divergence".to_string(),
            file: Some("codex-rs/model-provider/src/auth_test.rs".to_string()),
            ..Default::default()
        };
        let source = "pub struct UnauthenticatedAuthProvider;";
        assert_eq!(
            super::classify_intent_divergence_proof(&finding, source),
            ProofClass::LatticeGapProposal
        );
    }

    #[test]
    fn ffi_deref_null_guard_present_yields_invariant_violation_proof() {
        let source = "let ptr = qdb_read(key);\nif ptr.is_null() { return Err(e); }\nCStr::from_ptr(ptr)";
        assert_eq!(
            super::classify_ffi_deref_proof(source, 3),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn ffi_deref_unguarded_no_extern_yields_lattice_gap() {
        let source = "let ptr = qdb_read(key);\nlet value = CStr::from_ptr(ptr);\n";
        assert_eq!(
            super::classify_ffi_deref_proof(source, 2),
            ProofClass::LatticeGapProposal
        );
    }

    #[test]
    fn ffi_deref_unguarded_with_extern_c_yields_reachability_proof() {
        let source = "extern \"C\" pub fn get_config(key: *const c_char) -> *const c_char {\nlet ptr = qdb_read(key);\nCStr::from_ptr(ptr)\n}";
        assert_eq!(
            super::classify_ffi_deref_proof(source, 3),
            ProofClass::ReachabilityProof
        );
    }

    #[test]
    fn raw_pointer_deref_no_null_guard_yields_lattice_gap() {
        // Matches the ClickHouse PRQL FFI surface: *raw_ptr at line 9 with no .is_null() guard.
        let source = "use prql_compiler::compile;\npub fn compile_prql(prql: *const u8, len: usize) -> *mut u8 {\n    let slice = unsafe { std::slice::from_raw_parts(*raw_ptr, len) };\n    let result = compile(std::str::from_utf8(slice).unwrap());\n    let s = result.unwrap_or_default();\n    let boxed = s.into_boxed_str().into_boxed_bytes();\n    Box::into_raw(boxed) as *mut u8\n}\n";
        assert_eq!(
            super::classify_ffi_deref_proof(source, 3),
            ProofClass::LatticeGapProposal
        );
    }

    // --- lcm_double_free classifier tests ---

    #[test]
    fn lcm_double_free_null_guard_yields_invariant_violation() {
        let source = "int *buf = malloc(sz);\nif (buf != NULL) {\n    free(buf);\n    free(buf);\n}";
        assert_eq!(
            super::classify_lcm_double_free_proof(source, 3),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn lcm_double_free_secp256k1_api_yields_reachability_proof() {
        let source =
            "SECP256K1_API int secp256k1_sign(secp256k1_context *ctx, unsigned char *out) {\n    free(ctx->scratch);\n    free(ctx->scratch);\n    return 1;\n}";
        assert_eq!(
            super::classify_lcm_double_free_proof(source, 2),
            ProofClass::ReachabilityProof
        );
    }

    #[test]
    fn lcm_double_free_no_guard_no_extern_yields_lattice_gap() {
        let source = "void process(unsigned char *buf, size_t len) {\n    memcpy(tmp, buf, len);\n    free(buf);\n    free(buf);\n}";
        assert_eq!(
            super::classify_lcm_double_free_proof(source, 3),
            ProofClass::LatticeGapProposal
        );
    }

    // --- timing_comparison classifier tests ---

    #[test]
    fn timing_comparison_hmac_non_test_yields_reachability_proof() {
        let finding = StructuredFinding {
            id: "security:non_constant_time_comparison".to_string(),
            file: Some("p2p/discover/v5wire/encoding.go".to_string()),
            ..Default::default()
        };
        let source = "func verifySession(got, expected []byte) bool {\n    nonce := session.nonce\n    return bytes.Equal(got, expected)\n}";
        assert_eq!(
            super::classify_timing_comparison_proof(source, &finding),
            ProofClass::ReachabilityProof
        );
    }

    #[test]
    fn timing_comparison_test_path_yields_lattice_gap() {
        let finding = StructuredFinding {
            id: "security:non_constant_time_comparison".to_string(),
            file: Some("p2p/discover/v5wire/encoding_test.go".to_string()),
            ..Default::default()
        };
        let source = "func TestVerifySession(t *testing.T) {\n    nonce := session.nonce\n    return bytes.Equal(got, expected)\n}";
        assert_eq!(
            super::classify_timing_comparison_proof(source, &finding),
            ProofClass::LatticeGapProposal
        );
    }
}
