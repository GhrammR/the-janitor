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
        let target = finding_line.saturating_sub(1).min(lines.len().saturating_sub(1));
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
        ProofClass::ReachabilityProof
    } else {
        ProofClass::LatticeGapProposal
    }
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
    let target = finding_line.saturating_sub(1).min(lines.len().saturating_sub(1));
    let guard_start = target.saturating_sub(5);
    let guard_end = (target + 6).min(lines.len());
    let has_lifetime_guard = lines[guard_start..guard_end].iter().any(|l| {
        let t = l.trim();
        (t.contains("if (") && (t.contains("!= NULL") || t.contains("freed") || t.contains("is_valid")))
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
    let target = finding_line.saturating_sub(1).min(lines.len().saturating_sub(1));
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
pub fn classify_lcm_off_by_one_loop_proof(
    source: &str,
    finding: &StructuredFinding,
) -> ProofClass {
    let finding_line = finding.line.unwrap_or(1) as usize;
    let lines: Vec<&str> = source.lines().collect();
    if lines.is_empty() {
        return ProofClass::LatticeGapProposal;
    }
    let target = finding_line.saturating_sub(1).min(lines.len().saturating_sub(1));
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
/// Returns `true` when the callback is server-side AND no state check is present.
pub fn oauth_state_validation_is_missing(is_server_side: bool, has_state_check: bool) -> bool {
    is_server_side && !has_state_check
}

/// Classify proof class for `security:oauth_missing_state_validation` findings.
///
/// 1. Non-server-side file (TypeScript/JavaScript) → `LatticeGapProposal` (client-side
///    CSRF is not a real SSRF/CSRF surface without an SSR path).
/// 2. Server-side file (Python/Go/Ruby/Java) with a visible state-check → `InvariantViolationProof` (suppress).
/// 3. Server-side file with NO state check → `ReachabilityProof`.
pub fn classify_oauth_state_validation_proof(
    source: &str,
    finding: &StructuredFinding,
) -> ProofClass {
    let is_server_side = finding
        .file
        .as_deref()
        .map(|p| {
            p.ends_with(".py")
                || p.ends_with(".go")
                || p.ends_with(".rb")
                || p.ends_with(".java")
        })
        .unwrap_or(false);
    if !is_server_side {
        return ProofClass::LatticeGapProposal;
    }
    let has_state_check = source.contains("session.get(\"oauth_state\")")
        || source.contains("session.get('oauth_state')")
        || source.contains("state_parameter")
        || source.contains("verify_state(")
        || source.contains("oauth_state")
        || source.contains("state == session");
    if has_state_check {
        ProofClass::InvariantViolationProof
    } else {
        ProofClass::ReachabilityProof
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
            p.ends_with(".py")
                || p.ends_with(".go")
                || p.ends_with(".rb")
                || p.ends_with(".java")
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
    let uses_deprecated = source.contains("ptypes.UnmarshalAny")
        || source.contains("proto.UnmarshalAny");
    let uses_modern = source.contains("anypb.UnmarshalTo")
        || source.contains("anypb.UnmarshalNew");
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
pub fn classify_sqli_concatenation_proof(
    source: &str,
    finding: &StructuredFinding,
) -> ProofClass {
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
        let source = "def callback():\n    code = request.args.get('code')\n    _fetch_access_token(code)\n";
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
            file: Some("lib/oidc/endpoints/token.ts".to_string()),
            line: Some(34),
            ..Default::default()
        };
        let source = "export async function exchangeCode(code: string) { return fetch('/token', { body: JSON.stringify({ code }) }); }";
        assert_eq!(
            super::classify_oauth_state_validation_proof(source, &finding),
            ProofClass::LatticeGapProposal
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
        let source = "if err := ptypes.UnmarshalAny(entity.Metadata, &meta); err != nil { return err }";
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
}
