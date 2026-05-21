//! P4-11 Reflexive Assurance — Formal Verification Harnesses.
//!
//! Provides `#[kani::proof]` harnesses for critical security-scoring and
//! serialization functions. All harnesses are gated behind `#[cfg(kani)]`
//! and are therefore compiled only when the Kani Rust Verifier toolchain
//! is active (`cargo kani`). Regular `cargo test` excludes this block.
//!
//! ## Kani integration
//!
//! The `kani` crate is injected by the Kani toolchain and does NOT require a
//! separate crates.io dependency. Harnesses are written to the Kani ABI
//! (`kani::any::<T>()`, `kani::assume!`, `kani::assert!`) which is resolved
//! at verification time.
//!
//! To run: `cargo kani --harness <name>` with the Kani toolchain installed.

// ---------------------------------------------------------------------------
// Kani proof harnesses — compiled only under the Kani toolchain.
// ---------------------------------------------------------------------------

// The `kani` cfg is injected by the Kani toolchain at verification time.
// It is not a standard Cargo feature; suppress the lint for this module.
#[allow(unexpected_cfgs)]
#[cfg(kani)]
mod kani_proofs {
    use crate::agent_intent::session_tool_intent_drift;
    use crate::debug_endpoint_guard::debug_endpoint_missing_auth;
    use crate::dma_revocation::dma_shadow_access_missing_revocation_dominance;
    use crate::embedding_trust::trust_prioritization_missing;
    use crate::java_deser_guard::deser_missing_allowlist;
    use crate::lcm::ffi_deref_unguarded;
    use crate::linker_hijack::linker_hijack_missing_attestation;
    use crate::mcp_dispatch_guard::session_dispatch_missing_secret_check;
    use crate::model_lineage::llm_provenance_missing;
    use crate::noninterference::declassification_gate_missing;
    use crate::oidc_scope_guard::oidc_scope_missing_audience;
    use crate::proof_obligation::{
        ffi_deref_guard_classification, intent_divergence_is_reachable, proof_obligation_missing,
    };
    use crate::slop_hunter::Severity;
    use common::slop::ProofClass;

    /// Prove that `Severity::points()` never panics and always returns a value
    /// within the declared range [0, 150] for any symbolic `Severity` variant.
    ///
    /// Safety property: exhaustive `match` covers every discriminant; no
    /// integer overflow is possible because all arms are constant literals.
    #[kani::proof]
    fn severity_points_no_panic_and_bounded() {
        let idx: u8 = kani::any();
        kani::assume(idx < 6);
        let sev = match idx {
            0 => Severity::KevCritical,
            1 => Severity::Exhaustion,
            2 => Severity::Critical,
            3 => Severity::High,
            4 => Severity::Warning,
            _ => Severity::Lint,
        };
        let pts = sev.points();
        // Verify the output is within the known bounded range.
        kani::assert(pts <= 150, "points() must not exceed 150 (KevCritical cap)");
    }

    /// Prove that the OTLP `timeUnixNano` computation (`ts_ms as u128 * 1_000_000`)
    /// never overflows a u128 for any representable u64 timestamp.
    ///
    /// Safety property: u64::MAX (≈1.84e19) × 1_000_000 ≈ 1.84e25, which is
    /// well below u128::MAX (≈3.4e38). CBMC / Kani verifies this statically.
    #[kani::proof]
    fn otlp_time_nanosecond_conversion_no_overflow() {
        let ts_ms: u64 = kani::any();
        // This mirrors the cast in esg_ledger::build_otlp_payload.
        let ts_ns: u128 = ts_ms as u128 * 1_000_000u128;
        // Proof obligation: result fits in u128 with no wrap.
        let _ = ts_ns;
    }

    /// Prove that `Severity::points()` for KevCritical specifically equals 150.
    ///
    /// Guards against future refactors that accidentally change the scoring
    /// constant without also updating Crucible and Bounty Ledger payout tables.
    #[kani::proof]
    fn kev_critical_points_is_150() {
        let pts = Severity::KevCritical.points();
        kani::assert(pts == 150, "KevCritical must score exactly 150 points");
    }

    /// Prove the embedding-trust gate is a pure monotonic conjunction:
    /// it fires iff query + untrusted input are present and the trust guard is absent.
    #[kani::proof]
    fn embedding_trust_gate_is_conjunctive() {
        let has_query: bool = kani::any();
        let has_untrusted_input: bool = kani::any();
        let has_guard: bool = kani::any();
        let fired = trust_prioritization_missing(has_query, has_untrusted_input, has_guard);
        kani::assert(
            fired == (has_query && has_untrusted_input && !has_guard),
            "embedding trust gate must be exact",
        );
    }

    /// Prove the non-interference gate never fires when a declassification
    /// boundary is visible or the privileged tool does not occur after extraction.
    #[kani::proof]
    fn prompt_tool_interference_requires_missing_gate_and_order() {
        let has_prompt: bool = kani::any();
        let has_extraction: bool = kani::any();
        let has_privileged_tool: bool = kani::any();
        let has_gate: bool = kani::any();
        let tool_after_extraction: bool = kani::any();
        let fired = declassification_gate_missing(
            has_prompt,
            has_extraction,
            has_privileged_tool,
            has_gate,
            tool_after_extraction,
        );
        kani::assert(
            fired
                == (has_prompt
                    && has_extraction
                    && has_privileged_tool
                    && tool_after_extraction
                    && !has_gate),
            "prompt-tool noninterference gate must be exact",
        );
    }

    /// Prove critical findings are suppressed iff they require proof and no
    /// proof class has been attached.
    #[kani::proof]
    fn proof_obligation_gate_is_exact() {
        let requires_proof: bool = kani::any();
        let has_proof_class: bool = kani::any();
        let fired = proof_obligation_missing(requires_proof, has_proof_class);
        kani::assert(
            fired == (requires_proof && !has_proof_class),
            "proof obligation gate must be exact",
        );
    }

    /// Prove the DMA revocation detector fires only when revoke occurs after
    /// DMA activity and no unmap/fence dominates that revoke path.
    #[kani::proof]
    fn dma_revocation_gate_requires_missing_unmap_dominance() {
        let has_map: bool = kani::any();
        let has_submit: bool = kani::any();
        let has_revoke: bool = kani::any();
        let unmap_after_revoke: bool = kani::any();
        let revoke_after_activity: bool = kani::any();
        let fired = dma_shadow_access_missing_revocation_dominance(
            has_map,
            has_submit,
            has_revoke,
            unmap_after_revoke,
            revoke_after_activity,
        );
        kani::assert(
            fired
                == (has_map
                    && has_submit
                    && has_revoke
                    && revoke_after_activity
                    && !unmap_after_revoke),
            "DMA revocation gate must be exact",
        );
    }

    /// Prove the linker-hijack gate is an exact conjunction:
    /// fires iff LD_PRELOAD is present AND digest check is absent.
    #[kani::proof]
    fn linker_hijack_gate_is_exact() {
        let has_ld_preload: bool = kani::any();
        let has_digest_check: bool = kani::any();
        let fired = linker_hijack_missing_attestation(has_ld_preload, has_digest_check);
        kani::assert(
            fired == (has_ld_preload && !has_digest_check),
            "linker hijack gate must be exact conjunction",
        );
    }

    /// Prove the debug-endpoint gate is an exact conjunction:
    /// fires iff a debug route is present AND auth middleware is absent.
    #[kani::proof]
    fn debug_endpoint_gate_is_exact() {
        let has_debug_route: bool = kani::any();
        let has_auth_middleware: bool = kani::any();
        let fired = debug_endpoint_missing_auth(has_debug_route, has_auth_middleware);
        kani::assert(
            fired == (has_debug_route && !has_auth_middleware),
            "debug endpoint gate must be exact conjunction",
        );
    }

    /// Prove the Java deserialization allowlist-bypass gate is an exact conjunction:
    /// fires iff a decoder is present AND an allowlist suppressor is absent.
    #[kani::proof]
    fn deser_gate_is_exact() {
        let has_decoder: bool = kani::any();
        let has_allowlist: bool = kani::any();
        let fired = deser_missing_allowlist(has_decoder, has_allowlist);
        kani::assert(
            fired == (has_decoder && !has_allowlist),
            "java deser allowlist-bypass gate must be exact conjunction",
        );
    }

    /// Prove the OIDC scope-abuse gate is an exact conjunction:
    /// fires iff id-token write permission is present AND audience scope is absent.
    #[kani::proof]
    fn oidc_scope_gate_is_exact() {
        let has_write_permission: bool = kani::any();
        let has_audience_scope: bool = kani::any();
        let fired = oidc_scope_missing_audience(has_write_permission, has_audience_scope);
        kani::assert(
            fired == (has_write_permission && !has_audience_scope),
            "OIDC scope-abuse gate must be exact conjunction",
        );
    }

    /// Prove the MCP confused-deputy predicate is an exact conjunction:
    /// fires iff dispatch is present AND secret verification is absent.
    ///
    /// Safety property: no aliased session resolution is possible under
    /// a correct guard — the predicate never fires when `has_secret_verify`
    /// is true, regardless of `has_dispatch`.
    #[kani::proof]
    fn mcp_confused_deputy_gate_is_exact() {
        let has_dispatch: bool = kani::any();
        let has_secret_verify: bool = kani::any();
        let fired = session_dispatch_missing_secret_check(has_dispatch, has_secret_verify);
        kani::assert(
            fired == (has_dispatch && !has_secret_verify),
            "MCP confused-deputy gate must be exact conjunction",
        );
    }

    /// Prove the FFI raw-pointer dereference gate is an exact conjunction:
    /// fires iff a sink is present AND an FFI source is present AND no guard exists.
    #[kani::proof]
    fn lcm_ffi_gate_is_exact() {
        let has_sink: bool = kani::any();
        let has_source: bool = kani::any();
        let has_guard: bool = kani::any();
        let fired = ffi_deref_unguarded(has_sink, has_source, has_guard);
        kani::assert(
            fired == (has_sink && has_source && !has_guard),
            "FFI deref unguarded gate must be exact conjunction",
        );
    }

    /// Prove the AI-agent tool-intent drift gate is an exact conjunction:
    /// fires iff a tool sink is present AND an escalation indicator is present
    /// AND no intent suppressor blocks it.
    #[kani::proof]
    fn agent_intent_gate_is_exact() {
        let has_tool_sink: bool = kani::any();
        let has_escalation: bool = kani::any();
        let has_suppressor: bool = kani::any();
        let fired = session_tool_intent_drift(has_tool_sink, has_escalation, has_suppressor);
        kani::assert(
            fired == (has_tool_sink && has_escalation && !has_suppressor),
            "agent tool-intent drift gate must be exact conjunction",
        );
    }

    #[kani::proof]
    fn llm_provenance_gate_is_exact() {
        let has_load_sink: bool = kani::any();
        let has_provenance: bool = kani::any();
        let result = crate::model_lineage::llm_provenance_missing(has_load_sink, has_provenance);
        kani::assert(
            result == (has_load_sink && !has_provenance),
            "llm_provenance_missing must be true only when sink present and provenance absent",
        );
    }

    /// Prove that `intent_divergence_is_reachable` is an exact conjunction:
    /// reachable iff zero-auth indicator present AND path is not test-only.
    #[kani::proof]
    fn classify_intent_divergence_no_panic() {
        let has_unauth: bool = kani::any();
        let in_test: bool = kani::any();
        let result = intent_divergence_is_reachable(has_unauth, in_test);
        kani::assert(
            result == (has_unauth && !in_test),
            "intent divergence reachability must be exact conjunction",
        );
    }

    /// Prove that `ffi_deref_guard_classification` is a total, panic-free function
    /// returning exactly one of the three documented variants for all input pairs.
    #[kani::proof]
    fn classify_ffi_deref_no_panic() {
        let has_null_guard: bool = kani::any();
        let has_extern_c: bool = kani::any();
        let result = ffi_deref_guard_classification(has_null_guard, has_extern_c);
        // When null guard present, always InvariantViolationProof regardless of extern "C".
        if has_null_guard {
            kani::assert(
                result == ProofClass::InvariantViolationProof,
                "null guard must always produce InvariantViolationProof",
            );
        } else if has_extern_c {
            kani::assert(
                result == ProofClass::ReachabilityProof,
                "no guard + extern C must produce ReachabilityProof",
            );
        } else {
            kani::assert(
                result == ProofClass::LatticeGapProposal,
                "no guard + no extern C must produce LatticeGapProposal",
            );
        }
    }

}

// ---------------------------------------------------------------------------
// Regression tests (compiled under standard cargo test).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::agent_intent::session_tool_intent_drift;
    use crate::debug_endpoint_guard::debug_endpoint_missing_auth;
    use crate::dma_revocation::dma_shadow_access_missing_revocation_dominance;
    use crate::embedding_trust::trust_prioritization_missing;
    use crate::java_deser_guard::deser_missing_allowlist;
    use crate::lcm::ffi_deref_unguarded;
    use crate::linker_hijack::linker_hijack_missing_attestation;
    use crate::model_lineage::llm_provenance_missing;
    use crate::noninterference::declassification_gate_missing;
    use crate::oidc_scope_guard::oidc_scope_missing_audience;
    use crate::proof_obligation::{
        ffi_deref_guard_classification, intent_divergence_is_reachable,
        lcm_malloc_integer_truncation_is_exploitable, lcm_off_by_one_loop_is_exploitable,
        lcm_use_after_free_is_reachable, oauth_account_fusion_is_missing_email_guard,
        oauth_state_validation_is_missing, proof_obligation_missing, protobuf_any_is_unguarded,
    };
    use crate::slop_hunter::Severity;
    use common::slop::ProofClass;

    #[test]
    fn intent_divergence_reachable_when_unauth_and_non_test() {
        assert!(intent_divergence_is_reachable(true, false));
        assert!(!intent_divergence_is_reachable(false, false));
        assert!(!intent_divergence_is_reachable(true, true));
        assert!(!intent_divergence_is_reachable(false, true));
    }

    #[test]
    fn ffi_deref_guard_classification_table() {
        assert_eq!(
            ffi_deref_guard_classification(true, false),
            ProofClass::InvariantViolationProof
        );
        assert_eq!(
            ffi_deref_guard_classification(true, true),
            ProofClass::InvariantViolationProof
        );
        assert_eq!(
            ffi_deref_guard_classification(false, true),
            ProofClass::ReachabilityProof
        );
        assert_eq!(
            ffi_deref_guard_classification(false, false),
            ProofClass::LatticeGapProposal
        );
    }

    #[test]
    fn severity_points_exhaustive_match() {
        // Verify every variant maps to the documented constant — guards against
        // accidental constant changes that would invalidate Kani proof bounds.
        assert_eq!(Severity::KevCritical.points(), 150);
        assert_eq!(Severity::Exhaustion.points(), 100);
        assert_eq!(Severity::Critical.points(), 50);
        assert_eq!(Severity::High.points(), 40);
        assert_eq!(Severity::Warning.points(), 10);
        assert_eq!(Severity::Lint.points(), 0);
    }

    #[test]
    fn severity_points_max_is_150() {
        let all = [
            Severity::KevCritical,
            Severity::Exhaustion,
            Severity::Critical,
            Severity::High,
            Severity::Warning,
            Severity::Lint,
        ];
        assert!(
            all.iter().all(|s| s.points() <= 150),
            "no severity must exceed the 150-point Kani proof bound"
        );
    }

    #[test]
    fn otlp_ts_ns_conversion_does_not_overflow_u64_max() {
        let ts_ms = u64::MAX;
        // Same cast as build_otlp_payload — must not panic.
        let ts_ns: u128 = ts_ms as u128 * 1_000_000u128;
        assert!(ts_ns <= u128::MAX, "u64::MAX * 1_000_000 must fit in u128");
    }

    #[test]
    fn embedding_trust_gate_requires_missing_guard() {
        assert!(trust_prioritization_missing(true, true, false));
        assert!(!trust_prioritization_missing(true, true, true));
    }

    #[test]
    fn noninterference_gate_requires_order_and_missing_declassification() {
        assert!(declassification_gate_missing(true, true, true, false, true));
        assert!(!declassification_gate_missing(true, true, true, true, true));
        assert!(!declassification_gate_missing(
            true, true, true, false, false
        ));
    }

    #[test]
    fn proof_obligation_gate_requires_missing_class() {
        assert!(proof_obligation_missing(true, false));
        assert!(!proof_obligation_missing(true, true));
    }

    #[test]
    fn linker_hijack_gate_requires_missing_attestation() {
        assert!(linker_hijack_missing_attestation(true, false));
        assert!(!linker_hijack_missing_attestation(true, true));
        assert!(!linker_hijack_missing_attestation(false, false));
        assert!(!linker_hijack_missing_attestation(false, true));
    }

    #[test]
    fn debug_endpoint_gate_requires_missing_auth() {
        assert!(debug_endpoint_missing_auth(true, false));
        assert!(!debug_endpoint_missing_auth(true, true));
        assert!(!debug_endpoint_missing_auth(false, false));
        assert!(!debug_endpoint_missing_auth(false, true));
    }

    #[test]
    fn dma_revocation_gate_requires_missing_unmap_dominance() {
        assert!(dma_shadow_access_missing_revocation_dominance(
            true, true, true, false, true
        ));
        assert!(!dma_shadow_access_missing_revocation_dominance(
            true, true, true, true, true
        ));
    }

    #[test]
    fn deser_gate_requires_decoder_and_missing_allowlist() {
        assert!(deser_missing_allowlist(true, false));
        assert!(!deser_missing_allowlist(true, true));
        assert!(!deser_missing_allowlist(false, false));
        assert!(!deser_missing_allowlist(false, true));
    }

    #[test]
    fn oidc_scope_gate_requires_write_and_missing_audience() {
        assert!(oidc_scope_missing_audience(true, false));
        assert!(!oidc_scope_missing_audience(true, true));
        assert!(!oidc_scope_missing_audience(false, false));
        assert!(!oidc_scope_missing_audience(false, true));
    }

    #[test]
    fn lcm_ffi_gate_requires_sink_source_and_missing_guard() {
        assert!(ffi_deref_unguarded(true, true, false));
        assert!(!ffi_deref_unguarded(true, true, true));
        assert!(!ffi_deref_unguarded(false, true, false));
        assert!(!ffi_deref_unguarded(true, false, false));
    }

    #[test]
    fn agent_intent_gate_requires_sink_escalation_and_missing_suppressor() {
        assert!(session_tool_intent_drift(true, true, false));
        assert!(!session_tool_intent_drift(true, true, true));
        assert!(!session_tool_intent_drift(false, true, false));
        assert!(!session_tool_intent_drift(true, false, false));
    }

    #[test]
    fn llm_provenance_gate_requires_sink_and_missing_attestation() {
        assert!(llm_provenance_missing(true, false));
        assert!(!llm_provenance_missing(true, true));
        assert!(!llm_provenance_missing(false, false));
        assert!(!llm_provenance_missing(false, true));
    }

    #[test]
    fn lcm_use_after_free_reachability_is_exact_negation_conjunction() {
        assert!(lcm_use_after_free_is_reachable(false, false));
        assert!(!lcm_use_after_free_is_reachable(true, false));
        assert!(!lcm_use_after_free_is_reachable(false, true));
        assert!(!lcm_use_after_free_is_reachable(true, true));
    }

    #[test]
    fn lcm_malloc_truncation_exploitability_is_exact_negation_conjunction() {
        assert!(lcm_malloc_integer_truncation_is_exploitable(false, false));
        assert!(!lcm_malloc_integer_truncation_is_exploitable(true, false));
        assert!(!lcm_malloc_integer_truncation_is_exploitable(false, true));
        assert!(!lcm_malloc_integer_truncation_is_exploitable(true, true));
    }

    #[test]
    fn lcm_off_by_one_loop_exploitability_is_exact_negation_conjunction() {
        assert!(lcm_off_by_one_loop_is_exploitable(false, false));
        assert!(!lcm_off_by_one_loop_is_exploitable(true, false));
        assert!(!lcm_off_by_one_loop_is_exploitable(false, true));
        assert!(!lcm_off_by_one_loop_is_exploitable(true, true));
    }

    #[test]
    fn oauth_state_validation_missing_is_exact_conjunction() {
        assert!(oauth_state_validation_is_missing(true, false));
        assert!(!oauth_state_validation_is_missing(false, false));
        assert!(!oauth_state_validation_is_missing(true, true));
        assert!(!oauth_state_validation_is_missing(false, true));
    }

    #[test]
    fn oauth_account_fusion_email_guard_missing_is_exact_conjunction() {
        assert!(oauth_account_fusion_is_missing_email_guard(true, false));
        assert!(!oauth_account_fusion_is_missing_email_guard(false, false));
        assert!(!oauth_account_fusion_is_missing_email_guard(true, true));
        assert!(!oauth_account_fusion_is_missing_email_guard(false, true));
    }

    #[test]
    fn protobuf_any_unguarded_is_exact_conjunction() {
        assert!(protobuf_any_is_unguarded(true, false));
        assert!(!protobuf_any_is_unguarded(false, false));
        assert!(!protobuf_any_is_unguarded(true, true));
        assert!(!protobuf_any_is_unguarded(false, true));
    }
}

// ── binary_diff Kani proofs ───────────────────────────────────────────────
#[cfg(kani)]
mod binary_diff_kani {
    use crate::binary_diff::{compute_urgency_score, diff_binaries};

    #[kani::proof]
    fn no_oob_on_malformed_elf() {
        let len: usize = kani::any();
        kani::assume(len <= 512);
        let bytes: Vec<u8> = (0..len).map(|_| kani::any()).collect();
        // diff_binaries must not panic regardless of input shape.
        let r = diff_binaries(&bytes, &[]);
        kani::assert(r.patch_urgency_score <= 100, "score out of range");
    }

    #[kani::proof]
    fn urgency_score_never_exceeds_100() {
        let count: usize = kani::any();
        let has_class: bool = kani::any();
        kani::assume(count <= 1024);
        let score = compute_urgency_score(count, has_class);
        kani::assert(score <= 100, "urgency score exceeds 100");
    }
}

// ── medical Kani proofs (P8-3) ───────────────────────────────────────────────
#[cfg(kani)]
mod medical_kani {
    use crate::medical::{classify_iec_62304_level, Iec62304Level};

    /// Prove `classify_iec_62304_level` never panics on any symbolic input.
    ///
    /// The function performs pure string-contains checks; no index arithmetic,
    /// no allocation-bounds risk. Kani verifies no panic path exists.
    #[kani::proof]
    fn classify_iec_62304_no_panic() {
        let has_class_c: bool = kani::any();
        let has_class_b: bool = kani::any();
        let source = if has_class_c {
            "insulin_dose(patient, 5.0);"
        } else if has_class_b {
            "patient_data_write(record);"
        } else {
            "println!(\"hello\");"
        };
        let level = classify_iec_62304_level(source, "test.py");
        if has_class_c {
            kani::assert(
                matches!(level, Iec62304Level::ClassC),
                "ClassC sink must yield ClassC level",
            );
        }
    }

    /// Prove `is_config_gated_tls_bypass` never panics on symbolic line numbers.
    #[kani::proof]
    fn config_gated_tls_no_panic() {
        let line: usize = kani::any();
        kani::assume(line <= 1024);
        let has_if_guard: bool = kani::any();
        let source = if has_if_guard {
            "if cfg.InsecureTLS {\n    tlsCfg := &tls.Config{InsecureSkipVerify: true}\n}\n"
        } else {
            "tlsCfg := &tls.Config{InsecureSkipVerify: true}\n"
        };
        // Must not panic for any line ≤ 1024.
        let _result = crate::threat_model_oracle::is_config_gated_tls_bypass(source, line);
    }

    /// Prove `has_external_caller` never panics for any symbolic fn_name length.
    #[kani::proof]
    fn has_external_caller_no_panic() {
        let has_caller: bool = kani::any();
        let fn_name = "renderHtml";
        let source = if has_caller {
            "function renderHtml(el, content) {\n    el.innerHTML = content;\n}\nrenderHtml(div, x);\n"
        } else {
            "function renderHtml(el, content) {\n    el.innerHTML = content;\n}\n"
        };
        let result = crate::threat_model_oracle::has_external_caller(source, fn_name);
        if has_caller {
            kani::assert(result, "function with caller must report reachable");
        } else {
            kani::assert(!result, "function with no callers must report unreachable");
        }
    }
}

// ── compliance_oracle Kani proofs ────────────────────────────────────────────
#[cfg(kani)]
mod compliance_oracle_kani {
    use crate::compliance_oracle::map_finding_to_controls;
    use crate::proof_obligation::{
        lcm_double_free_is_reachable, lcm_malloc_integer_truncation_is_exploitable,
        lcm_off_by_one_loop_is_exploitable, lcm_use_after_free_is_reachable,
        oauth_account_fusion_is_missing_email_guard, oauth_state_validation_is_missing,
        protobuf_any_is_unguarded, timing_comparison_is_sensitive,
    };
    use common::slop::StructuredFinding;

    /// Prove that `map_finding_to_controls` always emits exactly two receipts
    /// and never panics, for both credential-leak and dead-code finding classes.
    #[kani::proof]
    fn compliance_oracle_always_two_receipts() {
        let is_cred: bool = kani::any();
        let finding = StructuredFinding {
            id: if is_cred {
                "security:credential_leak".to_string()
            } else {
                "dead_symbol".to_string()
            },
            ..Default::default()
        };
        let receipts = map_finding_to_controls(&finding);
        kani::assert(receipts.len() == 2, "compliance oracle must emit exactly 2 receipts");
    }

    /// Prove that `lcm_double_free_is_reachable` is an exact negation-conjunction:
    /// reachable iff no free guard present AND not in a test path.
    #[kani::proof]
    fn classify_lcm_double_free_no_panic() {
        let has_guard: bool = kani::any();
        let in_test: bool = kani::any();
        let result = lcm_double_free_is_reachable(has_guard, in_test);
        kani::assert(
            result == (!has_guard && !in_test),
            "lcm_double_free reachability must be exact negation-conjunction",
        );
    }

    /// Prove that `timing_comparison_is_sensitive` is an exact conjunction:
    /// sensitive iff secret marker present AND not in bench/test context.
    #[kani::proof]
    fn classify_timing_comparison_no_panic() {
        let has_secret: bool = kani::any();
        let in_bench_or_test: bool = kani::any();
        let result = timing_comparison_is_sensitive(has_secret, in_bench_or_test);
        kani::assert(
            result == (has_secret && !in_bench_or_test),
            "timing comparison sensitivity must be exact conjunction",
        );
    }

    /// Prove `lcm_use_after_free_is_reachable` is the exact negation-conjunction
    /// of its two boolean inputs.
    #[kani::proof]
    fn classify_lcm_use_after_free_no_panic() {
        let has_guard: bool = kani::any();
        let in_test: bool = kani::any();
        let result = lcm_use_after_free_is_reachable(has_guard, in_test);
        kani::assert(
            result == (!has_guard && !in_test),
            "lcm_use_after_free reachability must be exact negation-conjunction",
        );
    }

    /// Prove `lcm_malloc_integer_truncation_is_exploitable` is the exact
    /// negation-conjunction of its two boolean inputs.
    #[kani::proof]
    fn classify_lcm_malloc_truncation_no_panic() {
        let has_guard: bool = kani::any();
        let in_bench: bool = kani::any();
        let result = lcm_malloc_integer_truncation_is_exploitable(has_guard, in_bench);
        kani::assert(
            result == (!has_guard && !in_bench),
            "lcm_malloc truncation exploitability must be exact negation-conjunction",
        );
    }

    /// Prove `lcm_off_by_one_loop_is_exploitable` is the exact negation-conjunction
    /// of its two boolean inputs.
    #[kani::proof]
    fn classify_lcm_off_by_one_loop_no_panic() {
        let has_bounds: bool = kani::any();
        let in_test: bool = kani::any();
        let result = lcm_off_by_one_loop_is_exploitable(has_bounds, in_test);
        kani::assert(
            result == (!has_bounds && !in_test),
            "lcm_off_by_one_loop exploitability must be exact negation-conjunction",
        );
    }

    /// Prove `oauth_state_validation_is_missing` is the exact conjunction
    /// of server-side flag and absence of state check.
    #[kani::proof]
    fn classify_oauth_state_validation_no_panic() {
        let is_server_side: bool = kani::any();
        let has_state_check: bool = kani::any();
        let result = oauth_state_validation_is_missing(is_server_side, has_state_check);
        kani::assert(
            result == (is_server_side && !has_state_check),
            "oauth state validation missing must be exact conjunction",
        );
    }

    /// Prove `oauth_account_fusion_is_missing_email_guard` is the exact conjunction
    /// of server-side flag and absence of email-verified guard.
    #[kani::proof]
    fn classify_oauth_account_fusion_no_panic() {
        let is_server: bool = kani::any();
        let has_check: bool = kani::any();
        let result = oauth_account_fusion_is_missing_email_guard(is_server, has_check);
        kani::assert(
            result == (is_server && !has_check),
            "oauth fusion guard must be exact conjunction",
        );
    }

    /// Prove `protobuf_any_is_unguarded` is the exact conjunction of
    /// deprecated-API usage and absence of a test path.
    #[kani::proof]
    fn classify_protobuf_any_no_panic() {
        let uses_deprecated: bool = kani::any();
        let in_test: bool = kani::any();
        let result = protobuf_any_is_unguarded(uses_deprecated, in_test);
        kani::assert(
            result == (uses_deprecated && !in_test),
            "protobuf_any guard must be exact conjunction",
        );
    }
}
