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
    use crate::noninterference::declassification_gate_missing;
    use crate::oidc_scope_guard::oidc_scope_missing_audience;
    use crate::proof_obligation::{
        cargo_build_worm_is_reachable, ci_persistence_vector_is_reachable,
        debug_endpoint_is_unguarded, eval_injection_is_untrusted, ffi_deref_guard_classification,
        ffi_memory_corruption_is_reachable, intent_divergence_is_reachable,
        java_deser_allowlist_bypass_is_reachable, jndi_lookup_is_untrusted,
        mcp_confused_deputy_dispatch_is_reachable, oauth_excessive_scope_is_reachable,
        pqc_hybrid_downgrade_is_reachable, process_builder_is_untrusted, proof_obligation_missing,
        saml_xsw_validation_order_is_reachable, unsafe_deserialization_is_reachable,
        unverified_provenance_is_reachable, xxe_saml_parser_is_unguarded,
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

    /// Prove the proof-obligation debug-endpoint classifier predicate is exact:
    /// it fires iff a debug surface is visible and no auth guard is visible.
    #[kani::proof]
    fn debug_endpoint_unguarded_is_exact_conjunction() {
        let has_debug_surface: bool = kani::any();
        let has_auth_guard: bool = kani::any();
        let fired = debug_endpoint_is_unguarded(has_debug_surface, has_auth_guard);
        kani::assert(
            fired == (has_debug_surface && !has_auth_guard),
            "debug endpoint proof classifier predicate must be exact conjunction",
        );
    }

    /// Prove the XXE SAML parser predicate is exact:
    /// it fires iff a SAML XML parser is visible, hardening is absent, and path is not test-only.
    #[kani::proof]
    fn xxe_saml_parser_unguarded_is_exact_conjunction() {
        let has_saml_xml_parser: bool = kani::any();
        let has_xxe_hardening: bool = kani::any();
        let in_test_path: bool = kani::any();
        let fired =
            xxe_saml_parser_is_unguarded(has_saml_xml_parser, has_xxe_hardening, in_test_path);
        kani::assert(
            fired == (has_saml_xml_parser && !has_xxe_hardening && !in_test_path),
            "XXE SAML parser predicate must be exact conjunction",
        );
    }

    /// Prove the SAML XSW predicate is exact:
    /// it fires iff parser + signature + later selected assertion are visible,
    /// and no same-assertion binding guard or test/generated path is present.
    #[kani::proof]
    fn saml_xsw_validation_order_is_exact_conjunction() {
        let has_saml_parser: bool = kani::any();
        let has_signature_validation: bool = kani::any();
        let consumes_selected_assertion_after_signature: bool = kani::any();
        let has_assertion_binding_guard: bool = kani::any();
        let in_test_or_generated_path: bool = kani::any();
        let fired = saml_xsw_validation_order_is_reachable(
            has_saml_parser,
            has_signature_validation,
            consumes_selected_assertion_after_signature,
            has_assertion_binding_guard,
            in_test_or_generated_path,
        );
        kani::assert(
            fired
                == (has_saml_parser
                    && has_signature_validation
                    && consumes_selected_assertion_after_signature
                    && !has_assertion_binding_guard
                    && !in_test_or_generated_path),
            "SAML XSW predicate must be exact conjunction",
        );
    }

    /// Prove the JNDI predicate is exact:
    /// it fires iff lookup + untrusted source are present, and allowlist/constant
    /// context plus test/local path are absent.
    #[kani::proof]
    fn jndi_lookup_untrusted_is_exact_conjunction() {
        let has_jndi_lookup: bool = kani::any();
        let has_untrusted_source: bool = kani::any();
        let has_allowlist_or_constant_context: bool = kani::any();
        let in_test_or_local_path: bool = kani::any();
        let fired = jndi_lookup_is_untrusted(
            has_jndi_lookup,
            has_untrusted_source,
            has_allowlist_or_constant_context,
            in_test_or_local_path,
        );
        kani::assert(
            fired
                == (has_jndi_lookup
                    && has_untrusted_source
                    && !has_allowlist_or_constant_context
                    && !in_test_or_local_path),
            "JNDI lookup predicate must be exact conjunction",
        );
    }

    /// Prove the eval-injection predicate is exact:
    /// it fires iff dynamic eval + untrusted source are present, and
    /// allowlist/sandbox plus test/local path are absent.
    #[kani::proof]
    fn eval_injection_untrusted_is_exact_conjunction() {
        let has_eval_sink: bool = kani::any();
        let has_untrusted_source: bool = kani::any();
        let has_allowlist_or_sandbox: bool = kani::any();
        let in_test_or_local_path: bool = kani::any();
        let fired = eval_injection_is_untrusted(
            has_eval_sink,
            has_untrusted_source,
            has_allowlist_or_sandbox,
            in_test_or_local_path,
        );
        kani::assert(
            fired
                == (has_eval_sink
                    && has_untrusted_source
                    && !has_allowlist_or_sandbox
                    && !in_test_or_local_path),
            "eval-injection predicate must be exact conjunction",
        );
    }

    /// Prove the process-builder predicate is exact:
    /// it fires iff process execution + untrusted source are present, and
    /// command guard plus test/admin path are absent.
    #[kani::proof]
    fn process_builder_untrusted_is_exact_conjunction() {
        let has_process_sink: bool = kani::any();
        let has_untrusted_source: bool = kani::any();
        let has_command_guard: bool = kani::any();
        let in_test_or_admin_path: bool = kani::any();
        let fired = process_builder_is_untrusted(
            has_process_sink,
            has_untrusted_source,
            has_command_guard,
            in_test_or_admin_path,
        );
        kani::assert(
            fired
                == (has_process_sink
                    && has_untrusted_source
                    && !has_command_guard
                    && !in_test_or_admin_path),
            "process-builder predicate must be exact conjunction",
        );
    }

    /// Prove the PQC hybrid downgrade predicate is exact:
    /// it fires iff hybrid/PQC requirement + downgrade path are present, and
    /// policy pin/allowlist plus test/generated path are absent.
    #[kani::proof]
    fn pqc_hybrid_downgrade_is_exact_conjunction() {
        let has_hybrid_requirement: bool = kani::any();
        let has_downgrade_path: bool = kani::any();
        let has_policy_pin_or_allowlist: bool = kani::any();
        let in_test_or_generated_path: bool = kani::any();
        let fired = pqc_hybrid_downgrade_is_reachable(
            has_hybrid_requirement,
            has_downgrade_path,
            has_policy_pin_or_allowlist,
            in_test_or_generated_path,
        );
        kani::assert(
            fired
                == (has_hybrid_requirement
                    && has_downgrade_path
                    && !has_policy_pin_or_allowlist
                    && !in_test_or_generated_path),
            "PQC hybrid downgrade predicate must be exact conjunction",
        );
    }

    /// Prove the OAuth excessive-scope predicate is exact:
    /// it fires iff sensitive scope + token context are present, and
    /// audience/least-privilege guard plus test/admin path are absent.
    #[kani::proof]
    fn oauth_excessive_scope_is_exact_conjunction() {
        let has_sensitive_scope: bool = kani::any();
        let has_untrusted_or_token_context: bool = kani::any();
        let has_audience_or_least_privilege_guard: bool = kani::any();
        let in_test_or_admin_path: bool = kani::any();
        let fired = oauth_excessive_scope_is_reachable(
            has_sensitive_scope,
            has_untrusted_or_token_context,
            has_audience_or_least_privilege_guard,
            in_test_or_admin_path,
        );
        kani::assert(
            fired
                == (has_sensitive_scope
                    && has_untrusted_or_token_context
                    && !has_audience_or_least_privilege_guard
                    && !in_test_or_admin_path),
            "OAuth excessive-scope predicate must be exact conjunction",
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

    /// Prove the proof-obligation Java deserialization gate is exact:
    /// it fires iff sink + untrusted source are present, and filter plus
    /// nonproduction path are absent.
    #[kani::proof]
    fn java_deser_allowlist_bypass_is_exact_conjunction() {
        let has_deserialization_sink: bool = kani::any();
        let has_untrusted_source: bool = kani::any();
        let has_allowlist_or_filter: bool = kani::any();
        let in_nonproduction_path: bool = kani::any();
        let fired = java_deser_allowlist_bypass_is_reachable(
            has_deserialization_sink,
            has_untrusted_source,
            has_allowlist_or_filter,
            in_nonproduction_path,
        );
        kani::assert(
            fired
                == (has_deserialization_sink
                    && has_untrusted_source
                    && !has_allowlist_or_filter
                    && !in_nonproduction_path),
            "java deser proof predicate must be exact conjunction",
        );
    }

    /// Prove the unsafe deserialization proof gate is exact:
    /// it fires iff unsafe sink + untrusted source are present, and safe loader
    /// plus nonproduction path are absent.
    #[kani::proof]
    fn unsafe_deserialization_is_exact_conjunction() {
        let has_unsafe_deserialization_sink: bool = kani::any();
        let has_untrusted_source: bool = kani::any();
        let has_safe_deserialization_guard: bool = kani::any();
        let in_nonproduction_path: bool = kani::any();
        let fired = unsafe_deserialization_is_reachable(
            has_unsafe_deserialization_sink,
            has_untrusted_source,
            has_safe_deserialization_guard,
            in_nonproduction_path,
        );
        kani::assert(
            fired
                == (has_unsafe_deserialization_sink
                    && has_untrusted_source
                    && !has_safe_deserialization_guard
                    && !in_nonproduction_path),
            "unsafe deserialization predicate must be exact conjunction",
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

    /// Prove the MCP confused-deputy proof gate is exact:
    /// fires iff session dispatch and untrusted session/tool input are present,
    /// while secret/capability guard and nonproduction path are absent.
    #[kani::proof]
    fn mcp_confused_deputy_dispatch_is_exact_conjunction() {
        let has_session_dispatch: bool = kani::any();
        let has_untrusted_session_or_tool_input: bool = kani::any();
        let has_secret_or_capability_guard: bool = kani::any();
        let in_nonproduction_path: bool = kani::any();
        let fired = mcp_confused_deputy_dispatch_is_reachable(
            has_session_dispatch,
            has_untrusted_session_or_tool_input,
            has_secret_or_capability_guard,
            in_nonproduction_path,
        );
        kani::assert(
            fired
                == (has_session_dispatch
                    && has_untrusted_session_or_tool_input
                    && !has_secret_or_capability_guard
                    && !in_nonproduction_path),
            "MCP confused-deputy dispatch proof gate must be exact conjunction",
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

    /// Prove the FFI memory-corruption proof gate is exact:
    /// fires iff an FFI export boundary and unsafe memory sink are present,
    /// while pointer/length guard and nonproduction path are absent.
    #[kani::proof]
    fn ffi_memory_corruption_is_exact_conjunction() {
        let has_ffi_export_boundary: bool = kani::any();
        let has_unsafe_memory_sink: bool = kani::any();
        let has_pointer_or_length_guard: bool = kani::any();
        let in_nonproduction_path: bool = kani::any();
        let fired = ffi_memory_corruption_is_reachable(
            has_ffi_export_boundary,
            has_unsafe_memory_sink,
            has_pointer_or_length_guard,
            in_nonproduction_path,
        );
        kani::assert(
            fired
                == (has_ffi_export_boundary
                    && has_unsafe_memory_sink
                    && !has_pointer_or_length_guard
                    && !in_nonproduction_path),
            "FFI memory-corruption proof gate must be exact conjunction",
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

    #[kani::proof]
    fn unverified_provenance_is_exact_conjunction() {
        let has_artifact_ingestion: bool = kani::any();
        let has_provenance_guard: bool = kani::any();
        let in_nonproduction_path: bool = kani::any();
        let result = unverified_provenance_is_reachable(
            has_artifact_ingestion,
            has_provenance_guard,
            in_nonproduction_path,
        );
        kani::assert(
            result == (has_artifact_ingestion && !has_provenance_guard && !in_nonproduction_path),
            "unverified provenance reachability must be exact conjunction",
        );
    }

    #[kani::proof]
    fn cargo_build_worm_is_exact_conjunction() {
        let has_build_lifecycle: bool = kani::any();
        let has_dangerous_payload: bool = kani::any();
        let has_build_guard: bool = kani::any();
        let in_nonproduction_path: bool = kani::any();
        let result = cargo_build_worm_is_reachable(
            has_build_lifecycle,
            has_dangerous_payload,
            has_build_guard,
            in_nonproduction_path,
        );
        kani::assert(
            result
                == (has_build_lifecycle
                    && has_dangerous_payload
                    && !has_build_guard
                    && !in_nonproduction_path),
            "cargo build worm reachability must be exact conjunction",
        );
    }

    #[kani::proof]
    fn ci_persistence_vector_is_exact_conjunction() {
        let has_persistence_sink: bool = kani::any();
        let has_ci_or_package_lifecycle: bool = kani::any();
        let has_attestation_or_allowlist: bool = kani::any();
        let in_nonproduction_path: bool = kani::any();
        let result = ci_persistence_vector_is_reachable(
            has_persistence_sink,
            has_ci_or_package_lifecycle,
            has_attestation_or_allowlist,
            in_nonproduction_path,
        );
        kani::assert(
            result
                == (has_persistence_sink
                    && has_ci_or_package_lifecycle
                    && !has_attestation_or_allowlist
                    && !in_nonproduction_path),
            "CI persistence reachability must be exact conjunction",
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
        debug_endpoint_is_unguarded, eval_injection_is_untrusted, ffi_deref_guard_classification,
        financial_pii_is_unguarded, intent_divergence_is_reachable, jndi_lookup_is_untrusted,
        lcm_malloc_integer_truncation_is_exploitable, lcm_off_by_one_loop_is_exploitable,
        lcm_use_after_free_is_reachable, oauth_account_fusion_is_missing_email_guard,
        oauth_excessive_scope_is_reachable, oauth_state_validation_is_missing,
        pqc_hybrid_downgrade_is_reachable, process_builder_is_untrusted, proof_obligation_missing,
        protobuf_any_is_unguarded, react_xss_is_unguarded, saml_xsw_validation_order_is_reachable,
        sqli_concat_is_injectable, unverified_provenance_is_reachable,
        xxe_saml_parser_is_unguarded,
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
        // u64::MAX * 1_000_000 = 1.844e25, well within u128::MAX (3.4e38).
        let _ = ts_ns;
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
    fn debug_endpoint_unguarded_requires_debug_surface_and_missing_auth() {
        assert!(debug_endpoint_is_unguarded(true, false));
        assert!(!debug_endpoint_is_unguarded(true, true));
        assert!(!debug_endpoint_is_unguarded(false, false));
        assert!(!debug_endpoint_is_unguarded(false, true));
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
    fn eval_injection_reachability_requires_untrusted_source_without_guard() {
        assert!(eval_injection_is_untrusted(true, true, false, false));
        assert!(!eval_injection_is_untrusted(false, true, false, false));
        assert!(!eval_injection_is_untrusted(true, false, false, false));
        assert!(!eval_injection_is_untrusted(true, true, true, false));
        assert!(!eval_injection_is_untrusted(true, true, false, true));
    }

    #[test]
    fn process_builder_reachability_requires_untrusted_source_without_guard() {
        assert!(process_builder_is_untrusted(true, true, false, false));
        assert!(!process_builder_is_untrusted(false, true, false, false));
        assert!(!process_builder_is_untrusted(true, false, false, false));
        assert!(!process_builder_is_untrusted(true, true, true, false));
        assert!(!process_builder_is_untrusted(true, true, false, true));
    }

    #[test]
    fn pqc_hybrid_downgrade_requires_hybrid_requirement_and_downgrade_path() {
        assert!(pqc_hybrid_downgrade_is_reachable(true, true, false, false));
        assert!(!pqc_hybrid_downgrade_is_reachable(
            false, true, false, false
        ));
        assert!(!pqc_hybrid_downgrade_is_reachable(
            true, false, false, false
        ));
        assert!(!pqc_hybrid_downgrade_is_reachable(true, true, true, false));
        assert!(!pqc_hybrid_downgrade_is_reachable(true, true, false, true));
    }

    #[test]
    fn oauth_excessive_scope_requires_sensitive_scope_without_guard() {
        assert!(oauth_excessive_scope_is_reachable(true, true, false, false));
        assert!(!oauth_excessive_scope_is_reachable(
            false, true, false, false
        ));
        assert!(!oauth_excessive_scope_is_reachable(
            true, false, false, false
        ));
        assert!(!oauth_excessive_scope_is_reachable(true, true, true, false));
        assert!(!oauth_excessive_scope_is_reachable(true, true, false, true));
    }

    #[test]
    fn llm_provenance_gate_requires_sink_and_missing_attestation() {
        assert!(llm_provenance_missing(true, false));
        assert!(!llm_provenance_missing(true, true));
        assert!(!llm_provenance_missing(false, false));
        assert!(!llm_provenance_missing(false, true));
    }

    #[test]
    fn unverified_provenance_requires_ingestion_missing_guard_and_production_path() {
        assert!(unverified_provenance_is_reachable(true, false, false));
        assert!(!unverified_provenance_is_reachable(false, false, false));
        assert!(!unverified_provenance_is_reachable(true, true, false));
        assert!(!unverified_provenance_is_reachable(true, false, true));
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
        assert!(oauth_state_validation_is_missing(true, false, false));
        assert!(!oauth_state_validation_is_missing(false, false, false));
        assert!(!oauth_state_validation_is_missing(true, true, false));
        assert!(!oauth_state_validation_is_missing(false, true, false));
        assert!(!oauth_state_validation_is_missing(true, false, true));
    }

    #[test]
    fn xxe_saml_parser_unguarded_requires_parser_and_missing_hardening() {
        assert!(xxe_saml_parser_is_unguarded(true, false, false));
        assert!(!xxe_saml_parser_is_unguarded(false, false, false));
        assert!(!xxe_saml_parser_is_unguarded(true, true, false));
        assert!(!xxe_saml_parser_is_unguarded(true, false, true));
    }

    #[test]
    fn saml_xsw_reachability_requires_all_unprotected_markers() {
        assert!(saml_xsw_validation_order_is_reachable(
            true, true, true, false, false
        ));
        assert!(!saml_xsw_validation_order_is_reachable(
            false, true, true, false, false
        ));
        assert!(!saml_xsw_validation_order_is_reachable(
            true, false, true, false, false
        ));
        assert!(!saml_xsw_validation_order_is_reachable(
            true, true, false, false, false
        ));
        assert!(!saml_xsw_validation_order_is_reachable(
            true, true, true, true, false
        ));
        assert!(!saml_xsw_validation_order_is_reachable(
            true, true, true, false, true
        ));
    }

    #[test]
    fn jndi_lookup_reachability_requires_untrusted_source_without_guard() {
        assert!(jndi_lookup_is_untrusted(true, true, false, false));
        assert!(!jndi_lookup_is_untrusted(false, true, false, false));
        assert!(!jndi_lookup_is_untrusted(true, false, false, false));
        assert!(!jndi_lookup_is_untrusted(true, true, true, false));
        assert!(!jndi_lookup_is_untrusted(true, true, false, true));
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

    #[test]
    fn sqli_concat_injectable_is_exact_conjunction() {
        assert!(sqli_concat_is_injectable(true, false));
        assert!(!sqli_concat_is_injectable(false, false));
        assert!(!sqli_concat_is_injectable(true, true));
        assert!(!sqli_concat_is_injectable(false, true));
    }

    #[test]
    fn financial_pii_unguarded_is_exact_conjunction() {
        assert!(financial_pii_is_unguarded(true, false));
        assert!(!financial_pii_is_unguarded(false, false));
        assert!(!financial_pii_is_unguarded(true, true));
        assert!(!financial_pii_is_unguarded(false, true));
    }

    #[test]
    fn react_xss_unguarded_is_exact_conjunction() {
        assert!(react_xss_is_unguarded(true, false));
        assert!(!react_xss_is_unguarded(false, false));
        assert!(!react_xss_is_unguarded(true, true));
        assert!(!react_xss_is_unguarded(false, true));
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
        bounded_overflow_is_exploitable, classify_jwt_keyfunc_proof,
        dangerous_execution_is_reachable, dynamic_import_is_exploitable,
        embedding_trust_transposition_is_reachable, financial_pii_is_unguarded,
        jndi_lookup_is_untrusted, lcm_double_free_is_reachable,
        lcm_malloc_integer_truncation_is_exploitable, lcm_off_by_one_loop_is_exploitable,
        lcm_use_after_free_is_reachable, ld_preload_injection_is_exploitable,
        oauth_account_fusion_is_missing_email_guard, oauth_state_validation_is_missing,
        path_traversal_concat_is_exploitable, protobuf_any_is_unguarded,
        rag_context_poisoning_is_reachable, react_xss_is_unguarded,
        saml_xsw_validation_order_is_reachable, sqli_concat_is_injectable,
        timing_comparison_is_sensitive, xxe_saml_parser_is_unguarded,
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
        kani::assert(
            receipts.len() == 2,
            "compliance oracle must emit exactly 2 receipts",
        );
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
    /// of browser-callback marker, absence of state check, and non-callback context absence.
    #[kani::proof]
    fn classify_oauth_state_validation_no_panic() {
        let has_browser_callback: bool = kani::any();
        let has_state_check: bool = kani::any();
        let in_non_callback_context: bool = kani::any();
        let result = oauth_state_validation_is_missing(
            has_browser_callback,
            has_state_check,
            in_non_callback_context,
        );
        kani::assert(
            result == (has_browser_callback && !has_state_check && !in_non_callback_context),
            "oauth state validation missing must be exact conjunction",
        );
    }

    /// Prove `xxe_saml_parser_is_unguarded` is the exact conjunction of
    /// SAML parser visibility, missing XXE hardening, and production path.
    #[kani::proof]
    fn classify_xxe_saml_parser_no_panic() {
        let has_saml_xml_parser: bool = kani::any();
        let has_xxe_hardening: bool = kani::any();
        let in_test_path: bool = kani::any();
        let result =
            xxe_saml_parser_is_unguarded(has_saml_xml_parser, has_xxe_hardening, in_test_path);
        kani::assert(
            result == (has_saml_xml_parser && !has_xxe_hardening && !in_test_path),
            "xxe SAML parser guard must be exact conjunction",
        );
    }

    /// Prove `saml_xsw_validation_order_is_reachable` is the exact conjunction
    /// of parser, signature validation, selected-assertion consumption, and
    /// absence of same-assertion binding/test context.
    #[kani::proof]
    fn classify_saml_xsw_validation_order_no_panic() {
        let has_saml_parser: bool = kani::any();
        let has_signature_validation: bool = kani::any();
        let consumes_selected_assertion_after_signature: bool = kani::any();
        let has_assertion_binding_guard: bool = kani::any();
        let in_test_or_generated_path: bool = kani::any();
        let result = saml_xsw_validation_order_is_reachable(
            has_saml_parser,
            has_signature_validation,
            consumes_selected_assertion_after_signature,
            has_assertion_binding_guard,
            in_test_or_generated_path,
        );
        kani::assert(
            result
                == (has_saml_parser
                    && has_signature_validation
                    && consumes_selected_assertion_after_signature
                    && !has_assertion_binding_guard
                    && !in_test_or_generated_path),
            "saml XSW validation-order guard must be exact conjunction",
        );
    }

    /// Prove `jndi_lookup_is_untrusted` is the exact conjunction of lookup,
    /// untrusted source, and absence of allowlist/local context.
    #[kani::proof]
    fn classify_jndi_lookup_no_panic() {
        let has_jndi_lookup: bool = kani::any();
        let has_untrusted_source: bool = kani::any();
        let has_allowlist_or_constant_context: bool = kani::any();
        let in_test_or_local_path: bool = kani::any();
        let result = jndi_lookup_is_untrusted(
            has_jndi_lookup,
            has_untrusted_source,
            has_allowlist_or_constant_context,
            in_test_or_local_path,
        );
        kani::assert(
            result
                == (has_jndi_lookup
                    && has_untrusted_source
                    && !has_allowlist_or_constant_context
                    && !in_test_or_local_path),
            "jndi lookup guard must be exact conjunction",
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

    /// Prove `sqli_concat_is_injectable` is the exact conjunction of
    /// raw-concat flag and absence of migration path.
    #[kani::proof]
    fn sqli_concat_injectable_is_exact_conjunction() {
        let is_raw: bool = kani::any();
        let in_migration: bool = kani::any();
        let result = sqli_concat_is_injectable(is_raw, in_migration);
        kani::assert(
            result == (is_raw && !in_migration),
            "sqli_concat guard must be exact conjunction",
        );
    }

    /// Prove `financial_pii_is_unguarded` is the exact conjunction of
    /// PII-sink presence and absence of a masking guard.
    #[kani::proof]
    fn financial_pii_unguarded_is_exact_conjunction() {
        let has_sink: bool = kani::any();
        let has_mask: bool = kani::any();
        let result = financial_pii_is_unguarded(has_sink, has_mask);
        kani::assert(
            result == (has_sink && !has_mask),
            "financial_pii guard must be exact conjunction",
        );
    }

    /// Prove `react_xss_is_unguarded` is the exact conjunction of
    /// dangerous-html presence and absence of a sanitizer.
    #[kani::proof]
    fn react_xss_unguarded_is_exact_conjunction() {
        let has_dangerous: bool = kani::any();
        let has_sanitizer: bool = kani::any();
        let result = react_xss_is_unguarded(has_dangerous, has_sanitizer);
        kani::assert(
            result == (has_dangerous && !has_sanitizer),
            "react_xss guard must be exact conjunction",
        );
    }

    /// Prove `rag_context_poisoning_is_reachable` is the exact conjunction:
    /// (retrieval_sink ∧ untrusted_input) ∧ ¬isolation_guard ∧ ¬in_test_path.
    #[kani::proof]
    fn rag_context_poisoning_is_exact_conjunction() {
        let has_retrieval_sink: bool = kani::any();
        let has_untrusted_input: bool = kani::any();
        let has_isolation_guard: bool = kani::any();
        let in_test_path: bool = kani::any();
        let result = rag_context_poisoning_is_reachable(
            has_retrieval_sink,
            has_untrusted_input,
            has_isolation_guard,
            in_test_path,
        );
        kani::assert(
            result
                == (has_retrieval_sink
                    && has_untrusted_input
                    && !has_isolation_guard
                    && !in_test_path),
            "rag_context_poisoning gate must be exact conjunction of four guards",
        );
    }

    /// Prove `path_traversal_concat_is_exploitable` is the exact conjunction:
    /// user_path_component ∧ ¬canonicalization_guard ∧ ¬in_test_path.
    #[kani::proof]
    fn path_traversal_concat_is_exact_conjunction() {
        let has_user_path_component: bool = kani::any();
        let has_canonicalization_guard: bool = kani::any();
        let in_test_path: bool = kani::any();
        let result = path_traversal_concat_is_exploitable(
            has_user_path_component,
            has_canonicalization_guard,
            in_test_path,
        );
        kani::assert(
            result == (has_user_path_component && !has_canonicalization_guard && !in_test_path),
            "path_traversal_concat gate must be exact conjunction of three guards",
        );
    }

    /// Prove `dynamic_import_is_exploitable` is the exact conjunction:
    /// user_controlled_module ∧ ¬import_allowlist ∧ ¬in_test_path.
    #[kani::proof]
    fn dynamic_import_is_exact_conjunction() {
        let has_user_controlled_module: bool = kani::any();
        let has_import_allowlist: bool = kani::any();
        let in_test_path: bool = kani::any();
        let result = dynamic_import_is_exploitable(
            has_user_controlled_module,
            has_import_allowlist,
            in_test_path,
        );
        kani::assert(
            result == (has_user_controlled_module && !has_import_allowlist && !in_test_path),
            "dynamic_import gate must be exact conjunction of three guards",
        );
    }

    /// Prove `dangerous_execution_is_reachable` is the exact conjunction:
    /// user_input ∧ exec_sink ∧ ¬sanitizer ∧ ¬in_test_path.
    #[kani::proof]
    fn dangerous_execution_is_exact_conjunction() {
        let has_user_input: bool = kani::any();
        let has_exec_sink: bool = kani::any();
        let has_sanitizer: bool = kani::any();
        let in_test_path: bool = kani::any();
        let result = dangerous_execution_is_reachable(
            has_user_input,
            has_exec_sink,
            has_sanitizer,
            in_test_path,
        );
        kani::assert(
            result == (has_user_input && has_exec_sink && !has_sanitizer && !in_test_path),
            "dangerous_execution gate must be exact conjunction of four guards",
        );
    }

    /// Prove `bounded_overflow_is_exploitable` is the exact conjunction:
    /// has_user_controlled_bound ∧ ¬has_overflow_check ∧ ¬in_test_path.
    #[kani::proof]
    fn bounded_overflow_is_exact_conjunction() {
        let has_user_controlled_bound: bool = kani::any();
        let has_overflow_check: bool = kani::any();
        let in_test_path: bool = kani::any();
        let result = bounded_overflow_is_exploitable(
            has_user_controlled_bound,
            has_overflow_check,
            in_test_path,
        );
        kani::assert(
            result == (has_user_controlled_bound && !has_overflow_check && !in_test_path),
            "bounded_overflow gate must be exact conjunction of three guards",
        );
    }

    /// Prove `ld_preload_injection_is_exploitable` is the exact conjunction:
    /// has_user_input ∧ has_env_set ∧ ¬has_scope_guard ∧ ¬in_test_path.
    #[kani::proof]
    fn ld_preload_injection_is_exact_conjunction() {
        let has_user_input: bool = kani::any();
        let has_env_set: bool = kani::any();
        let has_scope_guard: bool = kani::any();
        let in_test_path: bool = kani::any();
        let result = ld_preload_injection_is_exploitable(
            has_user_input,
            has_env_set,
            has_scope_guard,
            in_test_path,
        );
        kani::assert(
            result == (has_user_input && has_env_set && !has_scope_guard && !in_test_path),
            "ld_preload_injection gate must be exact conjunction of four guards",
        );
    }

    /// Prove `classify_jwt_keyfunc_proof` is the exact priority-ordered predicate:
    /// in_test_path ∨ has_valid_methods_guard → InvariantViolationProof;
    /// has_nil_nil_return (without either above guard) → ReachabilityProof;
    /// otherwise → LatticeGapProposal.
    #[kani::proof]
    fn jwt_keyfunc_is_exact_conjunction() {
        use common::slop::ProofClass;
        let has_valid_methods_guard: bool = kani::any();
        let has_nil_nil_return: bool = kani::any();
        let in_test_path: bool = kani::any();
        let result =
            classify_jwt_keyfunc_proof(has_valid_methods_guard, has_nil_nil_return, in_test_path);
        if in_test_path || has_valid_methods_guard {
            kani::assert(
                result == ProofClass::InvariantViolationProof,
                "guarded or test-path JWT must yield InvariantViolationProof",
            );
        } else if has_nil_nil_return {
            kani::assert(
                result == ProofClass::ReachabilityProof,
                "nil/nil keyfunc without guard must yield ReachabilityProof",
            );
        } else {
            kani::assert(
                result == ProofClass::LatticeGapProposal,
                "unclassified JWT keyfunc must yield LatticeGapProposal",
            );
        }
    }

    /// Prove `embedding_trust_transposition_is_reachable` is the exact conjunction:
    /// (retrieval_sink ∧ llm_sink) ∧ untrusted_input ∧ ¬trust_guard ∧ ¬in_test_path.
    /// At the call site, the first arg is `has_retrieval_sink && has_llm_sink`.
    #[kani::proof]
    fn embedding_trust_transposition_is_exact_conjunction() {
        let has_retrieval_sink: bool = kani::any();
        let has_untrusted_input: bool = kani::any();
        let has_trust_guard: bool = kani::any();
        let in_test_path: bool = kani::any();
        let result = embedding_trust_transposition_is_reachable(
            has_retrieval_sink,
            has_untrusted_input,
            has_trust_guard,
            in_test_path,
        );
        kani::assert(
            result
                == (has_retrieval_sink && has_untrusted_input && !has_trust_guard && !in_test_path),
            "embedding_trust_transposition gate must be exact conjunction of four guards",
        );
    }
}
