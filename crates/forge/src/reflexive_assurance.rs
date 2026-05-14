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
    use crate::dma_revocation::dma_shadow_access_missing_revocation_dominance;
    use crate::embedding_trust::trust_prioritization_missing;
    use crate::noninterference::declassification_gate_missing;
    use crate::proof_obligation::proof_obligation_missing;
    use crate::slop_hunter::Severity;

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
}

// ---------------------------------------------------------------------------
// Regression tests (compiled under standard cargo test).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::dma_revocation::dma_shadow_access_missing_revocation_dominance;
    use crate::embedding_trust::trust_prioritization_missing;
    use crate::noninterference::declassification_gate_missing;
    use crate::proof_obligation::proof_obligation_missing;
    use crate::slop_hunter::Severity;

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
    fn dma_revocation_gate_requires_missing_unmap_dominance() {
        assert!(dma_shadow_access_missing_revocation_dominance(
            true, true, true, false, true
        ));
        assert!(!dma_shadow_access_missing_revocation_dominance(
            true, true, true, true, true
        ));
    }
}
