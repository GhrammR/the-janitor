//! False-positive proof obligation gate for critical findings.

use std::fs;
use std::path::Path;

use common::slop::{finding_has_required_proof_class, ProofClass, ProofSummary, StructuredFinding};

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
            kept.push(attach_proof_summary(finding.clone()));
            continue;
        }
        if let Some(upgraded) = upgrade_implicit_reachability_proof(finding) {
            kept.push(attach_proof_summary(upgraded));
            continue;
        }
        if proof_obligation_missing(true, finding_has_required_proof_class(finding)) {
            proposals.push(proposal_block_for(finding));
            continue;
        }
        kept.push(attach_proof_summary(finding.clone()));
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

/// Attach a compact proof summary when a finding already carries a required
/// proof class.
pub fn attach_proof_summary(mut finding: StructuredFinding) -> StructuredFinding {
    if finding.proof_summary.is_none() {
        finding.proof_summary = proof_summary_for(&finding);
    }
    finding
}

fn proof_summary_for(finding: &StructuredFinding) -> Option<ProofSummary> {
    let proof_class = finding.proof_class?;
    let (model, invariant, fixture) = match proof_class {
        ProofClass::ReachabilityProof => {
            if let Some(artifact) = finding.web_proof_artifact.as_ref() {
                (
                    "IFDS web source-to-sink trace".to_string(),
                    artifact.ifds_trace_output(),
                    "tp:reachable_source_sink_with_artifact".to_string(),
                )
            } else if let Some(witness) = finding.exploit_witness.as_ref() {
                let trace = if witness.call_chain.is_empty() {
                    witness
                        .path_proof
                        .as_deref()
                        .unwrap_or("reachability:witness_present")
                        .to_string()
                } else {
                    witness.call_chain.join(" -> ")
                };
                (
                    "IFDS/Z3 reachability witness".to_string(),
                    trace,
                    "tp:exploit_witness_preserved".to_string(),
                )
            } else {
                (
                    "IFDS reachability proof".to_string(),
                    "reachability proof class present".to_string(),
                    "tp:explicit_reachability_proof_class".to_string(),
                )
            }
        }
        ProofClass::InvariantViolationProof => (
            "Z3/Kani invariant witness".to_string(),
            format!("{} violates a detector invariant", finding.id),
            "tp:self_proving_invariant_violation".to_string(),
        ),
        ProofClass::LatticeGapProposal => (
            "IFDS lattice gap".to_string(),
            format!("{} requires a detector lattice extension", finding.id),
            "tn:lattice_gap_blocks_unproven_critical".to_string(),
        ),
    };
    Some(ProofSummary {
        proof_class,
        model,
        invariant,
        fixture,
    })
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
        append_gap_proposals_to, attach_proof_summary, enforce_false_positive_proof_obligation,
        proof_obligation_missing,
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
        assert!(
            filtered[0].proof_summary.is_some(),
            "kept critical finding must carry proof summary"
        );
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
    fn attaches_ifds_summary_for_reachability_proof() {
        let finding = StructuredFinding {
            id: "security:vector_filter_polymorphism".to_string(),
            severity: Some("Critical".to_string()),
            proof_class: Some(ProofClass::ReachabilityProof),
            exploit_witness: Some(ExploitWitness {
                call_chain: vec![
                    "tenant_filter".to_string(),
                    "vector_query".to_string(),
                    "llm_answer".to_string(),
                ],
                ..ExploitWitness::default()
            }),
            ..Default::default()
        };

        let routed = attach_proof_summary(finding);
        let summary = routed
            .proof_summary
            .expect("reachability proof must route a summary");
        assert_eq!(summary.proof_class, ProofClass::ReachabilityProof);
        assert!(summary.invariant.contains("tenant_filter -> vector_query"));
    }

    #[test]
    fn no_summary_for_unproven_informational_finding() {
        let finding = StructuredFinding {
            id: "security:low_yield_hint".to_string(),
            severity: Some("Informational".to_string()),
            ..Default::default()
        };

        let routed = attach_proof_summary(finding);
        assert!(
            routed.proof_summary.is_none(),
            "non-proof finding must not receive synthetic proof summary"
        );
    }
}
