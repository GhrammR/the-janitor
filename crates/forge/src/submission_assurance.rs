//! Bug-bounty acceptance oracle for candidate triage.

use common::slop::{
    finding_has_schema_taint_proof, finding_mentions_internal_metadata_proof, StructuredFinding,
};

/// Individual triager-proof gaps that prevent submission-ready routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsatisfiedClause {
    MissingInternalMetadataProof,
    MissingServerReflection,
}

impl UnsatisfiedClause {
    /// Stable ledger-ready explanation for operator routing.
    pub fn as_ledger_gap(self) -> &'static str {
        match self {
            Self::MissingInternalMetadataProof => {
                "Missing internal metadata proof (`169.254.169.254`) for SSRF acceptance."
            }
            Self::MissingServerReflection => {
                "Missing `schema_taint:proven` server-reflection proof for DOM XSS acceptance."
            }
        }
    }
}

/// Compact vector of unmet acceptance clauses for a finding.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnsatisfiedClauses {
    clauses: Vec<UnsatisfiedClause>,
}

impl UnsatisfiedClauses {
    /// Returns `true` when the candidate is acceptance-complete.
    pub fn is_empty(&self) -> bool {
        self.clauses.is_empty()
    }

    /// Returns the unmet clauses in deterministic order.
    pub fn clauses(&self) -> &[UnsatisfiedClause] {
        &self.clauses
    }

    /// Render the missing-proof vector for `CANDIDATE_LEDGER.md`.
    pub fn ledger_gap_summary(&self) -> String {
        if self.clauses.is_empty() {
            return "Acceptance proof complete.".to_string();
        }
        self.clauses
            .iter()
            .map(|clause| clause.as_ledger_gap())
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Score whether a structured finding satisfies the minimum proof clauses for
/// a high-confidence Bugcrowd submission.
pub fn score_acceptance_proof(candidate: &StructuredFinding) -> UnsatisfiedClauses {
    let mut clauses = Vec::new();
    let normalized_id = candidate.id.to_ascii_lowercase();

    if normalized_id.contains("ssrf") && !finding_mentions_internal_metadata_proof(candidate) {
        clauses.push(UnsatisfiedClause::MissingInternalMetadataProof);
    }

    if normalized_id.contains("dom_xss") && !finding_has_schema_taint_proof(candidate) {
        clauses.push(UnsatisfiedClause::MissingServerReflection);
    }

    UnsatisfiedClauses { clauses }
}

#[cfg(test)]
mod tests {
    use super::{score_acceptance_proof, UnsatisfiedClause};
    use common::slop::{ExploitWitness, StructuredFinding};

    #[test]
    fn flags_ssrf_missing_internal_metadata_proof() {
        let finding = StructuredFinding {
            id: "security:ssrf".to_string(),
            exploit_witness: Some(ExploitWitness {
                repro_cmd: Some(
                    "curl https://target.example/fetch?url=https://example.com".to_string(),
                ),
                ..Default::default()
            }),
            ..Default::default()
        };

        let gaps = score_acceptance_proof(&finding);
        assert_eq!(
            gaps.clauses(),
            &[UnsatisfiedClause::MissingInternalMetadataProof]
        );
    }

    #[test]
    fn accepts_ssrf_with_metadata_proof() {
        let finding = StructuredFinding {
            id: "security:ssrf".to_string(),
            exploit_witness: Some(ExploitWitness {
                repro_cmd: Some(
                    "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/"
                        .to_string(),
                ),
                ..Default::default()
            }),
            ..Default::default()
        };

        assert!(score_acceptance_proof(&finding).is_empty());
    }

    #[test]
    fn flags_dom_xss_without_schema_taint_proof() {
        let finding = StructuredFinding {
            id: "security:dom_xss_innerHTML".to_string(),
            exploit_witness: Some(ExploitWitness::default()),
            ..Default::default()
        };

        let gaps = score_acceptance_proof(&finding);
        assert_eq!(
            gaps.clauses(),
            &[UnsatisfiedClause::MissingServerReflection]
        );
    }
}
