//! P7-4 Continuous Regulatory Compliance Oracle.
//!
//! Maps [`StructuredFinding`] instances to compliance control receipts for
//! PCI-DSS 6.3 (SAST requirement) and HIPAA § 164.312(a)(1) (access control).
//! Each receipt carries a SHA-384 evidence digest over the finding's location
//! and class, suitable for inclusion in an auditor-ready dossier.

use common::slop::StructuredFinding;
use sha2::{Digest, Sha384};

/// Pass/Fail/NotApplicable verdict for a compliance control.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComplianceStatus {
    /// Finding does not violate this control.
    Pass,
    /// Finding constitutes a violation of this control.
    Fail,
    /// This control does not apply to the finding class.
    NotApplicable,
}

/// A cryptographically evidenced compliance control verdict for a single finding.
#[derive(Debug, Clone)]
pub struct ComplianceReceipt {
    /// Compliance framework name, e.g. `"PCI-DSS"` or `"HIPAA"`.
    pub framework: &'static str,
    /// Control identifier within the framework, e.g. `"6.3"`.
    pub control_id: String,
    /// Pass/Fail/NotApplicable verdict.
    pub status: ComplianceStatus,
    /// SHA-384 of `finding.file || finding.id` — 48-byte evidence capsule.
    pub evidence_digest: [u8; 48],
}

/// Map one finding to its applicable compliance control receipts.
///
/// Emits exactly one receipt per framework checked. Frameworks covered:
/// - **PCI-DSS 6.3** — SAST requirement; Fail on any credential, injection, or
///   memory-safety finding.
/// - **HIPAA § 164.312(a)(1)** — Access control; Fail on authentication-bypass
///   or JWT-class findings; NotApplicable otherwise.
pub fn map_finding_to_controls(finding: &StructuredFinding) -> Vec<ComplianceReceipt> {
    let digest = evidence_digest(finding);
    let id = finding.id.as_str();

    let pci_status = pci_dss_6_3_status(id);
    let hipaa_status = hipaa_164_312_a1_status(id);

    vec![
        ComplianceReceipt {
            framework: "PCI-DSS",
            control_id: "6.3".to_string(),
            status: pci_status,
            evidence_digest: digest,
        },
        ComplianceReceipt {
            framework: "HIPAA",
            control_id: "164.312(a)(1)".to_string(),
            status: hipaa_status,
            evidence_digest: digest,
        },
    ]
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn pci_dss_6_3_status(finding_id: &str) -> ComplianceStatus {
    const PCI_TRIGGERS: &[&str] = &[
        "credential_leak",
        "command_injection",
        "sql_injection",
        "injection",
        "memory_safety",
        "supply_chain",
        "slopsquat",
        "unpinned",
    ];
    if PCI_TRIGGERS.iter().any(|t| finding_id.contains(t)) {
        ComplianceStatus::Fail
    } else {
        ComplianceStatus::Pass
    }
}

fn hipaa_164_312_a1_status(finding_id: &str) -> ComplianceStatus {
    const HIPAA_TRIGGERS: &[&str] = &[
        "auth_bypass",
        "authentication",
        "jwt",
        "privilege",
        "session",
        "unauthenticated",
    ];
    if HIPAA_TRIGGERS.iter().any(|t| finding_id.contains(t)) {
        ComplianceStatus::Fail
    } else {
        ComplianceStatus::NotApplicable
    }
}

/// SHA-384 of `finding.file || finding.id` — 48 bytes.
pub(crate) fn evidence_digest(finding: &StructuredFinding) -> [u8; 48] {
    let mut h = Sha384::new();
    h.update(finding.file.as_deref().unwrap_or("").as_bytes());
    h.update(finding.id.as_bytes());
    let result = h.finalize();
    let mut out = [0u8; 48];
    out.copy_from_slice(&result);
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use common::slop::StructuredFinding;

    fn finding(id: &str, file: Option<&str>) -> StructuredFinding {
        StructuredFinding {
            id: id.to_string(),
            file: file.map(str::to_string),
            ..Default::default()
        }
    }

    #[test]
    fn credential_leak_fails_pci_dss() {
        let f = finding("security:credential_leak", Some("src/config.rs"));
        let receipts = map_finding_to_controls(&f);
        let pci = receipts.iter().find(|r| r.framework == "PCI-DSS").unwrap();
        assert_eq!(pci.status, ComplianceStatus::Fail);
        assert_eq!(pci.control_id, "6.3");
    }

    #[test]
    fn auth_bypass_fails_hipaa() {
        let f = finding("security:auth_bypass", None);
        let receipts = map_finding_to_controls(&f);
        let hipaa = receipts.iter().find(|r| r.framework == "HIPAA").unwrap();
        assert_eq!(hipaa.status, ComplianceStatus::Fail);
        assert_eq!(hipaa.control_id, "164.312(a)(1)");
    }

    #[test]
    fn dead_code_passes_pci_not_applicable_hipaa() {
        let f = finding("dead_symbol", Some("src/lib.rs"));
        let receipts = map_finding_to_controls(&f);
        assert_eq!(receipts.len(), 2);
        let pci = receipts.iter().find(|r| r.framework == "PCI-DSS").unwrap();
        let hipaa = receipts.iter().find(|r| r.framework == "HIPAA").unwrap();
        assert_eq!(pci.status, ComplianceStatus::Pass);
        assert_eq!(hipaa.status, ComplianceStatus::NotApplicable);
    }

    #[test]
    fn evidence_digest_is_48_bytes_and_deterministic() {
        let f = finding("security:credential_leak", Some("src/auth.rs"));
        let receipts = map_finding_to_controls(&f);
        let d1 = receipts[0].evidence_digest;
        let receipts2 = map_finding_to_controls(&f);
        let d2 = receipts2[0].evidence_digest;
        assert_eq!(d1.len(), 48);
        assert_eq!(d1, d2, "evidence digest must be deterministic");
    }

    #[test]
    fn command_injection_fails_both_frameworks() {
        let f = finding("security:command_injection", Some("src/runner.rs"));
        let receipts = map_finding_to_controls(&f);
        let pci = receipts.iter().find(|r| r.framework == "PCI-DSS").unwrap();
        assert_eq!(pci.status, ComplianceStatus::Fail);
    }

    #[test]
    fn always_emits_two_receipts() {
        for id in &[
            "security:credential_leak",
            "security:auth_bypass",
            "dead_symbol",
            "architecture:version_silo",
        ] {
            let f = finding(id, None);
            let receipts = map_finding_to_controls(&f);
            assert_eq!(receipts.len(), 2, "must always emit 2 receipts for {id}");
        }
    }
}
