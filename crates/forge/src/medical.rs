//! P8-3 — Medical Device Pack (IEC 62304 / HL7 / FHIR).
//!
//! Detects three classes of medical-device software safety violations:
//!
//! 1. **PHI data flowing to LLM sinks** (`security:phi_data_in_llm_sink`,
//!    KevCritical) — HL7/FHIR PHI field names co-occurring with an LLM
//!    inference API call within a 40-line window. Violates HIPAA §164.502
//!    and GDPR Art. 9 (sensitive health data processing).
//!
//! 2. **Audit-log absence near patient data writes**
//!    (`security:fda_audit_log_absent`, High) — `patient_data_write(`
//!    present in a file with no audit-log call anywhere in the same file.
//!    Violates FDA §820.180 record-retention requirements.
//!
//! 3. **IEC 62304 software safety level classification** — `ClassA`,
//!    `ClassB`, `ClassC`. ClassC sinks trigger `KevCritical`; used by
//!    downstream emitters to set severity appropriately.
//!
//! All detectors run as pure AhoCorasick scans — zero network, zero
//! subprocess, zero AST parsing. Suitable for CI pipelines with budget
//! memory constraints.

use aho_corasick::AhoCorasick;
use common::slop::StructuredFinding;

// ─── IEC 62304 classification ─────────────────────────────────────────────

/// IEC 62304 software safety classification.
///
/// - `ClassC`: injury or death may result from software failure → Critical.
/// - `ClassB`: non-serious injury may result.
/// - `ClassA`: no injury possible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Iec62304Level {
    ClassA,
    ClassB,
    ClassC,
}

const CLASS_C_SINKS: &[&str] = &[
    "defibrillate(",
    "pacemaker_shock(",
    "insulin_dose(",
    "radiation_dose(",
    "drug_infusion_pump(",
];

const CLASS_B_SINKS: &[&str] = &[
    "patient_data_write(",
    "imaging_acquire(",
    "lab_result_store(",
];

/// Classify the IEC 62304 safety level of the source unit.
///
/// Returns `ClassC` on any life-critical actuation sink, `ClassB` on
/// clinical-data sinks, and `ClassA` otherwise.
pub fn classify_iec_62304_level(source: &str, _label: &str) -> Iec62304Level {
    for sink in CLASS_C_SINKS {
        if source.contains(sink) {
            return Iec62304Level::ClassC;
        }
    }
    for sink in CLASS_B_SINKS {
        if source.contains(sink) {
            return Iec62304Level::ClassB;
        }
    }
    Iec62304Level::ClassA
}

// ─── PHI-to-LLM taint detector ────────────────────────────────────────────

const PHI_FIELDS: &[&str] = &[
    "patient.name",
    "patient.dob",
    "patient.ssn",
    "patient.diagnosis",
    "patient.medication",
    "patient.genomics",
    "patient.address",
    "patient.phone",
    "patient.email",
    "patient.insurance",
    "patient.mrn",
    "patient.npi",
    "resource.identifier",
    "resource.subject",
    "resource.patient",
    "fhir.Patient",
    "hl7.Patient",
    "PHI(",
    "getPHI(",
    ".phi.",
    ".phi_",
    "medicalRecord",
    "healthRecord",
    "clinicalRecord",
    "diagnosticReport",
];

const LLM_SINKS: &[&str] = &[
    "from_pretrained(",
    "openai.ChatCompletion",
    "openai.chat.completions",
    "anthropic.messages.create",
    "anthropic.Anthropic(",
    "genai.GenerativeModel",
    "cohere.Client(",
    "mistral.Mistral(",
    "llm.predict(",
    "llm.invoke(",
    "chain.run(",
    "pipeline(",
];

const PHI_LLM_WINDOW: usize = 40;

/// Emit `security:phi_data_in_llm_sink` findings (KevCritical) when a PHI
/// field name co-occurs with an LLM inference call within a 40-line window.
///
/// Violations indicate HIPAA §164.502 / GDPR Art. 9 data-processing exposure.
pub fn emit_phi_sink_findings(source: &str, label: &str) -> Vec<StructuredFinding> {
    let phi_ac = AhoCorasick::new(PHI_FIELDS).expect("valid phi patterns");
    let llm_ac = AhoCorasick::new(LLM_SINKS).expect("valid llm patterns");

    let lines: Vec<&str> = source.lines().collect();
    let mut findings = Vec::new();
    let mut seen_windows: std::collections::HashSet<usize> = std::collections::HashSet::new();

    for phi_match in phi_ac.find_iter(source) {
        let phi_line = source[..phi_match.start()].lines().count();
        let win_start = phi_line.saturating_sub(PHI_LLM_WINDOW);
        let win_end = (phi_line + PHI_LLM_WINDOW).min(lines.len());
        let window_text: String = lines[win_start..win_end].join("\n");

        if llm_ac.find(&window_text).is_some() && seen_windows.insert(phi_line) {
            findings.push(StructuredFinding {
                id: "security:phi_data_in_llm_sink".to_string(),
                file: Some(label.to_string()),
                line: Some((phi_line + 1) as u32),
                severity: Some("KevCritical".to_string()),
                remediation: Some("Remove PHI field access from LLM inference call path; apply de-identification before any AI processing. HIPAA §164.502 / GDPR Art. 9.".to_string()),
                ..Default::default()
            });
        }
    }
    findings
}

// ─── FDA audit-log absence detector ───────────────────────────────────────

const PATIENT_WRITE_SINKS: &[&str] = &["patient_data_write("];
const AUDIT_LOG_MARKERS: &[&str] = &[
    "audit_log(",
    "AuditService",
    "EventLog.Write(",
    "auditLogger.",
    "audit.Log(",
];

/// Emit `security:fda_audit_log_absent` findings (High) when
/// `patient_data_write(` is present but no audit-log call appears anywhere
/// in the same file. Violates FDA §820.180 record-retention requirements.
pub fn emit_audit_log_absence_findings(source: &str, label: &str) -> Vec<StructuredFinding> {
    let write_ac = AhoCorasick::new(PATIENT_WRITE_SINKS).expect("valid write patterns");
    let audit_ac = AhoCorasick::new(AUDIT_LOG_MARKERS).expect("valid audit patterns");

    let Some(m) = write_ac.find(source) else {
        return Vec::new();
    };
    if audit_ac.find(source).is_some() {
        return Vec::new();
    }

    let write_line = source[..m.start()].lines().count() + 1;
    vec![StructuredFinding {
        id: "security:fda_audit_log_absent".to_string(),
        file: Some(label.to_string()),
        line: Some(write_line as u32),
        severity: Some("High".to_string()),
        remediation: Some("Add an audit_log() or AuditService call immediately after patient_data_write(). FDA §820.180 requires traceable records of all patient data modifications.".to_string()),
        ..Default::default()
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_class_c_sink() {
        let src = "func administer() {\n    insulin_dose(patient, 5.0);\n}";
        assert_eq!(
            classify_iec_62304_level(src, "dosing.go"),
            Iec62304Level::ClassC
        );
    }

    #[test]
    fn classifies_class_b_sink() {
        let src = "def store(rec):\n    patient_data_write(rec)\n";
        assert_eq!(
            classify_iec_62304_level(src, "store.py"),
            Iec62304Level::ClassB
        );
    }

    #[test]
    fn classifies_class_a_when_no_medical_sink() {
        let src = "fn main() { println!(\"hello\"); }";
        assert_eq!(
            classify_iec_62304_level(src, "main.rs"),
            Iec62304Level::ClassA
        );
    }

    #[test]
    fn phi_llm_cooccurrence_emits_finding() {
        let src = "def analyze(patient):\n    data = patient.diagnosis\n    response = openai.ChatCompletion.create(model='gpt-4', messages=[{'content': data}])\n    return response\n";
        let findings = emit_phi_sink_findings(src, "analyze.py");
        assert!(
            !findings.is_empty(),
            "expected a PHI+LLM co-occurrence finding"
        );
        assert_eq!(findings[0].severity.as_deref(), Some("KevCritical"));
        assert!(findings[0].id.contains("phi_data_in_llm_sink"));
    }

    #[test]
    fn phi_without_llm_sink_does_not_emit() {
        let src = "def log(patient):\n    record = patient.diagnosis\n    db.insert(record)\n";
        let findings = emit_phi_sink_findings(src, "log.py");
        assert!(findings.is_empty());
    }

    #[test]
    fn audit_log_absent_emits_finding() {
        let src = "func saveRecord() {\n    patient_data_write(record);\n    db.commit();\n}";
        let findings = emit_audit_log_absence_findings(src, "record.go");
        assert!(!findings.is_empty());
        assert_eq!(findings[0].severity.as_deref(), Some("High"));
        assert!(findings[0].id.contains("fda_audit_log_absent"));
    }

    #[test]
    fn audit_log_present_does_not_emit() {
        let src = "func saveRecord() {\n    patient_data_write(record);\n    audit_log(\"write\", record.id);\n}";
        let findings = emit_audit_log_absence_findings(src, "record.go");
        assert!(findings.is_empty());
    }
}
