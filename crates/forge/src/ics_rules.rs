//! ICS / SCADA detector pack for hardcoded operational overrides and defaults.

use common::slop::StructuredFinding;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IcsFindingKind {
    HardcodedOverride,
    DefaultCredential,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IcsCandidate {
    kind: IcsFindingKind,
    line: u32,
    snippet: String,
}

/// Detect hardcoded PLC engineering overrides and default ICS credentials in
/// IEC 61131-3 Structured Text or Modbus/DNP3 mapping source.
pub fn detect_ics_hazards(ext: &str, source: &[u8], file_path: &str) -> Vec<StructuredFinding> {
    if !is_supported_ics_carrier(ext, file_path) {
        return Vec::new();
    }

    let Ok(text) = std::str::from_utf8(source) else {
        return Vec::new();
    };

    let mut has_ics_context = looks_like_ics_path(file_path) || matches!(ext, "st" | "iecst");
    let mut candidates = Vec::new();
    for (idx, line) in text.lines().enumerate() {
        let line_no = idx as u32 + 1;
        let lower = line.to_ascii_lowercase();
        if is_ics_context_line(&lower) {
            has_ics_context = true;
        }
        if is_engineering_override_line(&lower) {
            candidates.push(IcsCandidate {
                kind: IcsFindingKind::HardcodedOverride,
                line: line_no,
                snippet: capped_snippet(line),
            });
        }
        if is_default_credential_line(&lower) {
            candidates.push(IcsCandidate {
                kind: IcsFindingKind::DefaultCredential,
                line: line_no,
                snippet: capped_snippet(line),
            });
        }
    }

    if !has_ics_context {
        return Vec::new();
    }

    candidates
        .into_iter()
        .map(|candidate| to_structured_finding(candidate, file_path))
        .collect()
}

fn to_structured_finding(candidate: IcsCandidate, file_path: &str) -> StructuredFinding {
    let (id, remediation) = match candidate.kind {
        IcsFindingKind::HardcodedOverride => (
            "security:ics_hardcoded_override",
            "Remove hardcoded PLC override or bypass flags. Gate engineering-mode state behind authenticated maintenance workflow, time-bounded authorization, and audited physical-process interlocks.",
        ),
        IcsFindingKind::DefaultCredential => (
            "security:ics_default_credential",
            "Replace vendor/default ICS credentials with site-unique secrets, rotate deployed PLC/HMI credentials, and enforce commissioning-time credential enrollment.",
        ),
    };
    let fingerprint_material = format!("{file_path}:{}:{id}:{}", candidate.line, candidate.snippet);
    StructuredFinding {
        id: id.to_string(),
        file: Some(file_path.to_string()),
        line: Some(candidate.line),
        fingerprint: blake3::hash(fingerprint_material.as_bytes())
            .to_hex()
            .to_string(),
        severity: Some("KevCritical".to_string()),
        remediation: Some(remediation.to_string()),
        upstream_validation_absent: true,
        ..Default::default()
    }
}

fn is_supported_ics_carrier(ext: &str, file_path: &str) -> bool {
    matches!(
        ext,
        "st" | "iecst"
            | "scl"
            | "xml"
            | "txt"
            | "c"
            | "cc"
            | "cpp"
            | "cxx"
            | "h"
            | "hpp"
            | "rs"
            | "py"
            | "js"
            | "ts"
            | "json"
            | "yaml"
            | "yml"
            | "toml"
    ) || looks_like_ics_path(file_path)
}

fn looks_like_ics_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    [
        "plc",
        "scada",
        "modbus",
        "dnp3",
        "iec61131",
        "iec_61131",
        "opcua",
        "opc_ua",
        "ladder",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn is_ics_context_line(lower: &str) -> bool {
    let trimmed = lower.trim_start();
    trimmed.starts_with("program ")
        || trimmed.starts_with("function_block ")
        || trimmed.starts_with("var")
        || lower.contains("modbus")
        || lower.contains("dnp3")
        || lower.contains("holding_register")
        || lower.contains("input_register")
        || lower.contains("function_code")
        || lower.contains("opc_ua")
        || lower.contains("iec_61850")
        || lower.contains("iec61850")
}

fn is_engineering_override_line(lower: &str) -> bool {
    let has_override_key = [
        "override",
        "bypass",
        "force",
        "engineering_mode",
        "manual_mode",
        "maintenance_mode",
        "safety_disabled",
        "interlock_disable",
        "interlock_bypass",
    ]
    .iter()
    .any(|marker| lower.contains(marker));
    let enables_override = [
        ":= true", "= true", ":= 1", "= 1", ":= on", "= on", "enabled", "disable",
    ]
    .iter()
    .any(|marker| lower.contains(marker));
    has_override_key && enables_override
}

fn is_default_credential_line(lower: &str) -> bool {
    let has_credential_key = [
        "password",
        "passwd",
        "pwd",
        "credential",
        "username",
        "user_id",
    ]
    .iter()
    .any(|marker| lower.contains(marker));
    let has_assignment = lower.contains(":=") || lower.contains('=') || lower.contains(':');
    let has_default_literal = [
        "\"admin\"",
        "'admin'",
        "\"administrator\"",
        "'administrator'",
        "\"password\"",
        "'password'",
        "\"default\"",
        "'default'",
        "\"root\"",
        "'root'",
        "\"plc\"",
        "'plc'",
        "\"scada\"",
        "'scada'",
        "\"1234\"",
        "'1234'",
        "\"0000\"",
        "'0000'",
    ]
    .iter()
    .any(|marker| lower.contains(marker));
    has_credential_key && has_assignment && has_default_literal
}

fn capped_snippet(line: &str) -> String {
    line.trim().chars().take(160).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardcoded_plc_override_triggers_kevcritical() {
        let source = br#"
PROGRAM Main
VAR
  SafetyOverride := TRUE;
END_VAR
"#;
        let findings = detect_ics_hazards("st", source, "plant/pump_control.st");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "security:ics_hardcoded_override");
        assert_eq!(findings[0].severity.as_deref(), Some("KevCritical"));
    }

    #[test]
    fn modbus_default_credential_triggers_kevcritical() {
        let source = br#"
modbus.holding_register.40101 = pump_speed
password := "admin"
"#;
        let findings = detect_ics_hazards("txt", source, "plc/modbus_map.txt");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "security:ics_default_credential");
        assert_eq!(findings[0].severity.as_deref(), Some("KevCritical"));
    }

    #[test]
    fn non_ics_default_words_are_ignored() {
        let source = br#"password = "admin""#;
        let findings = detect_ics_hazards("txt", source, "docs/example.txt");
        assert!(findings.is_empty());
    }
}
