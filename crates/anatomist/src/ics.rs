//! Lightweight IEC 61131-3 / ICS mapping fact extraction.

/// The class of an ICS source marker extracted from a text buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IcsMatchKind {
    /// IEC 61131-3 Structured Text program shape.
    StructuredText,
    /// Modbus, DNP3, OPC UA, or IEC 61850 mapping.
    ProtocolMapping,
    /// Hardcoded engineering override, bypass, or force switch.
    EngineeringOverride,
    /// Default or vendor-style ICS credential literal.
    DefaultCredential,
}

/// A single line-addressable ICS fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcsMatch {
    /// 1-indexed source line number.
    pub line: u32,
    /// Extracted fact class.
    pub kind: IcsMatchKind,
    /// Trimmed, capped source line for deterministic reporting.
    pub snippet: String,
}

/// Aggregated low-memory facts for an ICS source buffer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IcsFacts {
    /// True when IEC 61131-3 Structured Text syntax was observed.
    pub has_structured_text: bool,
    /// Protocol register or telemetry mappings.
    pub protocol_mappings: Vec<IcsMatch>,
    /// Engineering overrides or safety bypasses.
    pub hardcoded_overrides: Vec<IcsMatch>,
    /// Default credential literals.
    pub default_credentials: Vec<IcsMatch>,
}

/// Parse IEC 61131-3 Structured Text and common ICS mapping markers from a
/// source buffer without materializing an AST or writing intermediate files.
pub fn parse_ics_source(source: &[u8]) -> IcsFacts {
    let Ok(text) = std::str::from_utf8(source) else {
        return IcsFacts::default();
    };

    let mut facts = IcsFacts::default();
    for (idx, line) in text.lines().enumerate() {
        let line_no = idx as u32 + 1;
        let lower = line.to_ascii_lowercase();
        if is_structured_text_line(&lower) {
            facts.has_structured_text = true;
        }
        if is_protocol_mapping_line(&lower) {
            facts.protocol_mappings.push(IcsMatch {
                line: line_no,
                kind: IcsMatchKind::ProtocolMapping,
                snippet: capped_snippet(line),
            });
        }
        if is_engineering_override_line(&lower) {
            facts.hardcoded_overrides.push(IcsMatch {
                line: line_no,
                kind: IcsMatchKind::EngineeringOverride,
                snippet: capped_snippet(line),
            });
        }
        if is_default_credential_line(&lower) {
            facts.default_credentials.push(IcsMatch {
                line: line_no,
                kind: IcsMatchKind::DefaultCredential,
                snippet: capped_snippet(line),
            });
        }
    }

    facts
}

fn is_structured_text_line(lower: &str) -> bool {
    let trimmed = lower.trim_start();
    trimmed.starts_with("program ")
        || trimmed.starts_with("function_block ")
        || trimmed.starts_with("var")
        || trimmed.starts_with("end_var")
        || trimmed.starts_with("end_program")
        || lower.contains(":=")
}

fn is_protocol_mapping_line(lower: &str) -> bool {
    [
        "holding_register",
        "input_register",
        "coil",
        "function_code",
        "dnp3_point",
        "dnp3_index",
        "dnp3_object",
        "opc_ua",
        "iec_61850",
        "iec61850",
        "iec 61850",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
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
    fn parses_structured_text_override() {
        let source = br#"
PROGRAM Main
VAR
    SafetyOverride := TRUE;
END_VAR
"#;
        let facts = parse_ics_source(source);
        assert!(facts.has_structured_text);
        assert_eq!(facts.hardcoded_overrides.len(), 1);
        assert_eq!(facts.hardcoded_overrides[0].line, 4);
    }

    #[test]
    fn parses_modbus_default_credential() {
        let source = br#"
modbus.holding_register.40101 = pump_speed
MODBUS_SERVER_PASSWORD := 'admin'
"#;
        let facts = parse_ics_source(source);
        assert_eq!(facts.protocol_mappings.len(), 1);
        assert_eq!(facts.default_credentials.len(), 1);
        assert_eq!(
            facts.default_credentials[0].kind,
            IcsMatchKind::DefaultCredential
        );
    }
}
