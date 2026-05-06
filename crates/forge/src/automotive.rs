//! Automotive and aerospace ECU detector pack.

use std::collections::VecDeque;

use common::slop::StructuredFinding;

const VALIDATION_WINDOW: usize = 8;

/// Detect unvalidated CAN frame data flowing into critical actuator functions.
pub fn detect_can_bus_unvalidated_actuation(
    ext: &str,
    source: &[u8],
    file_path: &str,
) -> Vec<StructuredFinding> {
    if !is_supported_code_ext(ext) {
        return Vec::new();
    }

    let Ok(text) = std::str::from_utf8(source) else {
        return Vec::new();
    };

    let mut has_can_context = looks_like_can_path(file_path);
    let mut tainted_vars: Vec<String> = Vec::new();
    let mut recent_lines: VecDeque<String> = VecDeque::with_capacity(VALIDATION_WINDOW);
    let mut findings = Vec::new();

    for (idx, line) in text.lines().enumerate() {
        let line_no = idx as u32 + 1;
        let lower = line.to_ascii_lowercase();
        if is_can_context_line(&lower) {
            has_can_context = true;
        }
        if let Some(var) = can_tainted_lhs(&lower) {
            if !tainted_vars.iter().any(|existing| existing == &var) {
                tainted_vars.push(var);
            }
        }

        if has_can_context
            && has_actuator_sink(&lower)
            && line_uses_can_taint(&lower, &tainted_vars)
            && !has_recent_validation(&lower, &recent_lines)
        {
            findings.push(StructuredFinding {
                id: "security:can_bus_unvalidated_actuation".to_string(),
                file: Some(file_path.to_string()),
                line: Some(line_no),
                fingerprint: blake3::hash(
                    format!("{file_path}:{line_no}:{}", line.trim()).as_bytes(),
                )
                .to_hex()
                .to_string(),
                severity: Some("KevCritical".to_string()),
                remediation: Some(
                    "Validate CAN frame identity, DLC, checksum/MAC, and actuator-specific bounds before steering, braking, throttle, or torque commands consume frame-derived data."
                        .to_string(),
                ),
                upstream_validation_absent: true,
                ..Default::default()
            });
        }

        if recent_lines.len() == VALIDATION_WINDOW {
            recent_lines.pop_front();
        }
        recent_lines.push_back(lower);
    }

    findings
}

fn is_supported_code_ext(ext: &str) -> bool {
    matches!(ext, "c" | "cc" | "cpp" | "cxx" | "h" | "hpp" | "rs")
}

fn looks_like_can_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    ["can", "dbc", "ecu", "adas", "brake", "steer", "vehicle"]
        .iter()
        .any(|marker| lower.contains(marker))
}

fn is_can_context_line(lower: &str) -> bool {
    [
        "can_frame",
        "canframe",
        "can_id",
        "socketcan",
        "frame.data",
        "msg.data",
        "rx.data",
        "dbc_",
        ".dbc",
        "can_rx",
        "canfd_frame",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn can_tainted_lhs(lower: &str) -> Option<String> {
    if !line_contains_can_data(lower) || !lower.contains('=') {
        return None;
    }
    let lhs = lower.split('=').next()?.trim();
    last_identifier(lhs)
}

fn line_contains_can_data(lower: &str) -> bool {
    [
        "frame.data",
        "msg.data",
        "rx.data",
        "can.data",
        "payload[",
        "data[",
        "bytes[",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn last_identifier(text: &str) -> Option<String> {
    text.rsplit(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .find(|token| !token.is_empty())
        .map(str::to_string)
}

fn has_actuator_sink(lower: &str) -> bool {
    [
        "set_steering",
        "apply_brakes",
        "apply_brake",
        "set_brake",
        "set_throttle",
        "set_torque",
        "actuate_brake",
        "steering_angle",
        "brake_pressure",
        "torque_request",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn line_uses_can_taint(lower: &str, tainted_vars: &[String]) -> bool {
    line_contains_can_data(lower)
        || tainted_vars
            .iter()
            .any(|var| contains_identifier(lower, var.as_str()))
}

fn contains_identifier(line: &str, needle: &str) -> bool {
    line.split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .any(|token| token == needle)
}

fn has_recent_validation(current: &str, recent_lines: &VecDeque<String>) -> bool {
    validation_token_present(current)
        || recent_lines
            .iter()
            .rev()
            .any(|line| validation_token_present(line))
}

fn validation_token_present(lower: &str) -> bool {
    [
        "validate_can",
        "is_valid_can",
        "verify_can",
        "check_can",
        "crc",
        "checksum",
        "mac",
        "signature",
        "range_check",
        "bounds_check",
        "clamp",
        "dlc",
        "whitelist_can_id",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_frame_into_steering_without_validation_triggers() {
        let source = br#"
void on_can(struct can_frame frame) {
    int steering = frame.data[0];
    set_steering(steering);
}
"#;
        let findings = detect_can_bus_unvalidated_actuation("c", source, "src/ecu_can.c");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "security:can_bus_unvalidated_actuation");
        assert_eq!(findings[0].severity.as_deref(), Some("KevCritical"));
    }

    #[test]
    fn validated_can_frame_is_ignored() {
        let source = br#"
void on_can(struct can_frame frame) {
    if (!validate_can_frame(&frame) || !range_check(frame.data[0])) return;
    int steering = frame.data[0];
    set_steering(steering);
}
"#;
        let findings = detect_can_bus_unvalidated_actuation("c", source, "src/ecu_can.c");
        assert!(findings.is_empty());
    }
}
