//! Detect oversized encoded string literals that decode to executable binaries.

use base64::Engine;
use common::slop::StructuredFinding;

const MIN_LITERAL_BYTES: usize = 4096;
const MAX_DECODE_BYTES: usize = 64 * 1024 * 1024;
const MAX_LITERALS_PER_FILE: usize = 50;

/// Scan source for large string literals that decode to PE/ELF/Mach-O headers.
pub fn detect_embedded_executable_blob(source: &[u8], file_path: &str) -> Vec<StructuredFinding> {
    let mut findings = Vec::new();
    for (start, literal) in long_string_literals(source)
        .into_iter()
        .take(MAX_LITERALS_PER_FILE)
    {
        let Some(decoded) = decode_candidate(&literal) else {
            continue;
        };
        if !has_executable_magic(&decoded) {
            continue;
        }
        let end = start.saturating_add(literal.len());
        findings.push(StructuredFinding {
            id: "security:embedded_executable_blob".to_string(),
            file: Some(file_path.to_string()),
            line: Some(byte_to_line(source, start)),
            fingerprint: blake3::hash(&source[start..end.min(source.len())])
                .to_hex()
                .to_string(),
            severity: Some("KevCritical".to_string()),
            remediation: Some(
                "Remove embedded executable payloads from source literals. Ship signed artifacts \
                 via audited release channels instead of decoding binaries at runtime."
                    .to_string(),
            ),
            ..Default::default()
        });
    }
    findings
}

fn long_string_literals(source: &[u8]) -> Vec<(usize, Vec<u8>)> {
    let mut literals = Vec::new();
    let mut idx = 0usize;
    while idx < source.len() {
        let quote = source[idx];
        if !matches!(quote, b'\'' | b'"' | b'`') {
            idx += 1;
            continue;
        }
        let start = idx + 1;
        idx += 1;
        let mut escaped = false;
        while idx < source.len() {
            let byte = source[idx];
            if escaped {
                escaped = false;
                idx += 1;
                continue;
            }
            if byte == b'\\' && quote != b'`' {
                escaped = true;
                idx += 1;
                continue;
            }
            if byte == quote {
                let literal = &source[start..idx];
                if literal.len() >= MIN_LITERAL_BYTES {
                    literals.push((start, literal.to_vec()));
                }
                idx += 1;
                break;
            }
            idx += 1;
        }
    }
    literals
}

fn decode_candidate(literal: &[u8]) -> Option<Vec<u8>> {
    let compact = strip_ascii_whitespace(literal);
    if compact.is_empty() {
        return None;
    }
    if compact.len() <= MAX_DECODE_BYTES.saturating_mul(2)
        && compact.len().is_multiple_of(2)
        && compact.iter().all(u8::is_ascii_hexdigit)
    {
        let decoded = hex::decode(&compact).ok()?;
        if decoded.len() <= MAX_DECODE_BYTES {
            return Some(decoded);
        }
    }
    if compact.len() <= ((MAX_DECODE_BYTES * 4) / 3).saturating_add(8)
        && compact
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(*b, b'+' | b'/' | b'=' | b'-' | b'_'))
    {
        if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(&compact) {
            if decoded.len() <= MAX_DECODE_BYTES {
                return Some(decoded);
            }
        }
        if let Ok(decoded) = base64::engine::general_purpose::URL_SAFE.decode(&compact) {
            if decoded.len() <= MAX_DECODE_BYTES {
                return Some(decoded);
            }
        }
    }
    None
}

fn strip_ascii_whitespace(literal: &[u8]) -> Vec<u8> {
    literal
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect()
}

fn has_executable_magic(decoded: &[u8]) -> bool {
    decoded.starts_with(b"MZ")
        || decoded.starts_with(b"\x7fELF")
        || decoded.starts_with(&[0xCA, 0xFE, 0xBA, 0xBE])
        || decoded.starts_with(&[0xFE, 0xED, 0xFA, 0xCE])
        || decoded.starts_with(&[0xFE, 0xED, 0xFA, 0xCF])
        || decoded.starts_with(&[0xCE, 0xFA, 0xED, 0xFE])
        || decoded.starts_with(&[0xCF, 0xFA, 0xED, 0xFE])
}

fn byte_to_line(source: &[u8], byte_offset: usize) -> u32 {
    source[..byte_offset.min(source.len())]
        .iter()
        .filter(|&&b| b == b'\n')
        .count() as u32
        + 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn base64_encoded_mz_header_triggers_finding() {
        let mut payload = b"MZ".to_vec();
        payload.extend(std::iter::repeat_n(b'A', 4096));
        let encoded = base64::engine::general_purpose::STANDARD.encode(payload);
        let source = format!("blob = \"{encoded}\"");
        let findings = detect_embedded_executable_blob(source.as_bytes(), "loader.py");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "security:embedded_executable_blob");
        assert_eq!(findings[0].severity.as_deref(), Some("KevCritical"));
    }

    #[test]
    fn short_literal_is_ignored() {
        let source = b"blob = \"TVo=\"";
        let findings = detect_embedded_executable_blob(source, "loader.py");
        assert!(findings.is_empty());
    }
}
