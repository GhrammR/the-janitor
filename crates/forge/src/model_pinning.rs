//! Detect unpinned hosted-model loads that allow silent weight substitution.

use std::sync::OnceLock;

use aho_corasick::{AhoCorasick, AhoCorasickKind, MatchKind};
use common::slop::StructuredFinding;

const MODEL_PATTERNS: &[&str] = &[".from_pretrained(", "replicate.run(", "hf_hub_download("];

fn automaton() -> &'static AhoCorasick {
    static AC: OnceLock<AhoCorasick> = OnceLock::new();
    AC.get_or_init(|| {
        AhoCorasick::builder()
            .kind(Some(AhoCorasickKind::DFA))
            .match_kind(MatchKind::LeftmostFirst)
            .build(MODEL_PATTERNS)
            .expect("model_pinning: static patterns must compile")
    })
}

/// Scan Python and TypeScript-family source for model loads lacking a pinned revision SHA.
pub fn detect_unpinned_model_revisions(
    ext: &str,
    source: &[u8],
    file_path: &str,
) -> Vec<StructuredFinding> {
    if !matches!(ext, "py" | "ts" | "tsx" | "js" | "jsx") || is_non_production_path(file_path) {
        return Vec::new();
    }

    let lower = ascii_lower(source);
    let mut findings = Vec::new();
    for mat in automaton().find_iter(&lower) {
        let open = mat.end().saturating_sub(1);
        let Some(end) = find_matching_paren(source, open) else {
            continue;
        };
        let call = &source[mat.start()..end];
        if has_pinned_revision(call) || is_non_production_call(call) {
            continue;
        }
        findings.push(StructuredFinding {
            id: "security:unpinned_model_weights".to_string(),
            file: Some(file_path.to_string()),
            line: Some(byte_to_line(source, mat.start())),
            fingerprint: fingerprint(&source[mat.start()..end]),
            severity: Some("KevCritical".to_string()),
            remediation: Some(
                "Pin every hosted-model load to a 40-character commit SHA via \
                 `revision`, `sha`, or `commit_hash` to prevent silent weight substitution."
                    .to_string(),
            ),
            ..Default::default()
        });
    }

    findings
}

fn has_pinned_revision(call: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(call) else {
        return false;
    };
    let lower = text.to_ascii_lowercase();
    for key in ["revision", "commit_hash", "sha", "version"] {
        let mut cursor = 0;
        while let Some(relative) = lower[cursor..].find(key) {
            let idx = cursor + relative + key.len();
            let rest = &lower[idx..];
            let trimmed = rest.trim_start();
            let Some(separator) = trimmed.chars().next() else {
                break;
            };
            if separator != '=' && separator != ':' {
                cursor = idx;
                continue;
            }
            let value = trimmed[separator.len_utf8()..].trim_start();
            if let Some(hex) = extract_quoted_value(value) {
                if is_40_hex(hex) {
                    return true;
                }
            }
            cursor = idx;
        }
    }
    false
}

fn extract_quoted_value(value: &str) -> Option<&str> {
    let first = value.chars().next()?;
    if !matches!(first, '"' | '\'') {
        return None;
    }
    let mut chars = value.char_indices();
    chars.next()?;
    for (idx, ch) in chars {
        if ch == first {
            return value.get(1..idx);
        }
    }
    None
}

fn is_40_hex(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn find_matching_paren(source: &[u8], open_idx: usize) -> Option<usize> {
    if source.get(open_idx) != Some(&b'(') {
        return None;
    }
    let mut depth = 0usize;
    for (idx, byte) in source.iter().enumerate().skip(open_idx) {
        match *byte {
            b'(' => depth += 1,
            b')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(idx + 1);
                }
            }
            _ => {}
        }
    }
    None
}

fn byte_to_line(source: &[u8], byte_offset: usize) -> u32 {
    source[..byte_offset.min(source.len())]
        .iter()
        .filter(|&&b| b == b'\n')
        .count() as u32
        + 1
}

fn fingerprint(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

fn ascii_lower(source: &[u8]) -> Vec<u8> {
    source.iter().map(|b| b.to_ascii_lowercase()).collect()
}

fn is_non_production_path(file_path: &str) -> bool {
    let lower = file_path.to_ascii_lowercase();
    [
        "/test",
        "/tests",
        "/spec",
        "/fixture",
        "/fixtures",
        "/mock",
        "/mocks",
        "/example",
        "/examples",
        "/sample",
        "/samples",
        "/demo",
        "/demos",
        "/sandbox",
        "/staging",
        "/docs/",
        "/storybook",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn is_non_production_call(call: &[u8]) -> bool {
    let lower = String::from_utf8_lossy(call).to_ascii_lowercase();
    [
        "sandbox",
        "staging",
        "example",
        "demo",
        "sample",
        "mock",
        "test/",
        "test-",
        "localhost",
        "127.0.0.1",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unpinned_from_pretrained_triggers_kevcritical_finding() {
        let source = br#"
from transformers import AutoModel
model = AutoModel.from_pretrained("meta-llama/Llama-3-70b")
"#;
        let findings = detect_unpinned_model_revisions("py", source, "model.py");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "security:unpinned_model_weights");
        assert_eq!(findings[0].severity.as_deref(), Some("KevCritical"));
    }

    #[test]
    fn pinned_revision_sha_is_allowed() {
        let source = br#"
import { AutoModel } from "transformers";
const model = AutoModel.from_pretrained("meta-llama/Llama-3-70b", {
  revision: "0123456789abcdef0123456789abcdef01234567",
});
"#;
        let findings = detect_unpinned_model_revisions("ts", source, "model.ts");
        assert!(findings.is_empty());
    }

    #[test]
    fn sandbox_model_load_is_demoted() {
        let source = br#"
from transformers import AutoModel
model = AutoModel.from_pretrained("acme/sandbox-redteam-model")
"#;
        let findings = detect_unpinned_model_revisions("py", source, "examples/model.py");
        assert!(findings.is_empty());
    }
}
