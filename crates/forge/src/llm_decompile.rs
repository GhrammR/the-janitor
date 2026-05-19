//! Deterministic agent-surface decompilation for tool/prompt misalignment.

use std::sync::OnceLock;

use aho_corasick::{AhoCorasick, AhoCorasickKind, MatchKind};
use common::slop::StructuredFinding;

const SCANNED_EXTENSIONS: &[&str] = &[
    "rs", "py", "js", "jsx", "ts", "tsx", "json", "yaml", "yml", "toml",
];
const FRAMEWORK_MARKERS: &[&str] = &[
    "inputschema",
    "\"tools\"",
    "tool(",
    "structuredtool",
    "register_for_llm",
    "tool_use",
    "mcp",
    "server.tool",
    "@tool",
    "function_call",
];
const PROMPT_MARKERS: &[&str] = &[
    "system_prompt",
    "\"system\"",
    "system:",
    "\"instructions\"",
    "instructions:",
];
const RESTRICTIVE_PROMPT_PATTERNS: &[&str] = &[
    "read-only",
    "do not exfiltrate",
    "must not exfiltrate",
    "never exfiltrate",
    "do not access network",
    "no network access",
    "do not write files",
    "never write files",
    "do not run shell",
    "never execute commands",
    "only summarize",
    "must not modify",
];
const DANGEROUS_TOOL_PATTERNS: &[&str] = &[
    "exec",
    "shell",
    "subprocess",
    "bash",
    "terminal",
    "write_file",
    "filesystem.write",
    "delete_file",
    "requests.post",
    "http_post",
    "spawn",
    "eval",
];

fn pattern_set(patterns: &'static [&'static str]) -> &'static AhoCorasick {
    static FRAMEWORKS: OnceLock<AhoCorasick> = OnceLock::new();
    static PROMPTS: OnceLock<AhoCorasick> = OnceLock::new();
    static RESTRICTIVE: OnceLock<AhoCorasick> = OnceLock::new();
    static DANGEROUS: OnceLock<AhoCorasick> = OnceLock::new();
    let slot = if std::ptr::eq(patterns, FRAMEWORK_MARKERS) {
        &FRAMEWORKS
    } else if std::ptr::eq(patterns, PROMPT_MARKERS) {
        &PROMPTS
    } else if std::ptr::eq(patterns, RESTRICTIVE_PROMPT_PATTERNS) {
        &RESTRICTIVE
    } else {
        &DANGEROUS
    };
    slot.get_or_init(|| {
        AhoCorasick::builder()
            .kind(Some(AhoCorasickKind::DFA))
            .match_kind(MatchKind::LeftmostFirst)
            .ascii_case_insensitive(true)
            .build(patterns)
            .expect("llm_decompile: static patterns must compile")
    })
}

/// Emit `security:agent_intent_misalignment` when a shipped system prompt
/// advertises a constrained/read-only agent while the adjacent tool surface
/// exposes shell, file-write, or exfiltration capability.
pub fn detect_agent_intent_misalignment(
    ext: &str,
    source: &[u8],
    file_path: &str,
) -> Vec<StructuredFinding> {
    if !SCANNED_EXTENSIONS.contains(&ext) {
        return Vec::new();
    }

    let Ok(text) = std::str::from_utf8(source) else {
        return Vec::new();
    };
    let framework_hit = pattern_set(FRAMEWORK_MARKERS).find(text);
    let dangerous_hit = pattern_set(DANGEROUS_TOOL_PATTERNS).find(text);
    let restrictive_prompt = restrictive_prompt_span(text);
    let Some(framework_hit) = framework_hit else {
        return Vec::new();
    };
    let Some(dangerous_hit) = dangerous_hit else {
        return Vec::new();
    };
    let Some(prompt_span) = restrictive_prompt else {
        return Vec::new();
    };

    let start = prompt_span
        .0
        .min(framework_hit.start())
        .min(dangerous_hit.start());
    let end = prompt_span
        .1
        .max(framework_hit.end())
        .max(dangerous_hit.end());
    vec![StructuredFinding {
        id: "security:agent_intent_misalignment".to_string(),
        file: Some(file_path.to_string()),
        line: Some(byte_to_line(source, start)),
        fingerprint: blake3::hash(&source[start..end.min(source.len())])
            .to_hex()
            .to_string(),
        severity: Some("KevCritical".to_string()),
        remediation: Some(
            "Align the shipped system prompt with the exposed tool surface. Remove shell/file-write/exfiltration tools from read-only agents or rewrite the prompt so operator-visible intent matches actual capability."
                .to_string(),
        ),
        ..Default::default()
    }]
}

fn restrictive_prompt_span(text: &str) -> Option<(usize, usize)> {
    let marker = pattern_set(PROMPT_MARKERS).find(text)?;
    let raw_start = marker.start().saturating_sub(256);
    let raw_end = (marker.end() + 768).min(text.len());
    // Snap to char boundaries before slicing — translation files and other
    // UTF-8 inputs with multi-byte characters (e.g. CJK YAML in
    // discourse/discourse) would otherwise panic at the slice boundary.
    let mut window_start = raw_start;
    while window_start > 0 && !text.is_char_boundary(window_start) {
        window_start -= 1;
    }
    let mut window_end = raw_end;
    while window_end > window_start && !text.is_char_boundary(window_end) {
        window_end -= 1;
    }
    let window = &text[window_start..window_end];
    let restrictive = pattern_set(RESTRICTIVE_PROMPT_PATTERNS).find(window)?;
    Some((
        window_start + restrictive.start(),
        window_start + restrictive.end(),
    ))
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

    #[test]
    fn misaligned_prompt_and_tool_surface_triggers() {
        let source = br#"
const system_prompt = "You are a read-only analyst. Do not write files and never execute commands.";
server.tool("write_file", { inputSchema: { type: "object" } }, async () => {});
"#;
        let findings = detect_agent_intent_misalignment("ts", source, "agent.ts");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "security:agent_intent_misalignment");
        assert_eq!(findings[0].severity.as_deref(), Some("KevCritical"));
    }

    #[test]
    fn aligned_agent_surface_is_ignored() {
        let source = br#"
const system_prompt = "You are a read-only analyst. Only summarize local files.";
server.tool("summarize_repo", { inputSchema: { type: "object" } }, async () => {});
"#;
        let findings = detect_agent_intent_misalignment("ts", source, "agent.ts");
        assert!(findings.is_empty());
    }
}
