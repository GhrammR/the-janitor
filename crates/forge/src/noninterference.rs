//! Prompt/tool non-interference detector.

use common::slop::{ProofClass, StructuredFinding};

const PROMPT_SOURCES: &[&[u8]] = &[
    b"messages[".as_slice(),
    b"message.content",
    b"prompt =",
    b"user_prompt",
    b"req.body.prompt",
    b"request.json",
    b"input(",
];

const LLM_EXTRACTION_MARKERS: &[&[u8]] = &[
    b"response.choices",
    b"message.content",
    b"completion.text",
    b"tool_calls",
    b"assistant_response",
    b"model.generate",
    b"chat.completions.create",
];

const PRIVILEGED_TOOL_MARKERS: &[&[u8]] = &[
    b"shellexec",
    b"shell_exec",
    b"subprocess.run",
    b"os.system",
    b"child_process.exec",
    b"cloudmutate",
    b"kubectl apply",
    b"terraform apply",
    b"aws iam",
    b"gcloud iam",
];

const DECLASSIFICATION_GATES: &[&[u8]] = &[
    b"allowlist",
    b"regex",
    b"re.fullmatch",
    b"regexp.mustcompile",
    b"static_map",
    b"staticmapping",
    b"match command",
    b"match tool_name",
    b"approved_tools",
    b"approved_commands",
];

/// Detect prompt-derived interference into privileged tools without an explicit
/// hardcoded declassification gate.
pub fn prove_prompt_tool_non_interference(trace: &[u8]) -> Vec<StructuredFinding> {
    let lower = ascii_lower(trace);
    if !contains_any_bytes(&lower, PROMPT_SOURCES) {
        return Vec::new();
    }
    let Some(extract_offset) = first_offset(&lower, LLM_EXTRACTION_MARKERS) else {
        return Vec::new();
    };
    let Some(tool_offset) = first_offset(&lower, PRIVILEGED_TOOL_MARKERS) else {
        return Vec::new();
    };
    if tool_offset <= extract_offset {
        return Vec::new();
    }
    if contains_any_bytes(&lower, DECLASSIFICATION_GATES) {
        return Vec::new();
    }

    let line = byte_to_line(trace, tool_offset);
    vec![StructuredFinding {
        id: "security:prompt_tool_interference".to_string(),
        line: Some(line),
        fingerprint: short_fingerprint(
            format!("security:prompt_tool_interference:{extract_offset}:{tool_offset}").as_bytes(),
        ),
        severity: Some("KevCritical".to_string()),
        proof_class: Some(ProofClass::InvariantViolationProof),
        remediation: Some(
            "Insert a hardcoded declassification gate before privileged tools: route model output through a static mapping or regex allowlist rather than directly into ShellExec or CloudMutate surfaces."
                .to_string(),
        ),
        docs_url: None,
        exploit_witness: None,
        upstream_validation_absent: true,
        ..Default::default()
    }]
}

/// Pure helper used by regression tests and Kani.
pub fn declassification_gate_missing(
    has_prompt: bool,
    has_extraction: bool,
    has_privileged_tool: bool,
    has_gate: bool,
    tool_after_extraction: bool,
) -> bool {
    has_prompt && has_extraction && has_privileged_tool && tool_after_extraction && !has_gate
}

fn ascii_lower(source: &[u8]) -> Vec<u8> {
    source.iter().map(u8::to_ascii_lowercase).collect()
}

fn contains_any_bytes(haystack: &[u8], needles: &[&[u8]]) -> bool {
    needles.iter().any(|needle| {
        haystack
            .windows(needle.len())
            .any(|window| window == *needle)
    })
}

fn first_offset(haystack: &[u8], needles: &[&[u8]]) -> Option<usize> {
    needles
        .iter()
        .filter_map(|needle| {
            haystack
                .windows(needle.len())
                .position(|window| window == *needle)
        })
        .min()
}

fn byte_to_line(source: &[u8], byte: usize) -> u32 {
    source[..source.len().min(byte)]
        .iter()
        .filter(|&&b| b == b'\n')
        .count() as u32
        + 1
}

fn short_fingerprint(bytes: &[u8]) -> String {
    let digest = blake3::hash(bytes);
    digest.as_bytes()[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{declassification_gate_missing, prove_prompt_tool_non_interference};

    #[test]
    fn detects_prompt_to_shell_exec_without_gate() {
        let src = br#"
const prompt = req.body.prompt;
const response = await openai.chat.completions.create({
  messages: [{ role: "user", content: prompt }]
});
const command = response.choices[0].message.content;
ShellExec(command);
"#;
        let findings = prove_prompt_tool_non_interference(src);
        assert!(findings
            .iter()
            .any(|f| f.id == "security:prompt_tool_interference"));
    }

    #[test]
    fn clean_when_allowlist_gate_present() {
        let src = br#"
const prompt = req.body.prompt;
const response = await openai.chat.completions.create({
  messages: [{ role: "user", content: prompt }]
});
const command = response.choices[0].message.content;
if (!ALLOWLIST.test(command)) throw new Error("blocked");
ShellExec(command);
"#;
        assert!(prove_prompt_tool_non_interference(src).is_empty());
    }

    #[test]
    fn helper_tracks_required_gate_conditions() {
        assert!(declassification_gate_missing(true, true, true, false, true));
        assert!(!declassification_gate_missing(true, true, true, true, true));
        assert!(!declassification_gate_missing(
            true, true, true, false, false
        ));
    }
}
