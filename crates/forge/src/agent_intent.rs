//! P2-22 AI-Agent Deception Witness and Tool-Intent Guard.
//!
//! Detects AI-agent transcripts, configuration files, and tool-dispatch code
//! where a tool invocation or tool-selection expression appears within ±15 lines
//! of a privilege-escalating operation, without a read-only / sandbox intent label
//! suppressing the risk. Covers MCP tool calls, OpenAI function_call, Anthropic
//! tool_use, and LangChain/AutoGPT agent tool dispatch patterns.

use aho_corasick::{AhoCorasick, MatchKind};
use common::slop::{ProofClass, StructuredFinding};

/// Tool dispatch sinks — any of these indicate an agent is invoking or selecting
/// a tool.
const TOOL_SINKS: &[&str] = &[
    "tool_choice",
    "function_call",
    "tool_use",
    "<tool>",
    "invoke_tool",
    "call_tool",
    "execute_tool",
    "run_tool",
    "tool_call",
    "ToolInvocation",
    "dispatch_tool",
];

/// Privilege-escalation indicators — operations that could cause irreversible
/// side effects if dispatched without proper intent verification.
const ESCALATION_INDICATORS: &[&str] = &[
    "rm -rf",
    "DROP TABLE",
    "git push --force",
    "DELETE FROM",
    "truncate(",
    "os.remove",
    "shutil.rmtree",
    "fs.unlink",
    "unlink(",
    "format_disk",
    "role: admin",
    "\"admin\"",
    "'admin'",
    "sudo ",
    "privilege",
    "escalat",
];

/// Intent-label suppressors — declarations that bound the tool to read-only or
/// sandboxed execution. Presence of any suppressor in the window blocks the
/// finding.
const INTENT_SUPPRESSORS: &[&str] = &[
    "read_only",
    "dry_run",
    "preview",
    "sandbox",
    "no_side_effects",
    "readonly",
    "dryrun",
    "simulation",
    "\"read\"",
    "safe_mode",
];

fn window_matches(ac: &AhoCorasick, lines: &[&str]) -> bool {
    lines.iter().any(|l| ac.is_match(l.as_bytes()))
}

/// Emit agent tool-intent drift findings for `source` at `file`.
///
/// Fires `security:agent_tool_intent_drift` at KevCritical when a tool-dispatch
/// sink appears within ±15 lines of a privilege-escalation indicator, without an
/// intent-label suppressor present in the same window.
pub fn emit_agent_intent_guard_findings(source: &str, file: &str) -> Vec<StructuredFinding> {
    let lines: Vec<&str> = source.lines().collect();
    let n = lines.len();

    let sink_ac = AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostFirst)
        .build(TOOL_SINKS)
        .expect("TOOL_SINKS patterns valid");

    let esc_ac = AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostFirst)
        .build(ESCALATION_INDICATORS)
        .expect("ESCALATION_INDICATORS patterns valid");

    let sup_ac = AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostFirst)
        .build(INTENT_SUPPRESSORS)
        .expect("INTENT_SUPPRESSORS patterns valid");

    let mut findings = Vec::new();

    for (i, line) in lines.iter().enumerate() {
        if !sink_ac.is_match(line.as_bytes()) {
            continue;
        }
        let lo = i.saturating_sub(15);
        let hi = (i + 15).min(n.saturating_sub(1));
        let window = &lines[lo..=hi];

        if !window_matches(&esc_ac, window) {
            continue;
        }
        if window_matches(&sup_ac, window) {
            continue;
        }

        findings.push(StructuredFinding {
            id: "security:agent_tool_intent_drift".to_string(),
            severity: Some("KevCritical".to_string()),
            file: Some(file.to_string()),
            line: Some((i + 1) as u32),
            proof_class: Some(ProofClass::LatticeGapProposal),
            remediation: Some(
                "Declare an explicit intent label (`read_only`, `dry_run`, `sandbox`) alongside \
                 every tool dispatch that could execute privileged operations. Verify tool intent \
                 against an allowlist before dispatch — never allow an untrusted agent transcript \
                 to select a write-capable tool without an operator-approved intent declaration."
                    .to_string(),
            ),
            ..Default::default()
        });
    }

    findings
}

/// Pure boolean predicate for Kani and regression tests.
///
/// Returns `true` iff a tool sink is present AND an escalation indicator is
/// present AND no intent suppressor blocks it — the exact conjunction that emits
/// a finding.
pub fn session_tool_intent_drift(
    has_tool_sink: bool,
    has_escalation: bool,
    has_suppressor: bool,
) -> bool {
    has_tool_sink && has_escalation && !has_suppressor
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find(src: &str) -> Vec<StructuredFinding> {
        emit_agent_intent_guard_findings(src, "agent.json")
    }

    #[test]
    fn tp_tool_choice_with_admin_role() {
        let src = r#"
{
  "tool_choice": "auto",
  "role": "admin",
  "action": "delete_user"
}
"#;
        assert!(!find(src).is_empty());
    }

    #[test]
    fn tn_dry_run_suppressor() {
        let src = r#"
{
  "tool_choice": "auto",
  "dry_run": true,
  "role": "admin"
}
"#;
        assert!(find(src).is_empty());
    }

    #[test]
    fn tp_function_call_rm_rf() {
        let src = r#"
const response = await openai.chat.completions.create({
  function_call: { name: "shell_exec" },
  arguments: { cmd: "rm -rf /data" }
});
"#;
        assert!(!find(src).is_empty());
    }

    #[test]
    fn tn_sandbox_suppressor() {
        let src = r#"
const response = await openai.chat.completions.create({
  function_call: { name: "shell_exec" },
  sandbox: true,
  arguments: { cmd: "rm -rf /data" }
});
"#;
        assert!(find(src).is_empty());
    }

    #[test]
    fn tp_tool_use_drop_table() {
        let src = r#"
<tool>sql_execute</tool>
<parameters>{"query": "DROP TABLE users"}</parameters>
"#;
        assert!(!find(src).is_empty());
    }

    #[test]
    fn tn_read_only_suppressor() {
        let src = r#"
<tool>sql_execute</tool>
<parameters>{"query": "DROP TABLE users", "read_only": true}</parameters>
"#;
        assert!(find(src).is_empty());
    }

    #[test]
    fn tp_invoke_tool_git_force_push() {
        let src = r#"
result = invoke_tool("git_runner", {
    "command": "git push --force origin main"
})
"#;
        assert!(!find(src).is_empty());
    }

    #[test]
    fn tn_preview_suppressor() {
        let src = r#"
result = invoke_tool("git_runner", {
    "command": "git push --force origin main",
    "preview": True
})
"#;
        assert!(find(src).is_empty());
    }

    #[test]
    fn predicate_exact() {
        assert!(session_tool_intent_drift(true, true, false));
        assert!(!session_tool_intent_drift(true, true, true));
        assert!(!session_tool_intent_drift(false, true, false));
        assert!(!session_tool_intent_drift(true, false, false));
    }
}
