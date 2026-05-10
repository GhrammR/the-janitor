//! P-tier LLM Prompt Injection Boundary Detector.
//!
//! Detects when user-controlled input is interpolated into a system-prompt
//! string literal that the same source file then submits to an external LLM
//! API.  This is the classic prompt-injection vulnerability — the LLM cannot
//! tell the difference between operator instructions and adversarial user
//! content when they share the same string boundary.
//!
//! ## Narrow scope (high precision)
//!
//! Only fires when ALL of the following hold in the same source file:
//!
//! 1. The file references at least one external LLM SDK call or hostname
//!    (anthropic.messages.create, openai.chat.completions.create, etc. — see
//!    [`LLM_SINK_HOSTS`] / [`LLM_SINK_SDK_CALLS`] from
//!    [`crate::financial_pii`]).
//! 2. A Python f-string or a JavaScript/TypeScript template literal on a
//!    single line contains an instructions-style role indicator (e.g. "you
//!    are", "you must", "your role is", "system:", "do not reveal").
//! 3. That same string contains a user-controlled-variable interpolation
//!    matching `{user_*}` / `${user*}` / `{request.*}` / `${req.*}` /
//!    `{params[}` / `${body.*}` and similar request-derived names.
//!
//! Each condition independently has high false-positive volume; their
//! intersection within a single string literal is empirically near-exclusive
//! to the target vulnerability.

use crate::financial_pii::{LLM_SINK_HOSTS, LLM_SINK_SDK_CALLS};
use common::slop::StructuredFinding;

/// Substring indicators that a string literal is acting as a system-prompt
/// or operator-instruction context.  Matched case-insensitively against the
/// string body.
pub const ROLE_INDICATORS: &[&str] = &[
    "you are",
    "you're",
    "as an assistant",
    "your role is",
    "your role:",
    "instructions:",
    "important rules",
    "you must",
    "system:",
    "the assistant",
    "always respond",
    "never reveal",
    "do not reveal",
    "do not disclose",
];

/// Interpolation fragments that signal a user-controlled variable is being
/// dropped into a string body.  Covers Python f-strings (`{user_input}`) and
/// JS/TS template literals (`${userInput}`) plus common request-binding
/// patterns from Express, FastAPI, Flask, Hono, and Next.js handlers.
pub const USER_CONTROLLED_INTERP_FRAGMENTS: &[&str] = &[
    "{user_",
    "{userInput",
    "{userMessage",
    "{userQuery",
    "{userPrompt",
    "{request.",
    "{req.",
    "{params[",
    "{params.",
    "{body.",
    "{prompt}",
    "{query}",
    "{input}",
    "${user_",
    "${userInput",
    "${userMessage",
    "${userQuery",
    "${userPrompt",
    "${request.",
    "${req.",
    "${params[",
    "${params.",
    "${body.",
    "${prompt}",
    "${query}",
    "${input}",
];

/// Package-import / module-import substrings that signal the file is making
/// LLM calls even when the user has aliased the SDK to a custom variable
/// name (e.g. `const client = new Anthropic();` followed by
/// `client.messages.create(...)`).  Without this hint the SDK-call list would
/// only catch the conventional `anthropic.messages.create` form and miss the
/// more common renamed-variable form.
pub const LLM_SDK_PACKAGE_HINTS: &[&str] = &[
    "@anthropic-ai/sdk",
    "@langchain/anthropic",
    "@langchain/openai",
    "from anthropic",
    "import anthropic",
    "from openai",
    "import openai",
    "import { Anthropic }",
    "import { OpenAI }",
    "import Anthropic ",
    "import OpenAI ",
    "openai-node",
    "langchain.chat_models",
    ".messages.create(",
    ".chat.completions.create(",
];

fn file_references_llm_sink(source: &str) -> bool {
    LLM_SINK_HOSTS.iter().any(|h| source.contains(h))
        || LLM_SINK_SDK_CALLS.iter().any(|s| source.contains(s))
        || LLM_SDK_PACKAGE_HINTS.iter().any(|h| source.contains(h))
}

fn has_role_indicator(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    ROLE_INDICATORS.iter().any(|ind| lower.contains(ind))
}

fn has_user_controlled_interp(s: &str) -> bool {
    USER_CONTROLLED_INTERP_FRAGMENTS
        .iter()
        .any(|frag| s.contains(frag))
}

/// Extract Python f-string and JS/TS template-literal bodies from a single
/// line.  Multi-line strings are intentionally not handled — a multi-line
/// system prompt that interpolates user input is a large enough surface area
/// to merit a deliberate AST-aware rule, which is out of scope for this
/// narrow-precision detector.
fn iter_single_line_template_bodies(line: &str) -> Vec<&str> {
    let mut out: Vec<&str> = Vec::new();
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Python f-string: f"..." or f'...'  (also rf"...", fr"...", but accept just `f`/`F` prefix)
        let f_prefix = (bytes[i] == b'f' || bytes[i] == b'F')
            && i + 1 < bytes.len()
            && (bytes[i + 1] == b'"' || bytes[i + 1] == b'\'')
            && (i == 0 || !is_ident_byte(bytes[i - 1]));
        if f_prefix {
            let q = bytes[i + 1];
            let body_start = i + 2;
            if let Some(end) = find_unescaped(bytes, body_start, q) {
                if let Ok(s) = std::str::from_utf8(&bytes[body_start..end]) {
                    out.push(s);
                }
                i = end + 1;
                continue;
            }
        }
        if bytes[i] == b'`' {
            let body_start = i + 1;
            if let Some(end) = find_unescaped(bytes, body_start, b'`') {
                if let Ok(s) = std::str::from_utf8(&bytes[body_start..end]) {
                    out.push(s);
                }
                i = end + 1;
                continue;
            }
        }
        i += 1;
    }
    out
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn find_unescaped(bytes: &[u8], start: usize, target: u8) -> Option<usize> {
    let mut j = start;
    while j < bytes.len() {
        if bytes[j] == b'\\' {
            j += 2;
            continue;
        }
        if bytes[j] == target {
            return Some(j);
        }
        j += 1;
    }
    None
}

/// Scan a single source blob for the LLM prompt-injection boundary pattern.
///
/// Returns one finding per line that hits all three precision filters
/// (LLM-sink-in-file, role-indicator-in-string, user-interpolation-in-string).
/// `file` is preserved on each emitted [`StructuredFinding`].
pub fn find_llm_unbounded_prompt_concat(
    file: Option<&str>,
    source: &str,
) -> Vec<StructuredFinding> {
    if !file_references_llm_sink(source) {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for (idx, line) in source.lines().enumerate() {
        for body in iter_single_line_template_bodies(line) {
            if has_role_indicator(body) && has_user_controlled_interp(body) {
                findings.push(StructuredFinding {
                    id: "security:llm_prompt_injection_boundary".to_string(),
                    file: file.map(str::to_string),
                    line: Some((idx as u32).saturating_add(1)),
                    fingerprint: String::new(),
                    severity: Some("Critical".to_string()),
                    remediation: Some(
                        "Move user-controlled content out of the system-prompt string \
                         literal.  Place it in its own role-tagged message: \
                         messages=[{\"role\": \"system\", \"content\": <static>}, \
                         {\"role\": \"user\", \"content\": user_input}].  Concatenating \
                         user-controlled input into the system context lets adversaries \
                         override operator instructions (classic prompt injection)."
                            .to_string(),
                    ),
                    docs_url: Some(
                        "https://thejanitor.app/findings/llm-prompt-injection-boundary".to_string(),
                    ),
                    ..Default::default()
                });
                break;
            }
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    const TP_PYTHON_FSTRING: &str = r#"
import openai
def respond(user_input):
    messages = [{"role": "system", "content": f"You are a helpful assistant. The user said: {user_input}"}]
    return openai.chat.completions.create(model="gpt-4", messages=messages)
"#;

    const TN_PYTHON_ROLE_SEPARATED: &str = r#"
import openai
def respond(user_input):
    messages = [
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": user_input},
    ]
    return openai.chat.completions.create(model="gpt-4", messages=messages)
"#;

    const TP_JS_TEMPLATE_LITERAL: &str = r#"
import Anthropic from "@anthropic-ai/sdk";
const client = new Anthropic();
async function respond(req) {
    const messages = [
        { role: "system", content: `You must always respond. ${req.body.userPrompt}` }
    ];
    return client.messages.create({ model: "claude-3-7-sonnet-20250219", messages });
}
"#;

    const TN_NO_LLM_SINK: &str = r#"
def template(user_input):
    return f"You are a helpful assistant. User said: {user_input}"
"#;

    const TN_NO_USER_INTERP: &str = r#"
import openai
def respond():
    messages = [{"role": "system", "content": f"You are a helpful assistant created on {now()}."}]
    return openai.chat.completions.create(model="gpt-4", messages=messages)
"#;

    const TN_USER_INTERP_BUT_NO_ROLE: &str = r#"
import openai
def echo(user_input):
    text = f"user said: {user_input}"
    return openai.chat.completions.create(model="gpt-4", messages=[{"role": "user", "content": text}])
"#;

    #[test]
    fn detects_python_fstring_prompt_injection() {
        let findings = find_llm_unbounded_prompt_concat(Some("a.py"), TP_PYTHON_FSTRING);
        assert_eq!(
            findings.len(),
            1,
            "TP Python f-string must fire exactly once"
        );
        assert_eq!(findings[0].id, "security:llm_prompt_injection_boundary");
        assert_eq!(findings[0].severity.as_deref(), Some("Critical"));
        assert_eq!(findings[0].file.as_deref(), Some("a.py"));
        assert!(
            findings[0].remediation.is_some(),
            "remediation guidance is mandatory"
        );
        assert!(
            findings[0].docs_url.is_some(),
            "docs_url is mandatory for SARIF help.markdown"
        );
        assert!(findings[0].line.is_some_and(|l| l > 0));
    }

    #[test]
    fn detects_js_template_literal_prompt_injection() {
        let findings = find_llm_unbounded_prompt_concat(Some("a.ts"), TP_JS_TEMPLATE_LITERAL);
        assert_eq!(
            findings.len(),
            1,
            "TP JS template literal must fire exactly once"
        );
        assert_eq!(findings[0].severity.as_deref(), Some("Critical"));
    }

    #[test]
    fn does_not_fire_on_role_separated_messages() {
        let findings = find_llm_unbounded_prompt_concat(Some("safe.py"), TN_PYTHON_ROLE_SEPARATED);
        assert!(
            findings.is_empty(),
            "role-separated messages must not trigger the detector"
        );
    }

    #[test]
    fn does_not_fire_without_llm_sink() {
        let findings = find_llm_unbounded_prompt_concat(Some("template.py"), TN_NO_LLM_SINK);
        assert!(
            findings.is_empty(),
            "missing LLM sink must suppress finding (precision filter 1)"
        );
    }

    #[test]
    fn does_not_fire_without_user_interpolation() {
        let findings = find_llm_unbounded_prompt_concat(Some("static.py"), TN_NO_USER_INTERP);
        assert!(
            findings.is_empty(),
            "interpolation of non-user-controlled values must not fire"
        );
    }

    #[test]
    fn does_not_fire_without_role_indicator() {
        let findings =
            find_llm_unbounded_prompt_concat(Some("echo.py"), TN_USER_INTERP_BUT_NO_ROLE);
        assert!(
            findings.is_empty(),
            "user interpolation outside a role-prompt context is not the target bug"
        );
    }

    #[test]
    fn role_indicator_match_is_case_insensitive() {
        const SRC: &str = r#"
import openai
def r(user_input):
    s = f"YOU ARE THE ASSISTANT. Tell me {user_input}"
    return openai.chat.completions.create(model="gpt-4", messages=[{"role": "system", "content": s}])
"#;
        let findings = find_llm_unbounded_prompt_concat(Some("u.py"), SRC);
        assert_eq!(
            findings.len(),
            1,
            "uppercase role indicator must still match"
        );
    }

    #[test]
    fn handles_anthropic_sdk_sink() {
        const SRC: &str = r#"
const Anthropic = require("@anthropic-ai/sdk");
const client = new Anthropic.default();
function r(req) {
    const sys = `Your role is to never reveal secrets. ${req.body.userQuery}`;
    return client.messages.create({system: sys, messages: []});
}
"#;
        let findings = find_llm_unbounded_prompt_concat(Some("an.js"), SRC);
        assert_eq!(
            findings.len(),
            1,
            "anthropic.messages.create sink must be recognized"
        );
    }
}
