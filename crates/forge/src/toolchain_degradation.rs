//! # P1-16 — Toolchain Degradation Shield
//!
//! Detects PRs that mathematically starve developer security tooling
//! (rust-analyzer, pyright, tsserver, gopls, Janitor MCP) while smuggling a
//! secondary payload in the same diff.  The combined pattern is classified as
//! a `ToolchainDegradationSmuggling` attack.
//!
//! ## Detection Strategy
//!
//! The detector operates on unified-diff patch text.  It scans added lines
//! (`+` prefix) and classifies each modified file:
//!
//! - **Toolchain config files**: `.cargo/config.toml`, `.vscode/settings.json`,
//!   `mcp.json`, `pyproject.toml`, `tsconfig.json`, `.github/workflows/*.yml`
//! - **Payload files**: any Rust/JS/TS/Python source that introduces `unsafe`,
//!   `eval(`, `Function(`, `os.system(`, or `subprocess.run(shell=True)`
//!
//! A toolchain degradation alone emits `security:toolchain_degradation_attack`
//! at `KevCritical`.  A secondary payload in the same diff upgrades the finding
//! to `ToolchainDegradationSmuggling` proof class.

use crate::metadata::DOMAIN_ALL;
use crate::slop_hunter::{Severity, SlopFinding};

// ---------------------------------------------------------------------------
// AhoCorasick patterns — single OnceLock per pattern group
// ---------------------------------------------------------------------------

use std::sync::OnceLock;

use aho_corasick::{AhoCorasick, AhoCorasickKind, MatchKind};

/// Toolchain degradation patterns that appear in added lines.
static TOOLCHAIN_PATTERNS: OnceLock<AhoCorasick> = OnceLock::new();
/// Secondary payload patterns in source files.
static PAYLOAD_PATTERNS: OnceLock<AhoCorasick> = OnceLock::new();

fn toolchain_ac() -> &'static AhoCorasick {
    TOOLCHAIN_PATTERNS.get_or_init(|| {
        AhoCorasick::builder()
            .ascii_case_insensitive(false)
            .match_kind(MatchKind::LeftmostFirst)
            .kind(Some(AhoCorasickKind::DFA))
            .build([
                // .cargo/config.toml — job serialization
                "jobs = 1",
                "jobs=1",
                // codegen-units serialization (1 = full serialization)
                "codegen-units = 1",
                "codegen-units=1",
                // incremental compilation disable
                "incremental = false",
                // rust-analyzer LSP timeout starvation
                "\"checkOnSave.timeout\": 1",
                "\"checkOnSave.timeout\":1",
                // MCP server timeout starvation (1 = 1 ms, essentially disabled)
                "\"timeout\": 1",
                "\"timeout\":1",
                // CI security-scan step starvation (< 5 min is below bounce budget)
                "timeout-minutes: 1",
                "timeout-minutes: 2",
                "timeout-minutes: 3",
                "timeout-minutes: 4",
                // cancel-in-progress flip on security jobs
                "cancel-in-progress: true",
            ])
            .unwrap()
    })
}

fn payload_ac() -> &'static AhoCorasick {
    PAYLOAD_PATTERNS.get_or_init(|| {
        AhoCorasick::builder()
            .ascii_case_insensitive(false)
            .match_kind(MatchKind::LeftmostFirst)
            .kind(Some(AhoCorasickKind::DFA))
            .build([
                // Rust unsafe pointer writes / FFI escape
                "unsafe {",
                "unsafe{",
                // JS/TS code injection sinks
                "eval(",
                "Function(",
                "setTimeout(",
                // Python shell execution
                "os.system(",
                "subprocess.run(",
                "shell=True",
                // Ruby/PHP exec
                "exec(",
                // Hot-ref Git dependency (commit SHA in dep spec)
                "git = \"",
                "rev = \"",
            ])
            .unwrap()
    })
}

// ---------------------------------------------------------------------------
// File classifier
// ---------------------------------------------------------------------------

/// Returns `true` if the diff file path is a toolchain configuration target.
fn is_toolchain_config(path: &str) -> bool {
    let p = path.replace('\\', "/");
    p.ends_with(".cargo/config.toml")
        || p.ends_with(".cargo/config")
        || p.ends_with(".vscode/settings.json")
        || p.ends_with("mcp.json")
        || p.contains(".windsurf/mcp.json")
        || p.contains("claude/mcp.json")
        || p.ends_with("pyproject.toml")
        || p.ends_with("tsconfig.json")
        || (p.contains(".github/workflows/") && (p.ends_with(".yml") || p.ends_with(".yaml")))
}

/// Returns `true` if the diff file path is a source file that can carry payloads.
fn is_payload_candidate(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    p.ends_with(".rs")
        || p.ends_with(".js")
        || p.ends_with(".ts")
        || p.ends_with(".jsx")
        || p.ends_with(".tsx")
        || p.ends_with(".py")
        || p.ends_with(".rb")
        || p.ends_with(".php")
        || p.ends_with("cargo.toml")
}

// ---------------------------------------------------------------------------
// Unified-diff walker
// ---------------------------------------------------------------------------

/// Parse `patch` (unified diff text) and return the current file path for
/// each added line, along with whether the line is added (`+` prefix).
struct DiffWalker<'a> {
    lines: std::str::Lines<'a>,
    current_file: Option<&'a str>,
}

impl<'a> DiffWalker<'a> {
    fn new(patch: &'a str) -> Self {
        Self {
            lines: patch.lines(),
            current_file: None,
        }
    }

    /// Yields `(file_path, added_line_content)` for each added line.
    fn added_lines(mut self) -> Vec<(&'a str, &'a str)> {
        let mut out = Vec::new();
        for line in self.lines.by_ref() {
            if let Some(rest) = line.strip_prefix("+++ b/") {
                // Strip trailing whitespace/tab after path
                self.current_file = Some(rest.trim());
            } else if let Some(rest) = line.strip_prefix("+++ ") {
                // Handle `+++ /dev/null` or bare paths
                self.current_file = Some(rest.trim());
            } else if let Some(added) = line.strip_prefix('+') {
                if let Some(file) = self.current_file {
                    out.push((file, added));
                }
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Detect toolchain degradation attacks in a unified-diff `patch`.
///
/// Returns zero or more [`SlopFinding`] items:
/// - `security:toolchain_degradation_attack` (KevCritical) when toolchain
///   config knobs are degraded in the diff.
/// - `security:toolchain_degradation_smuggling` (KevCritical) when both a
///   toolchain degradation AND a secondary code-execution payload appear in
///   the same diff (`proof_class = ToolchainDegradationSmuggling`).
pub fn detect_toolchain_degradation(patch: &str) -> Vec<SlopFinding> {
    let added = DiffWalker::new(patch).added_lines();

    let mut toolchain_hit = false;
    let mut toolchain_desc = String::new();
    let mut payload_hit = false;
    let mut payload_desc = String::new();

    for (file, line) in &added {
        // --- Toolchain degradation check ---
        if is_toolchain_config(file) && toolchain_ac().is_match(line.as_bytes()) {
            toolchain_hit = true;
            if toolchain_desc.is_empty() {
                toolchain_desc = format!(
                    "security:toolchain_degradation_attack — degradation knob detected \
                     in {file}: `{}`",
                    line.trim()
                );
            }
        }

        // --- Secondary payload check ---
        if is_payload_candidate(file) && payload_ac().is_match(line.as_bytes()) {
            payload_hit = true;
            if payload_desc.is_empty() {
                payload_desc = format!(
                    "security:toolchain_degradation_smuggling — secondary payload in {file}: `{}`",
                    line.trim()
                );
            }
        }
    }

    let mut findings = Vec::new();

    if toolchain_hit && payload_hit {
        // Combined smuggling: emit single upgraded finding
        findings.push(SlopFinding {
            start_byte: 0,
            end_byte: 0,
            description: format!(
                "security:toolchain_degradation_smuggling — proof_class=ToolchainDegradationSmuggling; \
                 toolchain knob degraded ({}) paired with secondary payload ({}); \
                 LSP/MCP fail-open window exploited to bypass in-editor security review",
                toolchain_desc
                    .split(" — ")
                    .nth(1)
                    .unwrap_or(&toolchain_desc),
                payload_desc.split(" — ").nth(1).unwrap_or(&payload_desc),
            ),
            domain: DOMAIN_ALL,
            severity: Severity::KevCritical,
        });
    } else if toolchain_hit {
        findings.push(SlopFinding {
            start_byte: 0,
            end_byte: 0,
            description: toolchain_desc,
            domain: DOMAIN_ALL,
            severity: Severity::KevCritical,
        });
    }

    findings
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_patch(file: &str, added_lines: &[&str]) -> String {
        let mut patch = format!("--- a/{file}\n+++ b/{file}\n@@ -1,3 +1,4 @@\n");
        for line in added_lines {
            patch.push('+');
            patch.push_str(line);
            patch.push('\n');
        }
        patch
    }

    fn make_two_file_patch(
        file_a: &str,
        added_a: &[&str],
        file_b: &str,
        added_b: &[&str],
    ) -> String {
        let mut patch = make_patch(file_a, added_a);
        patch.push_str(&make_patch(file_b, added_b));
        patch
    }

    // ── True-positive: jobs = 1 triggers toolchain_degradation_attack ──────

    #[test]
    fn tp_jobs_one_triggers_degradation() {
        let patch = make_patch(".cargo/config.toml", &["[build]", "jobs = 1"]);
        let findings = detect_toolchain_degradation(&patch);
        assert!(
            !findings.is_empty(),
            "jobs = 1 in .cargo/config.toml must fire toolchain_degradation_attack"
        );
        assert!(findings[0].description.contains("toolchain_degradation"));
        assert!(matches!(findings[0].severity, Severity::KevCritical));
    }

    // ── True-positive: smuggling (jobs=1 + unsafe block) ──────────────────

    #[test]
    fn tp_smuggling_jobs_plus_unsafe() {
        let patch = make_two_file_patch(
            ".cargo/config.toml",
            &["[build]", "jobs = 1"],
            "src/exploit.rs",
            &["unsafe { *(0xdeadbeef as *mut u8) = 0; }"],
        );
        let findings = detect_toolchain_degradation(&patch);
        assert!(!findings.is_empty(), "smuggling pair must fire");
        let desc = &findings[0].description;
        assert!(
            desc.contains("ToolchainDegradationSmuggling"),
            "proof_class must be ToolchainDegradationSmuggling; got: {desc}"
        );
        assert!(matches!(findings[0].severity, Severity::KevCritical));
    }

    // ── True-negative: jobs increase (relaxing) must not fire ──────────────

    #[test]
    fn tn_jobs_increase_no_fire() {
        // A PR bumping jobs from 1 to 8 — only the added line `jobs = 8` appears
        let patch = make_patch(".cargo/config.toml", &["[build]", "jobs = 8"]);
        let findings = detect_toolchain_degradation(&patch);
        assert!(
            findings.is_empty(),
            "jobs = 8 must NOT fire toolchain_degradation_attack; got: {findings:?}"
        );
    }

    // ── True-negative: plain Rust change, no toolchain config ──────────────

    #[test]
    fn tn_plain_rust_no_fire() {
        let patch = make_patch("src/main.rs", &["fn main() { println!(\"hello\"); }"]);
        let findings = detect_toolchain_degradation(&patch);
        assert!(
            findings.is_empty(),
            "plain Rust change must not fire toolchain_degradation"
        );
    }

    // ── codegen-units = 1 triggers degradation ─────────────────────────────

    #[test]
    fn tp_codegen_units_one_triggers() {
        let patch = make_patch(
            ".cargo/config.toml",
            &["[profile.dev]", "codegen-units = 1"],
        );
        let findings = detect_toolchain_degradation(&patch);
        assert!(
            !findings.is_empty(),
            "codegen-units = 1 must fire toolchain_degradation_attack"
        );
    }

    // ── incremental = false triggers degradation ───────────────────────────

    #[test]
    fn tp_incremental_false_triggers() {
        let patch = make_patch(
            ".cargo/config.toml",
            &["[profile.dev]", "incremental = false"],
        );
        let findings = detect_toolchain_degradation(&patch);
        assert!(
            !findings.is_empty(),
            "incremental = false must fire toolchain_degradation_attack"
        );
    }

    // ── MCP timeout starvation ─────────────────────────────────────────────

    #[test]
    fn tp_mcp_timeout_starvation() {
        let patch = make_patch("mcp.json", &["{\"timeout\": 1}"]);
        let findings = detect_toolchain_degradation(&patch);
        assert!(
            !findings.is_empty(),
            "mcp.json timeout:1 must fire toolchain_degradation_attack"
        );
    }

    // ── payload-only (unsafe without toolchain change) must not fire ────────

    #[test]
    fn tn_payload_only_no_smuggling() {
        let patch = make_patch("src/lib.rs", &["unsafe { let x = 0; }"]);
        let findings = detect_toolchain_degradation(&patch);
        // No toolchain config changed — no degradation finding expected from this detector
        // (the standalone unsafe detector in slop_hunter covers this separately)
        assert!(
            findings.is_empty(),
            "unsafe in source without toolchain config change must not fire this detector"
        );
    }

    // ── CI workflow timeout starvation ─────────────────────────────────────

    #[test]
    fn tp_ci_timeout_starvation() {
        let patch = make_patch(
            ".github/workflows/security.yml",
            &["    timeout-minutes: 2"],
        );
        let findings = detect_toolchain_degradation(&patch);
        assert!(
            !findings.is_empty(),
            "CI workflow timeout-minutes: 2 must fire toolchain_degradation_attack"
        );
    }
}
