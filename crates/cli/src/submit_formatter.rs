//! Scope verification and SUBMISSION.md auto-generation for Bugcrowd engagements.
//!
//! When `--submit-check` is passed to `janitor hunt`, this module:
//! 1. Loads the program's `_targets.md` scope rules via AhoCorasick.
//! 2. Tags every finding as `[SCOPE: IN]` or `[SCOPE: OUT]`.
//! 3. For every in-scope finding with a populated `repro_cmd`, writes a
//!    `SUBMISSION.md` alongside the hunt report.

use common::slop::StructuredFinding;
use std::path::Path;

/// Scope verdict for a single finding.
#[derive(Debug, Clone)]
pub struct ScopeVerdict {
    pub in_scope: bool,
    pub reason: String,
}

/// Extracted scope rules from a Bugcrowd `_targets.md` file.
pub struct ScopeRules {
    in_scope_patterns: Vec<String>,
    out_scope_patterns: Vec<String>,
}

impl ScopeRules {
    /// Load scope rules from a program's targets markdown file.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("failed to read targets file {}: {e}", path.display()))?;
        Ok(Self::from_markdown(&content))
    }

    /// Create a permissive rule set that marks all security findings in-scope.
    pub fn load_permissive() -> Self {
        Self {
            in_scope_patterns: Vec::new(),
            out_scope_patterns: Vec::new(),
        }
    }

    fn from_markdown(md: &str) -> Self {
        let mut in_scope: Vec<String> = Vec::new();
        let mut out_scope: Vec<String> = Vec::new();
        let mut section = Section::Unknown;

        for line in md.lines() {
            let trimmed = line.trim();
            if is_out_of_scope_header(trimmed) {
                section = Section::OutOfScope;
                continue;
            }
            if is_in_scope_header(trimmed) {
                section = Section::InScope;
                continue;
            }
            if let Some(url) = extract_github_url(trimmed) {
                match section {
                    Section::InScope => in_scope.push(url),
                    Section::OutOfScope => out_scope.push(url),
                    Section::Unknown => in_scope.push(url),
                }
            }
        }

        // No structured section found — collect all GitHub URLs as in-scope
        if in_scope.is_empty() && out_scope.is_empty() {
            for line in md.lines() {
                if let Some(url) = extract_github_url(line.trim()) {
                    in_scope.push(url);
                }
            }
        }

        in_scope.sort();
        in_scope.dedup();
        out_scope.sort();
        out_scope.dedup();

        Self {
            in_scope_patterns: in_scope,
            out_scope_patterns: out_scope,
        }
    }

    /// Check whether a finding's file path / finding ID is in scope.
    pub fn check(&self, file_path: Option<&str>, finding_id: &str) -> ScopeVerdict {
        let file_path = file_path.unwrap_or("");

        for pat in &self.out_scope_patterns {
            if path_matches_pattern(file_path, pat) {
                return ScopeVerdict {
                    in_scope: false,
                    reason: format!("[SCOPE: OUT] matches exclusion: {pat}"),
                };
            }
        }
        for pat in &self.in_scope_patterns {
            if path_matches_pattern(file_path, pat) {
                return ScopeVerdict {
                    in_scope: true,
                    reason: format!("[SCOPE: IN] matches rule: {pat}"),
                };
            }
        }
        // No explicit rules or no pattern matched — default in-scope for security findings
        if finding_id.starts_with("security:") {
            return ScopeVerdict {
                in_scope: true,
                reason: "[SCOPE: IN] security finding; no explicit exclusion".to_string(),
            };
        }
        ScopeVerdict {
            in_scope: true,
            reason: "[SCOPE: IN] no scope restriction applies".to_string(),
        }
    }
}

enum Section {
    InScope,
    OutOfScope,
    Unknown,
}

fn is_out_of_scope_header(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    (lower.contains("out of scope")
        || lower.contains("out-of-scope")
        || lower.contains("exclusion"))
        && (line.starts_with('#') || line.starts_with("**") || line.starts_with("##"))
}

fn is_in_scope_header(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    (lower.contains("in scope") || lower.contains("in-scope") || lower.contains("## scope"))
        && (line.starts_with('#') || line.starts_with("**") || line.starts_with("##"))
}

fn extract_github_url(line: &str) -> Option<String> {
    if let Some(pos) = line.find("github.com/") {
        let rest = &line[pos..];
        let end = rest
            .find(|c: char| c.is_ascii_whitespace() || matches!(c, ')' | '>' | '"' | '\''))
            .unwrap_or(rest.len());
        let path = &rest[..end];
        // Require at least org/repo (two segments after github.com)
        if path.matches('/').count() >= 2 {
            return Some(format!("https://{path}"));
        }
    }
    if line.starts_with("- https://") || line.starts_with("- http://") {
        let url = line
            .trim_start_matches('-')
            .split_whitespace()
            .next()?
            .to_string();
        return Some(url);
    }
    None
}

fn path_matches_pattern(file_path: &str, pattern: &str) -> bool {
    let norm_pat = pattern
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches(".git");
    let norm_file = file_path
        .trim_start_matches("https://")
        .trim_start_matches("http://");

    // Direct substring match (remote vs remote, or local path contains full pattern)
    if norm_file.contains(norm_pat) || norm_pat.contains(norm_file) {
        return true;
    }

    // For GitHub URLs like "github.com/acme/backend", extract "acme/backend" and
    // also just "backend" so local clone paths like "/tmp/acme/backend/..." match.
    if let Some(org_repo) = norm_pat.strip_prefix("github.com/") {
        if norm_file.contains(org_repo) {
            return true;
        }
        if let Some(repo_name) = org_repo.split('/').next_back() {
            if !repo_name.is_empty() && norm_file.contains(repo_name) {
                return true;
            }
        }
    }
    false
}

/// Annotate a finding set with scope verdicts.
pub fn annotate_scope(
    findings: &[StructuredFinding],
    scope_rules: &ScopeRules,
) -> Vec<(StructuredFinding, ScopeVerdict)> {
    findings
        .iter()
        .map(|f| {
            let verdict = scope_rules.check(f.file.as_deref(), &f.id);
            (f.clone(), verdict)
        })
        .collect()
}

/// Write `SUBMISSION_<rule_id>.md` for every in-scope finding that has a `repro_cmd`.
///
/// Returns the number of files written.
pub fn write_submissions(
    annotated: &[(StructuredFinding, ScopeVerdict)],
    output_dir: &Path,
    program_name: &str,
) -> anyhow::Result<usize> {
    let mut written = 0usize;
    for (finding, verdict) in annotated {
        if !verdict.in_scope {
            continue;
        }
        let has_repro = finding
            .exploit_witness
            .as_ref()
            .and_then(|w| w.repro_cmd.as_ref())
            .is_some();
        if !has_repro {
            continue;
        }
        let safe_id = finding.id.replace([':', '/'], "_");
        let filename = format!("SUBMISSION_{safe_id}.md");
        let dest = output_dir.join(&filename);
        let content = format_submission_md(finding, verdict, program_name);
        std::fs::write(&dest, content.as_bytes())
            .map_err(|e| anyhow::anyhow!("failed to write {}: {e}", dest.display()))?;
        eprintln!("[submit-check] wrote {}", dest.display());
        written += 1;
    }
    Ok(written)
}

/// Print the scope summary to stderr.
pub fn print_scope_report(annotated: &[(StructuredFinding, ScopeVerdict)]) {
    let in_count = annotated.iter().filter(|(_, v)| v.in_scope).count();
    let out_count = annotated.iter().filter(|(_, v)| !v.in_scope).count();
    eprintln!("[submit-check] scope summary: {in_count} IN / {out_count} OUT");
    for (finding, verdict) in annotated {
        let label = if verdict.in_scope {
            "[SCOPE: IN]"
        } else {
            "[SCOPE: OUT]"
        };
        let loc = match (finding.file.as_deref(), finding.line) {
            (Some(f), Some(l)) => format!("{f}:{l}"),
            (Some(f), None) => f.to_string(),
            _ => "unknown".to_string(),
        };
        eprintln!("[submit-check] {label} {} @ {loc}", finding.id);
    }
}

/// Render a `StructuredFinding` as a Bugcrowd SUBMISSION.md document.
pub fn format_submission_md(
    finding: &StructuredFinding,
    scope_verdict: &ScopeVerdict,
    program_name: &str,
) -> String {
    let title = format!(
        "{} — {} in {}",
        finding.severity.as_deref().unwrap_or("Finding"),
        finding.id,
        finding.file.as_deref().unwrap_or("target"),
    );
    let cvss = severity_to_cvss(finding.severity.as_deref().unwrap_or("Informational"));
    let repro = finding
        .exploit_witness
        .as_ref()
        .and_then(|w| w.repro_cmd.as_deref())
        .unwrap_or("No automated reproduction command available. Manual verification required.");
    let remediation = finding
        .remediation
        .as_deref()
        .unwrap_or("No remediation advice available.");
    let impact = severity_to_impact(
        finding.severity.as_deref().unwrap_or("Informational"),
        &finding.id,
    );
    let file_line = match (finding.file.as_deref(), finding.line) {
        (Some(f), Some(l)) => format!("{f}:{l}"),
        (Some(f), None) => f.to_string(),
        _ => "unknown location".to_string(),
    };
    let docs_ref = finding
        .docs_url
        .as_deref()
        .map(|u| format!("- {u}\n"))
        .unwrap_or_default();

    format!(
        "# Bugcrowd Submission — {program_name}\n\n\
**Scope Status:** {}\n\n\
## Title\n{title}\n\n\
## CVSS Score\n{cvss}\n\n\
## Finding Location\n`{file_line}`\n\n\
## Vulnerability Class\n{}\n\n\
## Reproduction Steps\n```\n{repro}\n```\n\n\
## Impact\n{impact}\n\n\
## Remediation\n{remediation}\n\n\
## References\n{docs_ref}\
---\n\
*Generated by The Janitor {} — automated security engine*\n",
        scope_verdict.reason,
        finding.id,
        env!("CARGO_PKG_VERSION"),
    )
}

fn severity_to_cvss(severity: &str) -> &'static str {
    match severity {
        "KevCritical" => "CVSS 9.0–10.0 (Critical)",
        "Critical" => "CVSS 8.5–9.9 (Critical)",
        "High" => "CVSS 7.0–8.9 (High)",
        "Medium" => "CVSS 4.0–6.9 (Medium)",
        "Low" => "CVSS 0.1–3.9 (Low)",
        _ => "CVSS — Informational (score TBD per manual triage)",
    }
}

fn severity_to_impact(severity: &str, finding_id: &str) -> &'static str {
    if finding_id.contains("credential") || finding_id.contains("secret") {
        return "Credential compromise enabling unauthorized account access and lateral movement.";
    }
    if finding_id.contains("reentrancy") || finding_id.contains("delegatecall") {
        return "Complete loss of contract funds. Attacker can drain the contract balance in a single transaction.";
    }
    if finding_id.contains("sqli") || finding_id.contains("sql_injection") {
        return "Database exfiltration, authentication bypass, and potential remote code execution.";
    }
    if finding_id.contains("rce") || finding_id.contains("command_injection") {
        return "Remote code execution on the application server; full system compromise.";
    }
    match severity {
        "KevCritical" | "Critical" => {
            "Full compromise of affected system or protocol. Exploitation enables attacker \
to exfiltrate sensitive data, execute arbitrary code, or drain protocol funds."
        }
        "High" => {
            "Significant security degradation enabling privilege escalation or unauthorized \
data exfiltration."
        }
        "Medium" => "Limited impact requiring interaction or specific conditions to exploit.",
        _ => "Minimal direct impact; defence-in-depth improvement opportunity.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_finding(
        id: &str,
        file: Option<&str>,
        severity: &str,
        repro: Option<&str>,
    ) -> StructuredFinding {
        StructuredFinding {
            id: id.to_string(),
            file: file.map(str::to_string),
            severity: Some(severity.to_string()),
            exploit_witness: repro.map(|cmd| {
                let mut w = common::slop::ExploitWitness::default();
                w.repro_cmd = Some(cmd.to_string());
                w
            }),
            ..Default::default()
        }
    }

    #[test]
    fn scope_check_in_scope_github_path() {
        let md = "## Scope\n**In Scope**\n- https://github.com/acme/backend\n";
        let rules = ScopeRules::from_markdown(md);
        let v = rules.check(Some("/tmp/acme/backend/src/main.rs"), "security:sqli");
        assert!(v.in_scope, "path inside scoped repo must be in-scope");
    }

    #[test]
    fn scope_check_out_of_scope_exclusion() {
        let md = "## Scope\n**In Scope**\n- https://github.com/acme/backend\n\
**Out of Scope**\n- https://github.com/acme/docs\n";
        let rules = ScopeRules::from_markdown(md);
        let v = rules.check(Some("/tmp/acme/docs/README.md"), "security:sqli");
        assert!(!v.in_scope, "path in excluded repo must be out-of-scope");
    }

    #[test]
    fn scope_check_no_rules_defaults_in_scope() {
        let rules = ScopeRules::from_markdown("# Program\nSome description.\n");
        let v = rules.check(Some("/tmp/anything/src/file.py"), "security:rce");
        assert!(v.in_scope, "no scope rules must default to in-scope");
    }

    #[test]
    fn submission_md_generated_correctly() {
        let finding = make_finding(
            "security:reentrancy",
            Some("Vault.sol"),
            "KevCritical",
            Some("cast send 0x... 'withdraw()' --value 1ether"),
        );
        let verdict = ScopeVerdict {
            in_scope: true,
            reason: "[SCOPE: IN] test".to_string(),
        };
        let md = format_submission_md(&finding, &verdict, "test_program");
        assert!(md.contains("# Bugcrowd Submission"), "must contain header");
        assert!(
            md.contains("security:reentrancy"),
            "must contain finding ID"
        );
        assert!(
            md.contains("CVSS 9.0–10.0"),
            "KevCritical must map to Critical CVSS"
        );
        assert!(md.contains("cast send"), "must contain repro command");
    }

    #[test]
    fn write_submissions_skips_out_of_scope() {
        let dir = tempfile::tempdir().unwrap();
        let finding = make_finding(
            "security:sqli",
            Some("api.py"),
            "High",
            Some("curl -X POST"),
        );
        let verdict = ScopeVerdict {
            in_scope: false,
            reason: "[SCOPE: OUT] test".to_string(),
        };
        let annotated = vec![(finding, verdict)];
        let count = write_submissions(&annotated, dir.path(), "test").unwrap();
        assert_eq!(
            count, 0,
            "out-of-scope findings must not produce SUBMISSION.md"
        );
    }

    #[test]
    fn write_submissions_skips_missing_repro() {
        let dir = tempfile::tempdir().unwrap();
        let finding = make_finding("security:sqli", Some("api.py"), "High", None);
        let verdict = ScopeVerdict {
            in_scope: true,
            reason: "[SCOPE: IN] test".to_string(),
        };
        let annotated = vec![(finding, verdict)];
        let count = write_submissions(&annotated, dir.path(), "test").unwrap();
        assert_eq!(
            count, 0,
            "findings without repro_cmd must not produce SUBMISSION.md"
        );
    }

    #[test]
    fn write_submissions_creates_file_for_in_scope_with_repro() {
        let dir = tempfile::tempdir().unwrap();
        let finding = make_finding(
            "security:rce",
            Some("cmd.py"),
            "Critical",
            Some("curl -X POST /exec -d 'cmd=id'"),
        );
        let verdict = ScopeVerdict {
            in_scope: true,
            reason: "[SCOPE: IN] test".to_string(),
        };
        let annotated = vec![(finding, verdict)];
        let count = write_submissions(&annotated, dir.path(), "test_program").unwrap();
        assert_eq!(count, 1, "in-scope finding with repro must produce 1 file");
        let expected = dir.path().join("SUBMISSION_security_rce.md");
        assert!(expected.exists(), "SUBMISSION file must be created");
    }
}
