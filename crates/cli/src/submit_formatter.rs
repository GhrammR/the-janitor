//! Scope verification and SUBMISSION.md auto-generation for Bugcrowd engagements.
//!
//! When `--submit-check` is passed to `janitor hunt`, this module:
//! 1. Loads the program's `_targets.md` scope rules via AhoCorasick.
//! 2. Tags every finding as `[SCOPE: IN]` or `[SCOPE: OUT]`.
//! 3. For every in-scope, submission-grade finding with a concrete exploit
//!    strategy, writes a `SUBMISSION.md` into `.janitor/hunt_reports/`.

use crate::nuclei_templates::render_nuclei_template;
use common::slop::StructuredFinding;
use forge::dedup::{deduplicate_findings, DeduplicatedFinding, FindingOccurrence};
use std::path::{Component, Path, PathBuf};

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

/// Write `SUBMISSION_<rule_id>.md` for every in-scope finding that survives the
/// artifact-emission threat-model gate.
///
/// Returns the number of files written.
pub fn write_submissions(
    annotated: &[(StructuredFinding, ScopeVerdict)],
    output_dir: &Path,
    program_name: &str,
) -> anyhow::Result<usize> {
    let output_dir = submission_output_dir(output_dir);
    std::fs::create_dir_all(&output_dir).map_err(|e| {
        anyhow::anyhow!(
            "failed to create submission output directory {}: {e}",
            output_dir.display()
        )
    })?;
    let in_scope_findings: Vec<StructuredFinding> = annotated
        .iter()
        .filter(|(_, verdict)| verdict.in_scope)
        .map(|(finding, _)| finding.clone())
        .collect();
    let deduplicated = deduplicate_findings(in_scope_findings);

    let mut written = 0usize;
    for finding in &deduplicated {
        if !forge::exploitability::artifact_emission_allowed(&finding.finding, true) {
            continue;
        }
        let safe_id = finding.finding.id.replace([':', '/'], "_");
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let safe_prog = program_name.replace(['/', '\\', ':', ' '], "_");
        let filename = format!("{ts}_{safe_prog}_SUBMISSION_{safe_id}.md");
        let dest = output_dir.join(&filename);
        let content = generate_bugcrowd_submission_package(finding, program_name);
        std::fs::write(&dest, content.as_bytes())
            .map_err(|e| anyhow::anyhow!("failed to write {}: {e}", dest.display()))?;
        eprintln!("[submit-check] wrote {}", dest.display());
        written += 1;
    }
    Ok(written)
}

fn submission_output_dir(base: &Path) -> PathBuf {
    let mut components = base.components().rev();
    let tail = components.next();
    let parent = components.next();
    if matches!(tail, Some(Component::Normal(name)) if name == "hunt_reports")
        && matches!(parent, Some(Component::Normal(name)) if name == ".janitor")
    {
        return base.to_path_buf();
    }
    base.join(".janitor").join("hunt_reports")
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
        eprintln!(
            "[submit-check] {label} {} @ {loc} :: {}",
            finding.id, verdict.reason
        );
    }
}

/// Render a deduplicated finding class as a Bugcrowd SUBMISSION.md document.
pub fn format_submission_md(finding: &DeduplicatedFinding, canonical_target: &str) -> String {
    let primary = &finding.finding;
    let title = format!(
        "{} — {} in {}",
        primary.severity.as_deref().unwrap_or("Finding"),
        primary.id,
        primary.file.as_deref().unwrap_or("target"),
    );
    let severity = primary.severity.as_deref().unwrap_or("Informational");
    let description = finding_description(primary);
    let repro = primary
        .exploit_witness
        .as_ref()
        .and_then(|w| {
            w.reproduction_steps.as_ref().map(|steps| {
                let mut rendered = String::new();
                for (idx, step) in steps.iter().enumerate() {
                    rendered.push_str(&format!("{}. {}\n", idx + 1, step));
                }
                if let Some(repro_cmd) = w.repro_cmd.as_deref() {
                    rendered.push_str("\nDeterministic reproduction command:\n");
                    rendered.push_str(repro_cmd);
                }
                rendered
            })
        })
        .or_else(|| {
            primary
                .exploit_witness
                .as_ref()
                .and_then(|w| w.repro_cmd.as_ref().map(|cmd| cmd.to_string()))
        })
        .unwrap_or_else(|| {
            "No automated reproduction steps available. Manual verification required.".to_string()
        });
    let remediation = primary
        .remediation
        .as_deref()
        .unwrap_or("No remediation advice available.");
    let impact = severity_to_impact(severity, &primary.id);
    let docs_ref = primary
        .docs_url
        .as_deref()
        .map(|u| format!("- {u}\n"))
        .unwrap_or_default();
    let occurrences = render_occurrence_list(&finding.occurrences);
    let witness_context = render_witness_context(primary);

    format!(
        "# Bugcrowd Submission — {canonical_target}\n\n\
## Target\n`{canonical_target}`\n\n\
## Title\n{title}\n\n\
## Severity\n{severity}\n\n\
## Description\n{description}\n\n\
## Reproduction Steps\n```\n{repro}\n```\n\n\
### Affected Occurrences\n{occurrences}\n\n\
{witness_context}\
## Impact\n{impact}\n\n\
## Remediation\n{remediation}\n\n\
## References\n{docs_ref}\
---\n\
*Generated by The Janitor {version} — automated security engine*\n",
        canonical_target = canonical_target,
        title = title,
        severity = severity,
        description = description,
        repro = repro,
        occurrences = occurrences,
        witness_context = witness_context,
        impact = impact,
        remediation = remediation,
        docs_ref = docs_ref,
        version = env!("CARGO_PKG_VERSION"),
    )
}

/// Render a single copy-pasteable Bugcrowd package for one deduplicated finding.
///
/// The package contains the submission markdown body, the exact reproduction
/// command as a text attachment block, and any embedded HTML proof-of-concept
/// extracted from the witness command heredoc.
pub fn generate_bugcrowd_submission_package(
    finding: &DeduplicatedFinding,
    canonical_target: &str,
) -> String {
    let primary = &finding.finding;
    let mut package = format_submission_md(finding, canonical_target);

    if let Some(repro_cmd) = primary
        .exploit_witness
        .as_ref()
        .and_then(|witness| witness.repro_cmd.as_deref())
    {
        package.push_str("\n## Attached Reproduction Command\n```text\n");
        package.push_str(repro_cmd);
        if !repro_cmd.ends_with('\n') {
            package.push('\n');
        }
        package.push_str("```\n");

        if let Some(html_poc) = extract_html_poc(repro_cmd) {
            package.push_str("\n## Attached HTML PoC\n```html\n");
            package.push_str(html_poc);
            if !html_poc.ends_with('\n') {
                package.push('\n');
            }
            package.push_str("```\n");
        }
    }

    if let Some(artifact) = primary.web_proof_artifact.as_ref() {
        if let Some(template) = render_nuclei_template(artifact, canonical_target) {
            package.push_str("\n## Attached Nuclei Template\n```yaml\n");
            package.push_str(&template);
            if !template.ends_with('\n') {
                package.push('\n');
            }
            package.push_str("```\n");
        }
    }

    package
}

fn finding_description(finding: &StructuredFinding) -> String {
    let location = match (finding.file.as_deref(), finding.line) {
        (Some(file), Some(line)) => format!("{file}:{line}"),
        (Some(file), None) => file.to_string(),
        _ => "unknown location".to_string(),
    };
    let risk = finding
        .exploit_witness
        .as_ref()
        .and_then(|w| w.risk_classification.as_deref())
        .unwrap_or("Deterministic security finding");
    format!(
        "`{}` was detected at `{}`. Structural deduplication collapsed all equivalent \
         instances into this single submission. Risk classification: {}.",
        finding.id, location, risk
    )
}

fn render_occurrence_list(occurrences: &[FindingOccurrence]) -> String {
    let mut rendered = String::new();
    for occurrence in occurrences {
        match occurrence.line {
            Some(line) => rendered.push_str(&format!("- `{}`:{line}\n", occurrence.file)),
            None => rendered.push_str(&format!("- `{}`\n", occurrence.file)),
        }
    }
    rendered
}

fn render_witness_context(finding: &StructuredFinding) -> String {
    let mut sections = String::new();
    if let Some(artifact) = finding.web_proof_artifact.as_ref() {
        sections.push_str("### Web Proof Artifact\n");
        sections.push_str("- ");
        sections.push_str(&artifact.to_markdown());
        sections.push_str("\n\n");
    }

    let Some(witness) = finding.exploit_witness.as_ref() else {
        return sections;
    };

    if !witness.source_label.is_empty() || !witness.sink_label.is_empty() {
        sections.push_str("### Witness Context\n");
        sections.push_str(&format!(
            "- Source: `{}` in `{}`\n- Sink: `{}` in `{}`\n",
            witness.source_label,
            witness.source_function,
            witness.sink_label,
            witness.sink_function
        ));
    }
    if !witness.call_chain.is_empty() {
        if sections.is_empty() {
            sections.push_str("### Witness Context\n");
        }
        sections.push_str(&format!(
            "- Call chain: `{}`\n",
            witness.call_chain.join(" -> ")
        ));
    }
    if !sections.is_empty() {
        sections.push('\n');
    }
    sections
}

fn extract_html_poc(repro_cmd: &str) -> Option<&str> {
    let start = repro_cmd.find("<<'HTML'\n")? + "<<'HTML'\n".len();
    let tail = &repro_cmd[start..];
    let end = tail.find("\nHTML")?;
    Some(&tail[..end])
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
                w.reproduction_steps = Some(vec!["Execute the deterministic repro.".to_string()]);
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
        let deduplicated = DeduplicatedFinding {
            finding,
            occurrences: vec![FindingOccurrence {
                file: "Vault.sol".to_string(),
                line: None,
            }],
        };
        let md = format_submission_md(&deduplicated, "test_program");
        assert!(md.contains("# Bugcrowd Submission"), "must contain header");
        assert!(
            md.contains("security:reentrancy"),
            "must contain finding ID"
        );
        assert!(
            md.contains("## Severity\nKevCritical"),
            "severity heading must be present"
        );
        assert!(md.contains("cast send"), "must contain repro command");
        assert!(
            md.contains("## Description"),
            "must contain description section"
        );
        assert!(md.contains("## Impact"), "must contain impact section");
        assert!(
            md.contains("## Remediation"),
            "must contain remediation section"
        );
    }

    #[test]
    fn submission_package_includes_repro_attachment() {
        let finding = make_finding(
            "security:ssrf_dynamic_url",
            Some("server.ts"),
            "High",
            Some("curl -i https://target.example/internal"),
        );
        let deduplicated = DeduplicatedFinding {
            finding,
            occurrences: vec![FindingOccurrence {
                file: "server.ts".to_string(),
                line: Some(88),
            }],
        };
        let package = generate_bugcrowd_submission_package(&deduplicated, "github.com/acme/app");
        assert!(
            package.contains("## Attached Reproduction Command"),
            "package must include a reproduction attachment block"
        );
        assert!(
            package.contains("curl -i https://target.example/internal"),
            "package must preserve the exact repro command"
        );
    }

    #[test]
    fn submission_md_renders_web_proof_artifact() {
        let mut finding = make_finding(
            "security:ssrf_dynamic_url",
            Some("server.ts"),
            "High",
            Some("curl -i http://169.254.169.254/latest/meta-data/"),
        );
        finding.web_proof_artifact = Some(common::slop::WebProofArtifact {
            source_label: "url_param:url".to_string(),
            sink_label: "sink:http_client".to_string(),
            ifds_trace: vec!["handler".to_string(), "fetch_remote".to_string()],
            evidence_marker: Some("internal_metadata:169.254.169.254".to_string()),
            proof_class: common::slop::ProofClass::ReachabilityProof,
        });
        let deduplicated = DeduplicatedFinding {
            finding,
            occurrences: vec![FindingOccurrence {
                file: "server.ts".to_string(),
                line: Some(88),
            }],
        };

        let md = format_submission_md(&deduplicated, "github.com/acme/app");
        assert!(
            md.contains("### Web Proof Artifact"),
            "submission markdown must include unified web proof context"
        );
        assert!(
            md.contains("url_param:url -> handler -> fetch_remote -> sink:http_client"),
            "submission markdown must render the bound IFDS trace"
        );
    }

    #[test]
    fn submission_package_embeds_html_poc_attachment() {
        let finding = make_finding(
            "security:dom_xss",
            Some("app.js"),
            "High",
            Some(
                "cat > poc.html <<'HTML'\n<!doctype html>\n<script>alert(1)</script>\nHTML\npython3 -m http.server 8765",
            ),
        );
        let deduplicated = DeduplicatedFinding {
            finding,
            occurrences: vec![FindingOccurrence {
                file: "app.js".to_string(),
                line: Some(21),
            }],
        };
        let package = generate_bugcrowd_submission_package(&deduplicated, "github.com/acme/web");
        assert!(
            package.contains("## Attached HTML PoC"),
            "package must include the extracted HTML artifact"
        );
        assert!(
            package.contains("<!doctype html>"),
            "package must preserve the html body"
        );
        assert!(
            package.contains("<script>alert(1)</script>"),
            "package must preserve the PoC script content"
        );
    }

    #[test]
    fn submission_package_embeds_nuclei_template_attachment() {
        let mut finding = make_finding(
            "security:dom_xss",
            Some("app.js"),
            "High",
            Some("python3 -m http.server 8765"),
        );
        finding.web_proof_artifact = Some(common::slop::WebProofArtifact {
            source_label: "url_param:returnTo".to_string(),
            sink_label: "sink:innerHTML".to_string(),
            ifds_trace: vec!["handler".to_string(), "render".to_string()],
            evidence_marker: Some("dom_canary:reflected".to_string()),
            proof_class: common::slop::ProofClass::ReachabilityProof,
        });
        let deduplicated = DeduplicatedFinding {
            finding,
            occurrences: vec![FindingOccurrence {
                file: "app.js".to_string(),
                line: Some(21),
            }],
        };

        let package = generate_bugcrowd_submission_package(&deduplicated, "github.com/acme/web");
        assert!(package.contains("## Attached Nuclei Template"));
        assert!(package.contains("JANITOR_CANARY"));
        assert!(package.contains("janitor_template_hash"));
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
    fn write_submissions_skips_low_evidence_repro_without_strategy() {
        let dir = tempfile::tempdir().unwrap();
        let mut finding = make_finding(
            "security:sqli",
            Some("api.py"),
            "High",
            Some("curl -X POST"),
        );
        finding.exploit_witness = Some(common::slop::ExploitWitness {
            repro_cmd: Some("curl -X POST".to_string()),
            ..Default::default()
        });
        let verdict = ScopeVerdict {
            in_scope: true,
            reason: "[SCOPE: IN] test".to_string(),
        };
        let annotated = vec![(finding, verdict)];
        let count = write_submissions(&annotated, dir.path(), "test").unwrap();
        assert_eq!(
            count, 0,
            "repro without exploitation strategy must not produce SUBMISSION.md"
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
        let reports_dir = dir.path().join(".janitor").join("hunt_reports");
        let found = std::fs::read_dir(&reports_dir).unwrap().flatten().any(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            name.contains("SUBMISSION_security_rce") && name.ends_with(".md")
        });
        assert!(found, "SUBMISSION file must be created");
    }

    #[test]
    fn write_submissions_deduplicates_same_vulnerability_class() {
        let dir = tempfile::tempdir().unwrap();
        let verdict = ScopeVerdict {
            in_scope: true,
            reason: "[SCOPE: IN] test".to_string(),
        };
        let annotated = vec![
            (
                make_finding(
                    "security:rce",
                    Some("src/a.py"),
                    "Critical",
                    Some("curl -X POST /exec -d 'cmd=id'"),
                ),
                verdict.clone(),
            ),
            (
                make_finding(
                    "security:rce",
                    Some("src/b.py"),
                    "Critical",
                    Some("curl -X POST /exec -d 'cmd=id'"),
                ),
                verdict,
            ),
        ];
        let count = write_submissions(&annotated, dir.path(), "test_program").unwrap();
        assert_eq!(
            count, 1,
            "same structural finding class must produce one Bugcrowd submission"
        );
        let reports_dir = dir.path().join(".janitor").join("hunt_reports");
        let submission = std::fs::read_dir(&reports_dir)
            .unwrap()
            .flatten()
            .find(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                name.contains("SUBMISSION_security_rce") && name.ends_with(".md")
            })
            .expect("SUBMISSION file must be created");
        let content = std::fs::read_to_string(submission.path()).unwrap();
        assert!(content.contains("`src/a.py`"));
        assert!(content.contains("`src/b.py`"));
    }
}
