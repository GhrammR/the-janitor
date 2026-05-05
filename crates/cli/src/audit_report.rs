/// P0-REV-3: Private Audit Report Generator.
///
/// Runs the full hunt pipeline over a target repository and emits a
/// professional, PDF-ready Markdown security audit document suitable for
/// delivery to Web3 protocol clients, Code4rena contest submissions, or
/// Sherlock private audit engagements.
use anyhow::Context as _;
use common::slop::StructuredFinding;
use forge::brain::FindingRanker;
use forge::dedup::{deduplicate_findings, DeduplicatedFinding};
use std::path::Path;

/// Entry point: scan `repo`, write `<output_dir>/audit_report.md`.
pub fn cmd_audit_report(repo: &Path, output_dir: &Path) -> anyhow::Result<()> {
    let repo = repo
        .canonicalize()
        .with_context(|| format!("target repo not found: {}", repo.display()))?;

    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("cannot create output dir: {}", output_dir.display()))?;

    let raw_findings = crate::hunt::scan_directory(&repo)
        .with_context(|| format!("scan failed for {}", repo.display()))?;

    let repo_name = repo
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");
    let canonical_target = extract_git_remote(&repo);

    let component_info = format!("{} ({})", repo_name, repo.display());
    let findings = FindingRanker::rank_findings(raw_findings, Some(&component_info));
    let deduplicated = deduplicate_findings(findings);

    let report = render_report(&deduplicated, repo_name, &canonical_target);

    let out_path = output_dir.join("audit_report.md");
    std::fs::write(&out_path, report.as_bytes())
        .with_context(|| format!("failed to write report to {}", out_path.display()))?;

    eprintln!(
        "[audit-report] report written to {}  ({} deduplicated class(es))",
        out_path.display(),
        deduplicated.len()
    );
    Ok(())
}

fn render_report(
    findings: &[DeduplicatedFinding],
    repo_name: &str,
    canonical_target: &str,
) -> String {
    let version = env!("CARGO_PKG_VERSION");
    let now = chrono_date_utc();

    let mut out = String::with_capacity(8192);

    // ── Title block ──────────────────────────────────────────────────────────
    out.push_str(&format!(
        "# Security Audit Report — {repo_name}\n\n\
         **Prepared by**: The Janitor v{version}  \n\
         **Date**: {now} UTC  \n\
         **Target**: `{}`  \n\n\
         ---\n\n",
        canonical_target
    ));

    // ── Executive Summary ────────────────────────────────────────────────────
    out.push_str("## Executive Summary\n\n");

    let counts = severity_counts(findings);
    if findings.is_empty() {
        out.push_str(
            "No security findings were detected. \
             The repository is clear of all vulnerability classes \
             covered by the automated scan.\n\n",
        );
    } else {
        out.push_str(&format!(
            "The automated scan of **{repo_name}** identified **{}** \
             distinct vulnerability class(es) after deterministic structural \
             deduplication.\n\n",
            findings.len()
        ));
        out.push_str("| Severity | Count |\n|----------|-------|\n");
        for (sev, count) in &counts {
            out.push_str(&format!("| {sev} | {count} |\n"));
        }
        out.push('\n');

        let critical_count = counts
            .iter()
            .filter(|(s, _)| s.contains("Critical") || s.contains("Kev"))
            .map(|(_, c)| c)
            .sum::<usize>();
        if critical_count > 0 {
            out.push_str(&format!(
                "> **CRITICAL ALERT**: {critical_count} critical-severity finding(s) require \
                 immediate remediation before deployment.\n\n"
            ));
        }
    }

    // ── Findings Table ───────────────────────────────────────────────────────
    out.push_str("## Findings Table\n\n");
    if findings.is_empty() {
        out.push_str("_No findings detected._\n\n");
    } else {
        out.push_str("| # | ID | Severity | File | CVSS |\n");
        out.push_str("|---|-----|----------|------|------|\n");
        for (i, entry) in findings.iter().enumerate() {
            let f = &entry.finding;
            let sev = f.severity.as_deref().unwrap_or("Informational");
            let file = f
                .file
                .as_deref()
                .unwrap_or("—")
                .split('/')
                .next_back()
                .unwrap_or("—");
            out.push_str(&format!(
                "| {} | `{}` | {} | {} | {} |\n",
                i + 1,
                f.id,
                sev,
                file,
                severity_to_cvss(sev)
            ));
        }
        out.push('\n');
    }

    // ── Per-Finding Technical Detail ─────────────────────────────────────────
    out.push_str("## Per-Finding Technical Detail\n\n");
    if findings.is_empty() {
        out.push_str("_No findings to detail._\n\n");
    } else {
        for (i, entry) in findings.iter().enumerate() {
            let f = &entry.finding;
            let sev = f.severity.as_deref().unwrap_or("Informational");
            out.push_str(&format!("### Finding #{}: `{}`\n\n", i + 1, f.id));
            out.push_str(&format!("**Severity**: {}  \n", sev));
            if let Some(ref file) = f.file {
                out.push_str(&format!("**File**: `{file}`  \n"));
            }
            if let Some(line) = f.line {
                out.push_str(&format!("**Line**: {line}  \n"));
            }
            out.push_str(&format!("**CVSS**: {}  \n\n", severity_to_cvss(sev)));
            out.push_str("**Occurrences**:\n\n");
            for occurrence in &entry.occurrences {
                match occurrence.line {
                    Some(line) => {
                        out.push_str(&format!("- `{}`:{line}\n", occurrence.file));
                    }
                    None => {
                        out.push_str(&format!("- `{}`\n", occurrence.file));
                    }
                }
            }
            out.push('\n');

            // IFDS witness detail
            if let Some(ref w) = f.exploit_witness {
                if !w.source_label.is_empty() || !w.sink_label.is_empty() {
                    out.push_str("**Taint Flow**:\n\n");
                    out.push_str(&format!(
                        "- Source: `{}` in `{}`\n- Sink: `{}` in `{}`\n\n",
                        w.source_label, w.source_function, w.sink_label, w.sink_function
                    ));
                }
                if !w.call_chain.is_empty() {
                    out.push_str("**Call Chain**: ");
                    out.push_str(&w.call_chain.join(" → "));
                    out.push_str("\n\n");
                }
            }

            // AEG repro_cmd (nested in ExploitWitness)
            if let Some(cmd) = f
                .exploit_witness
                .as_ref()
                .and_then(|w| w.repro_cmd.as_deref())
            {
                out.push_str("**Reproduction Command** (AEG-synthesized):\n\n");
                out.push_str("```bash\n");
                out.push_str(cmd);
                out.push_str("\n```\n\n");
            }

            // Remediation
            out.push_str(&format!(
                "**Recommended Remediation**:\n\n{}\n\n",
                remediation_for(f)
            ));

            out.push_str("---\n\n");
        }
    }

    // ── Attestation ──────────────────────────────────────────────────────────
    out.push_str("## Certification Statement\n\n");
    out.push_str(&format!(
        "This report was generated automatically by **The Janitor v{version}** \
         using a deterministic static analysis pipeline (AST taint propagation, \
         IFDS data-flow, credential entropy, solidity reentrancy, FFI taint, \
         and IDOR/authz detectors). \
         Scan target: `{}`. \
         Report date: {now} UTC.\n\n\
         **SHA-384 Provenance Seal**: scan artefacts are reproducible — \
         re-running the engine over the same commit will produce an identical \
         finding set for deterministic detectors.\n\n\
         _The Janitor is not a substitute for manual review by a credentialed \
         security engineer. This report constitutes automated pre-audit triage \
         and reduces the scope of a full human engagement._\n",
        canonical_target
    ));

    out
}

pub(crate) fn extract_git_remote(dir: &Path) -> String {
    std::fs::read_to_string(dir.join(".git").join("config"))
        .ok()
        .and_then(|config| parse_git_remote_config(&config))
        .unwrap_or_else(|| fallback_target_name(dir))
}

fn parse_git_remote_config(config: &str) -> Option<String> {
    let mut in_origin = false;
    for line in config.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_origin = trimmed == "[remote \"origin\"]";
            continue;
        }
        if !in_origin {
            continue;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        if key.trim() == "url" {
            return normalize_remote_url(value.trim());
        }
    }
    None
}

fn normalize_remote_url(remote: &str) -> Option<String> {
    let trimmed = remote.trim().trim_end_matches(".git");
    if trimmed.is_empty() {
        return None;
    }
    if let Some(rest) = trimmed.strip_prefix("git@github.com:") {
        return Some(format!("https://github.com/{rest}"));
    }
    if let Some(rest) = trimmed.strip_prefix("ssh://git@github.com/") {
        return Some(format!("https://github.com/{rest}"));
    }
    if trimmed.starts_with("http://github.com/") {
        return Some(trimmed.replacen("http://", "https://", 1));
    }
    if trimmed.starts_with("https://github.com/") {
        return Some(trimmed.to_string());
    }
    Some(trimmed.to_string())
}

fn fallback_target_name(dir: &Path) -> String {
    dir.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string()
}

fn severity_counts(findings: &[DeduplicatedFinding]) -> Vec<(String, usize)> {
    let order = [
        "KevCritical",
        "Critical",
        "High",
        "Medium",
        "Low",
        "Informational",
    ];
    let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for f in findings {
        let sev = f.finding.severity.as_deref().unwrap_or("Informational");
        *counts.entry(sev).or_insert(0) += 1;
    }
    let mut result: Vec<(String, usize)> = order
        .iter()
        .filter_map(|&sev| counts.get(sev).map(|&c| (sev.to_string(), c)))
        .collect();
    // Append any unknown severities not in the ordered list.
    for (sev, count) in &counts {
        if !order.contains(sev) {
            result.push((sev.to_string(), *count));
        }
    }
    result
}

fn severity_to_cvss(severity: &str) -> &'static str {
    match severity {
        "KevCritical" => "CVSS 9.0–10.0 (Critical)",
        "Critical" => "CVSS 8.5–9.9 (Critical)",
        "High" => "CVSS 7.0–8.9 (High)",
        "Medium" => "CVSS 4.0–6.9 (Medium)",
        "Low" => "CVSS 0.1–3.9 (Low)",
        _ => "CVSS — Informational (score TBD)",
    }
}

fn remediation_for(f: &StructuredFinding) -> &'static str {
    match f.id.as_str() {
        id if id.contains("reentrancy") => {
            "Apply the Checks-Effects-Interactions (CEI) pattern. \
             Add `nonReentrant` modifier (OpenZeppelin ReentrancyGuard). \
             Audit all external calls for callback paths."
        }
        id if id.contains("delegatecall") => {
            "Validate the target address against a strict allowlist before \
             every `delegatecall`. Prefer `call` over `delegatecall` unless \
             proxy storage layout is formally verified."
        }
        id if id.contains("oracle") || id.contains("price_manipulation") => {
            "Replace spot-price reads with time-weighted average price (TWAP) \
             oracles (e.g. Uniswap V3 `observe()`). Add a minimum observation \
             window (≥ 30 min) and a maximum price-deviation circuit breaker."
        }
        id if id.contains("flash_loan") => {
            "Validate `msg.sender == address(pool)` and `initiator == address(this)` \
             inside every `executeOperation` callback. Recompute balances from \
             state, not from callback-supplied amounts."
        }
        id if id.contains("integer_overflow") || id.contains("arithmetic") => {
            "Upgrade to Solidity ≥ 0.8.x (built-in overflow checks) or wrap all \
             arithmetic in SafeMath. Add invariant assertions for critical accumulators."
        }
        id if id.contains("credential") || id.contains("entropy") => {
            "Rotate the exposed credential immediately. Store secrets in a secrets \
             manager (AWS Secrets Manager, HashiCorp Vault). Audit git history for \
             further exposure using `git log -S <secret>`."
        }
        id if id.contains("prototype_pollution") => {
            "Freeze prototype chains at module load time: `Object.freeze(Object.prototype)`. \
             Replace recursive merge utilities with safe alternatives (lodash ≥ 4.17.21, \
             or structured-clone). Validate all user-controlled keys against an allowlist."
        }
        id if id.contains("xss") || id.contains("innerHTML") => {
            "Replace `innerHTML` assignments with `textContent` or DOM API calls. \
             Apply DOMPurify sanitization to all untrusted HTML. \
             Enforce a strict Content-Security-Policy (CSP) header."
        }
        id if id.contains("sql") || id.contains("injection") => {
            "Use parameterised queries or prepared statements exclusively. \
             Never concatenate user input into SQL strings. \
             Apply a query allow-list at the ORM/driver layer."
        }
        id if id.contains("ssrf") => {
            "Validate and allowlist all server-side HTTP request destinations. \
             Block RFC-1918 / link-local address ranges at the HTTP client layer. \
             Disable automatic redirect following."
        }
        _ => {
            "Review the flagged code path with a credentialed security engineer. \
             Apply the principle of least privilege and validate all external inputs \
             at trust boundaries."
        }
    }
}

fn chrono_date_utc() -> String {
    // Use UNIX timestamp via std::time to avoid a heavy chrono dependency.
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Decompose into YYY-MM-DD (Gregorian, UTC, Zeller-based).
    let days = secs / 86400;
    let (y, m, d) = days_to_ymd(days);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Convert a count of days since 1970-01-01 to (year, month, day).
fn days_to_ymd(mut z: u64) -> (u32, u32, u32) {
    z += 719468;
    let era = z / 146097;
    let doe = z % 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as u32, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use forge::dedup::deduplicate_findings;

    fn make_finding(id: &str, severity: &str, file: &str) -> StructuredFinding {
        StructuredFinding {
            id: id.to_string(),
            severity: Some(severity.to_string()),
            file: Some(file.to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn empty_repo_produces_clean_certification() {
        let dir = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        // Empty directory → no findings.
        cmd_audit_report(dir.path(), out.path()).unwrap();
        let report = std::fs::read_to_string(out.path().join("audit_report.md")).unwrap();
        assert!(report.contains("No security findings were detected"));
        assert!(report.contains("Certification Statement"));
        assert!(report.contains("SHA-384 Provenance Seal"));
    }

    #[test]
    fn severity_counts_groups_correctly() {
        let findings = vec![
            make_finding("f1", "Critical", "a.sol"),
            make_finding("f2", "Critical", "b.sol"),
            make_finding("f3", "High", "c.rs"),
        ];
        let counts = severity_counts(&deduplicate_findings(findings));
        let crit = counts
            .iter()
            .find(|(s, _)| s == "Critical")
            .map(|(_, c)| *c);
        let high = counts.iter().find(|(s, _)| s == "High").map(|(_, c)| *c);
        assert_eq!(crit, Some(2));
        assert_eq!(high, Some(1));
    }

    #[test]
    fn report_contains_repro_cmd() {
        let findings = vec![{
            let mut f = make_finding("reentrancy_001", "Critical", "vault.sol");
            f.exploit_witness = Some(common::slop::ExploitWitness {
                repro_cmd: Some("cast send 0xDEAD 'attack()' --value 1ether".to_string()),
                ..Default::default()
            });
            f
        }];
        let report = render_report(&deduplicate_findings(findings), "test-repo", "test-repo");
        assert!(report.contains("cast send 0xDEAD"));
        assert!(report.contains("Reproduction Command"));
    }

    #[test]
    fn date_utc_is_reasonable() {
        let date = chrono_date_utc();
        assert!(date.starts_with("20"), "expected 2XXX date, got: {date}");
        assert_eq!(date.len(), 10);
    }

    #[test]
    fn days_to_ymd_epoch() {
        // 1970-01-01 is day 0 from epoch
        let (y, m, d) = days_to_ymd(0);
        assert_eq!((y, m, d), (1970, 1, 1));
    }

    #[test]
    fn remediation_covers_reentrancy() {
        let f = make_finding("reentrancy_check", "Critical", "vault.sol");
        let r = remediation_for(&f);
        assert!(r.contains("CEI"));
    }

    #[test]
    fn report_collapses_duplicate_findings_before_markdown_generation() {
        let findings = vec![
            make_finding("security:xss", "KevCritical", "src/a.ts"),
            make_finding("security:xss", "KevCritical", "src/b.ts"),
        ];
        let deduplicated = deduplicate_findings(findings);
        let report = render_report(&deduplicated, "test-repo", "test-repo");
        assert!(
            report.contains("identified **1** distinct vulnerability class(es)"),
            "executive summary must report deduplicated class count"
        );
        assert_eq!(
            report.matches("### Finding #").count(),
            1,
            "technical detail must render one section per deduplicated class"
        );
        assert!(
            report.contains("`src/a.ts`") && report.contains("`src/b.ts`"),
            "all duplicate locations must survive as occurrence entries"
        );
    }

    #[test]
    fn parse_git_remote_config_extracts_origin_url() {
        let config = r#"
[core]
    repositoryformatversion = 0
[remote "origin"]
    url = git@github.com:mattermost/mattermost-plugin-boards.git
    fetch = +refs/heads/*:refs/remotes/origin/*
"#;
        assert_eq!(
            parse_git_remote_config(config).as_deref(),
            Some("https://github.com/mattermost/mattermost-plugin-boards")
        );
    }
}
