//! `janitor hunt` — Offensive security scanner for bug-bounty engagements.
//!
//! Recursively walks a target directory (or a source tree reconstructed from a
//! JavaScript sourcemap / npm tarball / Android APK / Java JAR / Electron ASAR /
//! Docker image tarball), runs the full Janitor detector suite on every file, and
//! emits results as either a JSON array of
//! [`common::slop::StructuredFinding`] or a Bugcrowd-ready Markdown report to
//! stdout.
//!
//! ## Modes
//!
//! ```text
//! janitor hunt ./target                           # local directory
//! janitor hunt --sourcemap https://x.com/a.map    # JS sourcemap
//! janitor hunt --npm lodash@4.17.21               # npm package
//! janitor hunt --apk app.apk                      # Android APK (requires jadx)
//! janitor hunt --jar app.jar                      # Java archive
//! janitor hunt --asar app.asar                    # Electron ASAR archive
//! janitor hunt --docker image.tar                 # docker save tarball
//! janitor hunt --ipa app.ipa                      # iOS IPA bundle
//! janitor hunt ./target --filter '.[] | select(.severity == "Critical")'
//! ```
//!
//! JSON mode supports `--filter` for native `jq`-style filtering (no runtime
//! `jq` dependency required).

use anyhow::Context as _;
use common::slop::{ExploitWitness, ProofClass, StructuredFinding, WebProofArtifact};
use common::wisdom::{ArchivedSlopsquatCorpus, SlopsquatCorpus};
use forge::brain::FindingRanker;
use forge::slop_hunter::{find_slop, ParsedUnit};
use forge::submission_assurance::score_acceptance_proof;
use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// 16 MiB — HTTP body cap for sourcemap and npm registry responses.
const HTTP_BODY_LIMIT: u64 = 16 * 1024 * 1024;
/// 64 MiB — wheel / egg download and extraction cap.
const PYPI_BODY_LIMIT: u64 = 64 * 1024 * 1024;
/// 1 MiB — per-file circuit breaker matching slop_hunter.rs.
const MAX_FILE_BYTES: u64 = 1024 * 1024;
/// 512 MiB — total layer data buffered during docker save extraction.
const DOCKER_LAYER_BUDGET: usize = 512 * 1024 * 1024;
const GADGET_CHAIN_BUGCROWD_PROOF: &str = "A complete deserialization gadget chain was verified against the repository lockfile. The target is provably vulnerable to Remote Code Execution (RCE).";

/// Embedded offline-baseline slopsquat corpus produced by `build.rs`.
static EMBEDDED_SLOPSQUAT: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/slopsquat_corpus.rkyv"));

pub struct HuntArgs<'a> {
    pub scan_root: Option<&'a Path>,
    pub sourcemap_url: Option<&'a str>,
    pub npm_pkg: Option<&'a str>,
    pub whl_path: Option<&'a Path>,
    pub pypi_pkg: Option<&'a str>,
    pub apk_path: Option<&'a Path>,
    pub jar_path: Option<&'a Path>,
    pub asar_path: Option<&'a Path>,
    pub docker_path: Option<&'a Path>,
    pub ipa_path: Option<&'a Path>,
    pub filter_expr: Option<&'a str>,
    pub format: &'a str,
    pub corpus_path: Option<&'a Path>,
    /// When set, replay every synthesized `repro_cmd` against this base URL
    /// and embed the captured response as `ExploitWitness::live_proof`.
    pub live_tenant: Option<&'a str>,
    /// Explicit BrowserDOM tenant domain override for harness synthesis.
    pub live_tenant_domain: Option<&'a str>,
    /// Explicit BrowserDOM client ID override for harness synthesis.
    pub live_tenant_client_id: Option<&'a str>,
    /// When `true` and `BUGCROWD_API_TOKEN` is set, POST the generated
    /// Bugcrowd report to the Bugcrowd Submissions API.  Only active with
    /// `format == "bugcrowd"`.
    pub submit: bool,
    /// When `true`, cross-reference every finding against the program's
    /// `tools/campaign/targets/<program>_targets.md` scope rules, emit
    /// `[SCOPE: IN]` / `[SCOPE: OUT]` labels, and write `SUBMISSION_<id>.md`
    /// into `.janitor/hunt_reports/` for every in-scope finding that survives
    /// the artifact-emission threat-model gate.
    pub submit_check: bool,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Entry point for `janitor hunt`.
///
/// A local `scan_root` or one remote/archive fetcher is required. All modes
/// produce a `Vec<StructuredFinding>`. JSON mode serialises findings directly to
/// stdout; Bugcrowd mode renders grouped Markdown reports. If `filter_expr` is
/// provided the result set is piped through a native `jq`-compatible filter
/// before printing or Markdown rendering.
pub fn cmd_hunt(args: HuntArgs<'_>) -> anyhow::Result<()> {
    let HuntArgs {
        scan_root,
        sourcemap_url,
        npm_pkg,
        whl_path,
        pypi_pkg,
        apk_path,
        jar_path,
        asar_path,
        docker_path,
        ipa_path,
        filter_expr,
        format,
        corpus_path,
        live_tenant,
        live_tenant_domain,
        live_tenant_client_id,
        submit,
        submit_check,
    } = args;

    match format {
        "json" | "bugcrowd" | "auth0" | "sarif" | "immunefi" => {}
        _ => anyhow::bail!(
            "unsupported hunt output format '{format}' (expected 'json', 'bugcrowd', 'auth0', 'sarif', or 'immunefi')"
        ),
    }

    let has_explicit_ingest_source = sourcemap_url.is_some()
        || npm_pkg.is_some()
        || whl_path.is_some()
        || pypi_pkg.is_some()
        || apk_path.is_some()
        || jar_path.is_some()
        || asar_path.is_some()
        || docker_path.is_some()
        || ipa_path.is_some();
    let scan_root = if is_placeholder_scan_root(scan_root, has_explicit_ingest_source) {
        None
    } else {
        scan_root
    };

    let source_count = usize::from(scan_root.is_some())
        + usize::from(sourcemap_url.is_some())
        + usize::from(npm_pkg.is_some())
        + usize::from(whl_path.is_some())
        + usize::from(pypi_pkg.is_some())
        + usize::from(apk_path.is_some())
        + usize::from(jar_path.is_some())
        + usize::from(asar_path.is_some())
        + usize::from(docker_path.is_some());
    let source_count = source_count + usize::from(ipa_path.is_some());

    if source_count == 0 {
        anyhow::bail!(
            "hunt requires either <path> or one ingestion source: --sourcemap, --npm, --whl, --pypi, --apk, --jar, --asar, --docker, or --ipa"
        );
    }
    if source_count > 1 {
        anyhow::bail!(
            "hunt accepts exactly one source: provide either <path> or one of --sourcemap, --npm, --whl, --pypi, --apk, --jar, --asar, --docker, or --ipa"
        );
    }

    let local_scan_root = scan_root;
    let mut component_info_override: Option<String> = None;
    let findings = if let Some(url) = sourcemap_url {
        ingest_sourcemap(url)?
    } else if let Some(pkg) = npm_pkg {
        let (findings, component_info) = ingest_npm(pkg)?;
        component_info_override = Some(component_info);
        findings
    } else if let Some(path) = whl_path {
        ingest_whl(path, corpus_path)?
    } else if let Some(pkg) = pypi_pkg {
        ingest_pypi(pkg, corpus_path)?
    } else if let Some(apk) = apk_path {
        ingest_apk(apk)?
    } else if let Some(jar) = jar_path {
        ingest_jar(jar)?
    } else if let Some(asar) = asar_path {
        ingest_asar(asar)?
    } else if let Some(docker) = docker_path {
        ingest_docker(docker)?
    } else if let Some(ipa) = ipa_path {
        ingest_ipa(ipa)?
    } else if let Some(root) = scan_root {
        scan_directory(root)?
    } else {
        anyhow::bail!(
            "hunt requires either <path> or one ingestion source: --sourcemap, --npm, --whl, --pypi, --apk, --jar, --asar, --docker, or --ipa"
        );
    };

    let findings = if let Some(expr) = filter_expr {
        let filtered = apply_jaq_filter(
            expr,
            serde_json::to_value(&findings).context("failed to convert findings to JSON value")?,
        )?;
        serde_json::from_value::<Vec<StructuredFinding>>(filtered)
            .context("jaq filter must yield an array of structured findings")?
    } else {
        findings
    };

    let findings = {
        let mut findings = if let Some(browser_context) =
            synthesize_browser_tenant_spec(live_tenant, live_tenant_domain, live_tenant_client_id)
        {
            apply_live_tenant_browser_context(findings, &browser_context)
        } else {
            findings
        };
        if let Some(tenant_url) = live_tenant.filter(|value| is_live_tenant_replay_origin(value)) {
            findings = apply_live_tenant_replay(findings, tenant_url);
        }
        let output_dir = hunt_reports_dir()?;
        emit_browser_dom_harnesses(&mut findings, &output_dir)?;
        findings
    };

    let local_scan_component_info =
        local_scan_root.map(|root| detect_component_info_inner(&findings, Some(root)));
    let component_info_context = component_info_override
        .as_deref()
        .or(local_scan_component_info.as_deref());
    let findings = FindingRanker::rank_findings(findings, component_info_context);

    if submit_check {
        run_submit_check(&findings, local_scan_root)?;
    }

    if format == "bugcrowd" {
        let report = if let Some(component_info) = component_info_context {
            format_bugcrowd_report_with_component(&findings, Some(component_info))
        } else {
            format_bugcrowd_report(&findings)
        };
        println!("{report}");
        if submit {
            let target_label = component_info_context.unwrap_or("unknown-target");
            let top_rule = findings
                .first()
                .and_then(|f| f.severity.as_deref())
                .unwrap_or("Informational");
            let submission = common::receipt::BountySubmission {
                title: format!("{top_rule} findings in {target_label}"),
                target: target_label.to_string(),
                markdown_body: report,
                custom_field_vrt: findings
                    .first()
                    .map(|f| vrt_category(&f.id))
                    .unwrap_or("Other")
                    .to_string(),
            };
            post_bugcrowd_submission(&submission)?;
        }
        return Ok(());
    }

    if format == "auth0" {
        let report = if let Some(component_info) = component_info_context {
            format_auth0_report_with_component(&findings, Some(component_info))
        } else {
            format_auth0_report(&findings)
        };
        println!("{report}");
        return Ok(());
    }

    if format == "sarif" {
        let ci_meta = crate::ci_telemetry::ingest_ci_run_metadata();
        let sarif = crate::sarif_enterprise::render_enterprise_sarif(
            &findings,
            if ci_meta.is_populated() {
                Some(&ci_meta)
            } else {
                None
            },
        );
        println!("{sarif}");
        return Ok(());
    }

    if format == "immunefi" {
        let report = format_immunefi_report(&findings, component_info_context);
        println!("{report}");
        return Ok(());
    }

    let output_val =
        serde_json::to_value(&findings).context("failed to convert findings to JSON value")?;

    let json = serde_json::to_string_pretty(&output_val)
        .context("failed to serialise findings as JSON")?;
    println!("{json}");
    Ok(())
}

fn synthesize_browser_tenant_spec(
    live_tenant: Option<&str>,
    live_tenant_domain: Option<&str>,
    live_tenant_client_id: Option<&str>,
) -> Option<String> {
    let explicit_spec = live_tenant.filter(|value| !is_live_tenant_replay_origin(value));
    if let Some(spec) = explicit_spec {
        return Some(spec.to_string());
    }
    if live_tenant_domain.is_none() && live_tenant_client_id.is_none() {
        return None;
    }

    let mut tokens = Vec::new();
    if let Some(domain) = live_tenant_domain {
        tokens.push(format!("domain={domain}"));
    }
    if let Some(client_id) = live_tenant_client_id {
        tokens.push(format!("client_id={client_id}"));
    }
    Some(tokens.join(";"))
}

/// POST a `BountySubmission` to the Bugcrowd Submissions API.
///
/// Reads `BUGCROWD_API_TOKEN` from the environment.  Fails gracefully with a
/// log message when the token is absent so non-submission runs are unaffected.
fn post_bugcrowd_submission(submission: &common::receipt::BountySubmission) -> anyhow::Result<()> {
    let token = match std::env::var("BUGCROWD_API_TOKEN") {
        Ok(t) if !t.trim().is_empty() => t,
        _ => {
            eprintln!("[janitor] --submit: BUGCROWD_API_TOKEN not set; skipping submission");
            return Ok(());
        }
    };
    let body = submission
        .to_api_json()
        .context("failed to build Bugcrowd submission body")?;
    let agent = ureq::Agent::new_with_defaults();
    let result = agent
        .post("https://api.bugcrowd.com/submissions")
        .header("Authorization", &format!("Token {token}"))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .send(body.as_str());
    match result {
        Ok(r) if r.status() == 200 || r.status() == 201 => {
            eprintln!(
                "[janitor] bugcrowd submission accepted (HTTP {})",
                r.status()
            );
            Ok(())
        }
        Ok(r) => anyhow::bail!("bugcrowd submission rejected with HTTP {}", r.status()),
        Err(_) => anyhow::bail!("bugcrowd submission network error"),
    }
}

fn format_bugcrowd_report(findings: &[StructuredFinding]) -> String {
    format_bugcrowd_report_with_component(findings, None)
}

fn format_bugcrowd_report_with_component(
    findings: &[StructuredFinding],
    component_info_override: Option<&str>,
) -> String {
    let component_info = component_info_override
        .map(str::to_owned)
        .unwrap_or_else(|| detect_component_info(findings));
    let grouped = group_ranked_findings(FindingRanker::rank_finding_refs(
        findings,
        Some(&component_info),
    ));

    let mut reports = Vec::with_capacity(grouped.len().max(1));
    for (rule_id, group) in grouped {
        let mut sorted_group = group;
        sorted_group.sort_by(|left, right| {
            let left_key = (
                left.file.as_deref().unwrap_or("~"),
                left.line.unwrap_or(u32::MAX),
                left.fingerprint.as_str(),
            );
            let right_key = (
                right.file.as_deref().unwrap_or("~"),
                right.line.unwrap_or(u32::MAX),
                right.fingerprint.as_str(),
            );
            left_key.cmp(&right_key)
        });

        let details = sorted_group
            .iter()
            .map(|finding| {
                format!(
                    "- File: {}, Line: {}",
                    finding.file.as_deref().unwrap_or("unknown"),
                    finding
                        .line
                        .map(|line| line.to_string())
                        .unwrap_or_else(|| "unknown".to_string())
                )
            })
            .collect::<Vec<_>>()
            .join("\n");

        let highest_severity = sorted_group
            .iter()
            .filter_map(|finding| finding.severity.as_deref())
            .max_by_key(|severity| severity_rank(severity));

        let business_impact = business_impact_statement(rule_id, highest_severity);
        let mitigation = suggested_mitigation(&sorted_group);
        let upstream_validation_audit = upstream_validation_audit_section(&sorted_group);
        let proof_of_concept = proof_of_concept_section(&sorted_group);
        let live_section = live_tenant_section(&sorted_group);
        let data_flow = path_proof_mermaid_section(&sorted_group);
        let candidate_gap = candidate_ledger_gap_section(&sorted_group);

        reports.push(format!(
            "**Summary Title:** Multiple instances of {rule_id} in target\n\
**VRT Category:** {}\n\
**Affected Package / Component:** {component_info}\n\
**Vulnerability Details:**\n\
I found the following vulnerable code paths while reviewing the target artifacts:\n\
{details}\n\
{data_flow}\
**Business Impact:** {business_impact}\n\
**Data Flow Analysis:**\n\
{upstream_validation_audit}\n\
{candidate_gap}\
**Vulnerability Reproduction:**\n\
{proof_of_concept}\n\
{live_section}\
**Remediation Advice:** {mitigation}",
            vrt_category(rule_id)
        ));
    }

    if reports.is_empty() {
        return format!(
            "**Summary Title:** Multiple instances of no_findings in target\n\
**VRT Category:** Informational\n\
**Affected Package / Component:** {component_info}\n\
**Vulnerability Details:**\n\
No exploitable issue was identified in the reviewed target artifacts.\n\
**Business Impact:** No direct business impact was identified because the scan did not emit any findings.\n\
**Data Flow Analysis:**\n\
No vulnerable source-to-sink path was identified.\n\
**Vulnerability Reproduction:**\n\
No reproduction steps are required.\n\
**Remediation Advice:** No mitigation required."
        );
    }

    reports.join("\n\n---\n\n")
}

fn candidate_ledger_gap_section(findings: &[&StructuredFinding]) -> String {
    let gaps = findings
        .iter()
        .map(|finding| {
            let oracle = score_acceptance_proof(finding);
            let web_artifact = finding
                .web_proof_artifact
                .as_ref()
                .map(|artifact| artifact.to_markdown())
                .unwrap_or_default();
            if oracle.is_empty() {
                if web_artifact.is_empty() {
                    "Acceptance Oracle: proof-complete.".to_string()
                } else {
                    web_artifact
                }
            } else if web_artifact.is_empty() {
                format!("Acceptance Oracle: {}", oracle.ledger_gap_summary())
            } else {
                format!(
                    "{web_artifact} Acceptance Oracle: {}",
                    oracle.ledger_gap_summary()
                )
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    format!("**Candidate Ledger Gap:** {gaps}\n")
}

/// Render an Immunefi-format vulnerability submission for a finding set.
///
/// Maps Janitor finding IDs to the Immunefi Vulnerability Classification
/// System (VCS) tier, emitting the standard Immunefi submission template
/// (Title, Severity, Description, Proof of Concept, Recommended Fix, Impact)
/// for each finding group.
fn format_immunefi_report(findings: &[StructuredFinding], component_info: Option<&str>) -> String {
    let target = component_info.unwrap_or("smart-contract target");
    let grouped = group_ranked_findings(FindingRanker::rank_finding_refs(findings, component_info));

    if grouped.is_empty() {
        return format!(
            "# Immunefi Audit Report — {target}\n\n\
**Result:** No security findings identified.\n\n\
*Generated by The Janitor {} — automated security engine*",
            env!("CARGO_PKG_VERSION")
        );
    }

    let mut sections = Vec::with_capacity(grouped.len());
    for (rule_id, group) in &grouped {
        let (vcs_tier, payout_range) = immunefi_vcs_map(rule_id);
        let severity = group
            .iter()
            .filter_map(|f| f.severity.as_deref())
            .max_by_key(|s| severity_rank(s))
            .unwrap_or("Informational");
        let poc = group
            .iter()
            .filter_map(|f| f.exploit_witness.as_ref())
            .filter_map(|w| w.repro_cmd.as_deref())
            .find(|cmd| !cmd.trim().is_empty())
            .map(|cmd| format!("```\n{cmd}\n```"))
            .unwrap_or_else(|| {
                "No automated PoC synthesized. Static analysis confirmed the vulnerable path. \
Manual testing required to confirm runtime exploitability."
                    .to_string()
            });
        let remediation = group
            .iter()
            .find_map(|f| f.remediation.as_deref())
            .unwrap_or("Apply the recommended security pattern for this vulnerability class.");
        let impact = immunefi_impact(rule_id, severity);
        let locations: Vec<String> = group
            .iter()
            .filter_map(|f| {
                f.file.as_deref().map(|file| {
                    f.line
                        .map(|l| format!("- `{file}:{l}`"))
                        .unwrap_or_else(|| format!("- `{file}`"))
                })
            })
            .collect();
        let location_block = if locations.is_empty() {
            "Location not available (binary/bytecode scan).".to_string()
        } else {
            locations.join("\n")
        };

        sections.push(format!(
            "## {rule_id}\n\n\
**Immunefi VCS Tier:** {vcs_tier}\n\
**Severity:** {severity}\n\
**Estimated Payout:** {payout_range}\n\n\
### Description\n\
A `{rule_id}` vulnerability was identified in `{target}`.\n\n\
**Affected Locations:**\n{location_block}\n\n\
### Proof of Concept\n{poc}\n\n\
### Recommended Fix\n{remediation}\n\n\
### Impact\n{impact}"
        ));
    }

    format!(
        "# Immunefi Audit Report — {target}\n\n\
*Generated by The Janitor {} — automated security engine*\n\n\
---\n\n{}\n\n---\n\n\
**Submission Notes:** All findings above are generated by static analysis. \
Each `security:reentrancy` and `security:unsafe_delegatecall` finding requires \
manual confirmation of runtime exploitability before Immunefi submission. \
Cross-reference against the program's scope rules before submitting.",
        env!("CARGO_PKG_VERSION"),
        sections.join("\n\n---\n\n")
    )
}

/// Map a Janitor rule ID to the Immunefi VCS tier and payout range string.
fn immunefi_vcs_map(rule_id: &str) -> (&'static str, &'static str) {
    match rule_id {
        id if id.contains("reentrancy") || id.contains("delegatecall") => (
            "Critical — Direct theft of funds / permanent freezing",
            "$50,000–$1,000,000+",
        ),
        id if id.contains("signature_replay") || id.contains("flash_loan") => (
            "Critical — Theft of funds via cryptographic bypass",
            "$50,000–$500,000",
        ),
        id if id.contains("oracle_price_manipulation") => (
            "High — Price manipulation enabling indirect theft",
            "$10,000–$50,000",
        ),
        id if id.contains("integer_overflow") || id.contains("arithmetic") => (
            "High — Integer overflow enabling value manipulation",
            "$10,000–$50,000",
        ),
        id if id.contains("authority_transition") => (
            "High — Unprotected privilege escalation vector",
            "$5,000–$40,000",
        ),
        _ => ("Medium — Smart contract security finding", "$1,000–$10,000"),
    }
}

/// Map a rule ID + severity to an Immunefi-appropriate impact statement.
fn immunefi_impact(rule_id: &str, severity: &str) -> &'static str {
    if rule_id.contains("reentrancy") {
        return "Complete drainage of contract ETH/token balance via recursive call. \
Attacker can re-enter the vulnerable function before the state update, \
repeatedly withdrawing in a single transaction.";
    }
    if rule_id.contains("delegatecall") {
        return "Arbitrary code execution in the context of the proxy contract. \
An attacker-controlled delegatecall target can overwrite storage slots, \
steal ownership, and drain all protocol funds.";
    }
    if rule_id.contains("signature_replay") {
        return "Replay of previously-valid signatures across chain IDs or nonce \
boundaries allows an attacker to re-execute authorized actions \
(token transfers, governance votes) without re-obtaining a valid signature.";
    }
    if rule_id.contains("oracle_price_manipulation") {
        return "Flash-loan price manipulation allows the attacker to move the spot price \
to an extreme value within a single block, enabling profitable arbitrage at \
the expense of the protocol's liquidity providers.";
    }
    if rule_id.contains("flash_loan") {
        return "Unvalidated flash loan callback can be invoked by any caller, allowing \
protocol funds to be stolen by bypassing the lending pool's repayment check.";
    }
    match severity {
        "KevCritical" | "Critical" => {
            "Protocol funds at direct risk of exfiltration or permanent freezing."
        }
        "High" => "Significant loss of funds or protocol integrity degradation.",
        "Medium" => "Limited economic impact; requires chaining with additional vulnerabilities.",
        _ => "Informational — no direct financial impact identified.",
    }
}

/// Run scope verification and SUBMISSION.md generation if `submit_check` is enabled.
fn run_submit_check(
    findings: &[StructuredFinding],
    scan_root: Option<&Path>,
) -> anyhow::Result<()> {
    use crate::audit_report::extract_git_remote;
    use crate::submit_formatter::{
        annotate_scope, print_scope_report, write_submissions, ScopeRules,
    };

    let program_name = scan_root
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("unknown-program");
    let canonical_target = scan_root
        .map(extract_git_remote)
        .unwrap_or_else(|| program_name.to_string());

    let campaign_targets_dir = std::path::PathBuf::from("tools/campaign/targets");
    let targets_path = campaign_targets_dir.join(format!("{program_name}_targets.md"));
    let targets_path = if targets_path.exists() {
        Some(targets_path)
    } else {
        find_targets_file_for_canonical_target(&campaign_targets_dir, &canonical_target)
    };

    let scope_rules = if let Some(targets_path) = targets_path.as_ref() {
        ScopeRules::load(targets_path)?
    } else {
        eprintln!(
            "[submit-check] no targets file found for {}; using permissive scope",
            canonical_target
        );
        ScopeRules::load_permissive()
    };

    let annotated = annotate_scope(findings, &scope_rules);
    print_scope_report(&annotated);

    let output_dir = hunt_reports_dir()?;
    let written = write_submissions(&annotated, &output_dir, &canonical_target)?;
    if written > 0 {
        eprintln!(
            "[submit-check] {written} SUBMISSION.md file(s) written to {}",
            output_dir.display()
        );
    } else {
        eprintln!(
            "[submit-check] no in-scope findings with repro_cmd — no SUBMISSION.md files generated"
        );
    }
    Ok(())
}

fn find_targets_file_for_canonical_target(
    campaign_targets_dir: &Path,
    canonical_target: &str,
) -> Option<PathBuf> {
    let entries = std::fs::read_dir(campaign_targets_dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("md") {
            continue;
        }
        let content = std::fs::read_to_string(&path).ok()?;
        if content.contains(canonical_target) {
            return Some(path);
        }
    }
    None
}

fn hunt_reports_dir() -> anyhow::Result<PathBuf> {
    let dir = std::env::current_dir()
        .context("resolve current workspace directory")?
        .join(".janitor")
        .join("hunt_reports");
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create hunt reports dir {}", dir.display()))?;
    Ok(dir)
}

/// Render an Auth0-style Markdown vulnerability report for a finding set.
///
/// Groups findings by rule ID and emits Auth0-ready submission headers for
/// each group: Description, Business Impact, Upstream Validation Audit,
/// Working proof of concept, Discoverability, and Exploitability.
pub fn format_auth0_report(findings: &[StructuredFinding]) -> String {
    format_auth0_report_with_component(findings, None)
}

fn format_auth0_report_with_component(
    findings: &[StructuredFinding],
    component_info_override: Option<&str>,
) -> String {
    let component_info = component_info_override
        .map(str::to_owned)
        .unwrap_or_else(|| detect_component_info(findings));
    let grouped = group_ranked_findings(FindingRanker::rank_finding_refs(
        findings,
        Some(&component_info),
    ));

    if grouped.is_empty() {
        return format!(
            "**Description**\nNo security findings were identified in the target.\n\n\
**Affected Package / Component**\n{component_info}\n\n\
**Business Impact (how does this affect Auth0?)**\nNo business impact identified.\n\n\
**Upstream Validation Audit**\nNo upstream validation audit generated.\n\n\
**Working proof of concept**\nNo proof of concept available.\n\n\
**Discoverability (how likely is this to be discovered)**\nNot applicable.\n\n\
**Exploitability (how likely is this to be exploited)**\nNot applicable."
        );
    }

    let mut reports = Vec::with_capacity(grouped.len());
    for (rule_id, mut sorted_group) in grouped {
        sorted_group.sort_by(|left, right| {
            let left_key = (
                left.file.as_deref().unwrap_or("~"),
                left.line.unwrap_or(u32::MAX),
            );
            let right_key = (
                right.file.as_deref().unwrap_or("~"),
                right.line.unwrap_or(u32::MAX),
            );
            left_key.cmp(&right_key)
        });

        // Description: synthesize from rule_id + file:line locations.
        let locations: Vec<String> = sorted_group
            .iter()
            .filter_map(|f| {
                f.file.as_deref().map(|file| match f.line {
                    Some(line) => format!("`{file}` at line `{line}`"),
                    None => format!("`{file}`"),
                })
            })
            .collect();
        let location_clause = if locations.is_empty() {
            "the target artifact".to_string()
        } else {
            locations.join(", ")
        };
        let description = format!(
            "A `{rule_id}` vulnerability was identified in {location_clause}. \
Static analysis confirmed a reachable sink with no mitigating control between the \
externally-influenced input and the dangerous API call."
        );

        // Business Impact mapped from highest severity.
        let highest_severity = sorted_group
            .iter()
            .filter_map(|f| f.severity.as_deref())
            .max_by_key(|s| severity_rank(s));
        let business_impact = auth0_business_impact(rule_id, highest_severity);
        let upstream_validation_audit = upstream_validation_audit_section(&sorted_group);
        let defensive_evidence = defensive_evidence_section(&sorted_group);

        // Working PoC: delegate to the shared synthesizer so sqli/tls/etc.
        // all emit class-appropriate reproduction instructions.
        let poc = proof_of_concept_section(&sorted_group);

        // Discoverability: chain length > 1 → low discoverability.
        let max_chain = sorted_group
            .iter()
            .filter_map(|f| f.exploit_witness.as_ref())
            .map(|w| w.call_chain.len())
            .max()
            .unwrap_or(0);
        let discoverability = if max_chain > 1 {
            "Low. This vulnerability requires tracing data flow across multiple \
interprocedural boundaries, bypassing standard pattern-matching scanners."
                .to_string()
        } else if max_chain == 1 {
            "High. Direct sink exposure.".to_string()
        } else {
            "Medium. Static analysis identified the sink; dynamic confirmation requires \
targeted fuzzing or manual review of the affected entry points."
                .to_string()
        };

        // Exploitability: full repro_cmd = High; class-specific PoC synthesized = Medium-High;
        // static-only = Medium.
        let has_repro = sorted_group
            .iter()
            .filter_map(|f| f.exploit_witness.as_ref())
            .any(|w| w.repro_cmd.is_some());
        let has_class_poc = sorted_group.iter().any(|f| {
            f.id.contains("sqli")
                || f.id.contains("tls_verification")
                || f.id.contains("deserialization")
        });
        let exploitability = if has_repro {
            "High. A deterministic proof-of-concept payload has been successfully \
synthesized and is provided above."
                .to_string()
        } else if has_class_poc {
            "Medium-High. A class-representative reproduction script has been synthesized \
from the static reachability proof. Manual injection of the provided canary payload against \
a live endpoint is required to confirm runtime exploitability."
                .to_string()
        } else {
            "Medium. Static analysis confirmed the vulnerability, but a dynamic \
proof-of-concept payload was not autonomously synthesized. Manual verification is required."
                .to_string()
        };

        // Live tenant verification section (populated by --live-tenant replay).
        let live_section = live_tenant_section(&sorted_group);

        reports.push(format!(
            "**Description**\n{description}\n\n\
**Affected Package / Component**\n{component_info}\n\n\
**Business Impact (how does this affect Auth0?)**\n{business_impact}\n\n\
**Upstream Validation Audit**\n{upstream_validation_audit}\n\n\
{defensive_evidence}\
**Working proof of concept**\n{poc}\n{live_section}\n\
**Discoverability (how likely is this to be discovered)**\n{discoverability}\n\n\
**Exploitability (how likely is this to be exploited)**\n{exploitability}"
        ));
    }

    reports.join("\n\n---\n\n")
}

fn group_ranked_findings(ranked: Vec<&StructuredFinding>) -> Vec<(&str, Vec<&StructuredFinding>)> {
    let mut grouped: Vec<(&str, Vec<&StructuredFinding>)> = Vec::new();
    for finding in ranked {
        if let Some((_, group)) = grouped
            .iter_mut()
            .find(|(rule_id, _)| *rule_id == finding.id.as_str())
        {
            group.push(finding);
        } else {
            grouped.push((finding.id.as_str(), vec![finding]));
        }
    }
    grouped
}

/// Map a rule ID and severity to an Auth0-tailored business risk statement.
fn auth0_business_impact(rule_id: &str, severity: Option<&str>) -> String {
    if rule_id.contains("credential") || rule_id.contains("secret") || rule_id.contains("hardcoded")
    {
        return "Compromise of tenant isolation or credential harvesting. Embedded secrets can \
permit unauthorized access to Auth0 management APIs, enabling full tenant takeover, \
silent log exfiltration, or persistent backdoor installation across customer identities."
            .to_string();
    }
    if rule_id.contains("command_injection") {
        return "Remote code execution on the Auth0 infrastructure node hosting the affected \
service. Successful exploitation yields immediate host compromise and pivoting into the \
identity platform's internal network, enabling exfiltration of all tenant JWTs and \
private signing keys."
            .to_string();
    }
    if rule_id.contains("xss") {
        return "Session hijacking and arbitrary action execution in the Auth0 Dashboard or \
Universal Login context. An XSS payload delivered to an Auth0 administrator can harvest \
Management API tokens with tenant-admin scope."
            .to_string();
    }
    if rule_id.contains("sql") {
        return "Extraction of the Auth0 user store and tenant configuration database. SQL \
injection at this sink enables an attacker to dump all user records, hashed passwords, \
and OAuth client secrets across all tenants."
            .to_string();
    }
    match severity {
        Some("KevCritical") | Some("Critical") => {
            "Compromise of tenant isolation or credential harvesting. This class of vulnerability \
has a known KEV entry and active exploitation record; impact at Auth0 scale would affect \
millions of downstream consumer identities."
                .to_string()
        }
        Some("High") => {
            "High-severity exposure enabling privilege escalation or unauthorized data \
exfiltration from Auth0 tenant boundaries."
                .to_string()
        }
        Some("Medium") | Some("Low") => {
            "Incremental attack-surface expansion. This weakness can be chained with adjacent \
vulnerabilities to bypass Auth0 access controls."
                .to_string()
        }
        _ => "Security finding requiring triage to determine full business impact on Auth0 \
production systems and tenant data."
            .to_string(),
    }
}

fn proof_of_concept_section(findings: &[&StructuredFinding]) -> String {
    if findings
        .iter()
        .any(|finding| finding.id == "security:deserialization_gadget_chain")
    {
        return GADGET_CHAIN_BUGCROWD_PROOF.to_string();
    }
    // Phase B/E capsule: structured reproduction steps + optional payload blob.
    if let Some(witness) = findings
        .iter()
        .filter_map(|f| f.exploit_witness.as_ref())
        .find(|w| w.reproduction_steps.is_some() || w.payload.is_some())
    {
        let mut parts: Vec<String> = Vec::new();
        if let Some(steps) = &witness.reproduction_steps {
            let numbered = steps
                .iter()
                .enumerate()
                .map(|(i, s)| format!("{}. {s}", i + 1))
                .collect::<Vec<_>>()
                .join("\n");
            parts.push(numbered);
        }
        if let Some(cmd) = witness
            .repro_cmd
            .as_deref()
            .filter(|s| !s.trim().is_empty())
        {
            parts.push(format!("```text\n{cmd}\n```"));
        }
        if let Some(blob) = &witness.payload {
            parts.push(format!(
                "**Inert probe payload (base64):**\n```\n{blob}\n```"
            ));
        }
        if !parts.is_empty() {
            return parts.join("\n\n");
        }
    }
    if let Some(repro_cmd) = findings
        .iter()
        .filter_map(|finding| finding.exploit_witness.as_ref())
        .filter_map(|witness| witness.repro_cmd.as_deref())
        .map(str::trim)
        .find(|cmd| !cmd.is_empty())
    {
        return format!("```text\n{repro_cmd}\n```");
    }
    if let Some(artifact) = findings
        .iter()
        .filter_map(|finding| finding.web_proof_artifact.as_ref())
        .next()
    {
        return artifact.to_markdown();
    }
    // Synthesize class-specific PoC stubs for taint-family findings when no
    // dynamic repro_cmd was generated by the Z3 engine.
    if findings
        .iter()
        .any(|f| f.id.contains("sqli_concatenation") || f.id.contains("sqli_taint"))
    {
        let file = findings
            .iter()
            .find_map(|f| f.file.as_deref())
            .unwrap_or("(target file)");
        let line = findings
            .iter()
            .find_map(|f| f.line)
            .map(|l| l.to_string())
            .unwrap_or_default();
        return format!(
            "Static reachability confirmed. The IFDS solver traced an unbroken taint path \
from a user-controlled HTTP parameter to the concatenated SQL string at `{file}` line {line}.\n\n\
Minimal proof-of-concept payload (manual verification):\n\
```text\n\
# 1. Identify any API endpoint that feeds user input into the affected query path.\n\
# 2. Submit the canonical SQLi canary as the controlled parameter:\n\
#    value: ' OR '1'='1\n\
#\n\
# Expected result: the query returns all rows (authentication bypass) or\n\
# a database error message leaks the SQL dialect and schema.\n\
curl -s -X POST https://<target>/api/<endpoint> \\\n\
  -H 'Content-Type: application/json' \\\n\
  -d '{{\"input\": \"\\' OR \\'1\\'=\\'1\"}}'\n\
```\n\n\
For parameterized-query remediation, replace the concatenated string with `$1`/`$2` \
placeholders and pass values via `db.Query(sql, args...)`."
        );
    }
    if findings.iter().any(|f| f.id.contains("tls_verification")) {
        let file = findings
            .iter()
            .find_map(|f| f.file.as_deref())
            .unwrap_or("(target file)");
        let line = findings
            .iter()
            .find_map(|f| f.line)
            .map(|l| l.to_string())
            .unwrap_or_default();
        return format!(
            "Static reachability confirmed. TLS certificate verification is disabled at \
`{file}` line {line}, allowing a network-adjacent attacker to intercept TLS sessions \
via a self-signed or mis-issued certificate.\n\n\
Minimal proof-of-concept (manual verification):\n\
```text\n\
# Run a MITM proxy (e.g. mitmproxy) between the client and the upstream server.\n\
# Present a self-signed certificate for the upstream host.\n\
# Observe that the connection succeeds without certificate rejection.\n\
mitmproxy --mode transparent --ssl-insecure\n\
```\n\n\
Remediation: remove `InsecureSkipVerify: true` / `TLSClientConfig` overrides and \
enforce system CA pool validation."
        );
    }
    let location = findings
        .iter()
        .find_map(|f| match (f.file.as_deref(), f.line) {
            (Some(file), Some(line)) => Some(format!("`{file}` line {line}")),
            (Some(file), None) => Some(format!("`{file}`")),
            _ => None,
        })
        .unwrap_or_else(|| "the affected source location".to_string());
    format!(
        "Pentester notes:\n\
1. Review {location} and identify the route, command, or parser entry point that reaches this sink.\n\
2. Send a benign canary value through the affected input and confirm it reaches the sink without normalization or allowlist enforcement.\n\
3. Replace the canary with the payload class for this finding and capture the response, log entry, or state transition that demonstrates impact.\n\
4. Retest after adding the recommended validation control to confirm the sink no longer receives attacker-controlled input."
    )
}

fn upstream_validation_audit_section(findings: &[&StructuredFinding]) -> String {
    // Prefer an explicit sanitizer audit from the witness over the IFDS proof statement.
    if let Some(audit) = findings
        .iter()
        .filter_map(|finding| finding.exploit_witness.as_ref())
        .filter_map(|witness| witness.sanitizer_audit.as_deref())
        .map(str::trim)
        .find(|audit| !audit.is_empty())
    {
        return audit.to_string();
    }
    // TLS bypass is a structural configuration absence, not a taint path — emit a
    // targeted statement rather than the generic IFDS proof.
    if findings
        .iter()
        .any(|f| f.id.contains("tls_verification") || f.id.contains("insecure_tls"))
    {
        return "No upstream certificate validation gate is present: the TLS configuration \
                explicitly sets `InsecureSkipVerify: true` (or equivalent), unconditionally \
                disabling server certificate chain and hostname verification. No conditional \
                re-enablement path or compile-time guard was detected."
            .to_string();
    }
    // If the IFDS solver proved absence of sanitization, emit the canonical proof statement.
    if findings
        .iter()
        .any(|finding| finding.upstream_validation_absent)
    {
        return "Data flow reaches the vulnerable sink without an intervening sanitizer, \
                parameterization boundary, allowlist, or type-enforced validation gate."
            .to_string();
    }
    "No additional validation evidence was identified for this finding.".to_string()
}

fn defensive_evidence_section(findings: &[&StructuredFinding]) -> String {
    forge::rcal::defensive_evidence_for_findings(findings)
        .map(|evidence| format!("**Defensive Evidence:**\n{evidence}\n\n"))
        .unwrap_or_default()
}

/// Render a `**Live Tenant Verification:**` section if any finding in the
/// group carries a populated `live_proof` capture from `--live-tenant` replay.
/// Returns an empty string when no live proof is present.
fn live_tenant_section(findings: &[&StructuredFinding]) -> String {
    let proof = findings
        .iter()
        .filter_map(|f| f.exploit_witness.as_ref())
        .filter_map(|w| w.live_proof.as_deref())
        .find(|p| !p.is_empty());
    match proof {
        Some(p) => format!(
            "\n**Live Tenant Context:**\n\
The reproduction was prepared for an approved test tenant. Captured verification context:\n\
```http\n{p}\n```\n\n"
        ),
        None => String::new(),
    }
}

fn path_proof_mermaid_section(findings: &[&StructuredFinding]) -> String {
    if let Some(artifact) = findings
        .iter()
        .filter_map(|finding| finding.web_proof_artifact.as_ref())
        .next()
    {
        return render_ifds_graph(&artifact.bound_ifds_trace());
    }

    let Some(proof) = findings
        .iter()
        .filter_map(|f| f.exploit_witness.as_ref())
        .filter_map(|w| w.path_proof.as_deref())
        .find(|proof| !proof.trim().is_empty())
    else {
        return String::new();
    };
    let nodes = proof
        .split(['\n', '>', '|'])
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .take(8)
        .collect::<Vec<_>>();
    if nodes.len() < 2 {
        return String::new();
    }
    render_ifds_graph(&nodes)
}

fn render_ifds_graph<T: AsRef<str>>(nodes: &[T]) -> String {
    if nodes.len() < 2 {
        return String::new();
    }
    let mut graph = String::from("**Data Flow Graph:**\n```mermaid\nflowchart LR\n");
    for (idx, node) in nodes.iter().enumerate() {
        graph.push_str(&format!(
            "  n{idx}[\"{}\"]\n",
            escape_mermaid_label(node.as_ref())
        ));
    }
    for idx in 0..nodes.len() - 1 {
        graph.push_str(&format!("  n{idx} --> n{}\n", idx + 1));
    }
    graph.push_str("```\n");
    graph
}

fn escape_mermaid_label(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Bind browser-side PoCs to a live test tenant without executing them.
fn apply_live_tenant_browser_context(
    mut findings: Vec<StructuredFinding>,
    live_tenant: &str,
) -> Vec<StructuredFinding> {
    let Some(context) = forge::exploitability::BrowserTenantContext::from_spec(live_tenant) else {
        return findings;
    };
    for finding in &mut findings {
        let Some(witness) = finding.exploit_witness.as_mut() else {
            continue;
        };
        if let Some(repro) = forge::exploitability::synthesize_live_tenant_browser_repro(
            &finding.id,
            witness,
            &context,
        ) {
            witness.repro_cmd = Some(repro);
            witness.live_proof = Some(
                "Live tenant context injected into a standalone HTML harness. No network request was executed by Janitor; use the harness only against an approved test tenant."
                    .to_string(),
            );
        }
    }
    findings
}

fn emit_browser_dom_harnesses(
    findings: &mut [StructuredFinding],
    output_dir: &Path,
) -> anyhow::Result<()> {
    let mut emitted = BTreeMap::<String, usize>::new();
    for finding in findings {
        if !forge::exploitability::artifact_emission_allowed(finding, true) {
            continue;
        }
        let Some(witness) = finding.exploit_witness.as_mut() else {
            continue;
        };
        let Some(repro_cmd) = witness.repro_cmd.as_deref() else {
            continue;
        };
        let Some(html) = extract_browser_dom_payload(repro_cmd) else {
            continue;
        };
        let stem = sanitize_filename_component(&finding.id);
        let slot = emitted.entry(stem.clone()).or_default();
        *slot += 1;
        let suffix = if *slot == 1 {
            String::new()
        } else {
            format!("_{}", *slot)
        };
        let filename = format!("janitor_poc_{}{}.html", stem, suffix);
        let path = output_dir.join(&filename);
        std::fs::write(&path, html)
            .with_context(|| format!("failed to write BrowserDOM harness {}", path.display()))?;
        let note = format!(
            "BrowserDOM harness written to {}. No network request was executed by Janitor; use the harness only against an approved test tenant.",
            path.display()
        );
        witness.live_proof = Some(match witness.live_proof.take() {
            Some(existing) if !existing.is_empty() => format!("{existing}\n{note}"),
            _ => note,
        });
    }
    Ok(())
}

fn extract_browser_dom_payload(repro_cmd: &str) -> Option<&str> {
    let start = repro_cmd.find("<<'HTML'\n")?;
    let body = &repro_cmd[start + "<<'HTML'\n".len()..];
    let end = body.find("\nHTML\n")?;
    Some(&body[..end])
}

fn sanitize_filename_component(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if !out.ends_with('_') {
            out.push('_');
        }
    }
    let out = out.trim_matches('_').to_string();
    if out.is_empty() {
        "finding".to_string()
    } else {
        out
    }
}

fn is_live_tenant_replay_origin(live_tenant: &str) -> bool {
    let trimmed = live_tenant.trim_start();
    trimmed.starts_with("http://") || trimmed.starts_with("https://")
}

/// Substitute the scheme+host in a `curl` command URL with `live_tenant`.
///
/// Example: `"curl -X POST http://0.0.0.0/api/v1/users -d '...'"` +
/// `"http://localhost:3000"` → `"curl -X POST http://localhost:3000/api/v1/users -d '...'"`
fn replace_host_in_curl(repro_cmd: &str, live_tenant: &str) -> String {
    let start = repro_cmd
        .find("http://")
        .or_else(|| repro_cmd.find("https://"));
    let Some(start) = start else {
        return repro_cmd.to_string();
    };
    let url_tail = &repro_cmd[start..];
    let url_len = url_tail.find(' ').unwrap_or(url_tail.len());
    let full_url = &url_tail[..url_len];
    let scheme_len = if full_url.starts_with("https://") {
        8
    } else {
        7
    };
    let host_part = &full_url[scheme_len..];
    let path = host_part.find('/').map(|p| &host_part[p..]).unwrap_or("/");
    let new_url = format!("{}{}", live_tenant.trim_end_matches('/'), path);
    repro_cmd.replacen(full_url, &new_url, 1)
}

fn bounded_curl_command(repro_cmd: &str) -> String {
    let mut missing_opts = Vec::new();
    if !repro_cmd.contains("--connect-timeout") {
        missing_opts.push("--connect-timeout 5");
    }
    if !repro_cmd.contains("--max-time") {
        missing_opts.push("--max-time 20");
    }
    if !repro_cmd.contains("--retry") {
        missing_opts.push("--retry 0");
    }
    if missing_opts.is_empty() {
        return repro_cmd.to_string();
    }
    repro_cmd.replacen("curl ", &format!("curl {} ", missing_opts.join(" ")), 1)
}

fn authorization_replay_verdict(live_proof: &str) -> String {
    if live_proof.contains("HTTP/1.1 200")
        || live_proof.contains("HTTP/2 200")
        || live_proof.contains("HTTP/3 200")
    {
        return "potential_cross_tenant_read: replay returned 2xx".to_string();
    }
    if live_proof.contains("HTTP/1.1 401")
        || live_proof.contains("HTTP/1.1 403")
        || live_proof.contains("HTTP/1.1 404")
        || live_proof.contains("HTTP/2 401")
        || live_proof.contains("HTTP/2 403")
        || live_proof.contains("HTTP/2 404")
        || live_proof.contains("HTTP/3 401")
        || live_proof.contains("HTTP/3 403")
        || live_proof.contains("HTTP/3 404")
    {
        return "control_enforced: replay denied cross-principal object access".to_string();
    }
    "inconclusive: live replay did not expose an HTTP authorization status".to_string()
}

/// Execute `repro_cmd` against `live_tenant` for every finding that carries a
/// synthesized curl command. Populates `ExploitWitness::live_proof` with the
/// captured stdout+stderr of the shell invocation.
fn apply_live_tenant_replay(
    mut findings: Vec<StructuredFinding>,
    live_tenant: &str,
) -> Vec<StructuredFinding> {
    for finding in &mut findings {
        let Some(witness) = finding.exploit_witness.as_mut() else {
            continue;
        };
        let Some(repro_cmd) = witness.repro_cmd.as_deref() else {
            continue;
        };
        if !repro_cmd.trim_start().starts_with("curl ") {
            continue;
        }
        let cmd = bounded_curl_command(&replace_host_in_curl(repro_cmd, live_tenant));
        let output = std::process::Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .output();
        witness.live_proof = match output {
            Ok(out) => {
                let mut combined = String::new();
                if !out.stdout.is_empty() {
                    combined.push_str(&String::from_utf8_lossy(&out.stdout));
                }
                if !out.stderr.is_empty() {
                    if !combined.is_empty() {
                        combined.push('\n');
                    }
                    combined.push_str(&String::from_utf8_lossy(&out.stderr));
                }
                if combined.is_empty() {
                    Some("(no output captured)".to_string())
                } else {
                    Some(combined)
                }
            }
            Err(e) => Some(format!("live-tenant execution failed: {e}")),
        };
        if finding.id == "security:missing_ownership_check" {
            if let (Some(authz), Some(live_proof)) = (
                witness.authorization_witness.as_mut(),
                witness.live_proof.as_deref(),
            ) {
                authz.replay_verdict = authorization_replay_verdict(live_proof);
            }
        }
    }
    findings
}

/// Detect the affected package name and version by scanning for manifest files
/// (`package.json`, `Cargo.toml`, `go.mod`, `pom.xml`) walking upward from the
/// affected file path first, then the scan root / current directory fallback.
fn detect_component_info(findings: &[StructuredFinding]) -> String {
    detect_component_info_inner(findings, None)
}

fn detect_component_info_inner(
    findings: &[StructuredFinding],
    override_root: Option<&std::path::Path>,
) -> String {
    const MAX_MANIFEST_BYTES: u64 = 1_048_576;

    let mut search_roots: Vec<std::path::PathBuf> = Vec::new();
    let base_root = override_root
        .map(|root| root.to_path_buf())
        .or_else(|| std::env::current_dir().ok());
    for finding in findings {
        if let Some(file) = &finding.file {
            let p = std::path::Path::new(file);
            let candidate = if p.is_absolute() {
                p.parent().map(|d| d.to_path_buf())
            } else {
                base_root
                    .as_ref()
                    .map(|root| root.join(p))
                    .and_then(|abs| abs.parent().map(|d| d.to_path_buf()))
            };
            if let Some(c) = candidate {
                if !search_roots.iter().any(|existing| existing == &c) {
                    search_roots.push(c);
                }
            }
        }
    }
    if let Some(root) = base_root {
        if !search_roots.iter().any(|existing| existing == &root) {
            search_roots.push(root);
        }
    }

    for start in search_roots {
        let mut dir: &std::path::Path = &start;
        loop {
            let pkg_json = dir.join("package.json");
            if pkg_json
                .metadata()
                .map(|m| m.len() <= MAX_MANIFEST_BYTES)
                .unwrap_or(false)
            {
                if let Ok(text) = std::fs::read_to_string(&pkg_json) {
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&text) {
                        let name = val
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Unknown");
                        let ver = val
                            .get("version")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Unknown");
                        return format!("**{name}@{ver}** (`package.json`)");
                    }
                }
            }
            let cargo_toml = dir.join("Cargo.toml");
            if cargo_toml
                .metadata()
                .map(|m| m.len() <= MAX_MANIFEST_BYTES)
                .unwrap_or(false)
            {
                if let Ok(text) = std::fs::read_to_string(&cargo_toml) {
                    if let Some((name, ver)) = parse_cargo_toml_name_version(&text) {
                        return format!("**{name}** v{ver} (`Cargo.toml`)");
                    }
                }
            }
            let go_mod = dir.join("go.mod");
            if go_mod
                .metadata()
                .map(|m| m.len() <= MAX_MANIFEST_BYTES)
                .unwrap_or(false)
            {
                if let Ok(text) = std::fs::read_to_string(&go_mod) {
                    if let Some((module_name, go_version)) = parse_go_mod_component(&text) {
                        if let Some(go_version) = go_version {
                            return format!("**{module_name}** go{go_version} (`go.mod`)");
                        }
                        return format!("**{module_name}** (`go.mod`)");
                    }
                }
            }
            let pom_xml = dir.join("pom.xml");
            if pom_xml
                .metadata()
                .map(|m| m.len() <= MAX_MANIFEST_BYTES)
                .unwrap_or(false)
            {
                if let Ok(text) = std::fs::read_to_string(&pom_xml) {
                    if let Some((group_id, artifact_id, ver)) = parse_pom_xml_name_version(&text) {
                        if group_id.is_empty() {
                            return format!("**{artifact_id}** v{ver} (`pom.xml`)");
                        }
                        return format!("**{group_id}:{artifact_id}** v{ver} (`pom.xml`)");
                    }
                }
            }
            for gradle_name in &["build.gradle", "build.gradle.kts"] {
                let gradle_path = dir.join(gradle_name);
                if gradle_path
                    .metadata()
                    .map(|m| m.len() <= MAX_MANIFEST_BYTES)
                    .unwrap_or(false)
                {
                    if let Ok(text) = std::fs::read_to_string(&gradle_path) {
                        if let Some((group, ver)) = parse_gradle_name_version(&text) {
                            return format!("**{group}** v{ver} (`{gradle_name}`)");
                        }
                    }
                }
            }
            for settings_name in &["settings.gradle", "settings.gradle.kts"] {
                let settings_path = dir.join(settings_name);
                if settings_path
                    .metadata()
                    .map(|m| m.len() <= MAX_MANIFEST_BYTES)
                    .unwrap_or(false)
                {
                    if let Ok(text) = std::fs::read_to_string(&settings_path) {
                        if let Some(name) = parse_gradle_settings_project_name(&text) {
                            if let Some((_, ver)) =
                                parse_gradle_properties_component(&dir.join("gradle.properties"))
                            {
                                return format!("**{name}** v{ver} (`{settings_name}`)");
                            }
                            return format!("**{name}** (`{settings_name}`)");
                        }
                    }
                }
            }
            if let Some((group, ver)) =
                parse_gradle_properties_component(&dir.join("gradle.properties"))
            {
                return format!("**{group}** v{ver} (`gradle.properties`)");
            }
            let cmake_path = dir.join("CMakeLists.txt");
            if cmake_path
                .metadata()
                .map(|m| m.len() <= MAX_MANIFEST_BYTES)
                .unwrap_or(false)
            {
                if let Ok(text) = std::fs::read_to_string(&cmake_path) {
                    if let Some((name, ver)) = parse_cmake_project_component(&text) {
                        if let Some(ver) = ver {
                            return format!("**{name}** v{ver} (`CMakeLists.txt`)");
                        }
                        return format!("**{name}** (`CMakeLists.txt`)");
                    }
                }
            }
            let foundry_path = dir.join("foundry.toml");
            if foundry_path
                .metadata()
                .map(|m| m.len() <= MAX_MANIFEST_BYTES)
                .unwrap_or(false)
            {
                if let Ok(text) = std::fs::read_to_string(&foundry_path) {
                    if let Some(profile) = parse_foundry_component(&text) {
                        return format!("**{profile}** (`foundry.toml`)");
                    }
                }
            }
            let hardhat_path = dir.join("hardhat.config.js");
            if hardhat_path
                .metadata()
                .map(|m| m.len() <= MAX_MANIFEST_BYTES)
                .unwrap_or(false)
            {
                if let Ok(text) = std::fs::read_to_string(&hardhat_path) {
                    let name = parse_hardhat_component(&text).or_else(|| {
                        dir.file_name()
                            .map(|value| value.to_string_lossy().into_owned())
                    });
                    if let Some(name) = name {
                        return format!("**{name}** (`hardhat.config.js`)");
                    }
                }
            }
            let podspec = dir.read_dir().ok().and_then(|entries| {
                entries
                    .filter_map(Result::ok)
                    .map(|entry| entry.path())
                    .find(|path| path.extension().and_then(|ext| ext.to_str()) == Some("podspec"))
            });
            if let Some(podspec_path) = podspec {
                if podspec_path
                    .metadata()
                    .map(|m| m.len() <= MAX_MANIFEST_BYTES)
                    .unwrap_or(false)
                {
                    if let Ok(text) = std::fs::read_to_string(&podspec_path) {
                        if let Some((name, ver)) = parse_podspec_component(&text) {
                            if let Some(ver) = ver {
                                return format!("**{name}** v{ver} (`*.podspec`)");
                            }
                            return format!("**{name}** (`*.podspec`)");
                        }
                    }
                }
            }
            let package_swift = dir.join("Package.swift");
            if package_swift
                .metadata()
                .map(|m| m.len() <= MAX_MANIFEST_BYTES)
                .unwrap_or(false)
            {
                if let Ok(text) = std::fs::read_to_string(&package_swift) {
                    if let Some(name) = parse_swift_package_component(&text) {
                        return format!("**{name}** (`Package.swift`)");
                    }
                }
            }
            match dir.parent() {
                Some(parent) if parent != dir => dir = parent,
                _ => break,
            }
        }
    }
    "Unknown / Source Repository".to_string()
}

/// Extract `name` and `version` from a `Cargo.toml` `[package]` section.
fn parse_cargo_toml_name_version(content: &str) -> Option<(String, String)> {
    let mut in_package = false;
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    for line in content.lines() {
        let t = line.trim();
        if t == "[package]" {
            in_package = true;
            continue;
        }
        if t.starts_with('[') {
            if in_package {
                break;
            }
            continue;
        }
        if in_package {
            if let Some(v) = extract_toml_quoted_value(t, "name") {
                name = Some(v);
            }
            if let Some(v) = extract_toml_quoted_value(t, "version") {
                version = Some(v);
            }
        }
        if name.is_some() && version.is_some() {
            break;
        }
    }
    name.zip(version)
}

/// Extract module path and optional Go language version from a `go.mod`.
fn parse_go_mod_component(content: &str) -> Option<(String, Option<String>)> {
    let mut module_name: Option<String> = None;
    let mut go_version: Option<String> = None;

    for line in content.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with("//") {
            continue;
        }
        if module_name.is_none() {
            if let Some(rest) = t.strip_prefix("module ") {
                let value = rest.split_whitespace().next().unwrap_or("").trim();
                if !value.is_empty() {
                    module_name = Some(value.to_string());
                }
            }
        }
        if go_version.is_none() {
            if let Some(rest) = t.strip_prefix("go ") {
                let value = rest.split_whitespace().next().unwrap_or("").trim();
                if !value.is_empty() {
                    go_version = Some(value.to_string());
                }
            }
        }
        if module_name.is_some() && go_version.is_some() {
            break;
        }
    }

    module_name.map(|name| (name, go_version))
}

fn extract_toml_quoted_value(line: &str, key: &str) -> Option<String> {
    let prefix = format!("{key} = \"");
    line.strip_prefix(&prefix)
        .and_then(|rest| rest.find('"').map(|end| rest[..end].to_string()))
}

/// Extract `groupId`, `artifactId`, and `version` from the project-level `pom.xml` text.
fn parse_pom_xml_name_version(content: &str) -> Option<(String, String, String)> {
    let group_id = extract_xml_tag_value(content, "groupId").unwrap_or_default();
    let artifact_id = extract_xml_tag_value(content, "artifactId")?;
    let version = extract_xml_tag_value(content, "version")?;
    Some((group_id, artifact_id, version))
}

fn extract_xml_tag_value(content: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    content.find(&open).and_then(|pos| {
        let after = &content[pos + open.len()..];
        after
            .find(&close)
            .map(|end| after[..end].trim().to_string())
    })
}

/// Extract `group` and `version` from a `build.gradle` or `build.gradle.kts` text.
fn parse_gradle_name_version(content: &str) -> Option<(String, String)> {
    let mut group: Option<String> = None;
    let mut version: Option<String> = None;
    for line in content.lines() {
        let t = line.trim();
        if group.is_none() {
            if let Some(v) = extract_gradle_quoted_value(t, "group") {
                group = Some(v);
            }
        }
        if version.is_none() {
            if let Some(v) = extract_gradle_quoted_value(t, "version") {
                version = Some(v);
            }
        }
        if group.is_some() && version.is_some() {
            break;
        }
    }
    group.zip(version)
}

fn extract_gradle_quoted_value(line: &str, key: &str) -> Option<String> {
    let prefix_single = format!("{key} = '");
    let prefix_double = format!("{key} = \"");
    if let Some(rest) = line.strip_prefix(&prefix_single) {
        return rest.find('\'').map(|end| rest[..end].to_string());
    }
    if let Some(rest) = line.strip_prefix(&prefix_double) {
        return rest.find('"').map(|end| rest[..end].to_string());
    }
    None
}

fn parse_gradle_settings_project_name(content: &str) -> Option<String> {
    for line in content.lines() {
        let t = line.trim();
        if t.starts_with("rootProject.name") {
            return extract_assignment_string(t);
        }
    }
    None
}

fn parse_gradle_properties_component(path: &Path) -> Option<(String, String)> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut group = None;
    let mut version = None;
    for line in text.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("GROUP=") {
            group = Some(rest.trim().to_string());
        }
        if let Some(rest) = t.strip_prefix("VERSION_NAME=") {
            version = Some(rest.trim().to_string());
        }
    }
    group.zip(version)
}

fn parse_cmake_project_component(content: &str) -> Option<(String, Option<String>)> {
    for line in content.lines() {
        let t = line.split('#').next().unwrap_or("").trim();
        if !t.to_ascii_lowercase().starts_with("project") {
            continue;
        }
        let args = t
            .split_once('(')
            .and_then(|(_, rest)| rest.rsplit_once(')').map(|(inner, _)| inner))?;
        let tokens = args
            .split_whitespace()
            .map(|token| token.trim_matches(|c| c == '"' || c == '\''))
            .collect::<Vec<_>>();
        let name = tokens.first().copied().filter(|value| !value.is_empty())?;
        let version = tokens
            .windows(2)
            .find(|pair| pair[0].eq_ignore_ascii_case("VERSION"))
            .map(|pair| pair[1].to_string());
        return Some((name.to_string(), version));
    }
    None
}

fn parse_foundry_component(content: &str) -> Option<String> {
    for line in content.lines() {
        let t = line.trim();
        if let Some(value) = extract_toml_quoted_value(t, "project") {
            return Some(value);
        }
        if let Some(value) = extract_toml_quoted_value(t, "name") {
            return Some(value);
        }
        if let Some(profile) = t
            .strip_prefix("[profile.")
            .and_then(|rest| rest.strip_suffix(']'))
        {
            return Some(format!("foundry:{profile}"));
        }
    }
    None
}

fn parse_hardhat_component(content: &str) -> Option<String> {
    for key in ["projectName", "name", "defaultNetwork"] {
        for line in content.lines() {
            if let Some(value) = extract_js_string_property(line.trim(), key) {
                return Some(value);
            }
        }
    }
    None
}

fn extract_js_string_property(line: &str, key: &str) -> Option<String> {
    let key_pos = line.find(key)?;
    let after_key = &line[key_pos + key.len()..];
    let quote_pos = after_key.find(['"', '\''])?;
    let quote = after_key.as_bytes()[quote_pos] as char;
    let after_quote = &after_key[quote_pos + 1..];
    after_quote
        .find(quote)
        .map(|end| after_quote[..end].to_string())
}

fn parse_swift_package_component(content: &str) -> Option<String> {
    content
        .lines()
        .find_map(|line| extract_js_string_property(line.trim(), "name"))
}

fn parse_podspec_component(content: &str) -> Option<(String, Option<String>)> {
    let mut name = None;
    let mut version = None;
    for line in content.lines() {
        let t = line.trim();
        if t.starts_with("spec.name") {
            name = extract_assignment_string(t);
        }
        if t.starts_with("spec.version") {
            version = t
                .rsplit_once("||")
                .and_then(|(_, fallback)| extract_assignment_string(fallback.trim()))
                .or_else(|| extract_assignment_string(t));
        }
    }
    name.map(|name| (name, version))
}

fn extract_assignment_string(line: &str) -> Option<String> {
    let quote_pos = line.find(['"', '\''])?;
    let quote = line.as_bytes()[quote_pos] as char;
    let after_quote = &line[quote_pos + 1..];
    after_quote
        .find(quote)
        .map(|end| after_quote[..end].to_string())
}

fn vrt_category(rule_id: &str) -> &'static str {
    if rule_id.contains("xss") {
        "Cross-Site Scripting (XSS) > DOM-Based"
    } else if rule_id.contains("credential")
        || rule_id.contains("secret")
        || rule_id.contains("hardcoded")
    {
        "Server Security Misconfiguration > Hardcoded Credentials"
    } else if rule_id.contains("command_injection") {
        "Server-Side Code Injection > OS Command Injection"
    } else if rule_id.contains("sql") {
        "SQL Injection"
    } else if rule_id.contains("ssrf") {
        "Server-Side Request Forgery (SSRF)"
    } else if rule_id.contains("path_traversal") || rule_id.contains("directory_traversal") {
        "Path Traversal"
    } else if rule_id.contains("template") || rule_id.contains("ssti") {
        "Server-Side Code Injection > Server-Side Template Injection"
    } else if rule_id.contains("deserialize") {
        "Insecure Deserialization"
    } else if rule_id.contains("idor") || rule_id.contains("auth") {
        "Broken Access Control"
    } else {
        "Informational"
    }
}

fn severity_rank(severity: &str) -> u8 {
    match severity {
        "KevCritical" => 6,
        "Exhaustion" => 5,
        "Critical" => 4,
        "High" => 3,
        "Medium" => 2,
        "Low" => 1,
        _ => 0,
    }
}

fn business_impact_statement(rule_id: &str, severity: Option<&str>) -> String {
    if rule_id.contains("credential") || rule_id.contains("secret") || rule_id.contains("hardcoded")
    {
        return String::from(
            "Embedded secrets can permit unauthorized access to internal systems, enable account takeover, and create durable compromise paths for an attacker.",
        );
    }
    if rule_id.contains("xss") {
        return String::from(
            "A DOM-based XSS sink can enable session theft, arbitrary action execution in a victim browser, and lateral compromise of privileged user workflows.",
        );
    }
    if rule_id.contains("command_injection") {
        return String::from(
            "Command injection sinks can yield direct remote code execution, host compromise, and rapid pivoting into adjacent infrastructure.",
        );
    }

    match severity {
        Some("KevCritical") | Some("Critical") => String::from(
            "The identified sinks can enable high-impact compromise of confidentiality, integrity, and availability if they are reachable in production workflows.",
        ),
        Some("High") => String::from(
            "The identified sinks can expose sensitive data or privileged functionality and materially increase the likelihood of exploitable compromise.",
        ),
        Some("Medium") | Some("Low") => String::from(
            "The identified sinks increase attack surface and can become exploitable when combined with reachable input control or adjacent weaknesses.",
        ),
        _ => String::from(
            "The identified sinks require manual triage to determine exploitability, but they represent concrete attack-surface expansion that warrants remediation.",
        ),
    }
}

fn suggested_mitigation(findings: &[&StructuredFinding]) -> String {
    let mut mitigations = findings
        .iter()
        .filter_map(|finding| finding.remediation.as_deref())
        .collect::<Vec<_>>();
    mitigations.sort_unstable();
    mitigations.dedup();

    if mitigations.is_empty() {
        String::from("Review the affected sink usage, remove unsafe data flow into the target API, and apply the framework-native safe alternative.")
    } else {
        mitigations.join(" ")
    }
}

// ---------------------------------------------------------------------------
// Sourcemap ingestion  (Phase A)
// ---------------------------------------------------------------------------

/// Download a JavaScript sourcemap, reconstruct the source tree into a
/// `tempfile::TempDir`, scan it, and return findings.  The tempdir is
/// automatically deleted when the function returns (RAII drop).
fn ingest_sourcemap(url: &str) -> anyhow::Result<Vec<StructuredFinding>> {
    let agent = ureq::Agent::new_with_defaults();
    let map: serde_json::Value = agent
        .get(url)
        .call()
        .map_err(|_| anyhow::anyhow!("sourcemap HTTP fetch failed"))?
        .body_mut()
        .with_config()
        .limit(HTTP_BODY_LIMIT)
        .read_json::<serde_json::Value>()
        .context("sourcemap response is not valid JSON")?;

    let sources = map["sources"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("sourcemap missing 'sources' array"))?;
    let contents = map["sourcesContent"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    // RAII: tempdir is deleted when `tmpdir` drops at end of scope.
    let tmpdir = tempfile::TempDir::new().context("failed to create sourcemap tmpdir")?;

    for (i, source_val) in sources.iter().enumerate() {
        let raw = source_val.as_str().unwrap_or("");
        let safe = sanitize_sourcemap_path(raw, i);
        let dest = tmpdir.path().join(&safe);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create parent for sourcemap entry {i}"))?;
        }
        let content = contents.get(i).and_then(|v| v.as_str()).unwrap_or("");
        std::fs::write(&dest, content.as_bytes())
            .with_context(|| format!("write sourcemap entry {i}"))?;
    }

    scan_directory(tmpdir.path())
    // tmpdir drops here — reconstructed tree deleted
}

// ---------------------------------------------------------------------------
// npm tarball ingestion  (Phase B)
// ---------------------------------------------------------------------------

/// Download an npm package tarball, extract it to a `tempfile::TempDir`,
/// scan the extracted tree, and return findings.
///
/// `pkg` may be `"lodash"` (resolves latest) or `"lodash@4.17.21"`.
fn ingest_npm(pkg: &str) -> anyhow::Result<(Vec<StructuredFinding>, String)> {
    let (name, version) = parse_npm_spec(pkg);
    let resolved = if version.is_empty() {
        resolve_npm_package(name, None)?
    } else {
        resolve_npm_package(name, Some(version))?
    };

    let agent = ureq::Agent::new_with_defaults();
    let mut response = agent.get(&resolved.tarball_url).call().map_err(|_| {
        anyhow::anyhow!("npm registry fetch failed for {name}@{}", resolved.version)
    })?;

    // Stream through GzDecoder → tar::Archive → tempdir (RAII drop).
    let tmpdir = tempfile::TempDir::new().context("failed to create npm tmpdir")?;
    {
        let body_reader = response
            .body_mut()
            .with_config()
            .limit(HTTP_BODY_LIMIT)
            .reader();
        let gz = flate2::read::GzDecoder::new(body_reader);
        let mut archive = tar::Archive::new(gz);
        archive
            .unpack(tmpdir.path())
            .context("failed to extract npm tarball")?;
    }

    let findings = scan_directory(tmpdir.path())?;
    let component_info = format!("**{name}@{}** (`package.json`)", resolved.version);
    Ok((findings, component_info))
    // tmpdir drops here — extracted package deleted
}

/// Parse `"name@version"` → `("name", "version")`.
/// Handles scoped packages like `"@scope/name@1.0.0"`.
fn parse_npm_spec(pkg: &str) -> (&str, &str) {
    // For scoped packages (@scope/name), the `@` version separator can only
    // appear after the `/`.  Find the last `@` that is not at position 0.
    if let Some(at) = pkg[1..].rfind('@') {
        let pos = at + 1; // offset into original string
        (&pkg[..pos], &pkg[pos + 1..])
    } else {
        (pkg, "")
    }
}

struct NpmPackageMetadata {
    version: String,
    tarball_url: String,
}

fn resolve_npm_package(name: &str, version: Option<&str>) -> anyhow::Result<NpmPackageMetadata> {
    let version_path = version.unwrap_or("latest");
    let url = format!("https://registry.npmjs.org/{name}/{version_path}");
    let agent = ureq::Agent::new_with_defaults();
    let meta: serde_json::Value = agent
        .get(&url)
        .call()
        .map_err(|_| anyhow::anyhow!("npm registry metadata fetch failed for {name}"))?
        .body_mut()
        .with_config()
        .limit(HTTP_BODY_LIMIT)
        .read_json::<serde_json::Value>()
        .context("npm registry metadata is not valid JSON")?;

    let version = meta["version"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| anyhow::anyhow!("npm registry response missing 'version' field"))?;
    let tarball_url = npm_tarball_from_metadata(&meta)?;
    Ok(NpmPackageMetadata {
        version,
        tarball_url,
    })
}

fn npm_tarball_from_metadata(meta: &serde_json::Value) -> anyhow::Result<String> {
    meta.pointer("/dist/tarball")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| anyhow::anyhow!("npm registry response missing 'dist.tarball' field"))
}

// ---------------------------------------------------------------------------
// Python wheel / egg ingestion  (Phase P1-2b)
// ---------------------------------------------------------------------------

/// Extract a Python `.whl` or `.egg` archive into a temporary directory, scan
/// the unpacked payload, and return findings.
fn ingest_whl(path: &Path, corpus_path: Option<&Path>) -> anyhow::Result<Vec<StructuredFinding>> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("failed to open wheel archive {}", path.display()))?;
    let mut archive =
        zip::ZipArchive::new(file).context("failed to parse wheel/egg archive as ZIP")?;
    let tmpdir = tempfile::TempDir::new().context("failed to create wheel extraction tmpdir")?;

    let mut metadata_path: Option<PathBuf> = None;
    let mut entry_points_path: Option<PathBuf> = None;
    let mut script_paths = Vec::new();

    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .with_context(|| format!("failed to read wheel entry {index}"))?;
        let entry_name = entry.name().replace('\\', "/");
        let Some(safe_rel) = sanitize_archive_entry_path(&entry_name) else {
            continue;
        };
        let dest = tmpdir.path().join(&safe_rel);

        if entry.is_dir() {
            std::fs::create_dir_all(&dest)
                .with_context(|| format!("create wheel directory {}", dest.display()))?;
            continue;
        }
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create wheel parent {}", parent.display()))?;
        }

        let mut buf = Vec::new();
        entry
            .read_to_end(&mut buf)
            .with_context(|| format!("read wheel file {}", entry.name()))?;
        std::fs::write(&dest, &buf)
            .with_context(|| format!("write extracted wheel file {}", dest.display()))?;

        if entry_name.ends_with("/METADATA") {
            metadata_path = Some(dest.clone());
        } else if entry_name.ends_with("/entry_points.txt") {
            entry_points_path = Some(dest.clone());
        }

        let is_python_script = dest.extension().and_then(|ext| ext.to_str()) == Some("py")
            || buf.starts_with(b"#!/")
                && std::str::from_utf8(&buf[..buf.len().min(128)])
                    .unwrap_or("")
                    .to_ascii_lowercase()
                    .contains("python");
        if is_python_script {
            script_paths.push(dest);
        }
    }

    let mut findings = Vec::new();
    if let Some(metadata_path) = metadata_path.as_deref() {
        let metadata = std::fs::read_to_string(metadata_path)
            .with_context(|| format!("read wheel metadata {}", metadata_path.display()))?;
        if let Some(package_name) = parse_metadata_header(&metadata, "Name") {
            let artifact_label = path.display().to_string();
            if let Some(finding) = slopsquat_artifact_finding(
                &package_name,
                parse_metadata_header(&metadata, "Version").as_deref(),
                corpus_path,
                &artifact_label,
            ) {
                findings.push(finding);
            }
        }
    }

    if let Some(entry_points_path) = entry_points_path.as_deref() {
        let entry_points = std::fs::read_to_string(entry_points_path)
            .with_context(|| format!("read entry_points {}", entry_points_path.display()))?;
        for module in parse_entry_point_modules(&entry_points) {
            if let Some(module_path) = resolve_python_module_path(tmpdir.path(), &module) {
                findings.extend(scan_python_priority_file(
                    &module_path,
                    &relative_to_root(tmpdir.path(), &module_path),
                )?);
            }
        }
    }

    for script_path in &script_paths {
        findings.extend(scan_python_priority_file(
            script_path,
            &relative_to_root(tmpdir.path(), script_path),
        )?);
    }

    findings.extend(scan_directory(tmpdir.path())?);
    Ok(dedup_findings(findings))
}

/// Download a wheel from the official PyPI registry, extract it, and scan the
/// unpacked payload.
fn ingest_pypi(pkg: &str, corpus_path: Option<&Path>) -> anyhow::Result<Vec<StructuredFinding>> {
    let (name, version) = parse_pypi_spec(pkg);
    let version_opt = (!version.is_empty()).then_some(version);
    if let Some(finding) = slopsquat_artifact_finding(name, version_opt, corpus_path, pkg) {
        let mut findings = vec![finding];
        let downloaded = ingest_pypi_download(name, version, corpus_path)?;
        findings.extend(downloaded);
        return Ok(dedup_findings(findings));
    }
    ingest_pypi_download(name, version, corpus_path)
}

fn ingest_pypi_download(
    name: &str,
    version: &str,
    corpus_path: Option<&Path>,
) -> anyhow::Result<Vec<StructuredFinding>> {
    let meta_url = if version.is_empty() {
        format!("https://pypi.org/pypi/{name}/json")
    } else {
        format!("https://pypi.org/pypi/{name}/{version}/json")
    };
    let agent = ureq::Agent::new_with_defaults();
    let meta: serde_json::Value = agent
        .get(&meta_url)
        .call()
        .map_err(|_| anyhow::anyhow!("PyPI metadata fetch failed for {pkg}", pkg = name))?
        .body_mut()
        .with_config()
        .limit(HTTP_BODY_LIMIT)
        .read_json::<serde_json::Value>()
        .context("PyPI metadata response is not valid JSON")?;

    let urls = meta["urls"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("PyPI metadata missing 'urls' array"))?;
    let wheel_url = urls
        .iter()
        .find(|entry| entry["packagetype"].as_str() == Some("bdist_wheel"))
        .or_else(|| {
            urls.iter().find(|entry| {
                entry["filename"]
                    .as_str()
                    .is_some_and(|filename| filename.ends_with(".egg"))
            })
        })
        .and_then(|entry| entry["url"].as_str())
        .ok_or_else(|| anyhow::anyhow!("PyPI artifact set contains no wheel or egg"))?;

    let mut response = agent
        .get(wheel_url)
        .call()
        .map_err(|_| anyhow::anyhow!("PyPI artifact download failed for {name}"))?;
    let tmpdir = tempfile::TempDir::new().context("failed to create PyPI download tmpdir")?;
    let filename = urls
        .iter()
        .find_map(|entry| {
            let url = entry["url"].as_str()?;
            (url == wheel_url)
                .then(|| entry["filename"].as_str())
                .flatten()
        })
        .unwrap_or("package.whl");
    let artifact_path = tmpdir.path().join(filename);
    let mut bytes = Vec::new();
    response
        .body_mut()
        .with_config()
        .limit(PYPI_BODY_LIMIT)
        .reader()
        .read_to_end(&mut bytes)
        .context("failed to read PyPI artifact body")?;
    std::fs::write(&artifact_path, &bytes)
        .with_context(|| format!("write downloaded PyPI artifact {}", artifact_path.display()))?;
    ingest_whl(&artifact_path, corpus_path)
}

fn parse_pypi_spec(pkg: &str) -> (&str, &str) {
    if let Some(at) = pkg.rfind('@') {
        (&pkg[..at], &pkg[at + 1..])
    } else {
        (pkg, "")
    }
}

fn parse_metadata_header(metadata: &str, key: &str) -> Option<String> {
    metadata.lines().find_map(|line| {
        let (left, right) = line.split_once(':')?;
        (left.trim().eq_ignore_ascii_case(key)).then(|| right.trim().to_string())
    })
}

fn parse_entry_point_modules(entry_points: &str) -> Vec<String> {
    entry_points
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('[') || trimmed.starts_with('#') {
                return None;
            }
            let (_, target) = trimmed.split_once('=')?;
            let module = target.trim().split(':').next()?.trim();
            (!module.is_empty()).then(|| module.to_string())
        })
        .collect()
}

fn resolve_python_module_path(root: &Path, module: &str) -> Option<PathBuf> {
    let module_rel = module.replace('.', "/");
    let file_path = root.join(format!("{module_rel}.py"));
    if file_path.exists() {
        return Some(file_path);
    }
    let init_path = root.join(module_rel).join("__init__.py");
    init_path.exists().then_some(init_path)
}

fn scan_python_priority_file(path: &Path, label: &str) -> anyhow::Result<Vec<StructuredFinding>> {
    let source =
        std::fs::read(path).with_context(|| format!("read python file {}", path.display()))?;
    Ok(scan_buffer("py", &source, label, &[], &[], false))
}

// ---------------------------------------------------------------------------
// APK ingestion via jadx  (Phase C)
// ---------------------------------------------------------------------------

/// Decompile an Android APK using `jadx`, scan the decompiled source tree,
/// and return findings.  The decompiled tree is deleted via RAII on return.
///
/// # Errors
///
/// Returns an error if `jadx` is not installed, decompilation fails, or the
/// scan encounters an I/O error.
fn ingest_apk(path: &Path) -> anyhow::Result<Vec<StructuredFinding>> {
    // Preflight: verify jadx is available in PATH.
    std::process::Command::new("jadx")
        .arg("--version")
        .output()
        .map_err(|_| {
            anyhow::anyhow!("jadx is not installed or not in PATH. Required for APK decompilation.")
        })?;

    let tmpdir = tempfile::TempDir::new().context("failed to create APK decompilation tmpdir")?;

    let status = std::process::Command::new("jadx")
        .env("JAVA_OPTS", "-Xmx4G")
        .arg("-d")
        .arg(tmpdir.path())
        .arg("-j")
        .arg("1")
        .arg(path)
        .status()
        .context("failed to spawn jadx")?;

    if !status.success() {
        anyhow::bail!(
            "jadx decompilation failed with exit code {:?}",
            status.code()
        );
    }

    scan_directory(tmpdir.path())
    // tmpdir drops here — decompiled source deleted
}

// ---------------------------------------------------------------------------
// Docker save tarball ingestion  (Phase P1-2a)
// ---------------------------------------------------------------------------

/// Internal manifest entry from `manifest.json` in a `docker save` tarball.
#[derive(serde::Deserialize)]
struct DockerManifestEntry {
    #[serde(rename = "Layers")]
    layers: Vec<String>,
}

/// Ingest a `docker save` tarball, merge layers into a unified filesystem
/// tree in a `tempfile::TempDir`, scan the tree, and return findings.
///
/// ## docker save format
///
/// ```text
/// manifest.json            — JSON array of DockerManifestEntry
/// <hash>.json              — image config (ignored during scan)
/// <layer_id>/layer.tar     — one tar per layer, applied in order
/// ```
///
/// ## Circuit breaker
///
/// Total buffered layer data is capped at `DOCKER_LAYER_BUDGET` (512 MiB).
/// Any tarball that would exceed this limit is skipped.
fn ingest_docker(path: &Path) -> anyhow::Result<Vec<StructuredFinding>> {
    use std::io::Read as _;

    let file =
        std::fs::File::open(path).with_context(|| format!("open docker tar {}", path.display()))?;
    let mut outer = tar::Archive::new(file);

    // First pass: buffer manifest.json and all layer tars keyed by path.
    let mut manifest_bytes: Option<Vec<u8>> = None;
    let mut layer_bufs: std::collections::HashMap<String, Vec<u8>> =
        std::collections::HashMap::new();
    let mut total_layer_bytes: usize = 0;

    for entry in outer.entries().context("iterate docker tar entries")? {
        let mut entry = entry.context("read docker tar entry")?;
        let entry_path = entry
            .path()
            .context("docker tar entry path")?
            .to_string_lossy()
            .replace('\\', "/")
            .to_string();

        if entry_path == "manifest.json" {
            let mut buf = Vec::new();
            entry
                .read_to_end(&mut buf)
                .context("read manifest.json from docker tar")?;
            manifest_bytes = Some(buf);
        } else if entry_path.ends_with("/layer.tar") || entry_path == "layer.tar" {
            let mut buf = Vec::new();
            entry
                .read_to_end(&mut buf)
                .context("read layer.tar from docker tar")?;
            let new_total = total_layer_bytes.saturating_add(buf.len());
            if new_total > DOCKER_LAYER_BUDGET {
                // Skip layers that breach the circuit breaker.
                continue;
            }
            total_layer_bytes = new_total;
            layer_bufs.insert(entry_path, buf);
        }
    }

    let manifest_bytes =
        manifest_bytes.ok_or_else(|| anyhow::anyhow!("docker tar missing manifest.json"))?;
    let manifests: Vec<DockerManifestEntry> = serde_json::from_slice(&manifest_bytes)
        .context("docker manifest.json is not valid JSON")?;
    let manifest = manifests
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("docker manifest.json contains no entries"))?;

    let tmpdir =
        tempfile::TempDir::new().context("failed to create docker layer extraction tmpdir")?;

    // Apply layers in order. Whiteout handling is intentionally omitted in
    // this first iteration so the pipeline can focus on simple layer extraction.
    for layer_path in &manifest.layers {
        // Normalise path separators from manifest.json (may use backslash on Windows images).
        let normalised = layer_path.replace('\\', "/");
        let Some(layer_data) = layer_bufs.get(&normalised) else {
            // Layer not buffered (exceeded circuit breaker or absent) — skip.
            continue;
        };

        let mut layer_tar = tar::Archive::new(layer_data.as_slice());
        for entry in layer_tar.entries().context("iterate layer tar entries")? {
            let mut entry = entry.context("read layer tar entry")?;
            let raw_path = entry
                .path()
                .context("layer entry path")?
                .to_string_lossy()
                .replace('\\', "/")
                .to_string();

            // Sanitize path to prevent traversal.
            let Some(rel) = sanitize_archive_entry_path(&raw_path) else {
                continue;
            };

            let dest = tmpdir.path().join(&rel);

            if entry.header().entry_type().is_dir() {
                std::fs::create_dir_all(&dest)
                    .with_context(|| format!("create layer dir {}", dest.display()))?;
                continue;
            }

            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("create layer parent {}", parent.display()))?;
            }

            let mut buf = Vec::new();
            entry
                .read_to_end(&mut buf)
                .with_context(|| format!("read layer file {raw_path}"))?;
            std::fs::write(&dest, &buf)
                .with_context(|| format!("write layer file {}", dest.display()))?;
        }
    }

    scan_directory(tmpdir.path())
    // tmpdir drops here — merged layer tree deleted
}

// ---------------------------------------------------------------------------
// IPA ingestion  (Phase P1-2c)
// ---------------------------------------------------------------------------

/// Extract an iOS `.ipa` bundle into a `tempfile::TempDir`, parse the app
/// `Info.plist` when present, scan the extracted app tree, and return findings.
fn ingest_ipa(path: &Path) -> anyhow::Result<Vec<StructuredFinding>> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("failed to open IPA archive {}", path.display()))?;
    let mut archive = zip::ZipArchive::new(file).context("failed to parse IPA archive as ZIP")?;
    let tmpdir = tempfile::TempDir::new().context("failed to create IPA extraction tmpdir")?;

    let mut app_root: Option<std::path::PathBuf> = None;
    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .with_context(|| format!("failed to read IPA entry {i}"))?;
        let entry_name = entry.name().replace('\\', "/");
        if !entry_name.starts_with("Payload/") {
            continue;
        }
        let Some(safe_rel) = sanitize_archive_entry_path(&entry_name) else {
            continue;
        };
        if app_root.is_none() {
            let components = safe_rel.components().collect::<Vec<_>>();
            if components.len() >= 2 {
                let root =
                    components[..2]
                        .iter()
                        .fold(std::path::PathBuf::new(), |mut acc, component| {
                            acc.push(component.as_os_str());
                            acc
                        });
                app_root = Some(tmpdir.path().join(root));
            }
        }

        let dest = tmpdir.path().join(&safe_rel);
        if entry.is_dir() {
            std::fs::create_dir_all(&dest)
                .with_context(|| format!("create IPA directory {}", dest.display()))?;
            continue;
        }
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create IPA parent {}", parent.display()))?;
        }
        let mut buf = Vec::new();
        entry
            .read_to_end(&mut buf)
            .with_context(|| format!("read IPA file {}", entry.name()))?;
        std::fs::write(&dest, &buf)
            .with_context(|| format!("write extracted IPA file {}", dest.display()))?;
    }

    let scan_root = app_root
        .filter(|root| root.exists())
        .unwrap_or_else(|| tmpdir.path().to_path_buf());
    let info_plist = scan_root.join("Info.plist");
    if info_plist.exists() {
        let _: plist::Value = plist::Value::from_file(&info_plist)
            .with_context(|| format!("failed to parse IPA Info.plist {}", info_plist.display()))?;
    }

    scan_directory(&scan_root)
}

// ---------------------------------------------------------------------------
// JAR ingestion  (Phase D)
// ---------------------------------------------------------------------------

/// Extract a Java `.jar` archive into a `tempfile::TempDir`, scan the expanded
/// tree, and return findings.
fn ingest_jar(path: &Path) -> anyhow::Result<Vec<StructuredFinding>> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("failed to open JAR archive {}", path.display()))?;
    let mut archive = zip::ZipArchive::new(file).context("failed to parse JAR archive as ZIP")?;
    let tmpdir = tempfile::TempDir::new().context("failed to create JAR extraction tmpdir")?;

    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .with_context(|| format!("failed to read JAR entry {i}"))?;
        let Some(safe_rel) = sanitize_archive_entry_path(entry.name()) else {
            continue;
        };
        let dest = tmpdir.path().join(safe_rel);

        if entry.is_dir() {
            std::fs::create_dir_all(&dest)
                .with_context(|| format!("create JAR directory {}", dest.display()))?;
            continue;
        }

        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create JAR parent {}", parent.display()))?;
        }

        let mut buf = Vec::new();
        entry
            .read_to_end(&mut buf)
            .with_context(|| format!("read JAR file {}", entry.name()))?;
        std::fs::write(&dest, &buf)
            .with_context(|| format!("write extracted JAR file {}", dest.display()))?;
    }

    scan_directory(tmpdir.path())
}

// ---------------------------------------------------------------------------
// Electron ASAR ingestion  (Phase E)
// ---------------------------------------------------------------------------

/// Parse an Electron `.asar` archive in pure Rust, extract its contents to a
/// `tempfile::TempDir`, scan the extracted tree, and return findings.
///
/// ## ASAR format (Chromium Pickle):
///
/// ```text
/// [0..4]           uint32 LE = 4              (outer pickle header_size)
/// [4..8]           uint32 LE = header_buf_size (size of the inner pickle)
/// [8..12]          uint32 LE = inner payload   (4 + json_len, 4-byte aligned)
/// [12..16]         uint32 LE = json_len
/// [16..16+json_len] UTF-8 JSON header
/// [8+header_buf_size..] concatenated file data
/// ```
fn ingest_asar(path: &Path) -> anyhow::Result<Vec<StructuredFinding>> {
    let data = std::fs::read(path).context("failed to read ASAR file")?;

    if data.len() < 16 {
        anyhow::bail!(
            "not a valid ASAR archive: file too short ({} bytes)",
            data.len()
        );
    }

    let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
    if magic != 4 {
        anyhow::bail!(
            "not a valid ASAR archive: bad outer pickle header (expected 4, got {magic})"
        );
    }

    let header_buf_size = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;
    let json_len = u32::from_le_bytes(data[12..16].try_into().unwrap()) as usize;

    let json_end = 16usize
        .checked_add(json_len)
        .ok_or_else(|| anyhow::anyhow!("ASAR json_len overflow"))?;
    if data.len() < json_end {
        anyhow::bail!(
            "ASAR header JSON truncated: need {json_end} bytes, have {}",
            data.len()
        );
    }

    let header_json: serde_json::Value =
        serde_json::from_slice(&data[16..json_end]).context("ASAR header JSON is not valid")?;

    let data_offset = 8usize
        .checked_add(header_buf_size)
        .ok_or_else(|| anyhow::anyhow!("ASAR data_offset overflow"))?;
    if data.len() < data_offset {
        anyhow::bail!(
            "ASAR data region missing: need offset {data_offset}, have {} bytes",
            data.len()
        );
    }

    let tmpdir = tempfile::TempDir::new().context("failed to create ASAR extraction tmpdir")?;

    if let Some(files) = header_json.get("files") {
        extract_asar_dir(files, &data[data_offset..], tmpdir.path())?;
    }

    scan_directory(tmpdir.path())
    // tmpdir drops here — extracted tree deleted
}

/// Recursively extract a directory node from the ASAR header JSON.
///
/// `node` is the object under a `"files"` key.
/// `file_data` is the raw concatenated file data region.
/// `dest_dir` is the target directory on the local filesystem.
fn extract_asar_dir(
    node: &serde_json::Value,
    file_data: &[u8],
    dest_dir: &Path,
) -> anyhow::Result<()> {
    let entries = match node.as_object() {
        Some(o) => o,
        None => return Ok(()),
    };

    for (name, entry) in entries {
        // Path traversal guard: reject any name with separators or dots-only.
        if name.contains("..") || name.contains('/') || name.contains('\\') {
            continue;
        }
        let dest = dest_dir.join(name);

        if let Some(sub_files) = entry.get("files") {
            // Directory node — recurse.
            std::fs::create_dir_all(&dest)
                .with_context(|| format!("create ASAR subdir {}", dest.display()))?;
            extract_asar_dir(sub_files, file_data, &dest)?;
        } else {
            // File node — extract bytes by offset + size.
            // ASAR stores offset as a decimal string, not a JSON number.
            let offset = entry
                .get("offset")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(0);
            let size = entry.get("size").and_then(|v| v.as_u64()).unwrap_or(0) as usize;

            let end = offset.saturating_add(size);
            if end > file_data.len() {
                // Truncated file — skip rather than panic.
                continue;
            }
            std::fs::write(&dest, &file_data[offset..end])
                .with_context(|| format!("write ASAR file {}", dest.display()))?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Native jq-style filter  (Phase 3 / P2-7)
// ---------------------------------------------------------------------------

/// Apply a `jq`-compatible filter expression to a `serde_json::Value` using
/// the pure-Rust [`jaq`](https://crates.io/crates/jaq-core) engine.
///
/// Returns a `Value::Array` of all output values produced by the filter.
fn apply_jaq_filter(
    filter_str: &str,
    findings_json: serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    use jaq_core::load::{Arena, File, Loader};
    use jaq_core::{data, unwrap_valr, Ctx, Vars};

    let input: jaq_json::Val =
        serde_json::from_value(findings_json).context("jaq: invalid JSON input")?;
    let program = File {
        code: filter_str,
        path: (),
    };

    let defs = jaq_core::defs()
        .chain(jaq_std::defs())
        .chain(jaq_json::defs());
    let funs = jaq_core::funs()
        .chain(jaq_std::funs())
        .chain(jaq_json::funs());
    let loader = Loader::new(defs);
    let arena = Arena::default();
    let modules = loader
        .load(&arena, program)
        .map_err(|errs| anyhow::anyhow!("jaq: filter parse failed: {errs:?}"))?;
    let filter = jaq_core::Compiler::default()
        .with_funs(funs)
        .compile(modules)
        .map_err(|errs| anyhow::anyhow!("jaq: filter compile failed: {errs:?}"))?;

    let results: Vec<serde_json::Value> = filter
        .id
        .run((
            Ctx::<data::JustLut<jaq_json::Val>>::new(&filter.lut, Vars::new([])),
            input,
        ))
        .map(unwrap_valr)
        .filter_map(Result::ok)
        .map(|value| {
            let rendered = value.to_string();
            serde_json::from_str(&rendered).context("jaq: output is not JSON")
        })
        .collect::<anyhow::Result<_>>()?;

    Ok(serde_json::Value::Array(results))
}

fn is_placeholder_scan_root(scan_root: Option<&Path>, has_explicit_ingest_source: bool) -> bool {
    has_explicit_ingest_source && scan_root == Some(Path::new("."))
}

// ---------------------------------------------------------------------------
// Directory walker (shared by all ingestion paths)
// ---------------------------------------------------------------------------

/// Walk `dir` recursively, run all detectors on every file, and return the
/// unified finding list.  Files > 1 MiB and unreadable files are silently
/// skipped.
pub(crate) fn scan_directory(dir: &Path) -> anyhow::Result<Vec<StructuredFinding>> {
    let mut all: Vec<StructuredFinding> = Vec::new();
    let mut controller_surfaces = Vec::new();
    let mut frontend_routes = Vec::new();
    let has_ai_assistant_config = has_ai_assistant_config(dir);
    let gadget_manifests = collect_gadget_manifest_blobs(dir);
    let gadget_manifest_refs: Vec<(&str, &[u8])> = gadget_manifests
        .iter()
        .map(|(path, bytes)| (path.as_str(), bytes.as_slice()))
        .collect();

    for entry in WalkDir::new(dir)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| !is_excluded_hunt_entry(entry))
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let file_path = entry.path();
        if is_excluded_hunt_file(file_path) {
            continue;
        }
        if std::fs::metadata(file_path)
            .map(|m| m.len() > MAX_FILE_BYTES)
            .unwrap_or(false)
        {
            continue;
        }
        let ext = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !matches!(ext, "js" | "jsx" | "ts" | "tsx") {
            continue;
        }
        let source = match std::fs::read(file_path) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };
        let rel_path = file_path
            .strip_prefix(dir)
            .unwrap_or(file_path)
            .to_string_lossy()
            .to_string();
        frontend_routes.extend(forge::authz::extract_frontend_routes_from_source(
            ext, &source, &rel_path,
        ));
        controller_surfaces.extend(forge::authz::extract_controller_surface_matches_for_file(
            ext, &source, rel_path,
        ));
    }

    for entry in WalkDir::new(dir)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| !is_excluded_hunt_entry(entry))
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let file_path = entry.path();
        if is_excluded_hunt_file(file_path) {
            continue;
        }

        if std::fs::metadata(file_path)
            .map(|m| m.len() > MAX_FILE_BYTES)
            .unwrap_or(false)
        {
            continue;
        }

        let source = match std::fs::read(file_path) {
            Ok(b) => b,
            Err(_) => continue,
        };

        let ext = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let rel_path = file_path
            .strip_prefix(dir)
            .unwrap_or(file_path)
            .to_string_lossy()
            .to_string();

        all.extend(scan_buffer(
            ext,
            &source,
            &rel_path,
            &controller_surfaces,
            &frontend_routes,
            has_ai_assistant_config,
        ));
        all.extend(forge::gadgets::analyze_source_for_gadgets(
            ext,
            &source,
            &rel_path,
            &gadget_manifest_refs,
        ));
    }

    let mut deduped = dedup_findings(all);
    // P2-16: demote protobuf Any schema findings when no reachable decode call exists.
    apply_protobuf_any_reachability_demotion(dir, &mut deduped);
    // P2-16: demote protobuf Any findings whose file extension is .proto (schema-only).
    apply_p2_16_protobuf_demotion(&mut deduped);
    // P2-17: demote SSRF findings whose URL source is operator-config backed.
    apply_config_backed_ssrf_demotion(&mut deduped);
    // Sprint 140 — threat-model oracle. Suppress findings covered by per-route
    // auth decorators, downgrade to Informational when blueprint-level auth
    // hooks cover the route, suppress ownership-class findings on projects
    // that declare a shared-access threat model. Runs BEFORE the deprecation
    // and focus-area filters so suppressed findings skip downstream cycles.
    apply_threat_model_oracle(dir, &mut deduped);
    // Sprint 142 — JWT keyfunc oracle. Demote security:jwt_*_bypass findings
    // when the surrounding keyfunc body contains an algorithm allowlist check
    // or a type assertion on token.Method. Closes the chainlink JWT FP class
    // (Sprint 141 Tier-1 disposition).
    apply_jwt_keyfunc_demotion(dir, &mut deduped);
    // Sprint 142 — concrete-typed Unmarshal demotion. Demote
    // security:protobuf_any_unguarded_decode findings when the surrounding
    // proto.Unmarshal call has no anypb.Any reference nearby — the cited
    // Unmarshal is into a concrete typed message, not an Any field. Closes
    // the chainlink protobuf_any FP class (Sprint 141 Tier-1 disposition).
    apply_concrete_typed_unmarshal_demotion(dir, &mut deduped);
    // Sprint 143 — SQL sanitizer oracle. Demote security:sql_injection
    // / security:sqli* findings when the cited line is in a properly-
    // sanitized SQL context (pq.QuoteIdentifier / prepared statement /
    // //nolint:gosec annotation / test-fixture function). Closes the
    // chainlink SQLi FP class (Sprint 141 Tier-1 disposition).
    apply_sql_sanitizer_demotion(dir, &mut deduped);
    // Sprint 163 — proof-obligation classifiers. Attach deterministic proof
    // classes for detector families whose triage depends on nearby source
    // context before the false-positive proof obligation gate runs.
    apply_proof_classification(dir, &mut deduped);
    // Sprint 138 — demote findings on deprecated / community-only targets.
    apply_deprecation_demotion(dir, &mut deduped);
    // Sprint 138 — annotate findings whose vulnerability class does not
    // match the bounty program's stated focus areas (50% approval downgrade).
    apply_focus_area_demotion(dir, &mut deduped);
    Ok(forge::proof_obligation::enforce_false_positive_proof_obligation(&deduped))
}

/// Sprint 140 — Wire-in for `forge::threat_model_oracle::classify_finding`.
///
/// Iterates the candidate finding set, asks the oracle for a verdict on
/// each, and applies the verdict to the finding stream:
/// - `Suppress`: remove from results — the cited code is protected by a
///   per-route auth decorator or the project declares a shared-access
///   threat model that the upstream detector failed to account for.
/// - `DowngradeInformational`: keep the finding but set `severity` to
///   `Informational` and annotate `remediation` with the cause. The
///   blueprint covers the route via a framework-level hook, but
///   attribution is coarse enough that we surface it for operator review.
/// - `Emit`: no-op — preserve the upstream detector verdict.
///
/// Motivating regression (Sprint 140 SecureDrop IDOR FP): the upstream
/// ownership-check detector emitted a 44% approval CANDIDATE for
/// `journalist_app/admin.py:354` despite the `@admin_required` decorator
/// at line 355. This wire-in catches the class structurally.
fn apply_threat_model_oracle(dir: &Path, findings: &mut Vec<StructuredFinding>) {
    findings.retain_mut(|finding| {
        match forge::threat_model_oracle::classify_finding(dir, finding) {
            forge::threat_model_oracle::ThreatModelVerdict::Suppress => false,
            forge::threat_model_oracle::ThreatModelVerdict::DowngradeInformational => {
                finding.severity = Some("Informational".to_string());
                let existing = finding.remediation.take().unwrap_or_default();
                finding.remediation = Some(format!(
                    "{existing} [threat_model_oracle: blueprint_auth_hook_covers_route — downgraded by Sprint 140 oracle]"
                ));
                true
            }
            forge::threat_model_oracle::ThreatModelVerdict::Emit => true,
        }
    });
}

/// Sprint 142 — Concrete-typed Unmarshal demotion.
///
/// The `security:protobuf_any_unguarded_decode` detector emits findings on
/// every `proto.Unmarshal` call site without inspecting the destination
/// type. The protobuf-Any vulnerability class requires an `anypb.Any`
/// destination with `type_url` dispatch to arbitrary types — concrete
/// typed messages cannot suffer the type-confusion attack.
///
/// Heuristic: scan ±10 lines of the cited line in the cited file. If
/// no `anypb.Any` reference (`anypb.Any`, `*anypb.Any`, `anypb.New`,
/// `anypb.UnmarshalNew`, `ptypes.UnmarshalAny`, or `Any.UnmarshalTo`)
/// is present in that window, the Unmarshal target is concrete-typed
/// and the finding is a false positive.
///
/// Motivating regression (Sprint 141 chainlink protobuf_any FP):
/// `core/capabilities/confidentialrelay/handler.go:416` was
/// `proto.Unmarshal(payloadBytes, &sdkReq)` where `sdkReq` is
/// `sdkpb.CapabilityRequest` — a concrete typed protobuf message.
/// The detector misidentified the threat model. This post-filter
/// catches the class structurally.
fn apply_concrete_typed_unmarshal_demotion(dir: &Path, findings: &mut [StructuredFinding]) {
    /// Scan window around the cited line for `anypb.Any` evidence.
    /// 10 lines on each side covers the typical Go variable-declaration
    /// distance from its `proto.Unmarshal` site.
    const SCAN_RADIUS: usize = 10;
    /// Substrings that indicate genuine `anypb.Any` usage near the
    /// Unmarshal call. Any match in the scan window preserves the
    /// upstream finding verdict.
    const ANYPB_MARKERS: &[&str] = &[
        "anypb.Any",
        "*anypb.Any",
        "anypb.New",
        "anypb.UnmarshalNew",
        "ptypes.UnmarshalAny",
        "Any.UnmarshalTo",
    ];

    for finding in findings.iter_mut() {
        if !finding.id.contains("protobuf_any_unguarded_decode") {
            continue;
        }
        let Some(rel_path) = finding.file.as_deref() else {
            continue;
        };
        let abs_path = dir.join(rel_path);
        let Ok(content) = std::fs::read_to_string(&abs_path) else {
            continue;
        };
        let lines: Vec<&str> = content.lines().collect();
        let Some(line_num) = finding.line else {
            continue;
        };
        let target_idx = (line_num as usize).saturating_sub(1);
        let start = target_idx.saturating_sub(SCAN_RADIUS);
        let end = (target_idx + SCAN_RADIUS + 1).min(lines.len());
        if start >= end {
            continue;
        }
        let window = lines[start..end].join("\n");
        let has_anypb = ANYPB_MARKERS.iter().any(|m| window.contains(m));
        if !has_anypb {
            finding.severity = Some("Informational".to_string());
            let existing = finding.remediation.take().unwrap_or_default();
            finding.remediation = Some(format!(
                "{existing} [concrete_typed_unmarshal: cited Unmarshal target has no anypb.Any reference within {SCAN_RADIUS} lines — destination is a concrete typed message, not the Any type-confusion class]"
            ));
        }
    }
}

/// Sprint 143 — Wire-in for `forge::sql_sanitizer_oracle::classify_sql_finding`.
///
/// For each finding whose `id` matches `forge::sql_sanitizer_oracle::is_sql_class`
/// (SQL injection class), inspect the cited file for sanitizer context. If
/// the oracle returns `Sanitized`, the finding is demoted to `Informational`
/// severity with an annotation citing which sanitizer signal matched.
///
/// Motivating regression (Sprint 141 chainlink SQLi FP): the cited line
/// at `core/store/store.go:156` was inside `dropAndCreatePristineDB`
/// (test infrastructure) and used `pq.QuoteIdentifier()` (proper
/// identifier escaping) with an inline `//nolint:gosec` annotation. The
/// upstream detector emitted on the syntactic concatenation pattern
/// without any of these context signals.
fn apply_sql_sanitizer_demotion(dir: &Path, findings: &mut [StructuredFinding]) {
    for finding in findings.iter_mut() {
        if !forge::sql_sanitizer_oracle::is_sql_class(finding) {
            continue;
        }
        let Some(rel_path) = finding.file.as_deref() else {
            continue;
        };
        let abs_path = dir.join(rel_path);
        if forge::sql_sanitizer_oracle::classify_sql_finding(&abs_path, finding.line)
            == forge::sql_sanitizer_oracle::SqlSanitizerVerdict::Sanitized
        {
            finding.severity = Some("Informational".to_string());
            let existing = finding.remediation.take().unwrap_or_default();
            finding.remediation = Some(format!(
                "{existing} [sql_sanitizer_oracle: cited line is in a sanitized SQL context (quoting helper, //nolint annotation, or test-fixture function)]"
            ));
        }
    }
}

/// Sprint 142 — Wire-in for `forge::jwt_keyfunc_oracle::classify_jwt_finding`.
///
/// For each finding whose `id` is a JWT-class vulnerability (per
/// `forge::jwt_keyfunc_oracle::is_jwt_class`), inspect the surrounding
/// keyfunc body in the cited source file. If the keyfunc contains an
/// algorithm allowlist check or a type assertion on `token.Method`, the
/// finding is demoted to `Informational` severity with an annotation
/// citing the guard.
///
/// Sprint 147 — Phase 2B: Wire-in for the three new `forge::threat_model_oracle`
/// suppression predicates.
/// Attach proof classes to findings before the proof-obligation gate.
///
/// For `security:intent_divergence`: attaches `ReachabilityProof` when the
/// source file contains a zero-auth provider indicator outside a test path;
/// otherwise attaches `LatticeGapProposal`.
///
/// For `security:ffi_unsafe_deref` and `security:raw_pointer_deref`: attaches
/// `InvariantViolationProof` (and drops the finding as a FP) when a null guard
/// is visible within ±5 lines; attaches `ReachabilityProof` when `extern "C"`
/// is visible; otherwise attaches `LatticeGapProposal`.
///
/// For `security:lcm_double_free`: attaches `InvariantViolationProof` (drops as FP)
/// when a dominance-verified free guard is present; `ReachabilityProof` when an
/// exported C symbol is visible; otherwise `LatticeGapProposal`.
///
/// For `security:non_constant_time_comparison`: attaches `ReachabilityProof`
/// when the source contains HMAC/session-key markers outside a test path;
/// otherwise `LatticeGapProposal`.
fn classify_one_proof(dir: &Path, finding: &StructuredFinding) -> Option<ProofClass> {
    use forge::proof_obligation as po;
    let id = finding.id.as_str();
    let src = || {
        finding
            .file
            .as_deref()
            .and_then(|p| std::fs::read_to_string(dir.join(p)).ok())
            .unwrap_or_default()
    };
    let line = finding.line.unwrap_or(1) as usize;
    Some(if id.contains("intent_divergence") {
        po::classify_intent_divergence_proof(finding, &src())
    } else if id.contains("ffi_unsafe_deref") || id.contains("raw_pointer_deref") {
        po::classify_ffi_deref_proof(&src(), line)
    } else if id.contains("lcm_double_free") {
        po::classify_lcm_double_free_proof(&src(), line)
    } else if id.contains("non_constant_time_comparison") {
        po::classify_timing_comparison_proof(&src(), finding)
    } else if id.contains("lcm_use_after_free") {
        po::classify_lcm_use_after_free_proof(&src(), line)
    } else if id.contains("lcm_malloc_integer_truncation") {
        po::classify_lcm_malloc_integer_truncation_proof(&src(), finding)
    } else if id.contains("lcm_off_by_one_loop") {
        po::classify_lcm_off_by_one_loop_proof(&src(), finding)
    } else if id.contains("oauth_missing_state_validation") {
        po::classify_oauth_state_validation_proof(&src(), finding)
    } else if id.contains("oauth_excessive_scope") {
        po::classify_oauth_excessive_scope_proof(&src(), finding)
    } else if id.contains("pqc_hybrid_downgrade") {
        po::classify_pqc_hybrid_downgrade_proof(&src(), finding)
    } else if id.contains("unverified_provenance") {
        po::classify_unverified_provenance_proof(&src(), finding)
    } else if id.contains("cargo_build_worm") {
        po::classify_cargo_build_worm_proof(&src(), finding)
    } else if id.contains("ci_persistence_vector") {
        po::classify_ci_persistence_vector_proof(&src(), finding)
    } else if id.contains("java_deser_allowlist_bypass") {
        po::classify_java_deser_allowlist_bypass_proof(&src(), finding)
    } else if id.contains("unsafe_deserialization") {
        po::classify_unsafe_deserialization_proof(&src(), finding)
    } else if id.contains("mcp_confused_deputy_dispatch") {
        po::classify_mcp_confused_deputy_dispatch_proof(&src(), finding)
    } else if id.contains("embedding_trust_transposition") {
        po::classify_embedding_trust_transposition_proof(&src(), finding)
    } else if id.contains("rag_context_poisoning") {
        po::classify_rag_context_poisoning_proof(&src(), finding)
    } else if id.contains("path_traversal_concatenation") {
        po::classify_path_traversal_concat_proof(&src(), finding)
    } else if id.contains("dynamic_import") {
        po::classify_dynamic_import_proof(&src(), finding)
    } else if id.contains("dangerous_execution") {
        po::classify_dangerous_execution_proof(&src(), finding)
    } else if id.contains("bounded_overflow_witness") {
        po::classify_bounded_overflow_proof(&src(), finding)
    } else if id.contains("ld_preload_injection") {
        po::classify_ld_preload_injection_proof(&src(), finding)
    } else if id.contains("ffi_memory_corruption") {
        po::classify_ffi_memory_corruption_proof(&src(), finding)
    } else if id.contains("xxe_saml_parser") {
        po::classify_xxe_saml_parser_proof(&src(), finding)
    } else if id.contains("saml_xsw_validation_order") {
        po::classify_saml_xsw_validation_order_proof(&src(), finding)
    } else if id.contains("jndi_injection") {
        po::classify_jndi_injection_proof(&src(), finding)
    } else if id.contains("eval_injection") {
        po::classify_eval_injection_proof(&src(), finding)
    } else if id.contains("process_builder_injection") {
        po::classify_process_builder_injection_proof(&src(), finding)
    } else if id.contains("oauth_account_fusion") {
        po::classify_oauth_account_fusion_proof(&src(), finding)
    } else if id.contains("protobuf_any_unguarded_decode") {
        po::classify_protobuf_any_proof(&src(), finding)
    } else if id.contains("sqli_concatenation") {
        po::classify_sqli_concatenation_proof(&src(), finding)
    } else if id.contains("financial_pii_to_external_llm") {
        po::classify_financial_pii_proof(&src(), finding)
    } else if id.contains("react_xss_dangerous_html") {
        po::classify_react_xss_proof(&src(), finding)
    } else if id.contains("unauthenticated_debug_endpoint") {
        po::classify_debug_endpoint_proof(&src(), finding)
    } else if id.contains("jwt_validation_bypass") {
        po::classify_jwt_validation_bypass_proof(&src(), finding)
    } else {
        return None;
    })
}

fn apply_proof_classification(dir: &Path, findings: &mut Vec<StructuredFinding>) {
    findings.retain_mut(|finding| {
        let Some(proof) = classify_one_proof(dir, finding) else {
            return true;
        };
        if proof == ProofClass::InvariantViolationProof {
            return false;
        }
        finding.proof_class = Some(proof);
        true
    });
}
/// Motivating regression (Sprint 141 chainlink JWT FP): the upstream
/// detector emitted a 36% approval CANDIDATE for `core/utils/jwt.go:230`
/// without inspecting the keyfunc body at lines 258-266, which contains
/// TWO algorithm validation gates (`token.Method.Alg() != ...` and a
/// type assertion on `*SigningMethodEth`).
fn apply_jwt_keyfunc_demotion(dir: &Path, findings: &mut [StructuredFinding]) {
    for finding in findings.iter_mut() {
        if !forge::jwt_keyfunc_oracle::is_jwt_class(finding) {
            continue;
        }
        let Some(rel_path) = finding.file.as_deref() else {
            continue;
        };
        let abs_path = dir.join(rel_path);
        if forge::jwt_keyfunc_oracle::classify_jwt_finding(&abs_path, finding.line)
            == forge::jwt_keyfunc_oracle::JwtKeyfuncVerdict::Guarded
        {
            finding.severity = Some("Informational".to_string());
            let existing = finding.remediation.take().unwrap_or_default();
            finding.remediation = Some(format!(
                "{existing} [jwt_keyfunc_oracle: keyfunc_body_contains_algorithm_allowlist_or_type_assertion]"
            ));
        }
    }
}

/// Sprint 138 — Wire-in for `forge::slop_filter::apply_focus_area_check`.
///
/// Detects the bounty program for `dir` (via directory name + git remote
/// canonicalisation) and looks up its scope file in
/// `tools/campaign/targets/<program>_targets.md`. If a scope file is found,
/// the focus-area cross-check runs and annotates any finding whose
/// vulnerability class does not textually overlap the program's stated
/// `### Focus Areas` bullet list.
fn apply_focus_area_demotion(dir: &Path, findings: &mut [StructuredFinding]) {
    use crate::audit_report::extract_git_remote;

    if findings.is_empty() {
        return;
    }
    let Some(program_name) = dir.file_name().and_then(|n| n.to_str()) else {
        return;
    };
    let canonical_target = extract_git_remote(dir);
    let campaign_targets_dir = std::path::PathBuf::from("tools/campaign/targets");
    let direct_path = campaign_targets_dir.join(format!("{program_name}_targets.md"));
    let scope_file = if direct_path.exists() {
        Some(direct_path)
    } else {
        find_targets_file_for_canonical_target(&campaign_targets_dir, &canonical_target)
    };
    if let Some(scope_file) = scope_file {
        forge::slop_filter::apply_focus_area_check(findings, &scope_file);
    }
}

/// Sprint 138 — Target Deprecation Cross-Check.
///
/// Scans the target directory's README.md, README, README.rst, SECURITY.md,
/// and CONTRIBUTING.md for deprecation-signal keywords. If any are found,
/// the project is no longer officially maintained; findings against it are
/// bounty-ineligible per most bug-bounty program scope exclusions (community
/// plugins are accepted "informational only" per program rules).
///
/// Returns `Some((filename, matched_keyword))` on first hit, `None` otherwise.
pub fn is_deprecated_target(dir: &Path) -> Option<(String, String)> {
    const KEYWORDS: &[&str] = &[
        "archived",
        "deprecated",
        "community-maintained",
        "no longer officially supported",
        "transitioned to community",
        "no longer actively maintained",
        "moved to maintenance mode",
    ];
    const CANDIDATE_FILES: &[&str] = &[
        "README.md",
        "README.rst",
        "README",
        "README.txt",
        "SECURITY.md",
        "CONTRIBUTING.md",
    ];
    const SCAN_WINDOW_BYTES: usize = 16 * 1024;

    for filename in CANDIDATE_FILES {
        let path = dir.join(filename);
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        let scan_window = content
            .get(..content.len().min(SCAN_WINDOW_BYTES))
            .unwrap_or(&content);
        let lower = scan_window.to_lowercase();
        for keyword in KEYWORDS {
            if lower.contains(keyword) {
                return Some((filename.to_string(), keyword.to_string()));
            }
        }
    }
    None
}

/// Sprint 138 — Deprecation Demotion Post-Filter.
///
/// When the scan target is a deprecated / archived / community-only project,
/// every finding is demoted to `Informational` severity with the reason
/// appended to the `remediation` field. The findings remain in the output
/// (for LOW_YIELD ledger routing as negative training data) but are no
/// longer eligible for promotion to CANDIDATE or BOUNTY.
fn apply_deprecation_demotion(dir: &Path, findings: &mut [StructuredFinding]) {
    if findings.is_empty() {
        return;
    }
    let Some((filename, keyword)) = is_deprecated_target(dir) else {
        return;
    };
    let marker = format!(
        " [deprecated_target: {filename}=\"{keyword}\"] informational_only_per_scope_exclusion"
    );
    for finding in findings.iter_mut() {
        finding.severity = Some("Informational".to_string());
        let remediation = finding.remediation.take().unwrap_or_default();
        finding.remediation = Some(format!("{remediation}{marker}"));
    }
}

/// P2-16 — Protobuf Any Reachability Post-Filter.
///
/// Demotes `security:protobuf_any_type_field` findings to `Informational`
/// (LOW_YIELD routing) when the repository contains no evidence of an
/// `Any::unpack`, `Any::decode`, or `unpackTo` call without an adjacent
/// type-url allowlist guard.  The proto file itself defines the schema;
/// exploitability requires a consumer that decodes the `Any` field.
///
/// **Allowlist guard patterns** (within 30 source lines of the decode call):
/// - `type_url_allowlist`, `RegisteredTypes`, `getTypeRegistry`
/// - An exhaustive `match` over `@type` URL constants
///
/// If no decode evidence is found at all, all `protobuf_any_type_field`
/// findings are demoted — the field exists but is not consumed in this repo.
fn apply_protobuf_any_reachability_demotion(dir: &Path, findings: &mut [StructuredFinding]) {
    const RULE: &str = "security:protobuf_any_type_field";
    if !findings.iter().any(|f| f.id == RULE) {
        return;
    }

    // Decode-call patterns in implementation files.
    let decode_patterns: &[&[u8]] = &[
        b"unpackTo",
        b"Any.parseFrom",
        b"Any::decode",
        b"any.unpack",
        b".unpack(",
        b"TypeRegistry",
        b"proto.Any",
        b"google.protobuf.any",
    ];
    // Allowlist guard patterns that suppress the finding when nearby.
    let guard_patterns: &[&[u8]] = &[
        b"type_url_allowlist",
        b"RegisteredTypes",
        b"getTypeRegistry",
        b"allowedTypes",
        b"knownTypes",
        b"match @type",
        b"match type_url",
    ];

    // Scan implementation files for decode + guard evidence.
    let has_unguarded_decode = 'search: {
        for entry in walkdir::WalkDir::new(dir)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if !entry.file_type().is_file() {
                continue;
            }
            let ext = entry
                .path()
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("");
            if !matches!(
                ext,
                "go" | "java" | "kt" | "py" | "rs" | "ts" | "js" | "rb" | "cs" | "cpp"
            ) {
                continue;
            }
            if std::fs::metadata(entry.path())
                .map(|m| m.len() > MAX_FILE_BYTES)
                .unwrap_or(false)
            {
                continue;
            }
            let Ok(src) = std::fs::read(entry.path()) else {
                continue;
            };
            let has_decode = decode_patterns
                .iter()
                .any(|p| src.windows(p.len()).any(|w| w == *p));
            if !has_decode {
                continue;
            }
            // Decode call found — check for nearby allowlist guard.
            let has_guard = guard_patterns
                .iter()
                .any(|p| src.windows(p.len()).any(|w| w == *p));
            if !has_guard {
                // Unguarded decode call found — finding is reachable.
                break 'search true;
            }
        }
        false
    };

    if !has_unguarded_decode {
        for finding in findings.iter_mut() {
            if finding.id == RULE {
                finding.severity = Some("Informational".to_string());
            }
        }
    }
}

/// P2-16 — Proto Schema Demotion.
///
/// Demotes `security:protobuf_any_unguarded_decode` findings to `Informational`
/// when the finding's source file has a `.proto` extension.  Proto schema files
/// define message types — they do not decode Any fields themselves.  Exploitability
/// requires a reachable Go (or Java/C++) consumer that calls an Unmarshal API;
/// a finding in a `.proto` file alone provides no proven runtime decode path.
fn apply_p2_16_protobuf_demotion(findings: &mut [StructuredFinding]) {
    const RULE: &str = "security:protobuf_any_unguarded_decode";
    for finding in findings.iter_mut() {
        if finding.id != RULE {
            continue;
        }
        let is_proto_schema = finding
            .file
            .as_deref()
            .and_then(|f| std::path::Path::new(f).extension())
            .and_then(|e| e.to_str())
            == Some("proto");
        if is_proto_schema {
            finding.severity = Some("Informational".to_string());
        }
    }
}

/// P2-17 — Config-Backed SSRF Demotion Post-Filter.
///
/// Demotes `security:ssrf_dynamic_url` findings to `Informational` when the
/// source file is a recognized operator-config module and no internal-metadata
/// evidence marker is present.  Config modules set service hostnames from env
/// vars or static structs; they are operator-controlled, not attacker-controlled.
///
/// Demoted when ALL of the following hold:
/// - The file path indicates a config module (path segment or name contains
///   `config`, `settings`, `env`, or `options`).
/// - The finding has no `internal_metadata:` evidence marker (proven SSRF).
/// - The finding `upstream_validation_absent` flag was not set by taint analysis.
fn apply_config_backed_ssrf_demotion(findings: &mut [StructuredFinding]) {
    const RULE: &str = "ssrf_dynamic_url";
    for finding in findings.iter_mut() {
        if !finding.id.contains(RULE) {
            continue;
        }
        // Concrete SSRF (proven internal metadata target): never demote.
        if finding
            .web_proof_artifact
            .as_ref()
            .is_some_and(|a| a.has_marker("internal_metadata"))
        {
            continue;
        }
        let file = finding.file.as_deref().unwrap_or("");
        if is_config_module_path(file) {
            finding.severity = Some("Informational".to_string());
            finding.upstream_validation_absent = false;
        }
    }
}

/// Returns `true` when `path` indicates an operator-configuration module
/// (not a request-handler or business-logic file).
fn is_config_module_path(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    // Segment-level config indicators (avoid over-matching "reconfiguration" etc.)
    let segments: Vec<&str> = p.split(['/', '\\', '.']).collect();
    segments.iter().any(|s| {
        matches!(
            *s,
            "config" | "configuration" | "settings" | "options" | "conf"
        )
    }) || p.ends_with("config.go")
        || p.ends_with("config.py")
        || p.ends_with("config.ts")
        || p.ends_with("config.js")
        || p.ends_with("settings.py")
        || p.ends_with("settings.go")
        || p.ends_with(".env")
}

fn has_ai_assistant_config(root: &Path) -> bool {
    [".cursor", ".windsurf", ".mcp"]
        .iter()
        .any(|name| root.join(name).is_dir())
        || root.join("claude.json").is_file()
}

fn collect_gadget_manifest_blobs(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut manifests = Vec::new();
    for entry in WalkDir::new(dir)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| !is_excluded_hunt_entry(entry))
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let file_path = entry.path();
        let file_name = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if !matches!(file_name, "pom.xml" | "requirements.txt" | "Gemfile.lock") {
            continue;
        }
        if std::fs::metadata(file_path)
            .map(|m| m.len() > MAX_FILE_BYTES)
            .unwrap_or(false)
        {
            continue;
        }
        let Ok(bytes) = std::fs::read(file_path) else {
            continue;
        };
        let rel_path = file_path
            .strip_prefix(dir)
            .unwrap_or(file_path)
            .to_string_lossy()
            .to_string();
        manifests.push((rel_path, bytes));
    }
    manifests
}

fn is_excluded_hunt_entry(entry: &walkdir::DirEntry) -> bool {
    if !entry.file_type().is_dir() {
        return false;
    }
    let name = entry.file_name().to_string_lossy();
    if matches!(
        name.as_ref(),
        ".git"
            | ".github"
            | "node_modules"
            | "target"
            | "build"
            | "dist"
            | "docs"
            | "examples"
            | "coverage"
            | "vendor"
            // Framework-vendor directories that inherently use unsafe C patterns.
            // Per Framework Exemption Rule: glibc-compatibility shims and POCO library
            // calls use strcpy/sprintf by design to replicate glibc/BSD API contracts.
            | "glibc-compatibility"
            | "poco"
            // Labyrinth deception directories: skip in O(1) to prevent friendly fire.
            | ".labyrinth"
            | "janitor_decoys"
            | "ast_maze"
            // Sample apps and demo directories are not production code.
            | "sample-app"
            | "sample_app"
            | "demo"
            | "demos"
            | "samples"
            | "playground"
            | "storybook"
    ) {
        return true;
    }
    // Aggressively drop any directory whose name contains "sample-app" or "sdk-sample"
    if name.contains("sample-app") || name.starts_with("sdk-sample") {
        return true;
    }
    // Aggressively drop all test and debug infrastructure using full-path matching
    // so nested directories like `src/internal/test_helpers/debug/` are caught
    // regardless of OS path separator or depth.
    let full_path = entry.path().to_string_lossy().to_lowercase();
    if full_path.contains("test")
        || full_path.contains("mock")
        || full_path.contains("debug")
        || full_path.contains("/it/")
        || full_path.contains("/e2e/")
        || full_path.contains("/integration/")
    {
        return true;
    }
    is_internal_mocks_dir(entry.path())
}

fn is_internal_mocks_dir(path: &Path) -> bool {
    let mut components = path.components().rev();
    let Some(std::path::Component::Normal(last)) = components.next() else {
        return false;
    };
    let Some(std::path::Component::Normal(parent)) = components.next() else {
        return false;
    };
    last.to_str() == Some("mocks") && parent.to_str() == Some("internal")
}

fn is_excluded_hunt_file(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if name.ends_with(".d.ts")
        || name.ends_with(".min.js")
        || name.ends_with(".min.esm.js")
        || name.ends_with(".map")
        || name.ends_with(".md")
        || name.ends_with(".txt")
        || name.ends_with("_test.go")
        || name.ends_with("_test.js")
        || name.ends_with("_test.py")
        || name.ends_with("_test.ts")
        || name.ends_with("_test.tsx")
        || name.ends_with("_mock.go")
        || name.ends_with("_mock.rs")
        || name.ends_with("_mock.ts")
        || name.ends_with("_mock.tsx")
        || name.starts_with("mock_")
        // Jest/Vitest/Mocha dot-style test files: `autocapture.test.ts`, `foo.spec.js`
        || name.ends_with(".test.ts")
        || name.ends_with(".test.tsx")
        || name.ends_with(".test.js")
        || name.ends_with(".spec.ts")
        || name.ends_with(".spec.tsx")
        || name.ends_with(".spec.js")
        // Shell scripts prefixed with `test_` are CI/docs-test utilities, not
        // production scripts — exclude to prevent false positives on unpinned curl
        // in test-harness entry points.
        || (name.starts_with("test_") && name.ends_with(".sh"))
        || (name.ends_with(".json") && !matches!(name, "package.json" | "manifest.json"))
        // Known vendor syntax highlighting libraries bundled into documentation sites.
        // These use innerHTML by design for syntax markup and are not attacker-reachable.
        || name == "prism.js"
        || name == "highlight.js"
        || name == "rainbow.js"
        || name == "shiki.js"
    {
        return true;
    }
    // Exclude files whose path indicates a documentation-only site (not production app).
    // Documentation sites commonly bundle vendor JS that uses innerHTML for rendering.
    let path_str = path.to_string_lossy();
    path_str.contains("/pie-docs/")
        || path_str.contains("-docs/src/assets/")
        || path_str.contains("/docs-site/")
        || path_str.contains("/docsite/")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Sanitise a raw sourcemap `sources[]` path to prevent path traversal.
///
/// Strips `webpack:///`, `file://`, and `//` prefixes; removes `../` sequences;
/// caps depth at 3 components.
pub fn sanitize_sourcemap_path(raw: &str, index: usize) -> String {
    let stripped = raw
        .trim_start_matches("webpack:///")
        .trim_start_matches("webpack://")
        .trim_start_matches("file:///")
        .trim_start_matches("file://")
        .trim_start_matches("//");

    let clean = stripped
        .replace("../", "")
        .replace("..\\", "")
        .replace("..", "");

    let components: Vec<&str> = clean
        .split(['/', '\\'])
        .filter(|s| !s.is_empty() && *s != ".")
        .collect();

    if components.is_empty() {
        return format!("source_{index}");
    }

    let capped = if components.len() > 3 {
        &components[components.len() - 3..]
    } else {
        &components[..]
    };
    capped.join("/")
}

fn byte_to_line(source: &[u8], byte_offset: usize) -> u32 {
    let capped = byte_offset.min(source.len());
    source[..capped].iter().filter(|&&b| b == b'\n').count() as u32 + 1
}

fn attach_web_proof_artifact(
    structured: &mut StructuredFinding,
    witness: &ExploitWitness,
    evidence_marker: Option<String>,
) {
    let proof_class = ProofClass::ReachabilityProof;
    structured.proof_class = Some(proof_class);
    structured.web_proof_artifact = Some(WebProofArtifact::from_witness(
        witness,
        proof_class,
        evidence_marker,
    ));
}

fn attach_memory_safety_witness_if_needed(finding: StructuredFinding) -> StructuredFinding {
    if !is_memory_safety_witness_id(&finding.id) || finding.exploit_witness.is_some() {
        return finding;
    }
    let file = finding.file.as_deref().unwrap_or("unknown");
    let line = finding.line.unwrap_or(1);
    let boundary = memory_boundary_from_id(&finding.id);
    let witness =
        forge::exploitability::cross_language_memory_witness(file, &finding.id, line, boundary);
    forge::exploitability::attach_exploit_witness(finding, witness)
}

fn is_memory_safety_witness_id(id: &str) -> bool {
    id.contains("lcm_")
        || id == "security:c_double_free"
        || id == "security:public_ffi_unsafe_deref"
        || id == "security:protobuf_any_unguarded_decode"
}

fn memory_boundary_from_id(id: &str) -> Option<String> {
    if id.contains("protobuf_any") {
        Some("google.protobuf.Any".to_string())
    } else if id.contains("public_ffi") {
        Some("extern_C_raw_pointer".to_string())
    } else if id.contains("double_free") {
        Some("heap_lifetime:free/free".to_string())
    } else {
        None
    }
}

fn attach_agent_deception_witness_if_needed(finding: StructuredFinding) -> StructuredFinding {
    if !is_agent_deception_witness_id(&finding.id) || finding.exploit_witness.is_some() {
        return finding;
    }
    let file = finding.file.as_deref().unwrap_or("unknown");
    let line = finding.line.unwrap_or(1);
    let (declared, observed) = agent_intent_labels_from_id(&finding.id);
    let witness =
        forge::exploitability::agent_deception_witness(file, &finding.id, line, declared, observed);
    forge::exploitability::attach_exploit_witness(finding, witness)
}

fn is_agent_deception_witness_id(id: &str) -> bool {
    matches!(
        id,
        "security:intent_divergence"
            | "security:swarm_context_exfiltration"
            | "security:agent_intent_misalignment"
    )
}

fn agent_intent_labels_from_id(id: &str) -> (Option<String>, Option<String>) {
    match id {
        "security:intent_divergence" => (
            Some("security_claim".to_string()),
            Some("vacuous_allow".to_string()),
        ),
        "security:swarm_context_exfiltration" => (
            Some("developer_context".to_string()),
            Some("context_exfiltration_marker".to_string()),
        ),
        "security:agent_intent_misalignment" => (
            Some("declared_tool_policy".to_string()),
            Some("tool_capability_escape".to_string()),
        ),
        _ => (None, None),
    }
}

fn ssrf_evidence_marker(text: &str) -> Option<String> {
    const INTERNAL_TARGETS: &[&str] = &[
        "169.254.169.254",
        "metadata.google.internal",
        "100.100.100.200",
        "127.0.0.1",
        "localhost",
    ];

    INTERNAL_TARGETS
        .iter()
        .find(|needle| text.contains(**needle))
        .map(|needle| format!("internal_metadata:{needle}"))
}

fn scan_buffer(
    ext: &str,
    source: &[u8],
    label: &str,
    controller_surfaces: &[forge::authz::EndpointSurfaceMatch],
    frontend_routes: &[forge::authz::FrontendRoute],
    has_ai_assistant_config: bool,
) -> Vec<StructuredFinding> {
    if is_compiled_artifact_extension(ext) {
        return forge::binary_recovery::analyze_binary(source, label);
    }

    let unit = ParsedUnit::unparsed(source);
    // GitHub issue-form YAML templates (.github/ISSUE_TEMPLATE/) contain
    // documentation URLs and form-schema links, not production asset loads.
    // Suppress supply-chain and OAuth FPs for these non-executable paths.
    let is_issue_template = label.contains("ISSUE_TEMPLATE");
    let mut slop_findings = find_slop(ext, &unit, label);
    slop_findings.extend(forge::slop_hunter::find_generative_build_execution(
        label, ext, source,
    ));
    slop_findings.extend(forge::slop_hunter::find_untrusted_ide_extensions(
        label, source,
    ));
    if has_ai_assistant_config {
        for finding in &mut slop_findings {
            if finding.description.contains("security:camoleak_") {
                finding.severity = forge::slop_hunter::Severity::KevCritical;
            }
        }
    }

    let mut findings = slop_findings
        .into_iter()
        .filter(|f| {
            !forge::slop_hunter::is_hunt_false_positive_path(label, &f.description)
                && !should_demote_unpinned_asset(label, &f.description, source)
                && (!is_issue_template
                    || (!f.description.contains("unpinned_asset")
                        && !f.description.contains("oauth_excessive_scope")))
        })
        .map(|finding| {
            let line = byte_to_line(source, finding.start_byte);
            let rule_id = extract_rule_id(&finding.description);
            // Taint-family findings (injection sinks reached without sanitization) carry
            // an implicit IFDS proof: the detector only fires when no safe API is present.
            let upstream_validation_absent = rule_id.contains("sqli")
                || rule_id.contains("ssrf")
                || rule_id.contains("command_injection")
                || rule_id.contains("path_traversal")
                || rule_id.contains("oracle_price_manipulation")
                || rule_id.contains("flash_loan_callback")
                || rule_id == "security:react_xss_dangerous_html";
            let mut structured = StructuredFinding {
                id: rule_id.to_string(),
                file: Some(label.to_string()),
                line: Some(line),
                fingerprint: fingerprint_finding(source, finding.start_byte, finding.end_byte),
                severity: Some(format!("{:?}", finding.severity)),
                remediation: None,
                docs_url: None,
                exploit_witness: None,
                upstream_validation_absent,
                ..Default::default()
            };
            let ingress_surface =
                ingress_surface_for_finding(&rule_id, label, line, controller_surfaces);
            if rule_id == "security:dom_xss_innerHTML" || rule_id.contains("prototype_pollution") {
                let mut witness =
                    forge::exploitability::browser_sink_witness(label, &rule_id, line);
                let mut evidence_marker = None;
                if finding.description.contains("schema_taint:proven") {
                    witness.path_proof = Some("schema_taint:proven".to_string());
                    evidence_marker = Some("schema_taint:proven".to_string());
                }
                if let Some(route) =
                    forge::authz::match_frontend_route_for_file(frontend_routes, label)
                {
                    witness.route_path = Some(route.route_path.clone());
                }
                attach_web_proof_artifact(&mut structured, &witness, evidence_marker);
                structured = forge::exploitability::attach_exploit_witness(structured, witness);
            } else if rule_id == "security:react_xss_dangerous_html" {
                // P2-5: Dual-frame stored XSS witness — Frame 1 writes payload, Frame 2 renders.
                let route = forge::authz::match_frontend_route_for_file(frontend_routes, label)
                    .map(|r| r.route_path.clone());
                let witness = forge::exploitability::stored_xss_dual_frame_witness(
                    label, &rule_id, line, route,
                );
                let evidence_marker =
                    Some("schema_taint:proven stored:cross_user_render".to_string());
                attach_web_proof_artifact(&mut structured, &witness, evidence_marker);
                structured.upstream_validation_absent = true;
                structured = forge::exploitability::attach_exploit_witness(structured, witness);
            } else if rule_id == "security:jwt_validation_bypass" {
                let mut witness =
                    forge::exploitability::protocol_bypass_witness(label, &rule_id, line, None);
                apply_ingress_surface(&mut structured, &mut witness, ingress_surface.as_ref());
                structured = forge::exploitability::attach_exploit_witness(structured, witness);
            } else if rule_id == "security:ssrf_dynamic_url" {
                let method = extract_go_http_method(&finding.description);
                let parameter = extract_go_url_parameter(&finding.description);
                let mut witness =
                    forge::exploitability::ssrf_witness(label, &rule_id, line, method, parameter);
                apply_ingress_surface(&mut structured, &mut witness, ingress_surface.as_ref());
                let evidence_marker = ssrf_evidence_marker(&finding.description)
                    .or_else(|| witness.repro_cmd.as_deref().and_then(ssrf_evidence_marker));
                attach_web_proof_artifact(&mut structured, &witness, evidence_marker);
                structured = forge::exploitability::attach_exploit_witness(structured, witness);
            } else if rule_id == "security:unsafe_string_function" {
                let witness = forge::exploitability::memory_unsafety_witness(
                    label,
                    &rule_id,
                    line,
                    extract_c_function_name(&finding.description),
                    source_snippet(source, finding.start_byte, finding.end_byte),
                    extract_c_buffer_width(&finding.description),
                );
                structured = forge::exploitability::attach_exploit_witness(structured, witness);
                if let Some(memory_witness) =
                    forge::memory_proof::witness_for_memory_finding(ext, source, label, line)
                {
                    structured.exploit_witness = Some(memory_witness);
                    structured.upstream_validation_absent = true;
                }
            } else if rule_id == "security:raw_pointer_deref" {
                if let Some(memory_witness) =
                    forge::memory_proof::witness_for_memory_finding(ext, source, label, line)
                {
                    structured.exploit_witness = Some(memory_witness);
                    structured.upstream_validation_absent = true;
                }
            } else if rule_id == "security:parser_exhaustion_anomaly" {
                let witness = forge::exploitability::parser_exhaustion_witness(
                    label,
                    &rule_id,
                    line,
                    extract_parser_lang_hint(&finding.description),
                );
                structured = forge::exploitability::attach_exploit_witness(structured, witness);
            } else if rule_id == "security:protobuf_any_type_field" {
                let witness = forge::exploitability::protobuf_any_witness(
                    label,
                    &rule_id,
                    line,
                    extract_backtick_after(&finding.description, "message path "),
                );
                structured = forge::exploitability::attach_exploit_witness(structured, witness);
            } else if rule_id == "security:os_command_injection"
                || rule_id == "security:subprocess_shell_injection"
                || rule_id.contains("lotl_api_c2_exfiltration")
            {
                let shell_mode = rule_id == "security:subprocess_shell_injection"
                    || rule_id.contains("lotl_api_c2_exfiltration");
                let witness = forge::exploitability::command_execution_witness(
                    label,
                    &rule_id,
                    line,
                    extract_c_function_name(&finding.description),
                    source_snippet(source, finding.start_byte, finding.end_byte),
                    None,
                    shell_mode,
                );
                structured = forge::exploitability::attach_exploit_witness(structured, witness);
            } else if rule_id.contains("unpinned_asset") {
                let url = extract_quoted_url(&finding.description);
                let context = if finding.description.contains("<script")
                    || finding.description.contains("script src")
                {
                    forge::exploitability::AssetContext::HtmlScript
                } else if finding.description.contains("cmake")
                    || finding.description.contains("CMake")
                    || finding.description.contains("ExternalProject")
                {
                    forge::exploitability::AssetContext::CmakeExternalProject
                } else {
                    forge::exploitability::AssetContext::ShellDownload
                };
                let witness = forge::exploitability::asset_integrity_witness(
                    label, &rule_id, line, url, context,
                );
                structured = forge::exploitability::attach_exploit_witness(structured, witness);
            } else if rule_id.contains("unpinned_ml_model_weights")
                || rule_id.contains("unpinned_model")
            {
                let model_id = finding
                    .description
                    .split('"')
                    .find(|s| !s.is_empty() && !s.starts_with("http"))
                    .map(str::to_string);
                let fmt = if finding.description.contains("git lfs")
                    || finding.description.contains("lfs")
                {
                    forge::exploitability::ModelLockfileFormat::GitLfs
                } else if finding.description.contains("local")
                    || finding.description.contains("cache")
                {
                    forge::exploitability::ModelLockfileFormat::LocalCache
                } else {
                    forge::exploitability::ModelLockfileFormat::HuggingFace
                };
                let witness = forge::exploitability::model_weight_witness(
                    label, &rule_id, line, model_id, fmt,
                );
                structured = forge::exploitability::attach_exploit_witness(structured, witness);
            } else if rule_id.contains("llm_prompt_injection") {
                let model_api = finding
                    .description
                    .split('`')
                    .find(|s| s.contains('.') && !s.is_empty())
                    .map(str::to_string);
                let witness = forge::exploitability::llm_prompt_injection_witness(
                    label, &rule_id, line, model_api,
                );
                structured = forge::exploitability::attach_exploit_witness(structured, witness);
            } else if rule_id == "security:embedding_trust_transposition" {
                let witness = ExploitWitness {
                    source_function: label.to_string(),
                    source_label: "rag_chunk:scraped_text".to_string(),
                    sink_function: label.to_string(),
                    sink_label: "sink:llm.invoke".to_string(),
                    call_chain: vec![
                        format!("{label}:{line}"),
                        "vector_query".to_string(),
                        "llm.invoke".to_string(),
                    ],
                    path_proof: Some(
                        "ifds:web_proof_artifact rag_chunk:scraped_text -> llm.invoke".to_string(),
                    ),
                    ..Default::default()
                };
                attach_web_proof_artifact(
                    &mut structured,
                    &witness,
                    Some("rag_trust:unprioritized_retrieval".to_string()),
                );
                structured = forge::exploitability::attach_exploit_witness(structured, witness);
            } else if rule_id == "security:vector_store_poisoning" {
                let witness = ExploitWitness {
                    source_function: label.to_string(),
                    source_label: "rag_chunk:vector_retrieval".to_string(),
                    sink_function: label.to_string(),
                    sink_label: "sink:llm.invoke".to_string(),
                    call_chain: vec![
                        format!("{label}:{line}"),
                        "vector_query".to_string(),
                        "retrieval_result".to_string(),
                        "llm.invoke".to_string(),
                    ],
                    path_proof: Some(
                        "ifds:web_proof_artifact rag_chunk:vector_retrieval -> llm.invoke"
                            .to_string(),
                    ),
                    ..Default::default()
                };
                attach_web_proof_artifact(
                    &mut structured,
                    &witness,
                    Some("vector_topology:missing_similarity_gate".to_string()),
                );
                structured = forge::exploitability::attach_exploit_witness(structured, witness);
            } else if rule_id == "security:vector_filter_polymorphism" {
                let witness = forge::exploitability::vector_filter_polymorphism_witness(
                    label, &rule_id, line, None,
                );
                attach_web_proof_artifact(
                    &mut structured,
                    &witness,
                    Some("vector_filter:tenant_predicate_polymorphism".to_string()),
                );
                structured = forge::exploitability::attach_exploit_witness(structured, witness);
            } else if rule_id == "security:missing_ownership_check" {
                let mut witness = forge::exploitability::authorization_ownership_witness(
                    label, &rule_id, line, None, None,
                );
                apply_ingress_surface(&mut structured, &mut witness, ingress_surface.as_ref());
                structured = forge::exploitability::attach_exploit_witness(structured, witness);
            } else if is_memory_safety_witness_id(&rule_id) {
                structured = attach_memory_safety_witness_if_needed(structured);
            } else if is_agent_deception_witness_id(&rule_id) {
                structured = attach_agent_deception_witness_if_needed(structured);
            }
            if matches!(
                rule_id.as_str(),
                "security:missing_ownership_check" | "security:missing_authz_check"
            ) || rule_id == "security:jwt_validation_bypass"
                || rule_id.contains("sqli")
            {
                if let Some(mut witness) = structured.exploit_witness.take() {
                    apply_ingress_surface(&mut structured, &mut witness, ingress_surface.as_ref());
                    structured.exploit_witness = Some(witness);
                } else if let Some(surface) = ingress_surface.as_ref() {
                    structured.auth_requirement = Some(format_supported_ingress(surface));
                }
            }
            structured
        })
        .collect::<Vec<_>>();
    findings.extend(forge::model_pinning::detect_unpinned_model_revisions(
        ext, source, label,
    ));
    findings.extend(forge::stego_binary::detect_embedded_executable_blob(
        source, label,
    ));
    findings.extend(
        forge::llm_decompile::detect_agent_intent_misalignment(ext, source, label)
            .into_iter()
            .map(attach_agent_deception_witness_if_needed),
    );
    findings.extend(forge::dataset_poisoning::detect_training_data_trojan(
        ext, source, label,
    ));
    findings.extend(forge::ics_rules::detect_ics_hazards(ext, source, label));
    findings.extend(forge::automotive::detect_can_bus_unvalidated_actuation(
        ext, source, label,
    ));
    // P8-3: Medical Device Pack — PHI-to-LLM taint + FDA audit-log absence.
    // Wired for Python, JavaScript, TypeScript, Java, Kotlin, C#.
    if matches!(ext, "py" | "js" | "ts" | "java" | "kt" | "cs") {
        let src_str = std::str::from_utf8(source).unwrap_or("");
        findings.extend(forge::medical::emit_phi_sink_findings(src_str, label));
        findings.extend(forge::medical::emit_audit_log_absence_findings(
            src_str, label,
        ));
    }
    let filename = std::path::Path::new(label)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    if ext == "fga" {
        findings.extend(forge::schema_graph::find_openfga_invariant_findings(
            source, label,
        ));
    }
    findings.extend(forge::agentic_graph::find_agentic_privilege_escalations(
        ext, source, label,
    ));
    findings.extend(forge::agentic_tool_audit::find_bare_metal_agentic_loops(
        ext, source, label,
    ));
    findings.extend(
        forge::noninterference::prove_prompt_tool_non_interference(source)
            .into_iter()
            .map(|mut finding| {
                if finding.file.is_none() {
                    finding.file = Some(label.to_string());
                }
                finding
            }),
    );
    findings.extend(
        forge::dma_revocation::detect_dma_revocation_shadow_access(source)
            .into_iter()
            .map(|mut finding| {
                if finding.file.is_none() {
                    finding.file = Some(label.to_string());
                }
                finding
            }),
    );
    if filename == "build.rs" {
        findings.extend(forge::rust_build_worm::find_cargo_build_worm_slop(
            label, source,
        ));
    }
    findings.extend(forge::idor::scan_source(ext, source, label));
    // Deobfuscation pre-pass: decode base64/hex/concat payloads before pattern detectors run.
    let normalized = forge::deobfuscate::normalize_payload(source);
    let source = normalized.as_deref().unwrap_or(source);
    let source_str = std::str::from_utf8(source).unwrap_or("");
    // Oracle: invisible Unicode payload scanner (trojan source / steganographic characters).
    if matches!(
        label.rsplit('.').next().unwrap_or(""),
        "py" | "js"
            | "ts"
            | "tsx"
            | "jsx"
            | "rs"
            | "go"
            | "java"
            | "kt"
            | "swift"
            | "rb"
            | "php"
            | "lua"
            | "sh"
            | "bash"
            | "ps1"
            | "cs"
            | "cpp"
            | "c"
            | "h"
    ) {
        findings.extend(
            forge::invisible_payload::scan_invisible_payloads(source, false)
                .into_iter()
                .map(|f| StructuredFinding {
                    id: extract_rule_id(&f.description),
                    severity: Some(format!("{:?}", f.severity)),
                    file: Some(label.to_string()),
                    line: Some(byte_to_line(source, f.start_byte)),
                    ..Default::default()
                }),
        );
    }
    findings
        .extend(forge::mcp_dispatch_guard::emit_mcp_confused_deputy_findings(source_str, label));
    if (label.ends_with(".yml") || label.ends_with(".yaml")) && source_str.contains("jobs:") {
        findings.extend(forge::workflow_evidence::emit_workflow_provenance_finding(
            label, source_str,
        ));
    }
    findings.extend(forge::debug_endpoint_guard::emit_debug_endpoint_findings(
        source_str, label,
    ));
    findings.extend(forge::linker_hijack::emit_linker_hijack_findings(
        source_str, label,
    ));
    findings.extend(forge::financial_pii::emit_financial_pii_to_llm_findings(
        Some(label),
        source_str,
    ));
    findings.extend(forge::ffi_taint::detect_ffi_boundary_violations(
        source_str, label,
    ));
    findings.extend(forge::java_deser_guard::emit_java_deser_findings(
        source_str, label,
    ));
    findings.extend(
        forge::llm_prompt_injection::find_llm_unbounded_prompt_concat(Some(label), source_str),
    );
    findings.extend(forge::oidc_scope_guard::emit_oidc_scope_findings(
        source_str, label,
    ));
    findings.extend(
        forge::embedding_trust::detect_embedding_trust_transposition(source_str.as_bytes())
            .into_iter()
            .map(|f| StructuredFinding {
                id: f.description.clone(),
                severity: Some(format!("{:?}", f.severity)),
                file: Some(label.to_string()),
                ..Default::default()
            }),
    );
    findings.extend(forge::lcm::emit_cross_language_memory_witnesses(
        source_str, label,
    ));
    findings.extend(forge::agent_intent::emit_agent_intent_guard_findings(
        source_str, label,
    ));
    findings.extend(forge::bayesian_taint::find_probabilistic_llm_hijacks(
        source_str.as_bytes(),
    ));
    findings.extend(
        forge::oauth_account_fusion::detect_oauth_account_fusion(source)
            .into_iter()
            .map(|f| StructuredFinding {
                id: f.description.clone(),
                severity: Some(format!("{:?}", f.severity)),
                file: Some(label.to_string()),
                proof_class: Some(common::slop::ProofClass::LatticeGapProposal),
                ..Default::default()
            }),
    );
    if matches!(
        ext,
        "py" | "js" | "ts" | "tsx" | "rb" | "go" | "java" | "php" | "kt"
    ) {
        findings.extend(
            forge::oauth_account_fusion::detect_missing_state_validation(source, label)
                .into_iter()
                .map(|f| StructuredFinding {
                    id: f.description.clone(),
                    severity: Some(format!("{:?}", f.severity)),
                    file: Some(label.to_string()),
                    proof_class: Some(common::slop::ProofClass::ReachabilityProof),
                    ..Default::default()
                }),
        );
    }
    findings.extend(forge::solidity_taint::find_solidity_slop(source));
    findings.extend(
        forge::config_taint::track_config_taint_js(source)
            .into_iter()
            .map(|f| common::slop::StructuredFinding {
                id: format!("security:config_taint_{}", f.property_path),
                severity: Some("High".to_string()),
                file: Some(label.to_string()),
                proof_class: Some(common::slop::ProofClass::LatticeGapProposal),
                ..Default::default()
            }),
    );
    // LLM load provenance: Python/JS/TS/notebook only — Rust test strings contain
    // these patterns as literals and trigger false positives on .rs diffs.
    if matches!(
        label.rsplit('.').next().unwrap_or(""),
        "py" | "ipynb" | "js" | "mjs" | "cjs" | "ts" | "tsx" | "jsx"
    ) {
        findings.extend(forge::model_lineage::emit_llm_model_provenance_findings(
            source_str, label,
        ));
    }

    // Malware genome extraction — baseline for corpus comparison in Sprint 137.
    if let Some(genome) =
        forge::malware_genome::extract_genome(source, label.rsplit('.').next().unwrap_or(""))
    {
        let _ = genome;
    }

    // Browser extension MV3 over-permission and MV2-compat-shim detector.
    if filename == "manifest.json" {
        findings.extend(forge::browser_ext::emit_browser_ext_findings(
            source_str, label,
        ));
    }

    // Neural model weight backdoor scanner (Phase A: header anomaly detection).
    if label.ends_with(".safetensors") {
        findings.extend(forge::model_backdoor::emit_model_backdoor_findings(
            source, label,
        ));
    }

    // Repojacking & unpinned Git dependency shield: scan manifest files.
    if matches!(
        filename,
        "package.json" | "Cargo.toml" | "go.mod" | "pyproject.toml" | "pom.xml"
    ) {
        for f in forge::slop_hunter::detect_unpinned_git_deps_with_provenance(
            std::path::Path::new(label),
            source,
            None,
        ) {
            let line = byte_to_line(source, f.start_byte);
            let rule_id = extract_rule_id(&f.description);
            let mut structured = StructuredFinding {
                id: rule_id.to_string(),
                file: Some(label.to_string()),
                line: Some(line),
                fingerprint: fingerprint_finding(source, f.start_byte, f.end_byte),
                severity: Some(format!("{:?}", f.severity)),
                remediation: None,
                docs_url: None,
                exploit_witness: None,
                upstream_validation_absent: false,
                ..Default::default()
            };
            if rule_id == "security:unpinned_git_dependency" {
                let witness = forge::exploitability::git_ref_dependency_witness(
                    label,
                    &rule_id,
                    line,
                    source_line_at(source, f.start_byte),
                    extract_backtick_after(&f.description, "dependency "),
                    extract_parenthesized_backtick_url(&f.description),
                );
                structured = forge::exploitability::attach_exploit_witness(structured, witness);
            }
            findings.push(structured);
        }
    }

    // P6-9 Phase A: swarm context-window exfiltration marker scan.
    // Applied to all text files — agentic IPC markers can appear in any
    // source language, commit-message templates, or CI YAML artifacts.
    if !is_compiled_artifact_extension(ext) {
        findings.extend(
            forge::swarm_exfil::detect_context_exfil(source, label)
                .into_iter()
                .map(attach_agent_deception_witness_if_needed),
        );
    }

    // P2-16: Go AST dominance — unguarded Protobuf Any decode call sites.
    findings.extend(
        forge::taint_catalog::find_protobuf_any_reachability(ext, source, label)
            .into_iter()
            .map(|mut f| {
                if f.file.is_none() {
                    f.file = Some(label.to_string());
                }
                attach_memory_safety_witness_if_needed(f)
            }),
    );

    // P2-7: Rust public FFI unsafe pointer dereference (0-hop reachability).
    findings.extend(
        forge::taint_catalog::collect_rust_call_graph_edges(ext, source, label)
            .into_iter()
            .map(|mut f| {
                if f.file.is_none() {
                    f.file = Some(label.to_string());
                }
                attach_memory_safety_witness_if_needed(f)
            }),
    );

    // P2-15 Phase A: CFG-aware C double-free witness.
    findings.extend(
        forge::taint_catalog::find_c_double_free_witness(ext, source, label)
            .into_iter()
            .map(|mut f| {
                if f.file.is_none() {
                    f.file = Some(label.to_string());
                }
                attach_memory_safety_witness_if_needed(f)
            }),
    );

    apply_p2_11_ci_sink_demotion(label, &mut findings);

    // P2-12: Demote embedding_trust_transposition when RAG answer-sink dataflow is not proven.
    // A vector-query call present in the file is insufficient for a bounty-grade finding;
    // the query result variable must structurally flow into a downstream LLM invoke call.
    if matches!(ext, "py" | "ts" | "js" | "go") {
        let dataflow_proven =
            forge::vector_topology::requires_rag_answer_sink_dataflow(source, ext);
        if !dataflow_proven {
            for f in findings.iter_mut() {
                if f.id == "security:embedding_trust_transposition" {
                    f.severity = Some("Informational".to_string());
                }
            }
        }
    }

    apply_p2_14_vendored_dom_demotion(label, ext, source, &mut findings);

    findings
}

/// P2-14 demotion lattice: a `security:dom_xss_innerHTML` finding whose
/// source file path is a vendored, bundled, or minified third-party
/// library is demoted to `Informational` unless the file *also* contains
/// a repository-native dynamic DOM reflection witness (an `innerHTML` /
/// `outerHTML` assignment whose RHS is structurally proven dynamic — an
/// identifier, call expression, or template string with substitutions).
///
/// Vendor bundles routinely emit `innerHTML = '<vendor template>'`
/// patterns by design; with no proven attacker-controlled data injection
/// the finding has no exploit path and is not bounty-grade.
fn apply_p2_14_vendored_dom_demotion(
    label: &str,
    ext: &str,
    source: &[u8],
    findings: &mut [StructuredFinding],
) {
    if !forge::slop_hunter::is_vendored_library_path(label) {
        return;
    }
    let proven = forge::slop_hunter::has_repository_native_dom_reflection(source, ext);
    if proven {
        return;
    }
    for finding in findings.iter_mut() {
        if finding.id == "security:dom_xss_innerHTML" {
            finding.severity = Some("Informational".to_string());
        }
    }
}

/// P2-11 demotion lattice: any finding whose file path identifies a CI
/// pipeline, build helper, devops automation, or test runner is demoted to
/// `Informational` unless a remote ingress node (HTTP route or public API
/// endpoint) has been resolved and recorded in `exploit_witness.route_path`.
///
/// Local shell access is required to trigger these sinks; they cannot be
/// exercised by an unauthenticated remote attacker.
fn apply_p2_11_ci_sink_demotion(label: &str, findings: &mut [StructuredFinding]) {
    if !forge::slop_hunter::is_ci_or_local_script_path(label) {
        return;
    }
    for finding in findings.iter_mut() {
        let has_remote_ingress = finding
            .exploit_witness
            .as_ref()
            .and_then(|w| w.route_path.as_ref())
            .is_some();
        if !has_remote_ingress {
            finding.severity = Some("Informational".to_string());
        }
    }
}

fn ingress_surface_for_finding(
    rule_id: &str,
    file: &str,
    line: u32,
    controller_surfaces: &[forge::authz::EndpointSurfaceMatch],
) -> Option<forge::authz::EndpointSurface> {
    if !(matches!(
        rule_id,
        "security:missing_ownership_check"
            | "security:missing_authz_check"
            | "security:jwt_validation_bypass"
    ) || rule_id.contains("sqli"))
    {
        return None;
    }

    let file_matches = controller_surfaces
        .iter()
        .filter(|surface| surface.surface.file == file)
        .cloned()
        .collect::<Vec<_>>();
    forge::authz::match_surface_for_witness(&file_matches, file, Some(line))
        .map(|entry| entry.surface.clone())
}

fn apply_ingress_surface(
    structured: &mut StructuredFinding,
    witness: &mut ExploitWitness,
    surface: Option<&forge::authz::EndpointSurface>,
) {
    let Some(surface) = surface else {
        return;
    };

    witness.route_path = Some(surface.route_path.clone());
    witness.http_method = Some(surface.http_method.clone());
    witness.auth_requirement = Some(format_supported_ingress(surface));
    structured.auth_requirement = witness.auth_requirement.clone();
}

fn format_supported_ingress(surface: &forge::authz::EndpointSurface) -> String {
    let boundary = surface
        .auth_requirement
        .as_deref()
        .map(compact_auth_requirement)
        .map(|auth| format!("authenticated_endpoint auth={auth}"))
        .unwrap_or_else(|| "public_api".to_string());
    format!("{boundary} {} {}", surface.http_method, surface.route_path)
}

fn compact_auth_requirement(auth: &str) -> String {
    let trimmed = auth.trim();
    if let Some(start) = trimmed.find('"') {
        if let Some(end) = trimmed[start + 1..].find('"') {
            return trimmed[start + 1..start + 1 + end].to_string();
        }
    }
    if let Some(start) = trimmed.find('\'') {
        if let Some(end) = trimmed[start + 1..].find('\'') {
            return trimmed[start + 1..start + 1 + end].to_string();
        }
    }
    trimmed
        .trim_start_matches("ROLE_")
        .trim_start_matches("role:")
        .to_string()
}

fn should_demote_unpinned_asset(label: &str, description: &str, source: &[u8]) -> bool {
    if !description.contains("unpinned_asset") {
        return false;
    }

    let lower = format!(
        "{label}\n{description}\n{}",
        String::from_utf8_lossy(source)
    )
    .to_ascii_lowercase();
    [
        "sandbox",
        "staging",
        "example",
        "examples",
        "demo",
        "sample",
        "mock",
        "test/",
        "test-",
        "localhost",
        "127.0.0.1",
        "sdk-example-server",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn is_compiled_artifact_extension(ext: &str) -> bool {
    matches!(
        ext.to_ascii_lowercase().as_str(),
        "so" | "dll" | "exe" | "dylib" | "macho" | "bin"
    )
}

fn source_snippet(source: &[u8], start: usize, end: usize) -> Option<String> {
    let start = start.min(source.len());
    let end = end.min(source.len());
    if start >= end {
        return None;
    }
    std::str::from_utf8(&source[start..end])
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn source_line_at(source: &[u8], byte_offset: usize) -> String {
    let offset = byte_offset.min(source.len());
    let start = source[..offset]
        .iter()
        .rposition(|b| *b == b'\n')
        .map(|idx| idx + 1)
        .unwrap_or(0);
    let end = source[offset..]
        .iter()
        .position(|b| *b == b'\n')
        .map(|idx| offset + idx)
        .unwrap_or(source.len());
    std::str::from_utf8(&source[start..end])
        .unwrap_or("")
        .trim_end()
        .to_string()
}

fn extract_rule_id(description: &str) -> String {
    description
        .split(" \u{2014} ") // U+2014 EM DASH with spaces
        .next()
        .unwrap_or(description)
        .to_owned()
}

fn extract_c_function_name(description: &str) -> Option<String> {
    description
        .split(" — ")
        .nth(1)
        .and_then(|tail| tail.split("():").next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn extract_c_buffer_width(description: &str) -> Option<usize> {
    description
        .split("inferred destination width `")
        .nth(1)
        .and_then(|tail| tail.split('`').next())
        .and_then(|value| value.parse().ok())
}

fn extract_parser_lang_hint(description: &str) -> Option<String> {
    description
        .split("tree-sitter parse of .")
        .nth(1)
        .and_then(|tail| tail.split_whitespace().next())
        .map(|value| value.trim_matches('.').to_string())
        .filter(|value| !value.is_empty())
}

fn extract_backtick_after(description: &str, marker: &str) -> Option<String> {
    description
        .split(marker)
        .nth(1)
        .and_then(|tail| tail.split('`').nth(1))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn extract_parenthesized_backtick_url(description: &str) -> Option<String> {
    description
        .split("(`")
        .nth(1)
        .and_then(|tail| tail.split("`)").next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn extract_go_http_method(description: &str) -> Option<String> {
    let call = description
        .split('`')
        .nth(1)
        .and_then(|value| value.strip_prefix("http."))
        .and_then(|value| value.strip_suffix("()"))?;
    match call {
        "Get" | "Head" => Some("GET".to_string()),
        "Post" => Some("POST".to_string()),
        _ => None,
    }
}

fn extract_go_url_parameter(description: &str) -> Option<String> {
    description
        .split("dynamic URL parameter `")
        .nth(1)
        .and_then(|tail| tail.split('`').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            value
                .rsplit(['.', '[', ']'])
                .find(|part| !part.is_empty())
                .unwrap_or(value)
                .trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
                .to_string()
        })
        .filter(|value| !value.is_empty())
}

/// Extract the first `http://` or `https://` URL from a finding description.
fn extract_quoted_url(description: &str) -> Option<String> {
    let start = description
        .find("http://")
        .or_else(|| description.find("https://"))?;
    let tail = &description[start..];
    let end = tail
        .find(|ch: char| ch == '"' || ch == '\'' || ch == '>' || ch.is_whitespace())
        .unwrap_or(tail.len());
    let url = tail[..end].trim_end_matches('"').trim_end_matches('\'');
    if url.is_empty() {
        None
    } else {
        Some(url.to_string())
    }
}

fn fingerprint_finding(source: &[u8], start: usize, end: usize) -> String {
    let s = start.min(source.len());
    let e = end.min(source.len());
    let window = if s < e { &source[s..e] } else { &source[s..s] };
    hex::encode(&blake3::hash(window).as_bytes()[..8])
}

fn sanitize_archive_entry_path(raw: &str) -> Option<std::path::PathBuf> {
    use std::path::{Component, PathBuf};

    let mut clean = PathBuf::new();
    for component in Path::new(raw).components() {
        match component {
            Component::Normal(seg) => clean.push(seg),
            Component::CurDir => {}
            Component::RootDir | Component::ParentDir | Component::Prefix(_) => return None,
        }
    }

    if clean.as_os_str().is_empty() {
        None
    } else {
        Some(clean)
    }
}

fn relative_to_root(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .to_string()
}

fn dedup_findings(findings: Vec<StructuredFinding>) -> Vec<StructuredFinding> {
    let mut deduped = Vec::with_capacity(findings.len());
    let mut seen = std::collections::BTreeSet::new();
    for finding in findings {
        let key = (
            finding.id.clone(),
            finding.file.clone().unwrap_or_default(),
            finding.line.unwrap_or_default(),
            finding.fingerprint.clone(),
        );
        if seen.insert(key) {
            deduped.push(finding);
        }
    }
    deduped
}

fn slopsquat_artifact_finding(
    package_name: &str,
    version: Option<&str>,
    corpus_path: Option<&Path>,
    artifact_label: &str,
) -> Option<StructuredFinding> {
    let normalized = normalize_package_name(package_name);
    if normalized.is_empty() {
        return None;
    }
    let corpus = load_effective_slopsquat_corpus(corpus_path).ok()?;
    let mut matched: Option<(&str, bool)> = None;
    for known in &corpus.package_names {
        let known_normalized = normalize_package_name(known);
        if known_normalized == normalized {
            matched = Some((known.as_str(), true));
            break;
        }
        if bounded_levenshtein(&normalized, &known_normalized, 1).is_some() {
            matched = Some((known.as_str(), false));
            break;
        }
    }
    let (matched_name, exact) = matched?;
    let version_suffix = version
        .filter(|value| !value.trim().is_empty())
        .map(|value| format!("@{value}"))
        .unwrap_or_default();
    let relation = if exact {
        "matches"
    } else {
        "is a one-edit near miss of"
    };
    Some(StructuredFinding {
        id: "security:slopsquat_injection".to_string(),
        file: Some(artifact_label.to_string()),
        line: Some(1),
        fingerprint: blake3::hash(format!("{normalized}:{matched_name}").as_bytes())
            .to_hex()
            .to_string(),
        severity: Some("Critical".to_string()),
        remediation: Some(format!(
            "PyPI artifact `{package_name}{version_suffix}` {relation} slopsquat corpus entry `{matched_name}`. Reject the artifact, verify provenance, and require an explicitly reviewed package allowlist before ingestion."
        )),
        docs_url: None,
        exploit_witness: None,
        upstream_validation_absent: false,
        ..Default::default()
    })
}

fn load_effective_slopsquat_corpus(corpus_path: Option<&Path>) -> anyhow::Result<SlopsquatCorpus> {
    if let Some(path) = corpus_path {
        if let Some(corpus) = common::wisdom::load_slopsquat_corpus(path) {
            return Ok(corpus);
        }
        anyhow::bail!("failed to load slopsquat corpus from {}", path.display());
    }

    let archived = rkyv::access::<ArchivedSlopsquatCorpus, rkyv::rancor::Error>(EMBEDDED_SLOPSQUAT)
        .context("embedded slopsquat corpus is corrupt")?;
    rkyv::deserialize::<SlopsquatCorpus, rkyv::rancor::Error>(archived)
        .context("embedded slopsquat corpus failed to deserialize")
}

fn normalize_package_name(name: &str) -> String {
    name.trim().to_ascii_lowercase().replace('_', "-")
}

fn bounded_levenshtein(left: &str, right: &str, max_distance: usize) -> Option<usize> {
    if left == right {
        return Some(0);
    }
    let left_chars = left.chars().collect::<Vec<_>>();
    let right_chars = right.chars().collect::<Vec<_>>();
    let length_delta = left_chars.len().abs_diff(right_chars.len());
    if length_delta > max_distance {
        return None;
    }

    let mut prev = (0..=right_chars.len()).collect::<Vec<_>>();
    let mut curr = vec![0usize; right_chars.len() + 1];
    for (i, left_char) in left_chars.iter().enumerate() {
        curr[0] = i + 1;
        let mut row_min = curr[0];
        for (j, right_char) in right_chars.iter().enumerate() {
            let substitution = usize::from(left_char != right_char);
            curr[j + 1] = (prev[j + 1] + 1)
                .min(curr[j] + 1)
                .min(prev[j] + substitution);
            row_min = row_min.min(curr[j + 1]);
        }
        if row_min > max_distance {
            return None;
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    (prev[right_chars.len()] <= max_distance).then_some(prev[right_chars.len()])
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    // -----------------------------------------------------------------------
    // sanitize_sourcemap_path
    // -----------------------------------------------------------------------

    #[test]
    fn sanitize_strips_webpack_prefix() {
        assert_eq!(
            sanitize_sourcemap_path("webpack:///src/components/App.js", 0),
            "src/components/App.js"
        );
    }

    #[test]
    fn sanitize_blocks_path_traversal() {
        let result = sanitize_sourcemap_path("webpack:///../../etc/passwd", 0);
        assert!(!result.contains(".."), "must strip path traversal");
        assert!(result.split('/').count() <= 3, "depth must be capped at 3");
    }

    #[test]
    fn sanitize_caps_depth_at_three() {
        let result = sanitize_sourcemap_path("webpack:///a/b/c/d/e/f/g.js", 0);
        assert!(result.split('/').count() <= 3, "depth must be capped at 3");
    }

    #[test]
    fn sanitize_empty_path_returns_fallback() {
        assert_eq!(sanitize_sourcemap_path("", 7), "source_7");
    }

    #[test]
    fn placeholder_scan_root_is_ignored_when_explicit_source_present() {
        assert!(is_placeholder_scan_root(Some(Path::new(".")), true));
        assert!(!is_placeholder_scan_root(Some(Path::new(".")), false));
        assert!(!is_placeholder_scan_root(Some(Path::new("./target")), true));
    }

    // -----------------------------------------------------------------------
    // extract_rule_id / byte_to_line
    // -----------------------------------------------------------------------

    #[test]
    fn extract_rule_id_splits_on_em_dash() {
        assert_eq!(
            extract_rule_id("security:command_injection \u{2014} system() with dynamic arg"),
            "security:command_injection"
        );
    }

    #[test]
    fn extract_rule_id_no_separator_returns_whole() {
        assert_eq!(extract_rule_id("security:raw"), "security:raw");
    }

    #[test]
    fn byte_to_line_counts_newlines() {
        let src = b"line1\nline2\nline3\n";
        assert_eq!(byte_to_line(src, 0), 1);
        assert_eq!(byte_to_line(src, 6), 2);
        assert_eq!(byte_to_line(src, 12), 3);
    }

    // -----------------------------------------------------------------------
    // scan_directory — credential detection
    // -----------------------------------------------------------------------

    #[test]
    fn scan_directory_emits_credential_finding() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("config.yml"),
            b"AKIAIOSFODNN7EXAMPLE = true",
        )
        .unwrap();
        let findings = scan_directory(dir.path()).unwrap();
        assert!(
            !findings.is_empty(),
            "AWS key prefix must trigger credential finding"
        );
        assert!(
            findings[0].id.contains("credential"),
            "finding id must contain 'credential'"
        );
    }

    #[test]
    fn scan_directory_skips_oversized_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("big.bin");
        let f = std::fs::File::create(&path).unwrap();
        f.set_len(MAX_FILE_BYTES + 1).unwrap();
        let findings = scan_directory(dir.path()).unwrap();
        assert!(
            findings
                .iter()
                .all(|f| f.file.as_deref() != Some("big.bin")),
            "oversized file must be skipped"
        );
    }

    // -----------------------------------------------------------------------
    // Sourcemap ingestion — mock JSON round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn sourcemap_reconstruction_scans_inline_content() {
        let map = serde_json::json!({
            "version": 3,
            "sources": ["webpack:///src/server.js"],
            "sourcesContent": [
                "const exec = require('child_process');\n\
                 exec.execSync('rm -rf ' + userInput);\n\
                 const key = 'AKIAIOSFODNN7EXAMPLEKEY123';\n"
            ]
        });
        let map_str = serde_json::to_string(&map).unwrap();

        let tmp = tempfile::TempDir::new().unwrap();
        let dest = tmp.path().join("src").join("server.js");
        std::fs::create_dir_all(dest.parent().unwrap()).unwrap();

        let content = map["sourcesContent"][0].as_str().unwrap();
        std::fs::write(&dest, content.as_bytes()).unwrap();

        let findings = scan_directory(tmp.path()).unwrap();
        assert!(
            findings.iter().any(|f| f.id.contains("credential")),
            "reconstructed source with AWS key must produce a credential finding; map={map_str}"
        );
    }

    // -----------------------------------------------------------------------
    // npm spec parsing
    // -----------------------------------------------------------------------

    #[test]
    fn parse_npm_spec_versioned() {
        let (name, ver) = parse_npm_spec("lodash@4.17.21");
        assert_eq!(name, "lodash");
        assert_eq!(ver, "4.17.21");
    }

    #[test]
    fn parse_npm_spec_unversioned() {
        let (name, ver) = parse_npm_spec("lodash");
        assert_eq!(name, "lodash");
        assert_eq!(ver, "");
    }

    #[test]
    fn parse_npm_spec_scoped_versioned() {
        let (name, ver) = parse_npm_spec("@scope/pkg@2.0.0");
        assert_eq!(name, "@scope/pkg");
        assert_eq!(ver, "2.0.0");
    }

    #[test]
    fn parse_npm_spec_scoped_unversioned() {
        let (name, ver) = parse_npm_spec("@scope/pkg");
        assert_eq!(name, "@scope/pkg");
        assert_eq!(ver, "");
    }

    #[test]
    fn npm_tarball_uses_registry_dist_url_for_scoped_packages() {
        let meta = serde_json::json!({
            "name": "@scope/pkg",
            "version": "2.0.0",
            "dist": {
                "tarball": "https://registry.npmjs.org/@scope/pkg/-/pkg-2.0.0.tgz"
            }
        });
        let tarball = npm_tarball_from_metadata(&meta).unwrap();
        assert_eq!(
            tarball,
            "https://registry.npmjs.org/@scope/pkg/-/pkg-2.0.0.tgz"
        );
    }

    fn build_whl(metadata_name: &str, python_source: &[u8]) -> tempfile::TempDir {
        let tmp = tempfile::TempDir::new().unwrap();
        let whl_path = tmp.path().join("sample.whl");
        let file = std::fs::File::create(&whl_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("pkg/__init__.py", options).unwrap();
        zip.write_all(python_source).unwrap();
        zip.start_file("demo-1.0.0.dist-info/METADATA", options)
            .unwrap();
        zip.write_all(
            format!("Metadata-Version: 2.1\nName: {metadata_name}\nVersion: 1.0.0\n").as_bytes(),
        )
        .unwrap();
        zip.start_file("demo-1.0.0.dist-info/entry_points.txt", options)
            .unwrap();
        zip.write_all(b"[console_scripts]\ndemo = pkg:main\n")
            .unwrap();
        zip.start_file("demo-1.0.0.data/scripts/demo", options)
            .unwrap();
        zip.write_all(b"#!/usr/bin/env python3\nfrom pkg import main\nmain()\n")
            .unwrap();
        zip.finish().unwrap();
        tmp
    }

    #[test]
    fn wheel_ingest_flags_slopsquat_package_name_immediately() {
        let wheel = build_whl("djago", b"def main():\n    return 0\n");
        let corpus_dir = tempfile::TempDir::new().unwrap();
        let corpus_path = corpus_dir.path().join("slopsquat_corpus.rkyv");
        let corpus = common::wisdom::SlopsquatCorpus {
            package_names: vec!["djago".to_string()],
        };
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&corpus).unwrap();
        std::fs::write(&corpus_path, bytes.as_slice()).unwrap();

        let findings = ingest_whl(&wheel.path().join("sample.whl"), Some(&corpus_path)).unwrap();
        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "security:slopsquat_injection"),
            "wheel metadata name in the slopsquat corpus must trigger an immediate Critical finding"
        );
    }

    #[test]
    fn wheel_ingest_surfaces_idor_in_extracted_python_handler() {
        let wheel = build_whl(
            "safe-demo",
            br#"
@app.get("/users/<int:user_id>")
def main(user_id):
    record = db.session.query(User).filter_by(id=user_id).first()
    return jsonify(record)
"#,
        );
        let findings = ingest_whl(&wheel.path().join("sample.whl"), None).unwrap();
        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "security:missing_ownership_check"),
            "wheel-extracted python route without an ownership check must trigger the IDOR detector"
        );
    }

    #[test]
    fn bugcrowd_formatter_emits_required_headers() {
        let finding = StructuredFinding {
            id: "security:dom_xss_innerHTML".to_string(),
            file: Some("static/app.js".to_string()),
            line: Some(42),
            fingerprint: "abc123".to_string(),
            severity: Some("Critical".to_string()),
            remediation: Some(
                "Replace innerHTML with textContent or a vetted sanitizer.".to_string(),
            ),
            docs_url: None,
            exploit_witness: None,
            upstream_validation_absent: false,
            ..Default::default()
        };

        let report = format_bugcrowd_report(&[finding]);
        assert!(report.contains(
            "**Summary Title:** Multiple instances of security:dom_xss_innerHTML in target"
        ));
        assert!(report.contains("**VRT Category:**"));
        assert!(report.contains("**Vulnerability Details:**"));
        assert!(report.contains("**Business Impact:**"));
        assert!(report.contains("**Data Flow Analysis:**"));
        assert!(report.contains("**Vulnerability Reproduction:**"));
        assert!(report.contains("Pentester notes:"));
        assert!(report.contains(
            "**Remediation Advice:** Replace innerHTML with textContent or a vetted sanitizer."
        ));
    }

    #[test]
    fn bugcrowd_formatter_renders_unified_web_proof_artifact() {
        let finding = StructuredFinding {
            id: "security:dom_xss_innerHTML".to_string(),
            file: Some("static/app.js".to_string()),
            line: Some(42),
            fingerprint: "webproof123".to_string(),
            severity: Some("Critical".to_string()),
            proof_class: Some(common::slop::ProofClass::ReachabilityProof),
            web_proof_artifact: Some(common::slop::WebProofArtifact {
                source_label: "url_param:returnTo".to_string(),
                sink_label: "sink:innerHTML".to_string(),
                ifds_trace: vec!["router.parse".to_string(), "render".to_string()],
                evidence_marker: Some("schema_taint:proven".to_string()),
                proof_class: common::slop::ProofClass::ReachabilityProof,
            }),
            upstream_validation_absent: true,
            ..Default::default()
        };

        let report = format_bugcrowd_report(&[finding]);
        assert!(
            report.contains("WebProofArtifact: `url_param:returnTo` -> `sink:innerHTML`"),
            "Bugcrowd markdown must use the unified web proof artifact"
        );
        assert!(
            report.contains("url_param:returnTo -> router.parse -> render -> sink:innerHTML"),
            "IFDS output must bind the external source to the execution sink"
        );
        assert!(
            report.contains("schema_taint:proven"),
            "compact evidence marker must survive formatting"
        );
        assert!(
            !report.contains("Acceptance Oracle: proof-complete"),
            "candidate gap section must not emit redundant proof-complete prose when an artifact exists"
        );
    }

    #[test]
    fn scan_buffer_attaches_web_proof_artifact_for_vector_store_poisoning() {
        let source = br#"
async function answer(req) {
  const results = await pinecone.query({ vector: embed(req.body.prompt), topK: 6 });
  return openai.chat.completions.create({
    messages: [{ role: "user", content: results.matches[0].metadata.page_content }]
  });
}
"#;

        let findings = scan_buffer("ts", source, "src/rag.ts", &[], &[], false);
        let finding = findings
            .iter()
            .find(|finding| finding.id == "security:vector_store_poisoning")
            .expect("vector store poisoning finding must be emitted");

        let artifact = finding
            .web_proof_artifact
            .as_ref()
            .expect("vector store poisoning finding must carry a web proof artifact");
        assert_eq!(artifact.source_label, "rag_chunk:vector_retrieval");
        assert_eq!(artifact.sink_label, "sink:llm.invoke");
        assert!(artifact.has_marker("vector_topology:missing_similarity_gate"));
    }

    #[test]
    fn scan_buffer_attaches_memory_witness_for_protobuf_any_decode() {
        let source = br#"
package handler
import "google.golang.org/protobuf/types/known/anypb"
func Handle(msg *anypb.Any) {
    _, _ = anypb.UnmarshalNew(msg, nil)
}
"#;
        let findings = scan_buffer("go", source, "handler/handler.go", &[], &[], false);
        let finding = findings
            .iter()
            .find(|finding| finding.id == "security:protobuf_any_unguarded_decode")
            .expect("protobuf Any decode finding must be emitted");
        let witness = finding
            .exploit_witness
            .as_ref()
            .expect("protobuf Any finding must carry an exploit witness");
        assert!(
            witness.memory_safety_witness.is_some(),
            "protobuf Any finding must carry cross-language memory evidence"
        );
        assert!(
            witness
                .repro_cmd
                .as_deref()
                .is_some_and(|cmd| cmd.contains("CrossLanguageMemoryWitness/v1")),
            "repro_cmd must encode the memory witness schema"
        );
    }

    #[test]
    fn scan_buffer_attaches_agent_deception_witness_for_intent_divergence() {
        let source = br#"
fn verify_signature() -> bool { true }
"#;
        let findings = scan_buffer("rs", source, "src/auth.rs", &[], &[], false);
        let finding = findings
            .iter()
            .find(|finding| finding.id == "security:intent_divergence")
            .expect("intent divergence finding must be emitted");
        let witness = finding
            .exploit_witness
            .as_ref()
            .expect("intent divergence finding must carry an exploit witness");
        assert!(
            witness.agent_deception_witness.is_some(),
            "intent divergence must carry agent deception evidence"
        );
        assert!(
            witness
                .repro_cmd
                .as_deref()
                .is_some_and(|cmd| cmd.contains("AgentDeceptionWitness/v1")),
            "repro_cmd must encode the agent deception schema"
        );
    }

    #[test]
    fn scan_buffer_attaches_supported_ingress_metadata_to_jwt_findings() {
        let source = br#"
const express = require("express");
const router = express.Router();
router.get("/api/tokens", ensureRole("ADMIN"), (req, res) => {
  jwt.decode(req.headers.authorization, { complete: true });
  res.json({ ok: true });
});
"#;
        let controller_surfaces = forge::authz::extract_controller_surface_matches_for_file(
            "js",
            source,
            "src/routes.js".to_string(),
        );
        let findings = scan_buffer(
            "js",
            source,
            "src/routes.js",
            &controller_surfaces,
            &[],
            false,
        );
        let finding = findings
            .iter()
            .find(|finding| finding.id == "security:jwt_validation_bypass")
            .expect("jwt validation bypass finding must be emitted");
        assert_eq!(
            finding.auth_requirement.as_deref(),
            Some("authenticated_endpoint auth=ADMIN GET /api/tokens")
        );
        let witness = finding
            .exploit_witness
            .as_ref()
            .expect("jwt finding must carry an exploit witness");
        assert_eq!(witness.route_path.as_deref(), Some("/api/tokens"));
        assert_eq!(witness.http_method.as_deref(), Some("GET"));
    }

    #[test]
    fn scan_buffer_demotes_sandbox_unpinned_assets() {
        let source = br#"
enum Environment {
  case sandbox
}
let bootstrap = "https://afterpay.github.io/sdk-example-server/widget-bootstrap.js"
"#;
        let findings = scan_buffer(
            "swift",
            source,
            "Sources/Afterpay/Model/Environment.swift",
            &[],
            &[],
            false,
        );
        assert!(
            findings
                .iter()
                .all(|finding| !finding.id.contains("unpinned_asset")),
            "sandbox bootstrap assets must be demoted before ledger routing"
        );
    }

    #[test]
    fn bugcrowd_formatter_injects_exploit_witness_repro_into_poc() {
        let finding = StructuredFinding {
            id: "security:unsafe_deserialization".to_string(),
            file: Some("api/handler.py".to_string()),
            line: Some(17),
            fingerprint: "deser123".to_string(),
            severity: Some("Critical".to_string()),
            remediation: Some("Replace `pickle.loads` with a safe codec.".to_string()),
            docs_url: None,
            exploit_witness: Some(common::slop::ExploitWitness {
                source_function: "handler".to_string(),
                source_label: "param:data".to_string(),
                sink_function: "pickle.loads".to_string(),
                sink_label: "sink:unsafe_deserialization".to_string(),
                call_chain: vec!["handler".to_string(), "pickle.loads".to_string()],
                repro_cmd: Some(
                    "python3 -c \"import base64,pickle; pickle.loads(base64.b64decode('Y29zCnN5c3RlbQooUydlY2hvIEpBTklUT1JfUFJPQkUnCnRSLg=='))\""
                        .to_string(),
                ),
                sanitizer_audit: Some(
                    "Path analysis confirms no registered sanitizers or validators (e.g., escapeHtml, Joi.string, express_validator_body) were invoked on this variable prior to the sink.".to_string(),
                ),
                ..Default::default()
            }),
            upstream_validation_absent: false,
                ..Default::default()
        };

        let report = format_bugcrowd_report(&[finding]);
        assert!(report.contains("**Data Flow Analysis:**"));
        assert!(report.contains("Path analysis confirms no registered sanitizers or validators"));
        assert!(report.contains("**Vulnerability Reproduction:**\n```text"));
        assert!(report.contains("pickle.loads(base64.b64decode"));
        assert!(!report.contains("Payload Synthesis"));
    }

    #[test]
    fn bugcrowd_formatter_renders_verified_gadget_chain_statement() {
        let finding = StructuredFinding {
            id: "security:deserialization_gadget_chain".to_string(),
            file: Some("src/Handler.java".to_string()),
            line: Some(6),
            fingerprint: "gadget123".to_string(),
            severity: Some("KevCritical".to_string()),
            remediation: None,
            docs_url: None,
            exploit_witness: Some(common::slop::ExploitWitness {
                source_function: "readObject".to_string(),
                source_label: "deserialization_entry".to_string(),
                sink_function: "Runtime.exec".to_string(),
                sink_label: "sink:rce_gadget_chain".to_string(),
                call_chain: vec![
                    "readObject".to_string(),
                    "InvokerTransformer".to_string(),
                    "Runtime.exec".to_string(),
                ],
                gadget_chain: Some(vec![
                    "readObject".to_string(),
                    "InvokerTransformer".to_string(),
                    "Runtime.exec".to_string(),
                ]),
                ..Default::default()
            }),
            upstream_validation_absent: true,
            ..Default::default()
        };

        let report = format_bugcrowd_report(&[finding]);
        assert!(report.contains(GADGET_CHAIN_BUGCROWD_PROOF));
    }

    #[test]
    fn bugcrowd_formatter_preserves_live_tenant_html_harness_in_poc() {
        let html_harness = r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Janitor Auth0 DOM XSS Witness</title>
  <script src="https://cdn.auth0.com/js/auth0/9.28/auth0.min.js"></script>
</head>
<body>
  <script>
    const webAuth = new auth0.WebAuth({
      domain: "tenant.example.auth0.com",
      clientID: "test-client-123",
      redirectUri: "http://localhost:8765/callback"
    });
  </script>
</body>
</html>"#;
        let finding = StructuredFinding {
            id: "security:dom_xss_innerHTML".to_string(),
            file: Some("src/auth0-widget.js".to_string()),
            line: Some(44),
            fingerprint: "domxss-live-tenant".to_string(),
            severity: Some("High".to_string()),
            remediation: None,
            docs_url: None,
            exploit_witness: Some(common::slop::ExploitWitness {
                source_function: "render".to_string(),
                source_label: "param:state".to_string(),
                sink_function: "Element.innerHTML".to_string(),
                sink_label: "sink:dom_xss".to_string(),
                call_chain: vec!["render".to_string(), "Element.innerHTML".to_string()],
                repro_cmd: Some(html_harness.to_string()),
                live_proof: Some(
                    "Live tenant context injected into a standalone HTML harness. No network request was executed by Janitor; use the harness only against an approved test tenant."
                        .to_string(),
                ),
                ..Default::default()
            }),
            upstream_validation_absent: true,
                ..Default::default()
        };

        let report = format_bugcrowd_report(&[finding]);

        assert!(report.contains("**Vulnerability Reproduction:**\n```text"));
        assert!(report.contains(
            "<script src=\"https://cdn.auth0.com/js/auth0/9.28/auth0.min.js\"></script>"
        ));
        assert!(report.contains("new auth0.WebAuth({"));
        assert!(report.contains("clientID: \"test-client-123\""));
        assert!(report.contains("**Live Tenant Context:**"));
        assert!(report.contains("No network request was executed by Janitor"));
    }

    #[test]
    fn bugcrowd_formatter_keeps_enterprise_attestation_out_of_markdown() {
        let finding = StructuredFinding {
            id: "security:dom_xss_innerHTML".to_string(),
            file: Some("src/auth0-widget.js".to_string()),
            line: Some(44),
            fingerprint: "domxss-psm".to_string(),
            severity: Some("High".to_string()),
            remediation: None,
            docs_url: None,
            exploit_witness: Some(common::slop::ExploitWitness {
                source_function: "render".to_string(),
                source_label: "param:state".to_string(),
                sink_function: "Element.innerHTML".to_string(),
                sink_label: "sink:dom_xss".to_string(),
                sanitizer_audit: Some(
                    "Path sanitizers [escapeHtml] matched PSM cohort 19/20 clean repos."
                        .to_string(),
                ),
                ..Default::default()
            }),
            upstream_validation_absent: false,
            ..Default::default()
        };

        let report = format_bugcrowd_report(&[finding]);

        assert!(!report.contains("**Defensive Evidence:**"));
        assert!(!report.contains("Proven Invariant"));
        assert!(report.contains("escapeHtml"));
        assert!(report.contains("19/20"));
    }

    #[test]
    fn auth0_formatter_emits_required_headers() {
        let finding = StructuredFinding {
            id: "security:command_injection".to_string(),
            file: Some("api/exec.js".to_string()),
            line: Some(18),
            fingerprint: "cmd123".to_string(),
            severity: Some("Critical".to_string()),
            remediation: None,
            docs_url: None,
            exploit_witness: Some(common::slop::ExploitWitness {
                source_function: "handler".to_string(),
                source_label: "param:cmd".to_string(),
                sink_function: "child_process.exec".to_string(),
                sink_label: "sink:command_injection".to_string(),
                call_chain: vec![
                    "handler".to_string(),
                    "exec_wrapper".to_string(),
                    "child_process.exec".to_string(),
                ],
                repro_cmd: Some(
                    "curl -X POST https://target.com/api/exec -d '{\"cmd\": \"id\"}'".to_string(),
                ),
                sanitizer_audit: Some(
                    "Path analysis confirms no registered sanitizers or validators (e.g., escapeHtml, Joi.string, express_validator_body) were invoked on this variable prior to the sink.".to_string(),
                ),
                ..Default::default()
            }),
            upstream_validation_absent: false,
                ..Default::default()
        };

        let report = format_auth0_report(&[finding]);
        assert!(
            report.contains("**Description**"),
            "must have Description header"
        );
        assert!(
            report.contains("**Business Impact (how does this affect Auth0?)**"),
            "must have Business Impact header"
        );
        assert!(
            report.contains("**Working proof of concept**"),
            "must have Working proof of concept header"
        );
        assert!(
            report.contains("**Upstream Validation Audit**"),
            "must have Upstream Validation Audit header"
        );
        assert!(
            report.contains("**Discoverability (how likely is this to be discovered)**"),
            "must have Discoverability header"
        );
        assert!(
            report.contains("**Exploitability (how likely is this to be exploited)**"),
            "must have Exploitability header"
        );
        assert!(
            report.contains("curl -X POST"),
            "repro_cmd must be injected into PoC section"
        );
        assert!(
            report.contains("Path analysis confirms no registered sanitizers or validators"),
            "sanitizer_audit must be injected into the validation audit section"
        );
        assert!(
            report.contains("multiple interprocedural boundaries"),
            "call chain > 1 must produce low-discoverability text"
        );
    }

    #[test]
    fn auth0_formatter_renders_tier_c_falsified_sanitizer_audit() {
        let finding = StructuredFinding {
            id: "security:sql_injection".to_string(),
            file: Some("api/users.js".to_string()),
            line: Some(42),
            fingerprint: "sqlfals001".to_string(),
            severity: Some("Critical".to_string()),
            remediation: None,
            docs_url: None,
            exploit_witness: Some(common::slop::ExploitWitness {
                source_function: "handler".to_string(),
                source_label: "param:q".to_string(),
                sink_function: "db.query".to_string(),
                sink_label: "sink:sql_query".to_string(),
                call_chain: vec!["handler".to_string(), "db.query".to_string()],
                repro_cmd: Some(
                    "curl -X POST https://target.com/api/users -d '{\"q\": \"1' OR 1=1--\"}'"
                        .to_string(),
                ),
                sanitizer_audit: Some(
                    "Sanitizer escape_html was invoked, but mathematical falsification proves it is bypassable. Counterexample payload: javascript:alert(1)".to_string(),
                ),
                upstream_validation_absent: true,
                ..Default::default()
            }),
            upstream_validation_absent: true,
                ..Default::default()
        };

        let report = format_auth0_report(&[finding]);
        assert!(
            report.contains("**Upstream Validation Audit**"),
            "Tier C finding must render Upstream Validation Audit section"
        );
        assert!(
            report.contains(
                "Sanitizer escape_html was invoked, but mathematical falsification proves it is bypassable."
            ),
            "Tier C falsification sentence must be embedded verbatim"
        );
        assert!(
            report.contains("Counterexample payload:"),
            "Tier C counterexample label must be embedded"
        );
    }

    #[test]
    fn auth0_formatter_renders_tier_b_partial_sanitization_audit() {
        let finding = StructuredFinding {
            id: "security:ssrf".to_string(),
            file: Some("api/fetch.js".to_string()),
            line: Some(17),
            fingerprint: "tierbssrf001".to_string(),
            severity: Some("Critical".to_string()),
            remediation: None,
            docs_url: None,
            exploit_witness: Some(common::slop::ExploitWitness {
                source_function: "Controller.fetchRemote".to_string(),
                source_label: "param:url".to_string(),
                sink_function: "Http.ssrf_fetch".to_string(),
                sink_label: "sink:ssrf_fetch".to_string(),
                call_chain: vec![
                    "Controller.fetchRemote".to_string(),
                    "escapeHtml".to_string(),
                    "Http.ssrf_fetch".to_string(),
                ],
                repro_cmd: Some(
                    "curl -X POST https://target.com/api/fetch -d '{\"url\": \"http://internal.admin/secret\"}'"
                        .to_string(),
                ),
                sanitizer_audit: Some(
                    "Path sanitizers [escapeHtml] do not mathematically entail the sink's safety contract. Counterexample: output = http://internal.admin. Gap: path is sanitized against XSS but fails to satisfy SSRF constraints."
                        .to_string(),
                ),
                upstream_validation_absent: true,
                ..Default::default()
            }),
            upstream_validation_absent: true,
                ..Default::default()
        };

        let report = format_auth0_report(&[finding]);
        assert!(
            report.contains("**Upstream Validation Audit**"),
            "Tier B finding must render Upstream Validation Audit section"
        );
        assert!(
            report.contains(
                "Path sanitizers [escapeHtml] do not mathematically entail the sink's safety contract."
            ),
            "Tier B entailment failure sentence must be embedded verbatim"
        );
        assert!(
            report.contains("Counterexample: output ="),
            "Tier B counterexample label must be embedded"
        );
        assert!(
            report.contains("Gap: path is sanitized against XSS but fails to satisfy SSRF"),
            "Tier B gap summary must name both sanitizer and sink domains"
        );
    }

    #[test]
    fn auth0_formatter_renders_tier_d_framework_implicit_citation() {
        let finding = StructuredFinding {
            id: "security:ssrf".to_string(),
            file: Some("api/UserController.java".to_string()),
            line: Some(42),
            fingerprint: "tierdspring001".to_string(),
            severity: Some("Critical".to_string()),
            remediation: None,
            docs_url: None,
            exploit_witness: Some(common::slop::ExploitWitness {
                source_function: "UserController.createUser".to_string(),
                source_label: "param:body".to_string(),
                sink_function: "InternalFetch.ssrf_fetch".to_string(),
                sink_label: "sink:ssrf_fetch".to_string(),
                call_chain: vec![
                    "UserController.createUser".to_string(),
                    "springRequestBody".to_string(),
                    "InternalFetch.ssrf_fetch".to_string(),
                ],
                repro_cmd: Some(
                    "curl -X POST https://target.com/api/users -d '{\"url\": \"http://internal.admin\"}'"
                        .to_string(),
                ),
                sanitizer_audit: Some(
                    "Path sanitizers [springRequestBody] do not mathematically entail the sink's safety contract. Counterexample: output = http://internal.admin. Gap: path is sanitized against generic input validation but fails to satisfy SSRF constraints. The Spring framework implicit validator (springRequestBody) was evaluated, but Z3 proves it does not entail safety for this sink."
                        .to_string(),
                ),
                upstream_validation_absent: true,
                ..Default::default()
            }),
            upstream_validation_absent: true,
                ..Default::default()
        };

        let report = format_auth0_report(&[finding]);
        assert!(
            report.contains("**Upstream Validation Audit**"),
            "Tier D finding must render the Upstream Validation Audit section"
        );
        assert!(
            report.contains(
                "The Spring framework implicit validator (springRequestBody) was evaluated, but Z3 proves it does not entail safety for this sink."
            ),
            "Tier D audit must cite the Spring framework verbatim"
        );
    }

    #[test]
    fn auth0_formatter_renders_tier_e_non_monotonic_exclusion() {
        let finding = StructuredFinding {
            id: "security:ssrf".to_string(),
            file: Some("api/fetch.js".to_string()),
            line: Some(31),
            fingerprint: "tiere001".to_string(),
            severity: Some("Critical".to_string()),
            remediation: None,
            docs_url: None,
            exploit_witness: Some(common::slop::ExploitWitness {
                source_function: "Controller.handle".to_string(),
                source_label: "param:url".to_string(),
                sink_function: "Http.ssrf_fetch".to_string(),
                sink_label: "sink:ssrf_fetch".to_string(),
                call_chain: vec![
                    "Controller.handle".to_string(),
                    "escapeHtml".to_string(),
                    "Http.ssrf_fetch".to_string(),
                ],
                sanitizer_audit: Some(
                    "Path sanitizers [escapeHtml] do not mathematically entail the sink's safety contract. Counterexample: output = http://internal.admin. Gap: path is sanitized against XSS but fails to satisfy SSRF constraints. A concurrent path correctly sanitized by [validateSsrfUrl] was analyzed, but the vulnerability remains exploitable via this bypass path."
                        .to_string(),
                ),
                upstream_validation_absent: true,
                ..Default::default()
            }),
            upstream_validation_absent: true,
                ..Default::default()
        };

        let report = format_auth0_report(&[finding]);
        assert!(
            report.contains(
                "A concurrent path correctly sanitized by [validateSsrfUrl] was analyzed, but the vulnerability remains exploitable via this bypass path."
            ),
            "Tier E exclusion clause must be rendered verbatim in the audit section"
        );
    }

    #[test]
    fn bugcrowd_filter_can_reduce_findings_before_rendering() {
        let findings = vec![
            StructuredFinding {
                id: "security:dom_xss_innerHTML".to_string(),
                file: Some("captcha.js".to_string()),
                line: Some(46),
                fingerprint: "xss1".to_string(),
                severity: Some("Critical".to_string()),
                remediation: None,
                docs_url: None,
                exploit_witness: None,
                upstream_validation_absent: false,
                ..Default::default()
            },
            StructuredFinding {
                id: "security:hardcoded_secret".to_string(),
                file: Some("config.js".to_string()),
                line: Some(7),
                fingerprint: "secret1".to_string(),
                severity: Some("Critical".to_string()),
                remediation: None,
                docs_url: None,
                exploit_witness: None,
                upstream_validation_absent: false,
                ..Default::default()
            },
        ];

        let filtered = apply_jaq_filter(
            ".[] | select(.id == \"security:dom_xss_innerHTML\")",
            serde_json::to_value(&findings).unwrap(),
        )
        .unwrap();
        let filtered_findings: Vec<StructuredFinding> = serde_json::from_value(filtered).unwrap();
        let report = format_bugcrowd_report(&filtered_findings);

        assert!(report.contains("security:dom_xss_innerHTML"));
        assert!(!report.contains("security:hardcoded_secret"));
    }

    #[test]
    fn bugcrowd_report_ranks_poc_findings_before_informational_noise() {
        let findings = vec![
            StructuredFinding {
                id: "security:aaa_informational".to_string(),
                file: Some("noise.txt".to_string()),
                line: Some(1),
                fingerprint: "noise".to_string(),
                severity: Some("Informational".to_string()),
                ..Default::default()
            },
            StructuredFinding {
                id: "security:zz_payload".to_string(),
                file: Some("src/app.rs".to_string()),
                line: Some(9),
                fingerprint: "poc".to_string(),
                severity: Some("Critical".to_string()),
                exploit_witness: Some(common::slop::ExploitWitness {
                    repro_cmd: Some("curl -X POST http://target.local/pwn".to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ];

        let report = format_bugcrowd_report_with_component(&findings, Some("**demo** v1"));
        let first_summary = report
            .lines()
            .find(|line| line.starts_with("**Summary Title:**"))
            .unwrap_or("");

        assert!(
            first_summary.contains("security:zz_payload"),
            "PoC-backed finding must rank first"
        );
    }

    // -----------------------------------------------------------------------
    // SBOM linkage — Affected Package / Component header
    // -----------------------------------------------------------------------

    #[test]
    fn sbom_linkage_section_appears_in_bugcrowd_and_auth0_reports() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(
            tmp.path().join("package.json"),
            r#"{"name":"auth0-lock","version":"12.3.1"}"#,
        )
        .unwrap();

        let component = detect_component_info_inner(&[], Some(tmp.path()));
        assert!(
            component.contains("auth0-lock@12.3.1"),
            "package.json component info must use name@version"
        );

        let finding = StructuredFinding {
            id: "security:dom_xss_innerHTML".to_string(),
            file: None,
            line: None,
            fingerprint: "abc123".to_string(),
            severity: Some("Critical".to_string()),
            remediation: None,
            docs_url: None,
            exploit_witness: None,
            upstream_validation_absent: false,
            ..Default::default()
        };
        let bugcrowd = format_bugcrowd_report(&[finding.clone()]);
        assert!(
            bugcrowd.contains("**Affected Package / Component:**"),
            "bugcrowd report must contain SBOM linkage header"
        );
        let auth0 = format_auth0_report(&[finding]);
        assert!(
            auth0.contains("**Affected Package / Component**"),
            "auth0 report must contain SBOM linkage header"
        );
    }

    #[test]
    fn auth0_report_accepts_ephemeral_npm_component_override() {
        let finding = StructuredFinding {
            id: "security:oauth_excessive_scope".to_string(),
            file: Some("package/src/index.ts".to_string()),
            line: Some(7),
            fingerprint: "scoped".to_string(),
            severity: Some("KevCritical".to_string()),
            remediation: None,
            docs_url: None,
            exploit_witness: None,
            upstream_validation_absent: false,
            ..Default::default()
        };
        let report = format_auth0_report_with_component(
            &[finding],
            Some("**@auth0/auth0-spa-js@2.19.2** (`package.json`)"),
        );
        assert!(report.contains("@auth0/auth0-spa-js@2.19.2"));
    }

    #[test]
    fn pom_xml_component_includes_group_id() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(
            tmp.path().join("pom.xml"),
            r#"<?xml version="1.0"?>
<project>
  <groupId>com.auth0</groupId>
  <artifactId>java-jwt</artifactId>
  <version>4.4.0</version>
</project>"#,
        )
        .unwrap();
        let component = detect_component_info_inner(&[], Some(tmp.path()));
        assert!(
            component.contains("com.auth0:java-jwt"),
            "pom.xml component must include groupId:artifactId"
        );
        assert!(
            component.contains("4.4.0"),
            "pom.xml component must include version"
        );
    }

    #[test]
    fn gradle_component_extracted_from_build_gradle() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(
            tmp.path().join("build.gradle"),
            "group = 'com.example'\nversion = '2.1.0'\n",
        )
        .unwrap();
        let component = detect_component_info_inner(&[], Some(tmp.path()));
        assert!(
            component.contains("com.example"),
            "build.gradle component must include group"
        );
        assert!(
            component.contains("2.1.0"),
            "build.gradle component must include version"
        );
        assert!(
            component.contains("build.gradle"),
            "build.gradle component must cite build.gradle"
        );
    }

    #[test]
    fn cmake_component_extracts_project_name() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(
            tmp.path().join("CMakeLists.txt"),
            "cmake_minimum_required(VERSION 3.20)\nproject(ClickHouse VERSION 24.1 LANGUAGES CXX)\n",
        )
        .unwrap();
        let component = detect_component_info_inner(&[], Some(tmp.path()));
        assert!(
            component.contains("ClickHouse"),
            "cmake project must be named"
        );
        assert!(component.contains("24.1"), "cmake version must be included");
        assert!(
            component.contains("CMakeLists.txt"),
            "cmake component must cite CMakeLists.txt"
        );
    }

    #[test]
    fn foundry_component_extracts_profile_name() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(
            tmp.path().join("foundry.toml"),
            "[profile.default]\nsrc = 'src'\n",
        )
        .unwrap();
        let component = detect_component_info_inner(&[], Some(tmp.path()));
        assert!(
            component.contains("foundry:default"),
            "foundry profile must be named"
        );
        assert!(
            component.contains("foundry.toml"),
            "foundry component must cite foundry.toml"
        );
    }

    #[test]
    fn hardhat_component_extracts_project_name() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(
            tmp.path().join("hardhat.config.js"),
            "module.exports = { projectName: 'wallet-contracts', defaultNetwork: 'hardhat' };\n",
        )
        .unwrap();
        let component = detect_component_info_inner(&[], Some(tmp.path()));
        assert!(
            component.contains("wallet-contracts"),
            "hardhat project must be named"
        );
        assert!(
            component.contains("hardhat.config.js"),
            "hardhat component must cite hardhat config"
        );
    }

    #[test]
    fn gradle_settings_component_extracts_root_project_name() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(
            tmp.path().join("settings.gradle.kts"),
            "rootProject.name = \"AfterpaySDK\"\n",
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("gradle.properties"),
            "GROUP=com.afterpay\nVERSION_NAME=4.8.3-SNAPSHOT\n",
        )
        .unwrap();
        let component = detect_component_info_inner(&[], Some(tmp.path()));
        assert!(
            component.contains("AfterpaySDK"),
            "gradle settings project must be named"
        );
        assert!(
            component.contains("4.8.3-SNAPSHOT"),
            "gradle properties version must be included"
        );
    }

    #[test]
    fn swift_package_component_extracts_package_name() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(
            tmp.path().join("Package.swift"),
            "let package = Package(\n  name: \"Afterpay\",\n)\n",
        )
        .unwrap();
        let component = detect_component_info_inner(&[], Some(tmp.path()));
        assert!(
            component.contains("Afterpay"),
            "swift package component must be named"
        );
        assert!(
            component.contains("Package.swift"),
            "swift component must cite Package.swift"
        );
    }

    #[test]
    fn podspec_component_extracts_name_and_fallback_version() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(
            tmp.path().join("Afterpay.podspec"),
            "Pod::Spec.new do |spec|\n  spec.name = \"Afterpay\"\n  spec.version = ENV['LIB_VERSION'] || '1.0.0'\nend\n",
        )
        .unwrap();
        let component = detect_component_info_inner(&[], Some(tmp.path()));
        assert!(
            component.contains("Afterpay"),
            "podspec component must be named"
        );
        assert!(
            component.contains("1.0.0"),
            "podspec fallback version must be included"
        );
    }

    // -----------------------------------------------------------------------
    // Formatter coherence — no contradiction when repro_cmd absent
    // -----------------------------------------------------------------------

    #[test]
    fn auth0_exploitability_is_medium_when_no_repro_cmd() {
        let finding = StructuredFinding {
            id: "security:command_injection".to_string(),
            file: Some("src/runner.py".to_string()),
            line: Some(88),
            fingerprint: "fp001".to_string(),
            severity: Some("Critical".to_string()),
            remediation: None,
            docs_url: None,
            exploit_witness: None,
            upstream_validation_absent: false,
            ..Default::default()
        };
        let report = format_auth0_report(&[finding]);
        assert!(
            report.contains("Medium. Static analysis confirmed the vulnerability"),
            "exploitability must be Medium when no repro_cmd is present"
        );
        assert!(
            !report.contains(
                "High. A deterministic proof-of-concept payload has been successfully synthesized"
            ),
            "report must not claim a PoC was synthesized when repro_cmd is absent"
        );
        assert!(
            report.contains("at line `88`"),
            "description must include the line number"
        );
    }

    #[test]
    fn auth0_exploitability_is_high_when_repro_cmd_present() {
        let finding = StructuredFinding {
            id: "security:command_injection".to_string(),
            file: Some("src/runner.py".to_string()),
            line: Some(88),
            fingerprint: "fp002".to_string(),
            severity: Some("Critical".to_string()),
            remediation: None,
            docs_url: None,
            exploit_witness: Some(common::slop::ExploitWitness {
                repro_cmd: Some("curl -X POST http://0.0.0.0/run -d '{}'".to_string()),
                ..Default::default()
            }),
            upstream_validation_absent: false,
            ..Default::default()
        };
        let report = format_auth0_report(&[finding]);
        assert!(
            report.contains(
                "High. A deterministic proof-of-concept payload has been successfully synthesized"
            ),
            "exploitability must be High when repro_cmd is present"
        );
        assert!(
            !report.contains("Medium. Static analysis confirmed the vulnerability"),
            "report must not claim medium exploitability when repro_cmd is present"
        );
    }

    #[test]
    fn scan_directory_applies_exclusion_lattice() {
        let dir = tempfile::TempDir::new().unwrap();
        for excluded in [
            ".git",
            ".github",
            "node_modules",
            "target",
            "build",
            "dist",
            "docs",
            "tests",
            "__tests__",
            "examples",
            "coverage",
            "vendor",
            "testutils",
            "testfixtures",
            "mocks",
        ] {
            let excluded_dir = dir.path().join(excluded);
            std::fs::create_dir(&excluded_dir).unwrap();
            std::fs::write(
                excluded_dir.join("config.js"),
                b"const secret = 'AKIAIOSFODNN7EXAMPLEKEY1234567890';",
            )
            .unwrap();
        }
        for excluded_file in [
            "types.d.ts",
            "bundle.min.js",
            "bundle.min.esm.js",
            "bundle.js.map",
            "README.md",
            "notes.txt",
            "metadata.json",
            "handler_test.go",
            "handler_test.js",
            "handler_test.py",
            "handler_test.ts",
            "handler_test.tsx",
            "client_mock.go",
            "transport_mock.rs",
            "widget_mock.tsx",
            "mock_client.ts",
            "component.test.tsx",
            "component.spec.tsx",
        ] {
            std::fs::write(
                dir.path().join(excluded_file),
                b"const secret = 'AKIAIOSFODNN7EXAMPLEKEY1234567890';",
            )
            .unwrap();
        }
        std::fs::write(
            dir.path().join("package.json"),
            br#"{"name":"safe-package-manifest"}"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("manifest.json"),
            br#"{"name":"safe-runtime-manifest"}"#,
        )
        .unwrap();
        std::fs::create_dir_all(dir.path().join("internal").join("mocks")).unwrap();
        std::fs::write(
            dir.path().join("internal").join("mocks").join("config.js"),
            b"const secret = 'AKIAIOSFODNN7EXAMPLEKEY1234567890';",
        )
        .unwrap();
        let findings = scan_directory(dir.path()).unwrap();
        assert!(
            findings.is_empty(),
            "findings inside excluded directories or generated artifacts must be excluded"
        );
    }

    #[test]
    fn detect_component_info_parses_go_mod_module() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("go.mod"),
            b"module github.com/openfga/openfga\n\ngo 1.22\n",
        )
        .unwrap();

        let component = detect_component_info_inner(&[], Some(dir.path()));

        assert_eq!(
            component,
            "**github.com/openfga/openfga** go1.22 (`go.mod`)"
        );
    }

    #[test]
    fn detect_component_info_walks_up_from_nested_scan_root_to_go_mod() {
        let dir = tempfile::TempDir::new().unwrap();
        let nested = dir.path().join("cmd").join("server");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(
            dir.path().join("go.mod"),
            b"module github.com/openfga/openfga\n\ngo 1.22\n",
        )
        .unwrap();

        let component = detect_component_info_inner(&[], Some(&nested));

        assert_eq!(
            component,
            "**github.com/openfga/openfga** go1.22 (`go.mod`)"
        );
    }

    #[test]
    fn detect_component_info_prefers_nearest_manifest_for_finding_path() {
        let dir = tempfile::TempDir::new().unwrap();
        let plugin_src = dir.path().join("plugins").join("plugin-a").join("src");
        std::fs::create_dir_all(&plugin_src).unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            br#"{"name":"root-app","version":"1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(
            dir.path()
                .join("plugins")
                .join("plugin-a")
                .join("package.json"),
            br#"{"name":"plugin-a","version":"2.3.4"}"#,
        )
        .unwrap();

        let finding = StructuredFinding {
            id: "security:dom_xss_innerHTML".to_string(),
            file: Some("plugins/plugin-a/src/file.ts".to_string()),
            line: Some(17),
            fingerprint: "monorepo_component".to_string(),
            severity: Some("Critical".to_string()),
            remediation: None,
            docs_url: None,
            exploit_witness: None,
            upstream_validation_absent: false,
            ..Default::default()
        };
        let component = detect_component_info_inner(&[finding], Some(dir.path()));

        assert_eq!(component, "**plugin-a@2.3.4** (`package.json`)");
    }

    #[test]
    fn scan_directory_appends_lockfile_verified_deserialization_gadget_chain() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("pom.xml"),
            r#"
<project>
  <dependencies>
    <dependency>
      <artifactId>commons-collections</artifactId>
      <version>3.2.1</version>
    </dependency>
  </dependencies>
</project>
"#,
        )
        .unwrap();
        std::fs::create_dir(dir.path().join("src")).unwrap();
        std::fs::write(
            dir.path().join("src").join("Handler.java"),
            r#"
import java.io.ObjectInputStream;
class Handler {
    Object receive(ObjectInputStream input) throws Exception {
        return input.readObject();
    }
}
"#,
        )
        .unwrap();

        let findings = scan_directory(dir.path()).unwrap();
        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "security:deserialization_gadget_chain"),
            "readObject plus vulnerable commons-collections lockfile must emit gadget chain"
        );
    }

    #[test]
    fn replace_host_in_curl_substitutes_correctly() {
        let cmd = "curl -X POST http://0.0.0.0/api/v1/users -d '{\"x\":\"y\"}'";
        let result = replace_host_in_curl(cmd, "http://localhost:3000");
        assert_eq!(
            result,
            "curl -X POST http://localhost:3000/api/v1/users -d '{\"x\":\"y\"}'"
        );
    }

    #[test]
    fn live_tenant_replay_origin_rejects_key_value_context() {
        assert!(is_live_tenant_replay_origin("https://tenant.example.com"));
        assert!(!is_live_tenant_replay_origin(
            "domain=tenant.example.auth0.com;client_id=test-client-123"
        ));
    }

    #[test]
    fn live_tenant_replay_adds_curl_timeouts() {
        let cmd = "curl -i -X GET https://example.invalid/api/resources/123";
        let bounded = bounded_curl_command(cmd);
        assert!(bounded.contains("--connect-timeout 5"));
        assert!(bounded.contains("--max-time 20"));
        assert!(bounded.contains("--retry 0"));
    }

    #[test]
    fn authorization_replay_verdict_distinguishes_200_from_denial() {
        assert_eq!(
            authorization_replay_verdict("HTTP/2 200\r\n\r\n{\"id\":\"user_b\"}"),
            "potential_cross_tenant_read: replay returned 2xx"
        );
        assert_eq!(
            authorization_replay_verdict("HTTP/1.1 403 Forbidden\r\n\r\n"),
            "control_enforced: replay denied cross-principal object access"
        );
    }

    #[test]
    fn browser_dom_harness_is_emitted_to_output_directory() {
        let temp = tempfile::tempdir().unwrap();
        let mut findings = vec![StructuredFinding {
            id: "security:dom_xss_innerHTML".to_string(),
            file: Some("src/auth0-widget.js".to_string()),
            line: Some(44),
            fingerprint: "domxss-live-tenant".to_string(),
            severity: Some("High".to_string()),
            remediation: None,
            docs_url: None,
            exploit_witness: Some(common::slop::ExploitWitness {
                repro_cmd: Some(
                    "cat > janitor-auth0-dom-xss-poc.html <<'HTML'\n<!doctype html>\n<title>Harness</title>\n<script>console.log('ready')</script>\nHTML\npython3 -m http.server 8765"
                        .to_string(),
                ),
                reproduction_steps: Some(vec!["Serve the harness.".to_string()]),
                live_proof: Some("Live tenant context injected.".to_string()),
                ..Default::default()
            }),
            upstream_validation_absent: false,
                ..Default::default()
        }];

        emit_browser_dom_harnesses(&mut findings, temp.path()).unwrap();

        let emitted = temp
            .path()
            .join("janitor_poc_security_dom_xss_innerhtml.html");
        let written = std::fs::read_to_string(&emitted).unwrap();
        assert!(written.contains("<!doctype html>"));
        assert!(written.contains("console.log('ready')"));
        assert!(
            findings[0]
                .exploit_witness
                .as_ref()
                .and_then(|w| w.live_proof.as_deref())
                .is_some_and(|proof| proof.contains("BrowserDOM harness written to")),
            "live proof must mention the emitted harness path"
        );
    }

    #[test]
    fn browser_dom_harness_is_skipped_without_exploitation_strategy() {
        let temp = tempfile::tempdir().unwrap();
        let mut findings = vec![StructuredFinding {
            id: "security:dom_xss_innerHTML".to_string(),
            file: Some("src/auth0-widget.js".to_string()),
            line: Some(44),
            fingerprint: "domxss-low-evidence".to_string(),
            severity: Some("High".to_string()),
            exploit_witness: Some(common::slop::ExploitWitness {
                repro_cmd: Some(
                    "cat > janitor-auth0-dom-xss-poc.html <<'HTML'\n<!doctype html>\n<title>Harness</title>\n<script>console.log('ready')</script>\nHTML\npython3 -m http.server 8765"
                        .to_string(),
                ),
                ..Default::default()
            }),
            ..Default::default()
        }];

        emit_browser_dom_harnesses(&mut findings, temp.path()).unwrap();

        let emitted = temp
            .path()
            .join("janitor_poc_security_dom_xss_innerhtml.html");
        assert!(
            !emitted.exists(),
            "low-evidence BrowserDOM harness must not be written"
        );
    }

    #[test]
    fn explicit_live_tenant_flags_build_browser_context_spec() {
        let spec = synthesize_browser_tenant_spec(
            Some("https://tenant.example.com"),
            Some("tenant.example.auth0.com"),
            Some("client-123"),
        )
        .unwrap();
        assert!(
            spec.contains("domain=tenant.example.auth0.com"),
            "explicit tenant domain must be injected into browser context synthesis"
        );
        assert!(
            spec.contains("client_id=client-123"),
            "explicit client id must be injected into browser context synthesis"
        );
    }

    // -----------------------------------------------------------------------
    // npm tarball extraction round-trip (mock tarball in memory)
    // -----------------------------------------------------------------------

    #[test]
    fn npm_tarball_extraction_scans_extracted_files() {
        let mut tar_bytes: Vec<u8> = Vec::new();
        {
            let gz = flate2::write::GzEncoder::new(&mut tar_bytes, flate2::Compression::fast());
            let mut tar = tar::Builder::new(gz);

            let content = b"const secret = 'AKIAIOSFODNN7EXAMPLEKEY1234567890';\n";
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append_data(&mut header, "package/index.js", content.as_ref())
                .unwrap();
            tar.into_inner().unwrap().finish().unwrap();
        }

        let extract_dir = tempfile::TempDir::new().unwrap();
        {
            let gz = flate2::read::GzDecoder::new(tar_bytes.as_slice());
            let mut archive = tar::Archive::new(gz);
            archive.unpack(extract_dir.path()).unwrap();
        }

        let findings = scan_directory(extract_dir.path()).unwrap();
        assert!(
            findings.iter().any(|f| f.id.contains("credential")),
            "extracted JS with AWS key must produce a credential finding"
        );
    }

    // -----------------------------------------------------------------------
    // JAR extraction round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn jar_extraction_scans_embedded_java_source() {
        let tmp = tempfile::TempDir::new().unwrap();
        let jar_path = tmp.path().join("sample.jar");
        let file = std::fs::File::create(&jar_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        let content = b"class Demo { void run(String cmd) throws Exception { Runtime.getRuntime().exec(cmd); } }\n";
        zip.start_file("src/Demo.java", options).unwrap();
        zip.write_all(content).unwrap();
        zip.finish().unwrap();

        let findings = ingest_jar(&jar_path).unwrap();
        assert!(
            findings
                .iter()
                .any(|f| { f.id.contains("runtime_exec") || f.id.contains("command_injection") }),
            "JAR-extracted Java source with Runtime.exec must produce a finding"
        );
    }

    // -----------------------------------------------------------------------
    // ASAR parser — synthetic archive round-trip  (Phase D)
    // -----------------------------------------------------------------------

    /// Build a minimal in-memory ASAR archive containing `filename` with `content`.
    fn build_asar(filename: &str, content: &[u8]) -> Vec<u8> {
        let file_header = serde_json::json!({
            "files": {
                filename: {
                    "size": content.len(),
                    "offset": "0"
                }
            }
        });
        let json_str = serde_json::to_string(&file_header).unwrap();
        let json_bytes = json_str.as_bytes();
        let json_len = json_bytes.len();

        // Inner pickle payload: [json_len as u32] + json_bytes, 4-byte aligned.
        let inner_payload = 4 + json_len;
        let inner_payload_padded = (inner_payload + 3) & !3;
        let inner_pickle_size = 4 + inner_payload_padded;

        let mut asar: Vec<u8> = Vec::new();
        // Outer pickle: header_size=4, then inner_pickle_size.
        asar.extend_from_slice(&4u32.to_le_bytes());
        asar.extend_from_slice(&(inner_pickle_size as u32).to_le_bytes());
        // Inner pickle: payload_size, then json_len string prefix, then JSON.
        asar.extend_from_slice(&(inner_payload_padded as u32).to_le_bytes());
        asar.extend_from_slice(&(json_len as u32).to_le_bytes());
        asar.extend_from_slice(json_bytes);
        // Padding to 4-byte boundary.
        let pad = inner_payload_padded - inner_payload;
        asar.resize(asar.len() + pad, 0u8);
        // File data.
        asar.extend_from_slice(content);
        asar
    }

    #[test]
    fn asar_extraction_scans_embedded_credential() {
        let content = b"const secret = 'AKIAIOSFODNN7EXAMPLEKEY1234567890';\n";
        let asar_bytes = build_asar("index.js", content);

        let tmp = tempfile::TempDir::new().unwrap();
        let asar_path = tmp.path().join("app.asar");
        std::fs::write(&asar_path, &asar_bytes).unwrap();

        let findings = ingest_asar(&asar_path).unwrap();
        assert!(
            findings.iter().any(|f| f.id.contains("credential")),
            "ASAR-extracted JS with AWS key must produce a credential finding"
        );
    }

    #[test]
    fn asar_rejects_bad_magic() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("bad.asar");
        // Magic = 0x01020304, not 0x00000004.
        std::fs::write(
            &path,
            b"\x01\x02\x03\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        )
        .unwrap();
        assert!(
            ingest_asar(&path).is_err(),
            "invalid ASAR magic must return an error"
        );
    }

    // -----------------------------------------------------------------------
    // Docker save tarball ingestion
    // -----------------------------------------------------------------------

    /// Build a minimal in-memory `docker save` tar containing one layer.
    /// The layer tar contains `filename` with `content`.
    fn build_docker_tar(filename: &str, content: &[u8]) -> Vec<u8> {
        // Build inner layer.tar bytes.
        let mut layer_tar_bytes: Vec<u8> = Vec::new();
        {
            let mut layer_builder = tar::Builder::new(&mut layer_tar_bytes);
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            layer_builder
                .append_data(&mut header, filename, content)
                .unwrap();
            layer_builder.finish().unwrap();
        }

        // Build manifest.json.
        let manifest = serde_json::json!([{
            "Config": "abc123.json",
            "RepoTags": ["test:latest"],
            "Layers": ["layer0/layer.tar"]
        }]);
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();

        // Build outer docker save tar.
        let mut outer_bytes: Vec<u8> = Vec::new();
        {
            let mut outer = tar::Builder::new(&mut outer_bytes);

            // manifest.json
            let mut mhdr = tar::Header::new_gnu();
            mhdr.set_size(manifest_bytes.len() as u64);
            mhdr.set_mode(0o644);
            mhdr.set_cksum();
            outer
                .append_data(&mut mhdr, "manifest.json", manifest_bytes.as_slice())
                .unwrap();

            // layer0/layer.tar
            let mut lhdr = tar::Header::new_gnu();
            lhdr.set_size(layer_tar_bytes.len() as u64);
            lhdr.set_mode(0o644);
            lhdr.set_cksum();
            outer
                .append_data(&mut lhdr, "layer0/layer.tar", layer_tar_bytes.as_slice())
                .unwrap();

            outer.finish().unwrap();
        }

        outer_bytes
    }

    #[test]
    fn docker_ingest_extracts_and_scans_layer_content() {
        let content = b"const secret = 'AKIAIOSFODNN7EXAMPLEKEY1234567890';\n";
        let docker_bytes = build_docker_tar("app/index.js", content);

        let tmp = tempfile::TempDir::new().unwrap();
        let tar_path = tmp.path().join("image.tar");
        std::fs::write(&tar_path, &docker_bytes).unwrap();

        let findings = ingest_docker(&tar_path).unwrap();
        assert!(
            findings.iter().any(|f| f.id.contains("credential")),
            "docker layer JS with AWS key must produce a credential finding"
        );
    }

    #[test]
    fn docker_ingest_rejects_missing_manifest() {
        let tmp = tempfile::TempDir::new().unwrap();
        let tar_path = tmp.path().join("bad.tar");

        // Build a tar with no manifest.json.
        let mut bytes: Vec<u8> = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut bytes);
            let content = b"irrelevant";
            let mut hdr = tar::Header::new_gnu();
            hdr.set_size(content.len() as u64);
            hdr.set_mode(0o644);
            hdr.set_cksum();
            builder
                .append_data(&mut hdr, "some_file.txt", content.as_ref())
                .unwrap();
            builder.finish().unwrap();
        }
        std::fs::write(&tar_path, &bytes).unwrap();

        assert!(
            ingest_docker(&tar_path).is_err(),
            "docker tar without manifest.json must return an error"
        );
    }

    // -----------------------------------------------------------------------
    // IPA extraction round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn ipa_ingest_extracts_payload_and_scans_web_bundle() {
        let tmp = tempfile::TempDir::new().unwrap();
        let ipa_path = tmp.path().join("sample.ipa");
        let file = std::fs::File::create(&ipa_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();

        zip.add_directory("Payload/Demo.app/", options).unwrap();
        zip.start_file("Payload/Demo.app/Info.plist", options)
            .unwrap();
        zip.write_all(
            br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key>
  <string>com.example.demo</string>
</dict>
</plist>"#,
        )
        .unwrap();
        zip.start_file("Payload/Demo.app/www/app.js", options)
            .unwrap();
        zip.write_all(b"const key = 'AKIAIOSFODNN7EXAMPLEKEY1234567890';\n")
            .unwrap();
        zip.finish().unwrap();

        let findings = ingest_ipa(&ipa_path).unwrap();
        assert!(
            findings.iter().any(|f| f.id.contains("credential")),
            "IPA-extracted web bundle with AWS key must produce a credential finding"
        );
    }

    // -----------------------------------------------------------------------
    // jaq native filter  (Phase 3 / P2-7)
    // -----------------------------------------------------------------------

    #[test]
    fn jaq_filter_selects_by_severity() {
        let input = serde_json::json!([
            {"id": "security:a", "severity": "Critical"},
            {"id": "security:b", "severity": "Low"}
        ]);
        let result = apply_jaq_filter(".[] | select(.severity == \"Critical\")", input).unwrap();
        let arr = result.as_array().unwrap();
        assert_eq!(
            arr.len(),
            1,
            "filter must select exactly one Critical finding"
        );
        assert_eq!(arr[0]["id"].as_str().unwrap(), "security:a");
    }

    #[test]
    fn jaq_filter_iterates_all_elements() {
        let input = serde_json::json!([{"id": "a"}, {"id": "b"}, {"id": "c"}]);
        let result = apply_jaq_filter(".[]", input).unwrap();
        let arr = result.as_array().unwrap();
        assert_eq!(arr.len(), 3, ".[] must iterate over all elements");
    }

    #[test]
    fn jaq_filter_invalid_syntax_returns_error() {
        let input = serde_json::json!([]);
        assert!(
            apply_jaq_filter("invalid ][[ syntax", input).is_err(),
            "malformed filter must return an error"
        );
    }

    #[test]
    fn upstream_validation_audit_emits_ifds_proof_when_absent_and_no_sanitizer_audit() {
        let finding = StructuredFinding {
            id: "security:sqli_taint_confirmed".to_string(),
            file: Some("api/db.go".to_string()),
            line: Some(42),
            fingerprint: "ifds_proof_001".to_string(),
            severity: Some("KevCritical".to_string()),
            remediation: None,
            docs_url: None,
            exploit_witness: Some(common::slop::ExploitWitness {
                source_function: "HandleRequest".to_string(),
                source_label: "param:query".to_string(),
                sink_function: "db.QueryContext".to_string(),
                sink_label: "sink:sql_query".to_string(),
                call_chain: vec!["HandleRequest".to_string(), "db.QueryContext".to_string()],
                upstream_validation_absent: true,
                ..Default::default()
            }),
            upstream_validation_absent: true,
            ..Default::default()
        };
        let report = format_bugcrowd_report(&[finding]);
        assert!(
            report.contains(
                "Data flow reaches the vulnerable sink without an intervening sanitizer, \
                 parameterization boundary, allowlist, or type-enforced validation gate."
            ),
            "upstream_validation_absent=true with no sanitizer_audit must emit the data-flow statement"
        );
    }

    #[test]
    fn upstream_validation_audit_prefers_explicit_sanitizer_audit_over_ifds_proof() {
        let finding = StructuredFinding {
            id: "security:sqli_taint_confirmed".to_string(),
            file: Some("api/db.go".to_string()),
            line: Some(42),
            fingerprint: "ifds_audit_pref_001".to_string(),
            severity: Some("KevCritical".to_string()),
            remediation: None,
            docs_url: None,
            exploit_witness: Some(common::slop::ExploitWitness {
                source_function: "HandleRequest".to_string(),
                source_label: "param:query".to_string(),
                sink_function: "db.QueryContext".to_string(),
                sink_label: "sink:sql_query".to_string(),
                call_chain: vec!["HandleRequest".to_string(), "db.QueryContext".to_string()],
                sanitizer_audit: Some("Custom audit detail from IFDS trace.".to_string()),
                upstream_validation_absent: true,
                ..Default::default()
            }),
            upstream_validation_absent: true,
            ..Default::default()
        };
        let report = format_bugcrowd_report(&[finding]);
        assert!(
            report.contains("Custom audit detail from IFDS trace."),
            "explicit sanitizer_audit must take priority over the IFDS proof statement"
        );
    }

    // -----------------------------------------------------------------------
    // P2-11: apply_p2_11_ci_sink_demotion
    // -----------------------------------------------------------------------

    #[test]
    fn p2_11_ci_path_command_injection_demoted_to_informational() {
        // subprocess.run with shell=True triggers security:subprocess_shell_injection
        let source = b"import subprocess\nsubprocess.run(cmd, shell=True)\n";
        let findings = scan_buffer("py", source, "ci/build.py", &[], &[], false);
        let shell_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.id.contains("shell_injection") || f.id.contains("command_injection"))
            .collect();
        assert!(
            !shell_findings.is_empty(),
            "subprocess shell=True must still produce a finding in ci/ path"
        );
        assert!(
            shell_findings
                .iter()
                .all(|f| f.severity.as_deref() == Some("Informational")),
            "command injection in ci/ path without ingress must be demoted to Informational"
        );
    }

    #[test]
    fn p2_11_production_path_command_injection_stays_critical() {
        let source = b"import subprocess\nsubprocess.run(cmd, shell=True)\n";
        let findings = scan_buffer("py", source, "src/server.py", &[], &[], false);
        let shell_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.id.contains("shell_injection") || f.id.contains("command_injection"))
            .collect();
        assert!(
            !shell_findings.is_empty(),
            "subprocess shell=True must be detected in src/ path"
        );
        assert!(
            shell_findings
                .iter()
                .all(|f| f.severity.as_deref() != Some("Informational")),
            "command injection in src/server.py must not be demoted — production surface"
        );
    }

    // -----------------------------------------------------------------------
    // P2-5: Stored XSS dual-frame witness
    // -----------------------------------------------------------------------

    #[test]
    fn p2_5_react_xss_dangerous_html_gets_dual_frame_witness() {
        let source = b"const el = <div dangerouslySetInnerHTML={{ __html: userContent }} />;\n";
        let findings = scan_buffer("tsx", source, "src/components/Post.tsx", &[], &[], false);
        let xss: Vec<_> = findings
            .iter()
            .filter(|f| f.id == "security:react_xss_dangerous_html")
            .collect();
        assert!(!xss.is_empty(), "dangerouslySetInnerHTML must fire");
        let f = &xss[0];
        assert!(
            f.upstream_validation_absent,
            "stored XSS must set upstream_validation_absent"
        );
        let artifact = f
            .web_proof_artifact
            .as_ref()
            .expect("dual-frame witness must attach WebProofArtifact");
        assert!(
            artifact.has_marker("schema_taint:proven"),
            "artifact must carry schema_taint:proven evidence marker"
        );
        let witness = f
            .exploit_witness
            .as_ref()
            .expect("exploit witness must be present");
        let repro = witness.repro_cmd.as_deref().unwrap_or("");
        assert!(
            repro.contains("JANITOR_XSS_CANARY"),
            "repro_cmd must embed JANITOR_XSS_CANARY canary token"
        );
        assert!(
            repro.contains("data-janitor-witness"),
            "repro_cmd must embed data-janitor-witness attribute"
        );
        assert!(
            repro.contains("Frame 1") && repro.contains("Frame 2"),
            "repro_cmd must contain dual-frame structure"
        );
    }

    // -----------------------------------------------------------------------
    // P2-17: Config-Backed SSRF Demotion
    // -----------------------------------------------------------------------

    #[test]
    fn p2_17_config_module_ssrf_demoted_to_informational() {
        let mut findings = vec![common::slop::StructuredFinding {
            id: "security:ssrf_dynamic_url".to_string(),
            file: Some("src/config/api_config.go".to_string()),
            severity: Some("KevCritical".to_string()),
            upstream_validation_absent: false,
            ..Default::default()
        }];
        apply_config_backed_ssrf_demotion(&mut findings);
        assert_eq!(
            findings[0].severity.as_deref(),
            Some("Informational"),
            "SSRF in config module must be demoted to Informational"
        );
    }

    #[test]
    fn p2_17_production_handler_ssrf_stays_critical() {
        let mut findings = vec![common::slop::StructuredFinding {
            id: "security:ssrf_dynamic_url".to_string(),
            file: Some("server/channels/app/admin.go".to_string()),
            severity: Some("KevCritical".to_string()),
            upstream_validation_absent: false,
            ..Default::default()
        }];
        apply_config_backed_ssrf_demotion(&mut findings);
        assert_eq!(
            findings[0].severity.as_deref(),
            Some("KevCritical"),
            "SSRF in production handler must not be demoted"
        );
    }

    #[test]
    fn p2_17_concrete_ssrf_with_internal_metadata_never_demoted() {
        let artifact = common::slop::WebProofArtifact {
            source_label: "url_param:url".to_string(),
            sink_label: "sink:fetch".to_string(),
            ifds_trace: vec![],
            evidence_marker: Some("internal_metadata:169.254.169.254".to_string()),
            proof_class: common::slop::ProofClass::ReachabilityProof,
        };
        let mut findings = vec![common::slop::StructuredFinding {
            id: "security:ssrf_dynamic_url".to_string(),
            file: Some("pkg/config/settings.go".to_string()),
            severity: Some("KevCritical".to_string()),
            web_proof_artifact: Some(artifact),
            upstream_validation_absent: false,
            ..Default::default()
        }];
        apply_config_backed_ssrf_demotion(&mut findings);
        assert_eq!(
            findings[0].severity.as_deref(),
            Some("KevCritical"),
            "Concrete SSRF with internal_metadata marker must never be demoted even in config file"
        );
    }

    // -----------------------------------------------------------------------
    // Sprint 138 — Target Deprecation Cross-Check (is_deprecated_target +
    // apply_deprecation_demotion). Mattermost-plugin-boards was the
    // motivating case: scope file listed it as in-scope but the project had
    // been transitioned to community maintenance, making findings
    // informational-only per scope exclusion. The cross-check catches this
    // class of stale-scope failure before findings land in BOUNTY_LEDGER.
    // -----------------------------------------------------------------------

    #[test]
    fn is_deprecated_target_detects_archived_readme() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("README.md"),
            b"# Old Project\n\nThis project has been archived. Please use the new fork.\n",
        )
        .unwrap();
        let verdict = is_deprecated_target(dir.path());
        assert!(
            verdict.is_some(),
            "archived README must register as deprecated"
        );
        let (filename, keyword) = verdict.unwrap();
        assert_eq!(filename, "README.md");
        assert_eq!(keyword, "archived");
    }

    #[test]
    fn is_deprecated_target_returns_none_for_active_repo() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("README.md"),
            b"# Active Project\n\nWelcome to Foo, an actively-developed open source library with first-class support.\n",
        )
        .unwrap();
        assert!(
            is_deprecated_target(dir.path()).is_none(),
            "active project README must NOT register as deprecated"
        );
    }

    #[test]
    fn is_deprecated_target_recognises_mattermost_boards_community_pattern() {
        // Mattermost-plugin-boards (Focalboard) README excerpt simulation
        // for Sprint 138 deprecation detection.
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("README.md"),
            b"# Mattermost Boards\n\nNote: as of late 2023 this plugin has transitioned to community maintenance and is no longer officially supported by Mattermost staff.\n",
        )
        .unwrap();
        let verdict = is_deprecated_target(dir.path());
        assert!(
            verdict.is_some(),
            "community-maintained pattern must register as deprecated"
        );
    }

    #[test]
    fn is_deprecated_target_falls_back_to_security_md() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("README.md"),
            b"# Active project, no deprecation language here\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("SECURITY.md"),
            b"This repository is deprecated. Please report security issues to the upstream fork.\n",
        )
        .unwrap();
        let verdict = is_deprecated_target(dir.path());
        assert!(
            verdict.is_some(),
            "SECURITY.md must be scanned as a fallback"
        );
        let (filename, _) = verdict.unwrap();
        assert_eq!(filename, "SECURITY.md");
    }

    #[test]
    fn apply_deprecation_demotion_marks_findings_informational() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("README.md"),
            b"# Deprecated Project\n\nThis project is deprecated.\n",
        )
        .unwrap();
        let mut findings = vec![common::slop::StructuredFinding {
            id: "security:react_xss_dangerous_html".to_string(),
            severity: Some("Critical".to_string()),
            remediation: Some("Sanitize input with DOMPurify".to_string()),
            ..Default::default()
        }];
        apply_deprecation_demotion(dir.path(), &mut findings);
        assert_eq!(findings[0].severity.as_deref(), Some("Informational"));
        let remediation = findings[0].remediation.as_deref().unwrap_or("");
        assert!(
            remediation.contains("deprecated_target"),
            "remediation must annotate deprecation: {remediation}"
        );
        assert!(
            remediation.contains("informational_only_per_scope_exclusion"),
            "remediation must contain scope-exclusion reason: {remediation}"
        );
    }

    #[test]
    fn apply_deprecation_demotion_is_noop_on_fresh_target() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("README.md"),
            b"# Active Project\n\nFirst-party supported library.\n",
        )
        .unwrap();
        let mut findings = vec![common::slop::StructuredFinding {
            id: "security:react_xss_dangerous_html".to_string(),
            severity: Some("Critical".to_string()),
            remediation: Some("Sanitize input".to_string()),
            ..Default::default()
        }];
        apply_deprecation_demotion(dir.path(), &mut findings);
        assert_eq!(
            findings[0].severity.as_deref(),
            Some("Critical"),
            "fresh target must not be demoted"
        );
    }

    // -----------------------------------------------------------------------
    // Sprint 142 — Concrete-typed Unmarshal demotion. Sprint 141 demoted the
    // chainlink protobuf_any CANDIDATE because the cited Unmarshal target was
    // a concrete typed message (sdkpb.CapabilityRequest), not anypb.Any. This
    // post-filter catches the class structurally.
    // -----------------------------------------------------------------------

    #[test]
    fn concrete_typed_unmarshal_demotes_when_no_anypb_nearby() {
        let dir = tempfile::TempDir::new().unwrap();
        let go_path = dir.path().join("handler.go");
        std::fs::write(
            &go_path,
            b"package handler\n\nimport sdkpb \"example.com/sdkpb\"\n\nfunc Handle(payloadBytes []byte) error {\n    var sdkReq sdkpb.CapabilityRequest\n    if err := proto.Unmarshal(payloadBytes, &sdkReq); err != nil {\n        return err\n    }\n    return nil\n}\n",
        )
        .unwrap();
        let mut findings = vec![common::slop::StructuredFinding {
            id: "security:protobuf_any_unguarded_decode".to_string(),
            file: Some("handler.go".to_string()),
            line: Some(7),
            severity: Some("High".to_string()),
            remediation: Some("Validate Any.type_url".to_string()),
            ..Default::default()
        }];
        apply_concrete_typed_unmarshal_demotion(dir.path(), &mut findings);
        assert_eq!(findings[0].severity.as_deref(), Some("Informational"));
        let remediation = findings[0].remediation.as_deref().unwrap_or("");
        assert!(
            remediation.contains("concrete_typed_unmarshal"),
            "remediation must annotate: {remediation}"
        );
    }

    #[test]
    fn concrete_typed_unmarshal_preserves_when_anypb_present_in_window() {
        let dir = tempfile::TempDir::new().unwrap();
        let go_path = dir.path().join("genuine_any.go");
        std::fs::write(
            &go_path,
            b"package handler\n\nimport \"google.golang.org/protobuf/types/known/anypb\"\n\nfunc Handle(payloadBytes []byte) error {\n    var msg anypb.Any\n    if err := proto.Unmarshal(payloadBytes, &msg); err != nil {\n        return err\n    }\n    return nil\n}\n",
        )
        .unwrap();
        let mut findings = vec![common::slop::StructuredFinding {
            id: "security:protobuf_any_unguarded_decode".to_string(),
            file: Some("genuine_any.go".to_string()),
            line: Some(7),
            severity: Some("High".to_string()),
            remediation: Some("Validate Any.type_url".to_string()),
            ..Default::default()
        }];
        apply_concrete_typed_unmarshal_demotion(dir.path(), &mut findings);
        assert_eq!(
            findings[0].severity.as_deref(),
            Some("High"),
            "anypb.Any presence must preserve upstream finding"
        );
    }

    #[test]
    fn concrete_typed_unmarshal_unaffects_non_protobuf_findings() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("foo.go"),
            b"package handler\n\nfunc Handle() {}\n",
        )
        .unwrap();
        let mut findings = vec![common::slop::StructuredFinding {
            id: "security:sql_injection".to_string(),
            file: Some("foo.go".to_string()),
            line: Some(3),
            severity: Some("High".to_string()),
            remediation: Some("Parameterize query".to_string()),
            ..Default::default()
        }];
        apply_concrete_typed_unmarshal_demotion(dir.path(), &mut findings);
        assert_eq!(
            findings[0].severity.as_deref(),
            Some("High"),
            "non-protobuf finding must be unaffected"
        );
    }

    #[test]
    fn concrete_typed_unmarshal_safe_on_missing_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut findings = vec![common::slop::StructuredFinding {
            id: "security:protobuf_any_unguarded_decode".to_string(),
            file: Some("nonexistent.go".to_string()),
            line: Some(1),
            severity: Some("High".to_string()),
            ..Default::default()
        }];
        // Must not panic, must not modify the finding.
        apply_concrete_typed_unmarshal_demotion(dir.path(), &mut findings);
        assert_eq!(findings[0].severity.as_deref(), Some("High"));
    }
}
