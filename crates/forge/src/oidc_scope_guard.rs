//! P2-28 GitHub Actions OIDC Scope Abuse & Cache Poisoning Detector.
//!
//! Detects GitHub Actions workflows that grant `permissions: id-token: write` without
//! scoping an OIDC audience, combined with an unpinned `actions/cache` restore step.
//! The Mini Shai-Hulud worm (CVE-2026-45321) exploited this exact chain to extract
//! short-lived npm publish tokens from Actions runners.
//!
//! # Detection model
//!
//! 1. **OIDC write sink**: `id-token: write` or `id-token:write` in a workflow file.
//! 2. **Audience suppressor**: within ±10 lines, any of `audience:`, `issuer:`,
//!    `subject:` must appear to indicate a scoped OIDC token request.
//! 3. If `id-token: write` appears without a suppressor → emit
//!    `security:oidc_scope_abuse` at KevCritical.
//!
//! Additionally:
//! 4. **Unpinned cache sink**: `actions/cache@v` / `@main` / `@master` (not a 40-char SHA).
//! 5. If an unpinned cache restore step is found → emit `security:unpinned_cache_restore`
//!    at High.
//!
//! # Kani predicate
//!
//! `oidc_scope_missing_audience(has_write_permission, has_audience_scope)` is a pure
//! boolean predicate suitable for formal verification. The Kani harness in
//! `reflexive_assurance.rs` proves it is an exact conjunction.

use aho_corasick::{AhoCorasick, MatchKind};
use common::slop::StructuredFinding;

// ── Pattern tables ────────────────────────────────────────────────────────────

const OIDC_WRITE_SINKS: &[&str] = &["id-token: write", "id-token:write"];

const OIDC_SUPPRESSORS: &[&str] = &["audience:", "issuer:", "subject:"];

const UNPINNED_CACHE_SINKS: &[&str] = &[
    "actions/cache@v",
    "actions/cache@main",
    "actions/cache@master",
];

// ── Pure predicate (Kani-provable) ────────────────────────────────────────────

/// Returns `true` when an OIDC write permission is present without an audience
/// suppressor — the core OIDC scope-abuse invariant.
///
/// Extracted as a pure predicate so `reflexive_assurance.rs` can prove it is an
/// exact conjunction under all possible boolean inputs.
pub fn oidc_scope_missing_audience(has_write_permission: bool, has_audience_scope: bool) -> bool {
    has_write_permission && !has_audience_scope
}

// ── SHA-pin check ─────────────────────────────────────────────────────────────

/// Returns `true` if `line` contains `actions/cache@` followed immediately by a
/// 40-character lowercase hex commit SHA — a fully pinned cache reference.
fn is_sha_pinned_cache(line: &str) -> bool {
    let needle = "actions/cache@";
    if let Some(pos) = line.find(needle) {
        let rest = &line[pos + needle.len()..];
        // Take up to 40 chars; all must be lowercase hex.
        let sha_part: &str = rest.split_whitespace().next().unwrap_or("");
        sha_part.len() == 40 && sha_part.chars().all(|c| c.is_ascii_hexdigit())
    } else {
        false
    }
}

// ── Source scanners ───────────────────────────────────────────────────────────

/// Scan `source` for unscoped OIDC write permissions. Returns 1-indexed line
/// numbers where `id-token: write` appears without an audience suppressor within
/// ±10 lines.
fn find_unscoped_oidc_write(source: &str, window: usize) -> Vec<u32> {
    let sink_ac = AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostFirst)
        .build(OIDC_WRITE_SINKS)
        .expect("static OIDC_WRITE_SINKS patterns are valid");

    let suppressor_ac = AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostFirst)
        .build(OIDC_SUPPRESSORS)
        .expect("static OIDC_SUPPRESSORS patterns are valid");

    let lines: Vec<&str> = source.lines().collect();
    let mut hits: Vec<u32> = Vec::new();

    for (line_idx, line) in lines.iter().enumerate() {
        if sink_ac.find(line.as_bytes()).is_none() {
            continue;
        }

        let lo = line_idx.saturating_sub(window);
        let hi = (line_idx + window + 1).min(lines.len());
        let window_text = lines[lo..hi].join("\n");

        if suppressor_ac.find(window_text.as_bytes()).is_none() {
            hits.push((line_idx + 1) as u32);
        }
    }

    hits
}

/// Scan `source` for unpinned `actions/cache` restore steps (not SHA-pinned).
/// Returns 1-indexed line numbers where an unpinned cache reference occurs.
fn find_unpinned_cache_restores(source: &str) -> Vec<u32> {
    let sink_ac = AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostFirst)
        .build(UNPINNED_CACHE_SINKS)
        .expect("static UNPINNED_CACHE_SINKS patterns are valid");

    source
        .lines()
        .enumerate()
        .filter(|(_, line)| sink_ac.find(line.as_bytes()).is_some() && !is_sha_pinned_cache(line))
        .map(|(idx, _)| (idx + 1) as u32)
        .collect()
}

// ── Public emitter ────────────────────────────────────────────────────────────

/// Emit OIDC scope abuse and unpinned cache restore findings for the given
/// workflow source. `file` labels the finding path.
///
/// Only runs on `.github/workflows/` files — the `file` argument is checked for
/// this path prefix to avoid false positives on non-workflow YAML.
pub fn emit_oidc_scope_findings(source: &str, file: &str) -> Vec<StructuredFinding> {
    let normalized = file.replace('\\', "/");
    if !normalized.contains(".github/workflows/") {
        return Vec::new();
    }

    let mut findings: Vec<StructuredFinding> = Vec::new();

    for line_no in find_unscoped_oidc_write(source, 10) {
        findings.push(StructuredFinding {
            id: "security:oidc_scope_abuse".into(),
            severity: Some("KevCritical".into()),
            file: Some(file.to_string()),
            line: Some(line_no),
            remediation: Some(
                "Scope the OIDC token request by adding `audience:`, `issuer:`, or `subject:` \
                 restrictions within the workflow step that uses `id-token: write`. Unscoped \
                 OIDC tokens allow any workflow step to mint publish credentials \
                 (CVE-2026-45321)."
                    .into(),
            ),
            regulatory_regimes: Some(vec!["ISO-27001-A.12.6".into(), "SLSA-L3".into()]),
            ..Default::default()
        });
    }

    for line_no in find_unpinned_cache_restores(source) {
        findings.push(StructuredFinding {
            id: "security:unpinned_cache_restore".into(),
            severity: Some("High".into()),
            file: Some(file.to_string()),
            line: Some(line_no),
            remediation: Some(
                "Pin `actions/cache` to a full 40-character commit SHA \
                 (e.g., `actions/cache@a8976f...`) to prevent cache-poisoning attacks \
                 that can inject malicious steps into the workflow runner."
                    .into(),
            ),
            regulatory_regimes: Some(vec!["SLSA-L2".into()]),
            ..Default::default()
        });
    }

    findings
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── SHA-pin helper ──────────────────────────────────────────────────────

    #[test]
    fn sha_pin_40_char_hex_accepted() {
        // 27d5ce7f107fe9357f9df03efb73ab90386fccae is exactly 40 hex chars
        assert!(is_sha_pinned_cache(
            "uses: actions/cache@27d5ce7f107fe9357f9df03efb73ab90386fccae # v5.0.5"
        ));
    }

    #[test]
    fn sha_pin_semver_not_accepted() {
        assert!(!is_sha_pinned_cache("uses: actions/cache@v3"));
    }

    // ── Pure predicate ──────────────────────────────────────────────────────

    #[test]
    fn predicate_fires_only_on_write_without_audience() {
        assert!(oidc_scope_missing_audience(true, false));
        assert!(!oidc_scope_missing_audience(true, true));
        assert!(!oidc_scope_missing_audience(false, false));
        assert!(!oidc_scope_missing_audience(false, true));
    }

    // ── TP: id-token:write + unpinned cache → fires both findings ────────────

    #[test]
    fn tp_oidc_write_with_unpinned_cache() {
        let src = r#"
permissions:
  id-token: write
  contents: read
steps:
  - uses: actions/cache@v3
    with:
      path: ~/.cargo
      key: cargo-${{ hashFiles('**/Cargo.lock') }}
"#;
        let findings = emit_oidc_scope_findings(src, ".github/workflows/release.yml");
        let oidc: Vec<_> = findings
            .iter()
            .filter(|f| f.id == "security:oidc_scope_abuse")
            .collect();
        let cache: Vec<_> = findings
            .iter()
            .filter(|f| f.id == "security:unpinned_cache_restore")
            .collect();
        assert!(
            !oidc.is_empty(),
            "id-token: write without audience must fire"
        );
        assert!(
            !cache.is_empty(),
            "actions/cache@v3 must fire unpinned_cache_restore"
        );
    }

    // ── TN: SHA-pinned cache must not fire unpinned_cache_restore ────────────

    #[test]
    fn tn_sha_pinned_cache_no_finding() {
        let src = r#"
steps:
  - uses: actions/cache@27d5ce7f107fe9357f9df03efb73ab90386fccae # v5.0.5
    with:
      path: ~/.cargo
      key: cargo-${{ hashFiles('**/Cargo.lock') }}
"#;
        let findings = emit_oidc_scope_findings(src, ".github/workflows/ci.yml");
        let cache: Vec<_> = findings
            .iter()
            .filter(|f| f.id == "security:unpinned_cache_restore")
            .collect();
        assert!(cache.is_empty(), "SHA-pinned cache must not fire");
    }

    // ── TN: audience scoped → oidc_scope_abuse must not fire ─────────────────

    #[test]
    fn tn_audience_scoped_oidc_no_finding() {
        let src = r#"
permissions:
  id-token: write
steps:
  - name: Get token
    uses: actions/github-script@v6
    with:
      audience: sigstore
      script: core.getIDToken('sigstore')
"#;
        let findings = emit_oidc_scope_findings(src, ".github/workflows/sign.yml");
        let oidc: Vec<_> = findings
            .iter()
            .filter(|f| f.id == "security:oidc_scope_abuse")
            .collect();
        assert!(
            oidc.is_empty(),
            "audience: within window must suppress oidc_scope_abuse"
        );
    }

    // ── TP: actions/cache@main fires ─────────────────────────────────────────

    #[test]
    fn tp_cache_main_unpinned() {
        let src = "      - uses: actions/cache@main\n";
        let findings = emit_oidc_scope_findings(src, ".github/workflows/build.yml");
        assert!(
            findings
                .iter()
                .any(|f| f.id == "security:unpinned_cache_restore"),
            "actions/cache@main must fire"
        );
    }

    // ── TN: non-workflow file must not produce findings ───────────────────────

    #[test]
    fn tn_non_workflow_file_ignored() {
        let src = "id-token: write\n";
        let findings = emit_oidc_scope_findings(src, "config/settings.yaml");
        assert!(
            findings.is_empty(),
            "non-workflow file must not produce OIDC findings"
        );
    }

    // ── TP: id-token:write compact form fires ────────────────────────────────

    #[test]
    fn tp_compact_oidc_write_fires() {
        let src = "permissions: {id-token:write, contents:read}\n";
        let findings = emit_oidc_scope_findings(src, ".github/workflows/deploy.yml");
        assert!(
            findings.iter().any(|f| f.id == "security:oidc_scope_abuse"),
            "compact id-token:write must fire"
        );
    }

    // ── TN: issuer suppressor blocks oidc_scope_abuse ────────────────────────

    #[test]
    fn tn_issuer_suppressor_blocks() {
        let src = r#"
permissions:
  id-token: write
steps:
  - name: mint token
    with:
      issuer: https://token.actions.githubusercontent.com
"#;
        let findings = emit_oidc_scope_findings(src, ".github/workflows/attest.yml");
        assert!(
            !findings.iter().any(|f| f.id == "security:oidc_scope_abuse"),
            "issuer: within window must suppress oidc_scope_abuse"
        );
    }
}
