//! P2-26 LD_PRELOAD and Dynamic Linker Hijack Detector.
//!
//! Detects CI/build script patterns that inject a shared library via
//! `LD_PRELOAD` or persist a loader path via `/etc/ld.so.conf`, `.bashrc`
//! writes, or `systemctl enable` without a cryptographic attestation check
//! (sha256sum, cosign verify, openssl dgst) within ±5 lines.
//!
//! # Threat model
//!
//! An attacker who can write to a CI step or Dockerfile RUN line can set
//! `LD_PRELOAD=/tmp/evil.so` before any binary invocation.  The dynamic linker
//! loads the attacker-controlled library before libc, giving full code-exec in
//! every process in the pipeline.  Persistence vectors (`echo >> .bashrc`,
//! `systemctl enable`, `init.d/`) survive reboots.
//!
//! # Detection model
//!
//! 1. **Hijack sink**: `LD_PRELOAD=`, `/etc/ld.so.conf`, `echo >> .bashrc`,
//!    `systemctl enable`, `ln -s`, `init.d/`.
//! 2. **Attestation suppressor**: within ±5 lines, `sha256sum`, `cosign verify`,
//!    `openssl dgst`, `gpg --verify`, `sigstore`, `in-toto`.
//! 3. No suppressor → emit `security:ld_preload_injection` (KevCritical) or
//!    `security:ci_persistence_vector` (Critical) depending on pattern class.
//!
//! # Kani predicate
//!
//! `linker_hijack_missing_attestation(has_ld_preload, has_digest_check)` is a
//! pure boolean predicate.  The Kani harness in `reflexive_assurance.rs` proves
//! it is an exact conjunction.

use aho_corasick::{AhoCorasick, MatchKind};
use common::slop::StructuredFinding;

// ── Pattern tables ────────────────────────────────────────────────────────────

const LD_PRELOAD_SINKS: &[&str] = &["LD_PRELOAD=", "LD_LIBRARY_PATH=", "/etc/ld.so.conf"];

const PERSISTENCE_SINKS: &[&str] = &[
    "echo >> .bashrc",
    "echo >> ~/.bashrc",
    "echo >> /etc/environment",
    "systemctl enable",
    "init.d/",
    "rc.local",
    "crontab -",
];

const ATTESTATION_SUPPRESSORS: &[&str] = &[
    "sha256sum",
    "cosign verify",
    "openssl dgst",
    "gpg --verify",
    "sigstore",
    "in-toto",
    "sha384sum",
    "sha512sum",
    "checksum",
];

// ── Pure predicates (Kani-provable) ──────────────────────────────────────────

/// Returns `true` when an `LD_PRELOAD` or linker-path injection is present
/// without a cryptographic attestation suppressor.
pub fn linker_hijack_missing_attestation(has_ld_preload: bool, has_digest_check: bool) -> bool {
    has_ld_preload && !has_digest_check
}

/// Returns `true` when a CI persistence vector is present without attestation.
pub fn persistence_missing_attestation(has_persistence: bool, has_digest_check: bool) -> bool {
    has_persistence && !has_digest_check
}

// ── Source extractor ──────────────────────────────────────────────────────────

fn scan_with_patterns(
    source: &str,
    sink_ac: &AhoCorasick,
    supp_ac: &AhoCorasick,
    window: usize,
) -> Vec<u32> {
    let lines: Vec<&str> = source.lines().collect();
    let mut hits = Vec::new();
    for (line_idx, line) in lines.iter().enumerate() {
        if sink_ac.is_match(line) {
            let lo = line_idx.saturating_sub(window);
            let hi = (line_idx + window + 1).min(lines.len());
            let window_text = lines[lo..hi].join("\n");
            if !supp_ac.is_match(&window_text) {
                hits.push(line_idx as u32 + 1);
            }
        }
    }
    hits
}

// ── Finding emitter ───────────────────────────────────────────────────────────

/// Scan `source` for unattested LD_PRELOAD / persistence patterns.
/// Returns one `StructuredFinding` per violation.
pub fn emit_linker_hijack_findings(source: &str, file: &str) -> Vec<StructuredFinding> {
    let supp_ac = AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostFirst)
        .build(ATTESTATION_SUPPRESSORS)
        .expect("static ATTESTATION_SUPPRESSORS are valid");

    let ld_ac = AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostFirst)
        .build(LD_PRELOAD_SINKS)
        .expect("static LD_PRELOAD_SINKS are valid");

    let persist_ac = AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostFirst)
        .build(PERSISTENCE_SINKS)
        .expect("static PERSISTENCE_SINKS are valid");

    let mut findings: Vec<StructuredFinding> = Vec::new();

    for line_no in scan_with_patterns(source, &ld_ac, &supp_ac, 5) {
        findings.push(StructuredFinding {
            id: "security:ld_preload_injection".to_string(),
            severity: Some("KevCritical".to_string()),
            file: Some(file.to_string()),
            line: Some(line_no),
            remediation: Some(
                "LD_PRELOAD or LD_LIBRARY_PATH is set without a cryptographic digest \
check on the library being loaded.  Verify the shared object with `sha256sum -c \
<lib>.sha256` or `cosign verify-blob` before setting LD_PRELOAD.  In CI pipelines, \
pin the library artifact by digest and verify with `openssl dgst -sha256`.  Without \
attestation, any step with write access to /tmp can substitute a malicious library."
                    .to_string(),
            ),
            ..Default::default()
        });
    }

    for line_no in scan_with_patterns(source, &persist_ac, &supp_ac, 5) {
        findings.push(StructuredFinding {
            id: "security:ci_persistence_vector".to_string(),
            severity: Some("Critical".to_string()),
            file: Some(file.to_string()),
            line: Some(line_no),
            remediation: Some(
                "CI/build script writes to a shell profile, systemd unit, or init.d \
script without a cryptographic attestation check.  An attacker who can inject this \
step gains persistent code execution across reboots.  Pin the artifact by digest \
(`sha256sum -c`) and verify with `cosign verify` before installation."
                    .to_string(),
            ),
            ..Default::default()
        });
    }

    findings
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Pure predicates ───────────────────────────────────────────────────────

    #[test]
    fn predicate_ld_preload_exact_conjunction() {
        assert!(linker_hijack_missing_attestation(true, false));
        assert!(!linker_hijack_missing_attestation(true, true));
        assert!(!linker_hijack_missing_attestation(false, false));
        assert!(!linker_hijack_missing_attestation(false, true));
    }

    #[test]
    fn predicate_persistence_exact_conjunction() {
        assert!(persistence_missing_attestation(true, false));
        assert!(!persistence_missing_attestation(true, true));
        assert!(!persistence_missing_attestation(false, false));
    }

    // ── TP: LD_PRELOAD in Dockerfile RUN → KevCritical ────────────────────────
    #[test]
    fn tp_ld_preload_in_dockerfile_run() {
        let src = r#"
FROM ubuntu:22.04
RUN LD_PRELOAD=/tmp/hook.so ./build.sh
RUN make install
"#;
        let findings = emit_linker_hijack_findings(src, "Dockerfile");
        assert!(
            findings
                .iter()
                .any(|f| f.id == "security:ld_preload_injection"),
            "LD_PRELOAD without sha256sum must fire"
        );
        assert_eq!(
            findings
                .iter()
                .find(|f| f.id == "security:ld_preload_injection")
                .unwrap()
                .severity
                .as_deref(),
            Some("KevCritical")
        );
    }

    // ── TN: LD_PRELOAD with sha256sum nearby → no finding ────────────────────
    #[test]
    fn tn_ld_preload_with_sha256sum() {
        let src = r#"
FROM ubuntu:22.04
RUN sha256sum -c hook.sha256 && LD_PRELOAD=/usr/lib/hook.so ./build.sh
"#;
        let findings = emit_linker_hijack_findings(src, "Dockerfile");
        assert!(
            !findings
                .iter()
                .any(|f| f.id == "security:ld_preload_injection"),
            "sha256sum within window must suppress LD_PRELOAD finding"
        );
    }

    // ── TP: persistence vector (systemctl enable) without attestation ─────────
    #[test]
    fn tp_systemctl_enable_no_attestation() {
        let src = r#"
#!/bin/bash
cp ./myservice /etc/systemd/system/
systemctl enable myservice
systemctl start myservice
"#;
        let findings = emit_linker_hijack_findings(src, "install.sh");
        assert!(
            findings
                .iter()
                .any(|f| f.id == "security:ci_persistence_vector"),
            "systemctl enable without attestation must fire"
        );
    }

    // ── TN: systemctl enable with cosign verify nearby ────────────────────────
    #[test]
    fn tn_systemctl_enable_with_cosign() {
        let src = r#"
#!/bin/bash
cosign verify --key cosign.pub myservice.sig
cp ./myservice /etc/systemd/system/
systemctl enable myservice
"#;
        let findings = emit_linker_hijack_findings(src, "install.sh");
        assert!(
            !findings
                .iter()
                .any(|f| f.id == "security:ci_persistence_vector"),
            "cosign verify must suppress persistence finding"
        );
    }

    // ── TN: attestation outside ±5 line window → still fires ──────────────────
    #[test]
    fn tp_attestation_outside_window_still_fires() {
        let mut src = String::from("sha256sum -c lib.sha256\n");
        for _ in 0..10 {
            src.push_str("echo 'step'\n");
        }
        src.push_str("LD_PRELOAD=/tmp/evil.so ./run\n");
        let findings = emit_linker_hijack_findings(&src, "ci.sh");
        assert!(
            findings
                .iter()
                .any(|f| f.id == "security:ld_preload_injection"),
            "sha256sum >5 lines away must not suppress LD_PRELOAD finding"
        );
    }

    // ── TN: plain env var without preload path → no finding ───────────────────
    #[test]
    fn tn_unrelated_env_not_flagged() {
        let src = r#"
export PATH=/usr/local/bin:$PATH
export GOPATH=/home/user/go
make build
"#;
        let findings = emit_linker_hijack_findings(src, "build.sh");
        assert!(findings.is_empty(), "unrelated env vars must not fire");
    }
}
