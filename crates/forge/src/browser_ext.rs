use common::slop::{ProofClass, StructuredFinding};

/// Chrome/Firefox extension permissions that warrant security review.
const CRITICAL_PERMISSIONS: &[&str] = &[
    "\"tabs\"",
    "\"webRequest\"",
    "\"webRequestBlocking\"",
    "\"clipboardRead\"",
    "\"cookies\"",
    "\"history\"",
    "\"debugger\"",
    "\"nativeMessaging\"",
    "\"<all_urls>\"",
];

/// Manifest fields that indicate the extension has explicit scope restrictions.
const PERMISSION_SUPPRESSORS: &[&str] =
    &["\"content_security_policy\"", "\"externally_connectable\""];

/// Emit MV3 over-permission and MV2-compat-shim findings for `manifest.json` files.
///
/// Only fires when `label` ends with `manifest.json`.
pub fn emit_browser_ext_findings(source_str: &str, label: &str) -> Vec<StructuredFinding> {
    if !label.ends_with("manifest.json") {
        return Vec::new();
    }

    let mut findings = Vec::new();
    let has_suppressor = PERMISSION_SUPPRESSORS
        .iter()
        .any(|s| source_str.contains(s));

    for perm in CRITICAL_PERMISSIONS {
        if source_str.contains(perm) && !has_suppressor {
            findings.push(StructuredFinding {
                id: "security:browser_ext_overpermission".to_string(),
                severity: Some("High".to_string()),
                file: Some(label.to_string()),
                proof_class: Some(ProofClass::LatticeGapProposal),
                remediation: Some(format!(
                    "Remove or scope the {} permission; add content_security_policy restrictions if broad access is required",
                    perm.trim_matches('"')
                )),
                ..Default::default()
            });
            break;
        }
    }

    // MV2 background.scripts pattern inside a manifest_version 3 declaration.
    let is_mv3 = source_str.contains("\"manifest_version\": 3")
        || source_str.contains("\"manifest_version\":3");
    if is_mv3 && source_str.contains("\"scripts\"") && source_str.contains("\"background\"") {
        findings.push(StructuredFinding {
            id: "security:browser_ext_mv2_compat_shim".to_string(),
            severity: Some("Medium".to_string()),
            file: Some(label.to_string()),
            proof_class: Some(ProofClass::LatticeGapProposal),
            remediation: Some(
                "Replace background.scripts with a service_worker declaration (MV3 requirement); MV2 compat shims bypass CSP enforcement"
                    .to_string(),
            ),
            ..Default::default()
        });
    }

    findings
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const MV3_OVERPERM: &str = r#"{
  "manifest_version": 3,
  "name": "DataStealer",
  "permissions": ["tabs", "<all_urls>"],
  "action": {}
}"#;

    const MV3_SAFE: &str = r#"{
  "manifest_version": 3,
  "name": "Bookmark Manager",
  "permissions": ["storage", "activeTab"],
  "action": {}
}"#;

    const MV3_SUPPRESSED: &str = r#"{
  "manifest_version": 3,
  "name": "Safe Extension",
  "permissions": ["tabs"],
  "content_security_policy": { "extension_pages": "script-src 'self'" }
}"#;

    const MV2_COMPAT_IN_MV3: &str = r#"{
  "manifest_version": 3,
  "name": "LegacyBridge",
  "background": {
    "scripts": ["background.js"],
    "persistent": false
  }
}"#;

    const NOT_MANIFEST: &str = r#"{ "name": "pkg", "version": "1.0" }"#;

    #[test]
    fn tp_overpermission_fires_on_tabs_and_all_urls() {
        let findings = emit_browser_ext_findings(MV3_OVERPERM, "extension/manifest.json");
        assert!(
            findings
                .iter()
                .any(|f| f.id == "security:browser_ext_overpermission"),
            "tabs + <all_urls> must fire overpermission"
        );
    }

    #[test]
    fn tp_mv2_compat_shim_fires_in_mv3_manifest() {
        let findings = emit_browser_ext_findings(MV2_COMPAT_IN_MV3, "src/manifest.json");
        assert!(
            findings
                .iter()
                .any(|f| f.id == "security:browser_ext_mv2_compat_shim"),
            "background.scripts in MV3 manifest must fire compat-shim warning"
        );
    }

    #[test]
    fn tn_safe_permissions_no_findings() {
        let findings = emit_browser_ext_findings(MV3_SAFE, "manifest.json");
        assert!(
            findings.is_empty(),
            "storage + activeTab must produce no findings"
        );
    }

    #[test]
    fn tn_non_manifest_file_no_findings() {
        let findings = emit_browser_ext_findings(NOT_MANIFEST, "package.json");
        assert!(
            findings.is_empty(),
            "non-manifest.json file must produce no findings"
        );
    }

    #[test]
    fn tn_suppressor_prevents_overpermission() {
        let findings = emit_browser_ext_findings(MV3_SUPPRESSED, "manifest.json");
        assert!(
            !findings
                .iter()
                .any(|f| f.id == "security:browser_ext_overpermission"),
            "content_security_policy suppressor must prevent overpermission finding"
        );
    }
}
