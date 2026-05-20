//! crates.io adapter for the registry-watch pipeline.
//!
//! Polls `https://crates.io/api/v1/summary` which returns a `new_crates`
//! array of the most-recently-published crates. The summary record
//! exposes enough metadata to build a [`PackageUpload`] without a
//! secondary fetch per crate. Cargo's install-script analog is
//! `build.rs`; the summary doesn't expose that, so the adapter
//! leaves `has_install_scripts = false` and lets downstream scoring
//! pick up the signal from other axes (Levenshtein distance, publish
//! recency, etc.).
//!
//! Tests use fixture JSON and never touch the network.

use anyhow::Context as _;
use serde::Deserialize;

use crate::registry_watch::{PackageUpload, Registry, RegistryAdapter};

pub const CRATES_SUMMARY_URL: &str = "https://crates.io/api/v1/summary";

/// crates.io adapter. Owns its `ureq::Agent`.
pub struct CratesIoAdapter {
    agent: ureq::Agent,
}

impl CratesIoAdapter {
    pub fn new() -> Self {
        Self {
            agent: ureq::Agent::new_with_defaults(),
        }
    }
}

impl Default for CratesIoAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Deserialize)]
struct SummaryResponse {
    #[serde(default)]
    new_crates: Vec<NewCrateRecord>,
}

#[derive(Debug, Deserialize)]
struct NewCrateRecord {
    name: String,
    max_version: Option<String>,
    description: Option<String>,
    updated_at: Option<String>,
}

impl RegistryAdapter for CratesIoAdapter {
    fn poll_recent_uploads(&mut self) -> anyhow::Result<Vec<PackageUpload>> {
        let mut resp = self
            .agent
            .get(CRATES_SUMMARY_URL)
            .header("User-Agent", "janitor-registry-watch/1.0")
            .call()
            .context("crates.io summary: request failed")?;
        let body: SummaryResponse = resp
            .body_mut()
            .read_json()
            .context("crates.io summary: response body is not valid JSON")?;
        Ok(parse_summary_response(body))
    }
}

/// Convert a parsed summary into the canonical [`PackageUpload`] vec.
/// Exposed so tests can supply fixture JSON without network I/O.
#[cfg(test)]
pub(crate) fn parse_summary_response_from_value(body: serde_json::Value) -> Vec<PackageUpload> {
    let Ok(parsed) = serde_json::from_value::<SummaryResponse>(body) else {
        return Vec::new();
    };
    parse_summary_response(parsed)
}

fn parse_summary_response(body: SummaryResponse) -> Vec<PackageUpload> {
    let mut uploads = Vec::with_capacity(body.new_crates.len());
    for rec in body.new_crates {
        let Some(version) = rec.max_version else {
            continue;
        };
        uploads.push(PackageUpload {
            registry: Registry::Crates,
            name: rec.name,
            version,
            published_at: rec.updated_at,
            // crates.io summary doesn't expose owner count without a
            // secondary /owners fetch; leave unknown.
            maintainer_count: None,
            // build.rs detection requires fetching the crate manifest;
            // out of scope for the summary-only poll.
            has_install_scripts: false,
            description: rec.description,
        });
    }
    uploads
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_new_crates_into_uploads() {
        let body = serde_json::json!({
            "new_crates": [
                {
                    "id": "tokio-mock",
                    "name": "tokio-mock",
                    "max_version": "0.1.0",
                    "description": "Mocks for tokio",
                    "updated_at": "2026-05-18T10:00:00Z",
                    "downloads": 5
                },
                {
                    "id": "serde-helper-x",
                    "name": "serde-helper-x",
                    "max_version": "1.0.0",
                    "description": null,
                    "updated_at": "2026-05-18T09:55:00Z",
                    "downloads": 0
                }
            ]
        });
        let uploads = parse_summary_response_from_value(body);
        assert_eq!(uploads.len(), 2);
        assert_eq!(uploads[0].name, "tokio-mock");
        assert_eq!(uploads[0].version, "0.1.0");
        assert_eq!(uploads[0].registry, Registry::Crates);
        assert!(!uploads[0].has_install_scripts);
        assert_eq!(uploads[0].maintainer_count, None);
    }

    #[test]
    fn skips_records_without_version() {
        let body = serde_json::json!({
            "new_crates": [
                {"name": "no-version", "description": "?"}
            ]
        });
        let uploads = parse_summary_response_from_value(body);
        assert!(uploads.is_empty());
    }

    #[test]
    fn malformed_response_yields_empty_vec() {
        let body = serde_json::json!({"unrelated": "data"});
        let uploads = parse_summary_response_from_value(body);
        assert!(uploads.is_empty());
    }
}
