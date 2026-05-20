//! npm adapter for the registry-watch pipeline.
//!
//! ## Two-phase polling (Sprint 145 fix)
//!
//! `replicate.npmjs.com/_changes?include_docs=true` returns HTTP 400.
//! The adapter uses a two-phase strategy instead:
//!
//! Phase 1a: name-only poll — fetches `_changes` without `include_docs`,
//! extracting only the `id` (package name) from each result record.
//!
//! Phase 1b: selective metadata fetch — for each name where the Levenshtein
//! distance to any popular package is ≤ 2, or where the name contains a
//! literal install-hook keyword (`postinstall`, `preinstall`), fetches
//! `https://registry.npmjs.org/<name>` for full metadata via
//! [`crate::registry_probe::probe_npm`]. This eliminates the broken
//! parameter and halves registry load compared to an all-docs approach.
//!
//! Rate limit: 1 req/sec between per-name metadata fetches (npm ToS).
//!
//! Tests use fixture JSON and never touch the network.

use std::time::Duration;

use anyhow::Context as _;
use serde::Deserialize;

use crate::registry_probe::probe_npm;
use crate::registry_watch::{score::levenshtein, PackageUpload, Registry, RegistryAdapter};

/// CouchDB-style `_changes` feed exposed by the npm registry replica.
pub const NPM_CHANGES_URL: &str = "https://replicate.npmjs.com/_changes";
/// Default batch size per poll. Conservative to avoid rate-limit pressure.
pub const DEFAULT_LIMIT: usize = 50;

/// Adapter for the npm `_changes` feed. Owns its `ureq::Agent`.
pub struct NpmAdapter {
    agent: ureq::Agent,
    since: String,
    limit: usize,
    /// Popular package names used to gate per-name metadata fetches.
    popular: Vec<String>,
}

impl NpmAdapter {
    /// Build an adapter that polls from the registry head (`since=now`)
    /// and fetches up to [`DEFAULT_LIMIT`] uploads per poll.
    pub fn new() -> Self {
        Self {
            agent: ureq::Agent::new_with_defaults(),
            since: "now".to_string(),
            limit: DEFAULT_LIMIT,
            popular: Vec::new(),
        }
    }

    /// Override the batch size.
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = limit;
        self
    }

    /// Resume polling from a specific CouchDB sequence ID.
    pub fn with_since(mut self, since: impl Into<String>) -> Self {
        self.since = since.into();
        self
    }

    /// Set the popular-package list used to gate per-name metadata fetches.
    /// Only names within Levenshtein distance ≤ 2 of any entry in this list,
    /// or names containing `postinstall`/`preinstall`, are fetched.
    pub fn with_popular(mut self, names: &[&str]) -> Self {
        self.popular = names.iter().map(|s| s.to_string()).collect();
        self
    }
}

impl Default for NpmAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Deserialize)]
struct ChangesResponse {
    results: Vec<ChangeRecord>,
    #[serde(default)]
    last_seq: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct ChangeRecord {
    id: String,
    #[serde(default)]
    deleted: bool,
}

impl RegistryAdapter for NpmAdapter {
    fn poll_recent_uploads(&mut self) -> anyhow::Result<Vec<PackageUpload>> {
        // Phase 1a: name-only poll (no include_docs — rejected with HTTP 400).
        let url = format!(
            "{NPM_CHANGES_URL}?since={}&limit={}",
            self.since, self.limit
        );
        let mut resp = self
            .agent
            .get(&url)
            .call()
            .context("npm _changes feed: request failed")?;
        let body: ChangesResponse = resp
            .body_mut()
            .read_json()
            .context("npm _changes feed: response body is not valid JSON")?;

        // Advance the sequence cursor so the next call fetches only new uploads.
        if let Some(seq) = body.last_seq.as_str() {
            self.since = seq.to_string();
        } else if let Some(seq) = body.last_seq.as_u64() {
            self.since = seq.to_string();
        }

        let names = parse_names_response(body);

        // Phase 1b: selective per-name metadata fetch.
        let mut uploads = Vec::new();
        for name in &names {
            if !should_probe(name, &self.popular) {
                continue;
            }
            match probe_npm(name, &self.agent) {
                Ok(Some(probe)) => {
                    let Some(version) = probe.latest_version else {
                        continue;
                    };
                    uploads.push(PackageUpload {
                        registry: Registry::Npm,
                        name: name.clone(),
                        version,
                        published_at: probe.modified_at,
                        maintainer_count: Some(probe.maintainer_count),
                        has_install_scripts: probe.has_install_scripts,
                        description: probe.description,
                    });
                }
                Ok(None) => {}
                Err(e) => {
                    eprintln!("[npm-watch] probe failed for {name}: {e}");
                }
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        Ok(uploads)
    }
}

/// Returns `true` when `name` warrants a per-name metadata fetch.
/// Fires when: Levenshtein distance ≤ 2 to any popular package, OR
/// the name contains a literal install-hook keyword.
fn should_probe(name: &str, popular: &[String]) -> bool {
    if name.contains("postinstall") || name.contains("preinstall") {
        return true;
    }
    popular.iter().any(|p| levenshtein(name, p) <= 2)
}

fn parse_names_response(body: ChangesResponse) -> Vec<String> {
    body.results
        .into_iter()
        .filter(|r| !r.deleted)
        .map(|r| r.id)
        .collect()
}

/// Exposed for tests — extracts names from fixture JSON without network I/O.
#[cfg(test)]
pub(crate) fn parse_names_response_from_value(body: serde_json::Value) -> Vec<String> {
    let Ok(parsed) = serde_json::from_value::<ChangesResponse>(body) else {
        return Vec::new();
    };
    parse_names_response(parsed)
}

/// Exposed for tests — builds a [`PackageUpload`] from a probe result,
/// mirroring the production path in `poll_recent_uploads`.
#[cfg(test)]
pub(crate) fn upload_from_probe(
    name: &str,
    probe: &crate::registry_probe::NpmRegistryProbe,
) -> Option<PackageUpload> {
    let version = probe.latest_version.clone()?;
    Some(PackageUpload {
        registry: Registry::Npm,
        name: name.to_string(),
        version,
        published_at: probe.modified_at.clone(),
        maintainer_count: Some(probe.maintainer_count),
        has_install_scripts: probe.has_install_scripts,
        description: probe.description.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_names_from_changes_response() {
        let body = serde_json::json!({
            "results": [
                {"seq": 1, "id": "lodahs",      "changes": [{"rev": "1-a"}]},
                {"seq": 2, "id": "expres",      "changes": [{"rev": "1-b"}]},
                {"seq": 3, "id": "react-utils", "changes": [{"rev": "1-c"}]}
            ],
            "last_seq": "3-z"
        });
        let names = parse_names_response_from_value(body);
        assert_eq!(names, vec!["lodahs", "expres", "react-utils"]);
    }

    #[test]
    fn skips_deleted_records() {
        let body = serde_json::json!({
            "results": [
                {"seq": 1, "id": "deleted-pkg", "changes": [{"rev": "2-x"}], "deleted": true},
                {"seq": 2, "id": "live-pkg",    "changes": [{"rev": "1-y"}]}
            ],
            "last_seq": "2-z"
        });
        let names = parse_names_response_from_value(body);
        assert_eq!(names, vec!["live-pkg"]);
    }

    #[test]
    fn malformed_changes_response_yields_empty_vec() {
        let body = serde_json::json!({"unrelated": "data"});
        let names = parse_names_response_from_value(body);
        assert!(names.is_empty());
    }

    #[test]
    fn should_probe_fires_on_levenshtein_distance_lte_2() {
        let popular = vec!["react".to_string(), "lodash".to_string()];
        // "recat" is Levenshtein distance 2 from "react" — fires.
        assert!(should_probe("recat", &popular));
        // "lodahs" is distance 2 from "lodash" — fires.
        assert!(should_probe("lodahs", &popular));
        // distance > 2 from both — does not fire.
        assert!(!should_probe("completely-different", &popular));
    }

    #[test]
    fn should_probe_fires_on_install_hook_keyword() {
        let popular: Vec<String> = vec![];
        assert!(should_probe("my-postinstall-hook", &popular));
        assert!(should_probe("preinstall-script", &popular));
        assert!(!should_probe("innocuous-package", &popular));
    }

    #[test]
    fn upload_from_probe_extracts_fields() {
        use crate::registry_probe::NpmRegistryProbe;
        let probe = NpmRegistryProbe {
            name: "recat".to_string(),
            latest_version: Some("0.0.1".to_string()),
            created_at: Some("2026-05-01T00:00:00Z".to_string()),
            modified_at: Some("2026-05-19T00:00:00Z".to_string()),
            maintainer_count: 1,
            has_install_scripts: true,
            description: Some("test pkg".to_string()),
            homepage: None,
        };
        let upload = upload_from_probe("recat", &probe).unwrap();
        assert_eq!(upload.name, "recat");
        assert_eq!(upload.version, "0.0.1");
        assert_eq!(upload.maintainer_count, Some(1));
        assert!(upload.has_install_scripts);
        assert_eq!(upload.registry, Registry::Npm);
        assert_eq!(upload.published_at.as_deref(), Some("2026-05-19T00:00:00Z"));
    }
}
