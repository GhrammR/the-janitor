//! Live-registry diff pipeline for supply-chain monitoring.
//!
//! This module subscribes to recent-upload feeds on npm, crates.io, and
//! PyPI, scores each upload against a set of suspicion heuristics
//! (Levenshtein distance to popular packages, install-script presence,
//! maintainer age, publish-time recency, etc.), and emits high-scoring
//! candidates to a triage queue for operator review.
//!
//! ## Architecture
//!
//! - [`RegistryAdapter`] is the trait each registry implements.
//!   Implementations live in `npm.rs`, `crates_io.rs`, `pypi.rs`.
//! - [`PackageUpload`] is the common record produced by every adapter.
//! - [`score`] computes an integer score (0-100) per upload.
//! - [`queue`] persists scored candidates as NDJSON.
//!
//! ## Scope (Sprint 145 /goal)
//!
//! - Polls recent-upload feeds; does NOT subscribe to a stream
//! - Read-only metadata fetch; never executes install scripts
//! - Pure Rust; no paid threat-intel feeds; no daemon process

use serde::{Deserialize, Serialize};

pub mod crates_io;
pub mod npm;
pub mod pypi;
pub mod queue;
pub mod score;

/// Identifies which package registry an upload came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Registry {
    Npm,
    Crates,
    PyPI,
}

impl Registry {
    /// Short tag used in queue dedup keys and queue rendering.
    pub fn tag(&self) -> &'static str {
        match self {
            Registry::Npm => "npm",
            Registry::Crates => "crates",
            Registry::PyPI => "pypi",
        }
    }
}

/// A single package upload observed on a live registry feed. This is
/// the canonical record every adapter produces; the scoring module
/// consumes it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageUpload {
    pub registry: Registry,
    pub name: String,
    pub version: String,
    /// ISO 8601 publish timestamp if the registry exposes it.
    pub published_at: Option<String>,
    /// Number of maintainers, if the registry exposes maintainer count.
    pub maintainer_count: Option<usize>,
    /// True when the package declares an install/preinstall/postinstall
    /// script or equivalent execution-on-install hook.
    pub has_install_scripts: bool,
    /// Short human-readable description from the registry metadata.
    pub description: Option<String>,
}

/// Trait implemented by each registry adapter. Implementations poll a
/// recent-uploads feed and return canonical [`PackageUpload`] records.
pub trait RegistryAdapter {
    /// Fetch the most recent uploads from this registry. Implementations
    /// must honour the rate limits documented in
    /// `tools/campaign/REGISTRY_WATCH_GUIDE.md` and use exponential
    /// backoff on 429 / 503 responses.
    ///
    /// `&mut self` allows adapters (e.g. [`npm::NpmAdapter`]) to advance
    /// their internal sequence cursor after each successful poll so
    /// subsequent calls return only new uploads rather than re-fetching
    /// from the same starting position.
    fn poll_recent_uploads(&mut self) -> anyhow::Result<Vec<PackageUpload>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_tag_round_trips() {
        assert_eq!(Registry::Npm.tag(), "npm");
        assert_eq!(Registry::Crates.tag(), "crates");
        assert_eq!(Registry::PyPI.tag(), "pypi");
    }

    #[test]
    fn package_upload_serialises_round_trip() {
        let u = PackageUpload {
            registry: Registry::Npm,
            name: "x".into(),
            version: "1.0.0".into(),
            published_at: Some("2026-05-18T00:00:00Z".into()),
            maintainer_count: Some(1),
            has_install_scripts: true,
            description: None,
        };
        let s = serde_json::to_string(&u).unwrap();
        let back: PackageUpload = serde_json::from_str(&s).unwrap();
        assert_eq!(back.name, "x");
        assert!(back.has_install_scripts);
    }
}
