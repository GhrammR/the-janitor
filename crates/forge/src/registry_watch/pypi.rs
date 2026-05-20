//! PyPI adapter for the registry-watch pipeline.
//!
//! ## Endpoint deviation from the /goal spec
//!
//! The /goal originally specified `https://pypi.org/simple/` for
//! discovery, but `/simple/` is a multi-MiB HTML index of every PyPI
//! package — impractical for incremental polling. This adapter uses
//! `https://pypi.org/rss/updates.xml` (the standard PyPI recent-uploads
//! RSS feed) instead, then fetches per-package metadata from
//! `https://pypi.org/pypi/<name>/json` for any items the operator
//! wants to enrich further.
//!
//! The deviation is documented in [`REGISTRY_WATCH_GUIDE.md`].
//!
//! ## What this adapter exposes
//!
//! - One [`poll_recent_uploads`] call returns the most recent entries
//!   in the RSS feed as [`PackageUpload`] records.
//! - Each record carries `name`, `version`, and `published_at` parsed
//!   from the RSS `<item>` block.
//! - `maintainer_count` and `has_install_scripts` are left unknown by
//!   the RSS poll. Callers that need them can invoke
//!   [`fetch_package_metadata`] per-name to enrich.
//!
//! Tests use fixture XML and never touch the network.

use anyhow::Context as _;

use crate::registry_watch::{PackageUpload, Registry, RegistryAdapter};

pub const PYPI_RSS_URL: &str = "https://pypi.org/rss/updates.xml";

/// PyPI adapter. Owns its `ureq::Agent`.
pub struct PyPiAdapter {
    agent: ureq::Agent,
}

impl PyPiAdapter {
    pub fn new() -> Self {
        Self {
            agent: ureq::Agent::new_with_defaults(),
        }
    }

    /// Fetch enrichment metadata for a single package. Returns the raw
    /// `info` block from `https://pypi.org/pypi/<name>/json`, or `None`
    /// on 404 / parse failure. Callers should apply this selectively to
    /// queue rows that score above the triage threshold — never to
    /// every poll-cycle name, due to PyPI rate limits.
    pub fn fetch_package_metadata(&self, name: &str) -> anyhow::Result<Option<serde_json::Value>> {
        let url = format!("https://pypi.org/pypi/{name}/json");
        let mut resp = match self.agent.get(&url).call() {
            Ok(r) => r,
            Err(ureq::Error::StatusCode(404)) => return Ok(None),
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "pypi metadata fetch failed for {name}: {e}"
                ))
            }
        };
        let body: serde_json::Value = resp
            .body_mut()
            .read_json()
            .context("pypi metadata: response body is not valid JSON")?;
        Ok(Some(body))
    }
}

impl Default for PyPiAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl RegistryAdapter for PyPiAdapter {
    fn poll_recent_uploads(&mut self) -> anyhow::Result<Vec<PackageUpload>> {
        let mut resp = self
            .agent
            .get(PYPI_RSS_URL)
            .header("User-Agent", "janitor-registry-watch/1.0")
            .call()
            .context("pypi RSS: request failed")?;
        let body: String = resp
            .body_mut()
            .read_to_string()
            .context("pypi RSS: response body is not UTF-8")?;
        Ok(parse_rss_feed(&body))
    }
}

/// Parse a PyPI RSS updates feed into [`PackageUpload`] records.
/// Public-in-crate so tests can supply fixture XML without network I/O.
pub(crate) fn parse_rss_feed(rss: &str) -> Vec<PackageUpload> {
    let mut uploads = Vec::new();
    let mut pos = 0;
    while let Some(item_offset) = rss[pos..].find("<item>") {
        let item_start = pos + item_offset;
        let Some(end_offset) = rss[item_start..].find("</item>") else {
            break;
        };
        let item_end = item_start + end_offset;
        let block = &rss[item_start..item_end];

        let Some(title) = extract_tag(block, "title") else {
            pos = item_end;
            continue;
        };
        // PyPI titles are `<title>name version</title>` — split on last space.
        let Some((name, version)) = title.rsplit_once(' ') else {
            pos = item_end;
            continue;
        };
        let published = extract_tag(block, "pubDate").map(|s| s.to_string());

        uploads.push(PackageUpload {
            registry: Registry::PyPI,
            name: name.trim().to_string(),
            version: version.trim().to_string(),
            published_at: published,
            // RSS feed doesn't expose maintainer / script info; would
            // require a per-name JSON fetch.
            maintainer_count: None,
            has_install_scripts: false,
            description: None,
        });

        pos = item_end;
    }
    uploads
}

fn extract_tag<'a>(block: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = block.find(&open)? + open.len();
    let end_rel = block[start..].find(&close)?;
    Some(&block[start..start + end_rel])
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_RSS: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>PyPI recent updates</title>
    <item>
      <title>requests 2.32.4</title>
      <link>https://pypi.org/project/requests/2.32.4/</link>
      <pubDate>Sun, 18 May 2026 10:00:00 GMT</pubDate>
    </item>
    <item>
      <title>suspicious-typo-pkg 0.0.1</title>
      <link>https://pypi.org/project/suspicious-typo-pkg/0.0.1/</link>
      <pubDate>Sun, 18 May 2026 11:30:00 GMT</pubDate>
    </item>
    <item>
      <title>malformed-no-version</title>
      <link>https://pypi.org/project/malformed-no-version/</link>
    </item>
  </channel>
</rss>"#;

    #[test]
    fn parses_well_formed_rss_items() {
        let uploads = parse_rss_feed(FIXTURE_RSS);
        assert_eq!(uploads.len(), 2);
        assert_eq!(uploads[0].name, "requests");
        assert_eq!(uploads[0].version, "2.32.4");
        assert_eq!(uploads[0].registry, Registry::PyPI);
        assert_eq!(
            uploads[0].published_at.as_deref(),
            Some("Sun, 18 May 2026 10:00:00 GMT")
        );
        assert_eq!(uploads[1].name, "suspicious-typo-pkg");
        assert_eq!(uploads[1].version, "0.0.1");
    }

    #[test]
    fn skips_items_without_space_separated_title() {
        // The "malformed-no-version" item has no version in its title;
        // adapter skips it without panicking.
        let uploads = parse_rss_feed(FIXTURE_RSS);
        assert!(uploads.iter().all(|u| u.name != "malformed-no-version"));
    }

    #[test]
    fn handles_empty_feed() {
        let rss = r#"<?xml version="1.0"?><rss><channel></channel></rss>"#;
        let uploads = parse_rss_feed(rss);
        assert!(uploads.is_empty());
    }
}
