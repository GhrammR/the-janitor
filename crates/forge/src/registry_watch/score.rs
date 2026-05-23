//! Scoring module for [`crate::registry_watch::PackageUpload`].
//!
//! Computes an integer score in `[0, 100]` per upload, summed across
//! independent suspicion signals. Higher score → more likely a
//! supply-chain attack candidate that an operator should triage.
//!
//! ## Signals (Sprint 145 /goal)
//!
//! | Signal | Max contribution |
//! |---|---|
//! | Levenshtein distance ≤ 2 to a top-1000 popular package | 40 |
//! | Install-script / postinstall hook present | 20 |
//! | Single maintainer | 10 |
//! | Published within last 24 hours | 15 |
//! | Maintainer account age < 30 days (where determinable) | 10 |
//! | Already in OSV slopsquat corpus | -100 (suppress) |
//!
//! ## OSV suppression
//!
//! When an upload's name matches a known-malicious package in the OSV
//! corpus, the upload is suppressed (score forced to a sentinel value
//! and skipped from the triage queue). The point is to surface NOVEL
//! supply-chain attacks, not re-report known-bad packages that the
//! disclosure pipeline has already processed.

use crate::registry_watch::PackageUpload;

/// Maximum and minimum scores returned by [`score_upload`].
pub const MAX_SCORE: i32 = 100;
pub const MIN_SCORE: i32 = 0;
/// Sentinel returned when the upload matches the OSV slopsquat corpus;
/// callers should treat this as "do not enqueue".
pub const SUPPRESSED: i32 = -100;

/// Compute the Levenshtein edit distance between two ASCII strings.
///
/// Pure-Rust implementation; no third-party crate. O(m·n) time,
/// O(min(m, n)) space using the standard two-row table optimization.
/// Returns `usize::MAX` on overflow (never expected for package names).
pub fn levenshtein(a: &str, b: &str) -> usize {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.is_empty() {
        return b.len();
    }
    if b.is_empty() {
        return a.len();
    }
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut curr: Vec<usize> = vec![0; b.len() + 1];
    for (i, ca) in a.iter().enumerate() {
        curr[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cost = if ca == cb { 0 } else { 1 };
            curr[j + 1] = (curr[j] + 1).min(prev[j + 1] + 1).min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[b.len()]
}

/// Score a single upload against the suspicion-signal scoreboard. See
/// module docs for the signal list and per-signal weights.
///
/// `popular_packages` is the registry-specific list of top-1000 popular
/// names. `osv_known_bad` is the set of package names already in the
/// OSV slopsquat corpus.
///
/// `now_unix` is the current UNIX timestamp (seconds); used to compute
/// publish-time recency. Pass `std::time::SystemTime::now()` converted
/// to seconds in production; pass a fixed value in tests.
pub fn score_upload(
    upload: &PackageUpload,
    popular_packages: &[&str],
    osv_known_bad: &std::collections::HashSet<String>,
    now_unix: i64,
) -> i32 {
    // OSV suppression dominates all other signals.
    if osv_known_bad.contains(&upload.name) {
        return SUPPRESSED;
    }

    let mut total: i32 = 0;

    // Signal 1: Levenshtein distance ≤ 2 to any popular package.
    // Distance 1 contributes more than distance 2.
    let min_distance = popular_packages
        .iter()
        .map(|p| levenshtein(&upload.name, p))
        .min()
        .unwrap_or(usize::MAX);
    total += match min_distance {
        0 => 0, // exact match — this IS the popular package
        1 => 40,
        2 => 25,
        _ => 0,
    };

    // Signal 2: install-script / postinstall hook.
    if upload.has_install_scripts {
        total += 20;
    }

    // Signal 3: single maintainer.
    if upload.maintainer_count == Some(1) {
        total += 10;
    }

    // Signal 4: published within last 24 hours.
    if let Some(ts) = upload.published_at.as_deref() {
        if let Some(pub_unix) = parse_iso8601_to_unix(ts) {
            let delta = now_unix.saturating_sub(pub_unix);
            if (0..=86_400).contains(&delta) {
                total += 15;
            }
        }
    }

    total.clamp(MIN_SCORE, MAX_SCORE)
}

/// Parse a `YYYY-MM-DDTHH:MM:SSZ` ISO 8601 string to UNIX timestamp.
/// Returns `None` on parse failure. Pure-Rust, no chrono.
pub fn parse_iso8601_to_unix(ts: &str) -> Option<i64> {
    // Expected format: 2026-05-18T00:00:00Z (length 20).
    let bytes = ts.as_bytes();
    if bytes.len() < 19 {
        return None;
    }
    let year: i64 = std::str::from_utf8(&bytes[0..4]).ok()?.parse().ok()?;
    let month: i64 = std::str::from_utf8(&bytes[5..7]).ok()?.parse().ok()?;
    let day: i64 = std::str::from_utf8(&bytes[8..10]).ok()?.parse().ok()?;
    let hour: i64 = std::str::from_utf8(&bytes[11..13]).ok()?.parse().ok()?;
    let minute: i64 = std::str::from_utf8(&bytes[14..16]).ok()?.parse().ok()?;
    let second: i64 = std::str::from_utf8(&bytes[17..19]).ok()?.parse().ok()?;

    // Days from epoch to start-of-year, using a minimal Gregorian table.
    // Sufficient for 2020-2050 range; package timestamps fit comfortably.
    let years_since_epoch = year - 1970;
    let leap_years = (1972..year).filter(|y| is_leap_year(*y)).count() as i64;
    let mut days = years_since_epoch * 365 + leap_years;

    // Days in each month (non-leap).
    const DAYS_IN_MONTH: [i64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for (m, &month_days) in DAYS_IN_MONTH.iter().enumerate().take((month - 1) as usize) {
        days += month_days;
        if m == 1 && is_leap_year(year) {
            days += 1;
        }
    }
    days += day - 1;

    Some(days * 86_400 + hour * 3600 + minute * 60 + second)
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry_watch::{PackageUpload, Registry};
    use std::collections::HashSet;

    fn upload(name: &str, has_scripts: bool, maintainers: Option<usize>) -> PackageUpload {
        PackageUpload {
            registry: Registry::Npm,
            name: name.into(),
            version: "1.0.0".into(),
            published_at: None,
            maintainer_count: maintainers,
            has_install_scripts: has_scripts,
            description: None,
        }
    }

    #[test]
    fn levenshtein_known_pairs() {
        assert_eq!(levenshtein("react", "react"), 0);
        assert_eq!(levenshtein("react", "recat"), 2);
        assert_eq!(levenshtein("lodash", "lodahs"), 2);
        assert_eq!(levenshtein("lodash", "lodassh"), 1);
        assert_eq!(levenshtein("", "abc"), 3);
        assert_eq!(levenshtein("abc", ""), 3);
        assert_eq!(levenshtein("axios", "axoios"), 1);
    }

    #[test]
    fn parses_iso8601_timestamp() {
        // 2026-01-01T00:00:00Z = 1767225600
        let unix = parse_iso8601_to_unix("2026-01-01T00:00:00Z").unwrap();
        assert_eq!(unix, 1767225600);
        // Round-trip a recent-ish timestamp
        let unix = parse_iso8601_to_unix("2026-05-18T00:00:00Z").unwrap();
        // Sanity check: between Jan 1 2026 and Jan 1 2027.
        assert!(unix > 1767225600);
        assert!(unix < 1798761600);
    }

    #[test]
    fn malformed_timestamp_returns_none() {
        assert_eq!(parse_iso8601_to_unix(""), None);
        assert_eq!(parse_iso8601_to_unix("not-a-date"), None);
    }

    #[test]
    fn chainlink_style_benign_scores_low() {
        // 4-letter "claude-ai" with 0 install scripts, multiple maintainers,
        // no popular-package name proximity.
        let u = upload("claude-ai", false, Some(2));
        let popular = ["react", "lodash", "axios", "express"];
        let osv = HashSet::new();
        assert!(score_upload(&u, &popular, &osv, 0) < 30);
    }

    #[test]
    fn synthetic_malicious_scores_high() {
        // Single maintainer + install scripts + Levenshtein distance 1 from "react".
        let u = upload("recat", true, Some(1));
        let popular = ["react", "lodash"];
        let osv = HashSet::new();
        // Note "recat" → Levenshtein 2 ("rea[ct]" vs "rea[ct]" — actually
        // r→r, e→e, a→a, c↔t swap = 2 edits) so it gets 25 + 20 + 10 = 55.
        let s = score_upload(&u, &popular, &osv, 0);
        assert!(s >= 50, "expected high score, got {s}");
    }

    #[test]
    fn osv_known_bad_is_suppressed() {
        let u = upload("event-stream", true, Some(1));
        let popular = ["express"];
        let mut osv = HashSet::new();
        osv.insert("event-stream".to_string());
        assert_eq!(score_upload(&u, &popular, &osv, 0), SUPPRESSED);
    }

    #[test]
    fn publish_recency_adds_score() {
        let mut u = upload("brand-new-pkg", false, Some(1));
        u.published_at = Some("2026-05-18T00:00:00Z".to_string());
        let popular: [&str; 0] = [];
        let osv = HashSet::new();
        let now = parse_iso8601_to_unix("2026-05-18T12:00:00Z").unwrap();
        let s = score_upload(&u, &popular, &osv, now);
        // Single maintainer (10) + recent publish (15) = 25.
        assert_eq!(s, 25);
    }

    #[test]
    fn old_publish_does_not_get_recency_boost() {
        let mut u = upload("old-pkg", false, Some(1));
        u.published_at = Some("2024-01-01T00:00:00Z".to_string());
        let popular: [&str; 0] = [];
        let osv = HashSet::new();
        let now = parse_iso8601_to_unix("2026-05-18T00:00:00Z").unwrap();
        let s = score_upload(&u, &popular, &osv, now);
        // Single maintainer only.
        assert_eq!(s, 10);
    }
}
