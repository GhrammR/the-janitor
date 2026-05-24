//! CLI implementations for `janitor watch-registries` and
//! `janitor triage-registry-queue`. The enum variants live in
//! `main.rs::Commands`; this module owns the runtime behaviour.

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context as _;

use forge::registry_watch::{
    crates_io::CratesIoAdapter,
    npm::NpmAdapter,
    pypi::PyPiAdapter,
    queue::WatchQueue,
    score::{score_upload, MIN_SCORE},
    PackageUpload, RegistryAdapter,
};

/// Default popular-package lists baked into the binary. Operators can
/// override per-registry by passing `--popular-list <path>` pointing at
/// a newline-separated file. The lists below intentionally focus on
/// the most-typosquatted names in real-world attacks.
const NPM_POPULAR: &[&str] = &[
    "react",
    "lodash",
    "axios",
    "express",
    "commander",
    "async",
    "debug",
    "request",
    "chalk",
    "moment",
    "ws",
    "qs",
    "ms",
    "yargs",
    "fs-extra",
    "uuid",
    "minimist",
    "glob",
    "rimraf",
    "tslib",
    "typescript",
    "vue",
    "webpack",
    "babel-core",
    "underscore",
];
const CRATES_POPULAR: &[&str] = &[
    "serde",
    "tokio",
    "anyhow",
    "thiserror",
    "clap",
    "log",
    "rand",
    "regex",
    "serde_json",
    "reqwest",
    "futures",
    "uuid",
    "chrono",
    "tracing",
    "bytes",
    "tempfile",
    "once_cell",
    "lazy_static",
];
const PYPI_POPULAR: &[&str] = &[
    "requests",
    "urllib3",
    "flask",
    "django",
    "fastapi",
    "numpy",
    "pandas",
    "boto3",
    "pyyaml",
    "click",
    "pytest",
    "setuptools",
    "wheel",
    "pip",
    "scipy",
    "tensorflow",
    "torch",
    "scikit-learn",
    "matplotlib",
    "beautifulsoup4",
];

/// Run the watch-registries subcommand.
pub fn cmd_watch_registries(
    registry: &str,
    once: bool,
    project_root: &Path,
    popular_list: Option<&Path>,
    dry_run: bool,
    max_age_hours: u64,
) -> anyhow::Result<()> {
    let queue_path = project_root
        .join(".janitor")
        .join("registry_watch_queue.ndjson");
    let mut queue = WatchQueue::load(queue_path.clone())?;

    let override_popular = load_popular_list_override(popular_list)?;
    let osv_known = load_osv_corpus(project_root);

    let registries_to_poll: Vec<&'static str> = match registry {
        "npm" => vec!["npm"],
        "crates" => vec!["crates"],
        "pypi" => vec!["pypi"],
        "all" => vec!["npm", "crates", "pypi"],
        other => anyhow::bail!("unknown --registry value '{other}' (expected npm|crates|pypi|all)"),
    };

    eprintln!(
        "[watch-registries] polling {} once={}",
        registries_to_poll.join(","),
        once
    );
    loop {
        for reg in &registries_to_poll {
            let popular = popular_for_registry(reg, override_popular.as_deref());
            let uploads = match poll_one(reg, &popular) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("[watch-registries] {reg} poll error: {e}");
                    continue;
                }
            };
            let now = now_unix();
            let captured = now_iso8601();
            let max_age_secs = max_age_hours as i64 * 3600;
            let mut enqueued = 0_usize;
            for upload in uploads {
                // Skip packages older than max_age_hours.
                if max_age_hours > 0 {
                    if let Some(ref published) = upload.published_at {
                        if let Some(ts) = parse_published_at(published) {
                            if now - ts > max_age_secs {
                                continue;
                            }
                        }
                    }
                }
                let score = score_upload(&upload, &popular, &osv_known, now);
                if score <= MIN_SCORE {
                    continue;
                }
                if dry_run {
                    println!("{}", serde_json::to_string(&upload).unwrap_or_default());
                    enqueued += 1;
                } else if queue.append_if_new(upload, score, captured.clone())? {
                    enqueued += 1;
                }
            }
            eprintln!(
                "[watch-registries] {reg}: {} {enqueued} new candidates",
                if dry_run { "dry-run found" } else { "enqueued" }
            );
            // Per /goal rate limits: ≤1 req/sec npm, ≤2 req/sec crates, ≤1 req/sec pypi.
            // We do one poll per registry per cycle, so a 1-second sleep between
            // registries comfortably honours all three.
            std::thread::sleep(Duration::from_secs(1));
        }
        if once {
            break;
        }
        eprintln!("[watch-registries] cycle complete; sleeping 60s before next poll");
        std::thread::sleep(Duration::from_secs(60));
    }
    Ok(())
}

/// Run the triage-registry-queue subcommand.
pub fn cmd_triage_registry_queue(
    min_score: i32,
    render: &str,
    project_root: &Path,
) -> anyhow::Result<()> {
    let queue_path = project_root
        .join(".janitor")
        .join("registry_watch_queue.ndjson");
    let queue = WatchQueue::load(queue_path)?;
    let entries = queue.entries_above(min_score)?;

    match render {
        "markdown" => render_markdown(&entries),
        "text" => render_text(&entries),
        other => anyhow::bail!("unknown --render value '{other}' (expected text|markdown)"),
    }
    Ok(())
}

fn poll_one(reg: &str, popular: &[&str]) -> anyhow::Result<Vec<PackageUpload>> {
    match reg {
        "npm" => NpmAdapter::new()
            .with_popular(popular)
            .poll_recent_uploads(),
        "crates" => CratesIoAdapter::new().poll_recent_uploads(),
        "pypi" => PyPiAdapter::new().poll_recent_uploads(),
        _ => unreachable!("registry filter is validated upstream"),
    }
}

fn popular_for_registry<'a>(reg: &str, override_popular: Option<&'a [String]>) -> Vec<&'a str> {
    if let Some(list) = override_popular {
        return list.iter().map(String::as_str).collect();
    }
    let baked: &[&str] = match reg {
        "npm" => NPM_POPULAR,
        "crates" => CRATES_POPULAR,
        "pypi" => PYPI_POPULAR,
        _ => &[],
    };
    baked.to_vec()
}

fn load_popular_list_override(path: Option<&Path>) -> anyhow::Result<Option<Vec<String>>> {
    let Some(p) = path else {
        return Ok(None);
    };
    let content = std::fs::read_to_string(p)
        .with_context(|| format!("cannot read popular-list file {}", p.display()))?;
    let names: Vec<String> = content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect();
    Ok(Some(names))
}

fn load_osv_corpus(project_root: &Path) -> std::collections::HashSet<String> {
    let path = project_root.join(".janitor").join("slopsquat_corpus.rkyv");
    let Ok(bytes) = std::fs::read(&path) else {
        return std::collections::HashSet::new();
    };
    // The corpus is rkyv-serialised SlopsquatCorpus { package_names: Vec<String> }.
    // We deserialize defensively; on any failure we fall back to an empty set
    // (which is safe — it just disables the OSV suppression signal).
    match rkyv::from_bytes::<common::wisdom::SlopsquatCorpus, rkyv::rancor::Error>(&bytes) {
        Ok(corpus) => corpus.package_names.into_iter().collect(),
        Err(_) => std::collections::HashSet::new(),
    }
}

/// Thin wrapper around score.rs's ISO 8601 parser for use in the max-age filter.
fn parse_published_at(ts: &str) -> Option<i64> {
    forge::registry_watch::score::parse_iso8601_to_unix(ts)
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn now_iso8601() -> String {
    // Minimal ISO 8601 formatter: convert seconds-since-epoch to
    // YYYY-MM-DDTHH:MM:SSZ via the same arithmetic the parser uses.
    let secs = now_unix();
    format_iso8601(secs)
}

/// Inverse of `parse_iso8601_to_unix`. Pure-Rust, no chrono. Sufficient
/// for the queue captured-at field which doesn't need sub-second precision.
fn format_iso8601(unix: i64) -> String {
    let mut days = unix / 86_400;
    let mut secs_of_day = unix % 86_400;
    if secs_of_day < 0 {
        secs_of_day += 86_400;
        days -= 1;
    }
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;

    // Walk year by year from 1970 forward.
    let mut year: i64 = 1970;
    loop {
        let year_days: i64 = if is_leap_year(year) { 366 } else { 365 };
        if days < year_days {
            break;
        }
        days -= year_days;
        year += 1;
    }
    // Walk month.
    const DAYS_IN_MONTH: [i64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month: i64 = 1;
    for (i, &d) in DAYS_IN_MONTH.iter().enumerate() {
        let mut this_month = d;
        if i == 1 && is_leap_year(year) {
            this_month += 1;
        }
        if days < this_month {
            break;
        }
        days -= this_month;
        month += 1;
    }
    let day = days + 1;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn render_text(entries: &[forge::registry_watch::queue::QueueEntry]) {
    if entries.is_empty() {
        println!("(no entries above threshold)");
        return;
    }
    println!(
        "{:5} {:8} {:30} {:12} PUBLISHED_AT",
        "SCORE", "REGISTRY", "NAME", "VERSION"
    );
    for e in entries {
        println!(
            "{:5} {:8} {:30} {:12} {}",
            e.score,
            e.upload.registry.tag(),
            truncate(&e.upload.name, 30),
            truncate(&e.upload.version, 12),
            e.upload.published_at.as_deref().unwrap_or("?")
        );
    }
}

fn render_markdown(entries: &[forge::registry_watch::queue::QueueEntry]) {
    if entries.is_empty() {
        println!("_No entries above the requested threshold._");
        return;
    }
    println!("| Score | Registry | Name | Version | Published | Maintainers | Install scripts |");
    println!("|------:|----------|------|---------|-----------|------------:|:---------------:|");
    for e in entries {
        println!(
            "| {} | {} | `{}` | `{}` | {} | {} | {} |",
            e.score,
            e.upload.registry.tag(),
            e.upload.name,
            e.upload.version,
            e.upload.published_at.as_deref().unwrap_or("?"),
            e.upload
                .maintainer_count
                .map(|n| n.to_string())
                .unwrap_or_else(|| "?".to_string()),
            if e.upload.has_install_scripts {
                "yes"
            } else {
                "no"
            }
        );
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n.saturating_sub(1)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_age_filter_excludes_old_packages() {
        // Timestamp far in the past (2020-01-01) should be filtered when max_age_hours = 24.
        let old_ts = "2020-01-01T00:00:00Z";
        let ts_unix = parse_published_at(old_ts).expect("parseable timestamp");
        let now = now_unix();
        let max_age_secs: i64 = 24 * 3600;
        assert!(
            now - ts_unix > max_age_secs,
            "2020 timestamp should be older than 24 hours"
        );
    }

    #[test]
    fn max_age_filter_passes_recent_packages() {
        // A package published in the future (2099) is always within any max_age window.
        let future_ts = "2099-12-31T23:59:59Z";
        let ts_unix = parse_published_at(future_ts).expect("parseable timestamp");
        let now = now_unix();
        let max_age_secs: i64 = 24 * 3600;
        assert!(
            now - ts_unix < max_age_secs,
            "2099 timestamp should be within 24 hours of now"
        );
    }

    #[test]
    fn iso8601_format_produces_expected_date_prefix() {
        // 1_767_225_600 = 2026-01-01T00:00:00Z per the forge score.rs parser.
        let s = format_iso8601(1_767_225_600);
        assert!(
            s.starts_with("2026-01-01"),
            "expected 2026-01-01 prefix, got {s}"
        );
    }

    #[test]
    fn iso8601_format_full_timestamp_uses_colons() {
        // Regression guard: minutes and seconds must be separated by ':' not '-'.
        // Bug fixed on 2026-05-19: format string had {minute:02}-{second:02}.
        let s = format_iso8601(1_767_225_600 + 3661); // +1h 1m 1s
        assert_eq!(
            s, "2026-01-01T01:01:01Z",
            "full ISO 8601 timestamp must use colon separators, got {s}"
        );
    }

    #[test]
    fn truncate_respects_limit() {
        assert_eq!(truncate("short", 30), "short");
        assert_eq!(truncate("0123456789", 5).chars().count(), 5);
    }

    #[test]
    fn load_popular_list_override_filters_comments_and_blanks() {
        let dir = tempfile::TempDir::new().unwrap();
        let p = dir.path().join("popular.txt");
        std::fs::write(&p, "# comment\nfoo\n\nbar\n  baz  \n").unwrap();
        let names = load_popular_list_override(Some(&p)).unwrap().unwrap();
        assert_eq!(names, vec!["foo", "bar", "baz"]);
    }

    #[test]
    fn load_osv_corpus_returns_empty_set_when_file_absent() {
        let dir = tempfile::TempDir::new().unwrap();
        let s = load_osv_corpus(dir.path());
        assert!(s.is_empty());
    }
}
