//! Append-only NDJSON queue for scored [`PackageUpload`] records.
//!
//! Each line is a [`QueueEntry`] serialized as JSON. The queue is
//! deduplicated by `<registry>:<name>:<version>` so the same upload is
//! never recorded twice across multiple poll cycles, even if the
//! adapter sees it again. The file rotates when it exceeds
//! [`ROTATION_BYTES`] — the current file is renamed to
//! `<path>.<unix_timestamp>.bak` and a fresh file is started.
//!
//! ## Concurrency
//!
//! Single-writer model. The CLI subcommand owns the queue for the
//! duration of a poll cycle; there is no file-level locking. Running
//! two `janitor watch-registries` processes against the same queue
//! file is undefined behaviour.

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use serde::{Deserialize, Serialize};

use crate::registry_watch::PackageUpload;

/// Rotate the queue file when it exceeds this size on disk.
pub const ROTATION_BYTES: u64 = 100 * 1024 * 1024;

/// A single scored entry in the watch queue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueEntry {
    pub upload: PackageUpload,
    pub score: i32,
    /// ISO 8601 timestamp at which the queue captured this upload.
    pub captured_at: String,
}

impl QueueEntry {
    /// Stable dedup key used to suppress duplicate enqueues across
    /// multiple poll cycles.
    pub fn dedup_key(&self) -> String {
        format!(
            "{}:{}:{}",
            self.upload.registry.tag(),
            self.upload.name,
            self.upload.version
        )
    }
}

/// Append-only NDJSON queue.
pub struct WatchQueue {
    path: PathBuf,
    seen: HashSet<String>,
}

impl WatchQueue {
    /// Open the queue at `path`. Creates the parent directory if
    /// missing. Reads any existing entries to populate the dedup set.
    pub fn load(path: PathBuf) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!(
                    "WatchQueue::load: cannot create parent directory for {}",
                    path.display()
                )
            })?;
        }
        let seen = if path.exists() {
            read_dedup_keys(&path)?
        } else {
            HashSet::new()
        };
        Ok(Self { path, seen })
    }

    /// Append a new [`QueueEntry`] iff its dedup key has not been seen.
    /// Returns `true` when the entry was newly written; `false` on a
    /// dedup hit (no I/O performed). Rotates the file when it crosses
    /// [`ROTATION_BYTES`] before writing the new line.
    pub fn append_if_new(
        &mut self,
        upload: PackageUpload,
        score: i32,
        captured_at: String,
    ) -> anyhow::Result<bool> {
        let entry = QueueEntry {
            upload,
            score,
            captured_at,
        };
        let key = entry.dedup_key();
        if !self.seen.insert(key) {
            return Ok(false);
        }
        self.maybe_rotate()?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .with_context(|| {
                format!(
                    "WatchQueue::append_if_new: cannot open {}",
                    self.path.display()
                )
            })?;
        let line = serde_json::to_string(&entry)
            .context("WatchQueue::append_if_new: serialising entry")?;
        writeln!(file, "{line}").context("WatchQueue::append_if_new: writing line")?;
        Ok(true)
    }

    /// Read every entry currently in the queue file.
    pub fn read_entries(&self) -> anyhow::Result<Vec<QueueEntry>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let f = File::open(&self.path).with_context(|| {
            format!(
                "WatchQueue::read_entries: cannot open {}",
                self.path.display()
            )
        })?;
        let mut out = Vec::new();
        for line in BufReader::new(f).lines() {
            let line = line.context("WatchQueue::read_entries: read line")?;
            if line.trim().is_empty() {
                continue;
            }
            let Ok(entry) = serde_json::from_str::<QueueEntry>(&line) else {
                continue;
            };
            out.push(entry);
        }
        Ok(out)
    }

    /// Filtered read: only entries with `score >= min_score`.
    pub fn entries_above(&self, min_score: i32) -> anyhow::Result<Vec<QueueEntry>> {
        Ok(self
            .read_entries()?
            .into_iter()
            .filter(|e| e.score >= min_score)
            .collect())
    }

    fn maybe_rotate(&self) -> anyhow::Result<()> {
        let Ok(meta) = std::fs::metadata(&self.path) else {
            return Ok(());
        };
        if meta.len() < ROTATION_BYTES {
            return Ok(());
        }
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let backup = self.path.with_extension(format!("ndjson.{ts}.bak"));
        std::fs::rename(&self.path, &backup).with_context(|| {
            format!(
                "WatchQueue::maybe_rotate: cannot rotate {} → {}",
                self.path.display(),
                backup.display()
            )
        })?;
        Ok(())
    }
}

fn read_dedup_keys(path: &Path) -> anyhow::Result<HashSet<String>> {
    let f = File::open(path)
        .with_context(|| format!("read_dedup_keys: cannot open {}", path.display()))?;
    let mut seen = HashSet::new();
    for line in BufReader::new(f).lines() {
        let line = line.context("read_dedup_keys: read line")?;
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(entry) = serde_json::from_str::<QueueEntry>(&line) {
            seen.insert(entry.dedup_key());
        }
    }
    Ok(seen)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry_watch::Registry;
    use tempfile::TempDir;

    fn upload(name: &str, version: &str) -> PackageUpload {
        PackageUpload {
            registry: Registry::Npm,
            name: name.into(),
            version: version.into(),
            published_at: None,
            maintainer_count: None,
            has_install_scripts: false,
            description: None,
        }
    }

    #[test]
    fn append_then_read_round_trips() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("watch.ndjson");
        let mut q = WatchQueue::load(path.clone()).unwrap();
        assert!(q
            .append_if_new(upload("foo", "1.0.0"), 42, "t1".into())
            .unwrap());
        assert!(q
            .append_if_new(upload("bar", "0.0.1"), 80, "t2".into())
            .unwrap());
        let entries = q.read_entries().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].upload.name, "foo");
        assert_eq!(entries[0].score, 42);
        assert_eq!(entries[1].upload.name, "bar");
    }

    #[test]
    fn dedup_blocks_repeat_enqueue() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("watch.ndjson");
        let mut q = WatchQueue::load(path.clone()).unwrap();
        assert!(q
            .append_if_new(upload("foo", "1.0.0"), 50, "t1".into())
            .unwrap());
        assert!(
            !q.append_if_new(upload("foo", "1.0.0"), 50, "t2".into())
                .unwrap(),
            "second append of same dedup key must return false"
        );
        assert_eq!(q.read_entries().unwrap().len(), 1);
    }

    #[test]
    fn dedup_persists_across_reload() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("watch.ndjson");
        {
            let mut q = WatchQueue::load(path.clone()).unwrap();
            q.append_if_new(upload("foo", "1.0.0"), 50, "t1".into())
                .unwrap();
        }
        let mut q2 = WatchQueue::load(path).unwrap();
        assert!(
            !q2.append_if_new(upload("foo", "1.0.0"), 50, "t2".into())
                .unwrap(),
            "dedup keys must survive reload"
        );
    }

    #[test]
    fn entries_above_threshold_filters() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("watch.ndjson");
        let mut q = WatchQueue::load(path).unwrap();
        q.append_if_new(upload("low", "1.0.0"), 10, "t1".into())
            .unwrap();
        q.append_if_new(upload("mid", "1.0.0"), 50, "t2".into())
            .unwrap();
        q.append_if_new(upload("high", "1.0.0"), 95, "t3".into())
            .unwrap();
        let above_60 = q.entries_above(60).unwrap();
        assert_eq!(above_60.len(), 1);
        assert_eq!(above_60[0].upload.name, "high");
    }

    #[test]
    fn read_entries_tolerates_malformed_lines() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("watch.ndjson");
        let mut q = WatchQueue::load(path.clone()).unwrap();
        q.append_if_new(upload("ok", "1.0.0"), 50, "t1".into())
            .unwrap();
        // Inject malformed line.
        use std::io::Write as _;
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        writeln!(f, "{{not-valid-json").unwrap();
        let entries = q.read_entries().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].upload.name, "ok");
    }
}
