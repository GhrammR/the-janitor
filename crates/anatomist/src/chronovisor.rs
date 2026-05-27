//! Historical vulnerability archaeology over the git object graph.
//!
//! Chronovisor replays a detector against historical blobs directly from the
//! repository object database so the engine can answer "when did this finding
//! first appear?" without writing checkout trees to disk.

use anyhow::Context as _;
use common::slop::StructuredFinding;
use forge::slop_hunter::{find_slop, ParsedUnit};
use git2::{ObjectType, Repository, Sort, Tree};
use std::path::{Path, PathBuf};

/// Historical origin metadata for a structured finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingOrigin {
    /// Commit SHA where the finding first appears in history.
    pub commit_sha: String,
    /// Commit timestamp as Unix epoch seconds.
    pub timestamp_unix: i64,
    /// Commit timezone offset in minutes from UTC.
    pub offset_minutes: i32,
}

/// Git-backed vulnerability archaeology engine.
pub struct Chronovisor {
    repo: Repository,
    repo_root: PathBuf,
}

impl Chronovisor {
    /// Open the git repository containing `path`.
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let repo = Repository::discover(path)
            .with_context(|| format!("failed to discover git repository for {}", path.display()))?;
        let repo_root = repo
            .workdir()
            .map(Path::to_path_buf)
            .or_else(|| repo.path().parent().map(Path::to_path_buf))
            .context("repository has no accessible workdir")?;
        Ok(Self { repo, repo_root })
    }

    /// Walk history and return the first commit where `finding` appears.
    pub fn first_introduction(
        &self,
        finding: &StructuredFinding,
    ) -> anyhow::Result<Option<FindingOrigin>> {
        let relative_path = resolve_relative_path(&self.repo_root, finding)?;
        let detector = Detector::for_finding(finding, &relative_path);

        let mut revwalk = self.repo.revwalk().context("create git revwalk")?;
        revwalk.push_head().context("push HEAD into revwalk")?;
        revwalk
            .set_sorting(Sort::TOPOLOGICAL | Sort::REVERSE)
            .context("set revwalk ordering")?;

        for oid in revwalk {
            let oid = oid.context("read revwalk entry")?;
            let commit = self.repo.find_commit(oid).context("load commit")?;
            let tree = commit.tree().context("load commit tree")?;
            let present_in_commit = self.file_has_finding(&tree, &relative_path, &detector)?;
            if !present_in_commit {
                continue;
            }

            let present_in_parent = if let Some(parent) = commit.parents().next() {
                let parent_tree = parent.tree().context("load parent tree")?;
                self.file_has_finding(&parent_tree, &relative_path, &detector)?
            } else {
                false
            };

            if !present_in_parent {
                let time = commit.time();
                return Ok(Some(FindingOrigin {
                    commit_sha: oid.to_string(),
                    timestamp_unix: time.seconds(),
                    offset_minutes: time.offset_minutes(),
                }));
            }
        }

        Ok(None)
    }

    fn file_has_finding(
        &self,
        tree: &Tree<'_>,
        relative_path: &Path,
        detector: &Detector<'_>,
    ) -> anyhow::Result<bool> {
        let Ok(entry) = tree.get_path(relative_path) else {
            return Ok(false);
        };
        if entry.kind() != Some(ObjectType::Blob) {
            return Ok(false);
        }
        let blob = self.repo.find_blob(entry.id()).context("load blob")?;
        Ok(detector.matches(blob.content()))
    }
}

fn resolve_relative_path(repo_root: &Path, finding: &StructuredFinding) -> anyhow::Result<PathBuf> {
    let raw = finding
        .file
        .as_deref()
        .context("finding has no file path; Chronovisor requires a file-backed finding")?;
    let path = Path::new(raw);
    if path.is_absolute() {
        return path
            .strip_prefix(repo_root)
            .map(Path::to_path_buf)
            .with_context(|| format!("finding path {} is outside repo root", path.display()));
    }
    Ok(path.to_path_buf())
}

struct Detector<'a> {
    finding_id: &'a str,
    ext: String,
    label: String,
}

impl<'a> Detector<'a> {
    fn for_finding(finding: &'a StructuredFinding, relative_path: &Path) -> Self {
        let ext = relative_path
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        Self {
            finding_id: &finding.id,
            ext,
            label: relative_path.to_string_lossy().to_string(),
        }
    }

    fn matches(&self, source: &[u8]) -> bool {
        if self.matches_specialized(source) {
            return true;
        }
        let parsed = ParsedUnit::unparsed(source);
        find_slop(&self.ext, &parsed, "")
            .into_iter()
            .any(|finding| extract_rule_id(&finding.description) == self.finding_id)
    }

    fn matches_specialized(&self, source: &[u8]) -> bool {
        if self.finding_id == "security:embedded_executable_blob" {
            return forge::stego_binary::detect_embedded_executable_blob(source, &self.label)
                .into_iter()
                .any(|finding| finding.id == self.finding_id);
        }
        if self.finding_id == "security:agent_intent_misalignment" {
            return forge::llm_decompile::detect_agent_intent_misalignment(
                &self.ext,
                source,
                &self.label,
            )
            .into_iter()
            .any(|finding| finding.id == self.finding_id);
        }
        if self.finding_id == "security:training_data_trojan" {
            return forge::dataset_poisoning::detect_training_data_trojan(
                &self.ext,
                source,
                &self.label,
            )
            .into_iter()
            .any(|finding| finding.id == self.finding_id);
        }
        if self.finding_id == "security:unpinned_model_weights" {
            return forge::model_pinning::detect_unpinned_model_revisions(
                &self.ext,
                source,
                &self.label,
            )
            .into_iter()
            .any(|finding| finding.id == self.finding_id);
        }
        if self.finding_id.starts_with("security:") {
            return forge::idor::scan_source(&self.ext, source, &self.label)
                .into_iter()
                .any(|finding| finding.id == self.finding_id)
                || forge::agentic_graph::find_agentic_privilege_escalations(
                    &self.ext,
                    source,
                    &self.label,
                )
                .into_iter()
                .any(|finding| finding.id == self.finding_id)
                || forge::agentic_tool_audit::find_bare_metal_agentic_loops(
                    &self.ext,
                    source,
                    &self.label,
                )
                .into_iter()
                .any(|finding| finding.id == self.finding_id)
                || forge::swarm_exfil::detect_context_exfil(source, &self.label)
                    .into_iter()
                    .any(|finding| finding.id == self.finding_id);
        }
        false
    }
}

fn extract_rule_id(description: &str) -> &str {
    description
        .split(" \u{2014} ")
        .next()
        .unwrap_or(description)
}

#[cfg(test)]
mod tests {
    use super::*;
    use git2::{Oid, Signature};
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn first_introduction_detects_historical_unsafe_string_function() {
        let tmp = tempdir().unwrap();
        let repo = Repository::init(tmp.path()).unwrap();
        let sig = Signature::now("Janitor", "janitor@example.com").unwrap();
        let src_dir = tmp.path().join("src");
        fs::create_dir_all(&src_dir).unwrap();
        let file_path = src_dir.join("main.c");

        fs::write(
            &file_path,
            "void copy(char *dst, const char *src) { snprintf(dst, 16, \"%s\", src); }\n",
        )
        .unwrap();
        let first_commit = commit_all(&repo, &sig, "safe");

        fs::write(
            &file_path,
            "void copy(char *dst, const char *src) { strcpy(dst, src); }\n",
        )
        .unwrap();
        let vuln_commit = commit_all(&repo, &sig, "introduce strcpy");

        fs::write(
            &file_path,
            "void copy(char *dst, const char *src) { strcpy(dst, src); /* still vulnerable */ }\n",
        )
        .unwrap();
        commit_all(&repo, &sig, "keep strcpy");

        let finding = StructuredFinding {
            id: "security:unsafe_string_function".to_string(),
            file: Some("src/main.c".to_string()),
            ..Default::default()
        };
        let chronovisor = Chronovisor::open(tmp.path()).unwrap();
        let origin = chronovisor.first_introduction(&finding).unwrap().unwrap();

        assert_eq!(origin.commit_sha, vuln_commit.to_string());
        assert_ne!(origin.commit_sha, first_commit.to_string());
    }

    #[test]
    fn first_introduction_returns_none_when_finding_never_appears() {
        let tmp = tempdir().unwrap();
        let repo = Repository::init(tmp.path()).unwrap();
        let sig = Signature::now("Janitor", "janitor@example.com").unwrap();
        let src_dir = tmp.path().join("src");
        fs::create_dir_all(&src_dir).unwrap();
        let file_path = src_dir.join("main.c");

        fs::write(
            &file_path,
            "void copy(char *dst, const char *src) { snprintf(dst, 16, \"%s\", src); }\n",
        )
        .unwrap();
        commit_all(&repo, &sig, "safe");

        let finding = StructuredFinding {
            id: "security:unsafe_string_function".to_string(),
            file: Some("src/main.c".to_string()),
            ..Default::default()
        };
        let chronovisor = Chronovisor::open(tmp.path()).unwrap();
        let origin = chronovisor.first_introduction(&finding).unwrap();
        assert!(origin.is_none());
    }

    fn commit_all(repo: &Repository, sig: &Signature<'_>, message: &str) -> Oid {
        let mut index = repo.index().unwrap();
        index
            .add_all(["*"], git2::IndexAddOption::DEFAULT, None)
            .unwrap();
        index.write().unwrap();
        let tree_id = index.write_tree().unwrap();
        let tree = repo.find_tree(tree_id).unwrap();
        let parent = repo
            .head()
            .ok()
            .and_then(|head| head.target())
            .and_then(|oid| repo.find_commit(oid).ok());
        let parents: Vec<&git2::Commit<'_>> = parent.iter().collect();
        repo.commit(Some("HEAD"), sig, sig, message, &tree, &parents)
            .unwrap()
    }
}
