use anyhow::Context as _;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const SCHEMA_VERSION: &str = "janitor.target-ledger.v1";

const SEED_ATTACK_KEYWORDS: &[&str] = &[
    "OAuth",
    "Azure",
    "Terraform",
    "LLM",
    "GraphQL",
    "SAML",
    "OIDC",
    "Auth0",
    "Kubernetes",
    "GitHub",
    "Microsoft Graph",
    "RAG",
    "MCP",
];

const LANGUAGE_HINTS: &[(&str, &str)] = &[
    ("rust", "Rust"),
    ("cargo", "Rust"),
    ("go", "Go"),
    ("golang", "Go"),
    ("python", "Python"),
    ("django", "Python"),
    ("fastapi", "Python"),
    ("java", "Java"),
    ("spring", "Java"),
    ("javascript", "JavaScript"),
    ("typescript", "TypeScript"),
    ("js/ts", "JS/TS"),
    ("react", "TypeScript"),
    ("node", "JavaScript"),
    ("solidity", "Solidity"),
    ("evm", "Solidity"),
    ("terraform", "Terraform"),
    ("graphql", "GraphQL"),
    ("azure", "Azure"),
    ("llm", "LLM"),
    ("oauth", "OAuth"),
];

#[derive(Debug, Serialize)]
struct TargetLedger {
    schema_version: &'static str,
    generated_by: &'static str,
    attack_ledger_keywords: Vec<String>,
    targets: Vec<CampaignTarget>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct CampaignTarget {
    engagement: String,
    source_file: String,
    line_number: usize,
    target: String,
    urls: Vec<String>,
    language_tags: Vec<String>,
    matched_attack_keywords: Vec<String>,
    priority_score: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hunted: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hunt_result: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    covered_by: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ExistingTargetLedger {
    #[serde(default)]
    targets: Vec<CampaignTarget>,
}

#[derive(Debug, Default, Clone)]
struct TargetState {
    hunted: Option<bool>,
    hunt_result: Option<String>,
    covered_by: Option<String>,
}

pub(crate) fn cmd_ingest_campaigns(dir: &Path) -> anyhow::Result<()> {
    let output_path = ingest_campaigns(dir)?;
    println!("wrote {}", output_path.display());
    Ok(())
}

fn ingest_campaigns(dir: &Path) -> anyhow::Result<PathBuf> {
    anyhow::ensure!(
        dir.is_dir(),
        "campaign ingestion path is not a directory: {}",
        dir.display()
    );

    let attack_ledger = load_attack_ledger(dir)?;
    let keywords = attack_keywords(&attack_ledger);
    let prior_state = load_existing_target_state(&dir.join("target_ledger.json"))?;
    let mut targets = Vec::new();

    for path in markdown_files(dir)? {
        if path
            .file_name()
            .is_some_and(|name| name == "ATTACK_LEDGER.md" || name == "TARGET_LEDGER.md")
        {
            continue;
        }
        ingest_file(dir, &path, &keywords, &mut targets)?;
    }

    targets = deduplicate_targets(targets, &prior_state);
    targets.sort_by(|left, right| {
        right
            .priority_score
            .cmp(&left.priority_score)
            .then_with(|| left.engagement.cmp(&right.engagement))
            .then_with(|| left.target.cmp(&right.target))
    });

    let ledger = TargetLedger {
        schema_version: SCHEMA_VERSION,
        generated_by: "janitor ingest-campaigns",
        attack_ledger_keywords: keywords.iter().cloned().collect(),
        targets,
    };
    let output_path = dir.join("target_ledger.json");
    let json = serde_json::to_vec_pretty(&ledger).context("serialize target ledger")?;
    fs::write(&output_path, json).with_context(|| {
        format!(
            "failed to write campaign target ledger to {}",
            output_path.display()
        )
    })?;
    Ok(output_path)
}

fn load_attack_ledger(dir: &Path) -> anyhow::Result<String> {
    let candidates = [
        dir.join("ATTACK_LEDGER.md"),
        PathBuf::from("tools/campaign/ATTACK_LEDGER.md"),
    ];
    for candidate in candidates {
        if candidate.is_file() {
            return fs::read_to_string(&candidate)
                .with_context(|| format!("failed to read {}", candidate.display()));
        }
    }
    Ok(String::new())
}

fn markdown_files(dir: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let root = dir.join("targets");
    let walk_root = if root.is_dir() {
        root
    } else {
        dir.to_path_buf()
    };
    let mut files = Vec::new();
    for entry in walkdir::WalkDir::new(&walk_root).follow_links(false) {
        let entry = entry.with_context(|| format!("failed to walk {}", walk_root.display()))?;
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.into_path();
        if path.extension().is_some_and(|ext| ext == "md") && !is_generated_campaign_ledger(&path) {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

fn is_generated_campaign_ledger(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            matches!(
                name,
                "ATTACK_LEDGER.md"
                    | "TARGET_LEDGER.md"
                    | "BOUNTY_LEDGER.md"
                    | "CANDIDATE_LEDGER.md"
                    | "LOW_YIELD_LEDGER.md"
            )
        })
}

fn ingest_file(
    root: &Path,
    path: &Path,
    attack_keywords: &BTreeSet<String>,
    targets: &mut Vec<CampaignTarget>,
) -> anyhow::Result<()> {
    let source = fs::read_to_string(path)
        .with_context(|| format!("failed to read campaign file {}", path.display()))?;
    let engagement = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("unknown")
        .to_string();
    let source_file = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");

    for (idx, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        let urls = extract_urls(trimmed);
        if !is_target_line(trimmed, &urls) {
            continue;
        }

        let language_tags = language_tags(trimmed);
        let matched_attack_keywords = matched_keywords(trimmed, attack_keywords);
        let priority_score =
            priority_score(trimmed, &urls, &language_tags, &matched_attack_keywords);
        targets.push(CampaignTarget {
            engagement: engagement.clone(),
            source_file: source_file.clone(),
            line_number: idx + 1,
            target: normalize_target(trimmed),
            urls,
            language_tags,
            matched_attack_keywords,
            priority_score,
            hunted: None,
            hunt_result: None,
            covered_by: None,
        });
    }
    Ok(())
}

fn load_existing_target_state(path: &Path) -> anyhow::Result<BTreeMap<String, TargetState>> {
    if !path.is_file() {
        return Ok(BTreeMap::new());
    }
    let content =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let ledger: ExistingTargetLedger = serde_json::from_str(&content)
        .with_context(|| format!("failed to parse existing target ledger {}", path.display()))?;
    let mut state = BTreeMap::new();
    for target in ledger.targets {
        let key = canonical_target_key(&target);
        let entry = state.entry(key).or_default();
        merge_target_state(entry, &target);
    }
    Ok(state)
}

fn merge_target_state(state: &mut TargetState, target: &CampaignTarget) {
    if target.hunted == Some(true) {
        state.hunted = Some(true);
    }
    if state.hunt_result.is_none() {
        state.hunt_result = target.hunt_result.clone();
    }
    if state.covered_by.is_none() {
        state.covered_by = target.covered_by.clone();
    }
}

fn deduplicate_targets(
    targets: Vec<CampaignTarget>,
    prior_state: &BTreeMap<String, TargetState>,
) -> Vec<CampaignTarget> {
    let mut deduped: BTreeMap<String, CampaignTarget> = BTreeMap::new();

    for mut target in targets {
        if let Some(state) = prior_state.get(&canonical_target_key(&target)) {
            target.hunted = state.hunted;
            target.hunt_result = state.hunt_result.clone();
            target.covered_by = state.covered_by.clone();
        }

        let key = canonical_target_key(&target);
        if let Some(existing) = deduped.get_mut(&key) {
            merge_duplicate_target(existing, target);
        } else {
            deduped.insert(key, target);
        }
    }

    deduped.into_values().collect()
}

fn merge_duplicate_target(existing: &mut CampaignTarget, candidate: CampaignTarget) {
    if candidate.priority_score > existing.priority_score {
        existing.engagement = candidate.engagement.clone();
        existing.source_file = candidate.source_file.clone();
        existing.line_number = candidate.line_number;
        existing.target = candidate.target.clone();
        existing.priority_score = candidate.priority_score;
    }
    merge_unique_strings(&mut existing.urls, candidate.urls);
    merge_unique_strings(&mut existing.language_tags, candidate.language_tags);
    merge_unique_strings(
        &mut existing.matched_attack_keywords,
        candidate.matched_attack_keywords,
    );
    if existing.hunted != Some(true) {
        existing.hunted = candidate.hunted;
    }
    if existing.hunt_result.is_none() {
        existing.hunt_result = candidate.hunt_result;
    }
    if existing.covered_by.is_none() {
        existing.covered_by = candidate.covered_by;
    }
}

fn merge_unique_strings(existing: &mut Vec<String>, incoming: Vec<String>) {
    let mut merged = existing.iter().cloned().collect::<BTreeSet<_>>();
    merged.extend(incoming);
    *existing = merged.into_iter().collect();
}

fn canonical_target_key(target: &CampaignTarget) -> String {
    let github_repos = target
        .urls
        .iter()
        .filter_map(|url| github_repo_key(url))
        .collect::<BTreeSet<_>>();
    if github_repos.len() == 1 {
        return format!(
            "github:{}",
            github_repos.into_iter().next().unwrap_or_default()
        );
    }
    format!("literal:{}", normalize_literal_key(&target.target))
}

fn github_repo_key(url: &str) -> Option<String> {
    let trimmed = url.trim();
    let rest = trimmed
        .strip_prefix("https://github.com/")
        .or_else(|| trimmed.strip_prefix("http://github.com/"))?;
    let repo_path = rest
        .split(['?', '#'])
        .next()
        .unwrap_or(rest)
        .trim_end_matches('/');
    let mut segments = repo_path.split('/').filter(|segment| !segment.is_empty());
    let owner = segments.next()?.to_ascii_lowercase();
    let repo = segments
        .next()?
        .trim_end_matches(".git")
        .to_ascii_lowercase();
    if owner.is_empty() || repo.is_empty() {
        return None;
    }
    Some(format!("{owner}/{repo}"))
}

fn normalize_literal_key(target: &str) -> String {
    target
        .trim()
        .to_ascii_lowercase()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '/' | ':' | '-' | '_' | '.') {
                ch
            } else {
                ' '
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn is_target_line(line: &str, urls: &[String]) -> bool {
    line.starts_with("- [ ]")
        || line.starts_with("* [ ]")
        || line.starts_with("[ ]")
        || (!urls.is_empty()
            && !line.starts_with('>')
            && !line.starts_with('#')
            && !line.to_ascii_lowercase().contains("http status"))
}

fn normalize_target(line: &str) -> String {
    line.trim_start_matches("- [ ]")
        .trim_start_matches("* [ ]")
        .trim_start_matches("[ ]")
        .trim()
        .to_string()
}

fn attack_keywords(attack_ledger: &str) -> BTreeSet<String> {
    let mut keywords = BTreeSet::new();
    for keyword in SEED_ATTACK_KEYWORDS {
        if attack_ledger.is_empty()
            || attack_ledger
                .to_ascii_lowercase()
                .contains(&keyword.to_ascii_lowercase())
        {
            keywords.insert((*keyword).to_string());
        }
    }
    keywords
}

fn language_tags(line: &str) -> Vec<String> {
    let lower = line.to_ascii_lowercase();
    let mut tags = BTreeSet::new();
    for (needle, tag) in LANGUAGE_HINTS {
        if lower.contains(needle) {
            tags.insert((*tag).to_string());
        }
    }
    tags.into_iter().collect()
}

fn matched_keywords(line: &str, attack_keywords: &BTreeSet<String>) -> Vec<String> {
    let lower = line.to_ascii_lowercase();
    attack_keywords
        .iter()
        .filter(|keyword| lower.contains(&keyword.to_ascii_lowercase()))
        .cloned()
        .collect()
}

fn priority_score(
    line: &str,
    urls: &[String],
    language_tags: &[String],
    matched_attack_keywords: &[String],
) -> u32 {
    let mut score = 10;
    if line.starts_with("- [ ]") || line.starts_with("* [ ]") || line.starts_with("[ ]") {
        score += 5;
    }
    score += (urls.len() as u32).saturating_mul(2);
    score += (language_tags.len() as u32).saturating_mul(3);
    score += (matched_attack_keywords.len() as u32).saturating_mul(20);
    score
}

fn extract_urls(line: &str) -> Vec<String> {
    let mut urls = BTreeSet::new();
    for token in line.split(|ch: char| ch.is_whitespace() || ch == '(' || ch == ')' || ch == ',') {
        let clean = token.trim_matches(|ch: char| {
            matches!(
                ch,
                '`' | '\'' | '"' | '[' | ']' | '<' | '>' | '{' | '}' | '.' | ';' | ':'
            )
        });
        if clean.starts_with("https://") || clean.starts_with("http://") {
            urls.insert(clean.to_string());
        }
    }
    urls.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oauth_target_ranks_above_generic_target() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        fs::write(
            tmp.path().join("ATTACK_LEDGER.md"),
            "## OAuth Scope Drift\n## GraphQL Exposure\n",
        )
        .expect("write attack ledger");
        fs::write(
            tmp.path().join("targets.md"),
            "- [ ] https://generic.example.com static marketing site\n\
             - [ ] https://auth.example.com OAuth JS/TS integration API\n",
        )
        .expect("write campaign file");

        let output = ingest_campaigns(tmp.path()).expect("ingest campaigns");
        let json = fs::read_to_string(output).expect("read output");
        let ledger: serde_json::Value = serde_json::from_str(&json).expect("parse output");
        let targets = ledger["targets"].as_array().expect("targets array");

        assert!(targets[0]["target"]
            .as_str()
            .expect("target")
            .contains("OAuth"));
        assert!(
            targets[0]["priority_score"].as_u64().expect("score")
                > targets[1]["priority_score"].as_u64().expect("score")
        );
    }

    #[test]
    fn deduplicates_github_variants_and_preserves_hunt_state() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        fs::write(tmp.path().join("ATTACK_LEDGER.md"), "## GitHub Scope\n")
            .expect("write attack ledger");
        fs::write(
            tmp.path().join("targets.md"),
            "https://github.com/freedomofpress/securedrop-client\n\
             https://github.com/freedomofpress/securedrop-client/\n\
             https://github.com/freedomofpress/securedrop-client.git\n",
        )
        .expect("write campaign file");
        fs::write(
            tmp.path().join("target_ledger.json"),
            r#"{
  "schema_version":"janitor.target-ledger.v1",
  "generated_by":"janitor ingest-campaigns",
  "attack_ledger_keywords":["GitHub"],
  "targets":[
    {
      "engagement":"legacy",
      "source_file":"targets.md",
      "line_number":1,
      "target":"https://github.com/freedomofpress/securedrop-client",
      "urls":["https://github.com/freedomofpress/securedrop-client"],
      "language_tags":[],
      "matched_attack_keywords":["GitHub"],
      "priority_score":32,
      "hunted":true,
      "hunt_result":"no_findings"
    }
  ]
}"#,
        )
        .expect("seed target ledger");

        let output = ingest_campaigns(tmp.path()).expect("ingest campaigns");
        let json = fs::read_to_string(output).expect("read output");
        let ledger: ExistingTargetLedger = serde_json::from_str(&json).expect("parse output");

        assert_eq!(ledger.targets.len(), 1);
        assert_eq!(ledger.targets[0].hunted, Some(true));
        assert_eq!(
            ledger.targets[0].hunt_result.as_deref(),
            Some("no_findings")
        );
    }
}
