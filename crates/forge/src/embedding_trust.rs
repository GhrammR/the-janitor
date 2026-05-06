//! Embedding-manifold trust transposition detector.

use crate::metadata::DOMAIN_FIRST_PARTY;
use crate::slop_hunter::{Severity, SlopFinding};

const QUERY_MARKERS: &[&[u8]] = &[
    b"chromadb.query",
    b"pinecone.query",
    b"index.query",
    b"similaritysearch",
    b"similarity_search",
    b"astriever(",
    b"retrieve(",
    b"vectorstore.query",
];

const UNTRUSTED_INPUT_MARKERS: &[&[u8]] = &[
    b"req.query",
    b"req.body",
    b"request.args",
    b"request.json",
    b"user_input",
    b"prompt",
    b"document",
    b"chunk",
    b"page_content",
];

const TRUST_GUARD_MARKERS: &[&[u8]] = &[
    b"trust_level",
    b"trusted_only",
    b"trusted_source",
    b"source_type",
    b"namespace=\"policy\"",
    b"namespace='policy'",
    b"namespace=\"runbook\"",
    b"namespace='runbook'",
    b"where={\"trust",
    b"where={'trust",
    b"metadata_filter",
    b"filter={\"trust",
    b"filter={'trust",
    b"policy_context",
    b"runbook_context",
    b"priority_context",
    b"rerank_trusted",
    b"rerankTrusted",
];

/// Detect vector-store retrieval that can let untrusted chunks outrank policy
/// or runbook context because no explicit trust-prioritization guard is visible.
pub fn detect_embedding_trust_transposition(source: &[u8]) -> Vec<SlopFinding> {
    let lower = ascii_lower(source);
    let Some(query_offset) = first_offset(&lower, QUERY_MARKERS) else {
        return Vec::new();
    };
    if !contains_any_bytes(&lower, UNTRUSTED_INPUT_MARKERS) {
        return Vec::new();
    }
    if contains_any_bytes(&lower, TRUST_GUARD_MARKERS) {
        return Vec::new();
    }

    vec![SlopFinding {
        start_byte: query_offset,
        end_byte: query_offset.saturating_add(24),
        description: "security:embedding_trust_transposition — vector-store retrieval queries untrusted chunks without a visible trust-prioritization filter for policy or runbook context; similarity alone can transpose attacker-controlled content into trusted answer space.".to_string(),
        domain: DOMAIN_FIRST_PARTY,
        severity: Severity::Critical,
    }]
}

/// Pure helper used by tests and formal assurance.
pub fn trust_prioritization_missing(
    has_query: bool,
    has_untrusted_input: bool,
    has_guard: bool,
) -> bool {
    has_query && has_untrusted_input && !has_guard
}

fn ascii_lower(source: &[u8]) -> Vec<u8> {
    source.iter().map(u8::to_ascii_lowercase).collect()
}

fn contains_any_bytes(haystack: &[u8], needles: &[&[u8]]) -> bool {
    needles.iter().any(|needle| {
        haystack
            .windows(needle.len())
            .any(|window| window == *needle)
    })
}

fn first_offset(haystack: &[u8], needles: &[&[u8]]) -> Option<usize> {
    needles
        .iter()
        .filter_map(|needle| {
            haystack
                .windows(needle.len())
                .position(|window| window == *needle)
        })
        .min()
}

#[cfg(test)]
mod tests {
    use super::{detect_embedding_trust_transposition, trust_prioritization_missing};

    #[test]
    fn detects_untrusted_similarity_query_without_policy_guard() {
        let src = br#"
async function answer(req) {
  const results = await pinecone.query({
    vector: embed(req.body.prompt),
    topK: 6
  });
  return openai.chat.completions.create({
    messages: [{ role: "user", content: results.matches[0].metadata.page_content }]
  });
}
"#;
        let findings = detect_embedding_trust_transposition(src);
        assert!(findings
            .iter()
            .any(|f| f.description.contains("embedding_trust_transposition")));
    }

    #[test]
    fn clean_when_trusted_namespace_filter_present() {
        let src = br#"
async function answer(req) {
  const results = await pinecone.query({
    vector: embed(req.body.prompt),
    topK: 6,
    filter: {"trust_level": "policy"}
  });
  return results;
}
"#;
        assert!(detect_embedding_trust_transposition(src).is_empty());
    }

    #[test]
    fn helper_requires_query_and_untrusted_input_without_guard() {
        assert!(trust_prioritization_missing(true, true, false));
        assert!(!trust_prioritization_missing(true, true, true));
        assert!(!trust_prioritization_missing(false, true, false));
    }
}
