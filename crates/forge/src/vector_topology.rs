//! Vector-store topology poisoning detector.

use crate::metadata::DOMAIN_FIRST_PARTY;
use crate::slop_hunter::{Severity, SlopFinding};

const QUERY_MARKERS: &[&[u8]] = &[
    b"chromadb.query",
    b"pinecone.query",
    b"weaviate.query",
    b"milvus.search",
    b"qdrant.search",
    b"similaritysearch",
    b"similarity_search",
    b"vectorstore.query",
    b"index.query",
    b".query(",
];

const RESULT_MARKERS: &[&[u8]] = &[
    b"matches[0]",
    b"results[0]",
    b"documents[0]",
    b"context = results",
    b"context=results",
    b"page_content",
    b"metadata.text",
    b"retrieved_docs",
    b"retriever.invoke",
];

const LLM_SINK_MARKERS: &[&[u8]] = &[
    b"openai.chat.completions.create",
    b"client.chat.completions.create",
    b"anthropic.messages.create",
    b"messages.create",
    b"llm.invoke",
    b"gpt-4-vision-preview",
    b"responses.create",
];

const VALIDATION_MARKERS: &[&[u8]] = &[
    b"score_threshold",
    b"similarity_threshold",
    b"distance_threshold",
    b"min_score",
    b"minsimilarity",
    b"rerank(",
    b"re_rank(",
    b"semantic_filter",
    b"trust_score",
    b"metadata_filter",
    b"threshold:",
];

/// Detect vector-query results that flow into an LLM sink without visible
/// semantic or similarity-score validation.
pub fn detect_vector_store_poisoning(source: &[u8]) -> Vec<SlopFinding> {
    let lower = ascii_lower(source);
    let Some(query_offset) = first_offset(&lower, QUERY_MARKERS) else {
        return Vec::new();
    };
    if !contains_any_bytes(&lower, RESULT_MARKERS) || !contains_any_bytes(&lower, LLM_SINK_MARKERS)
    {
        return Vec::new();
    }
    if contains_any_bytes(&lower, VALIDATION_MARKERS) {
        return Vec::new();
    }

    vec![SlopFinding {
        start_byte: query_offset,
        end_byte: query_offset.saturating_add(32),
        description: "security:vector_store_poisoning — vector-query results flow into an LLM context sink without a visible semantic rerank or similarity-score threshold; a poisoned document can become the retrieval bridge into trusted answer space.".to_string(),
        domain: DOMAIN_FIRST_PARTY,
        severity: Severity::High,
    }]
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
    use super::detect_vector_store_poisoning;

    #[test]
    fn vector_query_into_llm_without_threshold_fires() {
        let src = br#"
async function answer(req) {
  const results = await pinecone.query({ vector: embed(req.body.prompt), topK: 6 });
  return openai.chat.completions.create({
    messages: [{ role: "user", content: results.matches[0].metadata.page_content }]
  });
}
"#;
        let findings = detect_vector_store_poisoning(src);
        assert!(findings.iter().any(|finding| finding
            .description
            .contains("security:vector_store_poisoning")));
    }

    #[test]
    fn score_threshold_suppresses_vector_poisoning() {
        let src = br#"
async function answer(req) {
  const results = await pinecone.query({
    vector: embed(req.body.prompt),
    topK: 6,
    score_threshold: 0.92
  });
  return openai.chat.completions.create({
    messages: [{ role: "user", content: results.matches[0].metadata.page_content }]
  });
}
"#;
        assert!(detect_vector_store_poisoning(src).is_empty());
    }
}
