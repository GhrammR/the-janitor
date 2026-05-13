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

const VECTOR_STORE_QUERY_MARKERS: &[&[u8]] = &[
    b"chromadb.query",
    b"pinecone.query",
    b"weaviate.query",
    b"milvus.search",
    b"qdrant.search",
    b"similaritysearch",
    b"similarity_search",
    b"vectorstore.query",
    b"index.query",
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

const FILTER_MARKERS: &[&[u8]] = &[
    b"filter:",
    b"filter =",
    b"filter=",
    b"where:",
    b"where =",
    b"where=",
    b"query_filter",
    b"metadata_filter",
    b"metadatafilter",
];

const DYNAMIC_FILTER_MARKERS: &[&[u8]] = &[
    b"req.query",
    b"req.body",
    b"request.args",
    b"request.json",
    b"ctx.query",
    b"params.",
    b"json.parse",
    b"input.filter",
    b"user_filter",
    b"userfilter",
];

const POLYMORPHIC_PREDICATE_MARKERS: &[&[u8]] = &[
    b"$or",
    b"$ne",
    b"$in",
    b"operator",
    b"where_document",
    b"...req.",
    b"...request.",
    b"...params.",
];

const AUTHORITATIVE_TENANT_MARKERS: &[&[u8]] = &[
    b"tenant_id: req.user.tenant_id",
    b"tenant_id:req.user.tenant_id",
    b"tenant_id: session.tenant_id",
    b"tenant_id: auth.tenant_id",
    b"tenantid: req.user.tenantid",
    b"namespace: req.user.tenant_id",
    b"namespace: session.tenant_id",
];

/// Detect vector-query results that flow into an LLM sink without visible
/// semantic or similarity-score validation.
pub fn detect_vector_store_poisoning(source: &[u8]) -> Vec<SlopFinding> {
    let lower = ascii_lower(source);
    let Some(query_offset) = first_offset(&lower, QUERY_MARKERS) else {
        return Vec::new();
    };
    let mut findings = Vec::new();

    if has_vector_filter_predicate_polymorphism(&lower) {
        findings.push(SlopFinding {
            start_byte: query_offset,
            end_byte: query_offset.saturating_add(32),
            description: "security:vector_filter_polymorphism — vector-store query accepts attacker-shaped metadata filter predicates without a server-side tenant equality guard; a crafted $or/$ne predicate can cross tenant retrieval boundaries before answer synthesis.".to_string(),
            domain: DOMAIN_FIRST_PARTY,
            severity: Severity::High,
        });
    }

    if !contains_any_bytes(&lower, RESULT_MARKERS) || !contains_any_bytes(&lower, LLM_SINK_MARKERS)
    {
        return findings;
    }
    if contains_any_bytes(&lower, VALIDATION_MARKERS) {
        return findings;
    }

    findings.push(SlopFinding {
        start_byte: query_offset,
        end_byte: query_offset.saturating_add(32),
        description: "security:vector_store_poisoning — vector-query results flow into an LLM context sink without a visible semantic rerank or similarity-score threshold; a poisoned document can become the retrieval bridge into trusted answer space.".to_string(),
        domain: DOMAIN_FIRST_PARTY,
        severity: Severity::High,
    });
    findings
}

fn has_vector_filter_predicate_polymorphism(lower: &[u8]) -> bool {
    if !contains_any_bytes(lower, VECTOR_STORE_QUERY_MARKERS)
        || !contains_any_bytes(lower, FILTER_MARKERS)
    {
        return false;
    }

    let dynamic_filter = contains_any_bytes(lower, DYNAMIC_FILTER_MARKERS);
    let polymorphic_predicate = contains_any_bytes(lower, POLYMORPHIC_PREDICATE_MARKERS);
    if !dynamic_filter && !polymorphic_predicate {
        return false;
    }

    let authoritative_tenant_guard = contains_any_bytes(lower, AUTHORITATIVE_TENANT_MARKERS);
    if authoritative_tenant_guard && !polymorphic_predicate {
        return false;
    }

    true
}

/// Returns `true` when a data-dependency chain is proven between a vector-query
/// result variable and a downstream LLM answer-synthesis call in the same source
/// unit.
///
/// The proof requires:
/// 1. A RAG query call whose result is assigned to a named identifier.
/// 2. That same identifier appears inside the argument list of a subsequent
///    LLM sink call, establishing structural data-flow linkage.
///
/// Returns `false` when the identifier returned by the query is never passed
/// to the LLM sink (the call sites are unlinked), demoting the finding to
/// Informational.
pub fn requires_rag_answer_sink_dataflow(source: &[u8], ext: &str) -> bool {
    if !matches!(ext, "py" | "ts" | "js" | "go") {
        return false;
    }
    let lower = ascii_lower(source);

    // Step 1: Locate first query marker.
    let Some(query_pos) = first_offset(&lower, QUERY_MARKERS) else {
        return false;
    };

    // Step 2: Extract the assigned variable from `<var> =` or `<var> :=` before the query.
    let window_start = query_pos.saturating_sub(200);
    let before_query = &source[window_start..query_pos];
    let Some(var_name) = extract_assignment_lhs(before_query) else {
        return false;
    };

    // Step 3: Find an LLM sink marker that appears AFTER the query.
    let after_query_lower = &lower[query_pos..];
    let Some(sink_rel) = LLM_SINK_MARKERS
        .iter()
        .filter_map(|m| after_query_lower.windows(m.len()).position(|w| w == *m))
        .min()
    else {
        return false;
    };
    let sink_pos = query_pos + sink_rel;

    // Step 4: Find the argument span of the LLM sink call (from `(` to `)`).
    let call_suffix = &source[sink_pos..];
    let paren_open = call_suffix.iter().position(|&b| b == b'(').unwrap_or(0);
    let arg_start = sink_pos + paren_open;
    let arg_end = find_matching_paren(source, arg_start).unwrap_or(arg_start + 512);

    // Step 5: Check if var_name appears inside the argument region.
    let arg_region = &source[arg_start..arg_end.min(source.len())];
    arg_region
        .windows(var_name.len())
        .any(|w| w == var_name.as_slice())
}

/// Extracts the left-hand-side identifier from the last assignment expression
/// (`<var> =` or `<var> :=`) present in `buf`.
fn extract_assignment_lhs(buf: &[u8]) -> Option<Vec<u8>> {
    let mut i = buf.len();
    while i > 0 {
        i -= 1;
        if buf[i] != b'=' {
            continue;
        }
        let prev = if i > 0 { buf[i - 1] } else { 0 };
        let next = if i + 1 < buf.len() { buf[i + 1] } else { 0 };
        // Skip `==`, `!=`, `<=`, `>=`
        if matches!(prev, b'!' | b'<' | b'>' | b'=') || next == b'=' {
            continue;
        }
        // Handle `:=` (Go short declaration) — strip the `:` from lhs boundary
        let lhs_end_idx = if prev == b':' { i.saturating_sub(1) } else { i };
        let lhs_source = &buf[..lhs_end_idx];
        let end = match lhs_source.iter().rposition(|&b| !b.is_ascii_whitespace()) {
            Some(e) => e,
            None => continue,
        };
        if !lhs_source[end].is_ascii_alphanumeric() && lhs_source[end] != b'_' {
            continue;
        }
        let mut start = end;
        while start > 0
            && (lhs_source[start - 1].is_ascii_alphanumeric() || lhs_source[start - 1] == b'_')
        {
            start -= 1;
        }
        let word = &lhs_source[start..=end];
        if !word.is_empty() && (word[0].is_ascii_alphabetic() || word[0] == b'_') {
            return Some(word.to_vec());
        }
    }
    None
}

/// Returns the byte position immediately after the closing `)` that matches
/// the opening `(` at `open_pos`, or `None` if unmatched.
fn find_matching_paren(source: &[u8], open_pos: usize) -> Option<usize> {
    if open_pos >= source.len() || source[open_pos] != b'(' {
        return None;
    }
    let mut depth: usize = 0;
    for (offset, &b) in source[open_pos..].iter().enumerate() {
        match b {
            b'(' => depth += 1,
            b')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(open_pos + offset + 1);
                }
            }
            _ => {}
        }
    }
    None
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
    use super::{detect_vector_store_poisoning, requires_rag_answer_sink_dataflow};

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

    #[test]
    fn vector_filter_polymorphism_fires_for_user_supplied_filter() {
        let src = br#"
async function answer(req) {
  const filter = JSON.parse(req.query.filter);
  const results = await pinecone.query({ vector: embed(req.body.prompt), topK: 6, filter });
  return openai.chat.completions.create({
    messages: [{ role: "user", content: results.matches[0].metadata.page_content }]
  });
}
"#;
        let findings = detect_vector_store_poisoning(src);
        assert!(findings.iter().any(|finding| finding
            .description
            .contains("security:vector_filter_polymorphism")));
    }

    #[test]
    fn vector_filter_polymorphism_fires_for_operator_override() {
        let src = br#"
async function answer(req) {
  const results = await pinecone.query({
    vector: embed(req.body.prompt),
    filter: { tenant_id: req.user.tenant_id, ...req.query.filter, "$or": req.query.or },
    topK: 6
  });
  return client.chat.completions.create({
    messages: [{ role: "user", content: results.matches[0].metadata.page_content }]
  });
}
"#;
        let findings = detect_vector_store_poisoning(src);
        assert!(findings.iter().any(|finding| finding
            .description
            .contains("security:vector_filter_polymorphism")));
    }

    #[test]
    fn authoritative_tenant_filter_suppresses_polymorphism() {
        let src = br#"
async function answer(req) {
  const results = await pinecone.query({
    vector: embed(req.body.prompt),
    filter: { tenant_id: req.user.tenant_id, document_type: "policy" },
    topK: 6,
    score_threshold: 0.91
  });
  return client.chat.completions.create({
    messages: [{ role: "user", content: results.matches[0].metadata.page_content }]
  });
}
"#;
        assert!(detect_vector_store_poisoning(src).is_empty());
    }

    // ── P2-12: RAG dataflow proof tests ────────────────────────────────────

    /// TP: query result variable is passed as argument to LLM invoke → proven.
    #[test]
    fn rag_dataflow_proven_when_var_flows_to_sink() {
        let src = br#"
docs = index.query(question, topK=5)
answer = llm.invoke({"context": docs[0].page_content, "question": question})
"#;
        assert!(
            requires_rag_answer_sink_dataflow(src, "py"),
            "query result variable 'docs' passed to llm.invoke must prove dataflow"
        );
    }

    /// TN: query result variable is never passed to the LLM sink → not proven.
    #[test]
    fn rag_dataflow_not_proven_when_var_unlinked() {
        let src = br#"
docs = index.query(question, topK=5)
answer = llm.invoke({"question": question})
"#;
        assert!(
            !requires_rag_answer_sink_dataflow(src, "py"),
            "when 'docs' is not passed to llm.invoke the dataflow must not be proven"
        );
    }

    /// TN: non-RAG extension returns false without scanning.
    #[test]
    fn rag_dataflow_false_for_non_rag_ext() {
        let src = br#"
results = index.query(prompt)
llm.invoke(results)
"#;
        assert!(
            !requires_rag_answer_sink_dataflow(src, "rs"),
            "Rust files must not be evaluated for RAG dataflow"
        );
    }

    /// TP: Go short-declaration `:=` syntax for query assignment.
    #[test]
    fn rag_dataflow_proven_for_go_short_decl() {
        let src = br#"
results := index.query(ctx, queryVec, 5)
resp, _ := llm.invoke(context.Background(), results[0].Metadata["text"])
"#;
        assert!(
            requires_rag_answer_sink_dataflow(src, "go"),
            "Go := query result variable passed to llm.invoke must prove dataflow"
        );
    }
}
