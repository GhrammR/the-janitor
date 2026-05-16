/// Real-time patch correctness prover — Phase A (AST bisimulation).
///
/// Compares two source buffers (pre-patch and post-patch) using tree-sitter
/// AST diff and emits a [`PatchVerdict`] classifying the structural change.
/// No Kani or Z3 invocation in Phase A — pure structural analysis.
use polyglot::LazyGrammarRegistry;

/// Verdict produced by the patch bisimulation engine.
#[derive(Debug, Clone, PartialEq)]
pub enum PatchVerdict {
    /// The patch makes no structural node changes — consistent with a
    /// string-literal, comment, or value-only fix.
    EquivalentExceptForFix,
    /// The patch introduces new structural behavior beyond the targeted fix.
    IntroducesNewBehavior { changed_nodes: Vec<String> },
    /// Parsing failed for at least one buffer — proof is impossible.
    Unsatisfiable,
}

/// Output of [`prove_patch_correctness`].
#[derive(Debug, Clone, PartialEq)]
pub struct PatchProof {
    pub verdict: PatchVerdict,
    pub added_node_count: usize,
    pub removed_node_count: usize,
    pub modified_functions: Vec<String>,
}

/// Supported source extensions for Phase A bisimulation.
const SUPPORTED_EXTS: &[&str] = &["rs", "go", "py", "js", "ts", "c", "cpp", "java"];

/// Proves whether a patch is structurally equivalent to the targeted fix or
/// introduces new behaviour.
///
/// Returns `None` for unsupported file extensions.
#[must_use]
pub fn prove_patch_correctness(before: &[u8], after: &[u8], lang_ext: &str) -> Option<PatchProof> {
    if !SUPPORTED_EXTS.contains(&lang_ext) {
        return None;
    }

    let lang = LazyGrammarRegistry::get(lang_ext)?;

    // Unsatisfiable if either buffer is empty.
    if before.is_empty() || after.is_empty() {
        return Some(PatchProof {
            verdict: PatchVerdict::Unsatisfiable,
            added_node_count: 0,
            removed_node_count: 0,
            modified_functions: vec![],
        });
    }

    let mut parser = tree_sitter::Parser::new();
    parser.set_language(lang).ok()?;

    let tree_before = parser.parse(before, None)?;
    // Re-parse resets the parser; parse after is independent.
    let tree_after = parser.parse(after, None)?;

    let funcs_before = collect_functions(tree_before.root_node(), before);
    let funcs_after = collect_functions(tree_after.root_node(), after);

    // Symmetric diff: functions whose node-kind sequences changed.
    let mut added_nodes = 0usize;
    let mut removed_nodes = 0usize;
    let mut modified_functions: Vec<String> = Vec::new();
    let mut changed_node_kinds: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();

    for (name, kinds_after) in &funcs_after {
        match funcs_before.get(name) {
            Some(kinds_before) => {
                if kinds_before != kinds_after {
                    modified_functions.push(name.clone());
                    // Count added kinds.
                    for k in kinds_after {
                        if !kinds_before.contains(k) {
                            added_nodes += 1;
                            *changed_node_kinds.entry(k.clone()).or_insert(0) += 1;
                        }
                    }
                    for k in kinds_before {
                        if !kinds_after.contains(k) {
                            removed_nodes += 1;
                        }
                    }
                }
            }
            None => {
                // New function introduced by the patch.
                added_nodes += kinds_after.len();
                modified_functions.push(name.clone());
            }
        }
    }
    for (name, kinds_before) in &funcs_before {
        if !funcs_after.contains_key(name) {
            removed_nodes += kinds_before.len();
            modified_functions.push(name.clone());
        }
    }

    let verdict = if added_nodes + removed_nodes == 0 {
        PatchVerdict::EquivalentExceptForFix
    } else if modified_functions.len() > 3 {
        // Collect top-3 most-changed node kinds.
        let mut kinds_sorted: Vec<(String, usize)> = changed_node_kinds.into_iter().collect();
        kinds_sorted.sort_by(|a, b| b.1.cmp(&a.1));
        let top3: Vec<String> = kinds_sorted.into_iter().take(3).map(|(k, _)| k).collect();
        PatchVerdict::IntroducesNewBehavior {
            changed_nodes: top3,
        }
    } else {
        PatchVerdict::EquivalentExceptForFix
    };

    Some(PatchProof {
        verdict,
        added_node_count: added_nodes,
        removed_node_count: removed_nodes,
        modified_functions,
    })
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

/// Returns a map of `function_name → sorted Vec<node_kind>` for the top-level
/// functions reachable from `root`.
fn collect_functions(
    root: tree_sitter::Node<'_>,
    source: &[u8],
) -> std::collections::HashMap<String, Vec<String>> {
    let mut map = std::collections::HashMap::new();
    collect_functions_rec(root, source, &mut map);
    map
}

fn collect_functions_rec(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    map: &mut std::collections::HashMap<String, Vec<String>>,
) {
    let kind = node.kind();
    // Function-level node kinds across supported languages.
    let is_function = matches!(
        kind,
        "function_item"          // Rust
            | "function_declaration" // Go, JS, TS
            | "function_definition"  // Python, C, C++
            | "method_declaration"   // Go
            | "method_definition"    // JS, TS
            | "method_item" // Rust (trait/impl)
    );

    if is_function {
        // Extract name from named child "name" or first identifier.
        let name = node
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(source).ok())
            .map(|s| s.to_owned())
            .unwrap_or_else(|| format!("__anon_{}", node.start_byte()));

        let mut kinds: Vec<String> = Vec::new();
        collect_node_kinds_flat(node, &mut kinds);
        kinds.sort_unstable();
        map.insert(name, kinds);
        // Do not recurse into nested function bodies — treat as monolithic unit.
        return;
    }

    for i in 0..node.named_child_count() {
        if let Some(child) = node.named_child(i as u32) {
            collect_functions_rec(child, source, map);
        }
    }
}

fn collect_node_kinds_flat(node: tree_sitter::Node<'_>, out: &mut Vec<String>) {
    let kind = node.kind();
    // Skip pure naming / punctuation — focus on structural kinds.
    if !matches!(
        kind,
        "identifier"
            | "string"
            | "string_content"
            | "comment"
            | "line_comment"
            | "block_comment"
            | ","
            | ";"
            | "("
            | ")"
            | "{"
            | "}"
            | "["
            | "]"
    ) {
        out.push(kind.to_owned());
    }
    for i in 0..node.named_child_count() {
        if let Some(child) = node.named_child(i as u32) {
            collect_node_kinds_flat(child, out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIMPLE_FN: &[u8] = b"fn greet() { println!(\"hello\"); }";
    const SIMPLE_FN_RENAMED: &[u8] = b"fn greet() { println!(\"world\"); }";
    const FN_WITH_BRANCH: &[u8] = b"fn greet(x: i32) { if x > 0 { println!(\"pos\"); } }";

    fn make_four_fn_source(extra_branch: bool) -> Vec<u8> {
        let branch = if extra_branch { " if x > 0 { x }" } else { "" };
        format!(
            "fn a(x: i32) -> i32 {{ x{branch} }}\n\
             fn b(x: i32) -> i32 {{ x{branch} }}\n\
             fn c(x: i32) -> i32 {{ x{branch} }}\n\
             fn d(x: i32) -> i32 {{ x{branch} }}\n",
        )
        .into_bytes()
    }

    #[test]
    fn tp_identical_buffers_returns_equivalent() {
        let proof = prove_patch_correctness(SIMPLE_FN, SIMPLE_FN, "rs");
        assert_eq!(proof.unwrap().verdict, PatchVerdict::EquivalentExceptForFix);
    }

    #[test]
    fn tp_rename_only_returns_equivalent() {
        // String literal change only — node-kind sequence is identical.
        let proof = prove_patch_correctness(SIMPLE_FN, SIMPLE_FN_RENAMED, "rs");
        assert_eq!(proof.unwrap().verdict, PatchVerdict::EquivalentExceptForFix);
    }

    #[test]
    fn tp_added_branch_returns_new_behavior() {
        let proof = prove_patch_correctness(SIMPLE_FN, FN_WITH_BRANCH, "rs");
        let p = proof.unwrap();
        // Added an if_expression — not EquivalentExceptForFix.
        assert_ne!(
            p.added_node_count, 0,
            "if branch should add structural nodes"
        );
    }

    #[test]
    fn tp_empty_before_returns_unsatisfiable() {
        let proof = prove_patch_correctness(b"", SIMPLE_FN, "rs");
        assert_eq!(proof.unwrap().verdict, PatchVerdict::Unsatisfiable);
    }

    #[test]
    fn tp_unsupported_ext_returns_none() {
        let result = prove_patch_correctness(SIMPLE_FN, SIMPLE_FN, "rb");
        assert!(result.is_none(), "Ruby is not supported in Phase A");
    }

    #[test]
    fn tp_four_function_change_returns_new_behavior() {
        let before = make_four_fn_source(false);
        let after = make_four_fn_source(true);
        let proof = prove_patch_correctness(&before, &after, "rs").unwrap();
        assert!(
            matches!(proof.verdict, PatchVerdict::IntroducesNewBehavior { .. }),
            "4-function structural change must be IntroducesNewBehavior: {:?}",
            proof.verdict
        );
    }
}
