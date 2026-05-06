//! Optimizer-phantom authority erasure detector.

use crate::metadata::DOMAIN_FIRST_PARTY;
use crate::slop_hunter::{parse_with_timeout, parser_exhaustion_finding, Severity, SlopFinding};
use tree_sitter::Node;

/// Detect C/C++ functions that dereference a pointer before a later null guard.
///
/// Once a pointer is dereferenced, GCC/Clang may assume it is non-null and
/// optimize a subsequent security check away as dead code.
pub fn detect_optimizer_phantom_authority(source: &[u8], language: &str) -> Vec<SlopFinding> {
    let mut parser = tree_sitter::Parser::new();
    let lang = match language {
        "c" | "h" => tree_sitter_c::LANGUAGE,
        "cpp" | "cxx" | "cc" | "hpp" => tree_sitter_cpp::LANGUAGE,
        _ => return Vec::new(),
    };
    if parser.set_language(&lang.into()).is_err() {
        return Vec::new();
    }
    let Some(tree) = parse_with_timeout(&mut parser, source) else {
        return vec![parser_exhaustion_finding(language)];
    };

    let mut findings = Vec::new();
    walk_functions(tree.root_node(), source, &mut findings);
    findings
}

fn walk_functions(node: Node<'_>, source: &[u8], findings: &mut Vec<SlopFinding>) {
    if node.kind() == "function_definition" {
        if let Some(body) = node.child_by_field_name("body") {
            scan_function_body(body, source, findings);
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_functions(child, source, findings);
    }
}

fn scan_function_body(body: Node<'_>, source: &[u8], findings: &mut Vec<SlopFinding>) {
    let body_bytes = &source[body.start_byte()..body.end_byte()];
    for deref in find_pointer_dereferences(body_bytes) {
        if has_null_check_before(body_bytes, deref.offset, &deref.name) {
            continue;
        }
        if let Some(guard_offset) = find_null_check_after(body_bytes, deref.offset, &deref.name) {
            findings.push(SlopFinding {
                start_byte: body.start_byte() + deref.offset,
                end_byte: body.start_byte() + guard_offset + deref.name.len(),
                description: format!(
                    "security:optimizer_phantom_authority — pointer `{}` is dereferenced before a later null/authority guard; C/C++ undefined behavior lets the optimizer assume non-null and erase the security check.",
                    deref.name
                ),
                domain: DOMAIN_FIRST_PARTY,
                severity: Severity::Critical,
            });
            return;
        }
    }
}

#[derive(Debug, Clone)]
struct PointerDeref {
    name: String,
    offset: usize,
}

fn find_pointer_dereferences(bytes: &[u8]) -> Vec<PointerDeref> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'-' && bytes[i + 1] == b'>' {
            if let Some(name) = identifier_before(bytes, i) {
                out.push(PointerDeref { name, offset: i });
            }
        } else if bytes[i] == b'(' && i + 2 < bytes.len() && bytes[i + 1] == b'*' {
            if let Some((name, consumed)) = identifier_after_star_paren(&bytes[i..]) {
                out.push(PointerDeref { name, offset: i });
                i += consumed;
                continue;
            }
        }
        i += 1;
    }
    out
}

fn identifier_before(bytes: &[u8], arrow_idx: usize) -> Option<String> {
    if arrow_idx == 0 {
        return None;
    }
    let mut end = arrow_idx;
    while end > 0 && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    let mut start = end;
    while start > 0 && is_ident(bytes[start - 1]) {
        start -= 1;
    }
    if start == end {
        return None;
    }
    std::str::from_utf8(&bytes[start..end])
        .ok()
        .map(str::to_string)
}

fn identifier_after_star_paren(bytes: &[u8]) -> Option<(String, usize)> {
    if bytes.len() < 4 || bytes[0] != b'(' || bytes[1] != b'*' {
        return None;
    }
    let mut i = 2;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    let start = i;
    while i < bytes.len() && is_ident(bytes[i]) {
        i += 1;
    }
    if i == start {
        return None;
    }
    let name = std::str::from_utf8(&bytes[start..i]).ok()?.to_string();
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i < bytes.len() && bytes[i] == b')' {
        Some((name, i))
    } else {
        None
    }
}

fn is_ident(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn has_null_check_before(bytes: &[u8], deref_offset: usize, name: &str) -> bool {
    find_null_check_in_window(&bytes[..deref_offset], name).is_some()
}

fn find_null_check_after(bytes: &[u8], deref_offset: usize, name: &str) -> Option<usize> {
    let suffix = &bytes[deref_offset..];
    find_null_check_in_window(suffix, name).map(|pos| deref_offset + pos)
}

fn find_null_check_in_window(bytes: &[u8], name: &str) -> Option<usize> {
    let patterns = [
        format!("if (!{name})"),
        format!("if(!{name})"),
        format!("if ({name} == NULL)"),
        format!("if({name}==NULL)"),
        format!("if ({name} == nullptr)"),
        format!("if({name}==nullptr)"),
        format!("if (NULL == {name})"),
        format!("if(NULL=={name})"),
        format!("if (nullptr == {name})"),
        format!("if(nullptr=={name})"),
    ];

    patterns
        .iter()
        .filter_map(|pattern| {
            bytes
                .windows(pattern.len())
                .position(|window| window == pattern.as_bytes())
        })
        .min()
}

/// Pure helper used by formal assurance and regression tests.
pub fn phantom_guard_order_is_invalid(deref_offset: usize, guard_offset: usize) -> bool {
    deref_offset < guard_offset
}

#[cfg(test)]
mod tests {
    use super::{detect_optimizer_phantom_authority, phantom_guard_order_is_invalid};

    #[test]
    fn detects_cpp_null_check_after_pointer_deref() {
        let src = br#"
struct Auth { int allow; };
int gate(Auth* auth) {
    if (auth->allow == 1) { return 1; }
    if (auth == NULL) { return 0; }
    return 0;
}
"#;
        let findings = detect_optimizer_phantom_authority(src, "cpp");
        assert!(findings
            .iter()
            .any(|f| f.description.contains("optimizer_phantom_authority")));
    }

    #[test]
    fn clean_when_null_guard_precedes_deref() {
        let src = br#"
struct Auth { int allow; };
int gate(Auth* auth) {
    if (auth == NULL) { return 0; }
    if (auth->allow == 1) { return 1; }
    return 0;
}
"#;
        let findings = detect_optimizer_phantom_authority(src, "cpp");
        assert!(findings.is_empty());
    }

    #[test]
    fn guard_order_helper_is_strict() {
        assert!(phantom_guard_order_is_invalid(3, 9));
        assert!(!phantom_guard_order_is_invalid(9, 3));
    }
}
