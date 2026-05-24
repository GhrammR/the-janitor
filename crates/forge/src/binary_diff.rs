//! Binary diff engine for patch-urgency prediction (P7-3).
//!
//! Compares a patched binary against a customer's unpatched artifact using a
//! symbol-table MD-index: for each exported or named function in the patched
//! binary, computes a BLAKE3 hash of the function's raw bytes, then diffs
//! against the hash set from the customer binary. Changed functions are
//! `patched_set \ customer_set`.
//!
//! Handles malformed or non-ELF/PE inputs gracefully — never panics, always
//! returns an empty result.

use std::collections::HashMap;

/// Result of comparing a patched binary against a customer artifact.
pub struct BinaryDiffResult {
    /// Names of functions whose byte-hash changed between patched and customer.
    pub changed_functions: Vec<String>,
    /// Inferred vulnerability class based on changed-function name patterns.
    pub vuln_class_hint: Option<String>,
    /// Urgency score in `[0, 100]`: higher = more likely a weaponisable 1-day.
    pub patch_urgency_score: u8,
}

/// Compare `patched` against `customer` and return a structured diff.
/// Both inputs are raw binary bytes (ELF or PE). Unrecognised formats
/// yield an empty result with score 0.
pub fn diff_binaries(patched: &[u8], customer: &[u8]) -> BinaryDiffResult {
    let patched_hashes = extract_function_hashes(patched);
    let customer_hashes = extract_function_hashes(customer);

    let mut changed: Vec<String> = patched_hashes
        .iter()
        .filter(|(name, hash)| customer_hashes.get(*name) != Some(*hash))
        .map(|(name, _)| name.clone())
        .collect();
    changed.sort_unstable();

    let vuln_class_hint = classify_changed_functions(&changed);
    let patch_urgency_score = compute_urgency_score(changed.len(), vuln_class_hint.is_some());

    BinaryDiffResult {
        changed_functions: changed,
        vuln_class_hint,
        patch_urgency_score,
    }
}

/// Extract a `name → BLAKE3(function_bytes)` map from a binary.
/// Returns an empty map on any parse or bounds error.
fn extract_function_hashes(bytes: &[u8]) -> HashMap<String, [u8; 32]> {
    let mut out = HashMap::new();
    if bytes.is_empty() {
        return out;
    }
    match goblin::Object::parse(bytes) {
        Ok(goblin::Object::Elf(elf)) => extract_elf_hashes(bytes, &elf, &mut out),
        Ok(goblin::Object::PE(pe)) => extract_pe_hashes(bytes, &pe, &mut out),
        _ => {}
    }
    out
}

fn extract_elf_hashes(
    bytes: &[u8],
    elf: &goblin::elf::Elf<'_>,
    out: &mut HashMap<String, [u8; 32]>,
) {
    for sym in &elf.syms {
        if sym.st_type() != goblin::elf::sym::STT_FUNC || sym.st_size == 0 {
            continue;
        }
        let name = match elf.strtab.get_at(sym.st_name) {
            Some(n) if !n.is_empty() => n.to_string(),
            _ => continue,
        };
        // Locate function bytes via section header file offsets.
        let fb = elf.section_headers.iter().find_map(|sh| {
            let addr = sh.sh_addr;
            let sh_size = sh.sh_size;
            if addr == 0 || sh_size == 0 {
                return None;
            }
            if sym.st_value < addr || sym.st_value >= addr + sh_size {
                return None;
            }
            let file_off = sh.sh_offset as usize + (sym.st_value - addr) as usize;
            let end = file_off.checked_add(sym.st_size as usize)?;
            bytes.get(file_off..end)
        });
        if let Some(fb) = fb {
            out.insert(name, *blake3::hash(fb).as_bytes());
        }
    }
}

fn extract_pe_hashes(bytes: &[u8], pe: &goblin::pe::PE<'_>, out: &mut HashMap<String, [u8; 32]>) {
    for export in &pe.exports {
        let Some(name) = export.name else { continue };
        let Some(offset) = export.offset else {
            continue;
        };
        // Conservative stub window: 64 bytes for export-table entries.
        let end = offset.saturating_add(64).min(bytes.len());
        if let Some(fb) = bytes.get(offset..end) {
            out.insert(name.to_string(), *blake3::hash(fb).as_bytes());
        }
    }
}

/// Classify changed function names into a vulnerability hint.
/// Returns `None` when no security-relevant pattern matches.
pub(crate) fn classify_changed_functions(names: &[String]) -> Option<String> {
    let mem_keywords = ["free", "delete", "release", "destroy", "dealloc"];
    let auth_keywords = ["auth", "token", "credential", "session", "privilege"];
    let parse_keywords = ["parse", "deserializ", "decode", "unmarshal"];

    let mut mem = false;
    let mut auth = false;
    let mut parse = false;

    for n in names {
        let lower = n.to_ascii_lowercase();
        if mem_keywords.iter().any(|k| lower.contains(k)) {
            mem = true;
        }
        if auth_keywords.iter().any(|k| lower.contains(k)) {
            auth = true;
        }
        if parse_keywords.iter().any(|k| lower.contains(k)) {
            parse = true;
        }
    }

    if auth {
        Some("auth_bypass".to_string())
    } else if mem {
        Some("memory_safety".to_string())
    } else if parse {
        Some("parsing_vuln".to_string())
    } else {
        None
    }
}

/// Map changed-function count and class presence to a 0–100 urgency score.
pub(crate) fn compute_urgency_score(changed_count: usize, has_class: bool) -> u8 {
    if changed_count == 0 {
        return 0;
    }
    let base: u8 = match changed_count {
        1 => 20,
        2..=4 => 40,
        5..=9 => 60,
        _ => 80,
    };
    if has_class {
        base.saturating_add(20).min(100)
    } else {
        base
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    fn no_oob_on_malformed_elf() {
        let len: usize = kani::any();
        kani::assume(len <= 1024);
        let bytes: Vec<u8> = (0..len).map(|_| kani::any()).collect();
        // Must not panic or OOB — result is ignored.
        let _ = extract_function_hashes(&bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_binaries_produce_empty_diff() {
        let r = diff_binaries(&[], &[]);
        assert!(r.changed_functions.is_empty());
        assert!(r.vuln_class_hint.is_none());
        assert_eq!(r.patch_urgency_score, 0);
    }

    #[test]
    fn malformed_bytes_produce_empty_diff() {
        let r = diff_binaries(b"not an elf binary", b"\x00garbage\xff");
        assert!(r.changed_functions.is_empty());
        assert_eq!(r.patch_urgency_score, 0);
    }

    #[test]
    fn classify_auth_takes_priority_over_memory() {
        let names = vec!["validate_auth_token".to_string(), "free_buffer".to_string()];
        assert_eq!(
            classify_changed_functions(&names).as_deref(),
            Some("auth_bypass")
        );
    }

    #[test]
    fn classify_memory_safety_from_name() {
        let names = vec!["safe_free_buffer".to_string()];
        assert_eq!(
            classify_changed_functions(&names).as_deref(),
            Some("memory_safety")
        );
    }

    #[test]
    fn classify_returns_none_for_innocuous_names() {
        let names = vec!["compute_checksum".to_string(), "render_widget".to_string()];
        assert!(classify_changed_functions(&names).is_none());
    }

    #[test]
    fn urgency_score_scales_with_count() {
        assert_eq!(compute_urgency_score(0, false), 0);
        assert!(compute_urgency_score(1, false) > 0);
        assert!(compute_urgency_score(10, false) > compute_urgency_score(1, false));
        assert!(compute_urgency_score(1, true) > compute_urgency_score(1, false));
        assert!(compute_urgency_score(10, true) <= 100);
    }
}
