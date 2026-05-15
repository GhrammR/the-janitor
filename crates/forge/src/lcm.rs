//! P2-21 Cross-Language Memory Safety Witness Translation.
//!
//! Detects raw-pointer dereferences at FFI boundaries where an external C function
//! returns a pointer that flows into Rust unsafe code without a null/bounds guard.
//! Primary target: `qdb_read()` → `CStr::from_ptr` patterns in QubesDB/Xen proxy
//! surfaces (freedomofpress/securedrop-client proxy/src/config_qubesdb.rs).

use aho_corasick::{AhoCorasick, MatchKind};
use common::slop::{ProofClass, StructuredFinding};

const FFI_SINKS: &[&str] = &[
    "CStr::from_ptr",
    "from_raw_parts",
    "slice::from_raw_parts",
    "std::ptr::read",
    "unsafe { *",
];

const FFI_SOURCES: &[&str] = &[
    "extern \"C\" fn",
    "#[no_mangle]",
    "pub unsafe fn",
    "qdb_read",
    "::ffi::",
];

const GUARDS: &[&str] = &[
    "!ptr.is_null()",
    "NonNull::new",
    "if ptr.is_null()",
    "assert!(!ptr.is_null())",
    "len != 0",
    ".is_null()",
    "ptr::NonNull",
];

/// Returns true when `line` is a suppressor — a null/bounds guard that makes
/// the dereference safe.
fn has_guard(lines: &[&str]) -> bool {
    let ac = AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostFirst)
        .build(GUARDS)
        .expect("GUARDS patterns are valid");
    lines.iter().any(|l| ac.is_match(l.as_bytes()))
}

/// Emit cross-language memory safety findings for `source` at `file`.
///
/// Fires `security:ffi_unsafe_deref_unguarded` at KevCritical when a raw-pointer
/// sink (`CStr::from_ptr`, `slice::from_raw_parts`, etc.) appears within ±20 lines
/// of an FFI source boundary (`extern "C" fn`, `qdb_read`, etc.) without a
/// null/bounds guard in the same window.
pub fn emit_cross_language_memory_witnesses(source: &str, file: &str) -> Vec<StructuredFinding> {
    let lines: Vec<&str> = source.lines().collect();
    let n = lines.len();

    let sink_ac = AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostFirst)
        .build(FFI_SINKS)
        .expect("FFI_SINKS patterns are valid");

    let src_ac = AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostFirst)
        .build(FFI_SOURCES)
        .expect("FFI_SOURCES patterns are valid");

    let mut findings = Vec::new();

    for (i, line) in lines.iter().enumerate() {
        if !sink_ac.is_match(line.as_bytes()) {
            continue;
        }
        // Window: ±20 lines.
        let lo = i.saturating_sub(20);
        let hi = (i + 20).min(n.saturating_sub(1));
        let window = &lines[lo..=hi];

        // Source must be visible in the window.
        let has_source = window.iter().any(|l| src_ac.is_match(l.as_bytes()));
        if !has_source {
            continue;
        }

        // Guard must NOT be present.
        if has_guard(window) {
            continue;
        }

        findings.push(StructuredFinding {
            id: "security:ffi_unsafe_deref_unguarded".to_string(),
            severity: Some("KevCritical".to_string()),
            file: Some(file.to_string()),
            line: Some((i + 1) as u32),
            proof_class: Some(ProofClass::LatticeGapProposal),
            remediation: Some(
                "Add a null check before dereferencing the raw pointer: \
                 `if ptr.is_null() { return Err(...); }` or use `NonNull::new(ptr).ok_or(...)?`."
                    .to_string(),
            ),
            ..Default::default()
        });
    }

    findings
}

/// Pure boolean predicate used by Kani and regression tests.
///
/// Returns `true` iff a sink is present within the window AND a source is
/// present AND no guard is visible — the exact condition that emits a finding.
pub fn ffi_deref_unguarded(has_sink: bool, has_source: bool, has_guard: bool) -> bool {
    has_sink && has_source && !has_guard
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find(src: &str) -> Vec<StructuredFinding> {
        emit_cross_language_memory_witnesses(src, "test.rs")
    }

    #[test]
    fn tp_raw_ptr_without_null_check() {
        let src = r#"
extern "C" fn read_value() -> *const u8 { todo!() }
fn use_it() {
    let ptr = read_value();
    let s = unsafe { CStr::from_ptr(ptr) };
}
"#;
        assert!(!find(src).is_empty());
    }

    #[test]
    fn tn_null_check_present() {
        let src = r#"
extern "C" fn read_value() -> *const u8 { todo!() }
fn use_it() {
    let ptr = read_value();
    if ptr.is_null() { return; }
    let s = unsafe { CStr::from_ptr(ptr) };
}
"#;
        assert!(find(src).is_empty());
    }

    #[test]
    fn tp_qdb_read_into_cstr() {
        let src = r#"
fn config_from_qubesdb() {
    let value_unsafe = qdb_read(handle, key, &mut len);
    let c_str = unsafe { CStr::from_ptr(value_unsafe) };
}
"#;
        assert!(!find(src).is_empty());
    }

    #[test]
    fn tn_nonnull_guard() {
        let src = r#"
fn config_from_qubesdb() {
    let value_unsafe = qdb_read(handle, key, &mut len);
    let ptr = NonNull::new(value_unsafe).expect("qdb_read returned null");
    let c_str = unsafe { CStr::from_ptr(ptr.as_ptr()) };
}
"#;
        assert!(find(src).is_empty());
    }

    #[test]
    fn tp_slice_from_raw_parts_unguarded() {
        let src = r#"
#[no_mangle]
pub extern "C" fn process_buf(ptr: *const u8, len: usize) {
    let data = unsafe { slice::from_raw_parts(ptr, len) };
}
"#;
        assert!(!find(src).is_empty());
    }

    #[test]
    fn tn_len_zero_check() {
        let src = r#"
#[no_mangle]
pub extern "C" fn process_buf(ptr: *const u8, len: usize) {
    assert!(!ptr.is_null());
    let data = unsafe { slice::from_raw_parts(ptr, len) };
}
"#;
        assert!(find(src).is_empty());
    }

    #[test]
    fn tp_pub_unsafe_fn_unchecked() {
        let src = r#"
pub unsafe fn from_ffi(raw: *mut u8) -> u8 {
    let val = std::ptr::read(raw);
    val
}
"#;
        assert!(!find(src).is_empty());
    }

    #[test]
    fn tn_assert_not_null() {
        let src = r#"
pub unsafe fn from_ffi(raw: *mut u8) -> u8 {
    assert!(!raw.is_null());
    let val = std::ptr::read(raw);
    val
}
"#;
        assert!(find(src).is_empty());
    }

    #[test]
    fn predicate_exact() {
        assert!(ffi_deref_unguarded(true, true, false));
        assert!(!ffi_deref_unguarded(true, true, true));
        assert!(!ffi_deref_unguarded(false, true, false));
        assert!(!ffi_deref_unguarded(true, false, false));
    }
}
