//! P8-4 — Linux Kernel Exploit Primitive Catalog.
//!
//! Detects five kernel-specific exploit primitive classes that generic C SAST
//! misses entirely: OOB writes via unbounded `copy_from_user`, heap-spray via
//! unchecked `kmalloc` size, unrestricted `call_usermodehelper` invocations,
//! unguarded writes to privilege escalation paths (`modprobe_path`,
//! `core_pattern`), and use-after-free via missing null-after-free discipline.
//!
//! # Threat model
//!
//! Linux kernel exploit chains almost universally begin with one of:
//! 1. **OOB write** (`copy_from_user` without `min_t`/`sizeof` bound) →
//!    corrupts adjacent kernel heap objects → type confusion → LPE.
//! 2. **Heap spray** (`kmalloc` with attacker-controlled `size`) → fills
//!    slab allocator with controlled payload → exploits UAF → LPE.
//! 3. **Usermode helper RCE** (`call_usermodehelper` with non-literal path) →
//!    arbitrary root command execution → RCE / ContainerEscape.
//! 4. **Privilege path write** (`modprobe_path` / `core_pattern` overwrite
//!    without `capable(CAP_SYS_ADMIN)` guard) → root trigger via module load
//!    or core dump → LPE.
//! 5. **Use-after-free** (`kfree` without null-after-free discipline) →
//!    dangling pointer reuse → LPE via heap grooming.
//!
//! # Detection model
//!
//! Each class: AhoCorasick sink scan → ±window suppressor check → emit.
//! Suppressors are class-specific (size bounds, privilege checks, null
//! assignments).  No suppressor within the window → finding emitted.
//!
//! # Kani predicates
//!
//! Each `*_unguarded` function is a pure boolean predicate that `reflexive_assurance.rs`
//! can prove via Kani.

use std::sync::OnceLock;

use aho_corasick::{AhoCorasick, MatchKind};
use common::slop::StructuredFinding;

// ── Pattern tables ────────────────────────────────────────────────────────────

const COPY_FROM_USER_SINKS: &[&str] = &[
    "copy_from_user(",
    "__copy_from_user(",
    "copy_from_user_nofault(",
];

const KMALLOC_SINKS: &[&str] = &["kmalloc(", "kzalloc(", "krealloc(", "vmalloc(", "kvmalloc("];

const USERMODE_HELPER_SINKS: &[&str] = &["call_usermodehelper(", "call_usermodehelper_fns("];

const PRIVILEGE_PATH_SINKS: &[&str] = &["modprobe_path", "core_pattern", "uevent_helper"];

const UAF_SINKS: &[&str] = &["kfree(", "kvfree(", "kfree_sensitive("];

// ── Suppressor tables ─────────────────────────────────────────────────────────

/// Size-bound guards that indicate the allocation/copy size is properly clamped.
const SIZE_BOUND_SUPPRESSORS: &[&str] = &[
    "min(",
    "min_t(",
    "min_unsafe(",
    "PAGE_SIZE",
    "PAGE_ALIGN(",
    "sizeof(",
    "MAX_PAYLOAD",
    "max_size",
    "bound_check",
    "MAX_SIZE",
    "KMALLOC_MAX_SIZE",
    "kmalloc_size_roundup",
];

/// Privilege guards that indicate caller already holds CAP_SYS_ADMIN.
const PRIVILEGE_SUPPRESSORS: &[&str] = &[
    "capable(",
    "ns_capable(",
    "CAP_SYS_ADMIN",
    "CAP_SYS_MODULE",
    "security_capset(",
    "prctl(",
];

/// Literal-path patterns indicating `call_usermodehelper` uses a compile-time path.
const HELPER_PATH_SUPPRESSORS: &[&str] = &[
    "call_usermodehelper(\"/",
    "call_usermodehelper_fns(\"/",
    "call_usermodehelper_exec(",
];

/// Null-after-free discipline — pointer nulled immediately after `kfree`.
const UAF_SUPPRESSORS: &[&str] = &["= NULL", "= null", "= nullptr", "ptr = NULL", "= (void *)0"];

// ── Static AhoCorasick instances ──────────────────────────────────────────────

static COPY_FROM_USER_AC: OnceLock<AhoCorasick> = OnceLock::new();
static KMALLOC_AC: OnceLock<AhoCorasick> = OnceLock::new();
static USERMODE_HELPER_AC: OnceLock<AhoCorasick> = OnceLock::new();
static PRIVILEGE_PATH_AC: OnceLock<AhoCorasick> = OnceLock::new();
static UAF_AC: OnceLock<AhoCorasick> = OnceLock::new();
static SIZE_BOUND_SUPP_AC: OnceLock<AhoCorasick> = OnceLock::new();
static PRIVILEGE_SUPP_AC: OnceLock<AhoCorasick> = OnceLock::new();
static HELPER_PATH_SUPP_AC: OnceLock<AhoCorasick> = OnceLock::new();
static UAF_SUPP_AC: OnceLock<AhoCorasick> = OnceLock::new();

/// Single parameterized initializer — eliminates structural clone across all 9 instances.
fn ac(
    lock: &'static OnceLock<AhoCorasick>,
    patterns: &'static [&'static str],
) -> &'static AhoCorasick {
    lock.get_or_init(|| {
        AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostFirst)
            .build(patterns)
            .expect("kernel AC build infallible")
    })
}

// ── Pure predicates (Kani-provable) ──────────────────────────────────────────

/// True when `copy_from_user` is called without a size-bound suppressor.
pub fn copy_unguarded(has_copy_from_user: bool, has_size_bound: bool) -> bool {
    has_copy_from_user && !has_size_bound
}

/// True when `kmalloc` is called without a size-bound suppressor.
pub fn kmalloc_unguarded(has_kmalloc: bool, has_size_bound: bool) -> bool {
    has_kmalloc && !has_size_bound
}

/// True when `call_usermodehelper` is called without a literal-path suppressor.
pub fn usermode_helper_unguarded(has_helper: bool, has_literal_path: bool) -> bool {
    has_helper && !has_literal_path
}

/// True when a privilege escalation path is written without a capability check.
pub fn privilege_path_unguarded(has_path_write: bool, has_capable: bool) -> bool {
    has_path_write && !has_capable
}

/// True when `kfree` is called without null-after-free discipline.
pub fn kfree_unguarded(has_kfree: bool, has_null_after: bool) -> bool {
    has_kfree && !has_null_after
}

// ── Window scanner ────────────────────────────────────────────────────────────

fn scan_window(
    lines: &[&str],
    sink_ac: &AhoCorasick,
    supp_ac: &AhoCorasick,
    before: usize,
    after: usize,
) -> Vec<u32> {
    let mut hits = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        if sink_ac.is_match(line) {
            let lo = idx.saturating_sub(before);
            let hi = (idx + after + 1).min(lines.len());
            let window = lines[lo..hi].join("\n");
            if !supp_ac.is_match(&window) {
                hits.push(idx as u32 + 1);
            }
        }
    }
    hits
}

// ── Finding emitter ───────────────────────────────────────────────────────────

/// Scan `source` (C/kernel source file) for kernel exploit primitives.
/// Returns one [`StructuredFinding`] per violation.
pub fn emit_kernel_findings(source: &str, file: &str) -> Vec<StructuredFinding> {
    let lines: Vec<&str> = source.lines().collect();
    let mut findings: Vec<StructuredFinding> = Vec::new();

    // ── Class 1: copy_from_user OOB write ────────────────────────────────────
    for line_no in scan_window(
        &lines,
        ac(&COPY_FROM_USER_AC, COPY_FROM_USER_SINKS),
        ac(&SIZE_BOUND_SUPP_AC, SIZE_BOUND_SUPPRESSORS),
        10,
        3,
    ) {
        findings.push(StructuredFinding {
            id: "security:kernel_oob_write".to_string(),
            severity: Some("KevCritical".to_string()),
            file: Some(file.to_string()),
            line: Some(line_no),
            remediation: Some(
                "copy_from_user() is called without a preceding size-bound check (min_t, \
sizeof, PAGE_SIZE, or equivalent).  An attacker who controls the size argument can \
trigger an out-of-bounds kernel heap write, corrupting adjacent slab objects and \
enabling LPE.  Gate with: `count = min_t(size_t, user_count, sizeof(buf));` before \
the copy call.  Exploit class: LPE."
                    .to_string(),
            ),
            ..Default::default()
        });
    }

    // ── Class 2: kmalloc heap spray ───────────────────────────────────────────
    for line_no in scan_window(
        &lines,
        ac(&KMALLOC_AC, KMALLOC_SINKS),
        ac(&SIZE_BOUND_SUPP_AC, SIZE_BOUND_SUPPRESSORS),
        10,
        3,
    ) {
        findings.push(StructuredFinding {
            id: "security:kernel_heap_spray".to_string(),
            severity: Some("KevCritical".to_string()),
            file: Some(file.to_string()),
            line: Some(line_no),
            remediation: Some(
                "kmalloc/kzalloc is called without a size-bound suppressor (min_t, PAGE_SIZE, \
KMALLOC_MAX_SIZE, or kmalloc_size_roundup).  An attacker who controls the size argument \
can exhaust the slab allocator, shape the heap for a subsequent UAF exploit, or trigger \
an integer wrap producing a zero-byte allocation.  Gate with: \
`size = min_t(size_t, user_size, MAX_SAFE_SIZE);` before the allocation.  \
Exploit class: LPE."
                    .to_string(),
            ),
            ..Default::default()
        });
    }

    // ── Class 3: call_usermodehelper RCE ─────────────────────────────────────
    for line_no in scan_window(
        &lines,
        ac(&USERMODE_HELPER_AC, USERMODE_HELPER_SINKS),
        ac(&HELPER_PATH_SUPP_AC, HELPER_PATH_SUPPRESSORS),
        5,
        0,
    ) {
        findings.push(StructuredFinding {
            id: "security:kernel_rce_usermode_helper".to_string(),
            severity: Some("KevCritical".to_string()),
            file: Some(file.to_string()),
            line: Some(line_no),
            remediation: Some(
                "call_usermodehelper() is invoked without a compile-time literal path.  A \
writable path variable (modprobe_path, core_pattern, attacker-controlled buffer) passed \
here executes an arbitrary root process in user space.  Pin the path to a string literal \
or validate against an allowlist of known-good absolute paths before invocation.  \
Exploit class: RCE / ContainerEscape."
                    .to_string(),
            ),
            ..Default::default()
        });
    }

    // ── Class 4: modprobe_path / core_pattern privilege write ─────────────────
    for line_no in scan_window(
        &lines,
        ac(&PRIVILEGE_PATH_AC, PRIVILEGE_PATH_SINKS),
        ac(&PRIVILEGE_SUPP_AC, PRIVILEGE_SUPPRESSORS),
        15,
        0,
    ) {
        findings.push(StructuredFinding {
            id: "security:kernel_privilege_path_write".to_string(),
            severity: Some("KevCritical".to_string()),
            file: Some(file.to_string()),
            line: Some(line_no),
            remediation: Some(
                "modprobe_path, core_pattern, or uevent_helper is written without a preceding \
`capable(CAP_SYS_ADMIN)` or `ns_capable()` check.  An attacker with write access to \
this path (via a kernel write primitive) can redirect the kernel's module-load or \
core-dump invocation to an arbitrary binary, achieving immediate LPE.  Gate writes with \
`if (!capable(CAP_SYS_ADMIN)) return -EPERM;`.  Exploit class: LPE."
                    .to_string(),
            ),
            ..Default::default()
        });
    }

    // ── Class 5: kfree UAF (missing null-after-free) ──────────────────────────
    for line_no in scan_window(
        &lines,
        ac(&UAF_AC, UAF_SINKS),
        ac(&UAF_SUPP_AC, UAF_SUPPRESSORS),
        0,
        3,
    ) {
        findings.push(StructuredFinding {
            id: "security:kernel_uaf".to_string(),
            severity: Some("KevCritical".to_string()),
            file: Some(file.to_string()),
            line: Some(line_no),
            remediation: Some(
                "kfree() is called without null-after-free discipline (pointer not set to NULL \
within 3 lines of the free).  A dangling pointer reused after free is the entry point \
for heap-grooming UAF exploits in the SLUB/SLAB allocator.  Always follow kfree with \
`ptr = NULL;` to make subsequent dereferences crash immediately rather than silently \
reuse freed memory.  Exploit class: LPE."
                    .to_string(),
            ),
            ..Default::default()
        });
    }

    findings
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Pure predicate coverage ───────────────────────────────────────────────

    #[test]
    fn predicates_exact_conjunction() {
        assert!(copy_unguarded(true, false));
        assert!(!copy_unguarded(true, true));
        assert!(!copy_unguarded(false, false));

        assert!(kmalloc_unguarded(true, false));
        assert!(!kmalloc_unguarded(true, true));

        assert!(usermode_helper_unguarded(true, false));
        assert!(!usermode_helper_unguarded(true, true));

        assert!(privilege_path_unguarded(true, false));
        assert!(!privilege_path_unguarded(true, true));

        assert!(kfree_unguarded(true, false));
        assert!(!kfree_unguarded(true, true));
    }

    // ── Class 1: copy_from_user OOB write ────────────────────────────────────

    #[test]
    fn tp_copy_from_user_no_bound_fires() {
        let src = r#"
static int ioctl_handler(unsigned long arg)
{
    char buf[64];
    size_t len = ((struct user_req *)arg)->len;
    if (copy_from_user(buf, (void __user *)arg, len))
        return -EFAULT;
    return 0;
}
"#;
        let findings = emit_kernel_findings(src, "driver.c");
        assert!(
            findings.iter().any(|f| f.id == "security:kernel_oob_write"),
            "copy_from_user without min_t must fire"
        );
        assert_eq!(
            findings
                .iter()
                .find(|f| f.id == "security:kernel_oob_write")
                .unwrap()
                .severity
                .as_deref(),
            Some("KevCritical")
        );
    }

    #[test]
    fn tn_copy_from_user_with_min_t_suppressed() {
        let src = r#"
static int ioctl_handler(unsigned long arg)
{
    char buf[64];
    size_t len = min_t(size_t, ((struct user_req *)arg)->len, sizeof(buf));
    if (copy_from_user(buf, (void __user *)arg, len))
        return -EFAULT;
    return 0;
}
"#;
        let findings = emit_kernel_findings(src, "driver.c");
        assert!(
            !findings.iter().any(|f| f.id == "security:kernel_oob_write"),
            "min_t within window must suppress copy_from_user finding"
        );
    }

    // ── Class 2: kmalloc heap spray ───────────────────────────────────────────

    #[test]
    fn tp_kmalloc_unchecked_size_fires() {
        let src = r#"
void *alloc_user_buffer(size_t user_size)
{
    void *buf = kmalloc(user_size, GFP_KERNEL);
    if (!buf)
        return NULL;
    return buf;
}
"#;
        let findings = emit_kernel_findings(src, "mem.c");
        assert!(
            findings
                .iter()
                .any(|f| f.id == "security:kernel_heap_spray"),
            "kmalloc with unchecked user_size must fire"
        );
    }

    #[test]
    fn tn_kmalloc_with_page_size_suppressed() {
        let src = r#"
void *alloc_safe(size_t user_size)
{
    size_t safe = min_t(size_t, user_size, PAGE_SIZE);
    void *buf = kmalloc(safe, GFP_KERNEL);
    return buf;
}
"#;
        let findings = emit_kernel_findings(src, "mem.c");
        assert!(
            !findings
                .iter()
                .any(|f| f.id == "security:kernel_heap_spray"),
            "min_t + PAGE_SIZE must suppress kmalloc finding"
        );
    }

    // ── Class 3: call_usermodehelper RCE ─────────────────────────────────────

    #[test]
    fn tp_call_usermodehelper_var_path_fires() {
        let src = r#"
void trigger_helper(char *path)
{
    char *argv[] = { path, NULL };
    char *envp[] = { "HOME=/", NULL };
    call_usermodehelper(path, argv, envp, UMH_WAIT_EXEC);
}
"#;
        let findings = emit_kernel_findings(src, "helper.c");
        assert!(
            findings
                .iter()
                .any(|f| f.id == "security:kernel_rce_usermode_helper"),
            "call_usermodehelper with variable path must fire"
        );
    }

    // ── Class 4: modprobe_path privilege write ────────────────────────────────

    #[test]
    fn tp_modprobe_path_no_capable_fires() {
        let src = r#"
static ssize_t modprobe_write(struct file *file, const char __user *buf,
                              size_t count, loff_t *ppos)
{
    if (count >= sizeof(modprobe_path))
        return -EINVAL;
    if (copy_from_user(modprobe_path, buf, count))
        return -EFAULT;
    modprobe_path[count] = '\0';
    return count;
}
"#;
        let findings = emit_kernel_findings(src, "sysctl.c");
        assert!(
            findings
                .iter()
                .any(|f| f.id == "security:kernel_privilege_path_write"),
            "modprobe_path write without capable() must fire"
        );
    }

    #[test]
    fn tn_modprobe_path_with_capable_suppressed() {
        let src = r#"
static ssize_t modprobe_write(struct file *file, const char __user *buf,
                              size_t count, loff_t *ppos)
{
    if (!capable(CAP_SYS_ADMIN))
        return -EPERM;
    if (count >= sizeof(modprobe_path))
        return -EINVAL;
    if (copy_from_user(modprobe_path, buf, count))
        return -EFAULT;
    modprobe_path[count] = '\0';
    return count;
}
"#;
        let findings = emit_kernel_findings(src, "sysctl.c");
        assert!(
            !findings
                .iter()
                .any(|f| f.id == "security:kernel_privilege_path_write"),
            "capable(CAP_SYS_ADMIN) must suppress privilege path write"
        );
    }

    // ── Class 5: kfree UAF ────────────────────────────────────────────────────

    #[test]
    fn tp_kfree_no_null_after_fires() {
        let src = r#"
void cleanup(struct my_obj *obj)
{
    kfree(obj->buf);
    /* buf dangling — not zeroed */
    process_late(obj);
}
"#;
        let findings = emit_kernel_findings(src, "obj.c");
        assert!(
            findings.iter().any(|f| f.id == "security:kernel_uaf"),
            "kfree without null-after-free must fire"
        );
    }

    #[test]
    fn tn_kfree_with_null_after_suppressed() {
        let src = r#"
void cleanup(struct my_obj *obj)
{
    kfree(obj->buf);
    obj->buf = NULL;
}
"#;
        let findings = emit_kernel_findings(src, "obj.c");
        assert!(
            !findings.iter().any(|f| f.id == "security:kernel_uaf"),
            "null-after-free within 3 lines must suppress UAF finding"
        );
    }

    // ── Negative: unrelated C code must not fire ──────────────────────────────

    #[test]
    fn tn_unrelated_c_code_clean() {
        let src = r#"
#include <stdio.h>
int main(void)
{
    int x = 42;
    printf("value: %d\n", x);
    return 0;
}
"#;
        let findings = emit_kernel_findings(src, "main.c");
        assert!(
            findings.is_empty(),
            "plain C code must not fire any kernel finding"
        );
    }
}
