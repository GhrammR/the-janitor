//! Sprint 143 — SQL Sanitizer Oracle.
//!
//! Pre-detector module that inspects the surrounding code context of
//! `security:sql_injection` / `security:sqli` findings. Suppresses
//! findings when the cited line uses an identifier-quoting helper, has
//! an inline `//nolint:gosec` annotation, or sits inside a function
//! whose name matches test-fixture / pristine-database / drop-and-
//! create patterns.
//!
//! Motivating regression (Sprint 141): the chainlink SQL injection
//! CANDIDATE ($16.2K nominal EV) was demoted after Tier-1 validation
//! found the cited line was inside `dropAndCreatePristineDB(db *sqlx.DB,
//! template string)` — a TEST infrastructure helper that uses
//! `pq.QuoteIdentifier()` for safe identifier escaping AND carries an
//! explicit `//nolint:gosec // G701 false positive: identifiers from
//! pq.QuoteIdentifier only` annotation. The upstream SQL detector
//! emitted on the syntactic concatenation pattern without inspecting
//! these context signals. This module is the structural cure.
//!
//! ## Detection Strategy
//!
//! Run three context checks in order; return `Sanitized` on first match:
//!
//! 1. **Sanitizer marker** within ±5 lines: identifier-quoting helpers
//!    (`pq.QuoteIdentifier(`, `sqlx.QuoteIdentifier(`, `sql/driver.Quote`),
//!    prepared-statement construction (`PreparedStatement`, `.Prepare(`),
//!    or maintainer-asserted comment hints (`parameterized`,
//!    `parameterise`).
//! 2. **`//nolint` annotation** on the cited line itself:
//!    `//nolint:gosec`, `//nolint:G201`, `//nolint:G202`.
//! 3. **Test / fixture / pristine function name** within ±20 lines:
//!    `func Test*`, `func TestSetup*`, `func setupTest*`,
//!    `func *pristine*`, `func drop*Create*`, or the file path
//!    contains `_test.go` / `/testdb/` / `/fixtures/`.
//!
//! If none match → `Suspicious` (preserve upstream finding).

use std::path::Path;

use common::slop::StructuredFinding;

/// Vertical scan radius (in lines) for sanitizer-marker detection.
/// 5 lines on each side of the cited line covers the typical
/// distance between a `pq.QuoteIdentifier` helper call and its
/// `db.Exec` / `db.QueryRow` consumer.
const SANITIZER_SCAN_RADIUS: usize = 5;

/// Vertical scan radius (in lines) for enclosing-function detection.
/// 20 lines on each side covers the typical Go function-body span from
/// the `func` declaration to a SQL call site inside it.
const FUNCTION_SCAN_RADIUS: usize = 20;

/// Sanitizer marker substrings. Presence within `SANITIZER_SCAN_RADIUS`
/// of the cited line indicates the SQL surface is properly defended.
const SANITIZER_MARKERS: &[&str] = &[
    "pq.QuoteIdentifier(",
    "sqlx.QuoteIdentifier(",
    "sql/driver.Quote",
    "PreparedStatement",
    ".Prepare(",
    "parameterized",
    "parameterise",
];

/// Inline `//nolint` annotation substrings. Presence on the cited line
/// itself is a maintainer-asserted suppression signal.
const NOLINT_ANNOTATIONS: &[&str] = &["//nolint:gosec", "//nolint:G201", "//nolint:G202"];

/// Path substrings indicating the cited file is test infrastructure.
const TEST_PATH_MARKERS: &[&str] = &["_test.go", "/testdb/", "/fixtures/"];

/// Verdict returned by the SQL sanitizer oracle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqlSanitizerVerdict {
    /// The cited line is in a properly-sanitized SQL context. The
    /// upstream SQL injection finding should be demoted to
    /// Informational by the post-filter.
    Sanitized,
    /// No sanitizer context detected. Preserve the upstream finding.
    Suspicious,
}

/// Classify a SQL-class finding against its surrounding sanitizer
/// context. See module-level docs for the 3-tier decision logic.
pub fn classify_sql_finding(file_path: &Path, finding_line: Option<u32>) -> SqlSanitizerVerdict {
    let Ok(content) = std::fs::read_to_string(file_path) else {
        return SqlSanitizerVerdict::Suspicious;
    };
    let lines: Vec<&str> = content.lines().collect();
    let Some(line_num) = finding_line else {
        return SqlSanitizerVerdict::Suspicious;
    };
    let target_idx = (line_num as usize).saturating_sub(1);
    if target_idx >= lines.len() {
        return SqlSanitizerVerdict::Suspicious;
    }

    // Step 1: scan +/-5 lines for sanitizer markers.
    let sani_start = target_idx.saturating_sub(SANITIZER_SCAN_RADIUS);
    let sani_end = (target_idx + SANITIZER_SCAN_RADIUS + 1).min(lines.len());
    let sani_window = lines[sani_start..sani_end].join("\n");
    if SANITIZER_MARKERS.iter().any(|m| sani_window.contains(m)) {
        return SqlSanitizerVerdict::Sanitized;
    }

    // Step 2: inline //nolint annotation on the cited line itself.
    let cited_line = lines[target_idx];
    if NOLINT_ANNOTATIONS.iter().any(|m| cited_line.contains(m)) {
        return SqlSanitizerVerdict::Sanitized;
    }

    // Step 3a: file path indicates test infrastructure.
    let path_str = file_path.to_string_lossy();
    if TEST_PATH_MARKERS.iter().any(|m| path_str.contains(m)) {
        return SqlSanitizerVerdict::Sanitized;
    }

    // Step 3b: enclosing function name matches test/fixture/pristine patterns.
    let func_start = target_idx.saturating_sub(FUNCTION_SCAN_RADIUS);
    let func_end = (target_idx + FUNCTION_SCAN_RADIUS + 1).min(lines.len());
    for line in &lines[func_start..func_end] {
        let trimmed = line.trim_start();
        if !trimmed.starts_with("func ") {
            continue;
        }
        // Extract the function name token. For methods `func (recv) Name(...)`,
        // skip the parenthesized receiver first. For free functions
        // `func Name(...)`, parse directly — splitting on `) ` would
        // falsely match the return-type space in `... params) error {`.
        let after_func = &trimmed["func ".len()..];
        let after_recv = if after_func.starts_with('(') {
            after_func
                .split_once(") ")
                .map(|(_, rest)| rest)
                .unwrap_or(after_func)
        } else {
            after_func
        };
        let name_end = after_recv.find('(').unwrap_or(after_recv.len());
        let name = &after_recv[..name_end];
        let name_lower = name.to_lowercase();
        if name_lower.starts_with("test")
            || name_lower.starts_with("setuptest")
            || name_lower.contains("pristine")
            || (name_lower.starts_with("drop") && name_lower.contains("create"))
            || name_lower.contains("fixture")
        {
            return SqlSanitizerVerdict::Sanitized;
        }
    }

    SqlSanitizerVerdict::Suspicious
}

/// Returns `true` when `finding.id` references a SQL-class
/// vulnerability. Used by the hunt post-filter to scope the oracle's
/// invocation to SQL findings only.
pub fn is_sql_class(finding: &StructuredFinding) -> bool {
    let lower = finding.id.to_lowercase();
    lower.contains("sql_injection") || lower.contains("sqli")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn chainlink_pq_quote_identifier_sanitized() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("store.go");
        fs::write(
            &path,
            b"package store\n\nimport \"github.com/lib/pq\"\n\nfunc dropAndCreatePristineDB(db *sqlx.DB, template string) error {\n    _, err := db.ExecContext(ctx, \"CREATE DATABASE \"+pq.QuoteIdentifier(testdb.PristineDBName)+\" WITH TEMPLATE \"+pq.QuoteIdentifier(template))\n    return err\n}\n",
        )
        .unwrap();
        assert_eq!(
            classify_sql_finding(&path, Some(6)),
            SqlSanitizerVerdict::Sanitized
        );
    }

    #[test]
    fn nolint_gosec_annotation_sanitized() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("store.go");
        fs::write(
            &path,
            b"package store\n\nfunc createDB(db *sql.DB, name string) error {\n    _, err := db.Exec(\"CREATE DATABASE \" + name) //nolint:gosec // G201 false positive\n    return err\n}\n",
        )
        .unwrap();
        assert_eq!(
            classify_sql_finding(&path, Some(4)),
            SqlSanitizerVerdict::Sanitized
        );
    }

    #[test]
    fn test_function_name_sanitized() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("store.go");
        fs::write(
            &path,
            b"package store\n\nfunc dropAndCreatePristineDB(db *sqlx.DB, template string) error {\n    _, err := db.ExecContext(ctx, \"CREATE DATABASE \" + template)\n    return err\n}\n",
        )
        .unwrap();
        assert_eq!(
            classify_sql_finding(&path, Some(4)),
            SqlSanitizerVerdict::Sanitized
        );
    }

    #[test]
    fn bare_string_concatenation_suspicious() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("handler.go");
        fs::write(
            &path,
            b"package handler\n\nfunc QueryByUser(db *sql.DB, userInput string) (*sql.Rows, error) {\n    return db.Query(\"SELECT * FROM users WHERE name = '\" + userInput + \"'\")\n}\n",
        )
        .unwrap();
        assert_eq!(
            classify_sql_finding(&path, Some(4)),
            SqlSanitizerVerdict::Suspicious
        );
    }

    #[test]
    fn prepared_statement_sanitized() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("handler.go");
        fs::write(
            &path,
            b"package handler\n\nfunc InsertUser(db *sql.DB, name string, role string) error {\n    stmt, err := db.Prepare(\"INSERT INTO users (name, role) VALUES (?, ?)\")\n    if err != nil { return err }\n    _, err = stmt.Exec(name, role)\n    return err\n}\n",
        )
        .unwrap();
        assert_eq!(
            classify_sql_finding(&path, Some(4)),
            SqlSanitizerVerdict::Sanitized
        );
    }

    #[test]
    fn test_path_marker_sanitized() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("handler_test.go");
        fs::write(
            &path,
            b"package handler\n\nfunc someTestHelper(db *sql.DB, raw string) error {\n    _, err := db.Exec(\"SELECT \" + raw)\n    return err\n}\n",
        )
        .unwrap();
        assert_eq!(
            classify_sql_finding(&path, Some(4)),
            SqlSanitizerVerdict::Sanitized
        );
    }

    #[test]
    fn is_sql_class_recognises_canonical_ids() {
        let sqli = StructuredFinding {
            id: "security:sql_injection".to_string(),
            ..Default::default()
        };
        let sqli_alt = StructuredFinding {
            id: "security:sqli_concat".to_string(),
            ..Default::default()
        };
        let xss = StructuredFinding {
            id: "security:react_xss_dangerous_html".to_string(),
            ..Default::default()
        };
        assert!(is_sql_class(&sqli));
        assert!(is_sql_class(&sqli_alt));
        assert!(!is_sql_class(&xss));
    }

    #[test]
    fn missing_file_returns_suspicious() {
        let result = classify_sql_finding(Path::new("/nonexistent/path.go"), Some(1));
        assert_eq!(result, SqlSanitizerVerdict::Suspicious);
    }
}
