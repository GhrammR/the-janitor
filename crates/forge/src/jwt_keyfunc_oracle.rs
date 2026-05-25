//! Sprint 142 — JWT Keyfunc Oracle.
//!
//! Pre-detector module that inspects `jwt.Parse` / `jwt.ParseWithClaims`
//! keyfunc bodies in Go source. Suppresses
//! `security:jwt_validation_bypass` findings when the keyfunc contains
//! an algorithm allowlist check (`token.Method.Alg() != ...`) or a type
//! assertion on `token.Method`. The detector misfires when it pattern-
//! matches on the `jwt.Parse` call shape without inspecting the keyfunc
//! body.
//!
//! Motivating regression (Sprint 141): the chainlink JWT bypass
//! CANDIDATE ($27K nominal EV) was demoted after Tier-1 validation
//! found the keyfunc at `core/utils/jwt.go:258-266` had TWO algorithm
//! validation gates: `if token.Method.Alg() != EthereumSigningMethod.Alg()`
//! and `if _, ok := token.Method.(*SigningMethodEth); !ok`. The
//! candidate's `alg:none` repro fails at the first gate. This oracle
//! catches the class structurally.
//!
//! ## Detection Strategy
//!
//! Inspect the source content from the cited line's `jwt.Parse` /
//! `jwt.ParseWithClaims` call through the closing brace of the keyfunc
//! closure. Search that window for one of:
//!
//! 1. **Algorithm comparison**: literal substring `token.Method.Alg()`
//!    appearing inside an `if`/`return` condition (the canonical
//!    allowlist pattern).
//! 2. **Type assertion on Method**: literal substring
//!    `token.Method.(*` (Go type assertion syntax) — chainlink's
//!    `_, ok := token.Method.(*SigningMethodEth)` matches.
//! 3. **Allowlist comparison**: `SigningMethod` followed by a name
//!    (e.g. `SigningMethodHS256`, `SigningMethodRS256`, custom
//!    `SigningMethodEth`) used in an equality comparison.
//!
//! If any pattern is present in the keyfunc body → `Guarded` (suppress
//! upstream JWT-bypass finding).
//!
//! ## Heuristic Bounds
//!
//! Keyfunc bodies in production Go code are typically 3-20 lines. The
//! scan window is bounded to 40 lines after the cited line to capture
//! multi-line keyfuncs without runaway scans on large files.

use std::path::Path;

use common::slop::StructuredFinding;

/// Lines after the cited `jwt.Parse`/`jwt.ParseWithClaims` line to scan
/// for keyfunc-body guards. 40 lines covers all real-world keyfunc
/// bodies including verbose multi-claim validation.
const KEYFUNC_SCAN_FORWARD_LINES: usize = 40;

/// Verdict returned by the JWT keyfunc oracle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwtKeyfuncVerdict {
    /// The keyfunc body contains an algorithm allowlist or type
    /// assertion on `token.Method`. The `alg:none` attack class cannot
    /// reach the public-key return. Upstream JWT-bypass finding should
    /// be suppressed.
    Guarded,
    /// No guard detected. Either the keyfunc is genuinely unguarded
    /// (real vulnerability) or the cited line does not surround a
    /// `jwt.Parse` call (detector noise). Preserve the upstream
    /// verdict and let downstream filters handle it.
    Unguarded,
}

/// Classify a `security:jwt_*` finding against the keyfunc body of the
/// surrounding `jwt.Parse`/`jwt.ParseWithClaims` call.
///
/// Returns `Guarded` when an algorithm-allowlist check or
/// type-assertion guard is detected in the keyfunc body within
/// `KEYFUNC_SCAN_FORWARD_LINES` of the cited line.
///
/// Returns `Unguarded` when no guard is detected, the file cannot be
/// read, or the cited line has no surrounding `jwt.Parse` call. The
/// hunt post-filter chain interprets `Unguarded` as a no-op
/// (preserve the upstream detector's verdict).
pub fn classify_jwt_finding(file_path: &Path, finding_line: Option<u32>) -> JwtKeyfuncVerdict {
    let Ok(content) = std::fs::read_to_string(file_path) else {
        return JwtKeyfuncVerdict::Unguarded;
    };
    let lines: Vec<&str> = content.lines().collect();
    let Some(line_num) = finding_line else {
        return JwtKeyfuncVerdict::Unguarded;
    };
    let target_idx = (line_num as usize).saturating_sub(1);
    let scan_start = target_idx;
    let scan_end = (target_idx + KEYFUNC_SCAN_FORWARD_LINES).min(lines.len());

    if scan_start >= scan_end {
        return JwtKeyfuncVerdict::Unguarded;
    }

    let window = lines[scan_start..scan_end].join("\n");

    // Pattern 1: algorithm comparison inside if/return.
    // Catches chainlink's `if token.Method.Alg() != EthereumSigningMethod.Alg()`.
    if window.contains("token.Method.Alg()") {
        return JwtKeyfuncVerdict::Guarded;
    }
    // Pattern 2: type assertion on Method.
    // Catches chainlink's `_, ok := token.Method.(*SigningMethodEth)`.
    if window.contains("token.Method.(*") {
        return JwtKeyfuncVerdict::Guarded;
    }
    // Pattern 3: SigningMethod name comparison via *jwt.SigningMethod*.
    // Catches `case *jwt.SigningMethodHMAC:` and similar dispatch
    // patterns within the keyfunc body.
    if window.contains("*jwt.SigningMethod") || window.contains("*SigningMethod") {
        return JwtKeyfuncVerdict::Guarded;
    }
    // Pattern 4: WithValidMethods option passed to ParseWithClaims.
    // go-ethereum / golang-jwt v5 pattern: jwt.WithValidMethods([]string{"HS256"}).
    // Explicitly pins the algorithm set; alg-confusion bypass is blocked by the library.
    if window.contains("WithValidMethods(") {
        return JwtKeyfuncVerdict::Guarded;
    }

    JwtKeyfuncVerdict::Unguarded
}

/// Returns `true` when `finding.id` references a JWT-class
/// vulnerability. Used by the hunt post-filter to decide whether to
/// invoke the JWT keyfunc oracle for this specific finding.
pub fn is_jwt_class(finding: &StructuredFinding) -> bool {
    let lower = finding.id.to_lowercase();
    lower.contains("jwt") && (lower.contains("bypass") || lower.contains("validation"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn finding(id: &str, line: u32) -> StructuredFinding {
        StructuredFinding {
            id: id.to_string(),
            line: Some(line),
            ..Default::default()
        }
    }

    #[test]
    fn chainlink_style_alg_check_is_guarded() {
        // Mirror of chainlink's core/utils/jwt.go:258-266 keyfunc.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("jwt.go");
        fs::write(
            &path,
            b"package utils\n\nfunc VerifyJWT(token string) error {\n    verifiedToken, err := jwt.ParseWithClaims(token, &JWTClaims{}, func(token *jwt.Token) (any, error) {\n        if token.Method.Alg() != EthereumSigningMethod.Alg() {\n            return nil, fmt.Errorf(\"unsupported JWT 'alg': '%s'\", token.Method.Alg())\n        }\n        if _, ok := token.Method.(*SigningMethodEth); !ok {\n            return nil, jwt.ErrSignatureInvalid\n        }\n        return pubKey, nil\n    })\n    return err\n}\n",
        )
        .unwrap();
        assert_eq!(
            classify_jwt_finding(&path, Some(4)),
            JwtKeyfuncVerdict::Guarded
        );
    }

    #[test]
    fn bare_keyfunc_returning_nil_key_is_unguarded() {
        // The actual alg:none vulnerability: keyfunc returns nil
        // unconditionally, allowing alg=none tokens to pass verification.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("jwt.go");
        fs::write(
            &path,
            b"package handlers\n\nfunc VerifyToken(token string) error {\n    parsed, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {\n        return nil, nil\n    })\n    return err\n}\n",
        )
        .unwrap();
        assert_eq!(
            classify_jwt_finding(&path, Some(4)),
            JwtKeyfuncVerdict::Unguarded
        );
    }

    #[test]
    fn hs256_type_assertion_is_guarded() {
        // Common Go JWT pattern: type-assert the signing method.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("jwt.go");
        fs::write(
            &path,
            b"package auth\n\nfunc Verify(token string) error {\n    return jwt.Parse(token, func(t *jwt.Token) (any, error) {\n        if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {\n            return nil, errors.New(\"wrong signing method\")\n        }\n        return secret, nil\n    })\n}\n",
        )
        .unwrap();
        assert_eq!(
            classify_jwt_finding(&path, Some(4)),
            JwtKeyfuncVerdict::Guarded
        );
    }

    #[test]
    fn switch_dispatch_on_signing_method_is_guarded() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("jwt.go");
        fs::write(
            &path,
            b"package auth\n\nfunc Verify(token string) error {\n    return jwt.Parse(token, func(t *jwt.Token) (any, error) {\n        switch t.Method.(type) {\n        case *jwt.SigningMethodHMAC:\n            return hmacKey, nil\n        case *jwt.SigningMethodRSA:\n            return rsaKey, nil\n        default:\n            return nil, errors.New(\"unknown signing method\")\n        }\n    })\n}\n",
        )
        .unwrap();
        assert_eq!(
            classify_jwt_finding(&path, Some(4)),
            JwtKeyfuncVerdict::Guarded
        );
    }

    #[test]
    fn is_jwt_class_recognises_canonical_ids() {
        assert!(is_jwt_class(&finding("security:jwt_validation_bypass", 1)));
        assert!(is_jwt_class(&finding("security:jwt_alg_none_bypass", 1)));
        assert!(!is_jwt_class(&finding("security:sql_injection", 1)));
        assert!(!is_jwt_class(&finding(
            "security:react_xss_dangerous_html",
            1
        )));
    }

    #[test]
    fn missing_file_returns_unguarded() {
        let result = classify_jwt_finding(Path::new("/nonexistent/never/exists.go"), Some(1));
        assert_eq!(result, JwtKeyfuncVerdict::Unguarded);
    }

    #[test]
    fn missing_line_returns_unguarded() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("jwt.go");
        fs::write(&path, b"package foo\n").unwrap();
        let result = classify_jwt_finding(&path, None);
        assert_eq!(result, JwtKeyfuncVerdict::Unguarded);
    }

    #[test]
    fn jwt_keyfunc_with_valid_methods_guard_yields_invariant_violation() {
        // Pure predicate: algorithm-restriction guard → InvariantViolationProof.
        use common::slop::ProofClass;
        let result = crate::proof_obligation::classify_jwt_keyfunc_proof(true, false, false);
        assert_eq!(result, ProofClass::InvariantViolationProof);
    }

    #[test]
    fn jwt_keyfunc_nil_nil_return_yields_reachability() {
        // Pure predicate: keyfunc returns nil,nil without any guard → ReachabilityProof.
        use common::slop::ProofClass;
        let result = crate::proof_obligation::classify_jwt_keyfunc_proof(false, true, false);
        assert_eq!(result, ProofClass::ReachabilityProof);
    }

    #[test]
    fn jwt_keyfunc_grafana_fp_class_yields_invariant_violation() {
        // Grafana FP class: ParseWithClaims + WithValidMethods guard on a real file.
        // The source-reading classify_jwt_validation_bypass_proof must return
        // InvariantViolationProof, suppressing the finding.
        use common::slop::ProofClass;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("jwt_handler.go");
        fs::write(
            &path,
            b"package node\n\nfunc (h *jwtHandler) verify(w http.ResponseWriter, r *http.Request) {\n\
              token, err := jwt.ParseWithClaims(strToken, &claims, h.keyFunc,\n\
              \t\t\tjwt.WithValidMethods([]string{\"RS256\"}),\n\
              \t\t\tjwt.WithoutClaimsValidation())\n\
              _ = token; _ = err\n}\n",
        )
        .unwrap();
        let source = std::fs::read_to_string(&path).unwrap();
        let f = finding("security:jwt_validation_bypass", 4);
        let result = crate::proof_obligation::classify_jwt_validation_bypass_proof(&source, &f);
        assert_eq!(result, ProofClass::InvariantViolationProof);
    }

    #[test]
    fn with_valid_methods_option_is_guarded() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("jwt_handler.go");
        fs::write(
            &path,
            b"package node\n\nfunc (h *jwtHandler) verify(out http.ResponseWriter, r *http.Request) {\n\
              token, err := jwt.ParseWithClaims(strToken, &claims, h.keyFunc,\n\
              \t\t\tjwt.WithValidMethods([]string{\"HS256\"}),\n\
              \t\t\tjwt.WithoutClaimsValidation())\n\
              }\n",
        )
        .unwrap();
        assert_eq!(
            classify_jwt_finding(&path, Some(4)),
            JwtKeyfuncVerdict::Guarded
        );
    }
}
