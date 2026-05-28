//! OAuth Pre-Account Fusion Detector (P1-13).
//!
//! Detects identity pre-account takeover — the pattern where a local account is
//! created or looked up by email and then merged with an OAuth/SSO identity
//! without requiring that the local email address is verified first.
//!
//! ## Detection Strategy
//!
//! Uses AhoCorasick pre-screen for account-merge sink keywords, then emits
//! `security:oauth_account_fusion_pretakeover` at `KevCritical` when the merge
//! sink is NOT preceded by an email-verification dominance check within the same
//! source block (± 30 lines heuristic window).
//!
//! Plain email equality (`user.email == provider.email`) is explicitly NOT a
//! sufficient sanitizer — only a boolean verified flag, a signed token check, or
//! a provider-attested claim counts.

use std::sync::OnceLock;

use aho_corasick::{AhoCorasick, MatchKind};

use crate::metadata::DOMAIN_FIRST_PARTY;
use crate::slop_hunter::{Severity, SlopFinding};

// ---------------------------------------------------------------------------
// Merge-sink patterns (account linking / identity fusion)
// ---------------------------------------------------------------------------

/// AhoCorasick automaton for account-merge sink keywords.
fn merge_sink_ac() -> &'static AhoCorasick {
    static AC: OnceLock<AhoCorasick> = OnceLock::new();
    AC.get_or_init(|| {
        AhoCorasick::new([
            "linkAccount".as_bytes(),
            b"link_account",
            b"mergeAccount",
            b"merge_account",
            b"connectProvider",
            b"connect_provider",
            b"associateIdentity",
            b"associate_identity",
            b"find_or_create_by",
            b"findOrCreateBy",
            b"OAuth.link",
            b"passport.authenticate",
            b"OmniAuth",
            b"omniauth",
            b"provider_link",
            b"account_link",
            b"NextAuth",
            b"linkWithCredential",
            b"linkWithPopup",
            b"linkWithRedirect",
        ])
        .expect("merge_sink_ac: static patterns are valid")
    })
}

// ---------------------------------------------------------------------------
// Email-verification dominator patterns
// ---------------------------------------------------------------------------

/// AhoCorasick automaton for email-verified dominator keywords.
fn email_verified_ac() -> &'static AhoCorasick {
    static AC: OnceLock<AhoCorasick> = OnceLock::new();
    AC.get_or_init(|| {
        AhoCorasick::new([
            "email_verified".as_bytes(),
            b"emailVerified",
            b"email_confirmed",
            b"emailConfirmed",
            b"isVerified",
            b"is_verified",
            b"verifiedEmail",
            b"verified_email",
            b"email_verification_token",
            b"confirm_email",
            b"confirmEmail",
            b"verifyEmail",
            b"verify_email",
            b"EmailVerified",
            b"providerData.email_verified",
            b"id_token_hint",
            b"email:verified",
        ])
        .expect("email_verified_ac: static patterns are valid")
    })
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Scan `source` for OAuth pre-account-takeover patterns.
///
/// Returns one finding per merge sink that is not locally dominated by an
/// email-verification guard within a ±30-line heuristic window.
pub fn detect_oauth_account_fusion(source: &[u8]) -> Vec<SlopFinding> {
    let mut out = Vec::new();
    let sink_ac = merge_sink_ac();

    for mat in sink_ac.find_iter(source) {
        let sink_byte = mat.start();
        let sink_end = mat.end();

        // Extract a ±30-line window around the sink.
        let window_start = window_line_start(source, sink_byte, 30);
        let window_end = window_line_end(source, sink_end, 30);
        let window = &source[window_start..window_end];

        // If no verification guard found in the window, fire.
        if !email_verified_ac().is_match(window) {
            let line = byte_to_line(source, sink_byte);
            let pattern_text =
                std::str::from_utf8(&source[sink_byte..sink_end]).unwrap_or("<utf8-error>");
            out.push(SlopFinding {
                start_byte: sink_byte,
                end_byte: sink_end,
                description: format!(
                    "security:oauth_account_fusion_pretakeover — account merge sink \
                     `{pattern_text}` at line {line} is not dominated by an \
                     email_verified check; attacker can pre-register victim email \
                     and absorb the OAuth identity (CWE-287, OWASP A07)"
                ),
                domain: DOMAIN_FIRST_PARTY,
                severity: Severity::KevCritical,
            });
        }
    }

    out
}

// ---------------------------------------------------------------------------
// OAuth State Parameter Absence Detector (P17-4)
// ---------------------------------------------------------------------------

/// AhoCorasick automaton for OAuth authorization-code extraction patterns.
fn oauth_code_ac() -> &'static AhoCorasick {
    static AC: OnceLock<AhoCorasick> = OnceLock::new();
    AC.get_or_init(|| {
        AhoCorasick::new([
            b"code=" as &[u8],
            b"authorization_code",
            b"grant_type=authorization_code",
            b"oauth_code",
            b"auth_code",
        ])
        .expect("oauth_code_ac: static patterns are valid")
    })
}

/// AhoCorasick automaton for state-parameter validation patterns.
fn oauth_state_ac() -> &'static AhoCorasick {
    static AC: OnceLock<AhoCorasick> = OnceLock::new();
    AC.get_or_init(|| {
        AhoCorasick::new([
            b"state_param" as &[u8],
            b"oauth_state",
            b"csrf_token",
            b"request_verifier",
            b"pkce_verifier",
            b"state =",
            b"state=",
        ])
        .expect("oauth_state_ac: static patterns are valid")
    })
}

/// Scan `source` for OAuth callbacks that extract an authorization code without
/// validating the `state` parameter (CSRF-driven code injection, CWE-352/352).
///
/// Emits one finding when group-1 (code extraction) fires anywhere in the
/// source AND group-2 (state validation) is entirely absent from the source.
/// Both groups are whole-file: a handler that receives `code=` shares a file
/// with state validation or it doesn't — intra-handler windowing would add FPs
/// for files where state is validated in a helper referenced by name.
pub fn detect_missing_state_validation(source: &[u8], label: &str) -> Vec<SlopFinding> {
    if !oauth_code_ac().is_match(source) {
        return Vec::new();
    }
    if oauth_state_ac().is_match(source) {
        return Vec::new();
    }
    vec![SlopFinding {
        start_byte: 0,
        end_byte: source.len().min(1),
        description: format!(
            "security:oauth_missing_state_validation — OAuth callback handler in `{label}` \
             extracts authorization code without validating state parameter \
             (CSRF-driven code injection vector, CWE-352)"
        ),
        domain: DOMAIN_FIRST_PARTY,
        severity: Severity::High,
    }]
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Walk backwards from `byte` by up to `lines` newlines.
fn window_line_start(source: &[u8], byte: usize, lines: usize) -> usize {
    let mut count = 0;
    let mut pos = byte;
    while pos > 0 {
        pos -= 1;
        if source[pos] == b'\n' {
            count += 1;
            if count >= lines {
                return pos + 1;
            }
        }
    }
    0
}

/// Walk forwards from `byte` by up to `lines` newlines.
fn window_line_end(source: &[u8], byte: usize, lines: usize) -> usize {
    let mut count = 0;
    let mut pos = byte;
    while pos < source.len() {
        if source[pos] == b'\n' {
            count += 1;
            if count >= lines {
                return pos + 1;
            }
        }
        pos += 1;
    }
    source.len()
}

/// Convert a byte offset to a 1-indexed line number.
fn byte_to_line(source: &[u8], byte: usize) -> usize {
    source[..byte.min(source.len())]
        .iter()
        .filter(|&&b| b == b'\n')
        .count()
        + 1
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_linkacount_without_email_verified() {
        let src = b"
async function oauthCallback(req, res) {
  const user = await User.findOrCreateBy({ email: req.body.email });
  await linkAccount(user, req.oauthProfile);
}
";
        let findings = detect_oauth_account_fusion(src);
        assert!(
            !findings.is_empty(),
            "linkAccount without email_verified must fire"
        );
        assert!(findings[0].description.contains("oauth_account_fusion"));
        assert_eq!(findings[0].severity, Severity::KevCritical);
    }

    #[test]
    fn suppressed_when_email_verified_guard_present() {
        let src = b"
async function oauthCallback(req, res) {
  if (!req.oauthProfile.email_verified) {
    return res.status(403).json({ error: 'email not verified' });
  }
  const user = await User.findOrCreateBy({ email: req.oauthProfile.email });
  await linkAccount(user, req.oauthProfile);
}
";
        let findings = detect_oauth_account_fusion(src);
        assert!(
            findings.is_empty(),
            "email_verified guard must suppress the finding"
        );
    }

    #[test]
    fn flags_passport_authenticate_without_verification() {
        let src = b"
router.get('/auth/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    mergeAccount(req.user, req.session.localUser);
    res.redirect('/dashboard');
  }
);
";
        let findings = detect_oauth_account_fusion(src);
        assert!(
            !findings.is_empty(),
            "passport.authenticate + mergeAccount without email verification must fire"
        );
    }

    #[test]
    fn suppressed_when_emailconfirmed_used() {
        let src = b"
def oauth_callback(request):
    if not request.social_auth.email_confirmed:
        raise PermissionDenied
    user = User.objects.find_or_create_by(email=request.social_auth.email)
    link_account(user, request.social_auth)
";
        let findings = detect_oauth_account_fusion(src);
        assert!(
            findings.is_empty(),
            "email_confirmed guard must suppress the finding"
        );
    }

    #[test]
    fn flags_omniauth_without_verification() {
        let src = b"
def omniauth_callback
  @user = User.find_or_create_by(email: auth.info.email)
  sign_in_and_redirect @user
end
";
        let findings = detect_oauth_account_fusion(src);
        assert!(
            !findings.is_empty(),
            "OmniAuth find_or_create_by without email_verified must fire"
        );
    }

    // ── P17-4: detect_missing_state_validation ──────────────────────────────

    #[test]
    fn state_validation_tp_code_without_state() {
        // TP: code= present, no state validation → must fire
        let src = b"
def oauth_callback(request):
    code = request.GET.get('code=')
    token = exchange_code_for_token(code)
    user = get_or_create_user(token)
    login(request, user)
";
        let findings = detect_missing_state_validation(src, "views.py");
        assert!(
            !findings.is_empty(),
            "code= without state validation must fire"
        );
        assert!(
            findings[0]
                .description
                .contains("oauth_missing_state_validation"),
            "finding description must contain the rule ID"
        );
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn state_validation_tn_code_with_state_present() {
        // TN: code= present AND state= present → must not fire
        let src = b"
def oauth_callback(request):
    code = request.GET['code=']
    state = request.GET['state=']
    if state != request.session['oauth_state']:
        raise SuspiciousOperation
    token = exchange_code_for_token(code)
";
        let findings = detect_missing_state_validation(src, "views.py");
        assert!(
            findings.is_empty(),
            "state= present must suppress the finding"
        );
    }

    #[test]
    fn state_validation_tn_no_oauth_code() {
        // TN: no code-extraction pattern → must not fire
        let src = b"
def home(request):
    user = request.user
    return render(request, 'home.html', {'user': user})
";
        let findings = detect_missing_state_validation(src, "views.py");
        assert!(findings.is_empty(), "no OAuth code pattern must not fire");
    }

    #[test]
    fn state_validation_tn_state_without_code() {
        // TN: state= present but no code-extract → must not fire
        let src = b"
function validateState(req) {
    const state = req.query['state='];
    if (state !== req.session.oauth_state) throw new Error('CSRF');
}
";
        let findings = detect_missing_state_validation(src, "auth.js");
        assert!(
            findings.is_empty(),
            "state= without code-extract must not fire"
        );
    }
}

// ── IQ-6: PKCE Downgrade Detector ────────────────────────────────────────────

/// AhoCorasick patterns indicating an OAuth/OIDC server advertises PKCE-only
/// (`code_challenge_method=S256`) but also accepts implicit flow.
const PKCE_ADVERTISED: &[&[u8]] = &[
    b"code_challenge_method",
    b"code_challenge_method=S256",
    b"code_challenge_method = ",
    b"require_pkce",
    b"pkce_required",
];

const IMPLICIT_FLOW_SINKS: &[&[u8]] = &[
    b"response_type=token",
    b"response_type: token",
    b"response_type: \"token\"",
    b"response_type='token'",
    b"responseType: 'token'",
    b"responseType: \"token\"",
    b"response_type=id_token",
    b"response_type: id_token",
];

/// Returns `true` when a PKCE-advertised endpoint also accepts implicit flow —
/// the core PKCE downgrade invariant.
pub fn pkce_downgrade_possible(pkce_advertised: bool, implicit_accepted: bool) -> bool {
    pkce_advertised && implicit_accepted
}

/// Scan `source` for authorization endpoints that advertise PKCE
/// (`code_challenge_method=S256`) while also accepting `response_type=token`
/// (implicit flow). Emits `security:oauth_pkce_downgrade` at High.
pub fn detect_pkce_downgrade(source: &[u8], label: &str) -> Vec<SlopFinding> {
    let pkce_ac = AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostFirst)
        .build(PKCE_ADVERTISED)
        .expect("static PKCE_ADVERTISED patterns are valid");

    let implicit_ac = AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostFirst)
        .build(IMPLICIT_FLOW_SINKS)
        .expect("static IMPLICIT_FLOW_SINKS patterns are valid");

    let pkce_present = pkce_ac.find(source).is_some();
    let implicit_present = implicit_ac.find(source).is_some();

    if !pkce_downgrade_possible(pkce_present, implicit_present) {
        return Vec::new();
    }

    // Report at the byte offset of the first implicit-flow sink.
    let hit_byte = implicit_ac.find(source).map(|m| m.start()).unwrap_or(0);

    vec![SlopFinding {
        start_byte: hit_byte,
        end_byte: hit_byte,
        description: format!(
            "security:oauth_pkce_downgrade — `{label}` advertises \
             `code_challenge_method=S256` (PKCE-only) but also accepts \
             `response_type=token` (implicit flow). An attacker can downgrade \
             the flow to obtain access tokens without a code verifier, bypassing \
             PKCE entirely. Remove implicit-flow handling or enforce \
             `response_type=code` exclusively (RFC 9700 §4.1)."
        ),
        domain: crate::metadata::DOMAIN_FIRST_PARTY,
        severity: crate::slop_hunter::Severity::High,
    }]
}

#[cfg(test)]
mod pkce_tests {
    use super::*;

    #[test]
    fn predicate_exact_conjunction() {
        assert!(pkce_downgrade_possible(true, true));
        assert!(!pkce_downgrade_possible(true, false));
        assert!(!pkce_downgrade_possible(false, true));
        assert!(!pkce_downgrade_possible(false, false));
    }

    #[test]
    fn tp_pkce_advertised_with_implicit_accepted() {
        let src = br#"
# Authorization server config
code_challenge_method = "S256"
require_pkce = true
# Legacy clients may request implicit flow
response_type=token
"#;
        let findings = detect_pkce_downgrade(src, "auth_server.py");
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("oauth_pkce_downgrade")),
            "PKCE + implicit must fire"
        );
    }

    #[test]
    fn tn_pkce_only_no_implicit() {
        let src = br#"
code_challenge_method = "S256"
allowed_response_types = ["code"]
"#;
        let findings = detect_pkce_downgrade(src, "auth_server.py");
        assert!(findings.is_empty(), "PKCE-only must not fire");
    }

    #[test]
    fn tn_implicit_without_pkce_advertised() {
        let src = br#"
// Plain OAuth2 server, no PKCE
response_type=token
"#;
        let findings = detect_pkce_downgrade(src, "old_auth.py");
        assert!(
            findings.is_empty(),
            "implicit without PKCE advertisement must not fire"
        );
    }
}
