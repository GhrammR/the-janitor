//! Chronometric signature split-brain detector.

use crate::metadata::DOMAIN_FIRST_PARTY;
use crate::slop_hunter::{Severity, SlopFinding};

const SPLIT_BRAIN_LEEWAY_SECS: u64 = 300;

/// Detect auth paths that tolerate more than five minutes of clock skew
/// without a nonce / `jti` replay binding.
pub fn detect_clock_skew_auth_split_brain(source: &[u8]) -> Vec<SlopFinding> {
    let lower = ascii_lower(source);
    if !contains_any_bytes(
        &lower,
        &[
            b"jwt".as_slice(),
            b"id_token",
            b"access_token",
            b"signedurl",
            b"signed_url",
            b"presign",
            b"getsignedurl",
        ],
    ) {
        return Vec::new();
    }

    if has_nonce_or_jti_guard(&lower) {
        return Vec::new();
    }

    for (offset, seconds) in find_leeway_literals(&lower) {
        if leeway_exceeds_split_brain_threshold(seconds) {
            return vec![SlopFinding {
                start_byte: offset,
                end_byte: offset.saturating_add(16),
                description: format!(
                    "security:clock_skew_auth_split_brain — JWT or signed-URL validation accepts leeway of {seconds} seconds (>300) without a nonce/jti replay check; distributed verifiers can disagree on token expiry and forward stale authority."
                ),
                domain: DOMAIN_FIRST_PARTY,
                severity: Severity::High,
            }];
        }
    }

    Vec::new()
}

pub fn leeway_exceeds_split_brain_threshold(seconds: u64) -> bool {
    seconds > SPLIT_BRAIN_LEEWAY_SECS
}

fn has_nonce_or_jti_guard(lower: &[u8]) -> bool {
    contains_any_bytes(
        lower,
        &[
            b"nonce".as_slice(),
            b"jti",
            b"jwtid",
            b"token_id",
            b"replaycache",
            b"replay_cache",
        ],
    )
}

fn find_leeway_literals(lower: &[u8]) -> Vec<(usize, u64)> {
    const MARKERS: &[&[u8]] = &[
        b"leeway",
        b"clockskew",
        b"clock_skew",
        b"clocktolerance",
        b"clock_tolerance",
        b"allowedclockskewseconds",
        b"setallowedclockskewseconds",
        b"withleeway(",
    ];

    let mut out = Vec::new();
    for marker in MARKERS {
        let mut start = 0;
        while let Some(rel) = lower[start..]
            .windows(marker.len())
            .position(|window| window == *marker)
        {
            let idx = start + rel;
            if let Some(seconds) = parse_leeway_seconds(&lower[idx + marker.len()..]) {
                out.push((idx, seconds));
            }
            start = idx + marker.len();
        }
    }
    out
}

fn parse_leeway_seconds(bytes: &[u8]) -> Option<u64> {
    let mut i = 0;
    while i < bytes.len() && !bytes[i].is_ascii_digit() && bytes[i] != b'-' && bytes[i] != b'+' {
        i += 1;
    }
    if i >= bytes.len() || !bytes[i].is_ascii_digit() {
        return None;
    }

    let start = i;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    let value = std::str::from_utf8(&bytes[start..i])
        .ok()?
        .parse::<u64>()
        .ok()?;
    let unit_window = &bytes[i..bytes.len().min(i + 32)];

    if contains_any_bytes(unit_window, &[b"minute", b"minutes", b"min"]) {
        value.checked_mul(60)
    } else if contains_any_bytes(unit_window, &[b"millisecond", b"milliseconds", b"ms"]) {
        Some(value / 1_000)
    } else {
        Some(value)
    }
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

#[cfg(test)]
mod tests {
    use super::{detect_clock_skew_auth_split_brain, leeway_exceeds_split_brain_threshold};

    #[test]
    fn detects_large_jwt_leeway_without_jti() {
        let src = br#"
const claims = jwt.verify(token, key, {
  audience: "api",
  leeway: 601
});
"#;
        let findings = detect_clock_skew_auth_split_brain(src);
        assert!(findings
            .iter()
            .any(|f| f.description.contains("clock_skew_auth_split_brain")));
    }

    #[test]
    fn detects_large_clock_tolerance_without_jti() {
        let src = br#"
const claims = jwt.verify(token, key, {
  audience: "api",
  clockTolerance: 601
});
"#;
        let findings = detect_clock_skew_auth_split_brain(src);
        assert!(findings
            .iter()
            .any(|f| f.description.contains("clock_skew_auth_split_brain")));
    }

    #[test]
    fn clean_when_nonce_guard_present() {
        let src = br#"
const claims = jwt.verify(token, key, {
  audience: "api",
  leeway: 900,
  nonce: expectedNonce
});
"#;
        let findings = detect_clock_skew_auth_split_brain(src);
        assert!(findings.is_empty());
    }

    #[test]
    fn threshold_helper_obeys_five_minute_cap() {
        assert!(!leeway_exceeds_split_brain_threshold(300));
        assert!(leeway_exceeds_split_brain_threshold(301));
    }
}
