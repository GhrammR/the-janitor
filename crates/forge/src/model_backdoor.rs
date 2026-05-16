/// Neural model weight backdoor scanner — Phase A (header-only analysis).
///
/// Parses the safetensors binary format (8-byte LE header length + UTF-8 JSON)
/// and flags statistical anomalies that are consistent with BadNet-style
/// backdoors encoded in the weight metadata.  No inference engine required.
use common::slop::StructuredFinding;

const KNOWN_DTYPES: &[&str] = &["F32", "F16", "BF16", "I32", "I64", "U8", "BOOL"];

/// Standard tensor name prefixes that indicate legitimate model parameters.
const STANDARD_PREFIXES: &[&str] = &[
    "weight", "bias", "embed", "norm", "ln", "layer", "head", "pos", "attn", "mlp", "fc",
];

/// 10 MiB — headers beyond this size indicate unusual metadata injection.
const HEADER_SIZE_LIMIT: u64 = 10 * 1024 * 1024;

/// Parses a safetensors buffer and emits backdoor-anomaly findings.
pub fn emit_model_backdoor_findings(source: &[u8], label: &str) -> Vec<StructuredFinding> {
    if !label.ends_with(".safetensors") {
        return vec![];
    }

    // safetensors format: 8-byte LE u64 header_len, then header_len bytes of UTF-8 JSON.
    if source.len() < 8 {
        return vec![];
    }

    let header_len = u64::from_le_bytes(source[..8].try_into().unwrap_or([0u8; 8]));

    // Anomaly C: oversized header — emit finding and return (source may be truncated).
    if header_len > HEADER_SIZE_LIMIT {
        return vec![StructuredFinding {
            id: "security:model_oversized_header".to_string(),
            file: Some(label.to_string()),
            line: None,
            severity: Some("Low".to_string()),
            fingerprint: format!("model_oversized_header:{label}"),
            ..Default::default()
        }];
    }

    let header_end = 8u64.saturating_add(header_len) as usize;
    if source.len() < header_end {
        return vec![];
    }

    let header_bytes = &source[8..header_end];
    let Ok(header): Result<serde_json::Value, _> = serde_json::from_slice(header_bytes) else {
        return vec![];
    };

    let Some(obj) = header.as_object() else {
        return vec![];
    };

    let mut findings: Vec<StructuredFinding> = Vec::new();

    for (name, meta) in obj {
        // Skip the reserved __metadata__ key.
        if name == "__metadata__" {
            continue;
        }

        let Some(meta_obj) = meta.as_object() else {
            continue;
        };

        // Anomaly A: unknown dtype.
        if let Some(dtype_val) = meta_obj.get("dtype") {
            if let Some(dtype_str) = dtype_val.as_str() {
                if !KNOWN_DTYPES.contains(&dtype_str) {
                    findings.push(StructuredFinding {
                        id: "security:model_unknown_dtype".to_string(),
                        file: Some(label.to_string()),
                        line: None,
                        severity: Some("Medium".to_string()),
                        fingerprint: format!("model_unknown_dtype:{label}:{name}"),
                        ..Default::default()
                    });
                }
            }
        }

        // Anomaly B: suspicious scalar tensor with non-standard name prefix.
        if let Some(shape_val) = meta_obj.get("shape") {
            let is_scalar = match shape_val.as_array() {
                Some(arr) => arr.is_empty() || arr.len() == 1,
                None => false,
            };

            if is_scalar {
                let name_lower = name.to_lowercase();
                let is_standard = STANDARD_PREFIXES.iter().any(|p| name_lower.starts_with(p));

                if !is_standard {
                    findings.push(StructuredFinding {
                        id: "security:model_suspicious_scalar_tensor".to_string(),
                        file: Some(label.to_string()),
                        line: None,
                        severity: Some("Medium".to_string()),
                        fingerprint: format!("model_suspicious_scalar:{label}:{name}"),
                        ..Default::default()
                    });
                }
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    fn build_safetensors(header_json: &str) -> Vec<u8> {
        let json_bytes = header_json.as_bytes();
        let header_len = json_bytes.len() as u64;
        let mut buf = header_len.to_le_bytes().to_vec();
        buf.extend_from_slice(json_bytes);
        buf
    }

    use super::*;

    #[test]
    fn tp_unknown_dtype_fires() {
        let buf = build_safetensors(
            r#"{"trigger":{"dtype":"CUSTOM_TRIGGER","shape":[128,128],"data_offsets":[0,65536]}}"#,
        );
        let findings = emit_model_backdoor_findings(&buf, "model.safetensors");
        assert!(
            findings
                .iter()
                .any(|f| f.id == "security:model_unknown_dtype"),
            "expected model_unknown_dtype finding"
        );
    }

    #[test]
    fn tp_suspicious_scalar_fires() {
        let buf =
            build_safetensors(r#"{"_trigger":{"dtype":"F32","shape":[],"data_offsets":[0,4]}}"#);
        let findings = emit_model_backdoor_findings(&buf, "model.safetensors");
        assert!(
            findings
                .iter()
                .any(|f| f.id == "security:model_suspicious_scalar_tensor"),
            "expected suspicious scalar finding for _trigger"
        );
    }

    #[test]
    fn tp_oversized_header_fires() {
        // Encode a 12 MiB header length but provide only 8 bytes of source.
        let header_len: u64 = 12 * 1024 * 1024;
        let buf = header_len.to_le_bytes().to_vec();
        let findings = emit_model_backdoor_findings(&buf, "model.safetensors");
        assert!(
            findings
                .iter()
                .any(|f| f.id == "security:model_oversized_header"),
            "expected oversized header finding"
        );
    }

    #[test]
    fn tn_standard_weights_clean() {
        let buf = build_safetensors(
            r#"{"weight":{"dtype":"F32","shape":[768,768],"data_offsets":[0,2359296]}}"#,
        );
        let findings = emit_model_backdoor_findings(&buf, "model.safetensors");
        assert!(
            findings.is_empty(),
            "standard F32 weight tensor must not fire: {findings:?}"
        );
    }

    #[test]
    fn tn_non_safetensors_extension_ignored() {
        let buf = build_safetensors(
            r#"{"trigger":{"dtype":"CUSTOM_TRIGGER","shape":[],"data_offsets":[0,4]}}"#,
        );
        let findings = emit_model_backdoor_findings(&buf, "model.pt");
        assert!(
            findings.is_empty(),
            ".pt extension must be ignored by model_backdoor scanner"
        );
    }

    #[test]
    fn tn_malformed_header_no_panic() {
        // Only 4 bytes — cannot parse header length.
        let buf = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let findings = emit_model_backdoor_findings(&buf, "model.safetensors");
        assert!(
            findings.is_empty(),
            "truncated source must return empty without panic"
        );
    }
}
