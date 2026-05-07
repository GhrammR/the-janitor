use crate::metadata::DOMAIN_FIRST_PARTY;
use crate::slop_hunter::{Severity, SlopFinding};

const WEIGHT_LOAD_MARKERS: &[&str] = &[
    ".safetensors",
    "safetensors",
    "adapter_model.safetensors",
    "adapter_model.bin",
    "adapter_config.json",
    "lora",
    "peftmodel.from_pretrained",
    "load_file(",
    "from_single_file(",
];

const LINEAGE_MARKERS: &[&str] = &[
    "sha256",
    "digest",
    "manifest",
    "signature",
    ".sig",
    "verify(",
    "verify_asset",
    "ed25519",
    "ml-dsa",
    "provenance",
];

/// Detects unsigned or lineage-less model adapters loaded directly into a runtime.
pub fn detect_model_weight_backdoor(source: &[u8]) -> Vec<SlopFinding> {
    let text = String::from_utf8_lossy(source).to_ascii_lowercase();
    if !WEIGHT_LOAD_MARKERS
        .iter()
        .any(|marker| text.contains(marker))
    {
        return Vec::new();
    }
    if LINEAGE_MARKERS.iter().any(|marker| text.contains(marker)) {
        return Vec::new();
    }

    vec![SlopFinding {
        start_byte: 0,
        end_byte: source.len(),
        description: "security:model_weight_backdoor — lineage-less adapter or safetensors payload is loaded without signature or manifest verification".into(),
        severity: Severity::High,
        domain: DOMAIN_FIRST_PARTY,
    }]
}

#[cfg(test)]
mod tests {
    use super::detect_model_weight_backdoor;

    #[test]
    fn flags_unsigned_safetensors_adapter_loading() {
        let source = br#"
header = "{\"__metadata__\":{\"format\":\"pt\"},\"weight_map\":{\"layer\":\"adapter_model.safetensors\"}}"
weights = load_file("adapter_model.safetensors")
model = PeftModel.from_pretrained(base_model, "lora")
"#;
        let findings = detect_model_weight_backdoor(source);
        assert!(
            findings.iter().any(|finding| finding
                .description
                .contains("security:model_weight_backdoor")),
            "expected unsigned safetensors loading to be flagged"
        );
    }

    #[test]
    fn ignores_verified_weight_lineage() {
        let source = br#"
manifest = load_manifest("adapter_model.safetensors.sig")
expected_sha256 = manifest["sha256"]
verify_asset("adapter_model.safetensors", expected_sha256, manifest["signature"])
"#;
        let findings = detect_model_weight_backdoor(source);
        assert!(
            findings.is_empty(),
            "verified lineage should suppress the finding"
        );
    }
}
