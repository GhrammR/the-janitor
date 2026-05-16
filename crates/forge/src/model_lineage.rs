use crate::metadata::DOMAIN_FIRST_PARTY;
use crate::slop_hunter::{Severity, SlopFinding};
use common::slop::{ProofClass, StructuredFinding};

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

/// LLM model load sinks that require provenance attestation.
const LLM_LOAD_SINKS: &[&str] = &[
    "from_pretrained(",
    "AutoModelForCausalLM.from_pretrained",
    "load_model(",
    "trust_remote_code=True",
    "pipeline(",
];

/// Provenance attestation suppressors within ±10 lines of a load sink.
const PROVENANCE_SUPPRESSORS: &[&str] = &[
    "model_sha256=",
    "model_hash=",
    "verify_model_hash(",
    "# sha256:",
    "# sha256 ",
    "sha256:",
    "model_digest=",
    "verify_weights(",
    "check_hash(",
];

/// Window half-width in lines for provenance attestation lookup.
const WINDOW_HALF: usize = 10;

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

/// Returns true when a model load sink exists without a nearby provenance
/// attestation — the Kani-provable Boolean predicate for this detector.
#[must_use]
pub fn llm_provenance_missing(has_load_sink: bool, has_provenance: bool) -> bool {
    has_load_sink && !has_provenance
}

/// Emit `security:llm_model_unverified_load` findings for every LLM model
/// load call that lacks a provenance attestation within ±10 lines.
pub fn emit_llm_model_provenance_findings(source_str: &str, label: &str) -> Vec<StructuredFinding> {
    let lines: Vec<&str> = source_str.lines().collect();
    let mut findings = Vec::new();

    for (i, line) in lines.iter().enumerate() {
        let hit = LLM_LOAD_SINKS.iter().any(|sink| line.contains(sink));
        if !hit {
            continue;
        }

        // Collect ±WINDOW_HALF lines around the sink.
        let lo = i.saturating_sub(WINDOW_HALF);
        let hi = (i + WINDOW_HALF + 1).min(lines.len());
        let window = lines[lo..hi].join("\n");

        let has_provenance = PROVENANCE_SUPPRESSORS
            .iter()
            .any(|sup| window.contains(sup));

        if llm_provenance_missing(true, has_provenance) {
            findings.push(StructuredFinding {
                id: "security:llm_model_unverified_load".to_string(),
                severity: Some("KevCritical".to_string()),
                file: Some(label.to_string()),
                line: Some((i + 1) as u32),
                proof_class: Some(ProofClass::LatticeGapProposal),
                remediation: Some(
                    "Add a SHA-256 hash check before loading: verify_model_hash(path, expected_sha256) or record model_sha256= in a manifest".to_string(),
                ),
                ..Default::default()
            });
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- detect_model_weight_backdoor (legacy) ----

    #[test]
    fn flags_unsigned_safetensors_adapter_loading() {
        let source = br#"
header = "{\"__metadata__\":{\"format\":\"pt\"},\"weight_map\":{\"layer\":\"adapter_model.safetensors\"}}"
weights = load_file("adapter_model.safetensors")
model = PeftModel.from_pretrained(base_model, "lora")
"#;
        let findings = detect_model_weight_backdoor(source);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("security:model_weight_backdoor")),
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
        assert!(detect_model_weight_backdoor(source).is_empty());
    }

    // ---- emit_llm_model_provenance_findings — True Positives ----

    #[test]
    fn tp_from_pretrained_no_hash() {
        let src = r#"model = AutoModelForCausalLM.from_pretrained("mistralai/Mistral-7B")"#;
        let findings = emit_llm_model_provenance_findings(src, "train.py");
        assert!(
            findings
                .iter()
                .any(|f| f.id == "security:llm_model_unverified_load"),
            "from_pretrained without hash must fire"
        );
    }

    #[test]
    fn tp_load_model_no_hash() {
        let src = r#"m = load_model("weights/llama.bin")"#;
        let findings = emit_llm_model_provenance_findings(src, "infer.py");
        assert!(!findings.is_empty(), "load_model without hash must fire");
    }

    #[test]
    fn tp_trust_remote_code_no_hash() {
        let src = r#"model = AutoModel.from_pretrained("org/model", trust_remote_code=True)"#;
        let findings = emit_llm_model_provenance_findings(src, "run.py");
        assert!(
            !findings.is_empty(),
            "trust_remote_code=True without attestation must fire"
        );
    }

    #[test]
    fn tp_pipeline_no_hash() {
        let src = r#"pipe = pipeline("text-generation", model="gpt2")"#;
        let findings = emit_llm_model_provenance_findings(src, "gen.py");
        assert!(!findings.is_empty(), "pipeline without hash must fire");
    }

    // ---- emit_llm_model_provenance_findings — True Negatives ----

    #[test]
    fn tn_from_pretrained_with_sha256_comment() {
        let src = "# sha256: abc123def456\nmodel = AutoModelForCausalLM.from_pretrained(\"org/m\")";
        assert!(
            emit_llm_model_provenance_findings(src, "m.py").is_empty(),
            "sha256 comment within window must suppress"
        );
    }

    #[test]
    fn tn_model_hash_field() {
        let src = "model_hash=expected_digest\nmodel = load_model(\"weights.bin\")";
        assert!(
            emit_llm_model_provenance_findings(src, "m.py").is_empty(),
            "model_hash= within window must suppress"
        );
    }

    #[test]
    fn tn_verify_model_hash_call() {
        let src = "verify_model_hash(path, sha256)\nmodel = pipeline(\"ner\", model=path)";
        assert!(
            emit_llm_model_provenance_findings(src, "m.py").is_empty(),
            "verify_model_hash call must suppress"
        );
    }

    #[test]
    fn tn_no_load_sink_no_finding() {
        let src = r#"x = 1 + 1"#;
        assert!(
            emit_llm_model_provenance_findings(src, "m.py").is_empty(),
            "source with no load sink must produce no findings"
        );
    }

    // ---- Boolean predicate ----

    #[test]
    fn predicate_fires_on_sink_without_provenance() {
        assert!(llm_provenance_missing(true, false));
        assert!(!llm_provenance_missing(true, true));
        assert!(!llm_provenance_missing(false, false));
        assert!(!llm_provenance_missing(false, true));
    }
}
