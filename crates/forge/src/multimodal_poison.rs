//! Detects steganographic or poisoned data embedded in media carrier files
//! (PNG, JPEG, PDF, WAV) passed to an LLM multimodal input path.
//! Called from `crates/forge/src/slop_hunter.rs` via `detect_multimodal_rag_poisoning`.

use crate::metadata::DOMAIN_FIRST_PARTY;
use crate::slop_hunter::{Severity, SlopFinding};

const CARRIER_MARKERS: &[&str] = &[
    ".png", ".jpg", ".jpeg", ".pdf", ".wav", ".mp3", "image/", "audio/",
];

const OCR_MARKERS: &[&str] = &[
    "pytesseract",
    "image_to_string",
    "ocr(",
    "ocr_image",
    "documentai",
    "textract",
];

const CONTEXT_SINK_MARKERS: &[&str] = &[
    "responses.create",
    "chat.completions.create",
    "messages.create",
    "llm.invoke",
    "context.append",
    "prompt +=",
    "rag_context",
    "gpt-4-vision-preview",
];

const SANITIZER_MARKERS: &[&str] = &[
    "sanitize_metadata",
    "strip_exif",
    "remove_metadata",
    "clear_metadata",
    "metadata_sanitizer",
    "content_disarm",
];

/// Detects multimodal carrier content flowing through OCR/vision parsing into an LLM sink without sanitization.
pub fn detect_multimodal_rag_poisoning(source: &[u8]) -> Vec<SlopFinding> {
    let text = String::from_utf8_lossy(source).to_ascii_lowercase();
    let has_carrier = CARRIER_MARKERS.iter().any(|marker| text.contains(marker));
    let has_ocr = OCR_MARKERS.iter().any(|marker| text.contains(marker));
    let has_sink = CONTEXT_SINK_MARKERS
        .iter()
        .any(|marker| text.contains(marker));
    let has_sanitizer = SANITIZER_MARKERS.iter().any(|marker| text.contains(marker));
    if !(has_carrier && has_ocr && has_sink) || has_sanitizer {
        return Vec::new();
    }

    vec![SlopFinding {
        start_byte: 0,
        end_byte: source.len(),
        description: "security:multimodal_rag_poisoning — image, audio, or PDF carrier reaches an OCR or vision parser and then an LLM context sink without metadata sanitization".into(),
        severity: Severity::High,
        domain: DOMAIN_FIRST_PARTY,
    }]
}

#[cfg(test)]
mod tests {
    use super::detect_multimodal_rag_poisoning;

    #[test]
    fn flags_unsanitized_png_ocr_flow_into_llm_context() {
        let source = br#"
carrier = "invoice.png"
text = pytesseract.image_to_string(carrier)
rag_context.append(text)
client.responses.create(model="gpt-4-vision-preview", input=rag_context)
"#;
        let findings = detect_multimodal_rag_poisoning(source);
        assert!(
            findings.iter().any(|finding| finding
                .description
                .contains("security:multimodal_rag_poisoning")),
            "expected unsanitized multimodal flow to be flagged"
        );
    }

    #[test]
    fn ignores_sanitized_pdf_ocr_flow() {
        let source = br#"
carrier = sanitize_metadata("statement.pdf")
text = pytesseract.image_to_string(carrier)
llm.invoke(text)
"#;
        let findings = detect_multimodal_rag_poisoning(source);
        assert!(
            findings.is_empty(),
            "metadata sanitization should suppress the finding"
        );
    }
}
