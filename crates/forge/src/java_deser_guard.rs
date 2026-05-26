//! P2-25 Java ObjectSerializationDecoder Allowlist-Bypass Deserialization Detector.
//!
//! Detects `ObjectSerializationDecoder` instantiations and `readObject()`/`deserialize(`
//! calls in Java/Kotlin/Scala source that lack a class allowlist guard within ±10 lines.
//! CVE-2026-42779 (CVSS 9.8) proved that Apache MINA, Netty, and Grizzly are exploitable
//! via crafted class hierarchies when `setAllowClasses(` or a `ClassFilter` is absent.
//!
//! # Detection model
//!
//! 1. **Deserialization sink**: any of `ObjectSerializationDecoder`, `new ObjectDecoder()`,
//!    `ObjectDecoderInputStream(`, `readObject()`, `deserialize(`.
//! 2. **Allowlist suppressor**: within ±10 lines, any of `setAllowClasses(`, `ClassFilter`,
//!    `AllowList`, `DenyList`, `allowlist`, `setDecoderClass`,
//!    `ObjectDecoder.CUMULATIVE_SIZE_LIMIT` must appear.
//! 3. If a sink appears without a suppressor → emit
//!    `security:java_deser_allowlist_bypass` at KevCritical.
//!
//! # Kani predicate
//!
//! `deser_missing_allowlist(has_decoder, has_allowlist)` is a pure boolean predicate
//! suitable for formal verification. The Kani harness in `reflexive_assurance.rs`
//! proves it is an exact conjunction.

use aho_corasick::{AhoCorasick, MatchKind};
use common::slop::StructuredFinding;

// ── Pattern tables ────────────────────────────────────────────────────────────

const DESER_SINKS: &[&str] = &[
    "ObjectSerializationDecoder",
    "new ObjectDecoder()",
    "ObjectDecoderInputStream(",
    "readObject()",
    "deserialize(",
];

// File-level context markers required before treating bare `deserialize(` as a
// Java Object Deserialization sink. Without these, `deserialize(` matches any
// generic `Deserializer<T>` interface (Kafka, Jackson, etc.) and produces FPs.
const OBJECT_DESER_CONTEXT_MARKERS: &[&str] = &[
    "ObjectInputStream",
    "Serializable",
    "ObjectDecoder",
    "ObjectSerializationDecoder",
    "readObject",
];

const ALLOWLIST_SUPPRESSORS: &[&str] = &[
    "setAllowClasses(",
    "ClassFilter",
    "AllowList",
    "DenyList",
    "allowlist",
    "setDecoderClass",
    "ObjectDecoder.CUMULATIVE_SIZE_LIMIT",
];

// ── Pure predicate (Kani-provable) ────────────────────────────────────────────

/// Returns `true` when a deserialization decoder is present without an allowlist
/// suppressor — the core allowlist-bypass invariant.
///
/// Extracted as a pure predicate so `reflexive_assurance.rs` can prove it is an
/// exact conjunction under all possible boolean inputs.
pub fn deser_missing_allowlist(has_decoder: bool, has_allowlist: bool) -> bool {
    has_decoder && !has_allowlist
}

// ── Source scanner ────────────────────────────────────────────────────────────

/// Scan `source` for deserialization sinks. For each match, check whether an
/// allowlist suppressor appears within `window` lines. Returns 1-indexed line
/// numbers where unguarded deserialization sinks occur.
fn find_unguarded_deser_sinks(source: &str, window: usize) -> Vec<u32> {
    let sink_ac = AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostFirst)
        .build(DESER_SINKS)
        .expect("static DESER_SINKS patterns are valid");

    let suppressor_ac = AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostFirst)
        .build(ALLOWLIST_SUPPRESSORS)
        .expect("static ALLOWLIST_SUPPRESSORS patterns are valid");

    let context_ac = AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostFirst)
        .build(OBJECT_DESER_CONTEXT_MARKERS)
        .expect("static OBJECT_DESER_CONTEXT_MARKERS patterns are valid");

    // Pre-compute: does this file contain Java Object Serialization context?
    let has_object_deser_context = context_ac.find(source.as_bytes()).is_some();

    let lines: Vec<&str> = source.lines().collect();
    let mut hits: Vec<u32> = Vec::new();

    for (line_idx, line) in lines.iter().enumerate() {
        if sink_ac.find(line.as_bytes()).is_none() {
            continue;
        }
        // Guard: bare `deserialize(` without Object Serialization context is a
        // generic interface method (Kafka Deserializer<T>, Jackson, etc.) — skip.
        if line.contains("deserialize(")
            && !line.contains("ObjectInputStream")
            && !line.contains("readObject")
            && !has_object_deser_context
        {
            continue;
        }

        let lo = line_idx.saturating_sub(window);
        let hi = (line_idx + window + 1).min(lines.len());
        let window_text = lines[lo..hi].join("\n");

        if suppressor_ac.find(window_text.as_bytes()).is_none() {
            hits.push((line_idx + 1) as u32);
        }
    }

    hits
}

// ── Public emitter ────────────────────────────────────────────────────────────

/// Emit `security:java_deser_allowlist_bypass` findings for every unguarded
/// deserialization sink in `source`. `file` labels the finding path.
pub fn emit_java_deser_findings(source: &str, file: &str) -> Vec<StructuredFinding> {
    find_unguarded_deser_sinks(source, 10)
        .into_iter()
        .map(|line_no| StructuredFinding {
            id: "security:java_deser_allowlist_bypass".into(),
            severity: Some("KevCritical".into()),
            file: Some(file.to_string()),
            line: Some(line_no),
            remediation: Some(
                "Add setAllowClasses( or a ClassFilter within ±10 lines of the \
                 deserialization decoder to prevent arbitrary class instantiation \
                 (CVE-2026-42779, CVSS 9.8)."
                    .into(),
            ),
            regulatory_regimes: Some(vec!["PCI-DSS-6.3".into(), "HIPAA-164.312(c)(1)".into()]),
            estimated_fine_floor_usd: Some(500_000),
            ..Default::default()
        })
        .collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Pure predicate ──────────────────────────────────────────────────────

    #[test]
    fn predicate_fires_only_on_decoder_without_allowlist() {
        assert!(deser_missing_allowlist(true, false));
        assert!(!deser_missing_allowlist(true, true));
        assert!(!deser_missing_allowlist(false, false));
        assert!(!deser_missing_allowlist(false, true));
    }

    // ── TP: ObjectSerializationDecoder with no filter ───────────────────────

    #[test]
    fn tp_object_serialization_decoder_no_filter() {
        let src = r#"
ChannelPipeline p = ch.pipeline();
p.addLast(new ObjectSerializationDecoder());
p.addLast(new ObjectSerializationEncoder());
p.addLast(new EchoServerHandler());
"#;
        let findings = emit_java_deser_findings(src, "EchoServer.java");
        assert!(
            !findings.is_empty(),
            "ObjectSerializationDecoder without allowlist must fire"
        );
        assert_eq!(findings[0].severity.as_deref(), Some("KevCritical"));
    }

    // ── TN: ObjectSerializationDecoder with setAllowClasses in window ────────

    #[test]
    fn tn_decoder_with_set_allow_classes() {
        let src = r#"
ObjectSerializationDecoder decoder = new ObjectSerializationDecoder();
decoder.setAllowClasses(SafeClass.class, AnotherSafe.class);
pipeline.addLast(decoder);
"#;
        let findings = emit_java_deser_findings(src, "PipelineInit.java");
        assert!(
            findings.is_empty(),
            "setAllowClasses( within window must suppress the finding"
        );
    }

    // ── TP: readObject() in unmarshalling context without ClassFilter ─────────

    #[test]
    fn tp_read_object_no_class_filter() {
        let src = r#"
ObjectInputStream ois = new ObjectInputStream(inputStream);
Object obj = ois.readObject();
return (MyClass) obj;
"#;
        let findings = emit_java_deser_findings(src, "Deserializer.java");
        assert!(
            !findings.is_empty(),
            "readObject() without ClassFilter must fire"
        );
    }

    // ── TN: ClassFilter present near readObject() ─────────────────────────────

    #[test]
    fn tn_read_object_with_class_filter() {
        let src = r#"
ClassFilter filter = new ClassFilter(SafeClass.class);
ValidatingObjectInputStream vois = new ValidatingObjectInputStream(in, filter);
Object obj = vois.readObject();
"#;
        let findings = emit_java_deser_findings(src, "SafeDeserializer.java");
        assert!(
            findings.is_empty(),
            "ClassFilter within window must suppress readObject() finding"
        );
    }

    // ── TP: deserialize( in Java Object Serialization context, no suppressor ────

    #[test]
    fn tp_deserialize_call_no_suppressor() {
        let src = r#"
// Java Object Serialization context — ObjectInputStream present
ObjectInputStream ois = new ObjectInputStream(inputStream);
public Object fromBytes(byte[] data) {
    return serializer.deserialize(data);
}
"#;
        let findings = emit_java_deser_findings(src, "Codec.java");
        assert!(
            !findings.is_empty(),
            "deserialize( in ObjectInputStream context without guard must fire"
        );
    }

    // ── TN: generic Deserializer<T> without Object Serialization context ──────

    #[test]
    fn tn_kafka_style_deserializer_interface_suppressed() {
        let src = r#"
// Kafka custom binary-protocol interface, no Java-object-deser context
key = keyBytes == null ? null : deserializers.keyDeserializer().deserialize(partition.topic(), headers, keyBytes);
value = valueBytes == null ? null : deserializers.valueDeserializer().deserialize(partition.topic(), headers, valueBytes);
"#;
        let findings = emit_java_deser_findings(src, "CompletedFetch.java");
        assert!(
            findings.is_empty(),
            "Kafka Deserializer<T> without ObjectInputStream context must not fire"
        );
    }

    // ── TN: AllowList present near deserialize( ──────────────────────────────

    #[test]
    fn tn_deserialize_with_allow_list() {
        let src = r#"
AllowList allowed = AllowList.of(SafeModel.class);
Object obj = serializer.deserialize(data, allowed);
"#;
        let findings = emit_java_deser_findings(src, "SafeCodec.java");
        assert!(
            findings.is_empty(),
            "AllowList within window must suppress deserialize( finding"
        );
    }

    // ── TP: suppressor outside window still fires ────────────────────────────

    #[test]
    fn tp_suppressor_outside_window_fires() {
        let mut src = String::from("ClassFilter globalFilter = new ClassFilter(Safe.class);\n");
        for _ in 0..15 {
            src.push('\n');
        }
        src.push_str("Object obj = ois.readObject();\n");
        let findings = emit_java_deser_findings(&src, "RiskyDeser.java");
        assert!(
            !findings.is_empty(),
            "suppressor >10 lines away must not block the finding"
        );
    }

    // ── TN: ObjectDecoder.CUMULATIVE_SIZE_LIMIT suppresses ───────────────────

    #[test]
    fn tn_cumulative_size_limit_suppresses() {
        let src = r#"
ObjectSerializationDecoder decoder = new ObjectSerializationDecoder();
decoder.setMaxObjectSize(ObjectDecoder.CUMULATIVE_SIZE_LIMIT);
ch.pipeline().addLast(decoder);
"#;
        let findings = emit_java_deser_findings(src, "SecurePipeline.java");
        assert!(
            findings.is_empty(),
            "ObjectDecoder.CUMULATIVE_SIZE_LIMIT within window must suppress"
        );
    }
}
