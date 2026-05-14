//! Shared finding DTOs for the Janitor MCP protocol.
//!
//! [`StructuredFinding`] is the canonical machine-readable envelope emitted by
//! `janitor_bounce` and `janitor_scan`.  Consumers (agents, CI integrations, IDE
//! plugins) parse this instead of regex-matching human-readable prose strings,
//! enabling deterministic pre-commit remediation and structured audit logging.

use serde::{Deserialize, Serialize};

/// Regulatory regime identifiers recognized by Janitor structured findings.
pub const RECOGNIZED_REGULATORY_REGIMES: &[&str] = &[
    "GLBA",
    "EU_AI_Act_Art_10",
    "EU_NIS2",
    "EU_DORA",
    "NYDFS_500_11",
    "OCC_2024_32",
];

/// Structured verification harness artifact synthesized by the Kani bridge (P4-1).
///
/// Encapsulates the harness source text and run command emitted by
/// `crates/forge/src/kani_bridge::synthesize_kani_harness`. The artifact is
/// stored on [`ExploitWitness`] so it is carried through to SARIF and Bugcrowd
/// exports without requiring a separate pipeline lookup.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarnessArtifact {
    /// Name of the vulnerable function the harness exercises.
    pub function_name: String,
    /// Human-readable list of symbolic input descriptions (one per `kani::any()` call).
    pub inputs: Vec<String>,
    /// The safety assertion proven by the harness (negation of the bug class invariant).
    pub assertion: String,
    /// Complete harness source text (C or Rust) ready to be written to a temp file.
    pub harness_source: String,
    /// CLI command to invoke the bounded model checker, e.g.
    /// `cargo kani --harness harness_foo`.
    pub run_command: String,
}

/// Exclusive proof class required for critical findings.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofClass {
    #[default]
    ReachabilityProof,
    InvariantViolationProof,
    LatticeGapProposal,
}

/// Unified web proof object binding an external taint source to a web sink.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebProofArtifact {
    /// Human-readable external taint source, e.g. `url_param:url` or `rag_chunk:scraped_text`.
    pub source_label: String,
    /// Human-readable execution sink, e.g. `sink:innerHTML`, `sink:fetch`, `sink:llm.invoke`.
    pub sink_label: String,
    /// Deterministic IFDS hop list proving the source-to-sink path.
    pub ifds_trace: Vec<String>,
    /// Optional compact evidence marker, e.g. `schema_taint:proven` or
    /// `internal_metadata:169.254.169.254`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_marker: Option<String>,
    /// Exact proof class carried by this artifact.
    pub proof_class: ProofClass,
}

impl WebProofArtifact {
    /// Build a web proof artifact from an exploit witness while preserving the
    /// witness call chain as the IFDS hop list.
    pub fn from_witness(
        witness: &ExploitWitness,
        proof_class: ProofClass,
        evidence_marker: Option<String>,
    ) -> Self {
        let ifds_trace = if witness.call_chain.is_empty() {
            witness
                .path_proof
                .as_deref()
                .map(parse_ifds_trace)
                .unwrap_or_default()
        } else {
            witness.call_chain.clone()
        };

        Self {
            source_label: witness.source_label.clone(),
            sink_label: witness.sink_label.clone(),
            ifds_trace,
            evidence_marker,
            proof_class,
        }
    }

    /// Returns `true` when the artifact carries the requested compact evidence marker.
    pub fn has_marker(&self, marker: &str) -> bool {
        self.evidence_marker
            .as_deref()
            .is_some_and(|value| value.contains(marker))
            || self.ifds_trace.iter().any(|hop| hop.contains(marker))
            || self.source_label.contains(marker)
            || self.sink_label.contains(marker)
    }

    /// Return the source-bound IFDS trace with the external source and execution
    /// sink pinned at the edges even when detector output supplied only middle hops.
    pub fn bound_ifds_trace(&self) -> Vec<String> {
        let mut trace = Vec::with_capacity(self.ifds_trace.len() + 2);
        if !self.source_label.is_empty() {
            trace.push(self.source_label.clone());
        }
        for hop in &self.ifds_trace {
            if hop.trim().is_empty() {
                continue;
            }
            if trace.last().is_some_and(|last| last == hop) {
                continue;
            }
            trace.push(hop.clone());
        }
        if !self.sink_label.is_empty() && trace.last().is_none_or(|last| last != &self.sink_label) {
            trace.push(self.sink_label.clone());
        }
        trace
    }

    /// Render the canonical IFDS source-to-sink binding.
    pub fn ifds_trace_output(&self) -> String {
        self.bound_ifds_trace().join(" -> ")
    }

    /// Render compact Bugcrowd-ready markdown for DOM XSS, SSRF, and RAG evidence.
    pub fn to_markdown(&self) -> String {
        let mut rendered = format!(
            "WebProofArtifact: `{}` -> `{}` | IFDS: `{}` | proof=`{:?}`",
            self.source_label,
            self.sink_label,
            self.ifds_trace_output(),
            self.proof_class
        );
        if let Some(marker) = self
            .evidence_marker
            .as_deref()
            .filter(|marker| !marker.trim().is_empty())
        {
            rendered.push_str(" | marker=`");
            rendered.push_str(marker);
            rendered.push('`');
        }
        rendered
    }
}

fn parse_ifds_trace(proof: &str) -> Vec<String> {
    proof
        .replace("ifds:web_proof_artifact", "")
        .split("->")
        .map(str::trim)
        .filter(|hop| !hop.is_empty())
        .map(str::to_string)
        .collect()
}

/// Deterministic exploitability proof for a confirmed source-to-sink chain.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExploitWitness {
    /// Function where the tainted source originates.
    pub source_function: String,
    /// Human-readable label of the tainted source fact.
    pub source_label: String,
    /// Function that contains the reached sink.
    pub sink_function: String,
    /// Human-readable label of the reached sink.
    pub sink_label: String,
    /// Exact interprocedural call chain proving reachability.
    pub call_chain: Vec<String>,
    /// Verified deserialization gadget path when the finding proves an RCE
    /// chain against repository dependency evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gadget_chain: Option<Vec<String>>,
    /// Concrete reproduction command synthesised from a Z3 model after
    /// symbolic execution confirms the path is satisfiable. `None` when the
    /// Z3 refinement stage was not run, was inconclusive, or the witness was
    /// emitted by a detector without a repro template.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repro_cmd: Option<String>,
    /// Deterministic negative-taint audit proving that at least one
    /// source-to-sink path bypasses all registered sanitizers or validators.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sanitizer_audit: Option<String>,
    /// HTTP route path associated with the ingress handler, e.g. `"/api/v1/users"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_path: Option<String>,
    /// HTTP method associated with the ingress handler, e.g. `"POST"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_method: Option<String>,
    /// Optional authorization annotation or middleware requirement extracted
    /// from the ingress handler, e.g. `"ADMIN"` or `"Authenticated"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_requirement: Option<String>,
    /// Two-principal authorization replay evidence proving whether an
    /// authenticated attacker can access another principal's object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_witness: Option<AuthorizationWitness>,
    /// Cross-language memory-safety proof tying an ingress language boundary to
    /// an unsafe sink through a stable ABI or serialization adapter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_safety_witness: Option<MemorySafetyWitness>,
    /// Agent/tool-intent proof tying an operator-approved intent to the actual
    /// tool capability reached by untrusted agent output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_deception_witness: Option<AgentDeceptionWitness>,
    /// True when negative-taint analysis proves that at least one reachable
    /// source-to-sink path bypasses all registered sanitizers or validators.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub upstream_validation_absent: bool,
    /// Captured HTTP response from executing `repro_cmd` against a live test
    /// tenant via `--live-tenant`. `None` when the flag was not supplied or
    /// the command was not executed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub live_proof: Option<String>,
    /// Deterministic IFDS proof path that established the taint chain, or a
    /// human-readable summary of the symbolic path used to prove reachability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_proof: Option<String>,
    /// Inert exploit payload blob (base64 or text) synthesized for
    /// deserialization and parser-injection findings.  Never contains live
    /// shellcode; use a signed Wasm policy to enable red-team mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
    /// Ordered human-readable steps to reproduce the vulnerability using the
    /// attached `payload`.  Populated by the deserialization and parser
    /// payload synthesis pipelines.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reproduction_steps: Option<Vec<String>>,
    /// CVSS-informed plain-text risk classification, e.g.
    /// `"Critical RCE via Java ObjectOutputStream deserialization"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_classification: Option<String>,
    /// `Some(true)` when Configuration Taint analysis proved the sink's source
    /// is a static developer-configured value (e.g., a compiled Stylus bundle),
    /// not an attacker-controlled runtime input — finding is pattern-true but
    /// exploitability-false.  `Some(false)` when a dynamic taint flow was confirmed.
    /// `None` when the analysis was not run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub static_source_proven: Option<bool>,
    /// Kani / CBMC bounded-model-checker harness synthesized from this witness
    /// by the P4-1 formal verification bridge. `None` when the harness synthesizer
    /// was not run or the witness lacked sufficient structural information.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness_artifact: Option<HarnessArtifact>,
}

/// Deterministic two-principal authorization proof for IDOR and ownership
/// bypass findings.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationWitness {
    /// Attacker principal used for the replay request.
    pub attacker_subject: String,
    /// Victim principal whose object is referenced by the replay request.
    pub victim_subject: String,
    /// Object identifier or route fragment controlled by the victim.
    pub object_reference: String,
    /// Expected safe control result for the replay request.
    pub expected_control: String,
    /// Observed or synthesized verdict for the replay.
    pub replay_verdict: String,
}

/// Cross-language memory-safety witness for FFI and serialization boundaries.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemorySafetyWitness {
    /// Language or serialization surface where attacker-controlled data enters.
    pub source_language: String,
    /// Language/runtime containing the unsafe sink.
    pub sink_language: String,
    /// Stable ABI, FFI, or serialization bridge that must preserve ownership.
    pub boundary: String,
    /// Required dominance invariant before the sink is considered exploitable.
    pub required_dominance: String,
    /// Formal model used by the witness builder.
    pub model: String,
    /// Deterministic replay verdict for the fixture or live proof.
    pub replay_verdict: String,
}

/// Agent deception witness for prompt/tool-intent divergence.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentDeceptionWitness {
    /// Operator-approved or prompt-declared tool intent.
    pub declared_intent: String,
    /// Actual capability reached by the tool or agent transcript.
    pub observed_tool_capability: String,
    /// Deterministic policy predicate that must remain false for safe output.
    pub policy_predicate: String,
    /// Expected safe control result.
    pub expected_control: String,
    /// Version marker for downstream SARIF, ledger, and ARTICLE_REVIEW parsers.
    pub evidence_schema_version: String,
}

/// A structured antipattern or dead-symbol finding for MCP tool consumption.
///
/// Fields map to the `{ "id": "security:...", "file": "src/main.rs", "line": 42 }`
/// envelope required by the P1-3 structured-findings mandate.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredFinding {
    /// Machine-readable finding identifier, e.g. `"security:command_injection"`,
    /// `"dead_symbol"`, or `"architecture:version_silo"`.
    pub id: String,

    /// Relative path of the file containing the finding.
    ///
    /// `None` when the bounce path operates on a unified diff without per-file
    /// tracking (e.g. the MCP `janitor_bounce` tool receiving a raw patch string
    /// without `bounce_git` context).
    pub file: Option<String>,

    /// 1-indexed line number of the finding within the file.
    ///
    /// `None` for findings that are not line-addressable (e.g. symbol-level dead
    /// code entries where only the symbol name is known).
    pub line: Option<u32>,

    /// Deterministic BLAKE3 fingerprint of the finding's structural root.
    #[serde(default)]
    pub fingerprint: String,

    /// Severity tier of the finding, e.g. `"KevCritical"` or `"Critical"`.
    ///
    /// Optional for backwards compatibility with pre-severity structured
    /// findings and synthetic report-derived findings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,

    /// Actionable remediation instruction for the developer, e.g.
    /// `"Remove the hallucinated dependency from your manifest and run cargo update"`.
    ///
    /// `None` for findings that have no structured remediation guidance yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,

    /// Stable documentation URL for this finding class, e.g.
    /// `"https://thejanitor.app/findings/security-slopsquat-injection"`.
    ///
    /// Mapped to `helpUri` in SARIF output so GitHub Advanced Security and
    /// Azure DevOps surface the "How to fix" link inside the PR review UI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub docs_url: Option<String>,

    /// Deterministic proof that a source reaches a sink across function boundaries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exploit_witness: Option<ExploitWitness>,

    /// Supported ingress metadata naming the public or authenticated boundary
    /// that reaches this finding, e.g. `public_api GET /health` or
    /// `authenticated_endpoint auth=ADMIN POST /api/v1/users`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_requirement: Option<String>,

    /// Mandatory proof class for `KevCritical` / `Critical` findings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_class: Option<ProofClass>,

    /// Unified web proof artifact for DOM XSS, SSRF, and RAG trust findings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub web_proof_artifact: Option<WebProofArtifact>,

    /// True when the engine proved that at least one reachable source-to-sink
    /// path bypasses all registered sanitizers or validators.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub upstream_validation_absent: bool,

    /// Regulatory compliance regimes implicated by this finding, e.g.
    /// `["GLBA", "EU_AI_Act_Art_10", "EU_NIS2", "EU_DORA", "NYDFS_500_11", "OCC_2024_32"]`.
    ///
    /// Populated by detectors with statutory exposure (Financial PII, health
    /// data, COPPA-scope children's data). Surfaced in SARIF `help.markdown`
    /// and Bugcrowd VRT exports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regulatory_regimes: Option<Vec<String>>,

    /// Estimated minimum regulatory fine floor in USD for this finding class.
    ///
    /// Populated alongside `regulatory_regimes` to support CFO-tier risk
    /// quantification in the actuarial ledger. `None` for findings without
    /// statutory dollar exposure (e.g. dead-code, logic clone).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub estimated_fine_floor_usd: Option<u64>,
}

/// Returns `true` when the finding carries explicit internal-network or cloud-metadata
/// proof required by the acceptance oracle for SSRF.
pub fn finding_mentions_internal_metadata_proof(finding: &StructuredFinding) -> bool {
    const NEEDLES: &[&str] = &[
        "169.254.169.254",
        "metadata.google.internal",
        "100.100.100.200",
        "127.0.0.1",
        "localhost",
    ];

    let mut haystacks: Vec<&str> = vec![finding.id.as_str()];
    if let Some(witness) = finding.exploit_witness.as_ref() {
        haystacks.push(witness.source_label.as_str());
        haystacks.push(witness.sink_label.as_str());
        if let Some(repro) = witness.repro_cmd.as_deref() {
            haystacks.push(repro);
        }
        if let Some(proof) = witness.path_proof.as_deref() {
            haystacks.push(proof);
        }
        if let Some(audit) = witness.sanitizer_audit.as_deref() {
            haystacks.push(audit);
        }
        if let Some(payload) = witness.payload.as_deref() {
            haystacks.push(payload);
        }
        if let Some(live) = witness.live_proof.as_deref() {
            haystacks.push(live);
        }
        if let Some(steps) = witness.reproduction_steps.as_ref() {
            haystacks.extend(steps.iter().map(String::as_str));
        }
    }

    if finding
        .web_proof_artifact
        .as_ref()
        .is_some_and(|artifact| artifact.has_marker("169.254.169.254"))
    {
        return true;
    }

    haystacks
        .iter()
        .any(|haystack| NEEDLES.iter().any(|needle| haystack.contains(needle)))
}

/// Returns `true` when the finding carries the `schema_taint:proven` evidence marker
/// required by the DOM-XSS acceptance oracle.
pub fn finding_has_schema_taint_proof(finding: &StructuredFinding) -> bool {
    let mut haystacks: Vec<&str> = vec![finding.id.as_str()];
    if let Some(witness) = finding.exploit_witness.as_ref() {
        if let Some(repro) = witness.repro_cmd.as_deref() {
            haystacks.push(repro);
        }
        if let Some(proof) = witness.path_proof.as_deref() {
            haystacks.push(proof);
        }
        if let Some(audit) = witness.sanitizer_audit.as_deref() {
            haystacks.push(audit);
        }
        if let Some(payload) = witness.payload.as_deref() {
            haystacks.push(payload);
        }
        if let Some(steps) = witness.reproduction_steps.as_ref() {
            haystacks.extend(steps.iter().map(String::as_str));
        }
    }

    if finding
        .web_proof_artifact
        .as_ref()
        .is_some_and(|artifact| artifact.has_marker("schema_taint:proven"))
    {
        return true;
    }

    haystacks
        .iter()
        .any(|haystack| haystack.contains("schema_taint:proven"))
}

/// Returns `true` when the finding carries one of the required proof classes.
pub fn finding_has_required_proof_class(finding: &StructuredFinding) -> bool {
    finding.proof_class.is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_source_proven_serializes_and_deserializes_correctly() {
        let finding = StructuredFinding {
            id: "security:dom_xss_innerHTML".to_string(),
            file: Some("src/core.js".to_string()),
            line: Some(248),
            fingerprint: "abc123".to_string(),
            severity: Some("Informational".to_string()),
            exploit_witness: Some(ExploitWitness {
                static_source_proven: Some(true),
                source_label: "static compiled bundle".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let json = serde_json::to_string(&finding).expect("serialization must not fail");
        assert!(
            json.contains("static_source_proven"),
            "field must appear in JSON output"
        );
        assert!(json.contains("true"), "value must be true");
        let round_trip: StructuredFinding =
            serde_json::from_str(&json).expect("deserialization must not fail");
        assert_eq!(
            round_trip.exploit_witness.unwrap().static_source_proven,
            Some(true)
        );
    }

    #[test]
    fn static_source_proven_none_omitted_from_json() {
        let finding = StructuredFinding {
            id: "security:command_injection".to_string(),
            exploit_witness: Some(ExploitWitness {
                static_source_proven: None,
                ..Default::default()
            }),
            ..Default::default()
        };
        let json = serde_json::to_string(&finding).expect("serialization must not fail");
        assert!(
            !json.contains("static_source_proven"),
            "None field must be omitted from JSON to preserve schema backwards-compatibility"
        );
    }

    #[test]
    fn metadata_proof_helper_detects_internal_ip() {
        let finding = StructuredFinding {
            id: "security:ssrf".to_string(),
            exploit_witness: Some(ExploitWitness {
                repro_cmd: Some("curl http://169.254.169.254/latest/meta-data/".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };

        assert!(finding_mentions_internal_metadata_proof(&finding));
    }

    #[test]
    fn schema_taint_helper_detects_proof_marker() {
        let finding = StructuredFinding {
            id: "security:dom_xss_innerHTML".to_string(),
            exploit_witness: Some(ExploitWitness {
                path_proof: Some("schema_taint:proven".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };

        assert!(finding_has_schema_taint_proof(&finding));
    }

    #[test]
    fn web_proof_artifact_serializes_and_proves_marker() {
        let finding = StructuredFinding {
            id: "security:ssrf_dynamic_url".to_string(),
            proof_class: Some(ProofClass::ReachabilityProof),
            web_proof_artifact: Some(WebProofArtifact {
                source_label: "url_param:url".to_string(),
                sink_label: "sink:fetch".to_string(),
                ifds_trace: vec!["handler:url".to_string(), "client:get".to_string()],
                evidence_marker: Some("internal_metadata:169.254.169.254".to_string()),
                proof_class: ProofClass::ReachabilityProof,
            }),
            ..Default::default()
        };

        let json = serde_json::to_string(&finding).expect("serialization must not fail");
        assert!(json.contains("web_proof_artifact"));
        assert!(finding_mentions_internal_metadata_proof(&finding));
        assert!(finding_has_required_proof_class(&finding));
    }

    #[test]
    fn web_proof_artifact_generates_unified_markdown() {
        let witness = ExploitWitness {
            source_label: "url_param:url".to_string(),
            sink_label: "sink:http_client".to_string(),
            call_chain: vec![
                "route:/fetch".to_string(),
                "service.fetch_remote".to_string(),
                "reqwest::get".to_string(),
            ],
            ..Default::default()
        };
        let artifact = WebProofArtifact::from_witness(
            &witness,
            ProofClass::ReachabilityProof,
            Some("internal_metadata:169.254.169.254".to_string()),
        );

        let markdown = artifact.to_markdown();
        assert!(
            markdown.contains("url_param:url"),
            "source label must be rendered"
        );
        assert!(
            markdown.contains("sink:http_client"),
            "sink label must be rendered"
        );
        assert!(
            markdown.contains(
                "url_param:url -> route:/fetch -> service.fetch_remote -> reqwest::get -> sink:http_client"
            ),
            "IFDS trace must bind source directly to sink"
        );
        assert!(
            markdown.contains("internal_metadata:169.254.169.254"),
            "compact evidence marker must be rendered"
        );
    }
}
