//! P2-23 Scientific Workflow Construction Guard.
//!
//! Detects AI-generated analysis scripts and notebooks that produce result files
//! without a reproducibility envelope: pinned dataset hash, deterministic seed,
//! test command, and environment lock.  Every generated scientific workflow that
//! omits any of these four pillars is a non-reproducible artifact — a compliance
//! and audit risk for regulated buyers.
//!
//! # Detection model
//!
//! 1. **Result-emission sink**: the script writes to a file, uploads a report,
//!    or calls a logging/artifact API — confirming it produces outputs.
//! 2. **Missing provenance predicates**: four predicates must ALL be satisfied:
//!    - `dataset_hash` — a hex/SHA digest of the input data referenced
//!    - `seed` — `random.seed`, `np.random.seed`, `set.seed`, `torch.manual_seed`
//!    - `test_command` — an invocation of a test runner (`pytest`, `Rscript`,
//!      `julia --project`, `cargo test`, `go test`)
//!    - `env_lock` — a `requirements.txt`, `poetry.lock`, `Cargo.lock`,
//!      `renv.lock`, `Manifest.toml`, or `environment.yml` referenced in the
//!      same directory tree
//! 3. Any missing predicate emits `WorkflowEnvelopeStatus::MissingProvenance`
//!    which proof_obligation.rs surfaces as a `security:workflow_no_provenance`
//!    finding.

use common::slop::StructuredFinding;

// ── Public types ─────────────────────────────────────────────────────────────

/// Captured provenance predicates from static scan of a workflow script.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct WorkflowEvidence {
    pub dataset_hash_present: bool,
    pub seed_present: bool,
    pub test_command_present: bool,
    pub env_lock_present: bool,
}

/// Gate result returned by `validate_workflow_evidence`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkflowEnvelopeStatus {
    Complete,
    MissingProvenance(Vec<&'static str>),
}

impl WorkflowEnvelopeStatus {
    pub fn is_complete(&self) -> bool {
        matches!(self, Self::Complete)
    }
}

// ── Validation ───────────────────────────────────────────────────────────────

/// Returns `Complete` only when all four provenance predicates are present.
/// Returns `MissingProvenance` with a non-empty list of missing pillars otherwise.
pub fn validate_workflow_evidence(ev: &WorkflowEvidence) -> WorkflowEnvelopeStatus {
    let mut missing: Vec<&'static str> = Vec::new();
    if !ev.dataset_hash_present {
        missing.push("dataset_hash");
    }
    if !ev.seed_present {
        missing.push("seed");
    }
    if !ev.test_command_present {
        missing.push("test_command");
    }
    if !ev.env_lock_present {
        missing.push("env_lock");
    }
    if missing.is_empty() {
        WorkflowEnvelopeStatus::Complete
    } else {
        WorkflowEnvelopeStatus::MissingProvenance(missing)
    }
}

// ── Static source extractor ──────────────────────────────────────────────────

const DATASET_HASH_PATTERNS: &[&str] = &[
    "sha256",
    "sha384",
    "sha512",
    "md5sum",
    "hashlib",
    "dataset_hash",
    "data_hash",
    "file_hash",
    "checksum",
];

const SEED_PATTERNS: &[&str] = &[
    "random.seed(",
    "np.random.seed(",
    "set.seed(",
    "torch.manual_seed(",
    "tf.random.set_seed(",
    "seed=",
];

const TEST_COMMAND_PATTERNS: &[&str] = &[
    "pytest",
    "unittest",
    "Rscript --vanilla",
    "julia --project",
    "cargo test",
    "go test",
    "bats ",
    "jest ",
    "vitest",
];

const ENV_LOCK_PATTERNS: &[&str] = &[
    "requirements.txt",
    "poetry.lock",
    "Pipfile.lock",
    "Cargo.lock",
    "renv.lock",
    "Manifest.toml",
    "environment.yml",
    "conda-lock.yml",
    "package-lock.json",
    "yarn.lock",
];

const RESULT_SINK_PATTERNS: &[&str] = &[
    ".to_csv(",
    ".to_parquet(",
    ".to_json(",
    "open(",
    "write(",
    "savefig(",
    "wandb.log(",
    "mlflow.log",
    "artifact.upload",
    "report.write",
];

/// Extracts `WorkflowEvidence` from raw source text via pattern matching.
/// This is intentionally O(source_len) — safe for files under the 1 MiB gate.
pub fn extract_evidence(source: &str) -> WorkflowEvidence {
    WorkflowEvidence {
        dataset_hash_present: DATASET_HASH_PATTERNS.iter().any(|p| source.contains(p)),
        seed_present: SEED_PATTERNS.iter().any(|p| source.contains(p)),
        test_command_present: TEST_COMMAND_PATTERNS.iter().any(|p| source.contains(p)),
        env_lock_present: ENV_LOCK_PATTERNS.iter().any(|p| source.contains(p)),
    }
}

/// Returns `true` when source emits results to an external sink.
pub fn has_result_emission(source: &str) -> bool {
    RESULT_SINK_PATTERNS.iter().any(|p| source.contains(p))
}

// ── Finding emitter ──────────────────────────────────────────────────────────

/// Emit a `security:workflow_no_provenance` finding for a script that produces
/// outputs without a full reproducibility envelope.  Returns `None` when the
/// script has no result emission or when provenance is complete.
pub fn emit_workflow_provenance_finding(file: &str, source: &str) -> Option<StructuredFinding> {
    if !has_result_emission(source) {
        return None;
    }
    let ev = extract_evidence(source);
    match validate_workflow_evidence(&ev) {
        WorkflowEnvelopeStatus::Complete => None,
        WorkflowEnvelopeStatus::MissingProvenance(missing) => {
            let gap = missing.join(", ");
            Some(StructuredFinding {
                id: "security:workflow_no_provenance".to_string(),
                severity: Some("High".to_string()),
                file: Some(file.to_string()),
                remediation: Some(format!(
                    "Scientific workflow emits results without reproducibility envelope. \
Missing: {gap}. Add pinned dataset hash, deterministic seed, test command, \
and environment lock before trusting outputs.",
                )),
                ..Default::default()
            })
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn full_evidence() -> WorkflowEvidence {
        WorkflowEvidence {
            dataset_hash_present: true,
            seed_present: true,
            test_command_present: true,
            env_lock_present: true,
        }
    }

    // TP: complete envelope passes gate
    #[test]
    fn complete_envelope_passes() {
        assert_eq!(
            validate_workflow_evidence(&full_evidence()),
            WorkflowEnvelopeStatus::Complete,
        );
    }

    // TN: missing all predicates fails gate
    #[test]
    fn empty_evidence_fails_with_all_missing() {
        let status = validate_workflow_evidence(&WorkflowEvidence::default());
        match status {
            WorkflowEnvelopeStatus::MissingProvenance(missing) => {
                assert_eq!(
                    missing.len(),
                    4,
                    "all four pillars must be reported missing"
                );
            }
            WorkflowEnvelopeStatus::Complete => panic!("should have failed"),
        }
    }

    // Partial: seed only → three pillars missing
    #[test]
    fn partial_evidence_reports_correct_gaps() {
        let ev = WorkflowEvidence {
            seed_present: true,
            ..Default::default()
        };
        let status = validate_workflow_evidence(&ev);
        match status {
            WorkflowEnvelopeStatus::MissingProvenance(missing) => {
                assert!(missing.contains(&"dataset_hash"));
                assert!(missing.contains(&"test_command"));
                assert!(missing.contains(&"env_lock"));
                assert!(!missing.contains(&"seed"), "seed is present");
            }
            WorkflowEnvelopeStatus::Complete => panic!("should have failed"),
        }
    }

    // TP source: full Python script with all four pillars
    #[test]
    fn extract_evidence_full_python_script() {
        let src = r#"
import hashlib, random
import numpy as np
np.random.seed(42)
data_hash = hashlib.sha256(open("data.csv","rb").read()).hexdigest()
# requirements.txt
df.to_csv("results.csv")
# run: pytest test_pipeline.py
"#;
        let ev = extract_evidence(src);
        assert!(ev.dataset_hash_present, "sha256 present");
        assert!(ev.seed_present, "np.random.seed present");
        assert!(ev.test_command_present, "pytest present");
        assert!(ev.env_lock_present, "requirements.txt present");
        assert!(has_result_emission(src), "to_csv is a result sink");
    }

    // TN source: bare result-emission script with no provenance
    #[test]
    fn extract_evidence_no_provenance_script() {
        let src = r#"
import pandas as pd
df = pd.read_csv("data.csv")
df["score"] = df["x"] * 2
df.to_parquet("output.parquet")
"#;
        let ev = extract_evidence(src);
        assert!(!ev.dataset_hash_present);
        assert!(!ev.seed_present);
        assert!(!ev.test_command_present);
        assert!(!ev.env_lock_present);
        assert!(has_result_emission(src));
        assert_eq!(
            validate_workflow_evidence(&ev),
            WorkflowEnvelopeStatus::MissingProvenance(vec![
                "dataset_hash",
                "seed",
                "test_command",
                "env_lock",
            ]),
        );
    }

    // emit_workflow_provenance_finding: TN — no emission → no finding
    #[test]
    fn no_finding_when_no_result_emission() {
        let src = "x = 1 + 2\nprint(x)\n";
        assert!(
            emit_workflow_provenance_finding("script.py", src).is_none(),
            "script with no result sink should not produce a finding",
        );
    }

    // emit_workflow_provenance_finding: finding carries correct id
    #[test]
    fn finding_id_on_missing_provenance() {
        let src = "df.to_csv('out.csv')\n";
        let finding =
            emit_workflow_provenance_finding("analysis.py", src).expect("must emit finding");
        assert_eq!(finding.id, "security:workflow_no_provenance");
        assert_eq!(finding.severity.as_deref(), Some("High"));
    }

    // emit_workflow_provenance_finding: TP — complete provenance → no finding
    #[test]
    fn no_finding_when_full_provenance_present() {
        let src = r#"
import hashlib
data_hash = hashlib.sha256(b"").hexdigest()
import numpy as np; np.random.seed(0)
# requirements.txt, pytest
df.to_parquet("results.parquet")
"#;
        assert!(
            emit_workflow_provenance_finding("full_pipeline.py", src).is_none(),
            "complete provenance must suppress the finding",
        );
    }
}
