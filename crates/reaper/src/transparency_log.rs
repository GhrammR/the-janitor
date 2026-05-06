//! Append-only transparency log with a SHA-384 hash chain.

use crate::ReaperError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha384};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use vault::fips_boundary::{CryptoAlgorithm, CryptoBoundary, SecurityPurpose};

/// Inclusion proof for an appended transparency leaf.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransparencyProof {
    /// Monotonic sequence index of the leaf.
    pub sequence_index: u64,
    /// Chained root after this leaf is committed.
    pub chained_hash: String,
}

/// One persisted transparency leaf.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransparencyLeaf {
    /// Monotonic sequence index.
    pub sequence_index: u64,
    /// SHA-384 hex digest of the payload bytes.
    pub payload_hash: String,
    /// Previous chained hash, or zero root for the first entry.
    pub previous_chained_hash: String,
    /// Current chained hash.
    pub chained_hash: String,
}

impl TransparencyLeaf {
    fn new(
        sequence_index: u64,
        previous_chained_hash: String,
        payload_hash: String,
    ) -> Result<Self, ReaperError> {
        let chained_hash =
            compute_chained_hash(sequence_index, &previous_chained_hash, &payload_hash)?;
        Ok(Self {
            sequence_index,
            payload_hash,
            previous_chained_hash,
            chained_hash,
        })
    }
}

/// Append-only SHA-384 transparency log.
pub struct TransparencyLog;

impl TransparencyLog {
    /// Append a payload leaf after verifying the entire on-disk chain.
    pub fn append_leaf(log_path: &Path, payload: &[u8]) -> Result<TransparencyProof, ReaperError> {
        CryptoBoundary::record_operation(
            "reaper::TransparencyLog::append_leaf",
            CryptoAlgorithm::Sha384,
            SecurityPurpose::AuditIntegrity,
        )
        .map_err(|e| ReaperError::ParseError(e.to_string()))?;
        let prior = Self::verify_chain(log_path)?;
        let payload_hash = hex::encode(Sha384::digest(payload));
        let (sequence_index, previous_chained_hash) = match prior {
            Some(leaf) => (leaf.sequence_index.saturating_add(1), leaf.chained_hash),
            None => (0, zero_hash_hex()),
        };
        let leaf = TransparencyLeaf::new(sequence_index, previous_chained_hash, payload_hash)?;
        if let Some(parent) = log_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let line = serde_json::to_string(&leaf).map_err(|e| {
            ReaperError::ParseError(format!("transparency leaf serialize failed: {e}"))
        })?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)?;
        writeln!(file, "{line}")?;
        file.sync_all()?;
        Ok(TransparencyProof {
            sequence_index: leaf.sequence_index,
            chained_hash: leaf.chained_hash,
        })
    }

    /// Verify the on-disk chain and return the last valid leaf.
    pub fn verify_chain(log_path: &Path) -> Result<Option<TransparencyLeaf>, ReaperError> {
        if !log_path.exists() {
            return Ok(None);
        }
        let file = std::fs::File::open(log_path)?;
        let reader = BufReader::new(file);
        let mut last_leaf: Option<TransparencyLeaf> = None;

        for (line_number, line) in reader.lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let leaf: TransparencyLeaf = serde_json::from_str(&line).map_err(|e| {
                ReaperError::ParseError(format!(
                    "transparency leaf parse failed on line {}: {e}",
                    line_number + 1
                ))
            })?;
            let expected_sequence = last_leaf
                .as_ref()
                .map(|prior| prior.sequence_index.saturating_add(1))
                .unwrap_or(0);
            if leaf.sequence_index != expected_sequence {
                return Err(ReaperError::ParseError(format!(
                    "transparency chain sequence break on line {}",
                    line_number + 1
                )));
            }
            let expected_previous = last_leaf
                .as_ref()
                .map(|prior| prior.chained_hash.clone())
                .unwrap_or_else(zero_hash_hex);
            if leaf.previous_chained_hash != expected_previous {
                return Err(ReaperError::ParseError(format!(
                    "transparency chain previous-hash mismatch on line {}",
                    line_number + 1
                )));
            }
            let expected_chain = compute_chained_hash(
                leaf.sequence_index,
                &leaf.previous_chained_hash,
                &leaf.payload_hash,
            )?;
            if leaf.chained_hash != expected_chain {
                return Err(ReaperError::ParseError(format!(
                    "transparency chain digest mismatch on line {}",
                    line_number + 1
                )));
            }
            last_leaf = Some(leaf);
        }

        Ok(last_leaf)
    }
}

fn zero_hash_hex() -> String {
    "0".repeat(96)
}

fn decode_hash(hex_hash: &str) -> Result<[u8; 48], ReaperError> {
    let raw = hex::decode(hex_hash)
        .map_err(|e| ReaperError::ParseError(format!("invalid transparency hash hex: {e}")))?;
    raw.as_slice().try_into().map_err(|_| {
        ReaperError::ParseError("transparency hash must be exactly 48 bytes".to_string())
    })
}

fn compute_chained_hash(
    sequence_index: u64,
    previous_chained_hash: &str,
    payload_hash: &str,
) -> Result<String, ReaperError> {
    CryptoBoundary::record_operation(
        "reaper::transparency_log::compute_chained_hash",
        CryptoAlgorithm::Sha384,
        SecurityPurpose::AuditIntegrity,
    )
    .map_err(|e| ReaperError::ParseError(e.to_string()))?;
    let previous = decode_hash(previous_chained_hash)?;
    let payload = decode_hash(payload_hash)?;
    let mut hasher = Sha384::new();
    hasher.update(sequence_index.to_be_bytes());
    hasher.update(previous);
    hasher.update(payload);
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_leaf_chains_entries() {
        let dir = tempfile::tempdir().expect("tempdir must exist");
        let path = dir.path().join("transparency.ndjson");

        let first = TransparencyLog::append_leaf(&path, b"alpha").expect("first append must work");
        let second = TransparencyLog::append_leaf(&path, b"beta").expect("second append must work");

        assert_eq!(first.sequence_index, 0);
        assert_eq!(second.sequence_index, 1);
        assert_ne!(first.chained_hash, second.chained_hash);
    }

    #[test]
    fn verify_chain_detects_broken_hash_chain() {
        let dir = tempfile::tempdir().expect("tempdir must exist");
        let path = dir.path().join("transparency.ndjson");
        TransparencyLog::append_leaf(&path, b"alpha").expect("first append must work");
        TransparencyLog::append_leaf(&path, b"beta").expect("second append must work");

        let tampered = r#"{"sequence_index":1,"payload_hash":"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","previous_chained_hash":"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","chained_hash":"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"}"#;
        let valid_first = std::fs::read_to_string(&path)
            .expect("log must exist")
            .lines()
            .next()
            .expect("first line must exist")
            .to_string();
        std::fs::write(&path, format!("{valid_first}\n{tampered}\n"))
            .expect("tamper write must succeed");

        let error = TransparencyLog::verify_chain(&path).expect_err("broken chain must fail");
        assert!(matches!(error, ReaperError::ParseError(_)));
    }
}
