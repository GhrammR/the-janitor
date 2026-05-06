//! FIPS boundary receipts for Janitor cryptographic operations.

use sha2::{Digest as _, Sha384};

/// Algorithms that may attempt to enter the Janitor compliance chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoAlgorithm {
    /// SHA-256 digest.
    Sha256,
    /// SHA-384 digest.
    Sha384,
    /// HMAC-SHA-256 message authentication.
    HmacSha256,
    /// HMAC-SHA-384 message authentication.
    HmacSha384,
    /// Ed25519 signature verification/signing within Janitor trust chains.
    Ed25519,
    /// SHA-1 digest. Explicitly rejected.
    Sha1,
    /// MD5 digest. Explicitly rejected.
    Md5,
    /// BLAKE3 digest used outside the compliance chain.
    Blake3,
}

impl CryptoAlgorithm {
    fn as_str(self) -> &'static str {
        match self {
            Self::Sha256 => "SHA-256",
            Self::Sha384 => "SHA-384",
            Self::HmacSha256 => "HMAC-SHA-256",
            Self::HmacSha384 => "HMAC-SHA-384",
            Self::Ed25519 => "Ed25519",
            Self::Sha1 => "SHA-1",
            Self::Md5 => "MD5",
            Self::Blake3 => "BLAKE3",
        }
    }

    fn is_nist_approved(self) -> bool {
        matches!(
            self,
            Self::Sha256 | Self::Sha384 | Self::HmacSha256 | Self::HmacSha384 | Self::Ed25519
        )
    }
}

/// Security decision classes that consume a cryptographic result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityPurpose {
    /// Token or license verification.
    TokenVerification,
    /// Audit or transparency log integrity.
    AuditIntegrity,
    /// Webhook or transport integrity.
    TransportIntegrity,
    /// Detached receipt or attestation signing.
    Attestation,
}

impl SecurityPurpose {
    fn as_str(self) -> &'static str {
        match self {
            Self::TokenVerification => "token_verification",
            Self::AuditIntegrity => "audit_integrity",
            Self::TransportIntegrity => "transport_integrity",
            Self::Attestation => "attestation",
        }
    }
}

/// Boundary failure for a non-approved algorithm.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BoundaryError {
    /// The attempted algorithm is outside the approved compliance chain.
    #[error(
        "non-approved algorithm {algorithm} blocked at {caller} for security purpose {purpose}"
    )]
    NonApprovedAlgorithm {
        /// Caller name that attempted to enter the chain.
        caller: String,
        /// Rejected algorithm.
        algorithm: &'static str,
        /// Security purpose.
        purpose: &'static str,
    },
}

/// Receipt proving an operation stayed inside the approved boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoReceipt {
    /// Static caller identifier.
    pub caller: String,
    /// Approved algorithm used for the operation.
    pub algorithm: CryptoAlgorithm,
    /// Security purpose attached to the operation.
    pub purpose: SecurityPurpose,
    /// Deterministic service indicator derived from the operation tuple.
    pub service_indicator: String,
}

/// Boundary verifier for cryptographic operations.
pub struct CryptoBoundary;

impl CryptoBoundary {
    /// Record a cryptographic operation and fail closed for non-approved algorithms.
    pub fn record_operation(
        caller: &str,
        algorithm: CryptoAlgorithm,
        purpose: SecurityPurpose,
    ) -> Result<CryptoReceipt, BoundaryError> {
        if !algorithm.is_nist_approved() {
            return Err(BoundaryError::NonApprovedAlgorithm {
                caller: caller.to_string(),
                algorithm: algorithm.as_str(),
                purpose: purpose.as_str(),
            });
        }

        let mut service_bytes = Vec::with_capacity(caller.len() + 32);
        service_bytes.extend_from_slice(caller.as_bytes());
        service_bytes.extend_from_slice(algorithm.as_str().as_bytes());
        service_bytes.extend_from_slice(purpose.as_str().as_bytes());

        Ok(CryptoReceipt {
            caller: caller.to_string(),
            algorithm,
            purpose,
            service_indicator: hex::encode(Sha384::digest(&service_bytes)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_operation_accepts_sha384() {
        let receipt = CryptoBoundary::record_operation(
            "vault::test",
            CryptoAlgorithm::Sha384,
            SecurityPurpose::AuditIntegrity,
        )
        .expect("SHA-384 must remain inside the FIPS boundary");
        assert_eq!(receipt.algorithm, CryptoAlgorithm::Sha384);
        assert_eq!(receipt.service_indicator.len(), 96);
    }

    #[test]
    fn record_operation_rejects_sha1() {
        let error = CryptoBoundary::record_operation(
            "vault::test",
            CryptoAlgorithm::Sha1,
            SecurityPurpose::AuditIntegrity,
        )
        .expect_err("SHA-1 must be rejected");
        assert!(matches!(
            error,
            BoundaryError::NonApprovedAlgorithm {
                algorithm: "SHA-1",
                ..
            }
        ));
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    fn approved_algorithms_do_not_panic() {
        let idx: u8 = kani::any();
        kani::assume(idx < 5);
        let algorithm = match idx {
            0 => CryptoAlgorithm::Sha256,
            1 => CryptoAlgorithm::Sha384,
            2 => CryptoAlgorithm::HmacSha256,
            3 => CryptoAlgorithm::HmacSha384,
            _ => CryptoAlgorithm::Ed25519,
        };
        let _ = CryptoBoundary::record_operation("kani", algorithm, SecurityPurpose::Attestation);
    }
}
