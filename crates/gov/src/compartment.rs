//! IL6 evidence compartment lattice and spillage guard.

use std::fmt;
use std::str::FromStr;

/// Ordered information-flow lattice for Janitor evidence artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Clearance {
    Unclassified,
    Cui,
    Secret,
}

impl Clearance {
    /// Parse a clearance string, defaulting to `Unclassified` when absent.
    pub fn from_optional_env(value: Option<String>) -> Result<Self, ClearanceParseError> {
        match value {
            Some(raw) => Self::from_str(raw.trim()),
            None => Ok(Self::Unclassified),
        }
    }
}

impl fmt::Display for Clearance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Unclassified => "Unclassified",
            Self::Cui => "CUI",
            Self::Secret => "Secret",
        };
        f.write_str(label)
    }
}

impl FromStr for Clearance {
    type Err = ClearanceParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "unclassified" | "public" => Ok(Self::Unclassified),
            "cui" | "controlled_unclassified_information" => Ok(Self::Cui),
            "secret" | "classified" => Ok(Self::Secret),
            other => Err(ClearanceParseError {
                raw: other.to_string(),
            }),
        }
    }
}

/// Parse failure for operator-provided clearance labels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClearanceParseError {
    raw: String,
}

impl fmt::Display for ClearanceParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unknown clearance `{}` (expected Unclassified, CUI, or Secret)",
            self.raw
        )
    }
}

impl std::error::Error for ClearanceParseError {}

/// Hard-fail spillage block emitted on attempted downgrade.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataSpillageBlock {
    pub src_clearance: Clearance,
    pub dst_clearance: Clearance,
}

impl fmt::Display for DataSpillageBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "data-spillage block: {} evidence cannot flow to {} destination",
            self.src_clearance, self.dst_clearance
        )
    }
}

impl std::error::Error for DataSpillageBlock {}

/// Enforce dominance in the IL6 evidence-flow lattice.
pub fn enforce_flow(
    src_clearance: Clearance,
    dst_clearance: Clearance,
) -> Result<(), DataSpillageBlock> {
    if src_clearance <= dst_clearance {
        Ok(())
    } else {
        Err(DataSpillageBlock {
            src_clearance,
            dst_clearance,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{enforce_flow, Clearance};

    #[test]
    fn blocks_secret_to_unclassified_downgrade() {
        let err = enforce_flow(Clearance::Secret, Clearance::Unclassified)
            .expect_err("secret evidence must not downgrade to unclassified");
        assert_eq!(err.src_clearance, Clearance::Secret);
        assert_eq!(err.dst_clearance, Clearance::Unclassified);
        assert!(err.to_string().contains("data-spillage block"));
    }

    #[test]
    fn allows_equal_or_higher_clearance_flows() {
        assert!(enforce_flow(Clearance::Secret, Clearance::Secret).is_ok());
        assert!(enforce_flow(Clearance::Cui, Clearance::Secret).is_ok());
        assert!(enforce_flow(Clearance::Unclassified, Clearance::Cui).is_ok());
    }
}
