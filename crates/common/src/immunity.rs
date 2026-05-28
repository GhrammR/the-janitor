//! Physarum Immune Memory — persistent pattern memory and affinity maturation.
//!
//! P9-1 Phase A: introduces three cooperating types:
//!
//! - [`MemoryCell`]: a persistent record of a confirmed or candidate
//!   vuln-pattern, annotated with maturity score and confirmation count.
//! - [`AffinityMaturator`]: pool of cells keyed by BLAKE3 pattern hash;
//!   groups related cells into vulnerability families via an ena union-find.
//! - [`SelfClassifier`]: learns a tenant's normal pattern baseline and flags
//!   any pattern below the observation threshold as anomalous (non-self).
//!
//! All three types are deterministic and `Send + Sync`-safe via `Mutex`
//! wrapping at the call site.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use ena::unify::{InPlaceUnificationTable, UnifyKey};

/// Score at or above which a [`MemoryCell`] is considered "mature".
pub const MATURITY_THRESHOLD: f32 = 0.7;

/// Number of confirmed true-positive exposures that advance a cell to full
/// maturity (maturity_score == 1.0).
const FULL_MATURITY_CONFIRMS: u32 = 5;

// ---------------------------------------------------------------------------
// MemoryCell
// ---------------------------------------------------------------------------

/// Persistent record of a detected or confirmed vuln-pattern signature.
///
/// Created by [`AffinityMaturator::ingest_pattern`] and ripened by
/// [`AffinityMaturator::confirm_true_positive`].
#[derive(Debug, Clone, PartialEq)]
pub struct MemoryCell {
    /// BLAKE3 hash of the raw detection pattern bytes.
    pub pattern_hash: [u8; 32],
    /// Maturity score ∈ \[0.0, 1.0\].  Grows linearly with confirmed TPs.
    pub maturity_score: f32,
    /// Unix-epoch seconds of first observation.
    pub first_seen: u64,
    /// Confirmed true-positive exposure count.
    pub confirm_count: u32,
}

impl MemoryCell {
    fn new(pattern_hash: [u8; 32]) -> Self {
        let first_seen = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        MemoryCell {
            pattern_hash,
            maturity_score: 0.0,
            first_seen,
            confirm_count: 0,
        }
    }

    fn record_confirmation(&mut self) {
        self.confirm_count += 1;
        // Linear ramp: 0 confirms → 0.0, FULL_MATURITY_CONFIRMS → 1.0.
        self.maturity_score = (self.confirm_count as f32 / FULL_MATURITY_CONFIRMS as f32).min(1.0);
    }
}

// ---------------------------------------------------------------------------
// AffinityMaturator
// ---------------------------------------------------------------------------

/// Index into [`AffinityMaturator`]'s cell pool — the ena union-find key type.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct CellKey(u32);

impl UnifyKey for CellKey {
    type Value = ();
    fn index(&self) -> u32 {
        self.0
    }
    fn from_index(u: u32) -> Self {
        CellKey(u)
    }
    fn tag() -> &'static str {
        "CellKey"
    }
}

/// Pool of [`MemoryCell`] records with union-find family grouping.
///
/// Related patterns (e.g., heap-spray and UAF variants of the same CVE) can
/// be merged into one family via [`merge_related`][Self::merge_related].
/// The canonical family representative is retrieved with
/// [`family_root`][Self::family_root].
pub struct AffinityMaturator {
    cells: Vec<MemoryCell>,
    index: HashMap<[u8; 32], usize>,
    uf: InPlaceUnificationTable<CellKey>,
}

impl Default for AffinityMaturator {
    fn default() -> Self {
        AffinityMaturator {
            cells: Vec::new(),
            index: HashMap::new(),
            uf: InPlaceUnificationTable::new(),
        }
    }
}

impl AffinityMaturator {
    /// Create an empty maturator.
    pub fn new() -> Self {
        AffinityMaturator::default()
    }

    /// Ingest a pattern hash: allocate a new cell on first sight, return its
    /// key. Idempotent — a second call with the same hash returns the existing
    /// key without creating a duplicate cell.
    pub fn ingest_pattern(&mut self, pattern_hash: [u8; 32]) -> CellKey {
        if let Some(&idx) = self.index.get(&pattern_hash) {
            return CellKey(idx as u32);
        }
        let idx = self.cells.len();
        self.cells.push(MemoryCell::new(pattern_hash));
        self.index.insert(pattern_hash, idx);
        let key = self.uf.new_key(());
        debug_assert_eq!(
            key.index() as usize,
            idx,
            "uf and cell pool must stay in sync"
        );
        key
    }

    /// Record a confirmed true-positive for `pattern_hash`.
    ///
    /// Ingests the pattern first if it is not yet known.
    pub fn confirm_true_positive(&mut self, pattern_hash: [u8; 32]) {
        let key = self.ingest_pattern(pattern_hash);
        self.cells[key.index() as usize].record_confirmation();
    }

    /// Merge two patterns into the same vulnerability family.
    ///
    /// Both patterns are ingested if not already known.  After merging,
    /// `family_root(a) == family_root(b)`.
    pub fn merge_related(&mut self, a: [u8; 32], b: [u8; 32]) {
        let ka = self.ingest_pattern(a);
        let kb = self.ingest_pattern(b);
        self.uf.union(ka, kb);
    }

    /// Return the canonical family root for a pattern, or `None` if unknown.
    pub fn family_root(&mut self, pattern_hash: [u8; 32]) -> Option<CellKey> {
        let idx = *self.index.get(&pattern_hash)?;
        Some(self.uf.find(CellKey(idx as u32)))
    }

    /// Return all cells at or above [`MATURITY_THRESHOLD`].
    pub fn mature_cells(&self) -> Vec<&MemoryCell> {
        self.cells
            .iter()
            .filter(|c| c.maturity_score >= MATURITY_THRESHOLD)
            .collect()
    }

    /// Total number of tracked cells (mature and immature combined).
    pub fn cell_count(&self) -> usize {
        self.cells.len()
    }
}

// ---------------------------------------------------------------------------
// SelfClassifier
// ---------------------------------------------------------------------------

/// Learns a tenant's normal detection-pattern baseline and flags foreign
/// patterns as anomalous.
///
/// Patterns observed at or above `anomaly_threshold` times are classified
/// as "self".  Any pattern below the threshold is considered a non-self
/// anomaly — a potential new attack surface the tenant has never encountered.
pub struct SelfClassifier {
    known_patterns: HashMap<[u8; 32], u32>,
    /// Minimum observation count before a pattern is accepted as "self".
    pub anomaly_threshold: u32,
    /// XOR accumulation over the unique pattern set — used in
    /// [`baseline_digest`][Self::baseline_digest].
    baseline_xor: [u8; 32],
}

impl SelfClassifier {
    /// Create a classifier with the given anomaly threshold.
    pub fn new(anomaly_threshold: u32) -> Self {
        SelfClassifier {
            known_patterns: HashMap::new(),
            anomaly_threshold,
            baseline_xor: [0u8; 32],
        }
    }

    /// Record a pattern as belonging to this tenant's normal baseline.
    pub fn update_baseline(&mut self, pattern_hash: [u8; 32]) {
        let count = self.known_patterns.entry(pattern_hash).or_insert(0);
        if *count == 0 {
            // XOR each byte of the new pattern into the accumulator so the
            // baseline_digest changes whenever an unseen pattern is added.
            for (acc, b) in self.baseline_xor.iter_mut().zip(pattern_hash.iter()) {
                *acc ^= b;
            }
        }
        *count += 1;
    }

    /// Returns `true` when `pattern_hash` is foreign to this tenant's baseline.
    pub fn is_anomalous(&self, pattern_hash: [u8; 32]) -> bool {
        self.known_patterns.get(&pattern_hash).copied().unwrap_or(0) < self.anomaly_threshold
    }

    /// Stable digest of the current baseline — BLAKE3 of the XOR-accumulated
    /// unique pattern set.  Changes each time a previously-unseen pattern is
    /// added; order-invariant across repeated observations of the same pattern.
    pub fn baseline_digest(&self) -> [u8; 32] {
        *blake3::hash(&self.baseline_xor).as_bytes()
    }
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

/// Hash arbitrary bytes to a 32-byte pattern key via BLAKE3.
pub fn hash_pattern(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ingest_creates_cell_idempotent() {
        let mut m = AffinityMaturator::new();
        let h = hash_pattern(b"oob_pattern_alpha");
        let k1 = m.ingest_pattern(h);
        let k2 = m.ingest_pattern(h);
        assert_eq!(k1, k2, "second ingest must return the existing key");
        assert_eq!(m.cell_count(), 1, "no duplicate cells");
        assert_eq!(m.cells[0].confirm_count, 0);
    }

    #[test]
    fn test_confirm_matures_cell() {
        let mut m = AffinityMaturator::new();
        let h = hash_pattern(b"heap_pattern_beta");
        for _ in 0..FULL_MATURITY_CONFIRMS {
            m.confirm_true_positive(h);
        }
        let cell = &m.cells[0];
        assert!(
            cell.maturity_score >= MATURITY_THRESHOLD,
            "cell must reach maturity after {} confirmations",
            FULL_MATURITY_CONFIRMS
        );
        assert_eq!(cell.maturity_score, 1.0);
        assert_eq!(m.mature_cells().len(), 1);
    }

    #[test]
    fn test_merge_related_shares_root() {
        let mut m = AffinityMaturator::new();
        let ha = hash_pattern(b"pattern_alpha");
        let hb = hash_pattern(b"pattern_beta");
        m.merge_related(ha, hb);
        let root_a = m.family_root(ha).expect("root for a");
        let root_b = m.family_root(hb).expect("root for b");
        assert_eq!(
            root_a, root_b,
            "merged patterns must share a canonical family root"
        );
    }

    #[test]
    fn test_self_classifier_baseline() {
        let mut sc = SelfClassifier::new(2);
        let known = hash_pattern(b"rce_pattern_known");
        let foreign = hash_pattern(b"privesc_pattern_foreign");

        // Below threshold — still anomalous.
        sc.update_baseline(known);
        assert!(
            sc.is_anomalous(known),
            "one observation < threshold=2 is anomalous"
        );

        // At threshold — no longer anomalous.
        sc.update_baseline(known);
        assert!(
            !sc.is_anomalous(known),
            "two observations == threshold=2 is not anomalous"
        );

        // Unseen pattern is always anomalous.
        assert!(sc.is_anomalous(foreign), "unseen pattern is anomalous");
    }

    #[test]
    fn test_mature_cells_filter() {
        let mut m = AffinityMaturator::new();
        let h_ripe = hash_pattern(b"uaf_pattern_ripe");
        let h_raw = hash_pattern(b"privesc_pattern_raw");

        // Ripen h_ripe to full maturity.
        for _ in 0..FULL_MATURITY_CONFIRMS {
            m.confirm_true_positive(h_ripe);
        }
        // Ingest h_raw without confirming — stays immature.
        m.ingest_pattern(h_raw);

        let mature = m.mature_cells();
        assert_eq!(mature.len(), 1);
        assert_eq!(mature[0].pattern_hash, h_ripe);
    }
}
