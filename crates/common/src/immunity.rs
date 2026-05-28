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
//! P9-1 Phase B extends [`AffinityMaturator`] with a mutation-select
//! refinement cycle: fully mature cells spawn deterministic hash variants via
//! `ChaCha8Rng`; zero-confirm cells older than 100 s are pruned.

use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use ena::unify::{InPlaceUnificationTable, UnifyKey};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;

/// Score at or above which a [`MemoryCell`] is considered "mature".
pub const MATURITY_THRESHOLD: f32 = 0.7;

/// Number of confirmed true-positive exposures that advance a cell to full
/// maturity (maturity_score == 1.0).
const FULL_MATURITY_CONFIRMS: u32 = 5;

/// Number of variant hashes spawned per mature cell in the mutation pass.
const MUTATION_VARIANT_COUNT: usize = 3;

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
    /// True when the selection pass has pruned this cell from the active pool.
    pub is_pruned: bool,
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
            is_pruned: false,
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
///
/// ## Mutation-select cycle (Phase B)
///
/// Call [`mature_cells`][Self::mature_cells] periodically (e.g. every 50
/// ingests) to:
/// - **Mutate** fully mature, non-suppressed cells into `MUTATION_VARIANT_COUNT`
///   deterministic variants via `ChaCha8Rng` seeded from the pattern hash.
/// - **Prune** zero-confirm cells that have never been reinforced and are older
///   than 100 seconds.
pub struct AffinityMaturator {
    cells: Vec<MemoryCell>,
    index: HashMap<[u8; 32], usize>,
    uf: InPlaceUnificationTable<CellKey>,
    /// Patterns exempt from mutation — known-bad Crucible fixture hashes.
    pub suppressed_patterns: HashSet<[u8; 32]>,
    /// Running count of [`ingest_pattern`][Self::ingest_pattern] calls.
    /// Callers use this to decide when to trigger [`mature_cells`][Self::mature_cells].
    pub ingest_count: u32,
}

impl Default for AffinityMaturator {
    fn default() -> Self {
        AffinityMaturator {
            cells: Vec::new(),
            index: HashMap::new(),
            uf: InPlaceUnificationTable::new(),
            suppressed_patterns: HashSet::new(),
            ingest_count: 0,
        }
    }
}

impl AffinityMaturator {
    /// Create an empty maturator.
    pub fn new() -> Self {
        AffinityMaturator::default()
    }

    /// Create a maturator pre-loaded with suppressed (Crucible-fixture) hashes.
    ///
    /// Suppressed patterns can still be ingested and confirmed normally; they
    /// are only excluded from the mutation pass in [`mature_cells`][Self::mature_cells].
    pub fn with_suppressed(suppressed: &[[u8; 32]]) -> Self {
        AffinityMaturator {
            suppressed_patterns: suppressed.iter().copied().collect(),
            ..AffinityMaturator::default()
        }
    }

    /// Ingest a pattern hash: allocate a new cell on first sight, return its
    /// key. Idempotent — a second call with the same hash returns the existing
    /// key without creating a duplicate cell.
    pub fn ingest_pattern(&mut self, pattern_hash: [u8; 32]) -> CellKey {
        let key = self.ingest_pattern_raw(pattern_hash);
        self.ingest_count = self.ingest_count.saturating_add(1);
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

    /// Return all active (non-pruned) cells at or above [`MATURITY_THRESHOLD`].
    pub fn list_mature_cells(&self) -> Vec<&MemoryCell> {
        self.cells
            .iter()
            .filter(|c| !c.is_pruned && c.maturity_score >= MATURITY_THRESHOLD)
            .collect()
    }

    /// Run the mutation-select refinement cycle.
    ///
    /// **Mutation pass**: every fully mature cell (`maturity_score ≥ MATURITY_THRESHOLD`,
    /// `confirm_count ≥ FULL_MATURITY_CONFIRMS`) that is not in `suppressed_patterns`
    /// spawns `MUTATION_VARIANT_COUNT` variant cells. Variants are derived by
    /// XOR-masking the seed hash with `ChaCha8Rng` output seeded deterministically
    /// from `pattern_hash[0..8]`, giving reproducible mutation across sessions.
    ///
    /// **Selection / pruning pass**: cells with `confirm_count == 0` that were
    /// first seen more than 100 seconds ago are marked `is_pruned = true` and
    /// removed from the active pool.
    pub fn mature_cells(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // --- Mutation pass ---
        // Collect seed hashes first to avoid borrow conflict with self.cells.
        let seed_hashes: Vec<[u8; 32]> = {
            let suppressed = &self.suppressed_patterns;
            self.cells
                .iter()
                .filter(|c| {
                    !c.is_pruned
                        && c.maturity_score >= MATURITY_THRESHOLD
                        && c.confirm_count >= FULL_MATURITY_CONFIRMS
                        && !suppressed.contains(&c.pattern_hash)
                })
                .map(|c| c.pattern_hash)
                .collect()
        };

        for seed_hash in seed_hashes {
            let mut seed_bytes = [0u8; 8];
            seed_bytes.copy_from_slice(&seed_hash[..8]);
            let seed_u64 = u64::from_le_bytes(seed_bytes);
            let mut rng = ChaCha8Rng::seed_from_u64(seed_u64);

            for _ in 0..MUTATION_VARIANT_COUNT {
                let mut xor_mask = [0u8; 32];
                rng.fill_bytes(&mut xor_mask);
                let mut variant = seed_hash;
                for (v, x) in variant.iter_mut().zip(xor_mask.iter()) {
                    *v ^= x;
                }
                if !self.index.contains_key(&variant)
                    && !self.suppressed_patterns.contains(&variant)
                {
                    self.ingest_pattern_raw(variant);
                }
            }
        }

        // --- Selection / pruning pass ---
        for cell in self.cells.iter_mut() {
            if !cell.is_pruned && cell.confirm_count == 0 && cell.first_seen + 100 < now {
                cell.is_pruned = true;
            }
        }
    }

    /// Total number of active (non-pruned) tracked cells.
    pub fn cell_count(&self) -> usize {
        self.cells.iter().filter(|c| !c.is_pruned).count()
    }

    /// Insert a pattern without incrementing `ingest_count` or triggering a sweep.
    ///
    /// Used internally by [`mature_cells`][Self::mature_cells] when spawning
    /// variant cells, to prevent re-entrant sweep triggering.
    fn ingest_pattern_raw(&mut self, pattern_hash: [u8; 32]) -> CellKey {
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
        assert_eq!(m.list_mature_cells().len(), 1);
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

        let mature = m.list_mature_cells();
        assert_eq!(mature.len(), 1);
        assert_eq!(mature[0].pattern_hash, h_ripe);
    }

    // --- Phase B tests ---

    #[test]
    fn test_mature_cells_produces_variants() {
        let mut m = AffinityMaturator::new();
        let h = hash_pattern(b"mature_seed_beta");
        // Bring to full maturity.
        for _ in 0..FULL_MATURITY_CONFIRMS {
            m.confirm_true_positive(h);
        }
        assert_eq!(m.cell_count(), 1, "one cell before sweep");
        m.mature_cells();
        // Original + MUTATION_VARIANT_COUNT variants.
        assert_eq!(
            m.cell_count(),
            1 + MUTATION_VARIANT_COUNT,
            "mutation must produce exactly {} variants",
            MUTATION_VARIANT_COUNT
        );
        // All variants have maturity_score=0.0 and confirm_count=0.
        let variants: Vec<&MemoryCell> = m
            .cells
            .iter()
            .filter(|c| !c.is_pruned && c.pattern_hash != h)
            .collect();
        assert_eq!(variants.len(), MUTATION_VARIANT_COUNT);
        for v in &variants {
            assert_eq!(v.maturity_score, 0.0, "variant must start immature");
            assert_eq!(v.confirm_count, 0, "variant must start unconfirmed");
        }
    }

    #[test]
    fn test_selection_prunes_zero_confirm_aged_cells() {
        let mut m = AffinityMaturator::new();
        let h = hash_pattern(b"aged_cell_alpha");
        let key = m.ingest_pattern(h);
        // Backdate first_seen to epoch 0 — guaranteed > 100 s old.
        m.cells[key.index() as usize].first_seen = 0;
        assert_eq!(m.cell_count(), 1, "cell present before sweep");
        m.mature_cells();
        assert_eq!(m.cell_count(), 0, "zero-confirm aged cell must be pruned");
    }

    #[test]
    fn test_suppressed_patterns_block_mutation() {
        let h = hash_pattern(b"mature_seed_beta");
        let mut m = AffinityMaturator::with_suppressed(&[h]);
        // Mature the suppressed cell fully.
        for _ in 0..FULL_MATURITY_CONFIRMS {
            m.confirm_true_positive(h);
        }
        let count_before = m.cell_count();
        assert_eq!(count_before, 1);
        m.mature_cells();
        // Suppressed pattern must not spawn any variants.
        assert_eq!(
            m.cell_count(),
            count_before,
            "suppressed pattern must not produce mutation variants"
        );
    }
}
