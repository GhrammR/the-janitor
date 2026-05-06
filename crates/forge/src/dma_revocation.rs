//! Revocation-after-DMA shadow access detector.

use common::slop::{ProofClass, StructuredFinding};

const DMA_MAP_MARKERS: &[&[u8]] = &[
    b"dma_map".as_slice(),
    b"dma_map_single",
    b"dma_map_page",
    b"iommu_map",
    b"vfio_pin_pages",
    b"pin_user_pages",
];

const DMA_SUBMIT_MARKERS: &[&[u8]] = &[
    b"dma_submit",
    b"queue_submit",
    b"submit_descriptor",
    b"ring_doorbell",
    b"writel(",
    b"cudaLaunchKernel",
];

const REVOCATION_MARKERS: &[&[u8]] = &[
    b"revoke_access",
    b"permission_revoked",
    b"disable_queue",
    b"teardown_context",
    b"close(fd)",
    b"acl_revoke",
];

const DMA_UNMAP_MARKERS: &[&[u8]] = &[
    b"dma_unmap",
    b"dma_unmap_single",
    b"iommu_unmap",
    b"unpin_user_pages",
    b"vfio_unmap",
    b"queue_fence_wait",
];

/// Detect logical access revocation while DMA-mapped buffers or descriptors remain live.
pub fn detect_dma_revocation_shadow_access(source: &[u8]) -> Vec<StructuredFinding> {
    let lower = ascii_lower(source);
    let Some(map_offset) = first_offset(&lower, DMA_MAP_MARKERS) else {
        return Vec::new();
    };
    let Some(submit_offset) = first_offset(&lower, DMA_SUBMIT_MARKERS) else {
        return Vec::new();
    };
    let Some(revoke_offset) = first_offset(&lower, REVOCATION_MARKERS) else {
        return Vec::new();
    };
    let unmap_offset = first_offset(&lower, DMA_UNMAP_MARKERS);
    let unmap_dominates_revoke = unmap_offset.is_some_and(|offset| offset <= revoke_offset);

    if !dma_shadow_access_missing_revocation_dominance(
        true,
        true,
        true,
        unmap_dominates_revoke,
        revoke_offset > map_offset && revoke_offset > submit_offset,
    ) {
        return Vec::new();
    }

    vec![StructuredFinding {
        id: "security:dma_revocation_shadow_access".to_string(),
        line: Some(byte_to_line(source, revoke_offset)),
        fingerprint: short_fingerprint(
            format!("security:dma_revocation_shadow_access:{map_offset}:{submit_offset}:{revoke_offset}")
                .as_bytes(),
        ),
        severity: Some("Critical".to_string()),
        remediation: Some(
            "Ensure every revocation path dominates outstanding DMA descriptors and mapped buffers: fence the queue, unmap the buffer, and only then revoke logical access."
                .to_string(),
        ),
        proof_class: Some(ProofClass::InvariantViolationProof),
        upstream_validation_absent: true,
        ..Default::default()
    }]
}

/// Pure helper for tests and formal assurance.
pub fn dma_shadow_access_missing_revocation_dominance(
    has_map: bool,
    has_submit: bool,
    has_revoke: bool,
    unmap_dominates_revoke: bool,
    revoke_after_activity: bool,
) -> bool {
    has_map && has_submit && has_revoke && revoke_after_activity && !unmap_dominates_revoke
}

fn ascii_lower(source: &[u8]) -> Vec<u8> {
    source.iter().map(u8::to_ascii_lowercase).collect()
}

fn first_offset(haystack: &[u8], needles: &[&[u8]]) -> Option<usize> {
    needles
        .iter()
        .filter_map(|needle| {
            haystack
                .windows(needle.len())
                .position(|window| window == *needle)
        })
        .min()
}

fn byte_to_line(source: &[u8], byte: usize) -> u32 {
    source[..source.len().min(byte)]
        .iter()
        .filter(|&&b| b == b'\n')
        .count() as u32
        + 1
}

fn short_fingerprint(bytes: &[u8]) -> String {
    let digest = blake3::hash(bytes);
    digest.as_bytes()[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        detect_dma_revocation_shadow_access, dma_shadow_access_missing_revocation_dominance,
    };

    #[test]
    fn detects_revocation_before_unmap() {
        let src = br#"
void revoke_gpu_access(struct ctx *ctx, dma_addr_t dma) {
  dma_map_single(dev, ctx->buf, ctx->len, DMA_TO_DEVICE);
  queue_submit(ctx->ring, dma);
  revoke_access(ctx);
}
"#;
        let findings = detect_dma_revocation_shadow_access(src);
        assert!(findings
            .iter()
            .any(|f| f.id == "security:dma_revocation_shadow_access"));
    }

    #[test]
    fn clean_when_unmap_follows_revocation_path() {
        let src = br#"
void revoke_gpu_access(struct ctx *ctx, dma_addr_t dma) {
  dma_map_single(dev, ctx->buf, ctx->len, DMA_TO_DEVICE);
  queue_submit(ctx->ring, dma);
  dma_unmap_single(dev, dma, ctx->len, DMA_TO_DEVICE);
  revoke_access(ctx);
}
"#;
        assert!(detect_dma_revocation_shadow_access(src).is_empty());
    }

    #[test]
    fn helper_requires_missing_dominance() {
        assert!(dma_shadow_access_missing_revocation_dominance(
            true, true, true, false, true
        ));
        assert!(!dma_shadow_access_missing_revocation_dominance(
            true, true, true, true, true
        ));
    }
}
