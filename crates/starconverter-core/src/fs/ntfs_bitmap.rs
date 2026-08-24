//! Bounded, allocation-free parsing of the NTFS volume allocation bitmap.
//!
//! NTFS stores one bit per logical cluster in the unnamed data stream of `$Bitmap`. Bit zero is
//! the least-significant bit of byte zero; a set bit means allocated. Microsoft documents that bit
//! ordering for volume bitmaps, and NTFS-3G's `mkntfs` rounds the on-disk `$Bitmap` data length to
//! an eight-byte boundary and marks every bit beyond the last addressable cluster as allocated.
//!
//! Bitmap parsing interprets only caller-owned bytes and performs no I/O or allocation. The
//! optional ownership reconciler allocates a caller-bounded list of cluster ranges so it can
//! compare the bitmap with independently inventoried non-resident attributes.

use std::fmt;

/// On-disk `$Bitmap` data-size alignment used by NTFS-3G's formatter.
pub const BITMAP_ALIGNMENT_BYTES: usize = 8;

/// Largest cluster count supported by this parser.
///
/// NTFS-3G's formatter requires the number of clusters to fit within 32 bits. At this limit the
/// canonical bitmap is 512 MiB, which is also this module's maximum accepted input length.
pub const MAX_SUPPORTED_CLUSTER_COUNT: u64 = 4_294_967_295;

/// Maximum canonical `$Bitmap` byte length accepted by this parser.
pub const MAX_SUPPORTED_BITMAP_BYTES: usize = 512 * 1024 * 1024;

/// How reserved bits after the last addressable cluster are handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TailBitPolicy {
    /// Reject a bitmap unless every reserved tail bit is set (allocated).
    RequireAllocated,
    /// Preserve tail-bit state as evidence without rejecting unset reserved bits.
    ReportOnly,
}

/// Allocation state of one addressable NTFS cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClusterAllocation {
    Free,
    Allocated,
}

/// Evidence about the canonical padding bits after the last addressable cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TailEvidence {
    /// Number of reserved bits between `cluster_count` and the end of the aligned bitmap.
    pub reserved_bits: u8,
    /// Number of those reserved bits that are marked allocated.
    pub allocated_bits: u8,
    /// First reserved bit that is unexpectedly free, expressed as a bit/LCN index.
    pub first_unallocated_bit: Option<u64>,
}

impl TailEvidence {
    /// Whether all reserved tail bits carry the formatter's expected allocated value.
    #[must_use]
    pub const fn all_allocated(self) -> bool {
        self.reserved_bits == self.allocated_bits
    }
}

/// A validated, borrowed view of an NTFS volume allocation bitmap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtfsBitmap<'a> {
    bytes: &'a [u8],
    cluster_count: u64,
    allocated_clusters: u64,
    tail: TailEvidence,
}

/// One physical cluster range claimed by an independently inventoried NTFS attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtfsAllocationClaim {
    pub start_lcn: u64,
    pub cluster_count: u64,
}

/// Resource limits for exact bitmap/ownership reconciliation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtfsReconciliationLimits {
    pub max_claims: usize,
}

impl Default for NtfsReconciliationLimits {
    fn default() -> Self {
        Self {
            max_claims: 8 * 1024 * 1024,
        }
    }
}

/// Exact counts proven while comparing `$Bitmap` with physical ownership claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtfsAllocationReconciliation {
    pub claim_count: usize,
    pub claimed_clusters: u64,
    pub unexplained_allocated_clusters: u64,
    pub first_unexplained_lcn: Option<u64>,
}

/// Whether the ownership comparison proves the complete allocated-cluster set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtfsAllocationReconciliationEvidence {
    /// Every allocated bit has exactly one physical owner and every claim has an allocated bit.
    Complete(NtfsAllocationReconciliation),
    /// Known claims are sound, but the inventory was already incomplete and therefore cannot
    /// explain every allocated cluster authoritatively.
    IncompleteInventory(NtfsAllocationReconciliation),
}

impl NtfsBitmap<'_> {
    /// Number of addressable clusters represented by this bitmap.
    #[must_use]
    pub const fn cluster_count(&self) -> u64 {
        self.cluster_count
    }

    /// Canonical aligned byte length of the bitmap data.
    #[must_use]
    pub const fn byte_len(&self) -> usize {
        self.bytes.len()
    }

    /// Number of addressable clusters marked allocated.
    #[must_use]
    pub const fn allocated_clusters(&self) -> u64 {
        self.allocated_clusters
    }

    /// Number of addressable clusters marked free.
    #[must_use]
    pub const fn free_clusters(&self) -> u64 {
        self.cluster_count - self.allocated_clusters
    }

    /// Evidence collected from reserved bits after the last addressable cluster.
    #[must_use]
    pub const fn tail_evidence(&self) -> TailEvidence {
        self.tail
    }

    /// Returns the allocation state of `lcn`.
    ///
    /// # Errors
    ///
    /// Returns [`NtfsBitmapError::ClusterOutOfRange`] when `lcn` is not an addressable cluster, or
    /// [`NtfsBitmapError::LengthCalculationOverflow`] on a host whose address space cannot index
    /// the already-validated bitmap.
    pub fn allocation(&self, lcn: u64) -> Result<ClusterAllocation, NtfsBitmapError> {
        if lcn >= self.cluster_count {
            return Err(NtfsBitmapError::ClusterOutOfRange {
                lcn,
                cluster_count: self.cluster_count,
            });
        }

        let byte_index =
            usize::try_from(lcn >> 3).map_err(|_| NtfsBitmapError::LengthCalculationOverflow {
                cluster_count: self.cluster_count,
            })?;
        let bit_index =
            u32::try_from(lcn & 7).map_err(|_| NtfsBitmapError::LengthCalculationOverflow {
                cluster_count: self.cluster_count,
            })?;
        if self.bytes[byte_index] & (1_u8 << bit_index) == 0 {
            Ok(ClusterAllocation::Free)
        } else {
            Ok(ClusterAllocation::Allocated)
        }
    }

    /// Returns whether `lcn` is marked allocated.
    ///
    /// # Errors
    ///
    /// Returns [`NtfsBitmapError::ClusterOutOfRange`] when `lcn` is not an addressable cluster, or
    /// [`NtfsBitmapError::LengthCalculationOverflow`] on a host whose address space cannot index
    /// the already-validated bitmap.
    pub fn is_allocated(&self, lcn: u64) -> Result<bool, NtfsBitmapError> {
        self.allocation(lcn)
            .map(|state| state == ClusterAllocation::Allocated)
    }
}

/// Reason an NTFS volume allocation bitmap could not be safely interpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtfsBitmapError {
    /// A bitmap cannot represent a volume without addressable clusters.
    ZeroClusterCount,
    /// The supplied geometry exceeds the parser's explicit support envelope.
    ClusterCountTooLarge { cluster_count: u64, maximum: u64 },
    /// Bitmap length calculation overflowed the host's address space.
    LengthCalculationOverflow { cluster_count: u64 },
    /// The borrowed input itself exceeds the parser's explicit byte cap.
    BitmapTooLarge { actual: usize, maximum: usize },
    /// The input is not the canonical eight-byte-aligned length for this cluster count.
    LengthMismatch {
        actual: usize,
        minimum: usize,
        canonical: usize,
    },
    /// A reserved bit after the last addressable cluster was marked free in strict mode.
    UnallocatedTailBit { bit_index: u64 },
    /// A caller attempted to query outside the addressable cluster range.
    ClusterOutOfRange { lcn: u64, cluster_count: u64 },
    /// Ownership reconciliation requires a non-zero claim cap.
    ZeroReconciliationClaimLimit,
    /// The caller supplied more ownership claims than the explicit reconciliation cap.
    ReconciliationClaimLimitExceeded { actual: usize, maximum: usize },
    /// Temporary storage for the bounded, sorted claim index could not be allocated.
    ReconciliationAllocationFailed,
    /// A physical allocation claim cannot contain zero clusters.
    EmptyAllocationClaim { claim_index: usize },
    /// A physical allocation claim overflowed while calculating its exclusive end LCN.
    AllocationClaimOverflow { claim_index: usize },
    /// A physical allocation claim extends beyond the addressable volume.
    AllocationClaimOutOfRange {
        claim_index: usize,
        start_lcn: u64,
        cluster_count: u64,
        volume_cluster_count: u64,
    },
    /// Two physical ownership claims overlap, which NTFS cannot represent losslessly here.
    OverlappingAllocationClaims {
        first_claim_index: usize,
        second_claim_index: usize,
        lcn: u64,
    },
    /// An inventoried physical extent claims a cluster that `$Bitmap` marks free.
    ClaimedClusterMarkedFree { claim_index: usize, lcn: u64 },
    /// An exhaustive inventory left one or more allocated bitmap clusters without an owner.
    UnexplainedAllocatedCluster { lcn: u64, unexplained_clusters: u64 },
}

impl fmt::Display for NtfsBitmapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroClusterCount => formatter.write_str("NTFS bitmap cluster count is zero"),
            Self::ClusterCountTooLarge {
                cluster_count,
                maximum,
            } => write!(
                formatter,
                "NTFS bitmap cluster count {cluster_count} exceeds the supported maximum {maximum}"
            ),
            Self::LengthCalculationOverflow { cluster_count } => write!(
                formatter,
                "NTFS bitmap length calculation overflowed for {cluster_count} clusters"
            ),
            Self::BitmapTooLarge { actual, maximum } => write!(
                formatter,
                "NTFS bitmap is {actual} bytes, exceeding the supported maximum {maximum}"
            ),
            Self::LengthMismatch {
                actual,
                minimum,
                canonical,
            } => write!(
                formatter,
                "NTFS bitmap has {actual} bytes; {minimum} bytes are required for the cluster bits and the canonical aligned length is {canonical}"
            ),
            Self::UnallocatedTailBit { bit_index } => write!(
                formatter,
                "reserved NTFS bitmap tail bit {bit_index} is marked free"
            ),
            Self::ClusterOutOfRange { lcn, cluster_count } => write!(
                formatter,
                "NTFS bitmap LCN {lcn} is out of range for {cluster_count} clusters"
            ),
            Self::ZeroReconciliationClaimLimit => {
                formatter.write_str("NTFS reconciliation claim limit is zero")
            }
            Self::ReconciliationClaimLimitExceeded { actual, maximum } => write!(
                formatter,
                "NTFS reconciliation received {actual} claims, exceeding caller cap {maximum}"
            ),
            Self::ReconciliationAllocationFailed => formatter
                .write_str("could not allocate the bounded NTFS reconciliation claim index"),
            Self::EmptyAllocationClaim { claim_index } => write!(
                formatter,
                "NTFS allocation claim {claim_index} contains zero clusters"
            ),
            Self::AllocationClaimOverflow { claim_index } => write!(
                formatter,
                "NTFS allocation claim {claim_index} overflows its ending LCN"
            ),
            Self::AllocationClaimOutOfRange {
                claim_index,
                start_lcn,
                cluster_count,
                volume_cluster_count,
            } => write!(
                formatter,
                "NTFS allocation claim {claim_index} at LCN {start_lcn} for {cluster_count} clusters exceeds the {volume_cluster_count}-cluster volume"
            ),
            Self::OverlappingAllocationClaims {
                first_claim_index,
                second_claim_index,
                lcn,
            } => write!(
                formatter,
                "NTFS allocation claims {first_claim_index} and {second_claim_index} overlap at LCN {lcn}"
            ),
            Self::ClaimedClusterMarkedFree { claim_index, lcn } => write!(
                formatter,
                "NTFS allocation claim {claim_index} uses LCN {lcn}, but $Bitmap marks it free"
            ),
            Self::UnexplainedAllocatedCluster {
                lcn,
                unexplained_clusters,
            } => write!(
                formatter,
                "NTFS $Bitmap marks {unexplained_clusters} clusters allocated without an inventoried owner; the first is LCN {lcn}"
            ),
        }
    }
}

impl std::error::Error for NtfsBitmapError {}

/// Parses an NTFS `$Bitmap` data stream using the strict formatter-compatible tail policy.
///
/// The accepted input length is exactly `ceil(cluster_count / 8)` rounded up to an eight-byte
/// boundary. Every reserved bit after `cluster_count` must be set. Only addressable cluster bits
/// contribute to the allocated/free counts.
///
/// # Errors
///
/// Returns [`NtfsBitmapError`] for unsupported geometry, a noncanonical byte length, or an unset
/// reserved tail bit.
pub fn parse_bitmap(cluster_count: u64, bytes: &[u8]) -> Result<NtfsBitmap<'_>, NtfsBitmapError> {
    parse_bitmap_with_tail_policy(cluster_count, bytes, TailBitPolicy::RequireAllocated)
}

/// Parses an NTFS `$Bitmap` data stream with an explicit reserved-tail policy.
///
/// [`TailBitPolicy::ReportOnly`] is intended for read-only forensic inspection: unset reserved
/// tail bits are retained in [`TailEvidence`] but do not change cluster accounting.
///
/// # Errors
///
/// Returns [`NtfsBitmapError`] for unsupported geometry, a noncanonical byte length, or (under
/// [`TailBitPolicy::RequireAllocated`]) an unset reserved tail bit.
pub fn parse_bitmap_with_tail_policy(
    cluster_count: u64,
    bytes: &[u8],
    tail_policy: TailBitPolicy,
) -> Result<NtfsBitmap<'_>, NtfsBitmapError> {
    let lengths = bitmap_lengths(cluster_count)?;
    if bytes.len() > MAX_SUPPORTED_BITMAP_BYTES {
        return Err(NtfsBitmapError::BitmapTooLarge {
            actual: bytes.len(),
            maximum: MAX_SUPPORTED_BITMAP_BYTES,
        });
    }
    if bytes.len() != lengths.canonical {
        return Err(NtfsBitmapError::LengthMismatch {
            actual: bytes.len(),
            minimum: lengths.minimum,
            canonical: lengths.canonical,
        });
    }

    let allocated_clusters = count_allocated_clusters(cluster_count, bytes);
    let tail = inspect_tail(cluster_count, bytes);
    if let (TailBitPolicy::RequireAllocated, Some(bit_index)) =
        (tail_policy, tail.first_unallocated_bit)
    {
        return Err(NtfsBitmapError::UnallocatedTailBit { bit_index });
    }

    Ok(NtfsBitmap {
        bytes,
        cluster_count,
        allocated_clusters,
        tail,
    })
}

/// Reconciles every addressable `$Bitmap` bit with independent physical ownership claims.
///
/// Claims are sorted under `limits.max_claims`, must be non-empty, in-range and pairwise
/// disjoint, and every claimed cluster must be allocated. When `ownership_complete` is true,
/// every allocated bitmap cluster must also have exactly one claim. When it is false, unexplained
/// allocated clusters are counted and returned as explicit incomplete evidence.
///
/// # Errors
///
/// Returns [`NtfsBitmapError`] for an invalid bound, malformed/overlapping claims, a claimed-free
/// cluster, an unexplained allocation under exhaustive ownership, or bounded allocation failure.
pub fn reconcile_allocation_claims(
    bitmap: &NtfsBitmap<'_>,
    claims: &[NtfsAllocationClaim],
    ownership_complete: bool,
    limits: NtfsReconciliationLimits,
) -> Result<NtfsAllocationReconciliationEvidence, NtfsBitmapError> {
    if limits.max_claims == 0 {
        return Err(NtfsBitmapError::ZeroReconciliationClaimLimit);
    }
    if claims.len() > limits.max_claims {
        return Err(NtfsBitmapError::ReconciliationClaimLimitExceeded {
            actual: claims.len(),
            maximum: limits.max_claims,
        });
    }

    let mut ordered = Vec::new();
    ordered
        .try_reserve_exact(claims.len())
        .map_err(|_| NtfsBitmapError::ReconciliationAllocationFailed)?;
    for (claim_index, claim) in claims.iter().copied().enumerate() {
        if claim.cluster_count == 0 {
            return Err(NtfsBitmapError::EmptyAllocationClaim { claim_index });
        }
        let end_lcn = claim
            .start_lcn
            .checked_add(claim.cluster_count)
            .ok_or(NtfsBitmapError::AllocationClaimOverflow { claim_index })?;
        if end_lcn > bitmap.cluster_count {
            return Err(NtfsBitmapError::AllocationClaimOutOfRange {
                claim_index,
                start_lcn: claim.start_lcn,
                cluster_count: claim.cluster_count,
                volume_cluster_count: bitmap.cluster_count,
            });
        }
        ordered.push(OrderedClaim {
            claim_index,
            start_lcn: claim.start_lcn,
            end_lcn,
        });
    }
    ordered.sort_unstable_by_key(|claim| (claim.start_lcn, claim.end_lcn, claim.claim_index));

    let mut claimed_clusters = 0_u64;
    let mut previous: Option<OrderedClaim> = None;
    for claim in &ordered {
        if let Some(prior) = previous {
            if claim.start_lcn < prior.end_lcn {
                return Err(NtfsBitmapError::OverlappingAllocationClaims {
                    first_claim_index: prior.claim_index,
                    second_claim_index: claim.claim_index,
                    lcn: claim.start_lcn,
                });
            }
        }
        if let Some(lcn) = first_cluster_with_state(
            bitmap,
            claim.start_lcn,
            claim.end_lcn,
            ClusterAllocation::Free,
        ) {
            return Err(NtfsBitmapError::ClaimedClusterMarkedFree {
                claim_index: claim.claim_index,
                lcn,
            });
        }
        claimed_clusters = claimed_clusters
            .checked_add(claim.end_lcn - claim.start_lcn)
            .ok_or(NtfsBitmapError::LengthCalculationOverflow {
                cluster_count: bitmap.cluster_count,
            })?;
        previous = Some(*claim);
    }

    let unexplained_allocated_clusters = bitmap.allocated_clusters - claimed_clusters;
    let first_unexplained_lcn = if unexplained_allocated_clusters == 0 {
        None
    } else {
        first_unclaimed_allocated_cluster(bitmap, &ordered)
    };
    let report = NtfsAllocationReconciliation {
        claim_count: claims.len(),
        claimed_clusters,
        unexplained_allocated_clusters,
        first_unexplained_lcn,
    };
    if ownership_complete {
        if let Some(lcn) = first_unexplained_lcn {
            return Err(NtfsBitmapError::UnexplainedAllocatedCluster {
                lcn,
                unexplained_clusters: unexplained_allocated_clusters,
            });
        }
        Ok(NtfsAllocationReconciliationEvidence::Complete(report))
    } else {
        Ok(NtfsAllocationReconciliationEvidence::IncompleteInventory(
            report,
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OrderedClaim {
    claim_index: usize,
    start_lcn: u64,
    end_lcn: u64,
}

fn first_unclaimed_allocated_cluster(
    bitmap: &NtfsBitmap<'_>,
    claims: &[OrderedClaim],
) -> Option<u64> {
    let mut cursor = 0_u64;
    for claim in claims {
        if let Some(lcn) = first_cluster_with_state(
            bitmap,
            cursor,
            claim.start_lcn,
            ClusterAllocation::Allocated,
        ) {
            return Some(lcn);
        }
        cursor = claim.end_lcn;
    }
    first_cluster_with_state(
        bitmap,
        cursor,
        bitmap.cluster_count,
        ClusterAllocation::Allocated,
    )
}

fn first_cluster_with_state(
    bitmap: &NtfsBitmap<'_>,
    start_lcn: u64,
    end_lcn: u64,
    state: ClusterAllocation,
) -> Option<u64> {
    if start_lcn >= end_lcn {
        return None;
    }
    let first_byte = usize::try_from(start_lcn >> 3).ok()?;
    let last_byte = usize::try_from((end_lcn - 1) >> 3).ok()?;
    for byte_index in first_byte..=last_byte {
        let byte_start = u64::try_from(byte_index).ok()?.checked_mul(8)?;
        let lower = start_lcn.saturating_sub(byte_start).min(8);
        let upper = end_lcn.saturating_sub(byte_start).min(8);
        let lower_shift = u32::try_from(lower).ok()?;
        let width = u32::try_from(upper - lower).ok()?;
        let range_mask = if width == 8 {
            u8::MAX
        } else {
            u8::try_from((1_u16 << width) - 1).ok()?
        } << lower_shift;
        let matching = match state {
            ClusterAllocation::Allocated => bitmap.bytes[byte_index] & range_mask,
            ClusterAllocation::Free => !bitmap.bytes[byte_index] & range_mask,
        };
        if matching != 0 {
            return byte_start.checked_add(u64::from(matching.trailing_zeros()));
        }
    }
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BitmapLengths {
    minimum: usize,
    canonical: usize,
}

fn bitmap_lengths(cluster_count: u64) -> Result<BitmapLengths, NtfsBitmapError> {
    if cluster_count == 0 {
        return Err(NtfsBitmapError::ZeroClusterCount);
    }
    if cluster_count > MAX_SUPPORTED_CLUSTER_COUNT {
        return Err(NtfsBitmapError::ClusterCountTooLarge {
            cluster_count,
            maximum: MAX_SUPPORTED_CLUSTER_COUNT,
        });
    }

    let minimum_u64 = cluster_count
        .checked_add(7)
        .ok_or(NtfsBitmapError::LengthCalculationOverflow { cluster_count })?
        / 8;
    let minimum = usize::try_from(minimum_u64)
        .map_err(|_| NtfsBitmapError::LengthCalculationOverflow { cluster_count })?;
    let canonical = minimum
        .checked_add(BITMAP_ALIGNMENT_BYTES - 1)
        .ok_or(NtfsBitmapError::LengthCalculationOverflow { cluster_count })?
        & !(BITMAP_ALIGNMENT_BYTES - 1);

    if canonical > MAX_SUPPORTED_BITMAP_BYTES {
        return Err(NtfsBitmapError::LengthCalculationOverflow { cluster_count });
    }
    Ok(BitmapLengths { minimum, canonical })
}

fn count_allocated_clusters(cluster_count: u64, bytes: &[u8]) -> u64 {
    let complete_bytes = usize::try_from(cluster_count / 8)
        .expect("supported cluster counts always produce an addressable byte count");
    let mut allocated = bytes[..complete_bytes]
        .iter()
        .map(|byte| u64::from(byte.count_ones()))
        .sum();
    let remainder = u32::try_from(cluster_count & 7).expect("bit remainder fits in u32");
    if remainder != 0 {
        let addressable_mask = (1_u8 << remainder) - 1;
        allocated += u64::from((bytes[complete_bytes] & addressable_mask).count_ones());
    }
    allocated
}

fn inspect_tail(cluster_count: u64, bytes: &[u8]) -> TailEvidence {
    let total_bits =
        u64::try_from(bytes.len()).expect("supported bitmap byte lengths fit in u64") * 8;
    let reserved_bits = u8::try_from(total_bits - cluster_count)
        .expect("eight-byte canonical alignment has at most 63 reserved bits");
    let mut allocated_bits = 0_u8;
    let mut first_unallocated_bit = None;

    for bit_index in cluster_count..total_bits {
        let byte_index =
            usize::try_from(bit_index >> 3).expect("supported bitmap bit indices fit in usize");
        let shift = u32::try_from(bit_index & 7).expect("bit-within-byte index fits in u32");
        if bytes[byte_index] & (1_u8 << shift) == 0 {
            first_unallocated_bit.get_or_insert(bit_index);
        } else {
            allocated_bits += 1;
        }
    }

    TailEvidence {
        reserved_bits,
        allocated_bits,
        first_unallocated_bit,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical_bytes(cluster_count: u64, fill: u8) -> Vec<u8> {
        let length = bitmap_lengths(cluster_count)
            .expect("test cluster geometry")
            .canonical;
        vec![fill; length]
    }

    fn set_tail_allocated(cluster_count: u64, bytes: &mut [u8]) {
        let total_bits = u64::try_from(bytes.len()).expect("test length fits") * 8;
        for bit_index in cluster_count..total_bits {
            let byte_index = usize::try_from(bit_index >> 3).expect("test index fits");
            let shift = u32::try_from(bit_index & 7).expect("test shift fits");
            bytes[byte_index] |= 1_u8 << shift;
        }
    }

    #[test]
    fn derives_minimum_and_canonical_lengths_at_boundaries() {
        for (clusters, minimum, canonical) in [
            (1, 1, 8),
            (8, 1, 8),
            (9, 2, 8),
            (63, 8, 8),
            (64, 8, 8),
            (65, 9, 16),
            (u64::from(u32::MAX), 536_870_912, 536_870_912),
        ] {
            assert_eq!(
                bitmap_lengths(clusters),
                Ok(BitmapLengths { minimum, canonical })
            );
        }
    }

    #[test]
    fn rejects_zero_and_more_than_32_bit_cluster_counts_without_reading_input() {
        assert_eq!(parse_bitmap(0, &[]), Err(NtfsBitmapError::ZeroClusterCount));
        assert_eq!(
            parse_bitmap(u64::from(u32::MAX) + 1, &[]),
            Err(NtfsBitmapError::ClusterCountTooLarge {
                cluster_count: u64::from(u32::MAX) + 1,
                maximum: MAX_SUPPORTED_CLUSTER_COUNT,
            })
        );
    }

    #[test]
    fn rejects_short_minimal_and_oversized_lengths_when_not_canonical() {
        for (actual, expected_error) in [
            (
                0,
                NtfsBitmapError::LengthMismatch {
                    actual: 0,
                    minimum: 2,
                    canonical: 8,
                },
            ),
            (
                2,
                NtfsBitmapError::LengthMismatch {
                    actual: 2,
                    minimum: 2,
                    canonical: 8,
                },
            ),
            (
                9,
                NtfsBitmapError::LengthMismatch {
                    actual: 9,
                    minimum: 2,
                    canonical: 8,
                },
            ),
        ] {
            assert_eq!(parse_bitmap(9, &vec![0xff; actual]), Err(expected_error));
        }
    }

    #[test]
    fn uses_lsb_first_bit_order_and_counts_only_addressable_clusters() {
        let mut bytes = canonical_bytes(10, 0);
        bytes[0] = 0b1000_0101; // LCNs 0, 2, and 7.
        bytes[1] = 0b0000_0010; // LCN 9.
        set_tail_allocated(10, &mut bytes);

        let bitmap = parse_bitmap(10, &bytes).expect("valid canonical bitmap");
        assert_eq!(bitmap.cluster_count(), 10);
        assert_eq!(bitmap.byte_len(), 8);
        assert_eq!(bitmap.allocated_clusters(), 4);
        assert_eq!(bitmap.free_clusters(), 6);
        assert_eq!(bitmap.allocation(0), Ok(ClusterAllocation::Allocated));
        assert_eq!(bitmap.allocation(1), Ok(ClusterAllocation::Free));
        assert_eq!(bitmap.allocation(7), Ok(ClusterAllocation::Allocated));
        assert_eq!(bitmap.allocation(8), Ok(ClusterAllocation::Free));
        assert_eq!(bitmap.allocation(9), Ok(ClusterAllocation::Allocated));
    }

    #[test]
    fn all_free_and_all_allocated_accounting_is_overflow_safe() {
        let free_bytes = canonical_bytes(64, 0);
        let free = parse_bitmap(64, &free_bytes).expect("no tail bits at aligned length");
        assert_eq!(free.allocated_clusters(), 0);
        assert_eq!(free.free_clusters(), 64);

        let allocated_bytes = canonical_bytes(64, 0xff);
        let allocated = parse_bitmap(64, &allocated_bytes).expect("fully allocated bitmap");
        assert_eq!(allocated.allocated_clusters(), 64);
        assert_eq!(allocated.free_clusters(), 0);
    }

    #[test]
    fn strict_policy_requires_every_reserved_tail_bit_to_be_allocated() {
        let bytes = canonical_bytes(1, 0);
        assert_eq!(
            parse_bitmap(1, &bytes),
            Err(NtfsBitmapError::UnallocatedTailBit { bit_index: 1 })
        );

        let mut valid = bytes;
        valid[0] = 1; // Addressable LCN 0; the helper sets only the reserved tail.
        set_tail_allocated(1, &mut valid);
        let parsed = parse_bitmap(1, &valid).expect("allocated canonical tail");
        assert_eq!(
            parsed.tail_evidence(),
            TailEvidence {
                reserved_bits: 63,
                allocated_bits: 63,
                first_unallocated_bit: None,
            }
        );
        assert!(parsed.tail_evidence().all_allocated());
    }

    #[test]
    fn report_only_policy_preserves_tail_anomalies_without_skewing_counts() {
        let mut bytes = canonical_bytes(9, 0xff);
        bytes[1] &= !(1 << 2); // Reserved bit 10 is unexpectedly free.

        let bitmap = parse_bitmap_with_tail_policy(9, &bytes, TailBitPolicy::ReportOnly)
            .expect("report-only mode accepts tail anomaly");
        assert_eq!(bitmap.allocated_clusters(), 9);
        assert_eq!(bitmap.free_clusters(), 0);
        assert_eq!(
            bitmap.tail_evidence(),
            TailEvidence {
                reserved_bits: 55,
                allocated_bits: 54,
                first_unallocated_bit: Some(10),
            }
        );
        assert!(!bitmap.tail_evidence().all_allocated());
    }

    #[test]
    fn cluster_queries_reject_tail_and_larger_indices() {
        let bytes = canonical_bytes(8, 0xff);
        let bitmap = parse_bitmap(8, &bytes).expect("valid bitmap");

        for lcn in [8, 63, u64::MAX] {
            assert_eq!(
                bitmap.allocation(lcn),
                Err(NtfsBitmapError::ClusterOutOfRange {
                    lcn,
                    cluster_count: 8,
                })
            );
            assert_eq!(
                bitmap.is_allocated(lcn),
                Err(NtfsBitmapError::ClusterOutOfRange {
                    lcn,
                    cluster_count: 8,
                })
            );
        }
    }

    #[test]
    fn exact_byte_boundary_has_no_reserved_tail_bits() {
        let bytes = canonical_bytes(64, 0);
        let bitmap = parse_bitmap(64, &bytes).expect("byte and alignment boundary");
        assert_eq!(
            bitmap.tail_evidence(),
            TailEvidence {
                reserved_bits: 0,
                allocated_bits: 0,
                first_unallocated_bit: None,
            }
        );
    }

    #[test]
    fn reconciles_unsorted_disjoint_claims_exactly_across_byte_boundaries() {
        let mut bytes = canonical_bytes(24, 0);
        for lcn in [0_u64, 1, 7, 8, 9, 20, 21, 22] {
            let index = usize::try_from(lcn / 8).unwrap();
            bytes[index] |= 1 << (lcn % 8);
        }
        set_tail_allocated(24, &mut bytes);
        let bitmap = parse_bitmap(24, &bytes).unwrap();
        let evidence = reconcile_allocation_claims(
            &bitmap,
            &[
                NtfsAllocationClaim {
                    start_lcn: 20,
                    cluster_count: 3,
                },
                NtfsAllocationClaim {
                    start_lcn: 7,
                    cluster_count: 3,
                },
                NtfsAllocationClaim {
                    start_lcn: 0,
                    cluster_count: 2,
                },
            ],
            true,
            NtfsReconciliationLimits { max_claims: 3 },
        )
        .unwrap();
        assert_eq!(
            evidence,
            NtfsAllocationReconciliationEvidence::Complete(NtfsAllocationReconciliation {
                claim_count: 3,
                claimed_clusters: 8,
                unexplained_allocated_clusters: 0,
                first_unexplained_lcn: None,
            })
        );
    }

    #[test]
    fn known_claim_on_free_cluster_fails_even_when_inventory_is_incomplete() {
        let mut bytes = canonical_bytes(16, 0);
        bytes[0] = 1;
        set_tail_allocated(16, &mut bytes);
        let bitmap = parse_bitmap(16, &bytes).unwrap();
        assert_eq!(
            reconcile_allocation_claims(
                &bitmap,
                &[NtfsAllocationClaim {
                    start_lcn: 0,
                    cluster_count: 2,
                }],
                false,
                NtfsReconciliationLimits { max_claims: 1 },
            ),
            Err(NtfsBitmapError::ClaimedClusterMarkedFree {
                claim_index: 0,
                lcn: 1,
            })
        );
    }

    #[test]
    fn unexplained_allocation_fails_closed_only_for_exhaustive_inventory() {
        let mut bytes = canonical_bytes(16, 0);
        bytes[0] = 0b1000_0001;
        set_tail_allocated(16, &mut bytes);
        let bitmap = parse_bitmap(16, &bytes).unwrap();
        let claims = [NtfsAllocationClaim {
            start_lcn: 0,
            cluster_count: 1,
        }];
        assert_eq!(
            reconcile_allocation_claims(
                &bitmap,
                &claims,
                true,
                NtfsReconciliationLimits { max_claims: 1 },
            ),
            Err(NtfsBitmapError::UnexplainedAllocatedCluster {
                lcn: 7,
                unexplained_clusters: 1,
            })
        );
        assert_eq!(
            reconcile_allocation_claims(
                &bitmap,
                &claims,
                false,
                NtfsReconciliationLimits { max_claims: 1 },
            ),
            Ok(NtfsAllocationReconciliationEvidence::IncompleteInventory(
                NtfsAllocationReconciliation {
                    claim_count: 1,
                    claimed_clusters: 1,
                    unexplained_allocated_clusters: 1,
                    first_unexplained_lcn: Some(7),
                }
            ))
        );
    }

    #[test]
    fn rejects_overlap_empty_out_of_range_overflow_and_invalid_caps() {
        let bytes = canonical_bytes(64, 0xff);
        let bitmap = parse_bitmap(64, &bytes).unwrap();
        let valid = NtfsReconciliationLimits { max_claims: 2 };
        assert_eq!(
            reconcile_allocation_claims(
                &bitmap,
                &[],
                true,
                NtfsReconciliationLimits { max_claims: 0 }
            ),
            Err(NtfsBitmapError::ZeroReconciliationClaimLimit)
        );
        assert_eq!(
            reconcile_allocation_claims(
                &bitmap,
                &[
                    NtfsAllocationClaim {
                        start_lcn: 0,
                        cluster_count: 1
                    },
                    NtfsAllocationClaim {
                        start_lcn: 2,
                        cluster_count: 1
                    },
                ],
                true,
                NtfsReconciliationLimits { max_claims: 1 },
            ),
            Err(NtfsBitmapError::ReconciliationClaimLimitExceeded {
                actual: 2,
                maximum: 1
            })
        );
        for (claim, error) in [
            (
                NtfsAllocationClaim {
                    start_lcn: 1,
                    cluster_count: 0,
                },
                NtfsBitmapError::EmptyAllocationClaim { claim_index: 0 },
            ),
            (
                NtfsAllocationClaim {
                    start_lcn: u64::MAX,
                    cluster_count: 2,
                },
                NtfsBitmapError::AllocationClaimOverflow { claim_index: 0 },
            ),
            (
                NtfsAllocationClaim {
                    start_lcn: 63,
                    cluster_count: 2,
                },
                NtfsBitmapError::AllocationClaimOutOfRange {
                    claim_index: 0,
                    start_lcn: 63,
                    cluster_count: 2,
                    volume_cluster_count: 64,
                },
            ),
        ] {
            assert_eq!(
                reconcile_allocation_claims(&bitmap, &[claim], false, valid),
                Err(error)
            );
        }
        assert_eq!(
            reconcile_allocation_claims(
                &bitmap,
                &[
                    NtfsAllocationClaim {
                        start_lcn: 8,
                        cluster_count: 4
                    },
                    NtfsAllocationClaim {
                        start_lcn: 10,
                        cluster_count: 1
                    },
                ],
                false,
                valid,
            ),
            Err(NtfsBitmapError::OverlappingAllocationClaims {
                first_claim_index: 0,
                second_claim_index: 1,
                lcn: 10,
            })
        );
    }
}
