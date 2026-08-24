//! Allocation-safe exFAT cluster, FAT, and allocation-bitmap primitives.
//!
//! These routines operate on already-bounded byte slices. They never perform I/O, allocate based
//! on an untrusted on-disk length, or silently accept cluster chains with cycles.

use std::fmt;

use super::exfat::ExfatBootSector;

const FIRST_DATA_CLUSTER: u32 = 2;
const BAD_CLUSTER: u32 = 0xffff_fff7;
const END_OF_CHAIN: u32 = u32::MAX;

/// Meaning of one validated exFAT FAT entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FatEntry {
    Free,
    Next(u32),
    Bad,
    EndOfChain,
}

/// A cycle-safe iterator over a FAT-linked cluster chain.
#[derive(Debug)]
pub struct FatChain<'a> {
    fat: &'a [u8],
    geometry: &'a ExfatBootSector,
    next: Option<u32>,
    traversed: u64,
    start_cluster: u32,
}

/// Proven allocation counts from the meaningful bits of an exFAT Allocation Bitmap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllocationSummary {
    pub allocated_clusters: u64,
    pub free_clusters: u64,
    /// Bytes required to represent every cluster bit, excluding permitted reserved tail bytes.
    pub required_bitmap_bytes: u64,
}

/// Structural failure while interpreting exFAT allocation metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExfatAllocationError {
    InvalidCluster {
        cluster: u32,
    },
    ArithmeticOverflow {
        calculation: &'static str,
    },
    FatSliceTooShort {
        required: u64,
        actual: usize,
    },
    BitmapSliceTooShort {
        required: u64,
        actual: usize,
    },
    /// The bitmap contains reserved bytes which this version cannot escrow byte-for-byte.
    BitmapSliceTooLong {
        required: u64,
        actual: usize,
    },
    /// A reserved bit after the final cluster bit is set and cannot yet be preserved.
    BitmapReservedTailBitSet {
        bit_index: u64,
    },
    InvalidFatValue {
        cluster: u32,
        value: u32,
    },
    FreeClusterInChain {
        cluster: u32,
    },
    BadClusterInChain {
        cluster: u32,
    },
    ChainCycleOrTooLong {
        start_cluster: u32,
    },
}

impl fmt::Display for ExfatAllocationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCluster { cluster } => {
                write!(
                    formatter,
                    "cluster {cluster} is outside the exFAT cluster heap"
                )
            }
            Self::ArithmeticOverflow { calculation } => {
                write!(formatter, "overflow while calculating {calculation}")
            }
            Self::FatSliceTooShort { required, actual } => write!(
                formatter,
                "FAT slice is too short: requires {required} bytes, contains {actual}"
            ),
            Self::BitmapSliceTooShort { required, actual } => write!(
                formatter,
                "allocation bitmap is too short: requires {required} bytes, contains {actual}"
            ),
            Self::BitmapSliceTooLong { required, actual } => write!(
                formatter,
                "allocation bitmap contains {actual} bytes, but exactly {required} are supported; reserved tail bytes cannot yet be preserved"
            ),
            Self::BitmapReservedTailBitSet { bit_index } => write!(
                formatter,
                "allocation bitmap reserved tail bit {bit_index} is set and cannot yet be preserved"
            ),
            Self::InvalidFatValue { cluster, value } => write!(
                formatter,
                "FAT entry for cluster {cluster} contains reserved or invalid value 0x{value:08x}"
            ),
            Self::FreeClusterInChain { cluster } => {
                write!(formatter, "cluster chain reaches free cluster {cluster}")
            }
            Self::BadClusterInChain { cluster } => {
                write!(formatter, "cluster chain reaches bad cluster {cluster}")
            }
            Self::ChainCycleOrTooLong { start_cluster } => write!(
                formatter,
                "cluster chain starting at {start_cluster} cycles or exceeds the volume cluster count"
            ),
        }
    }
}

impl std::error::Error for ExfatAllocationError {}

/// Returns the image-relative byte offset of a validated data cluster.
///
/// # Errors
///
/// Returns [`ExfatAllocationError::InvalidCluster`] if `cluster` is outside the cluster heap, or
/// [`ExfatAllocationError::ArithmeticOverflow`] if the byte offset cannot be represented.
pub fn cluster_byte_offset(
    geometry: &ExfatBootSector,
    cluster: u32,
) -> Result<u64, ExfatAllocationError> {
    validate_cluster(geometry, cluster)?;
    let relative_cluster = u64::from(cluster - FIRST_DATA_CLUSTER);
    let relative_bytes = relative_cluster
        .checked_mul(u64::from(geometry.bytes_per_cluster))
        .ok_or(ExfatAllocationError::ArithmeticOverflow {
            calculation: "cluster-relative byte offset",
        })?;
    u64::from(geometry.cluster_heap_offset_sectors)
        .checked_mul(u64::from(geometry.bytes_per_sector))
        .and_then(|heap_offset| heap_offset.checked_add(relative_bytes))
        .ok_or(ExfatAllocationError::ArithmeticOverflow {
            calculation: "image-relative cluster byte offset",
        })
}

/// Interprets one FAT entry after validating its cluster index and slice bounds.
///
/// # Errors
///
/// Returns [`ExfatAllocationError`] if the cluster is invalid, the FAT range overflows, the slice
/// does not contain the required entry, or the entry points outside the cluster heap.
pub fn fat_entry(
    fat: &[u8],
    geometry: &ExfatBootSector,
    cluster: u32,
) -> Result<FatEntry, ExfatAllocationError> {
    validate_cluster(geometry, cluster)?;
    let offset =
        u64::from(cluster)
            .checked_mul(4)
            .ok_or(ExfatAllocationError::ArithmeticOverflow {
                calculation: "FAT entry byte offset",
            })?;
    let end = offset
        .checked_add(4)
        .ok_or(ExfatAllocationError::ArithmeticOverflow {
            calculation: "FAT entry end",
        })?;
    let offset_usize =
        usize::try_from(offset).map_err(|_| ExfatAllocationError::ArithmeticOverflow {
            calculation: "FAT entry platform offset",
        })?;
    let bytes =
        fat.get(offset_usize..offset_usize + 4)
            .ok_or(ExfatAllocationError::FatSliceTooShort {
                required: end,
                actual: fat.len(),
            })?;
    let value = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);

    match value {
        0 => Ok(FatEntry::Free),
        BAD_CLUSTER => Ok(FatEntry::Bad),
        END_OF_CHAIN => Ok(FatEntry::EndOfChain),
        next if validate_cluster(geometry, next).is_ok() => Ok(FatEntry::Next(next)),
        value => Err(ExfatAllocationError::InvalidFatValue { cluster, value }),
    }
}

/// Returns whether one data cluster is marked allocated in an exFAT allocation bitmap.
///
/// The caller supplies the bitmap contents beginning with the bit for cluster 2.
///
/// # Errors
///
/// Returns [`ExfatAllocationError`] if the cluster is invalid or the bitmap is too short.
pub fn bitmap_cluster_is_allocated(
    bitmap: &[u8],
    geometry: &ExfatBootSector,
    cluster: u32,
) -> Result<bool, ExfatAllocationError> {
    validate_cluster(geometry, cluster)?;
    let bit_index = u64::from(cluster - FIRST_DATA_CLUSTER);
    let byte_index = bit_index / 8;
    let required = byte_index + 1;
    let byte = bitmap
        .get(
            usize::try_from(byte_index).map_err(|_| ExfatAllocationError::ArithmeticOverflow {
                calculation: "allocation bitmap platform offset",
            })?,
        )
        .ok_or(ExfatAllocationError::BitmapSliceTooShort {
            required,
            actual: bitmap.len(),
        })?;
    Ok(byte & (1 << (bit_index % 8)) != 0)
}

/// Counts allocated and free clusters after proving the bitmap has canonical, preservable bounds.
///
/// The current preservation sidecar does not retain reserved bitmap bytes or non-zero reserved
/// bits. This parser therefore fails closed rather than silently canonicalizing that evidence.
///
/// # Errors
///
/// Returns [`ExfatAllocationError`] if the supplied data does not contain exactly one rounded-up
/// byte span for every cluster bit, or if an unused bit in the final byte is non-zero.
pub fn summarize_allocation_bitmap(
    bitmap: &[u8],
    geometry: &ExfatBootSector,
) -> Result<AllocationSummary, ExfatAllocationError> {
    let cluster_count = u64::from(geometry.cluster_count);
    let required_bitmap_bytes = cluster_count.div_ceil(8);
    if u64::try_from(bitmap.len()).unwrap_or(u64::MAX) < required_bitmap_bytes {
        return Err(ExfatAllocationError::BitmapSliceTooShort {
            required: required_bitmap_bytes,
            actual: bitmap.len(),
        });
    }
    if u64::try_from(bitmap.len()).unwrap_or(u64::MAX) > required_bitmap_bytes {
        return Err(ExfatAllocationError::BitmapSliceTooLong {
            required: required_bitmap_bytes,
            actual: bitmap.len(),
        });
    }

    let full_bytes = usize::try_from(cluster_count / 8).map_err(|_| {
        ExfatAllocationError::ArithmeticOverflow {
            calculation: "allocation bitmap full-byte count",
        }
    })?;
    let allocated_in_full_bytes = bitmap[..full_bytes]
        .iter()
        .map(|byte| u64::from(byte.count_ones()))
        .sum::<u64>();
    let tail_bits =
        u32::try_from(cluster_count % 8).map_err(|_| ExfatAllocationError::ArithmeticOverflow {
            calculation: "allocation bitmap tail bit count",
        })?;
    if tail_bits != 0 {
        let meaningful_mask = (1_u8 << tail_bits) - 1;
        let reserved = bitmap[full_bytes] & !meaningful_mask;
        if reserved != 0 {
            return Err(ExfatAllocationError::BitmapReservedTailBitSet {
                bit_index: (u64::try_from(full_bytes).map_err(|_| {
                    ExfatAllocationError::ArithmeticOverflow {
                        calculation: "allocation bitmap tail byte index",
                    }
                })? * 8)
                    + u64::from(reserved.trailing_zeros()),
            });
        }
    }
    let allocated_in_tail = if tail_bits == 0 {
        0
    } else {
        let mask = (1_u8 << tail_bits) - 1;
        u64::from((bitmap[full_bytes] & mask).count_ones())
    };
    let allocated_clusters = allocated_in_full_bytes + allocated_in_tail;

    Ok(AllocationSummary {
        allocated_clusters,
        free_clusters: cluster_count - allocated_clusters,
        required_bitmap_bytes,
    })
}

/// Creates a cycle-safe iterator for a FAT-linked chain starting at `start_cluster`.
///
/// # Errors
///
/// Returns [`ExfatAllocationError::InvalidCluster`] if the starting cluster is outside the heap.
pub fn fat_chain<'a>(
    fat: &'a [u8],
    geometry: &'a ExfatBootSector,
    start_cluster: u32,
) -> Result<FatChain<'a>, ExfatAllocationError> {
    validate_cluster(geometry, start_cluster)?;
    Ok(FatChain {
        fat,
        geometry,
        next: Some(start_cluster),
        traversed: 0,
        start_cluster,
    })
}

impl Iterator for FatChain<'_> {
    type Item = Result<u32, ExfatAllocationError>;

    fn next(&mut self) -> Option<Self::Item> {
        let cluster = self.next?;
        if self.traversed >= u64::from(self.geometry.cluster_count) {
            self.next = None;
            return Some(Err(ExfatAllocationError::ChainCycleOrTooLong {
                start_cluster: self.start_cluster,
            }));
        }
        self.traversed += 1;

        match fat_entry(self.fat, self.geometry, cluster) {
            Ok(FatEntry::Next(next)) => self.next = Some(next),
            Ok(FatEntry::EndOfChain) => self.next = None,
            Ok(FatEntry::Free) => {
                self.next = None;
                return Some(Err(ExfatAllocationError::FreeClusterInChain { cluster }));
            }
            Ok(FatEntry::Bad) => {
                self.next = None;
                return Some(Err(ExfatAllocationError::BadClusterInChain { cluster }));
            }
            Err(error) => {
                self.next = None;
                return Some(Err(error));
            }
        }
        Some(Ok(cluster))
    }
}

fn validate_cluster(geometry: &ExfatBootSector, cluster: u32) -> Result<(), ExfatAllocationError> {
    let cluster_limit = FIRST_DATA_CLUSTER
        .checked_add(geometry.cluster_count)
        .ok_or(ExfatAllocationError::ArithmeticOverflow {
            calculation: "cluster heap index limit",
        })?;
    if cluster < FIRST_DATA_CLUSTER || cluster >= cluster_limit {
        Err(ExfatAllocationError::InvalidCluster { cluster })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::exfat::parse_boot_sector;

    fn geometry() -> ExfatBootSector {
        let mut sector = vec![0_u8; 512];
        sector[0..3].copy_from_slice(&[0xeb, 0x76, 0x90]);
        sector[3..11].copy_from_slice(b"EXFAT   ");
        sector[72..80].copy_from_slice(&2048_u64.to_le_bytes());
        sector[80..84].copy_from_slice(&24_u32.to_le_bytes());
        sector[84..88].copy_from_slice(&16_u32.to_le_bytes());
        sector[88..92].copy_from_slice(&40_u32.to_le_bytes());
        sector[92..96].copy_from_slice(&2008_u32.to_le_bytes());
        sector[96..100].copy_from_slice(&2_u32.to_le_bytes());
        sector[104..106].copy_from_slice(&0x0100_u16.to_le_bytes());
        sector[108] = 9;
        sector[110] = 1;
        sector[112] = 0xff;
        sector[510..512].copy_from_slice(&0xaa55_u16.to_le_bytes());
        parse_boot_sector(&sector).unwrap()
    }

    fn fat_with(entries: &[(u32, u32)]) -> Vec<u8> {
        let mut fat = vec![0_u8; 64];
        for &(cluster, value) in entries {
            let offset = usize::try_from(cluster * 4).unwrap();
            fat[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        fat
    }

    #[test]
    fn maps_first_and_last_cluster_offsets() {
        let boot = geometry();
        assert_eq!(cluster_byte_offset(&boot, 2).unwrap(), 40 * 512);
        assert_eq!(cluster_byte_offset(&boot, 2009).unwrap(), (40 + 2007) * 512);
        assert!(matches!(
            cluster_byte_offset(&boot, 2010),
            Err(ExfatAllocationError::InvalidCluster { .. })
        ));
    }

    #[test]
    fn classifies_entries_and_rejects_invalid_links() {
        let boot = geometry();
        let fat = fat_with(&[(2, 0), (3, 4), (4, BAD_CLUSTER), (5, END_OF_CHAIN)]);
        assert_eq!(fat_entry(&fat, &boot, 2).unwrap(), FatEntry::Free);
        assert_eq!(fat_entry(&fat, &boot, 3).unwrap(), FatEntry::Next(4));
        assert_eq!(fat_entry(&fat, &boot, 4).unwrap(), FatEntry::Bad);
        assert_eq!(fat_entry(&fat, &boot, 5).unwrap(), FatEntry::EndOfChain);

        let invalid = fat_with(&[(2, 1), (3, 0xffff_fffe)]);
        assert!(matches!(
            fat_entry(&invalid, &boot, 2),
            Err(ExfatAllocationError::InvalidFatValue {
                cluster: 2,
                value: 1
            })
        ));
        assert!(matches!(
            fat_entry(&invalid, &boot, 3),
            Err(ExfatAllocationError::InvalidFatValue {
                cluster: 3,
                value: 0xffff_fffe
            })
        ));
    }

    #[test]
    fn reports_short_fat_and_bitmap_slices() {
        let boot = geometry();
        assert!(matches!(
            fat_entry(&[0; 8], &boot, 2),
            Err(ExfatAllocationError::FatSliceTooShort { .. })
        ));
        assert!(matches!(
            bitmap_cluster_is_allocated(&[], &boot, 2),
            Err(ExfatAllocationError::BitmapSliceTooShort { .. })
        ));
    }

    #[test]
    fn reads_bitmap_bits_from_cluster_two() {
        let boot = geometry();
        let bitmap = [0b1000_0001, 0b0000_0010];
        assert!(bitmap_cluster_is_allocated(&bitmap, &boot, 2).unwrap());
        assert!(bitmap_cluster_is_allocated(&bitmap, &boot, 9).unwrap());
        assert!(bitmap_cluster_is_allocated(&bitmap, &boot, 11).unwrap());
        assert!(!bitmap_cluster_is_allocated(&bitmap, &boot, 10).unwrap());
    }

    #[test]
    fn summarizes_canonical_bitmap_bits() {
        let boot = geometry();
        let mut bitmap = vec![0xff_u8; 251];
        bitmap[250] = 0b0000_0001;

        let summary = summarize_allocation_bitmap(&bitmap, &boot).unwrap();
        assert_eq!(summary.required_bitmap_bytes, 251);
        assert_eq!(summary.allocated_clusters, 2001);
        assert_eq!(summary.free_clusters, 7);

        assert!(matches!(
            summarize_allocation_bitmap(&bitmap[..250], &boot),
            Err(ExfatAllocationError::BitmapSliceTooShort {
                required: 251,
                actual: 250
            })
        ));
    }

    #[test]
    fn refuses_unpreserved_bitmap_tail_bits_and_bytes() {
        let mut boot = geometry();
        boot.cluster_count = 2001;
        let mut canonical = vec![0xff_u8; 251];
        canonical[250] = 0b0000_0001;
        assert!(summarize_allocation_bitmap(&canonical, &boot).is_ok());

        let mut final_unused_bit = canonical.clone();
        final_unused_bit[250] |= 0b1000_0000;
        assert_eq!(
            summarize_allocation_bitmap(&final_unused_bit, &boot),
            Err(ExfatAllocationError::BitmapReservedTailBitSet { bit_index: 2007 })
        );

        let mut extra_zero = canonical.clone();
        extra_zero.push(0);
        assert_eq!(
            summarize_allocation_bitmap(&extra_zero, &boot),
            Err(ExfatAllocationError::BitmapSliceTooLong {
                required: 251,
                actual: 252,
            })
        );

        let mut extra_nonzero = canonical;
        extra_nonzero.push(0xa5);
        assert_eq!(
            summarize_allocation_bitmap(&extra_nonzero, &boot),
            Err(ExfatAllocationError::BitmapSliceTooLong {
                required: 251,
                actual: 252,
            })
        );
    }

    #[test]
    fn walks_valid_chain_in_order() {
        let boot = geometry();
        let fat = fat_with(&[(2, 7), (7, 3), (3, u32::MAX)]);
        let chain = fat_chain(&fat, &boot, 2)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(chain, vec![2, 7, 3]);
    }

    #[test]
    fn rejects_free_bad_and_cyclic_chains() {
        let boot = geometry();
        let free = fat_with(&[(2, 0)]);
        assert!(matches!(
            fat_chain(&free, &boot, 2).unwrap().next(),
            Some(Err(ExfatAllocationError::FreeClusterInChain { cluster: 2 }))
        ));

        let bad = fat_with(&[(2, BAD_CLUSTER)]);
        assert!(matches!(
            fat_chain(&bad, &boot, 2).unwrap().next(),
            Some(Err(ExfatAllocationError::BadClusterInChain { cluster: 2 }))
        ));

        let cycle = fat_with(&[(2, 3), (3, 2)]);
        let error = fat_chain(&cycle, &boot, 2)
            .unwrap()
            .nth(2008)
            .expect("cycle must reach traversal limit");
        assert!(matches!(
            error,
            Err(ExfatAllocationError::ChainCycleOrTooLong { .. })
        ));
    }
}
