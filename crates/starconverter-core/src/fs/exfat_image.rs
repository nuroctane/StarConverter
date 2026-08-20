//! Bounded exFAT stream reads from an already validated regular image file.
//!
//! This module bridges pure exFAT parsers to [`ImageFile`](crate::image::ImageFile). It has no
//! write path and no device discovery. Every allocation and traversal is capped by the caller.

use std::collections::HashSet;
use std::fmt;

use super::exfat::ExfatBootSector;
use super::exfat_allocation::{ExfatAllocationError, FatEntry, cluster_byte_offset};
use crate::image::{ImageError, ImageFile};

/// Explicit resource limits for one exFAT stream read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamReadLimits {
    /// Maximum logical stream bytes returned to the caller.
    pub max_bytes: usize,
    /// Maximum clusters examined while following a FAT chain.
    pub max_clusters: usize,
}

/// Validated stream bytes and allocation evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExfatStream {
    pub bytes: Vec<u8>,
    pub clusters: Vec<u32>,
    pub allocation_bytes: u64,
    pub contiguous: bool,
}

/// Zero-based selector for one of the on-disk exFAT FATs.
///
/// exFAT volumes with two FATs pair Allocation Bitmap identifier 0 with the first FAT and
/// identifier 1 with the second FAT. Callers which read an Allocation Bitmap stream must select
/// that corresponding FAT rather than blindly following the active FAT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FatIndex {
    First,
    Second,
}

impl FatIndex {
    const fn number(self) -> u8 {
        match self {
            Self::First => 0,
            Self::Second => 1,
        }
    }

    /// Converts an Allocation Bitmap identifier to its corresponding FAT selector.
    #[must_use]
    pub const fn from_bitmap_identifier(identifier: u8) -> Option<Self> {
        match identifier {
            0 => Some(Self::First),
            1 => Some(Self::Second),
            _ => None,
        }
    }

    #[must_use]
    pub const fn active(geometry: &ExfatBootSector) -> Self {
        if geometry.volume_flags & 1 == 0 {
            Self::First
        } else {
            Self::Second
        }
    }
}

/// Failure while reading a bounded exFAT stream from a regular image.
#[derive(Debug)]
pub enum ExfatImageError {
    InvalidLimits,
    InvalidFatIndex {
        requested: u8,
        available: u8,
    },
    InvalidDataLength {
        length: u64,
    },
    StreamTooLarge {
        length: u64,
        maximum: usize,
    },
    ClusterLimitExceeded {
        maximum: usize,
    },
    ChainCycle {
        cluster: u32,
    },
    ChainEndedEarly {
        expected_clusters: u64,
        actual_clusters: usize,
    },
    ChainContinuesPastData {
        next_cluster: u32,
    },
    FreeClusterInChain {
        cluster: u32,
    },
    BadClusterInChain {
        cluster: u32,
    },
    ArithmeticOverflow {
        calculation: &'static str,
    },
    AllocationFailed,
    Allocation(ExfatAllocationError),
    Image(ImageError),
}

impl fmt::Display for ExfatImageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("exFAT stream read limits must be non-zero"),
            Self::InvalidFatIndex {
                requested,
                available,
            } => write!(
                formatter,
                "exFAT FAT index {requested} is unavailable; volume has {available} FAT(s)"
            ),
            Self::InvalidDataLength { length } => {
                write!(formatter, "invalid exFAT stream data length {length}")
            }
            Self::StreamTooLarge { length, maximum } => write!(
                formatter,
                "exFAT stream length {length} exceeds caller limit {maximum}"
            ),
            Self::ClusterLimitExceeded { maximum } => {
                write!(
                    formatter,
                    "exFAT stream exceeds caller cluster limit {maximum}"
                )
            }
            Self::ChainCycle { cluster } => {
                write!(formatter, "exFAT FAT chain cycles at cluster {cluster}")
            }
            Self::ChainEndedEarly {
                expected_clusters,
                actual_clusters,
            } => write!(
                formatter,
                "exFAT FAT chain ended after {actual_clusters} clusters; stream needs {expected_clusters}"
            ),
            Self::ChainContinuesPastData { next_cluster } => write!(
                formatter,
                "exFAT FAT chain continues to cluster {next_cluster} past the declared stream allocation"
            ),
            Self::FreeClusterInChain { cluster } => {
                write!(
                    formatter,
                    "exFAT stream reaches free FAT entry at cluster {cluster}"
                )
            }
            Self::BadClusterInChain { cluster } => {
                write!(
                    formatter,
                    "exFAT stream reaches bad FAT entry at cluster {cluster}"
                )
            }
            Self::ArithmeticOverflow { calculation } => {
                write!(formatter, "overflow while calculating {calculation}")
            }
            Self::AllocationFailed => {
                formatter.write_str("could not allocate caller-bounded exFAT stream storage")
            }
            Self::Allocation(error) => write!(formatter, "invalid exFAT allocation: {error}"),
            Self::Image(error) => write!(formatter, "image read failed: {error}"),
        }
    }
}

impl std::error::Error for ExfatImageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Allocation(error) => Some(error),
            Self::Image(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ImageError> for ExfatImageError {
    fn from(error: ImageError) -> Self {
        Self::Image(error)
    }
}

impl From<ExfatAllocationError> for ExfatImageError {
    fn from(error: ExfatAllocationError) -> Self {
        Self::Allocation(error)
    }
}

/// Reads a stream with a known logical `data_length` from a regular image.
///
/// When `no_fat_chain` is true, the allocation is contiguous beginning at `first_cluster` and FAT
/// entries are not consulted. Otherwise the active FAT is followed and must describe exactly the
/// number of clusters needed for the declared length.
///
/// # Errors
///
/// Returns [`ExfatImageError`] for invalid limits/length/cluster geometry, cap violations,
/// malformed chains, overflow, allocation failure, or bounded image-read failure.
pub fn read_stream(
    image: &ImageFile,
    geometry: &ExfatBootSector,
    first_cluster: u32,
    data_length: u64,
    no_fat_chain: bool,
    limits: StreamReadLimits,
) -> Result<ExfatStream, ExfatImageError> {
    read_stream_from_fat(
        image,
        geometry,
        FatIndex::active(geometry),
        first_cluster,
        data_length,
        no_fat_chain,
        limits,
    )
}

/// Reads a stream using an explicitly selected FAT for linked allocation.
///
/// The selector is still validated for contiguous and empty streams so callers cannot silently
/// associate metadata with a FAT which does not exist on the volume.
///
/// # Errors
///
/// Returns [`ExfatImageError`] for an unavailable FAT, invalid limits/length/cluster geometry,
/// cap violations, malformed chains, overflow, allocation failure, or bounded image-read failure.
pub fn read_stream_from_fat(
    image: &ImageFile,
    geometry: &ExfatBootSector,
    fat: FatIndex,
    first_cluster: u32,
    data_length: u64,
    no_fat_chain: bool,
    limits: StreamReadLimits,
) -> Result<ExfatStream, ExfatImageError> {
    validate_limits(limits)?;
    validate_fat_index(geometry, fat)?;
    if data_length == 0 {
        if first_cluster != 0 {
            return Err(ExfatImageError::InvalidDataLength {
                length: data_length,
            });
        }
        return Ok(ExfatStream {
            bytes: Vec::new(),
            clusters: Vec::new(),
            allocation_bytes: 0,
            contiguous: no_fat_chain,
        });
    }
    enforce_byte_limit(data_length, limits.max_bytes)?;
    let cluster_bytes = u64::from(geometry.bytes_per_cluster);
    let needed_clusters = data_length.div_ceil(cluster_bytes);
    let needed_usize =
        usize::try_from(needed_clusters).map_err(|_| ExfatImageError::ArithmeticOverflow {
            calculation: "stream cluster count conversion",
        })?;
    if needed_usize > limits.max_clusters {
        return Err(ExfatImageError::ClusterLimitExceeded {
            maximum: limits.max_clusters,
        });
    }

    let clusters = if no_fat_chain {
        contiguous_clusters(geometry, first_cluster, needed_usize)?
    } else {
        exact_fat_chain(
            image,
            geometry,
            fat,
            first_cluster,
            needed_usize,
            limits.max_clusters,
        )?
    };
    let allocation_bytes =
        needed_clusters
            .checked_mul(cluster_bytes)
            .ok_or(ExfatImageError::ArithmeticOverflow {
                calculation: "stream allocation length",
            })?;
    let bytes = read_clusters(image, geometry, &clusters, data_length, limits.max_bytes)?;

    Ok(ExfatStream {
        bytes,
        clusters,
        allocation_bytes,
        contiguous: no_fat_chain,
    })
}

/// Reads a FAT-linked stream whose length is defined by its chain, such as the exFAT root.
///
/// # Errors
///
/// Returns [`ExfatImageError`] for invalid limits/cluster geometry, malformed or cyclic FAT
/// chains, cap violations, overflow, allocation failure, or bounded image-read failure.
pub fn read_chain_to_end(
    image: &ImageFile,
    geometry: &ExfatBootSector,
    first_cluster: u32,
    limits: StreamReadLimits,
) -> Result<ExfatStream, ExfatImageError> {
    read_chain_to_end_from_fat(
        image,
        geometry,
        FatIndex::active(geometry),
        first_cluster,
        limits,
    )
}

/// Reads a FAT-linked stream to end-of-chain through an explicitly selected FAT.
///
/// # Errors
///
/// Returns [`ExfatImageError`] for an unavailable FAT, invalid limits/cluster geometry,
/// malformed or cyclic chains, cap violations, overflow, allocation failure, or image failure.
pub fn read_chain_to_end_from_fat(
    image: &ImageFile,
    geometry: &ExfatBootSector,
    fat: FatIndex,
    first_cluster: u32,
    limits: StreamReadLimits,
) -> Result<ExfatStream, ExfatImageError> {
    validate_limits(limits)?;
    validate_fat_index(geometry, fat)?;
    let clusters = fat_chain_to_end(image, geometry, fat, first_cluster, limits.max_clusters)?;
    let cluster_bytes = u64::from(geometry.bytes_per_cluster);
    let data_length = u64::try_from(clusters.len())
        .map_err(|_| ExfatImageError::ArithmeticOverflow {
            calculation: "chain cluster count conversion",
        })?
        .checked_mul(cluster_bytes)
        .ok_or(ExfatImageError::ArithmeticOverflow {
            calculation: "chain byte length",
        })?;
    enforce_byte_limit(data_length, limits.max_bytes)?;
    let bytes = read_clusters(image, geometry, &clusters, data_length, limits.max_bytes)?;
    Ok(ExfatStream {
        bytes,
        clusters,
        allocation_bytes: data_length,
        contiguous: false,
    })
}

const fn validate_fat_index(
    geometry: &ExfatBootSector,
    fat: FatIndex,
) -> Result<(), ExfatImageError> {
    if fat.number() < geometry.number_of_fats {
        Ok(())
    } else {
        Err(ExfatImageError::InvalidFatIndex {
            requested: fat.number(),
            available: geometry.number_of_fats,
        })
    }
}

const fn validate_limits(limits: StreamReadLimits) -> Result<(), ExfatImageError> {
    if limits.max_bytes == 0 || limits.max_clusters == 0 {
        Err(ExfatImageError::InvalidLimits)
    } else {
        Ok(())
    }
}

fn enforce_byte_limit(length: u64, maximum: usize) -> Result<(), ExfatImageError> {
    if length > u64::try_from(maximum).unwrap_or(u64::MAX) {
        Err(ExfatImageError::StreamTooLarge { length, maximum })
    } else {
        Ok(())
    }
}

fn contiguous_clusters(
    geometry: &ExfatBootSector,
    first_cluster: u32,
    count: usize,
) -> Result<Vec<u32>, ExfatImageError> {
    cluster_byte_offset(geometry, first_cluster)?;
    let count_u32 = u32::try_from(count).map_err(|_| ExfatImageError::ArithmeticOverflow {
        calculation: "contiguous cluster count conversion",
    })?;
    let end = first_cluster
        .checked_add(count_u32)
        .ok_or(ExfatImageError::ArithmeticOverflow {
            calculation: "contiguous cluster range",
        })?;
    let heap_end =
        2_u32
            .checked_add(geometry.cluster_count)
            .ok_or(ExfatImageError::ArithmeticOverflow {
                calculation: "cluster heap end",
            })?;
    if end > heap_end {
        return Err(ExfatAllocationError::InvalidCluster {
            cluster: end.saturating_sub(1),
        }
        .into());
    }
    let mut clusters = Vec::new();
    clusters
        .try_reserve_exact(count)
        .map_err(|_| ExfatImageError::AllocationFailed)?;
    clusters.extend(first_cluster..end);
    Ok(clusters)
}

fn exact_fat_chain(
    image: &ImageFile,
    geometry: &ExfatBootSector,
    fat: FatIndex,
    first_cluster: u32,
    needed: usize,
    maximum: usize,
) -> Result<Vec<u32>, ExfatImageError> {
    let mut clusters = Vec::new();
    clusters
        .try_reserve_exact(needed)
        .map_err(|_| ExfatImageError::AllocationFailed)?;
    let mut seen = bounded_seen_set(needed)?;
    let mut current = first_cluster;
    for index in 0..needed {
        validate_new_cluster(geometry, current, &mut seen)?;
        clusters.push(current);
        match read_fat_entry(image, geometry, fat, current)? {
            FatEntry::Next(next) if index + 1 < needed => current = next,
            FatEntry::Next(next) => {
                return Err(ExfatImageError::ChainContinuesPastData { next_cluster: next });
            }
            FatEntry::EndOfChain if index + 1 == needed => return Ok(clusters),
            FatEntry::EndOfChain => {
                return Err(ExfatImageError::ChainEndedEarly {
                    expected_clusters: u64::try_from(needed).unwrap_or(u64::MAX),
                    actual_clusters: clusters.len(),
                });
            }
            FatEntry::Free => return Err(ExfatImageError::FreeClusterInChain { cluster: current }),
            FatEntry::Bad => return Err(ExfatImageError::BadClusterInChain { cluster: current }),
        }
    }
    Err(ExfatImageError::ClusterLimitExceeded { maximum })
}

fn fat_chain_to_end(
    image: &ImageFile,
    geometry: &ExfatBootSector,
    fat: FatIndex,
    first_cluster: u32,
    maximum: usize,
) -> Result<Vec<u32>, ExfatImageError> {
    let mut clusters = Vec::new();
    clusters
        .try_reserve(maximum.min(1024))
        .map_err(|_| ExfatImageError::AllocationFailed)?;
    let mut seen = bounded_seen_set(maximum)?;
    let mut current = first_cluster;
    loop {
        if clusters.len() >= maximum {
            return Err(ExfatImageError::ClusterLimitExceeded { maximum });
        }
        validate_new_cluster(geometry, current, &mut seen)?;
        clusters.push(current);
        match read_fat_entry(image, geometry, fat, current)? {
            FatEntry::Next(next) => current = next,
            FatEntry::EndOfChain => return Ok(clusters),
            FatEntry::Free => return Err(ExfatImageError::FreeClusterInChain { cluster: current }),
            FatEntry::Bad => return Err(ExfatImageError::BadClusterInChain { cluster: current }),
        }
    }
}

fn bounded_seen_set(maximum: usize) -> Result<HashSet<u32>, ExfatImageError> {
    let mut seen = HashSet::new();
    seen.try_reserve(maximum)
        .map_err(|_| ExfatImageError::AllocationFailed)?;
    Ok(seen)
}

fn validate_new_cluster(
    geometry: &ExfatBootSector,
    cluster: u32,
    seen: &mut HashSet<u32>,
) -> Result<(), ExfatImageError> {
    cluster_byte_offset(geometry, cluster)?;
    if !seen.insert(cluster) {
        return Err(ExfatImageError::ChainCycle { cluster });
    }
    Ok(())
}

fn read_fat_entry(
    image: &ImageFile,
    geometry: &ExfatBootSector,
    fat: FatIndex,
    cluster: u32,
) -> Result<FatEntry, ExfatImageError> {
    let fat_sector = u64::from(geometry.fat_offset_sectors)
        .checked_add(
            u64::from(fat.number())
                .checked_mul(u64::from(geometry.fat_length_sectors))
                .ok_or(ExfatImageError::ArithmeticOverflow {
                    calculation: "selected FAT sector offset",
                })?,
        )
        .ok_or(ExfatImageError::ArithmeticOverflow {
            calculation: "selected FAT sector",
        })?;
    let offset = fat_sector
        .checked_mul(u64::from(geometry.bytes_per_sector))
        .and_then(|base| base.checked_add(u64::from(cluster) * 4))
        .ok_or(ExfatImageError::ArithmeticOverflow {
            calculation: "FAT entry image offset",
        })?;
    let bytes = image.read_exact_at(offset, 4)?;
    let value = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    match value {
        0 => Ok(FatEntry::Free),
        0xffff_fff7 => Ok(FatEntry::Bad),
        u32::MAX => Ok(FatEntry::EndOfChain),
        next if cluster_byte_offset(geometry, next).is_ok() => Ok(FatEntry::Next(next)),
        _ => Err(ExfatAllocationError::InvalidFatValue { cluster, value }.into()),
    }
}

fn read_clusters(
    image: &ImageFile,
    geometry: &ExfatBootSector,
    clusters: &[u32],
    data_length: u64,
    maximum: usize,
) -> Result<Vec<u8>, ExfatImageError> {
    enforce_byte_limit(data_length, maximum)?;
    let length = usize::try_from(data_length).map_err(|_| ExfatImageError::ArithmeticOverflow {
        calculation: "stream length conversion",
    })?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| ExfatImageError::AllocationFailed)?;
    let mut remaining = length;
    for &cluster in clusters {
        let mut offset = cluster_byte_offset(geometry, cluster)?;
        let mut cluster_remaining =
            remaining.min(usize::try_from(geometry.bytes_per_cluster).map_err(|_| {
                ExfatImageError::ArithmeticOverflow {
                    calculation: "cluster byte length conversion",
                }
            })?);
        while cluster_remaining > 0 {
            let chunk_length = cluster_remaining.min(image.max_read_bytes());
            let chunk = image.read_exact_at(offset, chunk_length)?;
            bytes.extend_from_slice(&chunk);
            offset = offset
                .checked_add(u64::try_from(chunk_length).map_err(|_| {
                    ExfatImageError::ArithmeticOverflow {
                        calculation: "cluster chunk offset conversion",
                    }
                })?)
                .ok_or(ExfatImageError::ArithmeticOverflow {
                    calculation: "cluster chunk offset",
                })?;
            cluster_remaining -= chunk_length;
            remaining -= chunk_length;
        }
        if remaining == 0 {
            break;
        }
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::fs::exfat::parse_boot_sector;

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TempImage(PathBuf);

    impl TempImage {
        fn write(bytes: &[u8]) -> Self {
            let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "starconverter-exfat-stream-{}-{id}.img",
                std::process::id()
            ));
            fs::write(&path, bytes).unwrap();
            Self(path)
        }
    }

    impl Drop for TempImage {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    fn fixture() -> (Vec<u8>, ExfatBootSector) {
        let mut image = vec![0_u8; 2048 * 512];
        image[0..3].copy_from_slice(&[0xeb, 0x76, 0x90]);
        image[3..11].copy_from_slice(b"EXFAT   ");
        image[72..80].copy_from_slice(&2048_u64.to_le_bytes());
        image[80..84].copy_from_slice(&24_u32.to_le_bytes());
        image[84..88].copy_from_slice(&16_u32.to_le_bytes());
        image[88..92].copy_from_slice(&40_u32.to_le_bytes());
        image[92..96].copy_from_slice(&2008_u32.to_le_bytes());
        image[96..100].copy_from_slice(&2_u32.to_le_bytes());
        image[104..106].copy_from_slice(&0x0100_u16.to_le_bytes());
        image[108] = 9;
        image[110] = 1;
        image[112] = 0xff;
        image[510..512].copy_from_slice(&0xaa55_u16.to_le_bytes());
        let boot = parse_boot_sector(&image[..512]).unwrap();
        (image, boot)
    }

    fn set_fat(image: &mut [u8], cluster: u32, value: u32) {
        set_fat_at(image, 0, cluster, value);
    }

    fn set_fat_at(image: &mut [u8], index: usize, cluster: u32, value: u32) {
        let offset = (24 + index * 16) * 512 + usize::try_from(cluster).unwrap() * 4;
        image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn cluster_offset(cluster: u32) -> usize {
        40 * 512 + usize::try_from(cluster - 2).unwrap() * 512
    }

    const fn limits() -> StreamReadLimits {
        StreamReadLimits {
            max_bytes: 4096,
            max_clusters: 8,
        }
    }

    #[test]
    fn reads_fragmented_and_contiguous_streams() {
        let (mut bytes, boot) = fixture();
        set_fat(&mut bytes, 2, 5);
        set_fat(&mut bytes, 5, u32::MAX);
        bytes[cluster_offset(2)..cluster_offset(2) + 512].fill(b'A');
        bytes[cluster_offset(5)..cluster_offset(5) + 512].fill(b'B');
        bytes[cluster_offset(8)..cluster_offset(8) + 512].fill(b'C');
        bytes[cluster_offset(9)..cluster_offset(9) + 512].fill(b'D');
        let temp = TempImage::write(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();

        let fragmented = read_stream(&image, &boot, 2, 700, false, limits()).unwrap();
        assert_eq!(&fragmented.bytes[..512], &[b'A'; 512]);
        assert_eq!(&fragmented.bytes[512..], &[b'B'; 188]);
        assert_eq!(fragmented.clusters, vec![2, 5]);

        let contiguous = read_stream(&image, &boot, 8, 700, true, limits()).unwrap();
        assert_eq!(&contiguous.bytes[..512], &[b'C'; 512]);
        assert_eq!(&contiguous.bytes[512..], &[b'D'; 188]);
    }

    #[test]
    fn reads_chain_to_end_and_rejects_cycles() {
        let (mut bytes, boot) = fixture();
        set_fat(&mut bytes, 2, 3);
        set_fat(&mut bytes, 3, u32::MAX);
        let temp = TempImage::write(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();
        let stream = read_chain_to_end(&image, &boot, 2, limits()).unwrap();
        assert_eq!(stream.bytes.len(), 1024);

        drop(image);
        drop(temp);
        set_fat(&mut bytes, 3, 2);
        let cyclic = TempImage::write(&bytes);
        let image = ImageFile::open(&cyclic.0).unwrap();
        assert!(matches!(
            read_chain_to_end(&image, &boot, 2, limits()),
            Err(ExfatImageError::ChainCycle { cluster: 2 })
        ));
    }

    #[test]
    fn requires_exact_fat_allocation_length() {
        let (mut bytes, boot) = fixture();
        set_fat(&mut bytes, 2, u32::MAX);
        let temp = TempImage::write(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();
        assert!(matches!(
            read_stream(&image, &boot, 2, 513, false, limits()),
            Err(ExfatImageError::ChainEndedEarly { .. })
        ));

        drop(image);
        drop(temp);
        set_fat(&mut bytes, 2, 3);
        let temp = TempImage::write(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();
        assert!(matches!(
            read_stream(&image, &boot, 2, 1, false, limits()),
            Err(ExfatImageError::ChainContinuesPastData { next_cluster: 3 })
        ));
    }

    #[test]
    fn enforces_caps_and_empty_stream_rules() {
        let (bytes, boot) = fixture();
        let temp = TempImage::write(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();
        assert!(matches!(
            read_stream(&image, &boot, 2, 4097, true, limits()),
            Err(ExfatImageError::StreamTooLarge { .. })
        ));
        assert!(matches!(
            read_stream(
                &image,
                &boot,
                2,
                1,
                true,
                StreamReadLimits {
                    max_bytes: 1,
                    max_clusters: 0
                }
            ),
            Err(ExfatImageError::InvalidLimits)
        ));
        assert!(read_stream(&image, &boot, 0, 0, false, limits()).is_ok());
        assert!(matches!(
            read_stream(&image, &boot, 2, 0, false, limits()),
            Err(ExfatImageError::InvalidDataLength { .. })
        ));
    }

    #[test]
    fn explicitly_selects_corresponding_fat_on_two_fat_volume() {
        let mut bytes = vec![0_u8; 2048 * 512];
        bytes[0..3].copy_from_slice(&[0xeb, 0x76, 0x90]);
        bytes[3..11].copy_from_slice(b"EXFAT   ");
        bytes[72..80].copy_from_slice(&2048_u64.to_le_bytes());
        bytes[80..84].copy_from_slice(&24_u32.to_le_bytes());
        bytes[84..88].copy_from_slice(&16_u32.to_le_bytes());
        bytes[88..92].copy_from_slice(&56_u32.to_le_bytes());
        bytes[92..96].copy_from_slice(&1992_u32.to_le_bytes());
        bytes[96..100].copy_from_slice(&2_u32.to_le_bytes());
        bytes[104..106].copy_from_slice(&0x0100_u16.to_le_bytes());
        bytes[106..108].copy_from_slice(&1_u16.to_le_bytes());
        bytes[108] = 9;
        bytes[110] = 2;
        bytes[112] = 0xff;
        bytes[510..512].copy_from_slice(&0xaa55_u16.to_le_bytes());
        let boot = parse_boot_sector(&bytes[..512]).unwrap();

        set_fat_at(&mut bytes, 0, 2, 3);
        set_fat_at(&mut bytes, 0, 3, u32::MAX);
        set_fat_at(&mut bytes, 1, 2, 5);
        set_fat_at(&mut bytes, 1, 5, u32::MAX);
        let heap_cluster = |cluster: u32| 56 * 512 + usize::try_from(cluster - 2).unwrap() * 512;
        bytes[heap_cluster(2)..heap_cluster(2) + 512].fill(b'A');
        bytes[heap_cluster(3)..heap_cluster(3) + 512].fill(b'B');
        bytes[heap_cluster(5)..heap_cluster(5) + 512].fill(b'C');
        let temp = TempImage::write(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();

        let first =
            read_stream_from_fat(&image, &boot, FatIndex::First, 2, 700, false, limits()).unwrap();
        let second =
            read_stream_from_fat(&image, &boot, FatIndex::Second, 2, 700, false, limits()).unwrap();
        assert_eq!(first.clusters, vec![2, 3]);
        assert_eq!(second.clusters, vec![2, 5]);
        assert_eq!(&first.bytes[512..], &[b'B'; 188]);
        assert_eq!(&second.bytes[512..], &[b'C'; 188]);
        assert_eq!(
            read_stream(&image, &boot, 2, 700, false, limits())
                .unwrap()
                .clusters,
            vec![2, 5]
        );
    }

    #[test]
    fn rejects_unavailable_explicit_fat_even_for_contiguous_stream() {
        let (bytes, boot) = fixture();
        let temp = TempImage::write(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();
        assert!(matches!(
            read_stream_from_fat(&image, &boot, FatIndex::Second, 2, 1, true, limits()),
            Err(ExfatImageError::InvalidFatIndex {
                requested: 1,
                available: 1
            })
        ));
    }
}
