//! Bounded discovery of exFAT root metadata and proven free space.

use std::fmt;

use super::exfat::ExfatBootSector;
use super::exfat_allocation::{
    AllocationSummary, ExfatAllocationError, bitmap_cluster_is_allocated,
    summarize_allocation_bitmap,
};
use super::exfat_directory::{
    AllocationBitmapEntry, DirectoryContext, DirectoryError, DirectoryRecord, DirectorySummary,
    UpcaseTableEntry, parse_directory,
};
use super::exfat_image::{ExfatImageError, StreamReadLimits, read_chain_to_end, read_stream};
use super::exfat_upcase::{UpcaseError, UpcaseLimits, UpcaseTable};
use crate::image::ImageFile;

/// Explicit caps for read-only root discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExfatDiscoveryLimits {
    pub root_stream: StreamReadLimits,
    pub system_stream: StreamReadLimits,
    pub max_directory_entries: usize,
    pub max_secondary_entries: u8,
}

/// Root metadata and free-space evidence validated from the active Allocation Bitmap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExfatRootDiscovery {
    pub directory: DirectorySummary,
    pub active_bitmap: AllocationBitmapEntry,
    pub upcase_table: UpcaseTableEntry,
    pub upcase_mappings: UpcaseTable,
    pub allocation: AllocationSummary,
    pub free_bytes: u64,
    pub root_clusters: Vec<u32>,
    pub bitmap_clusters: Vec<u32>,
    pub upcase_clusters: Vec<u32>,
}

/// Failure to establish trustworthy exFAT root/allocation evidence.
#[derive(Debug)]
pub enum ExfatDiscoveryError {
    InvalidLimits,
    RootStream(ExfatImageError),
    RootDirectory(DirectoryError),
    MissingActiveBitmap { identifier: u8 },
    MissingUpcaseTable,
    BitmapStream(ExfatImageError),
    UpcaseStream(ExfatImageError),
    Upcase(UpcaseError),
    Allocation(ExfatAllocationError),
    MetadataClusterMarkedFree { cluster: u32, role: &'static str },
    PercentInUseMismatch { stored: u8, calculated: u8 },
    ArithmeticOverflow { calculation: &'static str },
}

impl fmt::Display for ExfatDiscoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("exFAT discovery limits must be non-zero"),
            Self::RootStream(error) => {
                write!(formatter, "could not read exFAT root chain: {error}")
            }
            Self::RootDirectory(error) => {
                write!(formatter, "invalid exFAT root directory: {error}")
            }
            Self::MissingActiveBitmap { identifier } => write!(
                formatter,
                "exFAT root does not describe active Allocation Bitmap {identifier}"
            ),
            Self::MissingUpcaseTable => {
                formatter.write_str("exFAT root does not describe an Up-case Table")
            }
            Self::BitmapStream(error) => {
                write!(
                    formatter,
                    "could not read active exFAT Allocation Bitmap: {error}"
                )
            }
            Self::UpcaseStream(error) => {
                write!(formatter, "could not read exFAT Up-case Table: {error}")
            }
            Self::Upcase(error) => write!(formatter, "invalid exFAT Up-case Table: {error}"),
            Self::Allocation(error) => {
                write!(formatter, "invalid exFAT allocation evidence: {error}")
            }
            Self::MetadataClusterMarkedFree { cluster, role } => write!(
                formatter,
                "exFAT Allocation Bitmap marks {role} cluster {cluster} free"
            ),
            Self::PercentInUseMismatch { stored, calculated } => write!(
                formatter,
                "exFAT PercentInUse is {stored}, but the active bitmap calculates {calculated}"
            ),
            Self::ArithmeticOverflow { calculation } => {
                write!(formatter, "overflow while calculating {calculation}")
            }
        }
    }
}

impl std::error::Error for ExfatDiscoveryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::RootStream(error) | Self::BitmapStream(error) | Self::UpcaseStream(error) => {
                Some(error)
            }
            Self::RootDirectory(error) => Some(error),
            Self::Allocation(error) => Some(error),
            Self::Upcase(error) => Some(error),
            _ => None,
        }
    }
}

/// Discovers and validates the root directory and active Allocation Bitmap.
///
/// # Errors
///
/// Returns [`ExfatDiscoveryError`] if resource limits are invalid, root/system streams cannot be
/// read within their caps, root entries are malformed or incomplete, allocation evidence is
/// inconsistent, or free-space arithmetic overflows.
pub fn discover_root(
    image: &ImageFile,
    boot: &ExfatBootSector,
    limits: ExfatDiscoveryLimits,
) -> Result<ExfatRootDiscovery, ExfatDiscoveryError> {
    if limits.max_directory_entries == 0 || limits.max_secondary_entries == 0 {
        return Err(ExfatDiscoveryError::InvalidLimits);
    }
    let root = read_chain_to_end(image, boot, boot.root_directory_cluster, limits.root_stream)
        .map_err(ExfatDiscoveryError::RootStream)?;
    let active_identifier = u8::try_from(boot.volume_flags & 1).map_err(|_| {
        ExfatDiscoveryError::ArithmeticOverflow {
            calculation: "active bitmap identifier",
        }
    })?;
    let mut active_bitmap = None;
    let mut upcase_table = None;
    let directory = parse_directory(
        &root.bytes,
        DirectoryContext {
            cluster_count: boot.cluster_count,
            bytes_per_cluster: boot.bytes_per_cluster,
            number_of_fats: boot.number_of_fats,
            is_root: true,
            max_entries: limits.max_directory_entries,
            max_secondary_entries: limits.max_secondary_entries,
        },
        |record| match record {
            DirectoryRecord::AllocationBitmap(entry)
                if entry.bitmap_identifier == active_identifier =>
            {
                active_bitmap = Some(entry);
            }
            DirectoryRecord::UpcaseTable(entry) => upcase_table = Some(entry),
            _ => {}
        },
    )
    .map_err(ExfatDiscoveryError::RootDirectory)?;
    let active_bitmap = active_bitmap.ok_or(ExfatDiscoveryError::MissingActiveBitmap {
        identifier: active_identifier,
    })?;
    let upcase_table = upcase_table.ok_or(ExfatDiscoveryError::MissingUpcaseTable)?;
    let bitmap = read_stream(
        image,
        boot,
        active_bitmap.first_cluster,
        active_bitmap.data_length,
        false,
        limits.system_stream,
    )
    .map_err(ExfatDiscoveryError::BitmapStream)?;
    let allocation = summarize_allocation_bitmap(&bitmap.bytes, boot)
        .map_err(ExfatDiscoveryError::Allocation)?;
    let upcase = read_stream(
        image,
        boot,
        upcase_table.first_cluster,
        upcase_table.data_length,
        false,
        limits.system_stream,
    )
    .map_err(ExfatDiscoveryError::UpcaseStream)?;
    let upcase_mappings = UpcaseTable::parse(
        &upcase.bytes,
        upcase_table.table_checksum,
        UpcaseLimits::COMPLETE_TABLE,
    )
    .map_err(ExfatDiscoveryError::Upcase)?;

    validate_metadata_allocated(&bitmap.bytes, boot, &root.clusters, "root directory")?;
    validate_metadata_allocated(&bitmap.bytes, boot, &bitmap.clusters, "Allocation Bitmap")?;
    validate_metadata_allocated(&bitmap.bytes, boot, &upcase.clusters, "Up-case Table")?;

    validate_percent_in_use(boot, allocation)?;
    let free_bytes = allocation
        .free_clusters
        .checked_mul(u64::from(boot.bytes_per_cluster))
        .ok_or(ExfatDiscoveryError::ArithmeticOverflow {
            calculation: "free byte count",
        })?;

    Ok(ExfatRootDiscovery {
        directory,
        active_bitmap,
        upcase_table,
        upcase_mappings,
        allocation,
        free_bytes,
        root_clusters: root.clusters,
        bitmap_clusters: bitmap.clusters,
        upcase_clusters: upcase.clusters,
    })
}

fn validate_percent_in_use(
    boot: &ExfatBootSector,
    allocation: AllocationSummary,
) -> Result<(), ExfatDiscoveryError> {
    let cluster_count = u64::from(boot.cluster_count);
    let numerator = allocation.allocated_clusters.checked_mul(100).ok_or(
        ExfatDiscoveryError::ArithmeticOverflow {
            calculation: "allocated-cluster percentage numerator",
        },
    )?;
    let calculated = u8::try_from(numerator / cluster_count).map_err(|_| {
        ExfatDiscoveryError::ArithmeticOverflow {
            calculation: "allocated-cluster percentage conversion",
        }
    })?;
    // Microsoft exFAT section 3.1.18 requires rounding down. fuse-exfat 1.3.0 and 1.4.0
    // instead persist the exact nearest-integer formula below when unmounting. The active
    // Allocation Bitmap remains authoritative, so accept only those two independently derived
    // representations; every other stored value remains a hard failure.
    let legacy_nearest = u8::try_from(
        numerator.checked_add(cluster_count / 2).ok_or(
            ExfatDiscoveryError::ArithmeticOverflow {
                calculation: "legacy allocated-cluster percentage rounding",
            },
        )? / cluster_count,
    )
    .map_err(|_| ExfatDiscoveryError::ArithmeticOverflow {
        calculation: "legacy allocated-cluster percentage conversion",
    })?;
    if let Some(stored) = boot.percent_in_use {
        if stored != calculated && stored != legacy_nearest {
            return Err(ExfatDiscoveryError::PercentInUseMismatch { stored, calculated });
        }
    }
    Ok(())
}

fn validate_metadata_allocated(
    bitmap: &[u8],
    boot: &ExfatBootSector,
    clusters: &[u32],
    role: &'static str,
) -> Result<(), ExfatDiscoveryError> {
    for &cluster in clusters {
        let allocated = bitmap_cluster_is_allocated(bitmap, boot, cluster)
            .map_err(ExfatDiscoveryError::Allocation)?;
        if !allocated {
            return Err(ExfatDiscoveryError::MetadataClusterMarkedFree { cluster, role });
        }
    }
    Ok(())
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
                "starconverter-exfat-discovery-{}-{id}.img",
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

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn encoded_upcase() -> Vec<u8> {
        let mut encoded = Vec::new();
        for code_unit in 0_u16..128 {
            let mapping = if (u16::from(b'a')..=u16::from(b'z')).contains(&code_unit) {
                code_unit - 0x20
            } else {
                code_unit
            };
            encoded.extend_from_slice(&mapping.to_le_bytes());
        }
        encoded.extend_from_slice(&0xffff_u16.to_le_bytes());
        encoded.extend_from_slice(&65_408_u16.to_le_bytes());
        encoded
    }

    fn fixture() -> (Vec<u8>, ExfatBootSector) {
        let mut image = vec![0_u8; 2048 * 512];
        image[0..3].copy_from_slice(&[0xeb, 0x76, 0x90]);
        image[3..11].copy_from_slice(b"EXFAT   ");
        put_u64(&mut image, 72, 2048);
        put_u32(&mut image, 80, 24);
        put_u32(&mut image, 84, 16);
        put_u32(&mut image, 88, 40);
        put_u32(&mut image, 92, 2008);
        put_u32(&mut image, 96, 2);
        image[104..106].copy_from_slice(&0x0100_u16.to_le_bytes());
        image[108] = 9;
        image[110] = 1;
        image[112] = 0xff;
        image[510..512].copy_from_slice(&0xaa55_u16.to_le_bytes());
        let boot = parse_boot_sector(&image[..512]).unwrap();

        for cluster in [2_u32, 3, 4] {
            let fat = 24 * 512 + usize::try_from(cluster).unwrap() * 4;
            put_u32(&mut image, fat, u32::MAX);
        }
        let root = 40 * 512;
        image[root] = 0x81;
        put_u32(&mut image, root + 20, 3);
        put_u64(&mut image, root + 24, 251);
        image[root + 32] = 0x82;
        let upcase = encoded_upcase();
        put_u32(
            &mut image,
            root + 36,
            super::super::exfat_upcase::table_checksum(&upcase),
        );
        put_u32(&mut image, root + 52, 4);
        put_u64(&mut image, root + 56, u64::try_from(upcase.len()).unwrap());
        let bitmap = 41 * 512;
        image[bitmap] = 0b0000_0111;
        let upcase_offset = 42 * 512;
        image[upcase_offset..upcase_offset + upcase.len()].copy_from_slice(&upcase);
        (image, boot)
    }

    const fn limits() -> ExfatDiscoveryLimits {
        ExfatDiscoveryLimits {
            root_stream: StreamReadLimits {
                max_bytes: 4096,
                max_clusters: 8,
            },
            system_stream: StreamReadLimits {
                max_bytes: 4096,
                max_clusters: 8,
            },
            max_directory_entries: 128,
            max_secondary_entries: 32,
        }
    }

    #[test]
    fn discovers_root_and_proves_free_space() {
        let (bytes, boot) = fixture();
        let temp = TempImage::write(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();
        let discovery = discover_root(&image, &boot, limits()).unwrap();

        assert_eq!(discovery.allocation.allocated_clusters, 3);
        assert_eq!(discovery.allocation.free_clusters, 2005);
        assert_eq!(discovery.free_bytes, 2005 * 512);
        assert_eq!(discovery.root_clusters, vec![2]);
        assert_eq!(discovery.bitmap_clusters, vec![3]);
        assert_eq!(discovery.upcase_clusters, vec![4]);
        assert_eq!(
            discovery.upcase_mappings.map(u16::from(b'a')),
            u16::from(b'A')
        );
    }

    #[test]
    fn rejects_free_metadata_and_percent_mismatch() {
        let (mut bytes, boot) = fixture();
        bytes[41 * 512] &= !0b0000_0100;
        let temp = TempImage::write(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();
        assert!(matches!(
            discover_root(&image, &boot, limits()),
            Err(ExfatDiscoveryError::MetadataClusterMarkedFree { cluster: 4, .. })
        ));

        drop(image);
        drop(temp);
        let (mut bytes, _) = fixture();
        bytes[112] = 99;
        let boot = parse_boot_sector(&bytes[..512]).unwrap();
        let temp = TempImage::write(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();
        assert!(matches!(
            discover_root(&image, &boot, limits()),
            Err(ExfatDiscoveryError::PercentInUseMismatch { .. })
        ));
    }

    #[test]
    fn accepts_only_the_legacy_fuse_nearest_percent_alternative() {
        let (_, mut boot) = fixture();
        boot.cluster_count = 32_256;
        boot.percent_in_use = Some(32);
        let allocation = AllocationSummary {
            allocated_clusters: 10_254,
            free_clusters: 22_002,
            required_bitmap_bytes: 4_032,
        };

        // 10,254 / 32,256 is 31.789%; Microsoft specifies 31, while fuse-exfat
        // persists 32 using nearest-integer rounding.
        validate_percent_in_use(&boot, allocation).unwrap();

        boot.percent_in_use = Some(33);
        assert!(matches!(
            validate_percent_in_use(&boot, allocation),
            Err(ExfatDiscoveryError::PercentInUseMismatch {
                stored: 33,
                calculated: 31
            })
        ));
    }
}
