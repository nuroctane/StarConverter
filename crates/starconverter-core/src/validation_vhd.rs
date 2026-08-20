//! Pure fixed-VHD construction for validation copies of partition candidates.
//!
//! This module never opens, mounts, attaches, or writes a disk. It wraps caller-owned partition
//! bytes in a deterministic MBR disk image followed by the 512-byte footer defined by Microsoft's
//! [Virtual Hard Disk Image Format Specification 1.0](https://www.microsoft.com/en-us/download/details.aspx?id=23850).
//! Microsoft also publishes the [fixed-footer field layout and file-length rule](https://learn.microsoft.com/en-us/partner-center/marketplace-offers/azure-vm-certification-faq#vhd-specifications),
//! the [MBR components and `0x55AA` marker](https://learn.microsoft.com/en-us/windows/win32/fileio/disk-devices-and-partitions),
//! and the [`0x07` NTFS/exFAT partition type](https://learn.microsoft.com/en-us/windows/win32/api/vds/ns-vds-create_partition_parameters).
//!
//! The wrapper deliberately emits one inactive primary partition. LBA fields are authoritative;
//! legacy CHS fields are derived deterministically from the VHD footer geometry and saturate when
//! the address is not representable. Every size is checked against caller caps before allocation.

#![allow(clippy::module_name_repetitions)]

use core::fmt;

use crate::fs::{exfat, ntfs};

pub const VHD_SECTOR_BYTES: u64 = 512;
pub const VHD_FOOTER_BYTES: usize = 512;
pub const ONE_MIB_PARTITION_ALIGNMENT_SECTORS: u64 = 2048;

const MBR_PARTITION_OFFSET: usize = 446;
const MBR_PARTITION_BYTES: usize = 16;
const MBR_SIGNATURE_OFFSET: usize = 440;
const MBR_END_MARKER_OFFSET: usize = 510;
const VHD_COOKIE: &[u8; 8] = b"conectix";
const VHD_FEATURES_RESERVED: u32 = 2;
const VHD_FORMAT_VERSION_1: u32 = 0x0001_0000;
const VHD_FIXED_DATA_OFFSET: u64 = u64::MAX;
const VHD_DISK_TYPE_FIXED: u32 = 2;
const CREATOR_APPLICATION: &[u8; 4] = b"StCv";
const CREATOR_VERSION: u32 = 0x0001_0000;
const CREATOR_HOST_OS_WINDOWS: &[u8; 4] = b"Wi2k";

/// Caller-controlled deterministic identity and partition placement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedVhdConfig {
    /// Absolute MBR LBA of the copied partition. Must be at least and a multiple of 1 MiB.
    pub partition_offset_sectors: u64,
    /// Four-byte MBR disk signature, serialized little-endian at byte 440.
    pub mbr_disk_signature: u32,
    /// Seconds since 2000-01-01 00:00:00 UTC, already in the VHD timestamp epoch.
    pub footer_timestamp: u32,
    /// Exact 16 on-disk bytes of the VHD unique ID. No ambient UUID source is consulted.
    pub unique_id: [u8; 16],
}

/// Caller-controlled work and output bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedVhdLimits {
    pub max_partition_bytes: u64,
    pub max_virtual_disk_bytes: u64,
    pub max_output_bytes: u64,
}

impl Default for FixedVhdLimits {
    fn default() -> Self {
        // The legacy fixed-VHD format is conventionally bounded below 2 TiB. MBR arithmetic
        // below imposes the tighter exact bound for each concrete image.
        const TWO_TIB: u64 = 2 * 1024 * 1024 * 1024 * 1024;
        Self {
            max_partition_bytes: TWO_TIB,
            max_virtual_disk_bytes: TWO_TIB,
            max_output_bytes: TWO_TIB + VHD_SECTOR_BYTES,
        }
    }
}

/// Footer CHS geometry encoded by the VHD 1.0 algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VhdGeometry {
    pub cylinders: u16,
    pub heads: u8,
    pub sectors_per_track: u8,
}

/// Independently parsed structural evidence from a complete fixed VHD.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatedFixedVhd {
    pub virtual_size_bytes: u64,
    pub partition_offset_sectors: u64,
    pub partition_sector_count: u32,
    pub mbr_disk_signature: u32,
    pub footer_timestamp: u32,
    pub unique_id: [u8; 16],
    pub geometry: VhdGeometry,
}

/// Complete regular-file bytes plus independently parsed evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedVhdImage {
    pub bytes: Vec<u8>,
    pub validated: ValidatedFixedVhd,
}

/// Why fixed-VHD construction or independent validation was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FixedVhdError {
    InvalidLimit {
        field: &'static str,
    },
    EmptyPartition,
    UnalignedPartitionLength {
        bytes: u64,
    },
    UnalignedPartitionOffset {
        sectors: u64,
    },
    PartitionOffsetTooSmall {
        sectors: u64,
    },
    LimitExceeded {
        component: &'static str,
        actual: u64,
        maximum: u64,
    },
    FieldOverflow {
        field: &'static str,
        value: u64,
    },
    ArithmeticOverflow,
    AllocationFailed,
    Truncated {
        actual: usize,
        minimum: usize,
    },
    UnsupportedPartitionBootSector,
    MalformedPartitionBootSector {
        filesystem: &'static str,
    },
    PartitionOffsetMismatch {
        expected_bytes: u64,
        actual_bytes: u64,
    },
    PartitionLengthMismatch {
        expected_bytes: u64,
        actual_bytes: u64,
    },
    InvalidMbr {
        field: &'static str,
    },
    InvalidFooter {
        field: &'static str,
    },
    FooterChecksumMismatch {
        stored: u32,
        computed: u32,
    },
    IdentityMismatch {
        field: &'static str,
    },
}

impl fmt::Display for FixedVhdError {
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit { field } => write!(f, "fixed-VHD limit {field} is zero"),
            Self::EmptyPartition => f.write_str("fixed VHD cannot wrap an empty partition"),
            Self::UnalignedPartitionLength { bytes } => {
                write!(f, "partition length {bytes} is not a multiple of 512 bytes")
            }
            Self::UnalignedPartitionOffset { sectors } => write!(
                f,
                "partition offset {sectors} is not aligned to 2048 sectors (1 MiB)"
            ),
            Self::PartitionOffsetTooSmall { sectors } => write!(
                f,
                "partition offset {sectors} leaves less than the required 1 MiB prefix"
            ),
            Self::LimitExceeded {
                component,
                actual,
                maximum,
            } => write!(f, "{component} size {actual} exceeds limit {maximum}"),
            Self::FieldOverflow { field, value } => {
                write!(f, "{field} value {value} cannot be represented on disk")
            }
            Self::ArithmeticOverflow => f.write_str("fixed-VHD size arithmetic overflow"),
            Self::AllocationFailed => f.write_str("could not allocate bounded fixed-VHD output"),
            Self::Truncated { actual, minimum } => {
                write!(
                    f,
                    "fixed VHD has {actual} bytes, requires at least {minimum}"
                )
            }
            Self::UnsupportedPartitionBootSector => {
                f.write_str("partition is neither a supported NTFS nor exFAT candidate")
            }
            Self::MalformedPartitionBootSector { filesystem } => {
                write!(f, "partition has a malformed {filesystem} boot sector")
            }
            Self::PartitionOffsetMismatch {
                expected_bytes,
                actual_bytes,
            } => write!(
                f,
                "partition boot field describes byte offset {actual_bytes}, MBR requires {expected_bytes}"
            ),
            Self::PartitionLengthMismatch {
                expected_bytes,
                actual_bytes,
            } => write!(
                f,
                "partition boot field describes {actual_bytes} bytes, MBR contains {expected_bytes}"
            ),
            Self::InvalidMbr { field } => write!(f, "invalid fixed-VHD MBR {field}"),
            Self::InvalidFooter { field } => write!(f, "invalid fixed-VHD footer {field}"),
            Self::FooterChecksumMismatch { stored, computed } => write!(
                f,
                "VHD footer checksum {stored:#010x} does not match {computed:#010x}"
            ),
            Self::IdentityMismatch { field } => {
                write!(f, "fixed-VHD caller identity mismatch in {field}")
            }
        }
    }
}

impl std::error::Error for FixedVhdError {}

/// Wraps an exact NTFS or exFAT partition candidate in a fixed VHD regular-file image.
///
/// # Errors
///
/// Refuses malformed filesystem geometry, BPB/MBR offset disagreement, non-sector-aligned input,
/// field overflow, invalid caps, cap overruns, and allocation failure.
pub fn wrap_fixed_vhd(
    partition: &[u8],
    config: FixedVhdConfig,
    limits: FixedVhdLimits,
) -> Result<FixedVhdImage, FixedVhdError> {
    validate_limits(limits)?;
    let partition_bytes =
        u64::try_from(partition.len()).map_err(|_| FixedVhdError::FieldOverflow {
            field: "partition byte length",
            value: u64::MAX,
        })?;
    validate_partition_shape(partition_bytes, config.partition_offset_sectors, limits)?;
    let partition_sectors = partition_bytes / VHD_SECTOR_BYTES;
    u32::try_from(config.partition_offset_sectors).map_err(|_| FixedVhdError::FieldOverflow {
        field: "MBR partition start LBA",
        value: config.partition_offset_sectors,
    })?;
    u32::try_from(partition_sectors).map_err(|_| FixedVhdError::FieldOverflow {
        field: "MBR partition sector count",
        value: partition_sectors,
    })?;
    validate_partition_boot(partition, config.partition_offset_sectors, partition_bytes)?;
    let virtual_sectors = config
        .partition_offset_sectors
        .checked_add(partition_sectors)
        .ok_or(FixedVhdError::ArithmeticOverflow)?;
    let last_partition_lba = virtual_sectors
        .checked_sub(1)
        .ok_or(FixedVhdError::ArithmeticOverflow)?;
    u32::try_from(last_partition_lba).map_err(|_| FixedVhdError::FieldOverflow {
        field: "MBR partition end LBA",
        value: last_partition_lba,
    })?;
    let virtual_size_bytes = virtual_sectors
        .checked_mul(VHD_SECTOR_BYTES)
        .ok_or(FixedVhdError::ArithmeticOverflow)?;
    enforce_limit(
        "virtual disk",
        virtual_size_bytes,
        limits.max_virtual_disk_bytes,
    )?;
    let output_bytes = virtual_size_bytes
        .checked_add(VHD_SECTOR_BYTES)
        .ok_or(FixedVhdError::ArithmeticOverflow)?;
    enforce_limit("VHD output", output_bytes, limits.max_output_bytes)?;
    let output_len = usize::try_from(output_bytes).map_err(|_| FixedVhdError::FieldOverflow {
        field: "host output length",
        value: output_bytes,
    })?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(output_len)
        .map_err(|_| FixedVhdError::AllocationFailed)?;
    bytes.resize(output_len, 0);

    let geometry = footer_geometry(virtual_sectors);
    write_mbr(
        &mut bytes[..VHD_FOOTER_BYTES],
        config,
        partition_sectors,
        geometry,
    )?;
    let partition_offset_bytes = config
        .partition_offset_sectors
        .checked_mul(VHD_SECTOR_BYTES)
        .ok_or(FixedVhdError::ArithmeticOverflow)?;
    let partition_start =
        usize::try_from(partition_offset_bytes).map_err(|_| FixedVhdError::FieldOverflow {
            field: "host partition offset",
            value: partition_offset_bytes,
        })?;
    let partition_end = partition_start
        .checked_add(partition.len())
        .ok_or(FixedVhdError::ArithmeticOverflow)?;
    bytes[partition_start..partition_end].copy_from_slice(partition);
    let footer_start =
        usize::try_from(virtual_size_bytes).map_err(|_| FixedVhdError::FieldOverflow {
            field: "host footer offset",
            value: virtual_size_bytes,
        })?;
    write_footer(
        &mut bytes[footer_start..],
        virtual_size_bytes,
        geometry,
        config,
    );

    let validated = validate_fixed_vhd(&bytes, config, limits)?;
    Ok(FixedVhdImage { bytes, validated })
}

/// Independently parses and validates an exact fixed-VHD image against caller identity.
///
/// # Errors
///
/// Refuses any footer, checksum, MBR, CHS, size, filesystem-BPB, identity, or cap mismatch.
#[allow(clippy::too_many_lines)]
pub fn validate_fixed_vhd(
    image: &[u8],
    expected: FixedVhdConfig,
    limits: FixedVhdLimits,
) -> Result<ValidatedFixedVhd, FixedVhdError> {
    validate_limits(limits)?;
    if image.len() < VHD_FOOTER_BYTES * 2 {
        return Err(FixedVhdError::Truncated {
            actual: image.len(),
            minimum: VHD_FOOTER_BYTES * 2,
        });
    }
    let image_bytes = u64::try_from(image.len()).map_err(|_| FixedVhdError::FieldOverflow {
        field: "host input length",
        value: u64::MAX,
    })?;
    enforce_limit("VHD output", image_bytes, limits.max_output_bytes)?;
    let footer = &image[image.len() - VHD_FOOTER_BYTES..];
    if &footer[0..8] != VHD_COOKIE {
        return Err(FixedVhdError::InvalidFooter { field: "cookie" });
    }
    require_be_u32(footer, 8, VHD_FEATURES_RESERVED, "features")?;
    require_be_u32(footer, 12, VHD_FORMAT_VERSION_1, "format version")?;
    require_be_u64(footer, 16, VHD_FIXED_DATA_OFFSET, "data offset")?;
    if &footer[28..32] != CREATOR_APPLICATION {
        return Err(FixedVhdError::InvalidFooter {
            field: "creator application",
        });
    }
    require_be_u32(footer, 32, CREATOR_VERSION, "creator version")?;
    if &footer[36..40] != CREATOR_HOST_OS_WINDOWS {
        return Err(FixedVhdError::InvalidFooter {
            field: "creator host OS",
        });
    }
    let original_size = be_u64(footer, 40);
    let current_size = be_u64(footer, 48);
    if original_size != current_size {
        return Err(FixedVhdError::InvalidFooter {
            field: "original/current size",
        });
    }
    if current_size % VHD_SECTOR_BYTES != 0 || current_size == 0 {
        return Err(FixedVhdError::InvalidFooter {
            field: "virtual size alignment",
        });
    }
    enforce_limit("virtual disk", current_size, limits.max_virtual_disk_bytes)?;
    let expected_file_bytes = current_size
        .checked_add(VHD_SECTOR_BYTES)
        .ok_or(FixedVhdError::ArithmeticOverflow)?;
    if expected_file_bytes != image_bytes {
        return Err(FixedVhdError::InvalidFooter {
            field: "file length",
        });
    }
    require_be_u32(footer, 60, VHD_DISK_TYPE_FIXED, "disk type")?;
    if footer[84] != 0 || footer[85..].iter().any(|byte| *byte != 0) {
        return Err(FixedVhdError::InvalidFooter {
            field: "saved state or reserved bytes",
        });
    }
    let stored_checksum = be_u32(footer, 64);
    let computed_checksum = footer_checksum(footer);
    if stored_checksum != computed_checksum {
        return Err(FixedVhdError::FooterChecksumMismatch {
            stored: stored_checksum,
            computed: computed_checksum,
        });
    }
    let footer_timestamp = be_u32(footer, 24);
    if footer_timestamp != expected.footer_timestamp {
        return Err(FixedVhdError::IdentityMismatch {
            field: "footer timestamp",
        });
    }
    let mut unique_id = [0_u8; 16];
    unique_id.copy_from_slice(&footer[68..84]);
    if unique_id != expected.unique_id {
        return Err(FixedVhdError::IdentityMismatch { field: "unique ID" });
    }

    let virtual_sectors = current_size / VHD_SECTOR_BYTES;
    let geometry = footer_geometry(virtual_sectors);
    if footer[56..60] != geometry_bytes(geometry) {
        return Err(FixedVhdError::InvalidFooter {
            field: "disk geometry",
        });
    }
    let mbr = &image[..VHD_FOOTER_BYTES];
    let mbr_signature = le_u32(mbr, MBR_SIGNATURE_OFFSET);
    if mbr_signature != expected.mbr_disk_signature {
        return Err(FixedVhdError::IdentityMismatch {
            field: "MBR disk signature",
        });
    }
    if mbr[..MBR_SIGNATURE_OFFSET].iter().any(|byte| *byte != 0)
        || mbr[444..MBR_PARTITION_OFFSET].iter().any(|byte| *byte != 0)
        || mbr[MBR_PARTITION_OFFSET + MBR_PARTITION_BYTES..MBR_END_MARKER_OFFSET]
            .iter()
            .any(|byte| *byte != 0)
    {
        return Err(FixedVhdError::InvalidMbr {
            field: "boot code, reserved bytes, or unused entries",
        });
    }
    if mbr[MBR_END_MARKER_OFFSET..] != [0x55, 0xaa] {
        return Err(FixedVhdError::InvalidMbr {
            field: "end marker",
        });
    }
    let entry = &mbr[MBR_PARTITION_OFFSET..MBR_PARTITION_OFFSET + MBR_PARTITION_BYTES];
    if entry[0] != 0 || entry[4] != 0x07 {
        return Err(FixedVhdError::InvalidMbr {
            field: "partition status or type",
        });
    }
    let partition_offset_sectors = u64::from(le_u32(entry, 8));
    let partition_sector_count = le_u32(entry, 12);
    validate_partition_offset(partition_offset_sectors)?;
    if partition_offset_sectors != expected.partition_offset_sectors {
        return Err(FixedVhdError::IdentityMismatch {
            field: "partition offset",
        });
    }
    if partition_sector_count == 0 {
        return Err(FixedVhdError::InvalidMbr {
            field: "zero partition sector count",
        });
    }
    let partition_end_sectors = partition_offset_sectors
        .checked_add(u64::from(partition_sector_count))
        .ok_or(FixedVhdError::ArithmeticOverflow)?;
    if partition_end_sectors != virtual_sectors {
        return Err(FixedVhdError::InvalidMbr {
            field: "partition does not exactly fill virtual disk tail",
        });
    }
    let last_lba = partition_end_sectors - 1;
    if entry[1..4] != encode_mbr_chs(partition_offset_sectors, geometry)
        || entry[5..8] != encode_mbr_chs(last_lba, geometry)
    {
        return Err(FixedVhdError::InvalidMbr {
            field: "partition CHS",
        });
    }
    let partition_start_bytes = partition_offset_sectors
        .checked_mul(VHD_SECTOR_BYTES)
        .ok_or(FixedVhdError::ArithmeticOverflow)?;
    let partition_bytes = u64::from(partition_sector_count)
        .checked_mul(VHD_SECTOR_BYTES)
        .ok_or(FixedVhdError::ArithmeticOverflow)?;
    enforce_limit("partition", partition_bytes, limits.max_partition_bytes)?;
    let start =
        usize::try_from(partition_start_bytes).map_err(|_| FixedVhdError::FieldOverflow {
            field: "host partition offset",
            value: partition_start_bytes,
        })?;
    let end = usize::try_from(current_size).map_err(|_| FixedVhdError::FieldOverflow {
        field: "host virtual disk length",
        value: current_size,
    })?;
    validate_partition_boot(
        &image[start..end],
        partition_offset_sectors,
        partition_bytes,
    )?;

    Ok(ValidatedFixedVhd {
        virtual_size_bytes: current_size,
        partition_offset_sectors,
        partition_sector_count,
        mbr_disk_signature: mbr_signature,
        footer_timestamp,
        unique_id,
        geometry,
    })
}

fn validate_limits(limits: FixedVhdLimits) -> Result<(), FixedVhdError> {
    for (field, value) in [
        ("max_partition_bytes", limits.max_partition_bytes),
        ("max_virtual_disk_bytes", limits.max_virtual_disk_bytes),
        ("max_output_bytes", limits.max_output_bytes),
    ] {
        if value == 0 {
            return Err(FixedVhdError::InvalidLimit { field });
        }
    }
    Ok(())
}

fn validate_partition_shape(
    partition_bytes: u64,
    partition_offset_sectors: u64,
    limits: FixedVhdLimits,
) -> Result<(), FixedVhdError> {
    if partition_bytes == 0 {
        return Err(FixedVhdError::EmptyPartition);
    }
    if partition_bytes % VHD_SECTOR_BYTES != 0 {
        return Err(FixedVhdError::UnalignedPartitionLength {
            bytes: partition_bytes,
        });
    }
    validate_partition_offset(partition_offset_sectors)?;
    enforce_limit("partition", partition_bytes, limits.max_partition_bytes)
}

const fn validate_partition_offset(partition_offset_sectors: u64) -> Result<(), FixedVhdError> {
    if partition_offset_sectors < ONE_MIB_PARTITION_ALIGNMENT_SECTORS {
        return Err(FixedVhdError::PartitionOffsetTooSmall {
            sectors: partition_offset_sectors,
        });
    }
    if partition_offset_sectors % ONE_MIB_PARTITION_ALIGNMENT_SECTORS != 0 {
        return Err(FixedVhdError::UnalignedPartitionOffset {
            sectors: partition_offset_sectors,
        });
    }
    Ok(())
}

fn validate_partition_boot(
    partition: &[u8],
    partition_offset_sectors: u64,
    partition_bytes: u64,
) -> Result<(), FixedVhdError> {
    if partition.len() < VHD_FOOTER_BYTES {
        return Err(FixedVhdError::Truncated {
            actual: partition.len(),
            minimum: VHD_FOOTER_BYTES,
        });
    }
    let expected_offset_bytes = partition_offset_sectors
        .checked_mul(VHD_SECTOR_BYTES)
        .ok_or(FixedVhdError::ArithmeticOverflow)?;
    match &partition[3..11] {
        b"NTFS    " => {
            let boot = ntfs::parse_boot_sector(&partition[..VHD_FOOTER_BYTES])
                .map_err(|_| FixedVhdError::MalformedPartitionBootSector { filesystem: "NTFS" })?;
            let actual_offset_bytes = u64::from(boot.hidden_sectors)
                .checked_mul(u64::from(boot.bytes_per_sector))
                .ok_or(FixedVhdError::ArithmeticOverflow)?;
            if actual_offset_bytes != expected_offset_bytes {
                return Err(FixedVhdError::PartitionOffsetMismatch {
                    expected_bytes: expected_offset_bytes,
                    actual_bytes: actual_offset_bytes,
                });
            }
            if boot.minimum_image_bytes != partition_bytes {
                return Err(FixedVhdError::PartitionLengthMismatch {
                    expected_bytes: partition_bytes,
                    actual_bytes: boot.minimum_image_bytes,
                });
            }
        }
        b"EXFAT   " => {
            let shift = partition[108];
            let sector_bytes = 1_usize.checked_shl(u32::from(shift)).ok_or(
                FixedVhdError::MalformedPartitionBootSector {
                    filesystem: "exFAT",
                },
            )?;
            let sector = partition
                .get(..sector_bytes)
                .ok_or(FixedVhdError::Truncated {
                    actual: partition.len(),
                    minimum: sector_bytes,
                })?;
            let boot = exfat::parse_boot_sector(sector).map_err(|_| {
                FixedVhdError::MalformedPartitionBootSector {
                    filesystem: "exFAT",
                }
            })?;
            let logical_sector_bytes = u64::from(boot.bytes_per_sector);
            let actual_offset_bytes = boot
                .partition_offset_sectors
                .checked_mul(logical_sector_bytes)
                .ok_or(FixedVhdError::ArithmeticOverflow)?;
            if actual_offset_bytes != expected_offset_bytes {
                return Err(FixedVhdError::PartitionOffsetMismatch {
                    expected_bytes: expected_offset_bytes,
                    actual_bytes: actual_offset_bytes,
                });
            }
            let actual_partition_bytes = boot
                .volume_length_sectors
                .checked_mul(logical_sector_bytes)
                .ok_or(FixedVhdError::ArithmeticOverflow)?;
            if actual_partition_bytes != partition_bytes {
                return Err(FixedVhdError::PartitionLengthMismatch {
                    expected_bytes: partition_bytes,
                    actual_bytes: actual_partition_bytes,
                });
            }
        }
        _ => return Err(FixedVhdError::UnsupportedPartitionBootSector),
    }
    Ok(())
}

const fn enforce_limit(
    component: &'static str,
    actual: u64,
    maximum: u64,
) -> Result<(), FixedVhdError> {
    if actual > maximum {
        return Err(FixedVhdError::LimitExceeded {
            component,
            actual,
            maximum,
        });
    }
    Ok(())
}

fn footer_geometry(total_sectors: u64) -> VhdGeometry {
    let maximum = 65_535_u64 * 16 * 255;
    let sectors = total_sectors.min(maximum);
    let (sectors_per_track, heads, cylinder_times_heads) = if sectors >= 65_535 * 16 * 63 {
        (255_u64, 16_u64, sectors / 255)
    } else {
        let mut sectors_per_track = 17_u64;
        let mut cylinder_times_heads = sectors / sectors_per_track;
        let mut heads = cylinder_times_heads.div_ceil(1024).max(4);
        if cylinder_times_heads >= heads * 1024 || heads > 16 {
            sectors_per_track = 31;
            heads = 16;
            cylinder_times_heads = sectors / sectors_per_track;
        }
        if cylinder_times_heads >= heads * 1024 {
            sectors_per_track = 63;
            heads = 16;
            cylinder_times_heads = sectors / sectors_per_track;
        }
        (sectors_per_track, heads, cylinder_times_heads)
    };
    let cylinders = cylinder_times_heads / heads;
    VhdGeometry {
        cylinders: u16::try_from(cylinders).unwrap_or(u16::MAX),
        heads: u8::try_from(heads).unwrap_or(16),
        sectors_per_track: u8::try_from(sectors_per_track).unwrap_or(255),
    }
}

fn encode_mbr_chs(lba: u64, geometry: VhdGeometry) -> [u8; 3] {
    let heads = u64::from(geometry.heads);
    let sectors = u64::from(geometry.sectors_per_track);
    if heads == 0 || sectors == 0 || sectors > 63 {
        return [0xfe, 0xff, 0xff];
    }
    let sectors_per_cylinder = heads * sectors;
    let cylinder = lba / sectors_per_cylinder;
    if cylinder > 1023 {
        return [0xfe, 0xff, 0xff];
    }
    let within_cylinder = lba % sectors_per_cylinder;
    let head = within_cylinder / sectors;
    let sector = within_cylinder % sectors + 1;
    [
        u8::try_from(head).unwrap_or(0xfe),
        u8::try_from(sector | ((cylinder >> 2) & 0xc0)).unwrap_or(0xff),
        u8::try_from(cylinder & 0xff).unwrap_or(0xff),
    ]
}

fn write_mbr(
    mbr: &mut [u8],
    config: FixedVhdConfig,
    partition_sectors: u64,
    geometry: VhdGeometry,
) -> Result<(), FixedVhdError> {
    put_le_u32(mbr, MBR_SIGNATURE_OFFSET, config.mbr_disk_signature);
    let entry = &mut mbr[MBR_PARTITION_OFFSET..MBR_PARTITION_OFFSET + MBR_PARTITION_BYTES];
    entry[0] = 0;
    entry[1..4].copy_from_slice(&encode_mbr_chs(config.partition_offset_sectors, geometry));
    entry[4] = 0x07;
    let last_lba = config
        .partition_offset_sectors
        .checked_add(partition_sectors)
        .and_then(|value| value.checked_sub(1))
        .ok_or(FixedVhdError::ArithmeticOverflow)?;
    entry[5..8].copy_from_slice(&encode_mbr_chs(last_lba, geometry));
    put_le_u32(
        entry,
        8,
        u32::try_from(config.partition_offset_sectors).map_err(|_| {
            FixedVhdError::FieldOverflow {
                field: "MBR partition start LBA",
                value: config.partition_offset_sectors,
            }
        })?,
    );
    put_le_u32(
        entry,
        12,
        u32::try_from(partition_sectors).map_err(|_| FixedVhdError::FieldOverflow {
            field: "MBR partition sector count",
            value: partition_sectors,
        })?,
    );
    mbr[MBR_END_MARKER_OFFSET..].copy_from_slice(&[0x55, 0xaa]);
    Ok(())
}

fn write_footer(
    footer: &mut [u8],
    virtual_size_bytes: u64,
    geometry: VhdGeometry,
    config: FixedVhdConfig,
) {
    footer[0..8].copy_from_slice(VHD_COOKIE);
    put_be_u32(footer, 8, VHD_FEATURES_RESERVED);
    put_be_u32(footer, 12, VHD_FORMAT_VERSION_1);
    put_be_u64(footer, 16, VHD_FIXED_DATA_OFFSET);
    put_be_u32(footer, 24, config.footer_timestamp);
    footer[28..32].copy_from_slice(CREATOR_APPLICATION);
    put_be_u32(footer, 32, CREATOR_VERSION);
    footer[36..40].copy_from_slice(CREATOR_HOST_OS_WINDOWS);
    put_be_u64(footer, 40, virtual_size_bytes);
    put_be_u64(footer, 48, virtual_size_bytes);
    footer[56..60].copy_from_slice(&geometry_bytes(geometry));
    put_be_u32(footer, 60, VHD_DISK_TYPE_FIXED);
    footer[68..84].copy_from_slice(&config.unique_id);
    let checksum = footer_checksum(footer);
    put_be_u32(footer, 64, checksum);
}

const fn geometry_bytes(geometry: VhdGeometry) -> [u8; 4] {
    let cylinders = geometry.cylinders.to_be_bytes();
    [
        cylinders[0],
        cylinders[1],
        geometry.heads,
        geometry.sectors_per_track,
    ]
}

fn footer_checksum(footer: &[u8]) -> u32 {
    let sum = footer
        .iter()
        .enumerate()
        .map(|(offset, byte)| if (64..68).contains(&offset) { 0 } else { *byte })
        .fold(0_u32, |sum, byte| sum.wrapping_add(u32::from(byte)));
    !sum
}

fn require_be_u32(
    bytes: &[u8],
    offset: usize,
    expected: u32,
    field: &'static str,
) -> Result<(), FixedVhdError> {
    if be_u32(bytes, offset) != expected {
        return Err(FixedVhdError::InvalidFooter { field });
    }
    Ok(())
}

fn require_be_u64(
    bytes: &[u8],
    offset: usize,
    expected: u64,
    field: &'static str,
) -> Result<(), FixedVhdError> {
    if be_u64(bytes, offset) != expected {
        return Err(FixedVhdError::InvalidFooter { field });
    }
    Ok(())
}

fn be_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn be_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn le_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn put_be_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

fn put_be_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
}

fn put_le_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    const PARTITION_BYTES: usize = 1024 * 1024;

    const fn config() -> FixedVhdConfig {
        FixedVhdConfig {
            partition_offset_sectors: 2048,
            mbr_disk_signature: 0x1234_abcd,
            footer_timestamp: 0x0102_0304,
            unique_id: [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ],
        }
    }

    fn ntfs_partition() -> Vec<u8> {
        let mut partition = vec![0_u8; PARTITION_BYTES];
        let boot = &mut partition[..VHD_FOOTER_BYTES];
        boot[0..3].copy_from_slice(&[0xeb, 0x52, 0x90]);
        boot[3..11].copy_from_slice(b"NTFS    ");
        boot[11..13].copy_from_slice(&512_u16.to_le_bytes());
        boot[13] = 8;
        boot[21] = 0xf8;
        boot[24..26].copy_from_slice(&63_u16.to_le_bytes());
        boot[26..28].copy_from_slice(&255_u16.to_le_bytes());
        boot[28..32].copy_from_slice(&2048_u32.to_le_bytes());
        boot[36] = 0x80;
        boot[38] = 0x80;
        boot[40..48].copy_from_slice(&2047_i64.to_le_bytes());
        boot[48..56].copy_from_slice(&4_i64.to_le_bytes());
        boot[56..64].copy_from_slice(&128_i64.to_le_bytes());
        boot[64] = (-10_i8).to_ne_bytes()[0];
        boot[68] = 1;
        boot[72..80].copy_from_slice(&0x0123_4567_89ab_cdef_u64.to_le_bytes());
        boot[510..512].copy_from_slice(&0xaa55_u16.to_le_bytes());
        partition
    }

    fn exfat_partition() -> Vec<u8> {
        const VOLUME_SECTORS: u64 = 64_088;
        let mut partition = vec![0_u8; usize::try_from(VOLUME_SECTORS * VHD_SECTOR_BYTES).unwrap()];
        let boot = &mut partition[..VHD_FOOTER_BYTES];
        boot[0..3].copy_from_slice(&[0xeb, 0x76, 0x90]);
        boot[3..11].copy_from_slice(b"EXFAT   ");
        boot[64..72].copy_from_slice(&2048_u64.to_le_bytes());
        boot[72..80].copy_from_slice(&VOLUME_SECTORS.to_le_bytes());
        boot[80..84].copy_from_slice(&24_u32.to_le_bytes());
        boot[84..88].copy_from_slice(&64_u32.to_le_bytes());
        boot[88..92].copy_from_slice(&88_u32.to_le_bytes());
        boot[92..96].copy_from_slice(&8000_u32.to_le_bytes());
        boot[96..100].copy_from_slice(&2_u32.to_le_bytes());
        boot[100..104].copy_from_slice(&0x1234_abcd_u32.to_le_bytes());
        boot[104..106].copy_from_slice(&0x0100_u16.to_le_bytes());
        boot[108] = 9;
        boot[109] = 3;
        boot[110] = 1;
        boot[111] = 0x80;
        boot[112] = 42;
        boot[510..512].copy_from_slice(&0xaa55_u16.to_le_bytes());
        partition
    }

    #[test]
    fn fixed_vhd_golden_layout_footer_and_independent_parser_roundtrip() {
        let partition = ntfs_partition();
        let image = wrap_fixed_vhd(&partition, config(), FixedVhdLimits::default()).unwrap();
        assert_eq!(image.bytes.len(), 2 * 1024 * 1024 + VHD_FOOTER_BYTES);
        assert_eq!(&image.bytes[510..512], &[0x55, 0xaa]);
        assert_eq!(le_u32(&image.bytes, 440), 0x1234_abcd);
        let entry = &image.bytes[446..462];
        assert_eq!(entry[0], 0);
        assert_eq!(&entry[1..4], &[0, 9, 30]);
        assert_eq!(entry[4], 0x07);
        assert_eq!(&entry[5..8], &[0, 16, 60]);
        assert_eq!(le_u32(entry, 8), 2048);
        assert_eq!(le_u32(entry, 12), 2048);
        assert_eq!(&image.bytes[1024 * 1024 + 3..1024 * 1024 + 11], b"NTFS    ");

        let footer = &image.bytes[image.bytes.len() - VHD_FOOTER_BYTES..];
        assert_eq!(&footer[0..8], b"conectix");
        assert_eq!(be_u32(footer, 8), 2);
        assert_eq!(be_u32(footer, 12), 0x0001_0000);
        assert_eq!(be_u64(footer, 16), u64::MAX);
        assert_eq!(be_u32(footer, 24), 0x0102_0304);
        assert_eq!(&footer[56..60], &[0, 60, 4, 17]);
        assert_eq!(be_u32(footer, 60), 2);
        assert_eq!(be_u32(footer, 64), footer_checksum(footer));
        assert_eq!(image.validated.geometry.cylinders, 60);
        assert_eq!(
            validate_fixed_vhd(&image.bytes, config(), FixedVhdLimits::default()).unwrap(),
            image.validated
        );
    }

    #[test]
    fn construction_is_deterministic_and_copies_partition_exactly() {
        let partition = ntfs_partition();
        let first = wrap_fixed_vhd(&partition, config(), FixedVhdLimits::default()).unwrap();
        let second = wrap_fixed_vhd(&partition, config(), FixedVhdLimits::default()).unwrap();
        assert_eq!(first, second);
        assert_eq!(&first.bytes[1024 * 1024..2 * 1024 * 1024], partition);
    }

    #[test]
    fn exfat_partition_offset_and_length_roundtrip_in_byte_units() {
        let partition = exfat_partition();
        let image = wrap_fixed_vhd(&partition, config(), FixedVhdLimits::default()).unwrap();
        assert_eq!(image.validated.partition_offset_sectors, 2048);
        assert_eq!(
            u64::from(image.validated.partition_sector_count) * VHD_SECTOR_BYTES,
            u64::try_from(partition.len()).unwrap()
        );
        assert_eq!(&image.bytes[1024 * 1024 + 3..1024 * 1024 + 11], b"EXFAT   ");
    }

    #[test]
    fn caps_alignment_fields_and_bpb_mismatch_fail_before_output() {
        let partition = ntfs_partition();
        let limits = FixedVhdLimits {
            max_partition_bytes: u64::try_from(PARTITION_BYTES - 1).unwrap(),
            ..FixedVhdLimits::default()
        };
        assert!(matches!(
            wrap_fixed_vhd(&partition, config(), limits),
            Err(FixedVhdError::LimitExceeded {
                component: "partition",
                ..
            })
        ));
        let mut unaligned = config();
        unaligned.partition_offset_sectors = 2049;
        assert!(matches!(
            wrap_fixed_vhd(&partition, unaligned, FixedVhdLimits::default()),
            Err(FixedVhdError::UnalignedPartitionOffset { .. })
        ));
        let mut too_large = config();
        too_large.partition_offset_sectors = u64::from(u32::MAX) + 1;
        assert!(matches!(
            wrap_fixed_vhd(&partition, too_large, FixedVhdLimits::default()),
            Err(FixedVhdError::FieldOverflow {
                field: "MBR partition start LBA",
                ..
            })
        ));
        let mut mismatch = partition.clone();
        mismatch[28..32].copy_from_slice(&4096_u32.to_le_bytes());
        assert!(matches!(
            wrap_fixed_vhd(&mismatch, config(), FixedVhdLimits::default()),
            Err(FixedVhdError::PartitionOffsetMismatch { .. })
        ));
        assert!(matches!(
            wrap_fixed_vhd(
                &partition[..partition.len() - 1],
                config(),
                FixedVhdLimits::default()
            ),
            Err(FixedVhdError::UnalignedPartitionLength { .. })
        ));
    }

    #[test]
    fn validator_rejects_footer_mbr_chs_partition_and_identity_mutations() {
        let image = wrap_fixed_vhd(&ntfs_partition(), config(), FixedVhdLimits::default())
            .unwrap()
            .bytes;
        for offset in [
            image.len() - VHD_FOOTER_BYTES,
            image.len() - VHD_FOOTER_BYTES + 64,
            446,
            447,
            450,
            454,
            458,
            510,
            1024 * 1024 + 28,
        ] {
            let mut mutated = image.clone();
            mutated[offset] ^= 1;
            assert!(
                validate_fixed_vhd(&mutated, config(), FixedVhdLimits::default()).is_err(),
                "offset {offset}"
            );
        }
        let mut wrong_identity = config();
        wrong_identity.footer_timestamp ^= 1;
        assert!(matches!(
            validate_fixed_vhd(&image, wrong_identity, FixedVhdLimits::default()),
            Err(FixedVhdError::IdentityMismatch {
                field: "footer timestamp"
            })
        ));
        assert!(
            validate_fixed_vhd(
                &image[..image.len() - 1],
                config(),
                FixedVhdLimits::default()
            )
            .is_err()
        );
    }

    #[test]
    fn footer_geometry_and_chs_boundaries_are_exact() {
        assert_eq!(
            footer_geometry(4096),
            VhdGeometry {
                cylinders: 60,
                heads: 4,
                sectors_per_track: 17
            }
        );
        assert_eq!(encode_mbr_chs(2048, footer_geometry(4096)), [0, 9, 30]);
        assert_eq!(
            encode_mbr_chs(
                1024 * 16 * 63,
                VhdGeometry {
                    cylinders: 2048,
                    heads: 16,
                    sectors_per_track: 63
                }
            ),
            [0xfe, 0xff, 0xff]
        );
        assert_eq!(
            footer_geometry(u64::MAX),
            VhdGeometry {
                cylinders: u16::MAX,
                heads: 16,
                sectors_per_track: 255
            }
        );
    }
}
