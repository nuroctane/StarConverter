//! Bounded, read-only parsing for the exFAT main boot sector.
//!
//! This module accepts exactly one logical sector. It performs no I/O and no
//! allocation while parsing, and it validates the geometry needed before later
//! code may trust offsets from an untrusted filesystem image.

#![allow(clippy::module_name_repetitions)]

use core::fmt;

const FIXED_BOOT_FIELDS_BYTES: usize = 512;
const FILE_SYSTEM_NAME: &[u8; 8] = b"EXFAT   ";
const JUMP_BOOT: [u8; 3] = [0xEB, 0x76, 0x90];
const BOOT_SIGNATURE: u16 = 0xAA55;
const EXFAT_REVISION_1_00: u16 = 0x0100;
const MAIN_AND_BACKUP_BOOT_SECTORS: u32 = 24;
const MIN_BYTES_PER_SECTOR_SHIFT: u8 = 9;
const MAX_BYTES_PER_SECTOR_SHIFT: u8 = 12;
const MAX_CLUSTER_BYTES_SHIFT: u8 = 25;
const MAX_CLUSTER_COUNT: u32 = 0xFFFF_FFF5;
const VALID_VOLUME_FLAGS_MASK: u16 = 0x000F;
const ACTIVE_FAT_FLAG: u16 = 0x0001;
const UNKNOWN_PERCENT_IN_USE: u8 = 0xFF;

/// Parsed and validated fields from an exFAT 1.00 main boot sector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExfatBootSector {
    pub partition_offset_sectors: u64,
    pub volume_length_sectors: u64,
    pub fat_offset_sectors: u32,
    pub fat_length_sectors: u32,
    pub cluster_heap_offset_sectors: u32,
    pub cluster_count: u32,
    pub root_directory_cluster: u32,
    pub volume_serial_number: u32,
    pub filesystem_revision: u16,
    pub volume_flags: u16,
    pub bytes_per_sector_shift: u8,
    pub sectors_per_cluster_shift: u8,
    pub number_of_fats: u8,
    pub drive_select: u8,
    /// `None` represents the on-disk unknown value (`0xFF`).
    pub percent_in_use: Option<u8>,
    pub bytes_per_sector: u32,
    pub sectors_per_cluster: u32,
    pub bytes_per_cluster: u32,
}

/// A structural or cross-field validation failure in an exFAT boot sector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExfatBootSectorError {
    Truncated {
        actual: usize,
        minimum: usize,
    },
    SectorLengthMismatch {
        declared: usize,
        actual: usize,
    },
    InvalidJumpBoot {
        found: [u8; 3],
    },
    InvalidFileSystemName {
        found: [u8; 8],
    },
    MustBeZero {
        offset: usize,
        value: u8,
    },
    ReservedMustBeZero {
        offset: usize,
        value: u8,
    },
    UnsupportedRevision {
        found: u16,
    },
    InvalidBytesPerSectorShift {
        found: u8,
    },
    InvalidSectorsPerClusterShift {
        found: u8,
        maximum: u8,
    },
    InvalidFatCount {
        found: u8,
    },
    InvalidVolumeFlags {
        found: u16,
    },
    InactiveOnlyFatMarkedActive,
    InvalidPercentInUse {
        found: u8,
    },
    InvalidBootSignature {
        found: u16,
    },
    VolumeTooShort {
        found: u64,
        minimum: u64,
    },
    FatOffsetBeforeBootRegions {
        found: u32,
        minimum: u32,
    },
    ZeroFatLength,
    InvalidClusterCount {
        found: u32,
    },
    ClusterCountMismatch {
        found: u32,
        expected: u32,
    },
    FatTooSmall {
        found: u32,
        minimum: u64,
    },
    FatRegionOutsideVolume {
        end: u64,
        volume_length: u64,
    },
    ClusterHeapOverlapsFatRegion {
        heap_offset: u32,
        fat_end: u64,
    },
    ClusterHeapOutsideVolume {
        heap_offset: u32,
        volume_length: u64,
    },
    ClusterHeapOutsideVolumeEnd {
        heap_end: u64,
        volume_length: u64,
    },
    RootDirectoryClusterOutOfRange {
        found: u32,
        minimum: u32,
        maximum: u32,
    },
    ArithmeticOverflow {
        operation: &'static str,
    },
}

impl fmt::Display for ExfatBootSectorError {
    // Keeping the exhaustive messages together makes every public corruption
    // class auditable alongside its enum variant.
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { actual, minimum } => write!(
                formatter,
                "exFAT boot sector is truncated: got {actual} bytes, need at least {minimum}"
            ),
            Self::SectorLengthMismatch { declared, actual } => write!(
                formatter,
                "declared logical sector is {declared} bytes, but input contains {actual} bytes"
            ),
            Self::InvalidJumpBoot { found } => {
                write!(formatter, "invalid exFAT jump instruction: {found:02X?}")
            }
            Self::InvalidFileSystemName { found } => {
                write!(formatter, "invalid exFAT filesystem name: {found:02X?}")
            }
            Self::MustBeZero { offset, value } => write!(
                formatter,
                "exFAT MustBeZero byte at offset {offset} contains {value:#04X}"
            ),
            Self::ReservedMustBeZero { offset, value } => write!(
                formatter,
                "reserved exFAT boot byte at offset {offset} contains {value:#04X}"
            ),
            Self::UnsupportedRevision { found } => {
                write!(
                    formatter,
                    "unsupported exFAT revision {found:#06X}; expected 1.00"
                )
            }
            Self::InvalidBytesPerSectorShift { found } => {
                write!(formatter, "invalid exFAT bytes-per-sector shift {found}")
            }
            Self::InvalidSectorsPerClusterShift { found, maximum } => write!(
                formatter,
                "invalid exFAT sectors-per-cluster shift {found}; maximum is {maximum}"
            ),
            Self::InvalidFatCount { found } => {
                write!(
                    formatter,
                    "invalid exFAT FAT count {found}; expected one or two"
                )
            }
            Self::InvalidVolumeFlags { found } => {
                write!(
                    formatter,
                    "invalid reserved bits in exFAT volume flags {found:#06X}"
                )
            }
            Self::InactiveOnlyFatMarkedActive => formatter.write_str(
                "exFAT active-FAT flag selects a second FAT, but the volume declares only one FAT",
            ),
            Self::InvalidPercentInUse { found } => write!(
                formatter,
                "invalid exFAT percent-in-use value {found}; expected 0..=100 or 0xFF"
            ),
            Self::InvalidBootSignature { found } => write!(
                formatter,
                "invalid exFAT boot signature {found:#06X}; expected 0xAA55"
            ),
            Self::VolumeTooShort { found, minimum } => write!(
                formatter,
                "exFAT volume is {found} sectors; minimum is {minimum} sectors"
            ),
            Self::FatOffsetBeforeBootRegions { found, minimum } => write!(
                formatter,
                "exFAT FAT offset {found} precedes the {minimum}-sector boot regions"
            ),
            Self::ZeroFatLength => formatter.write_str("exFAT FAT length is zero"),
            Self::InvalidClusterCount { found } => {
                write!(formatter, "invalid exFAT cluster count {found}")
            }
            Self::ClusterCountMismatch { found, expected } => write!(
                formatter,
                "exFAT cluster count is {found}; volume geometry requires {expected}"
            ),
            Self::FatTooSmall { found, minimum } => write!(
                formatter,
                "exFAT FAT is {found} sectors; at least {minimum} sectors are required"
            ),
            Self::FatRegionOutsideVolume { end, volume_length } => write!(
                formatter,
                "exFAT FAT region ends at sector {end}, beyond volume length {volume_length}"
            ),
            Self::ClusterHeapOverlapsFatRegion {
                heap_offset,
                fat_end,
            } => write!(
                formatter,
                "exFAT cluster heap starts at sector {heap_offset}, before FAT region end {fat_end}"
            ),
            Self::ClusterHeapOutsideVolume {
                heap_offset,
                volume_length,
            } => write!(
                formatter,
                "exFAT cluster heap starts at sector {heap_offset}, outside volume length {volume_length}"
            ),
            Self::ClusterHeapOutsideVolumeEnd {
                heap_end,
                volume_length,
            } => write!(
                formatter,
                "exFAT cluster heap ends at sector {heap_end}, beyond volume length {volume_length}"
            ),
            Self::RootDirectoryClusterOutOfRange {
                found,
                minimum,
                maximum,
            } => write!(
                formatter,
                "exFAT root directory cluster {found} is outside {minimum}..={maximum}"
            ),
            Self::ArithmeticOverflow { operation } => {
                write!(formatter, "integer overflow while calculating {operation}")
            }
        }
    }
}

impl std::error::Error for ExfatBootSectorError {}

/// Parses and validates exactly one exFAT main boot sector.
///
/// The declared logical-sector size must match `sector.len()`. No filesystem
/// offsets are dereferenced and no physical device access is performed.
///
/// # Errors
///
/// Returns [`ExfatBootSectorError`] when the input is truncated, disagrees with
/// the exFAT 1.00 boot-sector contract, contains inconsistent geometry, or any
/// derived boundary calculation overflows.
// The validation order deliberately follows the on-disk layout and then its
// cross-field dependencies, which is easier to audit than a stateful split.
#[allow(clippy::too_many_lines)]
pub fn parse_boot_sector(sector: &[u8]) -> Result<ExfatBootSector, ExfatBootSectorError> {
    if sector.len() < FIXED_BOOT_FIELDS_BYTES {
        return Err(ExfatBootSectorError::Truncated {
            actual: sector.len(),
            minimum: FIXED_BOOT_FIELDS_BYTES,
        });
    }

    let found_jump = [sector[0], sector[1], sector[2]];
    if found_jump != JUMP_BOOT {
        return Err(ExfatBootSectorError::InvalidJumpBoot { found: found_jump });
    }

    let found_name = array_8(sector, 3);
    if &found_name != FILE_SYSTEM_NAME {
        return Err(ExfatBootSectorError::InvalidFileSystemName { found: found_name });
    }

    validate_zeroes(sector, 11, 64, false)?;

    let bytes_per_sector_shift = sector[108];
    if !(MIN_BYTES_PER_SECTOR_SHIFT..=MAX_BYTES_PER_SECTOR_SHIFT).contains(&bytes_per_sector_shift)
    {
        return Err(ExfatBootSectorError::InvalidBytesPerSectorShift {
            found: bytes_per_sector_shift,
        });
    }
    let bytes_per_sector = 1_u32.checked_shl(u32::from(bytes_per_sector_shift)).ok_or(
        ExfatBootSectorError::ArithmeticOverflow {
            operation: "logical sector size",
        },
    )?;
    let declared_sector_bytes = usize::try_from(bytes_per_sector).map_err(|_| {
        ExfatBootSectorError::ArithmeticOverflow {
            operation: "logical sector size conversion",
        }
    })?;
    if sector.len() != declared_sector_bytes {
        return Err(ExfatBootSectorError::SectorLengthMismatch {
            declared: declared_sector_bytes,
            actual: sector.len(),
        });
    }

    let sectors_per_cluster_shift = sector[109];
    let maximum_cluster_shift = MAX_CLUSTER_BYTES_SHIFT - bytes_per_sector_shift;
    if sectors_per_cluster_shift > maximum_cluster_shift {
        return Err(ExfatBootSectorError::InvalidSectorsPerClusterShift {
            found: sectors_per_cluster_shift,
            maximum: maximum_cluster_shift,
        });
    }
    let sectors_per_cluster = 1_u32
        .checked_shl(u32::from(sectors_per_cluster_shift))
        .ok_or(ExfatBootSectorError::ArithmeticOverflow {
            operation: "sectors per cluster",
        })?;
    let bytes_per_cluster = bytes_per_sector.checked_mul(sectors_per_cluster).ok_or(
        ExfatBootSectorError::ArithmeticOverflow {
            operation: "bytes per cluster",
        },
    )?;

    validate_zeroes(sector, 113, 120, true)?;

    let filesystem_revision = read_u16(sector, 104);
    if filesystem_revision != EXFAT_REVISION_1_00 {
        return Err(ExfatBootSectorError::UnsupportedRevision {
            found: filesystem_revision,
        });
    }

    let number_of_fats = sector[110];
    if !matches!(number_of_fats, 1 | 2) {
        return Err(ExfatBootSectorError::InvalidFatCount {
            found: number_of_fats,
        });
    }

    let volume_flags = read_u16(sector, 106);
    if volume_flags & !VALID_VOLUME_FLAGS_MASK != 0 {
        return Err(ExfatBootSectorError::InvalidVolumeFlags {
            found: volume_flags,
        });
    }
    if number_of_fats == 1 && volume_flags & ACTIVE_FAT_FLAG != 0 {
        return Err(ExfatBootSectorError::InactiveOnlyFatMarkedActive);
    }

    let percent_in_use_raw = sector[112];
    let percent_in_use = match percent_in_use_raw {
        0..=100 => Some(percent_in_use_raw),
        UNKNOWN_PERCENT_IN_USE => None,
        found => return Err(ExfatBootSectorError::InvalidPercentInUse { found }),
    };

    let boot_signature = read_u16(sector, 510);
    if boot_signature != BOOT_SIGNATURE {
        return Err(ExfatBootSectorError::InvalidBootSignature {
            found: boot_signature,
        });
    }

    let partition_offset_sectors = read_u64(sector, 64);
    let volume_length_sectors = read_u64(sector, 72);
    partition_offset_sectors
        .checked_add(volume_length_sectors)
        .ok_or(ExfatBootSectorError::ArithmeticOverflow {
            operation: "partition end",
        })?;

    let minimum_volume_sectors = (1_u64 << 20) / u64::from(bytes_per_sector);
    if volume_length_sectors < minimum_volume_sectors {
        return Err(ExfatBootSectorError::VolumeTooShort {
            found: volume_length_sectors,
            minimum: minimum_volume_sectors,
        });
    }

    let fat_offset_sectors = read_u32(sector, 80);
    let minimum_fat_offset = MAIN_AND_BACKUP_BOOT_SECTORS;
    if fat_offset_sectors < minimum_fat_offset {
        return Err(ExfatBootSectorError::FatOffsetBeforeBootRegions {
            found: fat_offset_sectors,
            minimum: minimum_fat_offset,
        });
    }

    let fat_length_sectors = read_u32(sector, 84);
    if fat_length_sectors == 0 {
        return Err(ExfatBootSectorError::ZeroFatLength);
    }

    let cluster_count = read_u32(sector, 92);
    if cluster_count == 0 || cluster_count > MAX_CLUSTER_COUNT {
        return Err(ExfatBootSectorError::InvalidClusterCount {
            found: cluster_count,
        });
    }

    let fat_entry_count = u64::from(cluster_count).checked_add(2).ok_or(
        ExfatBootSectorError::ArithmeticOverflow {
            operation: "FAT entry count",
        },
    )?;
    let fat_bytes_required =
        fat_entry_count
            .checked_mul(4)
            .ok_or(ExfatBootSectorError::ArithmeticOverflow {
                operation: "FAT byte length",
            })?;
    let sector_bytes = u64::from(bytes_per_sector);
    let minimum_fat_sectors = fat_bytes_required.checked_add(sector_bytes - 1).ok_or(
        ExfatBootSectorError::ArithmeticOverflow {
            operation: "rounded FAT byte length",
        },
    )? / sector_bytes;
    if u64::from(fat_length_sectors) < minimum_fat_sectors {
        return Err(ExfatBootSectorError::FatTooSmall {
            found: fat_length_sectors,
            minimum: minimum_fat_sectors,
        });
    }

    let all_fats_length = u64::from(fat_length_sectors)
        .checked_mul(u64::from(number_of_fats))
        .ok_or(ExfatBootSectorError::ArithmeticOverflow {
            operation: "combined FAT length",
        })?;
    let fat_end = u64::from(fat_offset_sectors)
        .checked_add(all_fats_length)
        .ok_or(ExfatBootSectorError::ArithmeticOverflow {
            operation: "FAT region end",
        })?;
    if fat_end > volume_length_sectors {
        return Err(ExfatBootSectorError::FatRegionOutsideVolume {
            end: fat_end,
            volume_length: volume_length_sectors,
        });
    }

    let cluster_heap_offset_sectors = read_u32(sector, 88);
    if u64::from(cluster_heap_offset_sectors) < fat_end {
        return Err(ExfatBootSectorError::ClusterHeapOverlapsFatRegion {
            heap_offset: cluster_heap_offset_sectors,
            fat_end,
        });
    }
    if u64::from(cluster_heap_offset_sectors) >= volume_length_sectors {
        return Err(ExfatBootSectorError::ClusterHeapOutsideVolume {
            heap_offset: cluster_heap_offset_sectors,
            volume_length: volume_length_sectors,
        });
    }

    let cluster_heap_length = u64::from(cluster_count)
        .checked_mul(u64::from(sectors_per_cluster))
        .ok_or(ExfatBootSectorError::ArithmeticOverflow {
            operation: "cluster heap length",
        })?;
    let cluster_heap_end = u64::from(cluster_heap_offset_sectors)
        .checked_add(cluster_heap_length)
        .ok_or(ExfatBootSectorError::ArithmeticOverflow {
            operation: "cluster heap end",
        })?;
    if cluster_heap_end > volume_length_sectors {
        return Err(ExfatBootSectorError::ClusterHeapOutsideVolumeEnd {
            heap_end: cluster_heap_end,
            volume_length: volume_length_sectors,
        });
    }
    let available_heap_sectors = volume_length_sectors - u64::from(cluster_heap_offset_sectors);
    let clusters_that_fit = available_heap_sectors / u64::from(sectors_per_cluster);
    let expected_cluster_count = clusters_that_fit.min(u64::from(MAX_CLUSTER_COUNT));
    if u64::from(cluster_count) != expected_cluster_count {
        return Err(ExfatBootSectorError::ClusterCountMismatch {
            found: cluster_count,
            expected: u32::try_from(expected_cluster_count).map_err(|_| {
                ExfatBootSectorError::ArithmeticOverflow {
                    operation: "expected cluster count conversion",
                }
            })?,
        });
    }

    let root_directory_cluster = read_u32(sector, 96);
    let maximum_root_cluster =
        cluster_count
            .checked_add(1)
            .ok_or(ExfatBootSectorError::ArithmeticOverflow {
                operation: "maximum root directory cluster",
            })?;
    if !(2..=maximum_root_cluster).contains(&root_directory_cluster) {
        return Err(ExfatBootSectorError::RootDirectoryClusterOutOfRange {
            found: root_directory_cluster,
            minimum: 2,
            maximum: maximum_root_cluster,
        });
    }

    Ok(ExfatBootSector {
        partition_offset_sectors,
        volume_length_sectors,
        fat_offset_sectors,
        fat_length_sectors,
        cluster_heap_offset_sectors,
        cluster_count,
        root_directory_cluster,
        volume_serial_number: read_u32(sector, 100),
        filesystem_revision,
        volume_flags,
        bytes_per_sector_shift,
        sectors_per_cluster_shift,
        number_of_fats,
        drive_select: sector[111],
        percent_in_use,
        bytes_per_sector,
        sectors_per_cluster,
        bytes_per_cluster,
    })
}

fn validate_zeroes(
    bytes: &[u8],
    start: usize,
    end: usize,
    reserved: bool,
) -> Result<(), ExfatBootSectorError> {
    if let Some((relative_offset, value)) = bytes[start..end]
        .iter()
        .copied()
        .enumerate()
        .find(|(_, value)| *value != 0)
    {
        let offset = start + relative_offset;
        return Err(if reserved {
            ExfatBootSectorError::ReservedMustBeZero { offset, value }
        } else {
            ExfatBootSectorError::MustBeZero { offset, value }
        });
    }
    Ok(())
}

fn array_8(bytes: &[u8], offset: usize) -> [u8; 8] {
    let mut value = [0_u8; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    value
}

const fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

const fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

const fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn valid_sector(bytes_per_sector_shift: u8) -> Vec<u8> {
        let sector_bytes = 1_usize << bytes_per_sector_shift;
        let mut sector = vec![0_u8; sector_bytes];
        sector[0..3].copy_from_slice(&JUMP_BOOT);
        sector[3..11].copy_from_slice(FILE_SYSTEM_NAME);
        put_u64(&mut sector, 64, 2_048);
        put_u64(&mut sector, 72, 64_088);
        put_u32(&mut sector, 80, 24);
        put_u32(&mut sector, 84, 64);
        put_u32(&mut sector, 88, 88);
        put_u32(&mut sector, 92, 8_000);
        put_u32(&mut sector, 96, 2);
        put_u32(&mut sector, 100, 0x1234_ABCD);
        put_u16(&mut sector, 104, EXFAT_REVISION_1_00);
        put_u16(&mut sector, 106, 0);
        sector[108] = bytes_per_sector_shift;
        sector[109] = 3;
        sector[110] = 1;
        sector[111] = 0x80;
        sector[112] = 42;
        put_u16(&mut sector, 510, BOOT_SIGNATURE);
        sector
    }

    #[test]
    fn parses_valid_512_byte_sector() {
        let sector = valid_sector(9);
        let boot = parse_boot_sector(&sector).expect("valid 512-byte exFAT sector");

        assert_eq!(boot.bytes_per_sector, 512);
        assert_eq!(boot.sectors_per_cluster, 8);
        assert_eq!(boot.bytes_per_cluster, 4_096);
        assert_eq!(boot.partition_offset_sectors, 2_048);
        assert_eq!(boot.root_directory_cluster, 2);
        assert_eq!(boot.percent_in_use, Some(42));
    }

    #[test]
    fn parses_valid_4096_byte_sector_with_two_fats_and_unknown_usage() {
        let mut sector = valid_sector(12);
        put_u64(&mut sector, 72, 8_040);
        put_u32(&mut sector, 84, 8);
        put_u32(&mut sector, 88, 40);
        sector[109] = 0;
        sector[110] = 2;
        put_u16(&mut sector, 106, ACTIVE_FAT_FLAG);
        sector[112] = UNKNOWN_PERCENT_IN_USE;

        let boot = parse_boot_sector(&sector).expect("valid 4096-byte exFAT sector");

        assert_eq!(boot.bytes_per_sector, 4_096);
        assert_eq!(boot.sectors_per_cluster, 1);
        assert_eq!(boot.bytes_per_cluster, 4_096);
        assert_eq!(boot.number_of_fats, 2);
        assert_eq!(boot.percent_in_use, None);
    }

    #[test]
    fn rejects_truncated_sector_before_reading_fields() {
        assert_eq!(
            parse_boot_sector(&[0_u8; 511]),
            Err(ExfatBootSectorError::Truncated {
                actual: 511,
                minimum: 512,
            })
        );
    }

    #[test]
    fn rejects_sector_length_that_disagrees_with_shift() {
        let mut sector = valid_sector(9);
        sector[108] = 12;
        assert_eq!(
            parse_boot_sector(&sector),
            Err(ExfatBootSectorError::SectorLengthMismatch {
                declared: 4_096,
                actual: 512,
            })
        );
    }

    #[test]
    fn rejects_invalid_identifiers_and_zero_regions() {
        let mut sector = valid_sector(9);
        sector[0] = 0;
        assert!(matches!(
            parse_boot_sector(&sector),
            Err(ExfatBootSectorError::InvalidJumpBoot { .. })
        ));

        let mut sector = valid_sector(9);
        sector[3] = b'N';
        assert!(matches!(
            parse_boot_sector(&sector),
            Err(ExfatBootSectorError::InvalidFileSystemName { .. })
        ));

        let mut sector = valid_sector(9);
        sector[63] = 1;
        assert_eq!(
            parse_boot_sector(&sector),
            Err(ExfatBootSectorError::MustBeZero {
                offset: 63,
                value: 1,
            })
        );

        let mut sector = valid_sector(9);
        sector[119] = 1;
        assert_eq!(
            parse_boot_sector(&sector),
            Err(ExfatBootSectorError::ReservedMustBeZero {
                offset: 119,
                value: 1,
            })
        );
    }

    #[test]
    fn rejects_bad_revision_signature_and_geometry_shifts() {
        let mut sector = valid_sector(9);
        put_u16(&mut sector, 104, 0x0101);
        assert!(matches!(
            parse_boot_sector(&sector),
            Err(ExfatBootSectorError::UnsupportedRevision { found: 0x0101 })
        ));

        let mut sector = valid_sector(9);
        sector[108] = 8;
        assert!(matches!(
            parse_boot_sector(&sector),
            Err(ExfatBootSectorError::InvalidBytesPerSectorShift { found: 8 })
        ));

        let mut sector = valid_sector(9);
        sector[109] = 17;
        assert!(matches!(
            parse_boot_sector(&sector),
            Err(ExfatBootSectorError::InvalidSectorsPerClusterShift {
                found: 17,
                maximum: 16
            })
        ));

        let mut sector = valid_sector(9);
        put_u16(&mut sector, 510, 0);
        assert!(matches!(
            parse_boot_sector(&sector),
            Err(ExfatBootSectorError::InvalidBootSignature { found: 0 })
        ));
    }

    #[test]
    fn rejects_invalid_fat_count_flags_and_usage() {
        let mut sector = valid_sector(9);
        sector[110] = 0;
        assert!(matches!(
            parse_boot_sector(&sector),
            Err(ExfatBootSectorError::InvalidFatCount { found: 0 })
        ));

        let mut sector = valid_sector(9);
        put_u16(&mut sector, 106, 0x0010);
        assert!(matches!(
            parse_boot_sector(&sector),
            Err(ExfatBootSectorError::InvalidVolumeFlags { found: 0x0010 })
        ));

        let mut sector = valid_sector(9);
        put_u16(&mut sector, 106, ACTIVE_FAT_FLAG);
        assert_eq!(
            parse_boot_sector(&sector),
            Err(ExfatBootSectorError::InactiveOnlyFatMarkedActive)
        );

        let mut sector = valid_sector(9);
        sector[112] = 101;
        assert!(matches!(
            parse_boot_sector(&sector),
            Err(ExfatBootSectorError::InvalidPercentInUse { found: 101 })
        ));
    }

    #[test]
    fn rejects_volume_and_fat_bounds_failures() {
        let mut sector = valid_sector(9);
        put_u64(&mut sector, 72, 2_047);
        assert!(matches!(
            parse_boot_sector(&sector),
            Err(ExfatBootSectorError::VolumeTooShort { .. })
        ));

        let mut sector = valid_sector(9);
        put_u32(&mut sector, 80, 23);
        assert!(matches!(
            parse_boot_sector(&sector),
            Err(ExfatBootSectorError::FatOffsetBeforeBootRegions { .. })
        ));

        let mut sector = valid_sector(9);
        put_u32(&mut sector, 84, 0);
        assert_eq!(
            parse_boot_sector(&sector),
            Err(ExfatBootSectorError::ZeroFatLength)
        );

        let mut sector = valid_sector(9);
        put_u32(&mut sector, 84, 62);
        assert!(matches!(
            parse_boot_sector(&sector),
            Err(ExfatBootSectorError::FatTooSmall {
                found: 62,
                minimum: 63
            })
        ));

        let mut sector = valid_sector(9);
        put_u32(&mut sector, 80, 64_050);
        assert!(matches!(
            parse_boot_sector(&sector),
            Err(ExfatBootSectorError::FatRegionOutsideVolume { .. })
        ));
    }

    #[test]
    fn rejects_cluster_heap_and_root_bounds_failures() {
        let mut sector = valid_sector(9);
        put_u32(&mut sector, 92, 0);
        assert!(matches!(
            parse_boot_sector(&sector),
            Err(ExfatBootSectorError::InvalidClusterCount { found: 0 })
        ));

        let mut sector = valid_sector(9);
        put_u32(&mut sector, 92, MAX_CLUSTER_COUNT + 1);
        assert!(matches!(
            parse_boot_sector(&sector),
            Err(ExfatBootSectorError::InvalidClusterCount { .. })
        ));

        let mut sector = valid_sector(9);
        put_u32(&mut sector, 88, 87);
        assert!(matches!(
            parse_boot_sector(&sector),
            Err(ExfatBootSectorError::ClusterHeapOverlapsFatRegion { .. })
        ));

        let mut sector = valid_sector(9);
        put_u32(&mut sector, 88, 64_088);
        assert!(matches!(
            parse_boot_sector(&sector),
            Err(ExfatBootSectorError::ClusterHeapOutsideVolume { .. })
        ));

        let mut sector = valid_sector(9);
        put_u64(&mut sector, 72, 64_000);
        assert!(matches!(
            parse_boot_sector(&sector),
            Err(ExfatBootSectorError::ClusterHeapOutsideVolumeEnd { .. })
        ));

        let mut sector = valid_sector(9);
        put_u32(&mut sector, 96, 1);
        assert!(matches!(
            parse_boot_sector(&sector),
            Err(ExfatBootSectorError::RootDirectoryClusterOutOfRange { found: 1, .. })
        ));

        let mut sector = valid_sector(9);
        put_u32(&mut sector, 96, 8_002);
        assert!(matches!(
            parse_boot_sector(&sector),
            Err(ExfatBootSectorError::RootDirectoryClusterOutOfRange {
                found: 8_002,
                maximum: 8_001,
                ..
            })
        ));
    }

    #[test]
    fn rejects_partition_end_overflow() {
        let mut sector = valid_sector(9);
        put_u64(&mut sector, 64, u64::MAX - 10);

        assert_eq!(
            parse_boot_sector(&sector),
            Err(ExfatBootSectorError::ArithmeticOverflow {
                operation: "partition end",
            })
        );
    }

    #[test]
    fn rejects_cluster_count_that_does_not_match_heap_geometry() {
        let mut sector = valid_sector(9);
        put_u64(&mut sector, 72, 64_096);

        assert_eq!(
            parse_boot_sector(&sector),
            Err(ExfatBootSectorError::ClusterCountMismatch {
                found: 8_000,
                expected: 8_001,
            })
        );
    }
}
