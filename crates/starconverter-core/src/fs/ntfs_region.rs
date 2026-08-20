//! Validation of NTFS primary and backup boot-sector redundancy.
//!
//! This module performs no I/O and no allocation. Callers supply two exact logical-sector slices
//! and the byte bounds of the partition view from which they were read. This keeps large images
//! out of memory and makes the claimed backup location independently checkable.

use std::fmt;

use super::ntfs::{NtfsBootSector, NtfsBootSectorError, parse_boot_sector};

/// Identifies one of NTFS's redundant boot-sector copies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootSectorCopy {
    /// The primary copy at partition-relative byte offset zero.
    Primary,
    /// The alternate copy in the partition's final physical sector.
    Backup,
}

impl fmt::Display for BootSectorCopy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Primary => "primary",
            Self::Backup => "backup",
        })
    }
}

/// Validated NTFS boot-region redundancy and placement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtfsBootRegion {
    /// Parsed primary boot sector.
    pub primary: NtfsBootSector,
    /// Parsed backup boot sector. It is retained separately even though exact byte equality means
    /// its parsed fields are identical to `primary`.
    pub backup: NtfsBootSector,
    /// Exact length of the caller's bounded partition view.
    pub partition_bytes: u64,
    /// Logical sectors in the bounded partition view.
    pub partition_sectors: u64,
    /// Partition-relative byte offset at which the backup copy was validated.
    pub backup_offset: u64,
    /// Complete sectors after the declared NTFS filesystem and before the final backup sector.
    ///
    /// This may be nonzero after a partition has been enlarged without resizing NTFS. NTFS-3G's
    /// repair code still expects the backup at the actual final partition sector in that case.
    pub unaddressed_trailing_sectors: u64,
}

/// Reason the two-copy NTFS boot region could not be trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtfsBootRegionError {
    /// The primary boot sector failed structural or geometry validation.
    InvalidPrimary {
        /// Underlying parser error.
        source: NtfsBootSectorError,
    },
    /// A supplied sector slice was not exactly one primary-declared logical sector.
    WrongSectorSliceLength {
        /// Copy whose slice length was wrong.
        copy: BootSectorCopy,
        /// Supplied byte length.
        actual: usize,
        /// Required logical-sector byte length.
        required: usize,
    },
    /// The partition boundary does not end on a primary-declared logical-sector boundary.
    PartitionLengthNotSectorAligned {
        /// Bounded partition length in bytes.
        partition_bytes: u64,
        /// Primary-declared logical-sector size.
        bytes_per_sector: u16,
    },
    /// The bounded partition contains no sector after the declared NTFS filesystem for a modern
    /// end-of-partition backup copy.
    NoDedicatedBackupSector {
        /// Logical sectors in the bounded partition.
        partition_sectors: u64,
        /// Sectors declared as belonging to the NTFS filesystem.
        declared_sectors: u64,
    },
    /// The claimed backup slice was not read from the final logical sector of the bounded view.
    BackupOffsetNotFinalSector {
        /// Claimed partition-relative byte offset.
        actual: u64,
        /// Required partition-relative byte offset.
        expected: u64,
    },
    /// The backup boot sector failed independent structural or geometry validation.
    InvalidBackup {
        /// Underlying parser error.
        source: NtfsBootSectorError,
    },
    /// Both copies parsed independently, but their logical-sector bytes differ.
    BootSectorsDiffer {
        /// Offset of the first differing byte within the logical sector.
        offset: usize,
        /// Byte in the primary copy.
        primary: u8,
        /// Byte in the backup copy.
        backup: u8,
    },
}

impl fmt::Display for NtfsBootRegionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPrimary { source } => {
                write!(formatter, "invalid primary NTFS boot sector: {source}")
            }
            Self::WrongSectorSliceLength {
                copy,
                actual,
                required,
            } => write!(
                formatter,
                "{copy} NTFS boot-sector slice has {actual} bytes; expected exactly {required}"
            ),
            Self::PartitionLengthNotSectorAligned {
                partition_bytes,
                bytes_per_sector,
            } => write!(
                formatter,
                "NTFS partition length {partition_bytes} is not aligned to its {bytes_per_sector}-byte logical sector size"
            ),
            Self::NoDedicatedBackupSector {
                partition_sectors,
                declared_sectors,
            } => write!(
                formatter,
                "NTFS partition has {partition_sectors} sectors but the filesystem declares {declared_sectors}; no final sector remains for the modern backup boot sector"
            ),
            Self::BackupOffsetNotFinalSector { actual, expected } => write!(
                formatter,
                "NTFS backup boot sector was supplied from byte offset {actual}; the bounded partition's final sector starts at {expected}"
            ),
            Self::InvalidBackup { source } => {
                write!(formatter, "invalid backup NTFS boot sector: {source}")
            }
            Self::BootSectorsDiffer {
                offset,
                primary,
                backup,
            } => write!(
                formatter,
                "NTFS boot-sector copies first differ at byte {offset}: primary 0x{primary:02x}, backup 0x{backup:02x}"
            ),
        }
    }
}

impl std::error::Error for NtfsBootRegionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidPrimary { source } | Self::InvalidBackup { source } => Some(source),
            _ => None,
        }
    }
}

/// Validates a modern NTFS primary/backup boot-sector pair and the backup's location.
///
/// `primary_sector` and `backup_sector` must each contain exactly one logical sector, while
/// `partition_bytes` describes the exact bounded partition view and `backup_offset` records where
/// the caller read the backup slice. The primary copy is expected at byte offset zero; the backup
/// copy is required at the start of the partition's final logical sector.
///
/// The two sector slices must be byte-for-byte identical, including bootstrap code and any bytes
/// after the fixed 512-byte NTFS header when the logical sector is larger than 512 bytes. No field
/// differences are tolerated. This matches the full-sector `memcmp` policy used by NTFS-3G's
/// alternate-boot repair, label, and resize paths.
///
/// A partition may contain complete unaddressed sectors between the declared NTFS filesystem and
/// the final backup. NTFS-3G explicitly handles that post-resize geometry by using the actual last
/// partition sector for the backup while leaving the on-disk sector count unchanged.
///
/// # Errors
///
/// Returns [`NtfsBootRegionError`] if either copy is invalid, either slice is not exactly one
/// logical sector, the partition geometry cannot reserve a final backup sector, the claimed backup
/// offset is not the final sector, or any sector byte differs.
pub fn validate_boot_region(
    primary_sector: &[u8],
    backup_sector: &[u8],
    partition_bytes: u64,
    backup_offset: u64,
) -> Result<NtfsBootRegion, NtfsBootRegionError> {
    let primary = parse_boot_sector(primary_sector)
        .map_err(|source| NtfsBootRegionError::InvalidPrimary { source })?;
    let sector_bytes = usize::from(primary.bytes_per_sector);

    validate_slice_len(BootSectorCopy::Primary, primary_sector, sector_bytes)?;
    validate_slice_len(BootSectorCopy::Backup, backup_sector, sector_bytes)?;

    let sector_bytes_u64 = u64::from(primary.bytes_per_sector);
    if partition_bytes % sector_bytes_u64 != 0 {
        return Err(NtfsBootRegionError::PartitionLengthNotSectorAligned {
            partition_bytes,
            bytes_per_sector: primary.bytes_per_sector,
        });
    }

    let partition_sectors = partition_bytes / sector_bytes_u64;
    if partition_sectors <= primary.declared_sectors {
        return Err(NtfsBootRegionError::NoDedicatedBackupSector {
            partition_sectors,
            declared_sectors: primary.declared_sectors,
        });
    }

    let expected_backup_offset = partition_bytes - sector_bytes_u64;
    if backup_offset != expected_backup_offset {
        return Err(NtfsBootRegionError::BackupOffsetNotFinalSector {
            actual: backup_offset,
            expected: expected_backup_offset,
        });
    }

    let backup = parse_boot_sector(backup_sector)
        .map_err(|source| NtfsBootRegionError::InvalidBackup { source })?;

    if let Some((offset, (&primary_byte, &backup_byte))) = primary_sector
        .iter()
        .zip(backup_sector)
        .enumerate()
        .find(|(_, (primary_byte, backup_byte))| primary_byte != backup_byte)
    {
        return Err(NtfsBootRegionError::BootSectorsDiffer {
            offset,
            primary: primary_byte,
            backup: backup_byte,
        });
    }

    Ok(NtfsBootRegion {
        primary,
        backup,
        partition_bytes,
        partition_sectors,
        backup_offset,
        unaddressed_trailing_sectors: partition_sectors - primary.declared_sectors - 1,
    })
}

const fn validate_slice_len(
    copy: BootSectorCopy,
    bytes: &[u8],
    required: usize,
) -> Result<(), NtfsBootRegionError> {
    if bytes.len() != required {
        return Err(NtfsBootRegionError::WrongSectorSliceLength {
            copy,
            actual: bytes.len(),
            required,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DECLARED_SECTORS: u64 = 4_095;

    fn boot_sector(bytes_per_sector: u16) -> Vec<u8> {
        let mut boot = vec![0_u8; usize::from(bytes_per_sector)];
        boot[0..3].copy_from_slice(&[0xeb, 0x52, 0x90]);
        boot[3..11].copy_from_slice(b"NTFS    ");
        boot[11..13].copy_from_slice(&bytes_per_sector.to_le_bytes());
        boot[13] = 8;
        boot[21] = 0xf8;
        boot[24..26].copy_from_slice(&63_u16.to_le_bytes());
        boot[26..28].copy_from_slice(&255_u16.to_le_bytes());
        boot[28..32].copy_from_slice(&2_048_u32.to_le_bytes());
        boot[40..48].copy_from_slice(
            &i64::try_from(DECLARED_SECTORS)
                .expect("test geometry fits i64")
                .to_le_bytes(),
        );
        boot[48..56].copy_from_slice(&4_i64.to_le_bytes());
        boot[56..64].copy_from_slice(&8_i64.to_le_bytes());
        boot[64] = (-12_i8).to_ne_bytes()[0];
        boot[68] = (-12_i8).to_ne_bytes()[0];
        boot[72..80].copy_from_slice(&0x0123_4567_89ab_cdef_u64.to_le_bytes());
        boot[80..84].copy_from_slice(&0x1122_3344_u32.to_le_bytes());
        boot[510..512].copy_from_slice(&0xaa55_u16.to_le_bytes());
        boot
    }

    fn exact_partition_bytes(bytes_per_sector: u16) -> u64 {
        (DECLARED_SECTORS + 1) * u64::from(bytes_per_sector)
    }

    #[test]
    fn validates_exact_modern_layout() {
        let primary = boot_sector(512);
        let partition_bytes = exact_partition_bytes(512);
        let backup_offset = partition_bytes - 512;

        let region = validate_boot_region(&primary, &primary, partition_bytes, backup_offset)
            .expect("matching modern boot sectors");

        assert_eq!(region.partition_sectors, DECLARED_SECTORS + 1);
        assert_eq!(region.backup_offset, DECLARED_SECTORS * 512);
        assert_eq!(region.unaddressed_trailing_sectors, 0);
        assert_eq!(region.primary, region.backup);
    }

    #[test]
    fn supports_all_parser_sector_sizes_and_compares_the_whole_sector() {
        for sector_size in [512_u16, 1_024, 2_048, 4_096] {
            let mut primary = boot_sector(sector_size);
            let compared_offset = if sector_size == 512 {
                509
            } else {
                usize::from(sector_size) - 1
            };
            primary[compared_offset] = 0x5a;
            let backup = primary.clone();
            let partition_bytes = exact_partition_bytes(sector_size);

            let region = validate_boot_region(
                &primary,
                &backup,
                partition_bytes,
                partition_bytes - u64::from(sector_size),
            )
            .expect("matching full logical sectors");
            assert_eq!(region.primary.bytes_per_sector, sector_size);

            let mut mismatched_tail = backup;
            mismatched_tail[compared_offset] ^= 1;
            assert_eq!(
                validate_boot_region(
                    &primary,
                    &mismatched_tail,
                    partition_bytes,
                    partition_bytes - u64::from(sector_size),
                ),
                Err(NtfsBootRegionError::BootSectorsDiffer {
                    offset: compared_offset,
                    primary: 0x5a,
                    backup: 0x5b,
                })
            );
        }
    }

    #[test]
    fn permits_post_resize_unaddressed_sectors_but_requires_actual_last_sector() {
        let primary = boot_sector(512);
        let partition_sectors = DECLARED_SECTORS + 17;
        let partition_bytes = partition_sectors * 512;
        let expected_offset = partition_bytes - 512;

        let region = validate_boot_region(&primary, &primary, partition_bytes, expected_offset)
            .expect("enlarged partition with final-sector backup");
        assert_eq!(region.unaddressed_trailing_sectors, 16);

        let declared_end = DECLARED_SECTORS * 512;
        assert_eq!(
            validate_boot_region(&primary, &primary, partition_bytes, declared_end),
            Err(NtfsBootRegionError::BackupOffsetNotFinalSector {
                actual: declared_end,
                expected: expected_offset,
            })
        );
    }

    #[test]
    fn rejects_invalid_primary_before_trusting_its_geometry() {
        let mut primary = boot_sector(512);
        primary[3] = b'X';
        let backup = boot_sector(512);

        assert!(matches!(
            validate_boot_region(
                &primary,
                &backup,
                exact_partition_bytes(512),
                DECLARED_SECTORS * 512
            ),
            Err(NtfsBootRegionError::InvalidPrimary {
                source: NtfsBootSectorError::InvalidOemId { .. }
            })
        ));
    }

    #[test]
    fn rejects_truncated_primary_as_a_primary_parse_error() {
        let primary = vec![0_u8; 511];
        let backup = boot_sector(512);

        assert_eq!(
            validate_boot_region(
                &primary,
                &backup,
                exact_partition_bytes(512),
                DECLARED_SECTORS * 512
            ),
            Err(NtfsBootRegionError::InvalidPrimary {
                source: NtfsBootSectorError::Truncated {
                    actual: 511,
                    required: 512,
                },
            })
        );
    }

    #[test]
    fn requires_exact_bounded_sector_slices() {
        let primary_4k = boot_sector(4_096);
        let backup_4k = primary_4k.clone();
        let partition_bytes = exact_partition_bytes(4_096);
        let backup_offset = partition_bytes - 4_096;

        assert_eq!(
            validate_boot_region(
                &primary_4k[..512],
                &backup_4k,
                partition_bytes,
                backup_offset,
            ),
            Err(NtfsBootRegionError::WrongSectorSliceLength {
                copy: BootSectorCopy::Primary,
                actual: 512,
                required: 4_096,
            })
        );

        let mut oversized_backup = backup_4k;
        oversized_backup.push(0);
        assert_eq!(
            validate_boot_region(
                &primary_4k,
                &oversized_backup,
                partition_bytes,
                backup_offset,
            ),
            Err(NtfsBootRegionError::WrongSectorSliceLength {
                copy: BootSectorCopy::Backup,
                actual: 4_097,
                required: 4_096,
            })
        );
    }

    #[test]
    fn rejects_unaligned_partition_boundaries() {
        let primary = boot_sector(512);
        let partition_bytes = exact_partition_bytes(512) + 1;

        assert_eq!(
            validate_boot_region(&primary, &primary, partition_bytes, partition_bytes - 512),
            Err(NtfsBootRegionError::PartitionLengthNotSectorAligned {
                partition_bytes,
                bytes_per_sector: 512,
            })
        );
    }

    #[test]
    fn rejects_views_without_a_dedicated_final_backup_sector() {
        let primary = boot_sector(512);

        for partition_sectors in [DECLARED_SECTORS - 1, DECLARED_SECTORS] {
            let partition_bytes = partition_sectors * 512;
            assert_eq!(
                validate_boot_region(&primary, &primary, partition_bytes, partition_bytes - 512,),
                Err(NtfsBootRegionError::NoDedicatedBackupSector {
                    partition_sectors,
                    declared_sectors: DECLARED_SECTORS,
                })
            );
        }
    }

    #[test]
    fn independently_rejects_a_malformed_backup() {
        let primary = boot_sector(512);
        let mut backup = primary.clone();
        backup[510..512].copy_from_slice(&0_u16.to_le_bytes());
        let partition_bytes = exact_partition_bytes(512);

        assert_eq!(
            validate_boot_region(&primary, &backup, partition_bytes, partition_bytes - 512,),
            Err(NtfsBootRegionError::InvalidBackup {
                source: NtfsBootSectorError::InvalidBootSignature { found: 0 },
            })
        );
    }

    #[test]
    fn rejects_valid_copies_with_any_fixed_header_difference() {
        let primary = boot_sector(512);
        let mut backup = primary.clone();
        backup[72] ^= 1;
        let partition_bytes = exact_partition_bytes(512);

        assert_eq!(
            validate_boot_region(&primary, &backup, partition_bytes, partition_bytes - 512,),
            Err(NtfsBootRegionError::BootSectorsDiffer {
                offset: 72,
                primary: 0xef,
                backup: 0xee,
            })
        );
    }

    #[test]
    fn rejects_valid_copies_with_a_bootstrap_difference() {
        let mut primary = boot_sector(512);
        primary[100] = 0xa5;
        let mut backup = primary.clone();
        backup[100] = 0x5a;
        let partition_bytes = exact_partition_bytes(512);

        assert_eq!(
            validate_boot_region(&primary, &backup, partition_bytes, partition_bytes - 512,),
            Err(NtfsBootRegionError::BootSectorsDiffer {
                offset: 100,
                primary: 0xa5,
                backup: 0x5a,
            })
        );
    }
}
