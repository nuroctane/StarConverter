//! Validation of complete exFAT main and backup boot regions.
//!
//! This module implements the checksum and extended-boot-sector rules in
//! sections 3.1 through 3.4 of Microsoft's exFAT specification. It operates on
//! caller-owned memory only: there is no device access and every accepted input
//! is exactly 24 logical sectors (at most 96 KiB).

#![allow(clippy::module_name_repetitions)]

use core::fmt;

use super::exfat::{ExfatBootSector, ExfatBootSectorError, parse_boot_sector};

const MIN_BYTES_PER_SECTOR: usize = 512;
const MAX_BYTES_PER_SECTOR: usize = 4_096;
const SECTORS_PER_BOOT_REGION: usize = 12;
const CHECKSUMMED_SECTORS_PER_REGION: usize = 11;
const TOTAL_BOOT_REGION_SECTORS: usize = 24;
const FIRST_EXTENDED_BOOT_SECTOR: usize = 1;
const LAST_EXTENDED_BOOT_SECTOR: usize = 8;
const CHECKSUM_SECTOR: usize = 11;
const EXTENDED_BOOT_SIGNATURE: u32 = 0xAA55_0000;
const VOLUME_FLAGS_FIRST_OFFSET: usize = 106;
const VOLUME_FLAGS_SECOND_OFFSET: usize = 107;
const PERCENT_IN_USE_OFFSET: usize = 112;

/// Identifies one of the redundant exFAT boot regions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExfatBootRegionKind {
    Main,
    Backup,
}

impl fmt::Display for ExfatBootRegionKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Main => formatter.write_str("main"),
            Self::Backup => formatter.write_str("backup"),
        }
    }
}

/// A checksum-validated, structurally validated exFAT boot region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExfatBootRegionValidation {
    pub kind: ExfatBootRegionKind,
    pub boot_sector: ExfatBootSector,
    pub boot_checksum: u32,
}

/// Byte-level relationship between the main and backup boot regions.
///
/// The comparison excludes each checksum sector. The exFAT specification
/// expressly allows `VolumeFlags` and `PercentInUse` to change without a new
/// checksum and requires consumers to treat their backup copies as stale.
/// Consequently those three bytes are reported separately rather than as
/// divergence. Other divergence is diagnostic, not a validation error: the
/// specification also permits infrequent independent boot-code updates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExfatBootRegionComparison {
    Exact,
    EquivalentExceptStaleFields {
        volume_flags_differ: bool,
        percent_in_use_differs: bool,
    },
    Divergent {
        /// Byte offset within the corresponding 12-sector boot region.
        first_differing_byte: usize,
    },
}

/// Validated main and backup exFAT boot regions plus their correspondence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExfatBootRegionsValidation {
    pub main: ExfatBootRegionValidation,
    pub backup: ExfatBootRegionValidation,
    pub comparison: ExfatBootRegionComparison,
}

/// A complete-boot-region validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExfatBootRegionError {
    InvalidSectorSize {
        found: usize,
    },
    ArithmeticOverflow {
        operation: &'static str,
    },
    LengthMismatch {
        actual: usize,
        expected: usize,
    },
    InvalidBootSector {
        region: ExfatBootRegionKind,
        source: ExfatBootSectorError,
    },
    InvalidExtendedBootSignature {
        region: ExfatBootRegionKind,
        /// Sector index within the corresponding 12-sector boot region.
        sector: usize,
        found: u32,
    },
    InvalidBootChecksumWord {
        region: ExfatBootRegionKind,
        /// Four-byte word index within the checksum sector.
        word: usize,
        expected: u32,
        found: u32,
    },
}

impl fmt::Display for ExfatBootRegionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSectorSize { found } => write!(
                formatter,
                "invalid exFAT logical-sector size {found}; expected 512, 1024, 2048, or 4096 bytes"
            ),
            Self::ArithmeticOverflow { operation } => {
                write!(formatter, "integer overflow while calculating {operation}")
            }
            Self::LengthMismatch { actual, expected } => write!(
                formatter,
                "exFAT boot-region input is {actual} bytes; expected exactly {expected} bytes"
            ),
            Self::InvalidBootSector { region, source } => {
                write!(formatter, "invalid exFAT {region} boot sector: {source}")
            }
            Self::InvalidExtendedBootSignature {
                region,
                sector,
                found,
            } => write!(
                formatter,
                "invalid exFAT {region} extended boot signature in region sector {sector}: found {found:#010X}, expected 0xAA550000"
            ),
            Self::InvalidBootChecksumWord {
                region,
                word,
                expected,
                found,
            } => write!(
                formatter,
                "invalid exFAT {region} boot checksum word {word}: found {found:#010X}, expected {expected:#010X}"
            ),
        }
    }
}

impl std::error::Error for ExfatBootRegionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidBootSector { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Validates both complete exFAT boot regions from an exact 24-sector slice.
///
/// Each region is independently checksum-validated before any contained field
/// is trusted. Each boot sector is then parsed and all eight extended boot
/// signatures are checked. Main/backup divergence outside the explicitly stale
/// fields is returned in [`ExfatBootRegionsValidation::comparison`] so recovery
/// policy can decide which verified copy to trust.
///
/// # Errors
///
/// Returns [`ExfatBootRegionError`] for an unsupported sector size, incorrect
/// slice length, arithmetic overflow, invalid region checksum, invalid boot
/// sector, or invalid extended boot signature.
pub fn validate_boot_regions(
    regions: &[u8],
    bytes_per_sector: usize,
) -> Result<ExfatBootRegionsValidation, ExfatBootRegionError> {
    validate_sector_size(bytes_per_sector)?;
    let expected_length = bytes_per_sector
        .checked_mul(TOTAL_BOOT_REGION_SECTORS)
        .ok_or(ExfatBootRegionError::ArithmeticOverflow {
            operation: "combined boot-region byte length",
        })?;
    if regions.len() != expected_length {
        return Err(ExfatBootRegionError::LengthMismatch {
            actual: regions.len(),
            expected: expected_length,
        });
    }

    let region_bytes = bytes_per_sector
        .checked_mul(SECTORS_PER_BOOT_REGION)
        .ok_or(ExfatBootRegionError::ArithmeticOverflow {
            operation: "single boot-region byte length",
        })?;
    let (main_bytes, backup_bytes) = regions.split_at(region_bytes);
    let main = validate_boot_region(main_bytes, bytes_per_sector, ExfatBootRegionKind::Main)?;
    let backup = validate_boot_region(backup_bytes, bytes_per_sector, ExfatBootRegionKind::Backup)?;

    Ok(ExfatBootRegionsValidation {
        main,
        backup,
        comparison: compare_regions(main_bytes, backup_bytes, bytes_per_sector),
    })
}

/// Validates one exact 12-sector exFAT boot-region slice.
///
/// This lower-level entry point is useful for recovery tooling when only one
/// redundant copy is readable. The caller supplies its role explicitly so any
/// corruption report remains unambiguous.
///
/// # Errors
///
/// Returns [`ExfatBootRegionError`] for an unsupported sector size, incorrect
/// slice length, arithmetic overflow, invalid checksum, invalid boot sector,
/// or invalid extended boot signature.
pub fn validate_boot_region(
    region: &[u8],
    bytes_per_sector: usize,
    kind: ExfatBootRegionKind,
) -> Result<ExfatBootRegionValidation, ExfatBootRegionError> {
    validate_sector_size(bytes_per_sector)?;
    let expected_length = bytes_per_sector
        .checked_mul(SECTORS_PER_BOOT_REGION)
        .ok_or(ExfatBootRegionError::ArithmeticOverflow {
            operation: "boot-region byte length",
        })?;
    if region.len() != expected_length {
        return Err(ExfatBootRegionError::LengthMismatch {
            actual: region.len(),
            expected: expected_length,
        });
    }

    let checksummed_bytes = bytes_per_sector
        .checked_mul(CHECKSUMMED_SECTORS_PER_REGION)
        .ok_or(ExfatBootRegionError::ArithmeticOverflow {
            operation: "checksummed boot-region byte length",
        })?;
    let checksum = boot_checksum(&region[..checksummed_bytes]);
    let checksum_sector_start = bytes_per_sector.checked_mul(CHECKSUM_SECTOR).ok_or(
        ExfatBootRegionError::ArithmeticOverflow {
            operation: "boot checksum sector offset",
        },
    )?;
    validate_checksum_sector(&region[checksum_sector_start..], checksum, kind)?;

    let boot_sector = parse_boot_sector(&region[..bytes_per_sector]).map_err(|source| {
        ExfatBootRegionError::InvalidBootSector {
            region: kind,
            source,
        }
    })?;

    for sector in FIRST_EXTENDED_BOOT_SECTOR..=LAST_EXTENDED_BOOT_SECTOR {
        let sector_start = sector.checked_mul(bytes_per_sector).ok_or(
            ExfatBootRegionError::ArithmeticOverflow {
                operation: "extended boot sector offset",
            },
        )?;
        let signature_start = sector_start
            .checked_add(bytes_per_sector - size_of::<u32>())
            .ok_or(ExfatBootRegionError::ArithmeticOverflow {
                operation: "extended boot signature offset",
            })?;
        let found = read_u32(region, signature_start);
        if found != EXTENDED_BOOT_SIGNATURE {
            return Err(ExfatBootRegionError::InvalidExtendedBootSignature {
                region: kind,
                sector,
                found,
            });
        }
    }

    Ok(ExfatBootRegionValidation {
        kind,
        boot_sector,
        boot_checksum: checksum,
    })
}

fn validate_sector_size(bytes_per_sector: usize) -> Result<(), ExfatBootRegionError> {
    if !bytes_per_sector.is_power_of_two()
        || !(MIN_BYTES_PER_SECTOR..=MAX_BYTES_PER_SECTOR).contains(&bytes_per_sector)
    {
        return Err(ExfatBootRegionError::InvalidSectorSize {
            found: bytes_per_sector,
        });
    }
    Ok(())
}

/// Implements the normative rotate-right-and-add algorithm over sectors 0..10.
fn boot_checksum(covered_sectors: &[u8]) -> u32 {
    covered_sectors
        .iter()
        .copied()
        .enumerate()
        .filter(|(index, _)| {
            !matches!(
                *index,
                VOLUME_FLAGS_FIRST_OFFSET | VOLUME_FLAGS_SECOND_OFFSET | PERCENT_IN_USE_OFFSET
            )
        })
        .fold(0_u32, |checksum, (_, byte)| {
            checksum.rotate_right(1).wrapping_add(u32::from(byte))
        })
}

fn validate_checksum_sector(
    sector: &[u8],
    expected: u32,
    kind: ExfatBootRegionKind,
) -> Result<(), ExfatBootRegionError> {
    for (word, bytes) in sector.chunks_exact(size_of::<u32>()).enumerate() {
        let found = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if found != expected {
            return Err(ExfatBootRegionError::InvalidBootChecksumWord {
                region: kind,
                word,
                expected,
                found,
            });
        }
    }
    Ok(())
}

fn compare_regions(
    main: &[u8],
    backup: &[u8],
    bytes_per_sector: usize,
) -> ExfatBootRegionComparison {
    let compared_bytes = bytes_per_sector * CHECKSUMMED_SECTORS_PER_REGION;
    let stale_offsets = [
        VOLUME_FLAGS_FIRST_OFFSET,
        VOLUME_FLAGS_SECOND_OFFSET,
        PERCENT_IN_USE_OFFSET,
    ];

    if let Some(first_differing_byte) = (0..compared_bytes)
        .find(|offset| !stale_offsets.contains(offset) && main[*offset] != backup[*offset])
    {
        return ExfatBootRegionComparison::Divergent {
            first_differing_byte,
        };
    }

    let volume_flags_differ = main[VOLUME_FLAGS_FIRST_OFFSET] != backup[VOLUME_FLAGS_FIRST_OFFSET]
        || main[VOLUME_FLAGS_SECOND_OFFSET] != backup[VOLUME_FLAGS_SECOND_OFFSET];
    let percent_in_use_differs = main[PERCENT_IN_USE_OFFSET] != backup[PERCENT_IN_USE_OFFSET];
    if volume_flags_differ || percent_in_use_differs {
        ExfatBootRegionComparison::EquivalentExceptStaleFields {
            volume_flags_differ,
            percent_in_use_differs,
        }
    } else {
        ExfatBootRegionComparison::Exact
    }
}

const fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXFAT_REVISION_1_00: u16 = 0x0100;
    const BOOT_SIGNATURE: u16 = 0xAA55;

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn sector_shift(bytes_per_sector: usize) -> u8 {
        u8::try_from(bytes_per_sector.ilog2()).expect("supported shift fits in u8")
    }

    fn valid_boot_sector(bytes_per_sector: usize) -> Vec<u8> {
        let mut sector = vec![0_u8; bytes_per_sector];
        sector[0..3].copy_from_slice(&[0xEB, 0x76, 0x90]);
        sector[3..11].copy_from_slice(b"EXFAT   ");
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
        sector[108] = sector_shift(bytes_per_sector);
        sector[109] = 3;
        sector[110] = 1;
        sector[111] = 0x80;
        sector[112] = 42;
        put_u16(&mut sector, 510, BOOT_SIGNATURE);
        sector
    }

    fn refresh_region_checksum(region: &mut [u8], bytes_per_sector: usize) {
        let covered_end = CHECKSUMMED_SECTORS_PER_REGION * bytes_per_sector;
        let checksum = boot_checksum(&region[..covered_end]);
        for word in region[covered_end..].chunks_exact_mut(size_of::<u32>()) {
            word.copy_from_slice(&checksum.to_le_bytes());
        }
    }

    fn valid_regions(bytes_per_sector: usize) -> Vec<u8> {
        let region_bytes = SECTORS_PER_BOOT_REGION * bytes_per_sector;
        let mut main = vec![0_u8; region_bytes];
        main[..bytes_per_sector].copy_from_slice(&valid_boot_sector(bytes_per_sector));
        for sector in FIRST_EXTENDED_BOOT_SECTOR..=LAST_EXTENDED_BOOT_SECTOR {
            let signature = sector * bytes_per_sector + bytes_per_sector - size_of::<u32>();
            put_u32(&mut main, signature, EXTENDED_BOOT_SIGNATURE);
        }
        refresh_region_checksum(&mut main, bytes_per_sector);

        let mut both = Vec::with_capacity(region_bytes * 2);
        both.extend_from_slice(&main);
        both.extend_from_slice(&main);
        both
    }

    #[test]
    fn validates_exact_512_byte_regions() {
        let regions = valid_regions(512);
        let result = validate_boot_regions(&regions, 512).expect("valid boot regions");

        assert_eq!(result.main.boot_sector.bytes_per_sector, 512);
        assert_eq!(result.backup.boot_sector.bytes_per_sector, 512);
        assert_eq!(result.main.boot_checksum, result.backup.boot_checksum);
        assert_eq!(result.comparison, ExfatBootRegionComparison::Exact);
    }

    #[test]
    fn validates_largest_supported_sector_size() {
        let mut regions = valid_regions(4_096);
        // Rebuild geometry for one-sector clusters at 4096 bytes per sector.
        for base in [0, SECTORS_PER_BOOT_REGION * 4_096] {
            put_u64(&mut regions, base + 72, 8_040);
            put_u32(&mut regions, base + 84, 8);
            put_u32(&mut regions, base + 88, 40);
            regions[base + 109] = 0;
            put_u32(&mut regions, base + 92, 8_000);
        }
        let (main, backup) = regions.split_at_mut(SECTORS_PER_BOOT_REGION * 4_096);
        refresh_region_checksum(main, 4_096);
        refresh_region_checksum(backup, 4_096);

        let result = validate_boot_regions(&regions, 4_096).expect("valid 4096-byte regions");
        assert_eq!(result.main.boot_sector.bytes_per_sector, 4_096);
        assert_eq!(result.comparison, ExfatBootRegionComparison::Exact);
    }

    #[test]
    fn validates_every_supported_intermediate_sector_size() {
        for bytes_per_sector in [1_024, 2_048] {
            let regions = valid_regions(bytes_per_sector);
            let result = validate_boot_regions(&regions, bytes_per_sector)
                .expect("supported logical-sector size");
            assert_eq!(
                result.main.boot_sector.bytes_per_sector,
                u32::try_from(bytes_per_sector).expect("supported sector size fits u32")
            );
        }
    }

    #[test]
    fn rejects_unsupported_sector_sizes_and_non_exact_lengths() {
        for invalid in [0, 256, 1_000, 8_192] {
            assert_eq!(
                validate_boot_regions(&[], invalid),
                Err(ExfatBootRegionError::InvalidSectorSize { found: invalid })
            );
        }

        let mut regions = valid_regions(512);
        regions.pop();
        assert_eq!(
            validate_boot_regions(&regions, 512),
            Err(ExfatBootRegionError::LengthMismatch {
                actual: 24 * 512 - 1,
                expected: 24 * 512,
            })
        );
        regions.push(0);
        regions.push(0);
        assert!(matches!(
            validate_boot_regions(&regions, 512),
            Err(ExfatBootRegionError::LengthMismatch { .. })
        ));
    }

    #[test]
    fn checksum_matches_normative_rotation_vector_and_exclusions() {
        let mut covered = vec![0_u8; CHECKSUMMED_SECTORS_PER_REGION * 512];
        covered[0] = 1;
        // The byte is followed by 5,628 included zero bytes, so the value is
        // rotated right by 28 (equivalently, left by four).
        assert_eq!(boot_checksum(&covered), 16);

        covered.fill(0);
        covered[VOLUME_FLAGS_FIRST_OFFSET] = 0xFF;
        covered[VOLUME_FLAGS_SECOND_OFFSET] = 0xFF;
        covered[PERCENT_IN_USE_OFFSET] = 0xFF;
        assert_eq!(boot_checksum(&covered), 0);

        covered.fill(0);
        *covered.last_mut().expect("non-empty test vector") = 1;
        assert_eq!(boot_checksum(&covered), 1);
    }

    #[test]
    fn excluded_stale_fields_may_differ_without_checksum_update() {
        let mut regions = valid_regions(512);
        let backup_base = SECTORS_PER_BOOT_REGION * 512;
        put_u16(&mut regions, backup_base + VOLUME_FLAGS_FIRST_OFFSET, 2);
        regions[backup_base + PERCENT_IN_USE_OFFSET] = 99;

        let result = validate_boot_regions(&regions, 512)
            .expect("excluded fields do not invalidate checksum");
        assert_eq!(
            result.comparison,
            ExfatBootRegionComparison::EquivalentExceptStaleFields {
                volume_flags_differ: true,
                percent_in_use_differs: true,
            }
        );
    }

    #[test]
    fn checksum_covers_boot_extended_oem_and_reserved_sectors() {
        for offset in [64, 3 * 512 + 7, 9 * 512 + 9, 10 * 512 + 11] {
            let mut regions = valid_regions(512);
            regions[offset] ^= 1;
            assert!(matches!(
                validate_boot_regions(&regions, 512),
                Err(ExfatBootRegionError::InvalidBootChecksumWord {
                    region: ExfatBootRegionKind::Main,
                    word: 0,
                    ..
                })
            ));
        }
    }

    #[test]
    fn every_checksum_word_must_repeat_the_computed_value() {
        let mut regions = valid_regions(512);
        let checksum_start = CHECKSUM_SECTOR * 512;
        regions[checksum_start + 4 * 73] ^= 1;

        assert!(matches!(
            validate_boot_regions(&regions, 512),
            Err(ExfatBootRegionError::InvalidBootChecksumWord {
                region: ExfatBootRegionKind::Main,
                word: 73,
                ..
            })
        ));
    }

    #[test]
    fn validates_all_extended_boot_signatures_in_both_regions() {
        for (kind, region_base) in [
            (ExfatBootRegionKind::Main, 0),
            (ExfatBootRegionKind::Backup, SECTORS_PER_BOOT_REGION * 512),
        ] {
            for sector in FIRST_EXTENDED_BOOT_SECTOR..=LAST_EXTENDED_BOOT_SECTOR {
                let mut regions = valid_regions(512);
                let signature = region_base + sector * 512 + 512 - size_of::<u32>();
                put_u32(&mut regions, signature, 0);
                let affected = &mut regions[region_base..region_base + 12 * 512];
                refresh_region_checksum(affected, 512);

                assert_eq!(
                    validate_boot_regions(&regions, 512),
                    Err(ExfatBootRegionError::InvalidExtendedBootSignature {
                        region: kind,
                        sector,
                        found: 0,
                    })
                );
            }
        }
    }

    #[test]
    fn validates_backup_boot_sector_fields_after_its_checksum() {
        let mut regions = valid_regions(512);
        let backup_base = SECTORS_PER_BOOT_REGION * 512;
        regions[backup_base + 3] = b'N';
        refresh_region_checksum(&mut regions[backup_base..], 512);

        assert!(matches!(
            validate_boot_regions(&regions, 512),
            Err(ExfatBootRegionError::InvalidBootSector {
                region: ExfatBootRegionKind::Backup,
                source: ExfatBootSectorError::InvalidFileSystemName { .. },
            })
        ));
    }

    #[test]
    fn reports_non_stale_divergence_without_discarding_verified_backup() {
        let mut regions = valid_regions(512);
        let backup_base = SECTORS_PER_BOOT_REGION * 512;
        let differing_byte = 9 * 512 + 5;
        regions[backup_base + differing_byte] = 0xA5;
        refresh_region_checksum(&mut regions[backup_base..], 512);

        let result = validate_boot_regions(&regions, 512)
            .expect("both independently valid regions remain usable");
        assert_eq!(
            result.comparison,
            ExfatBootRegionComparison::Divergent {
                first_differing_byte: differing_byte,
            }
        );
        assert_ne!(result.main.boot_checksum, result.backup.boot_checksum);
    }

    #[test]
    fn single_region_entry_point_is_bounded_and_role_aware() {
        let regions = valid_regions(1_024);
        let region_bytes = SECTORS_PER_BOOT_REGION * 1_024;
        let backup = &regions[region_bytes..];
        let result = validate_boot_region(backup, 1_024, ExfatBootRegionKind::Backup)
            .expect("valid backup region");

        assert_eq!(result.kind, ExfatBootRegionKind::Backup);
        assert_eq!(result.boot_sector.bytes_per_sector, 1_024);
        assert_eq!(
            validate_boot_region(
                &backup[..backup.len() - 1],
                1_024,
                ExfatBootRegionKind::Backup,
            ),
            Err(ExfatBootRegionError::LengthMismatch {
                actual: region_bytes - 1,
                expected: region_bytes,
            })
        );
    }
}
