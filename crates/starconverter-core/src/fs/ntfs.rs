//! Allocation-free parsing of the fixed NTFS boot-sector header.
//!
//! This module only interprets caller-owned bytes. It performs no I/O and never allocates based on
//! values read from an image. The parser accepts a 512-byte boot-sector prefix; callers that have a
//! complete partition image can additionally call [`NtfsBootSector::validate_image_size`].

use std::fmt;

/// Number of bytes needed to recognize and parse an NTFS boot sector.
pub const NTFS_BOOT_SECTOR_PREFIX_LEN: usize = 512;

/// Largest NTFS cluster accepted by this parser's current support envelope.
pub const MAX_NTFS_CLUSTER_SIZE_BYTES: u64 = 2 * 1024 * 1024;

const NTFS_OEM_ID: [u8; 8] = *b"NTFS    ";
const BOOT_SIGNATURE: u16 = 0xaa55;

/// Identifies one of the two metadata locations stored in the boot sector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataFile {
    Mft,
    MftMirror,
}

impl fmt::Display for MetadataFile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Mft => "$MFT",
            Self::MftMirror => "$MFTMirr",
        })
    }
}

/// Identifies a boot-sector field that encodes a record size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordSizeKind {
    MftRecord,
    IndexBuffer,
}

impl fmt::Display for RecordSizeKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MftRecord => "MFT record",
            Self::IndexBuffer => "index buffer",
        })
    }
}

/// A validated NTFS record-size encoding and its decoded byte size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordSize {
    /// Signed value as stored in the boot sector.
    pub encoded: i8,
    /// Decoded record size in bytes.
    pub bytes: u64,
}

/// Validated geometry and identity fields from an NTFS boot sector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtfsBootSector {
    pub bytes_per_sector: u16,
    /// Decoded sector count. Large clusters may use NTFS's negative-power encoding on disk.
    pub sectors_per_cluster: u32,
    pub cluster_size_bytes: u64,
    /// Value stored in the NTFS `NumberOfSectors` field. NTFS reserves one following sector for
    /// the backup boot sector.
    pub declared_sectors: u64,
    pub cluster_count: u64,
    /// Byte length covered by `declared_sectors`, excluding the following backup boot sector.
    pub filesystem_bytes: u64,
    /// Minimum partition-image length, including the reserved backup boot sector.
    pub minimum_image_bytes: u64,
    pub mft_lcn: u64,
    pub mft_mirror_lcn: u64,
    pub mft_record_size: RecordSize,
    pub index_buffer_size: RecordSize,
    pub volume_serial_number: u64,
    pub boot_checksum: u32,
    pub media_descriptor: u8,
    pub sectors_per_track: u16,
    pub head_count: u16,
    pub hidden_sectors: u32,
}

impl NtfsBootSector {
    /// Checks that a partition image is long enough for the declared filesystem and its backup
    /// boot sector. Extra bytes are allowed so a bounded partition view can include trailing
    /// padding.
    ///
    /// # Errors
    ///
    /// Returns [`NtfsBootSectorError::ImageTooSmall`] when `image_len` does not cover the declared
    /// filesystem and its reserved backup boot sector.
    pub const fn validate_image_size(&self, image_len: u64) -> Result<(), NtfsBootSectorError> {
        if image_len < self.minimum_image_bytes {
            return Err(NtfsBootSectorError::ImageTooSmall {
                actual: image_len,
                required: self.minimum_image_bytes,
            });
        }
        Ok(())
    }
}

/// Reason a candidate NTFS boot sector could not be safely interpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtfsBootSectorError {
    Truncated {
        actual: usize,
        required: usize,
    },
    InvalidOemId {
        found: [u8; 8],
    },
    InvalidBootSignature {
        found: u16,
    },
    UnsupportedBytesPerSector {
        value: u16,
    },
    InvalidSectorsPerCluster {
        encoded: u8,
    },
    ClusterSizeTooLarge {
        bytes: u64,
        maximum: u64,
    },
    ReservedFieldNotZero {
        field: &'static str,
        value: u64,
    },
    InvalidTotalSectors {
        value: i64,
    },
    NoAddressableClusters {
        sectors: u64,
        sectors_per_cluster: u32,
    },
    GeometryOverflow {
        calculation: &'static str,
    },
    InvalidMetadataLcn {
        file: MetadataFile,
        value: i64,
        cluster_count: u64,
    },
    MetadataLocationsOverlap {
        lcn: u64,
    },
    MetadataRecordsOverlap {
        mft_offset: u64,
        mirror_offset: u64,
        record_bytes: u64,
    },
    InvalidRecordSizeEncoding {
        kind: RecordSizeKind,
        encoded: i8,
    },
    RecordSizeTooSmall {
        kind: RecordSizeKind,
        bytes: u64,
        bytes_per_sector: u16,
    },
    MetadataRecordOutOfBounds {
        file: MetadataFile,
        offset: u64,
        record_bytes: u64,
        filesystem_bytes: u64,
    },
    ImageTooSmall {
        actual: u64,
        required: u64,
    },
}

impl fmt::Display for NtfsBootSectorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { actual, required } => write!(
                formatter,
                "NTFS boot-sector prefix is truncated: got {actual} bytes, need {required}"
            ),
            Self::InvalidOemId { found } => {
                write!(formatter, "invalid NTFS OEM ID: {found:02x?}")
            }
            Self::InvalidBootSignature { found } => {
                write!(formatter, "invalid NTFS boot signature: 0x{found:04x}")
            }
            Self::UnsupportedBytesPerSector { value } => {
                write!(
                    formatter,
                    "unsupported NTFS bytes-per-sector value: {value}"
                )
            }
            Self::InvalidSectorsPerCluster { encoded } => write!(
                formatter,
                "invalid NTFS sectors-per-cluster encoding: 0x{encoded:02x}"
            ),
            Self::ClusterSizeTooLarge { bytes, maximum } => write!(
                formatter,
                "NTFS cluster size {bytes} exceeds the supported maximum {maximum}"
            ),
            Self::ReservedFieldNotZero { field, value } => {
                write!(formatter, "reserved NTFS field {field} is nonzero: {value}")
            }
            Self::InvalidTotalSectors { value } => {
                write!(formatter, "invalid NTFS total-sector count: {value}")
            }
            Self::NoAddressableClusters {
                sectors,
                sectors_per_cluster,
            } => write!(
                formatter,
                "NTFS geometry has no complete clusters: {sectors} sectors at {sectors_per_cluster} sectors per cluster"
            ),
            Self::GeometryOverflow { calculation } => {
                write!(
                    formatter,
                    "NTFS geometry overflow while calculating {calculation}"
                )
            }
            Self::InvalidMetadataLcn {
                file,
                value,
                cluster_count,
            } => write!(
                formatter,
                "invalid {file} LCN {value}; volume has {cluster_count} addressable clusters"
            ),
            Self::MetadataLocationsOverlap { lcn } => {
                write!(formatter, "$MFT and $MFTMirr both begin at LCN {lcn}")
            }
            Self::MetadataRecordsOverlap {
                mft_offset,
                mirror_offset,
                record_bytes,
            } => write!(
                formatter,
                "first $MFT and $MFTMirr records overlap: offsets {mft_offset} and {mirror_offset}, record size {record_bytes}"
            ),
            Self::InvalidRecordSizeEncoding { kind, encoded } => {
                write!(formatter, "invalid {kind} size encoding: {encoded}")
            }
            Self::RecordSizeTooSmall {
                kind,
                bytes,
                bytes_per_sector,
            } => write!(
                formatter,
                "decoded {kind} size {bytes} is smaller than a {bytes_per_sector}-byte sector"
            ),
            Self::MetadataRecordOutOfBounds {
                file,
                offset,
                record_bytes,
                filesystem_bytes,
            } => write!(
                formatter,
                "first {file} record at byte {offset} with length {record_bytes} exceeds the {filesystem_bytes}-byte filesystem"
            ),
            Self::ImageTooSmall { actual, required } => write!(
                formatter,
                "partition image is too small: got {actual} bytes, need at least {required}"
            ),
        }
    }
}

impl std::error::Error for NtfsBootSectorError {}

#[derive(Debug, Clone, Copy)]
struct Geometry {
    bytes_per_sector: u16,
    sectors_per_cluster: u32,
    cluster_size_bytes: u64,
    declared_sectors: u64,
    cluster_count: u64,
    filesystem_bytes: u64,
    minimum_image_bytes: u64,
}

/// Parses and validates the fixed 512-byte prefix of an NTFS boot sector.
///
/// The function performs no heap allocation and does not retain `bytes`. A longer slice is accepted,
/// but its length is not assumed to be the partition length; use
/// [`NtfsBootSector::validate_image_size`] when the caller has a complete partition image.
///
/// # Errors
///
/// Returns [`NtfsBootSectorError`] when the prefix is truncated, is not recognizable as NTFS, or
/// contains unsupported, inconsistent, out-of-bounds, or overflowing geometry.
pub fn parse_boot_sector(bytes: &[u8]) -> Result<NtfsBootSector, NtfsBootSectorError> {
    if bytes.len() < NTFS_BOOT_SECTOR_PREFIX_LEN {
        return Err(NtfsBootSectorError::Truncated {
            actual: bytes.len(),
            required: NTFS_BOOT_SECTOR_PREFIX_LEN,
        });
    }

    let oem_id = array_8(bytes, 3);
    if oem_id != NTFS_OEM_ID {
        return Err(NtfsBootSectorError::InvalidOemId { found: oem_id });
    }

    let signature = le_u16(bytes, 510);
    if signature != BOOT_SIGNATURE {
        return Err(NtfsBootSectorError::InvalidBootSignature { found: signature });
    }

    let geometry = parse_geometry(bytes)?;
    validate_reserved_fields(bytes)?;

    let mft_lcn = validate_lcn(MetadataFile::Mft, le_i64(bytes, 48), geometry.cluster_count)?;
    let mft_mirror_lcn = validate_lcn(
        MetadataFile::MftMirror,
        le_i64(bytes, 56),
        geometry.cluster_count,
    )?;
    if mft_lcn == mft_mirror_lcn {
        return Err(NtfsBootSectorError::MetadataLocationsOverlap { lcn: mft_lcn });
    }

    let mft_record_size = decode_record_size(
        RecordSizeKind::MftRecord,
        i8::from_ne_bytes([bytes[64]]),
        geometry.cluster_size_bytes,
        geometry.bytes_per_sector,
    )?;
    let index_buffer_size = decode_record_size(
        RecordSizeKind::IndexBuffer,
        i8::from_ne_bytes([bytes[68]]),
        geometry.cluster_size_bytes,
        geometry.bytes_per_sector,
    )?;

    validate_first_record_bounds(
        MetadataFile::Mft,
        mft_lcn,
        geometry.cluster_size_bytes,
        mft_record_size.bytes,
        geometry.filesystem_bytes,
    )?;
    validate_first_record_bounds(
        MetadataFile::MftMirror,
        mft_mirror_lcn,
        geometry.cluster_size_bytes,
        mft_record_size.bytes,
        geometry.filesystem_bytes,
    )?;
    validate_metadata_records_do_not_overlap(
        mft_lcn,
        mft_mirror_lcn,
        geometry.cluster_size_bytes,
        mft_record_size.bytes,
    )?;

    Ok(NtfsBootSector {
        bytes_per_sector: geometry.bytes_per_sector,
        sectors_per_cluster: geometry.sectors_per_cluster,
        cluster_size_bytes: geometry.cluster_size_bytes,
        declared_sectors: geometry.declared_sectors,
        cluster_count: geometry.cluster_count,
        filesystem_bytes: geometry.filesystem_bytes,
        minimum_image_bytes: geometry.minimum_image_bytes,
        mft_lcn,
        mft_mirror_lcn,
        mft_record_size,
        index_buffer_size,
        volume_serial_number: le_u64(bytes, 72),
        boot_checksum: le_u32(bytes, 80),
        media_descriptor: bytes[21],
        sectors_per_track: le_u16(bytes, 24),
        head_count: le_u16(bytes, 26),
        hidden_sectors: le_u32(bytes, 28),
    })
}

fn parse_geometry(bytes: &[u8]) -> Result<Geometry, NtfsBootSectorError> {
    let bytes_per_sector = le_u16(bytes, 11);
    if !matches!(bytes_per_sector, 512 | 1024 | 2048 | 4096) {
        return Err(NtfsBootSectorError::UnsupportedBytesPerSector {
            value: bytes_per_sector,
        });
    }

    let sectors_per_cluster = decode_sectors_per_cluster(bytes[13])?;
    let cluster_size_bytes = u64::from(bytes_per_sector)
        .checked_mul(u64::from(sectors_per_cluster))
        .ok_or(NtfsBootSectorError::GeometryOverflow {
            calculation: "cluster byte size",
        })?;
    if cluster_size_bytes > MAX_NTFS_CLUSTER_SIZE_BYTES {
        return Err(NtfsBootSectorError::ClusterSizeTooLarge {
            bytes: cluster_size_bytes,
            maximum: MAX_NTFS_CLUSTER_SIZE_BYTES,
        });
    }

    let signed_sectors = le_i64(bytes, 40);
    let declared_sectors =
        u64::try_from(signed_sectors).map_err(|_| NtfsBootSectorError::InvalidTotalSectors {
            value: signed_sectors,
        })?;
    if declared_sectors == 0 {
        return Err(NtfsBootSectorError::InvalidTotalSectors { value: 0 });
    }

    let cluster_count = declared_sectors / u64::from(sectors_per_cluster);
    if cluster_count == 0 {
        return Err(NtfsBootSectorError::NoAddressableClusters {
            sectors: declared_sectors,
            sectors_per_cluster,
        });
    }

    let filesystem_bytes = declared_sectors
        .checked_mul(u64::from(bytes_per_sector))
        .ok_or(NtfsBootSectorError::GeometryOverflow {
            calculation: "filesystem byte length",
        })?;
    let partition_sectors =
        declared_sectors
            .checked_add(1)
            .ok_or(NtfsBootSectorError::GeometryOverflow {
                calculation: "partition sector count",
            })?;
    let minimum_image_bytes = partition_sectors
        .checked_mul(u64::from(bytes_per_sector))
        .ok_or(NtfsBootSectorError::GeometryOverflow {
            calculation: "minimum partition-image byte length",
        })?;

    Ok(Geometry {
        bytes_per_sector,
        sectors_per_cluster,
        cluster_size_bytes,
        declared_sectors,
        cluster_count,
        filesystem_bytes,
        minimum_image_bytes,
    })
}

fn validate_reserved_fields(bytes: &[u8]) -> Result<(), NtfsBootSectorError> {
    validate_zero(bytes, 14, 2, "reserved sectors")?;
    validate_zero(bytes, 16, 1, "FAT count")?;
    validate_zero(bytes, 17, 2, "root-directory entries")?;
    validate_zero(bytes, 19, 2, "legacy 16-bit sector count")?;
    validate_zero(bytes, 22, 2, "legacy sectors per FAT")?;
    validate_zero(bytes, 32, 4, "legacy 32-bit sector count")?;
    validate_zero(bytes, 39, 1, "extended BPB reserved byte")?;
    validate_zero(bytes, 65, 3, "MFT record-size reserved bytes")?;
    validate_zero(bytes, 69, 3, "index buffer-size reserved bytes")
}

fn decode_sectors_per_cluster(encoded: u8) -> Result<u32, NtfsBootSectorError> {
    if encoded <= 128 && encoded.is_power_of_two() {
        return Ok(u32::from(encoded));
    }

    // NTFS-3G accepts the alternate signed encodings -16 through -3 (0xF0..=0xFD), decoded as
    // 2^(-encoded) sectors. The supported cluster-size ceiling below rejects results that are too
    // large for the current product envelope without ever shifting by an invalid amount.
    if (0xf0..=0xfd).contains(&encoded) {
        return Ok(1_u32 << (u32::from(256_u16 - u16::from(encoded))));
    }

    Err(NtfsBootSectorError::InvalidSectorsPerCluster { encoded })
}

fn validate_metadata_records_do_not_overlap(
    mft_lcn: u64,
    mirror_lcn: u64,
    cluster_size_bytes: u64,
    record_bytes: u64,
) -> Result<(), NtfsBootSectorError> {
    let mft_offset =
        mft_lcn
            .checked_mul(cluster_size_bytes)
            .ok_or(NtfsBootSectorError::GeometryOverflow {
                calculation: "$MFT byte offset",
            })?;
    let mirror_offset = mirror_lcn.checked_mul(cluster_size_bytes).ok_or(
        NtfsBootSectorError::GeometryOverflow {
            calculation: "$MFTMirr byte offset",
        },
    )?;
    let mft_end =
        mft_offset
            .checked_add(record_bytes)
            .ok_or(NtfsBootSectorError::GeometryOverflow {
                calculation: "$MFT first record end",
            })?;
    let mirror_end =
        mirror_offset
            .checked_add(record_bytes)
            .ok_or(NtfsBootSectorError::GeometryOverflow {
                calculation: "$MFTMirr first record end",
            })?;
    if mft_offset < mirror_end && mirror_offset < mft_end {
        return Err(NtfsBootSectorError::MetadataRecordsOverlap {
            mft_offset,
            mirror_offset,
            record_bytes,
        });
    }
    Ok(())
}

fn decode_record_size(
    kind: RecordSizeKind,
    encoded: i8,
    cluster_size_bytes: u64,
    bytes_per_sector: u16,
) -> Result<RecordSize, NtfsBootSectorError> {
    let bytes = if encoded > 0 && encoded.unsigned_abs().is_power_of_two() && encoded <= 64 {
        cluster_size_bytes
            .checked_mul(u64::from(encoded.unsigned_abs()))
            .ok_or(NtfsBootSectorError::GeometryOverflow {
                calculation: "record byte size",
            })?
    } else if (-31..=-9).contains(&encoded) {
        1_u64 << u32::from(encoded.unsigned_abs())
    } else {
        return Err(NtfsBootSectorError::InvalidRecordSizeEncoding { kind, encoded });
    };

    if bytes < u64::from(bytes_per_sector) {
        return Err(NtfsBootSectorError::RecordSizeTooSmall {
            kind,
            bytes,
            bytes_per_sector,
        });
    }

    Ok(RecordSize { encoded, bytes })
}

fn validate_lcn(
    file: MetadataFile,
    value: i64,
    cluster_count: u64,
) -> Result<u64, NtfsBootSectorError> {
    let lcn = u64::try_from(value).map_err(|_| NtfsBootSectorError::InvalidMetadataLcn {
        file,
        value,
        cluster_count,
    })?;
    if lcn == 0 || lcn >= cluster_count {
        return Err(NtfsBootSectorError::InvalidMetadataLcn {
            file,
            value,
            cluster_count,
        });
    }
    Ok(lcn)
}

fn validate_first_record_bounds(
    file: MetadataFile,
    lcn: u64,
    cluster_size_bytes: u64,
    record_bytes: u64,
    filesystem_bytes: u64,
) -> Result<(), NtfsBootSectorError> {
    let offset =
        lcn.checked_mul(cluster_size_bytes)
            .ok_or(NtfsBootSectorError::GeometryOverflow {
                calculation: "metadata byte offset",
            })?;
    let end = offset
        .checked_add(record_bytes)
        .ok_or(NtfsBootSectorError::GeometryOverflow {
            calculation: "metadata record end",
        })?;
    if end > filesystem_bytes {
        return Err(NtfsBootSectorError::MetadataRecordOutOfBounds {
            file,
            offset,
            record_bytes,
            filesystem_bytes,
        });
    }
    Ok(())
}

fn validate_zero(
    bytes: &[u8],
    offset: usize,
    len: usize,
    field: &'static str,
) -> Result<(), NtfsBootSectorError> {
    let value = match len {
        1 => u64::from(bytes[offset]),
        2 => u64::from(le_u16(bytes, offset)),
        3 => {
            u64::from(bytes[offset])
                | (u64::from(bytes[offset + 1]) << 8)
                | (u64::from(bytes[offset + 2]) << 16)
        }
        4 => u64::from(le_u32(bytes, offset)),
        _ => unreachable!("internal reserved-field width must be 1 through 4 bytes"),
    };
    if value != 0 {
        return Err(NtfsBootSectorError::ReservedFieldNotZero { field, value });
    }
    Ok(())
}

fn array_8(bytes: &[u8], offset: usize) -> [u8; 8] {
    let mut value = [0_u8; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    value
}

const fn le_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

const fn le_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn le_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(array_8(bytes, offset))
}

fn le_i64(bytes: &[u8], offset: usize) -> i64 {
    i64::from_le_bytes(array_8(bytes, offset))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_boot_sector() -> [u8; NTFS_BOOT_SECTOR_PREFIX_LEN] {
        let mut boot = [0_u8; NTFS_BOOT_SECTOR_PREFIX_LEN];
        boot[0..3].copy_from_slice(&[0xeb, 0x52, 0x90]);
        boot[3..11].copy_from_slice(&NTFS_OEM_ID);
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
        boot[80..84].copy_from_slice(&0x1020_3040_u32.to_le_bytes());
        boot[510..512].copy_from_slice(&BOOT_SIGNATURE.to_le_bytes());
        boot
    }

    fn set_i64(boot: &mut [u8], offset: usize, value: i64) {
        boot[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn parses_valid_standard_geometry_without_allocating_from_input() {
        let parsed = parse_boot_sector(&valid_boot_sector()).expect("valid NTFS boot sector");

        assert_eq!(parsed.bytes_per_sector, 512);
        assert_eq!(parsed.sectors_per_cluster, 8);
        assert_eq!(parsed.cluster_size_bytes, 4096);
        assert_eq!(parsed.declared_sectors, 2047);
        assert_eq!(parsed.cluster_count, 255);
        assert_eq!(parsed.filesystem_bytes, 2047 * 512);
        assert_eq!(parsed.minimum_image_bytes, 2048 * 512);
        assert_eq!(parsed.mft_lcn, 4);
        assert_eq!(parsed.mft_mirror_lcn, 128);
        assert_eq!(parsed.mft_record_size.bytes, 1024);
        assert_eq!(parsed.index_buffer_size.bytes, 4096);
        assert_eq!(parsed.volume_serial_number, 0x0123_4567_89ab_cdef);
        assert_eq!(parsed.boot_checksum, 0x1020_3040);
        assert_eq!(parsed.hidden_sectors, 2048);
    }

    #[test]
    fn accepts_all_supported_sector_sizes() {
        for sector_size in [512_u16, 1024, 2048, 4096] {
            let mut boot = valid_boot_sector();
            boot[11..13].copy_from_slice(&sector_size.to_le_bytes());
            boot[64] = (-12_i8).to_ne_bytes()[0];

            let parsed = parse_boot_sector(&boot).expect("supported sector size");
            assert_eq!(parsed.bytes_per_sector, sector_size);
        }
    }

    #[test]
    fn decodes_positive_and_negative_record_sizes() {
        let mut boot = valid_boot_sector();
        boot[64] = 2;
        boot[68] = (-12_i8).to_ne_bytes()[0];

        let parsed = parse_boot_sector(&boot).expect("valid record-size encodings");
        assert_eq!(
            parsed.mft_record_size,
            RecordSize {
                encoded: 2,
                bytes: 8192
            }
        );
        assert_eq!(
            parsed.index_buffer_size,
            RecordSize {
                encoded: -12,
                bytes: 4096,
            }
        );
    }

    #[test]
    fn accepts_large_cluster_sector_count_encoding_at_supported_limit() {
        let mut boot = valid_boot_sector();
        boot[11..13].copy_from_slice(&4096_u16.to_le_bytes());
        boot[13] = 0xf7; // 2^9 sectors = a 2 MiB cluster.
        set_i64(&mut boot, 40, 4095);
        set_i64(&mut boot, 48, 1);
        set_i64(&mut boot, 56, 2);
        boot[64] = (-12_i8).to_ne_bytes()[0];
        boot[68] = (-12_i8).to_ne_bytes()[0];

        let parsed = parse_boot_sector(&boot).expect("2 MiB NTFS cluster");
        assert_eq!(parsed.sectors_per_cluster, 512);
        assert_eq!(parsed.cluster_size_bytes, MAX_NTFS_CLUSTER_SIZE_BYTES);
    }

    #[test]
    fn accepts_alternate_negative_power_cluster_encoding() {
        let mut boot = valid_boot_sector();
        boot[13] = 0xf8; // 2^8 sectors = a 128 KiB cluster at 512-byte sectors.
        set_i64(&mut boot, 40, 4_095);
        set_i64(&mut boot, 48, 4);
        set_i64(&mut boot, 56, 8);

        let parsed = parse_boot_sector(&boot).expect("alternate cluster-size encoding");
        assert_eq!(parsed.sectors_per_cluster, 256);
        assert_eq!(parsed.cluster_size_bytes, 128 * 1024);
    }

    #[test]
    fn rejects_every_truncated_prefix_length_class() {
        let boot = valid_boot_sector();
        for len in [0, 3, 11, 64, 511] {
            assert_eq!(
                parse_boot_sector(&boot[..len]),
                Err(NtfsBootSectorError::Truncated {
                    actual: len,
                    required: NTFS_BOOT_SECTOR_PREFIX_LEN,
                })
            );
        }
    }

    #[test]
    fn rejects_wrong_oem_id_and_signature() {
        let mut wrong_oem = valid_boot_sector();
        wrong_oem[3..11].copy_from_slice(b"FAT32   ");
        assert!(matches!(
            parse_boot_sector(&wrong_oem),
            Err(NtfsBootSectorError::InvalidOemId { .. })
        ));

        let mut wrong_signature = valid_boot_sector();
        wrong_signature[510..512].copy_from_slice(&0x1234_u16.to_le_bytes());
        assert_eq!(
            parse_boot_sector(&wrong_signature),
            Err(NtfsBootSectorError::InvalidBootSignature { found: 0x1234 })
        );
    }

    #[test]
    fn rejects_unsupported_sector_sizes() {
        for sector_size in [0_u16, 256, 768, 8192] {
            let mut boot = valid_boot_sector();
            boot[11..13].copy_from_slice(&sector_size.to_le_bytes());
            assert_eq!(
                parse_boot_sector(&boot),
                Err(NtfsBootSectorError::UnsupportedBytesPerSector { value: sector_size })
            );
        }
    }

    #[test]
    fn rejects_invalid_cluster_encodings_and_oversized_clusters() {
        for encoded in [0_u8, 3, 127, 129, 0xe0, 0xee, 0xfe, 0xff] {
            let mut boot = valid_boot_sector();
            boot[13] = encoded;
            assert_eq!(
                parse_boot_sector(&boot),
                Err(NtfsBootSectorError::InvalidSectorsPerCluster { encoded })
            );
        }

        let mut oversized = valid_boot_sector();
        oversized[11..13].copy_from_slice(&4096_u16.to_le_bytes());
        oversized[13] = 0xf6; // 2^10 * 4096 = 4 MiB.
        assert_eq!(
            parse_boot_sector(&oversized),
            Err(NtfsBootSectorError::ClusterSizeTooLarge {
                bytes: 4 * 1024 * 1024,
                maximum: MAX_NTFS_CLUSTER_SIZE_BYTES,
            })
        );
    }

    #[test]
    fn permits_legacy_geometry_but_rejects_fields_reserved_by_ntfs() {
        let parsed = parse_boot_sector(&valid_boot_sector()).expect("legacy geometry is permitted");
        assert_eq!(parsed.sectors_per_track, 63);
        assert_eq!(parsed.head_count, 255);
        assert_eq!(parsed.hidden_sectors, 2048);

        for (offset, field) in [
            (14, "reserved sectors"),
            (16, "FAT count"),
            (17, "root-directory entries"),
            (19, "legacy 16-bit sector count"),
            (22, "legacy sectors per FAT"),
            (32, "legacy 32-bit sector count"),
            (39, "extended BPB reserved byte"),
            (65, "MFT record-size reserved bytes"),
            (69, "index buffer-size reserved bytes"),
        ] {
            let mut boot = valid_boot_sector();
            boot[offset] = 1;
            assert_eq!(
                parse_boot_sector(&boot),
                Err(NtfsBootSectorError::ReservedFieldNotZero { field, value: 1 })
            );
        }
    }

    #[test]
    fn rejects_zero_negative_and_clusterless_sector_counts() {
        for sector_count in [0_i64, -1] {
            let mut boot = valid_boot_sector();
            set_i64(&mut boot, 40, sector_count);
            assert_eq!(
                parse_boot_sector(&boot),
                Err(NtfsBootSectorError::InvalidTotalSectors {
                    value: sector_count,
                })
            );
        }

        let mut clusterless = valid_boot_sector();
        set_i64(&mut clusterless, 40, 7);
        assert_eq!(
            parse_boot_sector(&clusterless),
            Err(NtfsBootSectorError::NoAddressableClusters {
                sectors: 7,
                sectors_per_cluster: 8,
            })
        );
    }

    #[test]
    fn reports_geometry_multiplication_overflow() {
        let mut boot = valid_boot_sector();
        boot[11..13].copy_from_slice(&4096_u16.to_le_bytes());
        set_i64(&mut boot, 40, i64::MAX);

        assert_eq!(
            parse_boot_sector(&boot),
            Err(NtfsBootSectorError::GeometryOverflow {
                calculation: "filesystem byte length",
            })
        );
    }

    #[test]
    fn rejects_invalid_and_overlapping_metadata_locations() {
        for (offset, file) in [(48, MetadataFile::Mft), (56, MetadataFile::MftMirror)] {
            for lcn in [-1_i64, 0, 255, 256] {
                let mut boot = valid_boot_sector();
                set_i64(&mut boot, offset, lcn);
                assert!(matches!(
                    parse_boot_sector(&boot),
                    Err(NtfsBootSectorError::InvalidMetadataLcn {
                        file: found_file,
                        value,
                        cluster_count: 255,
                    }) if found_file == file && value == lcn
                ));
            }
        }

        let mut overlap = valid_boot_sector();
        set_i64(&mut overlap, 56, 4);
        assert_eq!(
            parse_boot_sector(&overlap),
            Err(NtfsBootSectorError::MetadataLocationsOverlap { lcn: 4 })
        );

        let mut range_overlap = valid_boot_sector();
        set_i64(&mut range_overlap, 48, 4);
        set_i64(&mut range_overlap, 56, 5);
        range_overlap[64] = 2;
        assert_eq!(
            parse_boot_sector(&range_overlap),
            Err(NtfsBootSectorError::MetadataRecordsOverlap {
                mft_offset: 16_384,
                mirror_offset: 20_480,
                record_bytes: 8_192,
            })
        );
    }

    #[test]
    fn rejects_malformed_record_and_index_encodings() {
        for (offset, kind) in [
            (64, RecordSizeKind::MftRecord),
            (68, RecordSizeKind::IndexBuffer),
        ] {
            for encoded in [0_i8, 3, 65, 127, -8, -32, i8::MIN] {
                let mut boot = valid_boot_sector();
                boot[offset] = encoded.to_ne_bytes()[0];
                assert_eq!(
                    parse_boot_sector(&boot),
                    Err(NtfsBootSectorError::InvalidRecordSizeEncoding { kind, encoded })
                );
            }
        }
    }

    #[test]
    fn rejects_record_smaller_than_sector_and_record_crossing_volume_end() {
        let mut too_small = valid_boot_sector();
        too_small[11..13].copy_from_slice(&4096_u16.to_le_bytes());
        too_small[64] = (-9_i8).to_ne_bytes()[0];
        assert_eq!(
            parse_boot_sector(&too_small),
            Err(NtfsBootSectorError::RecordSizeTooSmall {
                kind: RecordSizeKind::MftRecord,
                bytes: 512,
                bytes_per_sector: 4096,
            })
        );

        let mut out_of_bounds = valid_boot_sector();
        set_i64(&mut out_of_bounds, 56, 254);
        out_of_bounds[64] = 2;
        assert!(matches!(
            parse_boot_sector(&out_of_bounds),
            Err(NtfsBootSectorError::MetadataRecordOutOfBounds {
                file: MetadataFile::MftMirror,
                ..
            })
        ));
    }

    #[test]
    fn image_size_check_requires_backup_boot_sector_but_allows_padding() {
        let parsed = parse_boot_sector(&valid_boot_sector()).expect("valid NTFS boot sector");
        assert_eq!(
            parsed.validate_image_size(parsed.minimum_image_bytes - 1),
            Err(NtfsBootSectorError::ImageTooSmall {
                actual: parsed.minimum_image_bytes - 1,
                required: parsed.minimum_image_bytes,
            })
        );
        assert_eq!(
            parsed.validate_image_size(parsed.minimum_image_bytes),
            Ok(())
        );
        assert_eq!(
            parsed.validate_image_size(parsed.minimum_image_bytes + 4096),
            Ok(())
        );
    }

    #[test]
    fn longer_slice_does_not_implicitly_claim_to_be_a_complete_image() {
        let mut prefix_with_padding = vec![0_u8; 1024];
        prefix_with_padding[..512].copy_from_slice(&valid_boot_sector());
        let parsed = parse_boot_sector(&prefix_with_padding).expect("valid prefix in longer slice");
        let supplied_len =
            u64::try_from(prefix_with_padding.len()).expect("test slice length fits in u64");
        assert!(parsed.minimum_image_bytes > supplied_len);
    }
}
