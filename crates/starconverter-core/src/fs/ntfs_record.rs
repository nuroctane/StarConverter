//! Bounded, read-only validation of NTFS `FILE` records.
//!
//! NTFS protects each logical sector in a metadata record with a multi-sector transfer update
//! sequence. This module verifies that protection before interpreting the variable-length
//! attribute area. It never performs I/O and never mutates caller-owned bytes.

use std::fmt;

/// Smallest supported `FILE` record header (the NTFS 1.x through 3.0 layout).
pub const MIN_FILE_RECORD_HEADER_LEN: usize = 42;

/// Largest record this parser will copy and validate.
///
/// The cap is independent of any on-disk length field, so corrupt input cannot request an
/// unbounded allocation.
pub const MAX_FILE_RECORD_SIZE: usize = 16 * 1024 * 1024;

/// Update-sequence stride defined by NTFS, independent of the volume's reported sector size.
pub const UPDATE_SEQUENCE_STRIDE: usize = 512;

const FILE_MAGIC: [u8; 4] = *b"FILE";
const NTFS_31_HEADER_LEN: usize = 48;
const ATTRIBUTE_HEADER_LEN: usize = 16;
const ATTRIBUTE_END: u32 = 0xffff_ffff;
const KNOWN_FLAGS: u16 = 0x000f;

/// NTFS record-header generation identified from the update-sequence location.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileRecordHeaderVersion {
    /// NTFS 1.x through 3.0 header without an embedded record number.
    Legacy,
    /// NTFS 3.1+ header with reserved and record-number fields.
    Ntfs31,
}

/// Decoded NTFS MFT reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MftReference {
    /// Low 48-bit MFT record number.
    pub record_number: u64,
    /// High 16-bit sequence number used to detect stale references.
    pub sequence_number: u16,
}

/// Decoded `FILE` record flags, including unknown bits for lossless inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileRecordFlags {
    pub raw: u16,
    /// Bits not currently defined by NTFS-3G's public layout.
    pub unknown_bits: u16,
}

impl FileRecordFlags {
    #[must_use]
    pub const fn is_in_use(self) -> bool {
        self.raw & 0x0001 != 0
    }

    #[must_use]
    pub const fn is_directory(self) -> bool {
        self.raw & 0x0002 != 0
    }

    #[must_use]
    pub const fn is_metadata(self) -> bool {
        self.raw & 0x0004 != 0
    }

    #[must_use]
    pub const fn is_view_index(self) -> bool {
        self.raw & 0x0008 != 0
    }
}

/// A validated `FILE` record and a repaired, caller-independent byte image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsFileRecord {
    repaired: Vec<u8>,
    pub header_version: FileRecordHeaderVersion,
    pub update_sequence_offset: u16,
    pub update_sequence_count: u16,
    pub log_file_sequence_number: u64,
    pub sequence_number: u16,
    pub hard_link_count: u16,
    pub attributes_offset: u16,
    pub flags: FileRecordFlags,
    pub bytes_in_use: u32,
    pub bytes_allocated: u32,
    pub base_record: Option<MftReference>,
    pub next_attribute_id: u16,
    /// Present only for an NTFS 3.1+ header.
    pub record_number: Option<u32>,
    pub attribute_count: usize,
    pub end_marker_offset: usize,
}

impl NtfsFileRecord {
    /// Returns the bounded copy after update-sequence fixups have been applied.
    #[must_use]
    pub fn repaired_bytes(&self) -> &[u8] {
        &self.repaired
    }
}

/// Reason an NTFS `FILE` record could not be safely interpreted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NtfsFileRecordError {
    Truncated {
        actual: usize,
        required: usize,
    },
    RecordTooLarge {
        actual: usize,
        maximum: usize,
    },
    RecordSizeNotStrideAligned {
        record_size: usize,
        stride: usize,
    },
    InvalidMagic {
        found: [u8; 4],
    },
    InvalidUpdateSequenceOffset {
        value: u16,
    },
    InvalidUpdateSequenceCount {
        found: u16,
        expected: usize,
    },
    UpdateSequenceArrayOutOfBounds {
        offset: usize,
        length: usize,
        first_sector_limit: usize,
    },
    UpdateSequenceOverlapsAttributes {
        update_sequence_end: usize,
        attributes_offset: usize,
    },
    FixupMismatch {
        sector: usize,
        found: u16,
        expected: u16,
    },
    InvalidAllocatedSize {
        found: u32,
        record_size: usize,
    },
    InvalidUsedSize {
        found: u32,
        minimum: usize,
        allocated: u32,
    },
    UsedSizeNotEightByteAligned {
        value: u32,
    },
    InvalidAttributeOffset {
        value: u16,
        minimum: usize,
        used: u32,
    },
    AttributeOffsetNotEightByteAligned {
        value: u16,
    },
    ReservedFieldNotZero {
        value: u16,
    },
    TruncatedAttributeHeader {
        offset: usize,
        remaining: usize,
    },
    InvalidAttributeType {
        offset: usize,
        value: u32,
    },
    AttributeTypesOutOfOrder {
        offset: usize,
        previous: u32,
        current: u32,
    },
    InvalidAttributeLength {
        offset: usize,
        value: u32,
        remaining: usize,
    },
    InvalidNonResidentFlag {
        offset: usize,
        value: u8,
    },
    MissingEndMarker {
        attributes_offset: usize,
        used: u32,
    },
}

impl fmt::Display for NtfsFileRecordError {
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { actual, required } => {
                write!(
                    formatter,
                    "NTFS FILE record is truncated: got {actual} bytes, need at least {required}"
                )
            }
            Self::RecordTooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "NTFS FILE record size {actual} exceeds the {maximum}-byte parser cap"
                )
            }
            Self::RecordSizeNotStrideAligned {
                record_size,
                stride,
            } => write!(
                formatter,
                "NTFS FILE record size {record_size} is not a multiple of update-sequence stride {stride}"
            ),
            Self::InvalidMagic { found } => {
                write!(formatter, "invalid NTFS FILE signature: {found:02x?}")
            }
            Self::InvalidUpdateSequenceOffset { value } => {
                write!(formatter, "invalid update-sequence array offset: {value}")
            }
            Self::InvalidUpdateSequenceCount { found, expected } => write!(
                formatter,
                "invalid update-sequence count {found}; expected {expected}"
            ),
            Self::UpdateSequenceArrayOutOfBounds {
                offset,
                length,
                first_sector_limit,
            } => write!(
                formatter,
                "update-sequence array at {offset} with length {length} exceeds first-sector limit {first_sector_limit}"
            ),
            Self::UpdateSequenceOverlapsAttributes {
                update_sequence_end,
                attributes_offset,
            } => write!(
                formatter,
                "update-sequence array ending at {update_sequence_end} overlaps attributes beginning at {attributes_offset}"
            ),
            Self::FixupMismatch {
                sector,
                found,
                expected,
            } => write!(
                formatter,
                "NTFS multi-sector fixup mismatch in sector {sector}: found 0x{found:04x}, expected 0x{expected:04x}"
            ),
            Self::InvalidAllocatedSize { found, record_size } => write!(
                formatter,
                "FILE header allocation size {found} does not equal supplied record size {record_size}"
            ),
            Self::InvalidUsedSize {
                found,
                minimum,
                allocated,
            } => write!(
                formatter,
                "invalid FILE bytes-in-use value {found}; expected {minimum}..={allocated}"
            ),
            Self::UsedSizeNotEightByteAligned { value } => {
                write!(
                    formatter,
                    "FILE bytes-in-use value {value} is not 8-byte aligned"
                )
            }
            Self::InvalidAttributeOffset {
                value,
                minimum,
                used,
            } => write!(
                formatter,
                "invalid first-attribute offset {value}; expected {minimum}..{used}"
            ),
            Self::AttributeOffsetNotEightByteAligned { value } => {
                write!(
                    formatter,
                    "first-attribute offset {value} is not 8-byte aligned"
                )
            }
            Self::ReservedFieldNotZero { value } => {
                write!(
                    formatter,
                    "NTFS 3.1 FILE reserved field is nonzero: {value}"
                )
            }
            Self::TruncatedAttributeHeader { offset, remaining } => write!(
                formatter,
                "attribute header at {offset} is truncated: only {remaining} bytes remain"
            ),
            Self::InvalidAttributeType { offset, value } => {
                write!(
                    formatter,
                    "invalid attribute type 0x{value:08x} at {offset}"
                )
            }
            Self::AttributeTypesOutOfOrder {
                offset,
                previous,
                current,
            } => write!(
                formatter,
                "attribute type 0x{current:08x} at {offset} follows 0x{previous:08x} out of order"
            ),
            Self::InvalidAttributeLength {
                offset,
                value,
                remaining,
            } => write!(
                formatter,
                "invalid attribute length {value} at {offset}; {remaining} record bytes remain"
            ),
            Self::InvalidNonResidentFlag { offset, value } => {
                write!(
                    formatter,
                    "invalid non-resident flag {value} in attribute at {offset}"
                )
            }
            Self::MissingEndMarker {
                attributes_offset,
                used,
            } => write!(
                formatter,
                "attribute list beginning at {attributes_offset} has no end marker within {used} used bytes"
            ),
        }
    }
}

impl std::error::Error for NtfsFileRecordError {}

/// Validates and repairs one complete NTFS `FILE` record in bounded memory.
///
/// `bytes` must contain exactly one record. The returned object owns a copy with sector trailers
/// restored from the update-sequence array. The input slice is never modified.
///
/// # Errors
///
/// Returns [`NtfsFileRecordError`] for unsupported geometry, malformed or inconsistent header
/// fields, an incomplete multi-sector transfer, or an invalid attribute-list boundary.
pub fn parse_file_record(bytes: &[u8]) -> Result<NtfsFileRecord, NtfsFileRecordError> {
    validate_input_geometry(bytes)?;

    let magic = array_4(bytes, 0);
    if magic != FILE_MAGIC {
        return Err(NtfsFileRecordError::InvalidMagic { found: magic });
    }

    let update_sequence_offset = le_u16(bytes, 4);
    let update_sequence_count = le_u16(bytes, 6);
    let header_version = validate_update_sequence_layout(
        bytes.len(),
        update_sequence_offset,
        update_sequence_count,
    )?;

    let attributes_offset = le_u16(bytes, 20);
    let bytes_in_use = le_u32(bytes, 24);
    let bytes_allocated = le_u32(bytes, 28);
    validate_header_sizes(
        bytes.len(),
        header_version,
        update_sequence_offset,
        update_sequence_count,
        attributes_offset,
        bytes_in_use,
        bytes_allocated,
    )?;

    let record_number = if header_version == FileRecordHeaderVersion::Ntfs31 {
        let reserved = le_u16(bytes, 42);
        if reserved != 0 {
            return Err(NtfsFileRecordError::ReservedFieldNotZero { value: reserved });
        }
        Some(le_u32(bytes, 44))
    } else {
        None
    };

    let mut repaired = bytes.to_vec();
    apply_update_sequence_fixups(
        bytes,
        &mut repaired,
        usize::from(update_sequence_offset),
        usize::from(update_sequence_count),
    )?;

    let Ok(used) = usize::try_from(bytes_in_use) else {
        return Err(NtfsFileRecordError::InvalidUsedSize {
            found: bytes_in_use,
            minimum: MIN_FILE_RECORD_HEADER_LEN,
            allocated: bytes_allocated,
        });
    };
    let (attribute_count, end_marker_offset) =
        validate_attribute_list(&repaired, usize::from(attributes_offset), used)?;

    let raw_flags = le_u16(&repaired, 22);
    let base_raw = le_u64(&repaired, 32);
    Ok(NtfsFileRecord {
        repaired,
        header_version,
        update_sequence_offset,
        update_sequence_count,
        log_file_sequence_number: le_u64(bytes, 8),
        sequence_number: le_u16(bytes, 16),
        hard_link_count: le_u16(bytes, 18),
        attributes_offset,
        flags: FileRecordFlags {
            raw: raw_flags,
            unknown_bits: raw_flags & !KNOWN_FLAGS,
        },
        bytes_in_use,
        bytes_allocated,
        base_record: (base_raw != 0).then(|| decode_mft_reference(base_raw)),
        next_attribute_id: le_u16(bytes, 40),
        record_number,
        attribute_count,
        end_marker_offset,
    })
}

const fn validate_input_geometry(bytes: &[u8]) -> Result<(), NtfsFileRecordError> {
    if bytes.len() < MIN_FILE_RECORD_HEADER_LEN {
        return Err(NtfsFileRecordError::Truncated {
            actual: bytes.len(),
            required: MIN_FILE_RECORD_HEADER_LEN,
        });
    }
    if bytes.len() > MAX_FILE_RECORD_SIZE {
        return Err(NtfsFileRecordError::RecordTooLarge {
            actual: bytes.len(),
            maximum: MAX_FILE_RECORD_SIZE,
        });
    }
    if bytes.len() % UPDATE_SEQUENCE_STRIDE != 0 {
        return Err(NtfsFileRecordError::RecordSizeNotStrideAligned {
            record_size: bytes.len(),
            stride: UPDATE_SEQUENCE_STRIDE,
        });
    }
    Ok(())
}

fn validate_update_sequence_layout(
    record_size: usize,
    offset: u16,
    count: u16,
) -> Result<FileRecordHeaderVersion, NtfsFileRecordError> {
    let offset = usize::from(offset);
    let version = if offset == MIN_FILE_RECORD_HEADER_LEN {
        FileRecordHeaderVersion::Legacy
    } else if offset >= NTFS_31_HEADER_LEN && offset % 2 == 0 {
        FileRecordHeaderVersion::Ntfs31
    } else {
        return Err(NtfsFileRecordError::InvalidUpdateSequenceOffset {
            value: u16::try_from(offset).expect("offset originated as u16"),
        });
    };

    let expected = 1 + record_size / UPDATE_SEQUENCE_STRIDE;
    if usize::from(count) != expected {
        return Err(NtfsFileRecordError::InvalidUpdateSequenceCount {
            found: count,
            expected,
        });
    }
    let array_length = usize::from(count) * 2;
    let array_end = offset + array_length;
    let first_sector_limit = UPDATE_SEQUENCE_STRIDE - 2;
    if array_end > first_sector_limit {
        return Err(NtfsFileRecordError::UpdateSequenceArrayOutOfBounds {
            offset,
            length: array_length,
            first_sector_limit,
        });
    }
    Ok(version)
}

fn validate_header_sizes(
    record_size: usize,
    version: FileRecordHeaderVersion,
    update_sequence_offset: u16,
    update_sequence_count: u16,
    attributes_offset: u16,
    bytes_in_use: u32,
    bytes_allocated: u32,
) -> Result<(), NtfsFileRecordError> {
    if usize::try_from(bytes_allocated).ok() != Some(record_size) {
        return Err(NtfsFileRecordError::InvalidAllocatedSize {
            found: bytes_allocated,
            record_size,
        });
    }
    let minimum_header = match version {
        FileRecordHeaderVersion::Legacy => MIN_FILE_RECORD_HEADER_LEN,
        FileRecordHeaderVersion::Ntfs31 => NTFS_31_HEADER_LEN,
    };
    let used = usize::try_from(bytes_in_use).unwrap_or(usize::MAX);
    if used < minimum_header + 4 || used > record_size {
        return Err(NtfsFileRecordError::InvalidUsedSize {
            found: bytes_in_use,
            minimum: minimum_header + 4,
            allocated: bytes_allocated,
        });
    }
    if bytes_in_use % 8 != 0 {
        return Err(NtfsFileRecordError::UsedSizeNotEightByteAligned {
            value: bytes_in_use,
        });
    }
    if attributes_offset % 8 != 0 {
        return Err(NtfsFileRecordError::AttributeOffsetNotEightByteAligned {
            value: attributes_offset,
        });
    }
    let attributes = usize::from(attributes_offset);
    if attributes < minimum_header || attributes + 4 > used {
        return Err(NtfsFileRecordError::InvalidAttributeOffset {
            value: attributes_offset,
            minimum: minimum_header,
            used: bytes_in_use,
        });
    }
    let update_sequence_end =
        usize::from(update_sequence_offset) + usize::from(update_sequence_count) * 2;
    if update_sequence_end > attributes {
        return Err(NtfsFileRecordError::UpdateSequenceOverlapsAttributes {
            update_sequence_end,
            attributes_offset: attributes,
        });
    }
    Ok(())
}

fn apply_update_sequence_fixups(
    protected: &[u8],
    repaired: &mut [u8],
    array_offset: usize,
    array_count: usize,
) -> Result<(), NtfsFileRecordError> {
    let update_sequence_number = le_u16(protected, array_offset);
    for sector_index in 0..array_count - 1 {
        let trailer_offset = (sector_index + 1) * UPDATE_SEQUENCE_STRIDE - 2;
        let found = le_u16(protected, trailer_offset);
        if found != update_sequence_number {
            return Err(NtfsFileRecordError::FixupMismatch {
                sector: sector_index,
                found,
                expected: update_sequence_number,
            });
        }
        let replacement_offset = array_offset + (sector_index + 1) * 2;
        repaired[trailer_offset..trailer_offset + 2]
            .copy_from_slice(&protected[replacement_offset..replacement_offset + 2]);
    }
    Ok(())
}

fn validate_attribute_list(
    repaired: &[u8],
    attributes_offset: usize,
    bytes_in_use: usize,
) -> Result<(usize, usize), NtfsFileRecordError> {
    let mut offset = attributes_offset;
    let mut count = 0_usize;
    let mut previous_type = 0x10_u32;
    while bytes_in_use.saturating_sub(offset) >= 4 {
        let attribute_type = le_u32(repaired, offset);
        if attribute_type == ATTRIBUTE_END {
            return Ok((count, offset));
        }
        let remaining = bytes_in_use - offset;
        if remaining < ATTRIBUTE_HEADER_LEN {
            return Err(NtfsFileRecordError::TruncatedAttributeHeader { offset, remaining });
        }
        if attribute_type == 0 {
            return Err(NtfsFileRecordError::InvalidAttributeType {
                offset,
                value: attribute_type,
            });
        }
        if attribute_type < previous_type {
            return Err(NtfsFileRecordError::AttributeTypesOutOfOrder {
                offset,
                previous: previous_type,
                current: attribute_type,
            });
        }
        let length = le_u32(repaired, offset + 4);
        let length_usize = usize::try_from(length).unwrap_or(usize::MAX);
        if length_usize < ATTRIBUTE_HEADER_LEN || length_usize > remaining || length % 8 != 0 {
            return Err(NtfsFileRecordError::InvalidAttributeLength {
                offset,
                value: length,
                remaining,
            });
        }
        let non_resident = repaired[offset + 8];
        if non_resident > 1 {
            return Err(NtfsFileRecordError::InvalidNonResidentFlag {
                offset,
                value: non_resident,
            });
        }
        previous_type = attribute_type;
        offset += length_usize;
        count += 1;
    }
    Err(NtfsFileRecordError::MissingEndMarker {
        attributes_offset,
        used: u32::try_from(bytes_in_use).unwrap_or(u32::MAX),
    })
}

const fn decode_mft_reference(raw: u64) -> MftReference {
    MftReference {
        record_number: raw & 0x0000_ffff_ffff_ffff,
        sequence_number: (raw >> 48) as u16,
    }
}

fn array_4(bytes: &[u8], offset: usize) -> [u8; 4] {
    let mut value = [0_u8; 4];
    value.copy_from_slice(&bytes[offset..offset + 4]);
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

const fn le_u64(bytes: &[u8], offset: usize) -> u64 {
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

    const SECTOR_SIZE: usize = 512;
    const RECORD_SIZE: usize = 1024;
    const USA_OFFSET: usize = 48;
    const ATTRIBUTES_OFFSET: usize = 56;

    fn valid_record() -> Vec<u8> {
        let mut record = vec![0_u8; RECORD_SIZE];
        record[0..4].copy_from_slice(&FILE_MAGIC);
        set_u16(
            &mut record,
            4,
            u16::try_from(USA_OFFSET).expect("test offset fits u16"),
        );
        set_u16(&mut record, 6, 3);
        record[8..16].copy_from_slice(&0x1122_3344_5566_7788_u64.to_le_bytes());
        set_u16(&mut record, 16, 7);
        set_u16(&mut record, 18, 2);
        set_u16(
            &mut record,
            20,
            u16::try_from(ATTRIBUTES_OFFSET).expect("test offset fits u16"),
        );
        set_u16(&mut record, 22, 0x8003);
        set_u32(&mut record, 24, 80);
        set_u32(
            &mut record,
            28,
            u32::try_from(RECORD_SIZE).expect("test size fits u32"),
        );
        record[32..40].copy_from_slice(&((9_u64 << 48) | 0x2a).to_le_bytes());
        set_u16(&mut record, 40, 12);
        set_u32(&mut record, 44, 99);

        let usn = 0xa55a_u16;
        set_u16(&mut record, USA_OFFSET, usn);
        set_u16(&mut record, USA_OFFSET + 2, 0x1234);
        set_u16(&mut record, USA_OFFSET + 4, 0x5678);
        set_u16(&mut record, SECTOR_SIZE - 2, usn);
        set_u16(&mut record, RECORD_SIZE - 2, usn);

        set_u32(&mut record, ATTRIBUTES_OFFSET, 0x10);
        set_u32(&mut record, ATTRIBUTES_OFFSET + 4, 16);
        record[ATTRIBUTES_OFFSET + 8] = 0;
        set_u32(&mut record, ATTRIBUTES_OFFSET + 16, ATTRIBUTE_END);
        record
    }

    fn set_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn set_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn repairs_valid_record_without_mutating_input() {
        let protected = valid_record();
        let parsed = parse_file_record(&protected).expect("valid FILE record");

        assert_eq!(protected, valid_record());
        assert_eq!(
            parsed.repaired_bytes()[SECTOR_SIZE - 2..SECTOR_SIZE],
            [0x34, 0x12]
        );
        assert_eq!(parsed.repaired_bytes()[RECORD_SIZE - 2..], [0x78, 0x56]);
        assert_eq!(parsed.header_version, FileRecordHeaderVersion::Ntfs31);
        assert_eq!(parsed.log_file_sequence_number, 0x1122_3344_5566_7788);
        assert_eq!(parsed.sequence_number, 7);
        assert_eq!(parsed.hard_link_count, 2);
        assert_eq!(parsed.flags.raw, 0x8003);
        assert!(parsed.flags.is_in_use() && parsed.flags.is_directory());
        assert_eq!(parsed.flags.unknown_bits, 0x8000);
        assert_eq!(
            parsed.base_record,
            Some(MftReference {
                record_number: 42,
                sequence_number: 9
            })
        );
        assert_eq!(parsed.next_attribute_id, 12);
        assert_eq!(parsed.record_number, Some(99));
        assert_eq!(parsed.attribute_count, 1);
        assert_eq!(parsed.end_marker_offset, 72);
    }

    #[test]
    fn accepts_legacy_header_without_record_number() {
        let mut record = valid_record();
        set_u16(&mut record, 4, 42);
        set_u16(&mut record, 20, 48);
        set_u32(&mut record, 24, 72);
        set_u16(&mut record, 42, 0xa55a);
        set_u16(&mut record, 44, 0x1234);
        set_u16(&mut record, 46, 0x5678);
        set_u32(&mut record, 48, 0x10);
        set_u32(&mut record, 52, 16);
        record[56] = 0;
        set_u32(&mut record, 64, ATTRIBUTE_END);

        let parsed = parse_file_record(&record).expect("valid legacy FILE record");
        assert_eq!(parsed.header_version, FileRecordHeaderVersion::Legacy);
        assert_eq!(parsed.record_number, None);
        assert_eq!(parsed.end_marker_offset, 64);
    }

    #[test]
    fn rejects_truncation_cap_bad_geometry_and_magic() {
        assert_eq!(
            parse_file_record(&[0_u8; 41]),
            Err(NtfsFileRecordError::Truncated {
                actual: 41,
                required: 42
            })
        );
        assert_eq!(
            parse_file_record(&vec![0_u8; MAX_FILE_RECORD_SIZE + 1]),
            Err(NtfsFileRecordError::RecordTooLarge {
                actual: MAX_FILE_RECORD_SIZE + 1,
                maximum: MAX_FILE_RECORD_SIZE,
            })
        );
        let mut odd_size = valid_record();
        odd_size.pop();
        assert_eq!(
            parse_file_record(&odd_size),
            Err(NtfsFileRecordError::RecordSizeNotStrideAligned {
                record_size: 1023,
                stride: 512,
            })
        );

        let mut magic = valid_record();
        magic[0..4].copy_from_slice(b"BAAD");
        assert_eq!(
            parse_file_record(&magic),
            Err(NtfsFileRecordError::InvalidMagic { found: *b"BAAD" })
        );
    }

    #[test]
    fn rejects_malformed_update_sequence_boundaries() {
        let mut odd_offset = valid_record();
        set_u16(&mut odd_offset, 4, 47);
        assert!(matches!(
            parse_file_record(&odd_offset),
            Err(NtfsFileRecordError::InvalidUpdateSequenceOffset { .. })
        ));

        let mut wrong_count = valid_record();
        set_u16(&mut wrong_count, 6, 2);
        assert_eq!(
            parse_file_record(&wrong_count),
            Err(NtfsFileRecordError::InvalidUpdateSequenceCount {
                found: 2,
                expected: 3
            })
        );

        let mut huge_offset = valid_record();
        set_u16(&mut huge_offset, 4, u16::MAX - 1);
        assert!(matches!(
            parse_file_record(&huge_offset),
            Err(NtfsFileRecordError::UpdateSequenceArrayOutOfBounds { .. })
        ));

        let mut overlap = valid_record();
        set_u16(&mut overlap, 20, 48);
        assert!(matches!(
            parse_file_record(&overlap),
            Err(NtfsFileRecordError::UpdateSequenceOverlapsAttributes { .. })
        ));
    }

    #[test]
    fn rejects_each_sector_fixup_mismatch() {
        for (offset, sector) in [(SECTOR_SIZE - 2, 0), (RECORD_SIZE - 2, 1)] {
            let mut record = valid_record();
            set_u16(&mut record, offset, 0xbeef);
            assert_eq!(
                parse_file_record(&record),
                Err(NtfsFileRecordError::FixupMismatch {
                    sector,
                    found: 0xbeef,
                    expected: 0xa55a,
                })
            );
        }
    }

    #[test]
    fn rejects_size_alignment_and_attribute_offset_errors() {
        let mut allocated = valid_record();
        set_u32(&mut allocated, 28, 2048);
        assert!(matches!(
            parse_file_record(&allocated),
            Err(NtfsFileRecordError::InvalidAllocatedSize { .. })
        ));

        for used in [40_u32, 81, 1025] {
            let mut record = valid_record();
            set_u32(&mut record, 24, used);
            assert!(parse_file_record(&record).is_err());
        }

        let mut misaligned = valid_record();
        set_u16(&mut misaligned, 20, 57);
        assert_eq!(
            parse_file_record(&misaligned),
            Err(NtfsFileRecordError::AttributeOffsetNotEightByteAligned { value: 57 })
        );

        let mut after_used = valid_record();
        set_u16(&mut after_used, 20, 80);
        assert!(matches!(
            parse_file_record(&after_used),
            Err(NtfsFileRecordError::InvalidAttributeOffset { .. })
        ));
    }

    #[test]
    fn rejects_nonzero_modern_reserved_field() {
        let mut record = valid_record();
        set_u16(&mut record, 42, 1);
        assert_eq!(
            parse_file_record(&record),
            Err(NtfsFileRecordError::ReservedFieldNotZero { value: 1 })
        );
    }

    #[test]
    fn validates_attribute_walk_and_end_marker() {
        let mut invalid_type = valid_record();
        set_u32(&mut invalid_type, ATTRIBUTES_OFFSET, 0);
        assert!(matches!(
            parse_file_record(&invalid_type),
            Err(NtfsFileRecordError::InvalidAttributeType { .. })
        ));

        let mut short_length = valid_record();
        set_u32(&mut short_length, ATTRIBUTES_OFFSET + 4, 8);
        assert!(matches!(
            parse_file_record(&short_length),
            Err(NtfsFileRecordError::InvalidAttributeLength { .. })
        ));

        let mut too_long = valid_record();
        set_u32(&mut too_long, ATTRIBUTES_OFFSET + 4, u32::MAX);
        assert!(matches!(
            parse_file_record(&too_long),
            Err(NtfsFileRecordError::InvalidAttributeLength { .. })
        ));

        let mut bad_flag = valid_record();
        bad_flag[ATTRIBUTES_OFFSET + 8] = 2;
        assert!(matches!(
            parse_file_record(&bad_flag),
            Err(NtfsFileRecordError::InvalidNonResidentFlag { .. })
        ));

        let mut missing_end = valid_record();
        set_u32(&mut missing_end, ATTRIBUTES_OFFSET + 16, 0x20);
        assert!(matches!(
            parse_file_record(&missing_end),
            Err(NtfsFileRecordError::TruncatedAttributeHeader { .. })
        ));
    }

    #[test]
    fn rejects_out_of_order_attributes() {
        let mut record = valid_record();
        set_u32(&mut record, 24, 96);
        set_u32(&mut record, ATTRIBUTES_OFFSET + 16, 0x05);
        set_u32(&mut record, ATTRIBUTES_OFFSET + 20, 16);
        set_u32(&mut record, ATTRIBUTES_OFFSET + 32, ATTRIBUTE_END);
        assert!(matches!(
            parse_file_record(&record),
            Err(NtfsFileRecordError::AttributeTypesOutOfOrder {
                previous: 0x10,
                current: 0x05,
                ..
            })
        ));
    }
}
