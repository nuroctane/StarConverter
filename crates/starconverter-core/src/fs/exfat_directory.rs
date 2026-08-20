//! Allocation-bounded, read-only parsing for exFAT directory entries.
//!
//! The caller supplies an already-bounded directory byte slice, filesystem
//! geometry, and explicit entry limits. Parsing performs no I/O and no heap
//! allocation. Unknown benign entry sets are returned as borrowed raw bytes so
//! a future lossless writer can preserve them exactly; unknown critical entries
//! are refused.

#![allow(clippy::module_name_repetitions)]

use core::{char, fmt};

const ENTRY_BYTES: usize = 32;
const ENTRY_IN_USE: u8 = 0x80;
const ENTRY_SECONDARY: u8 = 0x40;
const ENTRY_BENIGN: u8 = 0x20;
const TYPE_ALLOCATION_BITMAP: u8 = 0x81;
const TYPE_UPCASE_TABLE: u8 = 0x82;
const TYPE_VOLUME_LABEL: u8 = 0x83;
const TYPE_FILE: u8 = 0x85;
const TYPE_STREAM_EXTENSION: u8 = 0xC0;
const TYPE_FILE_NAME: u8 = 0xC1;
const MAX_FILE_NAME_UNITS: usize = 255;
const MAX_DIRECTORY_BYTES: u64 = 256 * 1024 * 1024;
const VALID_FILE_ATTRIBUTES: u16 = 0x0037;
const DIRECTORY_ATTRIBUTE: u16 = 0x0010;

/// Explicit resource and geometry bounds for parsing one complete directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectoryContext {
    /// Number of addressable clusters in the Cluster Heap.
    pub cluster_count: u32,
    /// Bytes in one cluster.
    pub bytes_per_cluster: u32,
    /// Number of FATs (and, in the root, Allocation Bitmaps).
    pub number_of_fats: u8,
    /// Whether these bytes represent the root directory.
    pub is_root: bool,
    /// Maximum number of 32-byte entries the caller permits this parser to inspect.
    pub max_entries: usize,
    /// Maximum number of secondary entries permitted in any one entry set.
    pub max_secondary_entries: u8,
}

/// Summary of a successfully validated directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectorySummary {
    pub entries_examined: usize,
    pub records: usize,
    pub unused_entries: usize,
    pub reached_end_marker: bool,
    pub allocation_bitmaps: u8,
    pub upcase_tables: u8,
    pub volume_labels: u8,
    pub files: usize,
    pub benign_primary_sets: usize,
}

/// One allocation bitmap descriptor from the root directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllocationBitmapEntry {
    pub bitmap_identifier: u8,
    pub first_cluster: u32,
    pub data_length: u64,
}

/// The root directory's up-case table descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpcaseTableEntry {
    pub table_checksum: u32,
    pub first_cluster: u32,
    pub data_length: u64,
}

/// A fixed-capacity UTF-16 volume label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VolumeLabelEntry {
    units: [u16; 11],
    len: u8,
    /// Whether all unused UTF-16 fields contain the recommended zero padding.
    pub padding_zeroed: bool,
}

impl VolumeLabelEntry {
    /// Returns exactly the UTF-16 code units included in the label length.
    #[must_use]
    pub fn as_units(&self) -> &[u16] {
        &self.units[..usize::from(self.len)]
    }
}

/// A fixed-capacity UTF-16 exFAT file name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileName {
    units: [u16; MAX_FILE_NAME_UNITS],
    len: u8,
}

impl FileName {
    /// Returns exactly the UTF-16 code units named by `NameLength`.
    #[must_use]
    pub fn as_units(&self) -> &[u16] {
        &self.units[..usize::from(self.len)]
    }

    /// Returns the number of UTF-16 code units in this on-disk name.
    #[must_use]
    pub const fn len(&self) -> u8 {
        self.len
    }

    /// Returns whether the name contains no UTF-16 code units.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// A validated File/Stream Extension/File Name entry set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry<'a> {
    pub file_attributes: u16,
    pub create_timestamp: u32,
    pub modified_timestamp: u32,
    pub accessed_timestamp: u32,
    pub create_centiseconds: u8,
    pub modified_centiseconds: u8,
    pub create_utc_offset: u8,
    pub modified_utc_offset: u8,
    pub accessed_utc_offset: u8,
    pub is_directory: bool,
    pub no_fat_chain: bool,
    pub name_hash: u16,
    pub valid_data_length: u64,
    pub first_cluster: u32,
    pub data_length: u64,
    pub name: FileName,
    /// Whether all name slots beyond `NameLength` are zero, as recommended.
    pub name_padding_zeroed: bool,
    /// Count of benign secondary entries retained after the required name entries.
    pub benign_secondary_entries: u8,
    /// The exact primary and secondary bytes covered by `SetChecksum`.
    pub raw_set: &'a [u8],
}

/// A validated directory record delivered to the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
// The fixed UTF-16 buffer is intentional: boxing it would violate this
// parser's no-heap-allocation contract.
#[allow(clippy::large_enum_variant)]
pub enum DirectoryRecord<'a> {
    Unused {
        entry_type: u8,
        raw: &'a [u8],
    },
    AllocationBitmap(AllocationBitmapEntry),
    UpcaseTable(UpcaseTableEntry),
    VolumeLabel(VolumeLabelEntry),
    File(FileEntry<'a>),
    /// A benign primary set which must be preserved byte-for-byte.
    BenignPrimary {
        entry_type: u8,
        secondary_count: u8,
        raw_set: &'a [u8],
    },
}

/// Structural failure while parsing an exFAT directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectoryError {
    InvalidContext(&'static str),
    LengthNotEntryAligned {
        actual: usize,
    },
    EntryLimitExceeded {
        entries: usize,
        limit: usize,
    },
    InvalidEntryType {
        index: usize,
        entry_type: u8,
    },
    UnexpectedSecondary {
        index: usize,
        entry_type: u8,
    },
    UnknownCriticalEntry {
        index: usize,
        entry_type: u8,
    },
    CriticalSystemEntryOutsideRoot {
        index: usize,
        entry_type: u8,
    },
    EntrySetTruncated {
        index: usize,
        secondary_count: u8,
    },
    SecondaryLimitExceeded {
        index: usize,
        count: u8,
        limit: u8,
    },
    InvalidSetMember {
        index: usize,
        entry_type: u8,
    },
    SetChecksumMismatch {
        index: usize,
        stored: u16,
        computed: u16,
    },
    ReservedNotZero {
        index: usize,
        offset: usize,
        value: u8,
    },
    InvalidFlags {
        index: usize,
        value: u16,
    },
    InvalidTimestamp {
        index: usize,
        offset: usize,
        value: u32,
    },
    InvalidCluster {
        index: usize,
        cluster: u32,
    },
    InvalidDataLength {
        index: usize,
        length: u64,
    },
    InvalidBitmapIdentifier {
        index: usize,
        identifier: u8,
    },
    BitmapTooShort {
        index: usize,
        length: u64,
        required: u64,
    },
    InvalidVolumeLabelLength {
        index: usize,
        length: u8,
    },
    InvalidNameLength {
        index: usize,
        length: u8,
    },
    InvalidNameEntryCount {
        index: usize,
        expected: u8,
        found: u8,
    },
    InvalidNameCharacter {
        index: usize,
        code_unit: u16,
    },
    InvalidUtf16Name {
        index: usize,
    },
    ReservedFileName {
        index: usize,
    },
    InvalidValidDataLength {
        index: usize,
        valid: u64,
        data: u64,
    },
    DirectoryDataLengthMismatch {
        index: usize,
        valid: u64,
        data: u64,
    },
    DirectoryTooLarge {
        index: usize,
        length: u64,
    },
    ContiguousAllocationOutsideHeap {
        index: usize,
    },
    DuplicateAllocationBitmap {
        identifier: u8,
    },
    InvalidRootEntryCount {
        entry_type: u8,
        found: u8,
        expected: u8,
    },
    ArithmeticOverflow(&'static str),
}

impl fmt::Display for DirectoryError {
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::InvalidContext(reason) => {
                write!(formatter, "invalid exFAT directory context: {reason}")
            }
            Self::LengthNotEntryAligned { actual } => write!(
                formatter,
                "directory length {actual} is not a multiple of 32"
            ),
            Self::EntryLimitExceeded { entries, limit } => write!(
                formatter,
                "directory contains {entries} entries, exceeding limit {limit}"
            ),
            Self::InvalidEntryType { index, entry_type } => write!(
                formatter,
                "invalid entry type {entry_type:#04X} at directory index {index}"
            ),
            Self::UnexpectedSecondary { index, entry_type } => write!(
                formatter,
                "secondary entry {entry_type:#04X} appears outside a set at index {index}"
            ),
            Self::UnknownCriticalEntry { index, entry_type } => write!(
                formatter,
                "unrecognized critical entry {entry_type:#04X} at index {index}"
            ),
            Self::CriticalSystemEntryOutsideRoot { index, entry_type } => write!(
                formatter,
                "critical system entry {entry_type:#04X} occurs outside the root at index {index}"
            ),
            Self::EntrySetTruncated {
                index,
                secondary_count,
            } => write!(
                formatter,
                "entry set at {index} declares {secondary_count} unavailable secondaries"
            ),
            Self::SecondaryLimitExceeded {
                index,
                count,
                limit,
            } => write!(
                formatter,
                "entry set at {index} has {count} secondaries, exceeding limit {limit}"
            ),
            Self::InvalidSetMember { index, entry_type } => write!(
                formatter,
                "invalid set member {entry_type:#04X} at index {index}"
            ),
            Self::SetChecksumMismatch {
                index,
                stored,
                computed,
            } => write!(
                formatter,
                "entry set checksum mismatch at {index}: stored {stored:#06X}, computed {computed:#06X}"
            ),
            Self::ReservedNotZero {
                index,
                offset,
                value,
            } => write!(
                formatter,
                "reserved byte {offset} of entry {index} is {value:#04X}"
            ),
            Self::InvalidFlags { index, value } => {
                write!(formatter, "invalid flags {value:#06X} in entry {index}")
            }
            Self::InvalidTimestamp {
                index,
                offset,
                value,
            } => write!(
                formatter,
                "invalid timestamp {value:#010X} at byte {offset} of entry {index}"
            ),
            Self::InvalidCluster { index, cluster } => write!(
                formatter,
                "cluster {cluster} in entry {index} is outside the heap"
            ),
            Self::InvalidDataLength { index, length } => write!(
                formatter,
                "data length {length} in entry {index} is inconsistent with its allocation"
            ),
            Self::InvalidBitmapIdentifier { index, identifier } => write!(
                formatter,
                "allocation bitmap identifier {identifier} at {index} is invalid"
            ),
            Self::BitmapTooShort {
                index,
                length,
                required,
            } => write!(
                formatter,
                "allocation bitmap at {index} is {length} bytes; at least {required} are required"
            ),
            Self::InvalidVolumeLabelLength { index, length } => write!(
                formatter,
                "volume label at {index} has invalid length {length}"
            ),
            Self::InvalidNameLength { index, length } => write!(
                formatter,
                "stream at {index} has invalid name length {length}"
            ),
            Self::InvalidNameEntryCount {
                index,
                expected,
                found,
            } => write!(
                formatter,
                "file set at {index} needs {expected} name entries but has {found}"
            ),
            Self::InvalidNameCharacter { index, code_unit } => write!(
                formatter,
                "file or label at {index} contains invalid code unit {code_unit:#06X}"
            ),
            Self::InvalidUtf16Name { index } => write!(
                formatter,
                "file or label at {index} contains unpaired UTF-16 surrogate data"
            ),
            Self::ReservedFileName { index } => write!(
                formatter,
                "file set at {index} records reserved name '.' or '..'"
            ),
            Self::InvalidValidDataLength { index, valid, data } => write!(
                formatter,
                "valid data length {valid} exceeds data length {data} at {index}"
            ),
            Self::DirectoryDataLengthMismatch { index, valid, data } => write!(
                formatter,
                "directory at {index} has valid length {valid}, not allocation length {data}"
            ),
            Self::DirectoryTooLarge { index, length } => write!(
                formatter,
                "directory at {index} is {length} bytes, exceeding 256 MiB"
            ),
            Self::ContiguousAllocationOutsideHeap { index } => write!(
                formatter,
                "contiguous allocation at {index} extends beyond the cluster heap"
            ),
            Self::DuplicateAllocationBitmap { identifier } => write!(
                formatter,
                "duplicate allocation bitmap identifier {identifier}"
            ),
            Self::InvalidRootEntryCount {
                entry_type,
                found,
                expected,
            } => write!(
                formatter,
                "root has {found} entries of type {entry_type:#04X}; expected {expected}"
            ),
            Self::ArithmeticOverflow(operation) => {
                write!(formatter, "integer overflow while calculating {operation}")
            }
        }
    }
}

impl std::error::Error for DirectoryError {}

/// Validates a complete directory and visits its records without allocating.
///
/// The validator makes one full pass before invoking `visitor`, so corruption
/// never causes a partially delivered record stream. Unknown benign primary
/// sets and benign secondaries remain available in their exact `raw_set` bytes.
///
/// # Errors
///
/// Returns [`DirectoryError`] for malformed entry framing, invalid known entry
/// fields, checksum failures, unsafe geometry, missing root system entries, or
/// any unrecognized critical entry.
pub fn parse_directory<'a>(
    directory: &'a [u8],
    context: DirectoryContext,
    mut visitor: impl FnMut(DirectoryRecord<'a>),
) -> Result<DirectorySummary, DirectoryError> {
    validate_context(directory, context)?;
    scan_directory(directory, context, |_| {})?;
    scan_directory(directory, context, &mut visitor)
}

const fn validate_context(
    directory: &[u8],
    context: DirectoryContext,
) -> Result<(), DirectoryError> {
    if context.cluster_count == 0 {
        return Err(DirectoryError::InvalidContext("cluster_count is zero"));
    }
    if context.bytes_per_cluster == 0 || !context.bytes_per_cluster.is_power_of_two() {
        return Err(DirectoryError::InvalidContext(
            "bytes_per_cluster is not a non-zero power of two",
        ));
    }
    if !matches!(context.number_of_fats, 1 | 2) {
        return Err(DirectoryError::InvalidContext(
            "number_of_fats is not one or two",
        ));
    }
    if context.max_entries == 0 {
        return Err(DirectoryError::InvalidContext("max_entries is zero"));
    }
    // Keep the crate's Rust 1.85 MSRV; `is_multiple_of` stabilized later.
    if directory.len() / ENTRY_BYTES * ENTRY_BYTES != directory.len() {
        return Err(DirectoryError::LengthNotEntryAligned {
            actual: directory.len(),
        });
    }
    let entries = directory.len() / ENTRY_BYTES;
    if entries > context.max_entries {
        return Err(DirectoryError::EntryLimitExceeded {
            entries,
            limit: context.max_entries,
        });
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn scan_directory<'a>(
    directory: &'a [u8],
    context: DirectoryContext,
    mut visitor: impl FnMut(DirectoryRecord<'a>),
) -> Result<DirectorySummary, DirectoryError> {
    let mut summary = DirectorySummary {
        entries_examined: 0,
        records: 0,
        unused_entries: 0,
        reached_end_marker: false,
        allocation_bitmaps: 0,
        upcase_tables: 0,
        volume_labels: 0,
        files: 0,
        benign_primary_sets: 0,
    };
    let mut index = 0;
    let entry_count = directory.len() / ENTRY_BYTES;
    let mut bitmap_mask = 0_u8;

    while index < entry_count {
        let entry = entry_at(directory, index);
        let entry_type = entry[0];
        summary.entries_examined = index + 1;
        if entry_type == 0 {
            summary.reached_end_marker = true;
            for later in index + 1..entry_count {
                let later_type = entry_at(directory, later)[0];
                if later_type != 0 {
                    return Err(DirectoryError::InvalidEntryType {
                        index: later,
                        entry_type: later_type,
                    });
                }
            }
            summary.entries_examined = entry_count;
            break;
        }
        if entry_type == ENTRY_IN_USE {
            return Err(DirectoryError::InvalidEntryType { index, entry_type });
        }
        if entry_type & ENTRY_IN_USE == 0 {
            summary.unused_entries += 1;
            visitor(DirectoryRecord::Unused {
                entry_type,
                raw: entry,
            });
            index += 1;
            continue;
        }
        if entry_type & ENTRY_SECONDARY != 0 {
            return Err(DirectoryError::UnexpectedSecondary { index, entry_type });
        }

        let consumed = match entry_type {
            TYPE_ALLOCATION_BITMAP => {
                require_root(context, index, entry_type)?;
                let parsed = parse_bitmap(entry, index, context)?;
                let bit = 1_u8 << parsed.bitmap_identifier;
                if bitmap_mask & bit != 0 {
                    return Err(DirectoryError::DuplicateAllocationBitmap {
                        identifier: parsed.bitmap_identifier,
                    });
                }
                bitmap_mask |= bit;
                summary.allocation_bitmaps += 1;
                summary.records += 1;
                visitor(DirectoryRecord::AllocationBitmap(parsed));
                1
            }
            TYPE_UPCASE_TABLE => {
                require_root(context, index, entry_type)?;
                let parsed = parse_upcase(entry, index, context)?;
                summary.upcase_tables = summary.upcase_tables.saturating_add(1);
                summary.records += 1;
                visitor(DirectoryRecord::UpcaseTable(parsed));
                1
            }
            TYPE_VOLUME_LABEL => {
                require_root(context, index, entry_type)?;
                let parsed = parse_volume_label(entry, index)?;
                summary.volume_labels = summary.volume_labels.saturating_add(1);
                summary.records += 1;
                visitor(DirectoryRecord::VolumeLabel(parsed));
                1
            }
            TYPE_FILE => {
                let (parsed, count) = parse_file_set(directory, index, context)?;
                summary.files += 1;
                summary.records += 1;
                visitor(DirectoryRecord::File(parsed));
                count
            }
            other if other & ENTRY_BENIGN != 0 => {
                let secondary_count = entry[1];
                let raw_set = generic_benign_set(directory, index, secondary_count, context)?;
                summary.benign_primary_sets += 1;
                summary.records += 1;
                visitor(DirectoryRecord::BenignPrimary {
                    entry_type: other,
                    secondary_count,
                    raw_set,
                });
                usize::from(secondary_count) + 1
            }
            other => {
                return Err(DirectoryError::UnknownCriticalEntry {
                    index,
                    entry_type: other,
                });
            }
        };
        index = index
            .checked_add(consumed)
            .ok_or(DirectoryError::ArithmeticOverflow("directory entry index"))?;
    }

    if context.is_root {
        require_count(
            TYPE_ALLOCATION_BITMAP,
            summary.allocation_bitmaps,
            context.number_of_fats,
        )?;
        require_count(TYPE_UPCASE_TABLE, summary.upcase_tables, 1)?;
        if summary.volume_labels > 1 {
            return Err(DirectoryError::InvalidRootEntryCount {
                entry_type: TYPE_VOLUME_LABEL,
                found: summary.volume_labels,
                expected: 1,
            });
        }
    }
    Ok(summary)
}

fn parse_bitmap(
    entry: &[u8],
    index: usize,
    context: DirectoryContext,
) -> Result<AllocationBitmapEntry, DirectoryError> {
    if entry[1] & !1 != 0 {
        return Err(DirectoryError::InvalidFlags {
            index,
            value: u16::from(entry[1]),
        });
    }
    require_zero(entry, 2, 20, index)?;
    let identifier = entry[1] & 1;
    if identifier >= context.number_of_fats {
        return Err(DirectoryError::InvalidBitmapIdentifier { index, identifier });
    }
    let first_cluster = read_u32(entry, 20);
    let data_length = read_u64(entry, 24);
    validate_allocation(index, first_cluster, data_length, false, context)?;
    let required = u64::from(context.cluster_count).div_ceil(8);
    if data_length < required {
        return Err(DirectoryError::BitmapTooShort {
            index,
            length: data_length,
            required,
        });
    }
    Ok(AllocationBitmapEntry {
        bitmap_identifier: identifier,
        first_cluster,
        data_length,
    })
}

fn parse_upcase(
    entry: &[u8],
    index: usize,
    context: DirectoryContext,
) -> Result<UpcaseTableEntry, DirectoryError> {
    require_zero(entry, 1, 4, index)?;
    require_zero(entry, 8, 20, index)?;
    let first_cluster = read_u32(entry, 20);
    let data_length = read_u64(entry, 24);
    validate_allocation(index, first_cluster, data_length, false, context)?;
    if data_length == 0 || data_length & 1 != 0 {
        return Err(DirectoryError::InvalidDataLength {
            index,
            length: data_length,
        });
    }
    Ok(UpcaseTableEntry {
        table_checksum: read_u32(entry, 4),
        first_cluster,
        data_length,
    })
}

fn parse_volume_label(entry: &[u8], index: usize) -> Result<VolumeLabelEntry, DirectoryError> {
    let len = entry[1];
    if len > 11 {
        return Err(DirectoryError::InvalidVolumeLabelLength { index, length: len });
    }
    require_zero(entry, 24, 32, index)?;
    let mut units = [0_u16; 11];
    for (slot, unit) in units.iter_mut().enumerate() {
        *unit = read_u16(entry, 2 + slot * 2);
    }
    validate_name_units(&units[..usize::from(len)], index, false)?;
    let padding_zeroed = units[usize::from(len)..].iter().all(|unit| *unit == 0);
    Ok(VolumeLabelEntry {
        units,
        len,
        padding_zeroed,
    })
}

#[allow(clippy::too_many_lines)]
fn parse_file_set(
    directory: &[u8],
    index: usize,
    context: DirectoryContext,
) -> Result<(FileEntry<'_>, usize), DirectoryError> {
    let primary = entry_at(directory, index);
    let secondary_count = primary[1];
    let raw_set = checked_set(directory, index, secondary_count, context)?;
    verify_set_checksum(raw_set, index)?;
    if read_u16(primary, 4) & !VALID_FILE_ATTRIBUTES != 0 {
        return Err(DirectoryError::InvalidFlags {
            index,
            value: read_u16(primary, 4),
        });
    }
    require_zero(primary, 6, 8, index)?;
    require_zero(primary, 25, 32, index)?;
    for offset in [8, 12, 16] {
        validate_timestamp(primary, index, offset)?;
    }
    if primary[20] > 199 {
        return Err(DirectoryError::InvalidFlags {
            index,
            value: u16::from(primary[20]),
        });
    }
    if primary[21] > 199 {
        return Err(DirectoryError::InvalidFlags {
            index,
            value: u16::from(primary[21]),
        });
    }
    for offset in [22, 23, 24] {
        if primary[offset] & 0x80 == 0 && primary[offset] != 0 {
            return Err(DirectoryError::InvalidFlags {
                index,
                value: u16::from(primary[offset]),
            });
        }
    }

    let stream = entry_at(raw_set, 1);
    if stream[0] != TYPE_STREAM_EXTENSION {
        return Err(DirectoryError::InvalidSetMember {
            index: index + 1,
            entry_type: stream[0],
        });
    }
    if stream[1] & !0x03 != 0 || stream[1] & 1 == 0 {
        return Err(DirectoryError::InvalidFlags {
            index: index + 1,
            value: u16::from(stream[1]),
        });
    }
    require_zero(stream, 2, 3, index + 1)?;
    require_zero(stream, 6, 8, index + 1)?;
    require_zero(stream, 16, 20, index + 1)?;
    let name_length = stream[3];
    if name_length == 0 {
        return Err(DirectoryError::InvalidNameLength {
            index: index + 1,
            length: name_length,
        });
    }
    let name_entries = name_length.div_ceil(15);
    if u16::from(name_entries) + 1 > u16::from(secondary_count) {
        return Err(DirectoryError::InvalidNameEntryCount {
            index,
            expected: name_entries,
            found: secondary_count.saturating_sub(1),
        });
    }
    let mut name = FileName {
        units: [0; MAX_FILE_NAME_UNITS],
        len: name_length,
    };
    let mut cursor = 0_usize;
    let mut padding_zeroed = true;
    for sequence in 0..usize::from(name_entries) {
        let member_index = 2 + sequence;
        let member = entry_at(raw_set, member_index);
        if member[0] != TYPE_FILE_NAME {
            return Err(DirectoryError::InvalidSetMember {
                index: index + member_index,
                entry_type: member[0],
            });
        }
        if member[1] != 0 {
            return Err(DirectoryError::InvalidFlags {
                index: index + member_index,
                value: u16::from(member[1]),
            });
        }
        for slot in 0..15 {
            let unit = read_u16(member, 2 + slot * 2);
            if cursor < usize::from(name_length) {
                name.units[cursor] = unit;
            } else if unit != 0 {
                padding_zeroed = false;
            }
            cursor += 1;
        }
    }
    validate_name_units(name.as_units(), index, true)?;
    let required_secondaries =
        1_u8.checked_add(name_entries)
            .ok_or(DirectoryError::ArithmeticOverflow(
                "required file secondaries",
            ))?;
    let benign_count = secondary_count - required_secondaries;
    for member_index in usize::from(required_secondaries) + 1..=usize::from(secondary_count) {
        let member = entry_at(raw_set, member_index);
        if member[0] & (ENTRY_IN_USE | ENTRY_SECONDARY | ENTRY_BENIGN)
            != (ENTRY_IN_USE | ENTRY_SECONDARY | ENTRY_BENIGN)
        {
            return Err(if member[0] & ENTRY_BENIGN == 0 {
                DirectoryError::UnknownCriticalEntry {
                    index: index + member_index,
                    entry_type: member[0],
                }
            } else {
                DirectoryError::InvalidSetMember {
                    index: index + member_index,
                    entry_type: member[0],
                }
            });
        }
    }
    let valid_data_length = read_u64(stream, 8);
    let first_cluster = read_u32(stream, 20);
    let data_length = read_u64(stream, 24);
    let no_fat_chain = stream[1] & 2 != 0;
    validate_allocation(index + 1, first_cluster, data_length, no_fat_chain, context)?;
    if valid_data_length > data_length {
        return Err(DirectoryError::InvalidValidDataLength {
            index,
            valid: valid_data_length,
            data: data_length,
        });
    }
    let file_attributes = read_u16(primary, 4);
    let is_directory = file_attributes & DIRECTORY_ATTRIBUTE != 0;
    if is_directory && valid_data_length != data_length {
        return Err(DirectoryError::DirectoryDataLengthMismatch {
            index,
            valid: valid_data_length,
            data: data_length,
        });
    }
    if is_directory && data_length > MAX_DIRECTORY_BYTES {
        return Err(DirectoryError::DirectoryTooLarge {
            index,
            length: data_length,
        });
    }
    Ok((
        FileEntry {
            file_attributes,
            create_timestamp: read_u32(primary, 8),
            modified_timestamp: read_u32(primary, 12),
            accessed_timestamp: read_u32(primary, 16),
            create_centiseconds: primary[20],
            modified_centiseconds: primary[21],
            create_utc_offset: primary[22],
            modified_utc_offset: primary[23],
            accessed_utc_offset: primary[24],
            is_directory,
            no_fat_chain,
            name_hash: read_u16(stream, 4),
            valid_data_length,
            first_cluster,
            data_length,
            name,
            name_padding_zeroed: padding_zeroed,
            benign_secondary_entries: benign_count,
            raw_set,
        },
        usize::from(secondary_count) + 1,
    ))
}

fn generic_benign_set(
    directory: &[u8],
    index: usize,
    count: u8,
    context: DirectoryContext,
) -> Result<&[u8], DirectoryError> {
    let raw = checked_set(directory, index, count, context)?;
    verify_set_checksum(raw, index)?;
    for member_index in 1..=usize::from(count) {
        let member_type = entry_at(raw, member_index)[0];
        if member_type & (ENTRY_IN_USE | ENTRY_SECONDARY) != (ENTRY_IN_USE | ENTRY_SECONDARY) {
            return Err(DirectoryError::InvalidSetMember {
                index: index + member_index,
                entry_type: member_type,
            });
        }
    }
    Ok(raw)
}

fn checked_set(
    directory: &[u8],
    index: usize,
    count: u8,
    context: DirectoryContext,
) -> Result<&[u8], DirectoryError> {
    if count > context.max_secondary_entries {
        return Err(DirectoryError::SecondaryLimitExceeded {
            index,
            count,
            limit: context.max_secondary_entries,
        });
    }
    let entries = usize::from(count) + 1;
    let end_entry = index
        .checked_add(entries)
        .ok_or(DirectoryError::ArithmeticOverflow("entry set end"))?;
    if end_entry > directory.len() / ENTRY_BYTES {
        return Err(DirectoryError::EntrySetTruncated {
            index,
            secondary_count: count,
        });
    }
    Ok(&directory[index * ENTRY_BYTES..end_entry * ENTRY_BYTES])
}

fn verify_set_checksum(raw: &[u8], index: usize) -> Result<(), DirectoryError> {
    let stored = read_u16(raw, 2);
    let computed = raw
        .iter()
        .copied()
        .enumerate()
        .filter(|(offset, _)| !matches!(*offset, 2 | 3))
        .fold(0_u16, |sum, (_, byte)| {
            sum.rotate_right(1).wrapping_add(u16::from(byte))
        });
    if stored != computed {
        return Err(DirectoryError::SetChecksumMismatch {
            index,
            stored,
            computed,
        });
    }
    Ok(())
}

fn validate_allocation(
    index: usize,
    cluster: u32,
    length: u64,
    no_fat_chain: bool,
    context: DirectoryContext,
) -> Result<(), DirectoryError> {
    let maximum_cluster = context
        .cluster_count
        .checked_add(1)
        .ok_or(DirectoryError::ArithmeticOverflow("maximum cluster"))?;
    if cluster == 0 {
        if length != 0 || no_fat_chain {
            return Err(DirectoryError::InvalidDataLength { index, length });
        }
        return Ok(());
    }
    if !(2..=maximum_cluster).contains(&cluster) {
        return Err(DirectoryError::InvalidCluster { index, cluster });
    }
    let heap_bytes = u64::from(context.cluster_count)
        .checked_mul(u64::from(context.bytes_per_cluster))
        .ok_or(DirectoryError::ArithmeticOverflow(
            "cluster heap byte length",
        ))?;
    if length > heap_bytes || (no_fat_chain && length == 0) {
        return Err(DirectoryError::InvalidDataLength { index, length });
    }
    if no_fat_chain {
        let clusters = length.div_ceil(u64::from(context.bytes_per_cluster));
        let last = u64::from(cluster)
            .checked_add(clusters.saturating_sub(1))
            .ok_or(DirectoryError::ArithmeticOverflow(
                "contiguous allocation end",
            ))?;
        if last > u64::from(maximum_cluster) {
            return Err(DirectoryError::ContiguousAllocationOutsideHeap { index });
        }
    }
    Ok(())
}

fn validate_name_units(
    units: &[u16],
    index: usize,
    reject_dot_names: bool,
) -> Result<(), DirectoryError> {
    for unit in units {
        if *unit <= 0x1F
            || matches!(
                *unit,
                0x22 | 0x2A | 0x2F | 0x3A | 0x3C | 0x3E | 0x3F | 0x5C | 0x7C
            )
        {
            return Err(DirectoryError::InvalidNameCharacter {
                index,
                code_unit: *unit,
            });
        }
    }
    if char::decode_utf16(units.iter().copied()).any(|decoded| decoded.is_err()) {
        return Err(DirectoryError::InvalidUtf16Name { index });
    }
    if reject_dot_names
        && (units == [u16::from(b'.')] || units == [u16::from(b'.'), u16::from(b'.')])
    {
        return Err(DirectoryError::ReservedFileName { index });
    }
    Ok(())
}

const fn validate_timestamp(
    entry: &[u8],
    index: usize,
    offset: usize,
) -> Result<(), DirectoryError> {
    let timestamp = read_u32(entry, offset);
    let double_seconds = timestamp & 0x1F;
    let minute = (timestamp >> 5) & 0x3F;
    let hour = (timestamp >> 11) & 0x1F;
    let day = (timestamp >> 16) & 0x1F;
    let month = (timestamp >> 21) & 0x0F;
    let year = 1980 + ((timestamp >> 25) & 0x7F);
    // The encoded range is 1980..=2107, so 2100 is its sole four-year
    // boundary that the Gregorian century rule excludes.
    let leap = year.trailing_zeros() >= 2 && year != 2100;
    let maximum_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    };
    if double_seconds > 29 || minute > 59 || hour > 23 || day == 0 || day > maximum_day {
        return Err(DirectoryError::InvalidTimestamp {
            index,
            offset,
            value: timestamp,
        });
    }
    Ok(())
}

const fn require_root(
    context: DirectoryContext,
    index: usize,
    entry_type: u8,
) -> Result<(), DirectoryError> {
    if context.is_root {
        Ok(())
    } else {
        Err(DirectoryError::CriticalSystemEntryOutsideRoot { index, entry_type })
    }
}

const fn require_count(entry_type: u8, found: u8, expected: u8) -> Result<(), DirectoryError> {
    if found == expected {
        Ok(())
    } else {
        Err(DirectoryError::InvalidRootEntryCount {
            entry_type,
            found,
            expected,
        })
    }
}

fn require_zero(
    entry: &[u8],
    start: usize,
    end: usize,
    index: usize,
) -> Result<(), DirectoryError> {
    if let Some((relative, value)) = entry[start..end]
        .iter()
        .copied()
        .enumerate()
        .find(|(_, value)| *value != 0)
    {
        return Err(DirectoryError::ReservedNotZero {
            index,
            offset: start + relative,
            value,
        });
    }
    Ok(())
}

fn entry_at(bytes: &[u8], index: usize) -> &[u8] {
    &bytes[index * ENTRY_BYTES..(index + 1) * ENTRY_BYTES]
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

    const fn context(is_root: bool) -> DirectoryContext {
        DirectoryContext {
            cluster_count: 1_000,
            bytes_per_cluster: 4_096,
            number_of_fats: 1,
            is_root,
            max_entries: 128,
            max_secondary_entries: 32,
        }
    }
    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    fn checksum(set: &mut [u8]) {
        put_u16(set, 2, 0);
        let sum = set
            .iter()
            .copied()
            .enumerate()
            .filter(|(i, _)| !matches!(*i, 2 | 3))
            .fold(0_u16, |sum, (_, byte)| {
                sum.rotate_right(1).wrapping_add(u16::from(byte))
            });
        put_u16(set, 2, sum);
    }
    fn file_set(name: &[u16], directory: bool, no_fat: bool) -> Vec<u8> {
        let names = name.len().div_ceil(15);
        let mut set = vec![0_u8; (2 + names) * ENTRY_BYTES];
        set[0] = TYPE_FILE;
        set[1] = u8::try_from(1 + names).unwrap();
        put_u16(
            &mut set,
            4,
            if directory { DIRECTORY_ATTRIBUTE } else { 0x20 },
        );
        // 2024-01-01 00:00:00 for all three timestamps.
        let timestamp = ((2024 - 1980) << 25) | (1 << 21) | (1 << 16);
        for offset in [8, 12, 16] {
            put_u32(&mut set, offset, timestamp);
        }
        set[32] = TYPE_STREAM_EXTENSION;
        set[33] = 1 | if no_fat { 2 } else { 0 };
        set[35] = u8::try_from(name.len()).unwrap();
        let data = if directory { 4_096 } else { 100 };
        put_u64(&mut set, 40, data);
        put_u32(&mut set, 52, 2);
        put_u64(&mut set, 56, data);
        for (sequence, chunk) in name.chunks(15).enumerate() {
            let base = (2 + sequence) * ENTRY_BYTES;
            set[base] = TYPE_FILE_NAME;
            for (slot, unit) in chunk.iter().enumerate() {
                put_u16(&mut set, base + 2 + slot * 2, *unit);
            }
        }
        checksum(&mut set);
        set
    }

    #[test]
    fn parses_file_set_without_allocating() {
        let mut bytes = file_set(&"hello.txt".encode_utf16().collect::<Vec<_>>(), false, true);
        bytes.extend_from_slice(&[0; ENTRY_BYTES]);
        let mut seen = None;
        let summary = parse_directory(&bytes, context(false), |record| {
            if let DirectoryRecord::File(file) = record {
                seen = Some(file);
            }
        })
        .unwrap();
        let file = seen.unwrap();
        assert_eq!(
            file.name.as_units(),
            "hello.txt".encode_utf16().collect::<Vec<_>>()
        );
        assert!(file.no_fat_chain);
        assert!(file.name_padding_zeroed);
        assert_eq!(summary.files, 1);
    }

    #[test]
    fn parses_maximum_255_unit_name_across_17_entries() {
        let name = vec![u16::from(b'a'); 255];
        let bytes = file_set(&name, false, false);
        let mut length = 0;
        parse_directory(
            &bytes,
            DirectoryContext {
                max_secondary_entries: 18,
                ..context(false)
            },
            |record| {
                if let DirectoryRecord::File(file) = record {
                    length = file.name.len();
                }
            },
        )
        .unwrap();
        assert_eq!(length, 255);
    }

    #[test]
    fn preserves_nonzero_recommended_name_padding_as_evidence() {
        let mut bytes = file_set(&[u16::from(b'a')], false, false);
        put_u16(&mut bytes, 2 * ENTRY_BYTES + 4, u16::from(b'x'));
        checksum(&mut bytes);
        let mut zeroed = true;
        parse_directory(&bytes, context(false), |record| {
            if let DirectoryRecord::File(file) = record {
                zeroed = file.name_padding_zeroed;
            }
        })
        .unwrap();
        assert!(!zeroed);
    }

    #[test]
    fn rejects_checksum_truncation_and_secondary_cap() {
        let mut bytes = file_set(&[u16::from(b'a')], false, false);
        bytes[10] ^= 1;
        assert!(matches!(
            parse_directory(&bytes, context(false), |_| {}),
            Err(DirectoryError::SetChecksumMismatch { .. })
        ));
        let truncated = &file_set(&[u16::from(b'a')], false, false)[..ENTRY_BYTES * 2];
        assert!(matches!(
            parse_directory(truncated, context(false), |_| {}),
            Err(DirectoryError::EntrySetTruncated { .. })
        ));
        let bytes = file_set(&[u16::from(b'a')], false, false);
        assert!(matches!(
            parse_directory(
                &bytes,
                DirectoryContext {
                    max_secondary_entries: 1,
                    ..context(false)
                },
                |_| {}
            ),
            Err(DirectoryError::SecondaryLimitExceeded { .. })
        ));
    }

    #[test]
    fn rejects_bad_stream_name_and_allocation_rules() {
        let mut bytes = file_set(&[u16::from(b'a')], false, false);
        bytes[33] = 0;
        checksum(&mut bytes);
        assert!(matches!(
            parse_directory(&bytes, context(false), |_| {}),
            Err(DirectoryError::InvalidFlags { .. })
        ));
        let bytes = file_set(&[u16::from(b'*')], false, false);
        assert!(matches!(
            parse_directory(&bytes, context(false), |_| {}),
            Err(DirectoryError::InvalidNameCharacter { .. })
        ));
        let bytes = file_set(&[u16::from(b'.')], false, false);
        assert!(matches!(
            parse_directory(&bytes, context(false), |_| {}),
            Err(DirectoryError::ReservedFileName { .. })
        ));
        let bytes = file_set(&[0xD800], false, false);
        assert!(matches!(
            parse_directory(&bytes, context(false), |_| {}),
            Err(DirectoryError::InvalidUtf16Name { .. })
        ));
        let mut bytes = file_set(&[u16::from(b'a')], false, true);
        put_u32(&mut bytes, 52, 1_001);
        put_u64(&mut bytes, 56, 4_097);
        checksum(&mut bytes);
        assert!(matches!(
            parse_directory(&bytes, context(false), |_| {}),
            Err(DirectoryError::ContiguousAllocationOutsideHeap { .. })
        ));
    }

    #[test]
    fn rejects_invalid_calendar_timestamps_and_subsecond_increments() {
        let mut bytes = file_set(&[u16::from(b'a')], false, false);
        // 2023-02-29 does not exist.
        put_u32(
            &mut bytes,
            8,
            ((2023 - 1980) << 25) | (2 << 21) | (29 << 16),
        );
        checksum(&mut bytes);
        assert!(matches!(
            parse_directory(&bytes, context(false), |_| {}),
            Err(DirectoryError::InvalidTimestamp { offset: 8, .. })
        ));

        let mut bytes = file_set(&[u16::from(b'a')], false, false);
        bytes[20] = 200;
        checksum(&mut bytes);
        assert!(matches!(
            parse_directory(&bytes, context(false), |_| {}),
            Err(DirectoryError::InvalidFlags { .. })
        ));
    }

    #[test]
    fn enforces_directory_length_semantics() {
        let mut bytes = file_set(&[u16::from(b'd')], true, false);
        put_u64(&mut bytes, 40, 1);
        checksum(&mut bytes);
        assert!(matches!(
            parse_directory(&bytes, context(false), |_| {}),
            Err(DirectoryError::DirectoryDataLengthMismatch { .. })
        ));
        let mut bytes = file_set(&[u16::from(b'd')], true, false);
        put_u64(&mut bytes, 40, MAX_DIRECTORY_BYTES + 1);
        put_u64(&mut bytes, 56, MAX_DIRECTORY_BYTES + 1);
        checksum(&mut bytes);
        assert!(matches!(
            parse_directory(
                &bytes,
                DirectoryContext {
                    cluster_count: 100_000,
                    ..context(false)
                },
                |_| {}
            ),
            Err(DirectoryError::DirectoryTooLarge { .. })
        ));
    }

    #[test]
    fn parses_and_counts_required_root_system_entries() {
        let mut bytes = vec![0_u8; ENTRY_BYTES * 4];
        bytes[0] = TYPE_ALLOCATION_BITMAP;
        put_u32(&mut bytes, 20, 2);
        put_u64(&mut bytes, 24, 125);
        bytes[32] = TYPE_UPCASE_TABLE;
        put_u32(&mut bytes, 36, 0xE619_D30D);
        put_u32(&mut bytes, 52, 3);
        put_u64(&mut bytes, 56, 256);
        bytes[64] = TYPE_VOLUME_LABEL;
        bytes[65] = 1;
        put_u16(&mut bytes, 66, u16::from(b'X'));
        let summary = parse_directory(&bytes, context(true), |_| {}).unwrap();
        assert_eq!(summary.allocation_bitmaps, 1);
        assert_eq!(summary.upcase_tables, 1);
        assert_eq!(summary.volume_labels, 1);
    }

    #[test]
    fn rejects_duplicate_or_missing_root_system_entries() {
        let bytes = vec![0_u8; ENTRY_BYTES];
        assert!(matches!(
            parse_directory(&bytes, context(true), |_| {}),
            Err(DirectoryError::InvalidRootEntryCount {
                entry_type: TYPE_ALLOCATION_BITMAP,
                ..
            })
        ));
        let mut bytes = vec![0_u8; ENTRY_BYTES * 4];
        for base in [0, 32] {
            bytes[base] = TYPE_ALLOCATION_BITMAP;
            put_u32(&mut bytes, base + 20, 2);
            put_u64(&mut bytes, base + 24, 125);
        }
        bytes[64] = TYPE_UPCASE_TABLE;
        put_u32(&mut bytes, 84, 3);
        put_u64(&mut bytes, 88, 256);
        assert!(matches!(
            parse_directory(&bytes, context(true), |_| {}),
            Err(DirectoryError::DuplicateAllocationBitmap { identifier: 0 })
        ));
    }

    #[test]
    fn refuses_unknown_critical_and_preserves_unknown_benign() {
        let mut critical = vec![0_u8; ENTRY_BYTES];
        critical[0] = 0x84;
        assert!(matches!(
            parse_directory(&critical, context(false), |_| {}),
            Err(DirectoryError::UnknownCriticalEntry { .. })
        ));
        let mut benign = vec![0_u8; ENTRY_BYTES];
        benign[0] = 0xA7;
        checksum(&mut benign);
        let mut raw_type = 0;
        parse_directory(&benign, context(false), |record| {
            if let DirectoryRecord::BenignPrimary {
                entry_type,
                raw_set,
                ..
            } = record
            {
                raw_type = entry_type;
                assert_eq!(raw_set, benign);
            }
        })
        .unwrap();
        assert_eq!(raw_type, 0xA7);
    }

    #[test]
    fn accepts_benign_secondary_after_names_but_refuses_critical_one() {
        let mut bytes = file_set(&[u16::from(b'a')], false, false);
        bytes[1] += 1;
        bytes.extend_from_slice(&[0; ENTRY_BYTES]);
        let base = bytes.len() - ENTRY_BYTES;
        bytes[base] = 0xE7;
        checksum(&mut bytes);
        let mut benign = 0;
        parse_directory(&bytes, context(false), |record| {
            if let DirectoryRecord::File(file) = record {
                benign = file.benign_secondary_entries;
            }
        })
        .unwrap();
        assert_eq!(benign, 1);
        bytes[base] = 0xC7;
        checksum(&mut bytes);
        assert!(matches!(
            parse_directory(&bytes, context(false), |_| {}),
            Err(DirectoryError::UnknownCriticalEntry { .. })
        ));
    }

    #[test]
    fn rejects_unaligned_oversized_and_post_end_data() {
        assert!(matches!(
            parse_directory(&[0; 31], context(false), |_| {}),
            Err(DirectoryError::LengthNotEntryAligned { .. })
        ));
        let bytes = vec![0_u8; ENTRY_BYTES * 2];
        assert!(matches!(
            parse_directory(
                &bytes,
                DirectoryContext {
                    max_entries: 1,
                    ..context(false)
                },
                |_| {}
            ),
            Err(DirectoryError::EntryLimitExceeded { .. })
        ));
        let mut bytes = vec![0_u8; ENTRY_BYTES * 2];
        bytes[ENTRY_BYTES] = 1;
        assert!(matches!(
            parse_directory(&bytes, context(false), |_| {}),
            Err(DirectoryError::InvalidEntryType { index: 1, .. })
        ));
    }
}
