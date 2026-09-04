//! Bounded resolution of NTFS `$ATTRIBUTE_LIST` continuation records.
//!
//! The resolver starts with an already validated base `FILE` record and an already bootstrapped
//! `$MFT` mapping. It reads only regular image files through [`ImageFile`], follows each distinct
//! extension record at most once, and returns owned attribute bytes in deterministic list order.
//! No raw-device path or write operation is available in this module.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;

use crate::fs::ntfs::NtfsBootSector;
use crate::fs::ntfs_attribute::{
    AttributeBody, AttributeLimits, AttributeName, NtfsAttribute, NtfsAttributeError,
    parse_attribute_list,
};
use crate::fs::ntfs_discovery::{MftBootstrap, NtfsDiscoveryError, read_mft_record_with_reader};
use crate::fs::ntfs_record::{MftReference, NtfsFileRecord};
use crate::fs::ntfs_runlist::{
    ExtentLocation, MappingPairsError, MappingPairsLimits, NtfsRunlist, parse_mapping_pairs,
};
use crate::image::{BoundedImageReader, ImageError, ImageFile};

const ATTRIBUTE_LIST_TYPE: u32 = 0x20;
const ENTRY_HEADER_LEN: usize = 26;

/// Resource limits for one continuation-resolution operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttributeListLimits {
    /// Base record plus the maximum number of distinct extension records.
    pub max_records: usize,
    /// Maximum number of entries decoded from the `$ATTRIBUTE_LIST` value.
    pub max_entries: usize,
    /// Maximum attributes parsed from any one record.
    pub max_attributes_per_record: usize,
    /// Maximum individual on-record attribute size.
    pub max_attribute_bytes: usize,
    /// Maximum aggregate raw bytes copied into the result.
    pub max_collected_attribute_bytes: usize,
    /// Maximum logical byte length of the `$ATTRIBUTE_LIST` value.
    pub max_list_bytes: usize,
    /// Maximum UTF-16 code units in one attribute name.
    pub max_name_code_units: usize,
    /// Maximum mapping pairs across every non-resident `$ATTRIBUTE_LIST` extent.
    pub max_runs: usize,
    /// Maximum aggregate image bytes read for list data and extension records.
    pub max_read_bytes: u64,
}

impl Default for AttributeListLimits {
    fn default() -> Self {
        Self {
            max_records: 4096,
            max_entries: 65_536,
            max_attributes_per_record: 256,
            max_attribute_bytes: 16 * 1024 * 1024,
            max_collected_attribute_bytes: 64 * 1024 * 1024,
            max_list_bytes: 16 * 1024 * 1024,
            max_name_code_units: 255,
            max_runs: 65_536,
            max_read_bytes: 128 * 1024 * 1024,
        }
    }
}

/// One validated entry from the `$ATTRIBUTE_LIST` value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeListEntry {
    pub attribute_type: u32,
    pub name: Vec<u16>,
    pub name_is_well_formed: bool,
    pub lowest_vcn: u64,
    pub file_reference: MftReference,
    pub instance: u16,
}

/// Identity evidence for a record that contributed one or more attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedRecordIdentity {
    pub record_number: u64,
    pub sequence_number: u16,
    pub is_extension: bool,
}

/// One matched attribute extent in canonical `$ATTRIBUTE_LIST` order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAttributeExtent {
    pub attribute_type: u32,
    pub name: Vec<u16>,
    pub lowest_vcn: u64,
    pub instance: u16,
    pub record: ResolvedRecordIdentity,
    /// Exact repaired attribute bytes, owned independently of the source record.
    pub raw_attribute: Vec<u8>,
}

/// Deterministic owned view of all extents named by one `$ATTRIBUTE_LIST`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAttributeList {
    pub base_record: ResolvedRecordIdentity,
    pub extension_records: Vec<ResolvedRecordIdentity>,
    pub extents: Vec<ResolvedAttributeExtent>,
    pub list_was_resident: bool,
    pub bytes_read: u64,
}

/// Reason continuation evidence could not be safely resolved.
#[derive(Debug)]
pub enum AttributeListError {
    InvalidLimit {
        field: &'static str,
    },
    BaseRecordNumberMismatch {
        expected: u64,
        found: u64,
    },
    BaseRecordNotInUse,
    BaseRecordIsExtension,
    MissingAttributeList,
    EmptyAttributeList,
    DuplicateAttributeList,
    AttributeListNotFirstExtent {
        lowest_vcn: u64,
    },
    UnsupportedAttributeListStorage {
        reason: &'static str,
    },
    ListTooLarge {
        actual: u64,
        maximum: usize,
    },
    ListMappingIncomplete {
        mapped_bytes: u64,
        data_bytes: u64,
    },
    NoncontiguousAttributeListExtent {
        expected_vcn: u64,
        found_vcn: u64,
    },
    EntryTruncated {
        offset: usize,
        remaining: usize,
    },
    InvalidEntryType {
        offset: usize,
        value: u32,
    },
    InvalidEntryLength {
        offset: usize,
        value: u16,
        remaining: usize,
    },
    EntryLimitExceeded {
        maximum: usize,
    },
    NameLimitExceeded {
        offset: usize,
        value: usize,
        maximum: usize,
    },
    InvalidNameRange {
        offset: usize,
        name_offset: u8,
        name_units: u8,
        entry_length: u16,
    },
    NegativeLowestVcn {
        offset: usize,
        value: i64,
    },
    EntriesOutOfOrder {
        previous: usize,
        current: usize,
    },
    DuplicateEntry {
        offset: usize,
    },
    TrailingNonzeroByte {
        offset: usize,
        value: u8,
    },
    RecordLimitExceeded {
        maximum: usize,
    },
    ReadByteLimitExceeded {
        requested_total: u64,
        maximum: u64,
    },
    RecordSequenceMismatch {
        record_number: u64,
        expected: u16,
        found: u16,
    },
    ExtensionNotInUse {
        record_number: u64,
    },
    ExtensionBaseMismatch {
        record_number: u64,
        expected: MftReference,
        found: Option<MftReference>,
    },
    AttributeNotFound {
        entry_index: usize,
        record_number: u64,
    },
    AttributeMatchedMultipleTimes {
        entry_index: usize,
        record_number: u64,
    },
    CollectedByteLimitExceeded {
        requested_total: usize,
        maximum: usize,
    },
    GeometryOverflow {
        calculation: &'static str,
    },
    AllocationFailed,
    Attribute(NtfsAttributeError),
    MappingPairs(MappingPairsError),
    Discovery(NtfsDiscoveryError),
    Image(ImageError),
}

impl fmt::Display for AttributeListError {
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit { field } => {
                write!(formatter, "attribute-list limit {field} must be non-zero")
            }
            Self::BaseRecordNumberMismatch { expected, found } => write!(
                formatter,
                "base FILE record number mismatch: expected {expected}, found {found}"
            ),
            Self::BaseRecordNotInUse => {
                formatter.write_str("attribute-list base record is not in use")
            }
            Self::BaseRecordIsExtension => {
                formatter.write_str("attribute-list base record is itself an extension record")
            }
            Self::MissingAttributeList => formatter.write_str("base record has no $ATTRIBUTE_LIST"),
            Self::EmptyAttributeList => formatter.write_str("$ATTRIBUTE_LIST contains no entries"),
            Self::DuplicateAttributeList => formatter
                .write_str("base record has multiple first-extent $ATTRIBUTE_LIST attributes"),
            Self::AttributeListNotFirstExtent { lowest_vcn } => write!(
                formatter,
                "$ATTRIBUTE_LIST begins at VCN {lowest_vcn}, not zero"
            ),
            Self::UnsupportedAttributeListStorage { reason } => {
                write!(formatter, "unsupported $ATTRIBUTE_LIST storage: {reason}")
            }
            Self::ListTooLarge { actual, maximum } => write!(
                formatter,
                "$ATTRIBUTE_LIST is {actual} bytes, exceeding caller cap {maximum}"
            ),
            Self::ListMappingIncomplete {
                mapped_bytes,
                data_bytes,
            } => write!(
                formatter,
                "$ATTRIBUTE_LIST mapping covers {mapped_bytes} bytes but its data size is {data_bytes}"
            ),
            Self::NoncontiguousAttributeListExtent {
                expected_vcn,
                found_vcn,
            } => write!(
                formatter,
                "$ATTRIBUTE_LIST continuation begins at VCN {found_vcn}, expected {expected_vcn}"
            ),
            Self::EntryTruncated { offset, remaining } => write!(
                formatter,
                "$ATTRIBUTE_LIST entry at byte {offset} is truncated ({remaining} bytes remain)"
            ),
            Self::InvalidEntryType { offset, value } => write!(
                formatter,
                "$ATTRIBUTE_LIST entry at byte {offset} has invalid type 0x{value:08x}"
            ),
            Self::InvalidEntryLength {
                offset,
                value,
                remaining,
            } => write!(
                formatter,
                "$ATTRIBUTE_LIST entry at byte {offset} has invalid length {value} with {remaining} bytes remaining"
            ),
            Self::EntryLimitExceeded { maximum } => write!(
                formatter,
                "$ATTRIBUTE_LIST entry count exceeds caller cap {maximum}"
            ),
            Self::NameLimitExceeded {
                offset,
                value,
                maximum,
            } => write!(
                formatter,
                "$ATTRIBUTE_LIST name at byte {offset} has {value} UTF-16 units, exceeding caller cap {maximum}"
            ),
            Self::InvalidNameRange {
                offset,
                name_offset,
                name_units,
                entry_length,
            } => write!(
                formatter,
                "$ATTRIBUTE_LIST name range at byte {offset} (offset {name_offset}, units {name_units}) exceeds entry length {entry_length}"
            ),
            Self::NegativeLowestVcn { offset, value } => write!(
                formatter,
                "$ATTRIBUTE_LIST entry at byte {offset} has negative lowest VCN {value}"
            ),
            Self::EntriesOutOfOrder { previous, current } => write!(
                formatter,
                "$ATTRIBUTE_LIST entries at bytes {previous} and {current} are out of type/name/VCN/instance order"
            ),
            Self::DuplicateEntry { offset } => write!(
                formatter,
                "$ATTRIBUTE_LIST contains a duplicate entry at byte {offset}"
            ),
            Self::TrailingNonzeroByte { offset, value } => write!(
                formatter,
                "$ATTRIBUTE_LIST trailing byte {offset} is nonzero: 0x{value:02x}"
            ),
            Self::RecordLimitExceeded { maximum } => write!(
                formatter,
                "attribute-list record count exceeds caller cap {maximum}"
            ),
            Self::ReadByteLimitExceeded {
                requested_total,
                maximum,
            } => write!(
                formatter,
                "attribute-list resolution would read {requested_total} bytes, exceeding caller cap {maximum}"
            ),
            Self::RecordSequenceMismatch {
                record_number,
                expected,
                found,
            } => write!(
                formatter,
                "MFT record {record_number} sequence mismatch: reference says {expected}, record says {found}"
            ),
            Self::ExtensionNotInUse { record_number } => {
                write!(formatter, "extension record {record_number} is not in use")
            }
            Self::ExtensionBaseMismatch {
                record_number,
                expected,
                found,
            } => write!(
                formatter,
                "extension record {record_number} has base reference {found:?}, expected {expected:?}"
            ),
            Self::AttributeNotFound {
                entry_index,
                record_number,
            } => write!(
                formatter,
                "$ATTRIBUTE_LIST entry {entry_index} has no matching attribute in record {record_number}"
            ),
            Self::AttributeMatchedMultipleTimes {
                entry_index,
                record_number,
            } => write!(
                formatter,
                "$ATTRIBUTE_LIST entry {entry_index} matches multiple attributes in record {record_number}"
            ),
            Self::CollectedByteLimitExceeded {
                requested_total,
                maximum,
            } => write!(
                formatter,
                "resolved attribute bytes total {requested_total}, exceeding caller cap {maximum}"
            ),
            Self::GeometryOverflow { calculation } => write!(
                formatter,
                "attribute-list geometry overflow while calculating {calculation}"
            ),
            Self::AllocationFailed => {
                formatter.write_str("could not allocate bounded attribute-list metadata")
            }
            Self::Attribute(error) => write!(
                formatter,
                "invalid attribute while resolving $ATTRIBUTE_LIST: {error}"
            ),
            Self::MappingPairs(error) => {
                write!(formatter, "invalid $ATTRIBUTE_LIST mapping pairs: {error}")
            }
            Self::Discovery(error) => write!(
                formatter,
                "could not read attribute-list extension record: {error}"
            ),
            Self::Image(error) => write!(formatter, "could not read $ATTRIBUTE_LIST data: {error}"),
        }
    }
}

impl std::error::Error for AttributeListError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Attribute(error) => Some(error),
            Self::MappingPairs(error) => Some(error),
            Self::Discovery(error) => Some(error),
            Self::Image(error) => Some(error),
            _ => None,
        }
    }
}

impl From<NtfsAttributeError> for AttributeListError {
    fn from(value: NtfsAttributeError) -> Self {
        Self::Attribute(value)
    }
}

impl From<MappingPairsError> for AttributeListError {
    fn from(value: MappingPairsError) -> Self {
        Self::MappingPairs(value)
    }
}

impl From<NtfsDiscoveryError> for AttributeListError {
    fn from(value: NtfsDiscoveryError) -> Self {
        Self::Discovery(value)
    }
}

impl From<ImageError> for AttributeListError {
    fn from(value: ImageError) -> Self {
        Self::Image(value)
    }
}

/// Parses a complete `$ATTRIBUTE_LIST` value without performing I/O.
///
/// # Errors
///
/// Returns [`AttributeListError`] for malformed entries, ordering violations, duplicate entries,
/// nonzero trailing fragments, allocation failure, or caller-limit violations.
#[allow(clippy::too_many_lines)]
pub fn parse_attribute_list_value(
    bytes: &[u8],
    max_entries: usize,
    max_name_code_units: usize,
) -> Result<Vec<AttributeListEntry>, AttributeListError> {
    parse_attribute_list_entries(bytes, max_entries, max_name_code_units, false)
}

/// Parses the leading complete entries of a possibly truncated `$ATTRIBUTE_LIST` value.
///
/// A trailing entry whose declared length overruns `bytes` ends the parse instead of failing, so
/// callers can inspect the mapped prefix of a VCN-split list before its continuation is resolved.
pub(crate) fn parse_attribute_list_prefix(
    bytes: &[u8],
    max_entries: usize,
    max_name_code_units: usize,
) -> Result<Vec<AttributeListEntry>, AttributeListError> {
    parse_attribute_list_entries(bytes, max_entries, max_name_code_units, true)
}

#[allow(clippy::too_many_lines)]
fn parse_attribute_list_entries(
    bytes: &[u8],
    max_entries: usize,
    max_name_code_units: usize,
    allow_truncated_tail: bool,
) -> Result<Vec<AttributeListEntry>, AttributeListError> {
    if max_entries == 0 {
        return Err(AttributeListError::InvalidLimit {
            field: "max_entries",
        });
    }
    if max_name_code_units == 0 {
        return Err(AttributeListError::InvalidLimit {
            field: "max_name_code_units",
        });
    }
    let mut result = Vec::new();
    let mut offset = 0_usize;
    let mut previous: Option<(usize, AttributeListEntry)> = None;
    while bytes.len().saturating_sub(offset) >= ENTRY_HEADER_LEN {
        if result.len() >= max_entries {
            return Err(AttributeListError::EntryLimitExceeded {
                maximum: max_entries,
            });
        }
        let remaining = bytes.len() - offset;
        let attribute_type = le_u32(bytes, offset);
        if attribute_type < 0x10 || attribute_type & 0x0f != 0 || attribute_type == u32::MAX {
            return Err(AttributeListError::InvalidEntryType {
                offset,
                value: attribute_type,
            });
        }
        let length = le_u16(bytes, offset + 4);
        let length_usize = usize::from(length);
        if length_usize < ENTRY_HEADER_LEN || length_usize % 8 != 0 || length_usize > remaining {
            if allow_truncated_tail && !result.is_empty() {
                return Ok(result);
            }
            return Err(AttributeListError::InvalidEntryLength {
                offset,
                value: length,
                remaining,
            });
        }
        let name_units = bytes[offset + 6];
        let name_count = usize::from(name_units);
        if name_count > max_name_code_units {
            return Err(AttributeListError::NameLimitExceeded {
                offset,
                value: name_count,
                maximum: max_name_code_units,
            });
        }
        let name_offset = bytes[offset + 7];
        let name_start = usize::from(name_offset);
        let name_bytes = name_count
            .checked_mul(2)
            .ok_or(AttributeListError::InvalidNameRange {
                offset,
                name_offset,
                name_units,
                entry_length: length,
            })?;
        let name_end =
            name_start
                .checked_add(name_bytes)
                .ok_or(AttributeListError::InvalidNameRange {
                    offset,
                    name_offset,
                    name_units,
                    entry_length: length,
                })?;
        if (name_count == 0 && name_offset != 0)
            || (name_count != 0
                && (name_start < ENTRY_HEADER_LEN
                    || name_start % 2 != 0
                    || name_end > length_usize))
        {
            return Err(AttributeListError::InvalidNameRange {
                offset,
                name_offset,
                name_units,
                entry_length: length,
            });
        }
        let lowest_signed = le_i64(bytes, offset + 8);
        let lowest_vcn =
            u64::try_from(lowest_signed).map_err(|_| AttributeListError::NegativeLowestVcn {
                offset,
                value: lowest_signed,
            })?;
        let raw_reference = le_u64(bytes, offset + 16);
        let mut name = Vec::new();
        name.try_reserve(name_count)
            .map_err(|_| AttributeListError::AllocationFailed)?;
        for unit_offset in (name_start..name_end).step_by(2) {
            name.push(le_u16(bytes, offset + unit_offset));
        }
        let entry = AttributeListEntry {
            attribute_type,
            name_is_well_formed: char::decode_utf16(name.iter().copied()).all(|item| item.is_ok()),
            name,
            lowest_vcn,
            file_reference: decode_reference(raw_reference),
            instance: le_u16(bytes, offset + 24),
        };
        if let Some((previous_offset, previous_entry)) = &previous {
            match compare_entries(previous_entry, &entry) {
                Ordering::Greater => {
                    return Err(AttributeListError::EntriesOutOfOrder {
                        previous: *previous_offset,
                        current: offset,
                    });
                }
                Ordering::Equal => return Err(AttributeListError::DuplicateEntry { offset }),
                Ordering::Less => {}
            }
        }
        result
            .try_reserve(1)
            .map_err(|_| AttributeListError::AllocationFailed)?;
        result.push(entry.clone());
        previous = Some((offset, entry));
        offset = offset
            .checked_add(length_usize)
            .ok_or(AttributeListError::GeometryOverflow {
                calculation: "next attribute-list entry",
            })?;
    }
    if allow_truncated_tail {
        return Ok(result);
    }
    for (tail_offset, value) in bytes[offset..].iter().copied().enumerate() {
        if value != 0 {
            return Err(AttributeListError::TrailingNonzeroByte {
                offset: offset + tail_offset,
                value,
            });
        }
    }
    if offset != bytes.len() && bytes.len() - offset >= 8 {
        return Err(AttributeListError::EntryTruncated {
            offset,
            remaining: bytes.len() - offset,
        });
    }
    Ok(result)
}

/// Resolves and validates every attribute extent named by the base record's `$ATTRIBUTE_LIST`.
///
/// # Errors
///
/// Returns [`AttributeListError`] for malformed records, stale references, wrong base identities,
/// duplicate/cyclic continuation evidence, unsupported stream semantics, I/O errors, arithmetic
/// overflow, or any caller resource-limit violation.
#[allow(clippy::too_many_lines)]
pub fn resolve_attribute_list(
    image: &ImageFile,
    boot: &NtfsBootSector,
    mft: &MftBootstrap,
    base_record_number: u64,
    base_record: &NtfsFileRecord,
    limits: AttributeListLimits,
) -> Result<ResolvedAttributeList, AttributeListError> {
    resolve_attribute_list_with_reader(image, boot, mft, base_record_number, base_record, limits)
}

#[allow(clippy::too_many_lines)]
pub(crate) fn resolve_attribute_list_with_reader(
    image: &dyn BoundedImageReader,
    boot: &NtfsBootSector,
    mft: &MftBootstrap,
    base_record_number: u64,
    base_record: &NtfsFileRecord,
    limits: AttributeListLimits,
) -> Result<ResolvedAttributeList, AttributeListError> {
    validate_limits(limits)?;
    if let Some(found) = base_record.record_number {
        if u64::from(found) != base_record_number {
            return Err(AttributeListError::BaseRecordNumberMismatch {
                expected: base_record_number,
                found: u64::from(found),
            });
        }
    }
    if !base_record.flags.is_in_use() {
        return Err(AttributeListError::BaseRecordNotInUse);
    }
    if base_record.base_record.is_some() {
        return Err(AttributeListError::BaseRecordIsExtension);
    }

    let attribute_limits = record_attribute_limits(boot, limits);
    let base_attributes = parse_record_attributes(base_record, attribute_limits)?;
    let mut selected = None;
    for attribute in &base_attributes.attributes {
        if attribute.attribute_type != ATTRIBUTE_LIST_TYPE {
            continue;
        }
        let is_first = match &attribute.body {
            AttributeBody::Resident(_) => true,
            AttributeBody::NonResident(body) => body.lowest_vcn == 0,
        };
        if !is_first {
            continue;
        }
        if selected.is_some() {
            return Err(AttributeListError::DuplicateAttributeList);
        }
        selected = Some(attribute);
    }
    let list_attribute = selected.ok_or(AttributeListError::MissingAttributeList)?;
    let mut budget = ReadBudget::new(limits.max_read_bytes);
    let (list_bytes, list_was_resident) = read_list_value(
        image,
        boot,
        mft,
        base_record_number,
        base_record,
        list_attribute,
        limits,
        attribute_limits,
        &mut budget,
    )?;
    let entries =
        parse_attribute_list_value(&list_bytes, limits.max_entries, limits.max_name_code_units)?;
    if entries.is_empty() {
        return Err(AttributeListError::EmptyAttributeList);
    }

    let base_identity = ResolvedRecordIdentity {
        record_number: base_record_number,
        sequence_number: base_record.sequence_number,
        is_extension: false,
    };
    let expected_base = MftReference {
        record_number: base_record_number,
        sequence_number: base_record.sequence_number,
    };
    let mut records: BTreeMap<u64, NtfsFileRecord> = BTreeMap::new();
    let mut expected_sequences: BTreeMap<u64, u16> = BTreeMap::new();
    for entry in &entries {
        if entry.file_reference.record_number == base_record_number {
            if entry.file_reference.sequence_number != base_record.sequence_number {
                return Err(AttributeListError::RecordSequenceMismatch {
                    record_number: base_record_number,
                    expected: entry.file_reference.sequence_number,
                    found: base_record.sequence_number,
                });
            }
            continue;
        }
        if let Some(previous) = expected_sequences.insert(
            entry.file_reference.record_number,
            entry.file_reference.sequence_number,
        ) {
            if previous != entry.file_reference.sequence_number {
                return Err(AttributeListError::RecordSequenceMismatch {
                    record_number: entry.file_reference.record_number,
                    expected: previous,
                    found: entry.file_reference.sequence_number,
                });
            }
        }
    }
    if expected_sequences
        .len()
        .checked_add(1)
        .ok_or(AttributeListError::GeometryOverflow {
            calculation: "record count",
        })?
        > limits.max_records
    {
        return Err(AttributeListError::RecordLimitExceeded {
            maximum: limits.max_records,
        });
    }
    for (&record_number, &expected_sequence) in &expected_sequences {
        budget.charge(boot.mft_record_size.bytes)?;
        let record = read_mft_record_with_reader(
            image,
            boot,
            mft,
            record_number,
            boot.mft_record_size.bytes,
        )?;
        if record.sequence_number != expected_sequence {
            return Err(AttributeListError::RecordSequenceMismatch {
                record_number,
                expected: expected_sequence,
                found: record.sequence_number,
            });
        }
        if !record.flags.is_in_use() {
            return Err(AttributeListError::ExtensionNotInUse { record_number });
        }
        if record.base_record != Some(expected_base) {
            return Err(AttributeListError::ExtensionBaseMismatch {
                record_number,
                expected: expected_base,
                found: record.base_record,
            });
        }
        records.insert(record_number, record);
    }

    let mut extents = Vec::new();
    extents
        .try_reserve(entries.len())
        .map_err(|_| AttributeListError::AllocationFailed)?;
    let mut collected_bytes = 0_usize;
    for (entry_index, entry) in entries.iter().enumerate() {
        let (record, is_extension) = if entry.file_reference.record_number == base_record_number {
            (base_record, false)
        } else {
            (&records[&entry.file_reference.record_number], true)
        };
        let attributes = parse_record_attributes(record, attribute_limits)?;
        let mut matches = attributes
            .attributes
            .iter()
            .filter(|attribute| attribute_matches(entry, attribute));
        let Some(attribute) = matches.next() else {
            return Err(AttributeListError::AttributeNotFound {
                entry_index,
                record_number: entry.file_reference.record_number,
            });
        };
        if matches.next().is_some() {
            return Err(AttributeListError::AttributeMatchedMultipleTimes {
                entry_index,
                record_number: entry.file_reference.record_number,
            });
        }
        collected_bytes = collected_bytes.checked_add(attribute.raw.len()).ok_or(
            AttributeListError::GeometryOverflow {
                calculation: "collected attribute byte count",
            },
        )?;
        if collected_bytes > limits.max_collected_attribute_bytes {
            return Err(AttributeListError::CollectedByteLimitExceeded {
                requested_total: collected_bytes,
                maximum: limits.max_collected_attribute_bytes,
            });
        }
        let mut raw_attribute = Vec::new();
        raw_attribute
            .try_reserve_exact(attribute.raw.len())
            .map_err(|_| AttributeListError::AllocationFailed)?;
        raw_attribute.extend_from_slice(attribute.raw);
        extents.push(ResolvedAttributeExtent {
            attribute_type: entry.attribute_type,
            name: entry.name.clone(),
            lowest_vcn: entry.lowest_vcn,
            instance: entry.instance,
            record: ResolvedRecordIdentity {
                record_number: entry.file_reference.record_number,
                sequence_number: entry.file_reference.sequence_number,
                is_extension,
            },
            raw_attribute,
        });
    }
    let extension_records = records
        .iter()
        .map(|(&record_number, record)| ResolvedRecordIdentity {
            record_number,
            sequence_number: record.sequence_number,
            is_extension: true,
        })
        .collect();
    Ok(ResolvedAttributeList {
        base_record: base_identity,
        extension_records,
        extents,
        list_was_resident,
        bytes_read: budget.used,
    })
}

fn validate_limits(limits: AttributeListLimits) -> Result<(), AttributeListError> {
    for (field, zero) in [
        ("max_records", limits.max_records == 0),
        ("max_entries", limits.max_entries == 0),
        (
            "max_attributes_per_record",
            limits.max_attributes_per_record == 0,
        ),
        ("max_attribute_bytes", limits.max_attribute_bytes == 0),
        (
            "max_collected_attribute_bytes",
            limits.max_collected_attribute_bytes == 0,
        ),
        ("max_list_bytes", limits.max_list_bytes == 0),
        ("max_name_code_units", limits.max_name_code_units == 0),
        ("max_runs", limits.max_runs == 0),
        ("max_read_bytes", limits.max_read_bytes == 0),
    ] {
        if zero {
            return Err(AttributeListError::InvalidLimit { field });
        }
    }
    Ok(())
}

const fn record_attribute_limits(
    boot: &NtfsBootSector,
    limits: AttributeListLimits,
) -> AttributeLimits {
    AttributeLimits {
        cluster_size_bytes: boot.cluster_size_bytes,
        max_attribute_bytes: limits.max_attribute_bytes,
        max_name_code_units: limits.max_name_code_units,
        max_attributes: limits.max_attributes_per_record,
    }
}

fn parse_record_attributes(
    record: &NtfsFileRecord,
    limits: AttributeLimits,
) -> Result<crate::fs::ntfs_attribute::NtfsAttributeList<'_>, AttributeListError> {
    let used =
        usize::try_from(record.bytes_in_use).map_err(|_| AttributeListError::GeometryOverflow {
            calculation: "FILE record bytes in use",
        })?;
    Ok(parse_attribute_list(
        record.repaired_bytes(),
        usize::from(record.attributes_offset),
        used,
        limits,
    )?)
}

#[allow(clippy::too_many_arguments)]
fn read_list_value(
    image: &dyn BoundedImageReader,
    boot: &NtfsBootSector,
    mft: &MftBootstrap,
    base_record_number: u64,
    base_record: &NtfsFileRecord,
    attribute: &NtfsAttribute<'_>,
    limits: AttributeListLimits,
    attribute_limits: AttributeLimits,
    budget: &mut ReadBudget,
) -> Result<(Vec<u8>, bool), AttributeListError> {
    match &attribute.body {
        AttributeBody::Resident(resident) => {
            ensure_list_size(resident.value.len() as u64, limits.max_list_bytes)?;
            let mut value = Vec::new();
            value
                .try_reserve_exact(resident.value.len())
                .map_err(|_| AttributeListError::AllocationFailed)?;
            value.extend_from_slice(resident.value);
            Ok((value, true))
        }
        AttributeBody::NonResident(data) => {
            if data.lowest_vcn != 0 {
                return Err(AttributeListError::AttributeListNotFirstExtent {
                    lowest_vcn: data.lowest_vcn,
                });
            }
            if attribute.flags.is_compressed()
                || attribute.flags.encrypted
                || attribute.flags.sparse
            {
                return Err(AttributeListError::UnsupportedAttributeListStorage {
                    reason: "stream is compressed, encrypted, or sparse",
                });
            }
            let sizes = data
                .sizes
                .ok_or(AttributeListError::UnsupportedAttributeListStorage {
                    reason: "first extent has no authoritative sizes",
                })?;
            ensure_list_size(sizes.data, limits.max_list_bytes)?;
            if sizes.initialized < sizes.data {
                return Err(AttributeListError::UnsupportedAttributeListStorage {
                    reason: "stream contains uninitialized bytes",
                });
            }
            let mut runlist = parse_mapping_pairs(
                data.mapping_pairs,
                MappingPairsLimits {
                    starting_vcn: 0,
                    expected_next_vcn: Some(data.expected_next_vcn),
                    volume_cluster_count: boot.cluster_count,
                    max_runs: limits.max_runs,
                    max_decoded_clusters: boot.cluster_count,
                },
            )?;
            extend_attribute_list_runlist(
                image,
                boot,
                mft,
                base_record_number,
                base_record,
                &mut runlist,
                sizes.data,
                limits,
                attribute_limits,
                budget,
            )?;
            let mapped_bytes = runlist
                .next_vcn
                .checked_mul(boot.cluster_size_bytes)
                .ok_or(AttributeListError::GeometryOverflow {
                    calculation: "$ATTRIBUTE_LIST mapped bytes",
                })?;
            if mapped_bytes < sizes.data {
                return Err(AttributeListError::ListMappingIncomplete {
                    mapped_bytes,
                    data_bytes: sizes.data,
                });
            }
            let count =
                usize::try_from(sizes.data).map_err(|_| AttributeListError::ListTooLarge {
                    actual: sizes.data,
                    maximum: limits.max_list_bytes,
                })?;
            budget.charge(sizes.data)?;
            Ok((read_stream(image, boot, &runlist, count)?, false))
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn extend_attribute_list_runlist(
    image: &dyn BoundedImageReader,
    boot: &NtfsBootSector,
    mft: &MftBootstrap,
    base_record_number: u64,
    base_record: &NtfsFileRecord,
    runlist: &mut NtfsRunlist,
    data_bytes: u64,
    limits: AttributeListLimits,
    attribute_limits: AttributeLimits,
    budget: &mut ReadBudget,
) -> Result<(), AttributeListError> {
    let mut loaded: BTreeMap<u64, NtfsFileRecord> = BTreeMap::new();
    let expected_base = MftReference {
        record_number: base_record_number,
        sequence_number: base_record.sequence_number,
    };
    for _ in 0..limits.max_records {
        let mapped_bytes = runlist
            .next_vcn
            .checked_mul(boot.cluster_size_bytes)
            .ok_or(AttributeListError::GeometryOverflow {
                calculation: "$ATTRIBUTE_LIST mapped bytes",
            })?;
        if mapped_bytes >= data_bytes {
            return Ok(());
        }
        let prefix_len = usize::try_from(mapped_bytes.min(data_bytes)).map_err(|_| {
            AttributeListError::ListTooLarge {
                actual: mapped_bytes,
                maximum: limits.max_list_bytes,
            }
        })?;
        if prefix_len == 0 {
            return Err(AttributeListError::ListMappingIncomplete {
                mapped_bytes,
                data_bytes,
            });
        }
        let prefix = read_stream(image, boot, runlist, prefix_len)?;
        let entries =
            parse_attribute_list_prefix(&prefix, limits.max_entries, limits.max_name_code_units)?;
        let expected_vcn = runlist.next_vcn;
        let Some(entry) = entries.iter().find(|entry| {
            entry.attribute_type == ATTRIBUTE_LIST_TYPE
                && entry.name.is_empty()
                && entry.lowest_vcn == expected_vcn
        }) else {
            return Err(AttributeListError::ListMappingIncomplete {
                mapped_bytes,
                data_bytes,
            });
        };
        let continuation = load_attribute_list_continuation(
            image,
            boot,
            mft,
            base_record_number,
            base_record,
            entry,
            &expected_base,
            &mut loaded,
            limits,
            attribute_limits,
            budget,
        )?;
        append_runlist(runlist, continuation)?;
    }
    let mapped_bytes = runlist
        .next_vcn
        .checked_mul(boot.cluster_size_bytes)
        .ok_or(AttributeListError::GeometryOverflow {
            calculation: "$ATTRIBUTE_LIST mapped bytes",
        })?;
    Err(AttributeListError::ListMappingIncomplete {
        mapped_bytes,
        data_bytes,
    })
}

#[allow(clippy::too_many_arguments)]
fn load_attribute_list_continuation(
    image: &dyn BoundedImageReader,
    boot: &NtfsBootSector,
    mft: &MftBootstrap,
    base_record_number: u64,
    base_record: &NtfsFileRecord,
    entry: &AttributeListEntry,
    expected_base: &MftReference,
    loaded: &mut BTreeMap<u64, NtfsFileRecord>,
    limits: AttributeListLimits,
    attribute_limits: AttributeLimits,
    budget: &mut ReadBudget,
) -> Result<NtfsRunlist, AttributeListError> {
    if entry.file_reference.record_number == base_record_number {
        if entry.file_reference.sequence_number != base_record.sequence_number {
            return Err(AttributeListError::RecordSequenceMismatch {
                record_number: base_record_number,
                expected: entry.file_reference.sequence_number,
                found: base_record.sequence_number,
            });
        }
        return attribute_list_continuation_runlist(
            base_record,
            entry,
            boot,
            limits,
            attribute_limits,
        );
    }
    if let Some(previous) = loaded.get(&entry.file_reference.record_number) {
        if previous.sequence_number != entry.file_reference.sequence_number {
            return Err(AttributeListError::RecordSequenceMismatch {
                record_number: entry.file_reference.record_number,
                expected: entry.file_reference.sequence_number,
                found: previous.sequence_number,
            });
        }
    } else {
        budget.charge(boot.mft_record_size.bytes)?;
        let record = read_mft_record_with_reader(
            image,
            boot,
            mft,
            entry.file_reference.record_number,
            boot.mft_record_size.bytes,
        )?;
        if record.sequence_number != entry.file_reference.sequence_number {
            return Err(AttributeListError::RecordSequenceMismatch {
                record_number: entry.file_reference.record_number,
                expected: entry.file_reference.sequence_number,
                found: record.sequence_number,
            });
        }
        if !record.flags.is_in_use() {
            return Err(AttributeListError::ExtensionNotInUse {
                record_number: entry.file_reference.record_number,
            });
        }
        if record.base_record != Some(*expected_base) {
            return Err(AttributeListError::ExtensionBaseMismatch {
                record_number: entry.file_reference.record_number,
                expected: *expected_base,
                found: record.base_record,
            });
        }
        loaded.insert(entry.file_reference.record_number, record);
    }
    attribute_list_continuation_runlist(
        &loaded[&entry.file_reference.record_number],
        entry,
        boot,
        limits,
        attribute_limits,
    )
}

fn attribute_list_continuation_runlist(
    record: &NtfsFileRecord,
    entry: &AttributeListEntry,
    boot: &NtfsBootSector,
    limits: AttributeListLimits,
    attribute_limits: AttributeLimits,
) -> Result<NtfsRunlist, AttributeListError> {
    let attributes = parse_record_attributes(record, attribute_limits)?;
    let mut matches = attributes
        .attributes
        .iter()
        .filter(|attribute| attribute_matches(entry, attribute));
    let Some(attribute) = matches.next() else {
        return Err(AttributeListError::AttributeNotFound {
            entry_index: 0,
            record_number: entry.file_reference.record_number,
        });
    };
    if matches.next().is_some() {
        return Err(AttributeListError::AttributeMatchedMultipleTimes {
            entry_index: 0,
            record_number: entry.file_reference.record_number,
        });
    }
    if attribute.flags.is_compressed() || attribute.flags.encrypted || attribute.flags.sparse {
        return Err(AttributeListError::UnsupportedAttributeListStorage {
            reason: "continuation stream is compressed, encrypted, or sparse",
        });
    }
    let AttributeBody::NonResident(body) = &attribute.body else {
        return Err(AttributeListError::UnsupportedAttributeListStorage {
            reason: "continuation is resident",
        });
    };
    if body.lowest_vcn != entry.lowest_vcn {
        return Err(AttributeListError::NoncontiguousAttributeListExtent {
            expected_vcn: entry.lowest_vcn,
            found_vcn: body.lowest_vcn,
        });
    }
    Ok(parse_mapping_pairs(
        body.mapping_pairs,
        MappingPairsLimits {
            starting_vcn: body.lowest_vcn,
            expected_next_vcn: Some(body.expected_next_vcn),
            volume_cluster_count: boot.cluster_count,
            max_runs: limits.max_runs,
            max_decoded_clusters: boot.cluster_count,
        },
    )?)
}

fn append_runlist(into: &mut NtfsRunlist, extra: NtfsRunlist) -> Result<(), AttributeListError> {
    let found_vcn = extra
        .extents
        .first()
        .map_or(extra.next_vcn, |extent| extent.vcn);
    if found_vcn != into.next_vcn {
        return Err(AttributeListError::NoncontiguousAttributeListExtent {
            expected_vcn: into.next_vcn,
            found_vcn,
        });
    }
    into.extents.extend(extra.extents);
    into.next_vcn = extra.next_vcn;
    into.encoded_runs = into.encoded_runs.checked_add(extra.encoded_runs).ok_or(
        AttributeListError::GeometryOverflow {
            calculation: "$ATTRIBUTE_LIST run count",
        },
    )?;
    into.bytes_consumed = into
        .bytes_consumed
        .checked_add(extra.bytes_consumed)
        .ok_or(AttributeListError::GeometryOverflow {
            calculation: "$ATTRIBUTE_LIST mapping-pair bytes",
        })?;
    into.decoded_clusters = into
        .decoded_clusters
        .checked_add(extra.decoded_clusters)
        .ok_or(AttributeListError::GeometryOverflow {
            calculation: "$ATTRIBUTE_LIST decoded clusters",
        })?;
    into.physical_clusters = into
        .physical_clusters
        .checked_add(extra.physical_clusters)
        .ok_or(AttributeListError::GeometryOverflow {
            calculation: "$ATTRIBUTE_LIST physical clusters",
        })?;
    into.sparse_clusters = into
        .sparse_clusters
        .checked_add(extra.sparse_clusters)
        .ok_or(AttributeListError::GeometryOverflow {
            calculation: "$ATTRIBUTE_LIST sparse clusters",
        })?;
    Ok(())
}

fn read_stream(
    image: &dyn BoundedImageReader,
    boot: &NtfsBootSector,
    runlist: &NtfsRunlist,
    count: usize,
) -> Result<Vec<u8>, AttributeListError> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(count)
        .map_err(|_| AttributeListError::AllocationFailed)?;
    output.resize(count, 0);
    let mut logical_offset = 0_u64;
    let target = count as u64;
    for extent in &runlist.extents {
        if logical_offset >= target {
            break;
        }
        let extent_start = extent.vcn.checked_mul(boot.cluster_size_bytes).ok_or(
            AttributeListError::GeometryOverflow {
                calculation: "list extent logical start",
            },
        )?;
        if extent_start != logical_offset {
            return Err(AttributeListError::UnsupportedAttributeListStorage {
                reason: "mapping has a logical gap",
            });
        }
        let extent_bytes = extent.length.checked_mul(boot.cluster_size_bytes).ok_or(
            AttributeListError::GeometryOverflow {
                calculation: "list extent byte length",
            },
        )?;
        let take = (target - logical_offset).min(extent_bytes);
        let ExtentLocation::Physical { lcn } = extent.location else {
            return Err(AttributeListError::UnsupportedAttributeListStorage {
                reason: "mapping contains a sparse run",
            });
        };
        let physical = lcn.checked_mul(boot.cluster_size_bytes).ok_or(
            AttributeListError::GeometryOverflow {
                calculation: "list extent physical start",
            },
        )?;
        let start =
            usize::try_from(logical_offset).map_err(|_| AttributeListError::GeometryOverflow {
                calculation: "list output offset",
            })?;
        let take_usize =
            usize::try_from(take).map_err(|_| AttributeListError::GeometryOverflow {
                calculation: "list read length",
            })?;
        read_chunked(image, physical, &mut output[start..start + take_usize])?;
        logical_offset =
            logical_offset
                .checked_add(take)
                .ok_or(AttributeListError::GeometryOverflow {
                    calculation: "list logical progress",
                })?;
    }
    if logical_offset != target {
        return Err(AttributeListError::ListMappingIncomplete {
            mapped_bytes: logical_offset,
            data_bytes: target,
        });
    }
    Ok(output)
}

fn read_chunked(
    image: &dyn BoundedImageReader,
    mut offset: u64,
    mut destination: &mut [u8],
) -> Result<(), AttributeListError> {
    while !destination.is_empty() {
        let count = destination.len().min(image.max_read_bytes());
        let chunk = image.read_exact_at(offset, count)?;
        destination[..count].copy_from_slice(&chunk);
        destination = &mut destination[count..];
        offset = offset
            .checked_add(count as u64)
            .ok_or(AttributeListError::GeometryOverflow {
                calculation: "chunked list read offset",
            })?;
    }
    Ok(())
}

const fn ensure_list_size(actual: u64, maximum: usize) -> Result<(), AttributeListError> {
    if actual > maximum as u64 {
        return Err(AttributeListError::ListTooLarge { actual, maximum });
    }
    Ok(())
}

fn attribute_matches(entry: &AttributeListEntry, attribute: &NtfsAttribute<'_>) -> bool {
    // `$ATTRIBUTE_LIST::instance` is the attribute-record id named `id` by the record parser.
    #[allow(clippy::suspicious_operation_groupings)]
    let same_instance = entry.instance == attribute.id;
    entry.attribute_type == attribute.attribute_type
        && same_instance
        && names_equal(&entry.name, attribute.name.as_ref())
        && match &attribute.body {
            AttributeBody::Resident(_) => entry.lowest_vcn == 0,
            AttributeBody::NonResident(body) => entry.lowest_vcn == body.lowest_vcn,
        }
}

fn names_equal(entry: &[u16], attribute: Option<&AttributeName>) -> bool {
    attribute.map_or(entry.is_empty(), |name| entry == name.code_units)
}

fn compare_entries(left: &AttributeListEntry, right: &AttributeListEntry) -> Ordering {
    left.attribute_type
        .cmp(&right.attribute_type)
        .then_with(|| left.name.cmp(&right.name))
        .then_with(|| left.lowest_vcn.cmp(&right.lowest_vcn))
        .then_with(|| left.instance.cmp(&right.instance))
}

const fn decode_reference(raw: u64) -> MftReference {
    MftReference {
        record_number: raw & 0x0000_ffff_ffff_ffff,
        sequence_number: (raw >> 48) as u16,
    }
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
const fn le_i64(bytes: &[u8], offset: usize) -> i64 {
    i64::from_le_bytes([
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

struct ReadBudget {
    maximum: u64,
    used: u64,
}

impl ReadBudget {
    const fn new(maximum: u64) -> Self {
        Self { maximum, used: 0 }
    }
    fn charge(&mut self, amount: u64) -> Result<(), AttributeListError> {
        let requested_total =
            self.used
                .checked_add(amount)
                .ok_or(AttributeListError::GeometryOverflow {
                    calculation: "aggregate read bytes",
                })?;
        if requested_total > self.maximum {
            return Err(AttributeListError::ReadByteLimitExceeded {
                requested_total,
                maximum: self.maximum,
            });
        }
        self.used = requested_total;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::ntfs::RecordSize;
    use crate::fs::ntfs_record::parse_file_record;
    use crate::fs::ntfs_runlist::NtfsExtent;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

    const CLUSTER_SIZE: usize = 4096;
    const RECORD_SIZE: usize = 1024;
    const MFT_LCN: u64 = 4;
    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TempImage(PathBuf);

    impl TempImage {
        fn create(bytes: &[u8]) -> Self {
            let sequence = NEXT_TEMP.fetch_add(1, AtomicOrdering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "starconverter-attribute-list-{}-{sequence}.img",
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

    fn entry(
        attribute_type: u32,
        name: &[u16],
        lowest_vcn: i64,
        record: u64,
        sequence: u16,
        instance: u16,
    ) -> Vec<u8> {
        let unaligned = ENTRY_HEADER_LEN + name.len() * 2;
        let length = (unaligned + 7) & !7;
        let mut bytes = vec![0_u8; length];
        bytes[0..4].copy_from_slice(&attribute_type.to_le_bytes());
        bytes[4..6].copy_from_slice(&u16::try_from(length).unwrap().to_le_bytes());
        bytes[6] = u8::try_from(name.len()).unwrap();
        if !name.is_empty() {
            bytes[7] = u8::try_from(ENTRY_HEADER_LEN).unwrap();
        }
        bytes[8..16].copy_from_slice(&lowest_vcn.to_le_bytes());
        let reference = record | (u64::from(sequence) << 48);
        bytes[16..24].copy_from_slice(&reference.to_le_bytes());
        bytes[24..26].copy_from_slice(&instance.to_le_bytes());
        for (index, unit) in name.iter().enumerate() {
            let offset = ENTRY_HEADER_LEN + index * 2;
            bytes[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn parses_sorted_entries_losslessly() {
        let mut bytes = entry(0x10, &[], 0, 7, 3, 0);
        bytes.extend(entry(0x80, &[u16::from(b'A')], 4, 9, 2, 5));
        let parsed = parse_attribute_list_value(&bytes, 8, 255).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[1].name, [u16::from(b'A')]);
        assert_eq!(parsed[1].file_reference.record_number, 9);
        assert_eq!(parsed[1].lowest_vcn, 4);
    }

    #[test]
    fn rejects_out_of_order_and_duplicate_entries() {
        let high = entry(0x80, &[], 0, 7, 3, 1);
        let low = entry(0x10, &[], 0, 7, 3, 0);
        let mut reversed = high.clone();
        reversed.extend(low);
        assert!(matches!(
            parse_attribute_list_value(&reversed, 8, 255),
            Err(AttributeListError::EntriesOutOfOrder { .. })
        ));
        let mut duplicate = high.clone();
        duplicate.extend(high);
        assert!(matches!(
            parse_attribute_list_value(&duplicate, 8, 255),
            Err(AttributeListError::DuplicateEntry { .. })
        ));
    }

    #[test]
    fn rejects_malformed_name_and_negative_vcn() {
        let mut bad_name = entry(0x80, &[65], 0, 7, 3, 1);
        bad_name[7] = 25;
        assert!(matches!(
            parse_attribute_list_value(&bad_name, 8, 255),
            Err(AttributeListError::InvalidNameRange { .. })
        ));
        let negative = entry(0x80, &[], -1, 7, 3, 1);
        assert!(matches!(
            parse_attribute_list_value(&negative, 8, 255),
            Err(AttributeListError::NegativeLowestVcn { .. })
        ));
    }

    #[test]
    fn enforces_entry_and_name_caps() {
        let bytes = entry(0x80, &[65, 66], 0, 7, 3, 1);
        assert!(matches!(
            parse_attribute_list_value(&bytes, 0, 2),
            Err(AttributeListError::InvalidLimit {
                field: "max_entries"
            })
        ));
        assert!(matches!(
            parse_attribute_list_value(&bytes, 1, 1),
            Err(AttributeListError::NameLimitExceeded { .. })
        ));
        let mut two = entry(0x80, &[], 0, 7, 3, 1);
        two.extend(entry(0x80, &[], 1, 7, 3, 2));
        assert!(matches!(
            parse_attribute_list_value(&two, 1, 2),
            Err(AttributeListError::EntryLimitExceeded { maximum: 1 })
        ));
    }

    #[test]
    fn accepts_zero_padding_but_rejects_nonzero_tail() {
        let mut bytes = entry(0x80, &[], 0, 7, 3, 1);
        bytes.extend_from_slice(&[0, 0, 0]);
        assert_eq!(parse_attribute_list_value(&bytes, 2, 2).unwrap().len(), 1);
        *bytes.last_mut().unwrap() = 1;
        assert!(matches!(
            parse_attribute_list_value(&bytes, 2, 2),
            Err(AttributeListError::TrailingNonzeroByte { .. })
        ));
    }

    #[test]
    fn resolves_one_extension_once_and_preserves_entry_order() {
        let list_value = resolved_list_value();
        let base_bytes = file_record(
            2,
            7,
            None,
            &[
                resident_attribute(0x20, 1, &list_value),
                nonresident_attribute(0x80, 2, 0, 10),
            ],
        );
        let extension_bytes = file_record(
            5,
            11,
            Some(MftReference {
                record_number: 2,
                sequence_number: 7,
            }),
            &[nonresident_attribute(0x80, 3, 1, 11)],
        );
        let (temp, image, boot, mft) = image_with_records(&base_bytes, &extension_bytes);
        let base = parse_file_record(&base_bytes).unwrap();
        let resolved = resolve_attribute_list(
            &image,
            &boot,
            &mft,
            2,
            &base,
            AttributeListLimits::default(),
        )
        .unwrap();
        assert_eq!(resolved.extension_records.len(), 1);
        assert_eq!(resolved.extension_records[0].record_number, 5);
        assert_eq!(resolved.extents.len(), 2);
        assert_eq!(resolved.extents[0].lowest_vcn, 0);
        assert_eq!(resolved.extents[1].lowest_vcn, 1);
        assert_eq!(resolved.extents[1].record.sequence_number, 11);
        assert_eq!(resolved.bytes_read, RECORD_SIZE as u64);
        drop((temp, image));
    }

    #[test]
    fn rejects_stale_sequence_and_wrong_base_reference() {
        let list_value = resolved_list_value();
        let base_bytes = file_record(
            2,
            7,
            None,
            &[
                resident_attribute(0x20, 1, &list_value),
                nonresident_attribute(0x80, 2, 0, 10),
            ],
        );
        let stale = file_record(
            5,
            12,
            Some(MftReference {
                record_number: 2,
                sequence_number: 7,
            }),
            &[nonresident_attribute(0x80, 3, 1, 11)],
        );
        let (_temp, image, boot, mft) = image_with_records(&base_bytes, &stale);
        let base = parse_file_record(&base_bytes).unwrap();
        assert!(matches!(
            resolve_attribute_list(
                &image,
                &boot,
                &mft,
                2,
                &base,
                AttributeListLimits::default()
            ),
            Err(AttributeListError::RecordSequenceMismatch {
                record_number: 5,
                expected: 11,
                found: 12
            })
        ));

        let wrong_base = file_record(
            5,
            11,
            Some(MftReference {
                record_number: 9,
                sequence_number: 7,
            }),
            &[nonresident_attribute(0x80, 3, 1, 11)],
        );
        let (_temp, image, boot, mft) = image_with_records(&base_bytes, &wrong_base);
        assert!(matches!(
            resolve_attribute_list(
                &image,
                &boot,
                &mft,
                2,
                &base,
                AttributeListLimits::default()
            ),
            Err(AttributeListError::ExtensionBaseMismatch {
                record_number: 5,
                ..
            })
        ));
    }

    #[test]
    fn enforces_record_and_read_caps_before_extension_read() {
        let list_value = resolved_list_value();
        let base_bytes = file_record(
            2,
            7,
            None,
            &[
                resident_attribute(0x20, 1, &list_value),
                nonresident_attribute(0x80, 2, 0, 10),
            ],
        );
        let extension_bytes = file_record(
            5,
            11,
            Some(MftReference {
                record_number: 2,
                sequence_number: 7,
            }),
            &[nonresident_attribute(0x80, 3, 1, 11)],
        );
        let (_temp, image, boot, mft) = image_with_records(&base_bytes, &extension_bytes);
        let base = parse_file_record(&base_bytes).unwrap();
        assert!(matches!(
            resolve_attribute_list(
                &image,
                &boot,
                &mft,
                2,
                &base,
                AttributeListLimits {
                    max_records: 1,
                    ..AttributeListLimits::default()
                }
            ),
            Err(AttributeListError::RecordLimitExceeded { maximum: 1 })
        ));
        assert!(matches!(
            resolve_attribute_list(
                &image,
                &boot,
                &mft,
                2,
                &base,
                AttributeListLimits {
                    max_read_bytes: 1,
                    ..AttributeListLimits::default()
                }
            ),
            Err(AttributeListError::ReadByteLimitExceeded { .. })
        ));
    }

    fn resolved_list_value() -> Vec<u8> {
        let mut value = entry(0x80, &[], 0, 2, 7, 2);
        value.extend(entry(0x80, &[], 1, 5, 11, 3));
        value
    }

    const fn boot() -> NtfsBootSector {
        NtfsBootSector {
            bytes_per_sector: 512,
            sectors_per_cluster: 8,
            cluster_size_bytes: CLUSTER_SIZE as u64,
            declared_sectors: 256,
            cluster_count: 32,
            filesystem_bytes: 256 * 512,
            minimum_image_bytes: 257 * 512,
            mft_lcn: MFT_LCN,
            mft_mirror_lcn: 20,
            mft_record_size: RecordSize {
                encoded: -10,
                bytes: RECORD_SIZE as u64,
            },
            index_buffer_size: RecordSize {
                encoded: -10,
                bytes: RECORD_SIZE as u64,
            },
            volume_serial_number: 1,
            boot_checksum: 0,
            media_descriptor: 0xf8,
            sectors_per_track: 63,
            head_count: 255,
            hidden_sectors: 0,
        }
    }

    fn image_with_records(
        base: &[u8],
        extension: &[u8],
    ) -> (TempImage, ImageFile, NtfsBootSector, MftBootstrap) {
        let mut bytes = vec![0_u8; 257 * 512];
        let mft_start = usize::try_from(MFT_LCN).unwrap() * CLUSTER_SIZE;
        bytes[mft_start + 2 * RECORD_SIZE..mft_start + 3 * RECORD_SIZE].copy_from_slice(base);
        bytes[mft_start + 5 * RECORD_SIZE..mft_start + 6 * RECORD_SIZE].copy_from_slice(extension);
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();
        let runlist = NtfsRunlist {
            extents: vec![NtfsExtent {
                vcn: 0,
                length: 2,
                location: ExtentLocation::Physical { lcn: MFT_LCN },
            }],
            next_vcn: 2,
            encoded_runs: 1,
            bytes_consumed: 4,
            decoded_clusters: 2,
            physical_clusters: 2,
            sparse_clusters: 0,
        };
        let mft = MftBootstrap {
            runlist,
            allocated_bytes: (2 * CLUSTER_SIZE) as u64,
            data_bytes: (2 * CLUSTER_SIZE) as u64,
            initialized_bytes: (2 * CLUSTER_SIZE) as u64,
            mapping_complete: true,
            record_zero_sequence_number: 1,
        };
        (temp, image, boot(), mft)
    }

    fn resident_attribute(attribute_type: u32, id: u16, value: &[u8]) -> Vec<u8> {
        let length = (24 + value.len() + 7) & !7;
        let mut bytes = vec![0_u8; length];
        bytes[0..4].copy_from_slice(&attribute_type.to_le_bytes());
        bytes[4..8].copy_from_slice(&u32::try_from(length).unwrap().to_le_bytes());
        bytes[14..16].copy_from_slice(&id.to_le_bytes());
        bytes[16..20].copy_from_slice(&u32::try_from(value.len()).unwrap().to_le_bytes());
        bytes[20..22].copy_from_slice(&24_u16.to_le_bytes());
        bytes[24..24 + value.len()].copy_from_slice(value);
        bytes
    }

    fn nonresident_attribute(attribute_type: u32, id: u16, lowest_vcn: u64, lcn: u8) -> Vec<u8> {
        let mut bytes = vec![0_u8; 72];
        bytes[0..4].copy_from_slice(&attribute_type.to_le_bytes());
        bytes[4..8].copy_from_slice(&72_u32.to_le_bytes());
        bytes[8] = 1;
        bytes[14..16].copy_from_slice(&id.to_le_bytes());
        let lowest_vcn = i64::try_from(lowest_vcn).unwrap();
        bytes[16..24].copy_from_slice(&lowest_vcn.to_le_bytes());
        bytes[24..32].copy_from_slice(&lowest_vcn.to_le_bytes());
        bytes[32..34].copy_from_slice(&64_u16.to_le_bytes());
        if lowest_vcn == 0 {
            for offset in [40, 48, 56] {
                bytes[offset..offset + 8]
                    .copy_from_slice(&i64::try_from(CLUSTER_SIZE).unwrap().to_le_bytes());
            }
        }
        bytes[64..68].copy_from_slice(&[0x11, 1, lcn, 0]);
        bytes
    }

    fn file_record(
        record_number: u32,
        sequence: u16,
        base: Option<MftReference>,
        attributes: &[Vec<u8>],
    ) -> Vec<u8> {
        let mut bytes = vec![0_u8; RECORD_SIZE];
        bytes[0..4].copy_from_slice(b"FILE");
        bytes[4..6].copy_from_slice(&48_u16.to_le_bytes());
        bytes[6..8].copy_from_slice(&3_u16.to_le_bytes());
        bytes[16..18].copy_from_slice(&sequence.to_le_bytes());
        bytes[18..20].copy_from_slice(&1_u16.to_le_bytes());
        bytes[20..22].copy_from_slice(&56_u16.to_le_bytes());
        bytes[22..24].copy_from_slice(&1_u16.to_le_bytes());
        bytes[28..32].copy_from_slice(&u32::try_from(RECORD_SIZE).unwrap().to_le_bytes());
        if let Some(reference) = base {
            let raw = reference.record_number | (u64::from(reference.sequence_number) << 48);
            bytes[32..40].copy_from_slice(&raw.to_le_bytes());
        }
        bytes[40..42].copy_from_slice(&16_u16.to_le_bytes());
        bytes[44..48].copy_from_slice(&record_number.to_le_bytes());
        let mut offset = 56;
        for attribute in attributes {
            bytes[offset..offset + attribute.len()].copy_from_slice(attribute);
            offset += attribute.len();
        }
        bytes[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        offset += 8;
        bytes[24..28].copy_from_slice(&u32::try_from(offset).unwrap().to_le_bytes());
        let usn = 0xa55a_u16;
        bytes[48..50].copy_from_slice(&usn.to_le_bytes());
        let first_tail = [bytes[510], bytes[511]];
        let second_tail = [bytes[1022], bytes[1023]];
        bytes[50..52].copy_from_slice(&first_tail);
        bytes[52..54].copy_from_slice(&second_tail);
        bytes[510..512].copy_from_slice(&usn.to_le_bytes());
        bytes[1022..1024].copy_from_slice(&usn.to_le_bytes());
        bytes
    }
}
