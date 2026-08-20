//! Bounded parsing of attributes in a repaired NTFS `FILE` record.
//!
//! Callers must apply and validate the record's update-sequence fixups before using this module.
//! Attribute values and mapping pairs remain borrowed from caller-owned bytes. The only per-item
//! allocation is a caller-capped vector of UTF-16 name code units.

use std::fmt;

const COMMON_HEADER_LEN: usize = 16;
const RESIDENT_HEADER_LEN: usize = 24;
const NON_RESIDENT_HEADER_LEN: usize = 64;
const EXTENDED_NON_RESIDENT_HEADER_LEN: usize = 72;
const ATTRIBUTE_END: u32 = 0xffff_ffff;
const COMPRESSION_MASK: u16 = 0x00ff;
const COMPRESSED: u16 = 0x0001;
const ENCRYPTED: u16 = 0x4000;
const SPARSE: u16 = 0x8000;
const KNOWN_FLAGS: u16 = COMPRESSION_MASK | ENCRYPTED | SPARSE;

type ByteRange = (usize, usize);
type ParsedName = (Option<AttributeName>, Option<ByteRange>);

/// Caller-controlled parser limits and containing-volume geometry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttributeLimits {
    /// Cluster size used to validate non-resident allocation fields.
    pub cluster_size_bytes: u64,
    /// Largest individual attribute record accepted.
    pub max_attribute_bytes: usize,
    /// Largest number of UTF-16 code units copied for an attribute name.
    pub max_name_code_units: usize,
    /// Largest number of attributes collected from one `FILE` record.
    pub max_attributes: usize,
}

/// Lossless, bounded attribute-name representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeName {
    /// UTF-16 code units exactly as represented on disk.
    pub code_units: Vec<u16>,
    /// Whether the code units form a Unicode scalar sequence without unpaired surrogates.
    pub is_well_formed: bool,
}

/// Decoded attribute flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttributeFlags {
    pub raw: u16,
    pub compression_method: u8,
    pub encrypted: bool,
    pub sparse: bool,
    /// Reserved bits retained so an inventory can report unsupported semantics losslessly.
    pub unknown_bits: u16,
}

impl AttributeFlags {
    #[must_use]
    pub const fn is_compressed(self) -> bool {
        self.compression_method != 0
    }
}

/// Header and borrowed value of a resident attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResidentAttribute<'a> {
    pub indexed: bool,
    pub value_offset: u16,
    pub value: &'a [u8],
}

/// Size evidence present only in the first extent of a non-resident attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NonResidentSizes {
    pub allocated: u64,
    pub data: u64,
    pub initialized: u64,
    /// Actual allocated storage for compressed or sparse attributes.
    pub compressed: Option<u64>,
}

/// Header and borrowed mapping-pairs bytes of a non-resident attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonResidentAttribute<'a> {
    pub lowest_vcn: u64,
    /// `None` represents the documented `-1` value for an empty first extent.
    pub highest_vcn: Option<u64>,
    /// VCN immediately after this extent, suitable for `MappingPairsLimits.expected_next_vcn`.
    pub expected_next_vcn: u64,
    pub mapping_pairs_offset: u16,
    pub mapping_pairs: &'a [u8],
    pub compression_unit: u8,
    pub compression_block_bytes: Option<u64>,
    /// `None` on continuation extents, whose on-disk size fields are not authoritative.
    pub sizes: Option<NonResidentSizes>,
}

/// Storage form of a parsed NTFS attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttributeBody<'a> {
    Resident(ResidentAttribute<'a>),
    NonResident(NonResidentAttribute<'a>),
}

/// One validated NTFS attribute record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsAttribute<'a> {
    pub attribute_type: u32,
    pub length: u32,
    pub name: Option<AttributeName>,
    pub name_offset: u16,
    pub flags: AttributeFlags,
    pub id: u16,
    pub raw: &'a [u8],
    pub body: AttributeBody<'a>,
}

/// Bounded attribute collection ending at an NTFS end marker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsAttributeList<'a> {
    pub attributes: Vec<NtfsAttribute<'a>>,
    pub end_marker_offset: usize,
}

/// Attribute field identified by a range error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttributeRange {
    Name,
    ResidentValue,
    MappingPairs,
}

impl fmt::Display for AttributeRange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Name => "name",
            Self::ResidentValue => "resident value",
            Self::MappingPairs => "mapping pairs",
        })
    }
}

/// Reason an attribute or repaired record attribute list is inconsistent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NtfsAttributeError {
    InvalidClusterSize {
        value: u64,
    },
    Truncated {
        actual: usize,
        required: usize,
    },
    EndMarker,
    InvalidType {
        value: u32,
    },
    InvalidLength {
        value: u32,
        available: usize,
    },
    AttributeTooLarge {
        value: usize,
        maximum: usize,
    },
    InvalidStorageForm {
        value: u8,
    },
    NameLimitExceeded {
        value: usize,
        maximum: usize,
    },
    InvalidNameOffset {
        value: u16,
        minimum: usize,
    },
    RangeOutOfBounds {
        range: AttributeRange,
        offset: usize,
        length: usize,
        attribute_length: usize,
    },
    OverlappingRanges {
        first: AttributeRange,
        second: AttributeRange,
    },
    InvalidFlags {
        value: u16,
    },
    InvalidResidentFlags {
        value: u8,
    },
    ResidentReservedNotZero {
        value: u8,
    },
    InvalidValueOffset {
        value: u16,
    },
    NonResidentReservedNotZero,
    InvalidVcnRange {
        lowest: i64,
        highest: i64,
    },
    VcnOverflow {
        highest: u64,
    },
    InvalidMappingPairsOffset {
        value: u16,
        minimum: usize,
    },
    InvalidCompressionUnit {
        value: u8,
        flags: u16,
    },
    SizeFieldNegative {
        field: &'static str,
        value: i64,
    },
    SizeNotClusterAligned {
        field: &'static str,
        value: u64,
        cluster_size: u64,
    },
    InitializedExceedsData {
        initialized: u64,
        data: u64,
    },
    DataExceedsAllocation {
        data: u64,
        allocated: u64,
    },
    CompressedExceedsAllocation {
        compressed: u64,
        allocated: u64,
    },
    CompressionBlockOverflow,
    AllocationNotCompressionBlockAligned {
        allocated: u64,
        block_size: u64,
    },
    InvalidRecordBounds {
        attributes_offset: usize,
        bytes_in_use: usize,
        record_len: usize,
    },
    AttributeLimitExceeded {
        maximum: usize,
    },
    AttributeTypesOutOfOrder {
        previous: u32,
        current: u32,
    },
    DuplicateAttributeId {
        id: u16,
    },
    MissingEndMarker,
    AllocationFailed,
}

impl fmt::Display for NtfsAttributeError {
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidClusterSize { value } => {
                write!(formatter, "invalid NTFS cluster size {value}")
            }
            Self::Truncated { actual, required } => write!(
                formatter,
                "attribute is truncated: got {actual} bytes, need {required}"
            ),
            Self::EndMarker => formatter.write_str("attribute parser was given an end marker"),
            Self::InvalidType { value } => {
                write!(formatter, "invalid NTFS attribute type 0x{value:08x}")
            }
            Self::InvalidLength { value, available } => write!(
                formatter,
                "invalid attribute length {value}; {available} bytes are available"
            ),
            Self::AttributeTooLarge { value, maximum } => write!(
                formatter,
                "attribute length {value} exceeds caller cap {maximum}"
            ),
            Self::InvalidStorageForm { value } => {
                write!(formatter, "invalid attribute storage-form byte {value}")
            }
            Self::NameLimitExceeded { value, maximum } => write!(
                formatter,
                "attribute name has {value} UTF-16 units, exceeding caller cap {maximum}"
            ),
            Self::InvalidNameOffset { value, minimum } => write!(
                formatter,
                "invalid attribute-name offset {value}; minimum is {minimum}"
            ),
            Self::RangeOutOfBounds {
                range,
                offset,
                length,
                attribute_length,
            } => write!(
                formatter,
                "attribute {range} range {offset}..{} exceeds attribute length {attribute_length}",
                offset.saturating_add(*length)
            ),
            Self::OverlappingRanges { first, second } => {
                write!(formatter, "attribute {first} overlaps {second}")
            }
            Self::InvalidFlags { value } => {
                write!(formatter, "invalid attribute flags 0x{value:04x}")
            }
            Self::InvalidResidentFlags { value } => {
                write!(formatter, "invalid resident attribute flags 0x{value:02x}")
            }
            Self::ResidentReservedNotZero { value } => write!(
                formatter,
                "resident attribute reserved byte is nonzero: {value}"
            ),
            Self::InvalidValueOffset { value } => {
                write!(formatter, "invalid resident value offset {value}")
            }
            Self::NonResidentReservedNotZero => {
                formatter.write_str("non-resident attribute reserved bytes are nonzero")
            }
            Self::InvalidVcnRange { lowest, highest } => write!(
                formatter,
                "invalid non-resident VCN range {lowest}..={highest}"
            ),
            Self::VcnOverflow { highest } => {
                write!(formatter, "highest VCN {highest} has no following VCN")
            }
            Self::InvalidMappingPairsOffset { value, minimum } => write!(
                formatter,
                "invalid mapping-pairs offset {value}; minimum is {minimum}"
            ),
            Self::InvalidCompressionUnit { value, flags } => write!(
                formatter,
                "compression unit {value} is inconsistent with flags 0x{flags:04x}"
            ),
            Self::SizeFieldNegative { field, value } => {
                write!(formatter, "non-resident {field} is negative: {value}")
            }
            Self::SizeNotClusterAligned {
                field,
                value,
                cluster_size,
            } => write!(
                formatter,
                "non-resident {field} {value} is not aligned to cluster size {cluster_size}"
            ),
            Self::InitializedExceedsData { initialized, data } => write!(
                formatter,
                "initialized size {initialized} exceeds data size {data}"
            ),
            Self::DataExceedsAllocation { data, allocated } => write!(
                formatter,
                "data size {data} exceeds non-sparse allocation {allocated}"
            ),
            Self::CompressedExceedsAllocation {
                compressed,
                allocated,
            } => write!(
                formatter,
                "compressed size {compressed} exceeds logical allocation {allocated}"
            ),
            Self::CompressionBlockOverflow => {
                formatter.write_str("compression block size overflows u64")
            }
            Self::AllocationNotCompressionBlockAligned {
                allocated,
                block_size,
            } => write!(
                formatter,
                "compressed allocation {allocated} is not aligned to compression block {block_size}"
            ),
            Self::InvalidRecordBounds {
                attributes_offset,
                bytes_in_use,
                record_len,
            } => write!(
                formatter,
                "invalid repaired-record attribute bounds: offset {attributes_offset}, used {bytes_in_use}, length {record_len}"
            ),
            Self::AttributeLimitExceeded { maximum } => {
                write!(formatter, "attribute count exceeds caller cap {maximum}")
            }
            Self::AttributeTypesOutOfOrder { previous, current } => write!(
                formatter,
                "attribute type 0x{current:08x} follows 0x{previous:08x} out of order"
            ),
            Self::DuplicateAttributeId { id } => write!(formatter, "duplicate attribute id {id}"),
            Self::MissingEndMarker => {
                formatter.write_str("repaired FILE record has no attribute end marker")
            }
            Self::AllocationFailed => {
                formatter.write_str("could not allocate bounded attribute metadata")
            }
        }
    }
}

impl std::error::Error for NtfsAttributeError {}

/// Parses one attribute at the beginning of `bytes`.
///
/// The declared attribute length may be shorter than `bytes`; [`NtfsAttribute::raw`] and all body
/// slices are bounded to that declared length.
///
/// # Errors
///
/// Returns [`NtfsAttributeError`] for malformed geometry, fields, ranges, flags, VCNs, or sizes,
/// and for caller-limit violations.
pub fn parse_attribute(
    bytes: &[u8],
    limits: AttributeLimits,
) -> Result<NtfsAttribute<'_>, NtfsAttributeError> {
    validate_limits(limits)?;
    if bytes.len() < COMMON_HEADER_LEN {
        return Err(NtfsAttributeError::Truncated {
            actual: bytes.len(),
            required: COMMON_HEADER_LEN,
        });
    }
    let attribute_type = le_u32(bytes, 0);
    validate_type(attribute_type)?;
    let length_u32 = le_u32(bytes, 4);
    let length = usize::try_from(length_u32).unwrap_or(usize::MAX);
    if length < COMMON_HEADER_LEN || length % 8 != 0 || length > bytes.len() {
        return Err(NtfsAttributeError::InvalidLength {
            value: length_u32,
            available: bytes.len(),
        });
    }
    if length > limits.max_attribute_bytes {
        return Err(NtfsAttributeError::AttributeTooLarge {
            value: length,
            maximum: limits.max_attribute_bytes,
        });
    }
    let raw = &bytes[..length];
    let form = raw[8];
    if form > 1 {
        return Err(NtfsAttributeError::InvalidStorageForm { value: form });
    }
    let flags = parse_flags(le_u16(raw, 12))?;
    let header_len = if form == 0 {
        RESIDENT_HEADER_LEN
    } else if flags.is_compressed() || flags.sparse {
        EXTENDED_NON_RESIDENT_HEADER_LEN
    } else {
        NON_RESIDENT_HEADER_LEN
    };
    if length < header_len {
        return Err(NtfsAttributeError::Truncated {
            actual: length,
            required: header_len,
        });
    }
    let (name, name_range) = parse_name(raw, header_len, limits.max_name_code_units)?;
    let body = if form == 0 {
        AttributeBody::Resident(parse_resident(raw, flags, name_range)?)
    } else {
        AttributeBody::NonResident(parse_non_resident(
            raw,
            flags,
            name_range,
            limits.cluster_size_bytes,
        )?)
    };
    Ok(NtfsAttribute {
        attribute_type,
        length: length_u32,
        name,
        name_offset: le_u16(raw, 10),
        flags,
        id: le_u16(raw, 14),
        raw,
        body,
    })
}

/// Parses the attribute sequence in an already repaired and header-validated `FILE` record.
///
/// # Errors
///
/// Returns [`NtfsAttributeError`] for bad record bounds, malformed attributes, duplicate IDs,
/// unsorted types, a missing end marker, allocation failure, or a caller-limit violation.
pub fn parse_attribute_list(
    repaired_record: &[u8],
    attributes_offset: usize,
    bytes_in_use: usize,
    limits: AttributeLimits,
) -> Result<NtfsAttributeList<'_>, NtfsAttributeError> {
    validate_limits(limits)?;
    if attributes_offset > bytes_in_use || bytes_in_use > repaired_record.len() {
        return Err(NtfsAttributeError::InvalidRecordBounds {
            attributes_offset,
            bytes_in_use,
            record_len: repaired_record.len(),
        });
    }
    let mut attributes = Vec::new();
    let mut offset = attributes_offset;
    let mut previous_type = 0_u32;
    while offset.checked_add(4).is_some_and(|end| end <= bytes_in_use) {
        let attribute_type = le_u32(repaired_record, offset);
        if attribute_type == ATTRIBUTE_END {
            return Ok(NtfsAttributeList {
                attributes,
                end_marker_offset: offset,
            });
        }
        if attributes.len() >= limits.max_attributes {
            return Err(NtfsAttributeError::AttributeLimitExceeded {
                maximum: limits.max_attributes,
            });
        }
        let parsed = parse_attribute(&repaired_record[offset..bytes_in_use], limits)?;
        if parsed.attribute_type < previous_type {
            return Err(NtfsAttributeError::AttributeTypesOutOfOrder {
                previous: previous_type,
                current: parsed.attribute_type,
            });
        }
        if attributes
            .iter()
            .any(|existing: &NtfsAttribute<'_>| existing.id == parsed.id)
        {
            return Err(NtfsAttributeError::DuplicateAttributeId { id: parsed.id });
        }
        previous_type = parsed.attribute_type;
        offset = offset
            .checked_add(parsed.raw.len())
            .ok_or(NtfsAttributeError::MissingEndMarker)?;
        attributes
            .try_reserve(1)
            .map_err(|_| NtfsAttributeError::AllocationFailed)?;
        attributes.push(parsed);
    }
    Err(NtfsAttributeError::MissingEndMarker)
}

const fn validate_limits(limits: AttributeLimits) -> Result<(), NtfsAttributeError> {
    if limits.cluster_size_bytes < 512 || !limits.cluster_size_bytes.is_power_of_two() {
        return Err(NtfsAttributeError::InvalidClusterSize {
            value: limits.cluster_size_bytes,
        });
    }
    Ok(())
}

const fn validate_type(value: u32) -> Result<(), NtfsAttributeError> {
    if value == ATTRIBUTE_END {
        return Err(NtfsAttributeError::EndMarker);
    }
    if value < 0x10 || value & 0x0f != 0 {
        return Err(NtfsAttributeError::InvalidType { value });
    }
    Ok(())
}

const fn parse_flags(raw: u16) -> Result<AttributeFlags, NtfsAttributeError> {
    let compression_method = (raw & COMPRESSION_MASK) as u8;
    if compression_method > 1
        || raw & !(KNOWN_FLAGS) != 0
        || raw & ENCRYPTED != 0 && raw & (COMPRESSED | SPARSE) != 0
    {
        return Err(NtfsAttributeError::InvalidFlags { value: raw });
    }
    Ok(AttributeFlags {
        raw,
        compression_method,
        encrypted: raw & ENCRYPTED != 0,
        sparse: raw & SPARSE != 0,
        unknown_bits: raw & !KNOWN_FLAGS,
    })
}

fn parse_name(
    raw: &[u8],
    header_len: usize,
    maximum: usize,
) -> Result<ParsedName, NtfsAttributeError> {
    let units = usize::from(raw[9]);
    if units == 0 {
        return Ok((None, None));
    }
    if units > maximum {
        return Err(NtfsAttributeError::NameLimitExceeded {
            value: units,
            maximum,
        });
    }
    let offset_u16 = le_u16(raw, 10);
    let offset = usize::from(offset_u16);
    if offset < header_len || offset % 2 != 0 {
        return Err(NtfsAttributeError::InvalidNameOffset {
            value: offset_u16,
            minimum: header_len,
        });
    }
    let length = units
        .checked_mul(2)
        .ok_or(NtfsAttributeError::RangeOutOfBounds {
            range: AttributeRange::Name,
            offset,
            length: usize::MAX,
            attribute_length: raw.len(),
        })?;
    let name_bytes = checked_range(raw, AttributeRange::Name, offset, length)?;
    let mut code_units = Vec::new();
    code_units
        .try_reserve_exact(units)
        .map_err(|_| NtfsAttributeError::AllocationFailed)?;
    for pair in name_bytes.chunks_exact(2) {
        code_units.push(u16::from_le_bytes([pair[0], pair[1]]));
    }
    let is_well_formed = char::decode_utf16(code_units.iter().copied()).all(|item| item.is_ok());
    Ok((
        Some(AttributeName {
            code_units,
            is_well_formed,
        }),
        Some((offset, length)),
    ))
}

fn parse_resident(
    raw: &[u8],
    flags: AttributeFlags,
    name: Option<ByteRange>,
) -> Result<ResidentAttribute<'_>, NtfsAttributeError> {
    if flags.raw != 0 {
        return Err(NtfsAttributeError::InvalidFlags { value: flags.raw });
    }
    let resident_flags = raw[22];
    if resident_flags & !1 != 0 {
        return Err(NtfsAttributeError::InvalidResidentFlags {
            value: resident_flags,
        });
    }
    if raw[23] != 0 {
        return Err(NtfsAttributeError::ResidentReservedNotZero { value: raw[23] });
    }
    let value_offset_u16 = le_u16(raw, 20);
    let value_offset = usize::from(value_offset_u16);
    if value_offset < RESIDENT_HEADER_LEN || (name.is_some() && value_offset % 8 != 0) {
        return Err(NtfsAttributeError::InvalidValueOffset {
            value: value_offset_u16,
        });
    }
    let value_length = usize::try_from(le_u32(raw, 16)).unwrap_or(usize::MAX);
    let value = checked_range(
        raw,
        AttributeRange::ResidentValue,
        value_offset,
        value_length,
    )?;
    validate_no_overlap(
        name,
        (value_offset, value_length),
        AttributeRange::Name,
        AttributeRange::ResidentValue,
    )?;
    Ok(ResidentAttribute {
        indexed: resident_flags & 1 != 0,
        value_offset: value_offset_u16,
        value,
    })
}

fn parse_non_resident(
    raw: &[u8],
    flags: AttributeFlags,
    name: Option<ByteRange>,
    cluster_size: u64,
) -> Result<NonResidentAttribute<'_>, NtfsAttributeError> {
    if raw[35..40].iter().any(|byte| *byte != 0) {
        return Err(NtfsAttributeError::NonResidentReservedNotZero);
    }
    let lowest_signed = le_i64(raw, 16);
    let highest_signed = le_i64(raw, 24);
    let (lowest_vcn, highest_vcn, expected_next_vcn) = parse_vcns(lowest_signed, highest_signed)?;
    let header_len = if flags.is_compressed() || flags.sparse {
        EXTENDED_NON_RESIDENT_HEADER_LEN
    } else {
        NON_RESIDENT_HEADER_LEN
    };
    let mapping_offset_u16 = le_u16(raw, 32);
    let mapping_offset = usize::from(mapping_offset_u16);
    if mapping_offset < header_len || mapping_offset % 8 != 0 || mapping_offset >= raw.len() {
        return Err(NtfsAttributeError::InvalidMappingPairsOffset {
            value: mapping_offset_u16,
            minimum: header_len,
        });
    }
    validate_no_overlap(
        name,
        (mapping_offset, raw.len() - mapping_offset),
        AttributeRange::Name,
        AttributeRange::MappingPairs,
    )?;
    let compression_unit = raw[34];
    let compression_block_bytes = validate_compression(flags, compression_unit, cluster_size)?;
    let sizes = if lowest_vcn == 0 {
        Some(parse_sizes(
            raw,
            flags,
            cluster_size,
            compression_block_bytes,
        )?)
    } else {
        None
    };
    Ok(NonResidentAttribute {
        lowest_vcn,
        highest_vcn,
        expected_next_vcn,
        mapping_pairs_offset: mapping_offset_u16,
        mapping_pairs: &raw[mapping_offset..],
        compression_unit,
        compression_block_bytes,
        sizes,
    })
}

fn parse_vcns(lowest: i64, highest: i64) -> Result<(u64, Option<u64>, u64), NtfsAttributeError> {
    if lowest == 0 && highest == -1 {
        return Ok((0, None, 0));
    }
    let Ok(lowest_u64) = u64::try_from(lowest) else {
        return Err(NtfsAttributeError::InvalidVcnRange { lowest, highest });
    };
    let Ok(highest_u64) = u64::try_from(highest) else {
        return Err(NtfsAttributeError::InvalidVcnRange { lowest, highest });
    };
    if highest_u64 < lowest_u64 {
        return Err(NtfsAttributeError::InvalidVcnRange { lowest, highest });
    }
    let expected = highest_u64
        .checked_add(1)
        .ok_or(NtfsAttributeError::VcnOverflow {
            highest: highest_u64,
        })?;
    Ok((lowest_u64, Some(highest_u64), expected))
}

fn validate_compression(
    flags: AttributeFlags,
    unit: u8,
    cluster_size: u64,
) -> Result<Option<u64>, NtfsAttributeError> {
    if flags.is_compressed() {
        if unit == 0 || unit > 31 {
            return Err(NtfsAttributeError::InvalidCompressionUnit {
                value: unit,
                flags: flags.raw,
            });
        }
        let clusters = 1_u64
            .checked_shl(u32::from(unit))
            .ok_or(NtfsAttributeError::CompressionBlockOverflow)?;
        let bytes = cluster_size
            .checked_mul(clusters)
            .ok_or(NtfsAttributeError::CompressionBlockOverflow)?;
        Ok(Some(bytes))
    } else {
        if unit != 0 {
            return Err(NtfsAttributeError::InvalidCompressionUnit {
                value: unit,
                flags: flags.raw,
            });
        }
        Ok(None)
    }
}

fn parse_sizes(
    raw: &[u8],
    flags: AttributeFlags,
    cluster_size: u64,
    compression_block: Option<u64>,
) -> Result<NonResidentSizes, NtfsAttributeError> {
    let allocated = nonnegative_size(raw, 40, "allocated size")?;
    let data = nonnegative_size(raw, 48, "data size")?;
    let initialized = nonnegative_size(raw, 56, "initialized size")?;
    validate_cluster_alignment("allocated size", allocated, cluster_size)?;
    if initialized > data {
        return Err(NtfsAttributeError::InitializedExceedsData { initialized, data });
    }
    if !flags.sparse && !flags.is_compressed() && data > allocated {
        return Err(NtfsAttributeError::DataExceedsAllocation { data, allocated });
    }
    match compression_block {
        Some(block_size) if allocated % block_size != 0 => {
            return Err(NtfsAttributeError::AllocationNotCompressionBlockAligned {
                allocated,
                block_size,
            });
        }
        _ => {}
    }
    let compressed = if flags.sparse || flags.is_compressed() {
        let value = nonnegative_size(raw, 64, "compressed size")?;
        validate_cluster_alignment("compressed size", value, cluster_size)?;
        if value > allocated {
            return Err(NtfsAttributeError::CompressedExceedsAllocation {
                compressed: value,
                allocated,
            });
        }
        Some(value)
    } else {
        None
    };
    Ok(NonResidentSizes {
        allocated,
        data,
        initialized,
        compressed,
    })
}

fn nonnegative_size(
    raw: &[u8],
    offset: usize,
    field: &'static str,
) -> Result<u64, NtfsAttributeError> {
    let value = le_i64(raw, offset);
    u64::try_from(value).map_err(|_| NtfsAttributeError::SizeFieldNegative { field, value })
}

const fn validate_cluster_alignment(
    field: &'static str,
    value: u64,
    cluster_size: u64,
) -> Result<(), NtfsAttributeError> {
    if value % cluster_size != 0 {
        return Err(NtfsAttributeError::SizeNotClusterAligned {
            field,
            value,
            cluster_size,
        });
    }
    Ok(())
}

fn checked_range(
    raw: &[u8],
    range: AttributeRange,
    offset: usize,
    length: usize,
) -> Result<&[u8], NtfsAttributeError> {
    let Some(end) = offset.checked_add(length) else {
        return Err(NtfsAttributeError::RangeOutOfBounds {
            range,
            offset,
            length,
            attribute_length: raw.len(),
        });
    };
    raw.get(offset..end)
        .ok_or(NtfsAttributeError::RangeOutOfBounds {
            range,
            offset,
            length,
            attribute_length: raw.len(),
        })
}

const fn validate_no_overlap(
    first: Option<(usize, usize)>,
    second: (usize, usize),
    first_kind: AttributeRange,
    second_kind: AttributeRange,
) -> Result<(), NtfsAttributeError> {
    if let Some((first_offset, first_length)) = first {
        let first_end = first_offset.saturating_add(first_length);
        let second_end = second.0.saturating_add(second.1);
        if first_offset < second_end && second.0 < first_end {
            return Err(NtfsAttributeError::OverlappingRanges {
                first: first_kind,
                second: second_kind,
            });
        }
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    const fn limits() -> AttributeLimits {
        AttributeLimits {
            cluster_size_bytes: 4096,
            max_attribute_bytes: 4096,
            max_name_code_units: 255,
            max_attributes: 16,
        }
    }

    fn resident() -> Vec<u8> {
        let mut bytes = vec![0_u8; 32];
        set_u32(&mut bytes, 0, 0x10);
        set_u32(&mut bytes, 4, 32);
        set_u32(&mut bytes, 16, 4);
        set_u16(&mut bytes, 20, 24);
        bytes[22] = 1;
        bytes[24..28].copy_from_slice(b"DATA");
        bytes
    }

    fn nonresident(flags: u16) -> Vec<u8> {
        let header = if flags & (COMPRESSED | SPARSE) != 0 {
            72
        } else {
            64
        };
        let mut bytes = vec![0_u8; header + 8];
        set_u32(&mut bytes, 0, 0x80);
        let length = u32::try_from(bytes.len()).expect("test length fits");
        set_u32(&mut bytes, 4, length);
        bytes[8] = 1;
        set_u16(&mut bytes, 12, flags);
        set_i64(&mut bytes, 16, 0);
        set_i64(&mut bytes, 24, 1);
        set_u16(
            &mut bytes,
            32,
            u16::try_from(header).expect("test offset fits"),
        );
        set_i64(&mut bytes, 40, 8192);
        set_i64(&mut bytes, 48, 7000);
        set_i64(&mut bytes, 56, 6000);
        if header == 72 {
            set_i64(&mut bytes, 64, 4096);
        }
        bytes[header] = 0x11;
        bytes[header + 1] = 2;
        bytes[header + 2] = 5;
        bytes
    }

    fn set_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn set_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn set_i64(bytes: &mut [u8], offset: usize, value: i64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn parses_borrowed_resident_value() {
        let bytes = resident();
        let parsed = parse_attribute(&bytes, limits()).expect("valid resident attribute");
        let AttributeBody::Resident(body) = parsed.body else {
            panic!("resident")
        };
        assert_eq!(body.value, b"DATA");
        assert!(body.indexed);
        assert_eq!(body.value.as_ptr(), bytes[24..].as_ptr());
    }

    #[test]
    fn preserves_utf16_name_code_units_and_reports_well_formedness() {
        let mut bytes = resident();
        bytes.resize(48, 0);
        set_u32(&mut bytes, 4, 48);
        bytes[9] = 2;
        set_u16(&mut bytes, 10, 24);
        set_u16(&mut bytes, 24, 0xd800);
        set_u16(&mut bytes, 26, 0x0041);
        set_u32(&mut bytes, 16, 4);
        set_u16(&mut bytes, 20, 32);
        bytes[32..36].copy_from_slice(b"DATA");
        let parsed = parse_attribute(&bytes, limits()).expect("losslessly represented name");
        let name = parsed.name.expect("name");
        assert_eq!(name.code_units, [0xd800, 0x0041]);
        assert!(!name.is_well_formed);
    }

    #[test]
    fn parses_regular_nonresident_extent_for_runlist_handoff() {
        let bytes = nonresident(0);
        let parsed = parse_attribute(&bytes, limits()).expect("valid non-resident attribute");
        let AttributeBody::NonResident(body) = parsed.body else {
            panic!("nonresident")
        };
        assert_eq!(body.lowest_vcn, 0);
        assert_eq!(body.highest_vcn, Some(1));
        assert_eq!(body.expected_next_vcn, 2);
        assert_eq!(&body.mapping_pairs[..4], &[0x11, 2, 5, 0]);
        assert_eq!(body.sizes.expect("first extent").data, 7000);
    }

    #[test]
    fn parses_compressed_and_sparse_extended_sizes() {
        let mut compressed = nonresident(COMPRESSED);
        compressed[34] = 1;
        let parsed = parse_attribute(&compressed, limits()).expect("compressed attribute");
        let AttributeBody::NonResident(body) = parsed.body else {
            panic!("nonresident")
        };
        assert_eq!(body.compression_block_bytes, Some(8192));
        assert_eq!(body.sizes.expect("sizes").compressed, Some(4096));

        let sparse = nonresident(SPARSE);
        assert!(parse_attribute(&sparse, limits()).is_ok());
    }

    #[test]
    fn continuation_extent_does_not_trust_size_fields() {
        let mut bytes = nonresident(0);
        set_i64(&mut bytes, 16, 2);
        set_i64(&mut bytes, 24, 3);
        set_i64(&mut bytes, 40, -1);
        let parsed = parse_attribute(&bytes, limits()).expect("valid continuation extent");
        let AttributeBody::NonResident(body) = parsed.body else {
            panic!("nonresident")
        };
        assert_eq!(body.sizes, None);
    }

    #[test]
    fn accepts_documented_empty_vcn_range() {
        let mut bytes = nonresident(0);
        set_i64(&mut bytes, 24, -1);
        set_i64(&mut bytes, 40, 0);
        set_i64(&mut bytes, 48, 0);
        set_i64(&mut bytes, 56, 0);
        let parsed = parse_attribute(&bytes, limits()).expect("empty stream extent");
        let AttributeBody::NonResident(body) = parsed.body else {
            panic!("nonresident")
        };
        assert_eq!(body.highest_vcn, None);
        assert_eq!(body.expected_next_vcn, 0);
    }

    #[test]
    fn rejects_common_header_length_type_form_and_caps() {
        assert!(matches!(
            parse_attribute(&[0; 15], limits()),
            Err(NtfsAttributeError::Truncated { .. })
        ));
        let mut bad = resident();
        set_u32(&mut bad, 0, 0x11);
        assert!(matches!(
            parse_attribute(&bad, limits()),
            Err(NtfsAttributeError::InvalidType { .. })
        ));
        let mut bad = resident();
        set_u32(&mut bad, 4, 31);
        assert!(matches!(
            parse_attribute(&bad, limits()),
            Err(NtfsAttributeError::InvalidLength { .. })
        ));
        let mut bad = resident();
        bad[8] = 2;
        assert!(matches!(
            parse_attribute(&bad, limits()),
            Err(NtfsAttributeError::InvalidStorageForm { .. })
        ));
        let mut capped = limits();
        capped.max_attribute_bytes = 24;
        assert!(matches!(
            parse_attribute(&resident(), capped),
            Err(NtfsAttributeError::AttributeTooLarge { .. })
        ));
    }

    #[test]
    fn rejects_name_bounds_overlap_and_cap() {
        let mut bad = resident();
        bad[9] = 1;
        set_u16(&mut bad, 10, 23);
        assert!(matches!(
            parse_attribute(&bad, limits()),
            Err(NtfsAttributeError::InvalidNameOffset { .. })
        ));
        let mut bad = resident();
        bad[9] = 5;
        set_u16(&mut bad, 10, 24);
        assert!(matches!(
            parse_attribute(&bad, limits()),
            Err(NtfsAttributeError::RangeOutOfBounds { .. })
        ));
        let mut bad = resident();
        bad[9] = 2;
        set_u16(&mut bad, 10, 24);
        assert!(matches!(
            parse_attribute(&bad, limits()),
            Err(NtfsAttributeError::OverlappingRanges { .. })
        ));
        let mut capped = limits();
        capped.max_name_code_units = 1;
        assert!(matches!(
            parse_attribute(&bad, capped),
            Err(NtfsAttributeError::NameLimitExceeded { .. })
        ));
    }

    #[test]
    fn rejects_resident_body_corruption() {
        let mut bad = resident();
        set_u16(&mut bad, 12, SPARSE);
        assert!(matches!(
            parse_attribute(&bad, limits()),
            Err(NtfsAttributeError::InvalidFlags { .. })
        ));
        let mut bad = resident();
        bad[22] = 2;
        assert!(matches!(
            parse_attribute(&bad, limits()),
            Err(NtfsAttributeError::InvalidResidentFlags { .. })
        ));
        let mut bad = resident();
        bad[23] = 1;
        assert!(matches!(
            parse_attribute(&bad, limits()),
            Err(NtfsAttributeError::ResidentReservedNotZero { .. })
        ));
        let mut bad = resident();
        set_u32(&mut bad, 16, u32::MAX);
        assert!(matches!(
            parse_attribute(&bad, limits()),
            Err(NtfsAttributeError::RangeOutOfBounds { .. })
        ));
    }

    #[test]
    fn rejects_nonresident_vcn_mapping_and_compression_corruption() {
        let mut bad = nonresident(0);
        bad[35] = 1;
        assert_eq!(
            parse_attribute(&bad, limits()),
            Err(NtfsAttributeError::NonResidentReservedNotZero)
        );
        let mut bad = nonresident(0);
        set_i64(&mut bad, 16, 3);
        set_i64(&mut bad, 24, 2);
        assert!(matches!(
            parse_attribute(&bad, limits()),
            Err(NtfsAttributeError::InvalidVcnRange { .. })
        ));
        let mut bad = nonresident(0);
        set_u16(&mut bad, 32, 65);
        assert!(matches!(
            parse_attribute(&bad, limits()),
            Err(NtfsAttributeError::InvalidMappingPairsOffset { .. })
        ));
        let mut bad = nonresident(0);
        bad[34] = 4;
        assert!(matches!(
            parse_attribute(&bad, limits()),
            Err(NtfsAttributeError::InvalidCompressionUnit { .. })
        ));
        let mut bad = nonresident(COMPRESSED);
        bad[34] = 0;
        assert!(matches!(
            parse_attribute(&bad, limits()),
            Err(NtfsAttributeError::InvalidCompressionUnit { .. })
        ));
    }

    #[test]
    fn rejects_nonresident_size_contradictions() {
        let mut bad = nonresident(0);
        set_i64(&mut bad, 40, -1);
        assert!(matches!(
            parse_attribute(&bad, limits()),
            Err(NtfsAttributeError::SizeFieldNegative { .. })
        ));
        let mut bad = nonresident(0);
        set_i64(&mut bad, 40, 4097);
        assert!(matches!(
            parse_attribute(&bad, limits()),
            Err(NtfsAttributeError::SizeNotClusterAligned { .. })
        ));
        let mut bad = nonresident(0);
        set_i64(&mut bad, 56, 7001);
        assert!(matches!(
            parse_attribute(&bad, limits()),
            Err(NtfsAttributeError::InitializedExceedsData { .. })
        ));
        let mut bad = nonresident(0);
        set_i64(&mut bad, 48, 9000);
        assert!(matches!(
            parse_attribute(&bad, limits()),
            Err(NtfsAttributeError::DataExceedsAllocation { .. })
        ));
        let mut bad = nonresident(SPARSE);
        set_i64(&mut bad, 64, 12_288);
        assert!(matches!(
            parse_attribute(&bad, limits()),
            Err(NtfsAttributeError::CompressedExceedsAllocation { .. })
        ));
    }

    #[test]
    fn parses_bounded_sorted_list_and_rejects_list_corruption() {
        let first = resident();
        let mut second = resident();
        set_u32(&mut second, 0, 0x20);
        set_u16(&mut second, 14, 1);
        let mut record = vec![0_u8; 16];
        record.extend_from_slice(&first);
        record.extend_from_slice(&second);
        record.extend_from_slice(&ATTRIBUTE_END.to_le_bytes());
        record.extend_from_slice(&[0; 4]);
        let parsed = parse_attribute_list(&record, 16, record.len(), limits()).expect("valid list");
        assert_eq!(parsed.attributes.len(), 2);
        assert_eq!(parsed.end_marker_offset, 80);

        let mut capped = limits();
        capped.max_attributes = 1;
        assert!(matches!(
            parse_attribute_list(&record, 16, record.len(), capped),
            Err(NtfsAttributeError::AttributeLimitExceeded { .. })
        ));

        let mut duplicate = record.clone();
        set_u16(&mut duplicate, 16 + 32 + 14, 0);
        assert!(matches!(
            parse_attribute_list(&duplicate, 16, duplicate.len(), limits()),
            Err(NtfsAttributeError::DuplicateAttributeId { .. })
        ));

        let mut unordered = record.clone();
        set_u32(&mut unordered, 16 + 32, 0x10);
        set_u32(&mut unordered, 16, 0x20);
        assert!(matches!(
            parse_attribute_list(&unordered, 16, unordered.len(), limits()),
            Err(NtfsAttributeError::AttributeTypesOutOfOrder { .. })
        ));
    }
}
