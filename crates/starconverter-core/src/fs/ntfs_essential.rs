//! Pure codecs for the NTFS `$AttrDef` payload and empty `$BadClus:$Bad` stream.
//!
//! Microsoft normatively identifies `$AttrDef` as the attribute-definition system file,
//! `$BadClus` as the bad-cluster list, and publishes the NTFS attribute type names. The 160-byte
//! `$AttrDef` entry layout, the exact NTFS 3.x table below, and the empty `$Bad` runlist are
//! formatter precedent from NTFS-3G commit
//! `d327833ec1d5eb1358b6f2c37139f10a3460944d` (`layout.h`, `attrdef.c`, `runlist.c`,
//! and `mkntfs.c`), not claims that Microsoft's public Open Specifications require those exact
//! bytes. In particular, NTFS-3G encodes both mapping-pair run lengths and LCN deltas as the
//! shortest unambiguous *signed* little-endian integers.
//!
//! This module has no I/O or path/device API. Every parser borrows caller-owned bytes and every
//! allocation is preceded by an explicit size limit and a fallible reservation.

use std::char::decode_utf16;
use std::fmt;

/// Bytes in one NTFS `$AttrDef` entry.
pub const ATTRDEF_ENTRY_BYTES: usize = 160;
/// UTF-16 code-unit slots in an `$AttrDef` entry, including its terminator.
pub const ATTRDEF_NAME_UNITS: usize = 64;
/// Definitions in the NTFS-3G NTFS 3.x table, excluding the zero terminator.
pub const NTFS3X_ATTRDEF_DEFINITION_COUNT: usize = 15;
/// Exact byte length of the NTFS-3G NTFS 3.x table, including its zero terminator.
pub const NTFS3X_ATTRDEF_BYTES: usize = (NTFS3X_ATTRDEF_DEFINITION_COUNT + 1) * ATTRDEF_ENTRY_BYTES;
/// Microsoft-supported upper bound for clusters in an NTFS volume.
pub const NTFS_MAX_VOLUME_CLUSTERS: u64 = u32::MAX as u64;

const ATTRDEF_KNOWN_FLAGS: u32 = 0x0000_00fe;

/// Caller-controlled `$AttrDef` input and output bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttrDefLimits {
    pub max_bytes: usize,
    pub max_entries: usize,
}

impl Default for AttrDefLimits {
    fn default() -> Self {
        Self {
            max_bytes: 4 * 1024,
            max_entries: 32,
        }
    }
}

/// One decoded `$AttrDef` definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttrDefEntry {
    name: [u16; ATTRDEF_NAME_UNITS],
    name_len: u8,
    pub attribute_type: u32,
    pub display_rule: u32,
    pub collation_rule: u32,
    pub flags: u32,
    pub minimum_size: i64,
    pub maximum_size: i64,
}

impl AttrDefEntry {
    /// The name without the terminating zero or fixed-width zero padding.
    #[must_use]
    pub fn name(&self) -> &[u16] {
        &self.name[..usize::from(self.name_len)]
    }
}

/// Validated, borrowed `$AttrDef` data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttrDefTable<'a> {
    bytes: &'a [u8],
    definition_count: usize,
}

impl<'a> AttrDefTable<'a> {
    #[must_use]
    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    #[must_use]
    pub const fn definition_count(&self) -> usize {
        self.definition_count
    }

    /// Iterates decoded definitions without allocating.
    #[must_use]
    pub fn entries(&self) -> AttrDefEntries<'a> {
        AttrDefEntries {
            chunks: self.bytes[..self.definition_count * ATTRDEF_ENTRY_BYTES]
                .chunks_exact(ATTRDEF_ENTRY_BYTES),
        }
    }
}

/// Allocation-free iterator over validated `$AttrDef` definitions.
#[derive(Debug, Clone)]
pub struct AttrDefEntries<'a> {
    chunks: std::slice::ChunksExact<'a, u8>,
}

impl Iterator for AttrDefEntries<'_> {
    type Item = AttrDefEntry;

    fn next(&mut self) -> Option<Self::Item> {
        self.chunks.next().map(decode_attrdef_entry)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.chunks.size_hint()
    }
}

impl ExactSizeIterator for AttrDefEntries<'_> {}
impl std::iter::FusedIterator for AttrDefEntries<'_> {}

/// Field that differs from the pinned NTFS-3G NTFS 3.x table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttrDefField {
    ByteLength,
    EntryCount,
    Name,
    AttributeType,
    DisplayRule,
    CollationRule,
    Flags,
    MinimumSize,
    MaximumSize,
}

impl fmt::Display for AttrDefField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ByteLength => "byte length",
            Self::EntryCount => "entry count",
            Self::Name => "name",
            Self::AttributeType => "attribute type",
            Self::DisplayRule => "display rule",
            Self::CollationRule => "collation rule",
            Self::Flags => "flags",
            Self::MinimumSize => "minimum size",
            Self::MaximumSize => "maximum size",
        })
    }
}

/// Reason an `$AttrDef` payload could not be generated or validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttrDefError {
    InvalidLimit {
        field: &'static str,
    },
    ByteLimitExceeded {
        actual: usize,
        maximum: usize,
    },
    EntryLimitExceeded {
        actual: usize,
        maximum: usize,
    },
    LengthNotMultiple {
        actual: usize,
    },
    MissingTerminator,
    NonZeroAfterTerminator {
        index: usize,
    },
    EmptyName {
        index: usize,
    },
    NameNotTerminated {
        index: usize,
    },
    NonZeroNamePadding {
        index: usize,
        unit: usize,
    },
    InvalidUtf16Name {
        index: usize,
        unit: usize,
    },
    ZeroAttributeType {
        index: usize,
    },
    UnalignedAttributeType {
        index: usize,
        attribute_type: u32,
    },
    AttributeTypesNotIncreasing {
        index: usize,
        previous: u32,
        actual: u32,
    },
    UnknownFlags {
        index: usize,
        flags: u32,
    },
    InvalidSizeRange {
        index: usize,
        minimum: i64,
        maximum: i64,
    },
    NonCanonical {
        index: usize,
        field: AttrDefField,
    },
    AllocationFailed,
}

impl fmt::Display for AttrDefError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit { field } => write!(formatter, "$AttrDef limit {field} is zero"),
            Self::ByteLimitExceeded { actual, maximum } => write!(
                formatter,
                "$AttrDef payload is {actual} bytes, exceeding limit {maximum}"
            ),
            Self::EntryLimitExceeded { actual, maximum } => write!(
                formatter,
                "$AttrDef has {actual} entries, exceeding limit {maximum}"
            ),
            Self::LengthNotMultiple { actual } => write!(
                formatter,
                "$AttrDef length {actual} is not a multiple of {ATTRDEF_ENTRY_BYTES}"
            ),
            Self::MissingTerminator => formatter.write_str("$AttrDef has no zero terminator"),
            Self::NonZeroAfterTerminator { index } => {
                write!(
                    formatter,
                    "$AttrDef entry {index} is nonzero after the terminator"
                )
            }
            Self::EmptyName { index } => {
                write!(formatter, "$AttrDef entry {index} has an empty name")
            }
            Self::NameNotTerminated { index } => write!(
                formatter,
                "$AttrDef entry {index} name has no zero terminator"
            ),
            Self::NonZeroNamePadding { index, unit } => write!(
                formatter,
                "$AttrDef entry {index} has nonzero name padding at UTF-16 unit {unit}"
            ),
            Self::InvalidUtf16Name { index, unit } => write!(
                formatter,
                "$AttrDef entry {index} has invalid UTF-16 at unit {unit}"
            ),
            Self::ZeroAttributeType { index } => {
                write!(formatter, "$AttrDef entry {index} has attribute type zero")
            }
            Self::UnalignedAttributeType {
                index,
                attribute_type,
            } => write!(
                formatter,
                "$AttrDef entry {index} type {attribute_type:#x} is not a 0x10 multiple"
            ),
            Self::AttributeTypesNotIncreasing {
                index,
                previous,
                actual,
            } => write!(
                formatter,
                "$AttrDef entry {index} type {actual:#x} does not follow {previous:#x}"
            ),
            Self::UnknownFlags { index, flags } => write!(
                formatter,
                "$AttrDef entry {index} has unknown flags {flags:#x}"
            ),
            Self::InvalidSizeRange {
                index,
                minimum,
                maximum,
            } => write!(
                formatter,
                "$AttrDef entry {index} has invalid size range {minimum}..={maximum}"
            ),
            Self::NonCanonical { index, field } => write!(
                formatter,
                "$AttrDef entry {index} differs from NTFS-3G NTFS 3.x precedent in {field}"
            ),
            Self::AllocationFailed => {
                formatter.write_str("could not allocate bounded $AttrDef output")
            }
        }
    }
}

impl std::error::Error for AttrDefError {}

/// Parses a structurally strict `$AttrDef` table.
///
/// This validates the 160-byte layout, an all-zero terminator followed only by zero-filled slots,
/// sorted unique type codes, well-formed terminated UTF-16 names, known precedent flags, and
/// coherent size ranges. Accepting zero-filled slots after the first terminator accommodates
/// larger fixed-size `$AttrDef` streams without treating their unused tail as definitions. It does
/// not by itself require the exact NTFS-3G definition set; call [`validate_ntfs3x_attrdef`] for
/// that compatibility policy.
///
/// # Errors
/// Returns [`AttrDefError`] for a malformed payload or caller limit violation.
pub fn parse_attrdef(
    bytes: &[u8],
    limits: AttrDefLimits,
) -> Result<AttrDefTable<'_>, AttrDefError> {
    validate_attrdef_limits(limits)?;
    if bytes.len() > limits.max_bytes {
        return Err(AttrDefError::ByteLimitExceeded {
            actual: bytes.len(),
            maximum: limits.max_bytes,
        });
    }
    if bytes.len() % ATTRDEF_ENTRY_BYTES != 0 {
        return Err(AttrDefError::LengthNotMultiple {
            actual: bytes.len(),
        });
    }
    let entry_count = bytes.len() / ATTRDEF_ENTRY_BYTES;
    if entry_count > limits.max_entries {
        return Err(AttrDefError::EntryLimitExceeded {
            actual: entry_count,
            maximum: limits.max_entries,
        });
    }
    if entry_count == 0 {
        return Err(AttrDefError::MissingTerminator);
    }

    let mut previous_type = None;
    let mut definition_count = None;
    for (index, entry) in bytes.chunks_exact(ATTRDEF_ENTRY_BYTES).enumerate() {
        if entry.iter().all(|byte| *byte == 0) {
            definition_count.get_or_insert(index);
            continue;
        }
        if definition_count.is_some() {
            return Err(AttrDefError::NonZeroAfterTerminator { index });
        }
        validate_attrdef_entry(index, entry, previous_type)?;
        previous_type = Some(read_u32(entry, 0x80));
    }
    definition_count.map_or(Err(AttrDefError::MissingTerminator), |definition_count| {
        Ok(AttrDefTable {
            bytes,
            definition_count,
        })
    })
}

/// Generates the exact NTFS-3G NTFS 3.x `$AttrDef` payload under caller bounds.
///
/// # Errors
/// Returns [`AttrDefError`] if the canonical output exceeds the supplied bounds or allocation
/// fails.
pub fn generate_ntfs3x_attrdef(limits: AttrDefLimits) -> Result<Vec<u8>, AttrDefError> {
    validate_attrdef_limits(limits)?;
    ensure_attrdef_size_allowed(NTFS3X_ATTRDEF_BYTES, limits)?;

    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(NTFS3X_ATTRDEF_BYTES)
        .map_err(|_| AttrDefError::AllocationFailed)?;
    bytes.resize(NTFS3X_ATTRDEF_BYTES, 0);
    for (index, definition) in CANONICAL_ATTRDEF.iter().enumerate() {
        let start = index * ATTRDEF_ENTRY_BYTES;
        encode_canonical_attrdef_entry(&mut bytes[start..start + ATTRDEF_ENTRY_BYTES], definition);
    }
    Ok(bytes)
}

/// Requires the exact pinned NTFS-3G NTFS 3.x definition set and values.
///
/// # Errors
/// Returns [`AttrDefError`] for structural errors, limit violations, missing/additional entries,
/// or any field that differs from the pinned formatter table.
pub fn validate_ntfs3x_attrdef(
    bytes: &[u8],
    limits: AttrDefLimits,
) -> Result<AttrDefTable<'_>, AttrDefError> {
    let table = parse_attrdef(bytes, limits)?;
    if bytes.len() != NTFS3X_ATTRDEF_BYTES {
        return Err(AttrDefError::NonCanonical {
            index: table.definition_count(),
            field: AttrDefField::ByteLength,
        });
    }
    if table.definition_count() != NTFS3X_ATTRDEF_DEFINITION_COUNT {
        return Err(AttrDefError::NonCanonical {
            index: table.definition_count(),
            field: AttrDefField::EntryCount,
        });
    }
    for (index, (entry, expected)) in table.entries().zip(CANONICAL_ATTRDEF).enumerate() {
        compare_canonical_entry(index, &entry, &expected)?;
    }
    Ok(table)
}

const fn validate_attrdef_limits(limits: AttrDefLimits) -> Result<(), AttrDefError> {
    if limits.max_bytes == 0 {
        return Err(AttrDefError::InvalidLimit { field: "max_bytes" });
    }
    if limits.max_entries == 0 {
        return Err(AttrDefError::InvalidLimit {
            field: "max_entries",
        });
    }
    Ok(())
}

const fn ensure_attrdef_size_allowed(
    bytes: usize,
    limits: AttrDefLimits,
) -> Result<(), AttrDefError> {
    if bytes > limits.max_bytes {
        return Err(AttrDefError::ByteLimitExceeded {
            actual: bytes,
            maximum: limits.max_bytes,
        });
    }
    let entries = bytes / ATTRDEF_ENTRY_BYTES;
    if entries > limits.max_entries {
        return Err(AttrDefError::EntryLimitExceeded {
            actual: entries,
            maximum: limits.max_entries,
        });
    }
    Ok(())
}

fn validate_attrdef_entry(
    index: usize,
    entry: &[u8],
    previous_type: Option<u32>,
) -> Result<(), AttrDefError> {
    let mut name = [0_u16; ATTRDEF_NAME_UNITS];
    for (unit, slot) in name.iter_mut().enumerate() {
        *slot = read_u16(entry, unit * 2);
    }
    let Some(name_len) = name.iter().position(|unit| *unit == 0) else {
        return Err(AttrDefError::NameNotTerminated { index });
    };
    if name_len == 0 {
        return Err(AttrDefError::EmptyName { index });
    }
    if let Some((relative, _)) = name[name_len + 1..]
        .iter()
        .enumerate()
        .find(|(_, unit)| **unit != 0)
    {
        return Err(AttrDefError::NonZeroNamePadding {
            index,
            unit: name_len + 1 + relative,
        });
    }
    if let Some((unit, _)) = decode_utf16(name[..name_len].iter().copied())
        .enumerate()
        .find(|(_, character)| character.is_err())
    {
        return Err(AttrDefError::InvalidUtf16Name { index, unit });
    }

    let attribute_type = read_u32(entry, 0x80);
    if attribute_type == 0 {
        return Err(AttrDefError::ZeroAttributeType { index });
    }
    if attribute_type & 0x0f != 0 {
        return Err(AttrDefError::UnalignedAttributeType {
            index,
            attribute_type,
        });
    }
    if let Some(previous) = previous_type.filter(|previous| attribute_type <= *previous) {
        return Err(AttrDefError::AttributeTypesNotIncreasing {
            index,
            previous,
            actual: attribute_type,
        });
    }
    let flags = read_u32(entry, 0x8c);
    if flags & !ATTRDEF_KNOWN_FLAGS != 0 {
        return Err(AttrDefError::UnknownFlags { index, flags });
    }
    let minimum = read_i64(entry, 0x90);
    let maximum = read_i64(entry, 0x98);
    if minimum < 0 || maximum < -1 || (maximum != -1 && maximum < minimum) {
        return Err(AttrDefError::InvalidSizeRange {
            index,
            minimum,
            maximum,
        });
    }
    Ok(())
}

fn decode_attrdef_entry(entry: &[u8]) -> AttrDefEntry {
    let mut name = [0_u16; ATTRDEF_NAME_UNITS];
    for (unit, slot) in name.iter_mut().enumerate() {
        *slot = read_u16(entry, unit * 2);
    }
    let name_len = name
        .iter()
        .position(|unit| *unit == 0)
        .expect("validated attribute definition has a terminated name");
    AttrDefEntry {
        name,
        name_len: u8::try_from(name_len).expect("$AttrDef name has at most 63 units"),
        attribute_type: read_u32(entry, 0x80),
        display_rule: read_u32(entry, 0x84),
        collation_rule: read_u32(entry, 0x88),
        flags: read_u32(entry, 0x8c),
        minimum_size: read_i64(entry, 0x90),
        maximum_size: read_i64(entry, 0x98),
    }
}

#[derive(Debug, Clone, Copy)]
struct CanonicalAttrDef {
    name: &'static str,
    attribute_type: u32,
    display_rule: u32,
    collation_rule: u32,
    flags: u32,
    minimum_size: i64,
    maximum_size: i64,
}

const CANONICAL_ATTRDEF: [CanonicalAttrDef; NTFS3X_ATTRDEF_DEFINITION_COUNT] = [
    CanonicalAttrDef {
        name: "$STANDARD_INFORMATION",
        attribute_type: 0x10,
        display_rule: 0,
        collation_rule: 0,
        flags: 0x40,
        minimum_size: 48,
        maximum_size: 72,
    },
    CanonicalAttrDef {
        name: "$ATTRIBUTE_LIST",
        attribute_type: 0x20,
        display_rule: 0,
        collation_rule: 0,
        flags: 0x80,
        minimum_size: 0,
        maximum_size: -1,
    },
    CanonicalAttrDef {
        name: "$FILE_NAME",
        attribute_type: 0x30,
        display_rule: 0,
        collation_rule: 0,
        flags: 0x42,
        minimum_size: 68,
        maximum_size: 578,
    },
    CanonicalAttrDef {
        name: "$OBJECT_ID",
        attribute_type: 0x40,
        display_rule: 0,
        collation_rule: 0,
        flags: 0x40,
        minimum_size: 0,
        maximum_size: 256,
    },
    CanonicalAttrDef {
        name: "$SECURITY_DESCRIPTOR",
        attribute_type: 0x50,
        display_rule: 0,
        collation_rule: 0,
        flags: 0x80,
        minimum_size: 0,
        maximum_size: -1,
    },
    CanonicalAttrDef {
        name: "$VOLUME_NAME",
        attribute_type: 0x60,
        display_rule: 0,
        collation_rule: 0,
        flags: 0x40,
        minimum_size: 2,
        maximum_size: 256,
    },
    CanonicalAttrDef {
        name: "$VOLUME_INFORMATION",
        attribute_type: 0x70,
        display_rule: 0,
        collation_rule: 0,
        flags: 0x40,
        minimum_size: 12,
        maximum_size: 12,
    },
    CanonicalAttrDef {
        name: "$DATA",
        attribute_type: 0x80,
        display_rule: 0,
        collation_rule: 0,
        flags: 0,
        minimum_size: 0,
        maximum_size: -1,
    },
    CanonicalAttrDef {
        name: "$INDEX_ROOT",
        attribute_type: 0x90,
        display_rule: 0,
        collation_rule: 0,
        flags: 0x40,
        minimum_size: 0,
        maximum_size: -1,
    },
    CanonicalAttrDef {
        name: "$INDEX_ALLOCATION",
        attribute_type: 0xa0,
        display_rule: 0,
        collation_rule: 0,
        flags: 0x80,
        minimum_size: 0,
        maximum_size: -1,
    },
    CanonicalAttrDef {
        name: "$BITMAP",
        attribute_type: 0xb0,
        display_rule: 0,
        collation_rule: 0,
        flags: 0x80,
        minimum_size: 0,
        maximum_size: -1,
    },
    CanonicalAttrDef {
        name: "$REPARSE_POINT",
        attribute_type: 0xc0,
        display_rule: 0,
        collation_rule: 0,
        flags: 0x80,
        minimum_size: 0,
        maximum_size: 16_384,
    },
    CanonicalAttrDef {
        name: "$EA_INFORMATION",
        attribute_type: 0xd0,
        display_rule: 0,
        collation_rule: 0,
        flags: 0x40,
        minimum_size: 8,
        maximum_size: 8,
    },
    CanonicalAttrDef {
        name: "$EA",
        attribute_type: 0xe0,
        display_rule: 0,
        collation_rule: 0,
        flags: 0,
        minimum_size: 0,
        maximum_size: 65_536,
    },
    CanonicalAttrDef {
        name: "$LOGGED_UTILITY_STREAM",
        attribute_type: 0x100,
        display_rule: 0,
        collation_rule: 0,
        flags: 0x80,
        minimum_size: 0,
        maximum_size: 65_536,
    },
];

fn encode_canonical_attrdef_entry(entry: &mut [u8], definition: &CanonicalAttrDef) {
    for (unit, character) in definition.name.encode_utf16().enumerate() {
        entry[unit * 2..unit * 2 + 2].copy_from_slice(&character.to_le_bytes());
    }
    entry[0x80..0x84].copy_from_slice(&definition.attribute_type.to_le_bytes());
    entry[0x84..0x88].copy_from_slice(&definition.display_rule.to_le_bytes());
    entry[0x88..0x8c].copy_from_slice(&definition.collation_rule.to_le_bytes());
    entry[0x8c..0x90].copy_from_slice(&definition.flags.to_le_bytes());
    entry[0x90..0x98].copy_from_slice(&definition.minimum_size.to_le_bytes());
    entry[0x98..0xa0].copy_from_slice(&definition.maximum_size.to_le_bytes());
}

fn compare_canonical_entry(
    index: usize,
    actual: &AttrDefEntry,
    expected: &CanonicalAttrDef,
) -> Result<(), AttrDefError> {
    let checks = [
        (
            actual
                .name()
                .iter()
                .copied()
                .eq(expected.name.encode_utf16()),
            AttrDefField::Name,
        ),
        (
            actual.attribute_type == expected.attribute_type,
            AttrDefField::AttributeType,
        ),
        (
            actual.display_rule == expected.display_rule,
            AttrDefField::DisplayRule,
        ),
        (
            actual.collation_rule == expected.collation_rule,
            AttrDefField::CollationRule,
        ),
        (actual.flags == expected.flags, AttrDefField::Flags),
        (
            actual.minimum_size == expected.minimum_size,
            AttrDefField::MinimumSize,
        ),
        (
            actual.maximum_size == expected.maximum_size,
            AttrDefField::MaximumSize,
        ),
    ];
    if let Some((_, field)) = checks.into_iter().find(|(matches, _)| !matches) {
        return Err(AttrDefError::NonCanonical { index, field });
    }
    Ok(())
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

const fn read_i64(bytes: &[u8], offset: usize) -> i64 {
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

/// UTF-16 name of the mandatory named `$Bad` data stream.
pub const BADCLUS_STREAM_NAME: [u16; 4] = [0x24, 0x42, 0x61, 0x64];
pub const DATA_ATTRIBUTE_TYPE: u32 = 0x80;

/// Caller-controlled geometry and mapping-pairs bounds for `$BadClus:$Bad`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadClusLimits {
    pub max_volume_clusters: u64,
    pub max_mapping_pairs_bytes: usize,
}

impl Default for BadClusLimits {
    fn default() -> Self {
        Self {
            max_volume_clusters: u64::from(u32::MAX),
            max_mapping_pairs_bytes: 32,
        }
    }
}

/// Serializer-ready metadata for the empty, named `$BadClus:$Bad` `$DATA` stream.
///
/// `mapping_pairs` owns no file data: it describes a single sparse range spanning the volume.
/// The containing MFT record must additionally contain an empty unnamed resident `$DATA`
/// attribute; that separate record-level invariant is intentionally outside this stream plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmptyBadClusPlan {
    pub attribute_type: u32,
    pub name: [u16; 4],
    pub attribute_flags: u16,
    /// Nonresident-header compression unit; zero means uncompressed.
    pub compression_unit: u8,
    pub lowest_vcn: u64,
    pub highest_vcn: u64,
    pub allocated_size: u64,
    pub data_size: u64,
    pub initialized_size: u64,
    pub mapping_pairs: Vec<u8>,
}

/// Borrowed fields of an existing empty `$BadClus:$Bad` stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmptyBadClusRef<'a> {
    pub attribute_type: u32,
    pub name: &'a [u16],
    pub attribute_flags: u16,
    pub compression_unit: u8,
    pub lowest_vcn: u64,
    pub highest_vcn: u64,
    pub allocated_size: u64,
    pub data_size: u64,
    pub initialized_size: u64,
    pub mapping_pairs: &'a [u8],
}

impl EmptyBadClusPlan {
    #[must_use]
    pub fn as_ref(&self) -> EmptyBadClusRef<'_> {
        EmptyBadClusRef {
            attribute_type: self.attribute_type,
            name: &self.name,
            attribute_flags: self.attribute_flags,
            compression_unit: self.compression_unit,
            lowest_vcn: self.lowest_vcn,
            highest_vcn: self.highest_vcn,
            allocated_size: self.allocated_size,
            data_size: self.data_size,
            initialized_size: self.initialized_size,
            mapping_pairs: &self.mapping_pairs,
        }
    }
}

/// Reason the empty `$BadClus:$Bad` representation could not be planned or validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BadClusError {
    InvalidLimit { field: &'static str },
    ZeroClusterCount,
    ClusterCountTooLarge { actual: u64, maximum: u64 },
    ClusterCountOutsideNtfsLimit { actual: u64, maximum: u64 },
    InvalidClusterBytes { cluster_bytes: u32 },
    LogicalSizeOverflow,
    LogicalSizeOutsideNtfsSignedRange { logical_size: u64 },
    MappingPairsLimitExceeded { actual: usize, maximum: usize },
    WrongAttributeType { actual: u32 },
    WrongName,
    WrongAttributeFlags { actual: u16 },
    WrongCompressionUnit { actual: u8 },
    WrongLowestVcn { actual: u64 },
    WrongHighestVcn { expected: u64, actual: u64 },
    WrongAllocatedSize { expected: u64, actual: u64 },
    WrongDataSize { expected: u64, actual: u64 },
    WrongInitializedSize { actual: u64 },
    MissingMappingPairsTerminator,
    InvalidMappingPairsHeader { actual: u8 },
    NonMinimalRunLengthWidth { expected: u8, actual: u8 },
    TruncatedMappingPairs { required: usize, actual: usize },
    WrongSparseRunLength { expected: u64, actual: u64 },
    NonZeroMappingPairsPadding { offset: usize, value: u8 },
    AllocationFailed,
}

impl fmt::Display for BadClusError {
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit { field } => write!(formatter, "$BadClus limit {field} is zero"),
            Self::ZeroClusterCount => formatter.write_str("$BadClus volume cluster count is zero"),
            Self::ClusterCountTooLarge { actual, maximum } => write!(
                formatter,
                "$BadClus volume has {actual} clusters, exceeding limit {maximum}"
            ),
            Self::ClusterCountOutsideNtfsLimit { actual, maximum } => write!(
                formatter,
                "$BadClus volume has {actual} clusters, exceeding the NTFS limit {maximum}"
            ),
            Self::InvalidClusterBytes { cluster_bytes } => write!(
                formatter,
                "$BadClus cluster size {cluster_bytes} is not a supported power of two from 512 through 2097152"
            ),
            Self::LogicalSizeOverflow => formatter.write_str("$BadClus logical size overflows u64"),
            Self::LogicalSizeOutsideNtfsSignedRange { logical_size } => write!(
                formatter,
                "$BadClus logical size {logical_size} does not fit signed NTFS size fields"
            ),
            Self::MappingPairsLimitExceeded { actual, maximum } => write!(
                formatter,
                "$BadClus mapping pairs need {actual} bytes, exceeding limit {maximum}"
            ),
            Self::WrongAttributeType { actual } => write!(
                formatter,
                "$BadClus:$Bad has attribute type {actual:#x}, expected $DATA"
            ),
            Self::WrongName => formatter.write_str("$BadClus named stream is not `$Bad`"),
            Self::WrongAttributeFlags { actual } => write!(
                formatter,
                "$BadClus:$Bad has flags {actual:#x}; formatter precedent uses zero"
            ),
            Self::WrongCompressionUnit { actual } => write!(
                formatter,
                "$BadClus:$Bad has compression unit {actual}, expected zero"
            ),
            Self::WrongLowestVcn { actual } => write!(
                formatter,
                "$BadClus:$Bad starts at VCN {actual}, expected zero"
            ),
            Self::WrongHighestVcn { expected, actual } => write!(
                formatter,
                "$BadClus:$Bad highest VCN is {actual}, expected {expected}"
            ),
            Self::WrongAllocatedSize { expected, actual } => write!(
                formatter,
                "$BadClus:$Bad allocated size is {actual}, expected formatter value {expected}"
            ),
            Self::WrongDataSize { expected, actual } => write!(
                formatter,
                "$BadClus:$Bad data size is {actual}, expected {expected}"
            ),
            Self::WrongInitializedSize { actual } => write!(
                formatter,
                "$BadClus:$Bad initialized size is {actual}, expected zero"
            ),
            Self::MissingMappingPairsTerminator => {
                formatter.write_str("$BadClus:$Bad mapping pairs have no zero terminator")
            }
            Self::InvalidMappingPairsHeader { actual } => write!(
                formatter,
                "$BadClus:$Bad mapping-pairs header {actual:#x} is not a sparse run"
            ),
            Self::NonMinimalRunLengthWidth { expected, actual } => write!(
                formatter,
                "$BadClus:$Bad run length uses {actual} bytes, expected minimal width {expected}"
            ),
            Self::TruncatedMappingPairs { required, actual } => write!(
                formatter,
                "$BadClus:$Bad mapping pairs have {actual} bytes, need at least {required}"
            ),
            Self::WrongSparseRunLength { expected, actual } => write!(
                formatter,
                "$BadClus:$Bad sparse run spans {actual} clusters, expected {expected}"
            ),
            Self::NonZeroMappingPairsPadding { offset, value } => write!(
                formatter,
                "$BadClus:$Bad mapping-pairs byte {offset} after the terminator is {value:#x}"
            ),
            Self::AllocationFailed => {
                formatter.write_str("could not allocate bounded $BadClus mapping pairs")
            }
        }
    }
}

impl std::error::Error for BadClusError {}

/// Plans the empty `$BadClus:$Bad` representation emitted by the pinned NTFS-3G formatter.
///
/// This intentionally has no parameter for bad clusters. Conversion must not silently discard
/// source bad-cluster evidence; a future nonempty implementation needs an independently validated
/// physical runlist and matching `$Bitmap` reservations.
///
/// # Errors
/// Returns [`BadClusError`] for unsupported geometry, limit violations, overflow, or allocation
/// failure.
pub fn plan_empty_badclus(
    volume_clusters: u64,
    cluster_bytes: u32,
    limits: BadClusLimits,
) -> Result<EmptyBadClusPlan, BadClusError> {
    let logical_size = validate_badclus_geometry(volume_clusters, cluster_bytes, limits)?;
    let width = positive_signed_width(volume_clusters);
    let mapping_len = usize::from(width) + 2;
    if mapping_len > limits.max_mapping_pairs_bytes {
        return Err(BadClusError::MappingPairsLimitExceeded {
            actual: mapping_len,
            maximum: limits.max_mapping_pairs_bytes,
        });
    }
    let mut mapping_pairs = Vec::new();
    mapping_pairs
        .try_reserve_exact(mapping_len)
        .map_err(|_| BadClusError::AllocationFailed)?;
    mapping_pairs.push(width);
    append_unsigned(&mut mapping_pairs, volume_clusters, width);
    mapping_pairs.push(0);

    Ok(EmptyBadClusPlan {
        attribute_type: DATA_ATTRIBUTE_TYPE,
        name: BADCLUS_STREAM_NAME,
        attribute_flags: 0,
        compression_unit: 0,
        lowest_vcn: 0,
        highest_vcn: volume_clusters - 1,
        // This is deliberately the pinned mkntfs field value, even though the run is sparse.
        allocated_size: logical_size,
        data_size: logical_size,
        initialized_size: 0,
        mapping_pairs,
    })
}

/// Validates an empty `$BadClus:$Bad` stream against pinned formatter precedent.
///
/// Zero bytes after the mapping-pairs terminator are accepted as containing-attribute alignment
/// padding. No second run or hidden nonzero data is accepted.
///
/// # Errors
/// Returns [`BadClusError`] for field disagreement, malformed mapping pairs, unsupported geometry,
/// or a caller limit violation.
pub fn validate_empty_badclus(
    stream: EmptyBadClusRef<'_>,
    volume_clusters: u64,
    cluster_bytes: u32,
    limits: BadClusLimits,
) -> Result<(), BadClusError> {
    let logical_size = validate_badclus_geometry(volume_clusters, cluster_bytes, limits)?;
    if stream.mapping_pairs.len() > limits.max_mapping_pairs_bytes {
        return Err(BadClusError::MappingPairsLimitExceeded {
            actual: stream.mapping_pairs.len(),
            maximum: limits.max_mapping_pairs_bytes,
        });
    }
    if stream.attribute_type != DATA_ATTRIBUTE_TYPE {
        return Err(BadClusError::WrongAttributeType {
            actual: stream.attribute_type,
        });
    }
    if stream.name != BADCLUS_STREAM_NAME {
        return Err(BadClusError::WrongName);
    }
    if stream.attribute_flags != 0 {
        return Err(BadClusError::WrongAttributeFlags {
            actual: stream.attribute_flags,
        });
    }
    if stream.compression_unit != 0 {
        return Err(BadClusError::WrongCompressionUnit {
            actual: stream.compression_unit,
        });
    }
    if stream.lowest_vcn != 0 {
        return Err(BadClusError::WrongLowestVcn {
            actual: stream.lowest_vcn,
        });
    }
    let expected_highest = volume_clusters - 1;
    if stream.highest_vcn != expected_highest {
        return Err(BadClusError::WrongHighestVcn {
            expected: expected_highest,
            actual: stream.highest_vcn,
        });
    }
    if stream.allocated_size != logical_size {
        return Err(BadClusError::WrongAllocatedSize {
            expected: logical_size,
            actual: stream.allocated_size,
        });
    }
    if stream.data_size != logical_size {
        return Err(BadClusError::WrongDataSize {
            expected: logical_size,
            actual: stream.data_size,
        });
    }
    if stream.initialized_size != 0 {
        return Err(BadClusError::WrongInitializedSize {
            actual: stream.initialized_size,
        });
    }
    validate_empty_badclus_mapping_pairs(stream.mapping_pairs, volume_clusters)
}

fn validate_badclus_geometry(
    volume_clusters: u64,
    cluster_bytes: u32,
    limits: BadClusLimits,
) -> Result<u64, BadClusError> {
    if limits.max_volume_clusters == 0 {
        return Err(BadClusError::InvalidLimit {
            field: "max_volume_clusters",
        });
    }
    if limits.max_mapping_pairs_bytes == 0 {
        return Err(BadClusError::InvalidLimit {
            field: "max_mapping_pairs_bytes",
        });
    }
    if volume_clusters == 0 {
        return Err(BadClusError::ZeroClusterCount);
    }
    if volume_clusters > NTFS_MAX_VOLUME_CLUSTERS {
        return Err(BadClusError::ClusterCountOutsideNtfsLimit {
            actual: volume_clusters,
            maximum: NTFS_MAX_VOLUME_CLUSTERS,
        });
    }
    if volume_clusters > limits.max_volume_clusters {
        return Err(BadClusError::ClusterCountTooLarge {
            actual: volume_clusters,
            maximum: limits.max_volume_clusters,
        });
    }
    if !(512..=2 * 1024 * 1024).contains(&cluster_bytes) || !cluster_bytes.is_power_of_two() {
        return Err(BadClusError::InvalidClusterBytes { cluster_bytes });
    }
    let logical_size = volume_clusters
        .checked_mul(u64::from(cluster_bytes))
        .ok_or(BadClusError::LogicalSizeOverflow)?;
    if logical_size > i64::MAX as u64 {
        return Err(BadClusError::LogicalSizeOutsideNtfsSignedRange { logical_size });
    }
    Ok(logical_size)
}

fn validate_empty_badclus_mapping_pairs(
    bytes: &[u8],
    volume_clusters: u64,
) -> Result<(), BadClusError> {
    let Some(&header) = bytes.first() else {
        return Err(BadClusError::MissingMappingPairsTerminator);
    };
    let length_width = header & 0x0f;
    let lcn_width = header >> 4;
    if length_width == 0 || length_width > 8 || lcn_width != 0 {
        return Err(BadClusError::InvalidMappingPairsHeader { actual: header });
    }
    let expected_width = positive_signed_width(volume_clusters);
    if length_width != expected_width {
        return Err(BadClusError::NonMinimalRunLengthWidth {
            expected: expected_width,
            actual: length_width,
        });
    }
    let terminator = usize::from(length_width) + 1;
    let required = terminator + 1;
    if bytes.len() < required {
        return Err(BadClusError::TruncatedMappingPairs {
            required,
            actual: bytes.len(),
        });
    }
    let actual_length = decode_unsigned(&bytes[1..terminator]);
    if actual_length != volume_clusters {
        return Err(BadClusError::WrongSparseRunLength {
            expected: volume_clusters,
            actual: actual_length,
        });
    }
    if bytes[terminator] != 0 {
        return Err(BadClusError::MissingMappingPairsTerminator);
    }
    if let Some((relative, value)) = bytes[required..]
        .iter()
        .copied()
        .enumerate()
        .find(|(_, value)| *value != 0)
    {
        return Err(BadClusError::NonZeroMappingPairsPadding {
            offset: required + relative,
            value,
        });
    }
    Ok(())
}

fn positive_signed_width(value: u64) -> u8 {
    let significant_bits_with_sign = u64::BITS - value.leading_zeros() + 1;
    u8::try_from(significant_bits_with_sign.div_ceil(8))
        .expect("a positive signed u64 value uses at most nine bytes")
}

fn append_unsigned(bytes: &mut Vec<u8>, value: u64, width: u8) {
    bytes.extend_from_slice(&value.to_le_bytes()[..usize::from(width)]);
}

fn decode_unsigned(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .enumerate()
        .fold(0_u64, |value, (index, byte)| {
            value | (u64::from(*byte) << (index * 8))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attrdef_limits() -> AttrDefLimits {
        AttrDefLimits::default()
    }

    fn badclus_limits() -> BadClusLimits {
        BadClusLimits::default()
    }

    fn canonical_attrdef() -> Vec<u8> {
        generate_ntfs3x_attrdef(attrdef_limits()).expect("canonical table")
    }

    fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_i64(bytes: &mut [u8], offset: usize, value: i64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn canonical_attrdef_has_pinned_length_names_and_values() {
        let bytes = canonical_attrdef();
        assert_eq!(bytes.len(), 2560);
        let table = validate_ntfs3x_attrdef(&bytes, attrdef_limits()).expect("canonical table");
        assert_eq!(table.definition_count(), 15);
        assert_eq!(table.entries().len(), 15);
        let entries: Vec<_> = table.entries().collect();
        assert_eq!(
            entries[0].name(),
            "$STANDARD_INFORMATION".encode_utf16().collect::<Vec<_>>()
        );
        assert_eq!(entries[0].attribute_type, 0x10);
        assert_eq!(entries[0].minimum_size, 48);
        assert_eq!(entries[0].maximum_size, 72);
        assert_eq!(
            entries[14].name(),
            "$LOGGED_UTILITY_STREAM".encode_utf16().collect::<Vec<_>>()
        );
        assert_eq!(entries[14].attribute_type, 0x100);
        assert!(
            bytes[15 * ATTRDEF_ENTRY_BYTES..]
                .iter()
                .all(|byte| *byte == 0)
        );
    }

    #[test]
    fn attrdef_generation_is_deterministic() {
        assert_eq!(canonical_attrdef(), canonical_attrdef());
    }

    #[test]
    fn attrdef_rejects_zero_limits_and_exact_limit_minus_one() {
        for (limits, field) in [
            (
                AttrDefLimits {
                    max_bytes: 0,
                    max_entries: 32,
                },
                "max_bytes",
            ),
            (
                AttrDefLimits {
                    max_bytes: 4096,
                    max_entries: 0,
                },
                "max_entries",
            ),
        ] {
            assert_eq!(
                generate_ntfs3x_attrdef(limits),
                Err(AttrDefError::InvalidLimit { field })
            );
        }
        assert_eq!(
            generate_ntfs3x_attrdef(AttrDefLimits {
                max_bytes: NTFS3X_ATTRDEF_BYTES - 1,
                max_entries: 16,
            }),
            Err(AttrDefError::ByteLimitExceeded {
                actual: NTFS3X_ATTRDEF_BYTES,
                maximum: NTFS3X_ATTRDEF_BYTES - 1,
            })
        );
        assert_eq!(
            generate_ntfs3x_attrdef(AttrDefLimits {
                max_bytes: NTFS3X_ATTRDEF_BYTES,
                max_entries: 15,
            }),
            Err(AttrDefError::EntryLimitExceeded {
                actual: 16,
                maximum: 15,
            })
        );
    }

    #[test]
    fn attrdef_rejects_length_and_entry_caps_before_decoding() {
        assert_eq!(
            parse_attrdef(&[0; 159], attrdef_limits()),
            Err(AttrDefError::LengthNotMultiple { actual: 159 })
        );
        assert_eq!(
            parse_attrdef(
                &[0; 320],
                AttrDefLimits {
                    max_bytes: 320,
                    max_entries: 1,
                }
            ),
            Err(AttrDefError::EntryLimitExceeded {
                actual: 2,
                maximum: 1,
            })
        );
    }

    #[test]
    fn attrdef_requires_a_zero_terminator_and_rejects_data_after_it() {
        assert_eq!(
            parse_attrdef(&[], attrdef_limits()),
            Err(AttrDefError::MissingTerminator)
        );
        let mut bytes = canonical_attrdef();
        bytes.truncate(15 * ATTRDEF_ENTRY_BYTES);
        assert_eq!(
            parse_attrdef(&bytes, attrdef_limits()),
            Err(AttrDefError::MissingTerminator)
        );
        let mut early = canonical_attrdef();
        early[..ATTRDEF_ENTRY_BYTES].fill(0);
        assert_eq!(
            parse_attrdef(&early, attrdef_limits()),
            Err(AttrDefError::NonZeroAfterTerminator { index: 1 })
        );
    }

    #[test]
    fn attrdef_accepts_zero_tail_but_canonical_policy_requires_exact_bytes() {
        let mut bytes = canonical_attrdef();
        bytes.extend_from_slice(&[0; ATTRDEF_ENTRY_BYTES]);
        let table = parse_attrdef(&bytes, attrdef_limits()).expect("zero-filled tail");
        assert_eq!(table.definition_count(), NTFS3X_ATTRDEF_DEFINITION_COUNT);
        assert_eq!(table.bytes(), bytes);
        assert_eq!(
            validate_ntfs3x_attrdef(&bytes, attrdef_limits()),
            Err(AttrDefError::NonCanonical {
                index: NTFS3X_ATTRDEF_DEFINITION_COUNT,
                field: AttrDefField::ByteLength,
            })
        );

        bytes[16 * ATTRDEF_ENTRY_BYTES] = 1;
        assert_eq!(
            parse_attrdef(&bytes, attrdef_limits()),
            Err(AttrDefError::NonZeroAfterTerminator { index: 16 })
        );
    }

    #[test]
    fn attrdef_matches_pinned_ntfs3g_payload_digest() {
        use sha2::{Digest, Sha256};

        let digest: [u8; 32] = Sha256::digest(canonical_attrdef()).into();
        assert_eq!(
            digest,
            [
                0xd7, 0xde, 0x5b, 0x1b, 0x2f, 0x79, 0xf4, 0x5f, 0x23, 0x5c, 0xeb, 0x1a, 0xdb, 0xc4,
                0x69, 0x08, 0xed, 0x64, 0xea, 0xe1, 0x74, 0xeb, 0x90, 0xed, 0x66, 0xae, 0xfe, 0x5f,
                0x25, 0x16, 0x5d, 0xa3,
            ]
        );
    }

    #[test]
    fn attrdef_rejects_malformed_names() {
        let mut empty = canonical_attrdef();
        empty[0..2].fill(0);
        assert_eq!(
            parse_attrdef(&empty, attrdef_limits()),
            Err(AttrDefError::EmptyName { index: 0 })
        );

        let mut unterminated = canonical_attrdef();
        unterminated[..128].fill(1);
        assert_eq!(
            parse_attrdef(&unterminated, attrdef_limits()),
            Err(AttrDefError::NameNotTerminated { index: 0 })
        );

        let mut dirty_padding = canonical_attrdef();
        dirty_padding[126..128].copy_from_slice(&1_u16.to_le_bytes());
        assert_eq!(
            parse_attrdef(&dirty_padding, attrdef_limits()),
            Err(AttrDefError::NonZeroNamePadding { index: 0, unit: 63 })
        );

        let mut invalid_utf16 = canonical_attrdef();
        invalid_utf16[2..4].copy_from_slice(&0xd800_u16.to_le_bytes());
        assert_eq!(
            parse_attrdef(&invalid_utf16, attrdef_limits()),
            Err(AttrDefError::InvalidUtf16Name { index: 0, unit: 1 })
        );
    }

    #[test]
    fn attrdef_rejects_bad_types_flags_and_ranges() {
        let mut zero_type = canonical_attrdef();
        write_u32(&mut zero_type, 0x80, 0);
        assert_eq!(
            parse_attrdef(&zero_type, attrdef_limits()),
            Err(AttrDefError::ZeroAttributeType { index: 0 })
        );

        let mut unaligned = canonical_attrdef();
        write_u32(&mut unaligned, 0x80, 0x11);
        assert_eq!(
            parse_attrdef(&unaligned, attrdef_limits()),
            Err(AttrDefError::UnalignedAttributeType {
                index: 0,
                attribute_type: 0x11
            })
        );

        let mut unsorted = canonical_attrdef();
        write_u32(&mut unsorted, ATTRDEF_ENTRY_BYTES + 0x80, 0x10);
        assert_eq!(
            parse_attrdef(&unsorted, attrdef_limits()),
            Err(AttrDefError::AttributeTypesNotIncreasing {
                index: 1,
                previous: 0x10,
                actual: 0x10
            })
        );

        let mut flags = canonical_attrdef();
        write_u32(&mut flags, 0x8c, 1);
        assert_eq!(
            parse_attrdef(&flags, attrdef_limits()),
            Err(AttrDefError::UnknownFlags { index: 0, flags: 1 })
        );

        for (minimum, maximum) in [(-1, 4), (5, -2), (5, 4)] {
            let mut range = canonical_attrdef();
            write_i64(&mut range, 0x90, minimum);
            write_i64(&mut range, 0x98, maximum);
            assert_eq!(
                parse_attrdef(&range, attrdef_limits()),
                Err(AttrDefError::InvalidSizeRange {
                    index: 0,
                    minimum,
                    maximum
                })
            );
        }
    }

    #[test]
    fn structurally_valid_noncanonical_table_is_distinguished() {
        let mut bytes = canonical_attrdef();
        write_u32(&mut bytes, 0x84, 1);
        let parsed = parse_attrdef(&bytes, attrdef_limits()).expect("structurally valid");
        assert_eq!(parsed.entries().next().expect("entry").display_rule, 1);
        assert_eq!(
            validate_ntfs3x_attrdef(&bytes, attrdef_limits()),
            Err(AttrDefError::NonCanonical {
                index: 0,
                field: AttrDefField::DisplayRule
            })
        );
    }

    #[test]
    fn canonical_badclus_boundary_encodings_are_minimal() {
        for (clusters, expected) in [
            (1, vec![0x01, 0x01, 0]),
            (127, vec![0x01, 0x7f, 0]),
            (128, vec![0x02, 0x80, 0x00, 0]),
            (255, vec![0x02, 0xff, 0x00, 0]),
            (256, vec![0x02, 0x00, 0x01, 0]),
            (32_767, vec![0x02, 0xff, 0x7f, 0]),
            (32_768, vec![0x03, 0x00, 0x80, 0x00, 0]),
            (65_535, vec![0x03, 0xff, 0xff, 0x00, 0]),
            (65_536, vec![0x03, 0x00, 0x00, 0x01, 0]),
            (
                u64::from(u32::MAX),
                vec![0x05, 0xff, 0xff, 0xff, 0xff, 0x00, 0],
            ),
        ] {
            let plan = plan_empty_badclus(clusters, 4096, badclus_limits()).expect("geometry");
            assert_eq!(plan.mapping_pairs, expected);
            assert_eq!(plan.highest_vcn, clusters - 1);
            assert_eq!(plan.data_size, clusters * 4096);
            assert_eq!(plan.allocated_size, plan.data_size);
            assert_eq!(plan.initialized_size, 0);
            validate_empty_badclus(plan.as_ref(), clusters, 4096, badclus_limits())
                .expect("generated plan validates");
        }
    }

    #[test]
    fn badclus_generation_is_deterministic_and_accepts_zero_alignment_padding() {
        let first = plan_empty_badclus(4096, 4096, badclus_limits()).expect("plan");
        let second = plan_empty_badclus(4096, 4096, badclus_limits()).expect("plan");
        assert_eq!(first, second);
        let mut padded = first;
        padded.mapping_pairs.extend_from_slice(&[0; 7]);
        validate_empty_badclus(padded.as_ref(), 4096, 4096, badclus_limits())
            .expect("zero alignment padding");
    }

    #[test]
    fn badclus_rejects_invalid_limits_and_geometry() {
        assert_eq!(
            plan_empty_badclus(
                1,
                4096,
                BadClusLimits {
                    max_volume_clusters: 0,
                    max_mapping_pairs_bytes: 32
                }
            ),
            Err(BadClusError::InvalidLimit {
                field: "max_volume_clusters"
            })
        );
        assert_eq!(
            plan_empty_badclus(
                1,
                4096,
                BadClusLimits {
                    max_volume_clusters: 1,
                    max_mapping_pairs_bytes: 0
                }
            ),
            Err(BadClusError::InvalidLimit {
                field: "max_mapping_pairs_bytes"
            })
        );
        assert_eq!(
            plan_empty_badclus(0, 4096, badclus_limits()),
            Err(BadClusError::ZeroClusterCount)
        );
        assert_eq!(
            plan_empty_badclus(
                11,
                4096,
                BadClusLimits {
                    max_volume_clusters: 10,
                    max_mapping_pairs_bytes: 32
                }
            ),
            Err(BadClusError::ClusterCountTooLarge {
                actual: 11,
                maximum: 10
            })
        );
        for cluster_bytes in [0, 256, 768, 4 * 1024 * 1024] {
            assert_eq!(
                plan_empty_badclus(1, cluster_bytes, badclus_limits()),
                Err(BadClusError::InvalidClusterBytes { cluster_bytes })
            );
        }
        let outside_ntfs = NTFS_MAX_VOLUME_CLUSTERS + 1;
        assert_eq!(
            plan_empty_badclus(
                outside_ntfs,
                4096,
                BadClusLimits {
                    max_volume_clusters: outside_ntfs,
                    max_mapping_pairs_bytes: 32,
                },
            ),
            Err(BadClusError::ClusterCountOutsideNtfsLimit {
                actual: outside_ntfs,
                maximum: NTFS_MAX_VOLUME_CLUSTERS,
            })
        );
    }

    #[test]
    fn badclus_accepts_largest_supported_geometry_and_enforces_mapping_cap() {
        let plan = plan_empty_badclus(NTFS_MAX_VOLUME_CLUSTERS, 2 * 1024 * 1024, badclus_limits())
            .expect("largest Microsoft-supported geometry");
        assert_eq!(
            plan.data_size,
            NTFS_MAX_VOLUME_CLUSTERS * u64::from(2_u32 * 1024 * 1024)
        );
        assert_eq!(plan.mapping_pairs, [0x05, 0xff, 0xff, 0xff, 0xff, 0x00, 0]);
        assert_eq!(
            plan_empty_badclus(
                256,
                4096,
                BadClusLimits {
                    max_volume_clusters: 256,
                    max_mapping_pairs_bytes: 3
                }
            ),
            Err(BadClusError::MappingPairsLimitExceeded {
                actual: 4,
                maximum: 3
            })
        );
    }

    #[test]
    fn badclus_validator_checks_every_attribute_field() {
        let plan = plan_empty_badclus(1000, 4096, badclus_limits()).expect("plan");
        let base = plan.as_ref();
        let cases = [
            (
                EmptyBadClusRef {
                    attribute_type: 0x90,
                    ..base
                },
                BadClusError::WrongAttributeType { actual: 0x90 },
            ),
            (
                EmptyBadClusRef {
                    name: &[u16::from(b'X')],
                    ..base
                },
                BadClusError::WrongName,
            ),
            (
                EmptyBadClusRef {
                    attribute_flags: 0x8000,
                    ..base
                },
                BadClusError::WrongAttributeFlags { actual: 0x8000 },
            ),
            (
                EmptyBadClusRef {
                    compression_unit: 4,
                    ..base
                },
                BadClusError::WrongCompressionUnit { actual: 4 },
            ),
            (
                EmptyBadClusRef {
                    lowest_vcn: 1,
                    ..base
                },
                BadClusError::WrongLowestVcn { actual: 1 },
            ),
            (
                EmptyBadClusRef {
                    highest_vcn: 1,
                    ..base
                },
                BadClusError::WrongHighestVcn {
                    expected: 999,
                    actual: 1,
                },
            ),
            (
                EmptyBadClusRef {
                    allocated_size: 1,
                    ..base
                },
                BadClusError::WrongAllocatedSize {
                    expected: 4_096_000,
                    actual: 1,
                },
            ),
            (
                EmptyBadClusRef {
                    data_size: 1,
                    ..base
                },
                BadClusError::WrongDataSize {
                    expected: 4_096_000,
                    actual: 1,
                },
            ),
            (
                EmptyBadClusRef {
                    initialized_size: 1,
                    ..base
                },
                BadClusError::WrongInitializedSize { actual: 1 },
            ),
        ];
        for (stream, error) in cases {
            assert_eq!(
                validate_empty_badclus(stream, 1000, 4096, badclus_limits()),
                Err(error)
            );
        }
    }

    #[test]
    fn badclus_validator_rejects_malformed_mapping_pairs() {
        let plan = plan_empty_badclus(256, 4096, badclus_limits()).expect("plan");
        let base = plan.as_ref();
        for (mapping_pairs, error) in [
            (vec![], BadClusError::MissingMappingPairsTerminator),
            (
                vec![0x12, 0, 1, 0],
                BadClusError::InvalidMappingPairsHeader { actual: 0x12 },
            ),
            (
                vec![0x03, 0, 1, 0, 0],
                BadClusError::NonMinimalRunLengthWidth {
                    expected: 2,
                    actual: 3,
                },
            ),
            (
                vec![0x02, 0],
                BadClusError::TruncatedMappingPairs {
                    required: 4,
                    actual: 2,
                },
            ),
            (
                vec![0x02, 1, 1, 0],
                BadClusError::WrongSparseRunLength {
                    expected: 256,
                    actual: 257,
                },
            ),
            (
                vec![0x02, 0, 1, 1],
                BadClusError::MissingMappingPairsTerminator,
            ),
            (
                vec![0x02, 0, 1, 0, 7],
                BadClusError::NonZeroMappingPairsPadding {
                    offset: 4,
                    value: 7,
                },
            ),
        ] {
            assert_eq!(
                validate_empty_badclus(
                    EmptyBadClusRef {
                        mapping_pairs: &mapping_pairs,
                        ..base
                    },
                    256,
                    4096,
                    badclus_limits()
                ),
                Err(error)
            );
        }
    }
}
