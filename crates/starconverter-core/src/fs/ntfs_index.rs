//! Bounded, read-only parsing of NTFS directory indexes.
//!
//! The parser understands resident `INDEX_ROOT` values and complete `INDX` records from an
//! `INDEX_ALLOCATION` stream. It validates every entry before returning a view. `INDX` update
//! sequence replacements are applied virtually, so parsing neither mutates the caller's buffer
//! nor allocates a repaired copy.

use std::fmt;

/// `$FILE_NAME`, the key type used by the standard NTFS `$I30` directory index.
pub const FILE_NAME_ATTRIBUTE_TYPE: u32 = 0x30;
/// Filename collation, the collation rule used by the standard NTFS `$I30` directory index.
pub const FILE_NAME_COLLATION_RULE: u32 = 0x01;
/// NTFS multi-sector transfer protection always uses 512-byte strides.
pub const UPDATE_SEQUENCE_STRIDE: usize = 512;

const INDEX_ROOT_HEADER_LEN: usize = 16;
const INDEX_HEADER_LEN: usize = 16;
const INDEX_BLOCK_HEADER_LEN: usize = 24;
const INDEX_ENTRY_HEADER_LEN: usize = 16;
const FILE_NAME_KEY_HEADER_LEN: usize = 66;
const INDEX_ENTRY_NODE: u16 = 0x0001;
const INDEX_ENTRY_END: u16 = 0x0002;
const INDEX_ENTRY_KNOWN_FLAGS: u16 = INDEX_ENTRY_NODE | INDEX_ENTRY_END;

/// Explicit resource limits for hostile or corrupt index data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtfsIndexLimits {
    /// Maximum complete resident `INDEX_ROOT` value.
    pub max_root_bytes: usize,
    /// Maximum complete `INDX` block.
    pub max_block_bytes: usize,
    /// Maximum number of entries, including the terminal entry, in one index node.
    pub max_entries_per_node: usize,
    /// Maximum UTF-16 code units accepted in one filename key.
    pub max_name_code_units: usize,
}

impl Default for NtfsIndexLimits {
    fn default() -> Self {
        Self {
            max_root_bytes: 1024 * 1024,
            max_block_bytes: 16 * 1024 * 1024,
            max_entries_per_node: 65_536,
            max_name_code_units: 255,
        }
    }
}

/// Decoded NTFS file reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtfsFileReference {
    /// Low 48-bit MFT record number.
    pub record_number: u64,
    /// High 16-bit sequence number used to reject stale references.
    pub sequence_number: u16,
}

/// Common header embedded in an `INDEX_ROOT` value or `INDX` record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtfsIndexHeader {
    /// Offset from the beginning of this header to the first index entry.
    pub entries_offset: u32,
    /// Offset from the beginning of this header to the end of used index data.
    pub index_length: u32,
    /// Offset from the beginning of this header to the end of allocated index data.
    pub allocated_size: u32,
    /// Whether this node has children below it.
    pub has_children: bool,
}

/// A validated resident `$I30` `INDEX_ROOT` value.
#[derive(Debug, Clone, Copy)]
pub struct NtfsIndexRoot<'a> {
    pub indexed_attribute_type: u32,
    pub collation_rule: u32,
    pub index_block_size: u32,
    /// Number of clusters per index block, or 512-byte sectors when the block is sub-cluster.
    /// This field is an unsigned byte on disk.
    pub clusters_per_index_block: u8,
    pub header: NtfsIndexHeader,
    entries: ValidatedEntries<'a>,
}

impl<'a> NtfsIndexRoot<'a> {
    /// Returns the already-validated entries without allocating.
    #[must_use]
    pub const fn entries(&self) -> NtfsIndexEntries<'a> {
        self.entries.iter()
    }

    #[must_use]
    pub const fn entry_count(&self) -> usize {
        self.entries.count
    }
}

/// A validated, virtually repaired `INDX` index-allocation record.
#[derive(Debug, Clone, Copy)]
pub struct NtfsIndexBlock<'a> {
    pub log_file_sequence_number: u64,
    pub index_block_vcn: u64,
    pub update_sequence_offset: u16,
    pub update_sequence_count: u16,
    pub header: NtfsIndexHeader,
    entries: ValidatedEntries<'a>,
}

impl<'a> NtfsIndexBlock<'a> {
    /// Returns the already-validated entries without allocating.
    #[must_use]
    pub const fn entries(&self) -> NtfsIndexEntries<'a> {
        self.entries.iter()
    }

    #[must_use]
    pub const fn entry_count(&self) -> usize {
        self.entries.count
    }
}

/// Decoded filename namespace from an NTFS `$FILE_NAME` key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileNameNamespace {
    Posix,
    Win32,
    Dos,
    Win32AndDos,
}

/// Allocation-free UTF-16 filename view.
#[derive(Debug, Clone, Copy)]
pub struct NtfsUtf16Name<'a> {
    view: ByteView<'a>,
    offset: usize,
    code_units: usize,
}

impl NtfsUtf16Name<'_> {
    #[must_use]
    pub const fn len(&self) -> usize {
        self.code_units
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.code_units == 0
    }

    /// Iterates raw UTF-16 code units. Invalid surrogate combinations remain observable.
    #[must_use]
    pub const fn code_units(&self) -> NtfsUtf16CodeUnits<'_> {
        NtfsUtf16CodeUnits {
            view: self.view,
            offset: self.offset,
            remaining: self.code_units,
        }
    }
}

/// Iterator over a filename's raw UTF-16 code units.
#[derive(Debug, Clone)]
pub struct NtfsUtf16CodeUnits<'a> {
    view: ByteView<'a>,
    offset: usize,
    remaining: usize,
}

impl Iterator for NtfsUtf16CodeUnits<'_> {
    type Item = u16;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let value = self.view.u16(self.offset);
        self.offset += 2;
        self.remaining -= 1;
        Some(value)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for NtfsUtf16CodeUnits<'_> {}

/// `$FILE_NAME` key embedded in a directory index entry.
#[derive(Debug, Clone, Copy)]
pub struct NtfsFileNameKey<'a> {
    pub parent_directory: NtfsFileReference,
    pub creation_time: u64,
    pub modification_time: u64,
    pub mft_change_time: u64,
    pub access_time: u64,
    pub allocated_size: u64,
    pub data_size: u64,
    pub file_attributes: u32,
    pub reparse_tag_or_ea_size: u32,
    pub namespace: FileNameNamespace,
    pub name: NtfsUtf16Name<'a>,
}

/// One validated directory index entry.
#[derive(Debug, Clone, Copy)]
pub struct NtfsIndexEntry<'a> {
    /// `None` only for the terminal end entry.
    pub file_reference: Option<NtfsFileReference>,
    pub entry_length: u16,
    pub key_length: u16,
    pub has_child: bool,
    pub is_end: bool,
    /// Child index-block VCN when the node flag is present.
    pub child_vcn: Option<u64>,
    /// Parsed filename key; absent only on the terminal entry.
    pub file_name: Option<NtfsFileNameKey<'a>>,
}

/// Iterator over entries that were fully checked during parsing.
#[derive(Debug, Clone)]
pub struct NtfsIndexEntries<'a> {
    view: ByteView<'a>,
    cursor: usize,
    remaining: usize,
}

impl<'a> Iterator for NtfsIndexEntries<'a> {
    type Item = NtfsIndexEntry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let entry = decode_entry(self.view, self.cursor);
        self.cursor += usize::from(entry.entry_length);
        self.remaining -= 1;
        Some(entry)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for NtfsIndexEntries<'_> {}

#[derive(Debug, Clone, Copy)]
struct ValidatedEntries<'a> {
    view: ByteView<'a>,
    start: usize,
    count: usize,
}

impl<'a> ValidatedEntries<'a> {
    const fn iter(self) -> NtfsIndexEntries<'a> {
        NtfsIndexEntries {
            view: self.view,
            cursor: self.start,
            remaining: self.count,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum ByteView<'a> {
    Plain(&'a [u8]),
    Mst {
        bytes: &'a [u8],
        update_sequence_offset: usize,
    },
}

impl ByteView<'_> {
    const fn len(self) -> usize {
        match self {
            Self::Plain(bytes) | Self::Mst { bytes, .. } => bytes.len(),
        }
    }

    const fn byte(self, offset: usize) -> u8 {
        match self {
            Self::Plain(bytes) => bytes[offset],
            Self::Mst {
                bytes,
                update_sequence_offset,
            } => {
                let within_sector = offset % UPDATE_SEQUENCE_STRIDE;
                if within_sector >= UPDATE_SEQUENCE_STRIDE - 2 {
                    let sector = offset / UPDATE_SEQUENCE_STRIDE;
                    let replacement = update_sequence_offset + 2 + sector * 2;
                    bytes[replacement + within_sector - (UPDATE_SEQUENCE_STRIDE - 2)]
                } else {
                    bytes[offset]
                }
            }
        }
    }

    const fn u16(self, offset: usize) -> u16 {
        u16::from_le_bytes([self.byte(offset), self.byte(offset + 1)])
    }

    const fn u32(self, offset: usize) -> u32 {
        u32::from_le_bytes([
            self.byte(offset),
            self.byte(offset + 1),
            self.byte(offset + 2),
            self.byte(offset + 3),
        ])
    }

    const fn u64(self, offset: usize) -> u64 {
        u64::from_le_bytes([
            self.byte(offset),
            self.byte(offset + 1),
            self.byte(offset + 2),
            self.byte(offset + 3),
            self.byte(offset + 4),
            self.byte(offset + 5),
            self.byte(offset + 6),
            self.byte(offset + 7),
        ])
    }
}

/// Reason an NTFS directory index could not be safely interpreted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NtfsIndexError {
    Truncated {
        actual: usize,
        required: usize,
    },
    InputTooLarge {
        actual: usize,
        maximum: usize,
    },
    UnsupportedAttributeType {
        found: u32,
    },
    UnsupportedCollationRule {
        found: u32,
    },
    InvalidIndexBlockSize {
        value: u32,
    },
    InvalidClustersPerIndexBlock {
        value: u8,
    },
    InvalidMagic {
        found: [u8; 4],
    },
    BlockSizeNotStrideAligned {
        size: usize,
        stride: usize,
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
    },
    FixupMismatch {
        sector: usize,
        found: u16,
        expected: u16,
    },
    NegativeIndexBlockVcn {
        value: i64,
    },
    UnexpectedIndexBlockVcn {
        found: u64,
        expected: u64,
    },
    InvalidIndexHeaderFlags {
        value: u8,
    },
    NonzeroIndexHeaderReserved,
    InvalidEntriesOffset {
        value: u32,
        minimum: usize,
    },
    EntriesOffsetNotEightByteAligned {
        value: u32,
    },
    InvalidIndexLength {
        value: u32,
        entries_offset: u32,
        available: usize,
    },
    InvalidAllocatedSize {
        value: u32,
        index_length: u32,
        available: usize,
    },
    TruncatedEntry {
        offset: usize,
        remaining: usize,
    },
    InvalidEntryLength {
        offset: usize,
        value: u16,
        remaining: usize,
    },
    NoncanonicalEntryLength {
        offset: usize,
        found: u16,
        expected: usize,
    },
    EntryLengthNotEightByteAligned {
        offset: usize,
        value: u16,
    },
    InvalidEntryFlags {
        offset: usize,
        value: u16,
    },
    NonzeroEntryReserved {
        offset: usize,
        value: u16,
    },
    InvalidKeyLength {
        offset: usize,
        value: u16,
        available: usize,
    },
    TerminalEntryHasKey {
        offset: usize,
        key_length: u16,
    },
    MissingChildVcn {
        offset: usize,
    },
    NegativeChildVcn {
        offset: usize,
        value: i64,
    },
    InvalidFileNameKeyLength {
        offset: usize,
        value: u16,
    },
    InvalidFileNameNamespace {
        offset: usize,
        value: u8,
    },
    EmptyFileName {
        offset: usize,
    },
    FileNameTooLong {
        offset: usize,
        found: usize,
        maximum: usize,
    },
    FileNameLengthMismatch {
        offset: usize,
        key_length: u16,
        expected: usize,
    },
    EntryLimitExceeded {
        maximum: usize,
    },
    MissingEndEntry,
    DataAfterEndEntry {
        end: usize,
        used_end: usize,
    },
    ChildFlagMismatch {
        header_has_children: bool,
        entries_have_children: bool,
    },
    MixedChildPointers,
}

impl fmt::Display for NtfsIndexError {
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { actual, required } => write!(
                f,
                "NTFS index is truncated: got {actual} bytes, need at least {required}"
            ),
            Self::InputTooLarge { actual, maximum } => {
                write!(f, "NTFS index size {actual} exceeds parser cap {maximum}")
            }
            Self::UnsupportedAttributeType { found } => {
                write!(f, "unsupported NTFS index key attribute type 0x{found:08x}")
            }
            Self::UnsupportedCollationRule { found } => {
                write!(f, "unsupported NTFS index collation rule 0x{found:08x}")
            }
            Self::InvalidIndexBlockSize { value } => {
                write!(f, "invalid NTFS index block size {value}")
            }
            Self::InvalidClustersPerIndexBlock { value } => {
                write!(f, "invalid clusters-per-index-block value {value}")
            }
            Self::InvalidMagic { found } => write!(f, "invalid NTFS INDX signature: {found:02x?}"),
            Self::BlockSizeNotStrideAligned { size, stride } => write!(
                f,
                "INDX block size {size} is not a multiple of update-sequence stride {stride}"
            ),
            Self::InvalidUpdateSequenceOffset { value } => {
                write!(f, "invalid INDX update-sequence offset {value}")
            }
            Self::InvalidUpdateSequenceCount { found, expected } => write!(
                f,
                "invalid INDX update-sequence count {found}; expected {expected}"
            ),
            Self::UpdateSequenceArrayOutOfBounds { offset, length } => write!(
                f,
                "INDX update-sequence array at {offset} with length {length} is out of bounds"
            ),
            Self::FixupMismatch {
                sector,
                found,
                expected,
            } => write!(
                f,
                "INDX fixup mismatch in sector {sector}: found 0x{found:04x}, expected 0x{expected:04x}"
            ),
            Self::NegativeIndexBlockVcn { value } => write!(f, "negative INDX block VCN {value}"),
            Self::UnexpectedIndexBlockVcn { found, expected } => write!(
                f,
                "INDX block VCN {found} does not match requested VCN {expected}"
            ),
            Self::InvalidIndexHeaderFlags { value } => {
                write!(f, "invalid NTFS index-header flags 0x{value:02x}")
            }
            Self::NonzeroIndexHeaderReserved => {
                f.write_str("NTFS index-header reserved bytes are nonzero")
            }
            Self::InvalidEntriesOffset { value, minimum } => write!(
                f,
                "invalid index entries offset {value}; minimum is {minimum}"
            ),
            Self::EntriesOffsetNotEightByteAligned { value } => {
                write!(f, "index entries offset {value} is not 8-byte aligned")
            }
            Self::InvalidIndexLength {
                value,
                entries_offset,
                available,
            } => write!(
                f,
                "invalid index length {value}; entries begin at {entries_offset} and {available} bytes are available"
            ),
            Self::InvalidAllocatedSize {
                value,
                index_length,
                available,
            } => write!(
                f,
                "invalid index allocated size {value}; used length is {index_length} and {available} bytes are available"
            ),
            Self::TruncatedEntry { offset, remaining } => write!(
                f,
                "index entry at {offset} is truncated: {remaining} bytes remain"
            ),
            Self::InvalidEntryLength {
                offset,
                value,
                remaining,
            } => write!(
                f,
                "invalid index entry length {value} at {offset}; {remaining} bytes remain"
            ),
            Self::NoncanonicalEntryLength {
                offset,
                found,
                expected,
            } => write!(
                f,
                "index entry at {offset} has length {found}; canonical aligned length is {expected}"
            ),
            Self::EntryLengthNotEightByteAligned { offset, value } => write!(
                f,
                "index entry length {value} at {offset} is not 8-byte aligned"
            ),
            Self::InvalidEntryFlags { offset, value } => {
                write!(f, "invalid index entry flags 0x{value:04x} at {offset}")
            }
            Self::NonzeroEntryReserved { offset, value } => {
                write!(f, "index entry reserved field is 0x{value:04x} at {offset}")
            }
            Self::InvalidKeyLength {
                offset,
                value,
                available,
            } => write!(
                f,
                "invalid index key length {value} at {offset}; {available} bytes are available"
            ),
            Self::TerminalEntryHasKey { offset, key_length } => write!(
                f,
                "terminal index entry at {offset} has key length {key_length}"
            ),
            Self::MissingChildVcn { offset } => write!(
                f,
                "child index entry at {offset} has no room for a child VCN"
            ),
            Self::NegativeChildVcn { offset, value } => {
                write!(f, "index entry at {offset} has negative child VCN {value}")
            }
            Self::InvalidFileNameKeyLength { offset, value } => {
                write!(f, "invalid FILE_NAME key length {value} at {offset}")
            }
            Self::InvalidFileNameNamespace { offset, value } => {
                write!(f, "invalid FILE_NAME namespace {value} at {offset}")
            }
            Self::EmptyFileName { offset } => {
                write!(f, "FILE_NAME key at {offset} has an empty name")
            }
            Self::FileNameTooLong {
                offset,
                found,
                maximum,
            } => write!(
                f,
                "FILE_NAME at {offset} has {found} UTF-16 units; cap is {maximum}"
            ),
            Self::FileNameLengthMismatch {
                offset,
                key_length,
                expected,
            } => write!(
                f,
                "FILE_NAME key at {offset} has length {key_length}; encoded name requires {expected}"
            ),
            Self::EntryLimitExceeded { maximum } => {
                write!(f, "index node exceeds the {maximum}-entry cap")
            }
            Self::MissingEndEntry => f.write_str("NTFS index node has no terminal end entry"),
            Self::DataAfterEndEntry { end, used_end } => write!(
                f,
                "index node has data after terminal entry ending at {end}; used data ends at {used_end}"
            ),
            Self::ChildFlagMismatch {
                header_has_children,
                entries_have_children,
            } => write!(
                f,
                "index child flag mismatch: header={header_has_children}, entries={entries_have_children}"
            ),
            Self::MixedChildPointers => {
                f.write_str("NTFS index node mixes entries with and without child pointers")
            }
        }
    }
}

impl std::error::Error for NtfsIndexError {}

/// Parses one complete resident `$I30` `INDEX_ROOT` attribute value.
///
/// # Errors
/// Returns an error for unsupported index kinds, inconsistent sizes, malformed filename keys,
/// missing termination, or a configured limit violation.
pub fn parse_index_root(
    bytes: &[u8],
    limits: NtfsIndexLimits,
) -> Result<NtfsIndexRoot<'_>, NtfsIndexError> {
    if bytes.len() < INDEX_ROOT_HEADER_LEN + INDEX_HEADER_LEN {
        return Err(NtfsIndexError::Truncated {
            actual: bytes.len(),
            required: INDEX_ROOT_HEADER_LEN + INDEX_HEADER_LEN,
        });
    }
    if bytes.len() > limits.max_root_bytes {
        return Err(NtfsIndexError::InputTooLarge {
            actual: bytes.len(),
            maximum: limits.max_root_bytes,
        });
    }
    let view = ByteView::Plain(bytes);
    let indexed_attribute_type = view.u32(0);
    if indexed_attribute_type != FILE_NAME_ATTRIBUTE_TYPE {
        return Err(NtfsIndexError::UnsupportedAttributeType {
            found: indexed_attribute_type,
        });
    }
    let collation_rule = view.u32(4);
    if collation_rule != FILE_NAME_COLLATION_RULE {
        return Err(NtfsIndexError::UnsupportedCollationRule {
            found: collation_rule,
        });
    }
    let index_block_size = view.u32(8);
    if index_block_size == 0 || !index_block_size.is_power_of_two() || index_block_size % 512 != 0 {
        return Err(NtfsIndexError::InvalidIndexBlockSize {
            value: index_block_size,
        });
    }
    let clusters_per_index_block = bytes[12];
    if clusters_per_index_block == 0 {
        return Err(NtfsIndexError::InvalidClustersPerIndexBlock {
            value: clusters_per_index_block,
        });
    }
    if bytes[13..16] != [0, 0, 0] {
        return Err(NtfsIndexError::NonzeroIndexHeaderReserved);
    }
    let (header, entries) = parse_node(view, INDEX_ROOT_HEADER_LEN, limits)?;
    Ok(NtfsIndexRoot {
        indexed_attribute_type,
        collation_rule,
        index_block_size,
        clusters_per_index_block,
        header,
        entries,
    })
}

/// Parses one complete `INDX` record, validating update-sequence protection virtually.
///
/// `expected_vcn` should be supplied when traversal selected this block through a child pointer.
///
/// # Errors
/// Returns an error for invalid MST protection, a VCN mismatch, malformed node data, or a limit
/// violation.
pub fn parse_index_block(
    bytes: &[u8],
    expected_vcn: Option<u64>,
    limits: NtfsIndexLimits,
) -> Result<NtfsIndexBlock<'_>, NtfsIndexError> {
    if bytes.len() < UPDATE_SEQUENCE_STRIDE {
        return Err(NtfsIndexError::Truncated {
            actual: bytes.len(),
            required: UPDATE_SEQUENCE_STRIDE,
        });
    }
    if bytes.len() > limits.max_block_bytes {
        return Err(NtfsIndexError::InputTooLarge {
            actual: bytes.len(),
            maximum: limits.max_block_bytes,
        });
    }
    if bytes.len() % UPDATE_SEQUENCE_STRIDE != 0 {
        return Err(NtfsIndexError::BlockSizeNotStrideAligned {
            size: bytes.len(),
            stride: UPDATE_SEQUENCE_STRIDE,
        });
    }
    let found_magic = [bytes[0], bytes[1], bytes[2], bytes[3]];
    if found_magic != *b"INDX" {
        return Err(NtfsIndexError::InvalidMagic { found: found_magic });
    }
    let update_sequence_offset = plain_u16(bytes, 4);
    let update_sequence_count = plain_u16(bytes, 6);
    validate_fixups(bytes, update_sequence_offset, update_sequence_count)?;
    let view = ByteView::Mst {
        bytes,
        update_sequence_offset: usize::from(update_sequence_offset),
    };
    let raw_vcn = i64::from_le_bytes(view.u64(16).to_le_bytes());
    let index_block_vcn = u64::try_from(raw_vcn)
        .map_err(|_| NtfsIndexError::NegativeIndexBlockVcn { value: raw_vcn })?;
    if let Some(expected) = expected_vcn {
        if index_block_vcn != expected {
            return Err(NtfsIndexError::UnexpectedIndexBlockVcn {
                found: index_block_vcn,
                expected,
            });
        }
    }
    let (header, entries) = parse_node(view, INDEX_BLOCK_HEADER_LEN, limits)?;
    let usa_end = usize::from(update_sequence_offset) + usize::from(update_sequence_count) * 2;
    let entry_start =
        INDEX_BLOCK_HEADER_LEN + usize::try_from(header.entries_offset).unwrap_or(usize::MAX);
    if usa_end > entry_start {
        return Err(NtfsIndexError::UpdateSequenceArrayOutOfBounds {
            offset: usize::from(update_sequence_offset),
            length: usize::from(update_sequence_count) * 2,
        });
    }
    Ok(NtfsIndexBlock {
        log_file_sequence_number: view.u64(8),
        index_block_vcn,
        update_sequence_offset,
        update_sequence_count,
        header,
        entries,
    })
}

fn validate_fixups(bytes: &[u8], offset: u16, count: u16) -> Result<(), NtfsIndexError> {
    let offset_usize = usize::from(offset);
    if offset_usize < INDEX_BLOCK_HEADER_LEN + INDEX_HEADER_LEN || offset % 2 != 0 {
        return Err(NtfsIndexError::InvalidUpdateSequenceOffset { value: offset });
    }
    let expected = 1 + bytes.len() / UPDATE_SEQUENCE_STRIDE;
    if usize::from(count) != expected {
        return Err(NtfsIndexError::InvalidUpdateSequenceCount {
            found: count,
            expected,
        });
    }
    let length = usize::from(count) * 2;
    if offset_usize
        .checked_add(length)
        .is_none_or(|end| end > UPDATE_SEQUENCE_STRIDE - 2)
    {
        return Err(NtfsIndexError::UpdateSequenceArrayOutOfBounds {
            offset: offset_usize,
            length,
        });
    }
    let usn = plain_u16(bytes, offset_usize);
    for sector in 0..expected - 1 {
        let trailer = (sector + 1) * UPDATE_SEQUENCE_STRIDE - 2;
        let found = plain_u16(bytes, trailer);
        if found != usn {
            return Err(NtfsIndexError::FixupMismatch {
                sector,
                found,
                expected: usn,
            });
        }
    }
    Ok(())
}

fn parse_node(
    view: ByteView<'_>,
    header_offset: usize,
    limits: NtfsIndexLimits,
) -> Result<(NtfsIndexHeader, ValidatedEntries<'_>), NtfsIndexError> {
    let entries_offset = view.u32(header_offset);
    let index_length = view.u32(header_offset + 4);
    let allocated_size = view.u32(header_offset + 8);
    let flags = view.byte(header_offset + 12);
    if flags & !1 != 0 {
        return Err(NtfsIndexError::InvalidIndexHeaderFlags { value: flags });
    }
    if view.byte(header_offset + 13) != 0
        || view.byte(header_offset + 14) != 0
        || view.byte(header_offset + 15) != 0
    {
        return Err(NtfsIndexError::NonzeroIndexHeaderReserved);
    }
    let minimum = INDEX_HEADER_LEN;
    if usize::try_from(entries_offset).unwrap_or(usize::MAX) < minimum {
        return Err(NtfsIndexError::InvalidEntriesOffset {
            value: entries_offset,
            minimum,
        });
    }
    if entries_offset % 8 != 0 {
        return Err(NtfsIndexError::EntriesOffsetNotEightByteAligned {
            value: entries_offset,
        });
    }
    let available = view.len() - header_offset;
    let used_length = usize::try_from(index_length).unwrap_or(usize::MAX);
    if index_length < entries_offset || used_length > available {
        return Err(NtfsIndexError::InvalidIndexLength {
            value: index_length,
            entries_offset,
            available,
        });
    }
    let allocated_length = usize::try_from(allocated_size).unwrap_or(usize::MAX);
    if allocated_size < index_length || allocated_length > available {
        return Err(NtfsIndexError::InvalidAllocatedSize {
            value: allocated_size,
            index_length,
            available,
        });
    }
    let entries_start = header_offset + usize::try_from(entries_offset).unwrap_or(usize::MAX);
    let used_end = header_offset + used_length;
    let (count, entries_have_children, every_entry_has_child) =
        validate_entries(view, entries_start, used_end, limits)?;
    let header_has_children = flags == 1;
    if entries_have_children != every_entry_has_child {
        return Err(NtfsIndexError::MixedChildPointers);
    }
    if header_has_children != entries_have_children {
        return Err(NtfsIndexError::ChildFlagMismatch {
            header_has_children,
            entries_have_children,
        });
    }
    Ok((
        NtfsIndexHeader {
            entries_offset,
            index_length,
            allocated_size,
            has_children: header_has_children,
        },
        ValidatedEntries {
            view,
            start: entries_start,
            count,
        },
    ))
}

fn validate_entries(
    view: ByteView<'_>,
    start: usize,
    used_end: usize,
    limits: NtfsIndexLimits,
) -> Result<(usize, bool, bool), NtfsIndexError> {
    let mut cursor = start;
    let mut count = 0;
    let mut has_children = false;
    let mut every_entry_has_child = true;
    loop {
        if count >= limits.max_entries_per_node {
            return Err(NtfsIndexError::EntryLimitExceeded {
                maximum: limits.max_entries_per_node,
            });
        }
        let remaining = used_end.saturating_sub(cursor);
        if remaining < INDEX_ENTRY_HEADER_LEN {
            return if remaining == 0 {
                Err(NtfsIndexError::MissingEndEntry)
            } else {
                Err(NtfsIndexError::TruncatedEntry {
                    offset: cursor,
                    remaining,
                })
            };
        }
        let entry = validate_entry(view, cursor, remaining, limits)?;
        if entry.has_child {
            has_children = true;
        } else {
            every_entry_has_child = false;
        }
        count += 1;
        let end = cursor + entry.length;
        if entry.is_end {
            if end != used_end {
                return Err(NtfsIndexError::DataAfterEndEntry { end, used_end });
            }
            return Ok((count, has_children, every_entry_has_child));
        }
        cursor = end;
    }
}

#[derive(Debug, Clone, Copy)]
struct ValidatedEntryShape {
    length: usize,
    is_end: bool,
    has_child: bool,
}

fn validate_entry(
    view: ByteView<'_>,
    offset: usize,
    remaining: usize,
    limits: NtfsIndexLimits,
) -> Result<ValidatedEntryShape, NtfsIndexError> {
    let entry_length = view.u16(offset + 8);
    let key_length = view.u16(offset + 10);
    let flags = view.u16(offset + 12);
    let reserved = view.u16(offset + 14);
    if reserved != 0 {
        return Err(NtfsIndexError::NonzeroEntryReserved {
            offset,
            value: reserved,
        });
    }
    if flags & !INDEX_ENTRY_KNOWN_FLAGS != 0 {
        return Err(NtfsIndexError::InvalidEntryFlags {
            offset,
            value: flags,
        });
    }
    let length = usize::from(entry_length);
    if length < INDEX_ENTRY_HEADER_LEN || length > remaining {
        return Err(NtfsIndexError::InvalidEntryLength {
            offset,
            value: entry_length,
            remaining,
        });
    }
    if entry_length % 8 != 0 {
        return Err(NtfsIndexError::EntryLengthNotEightByteAligned {
            offset,
            value: entry_length,
        });
    }
    let has_child = flags & INDEX_ENTRY_NODE != 0;
    let child_bytes = if has_child { 8 } else { 0 };
    if has_child && length < INDEX_ENTRY_HEADER_LEN + child_bytes {
        return Err(NtfsIndexError::MissingChildVcn { offset });
    }
    let key_available = length - INDEX_ENTRY_HEADER_LEN - child_bytes;
    if usize::from(key_length) > key_available {
        return Err(NtfsIndexError::InvalidKeyLength {
            offset,
            value: key_length,
            available: key_available,
        });
    }
    let is_end = flags & INDEX_ENTRY_END != 0;
    if is_end && key_length != 0 {
        return Err(NtfsIndexError::TerminalEntryHasKey { offset, key_length });
    }
    if !is_end {
        validate_file_name_key(view, offset + INDEX_ENTRY_HEADER_LEN, key_length, limits)?;
    }
    let expected = align_eight(INDEX_ENTRY_HEADER_LEN + usize::from(key_length) + child_bytes);
    if length != expected {
        return Err(NtfsIndexError::NoncanonicalEntryLength {
            offset,
            found: entry_length,
            expected,
        });
    }
    if has_child {
        let raw = i64::from_le_bytes(view.u64(offset + length - 8).to_le_bytes());
        if raw < 0 {
            return Err(NtfsIndexError::NegativeChildVcn { offset, value: raw });
        }
    }
    Ok(ValidatedEntryShape {
        length,
        is_end,
        has_child,
    })
}

fn validate_file_name_key(
    view: ByteView<'_>,
    offset: usize,
    key_length: u16,
    limits: NtfsIndexLimits,
) -> Result<(), NtfsIndexError> {
    if usize::from(key_length) < FILE_NAME_KEY_HEADER_LEN {
        return Err(NtfsIndexError::InvalidFileNameKeyLength {
            offset,
            value: key_length,
        });
    }
    let name_units = usize::from(view.byte(offset + 64));
    if name_units == 0 {
        return Err(NtfsIndexError::EmptyFileName { offset });
    }
    if name_units > limits.max_name_code_units {
        return Err(NtfsIndexError::FileNameTooLong {
            offset,
            found: name_units,
            maximum: limits.max_name_code_units,
        });
    }
    let namespace = view.byte(offset + 65);
    if namespace > 3 {
        return Err(NtfsIndexError::InvalidFileNameNamespace {
            offset,
            value: namespace,
        });
    }
    let expected = FILE_NAME_KEY_HEADER_LEN + name_units * 2;
    if usize::from(key_length) != expected {
        return Err(NtfsIndexError::FileNameLengthMismatch {
            offset,
            key_length,
            expected,
        });
    }
    Ok(())
}

const fn align_eight(value: usize) -> usize {
    value.saturating_add(7) & !7
}

fn decode_entry(view: ByteView<'_>, offset: usize) -> NtfsIndexEntry<'_> {
    let entry_length = view.u16(offset + 8);
    let key_length = view.u16(offset + 10);
    let flags = view.u16(offset + 12);
    let has_child = flags & INDEX_ENTRY_NODE != 0;
    let is_end = flags & INDEX_ENTRY_END != 0;
    let entry_len = usize::from(entry_length);
    let child_vcn = has_child.then(|| view.u64(offset + entry_len - 8));
    let file_reference = (!is_end).then(|| decode_reference(view.u64(offset)));
    let file_name = (!is_end).then(|| decode_file_name(view, offset + INDEX_ENTRY_HEADER_LEN));
    NtfsIndexEntry {
        file_reference,
        entry_length,
        key_length,
        has_child,
        is_end,
        child_vcn,
        file_name,
    }
}

fn decode_file_name(view: ByteView<'_>, offset: usize) -> NtfsFileNameKey<'_> {
    let namespace = match view.byte(offset + 65) {
        0 => FileNameNamespace::Posix,
        1 => FileNameNamespace::Win32,
        2 => FileNameNamespace::Dos,
        3 => FileNameNamespace::Win32AndDos,
        _ => unreachable!("namespace was validated"),
    };
    let code_units = usize::from(view.byte(offset + 64));
    NtfsFileNameKey {
        parent_directory: decode_reference(view.u64(offset)),
        creation_time: view.u64(offset + 8),
        modification_time: view.u64(offset + 16),
        mft_change_time: view.u64(offset + 24),
        access_time: view.u64(offset + 32),
        allocated_size: view.u64(offset + 40),
        data_size: view.u64(offset + 48),
        file_attributes: view.u32(offset + 56),
        reparse_tag_or_ea_size: view.u32(offset + 60),
        namespace,
        name: NtfsUtf16Name {
            view,
            offset: offset + FILE_NAME_KEY_HEADER_LEN,
            code_units,
        },
    }
}

const fn decode_reference(raw: u64) -> NtfsFileReference {
    NtfsFileReference {
        record_number: raw & 0x0000_ffff_ffff_ffff,
        sequence_number: (raw >> 48) as u16,
    }
}

const fn plain_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
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

    fn filename_key(name: &[u16]) -> Vec<u8> {
        let mut key = vec![0; FILE_NAME_KEY_HEADER_LEN + name.len() * 2];
        put_u64(&mut key, 0, (7_u64 << 48) | 5);
        put_u64(&mut key, 8, 11);
        put_u64(&mut key, 40, 4096);
        put_u64(&mut key, 48, 1234);
        put_u32(&mut key, 56, 0x20);
        key[64] = u8::try_from(name.len()).unwrap();
        key[65] = 1;
        for (index, unit) in name.iter().enumerate() {
            put_u16(&mut key, 66 + index * 2, *unit);
        }
        key
    }

    fn append_entry(
        node: &mut Vec<u8>,
        reference: u64,
        key: &[u8],
        flags: u16,
        child: Option<u64>,
    ) {
        let raw_len = INDEX_ENTRY_HEADER_LEN + key.len() + usize::from(child.is_some()) * 8;
        let len = (raw_len + 7) & !7;
        let start = node.len();
        node.resize(start + len, 0);
        put_u64(node, start, reference);
        put_u16(node, start + 8, u16::try_from(len).unwrap());
        put_u16(node, start + 10, u16::try_from(key.len()).unwrap());
        put_u16(node, start + 12, flags);
        node[start + 16..start + 16 + key.len()].copy_from_slice(key);
        if let Some(vcn) = child {
            put_u64(node, start + len - 8, vcn);
        }
    }

    fn root(has_children: bool) -> Vec<u8> {
        let mut bytes = vec![0; 32];
        put_u32(&mut bytes, 0, FILE_NAME_ATTRIBUTE_TYPE);
        put_u32(&mut bytes, 4, FILE_NAME_COLLATION_RULE);
        put_u32(&mut bytes, 8, 4096);
        bytes[12] = 8;
        let key = filename_key(&[u16::from(b'a'), 0xd83d, 0xde80]);
        append_entry(
            &mut bytes,
            (3_u64 << 48) | 0x2a,
            &key,
            u16::from(has_children),
            has_children.then_some(9),
        );
        append_entry(
            &mut bytes,
            0,
            &[],
            INDEX_ENTRY_END | u16::from(has_children),
            has_children.then_some(12),
        );
        let used = u32::try_from(bytes.len() - 16).unwrap();
        put_u32(&mut bytes, 16, 16);
        put_u32(&mut bytes, 20, used);
        put_u32(&mut bytes, 24, used);
        bytes[28] = u8::from(has_children);
        bytes
    }

    fn indx() -> Vec<u8> {
        let source = root(false);
        let root_entries = &source[32..];
        let mut bytes = vec![0; 1024];
        bytes[..4].copy_from_slice(b"INDX");
        put_u16(&mut bytes, 4, 40);
        put_u16(&mut bytes, 6, 3);
        put_u64(&mut bytes, 8, 77);
        put_u64(&mut bytes, 16, 4);
        put_u32(&mut bytes, 24, 24);
        put_u32(
            &mut bytes,
            28,
            u32::try_from(24 + root_entries.len()).unwrap(),
        );
        put_u32(&mut bytes, 32, 1000);
        bytes[48..48 + root_entries.len()].copy_from_slice(root_entries);
        put_u16(&mut bytes, 40, 0xa55a);
        put_u16(&mut bytes, 42, 0x1111);
        put_u16(&mut bytes, 44, 0x2222);
        put_u16(&mut bytes, 510, 0xa55a);
        put_u16(&mut bytes, 1022, 0xa55a);
        bytes
    }

    #[test]
    fn parses_resident_root_and_filename_without_allocating() {
        let bytes = root(false);
        let parsed = parse_index_root(&bytes, NtfsIndexLimits::default()).unwrap();
        assert_eq!(parsed.entry_count(), 2);
        let first = parsed.entries().next().unwrap();
        assert_eq!(first.file_reference.unwrap().record_number, 42);
        let name = first.file_name.unwrap();
        assert_eq!(
            name.parent_directory,
            NtfsFileReference {
                record_number: 5,
                sequence_number: 7
            }
        );
        assert_eq!(
            name.name.code_units().collect::<Vec<_>>(),
            vec![0x61, 0xd83d, 0xde80]
        );
        assert!(parsed.entries().last().unwrap().is_end);
    }

    #[test]
    fn parses_unsigned_128_index_block_units() {
        let mut bytes = root(false);
        put_u32(&mut bytes, 8, 65_536);
        bytes[12] = 128;
        let parsed = parse_index_root(&bytes, NtfsIndexLimits::default()).unwrap();
        assert_eq!(parsed.index_block_size, 65_536);
        assert_eq!(parsed.clusters_per_index_block, 128);
    }

    #[test]
    fn parses_children_and_terminal_child_pointer() {
        let bytes = root(true);
        let parsed = parse_index_root(&bytes, NtfsIndexLimits::default()).unwrap();
        let entries: Vec<_> = parsed.entries().collect();
        assert!(parsed.header.has_children);
        assert_eq!(entries[0].child_vcn, Some(9));
        assert_eq!(entries[1].child_vcn, Some(12));
    }

    #[test]
    fn virtually_repairs_indx_sector_trailers() {
        let mut bytes = indx();
        // Put filename UTF-16 bytes across the first protected sector trailer. Validation and
        // decoding use the replacement array rather than the on-disk USN bytes.
        put_u32(&mut bytes, 24, 400);
        let key = filename_key(&[0x1234]);
        let mut entries = Vec::new();
        append_entry(&mut entries, 6, &key, 0, None);
        append_entry(&mut entries, 0, &[], INDEX_ENTRY_END, None);
        let start = 424;
        bytes[start..start + entries.len()].copy_from_slice(&entries);
        let used = 400 + entries.len();
        put_u32(&mut bytes, 28, u32::try_from(used).unwrap());
        let first_sector_replacement = plain_u16(&bytes, 510);
        let second_sector_replacement = plain_u16(&bytes, 1022);
        put_u16(&mut bytes, 42, first_sector_replacement);
        put_u16(&mut bytes, 44, second_sector_replacement);
        put_u16(&mut bytes, 510, 0xa55a);
        let parsed = parse_index_block(&bytes, Some(4), NtfsIndexLimits::default()).unwrap();
        assert_eq!(parsed.log_file_sequence_number, 77);
        assert_eq!(
            parsed
                .entries()
                .next()
                .unwrap()
                .file_name
                .unwrap()
                .name
                .code_units()
                .next(),
            Some(0x1234)
        );
        assert_eq!(&bytes[510..512], &0xa55a_u16.to_le_bytes());
    }

    #[test]
    fn rejects_bad_fixup_and_wrong_vcn() {
        let mut bytes = indx();
        bytes[510] ^= 1;
        assert!(matches!(
            parse_index_block(&bytes, Some(4), NtfsIndexLimits::default()),
            Err(NtfsIndexError::FixupMismatch { sector: 0, .. })
        ));
        let bytes = indx();
        assert!(matches!(
            parse_index_block(&bytes, Some(5), NtfsIndexLimits::default()),
            Err(NtfsIndexError::UnexpectedIndexBlockVcn {
                found: 4,
                expected: 5
            })
        ));
    }

    #[test]
    fn rejects_entry_alignment_bounds_and_unknown_flags() {
        let mut bytes = root(false);
        put_u16(&mut bytes, 40, 17);
        assert!(matches!(
            parse_index_root(&bytes, NtfsIndexLimits::default()),
            Err(NtfsIndexError::EntryLengthNotEightByteAligned { .. })
        ));
        let mut bytes = root(false);
        put_u16(&mut bytes, 42, u16::MAX);
        assert!(matches!(
            parse_index_root(&bytes, NtfsIndexLimits::default()),
            Err(NtfsIndexError::InvalidKeyLength { .. })
        ));
        let mut bytes = root(false);
        put_u16(&mut bytes, 44, 0x80);
        assert!(matches!(
            parse_index_root(&bytes, NtfsIndexLimits::default()),
            Err(NtfsIndexError::InvalidEntryFlags { .. })
        ));

        let mut bytes = root(false);
        let first_length = plain_u16(&bytes, 40);
        put_u16(&mut bytes, 40, first_length + 8);
        assert!(matches!(
            parse_index_root(&bytes, NtfsIndexLimits::default()),
            Err(NtfsIndexError::NoncanonicalEntryLength { .. })
        ));
    }

    #[test]
    fn rejects_missing_or_nonterminal_end_entry() {
        let mut bytes = root(false);
        let terminal = usize::from(plain_u16(&bytes, 40));
        bytes.truncate(32 + terminal);
        let used = u32::try_from(bytes.len() - 16).unwrap();
        put_u32(&mut bytes, 20, used);
        put_u32(&mut bytes, 24, used);
        assert_eq!(
            parse_index_root(&bytes, NtfsIndexLimits::default()).unwrap_err(),
            NtfsIndexError::MissingEndEntry
        );
        let mut bytes = root(false);
        bytes.extend_from_slice(&[0; 8]);
        let used = u32::try_from(bytes.len() - 16).unwrap();
        put_u32(&mut bytes, 20, used);
        put_u32(&mut bytes, 24, used);
        assert!(matches!(
            parse_index_root(&bytes, NtfsIndexLimits::default()),
            Err(NtfsIndexError::DataAfterEndEntry { .. })
        ));
    }

    #[test]
    fn rejects_malformed_filename_keys_and_caps() {
        let mut bytes = root(false);
        bytes[32 + 16 + 65] = 9;
        assert!(matches!(
            parse_index_root(&bytes, NtfsIndexLimits::default()),
            Err(NtfsIndexError::InvalidFileNameNamespace { .. })
        ));
        let mut bytes = root(false);
        bytes[32 + 16 + 64] = 0;
        assert!(matches!(
            parse_index_root(&bytes, NtfsIndexLimits::default()),
            Err(NtfsIndexError::EmptyFileName { .. })
        ));
        let bytes = root(false);
        let limits = NtfsIndexLimits {
            max_name_code_units: 2,
            ..NtfsIndexLimits::default()
        };
        assert!(matches!(
            parse_index_root(&bytes, limits),
            Err(NtfsIndexError::FileNameTooLong {
                found: 3,
                maximum: 2,
                ..
            })
        ));
        let bytes = root(false);
        let limits = NtfsIndexLimits {
            max_entries_per_node: 1,
            ..NtfsIndexLimits::default()
        };
        assert_eq!(
            parse_index_root(&bytes, limits).unwrap_err(),
            NtfsIndexError::EntryLimitExceeded { maximum: 1 }
        );
    }

    #[test]
    fn rejects_header_child_mismatch_and_bad_sizes() {
        let mut bytes = root(true);
        bytes[28] = 0;
        assert!(matches!(
            parse_index_root(&bytes, NtfsIndexLimits::default()),
            Err(NtfsIndexError::ChildFlagMismatch { .. })
        ));
        let mut bytes = root(false);
        put_u32(&mut bytes, 24, u32::MAX);
        assert!(matches!(
            parse_index_root(&bytes, NtfsIndexLimits::default()),
            Err(NtfsIndexError::InvalidAllocatedSize { .. })
        ));
        let mut bytes = root(false);
        put_u32(&mut bytes, 16, 17);
        assert!(matches!(
            parse_index_root(&bytes, NtfsIndexLimits::default()),
            Err(NtfsIndexError::EntriesOffsetNotEightByteAligned { .. })
        ));

        let mut bytes = root(false);
        let terminal = 32 + usize::from(plain_u16(&bytes, 40));
        put_u16(
            &mut bytes,
            terminal + 12,
            INDEX_ENTRY_END | INDEX_ENTRY_NODE,
        );
        assert!(matches!(
            parse_index_root(&bytes, NtfsIndexLimits::default()),
            Err(NtfsIndexError::MissingChildVcn { .. })
        ));
    }
}
