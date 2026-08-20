//! Deterministic, bounded serialization of NTFS `$I30` directory indexes.
//!
//! This module is pure: it accepts owned metadata views and returns bytes. It performs no file,
//! image, volume, or device I/O. Small indexes remain entirely in a resident `INDEX_ROOT` value.
//! Larger indexes use a single internal resident root over MST-protected leaf `INDX` records and
//! a canonical allocation bitmap. A topology needing internal `INDX` nodes is refused.
//!
//! The structure and split rules are pinned to ntfs-3g commit
//! `d327833ec1d5eb1358b6f2c37139f10a3460944d`: `layout.h` defines the structures,
//! `unistr.c:ntfs_names_full_collate` defines filename collation, and
//! `index.c:ntfs_ir_reparent`/`ntfs_ib_split` establish child-VCN and separator semantics.
//! Microsoft documents `$I30` as filename-collated `$INDEX_ROOT`, `$INDEX_ALLOCATION`, and
//! `$BITMAP` streams; it does not publish a bulk-construction algorithm.

use std::cmp::Ordering;
use std::fmt;
use std::ops::Range;

use super::ntfs_index::{
    FILE_NAME_ATTRIBUTE_TYPE, FILE_NAME_COLLATION_RULE, FileNameNamespace, NtfsFileReference,
    NtfsIndexLimits, parse_index_block, parse_index_root,
};

const INDEX_ROOT_PREFIX_BYTES: usize = 16;
const INDEX_HEADER_BYTES: usize = 16;
const INDEX_BLOCK_HEADER_BYTES: usize = 24;
const INDEX_ENTRY_HEADER_BYTES: usize = 16;
const FILE_NAME_KEY_HEADER_BYTES: usize = 66;
const UPDATE_SEQUENCE_OFFSET: usize = 40;
const UPDATE_SEQUENCE_STRIDE: usize = 512;
const INDEX_ENTRY_NODE: u16 = 0x0001;
const INDEX_ENTRY_END: u16 = 0x0002;
const MAX_MFT_RECORD_NUMBER: u64 = 0x0000_ffff_ffff_ffff;
const FULL_UPCASE_UNITS: usize = 65_536;

/// On-disk geometry required to serialize a directory index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtfsDirectoryIndexGeometry {
    /// NTFS cluster size in bytes.
    pub cluster_bytes: u32,
    /// Size of each `INDX` record in bytes.
    pub index_block_bytes: u32,
    /// Maximum complete resident `INDEX_ROOT` value accepted by the caller's FILE layout.
    pub resident_root_bytes: usize,
}

/// Resource caps for directory-index construction and validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtfsDirectoryIndexLimits {
    /// Maximum number of non-terminal directory entries.
    pub max_entries: usize,
    /// Maximum number of emitted leaf `INDX` records.
    pub max_blocks: usize,
    /// Maximum complete resident `INDEX_ROOT` value.
    pub max_root_bytes: usize,
    /// Maximum supported `INDX` record size.
    pub max_block_bytes: usize,
    /// Maximum total `INDEX_ALLOCATION` stream bytes.
    pub max_allocation_bytes: usize,
    /// Maximum UTF-16 code units in one filename.
    pub max_name_code_units: usize,
}

impl Default for NtfsDirectoryIndexLimits {
    fn default() -> Self {
        Self {
            max_entries: 1_000_000,
            max_blocks: 65_536,
            max_root_bytes: 1024 * 1024,
            max_block_bytes: 16 * 1024 * 1024,
            max_allocation_bytes: 512 * 1024 * 1024,
            max_name_code_units: 255,
        }
    }
}

/// Complete metadata embedded in one `$I30` filename key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsDirectoryIndexEntry {
    /// Referenced child FILE record and sequence number.
    pub file_reference: NtfsFileReference,
    /// Parent directory FILE record and sequence number.
    pub parent_directory: NtfsFileReference,
    /// FILETIME creation timestamp.
    pub creation_time: u64,
    /// FILETIME last-data-modification timestamp.
    pub modification_time: u64,
    /// FILETIME last-MFT-change timestamp.
    pub mft_change_time: u64,
    /// FILETIME last-access timestamp.
    pub access_time: u64,
    /// Allocated size of the referenced unnamed data stream.
    pub allocated_size: u64,
    /// Logical size of the referenced unnamed data stream.
    pub data_size: u64,
    /// DOS/Windows file attributes.
    pub file_attributes: u32,
    /// Reparse tag or packed EA size, depending on file attributes.
    pub reparse_tag_or_ea_size: u32,
    /// Filename namespace stored in the key.
    pub namespace: FileNameNamespace,
    /// Exact UTF-16 filename code units.
    pub name: Vec<u16>,
}

/// A complete serialized `$I30` stream set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerializedNtfsDirectoryIndex {
    /// Resident `$INDEX_ROOT:$I30` value.
    pub index_root: Vec<u8>,
    /// Concatenated nonresident `$INDEX_ALLOCATION:$I30` value, or empty for a small index.
    pub index_allocation: Vec<u8>,
    /// Resident `$BITMAP:$I30` value, or empty for a small index.
    pub bitmap: Vec<u8>,
    /// Child VCN stored in each emitted `INDX` record, in stream order.
    pub block_vcns: Vec<u64>,
}

impl SerializedNtfsDirectoryIndex {
    /// Returns whether the directory uses `INDEX_ALLOCATION` leaf records.
    #[must_use]
    pub fn is_spilled(&self) -> bool {
        !self.index_allocation.is_empty()
    }
}

/// Summary returned by the independent serialized-index validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatedNtfsDirectoryIndex {
    /// Number of non-terminal keys reachable through the index.
    pub entry_count: usize,
    /// Number of allocated leaf blocks.
    pub block_count: usize,
    /// Whether the index uses allocation blocks.
    pub spilled: bool,
}

/// Reason a directory index could not be serialized or validated safely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NtfsDirectoryIndexError {
    /// The supplied `$UpCase` table was not complete.
    IncompleteUpcaseTable { actual: usize },
    /// The geometry is not the supported cluster-aligned, single-level profile.
    UnsupportedGeometry { reason: &'static str },
    /// A configured cap is internally invalid.
    InvalidLimit { field: &'static str },
    /// Too many input entries were supplied.
    EntryLimitExceeded { actual: usize, maximum: usize },
    /// A filename is empty.
    EmptyName { entry: usize },
    /// A filename exceeds the configured or on-disk limit.
    NameTooLong {
        entry: usize,
        actual: usize,
        maximum: usize,
    },
    /// A FILE reference exceeds NTFS's 48-bit record-number field.
    FileReferenceOutOfRange { entry: usize, record_number: u64 },
    /// Two entries have the same filename collation key.
    CollationCollision { first: usize, second: usize },
    /// One entry cannot fit in a leaf record.
    EntryCannotFitLeaf {
        entry: usize,
        required: usize,
        available: usize,
    },
    /// The single-level topology cannot represent this index without empty leaves.
    UnsupportedSingleLevelPartition { remaining_entries: usize },
    /// Root separators do not fit the resident budget; another tree level would be needed.
    MultiLevelTreeRequired { root_bytes: usize, maximum: usize },
    /// The requested allocation exceeds a resource cap.
    AllocationLimitExceeded { actual: usize, maximum: usize },
    /// The requested leaf count exceeds a resource cap.
    BlockLimitExceeded { actual: usize, maximum: usize },
    /// Integer conversion or arithmetic overflowed.
    ArithmeticOverflow,
    /// Heap allocation failed.
    AllocationFailed,
    /// Serialized bytes failed independent structural validation.
    Malformed {
        component: &'static str,
        reason: String,
    },
}

impl fmt::Display for NtfsDirectoryIndexError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IncompleteUpcaseTable { actual } => write!(
                formatter,
                "NTFS filename collation requires 65536 upcase entries; got {actual}"
            ),
            Self::UnsupportedGeometry { reason } => {
                write!(
                    formatter,
                    "unsupported NTFS directory-index geometry: {reason}"
                )
            }
            Self::InvalidLimit { field } => write!(formatter, "invalid index limit `{field}`"),
            Self::EntryLimitExceeded { actual, maximum } => write!(
                formatter,
                "directory has {actual} entries; configured cap is {maximum}"
            ),
            Self::EmptyName { entry } => write!(formatter, "directory entry {entry} has no name"),
            Self::NameTooLong {
                entry,
                actual,
                maximum,
            } => write!(
                formatter,
                "directory entry {entry} has {actual} UTF-16 units; maximum is {maximum}"
            ),
            Self::FileReferenceOutOfRange {
                entry,
                record_number,
            } => write!(
                formatter,
                "directory entry {entry} references out-of-range MFT record {record_number}"
            ),
            Self::CollationCollision { first, second } => write!(
                formatter,
                "directory entries {first} and {second} have the same NTFS collation key"
            ),
            Self::EntryCannotFitLeaf {
                entry,
                required,
                available,
            } => write!(
                formatter,
                "directory entry {entry} needs {required} leaf bytes; only {available} are available"
            ),
            Self::UnsupportedSingleLevelPartition { remaining_entries } => write!(
                formatter,
                "a nonempty single-level split cannot place the final {remaining_entries} entries"
            ),
            Self::MultiLevelTreeRequired {
                root_bytes,
                maximum,
            } => write!(
                formatter,
                "separator root needs {root_bytes} bytes but resident budget is {maximum}; an internal INDX level is required"
            ),
            Self::AllocationLimitExceeded { actual, maximum } => write!(
                formatter,
                "index allocation needs {actual} bytes; configured cap is {maximum}"
            ),
            Self::BlockLimitExceeded { actual, maximum } => write!(
                formatter,
                "index allocation needs {actual} blocks; configured cap is {maximum}"
            ),
            Self::ArithmeticOverflow => formatter.write_str("directory-index arithmetic overflow"),
            Self::AllocationFailed => formatter.write_str("directory-index allocation failed"),
            Self::Malformed { component, reason } => {
                write!(formatter, "malformed {component}: {reason}")
            }
        }
    }
}

impl std::error::Error for NtfsDirectoryIndexError {}

#[derive(Debug, Clone, Copy)]
struct CheckedGeometry {
    block_bytes: usize,
    clusters_per_block: u8,
    entries_offset: usize,
    leaf_entry_bytes: usize,
    root_budget: usize,
}

/// Serialize a deterministic resident or single-level spilled `$I30` directory index.
///
/// `upcase` must be the exact 65,536-entry table selected for the destination NTFS volume.
/// Input order is irrelevant. Equal filename collation keys are refused.
///
/// # Errors
/// Returns an error for invalid geometry, invalid input, cap violations, filename collisions, or
/// an index that would require more than one allocation level.
pub fn serialize_ntfs_directory_index(
    entries: &[NtfsDirectoryIndexEntry],
    upcase: &[u16],
    geometry: NtfsDirectoryIndexGeometry,
    limits: NtfsDirectoryIndexLimits,
) -> Result<SerializedNtfsDirectoryIndex, NtfsDirectoryIndexError> {
    let checked = check_inputs(entries, upcase, geometry, limits)?;
    let mut sorted: Vec<(usize, &NtfsDirectoryIndexEntry)> = entries.iter().enumerate().collect();
    sorted.sort_by(|left, right| collate_names(&left.1.name, &right.1.name, upcase));
    for pair in sorted.windows(2) {
        if collate_names(&pair[0].1.name, &pair[1].1.name, upcase) == Ordering::Equal {
            return Err(NtfsDirectoryIndexError::CollationCollision {
                first: pair[0].0,
                second: pair[1].0,
            });
        }
    }

    let resident_bytes = root_size(&sorted, false)?;
    if resident_bytes <= checked.root_budget {
        return Ok(SerializedNtfsDirectoryIndex {
            index_root: build_root(&sorted, &[], checked, false)?,
            index_allocation: Vec::new(),
            bitmap: Vec::new(),
            block_vcns: Vec::new(),
        });
    }

    for (original_position, entry) in &sorted {
        let required = serialized_entry_len(entry.name.len(), false)?
            .checked_add(INDEX_ENTRY_HEADER_BYTES)
            .ok_or(NtfsDirectoryIndexError::ArithmeticOverflow)?;
        if required > checked.leaf_entry_bytes {
            return Err(NtfsDirectoryIndexError::EntryCannotFitLeaf {
                entry: *original_position,
                required,
                available: checked.leaf_entry_bytes,
            });
        }
    }

    let (leaf_ranges, separators) = partition_leaves(&sorted, checked)?;
    let root_bytes = root_size_for_separators(&sorted, &separators)?;
    if root_bytes > checked.root_budget {
        return Err(NtfsDirectoryIndexError::MultiLevelTreeRequired {
            root_bytes,
            maximum: checked.root_budget,
        });
    }
    if leaf_ranges.len() > limits.max_blocks {
        return Err(NtfsDirectoryIndexError::BlockLimitExceeded {
            actual: leaf_ranges.len(),
            maximum: limits.max_blocks,
        });
    }
    let allocation_bytes = checked
        .block_bytes
        .checked_mul(leaf_ranges.len())
        .ok_or(NtfsDirectoryIndexError::ArithmeticOverflow)?;
    if allocation_bytes > limits.max_allocation_bytes {
        return Err(NtfsDirectoryIndexError::AllocationLimitExceeded {
            actual: allocation_bytes,
            maximum: limits.max_allocation_bytes,
        });
    }

    let block_vcns = block_vcns(leaf_ranges.len(), checked.clusters_per_block)?;
    let mut index_allocation = Vec::new();
    index_allocation
        .try_reserve_exact(allocation_bytes)
        .map_err(|_| NtfsDirectoryIndexError::AllocationFailed)?;
    for (block_number, range) in leaf_ranges.iter().enumerate() {
        index_allocation.extend_from_slice(&build_leaf_block(
            &sorted[range.clone()],
            block_vcns[block_number],
            block_number,
            checked,
        )?);
    }
    let bitmap = build_bitmap(leaf_ranges.len())?;
    let index_root = build_root(&sorted, &separators, checked, true)?;
    Ok(SerializedNtfsDirectoryIndex {
        index_root,
        index_allocation,
        bitmap,
        block_vcns,
    })
}

/// Independently validate a complete serialized `$I30` stream set.
///
/// The validator parses MST records through [`super::ntfs_index`], checks canonical geometry and
/// bitmap bytes, walks the root/leaf topology in key order, and re-runs destination `$UpCase`
/// collation across every reachable key.
///
/// # Errors
/// Returns an error for malformed structures, noncanonical child VCNs, unreachable blocks,
/// invalid bitmap bits, ordering violations, or configured cap violations.
pub fn validate_serialized_ntfs_directory_index(
    serialized: &SerializedNtfsDirectoryIndex,
    upcase: &[u16],
    geometry: NtfsDirectoryIndexGeometry,
    limits: NtfsDirectoryIndexLimits,
) -> Result<ValidatedNtfsDirectoryIndex, NtfsDirectoryIndexError> {
    let checked = check_geometry(upcase, geometry, limits)?;
    if serialized.index_root.len() > checked.root_budget {
        return malformed("INDEX_ROOT", "resident value exceeds its configured budget");
    }
    let parser_limits = NtfsIndexLimits {
        max_root_bytes: limits.max_root_bytes,
        max_block_bytes: limits.max_block_bytes,
        max_entries_per_node: limits.max_entries.saturating_add(1),
        max_name_code_units: limits.max_name_code_units,
    };
    let root = parse_index_root(&serialized.index_root, parser_limits)
        .map_err(|error| malformed_error("INDEX_ROOT", error.to_string()))?;
    if root.index_block_size != geometry.index_block_bytes
        || root.clusters_per_index_block != i8::try_from(checked.clusters_per_block).unwrap_or(-1)
        || root.header.allocated_size != root.header.index_length
    {
        return malformed("INDEX_ROOT", "noncanonical geometry or allocation length");
    }
    let root_used = INDEX_ROOT_PREFIX_BYTES
        .checked_add(
            usize::try_from(root.header.index_length)
                .map_err(|_| NtfsDirectoryIndexError::ArithmeticOverflow)?,
        )
        .ok_or(NtfsDirectoryIndexError::ArithmeticOverflow)?;
    if root_used != serialized.index_root.len() {
        return malformed("INDEX_ROOT", "trailing bytes follow the used root value");
    }

    if !root.header.has_children {
        if !serialized.index_allocation.is_empty()
            || !serialized.bitmap.is_empty()
            || !serialized.block_vcns.is_empty()
        {
            return malformed("small index", "unexpected allocation streams or VCNs");
        }
        let names = collect_leaf_names(root.entries(), "INDEX_ROOT")?;
        validate_name_order(&names, upcase)?;
        if names.len() > limits.max_entries {
            return Err(NtfsDirectoryIndexError::EntryLimitExceeded {
                actual: names.len(),
                maximum: limits.max_entries,
            });
        }
        return Ok(ValidatedNtfsDirectoryIndex {
            entry_count: names.len(),
            block_count: 0,
            spilled: false,
        });
    }

    validate_spilled(serialized, &root, upcase, checked, limits, parser_limits)
}

fn validate_spilled(
    serialized: &SerializedNtfsDirectoryIndex,
    root: &super::ntfs_index::NtfsIndexRoot<'_>,
    upcase: &[u16],
    checked: CheckedGeometry,
    limits: NtfsDirectoryIndexLimits,
    parser_limits: NtfsIndexLimits,
) -> Result<ValidatedNtfsDirectoryIndex, NtfsDirectoryIndexError> {
    if serialized.index_allocation.is_empty()
        || serialized.index_allocation.len() % checked.block_bytes != 0
    {
        return malformed(
            "INDEX_ALLOCATION",
            "length is not a positive whole block count",
        );
    }
    let block_count = serialized.index_allocation.len() / checked.block_bytes;
    if block_count > limits.max_blocks {
        return Err(NtfsDirectoryIndexError::BlockLimitExceeded {
            actual: block_count,
            maximum: limits.max_blocks,
        });
    }
    if serialized.index_allocation.len() > limits.max_allocation_bytes {
        return Err(NtfsDirectoryIndexError::AllocationLimitExceeded {
            actual: serialized.index_allocation.len(),
            maximum: limits.max_allocation_bytes,
        });
    }
    let expected_vcns = block_vcns(block_count, checked.clusters_per_block)?;
    if serialized.block_vcns != expected_vcns {
        return malformed("INDEX_ALLOCATION", "noncanonical block VCN list");
    }
    if serialized.bitmap != build_bitmap(block_count)? {
        return malformed("BITMAP", "noncanonical allocation bits or padding");
    }

    let root_entries: Vec<_> = root.entries().collect();
    if root_entries.len() != block_count {
        return malformed(
            "INDEX_ROOT",
            "child count does not match allocated leaf count",
        );
    }
    let mut ordered_names = Vec::new();
    for block_number in 0..block_count {
        let root_entry = root_entries[block_number];
        if root_entry.child_vcn != Some(expected_vcns[block_number]) {
            return malformed("INDEX_ROOT", "child VCN is not in canonical stream order");
        }
        let start = block_number
            .checked_mul(checked.block_bytes)
            .ok_or(NtfsDirectoryIndexError::ArithmeticOverflow)?;
        let end = start
            .checked_add(checked.block_bytes)
            .ok_or(NtfsDirectoryIndexError::ArithmeticOverflow)?;
        let block = parse_index_block(
            &serialized.index_allocation[start..end],
            Some(expected_vcns[block_number]),
            parser_limits,
        )
        .map_err(|error| malformed_error("INDEX_ALLOCATION", error.to_string()))?;
        if block.header.has_children
            || block.log_file_sequence_number != 0
            || usize::from(block.update_sequence_offset) != UPDATE_SEQUENCE_OFFSET
            || usize::try_from(block.header.entries_offset).unwrap_or(usize::MAX)
                != checked.entries_offset - INDEX_BLOCK_HEADER_BYTES
            || usize::try_from(block.header.allocated_size).unwrap_or(usize::MAX)
                != checked.block_bytes - INDEX_BLOCK_HEADER_BYTES
        {
            return malformed("INDEX_ALLOCATION", "noncanonical leaf header");
        }
        if read_u16(
            &serialized.index_allocation[start..end],
            UPDATE_SEQUENCE_OFFSET,
        )? != update_sequence_number(block_number)?
        {
            return malformed("INDEX_ALLOCATION", "noncanonical update-sequence number");
        }
        ordered_names.extend(collect_leaf_names(block.entries(), "INDEX_ALLOCATION")?);
        if !root_entry.is_end {
            let key = root_entry.file_name.ok_or_else(|| {
                malformed_error("INDEX_ROOT", "separator has no filename key".to_owned())
            })?;
            ordered_names.push(key.name.code_units().collect());
        } else if block_number + 1 != block_count {
            return malformed("INDEX_ROOT", "terminal child precedes another child");
        }
    }
    if !root_entries.last().is_some_and(|entry| entry.is_end) {
        return malformed("INDEX_ROOT", "final child is not the terminal entry");
    }
    validate_name_order(&ordered_names, upcase)?;
    if ordered_names.len() > limits.max_entries {
        return Err(NtfsDirectoryIndexError::EntryLimitExceeded {
            actual: ordered_names.len(),
            maximum: limits.max_entries,
        });
    }
    Ok(ValidatedNtfsDirectoryIndex {
        entry_count: ordered_names.len(),
        block_count,
        spilled: true,
    })
}

fn check_inputs(
    entries: &[NtfsDirectoryIndexEntry],
    upcase: &[u16],
    geometry: NtfsDirectoryIndexGeometry,
    limits: NtfsDirectoryIndexLimits,
) -> Result<CheckedGeometry, NtfsDirectoryIndexError> {
    let checked = check_geometry(upcase, geometry, limits)?;
    if entries.len() > limits.max_entries {
        return Err(NtfsDirectoryIndexError::EntryLimitExceeded {
            actual: entries.len(),
            maximum: limits.max_entries,
        });
    }
    let maximum_name = limits.max_name_code_units.min(255);
    for (position, entry) in entries.iter().enumerate() {
        if entry.name.is_empty() {
            return Err(NtfsDirectoryIndexError::EmptyName { entry: position });
        }
        if entry.name.len() > maximum_name {
            return Err(NtfsDirectoryIndexError::NameTooLong {
                entry: position,
                actual: entry.name.len(),
                maximum: maximum_name,
            });
        }
        for reference in [entry.file_reference, entry.parent_directory] {
            if reference.record_number > MAX_MFT_RECORD_NUMBER {
                return Err(NtfsDirectoryIndexError::FileReferenceOutOfRange {
                    entry: position,
                    record_number: reference.record_number,
                });
            }
        }
    }
    Ok(checked)
}

fn check_geometry(
    upcase: &[u16],
    geometry: NtfsDirectoryIndexGeometry,
    limits: NtfsDirectoryIndexLimits,
) -> Result<CheckedGeometry, NtfsDirectoryIndexError> {
    if upcase.len() != FULL_UPCASE_UNITS {
        return Err(NtfsDirectoryIndexError::IncompleteUpcaseTable {
            actual: upcase.len(),
        });
    }
    if limits.max_entries == 0 {
        return Err(NtfsDirectoryIndexError::InvalidLimit {
            field: "max_entries",
        });
    }
    if limits.max_blocks == 0 {
        return Err(NtfsDirectoryIndexError::InvalidLimit {
            field: "max_blocks",
        });
    }
    if limits.max_name_code_units == 0 {
        return Err(NtfsDirectoryIndexError::InvalidLimit {
            field: "max_name_code_units",
        });
    }
    let block_bytes = usize::try_from(geometry.index_block_bytes)
        .map_err(|_| NtfsDirectoryIndexError::ArithmeticOverflow)?;
    let cluster_bytes = usize::try_from(geometry.cluster_bytes)
        .map_err(|_| NtfsDirectoryIndexError::ArithmeticOverflow)?;
    if cluster_bytes < UPDATE_SEQUENCE_STRIDE || !cluster_bytes.is_power_of_two() {
        return Err(NtfsDirectoryIndexError::UnsupportedGeometry {
            reason: "cluster size must be a power of two of at least 512 bytes",
        });
    }
    if block_bytes < cluster_bytes
        || !block_bytes.is_power_of_two()
        || block_bytes % cluster_bytes != 0
        || block_bytes % UPDATE_SEQUENCE_STRIDE != 0
    {
        return Err(NtfsDirectoryIndexError::UnsupportedGeometry {
            reason: "index blocks must be power-of-two, cluster-aligned, and at least one cluster",
        });
    }
    if block_bytes > limits.max_block_bytes {
        return Err(NtfsDirectoryIndexError::UnsupportedGeometry {
            reason: "index block exceeds the configured block-size cap",
        });
    }
    let clusters_per_block = block_bytes / cluster_bytes;
    let clusters_per_block = u8::try_from(clusters_per_block).map_err(|_| {
        NtfsDirectoryIndexError::UnsupportedGeometry {
            reason: "clusters per index block do not fit the supported positive root field",
        }
    })?;
    if clusters_per_block == 0 || clusters_per_block > u8::try_from(i8::MAX).unwrap_or(u8::MAX) {
        return Err(NtfsDirectoryIndexError::UnsupportedGeometry {
            reason: "clusters per index block must fit a positive signed byte",
        });
    }
    let sector_count = block_bytes / UPDATE_SEQUENCE_STRIDE;
    let usa_bytes = sector_count
        .checked_add(1)
        .and_then(|count| count.checked_mul(2))
        .ok_or(NtfsDirectoryIndexError::ArithmeticOverflow)?;
    let usa_end = UPDATE_SEQUENCE_OFFSET
        .checked_add(usa_bytes)
        .ok_or(NtfsDirectoryIndexError::ArithmeticOverflow)?;
    if usa_end > UPDATE_SEQUENCE_STRIDE - 2 {
        return Err(NtfsDirectoryIndexError::UnsupportedGeometry {
            reason: "update-sequence array does not fit before the first sector trailer",
        });
    }
    let entries_offset = align_eight(usa_end)?;
    let leaf_entry_bytes = block_bytes.checked_sub(entries_offset).ok_or(
        NtfsDirectoryIndexError::UnsupportedGeometry {
            reason: "index block has no room for entries",
        },
    )?;
    if leaf_entry_bytes < INDEX_ENTRY_HEADER_BYTES {
        return Err(NtfsDirectoryIndexError::UnsupportedGeometry {
            reason: "index block has no room for a terminal entry",
        });
    }
    let root_budget = geometry.resident_root_bytes.min(limits.max_root_bytes);
    if root_budget < INDEX_ROOT_PREFIX_BYTES + INDEX_HEADER_BYTES + INDEX_ENTRY_HEADER_BYTES {
        return Err(NtfsDirectoryIndexError::UnsupportedGeometry {
            reason: "resident root budget cannot hold an empty small index",
        });
    }
    Ok(CheckedGeometry {
        block_bytes,
        clusters_per_block,
        entries_offset,
        leaf_entry_bytes,
        root_budget,
    })
}

fn partition_leaves(
    sorted: &[(usize, &NtfsDirectoryIndexEntry)],
    checked: CheckedGeometry,
) -> Result<(Vec<Range<usize>>, Vec<usize>), NtfsDirectoryIndexError> {
    let payload_capacity = checked
        .leaf_entry_bytes
        .checked_sub(INDEX_ENTRY_HEADER_BYTES)
        .ok_or(NtfsDirectoryIndexError::ArithmeticOverflow)?;
    let mut ranges = Vec::new();
    let mut separators = Vec::new();
    let mut cursor = 0;
    while cursor < sorted.len() {
        let mut end = cursor;
        let mut used = 0_usize;
        while end < sorted.len() {
            let size = serialized_entry_len(sorted[end].1.name.len(), false)?;
            if used
                .checked_add(size)
                .is_none_or(|next| next > payload_capacity)
            {
                break;
            }
            used += size;
            end += 1;
        }
        if end == sorted.len() {
            ranges.push(cursor..end);
            break;
        }
        let maximum_group = sorted.len().saturating_sub(cursor).saturating_sub(2);
        end = end.min(cursor + maximum_group);
        if end == cursor {
            return Err(NtfsDirectoryIndexError::UnsupportedSingleLevelPartition {
                remaining_entries: sorted.len() - cursor,
            });
        }
        ranges.push(cursor..end);
        separators.push(end);
        cursor = end + 1;
    }
    if ranges.len() != separators.len() + 1 || ranges.iter().any(Range::is_empty) {
        return Err(NtfsDirectoryIndexError::UnsupportedSingleLevelPartition {
            remaining_entries: sorted.len().saturating_sub(cursor),
        });
    }
    Ok((ranges, separators))
}

fn root_size(
    entries: &[(usize, &NtfsDirectoryIndexEntry)],
    children: bool,
) -> Result<usize, NtfsDirectoryIndexError> {
    let mut bytes = INDEX_ROOT_PREFIX_BYTES + INDEX_HEADER_BYTES;
    for (_, entry) in entries {
        bytes = bytes
            .checked_add(serialized_entry_len(entry.name.len(), children)?)
            .ok_or(NtfsDirectoryIndexError::ArithmeticOverflow)?;
    }
    bytes
        .checked_add(serialized_terminal_len(children))
        .ok_or(NtfsDirectoryIndexError::ArithmeticOverflow)
}

fn root_size_for_separators(
    entries: &[(usize, &NtfsDirectoryIndexEntry)],
    separators: &[usize],
) -> Result<usize, NtfsDirectoryIndexError> {
    let selected: Vec<_> = separators
        .iter()
        .map(|position| entries[*position])
        .collect();
    root_size(&selected, true)
}

fn build_root(
    sorted: &[(usize, &NtfsDirectoryIndexEntry)],
    separators: &[usize],
    checked: CheckedGeometry,
    children: bool,
) -> Result<Vec<u8>, NtfsDirectoryIndexError> {
    let selected: Vec<_> = if children {
        separators
            .iter()
            .map(|position| sorted[*position])
            .collect()
    } else {
        sorted.to_vec()
    };
    let size = root_size(&selected, children)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .map_err(|_| NtfsDirectoryIndexError::AllocationFailed)?;
    bytes.resize(INDEX_ROOT_PREFIX_BYTES + INDEX_HEADER_BYTES, 0);
    put_u32(&mut bytes, 0, FILE_NAME_ATTRIBUTE_TYPE)?;
    put_u32(&mut bytes, 4, FILE_NAME_COLLATION_RULE)?;
    put_u32(
        &mut bytes,
        8,
        u32::try_from(checked.block_bytes)
            .map_err(|_| NtfsDirectoryIndexError::ArithmeticOverflow)?,
    )?;
    bytes[12] = checked.clusters_per_block;
    for (child_number, (_, entry)) in selected.iter().enumerate() {
        let child_vcn = children
            .then(|| child_vcn(child_number, checked.clusters_per_block))
            .transpose()?;
        append_entry(&mut bytes, entry, child_vcn, false)?;
    }
    let terminal_vcn = children
        .then(|| child_vcn(selected.len(), checked.clusters_per_block))
        .transpose()?;
    append_terminal(&mut bytes, terminal_vcn)?;
    let used = bytes
        .len()
        .checked_sub(INDEX_ROOT_PREFIX_BYTES)
        .ok_or(NtfsDirectoryIndexError::ArithmeticOverflow)?;
    put_u32(&mut bytes, INDEX_ROOT_PREFIX_BYTES, 16)?;
    put_u32(
        &mut bytes,
        INDEX_ROOT_PREFIX_BYTES + 4,
        u32::try_from(used).map_err(|_| NtfsDirectoryIndexError::ArithmeticOverflow)?,
    )?;
    put_u32(
        &mut bytes,
        INDEX_ROOT_PREFIX_BYTES + 8,
        u32::try_from(used).map_err(|_| NtfsDirectoryIndexError::ArithmeticOverflow)?,
    )?;
    bytes[INDEX_ROOT_PREFIX_BYTES + 12] = u8::from(children);
    Ok(bytes)
}

fn build_leaf_block(
    entries: &[(usize, &NtfsDirectoryIndexEntry)],
    vcn: u64,
    block_number: usize,
    checked: CheckedGeometry,
) -> Result<Vec<u8>, NtfsDirectoryIndexError> {
    let sector_count = checked.block_bytes / UPDATE_SEQUENCE_STRIDE;
    let usa_count = sector_count
        .checked_add(1)
        .ok_or(NtfsDirectoryIndexError::ArithmeticOverflow)?;
    let mut bytes = vec![0_u8; checked.block_bytes];
    bytes[..4].copy_from_slice(b"INDX");
    put_u16(
        &mut bytes,
        4,
        u16::try_from(UPDATE_SEQUENCE_OFFSET)
            .map_err(|_| NtfsDirectoryIndexError::ArithmeticOverflow)?,
    )?;
    put_u16(
        &mut bytes,
        6,
        u16::try_from(usa_count).map_err(|_| NtfsDirectoryIndexError::ArithmeticOverflow)?,
    )?;
    put_u64(&mut bytes, 16, vcn)?;

    let mut encoded_entries = Vec::new();
    for (_, entry) in entries {
        append_entry(&mut encoded_entries, entry, None, false)?;
    }
    append_terminal(&mut encoded_entries, None)?;
    let used_end = checked
        .entries_offset
        .checked_add(encoded_entries.len())
        .ok_or(NtfsDirectoryIndexError::ArithmeticOverflow)?;
    if used_end > checked.block_bytes {
        return malformed("INDEX_ALLOCATION", "leaf entries exceed their block");
    }
    bytes[checked.entries_offset..used_end].copy_from_slice(&encoded_entries);
    put_u32(
        &mut bytes,
        INDEX_BLOCK_HEADER_BYTES,
        u32::try_from(checked.entries_offset - INDEX_BLOCK_HEADER_BYTES)
            .map_err(|_| NtfsDirectoryIndexError::ArithmeticOverflow)?,
    )?;
    put_u32(
        &mut bytes,
        INDEX_BLOCK_HEADER_BYTES + 4,
        u32::try_from(used_end - INDEX_BLOCK_HEADER_BYTES)
            .map_err(|_| NtfsDirectoryIndexError::ArithmeticOverflow)?,
    )?;
    put_u32(
        &mut bytes,
        INDEX_BLOCK_HEADER_BYTES + 8,
        u32::try_from(checked.block_bytes - INDEX_BLOCK_HEADER_BYTES)
            .map_err(|_| NtfsDirectoryIndexError::ArithmeticOverflow)?,
    )?;

    let usn = update_sequence_number(block_number)?;
    put_u16(&mut bytes, UPDATE_SEQUENCE_OFFSET, usn)?;
    for sector in 0..sector_count {
        let trailer = (sector + 1) * UPDATE_SEQUENCE_STRIDE - 2;
        let original = read_u16(&bytes, trailer)?;
        put_u16(
            &mut bytes,
            UPDATE_SEQUENCE_OFFSET + 2 + sector * 2,
            original,
        )?;
        put_u16(&mut bytes, trailer, usn)?;
    }
    Ok(bytes)
}

fn append_entry(
    output: &mut Vec<u8>,
    entry: &NtfsDirectoryIndexEntry,
    child_vcn: Option<u64>,
    end: bool,
) -> Result<(), NtfsDirectoryIndexError> {
    let key = encode_file_name_key(entry)?;
    let length = serialized_entry_len(entry.name.len(), child_vcn.is_some())?;
    let start = output.len();
    let new_len = start
        .checked_add(length)
        .ok_or(NtfsDirectoryIndexError::ArithmeticOverflow)?;
    output
        .try_reserve_exact(length)
        .map_err(|_| NtfsDirectoryIndexError::AllocationFailed)?;
    output.resize(new_len, 0);
    put_u64(output, start, encode_reference(entry.file_reference)?)?;
    put_u16(
        output,
        start + 8,
        u16::try_from(length).map_err(|_| NtfsDirectoryIndexError::ArithmeticOverflow)?,
    )?;
    put_u16(
        output,
        start + 10,
        u16::try_from(key.len()).map_err(|_| NtfsDirectoryIndexError::ArithmeticOverflow)?,
    )?;
    let flags =
        (u16::from(child_vcn.is_some()) * INDEX_ENTRY_NODE) | (u16::from(end) * INDEX_ENTRY_END);
    put_u16(output, start + 12, flags)?;
    output[start + INDEX_ENTRY_HEADER_BYTES..start + INDEX_ENTRY_HEADER_BYTES + key.len()]
        .copy_from_slice(&key);
    if let Some(vcn) = child_vcn {
        put_u64(output, start + length - 8, vcn)?;
    }
    Ok(())
}

fn append_terminal(
    output: &mut Vec<u8>,
    child_vcn: Option<u64>,
) -> Result<(), NtfsDirectoryIndexError> {
    let length = serialized_terminal_len(child_vcn.is_some());
    let start = output.len();
    output
        .try_reserve_exact(length)
        .map_err(|_| NtfsDirectoryIndexError::AllocationFailed)?;
    output.resize(
        start
            .checked_add(length)
            .ok_or(NtfsDirectoryIndexError::ArithmeticOverflow)?,
        0,
    );
    put_u16(
        output,
        start + 8,
        u16::try_from(length).map_err(|_| NtfsDirectoryIndexError::ArithmeticOverflow)?,
    )?;
    let flags = INDEX_ENTRY_END | (u16::from(child_vcn.is_some()) * INDEX_ENTRY_NODE);
    put_u16(output, start + 12, flags)?;
    if let Some(vcn) = child_vcn {
        put_u64(output, start + length - 8, vcn)?;
    }
    Ok(())
}

fn encode_file_name_key(
    entry: &NtfsDirectoryIndexEntry,
) -> Result<Vec<u8>, NtfsDirectoryIndexError> {
    let name_bytes = entry
        .name
        .len()
        .checked_mul(2)
        .ok_or(NtfsDirectoryIndexError::ArithmeticOverflow)?;
    let key_bytes = FILE_NAME_KEY_HEADER_BYTES
        .checked_add(name_bytes)
        .ok_or(NtfsDirectoryIndexError::ArithmeticOverflow)?;
    let mut key = vec![0_u8; key_bytes];
    put_u64(&mut key, 0, encode_reference(entry.parent_directory)?)?;
    put_u64(&mut key, 8, entry.creation_time)?;
    put_u64(&mut key, 16, entry.modification_time)?;
    put_u64(&mut key, 24, entry.mft_change_time)?;
    put_u64(&mut key, 32, entry.access_time)?;
    put_u64(&mut key, 40, entry.allocated_size)?;
    put_u64(&mut key, 48, entry.data_size)?;
    put_u32(&mut key, 56, entry.file_attributes)?;
    put_u32(&mut key, 60, entry.reparse_tag_or_ea_size)?;
    key[64] =
        u8::try_from(entry.name.len()).map_err(|_| NtfsDirectoryIndexError::ArithmeticOverflow)?;
    key[65] = namespace_byte(entry.namespace);
    for (position, unit) in entry.name.iter().copied().enumerate() {
        put_u16(&mut key, FILE_NAME_KEY_HEADER_BYTES + position * 2, unit)?;
    }
    Ok(key)
}

const fn namespace_byte(namespace: FileNameNamespace) -> u8 {
    match namespace {
        FileNameNamespace::Posix => 0,
        FileNameNamespace::Win32 => 1,
        FileNameNamespace::Dos => 2,
        FileNameNamespace::Win32AndDos => 3,
    }
}

fn serialized_entry_len(name_units: usize, child: bool) -> Result<usize, NtfsDirectoryIndexError> {
    let name_bytes = name_units
        .checked_mul(2)
        .ok_or(NtfsDirectoryIndexError::ArithmeticOverflow)?;
    let child_bytes = usize::from(child) * 8;
    INDEX_ENTRY_HEADER_BYTES
        .checked_add(FILE_NAME_KEY_HEADER_BYTES)
        .and_then(|bytes| bytes.checked_add(name_bytes))
        .and_then(|bytes| bytes.checked_add(child_bytes))
        .ok_or(NtfsDirectoryIndexError::ArithmeticOverflow)
        .and_then(align_eight)
}

const fn serialized_terminal_len(child: bool) -> usize {
    INDEX_ENTRY_HEADER_BYTES + if child { 8 } else { 0 }
}

fn collate_names(left: &[u16], right: &[u16], upcase: &[u16]) -> Ordering {
    let common = left.len().min(right.len());
    let first_raw_difference = (0..common).find(|position| left[*position] != right[*position]);
    for position in 0..common {
        let ordering =
            upcase[usize::from(left[position])].cmp(&upcase[usize::from(right[position])]);
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    left.len().cmp(&right.len()).then_with(|| {
        first_raw_difference.map_or(Ordering::Equal, |position| {
            left[position].cmp(&right[position])
        })
    })
}

fn collect_leaf_names<'a>(
    entries: impl Iterator<Item = super::ntfs_index::NtfsIndexEntry<'a>>,
    component: &'static str,
) -> Result<Vec<Vec<u16>>, NtfsDirectoryIndexError> {
    let mut names = Vec::new();
    for entry in entries {
        if entry.is_end {
            continue;
        }
        if entry.has_child {
            return malformed(component, "leaf entry unexpectedly has a child VCN");
        }
        let key = entry.file_name.ok_or_else(|| {
            malformed_error(
                component,
                "nonterminal entry has no filename key".to_owned(),
            )
        })?;
        names.push(key.name.code_units().collect());
    }
    Ok(names)
}

fn validate_name_order(names: &[Vec<u16>], upcase: &[u16]) -> Result<(), NtfsDirectoryIndexError> {
    for pair in names.windows(2) {
        if collate_names(&pair[0], &pair[1], upcase) != Ordering::Less {
            return malformed(
                "index ordering",
                "keys are not in strict filename collation order",
            );
        }
    }
    Ok(())
}

fn block_vcns(count: usize, clusters_per_block: u8) -> Result<Vec<u64>, NtfsDirectoryIndexError> {
    let mut vcns = Vec::new();
    vcns.try_reserve_exact(count)
        .map_err(|_| NtfsDirectoryIndexError::AllocationFailed)?;
    for block in 0..count {
        vcns.push(child_vcn(block, clusters_per_block)?);
    }
    Ok(vcns)
}

fn child_vcn(block_number: usize, clusters_per_block: u8) -> Result<u64, NtfsDirectoryIndexError> {
    u64::try_from(block_number)
        .ok()
        .and_then(|block| block.checked_mul(u64::from(clusters_per_block)))
        .ok_or(NtfsDirectoryIndexError::ArithmeticOverflow)
}

fn build_bitmap(block_count: usize) -> Result<Vec<u8>, NtfsDirectoryIndexError> {
    let unaligned = block_count
        .checked_add(7)
        .ok_or(NtfsDirectoryIndexError::ArithmeticOverflow)?
        / 8;
    let byte_count = align_eight(unaligned)?;
    let mut bitmap = vec![0_u8; byte_count];
    for block in 0..block_count {
        bitmap[block / 8] |= 1_u8 << (block % 8);
    }
    Ok(bitmap)
}

fn update_sequence_number(block_number: usize) -> Result<u16, NtfsDirectoryIndexError> {
    let cycle = u16::try_from(block_number % 0x5ffe)
        .map_err(|_| NtfsDirectoryIndexError::ArithmeticOverflow)?;
    Ok(0xa000_u16.wrapping_add(cycle))
}

fn encode_reference(reference: NtfsFileReference) -> Result<u64, NtfsDirectoryIndexError> {
    if reference.record_number > MAX_MFT_RECORD_NUMBER {
        return Err(NtfsDirectoryIndexError::ArithmeticOverflow);
    }
    Ok(reference.record_number | (u64::from(reference.sequence_number) << 48))
}

fn align_eight(value: usize) -> Result<usize, NtfsDirectoryIndexError> {
    value
        .checked_add(7)
        .map(|bytes| bytes & !7)
        .ok_or(NtfsDirectoryIndexError::ArithmeticOverflow)
}

fn malformed<T>(component: &'static str, reason: &str) -> Result<T, NtfsDirectoryIndexError> {
    Err(malformed_error(component, reason.to_owned()))
}

const fn malformed_error(component: &'static str, reason: String) -> NtfsDirectoryIndexError {
    NtfsDirectoryIndexError::Malformed { component, reason }
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, NtfsDirectoryIndexError> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or(NtfsDirectoryIndexError::ArithmeticOverflow)?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) -> Result<(), NtfsDirectoryIndexError> {
    let target = bytes
        .get_mut(offset..offset + 2)
        .ok_or(NtfsDirectoryIndexError::ArithmeticOverflow)?;
    target.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) -> Result<(), NtfsDirectoryIndexError> {
    let target = bytes
        .get_mut(offset..offset + 4)
        .ok_or(NtfsDirectoryIndexError::ArithmeticOverflow)?;
    target.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) -> Result<(), NtfsDirectoryIndexError> {
    let target = bytes
        .get_mut(offset..offset + 8)
        .ok_or(NtfsDirectoryIndexError::ArithmeticOverflow)?;
    target.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upcase() -> Vec<u16> {
        let mut table: Vec<u16> = (u16::MIN..=u16::MAX).collect();
        for lower in b'a'..=b'z' {
            table[usize::from(lower)] = u16::from(lower.to_ascii_uppercase());
        }
        let lower_e_acute = u16::try_from(u32::from('é')).unwrap();
        let upper_e_acute = u16::try_from(u32::from('É')).unwrap();
        table[usize::from(lower_e_acute)] = upper_e_acute;
        table
    }

    const fn geometry(root_bytes: usize) -> NtfsDirectoryIndexGeometry {
        NtfsDirectoryIndexGeometry {
            cluster_bytes: 512,
            index_block_bytes: 512,
            resident_root_bytes: root_bytes,
        }
    }

    fn entry(name: &str, record_number: u64) -> NtfsDirectoryIndexEntry {
        NtfsDirectoryIndexEntry {
            file_reference: NtfsFileReference {
                record_number,
                sequence_number: 7,
            },
            parent_directory: NtfsFileReference {
                record_number: 5,
                sequence_number: 5,
            },
            creation_time: 1,
            modification_time: 2,
            mft_change_time: 3,
            access_time: 4,
            allocated_size: 4096,
            data_size: 17,
            file_attributes: 0x20,
            reparse_tag_or_ea_size: 0,
            namespace: FileNameNamespace::Win32,
            name: name.encode_utf16().collect(),
        }
    }

    fn entries(count: usize) -> Vec<NtfsDirectoryIndexEntry> {
        (0..count)
            .map(|position| {
                entry(
                    &format!("entry-{position:04}-with-a-deterministic-name"),
                    u64::try_from(position + 24).unwrap(),
                )
            })
            .collect()
    }

    #[test]
    fn resident_boundary_and_exact_metadata_round_trip() {
        let table = upcase();
        let input = vec![entry("zeta", 30), entry("Alpha", 29), entry("beta", 31)];
        let roomy = serialize_ntfs_directory_index(
            &input,
            &table,
            geometry(4096),
            NtfsDirectoryIndexLimits::default(),
        )
        .unwrap();
        assert!(!roomy.is_spilled());
        let exact = roomy.index_root.len();
        let boundary = serialize_ntfs_directory_index(
            &input,
            &table,
            geometry(exact),
            NtfsDirectoryIndexLimits::default(),
        )
        .unwrap();
        assert_eq!(roomy, boundary);
        let parsed = parse_index_root(&roomy.index_root, NtfsIndexLimits::default()).unwrap();
        let first = parsed.entries().next().unwrap().file_name.unwrap();
        assert_eq!(
            first.name.code_units().collect::<Vec<_>>(),
            "Alpha".encode_utf16().collect::<Vec<_>>()
        );
        assert_eq!(first.creation_time, 1);
        assert_eq!(first.data_size, 17);
        assert_eq!(
            validate_serialized_ntfs_directory_index(
                &roomy,
                &table,
                geometry(exact),
                NtfsDirectoryIndexLimits::default(),
            )
            .unwrap(),
            ValidatedNtfsDirectoryIndex {
                entry_count: 3,
                block_count: 0,
                spilled: false,
            }
        );
    }

    #[test]
    fn one_byte_below_resident_boundary_spills() {
        let table = upcase();
        let input = entries(3);
        let small = serialize_ntfs_directory_index(
            &input,
            &table,
            geometry(4096),
            NtfsDirectoryIndexLimits::default(),
        )
        .unwrap();
        let spill = serialize_ntfs_directory_index(
            &input,
            &table,
            geometry(small.index_root.len() - 1),
            NtfsDirectoryIndexLimits::default(),
        )
        .unwrap();
        assert!(spill.is_spilled());
        assert!(!spill.block_vcns.is_empty());
        validate_serialized_ntfs_directory_index(
            &spill,
            &table,
            geometry(small.index_root.len() - 1),
            NtfsDirectoryIndexLimits::default(),
        )
        .unwrap();
    }

    #[test]
    fn spill_crosses_multiple_leaf_and_bitmap_transitions() {
        let table = upcase();
        let input = entries(200);
        let serialized = serialize_ntfs_directory_index(
            &input,
            &table,
            geometry(16_384),
            NtfsDirectoryIndexLimits::default(),
        )
        .unwrap();
        assert!(serialized.block_vcns.len() > 64);
        assert_eq!(serialized.bitmap.len(), 16);
        let validated = validate_serialized_ntfs_directory_index(
            &serialized,
            &table,
            geometry(16_384),
            NtfsDirectoryIndexLimits::default(),
        )
        .unwrap();
        assert_eq!(validated.entry_count, 200);
        assert_eq!(validated.block_count, serialized.block_vcns.len());
    }

    #[test]
    fn child_vcns_advance_by_clusters_per_block() {
        let table = upcase();
        let input = entries(100);
        let two_cluster_blocks = NtfsDirectoryIndexGeometry {
            cluster_bytes: 512,
            index_block_bytes: 1024,
            resident_root_bytes: 4096,
        };
        let serialized = serialize_ntfs_directory_index(
            &input,
            &table,
            two_cluster_blocks,
            NtfsDirectoryIndexLimits::default(),
        )
        .unwrap();
        assert!(serialized.block_vcns.len() > 2);
        assert_eq!(&serialized.block_vcns[..3], &[0, 2, 4]);
        validate_serialized_ntfs_directory_index(
            &serialized,
            &table,
            two_cluster_blocks,
            NtfsDirectoryIndexLimits::default(),
        )
        .unwrap();
    }

    #[test]
    fn collation_matches_case_sensitive_ntfs_tie_break_and_non_ascii_upcase() {
        let table = upcase();
        let input = vec![
            entry("éclair", 30),
            entry("alpha", 31),
            entry("Zulu", 32),
            entry("Alpha", 33),
            entry("École", 34),
        ];
        let serialized = serialize_ntfs_directory_index(
            &input,
            &table,
            geometry(4096),
            NtfsDirectoryIndexLimits::default(),
        )
        .unwrap();
        let parsed = parse_index_root(&serialized.index_root, NtfsIndexLimits::default()).unwrap();
        let names: Vec<Vec<u16>> = parsed
            .entries()
            .filter_map(|value| value.file_name)
            .map(|value| value.name.code_units().collect())
            .collect();
        let expected: Vec<Vec<u16>> = ["Alpha", "alpha", "Zulu", "éclair", "École"]
            .iter()
            .map(|name| name.encode_utf16().collect())
            .collect();
        assert_eq!(names, expected);
    }

    #[test]
    fn exact_collation_collision_is_refused() {
        let table = upcase();
        let error = serialize_ntfs_directory_index(
            &[entry("same", 24), entry("same", 25)],
            &table,
            geometry(4096),
            NtfsDirectoryIndexLimits::default(),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            NtfsDirectoryIndexError::CollationCollision { .. }
        ));
    }

    #[test]
    fn multi_level_requirement_is_explicitly_refused() {
        let table = upcase();
        let error = serialize_ntfs_directory_index(
            &entries(12),
            &table,
            geometry(64),
            NtfsDirectoryIndexLimits::default(),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            NtfsDirectoryIndexError::MultiLevelTreeRequired { .. }
        ));
    }

    #[test]
    fn malformed_fixup_bitmap_order_and_vcn_are_rejected() {
        let table = upcase();
        let input = entries(16);
        let serialized = serialize_ntfs_directory_index(
            &input,
            &table,
            geometry(2048),
            NtfsDirectoryIndexLimits::default(),
        )
        .unwrap();
        assert!(serialized.is_spilled());

        let mut bad_fixup = serialized.clone();
        bad_fixup.index_allocation[510] ^= 1;
        assert!(
            validate_serialized_ntfs_directory_index(
                &bad_fixup,
                &table,
                geometry(2048),
                NtfsDirectoryIndexLimits::default(),
            )
            .is_err()
        );

        let mut bad_bitmap = serialized.clone();
        bad_bitmap.bitmap[0] ^= 1;
        assert!(
            validate_serialized_ntfs_directory_index(
                &bad_bitmap,
                &table,
                geometry(2048),
                NtfsDirectoryIndexLimits::default(),
            )
            .is_err()
        );

        let mut bad_vcn = serialized.clone();
        bad_vcn.block_vcns[0] = 99;
        assert!(
            validate_serialized_ntfs_directory_index(
                &bad_vcn,
                &table,
                geometry(2048),
                NtfsDirectoryIndexLimits::default(),
            )
            .is_err()
        );

        let mut bad_order = serialized;
        let first_block = &mut bad_order.index_allocation[..512];
        let entries_offset = 48;
        put_u16(
            first_block,
            entries_offset + INDEX_ENTRY_HEADER_BYTES + FILE_NAME_KEY_HEADER_BYTES,
            u16::MAX,
        )
        .unwrap();
        // Restore MST after mutating key bytes so the structural parser reaches ordering checks.
        let usn = read_u16(first_block, UPDATE_SEQUENCE_OFFSET).unwrap();
        put_u16(first_block, 510, usn).unwrap();
        assert!(
            validate_serialized_ntfs_directory_index(
                &bad_order,
                &table,
                geometry(2048),
                NtfsDirectoryIndexLimits::default(),
            )
            .is_err()
        );
    }

    #[test]
    fn limits_names_references_and_geometry_are_bounded() {
        let table = upcase();
        let limits = NtfsDirectoryIndexLimits {
            max_entries: 1,
            ..NtfsDirectoryIndexLimits::default()
        };
        assert!(matches!(
            serialize_ntfs_directory_index(
                &[entry("a", 24), entry("b", 25)],
                &table,
                geometry(4096),
                limits,
            ),
            Err(NtfsDirectoryIndexError::EntryLimitExceeded { .. })
        ));
        let mut too_long = entry("a", 24);
        too_long.name = vec![u16::from(b'x'); 256];
        assert!(matches!(
            serialize_ntfs_directory_index(
                &[too_long],
                &table,
                geometry(4096),
                NtfsDirectoryIndexLimits::default(),
            ),
            Err(NtfsDirectoryIndexError::NameTooLong { .. })
        ));
        let bad_reference = entry("a", MAX_MFT_RECORD_NUMBER + 1);
        assert!(matches!(
            serialize_ntfs_directory_index(
                &[bad_reference],
                &table,
                geometry(4096),
                NtfsDirectoryIndexLimits::default(),
            ),
            Err(NtfsDirectoryIndexError::FileReferenceOutOfRange { .. })
        ));
        let bad_geometry = NtfsDirectoryIndexGeometry {
            cluster_bytes: 4096,
            index_block_bytes: 1024,
            resident_root_bytes: 4096,
        };
        assert!(matches!(
            serialize_ntfs_directory_index(
                &[entry("a", 24)],
                &table,
                bad_geometry,
                NtfsDirectoryIndexLimits::default(),
            ),
            Err(NtfsDirectoryIndexError::UnsupportedGeometry { .. })
        ));
        assert!(matches!(
            serialize_ntfs_directory_index(
                &[entry("a", 24)],
                &table[..65_535],
                geometry(4096),
                NtfsDirectoryIndexLimits::default(),
            ),
            Err(NtfsDirectoryIndexError::IncompleteUpcaseTable { .. })
        ));
    }
}
