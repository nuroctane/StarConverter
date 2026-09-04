//! Deterministic serialization and independent validation of the `$Extend\$Reparse:$R` view
//! index, including the spilled `$INDEX_ALLOCATION:$R` form.
//!
//! `$R` is a `COLLATION_NTOFS_ULONGS` view index whose keys are fixed 12-byte `REPARSE_INDEX_KEY`
//! values (`le32 reparse_tag` followed by `leMFT_REF file_id`). Every entry therefore has one of
//! four exact sizes: a 32-byte leaf entry, a 40-byte node entry carrying a child VCN, a 16-byte
//! leaf terminal, or a 24-byte node terminal. That fixed geometry lets this module build a
//! complete B+-tree (resident root over leaf `INDX` records, with internal `INDX` levels when the
//! root cannot hold every leaf separator) without the filename-specific machinery of
//! [`super::ntfs_index_serialize`].
//!
//! The on-disk entry layout follows `layout.h` `REPARSE_INDEX` and `reparse.c:set_reparse_index`
//! at NTFS-3G commit `d327833ec1d5eb1358b6f2c37139f10a3460944d`; the `INDX` record layout follows
//! the same `INDEX_BLOCK`/`INDEX_HEADER` definitions the `$I30` serializer already uses.
//!
//! Validation parses bytes independently (including virtual update-sequence repair) and never
//! validates by regenerating output.

use std::fmt;
use std::ops::Range;

use super::ntfs_extend::{ATTRIBUTE_TYPE_UNUSED, COLLATION_NTOFS_ULONGS, ReparseIndexKey};

const INDEX_ROOT_PREFIX_BYTES: usize = 16;
const INDEX_HEADER_BYTES: usize = 16;
const INDEX_BLOCK_HEADER_BYTES: usize = 24;
const INDEX_ENTRY_HEADER_BYTES: usize = 16;
const KEY_BYTES: usize = 12;
/// `REPARSE_INDEX`: header, key, and a `le32 filling` pad to 8-byte alignment.
const LEAF_ENTRY_BYTES: usize = 32;
const NODE_ENTRY_BYTES: usize = LEAF_ENTRY_BYTES + 8;
const LEAF_TERMINAL_BYTES: usize = INDEX_ENTRY_HEADER_BYTES;
const NODE_TERMINAL_BYTES: usize = INDEX_ENTRY_HEADER_BYTES + 8;
const UPDATE_SEQUENCE_OFFSET: usize = 40;
const UPDATE_SEQUENCE_STRIDE: usize = 512;
const INDEX_ENTRY_NODE: u16 = 0x0001;
const INDEX_ENTRY_END: u16 = 0x0002;
const MAX_INDEX_DEPTH: usize = 8;
const _: () = assert!(INDEX_ENTRY_HEADER_BYTES + KEY_BYTES + 4 == LEAF_ENTRY_BYTES);

/// On-disk geometry required to serialize the `$R` index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtfsReparseIndexGeometry {
    /// NTFS cluster size in bytes.
    pub cluster_bytes: u32,
    /// Size of each `INDX` record in bytes.
    pub index_block_bytes: u32,
    /// Maximum complete resident `INDEX_ROOT:$R` value accepted by the `$Reparse` FILE layout.
    pub resident_root_bytes: usize,
}

/// Resource caps for `$R` construction and validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtfsReparseIndexLimits {
    /// Maximum number of reparse keys.
    pub max_keys: usize,
    /// Maximum number of emitted `INDX` records (leaf plus internal).
    pub max_blocks: usize,
    /// Maximum total `$INDEX_ALLOCATION:$R` bytes.
    pub max_allocation_bytes: usize,
}

impl Default for NtfsReparseIndexLimits {
    fn default() -> Self {
        Self {
            max_keys: 1_000_000,
            max_blocks: 65_536,
            max_allocation_bytes: 256 * 1024 * 1024,
        }
    }
}

/// A complete serialized `$R` stream set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerializedNtfsReparseIndex {
    /// Complete resident `$INDEX_ROOT:$R` value (16-byte prefix, 16-byte header, entries).
    pub index_root: Vec<u8>,
    /// Concatenated `$INDEX_ALLOCATION:$R` value, or empty for a resident index.
    pub index_allocation: Vec<u8>,
    /// Resident `$BITMAP:$R` value, or empty for a resident index.
    pub bitmap: Vec<u8>,
    /// VCN stored in each emitted `INDX` record, in stream order.
    pub block_vcns: Vec<u64>,
}

impl SerializedNtfsReparseIndex {
    /// Returns whether the index uses `INDEX_ALLOCATION` records.
    #[must_use]
    pub fn is_spilled(&self) -> bool {
        !self.index_allocation.is_empty()
    }

    /// The root entries (everything after the 32-byte prefix and header).
    #[must_use]
    pub fn root_entries(&self) -> &[u8] {
        &self.index_root
            [(INDEX_ROOT_PREFIX_BYTES + INDEX_HEADER_BYTES).min(self.index_root.len())..]
    }
}

/// Summary returned by the independent validator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedNtfsReparseIndex {
    /// Every key reachable through the index, in `COLLATION_NTOFS_ULONGS` order.
    pub keys: Vec<ReparseIndexKey>,
    /// Number of allocated `INDX` records.
    pub block_count: usize,
    /// Whether the index uses allocation blocks.
    pub spilled: bool,
}

/// Reason the `$R` index could not be serialized or validated safely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NtfsReparseIndexError {
    /// The geometry is not a supported cluster/sector-based index-block profile.
    UnsupportedGeometry { reason: &'static str },
    /// A configured cap is internally invalid.
    InvalidLimit { field: &'static str },
    /// Too many keys were supplied.
    KeyLimitExceeded { actual: usize, maximum: usize },
    /// Two keys collate equal (same tag and FILE reference).
    DuplicateKey { key: ReparseIndexKey },
    /// Root separators do not fit the resident budget and another tree level cannot be formed.
    MultiLevelTreeRequired { root_bytes: usize, maximum: usize },
    /// The requested allocation exceeds a resource cap.
    AllocationLimitExceeded { actual: usize, maximum: usize },
    /// The requested block count exceeds a resource cap.
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

impl fmt::Display for NtfsReparseIndexError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedGeometry { reason } => {
                write!(formatter, "unsupported $Reparse:$R geometry: {reason}")
            }
            Self::InvalidLimit { field } => {
                write!(formatter, "invalid $Reparse:$R limit `{field}`")
            }
            Self::KeyLimitExceeded { actual, maximum } => write!(
                formatter,
                "$Reparse:$R has {actual} keys; configured cap is {maximum}"
            ),
            Self::DuplicateKey { key } => write!(
                formatter,
                "duplicate $Reparse:$R key tag 0x{:08x} file reference 0x{:016x}",
                key.reparse_tag, key.file_reference
            ),
            Self::MultiLevelTreeRequired {
                root_bytes,
                maximum,
            } => write!(
                formatter,
                "$Reparse:$R separator root needs {root_bytes} bytes but resident budget is \
                 {maximum}; no further INDX level can be formed"
            ),
            Self::AllocationLimitExceeded { actual, maximum } => write!(
                formatter,
                "$Reparse:$R allocation needs {actual} bytes; configured cap is {maximum}"
            ),
            Self::BlockLimitExceeded { actual, maximum } => write!(
                formatter,
                "$Reparse:$R allocation needs {actual} blocks; configured cap is {maximum}"
            ),
            Self::ArithmeticOverflow => formatter.write_str("$Reparse:$R arithmetic overflow"),
            Self::AllocationFailed => formatter.write_str("$Reparse:$R allocation failed"),
            Self::Malformed { component, reason } => {
                write!(formatter, "malformed $Reparse:$R {component}: {reason}")
            }
        }
    }
}

impl std::error::Error for NtfsReparseIndexError {}

#[derive(Debug, Clone, Copy)]
struct CheckedGeometry {
    block_bytes: usize,
    vcn_units_per_block: u8,
    /// Offset of the first entry from the start of an `INDX` record.
    entries_offset: usize,
    /// Bytes available for entries (including the terminal) in one `INDX` record.
    node_capacity: usize,
    /// Leaf keys per `INDX` leaf record.
    leaf_keys_per_block: usize,
    /// Separator keys per internal `INDX` record (one fewer than its children).
    node_keys_per_block: usize,
    root_budget: usize,
}

enum PlannedNode {
    Leaf {
        range: Range<usize>,
    },
    Internal {
        children: Vec<usize>,
        separators: Vec<usize>,
    },
}

/// Serialize a deterministic resident or spilled `$Reparse:$R` view index.
///
/// Input order is irrelevant; keys are sorted by `COLLATION_NTOFS_ULONGS`. Equal keys are refused.
///
/// # Errors
/// Returns an error for invalid geometry, cap violations, duplicate keys, or a tree whose root
/// cannot hold a child pointer after every allowed allocation level.
pub fn serialize_ntfs_reparse_index(
    keys: &[ReparseIndexKey],
    geometry: NtfsReparseIndexGeometry,
    limits: NtfsReparseIndexLimits,
) -> Result<SerializedNtfsReparseIndex, NtfsReparseIndexError> {
    let checked = check_geometry(geometry, limits)?;
    if keys.len() > limits.max_keys {
        return Err(NtfsReparseIndexError::KeyLimitExceeded {
            actual: keys.len(),
            maximum: limits.max_keys,
        });
    }
    let mut sorted = Vec::new();
    sorted
        .try_reserve_exact(keys.len())
        .map_err(|_| NtfsReparseIndexError::AllocationFailed)?;
    sorted.extend_from_slice(keys);
    sorted.sort_unstable_by_key(|key| key.collation_ulongs());
    for pair in sorted.windows(2) {
        if pair[0].collation_ulongs() == pair[1].collation_ulongs() {
            return Err(NtfsReparseIndexError::DuplicateKey { key: pair[1] });
        }
    }

    let resident_bytes = root_size(sorted.len(), false)?;
    if resident_bytes <= checked.root_budget {
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(resident_bytes - INDEX_ROOT_PREFIX_BYTES - INDEX_HEADER_BYTES)
            .map_err(|_| NtfsReparseIndexError::AllocationFailed)?;
        for key in &sorted {
            append_entry(&mut entries, *key, None);
        }
        append_terminal(&mut entries, None);
        return Ok(SerializedNtfsReparseIndex {
            index_root: build_root(&entries, false, checked)?,
            index_allocation: Vec::new(),
            bitmap: Vec::new(),
            block_vcns: Vec::new(),
        });
    }
    spill(&sorted, checked, limits)
}

fn spill(
    sorted: &[ReparseIndexKey],
    checked: CheckedGeometry,
    limits: NtfsReparseIndexLimits,
) -> Result<SerializedNtfsReparseIndex, NtfsReparseIndexError> {
    let (leaf_ranges, mut separators) = partition_leaves(sorted.len(), checked)?;
    let mut nodes: Vec<PlannedNode> = leaf_ranges
        .into_iter()
        .map(|range| PlannedNode::Leaf { range })
        .collect();
    let mut level: Vec<usize> = (0..nodes.len()).collect();
    for _ in 0..MAX_INDEX_DEPTH {
        let root_bytes = root_size(separators.len(), true)?;
        if root_bytes <= checked.root_budget {
            return emit_spilled(sorted, &nodes, &level, &separators, checked, limits);
        }
        let previous = level.len();
        let (groups, promoted) = partition_internal_nodes(&separators, previous, checked)?;
        let mut child_cursor = 0_usize;
        let mut next_level = Vec::new();
        next_level
            .try_reserve_exact(groups.len())
            .map_err(|_| NtfsReparseIndexError::AllocationFailed)?;
        for (group_separators, child_count) in groups {
            let end = child_cursor
                .checked_add(child_count)
                .ok_or(NtfsReparseIndexError::ArithmeticOverflow)?;
            if end > level.len() {
                return Err(NtfsReparseIndexError::ArithmeticOverflow);
            }
            let id = nodes.len();
            nodes.push(PlannedNode::Internal {
                children: level[child_cursor..end].to_vec(),
                separators: group_separators,
            });
            next_level.push(id);
            child_cursor = end;
        }
        if next_level.is_empty() || next_level.len() >= previous {
            return Err(NtfsReparseIndexError::MultiLevelTreeRequired {
                root_bytes,
                maximum: checked.root_budget,
            });
        }
        level = next_level;
        separators = promoted;
    }
    Err(NtfsReparseIndexError::MultiLevelTreeRequired {
        root_bytes: root_size(separators.len(), true)?,
        maximum: checked.root_budget,
    })
}

fn emit_spilled(
    sorted: &[ReparseIndexKey],
    nodes: &[PlannedNode],
    root_children: &[usize],
    separators: &[usize],
    checked: CheckedGeometry,
    limits: NtfsReparseIndexLimits,
) -> Result<SerializedNtfsReparseIndex, NtfsReparseIndexError> {
    if nodes.len() > limits.max_blocks {
        return Err(NtfsReparseIndexError::BlockLimitExceeded {
            actual: nodes.len(),
            maximum: limits.max_blocks,
        });
    }
    let allocation_bytes = checked
        .block_bytes
        .checked_mul(nodes.len())
        .ok_or(NtfsReparseIndexError::ArithmeticOverflow)?;
    if allocation_bytes > limits.max_allocation_bytes {
        return Err(NtfsReparseIndexError::AllocationLimitExceeded {
            actual: allocation_bytes,
            maximum: limits.max_allocation_bytes,
        });
    }
    if root_children.len() != separators.len() + 1 {
        return Err(NtfsReparseIndexError::ArithmeticOverflow);
    }
    let block_vcns = block_vcns(nodes.len(), checked.vcn_units_per_block)?;
    let mut index_allocation = Vec::new();
    index_allocation
        .try_reserve_exact(allocation_bytes)
        .map_err(|_| NtfsReparseIndexError::AllocationFailed)?;
    for (block_number, node) in nodes.iter().enumerate() {
        let mut entries = Vec::new();
        let has_children = match node {
            PlannedNode::Leaf { range } => {
                for key in &sorted[range.clone()] {
                    append_entry(&mut entries, *key, None);
                }
                append_terminal(&mut entries, None);
                false
            }
            PlannedNode::Internal {
                children,
                separators,
            } => {
                if children.len() != separators.len() + 1 {
                    return Err(NtfsReparseIndexError::ArithmeticOverflow);
                }
                for (position, child) in children.iter().enumerate() {
                    let child_vcn = block_vcns
                        .get(*child)
                        .copied()
                        .ok_or(NtfsReparseIndexError::ArithmeticOverflow)?;
                    match separators.get(position) {
                        Some(&separator) => {
                            append_entry(&mut entries, sorted[separator], Some(child_vcn));
                        }
                        None => append_terminal(&mut entries, Some(child_vcn)),
                    }
                }
                true
            }
        };
        index_allocation.extend_from_slice(&build_index_block(
            &entries,
            has_children,
            block_vcns[block_number],
            block_number,
            checked,
        )?);
    }
    let mut root_entries = Vec::new();
    for (position, child) in root_children.iter().enumerate() {
        let child_vcn = block_vcns
            .get(*child)
            .copied()
            .ok_or(NtfsReparseIndexError::ArithmeticOverflow)?;
        match separators.get(position) {
            Some(&separator) => append_entry(&mut root_entries, sorted[separator], Some(child_vcn)),
            None => append_terminal(&mut root_entries, Some(child_vcn)),
        }
    }
    Ok(SerializedNtfsReparseIndex {
        index_root: build_root(&root_entries, true, checked)?,
        index_allocation,
        bitmap: build_bitmap(nodes.len())?,
        block_vcns,
    })
}

/// Assembles a complete `$INDEX_ROOT:$R` value (prefix, header, entries) for `geometry`.
///
/// # Errors
/// Returns an error for unsupported geometry or a root that exceeds its resident budget.
pub fn compose_reparse_root_value(
    entries: &[u8],
    has_children: bool,
    geometry: NtfsReparseIndexGeometry,
) -> Result<Vec<u8>, NtfsReparseIndexError> {
    let checked = check_geometry(geometry, NtfsReparseIndexLimits::default())?;
    build_root(entries, has_children, checked)
}

/// Independently validate a complete serialized `$R` stream set.
///
/// # Errors
/// Returns an error for malformed structures, noncanonical child VCNs, unreachable blocks,
/// invalid bitmap bits, ordering violations, or cap violations.
pub fn validate_serialized_ntfs_reparse_index(
    serialized: &SerializedNtfsReparseIndex,
    geometry: NtfsReparseIndexGeometry,
    limits: NtfsReparseIndexLimits,
) -> Result<ValidatedNtfsReparseIndex, NtfsReparseIndexError> {
    let checked = check_geometry(geometry, limits)?;
    let root = &serialized.index_root;
    if root.len() > checked.root_budget {
        return malformed("INDEX_ROOT", "resident value exceeds its configured budget");
    }
    if root.len() < INDEX_ROOT_PREFIX_BYTES + INDEX_HEADER_BYTES + LEAF_TERMINAL_BYTES {
        return malformed("INDEX_ROOT", "value is shorter than an empty root");
    }
    if read_u32(root, 0) != ATTRIBUTE_TYPE_UNUSED || read_u32(root, 4) != COLLATION_NTOFS_ULONGS {
        return malformed(
            "INDEX_ROOT",
            "indexed type or collation is not the $R profile",
        );
    }
    if usize::try_from(read_u32(root, 8)).unwrap_or(usize::MAX) != checked.block_bytes
        || root[12] != checked.vcn_units_per_block
        || root[13..16] != [0, 0, 0]
    {
        return malformed("INDEX_ROOT", "noncanonical index-block geometry");
    }
    let header = parse_index_header(root, INDEX_ROOT_PREFIX_BYTES, "INDEX_ROOT")?;
    if header.entries_offset != INDEX_HEADER_BYTES
        || header.allocated_size != header.index_length
        || INDEX_ROOT_PREFIX_BYTES + header.index_length != root.len()
    {
        return malformed("INDEX_ROOT", "noncanonical header or trailing bytes");
    }
    let root_entries = &root[INDEX_ROOT_PREFIX_BYTES + INDEX_HEADER_BYTES..];
    let mut keys = Vec::new();
    if !header.has_children {
        if !serialized.index_allocation.is_empty()
            || !serialized.bitmap.is_empty()
            || !serialized.block_vcns.is_empty()
        {
            return malformed("resident index", "unexpected allocation streams or VCNs");
        }
        let parsed = parse_entries(root_entries, false, "INDEX_ROOT")?;
        for key in parsed.into_iter().filter_map(|(key, _)| key) {
            push_ordered(&mut keys, key, limits)?;
        }
        return Ok(ValidatedNtfsReparseIndex {
            keys,
            block_count: 0,
            spilled: false,
        });
    }

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
        return Err(NtfsReparseIndexError::BlockLimitExceeded {
            actual: block_count,
            maximum: limits.max_blocks,
        });
    }
    if serialized.index_allocation.len() > limits.max_allocation_bytes {
        return Err(NtfsReparseIndexError::AllocationLimitExceeded {
            actual: serialized.index_allocation.len(),
            maximum: limits.max_allocation_bytes,
        });
    }
    let expected_vcns = block_vcns(block_count, checked.vcn_units_per_block)?;
    if serialized.block_vcns != expected_vcns {
        return malformed("INDEX_ALLOCATION", "noncanonical block VCN list");
    }
    if serialized.bitmap != build_bitmap(block_count)? {
        return malformed("BITMAP", "noncanonical allocation bits or padding");
    }
    let mut seen = vec![false; block_count];
    walk_node(
        root_entries,
        "INDEX_ROOT",
        serialized,
        &expected_vcns,
        &mut seen,
        &mut keys,
        checked,
        limits,
        0,
    )?;
    if seen.iter().any(|visited| !visited) {
        return malformed("INDEX_ALLOCATION", "allocated index block is unreachable");
    }
    Ok(ValidatedNtfsReparseIndex {
        keys,
        block_count,
        spilled: true,
    })
}

#[allow(clippy::too_many_arguments)]
fn walk_node(
    entries: &[u8],
    component: &'static str,
    serialized: &SerializedNtfsReparseIndex,
    expected_vcns: &[u64],
    seen: &mut [bool],
    keys: &mut Vec<ReparseIndexKey>,
    checked: CheckedGeometry,
    limits: NtfsReparseIndexLimits,
    depth: usize,
) -> Result<(), NtfsReparseIndexError> {
    if depth > MAX_INDEX_DEPTH {
        return malformed(component, "index tree exceeds the supported depth");
    }
    let parsed = parse_entries(entries, true, component)?;
    for (key, child_vcn) in parsed {
        let child_vcn = child_vcn.ok_or_else(|| {
            malformed_error(component, "node entry is missing a child VCN".to_owned())
        })?;
        let block_number = expected_vcns
            .iter()
            .position(|vcn| *vcn == child_vcn)
            .ok_or_else(|| {
                malformed_error(
                    component,
                    "child VCN is not in the allocation stream".to_owned(),
                )
            })?;
        if seen[block_number] {
            return malformed(component, "child VCN is reachable more than once");
        }
        seen[block_number] = true;
        let start = block_number
            .checked_mul(checked.block_bytes)
            .ok_or(NtfsReparseIndexError::ArithmeticOverflow)?;
        let block = &serialized.index_allocation[start..start + checked.block_bytes];
        let (block_entries, has_children) =
            parse_index_block(block, child_vcn, block_number, checked)?;
        if has_children {
            walk_node(
                &block_entries,
                "INDEX_ALLOCATION",
                serialized,
                expected_vcns,
                seen,
                keys,
                checked,
                limits,
                depth + 1,
            )?;
        } else {
            for leaf_key in parse_entries(&block_entries, false, "INDEX_ALLOCATION")?
                .into_iter()
                .filter_map(|(key, _)| key)
            {
                push_ordered(keys, leaf_key, limits)?;
            }
        }
        if let Some(key) = key {
            push_ordered(keys, key, limits)?;
        }
    }
    Ok(())
}

/// One `$R` node read from an arbitrary volume, in on-disk order.
///
/// Unlike [`validate_serialized_ntfs_reparse_index`], the readers that produce this type accept
/// any structurally sound `$R` node (arbitrary `$LogFile` sequence numbers, update-sequence
/// numbers, and unused-space contents), because an inventory must reconcile volumes written by
/// other implementations rather than only this crate's canonical output.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NtfsReparseIndexNode {
    /// Keys carried by this node's non-terminal entries, in on-disk order.
    pub keys: Vec<ReparseIndexKey>,
    /// Child VCNs of every entry including the terminal one; empty for leaf nodes.
    pub child_vcns: Vec<u64>,
}

impl NtfsReparseIndexNode {
    /// Whether this node points at `INDX` children.
    #[must_use]
    pub fn has_children(&self) -> bool {
        !self.child_vcns.is_empty()
    }
}

/// A parsed `$INDEX_ROOT:$R` value from an arbitrary volume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsReparseIndexRootView {
    /// `INDX` record size declared by the root.
    pub index_block_bytes: u32,
    /// Encoded clusters (or 512-byte units) per `INDX` record.
    pub clusters_per_index_block: u8,
    /// The root node's entries.
    pub node: NtfsReparseIndexNode,
}

/// Reads a `$INDEX_ROOT:$R` value written by any NTFS implementation.
///
/// The indexed-type and collation fields must still identify the `$R` profile and every entry
/// must have the fixed `REPARSE_INDEX` geometry, but header padding, unused trailing bytes, and
/// entry data fields are not required to be canonical.
///
/// # Errors
/// Returns [`NtfsReparseIndexError::Malformed`] for a value that is not a structurally sound
/// `$R` root, or a cap error when `max_entries` is exceeded.
pub fn read_reparse_index_root(
    value: &[u8],
    max_entries: usize,
) -> Result<NtfsReparseIndexRootView, NtfsReparseIndexError> {
    const COMPONENT: &str = "INDEX_ROOT";
    if value.len() < INDEX_ROOT_PREFIX_BYTES + INDEX_HEADER_BYTES + LEAF_TERMINAL_BYTES {
        return malformed(COMPONENT, "value is shorter than an empty root");
    }
    if read_u32(value, 0) != ATTRIBUTE_TYPE_UNUSED || read_u32(value, 4) != COLLATION_NTOFS_ULONGS {
        return malformed(COMPONENT, "indexed type or collation is not the $R profile");
    }
    let index_block_bytes = read_u32(value, 8);
    if index_block_bytes == 0 || index_block_bytes % 512 != 0 {
        return malformed(
            COMPONENT,
            "index-block size is not a positive sector multiple",
        );
    }
    let header = parse_index_header_lenient(value, INDEX_ROOT_PREFIX_BYTES, COMPONENT)?;
    let entries_start = INDEX_ROOT_PREFIX_BYTES + header.entries_offset;
    let entries_end = INDEX_ROOT_PREFIX_BYTES + header.index_length;
    if header.entries_offset < INDEX_HEADER_BYTES
        || header.entries_offset % 8 != 0
        || header.index_length < header.entries_offset
        || entries_end > value.len()
        || header.allocated_size < header.index_length
    {
        return malformed(COMPONENT, "index header bounds are inconsistent");
    }
    let node = read_node_entries(
        &value[entries_start..entries_end],
        header.has_children,
        COMPONENT,
        max_entries,
    )?;
    Ok(NtfsReparseIndexRootView {
        index_block_bytes,
        clusters_per_index_block: value[12],
        node,
    })
}

/// Reads one `$INDEX_ALLOCATION:$R` `INDX` record written by any NTFS implementation.
///
/// The update-sequence array is checked and virtually applied, and the record must declare
/// `expected_vcn`, but the `$LogFile` sequence number, the update-sequence number, and bytes
/// beyond `index_length` are not constrained.
///
/// # Errors
/// Returns [`NtfsReparseIndexError::Malformed`] for a torn or structurally unsound record, or a
/// cap error when `max_entries` is exceeded.
pub fn read_reparse_index_block(
    block: &[u8],
    expected_vcn: u64,
    max_entries: usize,
) -> Result<NtfsReparseIndexNode, NtfsReparseIndexError> {
    const COMPONENT: &str = "INDEX_ALLOCATION";
    if block.len() < UPDATE_SEQUENCE_STRIDE
        || block.len() % UPDATE_SEQUENCE_STRIDE != 0
        || &block[..4] != b"INDX"
    {
        return malformed(COMPONENT, "record size or magic is invalid");
    }
    let sector_count = block.len() / UPDATE_SEQUENCE_STRIDE;
    let usa_offset = usize::from(read_u16(block, 4));
    let usa_count = usize::from(read_u16(block, 6));
    let usa_end = usa_offset
        .checked_add(
            usa_count
                .checked_mul(2)
                .ok_or(NtfsReparseIndexError::ArithmeticOverflow)?,
        )
        .ok_or(NtfsReparseIndexError::ArithmeticOverflow)?;
    if usa_count != sector_count + 1
        || usa_offset < INDEX_BLOCK_HEADER_BYTES
        || usa_offset % 2 != 0
        || usa_end > UPDATE_SEQUENCE_STRIDE - 2
    {
        return malformed(COMPONENT, "update-sequence array header is invalid");
    }
    if read_u64(block, 16) != expected_vcn {
        return malformed(COMPONENT, "record VCN does not match its child pointer");
    }
    let usn = read_u16(block, usa_offset);
    let mut repaired = block.to_vec();
    for sector in 0..sector_count {
        let trailer = (sector + 1) * UPDATE_SEQUENCE_STRIDE - 2;
        if read_u16(block, trailer) != usn {
            return malformed(COMPONENT, "update-sequence fixup mismatch");
        }
        let saved = usa_offset + 2 + sector * 2;
        repaired[trailer..trailer + 2].copy_from_slice(&block[saved..saved + 2]);
    }
    let header = parse_index_header_lenient(&repaired, INDEX_BLOCK_HEADER_BYTES, COMPONENT)?;
    let entries_start = INDEX_BLOCK_HEADER_BYTES + header.entries_offset;
    let entries_end = INDEX_BLOCK_HEADER_BYTES + header.index_length;
    if header.entries_offset < INDEX_HEADER_BYTES
        || header.entries_offset % 8 != 0
        || entries_start < usa_end
        || header.index_length < header.entries_offset
        || header.index_length > header.allocated_size
        || INDEX_BLOCK_HEADER_BYTES + header.allocated_size > block.len()
    {
        return malformed(COMPONENT, "index-block header bounds are inconsistent");
    }
    read_node_entries(
        &repaired[entries_start..entries_end],
        header.has_children,
        COMPONENT,
        max_entries,
    )
}

fn parse_index_header_lenient(
    bytes: &[u8],
    offset: usize,
    component: &'static str,
) -> Result<ParsedIndexHeader, NtfsReparseIndexError> {
    let header = bytes
        .get(offset..offset + INDEX_HEADER_BYTES)
        .ok_or_else(|| malformed_error(component, "truncated index header".to_owned()))?;
    let flags = header[12];
    if flags & !1 != 0 {
        return malformed(component, "invalid index header flags");
    }
    Ok(ParsedIndexHeader {
        entries_offset: usize::try_from(read_u32(header, 0))
            .map_err(|_| NtfsReparseIndexError::ArithmeticOverflow)?,
        index_length: usize::try_from(read_u32(header, 4))
            .map_err(|_| NtfsReparseIndexError::ArithmeticOverflow)?,
        allocated_size: usize::try_from(read_u32(header, 8))
            .map_err(|_| NtfsReparseIndexError::ArithmeticOverflow)?,
        has_children: flags == 1,
    })
}

fn read_node_entries(
    entries: &[u8],
    has_children: bool,
    component: &'static str,
    max_entries: usize,
) -> Result<NtfsReparseIndexNode, NtfsReparseIndexError> {
    let parsed = parse_entries_with(entries, has_children, component, false, max_entries)?;
    let mut node = NtfsReparseIndexNode::default();
    for (key, child_vcn) in parsed {
        if let Some(key) = key {
            node.keys
                .try_reserve(1)
                .map_err(|_| NtfsReparseIndexError::AllocationFailed)?;
            node.keys.push(key);
        }
        if let Some(child_vcn) = child_vcn {
            node.child_vcns
                .try_reserve(1)
                .map_err(|_| NtfsReparseIndexError::AllocationFailed)?;
            node.child_vcns.push(child_vcn);
        }
    }
    Ok(node)
}

fn push_ordered(
    keys: &mut Vec<ReparseIndexKey>,
    key: ReparseIndexKey,
    limits: NtfsReparseIndexLimits,
) -> Result<(), NtfsReparseIndexError> {
    if let Some(previous) = keys.last() {
        match previous.collation_ulongs().cmp(&key.collation_ulongs()) {
            std::cmp::Ordering::Less => {}
            std::cmp::Ordering::Equal => {
                return Err(NtfsReparseIndexError::DuplicateKey { key });
            }
            std::cmp::Ordering::Greater => {
                return malformed(
                    "index ordering",
                    "keys are not in strict NTOFS_ULONGS collation order",
                );
            }
        }
    }
    if keys.len() >= limits.max_keys {
        return Err(NtfsReparseIndexError::KeyLimitExceeded {
            actual: keys.len() + 1,
            maximum: limits.max_keys,
        });
    }
    keys.try_reserve(1)
        .map_err(|_| NtfsReparseIndexError::AllocationFailed)?;
    keys.push(key);
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct ParsedIndexHeader {
    entries_offset: usize,
    index_length: usize,
    allocated_size: usize,
    has_children: bool,
}

fn parse_index_header(
    bytes: &[u8],
    offset: usize,
    component: &'static str,
) -> Result<ParsedIndexHeader, NtfsReparseIndexError> {
    let header = bytes
        .get(offset..offset + INDEX_HEADER_BYTES)
        .ok_or_else(|| malformed_error(component, "truncated index header".to_owned()))?;
    let flags = header[12];
    if flags & !1 != 0 || header[13..16] != [0, 0, 0] {
        return malformed(component, "invalid index header flags or reserved bytes");
    }
    Ok(ParsedIndexHeader {
        entries_offset: usize::try_from(read_u32(header, 0))
            .map_err(|_| NtfsReparseIndexError::ArithmeticOverflow)?,
        index_length: usize::try_from(read_u32(header, 4))
            .map_err(|_| NtfsReparseIndexError::ArithmeticOverflow)?,
        allocated_size: usize::try_from(read_u32(header, 8))
            .map_err(|_| NtfsReparseIndexError::ArithmeticOverflow)?,
        has_children: flags == 1,
    })
}

/// Virtually repairs one `INDX` record's update-sequence protection and returns its entry bytes.
fn parse_index_block(
    block: &[u8],
    expected_vcn: u64,
    block_number: usize,
    checked: CheckedGeometry,
) -> Result<(Vec<u8>, bool), NtfsReparseIndexError> {
    const COMPONENT: &str = "INDEX_ALLOCATION";
    if block.len() != checked.block_bytes || &block[..4] != b"INDX" {
        return malformed(COMPONENT, "record size or magic is not canonical");
    }
    let sector_count = checked.block_bytes / UPDATE_SEQUENCE_STRIDE;
    let usa_offset = usize::from(read_u16(block, 4));
    let usa_count = usize::from(read_u16(block, 6));
    if usa_offset != UPDATE_SEQUENCE_OFFSET || usa_count != sector_count + 1 {
        return malformed(COMPONENT, "noncanonical update-sequence array header");
    }
    if read_u64(block, 8) != 0 {
        return malformed(COMPONENT, "log-file sequence number is not zero");
    }
    if read_u64(block, 16) != expected_vcn {
        return malformed(COMPONENT, "record VCN does not match its child pointer");
    }
    let usn = read_u16(block, UPDATE_SEQUENCE_OFFSET);
    if usn != update_sequence_number(block_number)? {
        return malformed(COMPONENT, "noncanonical update-sequence number");
    }
    let mut repaired = block.to_vec();
    for sector in 0..sector_count {
        let trailer = (sector + 1) * UPDATE_SEQUENCE_STRIDE - 2;
        if read_u16(block, trailer) != usn {
            return malformed(COMPONENT, "update-sequence fixup mismatch");
        }
        let saved = UPDATE_SEQUENCE_OFFSET + 2 + sector * 2;
        repaired[trailer..trailer + 2].copy_from_slice(&block[saved..saved + 2]);
    }
    let header = parse_index_header(&repaired, INDEX_BLOCK_HEADER_BYTES, COMPONENT)?;
    if header.entries_offset != checked.entries_offset - INDEX_BLOCK_HEADER_BYTES
        || header.allocated_size != checked.block_bytes - INDEX_BLOCK_HEADER_BYTES
        || header.index_length < header.entries_offset
        || header.index_length > header.allocated_size
    {
        return malformed(COMPONENT, "noncanonical index-block header");
    }
    let used_end = INDEX_BLOCK_HEADER_BYTES + header.index_length;
    if repaired[used_end..].iter().any(|byte| *byte != 0) {
        return malformed(COMPONENT, "unused block bytes are not zero");
    }
    Ok((
        repaired[checked.entries_offset..used_end].to_vec(),
        header.has_children,
    ))
}

/// Parses one node's entry sequence, returning `(key, child_vcn)` pairs in order. The terminal
/// entry contributes `(None, child_vcn)`; leaf nodes contribute `child_vcn == None` throughout.
#[allow(clippy::type_complexity)]
fn parse_entries(
    bytes: &[u8],
    node: bool,
    component: &'static str,
) -> Result<Vec<(Option<ReparseIndexKey>, Option<u64>)>, NtfsReparseIndexError> {
    parse_entries_with(bytes, node, component, true, usize::MAX)
}

/// Shared entry walker. `strict` additionally requires the canonical zero data fields and
/// filling that this crate emits; lenient callers only require the fixed `REPARSE_INDEX`
/// entry geometry and consistent flags.
#[allow(clippy::type_complexity)]
fn parse_entries_with(
    bytes: &[u8],
    node: bool,
    component: &'static str,
    strict: bool,
    max_entries: usize,
) -> Result<Vec<(Option<ReparseIndexKey>, Option<u64>)>, NtfsReparseIndexError> {
    let mut parsed = Vec::new();
    let mut offset = 0_usize;
    loop {
        let header = bytes
            .get(offset..offset + INDEX_ENTRY_HEADER_BYTES)
            .ok_or_else(|| malformed_error(component, "missing terminal entry".to_owned()))?;
        let length = usize::from(read_u16(header, 8));
        let key_length = usize::from(read_u16(header, 10));
        let flags = read_u16(header, 12);
        let is_end = flags & INDEX_ENTRY_END != 0;
        let has_child = flags & INDEX_ENTRY_NODE != 0;
        if has_child != node || flags & !(INDEX_ENTRY_NODE | INDEX_ENTRY_END) != 0 {
            return malformed(component, "entry flags do not match the node kind");
        }
        if strict
            && (read_u16(header, 0) != 0
                || read_u16(header, 2) != 0
                || read_u32(header, 4) != 0
                || read_u16(header, 14) != 0)
        {
            return malformed(component, "entry header data fields are not zero");
        }
        if parsed.len() >= max_entries {
            return Err(NtfsReparseIndexError::KeyLimitExceeded {
                actual: parsed.len() + 1,
                maximum: max_entries,
            });
        }
        let expected_length = match (is_end, node) {
            (true, false) => LEAF_TERMINAL_BYTES,
            (true, true) => NODE_TERMINAL_BYTES,
            (false, false) => LEAF_ENTRY_BYTES,
            (false, true) => NODE_ENTRY_BYTES,
        };
        let expected_key_length = if is_end { 0 } else { KEY_BYTES };
        if length != expected_length || key_length != expected_key_length {
            return malformed(component, "entry length or key length is not canonical");
        }
        let entry = bytes
            .get(offset..offset + length)
            .ok_or_else(|| malformed_error(component, "truncated entry".to_owned()))?;
        let key = if is_end {
            None
        } else {
            if strict && read_u32(entry, 28) != 0 {
                return malformed(component, "entry filling is not zero");
            }
            Some(ReparseIndexKey {
                reparse_tag: read_u32(entry, 16),
                file_reference: read_u64(entry, 20),
            })
        };
        let child_vcn = node.then(|| read_u64(entry, length - 8));
        parsed
            .try_reserve(1)
            .map_err(|_| NtfsReparseIndexError::AllocationFailed)?;
        parsed.push((key, child_vcn));
        offset += length;
        if is_end {
            if offset != bytes.len() {
                return malformed(component, "bytes follow the terminal entry");
            }
            return Ok(parsed);
        }
    }
}

fn check_geometry(
    geometry: NtfsReparseIndexGeometry,
    limits: NtfsReparseIndexLimits,
) -> Result<CheckedGeometry, NtfsReparseIndexError> {
    if limits.max_keys == 0 {
        return Err(NtfsReparseIndexError::InvalidLimit { field: "max_keys" });
    }
    if limits.max_blocks == 0 {
        return Err(NtfsReparseIndexError::InvalidLimit {
            field: "max_blocks",
        });
    }
    let block_bytes = usize::try_from(geometry.index_block_bytes)
        .map_err(|_| NtfsReparseIndexError::ArithmeticOverflow)?;
    let cluster_bytes = usize::try_from(geometry.cluster_bytes)
        .map_err(|_| NtfsReparseIndexError::ArithmeticOverflow)?;
    if cluster_bytes < UPDATE_SEQUENCE_STRIDE || !cluster_bytes.is_power_of_two() {
        return Err(NtfsReparseIndexError::UnsupportedGeometry {
            reason: "cluster size must be a power of two of at least 512 bytes",
        });
    }
    if !block_bytes.is_power_of_two() || block_bytes % UPDATE_SEQUENCE_STRIDE != 0 {
        return Err(NtfsReparseIndexError::UnsupportedGeometry {
            reason: "index blocks must be power-of-two multiples of 512 bytes",
        });
    }
    let vcn_units_per_block = if block_bytes >= cluster_bytes {
        if block_bytes % cluster_bytes != 0 {
            return Err(NtfsReparseIndexError::UnsupportedGeometry {
                reason: "index blocks at least one cluster must contain a whole cluster count",
            });
        }
        block_bytes / cluster_bytes
    } else {
        if cluster_bytes % block_bytes != 0 {
            return Err(NtfsReparseIndexError::UnsupportedGeometry {
                reason: "sub-cluster index blocks must divide one cluster exactly",
            });
        }
        block_bytes / UPDATE_SEQUENCE_STRIDE
    };
    let vcn_units_per_block = u8::try_from(vcn_units_per_block).map_err(|_| {
        NtfsReparseIndexError::UnsupportedGeometry {
            reason: "index-block VCN units do not fit the root field",
        }
    })?;
    if vcn_units_per_block == 0 {
        return Err(NtfsReparseIndexError::UnsupportedGeometry {
            reason: "index-block VCN units must be nonzero",
        });
    }
    let sector_count = block_bytes / UPDATE_SEQUENCE_STRIDE;
    let usa_end = UPDATE_SEQUENCE_OFFSET + (sector_count + 1) * 2;
    if usa_end > UPDATE_SEQUENCE_STRIDE - 2 {
        return Err(NtfsReparseIndexError::UnsupportedGeometry {
            reason: "update-sequence array does not fit before the first sector trailer",
        });
    }
    let entries_offset = (usa_end + 7) & !7;
    let node_capacity = block_bytes - entries_offset;
    let leaf_keys_per_block = node_capacity.saturating_sub(LEAF_TERMINAL_BYTES) / LEAF_ENTRY_BYTES;
    let node_keys_per_block = node_capacity.saturating_sub(NODE_TERMINAL_BYTES) / NODE_ENTRY_BYTES;
    if leaf_keys_per_block < 2 || node_keys_per_block < 1 {
        return Err(NtfsReparseIndexError::UnsupportedGeometry {
            reason: "index block cannot hold a useful entry count",
        });
    }
    let root_budget = geometry.resident_root_bytes;
    if root_budget < INDEX_ROOT_PREFIX_BYTES + INDEX_HEADER_BYTES + NODE_TERMINAL_BYTES {
        return Err(NtfsReparseIndexError::UnsupportedGeometry {
            reason: "resident root budget cannot hold an empty root",
        });
    }
    Ok(CheckedGeometry {
        block_bytes,
        vcn_units_per_block,
        entries_offset,
        node_capacity,
        leaf_keys_per_block,
        node_keys_per_block,
        root_budget,
    })
}

fn partition_leaves(
    key_count: usize,
    checked: CheckedGeometry,
) -> Result<(Vec<Range<usize>>, Vec<usize>), NtfsReparseIndexError> {
    let per_leaf = checked.leaf_keys_per_block;
    let mut ranges = Vec::new();
    let mut separators = Vec::new();
    let mut cursor = 0_usize;
    while cursor < key_count {
        let mut end = cursor.saturating_add(per_leaf).min(key_count);
        if end == key_count {
            ranges.push(cursor..end);
            break;
        }
        // Keep at least one key for the next leaf after the promoted separator.
        end = end.min(key_count - 2);
        if end <= cursor {
            return Err(NtfsReparseIndexError::ArithmeticOverflow);
        }
        ranges.push(cursor..end);
        separators.push(end);
        cursor = end + 1;
    }
    if ranges.len() != separators.len() + 1 || ranges.iter().any(Range::is_empty) {
        return Err(NtfsReparseIndexError::ArithmeticOverflow);
    }
    Ok((ranges, separators))
}

type NodeGroup = (Vec<usize>, usize);

fn partition_internal_nodes(
    keys: &[usize],
    child_count: usize,
    checked: CheckedGeometry,
) -> Result<(Vec<NodeGroup>, Vec<usize>), NtfsReparseIndexError> {
    if child_count == 0 || keys.len().checked_add(1) != Some(child_count) {
        return Err(NtfsReparseIndexError::ArithmeticOverflow);
    }
    let max_children = checked
        .node_keys_per_block
        .checked_add(1)
        .ok_or(NtfsReparseIndexError::ArithmeticOverflow)?;
    let mut groups = Vec::new();
    let mut promoted = Vec::new();
    let mut child_cursor = 0_usize;
    let mut key_cursor = 0_usize;
    while child_cursor < child_count {
        let remaining_children = child_count - child_cursor;
        let mut take = max_children.min(remaining_children);
        if child_cursor + take < child_count {
            take = take.min(remaining_children - 1);
            if take == 0 {
                return Err(NtfsReparseIndexError::ArithmeticOverflow);
            }
            let group_keys = take - 1;
            groups.push((keys[key_cursor..key_cursor + group_keys].to_vec(), take));
            promoted.push(keys[key_cursor + group_keys]);
            key_cursor += take;
            child_cursor += take;
        } else {
            let group_keys = keys[key_cursor..].to_vec();
            if group_keys.len() + 1 != take {
                return Err(NtfsReparseIndexError::ArithmeticOverflow);
            }
            groups.push((group_keys, take));
            break;
        }
    }
    if groups.len() != promoted.len() + 1 {
        return Err(NtfsReparseIndexError::ArithmeticOverflow);
    }
    Ok((groups, promoted))
}

fn root_size(key_count: usize, children: bool) -> Result<usize, NtfsReparseIndexError> {
    let (entry, terminal) = if children {
        (NODE_ENTRY_BYTES, NODE_TERMINAL_BYTES)
    } else {
        (LEAF_ENTRY_BYTES, LEAF_TERMINAL_BYTES)
    };
    key_count
        .checked_mul(entry)
        .and_then(|bytes| bytes.checked_add(terminal))
        .and_then(|bytes| bytes.checked_add(INDEX_ROOT_PREFIX_BYTES + INDEX_HEADER_BYTES))
        .ok_or(NtfsReparseIndexError::ArithmeticOverflow)
}

fn build_root(
    entries: &[u8],
    children: bool,
    checked: CheckedGeometry,
) -> Result<Vec<u8>, NtfsReparseIndexError> {
    let total = INDEX_ROOT_PREFIX_BYTES + INDEX_HEADER_BYTES + entries.len();
    if total > checked.root_budget {
        return Err(NtfsReparseIndexError::MultiLevelTreeRequired {
            root_bytes: total,
            maximum: checked.root_budget,
        });
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(total)
        .map_err(|_| NtfsReparseIndexError::AllocationFailed)?;
    bytes.resize(INDEX_ROOT_PREFIX_BYTES + INDEX_HEADER_BYTES, 0);
    put_u32(&mut bytes, 0, ATTRIBUTE_TYPE_UNUSED);
    put_u32(&mut bytes, 4, COLLATION_NTOFS_ULONGS);
    put_u32(
        &mut bytes,
        8,
        u32::try_from(checked.block_bytes)
            .map_err(|_| NtfsReparseIndexError::ArithmeticOverflow)?,
    );
    bytes[12] = checked.vcn_units_per_block;
    let used = u32::try_from(INDEX_HEADER_BYTES + entries.len())
        .map_err(|_| NtfsReparseIndexError::ArithmeticOverflow)?;
    put_u32(&mut bytes, INDEX_ROOT_PREFIX_BYTES, 16);
    put_u32(&mut bytes, INDEX_ROOT_PREFIX_BYTES + 4, used);
    put_u32(&mut bytes, INDEX_ROOT_PREFIX_BYTES + 8, used);
    bytes[INDEX_ROOT_PREFIX_BYTES + 12] = u8::from(children);
    bytes.extend_from_slice(entries);
    Ok(bytes)
}

fn build_index_block(
    entries: &[u8],
    has_children: bool,
    vcn: u64,
    block_number: usize,
    checked: CheckedGeometry,
) -> Result<Vec<u8>, NtfsReparseIndexError> {
    if entries.len() > checked.node_capacity {
        return malformed("INDEX_ALLOCATION", "index entries exceed their block");
    }
    let sector_count = checked.block_bytes / UPDATE_SEQUENCE_STRIDE;
    let mut bytes = vec![0_u8; checked.block_bytes];
    bytes[..4].copy_from_slice(b"INDX");
    put_u16(
        &mut bytes,
        4,
        u16::try_from(UPDATE_SEQUENCE_OFFSET)
            .map_err(|_| NtfsReparseIndexError::ArithmeticOverflow)?,
    );
    put_u16(
        &mut bytes,
        6,
        u16::try_from(sector_count + 1).map_err(|_| NtfsReparseIndexError::ArithmeticOverflow)?,
    );
    put_u64(&mut bytes, 16, vcn);
    let used_end = checked.entries_offset + entries.len();
    bytes[checked.entries_offset..used_end].copy_from_slice(entries);
    put_u32(
        &mut bytes,
        INDEX_BLOCK_HEADER_BYTES,
        u32::try_from(checked.entries_offset - INDEX_BLOCK_HEADER_BYTES)
            .map_err(|_| NtfsReparseIndexError::ArithmeticOverflow)?,
    );
    put_u32(
        &mut bytes,
        INDEX_BLOCK_HEADER_BYTES + 4,
        u32::try_from(used_end - INDEX_BLOCK_HEADER_BYTES)
            .map_err(|_| NtfsReparseIndexError::ArithmeticOverflow)?,
    );
    put_u32(
        &mut bytes,
        INDEX_BLOCK_HEADER_BYTES + 8,
        u32::try_from(checked.block_bytes - INDEX_BLOCK_HEADER_BYTES)
            .map_err(|_| NtfsReparseIndexError::ArithmeticOverflow)?,
    );
    bytes[INDEX_BLOCK_HEADER_BYTES + 12] = u8::from(has_children);
    let usn = update_sequence_number(block_number)?;
    put_u16(&mut bytes, UPDATE_SEQUENCE_OFFSET, usn);
    for sector in 0..sector_count {
        let trailer = (sector + 1) * UPDATE_SEQUENCE_STRIDE - 2;
        let original = read_u16(&bytes, trailer);
        put_u16(
            &mut bytes,
            UPDATE_SEQUENCE_OFFSET + 2 + sector * 2,
            original,
        );
        put_u16(&mut bytes, trailer, usn);
    }
    Ok(bytes)
}

const LEAF_ENTRY_LENGTH_FIELD: u16 = 32;
const NODE_ENTRY_LENGTH_FIELD: u16 = 40;
const LEAF_TERMINAL_LENGTH_FIELD: u16 = 16;
const NODE_TERMINAL_LENGTH_FIELD: u16 = 24;
const KEY_LENGTH_FIELD: u16 = 12;
const _: () = assert!(LEAF_ENTRY_LENGTH_FIELD as usize == LEAF_ENTRY_BYTES);
const _: () = assert!(NODE_ENTRY_LENGTH_FIELD as usize == NODE_ENTRY_BYTES);
const _: () = assert!(LEAF_TERMINAL_LENGTH_FIELD as usize == LEAF_TERMINAL_BYTES);
const _: () = assert!(NODE_TERMINAL_LENGTH_FIELD as usize == NODE_TERMINAL_BYTES);
const _: () = assert!(KEY_LENGTH_FIELD as usize == KEY_BYTES);

fn append_entry(output: &mut Vec<u8>, key: ReparseIndexKey, child_vcn: Option<u64>) {
    let length = if child_vcn.is_some() {
        NODE_ENTRY_LENGTH_FIELD
    } else {
        LEAF_ENTRY_LENGTH_FIELD
    };
    output.extend_from_slice(&0_u16.to_le_bytes());
    output.extend_from_slice(&0_u16.to_le_bytes());
    output.extend_from_slice(&0_u32.to_le_bytes());
    output.extend_from_slice(&length.to_le_bytes());
    output.extend_from_slice(&KEY_LENGTH_FIELD.to_le_bytes());
    output.extend_from_slice(&(u16::from(child_vcn.is_some()) * INDEX_ENTRY_NODE).to_le_bytes());
    output.extend_from_slice(&0_u16.to_le_bytes());
    output.extend_from_slice(&key.reparse_tag.to_le_bytes());
    output.extend_from_slice(&key.file_reference.to_le_bytes());
    output.extend_from_slice(&0_u32.to_le_bytes());
    if let Some(vcn) = child_vcn {
        output.extend_from_slice(&vcn.to_le_bytes());
    }
}

fn append_terminal(output: &mut Vec<u8>, child_vcn: Option<u64>) {
    let length = if child_vcn.is_some() {
        NODE_TERMINAL_LENGTH_FIELD
    } else {
        LEAF_TERMINAL_LENGTH_FIELD
    };
    output.extend_from_slice(&[0_u8; 8]);
    output.extend_from_slice(&length.to_le_bytes());
    output.extend_from_slice(&0_u16.to_le_bytes());
    let flags = INDEX_ENTRY_END | (u16::from(child_vcn.is_some()) * INDEX_ENTRY_NODE);
    output.extend_from_slice(&flags.to_le_bytes());
    output.extend_from_slice(&0_u16.to_le_bytes());
    if let Some(vcn) = child_vcn {
        output.extend_from_slice(&vcn.to_le_bytes());
    }
}

fn block_vcns(count: usize, vcn_units_per_block: u8) -> Result<Vec<u64>, NtfsReparseIndexError> {
    let mut vcns = Vec::new();
    vcns.try_reserve_exact(count)
        .map_err(|_| NtfsReparseIndexError::AllocationFailed)?;
    for block in 0..count {
        vcns.push(
            u64::try_from(block)
                .ok()
                .and_then(|block| block.checked_mul(u64::from(vcn_units_per_block)))
                .ok_or(NtfsReparseIndexError::ArithmeticOverflow)?,
        );
    }
    Ok(vcns)
}

fn build_bitmap(block_count: usize) -> Result<Vec<u8>, NtfsReparseIndexError> {
    let unaligned = block_count
        .checked_add(7)
        .ok_or(NtfsReparseIndexError::ArithmeticOverflow)?
        / 8;
    let byte_count = unaligned
        .checked_add(7)
        .ok_or(NtfsReparseIndexError::ArithmeticOverflow)?
        & !7;
    let mut bitmap = vec![0_u8; byte_count];
    for block in 0..block_count {
        bitmap[block / 8] |= 1_u8 << (block % 8);
    }
    Ok(bitmap)
}

fn update_sequence_number(block_number: usize) -> Result<u16, NtfsReparseIndexError> {
    let cycle = u16::try_from(block_number % 0x5ffe)
        .map_err(|_| NtfsReparseIndexError::ArithmeticOverflow)?;
    Ok(0xa000_u16.wrapping_add(cycle))
}

fn malformed<T>(component: &'static str, reason: &str) -> Result<T, NtfsReparseIndexError> {
    Err(malformed_error(component, reason.to_owned()))
}

const fn malformed_error(component: &'static str, reason: String) -> NtfsReparseIndexError {
    NtfsReparseIndexError::Malformed { component, reason }
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

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    let mut raw = [0_u8; 8];
    raw.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(raw)
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

#[cfg(test)]
mod tests {
    use super::*;

    const fn geometry(root_budget: usize) -> NtfsReparseIndexGeometry {
        NtfsReparseIndexGeometry {
            cluster_bytes: 4096,
            index_block_bytes: 4096,
            resident_root_bytes: root_budget,
        }
    }

    fn keys(count: u64) -> Vec<ReparseIndexKey> {
        // Deliberately unsorted input with mixed tags.
        (0..count)
            .rev()
            .map(|index| ReparseIndexKey {
                reparse_tag: if index % 3 == 0 {
                    0xa000_000c
                } else {
                    0xa000_0003
                },
                file_reference: (1_u64 << 48) | (27 + index),
            })
            .collect()
    }

    fn sorted(keys: &[ReparseIndexKey]) -> Vec<ReparseIndexKey> {
        let mut sorted = keys.to_vec();
        sorted.sort_unstable_by_key(|key| key.collation_ulongs());
        sorted
    }

    #[test]
    fn small_index_stays_resident_and_round_trips() {
        let input = keys(20);
        let serialized =
            serialize_ntfs_reparse_index(&input, geometry(1024), NtfsReparseIndexLimits::default())
                .unwrap();
        assert!(!serialized.is_spilled());
        assert_eq!(serialized.index_root.len(), 32 + 20 * 32 + 16);
        assert_eq!(serialized.index_root[28], 0);
        let validated = validate_serialized_ntfs_reparse_index(
            &serialized,
            geometry(1024),
            NtfsReparseIndexLimits::default(),
        )
        .unwrap();
        assert_eq!(validated.keys, sorted(&input));
        assert!(!validated.spilled);
        // The resident entries are exactly the ntfs_extend leaf layout.
        let parsed =
            super::super::ntfs_extend::parse_reparse_r_index_entries(serialized.root_entries())
                .unwrap();
        assert_eq!(parsed, sorted(&input));
    }

    #[test]
    fn empty_index_is_a_bare_terminal() {
        let serialized =
            serialize_ntfs_reparse_index(&[], geometry(64), NtfsReparseIndexLimits::default())
                .unwrap();
        assert_eq!(serialized.index_root.len(), 48);
        let validated = validate_serialized_ntfs_reparse_index(
            &serialized,
            geometry(64),
            NtfsReparseIndexLimits::default(),
        )
        .unwrap();
        assert!(validated.keys.is_empty());
    }

    #[test]
    fn single_level_spill_round_trips_every_key_in_order() {
        // 4096-byte blocks hold 125 leaf keys; 300 keys need three leaves and two separators.
        let input = keys(300);
        let budget = 32 + 40 * 2 + 24;
        let serialized = serialize_ntfs_reparse_index(
            &input,
            geometry(budget),
            NtfsReparseIndexLimits::default(),
        )
        .unwrap();
        assert!(serialized.is_spilled());
        assert_eq!(serialized.block_vcns, [0, 1, 2]);
        assert_eq!(serialized.index_allocation.len(), 3 * 4096);
        assert_eq!(serialized.bitmap, [0b111, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(serialized.index_root[28], 1);
        let validated = validate_serialized_ntfs_reparse_index(
            &serialized,
            geometry(budget),
            NtfsReparseIndexLimits::default(),
        )
        .unwrap();
        assert_eq!(validated.keys, sorted(&input));
        assert_eq!(validated.block_count, 3);
        assert!(validated.spilled);
    }

    #[test]
    fn multi_level_spill_adds_internal_blocks_when_the_root_cannot_hold_separators() {
        // A root that holds at most one separator forces internal INDX levels.
        let input = keys(2_000);
        let budget = 32 + 40 + 24;
        let serialized = serialize_ntfs_reparse_index(
            &input,
            geometry(budget),
            NtfsReparseIndexLimits::default(),
        )
        .unwrap();
        assert!(serialized.is_spilled());
        assert!(
            serialized.block_vcns.len() > 16,
            "{:?}",
            serialized.block_vcns.len()
        );
        let validated = validate_serialized_ntfs_reparse_index(
            &serialized,
            geometry(budget),
            NtfsReparseIndexLimits::default(),
        )
        .unwrap();
        assert_eq!(validated.keys, sorted(&input));
        assert_eq!(validated.block_count, serialized.block_vcns.len());
    }

    #[test]
    fn duplicate_keys_and_caps_are_refused() {
        let mut input = keys(3);
        input.push(input[0]);
        assert!(matches!(
            serialize_ntfs_reparse_index(&input, geometry(1024), NtfsReparseIndexLimits::default()),
            Err(NtfsReparseIndexError::DuplicateKey { .. })
        ));
        assert!(matches!(
            serialize_ntfs_reparse_index(
                &keys(3),
                geometry(1024),
                NtfsReparseIndexLimits {
                    max_keys: 2,
                    ..NtfsReparseIndexLimits::default()
                }
            ),
            Err(NtfsReparseIndexError::KeyLimitExceeded {
                actual: 3,
                maximum: 2
            })
        ));
        assert!(matches!(
            serialize_ntfs_reparse_index(
                &keys(300),
                geometry(32 + 40 * 2 + 24),
                NtfsReparseIndexLimits {
                    max_blocks: 2,
                    ..NtfsReparseIndexLimits::default()
                }
            ),
            Err(NtfsReparseIndexError::BlockLimitExceeded {
                actual: 3,
                maximum: 2
            })
        ));
        assert!(matches!(
            serialize_ntfs_reparse_index(
                &keys(300),
                geometry(32 + 40 * 2 + 24),
                NtfsReparseIndexLimits {
                    max_allocation_bytes: 8192,
                    ..NtfsReparseIndexLimits::default()
                }
            ),
            Err(NtfsReparseIndexError::AllocationLimitExceeded { .. })
        ));
    }

    #[test]
    fn tampered_spilled_bytes_are_rejected_independently() {
        let input = keys(300);
        let budget = 32 + 40 * 2 + 24;
        let limits = NtfsReparseIndexLimits::default();
        let serialized = serialize_ntfs_reparse_index(&input, geometry(budget), limits).unwrap();

        let mut swapped = serialized.clone();
        // Swap two keys inside the first leaf: ordering must be re-derived, not trusted.
        let first = 64;
        let mut a = [0_u8; 32];
        a.copy_from_slice(&swapped.index_allocation[first..first + 32]);
        let mut b = [0_u8; 32];
        b.copy_from_slice(&swapped.index_allocation[first + 32..first + 64]);
        swapped.index_allocation[first..first + 32].copy_from_slice(&b);
        swapped.index_allocation[first + 32..first + 64].copy_from_slice(&a);
        assert!(matches!(
            validate_serialized_ntfs_reparse_index(&swapped, geometry(budget), limits),
            Err(NtfsReparseIndexError::Malformed {
                component: "index ordering",
                ..
            })
        ));

        let mut fixup = serialized.clone();
        fixup.index_allocation[510] ^= 1;
        assert!(matches!(
            validate_serialized_ntfs_reparse_index(&fixup, geometry(budget), limits),
            Err(NtfsReparseIndexError::Malformed {
                component: "INDEX_ALLOCATION",
                ..
            })
        ));

        let mut bitmap = serialized.clone();
        bitmap.bitmap[0] |= 0b1000;
        assert!(matches!(
            validate_serialized_ntfs_reparse_index(&bitmap, geometry(budget), limits),
            Err(NtfsReparseIndexError::Malformed {
                component: "BITMAP",
                ..
            })
        ));

        let mut unreachable = serialized.clone();
        unreachable.index_allocation.extend(vec![0_u8; 4096]);
        unreachable.block_vcns.push(3);
        unreachable.bitmap[0] |= 0b1000;
        assert!(matches!(
            validate_serialized_ntfs_reparse_index(&unreachable, geometry(budget), limits),
            Err(NtfsReparseIndexError::Malformed {
                component: "INDEX_ALLOCATION",
                ..
            })
        ));

        let mut wrong_vcn = serialized;
        let root_first_vcn = wrong_vcn.index_root.len() - 24 - 40 - 8;
        wrong_vcn.index_root[root_first_vcn..root_first_vcn + 8]
            .copy_from_slice(&9_u64.to_le_bytes());
        assert!(matches!(
            validate_serialized_ntfs_reparse_index(&wrong_vcn, geometry(budget), limits),
            Err(NtfsReparseIndexError::Malformed {
                component: "INDEX_ROOT",
                ..
            })
        ));
    }

    #[test]
    fn oversized_root_and_wrong_collation_are_rejected() {
        let serialized = serialize_ntfs_reparse_index(
            &keys(20),
            geometry(1024),
            NtfsReparseIndexLimits::default(),
        )
        .unwrap();
        assert!(matches!(
            validate_serialized_ntfs_reparse_index(
                &serialized,
                geometry(serialized.index_root.len() - 1),
                NtfsReparseIndexLimits::default()
            ),
            Err(NtfsReparseIndexError::Malformed {
                component: "INDEX_ROOT",
                ..
            })
        ));
        let mut collation = serialized;
        collation.index_root[4] = 16;
        assert!(matches!(
            validate_serialized_ntfs_reparse_index(
                &collation,
                geometry(1024),
                NtfsReparseIndexLimits::default()
            ),
            Err(NtfsReparseIndexError::Malformed {
                component: "INDEX_ROOT",
                ..
            })
        ));
    }

    /// Walks a serialized index through the lenient readers exactly as an inventory would.
    fn read_through_lenient_readers(
        serialized: &SerializedNtfsReparseIndex,
    ) -> Vec<ReparseIndexKey> {
        let root = read_reparse_index_root(&serialized.index_root, usize::MAX).unwrap();
        let block_bytes = usize::try_from(root.index_block_bytes).unwrap();
        let mut keys = Vec::new();
        let mut pending = std::collections::VecDeque::new();
        keys.extend(root.node.keys.iter().copied());
        pending.extend(root.node.child_vcns.iter().copied());
        while let Some(vcn) = pending.pop_front() {
            let block_number = serialized
                .block_vcns
                .iter()
                .position(|candidate| *candidate == vcn)
                .unwrap();
            let start = block_number * block_bytes;
            let node = read_reparse_index_block(
                &serialized.index_allocation[start..start + block_bytes],
                vcn,
                usize::MAX,
            )
            .unwrap();
            keys.extend(node.keys.iter().copied());
            pending.extend(node.child_vcns.iter().copied());
        }
        keys.sort_unstable_by_key(|key| key.collation_ulongs());
        keys
    }

    #[test]
    fn lenient_readers_recover_resident_and_spilled_keys() {
        let resident = serialize_ntfs_reparse_index(
            &keys(20),
            geometry(1024),
            NtfsReparseIndexLimits::default(),
        )
        .unwrap();
        assert_eq!(read_through_lenient_readers(&resident), sorted(&keys(20)));
        let root = read_reparse_index_root(&resident.index_root, usize::MAX).unwrap();
        assert_eq!(root.index_block_bytes, 4096);
        assert_eq!(root.clusters_per_index_block, 1);
        assert!(!root.node.has_children());

        let spilled = serialize_ntfs_reparse_index(
            &keys(2_000),
            geometry(32 + 40 + 24),
            NtfsReparseIndexLimits::default(),
        )
        .unwrap();
        assert_eq!(read_through_lenient_readers(&spilled), sorted(&keys(2_000)));
        assert!(
            read_reparse_index_root(&spilled.index_root, usize::MAX)
                .unwrap()
                .node
                .has_children()
        );
    }

    #[test]
    fn lenient_readers_tolerate_foreign_noncanonical_bytes_but_not_torn_records() {
        let serialized = serialize_ntfs_reparse_index(
            &keys(300),
            geometry(32 + 40 * 2 + 24),
            NtfsReparseIndexLimits::default(),
        )
        .unwrap();
        let block_bytes = 4096;
        let mut foreign = serialized.index_allocation[..block_bytes].to_vec();
        // Non-zero $LogFile LSN, arbitrary USN, non-zero unused tail, non-zero entry data fields.
        put_u64(&mut foreign, 8, 0x1234_5678_9abc);
        let index_length =
            usize::try_from(read_u32(&foreign, INDEX_BLOCK_HEADER_BYTES + 4)).unwrap();
        let used_end = INDEX_BLOCK_HEADER_BYTES + index_length;
        for byte in &mut foreign[used_end..] {
            *byte = 0xee;
        }
        let first_entry = INDEX_BLOCK_HEADER_BYTES
            + usize::try_from(read_u32(&foreign, INDEX_BLOCK_HEADER_BYTES)).unwrap();
        put_u32(&mut foreign, first_entry + 28, 0xdead_beef);
        // Re-protect with an arbitrary USN: the saved slots already hold the original bytes, so
        // only the number and every sector trailer change.
        let usn = 0x77aa_u16;
        put_u16(&mut foreign, UPDATE_SEQUENCE_OFFSET, usn);
        for sector in 0..block_bytes / UPDATE_SEQUENCE_STRIDE {
            put_u16(&mut foreign, (sector + 1) * UPDATE_SEQUENCE_STRIDE - 2, usn);
        }
        let node = read_reparse_index_block(&foreign, 0, usize::MAX).unwrap();
        assert_eq!(node.keys.len(), 125);
        assert!(!node.has_children());
        // The canonical validator still refuses the same bytes.
        assert!(matches!(
            parse_index_block(
                &foreign,
                0,
                0,
                check_geometry(
                    geometry(32 + 40 * 2 + 24),
                    NtfsReparseIndexLimits::default()
                )
                .unwrap()
            ),
            Err(NtfsReparseIndexError::Malformed { .. })
        ));

        // A torn sector is still refused.
        let mut torn = foreign.clone();
        put_u16(&mut torn, UPDATE_SEQUENCE_STRIDE - 2, usn.wrapping_add(1));
        assert!(matches!(
            read_reparse_index_block(&torn, 0, usize::MAX),
            Err(NtfsReparseIndexError::Malformed {
                component: "INDEX_ALLOCATION",
                ..
            })
        ));
        // A record claiming another VCN is refused.
        assert!(matches!(
            read_reparse_index_block(&foreign, 1, usize::MAX),
            Err(NtfsReparseIndexError::Malformed {
                component: "INDEX_ALLOCATION",
                ..
            })
        ));
        // Entry caps apply.
        assert!(matches!(
            read_reparse_index_block(&foreign, 0, 10),
            Err(NtfsReparseIndexError::KeyLimitExceeded { maximum: 10, .. })
        ));
        // A root with the wrong collation is refused even leniently.
        let mut root = serialized.index_root;
        put_u32(&mut root, 4, 1);
        assert!(matches!(
            read_reparse_index_root(&root, usize::MAX),
            Err(NtfsReparseIndexError::Malformed {
                component: "INDEX_ROOT",
                ..
            })
        ));
    }
}
