//! Bounded, read-only recursive inventory for exFAT images.
//!
//! File payloads are never read. Only directory and system streams plus individual FAT entries
//! are read from an already validated regular [`ImageFile`]. Object streams use the active FAT;
//! each Allocation Bitmap stream uses its corresponding FAT. Every traversal dimension is
//! caller-capped, and a successful result proves name, allocation-bitmap, ownership, and extent
//! consistency for every live object.

#![allow(clippy::module_name_repetitions)]

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

use super::exfat::ExfatBootSector;
use super::exfat_allocation::{
    ExfatAllocationError, FatEntry, bitmap_cluster_is_allocated, cluster_byte_offset,
};
use super::exfat_directory::{
    AllocationBitmapEntry, DirectoryContext, DirectoryError, DirectoryRecord, DirectorySummary,
    FileEntry, UpcaseTableEntry, VolumeLabelEntry, parse_directory,
};
use super::exfat_discovery::{
    ExfatDiscoveryError, ExfatDiscoveryLimits, ExfatRootDiscovery, discover_root_with_reader,
};
use super::exfat_image::{
    ExfatImageError, FatIndex, StreamReadLimits, read_chain_to_end_with_reader,
    read_stream_with_reader,
};
use super::exfat_upcase::{
    DuplicateError, DuplicateLimits, MAX_FILE_NAME_CODE_UNITS, NameError, UpcaseTable,
};
use crate::extent::{Extent, ExtentGraph, ExtentGraphError, ExtentKind, Placement, StreamId};
use crate::image::{BoundedImageReader, ImageError, ImageFile};

const ROOT_STREAM: StreamId = StreamId(1);
const RESERVED_STREAM: StreamId = StreamId(u64::MAX);
const UPCASE_STREAM: StreamId = StreamId(u64::MAX - 1);
const BAD_CLUSTER_STREAM: StreamId = StreamId(u64::MAX - 2);
// Two bitmap identifiers are valid; keep their namespace disjoint from every other metadata ID.
const BITMAP_STREAM_BASE: u64 = u64::MAX - 10;

/// Explicit limits for one complete recursive inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExfatInventoryLimits {
    pub discovery: ExfatDiscoveryLimits,
    pub directory_stream: StreamReadLimits,
    pub max_objects: usize,
    pub max_directories: usize,
    pub max_depth: usize,
    pub max_directory_bytes: u64,
    pub max_logical_bytes: u64,
    /// Maximum volume clusters inspected, including free clusters.
    pub max_clusters: usize,
    pub max_stream_clusters: usize,
    pub max_extents: usize,
    pub max_path_code_units: usize,
    pub max_sibling_comparisons: usize,
}

/// Stable kind of one live exFAT object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExfatObjectKind {
    RootDirectory,
    Directory,
    File,
}

/// Preservation-relevant flags retained from a file entry set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExfatObjectFlags {
    pub no_fat_chain: bool,
    pub name_padding_zeroed: bool,
    pub benign_secondary_entries: u8,
}

/// Exact exFAT timestamp fields retained for lossless conversion and rollback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExfatTimestamps {
    pub create: u32,
    pub modified: u32,
    pub accessed: u32,
    pub create_centiseconds: u8,
    pub modified_centiseconds: u8,
    pub create_utc_offset: u8,
    pub modified_utc_offset: u8,
    pub accessed_utc_offset: u8,
}

/// Normalized, lossless record for one live object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExfatObjectRecord {
    pub stream: StreamId,
    pub parent: Option<StreamId>,
    pub kind: ExfatObjectKind,
    /// Original UTF-16 name; empty only for the root.
    pub name: Vec<u16>,
    /// Original UTF-16 components from the root, without separators.
    pub path: Vec<Vec<u16>>,
    pub file_attributes: u16,
    pub timestamps: Option<ExfatTimestamps>,
    pub valid_data_length: u64,
    pub data_length: u64,
    pub allocation_bytes: u64,
    /// Logical-order cluster chain. Contiguous streams are represented explicitly too.
    pub clusters: Vec<u32>,
    pub flags: ExfatObjectFlags,
}

/// Counts of benign or recommendation-level on-disk evidence that must survive conversion.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExfatPreservationEvidence {
    pub unused_directory_entries: u64,
    pub benign_primary_sets: u64,
    pub benign_secondary_entries: u64,
    pub nonzero_name_padding_sets: u64,
    pub nonzero_volume_label_padding: bool,
}

/// Complete proven exFAT object and physical-extent inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExfatInventory {
    pub root: ExfatRootDiscovery,
    /// Exact 32-bit serial from the validated exFAT boot sector.
    pub volume_serial_number: u32,
    /// Exact logical label when the root entry's unused UTF-16 slots were all zero.
    /// Nonzero padding is deliberately represented only by [`ExfatPreservationEvidence`].
    pub volume_label: Option<VolumeLabelEntry>,
    pub objects: Vec<ExfatObjectRecord>,
    pub extents: ExtentGraph,
    pub preservation: ExfatPreservationEvidence,
    pub allocated_bad_clusters: u64,
}

/// Failure to prove a complete bounded exFAT inventory.
#[derive(Debug)]
pub enum ExfatInventoryError {
    InvalidLimits(&'static str),
    VolumeClusterLimitExceeded {
        actual: u32,
        maximum: usize,
    },
    ObjectLimitExceeded {
        maximum: usize,
    },
    DirectoryLimitExceeded {
        maximum: usize,
    },
    DepthLimitExceeded {
        depth: usize,
        maximum: usize,
    },
    DirectoryByteLimitExceeded {
        required: u64,
        maximum: u64,
    },
    LogicalByteLimitExceeded {
        required: u64,
        maximum: u64,
    },
    PathLimitExceeded {
        required: usize,
        maximum: usize,
    },
    StreamClusterLimitExceeded {
        required: u64,
        maximum: usize,
    },
    ClusterWorkLimitExceeded {
        maximum: usize,
    },
    ExtentLimitExceeded {
        maximum: usize,
    },
    AllocationFailed,
    ArithmeticOverflow {
        calculation: &'static str,
    },
    NameHashMismatch {
        stream: StreamId,
        stored: u16,
        computed: u16,
    },
    DuplicateSiblingName {
        directory: StreamId,
        first: usize,
        second: usize,
    },
    ClusterMarkedFree {
        stream: StreamId,
        cluster: u32,
    },
    ClusterOverlap {
        cluster: u32,
        first: StreamId,
        second: StreamId,
    },
    AllocatedClusterUnowned {
        cluster: u32,
        fat_entry: FatEntry,
    },
    FatChainEndedEarly {
        stream: StreamId,
        cluster: u32,
    },
    FatChainContinues {
        stream: StreamId,
        next: u32,
    },
    FatChainCycle {
        stream: StreamId,
        cluster: u32,
    },
    Discovery(ExfatDiscoveryError),
    Directory(DirectoryError),
    DirectoryStream(ExfatImageError),
    Image(ImageError),
    Allocation(ExfatAllocationError),
    Name(NameError),
    Duplicate(DuplicateError),
    Extents(ExtentGraphError),
}

impl fmt::Display for ExfatInventoryError {
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits(reason) => {
                write!(formatter, "invalid exFAT inventory limits: {reason}")
            }
            Self::VolumeClusterLimitExceeded { actual, maximum } => write!(
                formatter,
                "volume has {actual} clusters; inventory limit is {maximum}"
            ),
            Self::ObjectLimitExceeded { maximum } => {
                write!(formatter, "exFAT object count exceeds limit {maximum}")
            }
            Self::DirectoryLimitExceeded { maximum } => {
                write!(formatter, "exFAT directory count exceeds limit {maximum}")
            }
            Self::DepthLimitExceeded { depth, maximum } => write!(
                formatter,
                "exFAT directory depth {depth} exceeds limit {maximum}"
            ),
            Self::DirectoryByteLimitExceeded { required, maximum } => write!(
                formatter,
                "directory bytes {required} exceed limit {maximum}"
            ),
            Self::LogicalByteLimitExceeded { required, maximum } => write!(
                formatter,
                "logical object bytes {required} exceed limit {maximum}"
            ),
            Self::PathLimitExceeded { required, maximum } => write!(
                formatter,
                "path requires {required} UTF-16 units; limit is {maximum}"
            ),
            Self::StreamClusterLimitExceeded { required, maximum } => write!(
                formatter,
                "stream needs {required} clusters; limit is {maximum}"
            ),
            Self::ClusterWorkLimitExceeded { maximum } => {
                write!(formatter, "cluster traversal work exceeds limit {maximum}")
            }
            Self::ExtentLimitExceeded { maximum } => {
                write!(formatter, "extent count exceeds limit {maximum}")
            }
            Self::AllocationFailed => {
                formatter.write_str("could not allocate bounded exFAT inventory storage")
            }
            Self::ArithmeticOverflow { calculation } => {
                write!(formatter, "overflow while calculating {calculation}")
            }
            Self::NameHashMismatch {
                stream,
                stored,
                computed,
            } => write!(
                formatter,
                "stream {} name hash is {stored:#06X}; computed {computed:#06X}",
                stream.0
            ),
            Self::DuplicateSiblingName {
                directory,
                first,
                second,
            } => write!(
                formatter,
                "directory stream {} has case-insensitive duplicate names at records {first} and {second}",
                directory.0
            ),
            Self::ClusterMarkedFree { stream, cluster } => write!(
                formatter,
                "bitmap marks stream {} cluster {cluster} free",
                stream.0
            ),
            Self::ClusterOverlap {
                cluster,
                first,
                second,
            } => write!(
                formatter,
                "cluster {cluster} is owned by streams {} and {}",
                first.0, second.0
            ),
            Self::AllocatedClusterUnowned { cluster, fat_entry } => write!(
                formatter,
                "allocated cluster {cluster} has no object owner (FAT entry {fat_entry:?})"
            ),
            Self::FatChainEndedEarly { stream, cluster } => write!(
                formatter,
                "stream {} FAT chain ends early at cluster {cluster}",
                stream.0
            ),
            Self::FatChainContinues { stream, next } => write!(
                formatter,
                "stream {} FAT chain continues unexpectedly to cluster {next}",
                stream.0
            ),
            Self::FatChainCycle { stream, cluster } => write!(
                formatter,
                "stream {} FAT chain cycles at cluster {cluster}",
                stream.0
            ),
            Self::Discovery(error) => write!(formatter, "root discovery failed: {error}"),
            Self::Directory(error) => write!(formatter, "directory is invalid: {error}"),
            Self::DirectoryStream(error) => {
                write!(formatter, "directory stream read failed: {error}")
            }
            Self::Image(error) => write!(formatter, "image read failed: {error}"),
            Self::Allocation(error) => write!(formatter, "allocation metadata is invalid: {error}"),
            Self::Name(error) => write!(formatter, "filename is invalid: {error}"),
            Self::Duplicate(error) => write!(formatter, "duplicate-name scan failed: {error}"),
            Self::Extents(error) => write!(formatter, "extent graph is invalid: {error}"),
        }
    }
}

impl std::error::Error for ExfatInventoryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Discovery(error) => Some(error),
            Self::Directory(error) => Some(error),
            Self::DirectoryStream(error) => Some(error),
            Self::Image(error) => Some(error),
            Self::Allocation(error) => Some(error),
            Self::Name(error) => Some(error),
            Self::Duplicate(error) => Some(error),
            Self::Extents(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ExfatAllocationError> for ExfatInventoryError {
    fn from(error: ExfatAllocationError) -> Self {
        Self::Allocation(error)
    }
}
impl From<ImageError> for ExfatInventoryError {
    fn from(error: ImageError) -> Self {
        Self::Image(error)
    }
}

#[derive(Debug, Clone)]
struct OwnedFileEntry {
    file_attributes: u16,
    is_directory: bool,
    no_fat_chain: bool,
    name_hash: u16,
    valid_data_length: u64,
    first_cluster: u32,
    data_length: u64,
    name: Vec<u16>,
    name_padding_zeroed: bool,
    benign_secondary_entries: u8,
    timestamps: ExfatTimestamps,
}

impl From<FileEntry<'_>> for OwnedFileEntry {
    fn from(entry: FileEntry<'_>) -> Self {
        Self {
            file_attributes: entry.file_attributes,
            is_directory: entry.is_directory,
            no_fat_chain: entry.no_fat_chain,
            name_hash: entry.name_hash,
            valid_data_length: entry.valid_data_length,
            first_cluster: entry.first_cluster,
            data_length: entry.data_length,
            name: entry.name.as_units().to_vec(),
            name_padding_zeroed: entry.name_padding_zeroed,
            benign_secondary_entries: entry.benign_secondary_entries,
            timestamps: ExfatTimestamps {
                create: entry.create_timestamp,
                modified: entry.modified_timestamp,
                accessed: entry.accessed_timestamp,
                create_centiseconds: entry.create_centiseconds,
                modified_centiseconds: entry.modified_centiseconds,
                create_utc_offset: entry.create_utc_offset,
                modified_utc_offset: entry.modified_utc_offset,
                accessed_utc_offset: entry.accessed_utc_offset,
            },
        }
    }
}

#[derive(Debug)]
struct PendingDirectory {
    stream: StreamId,
    depth: usize,
    path: Vec<Vec<u16>>,
    first_cluster: u32,
    data_length: u64,
    no_fat_chain: bool,
}

#[derive(Debug)]
struct InventoryState<'a> {
    image: &'a dyn BoundedImageReader,
    boot: &'a ExfatBootSector,
    bitmap: &'a [u8],
    upcase: &'a UpcaseTable,
    limits: ExfatInventoryLimits,
    objects: Vec<ExfatObjectRecord>,
    extents: Vec<Extent>,
    owners: HashMap<u32, StreamId>,
    pending: VecDeque<PendingDirectory>,
    preservation: ExfatPreservationEvidence,
    next_stream: u64,
    directory_count: usize,
    directory_bytes: u64,
    logical_bytes: u64,
    cluster_work: usize,
}

/// Inventories every live object in an exFAT regular-file image without reading file payloads.
///
/// # Errors
///
/// Returns [`ExfatInventoryError`] on malformed metadata, cap exhaustion, a bad name hash,
/// duplicate sibling names, bitmap disagreement, cluster overlap/orphaning, or extent failure.
#[allow(clippy::too_many_lines)]
pub fn inventory_image(
    image: &ImageFile,
    boot: &ExfatBootSector,
    limits: ExfatInventoryLimits,
) -> Result<ExfatInventory, ExfatInventoryError> {
    inventory_image_with_reader(image, boot, limits)
}

#[allow(clippy::too_many_lines)]
pub(crate) fn inventory_image_with_reader(
    image: &dyn BoundedImageReader,
    boot: &ExfatBootSector,
    limits: ExfatInventoryLimits,
) -> Result<ExfatInventory, ExfatInventoryError> {
    validate_limits(boot, limits)?;
    let root = discover_root_with_reader(image, boot, limits.discovery)
        .map_err(ExfatInventoryError::Discovery)?;
    let bitmap_stream = read_stream_with_reader(
        image,
        boot,
        root.active_bitmap.first_cluster,
        root.active_bitmap.data_length,
        false,
        limits.discovery.system_stream,
    )
    .map_err(ExfatInventoryError::DirectoryStream)?;
    let root_stream = read_chain_to_end_with_reader(
        image,
        boot,
        boot.root_directory_cluster,
        limits.discovery.root_stream,
    )
    .map_err(ExfatInventoryError::DirectoryStream)?;

    let mut state = InventoryState {
        image,
        boot,
        bitmap: &bitmap_stream.bytes,
        upcase: &root.upcase_mappings,
        limits,
        objects: Vec::new(),
        extents: Vec::new(),
        owners: HashMap::new(),
        pending: VecDeque::new(),
        preservation: ExfatPreservationEvidence::default(),
        next_stream: 2,
        directory_count: 1,
        directory_bytes: u64::try_from(root_stream.bytes.len()).map_err(|_| {
            ExfatInventoryError::ArithmeticOverflow {
                calculation: "root directory length conversion",
            }
        })?,
        logical_bytes: 0,
        cluster_work: 0,
    };
    enforce_directory_bytes(&state)?;
    reserve_inventory(&mut state)?;
    add_reserved_extent(&mut state)?;
    state.claim_stream(
        ROOT_STREAM,
        &root_stream.clusters,
        ExtentKind::DirectoryData,
    )?;
    state.objects.push(ExfatObjectRecord {
        stream: ROOT_STREAM,
        parent: None,
        kind: ExfatObjectKind::RootDirectory,
        name: Vec::new(),
        path: Vec::new(),
        file_attributes: 0x10,
        timestamps: None,
        valid_data_length: u64::try_from(root_stream.bytes.len()).unwrap_or(u64::MAX),
        data_length: u64::try_from(root_stream.bytes.len()).unwrap_or(u64::MAX),
        allocation_bytes: root_stream.allocation_bytes,
        clusters: root_stream.clusters.clone(),
        flags: ExfatObjectFlags {
            no_fat_chain: false,
            name_padding_zeroed: true,
            benign_secondary_entries: 0,
        },
    });

    let (root_summary, root_files, bitmaps, upcase_entry, label_padding, volume_label) =
        parse_owned_directory(&root_stream.bytes, boot, true, limits)?;
    state.accumulate_preservation(root_summary, &root_files, label_padding)?;
    claim_system_streams(&mut state, &bitmaps, upcase_entry)?;
    state.process_children(ROOT_STREAM, 0, &[], root_files)?;

    while let Some(directory) = state.pending.pop_front() {
        let stream = read_stream_with_reader(
            image,
            boot,
            directory.first_cluster,
            directory.data_length,
            directory.no_fat_chain,
            limits.directory_stream,
        )
        .map_err(ExfatInventoryError::DirectoryStream)?;
        state.directory_bytes = state
            .directory_bytes
            .checked_add(directory.data_length)
            .ok_or(ExfatInventoryError::ArithmeticOverflow {
                calculation: "directory byte total",
            })?;
        enforce_directory_bytes(&state)?;
        // The allocation was already proven and claimed when the object was discovered.
        debug_assert_eq!(
            stream.clusters,
            state
                .objects
                .iter()
                .find(|object| object.stream == directory.stream)
                .map(|object| &object.clusters)
                .cloned()
                .unwrap_or_default()
        );
        let (summary, files, _, _, label_padding, _) =
            parse_owned_directory(&stream.bytes, boot, false, limits)?;
        state.accumulate_preservation(summary, &files, label_padding)?;
        state.process_children(directory.stream, directory.depth, &directory.path, files)?;
    }

    let allocated_bad_clusters = state.finish_cluster_ownership()?;
    let volume_bytes = boot
        .volume_length_sectors
        .checked_mul(u64::from(boot.bytes_per_sector))
        .ok_or(ExfatInventoryError::ArithmeticOverflow {
            calculation: "volume byte length",
        })?;
    let objects = std::mem::take(&mut state.objects);
    let raw_extents = std::mem::take(&mut state.extents);
    let preservation = state.preservation;
    drop(state);
    let extents = ExtentGraph::build(raw_extents, volume_bytes, limits.max_extents)
        .map_err(ExfatInventoryError::Extents)?;
    Ok(ExfatInventory {
        root,
        volume_serial_number: boot.volume_serial_number,
        volume_label,
        objects,
        extents,
        preservation,
        allocated_bad_clusters,
    })
}

fn validate_limits(
    boot: &ExfatBootSector,
    limits: ExfatInventoryLimits,
) -> Result<(), ExfatInventoryError> {
    if limits.max_objects == 0 {
        return Err(ExfatInventoryError::InvalidLimits("max_objects is zero"));
    }
    if limits.max_directories == 0 {
        return Err(ExfatInventoryError::InvalidLimits(
            "max_directories is zero",
        ));
    }
    if limits.max_directory_bytes == 0 || limits.max_logical_bytes == 0 {
        return Err(ExfatInventoryError::InvalidLimits(
            "byte limits must be non-zero",
        ));
    }
    if limits.max_clusters == 0 || limits.max_stream_clusters == 0 {
        return Err(ExfatInventoryError::InvalidLimits(
            "cluster limits must be non-zero",
        ));
    }
    if limits.max_extents == 0 || limits.max_path_code_units == 0 {
        return Err(ExfatInventoryError::InvalidLimits(
            "extent/path limits must be non-zero",
        ));
    }
    if limits.max_sibling_comparisons == 0 {
        return Err(ExfatInventoryError::InvalidLimits(
            "sibling comparison limit is zero",
        ));
    }
    if usize::try_from(boot.cluster_count).unwrap_or(usize::MAX) > limits.max_clusters {
        return Err(ExfatInventoryError::VolumeClusterLimitExceeded {
            actual: boot.cluster_count,
            maximum: limits.max_clusters,
        });
    }
    Ok(())
}

fn reserve_inventory(state: &mut InventoryState<'_>) -> Result<(), ExfatInventoryError> {
    state
        .objects
        .try_reserve(state.limits.max_objects.min(4096))
        .map_err(|_| ExfatInventoryError::AllocationFailed)?;
    state
        .extents
        .try_reserve(state.limits.max_extents.min(4096))
        .map_err(|_| ExfatInventoryError::AllocationFailed)?;
    state
        .owners
        .try_reserve(state.limits.max_clusters)
        .map_err(|_| ExfatInventoryError::AllocationFailed)?;
    Ok(())
}

const fn enforce_directory_bytes(state: &InventoryState<'_>) -> Result<(), ExfatInventoryError> {
    if state.directory_bytes > state.limits.max_directory_bytes {
        Err(ExfatInventoryError::DirectoryByteLimitExceeded {
            required: state.directory_bytes,
            maximum: state.limits.max_directory_bytes,
        })
    } else {
        Ok(())
    }
}

fn add_reserved_extent(state: &mut InventoryState<'_>) -> Result<(), ExfatInventoryError> {
    let length = u64::from(state.boot.cluster_heap_offset_sectors)
        .checked_mul(u64::from(state.boot.bytes_per_sector))
        .ok_or(ExfatInventoryError::ArithmeticOverflow {
            calculation: "pre-heap reserved bytes",
        })?;
    if length != 0 {
        state.push_extent(Extent {
            stream: RESERVED_STREAM,
            logical_offset: 0,
            length,
            placement: Placement::Physical { byte_offset: 0 },
            kind: ExtentKind::FileSystemMetadata,
        })?;
    }
    Ok(())
}

type ParsedDirectory = (
    DirectorySummary,
    Vec<OwnedFileEntry>,
    Vec<AllocationBitmapEntry>,
    Option<UpcaseTableEntry>,
    bool,
    Option<VolumeLabelEntry>,
);

fn parse_owned_directory(
    bytes: &[u8],
    boot: &ExfatBootSector,
    is_root: bool,
    limits: ExfatInventoryLimits,
) -> Result<ParsedDirectory, ExfatInventoryError> {
    let mut files = Vec::new();
    let mut bitmaps = Vec::new();
    let mut upcase = None;
    let mut label_padding = true;
    let mut volume_label = None;
    let summary = parse_directory(
        bytes,
        DirectoryContext {
            cluster_count: boot.cluster_count,
            bytes_per_cluster: boot.bytes_per_cluster,
            number_of_fats: boot.number_of_fats,
            is_root,
            max_entries: limits.discovery.max_directory_entries,
            max_secondary_entries: limits.discovery.max_secondary_entries,
        },
        |record| match record {
            DirectoryRecord::File(file) => files.push(OwnedFileEntry::from(file)),
            DirectoryRecord::AllocationBitmap(entry) => bitmaps.push(entry),
            DirectoryRecord::UpcaseTable(entry) => upcase = Some(entry),
            DirectoryRecord::VolumeLabel(entry) => {
                label_padding &= entry.padding_zeroed;
                if entry.padding_zeroed {
                    volume_label = Some(entry);
                }
            }
            DirectoryRecord::Unused { .. } | DirectoryRecord::BenignPrimary { .. } => {}
        },
    )
    .map_err(ExfatInventoryError::Directory)?;
    Ok((summary, files, bitmaps, upcase, label_padding, volume_label))
}

fn claim_system_streams(
    state: &mut InventoryState<'_>,
    bitmaps: &[AllocationBitmapEntry],
    upcase: Option<UpcaseTableEntry>,
) -> Result<(), ExfatInventoryError> {
    for bitmap in bitmaps {
        let stream = StreamId(BITMAP_STREAM_BASE - u64::from(bitmap.bitmap_identifier));
        let fat = FatIndex::from_bitmap_identifier(bitmap.bitmap_identifier).ok_or(
            ExfatInventoryError::InvalidLimits("validated bitmap has invalid identifier"),
        )?;
        let clusters = state.resolve_clusters_from_fat(
            stream,
            bitmap.first_cluster,
            bitmap.data_length,
            false,
            fat,
        )?;
        state.claim_stream(stream, &clusters, ExtentKind::FileSystemMetadata)?;
    }
    let upcase = upcase.ok_or(ExfatInventoryError::InvalidLimits(
        "validated root omitted Up-case descriptor",
    ))?;
    let clusters = state.resolve_clusters(
        UPCASE_STREAM,
        upcase.first_cluster,
        upcase.data_length,
        false,
    )?;
    state.claim_stream(UPCASE_STREAM, &clusters, ExtentKind::FileSystemMetadata)
}

impl InventoryState<'_> {
    fn accumulate_preservation(
        &mut self,
        summary: DirectorySummary,
        files: &[OwnedFileEntry],
        label_padding: bool,
    ) -> Result<(), ExfatInventoryError> {
        self.preservation.unused_directory_entries = self
            .preservation
            .unused_directory_entries
            .checked_add(u64::try_from(summary.unused_entries).map_err(|_| {
                ExfatInventoryError::ArithmeticOverflow {
                    calculation: "unused entry count conversion",
                }
            })?)
            .ok_or(ExfatInventoryError::ArithmeticOverflow {
                calculation: "unused entry count",
            })?;
        self.preservation.benign_primary_sets = self
            .preservation
            .benign_primary_sets
            .checked_add(u64::try_from(summary.benign_primary_sets).map_err(|_| {
                ExfatInventoryError::ArithmeticOverflow {
                    calculation: "benign primary count conversion",
                }
            })?)
            .ok_or(ExfatInventoryError::ArithmeticOverflow {
                calculation: "benign primary count",
            })?;
        for file in files {
            self.preservation.benign_secondary_entries = self
                .preservation
                .benign_secondary_entries
                .checked_add(u64::from(file.benign_secondary_entries))
                .ok_or(ExfatInventoryError::ArithmeticOverflow {
                    calculation: "benign secondary count",
                })?;
            if !file.name_padding_zeroed {
                self.preservation.nonzero_name_padding_sets = self
                    .preservation
                    .nonzero_name_padding_sets
                    .checked_add(1)
                    .ok_or(ExfatInventoryError::ArithmeticOverflow {
                        calculation: "name padding count",
                    })?;
            }
        }
        self.preservation.nonzero_volume_label_padding |= !label_padding;
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn process_children(
        &mut self,
        parent: StreamId,
        parent_depth: usize,
        parent_path: &[Vec<u16>],
        files: Vec<OwnedFileEntry>,
    ) -> Result<(), ExfatInventoryError> {
        let names: Vec<&[u16]> = files.iter().map(|file| file.name.as_slice()).collect();
        if let Some(duplicate) = self
            .upcase
            .find_duplicate_names(
                &names,
                DuplicateLimits {
                    max_names: self.limits.max_objects,
                    max_name_code_units: MAX_FILE_NAME_CODE_UNITS,
                    max_comparisons: self.limits.max_sibling_comparisons,
                },
            )
            .map_err(ExfatInventoryError::Duplicate)?
        {
            return Err(ExfatInventoryError::DuplicateSiblingName {
                directory: parent,
                first: duplicate.first_index,
                second: duplicate.second_index,
            });
        }
        for file in files {
            if self.objects.len() >= self.limits.max_objects {
                return Err(ExfatInventoryError::ObjectLimitExceeded {
                    maximum: self.limits.max_objects,
                });
            }
            let stream = StreamId(self.next_stream);
            self.next_stream =
                self.next_stream
                    .checked_add(1)
                    .ok_or(ExfatInventoryError::ArithmeticOverflow {
                        calculation: "stream identifier",
                    })?;
            let computed = self
                .upcase
                .name_hash(&file.name, MAX_FILE_NAME_CODE_UNITS)
                .map_err(ExfatInventoryError::Name)?;
            if computed != file.name_hash {
                return Err(ExfatInventoryError::NameHashMismatch {
                    stream,
                    stored: file.name_hash,
                    computed,
                });
            }
            let mut path = parent_path.to_vec();
            path.push(file.name.clone());
            let path_units = path
                .iter()
                .try_fold(path.len().saturating_sub(1), |sum, component| {
                    sum.checked_add(component.len())
                })
                .ok_or(ExfatInventoryError::ArithmeticOverflow {
                    calculation: "path length",
                })?;
            if path_units > self.limits.max_path_code_units {
                return Err(ExfatInventoryError::PathLimitExceeded {
                    required: path_units,
                    maximum: self.limits.max_path_code_units,
                });
            }
            self.logical_bytes = self.logical_bytes.checked_add(file.data_length).ok_or(
                ExfatInventoryError::ArithmeticOverflow {
                    calculation: "logical byte total",
                },
            )?;
            if self.logical_bytes > self.limits.max_logical_bytes {
                return Err(ExfatInventoryError::LogicalByteLimitExceeded {
                    required: self.logical_bytes,
                    maximum: self.limits.max_logical_bytes,
                });
            }
            let clusters = self.resolve_clusters(
                stream,
                file.first_cluster,
                file.data_length,
                file.no_fat_chain,
            )?;
            let kind = if file.is_directory {
                ExtentKind::DirectoryData
            } else {
                ExtentKind::FileData
            };
            self.claim_stream(stream, &clusters, kind)?;
            let allocation_bytes = u64::try_from(clusters.len())
                .map_err(|_| ExfatInventoryError::ArithmeticOverflow {
                    calculation: "allocation cluster count conversion",
                })?
                .checked_mul(u64::from(self.boot.bytes_per_cluster))
                .ok_or(ExfatInventoryError::ArithmeticOverflow {
                    calculation: "object allocation bytes",
                })?;
            let object_kind = if file.is_directory {
                ExfatObjectKind::Directory
            } else {
                ExfatObjectKind::File
            };
            self.objects.push(ExfatObjectRecord {
                stream,
                parent: Some(parent),
                kind: object_kind,
                name: file.name.clone(),
                path: path.clone(),
                file_attributes: file.file_attributes,
                timestamps: Some(file.timestamps),
                valid_data_length: file.valid_data_length,
                data_length: file.data_length,
                allocation_bytes,
                clusters: clusters.clone(),
                flags: ExfatObjectFlags {
                    no_fat_chain: file.no_fat_chain,
                    name_padding_zeroed: file.name_padding_zeroed,
                    benign_secondary_entries: file.benign_secondary_entries,
                },
            });
            if file.is_directory {
                let depth =
                    parent_depth
                        .checked_add(1)
                        .ok_or(ExfatInventoryError::ArithmeticOverflow {
                            calculation: "directory depth",
                        })?;
                if depth > self.limits.max_depth {
                    return Err(ExfatInventoryError::DepthLimitExceeded {
                        depth,
                        maximum: self.limits.max_depth,
                    });
                }
                if self.directory_count >= self.limits.max_directories {
                    return Err(ExfatInventoryError::DirectoryLimitExceeded {
                        maximum: self.limits.max_directories,
                    });
                }
                self.directory_count += 1;
                self.pending.push_back(PendingDirectory {
                    stream,
                    depth,
                    path,
                    first_cluster: file.first_cluster,
                    data_length: file.data_length,
                    no_fat_chain: file.no_fat_chain,
                });
            }
        }
        Ok(())
    }

    fn resolve_clusters(
        &mut self,
        stream: StreamId,
        first: u32,
        length: u64,
        no_fat_chain: bool,
    ) -> Result<Vec<u32>, ExfatInventoryError> {
        self.resolve_clusters_from_fat(
            stream,
            first,
            length,
            no_fat_chain,
            FatIndex::active(self.boot),
        )
    }

    fn resolve_clusters_from_fat(
        &mut self,
        stream: StreamId,
        first: u32,
        length: u64,
        no_fat_chain: bool,
        fat: FatIndex,
    ) -> Result<Vec<u32>, ExfatInventoryError> {
        if length == 0 {
            return Ok(Vec::new());
        }
        let needed = length.div_ceil(u64::from(self.boot.bytes_per_cluster));
        if needed > u64::try_from(self.limits.max_stream_clusters).unwrap_or(u64::MAX) {
            return Err(ExfatInventoryError::StreamClusterLimitExceeded {
                required: needed,
                maximum: self.limits.max_stream_clusters,
            });
        }
        let count =
            usize::try_from(needed).map_err(|_| ExfatInventoryError::ArithmeticOverflow {
                calculation: "stream cluster count conversion",
            })?;
        self.cluster_work = self.cluster_work.checked_add(count).ok_or(
            ExfatInventoryError::ArithmeticOverflow {
                calculation: "cluster work",
            },
        )?;
        if self.cluster_work > self.limits.max_clusters {
            return Err(ExfatInventoryError::ClusterWorkLimitExceeded {
                maximum: self.limits.max_clusters,
            });
        }
        let mut clusters = Vec::new();
        clusters
            .try_reserve_exact(count)
            .map_err(|_| ExfatInventoryError::AllocationFailed)?;
        if no_fat_chain {
            for offset in 0..count {
                let cluster = first
                    .checked_add(u32::try_from(offset).map_err(|_| {
                        ExfatInventoryError::ArithmeticOverflow {
                            calculation: "contiguous cluster index",
                        }
                    })?)
                    .ok_or(ExfatInventoryError::ArithmeticOverflow {
                        calculation: "contiguous cluster",
                    })?;
                cluster_byte_offset(self.boot, cluster)?;
                clusters.push(cluster);
            }
            return Ok(clusters);
        }
        let mut seen = HashSet::new();
        seen.try_reserve(count)
            .map_err(|_| ExfatInventoryError::AllocationFailed)?;
        let mut current = first;
        for index in 0..count {
            cluster_byte_offset(self.boot, current)?;
            if !seen.insert(current) {
                return Err(ExfatInventoryError::FatChainCycle {
                    stream,
                    cluster: current,
                });
            }
            clusters.push(current);
            match self.read_fat_entry_from(fat, current)? {
                FatEntry::Next(next) if index + 1 < count => current = next,
                FatEntry::Next(next) => {
                    return Err(ExfatInventoryError::FatChainContinues { stream, next });
                }
                FatEntry::EndOfChain if index + 1 == count => return Ok(clusters),
                FatEntry::EndOfChain | FatEntry::Free | FatEntry::Bad => {
                    return Err(ExfatInventoryError::FatChainEndedEarly {
                        stream,
                        cluster: current,
                    });
                }
            }
        }
        Ok(clusters)
    }

    fn read_fat_entry(&self, cluster: u32) -> Result<FatEntry, ExfatInventoryError> {
        self.read_fat_entry_from(FatIndex::active(self.boot), cluster)
    }

    fn read_fat_entry_from(
        &self,
        fat: FatIndex,
        cluster: u32,
    ) -> Result<FatEntry, ExfatInventoryError> {
        cluster_byte_offset(self.boot, cluster)?;
        let sector = u64::from(self.boot.fat_offset_sectors)
            .checked_add(
                u64::from(match fat {
                    FatIndex::First => 0_u8,
                    FatIndex::Second => 1_u8,
                })
                .checked_mul(u64::from(self.boot.fat_length_sectors))
                .ok_or(ExfatInventoryError::ArithmeticOverflow {
                    calculation: "selected FAT offset",
                })?,
            )
            .ok_or(ExfatInventoryError::ArithmeticOverflow {
                calculation: "selected FAT sector",
            })?;
        let offset = sector
            .checked_mul(u64::from(self.boot.bytes_per_sector))
            .and_then(|base| base.checked_add(u64::from(cluster) * 4))
            .ok_or(ExfatInventoryError::ArithmeticOverflow {
                calculation: "FAT entry offset",
            })?;
        let bytes = self.image.read_exact_at(offset, 4)?;
        let value = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        match value {
            0 => Ok(FatEntry::Free),
            0xffff_fff7 => Ok(FatEntry::Bad),
            u32::MAX => Ok(FatEntry::EndOfChain),
            next if cluster_byte_offset(self.boot, next).is_ok() => Ok(FatEntry::Next(next)),
            _ => Err(ExfatAllocationError::InvalidFatValue { cluster, value }.into()),
        }
    }

    fn claim_stream(
        &mut self,
        stream: StreamId,
        clusters: &[u32],
        kind: ExtentKind,
    ) -> Result<(), ExfatInventoryError> {
        for &cluster in clusters {
            if !bitmap_cluster_is_allocated(self.bitmap, self.boot, cluster)? {
                return Err(ExfatInventoryError::ClusterMarkedFree { stream, cluster });
            }
            if let Some(&first) = self.owners.get(&cluster) {
                return Err(ExfatInventoryError::ClusterOverlap {
                    cluster,
                    first,
                    second: stream,
                });
            }
            self.owners.insert(cluster, stream);
        }
        self.push_cluster_extents(stream, clusters, kind)
    }

    fn push_cluster_extents(
        &mut self,
        stream: StreamId,
        clusters: &[u32],
        kind: ExtentKind,
    ) -> Result<(), ExfatInventoryError> {
        if clusters.is_empty() {
            return Ok(());
        }
        let cluster_bytes = u64::from(self.boot.bytes_per_cluster);
        let mut run_start = 0;
        for index in 1..=clusters.len() {
            let continues =
                index < clusters.len() && clusters[index] == clusters[index - 1].saturating_add(1);
            if continues {
                continue;
            }
            let count = index - run_start;
            let logical_offset = u64::try_from(run_start)
                .map_err(|_| ExfatInventoryError::ArithmeticOverflow {
                    calculation: "extent logical cluster",
                })?
                .checked_mul(cluster_bytes)
                .ok_or(ExfatInventoryError::ArithmeticOverflow {
                    calculation: "extent logical offset",
                })?;
            let length = u64::try_from(count)
                .map_err(|_| ExfatInventoryError::ArithmeticOverflow {
                    calculation: "extent cluster count",
                })?
                .checked_mul(cluster_bytes)
                .ok_or(ExfatInventoryError::ArithmeticOverflow {
                    calculation: "extent length",
                })?;
            let byte_offset = cluster_byte_offset(self.boot, clusters[run_start])?;
            self.push_extent(Extent {
                stream,
                logical_offset,
                length,
                placement: Placement::Physical { byte_offset },
                kind,
            })?;
            run_start = index;
        }
        Ok(())
    }

    fn push_extent(&mut self, extent: Extent) -> Result<(), ExfatInventoryError> {
        if self.extents.len() >= self.limits.max_extents {
            return Err(ExfatInventoryError::ExtentLimitExceeded {
                maximum: self.limits.max_extents,
            });
        }
        self.extents.push(extent);
        Ok(())
    }

    fn finish_cluster_ownership(&mut self) -> Result<u64, ExfatInventoryError> {
        let mut bad = 0_u64;
        for relative in 0..self.boot.cluster_count {
            let cluster =
                relative
                    .checked_add(2)
                    .ok_or(ExfatInventoryError::ArithmeticOverflow {
                        calculation: "cluster scan index",
                    })?;
            if !bitmap_cluster_is_allocated(self.bitmap, self.boot, cluster)?
                || self.owners.contains_key(&cluster)
            {
                continue;
            }
            let fat_entry = self.read_fat_entry(cluster)?;
            if fat_entry != FatEntry::Bad {
                return Err(ExfatInventoryError::AllocatedClusterUnowned { cluster, fat_entry });
            }
            self.owners.insert(cluster, BAD_CLUSTER_STREAM);
            let cluster_bytes = u64::from(self.boot.bytes_per_cluster);
            let logical_offset =
                bad.checked_mul(cluster_bytes)
                    .ok_or(ExfatInventoryError::ArithmeticOverflow {
                        calculation: "bad-cluster logical offset",
                    })?;
            self.push_extent(Extent {
                stream: BAD_CLUSTER_STREAM,
                logical_offset,
                length: cluster_bytes,
                placement: Placement::Physical {
                    byte_offset: cluster_byte_offset(self.boot, cluster)?,
                },
                kind: ExtentKind::BadCluster,
            })?;
            bad = bad
                .checked_add(1)
                .ok_or(ExfatInventoryError::ArithmeticOverflow {
                    calculation: "bad cluster count",
                })?;
        }
        Ok(bad)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::FileSystem;
    use crate::GuaranteeMode;
    use crate::fs::exfat_normalize::{ExfatNormalizeLimits, normalize_inventory};
    use crate::fs::exfat_upcase::{UpcaseLimits, table_checksum};
    use crate::object::ObjectGraphLimits;
    use crate::preservation::{
        FieldDisposition, PreservationField, PreservationLimits, decode_escrow, evaluate_exfat,
    };

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
    const ENTRY: usize = 32;

    struct TempImage(PathBuf);
    impl TempImage {
        fn write(bytes: &[u8]) -> Self {
            let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "starconverter-exfat-inventory-{}-{id}.img",
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

    const fn boot() -> ExfatBootSector {
        ExfatBootSector {
            partition_offset_sectors: 0,
            volume_length_sectors: 2048,
            fat_offset_sectors: 24,
            fat_length_sectors: 16,
            cluster_heap_offset_sectors: 40,
            cluster_count: 2008,
            root_directory_cluster: 2,
            volume_serial_number: 1,
            filesystem_revision: 0x100,
            volume_flags: 0,
            bytes_per_sector_shift: 9,
            sectors_per_cluster_shift: 0,
            number_of_fats: 1,
            drive_select: 0x80,
            percent_in_use: None,
            bytes_per_sector: 512,
            sectors_per_cluster: 1,
            bytes_per_cluster: 512,
        }
    }
    fn cluster_offset(cluster: u32) -> usize {
        40 * 512 + usize::try_from(cluster - 2).unwrap() * 512
    }
    fn set_fat(image: &mut [u8], cluster: u32, value: u32) {
        let offset = 24 * 512 + usize::try_from(cluster).unwrap() * 4;
        image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn mark(image: &mut [u8], cluster: u32, allocated: bool) {
        let offset = cluster_offset(3) + usize::try_from((cluster - 2) / 8).unwrap();
        let mask = 1 << ((cluster - 2) % 8);
        if allocated {
            image[offset] |= mask;
        } else {
            image[offset] &= !mask;
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
    fn set_checksum(set: &mut [u8]) {
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
    fn upcase_bytes() -> Vec<u8> {
        let mut words = vec![0xffff, 97];
        words.extend(u16::from(b'A')..=u16::from(b'Z'));
        words.extend([0xffff, 65_413]);
        words.into_iter().flat_map(u16::to_le_bytes).collect()
    }
    fn name_hash(name: &[u16], encoded: &[u8]) -> u16 {
        UpcaseTable::parse(
            encoded,
            table_checksum(encoded),
            UpcaseLimits::COMPLETE_TABLE,
        )
        .unwrap()
        .name_hash(name, 255)
        .unwrap()
    }
    fn file_set(name: &str, cluster: u32, directory: bool, encoded: &[u8]) -> Vec<u8> {
        let name: Vec<u16> = name.encode_utf16().collect();
        let mut set = vec![0_u8; ENTRY * 3];
        set[0] = 0x85;
        set[1] = 2;
        put_u16(&mut set, 4, if directory { 0x10 } else { 0x20 });
        let timestamp = ((2024 - 1980) << 25) | (1 << 21) | (1 << 16);
        for offset in [8, 12, 16] {
            put_u32(&mut set, offset, timestamp);
        }
        set[ENTRY] = 0xc0;
        set[ENTRY + 1] = 3;
        set[ENTRY + 3] = u8::try_from(name.len()).unwrap();
        put_u16(&mut set, ENTRY + 4, name_hash(&name, encoded));
        let length = if directory { 512 } else { 100 };
        put_u64(&mut set, ENTRY + 8, length);
        put_u32(&mut set, ENTRY + 20, cluster);
        put_u64(&mut set, ENTRY + 24, length);
        set[ENTRY * 2] = 0xc1;
        for (index, unit) in name.iter().enumerate() {
            put_u16(&mut set, ENTRY * 2 + 2 + index * 2, *unit);
        }
        set_checksum(&mut set);
        set
    }
    fn fixture(files: &[(&str, u32, bool)]) -> (Vec<u8>, Vec<u8>) {
        let encoded = upcase_bytes();
        let mut image = vec![0_u8; 2048 * 512];
        set_fat(&mut image, 2, u32::MAX);
        set_fat(&mut image, 3, u32::MAX);
        set_fat(&mut image, 4, u32::MAX);
        let root = cluster_offset(2);
        image[root] = 0x81;
        put_u32(&mut image, root + 20, 3);
        put_u64(&mut image, root + 24, 251);
        image[root + ENTRY] = 0x82;
        put_u32(&mut image, root + ENTRY + 4, table_checksum(&encoded));
        put_u32(&mut image, root + ENTRY + 20, 4);
        put_u64(
            &mut image,
            root + ENTRY + 24,
            u64::try_from(encoded.len()).unwrap(),
        );
        let mut cursor = root + ENTRY * 2;
        for (name, cluster, directory) in files {
            let set = file_set(name, *cluster, *directory, &encoded);
            image[cursor..cursor + set.len()].copy_from_slice(&set);
            cursor += set.len();
            mark(&mut image, *cluster, true);
            if *directory {
                image[cluster_offset(*cluster)..cluster_offset(*cluster) + 512].fill(0);
            }
        }
        image[cluster_offset(4)..cluster_offset(4) + encoded.len()].copy_from_slice(&encoded);
        for cluster in [2, 3, 4] {
            mark(&mut image, cluster, true);
        }
        (image, encoded)
    }

    fn set_volume_label(image: &mut [u8], label: &str, nonzero_padding: bool) {
        let units = label.encode_utf16().collect::<Vec<_>>();
        assert!(units.len() <= 11);
        let offset = cluster_offset(2) + ENTRY * 2;
        image[offset] = 0x83;
        image[offset + 1] = u8::try_from(units.len()).expect("label length");
        for (index, unit) in units.iter().enumerate() {
            put_u16(image, offset + 2 + index * 2, *unit);
        }
        if nonzero_padding {
            put_u16(image, offset + 2 + units.len() * 2, 0x2605);
        }
    }

    const fn normalize_limits() -> ExfatNormalizeLimits {
        ExfatNormalizeLimits {
            graph: ObjectGraphLimits {
                max_objects: 64,
                max_entries: 64,
                max_streams: 64,
                max_name_code_units: 255,
            },
            max_extents: 256,
        }
    }
    const fn limits() -> ExfatInventoryLimits {
        ExfatInventoryLimits {
            discovery: ExfatDiscoveryLimits {
                root_stream: StreamReadLimits {
                    max_bytes: 4096,
                    max_clusters: 8,
                },
                system_stream: StreamReadLimits {
                    max_bytes: 4096,
                    max_clusters: 8,
                },
                max_directory_entries: 128,
                max_secondary_entries: 32,
            },
            directory_stream: StreamReadLimits {
                max_bytes: 4096,
                max_clusters: 8,
            },
            max_objects: 64,
            max_directories: 16,
            max_depth: 8,
            max_directory_bytes: 32 * 1024,
            max_logical_bytes: 1024 * 1024,
            max_clusters: 4096,
            max_stream_clusters: 64,
            max_extents: 256,
            max_path_code_units: 1024,
            max_sibling_comparisons: 4096,
        }
    }

    #[test]
    fn inventories_file_without_reading_payload_and_builds_extents() {
        let (mut bytes, _) = fixture(&[("hello.txt", 5, false)]);
        bytes[cluster_offset(5)..cluster_offset(5) + 100].fill(0xa5);
        let temp = TempImage::write(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();
        let inventory = inventory_image(&image, &boot(), limits()).unwrap();
        assert_eq!(inventory.objects.len(), 2);
        assert_eq!(
            inventory.objects[1].name,
            "hello.txt".encode_utf16().collect::<Vec<_>>()
        );
        assert_eq!(inventory.objects[1].clusters, vec![5]);
        assert_eq!(inventory.objects[1].allocation_bytes, 512);
        assert_eq!(inventory.allocated_bad_clusters, 0);
        assert!(
            inventory
                .extents
                .extents()
                .iter()
                .any(|extent| extent.stream == inventory.objects[1].stream
                    && extent.kind == ExtentKind::FileData)
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn volume_identity_survives_inventory_normalization_policy_and_escrow() {
        let (mut bytes, _) = fixture(&[]);
        set_volume_label(&mut bytes, "STAR", false);
        let temp = TempImage::write(&bytes);
        let image = ImageFile::open(&temp.0).expect("open image");
        let mut geometry = boot();
        geometry.volume_serial_number = 0x89ab_cdef;

        let inventory = inventory_image(&image, &geometry, limits()).expect("inventory");
        assert_eq!(inventory.volume_serial_number, 0x89ab_cdef);
        assert_eq!(
            inventory
                .volume_label
                .as_ref()
                .expect("exact label")
                .as_units(),
            "STAR".encode_utf16().collect::<Vec<_>>()
        );
        let normalized = normalize_inventory(&inventory, normalize_limits()).expect("normalize");
        assert_eq!(normalized.preservation.volume_serial_number, 0x89ab_cdef);
        assert_eq!(
            normalized
                .preservation
                .volume_label
                .as_ref()
                .expect("sidecar label")
                .as_units(),
            "STAR".encode_utf16().collect::<Vec<_>>()
        );

        let strict = evaluate_exfat(
            &normalized,
            FileSystem::Ntfs,
            GuaranteeMode::Strict,
            PreservationLimits::default(),
        )
        .expect("strict policy");
        for field in [
            PreservationField::VolumeSerial,
            PreservationField::VolumeLabel,
        ] {
            assert_eq!(
                strict
                    .assessments
                    .iter()
                    .find(|assessment| assessment.field == field)
                    .expect("identity assessment")
                    .disposition,
                FieldDisposition::CanonicalTransform
            );
            assert!(!strict.blockers.contains(&field));
        }

        let first_escrow = evaluate_exfat(
            &normalized,
            FileSystem::Ntfs,
            GuaranteeMode::Escrow,
            PreservationLimits::default(),
        )
        .expect("escrow policy")
        .escrow
        .expect("escrow bytes");
        let second_escrow = evaluate_exfat(
            &normalized,
            FileSystem::Ntfs,
            GuaranteeMode::Escrow,
            PreservationLimits::default(),
        )
        .expect("second escrow policy")
        .escrow
        .expect("second escrow bytes");
        assert_eq!(first_escrow, second_escrow);
        let decoded =
            decode_escrow(&first_escrow, PreservationLimits::default()).expect("decode escrow");
        assert_eq!(
            decoded.exfat_volume_identity,
            Some(crate::preservation::ExfatVolumeIdentity {
                volume_serial_number: 0x89ab_cdef,
                volume_label: crate::preservation::ExfatVolumeLabelIdentity::Exact(
                    "STAR".encode_utf16().collect()
                )
            })
        );
    }

    #[test]
    fn nonzero_volume_label_padding_remains_unretained_and_refused() {
        let (mut bytes, _) = fixture(&[]);
        set_volume_label(&mut bytes, "STAR", true);
        let temp = TempImage::write(&bytes);
        let image = ImageFile::open(&temp.0).expect("open image");
        let inventory = inventory_image(&image, &boot(), limits()).expect("inventory");
        assert!(inventory.volume_label.is_none());
        assert!(inventory.preservation.nonzero_volume_label_padding);
        let normalized = normalize_inventory(&inventory, normalize_limits()).expect("normalize");
        let report = evaluate_exfat(
            &normalized,
            FileSystem::Ntfs,
            GuaranteeMode::Escrow,
            PreservationLimits::default(),
        )
        .expect("policy");
        assert!(!report.permitted);
        assert!(report.blockers.contains(&PreservationField::VolumeLabel));
        assert!(report.blockers.contains(&PreservationField::ExfatPadding));
        let decoded = decode_escrow(
            report.escrow.as_deref().expect("escrow evidence"),
            PreservationLimits::default(),
        )
        .expect("decode escrow evidence");
        assert_eq!(
            decoded
                .exfat_volume_identity
                .expect("exFAT volume identity")
                .volume_label,
            crate::preservation::ExfatVolumeLabelIdentity::UnretainedNonzeroPadding
        );
    }

    #[test]
    fn recursively_inventories_a_child_directory() {
        let (mut bytes, encoded) = fixture(&[("sub", 5, true)]);
        let child = file_set("nested.bin", 6, false, &encoded);
        let offset = cluster_offset(5);
        bytes[offset..offset + child.len()].copy_from_slice(&child);
        mark(&mut bytes, 6, true);
        let temp = TempImage::write(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();
        let inventory = inventory_image(&image, &boot(), limits()).unwrap();
        assert_eq!(inventory.objects.len(), 3);
        assert_eq!(inventory.objects[2].path.len(), 2);
        assert_eq!(
            inventory.objects[2].parent,
            Some(inventory.objects[1].stream)
        );
    }

    #[test]
    fn rejects_bad_hash_and_case_insensitive_sibling_duplicate() {
        let (mut bytes, _) = fixture(&[("name", 5, false)]);
        let stream = cluster_offset(2) + ENTRY * 3;
        put_u16(&mut bytes, stream + 4, 0);
        let set_start = cluster_offset(2) + ENTRY * 2;
        set_checksum(&mut bytes[set_start..set_start + ENTRY * 3]);
        let temp = TempImage::write(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();
        assert!(matches!(
            inventory_image(&image, &boot(), limits()),
            Err(ExfatInventoryError::NameHashMismatch { .. })
        ));

        let (bytes, _) = fixture(&[("same", 5, false), ("SAME", 6, false)]);
        let temp = TempImage::write(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();
        assert!(matches!(
            inventory_image(&image, &boot(), limits()),
            Err(ExfatInventoryError::DuplicateSiblingName { .. })
        ));
    }

    #[test]
    fn rejects_free_or_multiply_owned_object_clusters() {
        let (mut bytes, _) = fixture(&[("a", 5, false)]);
        mark(&mut bytes, 5, false);
        let temp = TempImage::write(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();
        assert!(matches!(
            inventory_image(&image, &boot(), limits()),
            Err(ExfatInventoryError::ClusterMarkedFree { cluster: 5, .. })
        ));
        let (bytes, _) = fixture(&[("a", 5, false), ("b", 5, false)]);
        let temp = TempImage::write(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();
        assert!(matches!(
            inventory_image(&image, &boot(), limits()),
            Err(ExfatInventoryError::ClusterOverlap { cluster: 5, .. })
        ));
    }

    #[test]
    fn distinguishes_bad_clusters_from_orphaned_allocation() {
        let (mut bytes, _) = fixture(&[]);
        mark(&mut bytes, 7, true);
        set_fat(&mut bytes, 7, 0xffff_fff7);
        let temp = TempImage::write(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();
        assert_eq!(
            inventory_image(&image, &boot(), limits())
                .unwrap()
                .allocated_bad_clusters,
            1
        );
        let (mut bytes, _) = fixture(&[]);
        mark(&mut bytes, 7, true);
        let temp = TempImage::write(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();
        assert!(matches!(
            inventory_image(&image, &boot(), limits()),
            Err(ExfatInventoryError::AllocatedClusterUnowned {
                cluster: 7,
                fat_entry: FatEntry::Free
            })
        ));
    }

    #[test]
    fn enforces_depth_and_whole_volume_cluster_caps() {
        let (bytes, _) = fixture(&[("sub", 5, true)]);
        let temp = TempImage::write(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();
        let mut capped = limits();
        capped.max_depth = 0;
        assert!(matches!(
            inventory_image(&image, &boot(), capped),
            Err(ExfatInventoryError::DepthLimitExceeded { .. })
        ));
        let mut capped = limits();
        capped.max_clusters = 100;
        assert!(matches!(
            inventory_image(&image, &boot(), capped),
            Err(ExfatInventoryError::VolumeClusterLimitExceeded { .. })
        ));
    }

    #[test]
    fn validates_exact_fragmented_fat_chain_shape() {
        let (mut bytes, _) = fixture(&[("large.bin", 5, false)]);
        let set_start = cluster_offset(2) + ENTRY * 2;
        let stream = set_start + ENTRY;
        bytes[stream + 1] = 1;
        put_u64(&mut bytes, stream + 8, 700);
        put_u64(&mut bytes, stream + 24, 700);
        set_checksum(&mut bytes[set_start..set_start + ENTRY * 3]);
        mark(&mut bytes, 6, true);
        set_fat(&mut bytes, 5, 6);
        set_fat(&mut bytes, 6, u32::MAX);
        let temp = TempImage::write(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();
        assert_eq!(
            inventory_image(&image, &boot(), limits()).unwrap().objects[1].clusters,
            vec![5, 6]
        );

        drop(image);
        drop(temp);
        set_fat(&mut bytes, 5, u32::MAX);
        let temp = TempImage::write(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();
        assert!(matches!(
            inventory_image(&image, &boot(), limits()),
            Err(ExfatInventoryError::FatChainEndedEarly { cluster: 5, .. })
        ));

        drop(image);
        drop(temp);
        put_u64(&mut bytes, stream + 8, 1_025);
        put_u64(&mut bytes, stream + 24, 1_025);
        set_checksum(&mut bytes[set_start..set_start + ENTRY * 3]);
        set_fat(&mut bytes, 5, 6);
        set_fat(&mut bytes, 6, 5);
        let temp = TempImage::write(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();
        assert!(matches!(
            inventory_image(&image, &boot(), limits()),
            Err(ExfatInventoryError::FatChainCycle { cluster: 5, .. })
        ));
    }

    #[test]
    fn enforces_object_byte_path_stream_and_extent_caps() {
        let (bytes, _) = fixture(&[("file", 5, false)]);
        let temp = TempImage::write(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();

        let mut capped = limits();
        capped.max_objects = 1;
        assert!(matches!(
            inventory_image(&image, &boot(), capped),
            Err(ExfatInventoryError::ObjectLimitExceeded { .. })
        ));
        let mut capped = limits();
        capped.max_logical_bytes = 99;
        assert!(matches!(
            inventory_image(&image, &boot(), capped),
            Err(ExfatInventoryError::LogicalByteLimitExceeded { .. })
        ));
        let mut capped = limits();
        capped.max_path_code_units = 3;
        assert!(matches!(
            inventory_image(&image, &boot(), capped),
            Err(ExfatInventoryError::PathLimitExceeded { .. })
        ));
        let mut capped = limits();
        capped.max_stream_clusters = 0;
        assert!(matches!(
            inventory_image(&image, &boot(), capped),
            Err(ExfatInventoryError::InvalidLimits(_))
        ));
        let mut capped = limits();
        capped.max_extents = 1;
        assert!(matches!(
            inventory_image(&image, &boot(), capped),
            Err(ExfatInventoryError::ExtentLimitExceeded { .. })
        ));
        let mut capped = limits();
        capped.max_directory_bytes = 511;
        assert!(matches!(
            inventory_image(&image, &boot(), capped),
            Err(ExfatInventoryError::DirectoryByteLimitExceeded { .. })
        ));
    }

    #[test]
    fn retains_recommended_padding_and_unused_entry_evidence() {
        let (mut bytes, _) = fixture(&[("a", 5, false)]);
        let set_start = cluster_offset(2) + ENTRY * 2;
        put_u16(&mut bytes, set_start + ENTRY * 2 + 4, u16::from(b'x'));
        set_checksum(&mut bytes[set_start..set_start + ENTRY * 3]);
        bytes[set_start + ENTRY * 3] = 1;
        let temp = TempImage::write(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();
        let evidence = inventory_image(&image, &boot(), limits())
            .unwrap()
            .preservation;
        assert_eq!(evidence.nonzero_name_padding_sets, 1);
        assert_eq!(evidence.unused_directory_entries, 1);
    }

    #[test]
    fn represents_multiple_bad_clusters_without_logical_overlap() {
        let (mut bytes, _) = fixture(&[]);
        for cluster in [7, 8] {
            mark(&mut bytes, cluster, true);
            set_fat(&mut bytes, cluster, 0xffff_fff7);
        }
        let temp = TempImage::write(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();
        let inventory = inventory_image(&image, &boot(), limits()).unwrap();
        assert_eq!(inventory.allocated_bad_clusters, 2);
        assert_eq!(
            inventory
                .extents
                .extents()
                .iter()
                .filter(|extent| extent.kind == ExtentKind::BadCluster)
                .count(),
            2
        );
    }

    #[test]
    fn resolves_each_allocation_bitmap_through_its_corresponding_fat() {
        let boot = ExfatBootSector {
            partition_offset_sectors: 0,
            volume_length_sectors: 2048,
            fat_offset_sectors: 24,
            fat_length_sectors: 16,
            cluster_heap_offset_sectors: 56,
            cluster_count: 1992,
            root_directory_cluster: 2,
            volume_serial_number: 1,
            filesystem_revision: 0x100,
            volume_flags: 1,
            bytes_per_sector_shift: 9,
            sectors_per_cluster_shift: 0,
            number_of_fats: 2,
            drive_select: 0x80,
            percent_in_use: None,
            bytes_per_sector: 512,
            sectors_per_cluster: 1,
            bytes_per_cluster: 512,
        };
        let mut image_bytes = vec![0_u8; 2048 * 512];
        let heap_offset = |cluster: u32| 56 * 512 + usize::try_from(cluster - 2).unwrap() * 512;
        let fat_offset = |fat: usize, cluster: u32| {
            (24 + fat * 16) * 512 + usize::try_from(cluster).unwrap() * 4
        };
        let mut set_selected_fat = |fat: usize, cluster: u32, value: u32| {
            let offset = fat_offset(fat, cluster);
            image_bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        };

        // The active second FAT deliberately leaves the first bitmap's cluster free. Reading the
        // first bitmap's chain through the active FAT would therefore reject this valid pairing.
        set_selected_fat(0, 3, u32::MAX);
        for cluster in [2, 4, 5] {
            set_selected_fat(1, cluster, u32::MAX);
        }

        let root = heap_offset(2);
        let bitmap_length = u64::from(boot.cluster_count).div_ceil(8);
        for (entry_index, (identifier, cluster)) in [(0_u8, 3_u32), (1, 4)].into_iter().enumerate()
        {
            let entry = root + entry_index * ENTRY;
            image_bytes[entry] = 0x81;
            image_bytes[entry + 1] = identifier;
            put_u32(&mut image_bytes, entry + 20, cluster);
            put_u64(&mut image_bytes, entry + 24, bitmap_length);
        }
        let encoded = upcase_bytes();
        let upcase = root + ENTRY * 2;
        image_bytes[upcase] = 0x82;
        put_u32(&mut image_bytes, upcase + 4, table_checksum(&encoded));
        put_u32(&mut image_bytes, upcase + 20, 5);
        put_u64(
            &mut image_bytes,
            upcase + 24,
            u64::try_from(encoded.len()).unwrap(),
        );
        image_bytes[heap_offset(5)..heap_offset(5) + encoded.len()].copy_from_slice(&encoded);
        for bitmap_cluster in [3_u32, 4] {
            let bitmap = heap_offset(bitmap_cluster);
            for cluster in [2_u32, 3, 4, 5] {
                image_bytes[bitmap + usize::try_from((cluster - 2) / 8).unwrap()] |=
                    1 << ((cluster - 2) % 8);
            }
        }

        let temp = TempImage::write(&image_bytes);
        let image = ImageFile::open(&temp.0).unwrap();
        let inventory = inventory_image(&image, &boot, limits()).unwrap();
        let first_bitmap = StreamId(BITMAP_STREAM_BASE);
        let second_bitmap = StreamId(BITMAP_STREAM_BASE - 1);
        assert!(inventory.extents.extents().iter().any(|extent| {
            extent.stream == first_bitmap
                && extent.placement
                    == Placement::Physical {
                        byte_offset: u64::try_from(heap_offset(3)).unwrap(),
                    }
        }));
        assert!(inventory.extents.extents().iter().any(|extent| {
            extent.stream == second_bitmap
                && extent.placement
                    == Placement::Physical {
                        byte_offset: u64::try_from(heap_offset(4)).unwrap(),
                    }
        }));
    }
}
