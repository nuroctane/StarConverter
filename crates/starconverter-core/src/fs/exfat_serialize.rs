//! Pure, bounded exFAT 1.00 destination serialization for a strict lossless subset.
//!
//! This module never opens or writes an image. It converts a validated [`ObjectGraph`] plus the
//! exFAT-only metadata which the neutral graph cannot carry into sector-aligned overlay bytes and
//! explicit source/destination range requirements. Payload bytes are not copied: physical,
//! cluster-aligned source extents are reused in place, and every incompatible graph is refused.
//! `source_allocations` covers all physical streams present in the neutral graph. A conversion
//! coordinator must additionally retain source-filesystem extents held in its preservation
//! sidecar (boot, allocation, journals, and other non-object metadata) during staged layout.

#![allow(clippy::module_name_repetitions)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use super::exfat_inventory::{ExfatPreservationEvidence, ExfatTimestamps};
use super::exfat_upcase::{MAX_FILE_NAME_CODE_UNITS, UpcaseLimits, UpcaseTable, table_checksum};
use crate::extent::{ExtentKind, Placement, StreamId};
use crate::geometry::{ByteRange, DestinationReservation, ReservationKind, SourceAllocation};
use crate::object::{ObjectGraph, ObjectId, ObjectKind, StreamStorage};
use crate::overlay::{OverlayError, OverlayLimits, OverlayPlan, OverlayWrite};

const FAT_OFFSET_SECTORS: u64 = 24;
const ENTRY_BYTES: usize = 32;
const END_OF_CHAIN: u32 = u32::MAX;
const FAT_MEDIA_ENTRY: u32 = 0xffff_fff8;
const DIRECTORY_ATTRIBUTE: u16 = 0x0010;
const VALID_FILE_ATTRIBUTES: u16 = 0x0037;
const ACTIVATION_GAPS: &[&str] = &[
    "per-candidate exFAT driver mount and payload evidence is not yet bound into activation authorization",
    "external Windows chkdsk/mount interoperability has not been proven",
];

/// Exact exFAT fields absent from [`ObjectGraph`]. One record is required for every non-root
/// object. Requiring these fields prevents the serializer from inventing timestamps or flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExfatObjectMetadata {
    pub object: ObjectId,
    pub file_attributes: u16,
    pub timestamps: ExfatTimestamps,
}

/// Caller-selected volume metadata which the neutral object graph does not carry.
///
/// `encoded_upcase_table` must decode to all 65,536 UTF-16 mappings and must match
/// `upcase_checksum`. The serializer uses that exact table for collision checks, every file's
/// `NameHash`, and the root Up-case Table entry. `volume_label: Some(&[])` deliberately preserves
/// the presence of a zero-length Volume Label entry, while `None` emits no such entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExfatVolumeProfile<'a> {
    pub volume_label: Option<&'a [u16]>,
    pub encoded_upcase_table: &'a [u8],
    pub upcase_checksum: u32,
    pub source_preservation: ExfatPreservationEvidence,
    pub allocated_bad_clusters: u64,
}

/// Deterministic destination geometry and stable formatting choices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExfatSerializeOptions {
    pub bytes_per_sector: u32,
    pub bytes_per_cluster: u32,
    pub partition_offset_sectors: u64,
    pub volume_serial_number: u32,
    pub drive_select: u8,
}

impl Default for ExfatSerializeOptions {
    fn default() -> Self {
        Self {
            bytes_per_sector: 512,
            bytes_per_cluster: 4096,
            partition_offset_sectors: 0,
            volume_serial_number: 0,
            drive_select: 0x80,
        }
    }
}

/// Explicit work and output bounds. No count or byte length derived from a graph is trusted
/// without first checking one of these limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExfatSerializeLimits {
    pub max_objects: usize,
    pub max_entries: usize,
    pub max_extents: usize,
    pub max_clusters: usize,
    pub max_directory_bytes: usize,
    pub max_metadata_bytes: usize,
    pub overlay: OverlayLimits,
}

impl Default for ExfatSerializeLimits {
    fn default() -> Self {
        Self {
            max_objects: 1_000_000,
            max_entries: 1_000_000,
            max_extents: 8_000_000,
            max_clusters: 16_000_000,
            max_directory_bytes: 256 * 1024 * 1024,
            max_metadata_bytes: 512 * 1024 * 1024,
            overlay: OverlayLimits::default(),
        }
    }
}

/// Geometry fields encoded in both destination boot regions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExfatDestinationGeometry {
    pub volume_bytes: u64,
    pub volume_sectors: u64,
    pub fat_offset_sectors: u32,
    pub fat_length_sectors: u32,
    pub cluster_heap_offset_sectors: u32,
    pub cluster_count: u32,
    pub root_directory_cluster: u32,
    pub bytes_per_sector: u32,
    pub bytes_per_cluster: u32,
}

/// In-place payload placement recorded in destination directory/FAT metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReusedPayload {
    pub stream: StreamId,
    pub clusters: Vec<u32>,
    pub no_fat_chain: bool,
}

/// Complete immutable candidate. Applying it is deliberately outside this module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExfatSerializationPlan {
    pub geometry: ExfatDestinationGeometry,
    pub overlay: OverlayPlan,
    pub reservations: Vec<DestinationReservation>,
    pub source_allocations: Vec<SourceAllocation>,
    pub reused_payloads: Vec<ReusedPayload>,
}

impl ExfatSerializationPlan {
    /// Activation remains blocked until independent driver and native Windows validation pass.
    #[must_use]
    pub const fn activation_ready(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn activation_gaps(&self) -> &'static [&'static str] {
        ACTIVATION_GAPS
    }

    /// Main boot-region replacement, deliberately isolated for final activation.
    #[must_use]
    pub fn primary_boot_write(&self) -> &OverlayWrite {
        &self.overlay.writes()[0]
    }

    /// Backup boot-region replacement, which transaction code may persist before activation.
    #[must_use]
    pub fn backup_boot_write(&self) -> &OverlayWrite {
        &self.overlay.writes()[1]
    }

    /// Destination metadata writes which do not touch either boot region.
    pub fn staging_writes(&self) -> impl Iterator<Item = &OverlayWrite> {
        self.overlay.writes()[2..].iter()
    }
}

#[derive(Debug)]
pub enum ExfatSerializeError {
    InvalidLimit(&'static str),
    InvalidGeometry(&'static str),
    LimitExceeded {
        field: &'static str,
        actual: u64,
        maximum: usize,
    },
    ArithmeticOverflow(&'static str),
    AllocationFailed,
    MissingMetadata(ObjectId),
    DuplicateMetadata(ObjectId),
    RootMetadata(ObjectId),
    UnknownMetadata(ObjectId),
    UnsupportedObject {
        object: ObjectId,
        reason: &'static str,
    },
    InvalidAttributes(ObjectId),
    InvalidTimestamp(ObjectId),
    InvalidVolumeLabel(&'static str),
    InvalidUpcaseTable,
    UnsupportedPreservationEvidence(&'static str),
    InvalidName {
        object: ObjectId,
        reason: &'static str,
    },
    CaseInsensitiveCollision {
        parent: ObjectId,
    },
    PayloadOutsideHeap(StreamId),
    PayloadNotClusterAligned(StreamId),
    MetadataSpaceExhausted {
        clusters: u64,
    },
    Overlay(OverlayError),
}

impl fmt::Display for ExfatSerializeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit(field) => {
                write!(formatter, "exFAT serialization limit {field} is zero")
            }
            Self::InvalidGeometry(reason) => {
                write!(formatter, "invalid exFAT destination geometry: {reason}")
            }
            Self::LimitExceeded {
                field,
                actual,
                maximum,
            } => write!(formatter, "{field} value {actual} exceeds {maximum}"),
            Self::ArithmeticOverflow(operation) => {
                write!(formatter, "overflow while calculating {operation}")
            }
            Self::AllocationFailed => {
                formatter.write_str("could not allocate bounded exFAT serialization state")
            }
            Self::MissingMetadata(object) => {
                write!(formatter, "object {} has no exact exFAT metadata", object.0)
            }
            Self::DuplicateMetadata(object) => write!(
                formatter,
                "object {} has duplicate exFAT metadata",
                object.0
            ),
            Self::RootMetadata(object) => write!(
                formatter,
                "root object {} must not have a file-entry metadata record",
                object.0
            ),
            Self::UnknownMetadata(object) => {
                write!(formatter, "metadata references unknown object {}", object.0)
            }
            Self::UnsupportedObject { object, reason } => write!(
                formatter,
                "object {} cannot be represented losslessly as exFAT: {reason}",
                object.0
            ),
            Self::InvalidAttributes(object) => write!(
                formatter,
                "object {} has invalid or kind-inconsistent exFAT attributes",
                object.0
            ),
            Self::InvalidTimestamp(object) => write!(
                formatter,
                "object {} has an invalid exFAT timestamp field",
                object.0
            ),
            Self::InvalidVolumeLabel(reason) => {
                write!(formatter, "invalid exact exFAT volume label: {reason}")
            }
            Self::InvalidUpcaseTable => formatter.write_str(
                "caller-selected exFAT Up-case Table is incomplete, malformed, or has the wrong checksum",
            ),
            Self::UnsupportedPreservationEvidence(reason) => write!(
                formatter,
                "exFAT preservation evidence is not supported by this serializer: {reason}"
            ),
            Self::InvalidName { object, reason } => write!(
                formatter,
                "object {} has an exFAT-incompatible name: {reason}",
                object.0
            ),
            Self::CaseInsensitiveCollision { parent } => write!(
                formatter,
                "directory {} has names which collide under the destination up-case table",
                parent.0
            ),
            Self::PayloadOutsideHeap(stream) => write!(
                formatter,
                "stream {} cannot be reused inside the destination cluster heap",
                stream.0
            ),
            Self::PayloadNotClusterAligned(stream) => write!(
                formatter,
                "stream {} is not exactly cluster-aligned for in-place reuse",
                stream.0
            ),
            Self::MetadataSpaceExhausted { clusters } => write!(
                formatter,
                "cannot reserve {clusters} contiguous clusters for destination metadata"
            ),
            Self::Overlay(error) => write!(formatter, "invalid exFAT overlay: {error}"),
        }
    }
}

impl std::error::Error for ExfatSerializeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Overlay(error) => Some(error),
            _ => None,
        }
    }
}

impl From<OverlayError> for ExfatSerializeError {
    fn from(value: OverlayError) -> Self {
        Self::Overlay(value)
    }
}

#[derive(Debug, Clone)]
struct ObjectLayout {
    kind: ObjectKind,
    metadata: Option<ExfatObjectMetadata>,
    name: Option<Vec<u16>>,
    children: Vec<ObjectId>,
    stream: Option<StreamLayout>,
    directory_clusters: Vec<u32>,
    directory_bytes: usize,
}

#[derive(Debug, Clone)]
struct StreamLayout {
    stream: StreamId,
    logical_bytes: u64,
    initialized_bytes: u64,
    mapped_bytes: u64,
    clusters: Vec<u32>,
    no_fat_chain: bool,
}

#[derive(Debug, Clone, Copy)]
struct Allocation {
    first_cluster: u32,
    cluster_count: u32,
}

/// Serializes a strict object-subset exFAT 1.00 structural destination candidate.
///
/// Supported files have zero or one unnamed, fully initialized, non-sparse, uncompressed,
/// unencrypted stream. Non-empty payloads must already occupy whole destination clusters inside
/// the selected heap; fragmented files are supported through FAT chains. Directories are rebuilt
/// from the neutral namespace and therefore may not carry streams. Hard links, named streams,
/// reparse points, security descriptors, and case-folding name collisions are refused.
///
/// # Errors
///
/// Returns [`ExfatSerializeError`] if limits or geometry are invalid, the graph contains semantics
/// outside the documented subset, exact metadata is absent or malformed, payload placement cannot
/// be reused safely, destination metadata cannot be allocated, or overlay validation fails.
#[allow(clippy::too_many_lines)]
pub fn serialize_exfat_destination(
    graph: &ObjectGraph,
    metadata: &[ExfatObjectMetadata],
    profile: ExfatVolumeProfile<'_>,
    options: ExfatSerializeOptions,
    limits: ExfatSerializeLimits,
) -> Result<ExfatSerializationPlan, ExfatSerializeError> {
    validate_limits(limits)?;
    validate_volume_profile(profile)?;
    let geometry = choose_geometry(graph.extents().volume_bytes(), options, limits)?;
    let upcase = UpcaseTable::parse(
        profile.encoded_upcase_table,
        profile.upcase_checksum,
        UpcaseLimits::COMPLETE_TABLE,
    )
    .map_err(|_| ExfatSerializeError::InvalidUpcaseTable)?;

    let mut layouts = build_object_layouts(graph, metadata, &geometry, &upcase, limits)?;
    let cluster_count = usize::try_from(geometry.cluster_count)
        .map_err(|_| ExfatSerializeError::ArithmeticOverflow("cluster bitmap size"))?;
    let mut occupied = vec![false; cluster_count];
    let (source_allocations, reused_payloads) =
        map_payloads(graph, &geometry, &mut layouts, &mut occupied, limits)?;

    let bitmap_length = u64::from(geometry.cluster_count).div_ceil(8);
    let bitmap_clusters = clusters_for(bitmap_length, geometry.bytes_per_cluster)?;
    let upcase_clusters = clusters_for(
        u64::try_from(profile.encoded_upcase_table.len())
            .map_err(|_| ExfatSerializeError::ArithmeticOverflow("up-case length"))?,
        geometry.bytes_per_cluster,
    )?;
    let bitmap = allocate_contiguous(&mut occupied, bitmap_clusters)?;
    let upcase_allocation = allocate_contiguous(&mut occupied, upcase_clusters)?;

    let directory_order = directory_order(graph, &layouts);
    for object in &directory_order {
        let bytes = directory_length(
            *object,
            graph.root(),
            &layouts,
            profile.volume_label.is_some(),
        )?;
        if bytes > limits.max_directory_bytes {
            return Err(ExfatSerializeError::LimitExceeded {
                field: "directory bytes",
                actual: u64::try_from(bytes).unwrap_or(u64::MAX),
                maximum: limits.max_directory_bytes,
            });
        }
        let clusters = clusters_for(
            u64::try_from(bytes)
                .map_err(|_| ExfatSerializeError::ArithmeticOverflow("directory bytes"))?,
            geometry.bytes_per_cluster,
        )?;
        let allocation = allocate_contiguous(&mut occupied, clusters)?;
        let layout = layouts
            .get_mut(object)
            .ok_or(ExfatSerializeError::UnsupportedObject {
                object: *object,
                reason: "missing internal layout",
            })?;
        layout.directory_clusters = expand_allocation(allocation)?;
        layout.directory_bytes = bytes;
    }
    let root_cluster = layouts
        .get(&graph.root())
        .and_then(|layout| layout.directory_clusters.first())
        .copied()
        .ok_or_else(|| ExfatSerializeError::UnsupportedObject {
            object: graph.root(),
            reason: "root directory allocation is empty",
        })?;
    let geometry = ExfatDestinationGeometry {
        root_directory_cluster: root_cluster,
        ..geometry
    };

    let mut fat = vec![0_u8; fat_byte_length(&geometry)?];
    put_u32(&mut fat, 0, FAT_MEDIA_ENTRY);
    put_u32(&mut fat, 4, END_OF_CHAIN);
    write_chain(&mut fat, &expand_allocation(bitmap)?)?;
    write_chain(&mut fat, &expand_allocation(upcase_allocation)?)?;
    for object in &directory_order {
        if *object == graph.root() {
            write_chain(&mut fat, &layouts[object].directory_clusters)?;
        }
    }
    for reused in &reused_payloads {
        if !reused.no_fat_chain {
            write_chain(&mut fat, &reused.clusters)?;
        }
    }

    // `occupied` also contains old source directory clusters retained only while staging. Build
    // the destination bitmap from streams and metadata actually referenced by the new exFAT view,
    // so obsolete source namespace clusters become free only after boot activation.
    let mut destination_allocated = vec![false; cluster_count];
    for reused in &reused_payloads {
        for cluster in &reused.clusters {
            let index = usize::try_from(cluster.saturating_sub(2))
                .map_err(|_| ExfatSerializeError::ArithmeticOverflow("payload bitmap index"))?;
            destination_allocated[index] = true;
        }
    }
    mark_allocation(&mut destination_allocated, bitmap)?;
    mark_allocation(&mut destination_allocated, upcase_allocation)?;
    for object in &directory_order {
        for cluster in &layouts[object].directory_clusters {
            let index = usize::try_from(cluster.saturating_sub(2))
                .map_err(|_| ExfatSerializeError::ArithmeticOverflow("directory bitmap index"))?;
            destination_allocated[index] = true;
        }
    }
    let mut bitmap_bytes = vec![0_u8; padded_allocation_bytes(bitmap, geometry.bytes_per_cluster)?];
    for (index, allocated) in destination_allocated.iter().copied().enumerate() {
        if allocated {
            bitmap_bytes[index / 8] |= 1 << (index % 8);
        }
    }
    let allocated_clusters = destination_allocated.iter().filter(|value| **value).count();
    let percent_in_use =
        u8::try_from(allocated_clusters.saturating_mul(100) / occupied.len()).unwrap_or(100);

    let mut writes = Vec::new();
    let boot = build_boot_regions(&geometry, options, percent_in_use)?;
    let one_boot_region = usize::try_from(12_u64 * u64::from(geometry.bytes_per_sector))
        .map_err(|_| ExfatSerializeError::ArithmeticOverflow("single boot-region bytes"))?;
    let (primary_boot, backup_boot) = boot.split_at(one_boot_region);
    writes.push(OverlayWrite {
        offset: 0,
        bytes: primary_boot.to_vec(),
    });
    writes.push(OverlayWrite {
        offset: u64::try_from(one_boot_region)
            .map_err(|_| ExfatSerializeError::ArithmeticOverflow("backup boot offset"))?,
        bytes: backup_boot.to_vec(),
    });
    writes.push(OverlayWrite {
        offset: u64::from(geometry.fat_offset_sectors) * u64::from(geometry.bytes_per_sector),
        bytes: fat,
    });
    writes.push(allocation_write(&geometry, bitmap, bitmap_bytes)?);
    let mut upcase_padded =
        vec![0_u8; padded_allocation_bytes(upcase_allocation, geometry.bytes_per_cluster)?];
    upcase_padded[..profile.encoded_upcase_table.len()]
        .copy_from_slice(profile.encoded_upcase_table);
    writes.push(allocation_write(
        &geometry,
        upcase_allocation,
        upcase_padded,
    )?);
    for object in &directory_order {
        let bytes = build_directory(
            *object,
            graph.root(),
            &layouts,
            bitmap,
            upcase_allocation,
            bitmap_length,
            profile.volume_label,
            profile.encoded_upcase_table,
            profile.upcase_checksum,
            &upcase,
            geometry.bytes_per_cluster,
        )?;
        let allocation = allocation_from_clusters(&layouts[object].directory_clusters)?;
        writes.push(allocation_write(&geometry, allocation, bytes)?);
    }
    let metadata_bytes = writes
        .iter()
        .try_fold(0_u64, |sum, write| {
            sum.checked_add(u64::try_from(write.bytes.len()).ok()?)
        })
        .ok_or(ExfatSerializeError::ArithmeticOverflow(
            "metadata write bytes",
        ))?;
    if metadata_bytes > u64::try_from(limits.max_metadata_bytes).unwrap_or(u64::MAX) {
        return Err(ExfatSerializeError::LimitExceeded {
            field: "metadata bytes",
            actual: metadata_bytes,
            maximum: limits.max_metadata_bytes,
        });
    }

    let reservations = reservations_for(
        &geometry,
        bitmap,
        upcase_allocation,
        &directory_order,
        &layouts,
    )?;
    let overlay = OverlayPlan::build(
        geometry.volume_bytes,
        geometry.bytes_per_sector,
        writes,
        limits.overlay,
    )?;
    Ok(ExfatSerializationPlan {
        geometry,
        overlay,
        reservations,
        source_allocations,
        reused_payloads,
    })
}

fn mark_allocation(bits: &mut [bool], allocation: Allocation) -> Result<(), ExfatSerializeError> {
    let first = usize::try_from(allocation.first_cluster.saturating_sub(2))
        .map_err(|_| ExfatSerializeError::ArithmeticOverflow("metadata bitmap index"))?;
    let count = usize::try_from(allocation.cluster_count)
        .map_err(|_| ExfatSerializeError::ArithmeticOverflow("metadata bitmap length"))?;
    let end = first
        .checked_add(count)
        .ok_or(ExfatSerializeError::ArithmeticOverflow(
            "metadata bitmap end",
        ))?;
    let range =
        bits.get_mut(first..end)
            .ok_or_else(|| ExfatSerializeError::MetadataSpaceExhausted {
                clusters: u64::from(allocation.cluster_count),
            })?;
    range.fill(true);
    Ok(())
}

fn validate_limits(limits: ExfatSerializeLimits) -> Result<(), ExfatSerializeError> {
    for (field, value) in [
        ("max_objects", limits.max_objects),
        ("max_entries", limits.max_entries),
        ("max_extents", limits.max_extents),
        ("max_clusters", limits.max_clusters),
        ("max_directory_bytes", limits.max_directory_bytes),
        ("max_metadata_bytes", limits.max_metadata_bytes),
    ] {
        if value == 0 {
            return Err(ExfatSerializeError::InvalidLimit(field));
        }
    }
    Ok(())
}

fn validate_volume_profile(profile: ExfatVolumeProfile<'_>) -> Result<(), ExfatSerializeError> {
    let evidence = profile.source_preservation;
    if evidence.unused_directory_entries != 0 {
        return Err(ExfatSerializeError::UnsupportedPreservationEvidence(
            "inactive nonzero directory entries are present",
        ));
    }
    if evidence.benign_primary_sets != 0 || evidence.benign_secondary_entries != 0 {
        return Err(ExfatSerializeError::UnsupportedPreservationEvidence(
            "benign/vendor directory entries are present",
        ));
    }
    if evidence.nonzero_name_padding_sets != 0 || evidence.nonzero_volume_label_padding {
        return Err(ExfatSerializeError::UnsupportedPreservationEvidence(
            "nonzero recommended filename or volume-label padding is present",
        ));
    }
    if profile.allocated_bad_clusters != 0 {
        return Err(ExfatSerializeError::UnsupportedPreservationEvidence(
            "allocated bad-cluster markings are present",
        ));
    }
    if let Some(label) = profile.volume_label {
        if label.len() > 11 {
            return Err(ExfatSerializeError::InvalidVolumeLabel(
                "more than 11 UTF-16 code units",
            ));
        }
        if label.iter().copied().any(|unit| {
            unit <= 0x1f
                || matches!(
                    unit,
                    0x22 | 0x2a | 0x2f | 0x3a | 0x3c | 0x3e | 0x3f | 0x5c | 0x7c
                )
        }) {
            return Err(ExfatSerializeError::InvalidVolumeLabel(
                "contains an exFAT-forbidden character",
            ));
        }
        if char::decode_utf16(label.iter().copied()).any(|decoded| decoded.is_err()) {
            return Err(ExfatSerializeError::InvalidVolumeLabel(
                "contains unpaired UTF-16 surrogate code units",
            ));
        }
    }
    Ok(())
}

fn choose_geometry(
    volume_bytes: u64,
    options: ExfatSerializeOptions,
    limits: ExfatSerializeLimits,
) -> Result<ExfatDestinationGeometry, ExfatSerializeError> {
    let sector = options.bytes_per_sector;
    let cluster = options.bytes_per_cluster;
    if !(512..=4096).contains(&sector) || !sector.is_power_of_two() {
        return Err(ExfatSerializeError::InvalidGeometry(
            "sector size must be a power of two from 512 through 4096",
        ));
    }
    if cluster < sector
        || !cluster.is_power_of_two()
        || cluster > 32 * 1024 * 1024
        || cluster % sector != 0
    {
        return Err(ExfatSerializeError::InvalidGeometry(
            "cluster size must be a sector multiple and a power of two no larger than 32 MiB",
        ));
    }
    if volume_bytes < 1_048_576 || volume_bytes % u64::from(sector) != 0 {
        return Err(ExfatSerializeError::InvalidGeometry(
            "volume must be at least 1 MiB and sector aligned",
        ));
    }
    let volume_sectors = volume_bytes / u64::from(sector);
    options
        .partition_offset_sectors
        .checked_add(volume_sectors)
        .ok_or(ExfatSerializeError::InvalidGeometry(
            "partition offset plus volume length overflows",
        ))?;
    let sectors_per_cluster = u64::from(cluster / sector);
    let mut fat_length = 1_u64;
    let mut heap_offset = 0_u64;
    let mut cluster_count = 0_u64;
    for _ in 0..64 {
        let new_heap = align_up(
            FAT_OFFSET_SECTORS
                .checked_add(fat_length)
                .ok_or(ExfatSerializeError::ArithmeticOverflow("FAT end"))?,
            sectors_per_cluster,
        )?;
        if new_heap >= volume_sectors {
            return Err(ExfatSerializeError::InvalidGeometry(
                "metadata leaves no cluster heap",
            ));
        }
        let new_count = (volume_sectors - new_heap) / sectors_per_cluster;
        let fat_bytes = new_count
            .checked_add(2)
            .and_then(|value| value.checked_mul(4))
            .ok_or(ExfatSerializeError::ArithmeticOverflow("FAT entries"))?;
        let new_fat = fat_bytes.div_ceil(u64::from(sector));
        if new_heap == heap_offset && new_count == cluster_count && new_fat == fat_length {
            break;
        }
        heap_offset = new_heap;
        cluster_count = new_count;
        fat_length = new_fat;
    }
    if cluster_count == 0 || cluster_count > 0xffff_fff5 {
        return Err(ExfatSerializeError::InvalidGeometry(
            "cluster count is outside exFAT 1.00 bounds",
        ));
    }
    if cluster_count > u64::try_from(limits.max_clusters).unwrap_or(u64::MAX) {
        return Err(ExfatSerializeError::LimitExceeded {
            field: "clusters",
            actual: cluster_count,
            maximum: limits.max_clusters,
        });
    }
    Ok(ExfatDestinationGeometry {
        volume_bytes,
        volume_sectors,
        fat_offset_sectors: u32::try_from(FAT_OFFSET_SECTORS).unwrap(),
        fat_length_sectors: u32::try_from(fat_length)
            .map_err(|_| ExfatSerializeError::ArithmeticOverflow("FAT sector count"))?,
        cluster_heap_offset_sectors: u32::try_from(heap_offset)
            .map_err(|_| ExfatSerializeError::ArithmeticOverflow("heap sector offset"))?,
        cluster_count: u32::try_from(cluster_count)
            .map_err(|_| ExfatSerializeError::ArithmeticOverflow("cluster count"))?,
        root_directory_cluster: 2,
        bytes_per_sector: sector,
        bytes_per_cluster: cluster,
    })
}

#[allow(clippy::too_many_lines)]
fn build_object_layouts(
    graph: &ObjectGraph,
    metadata: &[ExfatObjectMetadata],
    geometry: &ExfatDestinationGeometry,
    upcase: &UpcaseTable,
    limits: ExfatSerializeLimits,
) -> Result<BTreeMap<ObjectId, ObjectLayout>, ExfatSerializeError> {
    if graph.objects().len() > limits.max_objects {
        return Err(ExfatSerializeError::LimitExceeded {
            field: "objects",
            actual: u64::try_from(graph.objects().len()).unwrap_or(u64::MAX),
            maximum: limits.max_objects,
        });
    }
    if graph.entries().len() > limits.max_entries {
        return Err(ExfatSerializeError::LimitExceeded {
            field: "entries",
            actual: u64::try_from(graph.entries().len()).unwrap_or(u64::MAX),
            maximum: limits.max_entries,
        });
    }
    if graph.extents().extents().len() > limits.max_extents {
        return Err(ExfatSerializeError::LimitExceeded {
            field: "extents",
            actual: u64::try_from(graph.extents().extents().len()).unwrap_or(u64::MAX),
            maximum: limits.max_extents,
        });
    }
    let known: BTreeSet<_> = graph.objects().iter().map(|object| object.id).collect();
    let mut exact = BTreeMap::new();
    for item in metadata {
        if item.object == graph.root() {
            return Err(ExfatSerializeError::RootMetadata(item.object));
        }
        if !known.contains(&item.object) {
            return Err(ExfatSerializeError::UnknownMetadata(item.object));
        }
        if exact.insert(item.object, *item).is_some() {
            return Err(ExfatSerializeError::DuplicateMetadata(item.object));
        }
    }
    let mut layouts = BTreeMap::new();
    for object in graph.objects() {
        if object.semantics.has_security_descriptor
            || object.semantics.is_reparse_point
            || (object.id != graph.root() && object.link_count != 1)
        {
            return Err(ExfatSerializeError::UnsupportedObject {
                object: object.id,
                reason: "security descriptors, reparse points, or hard links are not in the supported subset",
            });
        }
        let item = if object.id == graph.root() {
            None
        } else {
            Some(
                *exact
                    .get(&object.id)
                    .ok_or(ExfatSerializeError::MissingMetadata(object.id))?,
            )
        };
        if let Some(item) = item {
            validate_metadata(object.id, object.kind, item)?;
        }
        let stream = match object.kind {
            ObjectKind::Directory => {
                validate_directory_streams(object.id, &object.streams, graph)?;
                None
            }
            ObjectKind::File => Some(validate_file_stream(object.id, &object.streams, geometry)?),
        };
        layouts.insert(
            object.id,
            ObjectLayout {
                kind: object.kind,
                metadata: item,
                name: None,
                children: Vec::new(),
                stream,
                directory_clusters: Vec::new(),
                directory_bytes: 0,
            },
        );
    }
    if exact.len() != graph.objects().len().saturating_sub(1) {
        return Err(ExfatSerializeError::UnsupportedObject {
            object: graph.root(),
            reason: "metadata cardinality does not match non-root objects",
        });
    }
    for entry in graph.entries() {
        validate_name(&entry.name, entry.target)?;
        let target =
            layouts
                .get_mut(&entry.target)
                .ok_or(ExfatSerializeError::UnsupportedObject {
                    object: entry.target,
                    reason: "namespace target is absent",
                })?;
        target.name = Some(entry.name.clone());
        layouts
            .get_mut(&entry.parent)
            .ok_or(ExfatSerializeError::UnsupportedObject {
                object: entry.parent,
                reason: "namespace parent is absent",
            })?
            .children
            .push(entry.target);
    }
    let parent_ids: Vec<ObjectId> = layouts.keys().copied().collect();
    for parent in parent_ids {
        let mut children = layouts[&parent].children.clone();
        children.sort_unstable_by(|left, right| layouts_name_order(*left, *right, graph));
        let mut folded = BTreeSet::new();
        for child in &children {
            let name = layouts
                .get(child)
                .and_then(|value| value.name.as_deref())
                .ok_or(ExfatSerializeError::InvalidName {
                    object: *child,
                    reason: "missing namespace name",
                })?;
            let key: Vec<u16> = name.iter().map(|unit| upcase.map(*unit)).collect();
            if !folded.insert(key) {
                return Err(ExfatSerializeError::CaseInsensitiveCollision { parent });
            }
        }
        layouts.get_mut(&parent).expect("known parent").children = children;
    }
    Ok(layouts)
}

fn layouts_name_order(left: ObjectId, right: ObjectId, graph: &ObjectGraph) -> std::cmp::Ordering {
    const EMPTY: &[u16] = &[];
    let name = |id| {
        graph
            .entries()
            .iter()
            .find(|entry| entry.target == id)
            .map_or(EMPTY, |entry| entry.name.as_slice())
    };
    name(left).cmp(name(right)).then(left.cmp(&right))
}

fn validate_metadata(
    object: ObjectId,
    kind: ObjectKind,
    item: ExfatObjectMetadata,
) -> Result<(), ExfatSerializeError> {
    if item.file_attributes & !VALID_FILE_ATTRIBUTES != 0
        || ((item.file_attributes & DIRECTORY_ATTRIBUTE != 0) != (kind == ObjectKind::Directory))
    {
        return Err(ExfatSerializeError::InvalidAttributes(object));
    }
    let timestamps = item.timestamps;
    if !valid_timestamp(timestamps.create)
        || !valid_timestamp(timestamps.modified)
        || !valid_timestamp(timestamps.accessed)
        || timestamps.create_centiseconds > 199
        || timestamps.modified_centiseconds > 199
        || !valid_utc(timestamps.create_utc_offset)
        || !valid_utc(timestamps.modified_utc_offset)
        || !valid_utc(timestamps.accessed_utc_offset)
    {
        return Err(ExfatSerializeError::InvalidTimestamp(object));
    }
    Ok(())
}

const fn valid_utc(value: u8) -> bool {
    value == 0 || value & 0x80 != 0
}

const fn valid_timestamp(value: u32) -> bool {
    let seconds = value & 0x1f;
    let minute = (value >> 5) & 0x3f;
    let hour = (value >> 11) & 0x1f;
    let day = (value >> 16) & 0x1f;
    let month = (value >> 21) & 0x0f;
    let year = 1980 + ((value >> 25) & 0x7f);
    let leap = year.trailing_zeros() >= 2 && year != 2100;
    let maximum = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    };
    seconds <= 29 && minute <= 59 && hour <= 23 && day != 0 && day <= maximum
}

fn validate_name(name: &[u16], object: ObjectId) -> Result<(), ExfatSerializeError> {
    if name.is_empty() || name.len() > MAX_FILE_NAME_CODE_UNITS {
        return Err(ExfatSerializeError::InvalidName {
            object,
            reason: "length is outside 1..=255 UTF-16 code units",
        });
    }
    if name == [u16::from(b'.')] || name == [u16::from(b'.'), u16::from(b'.')] {
        return Err(ExfatSerializeError::InvalidName {
            object,
            reason: "dot names are reserved",
        });
    }
    if name.iter().any(|unit| {
        *unit <= 0x1f
            || matches!(
                *unit,
                0x22 | 0x2a | 0x2f | 0x3a | 0x3c | 0x3e | 0x3f | 0x5c | 0x7c
            )
    }) {
        return Err(ExfatSerializeError::InvalidName {
            object,
            reason: "contains a forbidden code unit",
        });
    }
    if char::decode_utf16(name.iter().copied()).any(|unit| unit.is_err()) {
        return Err(ExfatSerializeError::InvalidName {
            object,
            reason: "contains unpaired UTF-16 surrogates",
        });
    }
    Ok(())
}

fn validate_file_stream(
    object: ObjectId,
    streams: &[crate::object::ObjectStream],
    geometry: &ExfatDestinationGeometry,
) -> Result<StreamLayout, ExfatSerializeError> {
    if streams.is_empty() {
        return Ok(StreamLayout {
            stream: StreamId(object.0),
            logical_bytes: 0,
            initialized_bytes: 0,
            mapped_bytes: 0,
            clusters: Vec::new(),
            no_fat_chain: false,
        });
    }
    if streams.len() != 1 || streams[0].name.is_some() {
        return Err(ExfatSerializeError::UnsupportedObject {
            object,
            reason: "named or multiple data streams are unsupported",
        });
    }
    let stream = &streams[0];
    if stream.flags.sparse || stream.flags.compressed || stream.flags.encrypted {
        return Err(ExfatSerializeError::UnsupportedObject {
            object,
            reason: "sparse, compressed, or encrypted data cannot be represented",
        });
    }
    if stream.logical_bytes == 0 {
        if !matches!(&stream.storage, StreamStorage::Resident(bytes) if bytes.is_empty()) {
            return Err(ExfatSerializeError::UnsupportedObject {
                object,
                reason: "empty files must use empty resident storage",
            });
        }
    } else if !matches!(stream.storage, StreamStorage::Extents)
        || stream.mapped_bytes % u64::from(geometry.bytes_per_cluster) != 0
        || stream.allocated_bytes != stream.mapped_bytes
    {
        return Err(ExfatSerializeError::UnsupportedObject {
            object,
            reason: "non-empty files require fully physical, whole-cluster extent storage",
        });
    }
    Ok(StreamLayout {
        stream: stream.id,
        logical_bytes: stream.logical_bytes,
        initialized_bytes: stream.initialized_bytes,
        mapped_bytes: stream.mapped_bytes,
        clusters: Vec::new(),
        no_fat_chain: false,
    })
}

fn validate_directory_streams(
    object: ObjectId,
    streams: &[crate::object::ObjectStream],
    graph: &ObjectGraph,
) -> Result<(), ExfatSerializeError> {
    if streams.is_empty() {
        return Ok(());
    }
    if streams.len() != 1
        || streams[0].name.is_some()
        || streams[0].flags != crate::object::StreamFlags::default()
        || !matches!(streams[0].storage, StreamStorage::Extents)
        || graph
            .extents()
            .extents()
            .iter()
            .filter(|extent| extent.stream == streams[0].id)
            .any(|extent| extent.kind != ExtentKind::DirectoryData)
    {
        return Err(ExfatSerializeError::UnsupportedObject {
            object,
            reason: "directory storage is not a single ordinary metadata stream",
        });
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn map_payloads(
    graph: &ObjectGraph,
    geometry: &ExfatDestinationGeometry,
    layouts: &mut BTreeMap<ObjectId, ObjectLayout>,
    occupied: &mut [bool],
    limits: ExfatSerializeLimits,
) -> Result<(Vec<SourceAllocation>, Vec<ReusedPayload>), ExfatSerializeError> {
    let heap =
        u64::from(geometry.cluster_heap_offset_sectors) * u64::from(geometry.bytes_per_sector);
    let cluster_bytes = u64::from(geometry.bytes_per_cluster);
    let mut source = Vec::new();
    let mut reused = Vec::new();
    for extent in graph
        .extents()
        .extents()
        .iter()
        .filter(|extent| extent.kind != ExtentKind::FileData)
    {
        if extent.kind != ExtentKind::DirectoryData || extent.length % cluster_bytes != 0 {
            return Err(ExfatSerializeError::PayloadNotClusterAligned(extent.stream));
        }
        let physical = match extent.placement {
            Placement::Physical { byte_offset } => byte_offset,
            Placement::Sparse => {
                return Err(ExfatSerializeError::PayloadNotClusterAligned(extent.stream));
            }
        };
        if physical < heap || (physical - heap) % cluster_bytes != 0 {
            return Err(ExfatSerializeError::PayloadNotClusterAligned(extent.stream));
        }
        let first = (physical - heap) / cluster_bytes;
        let count = extent.length / cluster_bytes;
        if first
            .checked_add(count)
            .is_none_or(|end| end > u64::from(geometry.cluster_count))
        {
            return Err(ExfatSerializeError::PayloadOutsideHeap(extent.stream));
        }
        for index in first..first + count {
            let slot = usize::try_from(index)
                .map_err(|_| ExfatSerializeError::ArithmeticOverflow("source cluster index"))?;
            if occupied[slot] {
                return Err(ExfatSerializeError::PayloadOutsideHeap(extent.stream));
            }
            occupied[slot] = true;
        }
        source.push(SourceAllocation {
            stream: extent.stream,
            logical_offset: extent.logical_offset,
            range: ByteRange {
                offset: physical,
                length: extent.length,
            },
            movable: false,
        });
    }
    for layout in layouts
        .values_mut()
        .filter(|layout| layout.kind == ObjectKind::File)
    {
        let stream = layout
            .stream
            .as_mut()
            .expect("file layout always has stream state");
        if stream.mapped_bytes == 0 {
            continue;
        }
        let mut expected_logical = 0_u64;
        for extent in graph
            .extents()
            .extents()
            .iter()
            .filter(|extent| extent.stream == stream.stream)
        {
            if extent.kind != ExtentKind::FileData
                || extent.logical_offset != expected_logical
                || extent.length % cluster_bytes != 0
            {
                return Err(ExfatSerializeError::PayloadNotClusterAligned(stream.stream));
            }
            let physical = match extent.placement {
                Placement::Physical { byte_offset } => byte_offset,
                Placement::Sparse => {
                    return Err(ExfatSerializeError::UnsupportedObject {
                        object: ObjectId(stream.stream.0),
                        reason: "sparse payload extent",
                    });
                }
            };
            if physical < heap || (physical - heap) % cluster_bytes != 0 {
                return Err(ExfatSerializeError::PayloadNotClusterAligned(stream.stream));
            }
            let first = (physical - heap) / cluster_bytes;
            let count = extent.length / cluster_bytes;
            if first
                .checked_add(count)
                .is_none_or(|end| end > u64::from(geometry.cluster_count))
            {
                return Err(ExfatSerializeError::PayloadOutsideHeap(stream.stream));
            }
            for index in first..first + count {
                let slot = usize::try_from(index).map_err(|_| {
                    ExfatSerializeError::ArithmeticOverflow("payload cluster index")
                })?;
                if occupied[slot] {
                    return Err(ExfatSerializeError::PayloadOutsideHeap(stream.stream));
                }
                occupied[slot] = true;
                stream.clusters.push(u32::try_from(index + 2).map_err(|_| {
                    ExfatSerializeError::ArithmeticOverflow("payload cluster number")
                })?);
            }
            source.push(SourceAllocation {
                stream: stream.stream,
                logical_offset: extent.logical_offset,
                range: ByteRange {
                    offset: physical,
                    length: extent.length,
                },
                movable: false,
            });
            expected_logical = expected_logical.checked_add(extent.length).ok_or(
                ExfatSerializeError::ArithmeticOverflow("payload logical length"),
            )?;
        }
        if expected_logical != stream.mapped_bytes {
            return Err(ExfatSerializeError::PayloadNotClusterAligned(stream.stream));
        }
        stream.no_fat_chain = stream
            .clusters
            .windows(2)
            .all(|pair| pair[1] == pair[0] + 1);
        reused.push(ReusedPayload {
            stream: stream.stream,
            clusters: stream.clusters.clone(),
            no_fat_chain: stream.no_fat_chain,
        });
    }
    if source.len() > limits.max_extents {
        return Err(ExfatSerializeError::LimitExceeded {
            field: "payload extents",
            actual: u64::try_from(source.len()).unwrap_or(u64::MAX),
            maximum: limits.max_extents,
        });
    }
    source.sort_unstable_by_key(|item| item.range.offset);
    reused.sort_unstable_by_key(|item| item.stream);
    Ok((source, reused))
}

fn directory_order(
    graph: &ObjectGraph,
    layouts: &BTreeMap<ObjectId, ObjectLayout>,
) -> Vec<ObjectId> {
    let mut order = vec![graph.root()];
    let mut cursor = 0;
    while cursor < order.len() {
        let current = order[cursor];
        cursor += 1;
        for child in &layouts[&current].children {
            if layouts[child].kind == ObjectKind::Directory {
                order.push(*child);
            }
        }
    }
    order
}

fn directory_length(
    object: ObjectId,
    root: ObjectId,
    layouts: &BTreeMap<ObjectId, ObjectLayout>,
    has_volume_label: bool,
) -> Result<usize, ExfatSerializeError> {
    let system = if object == root {
        2_usize + usize::from(has_volume_label)
    } else {
        0
    };
    let entries = layouts[&object]
        .children
        .iter()
        .try_fold(system + 1, |sum, child| {
            let name_len = layouts[child].name.as_ref()?.len();
            sum.checked_add(2 + name_len.div_ceil(15))
        })
        .ok_or(ExfatSerializeError::ArithmeticOverflow(
            "directory entry count",
        ))?;
    entries
        .checked_mul(ENTRY_BYTES)
        .ok_or(ExfatSerializeError::ArithmeticOverflow("directory bytes"))
}

fn allocate_contiguous(
    occupied: &mut [bool],
    count: u32,
) -> Result<Allocation, ExfatSerializeError> {
    let count_usize = usize::try_from(count)
        .map_err(|_| ExfatSerializeError::ArithmeticOverflow("allocation cluster count"))?;
    if count_usize == 0 {
        return Err(ExfatSerializeError::MetadataSpaceExhausted { clusters: 0 });
    }
    let mut run = 0_usize;
    for (index, used) in occupied.iter().copied().enumerate() {
        run = if used { 0 } else { run + 1 };
        if run == count_usize {
            let start = index + 1 - count_usize;
            occupied[start..=index].fill(true);
            return Ok(Allocation {
                first_cluster: u32::try_from(start + 2).map_err(|_| {
                    ExfatSerializeError::ArithmeticOverflow("allocation first cluster")
                })?,
                cluster_count: count,
            });
        }
    }
    Err(ExfatSerializeError::MetadataSpaceExhausted {
        clusters: u64::from(count),
    })
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn build_directory(
    object: ObjectId,
    root: ObjectId,
    layouts: &BTreeMap<ObjectId, ObjectLayout>,
    bitmap: Allocation,
    upcase_allocation: Allocation,
    bitmap_length: u64,
    volume_label: Option<&[u16]>,
    upcase_bytes: &[u8],
    upcase_checksum: u32,
    upcase: &UpcaseTable,
    cluster_bytes: u32,
) -> Result<Vec<u8>, ExfatSerializeError> {
    let layout = &layouts[&object];
    let allocation = allocation_from_clusters(&layout.directory_clusters)?;
    let mut bytes = vec![0_u8; padded_allocation_bytes(allocation, cluster_bytes)?];
    let mut cursor = 0;
    if object == root {
        if let Some(label) = volume_label {
            bytes[cursor] = 0x83;
            bytes[cursor + 1] = u8::try_from(label.len())
                .map_err(|_| ExfatSerializeError::ArithmeticOverflow("volume label length"))?;
            for (index, unit) in label.iter().copied().enumerate() {
                put_u16(&mut bytes, cursor + 2 + index * 2, unit);
            }
            cursor += ENTRY_BYTES;
        }
        bytes[cursor] = 0x81;
        put_u32(&mut bytes, cursor + 20, bitmap.first_cluster);
        put_u64(&mut bytes, cursor + 24, bitmap_length);
        cursor += ENTRY_BYTES;
        bytes[cursor] = 0x82;
        debug_assert_eq!(upcase_checksum, table_checksum(upcase_bytes));
        put_u32(&mut bytes, cursor + 4, upcase_checksum);
        put_u32(&mut bytes, cursor + 20, upcase_allocation.first_cluster);
        put_u64(
            &mut bytes,
            cursor + 24,
            u64::try_from(upcase_bytes.len())
                .map_err(|_| ExfatSerializeError::ArithmeticOverflow("up-case data length"))?,
        );
        cursor += ENTRY_BYTES;
    }
    for child in &layout.children {
        let child_layout = &layouts[child];
        let name = child_layout
            .name
            .as_ref()
            .ok_or(ExfatSerializeError::InvalidName {
                object: *child,
                reason: "missing namespace name",
            })?;
        let stream = child_layout.stream.as_ref();
        let (first_cluster, valid_length, data_length, no_fat_chain) =
            if child_layout.kind == ObjectKind::Directory {
                let length = u64::try_from(child_layout.directory_clusters.len())
                    .map_err(|_| ExfatSerializeError::ArithmeticOverflow("directory clusters"))?
                    .checked_mul(u64::from(cluster_bytes))
                    .ok_or(ExfatSerializeError::ArithmeticOverflow(
                        "directory data length",
                    ))?;
                (child_layout.directory_clusters[0], length, length, true)
            } else {
                let value = stream.expect("file layout has stream state");
                (
                    value.clusters.first().copied().unwrap_or(0),
                    value.initialized_bytes,
                    value.logical_bytes,
                    value.no_fat_chain && value.mapped_bytes != 0,
                )
            };
        let name_entries = name.len().div_ceil(15);
        let set_entries = 2 + name_entries;
        let end = cursor
            .checked_add(set_entries * ENTRY_BYTES)
            .ok_or(ExfatSerializeError::ArithmeticOverflow("file entry set"))?;
        let set = bytes
            .get_mut(cursor..end)
            .ok_or(ExfatSerializeError::ArithmeticOverflow("directory buffer"))?;
        set[0] = 0x85;
        set[1] = u8::try_from(set_entries - 1)
            .map_err(|_| ExfatSerializeError::ArithmeticOverflow("secondary count"))?;
        let metadata = child_layout.metadata.expect("non-root layout has metadata");
        put_u16(set, 4, metadata.file_attributes);
        write_timestamps(set, metadata.timestamps);
        set[ENTRY_BYTES] = 0xc0;
        set[ENTRY_BYTES + 1] = 1 | if no_fat_chain { 2 } else { 0 };
        set[ENTRY_BYTES + 3] = u8::try_from(name.len())
            .map_err(|_| ExfatSerializeError::ArithmeticOverflow("name length"))?;
        put_u16(
            set,
            ENTRY_BYTES + 4,
            upcase
                .name_hash(name, MAX_FILE_NAME_CODE_UNITS)
                .map_err(|_| ExfatSerializeError::InvalidName {
                    object: *child,
                    reason: "up-case hash refused the name",
                })?,
        );
        put_u64(set, ENTRY_BYTES + 8, valid_length);
        put_u32(set, ENTRY_BYTES + 20, first_cluster);
        put_u64(set, ENTRY_BYTES + 24, data_length);
        for (index, unit) in name.iter().copied().enumerate() {
            let offset = 2 * ENTRY_BYTES + (index / 15) * ENTRY_BYTES + 2 + (index % 15) * 2;
            set[2 * ENTRY_BYTES + (index / 15) * ENTRY_BYTES] = 0xc1;
            put_u16(set, offset, unit);
        }
        set_checksum(set);
        cursor = end;
    }
    Ok(bytes)
}

fn write_timestamps(set: &mut [u8], value: ExfatTimestamps) {
    put_u32(set, 8, value.create);
    put_u32(set, 12, value.modified);
    put_u32(set, 16, value.accessed);
    set[20] = value.create_centiseconds;
    set[21] = value.modified_centiseconds;
    set[22] = value.create_utc_offset;
    set[23] = value.modified_utc_offset;
    set[24] = value.accessed_utc_offset;
}

fn set_checksum(set: &mut [u8]) {
    put_u16(set, 2, 0);
    let checksum = set
        .iter()
        .copied()
        .enumerate()
        .filter(|(index, _)| !matches!(*index, 2 | 3))
        .fold(0_u16, |sum, (_, byte)| {
            sum.rotate_right(1).wrapping_add(u16::from(byte))
        });
    put_u16(set, 2, checksum);
}

/// Builds a complete but deliberately ASCII-only Up-case Table for isolated serializer tests.
///
/// This table is structurally valid exFAT, but it is **not** an interoperability profile: all
/// non-ASCII code units use identity mapping. Production callers must supply an appropriate
/// caller-selected complete table through [`ExfatVolumeProfile`].
#[must_use]
pub fn non_interoperable_ascii_test_upcase_table() -> Vec<u8> {
    let mut bytes = Vec::with_capacity(260);
    for unit in 0_u16..128 {
        let mapped = if (u16::from(b'a')..=u16::from(b'z')).contains(&unit) {
            unit - 0x20
        } else {
            unit
        };
        bytes.extend_from_slice(&mapped.to_le_bytes());
    }
    bytes.extend_from_slice(&0xffff_u16.to_le_bytes());
    bytes.extend_from_slice(&65_408_u16.to_le_bytes());
    bytes
}

fn build_boot_regions(
    geometry: &ExfatDestinationGeometry,
    options: ExfatSerializeOptions,
    percent_in_use: u8,
) -> Result<Vec<u8>, ExfatSerializeError> {
    let sector = usize::try_from(geometry.bytes_per_sector)
        .map_err(|_| ExfatSerializeError::ArithmeticOverflow("sector bytes"))?;
    let region_bytes = sector
        .checked_mul(12)
        .ok_or(ExfatSerializeError::ArithmeticOverflow("boot region bytes"))?;
    let mut main = vec![0_u8; region_bytes];
    main[0..3].copy_from_slice(&[0xeb, 0x76, 0x90]);
    main[3..11].copy_from_slice(b"EXFAT   ");
    put_u64(&mut main, 64, options.partition_offset_sectors);
    put_u64(&mut main, 72, geometry.volume_sectors);
    put_u32(&mut main, 80, geometry.fat_offset_sectors);
    put_u32(&mut main, 84, geometry.fat_length_sectors);
    put_u32(&mut main, 88, geometry.cluster_heap_offset_sectors);
    put_u32(&mut main, 92, geometry.cluster_count);
    put_u32(&mut main, 96, geometry.root_directory_cluster);
    put_u32(&mut main, 100, options.volume_serial_number);
    put_u16(&mut main, 104, 0x0100);
    main[108] = u8::try_from(geometry.bytes_per_sector.trailing_zeros())
        .map_err(|_| ExfatSerializeError::ArithmeticOverflow("sector shift"))?;
    main[109] =
        u8::try_from((geometry.bytes_per_cluster / geometry.bytes_per_sector).trailing_zeros())
            .map_err(|_| ExfatSerializeError::ArithmeticOverflow("cluster shift"))?;
    main[110] = 1;
    main[111] = options.drive_select;
    main[112] = percent_in_use;
    put_u16(&mut main, 510, 0xaa55);
    for index in 1..=8 {
        put_u32(&mut main, index * sector + sector - 4, 0xaa55_0000);
    }
    let checksum = main[..11 * sector]
        .iter()
        .copied()
        .enumerate()
        .filter(|(index, _)| !matches!(*index, 106 | 107 | 112))
        .fold(0_u32, |sum, (_, byte)| {
            sum.rotate_right(1).wrapping_add(u32::from(byte))
        });
    for offset in (11 * sector..12 * sector).step_by(4) {
        put_u32(&mut main, offset, checksum);
    }
    let mut both = main.clone();
    both.extend_from_slice(&main);
    Ok(both)
}

fn reservations_for(
    geometry: &ExfatDestinationGeometry,
    bitmap: Allocation,
    upcase: Allocation,
    directories: &[ObjectId],
    layouts: &BTreeMap<ObjectId, ObjectLayout>,
) -> Result<Vec<DestinationReservation>, ExfatSerializeError> {
    let sector = u64::from(geometry.bytes_per_sector);
    let mut output = vec![
        DestinationReservation {
            range: ByteRange {
                offset: 0,
                length: 12 * sector,
            },
            kind: ReservationKind::BootRegion,
        },
        DestinationReservation {
            range: ByteRange {
                offset: 12 * sector,
                length: 12 * sector,
            },
            kind: ReservationKind::BootRegion,
        },
        DestinationReservation {
            range: ByteRange {
                offset: u64::from(geometry.fat_offset_sectors) * sector,
                length: u64::from(geometry.fat_length_sectors) * sector,
            },
            kind: ReservationKind::AllocationMetadata,
        },
        allocation_reservation(geometry, bitmap, ReservationKind::AllocationMetadata)?,
        allocation_reservation(geometry, upcase, ReservationKind::AllocationMetadata)?,
    ];
    for object in directories {
        output.push(allocation_reservation(
            geometry,
            allocation_from_clusters(&layouts[object].directory_clusters)?,
            ReservationKind::NamespaceMetadata,
        )?);
    }
    output.sort_unstable_by_key(|item| item.range.offset);
    Ok(output)
}

fn allocation_reservation(
    geometry: &ExfatDestinationGeometry,
    allocation: Allocation,
    kind: ReservationKind,
) -> Result<DestinationReservation, ExfatSerializeError> {
    Ok(DestinationReservation {
        range: ByteRange {
            offset: cluster_offset(geometry, allocation.first_cluster)?,
            length: u64::from(allocation.cluster_count) * u64::from(geometry.bytes_per_cluster),
        },
        kind,
    })
}

fn allocation_write(
    geometry: &ExfatDestinationGeometry,
    allocation: Allocation,
    bytes: Vec<u8>,
) -> Result<OverlayWrite, ExfatSerializeError> {
    Ok(OverlayWrite {
        offset: cluster_offset(geometry, allocation.first_cluster)?,
        bytes,
    })
}

fn cluster_offset(
    geometry: &ExfatDestinationGeometry,
    cluster: u32,
) -> Result<u64, ExfatSerializeError> {
    u64::from(geometry.cluster_heap_offset_sectors)
        .checked_mul(u64::from(geometry.bytes_per_sector))
        .and_then(|heap| {
            u64::from(cluster.checked_sub(2)?)
                .checked_mul(u64::from(geometry.bytes_per_cluster))
                .and_then(|relative| heap.checked_add(relative))
        })
        .ok_or(ExfatSerializeError::ArithmeticOverflow(
            "cluster byte offset",
        ))
}

fn allocation_from_clusters(clusters: &[u32]) -> Result<Allocation, ExfatSerializeError> {
    let first = *clusters
        .first()
        .ok_or(ExfatSerializeError::ArithmeticOverflow(
            "empty metadata allocation",
        ))?;
    if !clusters.windows(2).all(|pair| pair[1] == pair[0] + 1) {
        return Err(ExfatSerializeError::InvalidGeometry(
            "metadata allocation is not contiguous",
        ));
    }
    Ok(Allocation {
        first_cluster: first,
        cluster_count: u32::try_from(clusters.len())
            .map_err(|_| ExfatSerializeError::ArithmeticOverflow("metadata cluster count"))?,
    })
}

fn expand_allocation(allocation: Allocation) -> Result<Vec<u32>, ExfatSerializeError> {
    (0..allocation.cluster_count)
        .map(|index| {
            allocation
                .first_cluster
                .checked_add(index)
                .ok_or(ExfatSerializeError::ArithmeticOverflow("cluster chain"))
        })
        .collect()
}

fn write_chain(fat: &mut [u8], clusters: &[u32]) -> Result<(), ExfatSerializeError> {
    for (index, cluster) in clusters.iter().copied().enumerate() {
        let next = clusters.get(index + 1).copied().unwrap_or(END_OF_CHAIN);
        let offset = usize::try_from(cluster)
            .map_err(|_| ExfatSerializeError::ArithmeticOverflow("FAT cluster index"))?
            .checked_mul(4)
            .ok_or(ExfatSerializeError::ArithmeticOverflow("FAT byte offset"))?;
        if offset + 4 > fat.len() {
            return Err(ExfatSerializeError::InvalidGeometry(
                "FAT chain exceeds FAT",
            ));
        }
        put_u32(fat, offset, next);
    }
    Ok(())
}

fn fat_byte_length(geometry: &ExfatDestinationGeometry) -> Result<usize, ExfatSerializeError> {
    usize::try_from(u64::from(geometry.fat_length_sectors) * u64::from(geometry.bytes_per_sector))
        .map_err(|_| ExfatSerializeError::ArithmeticOverflow("FAT byte length"))
}

fn padded_allocation_bytes(
    allocation: Allocation,
    cluster_bytes: u32,
) -> Result<usize, ExfatSerializeError> {
    usize::try_from(u64::from(allocation.cluster_count) * u64::from(cluster_bytes))
        .map_err(|_| ExfatSerializeError::ArithmeticOverflow("allocation byte length"))
}

fn clusters_for(bytes: u64, cluster_bytes: u32) -> Result<u32, ExfatSerializeError> {
    u32::try_from(bytes.div_ceil(u64::from(cluster_bytes)).max(1))
        .map_err(|_| ExfatSerializeError::ArithmeticOverflow("allocation cluster count"))
}

fn align_up(value: u64, alignment: u64) -> Result<u64, ExfatSerializeError> {
    value
        .checked_add(alignment - 1)
        .map(|sum| sum / alignment * alignment)
        .ok_or(ExfatSerializeError::ArithmeticOverflow("alignment"))
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
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::extent::{Extent, ExtentGraph};
    use crate::fs::exfat_directory::{DirectoryContext, DirectoryRecord, parse_directory};
    use crate::fs::exfat_inventory::{ExfatInventoryLimits, inventory_image};
    use crate::fs::exfat_normalize::{ExfatNormalizeLimits, normalize_inventory};
    use crate::fs::exfat_region::{ExfatBootRegionComparison, validate_boot_regions};
    use crate::image::ImageFile;
    use crate::object::{
        NamespaceEntry, ObjectGraphLimits, ObjectRecord, ObjectSemantics, ObjectStream, StreamFlags,
    };

    const VOLUME_BYTES: u64 = 4 * 1024 * 1024;
    const GRAPH_LIMITS: ObjectGraphLimits = ObjectGraphLimits {
        max_objects: 4096,
        max_entries: 4096,
        max_streams: 4096,
        max_name_code_units: 255,
    };

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
    struct TempImage(PathBuf);
    impl TempImage {
        fn create(bytes: &[u8]) -> Self {
            let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "starconverter-exfat-serialize-{}-{id}.img",
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

    const fn timestamp() -> ExfatTimestamps {
        let midnight_2024_01_01 = ((2024 - 1980) << 25) | (1 << 21) | (1 << 16);
        ExfatTimestamps {
            create: midnight_2024_01_01,
            modified: midnight_2024_01_01,
            accessed: midnight_2024_01_01,
            create_centiseconds: 0,
            modified_centiseconds: 0,
            create_utc_offset: 0,
            modified_utc_offset: 0,
            accessed_utc_offset: 0,
        }
    }

    const fn root() -> ObjectRecord {
        ObjectRecord {
            id: ObjectId(1),
            kind: ObjectKind::Directory,
            link_count: 0,
            semantics: ObjectSemantics {
                has_security_descriptor: false,
                is_reparse_point: false,
            },
            streams: Vec::new(),
        }
    }

    fn graph(
        objects: Vec<ObjectRecord>,
        entries: Vec<NamespaceEntry>,
        extents: Vec<Extent>,
    ) -> ObjectGraph {
        let extents = ExtentGraph::build(extents, VOLUME_BYTES, 4096).unwrap();
        ObjectGraph::build(ObjectId(1), objects, entries, extents, GRAPH_LIMITS).unwrap()
    }

    fn candidate(plan: &ExfatSerializationPlan) -> Vec<u8> {
        let mut bytes = vec![0_u8; usize::try_from(plan.geometry.volume_bytes).unwrap()];
        for write in plan.overlay.writes() {
            let start = usize::try_from(write.offset).unwrap();
            bytes[start..start + write.bytes.len()].copy_from_slice(&write.bytes);
        }
        bytes
    }

    fn profile(upcase: &[u8]) -> ExfatVolumeProfile<'_> {
        ExfatVolumeProfile {
            volume_label: None,
            encoded_upcase_table: upcase,
            upcase_checksum: table_checksum(upcase),
            source_preservation: ExfatPreservationEvidence::default(),
            allocated_bad_clusters: 0,
        }
    }

    fn complete_upcase_with_non_ascii_mapping() -> Vec<u8> {
        let mut bytes = Vec::with_capacity(65_536 * 2);
        for unit in 0_u16..=u16::MAX {
            let mapped = match unit {
                0x0061..=0x007a => unit - 0x20,
                0x00e4 => 0x00c4,
                _ => unit,
            };
            bytes.extend_from_slice(&mapped.to_le_bytes());
        }
        bytes
    }

    const fn small_inventory_limits() -> ExfatInventoryLimits {
        use crate::fs::exfat_discovery::ExfatDiscoveryLimits;
        use crate::fs::exfat_image::StreamReadLimits;
        ExfatInventoryLimits {
            discovery: ExfatDiscoveryLimits {
                root_stream: StreamReadLimits {
                    max_clusters: 4096,
                    max_bytes: 4 * 1024 * 1024,
                },
                system_stream: StreamReadLimits {
                    max_clusters: 4096,
                    max_bytes: 4 * 1024 * 1024,
                },
                max_directory_entries: 4096,
                max_secondary_entries: 18,
            },
            directory_stream: StreamReadLimits {
                max_clusters: 4096,
                max_bytes: 4 * 1024 * 1024,
            },
            max_objects: 4096,
            max_directories: 4096,
            max_depth: 4096,
            max_directory_bytes: 4 * 1024 * 1024,
            max_logical_bytes: 64 * 1024 * 1024,
            max_clusters: 4096,
            max_stream_clusters: 4096,
            max_extents: 8192,
            max_path_code_units: 64 * 1024,
            max_sibling_comparisons: 1_000_000,
        }
    }

    #[test]
    fn empty_graph_roundtrips_boot_region_and_root_directory_parser() {
        let graph = graph(vec![root()], Vec::new(), Vec::new());
        let plan = serialize_exfat_destination(
            &graph,
            &[],
            profile(&non_interoperable_ascii_test_upcase_table()),
            ExfatSerializeOptions::default(),
            ExfatSerializeLimits::default(),
        )
        .unwrap();
        let image = candidate(&plan);
        let boot_bytes = 24 * usize::try_from(plan.geometry.bytes_per_sector).unwrap();
        let regions = validate_boot_regions(
            &image[..boot_bytes],
            usize::try_from(plan.geometry.bytes_per_sector).unwrap(),
        )
        .unwrap();
        assert_eq!(regions.comparison, ExfatBootRegionComparison::Exact);
        assert_eq!(plan.primary_boot_write().offset, 0);
        assert_eq!(plan.primary_boot_write().bytes.len(), 12 * 512);
        assert_eq!(plan.backup_boot_write().offset, 12 * 512);
        assert_eq!(plan.backup_boot_write().bytes.len(), 12 * 512);
        assert!(plan.staging_writes().all(|write| write.offset >= 24 * 512));
        assert_eq!(
            plan.reservations
                .iter()
                .filter(|reservation| reservation.kind == ReservationKind::BootRegion)
                .map(|reservation| reservation.range)
                .collect::<Vec<_>>(),
            [
                ByteRange {
                    offset: 0,
                    length: 12 * 512
                },
                ByteRange {
                    offset: 12 * 512,
                    length: 12 * 512
                },
            ]
        );
        let root_write = plan.overlay.writes().last().unwrap();
        let summary = parse_directory(
            &root_write.bytes,
            DirectoryContext {
                cluster_count: plan.geometry.cluster_count,
                bytes_per_cluster: plan.geometry.bytes_per_cluster,
                number_of_fats: 1,
                is_root: true,
                max_entries: root_write.bytes.len() / ENTRY_BYTES,
                max_secondary_entries: 18,
            },
            |_| {},
        )
        .unwrap();
        assert_eq!(summary.files, 0);
        assert_eq!(summary.allocation_bitmaps, 1);
        assert_eq!(summary.upcase_tables, 1);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn fragmented_payload_is_reused_and_inventory_roundtrips() {
        let options = ExfatSerializeOptions::default();
        let limits = ExfatSerializeLimits::default();
        let geometry = choose_geometry(VOLUME_BYTES, options, limits).unwrap();
        let heap =
            u64::from(geometry.cluster_heap_offset_sectors) * u64::from(geometry.bytes_per_sector);
        let cluster = u64::from(geometry.bytes_per_cluster);
        let stream = StreamId(42);
        let file = ObjectRecord {
            id: ObjectId(2),
            kind: ObjectKind::File,
            link_count: 1,
            semantics: ObjectSemantics::default(),
            streams: vec![ObjectStream {
                id: stream,
                name: None,
                logical_bytes: cluster + 17,
                initialized_bytes: cluster + 17,
                mapped_bytes: 2 * cluster,
                allocated_bytes: 2 * cluster,
                flags: StreamFlags::default(),
                storage: StreamStorage::Extents,
            }],
        };
        let graph = graph(
            vec![root(), file],
            vec![NamespaceEntry {
                parent: ObjectId(1),
                target: ObjectId(2),
                name: "payload.bin".encode_utf16().collect(),
            }],
            vec![
                Extent {
                    stream,
                    logical_offset: 0,
                    length: cluster,
                    placement: Placement::Physical {
                        byte_offset: heap + 100 * cluster,
                    },
                    kind: ExtentKind::FileData,
                },
                Extent {
                    stream,
                    logical_offset: cluster,
                    length: cluster,
                    placement: Placement::Physical {
                        byte_offset: heap + 120 * cluster,
                    },
                    kind: ExtentKind::FileData,
                },
            ],
        );
        let plan = serialize_exfat_destination(
            &graph,
            &[ExfatObjectMetadata {
                object: ObjectId(2),
                file_attributes: 0x20,
                timestamps: timestamp(),
            }],
            profile(&non_interoperable_ascii_test_upcase_table()),
            options,
            limits,
        )
        .unwrap();
        assert_eq!(plan.reused_payloads[0].clusters, [102, 122]);
        assert!(!plan.reused_payloads[0].no_fat_chain);
        assert_eq!(plan.source_allocations.len(), 2);

        let temp = TempImage::create(&candidate(&plan));
        let image = ImageFile::open(&temp.0).unwrap();
        let boot = validate_boot_regions(&image.read_exact_at(0, 24 * 512).unwrap(), 512)
            .unwrap()
            .main
            .boot_sector;
        let inventory = inventory_image(&image, &boot, small_inventory_limits()).unwrap();
        let parsed = inventory
            .objects
            .iter()
            .find(|object| object.name == "payload.bin".encode_utf16().collect::<Vec<_>>())
            .unwrap();
        assert_eq!(parsed.valid_data_length, cluster + 17);
        assert_eq!(parsed.data_length, cluster + 17);
        assert_eq!(parsed.clusters, [102, 122]);
        let normalized = normalize_inventory(
            &inventory,
            ExfatNormalizeLimits {
                graph: GRAPH_LIMITS,
                max_extents: 8192,
            },
        )
        .unwrap();
        assert_eq!(normalized.graph.objects().len(), 2);
        let exact: Vec<_> = normalized
            .preservation
            .objects
            .iter()
            .filter_map(|object| {
                object.timestamps.map(|timestamps| ExfatObjectMetadata {
                    object: object.object,
                    file_attributes: object.file_attributes,
                    timestamps,
                })
            })
            .collect();
        let second_plan = serialize_exfat_destination(
            &normalized.graph,
            &exact,
            profile(&non_interoperable_ascii_test_upcase_table()),
            options,
            ExfatSerializeLimits::default(),
        )
        .unwrap();
        assert_eq!(second_plan.source_allocations.len(), 2);
        assert!(
            normalized
                .preservation
                .filesystem_extents
                .iter()
                .any(|extent| extent.kind == ExtentKind::DirectoryData)
        );
    }

    #[test]
    fn deep_directories_roundtrip_without_recursive_serializer_work() {
        let depth = 64_u64;
        let mut objects = vec![root()];
        let mut entries = Vec::new();
        let mut metadata = Vec::new();
        for id in 2..=depth + 1 {
            objects.push(ObjectRecord {
                id: ObjectId(id),
                kind: ObjectKind::Directory,
                link_count: 1,
                semantics: ObjectSemantics::default(),
                streams: Vec::new(),
            });
            entries.push(NamespaceEntry {
                parent: ObjectId(id - 1),
                target: ObjectId(id),
                name: format!("d{id}").encode_utf16().collect(),
            });
            metadata.push(ExfatObjectMetadata {
                object: ObjectId(id),
                file_attributes: DIRECTORY_ATTRIBUTE,
                timestamps: timestamp(),
            });
        }
        let graph = graph(objects, entries, Vec::new());
        let plan = serialize_exfat_destination(
            &graph,
            &metadata,
            profile(&non_interoperable_ascii_test_upcase_table()),
            ExfatSerializeOptions::default(),
            ExfatSerializeLimits::default(),
        )
        .unwrap();
        let temp = TempImage::create(&candidate(&plan));
        let image = ImageFile::open(&temp.0).unwrap();
        let boot = validate_boot_regions(&image.read_exact_at(0, 24 * 512).unwrap(), 512)
            .unwrap()
            .main
            .boot_sector;
        let inventory = inventory_image(&image, &boot, small_inventory_limits()).unwrap();
        assert_eq!(inventory.objects.len(), usize::try_from(depth + 1).unwrap());
        assert!(
            inventory
                .objects
                .iter()
                .filter(
                    |object| object.kind == crate::fs::exfat_inventory::ExfatObjectKind::Directory
                )
                .all(|object| object.flags.no_fat_chain)
        );
        let fat_offset = usize::try_from(
            u64::from(plan.geometry.fat_offset_sectors) * u64::from(plan.geometry.bytes_per_sector)
                + u64::from(plan.geometry.root_directory_cluster) * 4,
        )
        .unwrap();
        let candidate = candidate(&plan);
        assert_eq!(
            u32::from_le_bytes(candidate[fat_offset..fat_offset + 4].try_into().unwrap()),
            END_OF_CHAIN
        );
    }

    #[test]
    fn refuses_lossy_semantics_collisions_and_caps() {
        let collision_objects = vec![
            root(),
            ObjectRecord {
                id: ObjectId(2),
                kind: ObjectKind::File,
                link_count: 1,
                semantics: ObjectSemantics::default(),
                streams: Vec::new(),
            },
            ObjectRecord {
                id: ObjectId(3),
                kind: ObjectKind::File,
                link_count: 1,
                semantics: ObjectSemantics::default(),
                streams: Vec::new(),
            },
        ];
        let collision_entries = vec![
            NamespaceEntry {
                parent: ObjectId(1),
                target: ObjectId(2),
                name: "Readme".encode_utf16().collect(),
            },
            NamespaceEntry {
                parent: ObjectId(1),
                target: ObjectId(3),
                name: "README".encode_utf16().collect(),
            },
        ];
        let graph = graph(collision_objects, collision_entries, Vec::new());
        let metadata = [
            ExfatObjectMetadata {
                object: ObjectId(2),
                file_attributes: 0x20,
                timestamps: timestamp(),
            },
            ExfatObjectMetadata {
                object: ObjectId(3),
                file_attributes: 0x20,
                timestamps: timestamp(),
            },
        ];
        assert!(matches!(
            serialize_exfat_destination(
                &graph,
                &metadata,
                profile(&non_interoperable_ascii_test_upcase_table()),
                ExfatSerializeOptions::default(),
                ExfatSerializeLimits::default()
            ),
            Err(ExfatSerializeError::CaseInsensitiveCollision { .. })
        ));
        assert!(matches!(
            serialize_exfat_destination(
                &graph,
                &metadata,
                profile(&non_interoperable_ascii_test_upcase_table()),
                ExfatSerializeOptions::default(),
                ExfatSerializeLimits {
                    max_objects: 1,
                    ..ExfatSerializeLimits::default()
                }
            ),
            Err(ExfatSerializeError::LimitExceeded {
                field: "objects",
                ..
            })
        ));
    }

    #[test]
    fn root_records_are_parser_visible_at_byte_level() {
        let graph = graph(vec![root()], Vec::new(), Vec::new());
        let plan = serialize_exfat_destination(
            &graph,
            &[],
            profile(&non_interoperable_ascii_test_upcase_table()),
            ExfatSerializeOptions::default(),
            ExfatSerializeLimits::default(),
        )
        .unwrap();
        let root_write = plan.overlay.writes().last().unwrap();
        let mut kinds = Vec::new();
        parse_directory(
            &root_write.bytes,
            DirectoryContext {
                cluster_count: plan.geometry.cluster_count,
                bytes_per_cluster: plan.geometry.bytes_per_cluster,
                number_of_fats: 1,
                is_root: true,
                max_entries: root_write.bytes.len() / ENTRY_BYTES,
                max_secondary_entries: 18,
            },
            |record| {
                kinds.push(match record {
                    DirectoryRecord::AllocationBitmap(_) => 1,
                    DirectoryRecord::UpcaseTable(_) => 2,
                    _ => 3,
                });
            },
        )
        .unwrap();
        assert_eq!(kinds, [1, 2]);
    }

    #[test]
    fn selected_non_ascii_upcase_table_controls_collision_detection() {
        let objects = vec![
            root(),
            ObjectRecord {
                id: ObjectId(2),
                kind: ObjectKind::File,
                link_count: 1,
                semantics: ObjectSemantics::default(),
                streams: Vec::new(),
            },
            ObjectRecord {
                id: ObjectId(3),
                kind: ObjectKind::File,
                link_count: 1,
                semantics: ObjectSemantics::default(),
                streams: Vec::new(),
            },
        ];
        let entries = vec![
            NamespaceEntry {
                parent: ObjectId(1),
                target: ObjectId(2),
                name: "\u{e4}.txt".encode_utf16().collect(),
            },
            NamespaceEntry {
                parent: ObjectId(1),
                target: ObjectId(3),
                name: "\u{c4}.txt".encode_utf16().collect(),
            },
        ];
        let graph = graph(objects, entries, Vec::new());
        let metadata = [
            ExfatObjectMetadata {
                object: ObjectId(2),
                file_attributes: 0x20,
                timestamps: timestamp(),
            },
            ExfatObjectMetadata {
                object: ObjectId(3),
                file_attributes: 0x20,
                timestamps: timestamp(),
            },
        ];
        let upcase = complete_upcase_with_non_ascii_mapping();
        assert!(matches!(
            serialize_exfat_destination(
                &graph,
                &metadata,
                profile(&upcase),
                ExfatSerializeOptions::default(),
                ExfatSerializeLimits::default(),
            ),
            Err(ExfatSerializeError::CaseInsensitiveCollision {
                parent: ObjectId(1)
            })
        ));
    }

    #[test]
    fn exact_label_and_selected_upcase_roundtrip_through_parser_and_inventory() {
        let graph = graph(vec![root()], Vec::new(), Vec::new());
        let upcase = complete_upcase_with_non_ascii_mapping();
        let label: Vec<u16> = "V\u{d8}L".encode_utf16().collect();
        let checksum = table_checksum(&upcase);
        let plan = serialize_exfat_destination(
            &graph,
            &[],
            ExfatVolumeProfile {
                volume_label: Some(&label),
                encoded_upcase_table: &upcase,
                upcase_checksum: checksum,
                source_preservation: ExfatPreservationEvidence::default(),
                allocated_bad_clusters: 0,
            },
            ExfatSerializeOptions::default(),
            ExfatSerializeLimits::default(),
        )
        .unwrap();

        let root_write = plan.overlay.writes().last().unwrap();
        let mut parsed_label = None;
        let mut parsed_checksum = None;
        let summary = parse_directory(
            &root_write.bytes,
            DirectoryContext {
                cluster_count: plan.geometry.cluster_count,
                bytes_per_cluster: plan.geometry.bytes_per_cluster,
                number_of_fats: 1,
                is_root: true,
                max_entries: root_write.bytes.len() / ENTRY_BYTES,
                max_secondary_entries: 18,
            },
            |record| match record {
                DirectoryRecord::VolumeLabel(entry) => {
                    parsed_label = Some(entry.as_units().to_vec());
                }
                DirectoryRecord::UpcaseTable(entry) => {
                    parsed_checksum = Some(entry.table_checksum);
                }
                _ => {}
            },
        )
        .unwrap();
        assert_eq!(summary.volume_labels, 1);
        assert_eq!(parsed_label.as_deref(), Some(label.as_slice()));
        assert_eq!(parsed_checksum, Some(checksum));
        assert_eq!(
            &plan.overlay.writes()[plan.overlay.writes().len() - 2].bytes[..upcase.len()],
            upcase.as_slice()
        );

        let temp = TempImage::create(&candidate(&plan));
        let image = ImageFile::open(&temp.0).unwrap();
        let boot = validate_boot_regions(&image.read_exact_at(0, 24 * 512).unwrap(), 512)
            .unwrap()
            .main
            .boot_sector;
        let inventory = inventory_image(&image, &boot, small_inventory_limits()).unwrap();
        assert_eq!(inventory.root.directory.volume_labels, 1);
        assert_eq!(inventory.root.upcase_table.table_checksum, checksum);
        assert_eq!(inventory.root.upcase_mappings.map(0x00e4), 0x00c4);
    }

    #[test]
    fn refuses_preservation_evidence_it_cannot_emit_losslessly() {
        let graph = graph(vec![root()], Vec::new(), Vec::new());
        let upcase = complete_upcase_with_non_ascii_mapping();
        let evidence = ExfatPreservationEvidence {
            benign_primary_sets: 1,
            ..ExfatPreservationEvidence::default()
        };
        assert!(matches!(
            serialize_exfat_destination(
                &graph,
                &[],
                ExfatVolumeProfile {
                    source_preservation: evidence,
                    ..profile(&upcase)
                },
                ExfatSerializeOptions::default(),
                ExfatSerializeLimits::default(),
            ),
            Err(ExfatSerializeError::UnsupportedPreservationEvidence(_))
        ));
        assert!(matches!(
            serialize_exfat_destination(
                &graph,
                &[],
                ExfatVolumeProfile {
                    allocated_bad_clusters: 1,
                    ..profile(&upcase)
                },
                ExfatSerializeOptions::default(),
                ExfatSerializeLimits::default(),
            ),
            Err(ExfatSerializeError::UnsupportedPreservationEvidence(_))
        ));
    }
}
