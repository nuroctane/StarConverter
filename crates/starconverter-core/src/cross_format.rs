//! Pure cross-format adapters which bind preservation policy to destination serialization.
//!
//! The adapters in this module do not perform I/O and cannot authorize activation. They derive
//! target metadata only from a complete normalized source, run the fail-closed preservation
//! policy themselves, and then invoke a structural serializer. Exact format-specific evidence is
//! returned beside the destination plan as a versioned escrow payload.
//!
//! exFAT timestamps are local calendar values with optional 15-minute UTC offsets and 10 ms
//! creation/modification increments (Microsoft exFAT 1.00 specification, sections 7.4.5-7.4.10):
//! <https://learn.microsoft.com/en-us/windows/win32/fileio/exfat-specification>. NTFS FILETIME is
//! counted in 100 ns intervals from 1601-01-01 UTC:
//! <https://learn.microsoft.com/en-us/windows/win32/sysinfo/file-times>. When exFAT marks an
//! offset invalid, the specification directs implementations to treat UTC as local time; the raw
//! offset-validity byte remains in escrow so the transformation is reversible.

#![allow(clippy::module_name_repetitions)]

use std::collections::BTreeMap;
use std::fmt;

use crate::FileSystem;
use crate::GuaranteeMode;
use crate::extent::{Placement, StreamId};
use crate::fs::exfat_inventory::{ExfatPreservationEvidence, ExfatTimestamps};
use crate::fs::exfat_normalize::NormalizedExfat;
use crate::fs::exfat_serialize::{
    ExfatObjectMetadata, ExfatSerializationPlan, ExfatSerializeError, ExfatSerializeLimits,
    ExfatSerializeOptions, ExfatVolumeProfile, serialize_exfat_destination,
};
use crate::fs::exfat_upcase_serialize::{
    RECOMMENDED_EXFAT_UPCASE_CHECKSUM, RecommendedExfatUpcaseError, RecommendedExfatUpcaseLimits,
    generate_recommended_exfat_upcase,
};
use crate::fs::ntfs_inventory::NtfsExtentPlacement;
use crate::fs::ntfs_normalize::NormalizedNtfs;
use crate::fs::ntfs_serialize::{
    NTFS3G_SECURITY_ID_READ_WRITE, NtfsDestinationInputs, NtfsDestinationPlan, NtfsObjectMetadata,
    NtfsObjectTimestamps, NtfsSerializeError, NtfsSerializeLimits, NtfsVolumeProfile,
    plan_ntfs_destination_with_metadata_and_volume,
};
use crate::geometry::{ByteRange, SourceAllocation};
use crate::object::{ObjectGraph, ObjectGraphError, ObjectGraphLimits, ObjectId, ObjectKind};
use crate::preservation::{
    PreservationError, PreservationField, PreservationLimits, PreservationReport, evaluate_exfat,
    evaluate_ntfs,
};

const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const TICKS_PER_SECOND: u64 = 10_000_000;
const TICKS_PER_10_MILLISECONDS: u64 = 100_000;
const SECONDS_PER_DAY: u64 = 86_400;
const EXFAT_EPOCH_YEAR: u32 = 1980;
const FILETIME_EPOCH_YEAR: u32 = 1601;

/// Deterministic target choices which cannot be inferred from an exFAT object graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExfatToNtfsOptions {
    pub partition_offset_sectors: u64,
    pub cluster_bytes: u32,
    /// FILETIME used only for NTFS system records and the target root, whose source exFAT root has
    /// no file-entry timestamp fields.
    pub system_timestamp: u64,
}

impl Default for ExfatToNtfsOptions {
    fn default() -> Self {
        Self {
            partition_offset_sectors: 0,
            cluster_bytes: 4096,
            system_timestamp: 0,
        }
    }
}

/// Aggregate caps applied by policy and serializer before any destination plan is returned.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExfatToNtfsLimits {
    pub preservation: PreservationLimits,
    pub serializer: NtfsSerializeLimits,
}

/// Policy-bound structural proposal. `destination.activation_ready()` remains false until the
/// serializer's independently documented filesystem/interoperability gaps are closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExfatToNtfsPlan {
    pub preservation: PreservationReport,
    /// Semantic graph actually supplied to the destination serializer/coordinator.
    pub target_graph: ObjectGraph,
    pub object_metadata: Vec<NtfsObjectMetadata>,
    pub volume_label: Option<Vec<u16>>,
    pub destination: NtfsDestinationPlan,
}

/// Deterministic exFAT geometry choices for a normalized NTFS source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtfsToExfatOptions {
    pub bytes_per_sector: u32,
    pub bytes_per_cluster: u32,
    pub partition_offset_sectors: u64,
    pub drive_select: u8,
}

impl Default for NtfsToExfatOptions {
    fn default() -> Self {
        Self {
            bytes_per_sector: 512,
            bytes_per_cluster: 4096,
            partition_offset_sectors: 0,
            drive_select: 0x80,
        }
    }
}

/// Aggregate caps for NTFS preservation classification, canonical up-case generation, and exFAT
/// serialization.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NtfsToExfatLimits {
    pub preservation: PreservationLimits,
    pub upcase: RecommendedExfatUpcaseLimits,
    pub serializer: ExfatSerializeLimits,
}

/// Policy-bound NTFS-to-exFAT structural proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsToExfatPlan {
    pub preservation: PreservationReport,
    /// Security enforcement is removed from the exFAT view only after exact descriptor bytes have
    /// been accepted into escrow. Source evidence remains intact in `preservation`.
    pub target_graph: ObjectGraph,
    pub object_metadata: Vec<ExfatObjectMetadata>,
    /// Exact source label when it is natively representable; otherwise `None` and the source value
    /// remains in escrow.
    pub destination_volume_label: Option<Vec<u16>>,
    /// Deterministic 32-bit target identity. The exact 64-bit NTFS serial remains in escrow.
    pub destination_volume_serial_number: u32,
    pub destination: ExfatSerializationPlan,
}

/// Refusal from policy, exact metadata conversion, or structural NTFS serialization.
#[derive(Debug)]
pub enum ExfatToNtfsError {
    ContentOnlyIsNotLossless,
    Preservation(PreservationError),
    PreservationRefused { blockers: Vec<PreservationField> },
    MissingObjectEvidence(ObjectId),
    DuplicateObjectEvidence(ObjectId),
    UnknownObjectEvidence(ObjectId),
    MissingTimestamp(ObjectId),
    InvalidTimestamp(ObjectId),
    AllocationFailed,
    SourceMetadataLimitExceeded { actual: usize, maximum: usize },
    GraphProjection(ObjectGraphError),
    Serialization(NtfsSerializeError),
}

impl fmt::Display for ExfatToNtfsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ContentOnlyIsNotLossless => formatter.write_str(
                "content-only mode cannot produce a lossless exFAT-to-NTFS conversion plan",
            ),
            Self::Preservation(error) => write!(formatter, "preservation policy failed: {error}"),
            Self::PreservationRefused { blockers } => write!(
                formatter,
                "preservation policy refused exFAT-to-NTFS conversion: {blockers:?}"
            ),
            Self::MissingObjectEvidence(object) => write!(
                formatter,
                "object {} has no exact exFAT sidecar evidence",
                object.0
            ),
            Self::DuplicateObjectEvidence(object) => write!(
                formatter,
                "object {} has duplicate exFAT sidecar evidence",
                object.0
            ),
            Self::UnknownObjectEvidence(object) => write!(
                formatter,
                "exFAT sidecar evidence names unknown object {}",
                object.0
            ),
            Self::MissingTimestamp(object) => {
                write!(formatter, "object {} has no exFAT timestamps", object.0)
            }
            Self::InvalidTimestamp(object) => {
                write!(
                    formatter,
                    "object {} has an invalid exFAT timestamp",
                    object.0
                )
            }
            Self::AllocationFailed => {
                formatter.write_str("could not allocate bounded cross-format metadata")
            }
            Self::SourceMetadataLimitExceeded { actual, maximum } => write!(
                formatter,
                "source metadata requires {actual} allocations, exceeding {maximum}"
            ),
            Self::GraphProjection(error) => write!(formatter, "graph projection failed: {error}"),
            Self::Serialization(error) => write!(formatter, "NTFS serialization failed: {error}"),
        }
    }
}

impl std::error::Error for ExfatToNtfsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Preservation(error) => Some(error),
            Self::Serialization(error) => Some(error),
            Self::GraphProjection(error) => Some(error),
            _ => None,
        }
    }
}

impl From<PreservationError> for ExfatToNtfsError {
    fn from(value: PreservationError) -> Self {
        Self::Preservation(value)
    }
}

impl From<NtfsSerializeError> for ExfatToNtfsError {
    fn from(value: NtfsSerializeError) -> Self {
        Self::Serialization(value)
    }
}

/// Refusal from NTFS policy, exact metadata conversion, canonical profile generation, or exFAT
/// serialization.
#[derive(Debug)]
pub enum NtfsToExfatError {
    ContentOnlyIsNotLossless,
    Preservation(PreservationError),
    PreservationRefused { blockers: Vec<PreservationField> },
    MissingObjectEvidence(ObjectId),
    DuplicateObjectEvidence(ObjectId),
    UnknownObjectEvidence(ObjectId),
    MissingStandardInformation(ObjectId),
    TimestampOutsideExfatRange(ObjectId),
    AttributesOutsideExfatRange(ObjectId),
    AllocationFailed,
    SourceMetadataLimitExceeded { actual: usize, maximum: usize },
    GraphProjection(ObjectGraphError),
    Upcase(RecommendedExfatUpcaseError),
    Serialization(ExfatSerializeError),
}

impl fmt::Display for NtfsToExfatError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ContentOnlyIsNotLossless => formatter.write_str(
                "content-only mode cannot produce a lossless NTFS-to-exFAT conversion plan",
            ),
            Self::Preservation(error) => write!(formatter, "preservation policy failed: {error}"),
            Self::PreservationRefused { blockers } => write!(
                formatter,
                "preservation policy refused NTFS-to-exFAT conversion: {blockers:?}"
            ),
            Self::MissingObjectEvidence(object) => write!(
                formatter,
                "object {} has no exact NTFS sidecar evidence",
                object.0
            ),
            Self::DuplicateObjectEvidence(object) => write!(
                formatter,
                "object {} has duplicate NTFS sidecar evidence",
                object.0
            ),
            Self::UnknownObjectEvidence(object) => write!(
                formatter,
                "NTFS sidecar evidence names unknown object {}",
                object.0
            ),
            Self::MissingStandardInformation(object) => write!(
                formatter,
                "object {} has no `$STANDARD_INFORMATION` evidence",
                object.0
            ),
            Self::TimestampOutsideExfatRange(object) => write!(
                formatter,
                "object {} has a timestamp outside exFAT's 1980-2107 range",
                object.0
            ),
            Self::AttributesOutsideExfatRange(object) => write!(
                formatter,
                "object {} has DOS attributes which cannot be represented by exFAT",
                object.0
            ),
            Self::AllocationFailed => {
                formatter.write_str("could not allocate bounded cross-format metadata")
            }
            Self::SourceMetadataLimitExceeded { actual, maximum } => write!(
                formatter,
                "source metadata requires {actual} allocations, exceeding {maximum}"
            ),
            Self::GraphProjection(error) => write!(formatter, "graph projection failed: {error}"),
            Self::Upcase(error) => {
                write!(
                    formatter,
                    "could not generate recommended exFAT up-case table: {error}"
                )
            }
            Self::Serialization(error) => write!(formatter, "exFAT serialization failed: {error}"),
        }
    }
}

impl std::error::Error for NtfsToExfatError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Preservation(error) => Some(error),
            Self::Upcase(error) => Some(error),
            Self::Serialization(error) => Some(error),
            Self::GraphProjection(error) => Some(error),
            _ => None,
        }
    }
}

impl From<PreservationError> for NtfsToExfatError {
    fn from(value: PreservationError) -> Self {
        Self::Preservation(value)
    }
}

impl From<RecommendedExfatUpcaseError> for NtfsToExfatError {
    fn from(value: RecommendedExfatUpcaseError) -> Self {
        Self::Upcase(value)
    }
}

impl From<ExfatSerializeError> for NtfsToExfatError {
    fn from(value: ExfatSerializeError) -> Self {
        Self::Serialization(value)
    }
}

/// Produces a policy-bound exFAT-to-NTFS structural candidate without opening or writing a file.
///
/// # Errors
///
/// Refuses content-only mode, any preservation blocker, incomplete/inconsistent sidecar evidence,
/// invalid timestamps, cap exhaustion, and every refusal exposed by the NTFS serializer.
pub fn plan_lossless_exfat_to_ntfs(
    normalized: &NormalizedExfat,
    mode: GuaranteeMode,
    options: ExfatToNtfsOptions,
    limits: ExfatToNtfsLimits,
) -> Result<ExfatToNtfsPlan, ExfatToNtfsError> {
    if mode == GuaranteeMode::ContentOnly {
        return Err(ExfatToNtfsError::ContentOnlyIsNotLossless);
    }
    let preservation = evaluate_exfat(normalized, FileSystem::Ntfs, mode, limits.preservation)?;
    if !preservation.permitted {
        let blockers = preservation.blockers;
        return Err(ExfatToNtfsError::PreservationRefused { blockers });
    }

    let object_metadata = map_exfat_object_metadata(normalized, options.system_timestamp)?;
    let volume_label = normalized
        .preservation
        .volume_label
        .map(|label| label.as_units().to_vec());
    let inputs = NtfsDestinationInputs {
        image_bytes: normalized.graph.extents().volume_bytes(),
        partition_offset_sectors: options.partition_offset_sectors,
        cluster_bytes: options.cluster_bytes,
        volume_serial_number: u64::from(normalized.preservation.volume_serial_number),
        timestamp: options.system_timestamp,
    };
    let target_graph = project_exfat_graph_for_ntfs(normalized)?;
    let mut destination = plan_ntfs_destination_with_metadata_and_volume(
        &normalized.graph,
        inputs,
        &object_metadata,
        NtfsVolumeProfile {
            volume_label: volume_label.as_deref(),
        },
        limits.serializer,
    )?;
    retain_exfat_source_metadata(
        &mut destination.source_allocations,
        normalized,
        limits.serializer.max_extents,
    )?;
    Ok(ExfatToNtfsPlan {
        preservation,
        target_graph,
        object_metadata,
        volume_label,
        destination,
    })
}

fn project_exfat_graph_for_ntfs(
    normalized: &NormalizedExfat,
) -> Result<ObjectGraph, ExfatToNtfsError> {
    let mut objects = normalized.graph.objects().to_vec();
    for object in &mut objects {
        // The destination writer assigns the exact pinned ordinary read/write descriptor to every
        // object, including the root. This is target-native protection rather than a claim that
        // exFAT carried ACL semantics, but the target graph must describe what reinspection sees.
        object.semantics.has_security_descriptor = true;
    }
    let entries = normalized.graph.entries().to_vec();
    let maximum_name_units = entries
        .iter()
        .map(|entry| entry.name.len())
        .max()
        .unwrap_or(1);
    let stream_count = objects
        .iter()
        .map(|object| object.streams.len())
        .sum::<usize>();
    ObjectGraph::build(
        normalized.graph.root(),
        objects,
        entries,
        normalized.graph.extents().clone(),
        ObjectGraphLimits {
            max_objects: normalized.graph.objects().len().max(1),
            max_entries: normalized.graph.entries().len().max(1),
            max_streams: stream_count.max(1),
            max_name_code_units: maximum_name_units,
        },
    )
    .map_err(ExfatToNtfsError::GraphProjection)
}

/// Produces a policy-bound NTFS-to-exFAT structural candidate without opening or writing a file.
///
/// NTFS timestamps are deterministically rounded down to exFAT's available resolution and written
/// as UTC with a valid zero offset. NTFS-only precision, MFT-change time, namespace variants, and
/// the full 64-bit serial remain in the returned escrow.
///
/// # Errors
///
/// Refuses content-only mode, any preservation blocker, incomplete/inconsistent sidecar evidence,
/// timestamps outside 1980-2107, cap exhaustion, and every refusal exposed by the exFAT writer.
pub fn plan_lossless_ntfs_to_exfat(
    normalized: &NormalizedNtfs,
    mode: GuaranteeMode,
    options: NtfsToExfatOptions,
    limits: NtfsToExfatLimits,
) -> Result<NtfsToExfatPlan, NtfsToExfatError> {
    if mode == GuaranteeMode::ContentOnly {
        return Err(NtfsToExfatError::ContentOnlyIsNotLossless);
    }
    let preservation = evaluate_ntfs(normalized, FileSystem::ExFat, mode, limits.preservation)?;
    if !preservation.permitted {
        let blockers = preservation.blockers;
        return Err(NtfsToExfatError::PreservationRefused { blockers });
    }
    let object_metadata = map_ntfs_object_metadata(normalized)?;
    let destination_volume_label = normalized
        .preservation
        .volume_label
        .as_ref()
        .filter(|label| is_representable_exfat_label(label))
        .cloned();
    let serial = fold_ntfs_volume_serial(normalized.preservation.volume_serial_number);
    let upcase = generate_recommended_exfat_upcase(limits.upcase)?;
    let target_graph = project_ntfs_graph_for_exfat(normalized)?;
    let mut destination = serialize_exfat_destination(
        &target_graph,
        &object_metadata,
        ExfatVolumeProfile {
            volume_label: destination_volume_label.as_deref(),
            encoded_upcase_table: upcase.encoded_bytes(),
            upcase_checksum: RECOMMENDED_EXFAT_UPCASE_CHECKSUM,
            source_preservation: ExfatPreservationEvidence::default(),
            allocated_bad_clusters: 0,
        },
        ExfatSerializeOptions {
            bytes_per_sector: options.bytes_per_sector,
            bytes_per_cluster: options.bytes_per_cluster,
            partition_offset_sectors: options.partition_offset_sectors,
            volume_serial_number: serial,
            drive_select: options.drive_select,
        },
        limits.serializer,
    )?;
    retain_ntfs_source_metadata(
        &mut destination.source_allocations,
        normalized,
        limits.serializer.max_extents,
    )?;
    Ok(NtfsToExfatPlan {
        preservation,
        target_graph,
        object_metadata,
        destination_volume_label,
        destination_volume_serial_number: serial,
        destination,
    })
}

fn project_ntfs_graph_for_exfat(
    normalized: &NormalizedNtfs,
) -> Result<ObjectGraph, NtfsToExfatError> {
    let mut objects = normalized.graph.objects().to_vec();
    for object in &mut objects {
        // exFAT cannot enforce per-object ACLs. The preservation policy has already required and
        // produced exact escrow before this projection is reached, so only the destination view
        // loses the enforcement marker; source identities and descriptor bytes stay in evidence.
        object.semantics.has_security_descriptor = false;
    }
    let entries = normalized.graph.entries().to_vec();
    let maximum_name_units = entries
        .iter()
        .map(|entry| entry.name.len())
        .max()
        .unwrap_or(1);
    let stream_count = objects
        .iter()
        .map(|object| object.streams.len())
        .sum::<usize>();
    ObjectGraph::build(
        normalized.graph.root(),
        objects,
        entries,
        normalized.graph.extents().clone(),
        ObjectGraphLimits {
            max_objects: normalized.graph.objects().len().max(1),
            max_entries: normalized.graph.entries().len().max(1),
            max_streams: stream_count.max(1),
            max_name_code_units: maximum_name_units,
        },
    )
    .map_err(NtfsToExfatError::GraphProjection)
}

fn map_exfat_object_metadata(
    normalized: &NormalizedExfat,
    root_timestamp: u64,
) -> Result<Vec<NtfsObjectMetadata>, ExfatToNtfsError> {
    let mut by_object = BTreeMap::new();
    for evidence in &normalized.preservation.objects {
        if by_object.insert(evidence.object, evidence).is_some() {
            return Err(ExfatToNtfsError::DuplicateObjectEvidence(evidence.object));
        }
    }
    let mut metadata = Vec::new();
    metadata
        .try_reserve_exact(normalized.graph.objects().len())
        .map_err(|_| ExfatToNtfsError::AllocationFailed)?;
    for object in normalized.graph.objects() {
        let evidence = by_object
            .get(&object.id)
            .ok_or(ExfatToNtfsError::MissingObjectEvidence(object.id))?;
        if object.id == normalized.graph.root() {
            metadata.push(NtfsObjectMetadata {
                object: object.id,
                object_kind: ObjectKind::Directory,
                timestamps: NtfsObjectTimestamps {
                    creation_time: root_timestamp,
                    modification_time: root_timestamp,
                    mft_change_time: root_timestamp,
                    access_time: root_timestamp,
                },
                dos_file_attributes: FILE_ATTRIBUTE_DIRECTORY,
                security_id: NTFS3G_SECURITY_ID_READ_WRITE,
            });
            continue;
        }
        let timestamps = evidence
            .timestamps
            .ok_or(ExfatToNtfsError::MissingTimestamp(object.id))?;
        metadata.push(NtfsObjectMetadata {
            object: object.id,
            object_kind: object.kind,
            timestamps: map_exfat_timestamps(timestamps)
                .ok_or(ExfatToNtfsError::InvalidTimestamp(object.id))?,
            dos_file_attributes: u32::from(evidence.file_attributes),
            security_id: NTFS3G_SECURITY_ID_READ_WRITE,
        });
    }
    if by_object.len() != normalized.graph.objects().len() {
        let unknown = by_object
            .keys()
            .find(|candidate| {
                !normalized
                    .graph
                    .objects()
                    .iter()
                    .any(|object| object.id == **candidate)
            })
            .copied()
            .expect("different evidence count after proving every graph object implies an unknown");
        return Err(ExfatToNtfsError::UnknownObjectEvidence(unknown));
    }
    Ok(metadata)
}

fn retain_exfat_source_metadata(
    allocations: &mut Vec<SourceAllocation>,
    normalized: &NormalizedExfat,
    maximum: usize,
) -> Result<(), ExfatToNtfsError> {
    let required = allocations
        .len()
        .checked_add(normalized.preservation.filesystem_extents.len())
        .ok_or(ExfatToNtfsError::SourceMetadataLimitExceeded {
            actual: usize::MAX,
            maximum,
        })?;
    if required > maximum {
        return Err(ExfatToNtfsError::SourceMetadataLimitExceeded {
            actual: required,
            maximum,
        });
    }
    allocations
        .try_reserve_exact(normalized.preservation.filesystem_extents.len())
        .map_err(|_| ExfatToNtfsError::AllocationFailed)?;
    for extent in &normalized.preservation.filesystem_extents {
        let Placement::Physical { byte_offset } = extent.placement else {
            continue;
        };
        allocations.push(SourceAllocation {
            stream: extent.stream,
            logical_offset: extent.logical_offset,
            range: ByteRange {
                offset: byte_offset,
                length: extent.length,
            },
            movable: false,
        });
    }
    allocations.sort_unstable_by_key(|allocation| allocation.range.offset);
    Ok(())
}

fn retain_ntfs_source_metadata(
    allocations: &mut Vec<SourceAllocation>,
    normalized: &NormalizedNtfs,
    maximum: usize,
) -> Result<(), NtfsToExfatError> {
    let physical = normalized
        .preservation
        .source_extents
        .iter()
        .filter(|extent| matches!(extent.placement, NtfsExtentPlacement::Physical { .. }))
        .filter(|extent| {
            !allocations.iter().any(|allocation| {
                let NtfsExtentPlacement::Physical { byte_offset } = extent.placement else {
                    return false;
                };
                allocation.range.offset == byte_offset && allocation.range.length == extent.length
            })
        })
        .count();
    let required = allocations.len().checked_add(physical).ok_or(
        NtfsToExfatError::SourceMetadataLimitExceeded {
            actual: usize::MAX,
            maximum,
        },
    )?;
    if required > maximum {
        return Err(NtfsToExfatError::SourceMetadataLimitExceeded {
            actual: required,
            maximum,
        });
    }
    allocations
        .try_reserve_exact(physical)
        .map_err(|_| NtfsToExfatError::AllocationFailed)?;
    for extent in &normalized.preservation.source_extents {
        let NtfsExtentPlacement::Physical { byte_offset } = extent.placement else {
            continue;
        };
        if allocations.iter().any(|allocation| {
            allocation.range.offset == byte_offset && allocation.range.length == extent.length
        }) {
            continue;
        }
        allocations.push(SourceAllocation {
            stream: StreamId(extent.stream_id),
            logical_offset: extent.logical_offset,
            range: ByteRange {
                offset: byte_offset,
                length: extent.length,
            },
            movable: false,
        });
    }
    allocations.sort_unstable_by_key(|allocation| allocation.range.offset);
    Ok(())
}

fn map_ntfs_object_metadata(
    normalized: &NormalizedNtfs,
) -> Result<Vec<ExfatObjectMetadata>, NtfsToExfatError> {
    let mut by_object = BTreeMap::new();
    for evidence in &normalized.preservation.objects {
        // System metadata records are deliberately retained in the sidecar but omitted from the
        // neutral graph. Only graph-backed identities participate in object metadata cardinality.
        if normalized
            .graph
            .objects()
            .iter()
            .any(|object| object.id == evidence.object)
        {
            if by_object.insert(evidence.object, evidence).is_some() {
                return Err(NtfsToExfatError::DuplicateObjectEvidence(evidence.object));
            }
        } else if evidence.source.reference.record_number > 26 {
            return Err(NtfsToExfatError::UnknownObjectEvidence(evidence.object));
        }
    }
    let mut metadata = Vec::new();
    metadata
        .try_reserve_exact(normalized.graph.objects().len().saturating_sub(1))
        .map_err(|_| NtfsToExfatError::AllocationFailed)?;
    for object in normalized.graph.objects() {
        let evidence = by_object
            .get(&object.id)
            .ok_or(NtfsToExfatError::MissingObjectEvidence(object.id))?;
        if object.id == normalized.graph.root() {
            continue;
        }
        let standard = evidence
            .source
            .standard_information
            .ok_or(NtfsToExfatError::MissingStandardInformation(object.id))?;
        let attributes = u16::try_from(standard.file_attributes & 0x37)
            .map_err(|_| NtfsToExfatError::AttributesOutsideExfatRange(object.id))?;
        let timestamps = map_ntfs_timestamps(
            standard.creation_time,
            standard.modification_time,
            standard.access_time,
        )
        .ok_or(NtfsToExfatError::TimestampOutsideExfatRange(object.id))?;
        metadata.push(ExfatObjectMetadata {
            object: object.id,
            file_attributes: attributes,
            timestamps,
        });
    }
    Ok(metadata)
}

fn map_ntfs_timestamps(creation: u64, modification: u64, access: u64) -> Option<ExfatTimestamps> {
    let (create, create_centiseconds) = filetime_to_exfat_timestamp(creation, true)?;
    let (modified, modified_centiseconds) = filetime_to_exfat_timestamp(modification, true)?;
    let (accessed, _) = filetime_to_exfat_timestamp(access, false)?;
    Some(ExfatTimestamps {
        create,
        modified,
        accessed,
        create_centiseconds,
        modified_centiseconds,
        create_utc_offset: 0x80,
        modified_utc_offset: 0x80,
        accessed_utc_offset: 0x80,
    })
}

fn filetime_to_exfat_timestamp(value: u64, with_increment: bool) -> Option<(u32, u8)> {
    let ticks_per_day = SECONDS_PER_DAY.checked_mul(TICKS_PER_SECOND)?;
    let mut days = value / ticks_per_day;
    let day_ticks = value % ticks_per_day;
    let mut year = FILETIME_EPOCH_YEAR;
    loop {
        let year_days = if is_leap_year(year) { 366_u64 } else { 365 };
        if days < year_days {
            break;
        }
        days = days.checked_sub(year_days)?;
        year = year.checked_add(1)?;
        if year > 2107 {
            return None;
        }
    }
    if !(EXFAT_EPOCH_YEAR..=2107).contains(&year) {
        return None;
    }
    let mut month = 1_u32;
    loop {
        let month_days = u64::from(days_in_month(year, month));
        if days < month_days {
            break;
        }
        days = days.checked_sub(month_days)?;
        month = month.checked_add(1)?;
        if month > 12 {
            return None;
        }
    }
    let total_seconds = day_ticks / TICKS_PER_SECOND;
    let hour = total_seconds / 3600;
    let minute = total_seconds % 3600 / 60;
    let second = total_seconds % 60;
    let increment = if with_increment {
        let fractional = day_ticks % TICKS_PER_SECOND / TICKS_PER_10_MILLISECONDS;
        u8::try_from((second % 2) * 100 + fractional).ok()?
    } else {
        0
    };
    let packed = ((year - EXFAT_EPOCH_YEAR) << 25)
        | (month << 21)
        | (u32::try_from(days).ok()?.checked_add(1)? << 16)
        | (u32::try_from(hour).ok()? << 11)
        | (u32::try_from(minute).ok()? << 5)
        | u32::try_from(second / 2).ok()?;
    Some((packed, increment))
}

fn is_representable_exfat_label(label: &[u16]) -> bool {
    !label.is_empty()
        && label.len() <= 11
        && label.iter().all(|unit| {
            *unit > 0x1f
                && !matches!(
                    *unit,
                    0x22 | 0x2a | 0x2f | 0x3a | 0x3c | 0x3e | 0x3f | 0x5c | 0x7c
                )
        })
        && char::decode_utf16(label.iter().copied()).all(|value| value.is_ok())
}

const fn fold_ntfs_volume_serial(value: u64) -> u32 {
    let bytes = value.to_le_bytes();
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
        ^ u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]])
}

fn map_exfat_timestamps(value: ExfatTimestamps) -> Option<NtfsObjectTimestamps> {
    let creation_time = exfat_timestamp_to_filetime(
        value.create,
        value.create_centiseconds,
        value.create_utc_offset,
    )?;
    let modification_time = exfat_timestamp_to_filetime(
        value.modified,
        value.modified_centiseconds,
        value.modified_utc_offset,
    )?;
    let access_time = exfat_timestamp_to_filetime(value.accessed, 0, value.accessed_utc_offset)?;
    Some(NtfsObjectTimestamps {
        creation_time,
        modification_time,
        // exFAT has no independent metadata-change timestamp. Using last-modified is deterministic;
        // the exact source timestamp tuple remains in escrow.
        mft_change_time: modification_time,
        access_time,
    })
}

fn exfat_timestamp_to_filetime(raw: u32, increment: u8, utc_offset: u8) -> Option<u64> {
    if increment > 199 {
        return None;
    }
    let year = EXFAT_EPOCH_YEAR + ((raw >> 25) & 0x7f);
    let month = (raw >> 21) & 0x0f;
    let day = (raw >> 16) & 0x1f;
    let hour = (raw >> 11) & 0x1f;
    let minute = (raw >> 5) & 0x3f;
    let double_seconds = raw & 0x1f;
    if !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || double_seconds > 29
    {
        return None;
    }
    let days = days_before_year(year)?
        .checked_add(days_before_month(year, month)?)?
        .checked_add(u64::from(day - 1))?;
    let local_seconds = days
        .checked_mul(SECONDS_PER_DAY)?
        .checked_add(u64::from(hour) * 3600)?
        .checked_add(u64::from(minute) * 60)?
        .checked_add(u64::from(double_seconds) * 2)?;
    let quarter_hours = if utc_offset & 0x80 == 0 {
        0_i16
    } else {
        let raw_offset = i16::from(utc_offset & 0x7f);
        if raw_offset & 0x40 == 0 {
            raw_offset
        } else {
            raw_offset - 128
        }
    };
    let utc_seconds = i128::from(local_seconds) - i128::from(quarter_hours) * 15 * 60;
    let seconds = u64::try_from(utc_seconds).ok()?;
    seconds
        .checked_mul(TICKS_PER_SECOND)?
        .checked_add(u64::from(increment) * TICKS_PER_10_MILLISECONDS)
}

fn days_before_year(year: u32) -> Option<u64> {
    if year < FILETIME_EPOCH_YEAR {
        return None;
    }
    let years = u64::from(year - FILETIME_EPOCH_YEAR);
    let prior = year.checked_sub(1)?;
    let leap_days =
        leap_years_through(prior).checked_sub(leap_years_through(FILETIME_EPOCH_YEAR - 1))?;
    years.checked_mul(365)?.checked_add(leap_days)
}

fn leap_years_through(year: u32) -> u64 {
    u64::from(year / 4 - year / 100 + year / 400)
}

fn days_before_month(year: u32, month: u32) -> Option<u64> {
    let mut days = 0_u64;
    for value in 1..month {
        days = days.checked_add(u64::from(days_in_month(year, value)))?;
    }
    Some(days)
}

const fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

const fn is_leap_year(year: u32) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extent::{ExtentGraph, StreamId};
    use crate::fs::exfat_allocation::AllocationSummary;
    use crate::fs::exfat_directory::{AllocationBitmapEntry, DirectorySummary, UpcaseTableEntry};
    use crate::fs::exfat_discovery::ExfatRootDiscovery;
    use crate::fs::exfat_inventory::ExfatObjectFlags;
    use crate::fs::exfat_normalize::{ExfatObjectPreservation, ExfatPreservationSidecar};
    use crate::fs::exfat_upcase::{UpcaseLimits, UpcaseTable};
    use crate::fs::exfat_upcase_serialize::{
        RECOMMENDED_EXFAT_UPCASE_CHECKSUM, RecommendedExfatUpcaseLimits,
        generate_recommended_exfat_upcase,
    };
    use crate::fs::ntfs_inventory::{
        NtfsDataStream, NtfsName, NtfsObject, NtfsObjectReference, NtfsStandardInformation,
        NtfsStreamStorage,
    };
    use crate::fs::ntfs_normalize::{NtfsObjectPreservation, NtfsPreservationSidecar};
    use crate::object::{
        NamespaceEntry, ObjectGraph, ObjectGraphLimits, ObjectRecord, ObjectSemantics,
        ObjectStream, StreamFlags, StreamStorage,
    };

    const fn packed_timestamp(
        year: u32,
        month: u32,
        day: u32,
        hour: u32,
        minute: u32,
        seconds: u32,
    ) -> u32 {
        ((year - 1980) << 25)
            | (month << 21)
            | (day << 16)
            | (hour << 11)
            | (minute << 5)
            | (seconds / 2)
    }

    #[allow(clippy::too_many_lines)]
    fn normalized_exfat() -> NormalizedExfat {
        let root = ObjectId(1);
        let file = ObjectId(2);
        let file_stream = StreamId(20);
        let graph = ObjectGraph::build(
            root,
            vec![
                ObjectRecord {
                    id: root,
                    kind: ObjectKind::Directory,
                    link_count: 0,
                    semantics: ObjectSemantics::default(),
                    streams: Vec::new(),
                },
                ObjectRecord {
                    id: file,
                    kind: ObjectKind::File,
                    link_count: 1,
                    semantics: ObjectSemantics::default(),
                    streams: vec![ObjectStream {
                        id: file_stream,
                        name: None,
                        logical_bytes: 0,
                        initialized_bytes: 0,
                        mapped_bytes: 0,
                        allocated_bytes: 0,
                        flags: StreamFlags::default(),
                        storage: StreamStorage::Extents,
                    }],
                },
            ],
            vec![NamespaceEntry {
                parent: root,
                target: file,
                name: "clock.txt".encode_utf16().collect(),
            }],
            ExtentGraph::build(Vec::new(), 64 * 1024 * 1024, 8).unwrap(),
            ObjectGraphLimits {
                max_objects: 4,
                max_entries: 4,
                max_streams: 4,
                max_name_code_units: 255,
            },
        )
        .unwrap();
        let encoded =
            generate_recommended_exfat_upcase(RecommendedExfatUpcaseLimits::default()).unwrap();
        let root_discovery = ExfatRootDiscovery {
            directory: DirectorySummary {
                entries_examined: 0,
                records: 0,
                unused_entries: 0,
                reached_end_marker: true,
                allocation_bitmaps: 1,
                upcase_tables: 1,
                volume_labels: 0,
                files: 1,
                benign_primary_sets: 0,
            },
            active_bitmap: AllocationBitmapEntry {
                bitmap_identifier: 0,
                first_cluster: 3,
                data_length: 1,
            },
            upcase_table: UpcaseTableEntry {
                table_checksum: RECOMMENDED_EXFAT_UPCASE_CHECKSUM,
                first_cluster: 4,
                data_length: u64::try_from(encoded.encoded_bytes().len()).unwrap(),
            },
            upcase_mappings: UpcaseTable::parse(
                encoded.encoded_bytes(),
                RECOMMENDED_EXFAT_UPCASE_CHECKSUM,
                UpcaseLimits::COMPLETE_TABLE,
            )
            .unwrap(),
            allocation: AllocationSummary {
                allocated_clusters: 0,
                free_clusters: 16_384,
                required_bitmap_bytes: 2048,
            },
            free_bytes: 64 * 1024 * 1024,
            root_clusters: Vec::new(),
            bitmap_clusters: Vec::new(),
            upcase_clusters: Vec::new(),
        };
        let flags = ExfatObjectFlags {
            no_fat_chain: true,
            name_padding_zeroed: true,
            benign_secondary_entries: 0,
        };
        let raw = ExfatTimestamps {
            create: packed_timestamp(2024, 2, 29, 13, 30, 10),
            modified: packed_timestamp(2024, 3, 1, 9, 0, 12),
            accessed: packed_timestamp(2024, 3, 2, 10, 15, 14),
            create_centiseconds: 57,
            modified_centiseconds: 1,
            create_utc_offset: 0x84,
            modified_utc_offset: 0x80,
            accessed_utc_offset: 0x80,
        };
        NormalizedExfat {
            graph,
            preservation: ExfatPreservationSidecar {
                root: root_discovery,
                volume_serial_number: 0x1234_abcd,
                volume_label: None,
                objects: vec![
                    ExfatObjectPreservation {
                        object: root,
                        source_stream: StreamId(10),
                        path: Vec::new(),
                        file_attributes: 0x10,
                        timestamps: None,
                        clusters: Vec::new(),
                        flags,
                    },
                    ExfatObjectPreservation {
                        object: file,
                        source_stream: file_stream,
                        path: vec!["clock.txt".encode_utf16().collect()],
                        file_attributes: 0x21,
                        timestamps: Some(raw),
                        clusters: Vec::new(),
                        flags,
                    },
                ],
                filesystem_extents: vec![crate::extent::Extent {
                    stream: StreamId(999),
                    logical_offset: 0,
                    length: 4096,
                    placement: Placement::Physical {
                        byte_offset: 31 * 1024 * 1024,
                    },
                    kind: crate::extent::ExtentKind::FileSystemMetadata,
                }],
                directory_evidence: ExfatPreservationEvidence::default(),
                allocated_bad_clusters: 0,
            },
        }
    }

    const fn ntfs_source_object(
        record_number: u64,
        is_directory: bool,
        attributes: u32,
        timestamp: u64,
    ) -> NtfsObject {
        NtfsObject {
            reference: NtfsObjectReference {
                record_number,
                sequence_number: 1,
            },
            hard_link_count: 1,
            is_directory,
            is_metadata: record_number < 16 && record_number != 5,
            standard_information: Some(NtfsStandardInformation {
                creation_time: timestamp,
                modification_time: timestamp,
                mft_change_time: timestamp,
                access_time: timestamp,
                file_attributes: attributes,
                owner_id: None,
                security_id: None,
                quota_charged: None,
                usn: None,
            }),
            file_names: Vec::new(),
            data_streams: Vec::new(),
            directory_entries: Vec::new(),
            has_reparse_point: false,
            has_attribute_list: false,
            directory_index_complete: true,
        }
    }

    fn normalized_ntfs() -> NormalizedNtfs {
        let root = ObjectId(5);
        let file = ObjectId(27);
        let graph = ObjectGraph::build(
            root,
            vec![
                ObjectRecord {
                    id: root,
                    kind: ObjectKind::Directory,
                    link_count: 0,
                    semantics: ObjectSemantics::default(),
                    streams: Vec::new(),
                },
                ObjectRecord {
                    id: file,
                    kind: ObjectKind::File,
                    link_count: 1,
                    semantics: ObjectSemantics::default(),
                    streams: vec![ObjectStream {
                        id: StreamId(27),
                        name: None,
                        logical_bytes: 0,
                        initialized_bytes: 0,
                        mapped_bytes: 0,
                        allocated_bytes: 0,
                        flags: StreamFlags::default(),
                        storage: StreamStorage::Resident(Vec::new()),
                    }],
                },
            ],
            vec![NamespaceEntry {
                parent: root,
                target: file,
                name: "legal.txt".encode_utf16().collect(),
            }],
            ExtentGraph::build(Vec::new(), 64 * 1024 * 1024, 8).unwrap(),
            ObjectGraphLimits {
                max_objects: 4,
                max_entries: 4,
                max_streams: 4,
                max_name_code_units: 255,
            },
        )
        .unwrap();
        let timestamp =
            exfat_timestamp_to_filetime(packed_timestamp(2024, 4, 5, 6, 7, 8), 91, 0x80).unwrap();
        let mut badclus = ntfs_source_object(8, false, 0x06, timestamp);
        badclus.data_streams.push(NtfsDataStream {
            attribute_id: 3,
            name: Some(NtfsName {
                code_units: "$Bad".encode_utf16().collect(),
                is_well_formed: true,
            }),
            compressed: false,
            encrypted: false,
            sparse: true,
            storage: NtfsStreamStorage::Resident { bytes: Vec::new() },
        });
        NormalizedNtfs {
            graph,
            preservation: NtfsPreservationSidecar {
                volume_serial_number: 0x1234_5678_90ab_cdef,
                volume_label: None,
                security_descriptors:
                    crate::fs::ntfs_normalize::NtfsSecurityDescriptorEvidence::Unavailable,
                root_reference: NtfsObjectReference {
                    record_number: 5,
                    sequence_number: 1,
                },
                objects: vec![
                    NtfsObjectPreservation {
                        object: root,
                        source: ntfs_source_object(5, true, 0x10, timestamp),
                    },
                    NtfsObjectPreservation {
                        object: file,
                        source: ntfs_source_object(27, false, 0x21, timestamp),
                    },
                    NtfsObjectPreservation {
                        object: ObjectId(8),
                        source: badclus,
                    },
                ],
                source_extents: vec![crate::fs::ntfs_inventory::NtfsInventoryExtent {
                    stream_id: 999,
                    logical_offset: 0,
                    length: 4096,
                    placement: NtfsExtentPlacement::Physical {
                        byte_offset: 31 * 1024 * 1024,
                    },
                }],
                scanned_records: 28,
                initialized_records: 28,
                in_use_base_records: 3,
                extension_records: 0,
                bytes_read: 0,
            },
        }
    }

    #[test]
    fn exfat_timestamp_maps_epoch_offset_increment_and_leap_day_exactly() {
        // 1980-01-01 is 138,426 days after the FILETIME epoch.
        assert_eq!(
            exfat_timestamp_to_filetime(packed_timestamp(1980, 1, 1, 0, 0, 0), 0, 0x80),
            Some(138_426 * SECONDS_PER_DAY * TICKS_PER_SECOND)
        );
        let utc = exfat_timestamp_to_filetime(packed_timestamp(2024, 2, 29, 12, 30, 10), 57, 0x80)
            .unwrap();
        let plus_one_hour =
            exfat_timestamp_to_filetime(packed_timestamp(2024, 2, 29, 13, 30, 10), 57, 0x84)
                .unwrap();
        assert_eq!(utc, plus_one_hour);
        assert_eq!(utc % TICKS_PER_SECOND, 570 * 10_000);
    }

    #[test]
    fn invalid_offset_is_deterministically_treated_as_local_utc_and_bad_fields_refuse() {
        let raw = packed_timestamp(2025, 6, 1, 8, 15, 0);
        assert_eq!(
            exfat_timestamp_to_filetime(raw, 0, 0x00),
            exfat_timestamp_to_filetime(raw, 0, 0x80)
        );
        assert!(exfat_timestamp_to_filetime(raw, 200, 0x80).is_none());
        assert!(exfat_timestamp_to_filetime(raw & !(0x0f << 21), 0, 0x80).is_none());
    }

    #[test]
    fn escrow_mode_binds_exact_exfat_evidence_to_ntfs_metadata_and_identity() {
        let normalized = normalized_exfat();
        assert!(matches!(
            plan_lossless_exfat_to_ntfs(
                &normalized,
                GuaranteeMode::Strict,
                ExfatToNtfsOptions::default(),
                ExfatToNtfsLimits::default(),
            ),
            Err(ExfatToNtfsError::PreservationRefused { .. })
        ));
        let plan = plan_lossless_exfat_to_ntfs(
            &normalized,
            GuaranteeMode::Escrow,
            ExfatToNtfsOptions {
                system_timestamp: 42,
                ..ExfatToNtfsOptions::default()
            },
            ExfatToNtfsLimits::default(),
        )
        .unwrap();
        assert!(plan.preservation.permitted);
        assert!(plan.preservation.escrow.is_some());
        assert!(!plan.destination.activation_ready());
        assert_eq!(plan.object_metadata[0].timestamps.creation_time, 42);
        assert_eq!(plan.object_metadata[1].dos_file_attributes, 0x21);
        assert_eq!(
            plan.object_metadata[1].timestamps.creation_time,
            exfat_timestamp_to_filetime(packed_timestamp(2024, 2, 29, 13, 30, 10), 57, 0x84,)
                .unwrap()
        );
        assert_eq!(
            u64::from_le_bytes(
                plan.destination.primary_boot_write.bytes[72..80]
                    .try_into()
                    .unwrap()
            ),
            0x1234_abcd
        );
        assert!(
            plan.destination
                .source_allocations
                .iter()
                .any(|allocation| {
                    allocation.stream == StreamId(999)
                        && allocation.range.offset == 31 * 1024 * 1024
                        && !allocation.movable
                })
        );
    }

    #[test]
    fn ntfs_time_rounds_to_exfat_resolution_while_escrow_keeps_exact_ticks() {
        let exact = exfat_timestamp_to_filetime(packed_timestamp(2024, 4, 5, 6, 7, 8), 91, 0x80)
            .unwrap()
            + 9_999;
        let (packed, increment) = filetime_to_exfat_timestamp(exact, true).unwrap();
        assert_eq!(packed, packed_timestamp(2024, 4, 5, 6, 7, 8));
        assert_eq!(increment, 91);
        let (access, access_increment) = filetime_to_exfat_timestamp(exact, false).unwrap();
        assert_eq!(access, packed_timestamp(2024, 4, 5, 6, 7, 8));
        assert_eq!(access_increment, 0);
        assert!(filetime_to_exfat_timestamp(0, true).is_none());
    }

    #[test]
    fn escrow_mode_binds_ntfs_evidence_to_canonical_exfat_plan() {
        let normalized = normalized_ntfs();
        assert!(matches!(
            plan_lossless_ntfs_to_exfat(
                &normalized,
                GuaranteeMode::Strict,
                NtfsToExfatOptions::default(),
                NtfsToExfatLimits::default(),
            ),
            Err(NtfsToExfatError::PreservationRefused { .. })
        ));
        let plan = plan_lossless_ntfs_to_exfat(
            &normalized,
            GuaranteeMode::Escrow,
            NtfsToExfatOptions::default(),
            NtfsToExfatLimits::default(),
        )
        .unwrap();
        assert!(plan.preservation.permitted);
        assert!(plan.preservation.escrow.is_some());
        assert!(!plan.destination.activation_ready());
        assert_eq!(plan.object_metadata.len(), 1);
        assert_eq!(plan.object_metadata[0].file_attributes, 0x21);
        assert_eq!(
            plan.destination_volume_serial_number,
            fold_ntfs_volume_serial(0x1234_5678_90ab_cdef)
        );
        assert!(
            plan.destination
                .source_allocations
                .iter()
                .any(|allocation| {
                    allocation.stream == StreamId(999)
                        && allocation.range.offset == 31 * 1024 * 1024
                        && !allocation.movable
                })
        );
    }
}
