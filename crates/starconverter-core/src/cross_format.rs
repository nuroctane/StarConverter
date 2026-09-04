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

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::FileSystem;
use crate::GuaranteeMode;
use crate::escrow_carrier::{
    ESCROW_CARRIER_DIRECTORY, carrier_directory_name, collides_with_carrier_directory,
    sidecar_carriers,
};
use crate::escrow_restore::{
    NtfsRestoreError, RestoredNtfsIdentities, restore_ntfs_identities_with_evidence,
};
use crate::extent::{Extent, ExtentGraph, ExtentGraphError, ExtentKind, Placement, StreamId};
use crate::fs::exfat_inventory::{ExfatPreservationEvidence, ExfatTimestamps};
use crate::fs::exfat_normalize::NormalizedExfat;
use crate::fs::exfat_serialize::{
    ExfatDestinationDraft, ExfatObjectMetadata, ExfatSerializationPlan, ExfatSerializeError,
    ExfatSerializeLimits, ExfatSerializeOptions, ExfatVolumeProfile, draft_exfat_destination,
    finalize_exfat_destination, serialize_exfat_destination,
};
use crate::fs::exfat_upcase::MAX_FILE_NAME_CODE_UNITS;
use crate::fs::exfat_upcase_serialize::{
    RECOMMENDED_EXFAT_UPCASE_CHECKSUM, RecommendedExfatUpcase, RecommendedExfatUpcaseError,
    RecommendedExfatUpcaseLimits, generate_recommended_exfat_upcase,
};
use crate::fs::ntfs_essential::BADCLUS_STREAM_NAME;
use crate::fs::ntfs_index::FileNameNamespace;
use crate::fs::ntfs_inventory::{NtfsExtentPlacement, NtfsStreamStorage};
use crate::fs::ntfs_normalize::{NormalizedNtfs, NtfsPreservationSidecar};
use crate::fs::ntfs_serialize::{
    NTFS3G_SECURITY_ID_READ_WRITE, NtfsDestinationDraft, NtfsDestinationInputs,
    NtfsDestinationPlan, NtfsObjectMetadata, NtfsObjectTimestamps, NtfsSerializeError,
    NtfsSerializeLimits, NtfsVolumeProfile, draft_ntfs_destination_with_metadata_and_volume,
    finalize_ntfs_destination, plan_ntfs_destination_with_metadata_and_volume,
};
use crate::geometry::{
    ByteRange, LayoutError, LayoutLimits, LayoutPlan, MaterializationRequest, RelocatedGraphError,
    SealedRelocationPlan, SourceAllocation, materialization_length_for_stream,
    solve_layout_with_destination_domain_alignments_and_materializations,
    solve_layout_with_staging_exclusions_and_io_alignment,
};
use crate::object::{
    NamespaceEntry, ObjectGraph, ObjectGraphError, ObjectGraphLimits, ObjectId, ObjectKind,
    ObjectRecord, ObjectSemantics,
};
use crate::preservation::{
    PreservationError, PreservationField, PreservationLimits, PreservationReport, evaluate_exfat,
    evaluate_ntfs, is_legal_exfat_name,
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

/// Policy-bound NTFS placement draft for sources whose payload must move out of target metadata.
///
/// Unlike [`ExfatToNtfsPlan`], this value exposes no destination bytes and cannot be passed to the
/// phase preview. A coordinator must solve its movable allocations, relocate `target_graph`, and
/// call [`crate::fs::ntfs_serialize::finalize_ntfs_destination`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExfatToNtfsRelocationDraft {
    preservation: PreservationReport,
    target_graph: ObjectGraph,
    object_metadata: Vec<NtfsObjectMetadata>,
    volume_label: Option<Vec<u16>>,
    destination: NtfsDestinationDraft,
}

/// Fully reserialized NTFS proposal after deterministic payload placement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExfatToNtfsSolvedPlan {
    pub preservation: PreservationReport,
    pub object_metadata: Vec<NtfsObjectMetadata>,
    pub volume_label: Option<Vec<u16>>,
    pub destination: NtfsDestinationPlan,
    relocation: SealedRelocationPlan,
}

impl ExfatToNtfsRelocationDraft {
    #[must_use]
    pub const fn preservation(&self) -> &PreservationReport {
        &self.preservation
    }

    #[must_use]
    pub const fn target_graph(&self) -> &ObjectGraph {
        &self.target_graph
    }

    #[must_use]
    pub const fn destination(&self) -> &NtfsDestinationDraft {
        &self.destination
    }
}

impl ExfatToNtfsSolvedPlan {
    #[must_use]
    pub const fn relocation(&self) -> &SealedRelocationPlan {
        &self.relocation
    }

    #[must_use]
    pub const fn target_graph(&self) -> &ObjectGraph {
        self.relocation.target_graph()
    }

    #[must_use]
    pub const fn layout(&self) -> &LayoutPlan {
        self.relocation.layout()
    }
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

/// Policy-bound, write-ineligible exFAT layout for a source whose payload may need relocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsToExfatRelocationDraft {
    preservation: PreservationReport,
    target_graph: ObjectGraph,
    object_metadata: Vec<ExfatObjectMetadata>,
    destination_volume_label: Option<Vec<u16>>,
    destination_volume_serial_number: u32,
    destination: ExfatDestinationDraft,
}

/// Fully reserialized exFAT proposal after deterministic target-heap placement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsToExfatSolvedPlan {
    pub preservation: PreservationReport,
    pub object_metadata: Vec<ExfatObjectMetadata>,
    pub destination_volume_label: Option<Vec<u16>>,
    pub destination_volume_serial_number: u32,
    pub destination: ExfatSerializationPlan,
    relocation: SealedRelocationPlan,
}

impl NtfsToExfatRelocationDraft {
    #[must_use]
    pub const fn preservation(&self) -> &PreservationReport {
        &self.preservation
    }

    #[must_use]
    pub const fn target_graph(&self) -> &ObjectGraph {
        &self.target_graph
    }

    #[must_use]
    pub const fn destination(&self) -> &ExfatDestinationDraft {
        &self.destination
    }
}

impl NtfsToExfatSolvedPlan {
    #[must_use]
    pub const fn relocation(&self) -> &SealedRelocationPlan {
        &self.relocation
    }

    #[must_use]
    pub const fn target_graph(&self) -> &ObjectGraph {
        self.relocation.target_graph()
    }

    #[must_use]
    pub const fn layout(&self) -> &LayoutPlan {
        self.relocation.layout()
    }
}

/// Refusal from policy, exact metadata conversion, or structural NTFS serialization.
#[derive(Debug)]
pub enum ExfatToNtfsError {
    ContentOnlyIsNotLossless,
    /// Source bad-cluster count and exact extent evidence disagree, so the destination cannot
    /// mark the same unusable media in `$BadClus:$Bad` and `$Bitmap`.
    InconsistentBadClusterEvidence {
        allocated_clusters: u64,
        bad_cluster_extents: usize,
    },
    Preservation(PreservationError),
    PreservationRefused {
        blockers: Vec<PreservationField>,
    },
    MissingObjectEvidence(ObjectId),
    DuplicateObjectEvidence(ObjectId),
    UnknownObjectEvidence(ObjectId),
    MissingTimestamp(ObjectId),
    InvalidTimestamp(ObjectId),
    AllocationFailed,
    SourceMetadataLimitExceeded {
        actual: usize,
        maximum: usize,
    },
    GraphProjection(ObjectGraphError),
    Layout(LayoutError),
    RelocatedGraph(RelocatedGraphError),
    Serialization(NtfsSerializeError),
    /// The NTFS→exFAT escrow could not be reattached onto this exFAT candidate.
    EscrowRestore(NtfsRestoreError),
    /// A sidecar object identified by dest-native path lacks `$STANDARD_INFORMATION`, so exact
    /// NTFS timestamps and attributes cannot be restored for it.
    MissingEscrowStandardInformation {
        dest: ObjectId,
        source_record: u64,
    },
}

impl fmt::Display for ExfatToNtfsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ContentOnlyIsNotLossless => formatter.write_str(
                "content-only mode cannot produce a lossless exFAT-to-NTFS conversion plan",
            ),
            Self::InconsistentBadClusterEvidence {
                allocated_clusters,
                bad_cluster_extents,
            } => write!(
                formatter,
                "exFAT reports {allocated_clusters} allocated bad clusters but {bad_cluster_extents} bad-cluster extents"
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
            Self::Layout(error) => write!(formatter, "payload layout failed: {error}"),
            Self::RelocatedGraph(error) => {
                write!(formatter, "target graph relocation failed: {error}")
            }
            Self::Serialization(error) => write!(formatter, "NTFS serialization failed: {error}"),
            Self::EscrowRestore(error) => {
                write!(formatter, "NTFS escrow identity restore failed: {error}")
            }
            Self::MissingEscrowStandardInformation {
                dest,
                source_record,
            } => write!(
                formatter,
                "escrow record {source_record} for dest object {} has no $STANDARD_INFORMATION",
                dest.0
            ),
        }
    }
}

impl std::error::Error for ExfatToNtfsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Preservation(error) => Some(error),
            Self::Serialization(error) => Some(error),
            Self::GraphProjection(error) => Some(error),
            Self::Layout(error) => Some(error),
            Self::RelocatedGraph(error) => Some(error),
            Self::EscrowRestore(error) => Some(error),
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

impl From<LayoutError> for ExfatToNtfsError {
    fn from(value: LayoutError) -> Self {
        Self::Layout(value)
    }
}

impl From<RelocatedGraphError> for ExfatToNtfsError {
    fn from(value: RelocatedGraphError) -> Self {
        Self::RelocatedGraph(value)
    }
}

/// Refusal from NTFS policy, exact metadata conversion, canonical profile generation, or exFAT
/// serialization.
#[derive(Debug)]
pub enum NtfsToExfatError {
    ContentOnlyIsNotLossless,
    Preservation(PreservationError),
    PreservationRefused {
        blockers: Vec<PreservationField>,
    },
    MissingObjectEvidence(ObjectId),
    DuplicateObjectEvidence(ObjectId),
    UnknownObjectEvidence(ObjectId),
    MissingStandardInformation(ObjectId),
    TimestampOutsideExfatRange(ObjectId),
    AttributesOutsideExfatRange(ObjectId),
    NameDisambiguationFailed {
        parent: ObjectId,
    },
    AllocationFailed,
    SourceMetadataLimitExceeded {
        actual: usize,
        maximum: usize,
    },
    /// The sidecar implies a carrier for a named stream, but the neutral graph has no such
    /// object or stream.
    EscrowCarrierStreamMissing {
        owner: ObjectId,
        attribute_id: u16,
    },
    /// A source root entry folds onto the reserved escrow carrier directory name.
    EscrowCarrierNameCollision,
    /// No free [`ObjectId`] remained for a dest-native carrier object.
    ObjectIdOverflow,
    GraphProjection(ObjectGraphError),
    ExtentProjection(ExtentGraphError),
    Upcase(RecommendedExfatUpcaseError),
    Layout(LayoutError),
    RelocatedGraph(RelocatedGraphError),
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
            Self::NameDisambiguationFailed { parent } => write!(
                formatter,
                "directory {} has names that collide under exFAT up-case and could not be disambiguated",
                parent.0
            ),
            Self::AllocationFailed => {
                formatter.write_str("could not allocate bounded cross-format metadata")
            }
            Self::SourceMetadataLimitExceeded { actual, maximum } => write!(
                formatter,
                "source metadata requires {actual} allocations, exceeding {maximum}"
            ),
            Self::EscrowCarrierStreamMissing {
                owner,
                attribute_id,
            } => write!(
                formatter,
                "escrow names an uncaptured named stream (record {}, attribute {attribute_id}) that the neutral graph does not carry",
                owner.0
            ),
            Self::EscrowCarrierNameCollision => write!(
                formatter,
                "a source root entry collides with the reserved `{ESCROW_CARRIER_DIRECTORY}` escrow carrier directory"
            ),
            Self::ObjectIdOverflow => {
                formatter.write_str("no free object identifier remained for an escrow carrier")
            }
            Self::GraphProjection(error) => write!(formatter, "graph projection failed: {error}"),
            Self::ExtentProjection(error) => {
                write!(formatter, "extent projection failed: {error}")
            }
            Self::Upcase(error) => {
                write!(
                    formatter,
                    "could not generate recommended exFAT up-case table: {error}"
                )
            }
            Self::Layout(error) => write!(formatter, "payload layout failed: {error}"),
            Self::RelocatedGraph(error) => {
                write!(formatter, "target graph relocation failed: {error}")
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
            Self::ExtentProjection(error) => Some(error),
            Self::Layout(error) => Some(error),
            Self::RelocatedGraph(error) => Some(error),
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

impl From<LayoutError> for NtfsToExfatError {
    fn from(value: LayoutError) -> Self {
        Self::Layout(value)
    }
}

impl From<RelocatedGraphError> for NtfsToExfatError {
    fn from(value: RelocatedGraphError) -> Self {
        Self::RelocatedGraph(value)
    }
}

/// Produces a policy-bound exFAT-to-NTFS structural candidate without opening or writing a file.
///
/// # Errors
///
/// Refuses content-only mode, inconsistent bad-cluster count/extent evidence, any preservation
/// blocker, incomplete/inconsistent sidecar evidence, invalid timestamps, cap exhaustion, and
/// every refusal exposed by the NTFS serializer. Consistent bad-cluster extents are projected
/// into `$BadClus:$Bad` and `$Bitmap`.
pub fn plan_lossless_exfat_to_ntfs(
    normalized: &NormalizedExfat,
    mode: GuaranteeMode,
    options: ExfatToNtfsOptions,
    limits: ExfatToNtfsLimits,
) -> Result<ExfatToNtfsPlan, ExfatToNtfsError> {
    if mode == GuaranteeMode::ContentOnly {
        return Err(ExfatToNtfsError::ContentOnlyIsNotLossless);
    }
    let bad_cluster_ranges = exfat_bad_cluster_ranges(normalized)?;
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
        &target_graph,
        inputs,
        &object_metadata,
        NtfsVolumeProfile {
            volume_label: volume_label.as_deref(),
            bad_cluster_ranges: &bad_cluster_ranges,
            reparse_points: &[],
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

/// Produces a policy-bound, non-executable NTFS layout draft which can solve payload conflicts.
///
/// This performs the same preservation and exact-metadata checks as
/// [`plan_lossless_exfat_to_ntfs`], but pins destination reservations without exposing first-pass
/// metadata bytes. Only ordinary file data is movable.
///
/// # Errors
///
/// Returns the same policy, evidence, cap, and serializer refusals as
/// [`plan_lossless_exfat_to_ntfs`], except that ordinary file-data overlap with NTFS metadata is
/// returned as relocation work.
pub fn draft_lossless_exfat_to_ntfs(
    normalized: &NormalizedExfat,
    mode: GuaranteeMode,
    options: ExfatToNtfsOptions,
    limits: ExfatToNtfsLimits,
) -> Result<ExfatToNtfsRelocationDraft, ExfatToNtfsError> {
    if mode == GuaranteeMode::ContentOnly {
        return Err(ExfatToNtfsError::ContentOnlyIsNotLossless);
    }
    let bad_cluster_ranges = exfat_bad_cluster_ranges(normalized)?;
    let preservation = evaluate_exfat(normalized, FileSystem::Ntfs, mode, limits.preservation)?;
    if !preservation.permitted {
        return Err(ExfatToNtfsError::PreservationRefused {
            blockers: preservation.blockers,
        });
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
    let mut destination = draft_ntfs_destination_with_metadata_and_volume(
        &target_graph,
        inputs,
        &object_metadata,
        NtfsVolumeProfile {
            volume_label: volume_label.as_deref(),
            bad_cluster_ranges: &bad_cluster_ranges,
            reparse_points: &[],
        },
        limits.serializer,
    )?;
    retain_exfat_source_metadata(
        &mut destination.source_allocations,
        normalized,
        limits.serializer.max_extents,
    )?;
    Ok(ExfatToNtfsRelocationDraft {
        preservation,
        target_graph,
        object_metadata,
        volume_label,
        destination,
    })
}

/// Drafts an exFAT→NTFS destination that reattaches the NTFS identities an earlier NTFS→exFAT
/// escrow recorded for this exact exFAT candidate.
///
/// The caller must already have proven that `sidecar` was decoded from an envelope bound to this
/// exFAT image (see [`crate::escrow_restore::decode_restore_sidecar`]). On top of the ordinary
/// dest-native projection this restores, per object matched by dest-native path: extra non-DOS
/// `$FILE_NAME` hard links, resident, captured, or carrier-backed named `$DATA` streams (carrier
/// files under the root `.starconverter-escrow` directory are folded back into their owners and
/// removed), resident `$REPARSE_POINT` payloads (listed in `$Extend:$R`), and exact
/// `$STANDARD_INFORMATION` timestamps and DOS attributes. The volume keeps the original 64-bit
/// NTFS serial and full-length label. Objects the escrow does not know (added on the exFAT side)
/// keep exFAT-derived metadata. Security descriptors remain the pinned ordinary profile, and exact
/// source MFT numbers and runlists are not rematerialized.
///
/// # Errors
///
/// Returns every refusal of [`draft_lossless_exfat_to_ntfs`] plus
/// [`ExfatToNtfsError::EscrowRestore`] when the escrow cannot be reattached (missing dest path,
/// kind mismatch, unrestorable stream, incomplete reparse payload) and
/// [`ExfatToNtfsError::MissingEscrowStandardInformation`] for an identified object without exact
/// NTFS metadata.
pub fn draft_escrow_restored_exfat_to_ntfs(
    normalized: &NormalizedExfat,
    sidecar: &NtfsPreservationSidecar,
    mode: GuaranteeMode,
    options: ExfatToNtfsOptions,
    limits: ExfatToNtfsLimits,
) -> Result<ExfatToNtfsRelocationDraft, ExfatToNtfsError> {
    if mode == GuaranteeMode::ContentOnly {
        return Err(ExfatToNtfsError::ContentOnlyIsNotLossless);
    }
    let bad_cluster_ranges = exfat_bad_cluster_ranges(normalized)?;
    let preservation = evaluate_exfat(normalized, FileSystem::Ntfs, mode, limits.preservation)?;
    if !preservation.permitted {
        return Err(ExfatToNtfsError::PreservationRefused {
            blockers: preservation.blockers,
        });
    }

    let dest_native = project_exfat_graph_for_ntfs(normalized)?;
    let restored = restore_ntfs_identities_with_evidence(&dest_native, sidecar)
        .map_err(ExfatToNtfsError::EscrowRestore)?;
    let mut exfat_metadata = map_exfat_object_metadata(normalized, options.system_timestamp)?;
    // Escrow carriers were folded back into their owners' named streams and no longer exist on
    // the restored graph, so they must not be described to the NTFS serializer.
    exfat_metadata.retain(|entry| !restored.removed_objects.contains(&entry.object));
    let object_metadata = restore_ntfs_object_metadata(&restored, sidecar, exfat_metadata)?;
    let volume_label = sidecar.volume_label.clone();
    let inputs = NtfsDestinationInputs {
        image_bytes: normalized.graph.extents().volume_bytes(),
        partition_offset_sectors: options.partition_offset_sectors,
        cluster_bytes: options.cluster_bytes,
        volume_serial_number: sidecar.volume_serial_number,
        timestamp: options.system_timestamp,
    };
    let reparse_points: Vec<(ObjectId, &[u8])> = restored
        .reparse_points
        .iter()
        .map(|(object, payload)| (*object, payload.as_slice()))
        .collect();
    let mut destination = draft_ntfs_destination_with_metadata_and_volume(
        &restored.graph,
        inputs,
        &object_metadata,
        NtfsVolumeProfile {
            volume_label: volume_label.as_deref(),
            bad_cluster_ranges: &bad_cluster_ranges,
            reparse_points: &reparse_points,
        },
        limits.serializer,
    )?;
    retain_exfat_source_metadata(
        &mut destination.source_allocations,
        normalized,
        limits.serializer.max_extents,
    )?;
    Ok(ExfatToNtfsRelocationDraft {
        preservation,
        target_graph: restored.graph,
        object_metadata,
        volume_label,
        destination,
    })
}

/// Overrides exFAT-derived NTFS metadata with the exact `$STANDARD_INFORMATION` the escrow
/// recorded for every dest object it identified by path.
///
/// `FILE_ATTRIBUTE_DIRECTORY` is re-derived from the dest object kind because the destination
/// serializer requires it on directories, and `FILE_ATTRIBUTE_REPARSE_POINT` is re-derived from the
/// restored payload. `COMPRESSED` and `ENCRYPTED` are cleared because dest streams are never
/// compressed or encrypted; `SPARSE` survives only when a restored stream is sparse.
fn restore_ntfs_object_metadata(
    restored: &RestoredNtfsIdentities,
    sidecar: &NtfsPreservationSidecar,
    mut metadata: Vec<NtfsObjectMetadata>,
) -> Result<Vec<NtfsObjectMetadata>, ExfatToNtfsError> {
    const FILE_ATTRIBUTE_SPARSE_FILE: u32 = 0x200;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    const FILE_ATTRIBUTE_COMPRESSED: u32 = 0x800;
    const FILE_ATTRIBUTE_ENCRYPTED: u32 = 0x4000;

    let sidecar_by_id: BTreeMap<ObjectId, _> = sidecar
        .objects
        .iter()
        .map(|preserved| (preserved.object, &preserved.source))
        .collect();
    for entry in &mut metadata {
        let Some(source_id) = restored.source_by_dest.get(&entry.object) else {
            continue;
        };
        let Some(source) = sidecar_by_id.get(source_id) else {
            continue;
        };
        let standard = source.standard_information.ok_or(
            ExfatToNtfsError::MissingEscrowStandardInformation {
                dest: entry.object,
                source_record: source.reference.record_number,
            },
        )?;
        let dest_object = restored
            .graph
            .objects()
            .iter()
            .find(|object| object.id == entry.object);
        let sparse = dest_object
            .is_some_and(|object| object.streams.iter().any(|stream| stream.flags.sparse));
        let mut attributes = standard.file_attributes
            & !(FILE_ATTRIBUTE_DIRECTORY
                | FILE_ATTRIBUTE_REPARSE_POINT
                | FILE_ATTRIBUTE_COMPRESSED
                | FILE_ATTRIBUTE_ENCRYPTED);
        if !sparse {
            attributes &= !FILE_ATTRIBUTE_SPARSE_FILE;
        }
        if entry.object_kind == ObjectKind::Directory {
            attributes |= FILE_ATTRIBUTE_DIRECTORY;
        }
        entry.timestamps = NtfsObjectTimestamps {
            creation_time: standard.creation_time,
            modification_time: standard.modification_time,
            mft_change_time: standard.mft_change_time,
            access_time: standard.access_time,
        };
        entry.dos_file_attributes = attributes;
    }
    Ok(metadata)
}

/// Solves a pinned exFAT-to-NTFS draft and regenerates every placement-dependent NTFS structure.
///
/// Source filesystem metadata which is not part of the neutral graph remains excluded from staging
/// scratch. The returned destination keeps those original source ranges and all original payload
/// ranges for copy/rollback evidence, while its runlists and allocation bitmap describe the solved
/// `target_graph`.
///
/// # Errors
///
/// Refuses immovable conflicts, insufficient staging space, resource-cap exhaustion, graph
/// relocation disagreement, or any final NTFS serialization/layout drift.
pub fn solve_lossless_exfat_to_ntfs(
    draft: ExfatToNtfsRelocationDraft,
    limits: LayoutLimits,
) -> Result<ExfatToNtfsSolvedPlan, ExfatToNtfsError> {
    let destination_alignment = u64::from(draft.destination.cluster_bytes);
    let (live_allocations, staging_exclusions, materializations) = partition_payload_work(
        draft.destination.source_allocations.iter().copied(),
        &draft.target_graph,
        destination_alignment,
    )?;
    let layout = if materializations.is_empty() {
        solve_layout_with_staging_exclusions_and_io_alignment(
            draft.destination.image_bytes,
            destination_alignment,
            512,
            live_allocations,
            draft.destination.reservations.clone(),
            staging_exclusions,
            limits,
        )?
    } else {
        solve_layout_with_destination_domain_alignments_and_materializations(
            draft.destination.image_bytes,
            512,
            destination_alignment,
            512,
            ByteRange {
                offset: 0,
                length: draft.destination.image_bytes,
            },
            live_allocations,
            draft.destination.reservations.clone(),
            staging_exclusions,
            &materializations,
            limits,
        )?
    };
    let relocation = SealedRelocationPlan::seal(draft.target_graph, layout)?;
    let destination = finalize_ntfs_destination(&draft.destination, relocation.target_graph())?;
    Ok(ExfatToNtfsSolvedPlan {
        preservation: draft.preservation,
        object_metadata: draft.object_metadata,
        volume_label: draft.volume_label,
        destination,
        relocation,
    })
}

fn ntfs_bad_cluster_ranges(normalized: &NormalizedNtfs) -> Vec<ByteRange> {
    const BADCLUS_RECORD: u64 = 8;
    let Some(object) = normalized
        .preservation
        .objects
        .iter()
        .find(|object| object.source.reference.record_number == BADCLUS_RECORD)
    else {
        return Vec::new();
    };
    let Some(stream) = object.source.data_streams.iter().find(|stream| {
        stream
            .name
            .as_ref()
            .is_some_and(|name| name.code_units == BADCLUS_STREAM_NAME)
    }) else {
        return Vec::new();
    };
    match &stream.storage {
        NtfsStreamStorage::Resident { .. } => Vec::new(),
        NtfsStreamStorage::NonResident { extents, .. } => extents
            .iter()
            .filter_map(|extent| match extent.placement {
                NtfsExtentPlacement::Physical { byte_offset } => Some(ByteRange {
                    offset: byte_offset,
                    length: extent.length,
                }),
                NtfsExtentPlacement::Sparse => None,
            })
            .collect(),
    }
}

fn exfat_bad_cluster_ranges(
    normalized: &NormalizedExfat,
) -> Result<Vec<ByteRange>, ExfatToNtfsError> {
    let extents: Vec<_> = normalized
        .preservation
        .filesystem_extents
        .iter()
        .filter(|extent| extent.kind == ExtentKind::BadCluster)
        .copied()
        .collect();
    let allocated = normalized.preservation.allocated_bad_clusters;
    if allocated != u64::try_from(extents.len()).map_err(|_| ExfatToNtfsError::AllocationFailed)? {
        return Err(ExfatToNtfsError::InconsistentBadClusterEvidence {
            allocated_clusters: allocated,
            bad_cluster_extents: extents.len(),
        });
    }
    let mut ranges = Vec::new();
    ranges
        .try_reserve(extents.len())
        .map_err(|_| ExfatToNtfsError::AllocationFailed)?;
    for extent in extents {
        let Placement::Physical { byte_offset } = extent.placement else {
            return Err(ExfatToNtfsError::InconsistentBadClusterEvidence {
                allocated_clusters: allocated,
                bad_cluster_extents: ranges.len() + 1,
            });
        };
        ranges.push(ByteRange {
            offset: byte_offset,
            length: extent.length,
        });
    }
    Ok(ranges)
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
    let projection = project_ntfs_graph_for_exfat(normalized)?;
    let object_metadata = map_ntfs_object_metadata(normalized, &projection)?;
    let destination_volume_label = normalized
        .preservation
        .volume_label
        .as_ref()
        .filter(|label| is_representable_exfat_label(label))
        .cloned();
    let serial = fold_ntfs_volume_serial(normalized.preservation.volume_serial_number);
    let upcase = generate_recommended_exfat_upcase(limits.upcase)?;
    let target_graph = projection.graph;
    let bad_cluster_ranges = ntfs_bad_cluster_ranges(normalized);
    let mut destination = serialize_exfat_destination(
        &target_graph,
        &object_metadata,
        ExfatVolumeProfile {
            volume_label: destination_volume_label.as_deref(),
            encoded_upcase_table: upcase.encoded_bytes(),
            upcase_checksum: RECOMMENDED_EXFAT_UPCASE_CHECKSUM,
            source_preservation: ExfatPreservationEvidence::default(),
            allocated_bad_clusters: u64::try_from(bad_cluster_ranges.len()).unwrap_or(u64::MAX),
            bad_cluster_ranges: &bad_cluster_ranges,
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

/// Produces a policy-bound, write-ineligible exFAT layout draft for relocation planning.
///
/// The draft pins target metadata without requiring ordinary NTFS file payloads to already occupy
/// valid exFAT cluster-heap positions. Source filesystem metadata remains protected and is never
/// marked movable.
///
/// # Errors
///
/// Returns the same preservation, metadata, profile, and serializer refusals as
/// [`plan_lossless_ntfs_to_exfat`], except that target-placement conflicts are deferred to
/// [`solve_lossless_ntfs_to_exfat`].
pub fn draft_lossless_ntfs_to_exfat(
    normalized: &NormalizedNtfs,
    mode: GuaranteeMode,
    options: NtfsToExfatOptions,
    limits: NtfsToExfatLimits,
) -> Result<NtfsToExfatRelocationDraft, NtfsToExfatError> {
    if mode == GuaranteeMode::ContentOnly {
        return Err(NtfsToExfatError::ContentOnlyIsNotLossless);
    }
    let preservation = evaluate_ntfs(normalized, FileSystem::ExFat, mode, limits.preservation)?;
    if !preservation.permitted {
        return Err(NtfsToExfatError::PreservationRefused {
            blockers: preservation.blockers,
        });
    }
    let projection = project_ntfs_graph_for_exfat(normalized)?;
    let object_metadata = map_ntfs_object_metadata(normalized, &projection)?;
    let destination_volume_label = normalized
        .preservation
        .volume_label
        .as_ref()
        .filter(|label| is_representable_exfat_label(label))
        .cloned();
    let serial = fold_ntfs_volume_serial(normalized.preservation.volume_serial_number);
    let upcase = generate_recommended_exfat_upcase(limits.upcase)?;
    let target_graph = projection.graph;
    let bad_cluster_ranges = ntfs_bad_cluster_ranges(normalized);
    let mut destination = draft_exfat_destination(
        &target_graph,
        &object_metadata,
        ExfatVolumeProfile {
            volume_label: destination_volume_label.as_deref(),
            encoded_upcase_table: upcase.encoded_bytes(),
            upcase_checksum: RECOMMENDED_EXFAT_UPCASE_CHECKSUM,
            source_preservation: ExfatPreservationEvidence::default(),
            allocated_bad_clusters: u64::try_from(bad_cluster_ranges.len()).unwrap_or(u64::MAX),
            bad_cluster_ranges: &bad_cluster_ranges,
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
        destination.source_allocations_mut(),
        normalized,
        limits.serializer.max_extents,
    )?;
    Ok(NtfsToExfatRelocationDraft {
        preservation,
        target_graph,
        object_metadata,
        destination_volume_label,
        destination_volume_serial_number: serial,
        destination,
    })
}

/// Solves an NTFS-to-exFAT draft inside its pinned cluster heap and regenerates target metadata.
///
/// # Errors
///
/// Refuses insufficient heap space, target-unrepresentable extent lengths, immovable conflicts,
/// graph relocation disagreement, or any final exFAT layout drift.
pub fn solve_lossless_ntfs_to_exfat(
    draft: NtfsToExfatRelocationDraft,
    limits: LayoutLimits,
) -> Result<NtfsToExfatSolvedPlan, NtfsToExfatError> {
    let destination_alignment = u64::from(draft.destination.geometry().bytes_per_cluster);
    let (live_allocations, staging_exclusions, materializations) = partition_payload_work(
        draft.destination.source_allocations().iter().copied(),
        &draft.target_graph,
        destination_alignment,
    )?;
    let layout = solve_layout_with_destination_domain_alignments_and_materializations(
        draft.destination.geometry().volume_bytes,
        512,
        destination_alignment,
        512,
        draft.destination.cluster_heap_range(),
        live_allocations,
        draft.destination.reservations().to_vec(),
        staging_exclusions,
        &materializations,
        limits,
    )?;
    let relocation = SealedRelocationPlan::seal(draft.target_graph, layout)?;
    let destination = finalize_exfat_destination(&draft.destination, &relocation)?;
    Ok(NtfsToExfatSolvedPlan {
        preservation: draft.preservation,
        object_metadata: draft.object_metadata,
        destination_volume_label: draft.destination_volume_label,
        destination_volume_serial_number: draft.destination_volume_serial_number,
        destination,
        relocation,
    })
}

/// One escrow carrier file placed on the dest-native exFAT graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProjectedCarrier {
    /// Dest-native carrier file object.
    pub object: ObjectId,
    /// Source object (sidecar record) whose named stream the carrier holds.
    pub owner: ObjectId,
}

/// Dest-native exFAT projection of an NTFS graph plus the escrow carriers it introduced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NtfsExfatProjection {
    pub graph: ObjectGraph,
    /// Root-level escrow carrier directory, present only when at least one carrier exists.
    pub escrow_directory: Option<ObjectId>,
    pub carriers: Vec<ProjectedCarrier>,
}

fn projected_stream_id(record: u64, attribute_id: u16) -> Option<StreamId> {
    record
        .checked_shl(16)
        .and_then(|value| value.checked_add(u64::from(attribute_id)))
        .map(StreamId)
}

/// Moves every sidecar-implied carrier stream out of its owner into a dest-native carrier file.
///
/// Carrier objects and the escrow directory receive fresh [`ObjectId`]s above every source id;
/// the moved stream keeps its [`StreamId`] so the graph's extents stay attached to the payload.
/// Carrier objects/entries introduced by [`project_escrow_carriers`].
#[derive(Debug, Default)]
struct CarrierProjection {
    escrow_directory: Option<ObjectId>,
    carriers: Vec<ProjectedCarrier>,
    entries: Vec<NamespaceEntry>,
}

fn project_escrow_carriers(
    normalized: &NormalizedNtfs,
    objects: &mut Vec<ObjectRecord>,
    kept_streams: &mut BTreeSet<StreamId>,
) -> Result<CarrierProjection, NtfsToExfatError> {
    let carriers = sidecar_carriers(&normalized.preservation);
    if carriers.is_empty() {
        return Ok(CarrierProjection::default());
    }
    let mut next_id = objects.iter().map(|object| object.id.0).max().unwrap_or(0);
    let allocate = |next_id: &mut u64| -> Result<ObjectId, NtfsToExfatError> {
        *next_id = next_id
            .checked_add(1)
            .ok_or(NtfsToExfatError::ObjectIdOverflow)?;
        Ok(ObjectId(*next_id))
    };
    let escrow_directory = allocate(&mut next_id)?;
    let mut projected = Vec::new();
    let mut carrier_objects = Vec::new();
    let mut carrier_entries = Vec::new();
    projected
        .try_reserve_exact(carriers.len())
        .map_err(|_| NtfsToExfatError::AllocationFailed)?;
    carrier_objects
        .try_reserve_exact(carriers.len().saturating_add(1))
        .map_err(|_| NtfsToExfatError::AllocationFailed)?;
    carrier_entries
        .try_reserve_exact(carriers.len().saturating_add(1))
        .map_err(|_| NtfsToExfatError::AllocationFailed)?;
    for carrier in &carriers {
        let missing = || NtfsToExfatError::EscrowCarrierStreamMissing {
            owner: carrier.owner,
            attribute_id: carrier.attribute_id,
        };
        let stream_id =
            projected_stream_id(carrier.owner.0, carrier.attribute_id).ok_or_else(missing)?;
        let owner = objects
            .iter_mut()
            .find(|object| object.id == carrier.owner)
            .ok_or_else(missing)?;
        let position = owner
            .streams
            .iter()
            .position(|stream| {
                stream.id == stream_id
                    && stream.name.as_deref() == Some(carrier.stream_name.as_slice())
                    && stream.logical_bytes == carrier.data_bytes
            })
            .ok_or_else(missing)?;
        let mut stream = owner.streams.remove(position);
        stream.name = None;
        // Same dest-view policy as unnamed payloads: exFAT has no sparse or compressed streams,
        // so the carrier materializes holes as zeros and decompresses LZNT1 units, while the
        // compression-unit size stays on the projected stream so reconstruction never copies
        // compressed clusters as plaintext.
        stream.flags.sparse = false;
        stream.flags.compressed = false;
        kept_streams.insert(stream.id);
        let object = allocate(&mut next_id)?;
        carrier_objects.push(ObjectRecord {
            id: object,
            kind: ObjectKind::File,
            link_count: 1,
            semantics: ObjectSemantics::default(),
            streams: vec![stream],
        });
        carrier_entries.push(NamespaceEntry {
            parent: escrow_directory,
            target: object,
            name: carrier.file_name(),
        });
        projected.push(ProjectedCarrier {
            object,
            owner: carrier.owner,
        });
    }
    carrier_objects.push(ObjectRecord {
        id: escrow_directory,
        kind: ObjectKind::Directory,
        link_count: 1,
        semantics: ObjectSemantics::default(),
        streams: Vec::new(),
    });
    carrier_entries.push(NamespaceEntry {
        parent: normalized.graph.root(),
        target: escrow_directory,
        name: carrier_directory_name(),
    });
    objects
        .try_reserve(carrier_objects.len())
        .map_err(|_| NtfsToExfatError::AllocationFailed)?;
    objects.extend(carrier_objects);
    Ok(CarrierProjection {
        escrow_directory: Some(escrow_directory),
        carriers: projected,
        entries: carrier_entries,
    })
}

#[allow(clippy::too_many_lines)]
pub(crate) fn project_ntfs_graph_for_exfat(
    normalized: &NormalizedNtfs,
) -> Result<NtfsExfatProjection, NtfsToExfatError> {
    let mut kept_streams = BTreeSet::new();
    let mut objects = normalized.graph.objects().to_vec();
    // Named streams the sidecar could not capture byte-for-byte become dest-native carrier files
    // before the remaining named streams are dropped from the destination view.
    let CarrierProjection {
        escrow_directory,
        carriers,
        entries: carrier_entries,
    } = project_escrow_carriers(normalized, &mut objects, &mut kept_streams)?;
    for object in &mut objects {
        // exFAT cannot enforce per-object ACLs or reparse semantics. The preservation policy has
        // already required and produced exact escrow before this projection is reached, so only
        // the destination view loses the enforcement markers; source identities, descriptor bytes,
        // and $REPARSE_POINT payloads stay in evidence.
        object.semantics.has_security_descriptor = false;
        object.semantics.is_reparse_point = false;
        if object.id != normalized.graph.root() {
            object.link_count = 1;
        }
        object.streams.retain(|stream| stream.name.is_none());
        for stream in &mut object.streams {
            stream.flags.sparse = false;
            stream.flags.compressed = false;
            kept_streams.insert(stream.id);
        }
    }
    let mut by_target: BTreeMap<ObjectId, Vec<&NamespaceEntry>> = BTreeMap::new();
    for entry in normalized.graph.entries() {
        by_target.entry(entry.target).or_default().push(entry);
    }
    let mut entries = Vec::new();
    entries
        .try_reserve(objects.len().saturating_sub(1))
        .map_err(|_| NtfsToExfatError::AllocationFailed)?;
    for object in normalized.graph.objects() {
        if object.id == normalized.graph.root() {
            continue;
        }
        let Some(choices) = by_target.get(&object.id) else {
            continue;
        };
        entries.push(select_dest_native_namespace_entry(
            object.id,
            choices,
            &normalized.preservation,
        ));
    }
    if escrow_directory.is_some()
        && entries.iter().any(|entry| {
            entry.parent == normalized.graph.root() && collides_with_carrier_directory(&entry.name)
        })
    {
        return Err(NtfsToExfatError::EscrowCarrierNameCollision);
    }
    // Hard-link collapse already picked one dest-native name per object. Remaining siblings
    // that fold together under the recommended exFAT up-case table keep the lowest ObjectId
    // name unchanged and receive a dest-legal `~N` suffix so the exFAT writer can serialize.
    disambiguate_exfat_case_collisions(&mut entries)?;
    // Carrier names are reserved and collision-free by construction, so they join after
    // disambiguation exactly as the restore side reconstructs them.
    entries.extend(carrier_entries);
    let filtered_extents: Vec<Extent> = normalized
        .graph
        .extents()
        .extents()
        .iter()
        .copied()
        .filter(|extent| kept_streams.contains(&extent.stream))
        .collect();
    let extent_graph = ExtentGraph::build(
        filtered_extents,
        normalized.graph.extents().volume_bytes(),
        normalized.graph.extents().extents().len().max(1),
    )
    .map_err(NtfsToExfatError::ExtentProjection)?;
    let maximum_name_units = entries
        .iter()
        .map(|entry| entry.name.len())
        .max()
        .unwrap_or(1);
    let stream_count = objects
        .iter()
        .map(|object| object.streams.len())
        .sum::<usize>();
    let object_count = objects.len();
    let entry_count = entries.len();
    let graph = ObjectGraph::build(
        normalized.graph.root(),
        objects,
        entries,
        extent_graph,
        ObjectGraphLimits {
            max_objects: object_count.max(1),
            max_entries: entry_count.max(1),
            max_streams: stream_count.max(1),
            max_name_code_units: maximum_name_units,
        },
    )
    .map_err(NtfsToExfatError::GraphProjection)?;
    Ok(NtfsExfatProjection {
        graph,
        escrow_directory,
        carriers,
    })
}

pub(crate) fn select_dest_native_namespace_entry(
    object: ObjectId,
    choices: &[&NamespaceEntry],
    sidecar: &crate::fs::ntfs_normalize::NtfsPreservationSidecar,
) -> NamespaceEntry {
    choices
        .iter()
        .min_by_key(|entry| {
            (
                dest_native_name_rank(object, entry, sidecar),
                entry.parent.0,
                entry.name.as_slice(),
            )
        })
        .copied()
        .expect("namespace projection is only called with a non-empty name set")
        .clone()
}

pub(crate) fn dest_native_name_rank(
    object: ObjectId,
    entry: &NamespaceEntry,
    sidecar: &crate::fs::ntfs_normalize::NtfsPreservationSidecar,
) -> u8 {
    let Some(preserved) = sidecar
        .objects
        .iter()
        .find(|candidate| candidate.object == object)
    else {
        return 4;
    };
    preserved
        .source
        .file_names
        .iter()
        .find_map(|name| {
            (name.parent.record_number == entry.parent.0 && name.name.code_units == entry.name)
                .then_some(match name.namespace {
                    FileNameNamespace::Win32AndDos => 0,
                    FileNameNamespace::Win32 => 1,
                    FileNameNamespace::Posix => 2,
                    FileNameNamespace::Dos => 3,
                })
        })
        .unwrap_or(4)
}

pub(crate) fn disambiguate_exfat_case_collisions(
    entries: &mut [NamespaceEntry],
) -> Result<(), NtfsToExfatError> {
    if entries.len() < 2 {
        return Ok(());
    }
    let table = generate_recommended_exfat_upcase(RecommendedExfatUpcaseLimits::default())?;
    let mut used = BTreeSet::new();
    let mut groups: BTreeMap<(ObjectId, Vec<u16>), Vec<usize>> = BTreeMap::new();
    for (index, entry) in entries.iter().enumerate() {
        let folded = fold_exfat_name(&entry.name, &table)?;
        groups
            .entry((entry.parent, folded.clone()))
            .or_default()
            .push(index);
        used.insert((entry.parent, folded));
    }
    for ((parent, _), mut members) in groups {
        if members.len() < 2 {
            continue;
        }
        members.sort_by(|left, right| {
            entries[*left]
                .target
                .cmp(&entries[*right].target)
                .then_with(|| entries[*left].name.cmp(&entries[*right].name))
        });
        for index in members.into_iter().skip(1) {
            let replacement =
                unique_exfat_sibling_name(&entries[index].name, parent, &table, &mut used)?;
            entries[index].name = replacement;
        }
    }
    Ok(())
}

fn fold_exfat_name(
    name: &[u16],
    table: &RecommendedExfatUpcase,
) -> Result<Vec<u16>, NtfsToExfatError> {
    let mut folded = Vec::new();
    folded
        .try_reserve_exact(name.len())
        .map_err(|_| NtfsToExfatError::AllocationFailed)?;
    folded.extend(name.iter().map(|unit| table.map(*unit)));
    Ok(folded)
}

fn split_exfat_stem_ext(name: &[u16]) -> (&[u16], &[u16]) {
    name.iter()
        .rposition(|unit| *unit == u16::from(b'.'))
        .filter(|position| *position > 0)
        .map_or((name, &[]), |position| {
            (&name[..position], &name[position..])
        })
}

fn exfat_disambiguated_name(stem: &[u16], ext: &[u16], n: u32) -> Option<Vec<u16>> {
    let suffix: Vec<u16> = format!("~{n}").encode_utf16().collect();
    let needed = suffix.len().checked_add(ext.len())?;
    if needed >= MAX_FILE_NAME_CODE_UNITS || stem.is_empty() {
        return None;
    }
    let max_stem = MAX_FILE_NAME_CODE_UNITS - needed;
    let stem = &stem[..stem.len().min(max_stem)];
    if stem.is_empty() {
        return None;
    }
    let mut name = Vec::new();
    name.try_reserve_exact(stem.len() + suffix.len() + ext.len())
        .ok()?;
    name.extend_from_slice(stem);
    name.extend_from_slice(&suffix);
    name.extend_from_slice(ext);
    Some(name)
}

fn unique_exfat_sibling_name(
    original: &[u16],
    parent: ObjectId,
    table: &RecommendedExfatUpcase,
    used: &mut BTreeSet<(ObjectId, Vec<u16>)>,
) -> Result<Vec<u16>, NtfsToExfatError> {
    let (stem, ext) = split_exfat_stem_ext(original);
    for n in 2_u32..=1_000_000 {
        let Some(candidate) = exfat_disambiguated_name(stem, ext, n) else {
            continue;
        };
        if !is_legal_exfat_name(&candidate) {
            continue;
        }
        let folded = fold_exfat_name(&candidate, table)?;
        if used.insert((parent, folded)) {
            return Ok(candidate);
        }
    }
    Err(NtfsToExfatError::NameDisambiguationFailed { parent })
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

type PartitionedPayloadWork = (
    Vec<SourceAllocation>,
    Vec<ByteRange>,
    Vec<MaterializationRequest>,
);

fn partition_payload_work<I>(
    allocations: I,
    graph: &ObjectGraph,
    destination_alignment: u64,
) -> Result<PartitionedPayloadWork, LayoutError>
where
    I: IntoIterator<Item = SourceAllocation>,
{
    let allocations: Vec<_> = allocations.into_iter().collect();
    let mut materializing = std::collections::BTreeSet::new();
    for object in graph.objects() {
        if object.kind != ObjectKind::File {
            continue;
        }
        for stream in &object.streams {
            if let Some(destination_length) =
                materialization_length_for_stream(graph, stream.id, destination_alignment)
            {
                materializing.insert((stream.id, destination_length));
            }
        }
    }
    let mut live_allocations = Vec::new();
    let mut staging_exclusions = Vec::new();
    live_allocations
        .try_reserve(allocations.len())
        .map_err(|_| LayoutError::AllocationFailed)?;
    staging_exclusions
        .try_reserve(allocations.len())
        .map_err(|_| LayoutError::AllocationFailed)?;
    for allocation in allocations {
        let graph_backed_file_data = allocation.movable
            && graph.extents().extents().iter().any(|extent| {
                extent.kind == ExtentKind::FileData
                    && extent.stream == allocation.stream
                    && extent.logical_offset == allocation.logical_offset
                    && extent.length == allocation.range.length
                    && extent.placement
                        == Placement::Physical {
                            byte_offset: allocation.range.offset,
                        }
            });
        let stream_materializes = materializing
            .iter()
            .any(|(stream, _)| *stream == allocation.stream);
        if graph_backed_file_data && !stream_materializes {
            live_allocations.push(allocation);
        } else {
            staging_exclusions.push(allocation.range);
        }
    }
    let mut materializations = Vec::new();
    materializations
        .try_reserve(materializing.len())
        .map_err(|_| LayoutError::AllocationFailed)?;
    for (stream, destination_length) in materializing {
        materializations.push(MaterializationRequest {
            stream,
            destination_length,
        });
    }
    Ok((live_allocations, staging_exclusions, materializations))
}

/// exFAT `FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM`, applied to every escrow carrier so the
/// dest volume never presents carrier payloads as ordinary user files.
const ESCROW_CARRIER_ATTRIBUTES: u16 = 0x06;
const EXFAT_ATTRIBUTE_DIRECTORY: u16 = 0x10;
const EXFAT_ATTRIBUTE_ARCHIVE: u16 = 0x20;

fn map_ntfs_object_metadata(
    normalized: &NormalizedNtfs,
    projection: &NtfsExfatProjection,
) -> Result<Vec<ExfatObjectMetadata>, NtfsToExfatError> {
    let mut metadata = map_ntfs_source_object_metadata(normalized)?;
    let Some(escrow_directory) = projection.escrow_directory else {
        return Ok(metadata);
    };
    metadata
        .try_reserve(projection.carriers.len().saturating_add(1))
        .map_err(|_| NtfsToExfatError::AllocationFailed)?;
    let standard_for = |object: ObjectId| {
        normalized
            .preservation
            .objects
            .iter()
            .find(|evidence| evidence.object == object)
            .and_then(|evidence| evidence.source.standard_information)
            .ok_or(NtfsToExfatError::MissingStandardInformation(object))
    };
    let root = standard_for(normalized.graph.root())?;
    metadata.push(ExfatObjectMetadata {
        object: escrow_directory,
        file_attributes: ESCROW_CARRIER_ATTRIBUTES | EXFAT_ATTRIBUTE_DIRECTORY,
        timestamps: map_ntfs_timestamps(
            root.creation_time,
            root.modification_time,
            root.access_time,
        )
        .ok_or(NtfsToExfatError::TimestampOutsideExfatRange(
            escrow_directory,
        ))?,
    });
    for carrier in &projection.carriers {
        let owner = standard_for(carrier.owner)?;
        metadata.push(ExfatObjectMetadata {
            object: carrier.object,
            file_attributes: ESCROW_CARRIER_ATTRIBUTES | EXFAT_ATTRIBUTE_ARCHIVE,
            timestamps: map_ntfs_timestamps(
                owner.creation_time,
                owner.modification_time,
                owner.access_time,
            )
            .ok_or(NtfsToExfatError::TimestampOutsideExfatRange(carrier.owner))?,
        });
    }
    Ok(metadata)
}

fn map_ntfs_source_object_metadata(
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
        NtfsAttributeEvidence, NtfsDataStream, NtfsInventoryExtent, NtfsName, NtfsObject,
        NtfsObjectReference, NtfsStandardInformation, NtfsStreamStorage,
    };
    use crate::fs::ntfs_normalize::{NtfsObjectPreservation, NtfsPreservationSidecar};
    use crate::object::{
        NamespaceEntry, ObjectGraph, ObjectGraphLimits, ObjectRecord, ObjectSemantics,
        ObjectStream, StreamFlags, StreamStorage,
    };
    use crate::preservation::FieldDisposition;

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

    fn ntfs_source_object(
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
            attribute_census: vec![NtfsAttributeEvidence {
                attribute_type: 0x10,
                name: None,
                flags_raw: 0,
                flags_unknown_bits: 0,
                attribute_id: 1,
                resident: true,
            }],
            directory_entries: Vec::new(),
            has_reparse_point: false,
            reparse_point: None,
            has_attribute_list: false,
            directory_index_complete: true,
        }
    }

    fn ntfs_empty_badclus(timestamp: u64) -> NtfsObject {
        let mut badclus = ntfs_source_object(8, false, 0x06, timestamp);
        let bad_name = NtfsName {
            code_units: "$Bad".encode_utf16().collect(),
            is_well_formed: true,
        };
        badclus.data_streams.push(NtfsDataStream {
            attribute_id: 3,
            name: Some(bad_name.clone()),
            compressed: false,
            encrypted: false,
            sparse: false,
            compression_block_bytes: 0,
            storage: NtfsStreamStorage::NonResident {
                allocated_bytes: 64 * 1024 * 1024,
                data_bytes: 64 * 1024 * 1024,
                initialized_bytes: 0,
                compressed_bytes: None,
                mapping_complete: true,
                extents: vec![NtfsInventoryExtent {
                    stream_id: (8 << 16) | 3,
                    logical_offset: 0,
                    length: 64 * 1024 * 1024,
                    placement: NtfsExtentPlacement::Sparse,
                }],
                captured_payload: None,
            },
        });
        badclus.attribute_census.push(NtfsAttributeEvidence {
            attribute_type: 0x80,
            name: Some(bad_name),
            flags_raw: 0,
            flags_unknown_bits: 0,
            attribute_id: 3,
            resident: false,
        });
        badclus
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
                        source: ntfs_empty_badclus(timestamp),
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

    fn normalized_ntfs_with_payload(byte_offset: u64) -> NormalizedNtfs {
        let mut normalized = normalized_ntfs();
        let stream_id = (27_u64 << 16) | 2;
        let mut objects = normalized.graph.objects().to_vec();
        let stream = &mut objects
            .iter_mut()
            .find(|object| object.id == ObjectId(27))
            .unwrap()
            .streams[0];
        stream.id = StreamId(stream_id);
        stream.logical_bytes = 4096;
        stream.initialized_bytes = 4096;
        stream.mapped_bytes = 4096;
        stream.allocated_bytes = 4096;
        stream.storage = StreamStorage::Extents;
        let source_extent = NtfsInventoryExtent {
            stream_id,
            logical_offset: 0,
            length: 4096,
            placement: NtfsExtentPlacement::Physical { byte_offset },
        };
        normalized.graph = ObjectGraph::build(
            normalized.graph.root(),
            objects,
            normalized.graph.entries().to_vec(),
            ExtentGraph::build(
                vec![crate::extent::Extent {
                    stream: StreamId(stream_id),
                    logical_offset: 0,
                    length: 4096,
                    placement: Placement::Physical { byte_offset },
                    kind: ExtentKind::FileData,
                }],
                normalized.graph.extents().volume_bytes(),
                8,
            )
            .unwrap(),
            ObjectGraphLimits {
                max_objects: 4,
                max_entries: 4,
                max_streams: 4,
                max_name_code_units: 255,
            },
        )
        .unwrap();
        let source = &mut normalized
            .preservation
            .objects
            .iter_mut()
            .find(|object| object.object == ObjectId(27))
            .unwrap()
            .source;
        source.data_streams.push(NtfsDataStream {
            attribute_id: 2,
            name: None,
            compressed: false,
            encrypted: false,
            sparse: false,
            compression_block_bytes: 0,
            storage: NtfsStreamStorage::NonResident {
                allocated_bytes: 4096,
                data_bytes: 4096,
                initialized_bytes: 4096,
                compressed_bytes: None,
                mapping_complete: true,
                extents: vec![source_extent],
                captured_payload: None,
            },
        });
        source.attribute_census.push(NtfsAttributeEvidence {
            attribute_type: 0x80,
            name: None,
            flags_raw: 0,
            flags_unknown_bits: 0,
            attribute_id: 2,
            resident: false,
        });
        normalized.preservation.source_extents.push(source_extent);
        normalized
    }

    fn normalized_ntfs_with_compressed_payload() -> NormalizedNtfs {
        let byte_offset = 8 * 1024 * 1024;
        let mut normalized = normalized_ntfs_with_payload(byte_offset);
        let stream_id = StreamId((27_u64 << 16) | 2);
        let mut objects = normalized.graph.objects().to_vec();
        let stream = &mut objects
            .iter_mut()
            .find(|object| object.id == ObjectId(27))
            .unwrap()
            .streams[0];
        stream.logical_bytes = 6;
        stream.initialized_bytes = 6;
        stream.mapped_bytes = 8192;
        stream.allocated_bytes = 4096;
        stream.flags.compressed = true;
        stream.flags.compression_block_bytes = 8192;
        let physical = NtfsInventoryExtent {
            stream_id: stream_id.0,
            logical_offset: 0,
            length: 4096,
            placement: NtfsExtentPlacement::Physical { byte_offset },
        };
        let hole = NtfsInventoryExtent {
            stream_id: stream_id.0,
            logical_offset: 4096,
            length: 4096,
            placement: NtfsExtentPlacement::Sparse,
        };
        normalized.graph = ObjectGraph::build(
            normalized.graph.root(),
            objects,
            normalized.graph.entries().to_vec(),
            ExtentGraph::build(
                vec![
                    crate::extent::Extent {
                        stream: stream_id,
                        logical_offset: 0,
                        length: 4096,
                        placement: Placement::Physical { byte_offset },
                        kind: ExtentKind::FileData,
                    },
                    crate::extent::Extent {
                        stream: stream_id,
                        logical_offset: 4096,
                        length: 4096,
                        placement: Placement::Sparse,
                        kind: ExtentKind::FileData,
                    },
                ],
                normalized.graph.extents().volume_bytes(),
                8,
            )
            .unwrap(),
            ObjectGraphLimits {
                max_objects: 4,
                max_entries: 4,
                max_streams: 4,
                max_name_code_units: 255,
            },
        )
        .unwrap();
        let source = &mut normalized
            .preservation
            .objects
            .iter_mut()
            .find(|object| object.object == ObjectId(27))
            .unwrap()
            .source;
        let stream = source
            .data_streams
            .iter_mut()
            .find(|stream| stream.attribute_id == 2)
            .unwrap();
        stream.compressed = true;
        stream.compression_block_bytes = 8192;
        stream.storage = NtfsStreamStorage::NonResident {
            allocated_bytes: 4096,
            data_bytes: 6,
            initialized_bytes: 6,
            compressed_bytes: Some(4096),
            mapping_complete: true,
            extents: vec![physical, hole],
            captured_payload: None,
        };
        if let Some(attribute) = source
            .attribute_census
            .iter_mut()
            .find(|attribute| attribute.attribute_id == 2)
        {
            attribute.flags_raw = 0x0001;
        }
        normalized
            .preservation
            .source_extents
            .retain(|extent| extent.stream_id != stream_id.0);
        normalized
            .preservation
            .source_extents
            .extend([physical, hole]);
        normalized
    }

    /// `legal.txt` gains a 4 KiB non-resident `:fork` stream the inventory did not capture.
    #[allow(clippy::too_many_lines)]
    fn normalized_ntfs_with_uncaptured_named_stream(byte_offset: u64) -> NormalizedNtfs {
        let mut normalized = normalized_ntfs_with_payload(4 * 1024 * 1024);
        let stream_id = StreamId((27_u64 << 16) | 3);
        let fork_name: Vec<u16> = "fork".encode_utf16().collect();
        let mut objects = normalized.graph.objects().to_vec();
        objects
            .iter_mut()
            .find(|object| object.id == ObjectId(27))
            .unwrap()
            .streams
            .push(ObjectStream {
                id: stream_id,
                name: Some(fork_name.clone()),
                logical_bytes: 4096,
                initialized_bytes: 4096,
                mapped_bytes: 4096,
                allocated_bytes: 4096,
                flags: StreamFlags::default(),
                storage: StreamStorage::Extents,
            });
        let source_extent = NtfsInventoryExtent {
            stream_id: stream_id.0,
            logical_offset: 0,
            length: 4096,
            placement: NtfsExtentPlacement::Physical { byte_offset },
        };
        let mut extents = normalized.graph.extents().extents().to_vec();
        extents.push(crate::extent::Extent {
            stream: stream_id,
            logical_offset: 0,
            length: 4096,
            placement: Placement::Physical { byte_offset },
            kind: ExtentKind::FileData,
        });
        normalized.graph = ObjectGraph::build(
            normalized.graph.root(),
            objects,
            normalized.graph.entries().to_vec(),
            ExtentGraph::build(extents, normalized.graph.extents().volume_bytes(), 8).unwrap(),
            ObjectGraphLimits {
                max_objects: 4,
                max_entries: 4,
                max_streams: 4,
                max_name_code_units: 255,
            },
        )
        .unwrap();
        let source = &mut normalized
            .preservation
            .objects
            .iter_mut()
            .find(|object| object.object == ObjectId(27))
            .unwrap()
            .source;
        // Escrow restore matches dest objects by the dest-native path reconstructed from the
        // sidecar's `$FILE_NAME`s, so the fixture needs the source name evidence too.
        source
            .file_names
            .push(crate::fs::ntfs_inventory::NtfsFileName {
                parent: NtfsObjectReference {
                    record_number: 5,
                    sequence_number: 1,
                },
                namespace: FileNameNamespace::Win32AndDos,
                name: NtfsName {
                    code_units: "legal.txt".encode_utf16().collect(),
                    is_well_formed: true,
                },
                allocated_size: 4096,
                data_size: 4096,
                file_attributes: 0x20,
                reparse_tag_or_ea_size: 0,
            });
        source.data_streams.push(NtfsDataStream {
            attribute_id: 3,
            name: Some(NtfsName {
                code_units: fork_name,
                is_well_formed: true,
            }),
            compressed: false,
            encrypted: false,
            sparse: false,
            compression_block_bytes: 0,
            storage: NtfsStreamStorage::NonResident {
                allocated_bytes: 4096,
                data_bytes: 4096,
                initialized_bytes: 4096,
                compressed_bytes: None,
                mapping_complete: true,
                extents: vec![source_extent],
                captured_payload: None,
            },
        });
        source.attribute_census.push(NtfsAttributeEvidence {
            attribute_type: 0x80,
            name: Some(NtfsName {
                code_units: "fork".encode_utf16().collect(),
                is_well_formed: true,
            }),
            flags_raw: 0,
            flags_unknown_bits: 0,
            attribute_id: 3,
            resident: false,
        });
        normalized.preservation.source_extents.push(source_extent);
        normalized
    }

    #[test]
    fn uncaptured_named_stream_is_projected_as_a_hidden_escrow_carrier_file() {
        use crate::escrow_carrier::{carrier_directory_name, carrier_file_name};

        let normalized = normalized_ntfs_with_uncaptured_named_stream(8 * 1024 * 1024);
        let projection = project_ntfs_graph_for_exfat(&normalized).unwrap();
        let graph = &projection.graph;
        let directory = projection.escrow_directory.expect("escrow directory");
        assert_eq!(projection.carriers.len(), 1);
        let carrier = projection.carriers[0];
        assert_eq!(carrier.owner, ObjectId(27));
        assert_eq!(graph.objects().len(), 4);

        let owner = graph
            .objects()
            .iter()
            .find(|object| object.id == ObjectId(27))
            .unwrap();
        assert_eq!(owner.streams.len(), 1);
        assert!(owner.streams[0].name.is_none());

        let carrier_object = graph
            .objects()
            .iter()
            .find(|object| object.id == carrier.object)
            .unwrap();
        assert_eq!(carrier_object.kind, ObjectKind::File);
        assert_eq!(carrier_object.streams.len(), 1);
        assert_eq!(carrier_object.streams[0].id, StreamId((27_u64 << 16) | 3));
        assert!(carrier_object.streams[0].name.is_none());
        assert_eq!(carrier_object.streams[0].storage, StreamStorage::Extents);
        assert!(graph.extents().extents().iter().any(|extent| {
            extent.stream == StreamId((27_u64 << 16) | 3)
                && extent.placement
                    == Placement::Physical {
                        byte_offset: 8 * 1024 * 1024,
                    }
        }));

        let directory_entry = graph
            .entries()
            .iter()
            .find(|entry| entry.target == directory)
            .unwrap();
        assert_eq!(directory_entry.parent, graph.root());
        assert_eq!(directory_entry.name, carrier_directory_name());
        let carrier_entry = graph
            .entries()
            .iter()
            .find(|entry| entry.target == carrier.object)
            .unwrap();
        assert_eq!(carrier_entry.parent, directory);
        assert_eq!(carrier_entry.name, carrier_file_name(27, 3));

        let metadata = map_ntfs_object_metadata(&normalized, &projection).unwrap();
        assert_eq!(metadata.len(), 3);
        let directory_metadata = metadata
            .iter()
            .find(|entry| entry.object == directory)
            .unwrap();
        assert_eq!(directory_metadata.file_attributes, 0x16);
        let carrier_metadata = metadata
            .iter()
            .find(|entry| entry.object == carrier.object)
            .unwrap();
        assert_eq!(carrier_metadata.file_attributes, 0x26);
        let owner_metadata = metadata
            .iter()
            .find(|entry| entry.object == ObjectId(27))
            .unwrap();
        assert_eq!(carrier_metadata.timestamps, owner_metadata.timestamps);

        // The carrier payload is relocated into the exFAT heap like any unnamed payload.
        let draft = draft_lossless_ntfs_to_exfat(
            &normalized,
            GuaranteeMode::Escrow,
            NtfsToExfatOptions::default(),
            NtfsToExfatLimits::default(),
        )
        .unwrap();
        assert!(draft.destination.source_allocations().iter().any(|item| {
            item.stream == StreamId((27_u64 << 16) | 3)
                && item.range.offset == 8 * 1024 * 1024
                && item.movable
        }));
        let solved = solve_lossless_ntfs_to_exfat(draft, LayoutLimits::default()).unwrap();
        assert!(
            solved
                .relocation()
                .target_graph()
                .objects()
                .iter()
                .any(|object| object.id == carrier.object)
        );
    }

    #[test]
    fn source_root_entry_colliding_with_the_escrow_directory_is_refused() {
        let mut normalized = normalized_ntfs_with_uncaptured_named_stream(8 * 1024 * 1024);
        let mut entries = normalized.graph.entries().to_vec();
        entries[0].name = ".StarConverter-Escrow".encode_utf16().collect();
        normalized.graph = ObjectGraph::build(
            normalized.graph.root(),
            normalized.graph.objects().to_vec(),
            entries,
            normalized.graph.extents().clone(),
            ObjectGraphLimits {
                max_objects: 4,
                max_entries: 4,
                max_streams: 4,
                max_name_code_units: 255,
            },
        )
        .unwrap();
        assert!(matches!(
            project_ntfs_graph_for_exfat(&normalized),
            Err(NtfsToExfatError::EscrowCarrierNameCollision)
        ));

        // Without any carrier the same name is an ordinary user entry.
        let plain = normalized_ntfs();
        let mut entries = plain.graph.entries().to_vec();
        entries[0].name = ".starconverter-escrow".encode_utf16().collect();
        let plain = NormalizedNtfs {
            graph: ObjectGraph::build(
                plain.graph.root(),
                plain.graph.objects().to_vec(),
                entries,
                plain.graph.extents().clone(),
                ObjectGraphLimits {
                    max_objects: 4,
                    max_entries: 4,
                    max_streams: 4,
                    max_name_code_units: 255,
                },
            )
            .unwrap(),
            preservation: plain.preservation,
        };
        let projection = project_ntfs_graph_for_exfat(&plain).unwrap();
        assert!(projection.escrow_directory.is_none());
        assert_eq!(projection.graph.objects().len(), 2);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn escrow_restore_folds_carrier_back_into_the_named_stream() {
        use crate::escrow_restore::restore_ntfs_identities_with_evidence;

        let normalized = normalized_ntfs_with_uncaptured_named_stream(8 * 1024 * 1024);
        let projection = project_ntfs_graph_for_exfat(&normalized).unwrap();
        let carrier = projection.carriers[0];
        let directory = projection.escrow_directory.unwrap();

        let restored =
            restore_ntfs_identities_with_evidence(&projection.graph, &normalized.preservation)
                .unwrap();
        assert_eq!(
            restored.removed_objects,
            BTreeSet::from([carrier.object, directory])
        );
        assert_eq!(restored.graph.objects().len(), 2);
        assert_eq!(restored.graph.entries().len(), 1);
        let file = restored
            .graph
            .objects()
            .iter()
            .find(|object| object.id == ObjectId(27))
            .unwrap();
        assert_eq!(file.streams.len(), 2);
        let fork_name: Vec<u16> = "fork".encode_utf16().collect();
        let fork = file
            .streams
            .iter()
            .find(|stream| stream.name.as_deref() == Some(fork_name.as_slice()))
            .expect("restored named stream");
        assert_eq!(fork.id, StreamId((27_u64 << 16) | 3));
        assert_eq!(fork.logical_bytes, 4096);
        assert_eq!(fork.storage, StreamStorage::Extents);
        assert_eq!(fork.flags, StreamFlags::default());
        assert!(
            restored
                .graph
                .extents()
                .extents()
                .iter()
                .any(|extent| extent.stream == fork.id)
        );

        // A carrier the sidecar expects but the candidate lacks fails closed.
        let without_carrier = ObjectGraph::build(
            projection.graph.root(),
            projection
                .graph
                .objects()
                .iter()
                .filter(|object| object.id != carrier.object)
                .cloned()
                .collect(),
            projection
                .graph
                .entries()
                .iter()
                .filter(|entry| entry.target != carrier.object)
                .cloned()
                .collect(),
            ExtentGraph::build(
                projection
                    .graph
                    .extents()
                    .extents()
                    .iter()
                    .filter(|extent| extent.stream != StreamId((27_u64 << 16) | 3))
                    .copied()
                    .collect(),
                projection.graph.extents().volume_bytes(),
                8,
            )
            .unwrap(),
            ObjectGraphLimits {
                max_objects: 4,
                max_entries: 4,
                max_streams: 4,
                max_name_code_units: 255,
            },
        )
        .unwrap();
        assert!(matches!(
            restore_ntfs_identities_with_evidence(&without_carrier, &normalized.preservation),
            Err(NtfsRestoreError::UnrestorableNamedStream {
                object: ObjectId(27),
                data_bytes: 4096,
                ..
            })
        ));

        // A carrier of the wrong length is not silently accepted.
        let mut wrong_length = projection.graph.objects().to_vec();
        let shortened = &mut wrong_length
            .iter_mut()
            .find(|object| object.id == carrier.object)
            .unwrap()
            .streams[0];
        shortened.logical_bytes = 4095;
        shortened.initialized_bytes = 4095;
        let wrong_length = ObjectGraph::build(
            projection.graph.root(),
            wrong_length,
            projection.graph.entries().to_vec(),
            projection.graph.extents().clone(),
            ObjectGraphLimits {
                max_objects: 4,
                max_entries: 4,
                max_streams: 4,
                max_name_code_units: 255,
            },
        )
        .unwrap();
        assert!(matches!(
            restore_ntfs_identities_with_evidence(&wrong_length, &normalized.preservation),
            Err(NtfsRestoreError::EscrowCarrierMismatch {
                owner: ObjectId(27),
                data_bytes: 4096,
                ..
            })
        ));

        // Foreign entries inside the escrow directory keep it from being deleted.
        let mut with_foreign_objects = projection.graph.objects().to_vec();
        with_foreign_objects.push(ObjectRecord {
            id: ObjectId(900),
            kind: ObjectKind::File,
            link_count: 1,
            semantics: ObjectSemantics::default(),
            streams: vec![ObjectStream {
                id: StreamId(900),
                name: None,
                logical_bytes: 0,
                initialized_bytes: 0,
                mapped_bytes: 0,
                allocated_bytes: 0,
                flags: StreamFlags::default(),
                storage: StreamStorage::Resident(Vec::new()),
            }],
        });
        let mut with_foreign_entries = projection.graph.entries().to_vec();
        with_foreign_entries.push(NamespaceEntry {
            parent: directory,
            target: ObjectId(900),
            name: "notes.txt".encode_utf16().collect(),
        });
        let with_foreign = ObjectGraph::build(
            projection.graph.root(),
            with_foreign_objects,
            with_foreign_entries,
            projection.graph.extents().clone(),
            ObjectGraphLimits {
                max_objects: 5,
                max_entries: 5,
                max_streams: 5,
                max_name_code_units: 255,
            },
        )
        .unwrap();
        assert_eq!(
            restore_ntfs_identities_with_evidence(&with_foreign, &normalized.preservation)
                .err()
                .unwrap(),
            NtfsRestoreError::EscrowDirectoryNotEmpty(directory)
        );
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
    fn exfat_payload_conflict_is_solved_then_ntfs_runlists_are_reserialized() {
        let mut normalized = normalized_exfat();
        let mut objects = normalized.graph.objects().to_vec();
        let stream = &mut objects
            .iter_mut()
            .find(|object| object.id == ObjectId(2))
            .unwrap()
            .streams[0];
        stream.logical_bytes = 4096;
        stream.initialized_bytes = 4096;
        stream.mapped_bytes = 4096;
        stream.allocated_bytes = 4096;
        normalized.graph = ObjectGraph::build(
            normalized.graph.root(),
            objects,
            normalized.graph.entries().to_vec(),
            ExtentGraph::build(
                vec![crate::extent::Extent {
                    stream: StreamId(20),
                    logical_offset: 0,
                    length: 4096,
                    placement: Placement::Physical { byte_offset: 4096 },
                    kind: ExtentKind::FileData,
                }],
                normalized.graph.extents().volume_bytes(),
                8,
            )
            .unwrap(),
            ObjectGraphLimits {
                max_objects: 4,
                max_entries: 4,
                max_streams: 4,
                max_name_code_units: 255,
            },
        )
        .unwrap();
        normalized
            .preservation
            .objects
            .iter_mut()
            .find(|object| object.object == ObjectId(2))
            .unwrap()
            .clusters = vec![5];

        assert!(matches!(
            plan_lossless_exfat_to_ntfs(
                &normalized,
                GuaranteeMode::Escrow,
                ExfatToNtfsOptions::default(),
                ExfatToNtfsLimits::default(),
            ),
            Err(ExfatToNtfsError::Serialization(
                NtfsSerializeError::PayloadMetadataConflict { .. }
            ))
        ));
        let draft = draft_lossless_exfat_to_ntfs(
            &normalized,
            GuaranteeMode::Escrow,
            ExfatToNtfsOptions::default(),
            ExfatToNtfsLimits::default(),
        )
        .unwrap();
        assert!(
            draft
                .destination
                .source_allocations
                .iter()
                .any(|allocation| allocation.stream == StreamId(20) && allocation.movable)
        );
        let solved = solve_lossless_exfat_to_ntfs(draft, LayoutLimits::default()).unwrap();
        assert_eq!(solved.layout().relocations.len(), 1);
        assert_eq!(solved.layout().relocations[0].source.offset, 4096);
        assert_ne!(solved.layout().relocations[0].destination.offset, 4096);
        assert!(solved.destination.reservations.iter().any(|reservation| {
            reservation.kind == crate::geometry::ReservationKind::AllocationMetadata
        }));
        assert!(
            solved
                .destination
                .source_allocations
                .iter()
                .any(|allocation| {
                    allocation.stream == StreamId(20)
                        && allocation.range.offset == 4096
                        && allocation.movable
                })
        );
        let target_extent = solved
            .target_graph()
            .extents()
            .extents()
            .iter()
            .find(|extent| extent.stream == StreamId(20))
            .unwrap();
        assert_eq!(
            target_extent.placement,
            Placement::Physical {
                byte_offset: solved.layout().relocations[0].destination.offset
            }
        );
    }

    #[test]
    fn ntfs_payload_outside_exfat_heap_is_relocated_and_reserialized() {
        let normalized = normalized_ntfs_with_payload(4096);
        assert!(matches!(
            plan_lossless_ntfs_to_exfat(
                &normalized,
                GuaranteeMode::Escrow,
                NtfsToExfatOptions::default(),
                NtfsToExfatLimits::default(),
            ),
            Err(NtfsToExfatError::Serialization(
                ExfatSerializeError::PayloadNotClusterAligned(_)
            ))
        ));

        let draft = draft_lossless_ntfs_to_exfat(
            &normalized,
            GuaranteeMode::Escrow,
            NtfsToExfatOptions::default(),
            NtfsToExfatLimits::default(),
        )
        .unwrap();
        assert!(draft.destination.cluster_heap_range().offset > 4096);
        assert!(draft.destination.source_allocations().iter().any(|item| {
            item.stream == StreamId((27_u64 << 16) | 2) && item.range.offset == 4096 && item.movable
        }));

        let solved = solve_lossless_ntfs_to_exfat(draft, LayoutLimits::default()).unwrap();
        assert_eq!(solved.layout().relocations.len(), 1);
        let relocation = solved.layout().relocations[0];
        assert_eq!(relocation.source.offset, 4096);
        assert_eq!(relocation.destination.offset % 4096, 0);
        let heap = u64::from(solved.destination.geometry.cluster_heap_offset_sectors)
            * u64::from(solved.destination.geometry.bytes_per_sector);
        let heap_end = heap
            + u64::from(solved.destination.geometry.cluster_count)
                * u64::from(solved.destination.geometry.bytes_per_cluster);
        assert!(relocation.destination.offset >= heap);
        assert!(relocation.destination.offset + relocation.destination.length <= heap_end);
        assert_eq!(solved.destination.reused_payloads.len(), 1);
        assert_eq!(
            solved.destination.reused_payloads[0].clusters[0],
            u32::try_from((relocation.destination.offset - heap) / 4096 + 2).unwrap()
        );
        assert!(solved.destination.source_allocations.iter().any(|item| {
            item.stream == StreamId((27_u64 << 16) | 2) && item.range.offset == 4096 && item.movable
        }));
    }

    #[test]
    fn escrow_ntfs_lznt1_is_materialized_as_dest_native_exfat() {
        let normalized = normalized_ntfs_with_compressed_payload();
        assert!(matches!(
            plan_lossless_ntfs_to_exfat(
                &normalized,
                GuaranteeMode::Strict,
                NtfsToExfatOptions::default(),
                NtfsToExfatLimits::default(),
            ),
            Err(NtfsToExfatError::PreservationRefused { blockers })
                if blockers.contains(&PreservationField::Compression)
        ));

        let draft = draft_lossless_ntfs_to_exfat(
            &normalized,
            GuaranteeMode::Escrow,
            NtfsToExfatOptions::default(),
            NtfsToExfatLimits::default(),
        )
        .unwrap();
        assert!(
            draft
                .target_graph()
                .objects()
                .iter()
                .flat_map(|object| &object.streams)
                .any(|stream| !stream.flags.compressed
                    && stream.flags.compression_block_bytes == 8192)
        );

        let solved = solve_lossless_ntfs_to_exfat(draft, LayoutLimits::default()).unwrap();
        assert!(solved.layout().relocations.is_empty());
        assert_eq!(solved.layout().materializations.len(), 1);
        assert_eq!(solved.layout().materializations[0].destination.length, 4096);
        assert!(solved
            .target_graph()
            .objects()
            .iter()
            .flat_map(|object| &object.streams)
            .all(|stream| stream.flags.compression_block_bytes == 0 && !stream.flags.compressed));
    }

    #[test]
    fn exfat_bad_clusters_are_reserved_on_the_ntfs_destination() {
        let mut normalized = normalized_exfat();
        normalized
            .preservation
            .filesystem_extents
            .push(crate::extent::Extent {
                stream: StreamId(998),
                logical_offset: 0,
                length: 4096,
                placement: Placement::Physical {
                    byte_offset: 30 * 1024 * 1024,
                },
                kind: ExtentKind::BadCluster,
            });
        normalized.preservation.allocated_bad_clusters = 1;
        assert!(
            evaluate_exfat(
                &normalized,
                FileSystem::Ntfs,
                GuaranteeMode::Escrow,
                PreservationLimits::default(),
            )
            .expect("consistent exact bad-cluster evidence")
            .permitted
        );

        let plan = plan_lossless_exfat_to_ntfs(
            &normalized,
            GuaranteeMode::Escrow,
            ExfatToNtfsOptions::default(),
            ExfatToNtfsLimits::default(),
        )
        .expect("consistent bad-cluster extents become dest-native $BadClus and $Bitmap marks");
        assert!(plan.destination.reservations.iter().any(|reservation| {
            reservation.kind == crate::geometry::ReservationKind::Other
                && reservation.range.offset == 30 * 1024 * 1024
                && reservation.range.length == 4096
        }));
    }

    #[test]
    fn exfat_bad_cluster_extent_cannot_bypass_guard_with_zero_reported_count() {
        let mut normalized = normalized_exfat();
        normalized
            .preservation
            .filesystem_extents
            .push(crate::extent::Extent {
                stream: StreamId(998),
                logical_offset: 0,
                length: 4096,
                placement: Placement::Physical {
                    byte_offset: 30 * 1024 * 1024,
                },
                kind: ExtentKind::BadCluster,
            });

        assert!(matches!(
            plan_lossless_exfat_to_ntfs(
                &normalized,
                GuaranteeMode::Escrow,
                ExfatToNtfsOptions::default(),
                ExfatToNtfsLimits::default(),
            ),
            Err(ExfatToNtfsError::InconsistentBadClusterEvidence {
                allocated_clusters: 0,
                bad_cluster_extents: 1,
            })
        ));
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

    fn empty_file(id: ObjectId, stream: StreamId) -> ObjectRecord {
        ObjectRecord {
            id,
            kind: ObjectKind::File,
            link_count: 1,
            semantics: ObjectSemantics::default(),
            streams: vec![ObjectStream {
                id: stream,
                name: None,
                logical_bytes: 0,
                initialized_bytes: 0,
                mapped_bytes: 0,
                allocated_bytes: 0,
                flags: StreamFlags::default(),
                storage: StreamStorage::Resident(Vec::new()),
            }],
        }
    }

    fn normalized_ntfs_with_case_colliding_files() -> NormalizedNtfs {
        let mut normalized = normalized_ntfs();
        let root = normalized.graph.root();
        let winner = ObjectId(27);
        let loser = ObjectId(28);
        let occupied = ObjectId(29);
        let timestamp = normalized.preservation.objects[1]
            .source
            .standard_information
            .unwrap()
            .creation_time;
        let objects = vec![
            normalized.graph.objects()[0].clone(),
            empty_file(winner, StreamId(27)),
            empty_file(loser, StreamId(28)),
            empty_file(occupied, StreamId(29)),
        ];
        normalized.graph = ObjectGraph::build(
            root,
            objects,
            vec![
                NamespaceEntry {
                    parent: root,
                    target: winner,
                    name: "ReadMe.txt".encode_utf16().collect(),
                },
                NamespaceEntry {
                    parent: root,
                    target: loser,
                    name: "README.TXT".encode_utf16().collect(),
                },
                NamespaceEntry {
                    parent: root,
                    target: occupied,
                    name: "README~2.TXT".encode_utf16().collect(),
                },
            ],
            normalized.graph.extents().clone(),
            ObjectGraphLimits {
                max_objects: 8,
                max_entries: 8,
                max_streams: 8,
                max_name_code_units: 255,
            },
        )
        .unwrap();
        normalized
            .preservation
            .objects
            .push(NtfsObjectPreservation {
                object: loser,
                source: ntfs_source_object(28, false, 0x21, timestamp),
            });
        normalized
            .preservation
            .objects
            .push(NtfsObjectPreservation {
                object: occupied,
                source: ntfs_source_object(29, false, 0x21, timestamp),
            });
        normalized
    }

    #[test]
    fn escrow_ntfs_case_collisions_are_disambiguated_without_clobbering_siblings() {
        let normalized = normalized_ntfs_with_case_colliding_files();
        let strict = plan_lossless_ntfs_to_exfat(
            &normalized,
            GuaranteeMode::Strict,
            NtfsToExfatOptions::default(),
            NtfsToExfatLimits::default(),
        );
        assert!(matches!(
            strict,
            Err(NtfsToExfatError::PreservationRefused { blockers })
                if blockers.contains(&PreservationField::NamesAndCase)
        ));
        let plan = plan_lossless_ntfs_to_exfat(
            &normalized,
            GuaranteeMode::Escrow,
            NtfsToExfatOptions::default(),
            NtfsToExfatLimits::default(),
        )
        .unwrap();
        assert_eq!(
            plan.preservation
                .assessments
                .iter()
                .find(|assessment| assessment.field == PreservationField::NamesAndCase)
                .map(|assessment| assessment.disposition),
            Some(FieldDisposition::EscrowRequired)
        );
        let mut names: Vec<Vec<u16>> = plan
            .target_graph
            .entries()
            .iter()
            .map(|entry| entry.name.clone())
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                "README~2.TXT".encode_utf16().collect::<Vec<u16>>(),
                "README~3.TXT".encode_utf16().collect::<Vec<u16>>(),
                "ReadMe.txt".encode_utf16().collect::<Vec<u16>>(),
            ]
        );
        let table =
            generate_recommended_exfat_upcase(RecommendedExfatUpcaseLimits::default()).unwrap();
        let folded: BTreeSet<Vec<u16>> = plan
            .target_graph
            .entries()
            .iter()
            .map(|entry| {
                entry
                    .name
                    .iter()
                    .map(|unit| table.map(*unit))
                    .collect::<Vec<u16>>()
            })
            .collect();
        assert_eq!(folded.len(), 3);
        assert_eq!(plan.object_metadata.len(), 3);
    }

    fn symlink_reparse_payload() -> Vec<u8> {
        let mut payload = vec![0_u8; 16];
        payload[..4].copy_from_slice(&0xa000_000c_u32.to_le_bytes());
        payload[4..6].copy_from_slice(&8_u16.to_le_bytes());
        payload
    }

    fn normalized_ntfs_with_reparse_point() -> (NormalizedNtfs, Vec<u8>) {
        let mut normalized = normalized_ntfs();
        let file = ObjectId(27);
        let mut objects = normalized.graph.objects().to_vec();
        for object in &mut objects {
            if object.id == file {
                object.semantics.is_reparse_point = true;
            }
        }
        normalized.graph = ObjectGraph::build(
            normalized.graph.root(),
            objects,
            normalized.graph.entries().to_vec(),
            normalized.graph.extents().clone(),
            ObjectGraphLimits {
                max_objects: 4,
                max_entries: 4,
                max_streams: 4,
                max_name_code_units: 255,
            },
        )
        .unwrap();
        let payload = symlink_reparse_payload();
        let preserved = normalized
            .preservation
            .objects
            .iter_mut()
            .find(|object| object.object == file)
            .unwrap();
        preserved.source.has_reparse_point = true;
        preserved.source.reparse_point = Some(payload.clone());
        preserved
            .source
            .standard_information
            .as_mut()
            .unwrap()
            .file_attributes |= 0x400;
        preserved
            .source
            .attribute_census
            .push(NtfsAttributeEvidence {
                attribute_type: 0xc0,
                name: None,
                flags_raw: 0,
                flags_unknown_bits: 0,
                attribute_id: 8,
                resident: true,
            });
        (normalized, payload)
    }

    #[test]
    fn escrow_ntfs_reparse_points_project_without_dest_semantics() {
        let (normalized, payload) = normalized_ntfs_with_reparse_point();
        let strict = plan_lossless_ntfs_to_exfat(
            &normalized,
            GuaranteeMode::Strict,
            NtfsToExfatOptions::default(),
            NtfsToExfatLimits::default(),
        );
        assert!(matches!(
            strict,
            Err(NtfsToExfatError::PreservationRefused { blockers })
                if blockers.contains(&PreservationField::ReparsePoints)
        ));
        let plan = plan_lossless_ntfs_to_exfat(
            &normalized,
            GuaranteeMode::Escrow,
            NtfsToExfatOptions::default(),
            NtfsToExfatLimits::default(),
        )
        .unwrap();
        assert_eq!(
            plan.preservation
                .assessments
                .iter()
                .find(|assessment| assessment.field == PreservationField::ReparsePoints)
                .map(|assessment| assessment.disposition),
            Some(FieldDisposition::EscrowRequired)
        );
        assert!(
            plan.target_graph
                .objects()
                .iter()
                .all(|object| !object.semantics.is_reparse_point)
        );
        assert_eq!(
            plan.object_metadata
                .iter()
                .find(|item| item.object == ObjectId(27))
                .map(|item| item.file_attributes),
            Some(0x21)
        );
        let escrow = plan.preservation.escrow.as_ref().expect("escrow");
        assert!(
            escrow
                .windows(payload.len())
                .any(|window| window == payload)
        );
    }
}
