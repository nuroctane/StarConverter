//! Pure, deterministic NTFS 3.1 destination-image planning.
//!
//! This module deliberately has no I/O and no device API.  It converts a validated
//! [`ObjectGraph`] into sector-aligned replacement ranges plus the exact source allocations and
//! destination reservations needed by the geometry solver.  The current writer is a conservative
//! *structural draft*: every emitted boot sector, FILE record, attribute and resident `$I30` index
//! is accepted by `StarConverter`'s independent parsers, but the plan is not activation-approved
//! until the remaining mandatory system files and external interoperability evidence are
//! implemented. `$AttrDef`, empty `$BadClus:$Bad`, the initial `$Secure` payload, and the narrow
//! `$Extend`/`$Quota`/`$ObjId`/`$Reparse` bootstrap emitted here are pinned to independently
//! validated NTFS-3G formatter precedent; they are not claimed to be a modern Windows-native
//! formatter profile.
//!
//! The supported object subset is intentionally narrow: one namespace link per non-root object,
//! no security/reparse semantics, no named/sparse/compressed/encrypted streams, resident unnamed
//! data that fits its FILE record, or cluster-aligned physical unnamed data extents. Directories
//! must fit a resident or single-level spilled `$I30` tree. Refusal is preferable to silently
//! weakening semantics.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::extent::{ExtentKind, Placement, StreamId};
use crate::fs::ntfs_essential::{
    AttrDefLimits, BadClusLimits, EmptyBadClusPlan, NTFS3X_ATTRDEF_BYTES, generate_ntfs3x_attrdef,
    plan_empty_badclus,
};
use crate::fs::ntfs_extend::{
    ExtendIndexSpec, ExtendRecordSpec, NtfsExtendActivationGap, NtfsExtendLimits,
    NtfsExtendMetadata, NtfsExtendProfile, QuotaChangeTimes, generate_ntfs3g_extend_metadata,
};
use crate::fs::ntfs_index::{FileNameNamespace, NtfsFileReference};
use crate::fs::ntfs_index_serialize::{
    NtfsDirectoryIndexEntry, NtfsDirectoryIndexError, NtfsDirectoryIndexGeometry,
    NtfsDirectoryIndexLimits, SerializedNtfsDirectoryIndex, serialize_ntfs_directory_index,
    validate_serialized_ntfs_directory_index,
};
use crate::fs::ntfs_logfile::{
    NTFS_LOGFILE_MIN_BYTES, NtfsLogFileConfig, NtfsLogFileLimits, NtfsLogFileProfile,
    generate_ntfs_logfile,
};
use crate::fs::ntfs_secure::{
    NtfsSecureLimits, NtfsSecureMetadata, NtfsSecureProfile, generate_ntfs_secure_metadata,
};
use crate::fs::ntfs_upcase_serialize::{
    NtfsUpcaseError, NtfsUpcaseLimits, NtfsUpcaseTable, generate_ntfs3g_windows61_upcase,
};
use crate::geometry::{ByteRange, DestinationReservation, ReservationKind, SourceAllocation};
use crate::object::{
    NamespaceEntry, ObjectGraph, ObjectId, ObjectKind, ObjectRecord, ObjectStream, StreamStorage,
};
use crate::overlay::OverlayWrite;

const SECTOR_BYTES: u64 = 512;
const RECORD_BYTES: usize = 1024;
const INDEX_BLOCK_BYTES: u64 = 4096;
const FIRST_USER_RECORD: u64 = 27;
const SYSTEM_RECORDS: usize = 12;
const FILE_RECORD_IN_USE: u16 = 0x0001;
const FILE_RECORD_DIRECTORY: u16 = 0x0002;
const STANDARD_INFORMATION: u32 = 0x10;
const FILE_NAME: u32 = 0x30;
const VOLUME_NAME: u32 = 0x60;
const VOLUME_INFORMATION: u32 = 0x70;
const DATA: u32 = 0x80;
const INDEX_ROOT: u32 = 0x90;
const INDEX_ALLOCATION: u32 = 0xa0;
const BITMAP: u32 = 0xb0;
const END_ATTRIBUTE: u32 = u32::MAX;
const FILE_ATTRIBUTE_HIDDEN: u32 = 0x0002;
const FILE_ATTRIBUTE_SYSTEM: u32 = 0x0004;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0010;
const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x0020;
const FILE_ATTRIBUTE_VIEW_INDEX_PRESENT: u32 = 0x1000_0000;
const MFT_LCN: u64 = 4;
const BOOT_FILE_BYTES: u64 = 8192;
const MIN_MFT_BITMAP_BYTES: u64 = 8;
const USA_OFFSET: usize = 48;
const ATTRIBUTES_OFFSET: usize = 56;
const USA_VALUE: u16 = 0xa55a;
/// Pinned NTFS-3G `$Secure` descriptor used for ordinary read/write objects.
pub const NTFS3G_SECURITY_ID_READ_WRITE: u32 = 0x101;
const ACTIVATION_GAPS: &[&str] = &[
    "$LogFile uses the pinned NTFS-3G erased clean profile, not a verified modern Windows-native profile",
    "$Secure uses a pinned NTFS-3G Windows-2003-era profile, not a verified modern Windows-native profile",
    "$Extend uses a pinned NTFS-3G bootstrap profile whose exact bytes are not specified by Microsoft",
    "$Extend case-sensitivity semantics remain a FIXME in the pinned formatter profile",
    "$UsnJrnl is omitted and modern $RmMetadata variants are not modeled",
    "directory indexes requiring internal INDX levels are not modeled",
    "external Windows chkdsk/mount interoperability has not been proven",
];

const STRUCTURAL_ACTIVATION_GAPS: &[&str] = &[
    "per-object NTFS timestamps and DOS attributes were synthesized by the structural compatibility wrapper",
    "$LogFile uses the pinned NTFS-3G erased clean profile, not a verified modern Windows-native profile",
    "$Secure uses a pinned NTFS-3G Windows-2003-era profile, not a verified modern Windows-native profile",
    "$Extend uses a pinned NTFS-3G bootstrap profile whose exact bytes are not specified by Microsoft",
    "$Extend case-sensitivity semantics remain a FIXME in the pinned formatter profile",
    "$UsnJrnl is omitted and modern $RmMetadata variants are not modeled",
    "directory indexes requiring internal INDX levels are not modeled",
    "external Windows chkdsk/mount interoperability has not been proven",
];

const EXTEND_ACTIVATION_GAPS: &[NtfsExtendActivationGap] = &[
    NtfsExtendActivationGap::MicrosoftDoesNotSpecifyBootstrapBytes,
    NtfsExtendActivationGap::CaseSensitivityMarkedFixmeByFormatter,
    NtfsExtendActivationGap::UsnJournalOmittedByPinnedProfile,
    NtfsExtendActivationGap::ModernResourceManagerMetadataNotModeled,
    NtfsExtendActivationGap::NativeChkdskAndMountValidationMissing,
];

/// Deterministic caller inputs. No value is obtained from ambient time or randomness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtfsDestinationInputs {
    /// Complete partition-image length, including the final backup-boot sector.
    pub image_bytes: u64,
    /// Absolute partition start LBA, serialized into the NTFS BPB hidden-sectors field.
    pub partition_offset_sectors: u64,
    pub cluster_bytes: u32,
    pub volume_serial_number: u64,
    /// NTFS timestamp (100 ns ticks since 1601) used for every synthesized metadata timestamp.
    pub timestamp: u64,
}

/// Exact volume metadata supplied independently from the neutral object graph.
///
/// `None` proves and preserves label absence. `Some(&[])` deliberately emits a present,
/// zero-length resident `$VOLUME_NAME`, keeping that state distinct from absence.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NtfsVolumeProfile<'a> {
    pub volume_label: Option<&'a [u16]>,
}

/// The four timestamps stored by both `$STANDARD_INFORMATION` and `$FILE_NAME`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtfsObjectTimestamps {
    pub creation_time: u64,
    pub modification_time: u64,
    pub mft_change_time: u64,
    pub access_time: u64,
}

impl NtfsObjectTimestamps {
    const fn uniform(timestamp: u64) -> Self {
        Self {
            creation_time: timestamp,
            modification_time: timestamp,
            mft_change_time: timestamp,
            access_time: timestamp,
        }
    }
}

/// Exact destination metadata for one neutral object.
///
/// Callers must provide exactly one entry for every object, including the root. `object_kind` and
/// the DOS directory bit are redundant on purpose: disagreement is refused before any bytes are
/// planned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtfsObjectMetadata {
    pub object: ObjectId,
    pub object_kind: ObjectKind,
    pub timestamps: NtfsObjectTimestamps,
    pub dos_file_attributes: u32,
    /// `$Secure` identifier. The current profile accepts only its pinned ordinary read/write
    /// descriptor because exFAT supplies no ACL semantics from which to infer another descriptor.
    pub security_id: u32,
}

/// Caller-controlled work and output bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtfsSerializeLimits {
    pub max_objects: usize,
    pub max_entries: usize,
    pub max_extents: usize,
    pub max_metadata_bytes: usize,
    pub max_resident_data_bytes: usize,
    /// Maximum leaf `INDX` records across any one directory.
    pub max_index_blocks: usize,
    /// Maximum `INDEX_ALLOCATION` bytes across any one directory.
    pub max_index_allocation_bytes: usize,
}

impl Default for NtfsSerializeLimits {
    fn default() -> Self {
        Self {
            max_objects: 1_000_000,
            max_entries: 1_000_000,
            max_extents: 8_000_000,
            max_metadata_bytes: 512 * 1024 * 1024,
            max_resident_data_bytes: 640,
            max_index_blocks: 65_536,
            max_index_allocation_bytes: 256 * 1024 * 1024,
        }
    }
}

/// Stable mapping between a normalized identity and its destination MFT record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtfsObjectPlacement {
    pub object: ObjectId,
    pub record_number: u64,
}

/// A pure destination proposal. `writes` are replacement bytes, not performed writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsDestinationPlan {
    pub image_bytes: u64,
    pub cluster_bytes: u32,
    pub mft_lcn: u64,
    pub mft_mirror_lcn: u64,
    /// Metadata which can be staged while the source primary boot sector remains untouched.
    pub staging_writes: Vec<OverlayWrite>,
    /// Backup boot sector installed before activation.
    pub backup_boot_write: OverlayWrite,
    /// Primary boot sector installed last to activate the candidate filesystem.
    pub primary_boot_write: OverlayWrite,
    pub reservations: Vec<DestinationReservation>,
    pub source_allocations: Vec<SourceAllocation>,
    pub object_placements: Vec<NtfsObjectPlacement>,
    exact_object_metadata: bool,
}

impl NtfsDestinationPlan {
    /// Activation is intentionally gated until all mandatory NTFS system streams are canonical.
    #[must_use]
    pub const fn activation_ready(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn activation_gaps(&self) -> &'static [&'static str] {
        if self.exact_object_metadata {
            ACTIVATION_GAPS
        } else {
            STRUCTURAL_ACTIVATION_GAPS
        }
    }

    /// Typed `$Extend` evidence gaps which remain after this serializer supplies the FILE and
    /// directory-entry wrappers omitted by the independently validated profile module.
    #[must_use]
    pub const fn extend_activation_gaps(&self) -> &'static [NtfsExtendActivationGap] {
        EXTEND_ACTIVATION_GAPS
    }
}

/// Exact refusal reason for the strict first serializer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NtfsSerializeError {
    InvalidLimit {
        field: &'static str,
    },
    ObjectLimitExceeded {
        actual: usize,
        maximum: usize,
    },
    MetadataEntryLimitExceeded {
        actual: usize,
        maximum: usize,
    },
    MissingObjectMetadata {
        object: ObjectId,
    },
    DuplicateObjectMetadata {
        object: ObjectId,
    },
    UnknownObjectMetadata {
        object: ObjectId,
    },
    ObjectMetadataKindMismatch {
        object: ObjectId,
        expected: ObjectKind,
        actual: ObjectKind,
    },
    ObjectMetadataAttributesMismatch {
        object: ObjectId,
        kind: ObjectKind,
        attributes: u32,
    },
    ObjectMetadataSecurityProfileMismatch {
        object: ObjectId,
        security_id: u32,
    },
    EntryLimitExceeded {
        actual: usize,
        maximum: usize,
    },
    ExtentLimitExceeded {
        actual: usize,
        maximum: usize,
    },
    SourceVolumeMismatch {
        graph_bytes: u64,
        image_bytes: u64,
    },
    InvalidImageGeometry,
    PartitionOffsetTooLarge {
        sectors: u64,
    },
    InvalidVolumeLabel {
        reason: &'static str,
    },
    /// Retained for API compatibility with older planners that stopped at 4 KiB clusters.
    UnsupportedDirectoryIndexGeometry {
        cluster_bytes: u32,
    },
    VolumeTooSmall {
        required: u64,
        actual: u64,
    },
    ArithmeticOverflow,
    AllocationFailed,
    UnsupportedObjectSemantics {
        object: ObjectId,
    },
    UnsupportedHardLink {
        object: ObjectId,
        links: u32,
    },
    UnsupportedNamedStream {
        object: ObjectId,
        stream: StreamId,
    },
    UnsupportedStreamFlags {
        object: ObjectId,
        stream: StreamId,
    },
    MultipleStreams {
        object: ObjectId,
    },
    UnsupportedDirectoryStream {
        object: ObjectId,
        stream: StreamId,
    },
    InvalidName {
        target: ObjectId,
    },
    ReservedRootName {
        target: ObjectId,
    },
    CaseCollision {
        parent: ObjectId,
    },
    UnalignedExtent {
        stream: StreamId,
        offset: u64,
        length: u64,
    },
    SparseExtent {
        stream: StreamId,
    },
    NonemptyBadClustersUnsupported {
        extents: usize,
    },
    ExtentOutsideNtfsClusters {
        stream: StreamId,
    },
    PayloadMetadataConflict {
        stream: StreamId,
        offset: u64,
    },
    ResidentDataTooLarge {
        stream: StreamId,
        actual: usize,
        maximum: usize,
    },
    MappingPairsTooLarge {
        stream: StreamId,
    },
    RecordOverflow {
        record_number: u64,
    },
    DirectoryIndexOverflow {
        object: ObjectId,
    },
    DirectoryIndex {
        object: ObjectId,
        source: NtfsDirectoryIndexError,
    },
    MetadataLimitExceeded {
        actual: u64,
        maximum: usize,
    },
    MandatoryMetadata {
        component: &'static str,
        reason: String,
    },
    Upcase {
        source: NtfsUpcaseError,
    },
}

impl fmt::Display for NtfsSerializeError {
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit { field } => write!(f, "NTFS serializer limit {field} is zero"),
            Self::ObjectLimitExceeded { actual, maximum } => {
                write!(f, "object count {actual} exceeds {maximum}")
            }
            Self::MetadataEntryLimitExceeded { actual, maximum } => {
                write!(f, "object metadata count {actual} exceeds {maximum}")
            }
            Self::MissingObjectMetadata { object } => {
                write!(f, "object {} has no destination metadata", object.0)
            }
            Self::DuplicateObjectMetadata { object } => {
                write!(f, "object {} has duplicate destination metadata", object.0)
            }
            Self::UnknownObjectMetadata { object } => {
                write!(f, "destination metadata names unknown object {}", object.0)
            }
            Self::ObjectMetadataKindMismatch {
                object,
                expected,
                actual,
            } => write!(
                f,
                "object {} metadata kind {actual:?} does not match {expected:?}",
                object.0
            ),
            Self::ObjectMetadataAttributesMismatch {
                object,
                kind,
                attributes,
            } => write!(
                f,
                "object {} {kind:?} has kind-inconsistent DOS attributes {attributes:#x}",
                object.0
            ),
            Self::ObjectMetadataSecurityProfileMismatch {
                object,
                security_id,
            } => write!(
                f,
                "object {} security ID {security_id:#x} is not the pinned ordinary read/write `$Secure` descriptor {NTFS3G_SECURITY_ID_READ_WRITE:#x}",
                object.0
            ),
            Self::EntryLimitExceeded { actual, maximum } => {
                write!(f, "entry count {actual} exceeds {maximum}")
            }
            Self::ExtentLimitExceeded { actual, maximum } => {
                write!(f, "extent count {actual} exceeds {maximum}")
            }
            Self::SourceVolumeMismatch {
                graph_bytes,
                image_bytes,
            } => write!(
                f,
                "object graph covers {graph_bytes} bytes but destination image has {image_bytes}"
            ),
            Self::InvalidImageGeometry => {
                f.write_str("image/cluster geometry cannot encode the supported NTFS layout")
            }
            Self::PartitionOffsetTooLarge { sectors } => write!(
                f,
                "partition offset {sectors} sectors exceeds the NTFS BPB hidden-sectors field"
            ),
            Self::InvalidVolumeLabel { reason } => {
                write!(f, "invalid exact NTFS volume label: {reason}")
            }
            Self::UnsupportedDirectoryIndexGeometry { cluster_bytes } => write!(
                f,
                "{cluster_bytes}-byte clusters have unsupported directory-index geometry"
            ),
            Self::VolumeTooSmall { required, actual } => write!(
                f,
                "NTFS metadata requires {required} bytes, image has {actual}"
            ),
            Self::ArithmeticOverflow => f.write_str("NTFS serialization arithmetic overflow"),
            Self::AllocationFailed => {
                f.write_str("could not allocate bounded NTFS serialization state")
            }
            Self::UnsupportedObjectSemantics { object } => write!(
                f,
                "object {} has unsupported security or reparse semantics",
                object.0
            ),
            Self::UnsupportedHardLink { object, links } => write!(
                f,
                "object {} has {links} links; only one is supported",
                object.0
            ),
            Self::UnsupportedNamedStream { object, stream } => {
                write!(f, "object {} stream {} is named", object.0, stream.0)
            }
            Self::UnsupportedStreamFlags { object, stream } => write!(
                f,
                "object {} stream {} is sparse, compressed, or encrypted",
                object.0, stream.0
            ),
            Self::MultipleStreams { object } => {
                write!(f, "object {} has more than one stream", object.0)
            }
            Self::UnsupportedDirectoryStream { object, stream } => write!(
                f,
                "directory {} stream {} is not extent-backed directory metadata",
                object.0, stream.0
            ),
            Self::InvalidName { target } => write!(
                f,
                "object {} has a name outside the strict NTFS subset",
                target.0
            ),
            Self::ReservedRootName { target } => write!(
                f,
                "object {} collides with a reserved NTFS root metadata name",
                target.0
            ),
            Self::CaseCollision { parent } => {
                write!(f, "directory {} has case-colliding names", parent.0)
            }
            Self::UnalignedExtent {
                stream,
                offset,
                length,
            } => write!(
                f,
                "stream {} extent {offset}+{length} is not cluster aligned",
                stream.0
            ),
            Self::SparseExtent { stream } => write!(f, "stream {} has a sparse extent", stream.0),
            Self::NonemptyBadClustersUnsupported { extents } => write!(
                f,
                "source has {extents} bad-cluster extents; the canonical empty `$BadClus:$Bad` plan cannot preserve them"
            ),
            Self::ExtentOutsideNtfsClusters { stream } => write!(
                f,
                "stream {} extent is outside addressable NTFS clusters",
                stream.0
            ),
            Self::PayloadMetadataConflict { stream, offset } => write!(
                f,
                "stream {} at {offset} conflicts with fixed destination metadata; runlists cannot be emitted until a relocation map is supplied",
                stream.0
            ),
            Self::ResidentDataTooLarge {
                stream,
                actual,
                maximum,
            } => write!(
                f,
                "resident stream {} has {actual} bytes, exceeding {maximum}",
                stream.0
            ),
            Self::MappingPairsTooLarge { stream } => write!(
                f,
                "stream {} mapping pairs do not fit one FILE record",
                stream.0
            ),
            Self::RecordOverflow { record_number } => write!(
                f,
                "MFT record {record_number} does not fit {RECORD_BYTES} bytes"
            ),
            Self::DirectoryIndexOverflow { object } => write!(
                f,
                "directory {} requires INDEX_ALLOCATION, outside the current subset",
                object.0
            ),
            Self::DirectoryIndex { object, source } => {
                write!(
                    f,
                    "could not serialize directory {} `$I30`: {source}",
                    object.0
                )
            }
            Self::MetadataLimitExceeded { actual, maximum } => {
                write!(f, "metadata plan is {actual} bytes, exceeding {maximum}")
            }
            Self::MandatoryMetadata { component, reason } => {
                write!(f, "could not construct canonical {component}: {reason}")
            }
            Self::Upcase { source } => write!(f, "could not construct pinned `$UpCase`: {source}"),
        }
    }
}

impl std::error::Error for NtfsSerializeError {}

#[derive(Debug, Clone, Copy)]
struct MetadataLayout {
    cluster: u64,
    cluster_count: u64,
    record_count: usize,
    mft_clusters: u64,
    mirror_lcn: u64,
    mirror_clusters: u64,
    logfile_lcn: u64,
    logfile_clusters: u64,
    attrdef_lcn: u64,
    attrdef_clusters: u64,
    secure_sds_lcn: u64,
    secure_sds_bytes: u64,
    secure_sds_clusters: u64,
    bitmap_lcn: u64,
    bitmap_clusters: u64,
    upcase_lcn: u64,
    upcase_clusters: u64,
    mft_bitmap_lcn: u64,
    mft_bitmap_bytes: u64,
    mft_bitmap_clusters: u64,
    directory_indexes_lcn: u64,
    directory_index_clusters: u64,
    metadata_clusters: u64,
}

#[derive(Debug)]
struct MandatoryMetadata {
    logfile: Vec<u8>,
    attrdef: Vec<u8>,
    badclus: EmptyBadClusPlan,
    secure: NtfsSecureMetadata,
    extend: NtfsExtendMetadata,
}

fn mandatory_metadata(
    cluster_count: u64,
    cluster_bytes: u32,
    timestamp: u64,
    maximum_bytes: usize,
) -> Result<MandatoryMetadata, NtfsSerializeError> {
    // Prove the containing-volume geometry before allocating any payload buffer.
    let badclus = plan_empty_badclus(
        cluster_count,
        cluster_bytes,
        BadClusLimits {
            max_volume_clusters: cluster_count,
            max_mapping_pairs_bytes: 32,
        },
    )
    .map_err(|error| NtfsSerializeError::MandatoryMetadata {
        component: "$BadClus:$Bad",
        reason: error.to_string(),
    })?;
    let logfile = generate_ntfs_logfile(
        NtfsLogFileProfile::Ntfs3gErased,
        NtfsLogFileConfig::ntfs31_lfs_v1_1(NTFS_LOGFILE_MIN_BYTES, 0),
        NtfsLogFileLimits {
            max_bytes: maximum_bytes,
        },
    )
    .map_err(|error| NtfsSerializeError::MandatoryMetadata {
        component: "$LogFile",
        reason: error.to_string(),
    })?;
    let attrdef = generate_ntfs3x_attrdef(AttrDefLimits {
        max_bytes: maximum_bytes,
        max_entries: 32,
    })
    .map_err(|error| NtfsSerializeError::MandatoryMetadata {
        component: "$AttrDef",
        reason: error.to_string(),
    })?;
    let secure = generate_ntfs_secure_metadata(
        NtfsSecureProfile::MkntfsWindows2003Ntfs31,
        NtfsSecureLimits {
            max_sds_bytes: maximum_bytes,
            max_index_bytes: 64 * 1024,
            max_descriptors: 2,
            max_descriptor_bytes: 0x68,
        },
    )
    .map_err(|error| NtfsSerializeError::MandatoryMetadata {
        component: "$Secure",
        reason: error.to_string(),
    })?;
    let extend_timestamp =
        i64::try_from(timestamp).map_err(|_| NtfsSerializeError::MandatoryMetadata {
            component: "$Extend",
            reason: "NTFS timestamp exceeds the pinned formatter's signed timestamp domain"
                .to_owned(),
        })?;
    let extend = generate_ntfs3g_extend_metadata(
        NtfsExtendProfile::MkntfsNtfs31,
        QuotaChangeTimes {
            defaults: extend_timestamp,
            administrators: extend_timestamp,
        },
        NtfsExtendLimits::default(),
    )
    .map_err(|error| NtfsSerializeError::MandatoryMetadata {
        component: "$Extend",
        reason: error.to_string(),
    })?;
    Ok(MandatoryMetadata {
        logfile,
        attrdef,
        badclus,
        secure,
        extend,
    })
}

#[derive(Debug, Clone)]
struct PlannedDirectoryIndex {
    object: ObjectId,
    record_number: u64,
    serialized: SerializedNtfsDirectoryIndex,
    allocation_lcn: Option<u64>,
    allocation_clusters: u64,
}

/// Builds a deterministic, non-mutating structural NTFS destination proposal.
///
/// This compatibility wrapper synthesizes uniform per-object metadata and therefore can never
/// produce an activation-ready plan. New conversion code must call
/// [`plan_ntfs_destination_with_metadata`] with exact preservation evidence.
///
/// # Errors
/// Returns the same bounded structural refusals as [`plan_ntfs_destination_with_metadata`].
pub fn plan_ntfs_destination(
    graph: &ObjectGraph,
    inputs: NtfsDestinationInputs,
    limits: NtfsSerializeLimits,
) -> Result<NtfsDestinationPlan, NtfsSerializeError> {
    let metadata: Vec<_> = graph
        .objects()
        .iter()
        .map(|object| NtfsObjectMetadata {
            object: object.id,
            object_kind: object.kind,
            timestamps: NtfsObjectTimestamps::uniform(inputs.timestamp),
            dos_file_attributes: match object.kind {
                ObjectKind::Directory => FILE_ATTRIBUTE_DIRECTORY,
                ObjectKind::File => FILE_ATTRIBUTE_ARCHIVE,
            },
            security_id: NTFS3G_SECURITY_ID_READ_WRITE,
        })
        .collect();
    plan_ntfs_destination_impl(
        graph,
        inputs,
        &metadata,
        NtfsVolumeProfile::default(),
        limits,
        false,
    )
}

/// Builds a deterministic, non-mutating NTFS destination proposal with exact object metadata.
///
/// # Errors
/// Refuses invalid/capped geometry, unsupported semantics, non-cluster-aligned physical payloads,
/// metadata conflicts, names which cannot be represented by the strict subset, or FILE/index-root
/// values which do not fit their bounded resident containers. A future relocation-aware second
/// pass must rewrite mapping pairs before conflicting payload can be accepted.
pub fn plan_ntfs_destination_with_metadata(
    graph: &ObjectGraph,
    inputs: NtfsDestinationInputs,
    metadata: &[NtfsObjectMetadata],
    limits: NtfsSerializeLimits,
) -> Result<NtfsDestinationPlan, NtfsSerializeError> {
    plan_ntfs_destination_with_metadata_and_volume(
        graph,
        inputs,
        metadata,
        NtfsVolumeProfile::default(),
        limits,
    )
}

/// Builds a deterministic NTFS proposal with exact object and volume metadata.
///
/// This is the lossless adapter entry point. It preserves proven volume-label absence separately
/// from a present empty label and refuses malformed or overlong UTF-16 before allocating the
/// destination metadata image.
///
/// # Errors
///
/// Returns the structural errors documented by [`plan_ntfs_destination_with_metadata`] and
/// [`NtfsSerializeError::InvalidVolumeLabel`] for invalid volume identity evidence.
pub fn plan_ntfs_destination_with_metadata_and_volume(
    graph: &ObjectGraph,
    inputs: NtfsDestinationInputs,
    metadata: &[NtfsObjectMetadata],
    volume: NtfsVolumeProfile<'_>,
    limits: NtfsSerializeLimits,
) -> Result<NtfsDestinationPlan, NtfsSerializeError> {
    plan_ntfs_destination_impl(graph, inputs, metadata, volume, limits, true)
}

#[allow(clippy::too_many_lines)]
fn plan_ntfs_destination_impl(
    graph: &ObjectGraph,
    inputs: NtfsDestinationInputs,
    metadata: &[NtfsObjectMetadata],
    volume: NtfsVolumeProfile<'_>,
    limits: NtfsSerializeLimits,
    exact_object_metadata: bool,
) -> Result<NtfsDestinationPlan, NtfsSerializeError> {
    validate_limits(limits)?;
    validate_volume_profile(volume)?;
    if graph.objects().len() > limits.max_objects {
        return Err(NtfsSerializeError::ObjectLimitExceeded {
            actual: graph.objects().len(),
            maximum: limits.max_objects,
        });
    }
    if graph.entries().len() > limits.max_entries {
        return Err(NtfsSerializeError::EntryLimitExceeded {
            actual: graph.entries().len(),
            maximum: limits.max_entries,
        });
    }
    if graph.extents().extents().len() > limits.max_extents {
        return Err(NtfsSerializeError::ExtentLimitExceeded {
            actual: graph.extents().extents().len(),
            maximum: limits.max_extents,
        });
    }
    let bad_cluster_extents = graph
        .extents()
        .extents()
        .iter()
        .filter(|extent| extent.kind == ExtentKind::BadCluster)
        .count();
    if bad_cluster_extents != 0 {
        return Err(NtfsSerializeError::NonemptyBadClustersUnsupported {
            extents: bad_cluster_extents,
        });
    }
    if graph.extents().volume_bytes() != inputs.image_bytes {
        return Err(NtfsSerializeError::SourceVolumeMismatch {
            graph_bytes: graph.extents().volume_bytes(),
            image_bytes: inputs.image_bytes,
        });
    }
    if inputs.partition_offset_sectors > u64::from(u32::MAX) {
        return Err(NtfsSerializeError::PartitionOffsetTooLarge {
            sectors: inputs.partition_offset_sectors,
        });
    }
    let cluster = u64::from(inputs.cluster_bytes);
    if inputs.image_bytes < SECTOR_BYTES * 2
        || inputs.image_bytes % SECTOR_BYTES != 0
        || !(SECTOR_BYTES..=2 * 1024 * 1024).contains(&cluster)
        || !cluster.is_power_of_two()
        || cluster % SECTOR_BYTES != 0
        || cluster / SECTOR_BYTES > 128
        || MFT_LCN * cluster < BOOT_FILE_BYTES
    {
        return Err(NtfsSerializeError::InvalidImageGeometry);
    }
    let declared_sectors = inputs.image_bytes / SECTOR_BYTES - 1;
    let cluster_count = declared_sectors / (cluster / SECTOR_BYTES);
    if cluster_count <= MFT_LCN + 1 {
        return Err(NtfsSerializeError::InvalidImageGeometry);
    }
    let upcase = generate_ntfs3g_windows61_upcase(NtfsUpcaseLimits::default())
        .map_err(|source| NtfsSerializeError::Upcase { source })?;

    let mut objects: Vec<&ObjectRecord> = graph.objects().iter().collect();
    objects.sort_unstable_by_key(|object| object.id);
    validate_objects(&objects, graph, limits)?;
    validate_names(graph.entries(), &upcase)?;
    let metadata_by_object = validate_object_metadata(&objects, metadata, limits.max_objects)?;

    let mut placements = Vec::new();
    placements
        .try_reserve(objects.len())
        .map_err(|_| NtfsSerializeError::AllocationFailed)?;
    let mut record_by_object = BTreeMap::new();
    record_by_object.insert(graph.root(), 5_u64);
    placements.push(NtfsObjectPlacement {
        object: graph.root(),
        record_number: 5,
    });
    let mut next = FIRST_USER_RECORD;
    for object in &objects {
        if object.id == graph.root() {
            continue;
        }
        record_by_object.insert(object.id, next);
        placements.push(NtfsObjectPlacement {
            object: object.id,
            record_number: next,
        });
        next = next
            .checked_add(1)
            .ok_or(NtfsSerializeError::ArithmeticOverflow)?;
    }
    placements.sort_unstable_by_key(|value| value.object);
    let record_count = usize::try_from(next.max(FIRST_USER_RECORD))
        .map_err(|_| NtfsSerializeError::ArithmeticOverflow)?;
    let mandatory = mandatory_metadata(
        cluster_count,
        inputs.cluster_bytes,
        inputs.timestamp,
        limits.max_metadata_bytes,
    )?;
    let preliminary_layout = metadata_layout(
        cluster,
        cluster_count,
        record_count,
        mandatory.secure.sds.len(),
        0,
    )?;
    let children = index_children(graph.entries());
    let directory_indexes = plan_directory_indexes(
        &objects,
        &children,
        &record_by_object,
        graph,
        &metadata_by_object,
        preliminary_layout,
        inputs.timestamp,
        &upcase,
        limits,
    )?;
    let directory_index_clusters = directory_indexes.iter().try_fold(0_u64, |total, index| {
        total
            .checked_add(index.allocation_clusters)
            .ok_or(NtfsSerializeError::ArithmeticOverflow)
    })?;
    let layout = metadata_layout(
        cluster,
        cluster_count,
        record_count,
        mandatory.secure.sds.len(),
        directory_index_clusters,
    )?;
    if layout.directory_indexes_lcn != preliminary_layout.directory_indexes_lcn {
        return Err(NtfsSerializeError::ArithmeticOverflow);
    }
    if layout.directory_index_clusters != directory_index_clusters {
        return Err(NtfsSerializeError::ArithmeticOverflow);
    }
    let metadata_bytes = layout
        .metadata_clusters
        .checked_mul(cluster)
        .ok_or(NtfsSerializeError::ArithmeticOverflow)?;
    if metadata_bytes > inputs.image_bytes.saturating_sub(SECTOR_BYTES) {
        return Err(NtfsSerializeError::VolumeTooSmall {
            required: metadata_bytes + SECTOR_BYTES,
            actual: inputs.image_bytes,
        });
    }
    if usize::try_from(metadata_bytes).unwrap_or(usize::MAX) > limits.max_metadata_bytes {
        return Err(NtfsSerializeError::MetadataLimitExceeded {
            actual: metadata_bytes,
            maximum: limits.max_metadata_bytes,
        });
    }

    let source_allocations = collect_sources(graph, &layout)?;
    let directory_index_by_object: BTreeMap<_, _> = directory_indexes
        .iter()
        .map(|index| (index.object, index))
        .collect();
    let mut metadata = vec![
        0_u8;
        usize::try_from(metadata_bytes)
            .map_err(|_| NtfsSerializeError::ArithmeticOverflow)?
    ];
    let boot = boot_sector(inputs, layout)?;
    metadata[..boot.len()].copy_from_slice(&boot);

    let mut records = vec![vec![0_u8; RECORD_BYTES]; record_count];
    for (record_number, record) in records.iter_mut().enumerate() {
        *record = unused_record(
            u64::try_from(record_number).map_err(|_| NtfsSerializeError::ArithmeticOverflow)?,
        )?;
    }
    records[0] = system_mft_record(0, layout, inputs.timestamp)?;
    records[1] = system_data_record(
        1,
        "$MFTMirr",
        layout.mirror_lcn,
        layout.mirror_clusters,
        4096,
        layout.cluster,
        inputs.timestamp,
    )?;
    records[2] = system_data_record(
        2,
        "$LogFile",
        layout.logfile_lcn,
        layout.logfile_clusters,
        u64::try_from(mandatory.logfile.len())
            .map_err(|_| NtfsSerializeError::ArithmeticOverflow)?,
        layout.cluster,
        inputs.timestamp,
    )?;
    records[3] = volume_record(inputs.timestamp, volume.volume_label)?;
    records[4] = system_data_record(
        4,
        "$AttrDef",
        layout.attrdef_lcn,
        layout.attrdef_clusters,
        u64::try_from(mandatory.attrdef.len())
            .map_err(|_| NtfsSerializeError::ArithmeticOverflow)?,
        layout.cluster,
        inputs.timestamp,
    )?;
    let root_name = NamespaceEntry {
        parent: graph.root(),
        target: graph.root(),
        name: vec![u16::from(b'.')],
    };
    records[5] = build_directory_record(
        5,
        Some(&root_name),
        &record_by_object,
        metadata_by_object[&graph.root()],
        directory_index_by_object[&graph.root()],
        layout.cluster,
    )?;
    let bitmap_logical = layout.cluster_count.div_ceil(8);
    records[6] = system_data_record(
        6,
        "$Bitmap",
        layout.bitmap_lcn,
        layout.bitmap_clusters,
        bitmap_logical,
        layout.cluster,
        inputs.timestamp,
    )?;
    let boot_clusters = div_ceil(BOOT_FILE_BYTES, layout.cluster)?;
    records[7] = system_data_record(
        7,
        "$Boot",
        0,
        boot_clusters,
        BOOT_FILE_BYTES,
        layout.cluster,
        inputs.timestamp,
    )?;
    records[8] = badclus_record(8, &mandatory.badclus, inputs.timestamp)?;
    records[9] = secure_record(9, layout, &mandatory.secure, inputs.timestamp)?;
    records[10] = system_data_record(
        10,
        "$UpCase",
        layout.upcase_lcn,
        layout.upcase_clusters,
        65_536 * 2,
        layout.cluster,
        inputs.timestamp,
    )?;
    let [
        extend_record,
        quota_record,
        object_id_record,
        reparse_record,
    ] = extend_records(layout, &mandatory.extend, inputs.timestamp, &upcase)?;
    records[11] = extend_record;
    records[24] = quota_record;
    records[25] = object_id_record;
    records[26] = reparse_record;

    let entry_by_target: BTreeMap<ObjectId, &NamespaceEntry> = graph
        .entries()
        .iter()
        .map(|entry| (entry.target, entry))
        .collect();
    for object in &objects {
        if object.id == graph.root() {
            continue;
        }
        let record_number = record_by_object[&object.id];
        let entry = entry_by_target[&object.id];
        let record = match object.kind {
            ObjectKind::Directory => build_directory_record(
                record_number,
                Some(entry),
                &record_by_object,
                metadata_by_object[&object.id],
                directory_index_by_object[&object.id],
                layout.cluster,
            )?,
            ObjectKind::File => file_record(
                record_number,
                object,
                entry,
                &record_by_object,
                graph,
                layout,
                metadata_by_object[&object.id],
                limits,
            )?,
        };
        records[usize::try_from(record_number)
            .map_err(|_| NtfsSerializeError::ArithmeticOverflow)?] = record;
    }

    let mft_offset = usize::try_from(
        MFT_LCN
            .checked_mul(cluster)
            .ok_or(NtfsSerializeError::ArithmeticOverflow)?,
    )
    .map_err(|_| NtfsSerializeError::ArithmeticOverflow)?;
    for (index, record) in records.iter().enumerate() {
        let offset = mft_offset
            .checked_add(
                index
                    .checked_mul(RECORD_BYTES)
                    .ok_or(NtfsSerializeError::ArithmeticOverflow)?,
            )
            .ok_or(NtfsSerializeError::ArithmeticOverflow)?;
        metadata[offset..offset + RECORD_BYTES].copy_from_slice(record);
    }
    let mirror_offset = usize::try_from(layout.mirror_lcn * cluster)
        .map_err(|_| NtfsSerializeError::ArithmeticOverflow)?;
    let mirror_bytes = SYSTEM_RECORDS.min(4) * RECORD_BYTES;
    metadata.copy_within(mft_offset..mft_offset + mirror_bytes, mirror_offset);
    write_attrdef(&mut metadata, layout, &mandatory.attrdef)?;
    write_logfile(&mut metadata, layout, &mandatory.logfile)?;
    write_secure_sds(&mut metadata, layout, &mandatory.secure.sds)?;
    write_bitmap(&mut metadata, layout, graph)?;
    write_upcase(&mut metadata, layout, upcase.little_endian_bytes())?;
    write_mft_bitmap(&mut metadata, layout)?;
    for index in &directory_indexes {
        if let Some(lcn) = index.allocation_lcn {
            let offset = usize::try_from(
                lcn.checked_mul(layout.cluster)
                    .ok_or(NtfsSerializeError::ArithmeticOverflow)?,
            )
            .map_err(|_| NtfsSerializeError::ArithmeticOverflow)?;
            let end = offset
                .checked_add(index.serialized.index_allocation.len())
                .ok_or(NtfsSerializeError::ArithmeticOverflow)?;
            metadata
                .get_mut(offset..end)
                .ok_or(NtfsSerializeError::ArithmeticOverflow)?
                .copy_from_slice(&index.serialized.index_allocation);
        }
    }

    let backup_offset = inputs.image_bytes - SECTOR_BYTES;
    let staging_bytes = metadata.split_off(512);
    let staging_writes = vec![OverlayWrite {
        offset: SECTOR_BYTES,
        bytes: staging_bytes,
    }];
    let backup_boot_write = OverlayWrite {
        offset: backup_offset,
        bytes: boot.clone(),
    };
    let primary_boot_write = OverlayWrite {
        offset: 0,
        bytes: boot,
    };
    let reservations = vec![
        DestinationReservation {
            range: ByteRange {
                offset: 0,
                length: SECTOR_BYTES,
            },
            kind: ReservationKind::BootRegion,
        },
        DestinationReservation {
            range: ByteRange {
                offset: SECTOR_BYTES,
                length: metadata_bytes - SECTOR_BYTES,
            },
            kind: ReservationKind::NamespaceMetadata,
        },
        DestinationReservation {
            range: ByteRange {
                offset: backup_offset,
                length: SECTOR_BYTES,
            },
            kind: ReservationKind::BootRegion,
        },
    ];
    Ok(NtfsDestinationPlan {
        image_bytes: inputs.image_bytes,
        cluster_bytes: inputs.cluster_bytes,
        mft_lcn: MFT_LCN,
        mft_mirror_lcn: layout.mirror_lcn,
        staging_writes,
        backup_boot_write,
        primary_boot_write,
        reservations,
        source_allocations,
        object_placements: placements,
        exact_object_metadata,
    })
}

fn validate_limits(limits: NtfsSerializeLimits) -> Result<(), NtfsSerializeError> {
    for (field, value) in [
        ("max_objects", limits.max_objects),
        ("max_entries", limits.max_entries),
        ("max_extents", limits.max_extents),
        ("max_metadata_bytes", limits.max_metadata_bytes),
        ("max_resident_data_bytes", limits.max_resident_data_bytes),
        ("max_index_blocks", limits.max_index_blocks),
        (
            "max_index_allocation_bytes",
            limits.max_index_allocation_bytes,
        ),
    ] {
        if value == 0 {
            return Err(NtfsSerializeError::InvalidLimit { field });
        }
    }
    Ok(())
}

fn validate_volume_profile(volume: NtfsVolumeProfile<'_>) -> Result<(), NtfsSerializeError> {
    let Some(label) = volume.volume_label else {
        return Ok(());
    };
    if label.len() > 32 {
        return Err(NtfsSerializeError::InvalidVolumeLabel {
            reason: "more than 32 UTF-16 code units",
        });
    }
    if label.contains(&0) {
        return Err(NtfsSerializeError::InvalidVolumeLabel {
            reason: "contains a NUL code unit",
        });
    }
    if char::decode_utf16(label.iter().copied()).any(|character| character.is_err()) {
        return Err(NtfsSerializeError::InvalidVolumeLabel {
            reason: "contains unpaired UTF-16 surrogates",
        });
    }
    Ok(())
}

fn validate_object_metadata(
    objects: &[&ObjectRecord],
    metadata: &[NtfsObjectMetadata],
    maximum: usize,
) -> Result<BTreeMap<ObjectId, NtfsObjectMetadata>, NtfsSerializeError> {
    if metadata.len() > maximum {
        return Err(NtfsSerializeError::MetadataEntryLimitExceeded {
            actual: metadata.len(),
            maximum,
        });
    }
    let objects_by_id: BTreeMap<_, _> = objects
        .iter()
        .map(|object| (object.id, object.kind))
        .collect();
    let mut by_object = BTreeMap::new();
    for value in metadata {
        let Some(expected) = objects_by_id.get(&value.object).copied() else {
            return Err(NtfsSerializeError::UnknownObjectMetadata {
                object: value.object,
            });
        };
        if by_object.insert(value.object, *value).is_some() {
            return Err(NtfsSerializeError::DuplicateObjectMetadata {
                object: value.object,
            });
        }
        if value.object_kind != expected {
            return Err(NtfsSerializeError::ObjectMetadataKindMismatch {
                object: value.object,
                expected,
                actual: value.object_kind,
            });
        }
        let has_directory_flag = value.dos_file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0;
        if has_directory_flag != (expected == ObjectKind::Directory) {
            return Err(NtfsSerializeError::ObjectMetadataAttributesMismatch {
                object: value.object,
                kind: expected,
                attributes: value.dos_file_attributes,
            });
        }
        if value.security_id != NTFS3G_SECURITY_ID_READ_WRITE {
            return Err(NtfsSerializeError::ObjectMetadataSecurityProfileMismatch {
                object: value.object,
                security_id: value.security_id,
            });
        }
    }
    for object in objects {
        if !by_object.contains_key(&object.id) {
            return Err(NtfsSerializeError::MissingObjectMetadata { object: object.id });
        }
    }
    Ok(by_object)
}

fn validate_objects(
    objects: &[&ObjectRecord],
    graph: &ObjectGraph,
    limits: NtfsSerializeLimits,
) -> Result<(), NtfsSerializeError> {
    for object in objects {
        if object.semantics.has_security_descriptor || object.semantics.is_reparse_point {
            return Err(NtfsSerializeError::UnsupportedObjectSemantics { object: object.id });
        }
        if object.link_count > 1 {
            return Err(NtfsSerializeError::UnsupportedHardLink {
                object: object.id,
                links: object.link_count,
            });
        }
        if object.streams.len() > 1 {
            return Err(NtfsSerializeError::MultipleStreams { object: object.id });
        }
        for stream in &object.streams {
            if stream.name.is_some() {
                return Err(NtfsSerializeError::UnsupportedNamedStream {
                    object: object.id,
                    stream: stream.id,
                });
            }
            if stream.flags.sparse || stream.flags.compressed || stream.flags.encrypted {
                return Err(NtfsSerializeError::UnsupportedStreamFlags {
                    object: object.id,
                    stream: stream.id,
                });
            }
            if object.kind == ObjectKind::Directory
                && (!matches!(stream.storage, StreamStorage::Extents)
                    || graph
                        .extents()
                        .extents()
                        .iter()
                        .filter(|extent| extent.stream == stream.id)
                        .any(|extent| extent.kind != ExtentKind::DirectoryData))
            {
                return Err(NtfsSerializeError::UnsupportedDirectoryStream {
                    object: object.id,
                    stream: stream.id,
                });
            }
            if let StreamStorage::Resident(bytes) = &stream.storage {
                if bytes.len() > limits.max_resident_data_bytes {
                    return Err(NtfsSerializeError::ResidentDataTooLarge {
                        stream: stream.id,
                        actual: bytes.len(),
                        maximum: limits.max_resident_data_bytes,
                    });
                }
            }
        }
    }
    Ok(())
}

fn validate_names(
    entries: &[NamespaceEntry],
    upcase: &NtfsUpcaseTable,
) -> Result<(), NtfsSerializeError> {
    let mut folded = BTreeSet::new();
    for entry in entries {
        if entry.name.is_empty()
            || entry.name.len() > 255
            || !char::decode_utf16(entry.name.iter().copied()).all(|value| value.is_ok())
            || entry
                .name
                .iter()
                .any(|unit| matches!(*unit, 0..=31 | 34 | 42 | 47 | 58 | 60 | 62 | 63 | 92 | 124))
            || entry
                .name
                .last()
                .is_some_and(|unit| matches!(*unit, 32 | 46))
        {
            return Err(NtfsSerializeError::InvalidName {
                target: entry.target,
            });
        }
        let key = upcase
            .upcase_name(&entry.name, NtfsUpcaseLimits::default())
            .map_err(|source| NtfsSerializeError::Upcase { source })?;
        if !folded.insert((entry.parent, key)) {
            return Err(NtfsSerializeError::CaseCollision {
                parent: entry.parent,
            });
        }
    }
    Ok(())
}

fn metadata_layout(
    cluster: u64,
    cluster_count: u64,
    record_count: usize,
    secure_sds_bytes: usize,
    directory_index_clusters: u64,
) -> Result<MetadataLayout, NtfsSerializeError> {
    let mft_bytes = u64::try_from(record_count)
        .map_err(|_| NtfsSerializeError::ArithmeticOverflow)?
        .checked_mul(RECORD_BYTES as u64)
        .ok_or(NtfsSerializeError::ArithmeticOverflow)?;
    let mft_clusters = div_ceil(mft_bytes, cluster)?;
    let mirror_lcn = MFT_LCN
        .checked_add(mft_clusters)
        .ok_or(NtfsSerializeError::ArithmeticOverflow)?;
    let mirror_clusters = div_ceil(
        u64::try_from(SYSTEM_RECORDS.min(4) * RECORD_BYTES).unwrap(),
        cluster,
    )?;
    let logfile_lcn = mirror_lcn
        .checked_add(mirror_clusters)
        .ok_or(NtfsSerializeError::ArithmeticOverflow)?;
    let logfile_clusters = div_ceil(NTFS_LOGFILE_MIN_BYTES, cluster)?;
    let attrdef_lcn = logfile_lcn
        .checked_add(logfile_clusters)
        .ok_or(NtfsSerializeError::ArithmeticOverflow)?;
    let attrdef_clusters = div_ceil(
        u64::try_from(NTFS3X_ATTRDEF_BYTES).map_err(|_| NtfsSerializeError::ArithmeticOverflow)?,
        cluster,
    )?;
    let secure_sds_lcn = attrdef_lcn
        .checked_add(attrdef_clusters)
        .ok_or(NtfsSerializeError::ArithmeticOverflow)?;
    let secure_sds_bytes =
        u64::try_from(secure_sds_bytes).map_err(|_| NtfsSerializeError::ArithmeticOverflow)?;
    let secure_sds_clusters = div_ceil(secure_sds_bytes, cluster)?;
    let bitmap_lcn = secure_sds_lcn
        .checked_add(secure_sds_clusters)
        .ok_or(NtfsSerializeError::ArithmeticOverflow)?;
    let bitmap_clusters = div_ceil(cluster_count.div_ceil(8), cluster)?;
    let upcase_lcn = bitmap_lcn
        .checked_add(bitmap_clusters)
        .ok_or(NtfsSerializeError::ArithmeticOverflow)?;
    let upcase_clusters = div_ceil(65_536 * 2, cluster)?;
    let mft_bitmap_lcn = upcase_lcn
        .checked_add(upcase_clusters)
        .ok_or(NtfsSerializeError::ArithmeticOverflow)?;
    let record_count_u64 =
        u64::try_from(record_count).map_err(|_| NtfsSerializeError::ArithmeticOverflow)?;
    let mft_bitmap_bytes = div_ceil(record_count_u64, 8)?.max(MIN_MFT_BITMAP_BYTES);
    let mft_bitmap_bytes = div_ceil(mft_bitmap_bytes, 8)?
        .checked_mul(8)
        .ok_or(NtfsSerializeError::ArithmeticOverflow)?;
    let mft_bitmap_clusters = div_ceil(mft_bitmap_bytes, cluster)?;
    let directory_indexes_lcn = mft_bitmap_lcn
        .checked_add(mft_bitmap_clusters)
        .ok_or(NtfsSerializeError::ArithmeticOverflow)?;
    let metadata_clusters = directory_indexes_lcn
        .checked_add(directory_index_clusters)
        .ok_or(NtfsSerializeError::ArithmeticOverflow)?;
    Ok(MetadataLayout {
        cluster,
        cluster_count,
        record_count,
        mft_clusters,
        mirror_lcn,
        mirror_clusters,
        logfile_lcn,
        logfile_clusters,
        attrdef_lcn,
        attrdef_clusters,
        secure_sds_lcn,
        secure_sds_bytes,
        secure_sds_clusters,
        bitmap_lcn,
        bitmap_clusters,
        upcase_lcn,
        upcase_clusters,
        mft_bitmap_lcn,
        mft_bitmap_bytes,
        mft_bitmap_clusters,
        directory_indexes_lcn,
        directory_index_clusters,
        metadata_clusters,
    })
}

fn collect_sources(
    graph: &ObjectGraph,
    layout: &MetadataLayout,
) -> Result<Vec<SourceAllocation>, NtfsSerializeError> {
    let metadata_end = layout.metadata_clusters * layout.cluster;
    let backup_start = graph.extents().volume_bytes() - SECTOR_BYTES;
    let mut sources = Vec::new();
    sources
        .try_reserve(graph.extents().extents().len())
        .map_err(|_| NtfsSerializeError::AllocationFailed)?;
    for extent in graph.extents().extents() {
        let offset = match extent.placement {
            Placement::Sparse => {
                return Err(NtfsSerializeError::SparseExtent {
                    stream: extent.stream,
                });
            }
            Placement::Physical { byte_offset } => byte_offset,
        };
        if extent.logical_offset % layout.cluster != 0
            || offset % layout.cluster != 0
            || extent.length % layout.cluster != 0
        {
            return Err(NtfsSerializeError::UnalignedExtent {
                stream: extent.stream,
                offset,
                length: extent.length,
            });
        }
        let end = offset
            .checked_add(extent.length)
            .ok_or(NtfsSerializeError::ArithmeticOverflow)?;
        if end > layout.cluster_count * layout.cluster {
            return Err(NtfsSerializeError::ExtentOutsideNtfsClusters {
                stream: extent.stream,
            });
        }
        if offset < metadata_end || end > backup_start {
            return Err(NtfsSerializeError::PayloadMetadataConflict {
                stream: extent.stream,
                offset,
            });
        }
        sources.push(SourceAllocation {
            stream: extent.stream,
            logical_offset: extent.logical_offset,
            range: ByteRange {
                offset,
                length: extent.length,
            },
            // Runlists and the target $Bitmap currently encode the source LCN. A relocation-aware
            // second serialization pass must rewrite both before these allocations may move.
            movable: false,
        });
    }
    sources.sort_unstable_by_key(|value| value.range.offset);
    Ok(sources)
}

fn index_children(entries: &[NamespaceEntry]) -> BTreeMap<ObjectId, Vec<&NamespaceEntry>> {
    let mut children: BTreeMap<ObjectId, Vec<&NamespaceEntry>> = BTreeMap::new();
    for entry in entries {
        children.entry(entry.parent).or_default().push(entry);
    }
    children
}

fn boot_sector(
    inputs: NtfsDestinationInputs,
    layout: MetadataLayout,
) -> Result<Vec<u8>, NtfsSerializeError> {
    let mut bytes = vec![0_u8; 512];
    bytes[0..3].copy_from_slice(&[0xeb, 0x52, 0x90]);
    bytes[3..11].copy_from_slice(b"NTFS    ");
    put_u16(&mut bytes, 11, 512);
    bytes[13] = u8::try_from(layout.cluster / SECTOR_BYTES)
        .map_err(|_| NtfsSerializeError::InvalidImageGeometry)?;
    bytes[21] = 0xf8;
    put_u16(&mut bytes, 24, 63);
    put_u16(&mut bytes, 26, 255);
    put_u32(
        &mut bytes,
        28,
        u32::try_from(inputs.partition_offset_sectors).map_err(|_| {
            NtfsSerializeError::PartitionOffsetTooLarge {
                sectors: inputs.partition_offset_sectors,
            }
        })?,
    );
    put_u64(&mut bytes, 40, inputs.image_bytes / SECTOR_BYTES - 1);
    put_u64(&mut bytes, 48, MFT_LCN);
    put_u64(&mut bytes, 56, layout.mirror_lcn);
    bytes[64] = (-10_i8).to_ne_bytes()[0];
    bytes[68] = if layout.cluster == INDEX_BLOCK_BYTES {
        1
    } else {
        (-12_i8).to_ne_bytes()[0]
    };
    put_u64(&mut bytes, 72, inputs.volume_serial_number);
    put_u16(&mut bytes, 510, 0xaa55);
    Ok(bytes)
}

fn unused_record(record_number: u64) -> Result<Vec<u8>, NtfsSerializeError> {
    finish_record(record_number, 0, 0, Vec::new())
}

fn standard_information(
    timestamps: NtfsObjectTimestamps,
    attributes: u32,
) -> Result<Vec<u8>, NtfsSerializeError> {
    standard_information_with_security_id(timestamps, attributes, 0)
}

fn standard_information_with_security_id(
    timestamps: NtfsObjectTimestamps,
    attributes: u32,
    security_id: u32,
) -> Result<Vec<u8>, NtfsSerializeError> {
    let mut value = vec![0_u8; 72];
    for (offset, timestamp) in [
        timestamps.creation_time,
        timestamps.modification_time,
        timestamps.mft_change_time,
        timestamps.access_time,
    ]
    .into_iter()
    .enumerate()
    {
        put_u64(&mut value, offset * 8, timestamp);
    }
    put_u32(&mut value, 32, attributes);
    put_u32(&mut value, 52, security_id);
    resident_attribute(STANDARD_INFORMATION, None, 0, &value)
}

fn system_file_name_attribute(
    name: &str,
    allocated: u64,
    logical: u64,
    timestamp: u64,
    id: u16,
) -> Result<Vec<u8>, NtfsSerializeError> {
    let name: Vec<u16> = name.encode_utf16().collect();
    let value = file_name_value(
        5,
        &name,
        allocated,
        logical,
        FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
        NtfsObjectTimestamps::uniform(timestamp),
    )?;
    resident_attribute(FILE_NAME, None, id, &value)
}

fn system_mft_record(
    record_number: u64,
    layout: MetadataLayout,
    timestamp: u64,
) -> Result<Vec<u8>, NtfsSerializeError> {
    let attrs = vec![
        standard_information(
            NtfsObjectTimestamps::uniform(timestamp),
            FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
        )?,
        system_file_name_attribute(
            "$MFT",
            layout.mft_clusters * layout.cluster,
            layout.record_count as u64 * RECORD_BYTES as u64,
            timestamp,
            1,
        )?,
        nonresident_attribute(
            DATA,
            layout.mft_lcn_run(),
            layout.record_count as u64 * RECORD_BYTES as u64,
            layout.record_count as u64 * RECORD_BYTES as u64,
            layout.mft_clusters * layout.cluster,
            2,
        )?,
        nonresident_attribute(
            BITMAP,
            (layout.mft_bitmap_lcn, layout.mft_bitmap_clusters),
            layout.mft_bitmap_bytes,
            layout.mft_bitmap_bytes,
            layout.mft_bitmap_clusters * layout.cluster,
            3,
        )?,
    ];
    finish_record(record_number, 0x0005, 1, attrs)
}

impl MetadataLayout {
    const fn mft_lcn_run(self) -> (u64, u64) {
        (MFT_LCN, self.mft_clusters)
    }
}

fn system_data_record(
    record_number: u64,
    name: &str,
    lcn: u64,
    clusters: u64,
    logical: u64,
    cluster: u64,
    timestamp: u64,
) -> Result<Vec<u8>, NtfsSerializeError> {
    finish_record(
        record_number,
        0x0005,
        1,
        vec![
            standard_information(
                NtfsObjectTimestamps::uniform(timestamp),
                FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
            )?,
            system_file_name_attribute(name, clusters * cluster, logical, timestamp, 1)?,
            nonresident_attribute(
                DATA,
                (lcn, clusters),
                logical,
                logical,
                clusters * cluster,
                2,
            )?,
        ],
    )
}

fn badclus_record(
    record_number: u64,
    badclus: &EmptyBadClusPlan,
    timestamp: u64,
) -> Result<Vec<u8>, NtfsSerializeError> {
    // Microsoft identifies `$BadClus:$Bad` as the bad-cluster stream. The empty unnamed `$DATA`
    // plus volume-sized sparse `$Bad` representation is pinned to NTFS-3G commit
    // d327833ec1d5eb1358b6f2c37139f10a3460944d and independently validated by ntfs_essential.
    finish_record(
        record_number,
        0x0005,
        1,
        vec![
            standard_information(
                NtfsObjectTimestamps::uniform(timestamp),
                FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
            )?,
            system_file_name_attribute("$BadClus", 0, 0, timestamp, 1)?,
            resident_attribute(DATA, None, 2, &[])?,
            badclus_attribute(badclus, 3)?,
        ],
    )
}

fn secure_record(
    record_number: u64,
    layout: MetadataLayout,
    secure: &NtfsSecureMetadata,
    timestamp: u64,
) -> Result<Vec<u8>, NtfsSerializeError> {
    // Microsoft documents the three named metadata streams. Their initial values and collation
    // rules are the independently validated NTFS-3G Windows-2003-era profile; the wrappers here
    // deliberately do not assert modern Windows formatter byte identity.
    let descriptor_stream_name: Vec<u16> = "$SDS".encode_utf16().collect();
    let security_id_index_name: Vec<u16> = "$SII".encode_utf16().collect();
    let security_hash_index_name: Vec<u16> = "$SDH".encode_utf16().collect();
    let sii_root = secure_index_root_value(
        layout.cluster,
        secure.sii_collation_rule,
        &secure.sii_index_entries,
    )?;
    let sdh_root = secure_index_root_value(
        layout.cluster,
        secure.sdh_collation_rule,
        &secure.sdh_index_entries,
    )?;
    finish_record(
        record_number,
        0x0005,
        1,
        vec![
            standard_information(
                NtfsObjectTimestamps::uniform(timestamp),
                FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
            )?,
            system_file_name_attribute(
                "$Secure",
                layout.secure_sds_clusters * layout.cluster,
                u64::try_from(secure.sds.len())
                    .map_err(|_| NtfsSerializeError::ArithmeticOverflow)?,
                timestamp,
                1,
            )?,
            nonresident_named_attribute(
                DATA,
                &descriptor_stream_name,
                (layout.secure_sds_lcn, layout.secure_sds_clusters),
                u64::try_from(secure.sds.len())
                    .map_err(|_| NtfsSerializeError::ArithmeticOverflow)?,
                u64::try_from(secure.sds.len())
                    .map_err(|_| NtfsSerializeError::ArithmeticOverflow)?,
                layout.secure_sds_clusters * layout.cluster,
                2,
            )?,
            // Pinned mkntfs creates `$SDH` before `$SII`; this also preserves same-type name order.
            resident_attribute(INDEX_ROOT, Some(&security_hash_index_name), 3, &sdh_root)?,
            resident_attribute(INDEX_ROOT, Some(&security_id_index_name), 4, &sii_root)?,
        ],
    )
}

fn secure_index_root_value(
    cluster: u64,
    collation_rule: u32,
    entries: &[u8],
) -> Result<Vec<u8>, NtfsSerializeError> {
    let length = 32_usize
        .checked_add(entries.len())
        .ok_or(NtfsSerializeError::ArithmeticOverflow)?;
    let mut value = vec![0_u8; length];
    // The indexed attribute type is zero for these security indexes in the pinned formatter.
    put_u32(&mut value, 4, collation_rule);
    put_u32(&mut value, 8, u32::try_from(INDEX_BLOCK_BYTES).unwrap());
    let clusters_or_sectors = if INDEX_BLOCK_BYTES >= cluster {
        INDEX_BLOCK_BYTES / cluster
    } else {
        INDEX_BLOCK_BYTES / SECTOR_BYTES
    };
    value[12] =
        u8::try_from(clusters_or_sectors).map_err(|_| NtfsSerializeError::InvalidImageGeometry)?;
    put_u32(&mut value, 16, 16);
    let used = u32::try_from(16_usize + entries.len())
        .map_err(|_| NtfsSerializeError::ArithmeticOverflow)?;
    put_u32(&mut value, 20, used);
    put_u32(&mut value, 24, used);
    value[32..].copy_from_slice(entries);
    Ok(value)
}

fn append_extend_i30_entry(
    bytes: &mut Vec<u8>,
    reference: u64,
    key: &[u8],
    end: bool,
) -> Result<(), NtfsSerializeError> {
    let length = align_eight(
        16_usize
            .checked_add(key.len())
            .ok_or(NtfsSerializeError::ArithmeticOverflow)?,
    );
    let start = bytes.len();
    bytes.resize(start + length, 0);
    put_u64(bytes, start, reference);
    put_u16(
        bytes,
        start + 8,
        u16::try_from(length).map_err(|_| NtfsSerializeError::ArithmeticOverflow)?,
    );
    put_u16(
        bytes,
        start + 10,
        u16::try_from(key.len()).map_err(|_| NtfsSerializeError::ArithmeticOverflow)?,
    );
    put_u16(bytes, start + 12, u16::from(end) * 2);
    bytes[start + 16..start + 16 + key.len()].copy_from_slice(key);
    Ok(())
}

fn extend_records(
    layout: MetadataLayout,
    extend: &NtfsExtendMetadata,
    timestamp: u64,
    upcase: &NtfsUpcaseTable,
) -> Result<[Vec<u8>; 4], NtfsSerializeError> {
    // Microsoft reserves `$Extend`, `$Quota`, `$ObjId`, and `$Reparse`, but does not publish
    // formatter-exact bootstrap bytes. Record numbers, flags, namespace relationships, index
    // collation rules, and initial entry payloads below are pinned to NTFS-3G commit
    // d327833ec1d5eb1358b6f2c37139f10a3460944d and independently validated by ntfs_extend.
    let namespace = &extend.namespace;
    let i30_spec = extend_index_spec(extend, 11, "$I30")?;
    let mut i30_entries = Vec::new();
    let mut children = Vec::with_capacity(3);
    for child in [namespace.quota, namespace.object_id, namespace.reparse] {
        let name: Vec<u16> = child.name.encode_utf16().collect();
        let folded = upcase
            .upcase_name(&name, NtfsUpcaseLimits::default())
            .map_err(|source| NtfsSerializeError::Upcase { source })?;
        children.push((folded, name, child));
    }
    children
        .sort_unstable_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    for (_, name, child) in children {
        let key = file_name_value_with_parent_sequence(
            child.parent_record_number,
            child.parent_sequence_number,
            &name,
            0,
            0,
            child.file_name_attributes,
            NtfsObjectTimestamps::uniform(timestamp),
        )?;
        append_extend_i30_entry(
            &mut i30_entries,
            mft_reference_with_sequence(child.record_number, child.sequence_number),
            &key,
            false,
        )?;
    }
    append_extend_i30_entry(&mut i30_entries, 0, &[], true)?;

    let extend_record =
        extend_directory_record(layout, namespace.extend, i30_spec, &i30_entries, timestamp)?;
    let quota_record = extend_child_record(
        layout,
        namespace.quota,
        &[
            (
                extend_index_spec(extend, 24, "$O")?,
                extend.quota_o_index_entries.as_slice(),
            ),
            (
                extend_index_spec(extend, 24, "$Q")?,
                extend.quota_q_index_entries.as_slice(),
            ),
        ],
        timestamp,
    )?;
    let object_id_record = extend_child_record(
        layout,
        namespace.object_id,
        &[(
            extend_index_spec(extend, 25, "$O")?,
            extend.object_id_o_index_entries.as_slice(),
        )],
        timestamp,
    )?;
    let reparse_record = extend_child_record(
        layout,
        namespace.reparse,
        &[(
            extend_index_spec(extend, 26, "$R")?,
            extend.reparse_r_index_entries.as_slice(),
        )],
        timestamp,
    )?;
    Ok([
        extend_record,
        quota_record,
        object_id_record,
        reparse_record,
    ])
}

fn extend_index_spec(
    extend: &NtfsExtendMetadata,
    owner: u64,
    name: &str,
) -> Result<ExtendIndexSpec, NtfsSerializeError> {
    extend
        .namespace
        .indexes
        .iter()
        .copied()
        .find(|spec| spec.owner_record_number == owner && spec.name == name)
        .ok_or_else(|| NtfsSerializeError::MandatoryMetadata {
            component: "$Extend",
            reason: format!("missing typed index role {owner}:{name}"),
        })
}

fn extend_directory_record(
    layout: MetadataLayout,
    spec: ExtendRecordSpec,
    index: ExtendIndexSpec,
    index_entries: &[u8],
    timestamp: u64,
) -> Result<Vec<u8>, NtfsSerializeError> {
    let name: Vec<u16> = spec.name.encode_utf16().collect();
    let index_name: Vec<u16> = index.name.encode_utf16().collect();
    let file_name = file_name_value_with_parent_sequence(
        spec.parent_record_number,
        spec.parent_sequence_number,
        &name,
        0,
        0,
        spec.file_name_attributes,
        NtfsObjectTimestamps::uniform(timestamp),
    )?;
    let root = extend_index_root_value(layout.cluster, index, index_entries)?;
    finish_record_with_sequence(
        spec.record_number,
        spec.sequence_number,
        spec.mft_flags,
        1,
        vec![
            standard_information(
                NtfsObjectTimestamps::uniform(timestamp),
                spec.standard_information_file_attributes,
            )?,
            resident_attribute(FILE_NAME, None, 1, &file_name)?,
            resident_attribute(INDEX_ROOT, Some(&index_name), 2, &root)?,
        ],
    )
}

fn extend_child_record(
    layout: MetadataLayout,
    spec: ExtendRecordSpec,
    indexes: &[(ExtendIndexSpec, &[u8])],
    timestamp: u64,
) -> Result<Vec<u8>, NtfsSerializeError> {
    let name: Vec<u16> = spec.name.encode_utf16().collect();
    let file_name = file_name_value_with_parent_sequence(
        spec.parent_record_number,
        spec.parent_sequence_number,
        &name,
        0,
        0,
        spec.file_name_attributes,
        NtfsObjectTimestamps::uniform(timestamp),
    )?;
    let mut attributes = vec![
        standard_information(
            NtfsObjectTimestamps::uniform(timestamp),
            spec.standard_information_file_attributes,
        )?,
        resident_attribute(FILE_NAME, None, 1, &file_name)?,
    ];
    for (attribute_id, (index, entries)) in (2_u16..).zip(indexes.iter()) {
        let index_name: Vec<u16> = index.name.encode_utf16().collect();
        let root = extend_index_root_value(layout.cluster, *index, entries)?;
        attributes.push(resident_attribute(
            INDEX_ROOT,
            Some(&index_name),
            attribute_id,
            &root,
        )?);
    }
    finish_record_with_sequence(
        spec.record_number,
        spec.sequence_number,
        spec.mft_flags,
        1,
        attributes,
    )
}

fn extend_index_root_value(
    cluster: u64,
    spec: ExtendIndexSpec,
    entries: &[u8],
) -> Result<Vec<u8>, NtfsSerializeError> {
    if !spec.resident {
        return Err(NtfsSerializeError::MandatoryMetadata {
            component: "$Extend",
            reason: format!(
                "typed index role {}:{} is not resident",
                spec.owner_record_number, spec.name
            ),
        });
    }
    let length = 32_usize
        .checked_add(entries.len())
        .ok_or(NtfsSerializeError::ArithmeticOverflow)?;
    let mut value = vec![0_u8; length];
    put_u32(&mut value, 0, spec.indexed_attribute_type);
    put_u32(&mut value, 4, spec.collation_rule);
    put_u32(&mut value, 8, u32::try_from(INDEX_BLOCK_BYTES).unwrap());
    let clusters_or_sectors = if INDEX_BLOCK_BYTES >= cluster {
        INDEX_BLOCK_BYTES / cluster
    } else {
        INDEX_BLOCK_BYTES / SECTOR_BYTES
    };
    value[12] =
        u8::try_from(clusters_or_sectors).map_err(|_| NtfsSerializeError::InvalidImageGeometry)?;
    put_u32(&mut value, 16, 16);
    let used = u32::try_from(16_usize + entries.len())
        .map_err(|_| NtfsSerializeError::ArithmeticOverflow)?;
    put_u32(&mut value, 20, used);
    put_u32(&mut value, 24, used);
    value[32..].copy_from_slice(entries);
    Ok(value)
}

fn volume_record(timestamp: u64, label: Option<&[u16]>) -> Result<Vec<u8>, NtfsSerializeError> {
    let mut info = vec![0_u8; 12];
    info[8] = 3;
    info[9] = 1;
    let mut attributes = vec![
        standard_information(
            NtfsObjectTimestamps::uniform(timestamp),
            FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
        )?,
        system_file_name_attribute("$Volume", 0, 0, timestamp, 1)?,
    ];
    let volume_information_id = if let Some(label) = label {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(label.len().saturating_mul(2))
            .map_err(|_| NtfsSerializeError::AllocationFailed)?;
        for unit in label {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        attributes.push(resident_attribute(VOLUME_NAME, None, 2, &bytes)?);
        3
    } else {
        2
    };
    attributes.push(resident_attribute(
        VOLUME_INFORMATION,
        None,
        volume_information_id,
        &info,
    )?);
    finish_record(3, 0x0005, 1, attributes)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn plan_directory_indexes(
    objects: &[&ObjectRecord],
    children: &BTreeMap<ObjectId, Vec<&NamespaceEntry>>,
    records: &BTreeMap<ObjectId, u64>,
    graph: &ObjectGraph,
    metadata_by_object: &BTreeMap<ObjectId, NtfsObjectMetadata>,
    layout: MetadataLayout,
    timestamp: u64,
    upcase: &NtfsUpcaseTable,
    limits: NtfsSerializeLimits,
) -> Result<Vec<PlannedDirectoryIndex>, NtfsSerializeError> {
    let entry_by_target: BTreeMap<ObjectId, &NamespaceEntry> = graph
        .entries()
        .iter()
        .map(|entry| (entry.target, entry))
        .collect();
    let mut directories: Vec<_> = objects
        .iter()
        .copied()
        .filter(|object| object.kind == ObjectKind::Directory)
        .collect();
    directories.sort_unstable_by_key(|object| records[&object.id]);
    let mut planned = Vec::new();
    planned
        .try_reserve_exact(directories.len())
        .map_err(|_| NtfsSerializeError::AllocationFailed)?;
    let mut next_lcn = layout.directory_indexes_lcn;
    for object in directories {
        let record_number = records[&object.id];
        let object_metadata = metadata_by_object[&object.id];
        let prefix = if object.id == graph.root() {
            let root_name = NamespaceEntry {
                parent: graph.root(),
                target: graph.root(),
                name: vec![u16::from(b'.')],
            };
            directory_prefix_attributes(record_number, Some(&root_name), records, object_metadata)?
        } else {
            directory_prefix_attributes(
                record_number,
                Some(entry_by_target[&object.id]),
                records,
                object_metadata,
            )?
        };
        let index_entries = directory_index_entries(
            object.id,
            children.get(&object.id).map_or(&[][..], Vec::as_slice),
            records,
            graph,
            metadata_by_object,
            layout,
            timestamp,
            upcase,
        )?;
        let small_budget = directory_index_root_budget(object.id, &prefix, &[])?;
        let mut validation_budget = small_budget;
        let mut serialized = serialize_directory_index(
            object.id,
            &index_entries,
            upcase.mappings(),
            layout.cluster,
            small_budget,
            limits,
        )?;
        let (allocation_lcn, allocation_clusters) = if serialized.is_spilled() {
            let allocation_bytes = u64::try_from(serialized.index_allocation.len())
                .map_err(|_| NtfsSerializeError::ArithmeticOverflow)?;
            let clusters = div_ceil(allocation_bytes, layout.cluster)?;
            let i30: Vec<u16> = "$I30".encode_utf16().collect();
            let allocation_attribute = nonresident_named_attribute(
                INDEX_ALLOCATION,
                &i30,
                (next_lcn, clusters),
                allocation_bytes,
                allocation_bytes,
                clusters
                    .checked_mul(layout.cluster)
                    .ok_or(NtfsSerializeError::ArithmeticOverflow)?,
                3,
            )?;
            let bitmap_attribute = resident_attribute(BITMAP, Some(&i30), 4, &serialized.bitmap)?;
            let large_budget = directory_index_root_budget(
                object.id,
                &prefix,
                &[allocation_attribute, bitmap_attribute],
            )?;
            validation_budget = large_budget;
            let final_serialized = serialize_directory_index(
                object.id,
                &index_entries,
                upcase.mappings(),
                layout.cluster,
                large_budget,
                limits,
            )?;
            if !final_serialized.is_spilled()
                || final_serialized.index_allocation.len() != serialized.index_allocation.len()
                || final_serialized.block_vcns != serialized.block_vcns
            {
                return Err(NtfsSerializeError::DirectoryIndex {
                    object: object.id,
                    source: NtfsDirectoryIndexError::Malformed {
                        component: "integration planning",
                        reason: "spilled index geometry changed after FILE-record budgeting"
                            .to_owned(),
                    },
                });
            }
            serialized = final_serialized;
            let lcn = next_lcn;
            next_lcn = next_lcn
                .checked_add(clusters)
                .ok_or(NtfsSerializeError::ArithmeticOverflow)?;
            (Some(lcn), clusters)
        } else {
            (None, 0)
        };
        validate_serialized_ntfs_directory_index(
            &serialized,
            upcase.mappings(),
            NtfsDirectoryIndexGeometry {
                cluster_bytes: u32::try_from(layout.cluster)
                    .map_err(|_| NtfsSerializeError::InvalidImageGeometry)?,
                index_block_bytes: u32::try_from(INDEX_BLOCK_BYTES).unwrap(),
                resident_root_bytes: validation_budget,
            },
            directory_index_limits(limits),
        )
        .map_err(|source| NtfsSerializeError::DirectoryIndex {
            object: object.id,
            source,
        })?;
        planned.push(PlannedDirectoryIndex {
            object: object.id,
            record_number,
            serialized,
            allocation_lcn,
            allocation_clusters,
        });
    }
    Ok(planned)
}

fn serialize_directory_index(
    object: ObjectId,
    entries: &[NtfsDirectoryIndexEntry],
    upcase: &[u16],
    cluster: u64,
    root_budget: usize,
    limits: NtfsSerializeLimits,
) -> Result<SerializedNtfsDirectoryIndex, NtfsSerializeError> {
    serialize_ntfs_directory_index(
        entries,
        upcase,
        NtfsDirectoryIndexGeometry {
            cluster_bytes: u32::try_from(cluster)
                .map_err(|_| NtfsSerializeError::InvalidImageGeometry)?,
            index_block_bytes: u32::try_from(INDEX_BLOCK_BYTES).unwrap(),
            resident_root_bytes: root_budget,
        },
        directory_index_limits(limits),
    )
    .map_err(|source| NtfsSerializeError::DirectoryIndex { object, source })
}

const fn directory_index_limits(limits: NtfsSerializeLimits) -> NtfsDirectoryIndexLimits {
    NtfsDirectoryIndexLimits {
        // The root index also contains NTFS's fixed system-file namespace.
        max_entries: limits.max_entries.saturating_add(SYSTEM_RECORDS),
        max_blocks: limits.max_index_blocks,
        max_root_bytes: RECORD_BYTES,
        max_block_bytes: 4096,
        max_allocation_bytes: limits.max_index_allocation_bytes,
        max_name_code_units: 255,
    }
}

fn directory_index_root_budget(
    object: ObjectId,
    prefix: &[Vec<u8>],
    suffix: &[Vec<u8>],
) -> Result<usize, NtfsSerializeError> {
    let used = prefix
        .iter()
        .chain(suffix)
        .try_fold(0_usize, |total, attribute| {
            total
                .checked_add(attribute.len())
                .ok_or(NtfsSerializeError::ArithmeticOverflow)
        })?;
    let attribute_capacity = (RECORD_BYTES - 2 - 8 - ATTRIBUTES_OFFSET) & !7;
    let root_attribute_capacity = attribute_capacity
        .checked_sub(used)
        .ok_or(NtfsSerializeError::DirectoryIndexOverflow { object })?;
    // A resident named `$I30` attribute has a 32-byte aligned header/name prefix.
    root_attribute_capacity
        .checked_sub(32)
        .ok_or(NtfsSerializeError::DirectoryIndexOverflow { object })
}

fn directory_prefix_attributes(
    record_number: u64,
    entry: Option<&NamespaceEntry>,
    records: &BTreeMap<ObjectId, u64>,
    object_metadata: NtfsObjectMetadata,
) -> Result<Vec<Vec<u8>>, NtfsSerializeError> {
    let mut attributes = vec![standard_information_with_security_id(
        object_metadata.timestamps,
        object_metadata.dos_file_attributes,
        object_metadata.security_id,
    )?];
    if let Some(entry) = entry {
        let value = file_name_value(
            records[&entry.parent],
            &entry.name,
            0,
            0,
            object_metadata.dos_file_attributes,
            object_metadata.timestamps,
        )?;
        attributes.push(resident_attribute(FILE_NAME, None, 1, &value)?);
    }
    if record_number > 0x0000_ffff_ffff_ffff {
        return Err(NtfsSerializeError::ArithmeticOverflow);
    }
    Ok(attributes)
}

#[allow(clippy::too_many_arguments)]
fn directory_index_entries(
    directory: ObjectId,
    children: &[&NamespaceEntry],
    records: &BTreeMap<ObjectId, u64>,
    graph: &ObjectGraph,
    metadata_by_object: &BTreeMap<ObjectId, NtfsObjectMetadata>,
    layout: MetadataLayout,
    timestamp: u64,
    upcase: &NtfsUpcaseTable,
) -> Result<Vec<NtfsDirectoryIndexEntry>, NtfsSerializeError> {
    let mut entries = if directory == graph.root() {
        system_directory_index_entries(layout, timestamp)?
    } else {
        Vec::new()
    };
    let objects: BTreeMap<ObjectId, &ObjectRecord> = graph
        .objects()
        .iter()
        .map(|object| (object.id, object))
        .collect();
    let reserved: BTreeSet<Vec<u16>> = entries
        .iter()
        .map(|entry| fold_name(&entry.name, upcase))
        .collect::<Result<_, _>>()?;
    entries
        .try_reserve(children.len())
        .map_err(|_| NtfsSerializeError::AllocationFailed)?;
    for child in children {
        if directory == graph.root() && reserved.contains(&fold_name(&child.name, upcase)?) {
            return Err(NtfsSerializeError::ReservedRootName {
                target: child.target,
            });
        }
        let object = objects[&child.target];
        let stream = object.streams.first();
        let metadata = metadata_by_object[&child.target];
        entries.push(NtfsDirectoryIndexEntry {
            file_reference: NtfsFileReference {
                record_number: records[&child.target],
                sequence_number: record_sequence(records[&child.target]),
            },
            parent_directory: NtfsFileReference {
                record_number: records[&child.parent],
                sequence_number: record_sequence(records[&child.parent]),
            },
            creation_time: metadata.timestamps.creation_time,
            modification_time: metadata.timestamps.modification_time,
            mft_change_time: metadata.timestamps.mft_change_time,
            access_time: metadata.timestamps.access_time,
            allocated_size: stream.map_or(0, |value| value.allocated_bytes),
            data_size: stream.map_or(0, |value| value.logical_bytes),
            file_attributes: metadata.dos_file_attributes,
            reparse_tag_or_ea_size: 0,
            namespace: FileNameNamespace::Win32,
            name: child.name.clone(),
        });
    }
    Ok(entries)
}

fn system_directory_index_entries(
    layout: MetadataLayout,
    timestamp: u64,
) -> Result<Vec<NtfsDirectoryIndexEntry>, NtfsSerializeError> {
    let uniform = NtfsObjectTimestamps::uniform(timestamp);
    let attributes = FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM;
    let boot_clusters = div_ceil(BOOT_FILE_BYTES, layout.cluster)?;
    let record_count =
        u64::try_from(layout.record_count).map_err(|_| NtfsSerializeError::ArithmeticOverflow)?;
    let definitions = [
        (
            0,
            "$MFT",
            layout.mft_clusters * layout.cluster,
            record_count * RECORD_BYTES as u64,
        ),
        (
            1,
            "$MFTMirr",
            layout.mirror_clusters * layout.cluster,
            layout.mirror_clusters * layout.cluster,
        ),
        (
            2,
            "$LogFile",
            layout.logfile_clusters * layout.cluster,
            NTFS_LOGFILE_MIN_BYTES,
        ),
        (3, "$Volume", 0, 0),
        (
            4,
            "$AttrDef",
            layout.attrdef_clusters * layout.cluster,
            u64::try_from(NTFS3X_ATTRDEF_BYTES)
                .map_err(|_| NtfsSerializeError::ArithmeticOverflow)?,
        ),
        (
            6,
            "$Bitmap",
            layout.bitmap_clusters * layout.cluster,
            layout.cluster_count.div_ceil(8),
        ),
        (7, "$Boot", boot_clusters * layout.cluster, BOOT_FILE_BYTES),
        (8, "$BadClus", 0, 0),
        (
            9,
            "$Secure",
            layout.secure_sds_clusters * layout.cluster,
            layout.secure_sds_bytes,
        ),
        (
            10,
            "$UpCase",
            layout.upcase_clusters * layout.cluster,
            65_536 * 2,
        ),
        (11, "$Extend", 0, 0),
    ];
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(definitions.len())
        .map_err(|_| NtfsSerializeError::AllocationFailed)?;
    for (record_number, name, allocated_size, data_size) in definitions {
        entries.push(NtfsDirectoryIndexEntry {
            file_reference: NtfsFileReference {
                record_number,
                sequence_number: record_sequence(record_number),
            },
            parent_directory: NtfsFileReference {
                record_number: 5,
                sequence_number: 5,
            },
            creation_time: uniform.creation_time,
            modification_time: uniform.modification_time,
            mft_change_time: uniform.mft_change_time,
            access_time: uniform.access_time,
            allocated_size,
            data_size,
            file_attributes: if record_number == 11 {
                attributes | FILE_ATTRIBUTE_VIEW_INDEX_PRESENT
            } else {
                attributes
            },
            reparse_tag_or_ea_size: 0,
            namespace: FileNameNamespace::Win32,
            name: name.encode_utf16().collect(),
        });
    }
    Ok(entries)
}

fn fold_name(name: &[u16], upcase: &NtfsUpcaseTable) -> Result<Vec<u16>, NtfsSerializeError> {
    upcase
        .upcase_name(name, NtfsUpcaseLimits::default())
        .map_err(|source| NtfsSerializeError::Upcase { source })
}

fn build_directory_record(
    record_number: u64,
    entry: Option<&NamespaceEntry>,
    records: &BTreeMap<ObjectId, u64>,
    object_metadata: NtfsObjectMetadata,
    index: &PlannedDirectoryIndex,
    cluster: u64,
) -> Result<Vec<u8>, NtfsSerializeError> {
    if index.record_number != record_number {
        return Err(NtfsSerializeError::ArithmeticOverflow);
    }
    let mut attributes =
        directory_prefix_attributes(record_number, entry, records, object_metadata)?;
    let i30: Vec<u16> = "$I30".encode_utf16().collect();
    attributes.push(resident_attribute(
        INDEX_ROOT,
        Some(&i30),
        2,
        &index.serialized.index_root,
    )?);
    if let Some(lcn) = index.allocation_lcn {
        let logical = u64::try_from(index.serialized.index_allocation.len())
            .map_err(|_| NtfsSerializeError::ArithmeticOverflow)?;
        attributes.push(nonresident_named_attribute(
            INDEX_ALLOCATION,
            &i30,
            (lcn, index.allocation_clusters),
            logical,
            logical,
            index
                .allocation_clusters
                .checked_mul(cluster)
                .ok_or(NtfsSerializeError::ArithmeticOverflow)?,
            3,
        )?);
        attributes.push(resident_attribute(
            BITMAP,
            Some(&i30),
            4,
            &index.serialized.bitmap,
        )?);
    }
    finish_record_with_sequence(
        record_number,
        record_sequence(record_number),
        FILE_RECORD_IN_USE | FILE_RECORD_DIRECTORY,
        u16::from(entry.is_some()),
        attributes,
    )
    .map_err(|error| match error {
        NtfsSerializeError::RecordOverflow { .. } => NtfsSerializeError::DirectoryIndexOverflow {
            object: index.object,
        },
        other => other,
    })
}

#[allow(clippy::too_many_arguments)]
fn file_record(
    record_number: u64,
    object: &ObjectRecord,
    entry: &NamespaceEntry,
    records: &BTreeMap<ObjectId, u64>,
    graph: &ObjectGraph,
    layout: MetadataLayout,
    metadata: NtfsObjectMetadata,
    limits: NtfsSerializeLimits,
) -> Result<Vec<u8>, NtfsSerializeError> {
    let stream = object.streams.first();
    let logical = stream.map_or(0, |value| value.logical_bytes);
    let allocated = stream.map_or(0, |value| value.allocated_bytes);
    let value = file_name_value(
        records[&entry.parent],
        &entry.name,
        allocated,
        logical,
        metadata.dos_file_attributes,
        metadata.timestamps,
    )?;
    let mut attrs = vec![
        standard_information_with_security_id(
            metadata.timestamps,
            metadata.dos_file_attributes,
            metadata.security_id,
        )?,
        resident_attribute(FILE_NAME, None, 1, &value)?,
    ];
    if let Some(stream) = stream {
        match &stream.storage {
            StreamStorage::Resident(bytes) => {
                if bytes.len() > limits.max_resident_data_bytes {
                    return Err(NtfsSerializeError::ResidentDataTooLarge {
                        stream: stream.id,
                        actual: bytes.len(),
                        maximum: limits.max_resident_data_bytes,
                    });
                }
                attrs.push(resident_attribute(DATA, None, 2, bytes)?);
            }
            StreamStorage::Extents => {
                attrs.push(nonresident_stream_attribute(stream, graph, layout, 2)?);
            }
        }
    } else {
        attrs.push(resident_attribute(DATA, None, 2, &[])?);
    }
    finish_record(record_number, 0x0001, 1, attrs)
}

fn finish_record(
    record_number: u64,
    flags: u16,
    hard_links: u16,
    attributes: Vec<Vec<u8>>,
) -> Result<Vec<u8>, NtfsSerializeError> {
    finish_record_with_sequence(record_number, 1, flags, hard_links, attributes)
}

fn finish_record_with_sequence(
    record_number: u64,
    sequence_number: u16,
    flags: u16,
    hard_links: u16,
    attributes: Vec<Vec<u8>>,
) -> Result<Vec<u8>, NtfsSerializeError> {
    let mut repaired = vec![0_u8; RECORD_BYTES];
    repaired[..4].copy_from_slice(b"FILE");
    put_u16(&mut repaired, 4, 48);
    put_u16(&mut repaired, 6, 3);
    put_u16(&mut repaired, 16, sequence_number);
    put_u16(&mut repaired, 18, hard_links);
    put_u16(&mut repaired, 20, 56);
    put_u16(&mut repaired, 22, flags);
    put_u32(&mut repaired, 28, 1024);
    put_u16(
        &mut repaired,
        40,
        u16::try_from(attributes.len()).unwrap_or(u16::MAX),
    );
    put_u32(
        &mut repaired,
        44,
        u32::try_from(record_number).map_err(|_| NtfsSerializeError::ArithmeticOverflow)?,
    );
    let mut cursor = ATTRIBUTES_OFFSET;
    for attribute in attributes {
        let end = cursor
            .checked_add(attribute.len())
            .ok_or(NtfsSerializeError::ArithmeticOverflow)?;
        if end
            .checked_add(8)
            .is_none_or(|value| value > RECORD_BYTES - 2)
        {
            return Err(NtfsSerializeError::RecordOverflow { record_number });
        }
        repaired[cursor..end].copy_from_slice(&attribute);
        cursor = end;
    }
    put_u32(&mut repaired, cursor, END_ATTRIBUTE);
    cursor = align_eight(cursor + 4);
    put_u32(&mut repaired, 24, u32::try_from(cursor).unwrap());
    put_u16(&mut repaired, USA_OFFSET, USA_VALUE);
    let original0 = read_u16(&repaired, 510);
    let original1 = read_u16(&repaired, 1022);
    put_u16(&mut repaired, USA_OFFSET + 2, original0);
    put_u16(&mut repaired, USA_OFFSET + 4, original1);
    put_u16(&mut repaired, 510, USA_VALUE);
    put_u16(&mut repaired, 1022, USA_VALUE);
    Ok(repaired)
}

fn resident_attribute(
    attribute_type: u32,
    name: Option<&[u16]>,
    id: u16,
    value: &[u8],
) -> Result<Vec<u8>, NtfsSerializeError> {
    let name = name.unwrap_or(&[]);
    let name_bytes = name
        .len()
        .checked_mul(2)
        .ok_or(NtfsSerializeError::ArithmeticOverflow)?;
    let name_offset = if name.is_empty() { 0 } else { 24 };
    let value_offset = align_eight(24 + name_bytes);
    let total = align_eight(
        value_offset
            .checked_add(value.len())
            .ok_or(NtfsSerializeError::ArithmeticOverflow)?,
    );
    let mut bytes = vec![0_u8; total];
    put_u32(&mut bytes, 0, attribute_type);
    put_u32(
        &mut bytes,
        4,
        u32::try_from(total).map_err(|_| NtfsSerializeError::ArithmeticOverflow)?,
    );
    bytes[9] = u8::try_from(name.len()).map_err(|_| NtfsSerializeError::ArithmeticOverflow)?;
    put_u16(&mut bytes, 10, name_offset);
    put_u16(&mut bytes, 14, id);
    put_u32(
        &mut bytes,
        16,
        u32::try_from(value.len()).map_err(|_| NtfsSerializeError::ArithmeticOverflow)?,
    );
    put_u16(
        &mut bytes,
        20,
        u16::try_from(value_offset).map_err(|_| NtfsSerializeError::ArithmeticOverflow)?,
    );
    if !name.is_empty() {
        write_utf16(&mut bytes, usize::from(name_offset), name);
    }
    bytes[value_offset..value_offset + value.len()].copy_from_slice(value);
    Ok(bytes)
}

fn nonresident_attribute(
    attribute_type: u32,
    run: (u64, u64),
    logical: u64,
    initialized: u64,
    allocated: u64,
    id: u16,
) -> Result<Vec<u8>, NtfsSerializeError> {
    let pairs = encode_runs(&[(run.0, run.1)]).ok_or(NtfsSerializeError::ArithmeticOverflow)?;
    nonresident_attribute_from_pairs(
        attribute_type,
        &pairs,
        run.1,
        logical,
        initialized,
        allocated,
        id,
    )
}

#[allow(clippy::too_many_arguments)]
fn nonresident_named_attribute(
    attribute_type: u32,
    name: &[u16],
    run: (u64, u64),
    logical: u64,
    initialized: u64,
    allocated: u64,
    id: u16,
) -> Result<Vec<u8>, NtfsSerializeError> {
    if name.is_empty() || run.1 == 0 {
        return Err(NtfsSerializeError::ArithmeticOverflow);
    }
    let pairs = encode_runs(&[run]).ok_or(NtfsSerializeError::ArithmeticOverflow)?;
    let name_bytes = name
        .len()
        .checked_mul(2)
        .ok_or(NtfsSerializeError::ArithmeticOverflow)?;
    let mapping_offset = align_eight(
        64_usize
            .checked_add(name_bytes)
            .ok_or(NtfsSerializeError::ArithmeticOverflow)?,
    );
    let total = align_eight(
        mapping_offset
            .checked_add(pairs.len())
            .ok_or(NtfsSerializeError::ArithmeticOverflow)?,
    );
    let mut bytes = vec![0_u8; total];
    put_u32(&mut bytes, 0, attribute_type);
    put_u32(
        &mut bytes,
        4,
        u32::try_from(total).map_err(|_| NtfsSerializeError::ArithmeticOverflow)?,
    );
    bytes[8] = 1;
    bytes[9] = u8::try_from(name.len()).map_err(|_| NtfsSerializeError::ArithmeticOverflow)?;
    put_u16(&mut bytes, 10, 64);
    put_u16(&mut bytes, 14, id);
    put_u64(&mut bytes, 16, 0);
    put_u64(&mut bytes, 24, run.1 - 1);
    put_u16(
        &mut bytes,
        32,
        u16::try_from(mapping_offset).map_err(|_| NtfsSerializeError::ArithmeticOverflow)?,
    );
    put_u64(&mut bytes, 40, allocated);
    put_u64(&mut bytes, 48, logical);
    put_u64(&mut bytes, 56, initialized);
    write_utf16(&mut bytes, 64, name);
    bytes[mapping_offset..mapping_offset + pairs.len()].copy_from_slice(&pairs);
    Ok(bytes)
}

fn badclus_attribute(plan: &EmptyBadClusPlan, id: u16) -> Result<Vec<u8>, NtfsSerializeError> {
    let name_bytes = plan
        .name
        .len()
        .checked_mul(2)
        .ok_or(NtfsSerializeError::ArithmeticOverflow)?;
    let mapping_offset = align_eight(
        64_usize
            .checked_add(name_bytes)
            .ok_or(NtfsSerializeError::ArithmeticOverflow)?,
    );
    let total = align_eight(
        mapping_offset
            .checked_add(plan.mapping_pairs.len())
            .ok_or(NtfsSerializeError::ArithmeticOverflow)?,
    );
    let mut bytes = vec![0_u8; total];
    put_u32(&mut bytes, 0, plan.attribute_type);
    put_u32(
        &mut bytes,
        4,
        u32::try_from(total).map_err(|_| NtfsSerializeError::ArithmeticOverflow)?,
    );
    bytes[8] = 1;
    bytes[9] = u8::try_from(plan.name.len()).unwrap();
    put_u16(&mut bytes, 10, 64);
    put_u16(&mut bytes, 12, plan.attribute_flags);
    put_u16(&mut bytes, 14, id);
    put_u64(&mut bytes, 16, plan.lowest_vcn);
    put_u64(&mut bytes, 24, plan.highest_vcn);
    put_u16(
        &mut bytes,
        32,
        u16::try_from(mapping_offset).map_err(|_| NtfsSerializeError::ArithmeticOverflow)?,
    );
    bytes[34] = plan.compression_unit;
    put_u64(&mut bytes, 40, plan.allocated_size);
    put_u64(&mut bytes, 48, plan.data_size);
    put_u64(&mut bytes, 56, plan.initialized_size);
    write_utf16(&mut bytes, 64, &plan.name);
    bytes[mapping_offset..mapping_offset + plan.mapping_pairs.len()]
        .copy_from_slice(&plan.mapping_pairs);
    Ok(bytes)
}

fn nonresident_stream_attribute(
    stream: &ObjectStream,
    graph: &ObjectGraph,
    layout: MetadataLayout,
    id: u16,
) -> Result<Vec<u8>, NtfsSerializeError> {
    let mut runs = Vec::new();
    for extent in graph
        .extents()
        .extents()
        .iter()
        .filter(|extent| extent.stream == stream.id)
    {
        let Placement::Physical { byte_offset } = extent.placement else {
            return Err(NtfsSerializeError::SparseExtent { stream: stream.id });
        };
        runs.push((byte_offset / layout.cluster, extent.length / layout.cluster));
    }
    let pairs =
        encode_runs(&runs).ok_or(NtfsSerializeError::MappingPairsTooLarge { stream: stream.id })?;
    nonresident_attribute_from_pairs(
        DATA,
        &pairs,
        stream.mapped_bytes / layout.cluster,
        stream.logical_bytes,
        stream.initialized_bytes,
        stream.allocated_bytes,
        id,
    )
    .map_err(|error| match error {
        NtfsSerializeError::RecordOverflow { .. } => {
            NtfsSerializeError::MappingPairsTooLarge { stream: stream.id }
        }
        other => other,
    })
}

fn nonresident_attribute_from_pairs(
    attribute_type: u32,
    pairs: &[u8],
    clusters: u64,
    logical: u64,
    initialized: u64,
    allocated: u64,
    id: u16,
) -> Result<Vec<u8>, NtfsSerializeError> {
    if clusters == 0 {
        return resident_attribute(attribute_type, None, id, &[]);
    }
    let total = align_eight(
        64_usize
            .checked_add(pairs.len())
            .ok_or(NtfsSerializeError::ArithmeticOverflow)?,
    );
    let mut bytes = vec![0_u8; total];
    put_u32(&mut bytes, 0, attribute_type);
    put_u32(
        &mut bytes,
        4,
        u32::try_from(total).map_err(|_| NtfsSerializeError::ArithmeticOverflow)?,
    );
    bytes[8] = 1;
    put_u16(&mut bytes, 14, id);
    put_u64(&mut bytes, 16, 0);
    put_u64(&mut bytes, 24, clusters - 1);
    put_u16(&mut bytes, 32, 64);
    put_u64(&mut bytes, 40, allocated);
    put_u64(&mut bytes, 48, logical);
    put_u64(&mut bytes, 56, initialized);
    bytes[64..64 + pairs.len()].copy_from_slice(pairs);
    Ok(bytes)
}

fn encode_runs(runs: &[(u64, u64)]) -> Option<Vec<u8>> {
    let mut output = Vec::new();
    let mut previous = 0_i128;
    for &(lcn, length) in runs {
        if length == 0 {
            return None;
        }
        let length_bytes = unsigned_bytes(length);
        let delta = i128::from(lcn) - previous;
        let delta_i64 = i64::try_from(delta).ok()?;
        let delta_bytes = signed_bytes(delta_i64);
        output.push(
            (u8::try_from(delta_bytes.len()).ok()? << 4) | u8::try_from(length_bytes.len()).ok()?,
        );
        output.extend_from_slice(&length_bytes);
        output.extend_from_slice(&delta_bytes);
        previous = i128::from(lcn);
    }
    output.push(0);
    Some(output)
}

fn unsigned_bytes(value: u64) -> Vec<u8> {
    let raw = value.to_le_bytes();
    let length = (1..=8)
        .find(|length| raw[*length..].iter().all(|byte| *byte == 0))
        .unwrap_or(8);
    raw[..length].to_vec()
}

fn signed_bytes(value: i64) -> Vec<u8> {
    let raw = value.to_le_bytes();
    let mut length = 8;
    while length > 1 {
        let top = raw[length - 1];
        let next = raw[length - 2];
        if (top == 0 && next & 0x80 == 0) || (top == 0xff && next & 0x80 != 0) {
            length -= 1;
        } else {
            break;
        }
    }
    raw[..length].to_vec()
}

fn file_name_value(
    parent_record: u64,
    name: &[u16],
    allocated: u64,
    logical: u64,
    attributes: u32,
    timestamps: NtfsObjectTimestamps,
) -> Result<Vec<u8>, NtfsSerializeError> {
    file_name_value_with_parent_sequence(
        parent_record,
        record_sequence(parent_record),
        name,
        allocated,
        logical,
        attributes,
        timestamps,
    )
}

#[allow(clippy::too_many_arguments)]
fn file_name_value_with_parent_sequence(
    parent_record: u64,
    parent_sequence: u16,
    name: &[u16],
    allocated: u64,
    logical: u64,
    attributes: u32,
    timestamps: NtfsObjectTimestamps,
) -> Result<Vec<u8>, NtfsSerializeError> {
    let mut bytes = vec![0_u8; 66 + name.len() * 2];
    put_u64(
        &mut bytes,
        0,
        mft_reference_with_sequence(parent_record, parent_sequence),
    );
    for (offset, timestamp) in [
        timestamps.creation_time,
        timestamps.modification_time,
        timestamps.mft_change_time,
        timestamps.access_time,
    ]
    .into_iter()
    .enumerate()
    {
        put_u64(&mut bytes, 8 + offset * 8, timestamp);
    }
    put_u64(&mut bytes, 40, allocated);
    put_u64(&mut bytes, 48, logical);
    put_u32(&mut bytes, 56, attributes);
    bytes[64] = u8::try_from(name.len()).map_err(|_| NtfsSerializeError::ArithmeticOverflow)?;
    bytes[65] = 1;
    write_utf16(&mut bytes, 66, name);
    Ok(bytes)
}

fn write_attrdef(
    metadata: &mut [u8],
    layout: MetadataLayout,
    attrdef: &[u8],
) -> Result<(), NtfsSerializeError> {
    let offset = usize::try_from(layout.attrdef_lcn * layout.cluster)
        .map_err(|_| NtfsSerializeError::ArithmeticOverflow)?;
    let end = offset
        .checked_add(attrdef.len())
        .ok_or(NtfsSerializeError::ArithmeticOverflow)?;
    metadata[offset..end].copy_from_slice(attrdef);
    Ok(())
}

fn write_logfile(
    metadata: &mut [u8],
    layout: MetadataLayout,
    logfile: &[u8],
) -> Result<(), NtfsSerializeError> {
    let offset = usize::try_from(layout.logfile_lcn * layout.cluster)
        .map_err(|_| NtfsSerializeError::ArithmeticOverflow)?;
    let end = offset
        .checked_add(logfile.len())
        .ok_or(NtfsSerializeError::ArithmeticOverflow)?;
    metadata[offset..end].copy_from_slice(logfile);
    Ok(())
}

fn write_secure_sds(
    metadata: &mut [u8],
    layout: MetadataLayout,
    sds: &[u8],
) -> Result<(), NtfsSerializeError> {
    let offset = usize::try_from(layout.secure_sds_lcn * layout.cluster)
        .map_err(|_| NtfsSerializeError::ArithmeticOverflow)?;
    let end = offset
        .checked_add(sds.len())
        .ok_or(NtfsSerializeError::ArithmeticOverflow)?;
    metadata[offset..end].copy_from_slice(sds);
    Ok(())
}

fn write_bitmap(
    metadata: &mut [u8],
    layout: MetadataLayout,
    graph: &ObjectGraph,
) -> Result<(), NtfsSerializeError> {
    let offset = usize::try_from(layout.bitmap_lcn * layout.cluster)
        .map_err(|_| NtfsSerializeError::ArithmeticOverflow)?;
    let boot_clusters = div_ceil(BOOT_FILE_BYTES, layout.cluster)?;
    for cluster in 0..boot_clusters {
        set_bitmap(metadata, offset, cluster)?;
    }
    for cluster in MFT_LCN..layout.metadata_clusters {
        set_bitmap(metadata, offset, cluster)?;
    }
    for extent in graph.extents().extents() {
        if let Placement::Physical { byte_offset } = extent.placement {
            let start = byte_offset / layout.cluster;
            for cluster in start..start + extent.length / layout.cluster {
                set_bitmap(metadata, offset, cluster)?;
            }
        }
    }
    let bitmap_len = usize::try_from(layout.cluster_count.div_ceil(8))
        .map_err(|_| NtfsSerializeError::ArithmeticOverflow)?;
    if layout.cluster_count % 8 != 0 {
        let valid = u8::try_from(layout.cluster_count % 8).unwrap();
        metadata[offset + bitmap_len - 1] |= !((1_u8 << valid) - 1);
    }
    Ok(())
}

fn set_bitmap(metadata: &mut [u8], offset: usize, cluster: u64) -> Result<(), NtfsSerializeError> {
    let byte = offset
        .checked_add(
            usize::try_from(cluster / 8).map_err(|_| NtfsSerializeError::ArithmeticOverflow)?,
        )
        .ok_or(NtfsSerializeError::ArithmeticOverflow)?;
    metadata[byte] |= 1 << (cluster % 8);
    Ok(())
}

fn write_upcase(
    metadata: &mut [u8],
    layout: MetadataLayout,
    upcase_bytes: &[u8],
) -> Result<(), NtfsSerializeError> {
    let offset = usize::try_from(layout.upcase_lcn * layout.cluster)
        .map_err(|_| NtfsSerializeError::ArithmeticOverflow)?;
    let end = offset
        .checked_add(upcase_bytes.len())
        .ok_or(NtfsSerializeError::ArithmeticOverflow)?;
    metadata
        .get_mut(offset..end)
        .ok_or(NtfsSerializeError::ArithmeticOverflow)?
        .copy_from_slice(upcase_bytes);
    Ok(())
}

fn write_mft_bitmap(metadata: &mut [u8], layout: MetadataLayout) -> Result<(), NtfsSerializeError> {
    let offset = usize::try_from(layout.mft_bitmap_lcn * layout.cluster)
        .map_err(|_| NtfsSerializeError::ArithmeticOverflow)?;
    let bitmap_len = usize::try_from(layout.mft_bitmap_bytes)
        .map_err(|_| NtfsSerializeError::ArithmeticOverflow)?;
    let bitmap = metadata
        .get_mut(offset..offset + bitmap_len)
        .ok_or(NtfsSerializeError::ArithmeticOverflow)?;
    for record in 0..=11_usize {
        bitmap[record / 8] |= 1 << (record % 8);
    }
    for record in 24..FIRST_USER_RECORD {
        let record = usize::try_from(record).map_err(|_| NtfsSerializeError::ArithmeticOverflow)?;
        bitmap[record / 8] |= 1 << (record % 8);
    }
    for record in FIRST_USER_RECORD..u64::try_from(layout.record_count).unwrap_or(u64::MAX) {
        let record = usize::try_from(record).map_err(|_| NtfsSerializeError::ArithmeticOverflow)?;
        if record / 8 >= bitmap.len() {
            return Err(NtfsSerializeError::MetadataLimitExceeded {
                actual: u64::try_from(layout.record_count.div_ceil(8)).unwrap_or(u64::MAX),
                maximum: bitmap.len(),
            });
        }
        bitmap[record / 8] |= 1 << (record % 8);
    }
    Ok(())
}

const fn mft_reference_with_sequence(record_number: u64, sequence_number: u16) -> u64 {
    ((sequence_number as u64) << 48) | record_number
}

const fn record_sequence(record_number: u64) -> u16 {
    match record_number {
        5 => 5,
        11 => 11,
        _ => 1,
    }
}

const fn align_eight(value: usize) -> usize {
    value.saturating_add(7) & !7
}

fn div_ceil(value: u64, divisor: u64) -> Result<u64, NtfsSerializeError> {
    value
        .checked_add(divisor - 1)
        .map(|sum| sum / divisor)
        .ok_or(NtfsSerializeError::ArithmeticOverflow)
}

fn write_utf16(bytes: &mut [u8], offset: usize, units: &[u16]) {
    for (index, unit) in units.iter().enumerate() {
        put_u16(bytes, offset + index * 2, *unit);
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
const fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::extent::{Extent, ExtentGraph};
    use crate::fs::ntfs::parse_boot_sector;
    use crate::fs::ntfs_attribute::{AttributeBody, AttributeLimits, parse_attribute_list};
    use crate::fs::ntfs_essential::{
        BADCLUS_STREAM_NAME, EmptyBadClusRef, validate_empty_badclus, validate_ntfs3x_attrdef,
    };
    use crate::fs::ntfs_extend::validate_ntfs3g_extend_metadata;
    use crate::fs::ntfs_index::{NtfsIndexLimits, parse_index_block, parse_index_root};
    use crate::fs::ntfs_logfile::validate_ntfs_logfile;
    use crate::fs::ntfs_record::parse_file_record;
    use crate::fs::ntfs_runlist::{MappingPairsLimits, parse_mapping_pairs};
    use crate::fs::ntfs_secure::validate_ntfs_secure_metadata;
    use crate::object::{ObjectGraphLimits, ObjectSemantics, StreamFlags};

    const IMAGE_BYTES: u64 = 16 * 1024 * 1024;
    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TempImage(PathBuf);

    impl TempImage {
        fn create(bytes: &[u8]) -> Self {
            let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "starconverter-ntfs-serialize-{}-{id}.img",
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

    fn graph(resident: Option<Vec<u8>>, physical: bool) -> ObjectGraph {
        let root = ObjectRecord {
            id: ObjectId(1),
            kind: ObjectKind::Directory,
            link_count: 0,
            semantics: ObjectSemantics::default(),
            streams: vec![],
        };
        let (stream, extents) = if physical {
            (
                ObjectStream {
                    id: StreamId(9),
                    name: None,
                    logical_bytes: 4,
                    initialized_bytes: 4,
                    mapped_bytes: 4096,
                    allocated_bytes: 4096,
                    flags: StreamFlags::default(),
                    storage: StreamStorage::Extents,
                },
                vec![Extent {
                    stream: StreamId(9),
                    logical_offset: 0,
                    length: 4096,
                    placement: Placement::Physical {
                        byte_offset: 8 * 1024 * 1024,
                    },
                    kind: ExtentKind::FileData,
                }],
            )
        } else {
            let value = resident.unwrap_or_default();
            (
                ObjectStream {
                    id: StreamId(9),
                    name: None,
                    logical_bytes: value.len() as u64,
                    initialized_bytes: value.len() as u64,
                    mapped_bytes: value.len() as u64,
                    allocated_bytes: 0,
                    flags: StreamFlags::default(),
                    storage: StreamStorage::Resident(value),
                },
                vec![],
            )
        };
        let file = ObjectRecord {
            id: ObjectId(2),
            kind: ObjectKind::File,
            link_count: 1,
            semantics: ObjectSemantics::default(),
            streams: vec![stream],
        };
        ObjectGraph::build(
            ObjectId(1),
            vec![file, root],
            vec![NamespaceEntry {
                parent: ObjectId(1),
                target: ObjectId(2),
                name: "hello.txt".encode_utf16().collect(),
            }],
            ExtentGraph::build(extents, IMAGE_BYTES, 16).unwrap(),
            ObjectGraphLimits {
                max_objects: 8,
                max_entries: 8,
                max_streams: 8,
                max_name_code_units: 255,
            },
        )
        .unwrap()
    }

    fn graph_with_bad_cluster() -> ObjectGraph {
        let stream = ObjectStream {
            id: StreamId(77),
            name: None,
            logical_bytes: 4096,
            initialized_bytes: 4096,
            mapped_bytes: 4096,
            allocated_bytes: 4096,
            flags: StreamFlags::default(),
            storage: StreamStorage::Extents,
        };
        let root = ObjectRecord {
            id: ObjectId(1),
            kind: ObjectKind::Directory,
            link_count: 0,
            semantics: ObjectSemantics::default(),
            streams: vec![stream],
        };
        ObjectGraph::build(
            ObjectId(1),
            vec![root],
            vec![],
            ExtentGraph::build(
                vec![Extent {
                    stream: StreamId(77),
                    logical_offset: 0,
                    length: 4096,
                    placement: Placement::Physical {
                        byte_offset: 8 * 1024 * 1024,
                    },
                    kind: ExtentKind::BadCluster,
                }],
                IMAGE_BYTES,
                4,
            )
            .unwrap(),
            ObjectGraphLimits {
                max_objects: 2,
                max_entries: 1,
                max_streams: 2,
                max_name_code_units: 255,
            },
        )
        .unwrap()
    }

    fn two_file_graph() -> ObjectGraph {
        let root = ObjectRecord {
            id: ObjectId(1),
            kind: ObjectKind::Directory,
            link_count: 0,
            semantics: ObjectSemantics::default(),
            streams: vec![],
        };
        let files = [
            (ObjectId(2), StreamId(9), b"one".as_slice()),
            (ObjectId(3), StreamId(10), b"two".as_slice()),
        ]
        .map(|(id, stream_id, bytes)| ObjectRecord {
            id,
            kind: ObjectKind::File,
            link_count: 1,
            semantics: ObjectSemantics::default(),
            streams: vec![ObjectStream {
                id: stream_id,
                name: None,
                logical_bytes: bytes.len() as u64,
                initialized_bytes: bytes.len() as u64,
                mapped_bytes: bytes.len() as u64,
                allocated_bytes: 0,
                flags: StreamFlags::default(),
                storage: StreamStorage::Resident(bytes.to_vec()),
            }],
        });
        ObjectGraph::build(
            ObjectId(1),
            vec![root, files[0].clone(), files[1].clone()],
            vec![
                NamespaceEntry {
                    parent: ObjectId(1),
                    target: ObjectId(2),
                    name: "one.txt".encode_utf16().collect(),
                },
                NamespaceEntry {
                    parent: ObjectId(1),
                    target: ObjectId(3),
                    name: "two.txt".encode_utf16().collect(),
                },
            ],
            ExtentGraph::build(vec![], IMAGE_BYTES, 16).unwrap(),
            ObjectGraphLimits {
                max_objects: 8,
                max_entries: 8,
                max_streams: 8,
                max_name_code_units: 255,
            },
        )
        .unwrap()
    }

    fn two_spilled_directories_graph(files_per_directory: usize) -> ObjectGraph {
        let root = ObjectRecord {
            id: ObjectId(1),
            kind: ObjectKind::Directory,
            link_count: 0,
            semantics: ObjectSemantics::default(),
            streams: vec![],
        };
        let mut objects = vec![root];
        let mut entries = Vec::new();
        for (directory_offset, directory_name) in ["alpha", "beta"].into_iter().enumerate() {
            let directory_id = ObjectId(u64::try_from(directory_offset + 2).unwrap());
            objects.push(ObjectRecord {
                id: directory_id,
                kind: ObjectKind::Directory,
                link_count: 1,
                semantics: ObjectSemantics::default(),
                streams: vec![],
            });
            entries.push(NamespaceEntry {
                parent: ObjectId(1),
                target: directory_id,
                name: directory_name.encode_utf16().collect(),
            });
            for index in 0..files_per_directory {
                let ordinal = directory_offset
                    .checked_mul(files_per_directory)
                    .and_then(|value| value.checked_add(index))
                    .unwrap();
                let object_id = ObjectId(u64::try_from(ordinal + 4).unwrap());
                let stream_id = StreamId(u64::try_from(ordinal + 100).unwrap());
                objects.push(ObjectRecord {
                    id: object_id,
                    kind: ObjectKind::File,
                    link_count: 1,
                    semantics: ObjectSemantics::default(),
                    streams: vec![ObjectStream {
                        id: stream_id,
                        name: None,
                        logical_bytes: 0,
                        initialized_bytes: 0,
                        mapped_bytes: 0,
                        allocated_bytes: 0,
                        flags: StreamFlags::default(),
                        storage: StreamStorage::Resident(Vec::new()),
                    }],
                });
                let name = match index {
                    0 => "Ωmega-directory-index-entry.txt".to_owned(),
                    1 => "Éclair-directory-index-entry.txt".to_owned(),
                    _ => format!("entry-{index:03}-long-directory-index-name.txt"),
                };
                entries.push(NamespaceEntry {
                    parent: directory_id,
                    target: object_id,
                    name: name.encode_utf16().collect(),
                });
            }
        }
        let maximum = files_per_directory.checked_mul(2).unwrap() + 3;
        ObjectGraph::build(
            ObjectId(1),
            objects,
            entries,
            ExtentGraph::build(vec![], IMAGE_BYTES, maximum).unwrap(),
            ObjectGraphLimits {
                max_objects: maximum,
                max_entries: maximum,
                max_streams: maximum,
                max_name_code_units: 255,
            },
        )
        .unwrap()
    }

    fn exact_metadata() -> Vec<NtfsObjectMetadata> {
        vec![
            NtfsObjectMetadata {
                object: ObjectId(1),
                object_kind: ObjectKind::Directory,
                timestamps: NtfsObjectTimestamps {
                    creation_time: 10,
                    modification_time: 11,
                    mft_change_time: 12,
                    access_time: 13,
                },
                dos_file_attributes: FILE_ATTRIBUTE_DIRECTORY,
                security_id: NTFS3G_SECURITY_ID_READ_WRITE,
            },
            NtfsObjectMetadata {
                object: ObjectId(2),
                object_kind: ObjectKind::File,
                timestamps: NtfsObjectTimestamps {
                    creation_time: 20,
                    modification_time: 21,
                    mft_change_time: 22,
                    access_time: 23,
                },
                dos_file_attributes: FILE_ATTRIBUTE_ARCHIVE | 0x0001,
                security_id: NTFS3G_SECURITY_ID_READ_WRITE,
            },
            NtfsObjectMetadata {
                object: ObjectId(3),
                object_kind: ObjectKind::File,
                timestamps: NtfsObjectTimestamps {
                    creation_time: 30,
                    modification_time: 31,
                    mft_change_time: 32,
                    access_time: 33,
                },
                dos_file_attributes: FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_HIDDEN,
                security_id: NTFS3G_SECURITY_ID_READ_WRITE,
            },
        ]
    }

    const fn inputs() -> NtfsDestinationInputs {
        NtfsDestinationInputs {
            image_bytes: IMAGE_BYTES,
            partition_offset_sectors: 0,
            cluster_bytes: 4096,
            volume_serial_number: 0x1122_3344_5566_7788,
            timestamp: 123,
        }
    }

    const fn attr_limits() -> AttributeLimits {
        AttributeLimits {
            cluster_size_bytes: 4096,
            max_attribute_bytes: 1024,
            max_name_code_units: 255,
            max_attributes: 16,
        }
    }

    const fn index_limits() -> NtfsIndexLimits {
        NtfsIndexLimits {
            max_root_bytes: 1024,
            max_block_bytes: 4096,
            max_entries_per_node: 64,
            max_name_code_units: 255,
        }
    }

    fn record(plan: &NtfsDestinationPlan, number: usize) -> &[u8] {
        let offset = usize::try_from(MFT_LCN).unwrap() * 4096 + number * RECORD_BYTES;
        let staging_offset = offset - 512;
        &plan.staging_writes[0].bytes[staging_offset..staging_offset + RECORD_BYTES]
    }

    fn root_index_block(plan: &NtfsDestinationPlan) -> &[u8] {
        let record_count = plan
            .object_placements
            .iter()
            .map(|placement| placement.record_number + 1)
            .max()
            .unwrap_or(FIRST_USER_RECORD)
            .max(FIRST_USER_RECORD);
        let layout = metadata_layout(
            u64::from(plan.cluster_bytes),
            (plan.image_bytes / SECTOR_BYTES - 1) / (u64::from(plan.cluster_bytes) / SECTOR_BYTES),
            usize::try_from(record_count).unwrap(),
            0x400fc,
            0,
        )
        .unwrap();
        let offset = usize::try_from(layout.directory_indexes_lcn * layout.cluster).unwrap();
        let staging_offset = offset - usize::try_from(SECTOR_BYTES).unwrap();
        &plan.staging_writes[0].bytes
            [staging_offset..staging_offset + usize::try_from(INDEX_BLOCK_BYTES).unwrap()]
    }

    fn staged_bytes(plan: &NtfsDestinationPlan, offset: u64, length: usize) -> &[u8] {
        let start = usize::try_from(offset - SECTOR_BYTES).unwrap();
        &plan.staging_writes[0].bytes[start..start + length]
    }

    fn directory_index_artifact(
        plan: &NtfsDestinationPlan,
        record_number: usize,
    ) -> SerializedNtfsDirectoryIndex {
        let directory = parse_file_record(record(plan, record_number)).unwrap();
        let attributes = parse_attribute_list(
            directory.repaired_bytes(),
            usize::from(directory.attributes_offset),
            usize::try_from(directory.bytes_in_use).unwrap(),
            attr_limits(),
        )
        .unwrap();
        let root = attributes
            .attributes
            .iter()
            .find(|attribute| attribute.attribute_type == INDEX_ROOT)
            .unwrap();
        let AttributeBody::Resident(root) = &root.body else {
            panic!("resident INDEX_ROOT")
        };
        let allocation = attributes
            .attributes
            .iter()
            .find(|attribute| attribute.attribute_type == INDEX_ALLOCATION)
            .unwrap();
        let AttributeBody::NonResident(allocation) = &allocation.body else {
            panic!("nonresident INDEX_ALLOCATION")
        };
        let sizes = allocation.sizes.unwrap();
        let allocation_clusters = sizes.allocated / u64::from(plan.cluster_bytes);
        let runs = parse_mapping_pairs(
            allocation.mapping_pairs,
            MappingPairsLimits {
                starting_vcn: 0,
                expected_next_vcn: Some(allocation_clusters),
                volume_cluster_count: plan.image_bytes / u64::from(plan.cluster_bytes),
                max_runs: 1,
                max_decoded_clusters: allocation_clusters,
            },
        )
        .unwrap();
        let crate::fs::ntfs_runlist::ExtentLocation::Physical { lcn } = runs.extents[0].location
        else {
            panic!("physical INDEX_ALLOCATION")
        };
        let bitmap = attributes
            .attributes
            .iter()
            .find(|attribute| attribute.attribute_type == BITMAP)
            .unwrap();
        let AttributeBody::Resident(bitmap) = &bitmap.body else {
            panic!("resident index BITMAP")
        };
        let block_count = usize::try_from(sizes.data / INDEX_BLOCK_BYTES).unwrap();
        SerializedNtfsDirectoryIndex {
            index_root: root.value.to_vec(),
            index_allocation: staged_bytes(
                plan,
                lcn * u64::from(plan.cluster_bytes),
                usize::try_from(sizes.data).unwrap(),
            )
            .to_vec(),
            bitmap: bitmap.value.to_vec(),
            block_vcns: (0..u64::try_from(block_count).unwrap()).collect(),
        }
    }

    fn activated_image(plan: &NtfsDestinationPlan) -> Vec<u8> {
        let mut image = vec![0_u8; usize::try_from(plan.image_bytes).unwrap()];
        for write in &plan.staging_writes {
            let offset = usize::try_from(write.offset).unwrap();
            image[offset..offset + write.bytes.len()].copy_from_slice(&write.bytes);
        }
        let backup = usize::try_from(plan.backup_boot_write.offset).unwrap();
        image[backup..backup + plan.backup_boot_write.bytes.len()]
            .copy_from_slice(&plan.backup_boot_write.bytes);
        image[..plan.primary_boot_write.bytes.len()]
            .copy_from_slice(&plan.primary_boot_write.bytes);
        image
    }

    #[test]
    fn boot_records_and_backup_are_byte_identical_and_parseable() {
        let plan = plan_ntfs_destination(
            &graph(Some(b"abc".to_vec()), false),
            inputs(),
            NtfsSerializeLimits::default(),
        )
        .unwrap();
        let boot = parse_boot_sector(&plan.primary_boot_write.bytes).unwrap();
        assert_eq!(boot.mft_lcn, 4);
        assert_eq!(boot.mft_mirror_lcn, plan.mft_mirror_lcn);
        assert_eq!(boot.hidden_sectors, 0);
        assert_eq!(plan.backup_boot_write.bytes, plan.primary_boot_write.bytes);
        assert!(plan.staging_writes.iter().all(|write| write.offset != 0));
        assert_eq!(
            parse_boot_sector(&plan.backup_boot_write.bytes).unwrap(),
            boot
        );
        for number in 0..28 {
            let parsed = parse_file_record(record(&plan, number)).unwrap();
            assert_eq!(parsed.record_number, Some(u32::try_from(number).unwrap()));
        }
        assert!(!plan.activation_ready());
        assert_eq!(plan.activation_gaps(), STRUCTURAL_ACTIVATION_GAPS);
        assert!(
            plan.extend_activation_gaps()
                .contains(&NtfsExtendActivationGap::MicrosoftDoesNotSpecifyBootstrapBytes)
        );
        assert!(
            !plan
                .extend_activation_gaps()
                .contains(&NtfsExtendActivationGap::FileAndAttributeWrappersNotGenerated)
        );
        assert!(
            !plan
                .extend_activation_gaps()
                .contains(&NtfsExtendActivationGap::ExtendDirectoryEntriesNotGenerated)
        );
    }

    #[test]
    fn partition_offset_roundtrips_through_both_ntfs_boot_copies() {
        let mut positioned = inputs();
        positioned.partition_offset_sectors = 2048;
        let plan = plan_ntfs_destination(
            &graph(Some(b"offset".to_vec()), false),
            positioned,
            NtfsSerializeLimits::default(),
        )
        .unwrap();
        assert_eq!(
            parse_boot_sector(&plan.primary_boot_write.bytes)
                .unwrap()
                .hidden_sectors,
            2048
        );
        assert_eq!(
            parse_boot_sector(&plan.backup_boot_write.bytes)
                .unwrap()
                .hidden_sectors,
            2048
        );

        positioned.partition_offset_sectors = u64::from(u32::MAX) + 1;
        assert!(matches!(
            plan_ntfs_destination(
                &graph(Some(b"offset".to_vec()), false),
                positioned,
                NtfsSerializeLimits::default(),
            ),
            Err(NtfsSerializeError::PartitionOffsetTooLarge { .. })
        ));
    }

    #[test]
    fn resident_data_and_root_i30_roundtrip() {
        let plan = plan_ntfs_destination(
            &graph(Some(vec![1, 2, 3, 4]), false),
            inputs(),
            NtfsSerializeLimits::default(),
        )
        .unwrap();
        let file = parse_file_record(record(&plan, 27)).unwrap();
        let attrs = parse_attribute_list(
            file.repaired_bytes(),
            file.attributes_offset as usize,
            file.bytes_in_use as usize,
            attr_limits(),
        )
        .unwrap();
        let data = attrs
            .attributes
            .iter()
            .find(|attribute| attribute.attribute_type == DATA)
            .unwrap();
        assert!(
            matches!(&data.body, AttributeBody::Resident(value) if value.value == [1, 2, 3, 4])
        );
        let root = parse_file_record(record(&plan, 5)).unwrap();
        let attrs = parse_attribute_list(
            root.repaired_bytes(),
            root.attributes_offset as usize,
            root.bytes_in_use as usize,
            attr_limits(),
        )
        .unwrap();
        let index = attrs
            .attributes
            .iter()
            .find(|attribute| attribute.attribute_type == INDEX_ROOT)
            .unwrap();
        let AttributeBody::Resident(index) = &index.body else {
            panic!("resident index")
        };
        let parsed = parse_index_root(index.value, index_limits()).unwrap();
        assert_eq!(parsed.entry_count(), 1);
        assert_eq!(parsed.entries().next().unwrap().child_vcn, Some(0));
        let block = parse_index_block(root_index_block(&plan), Some(0), index_limits()).unwrap();
        assert_eq!(block.entry_count(), 13);
        let names: BTreeSet<Vec<u16>> = block
            .entries()
            .filter_map(|entry| entry.file_name)
            .map(|name| name.name.code_units().collect())
            .collect();
        for expected in [
            "$MFT",
            "$MFTMirr",
            "$LogFile",
            "$Volume",
            "$AttrDef",
            "$Bitmap",
            "$Boot",
            "$BadClus",
            "$Secure",
            "$UpCase",
            "$Extend",
            "hello.txt",
        ] {
            assert!(names.contains(&expected.encode_utf16().collect::<Vec<_>>()));
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn extend_records_indexes_namespace_and_typed_payloads_roundtrip() {
        let plan = plan_ntfs_destination(
            &graph(Some(b"extend".to_vec()), false),
            inputs(),
            NtfsSerializeLimits::default(),
        )
        .unwrap();
        assert_eq!(plan.object_placements[1].record_number, FIRST_USER_RECORD);

        let expected = generate_ntfs3g_extend_metadata(
            NtfsExtendProfile::MkntfsNtfs31,
            QuotaChangeTimes {
                defaults: i64::try_from(inputs().timestamp).unwrap(),
                administrators: i64::try_from(inputs().timestamp).unwrap(),
            },
            NtfsExtendLimits::default(),
        )
        .unwrap();

        let extend_record = parse_file_record(record(&plan, 11)).unwrap();
        assert_eq!(
            extend_record.sequence_number,
            expected.namespace.extend.sequence_number
        );
        assert_eq!(extend_record.flags.raw, expected.namespace.extend.mft_flags);
        let extend_attributes = parse_attribute_list(
            extend_record.repaired_bytes(),
            usize::from(extend_record.attributes_offset),
            usize::try_from(extend_record.bytes_in_use).unwrap(),
            attr_limits(),
        )
        .unwrap();
        let extend_standard = extend_attributes
            .attributes
            .iter()
            .find(|attribute| attribute.attribute_type == STANDARD_INFORMATION)
            .unwrap();
        let AttributeBody::Resident(extend_standard) = &extend_standard.body else {
            panic!("resident $Extend standard information")
        };
        assert_eq!(
            u32::from_le_bytes(extend_standard.value[32..36].try_into().unwrap()),
            expected
                .namespace
                .extend
                .standard_information_file_attributes
        );
        let extend_name = extend_attributes
            .attributes
            .iter()
            .find(|attribute| attribute.attribute_type == FILE_NAME)
            .unwrap();
        let AttributeBody::Resident(extend_name) = &extend_name.body else {
            panic!("resident $Extend file name")
        };
        assert_eq!(
            u64::from_le_bytes(extend_name.value[..8].try_into().unwrap()),
            mft_reference_with_sequence(5, 5)
        );
        assert_eq!(
            u32::from_le_bytes(extend_name.value[56..60].try_into().unwrap()),
            expected.namespace.extend.file_name_attributes
        );
        let extend_i30 = extend_attributes
            .attributes
            .iter()
            .find(|attribute| {
                attribute.attribute_type == INDEX_ROOT
                    && attribute.name.as_ref().is_some_and(|name| {
                        name.code_units == "$I30".encode_utf16().collect::<Vec<_>>()
                    })
            })
            .unwrap();
        let AttributeBody::Resident(extend_i30) = &extend_i30.body else {
            panic!("resident $Extend:$I30")
        };
        let extend_i30 = parse_index_root(extend_i30.value, index_limits()).unwrap();
        assert_eq!(extend_i30.indexed_attribute_type, FILE_NAME);
        assert_eq!(extend_i30.collation_rule, 1);
        let children: Vec<_> = extend_i30
            .entries()
            .filter_map(|entry| entry.file_name.map(|name| (entry, name)))
            .collect();
        assert_eq!(children.len(), 3);
        let names: Vec<Vec<u16>> = children
            .iter()
            .map(|(_, name)| name.name.code_units().collect())
            .collect();
        assert_eq!(
            names,
            ["$ObjId", "$Quota", "$Reparse"].map(|name| name.encode_utf16().collect::<Vec<_>>())
        );
        for (entry, name) in children {
            assert_eq!(name.parent_directory.record_number, 11);
            assert_eq!(name.parent_directory.sequence_number, 11);
            let reference = entry.file_reference.unwrap();
            assert!(matches!(reference.record_number, 24..=26));
            assert_eq!(reference.sequence_number, 1);
        }

        let named_index_entries = |spec: ExtendRecordSpec, name: &str| {
            let record_number = usize::try_from(spec.record_number).unwrap();
            let parsed = parse_file_record(record(&plan, record_number)).unwrap();
            assert_eq!(parsed.sequence_number, spec.sequence_number);
            assert_eq!(parsed.flags.raw, spec.mft_flags);
            assert!(parsed.flags.is_in_use());
            assert!(parsed.flags.is_metadata());
            assert!(parsed.flags.is_view_index());
            let attributes = parse_attribute_list(
                parsed.repaired_bytes(),
                usize::from(parsed.attributes_offset),
                usize::try_from(parsed.bytes_in_use).unwrap(),
                attr_limits(),
            )
            .unwrap();
            let standard = attributes
                .attributes
                .iter()
                .find(|attribute| attribute.attribute_type == STANDARD_INFORMATION)
                .unwrap();
            let AttributeBody::Resident(standard) = &standard.body else {
                panic!("resident child standard information")
            };
            assert_eq!(
                u32::from_le_bytes(standard.value[32..36].try_into().unwrap()),
                spec.standard_information_file_attributes
            );
            let file_name = attributes
                .attributes
                .iter()
                .find(|attribute| attribute.attribute_type == FILE_NAME)
                .unwrap();
            let AttributeBody::Resident(file_name) = &file_name.body else {
                panic!("resident child file name")
            };
            assert_eq!(
                u64::from_le_bytes(file_name.value[..8].try_into().unwrap()),
                mft_reference_with_sequence(spec.parent_record_number, spec.parent_sequence_number)
            );
            assert_eq!(
                u32::from_le_bytes(file_name.value[56..60].try_into().unwrap()),
                spec.file_name_attributes
            );
            let expected_name: Vec<u16> = name.encode_utf16().collect();
            let root = attributes
                .attributes
                .iter()
                .find(|attribute| {
                    attribute.attribute_type == INDEX_ROOT
                        && attribute
                            .name
                            .as_ref()
                            .is_some_and(|value| value.code_units == expected_name)
                })
                .unwrap();
            let AttributeBody::Resident(root) = &root.body else {
                panic!("resident view index")
            };
            assert!(root.value.len() >= 32);
            let expected_index = expected
                .namespace
                .indexes
                .iter()
                .find(|index| index.owner_record_number == spec.record_number && index.name == name)
                .unwrap();
            assert_eq!(
                u32::from_le_bytes(root.value[..4].try_into().unwrap()),
                expected_index.indexed_attribute_type
            );
            assert_eq!(
                u32::from_le_bytes(root.value[4..8].try_into().unwrap()),
                expected_index.collation_rule
            );
            assert!(expected_index.resident);
            root.value[32..].to_vec()
        };
        let serialized = NtfsExtendMetadata {
            namespace: expected.namespace.clone(),
            quota_q_index_entries: named_index_entries(expected.namespace.quota, "$Q"),
            quota_o_index_entries: named_index_entries(expected.namespace.quota, "$O"),
            object_id_o_index_entries: named_index_entries(expected.namespace.object_id, "$O"),
            reparse_r_index_entries: named_index_entries(expected.namespace.reparse, "$R"),
        };
        assert_eq!(serialized, expected);
        let validation = validate_ntfs3g_extend_metadata(
            NtfsExtendProfile::MkntfsNtfs31,
            &serialized,
            NtfsExtendLimits::default(),
        )
        .unwrap();
        assert_eq!(validation.child_count, 3);
        assert!(!validation.activation_authorized);

        let root_index = parse_index_block(root_index_block(&plan), Some(0), index_limits())
            .unwrap()
            .entries()
            .find(|entry| {
                entry
                    .file_name
                    .is_some_and(|name| name.name.code_units().eq("$Extend".encode_utf16()))
            })
            .unwrap();
        assert_eq!(root_index.file_reference.unwrap().record_number, 11);
        assert_eq!(root_index.file_reference.unwrap().sequence_number, 11);
        for number in 12..24 {
            assert!(
                !parse_file_record(record(&plan, number))
                    .unwrap()
                    .flags
                    .is_in_use()
            );
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn mft_bitmap_system_names_and_boot_region_roundtrip() {
        let plan = plan_ntfs_destination(
            &graph(Some(b"metadata".to_vec()), false),
            inputs(),
            NtfsSerializeLimits::default(),
        )
        .unwrap();
        let layout = metadata_layout(4096, (IMAGE_BYTES / 512 - 1) / 8, 28, 0x400fc, 0).unwrap();

        let mft = parse_file_record(record(&plan, 0)).unwrap();
        let mft_attrs = parse_attribute_list(
            mft.repaired_bytes(),
            usize::from(mft.attributes_offset),
            usize::try_from(mft.bytes_in_use).unwrap(),
            attr_limits(),
        )
        .unwrap();
        assert!(
            mft_attrs
                .attributes
                .iter()
                .any(|attribute| attribute.attribute_type == FILE_NAME)
        );
        let mft_bitmap = mft_attrs
            .attributes
            .iter()
            .find(|attribute| attribute.attribute_type == BITMAP)
            .unwrap();
        let AttributeBody::NonResident(mft_bitmap) = &mft_bitmap.body else {
            panic!("nonresident MFT bitmap")
        };
        assert_eq!(mft_bitmap.sizes.unwrap().data, MIN_MFT_BITMAP_BYTES);
        let runs = parse_mapping_pairs(
            mft_bitmap.mapping_pairs,
            MappingPairsLimits {
                starting_vcn: 0,
                expected_next_vcn: Some(layout.mft_bitmap_clusters),
                volume_cluster_count: IMAGE_BYTES / 4096,
                max_runs: 2,
                max_decoded_clusters: 2,
            },
        )
        .unwrap();
        assert_eq!(
            runs.extents[0].location,
            crate::fs::ntfs_runlist::ExtentLocation::Physical {
                lcn: layout.mft_bitmap_lcn
            }
        );
        let bitmap_offset = usize::try_from(layout.mft_bitmap_lcn * layout.cluster).unwrap()
            - usize::try_from(SECTOR_BYTES).unwrap();
        let bitmap = &plan.staging_writes[0].bytes
            [bitmap_offset..bitmap_offset + usize::try_from(MIN_MFT_BITMAP_BYTES).unwrap()];
        for record in 0..=11 {
            assert_ne!(bitmap[record / 8] & (1 << (record % 8)), 0);
        }
        for record in 12..24 {
            assert_eq!(bitmap[record / 8] & (1 << (record % 8)), 0);
        }
        for record in 24..=27 {
            assert_ne!(bitmap[record / 8] & (1 << (record % 8)), 0);
        }

        let expected_names = [
            "$MFT", "$MFTMirr", "$LogFile", "$Volume", "$AttrDef", ".", "$Bitmap", "$Boot",
            "$BadClus", "$Secure", "$UpCase",
        ];
        for (record_number, expected) in expected_names.into_iter().enumerate() {
            let parsed = parse_file_record(record(&plan, record_number)).unwrap();
            let attrs = parse_attribute_list(
                parsed.repaired_bytes(),
                usize::from(parsed.attributes_offset),
                usize::try_from(parsed.bytes_in_use).unwrap(),
                attr_limits(),
            )
            .unwrap();
            let name = attrs
                .attributes
                .iter()
                .find(|attribute| attribute.attribute_type == FILE_NAME)
                .unwrap();
            let AttributeBody::Resident(name) = &name.body else {
                panic!("resident FILE_NAME")
            };
            let length = usize::from(name.value[64]);
            let actual: Vec<u16> = (0..length)
                .map(|index| read_u16(name.value, 66 + index * 2))
                .collect();
            assert_eq!(actual, expected.encode_utf16().collect::<Vec<_>>());
        }
        let extend = parse_file_record(record(&plan, 11)).unwrap();
        assert_eq!(extend.sequence_number, 11);

        let boot = parse_file_record(record(&plan, 7)).unwrap();
        let attrs = parse_attribute_list(
            boot.repaired_bytes(),
            usize::from(boot.attributes_offset),
            usize::try_from(boot.bytes_in_use).unwrap(),
            attr_limits(),
        )
        .unwrap();
        let data = attrs
            .attributes
            .iter()
            .find(|attribute| attribute.attribute_type == DATA)
            .unwrap();
        let AttributeBody::NonResident(data) = &data.body else {
            panic!("nonresident $Boot data")
        };
        assert_eq!(data.sizes.unwrap().data, BOOT_FILE_BYTES);
        assert_eq!(data.sizes.unwrap().initialized, BOOT_FILE_BYTES);
        assert!(
            plan.staging_writes[0].bytes[..8192 - 512]
                .iter()
                .all(|byte| *byte == 0)
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn mandatory_metadata_payloads_wrappers_and_bitmap_roundtrip() {
        let plan = plan_ntfs_destination(
            &graph(Some(b"metadata".to_vec()), false),
            inputs(),
            NtfsSerializeLimits::default(),
        )
        .unwrap();
        let secure = generate_ntfs_secure_metadata(
            NtfsSecureProfile::MkntfsWindows2003Ntfs31,
            NtfsSecureLimits::default(),
        )
        .unwrap();
        let layout = metadata_layout(
            4096,
            (IMAGE_BYTES / SECTOR_BYTES - 1) / 8,
            28,
            secure.sds.len(),
            0,
        )
        .unwrap();

        let attrdef = staged_bytes(
            &plan,
            layout.attrdef_lcn * layout.cluster,
            NTFS3X_ATTRDEF_BYTES,
        );
        let attrdef_table = validate_ntfs3x_attrdef(attrdef, AttrDefLimits::default()).unwrap();
        assert_eq!(attrdef_table.definition_count(), 15);
        let attrdef_record = parse_file_record(record(&plan, 4)).unwrap();
        let attrdef_attrs = parse_attribute_list(
            attrdef_record.repaired_bytes(),
            usize::from(attrdef_record.attributes_offset),
            usize::try_from(attrdef_record.bytes_in_use).unwrap(),
            attr_limits(),
        )
        .unwrap();
        let AttributeBody::NonResident(attrdef_data) = &attrdef_attrs
            .attributes
            .iter()
            .find(|attribute| attribute.attribute_type == DATA)
            .unwrap()
            .body
        else {
            panic!("nonresident $AttrDef")
        };
        assert_eq!(
            attrdef_data.sizes.unwrap().data,
            u64::try_from(NTFS3X_ATTRDEF_BYTES).unwrap()
        );

        let logfile = staged_bytes(
            &plan,
            layout.logfile_lcn * layout.cluster,
            usize::try_from(NTFS_LOGFILE_MIN_BYTES).unwrap(),
        );
        let logfile_validation =
            validate_ntfs_logfile(logfile, NtfsLogFileLimits::default()).unwrap();
        assert_eq!(logfile_validation.profile, NtfsLogFileProfile::Ntfs3gErased);
        assert!(logfile_validation.is_clean);
        let logfile_record = parse_file_record(record(&plan, 2)).unwrap();
        let logfile_attrs = parse_attribute_list(
            logfile_record.repaired_bytes(),
            usize::from(logfile_record.attributes_offset),
            usize::try_from(logfile_record.bytes_in_use).unwrap(),
            attr_limits(),
        )
        .unwrap();
        let AttributeBody::NonResident(logfile_data) = &logfile_attrs
            .attributes
            .iter()
            .find(|attribute| attribute.attribute_type == DATA)
            .unwrap()
            .body
        else {
            panic!("nonresident $LogFile")
        };
        assert_eq!(logfile_data.sizes.unwrap().data, NTFS_LOGFILE_MIN_BYTES);
        let logfile_runs = parse_mapping_pairs(
            logfile_data.mapping_pairs,
            MappingPairsLimits {
                starting_vcn: 0,
                expected_next_vcn: Some(layout.logfile_clusters),
                volume_cluster_count: layout.cluster_count,
                max_runs: 1,
                max_decoded_clusters: layout.logfile_clusters,
            },
        )
        .unwrap();
        assert_eq!(
            logfile_runs.extents[0].location,
            crate::fs::ntfs_runlist::ExtentLocation::Physical {
                lcn: layout.logfile_lcn
            }
        );

        let badclus_record = parse_file_record(record(&plan, 8)).unwrap();
        let badclus_attrs = parse_attribute_list(
            badclus_record.repaired_bytes(),
            usize::from(badclus_record.attributes_offset),
            usize::try_from(badclus_record.bytes_in_use).unwrap(),
            attr_limits(),
        )
        .unwrap();
        assert!(badclus_attrs.attributes.iter().any(|attribute| {
            attribute.attribute_type == DATA
                && attribute.name.is_none()
                && matches!(&attribute.body, AttributeBody::Resident(value) if value.value.is_empty())
        }));
        let bad = badclus_attrs
            .attributes
            .iter()
            .find(|attribute| {
                attribute.attribute_type == DATA
                    && attribute
                        .name
                        .as_ref()
                        .is_some_and(|name| name.code_units == BADCLUS_STREAM_NAME)
            })
            .unwrap();
        let AttributeBody::NonResident(bad_body) = &bad.body else {
            panic!("nonresident $Bad")
        };
        let bad_sizes = bad_body.sizes.unwrap();
        validate_empty_badclus(
            EmptyBadClusRef {
                attribute_type: bad.attribute_type,
                name: &bad.name.as_ref().unwrap().code_units,
                attribute_flags: bad.flags.raw,
                compression_unit: bad_body.compression_unit,
                lowest_vcn: bad_body.lowest_vcn,
                highest_vcn: bad_body.highest_vcn.unwrap(),
                allocated_size: bad_sizes.allocated,
                data_size: bad_sizes.data,
                initialized_size: bad_sizes.initialized,
                mapping_pairs: bad_body.mapping_pairs,
            },
            layout.cluster_count,
            u32::try_from(layout.cluster).unwrap(),
            BadClusLimits::default(),
        )
        .unwrap();

        let secure_record = parse_file_record(record(&plan, 9)).unwrap();
        let secure_attrs = parse_attribute_list(
            secure_record.repaired_bytes(),
            usize::from(secure_record.attributes_offset),
            usize::try_from(secure_record.bytes_in_use).unwrap(),
            attr_limits(),
        )
        .unwrap();
        let descriptor_stream = secure_attrs
            .attributes
            .iter()
            .find(|attribute| {
                attribute.attribute_type == DATA
                    && attribute.name.as_ref().is_some_and(|name| {
                        name.code_units == "$SDS".encode_utf16().collect::<Vec<_>>()
                    })
            })
            .unwrap();
        let AttributeBody::NonResident(descriptor_stream) = &descriptor_stream.body else {
            panic!("nonresident $SDS")
        };
        assert_eq!(
            descriptor_stream.sizes.unwrap().data,
            layout.secure_sds_bytes
        );
        let descriptor_runs = parse_mapping_pairs(
            descriptor_stream.mapping_pairs,
            MappingPairsLimits {
                starting_vcn: 0,
                expected_next_vcn: Some(layout.secure_sds_clusters),
                volume_cluster_count: layout.cluster_count,
                max_runs: 1,
                max_decoded_clusters: layout.secure_sds_clusters,
            },
        )
        .unwrap();
        assert_eq!(
            descriptor_runs.extents[0].location,
            crate::fs::ntfs_runlist::ExtentLocation::Physical {
                lcn: layout.secure_sds_lcn
            }
        );
        let named_resident = |name: &str| {
            let expected: Vec<u16> = name.encode_utf16().collect();
            secure_attrs
                .attributes
                .iter()
                .find(|attribute| {
                    attribute.attribute_type == INDEX_ROOT
                        && attribute
                            .name
                            .as_ref()
                            .is_some_and(|value| value.code_units == expected)
                })
                .and_then(|attribute| match &attribute.body {
                    AttributeBody::Resident(value) => Some(value.value),
                    AttributeBody::NonResident(_) => None,
                })
                .unwrap()
        };
        let sii = named_resident("$SII");
        let sdh = named_resident("$SDH");
        let serialized_secure = NtfsSecureMetadata {
            sds: staged_bytes(
                &plan,
                layout.secure_sds_lcn * layout.cluster,
                usize::try_from(layout.secure_sds_bytes).unwrap(),
            )
            .to_vec(),
            sii_index_entries: sii[32..].to_vec(),
            sdh_index_entries: sdh[32..].to_vec(),
            sii_collation_rule: u32::from_le_bytes(sii[4..8].try_into().unwrap()),
            sdh_collation_rule: u32::from_le_bytes(sdh[4..8].try_into().unwrap()),
        };
        assert_eq!(serialized_secure, secure);
        assert_eq!(
            validate_ntfs_secure_metadata(&serialized_secure, NtfsSecureLimits::default())
                .unwrap()
                .descriptors
                .len(),
            2
        );

        let bitmap_offset = layout.bitmap_lcn * layout.cluster;
        let bitmap = staged_bytes(
            &plan,
            bitmap_offset,
            usize::try_from(layout.cluster_count.div_ceil(8)).unwrap(),
        );
        let is_allocated = |cluster: u64| {
            bitmap[usize::try_from(cluster / 8).unwrap()] & (1 << (cluster % 8)) != 0
        };
        let boot_clusters = div_ceil(BOOT_FILE_BYTES, layout.cluster).unwrap();
        assert!((0..boot_clusters).all(is_allocated));
        assert!((boot_clusters..MFT_LCN).all(|cluster| !is_allocated(cluster)));
        assert!((MFT_LCN..layout.metadata_clusters).all(is_allocated));
        for cluster in [
            layout.logfile_lcn,
            layout.logfile_lcn + layout.logfile_clusters - 1,
            layout.attrdef_lcn,
            layout.attrdef_lcn + layout.attrdef_clusters - 1,
            layout.secure_sds_lcn,
            layout.secure_sds_lcn + layout.secure_sds_clusters - 1,
        ] {
            assert!(is_allocated(cluster));
        }
    }

    #[test]
    fn nonempty_bad_cluster_evidence_is_refused_before_empty_badclus_serialization() {
        assert!(matches!(
            plan_ntfs_destination(
                &graph_with_bad_cluster(),
                inputs(),
                NtfsSerializeLimits::default()
            ),
            Err(NtfsSerializeError::NonemptyBadClustersUnsupported { extents: 1 })
        ));
    }

    #[test]
    fn physical_mapping_pairs_and_requirements_roundtrip() {
        let plan =
            plan_ntfs_destination(&graph(None, true), inputs(), NtfsSerializeLimits::default())
                .unwrap();
        assert_eq!(plan.source_allocations.len(), 1);
        let file = parse_file_record(record(&plan, 27)).unwrap();
        let attrs = parse_attribute_list(
            file.repaired_bytes(),
            file.attributes_offset as usize,
            file.bytes_in_use as usize,
            attr_limits(),
        )
        .unwrap();
        let data = attrs
            .attributes
            .iter()
            .find(|attribute| attribute.attribute_type == DATA)
            .unwrap();
        let AttributeBody::NonResident(data) = &data.body else {
            panic!("nonresident data")
        };
        let runs = parse_mapping_pairs(
            data.mapping_pairs,
            MappingPairsLimits {
                starting_vcn: 0,
                expected_next_vcn: Some(1),
                volume_cluster_count: IMAGE_BYTES / 4096,
                max_runs: 4,
                max_decoded_clusters: 4,
            },
        )
        .unwrap();
        assert_eq!(
            runs.extents[0].location,
            crate::fs::ntfs_runlist::ExtentLocation::Physical { lcn: 2048 }
        );
    }

    #[test]
    fn output_is_deterministic_and_sector_aligned() {
        let graph = graph(Some(b"same".to_vec()), false);
        let first =
            plan_ntfs_destination(&graph, inputs(), NtfsSerializeLimits::default()).unwrap();
        let second =
            plan_ntfs_destination(&graph, inputs(), NtfsSerializeLimits::default()).unwrap();
        assert_eq!(first, second);
        assert!(
            first
                .staging_writes
                .iter()
                .all(|write| write.offset % 512 == 0 && write.bytes.len() % 512 == 0)
        );
        assert_eq!(first.primary_boot_write.offset, 0);
        assert_eq!(first.backup_boot_write.offset, IMAGE_BYTES - 512);
    }

    #[test]
    fn complete_candidate_roundtrips_through_read_only_inspection() {
        let graph = graph(Some(b"inspected".to_vec()), false);
        let plan = plan_ntfs_destination(&graph, inputs(), NtfsSerializeLimits::default()).unwrap();
        let mut image = vec![0_u8; usize::try_from(IMAGE_BYTES).unwrap()];
        for write in &plan.staging_writes {
            let offset = usize::try_from(write.offset).unwrap();
            image[offset..offset + write.bytes.len()].copy_from_slice(&write.bytes);
        }
        let backup = usize::try_from(plan.backup_boot_write.offset).unwrap();
        image[backup..backup + 512].copy_from_slice(&plan.backup_boot_write.bytes);
        // The primary is deliberately absent until the final activation phase.
        assert!(parse_boot_sector(&image[..512]).is_err());
        image[..512].copy_from_slice(&plan.primary_boot_write.bytes);
        let temp = TempImage::create(&image);
        let inspection = crate::inspect::inspect_image(&temp.0).unwrap();
        let inventory = inspection.ntfs_inventory.as_ref().unwrap();
        for record_number in [11_u64, 24, 25, 26, 27] {
            assert!(
                inventory
                    .objects
                    .iter()
                    .any(|object| object.reference.record_number == record_number)
            );
        }
        let extend = inventory
            .objects
            .iter()
            .find(|object| object.reference.record_number == 11)
            .unwrap();
        assert!(extend.is_directory);
        assert!(!extend.is_metadata);
        assert_eq!(extend.directory_entries.len(), 3);
        let normalized = inspection.normalized_ntfs.as_ref().unwrap();
        assert!(matches!(
            normalized.preservation.security_descriptors,
            crate::fs::ntfs_normalize::NtfsSecurityDescriptorEvidence::PinnedNtfs3gWindows2003 { .. }
        ));
        assert!(
            normalized
                .graph
                .objects()
                .iter()
                .all(|object| !matches!(object.id.0, 11 | 24..=26))
        );
        for record_number in [11_u64, 24, 25, 26] {
            assert!(
                normalized
                    .preservation
                    .objects
                    .iter()
                    .any(|object| { object.source.reference.record_number == record_number })
            );
        }
        assert!(inspection.profile.inventory_complete);
    }

    #[test]
    fn exact_volume_label_roundtrips_and_invalid_labels_fail_before_planning() {
        let graph = two_file_graph();
        let metadata = exact_metadata();
        let label: Vec<u16> = "STAR★".encode_utf16().collect();
        let plan = plan_ntfs_destination_with_metadata_and_volume(
            &graph,
            inputs(),
            &metadata,
            NtfsVolumeProfile {
                volume_label: Some(&label),
            },
            NtfsSerializeLimits::default(),
        )
        .unwrap();
        let mut image = vec![0_u8; usize::try_from(IMAGE_BYTES).unwrap()];
        for write in &plan.staging_writes {
            let offset = usize::try_from(write.offset).unwrap();
            image[offset..offset + write.bytes.len()].copy_from_slice(&write.bytes);
        }
        let backup = usize::try_from(plan.backup_boot_write.offset).unwrap();
        image[backup..backup + 512].copy_from_slice(&plan.backup_boot_write.bytes);
        image[..512].copy_from_slice(&plan.primary_boot_write.bytes);
        let temp = TempImage::create(&image);
        let inspection = crate::inspect::inspect_image(&temp.0).unwrap();
        assert_eq!(
            inspection.ntfs_inventory.as_ref().unwrap().volume_label,
            crate::fs::ntfs_inventory::NtfsVolumeLabelEvidence::Exact(label.clone())
        );
        assert_eq!(
            inspection
                .normalized_ntfs
                .as_ref()
                .unwrap()
                .preservation
                .volume_label,
            Some(label)
        );

        let too_long = vec![u16::from(b'A'); 33];
        assert!(matches!(
            plan_ntfs_destination_with_metadata_and_volume(
                &graph,
                inputs(),
                &metadata,
                NtfsVolumeProfile {
                    volume_label: Some(&too_long),
                },
                NtfsSerializeLimits::default(),
            ),
            Err(NtfsSerializeError::InvalidVolumeLabel { .. })
        ));
        assert!(matches!(
            plan_ntfs_destination_with_metadata_and_volume(
                &graph,
                inputs(),
                &metadata,
                NtfsVolumeProfile {
                    volume_label: Some(&[0xd800]),
                },
                NtfsSerializeLimits::default(),
            ),
            Err(NtfsSerializeError::InvalidVolumeLabel { .. })
        ));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn exact_object_metadata_survives_inventory_and_normalization() {
        let graph = two_file_graph();
        let metadata = exact_metadata();
        let plan = plan_ntfs_destination_with_metadata(
            &graph,
            inputs(),
            &metadata,
            NtfsSerializeLimits::default(),
        )
        .unwrap();
        assert_eq!(plan.activation_gaps(), ACTIVATION_GAPS);
        assert!(
            !plan
                .activation_gaps()
                .iter()
                .any(|gap| gap.contains("timestamps"))
        );

        for (record_number, expected) in [(27_usize, metadata[1]), (28, metadata[2])] {
            let parsed = parse_file_record(record(&plan, record_number)).unwrap();
            let attrs = parse_attribute_list(
                parsed.repaired_bytes(),
                usize::from(parsed.attributes_offset),
                usize::try_from(parsed.bytes_in_use).unwrap(),
                attr_limits(),
            )
            .unwrap();
            let name = attrs
                .attributes
                .iter()
                .find(|attribute| attribute.attribute_type == FILE_NAME)
                .unwrap();
            let AttributeBody::Resident(name) = &name.body else {
                panic!("resident file name")
            };
            for (offset, timestamp) in [
                expected.timestamps.creation_time,
                expected.timestamps.modification_time,
                expected.timestamps.mft_change_time,
                expected.timestamps.access_time,
            ]
            .into_iter()
            .enumerate()
            {
                assert_eq!(
                    u64::from_le_bytes(
                        name.value[8 + offset * 8..16 + offset * 8]
                            .try_into()
                            .unwrap()
                    ),
                    timestamp
                );
            }
            assert_eq!(
                u32::from_le_bytes(name.value[56..60].try_into().unwrap()),
                expected.dos_file_attributes
            );
        }
        let root_record = parse_file_record(record(&plan, 5)).unwrap();
        let root_attrs = parse_attribute_list(
            root_record.repaired_bytes(),
            usize::from(root_record.attributes_offset),
            usize::try_from(root_record.bytes_in_use).unwrap(),
            attr_limits(),
        )
        .unwrap();
        let root_index = root_attrs
            .attributes
            .iter()
            .find(|attribute| attribute.attribute_type == INDEX_ROOT)
            .unwrap();
        let AttributeBody::Resident(root_index) = &root_index.body else {
            panic!("resident root index")
        };
        let root_index = parse_index_root(root_index.value, index_limits()).unwrap();
        assert_eq!(root_index.entries().next().unwrap().child_vcn, Some(0));
        let root_index =
            parse_index_block(root_index_block(&plan), Some(0), index_limits()).unwrap();
        for entry in root_index.entries().filter(|entry| {
            entry
                .file_reference
                .is_some_and(|reference| matches!(reference.record_number, 27 | 28))
        }) {
            let record_number = entry.file_reference.unwrap().record_number;
            let expected = if record_number == 27 {
                metadata[1]
            } else {
                metadata[2]
            };
            let key = entry.file_name.unwrap();
            assert_eq!(key.creation_time, expected.timestamps.creation_time);
            assert_eq!(key.modification_time, expected.timestamps.modification_time);
            assert_eq!(key.mft_change_time, expected.timestamps.mft_change_time);
            assert_eq!(key.access_time, expected.timestamps.access_time);
            assert_eq!(key.file_attributes, expected.dos_file_attributes);
        }

        let mut image = vec![0_u8; usize::try_from(IMAGE_BYTES).unwrap()];
        for write in &plan.staging_writes {
            let offset = usize::try_from(write.offset).unwrap();
            image[offset..offset + write.bytes.len()].copy_from_slice(&write.bytes);
        }
        let backup = usize::try_from(plan.backup_boot_write.offset).unwrap();
        image[backup..backup + 512].copy_from_slice(&plan.backup_boot_write.bytes);
        image[..512].copy_from_slice(&plan.primary_boot_write.bytes);
        let temp = TempImage::create(&image);
        let inspection = crate::inspect::inspect_image(&temp.0).unwrap();
        let normalized = inspection.normalized_ntfs.unwrap();

        for (record_number, expected) in [(27_u64, metadata[1]), (28, metadata[2])] {
            let preserved = normalized
                .preservation
                .objects
                .iter()
                .find(|object| object.source.reference.record_number == record_number)
                .unwrap();
            let standard = preserved.source.standard_information.unwrap();
            assert_eq!(standard.creation_time, expected.timestamps.creation_time);
            assert_eq!(
                standard.modification_time,
                expected.timestamps.modification_time
            );
            assert_eq!(
                standard.mft_change_time,
                expected.timestamps.mft_change_time
            );
            assert_eq!(standard.access_time, expected.timestamps.access_time);
            assert_eq!(standard.file_attributes, expected.dos_file_attributes);
            assert_eq!(standard.security_id, Some(expected.security_id));
            assert_eq!(
                preserved.source.file_names[0].file_attributes,
                expected.dos_file_attributes
            );
        }
    }

    #[test]
    fn exact_object_metadata_refuses_caps_duplicates_missing_and_kind_mismatch() {
        let graph = two_file_graph();
        let metadata = exact_metadata();
        let mut over_cap = metadata.clone();
        over_cap.push(metadata[0]);
        assert!(matches!(
            plan_ntfs_destination_with_metadata(
                &graph,
                inputs(),
                &over_cap,
                NtfsSerializeLimits {
                    max_objects: 3,
                    ..NtfsSerializeLimits::default()
                },
            ),
            Err(NtfsSerializeError::MetadataEntryLimitExceeded {
                actual: 4,
                maximum: 3
            })
        ));

        let duplicate = [metadata[0], metadata[1], metadata[1]];
        assert!(matches!(
            plan_ntfs_destination_with_metadata(
                &graph,
                inputs(),
                &duplicate,
                NtfsSerializeLimits::default(),
            ),
            Err(NtfsSerializeError::DuplicateObjectMetadata {
                object: ObjectId(2)
            })
        ));
        assert!(matches!(
            plan_ntfs_destination_with_metadata(
                &graph,
                inputs(),
                &metadata[..2],
                NtfsSerializeLimits::default(),
            ),
            Err(NtfsSerializeError::MissingObjectMetadata {
                object: ObjectId(3)
            })
        ));

        let mut wrong_kind = metadata.clone();
        wrong_kind[1].object_kind = ObjectKind::Directory;
        wrong_kind[1].dos_file_attributes |= FILE_ATTRIBUTE_DIRECTORY;
        assert!(matches!(
            plan_ntfs_destination_with_metadata(
                &graph,
                inputs(),
                &wrong_kind,
                NtfsSerializeLimits::default(),
            ),
            Err(NtfsSerializeError::ObjectMetadataKindMismatch {
                object: ObjectId(2),
                ..
            })
        ));

        let mut wrong_flags = metadata;
        wrong_flags[2].dos_file_attributes |= FILE_ATTRIBUTE_DIRECTORY;
        assert!(matches!(
            plan_ntfs_destination_with_metadata(
                &graph,
                inputs(),
                &wrong_flags,
                NtfsSerializeLimits::default(),
            ),
            Err(NtfsSerializeError::ObjectMetadataAttributesMismatch {
                object: ObjectId(3),
                ..
            })
        ));

        let mut wrong_security = exact_metadata();
        wrong_security[1].security_id = 0x100;
        assert!(matches!(
            plan_ntfs_destination_with_metadata(
                &graph,
                inputs(),
                &wrong_security,
                NtfsSerializeLimits::default(),
            ),
            Err(NtfsSerializeError::ObjectMetadataSecurityProfileMismatch {
                object: ObjectId(2),
                security_id: 0x100,
            })
        ));
    }

    #[test]
    fn fragmented_nonresident_runs_preserve_relative_lcns_and_initialized_size() {
        let root = ObjectRecord {
            id: ObjectId(1),
            kind: ObjectKind::Directory,
            link_count: 0,
            semantics: ObjectSemantics::default(),
            streams: vec![],
        };
        let stream = ObjectStream {
            id: StreamId(9),
            name: None,
            logical_bytes: 5000,
            initialized_bytes: 4097,
            mapped_bytes: 8192,
            allocated_bytes: 8192,
            flags: StreamFlags::default(),
            storage: StreamStorage::Extents,
        };
        let file = ObjectRecord {
            id: ObjectId(2),
            kind: ObjectKind::File,
            link_count: 1,
            semantics: ObjectSemantics::default(),
            streams: vec![stream],
        };
        let graph = ObjectGraph::build(
            ObjectId(1),
            vec![root, file],
            vec![NamespaceEntry {
                parent: ObjectId(1),
                target: ObjectId(2),
                name: "fragmented.bin".encode_utf16().collect(),
            }],
            ExtentGraph::build(
                vec![
                    Extent {
                        stream: StreamId(9),
                        logical_offset: 0,
                        length: 4096,
                        placement: Placement::Physical {
                            byte_offset: 9 * 1024 * 1024,
                        },
                        kind: ExtentKind::FileData,
                    },
                    Extent {
                        stream: StreamId(9),
                        logical_offset: 4096,
                        length: 4096,
                        placement: Placement::Physical {
                            byte_offset: 8 * 1024 * 1024,
                        },
                        kind: ExtentKind::FileData,
                    },
                ],
                IMAGE_BYTES,
                4,
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
        let plan = plan_ntfs_destination(&graph, inputs(), NtfsSerializeLimits::default()).unwrap();
        let file = parse_file_record(record(&plan, 27)).unwrap();
        let attrs = parse_attribute_list(
            file.repaired_bytes(),
            usize::from(file.attributes_offset),
            usize::try_from(file.bytes_in_use).unwrap(),
            attr_limits(),
        )
        .unwrap();
        let data = attrs
            .attributes
            .iter()
            .find(|attribute| attribute.attribute_type == DATA)
            .unwrap();
        let AttributeBody::NonResident(data) = &data.body else {
            panic!("nonresident data")
        };
        assert_eq!(data.sizes.unwrap().initialized, 4097);
        let runs = parse_mapping_pairs(
            data.mapping_pairs,
            MappingPairsLimits {
                starting_vcn: 0,
                expected_next_vcn: Some(2),
                volume_cluster_count: IMAGE_BYTES / 4096,
                max_runs: 4,
                max_decoded_clusters: 4,
            },
        )
        .unwrap();
        assert_eq!(runs.encoded_runs, 2);
        assert_eq!(
            runs.extents[1].location,
            crate::fs::ntfs_runlist::ExtentLocation::Physical { lcn: 2048 }
        );
    }

    #[test]
    fn two_user_directories_spill_validate_parse_and_remain_deterministic() {
        let graph = two_spilled_directories_graph(36);
        let first =
            plan_ntfs_destination(&graph, inputs(), NtfsSerializeLimits::default()).unwrap();
        let second =
            plan_ntfs_destination(&graph, inputs(), NtfsSerializeLimits::default()).unwrap();
        assert_eq!(first, second);
        let upcase = generate_ntfs3g_windows61_upcase(NtfsUpcaseLimits::default()).unwrap();

        for directory in [ObjectId(2), ObjectId(3)] {
            let record_number = first
                .object_placements
                .iter()
                .find(|placement| placement.object == directory)
                .unwrap()
                .record_number;
            let artifact =
                directory_index_artifact(&first, usize::try_from(record_number).unwrap());
            assert!(artifact.block_vcns.len() >= 2);
            validate_serialized_ntfs_directory_index(
                &artifact,
                upcase.mappings(),
                NtfsDirectoryIndexGeometry {
                    cluster_bytes: first.cluster_bytes,
                    index_block_bytes: 4096,
                    resident_root_bytes: RECORD_BYTES,
                },
                directory_index_limits(NtfsSerializeLimits::default()),
            )
            .unwrap();
            let root = parse_index_root(&artifact.index_root, index_limits()).unwrap();
            assert!(root.entries().all(|entry| entry.child_vcn.is_some()));
            let mut names: BTreeSet<Vec<u16>> = root
                .entries()
                .filter_map(|entry| entry.file_name)
                .map(|name| name.name.code_units().collect())
                .collect();
            for (block, expected_vcn) in artifact
                .index_allocation
                .chunks_exact(usize::try_from(INDEX_BLOCK_BYTES).unwrap())
                .zip(artifact.block_vcns.iter().copied())
            {
                let parsed = parse_index_block(block, Some(expected_vcn), index_limits()).unwrap();
                names.extend(
                    parsed
                        .entries()
                        .filter_map(|entry| entry.file_name)
                        .map(|name| name.name.code_units().collect::<Vec<_>>()),
                );
            }
            assert_eq!(names.len(), 36);
            assert!(
                names.contains(
                    &"Ωmega-directory-index-entry.txt"
                        .encode_utf16()
                        .collect::<Vec<_>>()
                )
            );
            assert!(
                names.contains(
                    &"Éclair-directory-index-entry.txt"
                        .encode_utf16()
                        .collect::<Vec<_>>()
                )
            );

            let mut malformed = artifact.clone();
            malformed.index_allocation[510] ^= 1;
            assert!(
                validate_serialized_ntfs_directory_index(
                    &malformed,
                    upcase.mappings(),
                    NtfsDirectoryIndexGeometry {
                        cluster_bytes: first.cluster_bytes,
                        index_block_bytes: 4096,
                        resident_root_bytes: RECORD_BYTES,
                    },
                    directory_index_limits(NtfsSerializeLimits::default()),
                )
                .is_err()
            );
        }
    }

    #[test]
    fn spilled_directory_candidate_roundtrips_through_regular_image_inventory() {
        let graph = two_spilled_directories_graph(36);
        let plan = plan_ntfs_destination(&graph, inputs(), NtfsSerializeLimits::default()).unwrap();
        let temp = TempImage::create(&activated_image(&plan));
        let inspection = crate::inspect::inspect_image(&temp.0).unwrap();
        let inventory = inspection.ntfs_inventory.as_ref().unwrap();
        for directory in [ObjectId(2), ObjectId(3)] {
            let record_number = plan
                .object_placements
                .iter()
                .find(|placement| placement.object == directory)
                .unwrap()
                .record_number;
            let inventoried = inventory
                .objects
                .iter()
                .find(|object| object.reference.record_number == record_number)
                .unwrap();
            assert!(inventoried.is_directory);
            assert_eq!(inventoried.directory_entries.len(), 36);
        }
        assert!(inspection.profile.inventory_complete);
    }

    #[test]
    fn sub_cluster_directory_indexes_round_trip_at_large_cluster_sizes() {
        let graph = two_spilled_directories_graph(36);
        for cluster_bytes in [8192, 65_536] {
            let mut geometry = inputs();
            geometry.cluster_bytes = cluster_bytes;
            let plan =
                plan_ntfs_destination(&graph, geometry, NtfsSerializeLimits::default()).unwrap();
            assert_eq!(plan.cluster_bytes, cluster_bytes);
            assert_eq!(i8::from_ne_bytes([plan.primary_boot_write.bytes[68]]), -12);

            let temp = TempImage::create(&activated_image(&plan));
            let inspection = crate::inspect::inspect_image(&temp.0).unwrap();
            let inventory = inspection.ntfs_inventory.as_ref().unwrap();
            for directory in [ObjectId(2), ObjectId(3)] {
                let record_number = plan
                    .object_placements
                    .iter()
                    .find(|placement| placement.object == directory)
                    .unwrap()
                    .record_number;
                let inventoried = inventory
                    .objects
                    .iter()
                    .find(|object| object.reference.record_number == record_number)
                    .unwrap();
                assert!(inventoried.is_directory);
                assert_eq!(inventoried.directory_entries.len(), 36);
            }
            assert!(inspection.profile.inventory_complete);
        }
    }

    #[test]
    fn directory_index_limits_and_pinned_collisions_fail_closed() {
        let graph = two_spilled_directories_graph(36);

        let allocation_limited = NtfsSerializeLimits {
            max_index_allocation_bytes: 4095,
            ..NtfsSerializeLimits::default()
        };
        assert!(matches!(
            plan_ntfs_destination(&graph, inputs(), allocation_limited),
            Err(NtfsSerializeError::DirectoryIndex {
                source: NtfsDirectoryIndexError::AllocationLimitExceeded { .. },
                ..
            })
        ));
        let block_limited = NtfsSerializeLimits {
            max_index_blocks: 1,
            ..NtfsSerializeLimits::default()
        };
        assert!(matches!(
            plan_ntfs_destination(&graph, inputs(), block_limited),
            Err(NtfsSerializeError::DirectoryIndex {
                source: NtfsDirectoryIndexError::BlockLimitExceeded { .. },
                ..
            })
        ));

        let base = two_file_graph();
        let collision = ObjectGraph::build(
            base.root(),
            base.objects().to_vec(),
            vec![
                NamespaceEntry {
                    parent: base.root(),
                    target: ObjectId(2),
                    name: "ω.txt".encode_utf16().collect(),
                },
                NamespaceEntry {
                    parent: base.root(),
                    target: ObjectId(3),
                    name: "Ω.txt".encode_utf16().collect(),
                },
            ],
            base.extents().clone(),
            ObjectGraphLimits {
                max_objects: 8,
                max_entries: 8,
                max_streams: 8,
                max_name_code_units: 255,
            },
        )
        .unwrap();
        assert!(matches!(
            plan_ntfs_destination(&collision, inputs(), NtfsSerializeLimits::default()),
            Err(NtfsSerializeError::CaseCollision {
                parent: ObjectId(1)
            })
        ));
    }

    #[test]
    fn refuses_bad_geometry_caps_and_unapplied_relocation_conflicts() {
        let empty_graph = graph(Some(Vec::new()), false);
        let mut bad = inputs();
        bad.cluster_bytes = 1000;
        assert!(matches!(
            plan_ntfs_destination(&empty_graph, bad, NtfsSerializeLimits::default()),
            Err(NtfsSerializeError::InvalidImageGeometry)
        ));
        bad.cluster_bytes = 1024;
        assert!(matches!(
            plan_ntfs_destination(&empty_graph, bad, NtfsSerializeLimits::default()),
            Err(NtfsSerializeError::InvalidImageGeometry)
        ));
        let reserved_graph = ObjectGraph::build(
            empty_graph.root(),
            empty_graph.objects().to_vec(),
            vec![NamespaceEntry {
                parent: empty_graph.root(),
                target: ObjectId(2),
                name: "$mft".encode_utf16().collect(),
            }],
            empty_graph.extents().clone(),
            ObjectGraphLimits {
                max_objects: 8,
                max_entries: 8,
                max_streams: 8,
                max_name_code_units: 255,
            },
        )
        .unwrap();
        assert!(matches!(
            plan_ntfs_destination(&reserved_graph, inputs(), NtfsSerializeLimits::default()),
            Err(NtfsSerializeError::ReservedRootName {
                target: ObjectId(2)
            })
        ));
        let capped = NtfsSerializeLimits {
            max_objects: 1,
            ..NtfsSerializeLimits::default()
        };
        assert!(matches!(
            plan_ntfs_destination(&empty_graph, inputs(), capped),
            Err(NtfsSerializeError::ObjectLimitExceeded { .. })
        ));
        let root = ObjectRecord {
            id: ObjectId(1),
            kind: ObjectKind::Directory,
            link_count: 0,
            semantics: ObjectSemantics::default(),
            streams: vec![],
        };
        let stream = ObjectStream {
            id: StreamId(9),
            name: None,
            logical_bytes: 4,
            initialized_bytes: 4,
            mapped_bytes: 4096,
            allocated_bytes: 4096,
            flags: StreamFlags::default(),
            storage: StreamStorage::Extents,
        };
        let file = ObjectRecord {
            id: ObjectId(2),
            kind: ObjectKind::File,
            link_count: 1,
            semantics: ObjectSemantics::default(),
            streams: vec![stream],
        };
        let conflict = ObjectGraph::build(
            ObjectId(1),
            vec![root, file],
            vec![NamespaceEntry {
                parent: ObjectId(1),
                target: ObjectId(2),
                name: vec![u16::from(b'x')],
            }],
            ExtentGraph::build(
                vec![Extent {
                    stream: StreamId(9),
                    logical_offset: 0,
                    length: 4096,
                    placement: Placement::Physical { byte_offset: 4096 },
                    kind: ExtentKind::FileData,
                }],
                IMAGE_BYTES,
                2,
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
            plan_ntfs_destination(&conflict, inputs(), NtfsSerializeLimits::default()),
            Err(NtfsSerializeError::PayloadMetadataConflict { .. })
        ));
    }
}
