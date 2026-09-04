//! Versioned, bounded preservation policy for cross-format conversion.
//!
//! This module performs no I/O. It classifies every semantic family represented by the neutral
//! object graph and both normalization sidecars. Where a normalizer retained only a summary and
//! not the bytes required to reproduce a source feature, the policy reports a refusal instead of
//! inventing a default. Escrow is a deterministic binary snapshot of all available sidecar
//! evidence, protected by a CRC-32 checksum and explicit resource limits.

#![allow(clippy::module_name_repetitions)]

use std::collections::BTreeSet;
use std::fmt;

use crc32fast::Hasher;

use crate::extent::{Extent, ExtentKind, Placement};
use crate::fs::exfat_inventory::{ExfatObjectFlags, ExfatTimestamps};
use crate::fs::exfat_normalize::{ExfatPreservationSidecar, NormalizedExfat};
use crate::fs::exfat_upcase_serialize::{
    RecommendedExfatUpcaseLimits, generate_recommended_exfat_upcase,
};
use crate::fs::ntfs_index::FileNameNamespace;
use crate::fs::ntfs_inventory::{
    NtfsAttributeEvidence, NtfsDataStream, NtfsDirectoryEntry, NtfsExtentPlacement, NtfsFileName,
    NtfsInventoryExtent, NtfsName, NtfsObject, NtfsObjectReference, NtfsStandardInformation,
    NtfsStreamStorage,
};
use crate::fs::ntfs_normalize::{
    NormalizedNtfs, NtfsObjectPreservation, NtfsPreservationSidecar, NtfsSecurityDescriptorEvidence,
};
use crate::fs::ntfs_secure::{NtfsSecureLimits, NtfsSecureProfile, generate_ntfs_secure_metadata};
use crate::object::{ObjectGraph, ObjectId};
use crate::{FileSystem, GuaranteeMode};

const ESCROW_MAGIC: [u8; 8] = *b"SCESCROW";
/// Current on-disk escrow schema version.
pub const ESCROW_SCHEMA_VERSION: u16 = 4;
const HEADER_BYTES: usize = 28;
const RECORD_HEADER_BYTES: usize = 6;
const EXFAT_SOURCE: u8 = 1;
const NTFS_SOURCE: u8 = 2;

/// One preservation-relevant semantic or exact source-evidence family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum PreservationField {
    Content = 1,
    ObjectKinds = 2,
    DirectoryHierarchy = 3,
    AlternateDataStreams = 4,
    HardLinks = 5,
    SecurityDescriptors = 6,
    SecurityIdentifiers = 7,
    SparseAllocation = 8,
    Compression = 9,
    Encryption = 10,
    ReparsePoints = 11,
    Timestamps = 12,
    DosAttributes = 13,
    NamesAndCase = 14,
    NtfsNameNamespaces = 15,
    CaseMappingTable = 16,
    VolumeLabel = 17,
    VolumeSerial = 18,
    ExfatBenignEntries = 19,
    ExfatPadding = 20,
    BadClusters = 21,
    FileSystemMetadataExtents = 22,
    AllocationTopology = 23,
    InventoryAccounting = 24,
    NtfsAttributes = 25,
}

impl PreservationField {
    const ALL: [Self; 25] = [
        Self::Content,
        Self::ObjectKinds,
        Self::DirectoryHierarchy,
        Self::AlternateDataStreams,
        Self::HardLinks,
        Self::SecurityDescriptors,
        Self::SecurityIdentifiers,
        Self::SparseAllocation,
        Self::Compression,
        Self::Encryption,
        Self::ReparsePoints,
        Self::Timestamps,
        Self::DosAttributes,
        Self::NamesAndCase,
        Self::NtfsNameNamespaces,
        Self::CaseMappingTable,
        Self::VolumeLabel,
        Self::VolumeSerial,
        Self::ExfatBenignEntries,
        Self::ExfatPadding,
        Self::BadClusters,
        Self::FileSystemMetadataExtents,
        Self::AllocationTopology,
        Self::InventoryAccounting,
        Self::NtfsAttributes,
    ];

    fn from_tag(tag: u16) -> Option<Self> {
        Self::ALL.into_iter().find(|field| *field as u16 == tag)
    }
}

/// How one field can be represented by the requested destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldDisposition {
    /// The target has an equivalent native representation.
    Native,
    /// A deterministic and reversible semantic transformation is available.
    CanonicalTransform,
    /// Native target storage is insufficient; exact sidecar evidence must be escrowed.
    EscrowRequired,
    /// Required evidence is missing or the source content cannot safely be materialized.
    Refusal,
}

/// Stable evidence behind one field classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldAssessment {
    pub field: PreservationField,
    pub disposition: FieldDisposition,
    pub reason: &'static str,
}

/// Explicit caller caps for classification and escrow construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreservationLimits {
    pub max_assessments: usize,
    pub max_escrow_bytes: usize,
    pub max_record_bytes: usize,
}

impl Default for PreservationLimits {
    fn default() -> Self {
        Self {
            max_assessments: PreservationField::ALL.len(),
            max_escrow_bytes: 64 * 1024 * 1024,
            max_record_bytes: 64 * 1024 * 1024,
        }
    }
}

/// A complete policy result. A rejected result is still useful because it enumerates every
/// blocker and every content-only loss instead of stopping at the first unsupported field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreservationReport {
    pub schema_version: u16,
    pub source: FileSystem,
    pub target: FileSystem,
    pub mode: GuaranteeMode,
    pub permitted: bool,
    pub assessments: Vec<FieldAssessment>,
    pub blockers: Vec<PreservationField>,
    pub explicit_losses: Vec<PreservationField>,
    pub escrow: Option<Vec<u8>>,
}

/// One validated record from an escrow payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EscrowRecord {
    pub field: PreservationField,
    pub value: Vec<u8>,
}

/// Exact exFAT volume identity recovered from a validated schema-v4 escrow snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExfatVolumeIdentity {
    pub volume_serial_number: u32,
    pub volume_label: ExfatVolumeLabelIdentity,
}

/// Distinguishes label absence from an exact value and from deliberately unretained padding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExfatVolumeLabelIdentity {
    Absent,
    Exact(Vec<u16>),
    /// Logical label and nonzero unused slots were observed, but the raw padding was not retained.
    UnretainedNonzeroPadding,
}

/// Exact NTFS volume identity recovered from a validated schema-v4 escrow snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsVolumeIdentity {
    pub volume_serial_number: u64,
    pub volume_label: NtfsVolumeLabelIdentity,
}

/// Distinguishes a proven absent record-3 `$VOLUME_NAME` from its exact UTF-16 value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NtfsVolumeLabelIdentity {
    Absent,
    Exact(Vec<u16>),
}

/// Exact NTFS security evidence recovered from the canonical escrow snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NtfsSecurityDescriptorEscrow {
    Unavailable,
    PinnedNtfs3gWindows2003 { sds: Vec<u8> },
}

/// Validated, versioned escrow contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedEscrow {
    pub schema_version: u16,
    pub source: FileSystem,
    pub target: FileSystem,
    pub records: Vec<EscrowRecord>,
    pub exfat_volume_identity: Option<ExfatVolumeIdentity>,
    pub ntfs_volume_identity: Option<NtfsVolumeIdentity>,
    pub ntfs_security_descriptors: Option<NtfsSecurityDescriptorEscrow>,
}

/// Policy or escrow-schema failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreservationError {
    InvalidLimit(&'static str),
    SameSourceAndTarget(FileSystem),
    UnsupportedFilesystem(FileSystem),
    AssessmentLimitExceeded { required: usize, maximum: usize },
    EscrowLimitExceeded { required: usize, maximum: usize },
    RecordLimitExceeded { required: usize, maximum: usize },
    AllocationFailed,
    ArithmeticOverflow,
    MalformedEscrow { offset: usize, reason: &'static str },
    UnsupportedSchemaVersion(u16),
    ChecksumMismatch { stored: u32, computed: u32 },
}

impl fmt::Display for PreservationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit(field) => write!(formatter, "preservation limit {field} is zero"),
            Self::SameSourceAndTarget(filesystem) => {
                write!(formatter, "source and target are both {filesystem}")
            }
            Self::UnsupportedFilesystem(filesystem) => {
                write!(
                    formatter,
                    "unsupported preservation filesystem {filesystem}"
                )
            }
            Self::AssessmentLimitExceeded { required, maximum } => write!(
                formatter,
                "{required} preservation assessments exceed limit {maximum}"
            ),
            Self::EscrowLimitExceeded { required, maximum } => {
                write!(
                    formatter,
                    "escrow requires {required} bytes, exceeding {maximum}"
                )
            }
            Self::RecordLimitExceeded { required, maximum } => write!(
                formatter,
                "escrow record requires {required} bytes, exceeding {maximum}"
            ),
            Self::AllocationFailed => formatter.write_str("preservation allocation failed"),
            Self::ArithmeticOverflow => formatter.write_str("preservation accounting overflowed"),
            Self::MalformedEscrow { offset, reason } => {
                write!(formatter, "malformed escrow at byte {offset}: {reason}")
            }
            Self::UnsupportedSchemaVersion(version) => {
                write!(formatter, "unsupported escrow schema version {version}")
            }
            Self::ChecksumMismatch { stored, computed } => write!(
                formatter,
                "escrow checksum mismatch: stored {stored:#010x}, computed {computed:#010x}"
            ),
        }
    }
}

impl std::error::Error for PreservationError {}

/// Classifies normalized exFAT evidence for conversion to NTFS.
///
/// # Errors
///
/// Returns an error only for invalid targets, cap exhaustion, allocation failure, or arithmetic
/// overflow. Unsupported semantics are returned as explicit policy blockers.
pub fn evaluate_exfat(
    normalized: &NormalizedExfat,
    target: FileSystem,
    mode: GuaranteeMode,
    limits: PreservationLimits,
) -> Result<PreservationReport, PreservationError> {
    validate_request(FileSystem::ExFat, target, limits)?;
    let assessments = exfat_assessments(normalized)?;
    finish_report(
        FileSystem::ExFat,
        target,
        mode,
        assessments,
        limits,
        |writer| encode_exfat_sidecar(writer, &normalized.preservation),
    )
}

/// Classifies normalized NTFS evidence for conversion to exFAT.
///
/// # Errors
///
/// Returns an error only for invalid targets, cap exhaustion, allocation failure, or arithmetic
/// overflow. Unsupported semantics are returned as explicit policy blockers.
pub fn evaluate_ntfs(
    normalized: &NormalizedNtfs,
    target: FileSystem,
    mode: GuaranteeMode,
    limits: PreservationLimits,
) -> Result<PreservationReport, PreservationError> {
    validate_request(FileSystem::Ntfs, target, limits)?;
    let assessments = ntfs_assessments(normalized)?;
    finish_report(
        FileSystem::Ntfs,
        target,
        mode,
        assessments,
        limits,
        |writer| encode_ntfs_sidecar(writer, &normalized.preservation),
    )
}

fn validate_request(
    source: FileSystem,
    target: FileSystem,
    limits: PreservationLimits,
) -> Result<(), PreservationError> {
    if limits.max_assessments == 0 {
        return Err(PreservationError::InvalidLimit("max_assessments"));
    }
    if limits.max_escrow_bytes == 0 {
        return Err(PreservationError::InvalidLimit("max_escrow_bytes"));
    }
    if limits.max_record_bytes == 0 {
        return Err(PreservationError::InvalidLimit("max_record_bytes"));
    }
    if source == target {
        return Err(PreservationError::SameSourceAndTarget(source));
    }
    if target == FileSystem::Unknown {
        return Err(PreservationError::UnsupportedFilesystem(target));
    }
    if PreservationField::ALL.len() > limits.max_assessments {
        return Err(PreservationError::AssessmentLimitExceeded {
            required: PreservationField::ALL.len(),
            maximum: limits.max_assessments,
        });
    }
    Ok(())
}

const fn assessment(
    field: PreservationField,
    disposition: FieldDisposition,
    reason: &'static str,
) -> FieldAssessment {
    FieldAssessment {
        field,
        disposition,
        reason,
    }
}

fn base_assessments() -> Result<Vec<FieldAssessment>, PreservationError> {
    let mut assessments = Vec::new();
    assessments
        .try_reserve_exact(PreservationField::ALL.len())
        .map_err(|_| PreservationError::AllocationFailed)?;
    for field in PreservationField::ALL {
        assessments.push(assessment(
            field,
            FieldDisposition::Native,
            "feature is absent or native",
        ));
    }
    Ok(assessments)
}

fn set(
    assessments: &mut [FieldAssessment],
    field: PreservationField,
    disposition: FieldDisposition,
    reason: &'static str,
) {
    if let Some(value) = assessments.iter_mut().find(|value| value.field == field) {
        *value = assessment(field, disposition, reason);
    }
}

#[allow(clippy::too_many_lines)]
fn exfat_assessments(
    normalized: &NormalizedExfat,
) -> Result<Vec<FieldAssessment>, PreservationError> {
    let sidecar = &normalized.preservation;
    let mut result = base_assessments()?;
    set(
        &mut result,
        PreservationField::Timestamps,
        FieldDisposition::EscrowRequired,
        "raw exFAT timestamps, centiseconds, and UTC-offset validity need escrow",
    );
    set(
        &mut result,
        PreservationField::DosAttributes,
        FieldDisposition::CanonicalTransform,
        "the exFAT attribute subset maps reversibly to NTFS file attributes",
    );
    set(
        &mut result,
        PreservationField::NamesAndCase,
        FieldDisposition::CanonicalTransform,
        "exact UTF-16 names remain native while lookup collation changes",
    );
    set(
        &mut result,
        PreservationField::CaseMappingTable,
        FieldDisposition::EscrowRequired,
        "the exact exFAT 65,536-entry up-case mapping is format-specific",
    );
    set(
        &mut result,
        PreservationField::VolumeSerial,
        FieldDisposition::CanonicalTransform,
        "the exact exFAT 32-bit serial can be reversibly embedded in the NTFS serial field",
    );
    if sidecar.volume_label.is_some() {
        set(
            &mut result,
            PreservationField::VolumeLabel,
            FieldDisposition::CanonicalTransform,
            "the exact zero-padded exFAT UTF-16 label maps to NTFS $VOLUME_NAME",
        );
    } else if sidecar.root.directory.volume_labels > 0 {
        set(
            &mut result,
            PreservationField::VolumeLabel,
            FieldDisposition::Refusal,
            "a label was present with nonzero padding whose exact bytes were not retained",
        );
    }
    let evidence = sidecar.directory_evidence;
    if evidence.benign_primary_sets != 0 || evidence.benign_secondary_entries != 0 {
        set(
            &mut result,
            PreservationField::ExfatBenignEntries,
            FieldDisposition::Refusal,
            "normalization retained benign-entry counts but not their exact raw entry sets",
        );
    }
    let object_has_benign = sidecar
        .objects
        .iter()
        .any(|object| object.flags.benign_secondary_entries != 0);
    if object_has_benign {
        set(
            &mut result,
            PreservationField::ExfatBenignEntries,
            FieldDisposition::Refusal,
            "object evidence retained benign-secondary counts but not their exact bytes",
        );
    }
    let nonzero_name_padding = evidence.nonzero_name_padding_sets != 0
        || sidecar
            .objects
            .iter()
            .any(|object| !object.flags.name_padding_zeroed);
    if nonzero_name_padding || evidence.nonzero_volume_label_padding {
        set(
            &mut result,
            PreservationField::ExfatPadding,
            FieldDisposition::Refusal,
            "nonzero exFAT padding was observed but its exact bytes were not retained",
        );
    }
    if sidecar.allocated_bad_clusters != 0 {
        let bad_extents = sidecar
            .filesystem_extents
            .iter()
            .filter(|extent| extent.kind == ExtentKind::BadCluster)
            .count();
        let bad_count = usize::try_from(sidecar.allocated_bad_clusters)
            .map_err(|_| PreservationError::ArithmeticOverflow)?;
        set(
            &mut result,
            PreservationField::BadClusters,
            if bad_extents == bad_count {
                FieldDisposition::EscrowRequired
            } else {
                FieldDisposition::Refusal
            },
            if bad_extents == bad_count {
                "exact bad-cluster extents require format-specific escrow"
            } else {
                "bad-cluster count is not backed by one exact extent per cluster"
            },
        );
    }
    if !sidecar.filesystem_extents.is_empty() {
        set(
            &mut result,
            PreservationField::FileSystemMetadataExtents,
            FieldDisposition::EscrowRequired,
            "source metadata placement is not a target filesystem semantic",
        );
    }
    if sidecar
        .objects
        .iter()
        .any(|object| !object.clusters.is_empty())
    {
        set(
            &mut result,
            PreservationField::AllocationTopology,
            FieldDisposition::EscrowRequired,
            "exact FAT-chain and contiguous allocation topology is format-specific",
        );
    }
    set(
        &mut result,
        PreservationField::InventoryAccounting,
        FieldDisposition::EscrowRequired,
        "root discovery and allocation accounting are retained as source provenance",
    );
    debug_assert_eq!(result.len(), PreservationField::ALL.len());
    Ok(result)
}

#[allow(clippy::too_many_lines)]
fn ntfs_assessments(
    normalized: &NormalizedNtfs,
) -> Result<Vec<FieldAssessment>, PreservationError> {
    let graph = &normalized.graph;
    let sidecar = &normalized.preservation;
    let mut result = base_assessments()?;
    let unsupported_attributes = sidecar.objects.iter().any(|preserved| {
        preserved.source.attribute_census.is_empty()
            || preserved
                .source
                .attribute_census
                .iter()
                .any(|attribute| !ntfs_attribute_supported(attribute))
    });
    set(
        &mut result,
        PreservationField::NtfsAttributes,
        if unsupported_attributes {
            FieldDisposition::Refusal
        } else {
            FieldDisposition::Native
        },
        if unsupported_attributes {
            "the complete NTFS attribute census contains missing, unrecognized, or unsupported attribute evidence"
        } else {
            "every inventoried NTFS attribute is in the bounded common-subset allowlist"
        },
    );
    if has_named_stream(graph) {
        set(
            &mut result,
            PreservationField::AlternateDataStreams,
            FieldDisposition::EscrowRequired,
            "exFAT has no native alternate data stream namespace",
        );
    }
    if graph.objects().iter().any(|object| object.link_count > 1) {
        set(
            &mut result,
            PreservationField::HardLinks,
            FieldDisposition::EscrowRequired,
            "exFAT cannot represent multiple directory entries for one object identity",
        );
    }
    if graph
        .objects()
        .iter()
        .any(|object| object.semantics.has_security_descriptor)
    {
        let exact_pinned = matches!(
            sidecar.security_descriptors,
            NtfsSecurityDescriptorEvidence::PinnedNtfs3gWindows2003 { .. }
        ) && sidecar
            .objects
            .iter()
            .filter(|preserved| {
                graph
                    .objects()
                    .iter()
                    .any(|object| object.id == preserved.object)
            })
            .all(|object| {
                object
                    .source
                    .standard_information
                    .and_then(|standard| standard.security_id)
                    .is_none_or(|security_id| matches!(security_id, 0x100 | 0x101))
            });
        set(
            &mut result,
            PreservationField::SecurityDescriptors,
            if exact_pinned {
                FieldDisposition::EscrowRequired
            } else {
                FieldDisposition::Refusal
            },
            if exact_pinned {
                "exact pinned self-relative descriptors are retained in escrow while exFAT cannot enforce them"
            } else {
                "object security presence is known but exact self-relative descriptor bytes are absent"
            },
        );
    }
    if sidecar.objects.iter().any(|object| {
        object
            .source
            .standard_information
            .is_some_and(|standard| standard.security_id.is_some() || standard.owner_id.is_some())
    }) {
        set(
            &mut result,
            PreservationField::SecurityIdentifiers,
            FieldDisposition::EscrowRequired,
            "NTFS owner and security identifiers are format-specific",
        );
    }
    classify_stream_flags(graph, &mut result);
    classify_ntfs_reparse_points(graph, sidecar, &mut result);
    set(
        &mut result,
        PreservationField::Timestamps,
        FieldDisposition::EscrowRequired,
        "NTFS timestamps include 100-ns precision and MFT-change time absent from exFAT",
    );
    let unsupported_attributes = sidecar.objects.iter().any(|object| {
        object
            .source
            .standard_information
            .is_some_and(|standard| standard.file_attributes & !u32::from(0x37_u16) != 0)
    });
    set(
        &mut result,
        PreservationField::DosAttributes,
        if unsupported_attributes {
            FieldDisposition::EscrowRequired
        } else {
            FieldDisposition::CanonicalTransform
        },
        if unsupported_attributes {
            "NTFS attributes outside the exFAT subset require escrow"
        } else {
            "the shared DOS attribute subset maps reversibly"
        },
    );
    let names = classify_ntfs_names_for_exfat(graph)?;
    set(
        &mut result,
        PreservationField::NamesAndCase,
        match names {
            NtfsExfatNameClass::Compatible => FieldDisposition::CanonicalTransform,
            NtfsExfatNameClass::CaseCollision => FieldDisposition::EscrowRequired,
            NtfsExfatNameClass::Illegal => FieldDisposition::Refusal,
        },
        match names {
            NtfsExfatNameClass::Compatible => {
                "all names are legal and collision-free under the recommended exFAT up-case table"
            }
            NtfsExfatNameClass::CaseCollision => {
                "sibling names collide under the recommended exFAT up-case table and must be dest-native disambiguated"
            }
            NtfsExfatNameClass::Illegal => "a name is illegal under exFAT",
        },
    );
    if sidecar
        .objects
        .iter()
        .any(|object| !object.source.file_names.is_empty())
    {
        set(
            &mut result,
            PreservationField::NtfsNameNamespaces,
            FieldDisposition::EscrowRequired,
            "POSIX, Win32, DOS, and combined NTFS filename namespaces are format-specific",
        );
    }
    set(
        &mut result,
        PreservationField::CaseMappingTable,
        FieldDisposition::CanonicalTransform,
        "destination exFAT uses its canonical generated up-case table",
    );
    let (label_disposition, label_reason) = match &sidecar.volume_label {
        None => (
            FieldDisposition::Native,
            "proven NTFS label absence maps to exFAT label absence",
        ),
        Some(units) if is_canonical_exfat_volume_label(units) => (
            FieldDisposition::CanonicalTransform,
            "the exact NTFS UTF-16 label satisfies exFAT length and legality constraints",
        ),
        Some(_) => (
            FieldDisposition::EscrowRequired,
            "the exact NTFS label is not provably representable as an exFAT volume label",
        ),
    };
    set(
        &mut result,
        PreservationField::VolumeLabel,
        label_disposition,
        label_reason,
    );
    set(
        &mut result,
        PreservationField::VolumeSerial,
        FieldDisposition::EscrowRequired,
        "the exact 64-bit NTFS serial cannot fit exFAT's 32-bit serial field without truncation",
    );
    let bad_clusters = classify_ntfs_bad_clusters(sidecar);
    set(
        &mut result,
        PreservationField::BadClusters,
        match bad_clusters {
            NtfsBadClusterEvidence::EntirelySparse | NtfsBadClusterEvidence::Physical => {
                FieldDisposition::EscrowRequired
            }
            NtfsBadClusterEvidence::Incomplete => FieldDisposition::Refusal,
        },
        match bad_clusters {
            NtfsBadClusterEvidence::EntirelySparse => {
                "$BadClus:$Bad is completely mapped and entirely sparse; its exact mapping remains in escrow"
            }
            NtfsBadClusterEvidence::Physical => {
                "$BadClus:$Bad physical runs mark dest-native unusable clusters; the exact NTFS runlist remains in escrow"
            }
            NtfsBadClusterEvidence::Incomplete => {
                "complete unambiguous $BadClus:$Bad mapping evidence is unavailable"
            }
        },
    );
    if !sidecar.source_extents.is_empty() {
        set(
            &mut result,
            PreservationField::FileSystemMetadataExtents,
            FieldDisposition::EscrowRequired,
            "source stream placements and metadata extents require escrow",
        );
        set(
            &mut result,
            PreservationField::AllocationTopology,
            FieldDisposition::EscrowRequired,
            "NTFS run placement is not an exFAT semantic",
        );
    }
    set(
        &mut result,
        PreservationField::InventoryAccounting,
        FieldDisposition::EscrowRequired,
        "scan counts and source record evidence are retained as provenance",
    );
    debug_assert_eq!(result.len(), PreservationField::ALL.len());
    Ok(result)
}

const NTFS_STANDARD_INFORMATION: u32 = 0x10;
const NTFS_ATTRIBUTE_LIST: u32 = 0x20;
const NTFS_FILE_NAME: u32 = 0x30;
const NTFS_VOLUME_NAME: u32 = 0x60;
const NTFS_VOLUME_INFORMATION: u32 = 0x70;
const NTFS_DATA: u32 = 0x80;
const NTFS_INDEX_ROOT: u32 = 0x90;
const NTFS_INDEX_ALLOCATION: u32 = 0xa0;
const NTFS_BITMAP: u32 = 0xb0;
const NTFS_REPARSE_POINT: u32 = 0xc0;

fn ntfs_attribute_supported(attribute: &NtfsAttributeEvidence) -> bool {
    if attribute.flags_unknown_bits != 0
        || attribute
            .name
            .as_ref()
            .is_some_and(|name| !name.is_well_formed)
    {
        return false;
    }
    let unnamed = attribute.name.is_none();
    match attribute.attribute_type {
        NTFS_STANDARD_INFORMATION | NTFS_FILE_NAME | NTFS_VOLUME_NAME | NTFS_VOLUME_INFORMATION => {
            unnamed && attribute.resident && attribute.flags_raw == 0
        }
        NTFS_ATTRIBUTE_LIST | NTFS_REPARSE_POINT => unnamed && attribute.flags_raw == 0,
        NTFS_DATA => true,
        NTFS_INDEX_ROOT => attribute.resident && attribute.flags_raw == 0,
        NTFS_INDEX_ALLOCATION => !attribute.resident && attribute.flags_raw == 0,
        NTFS_BITMAP => attribute.flags_raw == 0,
        _ => false,
    }
}

fn classify_ntfs_reparse_points(
    graph: &ObjectGraph,
    sidecar: &NtfsPreservationSidecar,
    result: &mut [FieldAssessment],
) {
    if !graph
        .objects()
        .iter()
        .any(|object| object.semantics.is_reparse_point)
    {
        return;
    }
    let complete = graph
        .objects()
        .iter()
        .filter(|object| object.semantics.is_reparse_point)
        .all(|object| {
            sidecar
                .objects
                .iter()
                .find(|preserved| preserved.object == object.id)
                .and_then(|preserved| preserved.source.reparse_point.as_ref())
                .is_some_and(|payload| payload.len() >= 8)
        });
    set(
        result,
        PreservationField::ReparsePoints,
        if complete {
            FieldDisposition::EscrowRequired
        } else {
            FieldDisposition::Refusal
        },
        if complete {
            "exact $REPARSE_POINT bytes are retained in escrow; dest-native exFAT cannot enforce reparse semantics"
        } else {
            "reparse presence is known but the reparse attribute payload is absent"
        },
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NtfsBadClusterEvidence {
    Incomplete,
    EntirelySparse,
    Physical,
}

fn classify_ntfs_bad_clusters(sidecar: &NtfsPreservationSidecar) -> NtfsBadClusterEvidence {
    const BADCLUS_RECORD: u64 = 8;
    const BAD_NAME: &[u16] = &[0x24, 0x42, 0x61, 0x64];

    let mut matching = sidecar
        .objects
        .iter()
        .filter(|preserved| preserved.source.reference.record_number == BADCLUS_RECORD)
        .flat_map(|preserved| preserved.source.data_streams.iter())
        .filter(|stream| {
            stream
                .name
                .as_ref()
                .is_some_and(|name| name.is_well_formed && name.code_units == BAD_NAME)
        });
    let Some(stream) = matching.next() else {
        return NtfsBadClusterEvidence::Incomplete;
    };
    if matching.next().is_some() {
        return NtfsBadClusterEvidence::Incomplete;
    }
    let NtfsStreamStorage::NonResident {
        data_bytes,
        mapping_complete,
        extents,
        ..
    } = &stream.storage
    else {
        return NtfsBadClusterEvidence::Incomplete;
    };
    if !mapping_complete
        || stream.compressed
        || stream.encrypted
        || *data_bytes == 0
        || extents.is_empty()
    {
        return NtfsBadClusterEvidence::Incomplete;
    }
    // `$BadClus:$Bad` has deliberately unusual size fields in widely deployed formatter output:
    // the attribute need not carry the sparse flag, its allocated size can equal the volume size,
    // and its initialized size can be zero even when its sole mapping-pairs run is sparse. The
    // decoded runlist is therefore the authoritative evidence for whether bad clusters exist.
    if extents
        .iter()
        .all(|extent| matches!(extent.placement, NtfsExtentPlacement::Sparse))
    {
        NtfsBadClusterEvidence::EntirelySparse
    } else {
        NtfsBadClusterEvidence::Physical
    }
}

fn is_canonical_exfat_volume_label(units: &[u16]) -> bool {
    !units.is_empty()
        && units.len() <= 11
        && char::decode_utf16(units.iter().copied()).all(|character| {
            character.is_ok_and(|value| {
                let code = u32::from(value);
                !(code <= 0x1f
                    || matches!(value, '"' | '*' | '/' | ':' | '<' | '>' | '?' | '\\' | '|'))
            })
        })
}

enum NtfsExfatNameClass {
    Compatible,
    CaseCollision,
    Illegal,
}

fn classify_ntfs_names_for_exfat(
    graph: &ObjectGraph,
) -> Result<NtfsExfatNameClass, PreservationError> {
    let table = generate_recommended_exfat_upcase(RecommendedExfatUpcaseLimits::default())
        .map_err(|_| PreservationError::AllocationFailed)?;
    let mut folded = BTreeSet::new();
    let mut collision = false;
    for entry in graph.entries() {
        if !is_legal_exfat_name(&entry.name) {
            return Ok(NtfsExfatNameClass::Illegal);
        }
        let mut mapped = Vec::new();
        mapped
            .try_reserve_exact(entry.name.len())
            .map_err(|_| PreservationError::AllocationFailed)?;
        mapped.extend(entry.name.iter().map(|unit| table.map(*unit)));
        if !folded.insert((entry.parent, mapped)) {
            collision = true;
        }
    }
    Ok(if collision {
        NtfsExfatNameClass::CaseCollision
    } else {
        NtfsExfatNameClass::Compatible
    })
}

pub(crate) fn is_legal_exfat_name(name: &[u16]) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name != [u16::from(b'.')]
        && name != [u16::from(b'.'), u16::from(b'.')]
        && !name.iter().any(|unit| {
            *unit <= 0x1f
                || matches!(
                    *unit,
                    0x22 | 0x2a | 0x2f | 0x3a | 0x3c | 0x3e | 0x3f | 0x5c | 0x7c
                )
        })
        && char::decode_utf16(name.iter().copied()).all(|unit| unit.is_ok())
}

fn has_named_stream(graph: &ObjectGraph) -> bool {
    graph
        .objects()
        .iter()
        .flat_map(|object| &object.streams)
        .any(|stream| stream.name.is_some())
}

fn classify_stream_flags(graph: &ObjectGraph, result: &mut [FieldAssessment]) {
    if graph
        .objects()
        .iter()
        .flat_map(|object| &object.streams)
        .any(|stream| stream.flags.sparse)
    {
        set(
            result,
            PreservationField::SparseAllocation,
            FieldDisposition::EscrowRequired,
            "sparse logical ranges must be materialized for exFAT and escrowed for reversal",
        );
    }
    if graph
        .objects()
        .iter()
        .flat_map(|object| &object.streams)
        .any(|stream| stream.flags.compressed || stream.flags.compression_block_bytes != 0)
    {
        set(
            result,
            PreservationField::Compression,
            FieldDisposition::EscrowRequired,
            "NTFS LZNT1 streams are decompressed into dest-native bytes; the exact compressed mapping stays in escrow",
        );
    }
    if graph
        .objects()
        .iter()
        .flat_map(|object| &object.streams)
        .any(|stream| stream.flags.encrypted)
    {
        set(
            result,
            PreservationField::Encryption,
            FieldDisposition::Refusal,
            "EFS content cannot be promised without proven decryption and key access",
        );
    }
}

fn finish_report<F>(
    source: FileSystem,
    target: FileSystem,
    mode: GuaranteeMode,
    assessments: Vec<FieldAssessment>,
    limits: PreservationLimits,
    encode: F,
) -> Result<PreservationReport, PreservationError>
where
    F: FnOnce(&mut BoundedWriter) -> Result<(), PreservationError>,
{
    let mut blockers = Vec::new();
    let mut losses = Vec::new();
    blockers
        .try_reserve(assessments.len())
        .map_err(|_| PreservationError::AllocationFailed)?;
    losses
        .try_reserve(assessments.len())
        .map_err(|_| PreservationError::AllocationFailed)?;
    for value in &assessments {
        match mode {
            GuaranteeMode::Strict
                if matches!(
                    value.disposition,
                    FieldDisposition::EscrowRequired | FieldDisposition::Refusal
                ) =>
            {
                blockers.push(value.field);
            }
            GuaranteeMode::Escrow if value.disposition == FieldDisposition::Refusal => {
                blockers.push(value.field);
            }
            GuaranteeMode::ContentOnly
                if matches!(
                    value.field,
                    PreservationField::Encryption | PreservationField::NamesAndCase
                ) && value.disposition == FieldDisposition::Refusal =>
            {
                blockers.push(value.field);
                losses.push(value.field);
            }
            GuaranteeMode::ContentOnly
                if matches!(
                    value.disposition,
                    FieldDisposition::EscrowRequired | FieldDisposition::Refusal
                ) =>
            {
                losses.push(value.field);
            }
            _ => {}
        }
    }
    let escrow = if mode == GuaranteeMode::Escrow {
        let mut snapshot = BoundedWriter::new(limits.max_record_bytes);
        encode(&mut snapshot)?;
        Some(build_escrow(source, target, &snapshot.finish(), limits)?)
    } else {
        None
    };
    Ok(PreservationReport {
        schema_version: ESCROW_SCHEMA_VERSION,
        source,
        target,
        mode,
        permitted: blockers.is_empty(),
        assessments,
        blockers,
        explicit_losses: losses,
        escrow,
    })
}

fn build_escrow(
    source: FileSystem,
    target: FileSystem,
    snapshot: &[u8],
    limits: PreservationLimits,
) -> Result<Vec<u8>, PreservationError> {
    let body_len = RECORD_HEADER_BYTES
        .checked_add(snapshot.len())
        .ok_or(PreservationError::ArithmeticOverflow)?;
    let total = HEADER_BYTES
        .checked_add(body_len)
        .ok_or(PreservationError::ArithmeticOverflow)?;
    if total > limits.max_escrow_bytes {
        return Err(PreservationError::EscrowLimitExceeded {
            required: total,
            maximum: limits.max_escrow_bytes,
        });
    }
    let snapshot_len =
        u32::try_from(snapshot.len()).map_err(|_| PreservationError::RecordLimitExceeded {
            required: snapshot.len(),
            maximum: usize::try_from(u32::MAX).unwrap_or(usize::MAX),
        })?;
    let body_len_u64 =
        u64::try_from(body_len).map_err(|_| PreservationError::ArithmeticOverflow)?;
    let mut body = Vec::new();
    body.try_reserve_exact(body_len)
        .map_err(|_| PreservationError::AllocationFailed)?;
    body.extend_from_slice(&(PreservationField::InventoryAccounting as u16).to_le_bytes());
    body.extend_from_slice(&snapshot_len.to_le_bytes());
    body.extend_from_slice(snapshot);
    let mut output = Vec::new();
    output
        .try_reserve_exact(total)
        .map_err(|_| PreservationError::AllocationFailed)?;
    output.extend_from_slice(&ESCROW_MAGIC);
    output.extend_from_slice(&ESCROW_SCHEMA_VERSION.to_le_bytes());
    output.push(filesystem_tag(source)?);
    output.push(filesystem_tag(target)?);
    output.extend_from_slice(&1_u32.to_le_bytes());
    output.extend_from_slice(&body_len_u64.to_le_bytes());
    output.extend_from_slice(&0_u32.to_le_bytes());
    output.extend_from_slice(&body);
    let checksum = escrow_checksum(&output[..24], &output[HEADER_BYTES..]);
    output[24..28].copy_from_slice(&checksum.to_le_bytes());
    Ok(output)
}

/// Validates and decodes a bounded escrow payload.
///
/// # Errors
///
/// Returns [`PreservationError`] for an invalid header, unsupported version, length mismatch,
/// checksum failure, unknown/duplicate/out-of-order field tag, cap exhaustion, or allocation
/// failure.
#[allow(clippy::too_many_lines)]
pub fn decode_escrow(
    bytes: &[u8],
    limits: PreservationLimits,
) -> Result<DecodedEscrow, PreservationError> {
    if bytes.len() > limits.max_escrow_bytes {
        return Err(PreservationError::EscrowLimitExceeded {
            required: bytes.len(),
            maximum: limits.max_escrow_bytes,
        });
    }
    let header = bytes
        .get(..HEADER_BYTES)
        .ok_or(PreservationError::MalformedEscrow {
            offset: 0,
            reason: "truncated header",
        })?;
    if header[..8] != ESCROW_MAGIC {
        return malformed(0, "invalid magic");
    }
    let version = read_u16(header, 8)?;
    if version != ESCROW_SCHEMA_VERSION {
        return Err(PreservationError::UnsupportedSchemaVersion(version));
    }
    let source = filesystem_from_tag(header[10], 10)?;
    let target = filesystem_from_tag(header[11], 11)?;
    if source == target {
        return malformed(11, "source and target match");
    }
    let count = read_u32(header, 12)?;
    let count = usize::try_from(count).map_err(|_| PreservationError::ArithmeticOverflow)?;
    if count != 1 {
        return malformed(12, "schema version 4 requires exactly one snapshot record");
    }
    if count > limits.max_assessments {
        return Err(PreservationError::AssessmentLimitExceeded {
            required: count,
            maximum: limits.max_assessments,
        });
    }
    let body_len = read_u64(header, 16)?;
    let body_len = usize::try_from(body_len).map_err(|_| PreservationError::ArithmeticOverflow)?;
    if HEADER_BYTES.checked_add(body_len) != Some(bytes.len()) {
        return malformed(16, "body length mismatch");
    }
    let stored_checksum = read_u32(header, 24)?;
    let body = &bytes[HEADER_BYTES..];
    let computed_checksum = escrow_checksum(&bytes[..24], body);
    if stored_checksum != computed_checksum {
        return Err(PreservationError::ChecksumMismatch {
            stored: stored_checksum,
            computed: computed_checksum,
        });
    }
    let mut records = Vec::new();
    records
        .try_reserve_exact(count)
        .map_err(|_| PreservationError::AllocationFailed)?;
    let mut cursor = 0_usize;
    let mut previous = None;
    for _ in 0..count {
        let header_end = cursor
            .checked_add(RECORD_HEADER_BYTES)
            .ok_or(PreservationError::ArithmeticOverflow)?;
        let record_header =
            body.get(cursor..header_end)
                .ok_or(PreservationError::MalformedEscrow {
                    offset: HEADER_BYTES + cursor,
                    reason: "truncated record header",
                })?;
        let tag = read_u16(record_header, 0)?;
        let field = PreservationField::from_tag(tag).ok_or(PreservationError::MalformedEscrow {
            offset: HEADER_BYTES + cursor,
            reason: "unknown field tag",
        })?;
        if field != PreservationField::InventoryAccounting {
            return malformed(
                HEADER_BYTES + cursor,
                "schema version 4 record is not the canonical sidecar snapshot",
            );
        }
        if previous.is_some_and(|value| value >= tag) {
            return malformed(HEADER_BYTES + cursor, "duplicate or out-of-order field tag");
        }
        previous = Some(tag);
        let length = read_u32(record_header, 2)?;
        let length = usize::try_from(length).map_err(|_| PreservationError::ArithmeticOverflow)?;
        if length > limits.max_record_bytes {
            return Err(PreservationError::RecordLimitExceeded {
                required: length,
                maximum: limits.max_record_bytes,
            });
        }
        cursor = header_end;
        let end = cursor
            .checked_add(length)
            .ok_or(PreservationError::ArithmeticOverflow)?;
        let value = body
            .get(cursor..end)
            .ok_or(PreservationError::MalformedEscrow {
                offset: HEADER_BYTES + cursor,
                reason: "truncated record value",
            })?;
        validate_snapshot(value, source, HEADER_BYTES + cursor)?;
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(value.len())
            .map_err(|_| PreservationError::AllocationFailed)?;
        owned.extend_from_slice(value);
        records.push(EscrowRecord {
            field,
            value: owned,
        });
        cursor = end;
    }
    if cursor != body.len() {
        return malformed(HEADER_BYTES + cursor, "unclaimed trailing bytes");
    }
    let exfat_volume_identity = if source == FileSystem::ExFat {
        Some(decode_exfat_volume_identity(
            &records[0].value,
            HEADER_BYTES + RECORD_HEADER_BYTES,
        )?)
    } else {
        None
    };
    let ntfs_volume_identity = if source == FileSystem::Ntfs {
        Some(decode_ntfs_volume_identity(
            &records[0].value,
            HEADER_BYTES + RECORD_HEADER_BYTES,
        )?)
    } else {
        None
    };
    let ntfs_security_descriptors = if source == FileSystem::Ntfs {
        Some(decode_ntfs_security_descriptors(
            &records[0].value,
            HEADER_BYTES + RECORD_HEADER_BYTES,
        )?)
    } else {
        None
    };
    Ok(DecodedEscrow {
        schema_version: version,
        source,
        target,
        records,
        exfat_volume_identity,
        ntfs_volume_identity,
        ntfs_security_descriptors,
    })
}

/// Rebuilds the inner NTFS snapshot from a validated schema-v4 escrow payload.
///
/// Only the current inner snapshot (v7) is restored. Historical v3–v6 layouts remain readable
/// for integrity checks through [`decode_escrow`], but they do not authorize identity restore.
///
/// # Errors
///
/// Returns [`PreservationError`] when the outer envelope is invalid, the source is not NTFS, or
/// the inner snapshot is not a complete v7 sidecar.
pub fn decode_ntfs_sidecar_from_escrow(
    bytes: &[u8],
    limits: PreservationLimits,
) -> Result<NtfsPreservationSidecar, PreservationError> {
    let decoded = decode_escrow(bytes, limits)?;
    if decoded.source != FileSystem::Ntfs {
        return malformed(10, "escrow source is not NTFS");
    }
    let snapshot = decoded
        .records
        .first()
        .ok_or(PreservationError::MalformedEscrow {
            offset: HEADER_BYTES,
            reason: "missing NTFS sidecar snapshot",
        })?;
    decode_ntfs_preservation_sidecar(&snapshot.value)
}

/// Rebuilds [`NtfsPreservationSidecar`] from an inner NTFS snapshot v7.
///
/// # Errors
///
/// Returns [`PreservationError`] for an unsupported snapshot version, truncated fields, invalid
/// tags, UTF-16 validity disagreement, or unclaimed trailing bytes.
pub fn decode_ntfs_preservation_sidecar(
    snapshot: &[u8],
) -> Result<NtfsPreservationSidecar, PreservationError> {
    let mut reader = SnapshotCursor::new(snapshot, 0);
    if reader.u16()? != 7 {
        return malformed(0, "unsupported NTFS sidecar snapshot version");
    }
    let volume_serial_number = reader.u64()?;
    let volume_label = decode_ntfs_volume_label(&mut reader)?;
    let security_descriptors = decode_ntfs_security_evidence(&mut reader)?;
    let root_reference = decode_reference(&mut reader)?;
    let object_count = reader.count(1)?;
    let mut objects = Vec::new();
    objects
        .try_reserve_exact(object_count)
        .map_err(|_| PreservationError::AllocationFailed)?;
    for _ in 0..object_count {
        objects.push(NtfsObjectPreservation {
            object: ObjectId(reader.u64()?),
            source: decode_ntfs_object(&mut reader)?,
        });
    }
    let extent_count = reader.count(25)?;
    let mut source_extents = Vec::new();
    source_extents
        .try_reserve_exact(extent_count)
        .map_err(|_| PreservationError::AllocationFailed)?;
    for _ in 0..extent_count {
        source_extents.push(decode_ntfs_extent(&mut reader)?);
    }
    let scanned_records = reader.u64()?;
    let initialized_records = reader.u64()?;
    let in_use_base_records = reader.u64()?;
    let extension_records = reader.u64()?;
    let bytes_read = reader.u64()?;
    reader.finish()?;
    Ok(NtfsPreservationSidecar {
        volume_serial_number,
        volume_label,
        security_descriptors,
        root_reference,
        objects,
        source_extents,
        scanned_records,
        initialized_records,
        in_use_base_records,
        extension_records,
        bytes_read,
    })
}

fn escrow_checksum(header_prefix: &[u8], body: &[u8]) -> u32 {
    let mut hasher = Hasher::new();
    hasher.update(header_prefix);
    hasher.update(body);
    hasher.finalize()
}

fn validate_snapshot(
    bytes: &[u8],
    source: FileSystem,
    offset: usize,
) -> Result<(), PreservationError> {
    let version = bytes.get(..2).ok_or(PreservationError::MalformedEscrow {
        offset,
        reason: "truncated sidecar snapshot version",
    })?;
    let version = u16::from_le_bytes([version[0], version[1]]);
    match source {
        FileSystem::ExFat if version == 2 => validate_exfat_snapshot(bytes, offset),
        FileSystem::Ntfs if version == 7 => {
            validate_ntfs_snapshot(bytes, offset, NtfsSnapshotLayout::V7)
        }
        FileSystem::Ntfs if version == 6 => {
            validate_ntfs_snapshot(bytes, offset, NtfsSnapshotLayout::V6)
        }
        FileSystem::Ntfs if version == 5 => {
            validate_ntfs_snapshot(bytes, offset, NtfsSnapshotLayout::V5)
        }
        FileSystem::Ntfs if version == 4 => {
            validate_ntfs_snapshot(bytes, offset, NtfsSnapshotLayout::V4)
        }
        // Historical development snapshots used version 3 both immediately before and during the
        // attribute-census transition. Both layouts are fully walked; neither can authorize the
        // current census-dependent preservation policy. Version 4 is census-complete without the
        // trailing optional $REPARSE_POINT payload introduced in version 5. Version 6 adds the
        // per-stream compression-unit size. Version 7 appends optional captured named-stream
        // initialized bytes on NonResident storage.
        FileSystem::Ntfs if version == 3 => validate_ntfs_snapshot(
            bytes,
            offset,
            NtfsSnapshotLayout::V3 {
                has_attribute_census: false,
            },
        )
        .or_else(|_| {
            validate_ntfs_snapshot(
                bytes,
                offset,
                NtfsSnapshotLayout::V3 {
                    has_attribute_census: true,
                },
            )
        }),
        FileSystem::Unknown => malformed(offset, "unknown snapshot filesystem"),
        _ => malformed(offset, "unsupported sidecar snapshot version"),
    }
}

#[derive(Debug, Clone, Copy)]
struct SnapshotCursor<'a> {
    bytes: &'a [u8],
    cursor: usize,
    base: usize,
}

impl<'a> SnapshotCursor<'a> {
    const fn new(bytes: &'a [u8], base: usize) -> Self {
        Self {
            bytes,
            cursor: 0,
            base,
        }
    }

    const fn finish(self) -> Result<(), PreservationError> {
        if self.cursor == self.bytes.len() {
            Ok(())
        } else {
            malformed(self.base + self.cursor, "unclaimed snapshot bytes")
        }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], PreservationError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(PreservationError::ArithmeticOverflow)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(PreservationError::MalformedEscrow {
                offset: self.base + self.cursor,
                reason: "truncated sidecar snapshot",
            })?;
        self.cursor = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, PreservationError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, PreservationError> {
        let value = self.take(2)?;
        Ok(u16::from_le_bytes([value[0], value[1]]))
    }

    fn u32(&mut self) -> Result<u32, PreservationError> {
        let value = self.take(4)?;
        Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
    }

    fn u64(&mut self) -> Result<u64, PreservationError> {
        let value = self.take(8)?;
        Ok(u64::from_le_bytes([
            value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
        ]))
    }

    fn usize(&mut self) -> Result<usize, PreservationError> {
        usize::try_from(self.u64()?).map_err(|_| PreservationError::ArithmeticOverflow)
    }

    fn boolean(&mut self) -> Result<bool, PreservationError> {
        let offset = self.base + self.cursor;
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => malformed(offset, "invalid sidecar boolean"),
        }
    }

    fn optional_u32(&mut self) -> Result<(), PreservationError> {
        if self.boolean()? {
            self.u32()?;
        }
        Ok(())
    }

    fn optional_u64(&mut self) -> Result<(), PreservationError> {
        if self.boolean()? {
            self.u64()?;
        }
        Ok(())
    }

    fn count(&mut self, minimum_item_bytes: usize) -> Result<usize, PreservationError> {
        let count_offset = self.base + self.cursor;
        let count = self.usize()?;
        let remaining = self.bytes.len() - self.cursor;
        if minimum_item_bytes != 0 && count > remaining / minimum_item_bytes {
            return malformed(count_offset, "snapshot count exceeds remaining bytes");
        }
        Ok(count)
    }

    fn utf16(&mut self) -> Result<bool, PreservationError> {
        let count = self.count(2)?;
        let byte_length = count
            .checked_mul(2)
            .ok_or(PreservationError::ArithmeticOverflow)?;
        let bytes = self.take(byte_length)?;
        let units = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]));
        let well_formed = char::decode_utf16(units).all(|unit| unit.is_ok());
        Ok(well_formed)
    }

    fn bytes(&mut self) -> Result<(), PreservationError> {
        let length = self.count(1)?;
        self.take(length)?;
        Ok(())
    }

    fn optional_u32_value(&mut self) -> Result<Option<u32>, PreservationError> {
        if self.boolean()? {
            Ok(Some(self.u32()?))
        } else {
            Ok(None)
        }
    }

    fn optional_u64_value(&mut self) -> Result<Option<u64>, PreservationError> {
        if self.boolean()? {
            Ok(Some(self.u64()?))
        } else {
            Ok(None)
        }
    }

    fn utf16_units(&mut self) -> Result<(Vec<u16>, bool), PreservationError> {
        let count = self.count(2)?;
        let byte_length = count
            .checked_mul(2)
            .ok_or(PreservationError::ArithmeticOverflow)?;
        let bytes = self.take(byte_length)?;
        let mut units = Vec::new();
        units
            .try_reserve_exact(count)
            .map_err(|_| PreservationError::AllocationFailed)?;
        for pair in bytes.chunks_exact(2) {
            units.push(u16::from_le_bytes([pair[0], pair[1]]));
        }
        let well_formed = char::decode_utf16(units.iter().copied()).all(|unit| unit.is_ok());
        Ok((units, well_formed))
    }

    fn take_vec(&mut self) -> Result<Vec<u8>, PreservationError> {
        let length = self.count(1)?;
        let bytes = self.take(length)?;
        let mut value = Vec::new();
        value
            .try_reserve_exact(length)
            .map_err(|_| PreservationError::AllocationFailed)?;
        value.extend_from_slice(bytes);
        Ok(value)
    }
}

fn validate_exfat_snapshot(bytes: &[u8], base: usize) -> Result<(), PreservationError> {
    let mut reader = SnapshotCursor::new(bytes, base);
    if reader.u16()? != 2 {
        return malformed(base, "unsupported exFAT sidecar snapshot version");
    }
    reader.u32()?;
    let label_offset = reader.base + reader.cursor;
    match reader.u8()? {
        0 | 2 => {}
        1 => {
            let length_offset = reader.base + reader.cursor;
            let length = usize::from(reader.u8()?);
            if length > 11 {
                return malformed(
                    length_offset,
                    "exFAT snapshot label exceeds 11 UTF-16 units",
                );
            }
            let encoded = reader.take(
                length
                    .checked_mul(2)
                    .ok_or(PreservationError::ArithmeticOverflow)?,
            )?;
            let units = encoded
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]));
            if char::decode_utf16(units).any(|unit| unit.is_err()) {
                return malformed(
                    length_offset,
                    "exFAT snapshot label contains invalid UTF-16",
                );
            }
        }
        _ => return malformed(label_offset, "invalid exFAT snapshot label tag"),
    }
    for _ in 0..5 {
        reader.usize()?;
    }
    reader.boolean()?;
    for _ in 0..4 {
        reader.u8()?;
    }
    reader.u32()?;
    reader.u64()?;
    reader.u32()?;
    reader.u32()?;
    reader.u64()?;
    let mappings = reader.count(2)?;
    reader.take(
        mappings
            .checked_mul(2)
            .ok_or(PreservationError::ArithmeticOverflow)?,
    )?;
    for _ in 0..4 {
        reader.u64()?;
    }
    for _ in 0..3 {
        validate_u32_vector(&mut reader)?;
    }
    let objects = reader.count(1)?;
    for _ in 0..objects {
        reader.u64()?;
        reader.u64()?;
        let components = reader.count(8)?;
        for _ in 0..components {
            let component_offset = reader.base + reader.cursor;
            if !reader.utf16()? {
                return malformed(
                    component_offset,
                    "exFAT snapshot path contains invalid UTF-16",
                );
            }
        }
        reader.u16()?;
        if reader.boolean()? {
            for _ in 0..3 {
                reader.u32()?;
            }
            for _ in 0..5 {
                reader.u8()?;
            }
        }
        validate_u32_vector(&mut reader)?;
        reader.boolean()?;
        reader.boolean()?;
        reader.u8()?;
    }
    let extents = reader.count(26)?;
    for _ in 0..extents {
        validate_extent(&mut reader, true)?;
    }
    for _ in 0..4 {
        reader.u64()?;
    }
    reader.boolean()?;
    reader.u64()?;
    reader.finish()
}

fn validate_u32_vector(reader: &mut SnapshotCursor<'_>) -> Result<(), PreservationError> {
    let count = reader.count(4)?;
    reader.take(
        count
            .checked_mul(4)
            .ok_or(PreservationError::ArithmeticOverflow)?,
    )?;
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum NtfsSnapshotLayout {
    V3 { has_attribute_census: bool },
    V4,
    V5,
    V6,
    V7,
}

impl NtfsSnapshotLayout {
    const fn expected_version(self) -> u16 {
        match self {
            Self::V3 { .. } => 3,
            Self::V4 => 4,
            Self::V5 => 5,
            Self::V6 => 6,
            Self::V7 => 7,
        }
    }

    const fn has_attribute_census(self) -> bool {
        match self {
            Self::V3 {
                has_attribute_census,
            } => has_attribute_census,
            Self::V4 | Self::V5 | Self::V6 | Self::V7 => true,
        }
    }

    const fn has_reparse_payload(self) -> bool {
        matches!(self, Self::V5 | Self::V6 | Self::V7)
    }

    const fn has_stream_compression_block(self) -> bool {
        matches!(self, Self::V6 | Self::V7)
    }

    const fn has_captured_named_payload(self) -> bool {
        matches!(self, Self::V7)
    }
}

fn validate_ntfs_snapshot(
    bytes: &[u8],
    base: usize,
    layout: NtfsSnapshotLayout,
) -> Result<(), PreservationError> {
    let mut reader = SnapshotCursor::new(bytes, base);
    let version = reader.u16()?;
    if version != layout.expected_version() {
        return malformed(base, "unsupported NTFS sidecar snapshot version");
    }
    reader.u64()?;
    if reader.boolean()? {
        let length_offset = reader.base + reader.cursor;
        let length = usize::from(reader.u8()?);
        if length > 32 {
            return malformed(length_offset, "NTFS snapshot label exceeds 32 UTF-16 units");
        }
        let encoded = reader.take(
            length
                .checked_mul(2)
                .ok_or(PreservationError::ArithmeticOverflow)?,
        )?;
        let units = encoded
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]));
        if char::decode_utf16(units).any(|unit| unit.is_err()) {
            return malformed(length_offset, "NTFS snapshot label contains invalid UTF-16");
        }
    }
    let security_offset = reader.base + reader.cursor;
    match reader.u8()? {
        0 => {}
        1 => reader.bytes()?,
        _ => return malformed(security_offset, "invalid NTFS security snapshot tag"),
    }
    validate_reference(&mut reader)?;
    let objects = reader.count(1)?;
    for _ in 0..objects {
        reader.u64()?;
        validate_ntfs_object(&mut reader, layout)?;
    }
    let extents = reader.count(25)?;
    for _ in 0..extents {
        validate_extent(&mut reader, false)?;
    }
    for _ in 0..5 {
        reader.u64()?;
    }
    reader.finish()
}

fn validate_reference(reader: &mut SnapshotCursor<'_>) -> Result<(), PreservationError> {
    reader.u64()?;
    reader.u16()?;
    Ok(())
}

fn validate_ntfs_object(
    reader: &mut SnapshotCursor<'_>,
    layout: NtfsSnapshotLayout,
) -> Result<(), PreservationError> {
    validate_reference(reader)?;
    reader.u16()?;
    reader.boolean()?;
    reader.boolean()?;
    if reader.boolean()? {
        for _ in 0..4 {
            reader.u64()?;
        }
        reader.u32()?;
        reader.optional_u32()?;
        reader.optional_u32()?;
        reader.optional_u64()?;
        reader.optional_u64()?;
    }
    let names = reader.count(1)?;
    for _ in 0..names {
        validate_ntfs_file_name(reader)?;
    }
    let streams = reader.count(1)?;
    for _ in 0..streams {
        reader.u16()?;
        if reader.boolean()? {
            validate_ntfs_name(reader)?;
        }
        reader.boolean()?;
        reader.boolean()?;
        reader.boolean()?;
        if layout.has_stream_compression_block() {
            reader.u64()?;
        }
        let storage_offset = reader.base + reader.cursor;
        match reader.u8()? {
            1 => reader.bytes()?,
            2 => {
                reader.u64()?;
                reader.u64()?;
                reader.u64()?;
                reader.optional_u64()?;
                reader.boolean()?;
                let extents = reader.count(25)?;
                for _ in 0..extents {
                    validate_extent(reader, false)?;
                }
                if layout.has_captured_named_payload() && reader.boolean()? {
                    reader.bytes()?;
                }
            }
            _ => return malformed(storage_offset, "invalid NTFS stream-storage tag"),
        }
    }
    if layout.has_attribute_census() {
        let attributes = reader.count(1)?;
        for _ in 0..attributes {
            reader.u32()?;
            if reader.boolean()? {
                validate_ntfs_name(reader)?;
            }
            reader.u16()?;
            reader.u16()?;
            reader.u16()?;
            reader.boolean()?;
        }
    }
    let entries = reader.count(1)?;
    for _ in 0..entries {
        validate_reference(reader)?;
        validate_ntfs_file_name(reader)?;
    }
    reader.boolean()?;
    reader.boolean()?;
    reader.boolean()?;
    if layout.has_reparse_payload() && reader.boolean()? {
        reader.bytes()?;
    }
    Ok(())
}

fn validate_ntfs_name(reader: &mut SnapshotCursor<'_>) -> Result<(), PreservationError> {
    let name_offset = reader.base + reader.cursor;
    let actual = reader.utf16()?;
    let declared = reader.boolean()?;
    if actual != declared {
        return malformed(
            name_offset,
            "NTFS UTF-16 validity evidence disagrees with the name",
        );
    }
    Ok(())
}

fn validate_ntfs_file_name(reader: &mut SnapshotCursor<'_>) -> Result<(), PreservationError> {
    validate_reference(reader)?;
    let namespace_offset = reader.base + reader.cursor;
    if !matches!(reader.u8()?, 1..=4) {
        return malformed(namespace_offset, "invalid NTFS filename namespace tag");
    }
    validate_ntfs_name(reader)?;
    reader.u64()?;
    reader.u64()?;
    reader.u32()?;
    reader.u32()?;
    Ok(())
}

fn validate_extent(
    reader: &mut SnapshotCursor<'_>,
    includes_kind: bool,
) -> Result<(), PreservationError> {
    reader.u64()?;
    reader.u64()?;
    reader.u64()?;
    let placement_offset = reader.base + reader.cursor;
    match reader.u8()? {
        1 => {
            reader.u64()?;
        }
        2 => {}
        _ => return malformed(placement_offset, "invalid snapshot extent-placement tag"),
    }
    if includes_kind {
        let kind_offset = reader.base + reader.cursor;
        if !matches!(reader.u8()?, 1..=5) {
            return malformed(kind_offset, "invalid snapshot extent-kind tag");
        }
    }
    Ok(())
}

fn decode_ntfs_volume_label(
    reader: &mut SnapshotCursor<'_>,
) -> Result<Option<Vec<u16>>, PreservationError> {
    if !reader.boolean()? {
        return Ok(None);
    }
    let length_offset = reader.base + reader.cursor;
    let length = usize::from(reader.u8()?);
    if length > 32 {
        return malformed(length_offset, "NTFS snapshot label exceeds 32 UTF-16 units");
    }
    let encoded = reader.take(
        length
            .checked_mul(2)
            .ok_or(PreservationError::ArithmeticOverflow)?,
    )?;
    let mut units = Vec::new();
    units
        .try_reserve_exact(length)
        .map_err(|_| PreservationError::AllocationFailed)?;
    for pair in encoded.chunks_exact(2) {
        units.push(u16::from_le_bytes([pair[0], pair[1]]));
    }
    if char::decode_utf16(units.iter().copied()).any(|unit| unit.is_err()) {
        return malformed(length_offset, "NTFS snapshot label contains invalid UTF-16");
    }
    Ok(Some(units))
}

fn decode_ntfs_security_evidence(
    reader: &mut SnapshotCursor<'_>,
) -> Result<NtfsSecurityDescriptorEvidence, PreservationError> {
    let security_offset = reader.base + reader.cursor;
    match reader.u8()? {
        0 => Ok(NtfsSecurityDescriptorEvidence::Unavailable),
        1 => Ok(NtfsSecurityDescriptorEvidence::PinnedNtfs3gWindows2003 {
            sds: reader.take_vec()?,
        }),
        _ => malformed(security_offset, "invalid NTFS security snapshot tag"),
    }
}

fn decode_reference(
    reader: &mut SnapshotCursor<'_>,
) -> Result<NtfsObjectReference, PreservationError> {
    Ok(NtfsObjectReference {
        record_number: reader.u64()?,
        sequence_number: reader.u16()?,
    })
}

fn decode_ntfs_object(reader: &mut SnapshotCursor<'_>) -> Result<NtfsObject, PreservationError> {
    let reference = decode_reference(reader)?;
    let hard_link_count = reader.u16()?;
    let is_directory = reader.boolean()?;
    let is_metadata = reader.boolean()?;
    let standard_information = if reader.boolean()? {
        Some(decode_standard_information(reader)?)
    } else {
        None
    };
    let file_names = decode_counted(reader, decode_file_name)?;
    let data_streams = decode_counted(reader, decode_data_stream)?;
    let attribute_census = decode_counted(reader, decode_ntfs_attribute_evidence)?;
    let directory_entries = decode_counted(reader, decode_directory_entry)?;
    let has_reparse_point = reader.boolean()?;
    let has_attribute_list = reader.boolean()?;
    let directory_index_complete = reader.boolean()?;
    let reparse_point = if reader.boolean()? {
        Some(reader.take_vec()?)
    } else {
        None
    };
    Ok(NtfsObject {
        reference,
        hard_link_count,
        is_directory,
        is_metadata,
        standard_information,
        file_names,
        data_streams,
        attribute_census,
        directory_entries,
        has_reparse_point,
        reparse_point,
        has_attribute_list,
        directory_index_complete,
    })
}

fn decode_counted<T>(
    reader: &mut SnapshotCursor<'_>,
    decode_one: fn(&mut SnapshotCursor<'_>) -> Result<T, PreservationError>,
) -> Result<Vec<T>, PreservationError> {
    let count = reader.count(1)?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| PreservationError::AllocationFailed)?;
    for _ in 0..count {
        values.push(decode_one(reader)?);
    }
    Ok(values)
}

fn decode_standard_information(
    reader: &mut SnapshotCursor<'_>,
) -> Result<NtfsStandardInformation, PreservationError> {
    Ok(NtfsStandardInformation {
        creation_time: reader.u64()?,
        modification_time: reader.u64()?,
        mft_change_time: reader.u64()?,
        access_time: reader.u64()?,
        file_attributes: reader.u32()?,
        owner_id: reader.optional_u32_value()?,
        security_id: reader.optional_u32_value()?,
        quota_charged: reader.optional_u64_value()?,
        usn: reader.optional_u64_value()?,
    })
}

fn decode_ntfs_name(reader: &mut SnapshotCursor<'_>) -> Result<NtfsName, PreservationError> {
    let name_offset = reader.base + reader.cursor;
    let (code_units, well_formed) = reader.utf16_units()?;
    let declared = reader.boolean()?;
    if well_formed != declared {
        return malformed(
            name_offset,
            "NTFS UTF-16 validity evidence disagrees with the name",
        );
    }
    Ok(NtfsName {
        code_units,
        is_well_formed: declared,
    })
}

fn decode_file_name(reader: &mut SnapshotCursor<'_>) -> Result<NtfsFileName, PreservationError> {
    let parent = decode_reference(reader)?;
    let namespace_offset = reader.base + reader.cursor;
    let namespace = match reader.u8()? {
        1 => FileNameNamespace::Posix,
        2 => FileNameNamespace::Win32,
        3 => FileNameNamespace::Dos,
        4 => FileNameNamespace::Win32AndDos,
        _ => return malformed(namespace_offset, "invalid NTFS filename namespace tag"),
    };
    Ok(NtfsFileName {
        parent,
        namespace,
        name: decode_ntfs_name(reader)?,
        allocated_size: reader.u64()?,
        data_size: reader.u64()?,
        file_attributes: reader.u32()?,
        reparse_tag_or_ea_size: reader.u32()?,
    })
}

fn decode_data_stream(
    reader: &mut SnapshotCursor<'_>,
) -> Result<NtfsDataStream, PreservationError> {
    let attribute_id = reader.u16()?;
    let name = if reader.boolean()? {
        Some(decode_ntfs_name(reader)?)
    } else {
        None
    };
    let compressed = reader.boolean()?;
    let encrypted = reader.boolean()?;
    let sparse = reader.boolean()?;
    let compression_block_bytes = reader.u64()?;
    let storage_offset = reader.base + reader.cursor;
    let storage = match reader.u8()? {
        1 => NtfsStreamStorage::Resident {
            bytes: reader.take_vec()?,
        },
        2 => {
            let allocated_bytes = reader.u64()?;
            let data_bytes = reader.u64()?;
            let initialized_bytes = reader.u64()?;
            let compressed_bytes = reader.optional_u64_value()?;
            let mapping_complete = reader.boolean()?;
            let extents = decode_counted(reader, decode_ntfs_extent)?;
            let captured_payload = if reader.boolean()? {
                Some(reader.take_vec()?)
            } else {
                None
            };
            NtfsStreamStorage::NonResident {
                allocated_bytes,
                data_bytes,
                initialized_bytes,
                compressed_bytes,
                mapping_complete,
                extents,
                captured_payload,
            }
        }
        _ => return malformed(storage_offset, "invalid NTFS stream-storage tag"),
    };
    Ok(NtfsDataStream {
        attribute_id,
        name,
        compressed,
        encrypted,
        sparse,
        compression_block_bytes,
        storage,
    })
}

fn decode_ntfs_attribute_evidence(
    reader: &mut SnapshotCursor<'_>,
) -> Result<NtfsAttributeEvidence, PreservationError> {
    let attribute_type = reader.u32()?;
    let name = if reader.boolean()? {
        Some(decode_ntfs_name(reader)?)
    } else {
        None
    };
    Ok(NtfsAttributeEvidence {
        attribute_type,
        name,
        flags_raw: reader.u16()?,
        flags_unknown_bits: reader.u16()?,
        attribute_id: reader.u16()?,
        resident: reader.boolean()?,
    })
}

fn decode_directory_entry(
    reader: &mut SnapshotCursor<'_>,
) -> Result<NtfsDirectoryEntry, PreservationError> {
    Ok(NtfsDirectoryEntry {
        target: decode_reference(reader)?,
        file_name: decode_file_name(reader)?,
    })
}

fn decode_ntfs_extent(
    reader: &mut SnapshotCursor<'_>,
) -> Result<NtfsInventoryExtent, PreservationError> {
    let stream_id = reader.u64()?;
    let logical_offset = reader.u64()?;
    let length = reader.u64()?;
    let placement_offset = reader.base + reader.cursor;
    let placement = match reader.u8()? {
        1 => NtfsExtentPlacement::Physical {
            byte_offset: reader.u64()?,
        },
        2 => NtfsExtentPlacement::Sparse,
        _ => return malformed(placement_offset, "invalid snapshot extent-placement tag"),
    };
    Ok(NtfsInventoryExtent {
        stream_id,
        logical_offset,
        length,
        placement,
    })
}

fn decode_ntfs_volume_identity(
    bytes: &[u8],
    offset: usize,
) -> Result<NtfsVolumeIdentity, PreservationError> {
    let fixed = bytes.get(..11).ok_or(PreservationError::MalformedEscrow {
        offset,
        reason: "truncated NTFS volume identity",
    })?;
    let volume_serial_number = u64::from_le_bytes([
        fixed[2], fixed[3], fixed[4], fixed[5], fixed[6], fixed[7], fixed[8], fixed[9],
    ]);
    let volume_label = match fixed[10] {
        0 => NtfsVolumeLabelIdentity::Absent,
        1 => {
            let length = *bytes.get(11).ok_or(PreservationError::MalformedEscrow {
                offset: offset + 11,
                reason: "truncated NTFS volume-label length",
            })?;
            if length > 32 {
                return malformed(offset + 11, "NTFS volume label exceeds 32 UTF-16 units");
            }
            let byte_length = usize::from(length)
                .checked_mul(2)
                .ok_or(PreservationError::ArithmeticOverflow)?;
            let end = 12_usize
                .checked_add(byte_length)
                .ok_or(PreservationError::ArithmeticOverflow)?;
            let encoded = bytes
                .get(12..end)
                .ok_or(PreservationError::MalformedEscrow {
                    offset: offset + 12,
                    reason: "truncated NTFS volume-label units",
                })?;
            let mut units = Vec::new();
            units
                .try_reserve_exact(usize::from(length))
                .map_err(|_| PreservationError::AllocationFailed)?;
            for pair in encoded.chunks_exact(2) {
                units.push(u16::from_le_bytes([pair[0], pair[1]]));
            }
            NtfsVolumeLabelIdentity::Exact(units)
        }
        _ => return malformed(offset + 10, "invalid NTFS volume-label presence flag"),
    };
    Ok(NtfsVolumeIdentity {
        volume_serial_number,
        volume_label,
    })
}

fn decode_ntfs_security_descriptors(
    bytes: &[u8],
    offset: usize,
) -> Result<NtfsSecurityDescriptorEscrow, PreservationError> {
    let label_flag = *bytes.get(10).ok_or(PreservationError::MalformedEscrow {
        offset: offset + 10,
        reason: "truncated NTFS volume-label flag",
    })?;
    let cursor = match label_flag {
        0 => 11,
        1 => {
            let length = *bytes.get(11).ok_or(PreservationError::MalformedEscrow {
                offset: offset + 11,
                reason: "truncated NTFS volume-label length",
            })?;
            12_usize
                .checked_add(
                    usize::from(length)
                        .checked_mul(2)
                        .ok_or(PreservationError::ArithmeticOverflow)?,
                )
                .ok_or(PreservationError::ArithmeticOverflow)?
        }
        _ => return malformed(offset + 10, "invalid NTFS volume-label presence flag"),
    };
    let tag = *bytes
        .get(cursor)
        .ok_or(PreservationError::MalformedEscrow {
            offset: offset + cursor,
            reason: "truncated NTFS security-evidence tag",
        })?;
    match tag {
        0 => Ok(NtfsSecurityDescriptorEscrow::Unavailable),
        1 => {
            let length_offset = cursor
                .checked_add(1)
                .ok_or(PreservationError::ArithmeticOverflow)?;
            let length = read_u64(bytes, length_offset)?;
            let length =
                usize::try_from(length).map_err(|_| PreservationError::ArithmeticOverflow)?;
            let start = length_offset
                .checked_add(8)
                .ok_or(PreservationError::ArithmeticOverflow)?;
            let end = start
                .checked_add(length)
                .ok_or(PreservationError::ArithmeticOverflow)?;
            let sds = bytes
                .get(start..end)
                .ok_or(PreservationError::MalformedEscrow {
                    offset: offset + start,
                    reason: "truncated NTFS security descriptor stream",
                })?;
            let canonical = generate_ntfs_secure_metadata(
                NtfsSecureProfile::MkntfsWindows2003Ntfs31,
                NtfsSecureLimits::default(),
            )
            .map_err(|_| PreservationError::MalformedEscrow {
                offset: offset + start,
                reason: "could not reconstruct pinned NTFS security profile",
            })?;
            if sds != canonical.sds {
                return malformed(
                    offset + start,
                    "NTFS security bytes do not match the pinned profile",
                );
            }
            Ok(NtfsSecurityDescriptorEscrow::PinnedNtfs3gWindows2003 { sds: sds.to_vec() })
        }
        _ => malformed(offset + cursor, "invalid NTFS security-evidence tag"),
    }
}

fn decode_exfat_volume_identity(
    bytes: &[u8],
    offset: usize,
) -> Result<ExfatVolumeIdentity, PreservationError> {
    let fixed = bytes.get(..7).ok_or(PreservationError::MalformedEscrow {
        offset,
        reason: "truncated exFAT volume identity",
    })?;
    let volume_serial_number = u32::from_le_bytes([fixed[2], fixed[3], fixed[4], fixed[5]]);
    let volume_label = match fixed[6] {
        0 => ExfatVolumeLabelIdentity::Absent,
        1 => {
            let length = *bytes.get(7).ok_or(PreservationError::MalformedEscrow {
                offset: offset + 7,
                reason: "truncated exFAT volume-label length",
            })?;
            if length > 11 {
                return malformed(offset + 7, "exFAT volume label exceeds 11 UTF-16 units");
            }
            let byte_length = usize::from(length)
                .checked_mul(2)
                .ok_or(PreservationError::ArithmeticOverflow)?;
            let end = 8_usize
                .checked_add(byte_length)
                .ok_or(PreservationError::ArithmeticOverflow)?;
            let encoded = bytes
                .get(8..end)
                .ok_or(PreservationError::MalformedEscrow {
                    offset: offset + 8,
                    reason: "truncated exFAT volume-label units",
                })?;
            let mut units = Vec::new();
            units
                .try_reserve_exact(usize::from(length))
                .map_err(|_| PreservationError::AllocationFailed)?;
            for pair in encoded.chunks_exact(2) {
                units.push(u16::from_le_bytes([pair[0], pair[1]]));
            }
            if char::decode_utf16(units.iter().copied()).any(|character| character.is_err()) {
                return malformed(offset + 8, "exFAT volume label contains invalid UTF-16");
            }
            ExfatVolumeLabelIdentity::Exact(units)
        }
        2 => ExfatVolumeLabelIdentity::UnretainedNonzeroPadding,
        _ => return malformed(offset + 6, "invalid exFAT volume-label presence flag"),
    };
    Ok(ExfatVolumeIdentity {
        volume_serial_number,
        volume_label,
    })
}

const fn malformed<T>(offset: usize, reason: &'static str) -> Result<T, PreservationError> {
    Err(PreservationError::MalformedEscrow { offset, reason })
}

const fn filesystem_tag(filesystem: FileSystem) -> Result<u8, PreservationError> {
    match filesystem {
        FileSystem::ExFat => Ok(EXFAT_SOURCE),
        FileSystem::Ntfs => Ok(NTFS_SOURCE),
        FileSystem::Unknown => Err(PreservationError::UnsupportedFilesystem(filesystem)),
    }
}

const fn filesystem_from_tag(tag: u8, offset: usize) -> Result<FileSystem, PreservationError> {
    match tag {
        EXFAT_SOURCE => Ok(FileSystem::ExFat),
        NTFS_SOURCE => Ok(FileSystem::Ntfs),
        _ => malformed(offset, "unknown filesystem tag"),
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, PreservationError> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or(PreservationError::MalformedEscrow {
            offset,
            reason: "truncated u16",
        })?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, PreservationError> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or(PreservationError::MalformedEscrow {
            offset,
            reason: "truncated u32",
        })?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, PreservationError> {
    let value = bytes
        .get(offset..offset + 8)
        .ok_or(PreservationError::MalformedEscrow {
            offset,
            reason: "truncated u64",
        })?;
    Ok(u64::from_le_bytes([
        value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
    ]))
}

struct BoundedWriter {
    bytes: Vec<u8>,
    maximum: usize,
}

impl BoundedWriter {
    const fn new(maximum: usize) -> Self {
        Self {
            bytes: Vec::new(),
            maximum,
        }
    }

    fn reserve(&mut self, additional: usize) -> Result<(), PreservationError> {
        let required = self
            .bytes
            .len()
            .checked_add(additional)
            .ok_or(PreservationError::ArithmeticOverflow)?;
        if required > self.maximum {
            return Err(PreservationError::RecordLimitExceeded {
                required,
                maximum: self.maximum,
            });
        }
        self.bytes
            .try_reserve(additional)
            .map_err(|_| PreservationError::AllocationFailed)
    }

    fn raw(&mut self, value: &[u8]) -> Result<(), PreservationError> {
        self.reserve(value.len())?;
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn u8(&mut self, value: u8) -> Result<(), PreservationError> {
        self.raw(&[value])
    }

    fn bool(&mut self, value: bool) -> Result<(), PreservationError> {
        self.u8(u8::from(value))
    }

    fn u16(&mut self, value: u16) -> Result<(), PreservationError> {
        self.raw(&value.to_le_bytes())
    }

    fn u32(&mut self, value: u32) -> Result<(), PreservationError> {
        self.raw(&value.to_le_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), PreservationError> {
        self.raw(&value.to_le_bytes())
    }

    fn usize(&mut self, value: usize) -> Result<(), PreservationError> {
        self.u64(u64::try_from(value).map_err(|_| PreservationError::ArithmeticOverflow)?)
    }

    fn optional_u32(&mut self, value: Option<u32>) -> Result<(), PreservationError> {
        self.bool(value.is_some())?;
        if let Some(value) = value {
            self.u32(value)?;
        }
        Ok(())
    }

    fn optional_u64(&mut self, value: Option<u64>) -> Result<(), PreservationError> {
        self.bool(value.is_some())?;
        if let Some(value) = value {
            self.u64(value)?;
        }
        Ok(())
    }

    fn utf16(&mut self, value: &[u16]) -> Result<(), PreservationError> {
        self.usize(value.len())?;
        for unit in value {
            self.u16(*unit)?;
        }
        Ok(())
    }

    fn bytes(&mut self, value: &[u8]) -> Result<(), PreservationError> {
        self.usize(value.len())?;
        self.raw(value)
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

fn encode_exfat_sidecar(
    writer: &mut BoundedWriter,
    sidecar: &ExfatPreservationSidecar,
) -> Result<(), PreservationError> {
    writer.u16(2)?;
    writer.u32(sidecar.volume_serial_number)?;
    match sidecar.volume_label {
        Some(label) => {
            writer.u8(1)?;
            let units = label.as_units();
            writer
                .u8(u8::try_from(units.len()).map_err(|_| PreservationError::ArithmeticOverflow)?)?;
            for unit in units {
                writer.u16(*unit)?;
            }
        }
        None if sidecar.root.directory.volume_labels == 0 => writer.u8(0)?,
        None => writer.u8(2)?,
    }
    let root = &sidecar.root;
    let directory = root.directory;
    for value in [
        directory.entries_examined,
        directory.records,
        directory.unused_entries,
        directory.files,
        directory.benign_primary_sets,
    ] {
        writer.usize(value)?;
    }
    writer.bool(directory.reached_end_marker)?;
    writer.u8(directory.allocation_bitmaps)?;
    writer.u8(directory.upcase_tables)?;
    writer.u8(directory.volume_labels)?;
    writer.u8(root.active_bitmap.bitmap_identifier)?;
    writer.u32(root.active_bitmap.first_cluster)?;
    writer.u64(root.active_bitmap.data_length)?;
    writer.u32(root.upcase_table.table_checksum)?;
    writer.u32(root.upcase_table.first_cluster)?;
    writer.u64(root.upcase_table.data_length)?;
    writer.usize(root.upcase_mappings.mappings().len())?;
    for mapping in root.upcase_mappings.mappings() {
        writer.u16(*mapping)?;
    }
    writer.u64(root.allocation.allocated_clusters)?;
    writer.u64(root.allocation.free_clusters)?;
    writer.u64(root.allocation.required_bitmap_bytes)?;
    writer.u64(root.free_bytes)?;
    encode_u32_vec(writer, &root.root_clusters)?;
    encode_u32_vec(writer, &root.bitmap_clusters)?;
    encode_u32_vec(writer, &root.upcase_clusters)?;
    writer.usize(sidecar.objects.len())?;
    for object in &sidecar.objects {
        writer.u64(object.object.0)?;
        writer.u64(object.source_stream.0)?;
        writer.usize(object.path.len())?;
        for component in &object.path {
            writer.utf16(component)?;
        }
        writer.u16(object.file_attributes)?;
        writer.bool(object.timestamps.is_some())?;
        if let Some(timestamps) = object.timestamps {
            encode_exfat_timestamps(writer, timestamps)?;
        }
        encode_u32_vec(writer, &object.clusters)?;
        encode_exfat_flags(writer, object.flags)?;
    }
    writer.usize(sidecar.filesystem_extents.len())?;
    for extent in &sidecar.filesystem_extents {
        encode_extent(writer, *extent)?;
    }
    let evidence = sidecar.directory_evidence;
    writer.u64(evidence.unused_directory_entries)?;
    writer.u64(evidence.benign_primary_sets)?;
    writer.u64(evidence.benign_secondary_entries)?;
    writer.u64(evidence.nonzero_name_padding_sets)?;
    writer.bool(evidence.nonzero_volume_label_padding)?;
    writer.u64(sidecar.allocated_bad_clusters)
}

fn encode_exfat_timestamps(
    writer: &mut BoundedWriter,
    value: ExfatTimestamps,
) -> Result<(), PreservationError> {
    writer.u32(value.create)?;
    writer.u32(value.modified)?;
    writer.u32(value.accessed)?;
    writer.u8(value.create_centiseconds)?;
    writer.u8(value.modified_centiseconds)?;
    writer.u8(value.create_utc_offset)?;
    writer.u8(value.modified_utc_offset)?;
    writer.u8(value.accessed_utc_offset)
}

fn encode_exfat_flags(
    writer: &mut BoundedWriter,
    value: ExfatObjectFlags,
) -> Result<(), PreservationError> {
    writer.bool(value.no_fat_chain)?;
    writer.bool(value.name_padding_zeroed)?;
    writer.u8(value.benign_secondary_entries)
}

fn encode_u32_vec(writer: &mut BoundedWriter, values: &[u32]) -> Result<(), PreservationError> {
    writer.usize(values.len())?;
    for value in values {
        writer.u32(*value)?;
    }
    Ok(())
}

fn encode_extent(writer: &mut BoundedWriter, extent: Extent) -> Result<(), PreservationError> {
    writer.u64(extent.stream.0)?;
    writer.u64(extent.logical_offset)?;
    writer.u64(extent.length)?;
    match extent.placement {
        Placement::Physical { byte_offset } => {
            writer.u8(1)?;
            writer.u64(byte_offset)?;
        }
        Placement::Sparse => writer.u8(2)?,
    }
    writer.u8(extent_kind_tag(extent.kind))
}

const fn extent_kind_tag(kind: ExtentKind) -> u8 {
    match kind {
        ExtentKind::FileData => 1,
        ExtentKind::DirectoryData => 2,
        ExtentKind::FileSystemMetadata => 3,
        ExtentKind::Reserved => 4,
        ExtentKind::BadCluster => 5,
    }
}

fn encode_ntfs_sidecar(
    writer: &mut BoundedWriter,
    sidecar: &NtfsPreservationSidecar,
) -> Result<(), PreservationError> {
    // Inner NTFS snapshot v7 appends optional captured named-stream initialized bytes after each
    // NonResident runlist. Version 6 added the per-stream compression-unit size after the three
    // stream flag bools. Version 5 kept optional exact $REPARSE_POINT bytes after the trailing
    // object flags. The outer escrow envelope remains ESCROW_SCHEMA_VERSION 4.
    writer.u16(7)?;
    writer.u64(sidecar.volume_serial_number)?;
    writer.bool(sidecar.volume_label.is_some())?;
    if let Some(units) = &sidecar.volume_label {
        let length =
            u8::try_from(units.len()).map_err(|_| PreservationError::ArithmeticOverflow)?;
        writer.u8(length)?;
        for unit in units {
            writer.u16(*unit)?;
        }
    }
    match &sidecar.security_descriptors {
        NtfsSecurityDescriptorEvidence::Unavailable => writer.u8(0)?,
        NtfsSecurityDescriptorEvidence::PinnedNtfs3gWindows2003 { sds } => {
            writer.u8(1)?;
            writer.bytes(sds)?;
        }
    }
    encode_reference(writer, sidecar.root_reference)?;
    writer.usize(sidecar.objects.len())?;
    for preserved in &sidecar.objects {
        writer.u64(preserved.object.0)?;
        encode_ntfs_object(writer, &preserved.source)?;
    }
    writer.usize(sidecar.source_extents.len())?;
    for extent in &sidecar.source_extents {
        encode_ntfs_extent(writer, *extent)?;
    }
    writer.u64(sidecar.scanned_records)?;
    writer.u64(sidecar.initialized_records)?;
    writer.u64(sidecar.in_use_base_records)?;
    writer.u64(sidecar.extension_records)?;
    writer.u64(sidecar.bytes_read)
}

fn encode_reference(
    writer: &mut BoundedWriter,
    value: NtfsObjectReference,
) -> Result<(), PreservationError> {
    writer.u64(value.record_number)?;
    writer.u16(value.sequence_number)
}

fn encode_ntfs_object(
    writer: &mut BoundedWriter,
    object: &NtfsObject,
) -> Result<(), PreservationError> {
    encode_reference(writer, object.reference)?;
    writer.u16(object.hard_link_count)?;
    writer.bool(object.is_directory)?;
    writer.bool(object.is_metadata)?;
    writer.bool(object.standard_information.is_some())?;
    if let Some(standard) = object.standard_information {
        encode_standard_information(writer, standard)?;
    }
    writer.usize(object.file_names.len())?;
    for name in &object.file_names {
        encode_file_name(writer, name)?;
    }
    writer.usize(object.data_streams.len())?;
    for stream in &object.data_streams {
        encode_data_stream(writer, stream)?;
    }
    writer.usize(object.attribute_census.len())?;
    for attribute in &object.attribute_census {
        encode_ntfs_attribute_evidence(writer, attribute)?;
    }
    writer.usize(object.directory_entries.len())?;
    for entry in &object.directory_entries {
        encode_reference(writer, entry.target)?;
        encode_file_name(writer, &entry.file_name)?;
    }
    writer.bool(object.has_reparse_point)?;
    writer.bool(object.has_attribute_list)?;
    writer.bool(object.directory_index_complete)?;
    writer.bool(object.reparse_point.is_some())?;
    if let Some(payload) = &object.reparse_point {
        writer.bytes(payload)?;
    }
    Ok(())
}

fn encode_ntfs_attribute_evidence(
    writer: &mut BoundedWriter,
    attribute: &NtfsAttributeEvidence,
) -> Result<(), PreservationError> {
    writer.u32(attribute.attribute_type)?;
    writer.bool(attribute.name.is_some())?;
    if let Some(name) = &attribute.name {
        encode_name(writer, name)?;
    }
    writer.u16(attribute.flags_raw)?;
    writer.u16(attribute.flags_unknown_bits)?;
    writer.u16(attribute.attribute_id)?;
    writer.bool(attribute.resident)
}

fn encode_standard_information(
    writer: &mut BoundedWriter,
    value: NtfsStandardInformation,
) -> Result<(), PreservationError> {
    writer.u64(value.creation_time)?;
    writer.u64(value.modification_time)?;
    writer.u64(value.mft_change_time)?;
    writer.u64(value.access_time)?;
    writer.u32(value.file_attributes)?;
    writer.optional_u32(value.owner_id)?;
    writer.optional_u32(value.security_id)?;
    writer.optional_u64(value.quota_charged)?;
    writer.optional_u64(value.usn)
}

fn encode_name(writer: &mut BoundedWriter, name: &NtfsName) -> Result<(), PreservationError> {
    writer.utf16(&name.code_units)?;
    writer.bool(name.is_well_formed)
}

fn encode_file_name(
    writer: &mut BoundedWriter,
    name: &NtfsFileName,
) -> Result<(), PreservationError> {
    encode_reference(writer, name.parent)?;
    writer.u8(namespace_tag(name.namespace))?;
    encode_name(writer, &name.name)?;
    writer.u64(name.allocated_size)?;
    writer.u64(name.data_size)?;
    writer.u32(name.file_attributes)?;
    writer.u32(name.reparse_tag_or_ea_size)
}

const fn namespace_tag(namespace: FileNameNamespace) -> u8 {
    match namespace {
        FileNameNamespace::Posix => 1,
        FileNameNamespace::Win32 => 2,
        FileNameNamespace::Dos => 3,
        FileNameNamespace::Win32AndDos => 4,
    }
}

fn encode_data_stream(
    writer: &mut BoundedWriter,
    stream: &NtfsDataStream,
) -> Result<(), PreservationError> {
    writer.u16(stream.attribute_id)?;
    writer.bool(stream.name.is_some())?;
    if let Some(name) = &stream.name {
        encode_name(writer, name)?;
    }
    writer.bool(stream.compressed)?;
    writer.bool(stream.encrypted)?;
    writer.bool(stream.sparse)?;
    writer.u64(stream.compression_block_bytes)?;
    match &stream.storage {
        NtfsStreamStorage::Resident { bytes } => {
            writer.u8(1)?;
            writer.bytes(bytes)
        }
        NtfsStreamStorage::NonResident {
            allocated_bytes,
            data_bytes,
            initialized_bytes,
            compressed_bytes,
            mapping_complete,
            extents,
            captured_payload,
        } => {
            writer.u8(2)?;
            writer.u64(*allocated_bytes)?;
            writer.u64(*data_bytes)?;
            writer.u64(*initialized_bytes)?;
            writer.optional_u64(*compressed_bytes)?;
            writer.bool(*mapping_complete)?;
            writer.usize(extents.len())?;
            for extent in extents {
                encode_ntfs_extent(writer, *extent)?;
            }
            writer.bool(captured_payload.is_some())?;
            if let Some(bytes) = captured_payload {
                writer.bytes(bytes)?;
            }
            Ok(())
        }
    }
}

fn encode_ntfs_extent(
    writer: &mut BoundedWriter,
    extent: NtfsInventoryExtent,
) -> Result<(), PreservationError> {
    writer.u64(extent.stream_id)?;
    writer.u64(extent.logical_offset)?;
    writer.u64(extent.length)?;
    match extent.placement {
        NtfsExtentPlacement::Physical { byte_offset } => {
            writer.u8(1)?;
            writer.u64(byte_offset)
        }
        NtfsExtentPlacement::Sparse => writer.u8(2),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extent::{ExtentGraph, StreamId};
    use crate::fs::exfat_allocation::AllocationSummary;
    use crate::fs::exfat_directory::{AllocationBitmapEntry, DirectorySummary, UpcaseTableEntry};
    use crate::fs::exfat_discovery::ExfatRootDiscovery;
    use crate::fs::exfat_inventory::ExfatPreservationEvidence;
    use crate::fs::exfat_normalize::{ExfatObjectPreservation, ExfatPreservationSidecar};
    use crate::fs::exfat_upcase::{UpcaseLimits, UpcaseTable};
    use crate::fs::ntfs_normalize::{NtfsObjectPreservation, NtfsPreservationSidecar};
    use crate::object::{
        NamespaceEntry, ObjectGraphLimits, ObjectId, ObjectKind, ObjectRecord, ObjectSemantics,
        ObjectStream, StreamFlags, StreamStorage,
    };

    const GRAPH_LIMITS: ObjectGraphLimits = ObjectGraphLimits {
        max_objects: 8,
        max_entries: 8,
        max_streams: 8,
        max_name_code_units: 255,
    };

    fn empty_graph() -> ObjectGraph {
        ObjectGraph::build(
            ObjectId(1),
            vec![ObjectRecord {
                id: ObjectId(1),
                kind: ObjectKind::Directory,
                link_count: 0,
                semantics: ObjectSemantics::default(),
                streams: Vec::new(),
            }],
            Vec::<NamespaceEntry>::new(),
            ExtentGraph::build(Vec::new(), 1_048_576, 8).expect("extents"),
            GRAPH_LIMITS,
        )
        .expect("graph")
    }

    fn encoded_identity_upcase() -> Vec<u8> {
        let mut bytes = Vec::new();
        for value in 0_u16..=u16::MAX {
            let mapping = if (0x61..=0x7a).contains(&value) {
                value - 0x20
            } else {
                value
            };
            bytes.extend_from_slice(&mapping.to_le_bytes());
        }
        bytes
    }

    fn upcase_checksum(bytes: &[u8]) -> u32 {
        bytes.iter().fold(0_u32, |sum, byte| {
            sum.rotate_right(1).wrapping_add(u32::from(*byte))
        })
    }

    fn exfat() -> NormalizedExfat {
        let encoded = encoded_identity_upcase();
        let checksum = upcase_checksum(&encoded);
        let upcase =
            UpcaseTable::parse(&encoded, checksum, UpcaseLimits::COMPLETE_TABLE).expect("upcase");
        NormalizedExfat {
            graph: empty_graph(),
            preservation: ExfatPreservationSidecar {
                root: ExfatRootDiscovery {
                    directory: DirectorySummary {
                        entries_examined: 3,
                        records: 2,
                        unused_entries: 0,
                        reached_end_marker: true,
                        allocation_bitmaps: 1,
                        upcase_tables: 1,
                        volume_labels: 0,
                        files: 0,
                        benign_primary_sets: 0,
                    },
                    active_bitmap: AllocationBitmapEntry {
                        bitmap_identifier: 0,
                        first_cluster: 2,
                        data_length: 1,
                    },
                    upcase_table: UpcaseTableEntry {
                        table_checksum: checksum,
                        first_cluster: 3,
                        data_length: u64::try_from(encoded.len()).expect("length"),
                    },
                    upcase_mappings: upcase,
                    allocation: AllocationSummary {
                        allocated_clusters: 2,
                        free_clusters: 10,
                        required_bitmap_bytes: 2,
                    },
                    free_bytes: 40_960,
                    root_clusters: vec![4],
                    bitmap_clusters: vec![2],
                    upcase_clusters: vec![3],
                },
                volume_serial_number: 0x1234_abcd,
                volume_label: None,
                objects: vec![ExfatObjectPreservation {
                    object: ObjectId(1),
                    source_stream: StreamId(1),
                    path: Vec::new(),
                    file_attributes: 0x10,
                    timestamps: None,
                    clusters: vec![4],
                    flags: ExfatObjectFlags {
                        no_fat_chain: false,
                        name_padding_zeroed: true,
                        benign_secondary_entries: 0,
                    },
                }],
                filesystem_extents: Vec::new(),
                directory_evidence: ExfatPreservationEvidence::default(),
                allocated_bad_clusters: 0,
            },
        }
    }

    fn ntfs_object() -> NtfsObject {
        NtfsObject {
            reference: NtfsObjectReference {
                record_number: 5,
                sequence_number: 1,
            },
            hard_link_count: 0,
            is_directory: true,
            is_metadata: false,
            standard_information: Some(NtfsStandardInformation {
                creation_time: 1,
                modification_time: 2,
                mft_change_time: 3,
                access_time: 4,
                file_attributes: 0x10,
                owner_id: None,
                security_id: None,
                quota_charged: None,
                usn: None,
            }),
            file_names: Vec::new(),
            data_streams: Vec::new(),
            attribute_census: vec![NtfsAttributeEvidence {
                attribute_type: NTFS_STANDARD_INFORMATION,
                name: None,
                flags_raw: 0,
                flags_unknown_bits: 0,
                attribute_id: 0,
                resident: true,
            }],
            directory_entries: Vec::new(),
            has_reparse_point: false,
            reparse_point: None,
            has_attribute_list: false,
            directory_index_complete: true,
        }
    }

    fn ntfs() -> NormalizedNtfs {
        let object = ntfs_object();
        let bad_name = NtfsName {
            code_units: "$Bad".encode_utf16().collect(),
            is_well_formed: true,
        };
        let badclus = NtfsObject {
            reference: NtfsObjectReference {
                record_number: 8,
                sequence_number: 1,
            },
            hard_link_count: 0,
            is_directory: false,
            is_metadata: true,
            standard_information: None,
            file_names: Vec::new(),
            data_streams: vec![NtfsDataStream {
                attribute_id: 1,
                name: Some(bad_name.clone()),
                compressed: false,
                encrypted: false,
                sparse: false,
                compression_block_bytes: 0,
                storage: NtfsStreamStorage::NonResident {
                    allocated_bytes: 1_048_576,
                    data_bytes: 1_048_576,
                    initialized_bytes: 0,
                    compressed_bytes: None,
                    mapping_complete: true,
                    extents: vec![NtfsInventoryExtent {
                        stream_id: (8 << 16) | 1,
                        logical_offset: 0,
                        length: 1_048_576,
                        placement: NtfsExtentPlacement::Sparse,
                    }],
                    captured_payload: None,
                },
            }],
            attribute_census: vec![NtfsAttributeEvidence {
                attribute_type: NTFS_DATA,
                name: Some(bad_name),
                flags_raw: 0,
                flags_unknown_bits: 0,
                attribute_id: 1,
                resident: false,
            }],
            directory_entries: Vec::new(),
            has_reparse_point: false,
            reparse_point: None,
            has_attribute_list: false,
            directory_index_complete: true,
        };
        NormalizedNtfs {
            graph: empty_graph(),
            preservation: NtfsPreservationSidecar {
                volume_serial_number: 0x0123_4567_89ab_cdef,
                volume_label: None,
                security_descriptors: NtfsSecurityDescriptorEvidence::Unavailable,
                root_reference: object.reference,
                objects: vec![
                    NtfsObjectPreservation {
                        object: ObjectId(1),
                        source: object,
                    },
                    NtfsObjectPreservation {
                        object: ObjectId(8),
                        source: badclus,
                    },
                ],
                source_extents: Vec::new(),
                scanned_records: 16,
                initialized_records: 16,
                in_use_base_records: 2,
                extension_records: 0,
                bytes_read: 16_384,
            },
        }
    }

    fn disposition(report: &PreservationReport, field: PreservationField) -> FieldDisposition {
        report
            .assessments
            .iter()
            .find(|assessment| assessment.field == field)
            .expect("field")
            .disposition
    }

    #[test]
    fn every_field_is_classified_exactly_once_for_both_sources() {
        for report in [
            evaluate_exfat(
                &exfat(),
                FileSystem::Ntfs,
                GuaranteeMode::ContentOnly,
                PreservationLimits::default(),
            )
            .expect("exfat policy"),
            evaluate_ntfs(
                &ntfs(),
                FileSystem::ExFat,
                GuaranteeMode::ContentOnly,
                PreservationLimits::default(),
            )
            .expect("ntfs policy"),
        ] {
            assert_eq!(report.assessments.len(), PreservationField::ALL.len());
            let fields = report
                .assessments
                .iter()
                .map(|value| value.field)
                .collect::<std::collections::BTreeSet<_>>();
            assert_eq!(fields.len(), PreservationField::ALL.len());
        }
    }

    #[test]
    fn every_mode_has_explicit_and_stable_outcome_rules() {
        for mode in [
            GuaranteeMode::Strict,
            GuaranteeMode::Escrow,
            GuaranteeMode::ContentOnly,
        ] {
            let reports = [
                evaluate_exfat(
                    &exfat(),
                    FileSystem::Ntfs,
                    mode,
                    PreservationLimits::default(),
                )
                .expect("exfat policy"),
                evaluate_ntfs(
                    &ntfs(),
                    FileSystem::ExFat,
                    mode,
                    PreservationLimits::default(),
                )
                .expect("ntfs policy"),
            ];
            for report in reports {
                assert_eq!(report.mode, mode);
                assert_eq!(report.assessments.len(), PreservationField::ALL.len());
                match mode {
                    GuaranteeMode::Strict => {
                        assert!(report.escrow.is_none());
                        assert!(report.explicit_losses.is_empty());
                    }
                    GuaranteeMode::Escrow => {
                        assert!(report.escrow.is_some());
                        assert!(report.explicit_losses.is_empty());
                    }
                    GuaranteeMode::ContentOnly => {
                        assert!(report.escrow.is_none());
                        assert!(!report.explicit_losses.is_empty());
                    }
                }
            }
        }
    }

    #[test]
    fn strict_rejects_escrow_and_missing_evidence() {
        let report = evaluate_exfat(
            &exfat(),
            FileSystem::Ntfs,
            GuaranteeMode::Strict,
            PreservationLimits::default(),
        )
        .expect("policy");
        assert!(!report.permitted);
        assert!(report.blockers.contains(&PreservationField::Timestamps));
        assert!(!report.blockers.contains(&PreservationField::VolumeSerial));
        assert_eq!(
            disposition(&report, PreservationField::VolumeSerial),
            FieldDisposition::CanonicalTransform
        );
        assert!(report.explicit_losses.is_empty());
        assert!(report.escrow.is_none());
    }

    #[test]
    fn escrow_is_deterministic_checksummed_and_decodable() {
        let source = ntfs();
        let first = evaluate_ntfs(
            &source,
            FileSystem::ExFat,
            GuaranteeMode::Escrow,
            PreservationLimits::default(),
        )
        .expect("first");
        let second = evaluate_ntfs(
            &source,
            FileSystem::ExFat,
            GuaranteeMode::Escrow,
            PreservationLimits::default(),
        )
        .expect("second");
        assert_eq!(first.escrow, second.escrow);
        let encoded = first.escrow.expect("escrow");
        let decoded = decode_escrow(&encoded, PreservationLimits::default()).expect("decode");
        assert_eq!(decoded.source, FileSystem::Ntfs);
        assert_eq!(decoded.target, FileSystem::ExFat);
        assert_eq!(decoded.records.len(), 1);
        assert!(!decoded.records[0].value.is_empty());
        assert_eq!(
            decoded.ntfs_volume_identity,
            Some(NtfsVolumeIdentity {
                volume_serial_number: 0x0123_4567_89ab_cdef,
                volume_label: NtfsVolumeLabelIdentity::Absent,
            })
        );
    }

    #[test]
    fn exfat_escrow_preserves_serial_and_label_absence() {
        let source = exfat();
        let report = evaluate_exfat(
            &source,
            FileSystem::Ntfs,
            GuaranteeMode::Escrow,
            PreservationLimits::default(),
        )
        .expect("policy");
        let decoded = decode_escrow(
            report.escrow.as_deref().expect("escrow"),
            PreservationLimits::default(),
        )
        .expect("decode");
        assert_eq!(
            decoded.exfat_volume_identity,
            Some(ExfatVolumeIdentity {
                volume_serial_number: 0x1234_abcd,
                volume_label: ExfatVolumeLabelIdentity::Absent,
            })
        );
        assert_eq!(
            disposition(&report, PreservationField::VolumeSerial),
            FieldDisposition::CanonicalTransform
        );
        assert_eq!(
            disposition(&report, PreservationField::VolumeLabel),
            FieldDisposition::Native
        );

        let mut malformed_identity = report.escrow.expect("owned escrow");
        malformed_identity[HEADER_BYTES + RECORD_HEADER_BYTES + 6] = u8::MAX;
        let checksum = escrow_checksum(
            &malformed_identity[..24],
            &malformed_identity[HEADER_BYTES..],
        );
        malformed_identity[24..28].copy_from_slice(&checksum.to_le_bytes());
        assert!(matches!(
            decode_escrow(&malformed_identity, PreservationLimits::default()),
            Err(PreservationError::MalformedEscrow { .. })
        ));
    }

    #[test]
    fn ntfs_volume_identity_policy_is_width_and_legality_aware() {
        let mut source = ntfs();
        source.preservation.volume_label = Some("STAR".encode_utf16().collect());
        let legal = evaluate_ntfs(
            &source,
            FileSystem::ExFat,
            GuaranteeMode::Strict,
            PreservationLimits::default(),
        )
        .expect("policy");
        assert_eq!(
            disposition(&legal, PreservationField::VolumeLabel),
            FieldDisposition::CanonicalTransform
        );
        assert_eq!(
            disposition(&legal, PreservationField::VolumeSerial),
            FieldDisposition::EscrowRequired
        );
        assert!(legal.blockers.contains(&PreservationField::VolumeSerial));

        source.preservation.volume_label = Some("TOO-LONG-LABEL".encode_utf16().collect());
        let long = evaluate_ntfs(
            &source,
            FileSystem::ExFat,
            GuaranteeMode::ContentOnly,
            PreservationLimits::default(),
        )
        .expect("policy");
        assert_eq!(
            disposition(&long, PreservationField::VolumeLabel),
            FieldDisposition::EscrowRequired
        );
        assert!(
            long.explicit_losses
                .contains(&PreservationField::VolumeLabel)
        );

        source.preservation.volume_label = Some(vec![u16::from(b'*')]);
        let illegal = evaluate_ntfs(
            &source,
            FileSystem::ExFat,
            GuaranteeMode::Escrow,
            PreservationLimits::default(),
        )
        .expect("policy");
        assert_eq!(
            disposition(&illegal, PreservationField::VolumeLabel),
            FieldDisposition::EscrowRequired
        );

        source.preservation.volume_label = None;
        let absent = evaluate_ntfs(
            &source,
            FileSystem::ExFat,
            GuaranteeMode::ContentOnly,
            PreservationLimits::default(),
        )
        .expect("policy");
        assert_eq!(
            disposition(&absent, PreservationField::VolumeLabel),
            FieldDisposition::Native
        );
    }

    fn two_case_colliding_files(left: &str, right: &str) -> ObjectGraph {
        let file = |id: u64, stream: u64| ObjectRecord {
            id: ObjectId(id),
            kind: ObjectKind::File,
            link_count: 1,
            semantics: ObjectSemantics::default(),
            streams: vec![ObjectStream {
                id: StreamId(stream),
                name: None,
                logical_bytes: 0,
                initialized_bytes: 0,
                mapped_bytes: 0,
                allocated_bytes: 0,
                flags: StreamFlags::default(),
                storage: StreamStorage::Resident(Vec::new()),
            }],
        };
        ObjectGraph::build(
            ObjectId(1),
            vec![
                ObjectRecord {
                    id: ObjectId(1),
                    kind: ObjectKind::Directory,
                    link_count: 0,
                    semantics: ObjectSemantics::default(),
                    streams: Vec::new(),
                },
                file(2, 2),
                file(3, 3),
            ],
            vec![
                NamespaceEntry {
                    parent: ObjectId(1),
                    target: ObjectId(2),
                    name: left.encode_utf16().collect(),
                },
                NamespaceEntry {
                    parent: ObjectId(1),
                    target: ObjectId(3),
                    name: right.encode_utf16().collect(),
                },
            ],
            ExtentGraph::build(Vec::new(), 1_048_576, 8).expect("extents"),
            GRAPH_LIMITS,
        )
        .expect("graph")
    }

    fn symlink_reparse_payload() -> Vec<u8> {
        let mut payload = vec![0_u8; 16];
        payload[..4].copy_from_slice(&0xa000_000c_u32.to_le_bytes());
        payload[4..6].copy_from_slice(&8_u16.to_le_bytes());
        payload
    }

    fn ntfs_with_reparse_point(payload: Option<Vec<u8>>) -> NormalizedNtfs {
        let mut normalized = ntfs();
        let mut objects = normalized.graph.objects().to_vec();
        objects[0].semantics.is_reparse_point = true;
        normalized.graph = ObjectGraph::build(
            normalized.graph.root(),
            objects,
            normalized.graph.entries().to_vec(),
            normalized.graph.extents().clone(),
            GRAPH_LIMITS,
        )
        .expect("graph");
        let source = &mut normalized.preservation.objects[0].source;
        source.has_reparse_point = true;
        source.reparse_point = payload;
        source.attribute_census.push(NtfsAttributeEvidence {
            attribute_type: NTFS_REPARSE_POINT,
            name: None,
            flags_raw: 0,
            flags_unknown_bits: 0,
            attribute_id: 8,
            resident: true,
        });
        normalized
    }

    #[test]
    fn ntfs_exfat_reparse_points_are_escrowed_when_payload_is_complete() {
        let payload = symlink_reparse_payload();
        let complete = ntfs_with_reparse_point(Some(payload.clone()));
        let escrow = evaluate_ntfs(
            &complete,
            FileSystem::ExFat,
            GuaranteeMode::Escrow,
            PreservationLimits::default(),
        )
        .expect("policy");
        assert_eq!(
            disposition(&escrow, PreservationField::ReparsePoints),
            FieldDisposition::EscrowRequired
        );
        assert_eq!(
            disposition(&escrow, PreservationField::NtfsAttributes),
            FieldDisposition::Native
        );
        assert!(escrow.permitted);
        assert!(!escrow.blockers.contains(&PreservationField::ReparsePoints));
        let snapshot = escrow.escrow.expect("escrow");
        assert!(
            snapshot
                .windows(payload.len())
                .any(|window| window == payload),
            "exact $REPARSE_POINT bytes must appear in the inner NTFS snapshot"
        );

        let strict = evaluate_ntfs(
            &complete,
            FileSystem::ExFat,
            GuaranteeMode::Strict,
            PreservationLimits::default(),
        )
        .expect("policy");
        assert!(strict.blockers.contains(&PreservationField::ReparsePoints));

        let content_only = evaluate_ntfs(
            &complete,
            FileSystem::ExFat,
            GuaranteeMode::ContentOnly,
            PreservationLimits::default(),
        )
        .expect("policy");
        assert!(
            content_only
                .explicit_losses
                .contains(&PreservationField::ReparsePoints)
        );
        assert!(
            !content_only
                .blockers
                .contains(&PreservationField::ReparsePoints)
        );

        let incomplete = ntfs_with_reparse_point(None);
        let refused = evaluate_ntfs(
            &incomplete,
            FileSystem::ExFat,
            GuaranteeMode::Escrow,
            PreservationLimits::default(),
        )
        .expect("policy");
        assert_eq!(
            disposition(&refused, PreservationField::ReparsePoints),
            FieldDisposition::Refusal
        );
        assert!(refused.blockers.contains(&PreservationField::ReparsePoints));
        assert!(!refused.permitted);
    }

    #[test]
    fn ntfs_exfat_case_collisions_are_escrowed_while_illegal_names_remain_refusals() {
        let mut colliding = ntfs();
        colliding.graph = two_case_colliding_files("ReadMe.txt", "README.TXT");
        let escrow = evaluate_ntfs(
            &colliding,
            FileSystem::ExFat,
            GuaranteeMode::Escrow,
            PreservationLimits::default(),
        )
        .expect("policy");
        assert_eq!(
            disposition(&escrow, PreservationField::NamesAndCase),
            FieldDisposition::EscrowRequired
        );
        assert!(escrow.permitted);
        assert!(!escrow.blockers.contains(&PreservationField::NamesAndCase));

        let strict = evaluate_ntfs(
            &colliding,
            FileSystem::ExFat,
            GuaranteeMode::Strict,
            PreservationLimits::default(),
        )
        .expect("policy");
        assert!(strict.blockers.contains(&PreservationField::NamesAndCase));

        let content_only = evaluate_ntfs(
            &colliding,
            FileSystem::ExFat,
            GuaranteeMode::ContentOnly,
            PreservationLimits::default(),
        )
        .expect("policy");
        assert!(
            content_only
                .explicit_losses
                .contains(&PreservationField::NamesAndCase)
        );
        assert!(
            !content_only
                .blockers
                .contains(&PreservationField::NamesAndCase)
        );

        let mut illegal = ntfs();
        illegal.graph = two_case_colliding_files("ok.txt", "bad:name.txt");
        let refused = evaluate_ntfs(
            &illegal,
            FileSystem::ExFat,
            GuaranteeMode::Escrow,
            PreservationLimits::default(),
        )
        .expect("policy");
        assert_eq!(
            disposition(&refused, PreservationField::NamesAndCase),
            FieldDisposition::Refusal
        );
        assert!(refused.blockers.contains(&PreservationField::NamesAndCase));
        assert!(!refused.permitted);
    }

    #[test]
    fn ntfs_identity_schema_rejects_invalid_flags_and_lengths() {
        let report = evaluate_ntfs(
            &ntfs(),
            FileSystem::ExFat,
            GuaranteeMode::Escrow,
            PreservationLimits::default(),
        )
        .expect("policy");
        let mut invalid_flag = report.escrow.clone().expect("escrow");
        invalid_flag[HEADER_BYTES + RECORD_HEADER_BYTES + 10] = u8::MAX;
        let checksum = escrow_checksum(&invalid_flag[..24], &invalid_flag[HEADER_BYTES..]);
        invalid_flag[24..28].copy_from_slice(&checksum.to_le_bytes());
        assert!(matches!(
            decode_escrow(&invalid_flag, PreservationLimits::default()),
            Err(PreservationError::MalformedEscrow { .. })
        ));

        let mut overlong = report.escrow.expect("escrow");
        overlong[HEADER_BYTES + RECORD_HEADER_BYTES + 10] = 1;
        overlong[HEADER_BYTES + RECORD_HEADER_BYTES + 11] = 33;
        let checksum = escrow_checksum(&overlong[..24], &overlong[HEADER_BYTES..]);
        overlong[24..28].copy_from_slice(&checksum.to_le_bytes());
        assert!(matches!(
            decode_escrow(&overlong, PreservationLimits::default()),
            Err(PreservationError::MalformedEscrow { .. })
        ));
    }

    #[test]
    fn content_only_enumerates_losses_but_encryption_blocks_content() {
        let mut normalized = ntfs();
        let stream = ObjectStream {
            id: StreamId(9),
            name: Some("ads".encode_utf16().collect()),
            logical_bytes: 1,
            initialized_bytes: 1,
            mapped_bytes: 1,
            allocated_bytes: 0,
            flags: StreamFlags {
                sparse: false,
                compressed: false,
                encrypted: true,
                compression_block_bytes: 0,
            },
            storage: StreamStorage::Resident(vec![7]),
        };
        let root = ObjectRecord {
            id: ObjectId(1),
            kind: ObjectKind::Directory,
            link_count: 0,
            semantics: ObjectSemantics::default(),
            streams: vec![stream],
        };
        normalized.graph = ObjectGraph::build(
            ObjectId(1),
            vec![root],
            Vec::new(),
            ExtentGraph::build(Vec::new(), 1_048_576, 8).expect("extents"),
            GRAPH_LIMITS,
        )
        .expect("graph");
        let report = evaluate_ntfs(
            &normalized,
            FileSystem::ExFat,
            GuaranteeMode::ContentOnly,
            PreservationLimits::default(),
        )
        .expect("policy");
        assert!(!report.permitted);
        assert!(
            report
                .explicit_losses
                .contains(&PreservationField::AlternateDataStreams)
        );
        assert!(
            report
                .explicit_losses
                .contains(&PreservationField::Encryption)
        );
        assert_eq!(report.blockers, vec![PreservationField::Encryption]);
    }

    #[test]
    fn ntfs_exfat_compression_is_escrowed_with_the_compression_unit() {
        let mut normalized = ntfs();
        let stream = ObjectStream {
            id: StreamId(9),
            name: None,
            logical_bytes: 1,
            initialized_bytes: 1,
            mapped_bytes: 1,
            allocated_bytes: 0,
            flags: StreamFlags {
                sparse: false,
                compressed: true,
                encrypted: false,
                compression_block_bytes: 8192,
            },
            storage: StreamStorage::Resident(vec![7]),
        };
        let root = ObjectRecord {
            id: ObjectId(1),
            kind: ObjectKind::Directory,
            link_count: 0,
            semantics: ObjectSemantics::default(),
            streams: vec![stream],
        };
        normalized.graph = ObjectGraph::build(
            ObjectId(1),
            vec![root],
            Vec::new(),
            ExtentGraph::build(Vec::new(), 1_048_576, 8).expect("extents"),
            GRAPH_LIMITS,
        )
        .expect("graph");
        normalized.preservation.objects[0]
            .source
            .data_streams
            .push(NtfsDataStream {
                attribute_id: 4,
                name: None,
                compressed: true,
                encrypted: false,
                sparse: false,
                compression_block_bytes: 8192,
                storage: NtfsStreamStorage::Resident { bytes: vec![7] },
            });
        let escrow = evaluate_ntfs(
            &normalized,
            FileSystem::ExFat,
            GuaranteeMode::Escrow,
            PreservationLimits::default(),
        )
        .expect("policy");
        assert_eq!(
            disposition(&escrow, PreservationField::Compression),
            FieldDisposition::EscrowRequired
        );
        assert!(escrow.permitted);
        let snapshot = escrow.escrow.expect("escrow");
        assert!(
            snapshot
                .windows(8)
                .any(|window| window == 8192_u64.to_le_bytes()),
            "inner NTFS snapshot must retain the compression-unit size"
        );
        let strict = evaluate_ntfs(
            &normalized,
            FileSystem::ExFat,
            GuaranteeMode::Strict,
            PreservationLimits::default(),
        )
        .expect("policy");
        assert!(strict.blockers.contains(&PreservationField::Compression));
    }

    #[test]
    fn ntfs_feature_families_are_never_silently_defaulted() {
        let mut normalized = ntfs();
        normalized.preservation.objects[0]
            .source
            .standard_information
            .as_mut()
            .expect("standard")
            .security_id = Some(0x101);
        let report = evaluate_ntfs(
            &normalized,
            FileSystem::ExFat,
            GuaranteeMode::ContentOnly,
            PreservationLimits::default(),
        )
        .expect("policy");
        assert_eq!(
            disposition(&report, PreservationField::SecurityIdentifiers),
            FieldDisposition::EscrowRequired
        );
        assert_eq!(
            disposition(&report, PreservationField::VolumeSerial),
            FieldDisposition::EscrowRequired
        );
        assert!(
            report
                .explicit_losses
                .contains(&PreservationField::SecurityIdentifiers)
        );
    }

    #[test]
    fn unsupported_and_missing_ntfs_attribute_census_is_a_refusal() {
        let mut unsupported = ntfs();
        unsupported.preservation.objects[0]
            .source
            .attribute_census
            .push(NtfsAttributeEvidence {
                attribute_type: 0x40,
                name: None,
                flags_raw: 0,
                flags_unknown_bits: 0,
                attribute_id: 9,
                resident: true,
            });
        let report = evaluate_ntfs(
            &unsupported,
            FileSystem::ExFat,
            GuaranteeMode::Escrow,
            PreservationLimits::default(),
        )
        .unwrap();
        assert_eq!(
            disposition(&report, PreservationField::NtfsAttributes),
            FieldDisposition::Refusal
        );
        assert!(report.blockers.contains(&PreservationField::NtfsAttributes));

        let mut missing = ntfs();
        missing.preservation.objects[0]
            .source
            .attribute_census
            .clear();
        let report = evaluate_ntfs(
            &missing,
            FileSystem::ExFat,
            GuaranteeMode::Escrow,
            PreservationLimits::default(),
        )
        .unwrap();
        assert_eq!(
            disposition(&report, PreservationField::NtfsAttributes),
            FieldDisposition::Refusal
        );
    }

    #[test]
    fn badclus_requires_a_complete_entirely_sparse_mapping() {
        let sparse = evaluate_ntfs(
            &ntfs(),
            FileSystem::ExFat,
            GuaranteeMode::Escrow,
            PreservationLimits::default(),
        )
        .unwrap();
        assert_eq!(
            disposition(&sparse, PreservationField::BadClusters),
            FieldDisposition::EscrowRequired
        );

        let mut physical = ntfs();
        let NtfsStreamStorage::NonResident {
            allocated_bytes,
            extents,
            ..
        } = &mut physical.preservation.objects[1].source.data_streams[0].storage
        else {
            panic!("test $Bad stream must be non-resident");
        };
        *allocated_bytes = 1_048_576;
        extents[0].placement = NtfsExtentPlacement::Physical { byte_offset: 4096 };
        let report = evaluate_ntfs(
            &physical,
            FileSystem::ExFat,
            GuaranteeMode::Escrow,
            PreservationLimits::default(),
        )
        .unwrap();
        assert_eq!(
            disposition(&report, PreservationField::BadClusters),
            FieldDisposition::EscrowRequired
        );
        assert!(!report.blockers.contains(&PreservationField::BadClusters));

        let mut incomplete = ntfs();
        incomplete.preservation.objects.pop();
        let report = evaluate_ntfs(
            &incomplete,
            FileSystem::ExFat,
            GuaranteeMode::Escrow,
            PreservationLimits::default(),
        )
        .unwrap();
        assert_eq!(
            disposition(&report, PreservationField::BadClusters),
            FieldDisposition::Refusal
        );
    }

    #[test]
    fn pinned_ntfs_security_bytes_are_escrowed_and_independently_decoded() {
        let mut source = ntfs();
        let mut objects = source.graph.objects().to_vec();
        objects[0].semantics.has_security_descriptor = true;
        source.graph = crate::object::ObjectGraph::build(
            source.graph.root(),
            objects,
            source.graph.entries().to_vec(),
            source.graph.extents().clone(),
            crate::object::ObjectGraphLimits {
                max_objects: 2,
                max_entries: 2,
                max_streams: 2,
                max_name_code_units: 255,
            },
        )
        .unwrap();
        source.preservation.objects[0]
            .source
            .standard_information
            .as_mut()
            .unwrap()
            .security_id = Some(0x101);
        let secure = generate_ntfs_secure_metadata(
            NtfsSecureProfile::MkntfsWindows2003Ntfs31,
            NtfsSecureLimits::default(),
        )
        .unwrap();
        source.preservation.security_descriptors =
            NtfsSecurityDescriptorEvidence::PinnedNtfs3gWindows2003 {
                sds: secure.sds.clone(),
            };

        let report = evaluate_ntfs(
            &source,
            FileSystem::ExFat,
            GuaranteeMode::Escrow,
            PreservationLimits::default(),
        )
        .unwrap();
        assert_eq!(
            disposition(&report, PreservationField::SecurityDescriptors),
            FieldDisposition::EscrowRequired
        );
        let decoded = decode_escrow(
            report.escrow.as_deref().unwrap(),
            PreservationLimits::default(),
        )
        .unwrap();
        assert_eq!(
            decoded.ntfs_security_descriptors,
            Some(NtfsSecurityDescriptorEscrow::PinnedNtfs3gWindows2003 { sds: secure.sds })
        );
    }

    #[test]
    fn nonzero_exfat_padding_and_benign_entries_are_refused_without_raw_bytes() {
        let mut source = exfat();
        source
            .preservation
            .directory_evidence
            .nonzero_name_padding_sets = 1;
        source.preservation.directory_evidence.benign_primary_sets = 1;
        let report = evaluate_exfat(
            &source,
            FileSystem::Ntfs,
            GuaranteeMode::Escrow,
            PreservationLimits::default(),
        )
        .expect("policy");
        assert_eq!(
            disposition(&report, PreservationField::ExfatPadding),
            FieldDisposition::Refusal
        );
        assert_eq!(
            disposition(&report, PreservationField::ExfatBenignEntries),
            FieldDisposition::Refusal
        );
        assert!(!report.permitted);
    }

    #[test]
    fn caps_apply_before_unbounded_growth() {
        let tiny = PreservationLimits {
            max_assessments: PreservationField::ALL.len(),
            max_escrow_bytes: 64,
            max_record_bytes: 32,
        };
        assert!(matches!(
            evaluate_exfat(&exfat(), FileSystem::Ntfs, GuaranteeMode::Escrow, tiny),
            Err(PreservationError::RecordLimitExceeded { .. }
                | PreservationError::EscrowLimitExceeded { .. })
        ));
        let too_few = PreservationLimits {
            max_assessments: 1,
            ..PreservationLimits::default()
        };
        assert!(matches!(
            evaluate_ntfs(&ntfs(), FileSystem::ExFat, GuaranteeMode::Strict, too_few),
            Err(PreservationError::AssessmentLimitExceeded { .. })
        ));
    }

    #[test]
    fn decoder_rejects_truncation_checksum_unknown_tags_and_trailing_bytes() {
        let report = evaluate_ntfs(
            &ntfs(),
            FileSystem::ExFat,
            GuaranteeMode::Escrow,
            PreservationLimits::default(),
        )
        .expect("policy");
        let encoded = report.escrow.expect("escrow");
        assert!(decode_escrow(&encoded[..10], PreservationLimits::default()).is_err());

        let mut bad_checksum = encoded.clone();
        let last = bad_checksum.len() - 1;
        bad_checksum[last] ^= 1;
        assert!(matches!(
            decode_escrow(&bad_checksum, PreservationLimits::default()),
            Err(PreservationError::ChecksumMismatch { .. })
        ));

        let mut bad_header = encoded.clone();
        bad_header[10] = EXFAT_SOURCE;
        bad_header[11] = NTFS_SOURCE;
        assert!(matches!(
            decode_escrow(&bad_header, PreservationLimits::default()),
            Err(PreservationError::ChecksumMismatch { .. })
        ));

        let mut bad_tag = encoded.clone();
        bad_tag[HEADER_BYTES..HEADER_BYTES + 2].copy_from_slice(&u16::MAX.to_le_bytes());
        let checksum = escrow_checksum(&bad_tag[..24], &bad_tag[HEADER_BYTES..]);
        bad_tag[24..28].copy_from_slice(&checksum.to_le_bytes());
        assert!(matches!(
            decode_escrow(&bad_tag, PreservationLimits::default()),
            Err(PreservationError::MalformedEscrow { .. })
        ));

        let mut bad_snapshot_version = encoded.clone();
        let snapshot_start = HEADER_BYTES + RECORD_HEADER_BYTES;
        bad_snapshot_version[snapshot_start..snapshot_start + 2]
            .copy_from_slice(&1_u16.to_le_bytes());
        let checksum = escrow_checksum(
            &bad_snapshot_version[..24],
            &bad_snapshot_version[HEADER_BYTES..],
        );
        bad_snapshot_version[24..28].copy_from_slice(&checksum.to_le_bytes());
        assert!(matches!(
            decode_escrow(&bad_snapshot_version, PreservationLimits::default()),
            Err(PreservationError::MalformedEscrow { .. })
        ));

        let mut trailing = encoded;
        trailing.push(0);
        assert!(matches!(
            decode_escrow(&trailing, PreservationLimits::default()),
            Err(PreservationError::MalformedEscrow { .. })
        ));
    }

    #[test]
    fn decoder_walks_every_nested_snapshot_field_after_checksum_validation() {
        let report = evaluate_exfat(
            &exfat(),
            FileSystem::Ntfs,
            GuaranteeMode::Escrow,
            PreservationLimits::default(),
        )
        .expect("policy");
        let encoded = report.escrow.expect("escrow");
        let snapshot = HEADER_BYTES + RECORD_HEADER_BYTES;

        // This root-directory boolean lies beyond the identity fields decoded by older readers.
        let mut invalid_boolean = encoded.clone();
        invalid_boolean[snapshot + 47] = 2;
        let checksum = escrow_checksum(&invalid_boolean[..24], &invalid_boolean[HEADER_BYTES..]);
        invalid_boolean[24..28].copy_from_slice(&checksum.to_le_bytes());
        assert!(matches!(
            decode_escrow(&invalid_boolean, PreservationLimits::default()),
            Err(PreservationError::MalformedEscrow { .. })
        ));

        // The nested Up-case mapping count must be rejected before an attacker-controlled loop.
        let mut impossible_count = encoded;
        impossible_count[snapshot + 80..snapshot + 88].copy_from_slice(&u64::MAX.to_le_bytes());
        let checksum = escrow_checksum(&impossible_count[..24], &impossible_count[HEADER_BYTES..]);
        impossible_count[24..28].copy_from_slice(&checksum.to_le_bytes());
        assert!(matches!(
            decode_escrow(&impossible_count, PreservationLimits::default()),
            Err(PreservationError::MalformedEscrow { .. } | PreservationError::ArithmeticOverflow)
        ));
    }

    #[test]
    fn decoder_keeps_current_ntfs_v7_snapshots_readable() {
        let report = evaluate_ntfs(
            &ntfs(),
            FileSystem::ExFat,
            GuaranteeMode::Escrow,
            PreservationLimits::default(),
        )
        .expect("policy");
        let current = report.escrow.expect("escrow");
        let snapshot_start = HEADER_BYTES + RECORD_HEADER_BYTES;
        assert_eq!(
            &current[snapshot_start..snapshot_start + 2],
            &7_u16.to_le_bytes()
        );
        let decoded = decode_escrow(&current, PreservationLimits::default()).expect("current v7");
        assert_eq!(
            &decoded.records[0].value[..2],
            &7_u16.to_le_bytes(),
            "the current inner NTFS snapshot remains preserved verbatim"
        );
        assert_eq!(
            decoded.ntfs_volume_identity,
            Some(NtfsVolumeIdentity {
                volume_serial_number: ntfs().preservation.volume_serial_number,
                volume_label: NtfsVolumeLabelIdentity::Absent,
            })
        );
        assert_eq!(
            decode_ntfs_sidecar_from_escrow(&current, PreservationLimits::default())
                .expect("restore decoder"),
            ntfs().preservation
        );
    }

    #[test]
    fn invalid_target_and_zero_limits_are_rejected() {
        assert!(matches!(
            evaluate_exfat(
                &exfat(),
                FileSystem::ExFat,
                GuaranteeMode::Strict,
                PreservationLimits::default()
            ),
            Err(PreservationError::SameSourceAndTarget(FileSystem::ExFat))
        ));
        let invalid = PreservationLimits {
            max_record_bytes: 0,
            ..PreservationLimits::default()
        };
        assert!(matches!(
            evaluate_ntfs(&ntfs(), FileSystem::ExFat, GuaranteeMode::Strict, invalid),
            Err(PreservationError::InvalidLimit("max_record_bytes"))
        ));
    }
}
