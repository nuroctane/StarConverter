//! Lossless normalization of complete NTFS inventory evidence.
//!
//! This adapter performs no I/O. It converts an already bounded inventory into the
//! filesystem-neutral object graph while retaining every NTFS-specific field exposed by the
//! inventory in a preservation sidecar. Inventories with unresolved continuations or ambiguous
//! namespace evidence are rejected rather than guessed at.

#![allow(clippy::module_name_repetitions)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use super::ntfs_index::FileNameNamespace;
use super::ntfs_inventory::{
    NtfsDataStream, NtfsFileName, NtfsInventory, NtfsInventoryExtent,
    NtfsInventoryIncompleteReason, NtfsObject, NtfsObjectReference, NtfsStreamStorage,
    NtfsVolumeLabelEvidence,
};
use crate::extent::{Extent, ExtentGraph, ExtentGraphError, ExtentKind, Placement, StreamId};
use crate::object::{
    NamespaceEntry, ObjectGraph, ObjectGraphError, ObjectGraphLimits, ObjectId, ObjectKind,
    ObjectRecord, ObjectSemantics, ObjectStream, StreamFlags, StreamStorage,
};

const NTFS_ROOT_RECORD: u64 = 5;
const NTFS_EXTEND_RECORD: u64 = 11;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const NTFS_VOLUME_LABEL_MAX_CODE_UNITS: usize = 32;

/// Caller-controlled normalization and preservation bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtfsNormalizeLimits {
    pub graph: ObjectGraphLimits,
    pub max_extents: usize,
    pub max_directory_entries: usize,
    /// Maximum resident payload plus UTF-16 name bytes copied into the graph and sidecar.
    pub max_preservation_bytes: u64,
}

/// Exact NTFS source record paired with its stable record-derived identity.
///
/// NTFS system metadata records other than the root are intentionally not present in the neutral
/// object graph, but remain here so a later NTFS writer can reproduce their source semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsObjectPreservation {
    pub object: ObjectId,
    pub source: NtfsObject,
}

/// Exact security-descriptor evidence available to preservation policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NtfsSecurityDescriptorEvidence {
    /// Object records expose security IDs, but descriptor bytes were not proven.
    Unavailable,
    /// Exact canonical `$Secure:$SDS` bytes from the pinned NTFS-3G Windows-2003 profile.
    PinnedNtfs3gWindows2003 { sds: Vec<u8> },
}

/// NTFS-only evidence that must accompany a neutral graph for faithful planning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsPreservationSidecar {
    pub volume_serial_number: u64,
    pub volume_label: Option<Vec<u16>>,
    pub security_descriptors: NtfsSecurityDescriptorEvidence,
    pub root_reference: NtfsObjectReference,
    pub objects: Vec<NtfsObjectPreservation>,
    pub source_extents: Vec<NtfsInventoryExtent>,
    pub scanned_records: u64,
    pub initialized_records: u64,
    pub in_use_base_records: u64,
    pub extension_records: u64,
    pub bytes_read: u64,
}

/// A neutral object graph inseparably paired with exact NTFS inventory evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedNtfs {
    pub graph: ObjectGraph,
    pub preservation: NtfsPreservationSidecar,
}

/// Failure to prove that NTFS evidence is complete, unambiguous, and self-consistent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NtfsNormalizeError {
    InvalidLimit(&'static str),
    EmptyInventory,
    IncompleteInventory(Vec<NtfsInventoryIncompleteReason>),
    UnavailableVolumeLabelEvidence,
    InvalidVolumeLabelLength {
        actual: usize,
        maximum: usize,
    },
    PartialRecordScan {
        scanned: u64,
        initialized: u64,
    },
    BaseRecordCountMismatch {
        declared: u64,
        actual: usize,
    },
    DuplicateObjectReference(u64),
    ObjectReferenceTooLarge(u64),
    MissingRoot,
    RootNotDirectory,
    RootHasExternalName,
    MissingStandardInformation(u64),
    AttributeKindMismatch(u64),
    ReparseFlagMismatch(u64),
    IncompleteDirectoryIndex(u64),
    MissingFileName(u64),
    HardLinkCountMismatch {
        record: u64,
        declared: u16,
        names: usize,
    },
    MissingParent {
        record: u64,
        parent: u64,
    },
    ParentNotDirectory {
        record: u64,
        parent: u64,
    },
    StaleReference {
        record: u64,
        expected: u16,
        found: u16,
    },
    MissingTarget(u64),
    DirectoryParentMismatch {
        directory: u64,
        encoded_parent: u64,
    },
    DirectoryEvidenceMismatch,
    DirectoryEntryLimitExceeded {
        actual: usize,
        maximum: usize,
    },
    PreservationLimitExceeded {
        requested: u64,
        maximum: u64,
    },
    NameTooLong {
        record: u64,
        actual: usize,
        maximum: usize,
    },
    EmptyStreamName(u64),
    DuplicateStreamName(u64),
    AmbiguousResidentFlags(StreamId),
    ConflictingStreamFlags(StreamId),
    StreamIdOverflow {
        record: u64,
        attribute_id: u16,
    },
    DuplicateStreamId(StreamId),
    IncompleteStream(StreamId),
    InvalidStreamSizes(StreamId),
    InvalidCompressedSize(StreamId),
    AmbiguousSparseExtent(StreamId),
    StreamExtentMismatch(StreamId),
    InventoryExtentMismatch,
    ArithmeticOverflow,
    Extents(ExtentGraphError),
    Graph(ObjectGraphError),
}

impl fmt::Display for NtfsNormalizeError {
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit(field) => {
                write!(formatter, "NTFS normalization limit {field} is zero")
            }
            Self::EmptyInventory => formatter.write_str("NTFS inventory contains no objects"),
            Self::IncompleteInventory(reasons) => {
                write!(formatter, "NTFS inventory is incomplete: {reasons:?}")
            }
            Self::UnavailableVolumeLabelEvidence => {
                formatter.write_str("NTFS inventory did not reach record 3 volume-label evidence")
            }
            Self::InvalidVolumeLabelLength { actual, maximum } => write!(
                formatter,
                "NTFS volume label has {actual} UTF-16 units, exceeding {maximum}"
            ),
            Self::PartialRecordScan {
                scanned,
                initialized,
            } => write!(
                formatter,
                "NTFS inventory scanned {scanned} of {initialized} initialized records"
            ),
            Self::BaseRecordCountMismatch { declared, actual } => write!(
                formatter,
                "NTFS inventory declares {declared} base records but contains {actual}"
            ),
            Self::DuplicateObjectReference(record) => {
                write!(formatter, "NTFS record {record} appears more than once")
            }
            Self::ObjectReferenceTooLarge(record) => write!(
                formatter,
                "NTFS record {record} exceeds the 48-bit file-reference space"
            ),
            Self::MissingRoot => formatter.write_str("NTFS root record 5 is absent"),
            Self::RootNotDirectory => formatter.write_str("NTFS root record 5 is not a directory"),
            Self::RootHasExternalName => {
                formatter.write_str("NTFS root has a file name whose parent is not itself")
            }
            Self::MissingStandardInformation(record) => write!(
                formatter,
                "NTFS record {record} has no standard information"
            ),
            Self::AttributeKindMismatch(record) => write!(
                formatter,
                "NTFS record {record} directory attribute disagrees with its record kind"
            ),
            Self::ReparseFlagMismatch(record) => write!(
                formatter,
                "NTFS record {record} reparse attribute and standard-information flag disagree"
            ),
            Self::IncompleteDirectoryIndex(record) => write!(
                formatter,
                "NTFS directory {record} has incomplete index evidence"
            ),
            Self::MissingFileName(record) => {
                write!(formatter, "NTFS record {record} has no namespace name")
            }
            Self::HardLinkCountMismatch {
                record,
                declared,
                names,
            } => write!(
                formatter,
                "NTFS record {record} declares {declared} links but has {names} file-name attributes"
            ),
            Self::MissingParent { record, parent } => write!(
                formatter,
                "NTFS record {record} names missing parent record {parent}"
            ),
            Self::ParentNotDirectory { record, parent } => write!(
                formatter,
                "NTFS record {record} names non-directory parent {parent}"
            ),
            Self::StaleReference {
                record,
                expected,
                found,
            } => write!(
                formatter,
                "NTFS reference to record {record} expects sequence {expected}, found {found}"
            ),
            Self::MissingTarget(record) => write!(
                formatter,
                "NTFS directory entry names missing target record {record}"
            ),
            Self::DirectoryParentMismatch {
                directory,
                encoded_parent,
            } => write!(
                formatter,
                "NTFS directory {directory} contains a key naming parent {encoded_parent}"
            ),
            Self::DirectoryEvidenceMismatch => formatter
                .write_str("NTFS file-name attributes and directory-index entries disagree"),
            Self::DirectoryEntryLimitExceeded { actual, maximum } => write!(
                formatter,
                "NTFS directory evidence count {actual} exceeds {maximum}"
            ),
            Self::PreservationLimitExceeded { requested, maximum } => write!(
                formatter,
                "NTFS preservation data requires {requested} bytes, exceeding {maximum}"
            ),
            Self::NameTooLong {
                record,
                actual,
                maximum,
            } => write!(
                formatter,
                "NTFS record {record} contains a {actual}-unit name, exceeding {maximum}"
            ),
            Self::EmptyStreamName(record) => {
                write!(
                    formatter,
                    "NTFS record {record} contains an empty named data stream"
                )
            }
            Self::DuplicateStreamName(record) => write!(
                formatter,
                "NTFS record {record} contains duplicate data-stream names"
            ),
            Self::AmbiguousResidentFlags(stream) => write!(
                formatter,
                "resident NTFS stream {} carries non-resident storage flags",
                stream.0
            ),
            Self::ConflictingStreamFlags(stream) => write!(
                formatter,
                "NTFS stream {} is both compressed and encrypted",
                stream.0
            ),
            Self::StreamIdOverflow {
                record,
                attribute_id,
            } => write!(
                formatter,
                "NTFS record {record} attribute {attribute_id} cannot form a stable stream identity"
            ),
            Self::DuplicateStreamId(stream) => {
                write!(formatter, "NTFS stream identity {} is duplicated", stream.0)
            }
            Self::IncompleteStream(stream) => write!(
                formatter,
                "NTFS stream {} has incomplete mapping evidence",
                stream.0
            ),
            Self::InvalidStreamSizes(stream) => {
                write!(formatter, "NTFS stream {} has inconsistent sizes", stream.0)
            }
            Self::InvalidCompressedSize(stream) => write!(
                formatter,
                "NTFS stream {} has an invalid compressed size",
                stream.0
            ),
            Self::AmbiguousSparseExtent(stream) => write!(
                formatter,
                "NTFS stream {} has a sparse extent without sparse or compressed semantics",
                stream.0
            ),
            Self::StreamExtentMismatch(stream) => write!(
                formatter,
                "NTFS stream {} extents disagree with its size or allocation",
                stream.0
            ),
            Self::InventoryExtentMismatch => formatter
                .write_str("NTFS global extent inventory disagrees with per-stream evidence"),
            Self::ArithmeticOverflow => {
                formatter.write_str("NTFS normalization accounting overflowed")
            }
            Self::Extents(error) => {
                write!(formatter, "normalized NTFS extents are invalid: {error}")
            }
            Self::Graph(error) => write!(
                formatter,
                "normalized NTFS object graph is invalid: {error}"
            ),
        }
    }
}

impl std::error::Error for NtfsNormalizeError {}

/// Converts a complete NTFS inventory without reading or modifying an image.
///
/// `volume_bytes` is supplied separately because [`NtfsInventory`] intentionally contains only
/// object extents. It is used solely to prove that every physical extent is within the source
/// volume.
///
/// # Errors
///
/// Returns [`NtfsNormalizeError`] for incomplete scans or continuations, stale references,
/// namespace disagreement, inconsistent stream accounting, or caller-cap exhaustion.
#[allow(clippy::too_many_lines)]
pub fn normalize_inventory(
    inventory: &NtfsInventory,
    volume_bytes: u64,
    limits: NtfsNormalizeLimits,
) -> Result<NormalizedNtfs, NtfsNormalizeError> {
    validate_limits(volume_bytes, limits)?;
    validate_inventory_completeness(inventory)?;
    let volume_label = match &inventory.volume_label {
        NtfsVolumeLabelEvidence::Unavailable => {
            return Err(NtfsNormalizeError::UnavailableVolumeLabelEvidence);
        }
        NtfsVolumeLabelEvidence::Absent => None,
        NtfsVolumeLabelEvidence::Exact(units) => {
            if units.len() > NTFS_VOLUME_LABEL_MAX_CODE_UNITS {
                return Err(NtfsNormalizeError::InvalidVolumeLabelLength {
                    actual: units.len(),
                    maximum: NTFS_VOLUME_LABEL_MAX_CODE_UNITS,
                });
            }
            Some(units.clone())
        }
    };

    let all_records = index_records(&inventory.objects)?;
    let records = all_records
        .iter()
        .filter(|(record, object)| is_graph_record(**record, object.is_metadata))
        .map(|(record, object)| (*record, *object))
        .collect::<BTreeMap<_, _>>();
    let root_source = records
        .get(&NTFS_ROOT_RECORD)
        .copied()
        .ok_or(NtfsNormalizeError::MissingRoot)?;
    if !root_source.is_directory {
        return Err(NtfsNormalizeError::RootNotDirectory);
    }

    let preservation_bytes = preservation_bytes(inventory)?;
    if preservation_bytes > limits.max_preservation_bytes {
        return Err(NtfsNormalizeError::PreservationLimitExceeded {
            requested: preservation_bytes,
            maximum: limits.max_preservation_bytes,
        });
    }

    validate_records(&records, limits.graph.max_name_code_units)?;
    validate_directory_evidence(inventory, &records, limits.max_directory_entries)?;

    let mut extents = Vec::new();
    let mut objects = Vec::with_capacity(inventory.objects.len());
    let mut entries = Vec::new();
    let preservation = inventory
        .objects
        .iter()
        .map(|source| NtfsObjectPreservation {
            object: ObjectId(source.reference.record_number),
            source: source.clone(),
        })
        .collect();
    let mut stream_ids = BTreeSet::new();
    for source in inventory
        .objects
        .iter()
        .filter(|source| is_graph_record(source.reference.record_number, source.is_metadata))
    {
        let id = ObjectId(source.reference.record_number);
        let standard =
            source
                .standard_information
                .ok_or(NtfsNormalizeError::MissingStandardInformation(
                    source.reference.record_number,
                ))?;
        let mut streams = Vec::with_capacity(source.data_streams.len());
        let mut names = BTreeSet::new();
        for stream in &source.data_streams {
            let name = stream.name.as_ref().map(|value| value.code_units.clone());
            if name.as_ref().is_some_and(Vec::is_empty) {
                return Err(NtfsNormalizeError::EmptyStreamName(
                    source.reference.record_number,
                ));
            }
            if name
                .as_ref()
                .is_some_and(|value| value.len() > limits.graph.max_name_code_units)
            {
                return Err(NtfsNormalizeError::NameTooLong {
                    record: source.reference.record_number,
                    actual: name.as_ref().map_or(0, Vec::len),
                    maximum: limits.graph.max_name_code_units,
                });
            }
            if !names.insert(name.clone()) {
                return Err(NtfsNormalizeError::DuplicateStreamName(
                    source.reference.record_number,
                ));
            }
            let normalized =
                normalize_stream(source.reference.record_number, stream, &mut extents)?;
            if !stream_ids.insert(normalized.id) {
                return Err(NtfsNormalizeError::DuplicateStreamId(normalized.id));
            }
            streams.push(normalized);
        }
        let mut graph_links = 0_u32;
        for file_name in &source.file_names {
            if source.reference.record_number == NTFS_ROOT_RECORD {
                if file_name.parent != source.reference {
                    return Err(NtfsNormalizeError::RootHasExternalName);
                }
            } else if !is_dos_short_name_companion(file_name, &source.file_names) {
                graph_links = graph_links
                    .checked_add(1)
                    .ok_or(NtfsNormalizeError::ArithmeticOverflow)?;
                entries.push(NamespaceEntry {
                    parent: ObjectId(file_name.parent.record_number),
                    target: id,
                    name: file_name.name.code_units.clone(),
                });
            }
        }
        objects.push(ObjectRecord {
            id,
            kind: if source.is_directory {
                ObjectKind::Directory
            } else {
                ObjectKind::File
            },
            link_count: graph_links,
            semantics: ObjectSemantics {
                has_security_descriptor: standard.security_id.is_some(),
                is_reparse_point: source.has_reparse_point,
            },
            streams,
        });
    }

    validate_inventory_extents(inventory)?;
    validate_graph_extents(&inventory.extents, &extents, &stream_ids)?;
    let extent_graph = ExtentGraph::build(extents, volume_bytes, limits.max_extents)
        .map_err(NtfsNormalizeError::Extents)?;
    let graph = ObjectGraph::build(
        ObjectId(NTFS_ROOT_RECORD),
        objects,
        entries,
        extent_graph,
        limits.graph,
    )
    .map_err(NtfsNormalizeError::Graph)?;

    Ok(NormalizedNtfs {
        graph,
        preservation: NtfsPreservationSidecar {
            volume_serial_number: inventory.volume_serial_number,
            volume_label,
            security_descriptors: NtfsSecurityDescriptorEvidence::Unavailable,
            root_reference: root_source.reference,
            objects: preservation,
            source_extents: inventory.extents.clone(),
            scanned_records: inventory.scanned_records,
            initialized_records: inventory.initialized_records,
            in_use_base_records: inventory.in_use_base_records,
            extension_records: inventory.extension_records,
            bytes_read: inventory.bytes_read,
        },
    })
}

const fn is_graph_record(record_number: u64, is_metadata: bool) -> bool {
    record_number == NTFS_ROOT_RECORD || (!is_metadata && record_number != NTFS_EXTEND_RECORD)
}

fn validate_limits(
    volume_bytes: u64,
    limits: NtfsNormalizeLimits,
) -> Result<(), NtfsNormalizeError> {
    for (field, value) in [
        ("volume_bytes", usize::from(volume_bytes != 0)),
        ("max_extents", limits.max_extents),
        ("max_directory_entries", limits.max_directory_entries),
        (
            "max_preservation_bytes",
            usize::from(limits.max_preservation_bytes != 0),
        ),
    ] {
        if value == 0 {
            return Err(NtfsNormalizeError::InvalidLimit(field));
        }
    }
    Ok(())
}

fn validate_inventory_completeness(inventory: &NtfsInventory) -> Result<(), NtfsNormalizeError> {
    if inventory.objects.is_empty() {
        return Err(NtfsNormalizeError::EmptyInventory);
    }
    if !inventory.incomplete_reasons.is_empty() {
        return Err(NtfsNormalizeError::IncompleteInventory(
            inventory.incomplete_reasons.clone(),
        ));
    }
    if inventory.scanned_records != inventory.initialized_records {
        return Err(NtfsNormalizeError::PartialRecordScan {
            scanned: inventory.scanned_records,
            initialized: inventory.initialized_records,
        });
    }
    if usize::try_from(inventory.in_use_base_records).ok() != Some(inventory.objects.len()) {
        return Err(NtfsNormalizeError::BaseRecordCountMismatch {
            declared: inventory.in_use_base_records,
            actual: inventory.objects.len(),
        });
    }
    Ok(())
}

fn index_records(objects: &[NtfsObject]) -> Result<BTreeMap<u64, &NtfsObject>, NtfsNormalizeError> {
    let mut records = BTreeMap::new();
    for object in objects {
        let record = object.reference.record_number;
        if record > 0x0000_ffff_ffff_ffff {
            return Err(NtfsNormalizeError::ObjectReferenceTooLarge(record));
        }
        if records.insert(record, object).is_some() {
            return Err(NtfsNormalizeError::DuplicateObjectReference(record));
        }
    }
    Ok(records)
}

fn validate_records(
    records: &BTreeMap<u64, &NtfsObject>,
    max_name_code_units: usize,
) -> Result<(), NtfsNormalizeError> {
    for (&record, object) in records {
        let standard = object
            .standard_information
            .ok_or(NtfsNormalizeError::MissingStandardInformation(record))?;
        // The FILE record's directory flag is authoritative. NTFS-3G-created directories can
        // legitimately omit FILE_ATTRIBUTE_DIRECTORY from $STANDARD_INFORMATION (record 5 uses
        // HIDDEN|SYSTEM|ARCHIVE), while setting that bit on a non-directory is contradictory.
        if standard.file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0 && !object.is_directory {
            return Err(NtfsNormalizeError::AttributeKindMismatch(record));
        }
        if (standard.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0)
            != object.has_reparse_point
        {
            return Err(NtfsNormalizeError::ReparseFlagMismatch(record));
        }
        if object.is_directory && !object.directory_index_complete {
            return Err(NtfsNormalizeError::IncompleteDirectoryIndex(record));
        }
        if object.file_names.is_empty() {
            return Err(NtfsNormalizeError::MissingFileName(record));
        }
        if usize::from(object.hard_link_count) != object.file_names.len() {
            return Err(NtfsNormalizeError::HardLinkCountMismatch {
                record,
                declared: object.hard_link_count,
                names: object.file_names.len(),
            });
        }
        for name in &object.file_names {
            if name.name.code_units.len() > max_name_code_units {
                return Err(NtfsNormalizeError::NameTooLong {
                    record,
                    actual: name.name.code_units.len(),
                    maximum: max_name_code_units,
                });
            }
            let parent = records.get(&name.parent.record_number).copied().ok_or(
                NtfsNormalizeError::MissingParent {
                    record,
                    parent: name.parent.record_number,
                },
            )?;
            validate_reference(name.parent, parent.reference)?;
            if !parent.is_directory {
                return Err(NtfsNormalizeError::ParentNotDirectory {
                    record,
                    parent: name.parent.record_number,
                });
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
// `$FILE_NAME` caches sizes, timestamps, attributes, and EA/reparse state. Those duplicate fields
// can legitimately become stale until the name changes, so namespace agreement is deliberately
// limited to the exact binding identity below. Both cached variants remain in preservation data.
struct DirectoryKey {
    target_record: u64,
    target_sequence: u16,
    parent_record: u64,
    parent_sequence: u16,
    namespace: u8,
    name: Vec<u16>,
    name_is_well_formed: bool,
}

fn directory_key(target: NtfsObjectReference, name: &NtfsFileName) -> DirectoryKey {
    DirectoryKey {
        target_record: target.record_number,
        target_sequence: target.sequence_number,
        parent_record: name.parent.record_number,
        parent_sequence: name.parent.sequence_number,
        namespace: namespace_id(name.namespace),
        name: name.name.code_units.clone(),
        name_is_well_formed: name.name.is_well_formed,
    }
}

fn validate_directory_evidence(
    inventory: &NtfsInventory,
    records: &BTreeMap<u64, &NtfsObject>,
    maximum: usize,
) -> Result<(), NtfsNormalizeError> {
    let actual = inventory
        .objects
        .iter()
        .filter(|object| records.contains_key(&object.reference.record_number))
        .try_fold(0_usize, |sum, object| {
            let graph_entries = object
                .directory_entries
                .iter()
                .filter(|entry| records.contains_key(&entry.target.record_number))
                .count();
            sum.checked_add(graph_entries)
        });
    let actual = actual.ok_or(NtfsNormalizeError::ArithmeticOverflow)?;
    if actual > maximum {
        return Err(NtfsNormalizeError::DirectoryEntryLimitExceeded { actual, maximum });
    }
    let mut expected = BTreeMap::<DirectoryKey, usize>::new();
    for target in inventory
        .objects
        .iter()
        .filter(|target| records.contains_key(&target.reference.record_number))
    {
        for name in &target.file_names {
            if target.reference.record_number == NTFS_ROOT_RECORD && name.parent == target.reference
            {
                continue;
            }
            increment(&mut expected, directory_key(target.reference, name))?;
        }
    }
    let mut observed = BTreeMap::<DirectoryKey, usize>::new();
    for directory in inventory
        .objects
        .iter()
        .filter(|directory| records.contains_key(&directory.reference.record_number))
    {
        for entry in &directory.directory_entries {
            if !records.contains_key(&entry.target.record_number) {
                continue;
            }
            if entry.file_name.parent != directory.reference {
                return Err(NtfsNormalizeError::DirectoryParentMismatch {
                    directory: directory.reference.record_number,
                    encoded_parent: entry.file_name.parent.record_number,
                });
            }
            let target = records.get(&entry.target.record_number).copied().ok_or(
                NtfsNormalizeError::MissingTarget(entry.target.record_number),
            )?;
            validate_reference(entry.target, target.reference)?;
            let key = directory_key(entry.target, &entry.file_name);
            if directory.reference.record_number == NTFS_ROOT_RECORD
                && entry.target == directory.reference
            {
                // NTFS-3G indexes the root's self-parented `.` FILE_NAME while other valid
                // formatters omit that redundant index entry. Accept either representation, but
                // require any present self-entry to match the root's actual FILE_NAME evidence.
                if !target
                    .file_names
                    .iter()
                    .any(|name| directory_key(target.reference, name) == key)
                {
                    return Err(NtfsNormalizeError::DirectoryEvidenceMismatch);
                }
                continue;
            }
            increment(&mut observed, key)?;
        }
    }
    if expected != observed {
        return Err(NtfsNormalizeError::DirectoryEvidenceMismatch);
    }
    Ok(())
}

fn increment(
    values: &mut BTreeMap<DirectoryKey, usize>,
    key: DirectoryKey,
) -> Result<(), NtfsNormalizeError> {
    let value = values.entry(key).or_default();
    *value = value
        .checked_add(1)
        .ok_or(NtfsNormalizeError::ArithmeticOverflow)?;
    Ok(())
}

const fn validate_reference(
    expected: NtfsObjectReference,
    actual: NtfsObjectReference,
) -> Result<(), NtfsNormalizeError> {
    if expected.sequence_number != actual.sequence_number {
        return Err(NtfsNormalizeError::StaleReference {
            record: expected.record_number,
            expected: expected.sequence_number,
            found: actual.sequence_number,
        });
    }
    Ok(())
}

fn normalize_stream(
    record: u64,
    source: &NtfsDataStream,
    output_extents: &mut Vec<Extent>,
) -> Result<ObjectStream, NtfsNormalizeError> {
    let id = stream_id(record, source.attribute_id)?;
    let name = source.name.as_ref().map(|value| value.code_units.clone());
    let flags = StreamFlags {
        sparse: source.sparse,
        compressed: source.compressed,
        encrypted: source.encrypted,
        compression_block_bytes: source.compression_block_bytes,
    };
    if source.compressed && source.encrypted {
        return Err(NtfsNormalizeError::ConflictingStreamFlags(id));
    }
    if source.compressed != (source.compression_block_bytes != 0) {
        return Err(NtfsNormalizeError::ConflictingStreamFlags(id));
    }
    match &source.storage {
        NtfsStreamStorage::Resident { bytes } => {
            if source.compressed || source.encrypted || source.sparse {
                return Err(NtfsNormalizeError::AmbiguousResidentFlags(id));
            }
            let length =
                u64::try_from(bytes.len()).map_err(|_| NtfsNormalizeError::ArithmeticOverflow)?;
            Ok(ObjectStream {
                id,
                name,
                logical_bytes: length,
                initialized_bytes: length,
                mapped_bytes: length,
                allocated_bytes: 0,
                flags,
                storage: StreamStorage::Resident(bytes.clone()),
            })
        }
        NtfsStreamStorage::NonResident {
            allocated_bytes,
            data_bytes,
            initialized_bytes,
            compressed_bytes,
            mapping_complete,
            extents,
            captured_payload: _,
        } => {
            if !mapping_complete {
                return Err(NtfsNormalizeError::IncompleteStream(id));
            }
            let (mapped_bytes, physical_bytes) =
                normalize_stream_extents(id, source, extents, output_extents)?;
            if *initialized_bytes > *data_bytes || *data_bytes > mapped_bytes {
                return Err(NtfsNormalizeError::InvalidStreamSizes(id));
            }
            if physical_bytes != *allocated_bytes {
                return Err(NtfsNormalizeError::StreamExtentMismatch(id));
            }
            if compressed_bytes.is_some_and(|bytes| bytes > *allocated_bytes) {
                return Err(NtfsNormalizeError::InvalidCompressedSize(id));
            }
            Ok(ObjectStream {
                id,
                name,
                logical_bytes: *data_bytes,
                initialized_bytes: *initialized_bytes,
                mapped_bytes,
                allocated_bytes: *allocated_bytes,
                flags,
                storage: StreamStorage::Extents,
            })
        }
    }
}

fn normalize_stream_extents(
    stream: StreamId,
    source: &NtfsDataStream,
    source_extents: &[NtfsInventoryExtent],
    output: &mut Vec<Extent>,
) -> Result<(u64, u64), NtfsNormalizeError> {
    let mut expected = 0_u64;
    let mut physical = 0_u64;
    for extent in source_extents {
        if extent.stream_id != stream.0 || extent.logical_offset != expected || extent.length == 0 {
            return Err(NtfsNormalizeError::StreamExtentMismatch(stream));
        }
        let placement = match extent.placement {
            super::ntfs_inventory::NtfsExtentPlacement::Physical { byte_offset } => {
                physical = physical
                    .checked_add(extent.length)
                    .ok_or(NtfsNormalizeError::ArithmeticOverflow)?;
                Placement::Physical { byte_offset }
            }
            super::ntfs_inventory::NtfsExtentPlacement::Sparse => {
                if !source.sparse && !source.compressed {
                    return Err(NtfsNormalizeError::AmbiguousSparseExtent(stream));
                }
                Placement::Sparse
            }
        };
        output.push(Extent {
            stream,
            logical_offset: extent.logical_offset,
            length: extent.length,
            placement,
            // These are `$DATA` extents even when the owning object is a directory. Directory
            // index-allocation metadata is deliberately not represented as an object stream.
            kind: ExtentKind::FileData,
        });
        expected = expected
            .checked_add(extent.length)
            .ok_or(NtfsNormalizeError::ArithmeticOverflow)?;
    }
    Ok((expected, physical))
}

fn stream_id(record: u64, attribute_id: u16) -> Result<StreamId, NtfsNormalizeError> {
    record
        .checked_shl(16)
        .and_then(|value| value.checked_add(u64::from(attribute_id)))
        .map(StreamId)
        .ok_or(NtfsNormalizeError::StreamIdOverflow {
            record,
            attribute_id,
        })
}

fn validate_inventory_extents(inventory: &NtfsInventory) -> Result<(), NtfsNormalizeError> {
    let mut declared = inventory
        .objects
        .iter()
        .flat_map(|object| &object.data_streams)
        .flat_map(|stream| match &stream.storage {
            NtfsStreamStorage::Resident { .. } => &[][..],
            NtfsStreamStorage::NonResident { extents, .. } => extents.as_slice(),
        })
        .map(inventory_extent_key)
        .collect::<Vec<_>>();
    let mut global = inventory
        .extents
        .iter()
        .map(inventory_extent_key)
        .collect::<Vec<_>>();
    declared.sort_unstable();
    global.sort_unstable();
    if declared != global {
        return Err(NtfsNormalizeError::InventoryExtentMismatch);
    }
    Ok(())
}

fn validate_graph_extents(
    source: &[NtfsInventoryExtent],
    normalized: &[Extent],
    graph_streams: &BTreeSet<StreamId>,
) -> Result<(), NtfsNormalizeError> {
    let mut source_keys = source
        .iter()
        .filter(|extent| graph_streams.contains(&StreamId(extent.stream_id)))
        .map(inventory_extent_key)
        .collect::<Vec<_>>();
    let mut normalized_keys = normalized.iter().map(extent_key).collect::<Vec<_>>();
    source_keys.sort_unstable();
    normalized_keys.sort_unstable();
    if source_keys != normalized_keys {
        return Err(NtfsNormalizeError::InventoryExtentMismatch);
    }
    Ok(())
}

const fn inventory_extent_key(extent: &NtfsInventoryExtent) -> (u64, u64, u64, u8, u64) {
    let (placement, offset) = match extent.placement {
        super::ntfs_inventory::NtfsExtentPlacement::Physical { byte_offset } => (0, byte_offset),
        super::ntfs_inventory::NtfsExtentPlacement::Sparse => (1, 0),
    };
    (
        extent.stream_id,
        extent.logical_offset,
        extent.length,
        placement,
        offset,
    )
}

const fn extent_key(extent: &Extent) -> (u64, u64, u64, u8, u64) {
    let (placement, offset) = match extent.placement {
        Placement::Physical { byte_offset } => (0, byte_offset),
        Placement::Sparse => (1, 0),
    };
    (
        extent.stream.0,
        extent.logical_offset,
        extent.length,
        placement,
        offset,
    )
}

fn preservation_bytes(inventory: &NtfsInventory) -> Result<u64, NtfsNormalizeError> {
    let label_bytes = match &inventory.volume_label {
        NtfsVolumeLabelEvidence::Exact(units) => u64::try_from(units.len())
            .ok()
            .and_then(|length| length.checked_mul(2))
            .ok_or(NtfsNormalizeError::ArithmeticOverflow)?,
        NtfsVolumeLabelEvidence::Unavailable | NtfsVolumeLabelEvidence::Absent => 0,
    };
    inventory
        .objects
        .iter()
        .try_fold(label_bytes, |total, object| {
            let with_names = object
                .file_names
                .iter()
                .chain(
                    object
                        .directory_entries
                        .iter()
                        .map(|entry| &entry.file_name),
                )
                .try_fold(total, |sum, name| {
                    let units = u64::try_from(name.name.code_units.len())
                        .map_err(|_| NtfsNormalizeError::ArithmeticOverflow)?;
                    sum.checked_add(
                        units
                            .checked_mul(2)
                            .ok_or(NtfsNormalizeError::ArithmeticOverflow)?,
                    )
                    .ok_or(NtfsNormalizeError::ArithmeticOverflow)
                })?;
            object
                .data_streams
                .iter()
                .try_fold(with_names, |sum, stream| {
                    let name_bytes = stream.name.as_ref().map_or(Ok(0), |name| {
                        u64::try_from(name.code_units.len())
                            .ok()
                            .and_then(|units| units.checked_mul(2))
                            .ok_or(NtfsNormalizeError::ArithmeticOverflow)
                    })?;
                    let resident = match &stream.storage {
                        NtfsStreamStorage::Resident { bytes } => u64::try_from(bytes.len())
                            .map_err(|_| NtfsNormalizeError::ArithmeticOverflow)?,
                        NtfsStreamStorage::NonResident {
                            captured_payload, ..
                        } => captured_payload.as_ref().map_or(Ok(0), |bytes| {
                            u64::try_from(bytes.len())
                                .map_err(|_| NtfsNormalizeError::ArithmeticOverflow)
                        })?,
                    };
                    sum.checked_add(name_bytes)
                        .and_then(|value| value.checked_add(resident))
                        .ok_or(NtfsNormalizeError::ArithmeticOverflow)
                })
        })
}

const fn namespace_id(namespace: FileNameNamespace) -> u8 {
    match namespace {
        FileNameNamespace::Posix => 0,
        FileNameNamespace::Win32 => 1,
        FileNameNamespace::Dos => 2,
        FileNameNamespace::Win32AndDos => 3,
    }
}

fn is_dos_short_name_companion(name: &NtfsFileName, names: &[NtfsFileName]) -> bool {
    name.namespace == FileNameNamespace::Dos
        && names.iter().any(|other| {
            other.parent == name.parent
                && matches!(
                    other.namespace,
                    FileNameNamespace::Win32 | FileNameNamespace::Win32AndDos
                )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SemanticFeature;
    use crate::fs::ntfs_inventory::{
        NtfsDirectoryEntry, NtfsExtentPlacement, NtfsName, NtfsReparseIndexEvidence,
        NtfsStandardInformation,
    };

    const LIMITS: NtfsNormalizeLimits = NtfsNormalizeLimits {
        graph: ObjectGraphLimits {
            max_objects: 16,
            max_entries: 32,
            max_streams: 32,
            max_name_code_units: 255,
        },
        max_extents: 32,
        max_directory_entries: 32,
        max_preservation_bytes: 4096,
    };

    const fn reference(record_number: u64, sequence_number: u16) -> NtfsObjectReference {
        NtfsObjectReference {
            record_number,
            sequence_number,
        }
    }

    const fn standard(file_attributes: u32, security_id: u32) -> NtfsStandardInformation {
        NtfsStandardInformation {
            creation_time: 1,
            modification_time: 2,
            mft_change_time: 3,
            access_time: 4,
            file_attributes,
            owner_id: Some(5),
            security_id: Some(security_id),
            quota_charged: Some(6),
            usn: Some(7),
        }
    }

    fn file_name(parent: NtfsObjectReference, name: &str) -> NtfsFileName {
        NtfsFileName {
            parent,
            namespace: FileNameNamespace::Win32,
            name: NtfsName {
                code_units: name.encode_utf16().collect(),
                is_well_formed: true,
            },
            allocated_size: 4096,
            data_size: 3,
            file_attributes: 0x20,
            reparse_tag_or_ea_size: 0,
        }
    }

    fn resident(attribute_id: u16, name: Option<&str>, bytes: &[u8]) -> NtfsDataStream {
        NtfsDataStream {
            attribute_id,
            name: name.map(|value| NtfsName {
                code_units: value.encode_utf16().collect(),
                is_well_formed: true,
            }),
            compressed: false,
            encrypted: false,
            sparse: false,
            compression_block_bytes: 0,
            storage: NtfsStreamStorage::Resident {
                bytes: bytes.to_vec(),
            },
        }
    }

    fn root(entries: Vec<NtfsDirectoryEntry>) -> NtfsObject {
        let root_ref = reference(5, 2);
        NtfsObject {
            reference: root_ref,
            hard_link_count: 1,
            is_directory: true,
            is_metadata: true,
            standard_information: Some(standard(FILE_ATTRIBUTE_DIRECTORY, 1)),
            file_names: vec![file_name(root_ref, ".")],
            data_streams: Vec::new(),
            attribute_census: Vec::new(),
            directory_entries: entries,
            has_reparse_point: false,
            reparse_point: None,
            has_attribute_list: false,
            directory_index_complete: true,
        }
    }

    fn file(names: Vec<NtfsFileName>, streams: Vec<NtfsDataStream>) -> NtfsObject {
        NtfsObject {
            reference: reference(6, 3),
            hard_link_count: u16::try_from(names.len()).unwrap(),
            is_directory: false,
            is_metadata: false,
            standard_information: Some(standard(0x20, 42)),
            file_names: names,
            data_streams: streams,
            attribute_census: Vec::new(),
            directory_entries: Vec::new(),
            has_reparse_point: false,
            reparse_point: None,
            has_attribute_list: false,
            directory_index_complete: true,
        }
    }

    const fn system_metadata(record_number: u64) -> NtfsObject {
        NtfsObject {
            reference: reference(record_number, 1),
            hard_link_count: 0,
            is_directory: false,
            is_metadata: true,
            standard_information: None,
            file_names: Vec::new(),
            data_streams: Vec::new(),
            attribute_census: Vec::new(),
            directory_entries: Vec::new(),
            has_reparse_point: false,
            reparse_point: None,
            has_attribute_list: false,
            directory_index_complete: true,
        }
    }

    fn inventory(mut file: NtfsObject) -> NtfsInventory {
        let entries = file
            .file_names
            .iter()
            .cloned()
            .map(|file_name| NtfsDirectoryEntry {
                target: file.reference,
                file_name,
            })
            .collect();
        let extents = file
            .data_streams
            .iter()
            .flat_map(|stream| match &stream.storage {
                NtfsStreamStorage::NonResident { extents, .. } => extents.clone(),
                NtfsStreamStorage::Resident { .. } => Vec::new(),
            })
            .collect();
        file.directory_entries.clear();
        NtfsInventory {
            volume_serial_number: 0x0123_4567_89ab_cdef,
            volume_label: NtfsVolumeLabelEvidence::Absent,
            reparse_index: NtfsReparseIndexEvidence::Absent,
            objects: vec![root(entries), file],
            extents,
            physical_allocations: Vec::new(),
            scanned_records: 7,
            initialized_records: 7,
            in_use_base_records: 2,
            extension_records: 0,
            bytes_read: 7168,
            incomplete_reasons: Vec::new(),
        }
    }

    fn basic() -> NtfsInventory {
        let parent = reference(5, 2);
        inventory(file(
            vec![file_name(parent, "alpha"), file_name(parent, "beta")],
            vec![resident(1, None, b"abc"), resident(2, Some("fork"), b"x")],
        ))
    }

    #[test]
    fn preserves_hard_links_streams_namespaces_and_ntfs_metadata() {
        let source = basic();
        let normalized = normalize_inventory(&source, 65_536, LIMITS).unwrap();
        assert_eq!(normalized.graph.root(), ObjectId(5));
        assert_eq!(normalized.graph.entries().len(), 2);
        assert_eq!(normalized.graph.objects()[1].link_count, 2);
        assert_eq!(
            normalized.graph.objects()[1].streams[1].name,
            Some("fork".encode_utf16().collect())
        );
        assert_eq!(
            normalized.preservation.objects[1]
                .source
                .standard_information,
            Some(standard(0x20, 42))
        );
        assert_eq!(
            normalized.preservation.objects[1].source.file_names[0].namespace,
            FileNameNamespace::Win32
        );
        assert_eq!(
            normalized.graph.features(),
            &[
                SemanticFeature::AccessControl,
                SemanticFeature::AlternateDataStreams,
                SemanticFeature::HardLinks,
            ]
        );
    }

    fn file_name_with_namespace(
        parent: NtfsObjectReference,
        name: &str,
        namespace: FileNameNamespace,
    ) -> NtfsFileName {
        let mut value = file_name(parent, name);
        value.namespace = namespace;
        value
    }

    #[test]
    fn dos_short_name_companions_are_sidecar_aliases_not_graph_hard_links() {
        let parent = reference(5, 2);
        let source = inventory(file(
            vec![
                file_name(parent, "Long Document.txt"),
                file_name_with_namespace(parent, "LONGDO~1.TXT", FileNameNamespace::Dos),
            ],
            vec![resident(1, None, b"abc")],
        ));
        let normalized = normalize_inventory(&source, 65_536, LIMITS).unwrap();
        assert_eq!(normalized.graph.entries().len(), 1);
        assert_eq!(normalized.graph.objects()[1].link_count, 1);
        assert_eq!(
            normalized.graph.entries()[0].name,
            "Long Document.txt".encode_utf16().collect::<Vec<u16>>()
        );
        assert!(
            !normalized
                .graph
                .features()
                .contains(&SemanticFeature::HardLinks)
        );
        assert_eq!(
            normalized.preservation.objects[1].source.file_names.len(),
            2
        );
        assert_eq!(
            normalized.preservation.objects[1].source.file_names[1].namespace,
            FileNameNamespace::Dos
        );

        let hard_linked = inventory(file(
            vec![
                file_name(parent, "alpha"),
                file_name_with_namespace(parent, "ALPHA~1", FileNameNamespace::Dos),
                file_name(parent, "beta"),
                file_name_with_namespace(parent, "BETA~1", FileNameNamespace::Dos),
            ],
            vec![resident(1, None, b"abc")],
        ));
        let normalized = normalize_inventory(&hard_linked, 65_536, LIMITS).unwrap();
        assert_eq!(normalized.graph.entries().len(), 2);
        assert_eq!(normalized.graph.objects()[1].link_count, 2);
        assert!(
            normalized
                .graph
                .features()
                .contains(&SemanticFeature::HardLinks)
        );
        assert_eq!(
            normalized.preservation.objects[1].source.file_names.len(),
            4
        );

        let dos_only = inventory(file(
            vec![file_name_with_namespace(
                parent,
                "README.TXT",
                FileNameNamespace::Dos,
            )],
            vec![resident(1, None, b"abc")],
        ));
        let normalized = normalize_inventory(&dos_only, 65_536, LIMITS).unwrap();
        assert_eq!(normalized.graph.entries().len(), 1);
        assert_eq!(normalized.graph.objects()[1].link_count, 1);
        assert_eq!(
            normalized.graph.entries()[0].name,
            "README.TXT".encode_utf16().collect::<Vec<u16>>()
        );
    }

    #[test]
    fn accepts_directory_without_standard_information_directory_bit() {
        let mut source = basic();
        source.objects[0].standard_information = Some(standard(0x26, 1));
        let normalized = normalize_inventory(&source, 65_536, LIMITS).unwrap();
        assert_eq!(normalized.graph.objects()[0].kind, ObjectKind::Directory);
        assert_eq!(
            normalized.preservation.objects[0]
                .source
                .standard_information
                .unwrap()
                .file_attributes,
            0x26
        );
    }

    #[test]
    fn accepts_only_matching_optional_root_self_index_entry() {
        let mut source = basic();
        let root = source.objects[0].reference;
        let file_name = source.objects[0].file_names[0].clone();
        source.objects[0]
            .directory_entries
            .push(NtfsDirectoryEntry {
                target: root,
                file_name,
            });
        normalize_inventory(&source, 65_536, LIMITS).unwrap();

        source.objects[0]
            .directory_entries
            .last_mut()
            .unwrap()
            .file_name
            .name
            .code_units = "mismatch".encode_utf16().collect();
        assert_eq!(
            normalize_inventory(&source, 65_536, LIMITS),
            Err(NtfsNormalizeError::DirectoryEvidenceMismatch)
        );
    }

    #[test]
    fn accepts_stale_file_name_cache_when_namespace_identity_matches() {
        let mut source = basic();
        let entry = &mut source.objects[0].directory_entries[0].file_name;
        entry.allocated_size = 8192;
        entry.data_size = 4097;
        entry.file_attributes = 0x400;
        entry.reparse_tag_or_ea_size = 0xa000_000c;

        let normalized = normalize_inventory(&source, 65_536, LIMITS).unwrap();
        let preserved_root = &normalized.preservation.objects[0].source;
        let preserved_target = &normalized.preservation.objects[1].source;
        assert_eq!(
            preserved_root.directory_entries[0].file_name.data_size,
            4097
        );
        assert_eq!(preserved_target.file_names[0].data_size, 3);
        assert_eq!(normalized.graph.entries().len(), 2);
    }

    #[test]
    fn rejects_every_directory_namespace_identity_difference() {
        let mut target_record = basic();
        target_record.objects[0].directory_entries[0]
            .target
            .record_number = 7;
        assert!(normalize_inventory(&target_record, 65_536, LIMITS).is_err());

        let mut target_sequence = basic();
        target_sequence.objects[0].directory_entries[0]
            .target
            .sequence_number = 99;
        assert!(matches!(
            normalize_inventory(&target_sequence, 65_536, LIMITS),
            Err(NtfsNormalizeError::StaleReference { record: 6, .. })
        ));

        let mut parent_record = basic();
        parent_record.objects[0].directory_entries[0]
            .file_name
            .parent
            .record_number = 6;
        assert!(matches!(
            normalize_inventory(&parent_record, 65_536, LIMITS),
            Err(NtfsNormalizeError::DirectoryParentMismatch { .. })
        ));

        let mut parent_sequence = basic();
        parent_sequence.objects[0].directory_entries[0]
            .file_name
            .parent
            .sequence_number = 99;
        assert!(matches!(
            normalize_inventory(&parent_sequence, 65_536, LIMITS),
            Err(NtfsNormalizeError::DirectoryParentMismatch { .. })
        ));

        let mut namespace = basic();
        namespace.objects[0].directory_entries[0]
            .file_name
            .namespace = FileNameNamespace::Posix;
        assert_eq!(
            normalize_inventory(&namespace, 65_536, LIMITS),
            Err(NtfsNormalizeError::DirectoryEvidenceMismatch)
        );

        let mut name = basic();
        name.objects[0].directory_entries[0]
            .file_name
            .name
            .code_units = "different".encode_utf16().collect();
        assert_eq!(
            normalize_inventory(&name, 65_536, LIMITS),
            Err(NtfsNormalizeError::DirectoryEvidenceMismatch)
        );

        let mut well_formedness = basic();
        well_formedness.objects[0].directory_entries[0]
            .file_name
            .name
            .is_well_formed = false;
        assert_eq!(
            normalize_inventory(&well_formedness, 65_536, LIMITS),
            Err(NtfsNormalizeError::DirectoryEvidenceMismatch)
        );
    }

    #[test]
    fn preserves_exact_volume_identity_and_absence_without_defaulting() {
        let mut source = basic();
        source.volume_serial_number = 0xfedc_ba98_7654_3210;
        source.volume_label = NtfsVolumeLabelEvidence::Exact(vec![0x53, 0x54, 0x41, 0x52]);
        let normalized = normalize_inventory(&source, 65_536, LIMITS).unwrap();
        assert_eq!(
            normalized.preservation.volume_serial_number,
            0xfedc_ba98_7654_3210
        );
        assert_eq!(
            normalized.preservation.volume_label,
            Some(vec![0x53, 0x54, 0x41, 0x52])
        );

        source.volume_label = NtfsVolumeLabelEvidence::Unavailable;
        assert_eq!(
            normalize_inventory(&source, 65_536, LIMITS),
            Err(NtfsNormalizeError::UnavailableVolumeLabelEvidence)
        );
    }

    #[test]
    fn preserves_sparse_and_physical_extent_accounting() {
        let stream = NtfsDataStream {
            attribute_id: 9,
            name: None,
            compressed: false,
            encrypted: false,
            sparse: true,
            compression_block_bytes: 0,
            storage: NtfsStreamStorage::NonResident {
                allocated_bytes: 4096,
                data_bytes: 7000,
                initialized_bytes: 6000,
                compressed_bytes: Some(4096),
                mapping_complete: true,
                extents: vec![
                    NtfsInventoryExtent {
                        stream_id: (6 << 16) + 9,
                        logical_offset: 0,
                        length: 4096,
                        placement: NtfsExtentPlacement::Physical { byte_offset: 8192 },
                    },
                    NtfsInventoryExtent {
                        stream_id: (6 << 16) + 9,
                        logical_offset: 4096,
                        length: 4096,
                        placement: NtfsExtentPlacement::Sparse,
                    },
                ],
                captured_payload: None,
            },
        };
        let source = inventory(file(
            vec![file_name(reference(5, 2), "sparse")],
            vec![stream],
        ));
        let normalized = normalize_inventory(&source, 65_536, LIMITS).unwrap();
        let stream = &normalized.graph.objects()[1].streams[0];
        assert_eq!(
            (
                stream.logical_bytes,
                stream.initialized_bytes,
                stream.mapped_bytes,
                stream.allocated_bytes
            ),
            (7000, 6000, 8192, 4096)
        );
        assert_eq!(normalized.graph.extents().sparse_bytes(), 4096);
        assert_eq!(normalized.preservation.source_extents, source.extents);
    }

    #[test]
    fn preserves_ntfs_compression_unit_on_the_graph() {
        let stream = NtfsDataStream {
            attribute_id: 9,
            name: None,
            compressed: true,
            encrypted: false,
            sparse: false,
            compression_block_bytes: 8192,
            storage: NtfsStreamStorage::NonResident {
                allocated_bytes: 4096,
                data_bytes: 6,
                initialized_bytes: 6,
                compressed_bytes: Some(4096),
                mapping_complete: true,
                extents: vec![
                    NtfsInventoryExtent {
                        stream_id: (6 << 16) + 9,
                        logical_offset: 0,
                        length: 4096,
                        placement: NtfsExtentPlacement::Physical { byte_offset: 8192 },
                    },
                    NtfsInventoryExtent {
                        stream_id: (6 << 16) + 9,
                        logical_offset: 4096,
                        length: 4096,
                        placement: NtfsExtentPlacement::Sparse,
                    },
                ],
                captured_payload: None,
            },
        };
        let source = inventory(file(
            vec![file_name(reference(5, 2), "packed")],
            vec![stream],
        ));
        let normalized = normalize_inventory(&source, 65_536, LIMITS).unwrap();
        let flags = normalized.graph.objects()[1].streams[0].flags;
        assert!(flags.compressed);
        assert_eq!(flags.compression_block_bytes, 8192);
        assert!(!flags.sparse);
    }

    #[test]
    fn rejects_incomplete_dangling_and_stale_evidence() {
        let mut source = basic();
        source
            .incomplete_reasons
            .push(NtfsInventoryIncompleteReason::RecordLimit);
        assert!(matches!(
            normalize_inventory(&source, 65_536, LIMITS),
            Err(NtfsNormalizeError::IncompleteInventory(_))
        ));

        let mut source = basic();
        source.objects[1].file_names[0].parent = reference(99, 1);
        assert!(matches!(
            normalize_inventory(&source, 65_536, LIMITS),
            Err(NtfsNormalizeError::MissingParent { parent: 99, .. })
        ));

        let mut source = basic();
        source.objects[1].file_names[0].parent.sequence_number = 99;
        assert!(matches!(
            normalize_inventory(&source, 65_536, LIMITS),
            Err(NtfsNormalizeError::StaleReference { record: 5, .. })
        ));
    }

    #[test]
    fn rejects_directory_disagreement_and_incomplete_indexes() {
        let mut source = basic();
        source.objects[0].directory_entries.pop();
        assert_eq!(
            normalize_inventory(&source, 65_536, LIMITS).unwrap_err(),
            NtfsNormalizeError::DirectoryEvidenceMismatch
        );

        let mut source = basic();
        source.objects[0].directory_index_complete = false;
        assert_eq!(
            normalize_inventory(&source, 65_536, LIMITS).unwrap_err(),
            NtfsNormalizeError::IncompleteDirectoryIndex(5)
        );
    }

    #[test]
    fn accepts_resolved_attribute_list_and_preserves_source_layout_evidence() {
        let mut source = basic();
        source.objects[1].has_attribute_list = true;
        assert!(source.is_complete());

        let normalized = normalize_inventory(&source, 65_536, LIMITS).unwrap();
        let preserved = normalized
            .preservation
            .objects
            .iter()
            .find(|object| object.object == ObjectId(6))
            .unwrap();
        assert!(preserved.source.has_attribute_list);
        assert_eq!(
            preserved.source.data_streams,
            source.objects[1].data_streams
        );
    }

    #[test]
    fn excludes_system_metadata_from_graph_but_preserves_it_exactly() {
        let mut source = basic();
        source.objects[1].reference = reference(10, 3);
        for entry in &mut source.objects[0].directory_entries {
            entry.target = reference(10, 3);
        }
        let mut extend_name = file_name(reference(5, 2), "$Extend");
        extend_name.file_attributes = 0x1000_0006;
        source.objects[0]
            .directory_entries
            .push(NtfsDirectoryEntry {
                target: reference(NTFS_EXTEND_RECORD, 1),
                file_name: extend_name.clone(),
            });
        source.objects.splice(
            0..0,
            [
                system_metadata(0),
                system_metadata(1),
                system_metadata(3),
                system_metadata(6),
            ],
        );
        source.objects.push(NtfsObject {
            reference: reference(NTFS_EXTEND_RECORD, 1),
            hard_link_count: 1,
            is_directory: true,
            is_metadata: false,
            standard_information: Some(standard(0x0006, 256)),
            file_names: vec![extend_name],
            data_streams: Vec::new(),
            attribute_census: Vec::new(),
            directory_entries: Vec::new(),
            has_reparse_point: false,
            reparse_point: None,
            has_attribute_list: false,
            directory_index_complete: true,
        });
        source.scanned_records = 12;
        source.initialized_records = 12;
        source.in_use_base_records = 7;

        let normalized = normalize_inventory(&source, 65_536, LIMITS).unwrap();
        assert_eq!(normalized.graph.objects().len(), 2);
        assert_eq!(normalized.graph.objects()[0].id, ObjectId(5));
        assert_eq!(normalized.graph.objects()[1].id, ObjectId(10));
        assert_eq!(normalized.preservation.objects.len(), 7);
        for record in [0, 1, 3, 6] {
            let preserved = normalized
                .preservation
                .objects
                .iter()
                .find(|object| object.source.reference.record_number == record)
                .unwrap();
            assert!(preserved.source.is_metadata);
            assert!(preserved.source.standard_information.is_none());
            assert!(preserved.source.file_names.is_empty());
        }
        let extend = normalized
            .preservation
            .objects
            .iter()
            .find(|object| object.source.reference.record_number == NTFS_EXTEND_RECORD)
            .unwrap();
        assert!(extend.source.is_directory);
        assert!(!extend.source.is_metadata);
        assert_eq!(
            extend
                .source
                .standard_information
                .as_ref()
                .unwrap()
                .file_attributes,
            0x0006
        );
        assert_eq!(extend.source.file_names[0].file_attributes, 0x1000_0006);
    }

    #[test]
    fn rejects_stream_extent_and_global_extent_inconsistency() {
        let mut source = basic();
        source.objects[1].data_streams.push(NtfsDataStream {
            attribute_id: 7,
            name: Some(NtfsName {
                code_units: vec![0xd800],
                is_well_formed: false,
            }),
            compressed: false,
            encrypted: false,
            sparse: false,
            compression_block_bytes: 0,
            storage: NtfsStreamStorage::NonResident {
                allocated_bytes: 4096,
                data_bytes: 1,
                initialized_bytes: 1,
                compressed_bytes: None,
                mapping_complete: false,
                extents: vec![NtfsInventoryExtent {
                    stream_id: (6 << 16) + 7,
                    logical_offset: 0,
                    length: 4096,
                    placement: NtfsExtentPlacement::Physical { byte_offset: 4096 },
                }],
                captured_payload: None,
            },
        });
        assert!(matches!(
            normalize_inventory(&source, 65_536, LIMITS),
            Err(NtfsNormalizeError::IncompleteStream(_))
        ));

        let mut source = basic();
        source.extents.push(NtfsInventoryExtent {
            stream_id: 999,
            logical_offset: 0,
            length: 1,
            placement: NtfsExtentPlacement::Physical { byte_offset: 1 },
        });
        assert_eq!(
            normalize_inventory(&source, 65_536, LIMITS).unwrap_err(),
            NtfsNormalizeError::InventoryExtentMismatch
        );
    }

    #[test]
    fn enforces_preservation_and_directory_caps() {
        let source = basic();
        let small = NtfsNormalizeLimits {
            max_preservation_bytes: 1,
            ..LIMITS
        };
        assert!(matches!(
            normalize_inventory(&source, 65_536, small),
            Err(NtfsNormalizeError::PreservationLimitExceeded { .. })
        ));
        let small = NtfsNormalizeLimits {
            max_directory_entries: 1,
            ..LIMITS
        };
        assert_eq!(
            normalize_inventory(&source, 65_536, small).unwrap_err(),
            NtfsNormalizeError::DirectoryEntryLimitExceeded {
                actual: 2,
                maximum: 1
            }
        );
    }
}
