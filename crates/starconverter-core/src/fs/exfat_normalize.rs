//! Lossless normalization of a complete exFAT inventory into the filesystem-neutral graph.
//!
//! The neutral graph deliberately contains only semantics shared by supported filesystems. Exact
//! exFAT fields which have no neutral representation remain paired with their object in an
//! [`ExfatPreservationSidecar`]. No image data is read or written by this module.

#![allow(clippy::module_name_repetitions)]

use std::collections::BTreeMap;
use std::fmt;

use super::exfat_directory::VolumeLabelEntry;
use super::exfat_discovery::ExfatRootDiscovery;
use super::exfat_inventory::{
    ExfatInventory, ExfatObjectFlags, ExfatObjectKind, ExfatPreservationEvidence, ExfatTimestamps,
};
use crate::extent::{Extent, ExtentGraph, ExtentGraphError, ExtentKind, Placement, StreamId};
use crate::object::{
    NamespaceEntry, ObjectGraph, ObjectGraphError, ObjectGraphLimits, ObjectId, ObjectKind,
    ObjectRecord, ObjectSemantics, ObjectStream, StreamFlags, StreamStorage,
};

/// Caller-selected bounds for normalization and graph construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExfatNormalizeLimits {
    pub graph: ObjectGraphLimits,
    pub max_extents: usize,
}

/// Exact exFAT-only fields associated with one neutral object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExfatObjectPreservation {
    pub object: ObjectId,
    /// Parser identity used by the source inventory and its physical extents.
    pub source_stream: StreamId,
    pub path: Vec<Vec<u16>>,
    pub file_attributes: u16,
    pub timestamps: Option<ExfatTimestamps>,
    pub clusters: Vec<u32>,
    pub flags: ExfatObjectFlags,
}

/// exFAT evidence which cannot be represented directly by [`ObjectGraph`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExfatPreservationSidecar {
    pub root: ExfatRootDiscovery,
    pub volume_serial_number: u32,
    /// Exact logical root label, present only when all unused on-disk label slots were zero.
    pub volume_label: Option<VolumeLabelEntry>,
    pub objects: Vec<ExfatObjectPreservation>,
    /// Validated allocation belonging to filesystem structures rather than live objects.
    pub filesystem_extents: Vec<Extent>,
    pub directory_evidence: ExfatPreservationEvidence,
    pub allocated_bad_clusters: u64,
}

/// A neutral object graph inseparably paired with exact exFAT preservation evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedExfat {
    pub graph: ObjectGraph,
    pub preservation: ExfatPreservationSidecar,
}

type NormalizedRecords = (
    Vec<ObjectRecord>,
    Vec<NamespaceEntry>,
    Vec<ExfatObjectPreservation>,
);

/// Failure to prove that a supplied inventory is complete and internally consistent.
#[derive(Debug)]
pub enum ExfatNormalizeError {
    InvalidLimits(&'static str),
    EmptyInventory,
    ObjectIdOverflow,
    MissingIdentity(StreamId),
    DuplicateSourceStream(StreamId),
    RootCount {
        actual: usize,
    },
    InvalidRoot,
    NonRootMarkedAsRoot(StreamId),
    NonRootMissingParent(StreamId),
    MissingParent {
        stream: StreamId,
        parent: StreamId,
    },
    ParentNotDirectory {
        stream: StreamId,
        parent: StreamId,
    },
    SelfParent(StreamId),
    MissingName(StreamId),
    MissingTimestamps(StreamId),
    InvalidPath(StreamId),
    AttributeKindMismatch(StreamId),
    VolumeLabelEvidenceMismatch,
    UnexpectedSparseExtent(StreamId),
    ExtentKindMismatch {
        stream: StreamId,
        actual: ExtentKind,
    },
    Extents(ExtentGraphError),
    Graph(ObjectGraphError),
}

impl fmt::Display for ExfatNormalizeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits(field) => {
                write!(formatter, "exFAT normalization limit {field} is zero")
            }
            Self::EmptyInventory => formatter.write_str("exFAT inventory contains no objects"),
            Self::ObjectIdOverflow => formatter.write_str("exFAT object identity space overflowed"),
            Self::MissingIdentity(stream) => write!(
                formatter,
                "exFAT source stream {} has no normalized identity",
                stream.0
            ),
            Self::DuplicateSourceStream(stream) => {
                write!(
                    formatter,
                    "exFAT source stream {} identifies multiple objects",
                    stream.0
                )
            }
            Self::RootCount { actual } => {
                write!(formatter, "exFAT inventory contains {actual} root objects")
            }
            Self::InvalidRoot => formatter
                .write_str("exFAT root name, path, parent, attributes, or timestamps are invalid"),
            Self::NonRootMarkedAsRoot(stream) => {
                write!(
                    formatter,
                    "non-root stream {} is marked as an exFAT root",
                    stream.0
                )
            }
            Self::NonRootMissingParent(stream) => {
                write!(
                    formatter,
                    "non-root exFAT stream {} has no parent",
                    stream.0
                )
            }
            Self::MissingParent { stream, parent } => write!(
                formatter,
                "exFAT stream {} references missing parent stream {}",
                stream.0, parent.0
            ),
            Self::ParentNotDirectory { stream, parent } => write!(
                formatter,
                "exFAT stream {} parent stream {} is not a directory",
                stream.0, parent.0
            ),
            Self::SelfParent(stream) => {
                write!(formatter, "exFAT stream {} is its own parent", stream.0)
            }
            Self::MissingName(stream) => {
                write!(
                    formatter,
                    "exFAT stream {} has an empty non-root name",
                    stream.0
                )
            }
            Self::MissingTimestamps(stream) => {
                write!(
                    formatter,
                    "exFAT stream {} has no file-entry timestamps",
                    stream.0
                )
            }
            Self::InvalidPath(stream) => {
                write!(
                    formatter,
                    "exFAT stream {} path does not match its parent and name",
                    stream.0
                )
            }
            Self::AttributeKindMismatch(stream) => write!(
                formatter,
                "exFAT stream {} directory attribute disagrees with its object kind",
                stream.0
            ),
            Self::VolumeLabelEvidenceMismatch => formatter
                .write_str("exFAT volume-label count, exact value, and padding evidence disagree"),
            Self::UnexpectedSparseExtent(stream) => {
                write!(
                    formatter,
                    "exFAT stream {} contains a sparse extent",
                    stream.0
                )
            }
            Self::ExtentKindMismatch { stream, actual } => write!(
                formatter,
                "exFAT stream {} has preservation-inconsistent {actual:?} extents",
                stream.0
            ),
            Self::Extents(error) => {
                write!(formatter, "normalized exFAT extents are invalid: {error}")
            }
            Self::Graph(error) => write!(
                formatter,
                "normalized exFAT object graph is invalid: {error}"
            ),
        }
    }
}

impl std::error::Error for ExfatNormalizeError {}

/// Converts already validated exFAT evidence without reading or modifying an image.
///
/// Source stream identities are retained for extent addressing. Neutral object identities are
/// assigned densely in inventory order, so the two identity domains cannot alias accidentally.
/// Every non-root exFAT object produces exactly one namespace link.
///
/// # Errors
///
/// Returns [`ExfatNormalizeError`] when source hierarchy, paths, attributes, timestamp presence,
/// extent roles, accounting, or caller bounds are inconsistent.
pub fn normalize_inventory(
    inventory: &ExfatInventory,
    limits: ExfatNormalizeLimits,
) -> Result<NormalizedExfat, ExfatNormalizeError> {
    if limits.max_extents == 0 {
        return Err(ExfatNormalizeError::InvalidLimits("max_extents"));
    }
    if inventory.objects.is_empty() {
        return Err(ExfatNormalizeError::EmptyInventory);
    }
    validate_volume_identity(inventory)?;

    let mut source_to_object = BTreeMap::new();
    for (index, source) in inventory.objects.iter().enumerate() {
        let numeric = u64::try_from(index)
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or(ExfatNormalizeError::ObjectIdOverflow)?;
        if source_to_object
            .insert(source.stream, ObjectId(numeric))
            .is_some()
        {
            return Err(ExfatNormalizeError::DuplicateSourceStream(source.stream));
        }
    }

    let roots = inventory
        .objects
        .iter()
        .filter(|object| object.kind == ExfatObjectKind::RootDirectory)
        .collect::<Vec<_>>();
    if roots.len() != 1 {
        return Err(ExfatNormalizeError::RootCount {
            actual: roots.len(),
        });
    }
    let source_root = roots[0];
    if source_root.parent.is_some()
        || !source_root.name.is_empty()
        || !source_root.path.is_empty()
        || source_root.timestamps.is_some()
        || source_root.file_attributes & 0x10 == 0
    {
        return Err(ExfatNormalizeError::InvalidRoot);
    }
    let root = source_to_object
        .get(&source_root.stream)
        .copied()
        .ok_or(ExfatNormalizeError::MissingIdentity(source_root.stream))?;

    validate_hierarchy(inventory, &source_to_object, source_root.stream)?;

    let (extents, filesystem_extents) = partition_extents(inventory, &source_to_object, limits)?;
    let (objects, entries, preserved) = normalize_records(inventory, &source_to_object, root)?;
    let graph = ObjectGraph::build(root, objects, entries, extents, limits.graph)
        .map_err(ExfatNormalizeError::Graph)?;
    Ok(NormalizedExfat {
        graph,
        preservation: ExfatPreservationSidecar {
            root: inventory.root.clone(),
            volume_serial_number: inventory.volume_serial_number,
            volume_label: inventory.volume_label,
            objects: preserved,
            filesystem_extents,
            directory_evidence: inventory.preservation,
            allocated_bad_clusters: inventory.allocated_bad_clusters,
        },
    })
}

const fn validate_volume_identity(inventory: &ExfatInventory) -> Result<(), ExfatNormalizeError> {
    let label_count = inventory.root.directory.volume_labels;
    let nonzero_padding = inventory.preservation.nonzero_volume_label_padding;
    let consistent = match (label_count, inventory.volume_label) {
        (0, None) => !nonzero_padding,
        (1, Some(label)) => label.padding_zeroed && !nonzero_padding,
        (1, None) => nonzero_padding,
        _ => false,
    };
    if consistent {
        Ok(())
    } else {
        Err(ExfatNormalizeError::VolumeLabelEvidenceMismatch)
    }
}

fn partition_extents(
    inventory: &ExfatInventory,
    source_to_object: &BTreeMap<StreamId, ObjectId>,
    limits: ExfatNormalizeLimits,
) -> Result<(ExtentGraph, Vec<Extent>), ExfatNormalizeError> {
    let source_kinds = inventory
        .objects
        .iter()
        .map(|source| (source.stream, source.kind))
        .collect::<BTreeMap<_, _>>();
    let mut object_extents = Vec::new();
    let mut filesystem_extents = Vec::new();
    for extent in inventory.extents.extents() {
        if !source_to_object.contains_key(&extent.stream) {
            filesystem_extents.push(*extent);
            continue;
        }
        let source_kind = source_kinds
            .get(&extent.stream)
            .copied()
            .ok_or(ExfatNormalizeError::MissingIdentity(extent.stream))?;
        if matches!(extent.placement, Placement::Sparse) {
            return Err(ExfatNormalizeError::UnexpectedSparseExtent(extent.stream));
        }
        let expected_kind = match source_kind {
            ExfatObjectKind::RootDirectory | ExfatObjectKind::Directory => {
                ExtentKind::DirectoryData
            }
            ExfatObjectKind::File => ExtentKind::FileData,
        };
        if extent.kind != expected_kind {
            return Err(ExfatNormalizeError::ExtentKindMismatch {
                stream: extent.stream,
                actual: extent.kind,
            });
        }
        match source_kind {
            ExfatObjectKind::RootDirectory | ExfatObjectKind::Directory => {
                // Directory bytes are source-filesystem metadata, not cross-format object data.
                // Preserve their exact ranges as staging exclusions while the namespace is rebuilt
                // from validated entries in the neutral graph.
                filesystem_extents.push(*extent);
            }
            ExfatObjectKind::File => object_extents.push(*extent),
        }
    }
    let graph = ExtentGraph::build(
        object_extents,
        inventory.extents.volume_bytes(),
        limits.max_extents,
    )
    .map_err(ExfatNormalizeError::Extents)?;
    Ok((graph, filesystem_extents))
}

fn normalize_records(
    inventory: &ExfatInventory,
    source_to_object: &BTreeMap<StreamId, ObjectId>,
    root: ObjectId,
) -> Result<NormalizedRecords, ExfatNormalizeError> {
    let mut objects = Vec::with_capacity(inventory.objects.len());
    let mut entries = Vec::with_capacity(inventory.objects.len().saturating_sub(1));
    let mut preserved = Vec::with_capacity(inventory.objects.len());
    for source in &inventory.objects {
        let object = source_to_object
            .get(&source.stream)
            .copied()
            .ok_or(ExfatNormalizeError::MissingIdentity(source.stream))?;
        let kind = match source.kind {
            ExfatObjectKind::RootDirectory | ExfatObjectKind::Directory => ObjectKind::Directory,
            ExfatObjectKind::File => ObjectKind::File,
        };
        let streams = match source.kind {
            ExfatObjectKind::RootDirectory | ExfatObjectKind::Directory => Vec::new(),
            ExfatObjectKind::File => vec![ObjectStream {
                id: source.stream,
                name: None,
                logical_bytes: source.data_length,
                initialized_bytes: source.valid_data_length,
                mapped_bytes: source.allocation_bytes,
                allocated_bytes: source.allocation_bytes,
                flags: StreamFlags::default(),
                storage: StreamStorage::Extents,
            }],
        };
        objects.push(ObjectRecord {
            id: object,
            kind,
            link_count: u32::from(object != root),
            semantics: ObjectSemantics::default(),
            streams,
        });
        if let Some(parent_stream) = source.parent {
            let parent = source_to_object.get(&parent_stream).copied().ok_or(
                ExfatNormalizeError::MissingParent {
                    stream: source.stream,
                    parent: parent_stream,
                },
            )?;
            entries.push(NamespaceEntry {
                parent,
                target: object,
                name: source.name.clone(),
            });
        }
        preserved.push(ExfatObjectPreservation {
            object,
            source_stream: source.stream,
            path: source.path.clone(),
            file_attributes: source.file_attributes,
            timestamps: source.timestamps,
            clusters: source.clusters.clone(),
            flags: source.flags,
        });
    }
    Ok((objects, entries, preserved))
}

fn validate_hierarchy(
    inventory: &ExfatInventory,
    source_to_object: &BTreeMap<StreamId, ObjectId>,
    root_stream: StreamId,
) -> Result<(), ExfatNormalizeError> {
    for source in &inventory.objects {
        if source.stream == root_stream {
            continue;
        }
        if source.kind == ExfatObjectKind::RootDirectory {
            return Err(ExfatNormalizeError::NonRootMarkedAsRoot(source.stream));
        }
        let parent = source
            .parent
            .ok_or(ExfatNormalizeError::NonRootMissingParent(source.stream))?;
        if parent == source.stream {
            return Err(ExfatNormalizeError::SelfParent(source.stream));
        }
        if !source_to_object.contains_key(&parent) {
            return Err(ExfatNormalizeError::MissingParent {
                stream: source.stream,
                parent,
            });
        }
        let parent_record = inventory
            .objects
            .iter()
            .find(|candidate| candidate.stream == parent)
            .ok_or(ExfatNormalizeError::MissingParent {
                stream: source.stream,
                parent,
            })?;
        if parent_record.kind == ExfatObjectKind::File {
            return Err(ExfatNormalizeError::ParentNotDirectory {
                stream: source.stream,
                parent,
            });
        }
        if source.name.is_empty() {
            return Err(ExfatNormalizeError::MissingName(source.stream));
        }
        if source.timestamps.is_none() {
            return Err(ExfatNormalizeError::MissingTimestamps(source.stream));
        }
        let is_directory = source.kind == ExfatObjectKind::Directory;
        if (source.file_attributes & 0x10 != 0) != is_directory {
            return Err(ExfatNormalizeError::AttributeKindMismatch(source.stream));
        }
        let path_matches = source.path.len() == parent_record.path.len().saturating_add(1)
            && source.path.starts_with(&parent_record.path)
            && source.path.last() == Some(&source.name);
        if !path_matches {
            return Err(ExfatNormalizeError::InvalidPath(source.stream));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extent::Placement;
    use crate::fs::exfat_allocation::AllocationSummary;
    use crate::fs::exfat_directory::{AllocationBitmapEntry, DirectorySummary, UpcaseTableEntry};
    use crate::fs::exfat_upcase::{UpcaseLimits, UpcaseTable, table_checksum};

    const LIMITS: ExfatNormalizeLimits = ExfatNormalizeLimits {
        graph: ObjectGraphLimits {
            max_objects: 16,
            max_entries: 16,
            max_streams: 16,
            max_name_code_units: 255,
        },
        max_extents: 32,
    };

    const fn timestamps() -> ExfatTimestamps {
        ExfatTimestamps {
            create: 1,
            modified: 2,
            accessed: 3,
            create_centiseconds: 4,
            modified_centiseconds: 5,
            create_utc_offset: 0x80,
            modified_utc_offset: 0x84,
            accessed_utc_offset: 0x7c,
        }
    }

    const fn flags() -> ExfatObjectFlags {
        ExfatObjectFlags {
            no_fat_chain: true,
            name_padding_zeroed: false,
            benign_secondary_entries: 2,
        }
    }

    fn upcase() -> UpcaseTable {
        let mut words = vec![0xffff, 97];
        words.extend(u16::from(b'A')..=u16::from(b'Z'));
        words.extend([0xffff, 65_413]);
        let encoded = words
            .into_iter()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        UpcaseTable::parse(
            &encoded,
            table_checksum(&encoded),
            UpcaseLimits::COMPLETE_TABLE,
        )
        .unwrap()
    }

    fn discovery() -> ExfatRootDiscovery {
        ExfatRootDiscovery {
            directory: DirectorySummary {
                entries_examined: 0,
                records: 0,
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
                first_cluster: 3,
                data_length: 1,
            },
            upcase_table: UpcaseTableEntry {
                table_checksum: 0,
                first_cluster: 4,
                data_length: 1,
            },
            upcase_mappings: upcase(),
            allocation: AllocationSummary {
                allocated_clusters: 4,
                free_clusters: 4,
                required_bitmap_bytes: 1,
            },
            free_bytes: 2048,
            root_clusters: vec![2],
            bitmap_clusters: vec![3],
            upcase_clusters: vec![4],
        }
    }

    fn root() -> super::super::exfat_inventory::ExfatObjectRecord {
        super::super::exfat_inventory::ExfatObjectRecord {
            stream: StreamId(10),
            parent: None,
            kind: ExfatObjectKind::RootDirectory,
            name: Vec::new(),
            path: Vec::new(),
            file_attributes: 0x10,
            timestamps: None,
            valid_data_length: 512,
            data_length: 512,
            allocation_bytes: 512,
            clusters: vec![2],
            flags: flags(),
        }
    }

    fn child(
        stream: u64,
        parent: u64,
        name: &str,
        kind: ExfatObjectKind,
        logical: u64,
        allocation: u64,
    ) -> super::super::exfat_inventory::ExfatObjectRecord {
        let name = name.encode_utf16().collect::<Vec<_>>();
        super::super::exfat_inventory::ExfatObjectRecord {
            stream: StreamId(stream),
            parent: Some(StreamId(parent)),
            kind,
            name: name.clone(),
            path: vec![name],
            file_attributes: if kind == ExfatObjectKind::Directory {
                0x11
            } else {
                0x21
            },
            timestamps: Some(timestamps()),
            valid_data_length: logical,
            data_length: logical,
            allocation_bytes: allocation,
            clusters: if allocation == 0 { Vec::new() } else { vec![5] },
            flags: flags(),
        }
    }

    const fn extent(
        stream: u64,
        logical: u64,
        physical: u64,
        length: u64,
        kind: ExtentKind,
    ) -> Extent {
        Extent {
            stream: StreamId(stream),
            logical_offset: logical,
            length,
            placement: Placement::Physical {
                byte_offset: physical,
            },
            kind,
        }
    }

    fn inventory(
        objects: Vec<super::super::exfat_inventory::ExfatObjectRecord>,
        extents: Vec<Extent>,
    ) -> ExfatInventory {
        ExfatInventory {
            root: discovery(),
            volume_serial_number: 0x1234_abcd,
            volume_label: None,
            objects,
            extents: ExtentGraph::build(extents, 8192, 32).unwrap(),
            preservation: ExfatPreservationEvidence {
                unused_directory_entries: 1,
                benign_primary_sets: 2,
                benign_secondary_entries: 3,
                nonzero_name_padding_sets: 4,
                nonzero_volume_label_padding: false,
            },
            allocated_bad_clusters: 1,
        }
    }

    #[test]
    fn preserves_empty_file_without_inventing_resident_data() {
        let empty = child(20, 10, "empty", ExfatObjectKind::File, 0, 0);
        let source = inventory(
            vec![root(), empty],
            vec![extent(10, 0, 1024, 512, ExtentKind::DirectoryData)],
        );
        let normalized = normalize_inventory(&source, LIMITS).unwrap();
        let stream = &normalized.graph.objects()[1].streams[0];
        assert_eq!(stream.logical_bytes, 0);
        assert_eq!(stream.mapped_bytes, 0);
        assert!(matches!(stream.storage, StreamStorage::Extents));
        assert_eq!(
            normalized.graph.entries()[0].name,
            "empty".encode_utf16().collect::<Vec<_>>()
        );
    }

    #[test]
    fn preserves_cluster_slack_and_exact_exfat_fields() {
        let file = child(20, 10, "slack.bin", ExfatObjectKind::File, 3, 512);
        let source = inventory(
            vec![root(), file],
            vec![
                extent(10, 0, 1024, 512, ExtentKind::DirectoryData),
                extent(20, 0, 2048, 512, ExtentKind::FileData),
                extent(999, 0, 4096, 512, ExtentKind::FileSystemMetadata),
            ],
        );
        let normalized = normalize_inventory(&source, LIMITS).unwrap();
        let stream = &normalized.graph.objects()[1].streams[0];
        assert_eq!((stream.logical_bytes, stream.mapped_bytes), (3, 512));
        let sidecar = &normalized.preservation.objects[1];
        assert_eq!(sidecar.timestamps, Some(timestamps()));
        assert_eq!(sidecar.file_attributes, 0x21);
        assert_eq!(sidecar.flags, flags());
        assert_eq!(normalized.preservation.volume_serial_number, 0x1234_abcd);
        assert!(normalized.preservation.volume_label.is_none());
        assert_eq!(normalized.preservation.filesystem_extents.len(), 2);
        assert!(normalized.graph.objects()[0].streams.is_empty());
        assert_eq!(normalized.preservation.allocated_bad_clusters, 1);
    }

    #[test]
    fn preserves_nested_directory_hierarchy_and_paths() {
        let directory = child(20, 10, "sub", ExfatObjectKind::Directory, 512, 512);
        let mut nested = child(30, 20, "nested", ExfatObjectKind::File, 1, 512);
        nested.path = vec![
            "sub".encode_utf16().collect(),
            "nested".encode_utf16().collect(),
        ];
        let expected_path = nested.path.clone();
        let source = inventory(
            vec![root(), directory, nested],
            vec![
                extent(10, 0, 1024, 512, ExtentKind::DirectoryData),
                extent(20, 0, 2048, 512, ExtentKind::DirectoryData),
                extent(30, 0, 3072, 512, ExtentKind::FileData),
            ],
        );
        let normalized = normalize_inventory(&source, LIMITS).unwrap();
        assert_eq!(normalized.graph.entries()[1].parent, ObjectId(2));
        assert_eq!(normalized.graph.entries()[1].target, ObjectId(3));
        assert_eq!(normalized.preservation.objects[2].path, expected_path);
    }

    #[test]
    fn rejects_inconsistent_paths_links_kinds_and_extents() {
        let mut bad_path = child(20, 10, "file", ExfatObjectKind::File, 1, 512);
        bad_path.path = vec!["other".encode_utf16().collect()];
        let source = inventory(
            vec![root(), bad_path],
            vec![
                extent(10, 0, 1024, 512, ExtentKind::DirectoryData),
                extent(20, 0, 2048, 512, ExtentKind::FileData),
            ],
        );
        assert!(matches!(
            normalize_inventory(&source, LIMITS),
            Err(ExfatNormalizeError::InvalidPath(StreamId(20)))
        ));

        let mut missing_parent = child(20, 99, "file", ExfatObjectKind::File, 0, 0);
        missing_parent.path = vec!["file".encode_utf16().collect()];
        let source = inventory(
            vec![root(), missing_parent],
            vec![extent(10, 0, 1024, 512, ExtentKind::DirectoryData)],
        );
        assert!(matches!(
            normalize_inventory(&source, LIMITS),
            Err(ExfatNormalizeError::MissingParent {
                parent: StreamId(99),
                ..
            })
        ));

        let source = inventory(
            vec![root(), child(20, 10, "file", ExfatObjectKind::File, 1, 512)],
            vec![
                extent(10, 0, 1024, 512, ExtentKind::DirectoryData),
                extent(20, 0, 2048, 512, ExtentKind::DirectoryData),
            ],
        );
        assert!(matches!(
            normalize_inventory(&source, LIMITS),
            Err(ExfatNormalizeError::ExtentKindMismatch {
                stream: StreamId(20),
                ..
            })
        ));
    }

    #[test]
    fn rejects_identity_collisions_and_missing_one_link_parent() {
        let first = child(20, 10, "first", ExfatObjectKind::File, 0, 0);
        let mut collision = child(20, 10, "second", ExfatObjectKind::File, 0, 0);
        collision.path = vec!["second".encode_utf16().collect()];
        let source = inventory(
            vec![root(), first, collision],
            vec![extent(10, 0, 1024, 512, ExtentKind::DirectoryData)],
        );
        assert!(matches!(
            normalize_inventory(&source, LIMITS),
            Err(ExfatNormalizeError::DuplicateSourceStream(StreamId(20)))
        ));

        let mut unlinked = child(20, 10, "unlinked", ExfatObjectKind::File, 0, 0);
        unlinked.parent = None;
        let source = inventory(
            vec![root(), unlinked],
            vec![extent(10, 0, 1024, 512, ExtentKind::DirectoryData)],
        );
        assert!(matches!(
            normalize_inventory(&source, LIMITS),
            Err(ExfatNormalizeError::NonRootMissingParent(StreamId(20)))
        ));
    }

    #[test]
    fn rejects_inconsistent_volume_label_evidence() {
        let mut source = inventory(
            vec![root()],
            vec![extent(10, 0, 1024, 512, ExtentKind::DirectoryData)],
        );
        source.root.directory.volume_labels = 1;
        assert!(matches!(
            normalize_inventory(&source, LIMITS),
            Err(ExfatNormalizeError::VolumeLabelEvidenceMismatch)
        ));

        source.root.directory.volume_labels = 0;
        source.preservation.nonzero_volume_label_padding = true;
        assert!(matches!(
            normalize_inventory(&source, LIMITS),
            Err(ExfatNormalizeError::VolumeLabelEvidenceMismatch)
        ));
    }
}
