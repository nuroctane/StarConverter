//! Filesystem-neutral object, namespace, and stream graph validation.
//!
//! Directory entries are separate from objects so hard links remain explicit. Parsers may only
//! hand a graph to conversion planning after this layer proves namespace reachability, directory
//! acyclicity, stream identity, and exact logical/physical extent accounting.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::SemanticFeature;
use crate::extent::{ExtentGraph, Placement, StreamId};

/// Stable parser-assigned identity for one filesystem object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ObjectKind {
    File,
    Directory,
}

/// Representation-specific semantics relevant to lossless planning.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct ObjectSemantics {
    pub has_security_descriptor: bool,
    pub is_reparse_point: bool,
}

/// Preservation-relevant stream flags.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct StreamFlags {
    pub sparse: bool,
    pub compressed: bool,
    pub encrypted: bool,
}

/// Where a stream's bytes are represented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamStorage {
    /// Small resident bytes embedded in filesystem metadata.
    Resident(Vec<u8>),
    /// Logical bytes described by the graph's extent collection.
    Extents,
}

/// One unnamed or named data stream belonging to an object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectStream {
    pub id: StreamId,
    /// `None` is the primary unnamed stream; `Some` preserves UTF-16 stream names exactly.
    pub name: Option<Vec<u16>>,
    /// Meaningful stream bytes (end-of-file), excluding allocation-unit slack.
    pub logical_bytes: u64,
    pub initialized_bytes: u64,
    /// Logical address space covered by extents, including final allocation-unit slack.
    pub mapped_bytes: u64,
    pub allocated_bytes: u64,
    pub flags: StreamFlags,
    pub storage: StreamStorage,
}

/// One underlying file or directory object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectRecord {
    pub id: ObjectId,
    pub kind: ObjectKind,
    /// Number of namespace entries which must reference this object. The root uses zero.
    pub link_count: u32,
    pub semantics: ObjectSemantics,
    pub streams: Vec<ObjectStream>,
}

/// One exact UTF-16 name linking a parent directory to an object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceEntry {
    pub parent: ObjectId,
    pub target: ObjectId,
    pub name: Vec<u16>,
}

/// Caller-controlled work and memory bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectGraphLimits {
    pub max_objects: usize,
    pub max_entries: usize,
    pub max_streams: usize,
    pub max_name_code_units: usize,
}

/// Proven filesystem-neutral namespace and stream evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectGraph {
    root: ObjectId,
    objects: Vec<ObjectRecord>,
    entries: Vec<NamespaceEntry>,
    extents: ExtentGraph,
    features: Vec<SemanticFeature>,
}

impl ObjectGraph {
    /// Validates a complete normalized graph.
    ///
    /// # Errors
    ///
    /// Returns [`ObjectGraphError`] for cap exhaustion, inconsistent identities or sizes,
    /// incomplete extent coverage, namespace ambiguity, unreachable objects, or directory cycles.
    pub fn build(
        root: ObjectId,
        objects: Vec<ObjectRecord>,
        entries: Vec<NamespaceEntry>,
        extents: ExtentGraph,
        limits: ObjectGraphLimits,
    ) -> Result<Self, ObjectGraphError> {
        validate_limits(limits)?;
        if objects.len() > limits.max_objects {
            return Err(ObjectGraphError::ObjectLimitExceeded {
                actual: objects.len(),
                maximum: limits.max_objects,
            });
        }
        if entries.len() > limits.max_entries {
            return Err(ObjectGraphError::EntryLimitExceeded {
                actual: entries.len(),
                maximum: limits.max_entries,
            });
        }

        let object_index = index_objects(&objects, root, limits)?;
        let stream_index = validate_streams(&objects, &extents, limits)?;
        validate_entries(&objects, &entries, &object_index, root, limits)?;
        validate_extent_references(&extents, &stream_index)?;
        validate_reachability(&objects, &entries, &object_index, root)?;
        let features = collect_features(&objects);

        Ok(Self {
            root,
            objects,
            entries,
            extents,
            features,
        })
    }

    #[must_use]
    pub const fn root(&self) -> ObjectId {
        self.root
    }

    #[must_use]
    pub fn objects(&self) -> &[ObjectRecord] {
        &self.objects
    }

    #[must_use]
    pub fn entries(&self) -> &[NamespaceEntry] {
        &self.entries
    }

    #[must_use]
    pub const fn extents(&self) -> &ExtentGraph {
        &self.extents
    }

    #[must_use]
    pub fn features(&self) -> &[SemanticFeature] {
        &self.features
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectGraphError {
    InvalidLimit {
        field: &'static str,
    },
    ObjectLimitExceeded {
        actual: usize,
        maximum: usize,
    },
    EntryLimitExceeded {
        actual: usize,
        maximum: usize,
    },
    StreamLimitExceeded {
        actual: usize,
        maximum: usize,
    },
    DuplicateObject(ObjectId),
    MissingRoot(ObjectId),
    RootNotDirectory(ObjectId),
    DuplicateStream(StreamId),
    DuplicateUnnamedStream(ObjectId),
    InvalidStreamSizes {
        stream: StreamId,
    },
    ResidentLengthMismatch {
        stream: StreamId,
        declared: u64,
        actual: usize,
    },
    ResidentAllocation {
        stream: StreamId,
        allocated: u64,
    },
    MissingStreamExtent(StreamId),
    UnknownExtentStream(StreamId),
    ExtentGap {
        stream: StreamId,
        expected: u64,
        actual: u64,
    },
    ExtentLengthMismatch {
        stream: StreamId,
        expected: u64,
        actual: u64,
    },
    AllocationMismatch {
        stream: StreamId,
        expected: u64,
        actual: u64,
    },
    MissingParent(ObjectId),
    ParentNotDirectory(ObjectId),
    MissingTarget(ObjectId),
    RootHasNamespaceEntry,
    EmptyName {
        target: ObjectId,
    },
    NameTooLong {
        target: ObjectId,
        actual: usize,
        maximum: usize,
    },
    DuplicateName {
        parent: ObjectId,
        name: Vec<u16>,
    },
    LinkCountMismatch {
        object: ObjectId,
        expected: u32,
        actual: u32,
    },
    UnreachableObject(ObjectId),
    DirectoryCycle(ObjectId),
    ArithmeticOverflow,
}

impl fmt::Display for ObjectGraphError {
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit { field } => write!(formatter, "object graph limit {field} is zero"),
            Self::ObjectLimitExceeded { actual, maximum } => {
                write!(formatter, "object count {actual} exceeds {maximum}")
            }
            Self::EntryLimitExceeded { actual, maximum } => write!(
                formatter,
                "namespace entry count {actual} exceeds {maximum}"
            ),
            Self::StreamLimitExceeded { actual, maximum } => {
                write!(formatter, "stream count {actual} exceeds {maximum}")
            }
            Self::DuplicateObject(id) => write!(formatter, "duplicate object identity {}", id.0),
            Self::MissingRoot(id) => write!(formatter, "root object {} is missing", id.0),
            Self::RootNotDirectory(id) => {
                write!(formatter, "root object {} is not a directory", id.0)
            }
            Self::DuplicateStream(id) => write!(formatter, "duplicate stream identity {}", id.0),
            Self::DuplicateUnnamedStream(id) => {
                write!(formatter, "object {} has multiple unnamed streams", id.0)
            }
            Self::InvalidStreamSizes { stream } => write!(
                formatter,
                "stream {} has inconsistent initialized/logical sizes",
                stream.0
            ),
            Self::ResidentLengthMismatch {
                stream,
                declared,
                actual,
            } => write!(
                formatter,
                "resident stream {} declares {declared} bytes but contains {actual}",
                stream.0
            ),
            Self::ResidentAllocation { stream, allocated } => write!(
                formatter,
                "resident stream {} claims {allocated} allocated bytes",
                stream.0
            ),
            Self::MissingStreamExtent(id) => {
                write!(formatter, "non-empty extent stream {} has no extents", id.0)
            }
            Self::UnknownExtentStream(id) => write!(
                formatter,
                "extent references unknown or resident stream {}",
                id.0
            ),
            Self::ExtentGap {
                stream,
                expected,
                actual,
            } => write!(
                formatter,
                "stream {} extent gap: expected logical byte {expected}, found {actual}",
                stream.0
            ),
            Self::ExtentLengthMismatch {
                stream,
                expected,
                actual,
            } => write!(
                formatter,
                "stream {} covers {actual} logical bytes, expected {expected}",
                stream.0
            ),
            Self::AllocationMismatch {
                stream,
                expected,
                actual,
            } => write!(
                formatter,
                "stream {} has {actual} physical bytes, expected {expected}",
                stream.0
            ),
            Self::MissingParent(id) => write!(formatter, "namespace parent {} is missing", id.0),
            Self::ParentNotDirectory(id) => {
                write!(formatter, "namespace parent {} is not a directory", id.0)
            }
            Self::MissingTarget(id) => write!(formatter, "namespace target {} is missing", id.0),
            Self::RootHasNamespaceEntry => {
                formatter.write_str("root object must not have a namespace entry")
            }
            Self::EmptyName { target } => {
                write!(formatter, "namespace target {} has an empty name", target.0)
            }
            Self::NameTooLong {
                target,
                actual,
                maximum,
            } => write!(
                formatter,
                "namespace target {} name has {actual} UTF-16 units, exceeding {maximum}",
                target.0
            ),
            Self::DuplicateName { parent, .. } => write!(
                formatter,
                "directory {} contains an exact duplicate name",
                parent.0
            ),
            Self::LinkCountMismatch {
                object,
                expected,
                actual,
            } => write!(
                formatter,
                "object {} declares {expected} links but has {actual}",
                object.0
            ),
            Self::UnreachableObject(id) => {
                write!(formatter, "object {} is unreachable from the root", id.0)
            }
            Self::DirectoryCycle(id) => {
                write!(formatter, "directory graph cycles through object {}", id.0)
            }
            Self::ArithmeticOverflow => formatter.write_str("object graph accounting overflow"),
        }
    }
}

impl std::error::Error for ObjectGraphError {}

fn validate_limits(limits: ObjectGraphLimits) -> Result<(), ObjectGraphError> {
    for (field, value) in [
        ("max_objects", limits.max_objects),
        ("max_entries", limits.max_entries),
        ("max_streams", limits.max_streams),
        ("max_name_code_units", limits.max_name_code_units),
    ] {
        if value == 0 {
            return Err(ObjectGraphError::InvalidLimit { field });
        }
    }
    Ok(())
}

fn index_objects(
    objects: &[ObjectRecord],
    root: ObjectId,
    limits: ObjectGraphLimits,
) -> Result<BTreeMap<ObjectId, usize>, ObjectGraphError> {
    let mut index = BTreeMap::new();
    for (position, object) in objects.iter().enumerate() {
        if index.insert(object.id, position).is_some() {
            return Err(ObjectGraphError::DuplicateObject(object.id));
        }
    }
    let root_position = *index
        .get(&root)
        .ok_or(ObjectGraphError::MissingRoot(root))?;
    if objects[root_position].kind != ObjectKind::Directory {
        return Err(ObjectGraphError::RootNotDirectory(root));
    }
    if objects.len() > limits.max_objects {
        return Err(ObjectGraphError::ObjectLimitExceeded {
            actual: objects.len(),
            maximum: limits.max_objects,
        });
    }
    Ok(index)
}

fn validate_streams(
    objects: &[ObjectRecord],
    extents: &ExtentGraph,
    limits: ObjectGraphLimits,
) -> Result<BTreeMap<StreamId, bool>, ObjectGraphError> {
    let total = objects
        .iter()
        .try_fold(0_usize, |sum, object| sum.checked_add(object.streams.len()))
        .ok_or(ObjectGraphError::ArithmeticOverflow)?;
    if total > limits.max_streams {
        return Err(ObjectGraphError::StreamLimitExceeded {
            actual: total,
            maximum: limits.max_streams,
        });
    }
    let mut streams = BTreeMap::new();
    for object in objects {
        let mut unnamed = false;
        for stream in &object.streams {
            if stream.name.is_none() {
                if unnamed {
                    return Err(ObjectGraphError::DuplicateUnnamedStream(object.id));
                }
                unnamed = true;
            }
            if stream.initialized_bytes > stream.logical_bytes
                || stream.logical_bytes > stream.mapped_bytes
            {
                return Err(ObjectGraphError::InvalidStreamSizes { stream: stream.id });
            }
            let extent_backed = matches!(stream.storage, StreamStorage::Extents);
            if streams.insert(stream.id, extent_backed).is_some() {
                return Err(ObjectGraphError::DuplicateStream(stream.id));
            }
            match &stream.storage {
                StreamStorage::Resident(bytes) => {
                    if u64::try_from(bytes.len()).ok() != Some(stream.logical_bytes) {
                        return Err(ObjectGraphError::ResidentLengthMismatch {
                            stream: stream.id,
                            declared: stream.logical_bytes,
                            actual: bytes.len(),
                        });
                    }
                    if stream.allocated_bytes != 0 {
                        return Err(ObjectGraphError::ResidentAllocation {
                            stream: stream.id,
                            allocated: stream.allocated_bytes,
                        });
                    }
                    if stream.mapped_bytes != stream.logical_bytes {
                        return Err(ObjectGraphError::InvalidStreamSizes { stream: stream.id });
                    }
                }
                StreamStorage::Extents => validate_stream_extents(stream, extents)?,
            }
        }
    }
    Ok(streams)
}

fn validate_stream_extents(
    stream: &ObjectStream,
    graph: &ExtentGraph,
) -> Result<(), ObjectGraphError> {
    let mut expected_offset = 0_u64;
    let mut physical = 0_u64;
    let mut found = false;
    for extent in graph
        .extents()
        .iter()
        .filter(|extent| extent.stream == stream.id)
    {
        found = true;
        if extent.logical_offset != expected_offset {
            return Err(ObjectGraphError::ExtentGap {
                stream: stream.id,
                expected: expected_offset,
                actual: extent.logical_offset,
            });
        }
        expected_offset = expected_offset
            .checked_add(extent.length)
            .ok_or(ObjectGraphError::ArithmeticOverflow)?;
        if matches!(extent.placement, Placement::Physical { .. }) {
            physical = physical
                .checked_add(extent.length)
                .ok_or(ObjectGraphError::ArithmeticOverflow)?;
        }
    }
    if stream.mapped_bytes != 0 && !found {
        return Err(ObjectGraphError::MissingStreamExtent(stream.id));
    }
    if expected_offset != stream.mapped_bytes {
        return Err(ObjectGraphError::ExtentLengthMismatch {
            stream: stream.id,
            expected: stream.mapped_bytes,
            actual: expected_offset,
        });
    }
    if physical != stream.allocated_bytes {
        return Err(ObjectGraphError::AllocationMismatch {
            stream: stream.id,
            expected: stream.allocated_bytes,
            actual: physical,
        });
    }
    Ok(())
}

fn validate_extent_references(
    graph: &ExtentGraph,
    streams: &BTreeMap<StreamId, bool>,
) -> Result<(), ObjectGraphError> {
    for extent in graph.extents() {
        if streams.get(&extent.stream) != Some(&true) {
            return Err(ObjectGraphError::UnknownExtentStream(extent.stream));
        }
    }
    Ok(())
}

fn validate_entries(
    objects: &[ObjectRecord],
    entries: &[NamespaceEntry],
    index: &BTreeMap<ObjectId, usize>,
    root: ObjectId,
    limits: ObjectGraphLimits,
) -> Result<(), ObjectGraphError> {
    let mut names = BTreeSet::new();
    let mut links = BTreeMap::<ObjectId, u32>::new();
    for entry in entries {
        let parent = index
            .get(&entry.parent)
            .ok_or(ObjectGraphError::MissingParent(entry.parent))?;
        if objects[*parent].kind != ObjectKind::Directory {
            return Err(ObjectGraphError::ParentNotDirectory(entry.parent));
        }
        if !index.contains_key(&entry.target) {
            return Err(ObjectGraphError::MissingTarget(entry.target));
        }
        if entry.target == root {
            return Err(ObjectGraphError::RootHasNamespaceEntry);
        }
        if entry.name.is_empty() {
            return Err(ObjectGraphError::EmptyName {
                target: entry.target,
            });
        }
        if entry.name.len() > limits.max_name_code_units {
            return Err(ObjectGraphError::NameTooLong {
                target: entry.target,
                actual: entry.name.len(),
                maximum: limits.max_name_code_units,
            });
        }
        if !names.insert((entry.parent, entry.name.clone())) {
            return Err(ObjectGraphError::DuplicateName {
                parent: entry.parent,
                name: entry.name.clone(),
            });
        }
        let count = links.entry(entry.target).or_default();
        *count = count
            .checked_add(1)
            .ok_or(ObjectGraphError::ArithmeticOverflow)?;
    }
    for object in objects {
        let actual = links.get(&object.id).copied().unwrap_or(0);
        let expected = if object.id == root {
            0
        } else {
            object.link_count
        };
        if actual != expected {
            return Err(ObjectGraphError::LinkCountMismatch {
                object: object.id,
                expected,
                actual,
            });
        }
    }
    Ok(())
}

fn validate_reachability(
    objects: &[ObjectRecord],
    entries: &[NamespaceEntry],
    index: &BTreeMap<ObjectId, usize>,
    root: ObjectId,
) -> Result<(), ObjectGraphError> {
    let mut reachable = BTreeSet::new();
    let mut state = BTreeMap::<ObjectId, u8>::new();
    let mut directory_children = BTreeMap::<ObjectId, Vec<ObjectId>>::new();
    for entry in entries {
        if objects[*index.get(&entry.target).expect("validated target")].kind
            == ObjectKind::Directory
        {
            directory_children
                .entry(entry.parent)
                .or_default()
                .push(entry.target);
        }
    }
    let mut stack = Vec::new();
    let work_capacity = objects
        .len()
        .checked_add(entries.len())
        .and_then(|value| value.checked_add(1))
        .ok_or(ObjectGraphError::ArithmeticOverflow)?;
    stack
        .try_reserve(work_capacity)
        .map_err(|_| ObjectGraphError::ArithmeticOverflow)?;
    stack.push((root, false));
    while let Some((directory, exiting)) = stack.pop() {
        if exiting {
            state.insert(directory, 2);
            continue;
        }
        match state.get(&directory) {
            Some(1) => return Err(ObjectGraphError::DirectoryCycle(directory)),
            Some(2) => continue,
            _ => {}
        }
        state.insert(directory, 1);
        reachable.insert(directory);
        stack.push((directory, true));
        for entry in entries.iter().filter(|entry| entry.parent == directory) {
            reachable.insert(entry.target);
        }
        if let Some(children) = directory_children.get(&directory) {
            stack.extend(children.iter().rev().map(|child| (*child, false)));
        }
    }
    for object in objects {
        if !reachable.contains(&object.id) {
            return Err(ObjectGraphError::UnreachableObject(object.id));
        }
    }
    Ok(())
}

fn collect_features(objects: &[ObjectRecord]) -> Vec<SemanticFeature> {
    let mut found = BTreeSet::new();
    for object in objects {
        if object.link_count > 1 {
            found.insert(4_u8);
        }
        if object.semantics.has_security_descriptor {
            found.insert(0);
        }
        if object.semantics.is_reparse_point {
            found.insert(5);
        }
        for stream in &object.streams {
            if stream.name.is_some() {
                found.insert(1);
            }
            if stream.flags.compressed {
                found.insert(2);
            }
            if stream.flags.encrypted {
                found.insert(3);
            }
            if stream.flags.sparse {
                found.insert(6);
            }
        }
    }
    found
        .into_iter()
        .map(|feature| match feature {
            0 => SemanticFeature::AccessControl,
            1 => SemanticFeature::AlternateDataStreams,
            2 => SemanticFeature::Compression,
            3 => SemanticFeature::EncryptedFiles,
            4 => SemanticFeature::HardLinks,
            5 => SemanticFeature::ReparsePoints,
            _ => SemanticFeature::SparseFiles,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extent::{Extent, ExtentKind};

    const LIMITS: ObjectGraphLimits = ObjectGraphLimits {
        max_objects: 16,
        max_entries: 16,
        max_streams: 16,
        max_name_code_units: 255,
    };

    fn graph_extents(extents: Vec<Extent>) -> ExtentGraph {
        ExtentGraph::build(extents, 4096, 16).unwrap()
    }

    fn directory(id: u64, links: u32) -> ObjectRecord {
        ObjectRecord {
            id: ObjectId(id),
            kind: ObjectKind::Directory,
            link_count: links,
            semantics: ObjectSemantics::default(),
            streams: Vec::new(),
        }
    }

    fn file(id: u64, links: u32, stream: ObjectStream) -> ObjectRecord {
        ObjectRecord {
            id: ObjectId(id),
            kind: ObjectKind::File,
            link_count: links,
            semantics: ObjectSemantics::default(),
            streams: vec![stream],
        }
    }

    fn resident(id: u64, bytes: &[u8]) -> ObjectStream {
        ObjectStream {
            id: StreamId(id),
            name: None,
            logical_bytes: bytes.len() as u64,
            initialized_bytes: bytes.len() as u64,
            mapped_bytes: bytes.len() as u64,
            allocated_bytes: 0,
            flags: StreamFlags::default(),
            storage: StreamStorage::Resident(bytes.to_vec()),
        }
    }

    fn entry(parent: u64, target: u64, name: &str) -> NamespaceEntry {
        NamespaceEntry {
            parent: ObjectId(parent),
            target: ObjectId(target),
            name: name.encode_utf16().collect(),
        }
    }

    #[test]
    fn accepts_hard_links_and_derives_semantic_features() {
        let mut stream = resident(10, b"data");
        stream.name = Some("fork".encode_utf16().collect());
        stream.flags.compressed = true;
        let value = ObjectGraph::build(
            ObjectId(1),
            vec![directory(1, 0), file(2, 2, stream)],
            vec![entry(1, 2, "a"), entry(1, 2, "b")],
            graph_extents(Vec::new()),
            LIMITS,
        )
        .unwrap();
        assert_eq!(
            value.features(),
            &[
                SemanticFeature::AlternateDataStreams,
                SemanticFeature::Compression,
                SemanticFeature::HardLinks
            ]
        );
    }

    #[test]
    fn validates_exact_extent_coverage_and_allocation() {
        let stream = ObjectStream {
            id: StreamId(10),
            name: None,
            logical_bytes: 100,
            initialized_bytes: 80,
            mapped_bytes: 100,
            allocated_bytes: 60,
            flags: StreamFlags {
                sparse: true,
                ..StreamFlags::default()
            },
            storage: StreamStorage::Extents,
        };
        let extents = graph_extents(vec![
            Extent {
                stream: StreamId(10),
                logical_offset: 0,
                length: 60,
                placement: Placement::Physical { byte_offset: 1000 },
                kind: ExtentKind::FileData,
            },
            Extent {
                stream: StreamId(10),
                logical_offset: 60,
                length: 40,
                placement: Placement::Sparse,
                kind: ExtentKind::FileData,
            },
        ]);
        ObjectGraph::build(
            ObjectId(1),
            vec![directory(1, 0), file(2, 1, stream)],
            vec![entry(1, 2, "file")],
            extents,
            LIMITS,
        )
        .unwrap();

        let slack_stream = ObjectStream {
            id: StreamId(11),
            name: None,
            logical_bytes: 1,
            initialized_bytes: 1,
            mapped_bytes: 512,
            allocated_bytes: 512,
            flags: StreamFlags::default(),
            storage: StreamStorage::Extents,
        };
        let slack_extents = graph_extents(vec![Extent {
            stream: StreamId(11),
            logical_offset: 0,
            length: 512,
            placement: Placement::Physical { byte_offset: 2048 },
            kind: ExtentKind::FileData,
        }]);
        ObjectGraph::build(
            ObjectId(1),
            vec![directory(1, 0), file(2, 1, slack_stream)],
            vec![entry(1, 2, "slack")],
            slack_extents,
            LIMITS,
        )
        .unwrap();
    }

    #[test]
    fn rejects_extent_gaps_unknown_streams_and_bad_resident_sizes() {
        let stream = ObjectStream {
            id: StreamId(10),
            name: None,
            logical_bytes: 20,
            initialized_bytes: 20,
            mapped_bytes: 20,
            allocated_bytes: 10,
            flags: StreamFlags::default(),
            storage: StreamStorage::Extents,
        };
        let extents = graph_extents(vec![Extent {
            stream: StreamId(10),
            logical_offset: 10,
            length: 10,
            placement: Placement::Physical { byte_offset: 0 },
            kind: ExtentKind::FileData,
        }]);
        assert!(matches!(
            ObjectGraph::build(
                ObjectId(1),
                vec![directory(1, 0), file(2, 1, stream)],
                vec![entry(1, 2, "x")],
                extents,
                LIMITS
            ),
            Err(ObjectGraphError::ExtentGap { .. })
        ));

        let bad = ObjectStream {
            logical_bytes: 2,
            mapped_bytes: 2,
            ..resident(11, b"x")
        };
        assert!(matches!(
            ObjectGraph::build(
                ObjectId(1),
                vec![directory(1, 0), file(2, 1, bad)],
                vec![entry(1, 2, "x")],
                graph_extents(Vec::new()),
                LIMITS
            ),
            Err(ObjectGraphError::ResidentLengthMismatch { .. })
        ));
    }

    #[test]
    fn rejects_cycles_unreachable_objects_and_link_mismatch() {
        assert!(matches!(
            ObjectGraph::build(
                ObjectId(1),
                vec![directory(1, 0), directory(2, 1)],
                vec![entry(1, 2, "child"), entry(2, 1, "cycle")],
                graph_extents(Vec::new()),
                LIMITS
            ),
            Err(ObjectGraphError::RootHasNamespaceEntry)
        ));
        assert!(matches!(
            ObjectGraph::build(
                ObjectId(1),
                vec![directory(1, 0), directory(2, 1), directory(3, 1)],
                vec![entry(1, 2, "child")],
                graph_extents(Vec::new()),
                LIMITS
            ),
            Err(ObjectGraphError::LinkCountMismatch {
                object: ObjectId(3),
                ..
            })
        ));
        assert!(matches!(
            ObjectGraph::build(
                ObjectId(1),
                vec![directory(1, 0), file(2, 2, resident(10, b"x"))],
                vec![entry(1, 2, "x")],
                graph_extents(Vec::new()),
                LIMITS
            ),
            Err(ObjectGraphError::LinkCountMismatch { .. })
        ));
        assert!(matches!(
            ObjectGraph::build(
                ObjectId(1),
                vec![directory(1, 0), directory(2, 2), directory(3, 1)],
                vec![entry(1, 2, "a"), entry(2, 3, "b"), entry(3, 2, "c")],
                graph_extents(Vec::new()),
                LIMITS,
            ),
            Err(ObjectGraphError::DirectoryCycle(ObjectId(2)))
        ));
    }

    #[test]
    fn rejects_exact_duplicate_names_but_preserves_case_distinctions() {
        let objects = vec![
            directory(1, 0),
            file(2, 1, resident(10, b"a")),
            file(3, 1, resident(11, b"b")),
        ];
        assert!(matches!(
            ObjectGraph::build(
                ObjectId(1),
                objects.clone(),
                vec![entry(1, 2, "same"), entry(1, 3, "same")],
                graph_extents(Vec::new()),
                LIMITS
            ),
            Err(ObjectGraphError::DuplicateName { .. })
        ));
        ObjectGraph::build(
            ObjectId(1),
            objects,
            vec![entry(1, 2, "Name"), entry(1, 3, "name")],
            graph_extents(Vec::new()),
            LIMITS,
        )
        .unwrap();
    }

    #[test]
    fn validates_deep_directory_chain_without_process_stack_recursion() {
        const DEPTH: usize = 2_048;
        let mut objects = Vec::with_capacity(DEPTH);
        let mut entries = Vec::with_capacity(DEPTH - 1);
        objects.push(directory(1, 0));
        for value in 2..=DEPTH {
            let id = u64::try_from(value).unwrap();
            objects.push(directory(id, 1));
            entries.push(entry(id - 1, id, "d"));
        }
        ObjectGraph::build(
            ObjectId(1),
            objects,
            entries,
            graph_extents(Vec::new()),
            ObjectGraphLimits {
                max_objects: DEPTH,
                max_entries: DEPTH,
                max_streams: 1,
                max_name_code_units: 1,
            },
        )
        .unwrap();
    }
}
