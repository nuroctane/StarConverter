//! Exact physical range and relocation planning for staged filesystem layouts.
//!
//! The solver consumes already proven source allocation and destination-mandatory ranges. It keeps
//! non-conflicting payloads in place and relocates only conflicting movable extents into the
//! complement of *all* source allocation and destination reservations. Source metadata that may
//! disappear after activation is deliberately not treated as staging scratch.

use std::collections::BTreeSet;
use std::fmt;

use crate::extent::{Extent, ExtentGraph, ExtentGraphError, ExtentKind, Placement, StreamId};
use crate::object::{
    ObjectGraph, ObjectGraphError, ObjectGraphLimits, ObjectKind, ObjectStream, StreamStorage,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteRange {
    pub offset: u64,
    pub length: u64,
}

impl ByteRange {
    fn end(self) -> Result<u64, LayoutError> {
        self.offset
            .checked_add(self.length)
            .ok_or(LayoutError::RangeOverflow {
                offset: self.offset,
                length: self.length,
            })
    }
}

/// Dest-cluster indices whose byte span overlaps any caller-supplied unusable range.
///
/// A source mark that is not dest-cluster aligned expands to every dest cluster it touches so the
/// converted volume never allocates known-bad media. Ranges must be nonzero and inside `volume_bytes`.
///
/// # Errors
/// Returns [`LayoutError`] for a zero cluster size that is not a power of two, a zero-length
/// range, overflow, or a range that extends past the volume.
pub fn clusters_covering_ranges(
    ranges: &[ByteRange],
    cluster_bytes: u64,
    volume_bytes: u64,
) -> Result<Vec<u64>, LayoutError> {
    if cluster_bytes == 0 || !cluster_bytes.is_power_of_two() {
        return Err(LayoutError::InvalidAlignment {
            alignment: cluster_bytes,
        });
    }
    let mut lcns = BTreeSet::new();
    for range in ranges {
        if range.length == 0 {
            return Err(LayoutError::ZeroLengthRange {
                offset: range.offset,
            });
        }
        let end = range.end()?;
        if end > volume_bytes {
            return Err(LayoutError::RangeOutsideVolume {
                offset: range.offset,
                length: range.length,
                volume_bytes,
            });
        }
        let first = range.offset / cluster_bytes;
        let last = (end - 1) / cluster_bytes;
        for lcn in first..=last {
            lcns.insert(lcn);
        }
    }
    Ok(lcns.into_iter().collect())
}

/// One physically allocated source extent relevant to destination placement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceAllocation {
    pub stream: StreamId,
    pub logical_offset: u64,
    pub range: ByteRange,
    /// Only movable payloads may be relocated. Source metadata remains occupied during staging.
    pub movable: bool,
}

/// Why the destination requires one exact physical range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReservationKind {
    BootRegion,
    AllocationMetadata,
    NamespaceMetadata,
    Journal,
    Capsule,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DestinationReservation {
    pub range: ByteRange,
    pub kind: ReservationKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Relocation {
    pub stream: StreamId,
    pub logical_offset: u64,
    pub source: ByteRange,
    pub destination: ByteRange,
}

/// One destination-aligned payload assembled from the bound source graph.
///
/// Callers name only the stream and the required destination length. Source bytes are never
/// supplied as copy tuples; sealing reconstructs them from resident storage or the stream's
/// existing physical extents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaterializationRequest {
    pub stream: StreamId,
    pub destination_length: u64,
}

/// Sealed destination span for one materialized stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Materialization {
    pub stream: StreamId,
    pub destination: ByteRange,
}

/// Deterministic layout proof.
///
/// `free_after_staging` excludes all source allocation, reservations, relocation destinations,
/// and materialization destinations; it therefore remains usable before source activation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutPlan {
    pub relocations: Vec<Relocation>,
    pub materializations: Vec<Materialization>,
    pub free_after_staging: Vec<ByteRange>,
    pub relocated_bytes: u64,
    pub materialized_bytes: u64,
    pub largest_free_range: u64,
}

/// Opaque proof that one exact relocation layout was applied to one exact source graph.
///
/// Only the geometry coordinator can create this value. Consumers may inspect its immutable
/// source, target, and layout views, but cannot substitute a different graph or independently
/// edited relocation list at the write boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedRelocationPlan {
    source_graph: ObjectGraph,
    target_graph: ObjectGraph,
    layout: LayoutPlan,
}

impl SealedRelocationPlan {
    pub(crate) fn seal(
        source_graph: ObjectGraph,
        layout: LayoutPlan,
    ) -> Result<Self, RelocatedGraphError> {
        let target_graph = relocate_object_graph(&source_graph, &layout)?;
        Ok(Self {
            source_graph,
            target_graph,
            layout,
        })
    }

    /// Exact graph whose physical payload tuples authorize relocation reads.
    #[must_use]
    pub const fn source_graph(&self) -> &ObjectGraph {
        &self.source_graph
    }

    /// Exact graph derived by applying `layout` to `source_graph`.
    #[must_use]
    pub const fn target_graph(&self) -> &ObjectGraph {
        &self.target_graph
    }

    /// Exact immutable relocation layout bound to both graphs.
    #[must_use]
    pub const fn layout(&self) -> &LayoutPlan {
        &self.layout
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LayoutLimits {
    pub max_source_extents: usize,
    pub max_reservations: usize,
    pub max_free_ranges: usize,
    pub max_relocations: usize,
}

impl Default for LayoutLimits {
    fn default() -> Self {
        Self {
            max_source_extents: 8 * 1024 * 1024,
            max_reservations: 1024 * 1024,
            max_free_ranges: 8 * 1024 * 1024,
            max_relocations: 8 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LayoutError {
    InvalidLimit {
        field: &'static str,
    },
    InvalidAlignment {
        alignment: u64,
    },
    IncompatibleAlignments {
        io_alignment: u64,
        destination_alignment: u64,
    },
    SourceLimitExceeded {
        actual: usize,
        maximum: usize,
    },
    ReservationLimitExceeded {
        actual: usize,
        maximum: usize,
    },
    RelocationLimitExceeded {
        maximum: usize,
    },
    FreeRangeLimitExceeded {
        maximum: usize,
    },
    AllocationFailed,
    ZeroLengthRange {
        offset: u64,
    },
    RangeOverflow {
        offset: u64,
        length: u64,
    },
    RangeOutsideVolume {
        offset: u64,
        length: u64,
        volume_bytes: u64,
    },
    UnalignedRange {
        offset: u64,
        length: u64,
        alignment: u64,
    },
    DestinationLengthUnaligned {
        stream: StreamId,
        logical_offset: u64,
        length: u64,
        alignment: u64,
    },
    SourceOverlap {
        first_offset: u64,
        second_offset: u64,
    },
    StagingExclusionOverlap {
        first_offset: u64,
        second_offset: u64,
    },
    StagingExclusionOverlapsSource {
        source_offset: u64,
        exclusion_offset: u64,
    },
    ReservationOverlap {
        first_offset: u64,
        second_offset: u64,
    },
    ImmovableConflict {
        stream: StreamId,
        source_offset: u64,
        reservation_offset: u64,
    },
    ImmovableOutsideDestinationDomain {
        stream: StreamId,
        source_offset: u64,
        domain_offset: u64,
        domain_length: u64,
        alignment: u64,
    },
    InsufficientStagingSpace {
        required: u64,
        largest_free_range: u64,
        total_free: u64,
    },
    DuplicateMaterialization {
        stream: StreamId,
    },
    MaterializationConflictsWithLiveSource {
        stream: StreamId,
    },
    AccountingOverflow,
}

impl fmt::Display for LayoutError {
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit { field } => write!(formatter, "layout limit {field} is zero"),
            Self::InvalidAlignment { alignment } => write!(
                formatter,
                "layout alignment {alignment} is not a nonzero power of two"
            ),
            Self::IncompatibleAlignments {
                io_alignment,
                destination_alignment,
            } => write!(
                formatter,
                "destination alignment {destination_alignment} is not a multiple of I/O alignment {io_alignment}"
            ),
            Self::SourceLimitExceeded { actual, maximum } => write!(
                formatter,
                "source has {actual} extents, exceeding {maximum}"
            ),
            Self::ReservationLimitExceeded { actual, maximum } => write!(
                formatter,
                "destination has {actual} reservations, exceeding {maximum}"
            ),
            Self::RelocationLimitExceeded { maximum } => {
                write!(formatter, "relocation count exceeds {maximum}")
            }
            Self::FreeRangeLimitExceeded { maximum } => {
                write!(formatter, "free-range count exceeds {maximum}")
            }
            Self::AllocationFailed => {
                formatter.write_str("could not allocate bounded layout state")
            }
            Self::ZeroLengthRange { offset } => write!(formatter, "zero-length range at {offset}"),
            Self::RangeOverflow { offset, length } => write!(
                formatter,
                "range offset {offset}, length {length} overflows"
            ),
            Self::RangeOutsideVolume {
                offset,
                length,
                volume_bytes,
            } => write!(
                formatter,
                "range offset {offset}, length {length} exceeds {volume_bytes}-byte volume"
            ),
            Self::UnalignedRange {
                offset,
                length,
                alignment,
            } => write!(
                formatter,
                "range offset {offset}, length {length} is not aligned to {alignment}"
            ),
            Self::DestinationLengthUnaligned {
                stream,
                logical_offset,
                length,
                alignment,
            } => write!(
                formatter,
                "stream {} extent at logical byte {logical_offset} has length {length}, which is not aligned to the {alignment}-byte destination allocation unit",
                stream.0
            ),
            Self::SourceOverlap {
                first_offset,
                second_offset,
            } => write!(
                formatter,
                "source allocations at {first_offset} and {second_offset} overlap"
            ),
            Self::StagingExclusionOverlap {
                first_offset,
                second_offset,
            } => write!(
                formatter,
                "staging exclusions at {first_offset} and {second_offset} overlap"
            ),
            Self::StagingExclusionOverlapsSource {
                source_offset,
                exclusion_offset,
            } => write!(
                formatter,
                "staging exclusion at {exclusion_offset} overlaps live source allocation at {source_offset}"
            ),
            Self::ReservationOverlap {
                first_offset,
                second_offset,
            } => write!(
                formatter,
                "destination reservations at {first_offset} and {second_offset} overlap"
            ),
            Self::ImmovableConflict {
                stream,
                source_offset,
                reservation_offset,
            } => write!(
                formatter,
                "immovable stream {} at {source_offset} conflicts with destination reservation at {reservation_offset}",
                stream.0
            ),
            Self::ImmovableOutsideDestinationDomain {
                stream,
                source_offset,
                domain_offset,
                domain_length,
                alignment,
            } => write!(
                formatter,
                "immovable stream {} at {source_offset} is not a {alignment}-byte-aligned placement inside destination domain {domain_offset}..+{domain_length}",
                stream.0
            ),
            Self::InsufficientStagingSpace {
                required,
                largest_free_range,
                total_free,
            } => write!(
                formatter,
                "no staging range fits {required} bytes (largest {largest_free_range}, total {total_free})"
            ),
            Self::DuplicateMaterialization { stream } => write!(
                formatter,
                "stream {} has multiple materialization requests",
                stream.0
            ),
            Self::MaterializationConflictsWithLiveSource { stream } => write!(
                formatter,
                "stream {} cannot be both 1:1 relocated and materialized",
                stream.0
            ),
            Self::AccountingOverflow => formatter.write_str("layout byte accounting overflow"),
        }
    }
}

impl std::error::Error for LayoutError {}

/// Failure to derive the exact target object graph described by a relocation layout.
#[derive(Debug)]
pub enum RelocatedGraphError {
    AllocationFailed,
    InvalidRelocation {
        stream: StreamId,
        logical_offset: u64,
    },
    RelocationSourceMissing {
        stream: StreamId,
        logical_offset: u64,
    },
    DuplicateRelocationSource {
        stream: StreamId,
        logical_offset: u64,
    },
    NonPayloadRelocation {
        stream: StreamId,
        logical_offset: u64,
        kind: ExtentKind,
    },
    RelocatedByteCountMismatch {
        declared: u64,
        actual: u64,
    },
    DuplicateMaterialization {
        stream: StreamId,
    },
    MaterializationUnknownStream {
        stream: StreamId,
    },
    MaterializationConflictsWithRelocation {
        stream: StreamId,
    },
    InvalidMaterialization {
        stream: StreamId,
    },
    MaterializedByteCountMismatch {
        declared: u64,
        actual: u64,
    },
    Extents(ExtentGraphError),
    Objects(ObjectGraphError),
}

impl fmt::Display for RelocatedGraphError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AllocationFailed => {
                formatter.write_str("could not allocate bounded relocated-graph state")
            }
            Self::InvalidRelocation {
                stream,
                logical_offset,
            } => write!(
                formatter,
                "stream {} relocation at logical byte {logical_offset} has invalid geometry",
                stream.0
            ),
            Self::RelocationSourceMissing {
                stream,
                logical_offset,
            } => write!(
                formatter,
                "stream {} relocation source at logical byte {logical_offset} is absent from the source graph",
                stream.0
            ),
            Self::DuplicateRelocationSource {
                stream,
                logical_offset,
            } => write!(
                formatter,
                "stream {} extent at logical byte {logical_offset} has multiple relocation records",
                stream.0
            ),
            Self::NonPayloadRelocation {
                stream,
                logical_offset,
                kind,
            } => write!(
                formatter,
                "stream {} relocation at logical byte {logical_offset} targets non-payload extent {kind:?}",
                stream.0
            ),
            Self::RelocatedByteCountMismatch { declared, actual } => write!(
                formatter,
                "layout declares {declared} relocated bytes but exact relocation records contain {actual}"
            ),
            Self::DuplicateMaterialization { stream } => write!(
                formatter,
                "stream {} has multiple materialization records",
                stream.0
            ),
            Self::MaterializationUnknownStream { stream } => write!(
                formatter,
                "stream {} materialization is absent from the source graph",
                stream.0
            ),
            Self::MaterializationConflictsWithRelocation { stream } => write!(
                formatter,
                "stream {} cannot be both 1:1 relocated and materialized",
                stream.0
            ),
            Self::InvalidMaterialization { stream } => write!(
                formatter,
                "stream {} materialization has invalid destination geometry",
                stream.0
            ),
            Self::MaterializedByteCountMismatch { declared, actual } => write!(
                formatter,
                "layout declares {declared} materialized bytes but exact materialization records contain {actual}"
            ),
            Self::Extents(error) => write!(formatter, "relocated extent graph is invalid: {error}"),
            Self::Objects(error) => write!(formatter, "relocated object graph is invalid: {error}"),
        }
    }
}

impl std::error::Error for RelocatedGraphError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Extents(error) => Some(error),
            Self::Objects(error) => Some(error),
            _ => None,
        }
    }
}

/// Rebuilds an object graph with 1:1 payload relocations and sealed stream materializations.
///
/// The source graph is not modified. Every relocation must name one complete physical
/// [`ExtentKind::FileData`] extent by stream, logical offset, source offset, and length.
/// Every materialization names one stream whose destination span is reconstructed from resident
/// bytes or from that stream's source extents; the rebuilt graph replaces those extents with one
/// destination-aligned [`ExtentKind::FileData`] run. The rebuilt extent graph independently
/// rejects destination overlap and out-of-volume placement. Object identity, namespace, and
/// semantic-feature evidence is retained; only allocated/mapped stream storage may change for
/// materialized streams.
///
/// # Errors
///
/// Refuses partial, duplicate, missing, non-payload, overlapping, out-of-volume, or incorrectly
/// accounted relocations or materializations, and any graph which is no longer internally
/// consistent after remapping.
pub fn relocate_object_graph(
    source: &ObjectGraph,
    layout: &LayoutPlan,
) -> Result<ObjectGraph, RelocatedGraphError> {
    let mut relocated = source.extents().extents().to_vec();
    let sources = physical_extent_index(&relocated)?;
    let mut relocation_keys = Vec::new();
    relocation_keys
        .try_reserve_exact(layout.relocations.len())
        .map_err(|_| RelocatedGraphError::AllocationFailed)?;
    for relocation in &layout.relocations {
        relocation_keys.push(relocation_key(relocation));
    }
    relocation_keys.sort_unstable();
    if let Some(duplicate) = relocation_keys.windows(2).find(|pair| pair[0] == pair[1]) {
        return Err(RelocatedGraphError::DuplicateRelocationSource {
            stream: duplicate[0].0,
            logical_offset: duplicate[0].1,
        });
    }
    let mut actual_bytes = 0_u64;

    for relocation in &layout.relocations {
        if layout
            .materializations
            .iter()
            .any(|materialization| materialization.stream == relocation.stream)
        {
            return Err(
                RelocatedGraphError::MaterializationConflictsWithRelocation {
                    stream: relocation.stream,
                },
            );
        }
        if relocation.source.length == 0
            || relocation.source.length != relocation.destination.length
            || overlaps(relocation.source, relocation.destination).map_err(|_| {
                RelocatedGraphError::InvalidRelocation {
                    stream: relocation.stream,
                    logical_offset: relocation.logical_offset,
                }
            })?
        {
            return Err(RelocatedGraphError::InvalidRelocation {
                stream: relocation.stream,
                logical_offset: relocation.logical_offset,
            });
        }
        actual_bytes = actual_bytes.checked_add(relocation.source.length).ok_or(
            RelocatedGraphError::RelocatedByteCountMismatch {
                declared: layout.relocated_bytes,
                actual: u64::MAX,
            },
        )?;

        let key = relocation_key(relocation);
        let source_index = sources
            .binary_search_by_key(&key, |(candidate, _)| *candidate)
            .ok()
            .map(|position| sources[position].1)
            .ok_or(RelocatedGraphError::RelocationSourceMissing {
                stream: relocation.stream,
                logical_offset: relocation.logical_offset,
            })?;
        if relocated[source_index].kind != ExtentKind::FileData {
            return Err(RelocatedGraphError::NonPayloadRelocation {
                stream: relocation.stream,
                logical_offset: relocation.logical_offset,
                kind: relocated[source_index].kind,
            });
        }
        relocated[source_index].placement = Placement::Physical {
            byte_offset: relocation.destination.offset,
        };
    }

    if actual_bytes != layout.relocated_bytes {
        return Err(RelocatedGraphError::RelocatedByteCountMismatch {
            declared: layout.relocated_bytes,
            actual: actual_bytes,
        });
    }

    let mut objects = source.objects().to_vec();
    apply_materializations(&mut objects, &mut relocated, layout)?;
    rebuild_relocated_graph_with_objects(source, objects, relocated)
}

type PhysicalExtentKey = (StreamId, u64, u64, u64);

const fn relocation_key(relocation: &Relocation) -> PhysicalExtentKey {
    (
        relocation.stream,
        relocation.logical_offset,
        relocation.source.offset,
        relocation.source.length,
    )
}

fn physical_extent_index(
    extents: &[Extent],
) -> Result<Vec<(PhysicalExtentKey, usize)>, RelocatedGraphError> {
    let mut sources = Vec::new();
    sources
        .try_reserve_exact(extents.len())
        .map_err(|_| RelocatedGraphError::AllocationFailed)?;
    for (index, extent) in extents.iter().enumerate() {
        if let Placement::Physical { byte_offset } = extent.placement {
            sources.push((
                (
                    extent.stream,
                    extent.logical_offset,
                    byte_offset,
                    extent.length,
                ),
                index,
            ));
        }
    }
    sources.sort_unstable_by_key(|(key, _)| *key);
    Ok(sources)
}

fn apply_materializations(
    objects: &mut [crate::object::ObjectRecord],
    extents: &mut Vec<Extent>,
    layout: &LayoutPlan,
) -> Result<(), RelocatedGraphError> {
    let mut keys: Vec<StreamId> = layout
        .materializations
        .iter()
        .map(|materialization| materialization.stream)
        .collect();
    keys.sort_unstable();
    if let Some(duplicate) = keys.windows(2).find(|pair| pair[0] == pair[1]) {
        return Err(RelocatedGraphError::DuplicateMaterialization {
            stream: duplicate[0],
        });
    }
    let mut actual_bytes = 0_u64;
    for materialization in &layout.materializations {
        if materialization.destination.length == 0 {
            return Err(RelocatedGraphError::InvalidMaterialization {
                stream: materialization.stream,
            });
        }
        actual_bytes = actual_bytes
            .checked_add(materialization.destination.length)
            .ok_or(RelocatedGraphError::MaterializedByteCountMismatch {
                declared: layout.materialized_bytes,
                actual: u64::MAX,
            })?;
        let stream = find_file_stream_mut(objects, materialization.stream)?;
        if materialization.destination.length < stream.logical_bytes {
            return Err(RelocatedGraphError::InvalidMaterialization {
                stream: materialization.stream,
            });
        }
        stream.storage = StreamStorage::Extents;
        stream.mapped_bytes = materialization.destination.length;
        stream.allocated_bytes = materialization.destination.length;
        extents.retain(|extent| {
            !(extent.stream == materialization.stream && extent.kind == ExtentKind::FileData)
        });
        extents
            .try_reserve(1)
            .map_err(|_| RelocatedGraphError::AllocationFailed)?;
        extents.push(Extent {
            stream: materialization.stream,
            logical_offset: 0,
            length: materialization.destination.length,
            placement: Placement::Physical {
                byte_offset: materialization.destination.offset,
            },
            kind: ExtentKind::FileData,
        });
    }
    if actual_bytes != layout.materialized_bytes {
        return Err(RelocatedGraphError::MaterializedByteCountMismatch {
            declared: layout.materialized_bytes,
            actual: actual_bytes,
        });
    }
    for object in objects.iter_mut() {
        for stream in &mut object.streams {
            stream.flags.compressed = false;
            stream.flags.compression_block_bytes = 0;
        }
    }
    Ok(())
}

fn find_file_stream_mut(
    objects: &mut [crate::object::ObjectRecord],
    stream: StreamId,
) -> Result<&mut ObjectStream, RelocatedGraphError> {
    for object in objects.iter_mut() {
        if object.kind != ObjectKind::File {
            if object
                .streams
                .iter()
                .any(|candidate| candidate.id == stream)
            {
                return Err(RelocatedGraphError::InvalidMaterialization { stream });
            }
            continue;
        }
        if let Some(found) = object
            .streams
            .iter_mut()
            .find(|candidate| candidate.id == stream)
        {
            return Ok(found);
        }
    }
    Err(RelocatedGraphError::MaterializationUnknownStream { stream })
}

fn rebuild_relocated_graph_with_objects(
    source: &ObjectGraph,
    objects: Vec<crate::object::ObjectRecord>,
    relocated: Vec<Extent>,
) -> Result<ObjectGraph, RelocatedGraphError> {
    let extents = ExtentGraph::build(
        relocated,
        source.extents().volume_bytes(),
        source
            .extents()
            .extents()
            .len()
            .saturating_add(objects.len())
            .max(1),
    )
    .map_err(RelocatedGraphError::Extents)?;
    let limits = ObjectGraphLimits {
        max_objects: objects.len().max(1),
        max_entries: source.entries().len().max(1),
        max_streams: objects
            .iter()
            .map(|object| object.streams.len())
            .sum::<usize>()
            .max(1),
        max_name_code_units: source
            .entries()
            .iter()
            .map(|entry| entry.name.len())
            .max()
            .unwrap_or(1)
            .max(1),
    };
    ObjectGraph::build(
        source.root(),
        objects,
        source.entries().to_vec(),
        extents,
        limits,
    )
    .map_err(RelocatedGraphError::Objects)
}

/// Solves exact relocation placement for destination reservations.
///
/// # Errors
///
/// Rejects invalid/capped/overlapping geometry, immovable conflicts, or insufficient proven free
/// staging space. All input ranges and relocation lengths must be aligned to `alignment`.
pub fn solve_layout(
    volume_bytes: u64,
    alignment: u64,
    source: Vec<SourceAllocation>,
    reservations: Vec<DestinationReservation>,
    limits: LayoutLimits,
) -> Result<LayoutPlan, LayoutError> {
    solve_layout_with_staging_exclusions(
        volume_bytes,
        alignment,
        source,
        reservations,
        Vec::new(),
        limits,
    )
}

/// Solves relocation placement while protecting retired source metadata from use as scratch.
///
/// A staging exclusion is occupied until activation, but unlike a live source allocation it may
/// overlap a destination reservation. This is the correct model for source filesystem metadata:
/// relocation must not destroy it, while an exact destination write may replace it after its
/// before-image has been captured by the transaction layer.
///
/// # Errors
///
/// Applies the same checks as [`solve_layout`] and additionally rejects overlapping exclusions or
/// an exclusion which overlaps a live source allocation.
pub fn solve_layout_with_staging_exclusions(
    volume_bytes: u64,
    alignment: u64,
    source: Vec<SourceAllocation>,
    reservations: Vec<DestinationReservation>,
    staging_exclusions: Vec<ByteRange>,
    limits: LayoutLimits,
) -> Result<LayoutPlan, LayoutError> {
    solve_layout_with_staging_exclusions_and_io_alignment(
        volume_bytes,
        alignment,
        alignment,
        source,
        reservations,
        staging_exclusions,
        limits,
    )
}

/// Solves relocation placement when payload allocation and destination I/O have distinct alignment.
///
/// Source payload and relocation destinations obey `relocation_alignment`. Destination
/// reservations and retired-source staging exclusions obey `io_alignment`. This models formats
/// whose payload clusters are larger than independently writable boot or metadata sectors.
///
/// # Errors
///
/// Applies the same overlap, capacity, and resource checks as
/// [`solve_layout_with_staging_exclusions`], and refuses either invalid alignment or a range which
/// violates the alignment for its role.
#[allow(clippy::too_many_arguments)]
pub fn solve_layout_with_staging_exclusions_and_io_alignment(
    volume_bytes: u64,
    relocation_alignment: u64,
    io_alignment: u64,
    source: Vec<SourceAllocation>,
    reservations: Vec<DestinationReservation>,
    staging_exclusions: Vec<ByteRange>,
    limits: LayoutLimits,
) -> Result<LayoutPlan, LayoutError> {
    solve_layout_with_domain_and_alignments_inner(
        volume_bytes,
        relocation_alignment,
        relocation_alignment,
        io_alignment,
        ByteRange {
            offset: 0,
            length: volume_bytes,
        },
        false,
        source,
        reservations,
        staging_exclusions,
        &[],
        limits,
    )
}

/// Solves relocation placement into one exact destination allocation domain.
///
/// `source_alignment` proves that input ranges can be read safely, while
/// `destination_alignment` independently proves placements consumable by the target filesystem.
/// Every live source extent must have a destination-aligned length. A movable extent is relocated
/// when its current placement is outside `destination_domain`, is not destination-aligned, or
/// overlaps a destination reservation. Relocations are allocated only inside the domain. This is
/// the required model when a source payload is valid on its original filesystem but cannot be
/// reused at the same byte offset in a target cluster heap.
///
/// # Errors
///
/// Applies all checks from [`solve_layout_with_staging_exclusions_and_io_alignment`], validates
/// the destination domain and all three alignments, and refuses an immovable source which is not
/// already a valid target placement.
#[allow(clippy::too_many_arguments)]
pub fn solve_layout_with_destination_domain_and_alignments(
    volume_bytes: u64,
    source_alignment: u64,
    destination_alignment: u64,
    io_alignment: u64,
    destination_domain: ByteRange,
    source: Vec<SourceAllocation>,
    reservations: Vec<DestinationReservation>,
    staging_exclusions: Vec<ByteRange>,
    limits: LayoutLimits,
) -> Result<LayoutPlan, LayoutError> {
    validate_alignments([source_alignment, destination_alignment, io_alignment])?;
    if destination_alignment % io_alignment != 0 {
        return Err(LayoutError::IncompatibleAlignments {
            io_alignment,
            destination_alignment,
        });
    }
    solve_layout_with_domain_and_alignments_inner(
        volume_bytes,
        source_alignment,
        destination_alignment,
        io_alignment,
        destination_domain,
        true,
        source,
        reservations,
        staging_exclusions,
        &[],
        limits,
    )
}

/// Solves destination-domain relocation together with sealed stream materializations.
///
/// Materialization destinations are allocated first from proven free heap space. Remaining
/// destination-aligned live extents are then 1:1 relocated as in
/// [`solve_layout_with_destination_domain_and_alignments`].
///
/// # Errors
///
/// Returns the same refusals as [`solve_layout_with_destination_domain_and_alignments`], plus
/// duplicate materialization requests, requests that name a live 1:1 source, or destination
/// lengths that are not destination-aligned.
#[allow(clippy::too_many_arguments)]
pub fn solve_layout_with_destination_domain_alignments_and_materializations(
    volume_bytes: u64,
    source_alignment: u64,
    destination_alignment: u64,
    io_alignment: u64,
    destination_domain: ByteRange,
    source: Vec<SourceAllocation>,
    reservations: Vec<DestinationReservation>,
    staging_exclusions: Vec<ByteRange>,
    materializations: &[MaterializationRequest],
    limits: LayoutLimits,
) -> Result<LayoutPlan, LayoutError> {
    validate_alignments([source_alignment, destination_alignment, io_alignment])?;
    if destination_alignment % io_alignment != 0 {
        return Err(LayoutError::IncompatibleAlignments {
            io_alignment,
            destination_alignment,
        });
    }
    solve_layout_with_domain_and_alignments_inner(
        volume_bytes,
        source_alignment,
        destination_alignment,
        io_alignment,
        destination_domain,
        true,
        source,
        reservations,
        staging_exclusions,
        materializations,
        limits,
    )
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn solve_layout_with_domain_and_alignments_inner(
    volume_bytes: u64,
    source_alignment: u64,
    destination_alignment: u64,
    io_alignment: u64,
    destination_domain: ByteRange,
    require_aligned_domain: bool,
    mut source: Vec<SourceAllocation>,
    mut reservations: Vec<DestinationReservation>,
    mut staging_exclusions: Vec<ByteRange>,
    materialization_requests: &[MaterializationRequest],
    limits: LayoutLimits,
) -> Result<LayoutPlan, LayoutError> {
    validate_limits(limits)?;
    validate_alignments([source_alignment, destination_alignment, io_alignment])?;
    let protected_count = source
        .len()
        .checked_add(staging_exclusions.len())
        .ok_or(LayoutError::AccountingOverflow)?;
    if protected_count > limits.max_source_extents {
        return Err(LayoutError::SourceLimitExceeded {
            actual: protected_count,
            maximum: limits.max_source_extents,
        });
    }
    if reservations.len() > limits.max_reservations {
        return Err(LayoutError::ReservationLimitExceeded {
            actual: reservations.len(),
            maximum: limits.max_reservations,
        });
    }
    validate_ranges(
        volume_bytes,
        source_alignment,
        io_alignment,
        &source,
        &reservations,
    )?;
    if require_aligned_domain {
        validate_range(volume_bytes, destination_alignment, destination_domain)?;
    } else {
        validate_range(volume_bytes, io_alignment, destination_domain)?;
    }
    validate_destination_lengths(&source, destination_alignment)?;
    validate_materialization_requests(
        &source,
        materialization_requests,
        destination_alignment,
        limits.max_relocations,
    )?;
    for range in &staging_exclusions {
        validate_range(volume_bytes, io_alignment, *range)?;
    }
    source.sort_unstable_by_key(|value| value.range.offset);
    reservations.sort_unstable_by_key(|value| value.range.offset);
    staging_exclusions.sort_unstable_by_key(|range| range.offset);
    validate_nonoverlap_source(&source)?;
    validate_nonoverlap_reservations(&reservations)?;
    validate_staging_exclusions(&source, &staging_exclusions)?;

    let conflicts = collect_conflicts(
        &source,
        &reservations,
        destination_domain,
        destination_alignment,
        limits.max_relocations,
    )?;
    let occupied = union_occupied(
        &source,
        &reservations,
        &staging_exclusions,
        limits.max_free_ranges,
    )?;
    let mut free = complement(volume_bytes, &occupied, limits.max_free_ranges)?;
    let mut materializations = Vec::new();
    materializations
        .try_reserve(materialization_requests.len())
        .map_err(|_| LayoutError::AllocationFailed)?;
    let mut materialized_bytes = 0_u64;
    for request in materialization_requests {
        let destination = allocate_first_fit_aligned_within(
            &mut free,
            request.destination_length,
            destination_alignment,
            destination_domain,
            limits.max_free_ranges,
        )?
        .ok_or_else(|| {
            let (largest_free_range, total_free) =
                free_capacity_within(&free, destination_domain, destination_alignment)
                    .unwrap_or((0, 0));
            LayoutError::InsufficientStagingSpace {
                required: request.destination_length,
                largest_free_range,
                total_free,
            }
        })?;
        materialized_bytes = materialized_bytes
            .checked_add(request.destination_length)
            .ok_or(LayoutError::AccountingOverflow)?;
        materializations.push(Materialization {
            stream: request.stream,
            destination,
        });
    }
    let mut relocations = Vec::new();
    relocations
        .try_reserve(conflicts.len())
        .map_err(|_| LayoutError::AllocationFailed)?;
    let mut relocated_bytes = 0_u64;
    for allocation in conflicts {
        let destination = allocate_first_fit_aligned_within(
            &mut free,
            allocation.range.length,
            destination_alignment,
            destination_domain,
            limits.max_free_ranges,
        )?
        .ok_or_else(|| {
            let (largest_free_range, total_free) =
                free_capacity_within(&free, destination_domain, destination_alignment)
                    .unwrap_or((0, 0));
            LayoutError::InsufficientStagingSpace {
                required: allocation.range.length,
                largest_free_range,
                total_free,
            }
        })?;
        relocated_bytes = relocated_bytes
            .checked_add(allocation.range.length)
            .ok_or(LayoutError::AccountingOverflow)?;
        relocations.push(Relocation {
            stream: allocation.stream,
            logical_offset: allocation.logical_offset,
            source: allocation.range,
            destination,
        });
    }
    let largest_free_range = free.iter().map(|range| range.length).max().unwrap_or(0);
    Ok(LayoutPlan {
        relocations,
        materializations,
        free_after_staging: free,
        relocated_bytes,
        materialized_bytes,
        largest_free_range,
    })
}

fn validate_limits(limits: LayoutLimits) -> Result<(), LayoutError> {
    for (field, value) in [
        ("max_source_extents", limits.max_source_extents),
        ("max_reservations", limits.max_reservations),
        ("max_free_ranges", limits.max_free_ranges),
        ("max_relocations", limits.max_relocations),
    ] {
        if value == 0 {
            return Err(LayoutError::InvalidLimit { field });
        }
    }
    Ok(())
}

fn validate_alignments(alignments: [u64; 3]) -> Result<(), LayoutError> {
    for alignment in alignments {
        if alignment == 0 || !alignment.is_power_of_two() {
            return Err(LayoutError::InvalidAlignment { alignment });
        }
    }
    Ok(())
}

fn validate_destination_lengths(
    source: &[SourceAllocation],
    alignment: u64,
) -> Result<(), LayoutError> {
    for allocation in source {
        if allocation.range.length % alignment != 0 {
            return Err(LayoutError::DestinationLengthUnaligned {
                stream: allocation.stream,
                logical_offset: allocation.logical_offset,
                length: allocation.range.length,
                alignment,
            });
        }
    }
    Ok(())
}

fn validate_materialization_requests(
    source: &[SourceAllocation],
    requests: &[MaterializationRequest],
    alignment: u64,
    maximum: usize,
) -> Result<(), LayoutError> {
    if requests.len() > maximum {
        return Err(LayoutError::RelocationLimitExceeded { maximum });
    }
    let mut seen = requests
        .iter()
        .map(|request| request.stream)
        .collect::<Vec<_>>();
    seen.sort_unstable();
    if let Some(duplicate) = seen.windows(2).find(|pair| pair[0] == pair[1]) {
        return Err(LayoutError::DuplicateMaterialization {
            stream: duplicate[0],
        });
    }
    for request in requests {
        if request.destination_length == 0 || request.destination_length % alignment != 0 {
            return Err(LayoutError::DestinationLengthUnaligned {
                stream: request.stream,
                logical_offset: 0,
                length: request.destination_length,
                alignment,
            });
        }
        if source
            .iter()
            .any(|allocation| allocation.stream == request.stream)
        {
            return Err(LayoutError::MaterializationConflictsWithLiveSource {
                stream: request.stream,
            });
        }
    }
    Ok(())
}

/// Destination-aligned allocation length required to materialize one file stream, if any.
///
/// Empty resident files stay resident. Destination-aligned physical file-data extents remain
/// eligible for 1:1 relocation only when initialized bytes fill the destination span. Resident
/// payloads, sparse runs, uninitialized destination slack, and extent lengths that are not
/// divisible by `destination_alignment` require materialization.
#[must_use]
pub fn materialization_length_for_stream(
    graph: &ObjectGraph,
    stream: StreamId,
    destination_alignment: u64,
) -> Option<u64> {
    if destination_alignment == 0 || !destination_alignment.is_power_of_two() {
        return None;
    }
    let object_stream = graph.objects().iter().find_map(|object| {
        object
            .streams
            .iter()
            .find(|candidate| candidate.id == stream)
            .map(|candidate| (object.kind, candidate))
    })?;
    if object_stream.0 != ObjectKind::File {
        return None;
    }
    let stream = object_stream.1;
    if stream.logical_bytes == 0 {
        return None;
    }
    let dest_length = align_up(stream.logical_bytes, destination_alignment)?;
    if stream.flags.compression_block_bytes != 0 {
        return Some(dest_length);
    }
    if stream.initialized_bytes < dest_length {
        return Some(dest_length);
    }
    match &stream.storage {
        StreamStorage::Resident(bytes) if !bytes.is_empty() => Some(dest_length),
        StreamStorage::Resident(_) => None,
        StreamStorage::Extents => {
            let extents: Vec<_> = graph
                .extents()
                .extents()
                .iter()
                .filter(|extent| extent.stream == stream.id && extent.kind == ExtentKind::FileData)
                .collect();
            let representable = !extents.is_empty()
                && extents.iter().all(|extent| {
                    extent.length % destination_alignment == 0
                        && matches!(extent.placement, Placement::Physical { .. })
                });
            if representable {
                None
            } else {
                Some(dest_length)
            }
        }
    }
}

fn align_up(value: u64, alignment: u64) -> Option<u64> {
    if value == 0 {
        return Some(0);
    }
    let mask = alignment - 1;
    Some(value.checked_add(mask)? & !mask)
}

fn validate_range(volume_bytes: u64, alignment: u64, range: ByteRange) -> Result<(), LayoutError> {
    if range.length == 0 {
        return Err(LayoutError::ZeroLengthRange {
            offset: range.offset,
        });
    }
    let end = range.end()?;
    if end > volume_bytes {
        return Err(LayoutError::RangeOutsideVolume {
            offset: range.offset,
            length: range.length,
            volume_bytes,
        });
    }
    if range.offset % alignment != 0 || range.length % alignment != 0 {
        return Err(LayoutError::UnalignedRange {
            offset: range.offset,
            length: range.length,
            alignment,
        });
    }
    Ok(())
}

fn validate_ranges(
    volume_bytes: u64,
    source_alignment: u64,
    reservation_alignment: u64,
    source: &[SourceAllocation],
    reservations: &[DestinationReservation],
) -> Result<(), LayoutError> {
    for value in source {
        validate_range(volume_bytes, source_alignment, value.range)?;
    }
    for value in reservations {
        validate_range(volume_bytes, reservation_alignment, value.range)?;
    }
    Ok(())
}

fn validate_nonoverlap_source(source: &[SourceAllocation]) -> Result<(), LayoutError> {
    for pair in source.windows(2) {
        if pair[0].range.end()? > pair[1].range.offset {
            return Err(LayoutError::SourceOverlap {
                first_offset: pair[0].range.offset,
                second_offset: pair[1].range.offset,
            });
        }
    }
    Ok(())
}

fn validate_nonoverlap_reservations(
    reservations: &[DestinationReservation],
) -> Result<(), LayoutError> {
    for pair in reservations.windows(2) {
        if pair[0].range.end()? > pair[1].range.offset {
            return Err(LayoutError::ReservationOverlap {
                first_offset: pair[0].range.offset,
                second_offset: pair[1].range.offset,
            });
        }
    }
    Ok(())
}

fn validate_staging_exclusions(
    source: &[SourceAllocation],
    exclusions: &[ByteRange],
) -> Result<(), LayoutError> {
    for pair in exclusions.windows(2) {
        if pair[0].end()? > pair[1].offset {
            return Err(LayoutError::StagingExclusionOverlap {
                first_offset: pair[0].offset,
                second_offset: pair[1].offset,
            });
        }
    }
    let mut source_index = 0;
    for exclusion in exclusions {
        while source_index < source.len() && source[source_index].range.end()? <= exclusion.offset {
            source_index += 1;
        }
        if source_index < source.len() && overlaps(source[source_index].range, *exclusion)? {
            return Err(LayoutError::StagingExclusionOverlapsSource {
                source_offset: source[source_index].range.offset,
                exclusion_offset: exclusion.offset,
            });
        }
    }
    Ok(())
}

fn overlaps(left: ByteRange, right: ByteRange) -> Result<bool, LayoutError> {
    Ok(left.offset < right.end()? && right.offset < left.end()?)
}

fn collect_conflicts(
    source: &[SourceAllocation],
    reservations: &[DestinationReservation],
    destination_domain: ByteRange,
    destination_alignment: u64,
    maximum: usize,
) -> Result<Vec<SourceAllocation>, LayoutError> {
    let mut conflicts = Vec::new();
    let mut reservation_index = 0;
    for allocation in source {
        while reservation_index < reservations.len()
            && reservations[reservation_index].range.end()? <= allocation.range.offset
        {
            reservation_index += 1;
        }
        let mut current = reservation_index;
        let source_end = allocation.range.end()?;
        let domain_end = destination_domain.end()?;
        let mut found = allocation.range.offset < destination_domain.offset
            || source_end > domain_end
            || allocation.range.offset % destination_alignment != 0;
        if found && !allocation.movable {
            return Err(LayoutError::ImmovableOutsideDestinationDomain {
                stream: allocation.stream,
                source_offset: allocation.range.offset,
                domain_offset: destination_domain.offset,
                domain_length: destination_domain.length,
                alignment: destination_alignment,
            });
        }
        while current < reservations.len() && reservations[current].range.offset < source_end {
            if overlaps(allocation.range, reservations[current].range)? {
                if !allocation.movable {
                    return Err(LayoutError::ImmovableConflict {
                        stream: allocation.stream,
                        source_offset: allocation.range.offset,
                        reservation_offset: reservations[current].range.offset,
                    });
                }
                found = true;
            }
            current += 1;
        }
        if found {
            if conflicts.len() >= maximum {
                return Err(LayoutError::RelocationLimitExceeded { maximum });
            }
            conflicts
                .try_reserve(1)
                .map_err(|_| LayoutError::AllocationFailed)?;
            conflicts.push(*allocation);
        }
    }
    Ok(conflicts)
}

fn union_occupied(
    source: &[SourceAllocation],
    reservations: &[DestinationReservation],
    staging_exclusions: &[ByteRange],
    maximum: usize,
) -> Result<Vec<ByteRange>, LayoutError> {
    let mut all = Vec::new();
    all.try_reserve(
        source
            .len()
            .saturating_add(reservations.len())
            .saturating_add(staging_exclusions.len()),
    )
    .map_err(|_| LayoutError::AllocationFailed)?;
    all.extend(source.iter().map(|value| value.range));
    all.extend(reservations.iter().map(|value| value.range));
    all.extend_from_slice(staging_exclusions);
    all.sort_unstable_by_key(|range| range.offset);
    let mut merged: Vec<ByteRange> = Vec::new();
    for range in all {
        if let Some(last) = merged.last_mut() {
            let last_end = last.end()?;
            if range.offset <= last_end {
                let end = range.end()?.max(last_end);
                last.length = end - last.offset;
                continue;
            }
        }
        if merged.len() >= maximum {
            return Err(LayoutError::FreeRangeLimitExceeded { maximum });
        }
        merged
            .try_reserve(1)
            .map_err(|_| LayoutError::AllocationFailed)?;
        merged.push(range);
    }
    Ok(merged)
}

fn complement(
    volume_bytes: u64,
    occupied: &[ByteRange],
    maximum: usize,
) -> Result<Vec<ByteRange>, LayoutError> {
    let mut free = Vec::new();
    let mut cursor = 0_u64;
    for range in occupied {
        if cursor < range.offset {
            if free.len() >= maximum {
                return Err(LayoutError::FreeRangeLimitExceeded { maximum });
            }
            free.try_reserve(1)
                .map_err(|_| LayoutError::AllocationFailed)?;
            free.push(ByteRange {
                offset: cursor,
                length: range.offset - cursor,
            });
        }
        cursor = range.end()?;
    }
    if cursor < volume_bytes {
        if free.len() >= maximum {
            return Err(LayoutError::FreeRangeLimitExceeded { maximum });
        }
        free.try_reserve(1)
            .map_err(|_| LayoutError::AllocationFailed)?;
        free.push(ByteRange {
            offset: cursor,
            length: volume_bytes - cursor,
        });
    }
    Ok(free)
}

fn allocate_first_fit_aligned_within(
    free: &mut Vec<ByteRange>,
    length: u64,
    alignment: u64,
    domain: ByteRange,
    maximum_ranges: usize,
) -> Result<Option<ByteRange>, LayoutError> {
    let domain_end = domain.end()?;
    for position in 0..free.len() {
        let range = free[position];
        let range_end = range.end()?;
        let candidate_start = range.offset.max(domain.offset);
        let candidate_end = range_end.min(domain_end);
        if candidate_start >= candidate_end {
            continue;
        }
        let aligned_offset = candidate_start
            .checked_add(alignment - 1)
            .ok_or(LayoutError::AccountingOverflow)?
            & !(alignment - 1);
        let destination_end = aligned_offset
            .checked_add(length)
            .ok_or(LayoutError::AccountingOverflow)?;
        if destination_end > candidate_end {
            continue;
        }
        let prefix_length = aligned_offset - range.offset;
        let suffix_length = range_end - destination_end;
        match (prefix_length, suffix_length) {
            (0, 0) => {
                free.remove(position);
            }
            (0, suffix) => {
                free[position] = ByteRange {
                    offset: destination_end,
                    length: suffix,
                };
            }
            (prefix, 0) => {
                free[position].length = prefix;
            }
            (prefix, suffix) => {
                if free.len() >= maximum_ranges {
                    return Err(LayoutError::FreeRangeLimitExceeded {
                        maximum: maximum_ranges,
                    });
                }
                free.try_reserve(1)
                    .map_err(|_| LayoutError::AllocationFailed)?;
                free[position].length = prefix;
                free.insert(
                    position + 1,
                    ByteRange {
                        offset: destination_end,
                        length: suffix,
                    },
                );
            }
        }
        return Ok(Some(ByteRange {
            offset: aligned_offset,
            length,
        }));
    }
    Ok(None)
}

fn free_capacity_within(
    free: &[ByteRange],
    domain: ByteRange,
    alignment: u64,
) -> Result<(u64, u64), LayoutError> {
    let domain_end = domain.end()?;
    let mut largest = 0_u64;
    let mut total = 0_u64;
    for range in free {
        let candidate_start = range.offset.max(domain.offset);
        let start = candidate_start
            .checked_add(alignment - 1)
            .ok_or(LayoutError::AccountingOverflow)?
            & !(alignment - 1);
        let end = range.end()?.min(domain_end);
        if start >= end {
            continue;
        }
        let length = end - start;
        largest = largest.max(length);
        total = total
            .checked_add(length)
            .ok_or(LayoutError::AccountingOverflow)?;
    }
    Ok((largest, total))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extent::Extent;
    use crate::object::{
        NamespaceEntry, ObjectId, ObjectKind, ObjectRecord, ObjectSemantics, ObjectStream,
        StreamFlags, StreamStorage,
    };

    const LIMITS: LayoutLimits = LayoutLimits {
        max_source_extents: 16,
        max_reservations: 16,
        max_free_ranges: 32,
        max_relocations: 16,
    };
    const fn allocation(stream: u64, offset: u64, length: u64, movable: bool) -> SourceAllocation {
        SourceAllocation {
            stream: StreamId(stream),
            logical_offset: 0,
            range: ByteRange { offset, length },
            movable,
        }
    }
    const fn reservation(offset: u64, length: u64) -> DestinationReservation {
        DestinationReservation {
            range: ByteRange { offset, length },
            kind: ReservationKind::AllocationMetadata,
        }
    }

    #[test]
    fn dest_clusters_cover_every_byte_of_an_unaligned_bad_range() {
        assert_eq!(
            clusters_covering_ranges(
                &[ByteRange {
                    offset: 6 * 1024,
                    length: 8 * 1024,
                }],
                4096,
                64 * 1024,
            )
            .unwrap(),
            vec![1, 2, 3]
        );
    }

    fn payload_graph(kind: ExtentKind, offset: u64) -> ObjectGraph {
        let stream = ObjectStream {
            id: StreamId(7),
            name: None,
            logical_bytes: 512,
            initialized_bytes: 512,
            mapped_bytes: 512,
            allocated_bytes: 512,
            flags: StreamFlags::default(),
            storage: StreamStorage::Extents,
        };
        let extents = ExtentGraph::build(
            vec![Extent {
                stream: StreamId(7),
                logical_offset: 0,
                length: 512,
                placement: Placement::Physical {
                    byte_offset: offset,
                },
                kind,
            }],
            8192,
            1,
        )
        .unwrap();
        ObjectGraph::build(
            ObjectId(0),
            vec![
                ObjectRecord {
                    id: ObjectId(0),
                    kind: ObjectKind::Directory,
                    link_count: 0,
                    semantics: ObjectSemantics::default(),
                    streams: Vec::new(),
                },
                ObjectRecord {
                    id: ObjectId(1),
                    kind: ObjectKind::File,
                    link_count: 1,
                    semantics: ObjectSemantics::default(),
                    streams: vec![stream],
                },
            ],
            vec![NamespaceEntry {
                parent: ObjectId(0),
                target: ObjectId(1),
                name: "payload.bin".encode_utf16().collect(),
            }],
            extents,
            ObjectGraphLimits {
                max_objects: 2,
                max_entries: 1,
                max_streams: 1,
                max_name_code_units: 11,
            },
        )
        .unwrap()
    }

    fn relocation_layout(source: u64, destination: u64) -> LayoutPlan {
        LayoutPlan {
            relocations: vec![Relocation {
                stream: StreamId(7),
                logical_offset: 0,
                source: ByteRange {
                    offset: source,
                    length: 512,
                },
                destination: ByteRange {
                    offset: destination,
                    length: 512,
                },
            }],
            materializations: Vec::new(),
            free_after_staging: Vec::new(),
            relocated_bytes: 512,
            materialized_bytes: 0,
            largest_free_range: 0,
        }
    }

    #[test]
    fn keeps_nonconflicting_data_and_relocates_only_conflicts() {
        let plan = solve_layout(
            8192,
            512,
            vec![
                allocation(1, 0, 1024, true),
                allocation(2, 2048, 1024, true),
            ],
            vec![reservation(0, 512)],
            LIMITS,
        )
        .unwrap();
        assert_eq!(plan.relocations.len(), 1);
        assert_eq!(plan.relocations[0].source.offset, 0);
        assert_eq!(plan.relocations[0].destination.offset, 1024);
        assert_eq!(plan.relocated_bytes, 1024);
    }

    #[test]
    fn refuses_immovable_conflicts_and_insufficient_contiguous_space() {
        assert!(matches!(
            solve_layout(
                4096,
                512,
                vec![allocation(1, 0, 512, false)],
                vec![reservation(0, 512)],
                LIMITS
            ),
            Err(LayoutError::ImmovableConflict { .. })
        ));
        let source = vec![
            allocation(1, 0, 1024, true),
            allocation(2, 1536, 512, false),
            allocation(3, 2560, 1536, false),
        ];
        assert!(matches!(
            solve_layout(4096, 512, source, vec![reservation(0, 512)], LIMITS),
            Err(LayoutError::InsufficientStagingSpace {
                required: 1024,
                largest_free_range: 512,
                total_free: 1024
            })
        ));
    }

    #[test]
    fn validates_overlap_alignment_bounds_and_caps() {
        assert!(matches!(
            solve_layout(
                4096,
                512,
                vec![allocation(1, 0, 1024, true), allocation(2, 512, 512, true)],
                vec![],
                LIMITS
            ),
            Err(LayoutError::SourceOverlap { .. })
        ));
        assert!(matches!(
            solve_layout(4096, 512, vec![allocation(1, 1, 512, true)], vec![], LIMITS),
            Err(LayoutError::UnalignedRange { .. })
        ));
        assert!(matches!(
            solve_layout(
                4096,
                512,
                vec![allocation(1, 4096, 512, true)],
                vec![],
                LIMITS
            ),
            Err(LayoutError::RangeOutsideVolume { .. })
        ));
        assert!(matches!(
            solve_layout(4096, 3, vec![], vec![], LIMITS),
            Err(LayoutError::InvalidAlignment { .. })
        ));
    }

    #[test]
    fn result_is_deterministic_for_unsorted_input() {
        let first = solve_layout(
            8192,
            512,
            vec![allocation(2, 2048, 512, true), allocation(1, 0, 512, true)],
            vec![reservation(2048, 512), reservation(0, 512)],
            LIMITS,
        )
        .unwrap();
        let second = solve_layout(
            8192,
            512,
            vec![allocation(1, 0, 512, true), allocation(2, 2048, 512, true)],
            vec![reservation(0, 512), reservation(2048, 512)],
            LIMITS,
        )
        .unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn one_extent_crossing_adjacent_reservations_moves_once() {
        let plan = solve_layout(
            4096,
            512,
            vec![allocation(1, 0, 1024, true)],
            vec![reservation(0, 512), reservation(512, 512)],
            LIMITS,
        )
        .unwrap();
        assert_eq!(plan.relocations.len(), 1);
        assert_eq!(plan.relocations[0].destination.offset, 1024);
    }

    #[test]
    fn retired_metadata_is_not_scratch_but_may_be_replaced() {
        let plan = solve_layout_with_staging_exclusions(
            4096,
            512,
            vec![allocation(1, 0, 512, true)],
            vec![reservation(0, 512), reservation(1024, 512)],
            vec![ByteRange {
                offset: 1024,
                length: 512,
            }],
            LIMITS,
        )
        .unwrap();
        assert_eq!(plan.relocations.len(), 1);
        assert_eq!(plan.relocations[0].destination.offset, 512);
        assert!(
            plan.free_after_staging
                .iter()
                .all(|range| range.offset != 1024)
        );
    }

    #[test]
    fn sector_aligned_reservations_produce_cluster_aligned_relocations() {
        assert!(matches!(
            solve_layout_with_staging_exclusions(
                32 * 1024,
                4096,
                vec![allocation(1, 8192, 4096, true)],
                vec![reservation(0, 512), reservation(8192, 512)],
                Vec::new(),
                LIMITS,
            ),
            Err(LayoutError::UnalignedRange {
                alignment: 4096,
                ..
            })
        ));
        let plan = solve_layout_with_staging_exclusions_and_io_alignment(
            32 * 1024,
            4096,
            512,
            vec![allocation(1, 8192, 4096, true)],
            vec![reservation(0, 512), reservation(8192, 512)],
            Vec::new(),
            LIMITS,
        )
        .unwrap();
        assert_eq!(plan.relocations.len(), 1);
        assert_eq!(plan.relocations[0].destination.offset, 4096);
        assert_eq!(plan.relocations[0].destination.offset % 4096, 0);
        assert!(plan.free_after_staging.contains(&ByteRange {
            offset: 512,
            length: 3584,
        }));
    }

    #[test]
    fn target_domain_forces_valid_source_payload_into_cluster_heap() {
        let plan = solve_layout_with_destination_domain_and_alignments(
            32 * 1024,
            512,
            4096,
            512,
            ByteRange {
                offset: 8192,
                length: 16 * 1024,
            },
            vec![allocation(1, 512, 4096, true)],
            Vec::new(),
            Vec::new(),
            LIMITS,
        )
        .unwrap();

        assert_eq!(plan.relocations.len(), 1);
        assert_eq!(plan.relocations[0].source.offset, 512);
        assert_eq!(plan.relocations[0].destination.offset, 8192);
        assert_eq!(plan.relocations[0].destination.offset % 4096, 0);
        assert!(
            plan.free_after_staging
                .iter()
                .any(|range| range.offset == 0 && range.length == 512)
        );
    }

    #[test]
    fn target_domain_relocates_misaligned_payload_and_honors_exclusions() {
        let plan = solve_layout_with_destination_domain_and_alignments(
            32 * 1024,
            512,
            4096,
            512,
            ByteRange {
                offset: 8192,
                length: 16 * 1024,
            },
            vec![allocation(1, 8704, 4096, true)],
            Vec::new(),
            vec![ByteRange {
                offset: 16 * 1024,
                length: 4096,
            }],
            LIMITS,
        )
        .unwrap();

        assert_eq!(plan.relocations[0].destination.offset, 20 * 1024);
        assert!(plan.relocations[0].destination.offset >= 8192);
        assert!(plan.relocations[0].destination.end().unwrap() <= 24 * 1024);
    }

    #[test]
    fn full_volume_domain_preserves_legacy_solver_result() {
        let source = vec![allocation(1, 8192, 4096, true)];
        let reservations = vec![reservation(8192, 512)];
        let legacy = solve_layout_with_staging_exclusions_and_io_alignment(
            32 * 1024,
            4096,
            512,
            source.clone(),
            reservations.clone(),
            Vec::new(),
            LIMITS,
        )
        .unwrap();
        let domain = solve_layout_with_destination_domain_and_alignments(
            32 * 1024,
            4096,
            4096,
            512,
            ByteRange {
                offset: 0,
                length: 32 * 1024,
            },
            source,
            reservations,
            Vec::new(),
            LIMITS,
        )
        .unwrap();

        assert_eq!(legacy, domain);
    }

    #[test]
    fn legacy_solver_accepts_sector_aligned_volume_with_partial_cluster_tail() {
        let plan = solve_layout_with_staging_exclusions_and_io_alignment(
            10_240,
            4096,
            512,
            vec![allocation(1, 0, 4096, true)],
            vec![reservation(0, 512)],
            Vec::new(),
            LIMITS,
        )
        .unwrap();

        assert_eq!(plan.relocations.len(), 1);
        assert_eq!(plan.relocations[0].destination.offset, 4096);
        assert!(
            plan.free_after_staging
                .iter()
                .any(|range| { range.offset == 8192 && range.length == 2048 })
        );
    }

    #[test]
    fn destination_domain_exact_fit_succeeds_but_one_cluster_short_refuses() {
        let exact = solve_layout_with_destination_domain_and_alignments(
            32 * 1024,
            512,
            4096,
            512,
            ByteRange {
                offset: 8192,
                length: 8192,
            },
            vec![allocation(1, 0, 8192, true)],
            Vec::new(),
            Vec::new(),
            LIMITS,
        )
        .unwrap();
        assert_eq!(exact.relocations[0].destination.offset, 8192);

        assert!(matches!(
            solve_layout_with_destination_domain_and_alignments(
                32 * 1024,
                512,
                4096,
                512,
                ByteRange {
                    offset: 8192,
                    length: 4096,
                },
                vec![allocation(1, 0, 8192, true)],
                Vec::new(),
                Vec::new(),
                LIMITS,
            ),
            Err(LayoutError::InsufficientStagingSpace {
                required: 8192,
                largest_free_range: 4096,
                total_free: 4096,
            })
        ));
    }

    #[test]
    fn target_domain_refuses_immovable_or_unrepresentable_payload() {
        assert!(matches!(
            solve_layout_with_destination_domain_and_alignments(
                32 * 1024,
                512,
                4096,
                512,
                ByteRange {
                    offset: 8192,
                    length: 16 * 1024,
                },
                vec![allocation(1, 512, 4096, false)],
                Vec::new(),
                Vec::new(),
                LIMITS,
            ),
            Err(LayoutError::ImmovableOutsideDestinationDomain { .. })
        ));
        assert!(matches!(
            solve_layout_with_destination_domain_and_alignments(
                32 * 1024,
                512,
                4096,
                512,
                ByteRange {
                    offset: 8192,
                    length: 16 * 1024,
                },
                vec![allocation(1, 8192, 512, true)],
                Vec::new(),
                Vec::new(),
                LIMITS,
            ),
            Err(LayoutError::DestinationLengthUnaligned { .. })
        ));
        assert!(matches!(
            solve_layout_with_destination_domain_and_alignments(
                32 * 1024,
                512,
                512,
                4096,
                ByteRange {
                    offset: 8192,
                    length: 16 * 1024,
                },
                Vec::new(),
                Vec::new(),
                Vec::new(),
                LIMITS,
            ),
            Err(LayoutError::IncompatibleAlignments {
                io_alignment: 4096,
                destination_alignment: 512
            })
        ));
        assert!(matches!(
            solve_layout_with_destination_domain_and_alignments(
                32 * 1024,
                512,
                4096,
                512,
                ByteRange {
                    offset: 512,
                    length: 16 * 1024,
                },
                Vec::new(),
                Vec::new(),
                Vec::new(),
                LIMITS,
            ),
            Err(LayoutError::UnalignedRange {
                offset: 512,
                alignment: 4096,
                ..
            })
        ));
    }

    #[test]
    fn retired_metadata_must_be_disjoint_from_live_sources() {
        assert!(matches!(
            solve_layout_with_staging_exclusions(
                4096,
                512,
                vec![allocation(1, 1024, 512, true)],
                vec![],
                vec![ByteRange {
                    offset: 1024,
                    length: 512,
                }],
                LIMITS,
            ),
            Err(LayoutError::StagingExclusionOverlapsSource { .. })
        ));
    }

    #[test]
    fn relocates_exact_file_payload_extent_without_changing_semantics() {
        let source = payload_graph(ExtentKind::FileData, 4096);
        let target = relocate_object_graph(&source, &relocation_layout(4096, 6144)).unwrap();

        assert_eq!(target.root(), source.root());
        assert_eq!(target.objects(), source.objects());
        assert_eq!(target.entries(), source.entries());
        assert_eq!(target.features(), source.features());
        assert_eq!(
            target.extents().extents()[0].placement,
            Placement::Physical { byte_offset: 6144 }
        );
        assert_eq!(
            source.extents().extents()[0].placement,
            Placement::Physical { byte_offset: 4096 }
        );
    }

    #[test]
    fn relocated_graph_refuses_missing_duplicate_nonpayload_and_overlap() {
        let source = payload_graph(ExtentKind::FileData, 4096);
        assert!(matches!(
            relocate_object_graph(&source, &relocation_layout(3584, 6144)),
            Err(RelocatedGraphError::RelocationSourceMissing { .. })
        ));

        let mut duplicate = relocation_layout(4096, 6144);
        duplicate.relocations.push(Relocation {
            destination: ByteRange {
                offset: 6656,
                length: 512,
            },
            ..duplicate.relocations[0]
        });
        duplicate.relocated_bytes = 1024;
        assert!(matches!(
            relocate_object_graph(&source, &duplicate),
            Err(RelocatedGraphError::DuplicateRelocationSource { .. })
        ));

        let metadata = payload_graph(ExtentKind::DirectoryData, 4096);
        assert!(matches!(
            relocate_object_graph(&metadata, &relocation_layout(4096, 6144)),
            Err(RelocatedGraphError::NonPayloadRelocation { .. })
        ));

        let extents = ExtentGraph::build(
            vec![
                source.extents().extents()[0],
                Extent {
                    stream: StreamId(8),
                    logical_offset: 0,
                    length: 512,
                    placement: Placement::Physical { byte_offset: 6144 },
                    kind: ExtentKind::FileData,
                },
            ],
            8192,
            2,
        )
        .unwrap();
        let second_stream = ObjectStream {
            id: StreamId(8),
            name: Some("second".encode_utf16().collect()),
            logical_bytes: 512,
            initialized_bytes: 512,
            mapped_bytes: 512,
            allocated_bytes: 512,
            flags: StreamFlags::default(),
            storage: StreamStorage::Extents,
        };
        let mut objects = source.objects().to_vec();
        objects[1].streams.push(second_stream);
        let overlap = ObjectGraph::build(
            source.root(),
            objects,
            source.entries().to_vec(),
            extents,
            ObjectGraphLimits {
                max_objects: 2,
                max_entries: 1,
                max_streams: 2,
                max_name_code_units: 11,
            },
        )
        .unwrap();
        assert!(matches!(
            relocate_object_graph(&overlap, &relocation_layout(4096, 6144)),
            Err(RelocatedGraphError::Extents(
                ExtentGraphError::PhysicalOverlap { .. }
            ))
        ));
    }

    fn resident_payload_graph() -> ObjectGraph {
        let stream = ObjectStream {
            id: StreamId(7),
            name: None,
            logical_bytes: 3,
            initialized_bytes: 3,
            mapped_bytes: 3,
            allocated_bytes: 0,
            flags: StreamFlags::default(),
            storage: StreamStorage::Resident(b"abc".to_vec()),
        };
        ObjectGraph::build(
            ObjectId(0),
            vec![
                ObjectRecord {
                    id: ObjectId(0),
                    kind: ObjectKind::Directory,
                    link_count: 0,
                    semantics: ObjectSemantics::default(),
                    streams: Vec::new(),
                },
                ObjectRecord {
                    id: ObjectId(1),
                    kind: ObjectKind::File,
                    link_count: 1,
                    semantics: ObjectSemantics::default(),
                    streams: vec![stream],
                },
            ],
            vec![NamespaceEntry {
                parent: ObjectId(0),
                target: ObjectId(1),
                name: "payload.bin".encode_utf16().collect(),
            }],
            ExtentGraph::build(Vec::new(), 32 * 1024, 1).unwrap(),
            ObjectGraphLimits {
                max_objects: 2,
                max_entries: 1,
                max_streams: 1,
                max_name_code_units: 11,
            },
        )
        .unwrap()
    }

    fn aligned_file_extent_graph(
        logical: u64,
        initialized: u64,
        extent_length: u64,
    ) -> ObjectGraph {
        let stream = ObjectStream {
            id: StreamId(7),
            name: None,
            logical_bytes: logical,
            initialized_bytes: initialized,
            mapped_bytes: extent_length,
            allocated_bytes: extent_length,
            flags: StreamFlags::default(),
            storage: StreamStorage::Extents,
        };
        ObjectGraph::build(
            ObjectId(0),
            vec![
                ObjectRecord {
                    id: ObjectId(0),
                    kind: ObjectKind::Directory,
                    link_count: 0,
                    semantics: ObjectSemantics::default(),
                    streams: Vec::new(),
                },
                ObjectRecord {
                    id: ObjectId(1),
                    kind: ObjectKind::File,
                    link_count: 1,
                    semantics: ObjectSemantics::default(),
                    streams: vec![stream],
                },
            ],
            vec![NamespaceEntry {
                parent: ObjectId(0),
                target: ObjectId(1),
                name: "payload.bin".encode_utf16().collect(),
            }],
            ExtentGraph::build(
                vec![Extent {
                    stream: StreamId(7),
                    logical_offset: 0,
                    length: extent_length,
                    placement: Placement::Physical { byte_offset: 8192 },
                    kind: ExtentKind::FileData,
                }],
                32 * 1024,
                1,
            )
            .unwrap(),
            ObjectGraphLimits {
                max_objects: 2,
                max_entries: 1,
                max_streams: 1,
                max_name_code_units: 11,
            },
        )
        .unwrap()
    }

    #[test]
    fn materializes_unaligned_request_into_destination_aligned_heap() {
        let plan = solve_layout_with_destination_domain_alignments_and_materializations(
            32 * 1024,
            512,
            4096,
            512,
            ByteRange {
                offset: 8192,
                length: 16 * 1024,
            },
            Vec::new(),
            Vec::new(),
            vec![ByteRange {
                offset: 0,
                length: 4096,
            }],
            &[MaterializationRequest {
                stream: StreamId(7),
                destination_length: 4096,
            }],
            LIMITS,
        )
        .unwrap();

        assert!(plan.relocations.is_empty());
        assert_eq!(plan.materializations.len(), 1);
        assert_eq!(plan.materializations[0].stream, StreamId(7));
        assert_eq!(plan.materializations[0].destination.offset, 8192);
        assert_eq!(plan.materializations[0].destination.length, 4096);
        assert_eq!(plan.materialized_bytes, 4096);
        assert_eq!(
            materialization_length_for_stream(&resident_payload_graph(), StreamId(7), 4096),
            Some(4096)
        );
    }

    #[test]
    fn dest_aligned_extents_materialize_when_initialized_bytes_leave_slack() {
        let slack = aligned_file_extent_graph(8192, 5000, 8192);
        assert_eq!(
            materialization_length_for_stream(&slack, StreamId(7), 8192),
            Some(8192)
        );
        let filled = aligned_file_extent_graph(8192, 8192, 8192);
        assert_eq!(
            materialization_length_for_stream(&filled, StreamId(7), 8192),
            None
        );
    }

    #[test]
    fn sparse_file_data_requires_whole_stream_materialization() {
        let stream = ObjectStream {
            id: StreamId(7),
            name: None,
            logical_bytes: 8192,
            initialized_bytes: 8192,
            mapped_bytes: 8192,
            allocated_bytes: 4096,
            flags: StreamFlags {
                sparse: true,
                compressed: false,
                encrypted: false,
                compression_block_bytes: 0,
            },
            storage: StreamStorage::Extents,
        };
        let graph = ObjectGraph::build(
            ObjectId(0),
            vec![
                ObjectRecord {
                    id: ObjectId(0),
                    kind: ObjectKind::Directory,
                    link_count: 0,
                    semantics: ObjectSemantics::default(),
                    streams: Vec::new(),
                },
                ObjectRecord {
                    id: ObjectId(1),
                    kind: ObjectKind::File,
                    link_count: 1,
                    semantics: ObjectSemantics::default(),
                    streams: vec![stream],
                },
            ],
            vec![NamespaceEntry {
                parent: ObjectId(0),
                target: ObjectId(1),
                name: "payload.bin".encode_utf16().collect(),
            }],
            ExtentGraph::build(
                vec![
                    Extent {
                        stream: StreamId(7),
                        logical_offset: 0,
                        length: 4096,
                        placement: Placement::Physical { byte_offset: 8192 },
                        kind: ExtentKind::FileData,
                    },
                    Extent {
                        stream: StreamId(7),
                        logical_offset: 4096,
                        length: 4096,
                        placement: Placement::Sparse,
                        kind: ExtentKind::FileData,
                    },
                ],
                32 * 1024,
                2,
            )
            .unwrap(),
            ObjectGraphLimits {
                max_objects: 2,
                max_entries: 1,
                max_streams: 1,
                max_name_code_units: 11,
            },
        )
        .unwrap();
        assert_eq!(
            materialization_length_for_stream(&graph, StreamId(7), 4096),
            Some(8192)
        );
    }

    #[test]
    fn compressed_stream_requires_materialization_even_when_physical() {
        let stream = ObjectStream {
            id: StreamId(7),
            name: None,
            logical_bytes: 8192,
            initialized_bytes: 8192,
            mapped_bytes: 8192,
            allocated_bytes: 8192,
            flags: StreamFlags {
                compression_block_bytes: 8192,
                ..StreamFlags::default()
            },
            storage: StreamStorage::Extents,
        };
        let graph = ObjectGraph::build(
            ObjectId(0),
            vec![
                ObjectRecord {
                    id: ObjectId(0),
                    kind: ObjectKind::Directory,
                    link_count: 0,
                    semantics: ObjectSemantics::default(),
                    streams: Vec::new(),
                },
                ObjectRecord {
                    id: ObjectId(1),
                    kind: ObjectKind::File,
                    link_count: 1,
                    semantics: ObjectSemantics::default(),
                    streams: vec![stream],
                },
            ],
            vec![NamespaceEntry {
                parent: ObjectId(0),
                target: ObjectId(1),
                name: "packed.bin".encode_utf16().collect(),
            }],
            ExtentGraph::build(
                vec![Extent {
                    stream: StreamId(7),
                    logical_offset: 0,
                    length: 8192,
                    placement: Placement::Physical { byte_offset: 8192 },
                    kind: ExtentKind::FileData,
                }],
                32 * 1024,
                1,
            )
            .unwrap(),
            ObjectGraphLimits {
                max_objects: 2,
                max_entries: 1,
                max_streams: 1,
                max_name_code_units: 11,
            },
        )
        .unwrap();
        assert_eq!(
            materialization_length_for_stream(&graph, StreamId(7), 4096),
            Some(8192)
        );
    }

    #[test]
    fn seal_converts_resident_stream_into_destination_extents() {
        let source = resident_payload_graph();
        let layout = LayoutPlan {
            relocations: Vec::new(),
            materializations: vec![Materialization {
                stream: StreamId(7),
                destination: ByteRange {
                    offset: 8192,
                    length: 4096,
                },
            }],
            free_after_staging: Vec::new(),
            relocated_bytes: 0,
            materialized_bytes: 4096,
            largest_free_range: 0,
        };
        let sealed = SealedRelocationPlan::seal(source, layout).unwrap();
        let stream = &sealed.target_graph().objects()[1].streams[0];
        assert!(matches!(stream.storage, StreamStorage::Extents));
        assert_eq!(stream.logical_bytes, 3);
        assert_eq!(stream.mapped_bytes, 4096);
        assert_eq!(stream.allocated_bytes, 4096);
        assert_eq!(
            sealed.target_graph().extents().extents(),
            [Extent {
                stream: StreamId(7),
                logical_offset: 0,
                length: 4096,
                placement: Placement::Physical { byte_offset: 8192 },
                kind: ExtentKind::FileData,
            }]
        );
        assert_eq!(
            sealed.source_graph().objects()[1].streams[0].storage,
            StreamStorage::Resident(b"abc".to_vec())
        );
    }

    #[test]
    fn materialization_refuses_live_source_conflict_and_unaligned_length() {
        assert!(matches!(
            solve_layout_with_destination_domain_alignments_and_materializations(
                32 * 1024,
                512,
                4096,
                512,
                ByteRange {
                    offset: 8192,
                    length: 16 * 1024,
                },
                vec![allocation(7, 512, 4096, true)],
                Vec::new(),
                Vec::new(),
                &[MaterializationRequest {
                    stream: StreamId(7),
                    destination_length: 4096,
                }],
                LIMITS,
            ),
            Err(LayoutError::MaterializationConflictsWithLiveSource { .. })
        ));
        assert!(matches!(
            solve_layout_with_destination_domain_alignments_and_materializations(
                32 * 1024,
                512,
                4096,
                512,
                ByteRange {
                    offset: 8192,
                    length: 16 * 1024,
                },
                Vec::new(),
                Vec::new(),
                Vec::new(),
                &[MaterializationRequest {
                    stream: StreamId(7),
                    destination_length: 512,
                }],
                LIMITS,
            ),
            Err(LayoutError::DestinationLengthUnaligned { .. })
        ));
    }
}
