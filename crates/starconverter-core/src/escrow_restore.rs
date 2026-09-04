//! Restore source-only NTFS identities from a versioned escrow sidecar.
//!
//! Extra non-DOS `$FILE_NAME` hard links, resident named `$DATA` streams, captured non-resident
//! named `$DATA` payloads, carrier-backed named `$DATA` payloads (see [`crate::escrow_carrier`]),
//! and resident `$REPARSE_POINT` payloads are reattached onto a dest-native graph. Dest objects
//! are matched by dest-native path so remapped inventories (exFAT `ObjectId`s) still restore.
//! Carrier files and their escrow directory are removed from the restored graph once every
//! carrier has been folded back into its owner. Encrypted named streams, and nonempty named
//! streams with neither a captured payload nor a matching carrier, fail closed.

#![allow(clippy::module_name_repetitions)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::FileSystem;
use crate::candidate_export::decode_bound_escrow;
use crate::cross_format::{
    NtfsToExfatError, disambiguate_exfat_case_collisions, select_dest_native_namespace_entry,
};
use crate::escrow_carrier::{
    EscrowCarrier, carrier_directory_name, needs_carrier, sidecar_carriers,
};
use crate::extent::StreamId;
use crate::fs::ntfs_index::FileNameNamespace;
use crate::fs::ntfs_inventory::{NtfsFileName, NtfsObject, NtfsStreamStorage};
use crate::fs::ntfs_normalize::NtfsPreservationSidecar;
use crate::object::{
    NamespaceEntry, ObjectGraph, ObjectGraphError, ObjectGraphLimits, ObjectId, ObjectKind,
    ObjectRecord, ObjectStream, StreamFlags, StreamStorage,
};
use crate::preservation::{PreservationError, PreservationLimits, decode_ntfs_sidecar_from_escrow};

/// Failure to restore escrowed NTFS identities onto a dest-native graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NtfsRestoreError {
    MissingDestinationObject(ObjectId),
    KindMismatch(ObjectId),
    NamedStreamOnDirectory(ObjectId),
    EncryptedNamedStream {
        object: ObjectId,
        name: Vec<u16>,
    },
    CompressedNamedStream {
        object: ObjectId,
        name: Vec<u16>,
    },
    UnrestorableNamedStream {
        object: ObjectId,
        name: Vec<u16>,
        data_bytes: u64,
    },
    /// The dest-native carrier file for a named stream exists but is not a plain file with one
    /// unnamed stream of exactly the escrowed length.
    EscrowCarrierMismatch {
        owner: ObjectId,
        name: Vec<u16>,
        data_bytes: u64,
    },
    /// The escrow carrier directory still holds entries after every carrier was folded back.
    EscrowDirectoryNotEmpty(ObjectId),
    DuplicateStreamId(StreamId),
    StreamIdOverflow {
        record: u64,
        attribute_id: u16,
    },
    MissingDestinationPath(Vec<Vec<u16>>),
    DuplicateDestinationPath,
    AmbiguousDestinationNames(ObjectId),
    MissingDestNativeName(ObjectId),
    IncompleteReparse(ObjectId),
    NameDisambiguationFailed {
        parent: ObjectId,
    },
    Graph(ObjectGraphError),
    AllocationFailed,
    ArithmeticOverflow,
    /// The candidate-bound escrow envelope is malformed, oversized, or checksum-invalid.
    EscrowEnvelope(String),
    /// The escrow was not produced by an NTFS→exFAT export.
    EscrowDirectionMismatch {
        source: FileSystem,
        target: FileSystem,
    },
    /// The exFAT image being restored from is not the exact candidate the escrow was bound to.
    CandidateBindingMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    /// The embedded schema-v4 preservation payload could not be decoded as an NTFS snapshot.
    EscrowPayload(PreservationError),
}

/// Dest-native graph plus resident `$REPARSE_POINT` bytes keyed by dest [`ObjectId`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoredNtfsIdentities {
    pub graph: ObjectGraph,
    pub reparse_points: BTreeMap<ObjectId, Vec<u8>>,
    /// Dest [`ObjectId`] → sidecar [`ObjectId`] (source MFT record number) for every dest object
    /// that the sidecar identified by dest-native path, including the root.
    pub source_by_dest: BTreeMap<ObjectId, ObjectId>,
    /// Dest objects (escrow carrier files and their directory) consumed by the restore and absent
    /// from `graph`.
    pub removed_objects: BTreeSet<ObjectId>,
}

/// Dest-native carrier stream ready to be reattached as a named stream.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CarrierPayload {
    dest_object: ObjectId,
    stream: ObjectStream,
}

impl fmt::Display for NtfsRestoreError {
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingDestinationObject(object) => {
                write!(
                    formatter,
                    "escrow object {} is absent from the dest-native graph",
                    object.0
                )
            }
            Self::KindMismatch(object) => {
                write!(
                    formatter,
                    "escrow object {} kind does not match the dest-native graph",
                    object.0
                )
            }
            Self::NamedStreamOnDirectory(object) => {
                write!(
                    formatter,
                    "escrow directory {} carries a named stream the destination serializer cannot emit",
                    object.0
                )
            }
            Self::EncryptedNamedStream { object, .. } => {
                write!(
                    formatter,
                    "escrow object {} has an encrypted named stream that cannot be rematerialized",
                    object.0
                )
            }
            Self::CompressedNamedStream { object, .. } => {
                write!(
                    formatter,
                    "escrow object {} has a compressed named stream that cannot be rematerialized",
                    object.0
                )
            }
            Self::UnrestorableNamedStream {
                object, data_bytes, ..
            } => write!(
                formatter,
                "escrow object {} has a {data_bytes}-byte non-resident named stream whose payload is not on the dest-native graph",
                object.0
            ),
            Self::EscrowCarrierMismatch {
                owner, data_bytes, ..
            } => write!(
                formatter,
                "the escrow carrier for object {}'s {data_bytes}-byte named stream is not a plain file of that length",
                owner.0
            ),
            Self::EscrowDirectoryNotEmpty(directory) => write!(
                formatter,
                "escrow carrier directory {} still holds entries that are not escrow carriers",
                directory.0
            ),
            Self::DuplicateStreamId(stream) => {
                write!(
                    formatter,
                    "restored stream {} collides with a dest-native stream",
                    stream.0
                )
            }
            Self::MissingDestinationPath(path) => {
                write!(
                    formatter,
                    "escrow dest-native path {path:?} is absent from the dest graph"
                )
            }
            Self::DuplicateDestinationPath => formatter.write_str(
                "two escrow objects share one dest-native path or two dest objects share one path",
            ),
            Self::AmbiguousDestinationNames(object) => write!(
                formatter,
                "object {} does not have exactly one dest-native name",
                object.0
            ),
            Self::MissingDestNativeName(object) => write!(
                formatter,
                "escrow object {} has no dest-native $FILE_NAME",
                object.0
            ),
            Self::IncompleteReparse(object) => write!(
                formatter,
                "escrow object {} is a reparse point without resident $REPARSE_POINT bytes",
                object.0
            ),
            Self::NameDisambiguationFailed { parent } => write!(
                formatter,
                "could not reconstruct dest-native names under parent {}",
                parent.0
            ),
            Self::StreamIdOverflow {
                record,
                attribute_id,
            } => write!(
                formatter,
                "NTFS record {record} attribute {attribute_id} overflows the dest stream identity"
            ),
            Self::Graph(error) => write!(formatter, "{error}"),
            Self::AllocationFailed => {
                formatter.write_str("NTFS identity restore allocation failed")
            }
            Self::ArithmeticOverflow => {
                formatter.write_str("NTFS identity restore accounting overflowed")
            }
            Self::EscrowEnvelope(error) => write!(formatter, "escrow envelope rejected: {error}"),
            Self::EscrowDirectionMismatch { source, target } => write!(
                formatter,
                "escrow records a {source}→{target} export; NTFS identity restore needs an NTFS→exFAT escrow"
            ),
            Self::CandidateBindingMismatch { .. } => formatter.write_str(
                "the exFAT image is not the exact candidate this escrow was bound to (SHA-256 mismatch)",
            ),
            Self::EscrowPayload(error) => {
                write!(formatter, "escrow preservation payload rejected: {error}")
            }
        }
    }
}

impl std::error::Error for NtfsRestoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Graph(error) => Some(error),
            Self::EscrowPayload(error) => Some(error),
            _ => None,
        }
    }
}

/// Decodes a candidate-bound escrow sidecar so its NTFS identities can be restored onto the exact
/// exFAT candidate it was produced with.
///
/// The envelope must record an NTFS→exFAT export and its candidate SHA-256 must equal
/// `exfat_image_sha256`, the whole-image hash of the exFAT image about to be converted back. Any
/// later edit to that exFAT image therefore fails closed instead of reattaching stale identities.
///
/// # Errors
///
/// Returns an error for a malformed or oversized envelope, a non-NTFS→exFAT export, a candidate
/// hash mismatch, or an undecodable NTFS preservation payload.
pub fn decode_restore_sidecar(
    escrow_bytes: &[u8],
    exfat_image_sha256: [u8; 32],
    max_escrow_payload_bytes: usize,
    limits: PreservationLimits,
) -> Result<NtfsPreservationSidecar, NtfsRestoreError> {
    let envelope = decode_bound_escrow(escrow_bytes, max_escrow_payload_bytes)
        .map_err(|error| NtfsRestoreError::EscrowEnvelope(error.to_string()))?;
    if envelope.source_filesystem != FileSystem::Ntfs
        || envelope.target_filesystem != FileSystem::ExFat
    {
        return Err(NtfsRestoreError::EscrowDirectionMismatch {
            source: envelope.source_filesystem,
            target: envelope.target_filesystem,
        });
    }
    if envelope.candidate_sha256 != exfat_image_sha256 {
        return Err(NtfsRestoreError::CandidateBindingMismatch {
            expected: envelope.candidate_sha256,
            actual: exfat_image_sha256,
        });
    }
    decode_ntfs_sidecar_from_escrow(&envelope.preservation_payload, limits)
        .map_err(NtfsRestoreError::EscrowPayload)
}

/// Reattaches extra hard links and resident named streams from `sidecar` onto `dest_native`.
///
/// Dest-native unnamed payloads and the already-selected dest-native name are left in place.
/// DOS 8.3 companions stay aliases and do not become dest-native hard links. Dest objects are
/// matched by dest-native path, not raw [`ObjectId`].
///
/// # Errors
///
/// Fails closed when a restorable sidecar object has no dest-native path, kinds disagree, a named
/// stream is encrypted or a nonempty non-resident payload without a captured copy or a matching
/// dest-native carrier, a carrier is not a plain file of the escrowed length, the escrow carrier
/// directory keeps foreign entries, a directory carries a reparse point, or the rebuilt graph is
/// invalid.
pub fn restore_ntfs_identities(
    dest_native: &ObjectGraph,
    sidecar: &NtfsPreservationSidecar,
) -> Result<ObjectGraph, NtfsRestoreError> {
    Ok(restore_ntfs_identities_with_evidence(dest_native, sidecar)?.graph)
}

/// Same as [`restore_ntfs_identities`], plus dest-keyed resident `$REPARSE_POINT` bytes.
///
/// # Errors
///
/// Returns the same refusals as [`restore_ntfs_identities`].
pub fn restore_ntfs_identities_with_evidence(
    dest_native: &ObjectGraph,
    sidecar: &NtfsPreservationSidecar,
) -> Result<RestoredNtfsIdentities, NtfsRestoreError> {
    let sidecar_by_id: BTreeMap<ObjectId, &NtfsObject> = sidecar
        .objects
        .iter()
        .map(|preserved| (preserved.object, &preserved.source))
        .collect();
    let (id_map, dest_by_path) = match_sidecar_to_dest(dest_native, sidecar)?;
    let dest_to_sidecar: BTreeMap<ObjectId, ObjectId> = id_map
        .iter()
        .map(|(sidecar_id, dest_id)| (*dest_id, *sidecar_id))
        .collect();
    let carriers = locate_escrow_carriers(dest_native, sidecar, &dest_by_path)?;

    let mut objects = dest_native.objects().to_vec();
    let mut entries = dest_native.entries().to_vec();
    let mut used_streams = BTreeSet::new();
    let mut reparse_points = BTreeMap::new();
    for object in &objects {
        for stream in &object.streams {
            used_streams.insert(stream.id);
        }
    }

    for object in &mut objects {
        let Some(sidecar_id) = dest_to_sidecar.get(&object.id).copied() else {
            continue;
        };
        if sidecar_id == ObjectId(sidecar.root_reference.record_number) {
            continue;
        }
        let Some(source) = sidecar_by_id.get(&sidecar_id).copied() else {
            continue;
        };
        if skip_sidecar_object(source) {
            continue;
        }
        let expected = if source.is_directory {
            ObjectKind::Directory
        } else {
            ObjectKind::File
        };
        if object.kind != expected {
            return Err(NtfsRestoreError::KindMismatch(object.id));
        }
        restore_namespace_entries(object.id, source, &mut entries, &id_map)?;
        restore_named_streams(object, source, &mut used_streams, &carriers)?;
        restore_reparse_point(object, source, &mut reparse_points)?;
    }
    let removed_objects = remove_escrow_carriers(
        dest_native.root(),
        &carriers,
        &dest_by_path,
        &mut objects,
        &mut entries,
    )?;

    let root = dest_native.root();
    for object in &mut objects {
        object.link_count = if object.id == root {
            0
        } else {
            u32::try_from(
                entries
                    .iter()
                    .filter(|entry| entry.target == object.id)
                    .count(),
            )
            .map_err(|_| NtfsRestoreError::ArithmeticOverflow)?
        };
    }

    let max_name_code_units = restored_name_limit(&entries, &objects);
    let max_streams = objects
        .iter()
        .map(|object| object.streams.len())
        .sum::<usize>()
        .max(1);
    let graph = ObjectGraph::build(
        root,
        objects,
        entries,
        dest_native.extents().clone(),
        ObjectGraphLimits {
            max_objects: dest_native.objects().len().max(1),
            max_entries: dest_native
                .entries()
                .len()
                .saturating_add(sidecar_name_budget(sidecar))
                .max(1),
            max_streams,
            max_name_code_units,
        },
    )
    .map_err(NtfsRestoreError::Graph)?;
    Ok(RestoredNtfsIdentities {
        graph,
        reparse_points,
        source_by_dest: dest_to_sidecar,
        removed_objects,
    })
}

/// Resolves every sidecar-implied carrier to its dest-native file and validates its shape.
///
/// Returns `(sidecar owner, attribute id) → carrier payload`. A carrier the sidecar implies but
/// the dest graph lacks is reported by [`restore_named_streams`] as an unrestorable named stream,
/// so this function only refuses carriers that exist with the wrong shape.
fn locate_escrow_carriers(
    dest_native: &ObjectGraph,
    sidecar: &NtfsPreservationSidecar,
    dest_by_path: &BTreeMap<Vec<Vec<u16>>, ObjectId>,
) -> Result<BTreeMap<(ObjectId, u16), CarrierPayload>, NtfsRestoreError> {
    let mut carriers = BTreeMap::new();
    for carrier in sidecar_carriers(sidecar) {
        let Some(dest_object) = dest_by_path.get(&carrier.path()).copied() else {
            continue;
        };
        let object = dest_native
            .objects()
            .iter()
            .find(|object| object.id == dest_object)
            .ok_or(NtfsRestoreError::MissingDestinationObject(dest_object))?;
        let stream = carrier_stream(object, &carrier)?;
        if carriers
            .insert(
                (carrier.owner, carrier.attribute_id),
                CarrierPayload {
                    dest_object,
                    stream,
                },
            )
            .is_some()
        {
            return Err(NtfsRestoreError::DuplicateDestinationPath);
        }
    }
    Ok(carriers)
}

fn carrier_stream(
    object: &ObjectRecord,
    carrier: &EscrowCarrier,
) -> Result<ObjectStream, NtfsRestoreError> {
    let mismatch = || NtfsRestoreError::EscrowCarrierMismatch {
        owner: carrier.owner,
        name: carrier.stream_name.clone(),
        data_bytes: carrier.data_bytes,
    };
    if object.kind != ObjectKind::File || object.streams.len() != 1 {
        return Err(mismatch());
    }
    let stream = &object.streams[0];
    if stream.name.is_some() || stream.logical_bytes != carrier.data_bytes {
        return Err(mismatch());
    }
    Ok(stream.clone())
}

/// Drops consumed carrier files and the escrow directory from the restored graph.
fn remove_escrow_carriers(
    root: ObjectId,
    carriers: &BTreeMap<(ObjectId, u16), CarrierPayload>,
    dest_by_path: &BTreeMap<Vec<Vec<u16>>, ObjectId>,
    objects: &mut Vec<ObjectRecord>,
    entries: &mut Vec<NamespaceEntry>,
) -> Result<BTreeSet<ObjectId>, NtfsRestoreError> {
    let mut removed: BTreeSet<ObjectId> = carriers
        .values()
        .map(|carrier| carrier.dest_object)
        .collect();
    if removed.is_empty() {
        return Ok(removed);
    }
    let directory = dest_by_path
        .get(&vec![carrier_directory_name()])
        .copied()
        .ok_or_else(|| NtfsRestoreError::MissingDestinationPath(vec![carrier_directory_name()]))?;
    if directory == root {
        return Err(NtfsRestoreError::EscrowDirectoryNotEmpty(directory));
    }
    entries.retain(|entry| !removed.contains(&entry.target));
    if entries.iter().any(|entry| entry.parent == directory) {
        return Err(NtfsRestoreError::EscrowDirectoryNotEmpty(directory));
    }
    removed.insert(directory);
    entries.retain(|entry| entry.target != directory);
    objects.retain(|object| !removed.contains(&object.id));
    Ok(removed)
}

const NTFS_ROOT_RECORD: u64 = 5;
const NTFS_EXTEND_RECORD: u64 = 11;

/// Same membership as NTFS normalization: root plus non-metadata objects except `$Extend`.
const fn is_graph_record(record_number: u64, is_metadata: bool) -> bool {
    record_number == NTFS_ROOT_RECORD || (!is_metadata && record_number != NTFS_EXTEND_RECORD)
}

const fn skip_sidecar_object(source: &NtfsObject) -> bool {
    !is_graph_record(source.reference.record_number, source.is_metadata)
        || source.reference.record_number == NTFS_ROOT_RECORD
}

type DestByPath = BTreeMap<Vec<Vec<u16>>, ObjectId>;

fn match_sidecar_to_dest(
    dest_native: &ObjectGraph,
    sidecar: &NtfsPreservationSidecar,
) -> Result<(BTreeMap<ObjectId, ObjectId>, DestByPath), NtfsRestoreError> {
    let reconstructed = reconstruct_dest_native_entries(sidecar)?;
    let sidecar_root = ObjectId(sidecar.root_reference.record_number);
    let mut dest_by_path = BTreeMap::new();
    for object in dest_native.objects() {
        if object.id == dest_native.root() {
            continue;
        }
        let path = path_from_entries(dest_native.entries(), dest_native.root(), object.id)?;
        if dest_by_path.insert(path, object.id).is_some() {
            return Err(NtfsRestoreError::DuplicateDestinationPath);
        }
    }
    let mut id_map = BTreeMap::new();
    id_map.insert(sidecar_root, dest_native.root());
    let mut claimed_dest = BTreeSet::new();
    claimed_dest.insert(dest_native.root());
    for preserved in &sidecar.objects {
        if skip_sidecar_object(&preserved.source) {
            continue;
        }
        let path = path_from_entries(&reconstructed, sidecar_root, preserved.object)?;
        let dest_id = dest_by_path
            .get(&path)
            .copied()
            .ok_or(NtfsRestoreError::MissingDestinationPath(path))?;
        if !claimed_dest.insert(dest_id) {
            return Err(NtfsRestoreError::DuplicateDestinationPath);
        }
        id_map.insert(preserved.object, dest_id);
    }
    Ok((id_map, dest_by_path))
}

fn reconstruct_dest_native_entries(
    sidecar: &NtfsPreservationSidecar,
) -> Result<Vec<NamespaceEntry>, NtfsRestoreError> {
    let mut owned: BTreeMap<ObjectId, Vec<NamespaceEntry>> = BTreeMap::new();
    for preserved in &sidecar.objects {
        if skip_sidecar_object(&preserved.source) {
            continue;
        }
        let mut choices = Vec::new();
        for name in &preserved.source.file_names {
            if is_dos_short_name_companion(name, &preserved.source.file_names) {
                continue;
            }
            choices.push(NamespaceEntry {
                parent: ObjectId(name.parent.record_number),
                target: preserved.object,
                name: name.name.code_units.clone(),
            });
        }
        if choices.is_empty() {
            return Err(NtfsRestoreError::MissingDestNativeName(preserved.object));
        }
        let selected = {
            let refs: Vec<&NamespaceEntry> = choices.iter().collect();
            select_dest_native_namespace_entry(preserved.object, &refs, sidecar)
        };
        owned.insert(preserved.object, vec![selected]);
    }
    let mut entries: Vec<NamespaceEntry> = owned.into_values().flatten().collect();
    disambiguate_exfat_case_collisions(&mut entries).map_err(|error| match error {
        NtfsToExfatError::NameDisambiguationFailed { parent } => {
            NtfsRestoreError::NameDisambiguationFailed { parent }
        }
        _ => NtfsRestoreError::AllocationFailed,
    })?;
    Ok(entries)
}

fn path_from_entries(
    entries: &[NamespaceEntry],
    root: ObjectId,
    id: ObjectId,
) -> Result<Vec<Vec<u16>>, NtfsRestoreError> {
    let mut path = Vec::new();
    let mut current = id;
    let mut seen = BTreeSet::new();
    while current != root {
        if !seen.insert(current) {
            return Err(NtfsRestoreError::AmbiguousDestinationNames(id));
        }
        let targeting: Vec<&NamespaceEntry> = entries
            .iter()
            .filter(|entry| entry.target == current)
            .collect();
        if targeting.len() != 1 {
            return Err(NtfsRestoreError::AmbiguousDestinationNames(current));
        }
        path.push(targeting[0].name.clone());
        current = targeting[0].parent;
    }
    path.reverse();
    Ok(path)
}

fn restore_reparse_point(
    object: &mut ObjectRecord,
    source: &NtfsObject,
    reparse_points: &mut BTreeMap<ObjectId, Vec<u8>>,
) -> Result<(), NtfsRestoreError> {
    if !source.has_reparse_point {
        return Ok(());
    }
    let Some(payload) = source
        .reparse_point
        .as_ref()
        .filter(|bytes| bytes.len() >= 8)
    else {
        return Err(NtfsRestoreError::IncompleteReparse(object.id));
    };
    object.semantics.is_reparse_point = true;
    reparse_points.insert(object.id, payload.clone());
    Ok(())
}

fn sidecar_name_budget(sidecar: &NtfsPreservationSidecar) -> usize {
    sidecar
        .objects
        .iter()
        .filter(|preserved| !skip_sidecar_object(&preserved.source))
        .map(|preserved| preserved.source.file_names.len())
        .sum()
}

fn restored_name_limit(entries: &[NamespaceEntry], objects: &[ObjectRecord]) -> usize {
    entries
        .iter()
        .map(|entry| entry.name.len())
        .chain(objects.iter().flat_map(|object| {
            object
                .streams
                .iter()
                .filter_map(|stream| stream.name.as_ref().map(Vec::len))
        }))
        .max()
        .unwrap_or(1)
}

fn restore_namespace_entries(
    target: ObjectId,
    source: &NtfsObject,
    entries: &mut Vec<NamespaceEntry>,
    id_map: &BTreeMap<ObjectId, ObjectId>,
) -> Result<(), NtfsRestoreError> {
    for name in &source.file_names {
        if is_dos_short_name_companion(name, &source.file_names) {
            continue;
        }
        let parent = id_map
            .get(&ObjectId(name.parent.record_number))
            .copied()
            .ok_or(NtfsRestoreError::MissingDestinationObject(ObjectId(
                name.parent.record_number,
            )))?;
        let entry = NamespaceEntry {
            parent,
            target,
            name: name.name.code_units.clone(),
        };
        if entries.iter().any(|existing| {
            existing.parent == entry.parent
                && existing.target == entry.target
                && existing.name == entry.name
        }) {
            continue;
        }
        entries
            .try_reserve(1)
            .map_err(|_| NtfsRestoreError::AllocationFailed)?;
        entries.push(entry);
    }
    Ok(())
}

fn restore_named_streams(
    object: &mut ObjectRecord,
    source: &NtfsObject,
    used_streams: &mut BTreeSet<StreamId>,
    carriers: &BTreeMap<(ObjectId, u16), CarrierPayload>,
) -> Result<(), NtfsRestoreError> {
    let named = source
        .data_streams
        .iter()
        .filter(|stream| stream.name.is_some())
        .count();
    if object.kind == ObjectKind::Directory && named != 0 {
        return Err(NtfsRestoreError::NamedStreamOnDirectory(object.id));
    }
    for stream in &source.data_streams {
        let Some(name) = &stream.name else {
            continue;
        };
        if object
            .streams
            .iter()
            .any(|existing| existing.name.as_deref() == Some(name.code_units.as_slice()))
        {
            continue;
        }
        if stream.encrypted {
            return Err(NtfsRestoreError::EncryptedNamedStream {
                object: object.id,
                name: name.code_units.clone(),
            });
        }
        if needs_carrier(stream) {
            let carrier = carriers
                .get(&(
                    ObjectId(source.reference.record_number),
                    stream.attribute_id,
                ))
                .ok_or_else(|| NtfsRestoreError::UnrestorableNamedStream {
                    object: object.id,
                    name: name.code_units.clone(),
                    data_bytes: named_stream_data_bytes(&stream.storage),
                })?;
            restore_carrier_named_stream(object, &name.code_units, carrier)?;
            continue;
        }
        if stream.compressed || stream.compression_block_bytes != 0 {
            return Err(NtfsRestoreError::CompressedNamedStream {
                object: object.id,
                name: name.code_units.clone(),
            });
        }
        if stream.sparse {
            return Err(NtfsRestoreError::UnrestorableNamedStream {
                object: object.id,
                name: name.code_units.clone(),
                data_bytes: named_stream_data_bytes(&stream.storage),
            });
        }
        let bytes = match &stream.storage {
            NtfsStreamStorage::Resident { bytes } => bytes.clone(),
            NtfsStreamStorage::NonResident {
                data_bytes,
                initialized_bytes,
                captured_payload: Some(captured),
                ..
            } => restore_captured_named_payload(
                object.id,
                &name.code_units,
                captured,
                *data_bytes,
                *initialized_bytes,
            )?,
            NtfsStreamStorage::NonResident { data_bytes, .. } if *data_bytes == 0 => Vec::new(),
            NtfsStreamStorage::NonResident { data_bytes, .. } => {
                return Err(NtfsRestoreError::UnrestorableNamedStream {
                    object: object.id,
                    name: name.code_units.clone(),
                    data_bytes: *data_bytes,
                });
            }
        };
        let id = restored_stream_id(source.reference.record_number, stream.attribute_id)?;
        if !used_streams.insert(id) {
            return Err(NtfsRestoreError::DuplicateStreamId(id));
        }
        let length =
            u64::try_from(bytes.len()).map_err(|_| NtfsRestoreError::ArithmeticOverflow)?;
        object
            .streams
            .try_reserve(1)
            .map_err(|_| NtfsRestoreError::AllocationFailed)?;
        object.streams.push(ObjectStream {
            id,
            name: Some(name.code_units.clone()),
            logical_bytes: length,
            initialized_bytes: length,
            mapped_bytes: length,
            allocated_bytes: 0,
            flags: StreamFlags::default(),
            storage: StreamStorage::Resident(bytes),
        });
    }
    Ok(())
}

/// Reattaches a dest-native carrier payload as `name`.
///
/// The exporter carried this payload as a plain file; its dest extents (already materialized as
/// plain bytes) become the named stream, and the carrier object itself is removed afterwards. The
/// carrier's [`StreamId`] is retained so the extent graph keeps pointing at the payload.
fn restore_carrier_named_stream(
    object: &mut ObjectRecord,
    name: &[u16],
    carrier: &CarrierPayload,
) -> Result<(), NtfsRestoreError> {
    object
        .streams
        .try_reserve(1)
        .map_err(|_| NtfsRestoreError::AllocationFailed)?;
    object.streams.push(ObjectStream {
        id: carrier.stream.id,
        name: Some(name.to_vec()),
        logical_bytes: carrier.stream.logical_bytes,
        initialized_bytes: carrier.stream.initialized_bytes,
        mapped_bytes: carrier.stream.mapped_bytes,
        allocated_bytes: carrier.stream.allocated_bytes,
        flags: StreamFlags::default(),
        storage: carrier.stream.storage.clone(),
    });
    Ok(())
}

fn named_stream_data_bytes(storage: &NtfsStreamStorage) -> u64 {
    match storage {
        NtfsStreamStorage::Resident { bytes } => u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        NtfsStreamStorage::NonResident { data_bytes, .. } => *data_bytes,
    }
}

fn restore_captured_named_payload(
    object: ObjectId,
    name: &[u16],
    captured: &[u8],
    data_bytes: u64,
    initialized_bytes: u64,
) -> Result<Vec<u8>, NtfsRestoreError> {
    let captured_len =
        u64::try_from(captured.len()).map_err(|_| NtfsRestoreError::ArithmeticOverflow)?;
    if captured_len != initialized_bytes || initialized_bytes > data_bytes {
        return Err(NtfsRestoreError::UnrestorableNamedStream {
            object,
            name: name.to_vec(),
            data_bytes,
        });
    }
    let logical = usize::try_from(data_bytes).map_err(|_| NtfsRestoreError::ArithmeticOverflow)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(logical)
        .map_err(|_| NtfsRestoreError::AllocationFailed)?;
    bytes.extend_from_slice(captured);
    bytes.resize(logical, 0);
    Ok(bytes)
}

fn restored_stream_id(record: u64, attribute_id: u16) -> Result<StreamId, NtfsRestoreError> {
    record
        .checked_shl(16)
        .and_then(|value| value.checked_add(u64::from(attribute_id)))
        .map(StreamId)
        .ok_or(NtfsRestoreError::StreamIdOverflow {
            record,
            attribute_id,
        })
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
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::FileSystem;
    use crate::GuaranteeMode;
    use crate::cross_format::project_ntfs_graph_for_exfat;
    use crate::extent::ExtentGraph;
    use crate::fs::ntfs_inventory::{
        NtfsDataStream, NtfsFileName, NtfsName, NtfsObject, NtfsObjectReference, NtfsStreamStorage,
    };
    use crate::fs::ntfs_normalize::NtfsObjectPreservation;
    use crate::fs::ntfs_serialize::{
        NtfsDestinationInputs, NtfsDestinationPlan, NtfsSerializeLimits, plan_ntfs_destination,
        plan_ntfs_destination_with_reparse_points,
    };
    use crate::object::{ObjectSemantics, StreamStorage};
    use crate::preservation::{
        PreservationLimits, decode_ntfs_preservation_sidecar, decode_ntfs_sidecar_from_escrow,
        evaluate_ntfs,
    };

    const IMAGE_BYTES: u64 = 16 * 1024 * 1024;
    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TempImage(PathBuf);

    impl TempImage {
        fn create(bytes: &[u8]) -> Self {
            let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "starconverter-escrow-restore-{}-{id}.img",
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

    const fn reference(record_number: u64) -> NtfsObjectReference {
        NtfsObjectReference {
            record_number,
            sequence_number: 1,
        }
    }

    fn utf16(value: &str) -> Vec<u16> {
        value.encode_utf16().collect()
    }

    fn ntfs_name(value: &str) -> NtfsName {
        NtfsName {
            code_units: utf16(value),
            is_well_formed: true,
        }
    }

    fn file_name(parent: u64, namespace: FileNameNamespace, value: &str) -> NtfsFileName {
        NtfsFileName {
            parent: reference(parent),
            namespace,
            name: ntfs_name(value),
            allocated_size: 0,
            data_size: 0,
            file_attributes: 0,
            reparse_tag_or_ea_size: 0,
        }
    }

    fn dest_native_file_graph() -> ObjectGraph {
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
                ObjectRecord {
                    id: ObjectId(2),
                    kind: ObjectKind::File,
                    link_count: 1,
                    semantics: ObjectSemantics::default(),
                    streams: vec![ObjectStream {
                        id: StreamId(9),
                        name: None,
                        logical_bytes: 3,
                        initialized_bytes: 3,
                        mapped_bytes: 3,
                        allocated_bytes: 0,
                        flags: StreamFlags::default(),
                        storage: StreamStorage::Resident(b"abc".to_vec()),
                    }],
                },
            ],
            vec![NamespaceEntry {
                parent: ObjectId(1),
                target: ObjectId(2),
                name: utf16("alpha.txt"),
            }],
            ExtentGraph::build(Vec::new(), IMAGE_BYTES, 4).unwrap(),
            ObjectGraphLimits {
                max_objects: 4,
                max_entries: 8,
                max_streams: 8,
                max_name_code_units: 255,
            },
        )
        .unwrap()
    }

    fn dest_native_directory_graph(root: ObjectId, directory: ObjectId) -> ObjectGraph {
        ObjectGraph::build(
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
                    id: directory,
                    kind: ObjectKind::Directory,
                    link_count: 1,
                    semantics: ObjectSemantics::default(),
                    streams: Vec::new(),
                },
            ],
            vec![NamespaceEntry {
                parent: root,
                target: directory,
                name: utf16("junction"),
            }],
            ExtentGraph::build(Vec::new(), IMAGE_BYTES, 4).unwrap(),
            ObjectGraphLimits {
                max_objects: 4,
                max_entries: 8,
                max_streams: 8,
                max_name_code_units: 255,
            },
        )
        .unwrap()
    }

    const fn empty_object(record: u64, is_directory: bool, is_metadata: bool) -> NtfsObject {
        NtfsObject {
            reference: reference(record),
            hard_link_count: 0,
            is_directory,
            is_metadata,
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

    fn sidecar_with_file(file: NtfsObject) -> NtfsPreservationSidecar {
        NtfsPreservationSidecar {
            volume_serial_number: 1,
            volume_label: None,
            security_descriptors:
                crate::fs::ntfs_normalize::NtfsSecurityDescriptorEvidence::Unavailable,
            root_reference: reference(1),
            objects: vec![
                NtfsObjectPreservation {
                    object: ObjectId(1),
                    source: empty_object(1, true, true),
                },
                NtfsObjectPreservation {
                    object: ObjectId(2),
                    source: file,
                },
            ],
            source_extents: Vec::new(),
            scanned_records: 16,
            initialized_records: 16,
            in_use_base_records: 2,
            extension_records: 0,
            bytes_read: 1024,
        }
    }

    fn identity_file(names: Vec<NtfsFileName>, streams: Vec<NtfsDataStream>) -> NtfsObject {
        let mut file = empty_object(2, false, false);
        file.hard_link_count = u16::try_from(names.len()).unwrap();
        file.file_names = names;
        file.data_streams = streams;
        file
    }

    fn identity_directory(names: Vec<NtfsFileName>) -> NtfsObject {
        let mut directory = empty_object(2, true, false);
        directory.hard_link_count = u16::try_from(names.len()).unwrap();
        directory.file_names = names;
        directory
    }

    fn named_stream(
        attribute_id: u16,
        name: &str,
        encrypted: bool,
        compressed: bool,
        storage: NtfsStreamStorage,
    ) -> NtfsDataStream {
        NtfsDataStream {
            attribute_id,
            name: Some(ntfs_name(name)),
            compressed,
            encrypted,
            sparse: false,
            compression_block_bytes: u64::from(compressed) * 4096,
            storage,
        }
    }

    fn apply_plan(plan: &NtfsDestinationPlan) -> Vec<u8> {
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

    const fn inputs() -> NtfsDestinationInputs {
        NtfsDestinationInputs {
            image_bytes: IMAGE_BYTES,
            partition_offset_sectors: 0,
            cluster_bytes: 4096,
            volume_serial_number: 0x1122_3344_5566_7788,
            timestamp: 123,
        }
    }

    fn source_graph() -> ObjectGraph {
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
                ObjectRecord {
                    id: ObjectId(2),
                    kind: ObjectKind::Directory,
                    link_count: 2,
                    semantics: ObjectSemantics::default(),
                    streams: Vec::new(),
                },
                ObjectRecord {
                    id: ObjectId(3),
                    kind: ObjectKind::File,
                    link_count: 2,
                    semantics: ObjectSemantics::default(),
                    streams: vec![
                        ObjectStream {
                            id: StreamId(9),
                            name: None,
                            logical_bytes: 3,
                            initialized_bytes: 3,
                            mapped_bytes: 3,
                            allocated_bytes: 0,
                            flags: StreamFlags::default(),
                            storage: StreamStorage::Resident(b"abc".to_vec()),
                        },
                        ObjectStream {
                            id: StreamId(10),
                            name: Some(utf16("fork")),
                            logical_bytes: 1,
                            initialized_bytes: 1,
                            mapped_bytes: 1,
                            allocated_bytes: 0,
                            flags: StreamFlags::default(),
                            storage: StreamStorage::Resident(b"x".to_vec()),
                        },
                    ],
                },
            ],
            vec![
                NamespaceEntry {
                    parent: ObjectId(1),
                    target: ObjectId(2),
                    name: utf16("left"),
                },
                NamespaceEntry {
                    parent: ObjectId(1),
                    target: ObjectId(2),
                    name: utf16("right"),
                },
                NamespaceEntry {
                    parent: ObjectId(2),
                    target: ObjectId(3),
                    name: utf16("alpha.txt"),
                },
                NamespaceEntry {
                    parent: ObjectId(2),
                    target: ObjectId(3),
                    name: utf16("beta.txt"),
                },
            ],
            ExtentGraph::build(Vec::new(), IMAGE_BYTES, 4).unwrap(),
            ObjectGraphLimits {
                max_objects: 8,
                max_entries: 8,
                max_streams: 8,
                max_name_code_units: 255,
            },
        )
        .unwrap()
    }

    #[test]
    fn decode_refuses_historical_inner_snapshots() {
        assert!(decode_ntfs_preservation_sidecar(&[6, 0]).is_err());
        assert!(decode_ntfs_preservation_sidecar(&[5, 0]).is_err());
        assert!(decode_ntfs_preservation_sidecar(&[4, 0]).is_err());
    }

    #[test]
    fn restore_reattaches_extra_win32_names_and_skips_dos_aliases() {
        let dest = dest_native_file_graph();
        let file = identity_file(
            vec![
                file_name(1, FileNameNamespace::Win32, "alpha.txt"),
                file_name(1, FileNameNamespace::Dos, "ALPHA~1.TXT"),
                file_name(1, FileNameNamespace::Win32, "beta.txt"),
            ],
            vec![named_stream(
                2,
                "fork",
                false,
                false,
                NtfsStreamStorage::Resident {
                    bytes: b"x".to_vec(),
                },
            )],
        );
        let restored = restore_ntfs_identities(&dest, &sidecar_with_file(file)).unwrap();
        let file = restored
            .objects()
            .iter()
            .find(|object| object.id == ObjectId(2))
            .unwrap();
        assert_eq!(file.link_count, 2);
        assert_eq!(restored.entries().len(), 2);
        assert!(
            restored
                .entries()
                .iter()
                .any(|entry| entry.name == utf16("beta.txt"))
        );
        assert!(
            !restored
                .entries()
                .iter()
                .any(|entry| entry.name == utf16("ALPHA~1.TXT"))
        );
        assert!(file.streams.iter().any(|stream| {
            stream.name.as_deref() == Some(utf16("fork").as_slice())
                && matches!(&stream.storage, StreamStorage::Resident(bytes) if bytes == b"x")
        }));
    }

    #[test]
    fn restore_materializes_empty_nonresident_named_streams() {
        let dest = dest_native_file_graph();
        let file = identity_file(
            vec![file_name(1, FileNameNamespace::Win32, "alpha.txt")],
            vec![named_stream(
                2,
                "empty",
                false,
                false,
                NtfsStreamStorage::NonResident {
                    allocated_bytes: 0,
                    data_bytes: 0,
                    initialized_bytes: 0,
                    compressed_bytes: None,
                    mapping_complete: true,
                    extents: Vec::new(),
                    captured_payload: None,
                },
            )],
        );
        let restored = restore_ntfs_identities(&dest, &sidecar_with_file(file)).unwrap();
        let file = restored
            .objects()
            .iter()
            .find(|object| object.id == ObjectId(2))
            .unwrap();
        assert!(file.streams.iter().any(|stream| {
            stream.name.as_deref() == Some(utf16("empty").as_slice())
                && matches!(&stream.storage, StreamStorage::Resident(bytes) if bytes.is_empty())
        }));
    }

    #[test]
    fn restore_refuses_encrypted_named_streams() {
        let dest = dest_native_file_graph();
        let file = identity_file(
            vec![file_name(1, FileNameNamespace::Win32, "alpha.txt")],
            vec![named_stream(
                2,
                "secret",
                true,
                false,
                NtfsStreamStorage::Resident {
                    bytes: b"x".to_vec(),
                },
            )],
        );
        assert!(matches!(
            restore_ntfs_identities(&dest, &sidecar_with_file(file)),
            Err(NtfsRestoreError::EncryptedNamedStream { .. })
        ));
    }

    #[test]
    fn restore_refuses_nonresident_named_payloads() {
        let dest = dest_native_file_graph();
        let file = identity_file(
            vec![file_name(1, FileNameNamespace::Win32, "alpha.txt")],
            vec![named_stream(
                2,
                "big",
                false,
                false,
                NtfsStreamStorage::NonResident {
                    allocated_bytes: 4096,
                    data_bytes: 8,
                    initialized_bytes: 8,
                    compressed_bytes: None,
                    mapping_complete: true,
                    extents: Vec::new(),
                    captured_payload: None,
                },
            )],
        );
        assert!(matches!(
            restore_ntfs_identities(&dest, &sidecar_with_file(file)),
            Err(NtfsRestoreError::UnrestorableNamedStream { data_bytes: 8, .. })
        ));
    }

    #[test]
    fn restore_materializes_captured_nonresident_named_streams() {
        let dest = dest_native_file_graph();
        let payload = b"forkdata".to_vec();
        let file = identity_file(
            vec![file_name(1, FileNameNamespace::Win32, "alpha.txt")],
            vec![named_stream(
                2,
                "fork",
                false,
                false,
                NtfsStreamStorage::NonResident {
                    allocated_bytes: 4096,
                    data_bytes: 8,
                    initialized_bytes: 8,
                    compressed_bytes: None,
                    mapping_complete: true,
                    extents: Vec::new(),
                    captured_payload: Some(payload.clone()),
                },
            )],
        );
        let restored = restore_ntfs_identities(&dest, &sidecar_with_file(file)).unwrap();
        let file = restored
            .objects()
            .iter()
            .find(|object| object.kind == ObjectKind::File)
            .unwrap();
        assert!(file.streams.iter().any(|stream| {
            stream.name.as_deref() == Some(utf16("fork").as_slice())
                && matches!(&stream.storage, StreamStorage::Resident(bytes) if bytes == &payload)
        }));
        let inspection = inspect_serialized(&restored);
        let inventoried = inspection
            .normalized_ntfs
            .as_ref()
            .unwrap()
            .graph
            .objects()
            .iter()
            .find(|object| object.kind == ObjectKind::File)
            .unwrap();
        assert!(inventoried.streams.iter().any(|stream| {
            stream.name.as_deref() == Some(utf16("fork").as_slice())
                && matches!(&stream.storage, StreamStorage::Resident(bytes) if bytes == &payload)
        }));
    }

    #[test]
    fn restore_dest_cluster_materializes_overflow_named_resident() {
        let dest = dest_native_file_graph();
        let payload = (0..4096)
            .map(|index| u8::try_from(index % 251).unwrap())
            .collect::<Vec<_>>();
        let file = identity_file(
            vec![file_name(1, FileNameNamespace::Win32, "alpha.txt")],
            vec![named_stream(
                2,
                "fork",
                false,
                false,
                NtfsStreamStorage::NonResident {
                    allocated_bytes: 4096,
                    data_bytes: 4096,
                    initialized_bytes: 4096,
                    compressed_bytes: None,
                    mapping_complete: true,
                    extents: Vec::new(),
                    captured_payload: Some(payload.clone()),
                },
            )],
        );
        let restored = restore_ntfs_identities(&dest, &sidecar_with_file(file)).unwrap();
        let file = restored
            .objects()
            .iter()
            .find(|object| object.kind == ObjectKind::File)
            .unwrap();
        assert!(file.streams.iter().any(|stream| {
            stream.name.as_deref() == Some(utf16("fork").as_slice())
                && matches!(&stream.storage, StreamStorage::Resident(bytes) if bytes == &payload)
        }));
        let inspection = inspect_serialized(&restored);
        let inventoried = inspection
            .normalized_ntfs
            .as_ref()
            .unwrap()
            .graph
            .objects()
            .iter()
            .find(|object| object.kind == ObjectKind::File)
            .unwrap();
        let fork = inventoried
            .streams
            .iter()
            .find(|stream| stream.name.as_deref() == Some(utf16("fork").as_slice()))
            .unwrap();
        assert!(matches!(fork.storage, StreamStorage::Extents));
        assert_eq!(fork.logical_bytes, 4096);
        let source = inspection
            .ntfs_inventory
            .as_ref()
            .unwrap()
            .objects
            .iter()
            .find(|object| !object.is_metadata && !object.is_directory)
            .unwrap();
        let captured = source
            .data_streams
            .iter()
            .find(|stream| {
                stream
                    .name
                    .as_ref()
                    .is_some_and(|name| name.code_units == utf16("fork"))
            })
            .and_then(|stream| match &stream.storage {
                NtfsStreamStorage::NonResident {
                    captured_payload, ..
                } => captured_payload.clone(),
                NtfsStreamStorage::Resident { bytes } => Some(bytes.clone()),
            });
        assert_eq!(captured.as_deref(), Some(payload.as_slice()));
    }

    #[test]
    fn restore_refuses_sidecar_objects_missing_from_dest() {
        let dest = dest_native_file_graph();
        let mut sidecar = sidecar_with_file(identity_file(
            vec![file_name(1, FileNameNamespace::Win32, "alpha.txt")],
            Vec::new(),
        ));
        sidecar.objects.push(NtfsObjectPreservation {
            object: ObjectId(99),
            source: identity_file(
                vec![file_name(1, FileNameNamespace::Win32, "orphan.txt")],
                Vec::new(),
            ),
        });
        sidecar.objects.last_mut().unwrap().source.reference = reference(99);
        assert!(matches!(
            restore_ntfs_identities(&dest, &sidecar),
            Err(NtfsRestoreError::MissingDestinationPath(_))
        ));
    }

    fn first_kind(graph: &ObjectGraph, kind: ObjectKind) -> &ObjectRecord {
        graph
            .objects()
            .iter()
            .find(|object| object.kind == kind && object.id != graph.root())
            .unwrap()
    }

    fn assert_dest_native_projection(projected: &ObjectGraph) {
        let file = first_kind(projected, ObjectKind::File);
        assert_eq!(file.link_count, 1);
        assert_eq!(file.streams.len(), 1);
        assert_eq!(
            projected
                .entries()
                .iter()
                .filter(|entry| entry.target == file.id)
                .count(),
            1
        );
        assert_eq!(first_kind(projected, ObjectKind::Directory).link_count, 1);
    }

    fn assert_restored_identities(restored: &ObjectGraph) {
        let file = first_kind(restored, ObjectKind::File);
        assert_eq!(file.link_count, 2);
        assert_eq!(file.streams.len(), 2);
        assert!(file.streams.iter().any(|stream| {
            stream.name.as_deref() == Some(utf16("fork").as_slice())
                && matches!(&stream.storage, StreamStorage::Resident(bytes) if bytes == b"x")
        }));
        assert_eq!(first_kind(restored, ObjectKind::Directory).link_count, 2);
    }

    fn assert_inventoried_identities(dest: &crate::fs::ntfs_normalize::NormalizedNtfs) {
        let file = first_kind(&dest.graph, ObjectKind::File);
        assert_eq!(file.link_count, 2);
        for name in ["alpha.txt", "beta.txt", "left", "right"] {
            assert!(
                dest.graph
                    .entries()
                    .iter()
                    .any(|entry| entry.name == utf16(name))
            );
        }
        assert!(file.streams.iter().any(|stream| {
            stream.name.as_deref() == Some(utf16("fork").as_slice())
                && matches!(&stream.storage, StreamStorage::Resident(bytes) if bytes == b"x")
        }));
        assert!(file.streams.iter().any(|stream| stream.name.is_none()
            && matches!(&stream.storage, StreamStorage::Resident(bytes) if bytes == b"abc")));
    }

    fn inspect_serialized(graph: &ObjectGraph) -> crate::inspect::ImageInspection {
        let plan = plan_ntfs_destination(graph, inputs(), NtfsSerializeLimits::default()).unwrap();
        let temp = TempImage::create(&apply_plan(&plan));
        crate::inspect::inspect_image(&temp.0).unwrap()
    }

    #[test]
    fn project_restore_serialize_roundtrips_hard_links_and_resident_ads() {
        let first = inspect_serialized(&source_graph());
        let normalized = first.normalized_ntfs.as_ref().unwrap();
        let report = evaluate_ntfs(
            normalized,
            FileSystem::ExFat,
            GuaranteeMode::Escrow,
            PreservationLimits::default(),
        )
        .unwrap();
        let sidecar = decode_ntfs_sidecar_from_escrow(
            report.escrow.as_ref().expect("escrow"),
            PreservationLimits::default(),
        )
        .unwrap();
        assert_eq!(sidecar.objects.len(), normalized.preservation.objects.len());

        let projected = project_ntfs_graph_for_exfat(normalized).unwrap().graph;
        assert_dest_native_projection(&projected);
        let restored = restore_ntfs_identities(&projected, &sidecar).unwrap();
        assert_restored_identities(&restored);

        let second = inspect_serialized(&restored);
        assert_inventoried_identities(second.normalized_ntfs.as_ref().unwrap());
    }

    fn remapped_dest_file_graph() -> ObjectGraph {
        ObjectGraph::build(
            ObjectId(100),
            vec![
                ObjectRecord {
                    id: ObjectId(100),
                    kind: ObjectKind::Directory,
                    link_count: 0,
                    semantics: ObjectSemantics::default(),
                    streams: Vec::new(),
                },
                ObjectRecord {
                    id: ObjectId(200),
                    kind: ObjectKind::File,
                    link_count: 1,
                    semantics: ObjectSemantics::default(),
                    streams: vec![ObjectStream {
                        id: StreamId(9),
                        name: None,
                        logical_bytes: 3,
                        initialized_bytes: 3,
                        mapped_bytes: 3,
                        allocated_bytes: 0,
                        flags: StreamFlags::default(),
                        storage: StreamStorage::Resident(b"abc".to_vec()),
                    }],
                },
            ],
            vec![NamespaceEntry {
                parent: ObjectId(100),
                target: ObjectId(200),
                name: utf16("alpha.txt"),
            }],
            ExtentGraph::build(Vec::new(), IMAGE_BYTES, 4).unwrap(),
            ObjectGraphLimits {
                max_objects: 4,
                max_entries: 8,
                max_streams: 8,
                max_name_code_units: 255,
            },
        )
        .unwrap()
    }

    fn symlink_reparse_payload() -> Vec<u8> {
        let mut payload = vec![0_u8; 16];
        payload[..4].copy_from_slice(&0xa000_000c_u32.to_le_bytes());
        payload[4..6].copy_from_slice(&8_u16.to_le_bytes());
        payload
    }

    fn mount_point_reparse_payload() -> Vec<u8> {
        let mut payload = vec![0_u8; 16];
        payload[..4].copy_from_slice(&0xa000_0003_u32.to_le_bytes());
        payload[4..6].copy_from_slice(&8_u16.to_le_bytes());
        payload
    }

    #[test]
    fn restore_matches_remapped_dest_object_ids_by_path() {
        let dest = remapped_dest_file_graph();
        let file = identity_file(
            vec![
                file_name(1, FileNameNamespace::Win32, "alpha.txt"),
                file_name(1, FileNameNamespace::Dos, "ALPHA~1.TXT"),
                file_name(1, FileNameNamespace::Win32, "beta.txt"),
            ],
            vec![named_stream(
                2,
                "fork",
                false,
                false,
                NtfsStreamStorage::Resident {
                    bytes: b"x".to_vec(),
                },
            )],
        );
        let restored = restore_ntfs_identities(&dest, &sidecar_with_file(file)).unwrap();
        let file = restored
            .objects()
            .iter()
            .find(|object| object.id == ObjectId(200))
            .unwrap();
        assert_eq!(file.link_count, 2);
        assert!(restored.entries().iter().any(|entry| {
            entry.parent == ObjectId(100)
                && entry.target == ObjectId(200)
                && entry.name == utf16("beta.txt")
        }));
        assert!(file.streams.iter().any(|stream| {
            stream.name.as_deref() == Some(utf16("fork").as_slice())
                && matches!(&stream.storage, StreamStorage::Resident(bytes) if bytes == b"x")
        }));
    }

    #[test]
    fn restore_rematerializes_resident_reparse_point() {
        let dest = dest_native_file_graph();
        let mut file = identity_file(
            vec![file_name(1, FileNameNamespace::Win32, "alpha.txt")],
            Vec::new(),
        );
        let payload = symlink_reparse_payload();
        file.has_reparse_point = true;
        file.reparse_point = Some(payload.clone());
        let restored =
            restore_ntfs_identities_with_evidence(&dest, &sidecar_with_file(file)).unwrap();
        assert_eq!(
            restored.reparse_points.get(&ObjectId(2)).map(Vec::as_slice),
            Some(payload.as_slice())
        );
        let bindings: Vec<(ObjectId, &[u8])> = restored
            .reparse_points
            .iter()
            .map(|(object, bytes)| (*object, bytes.as_slice()))
            .collect();
        let plan = plan_ntfs_destination_with_reparse_points(
            &restored.graph,
            inputs(),
            &bindings,
            NtfsSerializeLimits::default(),
        )
        .unwrap();
        let temp = TempImage::create(&apply_plan(&plan));
        let inspection = crate::inspect::inspect_image(&temp.0).unwrap();
        let inventoried = inspection
            .normalized_ntfs
            .as_ref()
            .unwrap()
            .graph
            .objects()
            .iter()
            .find(|object| object.kind == ObjectKind::File)
            .unwrap();
        assert!(inventoried.semantics.is_reparse_point);
        let source = inspection
            .ntfs_inventory
            .as_ref()
            .unwrap()
            .objects
            .iter()
            .find(|object| !object.is_metadata && !object.is_directory)
            .unwrap();
        assert_eq!(source.reparse_point.as_deref(), Some(payload.as_slice()));
    }

    #[test]
    fn restore_rematerializes_resident_directory_reparse_point() {
        let dest = dest_native_directory_graph(ObjectId(100), ObjectId(200));
        let mut directory =
            identity_directory(vec![file_name(1, FileNameNamespace::Win32, "junction")]);
        let payload = mount_point_reparse_payload();
        directory.has_reparse_point = true;
        directory.reparse_point = Some(payload.clone());
        let restored =
            restore_ntfs_identities_with_evidence(&dest, &sidecar_with_file(directory)).unwrap();
        assert_eq!(
            restored
                .reparse_points
                .get(&ObjectId(200))
                .map(Vec::as_slice),
            Some(payload.as_slice())
        );
        assert!(
            restored
                .graph
                .objects()
                .iter()
                .find(|object| object.id == ObjectId(200))
                .unwrap()
                .semantics
                .is_reparse_point
        );
        let bindings: Vec<(ObjectId, &[u8])> = restored
            .reparse_points
            .iter()
            .map(|(object, bytes)| (*object, bytes.as_slice()))
            .collect();
        let plan = plan_ntfs_destination_with_reparse_points(
            &restored.graph,
            inputs(),
            &bindings,
            NtfsSerializeLimits::default(),
        )
        .unwrap();
        let temp = TempImage::create(&apply_plan(&plan));
        let inspection = crate::inspect::inspect_image(&temp.0).unwrap();
        let inventoried = inspection
            .normalized_ntfs
            .as_ref()
            .unwrap()
            .graph
            .objects()
            .iter()
            .find(|object| {
                object.kind == ObjectKind::Directory
                    && object.id != inspection.normalized_ntfs.as_ref().unwrap().graph.root()
            })
            .unwrap();
        assert!(inventoried.semantics.is_reparse_point);
        let source = inspection
            .ntfs_inventory
            .as_ref()
            .unwrap()
            .objects
            .iter()
            .find(|object| {
                object.is_directory
                    && object
                        .file_names
                        .iter()
                        .any(|name| name.name.code_units == utf16("junction"))
            })
            .unwrap();
        assert!(source.has_reparse_point);
        assert_eq!(source.reparse_point.as_deref(), Some(payload.as_slice()));
    }
}
