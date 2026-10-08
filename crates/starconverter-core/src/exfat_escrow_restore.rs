//! Restore source-only exFAT identities from a versioned escrow sidecar.
//!
//! An exFAT→NTFS export escrows the exFAT volume serial, label, up-case mappings, and every
//! object's exact timestamps (with centiseconds and UTC offsets) and attributes. When that NTFS
//! candidate is converted back to exFAT, this module reattaches those values onto the dest-native
//! graph the NTFS→exFAT projection produced. Dest objects are matched by dest-native path because
//! the NTFS candidate renumbered every object.
//!
//! Vendor (benign) directory entries are escrowed byte-exact but the exFAT writer has no way to
//! re-emit them yet, so a sidecar that carries any fails closed instead of silently dropping them.

#![allow(clippy::module_name_repetitions)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::FileSystem;
use crate::candidate_export::decode_bound_escrow;
use crate::fs::exfat_serialize::ExfatObjectMetadata;
use crate::fs::exfat_upcase::{UNICODE_MAPPING_COUNT, table_checksum};
use crate::fs::exfat_upcase_serialize::{
    RECOMMENDED_EXFAT_UPCASE_CHECKSUM, RecommendedExfatUpcaseLimits,
    generate_recommended_exfat_upcase,
};
use crate::object::{NamespaceEntry, ObjectGraph, ObjectId, ObjectKind};
use crate::preservation::{
    ExfatRestoreSidecar, ExfatVolumeLabelIdentity, PreservationError, PreservationLimits,
    decode_exfat_sidecar_from_escrow,
};

const EXFAT_ATTRIBUTE_DIRECTORY: u16 = 0x10;
/// Identity-run compression marker of the exFAT Up-case Table.
const COMPRESSION_MARKER: u16 = 0xffff;

/// Failure to restore escrowed exFAT identities onto a dest-native graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExfatRestoreError {
    /// The candidate-bound escrow envelope is malformed, oversized, or checksum-invalid.
    EscrowEnvelope(String),
    /// The escrow was not produced by an exFAT→NTFS export.
    EscrowDirectionMismatch {
        source: FileSystem,
        target: FileSystem,
    },
    /// The NTFS image being restored from is not the exact candidate the escrow was bound to.
    CandidateBindingMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    /// The embedded exFAT snapshot could not be decoded.
    EscrowPayload(PreservationError),
    /// The sidecar carries vendor directory entries the exFAT writer cannot re-emit.
    BenignEntriesNotRestorable {
        primary_sets: usize,
        secondary_entries: u64,
    },
    /// An escrowed path has no dest-native object.
    MissingDestinationPath(Vec<Vec<u16>>),
    /// Two escrow objects or two dest objects share one path.
    DuplicateDestinationPath,
    /// A dest object is reachable through zero or several names.
    AmbiguousDestinationNames(ObjectId),
    /// The escrow and the dest graph disagree on whether an object is a directory.
    KindMismatch(ObjectId),
    /// An identified object has no exact timestamps in the escrow.
    MissingTimestamps(ObjectId),
    /// The escrowed up-case mappings cannot be re-encoded to the escrowed `TableChecksum`.
    UpcaseTableNotReproducible {
        recorded: u32,
        reproduced: u32,
    },
    /// The escrowed up-case mapping table is not complete.
    IncompleteUpcaseTable(usize),
    AllocationFailed,
}

impl fmt::Display for ExfatRestoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EscrowEnvelope(error) => write!(formatter, "escrow envelope rejected: {error}"),
            Self::EscrowDirectionMismatch { source, target } => write!(
                formatter,
                "escrow records a {source}→{target} export; exFAT identity restore needs an exFAT→NTFS escrow"
            ),
            Self::CandidateBindingMismatch { .. } => formatter.write_str(
                "the NTFS image is not the exact candidate this escrow was bound to (SHA-256 mismatch)",
            ),
            Self::EscrowPayload(error) => {
                write!(formatter, "escrow preservation payload rejected: {error}")
            }
            Self::BenignEntriesNotRestorable {
                primary_sets,
                secondary_entries,
            } => write!(
                formatter,
                "escrow carries {primary_sets} benign primary set(s) and {secondary_entries} vendor secondary entries that the exFAT writer cannot re-emit"
            ),
            Self::MissingDestinationPath(path) => write!(
                formatter,
                "escrow exFAT path {path:?} is absent from the dest-native graph"
            ),
            Self::DuplicateDestinationPath => formatter.write_str(
                "two escrow objects share one dest-native path or two dest objects share one path",
            ),
            Self::AmbiguousDestinationNames(object) => write!(
                formatter,
                "object {} does not have exactly one dest-native name",
                object.0
            ),
            Self::KindMismatch(object) => write!(
                formatter,
                "escrow object kind does not match dest-native object {}",
                object.0
            ),
            Self::MissingTimestamps(object) => write!(
                formatter,
                "escrow identifies dest object {} without exact exFAT timestamps",
                object.0
            ),
            Self::UpcaseTableNotReproducible {
                recorded,
                reproduced,
            } => write!(
                formatter,
                "escrowed up-case mappings re-encode to TableChecksum {reproduced:#010x}, not the recorded {recorded:#010x}"
            ),
            Self::IncompleteUpcaseTable(count) => write!(
                formatter,
                "escrowed up-case table has {count} mappings instead of {UNICODE_MAPPING_COUNT}"
            ),
            Self::AllocationFailed => {
                formatter.write_str("exFAT identity restore allocation failed")
            }
        }
    }
}

impl std::error::Error for ExfatRestoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::EscrowPayload(error) => Some(error),
            _ => None,
        }
    }
}

/// Dest-keyed exact exFAT metadata plus the volume identity to write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoredExfatIdentities {
    /// Exact timestamps and attributes for every dest object the escrow identified by path.
    pub object_metadata: BTreeMap<ObjectId, ExfatObjectMetadata>,
    pub volume_serial_number: u32,
    /// `Some(units)` writes that exact label (possibly empty); `None` writes no label entry.
    pub volume_label: Option<Vec<u16>>,
    /// Encoded Up-case Table whose `TableChecksum` equals the escrowed one.
    pub encoded_upcase_table: Vec<u8>,
    pub upcase_checksum: u32,
}

/// Decodes a candidate-bound escrow sidecar so its exFAT identities can be restored onto the
/// exact NTFS candidate it was produced with.
///
/// The envelope must record an exFAT→NTFS export and its candidate SHA-256 must equal
/// `ntfs_image_sha256`, the whole-image hash of the NTFS image about to be converted back.
///
/// # Errors
///
/// Returns an error for a malformed or oversized envelope, a non-exFAT→NTFS export, a candidate
/// hash mismatch, or an undecodable exFAT snapshot.
pub fn decode_exfat_restore_sidecar(
    escrow_bytes: &[u8],
    ntfs_image_sha256: [u8; 32],
    max_escrow_payload_bytes: usize,
    limits: PreservationLimits,
) -> Result<ExfatRestoreSidecar, ExfatRestoreError> {
    let envelope = decode_bound_escrow(escrow_bytes, max_escrow_payload_bytes)
        .map_err(|error| ExfatRestoreError::EscrowEnvelope(error.to_string()))?;
    if envelope.source_filesystem != FileSystem::ExFat
        || envelope.target_filesystem != FileSystem::Ntfs
    {
        return Err(ExfatRestoreError::EscrowDirectionMismatch {
            source: envelope.source_filesystem,
            target: envelope.target_filesystem,
        });
    }
    if envelope.candidate_sha256 != ntfs_image_sha256 {
        return Err(ExfatRestoreError::CandidateBindingMismatch {
            expected: envelope.candidate_sha256,
            actual: ntfs_image_sha256,
        });
    }
    decode_exfat_sidecar_from_escrow(&envelope.preservation_payload, limits)
        .map_err(ExfatRestoreError::EscrowPayload)
}

/// Matches every escrowed exFAT object to `dest_native` by path and returns the exact metadata
/// and volume identity the exFAT writer should emit.
///
/// Dest objects the escrow does not know (added on the NTFS side, or the NTFS→exFAT escrow
/// carrier directory) are absent from the returned map and keep their NTFS-derived metadata. The
/// escrowed root carries no entry of its own and is skipped.
///
/// # Errors
///
/// Fails closed when the sidecar carries vendor entries, a path is missing or duplicated, kinds
/// disagree, an identified object lacks timestamps, or the up-case table cannot be reproduced.
pub fn restore_exfat_identities(
    dest_native: &ObjectGraph,
    sidecar: &ExfatRestoreSidecar,
) -> Result<RestoredExfatIdentities, ExfatRestoreError> {
    if sidecar.benign_primary_sets != 0 || sidecar.benign_secondary_entries != 0 {
        return Err(ExfatRestoreError::BenignEntriesNotRestorable {
            primary_sets: sidecar.benign_primary_sets,
            secondary_entries: sidecar.benign_secondary_entries,
        });
    }
    let (encoded_upcase_table, upcase_checksum) = reproduce_upcase_table(sidecar)?;

    let mut dest_by_path = BTreeMap::new();
    for object in dest_native.objects() {
        if object.id == dest_native.root() {
            continue;
        }
        let path = path_from_entries(dest_native.entries(), dest_native.root(), object.id)?;
        if dest_by_path.insert(path, object.id).is_some() {
            return Err(ExfatRestoreError::DuplicateDestinationPath);
        }
    }

    let mut object_metadata = BTreeMap::new();
    for escrowed in &sidecar.objects {
        if escrowed.path.is_empty() {
            continue;
        }
        let dest_id = dest_by_path
            .get(&escrowed.path)
            .copied()
            .ok_or_else(|| ExfatRestoreError::MissingDestinationPath(escrowed.path.clone()))?;
        let dest_object = dest_native
            .objects()
            .iter()
            .find(|object| object.id == dest_id)
            .ok_or(ExfatRestoreError::DuplicateDestinationPath)?;
        let escrowed_directory = escrowed.file_attributes & EXFAT_ATTRIBUTE_DIRECTORY != 0;
        let dest_directory = dest_object.kind == ObjectKind::Directory;
        if escrowed_directory != dest_directory {
            return Err(ExfatRestoreError::KindMismatch(dest_id));
        }
        let timestamps = escrowed
            .timestamps
            .ok_or(ExfatRestoreError::MissingTimestamps(dest_id))?;
        if object_metadata
            .insert(
                dest_id,
                ExfatObjectMetadata {
                    object: dest_id,
                    file_attributes: escrowed.file_attributes,
                    timestamps,
                },
            )
            .is_some()
        {
            return Err(ExfatRestoreError::DuplicateDestinationPath);
        }
    }

    let volume_label = match &sidecar.volume_label {
        ExfatVolumeLabelIdentity::Exact(units) => Some(units.clone()),
        // The logical label was observed but its padding was not retained; the escrow cannot
        // prove the exact entry, so the caller's label derivation stands.
        ExfatVolumeLabelIdentity::Absent | ExfatVolumeLabelIdentity::UnretainedNonzeroPadding => {
            None
        }
    };
    Ok(RestoredExfatIdentities {
        object_metadata,
        volume_serial_number: sidecar.volume_serial_number,
        volume_label,
        encoded_upcase_table,
        upcase_checksum,
    })
}

/// Whether the escrow proves the exact label entry (as opposed to only its logical value).
#[must_use]
pub const fn label_is_exact(sidecar: &ExfatRestoreSidecar) -> bool {
    !matches!(
        sidecar.volume_label,
        ExfatVolumeLabelIdentity::UnretainedNonzeroPadding
    )
}

/// Rebuilds an encoded Up-case Table whose checksum equals the escrowed one.
///
/// The recommended Table 25 profile is used verbatim when the escrowed mappings and checksum are
/// its own, because that is the only byte profile this crate pins. Any other table is re-encoded
/// with identity-run compression and accepted only when the normative checksum of the result
/// equals the escrowed `TableChecksum`, which proves the bytes are the ones the source carried.
fn reproduce_upcase_table(
    sidecar: &ExfatRestoreSidecar,
) -> Result<(Vec<u8>, u32), ExfatRestoreError> {
    if sidecar.upcase_mappings.len() != UNICODE_MAPPING_COUNT {
        return Err(ExfatRestoreError::IncompleteUpcaseTable(
            sidecar.upcase_mappings.len(),
        ));
    }
    if sidecar.upcase_checksum == RECOMMENDED_EXFAT_UPCASE_CHECKSUM {
        let recommended =
            generate_recommended_exfat_upcase(RecommendedExfatUpcaseLimits::default())
                .map_err(|_| ExfatRestoreError::AllocationFailed)?;
        if recommended.mappings() == sidecar.upcase_mappings.as_slice() {
            let mut encoded = Vec::new();
            encoded
                .try_reserve_exact(recommended.encoded_bytes().len())
                .map_err(|_| ExfatRestoreError::AllocationFailed)?;
            encoded.extend_from_slice(recommended.encoded_bytes());
            return Ok((encoded, RECOMMENDED_EXFAT_UPCASE_CHECKSUM));
        }
    }
    let compressed = compress_upcase_mappings(&sidecar.upcase_mappings)?;
    let reproduced = table_checksum(&compressed);
    if reproduced == sidecar.upcase_checksum {
        return Ok((compressed, reproduced));
    }
    // A formatter may also have written every mapping literally; that encoding is equally valid
    // and equally checkable.
    let literal = literal_upcase_mappings(&sidecar.upcase_mappings)?;
    if table_checksum(&literal) == sidecar.upcase_checksum {
        return Ok((literal, sidecar.upcase_checksum));
    }
    Err(ExfatRestoreError::UpcaseTableNotReproducible {
        recorded: sidecar.upcase_checksum,
        reproduced,
    })
}

/// Encodes a complete mapping table without identity-run compression.
fn literal_upcase_mappings(mappings: &[u16]) -> Result<Vec<u8>, ExfatRestoreError> {
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(mappings.len() * 2)
        .map_err(|_| ExfatRestoreError::AllocationFailed)?;
    for mapping in mappings {
        encoded.extend_from_slice(&mapping.to_le_bytes());
    }
    Ok(encoded)
}

/// Encodes a complete mapping table with the specification's identity-run compression: every
/// maximal run of two or more identity mappings becomes `FFFF, count`, and a lone `FFFF` mapping
/// at the very end is written literally (the decoder treats a trailing marker as a mapping).
fn compress_upcase_mappings(mappings: &[u16]) -> Result<Vec<u8>, ExfatRestoreError> {
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(mappings.len() * 2)
        .map_err(|_| ExfatRestoreError::AllocationFailed)?;
    let mut index = 0_usize;
    while index < mappings.len() {
        let code_unit = u16::try_from(index).map_err(|_| ExfatRestoreError::AllocationFailed)?;
        if mappings[index] == code_unit {
            let mut run = 0_usize;
            while index + run < mappings.len()
                && u16::try_from(index + run).is_ok_and(|unit| mappings[index + run] == unit)
            {
                run += 1;
            }
            if run >= 2 {
                encoded.extend_from_slice(&COMPRESSION_MARKER.to_le_bytes());
                encoded.extend_from_slice(
                    &u16::try_from(run)
                        .map_err(|_| ExfatRestoreError::AllocationFailed)?
                        .to_le_bytes(),
                );
                index += run;
                continue;
            }
        }
        encoded.extend_from_slice(&mappings[index].to_le_bytes());
        index += 1;
    }
    Ok(encoded)
}

fn path_from_entries(
    entries: &[NamespaceEntry],
    root: ObjectId,
    id: ObjectId,
) -> Result<Vec<Vec<u16>>, ExfatRestoreError> {
    let mut path = Vec::new();
    let mut current = id;
    let mut seen = BTreeSet::new();
    while current != root {
        if !seen.insert(current) {
            return Err(ExfatRestoreError::AmbiguousDestinationNames(id));
        }
        let targeting: Vec<&NamespaceEntry> = entries
            .iter()
            .filter(|entry| entry.target == current)
            .collect();
        if targeting.len() != 1 {
            return Err(ExfatRestoreError::AmbiguousDestinationNames(current));
        }
        path.push(targeting[0].name.clone());
        current = targeting[0].parent;
    }
    path.reverse();
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extent::{ExtentGraph, StreamId};
    use crate::fs::exfat_inventory::ExfatTimestamps;
    use crate::fs::exfat_upcase::{UpcaseLimits, UpcaseTable};
    use crate::object::{
        ObjectGraphLimits, ObjectRecord, ObjectSemantics, ObjectStream, StreamFlags, StreamStorage,
    };
    use crate::preservation::ExfatRestoreObject;

    fn graph() -> ObjectGraph {
        let root = ObjectId(5);
        let dir = ObjectId(40);
        let file = ObjectId(41);
        let stream = |id: u64| ObjectStream {
            id: StreamId(id),
            name: None,
            logical_bytes: 0,
            initialized_bytes: 0,
            mapped_bytes: 0,
            allocated_bytes: 0,
            flags: StreamFlags::default(),
            storage: StreamStorage::Resident(Vec::new()),
        };
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
                    id: dir,
                    kind: ObjectKind::Directory,
                    link_count: 1,
                    semantics: ObjectSemantics::default(),
                    streams: Vec::new(),
                },
                ObjectRecord {
                    id: file,
                    kind: ObjectKind::File,
                    link_count: 1,
                    semantics: ObjectSemantics::default(),
                    streams: vec![stream(41)],
                },
            ],
            vec![
                NamespaceEntry {
                    parent: root,
                    target: dir,
                    name: "alpha".encode_utf16().collect(),
                },
                NamespaceEntry {
                    parent: dir,
                    target: file,
                    name: "readme.txt".encode_utf16().collect(),
                },
            ],
            ExtentGraph::build(Vec::new(), 4 * 1024 * 1024, 8).unwrap(),
            ObjectGraphLimits {
                max_objects: 8,
                max_entries: 8,
                max_streams: 8,
                max_name_code_units: 255,
            },
        )
        .unwrap()
    }

    const fn timestamps(seed: u32) -> ExfatTimestamps {
        ExfatTimestamps {
            create: seed,
            modified: seed + 1,
            accessed: seed + 2,
            create_centiseconds: 7,
            modified_centiseconds: 199,
            create_utc_offset: 0xa0,
            modified_utc_offset: 0x90,
            accessed_utc_offset: 0x80,
        }
    }

    fn sidecar() -> ExfatRestoreSidecar {
        let recommended =
            generate_recommended_exfat_upcase(RecommendedExfatUpcaseLimits::default()).unwrap();
        ExfatRestoreSidecar {
            volume_serial_number: 0x1234_5678,
            volume_label: ExfatVolumeLabelIdentity::Exact("ORIGIN".encode_utf16().collect()),
            upcase_checksum: RECOMMENDED_EXFAT_UPCASE_CHECKSUM,
            upcase_mappings: recommended.mappings().to_vec(),
            objects: vec![
                ExfatRestoreObject {
                    path: Vec::new(),
                    file_attributes: 0x10,
                    timestamps: None,
                    benign_secondary_entries: 0,
                },
                ExfatRestoreObject {
                    path: vec!["alpha".encode_utf16().collect()],
                    file_attributes: 0x10,
                    timestamps: Some(timestamps(0x5d47_b0d7)),
                    benign_secondary_entries: 0,
                },
                ExfatRestoreObject {
                    path: vec![
                        "alpha".encode_utf16().collect(),
                        "readme.txt".encode_utf16().collect(),
                    ],
                    file_attributes: 0x21,
                    timestamps: Some(timestamps(0x5d47_b0e0)),
                    benign_secondary_entries: 0,
                },
            ],
            benign_primary_sets: 0,
            benign_secondary_entries: 0,
        }
    }

    #[test]
    fn restores_exact_metadata_by_path_and_the_recommended_upcase_verbatim() {
        let restored = restore_exfat_identities(&graph(), &sidecar()).unwrap();
        assert_eq!(restored.volume_serial_number, 0x1234_5678);
        assert_eq!(
            restored.volume_label,
            Some("ORIGIN".encode_utf16().collect::<Vec<u16>>())
        );
        assert_eq!(restored.upcase_checksum, RECOMMENDED_EXFAT_UPCASE_CHECKSUM);
        assert_eq!(restored.encoded_upcase_table.len(), 5836);
        assert_eq!(restored.object_metadata.len(), 2);
        let file = &restored.object_metadata[&ObjectId(41)];
        assert_eq!(file.file_attributes, 0x21);
        assert_eq!(file.timestamps, timestamps(0x5d47_b0e0));
        assert_eq!(
            restored.object_metadata[&ObjectId(40)].timestamps,
            timestamps(0x5d47_b0d7)
        );
    }

    #[test]
    fn refuses_kind_mismatch_missing_path_missing_timestamps_and_vendor_entries() {
        let mut flipped = sidecar();
        flipped.objects[2].file_attributes = 0x30;
        assert_eq!(
            restore_exfat_identities(&graph(), &flipped),
            Err(ExfatRestoreError::KindMismatch(ObjectId(41)))
        );

        let mut missing = sidecar();
        missing.objects[2].path[1] = "gone.txt".encode_utf16().collect();
        assert!(matches!(
            restore_exfat_identities(&graph(), &missing),
            Err(ExfatRestoreError::MissingDestinationPath(_))
        ));

        let mut no_time = sidecar();
        no_time.objects[1].timestamps = None;
        assert_eq!(
            restore_exfat_identities(&graph(), &no_time),
            Err(ExfatRestoreError::MissingTimestamps(ObjectId(40)))
        );

        let mut vendor = sidecar();
        vendor.benign_secondary_entries = 1;
        assert!(matches!(
            restore_exfat_identities(&graph(), &vendor),
            Err(ExfatRestoreError::BenignEntriesNotRestorable { .. })
        ));
    }

    #[test]
    fn unknown_dest_objects_keep_their_derived_metadata() {
        let mut partial = sidecar();
        partial.objects.pop();
        let restored = restore_exfat_identities(&graph(), &partial).unwrap();
        assert_eq!(restored.object_metadata.len(), 1);
        assert!(!restored.object_metadata.contains_key(&ObjectId(41)));
    }

    #[test]
    fn custom_upcase_mappings_are_reencoded_and_checked_against_the_recorded_checksum() {
        let mut mappings: Vec<u16> = (0..=u16::MAX).collect();
        for unit in b'a'..=b'z' {
            mappings[usize::from(unit)] = u16::from(unit - 32);
        }
        // One extra non-identity mapping that Table 25 lacks makes the table custom.
        mappings[0x0101] = 0x0100;
        let encoded = compress_upcase_mappings(&mappings).unwrap();
        let checksum = table_checksum(&encoded);
        let parsed = UpcaseTable::parse(
            &encoded,
            checksum,
            UpcaseLimits {
                max_encoded_bytes: encoded.len(),
                max_mappings: UNICODE_MAPPING_COUNT,
            },
        )
        .expect("re-encoded custom table round-trips through the parser");
        assert_eq!(parsed.mappings(), mappings.as_slice());

        let mut custom = sidecar();
        custom.upcase_mappings = mappings;
        custom.upcase_checksum = checksum;
        let restored = restore_exfat_identities(&graph(), &custom).unwrap();
        assert_eq!(restored.encoded_upcase_table, encoded);

        custom.upcase_checksum ^= 1;
        assert!(matches!(
            restore_exfat_identities(&graph(), &custom),
            Err(ExfatRestoreError::UpcaseTableNotReproducible { .. })
        ));
    }

    #[test]
    fn literally_encoded_source_tables_are_reproduced_from_their_checksum() {
        let mut mappings: Vec<u16> = (0..=u16::MAX).collect();
        for unit in b'a'..=b'z' {
            mappings[usize::from(unit)] = u16::from(unit - 32);
        }
        let literal = literal_upcase_mappings(&mappings).unwrap();
        assert_eq!(literal.len(), UNICODE_MAPPING_COUNT * 2);
        let checksum = table_checksum(&literal);
        assert_ne!(
            checksum,
            table_checksum(&compress_upcase_mappings(&mappings).unwrap())
        );
        let parsed = UpcaseTable::parse(
            &literal,
            checksum,
            UpcaseLimits {
                max_encoded_bytes: literal.len(),
                max_mappings: UNICODE_MAPPING_COUNT,
            },
        )
        .expect("literal table parses");
        assert_eq!(parsed.mappings(), mappings.as_slice());

        let mut custom = sidecar();
        custom.upcase_mappings = mappings;
        custom.upcase_checksum = checksum;
        let restored = restore_exfat_identities(&graph(), &custom).unwrap();
        assert_eq!(restored.encoded_upcase_table, literal);
        assert_eq!(restored.upcase_checksum, checksum);
    }

    #[test]
    fn trailing_identity_marker_is_encoded_literally() {
        let mut mappings: Vec<u16> = (0..=u16::MAX).collect();
        for unit in b'a'..=b'z' {
            mappings[usize::from(unit)] = u16::from(unit - 32);
        }
        mappings[0xfffe] = 0x0041;
        let encoded = compress_upcase_mappings(&mappings).unwrap();
        assert_eq!(&encoded[encoded.len() - 2..], &0xffff_u16.to_le_bytes());
        let checksum = table_checksum(&encoded);
        let parsed = UpcaseTable::parse(
            &encoded,
            checksum,
            UpcaseLimits {
                max_encoded_bytes: encoded.len(),
                max_mappings: UNICODE_MAPPING_COUNT,
            },
        )
        .unwrap();
        assert_eq!(parsed.mappings(), mappings.as_slice());
    }
}
