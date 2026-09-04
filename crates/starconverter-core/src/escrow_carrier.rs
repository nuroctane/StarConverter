//! Dest-native carrier files for NTFS named `$DATA` payloads that the escrow sidecar cannot hold.
//!
//! exFAT has no alternate-data-stream namespace. Resident named streams and small non-resident
//! named streams are captured byte-for-byte inside the schema-v4 escrow sidecar. Named streams
//! above the inventory capture cap (or whose mapping is sparse or NTFS-compressed) are instead
//! projected onto the exFAT destination as ordinary hidden+system files under one root-level
//! escrow directory. Their bytes travel through the same sealed relocation/materialization path as
//! unnamed payloads, and the exFAT→NTFS restore reattaches each carrier as the original named
//! stream before deleting the carrier and its directory.
//!
//! Both directions derive carrier identity from the same sidecar evidence, so no schema change is
//! needed: the carrier name is a pure function of the source MFT record number and the `$DATA`
//! attribute instance identifier that already live in the inner NTFS snapshot.

use crate::fs::ntfs_inventory::{NtfsDataStream, NtfsObject, NtfsStreamStorage};
use crate::fs::ntfs_normalize::NtfsPreservationSidecar;
use crate::object::ObjectId;

/// Root-level exFAT directory that holds every escrow carrier file.
pub const ESCROW_CARRIER_DIRECTORY: &str = ".starconverter-escrow";

const NTFS_ROOT_RECORD: u64 = 5;
const NTFS_EXTEND_RECORD: u64 = 11;

/// One named stream that must travel as a dest-native carrier file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EscrowCarrier {
    /// Sidecar object (source MFT record number) owning the named stream.
    pub owner: ObjectId,
    /// `$DATA` attribute instance identifier of the named stream inside that record.
    pub attribute_id: u16,
    /// Exact UTF-16 stream name.
    pub stream_name: Vec<u16>,
    /// Logical stream length (`data_bytes`).
    pub data_bytes: u64,
}

impl EscrowCarrier {
    /// Dest-native carrier file name, unique per (record, attribute) pair.
    #[must_use]
    pub fn file_name(&self) -> Vec<u16> {
        carrier_file_name(self.owner.0, self.attribute_id)
    }

    /// Dest-native path (`[directory, file]`) of the carrier.
    #[must_use]
    pub fn path(&self) -> Vec<Vec<u16>> {
        vec![carrier_directory_name(), self.file_name()]
    }
}

/// UTF-16 [`ESCROW_CARRIER_DIRECTORY`].
#[must_use]
pub fn carrier_directory_name() -> Vec<u16> {
    ESCROW_CARRIER_DIRECTORY.encode_utf16().collect()
}

/// UTF-16 carrier file name for one named stream: `r<record>-a<attribute>.ads`.
#[must_use]
pub fn carrier_file_name(record: u64, attribute_id: u16) -> Vec<u16> {
    format!("r{record}-a{attribute_id}.ads")
        .encode_utf16()
        .collect()
}

/// Whether `stream` is a named stream whose bytes are neither resident nor captured in the sidecar
/// and therefore must be carried as a dest-native file.
///
/// Encrypted streams are never carried: their plaintext is unavailable and preservation policy
/// refuses them independently.
#[must_use]
pub const fn needs_carrier(stream: &NtfsDataStream) -> bool {
    if stream.name.is_none() || stream.encrypted {
        return false;
    }
    match &stream.storage {
        NtfsStreamStorage::Resident { .. } => false,
        NtfsStreamStorage::NonResident {
            data_bytes,
            captured_payload,
            ..
        } => captured_payload.is_none() && *data_bytes > 0,
    }
}

/// Same membership as NTFS normalization and escrow restore: root plus non-metadata objects except
/// `$Extend`, minus the root itself (which carries no restorable identities).
const fn is_restorable_graph_object(source: &NtfsObject) -> bool {
    let record = source.reference.record_number;
    record != NTFS_ROOT_RECORD && !source.is_metadata && record != NTFS_EXTEND_RECORD
}

/// Every carrier the sidecar implies, in `(owner, attribute_id)` order.
#[must_use]
pub fn sidecar_carriers(sidecar: &NtfsPreservationSidecar) -> Vec<EscrowCarrier> {
    let mut carriers: Vec<EscrowCarrier> = sidecar
        .objects
        .iter()
        .filter(|preserved| is_restorable_graph_object(&preserved.source))
        .flat_map(|preserved| {
            preserved
                .source
                .data_streams
                .iter()
                .filter(|stream| needs_carrier(stream))
                .map(move |stream| EscrowCarrier {
                    owner: preserved.object,
                    attribute_id: stream.attribute_id,
                    stream_name: stream
                        .name
                        .as_ref()
                        .map(|name| name.code_units.clone())
                        .unwrap_or_default(),
                    data_bytes: match &stream.storage {
                        NtfsStreamStorage::Resident { bytes } => {
                            u64::try_from(bytes.len()).unwrap_or(u64::MAX)
                        }
                        NtfsStreamStorage::NonResident { data_bytes, .. } => *data_bytes,
                    },
                })
        })
        .collect();
    carriers.sort_by_key(|carrier| (carrier.owner, carrier.attribute_id));
    carriers
}

/// Case-insensitive (ASCII) equality against the carrier directory name, used to refuse a source
/// root entry that would collide with the escrow directory under any exFAT up-case table.
#[must_use]
pub fn collides_with_carrier_directory(name: &[u16]) -> bool {
    let directory = carrier_directory_name();
    name.len() == directory.len()
        && name.iter().zip(directory.iter()).all(|(left, right)| {
            let fold = |unit: u16| {
                u8::try_from(unit).map_or(unit, |byte| u16::from(byte.to_ascii_uppercase()))
            };
            fold(*left) == fold(*right)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::ntfs_inventory::NtfsName;

    fn named(name: &str) -> NtfsName {
        NtfsName {
            code_units: name.encode_utf16().collect(),
            is_well_formed: true,
        }
    }

    fn non_resident(name: Option<NtfsName>, data_bytes: u64, captured: bool) -> NtfsDataStream {
        NtfsDataStream {
            attribute_id: 3,
            name,
            compressed: false,
            encrypted: false,
            sparse: false,
            compression_block_bytes: 0,
            storage: NtfsStreamStorage::NonResident {
                allocated_bytes: data_bytes.div_ceil(4096) * 4096,
                data_bytes,
                initialized_bytes: data_bytes,
                compressed_bytes: None,
                mapping_complete: true,
                extents: Vec::new(),
                captured_payload: captured
                    .then(|| vec![0_u8; usize::try_from(data_bytes).unwrap()]),
            },
        }
    }

    #[test]
    fn only_uncaptured_nonempty_named_streams_need_carriers() {
        assert!(needs_carrier(&non_resident(
            Some(named("fork")),
            8192,
            false
        )));
        assert!(!needs_carrier(&non_resident(
            Some(named("fork")),
            8192,
            true
        )));
        assert!(!needs_carrier(&non_resident(Some(named("fork")), 0, false)));
        assert!(!needs_carrier(&non_resident(None, 8192, false)));
        let mut encrypted = non_resident(Some(named("fork")), 8192, false);
        encrypted.encrypted = true;
        assert!(!needs_carrier(&encrypted));
        let resident = NtfsDataStream {
            storage: NtfsStreamStorage::Resident { bytes: vec![1, 2] },
            ..non_resident(Some(named("fork")), 2, false)
        };
        assert!(!needs_carrier(&resident));
    }

    #[test]
    fn carrier_names_are_deterministic_and_legal() {
        let name = String::from_utf16(&carrier_file_name(64, 7)).unwrap();
        assert_eq!(name, "r64-a7.ads");
        assert!(collides_with_carrier_directory(
            &".STARCONVERTER-ESCROW".encode_utf16().collect::<Vec<u16>>()
        ));
        assert!(!collides_with_carrier_directory(
            &".starconverter-escrow2"
                .encode_utf16()
                .collect::<Vec<u16>>()
        ));
        let carrier = EscrowCarrier {
            owner: ObjectId(64),
            attribute_id: 7,
            stream_name: "fork".encode_utf16().collect(),
            data_bytes: 1,
        };
        assert_eq!(
            carrier.path(),
            vec![carrier_directory_name(), carrier_file_name(64, 7)]
        );
    }
}
