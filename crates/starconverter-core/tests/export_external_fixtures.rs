//! Opt-in regular-file fixtures for independent read-only validator experiments.
//!
//! These are structural serializer fixtures, not activation-ready conversion images. Run with:
//! `cargo test -p starconverter-core --test export_external_fixtures -- --ignored --nocapture`.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use starconverter_core::candidate_export::{
    CandidateExportEvidence, CandidateExportLimits, capture_source_image_snapshot,
    decode_bound_escrow, export_relocated_candidate_image,
};
use starconverter_core::cross_format::{
    ExfatToNtfsLimits, ExfatToNtfsOptions, NtfsToExfatLimits, NtfsToExfatOptions,
    draft_lossless_exfat_to_ntfs, draft_lossless_ntfs_to_exfat, solve_lossless_exfat_to_ntfs,
    solve_lossless_ntfs_to_exfat,
};
use starconverter_core::extent::{Extent, ExtentGraph, ExtentKind, Placement, StreamId};
use starconverter_core::fs::exfat_inventory::{ExfatPreservationEvidence, ExfatTimestamps};
use starconverter_core::fs::exfat_serialize::{
    ExfatObjectMetadata, ExfatSerializeLimits, ExfatSerializeOptions, ExfatVolumeProfile,
    serialize_exfat_destination,
};
use starconverter_core::fs::exfat_upcase_serialize::{
    RECOMMENDED_EXFAT_UPCASE_PROFILE, RecommendedExfatUpcaseLimits,
    generate_recommended_exfat_upcase,
};
use starconverter_core::fs::ntfs_index::{NtfsIndexLimits, parse_index_block};
use starconverter_core::fs::ntfs_serialize::{
    NtfsDestinationInputs, NtfsSerializeLimits, plan_ntfs_destination,
};
use starconverter_core::fs::ntfs_upcase_serialize;
use starconverter_core::geometry::LayoutLimits;
use starconverter_core::inspect::BootSector;
use starconverter_core::object::{
    NamespaceEntry, ObjectGraph, ObjectGraphLimits, ObjectId, ObjectKind, ObjectRecord,
    ObjectSemantics, ObjectStream, StreamFlags, StreamStorage,
};
use starconverter_core::overlay::OverlayWrite;
use starconverter_core::phase::{preview_exfat_phase_writes, preview_ntfs_phase_writes};
use starconverter_core::preimage::PreimageLimits;
use starconverter_core::validation_vhd::{
    FixedVhdConfig, FixedVhdLimits, ONE_MIB_PARTITION_ALIGNMENT_SECTORS, wrap_fixed_vhd,
};
use starconverter_core::{
    GuaranteeMode, image::ImageFile, inspect::inspect_open_image, windows_validation,
};

const IMAGE_BYTES: u64 = 32 * 1024 * 1024;
const GRAPH_LIMITS: ObjectGraphLimits = ObjectGraphLimits {
    max_objects: 64,
    max_entries: 64,
    max_streams: 64,
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
        Vec::new(),
        ExtentGraph::build(Vec::new(), IMAGE_BYTES, 8).unwrap(),
        GRAPH_LIMITS,
    )
    .unwrap()
}

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

const fn rich_timestamp() -> ExfatTimestamps {
    ExfatTimestamps {
        create: packed_timestamp(2026, 8, 20, 12, 34, 56),
        modified: packed_timestamp(2026, 8, 20, 13, 35, 58),
        accessed: packed_timestamp(2026, 8, 21, 9, 10, 12),
        create_centiseconds: 78,
        modified_centiseconds: 12,
        create_utc_offset: 0x80,
        modified_utc_offset: 0x80,
        accessed_utc_offset: 0x80,
    }
}

#[allow(clippy::too_many_lines)]
fn rich_graph() -> (ObjectGraph, Vec<ExfatObjectMetadata>) {
    let root = ObjectId(1);
    let directory = |id| ObjectRecord {
        id: ObjectId(id),
        kind: ObjectKind::Directory,
        link_count: 1,
        semantics: ObjectSemantics::default(),
        streams: Vec::new(),
    };
    let extent_file = |id, stream, logical, mapped| ObjectRecord {
        id: ObjectId(id),
        kind: ObjectKind::File,
        link_count: 1,
        semantics: ObjectSemantics::default(),
        streams: vec![ObjectStream {
            id: StreamId(stream),
            name: None,
            logical_bytes: logical,
            initialized_bytes: logical,
            mapped_bytes: mapped,
            allocated_bytes: mapped,
            flags: StreamFlags::default(),
            storage: StreamStorage::Extents,
        }],
    };
    let objects = vec![
        ObjectRecord {
            id: root,
            kind: ObjectKind::Directory,
            link_count: 0,
            semantics: ObjectSemantics::default(),
            streams: Vec::new(),
        },
        directory(2),
        directory(3),
        extent_file(4, 40, 14, 4096),
        extent_file(5, 50, 6000, 8192),
        ObjectRecord {
            id: ObjectId(6),
            kind: ObjectKind::File,
            link_count: 1,
            semantics: ObjectSemantics::default(),
            streams: vec![ObjectStream {
                id: StreamId(60),
                name: None,
                logical_bytes: 0,
                initialized_bytes: 0,
                mapped_bytes: 0,
                allocated_bytes: 0,
                flags: StreamFlags::default(),
                storage: StreamStorage::Resident(Vec::new()),
            }],
        },
    ];
    let entries = vec![
        NamespaceEntry {
            parent: root,
            target: ObjectId(2),
            name: "alpha".encode_utf16().collect(),
        },
        NamespaceEntry {
            parent: ObjectId(2),
            target: ObjectId(3),
            name: "Ωmega".encode_utf16().collect(),
        },
        NamespaceEntry {
            parent: root,
            target: ObjectId(4),
            name: "readme.txt".encode_utf16().collect(),
        },
        NamespaceEntry {
            parent: ObjectId(3),
            target: ObjectId(5),
            name: "fragmented.bin".encode_utf16().collect(),
        },
        NamespaceEntry {
            parent: ObjectId(2),
            target: ObjectId(6),
            name: "empty.dat".encode_utf16().collect(),
        },
    ];
    let extents = vec![
        Extent {
            stream: StreamId(40),
            logical_offset: 0,
            length: 4096,
            placement: Placement::Physical {
                byte_offset: 24 * 1024 * 1024,
            },
            kind: ExtentKind::FileData,
        },
        Extent {
            stream: StreamId(50),
            logical_offset: 0,
            length: 4096,
            placement: Placement::Physical {
                byte_offset: 25 * 1024 * 1024,
            },
            kind: ExtentKind::FileData,
        },
        Extent {
            stream: StreamId(50),
            logical_offset: 4096,
            length: 4096,
            placement: Placement::Physical {
                byte_offset: 27 * 1024 * 1024,
            },
            kind: ExtentKind::FileData,
        },
    ];
    let graph = ObjectGraph::build(
        root,
        objects,
        entries,
        ExtentGraph::build(extents, IMAGE_BYTES, GRAPH_LIMITS.max_streams).unwrap(),
        GRAPH_LIMITS,
    )
    .unwrap();
    let metadata = graph
        .objects()
        .iter()
        .filter(|object| object.id != root)
        .map(|object| ExfatObjectMetadata {
            object: object.id,
            file_attributes: match object.kind {
                ObjectKind::Directory => 0x11,
                ObjectKind::File => 0x21,
            },
            timestamps: rich_timestamp(),
        })
        .collect();
    (graph, metadata)
}

#[allow(clippy::too_many_lines)]
fn edge_graph() -> (ObjectGraph, Vec<ExfatObjectMetadata>) {
    let root = ObjectId(1);
    let directory = |id| ObjectRecord {
        id: ObjectId(id),
        kind: ObjectKind::Directory,
        link_count: 1,
        semantics: ObjectSemantics::default(),
        streams: Vec::new(),
    };
    let extent_file = |id, stream, logical, mapped| ObjectRecord {
        id: ObjectId(id),
        kind: ObjectKind::File,
        link_count: 1,
        semantics: ObjectSemantics::default(),
        streams: vec![ObjectStream {
            id: StreamId(stream),
            name: None,
            logical_bytes: logical,
            initialized_bytes: logical,
            mapped_bytes: mapped,
            allocated_bytes: mapped,
            flags: StreamFlags::default(),
            storage: StreamStorage::Extents,
        }],
    };
    let objects = vec![
        ObjectRecord {
            id: root,
            kind: ObjectKind::Directory,
            link_count: 0,
            semantics: ObjectSemantics::default(),
            streams: Vec::new(),
        },
        directory(2),
        directory(3),
        ObjectRecord {
            id: ObjectId(4),
            kind: ObjectKind::File,
            link_count: 1,
            semantics: ObjectSemantics::default(),
            streams: vec![ObjectStream {
                id: StreamId(40),
                name: None,
                logical_bytes: 0,
                initialized_bytes: 0,
                mapped_bytes: 0,
                allocated_bytes: 0,
                flags: StreamFlags::default(),
                storage: StreamStorage::Resident(Vec::new()),
            }],
        },
        extent_file(5, 50, 1, 4096),
        extent_file(6, 60, 4095, 4096),
        extent_file(7, 70, 4096, 4096),
        extent_file(8, 80, 4097, 8192),
        extent_file(9, 90, 8191, 8192),
        extent_file(10, 100, 9000, 12_288),
        extent_file(11, 110, 17, 4096),
        extent_file(12, 120, 33, 4096),
        extent_file(13, 130, 65, 4096),
    ];
    let long_name = format!("{}.bin", "n".repeat(251));
    let entries = vec![
        NamespaceEntry {
            parent: root,
            target: ObjectId(2),
            name: "δelta".encode_utf16().collect(),
        },
        NamespaceEntry {
            parent: ObjectId(2),
            target: ObjectId(3),
            name: "深度".encode_utf16().collect(),
        },
        NamespaceEntry {
            parent: root,
            target: ObjectId(4),
            name: "empty.zero".encode_utf16().collect(),
        },
        NamespaceEntry {
            parent: ObjectId(2),
            target: ObjectId(5),
            name: "one.bin".encode_utf16().collect(),
        },
        NamespaceEntry {
            parent: ObjectId(2),
            target: ObjectId(6),
            name: "sector-minus-one.bin".encode_utf16().collect(),
        },
        NamespaceEntry {
            parent: ObjectId(2),
            target: ObjectId(7),
            name: "sector.bin".encode_utf16().collect(),
        },
        NamespaceEntry {
            parent: ObjectId(2),
            target: ObjectId(8),
            name: "cluster-plus-one.bin".encode_utf16().collect(),
        },
        NamespaceEntry {
            parent: ObjectId(3),
            target: ObjectId(9),
            name: "two-cluster-minus-one.bin".encode_utf16().collect(),
        },
        NamespaceEntry {
            parent: ObjectId(3),
            target: ObjectId(10),
            name: "three-way-fragmented.bin".encode_utf16().collect(),
        },
        NamespaceEntry {
            parent: root,
            target: ObjectId(11),
            name: long_name.encode_utf16().collect(),
        },
        NamespaceEntry {
            parent: ObjectId(3),
            target: ObjectId(12),
            name: "rocket-🚀.bin".encode_utf16().collect(),
        },
        NamespaceEntry {
            parent: root,
            target: ObjectId(13),
            name: "Straße.txt".encode_utf16().collect(),
        },
    ];
    let physical = |stream, logical_offset, length, byte_offset| Extent {
        stream: StreamId(stream),
        logical_offset,
        length,
        placement: Placement::Physical { byte_offset },
        kind: ExtentKind::FileData,
    };
    let mib = 1024 * 1024;
    let extents = vec![
        physical(50, 0, 4096, 16 * mib),
        physical(60, 0, 4096, 17 * mib),
        physical(70, 0, 4096, 18 * mib),
        physical(80, 0, 8192, 19 * mib),
        physical(90, 0, 8192, 20 * mib),
        physical(100, 0, 4096, 22 * mib),
        physical(100, 4096, 4096, 24 * mib),
        physical(100, 8192, 4096, 26 * mib),
        physical(110, 0, 4096, 27 * mib),
        physical(120, 0, 4096, 28 * mib),
        physical(130, 0, 4096, 29 * mib),
    ];
    let graph = ObjectGraph::build(
        root,
        objects,
        entries,
        ExtentGraph::build(extents, IMAGE_BYTES, GRAPH_LIMITS.max_streams).unwrap(),
        GRAPH_LIMITS,
    )
    .unwrap();
    let metadata = graph
        .objects()
        .iter()
        .filter(|object| object.id != root)
        .map(|object| ExfatObjectMetadata {
            object: object.id,
            file_attributes: match object.kind {
                ObjectKind::Directory => 0x11,
                ObjectKind::File => 0x20 | (1 << ((object.id.0 - 4) % 3)),
            },
            timestamps: rich_timestamp(),
        })
        .collect();
    (graph, metadata)
}

fn payload_digest(stream: u64, logical_bytes: u64) -> String {
    let mut hasher = Sha256::new();
    for logical_offset in 0..logical_bytes {
        hasher.update([u8::try_from((stream + logical_offset) % 251).unwrap()]);
    }
    let mut output = String::with_capacity(64);
    for byte in hasher.finalize() {
        write!(&mut output, "{byte:02x}").unwrap();
    }
    output
}

fn misaligned_relocation_graph() -> ObjectGraph {
    const STREAM: u64 = 140;
    const PAYLOAD_BYTES: u64 = 8192;
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
                    id: StreamId(STREAM),
                    name: None,
                    logical_bytes: PAYLOAD_BYTES,
                    initialized_bytes: PAYLOAD_BYTES,
                    mapped_bytes: PAYLOAD_BYTES,
                    allocated_bytes: PAYLOAD_BYTES,
                    flags: StreamFlags::default(),
                    storage: StreamStorage::Extents,
                }],
            },
        ],
        vec![NamespaceEntry {
            parent: ObjectId(1),
            target: ObjectId(2),
            name: "relocated.bin".encode_utf16().collect(),
        }],
        ExtentGraph::build(
            vec![Extent {
                stream: StreamId(STREAM),
                logical_offset: 0,
                length: PAYLOAD_BYTES,
                placement: Placement::Physical {
                    // Valid for 4 KiB NTFS, deliberately misaligned for the 8 KiB exFAT target.
                    byte_offset: 24 * 1024 * 1024 + 4096,
                },
                kind: ExtentKind::FileData,
            }],
            IMAGE_BYTES,
            GRAPH_LIMITS.max_streams,
        )
        .unwrap(),
        GRAPH_LIMITS,
    )
    .unwrap()
}

fn misaligned_relocation_manifest() -> String {
    format!("/relocated.bin\t8192\t{}\n", payload_digest(140, 8192))
}

fn edge_manifest() -> String {
    let long_name = format!("{}.bin", "n".repeat(251));
    let files = [
        ("/empty.zero".to_owned(), 40, 0),
        ("/δelta/one.bin".to_owned(), 50, 1),
        ("/δelta/sector-minus-one.bin".to_owned(), 60, 4095),
        ("/δelta/sector.bin".to_owned(), 70, 4096),
        ("/δelta/cluster-plus-one.bin".to_owned(), 80, 4097),
        ("/δelta/深度/two-cluster-minus-one.bin".to_owned(), 90, 8191),
        ("/δelta/深度/three-way-fragmented.bin".to_owned(), 100, 9000),
        (format!("/{long_name}"), 110, 17),
        ("/δelta/深度/rocket-🚀.bin".to_owned(), 120, 33),
        ("/Straße.txt".to_owned(), 130, 65),
    ];
    let mut output = String::new();
    for (path, stream, logical_bytes) in files {
        writeln!(
            &mut output,
            "{path}\t{logical_bytes}\t{}",
            payload_digest(stream, logical_bytes)
        )
        .unwrap();
    }
    output
}

fn apply(image: &mut [u8], write: &OverlayWrite) {
    let offset = usize::try_from(write.offset).unwrap();
    image[offset..offset + write.bytes.len()].copy_from_slice(&write.bytes);
}

fn fixture_directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("target")
        .join("external-validator-fixtures")
}

fn base_image(graph: &ObjectGraph) -> Vec<u8> {
    let mut image = vec![0_u8; usize::try_from(IMAGE_BYTES).unwrap()];
    for extent in graph.extents().extents() {
        let Placement::Physical { byte_offset } = extent.placement else {
            continue;
        };
        let start = usize::try_from(byte_offset).unwrap();
        let meaningful = graph
            .objects()
            .iter()
            .flat_map(|object| &object.streams)
            .find(|stream| stream.id == extent.stream)
            .map_or(0, |stream| {
                stream
                    .logical_bytes
                    .saturating_sub(extent.logical_offset)
                    .min(extent.length)
            });
        for index in 0..usize::try_from(meaningful).unwrap() {
            image[start + index] = u8::try_from(
                (extent.stream.0 + extent.logical_offset + u64::try_from(index).unwrap()) % 251,
            )
            .unwrap();
        }
    }
    image
}

fn exfat_image(
    graph: &ObjectGraph,
    metadata: &[ExfatObjectMetadata],
    upcase: &[u8],
    partition_offset_sectors: u64,
) -> Vec<u8> {
    let exfat = serialize_exfat_destination(
        graph,
        metadata,
        ExfatVolumeProfile {
            volume_label: None,
            encoded_upcase_table: upcase,
            upcase_checksum: RECOMMENDED_EXFAT_UPCASE_PROFILE.table_checksum,
            source_preservation: ExfatPreservationEvidence::default(),
            allocated_bad_clusters: 0,
            bad_cluster_ranges: &[],
        },
        ExfatSerializeOptions {
            partition_offset_sectors,
            ..ExfatSerializeOptions::default()
        },
        ExfatSerializeLimits::default(),
    )
    .unwrap();
    assert!(!exfat.activation_ready());
    let mut image = base_image(graph);
    for write in exfat.overlay.writes() {
        apply(&mut image, write);
    }
    image
}

fn ntfs_image(graph: &ObjectGraph, partition_offset_sectors: u64) -> Vec<u8> {
    ntfs_image_with_cluster(graph, partition_offset_sectors, 4096)
}

fn ntfs_image_with_cluster(
    graph: &ObjectGraph,
    partition_offset_sectors: u64,
    cluster_bytes: u32,
) -> Vec<u8> {
    let ntfs = plan_ntfs_destination(
        graph,
        NtfsDestinationInputs {
            image_bytes: IMAGE_BYTES,
            cluster_bytes,
            partition_offset_sectors,
            volume_serial_number: 0x1122_3344_5566_7788,
            // 2026-08-20 12:34:56 UTC as a deterministic NTFS FILETIME. Keeping the fixture inside
            // exFAT's calendar range lets the bidirectional preview exercise timestamp mapping.
            timestamp: 134_317_028_960_000_000,
        },
        NtfsSerializeLimits::default(),
    )
    .unwrap();
    assert!(!ntfs.activation_ready());
    let mut image = base_image(graph);
    for write in &ntfs.staging_writes {
        apply(&mut image, write);
    }
    apply(&mut image, &ntfs.backup_boot_write);
    apply(&mut image, &ntfs.primary_boot_write);
    image
}

const fn vhd_config(unique_id: [u8; 16], disk_signature: u32) -> FixedVhdConfig {
    FixedVhdConfig {
        partition_offset_sectors: ONE_MIB_PARTITION_ALIGNMENT_SECTORS,
        mbr_disk_signature: disk_signature,
        footer_timestamp: 0x3141_5926,
        unique_id,
    }
}

fn export_ntfs_candidate(
    directory: &Path,
    source_path: &Path,
    output_name: &str,
    partition_offset_sectors: u64,
) -> CandidateExportEvidence {
    let output = directory.join(output_name);
    let escrow = directory.join(format!("{output_name}.starconverter-escrow"));
    for path in [&output, &escrow] {
        if path.exists() {
            fs::remove_file(path).unwrap();
        }
    }
    let source = ImageFile::open(source_path).unwrap();
    let inspection = inspect_open_image(&source).unwrap();
    let export_limits = CandidateExportLimits::default();
    let source_snapshot = capture_source_image_snapshot(&source, export_limits).unwrap();
    let normalized = inspection.normalized_exfat.as_deref().unwrap();
    let draft = draft_lossless_exfat_to_ntfs(
        normalized,
        GuaranteeMode::Escrow,
        ExfatToNtfsOptions {
            partition_offset_sectors,
            ..ExfatToNtfsOptions::default()
        },
        ExfatToNtfsLimits::default(),
    )
    .unwrap();
    let plan = solve_lossless_exfat_to_ntfs(draft, LayoutLimits::default()).unwrap();
    let preview =
        preview_ntfs_phase_writes(&source, &plan.destination, PreimageLimits::default()).unwrap();
    let evidence = export_relocated_candidate_image(
        &source,
        &output,
        Some(&escrow),
        &preview,
        &source_snapshot,
        plan.relocation(),
        &plan.preservation,
        export_limits,
    )
    .unwrap();
    let bound = decode_bound_escrow(&fs::read(&escrow).unwrap(), 64 * 1024 * 1024).unwrap();
    assert_eq!(bound.source_filesystem, plan.preservation.source);
    assert_eq!(bound.target_filesystem, plan.preservation.target);
    assert_eq!(bound.source_sha256, evidence.source_sha256);
    assert_eq!(bound.candidate_sha256, evidence.candidate_sha256);
    assert_eq!(bound.manifest_sha256, evidence.manifest_sha256);
    assert_eq!(
        Some(bound.preservation_payload.as_slice()),
        plan.preservation.escrow.as_deref()
    );
    evidence
}

fn export_exfat_candidate(
    directory: &Path,
    source_path: &Path,
    output_name: &str,
    partition_offset_sectors: u64,
    bytes_per_cluster: u32,
    expected_relocations: usize,
) -> CandidateExportEvidence {
    let output = directory.join(output_name);
    let escrow = directory.join(format!("{output_name}.starconverter-escrow"));
    for path in [&output, &escrow] {
        if path.exists() {
            fs::remove_file(path).unwrap();
        }
    }
    let source = ImageFile::open(source_path).unwrap();
    let inspection = inspect_open_image(&source).unwrap();
    let export_limits = CandidateExportLimits::default();
    let source_snapshot = capture_source_image_snapshot(&source, export_limits).unwrap();
    let normalized = inspection.normalized_ntfs.as_deref().unwrap();
    let draft = draft_lossless_ntfs_to_exfat(
        normalized,
        GuaranteeMode::Escrow,
        NtfsToExfatOptions {
            partition_offset_sectors,
            bytes_per_cluster,
            ..NtfsToExfatOptions::default()
        },
        NtfsToExfatLimits::default(),
    )
    .unwrap();
    let plan = solve_lossless_ntfs_to_exfat(draft, LayoutLimits::default()).unwrap();
    assert_eq!(plan.layout().relocations.len(), expected_relocations);
    let preview =
        preview_exfat_phase_writes(&source, &plan.destination, PreimageLimits::default()).unwrap();
    let evidence = export_relocated_candidate_image(
        &source,
        &output,
        Some(&escrow),
        &preview,
        &source_snapshot,
        plan.relocation(),
        &plan.preservation,
        export_limits,
    )
    .unwrap();
    let bound = decode_bound_escrow(&fs::read(&escrow).unwrap(), 64 * 1024 * 1024).unwrap();
    assert_eq!(bound.source_filesystem, plan.preservation.source);
    assert_eq!(bound.target_filesystem, plan.preservation.target);
    assert_eq!(bound.source_sha256, evidence.source_sha256);
    assert_eq!(bound.candidate_sha256, evidence.candidate_sha256);
    assert_eq!(bound.manifest_sha256, evidence.manifest_sha256);
    assert_eq!(
        Some(bound.preservation_payload.as_slice()),
        plan.preservation.escrow.as_deref()
    );
    evidence
}

fn export_windows_vhd_candidates(
    directory: &Path,
    rich_exfat_path: &Path,
    rich_ntfs_path: &Path,
) -> (PathBuf, PathBuf) {
    let ntfs_partition = export_ntfs_candidate(
        directory,
        rich_exfat_path,
        "converted-rich-exfat-to-ntfs-windows-partition.img",
        ONE_MIB_PARTITION_ALIGNMENT_SECTORS,
    );
    let ntfs_vhd = wrap_fixed_vhd(
        &fs::read(&ntfs_partition.output_path).unwrap(),
        vhd_config(*b"StarCvNtfsWin001", 0x5343_5754),
        FixedVhdLimits::default(),
    )
    .unwrap();
    let ntfs_path = directory.join("converted-rich-exfat-to-ntfs-windows.vhd");
    fs::write(&ntfs_path, ntfs_vhd.bytes).unwrap();

    let exfat_partition = export_exfat_candidate(
        directory,
        rich_ntfs_path,
        "converted-rich-ntfs-to-exfat-windows-partition.img",
        ONE_MIB_PARTITION_ALIGNMENT_SECTORS,
        4096,
        0,
    );
    let exfat_vhd = wrap_fixed_vhd(
        &fs::read(&exfat_partition.output_path).unwrap(),
        vhd_config(*b"StarCvExfatWin01", 0x5343_5758),
        FixedVhdLimits::default(),
    )
    .unwrap();
    let exfat_path = directory.join("converted-rich-ntfs-to-exfat-windows.vhd");
    fs::write(&exfat_path, exfat_vhd.bytes).unwrap();

    // The Windows harness and the report parser both pin these exact VHD identities. Asserting
    // them here turns every serializer byte change into a visible, deliberate pin refresh instead
    // of a silent drift that the elevated gate would only discover later.
    for (path, expected) in [
        (&ntfs_path, windows_validation::NTFS_CASE_HASH),
        (&exfat_path, windows_validation::EXFAT_CASE_HASH),
    ] {
        let bytes = fs::read(path).unwrap();
        assert_eq!(
            u64::try_from(bytes.len()).unwrap(),
            windows_validation::PINNED_VHD_BYTES,
            "{}",
            path.display()
        );
        let actual = upper_hex(&Sha256::digest(&bytes));
        assert_eq!(
            actual,
            expected,
            "pinned Windows VHD identity drifted for {}; refresh windows_validation.rs, \
             scripts/validate-windows-vhd.ps1, and docs/EXTERNAL_VALIDATION.md together",
            path.display()
        );
        println!("pinned Windows VHD identity: {actual} {}", path.display());
    }
    assert_ntfs_system_records_satisfy_windows_driver_invariants(&fs::read(&ntfs_path).unwrap());
    (ntfs_path, exfat_path)
}

/// Invariants the Windows NTFS driver and `chkdsk` enforce on the system records but NTFS-3G
/// tolerates, each learned from an elevated `windows-vhd` lane failure:
///
/// - every `$STANDARD_INFORMATION` and `$FILE_NAME` FILETIME is nonzero;
/// - every resident `$FILE_NAME` carries `RESIDENT_ATTR_IS_INDEXED`;
/// - no record 0–11 carries `FILE_SYSTEM_FILE` (`0x4`), which Windows and `mkntfs` reserve for
///   the `$Extend` view-index children;
/// - `$UpCase` carries the resident `$Info` stream with the pinned table CRC.
fn assert_ntfs_system_records_satisfy_windows_driver_invariants(vhd: &[u8]) {
    const PARTITION_BYTES: usize = 1024 * 1024;
    const CLUSTER_BYTES: usize = 4096;
    const RECORD_BYTES: usize = 1024;
    const MFT_LCN: usize = 4;
    let u16_at = |bytes: &[u8], at: usize| u16::from_le_bytes([bytes[at], bytes[at + 1]]);
    let u32_at =
        |bytes: &[u8], at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
    let u64_at =
        |bytes: &[u8], at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
    // Records 12–15 are free formatted reserved records in this profile and carry no attributes.
    for record_number in 0..12 {
        let start = PARTITION_BYTES + MFT_LCN * CLUSTER_BYTES + record_number * RECORD_BYTES;
        let mut record = vhd[start..start + RECORD_BYTES].to_vec();
        assert_eq!(&record[..4], b"FILE", "record {record_number} magic");
        // Undo the update-sequence fixups so attribute headers that straddle a sector end parse.
        let usa_offset = usize::from(u16_at(&record, 4));
        let usa_count = usize::from(u16_at(&record, 6));
        for sector in 1..usa_count {
            let original = u16_at(&record, usa_offset + 2 * sector);
            record[sector * 512 - 2..sector * 512].copy_from_slice(&original.to_le_bytes());
        }
        let record_flags = u16_at(&record, 0x16);
        assert_eq!(
            record_flags & 0x4,
            0,
            "record {record_number} carries FILE_SYSTEM_FILE"
        );

        let mut offset = usize::from(u16_at(&record, 0x14));
        let mut saw_standard_information = false;
        let mut saw_file_name = false;
        let mut saw_upcase_info = false;
        loop {
            let attribute_type = u32_at(&record, offset);
            if attribute_type == u32::MAX {
                break;
            }
            let length = usize::try_from(u32_at(&record, offset + 4)).unwrap();
            let non_resident = record[offset + 8] != 0;
            let name_len = usize::from(record[offset + 9]);
            let name_offset = usize::from(u16_at(&record, offset + 10));
            let name: Vec<u16> = (0..name_len)
                .map(|unit| u16_at(&record, offset + name_offset + 2 * unit))
                .collect();
            if !non_resident {
                let value_offset = usize::from(u16_at(&record, offset + 0x14));
                let value_len = usize::try_from(u32_at(&record, offset + 0x10)).unwrap();
                let value = &record[offset + value_offset..offset + value_offset + value_len];
                match attribute_type {
                    0x10 => {
                        saw_standard_information = true;
                        for field in 0..4 {
                            assert_ne!(
                                u64_at(value, field * 8),
                                0,
                                "record {record_number} $STANDARD_INFORMATION"
                            );
                        }
                    }
                    0x30 => {
                        saw_file_name = true;
                        assert_eq!(
                            record[offset + 0x16],
                            1,
                            "record {record_number} $FILE_NAME lacks RESIDENT_ATTR_IS_INDEXED"
                        );
                        for field in 0..4 {
                            assert_ne!(
                                u64_at(value, 8 + field * 8),
                                0,
                                "record {record_number} $FILE_NAME"
                            );
                        }
                    }
                    0x80 if record_number == 10
                        && name == "$Info".encode_utf16().collect::<Vec<_>>() =>
                    {
                        saw_upcase_info = true;
                        assert_eq!(value.len(), ntfs_upcase_serialize::NTFS_UPCASE_INFO_BYTES);
                        assert_eq!(u32_at(value, 0), 32, "$UpCase:$Info length field");
                        assert_eq!(
                            u64_at(value, 8),
                            ntfs_upcase_serialize::NTFS3G_WINDOWS61_UPCASE_INFO_CRC64,
                            "$UpCase:$Info CRC-64"
                        );
                    }
                    _ => {}
                }
            }
            offset += length;
        }
        assert!(
            saw_standard_information && saw_file_name,
            "system record {record_number} lacks $STANDARD_INFORMATION or $FILE_NAME"
        );
        assert!(
            record_number != 10 || saw_upcase_info,
            "$UpCase lacks the resident $Info stream"
        );
    }
}

fn upper_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(output, "{byte:02X}").unwrap();
    }
    output
}

fn export_edge_corpus(
    directory: &Path,
    upcase_bytes: &[u8],
) -> (
    PathBuf,
    PathBuf,
    CandidateExportEvidence,
    CandidateExportEvidence,
    PathBuf,
) {
    let (graph, metadata) = edge_graph();
    let exfat_path = directory.join("exfat-edge-corpus.img");
    fs::write(&exfat_path, exfat_image(&graph, &metadata, upcase_bytes, 0)).unwrap();
    let ntfs_path = directory.join("ntfs-edge-corpus.img");
    fs::write(&ntfs_path, ntfs_image(&graph, 0)).unwrap();
    let converted_ntfs = export_ntfs_candidate(
        directory,
        &exfat_path,
        "converted-edge-exfat-to-ntfs.img",
        0,
    );
    let converted_exfat = export_exfat_candidate(
        directory,
        &ntfs_path,
        "converted-edge-ntfs-to-exfat.img",
        0,
        4096,
        0,
    );
    let manifest_path = directory.join("edge-corpus-manifest.tsv");
    fs::write(&manifest_path, edge_manifest()).unwrap();
    (
        exfat_path,
        ntfs_path,
        converted_ntfs,
        converted_exfat,
        manifest_path,
    )
}

fn export_large_cluster_ntfs(directory: &Path, graph: &ObjectGraph) -> PathBuf {
    let path = directory.join("ntfs-structural-64k-cluster.img");
    fs::write(&path, ntfs_image_with_cluster(graph, 0, 65_536)).unwrap();
    path
}

fn print_structural_paths(paths: [&Path; 5]) {
    for (label, path) in [
        "exFAT",
        "NTFS",
        "NTFS 64 KiB-cluster",
        "exFAT VHD",
        "NTFS VHD",
    ]
    .into_iter()
    .zip(paths)
    {
        println!("{label} fixture: {}", path.display());
    }
}

fn print_windows_vhd_paths(ntfs: &Path, exfat: &Path) {
    println!("Windows NTFS VHD candidate: {}", ntfs.display());
    println!("Windows exFAT VHD candidate: {}", exfat.display());
}

#[test]
#[ignore = "writes regular image fixtures under target for independent tools"]
#[allow(clippy::too_many_lines)]
fn export_structural_candidate_images() {
    let directory = fixture_directory();
    fs::create_dir_all(&directory).unwrap();

    let graph = empty_graph();
    let empty_metadata = Vec::new();
    let upcase = generate_recommended_exfat_upcase(RecommendedExfatUpcaseLimits::default())
        .expect("generate pinned recommended exFAT up-case profile");
    let exfat_raw = exfat_image(&graph, &empty_metadata, upcase.encoded_bytes(), 0);
    let exfat_path = directory.join("exfat-structural-recommended-upcase.img");
    fs::write(&exfat_path, exfat_raw).unwrap();

    let ntfs_raw = ntfs_image(&graph, 0);
    let ntfs_path = directory.join("ntfs-structural-activation-blocked.img");
    fs::write(&ntfs_path, ntfs_raw).unwrap();

    let ntfs_large_cluster_path = export_large_cluster_ntfs(&directory, &graph);

    let exfat_partition = exfat_image(
        &graph,
        &empty_metadata,
        upcase.encoded_bytes(),
        ONE_MIB_PARTITION_ALIGNMENT_SECTORS,
    );
    let exfat_vhd = wrap_fixed_vhd(
        &exfat_partition,
        vhd_config(*b"StarExfatVhd2026", 0x5343_4558),
        FixedVhdLimits::default(),
    )
    .unwrap();
    let exfat_vhd_path = directory.join("exfat-structural-validation.vhd");
    fs::write(&exfat_vhd_path, exfat_vhd.bytes).unwrap();

    let ntfs_partition = ntfs_image(&graph, ONE_MIB_PARTITION_ALIGNMENT_SECTORS);
    let ntfs_vhd = wrap_fixed_vhd(
        &ntfs_partition,
        vhd_config(*b"StarNtfsVhd_2026", 0x5343_4e54),
        FixedVhdLimits::default(),
    )
    .unwrap();
    let ntfs_vhd_path = directory.join("ntfs-structural-validation.vhd");
    fs::write(&ntfs_vhd_path, ntfs_vhd.bytes).unwrap();

    let (rich_graph, rich_metadata) = rich_graph();
    let rich_exfat_path = directory.join("exfat-rich-namespace-payload.img");
    fs::write(
        &rich_exfat_path,
        exfat_image(&rich_graph, &rich_metadata, upcase.encoded_bytes(), 0),
    )
    .unwrap();
    let rich_ntfs_path = directory.join("ntfs-rich-namespace-payload.img");
    fs::write(&rich_ntfs_path, ntfs_image(&rich_graph, 0)).unwrap();

    let exported_ntfs = export_ntfs_candidate(
        &directory,
        &rich_exfat_path,
        "converted-rich-exfat-to-ntfs.img",
        0,
    );
    let exported_exfat = export_exfat_candidate(
        &directory,
        &rich_ntfs_path,
        "converted-rich-ntfs-to-exfat.img",
        0,
        4096,
        0,
    );
    let (windows_ntfs_vhd_path, windows_exfat_vhd_path) =
        export_windows_vhd_candidates(&directory, &rich_exfat_path, &rich_ntfs_path);
    let manifest_path = directory.join("rich-fixture-manifest.txt");
    fs::write(
        &manifest_path,
        concat!(
            "format=StarConverter deterministic payload v1\n",
            "/readme.txt stream=40 logical=14 physical=25165824\n",
            "/alpha/Ωmega/fragmented.bin stream=50 logical=6000 physical=26214400,28311552\n",
            "/alpha/empty.dat stream=60 logical=0\n",
        ),
    )
    .unwrap();

    let relocation_graph = misaligned_relocation_graph();
    let relocation_source_path = directory.join("ntfs-misaligned-8k-payload.img");
    fs::write(&relocation_source_path, ntfs_image(&relocation_graph, 0)).unwrap();
    let relocated_exfat = export_exfat_candidate(
        &directory,
        &relocation_source_path,
        "converted-misaligned-ntfs-to-exfat.img",
        0,
        8192,
        1,
    );
    let relocation_manifest_path = directory.join("misaligned-relocation-manifest.tsv");
    fs::write(&relocation_manifest_path, misaligned_relocation_manifest()).unwrap();

    let (
        edge_exfat_path,
        edge_ntfs_path,
        exported_edge_ntfs,
        exported_edge_exfat,
        edge_manifest_path,
    ) = export_edge_corpus(&directory, upcase.encoded_bytes());

    print_structural_paths([
        &exfat_path,
        &ntfs_path,
        &ntfs_large_cluster_path,
        &exfat_vhd_path,
        &ntfs_vhd_path,
    ]);
    println!("rich exFAT fixture: {}", rich_exfat_path.display());
    println!("rich NTFS fixture: {}", rich_ntfs_path.display());
    println!("converted NTFS candidate: {exported_ntfs:?}");
    println!("converted exFAT candidate: {exported_exfat:?}");
    print_windows_vhd_paths(&windows_ntfs_vhd_path, &windows_exfat_vhd_path);
    println!("rich manifest: {}", manifest_path.display());
    println!(
        "misaligned NTFS source: {}",
        relocation_source_path.display()
    );
    println!("relocated exFAT candidate: {relocated_exfat:?}");
    println!(
        "misaligned relocation manifest: {}",
        relocation_manifest_path.display()
    );
    println!("edge exFAT fixture: {}", edge_exfat_path.display());
    println!("edge NTFS fixture: {}", edge_ntfs_path.display());
    println!("converted edge NTFS candidate: {exported_edge_ntfs:?}");
    println!("converted edge exFAT candidate: {exported_edge_exfat:?}");
    println!("edge manifest: {}", edge_manifest_path.display());
}

fn large_directory_graph() -> (ObjectGraph, Vec<ExfatObjectMetadata>, String) {
    let root = ObjectId(1);
    let directory = ObjectId(2);
    let mut objects = vec![
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
    ];
    let mut entries = vec![NamespaceEntry {
        parent: root,
        target: directory,
        name: "alpha".encode_utf16().collect(),
    }];
    let mut manifest = String::new();
    let empty_sha256 = payload_digest(0, 0);
    for ordinal in 0..128_u64 {
        let object = ObjectId(ordinal + 3);
        let name = format!(
            "entry-{ordinal:03}-Ωmega-深度-rocket-🚀-{}.bin",
            "n".repeat(96)
        );
        objects.push(ObjectRecord {
            id: object,
            kind: ObjectKind::File,
            link_count: 1,
            semantics: ObjectSemantics::default(),
            streams: vec![ObjectStream {
                id: StreamId(ordinal + 100),
                name: None,
                logical_bytes: 0,
                initialized_bytes: 0,
                mapped_bytes: 0,
                allocated_bytes: 0,
                flags: StreamFlags::default(),
                storage: StreamStorage::Resident(Vec::new()),
            }],
        });
        writeln!(&mut manifest, "/alpha/{name}\t0\t{empty_sha256}").unwrap();
        entries.push(NamespaceEntry {
            parent: directory,
            target: object,
            name: name.encode_utf16().collect(),
        });
    }
    let graph = ObjectGraph::build(
        root,
        objects,
        entries,
        ExtentGraph::build(Vec::new(), IMAGE_BYTES, 256).unwrap(),
        ObjectGraphLimits {
            max_objects: 256,
            max_entries: 256,
            max_streams: 256,
            max_name_code_units: 255,
        },
    )
    .unwrap();
    let metadata = graph
        .objects()
        .iter()
        .filter(|object| object.id != root)
        .map(|object| ExfatObjectMetadata {
            object: object.id,
            file_attributes: match object.kind {
                ObjectKind::Directory => 0x11,
                ObjectKind::File => 0x21,
            },
            timestamps: rich_timestamp(),
        })
        .collect();
    (graph, metadata, manifest)
}

fn assert_large_directory_index(image: &ImageFile) -> usize {
    let inspection = inspect_open_image(image).unwrap();
    assert_eq!(inspection.image_bytes, IMAGE_BYTES);
    assert!(inspection.profile.inventory_complete);
    let BootSector::Ntfs(boot) = inspection.boot_sector else {
        panic!("large-directory candidate must be NTFS");
    };
    assert_eq!(boot.cluster_size_bytes, 4096);
    let inventory = inspection.ntfs_inventory.as_ref().unwrap();
    let alpha = inventory
        .objects
        .iter()
        .find(|object| {
            object.is_directory
                && object.file_names.iter().any(|file_name| {
                    file_name.name.code_units == "alpha".encode_utf16().collect::<Vec<_>>()
                })
        })
        .unwrap();
    assert!(alpha.directory_index_complete);
    assert_eq!(alpha.directory_entries.len(), 128);
    let allocation = alpha
        .attribute_census
        .iter()
        .find(|attribute| {
            attribute.attribute_type == 0xa0
                && attribute.name.as_ref().is_some_and(|name| {
                    name.code_units == "$I30".encode_utf16().collect::<Vec<_>>()
                })
        })
        .expect("large directory must spill into $INDEX_ALLOCATION:$I30");
    assert!(!allocation.resident);
    let mut blocks = 0;
    let mut internal_blocks = 0;
    for run in inventory.physical_allocations.iter().filter(|run| {
        run.record_number == alpha.reference.record_number
            && run.attribute_type == 0xa0
            && run.attribute_id == allocation.attribute_id
    }) {
        for cluster in 0..run.cluster_count {
            let offset = (run.start_lcn + cluster) * boot.cluster_size_bytes;
            let bytes = image.read_exact_at(offset, 4096).unwrap();
            let block = parse_index_block(
                &bytes,
                Some(run.starting_vcn + cluster),
                NtfsIndexLimits {
                    max_root_bytes: 1024,
                    max_block_bytes: 4096,
                    max_entries_per_node: 256,
                    max_name_code_units: 255,
                },
            )
            .unwrap();
            blocks += 1;
            if block.header.has_children {
                internal_blocks += 1;
            }
        }
    }
    assert!(blocks > internal_blocks, "index must contain leaf blocks");
    assert!(
        internal_blocks >= 1,
        "index must contain internal INDX nodes"
    );
    internal_blocks
}

#[test]
#[ignore = "writes isolated regular large-directory image fixtures under target"]
fn export_large_directory_candidate_images() {
    let directory = fixture_directory()
        .parent()
        .unwrap()
        .join("external-large-directory-fixtures");
    fs::create_dir_all(&directory).unwrap();
    let (graph, metadata, manifest) = large_directory_graph();
    let upcase =
        generate_recommended_exfat_upcase(RecommendedExfatUpcaseLimits::default()).unwrap();
    let source_path = directory.join("exfat-large-directory.img");
    fs::write(
        &source_path,
        exfat_image(&graph, &metadata, upcase.encoded_bytes(), 0),
    )
    .unwrap();
    let candidate = export_ntfs_candidate(
        &directory,
        &source_path,
        "converted-large-directory-exfat-to-ntfs.img",
        0,
    );
    let internal_blocks = {
        let image = ImageFile::open(&candidate.output_path).unwrap();
        assert_large_directory_index(&image)
    };
    let manifest_path = directory.join("large-directory-manifest.tsv");
    fs::write(&manifest_path, manifest).unwrap();
    println!("large-directory exFAT source: {}", source_path.display());
    println!("large-directory NTFS candidate: {candidate:?}");
    println!("large-directory internal INDX nodes: {internal_blocks}");
    println!("large-directory manifest: {}", manifest_path.display());
}
