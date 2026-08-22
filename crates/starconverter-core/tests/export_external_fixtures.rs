//! Opt-in regular-file fixtures for independent read-only validator experiments.
//!
//! These are structural serializer fixtures, not activation-ready conversion images. Run with:
//! `cargo test -p starconverter-core --test export_external_fixtures -- --ignored --nocapture`.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use starconverter_core::candidate_export::{
    CandidateExportEvidence, CandidateExportLimits, decode_bound_escrow, export_candidate_image,
};
use starconverter_core::cross_format::{
    ExfatToNtfsLimits, ExfatToNtfsOptions, NtfsToExfatLimits, NtfsToExfatOptions,
    plan_lossless_exfat_to_ntfs, plan_lossless_ntfs_to_exfat,
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
use starconverter_core::fs::ntfs_serialize::{
    NtfsDestinationInputs, NtfsSerializeLimits, plan_ntfs_destination,
};
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
use starconverter_core::{GuaranteeMode, image::ImageFile, inspect::inspect_image};

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
    let ntfs = plan_ntfs_destination(
        graph,
        NtfsDestinationInputs {
            image_bytes: IMAGE_BYTES,
            cluster_bytes: 4096,
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
    let inspection = inspect_image(source_path).unwrap();
    let normalized = inspection.normalized_exfat.as_deref().unwrap();
    let plan = plan_lossless_exfat_to_ntfs(
        normalized,
        GuaranteeMode::Escrow,
        ExfatToNtfsOptions {
            partition_offset_sectors,
            ..ExfatToNtfsOptions::default()
        },
        ExfatToNtfsLimits::default(),
    )
    .unwrap();
    let source = ImageFile::open(source_path).unwrap();
    let preview =
        preview_ntfs_phase_writes(&source, &plan.destination, PreimageLimits::default()).unwrap();
    let evidence = export_candidate_image(
        &source,
        &output,
        Some(&escrow),
        &preview,
        &plan.target_graph,
        &plan.preservation,
        CandidateExportLimits::default(),
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
) -> CandidateExportEvidence {
    let output = directory.join(output_name);
    let escrow = directory.join(format!("{output_name}.starconverter-escrow"));
    for path in [&output, &escrow] {
        if path.exists() {
            fs::remove_file(path).unwrap();
        }
    }
    let inspection = inspect_image(source_path).unwrap();
    let normalized = inspection.normalized_ntfs.as_deref().unwrap();
    let plan = plan_lossless_ntfs_to_exfat(
        normalized,
        GuaranteeMode::Escrow,
        NtfsToExfatOptions {
            partition_offset_sectors,
            ..NtfsToExfatOptions::default()
        },
        NtfsToExfatLimits::default(),
    )
    .unwrap();
    let source = ImageFile::open(source_path).unwrap();
    let preview =
        preview_exfat_phase_writes(&source, &plan.destination, PreimageLimits::default()).unwrap();
    let evidence = export_candidate_image(
        &source,
        &output,
        Some(&escrow),
        &preview,
        &plan.target_graph,
        &plan.preservation,
        CandidateExportLimits::default(),
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
    );
    let exfat_vhd = wrap_fixed_vhd(
        &fs::read(&exfat_partition.output_path).unwrap(),
        vhd_config(*b"StarCvExfatWin01", 0x5343_5758),
        FixedVhdLimits::default(),
    )
    .unwrap();
    let exfat_path = directory.join("converted-rich-ntfs-to-exfat-windows.vhd");
    fs::write(&exfat_path, exfat_vhd.bytes).unwrap();
    (ntfs_path, exfat_path)
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
    let converted_exfat =
        export_exfat_candidate(directory, &ntfs_path, "converted-edge-ntfs-to-exfat.img", 0);
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

#[test]
#[ignore = "writes regular image fixtures under target for independent tools"]
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

    let (
        edge_exfat_path,
        edge_ntfs_path,
        exported_edge_ntfs,
        exported_edge_exfat,
        edge_manifest_path,
    ) = export_edge_corpus(&directory, upcase.encoded_bytes());

    println!("exFAT fixture: {}", exfat_path.display());
    println!("NTFS fixture: {}", ntfs_path.display());
    println!("exFAT VHD: {}", exfat_vhd_path.display());
    println!("NTFS VHD: {}", ntfs_vhd_path.display());
    println!("rich exFAT fixture: {}", rich_exfat_path.display());
    println!("rich NTFS fixture: {}", rich_ntfs_path.display());
    println!("converted NTFS candidate: {exported_ntfs:?}");
    println!("converted exFAT candidate: {exported_exfat:?}");
    println!(
        "Windows NTFS VHD candidate: {}",
        windows_ntfs_vhd_path.display()
    );
    println!(
        "Windows exFAT VHD candidate: {}",
        windows_exfat_vhd_path.display()
    );
    println!("rich manifest: {}", manifest_path.display());
    println!("edge exFAT fixture: {}", edge_exfat_path.display());
    println!("edge NTFS fixture: {}", edge_ntfs_path.display());
    println!("converted edge NTFS candidate: {exported_edge_ntfs:?}");
    println!("converted edge exFAT candidate: {exported_edge_exfat:?}");
    println!("edge manifest: {}", edge_manifest_path.display());
}
