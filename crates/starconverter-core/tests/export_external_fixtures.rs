//! Opt-in regular-file fixtures for independent read-only validator experiments.
//!
//! These are structural serializer fixtures, not activation-ready conversion images. Run with:
//! `cargo test -p starconverter-core --test export_external_fixtures -- --ignored --nocapture`.

use std::fs;
use std::path::{Path, PathBuf};

use starconverter_core::candidate_export::{
    CandidateExportEvidence, CandidateExportLimits, export_candidate_image,
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

fn export_rich_ntfs_candidate(directory: &Path, source_path: &Path) -> CandidateExportEvidence {
    let output = directory.join("converted-rich-exfat-to-ntfs.img");
    let escrow = directory.join("converted-rich-exfat-to-ntfs.img.starconverter-escrow");
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
        ExfatToNtfsOptions::default(),
        ExfatToNtfsLimits::default(),
    )
    .unwrap();
    let source = ImageFile::open(source_path).unwrap();
    let preview =
        preview_ntfs_phase_writes(&source, &plan.destination, PreimageLimits::default()).unwrap();
    export_candidate_image(
        &source,
        &output,
        Some(&escrow),
        &preview,
        &plan.target_graph,
        &plan.preservation,
        CandidateExportLimits::default(),
    )
    .unwrap()
}

fn export_rich_exfat_candidate(directory: &Path, source_path: &Path) -> CandidateExportEvidence {
    let output = directory.join("converted-rich-ntfs-to-exfat.img");
    let escrow = directory.join("converted-rich-ntfs-to-exfat.img.starconverter-escrow");
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
        NtfsToExfatOptions::default(),
        NtfsToExfatLimits::default(),
    )
    .unwrap();
    let source = ImageFile::open(source_path).unwrap();
    let preview =
        preview_exfat_phase_writes(&source, &plan.destination, PreimageLimits::default()).unwrap();
    export_candidate_image(
        &source,
        &output,
        Some(&escrow),
        &preview,
        &plan.target_graph,
        &plan.preservation,
        CandidateExportLimits::default(),
    )
    .unwrap()
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

    let exported_ntfs = export_rich_ntfs_candidate(&directory, &rich_exfat_path);
    let exported_exfat = export_rich_exfat_candidate(&directory, &rich_ntfs_path);
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

    println!("exFAT fixture: {}", exfat_path.display());
    println!("NTFS fixture: {}", ntfs_path.display());
    println!("exFAT VHD: {}", exfat_vhd_path.display());
    println!("NTFS VHD: {}", ntfs_vhd_path.display());
    println!("rich exFAT fixture: {}", rich_exfat_path.display());
    println!("rich NTFS fixture: {}", rich_ntfs_path.display());
    println!("converted NTFS candidate: {exported_ntfs:?}");
    println!("converted exFAT candidate: {exported_exfat:?}");
    println!("rich manifest: {}", manifest_path.display());
}
