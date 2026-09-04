//! Regular-file and in-memory integration coverage for the image conversion pipeline.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use starconverter_core::FileSystem;
use starconverter_core::extent::{Extent, ExtentGraph, ExtentKind, Placement, StreamId};
use starconverter_core::fs::exfat_allocation::{
    FatEntry, bitmap_cluster_is_allocated, cluster_byte_offset, fat_entry,
};
use starconverter_core::fs::exfat_inventory::ExfatPreservationEvidence;
use starconverter_core::fs::exfat_serialize::{
    ExfatObjectMetadata, ExfatSerializationPlan, ExfatSerializeLimits, ExfatSerializeOptions,
    ExfatVolumeProfile, non_interoperable_ascii_test_upcase_table, serialize_exfat_destination,
};
use starconverter_core::fs::exfat_upcase::table_checksum;
use starconverter_core::fs::ntfs_serialize::{
    NtfsDestinationInputs, NtfsDestinationPlan, NtfsSerializeLimits, plan_ntfs_destination,
};
use starconverter_core::image::ImageFile;
use starconverter_core::inspect::{BootSector, inspect_image};
use starconverter_core::object::{
    NamespaceEntry, ObjectGraph, ObjectGraphLimits, ObjectId, ObjectKind, ObjectRecord,
    ObjectSemantics, ObjectStream, StreamFlags, StreamStorage,
};
use starconverter_core::overlay::OverlayWrite;
use starconverter_core::phase::{
    ActivationAuthorizedWrites, PhaseWriteError, prepare_exfat_phase_writes,
    prepare_ntfs_phase_writes, preview_exfat_phase_writes, preview_ntfs_phase_writes,
};
use starconverter_core::preimage::{PreimageLimits, capture_before_images};

const EXFAT_BYTES: u64 = 4 * 1024 * 1024;
const NTFS_BYTES: u64 = 16 * 1024 * 1024;
const CLUSTER_BYTES: u64 = 4096;
const SECTOR_BYTES_U64: u64 = 512;
const GRAPH_LIMITS: ObjectGraphLimits = ObjectGraphLimits {
    max_objects: 32,
    max_entries: 32,
    max_streams: 32,
    max_name_code_units: 255,
};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempImage(PathBuf);

impl TempImage {
    fn create(label: &str, bytes: &[u8]) -> Self {
        let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "starconverter-image-pipeline-{label}-{}-{id}.img",
            std::process::id()
        ));
        fs::write(&path, bytes).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempImage {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn root(streams: Vec<ObjectStream>) -> ObjectRecord {
    ObjectRecord {
        id: ObjectId(1),
        kind: ObjectKind::Directory,
        link_count: 0,
        semantics: ObjectSemantics::default(),
        streams,
    }
}

fn empty_graph(volume_bytes: u64) -> ObjectGraph {
    ObjectGraph::build(
        ObjectId(1),
        vec![root(Vec::new())],
        Vec::new(),
        ExtentGraph::build(Vec::new(), volume_bytes, 8).unwrap(),
        GRAPH_LIMITS,
    )
    .unwrap()
}

fn ntfs_graph() -> ObjectGraph {
    let payload = b"image pipeline".to_vec();
    let payload_bytes = u64::try_from(payload.len()).unwrap();
    let file = ObjectRecord {
        id: ObjectId(2),
        kind: ObjectKind::File,
        link_count: 1,
        semantics: ObjectSemantics::default(),
        streams: vec![ObjectStream {
            id: StreamId(2),
            name: None,
            logical_bytes: payload_bytes,
            initialized_bytes: payload_bytes,
            mapped_bytes: payload_bytes,
            allocated_bytes: 0,
            flags: StreamFlags::default(),
            storage: StreamStorage::Resident(payload),
        }],
    };
    ObjectGraph::build(
        ObjectId(1),
        vec![root(Vec::new()), file],
        vec![NamespaceEntry {
            parent: ObjectId(1),
            target: ObjectId(2),
            name: "pipeline.txt".encode_utf16().collect(),
        }],
        ExtentGraph::build(Vec::new(), NTFS_BYTES, 8).unwrap(),
        GRAPH_LIMITS,
    )
    .unwrap()
}

fn exfat_plan(graph: &ObjectGraph, metadata: &[ExfatObjectMetadata]) -> ExfatSerializationPlan {
    let upcase = non_interoperable_ascii_test_upcase_table();
    serialize_exfat_destination(
        graph,
        metadata,
        ExfatVolumeProfile {
            volume_label: None,
            encoded_upcase_table: &upcase,
            upcase_checksum: table_checksum(&upcase),
            source_preservation: ExfatPreservationEvidence::default(),
            allocated_bad_clusters: 0,
            bad_cluster_ranges: &[],
        },
        ExfatSerializeOptions::default(),
        ExfatSerializeLimits::default(),
    )
    .unwrap()
}

fn ntfs_plan() -> NtfsDestinationPlan {
    plan_ntfs_destination(
        &ntfs_graph(),
        NtfsDestinationInputs {
            image_bytes: NTFS_BYTES,
            cluster_bytes: u32::try_from(CLUSTER_BYTES).unwrap(),
            partition_offset_sectors: 0,
            volume_serial_number: 0x1122_3344_5566_7788,
            timestamp: 0x0102_0304_0506_0708,
        },
        NtfsSerializeLimits::default(),
    )
    .unwrap()
}

fn apply(image: &mut [u8], write: &OverlayWrite) {
    let offset = usize::try_from(write.offset).unwrap();
    image[offset..offset + write.bytes.len()].copy_from_slice(&write.bytes);
}

fn assert_activation_blocked(
    result: Result<ActivationAuthorizedWrites, PhaseWriteError>,
    filesystem: &str,
) {
    match result {
        Err(PhaseWriteError::ActivationBlocked {
            filesystem: actual,
            gaps,
        }) => {
            assert_eq!(actual, filesystem);
            assert!(!gaps.is_empty());
        }
        other => panic!("expected activation gate, got {other:?}"),
    }
}

#[test]
fn exfat_serializer_keeps_activation_separate_and_candidate_reinspects() {
    let plan = exfat_plan(&empty_graph(EXFAT_BYTES), &[]);
    assert!(!plan.activation_ready());
    assert_eq!(plan.primary_boot_write().offset, 0);
    assert_eq!(plan.backup_boot_write().offset, 12 * SECTOR_BYTES_U64);
    assert!(
        plan.staging_writes()
            .all(|write| write.offset >= 24 * SECTOR_BYTES_U64)
    );

    let original = vec![0x5a; usize::try_from(EXFAT_BYTES).unwrap()];
    let source = TempImage::create("exfat-source", &original);
    let image = ImageFile::open(source.path()).unwrap();
    assert_activation_blocked(
        prepare_exfat_phase_writes(&image, &plan, PreimageLimits::default()),
        "exFAT",
    );
    let preview = preview_exfat_phase_writes(&image, &plan, PreimageLimits::default()).unwrap();
    assert_eq!(preview.target_filesystem(), FileSystem::ExFat);
    assert!(!preview.activation_ready());
    assert_eq!(preview.activation_gaps(), plan.activation_gaps());
    assert!(
        preview
            .writes()
            .target_staging_rollback
            .iter()
            .chain(&preview.writes().backup_boot_rollback)
            .chain(&preview.writes().activation_rollback)
            .all(|write| write.bytes.iter().all(|byte| *byte == 0x5a))
    );
    assert_eq!(fs::read(source.path()).unwrap(), original);

    let mut candidate = vec![0_u8; usize::try_from(EXFAT_BYTES).unwrap()];
    for write in plan.staging_writes() {
        apply(&mut candidate, write);
    }
    apply(&mut candidate, plan.backup_boot_write());
    assert_eq!(&candidate[3..11], &[0_u8; 8]);
    apply(&mut candidate, plan.primary_boot_write());
    let candidate = TempImage::create("exfat-candidate", &candidate);
    let inspection = inspect_image(candidate.path()).unwrap();
    assert_eq!(inspection.profile.filesystem, FileSystem::ExFat);
    assert!(inspection.profile.inventory_complete);
    assert!(inspection.normalized_exfat.is_some());
}

#[test]
fn ntfs_serializer_keeps_activation_separate_and_candidate_reinspects() {
    let plan = ntfs_plan();
    assert!(!plan.activation_ready());
    assert_eq!(plan.primary_boot_write.offset, 0);
    assert_eq!(plan.backup_boot_write.offset, NTFS_BYTES - 512);
    assert!(plan.staging_writes.iter().all(|write| write.offset != 0));

    let original = vec![0xa5; usize::try_from(NTFS_BYTES).unwrap()];
    let source = TempImage::create("ntfs-source", &original);
    let image = ImageFile::open(source.path()).unwrap();
    assert_activation_blocked(
        prepare_ntfs_phase_writes(&image, &plan, PreimageLimits::default()),
        "NTFS",
    );
    let preview = preview_ntfs_phase_writes(&image, &plan, PreimageLimits::default()).unwrap();
    assert_eq!(preview.target_filesystem(), FileSystem::Ntfs);
    assert!(!preview.activation_ready());
    assert_eq!(preview.activation_gaps(), plan.activation_gaps());
    assert!(
        preview
            .writes()
            .target_staging_rollback
            .iter()
            .chain(&preview.writes().backup_boot_rollback)
            .chain(&preview.writes().activation_rollback)
            .all(|write| write.bytes.iter().all(|byte| *byte == 0xa5))
    );
    assert_eq!(fs::read(source.path()).unwrap(), original);

    let mut candidate = vec![0_u8; usize::try_from(NTFS_BYTES).unwrap()];
    for write in &plan.staging_writes {
        apply(&mut candidate, write);
    }
    apply(&mut candidate, &plan.backup_boot_write);
    assert_eq!(&candidate[3..11], &[0_u8; 8]);
    apply(&mut candidate, &plan.primary_boot_write);
    let candidate = TempImage::create("ntfs-candidate", &candidate);
    let inspection = inspect_image(candidate.path()).unwrap();
    assert_eq!(inspection.profile.filesystem, FileSystem::Ntfs);
    assert!(inspection.profile.inventory_complete);
    assert!(inspection.normalized_ntfs.is_some());
}

#[test]
fn preimage_capture_is_exact_sorted_and_read_only() {
    let original: Vec<u8> = (0_u8..=255).cycle().take(32 * 1024).collect();
    let temp = TempImage::create("preimage", &original);
    let image = ImageFile::open_with_limit(temp.path(), 97).unwrap();
    let captured = capture_before_images(
        &image,
        &[
            OverlayWrite {
                offset: 8192,
                bytes: vec![0x11; 1024],
            },
            OverlayWrite {
                offset: 512,
                bytes: vec![0x22; 1536],
            },
        ],
        PreimageLimits {
            max_writes: 2,
            max_total_bytes: 2560,
        },
    )
    .unwrap();

    assert_eq!(captured[0].offset, 512);
    assert_eq!(captured[0].bytes, original[512..2048]);
    assert_eq!(captured[1].offset, 8192);
    assert_eq!(captured[1].bytes, original[8192..9216]);
    assert_eq!(fs::read(temp.path()).unwrap(), original);
}

#[test]
fn old_exfat_directory_cluster_is_free_not_orphaned_in_destination() {
    let bootstrap = exfat_plan(&empty_graph(EXFAT_BYTES), &[]);
    let heap = u64::from(bootstrap.geometry.cluster_heap_offset_sectors)
        * u64::from(bootstrap.geometry.bytes_per_sector);
    let old_cluster = 102_u32;
    let old_offset = heap + u64::from(old_cluster - 2) * CLUSTER_BYTES;
    let directory_stream = ObjectStream {
        id: StreamId(77),
        name: None,
        logical_bytes: CLUSTER_BYTES,
        initialized_bytes: CLUSTER_BYTES,
        mapped_bytes: CLUSTER_BYTES,
        allocated_bytes: CLUSTER_BYTES,
        flags: StreamFlags::default(),
        storage: StreamStorage::Extents,
    };
    let graph = ObjectGraph::build(
        ObjectId(1),
        vec![root(vec![directory_stream])],
        Vec::new(),
        ExtentGraph::build(
            vec![Extent {
                stream: StreamId(77),
                logical_offset: 0,
                length: CLUSTER_BYTES,
                placement: Placement::Physical {
                    byte_offset: old_offset,
                },
                kind: ExtentKind::DirectoryData,
            }],
            EXFAT_BYTES,
            8,
        )
        .unwrap(),
        GRAPH_LIMITS,
    )
    .unwrap();
    let plan = exfat_plan(&graph, &[]);
    assert!(
        plan.source_allocations
            .iter()
            .any(|source| source.range.offset == old_offset)
    );

    let mut candidate = vec![0_u8; usize::try_from(EXFAT_BYTES).unwrap()];
    for write in plan.overlay.writes() {
        apply(&mut candidate, write);
    }
    let temp = TempImage::create("exfat-old-directory", &candidate);
    let inspection = inspect_image(temp.path()).unwrap();
    let BootSector::ExFat(boot) = inspection.boot_sector else {
        panic!("expected exFAT boot sector")
    };
    let root = inspection.exfat_root.as_ref().unwrap();
    let image = ImageFile::open(temp.path()).unwrap();
    let bitmap_offset = cluster_byte_offset(&boot, root.active_bitmap.first_cluster).unwrap();
    let bitmap = image
        .read_exact_at(
            bitmap_offset,
            usize::try_from(root.active_bitmap.data_length).unwrap(),
        )
        .unwrap();
    assert!(!bitmap_cluster_is_allocated(&bitmap, &boot, old_cluster).unwrap());

    let fat_offset = u64::from(boot.fat_offset_sectors) * u64::from(boot.bytes_per_sector);
    let fat_bytes =
        usize::try_from(u64::from(boot.fat_length_sectors) * u64::from(boot.bytes_per_sector))
            .unwrap();
    let fat = image.read_exact_at(fat_offset, fat_bytes).unwrap();
    assert_eq!(fat_entry(&fat, &boot, old_cluster).unwrap(), FatEntry::Free);
    let inventory = inspection.exfat_inventory.as_ref().unwrap();
    assert_eq!(inventory.allocated_bad_clusters, 0);
    assert!(
        inventory
            .objects
            .iter()
            .all(|object| !object.clusters.contains(&old_cluster))
    );
}
