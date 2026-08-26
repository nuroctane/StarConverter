//! Deterministic crash cuts for the public capsule and exact recovery-bundle APIs.
//!
//! The executor below mutates only caller-owned memory or a uniquely named regular temporary
//! image. Forward image writes and capsule persistence are intentionally separate, exposing every
//! durability window. `PreparedConversion` coverage cannot yet live in an integration test because
//! its activation authorization is deliberately unforgeable and neither serializer is currently
//! activation-ready.

use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use starconverter_core::capsule::{
    CapsuleIdentity, CapsuleLimits, HEADER_BYTES, TransactionPhase, append_generation,
    recover_capsule, scan_capsule,
};
use starconverter_core::capsule_store::CapsuleStore;
use starconverter_core::overlay::OverlayWrite;
use starconverter_core::recovery::{
    RecoveryBundle, RecoveryLimits, decode_recovery_bundle, encode_recovery_bundle,
};

const SECTOR_BYTES: usize = 512;
const IMAGE_BYTES: usize = 16 * 1024;
const IDENTITY: CapsuleIdentity = CapsuleIdentity {
    transaction_id: [0x23; 16],
    source_digest: [0x39; 32],
};
const PLAN_DIGEST: [u8; 32] = [0x51; 32];
const CHECKPOINT: &[u8] = b"crash-cut-plan-checkpoint";

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempImage(PathBuf);

impl TempImage {
    fn create(bytes: &[u8]) -> Self {
        let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "starconverter-crash-cut-{}-{sequence}.img",
            std::process::id()
        ));
        fs::write(&path, bytes).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn vacant(label: &str) -> Self {
        let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "starconverter-{label}-{}-{sequence}.starcap",
            std::process::id()
        ));
        Self(path)
    }
}

impl Drop for TempImage {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn write(offset: u64, byte: u8) -> OverlayWrite {
    OverlayWrite {
        offset,
        bytes: vec![byte; SECTOR_BYTES],
    }
}

fn forward_groups() -> [Vec<OverlayWrite>; 3] {
    [
        vec![write(2048, 0xa2), write(2560, 0xa3)],
        vec![write(1024, 0xb0)],
        vec![write(1536, 0xc0)],
    ]
}

fn recovery_bundle() -> RecoveryBundle {
    RecoveryBundle {
        plan_digest: PLAN_DIGEST,
        target_staging: vec![write(2048, 0x12), write(2560, 0x13)],
        backup_boot: vec![write(1024, 0x10)],
        activation: vec![write(1536, 0x11)],
    }
}

const fn recovery_limits() -> RecoveryLimits {
    RecoveryLimits {
        max_writes: 8,
        max_bytes: 8 * SECTOR_BYTES,
    }
}

fn recovery_payload() -> Vec<u8> {
    encode_recovery_bundle(&recovery_bundle(), recovery_limits()).unwrap()
}

const fn phases_through(phase: TransactionPhase) -> &'static [TransactionPhase] {
    match phase {
        TransactionPhase::Discovered => &[],
        TransactionPhase::Reserved => &[TransactionPhase::Reserved],
        TransactionPhase::Relocating => &[TransactionPhase::Reserved, TransactionPhase::Relocating],
        TransactionPhase::TargetStaged => &[
            TransactionPhase::Reserved,
            TransactionPhase::Relocating,
            TransactionPhase::TargetStaged,
        ],
        TransactionPhase::BackupBootWritten => &[
            TransactionPhase::Reserved,
            TransactionPhase::Relocating,
            TransactionPhase::TargetStaged,
            TransactionPhase::BackupBootWritten,
        ],
        TransactionPhase::Activated => &[
            TransactionPhase::Reserved,
            TransactionPhase::Relocating,
            TransactionPhase::TargetStaged,
            TransactionPhase::BackupBootWritten,
            TransactionPhase::Activated,
        ],
        TransactionPhase::Verified => &[
            TransactionPhase::Reserved,
            TransactionPhase::Relocating,
            TransactionPhase::TargetStaged,
            TransactionPhase::BackupBootWritten,
            TransactionPhase::Activated,
            TransactionPhase::Verified,
        ],
        TransactionPhase::Finalized => &[
            TransactionPhase::Reserved,
            TransactionPhase::Relocating,
            TransactionPhase::TargetStaged,
            TransactionPhase::BackupBootWritten,
            TransactionPhase::Activated,
            TransactionPhase::Verified,
            TransactionPhase::Finalized,
        ],
        TransactionPhase::RolledBack => &[TransactionPhase::RolledBack],
    }
}

fn capsule_at(phase: TransactionPhase) -> Vec<u8> {
    let limits = CapsuleLimits::default();
    let mut capsule = Vec::new();
    append_generation(
        &mut capsule,
        IDENTITY,
        TransactionPhase::Discovered,
        &recovery_payload(),
        limits,
    )
    .unwrap();
    for next in phases_through(phase) {
        append_generation(&mut capsule, IDENTITY, *next, CHECKPOINT, limits).unwrap();
    }
    capsule
}

fn source_image() -> Vec<u8> {
    let mut image: Vec<u8> = (0_u8..=255).cycle().take(IMAGE_BYTES).collect();
    for before_image in recovery_bundle()
        .target_staging
        .into_iter()
        .chain(recovery_bundle().backup_boot)
        .chain(recovery_bundle().activation)
    {
        apply(&mut image, &before_image);
    }
    image
}

fn apply(image: &mut [u8], write: &OverlayWrite) {
    let start = usize::try_from(write.offset).unwrap();
    let end = start.checked_add(write.bytes.len()).unwrap();
    image[start..end].copy_from_slice(&write.bytes);
}

fn apply_group(image: &mut [u8], writes: &[OverlayWrite]) {
    for item in writes {
        apply(image, item);
    }
}

fn persist_exact_regular_file(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new().write(true).open(path).unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    file.write_all(bytes).unwrap();
    file.set_len(u64::try_from(bytes.len()).unwrap()).unwrap();
    file.sync_data().unwrap();
    file.sync_all().unwrap();
    drop(file);
    assert_eq!(fs::read(path).unwrap(), bytes);
}

fn append_and_sync_regular_file(path: &Path, suffix: &[u8]) {
    let mut file = OpenOptions::new().append(true).open(path).unwrap();
    file.write_all(suffix).unwrap();
    file.sync_data().unwrap();
    file.sync_all().unwrap();
}

fn semantic_suffix_cuts(length: usize) -> Vec<usize> {
    let mut cuts = vec![
        0,
        1,
        HEADER_BYTES.saturating_sub(1),
        HEADER_BYTES,
        HEADER_BYTES.saturating_add(1),
        length / 2,
        length.saturating_sub(HEADER_BYTES).saturating_sub(1),
        length.saturating_sub(HEADER_BYTES),
        length.saturating_sub(1),
        length,
    ];
    cuts.retain(|cut| *cut <= length);
    cuts.sort_unstable();
    cuts.dedup();
    cuts
}

fn rollback_writes(bundle: &RecoveryBundle, phase: TransactionPhase) -> Vec<&OverlayWrite> {
    match phase {
        TransactionPhase::Discovered
        | TransactionPhase::Reserved
        | TransactionPhase::Finalized
        | TransactionPhase::RolledBack => Vec::new(),
        // Each durable phase conservatively covers the write group that may already be in flight.
        TransactionPhase::Relocating => bundle.target_staging.iter().collect(),
        TransactionPhase::TargetStaged => bundle
            .target_staging
            .iter()
            .chain(&bundle.backup_boot)
            .collect(),
        TransactionPhase::BackupBootWritten
        | TransactionPhase::Activated
        | TransactionPhase::Verified => bundle
            .target_staging
            .iter()
            .chain(&bundle.backup_boot)
            .chain(&bundle.activation)
            .collect(),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BootSelection {
    Source,
    Target,
}

#[derive(Clone, Copy)]
struct CrashCut {
    name: &'static str,
    durable_phase: TransactionPhase,
    applied_groups: usize,
    expected_boot: BootSelection,
    exact_restore_covered: bool,
}

#[test]
#[allow(clippy::too_many_lines)]
fn every_forward_write_group_has_before_after_and_checkpoint_crash_cuts() {
    let groups = forward_groups();
    let bundle = decode_recovery_bundle(&recovery_payload(), recovery_limits()).unwrap();
    let source = source_image();
    let cuts = [
        CrashCut {
            name: "before staging",
            durable_phase: TransactionPhase::Relocating,
            applied_groups: 0,
            expected_boot: BootSelection::Source,
            exact_restore_covered: true,
        },
        CrashCut {
            name: "after staging write, before checkpoint",
            durable_phase: TransactionPhase::Relocating,
            applied_groups: 1,
            expected_boot: BootSelection::Source,
            exact_restore_covered: true,
        },
        CrashCut {
            name: "after staging checkpoint",
            durable_phase: TransactionPhase::TargetStaged,
            applied_groups: 1,
            expected_boot: BootSelection::Source,
            exact_restore_covered: true,
        },
        CrashCut {
            name: "before backup boot",
            durable_phase: TransactionPhase::TargetStaged,
            applied_groups: 1,
            expected_boot: BootSelection::Source,
            exact_restore_covered: true,
        },
        CrashCut {
            name: "after backup boot write, before checkpoint",
            durable_phase: TransactionPhase::TargetStaged,
            applied_groups: 2,
            expected_boot: BootSelection::Source,
            exact_restore_covered: true,
        },
        CrashCut {
            name: "after backup boot checkpoint",
            durable_phase: TransactionPhase::BackupBootWritten,
            applied_groups: 2,
            expected_boot: BootSelection::Source,
            exact_restore_covered: true,
        },
        CrashCut {
            name: "before activation",
            durable_phase: TransactionPhase::BackupBootWritten,
            applied_groups: 2,
            expected_boot: BootSelection::Source,
            exact_restore_covered: true,
        },
        CrashCut {
            name: "after activation write, before checkpoint",
            durable_phase: TransactionPhase::BackupBootWritten,
            applied_groups: 3,
            expected_boot: BootSelection::Target,
            exact_restore_covered: true,
        },
        CrashCut {
            name: "after activation checkpoint",
            durable_phase: TransactionPhase::Activated,
            applied_groups: 3,
            expected_boot: BootSelection::Target,
            exact_restore_covered: true,
        },
    ];

    for cut in cuts {
        let capsule = capsule_at(cut.durable_phase);
        assert_eq!(
            scan_capsule(&capsule, CapsuleLimits::default())
                .unwrap()
                .newest()
                .unwrap()
                .phase,
            cut.durable_phase,
            "{}",
            cut.name
        );

        let mut crashed = source.clone();
        for group in groups.iter().take(cut.applied_groups) {
            apply_group(&mut crashed, group);
        }
        let activation = &groups[2][0];
        let activation_start = usize::try_from(activation.offset).unwrap();
        let activation_end = activation_start + activation.bytes.len();
        let boot = if crashed[activation_start..activation_end] == activation.bytes {
            BootSelection::Target
        } else {
            BootSelection::Source
        };
        assert_eq!(boot, cut.expected_boot, "{}", cut.name);

        for before_image in rollback_writes(&bundle, cut.durable_phase) {
            apply(&mut crashed, before_image);
        }
        assert_eq!(
            crashed == source,
            cut.exact_restore_covered,
            "rollback coverage at {}",
            cut.name
        );
    }
}

#[test]
fn each_durable_phase_restores_the_exact_regular_file_before_image() {
    let groups = forward_groups();
    let bundle = decode_recovery_bundle(&recovery_payload(), recovery_limits()).unwrap();
    let source = source_image();
    for (phase, applied_groups) in [
        (TransactionPhase::TargetStaged, 1),
        (TransactionPhase::BackupBootWritten, 2),
        (TransactionPhase::Activated, 3),
        (TransactionPhase::Verified, 3),
    ] {
        let temp = TempImage::create(&source);
        let mut bytes = fs::read(temp.path()).unwrap();
        for group in groups.iter().take(applied_groups) {
            apply_group(&mut bytes, group);
        }
        for before_image in rollback_writes(&bundle, phase) {
            apply(&mut bytes, before_image);
        }
        fs::write(temp.path(), &bytes).unwrap();
        assert_eq!(fs::read(temp.path()).unwrap(), source, "phase {phase:?}");
    }
}

#[test]
fn coupled_regular_image_and_semantic_capsule_cuts_recover_exact_disk_bytes() {
    let limits = CapsuleLimits::default();
    let groups = forward_groups();
    let bundle = decode_recovery_bundle(&recovery_payload(), recovery_limits()).unwrap();
    let source = source_image();
    for (previous_phase, next_phase, applied_groups) in [
        (
            TransactionPhase::TargetStaged,
            TransactionPhase::BackupBootWritten,
            2,
        ),
        (
            TransactionPhase::BackupBootWritten,
            TransactionPhase::Activated,
            3,
        ),
        (TransactionPhase::Activated, TransactionPhase::RolledBack, 0),
    ] {
        let previous = capsule_at(previous_phase);
        let mut updated = previous.clone();
        append_generation(&mut updated, IDENTITY, next_phase, CHECKPOINT, limits).unwrap();
        let suffix = &updated[previous.len()..];

        // Byte-exhaustive newest-generation recovery lives in capsule_store's focused tests. This
        // coupled disk matrix samples every framing transition while keeping routine Windows gates
        // fast despite multiple real FlushFileBuffers calls per cut.
        for cut in semantic_suffix_cuts(suffix.len()) {
            let image = TempImage::create(&source);
            let capsule = TempImage::vacant("coupled-cut");
            let (store, _) =
                CapsuleStore::create_new(capsule.path(), image.path(), &previous, limits).unwrap();
            drop(store);

            let mut changed = source.clone();
            if next_phase == TransactionPhase::RolledBack {
                for group in &groups {
                    apply_group(&mut changed, group);
                }
                for before_image in rollback_writes(&bundle, previous_phase) {
                    apply(&mut changed, before_image);
                }
            } else {
                for group in groups.iter().take(applied_groups) {
                    apply_group(&mut changed, group);
                }
            }
            persist_exact_regular_file(image.path(), &changed);
            append_and_sync_regular_file(capsule.path(), &suffix[..cut]);

            let (recovered, _) =
                CapsuleStore::resume_recovering(capsule.path(), image.path(), limits).unwrap();
            let durable_phase = scan_capsule(recovered.bytes(), limits)
                .unwrap()
                .newest()
                .unwrap()
                .phase;
            let expected_phase = if cut == suffix.len() {
                next_phase
            } else {
                previous_phase
            };
            assert_eq!(durable_phase, expected_phase, "{next_phase:?} cut {cut}");
            drop(recovered);

            let mut actual = fs::read(image.path()).unwrap();
            for before_image in rollback_writes(&bundle, durable_phase) {
                apply(&mut actual, before_image);
            }
            persist_exact_regular_file(image.path(), &actual);
            assert_eq!(
                fs::read(image.path()).unwrap(),
                source,
                "disk rollback at {next_phase:?} cut {cut} durable {durable_phase:?}"
            );
        }
    }
}

#[test]
fn recovery_payload_decodes_to_every_exact_phase_before_image() {
    let payload = recovery_payload();
    let decoded = decode_recovery_bundle(&payload, recovery_limits()).unwrap();
    assert_eq!(decoded, recovery_bundle());
    assert_eq!(decoded.plan_digest, PLAN_DIGEST);

    let discovered = capsule_at(TransactionPhase::Discovered);
    let view = scan_capsule(&discovered, CapsuleLimits::default()).unwrap();
    assert_eq!(view.newest().unwrap().payload, payload);

    let source = source_image();
    for before_image in decoded
        .target_staging
        .iter()
        .chain(&decoded.backup_boot)
        .chain(&decoded.activation)
    {
        let start = usize::try_from(before_image.offset).unwrap();
        let end = start + before_image.bytes.len();
        assert_eq!(before_image.bytes, source[start..end]);
    }
}

#[test]
fn all_newest_generation_cuts_fall_back_to_the_last_complete_prefix() {
    let phases = [
        TransactionPhase::Reserved,
        TransactionPhase::Relocating,
        TransactionPhase::TargetStaged,
        TransactionPhase::BackupBootWritten,
        TransactionPhase::Activated,
        TransactionPhase::Verified,
        TransactionPhase::Finalized,
    ];
    let limits = CapsuleLimits::default();

    for (index, phase) in phases.into_iter().enumerate() {
        let previous_phase = if index == 0 {
            TransactionPhase::Discovered
        } else {
            phases[index - 1]
        };
        let previous = capsule_at(previous_phase);
        let complete = capsule_at(phase);
        let view = scan_capsule(&complete, limits).unwrap();
        let newest = view.newest().unwrap();
        let start = usize::try_from(newest.offset).unwrap();
        assert_eq!(start, previous.len());

        for cut in start + 1..complete.len() {
            assert!(
                scan_capsule(&complete[..cut], limits).is_err(),
                "{phase:?} cut {cut}"
            );
            let recovered = recover_capsule(&complete[..cut], limits).unwrap();
            assert_eq!(recovered.validated_bytes(), previous.len());
            assert_eq!(recovered.newest().unwrap().phase, previous_phase);
        }
        assert_eq!(
            scan_capsule(&previous, limits)
                .unwrap()
                .newest()
                .unwrap()
                .phase,
            previous_phase
        );

        let trailing_start = complete.len() - HEADER_BYTES;
        let mut primary_corrupt = complete.clone();
        primary_corrupt[start] ^= 0x80;
        assert_eq!(
            scan_capsule(&primary_corrupt, limits)
                .unwrap()
                .newest()
                .unwrap()
                .phase,
            phase
        );
        let recovered = recover_capsule(&primary_corrupt, limits).unwrap();
        assert_eq!(recovered.validated_bytes(), complete.len());
        assert_eq!(recovered.newest().unwrap().phase, phase);
        let mut trailing_corrupt = complete.clone();
        trailing_corrupt[trailing_start] ^= 0x80;
        assert_eq!(
            scan_capsule(&trailing_corrupt, limits)
                .unwrap()
                .newest()
                .unwrap()
                .phase,
            phase
        );
        let recovered = recover_capsule(&trailing_corrupt, limits).unwrap();
        assert_eq!(recovered.validated_bytes(), complete.len());
        assert_eq!(recovered.newest().unwrap().phase, phase);
        let mut both_corrupt = primary_corrupt;
        both_corrupt[trailing_start] ^= 0x80;
        assert!(scan_capsule(&both_corrupt, limits).is_err());
        assert!(recover_capsule(&both_corrupt, limits).is_err());

        let payload_start = start + HEADER_BYTES;
        let mut payload_corrupt = complete.clone();
        payload_corrupt[payload_start] ^= 0x80;
        assert!(scan_capsule(&payload_corrupt, limits).is_err());
        assert!(recover_capsule(&payload_corrupt, limits).is_err());
    }
}

#[test]
fn finalized_is_the_only_forward_acceptance_boundary_for_rollback() {
    let limits = CapsuleLimits::default();
    for phase in [
        TransactionPhase::Discovered,
        TransactionPhase::Reserved,
        TransactionPhase::Relocating,
        TransactionPhase::TargetStaged,
        TransactionPhase::BackupBootWritten,
        TransactionPhase::Activated,
        TransactionPhase::Verified,
    ] {
        let mut capsule = capsule_at(phase);
        append_generation(
            &mut capsule,
            IDENTITY,
            TransactionPhase::RolledBack,
            CHECKPOINT,
            limits,
        )
        .unwrap();
        assert_eq!(
            scan_capsule(&capsule, limits)
                .unwrap()
                .newest()
                .unwrap()
                .phase,
            TransactionPhase::RolledBack
        );
    }

    let mut finalized = capsule_at(TransactionPhase::Finalized);
    assert!(
        append_generation(
            &mut finalized,
            IDENTITY,
            TransactionPhase::RolledBack,
            CHECKPOINT,
            limits,
        )
        .is_err()
    );
    assert_eq!(
        scan_capsule(&finalized, limits)
            .unwrap()
            .newest()
            .unwrap()
            .phase,
        TransactionPhase::Finalized
    );
}
