//! Internal durable coordination for the non-activating regular-image slice.
//!
//! There is deliberately no public or frontend entry point. This module acquires the image
//! executor first and the capsule store second, owns both locks, and cannot advance beyond
//! `TargetStaged`. Its candidate audit reads through a view borrowed from that already-locked
//! executor; honest construction of the initial sealed [`ObservedImage`] remains future work.

use std::fmt;
use std::path::Path;

use crate::FileSystem;
use crate::capsule::TransactionPhase;
use crate::capsule_store::{CapsuleRecoveryEvidence, CapsuleStore, CapsuleStoreError};
use crate::executor::{
    ExecutionLease, ExecutorError, ExecutorLimits, ImageExecutor, LeasedIntent, LeasedRollback,
};
use crate::image::ImageIdentity;
use crate::inspect::{InspectionError, inspect_overlay};
use crate::overlay::OverlayError;
use crate::verify::{
    VerificationError, VerificationLimits, VerificationManifest, build_manifest_with_reader,
};

use super::{
    ConversionError, ObservedImage, PreparedConversion, StagingVerificationEvidence,
    TransactionIntent,
};

const CANDIDATE_AUDIT_MAX_READ_BYTES: usize = 16 * 1024 * 1024;

/// Last checkpoint known to have been durably appended by this coordinator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurableCheckpoint {
    pub generation: u64,
    pub phase: TransactionPhase,
}

/// Locks and state for the deliberately bounded pre-activation transaction slice.
///
/// Field order is intentional: Rust drops fields in declaration order, so the image lock is held
/// until after the capsule store has been dropped.
#[derive(Debug)]
pub struct RegularImageCoordinator<'plan> {
    store: CapsuleStore,
    executor: ImageExecutor,
    prepared: &'plan PreparedConversion,
    observed: ObservedImage,
    poisoned: bool,
}

impl<'plan> RegularImageCoordinator<'plan> {
    /// Opens the image executor before opening/recovering the capsule store, then binds both to the
    /// exact sealed plan and current capsule generation.
    ///
    /// This remains crate-private because no production locked inspector can yet construct the
    /// required `ObservedImage` honestly.
    pub fn resume_existing(
        prepared: &'plan PreparedConversion,
        observed: ObservedImage,
        image_path: impl AsRef<Path>,
        expected_image: &ImageIdentity,
        capsule_path: impl AsRef<Path>,
        executor_limits: ExecutorLimits,
    ) -> Result<(Self, CapsuleRecoveryEvidence), RegularImageCoordinatorError> {
        // Lock order is a safety property: image first, capsule second.
        let executor = ImageExecutor::open(image_path.as_ref(), expected_image, executor_limits)
            .map_err(RegularImageCoordinatorError::Executor)?;
        if !prepared.matches_regular_image(executor.identity()) {
            return Err(RegularImageCoordinatorError::PlanImageMismatch);
        }
        let (store, recovery) =
            CapsuleStore::resume_recovering(capsule_path, image_path, prepared.capsule_limits)
                .map_err(RegularImageCoordinatorError::CapsuleStore)?;
        let coordinator = Self {
            store,
            executor,
            prepared,
            observed,
            poisoned: false,
        };
        let checkpoint = coordinator.checkpoint()?;
        if phase_after_target_staged(checkpoint.phase) {
            return Err(RegularImageCoordinatorError::BeyondPreactivation {
                phase: checkpoint.phase,
            });
        }
        Ok((coordinator, recovery))
    }

    /// Advances a no-relocation plan through its durable `TargetStaged` checkpoint.
    ///
    /// Any nonempty relocation list is refused before the executor receives an intent. Every image
    /// mutation completes read-back verification plus both flush barriers before the corresponding
    /// capsule generation is built and appended.
    pub fn advance_to_target_staged(
        &mut self,
    ) -> Result<DurableCheckpoint, RegularImageCoordinatorError> {
        self.ensure_forward_ready()?;
        if !self.prepared.layout().relocations.is_empty() {
            return Err(RegularImageCoordinatorError::RelocationNotSupported);
        }

        loop {
            let checkpoint = self.checkpoint()?;
            match checkpoint.phase {
                TransactionPhase::Discovered => self.append_reservation()?,
                TransactionPhase::Reserved | TransactionPhase::Relocating => {
                    self.execute_next_mutation(checkpoint)?;
                }
                TransactionPhase::TargetStaged => return Ok(checkpoint),
                phase => {
                    return Err(RegularImageCoordinatorError::BeyondPreactivation { phase });
                }
            }
        }
    }

    /// Parses and logically hashes the exact staged candidate through the prepared overlay.
    ///
    /// The base reader is cloned from the executor's already-open handle and cannot outlive its
    /// lock. The normalized graph must match the plan before staging evidence is returned. The
    /// logical manifest is diagnostic evidence only until a future durable plan envelope commits
    /// to the expected source manifest; this method never appends `Verified` or activates a boot
    /// sector.
    pub(crate) fn audit_staged_candidate(
        &mut self,
        verification_limits: VerificationLimits,
    ) -> Result<(StagingVerificationEvidence, VerificationManifest), RegularImageCoordinatorError>
    {
        self.ensure_forward_ready()?;
        let checkpoint = self.checkpoint()?;
        if checkpoint.phase != TransactionPhase::TargetStaged {
            return Err(RegularImageCoordinatorError::CandidateAuditUnavailable {
                phase: checkpoint.phase,
            });
        }

        let view = match self.executor.locked_view(CANDIDATE_AUDIT_MAX_READ_BYTES) {
            Ok(view) => view,
            Err(error) => {
                self.poison();
                return Err(RegularImageCoordinatorError::Executor(error));
            }
        };
        let expected = self.prepared.expected_staging_verification();
        let audit = (|| {
            let inspection = inspect_overlay(
                &view,
                self.executor.identity(),
                self.prepared.candidate_overlay(),
                self.prepared.candidate_overlay_digest(),
            )
            .map_err(RegularImageCoordinatorError::Inspection)?;
            if inspection.profile.filesystem != expected.target_filesystem {
                return Err(RegularImageCoordinatorError::CandidateFilesystemMismatch {
                    expected: expected.target_filesystem,
                    actual: inspection.profile.filesystem,
                });
            }
            if !inspection.profile.inventory_complete {
                return Err(RegularImageCoordinatorError::CandidateInventoryIncomplete);
            }
            let graph = match expected.target_filesystem {
                FileSystem::ExFat => inspection
                    .normalized_exfat
                    .as_deref()
                    .map(|normalized| &normalized.graph),
                FileSystem::Ntfs => inspection
                    .normalized_ntfs
                    .as_deref()
                    .map(|normalized| &normalized.graph),
                FileSystem::Unknown => None,
            }
            .ok_or(RegularImageCoordinatorError::CandidateInventoryIncomplete)?;
            let object_graph_digest = super::digest_graph(graph);
            if object_graph_digest != expected.object_graph_digest {
                return Err(RegularImageCoordinatorError::CandidateGraphMismatch);
            }

            let overlay_reader = self
                .prepared
                .candidate_overlay()
                .reader(&view)
                .map_err(RegularImageCoordinatorError::Overlay)?;
            let manifest = build_manifest_with_reader(&overlay_reader, graph, verification_limits)
                .map_err(RegularImageCoordinatorError::Verification)?;
            let evidence = StagingVerificationEvidence {
                target_filesystem: expected.target_filesystem,
                parser_validated: true,
                inventory_complete: true,
                object_graph_digest,
                plan_digest: expected.plan_digest,
                candidate_overlay_digest: expected.candidate_overlay_digest,
            };
            Ok((evidence, manifest))
        })();
        let revalidation = view.post_operation_revalidate();
        drop(view);
        if let Err(error) = revalidation {
            self.poison();
            return Err(RegularImageCoordinatorError::Executor(error));
        }
        audit
    }

    /// Reapplies the plan's conservative before-images and durably records `RolledBack`.
    ///
    /// If a capsule append was ambiguous, the store first restores its exact last verified prefix.
    /// Retrying this method is safe: rollback writes are exact before-images and therefore
    /// idempotent.
    pub fn rollback(&mut self) -> Result<DurableCheckpoint, RegularImageCoordinatorError> {
        if self.store.is_poisoned() {
            self.store
                .restore_verified_prefix()
                .map_err(RegularImageCoordinatorError::CapsuleStore)?;
        }
        let checkpoint = self.checkpoint()?;
        if matches!(
            checkpoint.phase,
            TransactionPhase::Finalized | TransactionPhase::RolledBack
        ) {
            return Err(RegularImageCoordinatorError::RollbackUnavailable {
                phase: checkpoint.phase,
            });
        }
        if phase_after_target_staged(checkpoint.phase) {
            return Err(RegularImageCoordinatorError::BeyondPreactivation {
                phase: checkpoint.phase,
            });
        }

        let intent = self
            .prepared
            .rollback_intent(checkpoint.phase)
            .map_err(RegularImageCoordinatorError::Conversion)?;
        let lease = self.lease(checkpoint);
        let executed = match self
            .executor
            .execute_leased_rollback(self.prepared, lease, intent)
        {
            Ok(executed) => executed,
            Err(error) => {
                self.poison();
                return Err(RegularImageCoordinatorError::Executor(error));
            }
        };
        self.append_rollback(checkpoint, executed)?;
        self.poisoned = false;
        self.checkpoint()
    }

    fn append_reservation(&mut self) -> Result<(), RegularImageCoordinatorError> {
        let mut updated = self.store.bytes().to_vec();
        self.prepared
            .record_reservation(&mut updated, self.observed)
            .map_err(RegularImageCoordinatorError::Conversion)?;
        self.append_capsule(&updated)
    }

    fn execute_next_mutation(
        &mut self,
        checkpoint: DurableCheckpoint,
    ) -> Result<(), RegularImageCoordinatorError> {
        let resumed = self
            .prepared
            .resume(self.store.bytes(), self.observed)
            .map_err(RegularImageCoordinatorError::Conversion)?;
        let authorized = matches!(
            (&resumed.next, checkpoint.phase),
            (TransactionIntent::Relocate(_), TransactionPhase::Reserved)
                | (
                    TransactionIntent::StageTarget(_),
                    TransactionPhase::Relocating
                )
        );
        if !authorized {
            return Err(RegularImageCoordinatorError::LeaseStateChanged);
        }
        let lease = self.lease(checkpoint);
        let executed = match self
            .executor
            .execute_leased_intent(self.prepared, lease, resumed.next)
        {
            Ok(executed) => executed,
            Err(error) => {
                self.poison();
                return Err(RegularImageCoordinatorError::Executor(error));
            }
        };
        self.append_execution(checkpoint, executed)
    }

    fn append_execution(
        &mut self,
        checkpoint: DurableCheckpoint,
        executed: LeasedIntent,
    ) -> Result<(), RegularImageCoordinatorError> {
        let (executed, generation, phase) = executed.into_parts();
        if generation != checkpoint.generation || phase != checkpoint.phase {
            self.poison();
            return Err(RegularImageCoordinatorError::LeaseStateChanged);
        }
        let mut updated = self.store.bytes().to_vec();
        if let Err(error) =
            self.prepared
                .record_execution(&mut updated, self.observed, executed, None)
        {
            self.poison();
            return Err(RegularImageCoordinatorError::Conversion(error));
        }
        self.append_capsule(&updated)
    }

    fn append_rollback(
        &mut self,
        checkpoint: DurableCheckpoint,
        executed: LeasedRollback,
    ) -> Result<(), RegularImageCoordinatorError> {
        let (executed, generation, phase) = executed.into_parts();
        if generation != checkpoint.generation || phase != checkpoint.phase {
            self.poison();
            return Err(RegularImageCoordinatorError::LeaseStateChanged);
        }
        let mut updated = self.store.bytes().to_vec();
        if let Err(error) =
            self.prepared
                .record_executed_rollback(&mut updated, self.observed, executed)
        {
            self.poison();
            return Err(RegularImageCoordinatorError::Conversion(error));
        }
        self.append_capsule(&updated)
    }

    fn append_capsule(&mut self, updated: &[u8]) -> Result<(), RegularImageCoordinatorError> {
        match self.store.append(updated) {
            Ok(evidence) if evidence.sync_data_completed && evidence.sync_all_completed => Ok(()),
            Ok(_) => {
                self.poison();
                Err(RegularImageCoordinatorError::CapsuleDurabilityMissing)
            }
            Err(error) => {
                self.poisoned = true;
                // `CapsuleStore::append` poisons itself at the first possibly mutating I/O
                // boundary. Preflight-only errors are also conservatively coupled-poisoned here.
                self.store.poison();
                Err(RegularImageCoordinatorError::CapsuleStore(error))
            }
        }
    }

    fn checkpoint(&self) -> Result<DurableCheckpoint, RegularImageCoordinatorError> {
        let resumed = self
            .prepared
            .resume(self.store.bytes(), self.observed)
            .map_err(RegularImageCoordinatorError::Conversion)?;
        let count = u64::try_from(self.store.generation_count())
            .map_err(|_| RegularImageCoordinatorError::GenerationOverflow)?;
        if count != resumed.generation.saturating_add(1) {
            return Err(RegularImageCoordinatorError::LeaseStateChanged);
        }
        Ok(DurableCheckpoint {
            generation: resumed.generation,
            phase: resumed.phase,
        })
    }

    fn lease(&self, checkpoint: DurableCheckpoint) -> ExecutionLease {
        ExecutionLease::new(
            checkpoint.generation,
            checkpoint.phase,
            self.prepared.plan_digest(),
            self.executor.identity().stable_container_token(),
        )
    }

    const fn ensure_forward_ready(&self) -> Result<(), RegularImageCoordinatorError> {
        if self.poisoned || self.store.is_poisoned() {
            Err(RegularImageCoordinatorError::Poisoned)
        } else {
            Ok(())
        }
    }

    const fn poison(&mut self) {
        self.poisoned = true;
        self.store.poison();
    }
}

const fn phase_after_target_staged(phase: TransactionPhase) -> bool {
    matches!(
        phase,
        TransactionPhase::BackupBootWritten
            | TransactionPhase::Activated
            | TransactionPhase::Verified
            | TransactionPhase::Finalized
    )
}

/// Internal coordinator construction, state, mutation, or durability failure.
#[derive(Debug)]
pub enum RegularImageCoordinatorError {
    Executor(ExecutorError),
    CapsuleStore(CapsuleStoreError),
    Conversion(ConversionError),
    Inspection(InspectionError),
    Overlay(OverlayError),
    Verification(VerificationError),
    PlanImageMismatch,
    RelocationNotSupported,
    LeaseStateChanged,
    CapsuleDurabilityMissing,
    Poisoned,
    GenerationOverflow,
    BeyondPreactivation {
        phase: TransactionPhase,
    },
    RollbackUnavailable {
        phase: TransactionPhase,
    },
    CandidateAuditUnavailable {
        phase: TransactionPhase,
    },
    CandidateFilesystemMismatch {
        expected: FileSystem,
        actual: FileSystem,
    },
    CandidateInventoryIncomplete,
    CandidateGraphMismatch,
}

impl fmt::Display for RegularImageCoordinatorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Executor(error) => write!(formatter, "image executor failed: {error}"),
            Self::CapsuleStore(error) => write!(formatter, "capsule store failed: {error}"),
            Self::Conversion(error) => write!(formatter, "conversion state rejected: {error}"),
            Self::Inspection(error) => write!(formatter, "candidate inspection failed: {error}"),
            Self::Overlay(error) => write!(formatter, "candidate overlay failed: {error}"),
            Self::Verification(error) => {
                write!(formatter, "candidate logical verification failed: {error}")
            }
            Self::PlanImageMismatch => {
                formatter.write_str("prepared conversion does not match the locked image")
            }
            Self::RelocationNotSupported => formatter.write_str(
                "pre-activation coordinator refuses nonempty relocation plans before writing",
            ),
            Self::LeaseStateChanged => {
                formatter.write_str("capsule generation or phase changed across a one-use lease")
            }
            Self::CapsuleDurabilityMissing => {
                formatter.write_str("capsule append returned incomplete durability evidence")
            }
            Self::Poisoned => formatter.write_str(
                "coordinator is poisoned after an ambiguous operation; rollback is required",
            ),
            Self::GenerationOverflow => formatter.write_str("capsule generation count overflowed"),
            Self::BeyondPreactivation { phase } => write!(
                formatter,
                "phase {phase:?} is beyond the coordinator's TargetStaged safety boundary"
            ),
            Self::RollbackUnavailable { phase } => {
                write!(formatter, "rollback is unavailable from phase {phase:?}")
            }
            Self::CandidateAuditUnavailable { phase } => write!(
                formatter,
                "candidate audit requires TargetStaged, found {phase:?}"
            ),
            Self::CandidateFilesystemMismatch { expected, actual } => write!(
                formatter,
                "candidate filesystem mismatch: expected {expected}, found {actual}"
            ),
            Self::CandidateInventoryIncomplete => {
                formatter.write_str("candidate filesystem inventory is incomplete")
            }
            Self::CandidateGraphMismatch => {
                formatter.write_str("candidate object graph does not match the prepared plan")
            }
        }
    }
}

impl std::error::Error for RegularImageCoordinatorError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Executor(error) => Some(error),
            Self::CapsuleStore(error) => Some(error),
            Self::Conversion(error) => Some(error),
            Self::Inspection(error) => Some(error),
            Self::Overlay(error) => Some(error),
            Self::Verification(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::capsule::recover_capsule;
    use crate::capsule_store::CapsuleStore;
    use crate::extent::{ExtentGraph, StreamId};
    use crate::fs::exfat_inventory::ExfatPreservationEvidence;
    use crate::fs::exfat_serialize::{
        ExfatSerializeLimits, ExfatSerializeOptions, ExfatVolumeProfile,
        non_interoperable_ascii_test_upcase_table, serialize_exfat_destination,
    };
    use crate::fs::exfat_upcase::table_checksum;
    use crate::geometry::{ByteRange, DestinationReservation, Relocation, ReservationKind};
    use crate::image::{BoundedImageReader, ImageFile};
    use crate::object::{
        ObjectGraph, ObjectGraphLimits, ObjectId, ObjectKind, ObjectRecord, ObjectSemantics,
    };
    use crate::phase::{ActivationAuthorizedWrites, preview_exfat_phase_writes};
    use crate::preimage::PreimageLimits;

    use super::super::{
        ConversionDraft, ConversionLimits, ImageIdentity as ConversionImageIdentity,
        PreflightEvidence, TargetCapabilities,
    };

    use super::*;

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    #[derive(Debug)]
    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let unique = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "starconverter-regular-coordinator-{}-{unique}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn fixture() -> (TempDir, PathBuf, PathBuf, PreparedConversion, ObservedImage) {
        let dir = TempDir::new();
        let image_path = dir.join("source.img");
        let capsule_path = dir.join("transaction.starcap");
        let mut prepared = super::super::tests::prepared();
        fs::write(
            &image_path,
            vec![0x5a; usize::try_from(prepared.preflight.image.image_bytes).unwrap()],
        )
        .unwrap();
        let image = ImageFile::open(&image_path).unwrap();
        let identity = image.identity().clone();
        prepared.test_bind_regular_image(&identity);
        let observed = ObservedImage {
            image: prepared.preflight.image,
            source_evidence_digest: Some(prepared.preflight.source_evidence_digest),
        };
        let mut capsule = Vec::new();
        prepared.begin_capsule(&mut capsule, observed).unwrap();
        drop(image);
        let (store, _) = CapsuleStore::create_new(
            &capsule_path,
            &image_path,
            &capsule,
            prepared.capsule_limits,
        )
        .unwrap();
        drop(store);
        (dir, image_path, capsule_path, prepared, observed)
    }

    fn empty_graph(image_bytes: u64) -> ObjectGraph {
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
            ExtentGraph::build(Vec::new(), image_bytes, 8).unwrap(),
            ObjectGraphLimits {
                max_objects: 8,
                max_entries: 8,
                max_streams: 8,
                max_name_code_units: 255,
            },
        )
        .unwrap()
    }

    fn valid_exfat_fixture() -> (TempDir, PathBuf, PathBuf, PreparedConversion, ObservedImage) {
        const IMAGE_BYTES: u64 = 4 * 1024 * 1024;

        let dir = TempDir::new();
        let image_path = dir.join("valid-source.img");
        let capsule_path = dir.join("valid-transaction.starcap");
        fs::write(
            &image_path,
            vec![0_u8; usize::try_from(IMAGE_BYTES).unwrap()],
        )
        .unwrap();
        let image = ImageFile::open(&image_path).unwrap();
        let graph = empty_graph(IMAGE_BYTES);
        let upcase = non_interoperable_ascii_test_upcase_table();
        let serializer = serialize_exfat_destination(
            &graph,
            &[],
            ExfatVolumeProfile {
                volume_label: None,
                encoded_upcase_table: &upcase,
                upcase_checksum: table_checksum(&upcase),
                source_preservation: ExfatPreservationEvidence::default(),
                allocated_bad_clusters: 0,
            },
            ExfatSerializeOptions::default(),
            ExfatSerializeLimits::default(),
        )
        .unwrap();
        let preview =
            preview_exfat_phase_writes(&image, &serializer, PreimageLimits::default()).unwrap();
        let source_identity = ConversionImageIdentity::from_regular_image(image.identity());
        let source_evidence_digest = [0x6a; 32];
        let mut reservations = serializer.reservations.clone();
        reservations.push(DestinationReservation {
            range: ByteRange {
                offset: IMAGE_BYTES - 512,
                length: 512,
            },
            kind: ReservationKind::Capsule,
        });
        let draft = ConversionDraft {
            transaction_id: [0x3c; 16],
            preflight: PreflightEvidence {
                image: source_identity,
                source_filesystem: FileSystem::Ntfs,
                source_evidence_digest,
                sector_bytes: 512,
                allocation_alignment: 512,
                inventory_complete: true,
                allocation_map_complete: true,
                health: crate::HealthState::Clean,
                access: crate::AccessState::Offline,
            },
            target: TargetCapabilities {
                filesystem: FileSystem::ExFat,
                features: Vec::new(),
            },
            source_allocations: serializer.source_allocations,
            reservations,
            writes: ActivationAuthorizedWrites::test_only(
                FileSystem::ExFat,
                preview.writes().clone(),
            ),
        };
        let prepared =
            PreparedConversion::build(&graph, draft, ConversionLimits::default()).unwrap();
        let observed = ObservedImage {
            image: source_identity,
            source_evidence_digest: Some(source_evidence_digest),
        };
        let mut capsule = Vec::new();
        prepared.begin_capsule(&mut capsule, observed).unwrap();
        drop(image);
        let (store, _) = CapsuleStore::create_new(
            &capsule_path,
            &image_path,
            &capsule,
            prepared.capsule_limits,
        )
        .unwrap();
        drop(store);
        (dir, image_path, capsule_path, prepared, observed)
    }

    #[test]
    fn stages_only_through_target_staged_and_flushes_capsule_after_image() {
        let (_dir, image_path, capsule_path, prepared, observed) = fixture();
        assert!(prepared.layout().relocations.is_empty());
        let image = ImageFile::open(&image_path).unwrap();
        let identity = image.identity().clone();
        drop(image);
        let (mut coordinator, recovery) = RegularImageCoordinator::resume_existing(
            &prepared,
            observed,
            &image_path,
            &identity,
            &capsule_path,
            ExecutorLimits::default(),
        )
        .unwrap();
        assert_eq!(recovery.discarded_torn_bytes, 0);

        let checkpoint = coordinator.advance_to_target_staged().unwrap();
        assert_eq!(
            checkpoint,
            DurableCheckpoint {
                generation: 3,
                phase: TransactionPhase::TargetStaged,
            }
        );
        drop(coordinator);

        let image_bytes = fs::read(&image_path).unwrap();
        assert_eq!(&image_bytes[2048..2560], &[0x20; 512]);
        assert_eq!(&image_bytes[2560..3072], &[0x30; 512]);
        assert_eq!(&image_bytes[1024..1536], &[0x5a; 512]);
        let capsule_bytes = fs::read(&capsule_path).unwrap();
        let view = recover_capsule(&capsule_bytes, prepared.capsule_limits).unwrap();
        assert_eq!(view.newest().unwrap().phase, TransactionPhase::TargetStaged);
    }

    #[test]
    fn target_staged_rollback_restores_exact_before_images_and_is_durable() {
        let (_dir, image_path, capsule_path, prepared, observed) = fixture();
        let image = ImageFile::open(&image_path).unwrap();
        let identity = image.identity().clone();
        drop(image);
        let (mut coordinator, _) = RegularImageCoordinator::resume_existing(
            &prepared,
            observed,
            &image_path,
            &identity,
            &capsule_path,
            ExecutorLimits::default(),
        )
        .unwrap();
        coordinator.advance_to_target_staged().unwrap();
        let checkpoint = coordinator.rollback().unwrap();
        assert_eq!(checkpoint.phase, TransactionPhase::RolledBack);
        assert_eq!(checkpoint.generation, 4);
        drop(coordinator);

        let image_bytes = fs::read(&image_path).unwrap();
        assert_eq!(&image_bytes[2048..2560], &[0x12; 512]);
        assert_eq!(&image_bytes[2560..3072], &[0x13; 512]);
        let capsule_bytes = fs::read(&capsule_path).unwrap();
        let view = recover_capsule(&capsule_bytes, prepared.capsule_limits).unwrap();
        assert_eq!(view.newest().unwrap().phase, TransactionPhase::RolledBack);
    }

    #[test]
    fn staged_candidate_audit_fails_closed_without_mutating_image_or_capsule() {
        let (_dir, image_path, capsule_path, prepared, observed) = fixture();
        let image = ImageFile::open(&image_path).unwrap();
        let identity = image.identity().clone();
        drop(image);
        let (mut coordinator, _) = RegularImageCoordinator::resume_existing(
            &prepared,
            observed,
            &image_path,
            &identity,
            &capsule_path,
            ExecutorLimits::default(),
        )
        .unwrap();
        coordinator.advance_to_target_staged().unwrap();
        let image_before = coordinator
            .executor
            .locked_view(CANDIDATE_AUDIT_MAX_READ_BYTES)
            .unwrap()
            .read_exact_at(
                0,
                usize::try_from(coordinator.executor.identity().length()).unwrap(),
            )
            .unwrap();
        let capsule_before = coordinator.store.bytes().to_vec();

        assert!(matches!(
            coordinator.audit_staged_candidate(VerificationLimits::default()),
            Err(RegularImageCoordinatorError::Inspection(
                InspectionError::UnrecognizedFileSystem
            ))
        ));
        let image_after = coordinator
            .executor
            .locked_view(CANDIDATE_AUDIT_MAX_READ_BYTES)
            .unwrap()
            .read_exact_at(0, image_before.len())
            .unwrap();
        assert_eq!(image_after, image_before);
        assert_eq!(coordinator.store.bytes(), capsule_before);
    }

    #[test]
    fn staged_candidate_audit_parses_and_hashes_the_plan_overlay() {
        let (_dir, image_path, capsule_path, prepared, observed) = valid_exfat_fixture();
        let image = ImageFile::open(&image_path).unwrap();
        let identity = image.identity().clone();
        drop(image);
        let (mut coordinator, _) = RegularImageCoordinator::resume_existing(
            &prepared,
            observed,
            &image_path,
            &identity,
            &capsule_path,
            ExecutorLimits::default(),
        )
        .unwrap();
        coordinator.advance_to_target_staged().unwrap();
        let capsule_before = coordinator.store.bytes().to_vec();

        let (evidence, manifest) = coordinator
            .audit_staged_candidate(VerificationLimits::default())
            .unwrap();

        assert_eq!(
            evidence.target_filesystem,
            prepared.expected_staging_verification().target_filesystem
        );
        assert!(evidence.parser_validated);
        assert!(evidence.inventory_complete);
        assert_eq!(evidence.object_graph_digest, prepared.graph_digest());
        assert_eq!(evidence.plan_digest, prepared.plan_digest());
        assert_eq!(
            evidence.candidate_overlay_digest,
            prepared.candidate_overlay_digest()
        );
        assert_eq!(manifest.logical_bytes_hashed, 0);
        assert_eq!(coordinator.store.bytes(), capsule_before);
    }

    #[test]
    fn nonempty_relocation_is_refused_before_image_or_capsule_changes() {
        let (_dir, image_path, capsule_path, mut prepared, observed) = fixture();
        prepared.layout.relocations.push(Relocation {
            stream: StreamId(7),
            logical_offset: 0,
            source: ByteRange {
                offset: 4096,
                length: 512,
            },
            destination: ByteRange {
                offset: 4608,
                length: 512,
            },
        });
        let image_before = fs::read(&image_path).unwrap();
        let capsule_before = fs::read(&capsule_path).unwrap();
        let image = ImageFile::open(&image_path).unwrap();
        let identity = image.identity().clone();
        drop(image);
        let (mut coordinator, _) = RegularImageCoordinator::resume_existing(
            &prepared,
            observed,
            &image_path,
            &identity,
            &capsule_path,
            ExecutorLimits::default(),
        )
        .unwrap();
        assert!(matches!(
            coordinator.advance_to_target_staged(),
            Err(RegularImageCoordinatorError::RelocationNotSupported)
        ));
        drop(coordinator);
        assert_eq!(fs::read(image_path).unwrap(), image_before);
        assert_eq!(fs::read(capsule_path).unwrap(), capsule_before);
    }
}
