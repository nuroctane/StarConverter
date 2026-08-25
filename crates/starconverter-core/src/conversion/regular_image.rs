//! Internal durable coordination for one regular-image conversion transaction.
//!
//! There is deliberately no public or frontend entry point. This module acquires the image
//! executor first and the capsule store second and owns both locks. Candidate audits read through a
//! view borrowed from that already-locked executor. Resume observations are freshly derived from
//! that locked handle, using conservative rollback before-images to reconstruct the original source
//! view at mutating checkpoints. Backup-boot and activation remain crate-private and are reachable
//! only through exact phase evidence and one-use leases. Verification is a separate operation, and
//! the irreversible finalization boundary additionally requires an unforgeable approval capability.

use std::borrow::Cow;
use std::fmt;
use std::path::Path;

use crate::FileSystem;
use crate::capsule::TransactionPhase;
use crate::capsule_store::{CapsuleRecoveryEvidence, CapsuleStore, CapsuleStoreError};
use crate::executor::{
    ExecutionLease, ExecutorError, ExecutorLimits, ImageExecutor, LeasedIntent, LeasedRollback,
};
use crate::image::{BoundedImageReader, ImageIdentity};
use crate::inspect::{InspectionError, inspect_overlay};
use crate::overlay::{OverlayError, OverlayWrite};
use crate::source_view::{
    SourceDigestLimits, SourceViewError, VirtualOriginalLimits, VirtualOriginalReader,
    digest_source_view,
};
use crate::verify::{
    VerificationError, VerificationLimits, VerificationManifest, build_manifest_with_reader,
};

use super::activation_bytes::{
    ActivationByteError, ActivationByteLimits, ActivationByteState, classify_reserved_write_group,
};
use super::{
    ConversionError, ObservedImage, PreparedConversion, ReservedWrite, StagingVerificationEvidence,
    TransactionIntent, VerificationEvidence,
};

const CANDIDATE_AUDIT_MAX_READ_BYTES: usize = 16 * 1024 * 1024;

/// Last checkpoint known to have been durably appended by this coordinator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurableCheckpoint {
    pub generation: u64,
    pub phase: TransactionPhase,
}

/// Capability required to cross the irreversible `Verified` -> `Finalized` boundary.
///
/// Production code deliberately has no constructor yet. A future frontend may create this only
/// after its explicit user-acceptance policy is implemented and reviewed.
#[derive(Debug, Clone, Copy)]
pub struct FinalizationApproval {
    _private: (),
}

#[cfg(test)]
impl FinalizationApproval {
    const fn for_test() -> Self {
        Self { _private: () }
    }
}

/// Locks and state for the deliberately bounded pre-activation transaction slice.
///
/// Field order is intentional: Rust drops fields in declaration order, so the image lock is held
/// until after the capsule store has been dropped.
#[derive(Debug)]
pub struct RegularImageCoordinator<'plan> {
    store: CapsuleStore,
    executor: ImageExecutor,
    prepared: Cow<'plan, PreparedConversion>,
    poisoned: bool,
}

impl<'plan> RegularImageCoordinator<'plan> {
    /// Opens the image executor before opening/recovering the capsule store, then binds both to the
    /// exact sealed plan and current capsule generation.
    ///
    /// The sealed observation is constructed internally from the locked image; callers cannot
    /// supply or replay source evidence.
    pub fn resume_existing(
        prepared: &'plan PreparedConversion,
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
            prepared: Cow::Borrowed(prepared),
            poisoned: false,
        };
        coordinator.checkpoint()?;
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

    /// Advances a fully prepared no-relocation regular image through activation only.
    ///
    /// Every durable boundary is independently re-audited from the locked handle. Backup boot and
    /// activation writes consume one-use leases. This helper deliberately stops at `Activated`,
    /// while rollback is still available.
    pub(crate) fn advance_to_activated(
        &mut self,
        verification_limits: VerificationLimits,
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
                TransactionPhase::TargetStaged => {
                    self.write_backup_boot(checkpoint, verification_limits)?;
                }
                TransactionPhase::BackupBootWritten => {
                    self.activate_target(checkpoint, verification_limits)?;
                }
                TransactionPhase::Activated => return Ok(checkpoint),
                TransactionPhase::Verified
                | TransactionPhase::Finalized
                | TransactionPhase::RolledBack => {
                    return Err(RegularImageCoordinatorError::ForwardUnavailable {
                        phase: checkpoint.phase,
                    });
                }
            }
        }
    }

    /// Independently re-audits an activated target and appends the durable `Verified` checkpoint.
    /// Rollback remains available after this operation.
    pub(crate) fn verify_activated_target(
        &mut self,
        verification_limits: VerificationLimits,
    ) -> Result<DurableCheckpoint, RegularImageCoordinatorError> {
        self.ensure_forward_ready()?;
        let checkpoint = self.checkpoint()?;
        if checkpoint.phase != TransactionPhase::Activated {
            return Err(RegularImageCoordinatorError::ForwardUnavailable {
                phase: checkpoint.phase,
            });
        }
        self.append_verification(verification_limits)?;
        self.checkpoint()
    }

    /// Repeats the complete activated-target audit and crosses the irreversible finalization
    /// boundary only when the caller presents explicit acceptance authority.
    pub(crate) fn finalize_verified_target(
        &mut self,
        _approval: FinalizationApproval,
        verification_limits: VerificationLimits,
    ) -> Result<DurableCheckpoint, RegularImageCoordinatorError> {
        self.ensure_forward_ready()?;
        let checkpoint = self.checkpoint()?;
        if checkpoint.phase != TransactionPhase::Verified {
            return Err(RegularImageCoordinatorError::ForwardUnavailable {
                phase: checkpoint.phase,
            });
        }
        self.append_finalization(verification_limits)?;
        self.checkpoint()
    }

    /// Parses and logically hashes the exact staged candidate through the prepared overlay.
    ///
    /// The base reader is cloned from the executor's already-open handle and cannot outlive its
    /// lock. Actual staged ranges must still equal the planned bytes before the overlay parser can
    /// fill later write groups. The normalized graph and logical manifest commitment must both
    /// match the plan; this method never appends `Verified` or activates a boot sector.
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

        let (object_graph_digest, manifest) =
            self.audit_candidate(checkpoint.phase, verification_limits)?;
        let expected = self.prepared.expected_staging_verification();
        Ok((
            StagingVerificationEvidence {
                target_filesystem: expected.target_filesystem,
                parser_validated: true,
                inventory_complete: true,
                object_graph_digest,
                plan_digest: expected.plan_digest,
                candidate_overlay_digest: expected.candidate_overlay_digest,
            },
            manifest,
        ))
    }

    /// Re-audits an activated target using exact real bytes before verification or finalization.
    fn audit_activated_candidate(
        &mut self,
        verification_limits: VerificationLimits,
    ) -> Result<(VerificationEvidence, VerificationManifest), RegularImageCoordinatorError> {
        self.ensure_forward_ready()?;
        let checkpoint = self.checkpoint()?;
        if !matches!(
            checkpoint.phase,
            TransactionPhase::Activated | TransactionPhase::Verified
        ) {
            return Err(RegularImageCoordinatorError::ActivatedAuditUnavailable {
                phase: checkpoint.phase,
            });
        }
        let (object_graph_digest, manifest) =
            self.audit_candidate(checkpoint.phase, verification_limits)?;
        let expected = self.prepared.expected_verification();
        Ok((
            VerificationEvidence {
                target_filesystem: expected.target_filesystem,
                inventory_complete: true,
                object_graph_digest,
                plan_digest: expected.plan_digest,
            },
            manifest,
        ))
    }

    /// Parses and hashes the complete target overlay after proving every write group that should
    /// already be durable is byte-for-byte present in the actual locked image.
    fn audit_candidate(
        &mut self,
        phase: TransactionPhase,
        verification_limits: VerificationLimits,
    ) -> Result<([u8; 32], VerificationManifest), RegularImageCoordinatorError> {
        let view = match self.executor.locked_view(CANDIDATE_AUDIT_MAX_READ_BYTES) {
            Ok(view) => view,
            Err(error) => {
                self.poison();
                return Err(RegularImageCoordinatorError::Executor(error));
            }
        };
        let expected = self.prepared.expected_staging_verification();
        let audit = (|| {
            verify_actual_staging_bytes(&view, self.prepared.target_staging_writes())?;
            if matches!(
                phase,
                TransactionPhase::BackupBootWritten
                    | TransactionPhase::Activated
                    | TransactionPhase::Verified
            ) {
                verify_actual_staging_bytes(&view, self.prepared.backup_boot_writes())?;
            }
            if matches!(
                phase,
                TransactionPhase::Activated | TransactionPhase::Verified
            ) {
                verify_actual_staging_bytes(&view, self.prepared.activation_writes())?;
            }
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
            if !self
                .prepared
                .source_manifest_commitment()
                .matches(&manifest)
                .map_err(RegularImageCoordinatorError::Verification)?
            {
                return Err(RegularImageCoordinatorError::CandidateManifestMismatch);
            }
            Ok((object_graph_digest, manifest))
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
        if checkpoint.phase == TransactionPhase::RolledBack {
            return Ok(checkpoint);
        }
        if checkpoint.phase == TransactionPhase::Finalized {
            return Err(RegularImageCoordinatorError::RollbackUnavailable {
                phase: checkpoint.phase,
            });
        }
        let intent = self
            .prepared
            .rollback_intent(checkpoint.phase)
            .map_err(RegularImageCoordinatorError::Conversion)?;
        let lease = self.lease(checkpoint);
        let executed =
            match self
                .executor
                .execute_leased_rollback(self.prepared.as_ref(), lease, intent)
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
        let observed = self.observe_current()?;
        self.prepared
            .record_reservation(&mut updated, observed)
            .map_err(RegularImageCoordinatorError::Conversion)?;
        self.append_capsule(&updated)
    }

    fn write_backup_boot(
        &mut self,
        checkpoint: DurableCheckpoint,
        verification_limits: VerificationLimits,
    ) -> Result<(), RegularImageCoordinatorError> {
        let state = self.classify_backup_boot_bytes()?;
        if state == ActivationByteState::ThirdState {
            return Err(RegularImageCoordinatorError::BackupBootBytesUnsafe { state });
        }
        let (staging_evidence, _) = self.audit_staged_candidate(verification_limits)?;
        let observed = self.observe_current()?;
        let lease = self.lease(checkpoint);
        let executed = {
            let intent = self
                .prepared
                .authorize_backup_boot(self.store.bytes(), observed, staging_evidence)
                .map_err(RegularImageCoordinatorError::Conversion)?;
            self.executor
                .execute_leased_intent(self.prepared.as_ref(), lease, intent)
        };
        let executed = match executed {
            Ok(executed) => executed,
            Err(error) => {
                self.poison();
                return Err(RegularImageCoordinatorError::Executor(error));
            }
        };
        self.append_execution(checkpoint, executed, Some(staging_evidence))
    }

    fn activate_target(
        &mut self,
        checkpoint: DurableCheckpoint,
        verification_limits: VerificationLimits,
    ) -> Result<(), RegularImageCoordinatorError> {
        let state = self.classify_activation_bytes()?;
        if matches!(
            state,
            ActivationByteState::MixedBeforeAfter | ActivationByteState::ThirdState
        ) {
            return Err(RegularImageCoordinatorError::ActivationBytesAmbiguous { state });
        }
        // The target overlay must remain complete and logically identical immediately before the
        // primary recognition/cutover write. At this phase, audit_candidate also proves all actual
        // staging and backup-boot bytes.
        self.audit_candidate(checkpoint.phase, verification_limits)?;
        let observed = self.observe_current()?;
        let resumed = self
            .prepared
            .resume(self.store.bytes(), observed)
            .map_err(RegularImageCoordinatorError::Conversion)?;
        if !matches!(resumed.next, TransactionIntent::Activate(_)) {
            return Err(RegularImageCoordinatorError::LeaseStateChanged);
        }
        let lease = self.lease(checkpoint);
        let executed =
            self.executor
                .execute_leased_intent(self.prepared.as_ref(), lease, resumed.next);
        let executed = match executed {
            Ok(executed) => executed,
            Err(error) => {
                self.poison();
                return Err(RegularImageCoordinatorError::Executor(error));
            }
        };
        self.append_execution(checkpoint, executed, None)
    }

    fn append_verification(
        &mut self,
        verification_limits: VerificationLimits,
    ) -> Result<(), RegularImageCoordinatorError> {
        let (evidence, _) = self.audit_activated_candidate(verification_limits)?;
        let mut updated = self.store.bytes().to_vec();
        let observed = self.observe_current()?;
        self.prepared
            .record_verification(&mut updated, observed, evidence)
            .map_err(RegularImageCoordinatorError::Conversion)?;
        self.append_capsule(&updated)
    }

    fn append_finalization(
        &mut self,
        verification_limits: VerificationLimits,
    ) -> Result<(), RegularImageCoordinatorError> {
        // Finalization crosses the rollback boundary, so repeat the full real-byte/parser/manifest
        // audit instead of relying on evidence from the prior checkpoint.
        self.audit_activated_candidate(verification_limits)?;
        let mut updated = self.store.bytes().to_vec();
        let observed = self.observe_current()?;
        self.prepared
            .record_finalization(&mut updated, observed)
            .map_err(RegularImageCoordinatorError::Conversion)?;
        self.append_capsule(&updated)
    }

    fn classify_backup_boot_bytes(
        &mut self,
    ) -> Result<ActivationByteState, RegularImageCoordinatorError> {
        let classified = classify_prepared_write_group(
            &self.executor,
            self.prepared.backup_boot_before_images(),
            self.prepared.backup_boot_writes(),
        );
        if classified.is_err() {
            self.poison();
        }
        classified
    }

    fn classify_activation_bytes(
        &mut self,
    ) -> Result<ActivationByteState, RegularImageCoordinatorError> {
        let classified = classify_prepared_write_group(
            &self.executor,
            self.prepared.activation_before_images(),
            self.prepared.activation_writes(),
        );
        if classified.is_err() {
            self.poison();
        }
        classified
    }

    fn execute_next_mutation(
        &mut self,
        checkpoint: DurableCheckpoint,
    ) -> Result<(), RegularImageCoordinatorError> {
        let observed = self.observe_current()?;
        let resumed = self
            .prepared
            .resume(self.store.bytes(), observed)
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
        let executed =
            match self
                .executor
                .execute_leased_intent(self.prepared.as_ref(), lease, resumed.next)
            {
                Ok(executed) => executed,
                Err(error) => {
                    self.poison();
                    return Err(RegularImageCoordinatorError::Executor(error));
                }
            };
        self.append_execution(checkpoint, executed, None)
    }

    fn append_execution(
        &mut self,
        checkpoint: DurableCheckpoint,
        executed: LeasedIntent,
        staging_verification: Option<StagingVerificationEvidence>,
    ) -> Result<(), RegularImageCoordinatorError> {
        let (executed, generation, phase) = executed.into_parts();
        if generation != checkpoint.generation || phase != checkpoint.phase {
            self.poison();
            return Err(RegularImageCoordinatorError::LeaseStateChanged);
        }
        let mut updated = self.store.bytes().to_vec();
        let observed = match self.observe_current() {
            Ok(observed) => observed,
            Err(error) => {
                self.poison();
                return Err(error);
            }
        };
        if let Err(error) =
            self.prepared
                .record_execution(&mut updated, observed, executed, staging_verification)
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
        // The executor has already restored every conservative before-image. Hash the raw current
        // image as the source, without phase masks, before accepting `RolledBack`.
        let observed = match self.observe_phase(TransactionPhase::Discovered) {
            Ok(observed) => observed,
            Err(error) => {
                self.poison();
                return Err(error);
            }
        };
        if let Err(error) = self
            .prepared
            .record_executed_rollback(&mut updated, observed, executed)
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
        let unobserved = self
            .prepared
            .resume_without_observation(self.store.bytes())
            .map_err(RegularImageCoordinatorError::Conversion)?;
        let observed = self.observe_phase(unobserved.phase)?;
        let resumed = self
            .prepared
            .resume_for_rollback(self.store.bytes(), observed)
            .map_err(RegularImageCoordinatorError::Conversion)?;
        if resumed.generation != unobserved.generation || resumed.phase != unobserved.phase {
            return Err(RegularImageCoordinatorError::LeaseStateChanged);
        }
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

    fn observe_current(&self) -> Result<ObservedImage, RegularImageCoordinatorError> {
        let checkpoint = self
            .prepared
            .resume_without_observation(self.store.bytes())
            .map_err(RegularImageCoordinatorError::Conversion)?;
        self.observe_phase(checkpoint.phase)
    }

    fn observe_phase(
        &self,
        phase: TransactionPhase,
    ) -> Result<ObservedImage, RegularImageCoordinatorError> {
        let source_evidence_digest = if super::phase_requires_source_evidence(phase) {
            let view = self
                .executor
                .locked_view(CANDIDATE_AUDIT_MAX_READ_BYTES)
                .map_err(RegularImageCoordinatorError::Executor)?;
            let rollback = self.prepared.observation_rollback_writes(phase);
            let digest = if let Some(writes) = rollback {
                let masked_bytes = writes
                    .iter()
                    .try_fold(0_usize, |total, write| total.checked_add(write.bytes.len()));
                let masked_bytes =
                    masked_bytes.ok_or(RegularImageCoordinatorError::CandidateRangeOverflow)?;
                let virtual_original = VirtualOriginalReader::new(
                    &view,
                    writes,
                    VirtualOriginalLimits {
                        max_writes: writes.len().max(1),
                        max_masked_bytes: masked_bytes.max(1),
                    },
                )
                .map_err(RegularImageCoordinatorError::SourceView)?;
                digest_source_view(
                    &virtual_original,
                    SourceDigestLimits {
                        max_image_bytes: self.prepared.preflight.image.image_bytes,
                        chunk_bytes: CANDIDATE_AUDIT_MAX_READ_BYTES,
                    },
                )
                .map_err(RegularImageCoordinatorError::SourceView)?
            } else {
                digest_source_view(
                    &view,
                    SourceDigestLimits {
                        max_image_bytes: self.prepared.preflight.image.image_bytes,
                        chunk_bytes: CANDIDATE_AUDIT_MAX_READ_BYTES,
                    },
                )
                .map_err(RegularImageCoordinatorError::SourceView)?
            };
            view.post_operation_revalidate()
                .map_err(RegularImageCoordinatorError::Executor)?;
            Some(digest)
        } else {
            None
        };
        Ok(ObservedImage {
            image: super::ImageIdentity::from_regular_image(self.executor.identity()),
            source_evidence_digest,
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

fn classify_prepared_write_group(
    executor: &ImageExecutor,
    before: &[OverlayWrite],
    after: &[ReservedWrite],
) -> Result<ActivationByteState, RegularImageCoordinatorError> {
    let write_bytes = before
        .iter()
        .try_fold(0_usize, |total, write| total.checked_add(write.bytes.len()))
        .ok_or(RegularImageCoordinatorError::CandidateRangeOverflow)?;
    let view = executor
        .locked_view(CANDIDATE_AUDIT_MAX_READ_BYTES)
        .map_err(RegularImageCoordinatorError::Executor)?;
    let classified = classify_reserved_write_group(
        &view,
        before,
        after,
        ActivationByteLimits {
            write_count: before.len().max(1),
            write_bytes: write_bytes.max(1),
            read_bytes: CANDIDATE_AUDIT_MAX_READ_BYTES,
        },
    )
    .map_err(RegularImageCoordinatorError::ActivationBytes);
    let revalidation = view.post_operation_revalidate();
    drop(view);
    revalidation.map_err(RegularImageCoordinatorError::Executor)?;
    classified
}

impl RegularImageCoordinator<'static> {
    /// Reconstructs the complete prepared plan from the capsule's generation-zero envelope after
    /// acquiring the image lock. Legacy recovery-only capsules fail closed because they cannot
    /// recreate forward execution authority.
    pub fn resume_from_capsule(
        image_path: impl AsRef<Path>,
        expected_image: &ImageIdentity,
        capsule_path: impl AsRef<Path>,
        executor_limits: ExecutorLimits,
        capsule_policy: crate::capsule::CapsuleLimits,
    ) -> Result<(Self, CapsuleRecoveryEvidence), RegularImageCoordinatorError> {
        let executor = ImageExecutor::open(image_path.as_ref(), expected_image, executor_limits)
            .map_err(RegularImageCoordinatorError::Executor)?;
        let (store, recovery) =
            CapsuleStore::resume_recovering(capsule_path, image_path, capsule_policy)
                .map_err(RegularImageCoordinatorError::CapsuleStore)?;
        let prepared = PreparedConversion::from_restart_capsule(store.bytes(), capsule_policy)
            .map_err(RegularImageCoordinatorError::Conversion)?;
        if !prepared.matches_regular_image(executor.identity()) {
            return Err(RegularImageCoordinatorError::PlanImageMismatch);
        }
        let coordinator = Self {
            store,
            executor,
            prepared: Cow::Owned(prepared),
            poisoned: false,
        };
        coordinator.checkpoint()?;
        Ok((coordinator, recovery))
    }
}

fn verify_actual_staging_bytes(
    reader: &dyn BoundedImageReader,
    writes: &[super::ReservedWrite],
) -> Result<(), RegularImageCoordinatorError> {
    let chunk_bytes = reader.max_read_bytes().min(CANDIDATE_AUDIT_MAX_READ_BYTES);
    if chunk_bytes == 0 {
        return Err(RegularImageCoordinatorError::CandidateReadLimitInvalid);
    }
    for reserved in writes {
        for (index, expected) in reserved.write.bytes.chunks(chunk_bytes).enumerate() {
            let relative = index
                .checked_mul(chunk_bytes)
                .and_then(|value| u64::try_from(value).ok())
                .ok_or(RegularImageCoordinatorError::CandidateRangeOverflow)?;
            let offset = reserved
                .write
                .offset
                .checked_add(relative)
                .ok_or(RegularImageCoordinatorError::CandidateRangeOverflow)?;
            let actual = reader
                .read_exact_at(offset, expected.len())
                .map_err(|error| {
                    RegularImageCoordinatorError::Executor(ExecutorError::Image(error))
                })?;
            if actual != expected {
                return Err(RegularImageCoordinatorError::CandidateStagingBytesMismatch { offset });
            }
        }
    }
    Ok(())
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
    SourceView(SourceViewError),
    ActivationBytes(ActivationByteError),
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
    ForwardUnavailable {
        phase: TransactionPhase,
    },
    BackupBootBytesUnsafe {
        state: ActivationByteState,
    },
    ActivationBytesAmbiguous {
        state: ActivationByteState,
    },
    CandidateAuditUnavailable {
        phase: TransactionPhase,
    },
    ActivatedAuditUnavailable {
        phase: TransactionPhase,
    },
    CandidateFilesystemMismatch {
        expected: FileSystem,
        actual: FileSystem,
    },
    CandidateInventoryIncomplete,
    CandidateGraphMismatch,
    CandidateManifestMismatch,
    CandidateStagingBytesMismatch {
        offset: u64,
    },
    CandidateReadLimitInvalid,
    CandidateRangeOverflow,
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
            Self::SourceView(error) => write!(formatter, "source view rejected: {error}"),
            Self::ActivationBytes(error) => {
                write!(formatter, "activation-byte classification failed: {error}")
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
            Self::ForwardUnavailable { phase } => {
                write!(
                    formatter,
                    "forward execution is unavailable from phase {phase:?}"
                )
            }
            Self::BackupBootBytesUnsafe { state } => write!(
                formatter,
                "backup-boot bytes are in unsafe state {state:?}; rollback is required"
            ),
            Self::ActivationBytesAmbiguous { state } => write!(
                formatter,
                "activation bytes are in ambiguous state {state:?}; rollback is required"
            ),
            Self::CandidateAuditUnavailable { phase } => write!(
                formatter,
                "candidate audit requires TargetStaged, found {phase:?}"
            ),
            Self::ActivatedAuditUnavailable { phase } => write!(
                formatter,
                "activated-target audit requires Activated or Verified, found {phase:?}"
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
            Self::CandidateManifestMismatch => {
                formatter.write_str("candidate logical manifest does not match the prepared source")
            }
            Self::CandidateStagingBytesMismatch { offset } => write!(
                formatter,
                "actual staged bytes differ from the prepared write at image offset {offset}"
            ),
            Self::CandidateReadLimitInvalid => {
                formatter.write_str("candidate reader reported a zero byte limit")
            }
            Self::CandidateRangeOverflow => {
                formatter.write_str("candidate staged byte range overflowed")
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
            Self::SourceView(error) => Some(error),
            Self::ActivationBytes(error) => Some(error),
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
    use crate::verify::{ManifestCommitment, build_manifest};

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

    fn fixture() -> (TempDir, PathBuf, PathBuf, PreparedConversion) {
        let dir = TempDir::new();
        let image_path = dir.join("source.img");
        let capsule_path = dir.join("transaction.starcap");
        let mut prepared = super::super::tests::prepared();
        let mut source_bytes =
            vec![0x5a; usize::try_from(prepared.preflight.image.image_bytes).unwrap()];
        for rollback in prepared.rollback_overlay().writes() {
            let start = usize::try_from(rollback.offset).unwrap();
            let end = start.checked_add(rollback.bytes.len()).unwrap();
            source_bytes[start..end].copy_from_slice(&rollback.bytes);
        }
        fs::write(&image_path, source_bytes).unwrap();
        let image = ImageFile::open(&image_path).unwrap();
        let identity = image.identity().clone();
        let source_evidence_digest = digest_source_view(
            &image,
            SourceDigestLimits {
                max_image_bytes: image.len(),
                chunk_bytes: CANDIDATE_AUDIT_MAX_READ_BYTES,
            },
        )
        .unwrap();
        prepared.test_bind_regular_image(&identity, source_evidence_digest);
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
        (dir, image_path, capsule_path, prepared)
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

    fn valid_exfat_fixture() -> (TempDir, PathBuf, PathBuf, PreparedConversion) {
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
        let source_evidence_digest = digest_source_view(
            &image,
            SourceDigestLimits {
                max_image_bytes: IMAGE_BYTES,
                chunk_bytes: CANDIDATE_AUDIT_MAX_READ_BYTES,
            },
        )
        .unwrap();
        let source_manifest =
            build_manifest(&image, &graph, VerificationLimits::default()).unwrap();
        let source_manifest_commitment =
            ManifestCommitment::from_manifest(&source_manifest).unwrap();
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
                source_manifest_commitment,
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
        (dir, image_path, capsule_path, prepared)
    }

    fn apply_reserved_writes(path: &Path, writes: &[super::super::ReservedWrite]) {
        let mut image = fs::read(path).unwrap();
        for reserved in writes {
            let start = usize::try_from(reserved.write.offset).unwrap();
            let end = start.checked_add(reserved.write.bytes.len()).unwrap();
            image[start..end].copy_from_slice(&reserved.write.bytes);
        }
        fs::write(path, image).unwrap();
    }

    #[test]
    fn stages_only_through_target_staged_and_flushes_capsule_after_image() {
        let (_dir, image_path, capsule_path, prepared) = fixture();
        assert!(prepared.layout().relocations.is_empty());
        let image = ImageFile::open(&image_path).unwrap();
        let identity = image.identity().clone();
        drop(image);
        let (mut coordinator, recovery) = RegularImageCoordinator::resume_existing(
            &prepared,
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
        assert_eq!(&image_bytes[1024..1536], &[0x10; 512]);
        let capsule_bytes = fs::read(&capsule_path).unwrap();
        let view = recover_capsule(&capsule_bytes, prepared.capsule_limits).unwrap();
        assert_eq!(view.newest().unwrap().phase, TransactionPhase::TargetStaged);
    }

    #[test]
    fn target_staged_rollback_restores_exact_before_images_and_is_durable() {
        let (_dir, image_path, capsule_path, prepared) = fixture();
        let image = ImageFile::open(&image_path).unwrap();
        let identity = image.identity().clone();
        drop(image);
        let (mut coordinator, _) = RegularImageCoordinator::resume_existing(
            &prepared,
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
        let (_dir, image_path, capsule_path, prepared) = fixture();
        let image = ImageFile::open(&image_path).unwrap();
        let identity = image.identity().clone();
        drop(image);
        let (mut coordinator, _) = RegularImageCoordinator::resume_existing(
            &prepared,
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
        let (_dir, image_path, capsule_path, prepared) = valid_exfat_fixture();
        let image = ImageFile::open(&image_path).unwrap();
        let identity = image.identity().clone();
        drop(image);
        let (mut coordinator, _) = RegularImageCoordinator::resume_existing(
            &prepared,
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
    fn staged_candidate_audit_rejects_corruption_hidden_by_the_overlay() {
        let (_dir, image_path, capsule_path, prepared) = valid_exfat_fixture();
        let image = ImageFile::open(&image_path).unwrap();
        let identity = image.identity().clone();
        drop(image);
        let (mut coordinator, _) = RegularImageCoordinator::resume_existing(
            &prepared,
            &image_path,
            &identity,
            &capsule_path,
            ExecutorLimits::default(),
        )
        .unwrap();
        coordinator.advance_to_target_staged().unwrap();
        drop(coordinator);

        let corrupt_offset = prepared.target_staging_writes()[0].write.offset;
        let mut bytes = fs::read(&image_path).unwrap();
        bytes[usize::try_from(corrupt_offset).unwrap()] ^= 0xff;
        fs::write(&image_path, bytes).unwrap();

        let image = ImageFile::open(&image_path).unwrap();
        let identity = image.identity().clone();
        drop(image);
        let (mut coordinator, _) = RegularImageCoordinator::resume_existing(
            &prepared,
            &image_path,
            &identity,
            &capsule_path,
            ExecutorLimits::default(),
        )
        .unwrap();
        assert!(matches!(
            coordinator.audit_staged_candidate(VerificationLimits::default()),
            Err(
                RegularImageCoordinatorError::CandidateStagingBytesMismatch { offset }
            ) if offset == corrupt_offset
        ));
    }

    #[test]
    fn target_staged_restart_rejects_change_outside_authorized_masks() {
        let (_dir, image_path, capsule_path, prepared) = fixture();
        let image = ImageFile::open(&image_path).unwrap();
        let identity = image.identity().clone();
        drop(image);
        let (mut coordinator, _) = RegularImageCoordinator::resume_existing(
            &prepared,
            &image_path,
            &identity,
            &capsule_path,
            ExecutorLimits::default(),
        )
        .unwrap();
        coordinator.advance_to_target_staged().unwrap();
        drop(coordinator);

        let mut bytes = fs::read(&image_path).unwrap();
        bytes[15_000] ^= 0xff;
        fs::write(&image_path, bytes).unwrap();
        let image = ImageFile::open(&image_path).unwrap();
        let changed_identity = image.identity().clone();
        drop(image);
        assert!(matches!(
            RegularImageCoordinator::resume_existing(
                &prepared,
                &image_path,
                &changed_identity,
                &capsule_path,
                ExecutorLimits::default(),
            ),
            Err(RegularImageCoordinatorError::Conversion(
                ConversionError::StaleSourceEvidence
            ))
        ));
    }

    #[test]
    fn target_staged_restart_reconstructs_plan_from_capsule_envelope() {
        let (_dir, image_path, capsule_path, prepared) = valid_exfat_fixture();
        let capsule_policy = prepared.capsule_limits;
        let image = ImageFile::open(&image_path).unwrap();
        let identity = image.identity().clone();
        drop(image);
        let (mut coordinator, _) = RegularImageCoordinator::resume_existing(
            &prepared,
            &image_path,
            &identity,
            &capsule_path,
            ExecutorLimits::default(),
        )
        .unwrap();
        coordinator.advance_to_target_staged().unwrap();
        drop(coordinator);
        drop(prepared);
        let image = ImageFile::open(&image_path).unwrap();
        let restarted_identity = image.identity().clone();
        drop(image);

        let (mut restarted, recovery) = RegularImageCoordinator::resume_from_capsule(
            &image_path,
            &restarted_identity,
            &capsule_path,
            ExecutorLimits::default(),
            capsule_policy,
        )
        .unwrap();
        assert_eq!(recovery.discarded_torn_bytes, 0);
        assert_eq!(
            restarted.checkpoint().unwrap().phase,
            TransactionPhase::TargetStaged
        );
        restarted
            .audit_staged_candidate(VerificationLimits::default())
            .unwrap();
    }

    #[test]
    fn full_regular_image_transaction_reaudits_and_finalizes_exact_target() {
        let (_dir, image_path, capsule_path, prepared) = valid_exfat_fixture();
        let image = ImageFile::open(&image_path).unwrap();
        let identity = image.identity().clone();
        drop(image);
        let (mut coordinator, _) = RegularImageCoordinator::resume_existing(
            &prepared,
            &image_path,
            &identity,
            &capsule_path,
            ExecutorLimits::default(),
        )
        .unwrap();

        let activated = coordinator
            .advance_to_activated(VerificationLimits::default())
            .unwrap();
        assert_eq!(activated.phase, TransactionPhase::Activated);
        let verified = coordinator
            .verify_activated_target(VerificationLimits::default())
            .unwrap();
        assert_eq!(verified.phase, TransactionPhase::Verified);
        let checkpoint = coordinator
            .finalize_verified_target(
                FinalizationApproval::for_test(),
                VerificationLimits::default(),
            )
            .unwrap();
        assert_eq!(
            checkpoint,
            DurableCheckpoint {
                generation: 7,
                phase: TransactionPhase::Finalized,
            }
        );
        assert!(matches!(
            coordinator.rollback(),
            Err(RegularImageCoordinatorError::RollbackUnavailable {
                phase: TransactionPhase::Finalized
            })
        ));
        drop(coordinator);

        let capsule = fs::read(&capsule_path).unwrap();
        let view = recover_capsule(&capsule, prepared.capsule_limits).unwrap();
        assert_eq!(view.newest().unwrap().phase, TransactionPhase::Finalized);
        let inspection = crate::inspect::inspect_image(&image_path).unwrap();
        assert_eq!(inspection.profile.filesystem, FileSystem::ExFat);
        assert!(inspection.profile.inventory_complete);
    }

    #[test]
    fn restart_after_each_recognition_boundary_reconstructs_and_finishes() {
        let (_dir, image_path, capsule_path, prepared) = valid_exfat_fixture();
        let capsule_policy = prepared.capsule_limits;
        let image = ImageFile::open(&image_path).unwrap();
        let identity = image.identity().clone();
        drop(image);
        let (mut coordinator, _) = RegularImageCoordinator::resume_existing(
            &prepared,
            &image_path,
            &identity,
            &capsule_path,
            ExecutorLimits::default(),
        )
        .unwrap();
        coordinator.advance_to_target_staged().unwrap();
        let staged = coordinator.checkpoint().unwrap();
        coordinator
            .write_backup_boot(staged, VerificationLimits::default())
            .unwrap();
        assert_eq!(
            coordinator.checkpoint().unwrap().phase,
            TransactionPhase::BackupBootWritten
        );
        drop(coordinator);

        let image = ImageFile::open(&image_path).unwrap();
        let identity = image.identity().clone();
        drop(image);
        let (mut coordinator, _) = RegularImageCoordinator::resume_from_capsule(
            &image_path,
            &identity,
            &capsule_path,
            ExecutorLimits::default(),
            capsule_policy,
        )
        .unwrap();
        let backup = coordinator.checkpoint().unwrap();
        coordinator
            .activate_target(backup, VerificationLimits::default())
            .unwrap();
        assert_eq!(
            coordinator.checkpoint().unwrap().phase,
            TransactionPhase::Activated
        );
        drop(coordinator);

        let image = ImageFile::open(&image_path).unwrap();
        let identity = image.identity().clone();
        drop(image);
        let (mut coordinator, _) = RegularImageCoordinator::resume_from_capsule(
            &image_path,
            &identity,
            &capsule_path,
            ExecutorLimits::default(),
            capsule_policy,
        )
        .unwrap();
        coordinator
            .verify_activated_target(VerificationLimits::default())
            .unwrap();
        assert_eq!(
            coordinator.checkpoint().unwrap().phase,
            TransactionPhase::Verified
        );
        drop(coordinator);

        let image = ImageFile::open(&image_path).unwrap();
        let identity = image.identity().clone();
        drop(image);
        let (mut coordinator, _) = RegularImageCoordinator::resume_from_capsule(
            &image_path,
            &identity,
            &capsule_path,
            ExecutorLimits::default(),
            capsule_policy,
        )
        .unwrap();
        let finalized = coordinator
            .finalize_verified_target(
                FinalizationApproval::for_test(),
                VerificationLimits::default(),
            )
            .unwrap();
        assert_eq!(finalized.phase, TransactionPhase::Finalized);
    }

    #[test]
    fn completed_uncheckpointed_backup_bytes_are_reaudited_and_adopted() {
        let (_dir, image_path, capsule_path, prepared) = valid_exfat_fixture();
        let image = ImageFile::open(&image_path).unwrap();
        let identity = image.identity().clone();
        drop(image);
        let (mut coordinator, _) = RegularImageCoordinator::resume_existing(
            &prepared,
            &image_path,
            &identity,
            &capsule_path,
            ExecutorLimits::default(),
        )
        .unwrap();
        coordinator.advance_to_target_staged().unwrap();
        drop(coordinator);

        apply_reserved_writes(&image_path, prepared.backup_boot_writes());
        let image = ImageFile::open(&image_path).unwrap();
        let identity = image.identity().clone();
        drop(image);
        let (mut coordinator, _) = RegularImageCoordinator::resume_existing(
            &prepared,
            &image_path,
            &identity,
            &capsule_path,
            ExecutorLimits::default(),
        )
        .unwrap();
        let activated = coordinator
            .advance_to_activated(VerificationLimits::default())
            .unwrap();
        assert_eq!(activated.phase, TransactionPhase::Activated);
    }

    #[test]
    fn completed_uncheckpointed_activation_is_reaudited_before_adoption() {
        let (_dir, image_path, capsule_path, prepared) = valid_exfat_fixture();
        let image = ImageFile::open(&image_path).unwrap();
        let identity = image.identity().clone();
        drop(image);
        let (mut coordinator, _) = RegularImageCoordinator::resume_existing(
            &prepared,
            &image_path,
            &identity,
            &capsule_path,
            ExecutorLimits::default(),
        )
        .unwrap();
        coordinator.advance_to_target_staged().unwrap();
        let staged = coordinator.checkpoint().unwrap();
        coordinator
            .write_backup_boot(staged, VerificationLimits::default())
            .unwrap();
        drop(coordinator);

        apply_reserved_writes(&image_path, prepared.activation_writes());
        let image = ImageFile::open(&image_path).unwrap();
        let identity = image.identity().clone();
        drop(image);
        let (mut coordinator, _) = RegularImageCoordinator::resume_existing(
            &prepared,
            &image_path,
            &identity,
            &capsule_path,
            ExecutorLimits::default(),
        )
        .unwrap();
        let activated = coordinator
            .advance_to_activated(VerificationLimits::default())
            .unwrap();
        assert_eq!(activated.phase, TransactionPhase::Activated);
    }

    #[test]
    fn third_state_backup_bytes_are_refused_and_source_is_rollbackable() {
        let (_dir, image_path, capsule_path, prepared) = valid_exfat_fixture();
        let image = ImageFile::open(&image_path).unwrap();
        let identity = image.identity().clone();
        drop(image);
        let (mut coordinator, _) = RegularImageCoordinator::resume_existing(
            &prepared,
            &image_path,
            &identity,
            &capsule_path,
            ExecutorLimits::default(),
        )
        .unwrap();
        coordinator.advance_to_target_staged().unwrap();
        drop(coordinator);

        let before = &prepared.backup_boot_before_images()[0];
        let after = &prepared.backup_boot_writes()[0].write;
        let relative = before
            .bytes
            .iter()
            .zip(&after.bytes)
            .position(|(left, right)| left != right)
            .expect("backup boot must change at least one byte");
        let third = (0_u8..=u8::MAX)
            .find(|value| *value != before.bytes[relative] && *value != after.bytes[relative])
            .unwrap();
        let mut image = fs::read(&image_path).unwrap();
        image[usize::try_from(before.offset).unwrap() + relative] = third;
        fs::write(&image_path, image).unwrap();

        let image = ImageFile::open(&image_path).unwrap();
        let identity = image.identity().clone();
        drop(image);
        let (mut coordinator, _) = RegularImageCoordinator::resume_existing(
            &prepared,
            &image_path,
            &identity,
            &capsule_path,
            ExecutorLimits::default(),
        )
        .unwrap();
        assert!(matches!(
            coordinator.advance_to_activated(VerificationLimits::default()),
            Err(RegularImageCoordinatorError::BackupBootBytesUnsafe {
                state: ActivationByteState::ThirdState
            })
        ));
        assert_eq!(
            coordinator.rollback().unwrap().phase,
            TransactionPhase::RolledBack
        );
    }

    #[test]
    fn mixed_activation_bytes_are_rollback_only_and_restore_exact_source() {
        let (_dir, image_path, capsule_path, prepared) = valid_exfat_fixture();
        let image = ImageFile::open(&image_path).unwrap();
        let identity = image.identity().clone();
        drop(image);
        let (mut coordinator, _) = RegularImageCoordinator::resume_existing(
            &prepared,
            &image_path,
            &identity,
            &capsule_path,
            ExecutorLimits::default(),
        )
        .unwrap();
        coordinator.advance_to_target_staged().unwrap();
        let staged = coordinator.checkpoint().unwrap();
        coordinator
            .write_backup_boot(staged, VerificationLimits::default())
            .unwrap();
        drop(coordinator);

        let mut image = fs::read(&image_path).unwrap();
        let mixed = prepared
            .activation_before_images()
            .iter()
            .zip(prepared.activation_writes())
            .find_map(|(before, after)| {
                before
                    .bytes
                    .iter()
                    .zip(&after.write.bytes)
                    .position(|(left, right)| left != right)
                    .map(|relative| (before.offset, relative, after.write.bytes[relative]))
            })
            .expect("activation must change at least one byte");
        image[usize::try_from(mixed.0).unwrap() + mixed.1] = mixed.2;
        fs::write(&image_path, image).unwrap();

        let image = ImageFile::open(&image_path).unwrap();
        let identity = image.identity().clone();
        drop(image);
        let (mut coordinator, _) = RegularImageCoordinator::resume_existing(
            &prepared,
            &image_path,
            &identity,
            &capsule_path,
            ExecutorLimits::default(),
        )
        .unwrap();
        assert!(matches!(
            coordinator.advance_to_activated(VerificationLimits::default()),
            Err(RegularImageCoordinatorError::ActivationBytesAmbiguous {
                state: ActivationByteState::MixedBeforeAfter
            })
        ));
        let rolled_back = coordinator.rollback().unwrap();
        assert_eq!(rolled_back.phase, TransactionPhase::RolledBack);
    }

    #[test]
    fn activated_corruption_is_rejected_before_verified_and_can_rollback() {
        let (_dir, image_path, capsule_path, prepared) = valid_exfat_fixture();
        let image = ImageFile::open(&image_path).unwrap();
        let identity = image.identity().clone();
        drop(image);
        let (mut coordinator, _) = RegularImageCoordinator::resume_existing(
            &prepared,
            &image_path,
            &identity,
            &capsule_path,
            ExecutorLimits::default(),
        )
        .unwrap();
        coordinator.advance_to_target_staged().unwrap();
        let staged = coordinator.checkpoint().unwrap();
        coordinator
            .write_backup_boot(staged, VerificationLimits::default())
            .unwrap();
        let backup = coordinator.checkpoint().unwrap();
        coordinator
            .activate_target(backup, VerificationLimits::default())
            .unwrap();
        drop(coordinator);

        let corrupt_offset = prepared.target_staging_writes()[0].write.offset;
        let mut image = fs::read(&image_path).unwrap();
        image[usize::try_from(corrupt_offset).unwrap()] ^= 0xff;
        fs::write(&image_path, image).unwrap();

        let image = ImageFile::open(&image_path).unwrap();
        let identity = image.identity().clone();
        drop(image);
        let (mut coordinator, _) = RegularImageCoordinator::resume_existing(
            &prepared,
            &image_path,
            &identity,
            &capsule_path,
            ExecutorLimits::default(),
        )
        .unwrap();
        assert!(matches!(
            coordinator.verify_activated_target(VerificationLimits::default()),
            Err(RegularImageCoordinatorError::CandidateStagingBytesMismatch { offset })
                if offset == corrupt_offset
        ));
        assert_eq!(
            coordinator.rollback().unwrap().phase,
            TransactionPhase::RolledBack
        );
    }

    #[test]
    fn verified_target_can_rollback_and_rolled_back_retry_is_idempotent() {
        let (_dir, image_path, capsule_path, prepared) = valid_exfat_fixture();
        let image = ImageFile::open(&image_path).unwrap();
        let identity = image.identity().clone();
        drop(image);
        let (mut coordinator, _) = RegularImageCoordinator::resume_existing(
            &prepared,
            &image_path,
            &identity,
            &capsule_path,
            ExecutorLimits::default(),
        )
        .unwrap();

        assert_eq!(
            coordinator
                .advance_to_activated(VerificationLimits::default())
                .unwrap()
                .phase,
            TransactionPhase::Activated
        );
        assert_eq!(
            coordinator
                .verify_activated_target(VerificationLimits::default())
                .unwrap()
                .phase,
            TransactionPhase::Verified
        );
        let first = coordinator.rollback().unwrap();
        let capsule_after_first = coordinator.store.bytes().to_vec();
        let second = coordinator.rollback().unwrap();

        assert_eq!(first.phase, TransactionPhase::RolledBack);
        assert_eq!(second, first);
        assert_eq!(coordinator.store.bytes(), capsule_after_first);
    }

    #[test]
    fn nonempty_relocation_is_refused_before_image_or_capsule_changes() {
        let (_dir, image_path, capsule_path, mut prepared) = fixture();
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
