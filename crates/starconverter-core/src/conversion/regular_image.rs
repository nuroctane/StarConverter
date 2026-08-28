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
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::FileSystem;
use crate::capsule::TransactionPhase;
use crate::capsule_store::{
    CapsuleRecoveryEvidence, CapsuleStore, CapsuleStoreError, CapsuleSyncEvidence,
    NamespaceDurability,
};
use crate::executor::{
    ExecutionLease, ExecutorError, ExecutorLimits, ImageExecutor, LeasedIntent, LeasedRollback,
    LockStrength,
};
use crate::image::{BoundedImageReader, ImageFile, ImageIdentity};
use crate::inspect::{
    ImageInspection, InspectionError, NtfsAllocationReconciliationStatus,
    NtfsMftRecordReconciliationStatus, inspect_overlay,
};
use crate::object::ObjectGraph;
use crate::overlay::{OverlayError, OverlayLimits, OverlayPlan, OverlayWrite};
use crate::preimage::{PreimageError, PreimageLimits, capture_before_images_with_reader};
use crate::source_view::{
    SourceDigestLimits, SourceViewError, VirtualOriginalLimits, VirtualOriginalReader,
    digest_source_view,
};
use crate::verify::{
    ManifestCommitment, VerificationError, VerificationLimits, VerificationManifest,
    build_manifest_with_reader,
};
use crate::{AccessState, HealthState};

use super::activation_bytes::{
    ActivationByteError, ActivationByteLimits, ActivationByteState, classify_reserved_write_group,
};
use super::{
    ConversionError, ObservedImage, PreflightEvidence, PreparedConversion, ReservedWrite,
    StagingVerificationEvidence, TransactionIntent, VerificationEvidence,
};

const CANDIDATE_AUDIT_MAX_READ_BYTES: usize = 16 * 1024 * 1024;
static NEXT_TRANSACTION_NONCE: AtomicU64 = AtomicU64::new(0);

/// Non-cloneable proof that the preparation session owns production-strength exclusion for one
/// exact regular-file container.
///
/// Windows deny-share access is currently the only supported production authority. Advisory Unix
/// locks exclude cooperating processes but cannot prove that an unrelated writer is absent, so
/// they fail closed instead of being relabeled as `Offline` evidence.
#[derive(Debug)]
struct OfflineRegularImageAuthority {
    image_instance: [u8; 32],
    _one_use: OfflineAuthoritySeal,
}

#[derive(Debug)]
struct OfflineAuthoritySeal;

impl OfflineRegularImageAuthority {
    #[allow(
        clippy::missing_const_for_fn, // Non-Windows cfg erases the identity read required on Windows.
        clippy::unnecessary_wraps // The advisory-lock host branch returns an error.
    )]
    fn mint(executor: &ImageExecutor) -> Result<Self, RegularImageCoordinatorError> {
        match executor.lock_strength() {
            #[cfg(windows)]
            LockStrength::MandatoryDenyShareAndFileLock => Ok(Self {
                image_instance: executor.identity().stable_container_token(),
                _one_use: OfflineAuthoritySeal,
            }),
            #[cfg(not(windows))]
            LockStrength::AdvisoryFileLock => {
                Err(RegularImageCoordinatorError::OfflineAuthorityUnavailable {
                    lock_strength: executor.lock_strength(),
                })
            }
        }
    }

    fn consume(self, executor: &ImageExecutor) -> Result<(), RegularImageCoordinatorError> {
        if self.image_instance != executor.identity().stable_container_token() {
            return Err(RegularImageCoordinatorError::OfflineAuthorityChanged);
        }
        Ok(())
    }
}

/// Trusted facts and bounded read helpers exposed only while the exclusive image lock is held.
///
/// The value borrows the session's locked handle, so neither the inspection nor exact preimage
/// capture can be retained as an independently reusable mutation authority.
#[derive(Debug)]
pub struct LockedRegularImagePlanningEvidence<'view> {
    inspection: &'view ImageInspection,
    graph: &'view ObjectGraph,
    preflight: PreflightEvidence,
    transaction_id: [u8; 16],
    reader: &'view dyn BoundedImageReader,
}

impl LockedRegularImagePlanningEvidence<'_> {
    pub(crate) const fn inspection(&self) -> &ImageInspection {
        self.inspection
    }

    pub(crate) const fn graph(&self) -> &ObjectGraph {
        self.graph
    }

    pub(crate) const fn preflight(&self) -> PreflightEvidence {
        self.preflight
    }

    pub(crate) const fn transaction_id(&self) -> [u8; 16] {
        self.transaction_id
    }

    /// Captures exact source bytes through the same locked view used for inspection and hashing.
    pub(crate) fn capture_before_images(
        &self,
        replacements: &[OverlayWrite],
        limits: PreimageLimits,
    ) -> Result<Vec<OverlayWrite>, PreimageError> {
        capture_before_images_with_reader(self.reader, replacements, limits)
    }
}

/// One-use production preparation session for a caller-named regular image.
///
/// Opening pins the container and acquires production-strength exclusion. `prepare_with` consumes
/// the session, runs inspection, whole-source hashing, logical manifest construction, planning,
/// and before-image validation without releasing that lock, then returns a session which still
/// owns the same executor.
#[derive(Debug)]
pub struct RegularImagePreparationSession {
    executor: ImageExecutor,
    authority: OfflineRegularImageAuthority,
}

impl RegularImagePreparationSession {
    pub(crate) fn open(
        image_path: impl AsRef<Path>,
        executor_limits: ExecutorLimits,
    ) -> Result<Self, RegularImageCoordinatorError> {
        // `ImageExecutor::open` requires a pinned read identity. The read-only handle is closed
        // before the Windows deny-share writer is opened; any namespace replacement between the
        // two opens is rejected by the executor's exact identity comparison.
        let image = ImageFile::open(image_path.as_ref())
            .map_err(|error| RegularImageCoordinatorError::Executor(ExecutorError::Image(error)))?;
        let identity = image.identity().clone();
        drop(image);
        let executor = ImageExecutor::open(image_path.as_ref(), &identity, executor_limits)
            .map_err(RegularImageCoordinatorError::Executor)?;
        let authority = OfflineRegularImageAuthority::mint(&executor)?;
        Ok(Self {
            executor,
            authority,
        })
    }

    pub(crate) fn prepare_with<F>(
        self,
        verification_limits: VerificationLimits,
        planner: F,
    ) -> Result<PreparedRegularImageSession, RegularImageCoordinatorError>
    where
        F: FnOnce(
            &LockedRegularImagePlanningEvidence<'_>,
        ) -> Result<PreparedConversion, ConversionError>,
    {
        let view = self
            .executor
            .locked_view(CANDIDATE_AUDIT_MAX_READ_BYTES)
            .map_err(RegularImageCoordinatorError::Executor)?;
        let empty_overlay =
            OverlayPlan::build(view.len(), 512, Vec::new(), OverlayLimits::default())
                .map_err(RegularImageCoordinatorError::Overlay)?;
        let inspection = inspect_overlay(
            &view,
            self.executor.identity(),
            &empty_overlay,
            super::digest_overlay_writes(empty_overlay.writes()),
        )
        .map_err(RegularImageCoordinatorError::Inspection)?;
        let graph = inspection_graph(&inspection)?;
        let source_evidence_digest = digest_source_view(
            &view,
            SourceDigestLimits {
                max_image_bytes: view.len(),
                chunk_bytes: CANDIDATE_AUDIT_MAX_READ_BYTES,
            },
        )
        .map_err(RegularImageCoordinatorError::SourceView)?;
        let manifest = build_manifest_with_reader(&view, graph, verification_limits)
            .map_err(RegularImageCoordinatorError::Verification)?;
        let source_manifest_commitment = ManifestCommitment::from_manifest(&manifest)
            .map_err(RegularImageCoordinatorError::Verification)?;
        let preflight = trusted_preflight(
            self.executor.identity(),
            &inspection,
            source_evidence_digest,
            source_manifest_commitment,
        )?;
        let transaction_id = mint_transaction_id(self.executor.identity(), source_evidence_digest);
        let evidence = LockedRegularImagePlanningEvidence {
            inspection: &inspection,
            graph,
            preflight,
            transaction_id,
            reader: &view,
        };
        let prepared = planner(&evidence).map_err(RegularImageCoordinatorError::Conversion)?;
        validate_locked_preparation(&view, graph, preflight, transaction_id, &prepared)?;
        view.post_operation_revalidate()
            .map_err(RegularImageCoordinatorError::Executor)?;
        drop(view);
        Ok(PreparedRegularImageSession {
            executor: self.executor,
            authority: self.authority,
            prepared,
        })
    }
}

/// A plan sealed to the still-held preparation lock and one-use offline authority.
#[derive(Debug)]
pub struct PreparedRegularImageSession {
    executor: ImageExecutor,
    authority: OfflineRegularImageAuthority,
    prepared: PreparedConversion,
}

impl PreparedRegularImageSession {
    /// Creates the initial capsule while the image remains locked, requires full file and parent
    /// namespace durability, then consumes the one-use authority into the coordinator.
    pub(crate) fn create_coordinator(
        self,
        capsule_path: impl AsRef<Path>,
    ) -> Result<(RegularImageCoordinator<'static>, CapsuleSyncEvidence), RegularImageCoordinatorError>
    {
        let observed = observe_locked_source(&self.executor, &self.prepared)?;
        let mut capsule = Vec::new();
        self.prepared
            .begin_capsule(&mut capsule, observed)
            .map_err(RegularImageCoordinatorError::Conversion)?;
        let (store, sync) = CapsuleStore::create_new(
            capsule_path,
            self.executor.identity().canonical_path(),
            &capsule,
            self.prepared.capsule_limits,
        )
        .map_err(RegularImageCoordinatorError::CapsuleStore)?;
        if !sync.sync_data_completed
            || !sync.sync_all_completed
            || sync.namespace_durability != NamespaceDurability::ParentDirectorySynchronized
        {
            return Err(
                RegularImageCoordinatorError::InitialCapsuleDurabilityMissing { evidence: sync },
            );
        }
        self.authority.consume(&self.executor)?;
        let coordinator = RegularImageCoordinator {
            store,
            executor: self.executor,
            prepared: Cow::Owned(self.prepared),
            poisoned: false,
        };
        coordinator.checkpoint()?;
        Ok((coordinator, sync))
    }
}

fn inspection_graph(
    inspection: &ImageInspection,
) -> Result<&ObjectGraph, RegularImageCoordinatorError> {
    match inspection.profile.filesystem {
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
    .ok_or(RegularImageCoordinatorError::SourceInventoryIncomplete)
}

fn trusted_preflight(
    identity: &ImageIdentity,
    inspection: &ImageInspection,
    source_evidence_digest: [u8; 32],
    source_manifest_commitment: ManifestCommitment,
) -> Result<PreflightEvidence, RegularImageCoordinatorError> {
    if inspection.profile.state.health != HealthState::Clean {
        return Err(RegularImageCoordinatorError::SourceHealthNotClean {
            actual: inspection.profile.state.health,
        });
    }
    let allocation_map_complete = match inspection.profile.filesystem {
        FileSystem::ExFat => inspection.normalized_exfat.is_some(),
        FileSystem::Ntfs => {
            matches!(
                inspection.ntfs_allocation_reconciliation,
                Some(NtfsAllocationReconciliationStatus::Complete(_))
            ) && matches!(
                inspection.ntfs_mft_record_reconciliation,
                Some(NtfsMftRecordReconciliationStatus::Complete(_))
            )
        }
        FileSystem::Unknown => false,
    };
    if !inspection.profile.inventory_complete || !allocation_map_complete {
        return Err(RegularImageCoordinatorError::SourceInventoryIncomplete);
    }
    if inspection.profile.logical_sector_bytes == 0
        || inspection.profile.cluster_bytes == 0
        || inspection.profile.cluster_bytes < inspection.profile.logical_sector_bytes
    {
        return Err(RegularImageCoordinatorError::InvalidSourceGeometry);
    }
    Ok(PreflightEvidence {
        image: super::ImageIdentity::from_regular_image(identity),
        source_filesystem: inspection.profile.filesystem,
        source_evidence_digest,
        source_manifest_commitment,
        sector_bytes: inspection.profile.logical_sector_bytes,
        allocation_alignment: u64::from(inspection.profile.cluster_bytes),
        inventory_complete: true,
        allocation_map_complete: true,
        health: inspection.profile.state.health,
        access: AccessState::Offline,
    })
}

fn validate_locked_preparation(
    reader: &dyn BoundedImageReader,
    graph: &ObjectGraph,
    preflight: PreflightEvidence,
    transaction_id: [u8; 16],
    prepared: &PreparedConversion,
) -> Result<(), RegularImageCoordinatorError> {
    if prepared.identity().transaction_id != transaction_id {
        return Err(RegularImageCoordinatorError::PreparedTransactionMismatch);
    }
    if prepared.preflight != preflight {
        return Err(RegularImageCoordinatorError::PreparedPreflightMismatch);
    }
    if prepared.graph_digest() != super::digest_graph(graph) {
        return Err(RegularImageCoordinatorError::PreparedGraphMismatch);
    }
    verify_locked_before_images(reader, prepared.staging_rollback_overlay().writes())?;
    verify_locked_before_images(reader, prepared.backup_boot_before_images())?;
    verify_locked_before_images(reader, prepared.activation_before_images())?;
    Ok(())
}

fn mint_transaction_id(identity: &ImageIdentity, source_digest: [u8; 32]) -> [u8; 16] {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let nonce = NEXT_TRANSACTION_NONCE.fetch_add(1, Ordering::Relaxed);
    let mut hasher = Sha256::new();
    hasher.update(b"starconverter/regular-image-transaction-id/v1\0");
    hasher.update(identity.stable_container_token());
    hasher.update(source_digest);
    hasher.update(std::process::id().to_le_bytes());
    hasher.update(elapsed.as_secs().to_le_bytes());
    hasher.update(elapsed.subsec_nanos().to_le_bytes());
    hasher.update(nonce.to_le_bytes());
    let digest = hasher.finalize();
    let mut transaction_id = [0_u8; 16];
    transaction_id.copy_from_slice(&digest[..16]);
    transaction_id
}

fn verify_locked_before_images(
    reader: &dyn BoundedImageReader,
    before_images: &[OverlayWrite],
) -> Result<(), RegularImageCoordinatorError> {
    for before in before_images {
        let mut relative = 0_usize;
        while relative < before.bytes.len() {
            let count = (before.bytes.len() - relative).min(reader.max_read_bytes());
            if count == 0 {
                return Err(RegularImageCoordinatorError::CandidateReadLimitInvalid);
            }
            let offset = before
                .offset
                .checked_add(
                    u64::try_from(relative)
                        .map_err(|_| RegularImageCoordinatorError::CandidateRangeOverflow)?,
                )
                .ok_or(RegularImageCoordinatorError::CandidateRangeOverflow)?;
            let actual = reader.read_exact_at(offset, count).map_err(|error| {
                RegularImageCoordinatorError::Executor(ExecutorError::Image(error))
            })?;
            if actual != before.bytes[relative..relative + count] {
                return Err(RegularImageCoordinatorError::PreparedBeforeImageMismatch { offset });
            }
            relative += count;
        }
    }
    Ok(())
}

fn verify_relocation_copies(
    executor: &ImageExecutor,
    prepared: &PreparedConversion,
) -> Result<(), RegularImageCoordinatorError> {
    if prepared.layout().relocations.is_empty() {
        return Ok(());
    }
    let view = executor
        .locked_view(CANDIDATE_AUDIT_MAX_READ_BYTES)
        .map_err(RegularImageCoordinatorError::Executor)?;
    for relocation in &prepared.layout().relocations {
        let mut relative = 0_u64;
        while relative < relocation.source.length {
            let remaining = relocation
                .source
                .length
                .checked_sub(relative)
                .ok_or(RegularImageCoordinatorError::RelocationRangeOverflow)?;
            let count = usize::try_from(
                remaining.min(
                    u64::try_from(view.max_read_bytes())
                        .map_err(|_| RegularImageCoordinatorError::RelocationRangeOverflow)?,
                ),
            )
            .map_err(|_| RegularImageCoordinatorError::RelocationRangeOverflow)?;
            if count == 0 {
                return Err(RegularImageCoordinatorError::CandidateReadLimitInvalid);
            }
            let source_offset = relocation
                .source
                .offset
                .checked_add(relative)
                .ok_or(RegularImageCoordinatorError::RelocationRangeOverflow)?;
            let destination_offset = relocation
                .destination
                .offset
                .checked_add(relative)
                .ok_or(RegularImageCoordinatorError::RelocationRangeOverflow)?;
            let source = view.read_exact_at(source_offset, count).map_err(|error| {
                RegularImageCoordinatorError::Executor(ExecutorError::Image(error))
            })?;
            let destination = view
                .read_exact_at(destination_offset, count)
                .map_err(|error| {
                    RegularImageCoordinatorError::Executor(ExecutorError::Image(error))
                })?;
            if source != destination {
                return Err(RegularImageCoordinatorError::RelocationCopyMismatch {
                    source_offset,
                    destination_offset,
                });
            }
            relative = relative
                .checked_add(
                    u64::try_from(count)
                        .map_err(|_| RegularImageCoordinatorError::RelocationRangeOverflow)?,
                )
                .ok_or(RegularImageCoordinatorError::RelocationRangeOverflow)?;
        }
    }
    view.post_operation_revalidate()
        .map_err(RegularImageCoordinatorError::Executor)
}

fn observe_locked_source(
    executor: &ImageExecutor,
    prepared: &PreparedConversion,
) -> Result<ObservedImage, RegularImageCoordinatorError> {
    let view = executor
        .locked_view(CANDIDATE_AUDIT_MAX_READ_BYTES)
        .map_err(RegularImageCoordinatorError::Executor)?;
    let source_evidence_digest = digest_source_view(
        &view,
        SourceDigestLimits {
            max_image_bytes: prepared.preflight.image.image_bytes,
            chunk_bytes: CANDIDATE_AUDIT_MAX_READ_BYTES,
        },
    )
    .map_err(RegularImageCoordinatorError::SourceView)?;
    view.post_operation_revalidate()
        .map_err(RegularImageCoordinatorError::Executor)?;
    Ok(ObservedImage {
        image: super::ImageIdentity::from_regular_image(executor.identity()),
        source_evidence_digest: Some(source_evidence_digest),
    })
}

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

// Naming the lifetime keeps the test-only borrowed-plan constructor and every instance method in
// one impl while making the returned coordinator's borrow explicit.
#[allow(
    unknown_lints,
    clippy::elidable_lifetime_names,
    clippy::needless_lifetimes
)]
impl<'plan> RegularImageCoordinator<'plan> {
    /// Opens the image executor before opening/recovering the capsule store, then binds both to the
    /// exact sealed plan and current capsule generation.
    ///
    /// The sealed observation is constructed internally from the locked image; callers cannot
    /// supply or replay source evidence.
    #[cfg(test)]
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

    /// Advances a prepared plan through its durable `TargetStaged` checkpoint.
    ///
    /// Every image mutation completes read-back verification plus both flush barriers before the
    /// corresponding capsule generation is built and appended. Before target staging, every
    /// relocated destination is independently compared with its still-intact source through the
    /// locked handle, including after a restarted transaction.
    pub fn advance_to_target_staged(
        &mut self,
    ) -> Result<DurableCheckpoint, RegularImageCoordinatorError> {
        self.ensure_forward_ready()?;

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

    /// Advances a fully prepared regular image through activation only.
    ///
    /// Every durable boundary is independently re-audited from the locked handle. Backup boot and
    /// activation writes consume one-use leases. This helper deliberately stops at `Activated`,
    /// while rollback is still available.
    pub(crate) fn advance_to_activated(
        &mut self,
        verification_limits: VerificationLimits,
    ) -> Result<DurableCheckpoint, RegularImageCoordinatorError> {
        self.ensure_forward_ready()?;

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
        if checkpoint.phase == TransactionPhase::Relocating {
            if let Err(error) = verify_relocation_copies(&self.executor, self.prepared.as_ref()) {
                self.poison();
                return Err(error);
            }
        }
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
        // Normal recovery still needs fresh production-strength offline authority. Unit tests use
        // regular temporary images on Unix and exercise coordinator logic under advisory locks;
        // non-test builds never accept that weaker exclusion.
        #[cfg(not(test))]
        let authority = OfflineRegularImageAuthority::mint(&executor)?;
        let (store, recovery) =
            CapsuleStore::resume_recovering(capsule_path, image_path, capsule_policy)
                .map_err(RegularImageCoordinatorError::CapsuleStore)?;
        let prepared = PreparedConversion::from_restart_capsule(store.bytes(), capsule_policy)
            .map_err(RegularImageCoordinatorError::Conversion)?;
        if !prepared.matches_regular_image(executor.identity()) {
            return Err(RegularImageCoordinatorError::PlanImageMismatch);
        }
        #[cfg(not(test))]
        authority.consume(&executor)?;
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
    OfflineAuthorityUnavailable {
        lock_strength: LockStrength,
    },
    OfflineAuthorityChanged,
    SourceInventoryIncomplete,
    SourceHealthNotClean {
        actual: HealthState,
    },
    InvalidSourceGeometry,
    PreparedTransactionMismatch,
    PreparedPreflightMismatch,
    PreparedGraphMismatch,
    PreparedBeforeImageMismatch {
        offset: u64,
    },
    InitialCapsuleDurabilityMissing {
        evidence: CapsuleSyncEvidence,
    },
    PlanImageMismatch,
    RelocationCopyMismatch {
        source_offset: u64,
        destination_offset: u64,
    },
    RelocationRangeOverflow,
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
    #[allow(clippy::too_many_lines)]
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
            Self::OfflineAuthorityUnavailable { lock_strength } => write!(
                formatter,
                "regular-image lock strength {lock_strength:?} cannot prove production offline access"
            ),
            Self::OfflineAuthorityChanged => formatter.write_str(
                "one-use offline regular-image authority no longer matches the locked container",
            ),
            Self::SourceInventoryIncomplete => formatter.write_str(
                "locked source inspection did not prove a complete object and allocation inventory",
            ),
            Self::SourceHealthNotClean { actual } => write!(
                formatter,
                "locked source filesystem health is {actual:?}, not clean",
            ),
            Self::InvalidSourceGeometry => formatter.write_str(
                "locked source inspection reported invalid sector or allocation geometry",
            ),
            Self::PreparedTransactionMismatch => formatter.write_str(
                "prepared conversion did not use the transaction identity minted by the locked session",
            ),
            Self::PreparedPreflightMismatch => formatter.write_str(
                "prepared conversion is not bound to the locked inspection, digest, and manifest evidence",
            ),
            Self::PreparedGraphMismatch => formatter.write_str(
                "prepared conversion graph differs from the graph parsed through the locked image view",
            ),
            Self::PreparedBeforeImageMismatch { offset } => write!(
                formatter,
                "prepared rollback bytes differ from the locked source at image offset {offset}",
            ),
            Self::InitialCapsuleDurabilityMissing { evidence } => write!(
                formatter,
                "initial capsule lacks full file and parent-namespace durability: {evidence:?}",
            ),
            Self::PlanImageMismatch => {
                formatter.write_str("prepared conversion does not match the locked image")
            }
            Self::RelocationCopyMismatch {
                source_offset,
                destination_offset,
            } => write!(
                formatter,
                "relocated bytes at image offset {destination_offset} differ from source offset {source_offset}",
            ),
            Self::RelocationRangeOverflow => {
                formatter.write_str("relocation verification range overflowed")
            }
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
    use crate::extent::{Extent, ExtentGraph, ExtentKind, Placement, StreamId};
    use crate::fs::exfat_inventory::ExfatPreservationEvidence;
    use crate::fs::exfat_serialize::{
        ExfatSerializeLimits, ExfatSerializeOptions, ExfatVolumeProfile,
        non_interoperable_ascii_test_upcase_table, serialize_exfat_destination,
    };
    use crate::fs::exfat_upcase::table_checksum;
    use crate::geometry::{
        ByteRange, DestinationReservation, ReservationKind, SourceAllocation,
        relocate_object_graph, solve_layout_with_staging_exclusions,
    };
    use crate::image::{BoundedImageReader, ImageFile};
    use crate::object::{
        NamespaceEntry, ObjectGraph, ObjectGraphLimits, ObjectId, ObjectKind, ObjectRecord,
        ObjectSemantics, ObjectStream, StreamFlags, StreamStorage,
    };
    use crate::phase::{ActivationAuthorizedWrites, preview_exfat_phase_writes};
    use crate::preimage::PreimageLimits;
    use crate::verify::{ManifestCommitment, build_manifest};

    use super::super::{
        ConversionDraft, ConversionLimits, ImageIdentity as ConversionImageIdentity,
        OpaqueWriteSets, PreflightEvidence, TargetCapabilities,
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

    #[allow(clippy::too_many_lines)]
    fn relocation_fixture() -> (TempDir, PathBuf, PathBuf, PreparedConversion, Vec<u8>) {
        const IMAGE_BYTES: u64 = 16 * 1024;
        const SOURCE_OFFSET: u64 = 4096;
        const EXTENT_BYTES: usize = 512;

        let dir = TempDir::new();
        let image_path = dir.join("relocation-source.img");
        let capsule_path = dir.join("relocation.starcap");
        let mut source_bytes = vec![0x5a; usize::try_from(IMAGE_BYTES).unwrap()];
        let payload: Vec<u8> = (0..EXTENT_BYTES)
            .map(|index| u8::try_from(index % 251).unwrap())
            .collect();
        source_bytes[usize::try_from(SOURCE_OFFSET).unwrap()
            ..usize::try_from(SOURCE_OFFSET).unwrap() + EXTENT_BYTES]
            .copy_from_slice(&payload);
        for (offset, byte) in [(1024, 0x10), (1536, 0x11), (2048, 0x12), (2560, 0x13)] {
            source_bytes[offset..offset + EXTENT_BYTES].fill(byte);
        }

        let graph = ObjectGraph::build(
            ObjectId(0),
            vec![
                ObjectRecord {
                    id: ObjectId(0),
                    kind: ObjectKind::Directory,
                    link_count: 0,
                    semantics: ObjectSemantics::default(),
                    streams: Vec::new(),
                },
                ObjectRecord {
                    id: ObjectId(1),
                    kind: ObjectKind::File,
                    link_count: 1,
                    semantics: ObjectSemantics::default(),
                    streams: vec![ObjectStream {
                        id: StreamId(1),
                        name: None,
                        logical_bytes: EXTENT_BYTES as u64,
                        initialized_bytes: EXTENT_BYTES as u64,
                        mapped_bytes: EXTENT_BYTES as u64,
                        allocated_bytes: EXTENT_BYTES as u64,
                        flags: StreamFlags::default(),
                        storage: StreamStorage::Extents,
                    }],
                },
            ],
            vec![NamespaceEntry {
                parent: ObjectId(0),
                target: ObjectId(1),
                name: "payload.bin".encode_utf16().collect(),
            }],
            ExtentGraph::build(
                vec![Extent {
                    stream: StreamId(1),
                    logical_offset: 0,
                    length: EXTENT_BYTES as u64,
                    placement: Placement::Physical {
                        byte_offset: SOURCE_OFFSET,
                    },
                    kind: ExtentKind::FileData,
                }],
                IMAGE_BYTES,
                1,
            )
            .unwrap(),
            ObjectGraphLimits {
                max_objects: 2,
                max_entries: 1,
                max_streams: 1,
                max_name_code_units: 11,
            },
        )
        .unwrap();
        let boot = DestinationReservation {
            range: ByteRange {
                offset: 1024,
                length: 1024,
            },
            kind: ReservationKind::BootRegion,
        };
        let allocation = DestinationReservation {
            range: ByteRange {
                offset: 2048,
                length: 512,
            },
            kind: ReservationKind::AllocationMetadata,
        };
        let namespace = DestinationReservation {
            range: ByteRange {
                offset: 2560,
                length: 512,
            },
            kind: ReservationKind::NamespaceMetadata,
        };
        let capsule = DestinationReservation {
            range: ByteRange {
                offset: 3584,
                length: 1024,
            },
            kind: ReservationKind::Capsule,
        };
        let reservations = vec![boot, allocation, namespace, capsule];
        let movable = SourceAllocation {
            stream: StreamId(1),
            logical_offset: 0,
            range: ByteRange {
                offset: SOURCE_OFFSET,
                length: EXTENT_BYTES as u64,
            },
            movable: true,
        };
        let retired_metadata = SourceAllocation {
            stream: StreamId(99),
            logical_offset: 0,
            range: ByteRange {
                offset: 0,
                length: EXTENT_BYTES as u64,
            },
            movable: false,
        };
        let limits = ConversionLimits::default();
        let layout = solve_layout_with_staging_exclusions(
            IMAGE_BYTES,
            512,
            vec![movable],
            reservations.clone(),
            vec![retired_metadata.range],
            limits.layout,
        )
        .unwrap();
        assert_eq!(layout.relocations.len(), 1);
        let target_graph = relocate_object_graph(&graph, &layout).unwrap();
        let destination = layout.relocations[0].destination;
        let destination_start = usize::try_from(destination.offset).unwrap();
        let destination_end = destination_start + usize::try_from(destination.length).unwrap();
        let relocation_before_images = vec![OverlayWrite {
            offset: destination.offset,
            bytes: source_bytes[destination_start..destination_end].to_vec(),
        }];
        let rollback = |offset: usize| OverlayWrite {
            offset: u64::try_from(offset).unwrap(),
            bytes: source_bytes[offset..offset + EXTENT_BYTES].to_vec(),
        };
        let writes = OpaqueWriteSets {
            target_staging: vec![
                ReservedWrite {
                    reservation_kind: allocation.kind,
                    write: OverlayWrite {
                        offset: allocation.range.offset,
                        bytes: vec![0xa1; EXTENT_BYTES],
                    },
                },
                ReservedWrite {
                    reservation_kind: namespace.kind,
                    write: OverlayWrite {
                        offset: namespace.range.offset,
                        bytes: vec![0xb2; EXTENT_BYTES],
                    },
                },
            ],
            backup_boot: vec![ReservedWrite {
                reservation_kind: boot.kind,
                write: OverlayWrite {
                    offset: boot.range.offset,
                    bytes: vec![0xc3; EXTENT_BYTES],
                },
            }],
            activation: vec![ReservedWrite {
                reservation_kind: boot.kind,
                write: OverlayWrite {
                    offset: boot.range.offset + EXTENT_BYTES as u64,
                    bytes: vec![0xd4; EXTENT_BYTES],
                },
            }],
            target_staging_rollback: vec![rollback(2048), rollback(2560)],
            backup_boot_rollback: vec![rollback(1024)],
            activation_rollback: vec![rollback(1536)],
        };
        let mut prepared = PreparedConversion::build_with_target_graph(
            &graph,
            &target_graph,
            ConversionDraft {
                transaction_id: [0x31; 16],
                preflight: PreflightEvidence {
                    image: ConversionImageIdentity {
                        instance: [0x41; 32],
                        image_bytes: IMAGE_BYTES,
                    },
                    source_filesystem: FileSystem::ExFat,
                    source_evidence_digest: [0x51; 32],
                    source_manifest_commitment: ManifestCommitment::from_validated_parts(
                        [0x61; 32], 1, 1,
                    ),
                    sector_bytes: 512,
                    allocation_alignment: 512,
                    inventory_complete: true,
                    allocation_map_complete: true,
                    health: HealthState::Clean,
                    access: AccessState::Offline,
                },
                target: TargetCapabilities {
                    filesystem: FileSystem::Ntfs,
                    features: Vec::new(),
                },
                source_allocations: vec![retired_metadata, movable],
                reservations,
                writes: ActivationAuthorizedWrites::test_only(FileSystem::Ntfs, writes),
            },
            relocation_before_images,
            limits,
        )
        .unwrap();
        fs::write(&image_path, &source_bytes).unwrap();
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
            source_evidence_digest: Some(source_evidence_digest),
        };
        let mut capsule_bytes = Vec::new();
        prepared
            .begin_capsule(&mut capsule_bytes, observed)
            .unwrap();
        drop(image);
        let (store, _) = CapsuleStore::create_new(
            &capsule_path,
            &image_path,
            &capsule_bytes,
            prepared.capsule_limits,
        )
        .unwrap();
        drop(store);
        (dir, image_path, capsule_path, prepared, source_bytes)
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

    fn inspectable_empty_exfat_source() -> (TempDir, PathBuf) {
        const IMAGE_BYTES: u64 = 4 * 1024 * 1024;

        let dir = TempDir::new();
        let image_path = dir.join("locked-source.exfat.img");
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
        let mut image = vec![0_u8; usize::try_from(IMAGE_BYTES).unwrap()];
        for write in serializer.staging_writes().chain([
            serializer.backup_boot_write(),
            serializer.primary_boot_write(),
        ]) {
            let start = usize::try_from(write.offset).unwrap();
            image[start..start + write.bytes.len()].copy_from_slice(&write.bytes);
        }
        fs::write(&image_path, image).unwrap();
        (dir, image_path)
    }

    fn prepared_from_locked_evidence(
        evidence: &LockedRegularImagePlanningEvidence<'_>,
        corrupt_before_image: bool,
    ) -> Result<PreparedConversion, ConversionError> {
        prepared_from_locked_evidence_with_bindings(
            evidence,
            corrupt_before_image,
            evidence.transaction_id(),
            evidence.preflight(),
        )
    }

    fn prepared_from_locked_evidence_with_bindings(
        evidence: &LockedRegularImagePlanningEvidence<'_>,
        corrupt_before_image: bool,
        transaction_id: [u8; 16],
        preflight: PreflightEvidence,
    ) -> Result<PreparedConversion, ConversionError> {
        let boot = DestinationReservation {
            range: ByteRange {
                offset: 1024 * 1024,
                length: 4096,
            },
            kind: ReservationKind::BootRegion,
        };
        let allocation = DestinationReservation {
            range: ByteRange {
                offset: 2 * 1024 * 1024,
                length: 4096,
            },
            kind: ReservationKind::AllocationMetadata,
        };
        let namespace = DestinationReservation {
            range: ByteRange {
                offset: 2 * 1024 * 1024 + 4096,
                length: 4096,
            },
            kind: ReservationKind::NamespaceMetadata,
        };
        let capsule = DestinationReservation {
            range: ByteRange {
                offset: 3 * 1024 * 1024,
                length: 4096,
            },
            kind: ReservationKind::Capsule,
        };
        let staging = vec![
            OverlayWrite {
                offset: allocation.range.offset,
                bytes: vec![0xa1; 512],
            },
            OverlayWrite {
                offset: namespace.range.offset,
                bytes: vec![0xb2; 512],
            },
        ];
        let backup = OverlayWrite {
            offset: boot.range.offset,
            bytes: vec![0xc3; 512],
        };
        let activation = OverlayWrite {
            offset: boot.range.offset + 512,
            bytes: vec![0xd4; 512],
        };
        let mut staging_rollback = evidence
            .capture_before_images(&staging, PreimageLimits::default())
            .unwrap();
        let backup_boot_rollback = evidence
            .capture_before_images(std::slice::from_ref(&backup), PreimageLimits::default())
            .unwrap();
        let activation_rollback = evidence
            .capture_before_images(std::slice::from_ref(&activation), PreimageLimits::default())
            .unwrap();
        if corrupt_before_image {
            staging_rollback[0].bytes[0] ^= 0xff;
        }
        let writes = OpaqueWriteSets {
            target_staging: vec![
                ReservedWrite {
                    reservation_kind: allocation.kind,
                    write: staging[0].clone(),
                },
                ReservedWrite {
                    reservation_kind: namespace.kind,
                    write: staging[1].clone(),
                },
            ],
            backup_boot: vec![ReservedWrite {
                reservation_kind: boot.kind,
                write: backup,
            }],
            activation: vec![ReservedWrite {
                reservation_kind: boot.kind,
                write: activation,
            }],
            target_staging_rollback: staging_rollback,
            backup_boot_rollback,
            activation_rollback,
        };
        PreparedConversion::build(
            evidence.graph(),
            ConversionDraft {
                transaction_id,
                preflight,
                target: TargetCapabilities {
                    filesystem: FileSystem::Ntfs,
                    features: Vec::new(),
                },
                source_allocations: Vec::new(),
                reservations: vec![boot, allocation, namespace, capsule],
                writes: ActivationAuthorizedWrites::test_only(FileSystem::Ntfs, writes),
            },
            ConversionLimits::default(),
        )
    }

    #[cfg(windows)]
    #[test]
    fn one_use_locked_session_binds_preflight_preimages_and_initial_capsule() {
        let (dir, image_path) = inspectable_empty_exfat_source();
        let capsule_path = dir.join("locked-transaction.starcap");
        let session =
            RegularImagePreparationSession::open(&image_path, ExecutorLimits::default()).unwrap();
        let prepared = session
            .prepare_with(VerificationLimits::default(), |evidence| {
                assert_eq!(evidence.inspection().profile.filesystem, FileSystem::ExFat);
                assert_eq!(evidence.preflight().access, AccessState::Offline);
                assert_ne!(evidence.transaction_id(), [0_u8; 16]);
                assert!(ImageFile::open(&image_path).is_err());
                prepared_from_locked_evidence(evidence, false)
            })
            .unwrap();
        assert!(ImageFile::open(&image_path).is_err());
        let (coordinator, sync) = prepared.create_coordinator(&capsule_path).unwrap();
        assert!(ImageFile::open(&image_path).is_err());
        assert!(sync.sync_data_completed);
        assert!(sync.sync_all_completed);
        assert_eq!(
            sync.namespace_durability,
            NamespaceDurability::ParentDirectorySynchronized
        );
        assert_eq!(
            coordinator.checkpoint().unwrap().phase,
            TransactionPhase::Discovered
        );
        drop(coordinator);
        assert!(ImageFile::open(&image_path).is_ok());
    }

    #[cfg(windows)]
    #[test]
    fn locked_session_rejects_planner_supplied_wrong_before_image() {
        let (_dir, image_path) = inspectable_empty_exfat_source();
        let session =
            RegularImagePreparationSession::open(&image_path, ExecutorLimits::default()).unwrap();
        assert!(matches!(
            session.prepare_with(VerificationLimits::default(), |evidence| {
                prepared_from_locked_evidence(evidence, true)
            }),
            Err(RegularImageCoordinatorError::PreparedBeforeImageMismatch { .. })
        ));
    }

    #[cfg(windows)]
    #[test]
    fn locked_session_rejects_planner_selected_transaction_identity() {
        let (_dir, image_path) = inspectable_empty_exfat_source();
        let session =
            RegularImagePreparationSession::open(&image_path, ExecutorLimits::default()).unwrap();
        assert!(matches!(
            session.prepare_with(VerificationLimits::default(), |evidence| {
                prepared_from_locked_evidence_with_bindings(
                    evidence,
                    false,
                    [0x77; 16],
                    evidence.preflight(),
                )
            }),
            Err(RegularImageCoordinatorError::PreparedTransactionMismatch)
        ));
    }

    #[cfg(windows)]
    #[test]
    fn locked_session_rejects_planner_substituted_preflight() {
        let (_dir, image_path) = inspectable_empty_exfat_source();
        let session =
            RegularImagePreparationSession::open(&image_path, ExecutorLimits::default()).unwrap();
        assert!(matches!(
            session.prepare_with(VerificationLimits::default(), |evidence| {
                let mut substituted = evidence.preflight();
                substituted.source_evidence_digest[0] ^= 0xff;
                prepared_from_locked_evidence_with_bindings(
                    evidence,
                    false,
                    evidence.transaction_id(),
                    substituted,
                )
            }),
            Err(RegularImageCoordinatorError::PreparedPreflightMismatch)
        ));
    }

    #[cfg(windows)]
    #[test]
    fn preparation_error_releases_mandatory_image_lock() {
        let (_dir, image_path) = inspectable_empty_exfat_source();
        let session =
            RegularImagePreparationSession::open(&image_path, ExecutorLimits::default()).unwrap();
        let result = session.prepare_with(VerificationLimits::default(), |_evidence| {
            Err(ConversionError::UnknownFilesystem)
        });
        assert!(matches!(
            result,
            Err(RegularImageCoordinatorError::Conversion(
                ConversionError::UnknownFilesystem
            ))
        ));
        assert!(ImageFile::open(&image_path).is_ok());
    }

    #[cfg(not(windows))]
    #[test]
    fn advisory_regular_file_lock_cannot_mint_offline_authority() {
        let (_dir, image_path) = inspectable_empty_exfat_source();
        assert!(matches!(
            RegularImagePreparationSession::open(&image_path, ExecutorLimits::default()),
            Err(RegularImageCoordinatorError::OfflineAuthorityUnavailable {
                lock_strength: LockStrength::AdvisoryFileLock,
            })
        ));
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
    fn relocation_journey_restarts_at_target_staged_and_rolls_back_exactly() {
        let (_dir, image_path, capsule_path, prepared, source_before) = relocation_fixture();
        let relocation = prepared.layout().relocations[0];
        let identity = ImageFile::open(&image_path).unwrap().identity().clone();
        let (mut coordinator, _) = RegularImageCoordinator::resume_existing(
            &prepared,
            &image_path,
            &identity,
            &capsule_path,
            ExecutorLimits::default(),
        )
        .unwrap();
        assert_eq!(
            coordinator.advance_to_target_staged().unwrap().phase,
            TransactionPhase::TargetStaged
        );
        drop(coordinator);

        let staged = fs::read(&image_path).unwrap();
        let source_start = usize::try_from(relocation.source.offset).unwrap();
        let destination_start = usize::try_from(relocation.destination.offset).unwrap();
        let length = usize::try_from(relocation.source.length).unwrap();
        assert_eq!(
            &staged[destination_start..destination_start + length],
            &source_before[source_start..source_start + length]
        );

        let identity = ImageFile::open(&image_path).unwrap().identity().clone();
        let (mut resumed, _) = RegularImageCoordinator::resume_existing(
            &prepared,
            &image_path,
            &identity,
            &capsule_path,
            ExecutorLimits::default(),
        )
        .unwrap();
        assert_eq!(
            resumed.checkpoint().unwrap().phase,
            TransactionPhase::TargetStaged
        );
        assert_eq!(
            resumed.rollback().unwrap().phase,
            TransactionPhase::RolledBack
        );
        drop(resumed);
        assert_eq!(fs::read(image_path).unwrap(), source_before);
    }

    #[test]
    fn every_reserved_partial_relocation_cut_retries_and_rolls_back_exactly() {
        for copied_bytes in [0_usize, 1, 127, 511, 512] {
            let (_dir, image_path, capsule_path, prepared, source_before) = relocation_fixture();
            let relocation = prepared.layout().relocations[0];
            let identity = ImageFile::open(&image_path).unwrap().identity().clone();
            let (mut coordinator, _) = RegularImageCoordinator::resume_existing(
                &prepared,
                &image_path,
                &identity,
                &capsule_path,
                ExecutorLimits::default(),
            )
            .unwrap();
            coordinator.append_reservation().unwrap();
            assert_eq!(
                coordinator.checkpoint().unwrap().phase,
                TransactionPhase::Reserved
            );
            drop(coordinator);

            let mut cut_image = source_before.clone();
            let source_start = usize::try_from(relocation.source.offset).unwrap();
            let destination_start = usize::try_from(relocation.destination.offset).unwrap();
            cut_image[destination_start..destination_start + copied_bytes]
                .copy_from_slice(&source_before[source_start..source_start + copied_bytes]);
            fs::write(&image_path, cut_image).unwrap();

            let identity = ImageFile::open(&image_path).unwrap().identity().clone();
            let (mut resumed, _) = RegularImageCoordinator::resume_existing(
                &prepared,
                &image_path,
                &identity,
                &capsule_path,
                ExecutorLimits::default(),
            )
            .unwrap();
            assert_eq!(
                resumed.advance_to_target_staged().unwrap().phase,
                TransactionPhase::TargetStaged
            );
            assert_eq!(
                resumed.rollback().unwrap().phase,
                TransactionPhase::RolledBack
            );
            drop(resumed);
            assert_eq!(fs::read(image_path).unwrap(), source_before);
        }
    }

    #[test]
    fn corrupted_durable_relocation_is_blocked_before_staging_and_can_rollback() {
        let (_dir, image_path, capsule_path, prepared, source_before) = relocation_fixture();
        let relocation = prepared.layout().relocations[0];
        let identity = ImageFile::open(&image_path).unwrap().identity().clone();
        let (mut coordinator, _) = RegularImageCoordinator::resume_existing(
            &prepared,
            &image_path,
            &identity,
            &capsule_path,
            ExecutorLimits::default(),
        )
        .unwrap();
        coordinator.append_reservation().unwrap();
        let reserved = coordinator.checkpoint().unwrap();
        coordinator.execute_next_mutation(reserved).unwrap();
        assert_eq!(
            coordinator.checkpoint().unwrap().phase,
            TransactionPhase::Relocating
        );
        drop(coordinator);

        let mut corrupted = fs::read(&image_path).unwrap();
        let destination_start = usize::try_from(relocation.destination.offset).unwrap();
        corrupted[destination_start] ^= 0xff;
        fs::write(&image_path, corrupted).unwrap();
        let identity = ImageFile::open(&image_path).unwrap().identity().clone();
        let (mut resumed, _) = RegularImageCoordinator::resume_existing(
            &prepared,
            &image_path,
            &identity,
            &capsule_path,
            ExecutorLimits::default(),
        )
        .unwrap();
        assert!(matches!(
            resumed.advance_to_target_staged(),
            Err(RegularImageCoordinatorError::RelocationCopyMismatch { .. })
        ));
        assert_eq!(
            resumed.rollback().unwrap().phase,
            TransactionPhase::RolledBack
        );
        drop(resumed);
        assert_eq!(fs::read(image_path).unwrap(), source_before);
    }
}
