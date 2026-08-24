//! Verified mutation of regular image files for already-prepared conversion intents.
//!
//! This module has no raw-device discovery or device API. It opens an existing regular file
//! without creating, truncating, or resizing it, revalidates the read-only [`ImageIdentity`] used
//! during planning, holds the strongest portable exclusive lock available, and returns completion
//! evidence only after read-back verification and durable flush boundaries.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::capsule::TransactionPhase;
use crate::conversion::{PreparedConversion, ReservedWrite, RollbackIntent, TransactionIntent};
use crate::geometry::Relocation;
use crate::image::{
    BoundedImageReader, ImageError, ImageFile, ImageIdentity, reject_device_like_path,
};
use crate::overlay::OverlayWrite;

/// Default maximum allocation and I/O size for each executor chunk (1 MiB).
pub const DEFAULT_EXECUTOR_CHUNK_BYTES: usize = 1024 * 1024;

/// Bounded executor configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutorLimits {
    /// Maximum buffer and individual positional I/O request size.
    pub max_chunk_bytes: usize,
}

impl Default for ExecutorLimits {
    fn default() -> Self {
        Self {
            max_chunk_bytes: DEFAULT_EXECUTOR_CHUNK_BYTES,
        }
    }
}

/// Strength of the file exclusion held for the executor lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockStrength {
    /// Windows deny-share opening plus a whole-file exclusive lock.
    #[cfg(windows)]
    MandatoryDenyShareAndFileLock,
    /// A kernel whole-file advisory lock. Cooperating processes are excluded.
    #[cfg(not(windows))]
    AdvisoryFileLock,
}

/// Mutation class proven by returned completion evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExecutionKind {
    Relocation,
    TargetStaging,
    BackupBoot,
    Activation,
    Rollback,
}

/// Every fault boundary exposed by the deterministic crash-injection hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FaultBoundary {
    BeforeRead,
    AfterRead,
    BeforeWrite,
    AfterWrite,
    BeforeVerificationRead,
    AfterVerification,
    BeforeSyncData,
    AfterSyncData,
    BeforeSyncAll,
    AfterSyncAll,
}

/// Exact location of one injectable crash boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FaultPoint {
    pub kind: ExecutionKind,
    pub boundary: FaultBoundary,
    /// Zero-based relocation or write index; `None` denotes a flush boundary.
    pub operation_index: Option<usize>,
    /// Byte offset within the current relocation/write; zero for flush boundaries.
    pub chunk_offset: u64,
}

/// Deterministic fault hook. Returning `true` aborts before the executor crosses `point`.
pub trait FaultInjector {
    fn should_fail(&mut self, point: FaultPoint) -> bool;
}

/// Production hook that never injects a fault.
#[derive(Debug, Default)]
pub struct NoFault;

impl FaultInjector for NoFault {
    fn should_fail(&mut self, _point: FaultPoint) -> bool {
        false
    }
}

/// Verified completion details sealed by the executor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionEvidence {
    kind: ExecutionKind,
    operations: usize,
    bytes_written: u64,
    /// Domain-separated digest of exact ranges and verified destination bytes.
    verified_digest: [u8; 32],
    sync_data_completed: bool,
    sync_all_completed: bool,
}

impl ExecutionEvidence {
    #[must_use]
    pub const fn kind(&self) -> ExecutionKind {
        self.kind
    }

    #[must_use]
    pub const fn operations(&self) -> usize {
        self.operations
    }

    #[must_use]
    pub const fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    #[must_use]
    pub const fn verified_digest(&self) -> [u8; 32] {
        self.verified_digest
    }

    #[must_use]
    pub const fn sync_data_completed(&self) -> bool {
        self.sync_data_completed
    }

    #[must_use]
    pub const fn sync_all_completed(&self) -> bool {
        self.sync_all_completed
    }
}

/// Opaque, plan-and-container-bound proof that one mutating intent reached both flush barriers.
#[derive(Debug, PartialEq, Eq)]
pub struct ExecutedIntent {
    evidence: ExecutionEvidence,
    plan_digest: [u8; 32],
    image_instance: [u8; 32],
    completed_phase: TransactionPhase,
}

/// One-use authorization for exactly one durable capsule generation and phase.
///
/// Construction and use are crate-private so only the durable regular-image coordinator can bind
/// executor work to the capsule lock it owns. The value is deliberately neither `Clone` nor
/// `Copy`.
#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ExecutionLease {
    capsule_generation: u64,
    current_phase: TransactionPhase,
    plan_digest: [u8; 32],
    image_instance: [u8; 32],
    one_use: LeaseSeal,
}

#[derive(Debug, PartialEq, Eq)]
struct LeaseSeal;

#[allow(dead_code)]
impl ExecutionLease {
    pub(crate) const fn new(
        capsule_generation: u64,
        current_phase: TransactionPhase,
        plan_digest: [u8; 32],
        image_instance: [u8; 32],
    ) -> Self {
        Self {
            capsule_generation,
            current_phase,
            plan_digest,
            image_instance,
            one_use: LeaseSeal,
        }
    }

    const fn into_parts(self) -> (u64, TransactionPhase, [u8; 32], [u8; 32]) {
        let Self {
            capsule_generation,
            current_phase,
            plan_digest,
            image_instance,
            one_use: _,
        } = self;
        (
            capsule_generation,
            current_phase,
            plan_digest,
            image_instance,
        )
    }
}

/// Executor completion retaining the exact capsule checkpoint that authorized it.
#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct LeasedIntent {
    executed: ExecutedIntent,
    capsule_generation: u64,
    current_phase: TransactionPhase,
}

#[allow(dead_code)]
impl LeasedIntent {
    pub(crate) const fn into_parts(self) -> (ExecutedIntent, u64, TransactionPhase) {
        (self.executed, self.capsule_generation, self.current_phase)
    }
}

/// Rollback completion retaining the exact durable checkpoint that authorized restoration.
#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct LeasedRollback {
    executed: ExecutedRollback,
    capsule_generation: u64,
    current_phase: TransactionPhase,
}

#[allow(dead_code)]
impl LeasedRollback {
    pub(crate) const fn into_parts(self) -> (ExecutedRollback, u64, TransactionPhase) {
        (self.executed, self.capsule_generation, self.current_phase)
    }
}

impl ExecutedIntent {
    #[must_use]
    pub const fn evidence(&self) -> &ExecutionEvidence {
        &self.evidence
    }

    #[must_use]
    pub const fn completed_phase(&self) -> TransactionPhase {
        self.completed_phase
    }

    pub(crate) const fn into_checkpoint(
        self,
    ) -> (ExecutionEvidence, [u8; 32], [u8; 32], TransactionPhase) {
        (
            self.evidence,
            self.plan_digest,
            self.image_instance,
            self.completed_phase,
        )
    }
}

type RollbackCheckpoint = (
    bool,
    Option<ExecutionEvidence>,
    [u8; 32],
    [u8; 32],
    Option<[u8; 32]>,
);

/// Result of executing a conservative rollback intent. Construction remains executor-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RollbackOutcome {
    /// No source-visible bytes required restoration.
    StagingDiscarded,
    /// Exact before-images were written, verified, and durably flushed.
    SourceRestored(ExecutionEvidence),
}

#[derive(Debug, PartialEq, Eq)]
pub struct ExecutedRollback {
    outcome: RollbackOutcome,
    plan_digest: [u8; 32],
    image_instance: [u8; 32],
    rollback_digest: Option<[u8; 32]>,
}

impl ExecutedRollback {
    #[must_use]
    pub const fn restored_source(&self) -> bool {
        matches!(self.outcome, RollbackOutcome::SourceRestored(_))
    }

    #[must_use]
    pub const fn evidence(&self) -> Option<&ExecutionEvidence> {
        match &self.outcome {
            RollbackOutcome::StagingDiscarded => None,
            RollbackOutcome::SourceRestored(evidence) => Some(evidence),
        }
    }

    pub(crate) const fn into_checkpoint(self) -> RollbackCheckpoint {
        let (restored_source, evidence) = match self.outcome {
            RollbackOutcome::StagingDiscarded => (false, None),
            RollbackOutcome::SourceRestored(evidence) => (true, Some(evidence)),
        };
        (
            restored_source,
            evidence,
            self.plan_digest,
            self.image_instance,
            self.rollback_digest,
        )
    }
}

/// Existing regular-image writer pinned to the identity established during inspection.
#[derive(Debug)]
pub struct ImageExecutor {
    file: File,
    identity: ImageIdentity,
    canonical_path: PathBuf,
    limits: ExecutorLimits,
    lock_strength: LockStrength,
}

/// Read-only view cloned from an executor's already-open, exclusively locked regular file.
///
/// The borrow prevents the view from outliving the executor and therefore the lock. Construction
/// is crate-private, retains no independently supplied path, and never reopens the image namespace.
#[derive(Debug)]
pub(crate) struct LockedImageView<'a> {
    image: ImageFile,
    executor: &'a ImageExecutor,
}

impl LockedImageView<'_> {
    /// Revalidates both the locked executor container and this pinned read handle after an
    /// inspection or verification operation.
    pub(crate) fn post_operation_revalidate(&self) -> Result<(), ExecutorError> {
        self.executor.ensure_same_container()?;
        self.image
            .read_exact_at(0, 0)
            .map_err(ExecutorError::Image)?;
        if self.image.len() != self.executor.identity.length()
            || self.image.identity().stable_container_token()
                != self.executor.identity.stable_container_token()
        {
            return Err(ExecutorError::IdentityMismatch);
        }
        Ok(())
    }
}

impl BoundedImageReader for LockedImageView<'_> {
    fn len(&self) -> u64 {
        self.image.len()
    }

    fn max_read_bytes(&self) -> usize {
        self.image.max_read_bytes()
    }

    fn read_exact_at(&self, offset: u64, length: usize) -> Result<Vec<u8>, ImageError> {
        self.image.read_exact_at(offset, length)
    }
}

impl ImageExecutor {
    /// Opens an existing image for verified in-place writes.
    ///
    /// This never enables `create`, `truncate`, or resize behavior. The caller must close the
    /// original read-only [`crate::image::ImageFile`] handle before opening on Windows, where
    /// deny-share access is mandatory.
    ///
    /// # Errors
    ///
    /// Rejects zero limits, lexical or canonical device paths, non-regular files, changed
    /// identities, lock contention, and all underlying I/O failures.
    pub fn open(
        path: impl AsRef<Path>,
        expected: &ImageIdentity,
        limits: ExecutorLimits,
    ) -> Result<Self, ExecutorError> {
        if limits.max_chunk_bytes == 0 {
            return Err(ExecutorError::InvalidChunkLimit);
        }
        let requested = path.as_ref();
        reject_device_like_path(requested).map_err(ExecutorError::Image)?;
        let canonical_path = fs::canonicalize(requested)
            .map_err(|source| ExecutorError::io("canonicalize image path", source))?;
        reject_device_like_path(&canonical_path).map_err(ExecutorError::Image)?;
        if canonical_path != expected.canonical_path() {
            return Err(ExecutorError::IdentityMismatch);
        }

        let path_metadata = fs::metadata(&canonical_path)
            .map_err(|source| ExecutorError::io("inspect image path", source))?;
        if !expected.matches_metadata(&path_metadata) {
            return Err(ExecutorError::IdentityMismatch);
        }

        let mut options = OpenOptions::new();
        options.read(true).write(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.share_mode(0);
        }
        let file = options
            .open(&canonical_path)
            .map_err(|source| ExecutorError::io("open image read-write", source))?;
        let opened_metadata = file
            .metadata()
            .map_err(|source| ExecutorError::io("inspect opened image", source))?;
        if !expected.matches_metadata(&opened_metadata) {
            return Err(ExecutorError::IdentityMismatch);
        }
        fs4::FileExt::try_lock(&file)
            .map_err(|source| ExecutorError::io("lock image exclusively", source.into()))?;

        let executor = Self {
            file,
            identity: expected.clone(),
            canonical_path,
            limits,
            lock_strength: platform_lock_strength(),
        };
        executor.ensure_same_container()?;
        Ok(executor)
    }

    /// Exclusion strength held until this executor is dropped.
    #[must_use]
    pub const fn lock_strength(&self) -> LockStrength {
        self.lock_strength
    }

    /// Immutable regular-image identity against which every operation is revalidated.
    #[must_use]
    pub const fn identity(&self) -> &ImageIdentity {
        &self.identity
    }

    /// Clones this already-open locked handle into a lifetime-bound bounded reader.
    ///
    /// The canonical path is retained only as identity evidence for the cloned [`ImageFile`]; it
    /// is never resolved or reopened by this operation.
    pub(crate) fn locked_view(
        &self,
        max_read_bytes: usize,
    ) -> Result<LockedImageView<'_>, ExecutorError> {
        self.ensure_same_container()?;
        let image = ImageFile::from_open_regular_file(
            &self.file,
            self.canonical_path.clone(),
            max_read_bytes,
        )
        .map_err(ExecutorError::Image)?;
        let view = LockedImageView {
            image,
            executor: self,
        };
        view.post_operation_revalidate()?;
        Ok(view)
    }

    /// Executes one mutating intent emitted for `prepared`.
    ///
    /// Non-mutating coordination intents are refused. Supplying `prepared` keeps mutation behind
    /// the serializer/coordinator authorization boundary; ranges are additionally checked against
    /// its immutable layout or candidate overlay.
    ///
    /// # Errors
    ///
    /// Refuses an intent not authorized by `prepared`, non-mutating intents, changed image
    /// identity/length, verification mismatches, arithmetic overflow, and I/O failures.
    fn execute_intent(
        &self,
        prepared: &PreparedConversion,
        intent: TransactionIntent<'_>,
    ) -> Result<ExecutedIntent, ExecutorError> {
        self.execute_intent_with_faults(prepared, intent, &mut NoFault)
    }

    /// Executes exactly the forward mutation authorized by one current capsule checkpoint.
    #[allow(dead_code)]
    pub(crate) fn execute_leased_intent(
        &self,
        prepared: &PreparedConversion,
        lease: ExecutionLease,
        intent: TransactionIntent<'_>,
    ) -> Result<LeasedIntent, ExecutorError> {
        let (capsule_generation, current_phase, plan_digest, image_instance) = lease.into_parts();
        self.validate_lease(prepared, plan_digest, image_instance)?;
        let authorized = matches!(
            (current_phase, &intent),
            (TransactionPhase::Reserved, TransactionIntent::Relocate(_))
                | (
                    TransactionPhase::Relocating,
                    TransactionIntent::StageTarget(_)
                )
        );
        if !authorized {
            return Err(ExecutorError::LeaseIntentMismatch);
        }
        let executed = self.execute_intent(prepared, intent)?;
        Ok(LeasedIntent {
            executed,
            capsule_generation,
            current_phase,
        })
    }

    /// Executes one mutating intent with deterministic crash injection.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorError::InjectedFault`] at a requested boundary, or the same failures as
    /// [`Self::execute_intent`]. No completion evidence is returned before both durable flushes.
    fn execute_intent_with_faults<F: FaultInjector>(
        &self,
        prepared: &PreparedConversion,
        intent: TransactionIntent<'_>,
        faults: &mut F,
    ) -> Result<ExecutedIntent, ExecutorError> {
        if !prepared.matches_regular_image(&self.identity) {
            return Err(ExecutorError::PlanImageMismatch);
        }
        let (evidence, completed_phase) = match intent {
            TransactionIntent::Relocate(relocations) => {
                if relocations != prepared.layout().relocations {
                    return Err(ExecutorError::IntentNotAuthorized);
                }
                self.copy_relocations(relocations, faults)
                    .map(|evidence| (evidence, TransactionPhase::Relocating))
            }
            TransactionIntent::StageTarget(writes) => {
                validate_exact_phase(prepared.target_staging_writes(), writes)?;
                self.apply_reserved_writes(ExecutionKind::TargetStaging, writes, faults)
                    .map(|evidence| (evidence, TransactionPhase::TargetStaged))
            }
            TransactionIntent::WriteBackupBoot(writes) => {
                validate_exact_phase(prepared.backup_boot_writes(), writes)?;
                self.apply_reserved_writes(ExecutionKind::BackupBoot, writes, faults)
                    .map(|evidence| (evidence, TransactionPhase::BackupBootWritten))
            }
            TransactionIntent::Activate(writes) => {
                validate_exact_phase(prepared.activation_writes(), writes)?;
                self.apply_reserved_writes(ExecutionKind::Activation, writes, faults)
                    .map(|evidence| (evidence, TransactionPhase::Activated))
            }
            TransactionIntent::Reserve(_)
            | TransactionIntent::VerifyStaging(_)
            | TransactionIntent::Verify(_)
            | TransactionIntent::Finalize
            | TransactionIntent::None => Err(ExecutorError::NonMutatingIntent),
        }?;
        Ok(ExecutedIntent {
            evidence,
            plan_digest: prepared.plan_digest(),
            image_instance: self.identity.stable_container_token(),
            completed_phase,
        })
    }

    /// Applies a coordinator-produced rollback intent.
    ///
    /// # Errors
    ///
    /// Refuses restoration bytes that are not exactly one of `prepared`'s conservative rollback
    /// overlays, or returns the mutation/I/O failures documented by [`Self::execute_intent`].
    fn execute_rollback(
        &self,
        prepared: &PreparedConversion,
        intent: RollbackIntent<'_>,
    ) -> Result<ExecutedRollback, ExecutorError> {
        self.execute_rollback_with_faults(prepared, intent, &mut NoFault)
    }

    /// Executes rollback bound to one current durable capsule checkpoint.
    #[allow(dead_code)]
    pub(crate) fn execute_leased_rollback(
        &self,
        prepared: &PreparedConversion,
        lease: ExecutionLease,
        intent: RollbackIntent<'_>,
    ) -> Result<LeasedRollback, ExecutorError> {
        let (capsule_generation, current_phase, plan_digest, image_instance) = lease.into_parts();
        self.validate_lease(prepared, plan_digest, image_instance)?;
        if matches!(
            current_phase,
            TransactionPhase::Finalized | TransactionPhase::RolledBack
        ) {
            return Err(ExecutorError::LeaseIntentMismatch);
        }
        let executed = self.execute_rollback(prepared, intent)?;
        Ok(LeasedRollback {
            executed,
            capsule_generation,
            current_phase,
        })
    }

    #[allow(dead_code)]
    fn validate_lease(
        &self,
        prepared: &PreparedConversion,
        plan_digest: [u8; 32],
        image_instance: [u8; 32],
    ) -> Result<(), ExecutorError> {
        if plan_digest != prepared.plan_digest()
            || image_instance != self.identity.stable_container_token()
            || !prepared.matches_regular_image(&self.identity)
        {
            return Err(ExecutorError::InvalidExecutionLease);
        }
        Ok(())
    }

    /// Applies rollback with deterministic crash injection.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorError::InjectedFault`] at requested boundaries and otherwise the same
    /// errors as [`Self::execute_rollback`].
    fn execute_rollback_with_faults<F: FaultInjector>(
        &self,
        prepared: &PreparedConversion,
        intent: RollbackIntent<'_>,
        faults: &mut F,
    ) -> Result<ExecutedRollback, ExecutorError> {
        if !prepared.matches_regular_image(&self.identity) {
            return Err(ExecutorError::PlanImageMismatch);
        }
        let (outcome, rollback_digest) = match intent {
            RollbackIntent::DiscardStaging => Ok((RollbackOutcome::StagingDiscarded, None)),
            RollbackIntent::RestoreSource { writes, digest } => {
                let authorized = [
                    prepared.staging_rollback_overlay().writes(),
                    prepared.backup_boot_rollback_overlay().writes(),
                    prepared.rollback_overlay().writes(),
                ]
                .into_iter()
                .any(|candidate| candidate == writes);
                if !authorized || overlay_digest(writes) != digest {
                    return Err(ExecutorError::IntentNotAuthorized);
                }
                self.apply_overlay_writes(ExecutionKind::Rollback, writes, faults)
                    .map(RollbackOutcome::SourceRestored)
                    .map(|outcome| (outcome, Some(digest)))
            }
        }?;
        Ok(ExecutedRollback {
            outcome,
            plan_digest: prepared.plan_digest(),
            image_instance: self.identity.stable_container_token(),
            rollback_digest,
        })
    }

    fn copy_relocations<F: FaultInjector>(
        &self,
        relocations: &[Relocation],
        faults: &mut F,
    ) -> Result<ExecutionEvidence, ExecutorError> {
        let kind = ExecutionKind::Relocation;
        let mut hasher = evidence_hasher(kind);
        let mut total = 0_u64;
        for (index, relocation) in relocations.iter().enumerate() {
            if relocation.source.length != relocation.destination.length
                || relocation.source.length == 0
                || ranges_overlap(
                    relocation.source.offset,
                    relocation.source.length,
                    relocation.destination.offset,
                    relocation.destination.length,
                )?
            {
                return Err(ExecutorError::InvalidRelocation { index });
            }
            validate_range(
                self.identity.length(),
                relocation.source.offset,
                relocation.source.length,
            )?;
            validate_range(
                self.identity.length(),
                relocation.destination.offset,
                relocation.destination.length,
            )?;
            hasher.update(relocation.source.offset.to_le_bytes());
            hasher.update(relocation.destination.offset.to_le_bytes());
            hasher.update(relocation.source.length.to_le_bytes());
            let mut relative = 0_u64;
            while relative < relocation.source.length {
                let count = chunk_length(
                    relocation.source.length - relative,
                    self.limits.max_chunk_bytes,
                )?;
                self.ensure_same_container()?;
                inject(
                    faults,
                    kind,
                    FaultBoundary::BeforeRead,
                    Some(index),
                    relative,
                )?;
                let mut bytes = vec![0_u8; count];
                read_exact_at(&self.file, relocation.source.offset + relative, &mut bytes)
                    .map_err(|source| ExecutorError::io("read relocation source", source))?;
                inject(
                    faults,
                    kind,
                    FaultBoundary::AfterRead,
                    Some(index),
                    relative,
                )?;
                inject(
                    faults,
                    kind,
                    FaultBoundary::BeforeWrite,
                    Some(index),
                    relative,
                )?;
                write_all_at(&self.file, relocation.destination.offset + relative, &bytes)
                    .map_err(|source| ExecutorError::io("write relocation destination", source))?;
                inject(
                    faults,
                    kind,
                    FaultBoundary::AfterWrite,
                    Some(index),
                    relative,
                )?;
                verify_at(
                    &self.file,
                    relocation.destination.offset + relative,
                    &bytes,
                    faults,
                    kind,
                    index,
                    relative,
                )?;
                hasher.update(&bytes);
                relative = relative
                    .checked_add(
                        u64::try_from(count).map_err(|_| ExecutorError::ArithmeticOverflow)?,
                    )
                    .ok_or(ExecutorError::ArithmeticOverflow)?;
                total = total
                    .checked_add(
                        u64::try_from(count).map_err(|_| ExecutorError::ArithmeticOverflow)?,
                    )
                    .ok_or(ExecutorError::ArithmeticOverflow)?;
            }
        }
        self.finish_durable(kind, relocations.len(), total, hasher, faults)
    }

    fn apply_reserved_writes<F: FaultInjector>(
        &self,
        kind: ExecutionKind,
        writes: &[ReservedWrite],
        faults: &mut F,
    ) -> Result<ExecutionEvidence, ExecutorError> {
        let overlays: Vec<_> = writes.iter().map(|value| &value.write).collect();
        self.apply_write_refs(kind, &overlays, faults)
    }

    fn apply_overlay_writes<F: FaultInjector>(
        &self,
        kind: ExecutionKind,
        writes: &[OverlayWrite],
        faults: &mut F,
    ) -> Result<ExecutionEvidence, ExecutorError> {
        let refs: Vec<_> = writes.iter().collect();
        self.apply_write_refs(kind, &refs, faults)
    }

    fn apply_write_refs<F: FaultInjector>(
        &self,
        kind: ExecutionKind,
        writes: &[&OverlayWrite],
        faults: &mut F,
    ) -> Result<ExecutionEvidence, ExecutorError> {
        let mut hasher = evidence_hasher(kind);
        let mut total = 0_u64;
        for (index, write) in writes.iter().enumerate() {
            let length =
                u64::try_from(write.bytes.len()).map_err(|_| ExecutorError::ArithmeticOverflow)?;
            validate_range(self.identity.length(), write.offset, length)?;
            hasher.update(write.offset.to_le_bytes());
            hasher.update(length.to_le_bytes());
            let mut relative = 0_u64;
            while relative < length {
                let count = chunk_length(length - relative, self.limits.max_chunk_bytes)?;
                let start =
                    usize::try_from(relative).map_err(|_| ExecutorError::ArithmeticOverflow)?;
                let end = start
                    .checked_add(count)
                    .ok_or(ExecutorError::ArithmeticOverflow)?;
                let bytes = &write.bytes[start..end];
                self.ensure_same_container()?;
                inject(
                    faults,
                    kind,
                    FaultBoundary::BeforeWrite,
                    Some(index),
                    relative,
                )?;
                write_all_at(&self.file, write.offset + relative, bytes)
                    .map_err(|source| ExecutorError::io("write prepared image range", source))?;
                inject(
                    faults,
                    kind,
                    FaultBoundary::AfterWrite,
                    Some(index),
                    relative,
                )?;
                verify_at(
                    &self.file,
                    write.offset + relative,
                    bytes,
                    faults,
                    kind,
                    index,
                    relative,
                )?;
                hasher.update(bytes);
                let count_u64 =
                    u64::try_from(count).map_err(|_| ExecutorError::ArithmeticOverflow)?;
                relative = relative
                    .checked_add(count_u64)
                    .ok_or(ExecutorError::ArithmeticOverflow)?;
                total = total
                    .checked_add(count_u64)
                    .ok_or(ExecutorError::ArithmeticOverflow)?;
            }
        }
        self.finish_durable(kind, writes.len(), total, hasher, faults)
    }

    fn finish_durable<F: FaultInjector>(
        &self,
        kind: ExecutionKind,
        operations: usize,
        bytes_written: u64,
        hasher: Sha256,
        faults: &mut F,
    ) -> Result<ExecutionEvidence, ExecutorError> {
        self.ensure_same_container()?;
        inject(faults, kind, FaultBoundary::BeforeSyncData, None, 0)?;
        self.file
            .sync_data()
            .map_err(|source| ExecutorError::io("flush image data", source))?;
        inject(faults, kind, FaultBoundary::AfterSyncData, None, 0)?;
        self.ensure_same_container()?;
        inject(faults, kind, FaultBoundary::BeforeSyncAll, None, 0)?;
        self.file
            .sync_all()
            .map_err(|source| ExecutorError::io("flush image data and metadata", source))?;
        inject(faults, kind, FaultBoundary::AfterSyncAll, None, 0)?;
        self.ensure_same_container()?;
        Ok(ExecutionEvidence {
            kind,
            operations,
            bytes_written,
            verified_digest: hasher.finalize().into(),
            sync_data_completed: true,
            sync_all_completed: true,
        })
    }

    fn ensure_same_container(&self) -> Result<(), ExecutorError> {
        let handle_metadata = self
            .file
            .metadata()
            .map_err(|source| ExecutorError::io("revalidate opened image", source))?;
        if !self.identity.matches_container_metadata(&handle_metadata) {
            return Err(ExecutorError::IdentityMismatch);
        }
        let current_path = fs::canonicalize(&self.canonical_path)
            .map_err(|source| ExecutorError::io("revalidate canonical image path", source))?;
        let path_metadata = fs::metadata(&current_path)
            .map_err(|source| ExecutorError::io("revalidate image path", source))?;
        if current_path != self.canonical_path
            || !self.identity.matches_container_metadata(&path_metadata)
        {
            return Err(ExecutorError::IdentityMismatch);
        }
        Ok(())
    }
}

impl Drop for ImageExecutor {
    fn drop(&mut self) {
        let _ = fs4::FileExt::unlock(&self.file);
    }
}

/// Regular-image executor failures.
#[derive(Debug)]
pub enum ExecutorError {
    Image(ImageError),
    Io {
        operation: &'static str,
        source: io::Error,
    },
    InvalidChunkLimit,
    IdentityMismatch,
    PlanImageMismatch,
    InvalidExecutionLease,
    LeaseIntentMismatch,
    IntentNotAuthorized,
    NonMutatingIntent,
    InvalidRelocation {
        index: usize,
    },
    RangeOutsideImage {
        offset: u64,
        length: u64,
        image_length: u64,
    },
    ArithmeticOverflow,
    VerificationMismatch {
        offset: u64,
    },
    InjectedFault {
        point: FaultPoint,
    },
}

impl ExecutorError {
    const fn io(operation: &'static str, source: io::Error) -> Self {
        Self::Io { operation, source }
    }
}

impl fmt::Display for ExecutorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Image(source) => write!(formatter, "image rejected: {source}"),
            Self::Io { operation, source } => write!(formatter, "{operation}: {source}"),
            Self::InvalidChunkLimit => formatter.write_str("executor chunk limit must be non-zero"),
            Self::IdentityMismatch => {
                formatter.write_str("regular image identity or fixed length changed")
            }
            Self::PlanImageMismatch => formatter
                .write_str("prepared conversion belongs to a different regular image container"),
            Self::InvalidExecutionLease => formatter.write_str(
                "execution lease belongs to a different plan or regular image container",
            ),
            Self::LeaseIntentMismatch => formatter
                .write_str("execution lease does not authorize this capsule phase or intent"),
            Self::IntentNotAuthorized => {
                formatter.write_str("intent is not authorized by the prepared conversion")
            }
            Self::NonMutatingIntent => {
                formatter.write_str("intent does not require image mutation")
            }
            Self::InvalidRelocation { index } => write!(
                formatter,
                "relocation {index} has invalid or overlapping geometry"
            ),
            Self::RangeOutsideImage {
                offset,
                length,
                image_length,
            } => write!(
                formatter,
                "range {offset}+{length} exceeds {image_length}-byte image"
            ),
            Self::ArithmeticOverflow => formatter.write_str("executor byte arithmetic overflowed"),
            Self::VerificationMismatch { offset } => write!(
                formatter,
                "read-back verification failed at image offset {offset}"
            ),
            Self::InjectedFault { point } => write!(formatter, "injected crash at {point:?}"),
        }
    }
}

impl std::error::Error for ExecutorError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Image(source) => Some(source),
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

fn validate_exact_phase(
    expected: &[ReservedWrite],
    supplied: &[ReservedWrite],
) -> Result<(), ExecutorError> {
    if supplied == expected {
        Ok(())
    } else {
        Err(ExecutorError::IntentNotAuthorized)
    }
}

fn verify_at<F: FaultInjector>(
    file: &File,
    offset: u64,
    expected: &[u8],
    faults: &mut F,
    kind: ExecutionKind,
    operation_index: usize,
    chunk_offset: u64,
) -> Result<(), ExecutorError> {
    inject(
        faults,
        kind,
        FaultBoundary::BeforeVerificationRead,
        Some(operation_index),
        chunk_offset,
    )?;
    let mut actual = vec![0_u8; expected.len()];
    read_exact_at(file, offset, &mut actual)
        .map_err(|source| ExecutorError::io("read back written image range", source))?;
    if actual != expected {
        return Err(ExecutorError::VerificationMismatch { offset });
    }
    inject(
        faults,
        kind,
        FaultBoundary::AfterVerification,
        Some(operation_index),
        chunk_offset,
    )
}

fn inject<F: FaultInjector>(
    faults: &mut F,
    kind: ExecutionKind,
    boundary: FaultBoundary,
    operation_index: Option<usize>,
    chunk_offset: u64,
) -> Result<(), ExecutorError> {
    let point = FaultPoint {
        kind,
        boundary,
        operation_index,
        chunk_offset,
    };
    if faults.should_fail(point) {
        Err(ExecutorError::InjectedFault { point })
    } else {
        Ok(())
    }
}

fn evidence_hasher(kind: ExecutionKind) -> Sha256 {
    let mut hasher = Sha256::new();
    hasher.update(b"starconverter-executor-evidence-v1");
    hasher.update([kind as u8]);
    hasher
}

fn overlay_digest(writes: &[OverlayWrite]) -> [u8; 32] {
    let mut ordered: Vec<_> = writes.iter().collect();
    ordered.sort_unstable_by_key(|write| write.offset);
    let mut hasher = Sha256::new();
    hasher.update(b"starconverter-overlay-writes-v1");
    for write in ordered {
        hasher.update(write.offset.to_le_bytes());
        hasher.update((write.bytes.len() as u64).to_le_bytes());
        hasher.update(&write.bytes);
    }
    hasher.finalize().into()
}

fn validate_range(image_length: u64, offset: u64, length: u64) -> Result<(), ExecutorError> {
    let end = offset
        .checked_add(length)
        .ok_or(ExecutorError::ArithmeticOverflow)?;
    if length == 0 || end > image_length {
        Err(ExecutorError::RangeOutsideImage {
            offset,
            length,
            image_length,
        })
    } else {
        Ok(())
    }
}

fn ranges_overlap(
    a_offset: u64,
    a_length: u64,
    b_offset: u64,
    b_length: u64,
) -> Result<bool, ExecutorError> {
    let a_end = a_offset
        .checked_add(a_length)
        .ok_or(ExecutorError::ArithmeticOverflow)?;
    let b_end = b_offset
        .checked_add(b_length)
        .ok_or(ExecutorError::ArithmeticOverflow)?;
    Ok(a_offset < b_end && b_offset < a_end)
}

fn chunk_length(remaining: u64, maximum: usize) -> Result<usize, ExecutorError> {
    let maximum_u64 = u64::try_from(maximum).map_err(|_| ExecutorError::ArithmeticOverflow)?;
    usize::try_from(remaining.min(maximum_u64)).map_err(|_| ExecutorError::ArithmeticOverflow)
}

#[cfg(windows)]
const fn platform_lock_strength() -> LockStrength {
    LockStrength::MandatoryDenyShareAndFileLock
}

#[cfg(not(windows))]
const fn platform_lock_strength() -> LockStrength {
    LockStrength::AdvisoryFileLock
}

#[cfg(unix)]
fn read_exact_at(file: &File, offset: u64, buffer: &mut [u8]) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    positional_read_loop(buffer, |chunk, relative| {
        file.read_at(chunk, offset + relative)
    })
}

#[cfg(windows)]
fn read_exact_at(file: &File, offset: u64, buffer: &mut [u8]) -> io::Result<()> {
    use std::os::windows::fs::FileExt;
    positional_read_loop(buffer, |chunk, relative| {
        file.seek_read(chunk, offset + relative)
    })
}

#[cfg(not(any(unix, windows)))]
fn read_exact_at(file: &File, offset: u64, buffer: &mut [u8]) -> io::Result<()> {
    use std::io::{Read, Seek, SeekFrom};
    let mut clone = file.try_clone()?;
    clone.seek(SeekFrom::Start(offset))?;
    clone.read_exact(buffer)
}

#[cfg(any(unix, windows))]
fn positional_read_loop(
    buffer: &mut [u8],
    mut read: impl FnMut(&mut [u8], u64) -> io::Result<usize>,
) -> io::Result<()> {
    let mut done = 0_usize;
    while done < buffer.len() {
        let count = read(&mut buffer[done..], done as u64)?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "short positional read",
            ));
        }
        done += count;
    }
    Ok(())
}

#[cfg(unix)]
fn write_all_at(file: &File, offset: u64, buffer: &[u8]) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    positional_write_loop(buffer, |chunk, relative| {
        file.write_at(chunk, offset + relative)
    })
}

#[cfg(windows)]
fn write_all_at(file: &File, offset: u64, buffer: &[u8]) -> io::Result<()> {
    use std::os::windows::fs::FileExt;
    positional_write_loop(buffer, |chunk, relative| {
        file.seek_write(chunk, offset + relative)
    })
}

#[cfg(not(any(unix, windows)))]
fn write_all_at(file: &File, offset: u64, buffer: &[u8]) -> io::Result<()> {
    use std::io::{Seek, SeekFrom, Write};
    let mut clone = file.try_clone()?;
    clone.seek(SeekFrom::Start(offset))?;
    clone.write_all(buffer)
}

#[cfg(any(unix, windows))]
fn positional_write_loop(
    buffer: &[u8],
    mut write: impl FnMut(&[u8], u64) -> io::Result<usize>,
) -> io::Result<()> {
    let mut done = 0_usize;
    while done < buffer.len() {
        let count = write(&buffer[done..], done as u64)?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short positional write",
            ));
        }
        done += count;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    #[derive(Debug)]
    struct TempImage(PathBuf);

    impl TempImage {
        fn new(bytes: &[u8]) -> Self {
            let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "starconverter-executor-{}-{sequence}.img",
                std::process::id()
            ));
            fs::write(&path, bytes).unwrap();
            Self(path)
        }
    }

    impl Drop for TempImage {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    #[derive(Debug)]
    struct RecordFaults {
        fail_at: Option<usize>,
        seen: Vec<FaultPoint>,
    }

    impl FaultInjector for RecordFaults {
        fn should_fail(&mut self, point: FaultPoint) -> bool {
            let index = self.seen.len();
            self.seen.push(point);
            self.fail_at == Some(index)
        }
    }

    fn open_executor(temp: &TempImage, chunk: usize) -> ImageExecutor {
        let image = crate::image::ImageFile::open(&temp.0).unwrap();
        let identity = image.identity().clone();
        drop(image);
        ImageExecutor::open(
            &temp.0,
            &identity,
            ExecutorLimits {
                max_chunk_bytes: chunk,
            },
        )
        .unwrap()
    }

    #[test]
    fn locked_view_borrows_executor_identity_and_reads_without_writing() {
        let original: Vec<u8> = (0_u8..64).collect();
        let temp = TempImage::new(&original);
        let executor = open_executor(&temp, 8);
        let executor_token = executor.identity().stable_container_token();

        // The returned type is `LockedImageView<'a>` where `'a` is this executor borrow; moving
        // it outside the executor's lifetime is therefore rejected by the type system.
        let view = executor.locked_view(7).expect("clone locked read handle");
        assert_eq!(
            BoundedImageReader::len(&view),
            u64::try_from(original.len()).unwrap()
        );
        assert_eq!(BoundedImageReader::max_read_bytes(&view), 7);
        assert_eq!(
            view.image.identity().stable_container_token(),
            executor_token
        );
        assert_eq!(
            BoundedImageReader::read_exact_at(&view, 5, 7).unwrap(),
            original[5..12]
        );
        view.post_operation_revalidate().unwrap();
        drop(view);
        drop(executor);

        assert_eq!(fs::read(&temp.0).unwrap(), original);
    }

    #[test]
    fn locked_view_refuses_invalid_read_limit_without_writing() {
        let original = vec![0x5a; 64];
        let temp = TempImage::new(&original);
        let executor = open_executor(&temp, 8);
        assert!(matches!(
            executor.locked_view(0),
            Err(ExecutorError::Image(ImageError::InvalidReadLimit))
        ));
        drop(executor);
        assert_eq!(fs::read(&temp.0).unwrap(), original);
    }

    #[cfg(not(windows))]
    #[test]
    fn locked_view_refuses_container_length_change_under_advisory_lock() {
        let original = vec![0x33; 64];
        let temp = TempImage::new(&original);
        let executor = open_executor(&temp, 8);
        fs::OpenOptions::new()
            .append(true)
            .open(&temp.0)
            .unwrap()
            .write_all(&[0x44])
            .unwrap();
        assert!(matches!(
            executor.locked_view(8),
            Err(ExecutorError::IdentityMismatch)
        ));
    }

    #[test]
    fn relocation_copy_is_chunked_verified_durable_and_does_not_resize() {
        let original: Vec<u8> = (0_u8..64).collect();
        let temp = TempImage::new(&original);
        let executor = open_executor(&temp, 5);
        let relocation = Relocation {
            stream: crate::extent::StreamId(7),
            logical_offset: 0,
            source: crate::geometry::ByteRange {
                offset: 8,
                length: 16,
            },
            destination: crate::geometry::ByteRange {
                offset: 40,
                length: 16,
            },
        };
        let mut faults = RecordFaults {
            fail_at: None,
            seen: Vec::new(),
        };
        let evidence = executor
            .copy_relocations(&[relocation], &mut faults)
            .unwrap();
        assert_eq!(evidence.bytes_written, 16);
        assert!(evidence.sync_data_completed && evidence.sync_all_completed);
        drop(executor);
        let actual = fs::read(&temp.0).unwrap();
        assert_eq!(&actual[40..56], &original[8..24]);
        assert_eq!(actual.len(), original.len());
        assert_eq!(
            faults
                .seen
                .iter()
                .filter(|p| p.boundary == FaultBoundary::BeforeWrite)
                .count(),
            4
        );
    }

    #[test]
    fn every_write_cut_point_withholds_completion_and_retry_converges() {
        let original = vec![0x11; 64];
        let desired = OverlayWrite {
            offset: 16,
            bytes: vec![0x77; 13],
        };
        let discovery = {
            let temp = TempImage::new(&original);
            let executor = open_executor(&temp, 5);
            let mut recorder = RecordFaults {
                fail_at: None,
                seen: Vec::new(),
            };
            executor
                .apply_overlay_writes(
                    ExecutionKind::Rollback,
                    std::slice::from_ref(&desired),
                    &mut recorder,
                )
                .unwrap();
            recorder.seen
        };
        assert!(!discovery.is_empty());
        for cut in 0..discovery.len() {
            let temp = TempImage::new(&original);
            let executor = open_executor(&temp, 5);
            let mut fault = RecordFaults {
                fail_at: Some(cut),
                seen: Vec::new(),
            };
            let error = executor
                .apply_overlay_writes(
                    ExecutionKind::Rollback,
                    std::slice::from_ref(&desired),
                    &mut fault,
                )
                .unwrap_err();
            assert!(matches!(error, ExecutorError::InjectedFault { .. }));
            let mut retry = RecordFaults {
                fail_at: None,
                seen: Vec::new(),
            };
            let evidence = executor
                .apply_overlay_writes(
                    ExecutionKind::Rollback,
                    std::slice::from_ref(&desired),
                    &mut retry,
                )
                .unwrap();
            assert!(evidence.sync_all_completed);
            drop(executor);
            assert_eq!(&fs::read(&temp.0).unwrap()[16..29], desired.bytes);
        }
    }

    #[test]
    fn every_relocation_cut_point_is_retryable() {
        let original: Vec<u8> = (0_u8..64).collect();
        let relocation = Relocation {
            stream: crate::extent::StreamId(1),
            logical_offset: 0,
            source: crate::geometry::ByteRange {
                offset: 0,
                length: 13,
            },
            destination: crate::geometry::ByteRange {
                offset: 32,
                length: 13,
            },
        };
        let points = {
            let temp = TempImage::new(&original);
            let executor = open_executor(&temp, 5);
            let mut recorder = RecordFaults {
                fail_at: None,
                seen: Vec::new(),
            };
            executor
                .copy_relocations(&[relocation], &mut recorder)
                .unwrap();
            recorder.seen
        };
        for cut in 0..points.len() {
            let temp = TempImage::new(&original);
            let executor = open_executor(&temp, 5);
            let mut fault = RecordFaults {
                fail_at: Some(cut),
                seen: Vec::new(),
            };
            assert!(matches!(
                executor.copy_relocations(&[relocation], &mut fault),
                Err(ExecutorError::InjectedFault { .. })
            ));
            let mut retry = NoFault;
            executor
                .copy_relocations(&[relocation], &mut retry)
                .unwrap();
            drop(executor);
            assert_eq!(&fs::read(&temp.0).unwrap()[32..45], &original[..13]);
        }
    }

    #[test]
    fn rejects_zero_limit_identity_change_directory_and_out_of_range() {
        let temp = TempImage::new(&[0; 32]);
        let image = crate::image::ImageFile::open(&temp.0).unwrap();
        let identity = image.identity().clone();
        drop(image);
        assert!(matches!(
            ImageExecutor::open(&temp.0, &identity, ExecutorLimits { max_chunk_bytes: 0 }),
            Err(ExecutorError::InvalidChunkLimit)
        ));
        fs::OpenOptions::new()
            .append(true)
            .open(&temp.0)
            .unwrap()
            .write_all(b"x")
            .unwrap();
        assert!(matches!(
            ImageExecutor::open(&temp.0, &identity, ExecutorLimits::default()),
            Err(ExecutorError::IdentityMismatch)
        ));

        let temp = TempImage::new(&[0; 32]);
        let executor = open_executor(&temp, 8);
        let invalid = OverlayWrite {
            offset: 31,
            bytes: vec![1, 2],
        };
        assert!(matches!(
            executor.apply_overlay_writes(ExecutionKind::Rollback, &[invalid], &mut NoFault),
            Err(ExecutorError::RangeOutsideImage { .. })
        ));
        assert!(matches!(
            ImageExecutor::open(
                std::env::temp_dir(),
                executor.identity(),
                ExecutorLimits::default()
            ),
            Err(ExecutorError::IdentityMismatch | ExecutorError::Image(_))
        ));
    }

    #[test]
    fn exclusive_lock_rejects_a_second_executor() {
        let temp = TempImage::new(&[0; 32]);
        let image = crate::image::ImageFile::open(&temp.0).unwrap();
        let identity = image.identity().clone();
        drop(image);
        let first = ImageExecutor::open(&temp.0, &identity, ExecutorLimits::default()).unwrap();
        assert!(ImageExecutor::open(&temp.0, &identity, ExecutorLimits::default()).is_err());
        drop(first);
        assert!(ImageExecutor::open(&temp.0, &identity, ExecutorLimits::default()).is_ok());
    }

    #[test]
    fn exact_phase_gate_rejects_empty_subset_and_mixed_phase_writes() {
        fn reserved(offset: u64, byte: u8) -> ReservedWrite {
            ReservedWrite {
                reservation_kind: crate::geometry::ReservationKind::AllocationMetadata,
                write: OverlayWrite {
                    offset,
                    bytes: vec![byte; 4],
                },
            }
        }

        let expected = vec![reserved(8, 1), reserved(16, 2)];
        assert!(validate_exact_phase(&expected, &expected).is_ok());
        assert!(matches!(
            validate_exact_phase(&expected, &[]),
            Err(ExecutorError::IntentNotAuthorized)
        ));
        assert!(matches!(
            validate_exact_phase(&expected, &expected[..1]),
            Err(ExecutorError::IntentNotAuthorized)
        ));
        let mixed = vec![expected[0].clone(), reserved(24, 3)];
        assert!(matches!(
            validate_exact_phase(&expected, &mixed),
            Err(ExecutorError::IntentNotAuthorized)
        ));
    }

    #[test]
    fn prepared_plan_cannot_mutate_a_different_same_length_image() {
        let source = TempImage::new(&vec![0x11; 8192]);
        let substitute = TempImage::new(&vec![0x22; 8192]);
        let source_image = crate::image::ImageFile::open(&source.0).unwrap();
        let mut plan = crate::conversion::tests::prepared();
        plan.test_bind_regular_image(source_image.identity());
        drop(source_image);

        let executor = open_executor(&substitute, 512);
        let intent = plan
            .rollback_intent(crate::capsule::TransactionPhase::Relocating)
            .unwrap();
        assert!(matches!(
            executor.execute_rollback(&plan, intent),
            Err(ExecutorError::PlanImageMismatch)
        ));
        drop(executor);
        assert_eq!(fs::read(&substitute.0).unwrap(), vec![0x22; 8192]);
    }

    #[cfg(windows)]
    #[test]
    fn rejects_device_namespace_lexically_before_any_open() {
        let temp = TempImage::new(&[0; 32]);
        let image = crate::image::ImageFile::open(&temp.0).unwrap();
        let identity = image.identity().clone();
        drop(image);
        assert!(matches!(
            ImageExecutor::open(r"\\.\PhysicalDrive0", &identity, ExecutorLimits::default()),
            Err(ExecutorError::Image(ImageError::DeviceLikePath { .. }))
        ));
    }
}
