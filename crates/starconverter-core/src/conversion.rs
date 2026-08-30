//! Pure, image-only conversion transaction coordination.
//!
//! This module deliberately has no path, device, or mutation API. It validates preflight evidence,
//! composes normalized object, allocation, relocation, capsule, and overlay proofs, and emits
//! explicit intents for the internal regular-image executor. Filesystem serializers remain
//! external: filesystem-specific phase adapters must authorize complete, sector-aligned write sets
//! before this coordinator accepts them. Independent completion and verification evidence remains
//! mandatory at the corresponding transaction boundaries.

use std::fmt;

use sha2::{Digest, Sha256};

use crate::capsule::{
    CapsuleError, CapsuleIdentity, CapsuleLimits, HEADER_BYTES, TransactionPhase,
    append_generation, recover_capsule, scan_capsule,
};
use crate::executor::{ExecutedIntent, ExecutedRollback};
use crate::extent::{ExtentKind, Placement};
use crate::geometry::{
    ByteRange, DestinationReservation, LayoutError, LayoutLimits, LayoutPlan, RelocatedGraphError,
    Relocation, ReservationKind, SourceAllocation, relocate_object_graph,
    solve_layout_with_staging_exclusions_and_io_alignment,
};
use crate::object::{ObjectGraph, ObjectKind, StreamStorage};
use crate::overlay::{OverlayError, OverlayLimits, OverlayPlan, OverlayWrite};
use crate::phase::ActivationAuthorizedWrites;
use crate::recovery::{RecoveryBundle, RecoveryError, RecoveryLimits, encode_recovery_bundle};
use crate::verify::ManifestCommitment;
use crate::{AccessState, FileSystem, HealthState, SemanticFeature};

// This internal foundation remains unreachable from frontends until trusted production preflight
// creation and at least one destination serializer can mint activation authority.
mod activation_bytes;
mod prepared_envelope;
#[allow(dead_code)]
pub(crate) mod regular_image;

const CHECKPOINT_MAGIC: &[u8; 8] = b"SCORCH1\0";

/// Stable identity of the regular image container, separate from its changing byte contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageIdentity {
    pub instance: [u8; 32],
    pub image_bytes: u64,
}

impl ImageIdentity {
    pub(crate) fn from_regular_image(identity: &crate::image::ImageIdentity) -> Self {
        Self {
            instance: identity.stable_container_token(),
            image_bytes: identity.length(),
        }
    }
}

/// Independently established facts required before any conversion can be coordinated.
///
/// Fields are module-private so callers cannot manufacture clean/offline/complete evidence. A
/// filesystem-specific locked inspector must eventually feed the only constructor exposed by the
/// activation path.
///
/// ```compile_fail
/// use starconverter_core::conversion::{ImageIdentity, PreflightEvidence};
///
/// let _forged = PreflightEvidence {
///     image: ImageIdentity { instance: [0; 32], image_bytes: 1 },
/// };
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreflightEvidence {
    image: ImageIdentity,
    source_filesystem: FileSystem,
    source_evidence_digest: [u8; 32],
    source_manifest_commitment: ManifestCommitment,
    sector_bytes: u32,
    allocation_alignment: u64,
    inventory_complete: bool,
    allocation_map_complete: bool,
    health: HealthState,
    access: AccessState,
}

/// A fresh observation used to reject a swapped image or stale pre-activation evidence.
///
/// This is sealed to the module so a future locked-image observer, rather than an untrusted caller,
/// must establish it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservedImage {
    image: ImageIdentity,
    /// Required until activation; it may be absent after the target boot region is activated.
    source_evidence_digest: Option<[u8; 32]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreservationMethod {
    Native,
    /// Exact representation-specific semantics are retained by a versioned escrow serializer.
    Escrow {
        schema_version: u16,
        payload_digest: [u8; 32],
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeatureCompatibility {
    pub feature: SemanticFeature,
    pub method: PreservationMethod,
}

/// Target semantics explicitly claimed by the serializer/planner boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetCapabilities {
    pub filesystem: FileSystem,
    pub features: Vec<FeatureCompatibility>,
}

/// One serializer-produced replacement bound to the reservation that authorizes its range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservedWrite {
    pub reservation_kind: ReservationKind,
    pub write: OverlayWrite,
}

/// Opaque writes grouped by the durability boundary at which an executor may apply them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OpaqueWriteSets {
    pub target_staging: Vec<ReservedWrite>,
    pub backup_boot: Vec<ReservedWrite>,
    pub activation: Vec<ReservedWrite>,
    /// Exact source bytes restoring every target-staging range.
    pub target_staging_rollback: Vec<OverlayWrite>,
    /// Exact source bytes restoring every backup-boot range.
    pub backup_boot_rollback: Vec<OverlayWrite>,
    /// Exact source bytes restoring every activation range.
    pub activation_rollback: Vec<OverlayWrite>,
}

/// Complete caller input. Allocation evidence may include extra immovable filesystem metadata, but
/// every physical extent in `ObjectGraph` must have an exact corresponding allocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversionDraft {
    pub transaction_id: [u8; 16],
    pub preflight: PreflightEvidence,
    pub target: TargetCapabilities,
    pub source_allocations: Vec<SourceAllocation>,
    pub reservations: Vec<DestinationReservation>,
    /// Write phases authorized by a filesystem-specific, activation-ready serializer adapter.
    pub writes: ActivationAuthorizedWrites,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConversionLimits {
    pub layout: LayoutLimits,
    pub overlay: OverlayLimits,
    pub capsule: CapsuleLimits,
    pub max_feature_rules: usize,
    pub max_total_writes: usize,
    pub max_total_write_bytes: usize,
}

impl Default for ConversionLimits {
    fn default() -> Self {
        Self {
            layout: LayoutLimits::default(),
            overlay: OverlayLimits::default(),
            capsule: CapsuleLimits::default(),
            max_feature_rules: 64,
            max_total_writes: 2 * 1024 * 1024,
            max_total_write_bytes: 1024 * 1024 * 1024,
        }
    }
}

/// Expected facts an independent parser/verifier must prove after activation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpectedVerification {
    pub target_filesystem: FileSystem,
    pub object_graph_digest: [u8; 32],
    pub plan_digest: [u8; 32],
}

/// Expected identity of the immutable candidate overlay before any boot activation begins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpectedStagingVerification {
    pub target_filesystem: FileSystem,
    pub object_graph_digest: [u8; 32],
    pub plan_digest: [u8; 32],
    pub candidate_overlay_digest: [u8; 32],
}

/// Result of parsing and checking the immutable overlay through the target filesystem reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StagingVerificationEvidence {
    target_filesystem: FileSystem,
    parser_validated: bool,
    inventory_complete: bool,
    object_graph_digest: [u8; 32],
    plan_digest: [u8; 32],
    candidate_overlay_digest: [u8; 32],
}

/// Evidence acknowledging completion of one emitted intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhaseCompletion {
    image: ImageIdentity,
    plan_digest: [u8; 32],
    health: HealthState,
    access: AccessState,
}

/// Independent target reinspection evidence required for the `Verified` checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationEvidence {
    target_filesystem: FileSystem,
    inventory_complete: bool,
    object_graph_digest: [u8; 32],
    plan_digest: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RollbackCompletion {
    image: ImageIdentity,
    plan_digest: [u8; 32],
    /// Required after either source-visible boot write; digest must match the phase-specific intent.
    applied_rollback_digest: Option<[u8; 32]>,
    health: HealthState,
    access: AccessState,
}

/// Next externally executed operation. Every borrowed byte slice remains opaque to this module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionIntent<'a> {
    Reserve(&'a [DestinationReservation]),
    /// Copy payloads to the planned destinations and flush them; source ranges remain intact until
    /// activation/finalization. This intent never authorizes a destructive move.
    Relocate(&'a [Relocation]),
    StageTarget(&'a [ReservedWrite]),
    WriteBackupBoot(&'a [ReservedWrite]),
    VerifyStaging(ExpectedStagingVerification),
    Activate(&'a [ReservedWrite]),
    Verify(ExpectedVerification),
    Finalize,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RollbackIntent<'a> {
    /// No source-visible mutation has occurred; staging reservations may be abandoned.
    DiscardStaging,
    /// Source-visible boot bytes changed and these exact before-images must be restored and flushed.
    RestoreSource {
        writes: &'a [OverlayWrite],
        digest: [u8; 32],
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResumePoint<'a> {
    pub generation: u64,
    pub phase: TransactionPhase,
    pub next: TransactionIntent<'a>,
}

/// Validated immutable transaction plan. Methods only inspect or mutate caller-owned capsule bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedConversion {
    identity: CapsuleIdentity,
    preflight: PreflightEvidence,
    target_filesystem: FileSystem,
    target_features: Vec<FeatureCompatibility>,
    source_graph_digest: [u8; 32],
    target_graph_digest: [u8; 32],
    plan_digest: [u8; 32],
    candidate_overlay_digest: [u8; 32],
    relocation_rollback_digest: [u8; 32],
    staging_rollback_digest: [u8; 32],
    preactivation_rollback_digest: [u8; 32],
    full_rollback_digest: [u8; 32],
    reservations: Vec<DestinationReservation>,
    layout: LayoutPlan,
    writes: OpaqueWriteSets,
    candidate_overlay: OverlayPlan,
    relocation_rollback_overlay: OverlayPlan,
    staging_rollback_overlay: OverlayPlan,
    preactivation_rollback_overlay: OverlayPlan,
    full_rollback_overlay: OverlayPlan,
    recovery_payload: Vec<u8>,
    prepared_envelope: Vec<u8>,
    capsule_limits: CapsuleLimits,
}

impl PreparedConversion {
    /// Builds a deterministic plan from complete read-only evidence and activation-authorized
    /// serializer output.
    ///
    /// # Errors
    ///
    /// Refuses unknown/dirty/mounted evidence, incomplete inventories/allocation maps, unknown or
    /// same-format targets, uncovered source extents/features, invalid reservations/write sets,
    /// unsafe relocation geometry, resource cap exhaustion, and arithmetic overflow.
    #[allow(clippy::too_many_lines)]
    pub fn build(
        source_graph: &ObjectGraph,
        draft: ConversionDraft,
        limits: ConversionLimits,
    ) -> Result<Self, ConversionError> {
        Self::build_with_target_graph(source_graph, source_graph, draft, Vec::new(), limits)
    }

    /// Builds a conversion whose expected target graph includes every solved payload relocation.
    ///
    /// `relocation_destination_before_images` must contain exactly one source before-image for
    /// every solved relocation destination: no missing, extra, duplicate, shortened, or extended
    /// range is accepted. The group is sorted and bound only after layout solving. An independently
    /// supplied `target_graph` must be byte-for-byte equivalent to
    /// [`relocate_object_graph(source_graph, solved_layout)`]. This makes the source identity and
    /// expected activated target distinct commitments. Call [`Self::build`] for the ergonomic
    /// no-relocation case; it deliberately fails closed if relocation becomes necessary.
    ///
    /// # Errors
    ///
    /// In addition to [`Self::build`] errors, refuses target-graph disagreement and any incomplete
    /// or inexact relocation destination before-image group.
    #[allow(clippy::too_many_lines)]
    pub fn build_with_target_graph(
        source_graph: &ObjectGraph,
        target_graph: &ObjectGraph,
        draft: ConversionDraft,
        relocation_destination_before_images: Vec<OverlayWrite>,
        limits: ConversionLimits,
    ) -> Result<Self, ConversionError> {
        Self::build_with_projected_target_graph(
            source_graph,
            source_graph,
            target_graph,
            draft,
            relocation_destination_before_images,
            limits,
        )
    }

    /// Builds a conversion across a semantic filesystem projection and solved payload relocation.
    ///
    /// `projected_target_graph` is the destination-format object graph before physical payload
    /// movement. Its file-data extents must therefore still identify the source allocations used by
    /// the solver. `target_graph` must equal that projection after applying the sealed layout. The
    /// durable envelope commits the independently authenticated source graph and the final target
    /// graph; the projection is a checked construction witness and is never accepted as recovery
    /// authority by itself.
    ///
    /// Call [`Self::build_with_target_graph`] when the conversion changes placement but not graph
    /// semantics, or [`Self::build`] when neither changes.
    ///
    /// # Errors
    ///
    /// In addition to [`Self::build_with_target_graph`] errors, refuses a projection whose physical
    /// file-data extents cannot accept the solved relocation layout.
    #[allow(clippy::too_many_lines)]
    pub fn build_with_projected_target_graph(
        source_graph: &ObjectGraph,
        projected_target_graph: &ObjectGraph,
        target_graph: &ObjectGraph,
        mut draft: ConversionDraft,
        mut relocation_destination_before_images: Vec<OverlayWrite>,
        limits: ConversionLimits,
    ) -> Result<Self, ConversionError> {
        validate_limits(limits)?;
        scan_capsule(&[], limits.capsule)?;
        let (authorized_filesystem, writes) = draft.writes.into_parts();
        if authorized_filesystem != draft.target.filesystem {
            return Err(ConversionError::ActivationAuthorizationMismatch {
                authorized: authorized_filesystem,
                target: draft.target.filesystem,
            });
        }
        validate_preflight(source_graph, draft.preflight, draft.target.filesystem)?;
        validate_features(source_graph, &mut draft.target, limits.max_feature_rules)?;
        validate_source_allocations(source_graph, &draft.source_allocations)?;
        validate_required_reservations(&draft.reservations)?;
        validate_write_caps(&writes, limits)?;

        draft
            .reservations
            .sort_unstable_by_key(reservation_sort_key);
        let mut writes = writes;
        writes
            .target_staging
            .sort_unstable_by_key(reserved_write_sort_key);
        writes
            .backup_boot
            .sort_unstable_by_key(reserved_write_sort_key);
        writes
            .activation
            .sort_unstable_by_key(reserved_write_sort_key);
        writes
            .target_staging_rollback
            .sort_unstable_by_key(|write| write.offset);
        writes
            .backup_boot_rollback
            .sort_unstable_by_key(|write| write.offset);
        writes
            .activation_rollback
            .sort_unstable_by_key(|write| write.offset);
        validate_writes_against_reservations(&writes, &draft.reservations)?;
        validate_rollback_pairing(&writes)?;

        let (live_allocations, staging_exclusions) =
            partition_source_allocations(source_graph, &draft.source_allocations);
        let layout = solve_layout_with_staging_exclusions_and_io_alignment(
            draft.preflight.image.image_bytes,
            draft.preflight.allocation_alignment,
            u64::from(draft.preflight.sector_bytes),
            live_allocations,
            draft.reservations.clone(),
            staging_exclusions,
            limits.layout,
        )?;
        let relocated_target = relocate_object_graph(projected_target_graph, &layout)?;
        if &relocated_target != target_graph {
            return Err(ConversionError::TargetGraphMismatch);
        }
        validate_relocation_before_images(
            &layout,
            &mut relocation_destination_before_images,
            &writes,
            limits,
        )?;
        let candidate_overlay = OverlayPlan::build(
            draft.preflight.image.image_bytes,
            draft.preflight.sector_bytes,
            final_writes(&writes),
            limits.overlay,
        )?;
        let relocation_rollback_overlay = OverlayPlan::build(
            draft.preflight.image.image_bytes,
            draft.preflight.sector_bytes,
            relocation_destination_before_images.clone(),
            limits.overlay,
        )?;
        let staging_rollback_overlay = OverlayPlan::build(
            draft.preflight.image.image_bytes,
            draft.preflight.sector_bytes,
            staging_rollback_writes(&relocation_destination_before_images, &writes),
            limits.overlay,
        )?;
        let preactivation_rollback_overlay = OverlayPlan::build(
            draft.preflight.image.image_bytes,
            draft.preflight.sector_bytes,
            preactivation_rollback_writes(&relocation_destination_before_images, &writes),
            limits.overlay,
        )?;
        let full_rollback_overlay = OverlayPlan::build(
            draft.preflight.image.image_bytes,
            draft.preflight.sector_bytes,
            full_rollback_writes(&relocation_destination_before_images, &writes),
            limits.overlay,
        )?;

        let source_graph_digest = digest_graph(source_graph);
        let target_graph_digest = digest_graph(target_graph);
        let plan_digest = digest_plan(
            draft.preflight,
            draft.target.filesystem,
            &draft.target.features,
            &draft.reservations,
            &layout,
            &writes,
            source_graph_digest,
            target_graph_digest,
            &relocation_destination_before_images,
        );
        let staging_rollback_digest = digest_overlay_writes(staging_rollback_overlay.writes());
        let relocation_rollback_digest =
            digest_overlay_writes(relocation_rollback_overlay.writes());
        let preactivation_rollback_digest =
            digest_overlay_writes(preactivation_rollback_overlay.writes());
        let full_rollback_digest = digest_overlay_writes(full_rollback_overlay.writes());
        let recovery_payload = encode_recovery_bundle(
            &RecoveryBundle {
                plan_digest,
                relocation_destinations: relocation_destination_before_images.clone(),
                target_staging: writes.target_staging_rollback.clone(),
                backup_boot: writes.backup_boot_rollback.clone(),
                activation: writes.activation_rollback.clone(),
            },
            RecoveryLimits {
                max_writes: limits.max_total_writes,
                max_bytes: limits.max_total_write_bytes,
            },
        )?;
        let candidate_overlay_digest = digest_overlay_writes(candidate_overlay.writes());
        let identity = CapsuleIdentity {
            transaction_id: draft.transaction_id,
            source_digest: digest_source_identity(draft.preflight, source_graph_digest),
        };

        let mut prepared = Self {
            identity,
            preflight: draft.preflight,
            target_filesystem: draft.target.filesystem,
            target_features: draft.target.features,
            source_graph_digest,
            target_graph_digest,
            plan_digest,
            candidate_overlay_digest,
            relocation_rollback_digest,
            staging_rollback_digest,
            preactivation_rollback_digest,
            full_rollback_digest,
            reservations: draft.reservations,
            layout,
            writes,
            candidate_overlay,
            relocation_rollback_overlay,
            staging_rollback_overlay,
            preactivation_rollback_overlay,
            full_rollback_overlay,
            recovery_payload,
            prepared_envelope: Vec::new(),
            capsule_limits: limits.capsule,
        };
        prepared.refresh_durable_envelope()?;
        Ok(prepared)
    }

    #[must_use]
    pub const fn identity(&self) -> CapsuleIdentity {
        self.identity
    }

    #[must_use]
    pub const fn graph_digest(&self) -> [u8; 32] {
        self.source_graph_digest
    }

    /// Digest of the graph expected after applying the sealed relocation layout.
    #[must_use]
    pub const fn target_graph_digest(&self) -> [u8; 32] {
        self.target_graph_digest
    }

    #[must_use]
    pub const fn plan_digest(&self) -> [u8; 32] {
        self.plan_digest
    }

    pub(crate) const fn source_manifest_commitment(&self) -> ManifestCommitment {
        self.preflight.source_manifest_commitment
    }

    /// Proves that the executor's pinned regular file is the container used by trusted preflight.
    pub(crate) fn matches_regular_image(&self, identity: &crate::image::ImageIdentity) -> bool {
        self.preflight.image == ImageIdentity::from_regular_image(identity)
    }

    #[cfg(test)]
    pub(crate) fn test_bind_regular_image(
        &mut self,
        identity: &crate::image::ImageIdentity,
        source_evidence_digest: [u8; 32],
    ) {
        self.preflight.image = ImageIdentity::from_regular_image(identity);
        self.preflight.source_evidence_digest = source_evidence_digest;
        self.plan_digest = digest_plan(
            self.preflight,
            self.target_filesystem,
            &self.target_features,
            &self.reservations,
            &self.layout,
            &self.writes,
            self.source_graph_digest,
            self.target_graph_digest,
            self.relocation_rollback_overlay.writes(),
        );
        self.identity.source_digest =
            digest_source_identity(self.preflight, self.source_graph_digest);
        let recovery_write_count = self
            .relocation_rollback_overlay
            .writes()
            .len()
            .saturating_add(self.writes.target_staging_rollback.len())
            .saturating_add(self.writes.backup_boot_rollback.len())
            .saturating_add(self.writes.activation_rollback.len());
        let recovery_bytes = self
            .relocation_rollback_overlay
            .writes()
            .iter()
            .chain(&self.writes.target_staging_rollback)
            .chain(&self.writes.backup_boot_rollback)
            .chain(&self.writes.activation_rollback)
            .fold(0_usize, |total, write| {
                total.saturating_add(write.bytes.len())
            });
        self.recovery_payload = encode_recovery_bundle(
            &RecoveryBundle {
                plan_digest: self.plan_digest,
                relocation_destinations: self.relocation_rollback_overlay.writes().to_vec(),
                target_staging: self.writes.target_staging_rollback.clone(),
                backup_boot: self.writes.backup_boot_rollback.clone(),
                activation: self.writes.activation_rollback.clone(),
            },
            RecoveryLimits {
                max_writes: recovery_write_count.max(1),
                max_bytes: recovery_bytes.max(1),
            },
        )
        .expect("test regular image recovery payload remains bounded");
        self.refresh_durable_envelope()
            .expect("test regular image durable envelope remains bounded");
    }

    #[must_use]
    pub const fn candidate_overlay_digest(&self) -> [u8; 32] {
        self.candidate_overlay_digest
    }

    #[must_use]
    pub const fn layout(&self) -> &LayoutPlan {
        &self.layout
    }

    #[must_use]
    pub const fn candidate_overlay(&self) -> &OverlayPlan {
        &self.candidate_overlay
    }

    /// Exact source bytes for every relocation destination, sealed after layout solving.
    #[must_use]
    pub const fn relocation_rollback_overlay(&self) -> &OverlayPlan {
        &self.relocation_rollback_overlay
    }

    #[must_use]
    pub const fn staging_rollback_overlay(&self) -> &OverlayPlan {
        &self.staging_rollback_overlay
    }

    #[must_use]
    pub const fn backup_boot_rollback_overlay(&self) -> &OverlayPlan {
        &self.preactivation_rollback_overlay
    }

    #[must_use]
    pub const fn rollback_overlay(&self) -> &OverlayPlan {
        &self.full_rollback_overlay
    }

    /// Exact staging group accepted by the regular-image executor.
    #[must_use]
    pub(crate) fn target_staging_writes(&self) -> &[ReservedWrite] {
        &self.writes.target_staging
    }

    /// Exact backup-boot group accepted by the regular-image executor.
    #[must_use]
    pub(crate) fn backup_boot_writes(&self) -> &[ReservedWrite] {
        &self.writes.backup_boot
    }

    /// Exact primary activation group accepted by the regular-image executor.
    #[must_use]
    pub(crate) fn activation_writes(&self) -> &[ReservedWrite] {
        &self.writes.activation
    }

    #[must_use]
    pub(crate) fn backup_boot_before_images(&self) -> &[OverlayWrite] {
        &self.writes.backup_boot_rollback
    }

    #[must_use]
    pub(crate) fn activation_before_images(&self) -> &[OverlayWrite] {
        &self.writes.activation_rollback
    }

    /// Before-images that conservatively reconstruct the original source byte view at a durable
    /// checkpoint, including the possibly torn next source-visible write group.
    pub(crate) fn observation_rollback_writes(
        &self,
        phase: TransactionPhase,
    ) -> Option<&[OverlayWrite]> {
        match phase {
            TransactionPhase::Discovered
            | TransactionPhase::Finalized
            | TransactionPhase::RolledBack => None,
            TransactionPhase::Reserved if self.layout.relocations.is_empty() => None,
            TransactionPhase::Reserved => Some(self.relocation_rollback_overlay.writes()),
            TransactionPhase::Relocating => Some(self.staging_rollback_overlay.writes()),
            TransactionPhase::TargetStaged => Some(self.preactivation_rollback_overlay.writes()),
            TransactionPhase::BackupBootWritten
            | TransactionPhase::Activated
            | TransactionPhase::Verified => Some(self.full_rollback_overlay.writes()),
        }
    }

    /// Versioned exact before-images written into the first durable capsule generation.
    #[must_use]
    pub fn recovery_payload(&self) -> &[u8] {
        &self.recovery_payload
    }

    fn refresh_durable_envelope(&mut self) -> Result<(), ConversionError> {
        let limits = prepared_envelope::PreparedEnvelopeLimits::default();
        let encoded = prepared_envelope::encode_prepared_envelope(self, limits)?;
        validate_initial_capsule_generation(encoded.len(), self.capsule_limits)?;
        self.prepared_envelope = encoded;
        Ok(())
    }

    /// Reconstructs complete execution and rollback authority from a new-format capsule alone.
    /// Legacy recovery-only capsules are deliberately refused without their external plan.
    pub(crate) fn from_restart_capsule(
        capsule: &[u8],
        policy: CapsuleLimits,
    ) -> Result<Self, ConversionError> {
        let view = recover_capsule(capsule, policy)?;
        let first = view
            .generations()
            .first()
            .ok_or(ConversionError::CapsuleNotStarted)?;
        let decoded = prepared_envelope::decode_prepared_envelope(
            first.payload,
            prepared_envelope::PreparedEnvelopeLimits::default(),
        )?;
        let mut prepared = decoded.prepared;
        if prepared.capsule_limits.max_capsule_bytes > policy.max_capsule_bytes
            || prepared.capsule_limits.max_generation_bytes > policy.max_generation_bytes
            || prepared.capsule_limits.max_generations > policy.max_generations
        {
            return Err(ConversionError::EnvelopeRaisesCapsuleLimits);
        }
        if first.identity != prepared.identity {
            return Err(ConversionError::TransactionIdentityChanged);
        }
        prepared.prepared_envelope = first.payload.to_vec();
        prepared.resume_without_observation(capsule)?;
        Ok(prepared)
    }

    #[must_use]
    pub const fn expected_verification(&self) -> ExpectedVerification {
        ExpectedVerification {
            target_filesystem: self.target_filesystem,
            object_graph_digest: self.target_graph_digest,
            plan_digest: self.plan_digest,
        }
    }

    #[must_use]
    pub const fn expected_staging_verification(&self) -> ExpectedStagingVerification {
        ExpectedStagingVerification {
            target_filesystem: self.target_filesystem,
            object_graph_digest: self.target_graph_digest,
            plan_digest: self.plan_digest,
            candidate_overlay_digest: self.candidate_overlay_digest,
        }
    }

    /// Starts a capsule with a source-bound `Discovered` checkpoint.
    ///
    /// # Errors
    ///
    /// Refuses a nonempty capsule, changed/stale image evidence, or capsule cap/framing failures.
    pub fn begin_capsule(
        &self,
        capsule: &mut Vec<u8>,
        observed: ObservedImage,
    ) -> Result<(), ConversionError> {
        if !capsule.is_empty() {
            return Err(ConversionError::CapsuleAlreadyStarted);
        }
        self.validate_observed(observed, true)?;
        append_generation(
            capsule,
            self.identity,
            TransactionPhase::Discovered,
            &self.prepared_envelope,
            self.capsule_limits,
        )?;
        Ok(())
    }

    /// Recovers an interrupted transaction and returns its next bounded, non-I/O intent.
    ///
    /// # Errors
    ///
    /// Refuses missing/corrupt capsules, transaction/plan disagreement, or changed/stale images.
    pub fn resume<'a>(
        &'a self,
        capsule: &[u8],
        observed: ObservedImage,
    ) -> Result<ResumePoint<'a>, ConversionError> {
        let resumed = self.resume_without_observation(capsule)?;
        if self.is_legacy_capsule(capsule)? {
            return Err(ConversionError::LegacyCapsuleRollbackOnly);
        }
        let require_source = phase_requires_source_evidence(resumed.phase);
        self.validate_observed(observed, require_source)?;
        Ok(resumed)
    }

    /// Validates capsule framing and its exact plan binding before a locked coordinator constructs
    /// a fresh observation of the current image bytes. This deliberately remains crate-private:
    /// callers must still pass the resulting checkpoint through [`Self::resume`] before any intent
    /// is authorized.
    pub(crate) fn resume_without_observation<'a>(
        &'a self,
        capsule: &[u8],
    ) -> Result<ResumePoint<'a>, ConversionError> {
        let view = recover_capsule(capsule, self.capsule_limits)?;
        let newest = view.newest().ok_or(ConversionError::CapsuleNotStarted)?;
        if newest.identity != self.identity {
            return Err(ConversionError::TransactionIdentityChanged);
        }
        let first = view
            .generations()
            .first()
            .ok_or(ConversionError::CapsuleNotStarted)?;
        if first.payload != self.prepared_envelope && first.payload != self.recovery_payload {
            return Err(ConversionError::PlanChanged);
        }
        if newest.generation != 0 && newest.payload != self.checkpoint_payload() {
            return Err(ConversionError::PlanChanged);
        }
        Ok(ResumePoint {
            generation: newest.generation,
            phase: newest.phase,
            next: self.intent_after(newest.phase),
        })
    }

    fn is_legacy_capsule(&self, capsule: &[u8]) -> Result<bool, ConversionError> {
        let view = recover_capsule(capsule, self.capsule_limits)?;
        let first = view
            .generations()
            .first()
            .ok_or(ConversionError::CapsuleNotStarted)?;
        Ok(first.payload == self.recovery_payload)
    }

    fn resume_for_rollback<'a>(
        &'a self,
        capsule: &[u8],
        observed: ObservedImage,
    ) -> Result<ResumePoint<'a>, ConversionError> {
        let resumed = self.resume_without_observation(capsule)?;
        self.validate_observed(observed, phase_requires_source_evidence(resumed.phase))?;
        Ok(resumed)
    }

    /// Records completion of exactly the next phase; this never executes the emitted intent.
    ///
    /// # Errors
    ///
    /// Refuses skipped phases, stale completion evidence, invalid verification, or capsule errors.
    fn record_phase(
        &self,
        capsule: &mut Vec<u8>,
        observed: ObservedImage,
        next: TransactionPhase,
        completion: PhaseCompletion,
        staging_verification: Option<StagingVerificationEvidence>,
        verification: Option<VerificationEvidence>,
    ) -> Result<(), ConversionError> {
        let current = self.resume(capsule, observed)?;
        let validated_bytes = recover_capsule(capsule, self.capsule_limits)?.validated_bytes();
        let expected = next_phase(current.phase).ok_or(ConversionError::TerminalPhase {
            phase: current.phase,
        })?;
        if next != expected {
            return Err(ConversionError::UnexpectedPhase {
                expected,
                actual: next,
            });
        }
        self.validate_completion(completion)?;
        if next == TransactionPhase::BackupBootWritten {
            let evidence =
                staging_verification.ok_or(ConversionError::StagingVerificationRequired)?;
            self.validate_staging_verification(evidence)?;
        } else if staging_verification.is_some() {
            return Err(ConversionError::UnexpectedStagingVerificationEvidence);
        }
        if next == TransactionPhase::Verified {
            let evidence = verification.ok_or(ConversionError::VerificationRequired)?;
            self.validate_verification(evidence)?;
        } else if verification.is_some() {
            return Err(ConversionError::UnexpectedVerificationEvidence);
        }
        capsule.truncate(validated_bytes);
        append_generation(
            capsule,
            self.identity,
            next,
            &self.checkpoint_payload(),
            self.capsule_limits,
        )?;
        Ok(())
    }

    /// Records the pure reservation checkpoint for the locked regular-image coordinator.
    #[allow(dead_code)]
    pub(crate) fn record_reservation(
        &self,
        capsule: &mut Vec<u8>,
        observed: ObservedImage,
    ) -> Result<(), ConversionError> {
        self.record_phase(
            capsule,
            observed,
            TransactionPhase::Reserved,
            PhaseCompletion {
                image: self.preflight.image,
                plan_digest: self.plan_digest,
                health: self.preflight.health,
                access: self.preflight.access,
            },
            None,
            None,
        )
    }

    /// Advances one mutating phase only from opaque executor evidence bound to this exact plan and
    /// regular-image container.
    ///
    /// # Errors
    ///
    /// Refuses evidence from another plan/container, evidence without both flush barriers, an
    /// unexpected phase, stale observation, or invalid staging-verification evidence.
    pub fn record_execution(
        &self,
        capsule: &mut Vec<u8>,
        observed: ObservedImage,
        executed: ExecutedIntent,
        staging_verification: Option<StagingVerificationEvidence>,
    ) -> Result<(), ConversionError> {
        let (evidence, plan_digest, image_instance, completed_phase) = executed.into_checkpoint();
        if plan_digest != self.plan_digest
            || image_instance != self.preflight.image.instance
            || !evidence.sync_data_completed()
            || !evidence.sync_all_completed()
        {
            return Err(ConversionError::InvalidExecutionEvidence);
        }
        self.record_phase(
            capsule,
            observed,
            completed_phase,
            PhaseCompletion {
                image: self.preflight.image,
                plan_digest: self.plan_digest,
                health: self.preflight.health,
                access: self.preflight.access,
            },
            staging_verification,
            None,
        )
    }

    /// Durably records an independently inspected activated target.
    ///
    /// This remains crate-private because only the locked regular-image coordinator may construct
    /// verification evidence from the exact image handle that owns the mutation lease.
    pub(crate) fn record_verification(
        &self,
        capsule: &mut Vec<u8>,
        observed: ObservedImage,
        evidence: VerificationEvidence,
    ) -> Result<(), ConversionError> {
        self.record_phase(
            capsule,
            observed,
            TransactionPhase::Verified,
            PhaseCompletion {
                image: self.preflight.image,
                plan_digest: self.plan_digest,
                health: self.preflight.health,
                access: self.preflight.access,
            },
            None,
            Some(evidence),
        )
    }

    /// Accepts the already-verified target and crosses the rollback boundary.
    ///
    /// The coordinator must freshly re-audit the exact target bytes immediately before calling
    /// this crate-private transition; callers outside the core cannot mint finalization authority.
    pub(crate) fn record_finalization(
        &self,
        capsule: &mut Vec<u8>,
        observed: ObservedImage,
    ) -> Result<(), ConversionError> {
        self.record_phase(
            capsule,
            observed,
            TransactionPhase::Finalized,
            PhaseCompletion {
                image: self.preflight.image,
                plan_digest: self.plan_digest,
                health: self.preflight.health,
                access: self.preflight.access,
            },
            None,
            None,
        )
    }

    /// Authorizes the backup-boot write intent only after the staged target overlay independently
    /// parses and normalizes to the expected complete graph.
    ///
    /// # Errors
    ///
    /// Refuses any phase except `TargetStaged`, stale image/capsule evidence, or mismatched parser
    /// and candidate-overlay verification.
    pub fn authorize_backup_boot<'a>(
        &'a self,
        capsule: &[u8],
        observed: ObservedImage,
        evidence: StagingVerificationEvidence,
    ) -> Result<TransactionIntent<'a>, ConversionError> {
        let current = self.resume(capsule, observed)?;
        if current.phase != TransactionPhase::TargetStaged {
            return Err(ConversionError::StagingVerificationNotExpected {
                phase: current.phase,
            });
        }
        self.validate_staging_verification(evidence)?;
        Ok(TransactionIntent::WriteBackupBoot(&self.writes.backup_boot))
    }

    /// Returns the conservative rollback operation for a durable checkpoint. Because a checkpoint
    /// records the last completed group, restoration also covers the possibly torn *next*
    /// source-visible group. Reapplying exact before-images to an untouched range is harmless.
    /// Finalization is the irreversible acceptance boundary; finalized or already rolled-back
    /// capsules refuse.
    ///
    /// # Errors
    ///
    /// Returns [`ConversionError::RollbackBoundaryCrossed`] after finalization or rollback.
    pub fn rollback_intent(
        &self,
        phase: TransactionPhase,
    ) -> Result<RollbackIntent<'_>, ConversionError> {
        match phase {
            TransactionPhase::Discovered => Ok(RollbackIntent::DiscardStaging),
            TransactionPhase::Reserved if self.layout.relocations.is_empty() => {
                Ok(RollbackIntent::DiscardStaging)
            }
            TransactionPhase::Reserved => Ok(RollbackIntent::RestoreSource {
                writes: self.relocation_rollback_overlay.writes(),
                digest: self.relocation_rollback_digest,
            }),
            TransactionPhase::Relocating => Ok(RollbackIntent::RestoreSource {
                writes: self.staging_rollback_overlay.writes(),
                digest: self.staging_rollback_digest,
            }),
            TransactionPhase::TargetStaged => Ok(RollbackIntent::RestoreSource {
                writes: self.preactivation_rollback_overlay.writes(),
                digest: self.preactivation_rollback_digest,
            }),
            TransactionPhase::BackupBootWritten
            | TransactionPhase::Activated
            | TransactionPhase::Verified => Ok(RollbackIntent::RestoreSource {
                writes: self.full_rollback_overlay.writes(),
                digest: self.full_rollback_digest,
            }),
            TransactionPhase::Finalized | TransactionPhase::RolledBack => {
                Err(ConversionError::RollbackBoundaryCrossed { phase })
            }
        }
    }

    /// Records externally completed rollback evidence without writing the image.
    ///
    /// # Errors
    ///
    /// Refuses stale identity/plan evidence, incorrect restored bytes, or a crossed boundary.
    fn record_rollback(
        &self,
        capsule: &mut Vec<u8>,
        observed: ObservedImage,
        completion: RollbackCompletion,
    ) -> Result<(), ConversionError> {
        let current = self.resume_for_rollback(capsule, observed)?;
        // Rollback completion is accepted only after the raw, current image again hashes to the
        // sealed source view. This remains mandatory even when the pre-rollback phase no longer
        // required source evidence (Activated or Verified).
        self.validate_observed(observed, true)?;
        let validated_bytes = recover_capsule(capsule, self.capsule_limits)?.validated_bytes();
        let intent = self.rollback_intent(current.phase)?;
        self.validate_common_completion(
            completion.image,
            completion.plan_digest,
            completion.health,
            completion.access,
        )?;
        match intent {
            RollbackIntent::DiscardStaging if completion.applied_rollback_digest.is_none() => {}
            RollbackIntent::RestoreSource { digest, .. }
                if completion.applied_rollback_digest == Some(digest) => {}
            _ => return Err(ConversionError::InvalidRollbackEvidence),
        }
        capsule.truncate(validated_bytes);
        append_generation(
            capsule,
            self.identity,
            TransactionPhase::RolledBack,
            &self.checkpoint_payload(),
            self.capsule_limits,
        )?;
        Ok(())
    }

    /// Records rollback only from opaque executor evidence bound to this plan and container.
    ///
    /// # Errors
    ///
    /// Refuses evidence from another plan/container, missing durable restoration evidence, stale
    /// observations, invalid restoration digests, or a crossed rollback boundary.
    pub fn record_executed_rollback(
        &self,
        capsule: &mut Vec<u8>,
        observed: ObservedImage,
        executed: ExecutedRollback,
    ) -> Result<(), ConversionError> {
        let (restored_source, evidence, plan_digest, image_instance, rollback_digest) =
            executed.into_checkpoint();
        let durable = evidence.as_ref().map_or_else(
            || !restored_source && rollback_digest.is_none(),
            |evidence| {
                restored_source
                    && evidence.kind() == crate::executor::ExecutionKind::Rollback
                    && evidence.sync_data_completed()
                    && evidence.sync_all_completed()
                    && rollback_digest.is_some()
            },
        );
        if !durable
            || plan_digest != self.plan_digest
            || image_instance != self.preflight.image.instance
        {
            return Err(ConversionError::InvalidExecutionEvidence);
        }
        self.record_rollback(
            capsule,
            observed,
            RollbackCompletion {
                image: self.preflight.image,
                plan_digest: self.plan_digest,
                applied_rollback_digest: rollback_digest,
                health: self.preflight.health,
                access: self.preflight.access,
            },
        )
    }

    fn intent_after(&self, phase: TransactionPhase) -> TransactionIntent<'_> {
        match phase {
            TransactionPhase::Discovered => TransactionIntent::Reserve(&self.reservations),
            TransactionPhase::Reserved => TransactionIntent::Relocate(&self.layout.relocations),
            TransactionPhase::Relocating => {
                TransactionIntent::StageTarget(&self.writes.target_staging)
            }
            TransactionPhase::TargetStaged => {
                TransactionIntent::VerifyStaging(self.expected_staging_verification())
            }
            TransactionPhase::BackupBootWritten => {
                TransactionIntent::Activate(&self.writes.activation)
            }
            TransactionPhase::Activated => TransactionIntent::Verify(self.expected_verification()),
            TransactionPhase::Verified => TransactionIntent::Finalize,
            TransactionPhase::Finalized | TransactionPhase::RolledBack => TransactionIntent::None,
        }
    }

    fn checkpoint_payload(&self) -> [u8; 40] {
        let mut payload = [0_u8; 40];
        payload[..8].copy_from_slice(CHECKPOINT_MAGIC);
        payload[8..].copy_from_slice(&self.plan_digest);
        payload
    }

    fn validate_observed(
        &self,
        observed: ObservedImage,
        require_source: bool,
    ) -> Result<(), ConversionError> {
        if observed.image != self.preflight.image {
            return Err(ConversionError::ImageIdentityChanged);
        }
        if require_source
            && observed.source_evidence_digest != Some(self.preflight.source_evidence_digest)
        {
            return Err(ConversionError::StaleSourceEvidence);
        }
        Ok(())
    }

    fn validate_completion(&self, completion: PhaseCompletion) -> Result<(), ConversionError> {
        self.validate_common_completion(
            completion.image,
            completion.plan_digest,
            completion.health,
            completion.access,
        )
    }

    fn validate_common_completion(
        &self,
        image: ImageIdentity,
        plan_digest: [u8; 32],
        health: HealthState,
        access: AccessState,
    ) -> Result<(), ConversionError> {
        if image != self.preflight.image {
            return Err(ConversionError::ImageIdentityChanged);
        }
        if plan_digest != self.plan_digest {
            return Err(ConversionError::PlanChanged);
        }
        require_clean_offline(health, access)
    }

    fn validate_verification(&self, evidence: VerificationEvidence) -> Result<(), ConversionError> {
        if !evidence.inventory_complete {
            return Err(ConversionError::VerificationInventoryIncomplete);
        }
        let expected = self.expected_verification();
        if evidence.target_filesystem != expected.target_filesystem
            || evidence.object_graph_digest != expected.object_graph_digest
            || evidence.plan_digest != expected.plan_digest
        {
            return Err(ConversionError::VerificationMismatch);
        }
        Ok(())
    }

    fn validate_staging_verification(
        &self,
        evidence: StagingVerificationEvidence,
    ) -> Result<(), ConversionError> {
        if !evidence.parser_validated || !evidence.inventory_complete {
            return Err(ConversionError::StagingVerificationIncomplete);
        }
        let expected = self.expected_staging_verification();
        if evidence.target_filesystem != expected.target_filesystem
            || evidence.object_graph_digest != expected.object_graph_digest
            || evidence.plan_digest != expected.plan_digest
            || evidence.candidate_overlay_digest != expected.candidate_overlay_digest
        {
            return Err(ConversionError::StagingVerificationMismatch);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum ConversionError {
    InvalidLimit {
        field: &'static str,
    },
    UnknownFilesystem,
    SameFilesystem,
    ActivationAuthorizationMismatch {
        authorized: FileSystem,
        target: FileSystem,
    },
    ImageLengthMismatch {
        graph: u64,
        evidence: u64,
    },
    InventoryIncomplete,
    AllocationMapIncomplete,
    HealthNotClean {
        actual: HealthState,
    },
    AccessNotOffline {
        actual: AccessState,
    },
    InvalidSectorSize {
        sector_bytes: u32,
    },
    InvalidAlignment {
        alignment: u64,
    },
    FeatureRuleLimitExceeded {
        actual: usize,
        maximum: usize,
    },
    DuplicateFeatureRule {
        feature: SemanticFeature,
    },
    MissingFeatureRule {
        feature: SemanticFeature,
    },
    FeatureNotPresent {
        feature: SemanticFeature,
    },
    UnsupportedNativeFeature {
        feature: SemanticFeature,
        target: FileSystem,
    },
    InvalidEscrowRule {
        feature: SemanticFeature,
    },
    MissingGraphAllocation {
        stream: crate::extent::StreamId,
        logical_offset: u64,
    },
    UnsafeMovableAllocation {
        stream: crate::extent::StreamId,
        logical_offset: u64,
    },
    MissingReservation {
        kind: ReservationKind,
    },
    WriteLimitExceeded {
        actual: usize,
        maximum: usize,
    },
    WriteByteLimitExceeded {
        actual: u64,
        maximum: usize,
    },
    EmptyWriteSet {
        set: &'static str,
    },
    WriteNotReserved {
        offset: u64,
        kind: ReservationKind,
    },
    InvalidWritePhase {
        set: &'static str,
        kind: ReservationKind,
    },
    RollbackRangeMismatch,
    RelocationBeforeImageRangeMismatch,
    TargetGraphMismatch,
    CapsuleAlreadyStarted,
    CapsuleNotStarted,
    LegacyCapsuleRollbackOnly,
    EnvelopeRaisesCapsuleLimits,
    TransactionIdentityChanged,
    ImageIdentityChanged,
    StaleSourceEvidence,
    PlanChanged,
    TerminalPhase {
        phase: TransactionPhase,
    },
    UnexpectedPhase {
        expected: TransactionPhase,
        actual: TransactionPhase,
    },
    VerificationRequired,
    StagingVerificationRequired,
    UnexpectedStagingVerificationEvidence,
    StagingVerificationNotExpected {
        phase: TransactionPhase,
    },
    StagingVerificationIncomplete,
    StagingVerificationMismatch,
    UnexpectedVerificationEvidence,
    InvalidExecutionEvidence,
    VerificationInventoryIncomplete,
    VerificationMismatch,
    RollbackBoundaryCrossed {
        phase: TransactionPhase,
    },
    InvalidRollbackEvidence,
    ArithmeticOverflow,
    Layout(LayoutError),
    RelocatedGraph(RelocatedGraphError),
    Overlay(OverlayError),
    Capsule(CapsuleError),
    Recovery(RecoveryError),
    PreparedEnvelopeInvalid,
}

impl fmt::Display for ConversionError {
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit { field } => write!(formatter, "conversion limit {field} is zero"),
            Self::UnknownFilesystem => {
                formatter.write_str("source and target filesystems must be known")
            }
            Self::SameFilesystem => {
                formatter.write_str("source and target filesystems are identical")
            }
            Self::ActivationAuthorizationMismatch { authorized, target } => write!(
                formatter,
                "serializer activation authorization is for {authorized}, not target {target}"
            ),
            Self::ImageLengthMismatch { graph, evidence } => write!(
                formatter,
                "object graph spans {graph} bytes but evidence identifies {evidence}"
            ),
            Self::InventoryIncomplete => formatter.write_str("object inventory is incomplete"),
            Self::AllocationMapIncomplete => {
                formatter.write_str("source allocation map is incomplete")
            }
            Self::HealthNotClean { actual } => {
                write!(formatter, "filesystem health is {actual:?}, not clean")
            }
            Self::AccessNotOffline { actual } => {
                write!(formatter, "image access state is {actual:?}, not offline")
            }
            Self::InvalidSectorSize { sector_bytes } => write!(
                formatter,
                "sector size {sector_bytes} is not a nonzero power of two"
            ),
            Self::InvalidAlignment { alignment } => write!(
                formatter,
                "allocation alignment {alignment} is not a nonzero power of two"
            ),
            Self::FeatureRuleLimitExceeded { actual, maximum } => write!(
                formatter,
                "feature compatibility has {actual} rules, exceeding {maximum}"
            ),
            Self::DuplicateFeatureRule { feature } => write!(
                formatter,
                "feature {} has duplicate compatibility rules",
                feature.label()
            ),
            Self::MissingFeatureRule { feature } => write!(
                formatter,
                "feature {} has no lossless target rule",
                feature.label()
            ),
            Self::FeatureNotPresent { feature } => write!(
                formatter,
                "compatibility rule names absent feature {}",
                feature.label()
            ),
            Self::UnsupportedNativeFeature { feature, target } => write!(
                formatter,
                "{} is not natively representable by {target}",
                feature.label()
            ),
            Self::InvalidEscrowRule { feature } => write!(
                formatter,
                "feature {} has invalid escrow schema or payload evidence",
                feature.label()
            ),
            Self::MissingGraphAllocation {
                stream,
                logical_offset,
            } => write!(
                formatter,
                "stream {} logical byte {logical_offset} is absent from allocation evidence",
                stream.0
            ),
            Self::UnsafeMovableAllocation {
                stream,
                logical_offset,
            } => write!(
                formatter,
                "stream {} logical byte {logical_offset} is marked movable without file-data evidence",
                stream.0
            ),
            Self::MissingReservation { kind } => write!(
                formatter,
                "required {kind:?} destination reservation is absent"
            ),
            Self::WriteLimitExceeded { actual, maximum } => {
                write!(formatter, "opaque write count {actual} exceeds {maximum}")
            }
            Self::WriteByteLimitExceeded { actual, maximum } => write!(
                formatter,
                "opaque writes contain {actual} bytes, exceeding {maximum}"
            ),
            Self::EmptyWriteSet { set } => {
                write!(formatter, "required opaque write set {set} is empty")
            }
            Self::WriteNotReserved { offset, kind } => write!(
                formatter,
                "write at {offset} is not contained by a {kind:?} reservation"
            ),
            Self::InvalidWritePhase { set, kind } => {
                write!(formatter, "{set} write cannot claim a {kind:?} reservation")
            }
            Self::RollbackRangeMismatch => formatter.write_str(
                "rollback ranges do not exactly pair with their source-visible write phase",
            ),
            Self::RelocationBeforeImageRangeMismatch => formatter.write_str(
                "relocation destination before-images do not exactly match solved destinations",
            ),
            Self::TargetGraphMismatch => formatter.write_str(
                "expected target graph does not equal the source graph after solved relocations",
            ),
            Self::CapsuleAlreadyStarted => {
                formatter.write_str("transaction capsule is already started")
            }
            Self::CapsuleNotStarted => {
                formatter.write_str("transaction capsule has no discovered checkpoint")
            }
            Self::LegacyCapsuleRollbackOnly => formatter
                .write_str("legacy recovery-only capsule cannot authorize forward execution"),
            Self::EnvelopeRaisesCapsuleLimits => formatter.write_str(
                "prepared envelope attempts to raise the caller's capsule policy limits",
            ),
            Self::TransactionIdentityChanged => {
                formatter.write_str("capsule transaction or source identity changed")
            }
            Self::ImageIdentityChanged => {
                formatter.write_str("regular image identity or length changed")
            }
            Self::StaleSourceEvidence => {
                formatter.write_str("source reinspection evidence is missing or stale")
            }
            Self::PlanChanged => {
                formatter.write_str("prepared plan differs from checkpoint/completion evidence")
            }
            Self::TerminalPhase { phase } => {
                write!(formatter, "transaction phase {phase:?} is terminal")
            }
            Self::UnexpectedPhase { expected, actual } => write!(
                formatter,
                "phase {actual:?} cannot follow current state; expected {expected:?}"
            ),
            Self::VerificationRequired => {
                formatter.write_str("independent target verification evidence is required")
            }
            Self::StagingVerificationRequired => formatter
                .write_str("independent candidate-overlay verification evidence is required"),
            Self::UnexpectedStagingVerificationEvidence => formatter.write_str(
                "staging verification evidence is only valid before backup-boot completion",
            ),
            Self::StagingVerificationNotExpected { phase } => write!(
                formatter,
                "candidate-overlay verification is not expected in phase {phase:?}"
            ),
            Self::StagingVerificationIncomplete => formatter.write_str(
                "candidate overlay was not parsed successfully into a complete inventory",
            ),
            Self::StagingVerificationMismatch => formatter.write_str(
                "candidate-overlay verification does not match the prepared graph and plan",
            ),
            Self::UnexpectedVerificationEvidence => formatter
                .write_str("verification evidence is only valid for the Verified checkpoint"),
            Self::InvalidExecutionEvidence => formatter
                .write_str("executor evidence is not bound to this plan and image container"),
            Self::VerificationInventoryIncomplete => {
                formatter.write_str("target verification inventory is incomplete")
            }
            Self::VerificationMismatch => formatter
                .write_str("target verification does not match the prepared graph and plan"),
            Self::RollbackBoundaryCrossed { phase } => write!(
                formatter,
                "rollback boundary was crossed at phase {phase:?}"
            ),
            Self::InvalidRollbackEvidence => formatter
                .write_str("rollback completion evidence does not match the required intent"),
            Self::ArithmeticOverflow => formatter.write_str("conversion accounting overflow"),
            Self::Layout(error) => write!(formatter, "layout planning failed: {error}"),
            Self::RelocatedGraph(error) => {
                write!(
                    formatter,
                    "relocated object graph validation failed: {error}"
                )
            }
            Self::Overlay(error) => write!(formatter, "overlay validation failed: {error}"),
            Self::Capsule(error) => write!(formatter, "capsule validation failed: {error}"),
            Self::Recovery(error) => {
                write!(formatter, "recovery bundle validation failed: {error}")
            }
            Self::PreparedEnvelopeInvalid => {
                formatter.write_str("prepared envelope validation failed")
            }
        }
    }
}

impl std::error::Error for ConversionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Layout(error) => Some(error),
            Self::RelocatedGraph(error) => Some(error),
            Self::Overlay(error) => Some(error),
            Self::Capsule(error) => Some(error),
            Self::Recovery(error) => Some(error),
            _ => None,
        }
    }
}

impl From<LayoutError> for ConversionError {
    fn from(value: LayoutError) -> Self {
        Self::Layout(value)
    }
}
impl From<RelocatedGraphError> for ConversionError {
    fn from(value: RelocatedGraphError) -> Self {
        Self::RelocatedGraph(value)
    }
}
impl From<OverlayError> for ConversionError {
    fn from(value: OverlayError) -> Self {
        Self::Overlay(value)
    }
}
impl From<CapsuleError> for ConversionError {
    fn from(value: CapsuleError) -> Self {
        Self::Capsule(value)
    }
}

impl From<RecoveryError> for ConversionError {
    fn from(value: RecoveryError) -> Self {
        Self::Recovery(value)
    }
}

impl From<prepared_envelope::PreparedEnvelopeError> for ConversionError {
    fn from(value: prepared_envelope::PreparedEnvelopeError) -> Self {
        match value {
            prepared_envelope::PreparedEnvelopeError::Capsule(error) => Self::Capsule(error),
            _ => Self::PreparedEnvelopeInvalid,
        }
    }
}

fn validate_limits(limits: ConversionLimits) -> Result<(), ConversionError> {
    for (field, value) in [
        ("max_feature_rules", limits.max_feature_rules),
        ("max_total_writes", limits.max_total_writes),
        ("max_total_write_bytes", limits.max_total_write_bytes),
    ] {
        if value == 0 {
            return Err(ConversionError::InvalidLimit { field });
        }
    }
    Ok(())
}

fn validate_initial_capsule_generation(
    payload_bytes: usize,
    limits: CapsuleLimits,
) -> Result<(), ConversionError> {
    if payload_bytes > limits.max_generation_bytes {
        return Err(CapsuleError::GenerationTooLarge {
            actual: payload_bytes,
            maximum: limits.max_generation_bytes,
        }
        .into());
    }
    let record_bytes = HEADER_BYTES
        .checked_mul(2)
        .and_then(|headers| headers.checked_add(payload_bytes))
        .ok_or(CapsuleError::ArithmeticOverflow)?;
    if record_bytes > limits.max_capsule_bytes {
        return Err(CapsuleError::CapsuleTooLarge {
            actual: record_bytes,
            maximum: limits.max_capsule_bytes,
        }
        .into());
    }
    Ok(())
}

fn validate_preflight(
    graph: &ObjectGraph,
    evidence: PreflightEvidence,
    target: FileSystem,
) -> Result<(), ConversionError> {
    if matches!(evidence.source_filesystem, FileSystem::Unknown)
        || matches!(target, FileSystem::Unknown)
    {
        return Err(ConversionError::UnknownFilesystem);
    }
    if evidence.source_filesystem == target {
        return Err(ConversionError::SameFilesystem);
    }
    if graph.extents().volume_bytes() != evidence.image.image_bytes {
        return Err(ConversionError::ImageLengthMismatch {
            graph: graph.extents().volume_bytes(),
            evidence: evidence.image.image_bytes,
        });
    }
    if !evidence.inventory_complete {
        return Err(ConversionError::InventoryIncomplete);
    }
    if !evidence.allocation_map_complete {
        return Err(ConversionError::AllocationMapIncomplete);
    }
    require_clean_offline(evidence.health, evidence.access)?;
    if evidence.sector_bytes == 0 || !evidence.sector_bytes.is_power_of_two() {
        return Err(ConversionError::InvalidSectorSize {
            sector_bytes: evidence.sector_bytes,
        });
    }
    if evidence.allocation_alignment == 0 || !evidence.allocation_alignment.is_power_of_two() {
        return Err(ConversionError::InvalidAlignment {
            alignment: evidence.allocation_alignment,
        });
    }
    if evidence.allocation_alignment % u64::from(evidence.sector_bytes) != 0 {
        return Err(ConversionError::InvalidAlignment {
            alignment: evidence.allocation_alignment,
        });
    }
    Ok(())
}

fn require_clean_offline(health: HealthState, access: AccessState) -> Result<(), ConversionError> {
    if health != HealthState::Clean {
        return Err(ConversionError::HealthNotClean { actual: health });
    }
    if access != AccessState::Offline {
        return Err(ConversionError::AccessNotOffline { actual: access });
    }
    Ok(())
}

fn validate_features(
    graph: &ObjectGraph,
    target: &mut TargetCapabilities,
    maximum: usize,
) -> Result<(), ConversionError> {
    if target.features.len() > maximum {
        return Err(ConversionError::FeatureRuleLimitExceeded {
            actual: target.features.len(),
            maximum,
        });
    }
    target
        .features
        .sort_unstable_by_key(|rule| feature_key(rule.feature));
    for pair in target.features.windows(2) {
        if pair[0].feature == pair[1].feature {
            return Err(ConversionError::DuplicateFeatureRule {
                feature: pair[0].feature,
            });
        }
    }
    for feature in graph.features() {
        let rule = target
            .features
            .iter()
            .find(|rule| rule.feature == *feature)
            .ok_or(ConversionError::MissingFeatureRule { feature: *feature })?;
        match rule.method {
            PreservationMethod::Native if !native_feature(target.filesystem, *feature) => {
                return Err(ConversionError::UnsupportedNativeFeature {
                    feature: *feature,
                    target: target.filesystem,
                });
            }
            PreservationMethod::Escrow {
                schema_version,
                payload_digest,
            } if schema_version == 0 || payload_digest == [0; 32] => {
                return Err(ConversionError::InvalidEscrowRule { feature: *feature });
            }
            _ => {}
        }
    }
    for rule in &target.features {
        if !graph.features().contains(&rule.feature) {
            return Err(ConversionError::FeatureNotPresent {
                feature: rule.feature,
            });
        }
    }
    Ok(())
}

const fn native_feature(target: FileSystem, feature: SemanticFeature) -> bool {
    matches!(target, FileSystem::Ntfs) && !matches!(feature, SemanticFeature::CaseCollisions)
}

fn validate_source_allocations(
    graph: &ObjectGraph,
    allocations: &[SourceAllocation],
) -> Result<(), ConversionError> {
    for extent in graph.extents().extents() {
        let Placement::Physical { byte_offset } = extent.placement else {
            continue;
        };
        let matched = allocations
            .iter()
            .find(|allocation| {
                allocation.stream == extent.stream
                    && allocation.logical_offset == extent.logical_offset
                    && allocation.range
                        == ByteRange {
                            offset: byte_offset,
                            length: extent.length,
                        }
            })
            .ok_or(ConversionError::MissingGraphAllocation {
                stream: extent.stream,
                logical_offset: extent.logical_offset,
            })?;
        if matched.movable && extent.kind != ExtentKind::FileData {
            return Err(ConversionError::UnsafeMovableAllocation {
                stream: extent.stream,
                logical_offset: extent.logical_offset,
            });
        }
    }
    for allocation in allocations.iter().filter(|allocation| allocation.movable) {
        let safe = graph.extents().extents().iter().any(|extent| {
            extent.stream == allocation.stream
                && extent.logical_offset == allocation.logical_offset
                && extent.length == allocation.range.length
                && extent.placement
                    == Placement::Physical {
                        byte_offset: allocation.range.offset,
                    }
                && extent.kind == ExtentKind::FileData
        });
        if !safe {
            return Err(ConversionError::UnsafeMovableAllocation {
                stream: allocation.stream,
                logical_offset: allocation.logical_offset,
            });
        }
    }
    Ok(())
}

/// Separates graph-backed content which may need relocation from retired filesystem metadata.
/// Extra immovable allocations are protected from relocation scratch, while destination writes
/// may deliberately replace them because phase preparation captures exact before-images.
fn partition_source_allocations(
    graph: &ObjectGraph,
    allocations: &[SourceAllocation],
) -> (Vec<SourceAllocation>, Vec<ByteRange>) {
    let mut live = Vec::new();
    let mut staging_exclusions = Vec::new();
    for allocation in allocations {
        if is_graph_allocation(graph, allocation) {
            live.push(*allocation);
        } else {
            debug_assert!(!allocation.movable);
            staging_exclusions.push(allocation.range);
        }
    }
    (live, staging_exclusions)
}

fn is_graph_allocation(graph: &ObjectGraph, allocation: &SourceAllocation) -> bool {
    graph.extents().extents().iter().any(|extent| {
        extent.stream == allocation.stream
            && extent.logical_offset == allocation.logical_offset
            && extent.length == allocation.range.length
            && extent.placement
                == Placement::Physical {
                    byte_offset: allocation.range.offset,
                }
    })
}

fn validate_required_reservations(
    reservations: &[DestinationReservation],
) -> Result<(), ConversionError> {
    for kind in [
        ReservationKind::BootRegion,
        ReservationKind::AllocationMetadata,
        ReservationKind::NamespaceMetadata,
    ] {
        if !reservations
            .iter()
            .any(|reservation| reservation.kind == kind)
        {
            return Err(ConversionError::MissingReservation { kind });
        }
    }
    Ok(())
}

fn validate_write_caps(
    writes: &OpaqueWriteSets,
    limits: ConversionLimits,
) -> Result<(), ConversionError> {
    for (set, empty) in [
        ("target_staging", writes.target_staging.is_empty()),
        ("backup_boot", writes.backup_boot.is_empty()),
        ("activation", writes.activation.is_empty()),
        (
            "target_staging_rollback",
            writes.target_staging_rollback.is_empty(),
        ),
        (
            "backup_boot_rollback",
            writes.backup_boot_rollback.is_empty(),
        ),
        ("activation_rollback", writes.activation_rollback.is_empty()),
    ] {
        if empty {
            return Err(ConversionError::EmptyWriteSet { set });
        }
    }
    let count = writes
        .target_staging
        .len()
        .checked_add(writes.backup_boot.len())
        .and_then(|v| v.checked_add(writes.activation.len()))
        .and_then(|v| v.checked_add(writes.target_staging_rollback.len()))
        .and_then(|v| v.checked_add(writes.backup_boot_rollback.len()))
        .and_then(|v| v.checked_add(writes.activation_rollback.len()))
        .ok_or(ConversionError::ArithmeticOverflow)?;
    if count > limits.max_total_writes {
        return Err(ConversionError::WriteLimitExceeded {
            actual: count,
            maximum: limits.max_total_writes,
        });
    }
    let bytes = writes
        .target_staging
        .iter()
        .chain(&writes.backup_boot)
        .chain(&writes.activation)
        .try_fold(0_u64, |sum, item| {
            sum.checked_add(
                u64::try_from(item.write.bytes.len())
                    .map_err(|_| ConversionError::ArithmeticOverflow)?,
            )
            .ok_or(ConversionError::ArithmeticOverflow)
        })?
        .checked_add(
            writes
                .target_staging_rollback
                .iter()
                .chain(&writes.backup_boot_rollback)
                .chain(&writes.activation_rollback)
                .try_fold(0_u64, |sum, item| {
                    sum.checked_add(
                        u64::try_from(item.bytes.len())
                            .map_err(|_| ConversionError::ArithmeticOverflow)?,
                    )
                    .ok_or(ConversionError::ArithmeticOverflow)
                })?,
        )
        .ok_or(ConversionError::ArithmeticOverflow)?;
    if usize::try_from(bytes).unwrap_or(usize::MAX) > limits.max_total_write_bytes {
        return Err(ConversionError::WriteByteLimitExceeded {
            actual: bytes,
            maximum: limits.max_total_write_bytes,
        });
    }
    Ok(())
}

fn validate_writes_against_reservations(
    writes: &OpaqueWriteSets,
    reservations: &[DestinationReservation],
) -> Result<(), ConversionError> {
    for (set, values) in [
        ("target_staging", writes.target_staging.as_slice()),
        ("backup_boot", writes.backup_boot.as_slice()),
        ("activation", writes.activation.as_slice()),
    ] {
        for value in values {
            if (set == "backup_boot" || set == "activation")
                && value.reservation_kind != ReservationKind::BootRegion
            {
                return Err(ConversionError::InvalidWritePhase {
                    set,
                    kind: value.reservation_kind,
                });
            }
            if set == "target_staging"
                && matches!(
                    value.reservation_kind,
                    ReservationKind::BootRegion | ReservationKind::Capsule
                )
            {
                return Err(ConversionError::InvalidWritePhase {
                    set,
                    kind: value.reservation_kind,
                });
            }
            let length = u64::try_from(value.write.bytes.len())
                .map_err(|_| ConversionError::ArithmeticOverflow)?;
            let write_end = value
                .write
                .offset
                .checked_add(length)
                .ok_or(ConversionError::ArithmeticOverflow)?;
            let contained = reservations.iter().any(|reservation| {
                reservation.kind == value.reservation_kind
                    && reservation.range.offset <= value.write.offset
                    && reservation
                        .range
                        .offset
                        .checked_add(reservation.range.length)
                        .is_some_and(|end| write_end <= end)
            });
            if !contained {
                return Err(ConversionError::WriteNotReserved {
                    offset: value.write.offset,
                    kind: value.reservation_kind,
                });
            }
        }
    }
    Ok(())
}

fn validate_rollback_pairing(writes: &OpaqueWriteSets) -> Result<(), ConversionError> {
    for (forward, rollback) in [
        (
            writes.target_staging.as_slice(),
            writes.target_staging_rollback.as_slice(),
        ),
        (
            writes.backup_boot.as_slice(),
            writes.backup_boot_rollback.as_slice(),
        ),
        (
            writes.activation.as_slice(),
            writes.activation_rollback.as_slice(),
        ),
    ] {
        let mut forward_ranges: Vec<_> = forward
            .iter()
            .map(|value| (value.write.offset, value.write.bytes.len()))
            .collect();
        let mut rollback_ranges: Vec<_> = rollback
            .iter()
            .map(|value| (value.offset, value.bytes.len()))
            .collect();
        forward_ranges.sort_unstable();
        rollback_ranges.sort_unstable();
        if forward_ranges != rollback_ranges {
            return Err(ConversionError::RollbackRangeMismatch);
        }
    }
    Ok(())
}

fn validate_relocation_before_images(
    layout: &LayoutPlan,
    before_images: &mut [OverlayWrite],
    writes: &OpaqueWriteSets,
    limits: ConversionLimits,
) -> Result<(), ConversionError> {
    before_images.sort_unstable_by_key(|write| write.offset);
    validate_relocation_before_image_ranges(layout, before_images)?;

    let existing_count = writes
        .target_staging
        .len()
        .checked_add(writes.backup_boot.len())
        .and_then(|value| value.checked_add(writes.activation.len()))
        .and_then(|value| value.checked_add(writes.target_staging_rollback.len()))
        .and_then(|value| value.checked_add(writes.backup_boot_rollback.len()))
        .and_then(|value| value.checked_add(writes.activation_rollback.len()))
        .ok_or(ConversionError::ArithmeticOverflow)?;
    let count = existing_count
        .checked_add(before_images.len())
        .ok_or(ConversionError::ArithmeticOverflow)?;
    if count > limits.max_total_writes {
        return Err(ConversionError::WriteLimitExceeded {
            actual: count,
            maximum: limits.max_total_writes,
        });
    }
    let existing_bytes = writes
        .target_staging
        .iter()
        .map(|value| value.write.bytes.len())
        .chain(
            writes
                .backup_boot
                .iter()
                .map(|value| value.write.bytes.len()),
        )
        .chain(
            writes
                .activation
                .iter()
                .map(|value| value.write.bytes.len()),
        )
        .chain(
            writes
                .target_staging_rollback
                .iter()
                .map(|value| value.bytes.len()),
        )
        .chain(
            writes
                .backup_boot_rollback
                .iter()
                .map(|value| value.bytes.len()),
        )
        .chain(
            writes
                .activation_rollback
                .iter()
                .map(|value| value.bytes.len()),
        )
        .chain(before_images.iter().map(|value| value.bytes.len()))
        .try_fold(0_usize, usize::checked_add)
        .ok_or(ConversionError::ArithmeticOverflow)?;
    if existing_bytes > limits.max_total_write_bytes {
        return Err(ConversionError::WriteByteLimitExceeded {
            actual: u64::try_from(existing_bytes).unwrap_or(u64::MAX),
            maximum: limits.max_total_write_bytes,
        });
    }
    Ok(())
}

fn validate_relocation_before_image_ranges(
    layout: &LayoutPlan,
    before_images: &[OverlayWrite],
) -> Result<(), ConversionError> {
    let mut expected: Vec<_> = layout
        .relocations
        .iter()
        .map(|relocation| (relocation.destination.offset, relocation.destination.length))
        .collect();
    expected.sort_unstable();
    let actual: Vec<_> = before_images
        .iter()
        .map(|write| {
            Ok((
                write.offset,
                u64::try_from(write.bytes.len())
                    .map_err(|_| ConversionError::ArithmeticOverflow)?,
            ))
        })
        .collect::<Result<_, ConversionError>>()?;
    if actual != expected {
        return Err(ConversionError::RelocationBeforeImageRangeMismatch);
    }
    Ok(())
}

fn staging_rollback_writes(
    relocation: &[OverlayWrite],
    writes: &OpaqueWriteSets,
) -> Vec<OverlayWrite> {
    relocation
        .iter()
        .chain(&writes.target_staging_rollback)
        .cloned()
        .collect()
}

fn preactivation_rollback_writes(
    relocation: &[OverlayWrite],
    writes: &OpaqueWriteSets,
) -> Vec<OverlayWrite> {
    staging_rollback_writes(relocation, writes)
        .into_iter()
        .chain(writes.backup_boot_rollback.iter().cloned())
        .collect()
}

fn full_rollback_writes(
    relocation: &[OverlayWrite],
    writes: &OpaqueWriteSets,
) -> Vec<OverlayWrite> {
    preactivation_rollback_writes(relocation, writes)
        .into_iter()
        .chain(writes.activation_rollback.iter().cloned())
        .collect()
}

fn final_writes(writes: &OpaqueWriteSets) -> Vec<OverlayWrite> {
    writes
        .target_staging
        .iter()
        .chain(&writes.backup_boot)
        .chain(&writes.activation)
        .map(|value| value.write.clone())
        .collect()
}

const fn next_phase(phase: TransactionPhase) -> Option<TransactionPhase> {
    match phase {
        TransactionPhase::Discovered => Some(TransactionPhase::Reserved),
        TransactionPhase::Reserved => Some(TransactionPhase::Relocating),
        TransactionPhase::Relocating => Some(TransactionPhase::TargetStaged),
        TransactionPhase::TargetStaged => Some(TransactionPhase::BackupBootWritten),
        TransactionPhase::BackupBootWritten => Some(TransactionPhase::Activated),
        TransactionPhase::Activated => Some(TransactionPhase::Verified),
        TransactionPhase::Verified => Some(TransactionPhase::Finalized),
        TransactionPhase::Finalized | TransactionPhase::RolledBack => None,
    }
}

const fn phase_requires_source_evidence(phase: TransactionPhase) -> bool {
    matches!(
        phase,
        TransactionPhase::Discovered
            | TransactionPhase::Reserved
            | TransactionPhase::Relocating
            | TransactionPhase::TargetStaged
            | TransactionPhase::BackupBootWritten
    )
}

const fn reservation_sort_key(value: &DestinationReservation) -> (u64, u64, u8) {
    (
        value.range.offset,
        value.range.length,
        reservation_kind_key(value.kind),
    )
}

fn reserved_write_sort_key(value: &ReservedWrite) -> (u64, usize, u8) {
    (
        value.write.offset,
        value.write.bytes.len(),
        reservation_kind_key(value.reservation_kind),
    )
}

const fn feature_key(feature: SemanticFeature) -> u8 {
    match feature {
        SemanticFeature::AccessControl => 0,
        SemanticFeature::AlternateDataStreams => 1,
        SemanticFeature::Compression => 2,
        SemanticFeature::EncryptedFiles => 3,
        SemanticFeature::HardLinks => 4,
        SemanticFeature::ReparsePoints => 5,
        SemanticFeature::SparseFiles => 6,
        SemanticFeature::CaseCollisions => 7,
    }
}

const fn reservation_kind_key(kind: ReservationKind) -> u8 {
    match kind {
        ReservationKind::BootRegion => 0,
        ReservationKind::AllocationMetadata => 1,
        ReservationKind::NamespaceMetadata => 2,
        ReservationKind::Journal => 3,
        ReservationKind::Capsule => 4,
        ReservationKind::Other => 5,
    }
}

const fn filesystem_key(filesystem: FileSystem) -> u8 {
    match filesystem {
        FileSystem::ExFat => 0,
        FileSystem::Ntfs => 1,
        FileSystem::Unknown => 2,
    }
}

fn put_u64(hasher: &mut Sha256, value: u64) {
    hasher.update(value.to_le_bytes());
}
fn put_bytes(hasher: &mut Sha256, bytes: &[u8]) {
    put_u64(hasher, bytes.len() as u64);
    hasher.update(bytes);
}
fn finish(hasher: Sha256) -> [u8; 32] {
    hasher.finalize().into()
}

fn digest_source_identity(evidence: PreflightEvidence, graph_digest: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"starconverter-source-v1");
    hasher.update(evidence.image.instance);
    put_u64(&mut hasher, evidence.image.image_bytes);
    hasher.update(evidence.source_evidence_digest);
    hasher.update(evidence.source_manifest_commitment.digest());
    put_u64(
        &mut hasher,
        evidence.source_manifest_commitment.logical_bytes_hashed(),
    );
    put_u64(
        &mut hasher,
        evidence.source_manifest_commitment.object_count(),
    );
    hasher.update(graph_digest);
    finish(hasher)
}

fn digest_graph(graph: &ObjectGraph) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"starconverter-object-graph-v1");
    put_u64(&mut hasher, graph.root().0);
    let mut objects: Vec<_> = graph.objects().iter().collect();
    objects.sort_unstable_by_key(|object| object.id);
    for object in objects {
        put_u64(&mut hasher, object.id.0);
        hasher.update([match object.kind {
            ObjectKind::File => 0,
            ObjectKind::Directory => 1,
        }]);
        hasher.update(object.link_count.to_le_bytes());
        hasher.update([
            u8::from(object.semantics.has_security_descriptor),
            u8::from(object.semantics.is_reparse_point),
        ]);
        let mut streams: Vec<_> = object.streams.iter().collect();
        streams.sort_unstable_by_key(|stream| stream.id);
        for stream in streams {
            put_u64(&mut hasher, stream.id.0);
            match &stream.name {
                None => hasher.update([0]),
                Some(name) => {
                    hasher.update([1]);
                    put_u64(&mut hasher, name.len() as u64);
                    for unit in name {
                        hasher.update(unit.to_le_bytes());
                    }
                }
            }
            for value in [
                stream.logical_bytes,
                stream.initialized_bytes,
                stream.mapped_bytes,
                stream.allocated_bytes,
            ] {
                put_u64(&mut hasher, value);
            }
            hasher.update([
                u8::from(stream.flags.sparse),
                u8::from(stream.flags.compressed),
                u8::from(stream.flags.encrypted),
            ]);
            match &stream.storage {
                StreamStorage::Resident(bytes) => {
                    hasher.update([0]);
                    put_bytes(&mut hasher, bytes);
                }
                StreamStorage::Extents => hasher.update([1]),
            }
        }
    }
    let mut entries: Vec<_> = graph.entries().iter().collect();
    entries
        .sort_unstable_by(|a, b| (a.parent, &a.name, a.target).cmp(&(b.parent, &b.name, b.target)));
    for entry in entries {
        put_u64(&mut hasher, entry.parent.0);
        put_u64(&mut hasher, entry.target.0);
        put_u64(&mut hasher, entry.name.len() as u64);
        for unit in &entry.name {
            hasher.update(unit.to_le_bytes());
        }
    }
    for extent in graph.extents().extents() {
        put_u64(&mut hasher, extent.stream.0);
        put_u64(&mut hasher, extent.logical_offset);
        put_u64(&mut hasher, extent.length);
        hasher.update([match extent.kind {
            ExtentKind::FileData => 0,
            ExtentKind::DirectoryData => 1,
            ExtentKind::FileSystemMetadata => 2,
            ExtentKind::Reserved => 3,
            ExtentKind::BadCluster => 4,
        }]);
        match extent.placement {
            Placement::Physical { byte_offset } => {
                hasher.update([0]);
                put_u64(&mut hasher, byte_offset);
            }
            Placement::Sparse => hasher.update([1]),
        }
    }
    finish(hasher)
}

#[allow(clippy::too_many_arguments)]
fn digest_plan(
    evidence: PreflightEvidence,
    target: FileSystem,
    features: &[FeatureCompatibility],
    reservations: &[DestinationReservation],
    layout: &LayoutPlan,
    writes: &OpaqueWriteSets,
    source_graph_digest: [u8; 32],
    target_graph_digest: [u8; 32],
    relocation_destination_before_images: &[OverlayWrite],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"starconverter-plan-v2");
    hasher.update(source_graph_digest);
    hasher.update(target_graph_digest);
    hasher.update([
        filesystem_key(evidence.source_filesystem),
        filesystem_key(target),
    ]);
    put_u64(&mut hasher, evidence.image.image_bytes);
    hasher.update(evidence.sector_bytes.to_le_bytes());
    put_u64(&mut hasher, evidence.allocation_alignment);
    hasher.update(evidence.source_manifest_commitment.digest());
    put_u64(
        &mut hasher,
        evidence.source_manifest_commitment.logical_bytes_hashed(),
    );
    put_u64(
        &mut hasher,
        evidence.source_manifest_commitment.object_count(),
    );
    for feature in features {
        hasher.update([feature_key(feature.feature)]);
        match feature.method {
            PreservationMethod::Native => hasher.update([0]),
            PreservationMethod::Escrow {
                schema_version,
                payload_digest,
            } => {
                hasher.update([1]);
                hasher.update(schema_version.to_le_bytes());
                hasher.update(payload_digest);
            }
        }
    }
    for reservation in reservations {
        put_u64(&mut hasher, reservation.range.offset);
        put_u64(&mut hasher, reservation.range.length);
        hasher.update([reservation_kind_key(reservation.kind)]);
    }
    for relocation in &layout.relocations {
        put_u64(&mut hasher, relocation.stream.0);
        put_u64(&mut hasher, relocation.logical_offset);
        for range in [relocation.source, relocation.destination] {
            put_u64(&mut hasher, range.offset);
            put_u64(&mut hasher, range.length);
        }
    }
    for (tag, set) in [
        (0_u8, writes.target_staging.as_slice()),
        (1, writes.backup_boot.as_slice()),
        (2, writes.activation.as_slice()),
    ] {
        for value in set {
            hasher.update([tag, reservation_kind_key(value.reservation_kind)]);
            put_u64(&mut hasher, value.write.offset);
            put_bytes(&mut hasher, &value.write.bytes);
        }
    }
    hasher.update(digest_overlay_writes(&writes.target_staging_rollback));
    hasher.update(digest_overlay_writes(&writes.backup_boot_rollback));
    hasher.update(digest_overlay_writes(&writes.activation_rollback));
    hasher.update(digest_overlay_writes(relocation_destination_before_images));
    finish(hasher)
}

fn digest_overlay_writes(writes: &[OverlayWrite]) -> [u8; 32] {
    let mut ordered: Vec<_> = writes.iter().collect();
    ordered.sort_unstable_by_key(|write| write.offset);
    let mut hasher = Sha256::new();
    hasher.update(b"starconverter-overlay-writes-v1");
    for write in ordered {
        put_u64(&mut hasher, write.offset);
        put_bytes(&mut hasher, &write.bytes);
    }
    finish(hasher)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::executor::{ExecutionLease, ExecutorLimits, ImageExecutor};
    use crate::extent::{Extent, ExtentGraph, StreamId};
    use crate::object::{
        NamespaceEntry, ObjectGraphLimits, ObjectRecord, ObjectSemantics, ObjectStream, StreamFlags,
    };
    use crate::recovery::{RecoveryLimits, decode_recovery_bundle};

    const IMAGE: ImageIdentity = ImageIdentity {
        instance: [7; 32],
        image_bytes: 16 * 1024,
    };
    static NEXT_EXECUTION_TEMP: AtomicU64 = AtomicU64::new(0);

    fn graph(feature: bool) -> ObjectGraph {
        let extents = ExtentGraph::build(
            vec![Extent {
                stream: StreamId(1),
                logical_offset: 0,
                length: 512,
                placement: Placement::Physical { byte_offset: 4096 },
                kind: ExtentKind::FileData,
            }],
            IMAGE.image_bytes,
            8,
        )
        .unwrap();
        ObjectGraph::build(
            crate::object::ObjectId(0),
            vec![
                ObjectRecord {
                    id: crate::object::ObjectId(0),
                    kind: ObjectKind::Directory,
                    link_count: 0,
                    semantics: ObjectSemantics::default(),
                    streams: Vec::new(),
                },
                ObjectRecord {
                    id: crate::object::ObjectId(1),
                    kind: ObjectKind::File,
                    link_count: 1,
                    semantics: ObjectSemantics {
                        has_security_descriptor: feature,
                        is_reparse_point: false,
                    },
                    streams: vec![ObjectStream {
                        id: StreamId(1),
                        name: None,
                        logical_bytes: 1,
                        initialized_bytes: 1,
                        mapped_bytes: 512,
                        allocated_bytes: 512,
                        flags: StreamFlags::default(),
                        storage: StreamStorage::Extents,
                    }],
                },
            ],
            vec![NamespaceEntry {
                parent: crate::object::ObjectId(0),
                target: crate::object::ObjectId(1),
                name: vec![u16::from(b'x')],
            }],
            extents,
            ObjectGraphLimits {
                max_objects: 8,
                max_entries: 8,
                max_streams: 8,
                max_name_code_units: 32,
            },
        )
        .unwrap()
    }

    fn rw(kind: ReservationKind, offset: u64, byte: u8) -> ReservedWrite {
        ReservedWrite {
            reservation_kind: kind,
            write: OverlayWrite {
                offset,
                bytes: vec![byte; 512],
            },
        }
    }

    fn draft() -> ConversionDraft {
        ConversionDraft {
            transaction_id: [3; 16],
            preflight: PreflightEvidence {
                image: IMAGE,
                source_filesystem: FileSystem::ExFat,
                source_evidence_digest: [9; 32],
                source_manifest_commitment: ManifestCommitment::from_validated_parts(
                    [0x4d; 32], 1, 2,
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
            source_allocations: vec![
                SourceAllocation {
                    stream: StreamId(99),
                    logical_offset: 0,
                    range: ByteRange {
                        offset: 0,
                        length: 512,
                    },
                    movable: false,
                },
                SourceAllocation {
                    stream: StreamId(1),
                    logical_offset: 0,
                    range: ByteRange {
                        offset: 4096,
                        length: 512,
                    },
                    movable: true,
                },
            ],
            reservations: vec![
                DestinationReservation {
                    range: ByteRange {
                        offset: 1024,
                        length: 1024,
                    },
                    kind: ReservationKind::BootRegion,
                },
                DestinationReservation {
                    range: ByteRange {
                        offset: 2048,
                        length: 512,
                    },
                    kind: ReservationKind::AllocationMetadata,
                },
                DestinationReservation {
                    range: ByteRange {
                        offset: 2560,
                        length: 512,
                    },
                    kind: ReservationKind::NamespaceMetadata,
                },
                DestinationReservation {
                    range: ByteRange {
                        offset: 3072,
                        length: 512,
                    },
                    kind: ReservationKind::Capsule,
                },
            ],
            writes: ActivationAuthorizedWrites::test_only(
                FileSystem::Ntfs,
                OpaqueWriteSets {
                    target_staging: vec![
                        rw(ReservationKind::AllocationMetadata, 2048, 0x20),
                        rw(ReservationKind::NamespaceMetadata, 2560, 0x30),
                    ],
                    backup_boot: vec![rw(ReservationKind::BootRegion, 1024, 0x40)],
                    activation: vec![rw(ReservationKind::BootRegion, 1536, 0x50)],
                    target_staging_rollback: vec![
                        OverlayWrite {
                            offset: 2048,
                            bytes: vec![0x12; 512],
                        },
                        OverlayWrite {
                            offset: 2560,
                            bytes: vec![0x13; 512],
                        },
                    ],
                    backup_boot_rollback: vec![OverlayWrite {
                        offset: 1024,
                        bytes: vec![0x10; 512],
                    }],
                    activation_rollback: vec![OverlayWrite {
                        offset: 1536,
                        bytes: vec![0x11; 512],
                    }],
                },
            ),
        }
    }

    pub fn prepared() -> PreparedConversion {
        PreparedConversion::build(&graph(false), draft(), ConversionLimits::default()).unwrap()
    }

    fn relocation_fixture() -> (ObjectGraph, ConversionDraft, ObjectGraph, Vec<OverlayWrite>) {
        let source = graph(false);
        let mut value = draft();
        value.reservations[2].range = ByteRange {
            offset: 4096,
            length: 512,
        };
        value.writes.test_writes_mut().target_staging[1]
            .write
            .offset = 4096;
        value.writes.test_writes_mut().target_staging_rollback[1].offset = 4096;

        let mut reservations = value.reservations.clone();
        reservations.sort_unstable_by_key(reservation_sort_key);
        let (live, exclusions) = partition_source_allocations(&source, &value.source_allocations);
        let layout = crate::geometry::solve_layout_with_staging_exclusions(
            value.preflight.image.image_bytes,
            value.preflight.allocation_alignment,
            live,
            reservations,
            exclusions,
            ConversionLimits::default().layout,
        )
        .unwrap();
        let target = relocate_object_graph(&source, &layout).unwrap();
        let before_images = layout
            .relocations
            .iter()
            .map(|relocation| OverlayWrite {
                offset: relocation.destination.offset,
                bytes: vec![0x77; usize::try_from(relocation.destination.length).unwrap()],
            })
            .collect();
        (source, value, target, before_images)
    }

    #[test]
    fn only_bound_executor_evidence_advances_mutation_and_rollback_phases() {
        let sequence = NEXT_EXECUTION_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "starconverter-conversion-execution-{}-{sequence}.img",
            std::process::id()
        ));
        fs::write(
            &path,
            vec![0x5a; usize::try_from(IMAGE.image_bytes).unwrap()],
        )
        .unwrap();
        let image = crate::image::ImageFile::open(&path).unwrap();
        let image_identity = image.identity().clone();
        let mut plan = prepared();
        let source_evidence_digest = plan.preflight.source_evidence_digest;
        plan.test_bind_regular_image(&image_identity, source_evidence_digest);
        let observed = ObservedImage {
            image: plan.preflight.image,
            source_evidence_digest: Some(plan.preflight.source_evidence_digest),
        };
        drop(image);

        let mut capsule = Vec::new();
        plan.begin_capsule(&mut capsule, observed).unwrap();
        plan.record_phase(
            &mut capsule,
            observed,
            TransactionPhase::Reserved,
            PhaseCompletion {
                image: plan.preflight.image,
                plan_digest: plan.plan_digest,
                health: HealthState::Clean,
                access: AccessState::Offline,
            },
            None,
            None,
        )
        .unwrap();

        let executor =
            ImageExecutor::open(&path, &image_identity, ExecutorLimits::default()).unwrap();
        let intent = plan.resume(&capsule, observed).unwrap().next;
        let lease = ExecutionLease::new(
            1,
            TransactionPhase::Reserved,
            plan.plan_digest(),
            image_identity.stable_container_token(),
        );
        let leased = executor
            .execute_leased_intent(&plan, lease, intent)
            .unwrap();
        let (executed, generation, phase) = leased.into_parts();
        assert_eq!(generation, 1);
        assert_eq!(phase, TransactionPhase::Reserved);
        assert_eq!(executed.completed_phase(), TransactionPhase::Relocating);
        plan.record_execution(&mut capsule, observed, executed, None)
            .unwrap();
        assert_eq!(
            plan.resume(&capsule, observed).unwrap().phase,
            TransactionPhase::Relocating
        );

        let rollback_intent = plan.rollback_intent(TransactionPhase::Relocating).unwrap();
        let lease = ExecutionLease::new(
            2,
            TransactionPhase::Relocating,
            plan.plan_digest(),
            image_identity.stable_container_token(),
        );
        let leased = executor
            .execute_leased_rollback(&plan, lease, rollback_intent)
            .unwrap();
        let (rollback, generation, phase) = leased.into_parts();
        assert_eq!(generation, 2);
        assert_eq!(phase, TransactionPhase::Relocating);
        assert!(rollback.restored_source());
        plan.record_executed_rollback(&mut capsule, observed, rollback)
            .unwrap();
        assert_eq!(
            plan.resume(&capsule, observed).unwrap().phase,
            TransactionPhase::RolledBack
        );
        drop(executor);
        fs::remove_file(path).unwrap();
    }
    const fn observed() -> ObservedImage {
        ObservedImage {
            image: IMAGE,
            source_evidence_digest: Some([9; 32]),
        }
    }
    const fn completion(plan: &PreparedConversion) -> PhaseCompletion {
        PhaseCompletion {
            image: IMAGE,
            plan_digest: plan.plan_digest(),
            health: HealthState::Clean,
            access: AccessState::Offline,
        }
    }

    const fn staging_verification(plan: &PreparedConversion) -> StagingVerificationEvidence {
        let expected = plan.expected_staging_verification();
        StagingVerificationEvidence {
            target_filesystem: expected.target_filesystem,
            parser_validated: true,
            inventory_complete: true,
            object_graph_digest: expected.object_graph_digest,
            plan_digest: expected.plan_digest,
            candidate_overlay_digest: expected.candidate_overlay_digest,
        }
    }

    fn record_success(plan: &PreparedConversion, capsule: &mut Vec<u8>, phase: TransactionPhase) {
        let staging =
            (phase == TransactionPhase::BackupBootWritten).then(|| staging_verification(plan));
        plan.record_phase(capsule, observed(), phase, completion(plan), staging, None)
            .unwrap();
    }

    #[test]
    fn deterministic_plan_and_capsule_identity() {
        let first = prepared();
        let mut shuffled = draft();
        shuffled.reservations.reverse();
        shuffled.target.features.reverse();
        let second =
            PreparedConversion::build(&graph(false), shuffled, ConversionLimits::default())
                .unwrap();
        assert_eq!(first.plan_digest(), second.plan_digest());
        assert_eq!(first.identity(), second.identity());
        assert_eq!(first.layout(), second.layout());
    }

    #[test]
    fn first_capsule_generation_durably_contains_restart_plan_and_exact_recovery_bytes() {
        let plan = prepared();
        let decoded = decode_recovery_bundle(
            plan.recovery_payload(),
            RecoveryLimits {
                max_writes: 8,
                max_bytes: 4096,
            },
        )
        .unwrap();
        assert_eq!(decoded.plan_digest, plan.plan_digest());
        assert!(decoded.relocation_destinations.is_empty());
        assert_eq!(decoded.target_staging, plan.writes.target_staging_rollback);
        assert_eq!(decoded.backup_boot, plan.writes.backup_boot_rollback);
        assert_eq!(decoded.activation, plan.writes.activation_rollback);

        let mut capsule = Vec::new();
        plan.begin_capsule(&mut capsule, observed()).unwrap();
        let view = scan_capsule(&capsule, CapsuleLimits::default()).unwrap();
        assert_eq!(view.newest().unwrap().payload, plan.prepared_envelope);
        assert_eq!(&view.newest().unwrap().payload[..8], b"SCPREP02");
        let restored =
            PreparedConversion::from_restart_capsule(&capsule, CapsuleLimits::default()).unwrap();
        assert_eq!(restored, plan);
    }

    #[test]
    fn legacy_recovery_only_capsule_cannot_recreate_forward_authority() {
        let plan = prepared();
        let mut legacy = Vec::new();
        append_generation(
            &mut legacy,
            plan.identity(),
            TransactionPhase::Discovered,
            plan.recovery_payload(),
            CapsuleLimits::default(),
        )
        .unwrap();

        assert!(matches!(
            plan.resume(&legacy, observed()),
            Err(ConversionError::LegacyCapsuleRollbackOnly)
        ));
        assert_eq!(
            plan.resume_for_rollback(&legacy, observed()).unwrap().phase,
            TransactionPhase::Discovered
        );
        assert!(matches!(
            PreparedConversion::from_restart_capsule(&legacy, CapsuleLimits::default()),
            Err(ConversionError::PreparedEnvelopeInvalid)
        ));
    }

    #[test]
    fn derives_relocation_and_keeps_writes_in_reserved_ranges() {
        let (source, value, target, before_images) = relocation_fixture();
        assert!(matches!(
            PreparedConversion::build(&source, value.clone(), ConversionLimits::default()),
            Err(ConversionError::TargetGraphMismatch)
        ));
        let plan = PreparedConversion::build_with_target_graph(
            &source,
            &target,
            value,
            before_images,
            ConversionLimits::default(),
        )
        .unwrap();
        assert_eq!(plan.layout().relocations.len(), 1);
        assert_eq!(plan.layout().relocations[0].source.offset, 4096);
        assert_ne!(plan.layout().relocations[0].destination.offset, 4096);
        assert_ne!(plan.graph_digest(), plan.target_graph_digest());
    }

    #[test]
    fn semantic_projection_is_checked_before_relocation_without_becoming_source_authority() {
        let (source, value, relocated_source, before_images) = relocation_fixture();
        let mut objects = source.objects().to_vec();
        for object in &mut objects {
            object.semantics.has_security_descriptor = true;
        }
        let graph_limits = ObjectGraphLimits {
            max_objects: objects.len().max(1),
            max_entries: source.entries().len().max(1),
            max_streams: objects
                .iter()
                .map(|object| object.streams.len())
                .sum::<usize>()
                .max(1),
            max_name_code_units: source
                .entries()
                .iter()
                .map(|entry| entry.name.len())
                .max()
                .unwrap_or(1),
        };
        let projected = ObjectGraph::build(
            source.root(),
            objects.clone(),
            source.entries().to_vec(),
            source.extents().clone(),
            graph_limits,
        )
        .unwrap();
        let relocated_target = ObjectGraph::build(
            source.root(),
            objects,
            source.entries().to_vec(),
            relocated_source.extents().clone(),
            graph_limits,
        )
        .unwrap();

        assert!(matches!(
            PreparedConversion::build_with_target_graph(
                &source,
                &relocated_target,
                value.clone(),
                before_images.clone(),
                ConversionLimits::default(),
            ),
            Err(ConversionError::TargetGraphMismatch)
        ));
        let plan = PreparedConversion::build_with_projected_target_graph(
            &source,
            &projected,
            &relocated_target,
            value,
            before_images,
            ConversionLimits::default(),
        )
        .unwrap();
        assert_eq!(plan.layout().relocations.len(), 1);
        assert_eq!(plan.graph_digest(), digest_graph(&source));
        assert_eq!(plan.target_graph_digest(), digest_graph(&relocated_target));
        assert_ne!(plan.graph_digest(), plan.target_graph_digest());
    }

    #[test]
    fn external_capsule_store_does_not_require_an_in_image_capsule_reservation() {
        let mut value = draft();
        value
            .reservations
            .retain(|reservation| reservation.kind != ReservationKind::Capsule);
        assert!(
            PreparedConversion::build(&graph(false), value, ConversionLimits::default()).is_ok()
        );

        for kind in [
            ReservationKind::BootRegion,
            ReservationKind::AllocationMetadata,
            ReservationKind::NamespaceMetadata,
        ] {
            let mut missing = draft();
            missing
                .reservations
                .retain(|reservation| reservation.kind != kind);
            assert!(matches!(
                PreparedConversion::build(&graph(false), missing, ConversionLimits::default()),
                Err(ConversionError::MissingReservation { kind: actual }) if actual == kind
            ));
        }
    }

    #[test]
    fn relocation_requires_exact_destination_before_images_and_target_graph() {
        for case in 0..4 {
            let (source, value, target, mut before_images) = relocation_fixture();
            match case {
                0 => before_images.clear(),
                1 => before_images.push(OverlayWrite {
                    offset: 15 * 1024,
                    bytes: vec![0; 512],
                }),
                2 => before_images.push(before_images[0].clone()),
                _ => before_images[0].bytes.pop().map_or((), drop),
            }
            assert!(matches!(
                PreparedConversion::build_with_target_graph(
                    &source,
                    &target,
                    value,
                    before_images,
                    ConversionLimits::default(),
                ),
                Err(ConversionError::RelocationBeforeImageRangeMismatch)
            ));
        }

        let (source, value, _target, before_images) = relocation_fixture();
        assert!(matches!(
            PreparedConversion::build_with_target_graph(
                &source,
                &source,
                value,
                before_images,
                ConversionLimits::default(),
            ),
            Err(ConversionError::TargetGraphMismatch)
        ));
    }

    #[test]
    fn relocation_rollback_masks_are_exact_and_survive_restart() {
        let (source, value, target, before_images) = relocation_fixture();
        let plan = PreparedConversion::build_with_target_graph(
            &source,
            &target,
            value,
            before_images,
            ConversionLimits::default(),
        )
        .unwrap();
        let expected_lengths = [
            (TransactionPhase::Reserved, 1),
            (TransactionPhase::Relocating, 3),
            (TransactionPhase::TargetStaged, 4),
            (TransactionPhase::BackupBootWritten, 5),
            (TransactionPhase::Activated, 5),
            (TransactionPhase::Verified, 5),
        ];
        for (phase, expected_len) in expected_lengths {
            let rollback = match plan.rollback_intent(phase).unwrap() {
                RollbackIntent::RestoreSource { writes, .. } => writes,
                RollbackIntent::DiscardStaging => panic!("relocation phase lost restoration"),
            };
            assert_eq!(rollback.len(), expected_len, "phase {phase:?}");
            assert_eq!(
                plan.observation_rollback_writes(phase).unwrap(),
                rollback,
                "phase {phase:?}",
            );
            assert!(rollback.iter().any(|write| {
                write.offset == plan.layout().relocations[0].destination.offset
                    && write.bytes.len() == 512
            }));
        }

        let mut capsule = Vec::new();
        plan.begin_capsule(&mut capsule, observed()).unwrap();
        let recovered =
            PreparedConversion::from_restart_capsule(&capsule, CapsuleLimits::default()).unwrap();
        assert_eq!(recovered, plan);
        assert_eq!(
            recovered.relocation_rollback_overlay().writes(),
            plan.relocation_rollback_overlay().writes()
        );
    }

    #[test]
    fn retired_source_metadata_may_share_a_destination_write_range() {
        let mut value = draft();
        value.source_allocations[0].range.offset = 2048;
        let plan = PreparedConversion::build(&graph(false), value, ConversionLimits::default())
            .expect("exact rollback bytes permit destination metadata to replace source metadata");
        assert!(
            plan.candidate_overlay()
                .writes()
                .iter()
                .any(|write| write.offset == 2048)
        );
    }

    #[test]
    fn phase_ordering_requires_exact_next_checkpoint() {
        let plan = prepared();
        let mut capsule = Vec::new();
        plan.begin_capsule(&mut capsule, observed()).unwrap();
        assert!(matches!(
            plan.record_phase(
                &mut capsule,
                observed(),
                TransactionPhase::Activated,
                completion(&plan),
                None,
                None
            ),
            Err(ConversionError::UnexpectedPhase { .. })
        ));
        plan.record_phase(
            &mut capsule,
            observed(),
            TransactionPhase::Reserved,
            completion(&plan),
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            plan.resume(&capsule, observed()).unwrap().phase,
            TransactionPhase::Reserved
        );
    }

    #[test]
    fn interrupted_capsule_resumes_with_precise_intent() {
        let plan = prepared();
        let mut capsule = Vec::new();
        plan.begin_capsule(&mut capsule, observed()).unwrap();
        plan.record_phase(
            &mut capsule,
            observed(),
            TransactionPhase::Reserved,
            completion(&plan),
            None,
            None,
        )
        .unwrap();
        let resumed = plan.resume(&capsule, observed()).unwrap();
        assert!(matches!(resumed.next, TransactionIntent::Relocate(_)));
        let recovered = capsule.clone();
        assert_eq!(plan.resume(&recovered, observed()).unwrap(), resumed);
    }

    #[test]
    fn torn_newest_checkpoint_is_recovered_and_replaced_before_append() {
        let plan = prepared();
        let mut capsule = Vec::new();
        plan.begin_capsule(&mut capsule, observed()).unwrap();
        let durable_len = capsule.len();

        let mut complete = capsule.clone();
        plan.record_phase(
            &mut complete,
            observed(),
            TransactionPhase::Reserved,
            completion(&plan),
            None,
            None,
        )
        .unwrap();
        capsule.extend_from_slice(&complete[durable_len..durable_len + 17]);

        assert_eq!(
            plan.resume(&capsule, observed()).unwrap().phase,
            TransactionPhase::Discovered
        );
        plan.record_phase(
            &mut capsule,
            observed(),
            TransactionPhase::Reserved,
            completion(&plan),
            None,
            None,
        )
        .unwrap();
        assert_eq!(capsule, complete);
        assert_eq!(
            scan_capsule(&capsule, CapsuleLimits::default())
                .unwrap()
                .newest()
                .unwrap()
                .phase,
            TransactionPhase::Reserved
        );
    }

    #[test]
    fn backup_boot_requires_matching_candidate_overlay_verification() {
        let plan = prepared();
        let mut capsule = Vec::new();
        plan.begin_capsule(&mut capsule, observed()).unwrap();
        for phase in [
            TransactionPhase::Reserved,
            TransactionPhase::Relocating,
            TransactionPhase::TargetStaged,
        ] {
            record_success(&plan, &mut capsule, phase);
        }
        assert!(matches!(
            plan.resume(&capsule, observed()).unwrap().next,
            TransactionIntent::VerifyStaging(_)
        ));
        assert!(matches!(
            plan.record_phase(
                &mut capsule,
                observed(),
                TransactionPhase::BackupBootWritten,
                completion(&plan),
                None,
                None,
            ),
            Err(ConversionError::StagingVerificationRequired)
        ));

        let mut bad = staging_verification(&plan);
        bad.candidate_overlay_digest = [0; 32];
        assert!(matches!(
            plan.authorize_backup_boot(&capsule, observed(), bad),
            Err(ConversionError::StagingVerificationMismatch)
        ));
        let good = staging_verification(&plan);
        assert!(matches!(
            plan.authorize_backup_boot(&capsule, observed(), good),
            Ok(TransactionIntent::WriteBackupBoot(_))
        ));
        plan.record_phase(
            &mut capsule,
            observed(),
            TransactionPhase::BackupBootWritten,
            completion(&plan),
            Some(good),
            None,
        )
        .unwrap();
    }

    #[test]
    fn activation_requires_verification_and_finalization_is_rollback_boundary() {
        let plan = prepared();
        let mut capsule = Vec::new();
        plan.begin_capsule(&mut capsule, observed()).unwrap();
        for phase in [
            TransactionPhase::Reserved,
            TransactionPhase::Relocating,
            TransactionPhase::TargetStaged,
            TransactionPhase::BackupBootWritten,
            TransactionPhase::Activated,
        ] {
            record_success(&plan, &mut capsule, phase);
        }
        assert!(matches!(
            plan.record_phase(
                &mut capsule,
                ObservedImage {
                    image: IMAGE,
                    source_evidence_digest: None
                },
                TransactionPhase::Verified,
                completion(&plan),
                None,
                None
            ),
            Err(ConversionError::VerificationRequired)
        ));
        let expected = plan.expected_verification();
        plan.record_phase(
            &mut capsule,
            ObservedImage {
                image: IMAGE,
                source_evidence_digest: None,
            },
            TransactionPhase::Verified,
            completion(&plan),
            None,
            Some(VerificationEvidence {
                target_filesystem: expected.target_filesystem,
                inventory_complete: true,
                object_graph_digest: expected.object_graph_digest,
                plan_digest: expected.plan_digest,
            }),
        )
        .unwrap();
        assert!(matches!(
            plan.rollback_intent(TransactionPhase::Verified),
            Ok(RollbackIntent::RestoreSource { .. })
        ));
        let mut rollback_capsule = capsule.clone();
        plan.record_rollback(
            &mut rollback_capsule,
            observed(),
            RollbackCompletion {
                image: IMAGE,
                plan_digest: plan.plan_digest(),
                applied_rollback_digest: Some(plan.full_rollback_digest),
                health: HealthState::Clean,
                access: AccessState::Offline,
            },
        )
        .unwrap();
        assert_eq!(
            plan.resume(
                &rollback_capsule,
                ObservedImage {
                    image: IMAGE,
                    source_evidence_digest: None,
                },
            )
            .unwrap()
            .phase,
            TransactionPhase::RolledBack
        );
        plan.record_phase(
            &mut capsule,
            ObservedImage {
                image: IMAGE,
                source_evidence_digest: None,
            },
            TransactionPhase::Finalized,
            completion(&plan),
            None,
            None,
        )
        .unwrap();
        assert!(matches!(
            plan.rollback_intent(TransactionPhase::Finalized),
            Err(ConversionError::RollbackBoundaryCrossed { .. })
        ));
    }

    #[test]
    fn activated_rollback_requires_exact_restoration_digest() {
        let plan = prepared();
        let mut capsule = Vec::new();
        plan.begin_capsule(&mut capsule, observed()).unwrap();
        for phase in [
            TransactionPhase::Reserved,
            TransactionPhase::Relocating,
            TransactionPhase::TargetStaged,
            TransactionPhase::BackupBootWritten,
            TransactionPhase::Activated,
        ] {
            record_success(&plan, &mut capsule, phase);
        }
        let bad = RollbackCompletion {
            image: IMAGE,
            plan_digest: plan.plan_digest(),
            applied_rollback_digest: Some([0; 32]),
            health: HealthState::Clean,
            access: AccessState::Offline,
        };
        assert!(matches!(
            plan.record_rollback(&mut capsule, observed(), bad),
            Err(ConversionError::InvalidRollbackEvidence)
        ));
        let good = RollbackCompletion {
            applied_rollback_digest: Some(plan.full_rollback_digest),
            ..bad
        };
        plan.record_rollback(&mut capsule, observed(), good)
            .unwrap();
        assert_eq!(
            plan.resume(
                &capsule,
                ObservedImage {
                    image: IMAGE,
                    source_evidence_digest: None
                }
            )
            .unwrap()
            .phase,
            TransactionPhase::RolledBack
        );
    }

    #[test]
    fn refuses_incomplete_unknown_dirty_mounted_and_stale_evidence() {
        for mutate in 0..5 {
            let mut value = draft();
            match mutate {
                0 => value.preflight.inventory_complete = false,
                1 => value.preflight.allocation_map_complete = false,
                2 => value.preflight.health = HealthState::Unknown,
                3 => value.preflight.access = AccessState::Unknown,
                _ => value.target.filesystem = FileSystem::Unknown,
            }
            assert!(
                PreparedConversion::build(&graph(false), value, ConversionLimits::default())
                    .is_err()
            );
        }
        let plan = prepared();
        let mut capsule = Vec::new();
        assert!(matches!(
            plan.begin_capsule(
                &mut capsule,
                ObservedImage {
                    image: IMAGE,
                    source_evidence_digest: Some([1; 32])
                }
            ),
            Err(ConversionError::StaleSourceEvidence)
        ));
    }

    #[test]
    fn rejects_identity_plan_and_capsule_changes() {
        let plan = prepared();
        let mut capsule = Vec::new();
        plan.begin_capsule(&mut capsule, observed()).unwrap();
        let changed = ObservedImage {
            image: ImageIdentity {
                instance: [1; 32],
                ..IMAGE
            },
            source_evidence_digest: Some([9; 32]),
        };
        assert!(matches!(
            plan.resume(&capsule, changed),
            Err(ConversionError::ImageIdentityChanged)
        ));
        let mut bad_completion = completion(&plan);
        bad_completion.plan_digest = [0; 32];
        assert!(matches!(
            plan.record_phase(
                &mut capsule,
                observed(),
                TransactionPhase::Reserved,
                bad_completion,
                None,
                None
            ),
            Err(ConversionError::PlanChanged)
        ));
        let other = {
            let mut value = draft();
            value.transaction_id = [8; 16];
            PreparedConversion::build(&graph(false), value, ConversionLimits::default()).unwrap()
        };
        assert!(matches!(
            other.resume(&capsule, observed()),
            Err(ConversionError::TransactionIdentityChanged)
        ));
    }

    #[test]
    fn rejects_overlapping_or_unreserved_opaque_writes_and_bad_rollback_ranges() {
        let mut overlap = draft();
        overlap.writes.test_writes_mut().target_staging.push(rw(
            ReservationKind::AllocationMetadata,
            2048,
            4,
        ));
        overlap
            .writes
            .test_writes_mut()
            .target_staging_rollback
            .push(OverlayWrite {
                offset: 2048,
                bytes: vec![0x12; 512],
            });
        assert!(matches!(
            PreparedConversion::build(&graph(false), overlap, ConversionLimits::default()),
            Err(ConversionError::Overlay(
                OverlayError::OverlappingWrites { .. }
            ))
        ));
        let mut unreserved = draft();
        unreserved.writes.test_writes_mut().target_staging[0]
            .write
            .offset = 8192;
        assert!(matches!(
            PreparedConversion::build(&graph(false), unreserved, ConversionLimits::default()),
            Err(ConversionError::WriteNotReserved { .. })
        ));
        let mut rollback = draft();
        rollback.writes.test_writes_mut().activation_rollback[0].offset = 1024;
        assert!(matches!(
            PreparedConversion::build(&graph(false), rollback, ConversionLimits::default()),
            Err(ConversionError::RollbackRangeMismatch)
        ));
        let mut backup_rollback = draft();
        backup_rollback
            .writes
            .test_writes_mut()
            .backup_boot_rollback
            .clear();
        assert!(matches!(
            PreparedConversion::build(&graph(false), backup_rollback, ConversionLimits::default()),
            Err(ConversionError::EmptyWriteSet {
                set: "backup_boot_rollback"
            })
        ));
        let mut staging_rollback = draft();
        staging_rollback
            .writes
            .test_writes_mut()
            .target_staging_rollback[0]
            .offset = 3072;
        assert!(matches!(
            PreparedConversion::build(&graph(false), staging_rollback, ConversionLimits::default()),
            Err(ConversionError::RollbackRangeMismatch)
        ));
    }

    #[test]
    fn rollback_intents_accumulate_every_source_visible_range() {
        let plan = prepared();
        assert_eq!(
            plan.rollback_intent(TransactionPhase::Reserved).unwrap(),
            RollbackIntent::DiscardStaging
        );
        let staged = match plan.rollback_intent(TransactionPhase::Relocating).unwrap() {
            RollbackIntent::RestoreSource { writes, .. } => writes,
            RollbackIntent::DiscardStaging => panic!("target staging is already source-visible"),
        };
        assert_eq!(staged, plan.staging_rollback_overlay().writes());
        assert_eq!(staged.len(), 2);

        let writes = match plan
            .rollback_intent(TransactionPhase::TargetStaged)
            .unwrap()
        {
            RollbackIntent::RestoreSource { writes, .. } => writes,
            RollbackIntent::DiscardStaging => panic!("backup boot is already source-visible"),
        };
        assert_eq!(writes, plan.backup_boot_rollback_overlay().writes());
        assert_eq!(writes.len(), 3);
        assert_eq!(writes[0].offset, 1024);
        assert_eq!(writes[1].offset, 2048);
        assert_eq!(writes[2].offset, 2560);

        let full = match plan
            .rollback_intent(TransactionPhase::BackupBootWritten)
            .unwrap()
        {
            RollbackIntent::RestoreSource { writes, .. } => writes,
            RollbackIntent::DiscardStaging => panic!("activation is already source-visible"),
        };
        assert_eq!(full, plan.rollback_overlay().writes());
        assert_eq!(full.len(), 4);

        let mut staged_capsule = Vec::new();
        plan.begin_capsule(&mut staged_capsule, observed()).unwrap();
        for phase in [
            TransactionPhase::Reserved,
            TransactionPhase::Relocating,
            TransactionPhase::TargetStaged,
        ] {
            record_success(&plan, &mut staged_capsule, phase);
        }
        plan.record_rollback(
            &mut staged_capsule,
            observed(),
            RollbackCompletion {
                image: IMAGE,
                plan_digest: plan.plan_digest(),
                applied_rollback_digest: Some(plan.preactivation_rollback_digest),
                health: HealthState::Clean,
                access: AccessState::Offline,
            },
        )
        .unwrap();

        let mut capsule = Vec::new();
        plan.begin_capsule(&mut capsule, observed()).unwrap();
        for phase in [
            TransactionPhase::Reserved,
            TransactionPhase::Relocating,
            TransactionPhase::TargetStaged,
            TransactionPhase::BackupBootWritten,
        ] {
            record_success(&plan, &mut capsule, phase);
        }
        plan.record_rollback(
            &mut capsule,
            observed(),
            RollbackCompletion {
                image: IMAGE,
                plan_digest: plan.plan_digest(),
                applied_rollback_digest: Some(plan.full_rollback_digest),
                health: HealthState::Clean,
                access: AccessState::Offline,
            },
        )
        .unwrap();
        assert_eq!(
            plan.resume(&capsule, observed()).unwrap().phase,
            TransactionPhase::RolledBack
        );
    }

    #[test]
    fn feature_compatibility_requires_native_support_or_nonempty_escrow_proof() {
        let graph = graph(true);
        let mut missing = draft();
        assert!(matches!(
            PreparedConversion::build(&graph, missing.clone(), ConversionLimits::default()),
            Err(ConversionError::MissingFeatureRule { .. })
        ));
        missing.target.filesystem = FileSystem::ExFat;
        missing.preflight.source_filesystem = FileSystem::Ntfs;
        missing.writes.test_set_filesystem(FileSystem::ExFat);
        missing.target.features = vec![FeatureCompatibility {
            feature: SemanticFeature::AccessControl,
            method: PreservationMethod::Native,
        }];
        assert!(matches!(
            PreparedConversion::build(&graph, missing.clone(), ConversionLimits::default()),
            Err(ConversionError::UnsupportedNativeFeature { .. })
        ));
        missing.target.features[0].method = PreservationMethod::Escrow {
            schema_version: 1,
            payload_digest: [5; 32],
        };
        assert!(PreparedConversion::build(&graph, missing, ConversionLimits::default()).is_ok());
    }

    #[test]
    fn strict_caps_are_checked_before_planning() {
        let limits = ConversionLimits {
            max_total_writes: 1,
            ..ConversionLimits::default()
        };
        assert!(matches!(
            PreparedConversion::build(&graph(false), draft(), limits),
            Err(ConversionError::WriteLimitExceeded { .. })
        ));
        let limits = ConversionLimits {
            max_feature_rules: 0,
            ..ConversionLimits::default()
        };
        assert!(matches!(
            PreparedConversion::build(&graph(false), draft(), limits),
            Err(ConversionError::InvalidLimit { .. })
        ));
        let limits = ConversionLimits {
            capsule: CapsuleLimits {
                max_generations: 0,
                ..CapsuleLimits::default()
            },
            ..ConversionLimits::default()
        };
        assert!(matches!(
            PreparedConversion::build(&graph(false), draft(), limits),
            Err(ConversionError::Capsule(CapsuleError::InvalidLimit { .. }))
        ));

        let limits = ConversionLimits {
            capsule: CapsuleLimits {
                max_generation_bytes: 1,
                ..CapsuleLimits::default()
            },
            ..ConversionLimits::default()
        };
        assert!(matches!(
            PreparedConversion::build(&graph(false), draft(), limits),
            Err(ConversionError::Capsule(
                CapsuleError::GenerationTooLarge { .. }
            ))
        ));

        let limits = ConversionLimits {
            capsule: CapsuleLimits {
                max_capsule_bytes: HEADER_BYTES * 2,
                ..CapsuleLimits::default()
            },
            ..ConversionLimits::default()
        };
        assert!(matches!(
            PreparedConversion::build(&graph(false), draft(), limits),
            Err(ConversionError::Capsule(
                CapsuleError::CapsuleTooLarge { .. }
            ))
        ));
    }

    #[test]
    fn refuses_activation_authorization_for_a_different_target() {
        let mut value = draft();
        value.target.filesystem = FileSystem::ExFat;
        assert!(matches!(
            PreparedConversion::build(&graph(false), value, ConversionLimits::default()),
            Err(ConversionError::ActivationAuthorizationMismatch {
                authorized: FileSystem::Ntfs,
                target: FileSystem::ExFat,
            })
        ));
    }
}
