//! Canonical durable encoding for restartable prepared conversions.
//!
//! This envelope is deliberately distinct from the append-only legacy capsule. A capsule remains
//! rollback/checkpoint evidence only; it cannot supply missing executable-plan or expected-manifest
//! authority. This codec binds both, plus exact recovery bytes, into one independently versioned
//! object suitable for atomic durable storage by a coordinator.

#![allow(dead_code)]

use std::fmt;

use crc32fast::Hasher as Crc32;
use sha2::{Digest, Sha256};

use super::{
    FeatureCompatibility, ImageIdentity, OpaqueWriteSets, PreflightEvidence, PreparedConversion,
    PreservationMethod, ReservedWrite, digest_overlay_writes, digest_plan, digest_source_identity,
    final_writes, full_rollback_writes, preactivation_rollback_writes, staging_rollback_writes,
    validate_initial_capsule_generation, validate_relocation_before_image_ranges,
    validate_required_reservations, validate_rollback_pairing,
    validate_writes_against_reservations,
};
use crate::capsule::{CapsuleError, CapsuleIdentity, CapsuleLimits};
use crate::extent::StreamId;
use crate::geometry::{ByteRange, DestinationReservation, LayoutPlan, Relocation, ReservationKind};
use crate::overlay::{OverlayLimits, OverlayPlan, OverlayWrite};
use crate::recovery::{RecoveryError, RecoveryLimits, decode_recovery_bundle};
use crate::verify::ManifestCommitment;
use crate::{AccessState, FileSystem, HealthState, SemanticFeature};

const MAGIC: &[u8; 8] = b"SCPREP02";
const VERSION: u16 = 2;
const HEADER_BYTES: usize = 576;
const HEADER_CRC_OFFSET: usize = 64;
const SECTION_HEADER_BYTES: usize = 48;
const SECTION_COUNT: usize = 12;
const RESERVED_WRITE_HEADER_BYTES: usize = 24;
const ROLLBACK_WRITE_HEADER_BYTES: usize = 16;

const RESERVATIONS: u16 = 1;
const RELOCATIONS: u16 = 2;
const FREE_RANGES: u16 = 3;
const TARGET_STAGING: u16 = 4;
const BACKUP_BOOT: u16 = 5;
const ACTIVATION: u16 = 6;
const TARGET_STAGING_ROLLBACK: u16 = 7;
const BACKUP_BOOT_ROLLBACK: u16 = 8;
const ACTIVATION_ROLLBACK: u16 = 9;
const RECOVERY_PAYLOAD: u16 = 10;
const TARGET_FEATURES: u16 = 11;
const RELOCATION_DESTINATION_ROLLBACK: u16 = 12;

/// Caller-controlled decode and reconstruction limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_field_names)]
pub(super) struct PreparedEnvelopeLimits {
    pub max_envelope_bytes: usize,
    pub max_entries: usize,
    pub max_write_bytes: usize,
    pub max_recovery_bytes: usize,
    pub max_read_bytes: usize,
    pub max_logical_bytes: u64,
}

impl Default for PreparedEnvelopeLimits {
    fn default() -> Self {
        Self {
            max_envelope_bytes: 2 * 1024 * 1024 * 1024,
            max_entries: 8 * 1024 * 1024,
            max_write_bytes: 1024 * 1024 * 1024,
            max_recovery_bytes: 1024 * 1024 * 1024,
            max_read_bytes: 16 * 1024 * 1024,
            max_logical_bytes: 1_u64 << 50,
        }
    }
}

/// A fully decoded prepared plan and the manifest authority that must accompany restart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DecodedPreparedEnvelope {
    pub prepared: PreparedConversion,
    pub expected_manifest: ManifestCommitment,
}

/// Durable-envelope framing, integrity, canonicality, cap, or reconstruction failure.
#[derive(Debug)]
pub(super) enum PreparedEnvelopeError {
    InvalidLimit { field: &'static str },
    EnvelopeTooLarge { actual: u64, maximum: usize },
    Truncated,
    InvalidMagic,
    UnsupportedVersion { actual: u16 },
    InvalidHeaderLength { actual: u16 },
    InvalidTotalLength { declared: u64, actual: usize },
    NonZeroReserved,
    HeaderCrcMismatch,
    PayloadDigestMismatch,
    InvalidSectionCount { actual: u32 },
    UnexpectedSection { expected: u16, actual: u16 },
    SectionDigestMismatch { section: u16 },
    EntryLimitExceeded { actual: u64, maximum: usize },
    WriteByteLimitExceeded { actual: u64, maximum: usize },
    RecoveryByteLimitExceeded { actual: u64, maximum: usize },
    InvalidFixedSectionLength { section: u16, declared: u64 },
    InvalidSingletonSection { section: u16, count: u32 },
    InvalidEnum { field: &'static str, value: u8 },
    InvalidBooleanFlags { value: u8 },
    InvalidGeometry,
    InvalidCapsuleLimits,
    InvalidPreparedInvariant,
    EmptyWrite { section: u16, offset: u64 },
    RangeOverflow { offset: u64, length: u64 },
    NonCanonicalOrder { section: u16 },
    AllocationFailed,
    ArithmeticOverflow,
    Capsule(CapsuleError),
    Recovery(RecoveryError),
    RecoveryMismatch,
    CommitmentMismatch { field: &'static str },
    Overlay(crate::overlay::OverlayError),
}

impl fmt::Display for PreparedEnvelopeError {
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit { field } => {
                write!(formatter, "prepared-envelope limit {field} is zero")
            }
            Self::EnvelopeTooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "prepared envelope has {actual} bytes, exceeding {maximum}"
                )
            }
            Self::Truncated => formatter.write_str("prepared envelope is truncated"),
            Self::InvalidMagic => formatter.write_str("prepared envelope magic is invalid"),
            Self::UnsupportedVersion { actual } => {
                write!(
                    formatter,
                    "prepared envelope version {actual} is unsupported"
                )
            }
            Self::InvalidHeaderLength { actual } => {
                write!(
                    formatter,
                    "prepared envelope header length {actual} is invalid"
                )
            }
            Self::InvalidTotalLength { declared, actual } => write!(
                formatter,
                "prepared envelope declares {declared} bytes but contains {actual}"
            ),
            Self::NonZeroReserved => {
                formatter.write_str("prepared envelope reserved bytes are nonzero")
            }
            Self::HeaderCrcMismatch => {
                formatter.write_str("prepared envelope header CRC does not match")
            }
            Self::PayloadDigestMismatch => {
                formatter.write_str("prepared envelope payload digest does not match")
            }
            Self::InvalidSectionCount { actual } => {
                write!(
                    formatter,
                    "prepared envelope has invalid section count {actual}"
                )
            }
            Self::UnexpectedSection { expected, actual } => write!(
                formatter,
                "prepared envelope expected section {expected}, found {actual}"
            ),
            Self::SectionDigestMismatch { section } => {
                write!(
                    formatter,
                    "prepared-envelope section {section} digest does not match"
                )
            }
            Self::EntryLimitExceeded { actual, maximum } => {
                write!(
                    formatter,
                    "prepared envelope has {actual} entries, exceeding {maximum}"
                )
            }
            Self::WriteByteLimitExceeded { actual, maximum } => {
                write!(
                    formatter,
                    "prepared envelope has {actual} write bytes, exceeding {maximum}"
                )
            }
            Self::RecoveryByteLimitExceeded { actual, maximum } => {
                write!(
                    formatter,
                    "prepared envelope has {actual} recovery bytes, exceeding {maximum}"
                )
            }
            Self::InvalidFixedSectionLength { section, declared } => write!(
                formatter,
                "prepared-envelope section {section} has invalid fixed length {declared}"
            ),
            Self::InvalidSingletonSection { section, count } => write!(
                formatter,
                "prepared-envelope section {section} has invalid singleton count {count}"
            ),
            Self::InvalidEnum { field, value } => {
                write!(
                    formatter,
                    "prepared envelope {field} value {value} is invalid"
                )
            }
            Self::InvalidBooleanFlags { value } => {
                write!(
                    formatter,
                    "prepared envelope boolean flags {value:#x} are invalid"
                )
            }
            Self::InvalidGeometry => formatter.write_str("prepared envelope geometry is invalid"),
            Self::InvalidCapsuleLimits => {
                formatter.write_str("prepared envelope capsule limits are invalid")
            }
            Self::InvalidPreparedInvariant => {
                formatter.write_str("prepared envelope violates a prepared-plan invariant")
            }
            Self::EmptyWrite { section, offset } => {
                write!(
                    formatter,
                    "prepared-envelope section {section} has an empty write at {offset}"
                )
            }
            Self::RangeOverflow { offset, length } => {
                write!(
                    formatter,
                    "prepared-envelope range {offset}+{length} overflows"
                )
            }
            Self::NonCanonicalOrder { section } => {
                write!(
                    formatter,
                    "prepared-envelope section {section} is not canonically ordered"
                )
            }
            Self::AllocationFailed => {
                formatter.write_str("could not allocate bounded prepared-envelope state")
            }
            Self::ArithmeticOverflow => {
                formatter.write_str("prepared-envelope byte accounting overflowed")
            }
            Self::Capsule(error) => write!(
                formatter,
                "prepared envelope cannot be stored as capsule generation zero: {error}"
            ),
            Self::Recovery(error) => write!(
                formatter,
                "prepared-envelope recovery payload is invalid: {error}"
            ),
            Self::RecoveryMismatch => formatter
                .write_str("prepared-envelope recovery bytes disagree with rollback sections"),
            Self::CommitmentMismatch { field } => {
                write!(
                    formatter,
                    "prepared-envelope {field} commitment does not match decoded data"
                )
            }
            Self::Overlay(error) => write!(
                formatter,
                "prepared-envelope overlay reconstruction failed: {error}"
            ),
        }
    }
}

impl std::error::Error for PreparedEnvelopeError {}

impl From<CapsuleError> for PreparedEnvelopeError {
    fn from(value: CapsuleError) -> Self {
        Self::Capsule(value)
    }
}

impl From<RecoveryError> for PreparedEnvelopeError {
    fn from(value: RecoveryError) -> Self {
        Self::Recovery(value)
    }
}

impl From<crate::overlay::OverlayError> for PreparedEnvelopeError {
    fn from(value: crate::overlay::OverlayError) -> Self {
        Self::Overlay(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EnvelopeState {
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
    relocation_destination_before_images: Vec<OverlayWrite>,
    recovery_payload: Vec<u8>,
    capsule_limits: CapsuleLimits,
}

impl EnvelopeState {
    fn from_prepared(prepared: &PreparedConversion) -> Self {
        Self {
            identity: prepared.identity,
            preflight: prepared.preflight,
            target_filesystem: prepared.target_filesystem,
            target_features: prepared.target_features.clone(),
            source_graph_digest: prepared.source_graph_digest,
            target_graph_digest: prepared.target_graph_digest,
            plan_digest: prepared.plan_digest,
            candidate_overlay_digest: prepared.candidate_overlay_digest,
            relocation_rollback_digest: prepared.relocation_rollback_digest,
            staging_rollback_digest: prepared.staging_rollback_digest,
            preactivation_rollback_digest: prepared.preactivation_rollback_digest,
            full_rollback_digest: prepared.full_rollback_digest,
            reservations: prepared.reservations.clone(),
            layout: prepared.layout.clone(),
            writes: prepared.writes.clone(),
            relocation_destination_before_images: prepared
                .relocation_rollback_overlay
                .writes()
                .to_vec(),
            recovery_payload: prepared.recovery_payload.clone(),
            capsule_limits: prepared.capsule_limits,
        }
    }

    fn into_decoded(
        self,
        limits: PreparedEnvelopeLimits,
    ) -> Result<DecodedPreparedEnvelope, PreparedEnvelopeError> {
        validate_state(&self, limits)?;
        let overlay_limits = OverlayLimits {
            max_writes: limits.max_entries,
            max_replacement_bytes: limits.max_write_bytes,
            max_read_bytes: limits.max_read_bytes,
        };
        let image_bytes = self.preflight.image.image_bytes;
        let sector_bytes = self.preflight.sector_bytes;
        let candidate_overlay = OverlayPlan::build(
            image_bytes,
            sector_bytes,
            final_writes(&self.writes),
            overlay_limits,
        )?;
        let staging_rollback_overlay = OverlayPlan::build(
            image_bytes,
            sector_bytes,
            staging_rollback_writes(&self.relocation_destination_before_images, &self.writes),
            overlay_limits,
        )?;
        let preactivation_rollback_overlay = OverlayPlan::build(
            image_bytes,
            sector_bytes,
            preactivation_rollback_writes(&self.relocation_destination_before_images, &self.writes),
            overlay_limits,
        )?;
        let full_rollback_overlay = OverlayPlan::build(
            image_bytes,
            sector_bytes,
            full_rollback_writes(&self.relocation_destination_before_images, &self.writes),
            overlay_limits,
        )?;
        let relocation_rollback_overlay = OverlayPlan::build(
            image_bytes,
            sector_bytes,
            self.relocation_destination_before_images,
            overlay_limits,
        )?;
        let expected_manifest = self.preflight.source_manifest_commitment;
        Ok(DecodedPreparedEnvelope {
            prepared: PreparedConversion {
                identity: self.identity,
                preflight: self.preflight,
                target_filesystem: self.target_filesystem,
                target_features: self.target_features,
                source_graph_digest: self.source_graph_digest,
                target_graph_digest: self.target_graph_digest,
                plan_digest: self.plan_digest,
                candidate_overlay_digest: self.candidate_overlay_digest,
                relocation_rollback_digest: self.relocation_rollback_digest,
                staging_rollback_digest: self.staging_rollback_digest,
                preactivation_rollback_digest: self.preactivation_rollback_digest,
                full_rollback_digest: self.full_rollback_digest,
                reservations: self.reservations,
                layout: self.layout,
                writes: self.writes,
                candidate_overlay,
                relocation_rollback_overlay,
                staging_rollback_overlay,
                preactivation_rollback_overlay,
                full_rollback_overlay,
                recovery_payload: self.recovery_payload,
                prepared_envelope: Vec::new(),
                capsule_limits: self.capsule_limits,
            },
            expected_manifest,
        })
    }
}

#[derive(Debug, Clone)]
struct EncodedSection {
    tag: u16,
    count: u32,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
struct SectionMeta {
    tag: u16,
    count: u32,
    start: usize,
    end: usize,
}

/// Encodes immutable activation authority and recovery evidence deterministically.
pub(super) fn encode_prepared_envelope(
    prepared: &PreparedConversion,
    limits: PreparedEnvelopeLimits,
) -> Result<Vec<u8>, PreparedEnvelopeError> {
    encode_state(&EnvelopeState::from_prepared(prepared), limits)
}

/// Decodes and reconstructs a prepared plan without consulting the legacy capsule.
pub(super) fn decode_prepared_envelope(
    bytes: &[u8],
    limits: PreparedEnvelopeLimits,
) -> Result<DecodedPreparedEnvelope, PreparedEnvelopeError> {
    let mut decoded = decode_state(bytes, limits)?.into_decoded(limits)?;
    decoded.prepared.prepared_envelope = copy_bounded(bytes)?;
    Ok(decoded)
}

fn encode_state(
    state: &EnvelopeState,
    limits: PreparedEnvelopeLimits,
) -> Result<Vec<u8>, PreparedEnvelopeError> {
    validate_limits(limits)?;
    validate_state(state, limits)?;
    let sections = encode_sections(state)?;
    let payload_bytes = sections.iter().try_fold(0_usize, |sum, section| {
        sum.checked_add(SECTION_HEADER_BYTES)
            .and_then(|value| value.checked_add(section.bytes.len()))
            .ok_or(PreparedEnvelopeError::ArithmeticOverflow)
    })?;
    let total_bytes = HEADER_BYTES
        .checked_add(payload_bytes)
        .ok_or(PreparedEnvelopeError::ArithmeticOverflow)?;
    ensure_envelope_cap(u64::try_from(total_bytes).unwrap_or(u64::MAX), limits)?;
    validate_envelope_generation(total_bytes, state.capsule_limits)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(total_bytes)
        .map_err(|_| PreparedEnvelopeError::AllocationFailed)?;
    output.resize(HEADER_BYTES, 0);
    for section in &sections {
        output.extend_from_slice(&section.tag.to_le_bytes());
        output.extend_from_slice(&[0_u8; 2]);
        output.extend_from_slice(&section.count.to_le_bytes());
        output.extend_from_slice(
            &u64::try_from(section.bytes.len())
                .map_err(|_| PreparedEnvelopeError::ArithmeticOverflow)?
                .to_le_bytes(),
        );
        output.extend_from_slice(&sha256(&section.bytes));
        output.extend_from_slice(&section.bytes);
    }
    let payload_digest = sha256(&output[HEADER_BYTES..]);
    encode_header(
        &mut output[..HEADER_BYTES],
        state,
        total_bytes,
        payload_digest,
    )?;
    Ok(output)
}

fn decode_state(
    bytes: &[u8],
    limits: PreparedEnvelopeLimits,
) -> Result<EnvelopeState, PreparedEnvelopeError> {
    validate_limits(limits)?;
    ensure_envelope_cap(u64::try_from(bytes.len()).unwrap_or(u64::MAX), limits)?;
    if bytes.len() < HEADER_BYTES {
        return Err(PreparedEnvelopeError::Truncated);
    }
    validate_header(bytes)?;
    let total = read_u64(bytes, 16)?;
    if total != u64::try_from(bytes.len()).unwrap_or(u64::MAX) {
        return Err(PreparedEnvelopeError::InvalidTotalLength {
            declared: total,
            actual: bytes.len(),
        });
    }
    let payload_len = read_u64(bytes, 24)?;
    if payload_len != u64::try_from(bytes.len() - HEADER_BYTES).unwrap_or(u64::MAX) {
        return Err(PreparedEnvelopeError::InvalidTotalLength {
            declared: payload_len,
            actual: bytes.len() - HEADER_BYTES,
        });
    }
    if sha256(&bytes[HEADER_BYTES..]) != array_32(bytes, 32)? {
        return Err(PreparedEnvelopeError::PayloadDigestMismatch);
    }
    let section_count = read_u32(bytes, 488)?;
    if section_count
        != u32::try_from(SECTION_COUNT).map_err(|_| PreparedEnvelopeError::ArithmeticOverflow)?
    {
        return Err(PreparedEnvelopeError::InvalidSectionCount {
            actual: section_count,
        });
    }
    let header = decode_header(bytes)?;
    validate_envelope_generation(bytes.len(), header.capsule_limits)?;
    let sections = scan_sections(bytes, limits)?;
    let reservations = decode_reservations(section_bytes(bytes, sections[0]), sections[0].count)?;
    let relocations = decode_relocations(section_bytes(bytes, sections[1]), sections[1].count)?;
    let free_after_staging = decode_ranges(section_bytes(bytes, sections[2]), sections[2].count)?;
    let target_staging =
        decode_reserved_writes(section_bytes(bytes, sections[3]), sections[3], limits)?;
    let backup_boot =
        decode_reserved_writes(section_bytes(bytes, sections[4]), sections[4], limits)?;
    let activation =
        decode_reserved_writes(section_bytes(bytes, sections[5]), sections[5], limits)?;
    let target_staging_rollback =
        decode_rollback_writes(section_bytes(bytes, sections[6]), sections[6], limits)?;
    let backup_boot_rollback =
        decode_rollback_writes(section_bytes(bytes, sections[7]), sections[7], limits)?;
    let activation_rollback =
        decode_rollback_writes(section_bytes(bytes, sections[8]), sections[8], limits)?;
    let recovery_payload = copy_bounded(section_bytes(bytes, sections[9]))?;
    let relocation_destination_before_images =
        decode_rollback_writes(section_bytes(bytes, sections[11]), sections[11], limits)?;
    let state = EnvelopeState {
        identity: header.identity,
        preflight: header.preflight,
        target_filesystem: header.target_filesystem,
        target_features: decode_target_features(
            section_bytes(bytes, sections[10]),
            sections[10].count,
        )?,
        source_graph_digest: header.source_graph_digest,
        target_graph_digest: header.target_graph_digest,
        plan_digest: header.plan_digest,
        candidate_overlay_digest: header.candidate_overlay_digest,
        relocation_rollback_digest: header.relocation_rollback_digest,
        staging_rollback_digest: header.staging_rollback_digest,
        preactivation_rollback_digest: header.preactivation_rollback_digest,
        full_rollback_digest: header.full_rollback_digest,
        reservations,
        layout: LayoutPlan {
            relocations,
            materializations: Vec::new(),
            free_after_staging,
            relocated_bytes: header.relocated_bytes,
            materialized_bytes: 0,
            largest_free_range: header.largest_free_range,
        },
        writes: OpaqueWriteSets {
            target_staging,
            backup_boot,
            activation,
            target_staging_rollback,
            backup_boot_rollback,
            activation_rollback,
        },
        relocation_destination_before_images,
        recovery_payload,
        capsule_limits: header.capsule_limits,
    };
    validate_state(&state, limits)?;
    Ok(state)
}

#[derive(Debug)]
struct HeaderState {
    identity: CapsuleIdentity,
    preflight: PreflightEvidence,
    target_filesystem: FileSystem,
    source_graph_digest: [u8; 32],
    target_graph_digest: [u8; 32],
    plan_digest: [u8; 32],
    candidate_overlay_digest: [u8; 32],
    relocation_rollback_digest: [u8; 32],
    staging_rollback_digest: [u8; 32],
    preactivation_rollback_digest: [u8; 32],
    full_rollback_digest: [u8; 32],
    relocated_bytes: u64,
    largest_free_range: u64,
    capsule_limits: CapsuleLimits,
}

fn encode_header(
    header: &mut [u8],
    state: &EnvelopeState,
    total_bytes: usize,
    payload_digest: [u8; 32],
) -> Result<(), PreparedEnvelopeError> {
    header[..8].copy_from_slice(MAGIC);
    put_u16(header, 8, VERSION);
    put_u16(
        header,
        10,
        u16::try_from(HEADER_BYTES).map_err(|_| PreparedEnvelopeError::ArithmeticOverflow)?,
    );
    put_u64(
        header,
        16,
        u64::try_from(total_bytes).map_err(|_| PreparedEnvelopeError::ArithmeticOverflow)?,
    );
    put_u64(
        header,
        24,
        u64::try_from(total_bytes - HEADER_BYTES)
            .map_err(|_| PreparedEnvelopeError::ArithmeticOverflow)?,
    );
    header[32..64].copy_from_slice(&payload_digest);
    header[72..88].copy_from_slice(&state.identity.transaction_id);
    header[88..120].copy_from_slice(&state.identity.source_digest);
    header[120..152].copy_from_slice(&state.preflight.image.instance);
    put_u64(header, 152, state.preflight.image.image_bytes);
    header[160..192].copy_from_slice(&state.preflight.source_evidence_digest);
    header[192..224].copy_from_slice(&state.source_graph_digest);
    header[224..256].copy_from_slice(&state.plan_digest);
    header[256..288].copy_from_slice(&state.candidate_overlay_digest);
    header[288..320].copy_from_slice(&state.staging_rollback_digest);
    header[320..352].copy_from_slice(&state.preactivation_rollback_digest);
    header[352..384].copy_from_slice(&state.full_rollback_digest);
    let manifest = state.preflight.source_manifest_commitment;
    header[384..416].copy_from_slice(&manifest.digest());
    put_u64(header, 416, manifest.logical_bytes_hashed());
    put_u32(header, 424, state.preflight.sector_bytes);
    header[428] = filesystem_key(state.preflight.source_filesystem)?;
    header[429] = filesystem_key(state.target_filesystem)?;
    header[430] = health_key(state.preflight.health);
    header[431] = access_key(state.preflight.access);
    put_u64(header, 432, state.preflight.allocation_alignment);
    header[440] = u8::from(state.preflight.inventory_complete)
        | (u8::from(state.preflight.allocation_map_complete) << 1);
    put_u64(header, 448, state.layout.relocated_bytes);
    put_u64(header, 456, state.layout.largest_free_range);
    put_u64(
        header,
        464,
        usize_u64(state.capsule_limits.max_capsule_bytes)?,
    );
    put_u64(
        header,
        472,
        usize_u64(state.capsule_limits.max_generation_bytes)?,
    );
    put_u64(
        header,
        480,
        usize_u64(state.capsule_limits.max_generations)?,
    );
    put_u32(
        header,
        488,
        u32::try_from(SECTION_COUNT).map_err(|_| PreparedEnvelopeError::ArithmeticOverflow)?,
    );
    put_u64(header, 492, manifest.object_count());
    header[500..532].copy_from_slice(&state.target_graph_digest);
    header[532..564].copy_from_slice(&state.relocation_rollback_digest);
    let crc = header_crc(header);
    put_u32(header, HEADER_CRC_OFFSET, crc);
    Ok(())
}

fn validate_header(bytes: &[u8]) -> Result<(), PreparedEnvelopeError> {
    if &bytes[..8] != MAGIC {
        return Err(PreparedEnvelopeError::InvalidMagic);
    }
    let version = read_u16(bytes, 8)?;
    if version != VERSION {
        return Err(PreparedEnvelopeError::UnsupportedVersion { actual: version });
    }
    let header_len = read_u16(bytes, 10)?;
    if usize::from(header_len) != HEADER_BYTES {
        return Err(PreparedEnvelopeError::InvalidHeaderLength { actual: header_len });
    }
    if bytes[12..16]
        .iter()
        .chain(&bytes[68..72])
        .chain(&bytes[441..448])
        .chain(&bytes[564..HEADER_BYTES])
        .any(|byte| *byte != 0)
    {
        return Err(PreparedEnvelopeError::NonZeroReserved);
    }
    if read_u32(bytes, HEADER_CRC_OFFSET)? != header_crc(&bytes[..HEADER_BYTES]) {
        return Err(PreparedEnvelopeError::HeaderCrcMismatch);
    }
    Ok(())
}

fn decode_header(bytes: &[u8]) -> Result<HeaderState, PreparedEnvelopeError> {
    let flags = bytes[440];
    if flags & !0x03 != 0 {
        return Err(PreparedEnvelopeError::InvalidBooleanFlags { value: flags });
    }
    let capsule_limits = CapsuleLimits {
        max_capsule_bytes: read_usize(bytes, 464)?,
        max_generation_bytes: read_usize(bytes, 472)?,
        max_generations: read_usize(bytes, 480)?,
    };
    Ok(HeaderState {
        identity: CapsuleIdentity {
            transaction_id: array_16(bytes, 72)?,
            source_digest: array_32(bytes, 88)?,
        },
        preflight: PreflightEvidence {
            image: ImageIdentity {
                instance: array_32(bytes, 120)?,
                image_bytes: read_u64(bytes, 152)?,
            },
            source_filesystem: decode_filesystem(bytes[428], "source filesystem")?,
            source_evidence_digest: array_32(bytes, 160)?,
            source_manifest_commitment: ManifestCommitment::from_validated_parts(
                array_32(bytes, 384)?,
                read_u64(bytes, 416)?,
                read_u64(bytes, 492)?,
            ),
            sector_bytes: read_u32(bytes, 424)?,
            allocation_alignment: read_u64(bytes, 432)?,
            inventory_complete: flags & 1 != 0,
            allocation_map_complete: flags & 2 != 0,
            health: decode_health(bytes[430])?,
            access: decode_access(bytes[431])?,
        },
        target_filesystem: decode_filesystem(bytes[429], "target filesystem")?,
        source_graph_digest: array_32(bytes, 192)?,
        target_graph_digest: array_32(bytes, 500)?,
        plan_digest: array_32(bytes, 224)?,
        candidate_overlay_digest: array_32(bytes, 256)?,
        relocation_rollback_digest: array_32(bytes, 532)?,
        staging_rollback_digest: array_32(bytes, 288)?,
        preactivation_rollback_digest: array_32(bytes, 320)?,
        full_rollback_digest: array_32(bytes, 352)?,
        relocated_bytes: read_u64(bytes, 448)?,
        largest_free_range: read_u64(bytes, 456)?,
        capsule_limits,
    })
}

fn encode_sections(
    state: &EnvelopeState,
) -> Result<[EncodedSection; SECTION_COUNT], PreparedEnvelopeError> {
    Ok([
        fixed_section(RESERVATIONS, &state.reservations, encode_reservation)?,
        fixed_section(RELOCATIONS, &state.layout.relocations, encode_relocation)?,
        fixed_section(FREE_RANGES, &state.layout.free_after_staging, encode_range)?,
        reserved_write_section(TARGET_STAGING, &state.writes.target_staging)?,
        reserved_write_section(BACKUP_BOOT, &state.writes.backup_boot)?,
        reserved_write_section(ACTIVATION, &state.writes.activation)?,
        rollback_write_section(
            TARGET_STAGING_ROLLBACK,
            &state.writes.target_staging_rollback,
        )?,
        rollback_write_section(BACKUP_BOOT_ROLLBACK, &state.writes.backup_boot_rollback)?,
        rollback_write_section(ACTIVATION_ROLLBACK, &state.writes.activation_rollback)?,
        EncodedSection {
            tag: RECOVERY_PAYLOAD,
            count: 1,
            bytes: state.recovery_payload.clone(),
        },
        fixed_section(
            TARGET_FEATURES,
            &state.target_features,
            encode_target_feature,
        )?,
        rollback_write_section(
            RELOCATION_DESTINATION_ROLLBACK,
            &state.relocation_destination_before_images,
        )?,
    ])
}

fn fixed_section<T>(
    tag: u16,
    values: &[T],
    encode: fn(&T, &mut Vec<u8>),
) -> Result<EncodedSection, PreparedEnvelopeError> {
    let mut bytes = Vec::new();
    for value in values {
        encode(value, &mut bytes);
    }
    Ok(EncodedSection {
        tag,
        count: u32::try_from(values.len())
            .map_err(|_| PreparedEnvelopeError::ArithmeticOverflow)?,
        bytes,
    })
}

fn reserved_write_section(
    tag: u16,
    writes: &[ReservedWrite],
) -> Result<EncodedSection, PreparedEnvelopeError> {
    let mut bytes = Vec::new();
    for value in writes {
        bytes.push(reservation_kind_key(value.reservation_kind));
        bytes.extend_from_slice(&[0_u8; 7]);
        bytes.extend_from_slice(&value.write.offset.to_le_bytes());
        bytes.extend_from_slice(&usize_u64(value.write.bytes.len())?.to_le_bytes());
        bytes.extend_from_slice(&value.write.bytes);
    }
    Ok(EncodedSection {
        tag,
        count: u32::try_from(writes.len())
            .map_err(|_| PreparedEnvelopeError::ArithmeticOverflow)?,
        bytes,
    })
}

fn rollback_write_section(
    tag: u16,
    writes: &[OverlayWrite],
) -> Result<EncodedSection, PreparedEnvelopeError> {
    let mut bytes = Vec::new();
    for value in writes {
        bytes.extend_from_slice(&value.offset.to_le_bytes());
        bytes.extend_from_slice(&usize_u64(value.bytes.len())?.to_le_bytes());
        bytes.extend_from_slice(&value.bytes);
    }
    Ok(EncodedSection {
        tag,
        count: u32::try_from(writes.len())
            .map_err(|_| PreparedEnvelopeError::ArithmeticOverflow)?,
        bytes,
    })
}

#[allow(clippy::too_many_lines)]
fn scan_sections(
    bytes: &[u8],
    limits: PreparedEnvelopeLimits,
) -> Result<[SectionMeta; SECTION_COUNT], PreparedEnvelopeError> {
    let mut cursor = HEADER_BYTES;
    let mut entries = 0_u64;
    let mut write_bytes = 0_u64;
    let mut metas = [SectionMeta {
        tag: 0,
        count: 0,
        start: 0,
        end: 0,
    }; SECTION_COUNT];
    let section_count =
        u16::try_from(SECTION_COUNT).map_err(|_| PreparedEnvelopeError::ArithmeticOverflow)?;
    for (index, expected) in (1_u16..=section_count).enumerate() {
        let header_end = cursor
            .checked_add(SECTION_HEADER_BYTES)
            .ok_or(PreparedEnvelopeError::ArithmeticOverflow)?;
        if header_end > bytes.len() {
            return Err(PreparedEnvelopeError::Truncated);
        }
        let tag = read_u16(bytes, cursor)?;
        if tag != expected {
            return Err(PreparedEnvelopeError::UnexpectedSection {
                expected,
                actual: tag,
            });
        }
        if bytes[cursor + 2..cursor + 4].iter().any(|byte| *byte != 0) {
            return Err(PreparedEnvelopeError::NonZeroReserved);
        }
        let count = read_u32(bytes, cursor + 4)?;
        let length = read_u64(bytes, cursor + 8)?;
        if tag == RECOVERY_PAYLOAD {
            if count != 1 {
                return Err(PreparedEnvelopeError::InvalidSingletonSection {
                    section: tag,
                    count,
                });
            }
            if length > usize_u64(limits.max_recovery_bytes)? {
                return Err(PreparedEnvelopeError::RecoveryByteLimitExceeded {
                    actual: length,
                    maximum: limits.max_recovery_bytes,
                });
            }
        } else {
            entries = entries
                .checked_add(u64::from(count))
                .ok_or(PreparedEnvelopeError::ArithmeticOverflow)?;
            if entries > usize_u64(limits.max_entries)? {
                return Err(PreparedEnvelopeError::EntryLimitExceeded {
                    actual: entries,
                    maximum: limits.max_entries,
                });
            }
        }
        let data_start = header_end;
        let data_end_u64 = usize_u64(data_start)?
            .checked_add(length)
            .ok_or(PreparedEnvelopeError::ArithmeticOverflow)?;
        let data_end =
            usize::try_from(data_end_u64).map_err(|_| PreparedEnvelopeError::Truncated)?;
        if data_end > bytes.len() {
            return Err(PreparedEnvelopeError::Truncated);
        }
        if sha256(&bytes[data_start..data_end]) != array_32(bytes, cursor + 16)? {
            return Err(PreparedEnvelopeError::SectionDigestMismatch { section: tag });
        }
        if matches!(
            tag,
            TARGET_STAGING
                | BACKUP_BOOT
                | ACTIVATION
                | TARGET_STAGING_ROLLBACK
                | BACKUP_BOOT_ROLLBACK
                | ACTIVATION_ROLLBACK
                | RELOCATION_DESTINATION_ROLLBACK
        ) {
            let header_bytes = if matches!(tag, TARGET_STAGING | BACKUP_BOOT | ACTIVATION) {
                RESERVED_WRITE_HEADER_BYTES as u64
            } else {
                ROLLBACK_WRITE_HEADER_BYTES as u64
            };
            let entry_headers = u64::from(count)
                .checked_mul(header_bytes)
                .ok_or(PreparedEnvelopeError::ArithmeticOverflow)?;
            let payload_bytes = length.checked_sub(entry_headers).ok_or(
                PreparedEnvelopeError::InvalidFixedSectionLength {
                    section: tag,
                    declared: length,
                },
            )?;
            write_bytes = write_bytes
                .checked_add(payload_bytes)
                .ok_or(PreparedEnvelopeError::ArithmeticOverflow)?;
            if write_bytes > usize_u64(limits.max_write_bytes)? {
                return Err(PreparedEnvelopeError::WriteByteLimitExceeded {
                    actual: write_bytes,
                    maximum: limits.max_write_bytes,
                });
            }
        }
        validate_fixed_section_len(tag, count, length)?;
        metas[index] = SectionMeta {
            tag,
            count,
            start: data_start,
            end: data_end,
        };
        cursor = data_end;
    }
    if cursor != bytes.len() {
        return Err(PreparedEnvelopeError::InvalidTotalLength {
            declared: usize_u64(cursor)?,
            actual: bytes.len(),
        });
    }
    Ok(metas)
}

fn validate_fixed_section_len(
    tag: u16,
    count: u32,
    length: u64,
) -> Result<(), PreparedEnvelopeError> {
    let unit = match tag {
        RESERVATIONS => Some(24_u64),
        RELOCATIONS => Some(48),
        FREE_RANGES => Some(16),
        TARGET_FEATURES => Some(36),
        _ => None,
    };
    if let Some(unit) = unit {
        let expected = u64::from(count)
            .checked_mul(unit)
            .ok_or(PreparedEnvelopeError::ArithmeticOverflow)?;
        if length != expected {
            return Err(PreparedEnvelopeError::InvalidFixedSectionLength {
                section: tag,
                declared: length,
            });
        }
    }
    Ok(())
}

fn decode_reservations(
    bytes: &[u8],
    count: u32,
) -> Result<Vec<DestinationReservation>, PreparedEnvelopeError> {
    let mut output = bounded_vec(count)?;
    for chunk in bytes.chunks_exact(24) {
        if chunk[17..24].iter().any(|byte| *byte != 0) {
            return Err(PreparedEnvelopeError::NonZeroReserved);
        }
        output.push(DestinationReservation {
            range: ByteRange {
                offset: read_u64(chunk, 0)?,
                length: read_u64(chunk, 8)?,
            },
            kind: decode_reservation_kind(chunk[16])?,
        });
    }
    ensure_order(&output, RESERVATIONS, |value| {
        (
            value.range.offset,
            value.range.length,
            reservation_kind_key(value.kind),
        )
    })?;
    Ok(output)
}

fn decode_relocations(bytes: &[u8], count: u32) -> Result<Vec<Relocation>, PreparedEnvelopeError> {
    let mut output = bounded_vec(count)?;
    for chunk in bytes.chunks_exact(48) {
        output.push(Relocation {
            stream: StreamId(read_u64(chunk, 0)?),
            logical_offset: read_u64(chunk, 8)?,
            source: ByteRange {
                offset: read_u64(chunk, 16)?,
                length: read_u64(chunk, 24)?,
            },
            destination: ByteRange {
                offset: read_u64(chunk, 32)?,
                length: read_u64(chunk, 40)?,
            },
        });
    }
    ensure_order(&output, RELOCATIONS, |value| {
        (value.source.offset, value.stream.0, value.logical_offset)
    })?;
    Ok(output)
}

fn decode_ranges(bytes: &[u8], count: u32) -> Result<Vec<ByteRange>, PreparedEnvelopeError> {
    let mut output = bounded_vec(count)?;
    for chunk in bytes.chunks_exact(16) {
        output.push(ByteRange {
            offset: read_u64(chunk, 0)?,
            length: read_u64(chunk, 8)?,
        });
    }
    ensure_order(&output, FREE_RANGES, |value| (value.offset, value.length))?;
    Ok(output)
}

fn decode_reserved_writes(
    bytes: &[u8],
    meta: SectionMeta,
    limits: PreparedEnvelopeLimits,
) -> Result<Vec<ReservedWrite>, PreparedEnvelopeError> {
    let mut output = bounded_vec(meta.count)?;
    let mut cursor = 0_usize;
    let mut payload = 0_u64;
    for _ in 0..meta.count {
        let header_end = cursor
            .checked_add(RESERVED_WRITE_HEADER_BYTES)
            .ok_or(PreparedEnvelopeError::ArithmeticOverflow)?;
        if header_end > bytes.len() {
            return Err(PreparedEnvelopeError::Truncated);
        }
        if bytes[cursor + 1..cursor + 8].iter().any(|byte| *byte != 0) {
            return Err(PreparedEnvelopeError::NonZeroReserved);
        }
        let offset = read_u64(bytes, cursor + 8)?;
        let length = read_u64(bytes, cursor + 16)?;
        let data_end = bounded_write_end(
            bytes,
            header_end,
            offset,
            length,
            meta.tag,
            &mut payload,
            limits,
        )?;
        output.push(ReservedWrite {
            reservation_kind: decode_reservation_kind(bytes[cursor])?,
            write: OverlayWrite {
                offset,
                bytes: copy_bounded(&bytes[header_end..data_end])?,
            },
        });
        cursor = data_end;
    }
    if cursor != bytes.len() {
        return Err(PreparedEnvelopeError::InvalidFixedSectionLength {
            section: meta.tag,
            declared: usize_u64(bytes.len())?,
        });
    }
    ensure_order(&output, meta.tag, |value| {
        (
            value.write.offset,
            reservation_kind_key(value.reservation_kind),
        )
    })?;
    Ok(output)
}

fn decode_rollback_writes(
    bytes: &[u8],
    meta: SectionMeta,
    limits: PreparedEnvelopeLimits,
) -> Result<Vec<OverlayWrite>, PreparedEnvelopeError> {
    let mut output = bounded_vec(meta.count)?;
    let mut cursor = 0_usize;
    let mut payload = 0_u64;
    for _ in 0..meta.count {
        let header_end = cursor
            .checked_add(ROLLBACK_WRITE_HEADER_BYTES)
            .ok_or(PreparedEnvelopeError::ArithmeticOverflow)?;
        if header_end > bytes.len() {
            return Err(PreparedEnvelopeError::Truncated);
        }
        let offset = read_u64(bytes, cursor)?;
        let length = read_u64(bytes, cursor + 8)?;
        let data_end = bounded_write_end(
            bytes,
            header_end,
            offset,
            length,
            meta.tag,
            &mut payload,
            limits,
        )?;
        output.push(OverlayWrite {
            offset,
            bytes: copy_bounded(&bytes[header_end..data_end])?,
        });
        cursor = data_end;
    }
    if cursor != bytes.len() {
        return Err(PreparedEnvelopeError::InvalidFixedSectionLength {
            section: meta.tag,
            declared: usize_u64(bytes.len())?,
        });
    }
    ensure_order(&output, meta.tag, |value| value.offset)?;
    Ok(output)
}

fn bounded_write_end(
    bytes: &[u8],
    start: usize,
    offset: u64,
    length: u64,
    section: u16,
    payload: &mut u64,
    limits: PreparedEnvelopeLimits,
) -> Result<usize, PreparedEnvelopeError> {
    if length == 0 {
        return Err(PreparedEnvelopeError::EmptyWrite { section, offset });
    }
    offset
        .checked_add(length)
        .ok_or(PreparedEnvelopeError::RangeOverflow { offset, length })?;
    *payload = payload
        .checked_add(length)
        .ok_or(PreparedEnvelopeError::ArithmeticOverflow)?;
    if *payload > usize_u64(limits.max_write_bytes)? {
        return Err(PreparedEnvelopeError::WriteByteLimitExceeded {
            actual: *payload,
            maximum: limits.max_write_bytes,
        });
    }
    let end = usize_u64(start)?
        .checked_add(length)
        .ok_or(PreparedEnvelopeError::ArithmeticOverflow)?;
    let end = usize::try_from(end).map_err(|_| PreparedEnvelopeError::Truncated)?;
    if end > bytes.len() {
        return Err(PreparedEnvelopeError::Truncated);
    }
    Ok(end)
}

#[allow(clippy::too_many_lines)]
fn validate_state(
    state: &EnvelopeState,
    limits: PreparedEnvelopeLimits,
) -> Result<(), PreparedEnvelopeError> {
    validate_limits(limits)?;
    if state.preflight.image.image_bytes == 0
        || state.preflight.sector_bytes == 0
        || !state.preflight.sector_bytes.is_power_of_two()
        || state.preflight.allocation_alignment == 0
        || !state.preflight.allocation_alignment.is_power_of_two()
        || state.preflight.source_filesystem == FileSystem::Unknown
        || state.target_filesystem == FileSystem::Unknown
        || state.preflight.source_filesystem == state.target_filesystem
        || !state.preflight.inventory_complete
        || !state.preflight.allocation_map_complete
        || state.preflight.health != HealthState::Clean
        || state.preflight.access != AccessState::Offline
    {
        return Err(PreparedEnvelopeError::InvalidGeometry);
    }
    if state.capsule_limits.max_capsule_bytes == 0
        || state.capsule_limits.max_generation_bytes == 0
        || state.capsule_limits.max_generations == 0
    {
        return Err(PreparedEnvelopeError::InvalidCapsuleLimits);
    }
    validate_counts_and_bytes(state, limits)?;
    validate_ranges(state)?;
    validate_target_features(&state.target_features)?;
    validate_required_reservations(&state.reservations)
        .map_err(|_| PreparedEnvelopeError::InvalidPreparedInvariant)?;
    validate_writes_against_reservations(&state.writes, &state.reservations)
        .map_err(|_| PreparedEnvelopeError::InvalidPreparedInvariant)?;
    validate_rollback_pairing(&state.writes)
        .map_err(|_| PreparedEnvelopeError::InvalidPreparedInvariant)?;
    validate_relocation_before_image_ranges(
        &state.layout,
        &state.relocation_destination_before_images,
    )
    .map_err(|_| PreparedEnvelopeError::InvalidPreparedInvariant)?;
    let manifest = state.preflight.source_manifest_commitment;
    if manifest.object_count() > usize_u64(limits.max_entries)?
        || manifest.logical_bytes_hashed() > limits.max_logical_bytes
    {
        return Err(PreparedEnvelopeError::InvalidPreparedInvariant);
    }
    let recovery = decode_recovery_bundle(
        &state.recovery_payload,
        RecoveryLimits {
            max_writes: limits.max_entries,
            max_bytes: limits.max_recovery_bytes,
        },
    )?;
    let recovery_groups = (
        recovery.plan_digest,
        &recovery.relocation_destinations,
        &recovery.target_staging,
        &recovery.backup_boot,
        &recovery.activation,
    );
    let prepared_groups = (
        state.plan_digest,
        &state.relocation_destination_before_images,
        &state.writes.target_staging_rollback,
        &state.writes.backup_boot_rollback,
        &state.writes.activation_rollback,
    );
    if recovery_groups != prepared_groups {
        return Err(PreparedEnvelopeError::RecoveryMismatch);
    }
    for (field, actual, expected) in [
        (
            "candidate overlay",
            digest_overlay_writes(&final_writes(&state.writes)),
            state.candidate_overlay_digest,
        ),
        (
            "relocation rollback",
            digest_overlay_writes(&state.relocation_destination_before_images),
            state.relocation_rollback_digest,
        ),
        (
            "staging rollback",
            digest_overlay_writes(&staging_rollback_writes(
                &state.relocation_destination_before_images,
                &state.writes,
            )),
            state.staging_rollback_digest,
        ),
        (
            "preactivation rollback",
            digest_overlay_writes(&preactivation_rollback_writes(
                &state.relocation_destination_before_images,
                &state.writes,
            )),
            state.preactivation_rollback_digest,
        ),
        (
            "full rollback",
            digest_overlay_writes(&full_rollback_writes(
                &state.relocation_destination_before_images,
                &state.writes,
            )),
            state.full_rollback_digest,
        ),
    ] {
        if actual != expected {
            return Err(PreparedEnvelopeError::CommitmentMismatch { field });
        }
    }
    if digest_plan(
        state.preflight,
        state.target_filesystem,
        &state.target_features,
        &state.reservations,
        &state.layout,
        &state.writes,
        state.source_graph_digest,
        state.target_graph_digest,
        &state.relocation_destination_before_images,
    ) != state.plan_digest
    {
        return Err(PreparedEnvelopeError::CommitmentMismatch { field: "plan" });
    }
    if digest_source_identity(state.preflight, state.source_graph_digest)
        != state.identity.source_digest
    {
        return Err(PreparedEnvelopeError::CommitmentMismatch {
            field: "source identity",
        });
    }
    Ok(())
}

fn validate_counts_and_bytes(
    state: &EnvelopeState,
    limits: PreparedEnvelopeLimits,
) -> Result<(), PreparedEnvelopeError> {
    let counts = [
        state.reservations.len(),
        state.layout.relocations.len(),
        state.layout.free_after_staging.len(),
        state.writes.target_staging.len(),
        state.writes.backup_boot.len(),
        state.writes.activation.len(),
        state.writes.target_staging_rollback.len(),
        state.writes.backup_boot_rollback.len(),
        state.writes.activation_rollback.len(),
        state.relocation_destination_before_images.len(),
        state.target_features.len(),
    ];
    let total = counts
        .into_iter()
        .try_fold(0_usize, usize::checked_add)
        .ok_or(PreparedEnvelopeError::ArithmeticOverflow)?;
    if total > limits.max_entries {
        return Err(PreparedEnvelopeError::EntryLimitExceeded {
            actual: usize_u64(total)?,
            maximum: limits.max_entries,
        });
    }
    let write_bytes = state
        .writes
        .target_staging
        .iter()
        .map(|v| v.write.bytes.len())
        .chain(state.writes.backup_boot.iter().map(|v| v.write.bytes.len()))
        .chain(state.writes.activation.iter().map(|v| v.write.bytes.len()))
        .chain(
            state
                .writes
                .target_staging_rollback
                .iter()
                .map(|v| v.bytes.len()),
        )
        .chain(
            state
                .writes
                .backup_boot_rollback
                .iter()
                .map(|v| v.bytes.len()),
        )
        .chain(
            state
                .writes
                .activation_rollback
                .iter()
                .map(|v| v.bytes.len()),
        )
        .chain(
            state
                .relocation_destination_before_images
                .iter()
                .map(|v| v.bytes.len()),
        )
        .try_fold(0_usize, usize::checked_add)
        .ok_or(PreparedEnvelopeError::ArithmeticOverflow)?;
    if write_bytes > limits.max_write_bytes {
        return Err(PreparedEnvelopeError::WriteByteLimitExceeded {
            actual: usize_u64(write_bytes)?,
            maximum: limits.max_write_bytes,
        });
    }
    if state.recovery_payload.len() > limits.max_recovery_bytes {
        return Err(PreparedEnvelopeError::RecoveryByteLimitExceeded {
            actual: usize_u64(state.recovery_payload.len())?,
            maximum: limits.max_recovery_bytes,
        });
    }
    Ok(())
}

fn validate_ranges(state: &EnvelopeState) -> Result<(), PreparedEnvelopeError> {
    for range in state
        .reservations
        .iter()
        .map(|v| v.range)
        .chain(state.layout.free_after_staging.iter().copied())
        .chain(
            state
                .layout
                .relocations
                .iter()
                .flat_map(|v| [v.source, v.destination]),
        )
    {
        if range.length == 0 {
            return Err(PreparedEnvelopeError::InvalidGeometry);
        }
        range
            .offset
            .checked_add(range.length)
            .ok_or(PreparedEnvelopeError::RangeOverflow {
                offset: range.offset,
                length: range.length,
            })?;
    }
    ensure_order(&state.reservations, RESERVATIONS, |v| {
        (v.range.offset, v.range.length, reservation_kind_key(v.kind))
    })?;
    ensure_order(&state.layout.relocations, RELOCATIONS, |v| {
        (v.source.offset, v.stream.0, v.logical_offset)
    })?;
    ensure_order(&state.layout.free_after_staging, FREE_RANGES, |v| {
        (v.offset, v.length)
    })?;
    let relocated_bytes = state
        .layout
        .relocations
        .iter()
        .try_fold(0_u64, |sum, value| {
            if value.source.length != value.destination.length {
                return Err(PreparedEnvelopeError::InvalidPreparedInvariant);
            }
            sum.checked_add(value.source.length)
                .ok_or(PreparedEnvelopeError::ArithmeticOverflow)
        })?;
    let largest_free_range = state
        .layout
        .free_after_staging
        .iter()
        .map(|range| range.length)
        .max()
        .unwrap_or(0);
    if !state.layout.materializations.is_empty() || state.layout.materialized_bytes != 0 {
        return Err(PreparedEnvelopeError::InvalidPreparedInvariant);
    }
    if relocated_bytes != state.layout.relocated_bytes
        || largest_free_range != state.layout.largest_free_range
    {
        return Err(PreparedEnvelopeError::InvalidPreparedInvariant);
    }
    for (tag, writes) in [
        (TARGET_STAGING, &state.writes.target_staging),
        (BACKUP_BOOT, &state.writes.backup_boot),
        (ACTIVATION, &state.writes.activation),
    ] {
        ensure_order(writes, tag, |v| {
            (v.write.offset, reservation_kind_key(v.reservation_kind))
        })?;
        for value in writes {
            validate_write(tag, &value.write)?;
        }
    }
    for (tag, writes) in [
        (
            TARGET_STAGING_ROLLBACK,
            &state.writes.target_staging_rollback,
        ),
        (BACKUP_BOOT_ROLLBACK, &state.writes.backup_boot_rollback),
        (ACTIVATION_ROLLBACK, &state.writes.activation_rollback),
        (
            RELOCATION_DESTINATION_ROLLBACK,
            &state.relocation_destination_before_images,
        ),
    ] {
        ensure_order(writes, tag, |v| v.offset)?;
        for value in writes {
            validate_write(tag, value)?;
        }
    }
    Ok(())
}

fn validate_write(section: u16, write: &OverlayWrite) -> Result<(), PreparedEnvelopeError> {
    let length = usize_u64(write.bytes.len())?;
    if length == 0 {
        return Err(PreparedEnvelopeError::EmptyWrite {
            section,
            offset: write.offset,
        });
    }
    write
        .offset
        .checked_add(length)
        .ok_or(PreparedEnvelopeError::RangeOverflow {
            offset: write.offset,
            length,
        })?;
    Ok(())
}

fn encode_reservation(value: &DestinationReservation, bytes: &mut Vec<u8>) {
    bytes.extend_from_slice(&value.range.offset.to_le_bytes());
    bytes.extend_from_slice(&value.range.length.to_le_bytes());
    bytes.push(reservation_kind_key(value.kind));
    bytes.extend_from_slice(&[0_u8; 7]);
}

fn encode_relocation(value: &Relocation, bytes: &mut Vec<u8>) {
    bytes.extend_from_slice(&value.stream.0.to_le_bytes());
    bytes.extend_from_slice(&value.logical_offset.to_le_bytes());
    encode_range(&value.source, bytes);
    encode_range(&value.destination, bytes);
}

fn encode_range(value: &ByteRange, bytes: &mut Vec<u8>) {
    bytes.extend_from_slice(&value.offset.to_le_bytes());
    bytes.extend_from_slice(&value.length.to_le_bytes());
}

fn encode_target_feature(value: &FeatureCompatibility, bytes: &mut Vec<u8>) {
    bytes.push(semantic_feature_key(value.feature));
    match value.method {
        PreservationMethod::Native => {
            bytes.push(0);
            bytes.extend_from_slice(&0_u16.to_le_bytes());
            bytes.extend_from_slice(&[0_u8; 32]);
        }
        PreservationMethod::Escrow {
            schema_version,
            payload_digest,
        } => {
            bytes.push(1);
            bytes.extend_from_slice(&schema_version.to_le_bytes());
            bytes.extend_from_slice(&payload_digest);
        }
    }
}

fn decode_target_features(
    bytes: &[u8],
    count: u32,
) -> Result<Vec<FeatureCompatibility>, PreparedEnvelopeError> {
    let mut output = bounded_vec(count)?;
    for chunk in bytes.chunks_exact(36) {
        let feature = decode_semantic_feature(chunk[0])?;
        let schema_version = u16::from_le_bytes([chunk[2], chunk[3]]);
        let mut payload_digest = [0_u8; 32];
        payload_digest.copy_from_slice(&chunk[4..36]);
        let method = match chunk[1] {
            0 if schema_version == 0 && payload_digest == [0; 32] => PreservationMethod::Native,
            0 => return Err(PreparedEnvelopeError::NonZeroReserved),
            1 if schema_version != 0 => PreservationMethod::Escrow {
                schema_version,
                payload_digest,
            },
            value => {
                return Err(PreparedEnvelopeError::InvalidEnum {
                    field: "preservation method",
                    value,
                });
            }
        };
        output.push(FeatureCompatibility { feature, method });
    }
    validate_target_features(&output)?;
    Ok(output)
}

fn validate_target_features(
    features: &[FeatureCompatibility],
) -> Result<(), PreparedEnvelopeError> {
    ensure_order(features, TARGET_FEATURES, |value| {
        semantic_feature_key(value.feature)
    })?;
    for value in features {
        if matches!(
            value.method,
            PreservationMethod::Escrow {
                schema_version: 0,
                ..
            }
        ) {
            return Err(PreparedEnvelopeError::CommitmentMismatch {
                field: "escrow schema version",
            });
        }
    }
    Ok(())
}

fn section_bytes(bytes: &[u8], meta: SectionMeta) -> &[u8] {
    &bytes[meta.start..meta.end]
}

fn bounded_vec<T>(count: u32) -> Result<Vec<T>, PreparedEnvelopeError> {
    let count = usize::try_from(count).map_err(|_| PreparedEnvelopeError::ArithmeticOverflow)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(count)
        .map_err(|_| PreparedEnvelopeError::AllocationFailed)?;
    Ok(output)
}

fn copy_bounded(bytes: &[u8]) -> Result<Vec<u8>, PreparedEnvelopeError> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(bytes.len())
        .map_err(|_| PreparedEnvelopeError::AllocationFailed)?;
    output.extend_from_slice(bytes);
    Ok(output)
}

fn ensure_order<T, K: Ord>(
    values: &[T],
    section: u16,
    key: impl Fn(&T) -> K,
) -> Result<(), PreparedEnvelopeError> {
    if values.windows(2).any(|pair| key(&pair[0]) >= key(&pair[1])) {
        return Err(PreparedEnvelopeError::NonCanonicalOrder { section });
    }
    Ok(())
}

fn validate_limits(limits: PreparedEnvelopeLimits) -> Result<(), PreparedEnvelopeError> {
    for (field, zero) in [
        ("max_envelope_bytes", limits.max_envelope_bytes == 0),
        ("max_entries", limits.max_entries == 0),
        ("max_write_bytes", limits.max_write_bytes == 0),
        ("max_recovery_bytes", limits.max_recovery_bytes == 0),
        ("max_read_bytes", limits.max_read_bytes == 0),
        ("max_logical_bytes", limits.max_logical_bytes == 0),
    ] {
        if zero {
            return Err(PreparedEnvelopeError::InvalidLimit { field });
        }
    }
    Ok(())
}

fn ensure_envelope_cap(
    actual: u64,
    limits: PreparedEnvelopeLimits,
) -> Result<(), PreparedEnvelopeError> {
    if actual > usize_u64(limits.max_envelope_bytes)? {
        return Err(PreparedEnvelopeError::EnvelopeTooLarge {
            actual,
            maximum: limits.max_envelope_bytes,
        });
    }
    Ok(())
}

fn validate_envelope_generation(
    payload_bytes: usize,
    limits: CapsuleLimits,
) -> Result<(), PreparedEnvelopeError> {
    validate_initial_capsule_generation(payload_bytes, limits).map_err(|error| match error {
        super::ConversionError::Capsule(error) => PreparedEnvelopeError::Capsule(error),
        _ => PreparedEnvelopeError::InvalidPreparedInvariant,
    })
}

const fn filesystem_key(value: FileSystem) -> Result<u8, PreparedEnvelopeError> {
    match value {
        FileSystem::ExFat => Ok(0),
        FileSystem::Ntfs => Ok(1),
        FileSystem::Unknown => Err(PreparedEnvelopeError::InvalidEnum {
            field: "filesystem",
            value: 2,
        }),
    }
}
const fn decode_filesystem(
    value: u8,
    field: &'static str,
) -> Result<FileSystem, PreparedEnvelopeError> {
    match value {
        0 => Ok(FileSystem::ExFat),
        1 => Ok(FileSystem::Ntfs),
        _ => Err(PreparedEnvelopeError::InvalidEnum { field, value }),
    }
}
const fn health_key(value: HealthState) -> u8 {
    match value {
        HealthState::Clean => 0,
        HealthState::Dirty => 1,
        HealthState::Unknown => 2,
    }
}
const fn decode_health(value: u8) -> Result<HealthState, PreparedEnvelopeError> {
    match value {
        0 => Ok(HealthState::Clean),
        1 => Ok(HealthState::Dirty),
        2 => Ok(HealthState::Unknown),
        _ => Err(PreparedEnvelopeError::InvalidEnum {
            field: "health",
            value,
        }),
    }
}
const fn access_key(value: AccessState) -> u8 {
    match value {
        AccessState::Offline => 0,
        AccessState::Mounted => 1,
        AccessState::Unknown => 2,
    }
}
const fn decode_access(value: u8) -> Result<AccessState, PreparedEnvelopeError> {
    match value {
        0 => Ok(AccessState::Offline),
        1 => Ok(AccessState::Mounted),
        2 => Ok(AccessState::Unknown),
        _ => Err(PreparedEnvelopeError::InvalidEnum {
            field: "access",
            value,
        }),
    }
}
const fn reservation_kind_key(value: ReservationKind) -> u8 {
    match value {
        ReservationKind::BootRegion => 0,
        ReservationKind::AllocationMetadata => 1,
        ReservationKind::NamespaceMetadata => 2,
        ReservationKind::Journal => 3,
        ReservationKind::Capsule => 4,
        ReservationKind::Other => 5,
    }
}
const fn decode_reservation_kind(value: u8) -> Result<ReservationKind, PreparedEnvelopeError> {
    match value {
        0 => Ok(ReservationKind::BootRegion),
        1 => Ok(ReservationKind::AllocationMetadata),
        2 => Ok(ReservationKind::NamespaceMetadata),
        3 => Ok(ReservationKind::Journal),
        4 => Ok(ReservationKind::Capsule),
        5 => Ok(ReservationKind::Other),
        _ => Err(PreparedEnvelopeError::InvalidEnum {
            field: "reservation kind",
            value,
        }),
    }
}
const fn semantic_feature_key(value: SemanticFeature) -> u8 {
    match value {
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
const fn decode_semantic_feature(value: u8) -> Result<SemanticFeature, PreparedEnvelopeError> {
    match value {
        0 => Ok(SemanticFeature::AccessControl),
        1 => Ok(SemanticFeature::AlternateDataStreams),
        2 => Ok(SemanticFeature::Compression),
        3 => Ok(SemanticFeature::EncryptedFiles),
        4 => Ok(SemanticFeature::HardLinks),
        5 => Ok(SemanticFeature::ReparsePoints),
        6 => Ok(SemanticFeature::SparseFiles),
        7 => Ok(SemanticFeature::CaseCollisions),
        _ => Err(PreparedEnvelopeError::InvalidEnum {
            field: "semantic feature",
            value,
        }),
    }
}

fn header_crc(header: &[u8]) -> u32 {
    let mut copy = [0_u8; HEADER_BYTES];
    copy.copy_from_slice(&header[..HEADER_BYTES]);
    copy[HEADER_CRC_OFFSET..HEADER_CRC_OFFSET + 4].fill(0);
    let mut crc = Crc32::new();
    crc.update(&copy);
    crc.finalize()
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn usize_u64(value: usize) -> Result<u64, PreparedEnvelopeError> {
    u64::try_from(value).map_err(|_| PreparedEnvelopeError::ArithmeticOverflow)
}
fn read_usize(bytes: &[u8], offset: usize) -> Result<usize, PreparedEnvelopeError> {
    usize::try_from(read_u64(bytes, offset)?).map_err(|_| PreparedEnvelopeError::ArithmeticOverflow)
}
fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, PreparedEnvelopeError> {
    Ok(u16::from_le_bytes(
        bytes
            .get(offset..offset + 2)
            .ok_or(PreparedEnvelopeError::Truncated)?
            .try_into()
            .map_err(|_| PreparedEnvelopeError::Truncated)?,
    ))
}
fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, PreparedEnvelopeError> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(PreparedEnvelopeError::Truncated)?
            .try_into()
            .map_err(|_| PreparedEnvelopeError::Truncated)?,
    ))
}
fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, PreparedEnvelopeError> {
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..offset + 8)
            .ok_or(PreparedEnvelopeError::Truncated)?
            .try_into()
            .map_err(|_| PreparedEnvelopeError::Truncated)?,
    ))
}
fn array_16(bytes: &[u8], offset: usize) -> Result<[u8; 16], PreparedEnvelopeError> {
    bytes
        .get(offset..offset + 16)
        .ok_or(PreparedEnvelopeError::Truncated)?
        .try_into()
        .map_err(|_| PreparedEnvelopeError::Truncated)
}
fn array_32(bytes: &[u8], offset: usize) -> Result<[u8; 32], PreparedEnvelopeError> {
    bytes
        .get(offset..offset + 32)
        .ok_or(PreparedEnvelopeError::Truncated)?
        .try_into()
        .map_err(|_| PreparedEnvelopeError::Truncated)
}
fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery::{RecoveryBundle, encode_recovery_bundle};

    const fn limits() -> PreparedEnvelopeLimits {
        PreparedEnvelopeLimits {
            max_envelope_bytes: 64 * 1024,
            max_entries: 64,
            max_write_bytes: 16 * 1024,
            max_recovery_bytes: 16 * 1024,
            max_read_bytes: 4096,
            max_logical_bytes: 64 * 1024,
        }
    }

    fn write(offset: u64, byte: u8) -> OverlayWrite {
        OverlayWrite {
            offset,
            bytes: vec![byte; 512],
        }
    }

    #[allow(clippy::too_many_lines)]
    fn state() -> EnvelopeState {
        let relocation_before = vec![write(12288, 10)];
        let rollback = OpaqueWriteSets {
            target_staging: vec![ReservedWrite {
                reservation_kind: ReservationKind::NamespaceMetadata,
                write: write(4096, 1),
            }],
            backup_boot: vec![ReservedWrite {
                reservation_kind: ReservationKind::BootRegion,
                write: write(512, 2),
            }],
            activation: vec![ReservedWrite {
                reservation_kind: ReservationKind::BootRegion,
                write: write(0, 3),
            }],
            target_staging_rollback: vec![write(4096, 11)],
            backup_boot_rollback: vec![write(512, 12)],
            activation_rollback: vec![write(0, 13)],
        };
        let mut state = EnvelopeState {
            identity: CapsuleIdentity {
                transaction_id: [1; 16],
                source_digest: [2; 32],
            },
            preflight: PreflightEvidence {
                image: ImageIdentity {
                    instance: [3; 32],
                    image_bytes: 16 * 1024,
                },
                source_filesystem: FileSystem::ExFat,
                source_evidence_digest: [4; 32],
                source_manifest_commitment: ManifestCommitment::from_validated_parts(
                    [8; 32], 1234, 9,
                ),
                sector_bytes: 512,
                allocation_alignment: 512,
                inventory_complete: true,
                allocation_map_complete: true,
                health: HealthState::Clean,
                access: AccessState::Offline,
            },
            target_filesystem: FileSystem::Ntfs,
            target_features: vec![FeatureCompatibility {
                feature: SemanticFeature::AccessControl,
                method: PreservationMethod::Native,
            }],
            source_graph_digest: [5; 32],
            target_graph_digest: [6; 32],
            plan_digest: [0; 32],
            candidate_overlay_digest: digest_overlay_writes(&final_writes(&rollback)),
            relocation_rollback_digest: digest_overlay_writes(&relocation_before),
            staging_rollback_digest: digest_overlay_writes(&staging_rollback_writes(
                &relocation_before,
                &rollback,
            )),
            preactivation_rollback_digest: digest_overlay_writes(&preactivation_rollback_writes(
                &relocation_before,
                &rollback,
            )),
            full_rollback_digest: digest_overlay_writes(&full_rollback_writes(
                &relocation_before,
                &rollback,
            )),
            reservations: vec![
                DestinationReservation {
                    range: ByteRange {
                        offset: 0,
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
                        offset: 4096,
                        length: 512,
                    },
                    kind: ReservationKind::NamespaceMetadata,
                },
                DestinationReservation {
                    range: ByteRange {
                        offset: 6144,
                        length: 512,
                    },
                    kind: ReservationKind::Capsule,
                },
            ],
            layout: LayoutPlan {
                relocations: vec![Relocation {
                    stream: StreamId(1),
                    logical_offset: 0,
                    source: ByteRange {
                        offset: 8192,
                        length: 512,
                    },
                    destination: ByteRange {
                        offset: 12288,
                        length: 512,
                    },
                }],
                materializations: Vec::new(),
                free_after_staging: vec![ByteRange {
                    offset: 15360,
                    length: 1024,
                }],
                relocated_bytes: 512,
                materialized_bytes: 0,
                largest_free_range: 1024,
            },
            writes: rollback,
            relocation_destination_before_images: relocation_before,
            recovery_payload: Vec::new(),
            capsule_limits: CapsuleLimits {
                max_capsule_bytes: 32768,
                max_generation_bytes: 8192,
                max_generations: 16,
            },
        };
        state.plan_digest = digest_plan(
            state.preflight,
            state.target_filesystem,
            &state.target_features,
            &state.reservations,
            &state.layout,
            &state.writes,
            state.source_graph_digest,
            state.target_graph_digest,
            &state.relocation_destination_before_images,
        );
        state.identity.source_digest =
            digest_source_identity(state.preflight, state.source_graph_digest);
        state.recovery_payload = encode_recovery_bundle(
            &RecoveryBundle {
                plan_digest: state.plan_digest,
                relocation_destinations: state.relocation_destination_before_images.clone(),
                target_staging: state.writes.target_staging_rollback.clone(),
                backup_boot: state.writes.backup_boot_rollback.clone(),
                activation: state.writes.activation_rollback.clone(),
            },
            RecoveryLimits {
                max_writes: 8,
                max_bytes: 4096,
            },
        )
        .unwrap();
        state
    }

    #[test]
    fn canonical_round_trip_is_byte_stable() {
        let first = encode_state(&state(), limits()).unwrap();
        let decoded = decode_state(&first, limits()).unwrap();
        assert_eq!(decoded, state());
        assert_eq!(encode_state(&decoded, limits()).unwrap(), first);
        assert_ne!(&first[..8], b"STARCAP\0");
    }

    #[test]
    fn prepared_api_reconstructs_complete_activation_authority() {
        let mut original = state().into_decoded(limits()).unwrap();
        let encoded = encode_prepared_envelope(&original.prepared, limits()).unwrap();
        original.prepared.prepared_envelope = encoded.clone();
        let restored = decode_prepared_envelope(&encoded, limits()).unwrap();

        assert_eq!(restored, original);
        assert_eq!(
            restored.prepared.plan_digest(),
            original.prepared.plan_digest()
        );
        assert_eq!(
            restored.prepared.recovery_payload(),
            original.prepared.recovery_payload()
        );
    }

    #[test]
    fn header_and_payload_tampering_fail_closed() {
        let encoded = encode_state(&state(), limits()).unwrap();
        let mut header = encoded.clone();
        header[120] ^= 1;
        assert!(matches!(
            decode_state(&header, limits()),
            Err(PreparedEnvelopeError::HeaderCrcMismatch)
        ));
        let mut payload = encoded;
        *payload.last_mut().unwrap() ^= 1;
        assert!(matches!(
            decode_state(&payload, limits()),
            Err(PreparedEnvelopeError::PayloadDigestMismatch)
        ));
    }

    #[test]
    fn tampered_target_digest_and_relocation_geometry_fail_commitment_validation() {
        let encoded = encode_state(&state(), limits()).unwrap();

        let mut target_digest = encoded.clone();
        target_digest[500] ^= 1;
        let crc = header_crc(&target_digest[..HEADER_BYTES]);
        put_u32(&mut target_digest, HEADER_CRC_OFFSET, crc);
        assert!(matches!(
            decode_state(&target_digest, limits()),
            Err(PreparedEnvelopeError::CommitmentMismatch { field: "plan" })
        ));

        let mut geometry = encoded;
        let reservation_bytes = state().reservations.len() * 24;
        let relocation_header = HEADER_BYTES + SECTION_HEADER_BYTES + reservation_bytes;
        let relocation_data = relocation_header + SECTION_HEADER_BYTES;
        let destination_offset = relocation_data + 32;
        put_u64(&mut geometry, destination_offset, 12_800);
        let relocation_end = relocation_data + 48;
        let section_digest = sha256(&geometry[relocation_data..relocation_end]);
        geometry[relocation_header + 16..relocation_header + 48].copy_from_slice(&section_digest);
        let payload_digest = sha256(&geometry[HEADER_BYTES..]);
        geometry[32..64].copy_from_slice(&payload_digest);
        let crc = header_crc(&geometry[..HEADER_BYTES]);
        put_u32(&mut geometry, HEADER_CRC_OFFSET, crc);
        assert!(decode_state(&geometry, limits()).is_err());
    }

    #[test]
    fn v1_executable_envelope_is_rejected() {
        let mut encoded = encode_state(&state(), limits()).unwrap();
        encoded[..8].copy_from_slice(b"SCPREP01");
        put_u16(&mut encoded, 8, 1);
        let crc = header_crc(&encoded[..HEADER_BYTES]);
        put_u32(&mut encoded, HEADER_CRC_OFFSET, crc);
        assert!(matches!(
            decode_state(&encoded, limits()),
            Err(PreparedEnvelopeError::InvalidMagic
                | PreparedEnvelopeError::UnsupportedVersion { actual: 1 })
        ));
    }

    #[test]
    fn every_truncation_is_rejected() {
        let encoded = encode_state(&state(), limits()).unwrap();
        for length in 0..encoded.len() {
            assert!(
                decode_state(&encoded[..length], limits()).is_err(),
                "accepted {length}-byte prefix"
            );
        }
    }

    #[test]
    fn declared_caps_are_checked_before_section_allocation() {
        let mut encoded = encode_state(&state(), limits()).unwrap();
        put_u32(&mut encoded, HEADER_BYTES + 4, u32::MAX);
        let section =
            &encoded[HEADER_BYTES + SECTION_HEADER_BYTES..HEADER_BYTES + SECTION_HEADER_BYTES + 24];
        let digest = sha256(section);
        encoded[HEADER_BYTES + 16..HEADER_BYTES + 48].copy_from_slice(&digest);
        let payload_digest = sha256(&encoded[HEADER_BYTES..]);
        encoded[32..64].copy_from_slice(&payload_digest);
        let crc = header_crc(&encoded[..HEADER_BYTES]);
        put_u32(&mut encoded, HEADER_CRC_OFFSET, crc);
        assert!(matches!(
            decode_state(&encoded, limits()),
            Err(PreparedEnvelopeError::EntryLimitExceeded { .. })
        ));
    }

    #[test]
    fn unknown_trailing_and_noncanonical_sections_are_rejected() {
        let encoded = encode_state(&state(), limits()).unwrap();
        let mut unknown = encoded.clone();
        put_u16(&mut unknown, HEADER_BYTES, 99);
        let payload_digest = sha256(&unknown[HEADER_BYTES..]);
        unknown[32..64].copy_from_slice(&payload_digest);
        let crc = header_crc(&unknown[..HEADER_BYTES]);
        put_u32(&mut unknown, HEADER_CRC_OFFSET, crc);
        assert!(matches!(
            decode_state(&unknown, limits()),
            Err(PreparedEnvelopeError::UnexpectedSection { .. })
        ));

        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode_state(&trailing, limits()).is_err());

        let mut noncanonical = state();
        noncanonical.reservations.swap(0, 1);
        assert!(matches!(
            encode_state(&noncanonical, limits()),
            Err(PreparedEnvelopeError::NonCanonicalOrder {
                section: RESERVATIONS
            })
        ));
    }

    #[test]
    fn exact_recovery_bytes_must_match_rollback_sections() {
        let mut value = state();
        value.recovery_payload = encode_recovery_bundle(
            &RecoveryBundle {
                plan_digest: value.plan_digest,
                relocation_destinations: value.relocation_destination_before_images.clone(),
                target_staging: vec![write(4096, 99)],
                backup_boot: value.writes.backup_boot_rollback.clone(),
                activation: value.writes.activation_rollback.clone(),
            },
            RecoveryLimits {
                max_writes: 8,
                max_bytes: 4096,
            },
        )
        .unwrap();
        assert!(matches!(
            encode_state(&value, limits()),
            Err(PreparedEnvelopeError::RecoveryMismatch)
        ));
    }

    #[test]
    fn executable_envelope_requires_exact_relocation_destination_group() {
        for case in 0..4 {
            let mut value = state();
            match case {
                0 => value.relocation_destination_before_images.clear(),
                1 => value
                    .relocation_destination_before_images
                    .push(write(15_360, 9)),
                2 => value
                    .relocation_destination_before_images
                    .push(value.relocation_destination_before_images[0].clone()),
                _ => {
                    value.relocation_destination_before_images[0].bytes.pop();
                }
            }
            assert!(matches!(
                encode_state(&value, limits()),
                Err(PreparedEnvelopeError::InvalidPreparedInvariant
                    | PreparedEnvelopeError::NonCanonicalOrder { .. })
            ));
        }
    }

    #[test]
    fn capsule_generation_error_retains_typed_detail() {
        let mut value = state();
        value.capsule_limits.max_generation_bytes = 1;
        assert!(matches!(
            encode_state(&value, limits()),
            Err(PreparedEnvelopeError::Capsule(
                CapsuleError::GenerationTooLarge {
                    actual,
                    maximum: 1
                }
            )) if actual > 1
        ));
    }

    #[test]
    fn capsule_size_is_the_effective_limit_for_a_larger_generation_cap() {
        let mut value = state();
        value.capsule_limits.max_capsule_bytes = crate::capsule::HEADER_BYTES * 2;
        assert!(matches!(
            encode_state(&value, limits()),
            Err(PreparedEnvelopeError::Capsule(
                CapsuleError::CapsuleTooLarge {
                    actual,
                    maximum
                }
            )) if actual > maximum && maximum == crate::capsule::HEADER_BYTES * 2
        ));
    }
}
