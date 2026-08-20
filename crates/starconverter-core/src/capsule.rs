//! Versioned append-only transaction capsule framing and recovery.
//!
//! Each generation stores identical independently checksummed headers before and after a SHA-256
//! bound payload. Recovery can therefore use either surviving header. This module only operates on
//! caller-owned byte buffers; durable ordering and flush barriers belong to a future backend.

use std::collections::BTreeMap;
use std::fmt;

use crc32fast::Hasher as Crc32;
use sha2::{Digest, Sha256};

pub const CAPSULE_VERSION: u16 = 1;
pub const HEADER_BYTES: usize = 136;
const MAGIC: &[u8; 8] = b"STARCAP\0";
const NO_PREVIOUS: u64 = u64::MAX;
const CRC_OFFSET: usize = 128;

/// Durable transaction state recorded by one capsule generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum TransactionPhase {
    Discovered = 0,
    Reserved = 1,
    Relocating = 2,
    TargetStaged = 3,
    BackupBootWritten = 4,
    Activated = 5,
    Verified = 6,
    Finalized = 7,
    RolledBack = 8,
}

impl TransactionPhase {
    const fn from_byte(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Discovered),
            1 => Some(Self::Reserved),
            2 => Some(Self::Relocating),
            3 => Some(Self::TargetStaged),
            4 => Some(Self::BackupBootWritten),
            5 => Some(Self::Activated),
            6 => Some(Self::Verified),
            7 => Some(Self::Finalized),
            8 => Some(Self::RolledBack),
            _ => None,
        }
    }

    const fn may_follow(self, previous: Self) -> bool {
        if matches!(previous, Self::Finalized | Self::RolledBack) {
            return false;
        }
        self as u8 == previous as u8 + 1 || self as u8 == Self::RolledBack as u8
    }
}

/// Fixed transaction identity and immutable source evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapsuleIdentity {
    pub transaction_id: [u8; 16],
    pub source_digest: [u8; 32],
}

/// Caller-controlled recovery and append bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapsuleLimits {
    pub max_capsule_bytes: usize,
    pub max_generation_bytes: usize,
    pub max_generations: usize,
}

impl Default for CapsuleLimits {
    fn default() -> Self {
        Self {
            max_capsule_bytes: 1024 * 1024 * 1024,
            max_generation_bytes: 256 * 1024 * 1024,
            max_generations: 4096,
        }
    }
}

/// One recovered complete generation borrowing its payload from the capsule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapsuleGeneration<'a> {
    pub offset: u64,
    pub generation: u64,
    pub phase: TransactionPhase,
    pub previous_offset: Option<u64>,
    pub identity: CapsuleIdentity,
    pub payload_digest: [u8; 32],
    pub payload: &'a [u8],
    pub primary_header_valid: bool,
    pub trailing_header_valid: bool,
}

/// A fully validated append-only capsule and its newest generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapsuleView<'a> {
    generations: Vec<CapsuleGeneration<'a>>,
    validated_bytes: usize,
}

impl<'a> CapsuleView<'a> {
    #[must_use]
    pub fn generations(&self) -> &[CapsuleGeneration<'a>] {
        &self.generations
    }

    #[must_use]
    pub fn newest(&self) -> Option<&CapsuleGeneration<'a>> {
        self.generations.last()
    }

    /// Length of the fully validated generation prefix. Recovery may safely truncate a torn
    /// append-only suffix to this boundary before appending another generation.
    #[must_use]
    pub const fn validated_bytes(&self) -> usize {
        self.validated_bytes
    }
}

/// Capsule framing, integrity, resource, or state-machine failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapsuleError {
    InvalidLimit {
        field: &'static str,
    },
    CapsuleTooLarge {
        actual: usize,
        maximum: usize,
    },
    GenerationTooLarge {
        actual: usize,
        maximum: usize,
    },
    TooManyGenerations {
        maximum: usize,
    },
    AllocationFailed,
    ArithmeticOverflow,
    NoRecoverableHeader {
        offset: usize,
    },
    ConflictingHeaders {
        offset: usize,
    },
    AmbiguousGeneration {
        offset: usize,
    },
    UnframedBytes {
        offset: usize,
    },
    UnsupportedVersion {
        version: u16,
    },
    InvalidHeaderLength {
        actual: u16,
    },
    InvalidPhase {
        value: u8,
    },
    NonZeroReserved,
    PayloadDigestMismatch {
        offset: usize,
    },
    FirstGenerationInvalid,
    GenerationSequence {
        expected: u64,
        actual: u64,
    },
    PreviousOffsetMismatch {
        expected: Option<u64>,
        actual: Option<u64>,
    },
    IdentityChanged,
    InvalidPhaseTransition {
        previous: TransactionPhase,
        next: TransactionPhase,
    },
    GenerationOverflow,
}

impl fmt::Display for CapsuleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit { field } => write!(formatter, "capsule limit {field} is zero"),
            Self::CapsuleTooLarge { actual, maximum } => {
                write!(formatter, "capsule has {actual} bytes, exceeding {maximum}")
            }
            Self::GenerationTooLarge { actual, maximum } => write!(
                formatter,
                "generation payload has {actual} bytes, exceeding {maximum}"
            ),
            Self::TooManyGenerations { maximum } => {
                write!(formatter, "capsule exceeds {maximum} generations")
            }
            Self::AllocationFailed => {
                formatter.write_str("could not allocate bounded capsule storage")
            }
            Self::ArithmeticOverflow => formatter.write_str("capsule byte accounting overflow"),
            Self::NoRecoverableHeader { offset } => write!(
                formatter,
                "no recoverable capsule header for generation at byte {offset}"
            ),
            Self::ConflictingHeaders { offset } => {
                write!(formatter, "valid capsule headers conflict at byte {offset}")
            }
            Self::AmbiguousGeneration { offset } => write!(
                formatter,
                "multiple valid capsule generations claim byte {offset}"
            ),
            Self::UnframedBytes { offset } => write!(
                formatter,
                "capsule contains unframed or truncated bytes at {offset}"
            ),
            Self::UnsupportedVersion { version } => {
                write!(formatter, "unsupported capsule version {version}")
            }
            Self::InvalidHeaderLength { actual } => write!(
                formatter,
                "capsule header length is {actual}, expected {HEADER_BYTES}"
            ),
            Self::InvalidPhase { value } => write!(formatter, "invalid capsule phase {value}"),
            Self::NonZeroReserved => {
                formatter.write_str("capsule header reserved bytes are nonzero")
            }
            Self::PayloadDigestMismatch { offset } => {
                write!(formatter, "capsule payload digest mismatch at {offset}")
            }
            Self::FirstGenerationInvalid => formatter
                .write_str("first capsule generation is not generation zero in Discovered phase"),
            Self::GenerationSequence { expected, actual } => write!(
                formatter,
                "capsule generation is {actual}, expected {expected}"
            ),
            Self::PreviousOffsetMismatch { expected, actual } => write!(
                formatter,
                "capsule previous offset is {actual:?}, expected {expected:?}"
            ),
            Self::IdentityChanged => formatter
                .write_str("capsule transaction/source identity changed between generations"),
            Self::InvalidPhaseTransition { previous, next } => write!(
                formatter,
                "invalid capsule phase transition {previous:?} -> {next:?}"
            ),
            Self::GenerationOverflow => formatter.write_str("capsule generation counter overflow"),
        }
    }
}

impl std::error::Error for CapsuleError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Header {
    generation: u64,
    phase: TransactionPhase,
    payload_len: u64,
    previous_offset: Option<u64>,
    identity: CapsuleIdentity,
    payload_digest: [u8; 32],
}

#[derive(Debug, Clone, Copy)]
struct Candidate {
    start: usize,
    header: Header,
    primary_valid: bool,
    trailing_valid: bool,
}

/// Appends one complete redundant generation to a caller-owned capsule buffer.
///
/// # Errors
///
/// Validates the existing capsule first and rejects invalid phase transitions, identity changes,
/// cap exhaustion, arithmetic overflow, or allocation failure.
pub fn append_generation(
    capsule: &mut Vec<u8>,
    identity: CapsuleIdentity,
    phase: TransactionPhase,
    payload: &[u8],
    limits: CapsuleLimits,
) -> Result<(), CapsuleError> {
    validate_limits(limits)?;
    if payload.len() > limits.max_generation_bytes {
        return Err(CapsuleError::GenerationTooLarge {
            actual: payload.len(),
            maximum: limits.max_generation_bytes,
        });
    }
    let view = scan_capsule(capsule, limits)?;
    let (generation, previous_offset) = match view.newest() {
        None => {
            if phase != TransactionPhase::Discovered {
                return Err(CapsuleError::FirstGenerationInvalid);
            }
            (0, None)
        }
        Some(previous) => {
            if previous.identity != identity {
                return Err(CapsuleError::IdentityChanged);
            }
            if !phase.may_follow(previous.phase) {
                return Err(CapsuleError::InvalidPhaseTransition {
                    previous: previous.phase,
                    next: phase,
                });
            }
            (
                previous
                    .generation
                    .checked_add(1)
                    .ok_or(CapsuleError::GenerationOverflow)?,
                Some(previous.offset),
            )
        }
    };
    if view.generations().len() >= limits.max_generations {
        return Err(CapsuleError::TooManyGenerations {
            maximum: limits.max_generations,
        });
    }
    let record_bytes = HEADER_BYTES
        .checked_mul(2)
        .and_then(|value| value.checked_add(payload.len()))
        .ok_or(CapsuleError::ArithmeticOverflow)?;
    let final_len = capsule
        .len()
        .checked_add(record_bytes)
        .ok_or(CapsuleError::ArithmeticOverflow)?;
    if final_len > limits.max_capsule_bytes {
        return Err(CapsuleError::CapsuleTooLarge {
            actual: final_len,
            maximum: limits.max_capsule_bytes,
        });
    }
    let header = Header {
        generation,
        phase,
        payload_len: u64::try_from(payload.len()).map_err(|_| CapsuleError::ArithmeticOverflow)?,
        previous_offset,
        identity,
        payload_digest: sha256(payload),
    };
    let encoded = encode_header(header);
    capsule
        .try_reserve(record_bytes)
        .map_err(|_| CapsuleError::AllocationFailed)?;
    capsule.extend_from_slice(&encoded);
    capsule.extend_from_slice(payload);
    capsule.extend_from_slice(&encoded);
    Ok(())
}

/// Recovers and validates every complete generation in an append-only capsule.
///
/// One header copy per generation may be corrupt. Payload corruption, ambiguous framing, gaps,
/// identity changes, invalid phase transitions, and truncated tails are rejected.
///
/// # Errors
///
/// Returns [`CapsuleError`] for invalid framing, integrity, sequence, phase, or resource evidence.
pub fn scan_capsule(bytes: &[u8], limits: CapsuleLimits) -> Result<CapsuleView<'_>, CapsuleError> {
    scan_capsule_impl(bytes, limits, false)
}

/// Recovers the complete generation prefix while tolerating only a provably incomplete newest
/// append. Completed framing or payload corruption remains fatal.
///
/// # Errors
///
/// Returns [`CapsuleError`] for invalid complete generations, ambiguous framing, resource-limit
/// violations, or a suffix that is not a partial next append.
pub fn recover_capsule(
    bytes: &[u8],
    limits: CapsuleLimits,
) -> Result<CapsuleView<'_>, CapsuleError> {
    scan_capsule_impl(bytes, limits, true)
}

fn scan_capsule_impl(
    bytes: &[u8],
    limits: CapsuleLimits,
    allow_torn_tail: bool,
) -> Result<CapsuleView<'_>, CapsuleError> {
    validate_limits(limits)?;
    if bytes.len() > limits.max_capsule_bytes {
        return Err(CapsuleError::CapsuleTooLarge {
            actual: bytes.len(),
            maximum: limits.max_capsule_bytes,
        });
    }
    if bytes.is_empty() {
        return Ok(CapsuleView {
            generations: Vec::new(),
            validated_bytes: 0,
        });
    }
    let candidates = find_candidates(bytes, limits)?;
    let mut by_start = BTreeMap::<usize, Candidate>::new();
    for candidate in candidates {
        match by_start.get(&candidate.start) {
            None => {
                by_start.insert(candidate.start, candidate);
            }
            Some(existing) if existing.header == candidate.header => {
                let merged = Candidate {
                    primary_valid: existing.primary_valid || candidate.primary_valid,
                    trailing_valid: existing.trailing_valid || candidate.trailing_valid,
                    ..*existing
                };
                by_start.insert(candidate.start, merged);
            }
            Some(_) => {
                return Err(CapsuleError::AmbiguousGeneration {
                    offset: candidate.start,
                });
            }
        }
    }

    let mut generations = Vec::new();
    generations
        .try_reserve(by_start.len().min(limits.max_generations))
        .map_err(|_| CapsuleError::AllocationFailed)?;
    let mut offset = 0_usize;
    while offset < bytes.len() {
        if generations.len() >= limits.max_generations {
            return Err(CapsuleError::TooManyGenerations {
                maximum: limits.max_generations,
            });
        }
        let Some(candidate) = by_start.get(&offset) else {
            if allow_torn_tail && is_recoverable_torn_tail(bytes, offset, &generations, limits)? {
                break;
            }
            return Err(CapsuleError::NoRecoverableHeader { offset });
        };
        let payload_len = usize::try_from(candidate.header.payload_len)
            .map_err(|_| CapsuleError::ArithmeticOverflow)?;
        let payload_start = offset
            .checked_add(HEADER_BYTES)
            .ok_or(CapsuleError::ArithmeticOverflow)?;
        let payload_end = payload_start
            .checked_add(payload_len)
            .ok_or(CapsuleError::ArithmeticOverflow)?;
        let end = payload_end
            .checked_add(HEADER_BYTES)
            .ok_or(CapsuleError::ArithmeticOverflow)?;
        if end > bytes.len() {
            return Err(CapsuleError::UnframedBytes { offset });
        }
        let payload = &bytes[payload_start..payload_end];
        if sha256(payload) != candidate.header.payload_digest {
            return Err(CapsuleError::PayloadDigestMismatch { offset });
        }
        validate_chain(&generations, candidate)?;
        generations.push(CapsuleGeneration {
            offset: u64::try_from(offset).map_err(|_| CapsuleError::ArithmeticOverflow)?,
            generation: candidate.header.generation,
            phase: candidate.header.phase,
            previous_offset: candidate.header.previous_offset,
            identity: candidate.header.identity,
            payload_digest: candidate.header.payload_digest,
            payload,
            primary_header_valid: candidate.primary_valid,
            trailing_header_valid: candidate.trailing_valid,
        });
        offset = end;
    }
    if !allow_torn_tail && offset != bytes.len() {
        return Err(CapsuleError::UnframedBytes { offset });
    }
    Ok(CapsuleView {
        generations,
        validated_bytes: offset,
    })
}

fn is_recoverable_torn_tail(
    bytes: &[u8],
    offset: usize,
    generations: &[CapsuleGeneration<'_>],
    limits: CapsuleLimits,
) -> Result<bool, CapsuleError> {
    let remaining = bytes
        .len()
        .checked_sub(offset)
        .ok_or(CapsuleError::ArithmeticOverflow)?;
    if remaining == 0 {
        return Ok(false);
    }
    if remaining < HEADER_BYTES {
        return Ok(true);
    }
    let header = decode_header(&bytes[offset..offset + HEADER_BYTES])?;
    let payload_len =
        usize::try_from(header.payload_len).map_err(|_| CapsuleError::ArithmeticOverflow)?;
    if payload_len > limits.max_generation_bytes {
        return Err(CapsuleError::GenerationTooLarge {
            actual: payload_len,
            maximum: limits.max_generation_bytes,
        });
    }
    let record_end = offset
        .checked_add(HEADER_BYTES)
        .and_then(|value| value.checked_add(payload_len))
        .and_then(|value| value.checked_add(HEADER_BYTES))
        .ok_or(CapsuleError::ArithmeticOverflow)?;
    if record_end <= bytes.len() {
        return Ok(false);
    }
    validate_chain(
        generations,
        &Candidate {
            start: offset,
            header,
            primary_valid: true,
            trailing_valid: false,
        },
    )?;
    Ok(true)
}

fn find_candidates(bytes: &[u8], limits: CapsuleLimits) -> Result<Vec<Candidate>, CapsuleError> {
    let mut candidates = Vec::new();
    candidates
        .try_reserve(
            limits
                .max_generations
                .saturating_mul(2)
                .min(bytes.len() / 8 + 1),
        )
        .map_err(|_| CapsuleError::AllocationFailed)?;
    for position in 0..=bytes.len().saturating_sub(MAGIC.len()) {
        if &bytes[position..position + MAGIC.len()] != MAGIC {
            continue;
        }
        let Some(header_bytes) = bytes.get(position..position.saturating_add(HEADER_BYTES)) else {
            continue;
        };
        let Ok(header) = decode_header(header_bytes) else {
            continue;
        };
        let payload_len =
            usize::try_from(header.payload_len).map_err(|_| CapsuleError::ArithmeticOverflow)?;
        if payload_len > limits.max_generation_bytes {
            continue;
        }
        if let Some(candidate) = candidate_as_primary(bytes, position, header, payload_len)? {
            candidates.push(candidate);
        }
        if let Some(candidate) = candidate_as_trailing(bytes, position, header, payload_len) {
            candidates.push(candidate);
        }
    }
    Ok(candidates)
}

fn candidate_as_primary(
    bytes: &[u8],
    start: usize,
    header: Header,
    payload_len: usize,
) -> Result<Option<Candidate>, CapsuleError> {
    let trailing = start
        .checked_add(HEADER_BYTES)
        .and_then(|value| value.checked_add(payload_len))
        .ok_or(CapsuleError::ArithmeticOverflow)?;
    let Some(trailing_bytes) = bytes.get(trailing..trailing.saturating_add(HEADER_BYTES)) else {
        return Ok(None);
    };
    let trailing_header = decode_header(trailing_bytes).ok();
    if trailing_header.is_some_and(|value| value != header) {
        return Ok(None);
    }
    Ok(Some(Candidate {
        start,
        header,
        primary_valid: true,
        trailing_valid: trailing_header == Some(header),
    }))
}

fn candidate_as_trailing(
    bytes: &[u8],
    trailing: usize,
    header: Header,
    payload_len: usize,
) -> Option<Candidate> {
    let start = trailing.checked_sub(HEADER_BYTES.saturating_add(payload_len))?;
    let primary_bytes = bytes.get(start..start.saturating_add(HEADER_BYTES))?;
    let primary_header = decode_header(primary_bytes).ok();
    if primary_header.is_some_and(|value| value != header) {
        return None;
    }
    Some(Candidate {
        start,
        header,
        primary_valid: primary_header == Some(header),
        trailing_valid: true,
    })
}

fn validate_chain(
    generations: &[CapsuleGeneration<'_>],
    candidate: &Candidate,
) -> Result<(), CapsuleError> {
    match generations.last() {
        None => {
            if candidate.header.generation != 0
                || candidate.header.phase != TransactionPhase::Discovered
                || candidate.header.previous_offset.is_some()
            {
                return Err(CapsuleError::FirstGenerationInvalid);
            }
        }
        Some(previous) => {
            let expected_generation = previous
                .generation
                .checked_add(1)
                .ok_or(CapsuleError::GenerationOverflow)?;
            if candidate.header.generation != expected_generation {
                return Err(CapsuleError::GenerationSequence {
                    expected: expected_generation,
                    actual: candidate.header.generation,
                });
            }
            if candidate.header.previous_offset != Some(previous.offset) {
                return Err(CapsuleError::PreviousOffsetMismatch {
                    expected: Some(previous.offset),
                    actual: candidate.header.previous_offset,
                });
            }
            if candidate.header.identity != previous.identity {
                return Err(CapsuleError::IdentityChanged);
            }
            if !candidate.header.phase.may_follow(previous.phase) {
                return Err(CapsuleError::InvalidPhaseTransition {
                    previous: previous.phase,
                    next: candidate.header.phase,
                });
            }
        }
    }
    Ok(())
}

fn validate_limits(limits: CapsuleLimits) -> Result<(), CapsuleError> {
    for (field, value) in [
        ("max_capsule_bytes", limits.max_capsule_bytes),
        ("max_generation_bytes", limits.max_generation_bytes),
        ("max_generations", limits.max_generations),
    ] {
        if value == 0 {
            return Err(CapsuleError::InvalidLimit { field });
        }
    }
    Ok(())
}

fn encode_header(header: Header) -> [u8; HEADER_BYTES] {
    let mut bytes = [0_u8; HEADER_BYTES];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..10].copy_from_slice(&CAPSULE_VERSION.to_le_bytes());
    bytes[10..12].copy_from_slice(&136_u16.to_le_bytes());
    bytes[16..24].copy_from_slice(&header.generation.to_le_bytes());
    bytes[24] = header.phase as u8;
    bytes[32..40].copy_from_slice(&header.payload_len.to_le_bytes());
    bytes[40..48].copy_from_slice(&header.previous_offset.unwrap_or(NO_PREVIOUS).to_le_bytes());
    bytes[48..64].copy_from_slice(&header.identity.transaction_id);
    bytes[64..96].copy_from_slice(&header.identity.source_digest);
    bytes[96..128].copy_from_slice(&header.payload_digest);
    let checksum = header_crc(&bytes);
    bytes[CRC_OFFSET..CRC_OFFSET + 4].copy_from_slice(&checksum.to_le_bytes());
    bytes
}

fn decode_header(bytes: &[u8]) -> Result<Header, CapsuleError> {
    if bytes.len() != HEADER_BYTES || &bytes[..8] != MAGIC {
        return Err(CapsuleError::NoRecoverableHeader { offset: 0 });
    }
    let version = read_u16(bytes, 8);
    if version != CAPSULE_VERSION {
        return Err(CapsuleError::UnsupportedVersion { version });
    }
    let header_len = read_u16(bytes, 10);
    if usize::from(header_len) != HEADER_BYTES {
        return Err(CapsuleError::InvalidHeaderLength { actual: header_len });
    }
    if bytes[12..16].iter().any(|byte| *byte != 0)
        || bytes[25..32].iter().any(|byte| *byte != 0)
        || bytes[132..136].iter().any(|byte| *byte != 0)
    {
        return Err(CapsuleError::NonZeroReserved);
    }
    if read_u32(bytes, CRC_OFFSET) != header_crc(bytes) {
        return Err(CapsuleError::NoRecoverableHeader { offset: 0 });
    }
    let phase_value = bytes[24];
    let phase = TransactionPhase::from_byte(phase_value)
        .ok_or(CapsuleError::InvalidPhase { value: phase_value })?;
    let previous = read_u64(bytes, 40);
    let mut transaction_id = [0_u8; 16];
    transaction_id.copy_from_slice(&bytes[48..64]);
    let mut source_digest = [0_u8; 32];
    source_digest.copy_from_slice(&bytes[64..96]);
    let mut payload_digest = [0_u8; 32];
    payload_digest.copy_from_slice(&bytes[96..128]);
    Ok(Header {
        generation: read_u64(bytes, 16),
        phase,
        payload_len: read_u64(bytes, 32),
        previous_offset: (previous != NO_PREVIOUS).then_some(previous),
        identity: CapsuleIdentity {
            transaction_id,
            source_digest,
        },
        payload_digest,
    })
}

fn header_crc(bytes: &[u8]) -> u32 {
    let mut hasher = Crc32::new();
    hasher.update(&bytes[..CRC_OFFSET]);
    hasher.update(&[0_u8; 4]);
    hasher.update(&bytes[CRC_OFFSET + 4..HEADER_BYTES]);
    hasher.finalize()
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

const fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

const fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

const fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMITS: CapsuleLimits = CapsuleLimits {
        max_capsule_bytes: 64 * 1024,
        max_generation_bytes: 4096,
        max_generations: 16,
    };

    const IDENTITY: CapsuleIdentity = CapsuleIdentity {
        transaction_id: [0x11; 16],
        source_digest: [0x22; 32],
    };

    #[test]
    fn appends_and_recovers_monotonic_generations() {
        let mut bytes = Vec::new();
        append_generation(
            &mut bytes,
            IDENTITY,
            TransactionPhase::Discovered,
            b"manifest",
            LIMITS,
        )
        .unwrap();
        append_generation(
            &mut bytes,
            IDENTITY,
            TransactionPhase::Reserved,
            b"reservations",
            LIMITS,
        )
        .unwrap();
        append_generation(
            &mut bytes,
            IDENTITY,
            TransactionPhase::Relocating,
            b"moves",
            LIMITS,
        )
        .unwrap();
        let view = scan_capsule(&bytes, LIMITS).unwrap();
        assert_eq!(view.generations().len(), 3);
        assert_eq!(view.newest().unwrap().payload, b"moves");
        assert_eq!(view.newest().unwrap().generation, 2);
    }

    #[test]
    fn recovers_with_either_header_copy_corrupt() {
        let mut original = Vec::new();
        append_generation(
            &mut original,
            IDENTITY,
            TransactionPhase::Discovered,
            b"abc",
            LIMITS,
        )
        .unwrap();
        let mut primary_bad = original.clone();
        primary_bad[20] ^= 1;
        let recovered = scan_capsule(&primary_bad, LIMITS).unwrap();
        assert!(!recovered.newest().unwrap().primary_header_valid);
        assert!(recovered.newest().unwrap().trailing_header_valid);

        let mut trailing_bad = original;
        let trailing = HEADER_BYTES + 3;
        trailing_bad[trailing + 20] ^= 1;
        let recovered = scan_capsule(&trailing_bad, LIMITS).unwrap();
        assert!(recovered.newest().unwrap().primary_header_valid);
        assert!(!recovered.newest().unwrap().trailing_header_valid);
    }

    #[test]
    fn rejects_payload_corruption_and_truncated_tail() {
        let mut bytes = Vec::new();
        append_generation(
            &mut bytes,
            IDENTITY,
            TransactionPhase::Discovered,
            b"abc",
            LIMITS,
        )
        .unwrap();
        bytes[HEADER_BYTES + 1] ^= 1;
        assert!(matches!(
            scan_capsule(&bytes, LIMITS),
            Err(CapsuleError::PayloadDigestMismatch { .. })
        ));

        let mut truncated = Vec::new();
        append_generation(
            &mut truncated,
            IDENTITY,
            TransactionPhase::Discovered,
            b"abc",
            LIMITS,
        )
        .unwrap();
        truncated.pop();
        assert!(scan_capsule(&truncated, LIMITS).is_err());
    }

    #[test]
    fn recovery_ignores_only_a_torn_newest_append() {
        let mut bytes = Vec::new();
        append_generation(
            &mut bytes,
            IDENTITY,
            TransactionPhase::Discovered,
            b"durable recovery bytes",
            LIMITS,
        )
        .unwrap();
        let durable_len = bytes.len();
        append_generation(
            &mut bytes,
            IDENTITY,
            TransactionPhase::Reserved,
            b"new checkpoint",
            LIMITS,
        )
        .unwrap();

        for cut in durable_len + 1..bytes.len() {
            let view = recover_capsule(&bytes[..cut], LIMITS).unwrap();
            assert_eq!(view.validated_bytes(), durable_len);
            assert_eq!(view.newest().unwrap().phase, TransactionPhase::Discovered);
            assert!(scan_capsule(&bytes[..cut], LIMITS).is_err());
        }

        let mut completed_but_corrupt = bytes;
        completed_but_corrupt[durable_len + HEADER_BYTES] ^= 1;
        assert!(recover_capsule(&completed_but_corrupt, LIMITS).is_err());
    }

    #[test]
    fn refuses_phase_skips_reopens_and_identity_changes() {
        let mut bytes = Vec::new();
        append_generation(
            &mut bytes,
            IDENTITY,
            TransactionPhase::Discovered,
            b"",
            LIMITS,
        )
        .unwrap();
        assert!(matches!(
            append_generation(
                &mut bytes,
                IDENTITY,
                TransactionPhase::Activated,
                b"",
                LIMITS
            ),
            Err(CapsuleError::InvalidPhaseTransition { .. })
        ));
        let other = CapsuleIdentity {
            transaction_id: [9; 16],
            ..IDENTITY
        };
        assert_eq!(
            append_generation(&mut bytes, other, TransactionPhase::Reserved, b"", LIMITS),
            Err(CapsuleError::IdentityChanged)
        );
    }

    #[test]
    fn rollback_is_terminal_and_finalize_requires_full_sequence() {
        let mut rolled_back = Vec::new();
        append_generation(
            &mut rolled_back,
            IDENTITY,
            TransactionPhase::Discovered,
            b"",
            LIMITS,
        )
        .unwrap();
        append_generation(
            &mut rolled_back,
            IDENTITY,
            TransactionPhase::RolledBack,
            b"",
            LIMITS,
        )
        .unwrap();
        assert!(
            append_generation(
                &mut rolled_back,
                IDENTITY,
                TransactionPhase::Reserved,
                b"",
                LIMITS
            )
            .is_err()
        );

        let mut finalized = Vec::new();
        for phase in [
            TransactionPhase::Discovered,
            TransactionPhase::Reserved,
            TransactionPhase::Relocating,
            TransactionPhase::TargetStaged,
            TransactionPhase::BackupBootWritten,
            TransactionPhase::Activated,
            TransactionPhase::Verified,
            TransactionPhase::Finalized,
        ] {
            append_generation(&mut finalized, IDENTITY, phase, &[], LIMITS).unwrap();
        }
        assert_eq!(
            scan_capsule(&finalized, LIMITS)
                .unwrap()
                .generations()
                .len(),
            8
        );
    }

    #[test]
    fn enforces_all_resource_caps_before_append() {
        let tiny = CapsuleLimits {
            max_capsule_bytes: 300,
            max_generation_bytes: 2,
            max_generations: 1,
        };
        let mut bytes = Vec::new();
        assert!(matches!(
            append_generation(
                &mut bytes,
                IDENTITY,
                TransactionPhase::Discovered,
                b"abc",
                tiny
            ),
            Err(CapsuleError::GenerationTooLarge { .. })
        ));
        append_generation(
            &mut bytes,
            IDENTITY,
            TransactionPhase::Discovered,
            b"a",
            tiny,
        )
        .unwrap();
        assert!(matches!(
            append_generation(&mut bytes, IDENTITY, TransactionPhase::Reserved, b"", tiny),
            Err(CapsuleError::TooManyGenerations { .. })
        ));
    }
}
