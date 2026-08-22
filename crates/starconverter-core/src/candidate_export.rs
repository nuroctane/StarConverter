//! Copy-based candidate-image export with source-byte immutability proof.
//!
//! This is deliberately separate from the in-place transaction executor. It accepts a read-only
//! [`PhaseWritePreview`], copies the complete regular source image to one caller-selected new file,
//! applies the candidate writes only to that copy, independently reinspects the result, and checks
//! a path/content-stable manifest against the target graph. It cannot overwrite a path, open a raw
//! device, authorize in-place activation, or resize the source.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest, Sha256};

use crate::conversion::{OpaqueWriteSets, ReservedWrite};
use crate::image::{ImageError, ImageFile, ImageIdentity, reject_device_like_path};
use crate::inspect::{InspectionError, inspect_open_image};
use crate::object::ObjectGraph;
use crate::overlay::OverlayWrite;
use crate::phase::PhaseWritePreview;
use crate::preservation::{
    PreservationError, PreservationLimits, PreservationReport, decode_escrow,
};
use crate::verify::{VerificationError, VerificationLimits, VerificationManifest, build_manifest};
use crate::{FileSystem, GuaranteeMode};

const BOUND_ESCROW_MAGIC: [u8; 8] = *b"STARXESC";
const BOUND_ESCROW_VERSION: u16 = 1;
const BOUND_ESCROW_FIXED_BYTES: usize = 8 + 2 + 1 + 1 + 8 + (32 * 3) + 32;
static NEXT_PARTIAL: AtomicU64 = AtomicU64::new(0);

/// Explicit work and output limits for one copy-based candidate export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CandidateExportLimits {
    pub max_image_bytes: u64,
    pub copy_chunk_bytes: usize,
    pub max_writes: usize,
    pub max_replacement_bytes: usize,
    pub max_escrow_bytes: usize,
    pub verification: VerificationLimits,
}

impl Default for CandidateExportLimits {
    fn default() -> Self {
        Self {
            max_image_bytes: 16_u64 * 1024 * 1024 * 1024 * 1024,
            copy_chunk_bytes: 4 * 1024 * 1024,
            max_writes: 1_048_576,
            max_replacement_bytes: 1024 * 1024 * 1024,
            max_escrow_bytes: 64 * 1024 * 1024,
            verification: VerificationLimits::default(),
        }
    }
}

/// Evidence returned only after the new candidate and optional escrow are flushed, reinspected,
/// and published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateExportEvidence {
    pub output_path: PathBuf,
    pub escrow_path: Option<PathBuf>,
    pub target_filesystem: FileSystem,
    pub image_bytes: u64,
    pub applied_writes: usize,
    pub replacement_bytes: u64,
    pub source_sha256: [u8; 32],
    pub candidate_sha256: [u8; 32],
    pub manifest_sha256: [u8; 32],
    pub output_directory_durability: DirectoryDurability,
    pub escrow_directory_durability: Option<DirectoryDurability>,
}

/// Strength of the namespace-durability barrier completed after publishing one artifact.
///
/// File contents are always flushed before publication. Safe Rust exposes directory `sync_all` on
/// Unix, but the standard library does not expose an equivalent Windows directory-handle flush.
/// Callers must therefore retain this evidence rather than assuming equal guarantees everywhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectoryDurability {
    /// The parent directory accepted a successful `sync_all` after the namespace change.
    Synchronized,
    /// The host or filesystem does not expose a supported directory synchronization operation.
    Unsupported,
}

impl DirectoryDurability {
    /// Stable label for CLI, GUI, logs, and saved evidence.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Synchronized => "synchronized",
            Self::Unsupported => "unsupported",
        }
    }
}

impl fmt::Display for DirectoryDurability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Decoded candidate-bound escrow sidecar.
///
/// The embedded preservation payload retains source-only semantics. The envelope prevents a valid
/// sidecar from another conversion in the same direction from being silently substituted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundEscrow {
    pub source_filesystem: FileSystem,
    pub target_filesystem: FileSystem,
    pub source_sha256: [u8; 32],
    pub candidate_sha256: [u8; 32],
    pub manifest_sha256: [u8; 32],
    pub preservation_payload: Vec<u8>,
}

/// Explicit work and allocation limits for read-only export verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CandidateVerificationLimits {
    pub max_image_bytes: u64,
    pub hash_chunk_bytes: usize,
    pub max_escrow_bytes: usize,
    pub verification: VerificationLimits,
}

impl Default for CandidateVerificationLimits {
    fn default() -> Self {
        let export = CandidateExportLimits::default();
        Self {
            max_image_bytes: export.max_image_bytes,
            hash_chunk_bytes: export.copy_chunk_bytes,
            max_escrow_bytes: export.max_escrow_bytes,
            verification: export.verification,
        }
    }
}

/// Evidence returned only after every bound-export check succeeds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateVerificationEvidence {
    pub candidate_path: PathBuf,
    pub escrow_path: PathBuf,
    pub source_path: Option<PathBuf>,
    pub source_filesystem: FileSystem,
    pub target_filesystem: FileSystem,
    pub candidate_bytes: u64,
    pub source_bytes: Option<u64>,
    pub source_sha256: [u8; 32],
    pub candidate_sha256: [u8; 32],
    pub manifest_sha256: [u8; 32],
    pub logical_bytes_hashed: u64,
    pub escrow_schema_version: u16,
    pub escrow_records: usize,
}

/// Refusal or failure from the copy-only exporter.
#[derive(Debug)]
pub enum CandidateExportError {
    InvalidLimit(&'static str),
    ImageTooLarge {
        actual: u64,
        maximum: u64,
    },
    WriteLimitExceeded {
        actual: usize,
        maximum: usize,
    },
    ReplacementLimitExceeded {
        actual: u64,
        maximum: usize,
    },
    EscrowLimitExceeded {
        actual: usize,
        maximum: usize,
    },
    EscrowEnvelope(&'static str),
    EscrowEnvelopeChecksum,
    OutputExists(PathBuf),
    OutputHasNoFileName(PathBuf),
    OutputParentNotDirectory(PathBuf),
    OutputAliasesSource(PathBuf),
    OutputAndEscrowAlias(PathBuf),
    EscrowPathRequired,
    UnexpectedEscrowPath,
    PolicyRefused,
    PolicyDirectionMismatch,
    ContentOnlyUnsupported,
    PreviewShape(&'static str),
    PreviewDoesNotMatchSource {
        offset: u64,
    },
    ArithmeticOverflow(&'static str),
    Io {
        operation: &'static str,
        source: io::Error,
    },
    Image(ImageError),
    Preservation(PreservationError),
    Inspection(InspectionError),
    SourceInspectionMismatch,
    TargetInspectionMismatch,
    Verification(VerificationError),
    ManifestMismatch,
    SourceChangedAfterExport,
    CandidateHashMismatch,
    CandidateManifestMismatch,
    CandidateFilesystemMismatch {
        expected: FileSystem,
        actual: FileSystem,
    },
    SourceHashMismatch,
    SourceFilesystemMismatch {
        expected: FileSystem,
        actual: FileSystem,
    },
    PublishedDirectorySyncFailed {
        published_path: PathBuf,
        partial_path: PathBuf,
        partial_removed: bool,
        source: io::Error,
    },
    PublishedPartialCleanupFailed {
        published_path: PathBuf,
        partial_path: PathBuf,
        source: io::Error,
    },
    PublicationCollision {
        destination: PathBuf,
        partial_path: PathBuf,
    },
    PublicationFailed {
        destination: PathBuf,
        partial_path: PathBuf,
        source: io::Error,
    },
    PartialIdentityMismatch(PathBuf),
    PublishedIdentityMismatch(PathBuf),
}

impl fmt::Display for CandidateExportError {
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit(field) => {
                write!(formatter, "candidate export limit {field} is zero")
            }
            Self::ImageTooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "image is {actual} bytes, exceeding export cap {maximum}"
                )
            }
            Self::WriteLimitExceeded { actual, maximum } => {
                write!(
                    formatter,
                    "candidate has {actual} writes, exceeding cap {maximum}"
                )
            }
            Self::ReplacementLimitExceeded { actual, maximum } => write!(
                formatter,
                "candidate replaces {actual} bytes, exceeding cap {maximum}"
            ),
            Self::EscrowLimitExceeded { actual, maximum } => {
                write!(
                    formatter,
                    "escrow is {actual} bytes, exceeding cap {maximum}"
                )
            }
            Self::EscrowEnvelope(reason) => write!(formatter, "invalid bound escrow: {reason}"),
            Self::EscrowEnvelopeChecksum => {
                formatter.write_str("bound escrow checksum does not match its contents")
            }
            Self::OutputExists(path) => {
                write!(
                    formatter,
                    "refusing to overwrite existing path: {}",
                    path.display()
                )
            }
            Self::OutputHasNoFileName(path) => {
                write!(formatter, "output has no file name: {}", path.display())
            }
            Self::OutputParentNotDirectory(path) => {
                write!(
                    formatter,
                    "output parent is not a directory: {}",
                    path.display()
                )
            }
            Self::OutputAliasesSource(path) => {
                write!(
                    formatter,
                    "output aliases the source image: {}",
                    path.display()
                )
            }
            Self::OutputAndEscrowAlias(path) => write!(
                formatter,
                "candidate and escrow resolve to the same path: {}",
                path.display()
            ),
            Self::EscrowPathRequired => {
                formatter.write_str("escrow mode requires a new escrow output path")
            }
            Self::UnexpectedEscrowPath => formatter.write_str(
                "an escrow path was supplied, but this preservation report has no escrow",
            ),
            Self::PolicyRefused => formatter.write_str("preservation policy refused this export"),
            Self::PolicyDirectionMismatch => {
                formatter.write_str("preservation report direction does not match the preview")
            }
            Self::ContentOnlyUnsupported => formatter
                .write_str("copy-based conversion requires strict or escrow losslessness mode"),
            Self::PreviewShape(reason) => write!(formatter, "invalid phase preview: {reason}"),
            Self::PreviewDoesNotMatchSource { offset } => write!(
                formatter,
                "preview rollback bytes do not match the source at offset {offset}"
            ),
            Self::ArithmeticOverflow(calculation) => {
                write!(formatter, "overflow while calculating {calculation}")
            }
            Self::Io { operation, source } => write!(formatter, "{operation}: {source}"),
            Self::Image(source) => write!(formatter, "source image access failed: {source}"),
            Self::Preservation(source) => write!(formatter, "escrow validation failed: {source}"),
            Self::Inspection(source) => {
                write!(formatter, "image inspection failed: {source}")
            }
            Self::SourceInspectionMismatch => formatter.write_str(
                "pinned source inspection does not match the preservation direction or is incomplete",
            ),
            Self::TargetInspectionMismatch => formatter
                .write_str("candidate reinspection did not produce the expected complete target"),
            Self::Verification(source) => {
                write!(formatter, "manifest verification failed: {source}")
            }
            Self::ManifestMismatch => formatter.write_str(
                "reinspected candidate namespace/content manifest does not match the plan",
            ),
            Self::SourceChangedAfterExport => {
                formatter.write_str("source content hash changed during candidate export")
            }
            Self::CandidateHashMismatch => formatter
                .write_str("candidate SHA-256 does not match the bound escrow envelope"),
            Self::CandidateManifestMismatch => formatter.write_str(
                "candidate logical namespace/content manifest does not match the bound escrow envelope",
            ),
            Self::CandidateFilesystemMismatch { expected, actual } => write!(
                formatter,
                "candidate filesystem is {actual}, but the bound escrow requires {expected}",
            ),
            Self::SourceHashMismatch => {
                formatter.write_str("source SHA-256 does not match the bound escrow envelope")
            }
            Self::SourceFilesystemMismatch { expected, actual } => write!(
                formatter,
                "source filesystem is {actual}, but the bound escrow requires {expected}",
            ),
            Self::PublishedDirectorySyncFailed {
                published_path,
                partial_path,
                partial_removed,
                source,
            } => {
                let cleanup = if *partial_removed {
                    "was removed, but that removal is not known durable"
                } else {
                    "was retained"
                };
                write!(
                    formatter,
                    "published {} but could not make its parent-directory update durable; partial {} {cleanup}: {source}",
                    published_path.display(),
                    partial_path.display(),
                )
            }
            Self::PublishedPartialCleanupFailed {
                published_path,
                partial_path,
                source,
            } => write!(
                formatter,
                "published {} but could not remove partial hard-link {}: {source}",
                published_path.display(),
                partial_path.display(),
            ),
            Self::PublicationCollision {
                destination,
                partial_path,
            } => write!(
                formatter,
                "refusing to overwrite raced-in destination {}; unpublished partial was retained at {}",
                destination.display(),
                partial_path.display(),
            ),
            Self::PublicationFailed {
                destination,
                partial_path,
                source,
            } => write!(
                formatter,
                "could not atomically publish {} without replacement; partial was retained at {}: {source}",
                destination.display(),
                partial_path.display(),
            ),
            Self::PartialIdentityMismatch(path) => write!(
                formatter,
                "verified partial path no longer identifies the pinned file: {}",
                path.display(),
            ),
            Self::PublishedIdentityMismatch(path) => write!(
                formatter,
                "published path does not identify the verified pinned file: {}",
                path.display(),
            ),
        }
    }
}

impl std::error::Error for CandidateExportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. }
            | Self::PublishedDirectorySyncFailed { source, .. }
            | Self::PublishedPartialCleanupFailed { source, .. }
            | Self::PublicationFailed { source, .. } => Some(source),
            Self::Image(source) => Some(source),
            Self::Preservation(source) => Some(source),
            Self::Inspection(source) => Some(source),
            Self::Verification(source) => Some(source),
            _ => None,
        }
    }
}

impl From<ImageError> for CandidateExportError {
    fn from(value: ImageError) -> Self {
        Self::Image(value)
    }
}

impl From<PreservationError> for CandidateExportError {
    fn from(value: PreservationError) -> Self {
        Self::Preservation(value)
    }
}

impl From<InspectionError> for CandidateExportError {
    fn from(value: InspectionError) -> Self {
        Self::Inspection(value)
    }
}

impl From<VerificationError> for CandidateExportError {
    fn from(value: VerificationError) -> Self {
        Self::Verification(value)
    }
}

/// Decodes and verifies the integrity of a candidate-bound escrow sidecar.
///
/// `max_payload_bytes` bounds the embedded schema-v4 preservation payload before allocation.
///
/// # Errors
///
/// Refuses malformed, oversized, unsupported, trailing, or checksum-invalid envelopes.
pub fn decode_bound_escrow(
    bytes: &[u8],
    max_payload_bytes: usize,
) -> Result<BoundEscrow, CandidateExportError> {
    if max_payload_bytes == 0 {
        return Err(CandidateExportError::InvalidLimit("max_escrow_bytes"));
    }
    if bytes.len() < BOUND_ESCROW_FIXED_BYTES {
        return Err(CandidateExportError::EscrowEnvelope("truncated envelope"));
    }
    if bytes[..8] != BOUND_ESCROW_MAGIC {
        return Err(CandidateExportError::EscrowEnvelope("unexpected magic"));
    }
    let version = u16::from_le_bytes([bytes[8], bytes[9]]);
    if version != BOUND_ESCROW_VERSION {
        return Err(CandidateExportError::EscrowEnvelope(
            "unsupported envelope version",
        ));
    }
    let source_filesystem = decode_filesystem(bytes[10])?;
    let target_filesystem = decode_filesystem(bytes[11])?;
    if source_filesystem == target_filesystem {
        return Err(CandidateExportError::EscrowEnvelope(
            "source and target filesystems are identical",
        ));
    }
    let payload_len =
        usize::try_from(u64::from_le_bytes(bytes[12..20].try_into().map_err(
            |_| CandidateExportError::EscrowEnvelope("truncated payload length"),
        )?))
        .map_err(|_| CandidateExportError::EscrowEnvelope("payload length is not representable"))?;
    if payload_len > max_payload_bytes {
        return Err(CandidateExportError::EscrowLimitExceeded {
            actual: payload_len,
            maximum: max_payload_bytes,
        });
    }
    let expected_len = BOUND_ESCROW_FIXED_BYTES.checked_add(payload_len).ok_or(
        CandidateExportError::ArithmeticOverflow("bound escrow length"),
    )?;
    if bytes.len() != expected_len {
        return Err(CandidateExportError::EscrowEnvelope(
            "payload length or trailing bytes mismatch",
        ));
    }
    let checksum_offset = expected_len - 32;
    let expected_checksum: [u8; 32] = bytes[checksum_offset..]
        .try_into()
        .map_err(|_| CandidateExportError::EscrowEnvelope("truncated checksum"))?;
    let actual_checksum: [u8; 32] = Sha256::digest(&bytes[..checksum_offset]).into();
    if actual_checksum != expected_checksum {
        return Err(CandidateExportError::EscrowEnvelopeChecksum);
    }
    let source_sha256 = bytes[20..52]
        .try_into()
        .map_err(|_| CandidateExportError::EscrowEnvelope("truncated source hash"))?;
    let candidate_sha256 = bytes[52..84]
        .try_into()
        .map_err(|_| CandidateExportError::EscrowEnvelope("truncated candidate hash"))?;
    let manifest_sha256 = bytes[84..116]
        .try_into()
        .map_err(|_| CandidateExportError::EscrowEnvelope("truncated manifest hash"))?;
    let preservation_payload = bytes[116..checksum_offset].to_vec();
    Ok(BoundEscrow {
        source_filesystem,
        target_filesystem,
        source_sha256,
        candidate_sha256,
        manifest_sha256,
        preservation_payload,
    })
}

/// Verifies a candidate image and its bound escrow without opening any path for write.
///
/// Both required paths, and the optional original source, must resolve to regular files. The
/// candidate is hashed, fully inspected, and reduced to the same deterministic logical manifest
/// used during export. When `source_path` is supplied, its filesystem and complete byte hash are
/// also checked against the envelope. No raw-device path is accepted.
///
/// # Errors
///
/// Refuses non-regular or device-like paths, invalid or oversized envelopes/images, malformed
/// preservation payloads, incomplete filesystem inventories, and every binding mismatch.
pub fn verify_bound_export(
    candidate_path: impl AsRef<Path>,
    escrow_path: impl AsRef<Path>,
    source_path: Option<&Path>,
    limits: CandidateVerificationLimits,
) -> Result<CandidateVerificationEvidence, CandidateExportError> {
    validate_verification_limits(limits)?;

    let max_envelope_bytes = BOUND_ESCROW_FIXED_BYTES
        .checked_add(limits.max_escrow_bytes)
        .ok_or(CandidateExportError::ArithmeticOverflow(
            "bound escrow verification limit",
        ))?;
    let escrow = ImageFile::open_with_limit(escrow_path, max_envelope_bytes)?;
    let escrow_bytes =
        usize::try_from(escrow.len()).map_err(|_| CandidateExportError::EscrowLimitExceeded {
            actual: usize::MAX,
            maximum: limits.max_escrow_bytes,
        })?;
    if escrow_bytes > max_envelope_bytes {
        return Err(CandidateExportError::EscrowLimitExceeded {
            actual: escrow_bytes,
            maximum: max_envelope_bytes,
        });
    }
    let envelope_bytes = escrow.read_exact_at(0, escrow_bytes)?;
    let envelope = decode_bound_escrow(&envelope_bytes, limits.max_escrow_bytes)?;
    let decoded = decode_escrow(
        &envelope.preservation_payload,
        PreservationLimits {
            max_escrow_bytes: limits.max_escrow_bytes,
            max_record_bytes: limits.max_escrow_bytes,
            ..PreservationLimits::default()
        },
    )?;
    if decoded.source != envelope.source_filesystem || decoded.target != envelope.target_filesystem
    {
        return Err(CandidateExportError::PolicyDirectionMismatch);
    }

    let candidate = ImageFile::open(candidate_path)?;
    if candidate.len() > limits.max_image_bytes {
        return Err(CandidateExportError::ImageTooLarge {
            actual: candidate.len(),
            maximum: limits.max_image_bytes,
        });
    }
    let inspection = inspect_open_image(&candidate)?;
    if inspection.profile.filesystem != envelope.target_filesystem {
        return Err(CandidateExportError::CandidateFilesystemMismatch {
            expected: envelope.target_filesystem,
            actual: inspection.profile.filesystem,
        });
    }
    if !inspection.profile.inventory_complete {
        return Err(CandidateExportError::TargetInspectionMismatch);
    }
    let graph = normalized_graph(&inspection, envelope.target_filesystem)
        .ok_or(CandidateExportError::TargetInspectionMismatch)?;
    let manifest = build_manifest(&candidate, graph, limits.verification)?;
    if manifest.metadata_sha256 != envelope.manifest_sha256 {
        return Err(CandidateExportError::CandidateManifestMismatch);
    }
    let candidate_sha256 = hash_image(&candidate, limits.hash_chunk_bytes)?;
    if candidate_sha256 != envelope.candidate_sha256 {
        return Err(CandidateExportError::CandidateHashMismatch);
    }

    let (resolved_source_path, source_bytes) = if let Some(path) = source_path {
        let source = ImageFile::open(path)?;
        if source.len() > limits.max_image_bytes {
            return Err(CandidateExportError::ImageTooLarge {
                actual: source.len(),
                maximum: limits.max_image_bytes,
            });
        }
        let source_inspection = inspect_open_image(&source)?;
        if source_inspection.profile.filesystem != envelope.source_filesystem {
            return Err(CandidateExportError::SourceFilesystemMismatch {
                expected: envelope.source_filesystem,
                actual: source_inspection.profile.filesystem,
            });
        }
        if hash_image(&source, limits.hash_chunk_bytes)? != envelope.source_sha256 {
            return Err(CandidateExportError::SourceHashMismatch);
        }
        (
            Some(source.identity().canonical_path().to_path_buf()),
            Some(source.len()),
        )
    } else {
        (None, None)
    };

    Ok(CandidateVerificationEvidence {
        candidate_path: candidate.identity().canonical_path().to_path_buf(),
        escrow_path: escrow.identity().canonical_path().to_path_buf(),
        source_path: resolved_source_path,
        source_filesystem: envelope.source_filesystem,
        target_filesystem: envelope.target_filesystem,
        candidate_bytes: candidate.len(),
        source_bytes,
        source_sha256: envelope.source_sha256,
        candidate_sha256,
        manifest_sha256: manifest.metadata_sha256,
        logical_bytes_hashed: manifest.logical_bytes_hashed,
        escrow_schema_version: decoded.schema_version,
        escrow_records: decoded.records.len(),
    })
}

fn normalized_graph(
    inspection: &crate::inspect::ImageInspection,
    filesystem: FileSystem,
) -> Option<&ObjectGraph> {
    match filesystem {
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
}

const fn validate_verification_limits(
    limits: CandidateVerificationLimits,
) -> Result<(), CandidateExportError> {
    if limits.max_image_bytes == 0 {
        return Err(CandidateExportError::InvalidLimit("max_image_bytes"));
    }
    if limits.hash_chunk_bytes == 0 {
        return Err(CandidateExportError::InvalidLimit("hash_chunk_bytes"));
    }
    if limits.max_escrow_bytes == 0 {
        return Err(CandidateExportError::InvalidLimit("max_escrow_bytes"));
    }
    Ok(())
}

fn encode_bound_escrow(
    source_filesystem: FileSystem,
    target_filesystem: FileSystem,
    source_sha256: [u8; 32],
    candidate_sha256: [u8; 32],
    manifest_sha256: [u8; 32],
    preservation_payload: &[u8],
) -> Result<Vec<u8>, CandidateExportError> {
    let payload_len = u64::try_from(preservation_payload.len())
        .map_err(|_| CandidateExportError::ArithmeticOverflow("escrow payload length"))?;
    let capacity = BOUND_ESCROW_FIXED_BYTES
        .checked_add(preservation_payload.len())
        .ok_or(CandidateExportError::ArithmeticOverflow(
            "bound escrow capacity",
        ))?;
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(&BOUND_ESCROW_MAGIC);
    bytes.extend_from_slice(&BOUND_ESCROW_VERSION.to_le_bytes());
    bytes.push(encode_filesystem(source_filesystem)?);
    bytes.push(encode_filesystem(target_filesystem)?);
    bytes.extend_from_slice(&payload_len.to_le_bytes());
    bytes.extend_from_slice(&source_sha256);
    bytes.extend_from_slice(&candidate_sha256);
    bytes.extend_from_slice(&manifest_sha256);
    bytes.extend_from_slice(preservation_payload);
    let checksum: [u8; 32] = Sha256::digest(&bytes).into();
    bytes.extend_from_slice(&checksum);
    Ok(bytes)
}

const fn encode_filesystem(filesystem: FileSystem) -> Result<u8, CandidateExportError> {
    match filesystem {
        FileSystem::ExFat => Ok(1),
        FileSystem::Ntfs => Ok(2),
        FileSystem::Unknown => Err(CandidateExportError::EscrowEnvelope(
            "unknown filesystem cannot be bound",
        )),
    }
}

const fn decode_filesystem(value: u8) -> Result<FileSystem, CandidateExportError> {
    match value {
        1 => Ok(FileSystem::ExFat),
        2 => Ok(FileSystem::Ntfs),
        _ => Err(CandidateExportError::EscrowEnvelope(
            "unknown filesystem identifier",
        )),
    }
}

/// Creates and independently verifies a complete target image without modifying the source.
///
/// `output_path` and `escrow_path` must not exist. Escrow mode requires the latter; strict mode
/// rejects it. Any failure removes only files newly created by this call.
///
/// # Errors
///
/// Refuses device-like paths, existing outputs, mismatched preview before-images or policy,
/// exhausted limits, incomplete target reinspection, manifest disagreement, and any I/O failure.
pub fn export_candidate_image(
    source: &ImageFile,
    output_path: impl AsRef<Path>,
    escrow_path: Option<&Path>,
    preview: &PhaseWritePreview,
    target_graph: &ObjectGraph,
    preservation: &PreservationReport,
    limits: CandidateExportLimits,
) -> Result<CandidateExportEvidence, CandidateExportError> {
    validate_limits(limits)?;
    validate_policy(preview, preservation, escrow_path, limits.max_escrow_bytes)?;
    let source_inspection = inspect_open_image(source)?;
    if source_inspection.profile.filesystem != preservation.source
        || !source_inspection.profile.inventory_complete
    {
        return Err(CandidateExportError::SourceInspectionMismatch);
    }
    if source.len() > limits.max_image_bytes {
        return Err(CandidateExportError::ImageTooLarge {
            actual: source.len(),
            maximum: limits.max_image_bytes,
        });
    }

    let output = resolve_new_path(output_path.as_ref())?;
    if output == source.identity().canonical_path() {
        return Err(CandidateExportError::OutputAliasesSource(output));
    }
    let escrow = escrow_path.map(resolve_new_path).transpose()?;
    if escrow.as_ref().is_some_and(|path| path == &output) {
        return Err(CandidateExportError::OutputAndEscrowAlias(output));
    }
    if let Some(path) = &escrow {
        if path == source.identity().canonical_path() {
            return Err(CandidateExportError::OutputAliasesSource(path.clone()));
        }
    }

    let (write_count, replacement_bytes) = validate_preview(source, preview.writes(), limits)?;
    let expected_manifest = build_manifest(source, target_graph, limits.verification)?;
    let source_sha256 = hash_image(source, limits.copy_chunk_bytes)?;

    let mut output_guard = NewFileGuard::create_partial(&output)?;
    copy_source(source, output_guard.file_mut(), limits.copy_chunk_bytes)?;
    apply_forward_writes(output_guard.file_mut(), preview.writes())?;
    output_guard
        .file()
        .sync_all()
        .map_err(|source| CandidateExportError::io("flush candidate image", source))?;

    let (manifest_sha256, candidate_sha256, candidate_identity) = verify_candidate(
        &output_guard,
        preview.target_filesystem(),
        &expected_manifest,
        limits,
    )?;
    output_guard.bind_verified_identity(candidate_identity);

    let after_sha256 = hash_image(source, limits.copy_chunk_bytes)?;
    if after_sha256 != source_sha256 {
        return Err(CandidateExportError::SourceChangedAfterExport);
    }

    let escrow_guard =
        if let (Some(bytes), Some(path)) = (preservation.escrow.as_deref(), escrow.as_deref()) {
            let envelope = encode_bound_escrow(
                preservation.source,
                preservation.target,
                source_sha256,
                candidate_sha256,
                manifest_sha256,
                bytes,
            )?;
            let mut guard = NewFileGuard::create_partial(path)?;
            guard
                .file_mut()
                .write_all(&envelope)
                .map_err(|source| CandidateExportError::io("write bound escrow", source))?;
            guard
                .file()
                .sync_all()
                .map_err(|source| CandidateExportError::io("flush bound escrow", source))?;
            guard.bind_current_identity()?;
            Some(guard)
        } else {
            None
        };

    let escrow_directory_durability =
        if let (Some(guard), Some(path)) = (escrow_guard, escrow.as_deref()) {
            Some(guard.publish(path)?)
        } else {
            None
        };
    // A published escrow path is intentionally retained if candidate publication fails. Removing
    // it by pathname here could unlink a raced-in foreign file in a hostile directory, and a lone
    // bound sidecar is safer than a final candidate without its preservation evidence.
    let output_directory_durability = output_guard.publish(&output)?;
    Ok(CandidateExportEvidence {
        output_path: output,
        escrow_path: escrow,
        target_filesystem: preview.target_filesystem(),
        image_bytes: source.len(),
        applied_writes: write_count,
        replacement_bytes,
        source_sha256,
        candidate_sha256,
        manifest_sha256,
        output_directory_durability,
        escrow_directory_durability,
    })
}

fn verify_candidate(
    guard: &NewFileGuard,
    target_filesystem: FileSystem,
    expected_manifest: &VerificationManifest,
    limits: CandidateExportLimits,
) -> Result<([u8; 32], [u8; 32], ImageIdentity), CandidateExportError> {
    let candidate = ImageFile::from_open_regular_file(
        guard.file(),
        guard.path.clone(),
        limits.copy_chunk_bytes,
    )?;
    let inspection = inspect_open_image(&candidate)?;
    if inspection.profile.filesystem != target_filesystem || !inspection.profile.inventory_complete
    {
        return Err(CandidateExportError::TargetInspectionMismatch);
    }
    let actual_graph = match target_filesystem {
        FileSystem::ExFat => inspection
            .normalized_exfat
            .as_deref()
            .map(|value| &value.graph),
        FileSystem::Ntfs => inspection
            .normalized_ntfs
            .as_deref()
            .map(|value| &value.graph),
        FileSystem::Unknown => None,
    }
    .ok_or(CandidateExportError::TargetInspectionMismatch)?;
    let actual_manifest = build_manifest(&candidate, actual_graph, limits.verification)?;
    if !expected_manifest.equivalent_to(&actual_manifest) {
        return Err(CandidateExportError::ManifestMismatch);
    }
    let candidate_sha256 = hash_image(&candidate, limits.copy_chunk_bytes)?;
    let identity = candidate.identity().clone();
    if !identity.matches_container_metadata(
        &guard
            .file()
            .metadata()
            .map_err(|source| CandidateExportError::io("revalidate candidate handle", source))?,
    ) {
        return Err(CandidateExportError::PartialIdentityMismatch(
            guard.path.clone(),
        ));
    }
    Ok((actual_manifest.metadata_sha256, candidate_sha256, identity))
}

fn validate_limits(limits: CandidateExportLimits) -> Result<(), CandidateExportError> {
    for (field, value) in [
        ("copy_chunk_bytes", limits.copy_chunk_bytes),
        ("max_writes", limits.max_writes),
        ("max_replacement_bytes", limits.max_replacement_bytes),
        ("max_escrow_bytes", limits.max_escrow_bytes),
    ] {
        if value == 0 {
            return Err(CandidateExportError::InvalidLimit(field));
        }
    }
    if limits.max_image_bytes == 0 {
        return Err(CandidateExportError::InvalidLimit("max_image_bytes"));
    }
    Ok(())
}

fn validate_policy(
    preview: &PhaseWritePreview,
    preservation: &PreservationReport,
    escrow_path: Option<&Path>,
    max_escrow_bytes: usize,
) -> Result<(), CandidateExportError> {
    if !preservation.permitted {
        return Err(CandidateExportError::PolicyRefused);
    }
    if preservation.target != preview.target_filesystem()
        || preservation.source == preservation.target
    {
        return Err(CandidateExportError::PolicyDirectionMismatch);
    }
    if preservation.mode == GuaranteeMode::ContentOnly {
        return Err(CandidateExportError::ContentOnlyUnsupported);
    }
    match (preservation.escrow.as_deref(), escrow_path) {
        (Some(bytes), Some(_)) => {
            if bytes.len() > max_escrow_bytes {
                return Err(CandidateExportError::EscrowLimitExceeded {
                    actual: bytes.len(),
                    maximum: max_escrow_bytes,
                });
            }
            let decoded = decode_escrow(
                bytes,
                PreservationLimits {
                    max_escrow_bytes,
                    max_record_bytes: max_escrow_bytes,
                    ..PreservationLimits::default()
                },
            )?;
            if decoded.source != preservation.source || decoded.target != preservation.target {
                return Err(CandidateExportError::PolicyDirectionMismatch);
            }
        }
        (Some(_), None) => return Err(CandidateExportError::EscrowPathRequired),
        (None, Some(_)) => return Err(CandidateExportError::UnexpectedEscrowPath),
        (None, None) => {}
    }
    Ok(())
}

fn validate_preview(
    source: &ImageFile,
    writes: &OpaqueWriteSets,
    limits: CandidateExportLimits,
) -> Result<(usize, u64), CandidateExportError> {
    let groups = [
        (
            &writes.target_staging[..],
            &writes.target_staging_rollback[..],
        ),
        (&writes.backup_boot[..], &writes.backup_boot_rollback[..]),
        (&writes.activation[..], &writes.activation_rollback[..]),
    ];
    let mut count = 0_usize;
    let mut bytes = 0_u64;
    for (forward, rollback) in groups {
        if forward.is_empty() || forward.len() != rollback.len() {
            return Err(CandidateExportError::PreviewShape(
                "each phase must have matching nonempty forward and rollback sets",
            ));
        }
        for (write, before) in forward.iter().zip(rollback) {
            validate_before_image(source, write, before)?;
            count = count
                .checked_add(1)
                .ok_or(CandidateExportError::ArithmeticOverflow("write count"))?;
            bytes = bytes
                .checked_add(u64::try_from(write.write.bytes.len()).map_err(|_| {
                    CandidateExportError::ArithmeticOverflow("replacement byte conversion")
                })?)
                .ok_or(CandidateExportError::ArithmeticOverflow(
                    "replacement byte total",
                ))?;
        }
    }
    if count > limits.max_writes {
        return Err(CandidateExportError::WriteLimitExceeded {
            actual: count,
            maximum: limits.max_writes,
        });
    }
    if bytes > u64::try_from(limits.max_replacement_bytes).unwrap_or(u64::MAX) {
        return Err(CandidateExportError::ReplacementLimitExceeded {
            actual: bytes,
            maximum: limits.max_replacement_bytes,
        });
    }
    Ok((count, bytes))
}

fn validate_before_image(
    source: &ImageFile,
    forward: &ReservedWrite,
    rollback: &OverlayWrite,
) -> Result<(), CandidateExportError> {
    if forward.write.offset != rollback.offset || forward.write.bytes.len() != rollback.bytes.len()
    {
        return Err(CandidateExportError::PreviewShape(
            "a forward write and rollback before-image disagree on range",
        ));
    }
    let actual = source.read_exact_at(rollback.offset, rollback.bytes.len())?;
    if actual != rollback.bytes {
        return Err(CandidateExportError::PreviewDoesNotMatchSource {
            offset: rollback.offset,
        });
    }
    Ok(())
}

fn resolve_new_path(path: &Path) -> Result<PathBuf, CandidateExportError> {
    reject_device_like_path(path)?;
    if path.exists() {
        return Err(CandidateExportError::OutputExists(path.to_path_buf()));
    }
    let name = path
        .file_name()
        .ok_or_else(|| CandidateExportError::OutputHasNoFileName(path.to_path_buf()))?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let canonical_parent = fs::canonicalize(parent)
        .map_err(|source| CandidateExportError::io("canonicalize output parent", source))?;
    if !fs::metadata(&canonical_parent)
        .map_err(|source| CandidateExportError::io("inspect output parent", source))?
        .is_dir()
    {
        return Err(CandidateExportError::OutputParentNotDirectory(
            canonical_parent,
        ));
    }
    reject_device_like_path(&canonical_parent)?;
    let resolved = canonical_parent.join(name);
    reject_device_like_path(&resolved)?;
    if resolved.exists() {
        return Err(CandidateExportError::OutputExists(resolved));
    }
    Ok(resolved)
}

fn hash_image(image: &ImageFile, chunk_bytes: usize) -> Result<[u8; 32], CandidateExportError> {
    let mut hasher = Sha256::new();
    let mut offset = 0_u64;
    while offset < image.len() {
        let remaining = image.len() - offset;
        let length = usize::try_from(remaining.min(chunk_bytes as u64))
            .map_err(|_| CandidateExportError::ArithmeticOverflow("hash chunk length"))?;
        hasher.update(image.read_exact_at(offset, length)?);
        offset =
            offset
                .checked_add(u64::try_from(length).map_err(|_| {
                    CandidateExportError::ArithmeticOverflow("hash offset conversion")
                })?)
                .ok_or(CandidateExportError::ArithmeticOverflow("hash offset"))?;
    }
    Ok(hasher.finalize().into())
}

fn copy_source(
    source: &ImageFile,
    output: &mut File,
    chunk_bytes: usize,
) -> Result<(), CandidateExportError> {
    let mut offset = 0_u64;
    while offset < source.len() {
        let remaining = source.len() - offset;
        let length = usize::try_from(remaining.min(chunk_bytes as u64))
            .map_err(|_| CandidateExportError::ArithmeticOverflow("copy chunk length"))?;
        let bytes = source.read_exact_at(offset, length)?;
        output
            .write_all(&bytes)
            .map_err(|source| CandidateExportError::io("copy source image", source))?;
        offset =
            offset
                .checked_add(u64::try_from(length).map_err(|_| {
                    CandidateExportError::ArithmeticOverflow("copy offset conversion")
                })?)
                .ok_or(CandidateExportError::ArithmeticOverflow("copy offset"))?;
    }
    Ok(())
}

fn apply_forward_writes(
    output: &mut File,
    writes: &OpaqueWriteSets,
) -> Result<(), CandidateExportError> {
    for write in writes
        .target_staging
        .iter()
        .chain(&writes.backup_boot)
        .chain(&writes.activation)
    {
        output
            .seek(SeekFrom::Start(write.write.offset))
            .map_err(|source| CandidateExportError::io("seek candidate image", source))?;
        output
            .write_all(&write.write.bytes)
            .map_err(|source| CandidateExportError::io("write candidate image", source))?;
    }
    Ok(())
}

struct NewFileGuard {
    path: PathBuf,
    file: Option<File>,
    verified_identity: Option<ImageIdentity>,
    keep: std::cell::Cell<bool>,
}

impl NewFileGuard {
    fn create(path: &Path) -> Result<Self, CandidateExportError> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;

            // Candidate images and escrow can contain the complete source volume's private data.
            // Begin restrictive; a future explicit export-permissions policy may relax the final
            // artifact after publication.
            options.mode(0o600);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;

            const FILE_SHARE_READ: u32 = 0x0000_0001;
            // Verification needs a second read handle. Denying write and delete sharing prevents
            // another Windows handle from mutating or replacing the partial before publication.
            options.share_mode(FILE_SHARE_READ);
        }
        let file = options
            .open(path)
            .map_err(|source| CandidateExportError::io("create new output", source))?;
        #[cfg(unix)]
        fs4::FileExt::try_lock(&file)
            .map_err(|source| CandidateExportError::io("lock new partial output", source.into()))?;
        let guard = Self {
            path: path.to_path_buf(),
            file: Some(file),
            verified_identity: None,
            keep: std::cell::Cell::new(false),
        };
        let metadata = guard
            .file()
            .metadata()
            .map_err(|source| CandidateExportError::io("inspect new output", source))?;
        if !metadata.is_file() {
            return Err(CandidateExportError::OutputParentNotDirectory(
                path.to_path_buf(),
            ));
        }
        Ok(guard)
    }

    fn create_partial(destination: &Path) -> Result<Self, CandidateExportError> {
        destination
            .file_name()
            .ok_or_else(|| CandidateExportError::OutputHasNoFileName(destination.to_path_buf()))?;
        let parent = destination.parent().unwrap_or_else(|| Path::new("."));
        for _ in 0..128 {
            let sequence = NEXT_PARTIAL.fetch_add(1, Ordering::Relaxed);
            let partial_name = format!(".starconverter-partial-{}-{sequence}", std::process::id());
            let partial = parent.join(partial_name);
            match Self::create(&partial) {
                Ok(guard) => return Ok(guard),
                Err(CandidateExportError::Io { source, .. })
                    if source.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Err(CandidateExportError::Io {
            operation: "create unique partial output",
            source: io::Error::new(
                io::ErrorKind::AlreadyExists,
                "exhausted partial output name attempts",
            ),
        })
    }

    const fn file(&self) -> &File {
        self.file
            .as_ref()
            .expect("a partial file remains open until publication cleanup")
    }

    const fn file_mut(&mut self) -> &mut File {
        self.file
            .as_mut()
            .expect("a partial file remains open until publication cleanup")
    }

    fn keep(&self) {
        self.keep.set(true);
    }

    fn bind_verified_identity(&mut self, identity: ImageIdentity) {
        self.verified_identity = Some(identity);
    }

    fn bind_current_identity(&mut self) -> Result<(), CandidateExportError> {
        let image = ImageFile::from_open_regular_file(self.file(), self.path.clone(), 1)?;
        self.bind_verified_identity(image.identity().clone());
        Ok(())
    }

    fn ensure_verified_path(&self, path: &Path) -> Result<(), CandidateExportError> {
        let identity = self
            .verified_identity
            .as_ref()
            .ok_or_else(|| CandidateExportError::PartialIdentityMismatch(self.path.clone()))?;
        let handle_metadata = self
            .file()
            .metadata()
            .map_err(|source| CandidateExportError::io("revalidate partial handle", source))?;
        let path_metadata = fs::metadata(path)
            .map_err(|source| CandidateExportError::io("revalidate partial path", source))?;
        if identity.matches_container_metadata(&handle_metadata)
            && identity.matches_container_metadata(&path_metadata)
        {
            Ok(())
        } else {
            Err(CandidateExportError::PartialIdentityMismatch(
                path.to_path_buf(),
            ))
        }
    }

    /// Publishes through a hard link because stable safe Rust has no portable no-replace rename.
    ///
    /// This is intentionally fail-closed on exFAT, FAT, and other filesystems without hard-link
    /// support. Falling back to `rename` would reintroduce an overwrite race on Windows and Unix.
    fn publish(self, destination: &Path) -> Result<DirectoryDurability, CandidateExportError> {
        self.publish_with(destination, &HostPublicationIo)
    }

    fn publish_with(
        mut self,
        destination: &Path,
        io: &impl PublicationIo,
    ) -> Result<DirectoryDurability, CandidateExportError> {
        if let Err(error) = self.ensure_verified_path(&self.path) {
            self.keep();
            return Err(error);
        }
        // From here on, even publication failure retains the partial. Deleting it by pathname
        // would reopen the same-UID Unix replacement race this identity check is meant to detect.
        self.keep();
        if let Err(source) = io.hard_link(&self.path, destination) {
            return if source.kind() == io::ErrorKind::AlreadyExists {
                Err(CandidateExportError::PublicationCollision {
                    destination: destination.to_path_buf(),
                    partial_path: self.path.clone(),
                })
            } else {
                Err(CandidateExportError::PublicationFailed {
                    destination: destination.to_path_buf(),
                    partial_path: self.path.clone(),
                    source,
                })
            };
        }
        // From this point onward the final path exists. Never let Drop obscure a partial-success
        // state by deleting the partial without being able to report whether cleanup was durable.
        let published_metadata = fs::metadata(destination)
            .map_err(|source| CandidateExportError::io("inspect published output", source))?;
        if !self
            .verified_identity
            .as_ref()
            .is_some_and(|identity| identity.matches_container_metadata(&published_metadata))
        {
            return Err(CandidateExportError::PublishedIdentityMismatch(
                destination.to_path_buf(),
            ));
        }
        let first_sync = io.sync_parent(destination).map_err(|source| {
            CandidateExportError::PublishedDirectorySyncFailed {
                published_path: destination.to_path_buf(),
                partial_path: self.path.clone(),
                partial_removed: false,
                source,
            }
        })?;
        self.close_file();
        io.remove_partial(&self.path).map_err(|source| {
            CandidateExportError::PublishedPartialCleanupFailed {
                published_path: destination.to_path_buf(),
                partial_path: self.path.clone(),
                source,
            }
        })?;
        let second_sync = io.sync_parent(destination).map_err(|source| {
            CandidateExportError::PublishedDirectorySyncFailed {
                published_path: destination.to_path_buf(),
                partial_path: self.path.clone(),
                partial_removed: true,
                source,
            }
        })?;
        Ok(combine_directory_durability(first_sync, second_sync))
    }

    fn close_file(&mut self) {
        if let Some(file) = self.file.take() {
            #[cfg(unix)]
            let _ = fs4::FileExt::unlock(&file);
            drop(file);
        }
    }
}

impl Drop for NewFileGuard {
    fn drop(&mut self) {
        self.close_file();
        // An unpublished partial is best-effort cleanup during unwinding because Drop cannot
        // return an I/O error. Every cleanup after publication is explicit in `publish_with`.
        if !self.keep.get() {
            let _ = fs::remove_file(&self.path);
        }
    }
}

trait PublicationIo {
    fn hard_link(&self, partial: &Path, destination: &Path) -> io::Result<()>;
    fn remove_partial(&self, partial: &Path) -> io::Result<()>;
    fn sync_parent(&self, destination: &Path) -> io::Result<DirectoryDurability>;
}

#[derive(Debug, Clone, Copy)]
struct HostPublicationIo;

impl PublicationIo for HostPublicationIo {
    fn hard_link(&self, partial: &Path, destination: &Path) -> io::Result<()> {
        fs::hard_link(partial, destination)
    }

    fn remove_partial(&self, partial: &Path) -> io::Result<()> {
        fs::remove_file(partial)
    }

    fn sync_parent(&self, destination: &Path) -> io::Result<DirectoryDurability> {
        #[cfg(unix)]
        {
            sync_parent_directory(destination)
        }
        #[cfg(not(unix))]
        {
            let _ = destination;
            // Windows requires platform directory-handle APIs that stable safe Rust does not
            // expose. Returning explicit evidence is safer than pretending that file `sync_all`
            // flushed the name.
            Ok(DirectoryDurability::Unsupported)
        }
    }
}

#[cfg(unix)]
fn sync_parent_directory(destination: &Path) -> io::Result<DirectoryDurability> {
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    let directory = File::open(parent)?;
    match directory.sync_all() {
        Ok(()) => Ok(DirectoryDurability::Synchronized),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::InvalidInput | io::ErrorKind::Unsupported
            ) =>
        {
            Ok(DirectoryDurability::Unsupported)
        }
        Err(error) => Err(error),
    }
}

const fn combine_directory_durability(
    first: DirectoryDurability,
    second: DirectoryDurability,
) -> DirectoryDurability {
    if matches!(
        (first, second),
        (
            DirectoryDurability::Synchronized,
            DirectoryDurability::Synchronized
        )
    ) {
        DirectoryDurability::Synchronized
    } else {
        DirectoryDurability::Unsupported
    }
}

impl CandidateExportError {
    const fn io(operation: &'static str, source: io::Error) -> Self {
        Self::Io { operation, source }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::conversion::OpaqueWriteSets;
    use crate::extent::ExtentGraph;
    use crate::fs::ntfs_inventory::NtfsObjectReference;
    use crate::fs::ntfs_normalize::{
        NormalizedNtfs, NtfsPreservationSidecar, NtfsSecurityDescriptorEvidence,
    };
    use crate::geometry::ReservationKind;
    use crate::object::{ObjectGraphLimits, ObjectId, ObjectKind, ObjectRecord, ObjectSemantics};
    use crate::preservation::evaluate_ntfs;

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    #[derive(Debug)]
    struct FaultingPublicationIo {
        fail_remove: bool,
        fail_sync_call: Option<usize>,
        remove_calls: Cell<usize>,
        sync_calls: Cell<usize>,
    }

    impl FaultingPublicationIo {
        const fn new(fail_remove: bool, fail_sync_call: Option<usize>) -> Self {
            Self {
                fail_remove,
                fail_sync_call,
                remove_calls: Cell::new(0),
                sync_calls: Cell::new(0),
            }
        }
    }

    impl PublicationIo for FaultingPublicationIo {
        fn hard_link(&self, partial: &Path, destination: &Path) -> io::Result<()> {
            fs::hard_link(partial, destination)
        }

        fn remove_partial(&self, partial: &Path) -> io::Result<()> {
            self.remove_calls.set(self.remove_calls.get() + 1);
            if self.fail_remove {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "injected partial cleanup failure",
                ))
            } else {
                fs::remove_file(partial)
            }
        }

        fn sync_parent(&self, _destination: &Path) -> io::Result<DirectoryDurability> {
            let call = self.sync_calls.get() + 1;
            self.sync_calls.set(call);
            if self.fail_sync_call == Some(call) {
                Err(io::Error::other("injected parent sync failure"))
            } else {
                Ok(DirectoryDurability::Synchronized)
            }
        }
    }

    struct TempFile {
        path: PathBuf,
    }

    impl TempFile {
        fn create(bytes: &[u8]) -> Self {
            let path = temp_path("source.img");
            fs::write(&path, bytes).expect("create test source");
            Self { path }
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    fn temp_path(suffix: &str) -> PathBuf {
        let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "starconverter-export-{}-{sequence}-{suffix}",
            std::process::id()
        ))
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

    fn minimal_exfat_image() -> Vec<u8> {
        const SECTOR_BYTES: usize = 512;
        const VOLUME_SECTORS: u64 = 2_048;

        let mut image = vec![0_u8; usize::try_from(VOLUME_SECTORS * 512).unwrap()];
        image[0..3].copy_from_slice(&[0xeb, 0x76, 0x90]);
        image[3..11].copy_from_slice(b"EXFAT   ");
        put_u64(&mut image, 72, VOLUME_SECTORS);
        put_u32(&mut image, 80, 24);
        put_u32(&mut image, 84, 16);
        put_u32(&mut image, 88, 40);
        put_u32(&mut image, 92, 2_008);
        put_u32(&mut image, 96, 2);
        put_u32(&mut image, 100, 0x1234_abcd);
        put_u16(&mut image, 104, 0x0100);
        image[108] = 9;
        image[110] = 1;
        image[112] = 0xff;
        put_u16(&mut image, 510, 0xaa55);
        for sector in 1..=8 {
            let signature = sector * SECTOR_BYTES + SECTOR_BYTES - 4;
            image[signature..signature + 4].copy_from_slice(&[0x00, 0x00, 0x55, 0xaa]);
        }
        let checksum = image[..11 * SECTOR_BYTES]
            .iter()
            .copied()
            .enumerate()
            .filter(|(offset, _)| !matches!(offset, 106 | 107 | 112))
            .fold(0_u32, |sum, (_, byte)| {
                sum.rotate_right(1).wrapping_add(u32::from(byte))
            });
        for offset in (11 * SECTOR_BYTES..12 * SECTOR_BYTES).step_by(4) {
            put_u32(&mut image, offset, checksum);
        }
        image.copy_within(0..12 * SECTOR_BYTES, 12 * SECTOR_BYTES);
        for cluster in [2_u32, 3, 4] {
            put_u32(
                &mut image,
                24 * SECTOR_BYTES + usize::try_from(cluster).unwrap() * 4,
                u32::MAX,
            );
        }
        let root = 40 * SECTOR_BYTES;
        image[root] = 0x81;
        put_u32(&mut image, root + 20, 3);
        put_u64(&mut image, root + 24, 251);
        let mut upcase = Vec::new();
        for code_unit in 0_u16..128 {
            let mapping = if (u16::from(b'a')..=u16::from(b'z')).contains(&code_unit) {
                code_unit - 0x20
            } else {
                code_unit
            };
            upcase.extend_from_slice(&mapping.to_le_bytes());
        }
        upcase.extend_from_slice(&0xffff_u16.to_le_bytes());
        upcase.extend_from_slice(&65_408_u16.to_le_bytes());
        image[root + 32] = 0x82;
        put_u32(
            &mut image,
            root + 36,
            crate::fs::exfat_upcase::table_checksum(&upcase),
        );
        put_u32(&mut image, root + 52, 4);
        put_u64(&mut image, root + 56, upcase.len() as u64);
        image[41 * SECTOR_BYTES] = 0b0000_0111;
        image[42 * SECTOR_BYTES..42 * SECTOR_BYTES + upcase.len()].copy_from_slice(&upcase);
        image
    }

    fn test_ntfs_escrow_payload() -> Vec<u8> {
        let root = ObjectId(1);
        let graph = ObjectGraph::build(
            root,
            vec![ObjectRecord {
                id: root,
                kind: ObjectKind::Directory,
                link_count: 0,
                semantics: ObjectSemantics::default(),
                streams: Vec::new(),
            }],
            Vec::new(),
            ExtentGraph::build(Vec::new(), 1, 1).unwrap(),
            ObjectGraphLimits {
                max_objects: 1,
                max_entries: 1,
                max_streams: 1,
                max_name_code_units: 255,
            },
        )
        .unwrap();
        let normalized = NormalizedNtfs {
            graph,
            preservation: NtfsPreservationSidecar {
                volume_serial_number: 7,
                volume_label: None,
                security_descriptors: NtfsSecurityDescriptorEvidence::Unavailable,
                root_reference: NtfsObjectReference {
                    record_number: 5,
                    sequence_number: 1,
                },
                objects: Vec::new(),
                source_extents: Vec::new(),
                scanned_records: 1,
                initialized_records: 1,
                in_use_base_records: 1,
                extension_records: 0,
                bytes_read: 1,
            },
        };
        evaluate_ntfs(
            &normalized,
            FileSystem::ExFat,
            GuaranteeMode::Escrow,
            PreservationLimits::default(),
        )
        .unwrap()
        .escrow
        .unwrap()
    }

    fn reserved(offset: u64, byte: u8) -> ReservedWrite {
        ReservedWrite {
            reservation_kind: ReservationKind::AllocationMetadata,
            write: OverlayWrite {
                offset,
                bytes: vec![byte; 512],
            },
        }
    }

    fn preview(source: &[u8]) -> PhaseWritePreview {
        let rollback = |offset: usize| OverlayWrite {
            offset: u64::try_from(offset).unwrap(),
            bytes: source[offset..offset + 512].to_vec(),
        };
        PhaseWritePreview::test_only(
            FileSystem::Ntfs,
            OpaqueWriteSets {
                target_staging: vec![reserved(512, b'S')],
                backup_boot: vec![reserved(1024, b'B')],
                activation: vec![reserved(0, b'A')],
                target_staging_rollback: vec![rollback(512)],
                backup_boot_rollback: vec![rollback(1024)],
                activation_rollback: vec![rollback(0)],
            },
            &["test-only activation gap"],
        )
    }

    #[test]
    fn copies_and_applies_all_phases_only_to_new_file() {
        let bytes = vec![b'x'; 1536];
        let source_file = TempFile::create(&bytes);
        let source = ImageFile::open_with_limit(&source_file.path, 512).unwrap();
        let preview = preview(&bytes);
        let limits = CandidateExportLimits {
            max_image_bytes: 1536,
            copy_chunk_bytes: 512,
            max_writes: 3,
            max_replacement_bytes: 1536,
            ..CandidateExportLimits::default()
        };

        assert_eq!(
            validate_preview(&source, preview.writes(), limits).unwrap(),
            (3, 1536)
        );
        let output = temp_path("candidate.img");
        {
            let mut guard = NewFileGuard::create(&output).unwrap();
            copy_source(&source, guard.file_mut(), 512).unwrap();
            apply_forward_writes(guard.file_mut(), preview.writes()).unwrap();
            guard.file().sync_all().unwrap();
            let actual = fs::read(&output).unwrap();
            assert_eq!(&actual[..512], vec![b'A'; 512]);
            assert_eq!(&actual[512..1024], vec![b'S'; 512]);
            assert_eq!(&actual[1024..], vec![b'B'; 512]);
        }
        assert!(
            !output.exists(),
            "failed export guard must remove its own file"
        );
        assert_eq!(fs::read(&source_file.path).unwrap(), bytes);
    }

    #[test]
    fn directory_durability_has_stable_user_facing_labels() {
        assert_eq!(
            DirectoryDurability::Synchronized.to_string(),
            "synchronized"
        );
        assert_eq!(DirectoryDurability::Unsupported.to_string(), "unsupported");
    }

    #[test]
    fn refuses_preview_whose_before_image_is_not_the_source() {
        let bytes = vec![b'x'; 1536];
        let source_file = TempFile::create(&bytes);
        let source = ImageFile::open(&source_file.path).unwrap();
        let original = preview(&bytes);
        let mut writes = original.writes().clone();
        writes.target_staging_rollback[0].bytes[0] ^= 0xff;
        let preview =
            PhaseWritePreview::test_only(FileSystem::Ntfs, writes, &["test-only activation gap"]);

        assert!(matches!(
            validate_preview(&source, preview.writes(), CandidateExportLimits::default()),
            Err(CandidateExportError::PreviewDoesNotMatchSource { offset: 512 })
        ));
    }

    #[test]
    fn new_path_resolution_refuses_existing_outputs() {
        let existing = TempFile::create(b"occupied");
        assert!(matches!(
            resolve_new_path(&existing.path),
            Err(CandidateExportError::OutputExists(_))
        ));
    }

    #[test]
    fn bound_escrow_round_trips_and_rejects_tampering() {
        let payload = b"schema-v4-preservation-payload";
        let encoded = encode_bound_escrow(
            FileSystem::ExFat,
            FileSystem::Ntfs,
            [0x11; 32],
            [0x22; 32],
            [0x33; 32],
            payload,
        )
        .unwrap();
        let decoded = decode_bound_escrow(&encoded, 1024).unwrap();
        assert_eq!(decoded.source_filesystem, FileSystem::ExFat);
        assert_eq!(decoded.target_filesystem, FileSystem::Ntfs);
        assert_eq!(decoded.source_sha256, [0x11; 32]);
        assert_eq!(decoded.candidate_sha256, [0x22; 32]);
        assert_eq!(decoded.manifest_sha256, [0x33; 32]);
        assert_eq!(decoded.preservation_payload, payload);

        let mut tampered = encoded;
        tampered[52] ^= 0xff;
        assert!(matches!(
            decode_bound_escrow(&tampered, 1024),
            Err(CandidateExportError::EscrowEnvelopeChecksum)
        ));
    }

    #[test]
    fn bound_escrow_identity_prevents_same_direction_substitution() {
        let first = encode_bound_escrow(
            FileSystem::Ntfs,
            FileSystem::ExFat,
            [1; 32],
            [2; 32],
            [3; 32],
            b"payload",
        )
        .unwrap();
        let second = encode_bound_escrow(
            FileSystem::Ntfs,
            FileSystem::ExFat,
            [4; 32],
            [5; 32],
            [6; 32],
            b"payload",
        )
        .unwrap();
        let first = decode_bound_escrow(&first, 1024).unwrap();
        let second = decode_bound_escrow(&second, 1024).unwrap();
        assert_ne!(first.source_sha256, second.source_sha256);
        assert_ne!(first.candidate_sha256, second.candidate_sha256);
        assert_ne!(first.manifest_sha256, second.manifest_sha256);
    }

    #[test]
    fn verifies_bound_candidate_read_only_and_reports_evidence() {
        let candidate_file = TempFile::create(&minimal_exfat_image());
        let candidate = ImageFile::open(&candidate_file.path).unwrap();
        let inspection = inspect_open_image(&candidate).unwrap();
        let graph = normalized_graph(&inspection, FileSystem::ExFat).unwrap();
        let manifest = build_manifest(&candidate, graph, VerificationLimits::default()).unwrap();
        let candidate_sha256 = hash_image(&candidate, 64 * 1024).unwrap();
        let source_sha256 = [0x5a; 32];
        let envelope = encode_bound_escrow(
            FileSystem::Ntfs,
            FileSystem::ExFat,
            source_sha256,
            candidate_sha256,
            manifest.metadata_sha256,
            &test_ntfs_escrow_payload(),
        )
        .unwrap();
        let escrow_file = TempFile::create(&envelope);
        let candidate_before = fs::read(&candidate_file.path).unwrap();
        let escrow_before = fs::read(&escrow_file.path).unwrap();

        let evidence = verify_bound_export(
            &candidate_file.path,
            &escrow_file.path,
            None,
            CandidateVerificationLimits::default(),
        )
        .unwrap();

        assert_eq!(evidence.source_filesystem, FileSystem::Ntfs);
        assert_eq!(evidence.target_filesystem, FileSystem::ExFat);
        assert_eq!(evidence.source_sha256, source_sha256);
        assert_eq!(evidence.candidate_sha256, candidate_sha256);
        assert_eq!(evidence.manifest_sha256, manifest.metadata_sha256);
        assert_eq!(evidence.escrow_schema_version, 4);
        assert_eq!(fs::read(&candidate_file.path).unwrap(), candidate_before);
        assert_eq!(fs::read(&escrow_file.path).unwrap(), escrow_before);
    }

    #[test]
    fn partial_output_is_not_exposed_at_requested_path() {
        let destination = temp_path("published.img");
        let mut guard = NewFileGuard::create_partial(&destination).unwrap();
        guard.file_mut().write_all(b"verified").unwrap();
        guard.file().sync_all().unwrap();
        guard.bind_current_identity().unwrap();
        assert!(!destination.exists());
        assert!(guard.path.exists());
        guard.publish(&destination).unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"verified");
        let _ = fs::remove_file(destination);
    }

    #[test]
    fn publication_never_replaces_an_existing_destination() {
        let destination = temp_path("publish-race.img");
        let mut guard = NewFileGuard::create_partial(&destination).unwrap();
        guard.file_mut().write_all(b"candidate").unwrap();
        guard.file().sync_all().unwrap();
        guard.bind_current_identity().unwrap();
        let partial = guard.path.clone();

        // Model another creator winning after the export's initial path checks but before publish.
        fs::write(&destination, b"foreign").unwrap();
        assert!(matches!(
            guard.publish(&destination),
            Err(CandidateExportError::PublicationCollision {
                destination: path,
                partial_path,
            }) if path == destination && partial_path == partial
        ));
        assert_eq!(fs::read(&destination).unwrap(), b"foreign");
        assert_eq!(fs::read(&partial).unwrap(), b"candidate");
        let _ = fs::remove_file(destination);
        let _ = fs::remove_file(partial);
    }

    #[cfg(unix)]
    #[test]
    fn replaced_partial_path_is_refused_without_deleting_the_replacement() {
        let destination = temp_path("identity-race-destination.img");
        let mut guard = NewFileGuard::create_partial(&destination).unwrap();
        guard.file_mut().write_all(b"verified").unwrap();
        guard.file().sync_all().unwrap();
        guard.bind_current_identity().unwrap();
        let partial = guard.path.clone();
        let moved_partial = temp_path("identity-race-original.img");
        fs::rename(&partial, &moved_partial).unwrap();
        fs::write(&partial, b"foreign").unwrap();

        assert!(matches!(
            guard.publish(&destination),
            Err(CandidateExportError::PartialIdentityMismatch(path)) if path == partial
        ));
        assert!(!destination.exists());
        assert_eq!(fs::read(&partial).unwrap(), b"foreign");
        assert_eq!(fs::read(&moved_partial).unwrap(), b"verified");
        fs::remove_file(partial).unwrap();
        fs::remove_file(moved_partial).unwrap();
    }

    #[test]
    fn published_partial_unlink_failure_is_returned_with_both_paths_intact() {
        let destination = temp_path("unlink-failure.img");
        let mut guard = NewFileGuard::create_partial(&destination).unwrap();
        guard.file_mut().write_all(b"verified").unwrap();
        guard.file().sync_all().unwrap();
        guard.bind_current_identity().unwrap();
        let partial = guard.path.clone();
        let publication_io = FaultingPublicationIo::new(true, None);

        assert!(matches!(
            guard.publish_with(&destination, &publication_io),
            Err(CandidateExportError::PublishedPartialCleanupFailed {
                published_path,
                partial_path,
                ..
            }) if published_path == destination && partial_path == partial
        ));
        assert_eq!(publication_io.sync_calls.get(), 1);
        assert_eq!(publication_io.remove_calls.get(), 1);
        assert_eq!(fs::read(&destination).unwrap(), b"verified");
        assert_eq!(fs::read(&partial).unwrap(), b"verified");
        assert!(
            partial.exists(),
            "reported orphan must not be hidden by Drop"
        );
        fs::remove_file(destination).unwrap();
        fs::remove_file(partial).unwrap();
    }

    #[test]
    fn first_parent_sync_failure_retains_the_partial_and_reports_publication() {
        let destination = temp_path("first-sync-failure.img");
        let mut guard = NewFileGuard::create_partial(&destination).unwrap();
        guard.file_mut().write_all(b"verified").unwrap();
        guard.file().sync_all().unwrap();
        guard.bind_current_identity().unwrap();
        let partial = guard.path.clone();
        let publication_io = FaultingPublicationIo::new(false, Some(1));

        assert!(matches!(
            guard.publish_with(&destination, &publication_io),
            Err(CandidateExportError::PublishedDirectorySyncFailed {
                published_path,
                partial_path,
                partial_removed: false,
                ..
            }) if published_path == destination && partial_path == partial
        ));
        assert_eq!(publication_io.sync_calls.get(), 1);
        assert_eq!(publication_io.remove_calls.get(), 0);
        assert!(destination.exists());
        assert!(partial.exists(), "reported partial must remain available");
        fs::remove_file(destination).unwrap();
        fs::remove_file(partial).unwrap();
    }

    #[test]
    fn second_parent_sync_failure_reports_that_partial_was_removed() {
        let destination = temp_path("second-sync-failure.img");
        let mut guard = NewFileGuard::create_partial(&destination).unwrap();
        guard.file_mut().write_all(b"verified").unwrap();
        guard.file().sync_all().unwrap();
        guard.bind_current_identity().unwrap();
        let partial = guard.path.clone();
        let publication_io = FaultingPublicationIo::new(false, Some(2));

        assert!(matches!(
            guard.publish_with(&destination, &publication_io),
            Err(CandidateExportError::PublishedDirectorySyncFailed {
                published_path,
                partial_path,
                partial_removed: true,
                ..
            }) if published_path == destination && partial_path == partial
        ));
        assert_eq!(publication_io.sync_calls.get(), 2);
        assert_eq!(publication_io.remove_calls.get(), 1);
        assert!(destination.exists());
        assert!(!partial.exists());
        fs::remove_file(destination).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn partial_files_begin_owner_only_and_hold_an_advisory_lock() {
        use std::os::unix::fs::PermissionsExt;

        let destination = temp_path("private-partial.img");
        let guard = NewFileGuard::create_partial(&destination).unwrap();
        let mode = guard.file().metadata().unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let competing = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&guard.path)
            .unwrap();
        assert!(fs4::FileExt::try_lock(&competing).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn partial_files_deny_competing_write_and_delete_sharing() {
        let destination = temp_path("deny-share-partial.img");
        let guard = NewFileGuard::create_partial(&destination).unwrap();
        assert!(OpenOptions::new().write(true).open(&guard.path).is_err());
        assert!(fs::remove_file(&guard.path).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn new_path_resolution_refuses_windows_reserved_device_names() {
        let path = std::env::temp_dir().join("NUL.img");
        assert!(matches!(
            resolve_new_path(&path),
            Err(CandidateExportError::Image(
                ImageError::DeviceLikePath { .. }
            ))
        ));
    }
}
