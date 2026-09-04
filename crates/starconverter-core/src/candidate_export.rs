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
use crate::extent::{ExtentKind, Placement};
use crate::fs::lznt1::{Lznt1Error, materialize_ntfs_compressed_stream};
use crate::geometry::{Materialization, Relocation, SealedRelocationPlan};
use crate::image::{
    BoundedImageReader, ImageError, ImageFile, ImageIdentity, reject_device_like_path,
};
use crate::inspect::{InspectionError, inspect_open_image};
use crate::object::{ObjectGraph, StreamStorage};
use crate::overlay::OverlayWrite;
use crate::phase::PhaseWritePreview;
use crate::preservation::{
    PreservationError, PreservationLimits, PreservationReport, decode_escrow,
};
use crate::verify::{
    VerificationError, VerificationLimits, VerificationManifest, build_manifest,
    build_manifest_with_reader,
};
use crate::{FileSystem, GuaranteeMode};

const BOUND_ESCROW_MAGIC: [u8; 8] = *b"STARXESC";
const BOUND_ESCROW_VERSION: u16 = 1;
/// Fixed envelope overhead of a bound escrow file beyond its preservation payload.
pub const BOUND_ESCROW_FIXED_BYTES: usize = 8 + 2 + 1 + 1 + 8 + (32 * 3) + 32;
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

/// Exact regular-file identity and content digest captured before relocation planning.
///
/// Relocated exports require this evidence so a payload-only edit between inspection/solve and
/// candidate creation cannot silently become the new expected content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceImageSnapshot {
    container_token: [u8; 32],
    image_bytes: u64,
    sha256: [u8; 32],
}

impl SourceImageSnapshot {
    /// Whole-image SHA-256 captured before planning.
    #[must_use]
    pub const fn sha256(&self) -> [u8; 32] {
        self.sha256
    }
}

/// Hashes the read-only source before planning and binds the result to its stable container.
///
/// # Errors
///
/// Refuses invalid limits, oversized images, and any source read failure.
pub fn capture_source_image_snapshot(
    source: &ImageFile,
    limits: CandidateExportLimits,
) -> Result<SourceImageSnapshot, CandidateExportError> {
    validate_limits(limits)?;
    if source.len() > limits.max_image_bytes {
        return Err(CandidateExportError::ImageTooLarge {
            actual: source.len(),
            maximum: limits.max_image_bytes,
        });
    }
    let sha256 = hash_image_with_progress(
        source,
        limits.copy_chunk_bytes,
        CandidateWorkPhase::HashSourceBefore,
        &mut |_| CandidateWorkControl::Continue,
    )?;
    Ok(SourceImageSnapshot {
        container_token: source.identity().stable_container_token(),
        image_bytes: source.len(),
        sha256,
    })
}

/// Stable stage identifiers for copy-only export and read-only bound verification progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateWorkPhase {
    InspectSource,
    BuildExpectedManifest,
    HashSourceBefore,
    CopySource,
    RelocatePayload,
    ApplyCandidateWrites,
    SyncCandidate,
    InspectCandidate,
    BuildCandidateManifest,
    HashCandidate,
    HashSourceAfter,
    WriteEscrow,
    ReadyToPublish,
    PublishArtifacts,
    VerifyBoundCandidate,
    HashVerificationCandidate,
    HashVerificationSource,
}

impl CandidateWorkPhase {
    /// Stable user-facing label for progress displays and logs.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::InspectSource => "inspect source",
            Self::BuildExpectedManifest => "build expected manifest",
            Self::HashSourceBefore => "hash source before export",
            Self::CopySource => "copy source into private candidate",
            Self::RelocatePayload => "relocate payload in private candidate",
            Self::ApplyCandidateWrites => "apply candidate writes",
            Self::SyncCandidate => "flush private candidate",
            Self::InspectCandidate => "inspect private candidate",
            Self::BuildCandidateManifest => "build candidate manifest",
            Self::HashCandidate => "hash private candidate",
            Self::HashSourceAfter => "prove source unchanged",
            Self::WriteEscrow => "write private bound escrow",
            Self::ReadyToPublish => "ready to publish",
            Self::PublishArtifacts => "publish verified artifacts",
            Self::VerifyBoundCandidate => "inspect bound export",
            Self::HashVerificationCandidate => "hash bound candidate",
            Self::HashVerificationSource => "hash original source",
        }
    }
}

/// One coalescible progress snapshot. `total_bytes == None` means the phase is intentionally
/// indeterminate; callers must not synthesize a percentage for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CandidateWorkProgress {
    pub phase: CandidateWorkPhase,
    pub completed_bytes: u64,
    pub total_bytes: Option<u64>,
    pub cancellable: bool,
}

/// Cooperative response from a progress observer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateWorkControl {
    Continue,
    Cancel,
}

/// Strength of the namespace-durability barrier completed after publishing one artifact.
///
/// File contents are always flushed before publication. Safe Rust exposes directory `sync_all` on
/// Unix, but the standard library does not expose an equivalent Windows directory-handle flush.
/// Callers must therefore retain this evidence rather than assuming equal guarantees everywhere.
/// In particular, `Unsupported` is not permission to retire the source after a power-loss-sensitive
/// workflow: it means that publication completed, but the namespace change is not proven durable.
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

    /// Whether publication completed with a proven parent-namespace durability barrier.
    ///
    /// This deliberately returns `false` for every weaker or future unknown guarantee, allowing
    /// callers to fail closed before retiring source data.
    #[must_use]
    pub const fn is_synchronized(self) -> bool {
        matches!(self, Self::Synchronized)
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
    RelocationShape(&'static str),
    ArithmeticOverflow(&'static str),
    NtfsCompression(Lznt1Error),
    Io {
        operation: &'static str,
        source: io::Error,
    },
    Image(ImageError),
    Preservation(PreservationError),
    Inspection(InspectionError),
    SourceInspectionMismatch,
    SourceChangedSincePlanning,
    TargetInspectionMismatch,
    Verification(VerificationError),
    ManifestMismatch,
    SourceChangedAfterExport,
    Cancelled {
        phase: CandidateWorkPhase,
    },
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
            Self::RelocationShape(reason) => {
                write!(formatter, "invalid relocation layout: {reason}")
            }
            Self::ArithmeticOverflow(calculation) => {
                write!(formatter, "overflow while calculating {calculation}")
            }
            Self::NtfsCompression(source) => {
                write!(formatter, "NTFS compression materialization failed: {source}")
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
            Self::SourceChangedSincePlanning => formatter.write_str(
                "source identity or content changed after the planning snapshot was captured",
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
            Self::Cancelled { phase } => write!(
                formatter,
                "operation cancelled at safe checkpoint during {}",
                phase.label()
            ),
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
            Self::NtfsCompression(source) => Some(source),
            _ => None,
        }
    }
}

impl From<Lznt1Error> for CandidateExportError {
    fn from(value: Lznt1Error) -> Self {
        Self::NtfsCompression(value)
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
    verify_bound_export_with_progress(candidate_path, escrow_path, source_path, limits, |_| {
        CandidateWorkControl::Continue
    })
}

/// Verifies a bound export read-only while reporting coalescible progress and honoring cooperative
/// cancellation at safe checkpoints.
///
/// The observer is invoked after successful byte chunks and at indeterminate phase boundaries.
/// Returning [`CandidateWorkControl::Cancel`] never opens an artifact for write.
///
/// # Errors
///
/// Returns the same errors as [`verify_bound_export`], plus
/// [`CandidateExportError::Cancelled`] when the observer requests cancellation.
#[allow(clippy::too_many_lines)]
pub fn verify_bound_export_with_progress<F>(
    candidate_path: impl AsRef<Path>,
    escrow_path: impl AsRef<Path>,
    source_path: Option<&Path>,
    limits: CandidateVerificationLimits,
    mut observer: F,
) -> Result<CandidateVerificationEvidence, CandidateExportError>
where
    F: FnMut(CandidateWorkProgress) -> CandidateWorkControl,
{
    validate_verification_limits(limits)?;
    observe_cancellable(
        &mut observer,
        CandidateWorkPhase::VerifyBoundCandidate,
        0,
        None,
    )?;

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
    let candidate_sha256 = hash_image_with_progress(
        &candidate,
        limits.hash_chunk_bytes,
        CandidateWorkPhase::HashVerificationCandidate,
        &mut observer,
    )?;
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
        if hash_image_with_progress(
            &source,
            limits.hash_chunk_bytes,
            CandidateWorkPhase::HashVerificationSource,
            &mut observer,
        )? != envelope.source_sha256
        {
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
/// rejects it. Failures before publication attempt best-effort cleanup of newly created partials.
/// Publication races and failures retain their partial and report its path. A failure after a hard
/// link is published reports that partial-success state and never silently removes published data.
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
    export_candidate_image_with_progress(
        source,
        output_path,
        escrow_path,
        preview,
        target_graph,
        preservation,
        limits,
        |_| CandidateWorkControl::Continue,
    )
}

/// Creates and verifies a new candidate while reporting safe-checkpoint progress.
///
/// Cancellation is cooperative. It is honored before publication begins, when all newly created
/// paths are still private partials governed by RAII cleanup. Once the observer receives
/// [`CandidateWorkPhase::PublishArtifacts`] with `cancellable == false`, its return value is
/// intentionally ignored and the function reports the real publication result. This prevents a
/// late request from hiding an already published escrow or candidate.
///
/// # Errors
///
/// Returns the same errors as [`export_candidate_image`], plus
/// [`CandidateExportError::Cancelled`] when cancellation is accepted at a safe checkpoint.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub fn export_candidate_image_with_progress<F>(
    source: &ImageFile,
    output_path: impl AsRef<Path>,
    escrow_path: Option<&Path>,
    preview: &PhaseWritePreview,
    target_graph: &ObjectGraph,
    preservation: &PreservationReport,
    limits: CandidateExportLimits,
    observer: F,
) -> Result<CandidateExportEvidence, CandidateExportError>
where
    F: FnMut(CandidateWorkProgress) -> CandidateWorkControl,
{
    export_candidate_image_impl(
        source,
        output_path,
        escrow_path,
        preview,
        target_graph,
        None,
        None,
        preservation,
        limits,
        observer,
    )
}

/// Creates and verifies a new candidate after copying a sealed relocation layout from the source.
///
/// Relocations are read only from the immutable source handle and written only to the private
/// candidate before destination metadata is applied. The expected logical manifest uses a virtual
/// relocation view over the source, so expected content is never derived from candidate output.
///
/// # Errors
///
/// Returns the same errors as [`export_candidate_image`] and additionally refuses malformed,
/// overlapping, out-of-image, uncommitted, or metadata-overlapping relocation destinations.
#[allow(clippy::too_many_arguments)]
pub fn export_relocated_candidate_image(
    source: &ImageFile,
    output_path: impl AsRef<Path>,
    escrow_path: Option<&Path>,
    preview: &PhaseWritePreview,
    source_snapshot: &SourceImageSnapshot,
    relocation: &SealedRelocationPlan,
    preservation: &PreservationReport,
    limits: CandidateExportLimits,
) -> Result<CandidateExportEvidence, CandidateExportError> {
    export_relocated_candidate_image_with_progress(
        source,
        output_path,
        escrow_path,
        preview,
        source_snapshot,
        relocation,
        preservation,
        limits,
        |_| CandidateWorkControl::Continue,
    )
}

/// Progress-reporting variant of [`export_relocated_candidate_image`].
///
/// # Errors
///
/// Returns the same validation, cancellation, I/O, inspection, verification, and publication
/// errors as [`export_relocated_candidate_image`].
#[allow(clippy::too_many_arguments)]
pub fn export_relocated_candidate_image_with_progress<F>(
    source: &ImageFile,
    output_path: impl AsRef<Path>,
    escrow_path: Option<&Path>,
    preview: &PhaseWritePreview,
    source_snapshot: &SourceImageSnapshot,
    relocation: &SealedRelocationPlan,
    preservation: &PreservationReport,
    limits: CandidateExportLimits,
    observer: F,
) -> Result<CandidateExportEvidence, CandidateExportError>
where
    F: FnMut(CandidateWorkProgress) -> CandidateWorkControl,
{
    export_candidate_image_impl(
        source,
        output_path,
        escrow_path,
        preview,
        relocation.target_graph(),
        Some(relocation),
        Some(source_snapshot),
        preservation,
        limits,
        observer,
    )
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn export_candidate_image_impl<F>(
    source: &ImageFile,
    output_path: impl AsRef<Path>,
    escrow_path: Option<&Path>,
    preview: &PhaseWritePreview,
    target_graph: &ObjectGraph,
    relocation: Option<&SealedRelocationPlan>,
    source_snapshot: Option<&SourceImageSnapshot>,
    preservation: &PreservationReport,
    limits: CandidateExportLimits,
    mut observer: F,
) -> Result<CandidateExportEvidence, CandidateExportError>
where
    F: FnMut(CandidateWorkProgress) -> CandidateWorkControl,
{
    validate_limits(limits)?;
    validate_policy(preview, preservation, escrow_path, limits.max_escrow_bytes)?;
    observe_cancellable(&mut observer, CandidateWorkPhase::InspectSource, 0, None)?;
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

    let (write_count, write_bytes) = validate_preview(source, preview.writes(), limits)?;
    let (relocation_count, relocation_bytes, sorted_relocations) = match relocation {
        Some(relocation) => validate_relocations(source, relocation, preview.writes(), limits)?,
        None => (0, 0, Vec::new()),
    };
    let (materialization_count, materialization_bytes, sorted_materializations) = match relocation {
        Some(relocation) => {
            validate_materializations(source, relocation, preview.writes(), limits)?
        }
        None => (0, 0, Vec::new()),
    };
    let applied_write_count = write_count
        .checked_add(relocation_count)
        .and_then(|count| count.checked_add(materialization_count))
        .ok_or(CandidateExportError::ArithmeticOverflow(
            "candidate operation count",
        ))?;
    let replacement_bytes = write_bytes
        .checked_add(relocation_bytes)
        .and_then(|bytes| bytes.checked_add(materialization_bytes))
        .ok_or(CandidateExportError::ArithmeticOverflow(
            "candidate replacement byte total",
        ))?;
    if applied_write_count > limits.max_writes {
        return Err(CandidateExportError::WriteLimitExceeded {
            actual: applied_write_count,
            maximum: limits.max_writes,
        });
    }
    if replacement_bytes > u64::try_from(limits.max_replacement_bytes).unwrap_or(u64::MAX) {
        return Err(CandidateExportError::ReplacementLimitExceeded {
            actual: replacement_bytes,
            maximum: limits.max_replacement_bytes,
        });
    }
    observe_cancellable(
        &mut observer,
        CandidateWorkPhase::BuildExpectedManifest,
        0,
        None,
    )?;
    let expected_manifest = if relocation.is_some() {
        let relocated_source = RelocatedSourceView {
            source,
            relocations: &sorted_relocations,
            materializations: &sorted_materializations,
            source_graph: relocation.map(SealedRelocationPlan::source_graph),
        };
        build_manifest_with_reader(&relocated_source, target_graph, limits.verification)?
    } else {
        build_manifest(source, target_graph, limits.verification)?
    };
    let source_sha256 = hash_image_with_progress(
        source,
        limits.copy_chunk_bytes,
        CandidateWorkPhase::HashSourceBefore,
        &mut observer,
    )?;
    if let Some(snapshot) = source_snapshot {
        if snapshot.container_token != source.identity().stable_container_token()
            || snapshot.image_bytes != source.len()
            || snapshot.sha256 != source_sha256
        {
            return Err(CandidateExportError::SourceChangedSincePlanning);
        }
    }

    let mut output_guard = NewFileGuard::create_partial(&output)?;
    copy_source_with_progress(
        source,
        output_guard.file_mut(),
        limits.copy_chunk_bytes,
        &mut observer,
    )?;
    if let Some(authority) = relocation {
        let payload_bytes = relocation_bytes.checked_add(materialization_bytes).ok_or(
            CandidateExportError::ArithmeticOverflow("payload progress total"),
        )?;
        apply_relocations_with_progress(
            source,
            output_guard.file_mut(),
            &sorted_relocations,
            limits.copy_chunk_bytes,
            payload_bytes,
            &mut observer,
        )?;
        apply_materializations_with_progress(
            source,
            output_guard.file_mut(),
            authority.source_graph(),
            &sorted_materializations,
            limits.copy_chunk_bytes,
            relocation_bytes,
            payload_bytes,
            &mut observer,
        )?;
    }
    apply_forward_writes_with_progress(
        output_guard.file_mut(),
        preview.writes(),
        limits.copy_chunk_bytes,
        replacement_bytes,
        &mut observer,
    )?;
    observe_cancellable(&mut observer, CandidateWorkPhase::SyncCandidate, 0, None)?;
    output_guard
        .file()
        .sync_all()
        .map_err(|source| CandidateExportError::io("flush candidate image", source))?;

    let (manifest_sha256, candidate_sha256, candidate_identity) = verify_candidate_with_progress(
        &output_guard,
        preview.target_filesystem(),
        &expected_manifest,
        limits,
        &mut observer,
    )?;
    output_guard.bind_verified_identity(candidate_identity);

    let after_sha256 = hash_image_with_progress(
        source,
        limits.copy_chunk_bytes,
        CandidateWorkPhase::HashSourceAfter,
        &mut observer,
    )?;
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
            write_escrow_with_progress(
                guard.file_mut(),
                &envelope,
                limits.copy_chunk_bytes,
                &mut observer,
            )?;
            guard
                .file()
                .sync_all()
                .map_err(|source| CandidateExportError::io("flush bound escrow", source))?;
            guard.bind_current_identity()?;
            Some(guard)
        } else {
            None
        };

    observe_cancellable(&mut observer, CandidateWorkPhase::ReadyToPublish, 0, None)?;
    report_non_cancellable(&mut observer, CandidateWorkPhase::PublishArtifacts, 0, None);

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
        applied_writes: applied_write_count,
        replacement_bytes,
        source_sha256,
        candidate_sha256,
        manifest_sha256,
        output_directory_durability,
        escrow_directory_durability,
    })
}

fn verify_candidate_with_progress<F>(
    guard: &NewFileGuard,
    target_filesystem: FileSystem,
    expected_manifest: &VerificationManifest,
    limits: CandidateExportLimits,
    observer: &mut F,
) -> Result<([u8; 32], [u8; 32], ImageIdentity), CandidateExportError>
where
    F: FnMut(CandidateWorkProgress) -> CandidateWorkControl,
{
    observe_cancellable(observer, CandidateWorkPhase::InspectCandidate, 0, None)?;
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
    observe_cancellable(
        observer,
        CandidateWorkPhase::BuildCandidateManifest,
        0,
        None,
    )?;
    let actual_manifest = build_manifest(&candidate, actual_graph, limits.verification)?;
    if !expected_manifest.equivalent_to(&actual_manifest) {
        return Err(CandidateExportError::ManifestMismatch);
    }
    let candidate_sha256 = hash_image_with_progress(
        &candidate,
        limits.copy_chunk_bytes,
        CandidateWorkPhase::HashCandidate,
        observer,
    )?;
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

#[derive(Debug)]
struct RelocatedSourceView<'a> {
    source: &'a ImageFile,
    /// Sorted by destination offset and independently validated as disjoint.
    relocations: &'a [Relocation],
    materializations: &'a [Materialization],
    source_graph: Option<&'a ObjectGraph>,
}

impl BoundedImageReader for RelocatedSourceView<'_> {
    fn len(&self) -> u64 {
        self.source.len()
    }

    fn max_read_bytes(&self) -> usize {
        BoundedImageReader::max_read_bytes(self.source)
    }

    fn read_exact_at(&self, offset: u64, length: usize) -> Result<Vec<u8>, ImageError> {
        let length_u64 = u64::try_from(length).map_err(|_| ImageError::RangeOverflow {
            offset,
            length: u64::MAX,
        })?;
        let end = offset
            .checked_add(length_u64)
            .ok_or(ImageError::RangeOverflow {
                offset,
                length: length_u64,
            })?;
        if let (Some(graph), Some(materialization)) = (
            self.source_graph,
            covering_materialization(self.materializations, offset, end),
        ) {
            return read_materialized_logical(self.source, graph, materialization, offset, length)
                .map_err(|_| ImageError::RangeOverflow {
                    offset,
                    length: length_u64,
                });
        }
        let position = self
            .relocations
            .partition_point(|relocation| relocation.destination.offset <= offset);
        if let Some(relocation) = position
            .checked_sub(1)
            .and_then(|index| self.relocations.get(index))
        {
            let destination_end = relocation
                .destination
                .offset
                .checked_add(relocation.destination.length)
                .ok_or(ImageError::RangeOverflow {
                    offset: relocation.destination.offset,
                    length: relocation.destination.length,
                })?;
            if end <= destination_end {
                let source_offset = relocation
                    .source
                    .offset
                    .checked_add(offset - relocation.destination.offset)
                    .ok_or(ImageError::RangeOverflow {
                        offset: relocation.source.offset,
                        length: offset - relocation.destination.offset,
                    })?;
                return self.source.read_exact_at(source_offset, length);
            }
        }
        self.source.read_exact_at(offset, length)
    }
}

fn covering_materialization(
    materializations: &[Materialization],
    offset: u64,
    end: u64,
) -> Option<&Materialization> {
    let position = materializations.partition_point(|item| item.destination.offset <= offset);
    position
        .checked_sub(1)
        .and_then(|index| materializations.get(index))
        .filter(|item| {
            item.destination
                .offset
                .checked_add(item.destination.length)
                .is_some_and(|destination_end| end <= destination_end)
        })
}

#[allow(clippy::too_many_lines)]
fn validate_relocations(
    source: &ImageFile,
    authority: &SealedRelocationPlan,
    writes: &OpaqueWriteSets,
    limits: CandidateExportLimits,
) -> Result<(usize, u64, Vec<Relocation>), CandidateExportError> {
    let source_graph = authority.source_graph();
    let target_graph = authority.target_graph();
    let layout = authority.layout();
    if layout.relocations.len() > limits.max_writes {
        return Err(CandidateExportError::WriteLimitExceeded {
            actual: layout.relocations.len(),
            maximum: limits.max_writes,
        });
    }
    let mut relocated_bytes = 0_u64;
    let mut source_ranges = Vec::new();
    let mut relocations = layout.relocations.clone();
    source_ranges
        .try_reserve_exact(relocations.len())
        .map_err(|_| CandidateExportError::RelocationShape("could not allocate range proof"))?;
    for relocation in &relocations {
        if relocation.source.length == 0
            || relocation.source.length != relocation.destination.length
        {
            return Err(CandidateExportError::RelocationShape(
                "source and destination lengths must be equal and nonzero",
            ));
        }
        let source_end = relocation
            .source
            .offset
            .checked_add(relocation.source.length)
            .ok_or(CandidateExportError::RelocationShape(
                "source range overflows",
            ))?;
        let destination_end = relocation
            .destination
            .offset
            .checked_add(relocation.destination.length)
            .ok_or(CandidateExportError::RelocationShape(
                "destination range overflows",
            ))?;
        if source_end > source.len() || destination_end > source.len() {
            return Err(CandidateExportError::RelocationShape(
                "range is outside the image",
            ));
        }
        if relocation.source.offset < destination_end && relocation.destination.offset < source_end
        {
            return Err(CandidateExportError::RelocationShape(
                "source and destination overlap",
            ));
        }
        let authorized_source = source_graph.extents().extents().iter().any(|extent| {
            extent.kind == crate::extent::ExtentKind::FileData
                && extent.stream == relocation.stream
                && extent.logical_offset == relocation.logical_offset
                && extent.length == relocation.source.length
                && extent.placement
                    == crate::extent::Placement::Physical {
                        byte_offset: relocation.source.offset,
                    }
        });
        if !authorized_source {
            return Err(CandidateExportError::RelocationShape(
                "source graph does not authorize a relocation read",
            ));
        }
        let committed = target_graph.extents().extents().iter().any(|extent| {
            extent.stream == relocation.stream
                && extent.logical_offset == relocation.logical_offset
                && extent.length == relocation.destination.length
                && extent.placement
                    == crate::extent::Placement::Physical {
                        byte_offset: relocation.destination.offset,
                    }
        });
        if !committed {
            return Err(CandidateExportError::RelocationShape(
                "target graph does not commit a relocation destination",
            ));
        }
        relocated_bytes = relocated_bytes
            .checked_add(relocation.source.length)
            .ok_or(CandidateExportError::ArithmeticOverflow(
                "relocation byte total",
            ))?;
        source_ranges.push((relocation.source.offset, source_end));
    }
    if relocated_bytes != layout.relocated_bytes {
        return Err(CandidateExportError::RelocationShape(
            "relocated byte total disagrees with the layout",
        ));
    }
    source_ranges.sort_unstable();
    if source_ranges.windows(2).any(|pair| pair[0].1 > pair[1].0) {
        return Err(CandidateExportError::RelocationShape(
            "source ranges overlap",
        ));
    }
    relocations.sort_unstable_by_key(|relocation| relocation.destination.offset);
    if relocations.windows(2).any(|pair| {
        pair[0]
            .destination
            .offset
            .checked_add(pair[0].destination.length)
            .is_none_or(|end| end > pair[1].destination.offset)
    }) {
        return Err(CandidateExportError::RelocationShape(
            "destination ranges overlap",
        ));
    }
    for relocation in &relocations {
        let destination_end = relocation.destination.offset + relocation.destination.length;
        for write in writes
            .target_staging
            .iter()
            .chain(&writes.backup_boot)
            .chain(&writes.activation)
        {
            let write_end = write
                .write
                .offset
                .checked_add(u64::try_from(write.write.bytes.len()).map_err(|_| {
                    CandidateExportError::ArithmeticOverflow("candidate write length")
                })?)
                .ok_or(CandidateExportError::ArithmeticOverflow(
                    "candidate write end",
                ))?;
            if relocation.destination.offset < write_end && write.write.offset < destination_end {
                return Err(CandidateExportError::RelocationShape(
                    "destination overlaps candidate metadata",
                ));
            }
        }
    }
    Ok((relocations.len(), relocated_bytes, relocations))
}

#[allow(clippy::too_many_lines)]
fn validate_materializations(
    source: &ImageFile,
    authority: &SealedRelocationPlan,
    writes: &OpaqueWriteSets,
    limits: CandidateExportLimits,
) -> Result<(usize, u64, Vec<Materialization>), CandidateExportError> {
    let source_graph = authority.source_graph();
    let target_graph = authority.target_graph();
    let mut materializations = authority.layout().materializations.clone();
    if materializations.len() > limits.max_writes {
        return Err(CandidateExportError::WriteLimitExceeded {
            actual: materializations.len(),
            maximum: limits.max_writes,
        });
    }
    let mut materialized_bytes = 0_u64;
    for materialization in &materializations {
        if materialization.destination.length == 0 {
            return Err(CandidateExportError::RelocationShape(
                "materialization destination length must be nonzero",
            ));
        }
        let destination_end = materialization
            .destination
            .offset
            .checked_add(materialization.destination.length)
            .ok_or(CandidateExportError::RelocationShape(
                "materialization destination overflows",
            ))?;
        if destination_end > source.len() {
            return Err(CandidateExportError::RelocationShape(
                "materialization destination is outside the image",
            ));
        }
        let stream = source_graph
            .objects()
            .iter()
            .find_map(|object| {
                object
                    .streams
                    .iter()
                    .find(|candidate| candidate.id == materialization.stream)
            })
            .ok_or(CandidateExportError::RelocationShape(
                "source graph does not authorize a materialization read",
            ))?;
        if materialization.destination.length < stream.logical_bytes {
            return Err(CandidateExportError::RelocationShape(
                "materialization destination is smaller than logical stream bytes",
            ));
        }
        let committed = target_graph.extents().extents().iter().any(|extent| {
            extent.kind == ExtentKind::FileData
                && extent.stream == materialization.stream
                && extent.logical_offset == 0
                && extent.length == materialization.destination.length
                && extent.placement
                    == Placement::Physical {
                        byte_offset: materialization.destination.offset,
                    }
        });
        if !committed {
            return Err(CandidateExportError::RelocationShape(
                "target graph does not commit a materialization destination",
            ));
        }
        materialized_bytes = materialized_bytes
            .checked_add(materialization.destination.length)
            .ok_or(CandidateExportError::ArithmeticOverflow(
                "materialization byte total",
            ))?;
    }
    if materialized_bytes != authority.layout().materialized_bytes {
        return Err(CandidateExportError::RelocationShape(
            "materialized byte total disagrees with the layout",
        ));
    }
    materializations.sort_unstable_by_key(|item| item.destination.offset);
    if materializations.windows(2).any(|pair| {
        pair[0]
            .destination
            .offset
            .checked_add(pair[0].destination.length)
            .is_none_or(|end| end > pair[1].destination.offset)
    }) {
        return Err(CandidateExportError::RelocationShape(
            "materialization destinations overlap",
        ));
    }
    for materialization in &materializations {
        let destination_end =
            materialization.destination.offset + materialization.destination.length;
        for relocation in &authority.layout().relocations {
            let relocation_end = relocation.destination.offset + relocation.destination.length;
            if materialization.destination.offset < relocation_end
                && relocation.destination.offset < destination_end
            {
                return Err(CandidateExportError::RelocationShape(
                    "materialization destination overlaps a relocation",
                ));
            }
        }
        for write in writes
            .target_staging
            .iter()
            .chain(&writes.backup_boot)
            .chain(&writes.activation)
        {
            let write_end = write
                .write
                .offset
                .checked_add(u64::try_from(write.write.bytes.len()).map_err(|_| {
                    CandidateExportError::ArithmeticOverflow("candidate write length")
                })?)
                .ok_or(CandidateExportError::ArithmeticOverflow(
                    "candidate write end",
                ))?;
            if materialization.destination.offset < write_end
                && write.write.offset < destination_end
            {
                return Err(CandidateExportError::RelocationShape(
                    "materialization destination overlaps candidate metadata",
                ));
            }
        }
    }
    Ok((materializations.len(), materialized_bytes, materializations))
}

fn read_materialized_logical(
    source: &ImageFile,
    graph: &ObjectGraph,
    materialization: &Materialization,
    offset: u64,
    length: usize,
) -> Result<Vec<u8>, CandidateExportError> {
    let logical_offset = offset
        .checked_sub(materialization.destination.offset)
        .ok_or(CandidateExportError::RelocationShape(
            "materialization read is before its destination",
        ))?;
    let payload = reconstruct_stream_destination(source, graph, materialization)?;
    let start = usize::try_from(logical_offset)
        .map_err(|_| CandidateExportError::ArithmeticOverflow("materialization read offset"))?;
    let end = start
        .checked_add(length)
        .ok_or(CandidateExportError::ArithmeticOverflow(
            "materialization read end",
        ))?;
    if end > payload.len() {
        return Err(CandidateExportError::RelocationShape(
            "materialization read exceeds destination",
        ));
    }
    Ok(payload[start..end].to_vec())
}

fn reconstruct_stream_destination(
    source: &ImageFile,
    graph: &ObjectGraph,
    materialization: &Materialization,
) -> Result<Vec<u8>, CandidateExportError> {
    let stream = graph
        .objects()
        .iter()
        .find_map(|object| {
            object
                .streams
                .iter()
                .find(|candidate| candidate.id == materialization.stream)
        })
        .ok_or(CandidateExportError::RelocationShape(
            "source graph does not authorize a materialization read",
        ))?;
    let dest_len = usize::try_from(materialization.destination.length).map_err(|_| {
        CandidateExportError::ArithmeticOverflow("materialization destination length")
    })?;
    let mut destination = vec![0_u8; dest_len];
    let initialized = usize::try_from(stream.initialized_bytes.min(stream.logical_bytes))
        .map_err(|_| CandidateExportError::ArithmeticOverflow("initialized stream bytes"))?;
    match &stream.storage {
        StreamStorage::Resident(bytes) => {
            let copy = initialized.min(bytes.len()).min(dest_len);
            destination[..copy].copy_from_slice(&bytes[..copy]);
        }
        StreamStorage::Extents if stream.flags.compression_block_bytes != 0 => {
            return materialize_ntfs_compressed_stream(
                graph.extents().extents(),
                stream.id,
                stream.flags.compression_block_bytes,
                stream.initialized_bytes.min(stream.logical_bytes),
                dest_len,
                |offset, length| {
                    source
                        .read_exact_at(offset, length)
                        .map_err(CandidateExportError::from)
                },
            );
        }
        StreamStorage::Extents => {
            for extent in
                graph.extents().extents().iter().filter(|extent| {
                    extent.stream == stream.id && extent.kind == ExtentKind::FileData
                })
            {
                if extent.logical_offset >= stream.initialized_bytes {
                    continue;
                }
                let take = extent
                    .length
                    .min(stream.initialized_bytes - extent.logical_offset);
                let dest_start = usize::try_from(extent.logical_offset).map_err(|_| {
                    CandidateExportError::ArithmeticOverflow("extent logical offset")
                })?;
                let take_usize = usize::try_from(take)
                    .map_err(|_| CandidateExportError::ArithmeticOverflow("extent copy length"))?;
                if dest_start >= dest_len {
                    continue;
                }
                let copy = take_usize.min(dest_len - dest_start);
                match extent.placement {
                    Placement::Physical { byte_offset } => {
                        let bytes = source.read_exact_at(byte_offset, copy)?;
                        destination[dest_start..dest_start + copy].copy_from_slice(&bytes);
                    }
                    Placement::Sparse => {}
                }
            }
        }
    }
    Ok(destination)
}

#[allow(clippy::too_many_arguments)]
fn apply_materializations_with_progress<F>(
    source: &ImageFile,
    output: &mut File,
    source_graph: &ObjectGraph,
    materializations: &[Materialization],
    chunk_bytes: usize,
    completed_bytes: u64,
    payload_bytes: u64,
    observer: &mut F,
) -> Result<(), CandidateExportError>
where
    F: FnMut(CandidateWorkProgress) -> CandidateWorkControl,
{
    if materializations.is_empty() {
        return Ok(());
    }
    let mut completed = completed_bytes;
    observe_cancellable(
        observer,
        CandidateWorkPhase::RelocatePayload,
        completed,
        Some(payload_bytes),
    )?;
    for materialization in materializations {
        let payload = reconstruct_stream_destination(source, source_graph, materialization)?;
        let mut copied = 0_usize;
        while copied < payload.len() {
            let remaining = payload.len() - copied;
            let length = remaining.min(chunk_bytes);
            let destination_offset = materialization
                .destination
                .offset
                .checked_add(u64::try_from(copied).map_err(|_| {
                    CandidateExportError::ArithmeticOverflow("materialization write offset")
                })?)
                .ok_or(CandidateExportError::ArithmeticOverflow(
                    "materialization write offset",
                ))?;
            output
                .seek(SeekFrom::Start(destination_offset))
                .map_err(|source| {
                    CandidateExportError::io("seek materialization destination", source)
                })?;
            output
                .write_all(&payload[copied..copied + length])
                .map_err(|source| CandidateExportError::io("write materialized payload", source))?;
            copied += length;
            completed = completed
                .checked_add(u64::try_from(length).map_err(|_| {
                    CandidateExportError::ArithmeticOverflow("materialization progress")
                })?)
                .ok_or(CandidateExportError::ArithmeticOverflow(
                    "materialization total progress",
                ))?;
            observe_cancellable(
                observer,
                CandidateWorkPhase::RelocatePayload,
                completed,
                Some(payload_bytes),
            )?;
        }
    }
    Ok(())
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

fn observe_cancellable<F>(
    observer: &mut F,
    phase: CandidateWorkPhase,
    completed_bytes: u64,
    total_bytes: Option<u64>,
) -> Result<(), CandidateExportError>
where
    F: FnMut(CandidateWorkProgress) -> CandidateWorkControl,
{
    match observer(CandidateWorkProgress {
        phase,
        completed_bytes,
        total_bytes,
        cancellable: true,
    }) {
        CandidateWorkControl::Continue => Ok(()),
        CandidateWorkControl::Cancel => Err(CandidateExportError::Cancelled { phase }),
    }
}

fn report_non_cancellable<F>(
    observer: &mut F,
    phase: CandidateWorkPhase,
    completed_bytes: u64,
    total_bytes: Option<u64>,
) where
    F: FnMut(CandidateWorkProgress) -> CandidateWorkControl,
{
    let _ = observer(CandidateWorkProgress {
        phase,
        completed_bytes,
        total_bytes,
        cancellable: false,
    });
}

#[cfg(test)]
fn hash_image(image: &ImageFile, chunk_bytes: usize) -> Result<[u8; 32], CandidateExportError> {
    hash_image_with_progress(
        image,
        chunk_bytes,
        CandidateWorkPhase::HashCandidate,
        &mut |_| CandidateWorkControl::Continue,
    )
}

fn hash_image_with_progress<F>(
    image: &ImageFile,
    chunk_bytes: usize,
    phase: CandidateWorkPhase,
    observer: &mut F,
) -> Result<[u8; 32], CandidateExportError>
where
    F: FnMut(CandidateWorkProgress) -> CandidateWorkControl,
{
    let mut hasher = Sha256::new();
    let mut offset = 0_u64;
    observe_cancellable(observer, phase, 0, Some(image.len()))?;
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
        observe_cancellable(observer, phase, offset, Some(image.len()))?;
    }
    Ok(hasher.finalize().into())
}

#[cfg(test)]
fn copy_source(
    source: &ImageFile,
    output: &mut File,
    chunk_bytes: usize,
) -> Result<(), CandidateExportError> {
    copy_source_with_progress(source, output, chunk_bytes, &mut |_| {
        CandidateWorkControl::Continue
    })
}

fn copy_source_with_progress<F>(
    source: &ImageFile,
    output: &mut File,
    chunk_bytes: usize,
    observer: &mut F,
) -> Result<(), CandidateExportError>
where
    F: FnMut(CandidateWorkProgress) -> CandidateWorkControl,
{
    let mut offset = 0_u64;
    observe_cancellable(
        observer,
        CandidateWorkPhase::CopySource,
        0,
        Some(source.len()),
    )?;
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
        observe_cancellable(
            observer,
            CandidateWorkPhase::CopySource,
            offset,
            Some(source.len()),
        )?;
    }
    Ok(())
}

fn apply_relocations_with_progress<F>(
    source: &ImageFile,
    output: &mut File,
    relocations: &[Relocation],
    chunk_bytes: usize,
    payload_bytes: u64,
    observer: &mut F,
) -> Result<(), CandidateExportError>
where
    F: FnMut(CandidateWorkProgress) -> CandidateWorkControl,
{
    if relocations.is_empty() {
        return Ok(());
    }
    let mut completed = 0_u64;
    observe_cancellable(
        observer,
        CandidateWorkPhase::RelocatePayload,
        0,
        Some(payload_bytes),
    )?;
    for relocation in relocations {
        let mut copied = 0_u64;
        while copied < relocation.source.length {
            let remaining = relocation.source.length - copied;
            let length = usize::try_from(remaining.min(chunk_bytes as u64))
                .map_err(|_| CandidateExportError::ArithmeticOverflow("relocation chunk length"))?;
            let source_offset = relocation.source.offset.checked_add(copied).ok_or(
                CandidateExportError::ArithmeticOverflow("relocation source offset"),
            )?;
            let destination_offset = relocation.destination.offset.checked_add(copied).ok_or(
                CandidateExportError::ArithmeticOverflow("relocation destination offset"),
            )?;
            let bytes = source.read_exact_at(source_offset, length)?;
            output
                .seek(SeekFrom::Start(destination_offset))
                .map_err(|source| {
                    CandidateExportError::io("seek relocation destination", source)
                })?;
            output
                .write_all(&bytes)
                .map_err(|source| CandidateExportError::io("write relocated payload", source))?;
            let length_u64 = u64::try_from(length).map_err(|_| {
                CandidateExportError::ArithmeticOverflow("relocation progress conversion")
            })?;
            copied =
                copied
                    .checked_add(length_u64)
                    .ok_or(CandidateExportError::ArithmeticOverflow(
                        "relocation extent progress",
                    ))?;
            completed = completed.checked_add(length_u64).ok_or(
                CandidateExportError::ArithmeticOverflow("relocation total progress"),
            )?;
            observe_cancellable(
                observer,
                CandidateWorkPhase::RelocatePayload,
                completed,
                Some(payload_bytes),
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
fn apply_forward_writes(
    output: &mut File,
    writes: &OpaqueWriteSets,
) -> Result<(), CandidateExportError> {
    let replacement_bytes = writes
        .target_staging
        .iter()
        .chain(&writes.backup_boot)
        .chain(&writes.activation)
        .try_fold(0_u64, |total, write| {
            total.checked_add(write.write.bytes.len() as u64)
        })
        .ok_or(CandidateExportError::ArithmeticOverflow(
            "replacement byte total",
        ))?;
    apply_forward_writes_with_progress(output, writes, usize::MAX, replacement_bytes, &mut |_| {
        CandidateWorkControl::Continue
    })
}

fn apply_forward_writes_with_progress<F>(
    output: &mut File,
    writes: &OpaqueWriteSets,
    chunk_bytes: usize,
    replacement_bytes: u64,
    observer: &mut F,
) -> Result<(), CandidateExportError>
where
    F: FnMut(CandidateWorkProgress) -> CandidateWorkControl,
{
    let mut completed = 0_u64;
    observe_cancellable(
        observer,
        CandidateWorkPhase::ApplyCandidateWrites,
        0,
        Some(replacement_bytes),
    )?;
    for write in writes
        .target_staging
        .iter()
        .chain(&writes.backup_boot)
        .chain(&writes.activation)
    {
        output
            .seek(SeekFrom::Start(write.write.offset))
            .map_err(|source| CandidateExportError::io("seek candidate image", source))?;
        for chunk in write.write.bytes.chunks(chunk_bytes) {
            output
                .write_all(chunk)
                .map_err(|source| CandidateExportError::io("write candidate image", source))?;
            completed = completed.checked_add(chunk.len() as u64).ok_or(
                CandidateExportError::ArithmeticOverflow("candidate write progress"),
            )?;
            observe_cancellable(
                observer,
                CandidateWorkPhase::ApplyCandidateWrites,
                completed,
                Some(replacement_bytes),
            )?;
        }
    }
    Ok(())
}

fn write_escrow_with_progress<F>(
    output: &mut File,
    envelope: &[u8],
    chunk_bytes: usize,
    observer: &mut F,
) -> Result<(), CandidateExportError>
where
    F: FnMut(CandidateWorkProgress) -> CandidateWorkControl,
{
    let total = envelope.len() as u64;
    let mut completed = 0_u64;
    observe_cancellable(observer, CandidateWorkPhase::WriteEscrow, 0, Some(total))?;
    for chunk in envelope.chunks(chunk_bytes) {
        output
            .write_all(chunk)
            .map_err(|source| CandidateExportError::io("write bound escrow", source))?;
        completed = completed.checked_add(chunk.len() as u64).ok_or(
            CandidateExportError::ArithmeticOverflow("bound escrow write progress"),
        )?;
        observe_cancellable(
            observer,
            CandidateWorkPhase::WriteEscrow,
            completed,
            Some(total),
        )?;
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
    /// A path-based Windows `MoveFileEx(..., WRITE_THROUGH)` wrapper is not an equivalent safe
    /// substitute here: moving requires releasing this guard's deny-delete handle, opening a path
    /// replacement race, and the MSRV-compatible safe wrapper accepts `str` rather than arbitrary
    /// Windows `Path` values. Until a safe handle-relative no-replace primitive exists, Windows
    /// publication therefore remains atomic/no-clobber but explicitly reports directory durability
    /// as unsupported.
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
            // Windows' documented FlushFileBuffers contract requires GENERIC_WRITE on a file (or
            // privileged volume) handle, while its documented directory-handle operations do not
            // include FlushFileBuffers. Stable safe Rust exposes neither a proven parent-directory
            // barrier nor a safe handle-relative write-through rename. Do not infer that the
            // pre-publication file `sync_all` flushed either hard-link namespace change.
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
    use crate::cross_format::{
        ExfatToNtfsLimits, ExfatToNtfsOptions, NtfsToExfatLimits, NtfsToExfatOptions,
        draft_lossless_exfat_to_ntfs, draft_lossless_ntfs_to_exfat, plan_lossless_exfat_to_ntfs,
        plan_lossless_ntfs_to_exfat, solve_lossless_exfat_to_ntfs, solve_lossless_ntfs_to_exfat,
    };
    use crate::extent::{Extent, ExtentGraph, ExtentKind, Placement, StreamId};
    use crate::fs::exfat_inventory::{ExfatPreservationEvidence, ExfatTimestamps};
    use crate::fs::exfat_serialize::{
        ExfatObjectMetadata, ExfatSerializeLimits, ExfatSerializeOptions, ExfatVolumeProfile,
        serialize_exfat_destination,
    };
    use crate::fs::exfat_upcase_serialize::{
        RECOMMENDED_EXFAT_UPCASE_CHECKSUM, RecommendedExfatUpcaseLimits,
        generate_recommended_exfat_upcase,
    };
    use crate::fs::ntfs_inventory::{NtfsInventoryLimits, NtfsObjectReference};
    use crate::fs::ntfs_normalize::{
        NormalizedNtfs, NtfsPreservationSidecar, NtfsSecurityDescriptorEvidence,
    };
    use crate::fs::ntfs_serialize::{
        NtfsDestinationInputs, NtfsObjectTimestamps, NtfsSerializeLimits, plan_ntfs_destination,
    };
    use crate::geometry::{ByteRange, LayoutLimits, ReservationKind};
    use crate::inspect::inspect_image;
    use crate::object::{
        NamespaceEntry, ObjectGraphLimits, ObjectId, ObjectKind, ObjectRecord, ObjectSemantics,
        ObjectStream, StreamFlags, StreamStorage,
    };
    use crate::phase::{preview_exfat_phase_writes, preview_ntfs_phase_writes};
    use crate::preimage::PreimageLimits;
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

    fn lznt1_abcabc_cluster() -> Vec<u8> {
        let payload = [0x08_u8, b'A', b'B', b'C', 0x00, 0x20];
        let header = 0xb000 | u16::try_from(payload.len() - 1).unwrap();
        let mut encoded = header.to_le_bytes().to_vec();
        encoded.extend_from_slice(&payload);
        encoded.extend_from_slice(&[0, 0]);
        encoded.resize(4096, 0);
        encoded
    }

    #[test]
    fn reconstruct_decompresses_ntfs_lznt1_into_dest_native_bytes() {
        let cluster = lznt1_abcabc_cluster();
        let source_file = TempFile::create(&cluster);
        let source = ImageFile::open(&source_file.path).unwrap();
        let graph = ObjectGraph::build(
            ObjectId(1),
            vec![
                ObjectRecord {
                    id: ObjectId(1),
                    kind: ObjectKind::Directory,
                    link_count: 0,
                    semantics: ObjectSemantics::default(),
                    streams: Vec::new(),
                },
                ObjectRecord {
                    id: ObjectId(2),
                    kind: ObjectKind::File,
                    link_count: 1,
                    semantics: ObjectSemantics::default(),
                    streams: vec![ObjectStream {
                        id: StreamId(2),
                        name: None,
                        logical_bytes: 6,
                        initialized_bytes: 6,
                        mapped_bytes: 8192,
                        allocated_bytes: 4096,
                        flags: StreamFlags {
                            compression_block_bytes: 8192,
                            ..StreamFlags::default()
                        },
                        storage: StreamStorage::Extents,
                    }],
                },
            ],
            vec![NamespaceEntry {
                parent: ObjectId(1),
                target: ObjectId(2),
                name: "packed.bin".encode_utf16().collect(),
            }],
            ExtentGraph::build(
                vec![
                    Extent {
                        stream: StreamId(2),
                        logical_offset: 0,
                        length: 4096,
                        placement: Placement::Physical { byte_offset: 0 },
                        kind: ExtentKind::FileData,
                    },
                    Extent {
                        stream: StreamId(2),
                        logical_offset: 4096,
                        length: 4096,
                        placement: Placement::Sparse,
                        kind: ExtentKind::FileData,
                    },
                ],
                8192,
                2,
            )
            .unwrap(),
            ObjectGraphLimits {
                max_objects: 4,
                max_entries: 4,
                max_streams: 4,
                max_name_code_units: 255,
            },
        )
        .unwrap();
        let payload = reconstruct_stream_destination(
            &source,
            &graph,
            &Materialization {
                stream: StreamId(2),
                destination: ByteRange {
                    offset: 4096,
                    length: 4096,
                },
            },
        )
        .unwrap();
        assert_eq!(&payload[..6], b"ABCABC");
        assert!(payload[6..].iter().all(|byte| *byte == 0));
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

    #[allow(clippy::too_many_lines)]
    fn exfat_image_with_early_payload() -> (Vec<u8>, Vec<u8>) {
        const VOLUME_BYTES: u64 = 16 * 1024 * 1024;
        const CLUSTER_BYTES: u32 = 4096;
        let root = ObjectId(1);
        let root_record = ObjectRecord {
            id: root,
            kind: ObjectKind::Directory,
            link_count: 0,
            semantics: ObjectSemantics::default(),
            streams: Vec::new(),
        };
        let graph_limits = ObjectGraphLimits {
            max_objects: 4,
            max_entries: 4,
            max_streams: 4,
            max_name_code_units: 255,
        };
        let empty_graph = ObjectGraph::build(
            root,
            vec![root_record.clone()],
            Vec::new(),
            ExtentGraph::build(Vec::new(), VOLUME_BYTES, 4).unwrap(),
            graph_limits,
        )
        .unwrap();
        let upcase =
            generate_recommended_exfat_upcase(RecommendedExfatUpcaseLimits::default()).unwrap();
        let volume = ExfatVolumeProfile {
            volume_label: None,
            encoded_upcase_table: upcase.encoded_bytes(),
            upcase_checksum: RECOMMENDED_EXFAT_UPCASE_CHECKSUM,
            source_preservation: ExfatPreservationEvidence::default(),
            allocated_bad_clusters: 0,
            bad_cluster_ranges: &[],
        };
        let options = ExfatSerializeOptions {
            bytes_per_cluster: CLUSTER_BYTES,
            volume_serial_number: 0x1234_abcd,
            ..ExfatSerializeOptions::default()
        };
        let bootstrap = serialize_exfat_destination(
            &empty_graph,
            &[],
            volume,
            options,
            ExfatSerializeLimits::default(),
        )
        .unwrap();
        let payload_offset = u64::from(bootstrap.geometry.cluster_heap_offset_sectors) * 512;
        let payload = (0..usize::try_from(CLUSTER_BYTES).unwrap())
            .map(|index| u8::try_from(index % 251).unwrap())
            .collect::<Vec<_>>();
        let file = ObjectRecord {
            id: ObjectId(2),
            kind: ObjectKind::File,
            link_count: 1,
            semantics: ObjectSemantics::default(),
            streams: vec![ObjectStream {
                id: StreamId(20),
                name: None,
                logical_bytes: u64::from(CLUSTER_BYTES),
                initialized_bytes: u64::from(CLUSTER_BYTES),
                mapped_bytes: u64::from(CLUSTER_BYTES),
                allocated_bytes: u64::from(CLUSTER_BYTES),
                flags: StreamFlags::default(),
                storage: StreamStorage::Extents,
            }],
        };
        let graph = ObjectGraph::build(
            root,
            vec![root_record, file],
            vec![NamespaceEntry {
                parent: root,
                target: ObjectId(2),
                name: "payload.bin".encode_utf16().collect(),
            }],
            ExtentGraph::build(
                vec![Extent {
                    stream: StreamId(20),
                    logical_offset: 0,
                    length: u64::from(CLUSTER_BYTES),
                    placement: Placement::Physical {
                        byte_offset: payload_offset,
                    },
                    kind: ExtentKind::FileData,
                }],
                VOLUME_BYTES,
                4,
            )
            .unwrap(),
            graph_limits,
        )
        .unwrap();
        let timestamp = ((2024_u32 - 1980) << 25) | (1 << 21) | (1 << 16);
        let plan = serialize_exfat_destination(
            &graph,
            &[ExfatObjectMetadata {
                object: ObjectId(2),
                file_attributes: 0x20,
                timestamps: ExfatTimestamps {
                    create: timestamp,
                    modified: timestamp,
                    accessed: timestamp,
                    create_centiseconds: 0,
                    modified_centiseconds: 0,
                    create_utc_offset: 0x80,
                    modified_utc_offset: 0x80,
                    accessed_utc_offset: 0x80,
                },
            }],
            volume,
            options,
            ExfatSerializeLimits::default(),
        )
        .unwrap();
        assert_eq!(plan.reused_payloads[0].stream, StreamId(20));
        let mut image = vec![0_u8; usize::try_from(VOLUME_BYTES).unwrap()];
        let payload_start = usize::try_from(payload_offset).unwrap();
        image[payload_start..payload_start + payload.len()].copy_from_slice(&payload);
        for write in plan.overlay.writes() {
            let start = usize::try_from(write.offset).unwrap();
            image[start..start + write.bytes.len()].copy_from_slice(&write.bytes);
        }
        (image, payload)
    }

    #[allow(clippy::too_many_lines)]
    fn exfat_image_with_aligned_uninitialized_payload() -> (Vec<u8>, Vec<u8>) {
        const VOLUME_BYTES: u64 = 16 * 1024 * 1024;
        const CLUSTER_BYTES: u32 = 4096;
        const INITIALIZED: usize = 1000;
        let root = ObjectId(1);
        let root_record = ObjectRecord {
            id: root,
            kind: ObjectKind::Directory,
            link_count: 0,
            semantics: ObjectSemantics::default(),
            streams: Vec::new(),
        };
        let graph_limits = ObjectGraphLimits {
            max_objects: 4,
            max_entries: 4,
            max_streams: 4,
            max_name_code_units: 255,
        };
        let empty_graph = ObjectGraph::build(
            root,
            vec![root_record.clone()],
            Vec::new(),
            ExtentGraph::build(Vec::new(), VOLUME_BYTES, 4).unwrap(),
            graph_limits,
        )
        .unwrap();
        let upcase =
            generate_recommended_exfat_upcase(RecommendedExfatUpcaseLimits::default()).unwrap();
        let volume = ExfatVolumeProfile {
            volume_label: None,
            encoded_upcase_table: upcase.encoded_bytes(),
            upcase_checksum: RECOMMENDED_EXFAT_UPCASE_CHECKSUM,
            source_preservation: ExfatPreservationEvidence::default(),
            allocated_bad_clusters: 0,
            bad_cluster_ranges: &[],
        };
        let options = ExfatSerializeOptions {
            bytes_per_cluster: CLUSTER_BYTES,
            volume_serial_number: 0x1234_abcd,
            ..ExfatSerializeOptions::default()
        };
        let bootstrap = serialize_exfat_destination(
            &empty_graph,
            &[],
            volume,
            options,
            ExfatSerializeLimits::default(),
        )
        .unwrap();
        let payload_offset = u64::from(bootstrap.geometry.cluster_heap_offset_sectors) * 512;
        let mut allocated = (0..usize::try_from(CLUSTER_BYTES).unwrap())
            .map(|index| u8::try_from(index % 251).unwrap())
            .collect::<Vec<_>>();
        for byte in allocated.iter_mut().skip(INITIALIZED) {
            *byte = 0xaa;
        }
        let initialized = allocated[..INITIALIZED].to_vec();
        let file = ObjectRecord {
            id: ObjectId(2),
            kind: ObjectKind::File,
            link_count: 1,
            semantics: ObjectSemantics::default(),
            streams: vec![ObjectStream {
                id: StreamId(20),
                name: None,
                logical_bytes: u64::from(CLUSTER_BYTES),
                initialized_bytes: u64::try_from(INITIALIZED).unwrap(),
                mapped_bytes: u64::from(CLUSTER_BYTES),
                allocated_bytes: u64::from(CLUSTER_BYTES),
                flags: StreamFlags::default(),
                storage: StreamStorage::Extents,
            }],
        };
        let graph = ObjectGraph::build(
            root,
            vec![root_record, file],
            vec![NamespaceEntry {
                parent: root,
                target: ObjectId(2),
                name: "payload.bin".encode_utf16().collect(),
            }],
            ExtentGraph::build(
                vec![Extent {
                    stream: StreamId(20),
                    logical_offset: 0,
                    length: u64::from(CLUSTER_BYTES),
                    placement: Placement::Physical {
                        byte_offset: payload_offset,
                    },
                    kind: ExtentKind::FileData,
                }],
                VOLUME_BYTES,
                4,
            )
            .unwrap(),
            graph_limits,
        )
        .unwrap();
        let timestamp = ((2024_u32 - 1980) << 25) | (1 << 21) | (1 << 16);
        let plan = serialize_exfat_destination(
            &graph,
            &[ExfatObjectMetadata {
                object: ObjectId(2),
                file_attributes: 0x20,
                timestamps: ExfatTimestamps {
                    create: timestamp,
                    modified: timestamp,
                    accessed: timestamp,
                    create_centiseconds: 0,
                    modified_centiseconds: 0,
                    create_utc_offset: 0x80,
                    modified_utc_offset: 0x80,
                    accessed_utc_offset: 0x80,
                },
            }],
            volume,
            options,
            ExfatSerializeLimits::default(),
        )
        .unwrap();
        let mut image = vec![0_u8; usize::try_from(VOLUME_BYTES).unwrap()];
        let payload_start = usize::try_from(payload_offset).unwrap();
        image[payload_start..payload_start + allocated.len()].copy_from_slice(&allocated);
        for write in plan.overlay.writes() {
            let start = usize::try_from(write.offset).unwrap();
            image[start..start + write.bytes.len()].copy_from_slice(&write.bytes);
        }
        (image, initialized)
    }

    #[allow(clippy::too_many_lines)]
    fn exfat_image_with_two_4k_fragments() -> (Vec<u8>, Vec<u8>) {
        const VOLUME_BYTES: u64 = 16 * 1024 * 1024;
        const CLUSTER_BYTES: u32 = 4096;
        let root = ObjectId(1);
        let root_record = ObjectRecord {
            id: root,
            kind: ObjectKind::Directory,
            link_count: 0,
            semantics: ObjectSemantics::default(),
            streams: Vec::new(),
        };
        let graph_limits = ObjectGraphLimits {
            max_objects: 4,
            max_entries: 4,
            max_streams: 4,
            max_name_code_units: 255,
        };
        let empty_graph = ObjectGraph::build(
            root,
            vec![root_record.clone()],
            Vec::new(),
            ExtentGraph::build(Vec::new(), VOLUME_BYTES, 4).unwrap(),
            graph_limits,
        )
        .unwrap();
        let upcase =
            generate_recommended_exfat_upcase(RecommendedExfatUpcaseLimits::default()).unwrap();
        let volume = ExfatVolumeProfile {
            volume_label: None,
            encoded_upcase_table: upcase.encoded_bytes(),
            upcase_checksum: RECOMMENDED_EXFAT_UPCASE_CHECKSUM,
            source_preservation: ExfatPreservationEvidence::default(),
            allocated_bad_clusters: 0,
            bad_cluster_ranges: &[],
        };
        let options = ExfatSerializeOptions {
            bytes_per_cluster: CLUSTER_BYTES,
            volume_serial_number: 0x1234_abcd,
            ..ExfatSerializeOptions::default()
        };
        let bootstrap = serialize_exfat_destination(
            &empty_graph,
            &[],
            volume,
            options,
            ExfatSerializeLimits::default(),
        )
        .unwrap();
        let heap = u64::from(bootstrap.geometry.cluster_heap_offset_sectors) * 512;
        let cluster = u64::from(CLUSTER_BYTES);
        let first = heap + 100 * cluster;
        let second = heap + 120 * cluster;
        let payload = (0..8192)
            .map(|index| u8::try_from((index * 13) % 251).unwrap())
            .collect::<Vec<_>>();
        let file = ObjectRecord {
            id: ObjectId(2),
            kind: ObjectKind::File,
            link_count: 1,
            semantics: ObjectSemantics::default(),
            streams: vec![ObjectStream {
                id: StreamId(20),
                name: None,
                logical_bytes: 8192,
                initialized_bytes: 8192,
                mapped_bytes: 8192,
                allocated_bytes: 8192,
                flags: StreamFlags::default(),
                storage: StreamStorage::Extents,
            }],
        };
        let graph = ObjectGraph::build(
            root,
            vec![root_record, file],
            vec![NamespaceEntry {
                parent: root,
                target: ObjectId(2),
                name: "split.bin".encode_utf16().collect(),
            }],
            ExtentGraph::build(
                vec![
                    Extent {
                        stream: StreamId(20),
                        logical_offset: 0,
                        length: cluster,
                        placement: Placement::Physical { byte_offset: first },
                        kind: ExtentKind::FileData,
                    },
                    Extent {
                        stream: StreamId(20),
                        logical_offset: cluster,
                        length: cluster,
                        placement: Placement::Physical {
                            byte_offset: second,
                        },
                        kind: ExtentKind::FileData,
                    },
                ],
                VOLUME_BYTES,
                4,
            )
            .unwrap(),
            graph_limits,
        )
        .unwrap();
        let timestamp = ((2024_u32 - 1980) << 25) | (1 << 21) | (1 << 16);
        let plan = serialize_exfat_destination(
            &graph,
            &[ExfatObjectMetadata {
                object: ObjectId(2),
                file_attributes: 0x20,
                timestamps: ExfatTimestamps {
                    create: timestamp,
                    modified: timestamp,
                    accessed: timestamp,
                    create_centiseconds: 0,
                    modified_centiseconds: 0,
                    create_utc_offset: 0x80,
                    modified_utc_offset: 0x80,
                    accessed_utc_offset: 0x80,
                },
            }],
            volume,
            options,
            ExfatSerializeLimits::default(),
        )
        .unwrap();
        let mut image = vec![0_u8; usize::try_from(VOLUME_BYTES).unwrap()];
        let first_start = usize::try_from(first).unwrap();
        let second_start = usize::try_from(second).unwrap();
        image[first_start..first_start + 4096].copy_from_slice(&payload[..4096]);
        image[second_start..second_start + 4096].copy_from_slice(&payload[4096..]);
        for write in plan.overlay.writes() {
            let start = usize::try_from(write.offset).unwrap();
            image[start..start + write.bytes.len()].copy_from_slice(&write.bytes);
        }
        (image, payload)
    }

    #[allow(clippy::too_many_lines)]
    fn ntfs_image_with_payload_misaligned_for_8k_exfat() -> (Vec<u8>, Vec<u8>, u64) {
        const VOLUME_BYTES: u64 = 64 * 1024 * 1024;
        const PAYLOAD_BYTES: u64 = 8192;
        let payload = (0..usize::try_from(PAYLOAD_BYTES).unwrap())
            .map(|index| u8::try_from((index * 7) % 251).unwrap())
            .collect::<Vec<_>>();
        let root = ObjectRecord {
            id: ObjectId(1),
            kind: ObjectKind::Directory,
            link_count: 0,
            semantics: ObjectSemantics::default(),
            streams: Vec::new(),
        };
        let file = ObjectRecord {
            id: ObjectId(2),
            kind: ObjectKind::File,
            link_count: 1,
            semantics: ObjectSemantics::default(),
            streams: vec![ObjectStream {
                id: StreamId(2),
                name: None,
                logical_bytes: PAYLOAD_BYTES,
                initialized_bytes: PAYLOAD_BYTES,
                mapped_bytes: PAYLOAD_BYTES,
                allocated_bytes: PAYLOAD_BYTES,
                flags: StreamFlags::default(),
                storage: StreamStorage::Extents,
            }],
        };
        let limits = ObjectGraphLimits {
            max_objects: 4,
            max_entries: 4,
            max_streams: 4,
            max_name_code_units: 255,
        };
        for offset in (4 * 1024 * 1024 + 4096..48 * 1024 * 1024).step_by(8192) {
            let graph = ObjectGraph::build(
                ObjectId(1),
                vec![root.clone(), file.clone()],
                vec![NamespaceEntry {
                    parent: ObjectId(1),
                    target: ObjectId(2),
                    name: "payload.bin".encode_utf16().collect(),
                }],
                ExtentGraph::build(
                    vec![Extent {
                        stream: StreamId(2),
                        logical_offset: 0,
                        length: PAYLOAD_BYTES,
                        placement: Placement::Physical {
                            byte_offset: offset,
                        },
                        kind: ExtentKind::FileData,
                    }],
                    VOLUME_BYTES,
                    4,
                )
                .unwrap(),
                limits,
            )
            .unwrap();
            let Ok(plan) = plan_ntfs_destination(
                &graph,
                NtfsDestinationInputs {
                    image_bytes: VOLUME_BYTES,
                    partition_offset_sectors: 0,
                    cluster_bytes: 4096,
                    volume_serial_number: 0x1122_3344_5566_7788,
                    timestamp: 0x01dc_0000_0000_0000,
                },
                NtfsSerializeLimits::default(),
            ) else {
                continue;
            };
            let mut image = vec![0_u8; usize::try_from(VOLUME_BYTES).unwrap()];
            let payload_start = usize::try_from(offset).unwrap();
            image[payload_start..payload_start + payload.len()].copy_from_slice(&payload);
            for write in plan
                .staging_writes
                .iter()
                .chain(std::iter::once(&plan.backup_boot_write))
                .chain(std::iter::once(&plan.primary_boot_write))
            {
                let start = usize::try_from(write.offset).unwrap();
                image[start..start + write.bytes.len()].copy_from_slice(&write.bytes);
            }
            return (image, payload, offset);
        }
        panic!("could not find a target-misaligned NTFS payload placement outside NTFS metadata");
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
    fn conflicting_exfat_payload_is_copied_relocated_and_verified_in_new_ntfs_image() {
        let (source_bytes, payload) = exfat_image_with_early_payload();
        let source_file = TempFile::create(&source_bytes);
        let source = ImageFile::open(&source_file.path).unwrap();
        let source_snapshot =
            capture_source_image_snapshot(&source, CandidateExportLimits::default()).unwrap();
        let inspection = inspect_open_image(&source).unwrap();
        let normalized = inspection.normalized_exfat.as_deref().unwrap();
        assert!(matches!(
            plan_lossless_exfat_to_ntfs(
                normalized,
                GuaranteeMode::Escrow,
                ExfatToNtfsOptions::default(),
                ExfatToNtfsLimits::default(),
            ),
            Err(crate::cross_format::ExfatToNtfsError::Serialization(
                crate::fs::ntfs_serialize::NtfsSerializeError::PayloadMetadataConflict { .. }
            ))
        ));
        let draft = draft_lossless_exfat_to_ntfs(
            normalized,
            GuaranteeMode::Escrow,
            ExfatToNtfsOptions::default(),
            ExfatToNtfsLimits::default(),
        )
        .unwrap();
        let solved = solve_lossless_exfat_to_ntfs(draft, LayoutLimits::default()).unwrap();
        assert_eq!(solved.layout().relocations.len(), 1);
        let relocation = solved.layout().relocations[0];
        let preview =
            preview_ntfs_phase_writes(&source, &solved.destination, PreimageLimits::default())
                .unwrap();
        let destination = temp_path("relocated-candidate.ntfs.img");
        let escrow = temp_path("relocated-candidate.escrow");
        let evidence = export_relocated_candidate_image(
            &source,
            &destination,
            Some(&escrow),
            &preview,
            &source_snapshot,
            solved.relocation(),
            &solved.preservation,
            CandidateExportLimits::default(),
        )
        .unwrap();
        assert_eq!(evidence.target_filesystem, FileSystem::Ntfs);
        assert_eq!(
            evidence.applied_writes,
            preview.writes().target_staging.len()
                + preview.writes().backup_boot.len()
                + preview.writes().activation.len()
                + 1
        );
        let candidate_bytes = fs::read(&destination).unwrap();
        let destination_start = usize::try_from(relocation.destination.offset).unwrap();
        assert_eq!(
            &candidate_bytes[destination_start..destination_start + payload.len()],
            payload
        );
        assert_eq!(fs::read(&source_file.path).unwrap(), source_bytes);
        fs::remove_file(destination).unwrap();
        fs::remove_file(escrow).unwrap();
    }

    #[test]
    fn cancellation_during_relocation_cleans_partial_and_preserves_source() {
        let (source_bytes, _) = exfat_image_with_early_payload();
        let source_file = TempFile::create(&source_bytes);
        let source = ImageFile::open(&source_file.path).unwrap();
        let source_snapshot =
            capture_source_image_snapshot(&source, CandidateExportLimits::default()).unwrap();
        let inspection = inspect_open_image(&source).unwrap();
        let normalized = inspection.normalized_exfat.as_deref().unwrap();
        let draft = draft_lossless_exfat_to_ntfs(
            normalized,
            GuaranteeMode::Escrow,
            ExfatToNtfsOptions::default(),
            ExfatToNtfsLimits::default(),
        )
        .unwrap();
        let solved = solve_lossless_exfat_to_ntfs(draft, LayoutLimits::default()).unwrap();
        let preview =
            preview_ntfs_phase_writes(&source, &solved.destination, PreimageLimits::default())
                .unwrap();
        let parent = temp_path("cancelled-during-relocation-dir");
        fs::create_dir(&parent).unwrap();
        let destination = parent.join("candidate.img");
        let escrow = parent.join("candidate.escrow");

        let error = export_relocated_candidate_image_with_progress(
            &source,
            &destination,
            Some(&escrow),
            &preview,
            &source_snapshot,
            solved.relocation(),
            &solved.preservation,
            CandidateExportLimits {
                copy_chunk_bytes: 512,
                ..CandidateExportLimits::default()
            },
            |progress| {
                if progress.phase == CandidateWorkPhase::RelocatePayload
                    && progress.completed_bytes >= 512
                {
                    CandidateWorkControl::Cancel
                } else {
                    CandidateWorkControl::Continue
                }
            },
        )
        .unwrap_err();
        assert!(matches!(
            error,
            CandidateExportError::Cancelled {
                phase: CandidateWorkPhase::RelocatePayload
            }
        ));
        assert_eq!(fs::read_dir(&parent).unwrap().count(), 0);
        assert!(!destination.exists());
        assert!(!escrow.exists());
        assert_eq!(fs::read(&source_file.path).unwrap(), source_bytes);
        fs::remove_dir(parent).unwrap();
    }

    #[test]
    fn cancellation_during_materialization_cleans_partial_and_preserves_source() {
        let (source_bytes, _) = ntfs_image_with_resident_payload();
        let source_file = TempFile::create(&source_bytes);
        let source = ImageFile::open(&source_file.path).unwrap();
        let source_snapshot =
            capture_source_image_snapshot(&source, CandidateExportLimits::default()).unwrap();
        let inspection = inspect_open_image(&source).unwrap();
        let normalized = inspection.normalized_ntfs.as_deref().unwrap();
        let draft = draft_lossless_ntfs_to_exfat(
            normalized,
            GuaranteeMode::Escrow,
            NtfsToExfatOptions {
                bytes_per_cluster: 8192,
                ..NtfsToExfatOptions::default()
            },
            NtfsToExfatLimits::default(),
        )
        .unwrap();
        let solved = solve_lossless_ntfs_to_exfat(draft, LayoutLimits::default()).unwrap();
        assert!(solved.layout().relocations.is_empty());
        assert_eq!(solved.layout().materializations.len(), 1);
        let preview =
            preview_exfat_phase_writes(&source, &solved.destination, PreimageLimits::default())
                .unwrap();
        let parent = temp_path("cancelled-during-materialize-dir");
        fs::create_dir(&parent).unwrap();
        let destination = parent.join("candidate.img");
        let escrow = parent.join("candidate.escrow");

        let error = export_relocated_candidate_image_with_progress(
            &source,
            &destination,
            Some(&escrow),
            &preview,
            &source_snapshot,
            solved.relocation(),
            &solved.preservation,
            CandidateExportLimits {
                copy_chunk_bytes: 512,
                ..CandidateExportLimits::default()
            },
            |progress| {
                if progress.phase == CandidateWorkPhase::RelocatePayload
                    && progress.completed_bytes >= 512
                {
                    CandidateWorkControl::Cancel
                } else {
                    CandidateWorkControl::Continue
                }
            },
        )
        .unwrap_err();
        assert!(matches!(
            error,
            CandidateExportError::Cancelled {
                phase: CandidateWorkPhase::RelocatePayload
            }
        ));
        assert_eq!(fs::read_dir(&parent).unwrap().count(), 0);
        assert!(!destination.exists());
        assert!(!escrow.exists());
        assert_eq!(fs::read(&source_file.path).unwrap(), source_bytes);
        fs::remove_dir(parent).unwrap();
    }

    #[test]
    fn misaligned_ntfs_payload_is_copied_relocated_and_verified_in_new_exfat_image() {
        let (source_bytes, payload, source_offset) =
            ntfs_image_with_payload_misaligned_for_8k_exfat();
        assert_eq!(source_offset % 8192, 4096);
        let source_file = TempFile::create(&source_bytes);
        let source = ImageFile::open(&source_file.path).unwrap();
        let source_snapshot =
            capture_source_image_snapshot(&source, CandidateExportLimits::default()).unwrap();
        let inspection = inspect_open_image(&source).unwrap();
        let normalized = inspection.normalized_ntfs.as_deref().unwrap();
        let options = NtfsToExfatOptions {
            bytes_per_cluster: 8192,
            ..NtfsToExfatOptions::default()
        };
        assert!(matches!(
            plan_lossless_ntfs_to_exfat(
                normalized,
                GuaranteeMode::Escrow,
                options,
                NtfsToExfatLimits::default(),
            ),
            Err(crate::cross_format::NtfsToExfatError::Serialization(
                crate::fs::exfat_serialize::ExfatSerializeError::PayloadNotClusterAligned(_)
            ))
        ));
        let draft = draft_lossless_ntfs_to_exfat(
            normalized,
            GuaranteeMode::Escrow,
            options,
            NtfsToExfatLimits::default(),
        )
        .unwrap();
        let solved = solve_lossless_ntfs_to_exfat(draft, LayoutLimits::default()).unwrap();
        assert_eq!(solved.layout().relocations.len(), 1);
        let relocation = solved.layout().relocations[0];
        assert_eq!(relocation.source.offset, source_offset);
        assert_eq!(relocation.destination.offset % 8192, 0);
        let preview =
            preview_exfat_phase_writes(&source, &solved.destination, PreimageLimits::default())
                .unwrap();
        let destination = temp_path("relocated-candidate.exfat.img");
        let escrow = temp_path("relocated-exfat-candidate.escrow");
        let evidence = export_relocated_candidate_image(
            &source,
            &destination,
            Some(&escrow),
            &preview,
            &source_snapshot,
            solved.relocation(),
            &solved.preservation,
            CandidateExportLimits::default(),
        )
        .unwrap();
        assert_eq!(evidence.target_filesystem, FileSystem::ExFat);
        let candidate_bytes = fs::read(&destination).unwrap();
        let destination_start = usize::try_from(relocation.destination.offset).unwrap();
        assert_eq!(
            &candidate_bytes[destination_start..destination_start + payload.len()],
            payload
        );
        let candidate = inspect_image(&destination).unwrap();
        assert_eq!(candidate.profile.filesystem, FileSystem::ExFat);
        assert!(candidate.profile.inventory_complete);
        let verification = verify_bound_export(
            &destination,
            &escrow,
            Some(&source_file.path),
            CandidateVerificationLimits::default(),
        )
        .unwrap();
        assert_eq!(verification.target_filesystem, FileSystem::ExFat);
        assert_eq!(fs::read(&source_file.path).unwrap(), source_bytes);
        fs::remove_file(destination).unwrap();
        fs::remove_file(escrow).unwrap();
    }

    fn ntfs_image_with_resident_payload() -> (Vec<u8>, Vec<u8>) {
        const VOLUME_BYTES: u64 = 64 * 1024 * 1024;
        let payload = b"xyz".to_vec();
        let graph = ObjectGraph::build(
            ObjectId(1),
            vec![
                ObjectRecord {
                    id: ObjectId(1),
                    kind: ObjectKind::Directory,
                    link_count: 0,
                    semantics: ObjectSemantics::default(),
                    streams: Vec::new(),
                },
                ObjectRecord {
                    id: ObjectId(2),
                    kind: ObjectKind::File,
                    link_count: 1,
                    semantics: ObjectSemantics::default(),
                    streams: vec![ObjectStream {
                        id: StreamId(2),
                        name: None,
                        logical_bytes: u64::try_from(payload.len()).unwrap(),
                        initialized_bytes: u64::try_from(payload.len()).unwrap(),
                        mapped_bytes: u64::try_from(payload.len()).unwrap(),
                        allocated_bytes: 0,
                        flags: StreamFlags::default(),
                        storage: StreamStorage::Resident(payload.clone()),
                    }],
                },
            ],
            vec![NamespaceEntry {
                parent: ObjectId(1),
                target: ObjectId(2),
                name: "tiny.txt".encode_utf16().collect(),
            }],
            ExtentGraph::build(Vec::new(), VOLUME_BYTES, 1).unwrap(),
            ObjectGraphLimits {
                max_objects: 4,
                max_entries: 4,
                max_streams: 4,
                max_name_code_units: 255,
            },
        )
        .unwrap();
        let plan = plan_ntfs_destination(
            &graph,
            NtfsDestinationInputs {
                image_bytes: VOLUME_BYTES,
                partition_offset_sectors: 0,
                cluster_bytes: 4096,
                volume_serial_number: 0x1122_3344_5566_7788,
                timestamp: 0x01dc_0000_0000_0000,
            },
            NtfsSerializeLimits::default(),
        )
        .unwrap();
        let mut image = vec![0_u8; usize::try_from(VOLUME_BYTES).unwrap()];
        for write in plan
            .staging_writes
            .iter()
            .chain(std::iter::once(&plan.backup_boot_write))
            .chain(std::iter::once(&plan.primary_boot_write))
        {
            let start = usize::try_from(write.offset).unwrap();
            image[start..start + write.bytes.len()].copy_from_slice(&write.bytes);
        }
        (image, payload)
    }

    #[allow(clippy::too_many_lines)]
    fn ntfs_image_with_sparse_payload() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        const VOLUME_BYTES: u64 = 16 * 1024 * 1024;
        const FIRST: u64 = 8 * 1024 * 1024;
        const SECOND: u64 = FIRST + 8192;
        let first = vec![0xa5_u8; 4096];
        let second = vec![0x5a_u8; 4096];
        let graph = ObjectGraph::build(
            ObjectId(1),
            vec![
                ObjectRecord {
                    id: ObjectId(1),
                    kind: ObjectKind::Directory,
                    link_count: 0,
                    semantics: ObjectSemantics::default(),
                    streams: Vec::new(),
                },
                ObjectRecord {
                    id: ObjectId(2),
                    kind: ObjectKind::File,
                    link_count: 1,
                    semantics: ObjectSemantics::default(),
                    streams: vec![ObjectStream {
                        id: StreamId(2),
                        name: None,
                        logical_bytes: 3 * 4096,
                        initialized_bytes: 3 * 4096,
                        mapped_bytes: 3 * 4096,
                        allocated_bytes: 2 * 4096,
                        flags: StreamFlags {
                            sparse: true,
                            compressed: false,
                            encrypted: false,
                            compression_block_bytes: 0,
                        },
                        storage: StreamStorage::Extents,
                    }],
                },
            ],
            vec![NamespaceEntry {
                parent: ObjectId(1),
                target: ObjectId(2),
                name: "sparse.bin".encode_utf16().collect(),
            }],
            ExtentGraph::build(
                vec![
                    Extent {
                        stream: StreamId(2),
                        logical_offset: 0,
                        length: 4096,
                        placement: Placement::Physical { byte_offset: FIRST },
                        kind: ExtentKind::FileData,
                    },
                    Extent {
                        stream: StreamId(2),
                        logical_offset: 4096,
                        length: 4096,
                        placement: Placement::Sparse,
                        kind: ExtentKind::FileData,
                    },
                    Extent {
                        stream: StreamId(2),
                        logical_offset: 8192,
                        length: 4096,
                        placement: Placement::Physical {
                            byte_offset: SECOND,
                        },
                        kind: ExtentKind::FileData,
                    },
                ],
                VOLUME_BYTES,
                4,
            )
            .unwrap(),
            ObjectGraphLimits {
                max_objects: 4,
                max_entries: 4,
                max_streams: 4,
                max_name_code_units: 255,
            },
        )
        .unwrap();
        let plan = plan_ntfs_destination(
            &graph,
            NtfsDestinationInputs {
                image_bytes: VOLUME_BYTES,
                partition_offset_sectors: 0,
                cluster_bytes: 4096,
                volume_serial_number: 0x1122_3344_5566_7788,
                timestamp: 0x01dc_0000_0000_0000,
            },
            NtfsSerializeLimits::default(),
        )
        .unwrap();
        let mut image = vec![0_u8; usize::try_from(VOLUME_BYTES).unwrap()];
        let first_start = usize::try_from(FIRST).unwrap();
        let second_start = usize::try_from(SECOND).unwrap();
        image[first_start..first_start + 4096].copy_from_slice(&first);
        image[second_start..second_start + 4096].copy_from_slice(&second);
        for write in plan
            .staging_writes
            .iter()
            .chain(std::iter::once(&plan.backup_boot_write))
            .chain(std::iter::once(&plan.primary_boot_write))
        {
            let start = usize::try_from(write.offset).unwrap();
            image[start..start + write.bytes.len()].copy_from_slice(&write.bytes);
        }
        (image, first, second)
    }

    fn unprotect_file_record(record: &mut [u8]) {
        let sequence_array = usize::from(u16::from_le_bytes(record[4..6].try_into().unwrap()));
        let count = usize::from(u16::from_le_bytes(record[6..8].try_into().unwrap()));
        for sector in 0..count.saturating_sub(1) {
            let trailer = (sector + 1) * 512 - 2;
            let original = sequence_array + (sector + 1) * 2;
            record.copy_within(original..original + 2, trailer);
        }
    }

    fn protect_file_record(record: &mut [u8]) {
        let sequence_array = usize::from(u16::from_le_bytes(record[4..6].try_into().unwrap()));
        let count = usize::from(u16::from_le_bytes(record[6..8].try_into().unwrap()));
        let sequence_number = record[sequence_array..sequence_array + 2].to_vec();
        for sector in 0..count.saturating_sub(1) {
            let trailer = (sector + 1) * 512 - 2;
            let original = sequence_array + (sector + 1) * 2;
            record.copy_within(trailer..trailer + 2, original);
            record[trailer..trailer + 2].copy_from_slice(&sequence_number);
        }
    }

    fn patch_unnamed_sparse_data_to_lznt1(record: &mut [u8]) -> bool {
        let mut cursor = usize::from(u16::from_le_bytes(record[20..22].try_into().unwrap()));
        while cursor + 16 <= record.len() {
            let attribute_type = u32::from_le_bytes(record[cursor..cursor + 4].try_into().unwrap());
            if attribute_type == u32::MAX {
                return false;
            }
            let length = usize::try_from(u32::from_le_bytes(
                record[cursor + 4..cursor + 8].try_into().unwrap(),
            ))
            .unwrap();
            if length < 16 || cursor + length > record.len() {
                return false;
            }
            let non_resident = record[cursor + 8] == 1;
            let name_length = record[cursor + 9];
            let flags = u16::from_le_bytes(record[cursor + 12..cursor + 14].try_into().unwrap());
            if attribute_type == 0x80 && non_resident && name_length == 0 && flags == 0x8000 {
                record[cursor + 12..cursor + 14].copy_from_slice(&1_u16.to_le_bytes());
                record[cursor + 34] = 1;
                return true;
            }
            cursor += length;
        }
        false
    }

    #[allow(clippy::too_many_lines)]
    fn ntfs_image_with_compressed_payload() -> (Vec<u8>, Vec<u8>) {
        const VOLUME_BYTES: u64 = 16 * 1024 * 1024;
        const PAYLOAD: u64 = 8 * 1024 * 1024;
        let encoded = lznt1_abcabc_cluster();
        let graph = ObjectGraph::build(
            ObjectId(1),
            vec![
                ObjectRecord {
                    id: ObjectId(1),
                    kind: ObjectKind::Directory,
                    link_count: 0,
                    semantics: ObjectSemantics::default(),
                    streams: Vec::new(),
                },
                ObjectRecord {
                    id: ObjectId(2),
                    kind: ObjectKind::File,
                    link_count: 1,
                    semantics: ObjectSemantics::default(),
                    streams: vec![ObjectStream {
                        id: StreamId(2),
                        name: None,
                        logical_bytes: 6,
                        initialized_bytes: 6,
                        mapped_bytes: 8192,
                        allocated_bytes: 4096,
                        flags: StreamFlags {
                            sparse: true,
                            compressed: false,
                            encrypted: false,
                            compression_block_bytes: 0,
                        },
                        storage: StreamStorage::Extents,
                    }],
                },
            ],
            vec![NamespaceEntry {
                parent: ObjectId(1),
                target: ObjectId(2),
                name: "packed.bin".encode_utf16().collect(),
            }],
            ExtentGraph::build(
                vec![
                    Extent {
                        stream: StreamId(2),
                        logical_offset: 0,
                        length: 4096,
                        placement: Placement::Physical {
                            byte_offset: PAYLOAD,
                        },
                        kind: ExtentKind::FileData,
                    },
                    Extent {
                        stream: StreamId(2),
                        logical_offset: 4096,
                        length: 4096,
                        placement: Placement::Sparse,
                        kind: ExtentKind::FileData,
                    },
                ],
                VOLUME_BYTES,
                4,
            )
            .unwrap(),
            ObjectGraphLimits {
                max_objects: 4,
                max_entries: 4,
                max_streams: 4,
                max_name_code_units: 255,
            },
        )
        .unwrap();
        let plan = plan_ntfs_destination(
            &graph,
            NtfsDestinationInputs {
                image_bytes: VOLUME_BYTES,
                partition_offset_sectors: 0,
                cluster_bytes: 4096,
                volume_serial_number: 0x1122_3344_5566_7788,
                timestamp: 0x01dc_0000_0000_0000,
            },
            NtfsSerializeLimits::default(),
        )
        .unwrap();
        let mut image = vec![0_u8; usize::try_from(VOLUME_BYTES).unwrap()];
        let payload_start = usize::try_from(PAYLOAD).unwrap();
        image[payload_start..payload_start + 4096].copy_from_slice(&encoded);
        for write in plan
            .staging_writes
            .iter()
            .chain(std::iter::once(&plan.backup_boot_write))
            .chain(std::iter::once(&plan.primary_boot_write))
        {
            let start = usize::try_from(write.offset).unwrap();
            image[start..start + write.bytes.len()].copy_from_slice(&write.bytes);
        }
        let mut patched = false;
        let mut offset = 0;
        while offset + 1024 <= image.len() {
            if &image[offset..offset + 4] != b"FILE" {
                offset += 1024;
                continue;
            }
            unprotect_file_record(&mut image[offset..offset + 1024]);
            let found = patch_unnamed_sparse_data_to_lznt1(&mut image[offset..offset + 1024]);
            protect_file_record(&mut image[offset..offset + 1024]);
            if found {
                patched = true;
            }
            offset += 1024;
        }
        assert!(
            patched,
            "serialized NTFS image must contain unnamed sparse $DATA"
        );
        (image, b"ABCABC".to_vec())
    }

    fn first_ntfs_distinct_exfat_colliding_units() -> (u16, u16) {
        use crate::fs::ntfs_upcase_serialize::{
            NtfsUpcaseLimits, generate_ntfs3g_windows61_upcase,
        };
        use crate::preservation::is_legal_exfat_name;
        let ntfs = generate_ntfs3g_windows61_upcase(NtfsUpcaseLimits::default()).unwrap();
        let exfat =
            generate_recommended_exfat_upcase(RecommendedExfatUpcaseLimits::default()).unwrap();
        let mut buckets: std::collections::BTreeMap<u16, Vec<u16>> =
            std::collections::BTreeMap::new();
        for unit in 0_u16..=u16::MAX {
            if (0xd800..=0xdfff).contains(&unit)
                || matches!(unit, 32 | 46)
                || !is_legal_exfat_name(&[unit])
            {
                continue;
            }
            buckets.entry(exfat.map(unit)).or_default().push(unit);
        }
        for members in buckets.values() {
            for (index, left) in members.iter().enumerate() {
                for right in &members[index + 1..] {
                    if ntfs.lookup(*left) != ntfs.lookup(*right) {
                        return (*left, *right);
                    }
                }
            }
        }
        panic!("expected an NTFS-distinct exFAT-colliding legal name pair");
    }

    #[allow(clippy::too_many_lines)]
    fn ntfs_image_with_exfat_case_colliding_names() -> (Vec<u8>, Vec<u16>, Vec<u16>) {
        const VOLUME_BYTES: u64 = 16 * 1024 * 1024;
        let (left_unit, right_unit) = first_ntfs_distinct_exfat_colliding_units();
        let left_name = vec![left_unit];
        let right_name = vec![right_unit];
        let left_payload = b"left".to_vec();
        let right_payload = b"right".to_vec();
        let graph = ObjectGraph::build(
            ObjectId(1),
            vec![
                ObjectRecord {
                    id: ObjectId(1),
                    kind: ObjectKind::Directory,
                    link_count: 0,
                    semantics: ObjectSemantics::default(),
                    streams: Vec::new(),
                },
                ObjectRecord {
                    id: ObjectId(2),
                    kind: ObjectKind::File,
                    link_count: 1,
                    semantics: ObjectSemantics::default(),
                    streams: vec![ObjectStream {
                        id: StreamId(2),
                        name: None,
                        logical_bytes: u64::try_from(left_payload.len()).unwrap(),
                        initialized_bytes: u64::try_from(left_payload.len()).unwrap(),
                        mapped_bytes: u64::try_from(left_payload.len()).unwrap(),
                        allocated_bytes: 0,
                        flags: StreamFlags::default(),
                        storage: StreamStorage::Resident(left_payload),
                    }],
                },
                ObjectRecord {
                    id: ObjectId(3),
                    kind: ObjectKind::File,
                    link_count: 1,
                    semantics: ObjectSemantics::default(),
                    streams: vec![ObjectStream {
                        id: StreamId(3),
                        name: None,
                        logical_bytes: u64::try_from(right_payload.len()).unwrap(),
                        initialized_bytes: u64::try_from(right_payload.len()).unwrap(),
                        mapped_bytes: u64::try_from(right_payload.len()).unwrap(),
                        allocated_bytes: 0,
                        flags: StreamFlags::default(),
                        storage: StreamStorage::Resident(right_payload),
                    }],
                },
            ],
            vec![
                NamespaceEntry {
                    parent: ObjectId(1),
                    target: ObjectId(2),
                    name: left_name.clone(),
                },
                NamespaceEntry {
                    parent: ObjectId(1),
                    target: ObjectId(3),
                    name: right_name.clone(),
                },
            ],
            ExtentGraph::build(Vec::new(), VOLUME_BYTES, 1).unwrap(),
            ObjectGraphLimits {
                max_objects: 8,
                max_entries: 8,
                max_streams: 8,
                max_name_code_units: 255,
            },
        )
        .unwrap();
        let plan = plan_ntfs_destination(
            &graph,
            NtfsDestinationInputs {
                image_bytes: VOLUME_BYTES,
                partition_offset_sectors: 0,
                cluster_bytes: 4096,
                volume_serial_number: 0x1122_3344_5566_7788,
                timestamp: 0x01dc_0000_0000_0000,
            },
            NtfsSerializeLimits::default(),
        )
        .unwrap();
        let mut image = vec![0_u8; usize::try_from(VOLUME_BYTES).unwrap()];
        for write in plan
            .staging_writes
            .iter()
            .chain(std::iter::once(&plan.backup_boot_write))
            .chain(std::iter::once(&plan.primary_boot_write))
        {
            let start = usize::try_from(write.offset).unwrap();
            image[start..start + write.bytes.len()].copy_from_slice(&write.bytes);
        }
        (image, left_name, right_name)
    }

    fn ntfs_image_with_hard_links_and_named_stream() -> (Vec<u8>, Vec<u8>) {
        const VOLUME_BYTES: u64 = 64 * 1024 * 1024;
        let payload = b"abc".to_vec();
        let graph = ObjectGraph::build(
            ObjectId(1),
            vec![
                ObjectRecord {
                    id: ObjectId(1),
                    kind: ObjectKind::Directory,
                    link_count: 0,
                    semantics: ObjectSemantics::default(),
                    streams: Vec::new(),
                },
                ObjectRecord {
                    id: ObjectId(2),
                    kind: ObjectKind::File,
                    link_count: 2,
                    semantics: ObjectSemantics::default(),
                    streams: vec![
                        ObjectStream {
                            id: StreamId(2),
                            name: None,
                            logical_bytes: u64::try_from(payload.len()).unwrap(),
                            initialized_bytes: u64::try_from(payload.len()).unwrap(),
                            mapped_bytes: u64::try_from(payload.len()).unwrap(),
                            allocated_bytes: 0,
                            flags: StreamFlags::default(),
                            storage: StreamStorage::Resident(payload.clone()),
                        },
                        ObjectStream {
                            id: StreamId(3),
                            name: Some("fork".encode_utf16().collect()),
                            logical_bytes: 1,
                            initialized_bytes: 1,
                            mapped_bytes: 1,
                            allocated_bytes: 0,
                            flags: StreamFlags::default(),
                            storage: StreamStorage::Resident(b"x".to_vec()),
                        },
                    ],
                },
            ],
            vec![
                NamespaceEntry {
                    parent: ObjectId(1),
                    target: ObjectId(2),
                    name: "beta.txt".encode_utf16().collect(),
                },
                NamespaceEntry {
                    parent: ObjectId(1),
                    target: ObjectId(2),
                    name: "alpha.txt".encode_utf16().collect(),
                },
            ],
            ExtentGraph::build(Vec::new(), VOLUME_BYTES, 1).unwrap(),
            ObjectGraphLimits {
                max_objects: 4,
                max_entries: 4,
                max_streams: 4,
                max_name_code_units: 255,
            },
        )
        .unwrap();
        let plan = plan_ntfs_destination(
            &graph,
            NtfsDestinationInputs {
                image_bytes: VOLUME_BYTES,
                partition_offset_sectors: 0,
                cluster_bytes: 4096,
                volume_serial_number: 0x1122_3344_5566_7788,
                timestamp: 0x01dc_0000_0000_0000,
            },
            NtfsSerializeLimits::default(),
        )
        .unwrap();
        let mut image = vec![0_u8; usize::try_from(VOLUME_BYTES).unwrap()];
        for write in plan
            .staging_writes
            .iter()
            .chain(std::iter::once(&plan.backup_boot_write))
            .chain(std::iter::once(&plan.primary_boot_write))
        {
            let start = usize::try_from(write.offset).unwrap();
            image[start..start + write.bytes.len()].copy_from_slice(&write.bytes);
        }
        (image, payload)
    }

    #[allow(clippy::too_many_lines)]
    fn ntfs_image_with_directory_hard_links_and_nonresident_ads() -> (Vec<u8>, Vec<u8>) {
        const VOLUME_BYTES: u64 = 64 * 1024 * 1024;
        let payload = b"abc".to_vec();
        let ads = (0..4096)
            .map(|index| u8::try_from(index % 251).unwrap())
            .collect::<Vec<_>>();
        let limits = ObjectGraphLimits {
            max_objects: 8,
            max_entries: 8,
            max_streams: 8,
            max_name_code_units: 255,
        };
        let objects = vec![
            ObjectRecord {
                id: ObjectId(1),
                kind: ObjectKind::Directory,
                link_count: 0,
                semantics: ObjectSemantics::default(),
                streams: Vec::new(),
            },
            ObjectRecord {
                id: ObjectId(2),
                kind: ObjectKind::Directory,
                link_count: 2,
                semantics: ObjectSemantics::default(),
                streams: Vec::new(),
            },
            ObjectRecord {
                id: ObjectId(3),
                kind: ObjectKind::Directory,
                link_count: 1,
                semantics: ObjectSemantics::default(),
                streams: Vec::new(),
            },
            ObjectRecord {
                id: ObjectId(4),
                kind: ObjectKind::File,
                link_count: 2,
                semantics: ObjectSemantics::default(),
                streams: vec![
                    ObjectStream {
                        id: StreamId(2),
                        name: None,
                        logical_bytes: u64::try_from(payload.len()).unwrap(),
                        initialized_bytes: u64::try_from(payload.len()).unwrap(),
                        mapped_bytes: u64::try_from(payload.len()).unwrap(),
                        allocated_bytes: 0,
                        flags: StreamFlags::default(),
                        storage: StreamStorage::Resident(payload.clone()),
                    },
                    ObjectStream {
                        id: StreamId(3),
                        name: Some("fork".encode_utf16().collect()),
                        logical_bytes: 4096,
                        initialized_bytes: 4096,
                        mapped_bytes: 4096,
                        allocated_bytes: 4096,
                        flags: StreamFlags::default(),
                        storage: StreamStorage::Extents,
                    },
                ],
            },
        ];
        let entries = vec![
            NamespaceEntry {
                parent: ObjectId(1),
                target: ObjectId(2),
                name: "right".encode_utf16().collect(),
            },
            NamespaceEntry {
                parent: ObjectId(1),
                target: ObjectId(2),
                name: "left".encode_utf16().collect(),
            },
            NamespaceEntry {
                parent: ObjectId(1),
                target: ObjectId(3),
                name: "other".encode_utf16().collect(),
            },
            NamespaceEntry {
                parent: ObjectId(2),
                target: ObjectId(4),
                name: "shared.bin".encode_utf16().collect(),
            },
            NamespaceEntry {
                parent: ObjectId(3),
                target: ObjectId(4),
                name: "alias.bin".encode_utf16().collect(),
            },
        ];
        for offset in (8 * 1024 * 1024..40 * 1024 * 1024).step_by(8192) {
            let graph = ObjectGraph::build(
                ObjectId(1),
                objects.clone(),
                entries.clone(),
                ExtentGraph::build(
                    vec![Extent {
                        stream: StreamId(3),
                        logical_offset: 0,
                        length: 4096,
                        placement: Placement::Physical {
                            byte_offset: offset,
                        },
                        kind: ExtentKind::FileData,
                    }],
                    VOLUME_BYTES,
                    4,
                )
                .unwrap(),
                limits,
            )
            .unwrap();
            let Ok(plan) = plan_ntfs_destination(
                &graph,
                NtfsDestinationInputs {
                    image_bytes: VOLUME_BYTES,
                    partition_offset_sectors: 0,
                    cluster_bytes: 4096,
                    volume_serial_number: 0x1122_3344_5566_7788,
                    timestamp: 0x01dc_0000_0000_0000,
                },
                NtfsSerializeLimits::default(),
            ) else {
                continue;
            };
            let mut image = vec![0_u8; usize::try_from(VOLUME_BYTES).unwrap()];
            let start = usize::try_from(offset).unwrap();
            image[start..start + ads.len()].copy_from_slice(&ads);
            for write in plan
                .staging_writes
                .iter()
                .chain(std::iter::once(&plan.backup_boot_write))
                .chain(std::iter::once(&plan.primary_boot_write))
            {
                let write_start = usize::try_from(write.offset).unwrap();
                image[write_start..write_start + write.bytes.len()].copy_from_slice(&write.bytes);
            }
            return (image, payload);
        }
        panic!("could not place a non-resident named stream outside NTFS metadata");
    }

    fn ntfs_image_with_two_4k_fragments() -> (Vec<u8>, Vec<u8>) {
        const VOLUME_BYTES: u64 = 64 * 1024 * 1024;
        let payload = (0..8192)
            .map(|index| u8::try_from((index * 11) % 251).unwrap())
            .collect::<Vec<_>>();
        let root = ObjectRecord {
            id: ObjectId(1),
            kind: ObjectKind::Directory,
            link_count: 0,
            semantics: ObjectSemantics::default(),
            streams: Vec::new(),
        };
        let file = ObjectRecord {
            id: ObjectId(2),
            kind: ObjectKind::File,
            link_count: 1,
            semantics: ObjectSemantics::default(),
            streams: vec![ObjectStream {
                id: StreamId(2),
                name: None,
                logical_bytes: 8192,
                initialized_bytes: 8192,
                mapped_bytes: 8192,
                allocated_bytes: 8192,
                flags: StreamFlags::default(),
                storage: StreamStorage::Extents,
            }],
        };
        let limits = ObjectGraphLimits {
            max_objects: 4,
            max_entries: 4,
            max_streams: 4,
            max_name_code_units: 255,
        };
        for first in (8 * 1024 * 1024..40 * 1024 * 1024).step_by(8192) {
            let second = first + 16 * 1024;
            let graph = ObjectGraph::build(
                ObjectId(1),
                vec![root.clone(), file.clone()],
                vec![NamespaceEntry {
                    parent: ObjectId(1),
                    target: ObjectId(2),
                    name: "split.bin".encode_utf16().collect(),
                }],
                ExtentGraph::build(
                    vec![
                        Extent {
                            stream: StreamId(2),
                            logical_offset: 0,
                            length: 4096,
                            placement: Placement::Physical { byte_offset: first },
                            kind: ExtentKind::FileData,
                        },
                        Extent {
                            stream: StreamId(2),
                            logical_offset: 4096,
                            length: 4096,
                            placement: Placement::Physical {
                                byte_offset: second,
                            },
                            kind: ExtentKind::FileData,
                        },
                    ],
                    VOLUME_BYTES,
                    4,
                )
                .unwrap(),
                limits,
            )
            .unwrap();
            let Ok(plan) = plan_ntfs_destination(
                &graph,
                NtfsDestinationInputs {
                    image_bytes: VOLUME_BYTES,
                    partition_offset_sectors: 0,
                    cluster_bytes: 4096,
                    volume_serial_number: 0x1122_3344_5566_7788,
                    timestamp: 0x01dc_0000_0000_0000,
                },
                NtfsSerializeLimits::default(),
            ) else {
                continue;
            };
            let mut image = vec![0_u8; usize::try_from(VOLUME_BYTES).unwrap()];
            let first_start = usize::try_from(first).unwrap();
            let second_start = usize::try_from(second).unwrap();
            image[first_start..first_start + 4096].copy_from_slice(&payload[..4096]);
            image[second_start..second_start + 4096].copy_from_slice(&payload[4096..]);
            for write in plan
                .staging_writes
                .iter()
                .chain(std::iter::once(&plan.backup_boot_write))
                .chain(std::iter::once(&plan.primary_boot_write))
            {
                let start = usize::try_from(write.offset).unwrap();
                image[start..start + write.bytes.len()].copy_from_slice(&write.bytes);
            }
            return (image, payload);
        }
        panic!("could not place a fragmented NTFS payload outside metadata");
    }

    #[allow(clippy::too_many_lines)]
    fn ntfs_image_with_partially_initialized_fragments() -> (Vec<u8>, Vec<u8>) {
        const VOLUME_BYTES: u64 = 64 * 1024 * 1024;
        const INITIALIZED: usize = 5000;
        let mut allocated = (0..8192)
            .map(|index| u8::try_from((index * 11) % 251).unwrap())
            .collect::<Vec<_>>();
        for byte in allocated.iter_mut().skip(INITIALIZED) {
            *byte = 0xaa;
        }
        let initialized = allocated[..INITIALIZED].to_vec();
        let root = ObjectRecord {
            id: ObjectId(1),
            kind: ObjectKind::Directory,
            link_count: 0,
            semantics: ObjectSemantics::default(),
            streams: Vec::new(),
        };
        let file = ObjectRecord {
            id: ObjectId(2),
            kind: ObjectKind::File,
            link_count: 1,
            semantics: ObjectSemantics::default(),
            streams: vec![ObjectStream {
                id: StreamId(2),
                name: None,
                logical_bytes: 8192,
                initialized_bytes: u64::try_from(INITIALIZED).unwrap(),
                mapped_bytes: 8192,
                allocated_bytes: 8192,
                flags: StreamFlags::default(),
                storage: StreamStorage::Extents,
            }],
        };
        let limits = ObjectGraphLimits {
            max_objects: 4,
            max_entries: 4,
            max_streams: 4,
            max_name_code_units: 255,
        };
        for first in (8 * 1024 * 1024..40 * 1024 * 1024).step_by(8192) {
            let second = first + 16 * 1024;
            let graph = ObjectGraph::build(
                ObjectId(1),
                vec![root.clone(), file.clone()],
                vec![NamespaceEntry {
                    parent: ObjectId(1),
                    target: ObjectId(2),
                    name: "partial.bin".encode_utf16().collect(),
                }],
                ExtentGraph::build(
                    vec![
                        Extent {
                            stream: StreamId(2),
                            logical_offset: 0,
                            length: 4096,
                            placement: Placement::Physical { byte_offset: first },
                            kind: ExtentKind::FileData,
                        },
                        Extent {
                            stream: StreamId(2),
                            logical_offset: 4096,
                            length: 4096,
                            placement: Placement::Physical {
                                byte_offset: second,
                            },
                            kind: ExtentKind::FileData,
                        },
                    ],
                    VOLUME_BYTES,
                    4,
                )
                .unwrap(),
                limits,
            )
            .unwrap();
            let Ok(plan) = plan_ntfs_destination(
                &graph,
                NtfsDestinationInputs {
                    image_bytes: VOLUME_BYTES,
                    partition_offset_sectors: 0,
                    cluster_bytes: 4096,
                    volume_serial_number: 0x1122_3344_5566_7788,
                    timestamp: 0x01dc_0000_0000_0000,
                },
                NtfsSerializeLimits::default(),
            ) else {
                continue;
            };
            let mut image = vec![0_u8; usize::try_from(VOLUME_BYTES).unwrap()];
            let first_start = usize::try_from(first).unwrap();
            let second_start = usize::try_from(second).unwrap();
            image[first_start..first_start + 4096].copy_from_slice(&allocated[..4096]);
            image[second_start..second_start + 4096].copy_from_slice(&allocated[4096..]);
            for write in plan
                .staging_writes
                .iter()
                .chain(std::iter::once(&plan.backup_boot_write))
                .chain(std::iter::once(&plan.primary_boot_write))
            {
                let start = usize::try_from(write.offset).unwrap();
                image[start..start + write.bytes.len()].copy_from_slice(&write.bytes);
            }
            return (image, initialized);
        }
        panic!("could not place a partially initialized NTFS payload outside metadata");
    }

    #[allow(clippy::too_many_lines)]
    fn ntfs_image_with_aligned_uninitialized_payload() -> (Vec<u8>, Vec<u8>, u64) {
        const VOLUME_BYTES: u64 = 64 * 1024 * 1024;
        const INITIALIZED: usize = 5000;
        let mut allocated = (0..8192)
            .map(|index| u8::try_from((index * 11) % 251).unwrap())
            .collect::<Vec<_>>();
        for byte in allocated.iter_mut().skip(INITIALIZED) {
            *byte = 0xaa;
        }
        let initialized = allocated[..INITIALIZED].to_vec();
        let root = ObjectRecord {
            id: ObjectId(1),
            kind: ObjectKind::Directory,
            link_count: 0,
            semantics: ObjectSemantics::default(),
            streams: Vec::new(),
        };
        let file = ObjectRecord {
            id: ObjectId(2),
            kind: ObjectKind::File,
            link_count: 1,
            semantics: ObjectSemantics::default(),
            streams: vec![ObjectStream {
                id: StreamId(2),
                name: None,
                logical_bytes: 8192,
                initialized_bytes: u64::try_from(INITIALIZED).unwrap(),
                mapped_bytes: 8192,
                allocated_bytes: 8192,
                flags: StreamFlags::default(),
                storage: StreamStorage::Extents,
            }],
        };
        let limits = ObjectGraphLimits {
            max_objects: 4,
            max_entries: 4,
            max_streams: 4,
            max_name_code_units: 255,
        };
        for offset in (8 * 1024 * 1024..40 * 1024 * 1024).step_by(8192) {
            let graph = ObjectGraph::build(
                ObjectId(1),
                vec![root.clone(), file.clone()],
                vec![NamespaceEntry {
                    parent: ObjectId(1),
                    target: ObjectId(2),
                    name: "partial.bin".encode_utf16().collect(),
                }],
                ExtentGraph::build(
                    vec![Extent {
                        stream: StreamId(2),
                        logical_offset: 0,
                        length: 8192,
                        placement: Placement::Physical {
                            byte_offset: offset,
                        },
                        kind: ExtentKind::FileData,
                    }],
                    VOLUME_BYTES,
                    4,
                )
                .unwrap(),
                limits,
            )
            .unwrap();
            let Ok(plan) = plan_ntfs_destination(
                &graph,
                NtfsDestinationInputs {
                    image_bytes: VOLUME_BYTES,
                    partition_offset_sectors: 0,
                    cluster_bytes: 4096,
                    volume_serial_number: 0x1122_3344_5566_7788,
                    timestamp: 0x01dc_0000_0000_0000,
                },
                NtfsSerializeLimits::default(),
            ) else {
                continue;
            };
            let mut image = vec![0_u8; usize::try_from(VOLUME_BYTES).unwrap()];
            let start = usize::try_from(offset).unwrap();
            image[start..start + allocated.len()].copy_from_slice(&allocated);
            for write in plan
                .staging_writes
                .iter()
                .chain(std::iter::once(&plan.backup_boot_write))
                .chain(std::iter::once(&plan.primary_boot_write))
            {
                let write_start = usize::try_from(write.offset).unwrap();
                image[write_start..write_start + write.bytes.len()].copy_from_slice(&write.bytes);
            }
            return (image, initialized, offset);
        }
        panic!("could not place an aligned uninitialized NTFS payload outside metadata");
    }

    #[allow(clippy::too_many_lines)]
    fn ntfs_image_with_misaligned_and_resident_payloads() -> (Vec<u8>, Vec<u8>, Vec<u8>, u64) {
        const VOLUME_BYTES: u64 = 64 * 1024 * 1024;
        const PAYLOAD_BYTES: u64 = 8192;
        let relocated = (0..usize::try_from(PAYLOAD_BYTES).unwrap())
            .map(|index| u8::try_from((index * 7) % 251).unwrap())
            .collect::<Vec<_>>();
        let resident = b"xyz".to_vec();
        let root = ObjectRecord {
            id: ObjectId(1),
            kind: ObjectKind::Directory,
            link_count: 0,
            semantics: ObjectSemantics::default(),
            streams: Vec::new(),
        };
        let extent_file = ObjectRecord {
            id: ObjectId(2),
            kind: ObjectKind::File,
            link_count: 1,
            semantics: ObjectSemantics::default(),
            streams: vec![ObjectStream {
                id: StreamId(2),
                name: None,
                logical_bytes: PAYLOAD_BYTES,
                initialized_bytes: PAYLOAD_BYTES,
                mapped_bytes: PAYLOAD_BYTES,
                allocated_bytes: PAYLOAD_BYTES,
                flags: StreamFlags::default(),
                storage: StreamStorage::Extents,
            }],
        };
        let resident_file = ObjectRecord {
            id: ObjectId(3),
            kind: ObjectKind::File,
            link_count: 1,
            semantics: ObjectSemantics::default(),
            streams: vec![ObjectStream {
                id: StreamId(3),
                name: None,
                logical_bytes: u64::try_from(resident.len()).unwrap(),
                initialized_bytes: u64::try_from(resident.len()).unwrap(),
                mapped_bytes: u64::try_from(resident.len()).unwrap(),
                allocated_bytes: 0,
                flags: StreamFlags::default(),
                storage: StreamStorage::Resident(resident.clone()),
            }],
        };
        let limits = ObjectGraphLimits {
            max_objects: 4,
            max_entries: 4,
            max_streams: 4,
            max_name_code_units: 255,
        };
        for offset in (4 * 1024 * 1024 + 4096..48 * 1024 * 1024).step_by(8192) {
            let graph = ObjectGraph::build(
                ObjectId(1),
                vec![root.clone(), extent_file.clone(), resident_file.clone()],
                vec![
                    NamespaceEntry {
                        parent: ObjectId(1),
                        target: ObjectId(2),
                        name: "payload.bin".encode_utf16().collect(),
                    },
                    NamespaceEntry {
                        parent: ObjectId(1),
                        target: ObjectId(3),
                        name: "tiny.txt".encode_utf16().collect(),
                    },
                ],
                ExtentGraph::build(
                    vec![Extent {
                        stream: StreamId(2),
                        logical_offset: 0,
                        length: PAYLOAD_BYTES,
                        placement: Placement::Physical {
                            byte_offset: offset,
                        },
                        kind: ExtentKind::FileData,
                    }],
                    VOLUME_BYTES,
                    4,
                )
                .unwrap(),
                limits,
            )
            .unwrap();
            let Ok(plan) = plan_ntfs_destination(
                &graph,
                NtfsDestinationInputs {
                    image_bytes: VOLUME_BYTES,
                    partition_offset_sectors: 0,
                    cluster_bytes: 4096,
                    volume_serial_number: 0x1122_3344_5566_7788,
                    timestamp: 0x01dc_0000_0000_0000,
                },
                NtfsSerializeLimits::default(),
            ) else {
                continue;
            };
            let mut image = vec![0_u8; usize::try_from(VOLUME_BYTES).unwrap()];
            let start = usize::try_from(offset).unwrap();
            image[start..start + relocated.len()].copy_from_slice(&relocated);
            for write in plan
                .staging_writes
                .iter()
                .chain(std::iter::once(&plan.backup_boot_write))
                .chain(std::iter::once(&plan.primary_boot_write))
            {
                let write_start = usize::try_from(write.offset).unwrap();
                image[write_start..write_start + write.bytes.len()].copy_from_slice(&write.bytes);
            }
            return (image, relocated, resident, offset);
        }
        panic!("could not place a mixed NTFS payload outside metadata");
    }

    #[test]
    fn resident_ntfs_payload_is_materialized_into_new_exfat_image() {
        let (source_bytes, payload) = ntfs_image_with_resident_payload();
        let source_file = TempFile::create(&source_bytes);
        let source = ImageFile::open(&source_file.path).unwrap();
        let source_snapshot =
            capture_source_image_snapshot(&source, CandidateExportLimits::default()).unwrap();
        let inspection = inspect_open_image(&source).unwrap();
        let normalized = inspection.normalized_ntfs.as_deref().unwrap();
        let draft = draft_lossless_ntfs_to_exfat(
            normalized,
            GuaranteeMode::Escrow,
            NtfsToExfatOptions {
                bytes_per_cluster: 8192,
                ..NtfsToExfatOptions::default()
            },
            NtfsToExfatLimits::default(),
        )
        .unwrap();
        let solved = solve_lossless_ntfs_to_exfat(draft, LayoutLimits::default()).unwrap();
        assert!(solved.layout().relocations.is_empty());
        assert_eq!(solved.layout().materializations.len(), 1);
        let destination_range = solved.layout().materializations[0].destination;
        assert_eq!(destination_range.length, 8192);
        assert_eq!(destination_range.offset % 8192, 0);
        let preview =
            preview_exfat_phase_writes(&source, &solved.destination, PreimageLimits::default())
                .unwrap();
        let destination = temp_path("resident-candidate.exfat.img");
        let escrow = temp_path("resident-candidate.escrow");
        let evidence = export_relocated_candidate_image(
            &source,
            &destination,
            Some(&escrow),
            &preview,
            &source_snapshot,
            solved.relocation(),
            &solved.preservation,
            CandidateExportLimits::default(),
        )
        .unwrap();
        assert_eq!(evidence.target_filesystem, FileSystem::ExFat);
        let candidate_bytes = fs::read(&destination).unwrap();
        let start = usize::try_from(destination_range.offset).unwrap();
        assert_eq!(&candidate_bytes[start..start + payload.len()], payload);
        assert!(
            candidate_bytes[start + payload.len()..start + 8192]
                .iter()
                .all(|byte| *byte == 0)
        );
        let candidate = inspect_image(&destination).unwrap();
        assert_eq!(candidate.profile.filesystem, FileSystem::ExFat);
        assert!(candidate.profile.inventory_complete);
        verify_bound_export(
            &destination,
            &escrow,
            Some(&source_file.path),
            CandidateVerificationLimits::default(),
        )
        .unwrap();
        assert_eq!(fs::read(&source_file.path).unwrap(), source_bytes);
        fs::remove_file(destination).unwrap();
        fs::remove_file(escrow).unwrap();
    }

    #[test]
    fn sparse_ntfs_payload_is_materialized_into_new_exfat_image() {
        let (source_bytes, first, second) = ntfs_image_with_sparse_payload();
        let source_file = TempFile::create(&source_bytes);
        let source = ImageFile::open(&source_file.path).unwrap();
        let source_snapshot =
            capture_source_image_snapshot(&source, CandidateExportLimits::default()).unwrap();
        let inspection = inspect_open_image(&source).unwrap();
        let normalized = inspection.normalized_ntfs.as_deref().unwrap();
        assert!(
            normalized
                .graph
                .objects()
                .iter()
                .flat_map(|object| &object.streams)
                .any(|stream| stream.flags.sparse)
        );
        let draft = draft_lossless_ntfs_to_exfat(
            normalized,
            GuaranteeMode::Escrow,
            NtfsToExfatOptions::default(),
            NtfsToExfatLimits::default(),
        )
        .unwrap();
        let solved = solve_lossless_ntfs_to_exfat(draft, LayoutLimits::default()).unwrap();
        assert!(solved.layout().relocations.is_empty());
        assert_eq!(solved.layout().materializations.len(), 1);
        let destination_range = solved.layout().materializations[0].destination;
        assert_eq!(destination_range.length, 3 * 4096);
        let preview =
            preview_exfat_phase_writes(&source, &solved.destination, PreimageLimits::default())
                .unwrap();
        let destination = temp_path("sparse-candidate.exfat.img");
        let escrow = temp_path("sparse-candidate.escrow");
        export_relocated_candidate_image(
            &source,
            &destination,
            Some(&escrow),
            &preview,
            &source_snapshot,
            solved.relocation(),
            &solved.preservation,
            CandidateExportLimits::default(),
        )
        .unwrap();
        let candidate_bytes = fs::read(&destination).unwrap();
        let start = usize::try_from(destination_range.offset).unwrap();
        assert_eq!(&candidate_bytes[start..start + 4096], first.as_slice());
        assert!(
            candidate_bytes[start + 4096..start + 8192]
                .iter()
                .all(|byte| *byte == 0)
        );
        assert_eq!(
            &candidate_bytes[start + 8192..start + 3 * 4096],
            second.as_slice()
        );
        verify_bound_export(
            &destination,
            &escrow,
            Some(&source_file.path),
            CandidateVerificationLimits::default(),
        )
        .unwrap();
        assert_eq!(fs::read(&source_file.path).unwrap(), source_bytes);
        fs::remove_file(destination).unwrap();
        fs::remove_file(escrow).unwrap();
    }

    #[test]
    fn compressed_ntfs_payload_is_decompressed_into_new_exfat_image() {
        let (source_bytes, plaintext) = ntfs_image_with_compressed_payload();
        let source_file = TempFile::create(&source_bytes);
        let source = ImageFile::open(&source_file.path).unwrap();
        let source_snapshot =
            capture_source_image_snapshot(&source, CandidateExportLimits::default()).unwrap();
        let inspection = inspect_open_image(&source).unwrap();
        let normalized = inspection.normalized_ntfs.as_deref().unwrap();
        assert!(
            normalized
                .graph
                .objects()
                .iter()
                .flat_map(|object| &object.streams)
                .any(|stream| stream.flags.compressed
                    && stream.flags.compression_block_bytes == 8192)
        );
        let draft = draft_lossless_ntfs_to_exfat(
            normalized,
            GuaranteeMode::Escrow,
            NtfsToExfatOptions::default(),
            NtfsToExfatLimits::default(),
        )
        .unwrap();
        assert!(
            draft
                .target_graph()
                .objects()
                .iter()
                .flat_map(|object| &object.streams)
                .any(|stream| !stream.flags.compressed
                    && stream.flags.compression_block_bytes == 8192)
        );
        let solved = solve_lossless_ntfs_to_exfat(draft, LayoutLimits::default()).unwrap();
        assert!(solved.layout().relocations.is_empty());
        assert_eq!(solved.layout().materializations.len(), 1);
        let destination_range = solved.layout().materializations[0].destination;
        assert_eq!(destination_range.length, 4096);
        assert!(
            solved
                .target_graph()
                .objects()
                .iter()
                .flat_map(|object| &object.streams)
                .all(|stream| stream.flags.compression_block_bytes == 0 && !stream.flags.compressed)
        );
        let preview =
            preview_exfat_phase_writes(&source, &solved.destination, PreimageLimits::default())
                .unwrap();
        let destination = temp_path("compressed-candidate.exfat.img");
        let escrow = temp_path("compressed-candidate.escrow");
        export_relocated_candidate_image(
            &source,
            &destination,
            Some(&escrow),
            &preview,
            &source_snapshot,
            solved.relocation(),
            &solved.preservation,
            CandidateExportLimits::default(),
        )
        .unwrap();
        let candidate_bytes = fs::read(&destination).unwrap();
        let start = usize::try_from(destination_range.offset).unwrap();
        assert_eq!(&candidate_bytes[start..start + plaintext.len()], plaintext);
        assert!(
            candidate_bytes[start + plaintext.len()..start + 4096]
                .iter()
                .all(|byte| *byte == 0)
        );
        verify_bound_export(
            &destination,
            &escrow,
            Some(&source_file.path),
            CandidateVerificationLimits::default(),
        )
        .unwrap();
        assert_eq!(fs::read(&source_file.path).unwrap(), source_bytes);
        fs::remove_file(destination).unwrap();
        fs::remove_file(escrow).unwrap();
    }

    #[test]
    fn escrow_ntfs_exfat_case_collisions_export_dest_native_names() {
        let (source_bytes, left_name, right_name) = ntfs_image_with_exfat_case_colliding_names();
        let source_file = TempFile::create(&source_bytes);
        let source = ImageFile::open(&source_file.path).unwrap();
        let source_snapshot =
            capture_source_image_snapshot(&source, CandidateExportLimits::default()).unwrap();
        let inspection = inspect_open_image(&source).unwrap();
        let normalized = inspection.normalized_ntfs.as_deref().unwrap();
        let mut source_names: Vec<Vec<u16>> = normalized
            .graph
            .entries()
            .iter()
            .map(|entry| entry.name.clone())
            .collect();
        source_names.sort();
        let mut expected_source = vec![left_name.clone(), right_name.clone()];
        expected_source.sort();
        assert_eq!(source_names, expected_source);
        let draft = draft_lossless_ntfs_to_exfat(
            normalized,
            GuaranteeMode::Escrow,
            NtfsToExfatOptions::default(),
            NtfsToExfatLimits::default(),
        )
        .unwrap();
        let solved = solve_lossless_ntfs_to_exfat(draft, LayoutLimits::default()).unwrap();
        let dest_names: std::collections::BTreeSet<Vec<u16>> = solved
            .target_graph()
            .entries()
            .iter()
            .map(|entry| entry.name.clone())
            .collect();
        assert_eq!(dest_names.len(), 2);
        assert!(dest_names.contains(&left_name));
        let mut renamed = right_name;
        renamed.extend("~2".encode_utf16());
        assert!(dest_names.contains(&renamed));
        let preview =
            preview_exfat_phase_writes(&source, &solved.destination, PreimageLimits::default())
                .unwrap();
        let destination = temp_path("case-collision-candidate.exfat.img");
        let escrow = temp_path("case-collision-candidate.escrow");
        export_relocated_candidate_image(
            &source,
            &destination,
            Some(&escrow),
            &preview,
            &source_snapshot,
            solved.relocation(),
            &solved.preservation,
            CandidateExportLimits::default(),
        )
        .unwrap();
        verify_bound_export(
            &destination,
            &escrow,
            Some(&source_file.path),
            CandidateVerificationLimits::default(),
        )
        .unwrap();
        let candidate = inspect_image(&destination).unwrap();
        assert_eq!(candidate.profile.filesystem, FileSystem::ExFat);
        assert!(candidate.profile.inventory_complete);
        assert_eq!(fs::read(&source_file.path).unwrap(), source_bytes);
        fs::remove_file(destination).unwrap();
        fs::remove_file(escrow).unwrap();
    }

    #[test]
    fn escrow_ntfs_hard_links_and_ads_export_dest_native_exfat() {
        let (source_bytes, payload) = ntfs_image_with_hard_links_and_named_stream();
        let source_file = TempFile::create(&source_bytes);
        let source = ImageFile::open(&source_file.path).unwrap();
        let source_snapshot =
            capture_source_image_snapshot(&source, CandidateExportLimits::default()).unwrap();
        let inspection = inspect_open_image(&source).unwrap();
        let normalized = inspection.normalized_ntfs.as_deref().unwrap();
        assert_eq!(normalized.graph.entries().len(), 2);
        assert_eq!(
            normalized
                .graph
                .objects()
                .iter()
                .find(|object| object.kind == ObjectKind::File)
                .unwrap()
                .streams
                .len(),
            2
        );
        assert!(
            !evaluate_ntfs(
                normalized,
                FileSystem::ExFat,
                GuaranteeMode::Strict,
                crate::preservation::PreservationLimits::default(),
            )
            .unwrap()
            .permitted
        );
        let draft = draft_lossless_ntfs_to_exfat(
            normalized,
            GuaranteeMode::Escrow,
            NtfsToExfatOptions {
                bytes_per_cluster: 8192,
                ..NtfsToExfatOptions::default()
            },
            NtfsToExfatLimits::default(),
        )
        .unwrap();
        let solved = solve_lossless_ntfs_to_exfat(draft, LayoutLimits::default()).unwrap();
        let dest_entries: Vec<Vec<u16>> = solved
            .target_graph()
            .entries()
            .iter()
            .map(|entry| entry.name.clone())
            .collect();
        assert_eq!(
            dest_entries,
            vec!["alpha.txt".encode_utf16().collect::<Vec<_>>()]
        );
        let dest_file = solved
            .target_graph()
            .objects()
            .iter()
            .find(|object| object.kind == ObjectKind::File)
            .unwrap();
        assert_eq!(dest_file.link_count, 1);
        assert_eq!(dest_file.streams.len(), 1);
        assert!(dest_file.streams[0].name.is_none());
        let destination_range = solved.layout().materializations[0].destination;
        let preview =
            preview_exfat_phase_writes(&source, &solved.destination, PreimageLimits::default())
                .unwrap();
        let destination = temp_path("hardlink-ads-candidate.exfat.img");
        let escrow = temp_path("hardlink-ads-candidate.escrow");
        export_relocated_candidate_image(
            &source,
            &destination,
            Some(&escrow),
            &preview,
            &source_snapshot,
            solved.relocation(),
            &solved.preservation,
            CandidateExportLimits::default(),
        )
        .unwrap();
        let candidate_bytes = fs::read(&destination).unwrap();
        let start = usize::try_from(destination_range.offset).unwrap();
        assert_eq!(&candidate_bytes[start..start + payload.len()], payload);
        verify_bound_export(
            &destination,
            &escrow,
            Some(&source_file.path),
            CandidateVerificationLimits::default(),
        )
        .unwrap();
        assert_eq!(fs::read(&source_file.path).unwrap(), source_bytes);
        fs::remove_file(destination).unwrap();
        fs::remove_file(escrow).unwrap();
    }

    /// Exact per-object NTFS evidence for the escrow round-trip source volume.
    struct RoundTripSource {
        image: Vec<u8>,
        serial: u64,
        label: Vec<u16>,
        /// (dest-native path, timestamps, low-word DOS attributes without the directory bit)
        objects: Vec<(Vec<&'static str>, NtfsObjectTimestamps, u32)>,
        junction_payload: Vec<u8>,
        symlink_payload: Vec<u8>,
    }

    fn reparse_payload(tag: u32, data: &[u8]) -> Vec<u8> {
        let mut payload = tag.to_le_bytes().to_vec();
        payload.extend_from_slice(&u16::try_from(data.len()).unwrap().to_le_bytes());
        payload.extend_from_slice(&[0, 0]);
        payload.extend_from_slice(data);
        payload
    }

    #[allow(clippy::too_many_lines)]
    fn ntfs_round_trip_source() -> RoundTripSource {
        use crate::fs::ntfs_serialize::{
            NTFS3G_SECURITY_ID_READ_WRITE, NtfsObjectMetadata, NtfsVolumeProfile,
            plan_ntfs_destination_with_metadata_and_volume,
        };

        const VOLUME_BYTES: u64 = 64 * 1024 * 1024;
        // 2025-era FILETIME base with sub-10 ms tick offsets that exFAT cannot represent.
        const BASE: u64 = 0x01dc_0000_0000_0000;
        let stamps = |offset: u64| NtfsObjectTimestamps {
            creation_time: BASE + offset + 1_234_567,
            modification_time: BASE + offset + 2_345_671,
            mft_change_time: BASE + offset + 3_456_713,
            access_time: BASE + offset + 4_567_131,
        };
        let root_stamps = stamps(0);
        let file_stamps = stamps(600_000_000);
        let junction_stamps = stamps(1_200_000_000);
        let symlink_stamps = stamps(1_800_000_000);
        let junction_payload = reparse_payload(0xa000_0003, b"\\??\\C:\\target\0");
        let symlink_payload = reparse_payload(0xa000_000c, b"relative\0");
        let resident = |id: u64, name: Option<&str>, bytes: &[u8]| ObjectStream {
            id: StreamId(id),
            name: name.map(|name| name.encode_utf16().collect()),
            logical_bytes: u64::try_from(bytes.len()).unwrap(),
            initialized_bytes: u64::try_from(bytes.len()).unwrap(),
            mapped_bytes: u64::try_from(bytes.len()).unwrap(),
            allocated_bytes: 0,
            flags: StreamFlags::default(),
            storage: StreamStorage::Resident(bytes.to_vec()),
        };
        let reparse_semantics = ObjectSemantics {
            is_reparse_point: true,
            ..ObjectSemantics::default()
        };
        let graph = ObjectGraph::build(
            ObjectId(1),
            vec![
                ObjectRecord {
                    id: ObjectId(1),
                    kind: ObjectKind::Directory,
                    link_count: 0,
                    semantics: ObjectSemantics::default(),
                    streams: Vec::new(),
                },
                ObjectRecord {
                    id: ObjectId(2),
                    kind: ObjectKind::File,
                    link_count: 2,
                    semantics: ObjectSemantics::default(),
                    streams: vec![resident(2, None, b"abc"), resident(3, Some("fork"), b"xyz")],
                },
                ObjectRecord {
                    id: ObjectId(3),
                    kind: ObjectKind::Directory,
                    link_count: 1,
                    semantics: reparse_semantics,
                    streams: Vec::new(),
                },
                ObjectRecord {
                    id: ObjectId(4),
                    kind: ObjectKind::File,
                    link_count: 1,
                    semantics: reparse_semantics,
                    streams: vec![resident(4, None, b"")],
                },
            ],
            vec![
                NamespaceEntry {
                    parent: ObjectId(1),
                    target: ObjectId(2),
                    name: "beta.txt".encode_utf16().collect(),
                },
                NamespaceEntry {
                    parent: ObjectId(1),
                    target: ObjectId(2),
                    name: "alpha.txt".encode_utf16().collect(),
                },
                NamespaceEntry {
                    parent: ObjectId(1),
                    target: ObjectId(3),
                    name: "junction".encode_utf16().collect(),
                },
                NamespaceEntry {
                    parent: ObjectId(1),
                    target: ObjectId(4),
                    name: "link.lnk".encode_utf16().collect(),
                },
            ],
            ExtentGraph::build(Vec::new(), VOLUME_BYTES, 1).unwrap(),
            ObjectGraphLimits {
                max_objects: 8,
                max_entries: 8,
                max_streams: 8,
                max_name_code_units: 255,
            },
        )
        .unwrap();
        let metadata =
            |object: u64, kind: ObjectKind, timestamps, attributes: u32| NtfsObjectMetadata {
                object: ObjectId(object),
                object_kind: kind,
                timestamps,
                dos_file_attributes: attributes,
                security_id: NTFS3G_SECURITY_ID_READ_WRITE,
            };
        let object_metadata = vec![
            metadata(1, ObjectKind::Directory, root_stamps, 0x16),
            metadata(2, ObjectKind::File, file_stamps, 0x21),
            metadata(3, ObjectKind::Directory, junction_stamps, 0x10),
            metadata(4, ObjectKind::File, symlink_stamps, 0x20),
        ];
        let label: Vec<u16> = "Round Trip Volume 2025".encode_utf16().collect();
        let serial = 0x1122_3344_5566_7788;
        let plan = plan_ntfs_destination_with_metadata_and_volume(
            &graph,
            NtfsDestinationInputs {
                image_bytes: VOLUME_BYTES,
                partition_offset_sectors: 0,
                cluster_bytes: 4096,
                volume_serial_number: serial,
                timestamp: BASE,
            },
            &object_metadata,
            NtfsVolumeProfile {
                volume_label: Some(&label),
                bad_cluster_ranges: &[],
                reparse_points: &[
                    (ObjectId(3), junction_payload.as_slice()),
                    (ObjectId(4), symlink_payload.as_slice()),
                ],
            },
            NtfsSerializeLimits::default(),
        )
        .unwrap();
        let mut image = vec![0_u8; usize::try_from(VOLUME_BYTES).unwrap()];
        for write in plan
            .staging_writes
            .iter()
            .chain(std::iter::once(&plan.backup_boot_write))
            .chain(std::iter::once(&plan.primary_boot_write))
        {
            let start = usize::try_from(write.offset).unwrap();
            image[start..start + write.bytes.len()].copy_from_slice(&write.bytes);
        }
        RoundTripSource {
            image,
            serial,
            label,
            objects: vec![
                (vec![], root_stamps, 0x06),
                (vec!["alpha.txt"], file_stamps, 0x21),
                (vec!["junction"], junction_stamps, 0x00),
                (vec!["link.lnk"], symlink_stamps, 0x20),
            ],
            junction_payload,
            symlink_payload,
        }
    }

    fn ntfs_path_of(normalized: &NormalizedNtfs, object: ObjectId) -> Vec<String> {
        let mut path = Vec::new();
        let mut current = object;
        while current != normalized.graph.root() {
            let entry = normalized
                .graph
                .entries()
                .iter()
                .find(|entry| entry.target == current)
                .unwrap();
            path.push(String::from_utf16(&entry.name).unwrap());
            current = entry.parent;
        }
        path.reverse();
        path
    }

    #[test]
    #[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
    fn escrow_round_trip_restores_ntfs_identities_metadata_and_reparse_index() {
        use crate::cross_format::draft_escrow_restored_exfat_to_ntfs;
        use crate::escrow_restore::{NtfsRestoreError, decode_restore_sidecar};
        use crate::fs::ntfs_extend::parse_reparse_r_index_entries;
        use crate::preservation::PreservationLimits;

        let source = ntfs_round_trip_source();
        let source_file = TempFile::create(&source.image);
        let source_image = ImageFile::open(&source_file.path).unwrap();
        let source_snapshot =
            capture_source_image_snapshot(&source_image, CandidateExportLimits::default()).unwrap();
        let inspection = inspect_open_image(&source_image).unwrap();
        let normalized = inspection.normalized_ntfs.as_deref().unwrap();
        assert_eq!(normalized.graph.objects().len(), 4);

        // Forward: NTFS -> exFAT with escrow.
        let draft = draft_lossless_ntfs_to_exfat(
            normalized,
            GuaranteeMode::Escrow,
            NtfsToExfatOptions::default(),
            NtfsToExfatLimits::default(),
        )
        .unwrap();
        let solved = solve_lossless_ntfs_to_exfat(draft, LayoutLimits::default()).unwrap();
        let preview = preview_exfat_phase_writes(
            &source_image,
            &solved.destination,
            PreimageLimits::default(),
        )
        .unwrap();
        let exfat_path = temp_path("round-trip.exfat.img");
        let exfat_escrow_path = temp_path("round-trip.exfat.escrow");
        export_relocated_candidate_image(
            &source_image,
            &exfat_path,
            Some(&exfat_escrow_path),
            &preview,
            &source_snapshot,
            solved.relocation(),
            &solved.preservation,
            CandidateExportLimits::default(),
        )
        .unwrap();

        // Backward: the exFAT candidate plus its bound escrow become a new NTFS image.
        let exfat_image = ImageFile::open(&exfat_path).unwrap();
        let exfat_snapshot =
            capture_source_image_snapshot(&exfat_image, CandidateExportLimits::default()).unwrap();
        let exfat_inspection = inspect_open_image(&exfat_image).unwrap();
        let normalized_exfat = exfat_inspection.normalized_exfat.as_deref().unwrap();
        assert_eq!(normalized_exfat.graph.entries().len(), 3);
        let escrow_bytes = fs::read(&exfat_escrow_path).unwrap();
        let sidecar = decode_restore_sidecar(
            &escrow_bytes,
            exfat_snapshot.sha256(),
            CandidateExportLimits::default().max_escrow_bytes,
            PreservationLimits::default(),
        )
        .unwrap();
        let restored_draft = draft_escrow_restored_exfat_to_ntfs(
            normalized_exfat,
            &sidecar,
            GuaranteeMode::Escrow,
            ExfatToNtfsOptions::default(),
            ExfatToNtfsLimits::default(),
        )
        .unwrap();
        assert_eq!(restored_draft.target_graph().entries().len(), 4);
        let restored_solved =
            solve_lossless_exfat_to_ntfs(restored_draft, LayoutLimits::default()).unwrap();
        let restored_preview = preview_ntfs_phase_writes(
            &exfat_image,
            &restored_solved.destination,
            PreimageLimits::default(),
        )
        .unwrap();
        let ntfs_path = temp_path("round-trip.restored.ntfs.img");
        let ntfs_escrow_path = temp_path("round-trip.restored.ntfs.escrow");
        export_relocated_candidate_image(
            &exfat_image,
            &ntfs_path,
            Some(&ntfs_escrow_path),
            &restored_preview,
            &exfat_snapshot,
            restored_solved.relocation(),
            &restored_solved.preservation,
            CandidateExportLimits::default(),
        )
        .unwrap();
        verify_bound_export(
            &ntfs_path,
            &ntfs_escrow_path,
            Some(&exfat_path),
            CandidateVerificationLimits::default(),
        )
        .unwrap();

        // The restored NTFS volume carries the original identities and exact metadata.
        let restored_inspection = inspect_image(&ntfs_path).unwrap();
        let restored = restored_inspection.normalized_ntfs.as_deref().unwrap();
        assert_eq!(restored.preservation.volume_serial_number, source.serial);
        assert_eq!(
            restored.preservation.volume_label.as_deref(),
            Some(source.label.as_slice())
        );
        assert_eq!(restored.graph.objects().len(), 4);
        let mut names: Vec<String> = restored
            .graph
            .entries()
            .iter()
            .map(|entry| String::from_utf16(&entry.name).unwrap())
            .collect();
        names.sort_unstable();
        assert_eq!(names, ["alpha.txt", "beta.txt", "junction", "link.lnk"]);
        let file = restored
            .graph
            .objects()
            .iter()
            .find(|object| object.streams.len() == 2)
            .unwrap();
        assert_eq!(file.link_count, 2);
        let restored_bytes = fs::read(&ntfs_path).unwrap();
        let stream_bytes = |stream: &crate::object::ObjectStream| -> Vec<u8> {
            match &stream.storage {
                StreamStorage::Resident(bytes) => bytes.clone(),
                StreamStorage::Extents => {
                    let mut bytes = Vec::new();
                    for extent in restored.graph.extents().extents() {
                        if extent.stream != stream.id {
                            continue;
                        }
                        let Placement::Physical { byte_offset } = extent.placement else {
                            panic!("physical placement");
                        };
                        let start = usize::try_from(byte_offset).unwrap();
                        let end = start + usize::try_from(extent.length).unwrap();
                        bytes.extend_from_slice(&restored_bytes[start..end]);
                    }
                    bytes.truncate(usize::try_from(stream.logical_bytes).unwrap());
                    bytes
                }
            }
        };
        let fork_name: Vec<u16> = "fork".encode_utf16().collect();
        let fork = file
            .streams
            .iter()
            .find(|stream| stream.name.as_deref() == Some(fork_name.as_slice()))
            .expect("restored named stream");
        assert_eq!(stream_bytes(fork), b"xyz");
        let unnamed = file
            .streams
            .iter()
            .find(|stream| stream.name.is_none())
            .expect("restored unnamed stream");
        assert_eq!(stream_bytes(unnamed), b"abc");
        let mut listed_reparse = Vec::new();
        let mut checked_objects = 0usize;
        for preserved in &restored.preservation.objects {
            let object = &preserved.source;
            let is_user_visible = preserved.object == restored.graph.root()
                || restored
                    .graph
                    .entries()
                    .iter()
                    .any(|entry| entry.target == preserved.object);
            if !is_user_visible {
                // System records ($MFT, $Extend and its children, ...) are not part of the
                // user-visible graph and carry no escrowed metadata.
                continue;
            }
            checked_objects += 1;
            let path = ntfs_path_of(restored, preserved.object);
            let expected = source
                .objects
                .iter()
                .find(|(expected_path, _, _)| {
                    expected_path.len() == path.len()
                        && expected_path
                            .iter()
                            .zip(path.iter())
                            .all(|(left, right)| *left == right)
                })
                .unwrap_or_else(|| panic!("unexpected restored path {path:?}"));
            let standard = object.standard_information.unwrap();
            assert_eq!(
                (
                    standard.creation_time,
                    standard.modification_time,
                    standard.mft_change_time,
                    standard.access_time
                ),
                (
                    expected.1.creation_time,
                    expected.1.modification_time,
                    expected.1.mft_change_time,
                    expected.1.access_time
                ),
                "timestamps for {path:?}"
            );
            assert_eq!(
                standard.file_attributes & 0xffff & !0x0410,
                expected.2,
                "attributes for {path:?}"
            );
            match path.first().map(String::as_str) {
                Some("junction") => {
                    assert!(object.is_directory);
                    assert_eq!(
                        object.reparse_point.as_deref(),
                        Some(source.junction_payload.as_slice())
                    );
                    listed_reparse.push(object.reference);
                }
                Some("link.lnk") => {
                    assert!(!object.is_directory);
                    assert_eq!(
                        object.reparse_point.as_deref(),
                        Some(source.symlink_payload.as_slice())
                    );
                    listed_reparse.push(object.reference);
                }
                _ => assert!(object.reparse_point.is_none()),
            }
        }
        assert_eq!(listed_reparse.len(), 2);
        assert_eq!(checked_objects, source.objects.len());

        // `$Extend\$Reparse:$R` lists exactly those two reparse points.
        let cluster = u64::from(restored_solved.destination.cluster_bytes);
        let record_offset =
            usize::try_from(restored_solved.destination.mft_lcn * cluster + 26 * 1024).unwrap();
        let record = crate::fs::ntfs_record::parse_file_record(
            &restored_bytes[record_offset..record_offset + 1024],
        )
        .unwrap();
        let attributes = crate::fs::ntfs_attribute::parse_attribute_list(
            record.repaired_bytes(),
            usize::from(record.attributes_offset),
            usize::try_from(record.bytes_in_use).unwrap(),
            crate::fs::ntfs_attribute::AttributeLimits {
                cluster_size_bytes: cluster,
                max_attribute_bytes: 1024,
                max_name_code_units: 255,
                max_attributes: 32,
            },
        )
        .unwrap();
        let r_name: Vec<u16> = "$R".encode_utf16().collect();
        let root = attributes
            .attributes
            .iter()
            .find(|attribute| {
                attribute.attribute_type == 0x90
                    && attribute
                        .name
                        .as_ref()
                        .is_some_and(|name| name.code_units == r_name)
            })
            .unwrap();
        let crate::fs::ntfs_attribute::AttributeBody::Resident(root) = &root.body else {
            panic!("resident $Reparse:$R");
        };
        let keys = parse_reparse_r_index_entries(&root.value[32..]).unwrap();
        let mut expected_keys: Vec<(u32, u64, u16)> = listed_reparse
            .iter()
            .map(|reference| {
                let object = restored
                    .preservation
                    .objects
                    .iter()
                    .find(|preserved| preserved.source.reference == *reference)
                    .unwrap();
                let tag = u32::from_le_bytes(
                    object.source.reparse_point.as_ref().unwrap()[..4]
                        .try_into()
                        .unwrap(),
                );
                (tag, reference.record_number, reference.sequence_number)
            })
            .collect();
        expected_keys.sort_unstable();
        let mut actual_keys: Vec<(u32, u64, u16)> = keys
            .iter()
            .map(|key| {
                (
                    key.reparse_tag,
                    key.file_reference & 0xffff_ffff_ffff,
                    u16::try_from(key.file_reference >> 48).unwrap(),
                )
            })
            .collect();
        actual_keys.sort_unstable();
        assert_eq!(actual_keys, expected_keys);

        // Binding: an edited exFAT image or a wrong-direction escrow is refused before restore.
        let mut edited = fs::read(&exfat_path).unwrap();
        let last = edited.len() - 1;
        edited[last] ^= 0x01;
        let edited_sha: [u8; 32] = Sha256::digest(&edited).into();
        assert!(matches!(
            decode_restore_sidecar(
                &escrow_bytes,
                edited_sha,
                CandidateExportLimits::default().max_escrow_bytes,
                PreservationLimits::default(),
            ),
            Err(NtfsRestoreError::CandidateBindingMismatch { .. })
        ));
        let restored_sha: [u8; 32] = Sha256::digest(&restored_bytes).into();
        assert!(matches!(
            decode_restore_sidecar(
                &fs::read(&ntfs_escrow_path).unwrap(),
                restored_sha,
                CandidateExportLimits::default().max_escrow_bytes,
                PreservationLimits::default(),
            ),
            Err(NtfsRestoreError::EscrowDirectionMismatch { .. })
        ));

        assert_eq!(fs::read(&source_file.path).unwrap(), source.image);
        for path in [exfat_path, exfat_escrow_path, ntfs_path, ntfs_escrow_path] {
            fs::remove_file(path).unwrap();
        }
    }

    /// Source NTFS image whose `data.bin` carries a `:big` stream one cluster above the inventory
    /// capture cap, so the escrow sidecar cannot hold its bytes.
    #[allow(clippy::too_many_lines)]
    fn ntfs_image_with_uncaptured_named_stream() -> (Vec<u8>, Vec<u8>) {
        const VOLUME_BYTES: u64 = 64 * 1024 * 1024;
        let ads_len = NtfsInventoryLimits::default().max_resident_data_bytes + 4096;
        let ads: Vec<u8> = (0..ads_len)
            .map(|index| u8::try_from((index * 7 + index / 4093) % 251).unwrap())
            .collect();
        let ads_bytes = u64::try_from(ads.len()).unwrap();
        let objects = vec![
            ObjectRecord {
                id: ObjectId(1),
                kind: ObjectKind::Directory,
                link_count: 0,
                semantics: ObjectSemantics::default(),
                streams: Vec::new(),
            },
            ObjectRecord {
                id: ObjectId(2),
                kind: ObjectKind::File,
                link_count: 1,
                semantics: ObjectSemantics::default(),
                streams: vec![
                    ObjectStream {
                        id: StreamId(2),
                        name: None,
                        logical_bytes: 3,
                        initialized_bytes: 3,
                        mapped_bytes: 3,
                        allocated_bytes: 0,
                        flags: StreamFlags::default(),
                        storage: StreamStorage::Resident(b"abc".to_vec()),
                    },
                    ObjectStream {
                        id: StreamId(3),
                        name: Some("big".encode_utf16().collect()),
                        logical_bytes: ads_bytes,
                        initialized_bytes: ads_bytes,
                        mapped_bytes: ads_bytes,
                        allocated_bytes: ads_bytes,
                        flags: StreamFlags::default(),
                        storage: StreamStorage::Extents,
                    },
                ],
            },
        ];
        let entries = vec![NamespaceEntry {
            parent: ObjectId(1),
            target: ObjectId(2),
            name: "data.bin".encode_utf16().collect(),
        }];
        for offset in (8 * 1024 * 1024..32 * 1024 * 1024).step_by(1024 * 1024) {
            let graph = ObjectGraph::build(
                ObjectId(1),
                objects.clone(),
                entries.clone(),
                ExtentGraph::build(
                    vec![Extent {
                        stream: StreamId(3),
                        logical_offset: 0,
                        length: ads_bytes,
                        placement: Placement::Physical {
                            byte_offset: offset,
                        },
                        kind: ExtentKind::FileData,
                    }],
                    VOLUME_BYTES,
                    4,
                )
                .unwrap(),
                ObjectGraphLimits {
                    max_objects: 4,
                    max_entries: 4,
                    max_streams: 4,
                    max_name_code_units: 255,
                },
            )
            .unwrap();
            let Ok(plan) = plan_ntfs_destination(
                &graph,
                NtfsDestinationInputs {
                    image_bytes: VOLUME_BYTES,
                    partition_offset_sectors: 0,
                    cluster_bytes: 4096,
                    volume_serial_number: 0x0bad_c0de_1234_5678,
                    timestamp: 0x01dc_0000_0000_0000,
                },
                NtfsSerializeLimits::default(),
            ) else {
                continue;
            };
            let mut image = vec![0_u8; usize::try_from(VOLUME_BYTES).unwrap()];
            let start = usize::try_from(offset).unwrap();
            image[start..start + ads.len()].copy_from_slice(&ads);
            for write in plan
                .staging_writes
                .iter()
                .chain(std::iter::once(&plan.backup_boot_write))
                .chain(std::iter::once(&plan.primary_boot_write))
            {
                let write_start = usize::try_from(write.offset).unwrap();
                image[write_start..write_start + write.bytes.len()].copy_from_slice(&write.bytes);
            }
            return (image, ads);
        }
        panic!("could not place the oversized named stream outside NTFS metadata");
    }

    fn graph_stream_bytes(
        graph: &ObjectGraph,
        image: &[u8],
        stream: &crate::object::ObjectStream,
    ) -> Vec<u8> {
        match &stream.storage {
            StreamStorage::Resident(bytes) => bytes.clone(),
            StreamStorage::Extents => {
                let mut extents: Vec<&Extent> = graph
                    .extents()
                    .extents()
                    .iter()
                    .filter(|extent| extent.stream == stream.id)
                    .collect();
                extents.sort_by_key(|extent| extent.logical_offset);
                let mut bytes = Vec::new();
                for extent in extents {
                    match extent.placement {
                        Placement::Physical { byte_offset } => {
                            let start = usize::try_from(byte_offset).unwrap();
                            let end = start + usize::try_from(extent.length).unwrap();
                            bytes.extend_from_slice(&image[start..end]);
                        }
                        Placement::Sparse => {
                            bytes.resize(bytes.len() + usize::try_from(extent.length).unwrap(), 0);
                        }
                    }
                }
                bytes.truncate(usize::try_from(stream.logical_bytes).unwrap());
                bytes
            }
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn escrow_round_trip_carries_uncaptured_named_stream_as_dest_native_file() {
        use crate::cross_format::draft_escrow_restored_exfat_to_ntfs;
        use crate::escrow_carrier::{carrier_directory_name, carrier_file_name};
        use crate::escrow_restore::decode_restore_sidecar;
        use crate::fs::ntfs_inventory::NtfsStreamStorage;
        use crate::preservation::PreservationLimits;

        let (source_bytes, ads) = ntfs_image_with_uncaptured_named_stream();
        let source_file = TempFile::create(&source_bytes);
        let source_image = ImageFile::open(&source_file.path).unwrap();
        let source_snapshot =
            capture_source_image_snapshot(&source_image, CandidateExportLimits::default()).unwrap();
        let inspection = inspect_open_image(&source_image).unwrap();
        let normalized = inspection.normalized_ntfs.as_deref().unwrap();
        let big_name: Vec<u16> = "big".encode_utf16().collect();
        let source_object = normalized
            .preservation
            .objects
            .iter()
            .find(|preserved| {
                preserved.source.data_streams.iter().any(|stream| {
                    stream.name.as_ref().map(|name| &name.code_units) == Some(&big_name)
                })
            })
            .expect("source file with :big");
        let big_stream = source_object
            .source
            .data_streams
            .iter()
            .find(|stream| stream.name.as_ref().map(|name| &name.code_units) == Some(&big_name))
            .unwrap();
        let NtfsStreamStorage::NonResident {
            captured_payload: None,
            data_bytes,
            ..
        } = &big_stream.storage
        else {
            panic!("the oversized named stream must be non-resident and uncaptured");
        };
        assert_eq!(*data_bytes, u64::try_from(ads.len()).unwrap());
        let expected_carrier_path = vec![
            carrier_directory_name(),
            carrier_file_name(source_object.object.0, big_stream.attribute_id),
        ];

        // Forward: NTFS -> exFAT with escrow; the ADS becomes a hidden+system carrier file.
        let draft = draft_lossless_ntfs_to_exfat(
            normalized,
            GuaranteeMode::Escrow,
            NtfsToExfatOptions::default(),
            NtfsToExfatLimits::default(),
        )
        .unwrap();
        let solved = solve_lossless_ntfs_to_exfat(draft, LayoutLimits::default()).unwrap();
        let preview = preview_exfat_phase_writes(
            &source_image,
            &solved.destination,
            PreimageLimits::default(),
        )
        .unwrap();
        let exfat_path = temp_path("carrier-round-trip.exfat.img");
        let exfat_escrow_path = temp_path("carrier-round-trip.exfat.escrow");
        export_relocated_candidate_image(
            &source_image,
            &exfat_path,
            Some(&exfat_escrow_path),
            &preview,
            &source_snapshot,
            solved.relocation(),
            &solved.preservation,
            CandidateExportLimits::default(),
        )
        .unwrap();
        verify_bound_export(
            &exfat_path,
            &exfat_escrow_path,
            Some(&source_file.path),
            CandidateVerificationLimits::default(),
        )
        .unwrap();

        let exfat_image = ImageFile::open(&exfat_path).unwrap();
        let exfat_snapshot =
            capture_source_image_snapshot(&exfat_image, CandidateExportLimits::default()).unwrap();
        let exfat_inspection = inspect_open_image(&exfat_image).unwrap();
        assert!(exfat_inspection.profile.inventory_complete);
        let normalized_exfat = exfat_inspection.normalized_exfat.as_deref().unwrap();
        let carrier = normalized_exfat
            .preservation
            .objects
            .iter()
            .find(|object| object.path == expected_carrier_path)
            .expect("dest-native carrier file");
        assert_eq!(
            carrier.file_attributes & 0x06,
            0x06,
            "carrier is hidden+system"
        );
        let directory = normalized_exfat
            .preservation
            .objects
            .iter()
            .find(|object| object.path == vec![carrier_directory_name()])
            .expect("escrow carrier directory");
        assert_eq!(directory.file_attributes & 0x16, 0x16);
        let exfat_bytes = fs::read(&exfat_path).unwrap();
        let carrier_object = normalized_exfat
            .graph
            .objects()
            .iter()
            .find(|object| object.id == carrier.object)
            .unwrap();
        assert_eq!(carrier_object.streams.len(), 1);
        assert_eq!(
            graph_stream_bytes(
                &normalized_exfat.graph,
                &exfat_bytes,
                &carrier_object.streams[0]
            ),
            ads,
            "carrier bytes equal the source named stream"
        );
        // The visible user namespace is unchanged apart from the reserved escrow directory.
        let mut root_names: Vec<String> = normalized_exfat
            .graph
            .entries()
            .iter()
            .filter(|entry| entry.parent == normalized_exfat.graph.root())
            .map(|entry| String::from_utf16(&entry.name).unwrap())
            .collect();
        root_names.sort_unstable();
        assert_eq!(root_names, [".starconverter-escrow", "data.bin"]);

        // Backward: the carrier folds back into `data.bin:big` and disappears from the namespace.
        let escrow_bytes = fs::read(&exfat_escrow_path).unwrap();
        let sidecar = decode_restore_sidecar(
            &escrow_bytes,
            exfat_snapshot.sha256(),
            CandidateExportLimits::default().max_escrow_bytes,
            PreservationLimits::default(),
        )
        .unwrap();
        let restored_draft = draft_escrow_restored_exfat_to_ntfs(
            normalized_exfat,
            &sidecar,
            GuaranteeMode::Escrow,
            ExfatToNtfsOptions::default(),
            ExfatToNtfsLimits::default(),
        )
        .unwrap();
        assert_eq!(restored_draft.target_graph().entries().len(), 1);
        assert_eq!(restored_draft.target_graph().objects().len(), 2);
        let restored_solved =
            solve_lossless_exfat_to_ntfs(restored_draft, LayoutLimits::default()).unwrap();
        let restored_preview = preview_ntfs_phase_writes(
            &exfat_image,
            &restored_solved.destination,
            PreimageLimits::default(),
        )
        .unwrap();
        let ntfs_path = temp_path("carrier-round-trip.restored.ntfs.img");
        let ntfs_escrow_path = temp_path("carrier-round-trip.restored.ntfs.escrow");
        export_relocated_candidate_image(
            &exfat_image,
            &ntfs_path,
            Some(&ntfs_escrow_path),
            &restored_preview,
            &exfat_snapshot,
            restored_solved.relocation(),
            &restored_solved.preservation,
            CandidateExportLimits::default(),
        )
        .unwrap();
        verify_bound_export(
            &ntfs_path,
            &ntfs_escrow_path,
            Some(&exfat_path),
            CandidateVerificationLimits::default(),
        )
        .unwrap();

        let restored_inspection = inspect_image(&ntfs_path).unwrap();
        assert!(restored_inspection.profile.inventory_complete);
        let restored = restored_inspection.normalized_ntfs.as_deref().unwrap();
        let names: Vec<String> = restored
            .graph
            .entries()
            .iter()
            .map(|entry| String::from_utf16(&entry.name).unwrap())
            .collect();
        assert_eq!(names, ["data.bin"]);
        let file = restored
            .graph
            .objects()
            .iter()
            .find(|object| object.kind == ObjectKind::File)
            .unwrap();
        assert_eq!(file.streams.len(), 2);
        let restored_bytes = fs::read(&ntfs_path).unwrap();
        let unnamed = file
            .streams
            .iter()
            .find(|stream| stream.name.is_none())
            .unwrap();
        assert_eq!(
            graph_stream_bytes(&restored.graph, &restored_bytes, unnamed),
            b"abc"
        );
        let big = file
            .streams
            .iter()
            .find(|stream| stream.name.as_deref() == Some(big_name.as_slice()))
            .expect("restored :big stream");
        assert_eq!(big.logical_bytes, u64::try_from(ads.len()).unwrap());
        assert_eq!(big.storage, StreamStorage::Extents);
        assert_eq!(
            graph_stream_bytes(&restored.graph, &restored_bytes, big),
            ads,
            "restored named stream bytes equal the source"
        );

        assert_eq!(fs::read(&source_file.path).unwrap(), source_bytes);
        for path in [exfat_path, exfat_escrow_path, ntfs_path, ntfs_escrow_path] {
            fs::remove_file(path).unwrap();
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn escrow_ntfs_directory_hard_links_and_nonresident_ads_export_dest_native_exfat() {
        let (source_bytes, payload) = ntfs_image_with_directory_hard_links_and_nonresident_ads();
        let source_file = TempFile::create(&source_bytes);
        let source = ImageFile::open(&source_file.path).unwrap();
        let source_snapshot =
            capture_source_image_snapshot(&source, CandidateExportLimits::default()).unwrap();
        let inspection = inspect_open_image(&source).unwrap();
        let normalized = inspection.normalized_ntfs.as_deref().unwrap();
        assert!(
            normalized
                .graph
                .objects()
                .iter()
                .any(|object| object.kind == ObjectKind::Directory && object.link_count == 2)
        );
        let file = normalized
            .graph
            .objects()
            .iter()
            .find(|object| object.kind == ObjectKind::File)
            .unwrap();
        assert_eq!(file.link_count, 2);
        assert_eq!(file.streams.len(), 2);
        assert!(file.streams.iter().any(
            |stream| stream.name.is_some() && matches!(stream.storage, StreamStorage::Extents)
        ));
        assert!(
            !evaluate_ntfs(
                normalized,
                FileSystem::ExFat,
                GuaranteeMode::Strict,
                crate::preservation::PreservationLimits::default(),
            )
            .unwrap()
            .permitted
        );
        let draft = draft_lossless_ntfs_to_exfat(
            normalized,
            GuaranteeMode::Escrow,
            NtfsToExfatOptions {
                bytes_per_cluster: 8192,
                ..NtfsToExfatOptions::default()
            },
            NtfsToExfatLimits::default(),
        )
        .unwrap();
        let solved = solve_lossless_ntfs_to_exfat(draft, LayoutLimits::default()).unwrap();
        let dest_entries: Vec<(u64, Vec<u16>)> = solved
            .target_graph()
            .entries()
            .iter()
            .map(|entry| (entry.parent.0, entry.name.clone()))
            .collect();
        assert_eq!(
            dest_entries,
            vec![
                (5, "left".encode_utf16().collect()),
                (5, "other".encode_utf16().collect()),
                (27, "shared.bin".encode_utf16().collect()),
            ]
        );
        let dest_file = solved
            .target_graph()
            .objects()
            .iter()
            .find(|object| object.kind == ObjectKind::File)
            .unwrap();
        assert_eq!(dest_file.link_count, 1);
        assert_eq!(dest_file.streams.len(), 1);
        assert!(dest_file.streams[0].name.is_none());
        assert!(
            solved
                .target_graph()
                .objects()
                .iter()
                .filter(|object| object.kind == ObjectKind::Directory && object.id.0 != 5)
                .all(|object| object.link_count == 1)
        );
        let destination_range = solved.layout().materializations[0].destination;
        let preview =
            preview_exfat_phase_writes(&source, &solved.destination, PreimageLimits::default())
                .unwrap();
        let destination = temp_path("dir-hardlink-ads-candidate.exfat.img");
        let escrow = temp_path("dir-hardlink-ads-candidate.escrow");
        export_relocated_candidate_image(
            &source,
            &destination,
            Some(&escrow),
            &preview,
            &source_snapshot,
            solved.relocation(),
            &solved.preservation,
            CandidateExportLimits::default(),
        )
        .unwrap();
        let candidate_bytes = fs::read(&destination).unwrap();
        let start = usize::try_from(destination_range.offset).unwrap();
        assert_eq!(&candidate_bytes[start..start + payload.len()], payload);
        verify_bound_export(
            &destination,
            &escrow,
            Some(&source_file.path),
            CandidateVerificationLimits::default(),
        )
        .unwrap();
        assert_eq!(fs::read(&source_file.path).unwrap(), source_bytes);
        fs::remove_file(destination).unwrap();
        fs::remove_file(escrow).unwrap();
    }

    #[test]
    fn fragmented_ntfs_runs_are_repacked_into_exfat_clusters() {
        let (source_bytes, payload) = ntfs_image_with_two_4k_fragments();
        let source_file = TempFile::create(&source_bytes);
        let source = ImageFile::open(&source_file.path).unwrap();
        let source_snapshot =
            capture_source_image_snapshot(&source, CandidateExportLimits::default()).unwrap();
        let inspection = inspect_open_image(&source).unwrap();
        let normalized = inspection.normalized_ntfs.as_deref().unwrap();
        let draft = draft_lossless_ntfs_to_exfat(
            normalized,
            GuaranteeMode::Escrow,
            NtfsToExfatOptions {
                bytes_per_cluster: 8192,
                ..NtfsToExfatOptions::default()
            },
            NtfsToExfatLimits::default(),
        )
        .unwrap();
        let solved = solve_lossless_ntfs_to_exfat(draft, LayoutLimits::default()).unwrap();
        assert!(solved.layout().relocations.is_empty());
        assert_eq!(solved.layout().materializations.len(), 1);
        let destination_range = solved.layout().materializations[0].destination;
        assert_eq!(destination_range.length, 8192);
        let preview =
            preview_exfat_phase_writes(&source, &solved.destination, PreimageLimits::default())
                .unwrap();
        let destination = temp_path("repacked-candidate.exfat.img");
        let escrow = temp_path("repacked-candidate.escrow");
        export_relocated_candidate_image(
            &source,
            &destination,
            Some(&escrow),
            &preview,
            &source_snapshot,
            solved.relocation(),
            &solved.preservation,
            CandidateExportLimits::default(),
        )
        .unwrap();
        let candidate_bytes = fs::read(&destination).unwrap();
        let start = usize::try_from(destination_range.offset).unwrap();
        assert_eq!(&candidate_bytes[start..start + payload.len()], payload);
        let candidate = inspect_image(&destination).unwrap();
        assert!(candidate.profile.inventory_complete);
        verify_bound_export(
            &destination,
            &escrow,
            Some(&source_file.path),
            CandidateVerificationLimits::default(),
        )
        .unwrap();
        assert_eq!(fs::read(&source_file.path).unwrap(), source_bytes);
        fs::remove_file(destination).unwrap();
        fs::remove_file(escrow).unwrap();
    }

    #[test]
    fn uninitialized_ntfs_fragment_tail_is_zeroed_when_materialized() {
        let (source_bytes, initialized) = ntfs_image_with_partially_initialized_fragments();
        let source_file = TempFile::create(&source_bytes);
        let source = ImageFile::open(&source_file.path).unwrap();
        let source_snapshot =
            capture_source_image_snapshot(&source, CandidateExportLimits::default()).unwrap();
        let inspection = inspect_open_image(&source).unwrap();
        let normalized = inspection.normalized_ntfs.as_deref().unwrap();
        let stream = normalized
            .graph
            .objects()
            .iter()
            .find(|object| object.kind == ObjectKind::File)
            .unwrap()
            .streams
            .first()
            .unwrap();
        assert_eq!(stream.initialized_bytes, 5000);
        assert_eq!(stream.logical_bytes, 8192);
        let draft = draft_lossless_ntfs_to_exfat(
            normalized,
            GuaranteeMode::Escrow,
            NtfsToExfatOptions {
                bytes_per_cluster: 8192,
                ..NtfsToExfatOptions::default()
            },
            NtfsToExfatLimits::default(),
        )
        .unwrap();
        let solved = solve_lossless_ntfs_to_exfat(draft, LayoutLimits::default()).unwrap();
        assert!(solved.layout().relocations.is_empty());
        assert_eq!(solved.layout().materializations.len(), 1);
        let destination_range = solved.layout().materializations[0].destination;
        let preview =
            preview_exfat_phase_writes(&source, &solved.destination, PreimageLimits::default())
                .unwrap();
        let destination = temp_path("partial-init-candidate.exfat.img");
        let escrow = temp_path("partial-init-candidate.escrow");
        export_relocated_candidate_image(
            &source,
            &destination,
            Some(&escrow),
            &preview,
            &source_snapshot,
            solved.relocation(),
            &solved.preservation,
            CandidateExportLimits::default(),
        )
        .unwrap();
        let candidate_bytes = fs::read(&destination).unwrap();
        let start = usize::try_from(destination_range.offset).unwrap();
        assert_eq!(
            &candidate_bytes[start..start + initialized.len()],
            initialized.as_slice()
        );
        assert!(
            candidate_bytes[start + initialized.len()..start + 8192]
                .iter()
                .all(|byte| *byte == 0),
            "uninitialized source slack must not be copied into the destination"
        );
        let candidate = inspect_image(&destination).unwrap();
        let dest_stream = candidate
            .normalized_exfat
            .as_deref()
            .unwrap()
            .graph
            .objects()
            .iter()
            .find(|object| object.kind == ObjectKind::File)
            .unwrap()
            .streams
            .first()
            .unwrap();
        assert_eq!(dest_stream.initialized_bytes, 5000);
        assert_eq!(dest_stream.logical_bytes, 8192);
        verify_bound_export(
            &destination,
            &escrow,
            Some(&source_file.path),
            CandidateVerificationLimits::default(),
        )
        .unwrap();
        assert_eq!(fs::read(&source_file.path).unwrap(), source_bytes);
        fs::remove_file(destination).unwrap();
        fs::remove_file(escrow).unwrap();
    }

    #[test]
    fn dest_aligned_uninitialized_ntfs_payload_is_materialized_and_zeroed() {
        let (source_bytes, initialized, source_offset) =
            ntfs_image_with_aligned_uninitialized_payload();
        assert_eq!(source_offset % 8192, 0);
        let source_file = TempFile::create(&source_bytes);
        let source = ImageFile::open(&source_file.path).unwrap();
        let source_snapshot =
            capture_source_image_snapshot(&source, CandidateExportLimits::default()).unwrap();
        let inspection = inspect_open_image(&source).unwrap();
        let normalized = inspection.normalized_ntfs.as_deref().unwrap();
        let file_data: Vec<_> = normalized
            .graph
            .extents()
            .extents()
            .iter()
            .filter(|extent| extent.kind == ExtentKind::FileData)
            .collect();
        assert_eq!(file_data.len(), 1);
        assert_eq!(file_data[0].length, 8192);
        assert_eq!(
            file_data[0].placement,
            Placement::Physical {
                byte_offset: source_offset
            }
        );
        let stream = normalized
            .graph
            .objects()
            .iter()
            .find(|object| object.kind == ObjectKind::File)
            .unwrap()
            .streams
            .first()
            .unwrap();
        assert_eq!(stream.initialized_bytes, 5000);
        assert_eq!(stream.logical_bytes, 8192);
        let draft = draft_lossless_ntfs_to_exfat(
            normalized,
            GuaranteeMode::Escrow,
            NtfsToExfatOptions {
                bytes_per_cluster: 8192,
                ..NtfsToExfatOptions::default()
            },
            NtfsToExfatLimits::default(),
        )
        .unwrap();
        let solved = solve_lossless_ntfs_to_exfat(draft, LayoutLimits::default()).unwrap();
        assert!(solved.layout().relocations.is_empty());
        assert_eq!(solved.layout().materializations.len(), 1);
        let destination_range = solved.layout().materializations[0].destination;
        assert_eq!(destination_range.length, 8192);
        assert_eq!(destination_range.offset % 8192, 0);
        let preview =
            preview_exfat_phase_writes(&source, &solved.destination, PreimageLimits::default())
                .unwrap();
        let destination = temp_path("aligned-partial-init-candidate.exfat.img");
        let escrow = temp_path("aligned-partial-init-candidate.escrow");
        export_relocated_candidate_image(
            &source,
            &destination,
            Some(&escrow),
            &preview,
            &source_snapshot,
            solved.relocation(),
            &solved.preservation,
            CandidateExportLimits::default(),
        )
        .unwrap();
        let candidate_bytes = fs::read(&destination).unwrap();
        let start = usize::try_from(destination_range.offset).unwrap();
        assert_eq!(
            &candidate_bytes[start..start + initialized.len()],
            initialized.as_slice()
        );
        assert!(
            candidate_bytes[start + initialized.len()..start + 8192]
                .iter()
                .all(|byte| *byte == 0),
            "uninitialized source slack must not be copied into a dest-aligned cluster"
        );
        verify_bound_export(
            &destination,
            &escrow,
            Some(&source_file.path),
            CandidateVerificationLimits::default(),
        )
        .unwrap();
        assert_eq!(fs::read(&source_file.path).unwrap(), source_bytes);
        fs::remove_file(destination).unwrap();
        fs::remove_file(escrow).unwrap();
    }

    #[test]
    fn mixed_relocation_and_resident_materialization_export_to_exfat() {
        let (source_bytes, relocated_payload, resident_payload, source_offset) =
            ntfs_image_with_misaligned_and_resident_payloads();
        let source_file = TempFile::create(&source_bytes);
        let source = ImageFile::open(&source_file.path).unwrap();
        let source_snapshot =
            capture_source_image_snapshot(&source, CandidateExportLimits::default()).unwrap();
        let inspection = inspect_open_image(&source).unwrap();
        let normalized = inspection.normalized_ntfs.as_deref().unwrap();
        let draft = draft_lossless_ntfs_to_exfat(
            normalized,
            GuaranteeMode::Escrow,
            NtfsToExfatOptions {
                bytes_per_cluster: 8192,
                ..NtfsToExfatOptions::default()
            },
            NtfsToExfatLimits::default(),
        )
        .unwrap();
        let solved = solve_lossless_ntfs_to_exfat(draft, LayoutLimits::default()).unwrap();
        assert_eq!(solved.layout().relocations.len(), 1);
        assert_eq!(solved.layout().materializations.len(), 1);
        let relocation = solved.layout().relocations[0];
        let materialization = solved.layout().materializations[0];
        assert_eq!(relocation.source.offset, source_offset);
        assert_eq!(relocation.destination.offset % 8192, 0);
        assert_eq!(materialization.destination.length, 8192);
        let payload_total = solved.layout().relocated_bytes + solved.layout().materialized_bytes;
        let preview =
            preview_exfat_phase_writes(&source, &solved.destination, PreimageLimits::default())
                .unwrap();
        let destination = temp_path("mixed-candidate.exfat.img");
        let escrow = temp_path("mixed-candidate.escrow");
        let mut last_payload_progress = None;
        export_relocated_candidate_image_with_progress(
            &source,
            &destination,
            Some(&escrow),
            &preview,
            &source_snapshot,
            solved.relocation(),
            &solved.preservation,
            CandidateExportLimits::default(),
            |progress| {
                if progress.phase == CandidateWorkPhase::RelocatePayload {
                    if let Some((completed, total)) = last_payload_progress {
                        assert!(progress.completed_bytes >= completed);
                        assert_eq!(progress.total_bytes, total);
                    }
                    last_payload_progress = Some((progress.completed_bytes, progress.total_bytes));
                }
                CandidateWorkControl::Continue
            },
        )
        .unwrap();
        assert_eq!(
            last_payload_progress,
            Some((payload_total, Some(payload_total)))
        );
        let candidate_bytes = fs::read(&destination).unwrap();
        let relocated_start = usize::try_from(relocation.destination.offset).unwrap();
        assert_eq!(
            &candidate_bytes[relocated_start..relocated_start + relocated_payload.len()],
            relocated_payload.as_slice()
        );
        let materialized_start = usize::try_from(materialization.destination.offset).unwrap();
        assert_eq!(
            &candidate_bytes[materialized_start..materialized_start + resident_payload.len()],
            resident_payload.as_slice()
        );
        assert!(
            candidate_bytes[materialized_start + resident_payload.len()..materialized_start + 8192]
                .iter()
                .all(|byte| *byte == 0)
        );
        verify_bound_export(
            &destination,
            &escrow,
            Some(&source_file.path),
            CandidateVerificationLimits::default(),
        )
        .unwrap();
        assert_eq!(fs::read(&source_file.path).unwrap(), source_bytes);
        fs::remove_file(destination).unwrap();
        fs::remove_file(escrow).unwrap();
    }

    #[test]
    fn fragmented_exfat_runs_are_repacked_into_ntfs_clusters() {
        let (source_bytes, payload) = exfat_image_with_two_4k_fragments();
        let source_file = TempFile::create(&source_bytes);
        let source = ImageFile::open(&source_file.path).unwrap();
        let source_snapshot =
            capture_source_image_snapshot(&source, CandidateExportLimits::default()).unwrap();
        let inspection = inspect_open_image(&source).unwrap();
        let normalized = inspection.normalized_exfat.as_deref().unwrap();
        let draft = draft_lossless_exfat_to_ntfs(
            normalized,
            GuaranteeMode::Escrow,
            ExfatToNtfsOptions {
                cluster_bytes: 8192,
                ..ExfatToNtfsOptions::default()
            },
            ExfatToNtfsLimits::default(),
        )
        .unwrap();
        let solved = solve_lossless_exfat_to_ntfs(draft, LayoutLimits::default()).unwrap();
        assert!(solved.layout().relocations.is_empty());
        assert_eq!(solved.layout().materializations.len(), 1);
        let destination_range = solved.layout().materializations[0].destination;
        assert_eq!(destination_range.length, 8192);
        assert_eq!(destination_range.offset % 8192, 0);
        let preview =
            preview_ntfs_phase_writes(&source, &solved.destination, PreimageLimits::default())
                .unwrap();
        let destination = temp_path("repacked-candidate.ntfs.img");
        let escrow = temp_path("repacked-ntfs-candidate.escrow");
        export_relocated_candidate_image(
            &source,
            &destination,
            Some(&escrow),
            &preview,
            &source_snapshot,
            solved.relocation(),
            &solved.preservation,
            CandidateExportLimits::default(),
        )
        .unwrap();
        let candidate_bytes = fs::read(&destination).unwrap();
        let start = usize::try_from(destination_range.offset).unwrap();
        assert_eq!(&candidate_bytes[start..start + payload.len()], payload);
        let candidate = inspect_image(&destination).unwrap();
        assert_eq!(candidate.profile.filesystem, FileSystem::Ntfs);
        assert!(candidate.profile.inventory_complete);
        verify_bound_export(
            &destination,
            &escrow,
            Some(&source_file.path),
            CandidateVerificationLimits::default(),
        )
        .unwrap();
        assert_eq!(fs::read(&source_file.path).unwrap(), source_bytes);
        fs::remove_file(destination).unwrap();
        fs::remove_file(escrow).unwrap();
    }

    #[test]
    fn dest_aligned_uninitialized_exfat_payload_is_materialized_and_zeroed() {
        let (source_bytes, initialized) = exfat_image_with_aligned_uninitialized_payload();
        let source_file = TempFile::create(&source_bytes);
        let source = ImageFile::open(&source_file.path).unwrap();
        let source_snapshot =
            capture_source_image_snapshot(&source, CandidateExportLimits::default()).unwrap();
        let inspection = inspect_open_image(&source).unwrap();
        let normalized = inspection.normalized_exfat.as_deref().unwrap();
        let file_data: Vec<_> = normalized
            .graph
            .extents()
            .extents()
            .iter()
            .filter(|extent| extent.kind == ExtentKind::FileData)
            .collect();
        assert_eq!(file_data.len(), 1);
        assert_eq!(file_data[0].length, 4096);
        let stream = normalized
            .graph
            .objects()
            .iter()
            .find(|object| object.kind == ObjectKind::File)
            .unwrap()
            .streams
            .first()
            .unwrap();
        assert_eq!(stream.initialized_bytes, 1000);
        assert_eq!(stream.logical_bytes, 4096);
        let draft = draft_lossless_exfat_to_ntfs(
            normalized,
            GuaranteeMode::Escrow,
            ExfatToNtfsOptions {
                cluster_bytes: 4096,
                ..ExfatToNtfsOptions::default()
            },
            ExfatToNtfsLimits::default(),
        )
        .unwrap();
        let solved = solve_lossless_exfat_to_ntfs(draft, LayoutLimits::default()).unwrap();
        assert!(solved.layout().relocations.is_empty());
        assert_eq!(solved.layout().materializations.len(), 1);
        let destination_range = solved.layout().materializations[0].destination;
        assert_eq!(destination_range.length, 4096);
        let preview =
            preview_ntfs_phase_writes(&source, &solved.destination, PreimageLimits::default())
                .unwrap();
        let destination = temp_path("aligned-partial-init-candidate.ntfs.img");
        let escrow = temp_path("aligned-partial-init-candidate.ntfs.escrow");
        export_relocated_candidate_image(
            &source,
            &destination,
            Some(&escrow),
            &preview,
            &source_snapshot,
            solved.relocation(),
            &solved.preservation,
            CandidateExportLimits::default(),
        )
        .unwrap();
        let candidate_bytes = fs::read(&destination).unwrap();
        let start = usize::try_from(destination_range.offset).unwrap();
        assert_eq!(
            &candidate_bytes[start..start + initialized.len()],
            initialized.as_slice()
        );
        assert!(
            candidate_bytes[start + initialized.len()..start + 4096]
                .iter()
                .all(|byte| *byte == 0),
            "uninitialized exFAT slack must not be copied into dest-aligned NTFS clusters"
        );
        verify_bound_export(
            &destination,
            &escrow,
            Some(&source_file.path),
            CandidateVerificationLimits::default(),
        )
        .unwrap();
        assert_eq!(fs::read(&source_file.path).unwrap(), source_bytes);
        fs::remove_file(destination).unwrap();
        fs::remove_file(escrow).unwrap();
    }

    #[test]
    fn payload_edit_after_snapshot_is_refused_before_candidate_creation() {
        let (source_bytes, _, source_offset) = ntfs_image_with_payload_misaligned_for_8k_exfat();
        let source_file = TempFile::create(&source_bytes);
        let source = ImageFile::open(&source_file.path).unwrap();
        let source_snapshot =
            capture_source_image_snapshot(&source, CandidateExportLimits::default()).unwrap();
        let inspection = inspect_open_image(&source).unwrap();
        let normalized = inspection.normalized_ntfs.as_deref().unwrap();
        let draft = draft_lossless_ntfs_to_exfat(
            normalized,
            GuaranteeMode::Escrow,
            NtfsToExfatOptions {
                bytes_per_cluster: 8192,
                ..NtfsToExfatOptions::default()
            },
            NtfsToExfatLimits::default(),
        )
        .unwrap();
        let solved = solve_lossless_ntfs_to_exfat(draft, LayoutLimits::default()).unwrap();
        let preview =
            preview_exfat_phase_writes(&source, &solved.destination, PreimageLimits::default())
                .unwrap();

        let mut writer = OpenOptions::new()
            .write(true)
            .open(&source_file.path)
            .unwrap();
        writer.seek(SeekFrom::Start(source_offset)).unwrap();
        writer
            .write_all(&[source_bytes[usize::try_from(source_offset).unwrap()] ^ 0xff])
            .unwrap();
        writer.sync_all().unwrap();
        writer
            .set_times(fs::FileTimes::new().set_modified(source.identity().modified().unwrap()))
            .unwrap();
        drop(writer);

        let destination = temp_path("stale-plan-candidate.exfat.img");
        let escrow = temp_path("stale-plan-candidate.escrow");
        let error = export_relocated_candidate_image(
            &source,
            &destination,
            Some(&escrow),
            &preview,
            &source_snapshot,
            solved.relocation(),
            &solved.preservation,
            CandidateExportLimits::default(),
        )
        .unwrap_err();
        assert!(
            matches!(error, CandidateExportError::SourceChangedSincePlanning),
            "unexpected stale-plan error: {error:?}"
        );
        assert!(!destination.exists());
        assert!(!escrow.exists());
    }

    #[test]
    fn cancellation_during_copy_cleans_private_partial_and_preserves_source() {
        let bytes = vec![b'x'; 1536];
        let source_file = TempFile::create(&bytes);
        let source = ImageFile::open_with_limit(&source_file.path, 512).unwrap();
        let destination = temp_path("cancelled-candidate.img");
        let partial;
        {
            let mut guard = NewFileGuard::create_partial(&destination).unwrap();
            partial = guard.path.clone();
            let error =
                copy_source_with_progress(&source, guard.file_mut(), 512, &mut |progress| {
                    if progress.completed_bytes >= 512 {
                        CandidateWorkControl::Cancel
                    } else {
                        CandidateWorkControl::Continue
                    }
                })
                .unwrap_err();
            assert!(matches!(
                error,
                CandidateExportError::Cancelled {
                    phase: CandidateWorkPhase::CopySource
                }
            ));
        }
        assert!(!destination.exists());
        assert!(!partial.exists());
        assert_eq!(fs::read(&source_file.path).unwrap(), bytes);
    }

    #[test]
    fn byte_progress_is_monotonic_bounded_and_finishes_at_total() {
        let bytes = vec![b'z'; 1537];
        let source_file = TempFile::create(&bytes);
        let source = ImageFile::open_with_limit(&source_file.path, 512).unwrap();
        let mut snapshots = Vec::new();
        let digest = hash_image_with_progress(
            &source,
            512,
            CandidateWorkPhase::HashSourceBefore,
            &mut |progress| {
                snapshots.push(progress);
                CandidateWorkControl::Continue
            },
        )
        .unwrap();
        assert_eq!(digest, Sha256::digest(&bytes)[..]);
        assert!(snapshots.windows(2).all(|pair| {
            pair[0].phase == pair[1].phase && pair[0].completed_bytes <= pair[1].completed_bytes
        }));
        assert!(snapshots.iter().all(|progress| {
            progress.total_bytes == Some(bytes.len() as u64)
                && progress.completed_bytes <= bytes.len() as u64
                && progress.cancellable
        }));
        assert_eq!(
            snapshots.last().unwrap().completed_bytes,
            bytes.len() as u64
        );
    }

    #[test]
    fn non_cancellable_publication_ignores_late_cancel_action() {
        let mut observed = None;
        report_non_cancellable(
            &mut |progress| {
                observed = Some(progress);
                CandidateWorkControl::Cancel
            },
            CandidateWorkPhase::PublishArtifacts,
            0,
            None,
        );
        assert_eq!(
            observed,
            Some(CandidateWorkProgress {
                phase: CandidateWorkPhase::PublishArtifacts,
                completed_bytes: 0,
                total_bytes: None,
                cancellable: false,
            })
        );
    }

    #[test]
    fn end_to_end_cancel_before_publication_never_exposes_destination() {
        let source_file = TempFile::create(&minimal_exfat_image());
        let source_before = fs::read(&source_file.path).unwrap();
        let source = ImageFile::open(&source_file.path).unwrap();
        let inspection = inspect_open_image(&source).unwrap();
        let normalized = inspection.normalized_exfat.as_deref().unwrap();
        let plan = plan_lossless_exfat_to_ntfs(
            normalized,
            GuaranteeMode::Escrow,
            ExfatToNtfsOptions::default(),
            ExfatToNtfsLimits::default(),
        )
        .unwrap();
        let preview =
            preview_ntfs_phase_writes(&source, &plan.destination, PreimageLimits::default())
                .unwrap();
        let destination = temp_path("cancelled-before-publication.img");
        let escrow = temp_path("cancelled-before-publication.escrow");

        let error = export_candidate_image_with_progress(
            &source,
            &destination,
            Some(&escrow),
            &preview,
            &plan.target_graph,
            &plan.preservation,
            CandidateExportLimits::default(),
            |progress| {
                if progress.phase == CandidateWorkPhase::ReadyToPublish {
                    CandidateWorkControl::Cancel
                } else {
                    CandidateWorkControl::Continue
                }
            },
        )
        .unwrap_err();
        assert!(matches!(
            error,
            CandidateExportError::Cancelled {
                phase: CandidateWorkPhase::ReadyToPublish
            }
        ));
        assert!(!destination.exists());
        assert!(!escrow.exists());
        assert_eq!(fs::read(&source_file.path).unwrap(), source_before);
    }

    #[test]
    fn end_to_end_late_cancel_during_publication_reports_real_success() {
        let source_file = TempFile::create(&minimal_exfat_image());
        let source_before = fs::read(&source_file.path).unwrap();
        let source = ImageFile::open(&source_file.path).unwrap();
        let inspection = inspect_open_image(&source).unwrap();
        let normalized = inspection.normalized_exfat.as_deref().unwrap();
        let plan = plan_lossless_exfat_to_ntfs(
            normalized,
            GuaranteeMode::Escrow,
            ExfatToNtfsOptions::default(),
            ExfatToNtfsLimits::default(),
        )
        .unwrap();
        let preview =
            preview_ntfs_phase_writes(&source, &plan.destination, PreimageLimits::default())
                .unwrap();
        let destination = temp_path("late-cancel-published.img");
        let escrow = temp_path("late-cancel-published.escrow");
        let mut saw_non_cancellable = false;

        let evidence = export_candidate_image_with_progress(
            &source,
            &destination,
            Some(&escrow),
            &preview,
            &plan.target_graph,
            &plan.preservation,
            CandidateExportLimits::default(),
            |progress| {
                if progress.phase == CandidateWorkPhase::PublishArtifacts {
                    saw_non_cancellable = !progress.cancellable;
                    CandidateWorkControl::Cancel
                } else {
                    CandidateWorkControl::Continue
                }
            },
        )
        .unwrap();
        assert!(saw_non_cancellable);
        assert_eq!(
            evidence.output_path,
            fs::canonicalize(&destination).unwrap()
        );
        assert!(destination.exists());
        assert_eq!(
            evidence.escrow_path,
            Some(fs::canonicalize(&escrow).unwrap())
        );
        assert!(escrow.exists());
        assert_eq!(fs::read(&source_file.path).unwrap(), source_before);
        fs::remove_file(destination).unwrap();
        fs::remove_file(escrow).unwrap();
    }

    #[test]
    fn directory_durability_has_stable_user_facing_labels() {
        assert_eq!(
            DirectoryDurability::Synchronized.to_string(),
            "synchronized"
        );
        assert_eq!(DirectoryDurability::Unsupported.to_string(), "unsupported");
        assert!(DirectoryDurability::Synchronized.is_synchronized());
        assert!(!DirectoryDurability::Unsupported.is_synchronized());
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
    fn cancelling_bound_verification_never_changes_artifacts() {
        let candidate_file = TempFile::create(&minimal_exfat_image());
        let candidate = ImageFile::open(&candidate_file.path).unwrap();
        let inspection = inspect_open_image(&candidate).unwrap();
        let graph = normalized_graph(&inspection, FileSystem::ExFat).unwrap();
        let manifest = build_manifest(&candidate, graph, VerificationLimits::default()).unwrap();
        let candidate_sha256 = hash_image(&candidate, 64 * 1024).unwrap();
        let envelope = encode_bound_escrow(
            FileSystem::Ntfs,
            FileSystem::ExFat,
            [0x5a; 32],
            candidate_sha256,
            manifest.metadata_sha256,
            &test_ntfs_escrow_payload(),
        )
        .unwrap();
        let escrow_file = TempFile::create(&envelope);
        let candidate_before = fs::read(&candidate_file.path).unwrap();
        let escrow_before = fs::read(&escrow_file.path).unwrap();

        let error = verify_bound_export_with_progress(
            &candidate_file.path,
            &escrow_file.path,
            None,
            CandidateVerificationLimits::default(),
            |progress| {
                if progress.phase == CandidateWorkPhase::HashVerificationCandidate {
                    CandidateWorkControl::Cancel
                } else {
                    CandidateWorkControl::Continue
                }
            },
        )
        .unwrap_err();
        assert!(matches!(
            error,
            CandidateExportError::Cancelled {
                phase: CandidateWorkPhase::HashVerificationCandidate
            }
        ));
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
    fn windows_publication_never_claims_an_unavailable_parent_barrier() {
        let destination = temp_path("windows-durability-boundary.img");
        let mut guard = NewFileGuard::create_partial(&destination).unwrap();
        guard.file_mut().write_all(b"verified").unwrap();
        guard.file().sync_all().unwrap();
        guard.bind_current_identity().unwrap();

        let durability = guard.publish(&destination).unwrap();

        assert_eq!(durability, DirectoryDurability::Unsupported);
        assert!(!durability.is_synchronized());
        assert_eq!(fs::read(&destination).unwrap(), b"verified");
        fs::remove_file(destination).unwrap();
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
