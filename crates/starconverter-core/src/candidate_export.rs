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
use crate::image::{ImageError, ImageFile, reject_device_like_path};
use crate::inspect::{InspectionError, inspect_image};
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

/// Evidence returned only after the new candidate and optional escrow are durable and reinspected.
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
    TargetInspectionMismatch,
    Verification(VerificationError),
    ManifestMismatch,
    SourceChangedAfterExport,
}

impl fmt::Display for CandidateExportError {
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
                write!(formatter, "candidate reinspection failed: {source}")
            }
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
        }
    }
}

impl std::error::Error for CandidateExportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
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

/// Decodes and authenticates a candidate-bound escrow sidecar.
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

    let (manifest_sha256, candidate_sha256) = verify_candidate(
        &output_guard.path,
        preview.target_filesystem(),
        &expected_manifest,
        limits,
    )?;

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
            Some(guard)
        } else {
            None
        };

    if let (Some(guard), Some(path)) = (escrow_guard, escrow.as_deref()) {
        guard.publish(path)?;
    }
    if let Err(error) = output_guard.publish(&output) {
        if let Some(path) = &escrow {
            let _ = fs::remove_file(path);
        }
        return Err(error);
    }
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
    })
}

fn verify_candidate(
    path: &Path,
    target_filesystem: FileSystem,
    expected_manifest: &VerificationManifest,
    limits: CandidateExportLimits,
) -> Result<([u8; 32], [u8; 32]), CandidateExportError> {
    let candidate = ImageFile::open(path)?;
    let inspection = inspect_image(path)?;
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
    Ok((
        actual_manifest.metadata_sha256,
        hash_image(&candidate, limits.copy_chunk_bytes)?,
    ))
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
    file: File,
    keep: std::cell::Cell<bool>,
}

impl NewFileGuard {
    fn create(path: &Path) -> Result<Self, CandidateExportError> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|source| CandidateExportError::io("create new output", source))?;
        let guard = Self {
            path: path.to_path_buf(),
            file,
            keep: std::cell::Cell::new(false),
        };
        let metadata = guard
            .file
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
        let file_name = destination
            .file_name()
            .ok_or_else(|| CandidateExportError::OutputHasNoFileName(destination.to_path_buf()))?;
        let parent = destination.parent().unwrap_or_else(|| Path::new("."));
        for _ in 0..128 {
            let sequence = NEXT_PARTIAL.fetch_add(1, Ordering::Relaxed);
            let mut partial_name = file_name.to_os_string();
            partial_name.push(format!(
                ".starconverter-partial-{}-{sequence}",
                std::process::id()
            ));
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
        &self.file
    }

    const fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    fn keep(&self) {
        self.keep.set(true);
    }

    fn publish(&self, destination: &Path) -> Result<(), CandidateExportError> {
        if destination.exists() {
            return Err(CandidateExportError::OutputExists(
                destination.to_path_buf(),
            ));
        }

        #[cfg(windows)]
        fs::rename(&self.path, destination).map_err(|source| {
            if source.kind() == io::ErrorKind::AlreadyExists {
                CandidateExportError::OutputExists(destination.to_path_buf())
            } else {
                CandidateExportError::io("publish verified output", source)
            }
        })?;

        #[cfg(not(windows))]
        {
            fs::hard_link(&self.path, destination).map_err(|source| {
                if source.kind() == io::ErrorKind::AlreadyExists {
                    CandidateExportError::OutputExists(destination.to_path_buf())
                } else {
                    CandidateExportError::io("publish verified output", source)
                }
            })?;
            let _ = fs::remove_file(&self.path);
        }

        self.keep();
        Ok(())
    }
}

impl Drop for NewFileGuard {
    fn drop(&mut self) {
        if !self.keep.get() {
            let _ = fs::remove_file(&self.path);
        }
    }
}

impl CandidateExportError {
    const fn io(operation: &'static str, source: io::Error) -> Self {
        Self::Io { operation, source }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::conversion::OpaqueWriteSets;
    use crate::geometry::ReservationKind;

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

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
    fn partial_output_is_not_exposed_at_requested_path() {
        let destination = temp_path("published.img");
        let mut guard = NewFileGuard::create_partial(&destination).unwrap();
        guard.file_mut().write_all(b"verified").unwrap();
        guard.file().sync_all().unwrap();
        assert!(!destination.exists());
        assert!(guard.path.exists());
        guard.publish(&destination).unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"verified");
        let _ = fs::remove_file(destination);
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
