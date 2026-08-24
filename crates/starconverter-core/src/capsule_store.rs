//! Durable append-only persistence for already-encoded transaction capsules.
//!
//! This backend is deliberately limited to caller-named regular files. It has no raw-device API,
//! never truncates or replaces a file, and accepts an append only when the caller supplies a fully
//! validated capsule whose bytes extend the currently locked capsule by exactly one generation.

use std::fmt;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use crate::capsule::{CapsuleError, CapsuleLimits, recover_capsule, scan_capsule};
use crate::image::{ImageError, reject_device_like_path};

/// Strength of the exclusion held for the store lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapsuleLockStrength {
    /// Windows deny-share opening plus a whole-file exclusive lock.
    #[cfg(windows)]
    MandatoryDenyShareAndFileLock,
    /// A kernel whole-file advisory lock. Cooperating processes are excluded.
    #[cfg(not(windows))]
    AdvisoryFileLock,
}

/// Namespace durability achieved by a completed store operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespaceDurability {
    /// The parent directory was flushed after exclusive creation.
    #[cfg(unix)]
    ParentDirectorySynchronized,
    /// File data and metadata were flushed, but portable Rust cannot open a Windows directory for
    /// an additional namespace flush without a platform-specific layer.
    #[cfg(windows)]
    FileSynchronizedOnly,
    /// Appending does not create or rename a directory entry.
    NotRequired,
}

/// Evidence returned only after write, flush, read-back, and identity verification complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapsuleSyncEvidence {
    pub previous_bytes: u64,
    pub bytes_appended: u64,
    pub total_bytes: u64,
    pub generation_count: usize,
    pub sync_data_completed: bool,
    pub sync_all_completed: bool,
    pub namespace_durability: NamespaceDurability,
}

/// Evidence that opening a durable capsule either required no repair or discarded only a suffix
/// proven to be an incomplete newest generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapsuleRecoveryEvidence {
    pub original_bytes: u64,
    pub retained_bytes: u64,
    pub discarded_torn_bytes: u64,
    pub generation_count: usize,
    pub repair_sync_data_completed: bool,
    pub repair_sync_all_completed: bool,
}

/// An exclusively locked, bounded, append-only regular-file capsule.
#[derive(Debug)]
pub struct CapsuleStore {
    file: File,
    canonical_path: PathBuf,
    identity: PlatformIdentity,
    bytes: Vec<u8>,
    generation_count: usize,
    limits: CapsuleLimits,
    lock_strength: CapsuleLockStrength,
    /// Set as soon as an append crosses its first possibly mutating I/O boundary and cleared only
    /// after the complete generation is read back, flushed, and adopted in memory.
    poisoned: bool,
}

impl CapsuleStore {
    /// Exclusively creates a new capsule file containing one or more encoded generations.
    ///
    /// The capsule path is required to differ from the canonical regular image path. The encoded
    /// bytes are validated before `create_new` is attempted, and an existing path is never opened,
    /// replaced, or truncated.
    ///
    /// # Errors
    ///
    /// Rejects invalid capsules, non-regular images, equal image/capsule paths, device namespaces,
    /// existing targets, lock contention, identity changes, and durability or verification errors.
    pub fn create_new(
        capsule_path: impl AsRef<Path>,
        image_path: impl AsRef<Path>,
        encoded_capsule: &[u8],
        limits: CapsuleLimits,
    ) -> Result<(Self, CapsuleSyncEvidence), CapsuleStoreError> {
        let view = scan_capsule(encoded_capsule, limits).map_err(CapsuleStoreError::Capsule)?;
        if view.generations().is_empty() {
            return Err(CapsuleStoreError::EmptyCapsule);
        }
        let generation_count = view.generations().len();
        let image = canonical_regular_image(image_path.as_ref())?;
        let target = canonical_new_target(capsule_path.as_ref())?;
        if target == image {
            return Err(CapsuleStoreError::CapsuleIsImage);
        }

        let file = open_exclusive(&target, true)?;
        let opened = file
            .metadata()
            .map_err(|source| CapsuleStoreError::io("inspect new capsule", source))?;
        if !opened.is_file() {
            return Err(CapsuleStoreError::NotRegularFile { path: target });
        }
        let identity = platform_identity(&opened);
        if opened.len() != 0 {
            return Err(CapsuleStoreError::UnexpectedLength {
                expected: 0,
                actual: opened.len(),
            });
        }

        let mut store = Self {
            file,
            canonical_path: target,
            identity,
            bytes: Vec::new(),
            generation_count: 0,
            limits,
            lock_strength: platform_lock_strength(),
            poisoned: false,
        };
        let mut evidence = store.persist_suffix(
            encoded_capsule,
            generation_count,
            NamespaceDurability::NotRequired,
        )?;
        evidence.namespace_durability = creation_durability(&store)?;
        Ok((store, evidence))
    }

    /// Opens and exclusively locks an existing complete capsule for subsequent append operations.
    ///
    /// # Errors
    ///
    /// Rejects empty, malformed, torn, oversized, non-regular, device-like, changed, unlocked, or
    /// image-equal paths. This function never repairs or truncates a torn append.
    pub fn resume(
        capsule_path: impl AsRef<Path>,
        image_path: impl AsRef<Path>,
        limits: CapsuleLimits,
    ) -> Result<Self, CapsuleStoreError> {
        Self::resume_internal(capsule_path.as_ref(), image_path.as_ref(), limits, false)
            .map(|(store, _)| store)
    }

    /// Opens an existing capsule and repairs only a provably torn newest append.
    ///
    /// The file is exclusively opened and locked before inspection. Complete corruption,
    /// ambiguous framing, an incomplete first generation, and every error that cannot be reduced
    /// to one validated nonempty prefix are refused without changing the file. When a torn suffix
    /// is proven, the file is shortened to that prefix, durably flushed, reread, and strict-scanned
    /// before the store is returned.
    ///
    /// # Errors
    ///
    /// Returns the same path, identity, limit, lock, and I/O failures as [`Self::resume`]. Capsule
    /// corruption is repairable only when [`recover_capsule`] proves the exact retained prefix.
    pub fn resume_recovering(
        capsule_path: impl AsRef<Path>,
        image_path: impl AsRef<Path>,
        limits: CapsuleLimits,
    ) -> Result<(Self, CapsuleRecoveryEvidence), CapsuleStoreError> {
        Self::resume_internal(capsule_path.as_ref(), image_path.as_ref(), limits, true)
    }

    fn resume_internal(
        capsule_path: &Path,
        image_path: &Path,
        limits: CapsuleLimits,
        recover_torn_tail: bool,
    ) -> Result<(Self, CapsuleRecoveryEvidence), CapsuleStoreError> {
        validate_limits_without_allocating(limits)?;
        let image = canonical_regular_image(image_path)?;
        let requested = capsule_path;
        reject_device_like_path(requested).map_err(CapsuleStoreError::ImagePath)?;
        let canonical_path = fs::canonicalize(requested)
            .map_err(|source| CapsuleStoreError::io("canonicalize capsule path", source))?;
        reject_device_like_path(&canonical_path).map_err(CapsuleStoreError::ImagePath)?;
        if canonical_path == image {
            return Err(CapsuleStoreError::CapsuleIsImage);
        }

        let file = open_exclusive(&canonical_path, false)?;
        let metadata = file
            .metadata()
            .map_err(|source| CapsuleStoreError::io("inspect opened capsule", source))?;
        if !metadata.is_file() {
            return Err(CapsuleStoreError::NotRegularFile {
                path: canonical_path,
            });
        }
        let image_metadata = fs::metadata(&image)
            .map_err(|source| CapsuleStoreError::io("reinspect image path", source))?;
        if same_platform_file(&metadata, &image_metadata) {
            return Err(CapsuleStoreError::CapsuleIsImage);
        }
        let length = bounded_length(metadata.len(), limits.max_capsule_bytes)?;
        if length == 0 {
            return Err(CapsuleStoreError::EmptyCapsule);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| CapsuleStoreError::AllocationFailed)?;
        bytes.resize(length, 0);
        read_exact_at(&file, 0, &mut bytes)
            .map_err(|source| CapsuleStoreError::io("read capsule", source))?;
        let original_bytes = metadata.len();
        let mut repair_sync_data_completed = false;
        let mut repair_sync_all_completed = false;
        let generation_count = match scan_capsule(&bytes, limits) {
            Ok(view) => {
                if view.generations().is_empty() || view.validated_bytes() != bytes.len() {
                    return Err(CapsuleStoreError::EmptyCapsule);
                }
                view.generations().len()
            }
            Err(strict_error) if recover_torn_tail => {
                let generations = repair_torn_suffix(&file, &mut bytes, limits, strict_error)?;
                repair_sync_data_completed = true;
                repair_sync_all_completed = true;
                generations
            }
            Err(error) => return Err(CapsuleStoreError::Capsule(error)),
        };

        let store = Self {
            file,
            canonical_path,
            identity: platform_identity(&metadata),
            bytes,
            generation_count,
            limits,
            lock_strength: platform_lock_strength(),
            poisoned: false,
        };
        store.ensure_unchanged()?;
        let retained_bytes =
            u64::try_from(store.bytes.len()).map_err(|_| CapsuleStoreError::ArithmeticOverflow)?;
        Ok((
            store,
            CapsuleRecoveryEvidence {
                original_bytes,
                retained_bytes,
                discarded_torn_bytes: original_bytes
                    .checked_sub(retained_bytes)
                    .ok_or(CapsuleStoreError::ArithmeticOverflow)?,
                generation_count,
                repair_sync_data_completed,
                repair_sync_all_completed,
            },
        ))
    }

    /// Appends exactly one already-encoded generation from a complete updated capsule buffer.
    ///
    /// `updated_capsule` must begin byte-for-byte with [`Self::bytes`] and must validate as the
    /// current capsule plus one generation. Only the suffix is written; shrink, rewrite, equal-
    /// length, and multi-generation updates are refused before any write.
    ///
    /// # Errors
    ///
    /// Rejects non-prefix updates, anything other than one generation of growth, invalid or
    /// oversized framing, identity/length changes, verification failures, and flush failures.
    pub fn append(
        &mut self,
        updated_capsule: &[u8],
    ) -> Result<CapsuleSyncEvidence, CapsuleStoreError> {
        if self.poisoned {
            return Err(CapsuleStoreError::Poisoned);
        }
        if updated_capsule.len() <= self.bytes.len()
            || !updated_capsule.starts_with(self.bytes.as_slice())
        {
            return Err(CapsuleStoreError::NotAppendOnly);
        }
        let view =
            scan_capsule(updated_capsule, self.limits).map_err(CapsuleStoreError::Capsule)?;
        let expected = self
            .generation_count
            .checked_add(1)
            .ok_or(CapsuleStoreError::ArithmeticOverflow)?;
        if view.generations().len() != expected || view.validated_bytes() != updated_capsule.len() {
            return Err(CapsuleStoreError::GenerationCount {
                expected,
                actual: view.generations().len(),
            });
        }
        self.ensure_unchanged()?;
        let suffix = &updated_capsule[self.bytes.len()..];
        self.persist_suffix(suffix, expected, NamespaceDurability::NotRequired)
    }

    /// Canonical capsule path pinned for the store lifetime.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.canonical_path
    }

    /// Complete, validated capsule bytes durably known by this store.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Number of complete capsule generations durably known by this store.
    #[must_use]
    pub const fn generation_count(&self) -> usize {
        self.generation_count
    }

    /// Exclusion strength held until this store is dropped.
    #[must_use]
    pub const fn lock_strength(&self) -> CapsuleLockStrength {
        self.lock_strength
    }

    /// Whether a prior append may have changed bytes without returning durable completion proof.
    #[must_use]
    #[allow(dead_code)]
    pub(crate) const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Conservatively prevents further appends after a coupled operation becomes ambiguous.
    #[allow(dead_code)]
    pub(crate) const fn poison(&mut self) {
        self.poisoned = true;
    }

    /// Restores the exact last in-memory, fully verified prefix after an ambiguous append.
    ///
    /// This is intentionally crate-private: only the regular-image coordinator may combine this
    /// destructive capsule repair with conservative image rollback. The locked file identity is
    /// checked before truncation and the retained prefix is reread and strictly scanned before the
    /// poison is cleared.
    #[allow(dead_code)]
    pub(crate) fn restore_verified_prefix(&mut self) -> Result<(), CapsuleStoreError> {
        if !self.poisoned {
            return Ok(());
        }
        self.ensure_identity_with_minimum_length()?;
        let retained =
            u64::try_from(self.bytes.len()).map_err(|_| CapsuleStoreError::ArithmeticOverflow)?;
        self.file
            .set_len(retained)
            .map_err(|source| CapsuleStoreError::io("discard ambiguous capsule suffix", source))?;
        self.file
            .sync_data()
            .map_err(|source| CapsuleStoreError::io("flush restored capsule prefix", source))?;
        let mut actual = vec![0_u8; self.bytes.len()];
        read_exact_at(&self.file, 0, &mut actual)
            .map_err(|source| CapsuleStoreError::io("verify restored capsule prefix", source))?;
        if actual != self.bytes {
            return Err(CapsuleStoreError::VerificationMismatch);
        }
        let view = scan_capsule(&actual, self.limits).map_err(CapsuleStoreError::Capsule)?;
        if view.validated_bytes() != actual.len()
            || view.generations().len() != self.generation_count
        {
            return Err(CapsuleStoreError::VerificationMismatch);
        }
        self.file.sync_all().map_err(|source| {
            CapsuleStoreError::io("flush restored capsule data and metadata", source)
        })?;
        self.ensure_unchanged()?;
        self.poisoned = false;
        Ok(())
    }

    fn persist_suffix(
        &mut self,
        suffix: &[u8],
        generation_count: usize,
        namespace_durability: NamespaceDurability,
    ) -> Result<CapsuleSyncEvidence, CapsuleStoreError> {
        self.ensure_unchanged()?;
        let previous = self.bytes.len();
        let total = previous
            .checked_add(suffix.len())
            .ok_or(CapsuleStoreError::ArithmeticOverflow)?;
        if total > self.limits.max_capsule_bytes {
            return Err(CapsuleStoreError::TooLarge {
                actual: total,
                maximum: self.limits.max_capsule_bytes,
            });
        }
        self.bytes
            .try_reserve_exact(suffix.len())
            .map_err(|_| CapsuleStoreError::AllocationFailed)?;
        let mut actual = Vec::new();
        actual
            .try_reserve_exact(suffix.len())
            .map_err(|_| CapsuleStoreError::AllocationFailed)?;
        actual.resize(suffix.len(), 0);
        let previous_bytes =
            u64::try_from(previous).map_err(|_| CapsuleStoreError::ArithmeticOverflow)?;
        let bytes_appended =
            u64::try_from(suffix.len()).map_err(|_| CapsuleStoreError::ArithmeticOverflow)?;
        let total_bytes =
            u64::try_from(total).map_err(|_| CapsuleStoreError::ArithmeticOverflow)?;

        let offset = previous_bytes;
        self.poisoned = true;
        let persisted = (|| {
            write_all_at(&self.file, offset, suffix)
                .map_err(|source| CapsuleStoreError::io("append capsule bytes", source))?;
            self.file
                .sync_data()
                .map_err(|source| CapsuleStoreError::io("flush capsule data", source))?;

            read_exact_at(&self.file, offset, &mut actual)
                .map_err(|source| CapsuleStoreError::io("verify appended capsule bytes", source))?;
            if actual != suffix {
                return Err(CapsuleStoreError::VerificationMismatch);
            }
            self.file.sync_all().map_err(|source| {
                CapsuleStoreError::io("flush capsule data and metadata", source)
            })?;
            Ok(())
        })();
        persisted?;

        self.bytes.extend_from_slice(suffix);
        self.generation_count = generation_count;
        self.ensure_unchanged()?;
        self.poisoned = false;
        Ok(CapsuleSyncEvidence {
            previous_bytes,
            bytes_appended,
            total_bytes,
            generation_count,
            sync_data_completed: true,
            sync_all_completed: true,
            namespace_durability,
        })
    }

    fn ensure_unchanged(&self) -> Result<(), CapsuleStoreError> {
        let expected_length =
            u64::try_from(self.bytes.len()).map_err(|_| CapsuleStoreError::ArithmeticOverflow)?;
        let handle = self
            .file
            .metadata()
            .map_err(|source| CapsuleStoreError::io("reinspect capsule handle", source))?;
        validate_same_file(self.identity, &handle, expected_length)?;

        let canonical_now = fs::canonicalize(&self.canonical_path)
            .map_err(|source| CapsuleStoreError::io("recanonicalize capsule path", source))?;
        reject_device_like_path(&canonical_now).map_err(CapsuleStoreError::ImagePath)?;
        if canonical_now != self.canonical_path {
            return Err(CapsuleStoreError::IdentityChanged);
        }
        let path = fs::metadata(&canonical_now)
            .map_err(|source| CapsuleStoreError::io("reinspect capsule path", source))?;
        validate_same_file(self.identity, &path, expected_length)
    }

    #[allow(dead_code)]
    fn ensure_identity_with_minimum_length(&self) -> Result<(), CapsuleStoreError> {
        let minimum =
            u64::try_from(self.bytes.len()).map_err(|_| CapsuleStoreError::ArithmeticOverflow)?;
        let handle = self
            .file
            .metadata()
            .map_err(|source| CapsuleStoreError::io("reinspect capsule handle", source))?;
        validate_same_file_minimum(self.identity, &handle, minimum)?;
        let canonical_now = fs::canonicalize(&self.canonical_path)
            .map_err(|source| CapsuleStoreError::io("recanonicalize capsule path", source))?;
        reject_device_like_path(&canonical_now).map_err(CapsuleStoreError::ImagePath)?;
        if canonical_now != self.canonical_path {
            return Err(CapsuleStoreError::IdentityChanged);
        }
        let path = fs::metadata(&canonical_now)
            .map_err(|source| CapsuleStoreError::io("reinspect capsule path", source))?;
        validate_same_file_minimum(self.identity, &path, minimum)
    }
}

fn repair_torn_suffix(
    file: &File,
    bytes: &mut Vec<u8>,
    limits: CapsuleLimits,
    strict_error: CapsuleError,
) -> Result<usize, CapsuleStoreError> {
    let recovered = recover_capsule(bytes, limits).map_err(CapsuleStoreError::Capsule)?;
    let retained = recovered.validated_bytes();
    if recovered.generations().is_empty() || retained == 0 || retained >= bytes.len() {
        return Err(CapsuleStoreError::Capsule(strict_error));
    }
    let generations = recovered.generations().len();
    drop(recovered);
    let retained_u64 =
        u64::try_from(retained).map_err(|_| CapsuleStoreError::ArithmeticOverflow)?;
    file.set_len(retained_u64)
        .map_err(|source| CapsuleStoreError::io("discard proven torn capsule suffix", source))?;
    file.sync_data()
        .map_err(|source| CapsuleStoreError::io("flush recovered capsule data", source))?;
    bytes.truncate(retained);
    let mut reread = vec![0_u8; retained];
    read_exact_at(file, 0, &mut reread)
        .map_err(|source| CapsuleStoreError::io("reread recovered capsule", source))?;
    if reread != *bytes {
        return Err(CapsuleStoreError::VerificationMismatch);
    }
    let strict = scan_capsule(&reread, limits).map_err(CapsuleStoreError::Capsule)?;
    if strict.generations().len() != generations || strict.validated_bytes() != reread.len() {
        return Err(CapsuleStoreError::VerificationMismatch);
    }
    file.sync_all().map_err(|source| {
        CapsuleStoreError::io("flush recovered capsule data and metadata", source)
    })?;
    Ok(generations)
}

impl Drop for CapsuleStore {
    fn drop(&mut self) {
        let _ = fs4::FileExt::unlock(&self.file);
    }
}

/// Capsule-store validation, exclusion, persistence, or I/O failure.
#[derive(Debug)]
pub enum CapsuleStoreError {
    Capsule(CapsuleError),
    ImagePath(ImageError),
    InvalidLimit {
        field: &'static str,
    },
    EmptyCapsule,
    GenerationCount {
        expected: usize,
        actual: usize,
    },
    CapsuleIsImage,
    NotRegularFile {
        path: PathBuf,
    },
    NotAppendOnly,
    /// A prior append crossed a mutating I/O boundary without complete durability evidence.
    Poisoned,
    IdentityChanged,
    UnexpectedLength {
        expected: u64,
        actual: u64,
    },
    TooLarge {
        actual: usize,
        maximum: usize,
    },
    AllocationFailed,
    ArithmeticOverflow,
    VerificationMismatch,
    Io {
        operation: &'static str,
        source: io::Error,
    },
}

impl CapsuleStoreError {
    const fn io(operation: &'static str, source: io::Error) -> Self {
        Self::Io { operation, source }
    }
}

impl fmt::Display for CapsuleStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Capsule(error) => write!(formatter, "invalid capsule: {error}"),
            Self::ImagePath(error) => write!(formatter, "invalid regular-file path: {error}"),
            Self::InvalidLimit { field } => write!(formatter, "capsule limit {field} is zero"),
            Self::EmptyCapsule => formatter.write_str("capsule contains no complete generation"),
            Self::GenerationCount { expected, actual } => write!(
                formatter,
                "capsule append must add exactly one generation: expected {expected}, found {actual}"
            ),
            Self::CapsuleIsImage => {
                formatter.write_str("capsule path must differ from the image path")
            }
            Self::NotRegularFile { path } => {
                write!(
                    formatter,
                    "capsule is not a regular file: {}",
                    path.display()
                )
            }
            Self::NotAppendOnly => formatter.write_str(
                "updated capsule must preserve every existing byte and append non-empty bytes",
            ),
            Self::Poisoned => formatter.write_str(
                "capsule store is poisoned after an ambiguous append and must be conservatively recovered",
            ),
            Self::IdentityChanged => {
                formatter.write_str("capsule file identity or path changed while locked")
            }
            Self::UnexpectedLength { expected, actual } => write!(
                formatter,
                "capsule length changed: expected {expected} bytes, found {actual}"
            ),
            Self::TooLarge { actual, maximum } => {
                write!(formatter, "capsule has {actual} bytes, exceeding {maximum}")
            }
            Self::AllocationFailed => formatter.write_str("could not allocate bounded storage"),
            Self::ArithmeticOverflow => formatter.write_str("capsule byte accounting overflow"),
            Self::VerificationMismatch => {
                formatter.write_str("appended capsule bytes failed read-back verification")
            }
            Self::Io { operation, source } => write!(formatter, "{operation}: {source}"),
        }
    }
}

impl std::error::Error for CapsuleStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Capsule(error) => Some(error),
            Self::ImagePath(error) => Some(error),
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

fn validate_limits_without_allocating(limits: CapsuleLimits) -> Result<(), CapsuleStoreError> {
    for (field, value) in [
        ("max_capsule_bytes", limits.max_capsule_bytes),
        ("max_generation_bytes", limits.max_generation_bytes),
        ("max_generations", limits.max_generations),
    ] {
        if value == 0 {
            return Err(CapsuleStoreError::InvalidLimit { field });
        }
    }
    Ok(())
}

fn canonical_regular_image(path: &Path) -> Result<PathBuf, CapsuleStoreError> {
    reject_device_like_path(path).map_err(CapsuleStoreError::ImagePath)?;
    let canonical = fs::canonicalize(path)
        .map_err(|source| CapsuleStoreError::io("canonicalize image path", source))?;
    reject_device_like_path(&canonical).map_err(CapsuleStoreError::ImagePath)?;
    let metadata = fs::metadata(&canonical)
        .map_err(|source| CapsuleStoreError::io("inspect image path", source))?;
    if !metadata.is_file() {
        return Err(CapsuleStoreError::NotRegularFile { path: canonical });
    }
    Ok(canonical)
}

fn canonical_new_target(path: &Path) -> Result<PathBuf, CapsuleStoreError> {
    reject_device_like_path(path).map_err(CapsuleStoreError::ImagePath)?;
    let name = path
        .file_name()
        .ok_or_else(|| CapsuleStoreError::NotRegularFile {
            path: path.to_path_buf(),
        })?;
    let parent = path.parent().filter(|value| !value.as_os_str().is_empty());
    let canonical_parent = fs::canonicalize(parent.unwrap_or_else(|| Path::new(".")))
        .map_err(|source| CapsuleStoreError::io("canonicalize capsule parent", source))?;
    reject_device_like_path(&canonical_parent).map_err(CapsuleStoreError::ImagePath)?;
    let target = canonical_parent.join(name);
    reject_device_like_path(&target).map_err(CapsuleStoreError::ImagePath)?;
    Ok(target)
}

fn open_exclusive(path: &Path, create_new: bool) -> Result<File, CapsuleStoreError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(create_new);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(0);
    }
    let file = options
        .open(path)
        .map_err(|source| CapsuleStoreError::io("open capsule exclusively", source))?;
    fs4::FileExt::try_lock(&file)
        .map_err(|source| CapsuleStoreError::io("lock capsule exclusively", source.into()))?;
    Ok(file)
}

fn bounded_length(length: u64, maximum: usize) -> Result<usize, CapsuleStoreError> {
    let length = usize::try_from(length).map_err(|_| CapsuleStoreError::TooLarge {
        actual: usize::MAX,
        maximum,
    })?;
    if length > maximum {
        return Err(CapsuleStoreError::TooLarge {
            actual: length,
            maximum,
        });
    }
    Ok(length)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PlatformIdentity {
    #[cfg(unix)]
    Unix { device: u64, inode: u64 },
    #[cfg(windows)]
    Windows { creation_time: u64 },
    #[cfg(not(any(unix, windows)))]
    Unavailable,
}

#[cfg(unix)]
fn platform_identity(metadata: &Metadata) -> PlatformIdentity {
    use std::os::unix::fs::MetadataExt;
    PlatformIdentity::Unix {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

#[cfg(windows)]
fn platform_identity(metadata: &Metadata) -> PlatformIdentity {
    use std::os::windows::fs::MetadataExt;
    PlatformIdentity::Windows {
        creation_time: metadata.creation_time(),
    }
}

#[cfg(not(any(unix, windows)))]
fn platform_identity(_metadata: &Metadata) -> PlatformIdentity {
    PlatformIdentity::Unavailable
}

fn validate_same_file(
    expected: PlatformIdentity,
    metadata: &Metadata,
    expected_length: u64,
) -> Result<(), CapsuleStoreError> {
    if !metadata.is_file() || platform_identity(metadata) != expected {
        return Err(CapsuleStoreError::IdentityChanged);
    }
    if metadata.len() != expected_length {
        return Err(CapsuleStoreError::UnexpectedLength {
            expected: expected_length,
            actual: metadata.len(),
        });
    }
    Ok(())
}

#[allow(dead_code)]
fn validate_same_file_minimum(
    expected: PlatformIdentity,
    metadata: &Metadata,
    minimum_length: u64,
) -> Result<(), CapsuleStoreError> {
    if !metadata.is_file() || platform_identity(metadata) != expected {
        return Err(CapsuleStoreError::IdentityChanged);
    }
    if metadata.len() < minimum_length {
        return Err(CapsuleStoreError::UnexpectedLength {
            expected: minimum_length,
            actual: metadata.len(),
        });
    }
    Ok(())
}

#[cfg(unix)]
fn same_platform_file(left: &Metadata, right: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
const fn same_platform_file(_left: &Metadata, _right: &Metadata) -> bool {
    // Windows deny-share access prevents replacement after opening. Stable Rust does not expose
    // the volume serial/file index pair needed to prove that differently named paths are hardlinks.
    false
}

#[cfg(windows)]
const fn platform_lock_strength() -> CapsuleLockStrength {
    CapsuleLockStrength::MandatoryDenyShareAndFileLock
}

#[cfg(not(windows))]
const fn platform_lock_strength() -> CapsuleLockStrength {
    CapsuleLockStrength::AdvisoryFileLock
}

#[cfg(unix)]
fn creation_durability(store: &CapsuleStore) -> Result<NamespaceDurability, CapsuleStoreError> {
    let parent = store
        .canonical_path
        .parent()
        .ok_or(CapsuleStoreError::IdentityChanged)?;
    let directory = File::open(parent)
        .map_err(|source| CapsuleStoreError::io("open capsule parent directory", source))?;
    directory
        .sync_all()
        .map_err(|source| CapsuleStoreError::io("flush capsule parent directory", source))?;
    Ok(NamespaceDurability::ParentDirectorySynchronized)
}

#[cfg(windows)]
fn creation_durability(store: &CapsuleStore) -> Result<NamespaceDurability, CapsuleStoreError> {
    store
        .file
        .sync_all()
        .map_err(|source| CapsuleStoreError::io("reflush capsule after creation", source))?;
    Ok(NamespaceDurability::FileSynchronizedOnly)
}

#[cfg(not(any(unix, windows)))]
fn creation_durability(store: &CapsuleStore) -> Result<NamespaceDurability, CapsuleStoreError> {
    store
        .file
        .sync_all()
        .map_err(|source| CapsuleStoreError::io("reflush capsule after creation", source))?;
    Ok(NamespaceDurability::NotRequired)
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
    use crate::capsule::{CapsuleIdentity, HEADER_BYTES, TransactionPhase, append_generation};
    #[cfg(unix)]
    use std::io::Write as _;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    #[derive(Debug)]
    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let unique = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "starconverter-capsule-store-{}-{unique}",
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

    const fn limits() -> CapsuleLimits {
        CapsuleLimits {
            max_capsule_bytes: 64 * 1024,
            max_generation_bytes: 4096,
            max_generations: 8,
        }
    }

    fn image(dir: &TempDir) -> PathBuf {
        let path = dir.join("image.bin");
        fs::write(&path, b"regular image bytes").unwrap();
        path
    }

    fn initial_capsule() -> Vec<u8> {
        let mut bytes = Vec::new();
        append_generation(
            &mut bytes,
            CapsuleIdentity {
                transaction_id: [0x12; 16],
                source_digest: [0x34; 32],
            },
            TransactionPhase::Discovered,
            b"discovery evidence",
            limits(),
        )
        .unwrap();
        bytes
    }

    fn appended_capsule(generations: usize) -> Vec<u8> {
        let mut bytes = initial_capsule();
        let phases = [
            TransactionPhase::Reserved,
            TransactionPhase::Relocating,
            TransactionPhase::TargetStaged,
        ];
        for phase in phases.into_iter().take(generations.saturating_sub(1)) {
            append_generation(
                &mut bytes,
                CapsuleIdentity {
                    transaction_id: [0x12; 16],
                    source_digest: [0x34; 32],
                },
                phase,
                b"durable evidence",
                limits(),
            )
            .unwrap();
        }
        bytes
    }

    #[test]
    fn create_append_and_resume_preserve_exact_bytes() {
        let dir = TempDir::new();
        let image = image(&dir);
        let capsule = dir.join("transaction.starcap");
        let initial = initial_capsule();
        let (mut store, created) =
            CapsuleStore::create_new(&capsule, &image, &initial, limits()).unwrap();
        assert_eq!(created.previous_bytes, 0);
        assert_eq!(
            created.bytes_appended,
            u64::try_from(initial.len()).unwrap()
        );
        assert!(created.sync_data_completed && created.sync_all_completed);

        let updated = appended_capsule(2);
        let appended = store.append(&updated).unwrap();
        assert_eq!(
            appended.previous_bytes,
            u64::try_from(initial.len()).unwrap()
        );
        assert_eq!(appended.total_bytes, u64::try_from(updated.len()).unwrap());
        assert_eq!(appended.generation_count, 2);
        assert_eq!(store.bytes(), updated);
        drop(store);

        let resumed = CapsuleStore::resume(&capsule, &image, limits()).unwrap();
        assert_eq!(resumed.bytes(), updated);
        assert_eq!(resumed.generation_count(), 2);
        drop(resumed);
        assert_eq!(fs::read(capsule).unwrap(), updated);
    }

    #[test]
    fn recovering_resume_repairs_every_cut_of_only_the_newest_append() {
        let complete = appended_capsule(2);
        let durable = initial_capsule();
        for cut in durable.len() + 1..complete.len() {
            let dir = TempDir::new();
            let image = image(&dir);
            let capsule = dir.join("cut.starcap");
            fs::write(&capsule, &complete[..cut]).unwrap();

            assert!(CapsuleStore::resume(&capsule, &image, limits()).is_err());
            let (store, evidence) =
                CapsuleStore::resume_recovering(&capsule, &image, limits()).unwrap();
            assert_eq!(store.bytes(), durable);
            assert_eq!(store.generation_count(), 1);
            assert_eq!(evidence.original_bytes, u64::try_from(cut).unwrap());
            assert_eq!(
                evidence.retained_bytes,
                u64::try_from(durable.len()).unwrap()
            );
            assert_eq!(
                evidence.discarded_torn_bytes,
                u64::try_from(cut - durable.len()).unwrap()
            );
            assert!(evidence.repair_sync_data_completed && evidence.repair_sync_all_completed);
            drop(store);
            assert_eq!(fs::read(&capsule).unwrap(), durable);

            let mut store = CapsuleStore::resume(&capsule, &image, limits()).unwrap();
            let appended = store.append(&complete).unwrap();
            assert_eq!(appended.generation_count, 2);
            drop(store);
            assert_eq!(fs::read(capsule).unwrap(), complete);
        }
    }

    #[test]
    fn recovering_resume_is_a_noop_for_a_complete_capsule() {
        let dir = TempDir::new();
        let image = image(&dir);
        let capsule = dir.join("complete.starcap");
        let complete = appended_capsule(2);
        fs::write(&capsule, &complete).unwrap();

        let (store, evidence) =
            CapsuleStore::resume_recovering(&capsule, &image, limits()).unwrap();
        assert_eq!(store.bytes(), complete);
        assert_eq!(evidence.discarded_torn_bytes, 0);
        assert!(!evidence.repair_sync_data_completed);
        assert!(!evidence.repair_sync_all_completed);
        drop(store);
        assert_eq!(fs::read(capsule).unwrap(), complete);
    }

    #[test]
    fn recovering_resume_never_repairs_complete_corruption_or_a_torn_first_generation() {
        let dir = TempDir::new();
        let image = image(&dir);
        let capsule = dir.join("corrupt.starcap");
        let mut corrupt = appended_capsule(2);
        corrupt[initial_capsule().len() + HEADER_BYTES] ^= 0x80;
        fs::write(&capsule, &corrupt).unwrap();
        assert!(CapsuleStore::resume_recovering(&capsule, &image, limits()).is_err());
        assert_eq!(fs::read(&capsule).unwrap(), corrupt);

        let first = initial_capsule();
        let torn_first = &first[..first.len() - 1];
        fs::write(&capsule, torn_first).unwrap();
        assert!(CapsuleStore::resume_recovering(&capsule, &image, limits()).is_err());
        assert_eq!(fs::read(capsule).unwrap(), torn_first);
    }

    #[test]
    fn create_new_never_replaces_and_refuses_image_path() {
        let dir = TempDir::new();
        let image = image(&dir);
        let capsule = dir.join("existing.starcap");
        fs::write(&capsule, b"do not replace").unwrap();

        assert!(CapsuleStore::create_new(&capsule, &image, &initial_capsule(), limits()).is_err());
        assert_eq!(fs::read(&capsule).unwrap(), b"do not replace");
        assert!(matches!(
            CapsuleStore::create_new(&image, &image, &initial_capsule(), limits()),
            Err(CapsuleStoreError::CapsuleIsImage)
        ));
        assert_eq!(fs::read(image).unwrap(), b"regular image bytes");

        let empty_target = dir.join("empty-not-created.starcap");
        assert!(matches!(
            CapsuleStore::create_new(&empty_target, dir.join("image.bin"), &[], limits()),
            Err(CapsuleStoreError::EmptyCapsule)
        ));
        assert!(!empty_target.exists());
    }

    #[test]
    fn create_accepts_a_complete_bounded_multi_generation_capsule() {
        let dir = TempDir::new();
        let image = image(&dir);
        let capsule = dir.join("existing-history.starcap");
        let encoded = appended_capsule(2);
        let (store, evidence) =
            CapsuleStore::create_new(&capsule, &image, &encoded, limits()).unwrap();
        assert_eq!(store.generation_count(), 2);
        assert_eq!(store.bytes(), encoded);
        assert_eq!(evidence.generation_count, 2);
    }

    #[test]
    fn append_refuses_rewrite_shrink_and_generation_jump_without_writing() {
        let dir = TempDir::new();
        let image = image(&dir);
        let capsule = dir.join("transaction.starcap");
        let initial = initial_capsule();
        let (mut store, _) =
            CapsuleStore::create_new(&capsule, &image, &initial, limits()).unwrap();

        let mut rewrite = appended_capsule(2);
        rewrite[0] ^= 1;
        assert!(matches!(
            store.append(&rewrite),
            Err(CapsuleStoreError::NotAppendOnly)
        ));
        assert!(matches!(
            store.append(&initial[..initial.len() - 1]),
            Err(CapsuleStoreError::NotAppendOnly)
        ));
        assert!(matches!(
            store.append(&appended_capsule(3)),
            Err(CapsuleStoreError::GenerationCount { .. })
        ));
        assert_eq!(store.bytes(), initial);
        drop(store);
        assert_eq!(fs::read(capsule).unwrap(), initial);
    }

    #[test]
    fn poisoned_store_refuses_append_until_exact_verified_prefix_is_restored() {
        let initial = initial_capsule();
        let complete = appended_capsule(2);
        let suffix = &complete[initial.len()..];
        // Exercise every possible nonempty torn suffix and the complete-but-unadopted generation.
        for cut in 1..=suffix.len() {
            let dir = TempDir::new();
            let image = image(&dir);
            let capsule = dir.join("poisoned.starcap");
            let (mut store, _) =
                CapsuleStore::create_new(&capsule, &image, &initial, limits()).unwrap();
            write_all_at(
                &store.file,
                u64::try_from(initial.len()).unwrap(),
                &suffix[..cut],
            )
            .unwrap();
            store.file.sync_data().unwrap();
            store.poison();
            assert!(matches!(
                store.append(&complete),
                Err(CapsuleStoreError::Poisoned)
            ));

            store.restore_verified_prefix().unwrap();
            assert!(!store.is_poisoned());
            assert_eq!(store.file.metadata().unwrap().len(), initial.len() as u64);
            let mut actual = vec![0_u8; initial.len()];
            read_exact_at(&store.file, 0, &mut actual).unwrap();
            assert_eq!(actual, initial);
            let evidence = store.append(&complete).unwrap();
            assert!(evidence.sync_data_completed && evidence.sync_all_completed);
        }
    }

    #[test]
    fn resume_refuses_empty_malformed_oversized_and_directory_paths() {
        let dir = TempDir::new();
        let image = image(&dir);
        let empty = dir.join("empty.starcap");
        fs::write(&empty, []).unwrap();
        assert!(matches!(
            CapsuleStore::resume(&empty, &image, limits()),
            Err(CapsuleStoreError::EmptyCapsule)
        ));

        let malformed = dir.join("malformed.starcap");
        fs::write(&malformed, b"not a capsule").unwrap();
        assert!(matches!(
            CapsuleStore::resume(&malformed, &image, limits()),
            Err(CapsuleStoreError::Capsule(_))
        ));

        let torn = dir.join("torn.starcap");
        let mut torn_bytes = initial_capsule();
        torn_bytes.pop();
        fs::write(&torn, torn_bytes).unwrap();
        assert!(matches!(
            CapsuleStore::resume(&torn, &image, limits()),
            Err(CapsuleStoreError::Capsule(_))
        ));

        let oversized = dir.join("oversized.starcap");
        fs::write(&oversized, vec![0; limits().max_capsule_bytes + 1]).unwrap();
        assert!(matches!(
            CapsuleStore::resume(&oversized, &image, limits()),
            Err(CapsuleStoreError::TooLarge { .. })
        ));
        assert!(matches!(
            CapsuleStore::resume(&dir.0, &image, limits()),
            Err(CapsuleStoreError::NotRegularFile { .. } | CapsuleStoreError::Io { .. })
        ));
    }

    #[test]
    fn exclusive_lock_refuses_a_second_store() {
        let dir = TempDir::new();
        let image = image(&dir);
        let capsule = dir.join("transaction.starcap");
        let (store, _) =
            CapsuleStore::create_new(&capsule, &image, &initial_capsule(), limits()).unwrap();
        assert!(CapsuleStore::resume(&capsule, &image, limits()).is_err());
        drop(store);
        assert!(CapsuleStore::resume(&capsule, &image, limits()).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn external_length_change_is_detected_before_append() {
        let dir = TempDir::new();
        let image = image(&dir);
        let capsule = dir.join("transaction.starcap");
        let initial = initial_capsule();
        let (mut store, _) =
            CapsuleStore::create_new(&capsule, &image, &initial, limits()).unwrap();
        OpenOptions::new()
            .append(true)
            .open(&capsule)
            .unwrap()
            .write_all(b"interference")
            .unwrap();
        assert!(matches!(
            store.append(&appended_capsule(2)),
            Err(CapsuleStoreError::UnexpectedLength { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn external_path_replacement_is_detected_before_append() {
        let dir = TempDir::new();
        let image = image(&dir);
        let capsule = dir.join("transaction.starcap");
        let displaced = dir.join("displaced.starcap");
        let (mut store, _) =
            CapsuleStore::create_new(&capsule, &image, &initial_capsule(), limits()).unwrap();
        fs::rename(&capsule, &displaced).unwrap();
        fs::write(&capsule, initial_capsule()).unwrap();
        assert!(matches!(
            store.append(&appended_capsule(2)),
            Err(CapsuleStoreError::IdentityChanged)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn resume_refuses_an_image_hardlink_alias() {
        let dir = TempDir::new();
        let image = dir.join("image.bin");
        fs::write(&image, initial_capsule()).unwrap();
        let capsule = dir.join("capsule-alias.starcap");
        fs::hard_link(&image, &capsule).unwrap();
        assert!(matches!(
            CapsuleStore::resume(&capsule, &image, limits()),
            Err(CapsuleStoreError::CapsuleIsImage)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn device_namespace_is_refused_without_opening() {
        let dir = TempDir::new();
        let image = image(&dir);
        assert!(matches!(
            CapsuleStore::resume("/dev/null", image, limits()),
            Err(CapsuleStoreError::ImagePath(
                ImageError::DeviceLikePath { .. }
            ))
        ));
    }

    #[cfg(windows)]
    #[test]
    fn device_namespace_is_refused_without_opening() {
        let dir = TempDir::new();
        let image = image(&dir);
        assert!(matches!(
            CapsuleStore::resume(r"\\.\PhysicalDrive0", image, limits()),
            Err(CapsuleStoreError::ImagePath(
                ImageError::DeviceLikePath { .. }
            ))
        ));
    }
}
