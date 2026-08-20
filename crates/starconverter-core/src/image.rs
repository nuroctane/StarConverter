//! Safe, read-only access to regular filesystem image files.
//!
//! This module deliberately has no raw-device discovery and no write API. Callers provide one
//! path, which is canonicalized and validated as a regular file before it is opened read-only.

use std::fmt;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Default upper bound for one allocation-backed image read (16 MiB).
pub const DEFAULT_MAX_READ_BYTES: usize = 16 * 1024 * 1024;

/// Open-time identity used to detect replacement, truncation, or modification of an image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageIdentity {
    canonical_path: PathBuf,
    length: u64,
    modified: Option<SystemTime>,
    created: Option<SystemTime>,
    platform: PlatformFileIdentity,
}

impl ImageIdentity {
    /// Canonical path resolved before the image was opened.
    #[must_use]
    pub fn canonical_path(&self) -> &Path {
        &self.canonical_path
    }

    /// Image length captured when the file was opened.
    #[must_use]
    pub const fn length(&self) -> u64 {
        self.length
    }

    /// Best-effort modification time captured when the file was opened.
    #[must_use]
    pub const fn modified(&self) -> Option<SystemTime> {
        self.modified
    }

    /// Best-effort creation time captured when the file was opened.
    #[must_use]
    pub const fn created(&self) -> Option<SystemTime> {
        self.created
    }

    /// Platform file identifier captured from the opened handle.
    #[must_use]
    pub const fn platform(&self) -> &PlatformFileIdentity {
        &self.platform
    }

    fn from_metadata(canonical_path: PathBuf, metadata: &Metadata) -> Self {
        Self {
            canonical_path,
            length: metadata.len(),
            modified: metadata.modified().ok(),
            created: metadata.created().ok(),
            platform: platform_file_identity(metadata),
        }
    }

    pub(crate) fn matches_metadata(&self, metadata: &Metadata) -> bool {
        metadata.is_file()
            && self.length == metadata.len()
            && self.modified == metadata.modified().ok()
            && self.created == metadata.created().ok()
            && self.platform == platform_file_identity(metadata)
    }

    /// Checks the fields that identify the same fixed-size container while allowing expected
    /// modification-time changes caused by a writer holding exclusive access.
    pub(crate) fn matches_container_metadata(&self, metadata: &Metadata) -> bool {
        metadata.is_file()
            && self.length == metadata.len()
            && self.created == metadata.created().ok()
            && same_platform_file(&self.platform, metadata)
    }
}

/// Stable file-identity fields exposed by the host platform's standard library.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlatformFileIdentity {
    #[cfg(unix)]
    Unix { device: u64, inode: u64 },
    #[cfg(windows)]
    Windows {
        file_attributes: u32,
        creation_time: u64,
        last_write_time: u64,
    },
    #[cfg(not(any(unix, windows)))]
    Unavailable,
}

/// A regular image file opened without write, create, or truncate permissions.
#[derive(Debug)]
pub struct ImageFile {
    file: File,
    identity: ImageIdentity,
    max_read_bytes: usize,
}

impl ImageFile {
    /// Open a regular image file with [`DEFAULT_MAX_READ_BYTES`] as the per-read limit.
    ///
    /// # Errors
    ///
    /// Returns [`ImageError`] if the path is device-like, cannot be resolved or opened, is not a
    /// regular file, or changes while it is being opened.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ImageError> {
        Self::open_with_limit(path, DEFAULT_MAX_READ_BYTES)
    }

    /// Open a regular image file with a caller-selected non-zero per-read limit.
    ///
    /// # Errors
    ///
    /// Returns [`ImageError::InvalidReadLimit`] for a zero limit. Other failures have the same
    /// causes as [`ImageFile::open`].
    pub fn open_with_limit(
        path: impl AsRef<Path>,
        max_read_bytes: usize,
    ) -> Result<Self, ImageError> {
        if max_read_bytes == 0 {
            return Err(ImageError::InvalidReadLimit);
        }

        let requested_path = path.as_ref();
        reject_device_like_path(requested_path)?;

        let canonical_path = fs::canonicalize(requested_path)
            .map_err(|source| ImageError::io("canonicalize image path", source))?;
        reject_device_like_path(&canonical_path)?;

        // Validate before opening so obvious directories and special files are never handed to
        // File::open. The second metadata check below closes the ordinary replacement race.
        let path_metadata = fs::metadata(&canonical_path)
            .map_err(|source| ImageError::io("inspect image path", source))?;
        if !path_metadata.is_file() {
            return Err(ImageError::NotRegularFile {
                path: canonical_path,
            });
        }

        let file = OpenOptions::new()
            .read(true)
            .open(&canonical_path)
            .map_err(|source| ImageError::io("open image read-only", source))?;
        let file_metadata = file
            .metadata()
            .map_err(|source| ImageError::io("inspect opened image", source))?;
        if !file_metadata.is_file() {
            return Err(ImageError::NotRegularFile {
                path: canonical_path,
            });
        }

        let identity = ImageIdentity::from_metadata(canonical_path, &file_metadata);
        if !identity.matches_metadata(&path_metadata) {
            return Err(ImageError::SourceChanged);
        }

        Ok(Self {
            file,
            identity,
            max_read_bytes,
        })
    }

    /// Immutable identity captured from the opened file handle.
    #[must_use]
    pub const fn identity(&self) -> &ImageIdentity {
        &self.identity
    }

    /// Open-time image length in bytes.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.identity.length
    }

    /// Whether the image was empty when opened.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Maximum number of bytes accepted by a single read.
    #[must_use]
    pub const fn max_read_bytes(&self) -> usize {
        self.max_read_bytes
    }

    /// Read exactly `length` bytes at an absolute byte offset.
    ///
    /// The complete range is validated before allocation or I/O. A short underlying read is
    /// reported as truncation rather than silently returning partial data.
    ///
    /// # Errors
    ///
    /// Returns [`ImageError`] if the range overflows or exceeds the image, the request exceeds the
    /// configured limit, I/O fails, a short read occurs, or the open-time identity changes.
    pub fn read_exact_at(&self, offset: u64, length: usize) -> Result<Vec<u8>, ImageError> {
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

        if length > self.max_read_bytes {
            return Err(ImageError::ReadTooLarge {
                requested: length,
                maximum: self.max_read_bytes,
            });
        }
        if end > self.len() {
            return Err(ImageError::OutOfRange {
                offset,
                length: length_u64,
                image_length: self.len(),
            });
        }

        self.ensure_unchanged()?;
        let mut bytes = vec![0_u8; length];
        let actual = read_all_at(&self.file, offset, &mut bytes)
            .map_err(|source| ImageError::io("read image", source))?;
        if actual != length {
            return Err(ImageError::Truncated {
                offset,
                expected: length,
                actual,
            });
        }
        self.ensure_unchanged()?;
        Ok(bytes)
    }

    /// Read exactly `length` bytes from the start of the image.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`ImageFile::read_exact_at`].
    pub fn read_prefix(&self, length: usize) -> Result<Vec<u8>, ImageError> {
        self.read_exact_at(0, length)
    }

    /// Read the first logical sector using the caller's validated sector size.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`ImageFile::read_exact_at`].
    pub fn read_first_sector(&self, sector_bytes: usize) -> Result<Vec<u8>, ImageError> {
        self.read_prefix(sector_bytes)
    }

    /// Read one sector by index with checked multiplication and range validation.
    ///
    /// # Errors
    ///
    /// Returns [`ImageError::RangeOverflow`] if the sector offset cannot be represented, or any
    /// error documented by [`ImageFile::read_exact_at`].
    pub fn read_sector(
        &self,
        sector_index: u64,
        sector_bytes: usize,
    ) -> Result<Vec<u8>, ImageError> {
        let sector_bytes_u64 =
            u64::try_from(sector_bytes).map_err(|_| ImageError::RangeOverflow {
                offset: sector_index,
                length: u64::MAX,
            })?;
        let offset =
            sector_index
                .checked_mul(sector_bytes_u64)
                .ok_or(ImageError::RangeOverflow {
                    offset: sector_index,
                    length: sector_bytes_u64,
                })?;
        self.read_exact_at(offset, sector_bytes)
    }

    fn ensure_unchanged(&self) -> Result<(), ImageError> {
        let metadata = self
            .file
            .metadata()
            .map_err(|source| ImageError::io("revalidate opened image", source))?;
        if self.identity.matches_metadata(&metadata) {
            Ok(())
        } else {
            Err(ImageError::SourceChanged)
        }
    }
}

/// Failures from opening or reading an image.
#[derive(Debug)]
pub enum ImageError {
    Io {
        operation: &'static str,
        source: io::Error,
    },
    NotRegularFile {
        path: PathBuf,
    },
    DeviceLikePath {
        path: PathBuf,
    },
    InvalidReadLimit,
    RangeOverflow {
        offset: u64,
        length: u64,
    },
    OutOfRange {
        offset: u64,
        length: u64,
        image_length: u64,
    },
    ReadTooLarge {
        requested: usize,
        maximum: usize,
    },
    Truncated {
        offset: u64,
        expected: usize,
        actual: usize,
    },
    SourceChanged,
}

impl ImageError {
    const fn io(operation: &'static str, source: io::Error) -> Self {
        Self::Io { operation, source }
    }
}

impl fmt::Display for ImageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { operation, source } => write!(formatter, "{operation}: {source}"),
            Self::NotRegularFile { path } => {
                write!(formatter, "image is not a regular file: {}", path.display())
            }
            Self::DeviceLikePath { path } => write!(
                formatter,
                "raw devices and device namespaces are forbidden: {}",
                path.display()
            ),
            Self::InvalidReadLimit => formatter.write_str("image read limit must be non-zero"),
            Self::RangeOverflow { offset, length } => write!(
                formatter,
                "image range overflows u64: offset {offset}, length {length}"
            ),
            Self::OutOfRange {
                offset,
                length,
                image_length,
            } => write!(
                formatter,
                "image range is outside the file: offset {offset}, length {length}, image length {image_length}"
            ),
            Self::ReadTooLarge { requested, maximum } => write!(
                formatter,
                "image read of {requested} bytes exceeds the {maximum}-byte limit"
            ),
            Self::Truncated {
                offset,
                expected,
                actual,
            } => write!(
                formatter,
                "image was truncated while reading at offset {offset}: expected {expected} bytes, received {actual}"
            ),
            Self::SourceChanged => {
                formatter.write_str("image identity or metadata changed while it was open")
            }
        }
    }
}

impl std::error::Error for ImageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(unix)]
fn platform_file_identity(metadata: &Metadata) -> PlatformFileIdentity {
    use std::os::unix::fs::MetadataExt;

    PlatformFileIdentity::Unix {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

#[cfg(windows)]
fn platform_file_identity(metadata: &Metadata) -> PlatformFileIdentity {
    use std::os::windows::fs::MetadataExt;

    // Stronger by-handle volume/file identifiers are deferred until Rust exposes a stable API or
    // StarConverter gains a narrowly reviewed Windows platform layer.
    PlatformFileIdentity::Windows {
        file_attributes: metadata.file_attributes(),
        creation_time: metadata.creation_time(),
        last_write_time: metadata.last_write_time(),
    }
}

#[cfg(not(any(unix, windows)))]
fn platform_file_identity(_metadata: &Metadata) -> PlatformFileIdentity {
    PlatformFileIdentity::Unavailable
}

#[cfg(unix)]
fn read_all_at(file: &File, offset: u64, buffer: &mut [u8]) -> io::Result<usize> {
    use std::os::unix::fs::FileExt;

    read_all_with(buffer, |chunk, relative_offset| {
        file.read_at(chunk, offset + relative_offset)
    })
}

#[cfg(windows)]
fn read_all_at(file: &File, offset: u64, buffer: &mut [u8]) -> io::Result<usize> {
    use std::os::windows::fs::FileExt;

    read_all_with(buffer, |chunk, relative_offset| {
        file.seek_read(chunk, offset + relative_offset)
    })
}

#[cfg(not(any(unix, windows)))]
fn read_all_at(file: &File, offset: u64, buffer: &mut [u8]) -> io::Result<usize> {
    use std::io::{Read, Seek, SeekFrom};

    let mut clone = file.try_clone()?;
    clone.seek(SeekFrom::Start(offset))?;
    clone.read(buffer)
}

fn read_all_with(
    buffer: &mut [u8],
    mut read: impl FnMut(&mut [u8], u64) -> io::Result<usize>,
) -> io::Result<usize> {
    let mut actual = 0_usize;
    while actual < buffer.len() {
        let count = read(&mut buffer[actual..], actual as u64)?;
        if count == 0 {
            break;
        }
        actual += count;
    }
    Ok(actual)
}

pub(crate) fn reject_device_like_path(path: &Path) -> Result<(), ImageError> {
    if is_device_like_path(path) {
        Err(ImageError::DeviceLikePath {
            path: path.to_path_buf(),
        })
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn same_platform_file(expected: &PlatformFileIdentity, metadata: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    matches!(
        expected,
        PlatformFileIdentity::Unix { device, inode }
            if *device == metadata.dev() && *inode == metadata.ino()
    )
}

#[cfg(windows)]
fn same_platform_file(expected: &PlatformFileIdentity, metadata: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    matches!(
        expected,
        PlatformFileIdentity::Windows {
            creation_time,
            ..
        } if *creation_time == metadata.creation_time()
    )
}

#[cfg(not(any(unix, windows)))]
fn same_platform_file(expected: &PlatformFileIdentity, _metadata: &Metadata) -> bool {
    matches!(expected, PlatformFileIdentity::Unavailable)
}

fn is_device_like_path(path: &Path) -> bool {
    let normalized = path.to_string_lossy().replace('\\', "/");
    let lowercase = normalized.to_ascii_lowercase();

    #[cfg(unix)]
    if lowercase == "/dev" || lowercase.starts_with("/dev/") {
        return true;
    }

    #[cfg(windows)]
    {
        if lowercase.starts_with("//./")
            || lowercase.starts_with("//?/globalroot/")
            || lowercase.starts_with("//?/device/")
            || lowercase.starts_with("//?/physicaldrive")
            || lowercase.starts_with("//?/volume{")
        {
            return true;
        }

        if let Some(name) = path.file_name().and_then(|name| name.to_str()) {
            let stem = name
                .trim_end_matches([' ', '.'])
                .split('.')
                .next()
                .unwrap_or("")
                .to_ascii_uppercase();
            if matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$")
                || stem.strip_prefix("COM").is_some_and(|suffix| {
                    matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
                })
                || stem.strip_prefix("LPT").is_some_and(|suffix| {
                    matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
                })
            {
                return true;
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TempEntry {
        path: PathBuf,
        is_directory: bool,
    }

    impl TempEntry {
        fn file(contents: &[u8]) -> Self {
            let path = unique_temp_path("img");
            fs::write(&path, contents).expect("create temporary image");
            Self {
                path,
                is_directory: false,
            }
        }

        fn directory() -> Self {
            let path = unique_temp_path("dir");
            fs::create_dir(&path).expect("create temporary directory");
            Self {
                path,
                is_directory: true,
            }
        }
    }

    impl Drop for TempEntry {
        fn drop(&mut self) {
            if self.is_directory {
                let _ = fs::remove_dir(&self.path);
            } else {
                let _ = fs::remove_file(&self.path);
            }
        }
    }

    fn unique_temp_path(extension: &str) -> PathBuf {
        let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "starconverter-image-{}-{sequence}.{extension}",
            std::process::id()
        ))
    }

    #[test]
    fn reads_successful_offsets_and_conveniences() {
        let temp = TempEntry::file(b"0123456789abcdef");
        let image = ImageFile::open(&temp.path).expect("open image");

        assert_eq!(image.read_exact_at(4, 4).unwrap(), b"4567");
        assert_eq!(image.read_prefix(4).unwrap(), b"0123");
        assert_eq!(image.read_first_sector(8).unwrap(), b"01234567");
        assert_eq!(image.read_sector(2, 4).unwrap(), b"89ab");
    }

    #[test]
    fn rejects_ranges_past_eof() {
        let temp = TempEntry::file(b"four");
        let image = ImageFile::open(&temp.path).unwrap();

        assert!(matches!(
            image.read_exact_at(3, 2),
            Err(ImageError::OutOfRange {
                offset: 3,
                length: 2,
                image_length: 4
            })
        ));
        assert_eq!(image.read_exact_at(4, 0).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn rejects_offset_length_overflow() {
        let temp = TempEntry::file(b"x");
        let image = ImageFile::open(&temp.path).unwrap();

        assert!(matches!(
            image.read_exact_at(u64::MAX, 2),
            Err(ImageError::RangeOverflow { .. })
        ));
        assert!(matches!(
            image.read_sector(u64::MAX, 2),
            Err(ImageError::RangeOverflow { .. })
        ));
    }

    #[test]
    fn enforces_configured_read_cap_before_allocation() {
        let temp = TempEntry::file(b"01234567");
        let image = ImageFile::open_with_limit(&temp.path, 4).unwrap();

        assert!(matches!(
            image.read_exact_at(0, 5),
            Err(ImageError::ReadTooLarge {
                requested: 5,
                maximum: 4
            })
        ));
    }

    #[test]
    fn rejects_directories() {
        let temp = TempEntry::directory();

        assert!(matches!(
            ImageFile::open(&temp.path),
            Err(ImageError::NotRegularFile { .. })
        ));
    }

    #[test]
    fn identity_contains_canonical_path_length_and_platform_id() {
        let temp = TempEntry::file(b"identity");
        let image = ImageFile::open(&temp.path).unwrap();

        assert_eq!(
            image.identity().canonical_path(),
            fs::canonicalize(&temp.path).unwrap()
        );
        assert_eq!(image.identity().length(), 8);
        #[cfg(windows)]
        assert!(matches!(
            image.identity().platform(),
            PlatformFileIdentity::Windows { .. }
        ));
        #[cfg(unix)]
        assert!(matches!(
            image.identity().platform(),
            PlatformFileIdentity::Unix { .. }
        ));
    }

    #[test]
    fn detects_truncation_after_open() {
        let temp = TempEntry::file(b"original");
        let image = ImageFile::open(&temp.path).unwrap();
        fs::write(&temp.path, b"short").unwrap();

        assert!(matches!(
            image.read_exact_at(0, 1),
            Err(ImageError::SourceChanged)
        ));
    }

    #[test]
    fn rejects_zero_read_limit() {
        let temp = TempEntry::file(b"x");
        assert!(matches!(
            ImageFile::open_with_limit(&temp.path, 0),
            Err(ImageError::InvalidReadLimit)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_unix_device_namespace_without_opening_it() {
        assert!(matches!(
            ImageFile::open("/dev/null"),
            Err(ImageError::DeviceLikePath { .. })
        ));
    }

    #[cfg(windows)]
    #[test]
    fn rejects_windows_device_namespace_without_opening_it() {
        assert!(matches!(
            ImageFile::open(r"\\.\PhysicalDrive0"),
            Err(ImageError::DeviceLikePath { .. })
        ));
        assert!(matches!(
            ImageFile::open("NUL"),
            Err(ImageError::DeviceLikePath { .. })
        ));
    }
}
