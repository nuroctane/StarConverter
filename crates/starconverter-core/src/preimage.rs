//! Bounded, read-only capture of exact source bytes for planned replacement ranges.
//!
//! This module accepts only an already validated regular [`ImageFile`]. It performs no writes and
//! turns each replacement range into an [`OverlayWrite`] containing the bytes that must be restored
//! if the corresponding transaction phase rolls back.

use std::fmt;

use crate::image::{BoundedImageReader, ImageError, ImageFile};
use crate::overlay::OverlayWrite;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreimageLimits {
    pub max_writes: usize,
    pub max_total_bytes: usize,
}

impl Default for PreimageLimits {
    fn default() -> Self {
        Self {
            max_writes: 2 * 1024 * 1024,
            max_total_bytes: 1024 * 1024 * 1024,
        }
    }
}

#[derive(Debug)]
pub enum PreimageError {
    InvalidLimit {
        field: &'static str,
    },
    WriteLimitExceeded {
        actual: usize,
        maximum: usize,
    },
    ByteLimitExceeded {
        actual: u64,
        maximum: usize,
    },
    EmptyWrite {
        offset: u64,
    },
    RangeOverflow {
        offset: u64,
        length: u64,
    },
    OverlappingWrites {
        first_offset: u64,
        second_offset: u64,
    },
    AllocationFailed,
    Image(ImageError),
}

impl fmt::Display for PreimageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit { field } => write!(formatter, "preimage limit {field} is zero"),
            Self::WriteLimitExceeded { actual, maximum } => {
                write!(
                    formatter,
                    "preimage has {actual} writes, exceeding {maximum}"
                )
            }
            Self::ByteLimitExceeded { actual, maximum } => {
                write!(
                    formatter,
                    "preimage has {actual} bytes, exceeding {maximum}"
                )
            }
            Self::EmptyWrite { offset } => write!(formatter, "replacement at {offset} is empty"),
            Self::RangeOverflow { offset, length } => {
                write!(formatter, "replacement range {offset}+{length} overflows")
            }
            Self::OverlappingWrites {
                first_offset,
                second_offset,
            } => write!(
                formatter,
                "replacement ranges at {first_offset} and {second_offset} overlap"
            ),
            Self::AllocationFailed => formatter.write_str("could not allocate bounded preimage"),
            Self::Image(source) => write!(formatter, "could not capture source preimage: {source}"),
        }
    }
}

impl std::error::Error for PreimageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Image(source) => Some(source),
            _ => None,
        }
    }
}

impl From<ImageError> for PreimageError {
    fn from(source: ImageError) -> Self {
        Self::Image(source)
    }
}

/// Reads exact before-images for nonempty, nonoverlapping replacement ranges.
///
/// Output is sorted by byte offset, making its subsequent overlay digest deterministic.
/// Large ranges are read in chunks no larger than the image backend's configured per-read cap.
///
/// # Errors
///
/// Refuses zero limits, excessive work or bytes, empty/overlapping/overflowing ranges, allocation
/// failure, out-of-image reads, and any image identity change detected during capture.
pub fn capture_before_images(
    image: &ImageFile,
    replacements: &[OverlayWrite],
    limits: PreimageLimits,
) -> Result<Vec<OverlayWrite>, PreimageError> {
    capture_before_images_with_reader(image, replacements, limits)
}

/// Shared bounded capture used by trusted readers that already pin the regular image handle.
pub(crate) fn capture_before_images_with_reader(
    image: &dyn BoundedImageReader,
    replacements: &[OverlayWrite],
    limits: PreimageLimits,
) -> Result<Vec<OverlayWrite>, PreimageError> {
    if limits.max_writes == 0 {
        return Err(PreimageError::InvalidLimit {
            field: "max_writes",
        });
    }
    if limits.max_total_bytes == 0 {
        return Err(PreimageError::InvalidLimit {
            field: "max_total_bytes",
        });
    }
    if replacements.len() > limits.max_writes {
        return Err(PreimageError::WriteLimitExceeded {
            actual: replacements.len(),
            maximum: limits.max_writes,
        });
    }

    let mut ordered = Vec::new();
    ordered
        .try_reserve_exact(replacements.len())
        .map_err(|_| PreimageError::AllocationFailed)?;
    ordered.extend(replacements);
    ordered.sort_unstable_by_key(|write| write.offset);

    let mut total = 0_u64;
    let mut prior: Option<(u64, u64)> = None;
    for write in &ordered {
        if write.bytes.is_empty() {
            return Err(PreimageError::EmptyWrite {
                offset: write.offset,
            });
        }
        let length =
            u64::try_from(write.bytes.len()).map_err(|_| PreimageError::RangeOverflow {
                offset: write.offset,
                length: u64::MAX,
            })?;
        let end = write
            .offset
            .checked_add(length)
            .ok_or(PreimageError::RangeOverflow {
                offset: write.offset,
                length,
            })?;
        if let Some((prior_offset, prior_end)) = prior {
            if write.offset < prior_end {
                return Err(PreimageError::OverlappingWrites {
                    first_offset: prior_offset,
                    second_offset: write.offset,
                });
            }
        }
        prior = Some((write.offset, end));
        total = total
            .checked_add(length)
            .ok_or(PreimageError::ByteLimitExceeded {
                actual: u64::MAX,
                maximum: limits.max_total_bytes,
            })?;
    }
    if total > u64::try_from(limits.max_total_bytes).unwrap_or(u64::MAX) {
        return Err(PreimageError::ByteLimitExceeded {
            actual: total,
            maximum: limits.max_total_bytes,
        });
    }

    let mut output = Vec::new();
    output
        .try_reserve_exact(ordered.len())
        .map_err(|_| PreimageError::AllocationFailed)?;
    for replacement in ordered {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(replacement.bytes.len())
            .map_err(|_| PreimageError::AllocationFailed)?;
        let mut read_offset = replacement.offset;
        let mut remaining = replacement.bytes.len();
        while remaining != 0 {
            let chunk_length = remaining.min(image.max_read_bytes());
            let chunk = image.read_exact_at(read_offset, chunk_length)?;
            bytes.extend_from_slice(&chunk);
            read_offset = read_offset
                .checked_add(u64::try_from(chunk_length).map_err(|_| {
                    PreimageError::RangeOverflow {
                        offset: read_offset,
                        length: u64::MAX,
                    }
                })?)
                .ok_or_else(|| PreimageError::RangeOverflow {
                    offset: read_offset,
                    length: u64::try_from(chunk_length).unwrap_or(u64::MAX),
                })?;
            remaining -= chunk_length;
        }
        output.push(OverlayWrite {
            offset: replacement.offset,
            bytes,
        });
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::io::Write;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn image_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("starconverter-preimage-{label}-{nonce}.img"))
    }

    #[test]
    fn captures_sorted_chunked_before_images_without_mutation() {
        let path = image_path("capture");
        let original: Vec<u8> = (0_u8..=255).cycle().take(4096).collect();
        File::create(&path).unwrap().write_all(&original).unwrap();
        let image = ImageFile::open_with_limit(&path, 128).unwrap();
        let captured = capture_before_images(
            &image,
            &[
                OverlayWrite {
                    offset: 2048,
                    bytes: vec![9; 512],
                },
                OverlayWrite {
                    offset: 256,
                    bytes: vec![8; 768],
                },
            ],
            PreimageLimits::default(),
        )
        .unwrap();
        assert_eq!(captured[0].offset, 256);
        assert_eq!(captured[0].bytes, original[256..1024]);
        assert_eq!(captured[1].bytes, original[2048..2560]);
        assert_eq!(fs::read(&path).unwrap(), original);
        drop(image);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn refuses_overlap_caps_empty_and_out_of_range() {
        let path = image_path("refuse");
        File::create(&path)
            .unwrap()
            .write_all(&[0_u8; 1024])
            .unwrap();
        let image = ImageFile::open(&path).unwrap();
        let write = |offset, length| OverlayWrite {
            offset,
            bytes: vec![1; length],
        };
        assert!(matches!(
            capture_before_images(
                &image,
                &[write(0, 512), write(256, 512)],
                PreimageLimits::default()
            ),
            Err(PreimageError::OverlappingWrites { .. })
        ));
        assert!(matches!(
            capture_before_images(&image, &[write(0, 0)], PreimageLimits::default()),
            Err(PreimageError::EmptyWrite { .. })
        ));
        assert!(matches!(
            capture_before_images(
                &image,
                &[write(0, 513)],
                PreimageLimits {
                    max_writes: 1,
                    max_total_bytes: 512
                }
            ),
            Err(PreimageError::ByteLimitExceeded { .. })
        ));
        assert!(matches!(
            capture_before_images(&image, &[write(768, 512)], PreimageLimits::default()),
            Err(PreimageError::Image(ImageError::OutOfRange { .. }))
        ));
        drop(image);
        fs::remove_file(path).unwrap();
    }
}
