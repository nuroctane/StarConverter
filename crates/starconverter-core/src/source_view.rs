//! Exact, bounded hashing of regular-image source views.
//!
//! A staged conversion may overwrite only plan-authorized ranges while the source filesystem
//! remains active. [`VirtualOriginalReader`] reconstructs the original byte view by substituting
//! exact rollback before-images selected by the coordinator for the current phase. Every byte
//! outside those ranges continues to come from the current base, so unrelated changes remain
//! visible to the digest.

use std::fmt;

use sha2::{Digest, Sha256};

use crate::image::{BoundedImageReader, ImageError};
use crate::overlay::OverlayWrite;

const SOURCE_VIEW_DOMAIN: &[u8] = b"starconverter/source-image-view/v1\0";

/// Explicit bounds for one complete source-view digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceDigestLimits {
    pub max_image_bytes: u64,
    pub chunk_bytes: usize,
}

/// Bounds for exact rollback substitutions in one virtual original view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtualOriginalLimits {
    pub max_writes: usize,
    pub max_masked_bytes: usize,
}

/// A current staged image read through exact, coordinator-selected rollback before-images.
#[derive(Debug)]
pub struct VirtualOriginalReader<'a> {
    base: &'a dyn BoundedImageReader,
    before_images: &'a [OverlayWrite],
}

impl<'a> VirtualOriginalReader<'a> {
    /// Borrows a canonical prepared rollback set after independently checking its resource and
    /// range invariants. The coordinator is responsible for selecting the rollback phases whose
    /// writes may already be present in `base`.
    pub fn new(
        base: &'a dyn BoundedImageReader,
        rollback_before_images: &'a [OverlayWrite],
        limits: VirtualOriginalLimits,
    ) -> Result<Self, SourceViewError> {
        validate_virtual_limits(limits)?;
        if rollback_before_images.len() > limits.max_writes {
            return Err(SourceViewError::MaskWriteLimitExceeded {
                actual: rollback_before_images.len(),
                maximum: limits.max_writes,
            });
        }
        validate_rollback_ranges(base.len(), rollback_before_images)?;

        let mut masked_bytes = 0_u64;
        for rollback in rollback_before_images {
            let rollback_length = u64::try_from(rollback.bytes.len())
                .map_err(|_| SourceViewError::ArithmeticOverflow)?;
            masked_bytes = masked_bytes
                .checked_add(rollback_length)
                .ok_or(SourceViewError::ArithmeticOverflow)?;
        }
        if masked_bytes > u64::try_from(limits.max_masked_bytes).unwrap_or(u64::MAX) {
            return Err(SourceViewError::MaskedByteLimitExceeded {
                actual: masked_bytes,
                maximum: limits.max_masked_bytes,
            });
        }

        Ok(Self {
            base,
            before_images: rollback_before_images,
        })
    }
}

impl BoundedImageReader for VirtualOriginalReader<'_> {
    fn len(&self) -> u64 {
        self.base.len()
    }

    fn max_read_bytes(&self) -> usize {
        self.base.max_read_bytes()
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
        let mut output = self.base.read_exact_at(offset, length)?;
        if output.len() != length {
            return Err(ImageError::Truncated {
                offset,
                expected: length,
                actual: output.len(),
            });
        }

        for write in self.before_images {
            if write.offset >= end {
                break;
            }
            let write_length =
                u64::try_from(write.bytes.len()).map_err(|_| ImageError::RangeOverflow {
                    offset: write.offset,
                    length: u64::MAX,
                })?;
            let write_end =
                write
                    .offset
                    .checked_add(write_length)
                    .ok_or(ImageError::RangeOverflow {
                        offset: write.offset,
                        length: write_length,
                    })?;
            let intersection_start = offset.max(write.offset);
            let intersection_end = end.min(write_end);
            if intersection_start >= intersection_end {
                continue;
            }
            let output_start = usize::try_from(intersection_start - offset).map_err(|_| {
                ImageError::RangeOverflow {
                    offset,
                    length: length_u64,
                }
            })?;
            let write_start = usize::try_from(intersection_start - write.offset).map_err(|_| {
                ImageError::RangeOverflow {
                    offset: write.offset,
                    length: write_length,
                }
            })?;
            let count = usize::try_from(intersection_end - intersection_start).map_err(|_| {
                ImageError::RangeOverflow {
                    offset,
                    length: length_u64,
                }
            })?;
            output[output_start..output_start + count]
                .copy_from_slice(&write.bytes[write_start..write_start + count]);
        }
        Ok(output)
    }
}

/// Hashes every byte of one fixed-size source view using a stable domain and length prefix.
pub fn digest_source_view(
    source: &dyn BoundedImageReader,
    limits: SourceDigestLimits,
) -> Result<[u8; 32], SourceViewError> {
    validate_digest_limits(limits)?;
    let image_bytes = source.len();
    if image_bytes > limits.max_image_bytes {
        return Err(SourceViewError::ImageByteLimitExceeded {
            actual: image_bytes,
            maximum: limits.max_image_bytes,
        });
    }
    let effective_chunk = limits.chunk_bytes.min(source.max_read_bytes());
    if effective_chunk == 0 {
        return Err(SourceViewError::InvalidLimit("reader max_read_bytes"));
    }

    let mut hasher = Sha256::new();
    hasher.update(SOURCE_VIEW_DOMAIN);
    hasher.update(image_bytes.to_le_bytes());
    let mut offset = 0_u64;
    let effective_chunk_u64 =
        u64::try_from(effective_chunk).map_err(|_| SourceViewError::ArithmeticOverflow)?;
    while offset < image_bytes {
        let remaining = image_bytes - offset;
        let count = usize::try_from(remaining.min(effective_chunk_u64))
            .map_err(|_| SourceViewError::ArithmeticOverflow)?;
        let bytes = source.read_exact_at(offset, count)?;
        if bytes.len() != count {
            return Err(SourceViewError::ShortRead {
                offset,
                expected: count,
                actual: bytes.len(),
            });
        }
        hasher.update(&bytes);
        offset = offset
            .checked_add(u64::try_from(count).map_err(|_| SourceViewError::ArithmeticOverflow)?)
            .ok_or(SourceViewError::ArithmeticOverflow)?;
    }
    Ok(hasher.finalize().into())
}

#[derive(Debug)]
pub enum SourceViewError {
    InvalidLimit(&'static str),
    ImageByteLimitExceeded {
        actual: u64,
        maximum: u64,
    },
    MaskWriteLimitExceeded {
        actual: usize,
        maximum: usize,
    },
    MaskedByteLimitExceeded {
        actual: u64,
        maximum: usize,
    },
    EmptyMask {
        offset: u64,
    },
    MaskOutsideImage {
        offset: u64,
        length: u64,
        image_bytes: u64,
    },
    OverlappingMasks {
        first_offset: u64,
        second_offset: u64,
    },
    MasksNotOrdered {
        previous_offset: u64,
        next_offset: u64,
    },
    ShortRead {
        offset: u64,
        expected: usize,
        actual: usize,
    },
    ArithmeticOverflow,
    Image(ImageError),
}

impl fmt::Display for SourceViewError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit(field) => write!(formatter, "source-view limit {field} is zero"),
            Self::ImageByteLimitExceeded { actual, maximum } => {
                write!(
                    formatter,
                    "source view has {actual} bytes, exceeding {maximum}"
                )
            }
            Self::MaskWriteLimitExceeded { actual, maximum } => write!(
                formatter,
                "source view has {actual} masked writes, exceeding {maximum}"
            ),
            Self::MaskedByteLimitExceeded { actual, maximum } => write!(
                formatter,
                "source view masks {actual} bytes, exceeding {maximum}"
            ),
            Self::EmptyMask { offset } => {
                write!(formatter, "source-view mask at {offset} is empty")
            }
            Self::MaskOutsideImage {
                offset,
                length,
                image_bytes,
            } => write!(
                formatter,
                "source-view mask {offset}+{length} exceeds {image_bytes}-byte image"
            ),
            Self::OverlappingMasks {
                first_offset,
                second_offset,
            } => write!(
                formatter,
                "source-view masks at {first_offset} and {second_offset} overlap"
            ),
            Self::MasksNotOrdered {
                previous_offset,
                next_offset,
            } => write!(
                formatter,
                "source-view masks are not ordered: {next_offset} follows {previous_offset}"
            ),
            Self::ShortRead {
                offset,
                expected,
                actual,
            } => write!(
                formatter,
                "source-view read at {offset} returned {actual} bytes, expected {expected}"
            ),
            Self::ArithmeticOverflow => formatter.write_str("source-view byte accounting overflow"),
            Self::Image(error) => write!(formatter, "source-view read failed: {error}"),
        }
    }
}

impl std::error::Error for SourceViewError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Self::Image(error) = self {
            Some(error)
        } else {
            None
        }
    }
}

impl From<ImageError> for SourceViewError {
    fn from(error: ImageError) -> Self {
        Self::Image(error)
    }
}

const fn validate_digest_limits(limits: SourceDigestLimits) -> Result<(), SourceViewError> {
    if limits.max_image_bytes == 0 {
        return Err(SourceViewError::InvalidLimit("max_image_bytes"));
    }
    if limits.chunk_bytes == 0 {
        return Err(SourceViewError::InvalidLimit("chunk_bytes"));
    }
    Ok(())
}

const fn validate_virtual_limits(limits: VirtualOriginalLimits) -> Result<(), SourceViewError> {
    if limits.max_writes == 0 {
        return Err(SourceViewError::InvalidLimit("max_writes"));
    }
    if limits.max_masked_bytes == 0 {
        return Err(SourceViewError::InvalidLimit("max_masked_bytes"));
    }
    Ok(())
}

fn validate_rollback_ranges(
    image_bytes: u64,
    writes: &[OverlayWrite],
) -> Result<(), SourceViewError> {
    for write in writes {
        validate_mask_range(image_bytes, write)?;
    }
    validate_nonoverlap(writes)
}

fn validate_mask_range(image_bytes: u64, write: &OverlayWrite) -> Result<(), SourceViewError> {
    if write.bytes.is_empty() {
        return Err(SourceViewError::EmptyMask {
            offset: write.offset,
        });
    }
    let length =
        u64::try_from(write.bytes.len()).map_err(|_| SourceViewError::ArithmeticOverflow)?;
    let end = write
        .offset
        .checked_add(length)
        .ok_or(SourceViewError::ArithmeticOverflow)?;
    if end > image_bytes {
        return Err(SourceViewError::MaskOutsideImage {
            offset: write.offset,
            length,
            image_bytes,
        });
    }
    Ok(())
}

fn validate_nonoverlap(writes: &[OverlayWrite]) -> Result<(), SourceViewError> {
    let mut previous: Option<&OverlayWrite> = None;
    for write in writes {
        if let Some(first) = previous {
            if first.offset >= write.offset {
                return Err(SourceViewError::MasksNotOrdered {
                    previous_offset: first.offset,
                    next_offset: write.offset,
                });
            }
            let first_length = u64::try_from(first.bytes.len())
                .map_err(|_| SourceViewError::ArithmeticOverflow)?;
            let first_end = first
                .offset
                .checked_add(first_length)
                .ok_or(SourceViewError::ArithmeticOverflow)?;
            if first_end > write.offset {
                return Err(SourceViewError::OverlappingMasks {
                    first_offset: first.offset,
                    second_offset: write.offset,
                });
            }
        }
        previous = Some(write);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::image::ImageFile;

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TempImage(PathBuf);

    impl TempImage {
        fn create(bytes: &[u8]) -> Self {
            let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "starconverter-source-view-{}-{sequence}.img",
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

    const fn digest_limits(chunk_bytes: usize) -> SourceDigestLimits {
        SourceDigestLimits {
            max_image_bytes: 4096,
            chunk_bytes,
        }
    }

    const fn virtual_limits() -> VirtualOriginalLimits {
        VirtualOriginalLimits {
            max_writes: 8,
            max_masked_bytes: 1024,
        }
    }

    #[test]
    fn digest_is_domain_length_and_exact_bytes_independent_of_chunking() {
        let bytes: Vec<u8> = (0_u8..=127).collect();
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open_with_limit(&temp.0, 11).unwrap();
        let one = digest_source_view(&image, digest_limits(7)).unwrap();
        let two = digest_source_view(&image, digest_limits(29)).unwrap();
        assert_eq!(one, two);

        let mut expected = Sha256::new();
        expected.update(SOURCE_VIEW_DOMAIN);
        expected.update(u64::try_from(bytes.len()).unwrap().to_le_bytes());
        expected.update(&bytes);
        assert_eq!(one, <[u8; 32]>::from(expected.finalize()));
    }

    #[test]
    fn digest_rejects_zero_and_image_limits() {
        let temp = TempImage::create(&[0x41; 32]);
        let image = ImageFile::open(&temp.0).unwrap();
        assert!(matches!(
            digest_source_view(
                &image,
                SourceDigestLimits {
                    max_image_bytes: 0,
                    chunk_bytes: 1,
                }
            ),
            Err(SourceViewError::InvalidLimit("max_image_bytes"))
        ));
        assert!(matches!(
            digest_source_view(
                &image,
                SourceDigestLimits {
                    max_image_bytes: 32,
                    chunk_bytes: 0,
                }
            ),
            Err(SourceViewError::InvalidLimit("chunk_bytes"))
        ));
        assert!(matches!(
            digest_source_view(
                &image,
                SourceDigestLimits {
                    max_image_bytes: 31,
                    chunk_bytes: 8,
                }
            ),
            Err(SourceViewError::ImageByteLimitExceeded { .. })
        ));
    }

    #[test]
    fn virtual_original_masks_only_prepared_rollback_ranges() {
        let original: Vec<u8> = (0_u8..64).collect();
        let rollback = vec![
            OverlayWrite {
                offset: 0,
                bytes: original[0..4].to_vec(),
            },
            OverlayWrite {
                offset: 16,
                bytes: original[16..20].to_vec(),
            },
            OverlayWrite {
                offset: 40,
                bytes: original[40..45].to_vec(),
            },
        ];
        let original_temp = TempImage::create(&original);
        let original_image = ImageFile::open(&original_temp.0).unwrap();
        let expected = digest_source_view(&original_image, digest_limits(13)).unwrap();

        let mut staged = original;
        staged[0..4].copy_from_slice(&[0xc3; 4]);
        staged[16..20].copy_from_slice(&[0xa1; 4]);
        staged[40..45].copy_from_slice(&[0xb2; 5]);
        let staged_temp = TempImage::create(&staged);
        let staged_image = ImageFile::open(&staged_temp.0).unwrap();
        let virtual_original =
            VirtualOriginalReader::new(&staged_image, &rollback, virtual_limits()).unwrap();
        assert_eq!(
            digest_source_view(&virtual_original, digest_limits(9)).unwrap(),
            expected
        );

        staged[7] ^= 0xff;
        let changed_temp = TempImage::create(&staged);
        let changed_image = ImageFile::open(&changed_temp.0).unwrap();
        let changed_view =
            VirtualOriginalReader::new(&changed_image, &rollback, virtual_limits()).unwrap();
        assert_ne!(
            digest_source_view(&changed_view, digest_limits(9)).unwrap(),
            expected
        );
    }

    #[test]
    fn virtual_original_rejects_invalid_unordered_and_over_limit_masks() {
        let temp = TempImage::create(&[0_u8; 64]);
        let image = ImageFile::open(&temp.0).unwrap();
        let overlap = vec![
            OverlayWrite {
                offset: 8,
                bytes: vec![0; 4],
            },
            OverlayWrite {
                offset: 10,
                bytes: vec![0; 4],
            },
        ];
        assert!(matches!(
            VirtualOriginalReader::new(&image, &overlap, virtual_limits()),
            Err(SourceViewError::OverlappingMasks { .. })
        ));

        let unordered = vec![
            OverlayWrite {
                offset: 24,
                bytes: vec![0; 4],
            },
            OverlayWrite {
                offset: 8,
                bytes: vec![0; 4],
            },
        ];
        assert!(matches!(
            VirtualOriginalReader::new(&image, &unordered, virtual_limits()),
            Err(SourceViewError::MasksNotOrdered { .. })
        ));

        let outside = vec![OverlayWrite {
            offset: 62,
            bytes: vec![0; 4],
        }];
        assert!(matches!(
            VirtualOriginalReader::new(&image, &outside, virtual_limits()),
            Err(SourceViewError::MaskOutsideImage { .. })
        ));

        let too_many = vec![
            OverlayWrite {
                offset: 8,
                bytes: vec![0; 4],
            },
            OverlayWrite {
                offset: 16,
                bytes: vec![0; 4],
            },
        ];
        assert!(matches!(
            VirtualOriginalReader::new(
                &image,
                &too_many,
                VirtualOriginalLimits {
                    max_writes: 1,
                    max_masked_bytes: 64,
                },
            ),
            Err(SourceViewError::MaskWriteLimitExceeded { .. })
        ));

        let four_bytes = vec![OverlayWrite {
            offset: 8,
            bytes: vec![0; 4],
        }];
        assert!(matches!(
            VirtualOriginalReader::new(
                &image,
                &four_bytes,
                VirtualOriginalLimits {
                    max_writes: 1,
                    max_masked_bytes: 3,
                },
            ),
            Err(SourceViewError::MaskedByteLimitExceeded { .. })
        ));
        assert!(matches!(
            VirtualOriginalReader::new(
                &image,
                &four_bytes,
                VirtualOriginalLimits {
                    max_writes: 0,
                    max_masked_bytes: 4,
                },
            ),
            Err(SourceViewError::InvalidLimit("max_writes"))
        ));
    }
}
