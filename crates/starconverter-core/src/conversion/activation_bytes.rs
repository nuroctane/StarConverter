//! Bounded exact-byte classification for one trusted conversion write group.
//!
//! This module owns no path, file handle, or mutation capability. It validates canonical paired
//! before/after ranges and observes them only through [`BoundedImageReader`].

use std::fmt;

use crate::image::{BoundedImageReader, ImageError};
use crate::overlay::OverlayWrite;

use super::ReservedWrite;

/// Aggregate and per-read bounds for one classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActivationByteLimits {
    /// Maximum number of paired ranges.
    pub write_count: usize,
    /// Maximum logical bytes covered by the group.
    pub write_bytes: usize,
    /// Maximum bytes requested by any single read.
    pub read_bytes: usize,
}

/// Exact relationship between the observed ranges and their prepared before/after bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationByteState {
    /// Every observed byte equals its before-image byte.
    ExactBefore,
    /// The group is not `ExactBefore`, and every observed byte equals its after-image byte.
    ExactAfter,
    /// Every observed byte is either its before- or after-image byte, but the group equals neither
    /// complete image. This includes torn writes within a range and before/after mixtures across
    /// ranges.
    MixedBeforeAfter,
    /// At least one observed byte equals neither its before- nor after-image byte.
    ThirdState,
}

/// Which half of a prepared exact-byte pair violated canonical range rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteImageSide {
    Before,
    After,
}

/// Validation or bounded observation failure.
#[derive(Debug)]
pub enum ActivationByteError {
    InvalidLimit(&'static str),
    EmptyGroup,
    WriteCountMismatch {
        before: usize,
        after: usize,
    },
    WriteLimitExceeded {
        actual: usize,
        maximum: usize,
    },
    EmptyWrite {
        side: ByteImageSide,
        index: usize,
        offset: u64,
    },
    RangesNotOrdered {
        side: ByteImageSide,
        previous_offset: u64,
        next_offset: u64,
    },
    OverlappingRanges {
        side: ByteImageSide,
        first_offset: u64,
        second_offset: u64,
    },
    RangeOutsideImage {
        side: ByteImageSide,
        index: usize,
        offset: u64,
        length: u64,
        image_bytes: u64,
    },
    RangeMismatch {
        index: usize,
        before_offset: u64,
        before_length: u64,
        after_offset: u64,
        after_length: u64,
    },
    WriteByteLimitExceeded {
        actual: u64,
        maximum: usize,
    },
    ShortRead {
        offset: u64,
        expected: usize,
        actual: usize,
    },
    ArithmeticOverflow,
    Image(ImageError),
}

impl fmt::Display for ActivationByteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit(field) => {
                write!(formatter, "activation-byte limit {field} is zero")
            }
            Self::EmptyGroup => formatter.write_str("activation-byte write group is empty"),
            Self::WriteCountMismatch { before, after } => write!(
                formatter,
                "before-image has {before} writes but after-image has {after}"
            ),
            Self::WriteLimitExceeded { actual, maximum } => write!(
                formatter,
                "activation-byte group has {actual} writes, exceeding {maximum}"
            ),
            Self::EmptyWrite {
                side,
                index,
                offset,
            } => write!(formatter, "{side:?} write {index} at {offset} has no bytes"),
            Self::RangesNotOrdered {
                side,
                previous_offset,
                next_offset,
            } => write!(
                formatter,
                "{side:?} ranges are not ordered: {next_offset} follows {previous_offset}"
            ),
            Self::OverlappingRanges {
                side,
                first_offset,
                second_offset,
            } => write!(
                formatter,
                "{side:?} ranges at {first_offset} and {second_offset} overlap"
            ),
            Self::RangeOutsideImage {
                side,
                index,
                offset,
                length,
                image_bytes,
            } => write!(
                formatter,
                "{side:?} write {index} range {offset}+{length} exceeds {image_bytes}-byte image"
            ),
            Self::RangeMismatch {
                index,
                before_offset,
                before_length,
                after_offset,
                after_length,
            } => write!(
                formatter,
                "write {index} before range {before_offset}+{before_length} does not match after range {after_offset}+{after_length}"
            ),
            Self::WriteByteLimitExceeded { actual, maximum } => write!(
                formatter,
                "activation-byte group covers {actual} bytes, exceeding {maximum}"
            ),
            Self::ShortRead {
                offset,
                expected,
                actual,
            } => write!(
                formatter,
                "activation-byte read at {offset} returned {actual} bytes, expected {expected}"
            ),
            Self::ArithmeticOverflow => {
                formatter.write_str("activation-byte range arithmetic overflow")
            }
            Self::Image(error) => write!(formatter, "activation-byte read failed: {error}"),
        }
    }
}

impl std::error::Error for ActivationByteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Self::Image(error) = self {
            Some(error)
        } else {
            None
        }
    }
}

impl From<ImageError> for ActivationByteError {
    fn from(error: ImageError) -> Self {
        Self::Image(error)
    }
}

/// Classifies a complete authorized write group without exposing a mutation capability.
///
/// Identical before/after groups deterministically classify as [`ActivationByteState::ExactBefore`].
#[cfg(test)]
fn classify_authorized_write_group(
    reader: &dyn BoundedImageReader,
    before: &[OverlayWrite],
    after: &[OverlayWrite],
    limits: ActivationByteLimits,
) -> Result<ActivationByteState, ActivationByteError> {
    classify_write_group(reader, before, after, limits)
}

/// Classifies a prepared group whose after-images retain their reservation proof, without cloning
/// any payload bytes during restart reconciliation.
pub fn classify_reserved_write_group(
    reader: &dyn BoundedImageReader,
    before: &[OverlayWrite],
    after: &[ReservedWrite],
    limits: ActivationByteLimits,
) -> Result<ActivationByteState, ActivationByteError> {
    classify_write_group(reader, before, after, limits)
}

trait CanonicalWrite {
    fn offset(&self) -> u64;
    fn bytes(&self) -> &[u8];
}

impl CanonicalWrite for OverlayWrite {
    fn offset(&self) -> u64 {
        self.offset
    }

    fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl CanonicalWrite for ReservedWrite {
    fn offset(&self) -> u64 {
        self.write.offset
    }

    fn bytes(&self) -> &[u8] {
        &self.write.bytes
    }
}

fn classify_write_group<A: CanonicalWrite>(
    reader: &dyn BoundedImageReader,
    before: &[OverlayWrite],
    after: &[A],
    limits: ActivationByteLimits,
) -> Result<ActivationByteState, ActivationByteError> {
    validate_limits(limits)?;
    if before.is_empty() || after.is_empty() {
        return Err(ActivationByteError::EmptyGroup);
    }
    if before.len() != after.len() {
        return Err(ActivationByteError::WriteCountMismatch {
            before: before.len(),
            after: after.len(),
        });
    }
    if before.len() > limits.write_count {
        return Err(ActivationByteError::WriteLimitExceeded {
            actual: before.len(),
            maximum: limits.write_count,
        });
    }

    let image_bytes = reader.len();
    validate_ranges(before, ByteImageSide::Before, image_bytes)?;
    validate_ranges(after, ByteImageSide::After, image_bytes)?;

    let mut total_bytes = 0_u64;
    for (index, (before_write, after_write)) in before.iter().zip(after).enumerate() {
        let before_length = write_length(before_write)?;
        let after_length = write_length(after_write)?;
        if before_write.offset() != after_write.offset() || before_length != after_length {
            return Err(ActivationByteError::RangeMismatch {
                index,
                before_offset: before_write.offset(),
                before_length,
                after_offset: after_write.offset(),
                after_length,
            });
        }
        total_bytes = total_bytes
            .checked_add(before_length)
            .ok_or(ActivationByteError::ArithmeticOverflow)?;
    }
    if total_bytes > u64::try_from(limits.write_bytes).unwrap_or(u64::MAX) {
        return Err(ActivationByteError::WriteByteLimitExceeded {
            actual: total_bytes,
            maximum: limits.write_bytes,
        });
    }

    let chunk_bytes = limits.read_bytes.min(reader.max_read_bytes());
    if chunk_bytes == 0 {
        return Err(ActivationByteError::InvalidLimit("reader max_read_bytes"));
    }
    let chunk_bytes_u64 =
        u64::try_from(chunk_bytes).map_err(|_| ActivationByteError::ArithmeticOverflow)?;

    let mut exact_before = true;
    let mut exact_after = true;
    let mut only_before_or_after = true;
    for (before_write, after_write) in before.iter().zip(after) {
        let write_bytes = write_length(before_write)?;
        let mut relative = 0_u64;
        while relative < write_bytes {
            let remaining = write_bytes - relative;
            let count = usize::try_from(remaining.min(chunk_bytes_u64))
                .map_err(|_| ActivationByteError::ArithmeticOverflow)?;
            let offset = before_write
                .offset()
                .checked_add(relative)
                .ok_or(ActivationByteError::ArithmeticOverflow)?;
            let observed = reader.read_exact_at(offset, count)?;
            if observed.len() != count {
                return Err(ActivationByteError::ShortRead {
                    offset,
                    expected: count,
                    actual: observed.len(),
                });
            }
            let start =
                usize::try_from(relative).map_err(|_| ActivationByteError::ArithmeticOverflow)?;
            let end = start
                .checked_add(count)
                .ok_or(ActivationByteError::ArithmeticOverflow)?;
            let before_chunk = &before_write.bytes()[start..end];
            let after_chunk = &after_write.bytes()[start..end];
            exact_before &= observed == before_chunk;
            exact_after &= observed == after_chunk;
            only_before_or_after &= observed.iter().zip(before_chunk).zip(after_chunk).all(
                |((&actual, &before_byte), &after_byte)| {
                    actual == before_byte || actual == after_byte
                },
            );
            relative = relative
                .checked_add(
                    u64::try_from(count).map_err(|_| ActivationByteError::ArithmeticOverflow)?,
                )
                .ok_or(ActivationByteError::ArithmeticOverflow)?;
        }
    }

    Ok(if exact_before {
        ActivationByteState::ExactBefore
    } else if exact_after {
        ActivationByteState::ExactAfter
    } else if only_before_or_after {
        ActivationByteState::MixedBeforeAfter
    } else {
        ActivationByteState::ThirdState
    })
}

const fn validate_limits(limits: ActivationByteLimits) -> Result<(), ActivationByteError> {
    if limits.write_count == 0 {
        return Err(ActivationByteError::InvalidLimit("max_writes"));
    }
    if limits.write_bytes == 0 {
        return Err(ActivationByteError::InvalidLimit("max_write_bytes"));
    }
    if limits.read_bytes == 0 {
        return Err(ActivationByteError::InvalidLimit("max_read_bytes"));
    }
    Ok(())
}

fn validate_ranges<W: CanonicalWrite>(
    writes: &[W],
    side: ByteImageSide,
    image_bytes: u64,
) -> Result<(), ActivationByteError> {
    let mut previous: Option<&W> = None;
    for (index, write) in writes.iter().enumerate() {
        if write.bytes().is_empty() {
            return Err(ActivationByteError::EmptyWrite {
                side,
                index,
                offset: write.offset(),
            });
        }
        let length = write_length(write)?;
        let end = write
            .offset()
            .checked_add(length)
            .ok_or(ActivationByteError::ArithmeticOverflow)?;
        if end > image_bytes {
            return Err(ActivationByteError::RangeOutsideImage {
                side,
                index,
                offset: write.offset(),
                length,
                image_bytes,
            });
        }
        if let Some(first) = previous {
            if first.offset() >= write.offset() {
                return Err(ActivationByteError::RangesNotOrdered {
                    side,
                    previous_offset: first.offset(),
                    next_offset: write.offset(),
                });
            }
            let first_end = first
                .offset()
                .checked_add(write_length(first)?)
                .ok_or(ActivationByteError::ArithmeticOverflow)?;
            if first_end > write.offset() {
                return Err(ActivationByteError::OverlappingRanges {
                    side,
                    first_offset: first.offset(),
                    second_offset: write.offset(),
                });
            }
        }
        previous = Some(write);
    }
    Ok(())
}

fn write_length<W: CanonicalWrite>(write: &W) -> Result<u64, ActivationByteError> {
    u64::try_from(write.bytes().len()).map_err(|_| ActivationByteError::ArithmeticOverflow)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
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
                "starconverter-activation-bytes-{}-{sequence}.img",
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

    #[derive(Debug)]
    struct RecordingReader<'a> {
        image: &'a ImageFile,
        reads: RefCell<Vec<(u64, usize)>>,
    }

    impl BoundedImageReader for RecordingReader<'_> {
        fn len(&self) -> u64 {
            BoundedImageReader::len(self.image)
        }

        fn max_read_bytes(&self) -> usize {
            BoundedImageReader::max_read_bytes(self.image)
        }

        fn read_exact_at(&self, offset: u64, length: usize) -> Result<Vec<u8>, ImageError> {
            self.reads.borrow_mut().push((offset, length));
            BoundedImageReader::read_exact_at(self.image, offset, length)
        }
    }

    const fn limits() -> ActivationByteLimits {
        ActivationByteLimits {
            write_count: 8,
            write_bytes: 1024,
            read_bytes: 3,
        }
    }

    fn write(offset: u64, bytes: &[u8]) -> OverlayWrite {
        OverlayWrite {
            offset,
            bytes: bytes.to_vec(),
        }
    }

    fn classify(
        observed: &[u8],
        before: &[OverlayWrite],
        after: &[OverlayWrite],
    ) -> ActivationByteState {
        let temp = TempImage::create(observed);
        let image = ImageFile::open(&temp.0).unwrap();
        classify_authorized_write_group(&image, before, after, limits()).unwrap()
    }

    #[test]
    fn classifies_exact_before_exact_after_and_identical_with_before_precedence() {
        let before = vec![write(2, &[1, 2, 3, 4])];
        let after = vec![write(2, &[5, 6, 7, 8])];
        assert_eq!(
            classify(&[0, 0, 1, 2, 3, 4, 0, 0], &before, &after),
            ActivationByteState::ExactBefore
        );
        assert_eq!(
            classify(&[0, 0, 5, 6, 7, 8, 0, 0], &before, &after),
            ActivationByteState::ExactAfter
        );
        assert_eq!(
            classify(&[0, 0, 1, 2, 3, 4, 0, 0], &before, &before),
            ActivationByteState::ExactBefore
        );
    }

    #[test]
    fn classifies_multi_range_mixture_and_torn_single_range() {
        let before = vec![write(1, &[1, 1, 1]), write(8, &[2, 2, 2, 2])];
        let after = vec![write(1, &[3, 3, 3]), write(8, &[4, 4, 4, 4])];
        let mut across_ranges = vec![0_u8; 16];
        across_ranges[1..4].copy_from_slice(&before[0].bytes);
        across_ranges[8..12].copy_from_slice(&after[1].bytes);
        assert_eq!(
            classify(&across_ranges, &before, &after),
            ActivationByteState::MixedBeforeAfter
        );

        let mut torn = vec![0_u8; 16];
        torn[1..4].copy_from_slice(&[1, 3, 1]);
        torn[8..12].copy_from_slice(&before[1].bytes);
        assert_eq!(
            classify(&torn, &before, &after),
            ActivationByteState::MixedBeforeAfter
        );
    }

    #[test]
    fn any_unrecognized_byte_makes_the_complete_group_third_state() {
        let before = vec![write(2, &[0x10; 4]), write(10, &[0x20; 3])];
        let after = vec![write(2, &[0x30; 4]), write(10, &[0x40; 3])];
        let mut observed = vec![0_u8; 16];
        observed[2..6].copy_from_slice(&[0x10, 0x30, 0x99, 0x10]);
        observed[10..13].copy_from_slice(&after[1].bytes);
        assert_eq!(
            classify(&observed, &before, &after),
            ActivationByteState::ThirdState
        );
    }

    #[test]
    fn enforces_canonical_matching_ranges_and_overflow() {
        let temp = TempImage::create(&[0_u8; 32]);
        let image = ImageFile::open(&temp.0).unwrap();
        let canonical = vec![write(4, &[0; 4]), write(16, &[0; 4])];

        assert!(matches!(
            classify_authorized_write_group(&image, &[], &[], limits()),
            Err(ActivationByteError::EmptyGroup)
        ));
        assert!(matches!(
            classify_authorized_write_group(&image, &canonical, &canonical[..1], limits()),
            Err(ActivationByteError::WriteCountMismatch { .. })
        ));
        let empty = vec![write(4, &[])];
        assert!(matches!(
            classify_authorized_write_group(&image, &empty, &empty, limits()),
            Err(ActivationByteError::EmptyWrite { .. })
        ));
        let unordered = vec![write(16, &[0; 4]), write(4, &[0; 4])];
        assert!(matches!(
            classify_authorized_write_group(&image, &unordered, &unordered, limits()),
            Err(ActivationByteError::RangesNotOrdered { .. })
        ));
        let overlap = vec![write(4, &[0; 4]), write(6, &[0; 4])];
        assert!(matches!(
            classify_authorized_write_group(&image, &overlap, &overlap, limits()),
            Err(ActivationByteError::OverlappingRanges { .. })
        ));
        let mismatch = vec![write(4, &[0; 3]), write(16, &[0; 4])];
        assert!(matches!(
            classify_authorized_write_group(&image, &canonical, &mismatch, limits()),
            Err(ActivationByteError::RangeMismatch { .. })
        ));
        let offset_mismatch = vec![write(5, &[0; 4]), write(16, &[0; 4])];
        assert!(matches!(
            classify_authorized_write_group(&image, &canonical, &offset_mismatch, limits()),
            Err(ActivationByteError::RangeMismatch { .. })
        ));
        let outside = vec![write(30, &[0; 4])];
        assert!(matches!(
            classify_authorized_write_group(&image, &outside, &outside, limits()),
            Err(ActivationByteError::RangeOutsideImage { .. })
        ));
        let overflow = vec![write(u64::MAX - 1, &[0; 4])];
        assert!(matches!(
            classify_authorized_write_group(&image, &overflow, &overflow, limits()),
            Err(ActivationByteError::ArithmeticOverflow)
        ));
    }

    #[test]
    fn enforces_all_caps_and_never_exceeds_effective_read_limit() {
        let bytes = vec![0x5a; 32];
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open_with_limit(&temp.0, 5).unwrap();
        let recording = RecordingReader {
            image: &image,
            reads: RefCell::new(Vec::new()),
        };
        let group = vec![write(4, &[0x5a; 7])];
        assert_eq!(
            classify_authorized_write_group(
                &recording,
                &group,
                &group,
                ActivationByteLimits {
                    read_bytes: 2,
                    ..limits()
                },
            )
            .unwrap(),
            ActivationByteState::ExactBefore
        );
        let reads = recording.reads.borrow();
        assert_eq!(reads.iter().map(|(_, length)| *length).max(), Some(2));
        assert_eq!(reads.iter().map(|(_, length)| *length).sum::<usize>(), 7);

        assert!(matches!(
            classify_authorized_write_group(
                &image,
                &group,
                &group,
                ActivationByteLimits {
                    write_count: 0,
                    ..limits()
                },
            ),
            Err(ActivationByteError::InvalidLimit("max_writes"))
        ));
        assert!(matches!(
            classify_authorized_write_group(
                &image,
                &group,
                &group,
                ActivationByteLimits {
                    write_bytes: 0,
                    ..limits()
                },
            ),
            Err(ActivationByteError::InvalidLimit("max_write_bytes"))
        ));
        assert!(matches!(
            classify_authorized_write_group(
                &image,
                &group,
                &group,
                ActivationByteLimits {
                    read_bytes: 0,
                    ..limits()
                },
            ),
            Err(ActivationByteError::InvalidLimit("max_read_bytes"))
        ));
        assert!(matches!(
            classify_authorized_write_group(
                &image,
                &group,
                &group,
                ActivationByteLimits {
                    write_count: 1,
                    write_bytes: 6,
                    read_bytes: 2,
                },
            ),
            Err(ActivationByteError::WriteByteLimitExceeded { .. })
        ));
        let two_writes = vec![write(4, &[0x5a; 2]), write(10, &[0x5a; 2])];
        assert!(matches!(
            classify_authorized_write_group(
                &image,
                &two_writes,
                &two_writes,
                ActivationByteLimits {
                    write_count: 1,
                    ..limits()
                },
            ),
            Err(ActivationByteError::WriteLimitExceeded { .. })
        ));
    }

    #[test]
    fn classification_does_not_mutate_the_regular_image() {
        let bytes: Vec<u8> = (0_u8..64).collect();
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();
        let before = vec![write(8, &bytes[8..16])];
        let after = vec![write(8, &[0xff; 8])];
        let disk_before = fs::read(&temp.0).unwrap();

        assert_eq!(
            classify_authorized_write_group(&image, &before, &after, limits()).unwrap(),
            ActivationByteState::ExactBefore
        );
        assert_eq!(fs::read(&temp.0).unwrap(), disk_before);
    }
}
