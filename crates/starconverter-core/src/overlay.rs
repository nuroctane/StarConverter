//! Bounded immutable overlay views for candidate filesystem verification.
//!
//! A validated overlay combines a regular read-only image with non-overlapping replacement byte
//! ranges. Consumers can run the same parsers against the virtual candidate without mutating the
//! base image. Durable transaction ordering is intentionally outside this module.

use std::fmt;

use crate::image::{BoundedImageReader, ImageError, ImageFile};

/// One final replacement range in a candidate image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayWrite {
    pub offset: u64,
    pub bytes: Vec<u8>,
}

/// Caller-controlled overlay bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverlayLimits {
    pub max_writes: usize,
    pub max_replacement_bytes: usize,
    pub max_read_bytes: usize,
}

impl Default for OverlayLimits {
    fn default() -> Self {
        Self {
            max_writes: 1_048_576,
            max_replacement_bytes: 512 * 1024 * 1024,
            max_read_bytes: 16 * 1024 * 1024,
        }
    }
}

/// Validated, deterministically ordered candidate replacements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayPlan {
    image_bytes: u64,
    sector_bytes: u32,
    writes: Vec<OverlayWrite>,
    replacement_bytes: u64,
    max_read_bytes: usize,
}

/// Crate-owned read-only view of one validated overlay over its pinned regular-file base.
///
/// Construction proves the base length matches the plan. The capability exposes no identity,
/// handle, path, seek state, or mutation API, so parsers can consume candidate bytes without being
/// able to manufacture trusted conversion evidence.
#[derive(Debug)]
pub(crate) struct OverlayReader<'a> {
    base: &'a dyn BoundedImageReader,
    plan: &'a OverlayPlan,
}

impl OverlayPlan {
    /// Validates and orders a complete set of final candidate writes.
    ///
    /// # Errors
    ///
    /// Rejects invalid limits or sector geometry, empty/unaligned/out-of-image writes, overlapping
    /// replacements, byte-accounting overflow, and cap exhaustion.
    pub fn build(
        image_bytes: u64,
        sector_bytes: u32,
        mut writes: Vec<OverlayWrite>,
        limits: OverlayLimits,
    ) -> Result<Self, OverlayError> {
        validate_limits(limits)?;
        if sector_bytes == 0 || !sector_bytes.is_power_of_two() {
            return Err(OverlayError::InvalidSectorSize { sector_bytes });
        }
        if writes.len() > limits.max_writes {
            return Err(OverlayError::WriteLimitExceeded {
                actual: writes.len(),
                maximum: limits.max_writes,
            });
        }
        let sector = u64::from(sector_bytes);
        let mut replacement_bytes = 0_u64;
        for write in &writes {
            if write.bytes.is_empty() {
                return Err(OverlayError::EmptyWrite {
                    offset: write.offset,
                });
            }
            let length =
                u64::try_from(write.bytes.len()).map_err(|_| OverlayError::ArithmeticOverflow)?;
            if write.offset % sector != 0 || length % sector != 0 {
                return Err(OverlayError::UnalignedWrite {
                    offset: write.offset,
                    length,
                    sector_bytes,
                });
            }
            let end = write
                .offset
                .checked_add(length)
                .ok_or(OverlayError::ArithmeticOverflow)?;
            if end > image_bytes {
                return Err(OverlayError::WriteOutsideImage {
                    offset: write.offset,
                    length,
                    image_bytes,
                });
            }
            replacement_bytes = replacement_bytes
                .checked_add(length)
                .ok_or(OverlayError::ArithmeticOverflow)?;
        }
        let replacement_usize = usize::try_from(replacement_bytes).unwrap_or(usize::MAX);
        if replacement_usize > limits.max_replacement_bytes {
            return Err(OverlayError::ReplacementLimitExceeded {
                actual: replacement_bytes,
                maximum: limits.max_replacement_bytes,
            });
        }
        writes.sort_unstable_by_key(|write| write.offset);
        for pair in writes.windows(2) {
            let first_length =
                u64::try_from(pair[0].bytes.len()).map_err(|_| OverlayError::ArithmeticOverflow)?;
            let first_end = pair[0]
                .offset
                .checked_add(first_length)
                .ok_or(OverlayError::ArithmeticOverflow)?;
            if first_end > pair[1].offset {
                return Err(OverlayError::OverlappingWrites {
                    first_offset: pair[0].offset,
                    second_offset: pair[1].offset,
                });
            }
        }
        Ok(Self {
            image_bytes,
            sector_bytes,
            writes,
            replacement_bytes,
            max_read_bytes: limits.max_read_bytes,
        })
    }

    #[must_use]
    pub const fn image_bytes(&self) -> u64 {
        self.image_bytes
    }

    #[must_use]
    pub const fn sector_bytes(&self) -> u32 {
        self.sector_bytes
    }

    #[must_use]
    pub fn writes(&self) -> &[OverlayWrite] {
        &self.writes
    }

    #[must_use]
    pub const fn replacement_bytes(&self) -> u64 {
        self.replacement_bytes
    }

    /// Creates a bounded candidate reader after binding this plan to an equal-length base image.
    pub(crate) fn reader<'a>(
        &'a self,
        base: &'a dyn BoundedImageReader,
    ) -> Result<OverlayReader<'a>, OverlayError> {
        if base.len() != self.image_bytes {
            return Err(OverlayError::ImageLengthChanged {
                expected: self.image_bytes,
                actual: base.len(),
            });
        }
        Ok(OverlayReader { base, plan: self })
    }

    /// Reads candidate bytes by copying the base image, then applying intersecting replacements.
    ///
    /// # Errors
    ///
    /// Rejects source identity/length disagreement, over-cap or out-of-image reads, arithmetic
    /// overflow, and base image errors.
    pub fn read_exact_at(
        &self,
        image: &ImageFile,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, OverlayError> {
        if image.len() != self.image_bytes {
            return Err(OverlayError::ImageLengthChanged {
                expected: self.image_bytes,
                actual: image.len(),
            });
        }
        if length > self.max_read_bytes {
            return Err(OverlayError::ReadLimitExceeded {
                actual: length,
                maximum: self.max_read_bytes,
            });
        }
        let length_u64 = u64::try_from(length).map_err(|_| OverlayError::ArithmeticOverflow)?;
        let end = offset
            .checked_add(length_u64)
            .ok_or(OverlayError::ArithmeticOverflow)?;
        if end > self.image_bytes {
            return Err(OverlayError::ReadOutsideImage {
                offset,
                length: length_u64,
                image_bytes: self.image_bytes,
            });
        }
        let mut output = image.read_exact_at(offset, length)?;
        self.apply_intersections(offset, end, &mut output)?;
        Ok(output)
    }

    fn apply_intersections(
        &self,
        offset: u64,
        end: u64,
        output: &mut [u8],
    ) -> Result<(), OverlayError> {
        for write in &self.writes {
            let write_length =
                u64::try_from(write.bytes.len()).map_err(|_| OverlayError::ArithmeticOverflow)?;
            let write_end = write
                .offset
                .checked_add(write_length)
                .ok_or(OverlayError::ArithmeticOverflow)?;
            let intersection_start = offset.max(write.offset);
            let intersection_end = end.min(write_end);
            if intersection_start >= intersection_end {
                continue;
            }
            let output_start = usize::try_from(intersection_start - offset)
                .map_err(|_| OverlayError::ArithmeticOverflow)?;
            let write_start = usize::try_from(intersection_start - write.offset)
                .map_err(|_| OverlayError::ArithmeticOverflow)?;
            let count = usize::try_from(intersection_end - intersection_start)
                .map_err(|_| OverlayError::ArithmeticOverflow)?;
            output[output_start..output_start + count]
                .copy_from_slice(&write.bytes[write_start..write_start + count]);
        }
        Ok(())
    }
}

impl BoundedImageReader for OverlayReader<'_> {
    fn len(&self) -> u64 {
        self.plan.image_bytes
    }

    fn max_read_bytes(&self) -> usize {
        self.base.max_read_bytes().min(self.plan.max_read_bytes)
    }

    fn read_exact_at(&self, offset: u64, length: usize) -> Result<Vec<u8>, ImageError> {
        if self.base.len() != self.plan.image_bytes {
            return Err(ImageError::SourceChanged);
        }
        let maximum = self.max_read_bytes();
        if length > maximum {
            return Err(ImageError::ReadTooLarge {
                requested: length,
                maximum,
            });
        }
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
        if end > self.plan.image_bytes {
            return Err(ImageError::OutOfRange {
                offset,
                length: length_u64,
                image_length: self.plan.image_bytes,
            });
        }

        let mut output = self.base.read_exact_at(offset, length)?;
        self.plan
            .apply_intersections(offset, end, &mut output)
            .map_err(|error| match error {
                OverlayError::ArithmeticOverflow => ImageError::RangeOverflow {
                    offset,
                    length: length_u64,
                },
                _ => ImageError::SourceChanged,
            })?;
        Ok(output)
    }
}

#[derive(Debug)]
pub enum OverlayError {
    InvalidLimit {
        field: &'static str,
    },
    InvalidSectorSize {
        sector_bytes: u32,
    },
    WriteLimitExceeded {
        actual: usize,
        maximum: usize,
    },
    ReplacementLimitExceeded {
        actual: u64,
        maximum: usize,
    },
    EmptyWrite {
        offset: u64,
    },
    UnalignedWrite {
        offset: u64,
        length: u64,
        sector_bytes: u32,
    },
    WriteOutsideImage {
        offset: u64,
        length: u64,
        image_bytes: u64,
    },
    OverlappingWrites {
        first_offset: u64,
        second_offset: u64,
    },
    ImageLengthChanged {
        expected: u64,
        actual: u64,
    },
    ReadLimitExceeded {
        actual: usize,
        maximum: usize,
    },
    ReadOutsideImage {
        offset: u64,
        length: u64,
        image_bytes: u64,
    },
    ArithmeticOverflow,
    Image(ImageError),
}

impl fmt::Display for OverlayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit { field } => write!(formatter, "overlay limit {field} is zero"),
            Self::InvalidSectorSize { sector_bytes } => write!(
                formatter,
                "overlay sector size {sector_bytes} is not a nonzero power of two"
            ),
            Self::WriteLimitExceeded { actual, maximum } => write!(
                formatter,
                "overlay has {actual} writes, exceeding {maximum}"
            ),
            Self::ReplacementLimitExceeded { actual, maximum } => write!(
                formatter,
                "overlay replaces {actual} bytes, exceeding {maximum}"
            ),
            Self::EmptyWrite { offset } => write!(formatter, "overlay write at {offset} is empty"),
            Self::UnalignedWrite {
                offset,
                length,
                sector_bytes,
            } => write!(
                formatter,
                "overlay write offset {offset}, length {length} is not aligned to {sector_bytes}"
            ),
            Self::WriteOutsideImage {
                offset,
                length,
                image_bytes,
            } => write!(
                formatter,
                "overlay write offset {offset}, length {length} exceeds {image_bytes}-byte image"
            ),
            Self::OverlappingWrites {
                first_offset,
                second_offset,
            } => write!(
                formatter,
                "overlay writes at {first_offset} and {second_offset} overlap"
            ),
            Self::ImageLengthChanged { expected, actual } => write!(
                formatter,
                "overlay base image length changed from {expected} to {actual}"
            ),
            Self::ReadLimitExceeded { actual, maximum } => write!(
                formatter,
                "overlay read of {actual} bytes exceeds {maximum}"
            ),
            Self::ReadOutsideImage {
                offset,
                length,
                image_bytes,
            } => write!(
                formatter,
                "overlay read offset {offset}, length {length} exceeds {image_bytes}-byte image"
            ),
            Self::ArithmeticOverflow => formatter.write_str("overlay byte accounting overflow"),
            Self::Image(error) => write!(formatter, "overlay base image read failed: {error}"),
        }
    }
}

impl std::error::Error for OverlayError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Self::Image(error) = self {
            Some(error)
        } else {
            None
        }
    }
}

impl From<ImageError> for OverlayError {
    fn from(value: ImageError) -> Self {
        Self::Image(value)
    }
}

fn validate_limits(limits: OverlayLimits) -> Result<(), OverlayError> {
    for (field, value) in [
        ("max_writes", limits.max_writes),
        ("max_replacement_bytes", limits.max_replacement_bytes),
        ("max_read_bytes", limits.max_read_bytes),
    ] {
        if value == 0 {
            return Err(OverlayError::InvalidLimit { field });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
    struct TempImage(PathBuf);
    impl TempImage {
        fn create(bytes: &[u8]) -> Self {
            let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "starconverter-overlay-{}-{id}.img",
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

    const fn limits() -> OverlayLimits {
        OverlayLimits {
            max_writes: 8,
            max_replacement_bytes: 4096,
            max_read_bytes: 4096,
        }
    }

    #[test]
    fn overlays_full_and_partial_intersections_without_mutating_base() {
        let original = vec![0x11_u8; 2048];
        let temp = TempImage::create(&original);
        let image = ImageFile::open(&temp.0).unwrap();
        let plan = OverlayPlan::build(
            2048,
            512,
            vec![
                OverlayWrite {
                    offset: 512,
                    bytes: vec![0x22; 512],
                },
                OverlayWrite {
                    offset: 1536,
                    bytes: vec![0x33; 512],
                },
            ],
            limits(),
        )
        .unwrap();
        let read = plan.read_exact_at(&image, 256, 1536).unwrap();
        assert_eq!(&read[..256], &[0x11; 256]);
        assert_eq!(&read[256..768], &[0x22; 512]);
        assert_eq!(&read[768..1280], &[0x11; 512]);
        assert_eq!(&read[1280..], &[0x33; 256]);
        assert_eq!(fs::read(&temp.0).unwrap(), original);
    }

    #[test]
    fn bounded_reader_merges_candidate_bytes_and_enforces_effective_cap() {
        let original = vec![0x11_u8; 2048];
        let temp = TempImage::create(&original);
        let image = ImageFile::open_with_limit(&temp.0, 1024).unwrap();
        let plan = OverlayPlan::build(
            2048,
            512,
            vec![
                OverlayWrite {
                    offset: 512,
                    bytes: vec![0x22; 512],
                },
                OverlayWrite {
                    offset: 1536,
                    bytes: vec![0x33; 512],
                },
            ],
            OverlayLimits {
                max_read_bytes: 768,
                ..limits()
            },
        )
        .unwrap();
        let reader = plan.reader(&image).unwrap();
        assert_eq!(reader.max_read_bytes(), 768);
        let read = reader.read_exact_at(256, 768).unwrap();
        assert_eq!(&read[..256], &[0x11; 256]);
        assert_eq!(&read[256..], &[0x22; 512]);
        assert!(matches!(
            reader.read_exact_at(0, 769),
            Err(ImageError::ReadTooLarge {
                requested: 769,
                maximum: 768
            })
        ));
        assert_eq!(fs::read(&temp.0).unwrap(), original);

        let short = TempImage::create(&vec![0_u8; 1024]);
        let short_image = ImageFile::open(&short.0).unwrap();
        assert!(matches!(
            plan.reader(&short_image),
            Err(OverlayError::ImageLengthChanged {
                expected: 2048,
                actual: 1024
            })
        ));
    }

    #[test]
    fn rejects_overlap_alignment_bounds_and_empty_writes() {
        assert!(matches!(
            OverlayPlan::build(
                2048,
                512,
                vec![OverlayWrite {
                    offset: 1,
                    bytes: vec![0; 512]
                }],
                limits()
            ),
            Err(OverlayError::UnalignedWrite { .. })
        ));
        assert!(matches!(
            OverlayPlan::build(
                2048,
                512,
                vec![OverlayWrite {
                    offset: 0,
                    bytes: Vec::new()
                }],
                limits()
            ),
            Err(OverlayError::EmptyWrite { .. })
        ));
        assert!(matches!(
            OverlayPlan::build(
                2048,
                512,
                vec![OverlayWrite {
                    offset: 1536,
                    bytes: vec![0; 1024]
                }],
                limits()
            ),
            Err(OverlayError::WriteOutsideImage { .. })
        ));
        assert!(matches!(
            OverlayPlan::build(
                2048,
                512,
                vec![
                    OverlayWrite {
                        offset: 0,
                        bytes: vec![0; 1024]
                    },
                    OverlayWrite {
                        offset: 512,
                        bytes: vec![0; 512]
                    }
                ],
                limits()
            ),
            Err(OverlayError::OverlappingWrites { .. })
        ));
    }

    #[test]
    fn read_caps_and_ranges_are_checked_before_io() {
        let temp = TempImage::create(&vec![0_u8; 1024]);
        let image = ImageFile::open(&temp.0).unwrap();
        let plan = OverlayPlan::build(
            1024,
            512,
            Vec::new(),
            OverlayLimits {
                max_read_bytes: 2,
                ..limits()
            },
        )
        .unwrap();
        assert!(matches!(
            plan.read_exact_at(&image, 0, 3),
            Err(OverlayError::ReadLimitExceeded { .. })
        ));
        assert!(matches!(
            plan.read_exact_at(&image, 1024, 1),
            Err(OverlayError::ReadOutsideImage { .. })
        ));
    }
}
