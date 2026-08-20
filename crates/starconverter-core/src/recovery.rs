//! Versioned encoding of exact rollback bytes retained by the transaction capsule.

use std::fmt;

use crate::overlay::OverlayWrite;

const MAGIC: &[u8; 8] = b"SCRECOV1";
const VERSION: u16 = 1;
const HEADER_BYTES: usize = 64;
const ENTRY_BYTES: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryLimits {
    pub max_writes: usize,
    pub max_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryBundle {
    pub plan_digest: [u8; 32],
    pub target_staging: Vec<OverlayWrite>,
    pub backup_boot: Vec<OverlayWrite>,
    pub activation: Vec<OverlayWrite>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryError {
    InvalidLimit {
        field: &'static str,
    },
    Truncated,
    InvalidMagic,
    UnsupportedVersion {
        actual: u16,
    },
    NonZeroReserved,
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
    TrailingBytes {
        actual: usize,
    },
    AllocationFailed,
    ArithmeticOverflow,
}

impl fmt::Display for RecoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit { field } => write!(formatter, "recovery limit {field} is zero"),
            Self::Truncated => formatter.write_str("recovery bundle is truncated"),
            Self::InvalidMagic => formatter.write_str("recovery bundle magic is invalid"),
            Self::UnsupportedVersion { actual } => {
                write!(formatter, "recovery bundle version {actual} is unsupported")
            }
            Self::NonZeroReserved => {
                formatter.write_str("recovery bundle reserved bytes are nonzero")
            }
            Self::WriteLimitExceeded { actual, maximum } => {
                write!(
                    formatter,
                    "recovery bundle has {actual} writes, exceeding {maximum}"
                )
            }
            Self::ByteLimitExceeded { actual, maximum } => {
                write!(
                    formatter,
                    "recovery bundle has {actual} bytes, exceeding {maximum}"
                )
            }
            Self::EmptyWrite { offset } => write!(formatter, "recovery write at {offset} is empty"),
            Self::RangeOverflow { offset, length } => {
                write!(formatter, "recovery range {offset}+{length} overflows")
            }
            Self::OverlappingWrites {
                first_offset,
                second_offset,
            } => write!(
                formatter,
                "recovery writes at {first_offset} and {second_offset} overlap"
            ),
            Self::TrailingBytes { actual } => {
                write!(formatter, "recovery bundle has {actual} trailing bytes")
            }
            Self::AllocationFailed => {
                formatter.write_str("could not allocate bounded recovery data")
            }
            Self::ArithmeticOverflow => formatter.write_str("recovery byte accounting overflowed"),
        }
    }
}

impl std::error::Error for RecoveryError {}

/// Encodes exact phase before-images into a deterministic, versioned capsule payload.
///
/// # Errors
///
/// Refuses invalid caps, excessive/empty/overlapping ranges, arithmetic overflow, and allocation
/// failure.
pub fn encode_recovery_bundle(
    bundle: &RecoveryBundle,
    limits: RecoveryLimits,
) -> Result<Vec<u8>, RecoveryError> {
    validate_limits(limits)?;
    validate_bundle(bundle, limits)?;
    let payload_bytes = total_payload_bytes(bundle)?;
    let entry_count = total_write_count(bundle)?;
    let encoded_bytes = HEADER_BYTES
        .checked_add(
            entry_count
                .checked_mul(ENTRY_BYTES)
                .ok_or(RecoveryError::ArithmeticOverflow)?,
        )
        .and_then(|value| value.checked_add(payload_bytes))
        .ok_or(RecoveryError::ArithmeticOverflow)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(encoded_bytes)
        .map_err(|_| RecoveryError::AllocationFailed)?;
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(&VERSION.to_le_bytes());
    output.extend_from_slice(&[0_u8; 6]);
    output.extend_from_slice(&bundle.plan_digest);
    for count in [
        bundle.target_staging.len(),
        bundle.backup_boot.len(),
        bundle.activation.len(),
    ] {
        output.extend_from_slice(
            &u32::try_from(count)
                .map_err(|_| RecoveryError::ArithmeticOverflow)?
                .to_le_bytes(),
        );
    }
    output.extend_from_slice(&[0_u8; 4]);
    for write in bundle
        .target_staging
        .iter()
        .chain(&bundle.backup_boot)
        .chain(&bundle.activation)
    {
        output.extend_from_slice(&write.offset.to_le_bytes());
        output.extend_from_slice(
            &u64::try_from(write.bytes.len())
                .map_err(|_| RecoveryError::ArithmeticOverflow)?
                .to_le_bytes(),
        );
        output.extend_from_slice(&write.bytes);
    }
    Ok(output)
}

/// Decodes and revalidates a capsule recovery payload under caller caps.
///
/// # Errors
///
/// Refuses malformed framing, unsupported versions, caps, overlaps, truncation, trailing bytes,
/// arithmetic overflow, and allocation failure.
#[allow(clippy::too_many_lines)]
pub fn decode_recovery_bundle(
    bytes: &[u8],
    limits: RecoveryLimits,
) -> Result<RecoveryBundle, RecoveryError> {
    validate_limits(limits)?;
    if bytes.len() < HEADER_BYTES {
        return Err(RecoveryError::Truncated);
    }
    if &bytes[..8] != MAGIC {
        return Err(RecoveryError::InvalidMagic);
    }
    let version = read_u16(bytes, 8)?;
    if version != VERSION {
        return Err(RecoveryError::UnsupportedVersion { actual: version });
    }
    if bytes[10..16]
        .iter()
        .chain(&bytes[60..64])
        .any(|byte| *byte != 0)
    {
        return Err(RecoveryError::NonZeroReserved);
    }
    let mut plan_digest = [0_u8; 32];
    plan_digest.copy_from_slice(&bytes[16..48]);
    let counts = [
        read_u32(bytes, 48)?,
        read_u32(bytes, 52)?,
        read_u32(bytes, 56)?,
    ];
    let counts = counts.map(|count| usize::try_from(count).unwrap_or(usize::MAX));
    let total_count = counts
        .into_iter()
        .try_fold(0_usize, usize::checked_add)
        .ok_or(RecoveryError::ArithmeticOverflow)?;
    if total_count > limits.max_writes {
        return Err(RecoveryError::WriteLimitExceeded {
            actual: total_count,
            maximum: limits.max_writes,
        });
    }
    let mut cursor = HEADER_BYTES;
    let mut groups = [Vec::new(), Vec::new(), Vec::new()];
    let mut total_bytes = 0_u64;
    for (group, count) in groups.iter_mut().zip(counts) {
        group
            .try_reserve_exact(count)
            .map_err(|_| RecoveryError::AllocationFailed)?;
        for _ in 0..count {
            let header_end = cursor
                .checked_add(ENTRY_BYTES)
                .ok_or(RecoveryError::ArithmeticOverflow)?;
            if header_end > bytes.len() {
                return Err(RecoveryError::Truncated);
            }
            let offset = read_u64(bytes, cursor)?;
            let length_u64 = read_u64(bytes, cursor + 8)?;
            if length_u64 == 0 {
                return Err(RecoveryError::EmptyWrite { offset });
            }
            offset
                .checked_add(length_u64)
                .ok_or(RecoveryError::RangeOverflow {
                    offset,
                    length: length_u64,
                })?;
            let length =
                usize::try_from(length_u64).map_err(|_| RecoveryError::ByteLimitExceeded {
                    actual: length_u64,
                    maximum: limits.max_bytes,
                })?;
            let data_end = header_end
                .checked_add(length)
                .ok_or(RecoveryError::ArithmeticOverflow)?;
            if data_end > bytes.len() {
                return Err(RecoveryError::Truncated);
            }
            total_bytes = total_bytes
                .checked_add(length_u64)
                .ok_or(RecoveryError::ArithmeticOverflow)?;
            if total_bytes > u64::try_from(limits.max_bytes).unwrap_or(u64::MAX) {
                return Err(RecoveryError::ByteLimitExceeded {
                    actual: total_bytes,
                    maximum: limits.max_bytes,
                });
            }
            let mut write_bytes = Vec::new();
            write_bytes
                .try_reserve_exact(length)
                .map_err(|_| RecoveryError::AllocationFailed)?;
            write_bytes.extend_from_slice(&bytes[header_end..data_end]);
            group.push(OverlayWrite {
                offset,
                bytes: write_bytes,
            });
            cursor = data_end;
        }
    }
    if cursor != bytes.len() {
        return Err(RecoveryError::TrailingBytes {
            actual: bytes.len() - cursor,
        });
    }
    let [target_staging, backup_boot, activation] = groups;
    let bundle = RecoveryBundle {
        plan_digest,
        target_staging,
        backup_boot,
        activation,
    };
    validate_bundle(&bundle, limits)?;
    Ok(bundle)
}

const fn validate_limits(limits: RecoveryLimits) -> Result<(), RecoveryError> {
    if limits.max_writes == 0 {
        return Err(RecoveryError::InvalidLimit {
            field: "max_writes",
        });
    }
    if limits.max_bytes == 0 {
        return Err(RecoveryError::InvalidLimit { field: "max_bytes" });
    }
    Ok(())
}

fn validate_bundle(bundle: &RecoveryBundle, limits: RecoveryLimits) -> Result<(), RecoveryError> {
    let count = total_write_count(bundle)?;
    if count > limits.max_writes {
        return Err(RecoveryError::WriteLimitExceeded {
            actual: count,
            maximum: limits.max_writes,
        });
    }
    let bytes = total_payload_bytes(bundle)?;
    if bytes > limits.max_bytes {
        return Err(RecoveryError::ByteLimitExceeded {
            actual: u64::try_from(bytes).unwrap_or(u64::MAX),
            maximum: limits.max_bytes,
        });
    }
    let mut ranges = Vec::new();
    ranges
        .try_reserve_exact(count)
        .map_err(|_| RecoveryError::AllocationFailed)?;
    for write in bundle
        .target_staging
        .iter()
        .chain(&bundle.backup_boot)
        .chain(&bundle.activation)
    {
        if write.bytes.is_empty() {
            return Err(RecoveryError::EmptyWrite {
                offset: write.offset,
            });
        }
        let length =
            u64::try_from(write.bytes.len()).map_err(|_| RecoveryError::ArithmeticOverflow)?;
        let end = write
            .offset
            .checked_add(length)
            .ok_or(RecoveryError::RangeOverflow {
                offset: write.offset,
                length,
            })?;
        ranges.push((write.offset, end));
    }
    ranges.sort_unstable();
    for pair in ranges.windows(2) {
        if pair[1].0 < pair[0].1 {
            return Err(RecoveryError::OverlappingWrites {
                first_offset: pair[0].0,
                second_offset: pair[1].0,
            });
        }
    }
    Ok(())
}

fn total_write_count(bundle: &RecoveryBundle) -> Result<usize, RecoveryError> {
    bundle
        .target_staging
        .len()
        .checked_add(bundle.backup_boot.len())
        .and_then(|value| value.checked_add(bundle.activation.len()))
        .ok_or(RecoveryError::ArithmeticOverflow)
}

fn total_payload_bytes(bundle: &RecoveryBundle) -> Result<usize, RecoveryError> {
    bundle
        .target_staging
        .iter()
        .chain(&bundle.backup_boot)
        .chain(&bundle.activation)
        .try_fold(0_usize, |sum, write| sum.checked_add(write.bytes.len()))
        .ok_or(RecoveryError::ArithmeticOverflow)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, RecoveryError> {
    let raw = bytes
        .get(offset..offset + 2)
        .ok_or(RecoveryError::Truncated)?;
    Ok(u16::from_le_bytes([raw[0], raw[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, RecoveryError> {
    let raw = bytes
        .get(offset..offset + 4)
        .ok_or(RecoveryError::Truncated)?;
    Ok(u32::from_le_bytes(
        raw.try_into().map_err(|_| RecoveryError::Truncated)?,
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, RecoveryError> {
    let raw = bytes
        .get(offset..offset + 8)
        .ok_or(RecoveryError::Truncated)?;
    Ok(u64::from_le_bytes(
        raw.try_into().map_err(|_| RecoveryError::Truncated)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle() -> RecoveryBundle {
        RecoveryBundle {
            plan_digest: [7; 32],
            target_staging: vec![OverlayWrite {
                offset: 1024,
                bytes: vec![1; 512],
            }],
            backup_boot: vec![OverlayWrite {
                offset: 512,
                bytes: vec![2; 512],
            }],
            activation: vec![OverlayWrite {
                offset: 0,
                bytes: vec![3; 512],
            }],
        }
    }

    const LIMITS: RecoveryLimits = RecoveryLimits {
        max_writes: 8,
        max_bytes: 4096,
    };

    #[test]
    fn deterministic_roundtrip_preserves_exact_phase_bytes() {
        let first = encode_recovery_bundle(&bundle(), LIMITS).unwrap();
        let second = encode_recovery_bundle(&bundle(), LIMITS).unwrap();
        assert_eq!(first, second);
        assert_eq!(decode_recovery_bundle(&first, LIMITS).unwrap(), bundle());
    }

    #[test]
    fn rejects_truncation_corruption_caps_overlap_and_trailing_bytes() {
        let encoded = encode_recovery_bundle(&bundle(), LIMITS).unwrap();
        for length in 0..encoded.len() {
            assert!(decode_recovery_bundle(&encoded[..length], LIMITS).is_err());
        }
        let mut bad_magic = encoded.clone();
        bad_magic[0] ^= 1;
        assert!(matches!(
            decode_recovery_bundle(&bad_magic, LIMITS),
            Err(RecoveryError::InvalidMagic)
        ));
        let mut trailing = encoded;
        trailing.push(0);
        assert!(matches!(
            decode_recovery_bundle(&trailing, LIMITS),
            Err(RecoveryError::TrailingBytes { .. })
        ));
        let mut overlap = bundle();
        overlap.target_staging[0].offset = 0;
        assert!(matches!(
            encode_recovery_bundle(&overlap, LIMITS),
            Err(RecoveryError::OverlappingWrites { .. })
        ));
        assert!(matches!(
            encode_recovery_bundle(
                &bundle(),
                RecoveryLimits {
                    max_writes: 2,
                    max_bytes: 4096
                }
            ),
            Err(RecoveryError::WriteLimitExceeded { .. })
        ));
    }
}
