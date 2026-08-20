//! Bounded parsing of NTFS non-resident attribute mapping pairs.
//!
//! Mapping pairs encode a contiguous sequence of virtual cluster numbers (VCNs). Each physical
//! run stores a signed LCN delta relative to the previous physical run; a zero-width LCN field
//! denotes a sparse run. This module only parses caller-owned bytes and never performs I/O.

use std::fmt;

/// Caller-supplied geometry and resource limits for mapping-pairs parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MappingPairsLimits {
    /// First VCN represented by this mapping-pairs fragment.
    pub starting_vcn: u64,
    /// Expected VCN immediately after the fragment, normally `highest_vcn + 1`.
    ///
    /// Leave this as `None` only when the enclosing attribute has not yet supplied that evidence.
    pub expected_next_vcn: Option<u64>,
    /// Number of addressable clusters in the containing NTFS volume.
    pub volume_cluster_count: u64,
    /// Maximum number of encoded runs to examine, including zero-length sparse runs.
    pub max_runs: usize,
    /// Maximum total run length, in virtual clusters, to decode from this fragment.
    pub max_decoded_clusters: u64,
}

/// Location represented by one decoded NTFS extent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtentLocation {
    /// The extent is a hole and has no clusters allocated on disk.
    Sparse,
    /// The extent begins at this logical cluster number.
    Physical { lcn: u64 },
}

/// One non-empty, contiguous range in an NTFS attribute runlist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtfsExtent {
    pub vcn: u64,
    pub length: u64,
    pub location: ExtentLocation,
}

/// A validated, compact NTFS runlist fragment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsRunlist {
    /// Decoded extents. Adjacent compatible mapping pairs are coalesced.
    pub extents: Vec<NtfsExtent>,
    /// VCN immediately following the represented range.
    pub next_vcn: u64,
    /// Number of encoded mapping pairs consumed, before the terminator.
    pub encoded_runs: usize,
    /// Number of bytes through and including the zero terminator.
    pub bytes_consumed: usize,
    pub decoded_clusters: u64,
    pub physical_clusters: u64,
    pub sparse_clusters: u64,
}

/// Mapping-pairs field identified in a structural error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingPairField {
    RunLength,
    LcnDelta,
}

impl fmt::Display for MappingPairField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RunLength => "run length",
            Self::LcnDelta => "LCN delta",
        })
    }
}

/// Reason an NTFS mapping-pairs array could not be safely interpreted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MappingPairsError {
    MissingTerminator,
    MissingRunLength {
        offset: usize,
    },
    FieldWidthTooLarge {
        field: MappingPairField,
        offset: usize,
        width: u8,
    },
    TruncatedRun {
        offset: usize,
        required_end: usize,
        actual: usize,
    },
    RunLimitExceeded {
        maximum: usize,
    },
    ZeroLengthPhysicalRun {
        run_index: usize,
    },
    DecodedClusterCountOverflow,
    DecodedClusterLimitExceeded {
        decoded: u64,
        maximum: u64,
    },
    VcnOverflow {
        vcn: u64,
        length: u64,
    },
    LcnOverflow {
        run_index: usize,
        previous_lcn: i64,
        delta: i64,
    },
    NegativeLcn {
        run_index: usize,
        value: i64,
    },
    PhysicalRunEndOverflow {
        run_index: usize,
        lcn: u64,
        length: u64,
    },
    PhysicalRunOutOfBounds {
        run_index: usize,
        lcn: u64,
        length: u64,
        volume_cluster_count: u64,
    },
    ExpectedNextVcnMismatch {
        expected: u64,
        actual: u64,
    },
    TrailingNonZeroByte {
        offset: usize,
        value: u8,
    },
    AllocationFailed,
}

impl fmt::Display for MappingPairsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingTerminator => {
                formatter.write_str("NTFS mapping pairs have no zero terminator")
            }
            Self::MissingRunLength { offset } => {
                write!(
                    formatter,
                    "mapping pair at byte {offset} has no run-length field"
                )
            }
            Self::FieldWidthTooLarge {
                field,
                offset,
                width,
            } => write!(
                formatter,
                "mapping-pair {field} at byte {offset} uses unsupported width {width}"
            ),
            Self::TruncatedRun {
                offset,
                required_end,
                actual,
            } => write!(
                formatter,
                "mapping pair at byte {offset} is truncated: ends at {actual}, needs byte {required_end}"
            ),
            Self::RunLimitExceeded { maximum } => {
                write!(
                    formatter,
                    "mapping-pair run count exceeds caller limit {maximum}"
                )
            }
            Self::ZeroLengthPhysicalRun { run_index } => {
                write!(
                    formatter,
                    "physical mapping-pair run {run_index} has zero length"
                )
            }
            Self::DecodedClusterCountOverflow => {
                formatter.write_str("decoded mapping-pair cluster count overflows u64")
            }
            Self::DecodedClusterLimitExceeded { decoded, maximum } => write!(
                formatter,
                "mapping pairs decode {decoded} clusters, exceeding caller limit {maximum}"
            ),
            Self::VcnOverflow { vcn, length } => {
                write!(
                    formatter,
                    "VCN {vcn} plus run length {length} overflows u64"
                )
            }
            Self::LcnOverflow {
                run_index,
                previous_lcn,
                delta,
            } => write!(
                formatter,
                "LCN delta overflows on run {run_index}: {previous_lcn} + {delta}"
            ),
            Self::NegativeLcn { run_index, value } => {
                write!(
                    formatter,
                    "mapping-pair run {run_index} resolves to negative LCN {value}"
                )
            }
            Self::PhysicalRunEndOverflow {
                run_index,
                lcn,
                length,
            } => write!(
                formatter,
                "physical run {run_index} end overflows: LCN {lcn} + length {length}"
            ),
            Self::PhysicalRunOutOfBounds {
                run_index,
                lcn,
                length,
                volume_cluster_count,
            } => write!(
                formatter,
                "physical run {run_index} at LCN {lcn} with length {length} exceeds {volume_cluster_count} volume clusters"
            ),
            Self::ExpectedNextVcnMismatch { expected, actual } => write!(
                formatter,
                "mapping-pair VCN range ends at {actual}, expected {expected}"
            ),
            Self::TrailingNonZeroByte { offset, value } => write!(
                formatter,
                "nonzero byte 0x{value:02x} follows mapping-pairs terminator at byte {offset}"
            ),
            Self::AllocationFailed => {
                formatter.write_str("could not allocate bounded NTFS extent storage")
            }
        }
    }
}

impl std::error::Error for MappingPairsError {}

#[derive(Debug, Clone, Copy)]
struct DecodedRun {
    length: u64,
    location: ExtentLocation,
    next_lcn: i64,
    next_offset: usize,
}

/// Parses an entire terminated NTFS mapping-pairs array under explicit caller limits.
///
/// The parser requires a zero header terminator and requires every remaining byte in `bytes` to be
/// zero padding. This avoids silently accepting a second hidden runlist or unexplained attribute
/// data. Zero-length physical runs are rejected. For compatibility with NTFS-3G/chkdsk behavior,
/// zero-length sparse runs are accepted, counted against `max_runs`, and omitted from `extents`.
///
/// # Errors
///
/// Returns [`MappingPairsError`] for malformed widths or truncation, missing or dirty trailing
/// termination, arithmetic overflow, a caller limit violation, inconsistent VCN evidence, or a
/// physical extent outside the supplied volume geometry.
pub fn parse_mapping_pairs(
    bytes: &[u8],
    limits: MappingPairsLimits,
) -> Result<NtfsRunlist, MappingPairsError> {
    let mut extents = Vec::new();
    let mut offset = 0_usize;
    let mut encoded_runs = 0_usize;
    let mut next_vcn = limits.starting_vcn;
    let mut previous_lcn = 0_i64;
    let mut decoded_clusters = 0_u64;
    let mut physical_clusters = 0_u64;
    let mut sparse_clusters = 0_u64;

    loop {
        let Some(&header) = bytes.get(offset) else {
            return Err(MappingPairsError::MissingTerminator);
        };
        if header == 0 {
            let bytes_consumed = offset + 1;
            validate_zero_padding(bytes, bytes_consumed)?;
            match limits.expected_next_vcn {
                Some(expected) if next_vcn != expected => {
                    return Err(MappingPairsError::ExpectedNextVcnMismatch {
                        expected,
                        actual: next_vcn,
                    });
                }
                _ => {}
            }
            return Ok(NtfsRunlist {
                extents,
                next_vcn,
                encoded_runs,
                bytes_consumed,
                decoded_clusters,
                physical_clusters,
                sparse_clusters,
            });
        }

        if encoded_runs >= limits.max_runs {
            return Err(MappingPairsError::RunLimitExceeded {
                maximum: limits.max_runs,
            });
        }
        let run_index = encoded_runs;
        encoded_runs += 1;

        let run = decode_run(
            bytes,
            offset,
            header,
            run_index,
            previous_lcn,
            limits.volume_cluster_count,
        )?;
        previous_lcn = run.next_lcn;
        offset = run.next_offset;

        decoded_clusters = decoded_clusters
            .checked_add(run.length)
            .ok_or(MappingPairsError::DecodedClusterCountOverflow)?;
        if decoded_clusters > limits.max_decoded_clusters {
            return Err(MappingPairsError::DecodedClusterLimitExceeded {
                decoded: decoded_clusters,
                maximum: limits.max_decoded_clusters,
            });
        }
        let run_vcn = next_vcn;
        next_vcn = next_vcn
            .checked_add(run.length)
            .ok_or(MappingPairsError::VcnOverflow {
                vcn: next_vcn,
                length: run.length,
            })?;

        match run.location {
            ExtentLocation::Sparse => {
                sparse_clusters = sparse_clusters
                    .checked_add(run.length)
                    .ok_or(MappingPairsError::DecodedClusterCountOverflow)?;
            }
            ExtentLocation::Physical { .. } => {
                physical_clusters = physical_clusters
                    .checked_add(run.length)
                    .ok_or(MappingPairsError::DecodedClusterCountOverflow)?;
            }
        }

        if run.length != 0 {
            append_extent(
                &mut extents,
                NtfsExtent {
                    vcn: run_vcn,
                    length: run.length,
                    location: run.location,
                },
            )?;
        }
    }
}

fn decode_run(
    bytes: &[u8],
    offset: usize,
    header: u8,
    run_index: usize,
    previous_lcn: i64,
    volume_cluster_count: u64,
) -> Result<DecodedRun, MappingPairsError> {
    let length_width = header & 0x0f;
    let lcn_width = header >> 4;
    if length_width == 0 {
        return Err(MappingPairsError::MissingRunLength { offset });
    }
    validate_width(MappingPairField::RunLength, offset, length_width)?;
    validate_width(MappingPairField::LcnDelta, offset, lcn_width)?;

    let payload_width = usize::from(length_width) + usize::from(lcn_width);
    let required_end =
        offset
            .checked_add(1 + payload_width)
            .ok_or(MappingPairsError::TruncatedRun {
                offset,
                required_end: usize::MAX,
                actual: bytes.len(),
            })?;
    if required_end > bytes.len() {
        return Err(MappingPairsError::TruncatedRun {
            offset,
            required_end,
            actual: bytes.len(),
        });
    }

    let length_start = offset + 1;
    let lcn_start = length_start + usize::from(length_width);
    let length = decode_unsigned(&bytes[length_start..lcn_start]);
    if lcn_width == 0 {
        return Ok(DecodedRun {
            length,
            location: ExtentLocation::Sparse,
            next_lcn: previous_lcn,
            next_offset: required_end,
        });
    }
    if length == 0 {
        return Err(MappingPairsError::ZeroLengthPhysicalRun { run_index });
    }

    let delta = decode_signed(&bytes[lcn_start..required_end]);
    let sum = i128::from(previous_lcn) + i128::from(delta);
    let next_lcn = i64::try_from(sum).map_err(|_| MappingPairsError::LcnOverflow {
        run_index,
        previous_lcn,
        delta,
    })?;
    if next_lcn < 0 {
        return Err(MappingPairsError::NegativeLcn {
            run_index,
            value: next_lcn,
        });
    }
    let lcn = u64::try_from(next_lcn).expect("nonnegative i64 always fits in u64");
    let run_end = lcn
        .checked_add(length)
        .ok_or(MappingPairsError::PhysicalRunEndOverflow {
            run_index,
            lcn,
            length,
        })?;
    if run_end > volume_cluster_count {
        return Err(MappingPairsError::PhysicalRunOutOfBounds {
            run_index,
            lcn,
            length,
            volume_cluster_count,
        });
    }

    Ok(DecodedRun {
        length,
        location: ExtentLocation::Physical { lcn },
        next_lcn,
        next_offset: required_end,
    })
}

const fn validate_width(
    field: MappingPairField,
    offset: usize,
    width: u8,
) -> Result<(), MappingPairsError> {
    if width > 8 {
        return Err(MappingPairsError::FieldWidthTooLarge {
            field,
            offset,
            width,
        });
    }
    Ok(())
}

fn decode_unsigned(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .enumerate()
        .fold(0_u64, |value, (shift, byte)| {
            value | (u64::from(*byte) << (shift * 8))
        })
}

fn decode_signed(bytes: &[u8]) -> i64 {
    let unsigned = decode_unsigned(bytes);
    let bits = bytes.len() * 8;
    if bits == 64 {
        i64::from_le_bytes(unsigned.to_le_bytes())
    } else if bytes.last().is_some_and(|byte| byte & 0x80 != 0) {
        i64::try_from(i128::from(unsigned) - (1_i128 << bits))
            .expect("a sign-extended sub-64-bit integer always fits in i64")
    } else {
        i64::try_from(unsigned).expect("a positive sub-64-bit integer always fits in i64")
    }
}

fn validate_zero_padding(bytes: &[u8], start: usize) -> Result<(), MappingPairsError> {
    if let Some((relative_offset, value)) = bytes[start..]
        .iter()
        .copied()
        .enumerate()
        .find(|(_, value)| *value != 0)
    {
        return Err(MappingPairsError::TrailingNonZeroByte {
            offset: start + relative_offset,
            value,
        });
    }
    Ok(())
}

fn append_extent(
    extents: &mut Vec<NtfsExtent>,
    extent: NtfsExtent,
) -> Result<(), MappingPairsError> {
    if let Some(previous) = extents
        .last_mut()
        .filter(|previous| previous.vcn.checked_add(previous.length) == Some(extent.vcn))
    {
        let mergeable = match (previous.location, extent.location) {
            (ExtentLocation::Sparse, ExtentLocation::Sparse) => true,
            (ExtentLocation::Physical { lcn: previous_lcn }, ExtentLocation::Physical { lcn }) => {
                previous_lcn.checked_add(previous.length) == Some(lcn)
            }
            _ => false,
        };
        if mergeable {
            previous.length = previous
                .length
                .checked_add(extent.length)
                .ok_or(MappingPairsError::DecodedClusterCountOverflow)?;
            return Ok(());
        }
    }

    extents
        .try_reserve(1)
        .map_err(|_| MappingPairsError::AllocationFailed)?;
    extents.push(extent);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn limits() -> MappingPairsLimits {
        MappingPairsLimits {
            starting_vcn: 0,
            expected_next_vcn: None,
            volume_cluster_count: 1_000,
            max_runs: 32,
            max_decoded_clusters: 1_000,
        }
    }

    #[test]
    fn parses_physical_negative_delta_and_sparse_runs() {
        let mut config = limits();
        config.starting_vcn = 10;
        config.expected_next_vcn = Some(19);
        let parsed = parse_mapping_pairs(
            &[
                0x11, 3, 5, // VCN 10..13 -> LCN 5.
                0x11, 2, 0xfe, // VCN 13..15 -> LCN 3 (delta -2).
                0x01, 4, // VCN 15..19 is sparse.
                0, 0, 0,
            ],
            config,
        )
        .expect("valid mixed runlist");

        assert_eq!(
            parsed.extents,
            vec![
                NtfsExtent {
                    vcn: 10,
                    length: 3,
                    location: ExtentLocation::Physical { lcn: 5 },
                },
                NtfsExtent {
                    vcn: 13,
                    length: 2,
                    location: ExtentLocation::Physical { lcn: 3 },
                },
                NtfsExtent {
                    vcn: 15,
                    length: 4,
                    location: ExtentLocation::Sparse,
                },
            ]
        );
        assert_eq!(parsed.next_vcn, 19);
        assert_eq!(parsed.encoded_runs, 3);
        assert_eq!(parsed.bytes_consumed, 9);
        assert_eq!(parsed.decoded_clusters, 9);
        assert_eq!(parsed.physical_clusters, 5);
        assert_eq!(parsed.sparse_clusters, 4);
    }

    #[test]
    fn accepts_every_supported_integer_width() {
        for width in 1_u8..=8 {
            let mut bytes = vec![(width << 4) | width];
            bytes.extend(std::iter::once(1).chain(std::iter::repeat_n(0, usize::from(width) - 1)));
            bytes.extend(std::iter::once(1).chain(std::iter::repeat_n(0, usize::from(width) - 1)));
            bytes.push(0);

            let parsed = parse_mapping_pairs(&bytes, limits()).expect("supported field width");
            assert_eq!(parsed.extents[0].length, 1);
            assert_eq!(
                parsed.extents[0].location,
                ExtentLocation::Physical { lcn: 1 }
            );
        }
    }

    #[test]
    fn sign_extends_lcn_deltas_at_multiple_widths() {
        for delta_bytes in [
            &[0xfe][..],
            &[0xfe, 0xff][..],
            &[0xfe, 0xff, 0xff, 0xff][..],
        ] {
            let width = u8::try_from(delta_bytes.len()).expect("test width fits");
            let mut bytes = vec![0x11, 1, 10, (width << 4) | 1, 1];
            bytes.extend_from_slice(delta_bytes);
            bytes.push(0);
            let parsed = parse_mapping_pairs(&bytes, limits()).expect("negative relative delta");
            assert_eq!(
                parsed.extents[1].location,
                ExtentLocation::Physical { lcn: 8 }
            );
        }
    }

    #[test]
    fn compacts_adjacent_physical_and_sparse_runs() {
        let parsed = parse_mapping_pairs(
            &[
                0x11, 2, 10, // LCN 10, length 2.
                0x11, 3, 2, // LCN 12, length 3: physically contiguous.
                0x01, 4, 0x01, 5, // Adjacent sparse runs.
                0,
            ],
            limits(),
        )
        .expect("valid compactable runlist");
        assert_eq!(parsed.encoded_runs, 4);
        assert_eq!(
            parsed.extents,
            vec![
                NtfsExtent {
                    vcn: 0,
                    length: 5,
                    location: ExtentLocation::Physical { lcn: 10 },
                },
                NtfsExtent {
                    vcn: 5,
                    length: 9,
                    location: ExtentLocation::Sparse,
                }
            ]
        );
    }

    #[test]
    fn accepts_empty_list_and_zero_length_sparse_compatibility_run() {
        let empty = parse_mapping_pairs(&[0, 0], limits()).expect("empty terminated runlist");
        assert!(empty.extents.is_empty());
        assert_eq!(empty.encoded_runs, 0);
        assert_eq!(empty.bytes_consumed, 1);

        let zero_sparse = parse_mapping_pairs(&[0x01, 0, 0], limits())
            .expect("NTFS-3G-compatible zero sparse run");
        assert!(zero_sparse.extents.is_empty());
        assert_eq!(zero_sparse.encoded_runs, 1);
        assert_eq!(zero_sparse.decoded_clusters, 0);
    }

    #[test]
    fn rejects_missing_length_oversized_widths_and_truncation() {
        assert_eq!(
            parse_mapping_pairs(&[0x10, 0], limits()),
            Err(MappingPairsError::MissingRunLength { offset: 0 })
        );
        assert_eq!(
            parse_mapping_pairs(&[0x19, 0], limits()),
            Err(MappingPairsError::FieldWidthTooLarge {
                field: MappingPairField::RunLength,
                offset: 0,
                width: 9,
            })
        );
        assert_eq!(
            parse_mapping_pairs(&[0x91, 0], limits()),
            Err(MappingPairsError::FieldWidthTooLarge {
                field: MappingPairField::LcnDelta,
                offset: 0,
                width: 9,
            })
        );
        assert_eq!(
            parse_mapping_pairs(&[0x21, 1, 2], limits()),
            Err(MappingPairsError::TruncatedRun {
                offset: 0,
                required_end: 4,
                actual: 3,
            })
        );
    }

    #[test]
    fn requires_terminator_and_zero_trailing_padding() {
        assert_eq!(
            parse_mapping_pairs(&[0x11, 1, 1], limits()),
            Err(MappingPairsError::MissingTerminator)
        );
        assert_eq!(
            parse_mapping_pairs(&[0, 0, 0x7f], limits()),
            Err(MappingPairsError::TrailingNonZeroByte {
                offset: 2,
                value: 0x7f,
            })
        );
    }

    #[test]
    fn enforces_encoded_run_and_decoded_cluster_caps() {
        let mut run_limited = limits();
        run_limited.max_runs = 1;
        assert_eq!(
            parse_mapping_pairs(&[0x01, 0, 0x01, 0, 0], run_limited),
            Err(MappingPairsError::RunLimitExceeded { maximum: 1 })
        );

        let mut cluster_limited = limits();
        cluster_limited.max_decoded_clusters = 4;
        assert_eq!(
            parse_mapping_pairs(&[0x01, 5, 0], cluster_limited),
            Err(MappingPairsError::DecodedClusterLimitExceeded {
                decoded: 5,
                maximum: 4,
            })
        );
    }

    #[test]
    fn rejects_vcn_overflow_and_end_evidence_mismatch() {
        let mut overflowing = limits();
        overflowing.starting_vcn = u64::MAX;
        assert_eq!(
            parse_mapping_pairs(&[0x01, 1, 0], overflowing),
            Err(MappingPairsError::VcnOverflow {
                vcn: u64::MAX,
                length: 1,
            })
        );

        let mut mismatched = limits();
        mismatched.expected_next_vcn = Some(7);
        assert_eq!(
            parse_mapping_pairs(&[0x01, 6, 0], mismatched),
            Err(MappingPairsError::ExpectedNextVcnMismatch {
                expected: 7,
                actual: 6,
            })
        );
    }

    #[test]
    fn rejects_zero_length_physical_and_negative_lcn() {
        assert_eq!(
            parse_mapping_pairs(&[0x11, 0, 1, 0], limits()),
            Err(MappingPairsError::ZeroLengthPhysicalRun { run_index: 0 })
        );
        assert_eq!(
            parse_mapping_pairs(&[0x11, 1, 0xff, 0], limits()),
            Err(MappingPairsError::NegativeLcn {
                run_index: 0,
                value: -1,
            })
        );
    }

    #[test]
    fn rejects_cumulative_lcn_overflow() {
        let mut config = limits();
        config.volume_cluster_count = u64::MAX;
        let mut bytes = vec![0x81, 1];
        bytes.extend_from_slice(&i64::MAX.to_le_bytes());
        bytes.extend_from_slice(&[0x11, 1, 1, 0]);
        assert_eq!(
            parse_mapping_pairs(&bytes, config),
            Err(MappingPairsError::LcnOverflow {
                run_index: 1,
                previous_lcn: i64::MAX,
                delta: 1,
            })
        );
    }

    #[test]
    fn rejects_physical_extent_outside_volume_or_u64_end() {
        let mut outside = limits();
        outside.volume_cluster_count = 10;
        assert_eq!(
            parse_mapping_pairs(&[0x11, 2, 9, 0], outside),
            Err(MappingPairsError::PhysicalRunOutOfBounds {
                run_index: 0,
                lcn: 9,
                length: 2,
                volume_cluster_count: 10,
            })
        );

        let mut overflow = limits();
        overflow.volume_cluster_count = u64::MAX;
        let mut bytes = vec![0x88];
        bytes.extend_from_slice(&u64::MAX.to_le_bytes());
        bytes.extend_from_slice(&i64::MAX.to_le_bytes());
        bytes.push(0);
        assert_eq!(
            parse_mapping_pairs(&bytes, overflow),
            Err(MappingPairsError::PhysicalRunEndOverflow {
                run_index: 0,
                lcn: i64::MAX as u64,
                length: u64::MAX,
            })
        );
    }
}
