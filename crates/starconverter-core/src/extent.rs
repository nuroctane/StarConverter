//! Filesystem-neutral physical and logical extent validation.
//!
//! Format parsers emit extents into this layer only after validating their own on-disk metadata.
//! The graph then proves volume bounds, physical non-overlap, and per-stream logical non-overlap
//! before any geometry or conversion planner may consume them.

use std::fmt;

/// Stable parser-assigned identity for one data stream or metadata object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StreamId(pub u64);

/// Semantic role of one extent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtentKind {
    FileData,
    DirectoryData,
    FileSystemMetadata,
    Reserved,
    BadCluster,
}

/// Physical placement of an extent, or an intentionally unallocated sparse range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placement {
    Physical { byte_offset: u64 },
    Sparse,
}

/// One filesystem-neutral stream extent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extent {
    pub stream: StreamId,
    pub logical_offset: u64,
    pub length: u64,
    pub placement: Placement,
    pub kind: ExtentKind,
}

/// Validated, deterministically ordered extents for a bounded volume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtentGraph {
    volume_bytes: u64,
    extents: Vec<Extent>,
    physically_allocated_bytes: u64,
    sparse_bytes: u64,
}

impl ExtentGraph {
    /// Validates and orders a caller-bounded collection of extents.
    ///
    /// # Errors
    ///
    /// Returns [`ExtentGraphError`] if the input exceeds `max_extents`, contains zero-length or
    /// overflowing ranges, places physical data outside the volume, overlaps physical storage, or
    /// overlaps logical ranges within one stream.
    pub fn build(
        mut extents: Vec<Extent>,
        volume_bytes: u64,
        max_extents: usize,
    ) -> Result<Self, ExtentGraphError> {
        if extents.len() > max_extents {
            return Err(ExtentGraphError::TooManyExtents {
                actual: extents.len(),
                maximum: max_extents,
            });
        }

        for extent in &extents {
            validate_extent(*extent, volume_bytes)?;
        }
        validate_logical_ranges(&extents)?;
        validate_physical_ranges(&extents)?;

        extents.sort_unstable_by_key(|extent| {
            (
                extent.stream,
                extent.logical_offset,
                placement_sort_key(extent.placement),
            )
        });

        let mut physically_allocated_bytes = 0_u64;
        let mut sparse_bytes = 0_u64;
        for extent in &extents {
            match extent.placement {
                Placement::Physical { .. } => {
                    physically_allocated_bytes = physically_allocated_bytes
                        .checked_add(extent.length)
                        .ok_or(ExtentGraphError::AccountingOverflow)?;
                }
                Placement::Sparse => {
                    sparse_bytes = sparse_bytes
                        .checked_add(extent.length)
                        .ok_or(ExtentGraphError::AccountingOverflow)?;
                }
            }
        }

        Ok(Self {
            volume_bytes,
            extents,
            physically_allocated_bytes,
            sparse_bytes,
        })
    }

    #[must_use]
    pub const fn volume_bytes(&self) -> u64 {
        self.volume_bytes
    }

    #[must_use]
    pub fn extents(&self) -> &[Extent] {
        &self.extents
    }

    #[must_use]
    pub const fn physically_allocated_bytes(&self) -> u64 {
        self.physically_allocated_bytes
    }

    #[must_use]
    pub const fn sparse_bytes(&self) -> u64 {
        self.sparse_bytes
    }
}

/// Failure to establish an internally consistent extent graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtentGraphError {
    TooManyExtents {
        actual: usize,
        maximum: usize,
    },
    ZeroLength {
        stream: StreamId,
        logical_offset: u64,
    },
    LogicalRangeOverflow {
        stream: StreamId,
        logical_offset: u64,
        length: u64,
    },
    PhysicalRangeOverflow {
        byte_offset: u64,
        length: u64,
    },
    PhysicalRangeOutsideVolume {
        byte_offset: u64,
        length: u64,
        volume_bytes: u64,
    },
    SparseMetadata {
        stream: StreamId,
        kind: ExtentKind,
    },
    LogicalOverlap {
        stream: StreamId,
        first_offset: u64,
        second_offset: u64,
    },
    PhysicalOverlap {
        first_offset: u64,
        second_offset: u64,
    },
    AccountingOverflow,
}

impl fmt::Display for ExtentGraphError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyExtents { actual, maximum } => {
                write!(
                    formatter,
                    "extent count {actual} exceeds configured maximum {maximum}"
                )
            }
            Self::ZeroLength {
                stream,
                logical_offset,
            } => write!(
                formatter,
                "stream {} has a zero-length extent at logical byte {logical_offset}",
                stream.0
            ),
            Self::LogicalRangeOverflow {
                stream,
                logical_offset,
                length,
            } => write!(
                formatter,
                "stream {} logical range overflows: offset {logical_offset}, length {length}",
                stream.0
            ),
            Self::PhysicalRangeOverflow {
                byte_offset,
                length,
            } => write!(
                formatter,
                "physical range overflows: offset {byte_offset}, length {length}"
            ),
            Self::PhysicalRangeOutsideVolume {
                byte_offset,
                length,
                volume_bytes,
            } => write!(
                formatter,
                "physical range offset {byte_offset}, length {length} exceeds {volume_bytes}-byte volume"
            ),
            Self::SparseMetadata { stream, kind } => write!(
                formatter,
                "stream {} has an invalid sparse {kind:?} extent",
                stream.0
            ),
            Self::LogicalOverlap {
                stream,
                first_offset,
                second_offset,
            } => write!(
                formatter,
                "stream {} logical extents at {first_offset} and {second_offset} overlap",
                stream.0
            ),
            Self::PhysicalOverlap {
                first_offset,
                second_offset,
            } => write!(
                formatter,
                "physical extents at {first_offset} and {second_offset} overlap"
            ),
            Self::AccountingOverflow => formatter.write_str("extent byte accounting overflowed"),
        }
    }
}

impl std::error::Error for ExtentGraphError {}

fn validate_extent(extent: Extent, volume_bytes: u64) -> Result<(), ExtentGraphError> {
    if extent.length == 0 {
        return Err(ExtentGraphError::ZeroLength {
            stream: extent.stream,
            logical_offset: extent.logical_offset,
        });
    }
    extent.logical_offset.checked_add(extent.length).ok_or(
        ExtentGraphError::LogicalRangeOverflow {
            stream: extent.stream,
            logical_offset: extent.logical_offset,
            length: extent.length,
        },
    )?;

    match extent.placement {
        Placement::Physical { byte_offset } => {
            let end = byte_offset.checked_add(extent.length).ok_or(
                ExtentGraphError::PhysicalRangeOverflow {
                    byte_offset,
                    length: extent.length,
                },
            )?;
            if end > volume_bytes {
                return Err(ExtentGraphError::PhysicalRangeOutsideVolume {
                    byte_offset,
                    length: extent.length,
                    volume_bytes,
                });
            }
        }
        Placement::Sparse if extent.kind != ExtentKind::FileData => {
            return Err(ExtentGraphError::SparseMetadata {
                stream: extent.stream,
                kind: extent.kind,
            });
        }
        Placement::Sparse => {}
    }
    Ok(())
}

fn validate_logical_ranges(extents: &[Extent]) -> Result<(), ExtentGraphError> {
    let mut logical = extents.to_vec();
    logical.sort_unstable_by_key(|extent| (extent.stream, extent.logical_offset));
    for pair in logical.windows(2) {
        let first = pair[0];
        let second = pair[1];
        if first.stream == second.stream
            && first.logical_offset + first.length > second.logical_offset
        {
            return Err(ExtentGraphError::LogicalOverlap {
                stream: first.stream,
                first_offset: first.logical_offset,
                second_offset: second.logical_offset,
            });
        }
    }
    Ok(())
}

fn validate_physical_ranges(extents: &[Extent]) -> Result<(), ExtentGraphError> {
    let mut physical = extents
        .iter()
        .filter_map(|extent| match extent.placement {
            Placement::Physical { byte_offset } => Some((byte_offset, extent.length)),
            Placement::Sparse => None,
        })
        .collect::<Vec<_>>();
    physical.sort_unstable_by_key(|&(offset, _)| offset);
    for pair in physical.windows(2) {
        let (first_offset, first_length) = pair[0];
        let (second_offset, _) = pair[1];
        if first_offset + first_length > second_offset {
            return Err(ExtentGraphError::PhysicalOverlap {
                first_offset,
                second_offset,
            });
        }
    }
    Ok(())
}

const fn placement_sort_key(placement: Placement) -> (u8, u64) {
    match placement {
        Placement::Physical { byte_offset } => (0, byte_offset),
        Placement::Sparse => (1, 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn physical(stream: u64, logical: u64, physical: u64, length: u64) -> Extent {
        Extent {
            stream: StreamId(stream),
            logical_offset: logical,
            length,
            placement: Placement::Physical {
                byte_offset: physical,
            },
            kind: ExtentKind::FileData,
        }
    }

    #[test]
    fn builds_deterministic_graph_and_accounts_sparse_ranges() {
        let sparse = Extent {
            stream: StreamId(2),
            logical_offset: 0,
            length: 4096,
            placement: Placement::Sparse,
            kind: ExtentKind::FileData,
        };
        let graph = ExtentGraph::build(
            vec![
                physical(1, 4096, 8192, 4096),
                sparse,
                physical(1, 0, 4096, 4096),
            ],
            16_384,
            3,
        )
        .unwrap();

        assert_eq!(graph.extents()[0].logical_offset, 0);
        assert_eq!(graph.extents()[1].logical_offset, 4096);
        assert_eq!(graph.physically_allocated_bytes(), 8192);
        assert_eq!(graph.sparse_bytes(), 4096);
    }

    #[test]
    fn rejects_count_zero_overflow_and_out_of_volume() {
        assert!(matches!(
            ExtentGraph::build(vec![physical(1, 0, 0, 1)], 1, 0),
            Err(ExtentGraphError::TooManyExtents { .. })
        ));
        assert!(matches!(
            ExtentGraph::build(vec![physical(1, 0, 0, 0)], 1, 1),
            Err(ExtentGraphError::ZeroLength { .. })
        ));
        assert!(matches!(
            ExtentGraph::build(vec![physical(1, u64::MAX, 0, 2)], 4, 1),
            Err(ExtentGraphError::LogicalRangeOverflow { .. })
        ));
        assert!(matches!(
            ExtentGraph::build(vec![physical(1, 0, u64::MAX, 2)], u64::MAX, 1),
            Err(ExtentGraphError::PhysicalRangeOverflow { .. })
        ));
        assert!(matches!(
            ExtentGraph::build(vec![physical(1, 0, 4, 2)], 5, 1),
            Err(ExtentGraphError::PhysicalRangeOutsideVolume { .. })
        ));
    }

    #[test]
    fn rejects_logical_and_physical_overlap_but_allows_adjacency() {
        assert!(matches!(
            ExtentGraph::build(vec![physical(1, 0, 0, 4), physical(1, 3, 8, 4)], 16, 2),
            Err(ExtentGraphError::LogicalOverlap { .. })
        ));
        assert!(matches!(
            ExtentGraph::build(vec![physical(1, 0, 0, 4), physical(2, 0, 3, 4)], 16, 2),
            Err(ExtentGraphError::PhysicalOverlap { .. })
        ));
        assert!(ExtentGraph::build(vec![physical(1, 0, 0, 4), physical(1, 4, 4, 4)], 8, 2).is_ok());
    }

    #[test]
    fn sparse_is_only_valid_for_file_payloads() {
        let metadata = Extent {
            stream: StreamId(9),
            logical_offset: 0,
            length: 1,
            placement: Placement::Sparse,
            kind: ExtentKind::FileSystemMetadata,
        };
        assert!(matches!(
            ExtentGraph::build(vec![metadata], 1, 1),
            Err(ExtentGraphError::SparseMetadata { .. })
        ));
    }
}
