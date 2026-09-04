//! LZNT1 decompression for NTFS compressed `$DATA` streams.
//!
//! NTFS splits a compressed non-resident attribute into compression units (CU). The CU size in
//! clusters is `1 << compression_unit`; with 4 KiB clusters and `compression_unit == 4` that is
//! 16 clusters (64 KiB). Each CU is one of:
//!
//! * all sparse → zeros
//! * fully allocated → stored uncompressed
//! * fewer allocated clusters plus a sparse tail → LZNT1 of the allocated bytes
//!
//! LZNT1 (MS-XCA §2.5) is a sequence of 4 KiB chunks. Each chunk starts with a 16-bit header:
//! bit 15 compressed, bits 14–12 signature `011`, bits 11–0 payload length minus one.

use std::fmt;

use crate::extent::{Extent, ExtentKind, Placement, StreamId};

/// Framing or back-reference failure while decoding LZNT1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lznt1Error {
    TruncatedChunk,
    BackReferenceBeforeChunk,
    CompressionBlockTooLarge,
    ArithmeticOverflow,
}

impl fmt::Display for Lznt1Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedChunk => write!(formatter, "LZNT1 chunk is truncated"),
            Self::BackReferenceBeforeChunk => {
                write!(formatter, "LZNT1 back-reference predates the chunk")
            }
            Self::CompressionBlockTooLarge => {
                write!(formatter, "NTFS compression unit exceeds the decode limit")
            }
            Self::ArithmeticOverflow => write!(formatter, "NTFS compression arithmetic overflow"),
        }
    }
}

impl std::error::Error for Lznt1Error {}

/// Decompress one NTFS compression unit of LZNT1 into `dst`.
///
/// Trailing `dst` bytes past the last decoded chunk are left unchanged so the caller can
/// pre-zero a CU-sized buffer. Returns the number of bytes emitted from real chunks.
///
/// # Errors
///
/// Returns [`Lznt1Error`] when a chunk header oversteps `src` or a match predates the chunk.
pub fn decompress_unit(src: &[u8], dst: &mut [u8]) -> Result<usize, Lznt1Error> {
    let mut src_cursor = 0_usize;
    let mut dst_cursor = 0_usize;
    while src_cursor.saturating_add(2) <= src.len() && dst_cursor < dst.len() {
        let header = u16::from_le_bytes([src[src_cursor], src[src_cursor + 1]]);
        if header == 0 {
            break;
        }
        src_cursor += 2;
        let is_compressed = header & 0x8000 != 0;
        let chunk_len = usize::from(header & 0x0fff) + 1;
        let end = src_cursor
            .checked_add(chunk_len)
            .ok_or(Lznt1Error::ArithmeticOverflow)?;
        if end > src.len() {
            return Err(Lznt1Error::TruncatedChunk);
        }
        let chunk = &src[src_cursor..end];
        src_cursor = end;
        if !is_compressed {
            let take = chunk_len.min(dst.len() - dst_cursor);
            dst[dst_cursor..dst_cursor + take].copy_from_slice(&chunk[..take]);
            dst_cursor += take;
            continue;
        }
        let chunk_start = dst_cursor;
        let mut chunk_in = 0_usize;
        while chunk_in < chunk.len() && dst_cursor < dst.len() {
            let flags = chunk[chunk_in];
            chunk_in += 1;
            for bit in 0..8_u8 {
                if chunk_in >= chunk.len() || dst_cursor >= dst.len() {
                    break;
                }
                if flags & (1 << bit) == 0 {
                    dst[dst_cursor] = chunk[chunk_in];
                    chunk_in += 1;
                    dst_cursor += 1;
                    continue;
                }
                if chunk_in
                    .checked_add(2)
                    .is_none_or(|needed| needed > chunk.len())
                {
                    return Err(Lznt1Error::TruncatedChunk);
                }
                let token = u16::from_le_bytes([chunk[chunk_in], chunk[chunk_in + 1]]);
                chunk_in += 2;
                let emitted = u32::try_from(dst_cursor - chunk_start)
                    .map_err(|_| Lznt1Error::ArithmeticOverflow)?;
                let offset_bits = bit_allocator_u(emitted);
                let length_bits = 16 - offset_bits;
                let length_mask = (1_u16 << length_bits) - 1;
                let length = usize::from(token & length_mask) + 3;
                let offset = usize::from(token >> length_bits) + 1;
                if offset > dst_cursor - chunk_start {
                    return Err(Lznt1Error::BackReferenceBeforeChunk);
                }
                let src_pos = dst_cursor - offset;
                let take = length.min(dst.len() - dst_cursor);
                for index in 0..take {
                    dst[dst_cursor + index] = dst[src_pos + index];
                }
                dst_cursor += take;
            }
        }
    }
    Ok(dst_cursor)
}

const fn bit_allocator_u(emitted: u32) -> u32 {
    let mut offset_bits = 4_u32;
    let mut threshold = 1_u32 << 4;
    while emitted >= threshold && offset_bits < 12 {
        offset_bits += 1;
        threshold <<= 1;
    }
    offset_bits
}

/// Rebuild dest-native plaintext for one NTFS compressed stream from source extents.
///
/// # Errors
///
/// Returns [`Lznt1Error`] for malformed LZNT1, a CU larger than 16 MiB, or a physical read
/// failure mapped by `read_physical`.
pub fn materialize_ntfs_compressed_stream<E, F>(
    extents: &[Extent],
    stream: StreamId,
    compression_block_bytes: u64,
    initialized_bytes: u64,
    dest_len: usize,
    mut read_physical: F,
) -> Result<Vec<u8>, E>
where
    E: From<Lznt1Error>,
    F: FnMut(u64, usize) -> Result<Vec<u8>, E>,
{
    if compression_block_bytes == 0 {
        return Err(E::from(Lznt1Error::CompressionBlockTooLarge));
    }
    if compression_block_bytes > 16 * 1024 * 1024 {
        return Err(E::from(Lznt1Error::CompressionBlockTooLarge));
    }
    let block = usize::try_from(compression_block_bytes)
        .map_err(|_| E::from(Lznt1Error::ArithmeticOverflow))?;
    let mut destination = vec![0_u8; dest_len];
    let logical_end = initialized_bytes.min(u64::try_from(dest_len).unwrap_or(u64::MAX));
    let mut cu_start = 0_u64;
    while cu_start < logical_end {
        let window_end = cu_start
            .checked_add(compression_block_bytes)
            .ok_or_else(|| E::from(Lznt1Error::ArithmeticOverflow))?;
        let (physical, physical_bytes, sparse_bytes) =
            collect_cu_payload(extents, stream, cu_start, window_end, &mut read_physical)?;
        let dest_start =
            usize::try_from(cu_start).map_err(|_| E::from(Lznt1Error::ArithmeticOverflow))?;
        if dest_start >= dest_len {
            break;
        }
        let copy =
            (logical_end - cu_start).min(u64::try_from(dest_len - dest_start).unwrap_or(u64::MAX));
        let copy = usize::try_from(copy).map_err(|_| E::from(Lznt1Error::ArithmeticOverflow))?;
        if physical_bytes == 0 {
            cu_start = window_end;
            continue;
        }
        let window = window_end - cu_start;
        if sparse_bytes == 0 && physical_bytes == window {
            let take = copy.min(physical.len());
            destination[dest_start..dest_start + take].copy_from_slice(&physical[..take]);
        } else {
            let mut unit = vec![0_u8; block];
            decompress_unit(&physical, &mut unit).map_err(E::from)?;
            let take = copy.min(unit.len());
            destination[dest_start..dest_start + take].copy_from_slice(&unit[..take]);
        }
        cu_start = window_end;
    }
    Ok(destination)
}

fn collect_cu_payload<E, F>(
    extents: &[Extent],
    stream: StreamId,
    cu_start: u64,
    window_end: u64,
    read_physical: &mut F,
) -> Result<(Vec<u8>, u64, u64), E>
where
    E: From<Lznt1Error>,
    F: FnMut(u64, usize) -> Result<Vec<u8>, E>,
{
    let mut physical = Vec::new();
    let mut physical_bytes = 0_u64;
    let mut sparse_bytes = 0_u64;
    for extent in extents.iter().filter(|extent| {
        extent.stream == stream
            && extent.kind == ExtentKind::FileData
            && extent.logical_offset < window_end
            && extent
                .logical_offset
                .checked_add(extent.length)
                .is_some_and(|end| end > cu_start)
    }) {
        let overlap_start = extent.logical_offset.max(cu_start);
        let overlap_end = extent
            .logical_offset
            .checked_add(extent.length)
            .ok_or_else(|| E::from(Lznt1Error::ArithmeticOverflow))?
            .min(window_end);
        if overlap_end <= overlap_start {
            continue;
        }
        let overlap = overlap_end - overlap_start;
        match extent.placement {
            Placement::Sparse => {
                sparse_bytes = sparse_bytes
                    .checked_add(overlap)
                    .ok_or_else(|| E::from(Lznt1Error::ArithmeticOverflow))?;
            }
            Placement::Physical { byte_offset } => {
                let skip = overlap_start - extent.logical_offset;
                let read_at = byte_offset
                    .checked_add(skip)
                    .ok_or_else(|| E::from(Lznt1Error::ArithmeticOverflow))?;
                let take = usize::try_from(overlap)
                    .map_err(|_| E::from(Lznt1Error::ArithmeticOverflow))?;
                let bytes = read_physical(read_at, take)?;
                if bytes.len() != take {
                    return Err(E::from(Lznt1Error::TruncatedChunk));
                }
                physical
                    .try_reserve(take)
                    .map_err(|_| E::from(Lznt1Error::ArithmeticOverflow))?;
                physical.extend_from_slice(&bytes);
                physical_bytes = physical_bytes
                    .checked_add(overlap)
                    .ok_or_else(|| E::from(Lznt1Error::ArithmeticOverflow))?;
            }
        }
    }
    Ok((physical, physical_bytes, sparse_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compressed_header(payload_len: usize) -> u16 {
        0xb000 | u16::try_from(payload_len.saturating_sub(1)).unwrap()
    }

    fn literal_header(payload_len: usize) -> u16 {
        0x3000 | u16::try_from(payload_len.saturating_sub(1)).unwrap()
    }

    #[test]
    fn decompresses_literal_chunk() {
        let mut src = literal_header(4).to_le_bytes().to_vec();
        src.extend_from_slice(b"ABCD");
        src.extend_from_slice(&[0, 0]);
        let mut dst = vec![0_u8; 16];
        let emitted = decompress_unit(&src, &mut dst).unwrap();
        assert_eq!(emitted, 4);
        assert_eq!(&dst[..4], b"ABCD");
        assert_eq!(&dst[4..], &[0_u8; 12]);
    }

    #[test]
    fn decompresses_all_literal_compressed_chunk() {
        let payload = [0x00_u8, b'A', b'B', b'C', b'D', b'E', b'F', b'G', b'H'];
        let mut src = compressed_header(payload.len()).to_le_bytes().to_vec();
        src.extend_from_slice(&payload);
        src.extend_from_slice(&[0, 0]);
        let mut dst = vec![0_u8; 16];
        let emitted = decompress_unit(&src, &mut dst).unwrap();
        assert_eq!(emitted, 8);
        assert_eq!(&dst[..8], b"ABCDEFGH");
    }

    #[test]
    fn decompresses_back_reference() {
        let payload = [0x08_u8, b'A', b'B', b'C', 0x00, 0x20];
        let mut src = compressed_header(payload.len()).to_le_bytes().to_vec();
        src.extend_from_slice(&payload);
        src.extend_from_slice(&[0, 0]);
        let mut dst = vec![0_u8; 16];
        let emitted = decompress_unit(&src, &mut dst).unwrap();
        assert_eq!(emitted, 6);
        assert_eq!(&dst[..6], b"ABCABC");
    }

    #[test]
    fn back_reference_self_overlap() {
        let payload = [0x02_u8, b'X', 0x02, 0x00];
        let mut src = compressed_header(payload.len()).to_le_bytes().to_vec();
        src.extend_from_slice(&payload);
        src.extend_from_slice(&[0, 0]);
        let mut dst = vec![0_u8; 16];
        let emitted = decompress_unit(&src, &mut dst).unwrap();
        assert_eq!(emitted, 6);
        assert_eq!(&dst[..6], b"XXXXXX");
    }

    #[test]
    fn bit_allocator_clamps() {
        assert_eq!(bit_allocator_u(0), 4);
        assert_eq!(bit_allocator_u(15), 4);
        assert_eq!(bit_allocator_u(16), 5);
        assert_eq!(bit_allocator_u(31), 5);
        assert_eq!(bit_allocator_u(32), 6);
        assert_eq!(bit_allocator_u(4095), 12);
        assert_eq!(bit_allocator_u(8192), 12);
    }

    #[test]
    fn compressed_unit_with_sparse_tail_decompresses_logical_bytes() {
        let payload = [0x08_u8, b'A', b'B', b'C', 0x00, 0x20];
        let mut encoded = compressed_header(payload.len()).to_le_bytes().to_vec();
        encoded.extend_from_slice(&payload);
        encoded.extend_from_slice(&[0, 0]);
        encoded.resize(4096, 0);
        let extents = vec![
            Extent {
                stream: StreamId(7),
                logical_offset: 0,
                length: 4096,
                placement: Placement::Physical { byte_offset: 0 },
                kind: ExtentKind::FileData,
            },
            Extent {
                stream: StreamId(7),
                logical_offset: 4096,
                length: 15 * 4096,
                placement: Placement::Sparse,
                kind: ExtentKind::FileData,
            },
        ];
        let dest = materialize_ntfs_compressed_stream(
            &extents,
            StreamId(7),
            16 * 4096,
            6,
            4096,
            |offset, length| {
                assert_eq!(offset, 0);
                let start = usize::try_from(offset).map_err(|_| Lznt1Error::ArithmeticOverflow)?;
                Ok::<Vec<u8>, Lznt1Error>(encoded[start..start + length].to_vec())
            },
        )
        .unwrap();
        assert_eq!(&dest[..6], b"ABCABC");
        assert!(dest[6..].iter().all(|byte| *byte == 0));
    }
}
