//! Canonical, pure NTFS 3.1 `$Secure` metadata construction and validation.
//!
//! This module has no I/O and does not build an MFT record. It emits the exact `$SDS` stream
//! payload and the ordered index-entry sequences which a caller can place inside resident `$SII`
//! and `$SDH` index roots. The caller remains responsible for the `$Secure` FILE record,
//! attribute headers, index-root headers, and geometry.
//!
//! Provenance and deliberately narrow compatibility contract:
//!
//! - Microsoft documents `$Secure:$SDS`, `$Secure:$SII`, and `$Secure:$SDH` as NTFS metadata
//!   streams, and NTFS as deduplicating security descriptors.
//! - The byte layout, two initial descriptors, hashes, IDs, duplicate-copy distance, entry sizes,
//!   and collation rules are pinned to `ntfs-3g` commit
//!   `d327833ec1d5eb1358b6f2c37139f10a3460944d`, specifically `ntfsprogs/sd.c`,
//!   `ntfsprogs/mkntfs.c`, `libntfs-3g/security.c`, and `include/ntfs-3g/layout.h`.
//! - That formatter describes this payload as matching a newly formatted Windows 2003 NTFS 3.1
//!   volume. A byte-for-byte claim for modern native Windows formatters is intentionally refused.
//!
//! The validator parses and cross-checks every structure rather than comparing against freshly
//! generated output. It rejects unknown profiles, trailing bytes, non-zero padding, malformed
//! self-relative descriptors, unsorted indexes, mismatched copies, and inconsistent index data.

use std::fmt;

const SDS_HEADER_BYTES: usize = 20;
const SDS_ALIGNMENT: usize = 16;
const SDS_COPY_DISTANCE: usize = 0x40000;
const FIRST_COPY_BYTES: usize = 0xfc;
const CANONICAL_SDS_BYTES: usize = SDS_COPY_DISTANCE + FIRST_COPY_BYTES;
const CANONICAL_DESCRIPTOR_BYTES: usize = 0x68;
const CANONICAL_ENTRY_BYTES: usize = SDS_HEADER_BYTES + CANONICAL_DESCRIPTOR_BYTES;
const CANONICAL_ENTRY_LENGTH: u32 = 0x7c;
const SII_ENTRY_BYTES: usize = 0x28;
const SDH_ENTRY_BYTES: usize = 0x30;
const INDEX_END_ENTRY_BYTES: usize = 0x10;
const INDEX_END_ENTRY_LENGTH: u16 = 0x10;
const CANONICAL_DESCRIPTOR_COUNT: usize = 2;
const CANONICAL_SII_BYTES: usize =
    CANONICAL_DESCRIPTOR_COUNT * SII_ENTRY_BYTES + INDEX_END_ENTRY_BYTES;
const CANONICAL_SDH_BYTES: usize =
    CANONICAL_DESCRIPTOR_COUNT * SDH_ENTRY_BYTES + INDEX_END_ENTRY_BYTES;
const SECURITY_ID_READ_ONLY: u32 = 0x100;
const SECURITY_ID_READ_WRITE: u32 = 0x101;
const HASH_READ_ONLY: u32 = 0xf803_12f0;
const HASH_READ_WRITE: u32 = 0x00b3_2451;
const READ_ONLY_MASK: u32 = 0x0012_0089;
const READ_WRITE_MASK: u32 = 0x0012_019f;
const SE_SELF_RELATIVE_AND_DACL_PRESENT: u16 = 0x8004;
const INDEX_ENTRY_END: u16 = 0x0002;
const SDH_RESERVED_II: u32 = 0x0049_0049;

/// `$SII` uses ascending little-endian `u32` collation.
pub const SII_COLLATION_NTOFS_ULONG: u32 = 16;
/// `$SDH` uses ascending `(hash, security_id)` collation.
pub const SDH_COLLATION_NTOFS_SECURITY_HASH: u32 = 18;

/// The only output profile whose bytes are justified by the pinned sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtfsSecureProfile {
    /// Initial NTFS 3.1 `$Secure` state emitted by the pinned `mkntfs` implementation.
    MkntfsWindows2003Ntfs31,
    /// Reserved to make refusal of an unverified modern-native format explicit.
    ModernWindowsNative,
}

/// Caller-controlled work and output bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtfsSecureLimits {
    pub max_sds_bytes: usize,
    pub max_index_bytes: usize,
    pub max_descriptors: usize,
    pub max_descriptor_bytes: usize,
}

impl Default for NtfsSecureLimits {
    fn default() -> Self {
        Self {
            max_sds_bytes: 1024 * 1024,
            max_index_bytes: 64 * 1024,
            max_descriptors: 4096,
            max_descriptor_bytes: 64 * 1024,
        }
    }
}

/// Exact stream payloads and index-entry fragments for a canonical `$Secure` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsSecureMetadata {
    /// Complete `$Secure:$SDS:$DATA` value, including its zero gap and duplicate copy.
    pub sds: Vec<u8>,
    /// Ordered entries for `$Secure:$SII`, followed by one terminal `INDEX_ENTRY_END`.
    pub sii_index_entries: Vec<u8>,
    /// Ordered entries for `$Secure:$SDH`, followed by one terminal `INDEX_ENTRY_END`.
    pub sdh_index_entries: Vec<u8>,
    pub sii_collation_rule: u32,
    pub sdh_collation_rule: u32,
}

/// A validated descriptor record, useful when wiring object security IDs into
/// `$STANDARD_INFORMATION`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtfsSecureDescriptorSummary {
    pub hash: u32,
    pub security_id: u32,
    pub primary_offset: u64,
    /// Header plus self-relative descriptor; alignment padding is excluded.
    pub entry_length: u32,
}

/// Successful independent validation result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsSecureValidation {
    pub descriptors: Vec<NtfsSecureDescriptorSummary>,
}

/// Precise refusal or malformed-input reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NtfsSecureError {
    UnsupportedProfile {
        profile: NtfsSecureProfile,
        reason: &'static str,
    },
    LimitExceeded {
        what: &'static str,
        actual: usize,
        limit: usize,
    },
    AllocationFailed {
        what: &'static str,
    },
    HashInputNotWordAligned {
        length: usize,
    },
    Malformed {
        component: &'static str,
        offset: usize,
        reason: &'static str,
    },
}

impl fmt::Display for NtfsSecureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedProfile { profile, reason } => {
                write!(
                    formatter,
                    "unsupported NTFS secure profile {profile:?}: {reason}"
                )
            }
            Self::LimitExceeded {
                what,
                actual,
                limit,
            } => write!(
                formatter,
                "{what} requires {actual} units, exceeding limit {limit}"
            ),
            Self::AllocationFailed { what } => {
                write!(formatter, "allocation failed while constructing {what}")
            }
            Self::HashInputNotWordAligned { length } => write!(
                formatter,
                "security descriptor length {length} is not a multiple of four"
            ),
            Self::Malformed {
                component,
                offset,
                reason,
            } => write!(
                formatter,
                "malformed {component} at byte {offset}: {reason}"
            ),
        }
    }
}

impl std::error::Error for NtfsSecureError {}

/// Generate the pinned minimal NTFS 3.1 `$Secure` state.
///
/// # Errors
///
/// Returns [`NtfsSecureError::UnsupportedProfile`] for profiles without pinned
/// provenance, [`NtfsSecureError::LimitExceeded`] when a caller bound is too
/// small, or [`NtfsSecureError::AllocationFailed`] if an output allocation fails.
pub fn generate_ntfs_secure_metadata(
    profile: NtfsSecureProfile,
    limits: NtfsSecureLimits,
) -> Result<NtfsSecureMetadata, NtfsSecureError> {
    if profile != NtfsSecureProfile::MkntfsWindows2003Ntfs31 {
        return Err(NtfsSecureError::UnsupportedProfile {
            profile,
            reason: "modern Windows-native formatter bytes have not been independently pinned",
        });
    }
    require_limit("SDS bytes", CANONICAL_SDS_BYTES, limits.max_sds_bytes)?;
    require_limit(
        "SII index bytes",
        CANONICAL_SII_BYTES,
        limits.max_index_bytes,
    )?;
    require_limit(
        "SDH index bytes",
        CANONICAL_SDH_BYTES,
        limits.max_index_bytes,
    )?;
    require_limit(
        "security descriptors",
        CANONICAL_DESCRIPTOR_COUNT,
        limits.max_descriptors,
    )?;
    require_limit(
        "security descriptor bytes",
        CANONICAL_DESCRIPTOR_BYTES,
        limits.max_descriptor_bytes,
    )?;

    let mut sds = zeroed_vec(CANONICAL_SDS_BYTES, "$SDS")?;
    let read_only = build_descriptor(READ_ONLY_MASK)?;
    let read_write = build_descriptor(READ_WRITE_MASK)?;
    write_sds_entry(
        &mut sds,
        0,
        HASH_READ_ONLY,
        SECURITY_ID_READ_ONLY,
        &read_only,
    );
    write_sds_entry(
        &mut sds,
        0x80,
        HASH_READ_WRITE,
        SECURITY_ID_READ_WRITE,
        &read_write,
    );
    let (primary, duplicate) = sds.split_at_mut(SDS_COPY_DISTANCE);
    duplicate.copy_from_slice(&primary[..FIRST_COPY_BYTES]);

    let mut descriptors = [
        NtfsSecureDescriptorSummary {
            hash: HASH_READ_ONLY,
            security_id: SECURITY_ID_READ_ONLY,
            primary_offset: 0,
            entry_length: CANONICAL_ENTRY_LENGTH,
        },
        NtfsSecureDescriptorSummary {
            hash: HASH_READ_WRITE,
            security_id: SECURITY_ID_READ_WRITE,
            primary_offset: 0x80,
            entry_length: CANONICAL_ENTRY_LENGTH,
        },
    ];

    let mut sii_index_entries = zeroed_vec(CANONICAL_SII_BYTES, "$SII")?;
    descriptors.sort_by_key(|entry| entry.security_id);
    for (index, descriptor) in descriptors.iter().enumerate() {
        write_sii_entry(
            &mut sii_index_entries[index * SII_ENTRY_BYTES..][..SII_ENTRY_BYTES],
            *descriptor,
        );
    }
    write_index_end(&mut sii_index_entries[2 * SII_ENTRY_BYTES..]);

    let mut sdh_index_entries = zeroed_vec(CANONICAL_SDH_BYTES, "$SDH")?;
    descriptors.sort_by_key(|entry| (entry.hash, entry.security_id));
    for (index, descriptor) in descriptors.iter().enumerate() {
        write_sdh_entry(
            &mut sdh_index_entries[index * SDH_ENTRY_BYTES..][..SDH_ENTRY_BYTES],
            *descriptor,
        );
    }
    write_index_end(&mut sdh_index_entries[2 * SDH_ENTRY_BYTES..]);

    Ok(NtfsSecureMetadata {
        sds,
        sii_index_entries,
        sdh_index_entries,
        sii_collation_rule: SII_COLLATION_NTOFS_ULONG,
        sdh_collation_rule: SDH_COLLATION_NTOFS_SECURITY_HASH,
    })
}

/// Validate a minimal canonical metadata set by parsing all three payloads and cross-referencing
/// their hashes, IDs, offsets, lengths, ordering, padding, and duplicate `$SDS` copy.
///
/// # Errors
///
/// Returns [`NtfsSecureError::LimitExceeded`] when a caller bound is exceeded,
/// [`NtfsSecureError::AllocationFailed`] if summary allocation fails, or
/// [`NtfsSecureError::Malformed`] for any non-canonical or inconsistent byte.
pub fn validate_ntfs_secure_metadata(
    metadata: &NtfsSecureMetadata,
    limits: NtfsSecureLimits,
) -> Result<NtfsSecureValidation, NtfsSecureError> {
    require_limit("SDS bytes", metadata.sds.len(), limits.max_sds_bytes)?;
    require_limit(
        "SII index bytes",
        metadata.sii_index_entries.len(),
        limits.max_index_bytes,
    )?;
    require_limit(
        "SDH index bytes",
        metadata.sdh_index_entries.len(),
        limits.max_index_bytes,
    )?;
    if metadata.sii_collation_rule != SII_COLLATION_NTOFS_ULONG {
        return malformed("$SII", 0, "wrong collation rule");
    }
    if metadata.sdh_collation_rule != SDH_COLLATION_NTOFS_SECURITY_HASH {
        return malformed("$SDH", 0, "wrong collation rule");
    }
    if metadata.sds.len() != CANONICAL_SDS_BYTES {
        return malformed("$SDS", metadata.sds.len(), "non-canonical stream length");
    }

    let descriptors = parse_sds(&metadata.sds, limits)?;
    let sii = parse_sii(&metadata.sii_index_entries, limits)?;
    let sdh = parse_sdh(&metadata.sdh_index_entries, limits)?;
    cross_check_indexes(&descriptors, &sii, &sdh)?;

    let mut summaries = Vec::new();
    summaries
        .try_reserve_exact(descriptors.len())
        .map_err(|_| NtfsSecureError::AllocationFailed {
            what: "validated descriptor summaries",
        })?;
    summaries.extend(descriptors.iter().map(ParsedSdsEntry::summary));
    Ok(NtfsSecureValidation {
        descriptors: summaries,
    })
}

/// Calculate the little-endian NTFS security hash used by `$SDS`, `$SII`, and `$SDH`.
///
/// Canonical self-relative security descriptors are word-aligned. The pinned C implementation
/// silently ignores a trailing partial word; this stricter API refuses one instead.
///
/// # Errors
///
/// Returns [`NtfsSecureError::HashInputNotWordAligned`] unless `descriptor`
/// contains a whole number of little-endian 32-bit words.
pub fn ntfs_security_descriptor_hash(descriptor: &[u8]) -> Result<u32, NtfsSecureError> {
    if descriptor.len() % 4 != 0 {
        return Err(NtfsSecureError::HashInputNotWordAligned {
            length: descriptor.len(),
        });
    }
    let mut hash = 0_u32;
    for word in descriptor.chunks_exact(4) {
        let value = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
        hash = value.wrapping_add(hash.rotate_left(3));
    }
    Ok(hash)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ParsedSdsEntry<'a> {
    hash: u32,
    security_id: u32,
    offset: u64,
    length: u32,
    descriptor: &'a [u8],
}

impl ParsedSdsEntry<'_> {
    const fn summary(&self) -> NtfsSecureDescriptorSummary {
        NtfsSecureDescriptorSummary {
            hash: self.hash,
            security_id: self.security_id,
            primary_offset: self.offset,
            entry_length: self.length,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ParsedIndexEntry {
    hash: u32,
    security_id: u32,
    offset: u64,
    length: u32,
}

fn parse_sds(
    sds: &[u8],
    limits: NtfsSecureLimits,
) -> Result<Vec<ParsedSdsEntry<'_>>, NtfsSecureError> {
    require_limit(
        "security descriptors",
        CANONICAL_DESCRIPTOR_COUNT,
        limits.max_descriptors,
    )?;
    if sds[FIRST_COPY_BYTES..SDS_COPY_DISTANCE]
        .iter()
        .any(|byte| *byte != 0)
    {
        return malformed("$SDS", FIRST_COPY_BYTES, "non-zero cache-boundary gap");
    }
    if sds[..FIRST_COPY_BYTES] != sds[SDS_COPY_DISTANCE..] {
        return malformed(
            "$SDS",
            SDS_COPY_DISTANCE,
            "duplicate descriptor copy differs from primary",
        );
    }

    let mut entries = Vec::new();
    entries
        .try_reserve_exact(CANONICAL_DESCRIPTOR_COUNT)
        .map_err(|_| NtfsSecureError::AllocationFailed {
            what: "parsed $SDS entries",
        })?;
    let mut cursor = 0_usize;
    while cursor < FIRST_COPY_BYTES {
        if entries.len() == limits.max_descriptors {
            return Err(NtfsSecureError::LimitExceeded {
                what: "security descriptors",
                actual: entries.len() + 1,
                limit: limits.max_descriptors,
            });
        }
        if cursor % SDS_ALIGNMENT != 0 {
            return malformed("$SDS", cursor, "descriptor is not 16-byte aligned");
        }
        let header = checked_slice(sds, cursor, SDS_HEADER_BYTES, "$SDS")?;
        let hash = read_u32(header, 0, "$SDS", cursor)?;
        let security_id = read_u32(header, 4, "$SDS", cursor)?;
        let offset = read_u64(header, 8, "$SDS", cursor)?;
        let length = read_u32(header, 16, "$SDS", cursor)?;
        let length_usize = usize::try_from(length)
            .map_err(|_| malformed_error("$SDS", cursor + 16, "entry length overflows usize"))?;
        if length_usize < SDS_HEADER_BYTES {
            return malformed("$SDS", cursor + 16, "entry shorter than its header");
        }
        let descriptor_length = length_usize - SDS_HEADER_BYTES;
        require_limit(
            "security descriptor bytes",
            descriptor_length,
            limits.max_descriptor_bytes,
        )?;
        let entry_end = cursor
            .checked_add(length_usize)
            .ok_or_else(|| malformed_error("$SDS", cursor + 16, "entry end offset overflows"))?;
        if entry_end > FIRST_COPY_BYTES {
            return malformed(
                "$SDS",
                cursor + 16,
                "entry crosses canonical first-copy end",
            );
        }
        let entry = checked_slice(sds, cursor, length_usize, "$SDS")?;
        let descriptor = &entry[SDS_HEADER_BYTES..];
        if offset != cursor as u64 {
            return malformed(
                "$SDS",
                cursor + 8,
                "header offset is not the primary offset",
            );
        }
        validate_canonical_descriptor(descriptor, security_id, cursor + SDS_HEADER_BYTES)?;
        if ntfs_security_descriptor_hash(descriptor)? != hash {
            return malformed("$SDS", cursor, "descriptor hash mismatch");
        }
        entries.push(ParsedSdsEntry {
            hash,
            security_id,
            offset,
            length,
            descriptor,
        });
        cursor = next_sds_cursor(sds, cursor, entry_end)?;
    }
    if cursor != FIRST_COPY_BYTES {
        return malformed("$SDS", cursor, "first copy does not end canonically");
    }
    if entries.len() != CANONICAL_DESCRIPTOR_COUNT {
        return malformed("$SDS", cursor, "wrong number of initial descriptors");
    }
    if entries[0].security_id != SECURITY_ID_READ_ONLY
        || entries[1].security_id != SECURITY_ID_READ_WRITE
    {
        return malformed("$SDS", 4, "non-canonical security IDs or order");
    }
    Ok(entries)
}

fn next_sds_cursor(sds: &[u8], cursor: usize, entry_end: usize) -> Result<usize, NtfsSecureError> {
    // Only the *start* of each SDS_ENTRY is 16-byte aligned.  The pinned
    // formatter's final entry ends at 0xfc and the stream terminates there;
    // it does not append four bytes merely to round the data size to 0x100.
    if entry_end == FIRST_COPY_BYTES {
        return Ok(entry_end);
    }
    let next = align_up(entry_end, SDS_ALIGNMENT)
        .ok_or_else(|| malformed_error("$SDS", cursor + 16, "next entry offset overflows"))?;
    if next > FIRST_COPY_BYTES {
        return malformed(
            "$SDS",
            cursor + 16,
            "entry padding crosses canonical first-copy end",
        );
    }
    if sds[entry_end..next].iter().any(|byte| *byte != 0) {
        return malformed("$SDS", entry_end, "non-zero alignment padding");
    }
    Ok(next)
}

fn validate_canonical_descriptor(
    descriptor: &[u8],
    security_id: u32,
    base: usize,
) -> Result<(), NtfsSecureError> {
    if descriptor.len() != CANONICAL_DESCRIPTOR_BYTES {
        return malformed(
            "security descriptor",
            base,
            "non-canonical descriptor length",
        );
    }
    if descriptor[0] != 1 || descriptor[1] != 0 {
        return malformed(
            "security descriptor",
            base,
            "invalid revision or alignment byte",
        );
    }
    if read_u16(descriptor, 2, "security descriptor", base)? != SE_SELF_RELATIVE_AND_DACL_PRESENT {
        return malformed("security descriptor", base + 2, "unexpected control flags");
    }
    if read_u32(descriptor, 4, "security descriptor", base)? != 0x48
        || read_u32(descriptor, 8, "security descriptor", base)? != 0x58
        || read_u32(descriptor, 12, "security descriptor", base)? != 0
        || read_u32(descriptor, 16, "security descriptor", base)? != 0x14
    {
        return malformed(
            "security descriptor",
            base + 4,
            "invalid self-relative offsets",
        );
    }
    let acl = checked_slice(descriptor, 0x14, 0x34, "security descriptor")?;
    if acl[0] != 2
        || acl[1] != 0
        || read_u16(acl, 2, "DACL", base + 0x14)? != 0x34
        || read_u16(acl, 4, "DACL", base + 0x14)? != 2
        || read_u16(acl, 6, "DACL", base + 0x14)? != 0
    {
        return malformed("DACL", base + 0x14, "invalid canonical ACL header");
    }
    let mask = match security_id {
        SECURITY_ID_READ_ONLY => READ_ONLY_MASK,
        SECURITY_ID_READ_WRITE => READ_WRITE_MASK,
        _ => {
            return malformed(
                "security descriptor",
                base,
                "unsupported initial security ID",
            );
        }
    };
    validate_access_allowed_ace(descriptor, 0x1c, 0x14, mask, &[18], base)?;
    validate_access_allowed_ace(descriptor, 0x30, 0x18, mask, &[32, 544], base)?;
    validate_sid(descriptor, 0x48, &[32, 544], base)?;
    validate_sid(descriptor, 0x58, &[32, 544], base)?;
    Ok(())
}

fn validate_access_allowed_ace(
    descriptor: &[u8],
    offset: usize,
    size: usize,
    mask: u32,
    sub_authorities: &[u32],
    base: usize,
) -> Result<(), NtfsSecureError> {
    let ace = checked_slice(descriptor, offset, size, "security descriptor")?;
    if ace[0] != 0 || ace[1] != 0 {
        return malformed(
            "access-allowed ACE",
            base + offset,
            "unexpected type or flags",
        );
    }
    if usize::from(read_u16(ace, 2, "access-allowed ACE", base + offset)?) != size {
        return malformed("access-allowed ACE", base + offset + 2, "wrong ACE size");
    }
    if read_u32(ace, 4, "access-allowed ACE", base + offset)? != mask {
        return malformed("access-allowed ACE", base + offset + 4, "wrong access mask");
    }
    validate_sid(ace, 8, sub_authorities, base + offset)
}

fn validate_sid(
    bytes: &[u8],
    offset: usize,
    expected_sub_authorities: &[u32],
    base: usize,
) -> Result<(), NtfsSecureError> {
    let sid_bytes = 8_usize
        .checked_add(
            expected_sub_authorities
                .len()
                .checked_mul(4)
                .ok_or_else(|| {
                    malformed_error("SID", base + offset, "sub-authority size overflows")
                })?,
        )
        .ok_or_else(|| malformed_error("SID", base + offset, "SID size overflows"))?;
    let sid = checked_slice(bytes, offset, sid_bytes, "SID")?;
    if sid[0] != 1 || usize::from(sid[1]) != expected_sub_authorities.len() {
        return malformed(
            "SID",
            base + offset,
            "invalid revision or sub-authority count",
        );
    }
    if sid[2..8] != [0, 0, 0, 0, 0, 5] {
        return malformed("SID", base + offset + 2, "unexpected identifier authority");
    }
    for (index, expected) in expected_sub_authorities.iter().enumerate() {
        let sub_offset = 8 + index * 4;
        if read_u32(sid, sub_offset, "SID", base + offset)? != *expected {
            return malformed("SID", base + offset + sub_offset, "wrong sub-authority");
        }
    }
    Ok(())
}

fn parse_sii(
    bytes: &[u8],
    limits: NtfsSecureLimits,
) -> Result<Vec<ParsedIndexEntry>, NtfsSecureError> {
    if bytes.len() != CANONICAL_SII_BYTES {
        return malformed("$SII", bytes.len(), "non-canonical entry-sequence length");
    }
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(CANONICAL_DESCRIPTOR_COUNT)
        .map_err(|_| NtfsSecureError::AllocationFailed {
            what: "parsed $SII entries",
        })?;
    for index in 0..CANONICAL_DESCRIPTOR_COUNT {
        if entries.len() == limits.max_descriptors {
            return Err(NtfsSecureError::LimitExceeded {
                what: "$SII entries",
                actual: entries.len() + 1,
                limit: limits.max_descriptors,
            });
        }
        let base = index * SII_ENTRY_BYTES;
        let entry = &bytes[base..base + SII_ENTRY_BYTES];
        validate_index_header(entry, base, "$SII", 0x14, 0x14, 0x28, 4)?;
        let security_id = read_u32(entry, 16, "$SII", base)?;
        let data = ParsedIndexEntry {
            hash: read_u32(entry, 20, "$SII", base)?,
            security_id: read_u32(entry, 24, "$SII", base)?,
            offset: read_u64(entry, 28, "$SII", base)?,
            length: read_u32(entry, 36, "$SII", base)?,
        };
        if security_id != data.security_id {
            return malformed("$SII", base + 16, "key and data security IDs differ");
        }
        if entries
            .last()
            .is_some_and(|previous: &ParsedIndexEntry| previous.security_id >= security_id)
        {
            return malformed("$SII", base + 16, "entries are not strictly ID-sorted");
        }
        entries.push(data);
    }
    validate_index_end(&bytes[2 * SII_ENTRY_BYTES..], 2 * SII_ENTRY_BYTES, "$SII")?;
    Ok(entries)
}

fn parse_sdh(
    bytes: &[u8],
    limits: NtfsSecureLimits,
) -> Result<Vec<ParsedIndexEntry>, NtfsSecureError> {
    if bytes.len() != CANONICAL_SDH_BYTES {
        return malformed("$SDH", bytes.len(), "non-canonical entry-sequence length");
    }
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(CANONICAL_DESCRIPTOR_COUNT)
        .map_err(|_| NtfsSecureError::AllocationFailed {
            what: "parsed $SDH entries",
        })?;
    for index in 0..CANONICAL_DESCRIPTOR_COUNT {
        if entries.len() == limits.max_descriptors {
            return Err(NtfsSecureError::LimitExceeded {
                what: "$SDH entries",
                actual: entries.len() + 1,
                limit: limits.max_descriptors,
            });
        }
        let base = index * SDH_ENTRY_BYTES;
        let entry = &bytes[base..base + SDH_ENTRY_BYTES];
        validate_index_header(entry, base, "$SDH", 0x18, 0x14, 0x30, 8)?;
        let key_hash = read_u32(entry, 16, "$SDH", base)?;
        let key_id = read_u32(entry, 20, "$SDH", base)?;
        let data = ParsedIndexEntry {
            hash: read_u32(entry, 24, "$SDH", base)?,
            security_id: read_u32(entry, 28, "$SDH", base)?,
            offset: read_u64(entry, 32, "$SDH", base)?,
            length: read_u32(entry, 40, "$SDH", base)?,
        };
        if key_hash != data.hash || key_id != data.security_id {
            return malformed("$SDH", base + 16, "key and data tuple differ");
        }
        if read_u32(entry, 44, "$SDH", base)? != SDH_RESERVED_II {
            return malformed("$SDH", base + 44, "reserved II field is not canonical");
        }
        if entries.last().is_some_and(|previous: &ParsedIndexEntry| {
            (previous.hash, previous.security_id) >= (data.hash, data.security_id)
        }) {
            return malformed("$SDH", base + 16, "entries are not strictly hash/ID-sorted");
        }
        entries.push(data);
    }
    validate_index_end(&bytes[2 * SDH_ENTRY_BYTES..], 2 * SDH_ENTRY_BYTES, "$SDH")?;
    Ok(entries)
}

fn cross_check_indexes(
    descriptor_entries: &[ParsedSdsEntry<'_>],
    id_index_entries: &[ParsedIndexEntry],
    hash_index_entries: &[ParsedIndexEntry],
) -> Result<(), NtfsSecureError> {
    if descriptor_entries.len() != id_index_entries.len()
        || descriptor_entries.len() != hash_index_entries.len()
    {
        return malformed("$Secure", 0, "descriptor and index cardinalities differ");
    }
    for descriptor in descriptor_entries {
        let expected = ParsedIndexEntry {
            hash: descriptor.hash,
            security_id: descriptor.security_id,
            offset: descriptor.offset,
            length: descriptor.length,
        };
        if id_index_entries
            .iter()
            .find(|entry| entry.security_id == descriptor.security_id)
            != Some(&expected)
        {
            return malformed("$SII", 0, "entry does not match $SDS descriptor header");
        }
        if hash_index_entries.iter().find(|entry| {
            entry.hash == descriptor.hash && entry.security_id == descriptor.security_id
        }) != Some(&expected)
        {
            return malformed("$SDH", 0, "entry does not match $SDS descriptor header");
        }
    }
    Ok(())
}

fn build_descriptor(mask: u32) -> Result<Vec<u8>, NtfsSecureError> {
    let mut descriptor = zeroed_vec(CANONICAL_DESCRIPTOR_BYTES, "security descriptor")?;
    descriptor[0] = 1;
    put_u16(&mut descriptor, 2, SE_SELF_RELATIVE_AND_DACL_PRESENT);
    put_u32(&mut descriptor, 4, 0x48);
    put_u32(&mut descriptor, 8, 0x58);
    put_u32(&mut descriptor, 16, 0x14);
    descriptor[0x14] = 2;
    put_u16(&mut descriptor, 0x16, 0x34);
    put_u16(&mut descriptor, 0x18, 2);
    write_access_allowed_ace(&mut descriptor[0x1c..0x30], mask, &[18])?;
    write_access_allowed_ace(&mut descriptor[0x30..0x48], mask, &[32, 544])?;
    write_sid(&mut descriptor[0x48..0x58], &[32, 544])?;
    write_sid(&mut descriptor[0x58..0x68], &[32, 544])?;
    Ok(descriptor)
}

fn write_sds_entry(sds: &mut [u8], offset: usize, hash: u32, security_id: u32, descriptor: &[u8]) {
    let entry = &mut sds[offset..offset + CANONICAL_ENTRY_BYTES];
    put_u32(entry, 0, hash);
    put_u32(entry, 4, security_id);
    put_u64(entry, 8, offset as u64);
    put_u32(entry, 16, CANONICAL_ENTRY_LENGTH);
    entry[SDS_HEADER_BYTES..].copy_from_slice(descriptor);
}

fn write_sii_entry(entry: &mut [u8], descriptor: NtfsSecureDescriptorSummary) {
    put_u16(entry, 0, 0x14);
    put_u16(entry, 2, 0x14);
    put_u16(entry, 8, 0x28);
    put_u16(entry, 10, 4);
    put_u32(entry, 16, descriptor.security_id);
    write_index_data(entry, 20, descriptor);
}

fn write_sdh_entry(entry: &mut [u8], descriptor: NtfsSecureDescriptorSummary) {
    put_u16(entry, 0, 0x18);
    put_u16(entry, 2, 0x14);
    put_u16(entry, 8, 0x30);
    put_u16(entry, 10, 8);
    put_u32(entry, 16, descriptor.hash);
    put_u32(entry, 20, descriptor.security_id);
    write_index_data(entry, 24, descriptor);
    put_u32(entry, 44, SDH_RESERVED_II);
}

fn write_index_data(entry: &mut [u8], offset: usize, descriptor: NtfsSecureDescriptorSummary) {
    put_u32(entry, offset, descriptor.hash);
    put_u32(entry, offset + 4, descriptor.security_id);
    put_u64(entry, offset + 8, descriptor.primary_offset);
    put_u32(entry, offset + 16, descriptor.entry_length);
}

fn write_index_end(entry: &mut [u8]) {
    put_u16(entry, 8, INDEX_END_ENTRY_LENGTH);
    put_u16(entry, 12, INDEX_ENTRY_END);
}

fn validate_index_header(
    entry: &[u8],
    base: usize,
    component: &'static str,
    data_offset: u16,
    data_length: u16,
    length: u16,
    key_length: u16,
) -> Result<(), NtfsSecureError> {
    if read_u16(entry, 0, component, base)? != data_offset
        || read_u16(entry, 2, component, base)? != data_length
        || read_u32(entry, 4, component, base)? != 0
        || read_u16(entry, 8, component, base)? != length
        || read_u16(entry, 10, component, base)? != key_length
        || read_u16(entry, 12, component, base)? != 0
        || read_u16(entry, 14, component, base)? != 0
    {
        return malformed(component, base, "invalid index-entry header");
    }
    if usize::from(length) % 8 != 0 {
        return malformed(component, base + 8, "entry length is not 8-byte aligned");
    }
    Ok(())
}

fn validate_index_end(
    entry: &[u8],
    base: usize,
    component: &'static str,
) -> Result<(), NtfsSecureError> {
    if entry.len() != INDEX_END_ENTRY_BYTES
        || read_u16(entry, 8, component, base)? != INDEX_END_ENTRY_LENGTH
        || read_u16(entry, 12, component, base)? != INDEX_ENTRY_END
    {
        return malformed(component, base, "invalid terminal index entry");
    }
    if entry[..8].iter().any(|byte| *byte != 0)
        || entry[10..12].iter().any(|byte| *byte != 0)
        || entry[14..16].iter().any(|byte| *byte != 0)
    {
        return malformed(
            component,
            base,
            "terminal index entry has non-zero reserved fields",
        );
    }
    Ok(())
}

fn write_access_allowed_ace(
    ace: &mut [u8],
    mask: u32,
    sub_authorities: &[u32],
) -> Result<(), NtfsSecureError> {
    let length = u16::try_from(ace.len()).map_err(|_| NtfsSecureError::LimitExceeded {
        what: "access-allowed ACE bytes",
        actual: ace.len(),
        limit: usize::from(u16::MAX),
    })?;
    put_u16(ace, 2, length);
    put_u32(ace, 4, mask);
    write_sid(&mut ace[8..], sub_authorities)
}

fn write_sid(sid: &mut [u8], sub_authorities: &[u32]) -> Result<(), NtfsSecureError> {
    let count =
        u8::try_from(sub_authorities.len()).map_err(|_| NtfsSecureError::LimitExceeded {
            what: "SID sub-authorities",
            actual: sub_authorities.len(),
            limit: usize::from(u8::MAX),
        })?;
    sid[0] = 1;
    sid[1] = count;
    sid[7] = 5;
    for (index, sub_authority) in sub_authorities.iter().enumerate() {
        put_u32(sid, 8 + index * 4, *sub_authority);
    }
    Ok(())
}

fn zeroed_vec(length: usize, what: &'static str) -> Result<Vec<u8>, NtfsSecureError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| NtfsSecureError::AllocationFailed { what })?;
    bytes.resize(length, 0);
    Ok(bytes)
}

const fn require_limit(
    what: &'static str,
    actual: usize,
    limit: usize,
) -> Result<(), NtfsSecureError> {
    if actual > limit {
        return Err(NtfsSecureError::LimitExceeded {
            what,
            actual,
            limit,
        });
    }
    Ok(())
}

fn checked_slice<'a>(
    bytes: &'a [u8],
    offset: usize,
    length: usize,
    component: &'static str,
) -> Result<&'a [u8], NtfsSecureError> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| malformed_error(component, offset, "range overflows"))?;
    bytes
        .get(offset..end)
        .ok_or_else(|| malformed_error(component, offset, "truncated structure"))
}

fn read_u16(
    bytes: &[u8],
    offset: usize,
    component: &'static str,
    base: usize,
) -> Result<u16, NtfsSecureError> {
    let absolute = base
        .checked_add(offset)
        .ok_or_else(|| malformed_error(component, base, "u16 offset overflows"))?;
    let value = checked_slice(bytes, offset, 2, component)
        .map_err(|_| malformed_error(component, absolute, "truncated little-endian u16"))?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(
    bytes: &[u8],
    offset: usize,
    component: &'static str,
    base: usize,
) -> Result<u32, NtfsSecureError> {
    let value = checked_slice(bytes, offset, 4, component)
        .map_err(|_| malformed_error(component, base + offset, "truncated little-endian u32"))?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn read_u64(
    bytes: &[u8],
    offset: usize,
    component: &'static str,
    base: usize,
) -> Result<u64, NtfsSecureError> {
    let value = checked_slice(bytes, offset, 8, component)
        .map_err(|_| malformed_error(component, base + offset, "truncated little-endian u64"))?;
    Ok(u64::from_le_bytes([
        value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
    ]))
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn align_up(value: usize, alignment: usize) -> Option<usize> {
    value
        .checked_add(alignment.checked_sub(1)?)
        .map(|sum| sum / alignment * alignment)
}

const fn malformed<T>(
    component: &'static str,
    offset: usize,
    reason: &'static str,
) -> Result<T, NtfsSecureError> {
    Err(malformed_error(component, offset, reason))
}

const fn malformed_error(
    component: &'static str,
    offset: usize,
    reason: &'static str,
) -> NtfsSecureError {
    NtfsSecureError::Malformed {
        component,
        offset,
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Exact bytes from ntfsprogs/sd.c:init_secure_sds at the pinned commit.
    // Keeping this independent literal prevents generator/validator agreement
    // from masquerading as compatibility evidence.
    const PINNED_READ_ONLY_DESCRIPTOR: [u8; 0x68] = [
        // SECURITY_DESCRIPTOR_RELATIVE
        0x01, 0x00, 0x04, 0x80, 0x48, 0x00, 0x00, 0x00, 0x58, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x14, 0x00, 0x00, 0x00, // ACL
        0x02, 0x00, 0x34, 0x00, 0x02, 0x00, 0x00, 0x00,
        // ACCESS_ALLOWED_ACE for LocalSystem
        0x00, 0x00, 0x14, 0x00, 0x89, 0x00, 0x12, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x05, 0x12, 0x00, 0x00, 0x00, // ACCESS_ALLOWED_ACE for Builtin Administrators
        0x00, 0x00, 0x18, 0x00, 0x89, 0x00, 0x12, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x05, 0x20, 0x00, 0x00, 0x00, 0x20, 0x02, 0x00, 0x00,
        // Owner and group: Builtin Administrators
        0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00, 0x20, 0x02, 0x00,
        0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00, 0x20, 0x02,
        0x00, 0x00,
    ];

    fn canonical() -> NtfsSecureMetadata {
        generate_ntfs_secure_metadata(
            NtfsSecureProfile::MkntfsWindows2003Ntfs31,
            NtfsSecureLimits::default(),
        )
        .expect("canonical generation")
    }

    #[test]
    fn canonical_generation_is_deterministic_and_valid() {
        let first = canonical();
        let second = canonical();
        assert_eq!(first, second);
        assert_eq!(first.sds.len(), 0x400fc);
        assert_eq!(first.sii_index_entries.len(), 0x60);
        assert_eq!(first.sdh_index_entries.len(), 0x70);
        let validated = validate_ntfs_secure_metadata(&first, NtfsSecureLimits::default())
            .expect("canonical validation");
        assert_eq!(
            validated.descriptors,
            vec![
                NtfsSecureDescriptorSummary {
                    hash: HASH_READ_ONLY,
                    security_id: 0x100,
                    primary_offset: 0,
                    entry_length: 0x7c,
                },
                NtfsSecureDescriptorSummary {
                    hash: HASH_READ_WRITE,
                    security_id: 0x101,
                    primary_offset: 0x80,
                    entry_length: 0x7c,
                },
            ]
        );
    }

    #[test]
    fn security_hash_matches_pinned_formatter_constants() {
        let metadata = canonical();
        assert_eq!(
            ntfs_security_descriptor_hash(&metadata.sds[20..0x7c]).expect("hash"),
            HASH_READ_ONLY
        );
        assert_eq!(
            ntfs_security_descriptor_hash(&metadata.sds[0x94..0xfc]).expect("hash"),
            HASH_READ_WRITE
        );
        assert!(matches!(
            ntfs_security_descriptor_hash(&[0, 1, 2]),
            Err(NtfsSecureError::HashInputNotWordAligned { length: 3 })
        ));
    }

    #[test]
    fn descriptors_match_independent_pinned_known_answer_bytes() {
        let metadata = canonical();
        assert_eq!(&metadata.sds[0x14..0x7c], &PINNED_READ_ONLY_DESCRIPTOR);

        let mut expected_read_write = PINNED_READ_ONLY_DESCRIPTOR;
        expected_read_write[0x20..0x24].copy_from_slice(&READ_WRITE_MASK.to_le_bytes());
        expected_read_write[0x34..0x38].copy_from_slice(&READ_WRITE_MASK.to_le_bytes());
        assert_eq!(&metadata.sds[0x94..0xfc], &expected_read_write);
    }

    #[test]
    fn exact_limits_are_accepted() {
        let limits = NtfsSecureLimits {
            max_sds_bytes: CANONICAL_SDS_BYTES,
            max_index_bytes: CANONICAL_SDH_BYTES,
            max_descriptors: CANONICAL_DESCRIPTOR_COUNT,
            max_descriptor_bytes: CANONICAL_DESCRIPTOR_BYTES,
        };
        let metadata =
            generate_ntfs_secure_metadata(NtfsSecureProfile::MkntfsWindows2003Ntfs31, limits)
                .expect("exact generation limits");
        validate_ntfs_secure_metadata(&metadata, limits).expect("exact validation limits");
    }

    #[test]
    fn unsupported_native_profile_is_explicit() {
        assert!(matches!(
            generate_ntfs_secure_metadata(
                NtfsSecureProfile::ModernWindowsNative,
                NtfsSecureLimits::default()
            ),
            Err(NtfsSecureError::UnsupportedProfile { .. })
        ));
    }

    #[test]
    fn every_output_limit_is_enforced() {
        for limits in [
            NtfsSecureLimits {
                max_sds_bytes: CANONICAL_SDS_BYTES - 1,
                ..NtfsSecureLimits::default()
            },
            NtfsSecureLimits {
                max_index_bytes: CANONICAL_SDH_BYTES - 1,
                ..NtfsSecureLimits::default()
            },
            NtfsSecureLimits {
                max_descriptors: 1,
                ..NtfsSecureLimits::default()
            },
            NtfsSecureLimits {
                max_descriptor_bytes: CANONICAL_DESCRIPTOR_BYTES - 1,
                ..NtfsSecureLimits::default()
            },
        ] {
            assert!(matches!(
                generate_ntfs_secure_metadata(NtfsSecureProfile::MkntfsWindows2003Ntfs31, limits),
                Err(NtfsSecureError::LimitExceeded { .. })
            ));
        }
    }

    #[test]
    fn validator_rejects_truncation_and_trailing_bytes() {
        let metadata = canonical();
        for length in [
            0,
            19,
            123,
            FIRST_COPY_BYTES,
            SDS_COPY_DISTANCE,
            CANONICAL_SDS_BYTES - 1,
        ] {
            let mut malformed = metadata.clone();
            malformed.sds.truncate(length);
            assert!(
                validate_ntfs_secure_metadata(&malformed, NtfsSecureLimits::default()).is_err()
            );
        }
        let mut trailing = metadata;
        trailing.sii_index_entries.push(0);
        assert!(validate_ntfs_secure_metadata(&trailing, NtfsSecureLimits::default()).is_err());
    }

    #[test]
    fn validator_rejects_sds_header_descriptor_and_padding_corruption() {
        for offset in [0, 4, 8, 16, 20, 22, 24, 40, 48, 72, 0x7c] {
            let mut metadata = canonical();
            metadata.sds[offset] ^= 1;
            assert!(
                validate_ntfs_secure_metadata(&metadata, NtfsSecureLimits::default()).is_err(),
                "offset {offset:#x} unexpectedly accepted"
            );
        }
    }

    #[test]
    fn validator_rejects_gap_and_duplicate_copy_corruption() {
        let mut gap = canonical();
        gap.sds[FIRST_COPY_BYTES] = 1;
        assert!(validate_ntfs_secure_metadata(&gap, NtfsSecureLimits::default()).is_err());

        let mut duplicate = canonical();
        duplicate.sds[SDS_COPY_DISTANCE + 20] ^= 1;
        assert!(validate_ntfs_secure_metadata(&duplicate, NtfsSecureLimits::default()).is_err());
    }

    #[test]
    fn validator_rejects_every_mirrored_primary_byte_mutation() {
        for offset in 0..FIRST_COPY_BYTES {
            let mut metadata = canonical();
            metadata.sds[offset] ^= 1;
            metadata.sds[SDS_COPY_DISTANCE + offset] ^= 1;
            assert!(
                validate_ntfs_secure_metadata(&metadata, NtfsSecureLimits::default()).is_err(),
                "mirrored SDS offset {offset:#x} unexpectedly accepted"
            );
        }
    }

    #[test]
    fn validator_rejects_sii_structure_sort_and_cross_reference_corruption() {
        for offset in [0, 2, 4, 8, 10, 12, 14, 16, 20, 24, 28, 36, 80, 88, 92] {
            let mut metadata = canonical();
            metadata.sii_index_entries[offset] ^= 1;
            assert!(
                validate_ntfs_secure_metadata(&metadata, NtfsSecureLimits::default()).is_err(),
                "SII offset {offset:#x} unexpectedly accepted"
            );
        }
        let mut reversed = canonical();
        let (first, rest) = reversed.sii_index_entries.split_at_mut(SII_ENTRY_BYTES);
        first.swap_with_slice(&mut rest[..SII_ENTRY_BYTES]);
        assert!(validate_ntfs_secure_metadata(&reversed, NtfsSecureLimits::default()).is_err());
    }

    #[test]
    fn validator_rejects_sdh_structure_sort_and_cross_reference_corruption() {
        for offset in [
            0, 2, 4, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 44, 96, 104, 108,
        ] {
            let mut metadata = canonical();
            metadata.sdh_index_entries[offset] ^= 1;
            assert!(
                validate_ntfs_secure_metadata(&metadata, NtfsSecureLimits::default()).is_err(),
                "SDH offset {offset:#x} unexpectedly accepted"
            );
        }
        let mut reversed = canonical();
        let (first, rest) = reversed.sdh_index_entries.split_at_mut(SDH_ENTRY_BYTES);
        first.swap_with_slice(&mut rest[..SDH_ENTRY_BYTES]);
        assert!(validate_ntfs_secure_metadata(&reversed, NtfsSecureLimits::default()).is_err());
    }

    #[test]
    fn validator_rejects_every_index_byte_mutation() {
        let canonical = canonical();
        for offset in 0..canonical.sii_index_entries.len() {
            let mut metadata = canonical.clone();
            metadata.sii_index_entries[offset] ^= 1;
            assert!(
                validate_ntfs_secure_metadata(&metadata, NtfsSecureLimits::default()).is_err(),
                "SII offset {offset:#x} unexpectedly accepted"
            );
        }
        for offset in 0..canonical.sdh_index_entries.len() {
            let mut metadata = canonical.clone();
            metadata.sdh_index_entries[offset] ^= 1;
            assert!(
                validate_ntfs_secure_metadata(&metadata, NtfsSecureLimits::default()).is_err(),
                "SDH offset {offset:#x} unexpectedly accepted"
            );
        }
    }

    #[test]
    fn truncated_u16_reports_absolute_offset() {
        assert_eq!(
            read_u16(&[0], 0, "test", 123),
            Err(NtfsSecureError::Malformed {
                component: "test",
                offset: 123,
                reason: "truncated little-endian u16",
            })
        );
    }

    #[test]
    fn validator_applies_limits_before_deep_parsing() {
        let metadata = canonical();
        let limits = NtfsSecureLimits {
            max_sds_bytes: metadata.sds.len() - 1,
            ..NtfsSecureLimits::default()
        };
        assert!(matches!(
            validate_ntfs_secure_metadata(&metadata, limits),
            Err(NtfsSecureError::LimitExceeded {
                what: "SDS bytes",
                ..
            })
        ));
    }
}
