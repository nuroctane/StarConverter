//! Bounded, byte-preserving validation of self-relative Windows security descriptors.
//!
//! Supported ACE profile: basic access-allowed (0) / access-denied (1) in a DACL and
//! system-audit (2) in a SACL, each with one complete revision-1 SID and no application data.
//! Unknown, object, callback, compound, label, resource and policy ACEs are explicitly refused.
//! This is structural evidence for exact preservation, not an access check or permission rewrite.
//! ACL slack and descriptor gaps are retained; ACE order, masks, authorities and control bits
//! are never normalized. Absent, present-null and allocated-empty ACLs remain distinct.
//!
//! Primary format references:
//! - <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7d4dac05-9cef-4563-a058-f108abecce1d>
//! - <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/f992ad60-0fe4-4b87-9fed-beb478836861>
//! - <https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-acl>
//! - <https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-ace_header>
//! - <https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-access_allowed_ace>
//! - <https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-getsecuritydescriptordacl>
//!
//! Exact owner/group SID sharing, shared empty ACLs and owner/group references to complete ACE
//! SIDs are supported. Other overlapping component layouts are an unsupported preservation
//! profile, not a claim that every such layout is rejected by native Windows.

use std::fmt;

const HEADER_BYTES: usize = 20;
const SELF_RELATIVE: u16 = 0x8000;
const DACL_PRESENT: u16 = 0x0004;
const SACL_PRESENT: u16 = 0x0010;

/// Caller-selected byte and aggregate ACE-work limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtfsSecurityDescriptorLimits {
    pub max_bytes: usize,
    /// Counts ACEs across both ACLs, including repeated references to shared ACLs.
    pub max_aces: usize,
}

impl Default for NtfsSecurityDescriptorLimits {
    fn default() -> Self {
        Self {
            max_bytes: 64 * 1024,
            max_aces: 4096,
        }
    }
}

/// A validated range relative to the beginning of the original descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtfsSecurityRange {
    pub offset: usize,
    pub length: usize,
}

impl NtfsSecurityRange {
    const fn end(self) -> usize {
        // Every range is checked against the containing slice before construction.
        self.offset + self.length
    }

    const fn overlaps(self, other: Self) -> bool {
        self.offset < other.end() && other.offset < self.end()
    }
}

/// ACL pointer and presence semantics; null is deliberately different from empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtfsSecurityAcl {
    Absent,
    Null,
    Present {
        range: NtfsSecurityRange,
        revision: u8,
        ace_count: u16,
        /// Declared unused bytes after the last ACE; their original values are retained.
        slack_bytes: usize,
    },
}

/// Evidence that the original bytes satisfy the documented, bounded supported profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsSecurityDescriptorValidation<'a> {
    /// Exact input including ACL slack and descriptor gaps; never rebuilt or canonicalized.
    pub bytes: &'a [u8],
    pub control: u16,
    /// Sbz1 is resource-manager control when control bit 0x4000 is set, otherwise uninterpreted.
    pub resource_manager_control: u8,
    pub owner: Option<NtfsSecurityRange>,
    pub group: Option<NtfsSecurityRange>,
    pub sacl: NtfsSecurityAcl,
    pub dacl: NtfsSecurityAcl,
    pub ace_count: usize,
}

/// Malformed input and intentionally unsupported security formats are separate refusals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NtfsSecurityDescriptorError {
    ByteLimit {
        actual: usize,
        maximum: usize,
    },
    AceLimit {
        actual: usize,
        maximum: usize,
    },
    Malformed {
        offset: usize,
        reason: &'static str,
    },
    UnsupportedRevision {
        offset: usize,
        revision: u8,
    },
    UnsupportedAceType {
        offset: usize,
        ace_type: u8,
    },
    UnsupportedAceFlags {
        offset: usize,
        flags: u8,
    },
    UnsupportedAcePayload {
        offset: usize,
        trailing_bytes: usize,
    },
    AceInWrongAcl {
        offset: usize,
        ace_type: u8,
    },
    UnsupportedAliasing {
        first: NtfsSecurityRange,
        second: NtfsSecurityRange,
    },
}

impl fmt::Display for NtfsSecurityDescriptorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "security descriptor refused: {self:?}")
    }
}

impl std::error::Error for NtfsSecurityDescriptorError {}

/// A valid self-relative descriptor shared by cross-module tests: one access-allowed ACE for
/// `S-1-5-18` with four bytes of ACL slack, and `S-1-5-32-544` as both owner and group.
#[cfg(test)]
#[must_use]
pub(crate) fn sample_self_relative_descriptor() -> Vec<u8> {
    sample_self_relative_descriptor_with_aces(1)
}

/// Like [`sample_self_relative_descriptor`] but with `aces` identical access-allowed ACEs, so
/// tests can build descriptors that exceed a resident attribute budget. The result is
/// `48 + 20 * aces` bytes; mkntfs writes a 4140-byte root descriptor, so 205 ACEs (4148 bytes)
/// model that shape.
#[cfg(test)]
#[must_use]
pub(crate) fn sample_self_relative_descriptor_with_aces(aces: usize) -> Vec<u8> {
    let mut bytes = vec![0; HEADER_BYTES];
    bytes[0] = 1;
    bytes[2..4].copy_from_slice(&(SELF_RELATIVE | DACL_PRESENT).to_le_bytes());
    bytes[16..20].copy_from_slice(&20_u32.to_le_bytes());
    let mut acl = vec![2, 0, 0, 0, 0, 0, 0, 0];
    acl[4..6].copy_from_slice(&u16::try_from(aces).unwrap().to_le_bytes());
    for _ in 0..aces {
        acl.extend_from_slice(&[0, 0, 20, 0]);
        acl.extend_from_slice(&0x001f_01ff_u32.to_le_bytes());
        acl.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 5]);
        acl.extend_from_slice(&18_u32.to_le_bytes());
    }
    acl.extend_from_slice(&[0xa5; 4]);
    let acl_size = u16::try_from(acl.len()).unwrap();
    acl[2..4].copy_from_slice(&acl_size.to_le_bytes());
    bytes.extend_from_slice(&acl);
    let owner = u32::try_from(bytes.len()).unwrap();
    bytes[4..8].copy_from_slice(&owner.to_le_bytes());
    bytes[8..12].copy_from_slice(&owner.to_le_bytes());
    bytes.extend_from_slice(&[1, 2, 0, 0, 0, 0, 0, 5]);
    bytes.extend_from_slice(&32_u32.to_le_bytes());
    bytes.extend_from_slice(&544_u32.to_le_bytes());
    bytes
}

type Error = NtfsSecurityDescriptorError;

const fn malformed(offset: usize, reason: &'static str) -> Error {
    Error::Malformed { offset, reason }
}

fn range(bytes: &[u8], offset: usize, length: usize) -> Result<NtfsSecurityRange, Error> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| malformed(offset, "component range overflows"))?;
    if end > bytes.len() {
        return Err(malformed(offset, "component exceeds containing bytes"));
    }
    Ok(NtfsSecurityRange { offset, length })
}

const fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

const fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn component_offset(bytes: &[u8], field: usize) -> Result<Option<usize>, Error> {
    let raw = u32_at(bytes, field);
    if raw == 0 {
        return Ok(None);
    }
    let offset = usize::try_from(raw)
        .map_err(|_| malformed(field, "component offset is not representable"))?;
    if offset < HEADER_BYTES || offset % 4 != 0 {
        return Err(malformed(
            field,
            "component offset is not outside the header and DWORD aligned",
        ));
    }
    range(bytes, offset, 1)?;
    Ok(Some(offset))
}

fn sid(bytes: &[u8], offset: usize, containing_end: usize) -> Result<NtfsSecurityRange, Error> {
    let header = range(bytes, offset, 8)?;
    if header.end() > containing_end {
        return Err(malformed(offset, "SID header exceeds enclosing ACE"));
    }
    if bytes[offset] != 1 {
        return Err(Error::UnsupportedRevision {
            offset,
            revision: bytes[offset],
        });
    }
    let count = usize::from(bytes[offset + 1]);
    if count > 15 {
        return Err(malformed(offset + 1, "SID has more than 15 subauthorities"));
    }
    let result = range(bytes, offset, 8 + count * 4)?;
    if result.end() > containing_end {
        return Err(malformed(offset, "SID subauthorities exceed enclosing ACE"));
    }
    Ok(result)
}

#[derive(Debug)]
struct ParsedAcl {
    evidence: NtfsSecurityAcl,
    range: Option<NtfsSecurityRange>,
    ace_sids: Vec<NtfsSecurityRange>,
}

/// Validates one ACE at `cursor` and returns its range plus the range of its trustee SID.
fn ace(
    bytes: &[u8],
    cursor: usize,
    acl_end: usize,
    is_sacl: bool,
) -> Result<(NtfsSecurityRange, NtfsSecurityRange), Error> {
    if range(bytes, cursor, 4)?.end() > acl_end {
        return Err(malformed(cursor, "ACE header exceeds ACL"));
    }
    let ace_type = bytes[cursor];
    let flags = bytes[cursor + 1];
    let ace_bytes = usize::from(u16_at(bytes, cursor + 2));
    if ace_bytes < 16 || ace_bytes % 4 != 0 {
        return Err(malformed(
            cursor + 2,
            "ACE size cannot contain a SID or is unaligned",
        ));
    }
    let ace_range = range(bytes, cursor, ace_bytes)?;
    if ace_range.end() > acl_end {
        return Err(malformed(cursor, "ACE exceeds declared ACL"));
    }
    if !matches!(ace_type, 0..=2) {
        return Err(Error::UnsupportedAceType {
            offset: cursor,
            ace_type,
        });
    }
    if is_sacl != (ace_type == 2) {
        return Err(Error::AceInWrongAcl {
            offset: cursor,
            ace_type,
        });
    }
    let known_flags = if ace_type == 2 { 0xdf } else { 0x1f };
    if flags & !known_flags != 0 {
        return Err(Error::UnsupportedAceFlags {
            offset: cursor + 1,
            flags,
        });
    }
    let trustee = sid(bytes, cursor + 8, ace_range.end())?;
    if trustee.end() != ace_range.end() {
        return Err(Error::UnsupportedAcePayload {
            offset: cursor,
            trailing_bytes: ace_range.end() - trustee.end(),
        });
    }
    Ok((ace_range, trustee))
}

fn acl(
    bytes: &[u8],
    offset: Option<usize>,
    present: bool,
    is_sacl: bool,
    limits: NtfsSecurityDescriptorLimits,
    total_aces: &mut usize,
) -> Result<ParsedAcl, Error> {
    let Some(offset) = offset else {
        return Ok(ParsedAcl {
            evidence: if present {
                NtfsSecurityAcl::Null
            } else {
                NtfsSecurityAcl::Absent
            },
            range: None,
            ace_sids: Vec::new(),
        });
    };
    if !present {
        return Err(malformed(
            offset,
            "ACL offset is nonzero without its PRESENT flag",
        ));
    }
    range(bytes, offset, 8)?;
    let revision = bytes[offset];
    if !matches!(revision, 2 | 4) {
        return Err(Error::UnsupportedRevision { offset, revision });
    }
    if bytes[offset + 1] != 0 || u16_at(bytes, offset + 6) != 0 {
        return Err(malformed(offset, "ACL reserved fields must be zero"));
    }
    let length = usize::from(u16_at(bytes, offset + 2));
    if length < 8 || length % 4 != 0 {
        return Err(malformed(
            offset + 2,
            "ACL size must include its header and be DWORD aligned",
        ));
    }
    let acl_range = range(bytes, offset, length)?;
    let count = u16_at(bytes, offset + 4);
    *total_aces = total_aces
        .checked_add(usize::from(count))
        .ok_or_else(|| malformed(offset + 4, "aggregate ACE count overflows"))?;
    if *total_aces > limits.max_aces {
        return Err(Error::AceLimit {
            actual: *total_aces,
            maximum: limits.max_aces,
        });
    }
    if usize::from(count) > (length - 8) / 4 {
        return Err(malformed(
            offset + 4,
            "ACE count cannot fit in declared ACL",
        ));
    }
    let mut cursor = offset + 8;
    let mut ace_sids = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        let (entry, trustee) = ace(bytes, cursor, acl_range.end(), is_sacl)?;
        ace_sids.push(trustee);
        cursor = entry.end();
    }
    Ok(ParsedAcl {
        evidence: NtfsSecurityAcl::Present {
            range: acl_range,
            revision,
            ace_count: count,
            slack_bytes: acl_range.end() - cursor,
        },
        range: Some(acl_range),
        ace_sids,
    })
}

fn validate_aliasing(
    owner: Option<NtfsSecurityRange>,
    group: Option<NtfsSecurityRange>,
    sacl: &ParsedAcl,
    dacl: &ParsedAcl,
) -> Result<(), Error> {
    for (first, second) in [(owner, group), (sacl.range, dacl.range)] {
        if let (Some(first), Some(second)) = (first, second) {
            if first.overlaps(second) && first != second {
                return Err(Error::UnsupportedAliasing { first, second });
            }
        }
    }
    for sid_range in [owner, group].into_iter().flatten() {
        for parsed in [sacl, dacl] {
            let Some(acl_range) = parsed.range else {
                continue;
            };
            if sid_range.overlaps(acl_range) && !parsed.ace_sids.contains(&sid_range) {
                return Err(Error::UnsupportedAliasing {
                    first: sid_range,
                    second: acl_range,
                });
            }
        }
    }
    Ok(())
}

/// Validate a bounded supported descriptor without changing any original byte.
///
/// # Errors
/// Returns a typed malformed-input, resource-limit or unsupported-profile refusal.
pub fn validate_ntfs_security_descriptor(
    bytes: &[u8],
    limits: NtfsSecurityDescriptorLimits,
) -> Result<NtfsSecurityDescriptorValidation<'_>, Error> {
    if bytes.len() > limits.max_bytes {
        return Err(Error::ByteLimit {
            actual: bytes.len(),
            maximum: limits.max_bytes,
        });
    }
    range(bytes, 0, HEADER_BYTES)?;
    if bytes[0] != 1 {
        return Err(Error::UnsupportedRevision {
            offset: 0,
            revision: bytes[0],
        });
    }
    let control = u16_at(bytes, 2);
    if control & SELF_RELATIVE == 0 {
        return Err(malformed(2, "SELF_RELATIVE flag is required"));
    }
    let owner = component_offset(bytes, 4)?
        .map(|offset| sid(bytes, offset, bytes.len()))
        .transpose()?;
    let group = component_offset(bytes, 8)?
        .map(|offset| sid(bytes, offset, bytes.len()))
        .transpose()?;
    let mut ace_count = 0;
    let sacl = acl(
        bytes,
        component_offset(bytes, 12)?,
        control & SACL_PRESENT != 0,
        true,
        limits,
        &mut ace_count,
    )?;
    let dacl = acl(
        bytes,
        component_offset(bytes, 16)?,
        control & DACL_PRESENT != 0,
        false,
        limits,
        &mut ace_count,
    )?;
    validate_aliasing(owner, group, &sacl, &dacl)?;
    Ok(NtfsSecurityDescriptorValidation {
        bytes,
        control,
        resource_manager_control: bytes[1],
        owner,
        group,
        sacl: sacl.evidence,
        dacl: dacl.evidence,
        ace_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(control: u16) -> Vec<u8> {
        let mut result = vec![0; HEADER_BYTES];
        result[0] = 1;
        result[2..4].copy_from_slice(&control.to_le_bytes());
        result
    }

    fn set_offset(bytes: &mut [u8], field: usize, offset: usize) {
        bytes[field..field + 4].copy_from_slice(&u32::try_from(offset).unwrap().to_le_bytes());
    }

    fn test_sid(subauthorities: &[u32]) -> Vec<u8> {
        let mut result = vec![
            1,
            u8::try_from(subauthorities.len()).unwrap(),
            0,
            0,
            0,
            0,
            0,
            5,
        ];
        for value in subauthorities {
            result.extend_from_slice(&value.to_le_bytes());
        }
        result
    }

    fn test_acl(ace_type: u8, flags: u8, slack: usize) -> Vec<u8> {
        let sid = test_sid(&[18]);
        let mut result = vec![2, 0, 0, 0, 1, 0, 0, 0, ace_type, flags, 20, 0];
        result.extend_from_slice(&0x001f_01ff_u32.to_le_bytes());
        result.extend_from_slice(&sid);
        result.extend(std::iter::repeat_n(0xa5, slack));
        let size = u16::try_from(result.len()).unwrap();
        result[2..4].copy_from_slice(&size.to_le_bytes());
        result
    }

    fn descriptor() -> Vec<u8> {
        let mut bytes = header(SELF_RELATIVE | DACL_PRESENT);
        set_offset(&mut bytes, 16, 20);
        bytes.extend_from_slice(&test_acl(0, 0, 4));
        let owner = bytes.len();
        set_offset(&mut bytes, 4, owner);
        set_offset(&mut bytes, 8, owner);
        bytes.extend_from_slice(&test_sid(&[32, 544]));
        bytes
    }

    fn check(bytes: &[u8]) -> Result<NtfsSecurityDescriptorValidation<'_>, Error> {
        validate_ntfs_security_descriptor(bytes, NtfsSecurityDescriptorLimits::default())
    }

    #[test]
    fn shared_sample_descriptor_matches_the_local_fixture_and_validates() {
        let sample = sample_self_relative_descriptor();
        assert_eq!(sample, descriptor());
        let validated = check(&sample).unwrap();
        assert_eq!(validated.bytes, sample.as_slice());
        assert_eq!(validated.ace_count, 1);
    }

    #[test]
    fn descriptor_exact_bytes_slack_and_owner_group_sharing_are_preserved() {
        let bytes = descriptor();
        let result = check(&bytes).unwrap();
        assert_eq!(result.bytes, bytes);
        assert!(std::ptr::eq(result.bytes.as_ptr(), bytes.as_ptr()));
        assert_eq!(result.owner, result.group);
        assert_eq!(result.ace_count, 1);
        assert!(matches!(
            result.dacl,
            NtfsSecurityAcl::Present { slack_bytes: 4, .. }
        ));
    }

    #[test]
    fn absent_null_and_empty_acls_are_distinct() {
        assert_eq!(
            check(&header(SELF_RELATIVE)).unwrap().dacl,
            NtfsSecurityAcl::Absent
        );
        assert_eq!(
            check(&header(SELF_RELATIVE | DACL_PRESENT)).unwrap().dacl,
            NtfsSecurityAcl::Null
        );
        let mut bytes = header(SELF_RELATIVE | DACL_PRESENT | SACL_PRESENT);
        set_offset(&mut bytes, 16, 20);
        set_offset(&mut bytes, 12, 20);
        bytes.extend_from_slice(&[2, 0, 8, 0, 0, 0, 0, 0]);
        let result = check(&bytes).unwrap();
        assert_eq!(result.dacl, result.sacl);
        assert!(matches!(
            result.dacl,
            NtfsSecurityAcl::Present { ace_count: 0, .. }
        ));
    }

    #[test]
    fn every_truncated_prefix_of_a_referenced_descriptor_fails() {
        let bytes = descriptor();
        for length in 0..bytes.len() {
            assert!(check(&bytes[..length]).is_err(), "prefix {length}");
        }
    }

    #[test]
    fn hostile_offsets_revision_and_absolute_control_are_refused() {
        for offset in [1_u32, 16, 21, u32::MAX - 3, u32::MAX] {
            let mut bytes = descriptor();
            bytes[4..8].copy_from_slice(&offset.to_le_bytes());
            assert!(check(&bytes).is_err());
        }
        let mut bytes = descriptor();
        bytes[0] = 2;
        assert!(matches!(
            check(&bytes),
            Err(Error::UnsupportedRevision { offset: 0, .. })
        ));
        bytes[0] = 1;
        bytes[3] &= 0x7f;
        assert!(check(&bytes).is_err());
    }

    #[test]
    fn malformed_acl_size_count_reserved_fields_and_sid_bounds_are_refused() {
        for (offset, value) in [
            (20, 3),
            (21, 1),
            (22, 7),
            (22, 255),
            (24, 255),
            (26, 1),
            (30, 0),
            (30, 19),
            (30, 40),
            (36, 2),
            (37, 16),
        ] {
            let mut bytes = descriptor();
            bytes[offset] = value;
            assert!(check(&bytes).is_err(), "mutation at {offset}");
        }
        let mut bytes = descriptor();
        bytes[37] = 15; // SID cannot consume bytes beyond its own ACE even if input is long enough.
        bytes.extend_from_slice(&[0; 128]);
        assert!(check(&bytes).is_err());
    }

    #[test]
    fn supported_ace_types_and_acl_roles_are_checked() {
        for ace_type in [0, 1] {
            let mut bytes = descriptor();
            bytes[28] = ace_type;
            bytes[29] = 0x1f;
            check(&bytes).unwrap();
        }
        let mut bytes = header(SELF_RELATIVE | SACL_PRESENT);
        set_offset(&mut bytes, 12, 20);
        bytes.extend_from_slice(&test_acl(2, 0xc0, 0));
        check(&bytes).unwrap();
        bytes[28] = 0;
        assert!(matches!(check(&bytes), Err(Error::AceInWrongAcl { .. })));
        let mut bytes = descriptor();
        bytes[28] = 2;
        assert!(matches!(check(&bytes), Err(Error::AceInWrongAcl { .. })));
    }

    #[test]
    fn unknown_callback_object_and_reserved_ace_flags_fail_closed() {
        for ace_type in [3, 4, 5, 9, 17, 18, 19, 255] {
            let mut bytes = descriptor();
            bytes[28] = ace_type;
            assert!(matches!(
                check(&bytes),
                Err(Error::UnsupportedAceType { .. })
            ));
        }
        for flags in [0x20, 0x40, 0x80] {
            let mut bytes = descriptor();
            bytes[29] = flags;
            assert!(matches!(
                check(&bytes),
                Err(Error::UnsupportedAceFlags { .. })
            ));
        }
    }

    #[test]
    fn application_ace_data_is_explicitly_unsupported_not_discarded() {
        let mut bytes = descriptor();
        bytes[30] = 24; // Consume the legal ACL slack as unknown per-ACE application data.
        assert!(matches!(
            check(&bytes),
            Err(Error::UnsupportedAcePayload {
                trailing_bytes: 4,
                ..
            })
        ));
    }

    #[test]
    fn acl_revision_four_component_order_and_resource_manager_byte_are_retained() {
        let mut bytes = header(SELF_RELATIVE | DACL_PRESENT | 0x4000);
        bytes[1] = 0x8f;
        set_offset(&mut bytes, 4, 20);
        bytes.extend_from_slice(&test_sid(&[]));
        set_offset(&mut bytes, 16, 28);
        bytes.extend_from_slice(&test_acl(1, 0, 0));
        bytes[28] = 4;
        let result = check(&bytes).unwrap();
        assert_eq!(result.resource_manager_control, 0x8f);
        assert_eq!(result.bytes, bytes);
    }

    #[test]
    fn exact_owner_alias_to_an_ace_sid_is_supported_but_other_overlap_is_not() {
        let mut bytes = descriptor();
        set_offset(&mut bytes, 4, 36);
        set_offset(&mut bytes, 8, 36);
        check(&bytes).unwrap();
        set_offset(&mut bytes, 4, 48); // Legal-looking SID stored in ACL slack + following bytes.
        bytes[48..56].copy_from_slice(&[1, 0, 0, 0, 0, 0, 0, 5]);
        set_offset(&mut bytes, 8, 0);
        assert!(matches!(
            check(&bytes),
            Err(Error::UnsupportedAliasing { .. })
        ));
    }

    #[test]
    fn byte_and_aggregate_ace_work_limits_are_enforced() {
        let bytes = descriptor();
        assert!(matches!(
            validate_ntfs_security_descriptor(
                &bytes,
                NtfsSecurityDescriptorLimits {
                    max_bytes: bytes.len() - 1,
                    max_aces: 1
                }
            ),
            Err(Error::ByteLimit { .. })
        ));
        assert!(matches!(
            validate_ntfs_security_descriptor(
                &bytes,
                NtfsSecurityDescriptorLimits {
                    max_bytes: bytes.len(),
                    max_aces: 0
                }
            ),
            Err(Error::AceLimit { .. })
        ));
        validate_ntfs_security_descriptor(
            &bytes,
            NtfsSecurityDescriptorLimits {
                max_bytes: bytes.len(),
                max_aces: 1,
            },
        )
        .unwrap();
    }

    #[test]
    fn nonzero_acl_offset_without_presence_is_refused() {
        let mut bytes = descriptor();
        bytes[2] &= !4;
        assert!(check(&bytes).is_err());
    }
}
