//! Pure generation and validation of a pinned NTFS 3.1 `$UpCase` payload.
//!
//! Microsoft's public file-system documentation identifies `$UpCase` as the uppercase table used
//! for NTFS collation, but does not publish one mandatory 131,072-byte formatter image. The exact
//! profile here is therefore formatter precedent, not a claim of Microsoft-normative bytes. It is
//! pinned to NTFS-3G 2022.10.3 commit
//! `78414d93613532fd82f3a82aba5d4a1c32898781`, specifically `libntfs-3g/unistr.c` and
//! `include/ntfs-3g/param.h`. That source selects the Windows 6.1 table and records the same MD5
//! emitted by its `mkntfs`; the SHA-256 below was independently measured from inode 10 of a fresh
//! regular-file image formatted by that exact release.
//!
//! The mapping is over UTF-16 *code units*, not Unicode scalar values. It intentionally differs
//! from Rust's evolving Unicode case conversion, preserves lone surrogate code units, and never
//! expands one input unit into multiple output units. This module performs no I/O and exposes no
//! path or device API. Every allocation and filename operation is caller-bounded.

use std::cmp::Ordering;
use std::fmt;

use sha2::{Digest, Sha256};

/// Number of UTF-16 code-unit mappings in the canonical NTFS table.
pub const NTFS_UPCASE_TABLE_UNITS: usize = 65_536;
/// Byte length of the canonical little-endian `$UpCase` unnamed `$DATA` stream.
pub const NTFS_UPCASE_TABLE_BYTES: usize = NTFS_UPCASE_TABLE_UNITS * 2;
/// NTFS filename-component limit, measured in UTF-16 code units.
pub const NTFS_MAX_FILE_NAME_UNITS: usize = 255;

/// SHA-256 of the 131,072-byte table emitted by NTFS-3G 2022.10.3 `mkntfs`.
pub const NTFS3G_WINDOWS61_UPCASE_SHA256: [u8; 32] = [
    0x41, 0xc2, 0x6b, 0xc7, 0xa1, 0x2b, 0xda, 0xeb, 0x26, 0x02, 0x5c, 0x93, 0x11, 0x86, 0x97, 0xc7,
    0xe3, 0xef, 0x81, 0xee, 0x04, 0x8b, 0x00, 0xfe, 0x5c, 0xce, 0x2a, 0x47, 0x2e, 0x0e, 0x07, 0x42,
];

/// Exact provenance for a supported destination `$UpCase` byte profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtfsUpcaseProfile {
    pub profile_name: &'static str,
    pub ntfs_major: u8,
    pub ntfs_minor: u8,
    pub formatter_release: &'static str,
    pub formatter_commit: &'static str,
    pub formatter_table_os_major: u8,
    pub formatter_table_os_minor: u8,
    pub golden_md5: &'static str,
    pub golden_sha256: [u8; 32],
}

/// The only profile currently authorized for deterministic destination generation.
pub const NTFS3G_WINDOWS61_UPCASE_PROFILE: NtfsUpcaseProfile = NtfsUpcaseProfile {
    profile_name: "ntfs-3g-windows-6.1-upcase",
    ntfs_major: 3,
    ntfs_minor: 1,
    formatter_release: "NTFS-3G 2022.10.3",
    formatter_commit: "78414d93613532fd82f3a82aba5d4a1c32898781",
    formatter_table_os_major: 6,
    formatter_table_os_minor: 1,
    golden_md5: "7ff498a44e45e77374cc7c962b1b92f2",
    golden_sha256: NTFS3G_WINDOWS61_UPCASE_SHA256,
};

/// Caller-controlled allocation and filename-work limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtfsUpcaseLimits {
    pub max_table_bytes: usize,
    pub max_name_units: usize,
}

impl Default for NtfsUpcaseLimits {
    fn default() -> Self {
        Self {
            max_table_bytes: NTFS_UPCASE_TABLE_BYTES,
            max_name_units: NTFS_MAX_FILE_NAME_UNITS,
        }
    }
}

/// An owned table whose exact bytes have passed the independent golden validator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsUpcaseTable {
    mappings: Box<[u16]>,
    little_endian_bytes: Box<[u8]>,
}

impl NtfsUpcaseTable {
    /// All 65,536 mappings, indexed directly by an input UTF-16 code unit.
    #[must_use]
    pub const fn mappings(&self) -> &[u16] {
        &self.mappings
    }

    /// Exact 131,072-byte unnamed `$DATA` payload for `$UpCase`.
    #[must_use]
    pub const fn little_endian_bytes(&self) -> &[u8] {
        &self.little_endian_bytes
    }

    /// Maps exactly one UTF-16 code unit with the pinned on-disk table.
    #[must_use]
    pub fn lookup(&self, unit: u16) -> u16 {
        self.mappings[usize::from(unit)]
    }

    /// Returns a table-mapped copy of a bounded UTF-16 name.
    ///
    /// # Errors
    ///
    /// Refuses invalid limits, names longer than `max_name_units`, or allocation failure.
    pub fn upcase_name(
        &self,
        name: &[u16],
        limits: NtfsUpcaseLimits,
    ) -> Result<Vec<u16>, NtfsUpcaseError> {
        check_name_limit(name, limits)?;
        let mut mapped = Vec::new();
        mapped
            .try_reserve_exact(name.len())
            .map_err(|_| NtfsUpcaseError::AllocationFailed {
                component: "upcased name",
                requested: name.len(),
            })?;
        mapped.extend(name.iter().map(|unit| self.lookup(*unit)));
        Ok(mapped)
    }

    /// Compares names after mapping every code unit through `$UpCase`.
    ///
    /// Names that differ only by a table-defined case pair compare equal.
    ///
    /// # Errors
    ///
    /// Refuses invalid limits or either name exceeding `max_name_units`.
    pub fn collate_case_insensitive(
        &self,
        left: &[u16],
        right: &[u16],
        limits: NtfsUpcaseLimits,
    ) -> Result<Ordering, NtfsUpcaseError> {
        check_name_limit(left, limits)?;
        check_name_limit(right, limits)?;
        Ok(collate_mapped(left, right, &self.mappings))
    }

    /// Reproduces the NTFS-3G full, case-sensitive directory-index collation rule.
    ///
    /// The primary comparison uses `$UpCase`; names equal under that comparison are ordered by
    /// their original UTF-16 code units. This yields `"ABC" < "abc" < "BCD"`.
    ///
    /// # Errors
    ///
    /// Refuses invalid limits or either name exceeding `max_name_units`.
    pub fn collate_directory(
        &self,
        left: &[u16],
        right: &[u16],
        limits: NtfsUpcaseLimits,
    ) -> Result<Ordering, NtfsUpcaseError> {
        let mapped = self.collate_case_insensitive(left, right, limits)?;
        Ok(mapped.then_with(|| left.cmp(right)))
    }
}

/// Reason generation, validation, or bounded collation was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NtfsUpcaseError {
    InvalidLimit {
        field: &'static str,
    },
    TableByteLimitExceeded {
        actual: usize,
        maximum: usize,
    },
    NameUnitLimitExceeded {
        actual: usize,
        maximum: usize,
    },
    IncorrectByteLength {
        actual: usize,
        expected: usize,
    },
    ProfileDigestMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    AllocationFailed {
        component: &'static str,
        requested: usize,
    },
    ProfileDefinitionInvalid,
}

impl fmt::Display for NtfsUpcaseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit { field } => write!(formatter, "invalid `$UpCase` limit: {field}"),
            Self::TableByteLimitExceeded { actual, maximum } => write!(
                formatter,
                "`$UpCase` requires {actual} bytes but the limit is {maximum}"
            ),
            Self::NameUnitLimitExceeded { actual, maximum } => write!(
                formatter,
                "NTFS name has {actual} UTF-16 units but the limit is {maximum}"
            ),
            Self::IncorrectByteLength { actual, expected } => write!(
                formatter,
                "`$UpCase` has {actual} bytes; the pinned profile requires {expected}"
            ),
            Self::ProfileDigestMismatch { .. } => {
                formatter.write_str("`$UpCase` does not match the pinned profile digest")
            }
            Self::AllocationFailed {
                component,
                requested,
            } => write!(
                formatter,
                "could not reserve {requested} units for {component}"
            ),
            Self::ProfileDefinitionInvalid => {
                formatter.write_str("the compiled `$UpCase` profile definition is invalid")
            }
        }
    }
}

impl std::error::Error for NtfsUpcaseError {}

/// Generates the complete pinned NTFS-3G Windows 6.1 table and then subjects the result to the
/// independent byte-length and SHA-256 validator.
///
/// # Errors
///
/// Refuses invalid or insufficient limits, allocation failure, a malformed compiled profile, or
/// any generated byte sequence that does not match the pinned golden digest.
pub fn generate_ntfs3g_windows61_upcase(
    limits: NtfsUpcaseLimits,
) -> Result<NtfsUpcaseTable, NtfsUpcaseError> {
    check_table_limit(NTFS_UPCASE_TABLE_BYTES, limits)?;

    let mut mappings = Vec::new();
    mappings
        .try_reserve_exact(NTFS_UPCASE_TABLE_UNITS)
        .map_err(|_| NtfsUpcaseError::AllocationFailed {
            component: "`$UpCase` mappings",
            requested: NTFS_UPCASE_TABLE_UNITS,
        })?;
    mappings.extend(0_u16..=u16::MAX);

    for rule in XP_RUN_RULES {
        apply_exclusive_offset_rule(&mut mappings, *rule)?;
    }
    for rule in XP_DUPLICATE_RULES {
        apply_duplicate_rule(&mut mappings, *rule)?;
    }
    for &(input, output) in XP_SINGLE_MAPPINGS {
        mappings[usize::from(input)] = output;
    }
    for rule in WINDOWS60_AND_61_RULES {
        apply_inclusive_offset_rule(&mut mappings, *rule)?;
    }

    let bytes = encode_little_endian(&mappings, limits)?;
    validate_ntfs3g_windows61_upcase(&bytes, limits)
}

/// Independently validates caller-provided `$UpCase` bytes against the pinned authoritative
/// length and digest, then decodes all 65,536 little-endian mappings.
///
/// This validator deliberately does not call the generator or replay its mapping rules.
///
/// # Errors
///
/// Refuses invalid limits, over-limit or noncanonical lengths, a digest mismatch, or allocation
/// failure while constructing the validated owned table.
pub fn validate_ntfs3g_windows61_upcase(
    bytes: &[u8],
    limits: NtfsUpcaseLimits,
) -> Result<NtfsUpcaseTable, NtfsUpcaseError> {
    check_table_limit(bytes.len(), limits)?;
    if bytes.len() != NTFS_UPCASE_TABLE_BYTES {
        return Err(NtfsUpcaseError::IncorrectByteLength {
            actual: bytes.len(),
            expected: NTFS_UPCASE_TABLE_BYTES,
        });
    }

    let actual_digest: [u8; 32] = Sha256::digest(bytes).into();
    if actual_digest != NTFS3G_WINDOWS61_UPCASE_SHA256 {
        return Err(NtfsUpcaseError::ProfileDigestMismatch {
            expected: NTFS3G_WINDOWS61_UPCASE_SHA256,
            actual: actual_digest,
        });
    }

    let mut mappings = Vec::new();
    mappings
        .try_reserve_exact(NTFS_UPCASE_TABLE_UNITS)
        .map_err(|_| NtfsUpcaseError::AllocationFailed {
            component: "validated `$UpCase` mappings",
            requested: NTFS_UPCASE_TABLE_UNITS,
        })?;
    mappings.extend(
        bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]])),
    );

    let mut owned_bytes = Vec::new();
    owned_bytes
        .try_reserve_exact(NTFS_UPCASE_TABLE_BYTES)
        .map_err(|_| NtfsUpcaseError::AllocationFailed {
            component: "validated `$UpCase` bytes",
            requested: NTFS_UPCASE_TABLE_BYTES,
        })?;
    owned_bytes.extend_from_slice(bytes);

    Ok(NtfsUpcaseTable {
        mappings: mappings.into_boxed_slice(),
        little_endian_bytes: owned_bytes.into_boxed_slice(),
    })
}

const fn check_table_limit(actual: usize, limits: NtfsUpcaseLimits) -> Result<(), NtfsUpcaseError> {
    if limits.max_table_bytes == 0 {
        return Err(NtfsUpcaseError::InvalidLimit {
            field: "max_table_bytes must be nonzero",
        });
    }
    if limits.max_name_units == 0 || limits.max_name_units > NTFS_MAX_FILE_NAME_UNITS {
        return Err(NtfsUpcaseError::InvalidLimit {
            field: "max_name_units must be in 1..=255",
        });
    }
    if actual > limits.max_table_bytes {
        return Err(NtfsUpcaseError::TableByteLimitExceeded {
            actual,
            maximum: limits.max_table_bytes,
        });
    }
    Ok(())
}

fn check_name_limit(name: &[u16], limits: NtfsUpcaseLimits) -> Result<(), NtfsUpcaseError> {
    check_table_limit(NTFS_UPCASE_TABLE_BYTES, limits)?;
    if name.len() > limits.max_name_units {
        return Err(NtfsUpcaseError::NameUnitLimitExceeded {
            actual: name.len(),
            maximum: limits.max_name_units,
        });
    }
    Ok(())
}

fn encode_little_endian(
    mappings: &[u16],
    limits: NtfsUpcaseLimits,
) -> Result<Vec<u8>, NtfsUpcaseError> {
    check_table_limit(NTFS_UPCASE_TABLE_BYTES, limits)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(NTFS_UPCASE_TABLE_BYTES)
        .map_err(|_| NtfsUpcaseError::AllocationFailed {
            component: "generated `$UpCase` bytes",
            requested: NTFS_UPCASE_TABLE_BYTES,
        })?;
    for mapping in mappings {
        bytes.extend_from_slice(&mapping.to_le_bytes());
    }
    Ok(bytes)
}

fn collate_mapped(left: &[u16], right: &[u16], mappings: &[u16]) -> Ordering {
    left.iter()
        .zip(right)
        .map(|(left, right)| mappings[usize::from(*left)].cmp(&mappings[usize::from(*right)]))
        .find(|ordering| *ordering != Ordering::Equal)
        .unwrap_or_else(|| left.len().cmp(&right.len()))
}

#[derive(Debug, Clone, Copy)]
struct ExclusiveOffsetRule {
    first: u16,
    end: u16,
    difference: i32,
}

#[derive(Debug, Clone, Copy)]
struct DuplicateRule {
    first: u16,
    end: u16,
}

#[derive(Debug, Clone, Copy)]
struct InclusiveOffsetRule {
    first: u16,
    last: u16,
    difference: i32,
    step: u16,
}

fn offset_unit(unit: u16, difference: i32) -> Result<u16, NtfsUpcaseError> {
    let wrapped = (i32::from(unit) + difference).rem_euclid(65_536);
    u16::try_from(wrapped).map_err(|_| NtfsUpcaseError::ProfileDefinitionInvalid)
}

fn apply_exclusive_offset_rule(
    mappings: &mut [u16],
    rule: ExclusiveOffsetRule,
) -> Result<(), NtfsUpcaseError> {
    if rule.first >= rule.end {
        return Err(NtfsUpcaseError::ProfileDefinitionInvalid);
    }
    for point in u32::from(rule.first)..u32::from(rule.end) {
        let unit = u16::try_from(point).map_err(|_| NtfsUpcaseError::ProfileDefinitionInvalid)?;
        mappings[usize::from(unit)] = offset_unit(unit, rule.difference)?;
    }
    Ok(())
}

fn apply_duplicate_rule(mappings: &mut [u16], rule: DuplicateRule) -> Result<(), NtfsUpcaseError> {
    let mut source = u32::from(rule.first);
    let end = u32::from(rule.end);
    while source < end {
        let destination = source
            .checked_add(1)
            .ok_or(NtfsUpcaseError::ProfileDefinitionInvalid)?;
        let source_unit =
            u16::try_from(source).map_err(|_| NtfsUpcaseError::ProfileDefinitionInvalid)?;
        let destination_unit =
            u16::try_from(destination).map_err(|_| NtfsUpcaseError::ProfileDefinitionInvalid)?;
        mappings[usize::from(destination_unit)] = source_unit;
        source = source
            .checked_add(2)
            .ok_or(NtfsUpcaseError::ProfileDefinitionInvalid)?;
    }
    Ok(())
}

fn apply_inclusive_offset_rule(
    mappings: &mut [u16],
    rule: InclusiveOffsetRule,
) -> Result<(), NtfsUpcaseError> {
    if rule.first > rule.last || rule.step == 0 {
        return Err(NtfsUpcaseError::ProfileDefinitionInvalid);
    }
    let mut point = u32::from(rule.first);
    let last = u32::from(rule.last);
    while point <= last {
        let unit = u16::try_from(point).map_err(|_| NtfsUpcaseError::ProfileDefinitionInvalid)?;
        mappings[usize::from(unit)] = offset_unit(unit, rule.difference)?;
        point = point
            .checked_add(u32::from(rule.step))
            .ok_or(NtfsUpcaseError::ProfileDefinitionInvalid)?;
    }
    Ok(())
}

const XP_RUN_RULES: &[ExclusiveOffsetRule] = &[
    ExclusiveOffsetRule {
        first: 0x0061,
        end: 0x007b,
        difference: -32,
    },
    ExclusiveOffsetRule {
        first: 0x0451,
        end: 0x045d,
        difference: -80,
    },
    ExclusiveOffsetRule {
        first: 0x1f70,
        end: 0x1f72,
        difference: 74,
    },
    ExclusiveOffsetRule {
        first: 0x00e0,
        end: 0x00f7,
        difference: -32,
    },
    ExclusiveOffsetRule {
        first: 0x045e,
        end: 0x0460,
        difference: -80,
    },
    ExclusiveOffsetRule {
        first: 0x1f72,
        end: 0x1f76,
        difference: 86,
    },
    ExclusiveOffsetRule {
        first: 0x00f8,
        end: 0x00ff,
        difference: -32,
    },
    ExclusiveOffsetRule {
        first: 0x0561,
        end: 0x0587,
        difference: -48,
    },
    ExclusiveOffsetRule {
        first: 0x1f76,
        end: 0x1f78,
        difference: 100,
    },
    ExclusiveOffsetRule {
        first: 0x0256,
        end: 0x0258,
        difference: -205,
    },
    ExclusiveOffsetRule {
        first: 0x1f00,
        end: 0x1f08,
        difference: 8,
    },
    ExclusiveOffsetRule {
        first: 0x1f78,
        end: 0x1f7a,
        difference: 128,
    },
    ExclusiveOffsetRule {
        first: 0x028a,
        end: 0x028c,
        difference: -217,
    },
    ExclusiveOffsetRule {
        first: 0x1f10,
        end: 0x1f16,
        difference: 8,
    },
    ExclusiveOffsetRule {
        first: 0x1f7a,
        end: 0x1f7c,
        difference: 112,
    },
    ExclusiveOffsetRule {
        first: 0x03ac,
        end: 0x03ad,
        difference: -38,
    },
    ExclusiveOffsetRule {
        first: 0x1f20,
        end: 0x1f28,
        difference: 8,
    },
    ExclusiveOffsetRule {
        first: 0x1f7c,
        end: 0x1f7e,
        difference: 126,
    },
    ExclusiveOffsetRule {
        first: 0x03ad,
        end: 0x03b0,
        difference: -37,
    },
    ExclusiveOffsetRule {
        first: 0x1f30,
        end: 0x1f38,
        difference: 8,
    },
    ExclusiveOffsetRule {
        first: 0x1fb0,
        end: 0x1fb2,
        difference: 8,
    },
    ExclusiveOffsetRule {
        first: 0x03b1,
        end: 0x03c2,
        difference: -32,
    },
    ExclusiveOffsetRule {
        first: 0x1f40,
        end: 0x1f46,
        difference: 8,
    },
    ExclusiveOffsetRule {
        first: 0x1fd0,
        end: 0x1fd2,
        difference: 8,
    },
    ExclusiveOffsetRule {
        first: 0x03c2,
        end: 0x03c3,
        difference: -31,
    },
    ExclusiveOffsetRule {
        first: 0x1f51,
        end: 0x1f52,
        difference: 8,
    },
    ExclusiveOffsetRule {
        first: 0x1fe0,
        end: 0x1fe2,
        difference: 8,
    },
    ExclusiveOffsetRule {
        first: 0x03c3,
        end: 0x03cc,
        difference: -32,
    },
    ExclusiveOffsetRule {
        first: 0x1f53,
        end: 0x1f54,
        difference: 8,
    },
    ExclusiveOffsetRule {
        first: 0x1fe5,
        end: 0x1fe6,
        difference: 7,
    },
    ExclusiveOffsetRule {
        first: 0x03cc,
        end: 0x03cd,
        difference: -64,
    },
    ExclusiveOffsetRule {
        first: 0x1f55,
        end: 0x1f56,
        difference: 8,
    },
    ExclusiveOffsetRule {
        first: 0x2170,
        end: 0x2180,
        difference: -16,
    },
    ExclusiveOffsetRule {
        first: 0x03cd,
        end: 0x03cf,
        difference: -63,
    },
    ExclusiveOffsetRule {
        first: 0x1f57,
        end: 0x1f58,
        difference: 8,
    },
    ExclusiveOffsetRule {
        first: 0x24d0,
        end: 0x24ea,
        difference: -26,
    },
    ExclusiveOffsetRule {
        first: 0x0430,
        end: 0x0450,
        difference: -32,
    },
    ExclusiveOffsetRule {
        first: 0x1f60,
        end: 0x1f68,
        difference: 8,
    },
    ExclusiveOffsetRule {
        first: 0xff41,
        end: 0xff5b,
        difference: -32,
    },
];

const XP_DUPLICATE_RULES: &[DuplicateRule] = &[
    DuplicateRule {
        first: 0x0100,
        end: 0x012f,
    },
    DuplicateRule {
        first: 0x01a0,
        end: 0x01a6,
    },
    DuplicateRule {
        first: 0x03e2,
        end: 0x03ef,
    },
    DuplicateRule {
        first: 0x04cb,
        end: 0x04cc,
    },
    DuplicateRule {
        first: 0x0132,
        end: 0x0137,
    },
    DuplicateRule {
        first: 0x01b3,
        end: 0x01b7,
    },
    DuplicateRule {
        first: 0x0460,
        end: 0x0481,
    },
    DuplicateRule {
        first: 0x04d0,
        end: 0x04eb,
    },
    DuplicateRule {
        first: 0x0139,
        end: 0x0149,
    },
    DuplicateRule {
        first: 0x01cd,
        end: 0x01dd,
    },
    DuplicateRule {
        first: 0x0490,
        end: 0x04bf,
    },
    DuplicateRule {
        first: 0x04ee,
        end: 0x04f5,
    },
    DuplicateRule {
        first: 0x014a,
        end: 0x0178,
    },
    DuplicateRule {
        first: 0x01de,
        end: 0x01ef,
    },
    DuplicateRule {
        first: 0x04bf,
        end: 0x04bf,
    },
    DuplicateRule {
        first: 0x04f8,
        end: 0x04f9,
    },
    DuplicateRule {
        first: 0x0179,
        end: 0x017e,
    },
    DuplicateRule {
        first: 0x01f4,
        end: 0x01f5,
    },
    DuplicateRule {
        first: 0x04c1,
        end: 0x04c4,
    },
    DuplicateRule {
        first: 0x1e00,
        end: 0x1e95,
    },
    DuplicateRule {
        first: 0x018b,
        end: 0x018b,
    },
    DuplicateRule {
        first: 0x01fa,
        end: 0x0218,
    },
    DuplicateRule {
        first: 0x04c7,
        end: 0x04c8,
    },
    DuplicateRule {
        first: 0x1ea0,
        end: 0x1ef9,
    },
];

const XP_SINGLE_MAPPINGS: &[(u16, u16)] = &[
    (0x00ff, 0x0178),
    (0x01ad, 0x01ac),
    (0x01f3, 0x01f1),
    (0x0269, 0x0196),
    (0x0183, 0x0182),
    (0x01b0, 0x01af),
    (0x0253, 0x0181),
    (0x026f, 0x019c),
    (0x0185, 0x0184),
    (0x01b9, 0x01b8),
    (0x0254, 0x0186),
    (0x0272, 0x019d),
    (0x0188, 0x0187),
    (0x01bd, 0x01bc),
    (0x0259, 0x018f),
    (0x0275, 0x019f),
    (0x018c, 0x018b),
    (0x01c6, 0x01c4),
    (0x025b, 0x0190),
    (0x0283, 0x01a9),
    (0x0192, 0x0191),
    (0x01c9, 0x01c7),
    (0x0260, 0x0193),
    (0x0288, 0x01ae),
    (0x0199, 0x0198),
    (0x01cc, 0x01ca),
    (0x0263, 0x0194),
    (0x0292, 0x01b7),
    (0x01a8, 0x01a7),
    (0x01dd, 0x018e),
    (0x0268, 0x0197),
];

const WINDOWS60_AND_61_RULES: &[InclusiveOffsetRule] = &[
    InclusiveOffsetRule {
        first: 0x037b,
        last: 0x037d,
        difference: 0x82,
        step: 1,
    },
    InclusiveOffsetRule {
        first: 0x1f80,
        last: 0x1f87,
        difference: 8,
        step: 1,
    },
    InclusiveOffsetRule {
        first: 0x1f90,
        last: 0x1f97,
        difference: 8,
        step: 1,
    },
    InclusiveOffsetRule {
        first: 0x1fa0,
        last: 0x1fa7,
        difference: 8,
        step: 1,
    },
    InclusiveOffsetRule {
        first: 0x2c30,
        last: 0x2c5e,
        difference: -0x30,
        step: 1,
    },
    InclusiveOffsetRule {
        first: 0x2d00,
        last: 0x2d25,
        difference: -0x1c60,
        step: 1,
    },
    InclusiveOffsetRule {
        first: 0x2c68,
        last: 0x2c6c,
        difference: -1,
        step: 2,
    },
    InclusiveOffsetRule {
        first: 0x0219,
        last: 0x021f,
        difference: -1,
        step: 2,
    },
    InclusiveOffsetRule {
        first: 0x0223,
        last: 0x0233,
        difference: -1,
        step: 2,
    },
    InclusiveOffsetRule {
        first: 0x0247,
        last: 0x024f,
        difference: -1,
        step: 2,
    },
    InclusiveOffsetRule {
        first: 0x03d9,
        last: 0x03e1,
        difference: -1,
        step: 2,
    },
    InclusiveOffsetRule {
        first: 0x048b,
        last: 0x048f,
        difference: -1,
        step: 2,
    },
    InclusiveOffsetRule {
        first: 0x04fb,
        last: 0x0513,
        difference: -1,
        step: 2,
    },
    InclusiveOffsetRule {
        first: 0x2c81,
        last: 0x2ce3,
        difference: -1,
        step: 2,
    },
    InclusiveOffsetRule {
        first: 0x03f8,
        last: 0x03fb,
        difference: -1,
        step: 3,
    },
    InclusiveOffsetRule {
        first: 0x04c6,
        last: 0x04ce,
        difference: -1,
        step: 4,
    },
    InclusiveOffsetRule {
        first: 0x023c,
        last: 0x0242,
        difference: -1,
        step: 6,
    },
    InclusiveOffsetRule {
        first: 0x04ed,
        last: 0x04f7,
        difference: -1,
        step: 10,
    },
    InclusiveOffsetRule {
        first: 0x0450,
        last: 0x045d,
        difference: -0x50,
        step: 13,
    },
    InclusiveOffsetRule {
        first: 0x2c61,
        last: 0x2c76,
        difference: -1,
        step: 21,
    },
    InclusiveOffsetRule {
        first: 0x1fcc,
        last: 0x1ffc,
        difference: -9,
        step: 48,
    },
    InclusiveOffsetRule {
        first: 0x0180,
        last: 0x0180,
        difference: 0xc3,
        step: 1,
    },
    InclusiveOffsetRule {
        first: 0x0195,
        last: 0x0195,
        difference: 0x61,
        step: 1,
    },
    InclusiveOffsetRule {
        first: 0x019a,
        last: 0x019a,
        difference: 0xa3,
        step: 1,
    },
    InclusiveOffsetRule {
        first: 0x019e,
        last: 0x019e,
        difference: 0x82,
        step: 1,
    },
    InclusiveOffsetRule {
        first: 0x01bf,
        last: 0x01bf,
        difference: 0x38,
        step: 1,
    },
    InclusiveOffsetRule {
        first: 0x01f9,
        last: 0x01f9,
        difference: -1,
        step: 1,
    },
    InclusiveOffsetRule {
        first: 0x023a,
        last: 0x023a,
        difference: 0x2a2b,
        step: 1,
    },
    InclusiveOffsetRule {
        first: 0x023e,
        last: 0x023e,
        difference: 0x2a28,
        step: 1,
    },
    InclusiveOffsetRule {
        first: 0x026b,
        last: 0x026b,
        difference: 0x29f7,
        step: 1,
    },
    InclusiveOffsetRule {
        first: 0x027d,
        last: 0x027d,
        difference: 0x29e7,
        step: 1,
    },
    InclusiveOffsetRule {
        first: 0x0280,
        last: 0x0280,
        difference: -0xda,
        step: 1,
    },
    InclusiveOffsetRule {
        first: 0x0289,
        last: 0x0289,
        difference: -0x45,
        step: 1,
    },
    InclusiveOffsetRule {
        first: 0x028c,
        last: 0x028c,
        difference: -0x47,
        step: 1,
    },
    InclusiveOffsetRule {
        first: 0x03f2,
        last: 0x03f2,
        difference: 7,
        step: 1,
    },
    InclusiveOffsetRule {
        first: 0x04cf,
        last: 0x04cf,
        difference: -0xf,
        step: 1,
    },
    InclusiveOffsetRule {
        first: 0x1d7d,
        last: 0x1d7d,
        difference: 0xee6,
        step: 1,
    },
    InclusiveOffsetRule {
        first: 0x1fb3,
        last: 0x1fb3,
        difference: 9,
        step: 1,
    },
    InclusiveOffsetRule {
        first: 0x214e,
        last: 0x214e,
        difference: -0x1c,
        step: 1,
    },
    InclusiveOffsetRule {
        first: 0x2184,
        last: 0x2184,
        difference: -1,
        step: 1,
    },
    InclusiveOffsetRule {
        first: 0x023a,
        last: 0x023e,
        difference: 0,
        step: 4,
    },
    InclusiveOffsetRule {
        first: 0x0250,
        last: 0x0250,
        difference: 0x2a1f,
        step: 2,
    },
    InclusiveOffsetRule {
        first: 0x0251,
        last: 0x0251,
        difference: 0x2a1c,
        step: 2,
    },
    InclusiveOffsetRule {
        first: 0x0271,
        last: 0x0271,
        difference: 0x29fd,
        step: 2,
    },
    InclusiveOffsetRule {
        first: 0x0371,
        last: 0x0373,
        difference: -1,
        step: 2,
    },
    InclusiveOffsetRule {
        first: 0x0377,
        last: 0x0377,
        difference: -1,
        step: 2,
    },
    InclusiveOffsetRule {
        first: 0x03c2,
        last: 0x03c2,
        difference: 0,
        step: 2,
    },
    InclusiveOffsetRule {
        first: 0x03d7,
        last: 0x03d7,
        difference: -8,
        step: 2,
    },
    InclusiveOffsetRule {
        first: 0x0515,
        last: 0x0523,
        difference: -1,
        step: 2,
    },
    InclusiveOffsetRule {
        first: 0x1d79,
        last: 0x1d79,
        difference: -0x75fc,
        step: 2,
    },
    InclusiveOffsetRule {
        first: 0x1efb,
        last: 0x1eff,
        difference: -1,
        step: 2,
    },
    InclusiveOffsetRule {
        first: 0x1fc3,
        last: 0x1ff3,
        difference: 9,
        step: 48,
    },
    InclusiveOffsetRule {
        first: 0x1fcc,
        last: 0x1ffc,
        difference: 0,
        step: 48,
    },
    InclusiveOffsetRule {
        first: 0x2c65,
        last: 0x2c65,
        difference: -0x2a2b,
        step: 2,
    },
    InclusiveOffsetRule {
        first: 0x2c66,
        last: 0x2c66,
        difference: -0x2a28,
        step: 2,
    },
    InclusiveOffsetRule {
        first: 0x2c73,
        last: 0x2c73,
        difference: -1,
        step: 2,
    },
    InclusiveOffsetRule {
        first: 0xa641,
        last: 0xa65f,
        difference: -1,
        step: 2,
    },
    InclusiveOffsetRule {
        first: 0xa663,
        last: 0xa66d,
        difference: -1,
        step: 2,
    },
    InclusiveOffsetRule {
        first: 0xa681,
        last: 0xa697,
        difference: -1,
        step: 2,
    },
    InclusiveOffsetRule {
        first: 0xa723,
        last: 0xa72f,
        difference: -1,
        step: 2,
    },
    InclusiveOffsetRule {
        first: 0xa733,
        last: 0xa76f,
        difference: -1,
        step: 2,
    },
    InclusiveOffsetRule {
        first: 0xa77a,
        last: 0xa77c,
        difference: -1,
        step: 2,
    },
    InclusiveOffsetRule {
        first: 0xa77f,
        last: 0xa787,
        difference: -1,
        step: 2,
    },
    InclusiveOffsetRule {
        first: 0xa78c,
        last: 0xa78c,
        difference: -1,
        step: 2,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> NtfsUpcaseTable {
        generate_ntfs3g_windows61_upcase(NtfsUpcaseLimits::default()).expect("profile")
    }

    #[test]
    fn generated_table_matches_pinned_formatter_digest_and_size() {
        let table = table();
        assert_eq!(table.mappings().len(), NTFS_UPCASE_TABLE_UNITS);
        assert_eq!(table.little_endian_bytes().len(), NTFS_UPCASE_TABLE_BYTES);
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(table.little_endian_bytes())),
            NTFS3G_WINDOWS61_UPCASE_SHA256
        );
        assert_eq!(
            NTFS3G_WINDOWS61_UPCASE_PROFILE.golden_md5,
            "7ff498a44e45e77374cc7c962b1b92f2"
        );
    }

    #[test]
    fn validator_rejects_truncation_extension_and_digest_mutation() {
        let canonical = table().little_endian_bytes().to_vec();
        assert!(matches!(
            validate_ntfs3g_windows61_upcase(
                &canonical[..canonical.len() - 1],
                NtfsUpcaseLimits::default()
            ),
            Err(NtfsUpcaseError::IncorrectByteLength { .. })
        ));

        let mut extended = canonical.clone();
        extended.push(0);
        assert_eq!(
            validate_ntfs3g_windows61_upcase(&extended, NtfsUpcaseLimits::default()),
            Err(NtfsUpcaseError::TableByteLimitExceeded {
                actual: NTFS_UPCASE_TABLE_BYTES + 1,
                maximum: NTFS_UPCASE_TABLE_BYTES,
            })
        );

        let mut mutated = canonical;
        mutated[0x2c65 * 2] ^= 1;
        assert!(matches!(
            validate_ntfs3g_windows61_upcase(&mutated, NtfsUpcaseLimits::default()),
            Err(NtfsUpcaseError::ProfileDigestMismatch { .. })
        ));
    }

    #[test]
    fn exact_non_ascii_and_utf16_code_unit_cases_match_golden_profile() {
        let table = table();
        assert_eq!(table.lookup(0x0061), 0x0041);
        assert_eq!(table.lookup(0x00df), 0x00df); // no one-to-many `SS` expansion
        assert_eq!(table.lookup(0x00ff), 0x0178);
        assert_eq!(table.lookup(0x0131), 0x0131); // unlike current Rust Unicode casing
        assert_eq!(table.lookup(0x017f), 0x017f); // unlike current Rust Unicode casing
        assert_eq!(table.lookup(0x0180), 0x0243);
        assert_eq!(table.lookup(0x0250), 0x2c6f);
        assert_eq!(table.lookup(0x0371), 0x0370);
        assert_eq!(table.lookup(0x03c2), 0x03c2); // Win7 override of the XP mapping
        assert_eq!(table.lookup(0x1d79), 0xa77d); // deliberate 16-bit wrapped offset
        assert_eq!(table.lookup(0x2c65), 0x023a);
        assert_eq!(table.lookup(0xa641), 0xa640);
        assert_eq!(table.lookup(0xd800), 0xd800); // lone surrogate is a code unit
        assert_eq!(table.lookup(0xff41), 0xff21);
    }

    #[test]
    fn collation_uses_profile_then_original_units_as_tie_break() {
        let table = table();
        let limits = NtfsUpcaseLimits::default();
        let abc_upper: Vec<u16> = "ABC".encode_utf16().collect();
        let abc_lower: Vec<u16> = "abc".encode_utf16().collect();
        let bcd_upper: Vec<u16> = "BCD".encode_utf16().collect();

        assert_eq!(
            table.collate_case_insensitive(&abc_upper, &abc_lower, limits),
            Ok(Ordering::Equal)
        );
        assert_eq!(
            table.collate_directory(&abc_upper, &abc_lower, limits),
            Ok(Ordering::Less)
        );
        assert_eq!(
            table.collate_directory(&abc_lower, &bcd_upper, limits),
            Ok(Ordering::Less)
        );
        assert_eq!(
            table.collate_case_insensitive(&[0x0371], &[0x0370], limits),
            Ok(Ordering::Equal)
        );
    }

    #[test]
    fn generation_and_name_work_refuse_caller_limit_overruns() {
        let small_table_limit = NtfsUpcaseLimits {
            max_table_bytes: NTFS_UPCASE_TABLE_BYTES - 1,
            ..NtfsUpcaseLimits::default()
        };
        assert_eq!(
            generate_ntfs3g_windows61_upcase(small_table_limit),
            Err(NtfsUpcaseError::TableByteLimitExceeded {
                actual: NTFS_UPCASE_TABLE_BYTES,
                maximum: NTFS_UPCASE_TABLE_BYTES - 1,
            })
        );

        let table = table();
        let name_limits = NtfsUpcaseLimits {
            max_name_units: 2,
            ..NtfsUpcaseLimits::default()
        };
        assert_eq!(
            table.upcase_name(&[b'a'.into(), b'b'.into(), b'c'.into()], name_limits),
            Err(NtfsUpcaseError::NameUnitLimitExceeded {
                actual: 3,
                maximum: 2,
            })
        );
    }

    #[test]
    fn every_mapping_is_idempotent() {
        let table = table();
        for (input, mapped) in table.mappings().iter().copied().enumerate() {
            assert_eq!(
                table.lookup(mapped),
                mapped,
                "mapping for {input:#06x} was not idempotent"
            );
        }
    }
}
