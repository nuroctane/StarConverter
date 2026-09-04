//! Production generation and independent validation of the recommended exFAT Up-case Table.
//!
//! The exFAT 1.00 specification normatively requires a complete table whenever a formatter
//! defines mappings outside the mandatory first 128 code units, permits identity-run compression,
//! and normatively defines the checksum over the *encoded* bytes. Section 7.2.5.1 separately says
//! formatters **should** use its recommended 5,836-byte compressed table, whose checksum is
//! `0xE619_D30D`; that particular byte profile is recommended, not the only conforming profile.
//!
//! The embedded profile is additionally pinned to exfatprogs 1.2.2 commit
//! `8fe26c50703fba6eb3046e42b674eb0a41da2119` (`mkfs/upcase.c`, `mkfs/mkfs.c`, and
//! `include/libexfat.h`). Its SHA-256 was independently measured from the Up-case stream of a fresh
//! regular-file image created by that release. This module has no I/O or path/device API, treats
//! names as UTF-16 code units, and bounds every allocation and filename operation.

use std::cmp::Ordering;
use std::fmt;

use sha2::{Digest, Sha256};

use super::exfat_upcase::{
    MAX_FILE_NAME_CODE_UNITS, NameError, UNICODE_MAPPING_COUNT, UpcaseError, UpcaseLimits,
    UpcaseTable,
};

/// Exact byte length of Microsoft exFAT 1.00 Table 25 in compressed form.
pub const RECOMMENDED_EXFAT_UPCASE_BYTES: usize = 5_836;
/// Normative `TableChecksum` published for the recommended compressed byte sequence.
pub const RECOMMENDED_EXFAT_UPCASE_CHECKSUM: u32 = 0xe619_d30d;
/// SHA-256 of exfatprogs 1.2.2's exact 5,836-byte formatter payload.
pub const RECOMMENDED_EXFAT_UPCASE_SHA256: [u8; 32] = [
    0x83, 0x44, 0xf2, 0x7a, 0x41, 0x0a, 0x16, 0xdf, 0x14, 0xad, 0x98, 0xde, 0xcd, 0xe3, 0x2b, 0x48,
    0xc4, 0xdb, 0x0b, 0x8e, 0x7f, 0xa8, 0xb9, 0xdc, 0x43, 0x94, 0xb5, 0x8c, 0xed, 0x97, 0x2f, 0x11,
];

/// Typed provenance and standards status for the production profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecommendedExfatUpcaseProfile {
    pub profile_name: &'static str,
    pub exfat_specification_revision: &'static str,
    pub specification_section: &'static str,
    /// `true` means the specification uses SHOULD for this exact profile, not SHALL.
    pub exact_profile_is_recommended: bool,
    /// Custom profiles must still cover all 65,536 code units.
    pub complete_custom_profile_is_mandatory: bool,
    pub formatter_release: &'static str,
    pub formatter_commit: &'static str,
    pub encoded_bytes: usize,
    pub table_checksum: u32,
    pub golden_md5: &'static str,
    pub golden_sha256: [u8; 32],
}

pub const RECOMMENDED_EXFAT_UPCASE_PROFILE: RecommendedExfatUpcaseProfile =
    RecommendedExfatUpcaseProfile {
        profile_name: "microsoft-exfat-1.00-recommended-upcase",
        exfat_specification_revision: "1.00",
        specification_section: "7.2.5.1 / Table 25",
        exact_profile_is_recommended: true,
        complete_custom_profile_is_mandatory: true,
        formatter_release: "exfatprogs 1.2.2",
        formatter_commit: "8fe26c50703fba6eb3046e42b674eb0a41da2119",
        encoded_bytes: RECOMMENDED_EXFAT_UPCASE_BYTES,
        table_checksum: RECOMMENDED_EXFAT_UPCASE_CHECKSUM,
        golden_md5: "ac9963c2a3292858c4f109763d721dfa",
        golden_sha256: RECOMMENDED_EXFAT_UPCASE_SHA256,
    };

/// Caller-controlled output, decompression, and filename-work limits.
#[allow(clippy::struct_field_names)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecommendedExfatUpcaseLimits {
    pub max_encoded_bytes: usize,
    pub max_mappings: usize,
    pub max_name_units: usize,
}

impl Default for RecommendedExfatUpcaseLimits {
    fn default() -> Self {
        Self {
            max_encoded_bytes: RECOMMENDED_EXFAT_UPCASE_BYTES,
            max_mappings: UNICODE_MAPPING_COUNT,
            max_name_units: MAX_FILE_NAME_CODE_UNITS,
        }
    }
}

/// An owned exact encoded stream plus its independently decoded complete mapping table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecommendedExfatUpcase {
    encoded: Box<[u8]>,
    table: UpcaseTable,
}

impl RecommendedExfatUpcase {
    #[must_use]
    pub const fn encoded_bytes(&self) -> &[u8] {
        &self.encoded
    }

    #[must_use]
    pub const fn mappings(&self) -> &[u16] {
        self.table.mappings()
    }

    #[must_use]
    pub fn map(&self, unit: u16) -> u16 {
        self.table.map(unit)
    }

    /// Returns a bounded mapped copy of a valid nonempty exFAT filename.
    ///
    /// # Errors
    ///
    /// Refuses invalid limits, empty or over-limit names, and allocation failure.
    pub fn upcase_name(
        &self,
        name: &[u16],
        limits: RecommendedExfatUpcaseLimits,
    ) -> Result<Vec<u16>, RecommendedExfatUpcaseError> {
        check_name(name, limits)?;
        let mut output = Vec::new();
        output.try_reserve_exact(name.len()).map_err(|_| {
            RecommendedExfatUpcaseError::AllocationFailed {
                component: "upcased name",
                requested: name.len(),
            }
        })?;
        output.resize(name.len(), 0);
        self.table
            .upcase_name_into(name, &mut output, limits.max_name_units)
            .map_err(RecommendedExfatUpcaseError::Name)?;
        Ok(output)
    }

    /// Computes the normative exFAT `NameHash` over table-mapped little-endian name bytes.
    ///
    /// # Errors
    ///
    /// Refuses invalid limits or an empty/over-limit name.
    pub fn name_hash(
        &self,
        name: &[u16],
        limits: RecommendedExfatUpcaseLimits,
    ) -> Result<u16, RecommendedExfatUpcaseError> {
        check_limits(limits)?;
        self.table
            .name_hash(name, limits.max_name_units)
            .map_err(RecommendedExfatUpcaseError::Name)
    }

    /// Compares two names lexicographically after exact table mapping.
    ///
    /// # Errors
    ///
    /// Refuses invalid limits or either empty/over-limit name.
    pub fn collate(
        &self,
        left: &[u16],
        right: &[u16],
        limits: RecommendedExfatUpcaseLimits,
    ) -> Result<Ordering, RecommendedExfatUpcaseError> {
        check_name(left, limits)?;
        check_name(right, limits)?;
        Ok(left
            .iter()
            .zip(right)
            .map(|(left, right)| self.map(*left).cmp(&self.map(*right)))
            .find(|ordering| *ordering != Ordering::Equal)
            .unwrap_or_else(|| left.len().cmp(&right.len())))
    }

    /// Confirms whether two valid names collide under exFAT's case-insensitive mapping.
    ///
    /// # Errors
    ///
    /// Refuses invalid limits or either empty/over-limit name.
    pub fn names_collide(
        &self,
        left: &[u16],
        right: &[u16],
        limits: RecommendedExfatUpcaseLimits,
    ) -> Result<bool, RecommendedExfatUpcaseError> {
        Ok(self.collate(left, right, limits)? == Ordering::Equal)
    }
}

/// Reason production profile generation, validation, or name work was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecommendedExfatUpcaseError {
    InvalidLimit {
        field: &'static str,
    },
    IncorrectEncodedLength {
        actual: usize,
        expected: usize,
    },
    ProfileDigestMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    CompiledProfileInvalid,
    AllocationFailed {
        component: &'static str,
        requested: usize,
    },
    Table(UpcaseError),
    Name(NameError),
}

impl fmt::Display for RecommendedExfatUpcaseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit { field } => {
                write!(formatter, "invalid exFAT Up-case limit: {field}")
            }
            Self::IncorrectEncodedLength { actual, expected } => write!(
                formatter,
                "recommended exFAT Up-case Table has {actual} bytes; expected {expected}"
            ),
            Self::ProfileDigestMismatch { .. } => formatter
                .write_str("exFAT Up-case bytes do not match the recommended profile digest"),
            Self::CompiledProfileInvalid => {
                formatter.write_str("compiled recommended exFAT Up-case profile is malformed")
            }
            Self::AllocationFailed {
                component,
                requested,
            } => {
                write!(
                    formatter,
                    "could not reserve {requested} units for {component}"
                )
            }
            Self::Table(source) => write!(formatter, "invalid exFAT Up-case Table: {source}"),
            Self::Name(source) => write!(formatter, "invalid exFAT filename: {source}"),
        }
    }
}

impl std::error::Error for RecommendedExfatUpcaseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Table(source) => Some(source),
            Self::Name(source) => Some(source),
            _ => None,
        }
    }
}

/// Generates the exact recommended encoded profile from its embedded golden representation and
/// then runs the independent checksum, SHA-256, completeness, and mandatory-ASCII validator.
///
/// # Errors
///
/// Refuses invalid/insufficient limits, allocation failure, a malformed compiled representation,
/// or any generated bytes that fail independent profile validation.
pub fn generate_recommended_exfat_upcase(
    limits: RecommendedExfatUpcaseLimits,
) -> Result<RecommendedExfatUpcase, RecommendedExfatUpcaseError> {
    check_limits(limits)?;
    let bytes = decode_profile(limits)?;
    validate_recommended_exfat_upcase(&bytes, limits)
}

/// Independently validates exact caller-provided encoded bytes without using the generator.
///
/// The normative exFAT checksum is checked by the shared complete-table parser; SHA-256 narrows
/// acceptance to Microsoft Table 25 / exfatprogs' exact recommended byte sequence.
///
/// # Errors
///
/// Refuses invalid/insufficient limits, the wrong exact length or digest, malformed compression,
/// incomplete mappings, invalid mandatory ASCII mappings, or allocation failure.
pub fn validate_recommended_exfat_upcase(
    encoded: &[u8],
    limits: RecommendedExfatUpcaseLimits,
) -> Result<RecommendedExfatUpcase, RecommendedExfatUpcaseError> {
    check_limits(limits)?;
    if encoded.len() > limits.max_encoded_bytes {
        return Err(RecommendedExfatUpcaseError::Table(
            UpcaseError::EncodedTableTooLarge {
                actual: encoded.len(),
                maximum: limits.max_encoded_bytes,
            },
        ));
    }
    if encoded.len() != RECOMMENDED_EXFAT_UPCASE_BYTES {
        return Err(RecommendedExfatUpcaseError::IncorrectEncodedLength {
            actual: encoded.len(),
            expected: RECOMMENDED_EXFAT_UPCASE_BYTES,
        });
    }
    let actual_digest: [u8; 32] = Sha256::digest(encoded).into();
    if actual_digest != RECOMMENDED_EXFAT_UPCASE_SHA256 {
        return Err(RecommendedExfatUpcaseError::ProfileDigestMismatch {
            expected: RECOMMENDED_EXFAT_UPCASE_SHA256,
            actual: actual_digest,
        });
    }

    let table = UpcaseTable::parse(
        encoded,
        RECOMMENDED_EXFAT_UPCASE_CHECKSUM,
        UpcaseLimits {
            max_encoded_bytes: limits.max_encoded_bytes,
            max_mappings: limits.max_mappings,
        },
    )
    .map_err(RecommendedExfatUpcaseError::Table)?;
    let mut owned = Vec::new();
    owned.try_reserve_exact(encoded.len()).map_err(|_| {
        RecommendedExfatUpcaseError::AllocationFailed {
            component: "validated encoded table",
            requested: encoded.len(),
        }
    })?;
    owned.extend_from_slice(encoded);
    Ok(RecommendedExfatUpcase {
        encoded: owned.into_boxed_slice(),
        table,
    })
}

const fn check_limits(
    limits: RecommendedExfatUpcaseLimits,
) -> Result<(), RecommendedExfatUpcaseError> {
    if limits.max_encoded_bytes == 0 {
        return Err(RecommendedExfatUpcaseError::InvalidLimit {
            field: "max_encoded_bytes must be nonzero",
        });
    }
    if limits.max_mappings == 0 {
        return Err(RecommendedExfatUpcaseError::InvalidLimit {
            field: "max_mappings must be nonzero",
        });
    }
    if limits.max_name_units == 0 || limits.max_name_units > MAX_FILE_NAME_CODE_UNITS {
        return Err(RecommendedExfatUpcaseError::InvalidLimit {
            field: "max_name_units must be in 1..=255",
        });
    }
    Ok(())
}

fn check_name(
    name: &[u16],
    limits: RecommendedExfatUpcaseLimits,
) -> Result<(), RecommendedExfatUpcaseError> {
    check_limits(limits)?;
    if name.is_empty() {
        return Err(RecommendedExfatUpcaseError::Name(NameError::Empty));
    }
    if name.len() > limits.max_name_units {
        return Err(RecommendedExfatUpcaseError::Name(NameError::TooLong {
            actual: name.len(),
            maximum: limits.max_name_units,
        }));
    }
    Ok(())
}

fn decode_profile(
    limits: RecommendedExfatUpcaseLimits,
) -> Result<Vec<u8>, RecommendedExfatUpcaseError> {
    if RECOMMENDED_EXFAT_UPCASE_BYTES > limits.max_encoded_bytes {
        return Err(RecommendedExfatUpcaseError::Table(
            UpcaseError::EncodedTableTooLarge {
                actual: RECOMMENDED_EXFAT_UPCASE_BYTES,
                maximum: limits.max_encoded_bytes,
            },
        ));
    }
    decode_base64(PROFILE_BASE64, RECOMMENDED_EXFAT_UPCASE_BYTES)
}

fn decode_base64(
    encoded: &str,
    expected_bytes: usize,
) -> Result<Vec<u8>, RecommendedExfatUpcaseError> {
    // Base64 groups are four bytes; a bit mask is Rust 1.85-compatible.
    if encoded.len() & 3 != 0 {
        return Err(RecommendedExfatUpcaseError::CompiledProfileInvalid);
    }
    let mut output = Vec::new();
    output.try_reserve_exact(expected_bytes).map_err(|_| {
        RecommendedExfatUpcaseError::AllocationFailed {
            component: "embedded encoded table",
            requested: expected_bytes,
        }
    })?;
    let chunks = encoded.as_bytes().chunks_exact(4);
    let chunk_count = chunks.len();
    for (index, chunk) in chunks.enumerate() {
        let last = index + 1 == chunk_count;
        let a = base64_value(chunk[0])?;
        let b = base64_value(chunk[1])?;
        let c = if chunk[2] == b'=' {
            None
        } else {
            Some(base64_value(chunk[2])?)
        };
        let d = if chunk[3] == b'=' {
            None
        } else {
            Some(base64_value(chunk[3])?)
        };
        if (!last && (c.is_none() || d.is_none())) || (c.is_none() && d.is_some()) {
            return Err(RecommendedExfatUpcaseError::CompiledProfileInvalid);
        }
        output.push((a << 2) | (b >> 4));
        if let Some(c) = c {
            output.push((b << 4) | (c >> 2));
            if let Some(d) = d {
                output.push((c << 6) | d);
            }
        }
    }
    if output.len() != expected_bytes {
        return Err(RecommendedExfatUpcaseError::CompiledProfileInvalid);
    }
    Ok(output)
}

const fn base64_value(byte: u8) -> Result<u8, RecommendedExfatUpcaseError> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(RecommendedExfatUpcaseError::CompiledProfileInvalid),
    }
}

const PROFILE_BASE64: &str = concat!(
    "AAABAAIAAwAEAAUABgAHAAgACQAKAAsADAANAA4ADwAQABEAEgATABQAFQAWABcAGAAZABoAGwAcAB0AHgAfACAAIQAiACMA",
    "JAAlACYAJwAoACkAKgArACwALQAuAC8AMAAxADIAMwA0ADUANgA3ADgAOQA6ADsAPAA9AD4APwBAAEEAQgBDAEQARQBGAEcA",
    "SABJAEoASwBMAE0ATgBPAFAAUQBSAFMAVABVAFYAVwBYAFkAWgBbAFwAXQBeAF8AYABBAEIAQwBEAEUARgBHAEgASQBKAEsA",
    "TABNAE4ATwBQAFEAUgBTAFQAVQBWAFcAWABZAFoAewB8AH0AfgB/AIAAgQCCAIMAhACFAIYAhwCIAIkAigCLAIwAjQCOAI8A",
    "kACRAJIAkwCUAJUAlgCXAJgAmQCaAJsAnACdAJ4AnwCgAKEAogCjAKQApQCmAKcAqACpAKoAqwCsAK0ArgCvALAAsQCyALMA",
    "tAC1ALYAtwC4ALkAugC7ALwAvQC+AL8AwADBAMIAwwDEAMUAxgDHAMgAyQDKAMsAzADNAM4AzwDQANEA0gDTANQA1QDWANcA",
    "2ADZANoA2wDcAN0A3gDfAMAAwQDCAMMAxADFAMYAxwDIAMkAygDLAMwAzQDOAM8A0ADRANIA0wDUANUA1gD3ANgA2QDaANsA",
    "3ADdAN4AeAEAAQABAgECAQQBBAEGAQYBCAEIAQoBCgEMAQwBDgEOARABEAESARIBFAEUARYBFgEYARgBGgEaARwBHAEeAR4B",
    "IAEgASIBIgEkASQBJgEmASgBKAEqASoBLAEsAS4BLgEwATEBMgEyATQBNAE2ATYBOAE5ATkBOwE7AT0BPQE/AT8BQQFBAUMB",
    "QwFFAUUBRwFHAUkBSgFKAUwBTAFOAU4BUAFQAVIBUgFUAVQBVgFWAVgBWAFaAVoBXAFcAV4BXgFgAWABYgFiAWQBZAFmAWYB",
    "aAFoAWoBagFsAWwBbgFuAXABcAFyAXIBdAF0AXYBdgF4AXkBeQF7AXsBfQF9AX8BQwKBAYIBggGEAYQBhgGHAYcBiQGKAYsB",
    "iwGNAY4BjwGQAZEBkQGTAZQB9gGWAZcBmAGYAT0CmwGcAZ0BIAKfAaABoAGiAaIBpAGkAaYBpwGnAakBqgGrAawBrAGuAa8B",
    "rwGxAbIBswGzAbUBtQG3AbgBuAG6AbsBvAG8Ab4B9wHAAcEBwgHDAcQBxQHEAccByAHHAcoBywHKAc0BzQHPAc8B0QHRAdMB",
    "0wHVAdUB1wHXAdkB2QHbAdsBjgHeAd4B4AHgAeIB4gHkAeQB5gHmAegB6AHqAeoB7AHsAe4B7gHwAfEB8gHxAfQB9AH2AfcB",
    "+AH4AfoB+gH8AfwB/gH+AQACAAICAgICBAIEAgYCBgIIAggCCgIKAgwCDAIOAg4CEAIQAhICEgIUAhQCFgIWAhgCGAIaAhoC",
    "HAIcAh4CHgIgAiECIgIiAiQCJAImAiYCKAIoAioCKgIsAiwCLgIuAjACMAIyAjICNAI1AjYCNwI4AjkCZSw7AjsCPQJmLD8C",
    "QAJBAkECQwJEAkUCRgJGAkgCSAJKAkoCTAJMAk4CTgJQAlECUgKBAYYBVQKJAYoBWAKPAVoCkAFcAl0CXgJfApMBYQJiApQB",
    "ZAJlAmYCZwKXAZYBagJiLGwCbQJuApwBcAJxAp0BcwJ0Ap8BdgJ3AngCeQJ6AnsCfAJkLH4CfwKmAYECggKpAYQChQKGAocC",
    "rgFEArEBsgFFAo0CjgKPApACkQK3AZMClAKVApYClwKYApkCmgKbApwCnQKeAp8CoAKhAqICowKkAqUCpgKnAqgCqQKqAqsC",
    "rAKtAq4CrwKwArECsgKzArQCtQK2ArcCuAK5AroCuwK8Ar0CvgK/AsACwQLCAsMCxALFAsYCxwLIAskCygLLAswCzQLOAs8C",
    "0ALRAtIC0wLUAtUC1gLXAtgC2QLaAtsC3ALdAt4C3wLgAuEC4gLjAuQC5QLmAucC6ALpAuoC6wLsAu0C7gLvAvAC8QLyAvMC",
    "9AL1AvYC9wL4AvkC+gL7AvwC/QL+Av8CAAMBAwIDAwMEAwUDBgMHAwgDCQMKAwsDDAMNAw4DDwMQAxEDEgMTAxQDFQMWAxcD",
    "GAMZAxoDGwMcAx0DHgMfAyADIQMiAyMDJAMlAyYDJwMoAykDKgMrAywDLQMuAy8DMAMxAzIDMwM0AzUDNgM3AzgDOQM6AzsD",
    "PAM9Az4DPwNAA0EDQgNDA0QDRQNGA0cDSANJA0oDSwNMA00DTgNPA1ADUQNSA1MDVANVA1YDVwNYA1kDWgNbA1wDXQNeA18D",
    "YANhA2IDYwNkA2UDZgNnA2gDaQNqA2sDbANtA24DbwNwA3EDcgNzA3QDdQN2A3cDeAN5A3oD/QP+A/8DfgN/A4ADgQOCA4MD",
    "hAOFA4YDhwOIA4kDigOLA4wDjQOOA48DkAORA5IDkwOUA5UDlgOXA5gDmQOaA5sDnAOdA54DnwOgA6EDogOjA6QDpQOmA6cD",
    "qAOpA6oDqwOGA4gDiQOKA7ADkQOSA5MDlAOVA5YDlwOYA5kDmgObA5wDnQOeA58DoAOhA6MDowOkA6UDpgOnA6gDqQOqA6sD",
    "jAOOA48DzwPQA9ED0gPTA9QD1QPWA9cD2APYA9oD2gPcA9wD3gPeA+AD4APiA+ID5APkA+YD5gPoA+gD6gPqA+wD7APuA+4D",
    "8APxA/kD8wP0A/UD9gP3A/cD+QP6A/oD/AP9A/4D/wMABAEEAgQDBAQEBQQGBAcECAQJBAoECwQMBA0EDgQPBBAEEQQSBBME",
    "FAQVBBYEFwQYBBkEGgQbBBwEHQQeBB8EIAQhBCIEIwQkBCUEJgQnBCgEKQQqBCsELAQtBC4ELwQQBBEEEgQTBBQEFQQWBBcE",
    "GAQZBBoEGwQcBB0EHgQfBCAEIQQiBCMEJAQlBCYEJwQoBCkEKgQrBCwELQQuBC8EAAQBBAIEAwQEBAUEBgQHBAgECQQKBAsE",
    "DAQNBA4EDwRgBGAEYgRiBGQEZARmBGYEaARoBGoEagRsBGwEbgRuBHAEcARyBHIEdAR0BHYEdgR4BHgEegR6BHwEfAR+BH4E",
    "gASABIIEgwSEBIUEhgSHBIgEiQSKBIoEjASMBI4EjgSQBJAEkgSSBJQElASWBJYEmASYBJoEmgScBJwEngSeBKAEoASiBKIE",
    "pASkBKYEpgSoBKgEqgSqBKwErASuBK4EsASwBLIEsgS0BLQEtgS2BLgEuAS6BLoEvAS8BL4EvgTABMEEwQTDBMMExQTFBMcE",
    "xwTJBMkEywTLBM0EzQTABNAE0ATSBNIE1ATUBNYE1gTYBNgE2gTaBNwE3ATeBN4E4ATgBOIE4gTkBOQE5gTmBOgE6ATqBOoE",
    "7ATsBO4E7gTwBPAE8gTyBPQE9AT2BPYE+AT4BPoE+gT8BPwE/gT+BAAFAAUCBQIFBAUEBQYFBgUIBQgFCgUKBQwFDAUOBQ4F",
    "EAUQBRIFEgUUBRUFFgUXBRgFGQUaBRsFHAUdBR4FHwUgBSEFIgUjBSQFJQUmBScFKAUpBSoFKwUsBS0FLgUvBTAFMQUyBTMF",
    "NAU1BTYFNwU4BTkFOgU7BTwFPQU+BT8FQAVBBUIFQwVEBUUFRgVHBUgFSQVKBUsFTAVNBU4FTwVQBVEFUgVTBVQFVQVWBVcF",
    "WAVZBVoFWwVcBV0FXgVfBWAFMQUyBTMFNAU1BTYFNwU4BTkFOgU7BTwFPQU+BT8FQAVBBUIFQwVEBUUFRgVHBUgFSQVKBUsF",
    "TAVNBU4FTwVQBVEFUgVTBVQFVQVWBf//9hdjLH4dfx2AHYEdgh2DHYQdhR2GHYcdiB2JHYodix2MHY0djh2PHZAdkR2SHZMd",
    "lB2VHZYdlx2YHZkdmh2bHZwdnR2eHZ8doB2hHaIdox2kHaUdph2nHagdqR2qHasdrB2tHa4drx2wHbEdsh2zHbQdtR22Hbcd",
    "uB25Hbodux28Hb0dvh2/HcAdwR3CHcMdxB3FHcYdxx3IHckdyh3LHcwdzR3OHc8d0B3RHdId0x3UHdUd1h3XHdgd2R3aHdsd",
    "3B3dHd4d3x3gHeEd4h3jHeQd5R3mHecd6B3pHeod6x3sHe0d7h3vHfAd8R3yHfMd9B31HfYd9x34Hfkd+h37Hfwd/R3+Hf8d",
    "AB4AHgIeAh4EHgQeBh4GHggeCB4KHgoeDB4MHg4eDh4QHhAeEh4SHhQeFB4WHhYeGB4YHhoeGh4cHhweHh4eHiAeIB4iHiIe",
    "JB4kHiYeJh4oHigeKh4qHiweLB4uHi4eMB4wHjIeMh40HjQeNh42HjgeOB46HjoePB48Hj4ePh5AHkAeQh5CHkQeRB5GHkYe",
    "SB5IHkoeSh5MHkweTh5OHlAeUB5SHlIeVB5UHlYeVh5YHlgeWh5aHlweXB5eHl4eYB5gHmIeYh5kHmQeZh5mHmgeaB5qHmoe",
    "bB5sHm4ebh5wHnAech5yHnQedB52HnYeeB54Hnoeeh58Hnwefh5+HoAegB6CHoIehB6EHoYehh6IHogeih6KHowejB6OHo4e",
    "kB6QHpIekh6UHpQelh6XHpgemR6aHpsenB6dHp4enx6gHqAeoh6iHqQepB6mHqYeqB6oHqoeqh6sHqwerh6uHrAesB6yHrIe",
    "tB60HrYeth64Hrgeuh66HrwevB6+Hr4ewB7AHsIewh7EHsQexh7GHsgeyB7KHsoezB7MHs4ezh7QHtAe0h7SHtQe1B7WHtYe",
    "2B7YHtoe2h7cHtwe3h7eHuAe4B7iHuIe5B7kHuYe5h7oHuge6h7qHuwe7B7uHu4e8B7wHvIe8h70HvQe9h72Hvge+B76Hvse",
    "/B79Hv4e/x4IHwkfCh8LHwwfDR8OHw8fCB8JHwofCx8MHw0fDh8PHxgfGR8aHxsfHB8dHxYfFx8YHxkfGh8bHxwfHR8eHx8f",
    "KB8pHyofKx8sHy0fLh8vHygfKR8qHysfLB8tHy4fLx84HzkfOh87HzwfPR8+Hz8fOB85HzofOx88Hz0fPh8/H0gfSR9KH0sf",
    "TB9NH0YfRx9IH0kfSh9LH0wfTR9OH08fUB9ZH1IfWx9UH10fVh9fH1gfWR9aH1sfXB9dH14fXx9oH2kfah9rH2wfbR9uH28f",
    "aB9pH2ofax9sH20fbh9vH7ofux/IH8kfyh/LH9of2x/4H/kf6h/rH/of+x9+H38fiB+JH4ofix+MH40fjh+PH4gfiR+KH4sf",
    "jB+NH44fjx+YH5kfmh+bH5wfnR+eH58fmB+ZH5ofmx+cH50fnh+fH6gfqR+qH6sfrB+tH64frx+oH6kfqh+rH6wfrR+uH68f",
    "uB+5H7IfvB+0H7Ufth+3H7gfuR+6H7sfvB+9H74fvx/AH8Efwh/DH8QfxR/GH8cfyB/JH8ofyx/DH80fzh/PH9gf2R/SH9Mf",
    "1B/VH9Yf1x/YH9kf2h/bH9wf3R/eH98f6B/pH+If4x/kH+wf5h/nH+gf6R/qH+sf7B/tH+4f7x/wH/Ef8h/zH/Qf9R/2H/cf",
    "+B/5H/of+x/zH/0f/h//HwAgASACIAMgBCAFIAYgByAIIAkgCiALIAwgDSAOIA8gECARIBIgEyAUIBUgFiAXIBggGSAaIBsg",
    "HCAdIB4gHyAgICEgIiAjICQgJSAmICcgKCApICogKyAsIC0gLiAvIDAgMSAyIDMgNCA1IDYgNyA4IDkgOiA7IDwgPSA+ID8g",
    "QCBBIEIgQyBEIEUgRiBHIEggSSBKIEsgTCBNIE4gTyBQIFEgUiBTIFQgVSBWIFcgWCBZIFogWyBcIF0gXiBfIGAgYSBiIGMg",
    "ZCBlIGYgZyBoIGkgaiBrIGwgbSBuIG8gcCBxIHIgcyB0IHUgdiB3IHggeSB6IHsgfCB9IH4gfyCAIIEggiCDIIQghSCGIIcg",
    "iCCJIIogiyCMII0gjiCPIJAgkSCSIJMglCCVIJYglyCYIJkgmiCbIJwgnSCeIJ8goCChIKIgoyCkIKUgpiCnIKggqSCqIKsg",
    "rCCtIK4gryCwILEgsiCzILQgtSC2ILcguCC5ILoguyC8IL0gviC/IMAgwSDCIMMgxCDFIMYgxyDIIMkgyiDLIMwgzSDOIM8g",
    "0CDRINIg0yDUINUg1iDXINgg2SDaINsg3CDdIN4g3yDgIOEg4iDjIOQg5SDmIOcg6CDpIOog6yDsIO0g7iDvIPAg8SDyIPMg",
    "9CD1IPYg9yD4IPkg+iD7IPwg/SD+IP8gACEBIQIhAyEEIQUhBiEHIQghCSEKIQshDCENIQ4hDyEQIREhEiETIRQhFSEWIRch",
    "GCEZIRohGyEcIR0hHiEfISAhISEiISMhJCElISYhJyEoISkhKiErISwhLSEuIS8hMCExITIhMyE0ITUhNiE3ITghOSE6ITsh",
    "PCE9IT4hPyFAIUEhQiFDIUQhRSFGIUchSCFJIUohSyFMIU0hMiFPIVAhUSFSIVMhVCFVIVYhVyFYIVkhWiFbIVwhXSFeIV8h",
    "YCFhIWIhYyFkIWUhZiFnIWghaSFqIWshbCFtIW4hbyFgIWEhYiFjIWQhZSFmIWchaCFpIWohayFsIW0hbiFvIYAhgSGCIYMh",
    "gyH//0sDtiS3JLgkuSS6JLskvCS9JL4kvyTAJMEkwiTDJMQkxSTGJMckyCTJJMokyyTMJM0kziTPJP//RgcALAEsAiwDLAQs",
    "BSwGLAcsCCwJLAosCywMLA0sDiwPLBAsESwSLBMsFCwVLBYsFywYLBksGiwbLBwsHSweLB8sICwhLCIsIywkLCUsJiwnLCgs",
    "KSwqLCssLCwtLC4sXyxgLGAsYixjLGQsZSxmLGcsZyxpLGksayxrLG0sbixvLHAscSxyLHMsdCx1LHUsdyx4LHkseix7LHws",
    "fSx+LH8sgCyALIIsgiyELIQshiyGLIgsiCyKLIosjCyMLI4sjiyQLJAskiySLJQslCyWLJYsmCyYLJosmiycLJwsniyeLKAs",
    "oCyiLKIspCykLKYspiyoLKgsqiyqLKwsrCyuLK4ssCywLLIssiy0LLQstiy2LLgsuCy6LLosvCy8LL4svizALMAswizCLMQs",
    "xCzGLMYsyCzILMosyizMLMwszizOLNAs0CzSLNIs1CzULNYs1izYLNgs2izaLNws3CzeLN4s4CzgLOIs4izkLOUs5iznLOgs",
    "6SzqLOss7CztLO4s7yzwLPEs8izzLPQs9Sz2LPcs+Cz5LPos+yz8LP0s/iz/LKAQoRCiEKMQpBClEKYQpxCoEKkQqhCrEKwQ",
    "rRCuEK8QsBCxELIQsxC0ELUQthC3ELgQuRC6ELsQvBC9EL4QvxDAEMEQwhDDEMQQxRD//xvSIf8i/yP/JP8l/yb/J/8o/yn/",
    "Kv8r/yz/Lf8u/y//MP8x/zL/M/80/zX/Nv83/zj/Of86/1v/XP9d/17/X/9g/2H/Yv9j/2T/Zf9m/2f/aP9p/2r/a/9s/23/",
    "bv9v/3D/cf9y/3P/dP91/3b/d/94/3n/ev97/3z/ff9+/3//gP+B/4L/g/+E/4X/hv+H/4j/if+K/4v/jP+N/47/j/+Q/5H/",
    "kv+T/5T/lf+W/5f/mP+Z/5r/m/+c/53/nv+f/6D/of+i/6P/pP+l/6b/p/+o/6n/qv+r/6z/rf+u/6//sP+x/7L/s/+0/7X/",
    "tv+3/7j/uf+6/7v/vP+9/77/v//A/8H/wv/D/8T/xf/G/8f/yP/J/8r/y//M/83/zv/P/9D/0f/S/9P/1P/V/9b/1//Y/9n/",
    "2v/b/9z/3f/e/9//4P/h/+L/4//k/+X/5v/n/+j/6f/q/+v/7P/t/+7/7//w//H/8v/z//T/9f/2//f/+P/5//r/+//8//3/",
    "/v///w==",
);

#[cfg(test)]
mod tests {
    use super::super::exfat_upcase::table_checksum;
    use super::*;

    fn table() -> RecommendedExfatUpcase {
        generate_recommended_exfat_upcase(RecommendedExfatUpcaseLimits::default())
            .expect("recommended profile")
    }

    #[test]
    fn exact_profile_matches_spec_checksum_formatter_digest_and_length() {
        let table = table();
        assert_eq!(table.encoded_bytes().len(), RECOMMENDED_EXFAT_UPCASE_BYTES);
        assert_eq!(
            table_checksum(table.encoded_bytes()),
            RECOMMENDED_EXFAT_UPCASE_CHECKSUM
        );
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(table.encoded_bytes())),
            RECOMMENDED_EXFAT_UPCASE_SHA256
        );
        assert_eq!(table.mappings().len(), UNICODE_MAPPING_COUNT);
    }

    #[test]
    fn independent_validator_rejects_lengths_and_digest_mutation() {
        let canonical = table().encoded_bytes().to_vec();
        assert!(matches!(
            validate_recommended_exfat_upcase(
                &canonical[..canonical.len() - 2],
                RecommendedExfatUpcaseLimits::default()
            ),
            Err(RecommendedExfatUpcaseError::IncorrectEncodedLength { .. })
        ));
        let mut mutated = canonical;
        mutated[512] ^= 1;
        assert!(matches!(
            validate_recommended_exfat_upcase(&mutated, RecommendedExfatUpcaseLimits::default()),
            Err(RecommendedExfatUpcaseError::ProfileDigestMismatch { .. })
        ));
    }

    #[test]
    fn mappings_cover_legacy_non_ascii_and_utf16_code_unit_cases() {
        let table = table();
        assert_eq!(table.map(0x0061), 0x0041);
        assert_eq!(table.map(0x00df), 0x00df);
        assert_eq!(table.map(0x00ff), 0x0178);
        assert_eq!(table.map(0x0131), 0x0131);
        assert_eq!(table.map(0x017f), 0x017f);
        assert_eq!(table.map(0x0180), 0x0243);
        assert_eq!(table.map(0x0250), 0x0250);
        assert_eq!(table.map(0x0371), 0x0371);
        assert_eq!(table.map(0x03c2), 0x03a3);
        assert_eq!(table.map(0xd800), 0xd800);
        assert_eq!(table.map(0xff41), 0xff21);
        assert_eq!(table.map(0xffff), 0xffff);
    }

    #[test]
    fn non_ascii_case_pairs_collide_and_hash_identically() {
        let table = table();
        let limits = RecommendedExfatUpcaseLimits::default();
        let lower = [0x00ff, 0xff41];
        let upper = [0x0178, 0xff21];
        assert_eq!(table.names_collide(&lower, &upper, limits), Ok(true));
        assert_eq!(
            table.name_hash(&lower, limits),
            table.name_hash(&upper, limits)
        );
        assert_eq!(table.collate(&lower, &upper, limits), Ok(Ordering::Equal));
    }

    #[test]
    fn malformed_caps_and_names_fail_closed() {
        let byte_cap = RecommendedExfatUpcaseLimits {
            max_encoded_bytes: RECOMMENDED_EXFAT_UPCASE_BYTES - 1,
            ..RecommendedExfatUpcaseLimits::default()
        };
        assert!(matches!(
            generate_recommended_exfat_upcase(byte_cap),
            Err(RecommendedExfatUpcaseError::Table(
                UpcaseError::EncodedTableTooLarge { .. }
            ))
        ));

        let mapping_cap = RecommendedExfatUpcaseLimits {
            max_mappings: UNICODE_MAPPING_COUNT - 1,
            ..RecommendedExfatUpcaseLimits::default()
        };
        assert!(matches!(
            generate_recommended_exfat_upcase(mapping_cap),
            Err(RecommendedExfatUpcaseError::Table(
                UpcaseError::MappingLimitTooSmall { .. }
            ))
        ));

        let table = table();
        let name_cap = RecommendedExfatUpcaseLimits {
            max_name_units: 2,
            ..RecommendedExfatUpcaseLimits::default()
        };
        assert!(matches!(
            table.upcase_name(&[1, 2, 3], name_cap),
            Err(RecommendedExfatUpcaseError::Name(NameError::TooLong { .. }))
        ));
        assert!(matches!(
            table.collate(&[], &[1], name_cap),
            Err(RecommendedExfatUpcaseError::Name(NameError::Empty))
        ));
    }

    #[test]
    fn recommended_exfat_folds_a_windows61_ntfs_distinct_legal_name_pair() {
        use crate::fs::ntfs_upcase_serialize::{
            NtfsUpcaseLimits, generate_ntfs3g_windows61_upcase,
        };
        use crate::preservation::is_legal_exfat_name;
        let ntfs = generate_ntfs3g_windows61_upcase(NtfsUpcaseLimits::default()).unwrap();
        let exfat = table();
        let mut buckets: std::collections::BTreeMap<u16, Vec<u16>> =
            std::collections::BTreeMap::new();
        for unit in 0_u16..=u16::MAX {
            if (0xd800..=0xdfff).contains(&unit)
                || matches!(unit, 32 | 46)
                || !is_legal_exfat_name(&[unit])
            {
                continue;
            }
            buckets.entry(exfat.map(unit)).or_default().push(unit);
        }
        let mut pair = None;
        'search: for members in buckets.values() {
            for (index, left) in members.iter().enumerate() {
                for right in &members[index + 1..] {
                    if ntfs.lookup(*left) != ntfs.lookup(*right) {
                        pair = Some((*left, *right));
                        break 'search;
                    }
                }
            }
        }
        assert!(
            pair.is_some(),
            "expected at least one NTFS-distinct exFAT-colliding legal BMP pair"
        );
    }
}
