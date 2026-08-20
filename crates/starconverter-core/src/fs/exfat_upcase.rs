//! Bounded exFAT Up-case Table parsing and filename operations.
//!
//! The exFAT 1.00 specification requires an Up-case Table to cover every
//! UTF-16 code unit from `0x0000` through `0xFFFF`. On disk, identity mappings
//! may be compressed as `0xFFFF` followed by a run length. This module verifies
//! the on-disk checksum and the complete encoding before exposing any mapping.

#![allow(clippy::module_name_repetitions)]

use core::fmt;

/// Number of mappings in a complete exFAT Up-case Table.
pub const UNICODE_MAPPING_COUNT: usize = 65_536;
/// Maximum UTF-16 length of an exFAT filename.
pub const MAX_FILE_NAME_CODE_UNITS: usize = 255;

const COMPRESSION_MARKER: u16 = 0xFFFF;
const ASCII_LOWERCASE_START: usize = 0x61;
const ASCII_LOWERCASE_END: usize = 0x7A;
const ASCII_CASE_OFFSET: u16 = 0x20;

/// Caller-selected resource limits for parsing an Up-case Table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpcaseLimits {
    /// Maximum accepted size of the encoded table.
    pub max_encoded_bytes: usize,
    /// Maximum number of decompressed mappings the caller permits.
    pub max_mappings: usize,
}

impl UpcaseLimits {
    /// Limits sufficient for every valid exFAT Up-case Table.
    pub const COMPLETE_TABLE: Self = Self {
        max_encoded_bytes: UNICODE_MAPPING_COUNT * size_of::<u16>(),
        max_mappings: UNICODE_MAPPING_COUNT,
    };
}

/// A fully validated exFAT Up-case Table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpcaseTable {
    mappings: Box<[u16]>,
}

impl UpcaseTable {
    /// Parses a complete table after verifying its normative checksum.
    ///
    /// Allocation is fixed at exactly 65,536 `u16` mappings and occurs only
    /// after a no-allocation validation pass succeeds.
    ///
    /// # Errors
    ///
    /// Returns [`UpcaseError`] if a caller limit is exceeded, the checksum is
    /// wrong, the compressed form is malformed, the mandatory ASCII mappings
    /// differ from the specification, or allocation fails.
    pub fn parse(
        encoded: &[u8],
        expected_checksum: u32,
        limits: UpcaseLimits,
    ) -> Result<Self, UpcaseError> {
        validate_table(encoded, expected_checksum, limits)?;

        let mut mappings = Vec::new();
        mappings
            .try_reserve_exact(UNICODE_MAPPING_COUNT)
            .map_err(|_| UpcaseError::AllocationFailed {
                mappings: UNICODE_MAPPING_COUNT,
            })?;
        decode_valid_table(encoded, |_, mapping| mappings.push(mapping));
        debug_assert_eq!(mappings.len(), UNICODE_MAPPING_COUNT);
        Ok(Self {
            mappings: mappings.into_boxed_slice(),
        })
    }

    /// Returns the mapping for one UTF-16 code unit.
    #[must_use]
    pub fn map(&self, code_unit: u16) -> u16 {
        self.mappings[usize::from(code_unit)]
    }

    /// Returns all 65,536 mappings in code-unit order.
    #[must_use]
    pub const fn mappings(&self) -> &[u16] {
        &self.mappings
    }

    /// Up-cases an exFAT filename into caller-owned storage.
    ///
    /// `max_code_units` is an explicit caller work limit and cannot exceed the
    /// format maximum of 255. The input and output may not overlap in safe Rust.
    ///
    /// # Errors
    ///
    /// Returns [`NameError`] for an empty or over-limit name, an invalid caller
    /// limit, or insufficient output storage.
    pub fn upcase_name_into(
        &self,
        name: &[u16],
        output: &mut [u16],
        max_code_units: usize,
    ) -> Result<usize, NameError> {
        validate_name(name, max_code_units)?;
        if output.len() < name.len() {
            return Err(NameError::OutputTooSmall {
                required: name.len(),
                actual: output.len(),
            });
        }
        for (destination, &code_unit) in output.iter_mut().zip(name) {
            *destination = self.map(code_unit);
        }
        Ok(name.len())
    }

    /// Computes the normative exFAT `NameHash` of an up-cased filename.
    ///
    /// Each mapped UTF-16 code unit is hashed as its little-endian on-disk
    /// bytes. No temporary name buffer is allocated.
    ///
    /// # Errors
    ///
    /// Returns [`NameError`] when the name or caller limit is invalid.
    pub fn name_hash(&self, name: &[u16], max_code_units: usize) -> Result<u16, NameError> {
        validate_name(name, max_code_units)?;
        let mut hash = 0_u16;
        for &code_unit in name {
            for byte in self.map(code_unit).to_le_bytes() {
                hash = hash.rotate_right(1).wrapping_add(u16::from(byte));
            }
        }
        Ok(hash)
    }

    /// Finds the first pair of names equal after exFAT up-casing.
    ///
    /// This allocation-free routine is intentionally quadratic. Both the name
    /// count and pair-comparison count are explicitly bounded by the caller.
    /// Hash matches are always confirmed with a full up-cased comparison.
    ///
    /// # Errors
    ///
    /// Returns [`DuplicateError`] if a cap is invalid or exceeded, a name is
    /// invalid, or the comparison budget cannot cover the supplied names.
    pub fn find_duplicate_names(
        &self,
        names: &[&[u16]],
        limits: DuplicateLimits,
    ) -> Result<Option<DuplicateName>, DuplicateError> {
        if limits.max_name_code_units > MAX_FILE_NAME_CODE_UNITS {
            return Err(DuplicateError::InvalidNameLimit {
                requested: limits.max_name_code_units,
                maximum: MAX_FILE_NAME_CODE_UNITS,
            });
        }
        if names.len() > limits.max_names {
            return Err(DuplicateError::TooManyNames {
                actual: names.len(),
                maximum: limits.max_names,
            });
        }

        for (index, name) in names.iter().enumerate() {
            validate_name(name, limits.max_name_code_units)
                .map_err(|source| DuplicateError::InvalidName { index, source })?;
        }

        let mut comparisons = 0_usize;
        for second in 1..names.len() {
            let second_hash = self
                .name_hash(names[second], limits.max_name_code_units)
                .map_err(|source| DuplicateError::InvalidName {
                    index: second,
                    source,
                })?;
            for first in 0..second {
                comparisons =
                    comparisons
                        .checked_add(1)
                        .ok_or(DuplicateError::ComparisonLimitExceeded {
                            required_at_least: usize::MAX,
                            maximum: limits.max_comparisons,
                        })?;
                if comparisons > limits.max_comparisons {
                    return Err(DuplicateError::ComparisonLimitExceeded {
                        required_at_least: comparisons,
                        maximum: limits.max_comparisons,
                    });
                }
                let first_hash = self
                    .name_hash(names[first], limits.max_name_code_units)
                    .map_err(|source| DuplicateError::InvalidName {
                        index: first,
                        source,
                    })?;
                if first_hash == second_hash
                    && names[first].len() == names[second].len()
                    && names[first]
                        .iter()
                        .zip(names[second])
                        .all(|(&left, &right)| self.map(left) == self.map(right))
                {
                    return Ok(Some(DuplicateName {
                        first_index: first,
                        second_index: second,
                        name_hash: first_hash,
                    }));
                }
            }
        }
        Ok(None)
    }
}

/// Explicit work limits for duplicate-name detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DuplicateLimits {
    pub max_names: usize,
    pub max_name_code_units: usize,
    pub max_comparisons: usize,
}

/// A confirmed case-insensitive duplicate pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DuplicateName {
    pub first_index: usize,
    pub second_index: usize,
    pub name_hash: u16,
}

/// An Up-case Table validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpcaseError {
    EncodedTableTooLarge {
        actual: usize,
        maximum: usize,
    },
    MappingLimitTooSmall {
        required: usize,
        maximum: usize,
    },
    EmptyTable,
    OddByteLength {
        actual: usize,
    },
    ChecksumMismatch {
        expected: u32,
        actual: u32,
    },
    DanglingCompressionMarker {
        mapping_index: usize,
    },
    ZeroIdentityRun {
        mapping_index: usize,
    },
    IdentityRunOverflow {
        mapping_index: usize,
        run_length: usize,
    },
    ExtraMapping {
        encoded_word_index: usize,
    },
    IncompleteTable {
        mappings: usize,
        required: usize,
    },
    InvalidMandatoryMapping {
        code_unit: u16,
        expected: u16,
        actual: u16,
    },
    AllocationFailed {
        mappings: usize,
    },
}

impl fmt::Display for UpcaseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EncodedTableTooLarge { actual, maximum } => write!(
                formatter,
                "encoded exFAT Up-case Table is {actual} bytes; caller limit is {maximum}"
            ),
            Self::MappingLimitTooSmall { required, maximum } => write!(
                formatter,
                "complete exFAT Up-case Table requires {required} mappings; caller limit is {maximum}"
            ),
            Self::EmptyTable => formatter.write_str("exFAT Up-case Table is empty"),
            Self::OddByteLength { actual } => write!(
                formatter,
                "exFAT Up-case Table length {actual} is not a whole number of UTF-16 words"
            ),
            Self::ChecksumMismatch { expected, actual } => write!(
                formatter,
                "exFAT Up-case Table checksum is {actual:#010X}; expected {expected:#010X}"
            ),
            Self::DanglingCompressionMarker { mapping_index } => write!(
                formatter,
                "exFAT Up-case Table compression marker at mapping {mapping_index:#06X} has no run length"
            ),
            Self::ZeroIdentityRun { mapping_index } => write!(
                formatter,
                "exFAT Up-case Table has a zero-length identity run at mapping {mapping_index:#06X}"
            ),
            Self::IdentityRunOverflow {
                mapping_index,
                run_length,
            } => write!(
                formatter,
                "exFAT Up-case Table identity run of {run_length} at mapping {mapping_index:#06X} exceeds U+FFFF"
            ),
            Self::ExtraMapping { encoded_word_index } => write!(
                formatter,
                "exFAT Up-case Table has data after U+FFFF at encoded word {encoded_word_index}"
            ),
            Self::IncompleteTable { mappings, required } => write!(
                formatter,
                "exFAT Up-case Table defines {mappings} mappings; {required} are required"
            ),
            Self::InvalidMandatoryMapping {
                code_unit,
                expected,
                actual,
            } => write!(
                formatter,
                "mandatory exFAT mapping for U+{code_unit:04X} is U+{actual:04X}; expected U+{expected:04X}"
            ),
            Self::AllocationFailed { mappings } => write!(
                formatter,
                "could not allocate storage for {mappings} exFAT Up-case Table mappings"
            ),
        }
    }
}

impl std::error::Error for UpcaseError {}

/// An invalid filename or filename-work limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameError {
    Empty,
    InvalidLimit { requested: usize, maximum: usize },
    TooLong { actual: usize, maximum: usize },
    OutputTooSmall { required: usize, actual: usize },
}

impl fmt::Display for NameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("exFAT filename is empty"),
            Self::InvalidLimit { requested, maximum } => write!(
                formatter,
                "exFAT filename limit {requested} exceeds format maximum {maximum}"
            ),
            Self::TooLong { actual, maximum } => write!(
                formatter,
                "exFAT filename contains {actual} UTF-16 code units; maximum is {maximum}"
            ),
            Self::OutputTooSmall { required, actual } => write!(
                formatter,
                "up-cased filename output has {actual} slots; {required} are required"
            ),
        }
    }
}

impl std::error::Error for NameError {}

/// A bounded duplicate-name scan failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DuplicateError {
    InvalidNameLimit {
        requested: usize,
        maximum: usize,
    },
    TooManyNames {
        actual: usize,
        maximum: usize,
    },
    InvalidName {
        index: usize,
        source: NameError,
    },
    ComparisonLimitExceeded {
        required_at_least: usize,
        maximum: usize,
    },
}

impl fmt::Display for DuplicateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidNameLimit { requested, maximum } => write!(
                formatter,
                "duplicate scan filename limit {requested} exceeds exFAT maximum {maximum}"
            ),
            Self::TooManyNames { actual, maximum } => write!(
                formatter,
                "duplicate scan received {actual} names; caller limit is {maximum}"
            ),
            Self::InvalidName { index, source } => {
                write!(
                    formatter,
                    "invalid exFAT filename at index {index}: {source}"
                )
            }
            Self::ComparisonLimitExceeded {
                required_at_least,
                maximum,
            } => write!(
                formatter,
                "duplicate scan needs at least {required_at_least} comparisons; caller limit is {maximum}"
            ),
        }
    }
}

impl std::error::Error for DuplicateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidName { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Computes the exFAT Up-case Table checksum over its exact on-disk bytes.
#[must_use]
pub fn table_checksum(encoded: &[u8]) -> u32 {
    encoded.iter().fold(0_u32, |checksum, &byte| {
        checksum.rotate_right(1).wrapping_add(u32::from(byte))
    })
}

/// Validates and visits every mapping without allocating a decompressed table.
///
/// The callback is not invoked unless checksum and structural validation have
/// both completed successfully. It receives mappings in ascending code-unit
/// order, exactly 65,536 times.
///
/// # Errors
///
/// Returns [`UpcaseError`] under the same conditions as [`UpcaseTable::parse`],
/// except allocation cannot fail.
pub fn visit_mappings(
    encoded: &[u8],
    expected_checksum: u32,
    limits: UpcaseLimits,
    visitor: impl FnMut(u16, u16),
) -> Result<(), UpcaseError> {
    validate_table(encoded, expected_checksum, limits)?;
    decode_valid_table(encoded, visitor);
    Ok(())
}

fn validate_table(
    encoded: &[u8],
    expected_checksum: u32,
    limits: UpcaseLimits,
) -> Result<(), UpcaseError> {
    if encoded.len() > limits.max_encoded_bytes {
        return Err(UpcaseError::EncodedTableTooLarge {
            actual: encoded.len(),
            maximum: limits.max_encoded_bytes,
        });
    }
    if limits.max_mappings < UNICODE_MAPPING_COUNT {
        return Err(UpcaseError::MappingLimitTooSmall {
            required: UNICODE_MAPPING_COUNT,
            maximum: limits.max_mappings,
        });
    }
    if encoded.is_empty() {
        return Err(UpcaseError::EmptyTable);
    }
    if encoded.len() % size_of::<u16>() != 0 {
        return Err(UpcaseError::OddByteLength {
            actual: encoded.len(),
        });
    }
    let actual_checksum = table_checksum(encoded);
    if actual_checksum != expected_checksum {
        return Err(UpcaseError::ChecksumMismatch {
            expected: expected_checksum,
            actual: actual_checksum,
        });
    }
    validate_encoding(encoded)
}

fn validate_encoding(encoded: &[u8]) -> Result<(), UpcaseError> {
    let mut mapping_index = 0_usize;
    let mut word_index = 0_usize;
    while word_index < encoded.len() / 2 {
        if mapping_index == UNICODE_MAPPING_COUNT {
            return Err(UpcaseError::ExtraMapping {
                encoded_word_index: word_index,
            });
        }
        let word = encoded_word(encoded, word_index);
        word_index += 1;

        // In a fully uncompressed table, its final identity mapping is itself
        // 0xFFFF. At this sole position, a final marker-sized word is therefore
        // unambiguously the literal U+FFFF mapping.
        if word == COMPRESSION_MARKER
            && !(mapping_index == UNICODE_MAPPING_COUNT - 1 && word_index == encoded.len() / 2)
        {
            if word_index == encoded.len() / 2 {
                return Err(UpcaseError::DanglingCompressionMarker { mapping_index });
            }
            let run_length = usize::from(encoded_word(encoded, word_index));
            word_index += 1;
            if run_length == 0 {
                return Err(UpcaseError::ZeroIdentityRun { mapping_index });
            }
            let run_end =
                mapping_index
                    .checked_add(run_length)
                    .ok_or(UpcaseError::IdentityRunOverflow {
                        mapping_index,
                        run_length,
                    })?;
            if run_end > UNICODE_MAPPING_COUNT {
                return Err(UpcaseError::IdentityRunOverflow {
                    mapping_index,
                    run_length,
                });
            }
            for index in mapping_index..run_end.min(128) {
                validate_mandatory(index, mapping_code_unit(index))?;
            }
            mapping_index = run_end;
        } else {
            validate_mandatory(mapping_index, word)?;
            mapping_index += 1;
        }
    }
    if mapping_index != UNICODE_MAPPING_COUNT {
        return Err(UpcaseError::IncompleteTable {
            mappings: mapping_index,
            required: UNICODE_MAPPING_COUNT,
        });
    }
    Ok(())
}

fn decode_valid_table(encoded: &[u8], mut visitor: impl FnMut(u16, u16)) {
    let mut mapping_index = 0_usize;
    let mut word_index = 0_usize;
    while word_index < encoded.len() / 2 {
        let word = encoded_word(encoded, word_index);
        word_index += 1;
        if word == COMPRESSION_MARKER
            && !(mapping_index == UNICODE_MAPPING_COUNT - 1 && word_index == encoded.len() / 2)
        {
            let run_length = usize::from(encoded_word(encoded, word_index));
            word_index += 1;
            let run_end = mapping_index + run_length;
            while mapping_index < run_end {
                let code_unit = mapping_code_unit(mapping_index);
                visitor(code_unit, code_unit);
                mapping_index += 1;
            }
        } else {
            visitor(mapping_code_unit(mapping_index), word);
            mapping_index += 1;
        }
    }
    debug_assert_eq!(mapping_index, UNICODE_MAPPING_COUNT);
}

fn validate_mandatory(index: usize, actual: u16) -> Result<(), UpcaseError> {
    if index >= 128 {
        return Ok(());
    }
    let code_unit = mapping_code_unit(index);
    let expected = if (ASCII_LOWERCASE_START..=ASCII_LOWERCASE_END).contains(&index) {
        code_unit - ASCII_CASE_OFFSET
    } else {
        code_unit
    };
    if actual != expected {
        return Err(UpcaseError::InvalidMandatoryMapping {
            code_unit,
            expected,
            actual,
        });
    }
    Ok(())
}

const fn validate_name(name: &[u16], max_code_units: usize) -> Result<(), NameError> {
    if max_code_units > MAX_FILE_NAME_CODE_UNITS {
        return Err(NameError::InvalidLimit {
            requested: max_code_units,
            maximum: MAX_FILE_NAME_CODE_UNITS,
        });
    }
    if name.is_empty() {
        return Err(NameError::Empty);
    }
    if name.len() > max_code_units {
        return Err(NameError::TooLong {
            actual: name.len(),
            maximum: max_code_units,
        });
    }
    Ok(())
}

// Every caller has already bounded the index to the complete BMP table. This
// cannot be const until `TryFrom` is a stable const trait on the MSRV.
#[allow(clippy::missing_const_for_fn)]
fn mapping_code_unit(index: usize) -> u16 {
    u16::try_from(index).unwrap_or_else(|_| unreachable!())
}

const fn encoded_word(encoded: &[u8], word_index: usize) -> u16 {
    let offset = word_index * 2;
    u16::from_le_bytes([encoded[offset], encoded[offset + 1]])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_word(encoded: &mut Vec<u8>, word: u16) {
        encoded.extend_from_slice(&word.to_le_bytes());
    }

    fn compressed_ascii_table() -> Vec<u8> {
        let mut encoded = Vec::new();
        for code_unit in 0_u16..128 {
            let mapping = if (u16::from(b'a')..=u16::from(b'z')).contains(&code_unit) {
                code_unit - ASCII_CASE_OFFSET
            } else {
                code_unit
            };
            push_word(&mut encoded, mapping);
        }
        push_word(&mut encoded, COMPRESSION_MARKER);
        push_word(&mut encoded, 65_408);
        encoded
    }

    fn parse_test_table() -> UpcaseTable {
        let encoded = compressed_ascii_table();
        UpcaseTable::parse(
            &encoded,
            table_checksum(&encoded),
            UpcaseLimits::COMPLETE_TABLE,
        )
        .expect("valid compressed test table")
    }

    #[test]
    fn parses_compressed_table_and_visits_full_range() {
        let encoded = compressed_ascii_table();
        let table = parse_test_table();
        assert_eq!(table.mappings().len(), UNICODE_MAPPING_COUNT);
        assert_eq!(table.map(b'a'.into()), u16::from(b'A'));
        assert_eq!(table.map(0x0080), 0x0080);
        assert_eq!(table.map(0xFFFF), 0xFFFF);

        let mut count = 0_usize;
        let mut last = None;
        visit_mappings(
            &encoded,
            table_checksum(&encoded),
            UpcaseLimits::COMPLETE_TABLE,
            |index, mapping| {
                count += 1;
                last = Some((index, mapping));
            },
        )
        .expect("visit valid table");
        assert_eq!(count, UNICODE_MAPPING_COUNT);
        assert_eq!(last, Some((0xFFFF, 0xFFFF)));
    }

    #[test]
    fn parses_fully_uncompressed_table_with_final_ffff_literal() {
        let mut encoded = Vec::with_capacity(UNICODE_MAPPING_COUNT * 2);
        for code_unit in 0_u16..=u16::MAX {
            let mapping = if (u16::from(b'a')..=u16::from(b'z')).contains(&code_unit) {
                code_unit - ASCII_CASE_OFFSET
            } else {
                code_unit
            };
            push_word(&mut encoded, mapping);
        }
        let table = UpcaseTable::parse(
            &encoded,
            table_checksum(&encoded),
            UpcaseLimits::COMPLETE_TABLE,
        )
        .expect("valid uncompressed table");
        assert_eq!(table.map(0xFFFF), 0xFFFF);
    }

    #[test]
    fn checksum_matches_normative_rotate_and_add() {
        let bytes = [0x01, 0x02, 0x03, 0x04];
        let expected = 0_u32
            .rotate_right(1)
            .wrapping_add(1)
            .rotate_right(1)
            .wrapping_add(2)
            .rotate_right(1)
            .wrapping_add(3)
            .rotate_right(1)
            .wrapping_add(4);
        assert_eq!(table_checksum(&bytes), expected);
    }

    #[test]
    fn rejects_bad_checksum_before_visiting() {
        let encoded = compressed_ascii_table();
        let mut calls = 0;
        let error = visit_mappings(
            &encoded,
            table_checksum(&encoded).wrapping_add(1),
            UpcaseLimits::COMPLETE_TABLE,
            |_, _| calls += 1,
        )
        .expect_err("checksum mismatch");
        assert!(matches!(error, UpcaseError::ChecksumMismatch { .. }));
        assert_eq!(calls, 0);
    }

    #[test]
    fn rejects_resource_limit_empty_and_odd_tables() {
        let encoded = compressed_ascii_table();
        assert!(matches!(
            UpcaseTable::parse(
                &encoded,
                table_checksum(&encoded),
                UpcaseLimits {
                    max_encoded_bytes: encoded.len() - 1,
                    max_mappings: UNICODE_MAPPING_COUNT,
                }
            ),
            Err(UpcaseError::EncodedTableTooLarge { .. })
        ));
        assert!(matches!(
            UpcaseTable::parse(
                &encoded,
                table_checksum(&encoded),
                UpcaseLimits {
                    max_encoded_bytes: encoded.len(),
                    max_mappings: UNICODE_MAPPING_COUNT - 1,
                }
            ),
            Err(UpcaseError::MappingLimitTooSmall { .. })
        ));
        assert_eq!(
            UpcaseTable::parse(&[], 0, UpcaseLimits::COMPLETE_TABLE),
            Err(UpcaseError::EmptyTable)
        );
        assert_eq!(
            UpcaseTable::parse(&[0], 0, UpcaseLimits::COMPLETE_TABLE),
            Err(UpcaseError::OddByteLength { actual: 1 })
        );
    }

    #[test]
    fn rejects_dangling_zero_and_overflowing_identity_runs() {
        let mut dangling = Vec::new();
        push_word(&mut dangling, COMPRESSION_MARKER);
        let checksum = table_checksum(&dangling);
        assert_eq!(
            UpcaseTable::parse(&dangling, checksum, UpcaseLimits::COMPLETE_TABLE),
            Err(UpcaseError::DanglingCompressionMarker { mapping_index: 0 })
        );

        let mut zero = Vec::new();
        push_word(&mut zero, COMPRESSION_MARKER);
        push_word(&mut zero, 0);
        let checksum = table_checksum(&zero);
        assert_eq!(
            UpcaseTable::parse(&zero, checksum, UpcaseLimits::COMPLETE_TABLE),
            Err(UpcaseError::ZeroIdentityRun { mapping_index: 0 })
        );

        let mut overflow = compressed_ascii_table();
        let last = overflow.len();
        overflow[last - 2..].copy_from_slice(&u16::MAX.to_le_bytes());
        let checksum = table_checksum(&overflow);
        assert!(matches!(
            UpcaseTable::parse(&overflow, checksum, UpcaseLimits::COMPLETE_TABLE),
            Err(UpcaseError::IdentityRunOverflow { .. })
        ));
    }

    #[test]
    fn rejects_incomplete_extra_and_invalid_ascii_tables() {
        let mut incomplete = compressed_ascii_table();
        let run = 65_407_u16;
        let end = incomplete.len();
        incomplete[end - 2..].copy_from_slice(&run.to_le_bytes());
        let checksum = table_checksum(&incomplete);
        assert!(matches!(
            UpcaseTable::parse(&incomplete, checksum, UpcaseLimits::COMPLETE_TABLE),
            Err(UpcaseError::IncompleteTable { .. })
        ));

        let mut extra = compressed_ascii_table();
        push_word(&mut extra, 0);
        let checksum = table_checksum(&extra);
        assert!(matches!(
            UpcaseTable::parse(&extra, checksum, UpcaseLimits::COMPLETE_TABLE),
            Err(UpcaseError::ExtraMapping { .. })
        ));

        let mut bad_ascii = compressed_ascii_table();
        bad_ascii[usize::from(b'a') * 2..usize::from(b'a') * 2 + 2]
            .copy_from_slice(&(u16::from(b'a')).to_le_bytes());
        let checksum = table_checksum(&bad_ascii);
        assert_eq!(
            UpcaseTable::parse(&bad_ascii, checksum, UpcaseLimits::COMPLETE_TABLE),
            Err(UpcaseError::InvalidMandatoryMapping {
                code_unit: u16::from(b'a'),
                expected: u16::from(b'A'),
                actual: u16::from(b'a'),
            })
        );
    }

    #[test]
    fn upcases_names_and_computes_little_endian_name_hash() {
        let table = parse_test_table();
        let name = [u16::from(b'a'), u16::from(b'Z'), 0x1234];
        let mut output = [0_u16; 3];
        assert_eq!(table.upcase_name_into(&name, &mut output, 3), Ok(3));
        assert_eq!(output, [u16::from(b'A'), u16::from(b'Z'), 0x1234]);

        let mut expected = 0_u16;
        for byte in output.into_iter().flat_map(u16::to_le_bytes) {
            expected = expected.rotate_right(1).wrapping_add(u16::from(byte));
        }
        assert_eq!(table.name_hash(&name, 3), Ok(expected));
    }

    #[test]
    fn enforces_name_and_output_limits() {
        let table = parse_test_table();
        assert_eq!(table.name_hash(&[], 255), Err(NameError::Empty));
        assert!(matches!(
            table.name_hash(&[1], 256),
            Err(NameError::InvalidLimit { .. })
        ));
        assert_eq!(
            table.name_hash(&[1, 2], 1),
            Err(NameError::TooLong {
                actual: 2,
                maximum: 1
            })
        );
        assert_eq!(
            table.upcase_name_into(&[1, 2], &mut [0], 2),
            Err(NameError::OutputTooSmall {
                required: 2,
                actual: 1
            })
        );
    }

    #[test]
    fn detects_case_insensitive_duplicates_and_confirms_hashes() {
        let table = parse_test_table();
        let first = [u16::from(b'R'), u16::from(b'e'), u16::from(b'a')];
        let second = [u16::from(b'r'), u16::from(b'E'), u16::from(b'A')];
        let distinct = [u16::from(b'x')];
        let limits = DuplicateLimits {
            max_names: 3,
            max_name_code_units: 255,
            max_comparisons: 3,
        };
        assert_eq!(
            table.find_duplicate_names(&[&first, &distinct, &second], limits),
            Ok(Some(DuplicateName {
                first_index: 0,
                second_index: 2,
                name_hash: table.name_hash(&first, 255).expect("valid name"),
            }))
        );
        assert_eq!(
            table.find_duplicate_names(&[&first, &distinct], limits),
            Ok(None)
        );
    }

    #[test]
    fn bounds_duplicate_scan_names_comparisons_and_name_lengths() {
        let table = parse_test_table();
        let one = [1_u16];
        let two = [2_u16];
        let three = [3_u16];
        assert!(matches!(
            table.find_duplicate_names(
                &[&one, &two],
                DuplicateLimits {
                    max_names: 1,
                    max_name_code_units: 255,
                    max_comparisons: 1,
                }
            ),
            Err(DuplicateError::TooManyNames { .. })
        ));
        assert!(matches!(
            table.find_duplicate_names(
                &[&one, &two, &three],
                DuplicateLimits {
                    max_names: 3,
                    max_name_code_units: 255,
                    max_comparisons: 1,
                }
            ),
            Err(DuplicateError::ComparisonLimitExceeded { .. })
        ));
        assert!(matches!(
            table.find_duplicate_names(
                &[&one],
                DuplicateLimits {
                    max_names: 1,
                    max_name_code_units: 0,
                    max_comparisons: 0,
                }
            ),
            Err(DuplicateError::InvalidName { .. })
        ));
    }
}
