//! Pure, bounded construction and independent validation of the narrow NTFS-3G `$Extend`
//! profile.
//!
//! This module deliberately does **not** build FILE records, resident attribute wrappers, or the
//! `$Extend:$I30` directory entries. It provides the exact default quota index-entry payloads,
//! empty child-index payloads, and typed record/index requirements supported by the pinned
//! formatter evidence. A serializer can consume those pieces, but it cannot treat them as write
//! authorization.
//!
//! Provenance and compatibility boundary:
//!
//! - Microsoft identifies `$Extend` as a directory and reserves `$Extend\$ObjId`, `$Quota`, and
//!   `$Reparse`; its defragmentation documentation identifies their `$O`, `$Q`, and `$R` index
//!   streams. Microsoft does not publish the complete on-disk `FILE/INDEX_ROOT` bootstrap bytes.
//! - Exact record numbers, flags, collation rules, quota entries, and the resident `$I30`
//!   requirement come from NTFS-3G commit
//!   `d327833ec1d5eb1358b6f2c37139f10a3460944d`: `ntfsprogs/mkntfs.c` lines
//!   2919-3006 and 4862-4970, plus `include/ntfs-3g/layout.h` lines 238-270,
//!   533-574, and 2178-2280.
//! - The pinned formatter itself marks case-insensitive handling of these indexes as FIXME and
//!   describes the resident `$I30` rule as empirical Windows Server 2003 behavior. Those facts,
//!   its omission of `$UsnJrnl`, and modern `$RmMetadata` variants are explicit activation gaps.
//!
//! There is no path, device, or I/O API in this module. All allocations are fixed-size and checked
//! against caller-provided limits first. Validation parses fields and relationships independently;
//! it never validates by regenerating and comparing output.

use std::fmt;

const INDEX_ENTRY_HEADER_BYTES: usize = 16;
const INDEX_ENTRY_END: u16 = 0x0002;
const Q_DEFAULTS_ENTRY_BYTES: usize = 0x48;
const Q_ADMINISTRATORS_ENTRY_BYTES: usize = 0x58;
const O_ADMINISTRATORS_ENTRY_BYTES: usize = 0x28;
const Q_INDEX_BYTES: usize =
    Q_DEFAULTS_ENTRY_BYTES + Q_ADMINISTRATORS_ENTRY_BYTES + INDEX_ENTRY_HEADER_BYTES;
const O_INDEX_BYTES: usize = O_ADMINISTRATORS_ENTRY_BYTES + INDEX_ENTRY_HEADER_BYTES;
const EMPTY_INDEX_BYTES: usize = INDEX_ENTRY_HEADER_BYTES;
const ALL_INDEX_BYTES: usize = Q_INDEX_BYTES + O_INDEX_BYTES + 2 * EMPTY_INDEX_BYTES;

const QUOTA_DEFAULTS_ID: u32 = 1;
const QUOTA_FIRST_USER_ID: u32 = 0x100;
const QUOTA_ENTRY_VERSION: u32 = 2;
const QUOTA_FLAG_DEFAULT_LIMITS: u32 = 1;
const SECURITY_BUILTIN_DOMAIN_RID: u32 = 0x20;
const DOMAIN_ALIAS_RID_ADMINS: u32 = 0x220;

/// `$Extend:$I30` uses filename collation.
pub const COLLATION_FILE_NAME: u32 = 1;
/// `$Quota:$Q` uses ascending little-endian `u32` collation.
pub const COLLATION_NTOFS_ULONG: u32 = 16;
/// `$Quota:$O` uses SID collation.
pub const COLLATION_NTOFS_SID: u32 = 17;
/// `$ObjId:$O` and `$Reparse:$R` use sequences of little-endian `u32` values.
pub const COLLATION_NTOFS_ULONGS: u32 = 19;

/// Attribute type indexed by `$Extend:$I30`.
pub const ATTRIBUTE_TYPE_FILE_NAME: u32 = 0x30;
/// The special value used by the three view indexes in the pinned formatter.
pub const ATTRIBUTE_TYPE_UNUSED: u32 = 0;

/// The only profile for which this module has exact formatter evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtfsExtendProfile {
    /// NTFS 3.1 metadata emitted by the pinned NTFS-3G `mkntfs` implementation.
    MkntfsNtfs31,
    /// Reserved so a caller must explicitly confront the lack of modern-native evidence.
    ModernWindowsNative,
}

/// Caller-controlled output bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtfsExtendLimits {
    pub max_index_bytes: usize,
    pub max_children: usize,
}

impl Default for NtfsExtendLimits {
    fn default() -> Self {
        Self {
            max_index_bytes: 4 * 1024,
            max_children: 8,
        }
    }
}

/// The two time values that the pinned formatter obtains independently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotaChangeTimes {
    /// NTFS timestamp for the quota-defaults entry.
    pub defaults: i64,
    /// NTFS timestamp for the built-in Administrators entry.
    pub administrators: i64,
}

/// Required MFT-record role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtendRecordSpec {
    pub record_number: u64,
    pub sequence_number: u16,
    pub name: &'static str,
    pub parent_record_number: u64,
    pub parent_sequence_number: u16,
    /// Final flags, including `MFT_RECORD_IN_USE` supplied by base record layout.
    pub mft_flags: u16,
    pub standard_information_file_attributes: u32,
    pub file_name_attributes: u32,
}

/// Required resident index-root role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtendIndexSpec {
    pub owner_record_number: u64,
    pub name: &'static str,
    pub indexed_attribute_type: u32,
    pub collation_rule: u32,
    /// The pinned profile requires the root to remain resident.
    pub resident: bool,
}

/// Evidence-backed namespace and index-role plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsExtendNamespace {
    pub extend: ExtendRecordSpec,
    pub quota: ExtendRecordSpec,
    pub object_id: ExtendRecordSpec,
    pub reparse: ExtendRecordSpec,
    pub indexes: [ExtendIndexSpec; 5],
}

/// Exact index-entry fragments for the pinned formatter's initial `$Extend` children.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsExtendMetadata {
    pub namespace: NtfsExtendNamespace,
    /// Two quota-control entries followed by one terminal entry.
    pub quota_q_index_entries: Vec<u8>,
    /// One Administrators SID-to-owner entry followed by one terminal entry.
    pub quota_o_index_entries: Vec<u8>,
    /// The initial `$ObjId:$O` is empty unless `mkntfs --with-uuid` is requested.
    pub object_id_o_index_entries: Vec<u8>,
    /// The initial `$Reparse:$R` is empty.
    pub reparse_r_index_entries: Vec<u8>,
}

/// One parsed quota control entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotaControlSummary {
    pub owner_id: u32,
    pub change_time: i64,
    pub has_sid: bool,
}

/// Successful independent validation result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsExtendValidation {
    pub quota_entries: [QuotaControlSummary; 2],
    pub quota_owner_id: u32,
    pub child_count: usize,
    /// Always false: validation establishes conformance to the pinned profile, not safety to
    /// activate a converted filesystem.
    pub activation_authorized: bool,
}

/// Evidence gap that prevents this module from authorizing activation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtfsExtendActivationGap {
    MicrosoftDoesNotSpecifyBootstrapBytes,
    FileAndAttributeWrappersNotGenerated,
    ExtendDirectoryEntriesNotGenerated,
    CaseSensitivityMarkedFixmeByFormatter,
    UsnJournalOmittedByPinnedProfile,
    ModernResourceManagerMetadataNotModeled,
    NativeChkdskAndMountValidationMissing,
}

/// All known blockers are returned rather than hidden behind a boolean.
pub const ACTIVATION_GAPS: [NtfsExtendActivationGap; 7] = [
    NtfsExtendActivationGap::MicrosoftDoesNotSpecifyBootstrapBytes,
    NtfsExtendActivationGap::FileAndAttributeWrappersNotGenerated,
    NtfsExtendActivationGap::ExtendDirectoryEntriesNotGenerated,
    NtfsExtendActivationGap::CaseSensitivityMarkedFixmeByFormatter,
    NtfsExtendActivationGap::UsnJournalOmittedByPinnedProfile,
    NtfsExtendActivationGap::ModernResourceManagerMetadataNotModeled,
    NtfsExtendActivationGap::NativeChkdskAndMountValidationMissing,
];

/// Refusal or malformed-input reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NtfsExtendError {
    UnsupportedProfile {
        profile: NtfsExtendProfile,
    },
    InvalidLimit {
        field: &'static str,
    },
    ByteLimitExceeded {
        actual: usize,
        maximum: usize,
    },
    ChildLimitExceeded {
        actual: usize,
        maximum: usize,
    },
    AllocationFailure {
        target: &'static str,
    },
    InvalidTimestamp {
        entry: &'static str,
        value: i64,
    },
    NamespaceMismatch {
        field: &'static str,
    },
    InvalidIndexLength {
        index: &'static str,
        actual: usize,
        expected: usize,
    },
    InvalidIndexField {
        index: &'static str,
        entry: usize,
        field: &'static str,
    },
    NonZeroPadding {
        index: &'static str,
        entry: usize,
        offset: usize,
    },
}

impl fmt::Display for NtfsExtendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedProfile { profile } => {
                write!(formatter, "unsupported NTFS $Extend profile: {profile:?}")
            }
            Self::InvalidLimit { field } => write!(formatter, "invalid $Extend limit: {field}"),
            Self::ByteLimitExceeded { actual, maximum } => write!(
                formatter,
                "$Extend index bytes {actual} exceed caller limit {maximum}"
            ),
            Self::ChildLimitExceeded { actual, maximum } => write!(
                formatter,
                "$Extend child count {actual} exceeds caller limit {maximum}"
            ),
            Self::AllocationFailure { target } => {
                write!(formatter, "could not allocate bounded {target} output")
            }
            Self::InvalidTimestamp { entry, value } => {
                write!(formatter, "invalid {entry} quota timestamp {value}")
            }
            Self::NamespaceMismatch { field } => {
                write!(formatter, "$Extend namespace mismatch in {field}")
            }
            Self::InvalidIndexLength {
                index,
                actual,
                expected,
            } => write!(
                formatter,
                "invalid {index} byte length {actual}, expected {expected}"
            ),
            Self::InvalidIndexField {
                index,
                entry,
                field,
            } => write!(formatter, "invalid {index} entry {entry} field {field}"),
            Self::NonZeroPadding {
                index,
                entry,
                offset,
            } => write!(
                formatter,
                "non-zero {index} entry {entry} padding at byte {offset}"
            ),
        }
    }
}

impl std::error::Error for NtfsExtendError {}

/// Returns the immutable list of gaps which prevents activation authorization.
#[must_use]
pub const fn activation_gaps() -> &'static [NtfsExtendActivationGap] {
    &ACTIVATION_GAPS
}

/// Generate the narrow initial `$Extend` metadata profile proven by the pinned NTFS-3G source.
///
/// # Errors
///
/// Returns an error for an unsupported profile, invalid/insufficient limits, invalid NTFS
/// timestamps, or allocation failure.
pub fn generate_ntfs3g_extend_metadata(
    profile: NtfsExtendProfile,
    times: QuotaChangeTimes,
    limits: NtfsExtendLimits,
) -> Result<NtfsExtendMetadata, NtfsExtendError> {
    require_supported_profile(profile)?;
    validate_limits(limits)?;
    validate_timestamp("defaults", times.defaults)?;
    validate_timestamp("Administrators", times.administrators)?;

    let mut q = Vec::new();
    q.try_reserve_exact(Q_INDEX_BYTES)
        .map_err(|_| NtfsExtendError::AllocationFailure {
            target: "$Quota:$Q",
        })?;
    append_q_entry(&mut q, QUOTA_DEFAULTS_ID, times.defaults, false);
    append_q_entry(&mut q, QUOTA_FIRST_USER_ID, times.administrators, true);
    append_terminal(&mut q);

    let mut o = Vec::new();
    o.try_reserve_exact(O_INDEX_BYTES)
        .map_err(|_| NtfsExtendError::AllocationFailure {
            target: "$Quota:$O",
        })?;
    append_o_entry(&mut o);
    append_terminal(&mut o);

    Ok(NtfsExtendMetadata {
        namespace: canonical_namespace(),
        quota_q_index_entries: q,
        quota_o_index_entries: o,
        object_id_o_index_entries: make_empty_index("$ObjId:$O")?,
        reparse_r_index_entries: make_empty_index("$Reparse:$R")?,
    })
}

/// Independently parse and validate the pinned `$Extend` profile.
///
/// # Errors
///
/// Returns an error when the profile is unsupported, bounds are insufficient, namespace roles do
/// not match the pinned profile, or any index entry is truncated, malformed, or inconsistent.
pub fn validate_ntfs3g_extend_metadata(
    profile: NtfsExtendProfile,
    metadata: &NtfsExtendMetadata,
    limits: NtfsExtendLimits,
) -> Result<NtfsExtendValidation, NtfsExtendError> {
    require_supported_profile(profile)?;
    validate_limits(limits)?;
    validate_namespace(&metadata.namespace)?;
    validate_total_bytes(metadata, limits)?;

    require_len("$Quota:$Q", &metadata.quota_q_index_entries, Q_INDEX_BYTES)?;
    let defaults = parse_q_entry(
        "$Quota:$Q",
        0,
        &metadata.quota_q_index_entries[..Q_DEFAULTS_ENTRY_BYTES],
        QUOTA_DEFAULTS_ID,
        false,
    )?;
    let admin_start = Q_DEFAULTS_ENTRY_BYTES;
    let admin_end = admin_start + Q_ADMINISTRATORS_ENTRY_BYTES;
    let administrators = parse_q_entry(
        "$Quota:$Q",
        1,
        &metadata.quota_q_index_entries[admin_start..admin_end],
        QUOTA_FIRST_USER_ID,
        true,
    )?;
    parse_terminal("$Quota:$Q", 2, &metadata.quota_q_index_entries[admin_end..])?;

    require_len("$Quota:$O", &metadata.quota_o_index_entries, O_INDEX_BYTES)?;
    let owner_id = parse_o_entry(
        "$Quota:$O",
        0,
        &metadata.quota_o_index_entries[..O_ADMINISTRATORS_ENTRY_BYTES],
    )?;
    parse_terminal(
        "$Quota:$O",
        1,
        &metadata.quota_o_index_entries[O_ADMINISTRATORS_ENTRY_BYTES..],
    )?;

    validate_empty_index("$ObjId:$O", &metadata.object_id_o_index_entries)?;
    validate_empty_index("$Reparse:$R", &metadata.reparse_r_index_entries)?;

    if owner_id != administrators.owner_id {
        return Err(NtfsExtendError::InvalidIndexField {
            index: "$Quota:$O",
            entry: 0,
            field: "owner_id cross-reference",
        });
    }

    Ok(NtfsExtendValidation {
        quota_entries: [defaults, administrators],
        quota_owner_id: owner_id,
        child_count: 3,
        activation_authorized: false,
    })
}

const fn require_supported_profile(profile: NtfsExtendProfile) -> Result<(), NtfsExtendError> {
    match profile {
        NtfsExtendProfile::MkntfsNtfs31 => Ok(()),
        NtfsExtendProfile::ModernWindowsNative => {
            Err(NtfsExtendError::UnsupportedProfile { profile })
        }
    }
}

const fn validate_limits(limits: NtfsExtendLimits) -> Result<(), NtfsExtendError> {
    if limits.max_index_bytes == 0 {
        return Err(NtfsExtendError::InvalidLimit {
            field: "max_index_bytes",
        });
    }
    if limits.max_children == 0 {
        return Err(NtfsExtendError::InvalidLimit {
            field: "max_children",
        });
    }
    if ALL_INDEX_BYTES > limits.max_index_bytes {
        return Err(NtfsExtendError::ByteLimitExceeded {
            actual: ALL_INDEX_BYTES,
            maximum: limits.max_index_bytes,
        });
    }
    if 3 > limits.max_children {
        return Err(NtfsExtendError::ChildLimitExceeded {
            actual: 3,
            maximum: limits.max_children,
        });
    }
    Ok(())
}

const fn validate_timestamp(entry: &'static str, value: i64) -> Result<(), NtfsExtendError> {
    if value < 0 {
        Err(NtfsExtendError::InvalidTimestamp { entry, value })
    } else {
        Ok(())
    }
}

const fn canonical_namespace() -> NtfsExtendNamespace {
    const ROOT: u64 = 5;
    const EXTEND: u64 = 11;
    const SYSTEM_CHILD_FLAGS: u16 = 0x000d;
    const EXTEND_FLAGS: u16 = 0x0003;
    const HIDDEN_SYSTEM: u32 = 0x0000_0006;
    const EXTEND_FILE_ATTRIBUTES: u32 = HIDDEN_SYSTEM | 0x1000_0000;
    const CHILD_FILE_ATTRIBUTES: u32 = HIDDEN_SYSTEM | 0x20 | 0x2000_0000;

    NtfsExtendNamespace {
        extend: ExtendRecordSpec {
            record_number: EXTEND,
            sequence_number: 11,
            name: "$Extend",
            parent_record_number: ROOT,
            parent_sequence_number: 5,
            mft_flags: EXTEND_FLAGS,
            standard_information_file_attributes: HIDDEN_SYSTEM,
            file_name_attributes: EXTEND_FILE_ATTRIBUTES,
        },
        quota: ExtendRecordSpec {
            record_number: 24,
            sequence_number: 1,
            name: "$Quota",
            parent_record_number: EXTEND,
            parent_sequence_number: 11,
            mft_flags: SYSTEM_CHILD_FLAGS,
            standard_information_file_attributes: CHILD_FILE_ATTRIBUTES,
            file_name_attributes: CHILD_FILE_ATTRIBUTES,
        },
        object_id: ExtendRecordSpec {
            record_number: 25,
            sequence_number: 1,
            name: "$ObjId",
            parent_record_number: EXTEND,
            parent_sequence_number: 11,
            mft_flags: SYSTEM_CHILD_FLAGS,
            standard_information_file_attributes: CHILD_FILE_ATTRIBUTES,
            file_name_attributes: CHILD_FILE_ATTRIBUTES,
        },
        reparse: ExtendRecordSpec {
            record_number: 26,
            sequence_number: 1,
            name: "$Reparse",
            parent_record_number: EXTEND,
            parent_sequence_number: 11,
            mft_flags: SYSTEM_CHILD_FLAGS,
            standard_information_file_attributes: CHILD_FILE_ATTRIBUTES,
            file_name_attributes: CHILD_FILE_ATTRIBUTES,
        },
        indexes: [
            ExtendIndexSpec {
                owner_record_number: EXTEND,
                name: "$I30",
                indexed_attribute_type: ATTRIBUTE_TYPE_FILE_NAME,
                collation_rule: COLLATION_FILE_NAME,
                resident: true,
            },
            ExtendIndexSpec {
                owner_record_number: 24,
                name: "$Q",
                indexed_attribute_type: ATTRIBUTE_TYPE_UNUSED,
                collation_rule: COLLATION_NTOFS_ULONG,
                resident: true,
            },
            ExtendIndexSpec {
                owner_record_number: 24,
                name: "$O",
                indexed_attribute_type: ATTRIBUTE_TYPE_UNUSED,
                collation_rule: COLLATION_NTOFS_SID,
                resident: true,
            },
            ExtendIndexSpec {
                owner_record_number: 25,
                name: "$O",
                indexed_attribute_type: ATTRIBUTE_TYPE_UNUSED,
                collation_rule: COLLATION_NTOFS_ULONGS,
                resident: true,
            },
            ExtendIndexSpec {
                owner_record_number: 26,
                name: "$R",
                indexed_attribute_type: ATTRIBUTE_TYPE_UNUSED,
                collation_rule: COLLATION_NTOFS_ULONGS,
                resident: true,
            },
        ],
    }
}

fn validate_namespace(namespace: &NtfsExtendNamespace) -> Result<(), NtfsExtendError> {
    let expected = canonical_namespace();
    if namespace.extend != expected.extend {
        return Err(NtfsExtendError::NamespaceMismatch { field: "$Extend" });
    }
    if namespace.quota != expected.quota {
        return Err(NtfsExtendError::NamespaceMismatch { field: "$Quota" });
    }
    if namespace.object_id != expected.object_id {
        return Err(NtfsExtendError::NamespaceMismatch { field: "$ObjId" });
    }
    if namespace.reparse != expected.reparse {
        return Err(NtfsExtendError::NamespaceMismatch { field: "$Reparse" });
    }
    if namespace.indexes != expected.indexes {
        return Err(NtfsExtendError::NamespaceMismatch { field: "indexes" });
    }
    Ok(())
}

fn validate_total_bytes(
    metadata: &NtfsExtendMetadata,
    limits: NtfsExtendLimits,
) -> Result<(), NtfsExtendError> {
    let actual = metadata
        .quota_q_index_entries
        .len()
        .checked_add(metadata.quota_o_index_entries.len())
        .and_then(|size| size.checked_add(metadata.object_id_o_index_entries.len()))
        .and_then(|size| size.checked_add(metadata.reparse_r_index_entries.len()))
        .ok_or(NtfsExtendError::ByteLimitExceeded {
            actual: usize::MAX,
            maximum: limits.max_index_bytes,
        })?;
    if actual > limits.max_index_bytes {
        return Err(NtfsExtendError::ByteLimitExceeded {
            actual,
            maximum: limits.max_index_bytes,
        });
    }
    Ok(())
}

fn append_q_entry(output: &mut Vec<u8>, owner_id: u32, change_time: i64, sid: bool) {
    let (entry_length, data_length) = if sid {
        (Q_ADMINISTRATORS_ENTRY_BYTES, 0x40_u16)
    } else {
        (Q_DEFAULTS_ENTRY_BYTES, 0x30_u16)
    };
    push_u16(output, 0x14);
    push_u16(output, data_length);
    push_u32(output, 0);
    push_u16(
        output,
        u16::try_from(entry_length).expect("fixed entry length fits u16"),
    );
    push_u16(output, 4);
    push_u16(output, 0);
    push_u16(output, 0);
    push_u32(output, owner_id);
    push_u32(output, QUOTA_ENTRY_VERSION);
    push_u32(output, QUOTA_FLAG_DEFAULT_LIMITS);
    push_u64(output, 0);
    push_i64(output, change_time);
    push_i64(output, -1);
    push_i64(output, -1);
    push_i64(output, 0);
    if sid {
        append_administrators_sid(output);
    }
    output.resize(output.len() + 4, 0);
}

fn append_o_entry(output: &mut Vec<u8>) {
    push_u16(output, 0x20);
    push_u16(output, 4);
    push_u32(output, 0);
    push_u16(output, 0x28);
    push_u16(output, 0x10);
    push_u16(output, 0);
    push_u16(output, 0);
    append_administrators_sid(output);
    push_u32(output, QUOTA_FIRST_USER_ID);
    // NTFS-3G preserves the observed NTFS 3.1 value 32 here. Its layout comment calls this
    // padding and explicitly says it is excluded from data_length.
    push_u32(output, 32);
}

fn append_administrators_sid(output: &mut Vec<u8>) {
    output.push(1);
    output.push(2);
    output.extend_from_slice(&[0, 0, 0, 0, 0, 5]);
    push_u32(output, SECURITY_BUILTIN_DOMAIN_RID);
    push_u32(output, DOMAIN_ALIAS_RID_ADMINS);
}

fn append_terminal(output: &mut Vec<u8>) {
    output.extend_from_slice(&terminal_entry());
}

fn make_empty_index(target: &'static str) -> Result<Vec<u8>, NtfsExtendError> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(INDEX_ENTRY_HEADER_BYTES)
        .map_err(|_| NtfsExtendError::AllocationFailure { target })?;
    append_terminal(&mut output);
    Ok(output)
}

const fn terminal_entry() -> [u8; INDEX_ENTRY_HEADER_BYTES] {
    [0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0, 0, 0, 2, 0, 0, 0]
}

fn parse_q_entry(
    index: &'static str,
    entry: usize,
    bytes: &[u8],
    expected_owner: u32,
    expect_sid: bool,
) -> Result<QuotaControlSummary, NtfsExtendError> {
    let expected_len = if expect_sid {
        Q_ADMINISTRATORS_ENTRY_BYTES
    } else {
        Q_DEFAULTS_ENTRY_BYTES
    };
    require_len(index, bytes, expected_len)?;
    require_u16(index, entry, "data_offset", bytes, 0, 0x14)?;
    require_u16(
        index,
        entry,
        "data_length",
        bytes,
        2,
        if expect_sid { 0x40 } else { 0x30 },
    )?;
    require_u32(index, entry, "reservedV", bytes, 4, 0)?;
    require_u16(
        index,
        entry,
        "length",
        bytes,
        8,
        u16::try_from(expected_len).expect("fixed entry length fits u16"),
    )?;
    require_u16(index, entry, "key_length", bytes, 10, 4)?;
    require_u16(index, entry, "flags", bytes, 12, 0)?;
    require_u16(index, entry, "reserved", bytes, 14, 0)?;
    require_u32(index, entry, "owner_id", bytes, 16, expected_owner)?;
    require_u32(index, entry, "version", bytes, 20, QUOTA_ENTRY_VERSION)?;
    require_u32(
        index,
        entry,
        "quota flags",
        bytes,
        24,
        QUOTA_FLAG_DEFAULT_LIMITS,
    )?;
    require_u64(index, entry, "bytes_used", bytes, 28, 0)?;
    let change_time = read_i64(bytes, 36);
    validate_timestamp(
        if expect_sid {
            "Administrators"
        } else {
            "defaults"
        },
        change_time,
    )?;
    require_i64(index, entry, "threshold", bytes, 44, -1)?;
    require_i64(index, entry, "limit", bytes, 52, -1)?;
    require_i64(index, entry, "exceeded_time", bytes, 60, 0)?;
    if expect_sid {
        parse_administrators_sid(index, entry, &bytes[68..84])?;
        require_zero(index, entry, bytes, 84..88)?;
    } else {
        require_zero(index, entry, bytes, 68..72)?;
    }
    Ok(QuotaControlSummary {
        owner_id: expected_owner,
        change_time,
        has_sid: expect_sid,
    })
}

fn parse_o_entry(index: &'static str, entry: usize, bytes: &[u8]) -> Result<u32, NtfsExtendError> {
    require_len(index, bytes, O_ADMINISTRATORS_ENTRY_BYTES)?;
    require_u16(index, entry, "data_offset", bytes, 0, 0x20)?;
    require_u16(index, entry, "data_length", bytes, 2, 4)?;
    require_u32(index, entry, "reservedV", bytes, 4, 0)?;
    require_u16(index, entry, "length", bytes, 8, 0x28)?;
    require_u16(index, entry, "key_length", bytes, 10, 0x10)?;
    require_u16(index, entry, "flags", bytes, 12, 0)?;
    require_u16(index, entry, "reserved", bytes, 14, 0)?;
    parse_administrators_sid(index, entry, &bytes[16..32])?;
    let owner_id = read_u32(bytes, 32);
    if owner_id != QUOTA_FIRST_USER_ID {
        return Err(NtfsExtendError::InvalidIndexField {
            index,
            entry,
            field: "owner_id",
        });
    }
    require_u32(index, entry, "NTFS 3.1 trailing value", bytes, 36, 32)?;
    Ok(owner_id)
}

fn parse_administrators_sid(
    index: &'static str,
    entry: usize,
    sid: &[u8],
) -> Result<(), NtfsExtendError> {
    if sid.len() != 16
        || sid[0] != 1
        || sid[1] != 2
        || sid[2..8] != [0, 0, 0, 0, 0, 5]
        || read_u32(sid, 8) != SECURITY_BUILTIN_DOMAIN_RID
        || read_u32(sid, 12) != DOMAIN_ALIAS_RID_ADMINS
    {
        return Err(NtfsExtendError::InvalidIndexField {
            index,
            entry,
            field: "Administrators SID",
        });
    }
    Ok(())
}

fn validate_empty_index(index: &'static str, bytes: &[u8]) -> Result<(), NtfsExtendError> {
    require_len(index, bytes, EMPTY_INDEX_BYTES)?;
    parse_terminal(index, 0, bytes)
}

fn parse_terminal(index: &'static str, entry: usize, bytes: &[u8]) -> Result<(), NtfsExtendError> {
    require_len(index, bytes, INDEX_ENTRY_HEADER_BYTES)?;
    require_zero(index, entry, bytes, 0..8)?;
    require_u16(index, entry, "length", bytes, 8, 0x10)?;
    require_u16(index, entry, "key_length", bytes, 10, 0)?;
    require_u16(index, entry, "flags", bytes, 12, INDEX_ENTRY_END)?;
    require_u16(index, entry, "reserved", bytes, 14, 0)
}

const fn require_len(
    index: &'static str,
    bytes: &[u8],
    expected: usize,
) -> Result<(), NtfsExtendError> {
    if bytes.len() == expected {
        Ok(())
    } else {
        Err(NtfsExtendError::InvalidIndexLength {
            index,
            actual: bytes.len(),
            expected,
        })
    }
}

fn require_zero(
    index: &'static str,
    entry: usize,
    bytes: &[u8],
    range: std::ops::Range<usize>,
) -> Result<(), NtfsExtendError> {
    for offset in range {
        if bytes[offset] != 0 {
            return Err(NtfsExtendError::NonZeroPadding {
                index,
                entry,
                offset,
            });
        }
    }
    Ok(())
}

const fn require_u16(
    index: &'static str,
    entry: usize,
    field: &'static str,
    bytes: &[u8],
    offset: usize,
    expected: u16,
) -> Result<(), NtfsExtendError> {
    if read_u16(bytes, offset) == expected {
        Ok(())
    } else {
        Err(NtfsExtendError::InvalidIndexField {
            index,
            entry,
            field,
        })
    }
}

const fn require_u32(
    index: &'static str,
    entry: usize,
    field: &'static str,
    bytes: &[u8],
    offset: usize,
    expected: u32,
) -> Result<(), NtfsExtendError> {
    if read_u32(bytes, offset) == expected {
        Ok(())
    } else {
        Err(NtfsExtendError::InvalidIndexField {
            index,
            entry,
            field,
        })
    }
}

const fn require_u64(
    index: &'static str,
    entry: usize,
    field: &'static str,
    bytes: &[u8],
    offset: usize,
    expected: u64,
) -> Result<(), NtfsExtendError> {
    if read_u64(bytes, offset) == expected {
        Ok(())
    } else {
        Err(NtfsExtendError::InvalidIndexField {
            index,
            entry,
            field,
        })
    }
}

const fn require_i64(
    index: &'static str,
    entry: usize,
    field: &'static str,
    bytes: &[u8],
    offset: usize,
    expected: i64,
) -> Result<(), NtfsExtendError> {
    if read_i64(bytes, offset) == expected {
        Ok(())
    } else {
        Err(NtfsExtendError::InvalidIndexField {
            index,
            entry,
            field,
        })
    }
}

const fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

const fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

const fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

const fn read_i64(bytes: &[u8], offset: usize) -> i64 {
    i64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

fn push_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn push_i64(output: &mut Vec<u8>, value: i64) {
    output.extend_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    const TIMES: QuotaChangeTimes = QuotaChangeTimes {
        defaults: 0x0123_4567_89ab_cdef,
        administrators: 0x1020_3040_5060_7080,
    };

    fn generated() -> NtfsExtendMetadata {
        generate_ntfs3g_extend_metadata(
            NtfsExtendProfile::MkntfsNtfs31,
            TIMES,
            NtfsExtendLimits::default(),
        )
        .expect("canonical generation succeeds")
    }

    #[test]
    fn golden_quota_prefix_and_sid_match_pinned_mkntfs() {
        let metadata = generated();
        assert_eq!(
            &metadata.quota_q_index_entries[..28],
            &[
                0x14, 0, 0x30, 0, 0, 0, 0, 0, 0x48, 0, 4, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 1,
                0, 0, 0,
            ]
        );
        assert_eq!(
            &metadata.quota_q_index_entries
                [68 + Q_DEFAULTS_ENTRY_BYTES..84 + Q_DEFAULTS_ENTRY_BYTES],
            &[1, 2, 0, 0, 0, 0, 0, 5, 0x20, 0, 0, 0, 0x20, 2, 0, 0]
        );
        assert_eq!(
            &metadata.quota_o_index_entries[16..32],
            &[1, 2, 0, 0, 0, 0, 0, 5, 0x20, 0, 0, 0, 0x20, 2, 0, 0]
        );
    }

    #[test]
    fn canonical_profile_round_trips_through_independent_validator() {
        let validation = validate_ntfs3g_extend_metadata(
            NtfsExtendProfile::MkntfsNtfs31,
            &generated(),
            NtfsExtendLimits::default(),
        )
        .expect("canonical metadata validates");
        assert_eq!(validation.quota_entries[0].change_time, TIMES.defaults);
        assert_eq!(
            validation.quota_entries[1].change_time,
            TIMES.administrators
        );
        assert_eq!(validation.quota_owner_id, QUOTA_FIRST_USER_ID);
        assert!(!validation.activation_authorized);
        assert_eq!(activation_gaps().len(), 7);
    }

    #[test]
    fn namespace_pins_records_parents_and_index_roles() {
        let namespace = generated().namespace;
        assert_eq!(namespace.extend.record_number, 11);
        assert_eq!(namespace.quota.record_number, 24);
        assert_eq!(namespace.object_id.record_number, 25);
        assert_eq!(namespace.reparse.record_number, 26);
        assert_eq!(namespace.quota.parent_record_number, 11);
        assert_eq!(namespace.extend.mft_flags, 0x0003);
        assert_eq!(namespace.quota.mft_flags, 0x000d);
        assert_eq!(namespace.extend.standard_information_file_attributes, 6);
        assert_eq!(namespace.extend.file_name_attributes, 0x1000_0006);
        assert_eq!(
            namespace.quota.standard_information_file_attributes,
            0x2000_0026
        );
        assert_eq!(namespace.quota.file_name_attributes, 0x2000_0026);
        assert!(namespace.indexes[0].resident);
        assert_eq!(namespace.indexes[0].collation_rule, COLLATION_FILE_NAME);
        assert_eq!(namespace.indexes[1].collation_rule, COLLATION_NTOFS_ULONG);
        assert_eq!(namespace.indexes[2].collation_rule, COLLATION_NTOFS_SID);
        assert_eq!(namespace.indexes[3].collation_rule, COLLATION_NTOFS_ULONGS);
        assert_eq!(namespace.indexes[4].collation_rule, COLLATION_NTOFS_ULONGS);
    }

    #[test]
    fn modern_native_profile_is_refused() {
        let error = generate_ntfs3g_extend_metadata(
            NtfsExtendProfile::ModernWindowsNative,
            TIMES,
            NtfsExtendLimits::default(),
        )
        .expect_err("unproven profile must be refused");
        assert!(matches!(
            error,
            NtfsExtendError::UnsupportedProfile {
                profile: NtfsExtendProfile::ModernWindowsNative
            }
        ));
    }

    #[test]
    fn limits_are_enforced_before_allocation_or_parsing() {
        for limits in [
            NtfsExtendLimits {
                max_index_bytes: 0,
                max_children: 8,
            },
            NtfsExtendLimits {
                max_index_bytes: ALL_INDEX_BYTES - 1,
                max_children: 8,
            },
            NtfsExtendLimits {
                max_index_bytes: ALL_INDEX_BYTES,
                max_children: 2,
            },
        ] {
            assert!(
                generate_ntfs3g_extend_metadata(NtfsExtendProfile::MkntfsNtfs31, TIMES, limits)
                    .is_err()
            );
        }
    }

    #[test]
    fn negative_timestamps_are_rejected() {
        let error = generate_ntfs3g_extend_metadata(
            NtfsExtendProfile::MkntfsNtfs31,
            QuotaChangeTimes {
                defaults: -1,
                administrators: 0,
            },
            NtfsExtendLimits::default(),
        )
        .expect_err("negative NTFS time must fail");
        assert!(matches!(error, NtfsExtendError::InvalidTimestamp { .. }));
    }

    #[test]
    fn each_truncation_is_rejected_without_panicking() {
        let metadata = generated();
        for length in 0..metadata.quota_q_index_entries.len() {
            let mut truncated = metadata.clone();
            truncated.quota_q_index_entries.truncate(length);
            assert!(
                validate_ntfs3g_extend_metadata(
                    NtfsExtendProfile::MkntfsNtfs31,
                    &truncated,
                    NtfsExtendLimits::default()
                )
                .is_err()
            );
        }
    }

    #[test]
    fn malformed_header_data_and_terminal_fields_are_rejected() {
        for offset in [0, 2, 4, 8, 10, 12, 14, 16, 20, 24, 28, 44, 52, 60, 68, 84] {
            let mut metadata = generated();
            metadata.quota_q_index_entries[offset] ^= 0x80;
            assert!(
                validate_ntfs3g_extend_metadata(
                    NtfsExtendProfile::MkntfsNtfs31,
                    &metadata,
                    NtfsExtendLimits::default()
                )
                .is_err(),
                "offset {offset}"
            );
        }
        let mut metadata = generated();
        let terminal_offset = Q_DEFAULTS_ENTRY_BYTES + Q_ADMINISTRATORS_ENTRY_BYTES + 12;
        metadata.quota_q_index_entries[terminal_offset] = 0;
        assert!(
            validate_ntfs3g_extend_metadata(
                NtfsExtendProfile::MkntfsNtfs31,
                &metadata,
                NtfsExtendLimits::default()
            )
            .is_err()
        );
    }

    #[test]
    fn trailing_bytes_and_nonempty_initial_optional_indexes_are_rejected() {
        let mut trailing = generated();
        trailing.quota_o_index_entries.push(0);
        assert!(
            validate_ntfs3g_extend_metadata(
                NtfsExtendProfile::MkntfsNtfs31,
                &trailing,
                NtfsExtendLimits::default()
            )
            .is_err()
        );

        let mut object_id = generated();
        object_id
            .object_id_o_index_entries
            .extend_from_slice(&[0; 8]);
        assert!(
            validate_ntfs3g_extend_metadata(
                NtfsExtendProfile::MkntfsNtfs31,
                &object_id,
                NtfsExtendLimits::default()
            )
            .is_err()
        );
    }

    #[test]
    fn cross_index_owner_reference_is_checked() {
        let mut metadata = generated();
        metadata.quota_o_index_entries[32..36].copy_from_slice(&0x101_u32.to_le_bytes());
        let error = validate_ntfs3g_extend_metadata(
            NtfsExtendProfile::MkntfsNtfs31,
            &metadata,
            NtfsExtendLimits::default(),
        )
        .expect_err("wrong owner reference must fail");
        assert!(matches!(error, NtfsExtendError::InvalidIndexField { .. }));
    }

    #[test]
    fn mutated_namespace_is_rejected() {
        let mut metadata = generated();
        metadata.namespace.quota.parent_record_number = 5;
        assert!(matches!(
            validate_ntfs3g_extend_metadata(
                NtfsExtendProfile::MkntfsNtfs31,
                &metadata,
                NtfsExtendLimits::default()
            ),
            Err(NtfsExtendError::NamespaceMismatch { field: "$Quota" })
        ));
    }
}
