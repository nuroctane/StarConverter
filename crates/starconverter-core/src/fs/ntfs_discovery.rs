//! Bounded, read-only bootstrap and first-pass discovery of NTFS system records.
//!
//! The boot sector identifies the first `$MFT` record. Record zero then identifies the `$MFT`
//! stream's physical extents through its unnamed, non-resident `$DATA` attribute. This module
//! follows that trust chain using regular image-file reads only. Same-record unnamed `$DATA`
//! fragments are concatenated in VCN order. Record zero's `$ATTRIBUTE_LIST` (resident, or
//! non-resident on volume clusters, including a VCN-split list whose continuation extent sits in
//! record zero or in an already-mapped extension record) is then followed to unnamed `$DATA` hosts
//! inside the growing map. A continuation host outside the current map remains explicit
//! incomplete mapping evidence rather than a guess.

use std::fmt;

use crate::fs::ntfs::NtfsBootSector;
use crate::fs::ntfs_attribute::{
    AttributeBody, AttributeLimits, NtfsAttribute, NtfsAttributeError, parse_attribute,
    parse_attribute_list,
};
use crate::fs::ntfs_attribute_list::{
    AttributeListEntry, AttributeListError, AttributeListLimits, parse_attribute_list_prefix,
    parse_attribute_list_value, resolve_attribute_list_with_reader,
};
use crate::fs::ntfs_record::{
    MAX_FILE_RECORD_SIZE, MftReference, NtfsFileRecord, NtfsFileRecordError, parse_file_record,
};
use crate::fs::ntfs_runlist::{
    ExtentLocation, MappingPairsError, MappingPairsLimits, NtfsRunlist, parse_mapping_pairs,
};
use crate::image::{BoundedImageReader, ImageError, ImageFile};

const ATTRIBUTE_LIST_TYPE: u32 = 0x20;
const DATA_ATTRIBUTE_TYPE: u32 = 0x80;
const MIN_MFT_MIRROR_RECORDS: u64 = 4;
// NTFS-3G's FILE_first_user is 16. Record 24 is the first user record only in some other NTFS
// implementations/profiles and must not be used as the mirror comparison boundary.
const FIRST_USER_MFT_RECORD: u64 = 16;
const SYSTEM_RECORDS: [SystemRecordKind; 3] = [
    SystemRecordKind::MftMirror,
    SystemRecordKind::Volume,
    SystemRecordKind::Bitmap,
];

/// Caller-controlled limits for NTFS discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtfsDiscoveryLimits {
    /// Maximum number of `$MFT`/`$MFTMirr` FILE records semantically compared.
    ///
    /// Fixed bootstrap/system reads are separate; the aggregate byte cap independently bounds all
    /// resulting I/O.
    pub max_records: usize,
    /// Maximum number of mapping pairs decoded from record zero.
    pub max_runs: usize,
    /// Maximum aggregate image bytes read by one discovery operation.
    pub max_bytes: u64,
    /// Maximum individual attribute size accepted from record zero.
    pub max_attribute_bytes: usize,
    /// Maximum attributes collected from record zero.
    pub max_attributes: usize,
    /// Maximum UTF-16 code units copied for one attribute name.
    pub max_name_code_units: usize,
}

impl Default for NtfsDiscoveryLimits {
    fn default() -> Self {
        Self {
            max_records: 16,
            max_runs: 4096,
            max_bytes: 256 * 1024 * 1024,
            max_attribute_bytes: 16 * 1024 * 1024,
            max_attributes: 256,
            max_name_code_units: 255,
        }
    }
}

/// Validated bootstrap evidence from `$MFT` record zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MftBootstrap {
    /// Concatenated unnamed `$DATA` runlist decoded from record zero and mapped continuations.
    pub runlist: NtfsRunlist,
    pub allocated_bytes: u64,
    pub data_bytes: u64,
    pub initialized_bytes: u64,
    /// Whether the decoded mapping covers the complete `$DATA` allocation.
    ///
    /// `false` means a `$DATA` or `$ATTRIBUTE_LIST` continuation host lies outside the decoded
    /// mapping, or record zero advertises allocation that no attribute maps.
    pub mapping_complete: bool,
    pub record_zero_sequence_number: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MftMirrorMapping {
    runlist: NtfsRunlist,
    data_bytes: u64,
    records_to_compare: u64,
}

/// NTFS system records included in the first discovery pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemRecordKind {
    MftMirror,
    Volume,
    Bitmap,
}

impl SystemRecordKind {
    #[must_use]
    pub const fn record_number(self) -> u64 {
        match self {
            Self::MftMirror => 1,
            Self::Volume => 3,
            Self::Bitmap => 6,
        }
    }
}

impl fmt::Display for SystemRecordKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MftMirror => "$MFTMirr",
            Self::Volume => "$Volume",
            Self::Bitmap => "$Bitmap",
        })
    }
}

/// Identity retained for a successfully parsed system record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemRecordIdentifier {
    pub kind: SystemRecordKind,
    pub record_number: u64,
    pub sequence_number: u16,
    pub in_use: bool,
}

/// Why a requested system record was not read in this bounded first pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncompleteReason {
    /// The caller's record cap was reached before this record.
    RecordLimit,
    /// Record bytes lie beyond the currently decoded `$MFT` mapping.
    MappingContinuationRequired,
}

/// First-pass evidence for one well-known NTFS record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemRecordEvidence {
    Found(SystemRecordIdentifier),
    Incomplete {
        kind: SystemRecordKind,
        reason: IncompleteReason,
    },
}

/// Exact comparison of used `$MFTMirr` FILE-record content with the corresponding `$MFT`
/// records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MftMirrorEvidence {
    /// Every system/reserved record represented by the mirror profile is present and its repaired,
    /// used FILE-record content matches exactly.
    Exact {
        records_compared: u64,
        bytes_compared: u64,
    },
    /// The mirror differs from its authoritative `$MFT` record bytes.
    Mismatch {
        record_number: u64,
        byte_offset_within_record: u64,
    },
    /// The bounded discovery pass could not compare all four protected records.
    Incomplete { reason: IncompleteReason },
}

/// Bounded NTFS bootstrap result and the first well-known system-record identities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsSystemDiscovery {
    pub mft: MftBootstrap,
    pub mft_mirror: MftMirrorEvidence,
    pub system_records: Vec<SystemRecordEvidence>,
    /// Total image bytes read during discovery.
    pub bytes_read: u64,
}

/// Failure to establish or safely follow the `$MFT` trust chain.
#[derive(Debug)]
pub enum NtfsDiscoveryError {
    InvalidLimit {
        field: &'static str,
    },
    GeometryOverflow {
        calculation: &'static str,
    },
    UnsupportedRecordSize {
        bytes: u64,
    },
    ByteLimitExceeded {
        requested_total: u64,
        maximum: u64,
    },
    Image(ImageError),
    FileRecord(NtfsFileRecordError),
    Attribute(NtfsAttributeError),
    MappingPairs(MappingPairsError),
    /// `$MFTMirr`'s `$ATTRIBUTE_LIST` could not be resolved into a complete attribute set.
    MftMirrorAttributeList(Box<AttributeListError>),
    RecordZeroNotInUse,
    RecordZeroIsExtension,
    RecordNumberMismatch {
        expected: u64,
        found: u64,
    },
    MissingUnnamedData,
    DuplicateUnnamedData,
    MissingMftMirrorData,
    DuplicateMftMirrorData,
    UnsupportedDataStorage {
        reason: &'static str,
    },
    UnsupportedMftMirrorStorage {
        reason: &'static str,
    },
    MftStartMismatch {
        boot_lcn: u64,
        runlist_lcn: Option<u64>,
    },
    MftMirrorStartMismatch {
        boot_lcn: u64,
        runlist_lcn: Option<u64>,
    },
    MftMirrorSizeMismatch {
        field: &'static str,
        expected: u64,
        actual: u64,
    },
    MftRecordOutsideMapping {
        record_number: u64,
    },
    SparseMftRange {
        record_number: u64,
    },
}

impl fmt::Display for NtfsDiscoveryError {
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit { field } => {
                write!(formatter, "NTFS discovery limit {field} must be non-zero")
            }
            Self::GeometryOverflow { calculation } => {
                write!(
                    formatter,
                    "NTFS discovery overflow while calculating {calculation}"
                )
            }
            Self::UnsupportedRecordSize { bytes } => {
                write!(
                    formatter,
                    "NTFS MFT record size {bytes} cannot be represented in memory"
                )
            }
            Self::ByteLimitExceeded {
                requested_total,
                maximum,
            } => write!(
                formatter,
                "NTFS discovery would read {requested_total} bytes, exceeding caller cap {maximum}"
            ),
            Self::Image(error) => write!(formatter, "could not read NTFS image: {error}"),
            Self::FileRecord(error) => write!(formatter, "invalid NTFS FILE record: {error}"),
            Self::Attribute(error) => write!(formatter, "invalid NTFS attribute: {error}"),
            Self::MappingPairs(error) => write!(formatter, "invalid NTFS mapping pairs: {error}"),
            Self::MftMirrorAttributeList(error) => write!(
                formatter,
                "could not resolve $MFTMirr $ATTRIBUTE_LIST: {error}"
            ),
            Self::RecordZeroNotInUse => {
                formatter.write_str("$MFT record zero is not marked in use")
            }
            Self::RecordZeroIsExtension => {
                formatter.write_str("$MFT record zero is an extension record")
            }
            Self::RecordNumberMismatch { expected, found } => write!(
                formatter,
                "NTFS FILE record number mismatch: expected {expected}, found {found}"
            ),
            Self::MissingUnnamedData => {
                formatter.write_str("$MFT record zero has no unnamed non-resident $DATA attribute")
            }
            Self::DuplicateUnnamedData => formatter
                .write_str("$MFT record zero has multiple unnamed first-extent $DATA attributes"),
            Self::MissingMftMirrorData => formatter
                .write_str("$MFTMirr record one has no unnamed non-resident $DATA attribute"),
            Self::DuplicateMftMirrorData => {
                formatter.write_str("$MFTMirr record one has multiple unnamed $DATA attributes")
            }
            Self::UnsupportedDataStorage { reason } => {
                write!(formatter, "unsupported $MFT storage: {reason}")
            }
            Self::UnsupportedMftMirrorStorage { reason } => {
                write!(formatter, "unsupported $MFTMirr storage: {reason}")
            }
            Self::MftStartMismatch {
                boot_lcn,
                runlist_lcn,
            } => write!(
                formatter,
                "$MFT runlist starts at LCN {runlist_lcn:?}, but the boot sector identifies LCN {boot_lcn}"
            ),
            Self::MftMirrorStartMismatch {
                boot_lcn,
                runlist_lcn,
            } => write!(
                formatter,
                "$MFTMirr runlist starts at LCN {runlist_lcn:?}, but the boot sector identifies LCN {boot_lcn}"
            ),
            Self::MftMirrorSizeMismatch {
                field,
                expected,
                actual,
            } => write!(
                formatter,
                "$MFTMirr {field} is {actual} bytes, expected {expected} bytes"
            ),
            Self::MftRecordOutsideMapping { record_number } => {
                write!(
                    formatter,
                    "$MFT record {record_number} is outside the decoded mapping fragment"
                )
            }
            Self::SparseMftRange { record_number } => {
                write!(
                    formatter,
                    "$MFT record {record_number} intersects a sparse extent"
                )
            }
        }
    }
}

impl std::error::Error for NtfsDiscoveryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Image(error) => Some(error),
            Self::FileRecord(error) => Some(error),
            Self::Attribute(error) => Some(error),
            Self::MappingPairs(error) => Some(error),
            Self::MftMirrorAttributeList(error) => Some(error.as_ref()),
            _ => None,
        }
    }
}

impl From<ImageError> for NtfsDiscoveryError {
    fn from(value: ImageError) -> Self {
        Self::Image(value)
    }
}

impl From<NtfsFileRecordError> for NtfsDiscoveryError {
    fn from(value: NtfsFileRecordError) -> Self {
        Self::FileRecord(value)
    }
}

impl From<NtfsAttributeError> for NtfsDiscoveryError {
    fn from(value: NtfsAttributeError) -> Self {
        Self::Attribute(value)
    }
}

impl From<MappingPairsError> for NtfsDiscoveryError {
    fn from(value: MappingPairsError) -> Self {
        Self::MappingPairs(value)
    }
}

/// Bootstraps `$MFT`, then identifies `$MFTMirr`, `$Volume`, and `$Bitmap` when their bytes are
/// available within the decoded mapping.
///
/// # Errors
///
/// Returns [`NtfsDiscoveryError`] for malformed records, attributes, mapping pairs, inconsistent
/// identity or geometry, unsafe storage semantics, image errors, arithmetic overflow, or a caller
/// byte limit violation. A record or mapping cap produces explicit incomplete evidence where
/// possible rather than silently claiming a complete inventory.
pub fn discover_system_records(
    image: &ImageFile,
    boot: &NtfsBootSector,
    limits: NtfsDiscoveryLimits,
) -> Result<NtfsSystemDiscovery, NtfsDiscoveryError> {
    discover_system_records_with_reader(image, boot, limits)
}

pub(crate) fn discover_system_records_with_reader(
    image: &dyn BoundedImageReader,
    boot: &NtfsBootSector,
    limits: NtfsDiscoveryLimits,
) -> Result<NtfsSystemDiscovery, NtfsDiscoveryError> {
    validate_limits(limits)?;
    let record_size = record_size(boot)?;
    let mut budget = ReadBudget::new(limits.max_bytes);
    let record_zero_offset = boot.mft_lcn.checked_mul(boot.cluster_size_bytes).ok_or(
        NtfsDiscoveryError::GeometryOverflow {
            calculation: "$MFT record-zero byte offset",
        },
    )?;
    budget.charge(boot.mft_record_size.bytes)?;
    let mut record_zero_bytes = vec![0_u8; record_size];
    read_chunked(image, record_zero_offset, &mut record_zero_bytes)?;
    let record_zero = parse_file_record(&record_zero_bytes)?;
    validate_record_identity(&record_zero, 0)?;
    if !record_zero.flags.is_in_use() {
        return Err(NtfsDiscoveryError::RecordZeroNotInUse);
    }
    if record_zero.base_record.is_some() {
        return Err(NtfsDiscoveryError::RecordZeroIsExtension);
    }

    let mut mft = parse_mft_data(&record_zero, boot, limits)?;
    extend_mft_mapping_from_attribute_list(
        image,
        boot,
        limits,
        &record_zero,
        record_size,
        &mut budget,
        &mut mft,
    )?;
    let mut system_records = Vec::new();
    let mut mft_mirror_mapping = None;
    system_records
        .try_reserve(SYSTEM_RECORDS.len())
        .map_err(|_| NtfsDiscoveryError::UnsupportedDataStorage {
            reason: "could not allocate bounded system-record evidence",
        })?;
    let mut records_read = 1_usize;
    for kind in SYSTEM_RECORDS {
        if records_read >= limits.max_records {
            system_records.push(SystemRecordEvidence::Incomplete {
                kind,
                reason: IncompleteReason::RecordLimit,
            });
            continue;
        }
        if !record_is_mapped(&mft, boot, kind.record_number())? {
            system_records.push(SystemRecordEvidence::Incomplete {
                kind,
                reason: IncompleteReason::MappingContinuationRequired,
            });
            continue;
        }
        budget.charge(boot.mft_record_size.bytes)?;
        let record = read_mft_record_inner(image, boot, &mft, kind.record_number(), record_size)?;
        validate_record_identity(&record, kind.record_number())?;
        if record.base_record.is_some() {
            return Err(NtfsDiscoveryError::UnsupportedDataStorage {
                reason: "well-known system record is an extension record",
            });
        }
        if kind == SystemRecordKind::MftMirror {
            mft_mirror_mapping =
                parse_mft_mirror_mapping(image, boot, &mft, &record, limits, &mut budget)?;
        }
        system_records.push(SystemRecordEvidence::Found(SystemRecordIdentifier {
            kind,
            record_number: kind.record_number(),
            sequence_number: record.sequence_number,
            in_use: record.flags.is_in_use(),
        }));
        records_read += 1;
    }

    let mft_mirror = validate_mft_mirror(
        image,
        boot,
        &mft,
        mft_mirror_mapping.as_ref(),
        limits,
        record_size,
        &mut budget,
    )?;

    Ok(NtfsSystemDiscovery {
        mft,
        mft_mirror,
        system_records,
        bytes_read: budget.used,
    })
}

/// Reads and validates one arbitrary `$MFT` record through an already bootstrapped runlist.
///
/// This function performs at most `max_bytes` of image I/O and requires the complete record range
/// to be present in the decoded runlist fragment.
///
/// # Errors
///
/// Returns [`NtfsDiscoveryError`] for an insufficient byte cap, an unmapped or sparse range,
/// inconsistent embedded record identity, malformed record bytes, image errors, or overflow.
pub fn read_mft_record(
    image: &ImageFile,
    boot: &NtfsBootSector,
    mft: &MftBootstrap,
    record_number: u64,
    max_bytes: u64,
) -> Result<NtfsFileRecord, NtfsDiscoveryError> {
    read_mft_record_with_reader(image, boot, mft, record_number, max_bytes)
}

pub(crate) fn read_mft_record_with_reader(
    image: &dyn BoundedImageReader,
    boot: &NtfsBootSector,
    mft: &MftBootstrap,
    record_number: u64,
    max_bytes: u64,
) -> Result<NtfsFileRecord, NtfsDiscoveryError> {
    if max_bytes == 0 {
        return Err(NtfsDiscoveryError::InvalidLimit { field: "max_bytes" });
    }
    let record_size = record_size(boot)?;
    let mut budget = ReadBudget::new(max_bytes);
    budget.charge(boot.mft_record_size.bytes)?;
    let record = read_mft_record_inner(image, boot, mft, record_number, record_size)?;
    validate_record_identity(&record, record_number)?;
    Ok(record)
}

/// Reads one record for a sequential inventory scan through a bounded image view.
///
/// NTFS formatters may leave the embedded record-number field at zero in records that have never
/// been allocated. Those bytes carry no identity while the in-use flag is clear, and inventory
/// ignores the rest of such a record. In-use records still require an exact embedded identity.
pub(crate) fn read_mft_record_for_inventory_with_reader(
    image: &dyn BoundedImageReader,
    boot: &NtfsBootSector,
    mft: &MftBootstrap,
    record_number: u64,
    max_bytes: u64,
) -> Result<NtfsFileRecord, NtfsDiscoveryError> {
    if max_bytes == 0 {
        return Err(NtfsDiscoveryError::InvalidLimit { field: "max_bytes" });
    }
    let record_size = record_size(boot)?;
    let mut budget = ReadBudget::new(max_bytes);
    budget.charge(boot.mft_record_size.bytes)?;
    let record = read_mft_record_inner(image, boot, mft, record_number, record_size)?;
    if record.flags.is_in_use() {
        validate_record_identity(&record, record_number)?;
    }
    Ok(record)
}

fn validate_limits(limits: NtfsDiscoveryLimits) -> Result<(), NtfsDiscoveryError> {
    for (field, zero) in [
        ("max_records", limits.max_records == 0),
        ("max_runs", limits.max_runs == 0),
        ("max_bytes", limits.max_bytes == 0),
        ("max_attribute_bytes", limits.max_attribute_bytes == 0),
        ("max_attributes", limits.max_attributes == 0),
        ("max_name_code_units", limits.max_name_code_units == 0),
    ] {
        if zero {
            return Err(NtfsDiscoveryError::InvalidLimit { field });
        }
    }
    Ok(())
}

fn record_size(boot: &NtfsBootSector) -> Result<usize, NtfsDiscoveryError> {
    let size = usize::try_from(boot.mft_record_size.bytes).map_err(|_| {
        NtfsDiscoveryError::UnsupportedRecordSize {
            bytes: boot.mft_record_size.bytes,
        }
    })?;
    if size > MAX_FILE_RECORD_SIZE {
        return Err(NtfsDiscoveryError::UnsupportedRecordSize {
            bytes: boot.mft_record_size.bytes,
        });
    }
    Ok(size)
}

fn parse_mft_data(
    record_zero: &NtfsFileRecord,
    boot: &NtfsBootSector,
    limits: NtfsDiscoveryLimits,
) -> Result<MftBootstrap, NtfsDiscoveryError> {
    let attributes = parse_mft_record_attributes(record_zero, boot, limits)?;
    let (runlist, sizes) = unnamed_mft_data_from_record(&attributes.attributes, boot, limits)?;
    validate_mft_start(&runlist, boot)?;
    let mapped_bytes = mapped_byte_length(&runlist, boot)?;
    if mapped_bytes < boot.mft_record_size.bytes {
        return Err(NtfsDiscoveryError::MftRecordOutsideMapping { record_number: 0 });
    }
    if mapped_bytes > sizes.allocated {
        return Err(NtfsDiscoveryError::UnsupportedDataStorage {
            reason: "$MFT runlist maps more bytes than its allocation size",
        });
    }
    Ok(MftBootstrap {
        runlist,
        allocated_bytes: sizes.allocated,
        data_bytes: sizes.data,
        initialized_bytes: sizes.initialized,
        mapping_complete: mapped_bytes == sizes.allocated,
        record_zero_sequence_number: record_zero.sequence_number,
    })
}

fn parse_mft_record_attributes<'a>(
    record: &'a NtfsFileRecord,
    boot: &NtfsBootSector,
    limits: NtfsDiscoveryLimits,
) -> Result<crate::fs::ntfs_attribute::NtfsAttributeList<'a>, NtfsDiscoveryError> {
    Ok(parse_attribute_list(
        record.repaired_bytes(),
        usize::from(record.attributes_offset),
        usize::try_from(record.bytes_in_use).map_err(|_| NtfsDiscoveryError::GeometryOverflow {
            calculation: "$MFT record bytes in use",
        })?,
        AttributeLimits {
            cluster_size_bytes: boot.cluster_size_bytes,
            max_attribute_bytes: limits.max_attribute_bytes,
            max_name_code_units: limits.max_name_code_units,
            max_attributes: limits.max_attributes,
        },
    )?)
}

fn unnamed_mft_data_from_record(
    attributes: &[NtfsAttribute<'_>],
    boot: &NtfsBootSector,
    limits: NtfsDiscoveryLimits,
) -> Result<(NtfsRunlist, crate::fs::ntfs_attribute::NonResidentSizes), NtfsDiscoveryError> {
    let mut first = None;
    let mut continuations = Vec::new();
    for attribute in attributes {
        let Some(data) = unnamed_nonresident_mft_data(attribute)? else {
            continue;
        };
        if data.lowest_vcn == 0 {
            if first.is_some() {
                return Err(NtfsDiscoveryError::DuplicateUnnamedData);
            }
            let sizes = data
                .sizes
                .ok_or(NtfsDiscoveryError::UnsupportedDataStorage {
                    reason: "$MFT first data extent has no size evidence",
                })?;
            let runlist = parse_unnamed_mft_data_runlist(data, boot, limits, 0)?;
            first = Some((runlist, sizes));
            continue;
        }
        continuations.push(data);
    }
    let Some((mut runlist, sizes)) = first else {
        return Err(NtfsDiscoveryError::MissingUnnamedData);
    };
    continuations.sort_by_key(|data| data.lowest_vcn);
    for data in continuations {
        if data.lowest_vcn < runlist.next_vcn {
            return Err(NtfsDiscoveryError::UnsupportedDataStorage {
                reason: "$MFT $DATA continuation overlaps a decoded VCN range",
            });
        }
        if data.lowest_vcn != runlist.next_vcn {
            return Err(NtfsDiscoveryError::UnsupportedDataStorage {
                reason: "$MFT $DATA continuation is not VCN-contiguous",
            });
        }
        let extra = parse_unnamed_mft_data_runlist(data, boot, limits, runlist.encoded_runs)?;
        append_mft_runlist(&mut runlist, extra)?;
    }
    if runlist.sparse_clusters != 0 {
        return Err(NtfsDiscoveryError::UnsupportedDataStorage {
            reason: "$MFT runlist contains sparse clusters",
        });
    }
    Ok((runlist, sizes))
}

const fn unnamed_nonresident_mft_data<'a>(
    attribute: &'a NtfsAttribute<'a>,
) -> Result<Option<&'a crate::fs::ntfs_attribute::NonResidentAttribute<'a>>, NtfsDiscoveryError> {
    if attribute.attribute_type != DATA_ATTRIBUTE_TYPE || attribute.name.is_some() {
        return Ok(None);
    }
    let AttributeBody::NonResident(data) = &attribute.body else {
        return Err(NtfsDiscoveryError::UnsupportedDataStorage {
            reason: "$MFT unnamed $DATA is resident",
        });
    };
    if attribute.flags.is_compressed() || attribute.flags.encrypted || attribute.flags.sparse {
        return Err(NtfsDiscoveryError::UnsupportedDataStorage {
            reason: "$MFT unnamed $DATA is compressed, encrypted, or sparse",
        });
    }
    Ok(Some(data))
}

fn parse_unnamed_mft_data_runlist(
    data: &crate::fs::ntfs_attribute::NonResidentAttribute<'_>,
    boot: &NtfsBootSector,
    limits: NtfsDiscoveryLimits,
    encoded_runs: usize,
) -> Result<NtfsRunlist, NtfsDiscoveryError> {
    let remaining_runs = limits.max_runs.saturating_sub(encoded_runs);
    if remaining_runs == 0 {
        return Err(NtfsDiscoveryError::UnsupportedDataStorage {
            reason: "$MFT $DATA mapping exceeds the caller run cap",
        });
    }
    Ok(parse_mapping_pairs(
        data.mapping_pairs,
        MappingPairsLimits {
            starting_vcn: data.lowest_vcn,
            expected_next_vcn: Some(data.expected_next_vcn),
            volume_cluster_count: boot.cluster_count,
            max_runs: remaining_runs,
            max_decoded_clusters: boot.cluster_count,
        },
    )?)
}

fn append_mft_runlist(
    into: &mut NtfsRunlist,
    extra: NtfsRunlist,
) -> Result<(), NtfsDiscoveryError> {
    append_mft_stream_runlist(into, extra, "$MFT $DATA continuation is not VCN-contiguous")
}

fn append_mft_stream_runlist(
    into: &mut NtfsRunlist,
    extra: NtfsRunlist,
    noncontiguous_reason: &'static str,
) -> Result<(), NtfsDiscoveryError> {
    let found_vcn = extra
        .extents
        .first()
        .map_or(extra.next_vcn, |extent| extent.vcn);
    if found_vcn != into.next_vcn {
        return Err(NtfsDiscoveryError::UnsupportedDataStorage {
            reason: noncontiguous_reason,
        });
    }
    into.extents.extend(extra.extents);
    into.next_vcn = extra.next_vcn;
    into.encoded_runs = into.encoded_runs.checked_add(extra.encoded_runs).ok_or(
        NtfsDiscoveryError::GeometryOverflow {
            calculation: "$MFT concatenated run count",
        },
    )?;
    into.bytes_consumed = into
        .bytes_consumed
        .checked_add(extra.bytes_consumed)
        .ok_or(NtfsDiscoveryError::GeometryOverflow {
            calculation: "$MFT concatenated mapping-pair bytes",
        })?;
    into.decoded_clusters = into
        .decoded_clusters
        .checked_add(extra.decoded_clusters)
        .ok_or(NtfsDiscoveryError::GeometryOverflow {
            calculation: "$MFT concatenated decoded clusters",
        })?;
    into.physical_clusters = into
        .physical_clusters
        .checked_add(extra.physical_clusters)
        .ok_or(NtfsDiscoveryError::GeometryOverflow {
            calculation: "$MFT concatenated physical clusters",
        })?;
    into.sparse_clusters = into
        .sparse_clusters
        .checked_add(extra.sparse_clusters)
        .ok_or(NtfsDiscoveryError::GeometryOverflow {
            calculation: "$MFT concatenated sparse clusters",
        })?;
    Ok(())
}

fn validate_mft_start(
    runlist: &NtfsRunlist,
    boot: &NtfsBootSector,
) -> Result<(), NtfsDiscoveryError> {
    let first_extent = runlist.extents.first();
    let first_lcn = first_extent.and_then(|extent| match extent.location {
        ExtentLocation::Physical { lcn } if extent.vcn == 0 => Some(lcn),
        _ => None,
    });
    if first_lcn != Some(boot.mft_lcn) {
        return Err(NtfsDiscoveryError::MftStartMismatch {
            boot_lcn: boot.mft_lcn,
            runlist_lcn: first_lcn,
        });
    }
    let first_extent_bytes = first_extent
        .and_then(|extent| extent.length.checked_mul(boot.cluster_size_bytes))
        .ok_or(NtfsDiscoveryError::GeometryOverflow {
            calculation: "$MFT first-extent byte length",
        })?;
    if first_extent_bytes < boot.mft_record_size.bytes {
        return Err(NtfsDiscoveryError::MftRecordOutsideMapping { record_number: 0 });
    }
    Ok(())
}

fn mapped_byte_length(
    runlist: &NtfsRunlist,
    boot: &NtfsBootSector,
) -> Result<u64, NtfsDiscoveryError> {
    runlist.next_vcn.checked_mul(boot.cluster_size_bytes).ok_or(
        NtfsDiscoveryError::GeometryOverflow {
            calculation: "$MFT mapped byte length",
        },
    )
}

fn refresh_mft_mapping_complete(
    mft: &mut MftBootstrap,
    boot: &NtfsBootSector,
) -> Result<(), NtfsDiscoveryError> {
    let mapped_bytes = mapped_byte_length(&mft.runlist, boot)?;
    if mapped_bytes > mft.allocated_bytes {
        return Err(NtfsDiscoveryError::UnsupportedDataStorage {
            reason: "$MFT runlist maps more bytes than its allocation size",
        });
    }
    mft.mapping_complete = mapped_bytes == mft.allocated_bytes;
    Ok(())
}

fn extend_mft_mapping_from_attribute_list(
    image: &dyn BoundedImageReader,
    boot: &NtfsBootSector,
    limits: NtfsDiscoveryLimits,
    record_zero: &NtfsFileRecord,
    record_size: usize,
    budget: &mut ReadBudget,
    mft: &mut MftBootstrap,
) -> Result<(), NtfsDiscoveryError> {
    if mft.mapping_complete {
        return Ok(());
    }
    let Some(value) =
        mft_attribute_list_value(image, boot, limits, record_zero, record_size, budget, mft)?
    else {
        return Ok(());
    };
    let entries =
        parse_attribute_list_value(&value, limits.max_attributes, limits.max_name_code_units)
            .map_err(|_| NtfsDiscoveryError::UnsupportedDataStorage {
                reason: "$MFT $ATTRIBUTE_LIST is malformed",
            })?;
    let expected_base = MftReference {
        record_number: 0,
        sequence_number: record_zero.sequence_number,
    };
    let mut consumed = 0_usize;
    while !mft.mapping_complete {
        let Some(entry) = next_unnamed_mft_data_entry(&entries, mft.runlist.next_vcn) else {
            return Ok(());
        };
        if entry.file_reference.record_number == 0 {
            return Err(NtfsDiscoveryError::UnsupportedDataStorage {
                reason: "$MFT $ATTRIBUTE_LIST names a record-zero $DATA continuation that was not present",
            });
        }
        if !record_is_mapped(mft, boot, entry.file_reference.record_number)? {
            return Ok(());
        }
        consumed = consumed
            .checked_add(1)
            .ok_or(NtfsDiscoveryError::GeometryOverflow {
                calculation: "$MFT $ATTRIBUTE_LIST continuation count",
            })?;
        if consumed > entries.len() {
            return Err(NtfsDiscoveryError::UnsupportedDataStorage {
                reason: "$MFT $ATTRIBUTE_LIST $DATA continuations do not make forward progress",
            });
        }
        budget.charge(boot.mft_record_size.bytes)?;
        let host = read_mft_record_inner(
            image,
            boot,
            mft,
            entry.file_reference.record_number,
            record_size,
        )?;
        validate_record_identity(&host, entry.file_reference.record_number)?;
        validate_mft_extension_host(&host, entry, expected_base)?;
        let host_attributes = parse_mft_record_attributes(&host, boot, limits)?;
        let extra = unnamed_mft_data_for_list_entry(
            &host_attributes.attributes,
            entry,
            boot,
            limits,
            mft.runlist.encoded_runs,
        )?;
        append_mft_runlist(&mut mft.runlist, extra)?;
        if mft.runlist.sparse_clusters != 0 {
            return Err(NtfsDiscoveryError::UnsupportedDataStorage {
                reason: "$MFT runlist contains sparse clusters",
            });
        }
        refresh_mft_mapping_complete(mft, boot)?;
    }
    Ok(())
}

/// Where record zero stores its unnamed `$ATTRIBUTE_LIST` value.
enum MftAttributeListSource<'a> {
    Resident(&'a [u8]),
    NonResident {
        /// Concatenated record-zero extents; may still stop short of `data_bytes`.
        runlist: NtfsRunlist,
        data_bytes: u64,
    },
}

/// Returns the complete `$ATTRIBUTE_LIST` value of record zero, or `None` when record zero has no
/// list or a VCN-split list's continuation host is not yet inside the decoded `$MFT` mapping.
///
/// List clusters are volume LCNs, so a non-resident value is read directly from the image; only a
/// continuation *attribute* hosted in an extension record depends on the `$MFT` map.
fn mft_attribute_list_value(
    image: &dyn BoundedImageReader,
    boot: &NtfsBootSector,
    limits: NtfsDiscoveryLimits,
    record_zero: &NtfsFileRecord,
    record_size: usize,
    budget: &mut ReadBudget,
    mft: &MftBootstrap,
) -> Result<Option<Vec<u8>>, NtfsDiscoveryError> {
    let attributes = parse_mft_record_attributes(record_zero, boot, limits)?;
    let Some(source) = mft_attribute_list_source(&attributes.attributes, boot, limits)? else {
        return Ok(None);
    };
    match source {
        MftAttributeListSource::Resident(value) => Ok(Some(value.to_vec())),
        MftAttributeListSource::NonResident {
            mut runlist,
            data_bytes,
        } => {
            if !complete_mft_attribute_list_runlist(
                image,
                boot,
                limits,
                record_zero,
                record_size,
                budget,
                mft,
                &mut runlist,
                data_bytes,
            )? {
                return Ok(None);
            }
            Ok(Some(read_runlist_prefix(
                image,
                boot,
                &runlist,
                data_bytes,
                budget,
                "$MFT $ATTRIBUTE_LIST",
            )?))
        }
    }
}

fn mft_attribute_list_source<'a>(
    attributes: &'a [NtfsAttribute<'a>],
    boot: &NtfsBootSector,
    limits: NtfsDiscoveryLimits,
) -> Result<Option<MftAttributeListSource<'a>>, NtfsDiscoveryError> {
    let mut resident = None;
    let mut first = None;
    let mut continuations = Vec::new();
    for attribute in attributes {
        let Some(list) = unnamed_mft_attribute_list(attribute)? else {
            continue;
        };
        match list {
            AttributeBody::Resident(body) => {
                if resident.is_some() || first.is_some() {
                    return Err(NtfsDiscoveryError::UnsupportedDataStorage {
                        reason: "$MFT record zero has multiple $ATTRIBUTE_LIST attributes",
                    });
                }
                resident = Some(body.value);
            }
            AttributeBody::NonResident(data) if data.lowest_vcn == 0 => {
                if resident.is_some() || first.is_some() {
                    return Err(NtfsDiscoveryError::UnsupportedDataStorage {
                        reason: "$MFT record zero has multiple $ATTRIBUTE_LIST attributes",
                    });
                }
                first = Some(data);
            }
            AttributeBody::NonResident(data) => continuations.push(data),
        }
    }
    if let Some(value) = resident {
        if !continuations.is_empty() {
            return Err(NtfsDiscoveryError::UnsupportedDataStorage {
                reason: "$MFT resident $ATTRIBUTE_LIST has a non-resident continuation",
            });
        }
        return Ok(Some(MftAttributeListSource::Resident(value)));
    }
    let Some(first) = first else {
        if continuations.is_empty() {
            return Ok(None);
        }
        return Err(NtfsDiscoveryError::UnsupportedDataStorage {
            reason: "$MFT $ATTRIBUTE_LIST continuation has no first extent",
        });
    };
    let sizes = first
        .sizes
        .ok_or(NtfsDiscoveryError::UnsupportedDataStorage {
            reason: "$MFT $ATTRIBUTE_LIST first extent has no size evidence",
        })?;
    if sizes.data > sizes.allocated || sizes.initialized < sizes.data {
        return Err(NtfsDiscoveryError::UnsupportedDataStorage {
            reason: "$MFT $ATTRIBUTE_LIST size fields are inconsistent",
        });
    }
    if usize::try_from(sizes.data).map_or(true, |bytes| bytes > limits.max_attribute_bytes) {
        return Err(NtfsDiscoveryError::UnsupportedDataStorage {
            reason: "$MFT $ATTRIBUTE_LIST exceeds the caller attribute cap",
        });
    }
    let mut runlist = parse_mft_attribute_list_runlist(first, boot, limits, 0)?;
    continuations.sort_by_key(|data| data.lowest_vcn);
    for data in continuations {
        let extra = parse_mft_attribute_list_runlist(data, boot, limits, runlist.encoded_runs)?;
        append_mft_stream_runlist(
            &mut runlist,
            extra,
            "$MFT $ATTRIBUTE_LIST continuation is not VCN-contiguous",
        )?;
    }
    if mapped_byte_length(&runlist, boot)? > sizes.allocated {
        return Err(NtfsDiscoveryError::UnsupportedDataStorage {
            reason: "$MFT $ATTRIBUTE_LIST runlist maps more bytes than its allocation size",
        });
    }
    Ok(Some(MftAttributeListSource::NonResident {
        runlist,
        data_bytes: sizes.data,
    }))
}

const fn unnamed_mft_attribute_list<'a>(
    attribute: &'a NtfsAttribute<'a>,
) -> Result<Option<&'a AttributeBody<'a>>, NtfsDiscoveryError> {
    if attribute.attribute_type != ATTRIBUTE_LIST_TYPE || attribute.name.is_some() {
        return Ok(None);
    }
    if attribute.flags.is_compressed() || attribute.flags.encrypted || attribute.flags.sparse {
        return Err(NtfsDiscoveryError::UnsupportedDataStorage {
            reason: "$MFT $ATTRIBUTE_LIST is compressed, encrypted, or sparse",
        });
    }
    Ok(Some(&attribute.body))
}

fn parse_mft_attribute_list_runlist(
    data: &crate::fs::ntfs_attribute::NonResidentAttribute<'_>,
    boot: &NtfsBootSector,
    limits: NtfsDiscoveryLimits,
    encoded_runs: usize,
) -> Result<NtfsRunlist, NtfsDiscoveryError> {
    let remaining_runs = limits.max_runs.saturating_sub(encoded_runs);
    if remaining_runs == 0 {
        return Err(NtfsDiscoveryError::UnsupportedDataStorage {
            reason: "$MFT $ATTRIBUTE_LIST mapping exceeds the caller run cap",
        });
    }
    let runlist = parse_mapping_pairs(
        data.mapping_pairs,
        MappingPairsLimits {
            starting_vcn: data.lowest_vcn,
            expected_next_vcn: Some(data.expected_next_vcn),
            volume_cluster_count: boot.cluster_count,
            max_runs: remaining_runs,
            max_decoded_clusters: boot.cluster_count,
        },
    )?;
    if runlist.sparse_clusters != 0 {
        return Err(NtfsDiscoveryError::UnsupportedDataStorage {
            reason: "$MFT $ATTRIBUTE_LIST runlist contains sparse clusters",
        });
    }
    Ok(runlist)
}

/// Follows VCN-split `$ATTRIBUTE_LIST` continuation attributes hosted in already-mapped
/// extension records until the list runlist covers `data_bytes`.
///
/// Returns `Ok(false)` when the next continuation host is not yet inside the `$MFT` mapping.
#[allow(clippy::too_many_arguments)]
fn complete_mft_attribute_list_runlist(
    image: &dyn BoundedImageReader,
    boot: &NtfsBootSector,
    limits: NtfsDiscoveryLimits,
    record_zero: &NtfsFileRecord,
    record_size: usize,
    budget: &mut ReadBudget,
    mft: &MftBootstrap,
    runlist: &mut NtfsRunlist,
    data_bytes: u64,
) -> Result<bool, NtfsDiscoveryError> {
    let expected_base = MftReference {
        record_number: 0,
        sequence_number: record_zero.sequence_number,
    };
    let mut followed = 0_usize;
    while mapped_byte_length(runlist, boot)? < data_bytes {
        followed = followed
            .checked_add(1)
            .ok_or(NtfsDiscoveryError::GeometryOverflow {
                calculation: "$MFT $ATTRIBUTE_LIST continuation count",
            })?;
        if followed > limits.max_attributes {
            return Err(NtfsDiscoveryError::UnsupportedDataStorage {
                reason: "$MFT $ATTRIBUTE_LIST continuations exceed the caller attribute cap",
            });
        }
        let mapped_bytes = mapped_byte_length(runlist, boot)?;
        let prefix = read_runlist_prefix(
            image,
            boot,
            runlist,
            mapped_bytes.min(data_bytes),
            budget,
            "$MFT $ATTRIBUTE_LIST prefix",
        )?;
        let entries =
            parse_attribute_list_prefix(&prefix, limits.max_attributes, limits.max_name_code_units)
                .map_err(|_| NtfsDiscoveryError::UnsupportedDataStorage {
                    reason: "$MFT $ATTRIBUTE_LIST is malformed",
                })?;
        let Some(entry) = entries.iter().find(|entry| {
            entry.attribute_type == ATTRIBUTE_LIST_TYPE
                && entry.name.is_empty()
                && entry.lowest_vcn == runlist.next_vcn
        }) else {
            return Err(NtfsDiscoveryError::UnsupportedDataStorage {
                reason: "$MFT $ATTRIBUTE_LIST mapping does not cover its data and names no continuation",
            });
        };
        if entry.file_reference.record_number == 0 {
            return Err(NtfsDiscoveryError::UnsupportedDataStorage {
                reason: "$MFT $ATTRIBUTE_LIST names a record-zero continuation that was not present",
            });
        }
        if !record_is_mapped(mft, boot, entry.file_reference.record_number)? {
            return Ok(false);
        }
        budget.charge(boot.mft_record_size.bytes)?;
        let host = read_mft_record_inner(
            image,
            boot,
            mft,
            entry.file_reference.record_number,
            record_size,
        )?;
        validate_record_identity(&host, entry.file_reference.record_number)?;
        validate_mft_extension_host(&host, entry, expected_base)?;
        let host_attributes = parse_mft_record_attributes(&host, boot, limits)?;
        let extra = mft_attribute_list_extent_for_entry(
            &host_attributes.attributes,
            entry,
            boot,
            limits,
            runlist.encoded_runs,
        )?;
        append_mft_stream_runlist(
            runlist,
            extra,
            "$MFT $ATTRIBUTE_LIST continuation is not VCN-contiguous",
        )?;
    }
    Ok(true)
}

fn mft_attribute_list_extent_for_entry(
    attributes: &[NtfsAttribute<'_>],
    entry: &AttributeListEntry,
    boot: &NtfsBootSector,
    limits: NtfsDiscoveryLimits,
    encoded_runs: usize,
) -> Result<NtfsRunlist, NtfsDiscoveryError> {
    let mut selected = None;
    for attribute in attributes {
        if attribute.id != entry.instance {
            continue;
        }
        let Some(AttributeBody::NonResident(data)) = unnamed_mft_attribute_list(attribute)? else {
            continue;
        };
        if data.lowest_vcn != entry.lowest_vcn {
            continue;
        }
        if selected.is_some() {
            return Err(NtfsDiscoveryError::UnsupportedDataStorage {
                reason: "$MFT $ATTRIBUTE_LIST continuation matched multiple attributes",
            });
        }
        selected = Some(parse_mft_attribute_list_runlist(
            data,
            boot,
            limits,
            encoded_runs,
        )?);
    }
    selected.ok_or(NtfsDiscoveryError::UnsupportedDataStorage {
        reason: "$MFT $ATTRIBUTE_LIST names a continuation extent that is not present",
    })
}

/// Reads the first `byte_len` logical bytes of a physical-only runlist.
fn read_runlist_prefix(
    image: &dyn BoundedImageReader,
    boot: &NtfsBootSector,
    runlist: &NtfsRunlist,
    byte_len: u64,
    budget: &mut ReadBudget,
    what: &'static str,
) -> Result<Vec<u8>, NtfsDiscoveryError> {
    if byte_len > mapped_byte_length(runlist, boot)? {
        return Err(NtfsDiscoveryError::UnsupportedDataStorage {
            reason: "$MFT stream read exceeds its decoded mapping",
        });
    }
    let len = usize::try_from(byte_len)
        .map_err(|_| NtfsDiscoveryError::UnsupportedRecordSize { bytes: byte_len })?;
    budget.charge(byte_len)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(len)
        .map_err(|_| NtfsDiscoveryError::UnsupportedDataStorage {
            reason: "could not allocate bounded $MFT stream storage",
        })?;
    output.resize(len, 0);
    let mut written = 0_usize;
    for extent in &runlist.extents {
        if written >= len {
            break;
        }
        let ExtentLocation::Physical { lcn } = extent.location else {
            return Err(NtfsDiscoveryError::UnsupportedDataStorage {
                reason: "$MFT stream prefix intersects a sparse extent",
            });
        };
        let extent_bytes = extent
            .length
            .checked_mul(boot.cluster_size_bytes)
            .ok_or(NtfsDiscoveryError::GeometryOverflow { calculation: what })?;
        let chunk = usize::try_from(extent_bytes)
            .unwrap_or(usize::MAX)
            .min(len - written);
        let physical = lcn
            .checked_mul(boot.cluster_size_bytes)
            .ok_or(NtfsDiscoveryError::GeometryOverflow { calculation: what })?;
        read_chunked(image, physical, &mut output[written..written + chunk])?;
        written += chunk;
    }
    if written != len {
        return Err(NtfsDiscoveryError::UnsupportedDataStorage {
            reason: "$MFT stream mapping ended before its declared prefix",
        });
    }
    Ok(output)
}

fn next_unnamed_mft_data_entry(
    entries: &[AttributeListEntry],
    next_vcn: u64,
) -> Option<&AttributeListEntry> {
    entries.iter().find(|entry| {
        entry.attribute_type == DATA_ATTRIBUTE_TYPE
            && entry.name.is_empty()
            && entry.lowest_vcn == next_vcn
    })
}

fn validate_mft_extension_host(
    host: &NtfsFileRecord,
    entry: &AttributeListEntry,
    expected_base: MftReference,
) -> Result<(), NtfsDiscoveryError> {
    if !host.flags.is_in_use() {
        return Err(NtfsDiscoveryError::UnsupportedDataStorage {
            reason: "$MFT extension record is not marked in use",
        });
    }
    if host.sequence_number != entry.file_reference.sequence_number {
        return Err(NtfsDiscoveryError::UnsupportedDataStorage {
            reason: "$MFT extension record sequence mismatch",
        });
    }
    if host.base_record != Some(expected_base) {
        return Err(NtfsDiscoveryError::UnsupportedDataStorage {
            reason: "$MFT extension record is not an extension of record zero",
        });
    }
    Ok(())
}

fn unnamed_mft_data_for_list_entry(
    attributes: &[NtfsAttribute<'_>],
    entry: &AttributeListEntry,
    boot: &NtfsBootSector,
    limits: NtfsDiscoveryLimits,
    encoded_runs: usize,
) -> Result<NtfsRunlist, NtfsDiscoveryError> {
    let mut selected = None;
    for attribute in attributes {
        if attribute.attribute_type != DATA_ATTRIBUTE_TYPE
            || attribute.name.is_some()
            || attribute.id != entry.instance
        {
            continue;
        }
        let Some(data) = unnamed_nonresident_mft_data(attribute)? else {
            continue;
        };
        if data.lowest_vcn != entry.lowest_vcn {
            continue;
        }
        if selected.is_some() {
            return Err(NtfsDiscoveryError::UnsupportedDataStorage {
                reason: "$MFT $ATTRIBUTE_LIST $DATA continuation matched multiple attributes",
            });
        }
        selected = Some(parse_unnamed_mft_data_runlist(
            data,
            boot,
            limits,
            encoded_runs,
        )?);
    }
    selected.ok_or(NtfsDiscoveryError::UnsupportedDataStorage {
        reason: "$MFT $ATTRIBUTE_LIST names a $DATA extent that is not present",
    })
}

fn mft_mirror_profile(boot: &NtfsBootSector) -> Result<(u64, u64, u64), NtfsDiscoveryError> {
    // NTFS-3G bootsect.c at d327833e derives four records unless a larger cluster can contain more,
    // then uses one cluster's record count. Its mount-time comparison stops at FILE_first_user (16)
    // because current Windows may leave the remaining mirror slots stale.
    let minimum_bytes = MIN_MFT_MIRROR_RECORDS
        .checked_mul(boot.mft_record_size.bytes)
        .ok_or(NtfsDiscoveryError::GeometryOverflow {
            calculation: "$MFTMirr minimum byte length",
        })?;
    let stored_records = if boot.cluster_size_bytes <= minimum_bytes {
        MIN_MFT_MIRROR_RECORDS
    } else {
        boot.cluster_size_bytes / boot.mft_record_size.bytes
    };
    let compared_records = stored_records.min(FIRST_USER_MFT_RECORD);
    let data_bytes = stored_records
        .checked_mul(boot.mft_record_size.bytes)
        .ok_or(NtfsDiscoveryError::GeometryOverflow {
            calculation: "$MFTMirr logical data length",
        })?;
    Ok((stored_records, compared_records, data_bytes))
}

/// Builds the `$MFTMirr` mapping from record one, following its `$ATTRIBUTE_LIST` when present.
///
/// Returns `Ok(None)` when the list names a continuation host outside the decoded `$MFT` mapping;
/// the caller then reports mirror evidence as incomplete instead of claiming compatibility.
fn parse_mft_mirror_mapping(
    image: &dyn BoundedImageReader,
    boot: &NtfsBootSector,
    mft: &MftBootstrap,
    record_one: &NtfsFileRecord,
    limits: NtfsDiscoveryLimits,
    budget: &mut ReadBudget,
) -> Result<Option<MftMirrorMapping>, NtfsDiscoveryError> {
    if !record_one.flags.is_in_use() {
        return Err(NtfsDiscoveryError::UnsupportedMftMirrorStorage {
            reason: "$MFTMirr record one is not marked in use",
        });
    }
    let own = parse_mft_record_attributes(record_one, boot, limits)?;
    let has_attribute_list = own
        .attributes
        .iter()
        .any(|attribute| attribute.attribute_type == ATTRIBUTE_LIST_TYPE);
    if !has_attribute_list {
        return parse_mft_mirror_data(&own.attributes, boot, limits).map(Some);
    }

    let remaining = budget.remaining();
    if remaining == 0 {
        return Err(NtfsDiscoveryError::ByteLimitExceeded {
            requested_total: budget.used.saturating_add(1),
            maximum: budget.maximum,
        });
    }
    let list_limits = AttributeListLimits {
        max_attributes_per_record: limits.max_attributes,
        max_attribute_bytes: limits.max_attribute_bytes,
        max_name_code_units: limits.max_name_code_units,
        max_runs: limits.max_runs,
        max_read_bytes: remaining,
        ..AttributeListLimits::default()
    };
    let resolved = match resolve_attribute_list_with_reader(
        image,
        boot,
        mft,
        SystemRecordKind::MftMirror.record_number(),
        record_one,
        list_limits,
    ) {
        Ok(resolved) => resolved,
        Err(AttributeListError::Discovery(NtfsDiscoveryError::MftRecordOutsideMapping {
            ..
        })) => return Ok(None),
        Err(AttributeListError::Discovery(error)) => return Err(error),
        Err(error) => return Err(NtfsDiscoveryError::MftMirrorAttributeList(Box::new(error))),
    };
    budget.charge(resolved.bytes_read)?;
    let attribute_limits = AttributeLimits {
        cluster_size_bytes: boot.cluster_size_bytes,
        max_attribute_bytes: limits.max_attribute_bytes,
        max_name_code_units: limits.max_name_code_units,
        max_attributes: limits.max_attributes,
    };
    let attributes = resolved
        .extents
        .iter()
        .map(|extent| parse_attribute(&extent.raw_attribute, attribute_limits))
        .collect::<Result<Vec<_>, _>>()?;
    parse_mft_mirror_data(&attributes, boot, limits).map(Some)
}

/// Interprets the complete attribute set of `$MFTMirr`, concatenating VCN-split `$DATA` extents.
#[allow(clippy::too_many_lines)]
fn parse_mft_mirror_data(
    attributes: &[NtfsAttribute<'_>],
    boot: &NtfsBootSector,
    limits: NtfsDiscoveryLimits,
) -> Result<MftMirrorMapping, NtfsDiscoveryError> {
    let (geometry_records, _, _) = mft_mirror_profile(boot)?;
    let mut selected = None;
    let mut continuations = Vec::new();
    for attribute in attributes {
        if attribute.attribute_type != DATA_ATTRIBUTE_TYPE || attribute.name.is_some() {
            continue;
        }
        let AttributeBody::NonResident(data) = &attribute.body else {
            return Err(NtfsDiscoveryError::UnsupportedMftMirrorStorage {
                reason: "$MFTMirr unnamed $DATA is resident",
            });
        };
        if attribute.flags.is_compressed() || attribute.flags.encrypted || attribute.flags.sparse {
            return Err(NtfsDiscoveryError::UnsupportedMftMirrorStorage {
                reason: "$MFTMirr unnamed $DATA is compressed, encrypted, or sparse",
            });
        }
        if data.lowest_vcn != 0 {
            continuations.push((attribute, data));
            continue;
        }
        if selected.is_some() {
            return Err(NtfsDiscoveryError::DuplicateMftMirrorData);
        }
        let sizes = data
            .sizes
            .ok_or(NtfsDiscoveryError::UnsupportedMftMirrorStorage {
                reason: "$MFTMirr first data extent has no size evidence",
            })?;
        let runlist = parse_mapping_pairs(
            data.mapping_pairs,
            MappingPairsLimits {
                starting_vcn: data.lowest_vcn,
                expected_next_vcn: Some(data.expected_next_vcn),
                volume_cluster_count: boot.cluster_count,
                max_runs: limits.max_runs,
                max_decoded_clusters: boot.cluster_count,
            },
        )?;
        selected = Some((attribute, runlist, sizes));
    }

    let Some((first, mut runlist, sizes)) = selected else {
        return Err(NtfsDiscoveryError::MissingMftMirrorData);
    };
    continuations.sort_by_key(|(_, data)| data.lowest_vcn);
    for (attribute, data) in continuations {
        if attribute.flags != first.flags {
            return Err(NtfsDiscoveryError::UnsupportedMftMirrorStorage {
                reason: "$MFTMirr $DATA continuation changes the attribute flags",
            });
        }
        let remaining_runs = limits
            .max_runs
            .checked_sub(runlist.encoded_runs)
            .filter(|remaining| *remaining > 0)
            .ok_or(NtfsDiscoveryError::MappingPairs(
                MappingPairsError::RunLimitExceeded {
                    maximum: limits.max_runs,
                },
            ))?;
        let extra = parse_mapping_pairs(
            data.mapping_pairs,
            MappingPairsLimits {
                starting_vcn: data.lowest_vcn,
                expected_next_vcn: Some(data.expected_next_vcn),
                volume_cluster_count: boot.cluster_count,
                max_runs: remaining_runs,
                max_decoded_clusters: boot.cluster_count,
            },
        )?;
        append_mft_stream_runlist(
            &mut runlist,
            extra,
            "$MFTMirr $DATA continuation is not VCN-contiguous",
        )?;
    }
    if runlist.sparse_clusters != 0 {
        return Err(NtfsDiscoveryError::UnsupportedMftMirrorStorage {
            reason: "$MFTMirr runlist contains sparse clusters",
        });
    }
    let first_lcn = runlist.extents.first().and_then(|extent| {
        if extent.vcn != 0 {
            return None;
        }
        match extent.location {
            ExtentLocation::Physical { lcn } => Some(lcn),
            ExtentLocation::Sparse => None,
        }
    });
    if first_lcn != Some(boot.mft_mirror_lcn) {
        return Err(NtfsDiscoveryError::MftMirrorStartMismatch {
            boot_lcn: boot.mft_mirror_lcn,
            runlist_lcn: first_lcn,
        });
    }
    if sizes.data % boot.mft_record_size.bytes != 0 {
        return Err(NtfsDiscoveryError::MftMirrorSizeMismatch {
            field: "record-aligned data size",
            expected: sizes.data / boot.mft_record_size.bytes * boot.mft_record_size.bytes,
            actual: sizes.data,
        });
    }
    let stored_records = sizes.data / boot.mft_record_size.bytes;
    if stored_records < MIN_MFT_MIRROR_RECORDS {
        return Err(NtfsDiscoveryError::MftMirrorSizeMismatch {
            field: "complete FILE-record count",
            expected: MIN_MFT_MIRROR_RECORDS,
            actual: stored_records,
        });
    }
    // NTFS-3G accepts a short, complete-record read from $MFTMirr and reduces its runtime mirror
    // count. StarConverter does the same for source compatibility, while its serializer emits the
    // canonical geometry-sized profile.
    let records_to_compare = stored_records
        .min(geometry_records)
        .min(FIRST_USER_MFT_RECORD);
    let compared_bytes = records_to_compare
        .checked_mul(boot.mft_record_size.bytes)
        .ok_or(NtfsDiscoveryError::GeometryOverflow {
            calculation: "$MFTMirr compared byte length",
        })?;
    if sizes.initialized < compared_bytes {
        return Err(NtfsDiscoveryError::MftMirrorSizeMismatch {
            field: "initialized comparison bytes",
            expected: compared_bytes,
            actual: sizes.initialized,
        });
    }
    let mapped_bytes = runlist
        .next_vcn
        .checked_mul(boot.cluster_size_bytes)
        .ok_or(NtfsDiscoveryError::GeometryOverflow {
            calculation: "$MFTMirr mapped byte length",
        })?;
    if mapped_bytes != sizes.allocated {
        return Err(NtfsDiscoveryError::UnsupportedMftMirrorStorage {
            reason: "$MFTMirr base record does not map its complete allocation",
        });
    }
    if mapped_bytes < sizes.data {
        return Err(NtfsDiscoveryError::UnsupportedMftMirrorStorage {
            reason: "$MFTMirr runlist does not cover its logical data",
        });
    }
    Ok(MftMirrorMapping {
        runlist,
        data_bytes: sizes.data,
        records_to_compare,
    })
}

fn validate_record_identity(
    record: &NtfsFileRecord,
    expected: u64,
) -> Result<(), NtfsDiscoveryError> {
    if let Some(found) = record.record_number {
        if u64::from(found) != expected {
            return Err(NtfsDiscoveryError::RecordNumberMismatch {
                expected,
                found: u64::from(found),
            });
        }
    }
    Ok(())
}

fn record_range(
    boot: &NtfsBootSector,
    record_number: u64,
) -> Result<(u64, u64), NtfsDiscoveryError> {
    let start = record_number
        .checked_mul(boot.mft_record_size.bytes)
        .ok_or(NtfsDiscoveryError::GeometryOverflow {
            calculation: "$MFT record logical offset",
        })?;
    let end = start.checked_add(boot.mft_record_size.bytes).ok_or(
        NtfsDiscoveryError::GeometryOverflow {
            calculation: "$MFT record logical end",
        },
    )?;
    Ok((start, end))
}

fn record_is_mapped(
    mft: &MftBootstrap,
    boot: &NtfsBootSector,
    record_number: u64,
) -> Result<bool, NtfsDiscoveryError> {
    let (_, end) = record_range(boot, record_number)?;
    let mapped_end = mft
        .runlist
        .next_vcn
        .checked_mul(boot.cluster_size_bytes)
        .ok_or(NtfsDiscoveryError::GeometryOverflow {
            calculation: "$MFT mapped byte end",
        })?;
    Ok(end <= mapped_end && end <= mft.data_bytes && end <= mft.initialized_bytes)
}

fn read_mft_record_inner(
    image: &dyn BoundedImageReader,
    boot: &NtfsBootSector,
    mft: &MftBootstrap,
    record_number: u64,
    record_size: usize,
) -> Result<NtfsFileRecord, NtfsDiscoveryError> {
    let output = read_mft_record_bytes_inner(image, boot, mft, record_number, record_size)?;
    Ok(parse_file_record(&output)?)
}

fn read_mft_record_bytes_inner(
    image: &dyn BoundedImageReader,
    boot: &NtfsBootSector,
    mft: &MftBootstrap,
    record_number: u64,
    record_size: usize,
) -> Result<Vec<u8>, NtfsDiscoveryError> {
    if !record_is_mapped(mft, boot, record_number)? {
        return Err(NtfsDiscoveryError::MftRecordOutsideMapping { record_number });
    }
    let (start, end) = record_range(boot, record_number)?;
    let mut output = vec![0_u8; record_size];
    let mut logical = start;
    let mut output_offset = 0_usize;
    for extent in &mft.runlist.extents {
        let extent_start = extent.vcn.checked_mul(boot.cluster_size_bytes).ok_or(
            NtfsDiscoveryError::GeometryOverflow {
                calculation: "$MFT extent logical offset",
            },
        )?;
        let extent_bytes = extent.length.checked_mul(boot.cluster_size_bytes).ok_or(
            NtfsDiscoveryError::GeometryOverflow {
                calculation: "$MFT extent byte length",
            },
        )?;
        let extent_end =
            extent_start
                .checked_add(extent_bytes)
                .ok_or(NtfsDiscoveryError::GeometryOverflow {
                    calculation: "$MFT extent logical end",
                })?;
        if logical >= end {
            break;
        }
        if logical < extent_start || logical >= extent_end {
            continue;
        }
        let chunk_end = end.min(extent_end);
        let chunk_len_u64 = chunk_end - logical;
        let chunk_len = usize::try_from(chunk_len_u64).map_err(|_| {
            NtfsDiscoveryError::UnsupportedRecordSize {
                bytes: chunk_len_u64,
            }
        })?;
        let within_extent = logical - extent_start;
        let ExtentLocation::Physical { lcn } = extent.location else {
            return Err(NtfsDiscoveryError::SparseMftRange { record_number });
        };
        let physical_start = lcn
            .checked_mul(boot.cluster_size_bytes)
            .and_then(|base| base.checked_add(within_extent))
            .ok_or(NtfsDiscoveryError::GeometryOverflow {
                calculation: "$MFT physical record offset",
            })?;
        read_chunked(
            image,
            physical_start,
            &mut output[output_offset..output_offset + chunk_len],
        )?;
        logical = chunk_end;
        output_offset += chunk_len;
    }
    if logical != end || output_offset != record_size {
        return Err(NtfsDiscoveryError::MftRecordOutsideMapping { record_number });
    }
    Ok(output)
}

fn validate_mft_mirror(
    image: &dyn BoundedImageReader,
    boot: &NtfsBootSector,
    mft: &MftBootstrap,
    mirror_mapping: Option<&MftMirrorMapping>,
    limits: NtfsDiscoveryLimits,
    record_size: usize,
    budget: &mut ReadBudget,
) -> Result<MftMirrorEvidence, NtfsDiscoveryError> {
    if limits.max_records < usize::try_from(MIN_MFT_MIRROR_RECORDS).unwrap_or(usize::MAX) {
        return Ok(MftMirrorEvidence::Incomplete {
            reason: IncompleteReason::RecordLimit,
        });
    }
    let Some(mirror_mapping) = mirror_mapping else {
        return Ok(MftMirrorEvidence::Incomplete {
            reason: IncompleteReason::MappingContinuationRequired,
        });
    };
    let (geometry_records, _, _) = mft_mirror_profile(boot)?;
    // NTFS-3G first reads the full geometry-derived record count from `$MFT`, even though semantic
    // mirror comparison stops before FILE_first_user. Do not claim clean compatibility unless the
    // complete source range is mapped, logically present, and initialized.
    if geometry_records == 0 || !record_is_mapped(mft, boot, geometry_records - 1)? {
        return Ok(MftMirrorEvidence::Incomplete {
            reason: IncompleteReason::MappingContinuationRequired,
        });
    }
    let compared_records = mirror_mapping.records_to_compare;
    let required_records =
        usize::try_from(compared_records).map_err(|_| NtfsDiscoveryError::GeometryOverflow {
            calculation: "$MFTMirr protected record count",
        })?;
    if limits.max_records < required_records {
        return Ok(MftMirrorEvidence::Incomplete {
            reason: IncompleteReason::RecordLimit,
        });
    }
    for record_number in 0..compared_records {
        if !record_is_mapped(mft, boot, record_number)? {
            return Ok(MftMirrorEvidence::Incomplete {
                reason: IncompleteReason::MappingContinuationRequired,
            });
        }
    }
    let mut bytes_compared = 0_u64;
    for record_number in 0..compared_records {
        budget.charge(boot.mft_record_size.bytes)?;
        let source = read_mft_record_inner(image, boot, mft, record_number, record_size)?;
        validate_record_identity(&source, record_number)?;
        budget.charge(boot.mft_record_size.bytes)?;
        let mirror_bytes = read_mft_mirror_record_bytes_inner(
            image,
            boot,
            mirror_mapping,
            record_number,
            record_size,
        )?;
        let mirror = parse_file_record(&mirror_bytes)?;
        validate_record_identity(&mirror, record_number)?;
        // Match NTFS-3G's repaired-record comparison through bytes_in_use. Comparing the allocated
        // tail would reject current Windows volumes whose unused mirror tail was not refreshed.
        let used = usize::try_from(source.bytes_in_use).map_err(|_| {
            NtfsDiscoveryError::GeometryOverflow {
                calculation: "$MFT used record byte length",
            }
        })?;
        let source_content = &source.repaired_bytes()[..used];
        let mirror_content = &mirror.repaired_bytes()[..used];
        if let Some(byte_offset) = source_content
            .iter()
            .zip(mirror_content)
            .position(|(source_byte, mirror_byte)| source_byte != mirror_byte)
        {
            return Ok(MftMirrorEvidence::Mismatch {
                record_number,
                byte_offset_within_record: u64::try_from(byte_offset).map_err(|_| {
                    NtfsDiscoveryError::GeometryOverflow {
                        calculation: "$MFTMirr mismatch byte offset",
                    }
                })?,
            });
        }
        bytes_compared = bytes_compared
            .checked_add(u64::from(source.bytes_in_use))
            .ok_or(NtfsDiscoveryError::GeometryOverflow {
                calculation: "$MFTMirr compared byte count",
            })?;
    }

    Ok(MftMirrorEvidence::Exact {
        records_compared: compared_records,
        bytes_compared,
    })
}

fn read_mft_mirror_record_bytes_inner(
    image: &dyn BoundedImageReader,
    boot: &NtfsBootSector,
    mirror: &MftMirrorMapping,
    record_number: u64,
    record_size: usize,
) -> Result<Vec<u8>, NtfsDiscoveryError> {
    let start = record_number
        .checked_mul(boot.mft_record_size.bytes)
        .ok_or(NtfsDiscoveryError::GeometryOverflow {
            calculation: "$MFTMirr record logical offset",
        })?;
    let end = start.checked_add(boot.mft_record_size.bytes).ok_or(
        NtfsDiscoveryError::GeometryOverflow {
            calculation: "$MFTMirr record logical end",
        },
    )?;
    if end > mirror.data_bytes {
        return Err(NtfsDiscoveryError::UnsupportedMftMirrorStorage {
            reason: "$MFTMirr record lies beyond its logical data size",
        });
    }
    let mut output = vec![0_u8; record_size];
    let mut logical = start;
    let mut output_offset = 0_usize;
    for extent in &mirror.runlist.extents {
        let extent_start = extent.vcn.checked_mul(boot.cluster_size_bytes).ok_or(
            NtfsDiscoveryError::GeometryOverflow {
                calculation: "$MFTMirr extent logical offset",
            },
        )?;
        let extent_bytes = extent.length.checked_mul(boot.cluster_size_bytes).ok_or(
            NtfsDiscoveryError::GeometryOverflow {
                calculation: "$MFTMirr extent byte length",
            },
        )?;
        let extent_end =
            extent_start
                .checked_add(extent_bytes)
                .ok_or(NtfsDiscoveryError::GeometryOverflow {
                    calculation: "$MFTMirr extent logical end",
                })?;
        if logical >= end {
            break;
        }
        if logical < extent_start || logical >= extent_end {
            continue;
        }
        let chunk_end = end.min(extent_end);
        let chunk_len_u64 = chunk_end - logical;
        let chunk_len = usize::try_from(chunk_len_u64).map_err(|_| {
            NtfsDiscoveryError::UnsupportedRecordSize {
                bytes: chunk_len_u64,
            }
        })?;
        let within_extent = logical - extent_start;
        let ExtentLocation::Physical { lcn } = extent.location else {
            return Err(NtfsDiscoveryError::UnsupportedMftMirrorStorage {
                reason: "$MFTMirr record intersects a sparse extent",
            });
        };
        let physical_start = lcn
            .checked_mul(boot.cluster_size_bytes)
            .and_then(|base| base.checked_add(within_extent))
            .ok_or(NtfsDiscoveryError::GeometryOverflow {
                calculation: "$MFTMirr physical record offset",
            })?;
        read_chunked(
            image,
            physical_start,
            &mut output[output_offset..output_offset + chunk_len],
        )?;
        logical = chunk_end;
        output_offset += chunk_len;
    }
    if logical != end || output_offset != record_size {
        return Err(NtfsDiscoveryError::UnsupportedMftMirrorStorage {
            reason: "$MFTMirr runlist does not cover a compared record",
        });
    }
    Ok(output)
}

fn read_chunked(
    image: &dyn BoundedImageReader,
    mut offset: u64,
    mut destination: &mut [u8],
) -> Result<(), NtfsDiscoveryError> {
    while !destination.is_empty() {
        let count = destination.len().min(image.max_read_bytes());
        let chunk = image.read_exact_at(offset, count)?;
        destination[..count].copy_from_slice(&chunk);
        destination = &mut destination[count..];
        offset = offset
            .checked_add(u64::try_from(count).map_err(|_| {
                NtfsDiscoveryError::GeometryOverflow {
                    calculation: "chunked image read offset",
                }
            })?)
            .ok_or(NtfsDiscoveryError::GeometryOverflow {
                calculation: "chunked image read offset",
            })?;
    }
    Ok(())
}

struct ReadBudget {
    maximum: u64,
    used: u64,
}

impl ReadBudget {
    const fn new(maximum: u64) -> Self {
        Self { maximum, used: 0 }
    }

    const fn remaining(&self) -> u64 {
        self.maximum.saturating_sub(self.used)
    }

    fn charge(&mut self, amount: u64) -> Result<(), NtfsDiscoveryError> {
        let requested_total =
            self.used
                .checked_add(amount)
                .ok_or(NtfsDiscoveryError::GeometryOverflow {
                    calculation: "NTFS discovery byte budget",
                })?;
        if requested_total > self.maximum {
            return Err(NtfsDiscoveryError::ByteLimitExceeded {
                requested_total,
                maximum: self.maximum,
            });
        }
        self.used = requested_total;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::ntfs::{NtfsBootSector, RecordSize};
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    const CLUSTER_SIZE: usize = 4096;
    const RECORD_SIZE: usize = 1024;
    const MFT_LCN: u8 = 4;
    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TempImage(PathBuf);

    impl TempImage {
        fn create(bytes: &[u8]) -> Self {
            let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "starconverter-ntfs-discovery-{}-{sequence}.img",
                std::process::id()
            ));
            fs::write(&path, bytes).expect("create synthetic image");
            Self(path)
        }
    }

    impl Drop for TempImage {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    fn boot() -> NtfsBootSector {
        NtfsBootSector {
            bytes_per_sector: 512,
            sectors_per_cluster: 8,
            cluster_size_bytes: CLUSTER_SIZE as u64,
            declared_sectors: 512,
            cluster_count: 64,
            filesystem_bytes: 512 * 512,
            minimum_image_bytes: 513 * 512,
            mft_lcn: u64::from(MFT_LCN),
            mft_mirror_lcn: 32,
            mft_record_size: RecordSize {
                encoded: -10,
                bytes: RECORD_SIZE as u64,
            },
            index_buffer_size: RecordSize {
                encoded: -10,
                bytes: RECORD_SIZE as u64,
            },
            volume_serial_number: 1,
            boot_checksum: 0,
            media_descriptor: 0xf8,
            sectors_per_track: 63,
            head_count: 255,
            hidden_sectors: 0,
        }
    }

    fn synthetic_image(run_lcn: u8, run_clusters: u8, allocated_clusters: u64) -> Vec<u8> {
        let mut image = vec![0_u8; 513 * 512];
        let mft_offset = usize::from(run_lcn) * CLUSTER_SIZE;
        let record_zero = file_record(0, Some((run_lcn, run_clusters, allocated_clusters)));
        image[mft_offset..mft_offset + RECORD_SIZE].copy_from_slice(&record_zero);
        let record_one = file_record(1, Some((32, 1, 1)));
        image[mft_offset + RECORD_SIZE..mft_offset + 2 * RECORD_SIZE].copy_from_slice(&record_one);
        for record_number in [3_u32, 6] {
            let logical = usize::try_from(record_number).unwrap() * RECORD_SIZE;
            let offset = mft_offset + logical;
            image[offset..offset + RECORD_SIZE].copy_from_slice(&file_record(record_number, None));
        }
        let record_two_offset = mft_offset + 2 * RECORD_SIZE;
        image[record_two_offset..record_two_offset + RECORD_SIZE]
            .copy_from_slice(&file_record(2, None));
        let mirror_offset = 32 * CLUSTER_SIZE;
        image.copy_within(mft_offset..mft_offset + 4 * RECORD_SIZE, mirror_offset);
        image
    }

    fn fragmented_small_cluster_mirror() -> (NtfsBootSector, Vec<u8>) {
        const SMALL_CLUSTER: usize = 512;
        const SMALL_MFT_LCN: usize = 16;
        const SMALL_MIRROR_LCN: usize = 128;
        const SECOND_MIRROR_LCN: usize = 200;
        let boot = NtfsBootSector {
            bytes_per_sector: 512,
            sectors_per_cluster: 1,
            cluster_size_bytes: SMALL_CLUSTER as u64,
            declared_sectors: 512,
            cluster_count: 512,
            filesystem_bytes: 512 * 512,
            minimum_image_bytes: 513 * 512,
            mft_lcn: SMALL_MFT_LCN as u64,
            mft_mirror_lcn: SMALL_MIRROR_LCN as u64,
            mft_record_size: RecordSize {
                encoded: -10,
                bytes: RECORD_SIZE as u64,
            },
            index_buffer_size: RecordSize {
                encoded: -10,
                bytes: RECORD_SIZE as u64,
            },
            volume_serial_number: 2,
            boot_checksum: 0,
            media_descriptor: 0xf8,
            sectors_per_track: 63,
            head_count: 255,
            hidden_sectors: 0,
        };
        let mut image = vec![0_u8; 513 * 512];
        let mft_offset = SMALL_MFT_LCN * SMALL_CLUSTER;
        let record_zero = file_record_with_cluster(0, Some((16, 16, 16)), SMALL_CLUSTER);
        image[mft_offset..mft_offset + RECORD_SIZE].copy_from_slice(&record_zero);
        let mut record_one = file_record_with_cluster(1, Some((100, 8, 8)), SMALL_CLUSTER);
        let attribute = 56;
        set_i64(&mut record_one, attribute + 24, 7);
        record_one[attribute + 64..attribute + 72]
            .copy_from_slice(&[0x21, 3, 0x80, 0, 0x11, 5, 72, 0]);
        image[mft_offset + RECORD_SIZE..mft_offset + 2 * RECORD_SIZE].copy_from_slice(&record_one);
        for record_number in [2_u32, 3, 6] {
            let offset = mft_offset + usize::try_from(record_number).unwrap() * RECORD_SIZE;
            image[offset..offset + RECORD_SIZE].copy_from_slice(&file_record_with_cluster(
                record_number,
                None,
                SMALL_CLUSTER,
            ));
        }
        let first_mirror = SMALL_MIRROR_LCN * SMALL_CLUSTER;
        image.copy_within(mft_offset..mft_offset + 3 * SMALL_CLUSTER, first_mirror);
        let second_mirror = SECOND_MIRROR_LCN * SMALL_CLUSTER;
        image.copy_within(
            mft_offset + 3 * SMALL_CLUSTER..mft_offset + 4 * RECORD_SIZE,
            second_mirror,
        );
        (boot, image)
    }

    fn large_cluster_mirror() -> (NtfsBootSector, Vec<u8>) {
        const LARGE_CLUSTER: usize = 65_536;
        const LARGE_MFT_LCN: u8 = 4;
        const LARGE_MIRROR_LCN: u8 = 8;
        let cluster_count = 32_u64;
        let filesystem_bytes = cluster_count * LARGE_CLUSTER as u64;
        let boot = NtfsBootSector {
            bytes_per_sector: 512,
            sectors_per_cluster: 128,
            cluster_size_bytes: LARGE_CLUSTER as u64,
            declared_sectors: cluster_count * 128,
            cluster_count,
            filesystem_bytes,
            minimum_image_bytes: filesystem_bytes + 512,
            mft_lcn: u64::from(LARGE_MFT_LCN),
            mft_mirror_lcn: u64::from(LARGE_MIRROR_LCN),
            mft_record_size: RecordSize {
                encoded: -10,
                bytes: RECORD_SIZE as u64,
            },
            index_buffer_size: RecordSize {
                encoded: -10,
                bytes: RECORD_SIZE as u64,
            },
            volume_serial_number: 3,
            boot_checksum: 0,
            media_descriptor: 0xf8,
            sectors_per_track: 63,
            head_count: 255,
            hidden_sectors: 0,
        };
        let mut image = vec![0_u8; usize::try_from(filesystem_bytes + 512).unwrap()];
        let mft_offset = usize::from(LARGE_MFT_LCN) * LARGE_CLUSTER;
        for record_number in 0_u32..24 {
            let data = match record_number {
                0 => Some((LARGE_MFT_LCN, 1, 1)),
                1 => Some((LARGE_MIRROR_LCN, 1, 1)),
                _ => None,
            };
            let record = file_record_with_cluster(record_number, data, LARGE_CLUSTER);
            let offset = mft_offset + usize::try_from(record_number).unwrap() * RECORD_SIZE;
            image[offset..offset + RECORD_SIZE].copy_from_slice(&record);
        }
        let mirror_offset = usize::from(LARGE_MIRROR_LCN) * LARGE_CLUSTER;
        image.copy_within(mft_offset..mft_offset + LARGE_CLUSTER, mirror_offset);
        (boot, image)
    }

    fn file_record(record_number: u32, data: Option<(u8, u8, u64)>) -> Vec<u8> {
        file_record_with_cluster(record_number, data, CLUSTER_SIZE)
    }

    fn empty_file_record(record_number: u32, base: Option<(u64, u16)>) -> Vec<u8> {
        let mut record = vec![0_u8; RECORD_SIZE];
        record[0..4].copy_from_slice(b"FILE");
        set_u16(&mut record, 4, 48);
        set_u16(&mut record, 6, 3);
        set_u16(&mut record, 16, 1);
        set_u16(&mut record, 18, 1);
        set_u16(&mut record, 20, 56);
        set_u16(&mut record, 22, 1);
        set_u32(
            &mut record,
            28,
            u32::try_from(RECORD_SIZE).expect("record size fits u32"),
        );
        set_u32(&mut record, 44, record_number);
        if let Some((base_record, sequence)) = base {
            let raw = base_record | (u64::from(sequence) << 48);
            record[32..40].copy_from_slice(&raw.to_le_bytes());
        }
        record
    }

    fn write_unnamed_data(
        record: &mut [u8],
        offset: usize,
        lowest_vcn: u64,
        run: (u8, u8),
        allocated_clusters: u64,
        id: u16,
    ) -> usize {
        let (run_lcn, run_clusters) = run;
        set_u32(record, offset, DATA_ATTRIBUTE_TYPE);
        set_u32(record, offset + 4, 72);
        record[offset + 8] = 1;
        set_u16(record, offset + 14, id);
        set_i64(record, offset + 16, i64::try_from(lowest_vcn).unwrap());
        set_i64(
            record,
            offset + 24,
            i64::try_from(lowest_vcn + u64::from(run_clusters) - 1).unwrap(),
        );
        set_u16(record, offset + 32, 64);
        if lowest_vcn == 0 {
            let allocated = allocated_clusters * CLUSTER_SIZE as u64;
            let allocated = i64::try_from(allocated).expect("fixture allocation fits i64");
            set_i64(record, offset + 40, allocated);
            set_i64(record, offset + 48, allocated);
            set_i64(record, offset + 56, allocated);
        }
        record[offset + 64..offset + 68].copy_from_slice(&[0x11, run_clusters, run_lcn, 0]);
        offset + 72
    }

    fn write_resident_attribute_list(
        record: &mut [u8],
        offset: usize,
        value: &[u8],
        id: u16,
    ) -> usize {
        let length = 24 + value.len();
        set_u32(record, offset, ATTRIBUTE_LIST_TYPE);
        set_u32(record, offset + 4, u32::try_from(length).unwrap());
        set_u16(record, offset + 14, id);
        set_u32(record, offset + 16, u32::try_from(value.len()).unwrap());
        set_u16(record, offset + 20, 24);
        record[offset + 24..offset + 24 + value.len()].copy_from_slice(value);
        offset + length
    }

    /// Writes one non-resident unnamed `$ATTRIBUTE_LIST` extent mapping a single cluster.
    ///
    /// `sizes` is `(allocated_clusters, data_bytes)` for the first extent and `None` for a
    /// continuation extent, whose size fields are not authoritative.
    fn write_nonresident_attribute_list_extent(
        record: &mut [u8],
        offset: usize,
        lowest_vcn: u64,
        run_lcn: u8,
        sizes: Option<(u64, u64)>,
        id: u16,
    ) -> usize {
        set_u32(record, offset, ATTRIBUTE_LIST_TYPE);
        set_u32(record, offset + 4, 72);
        record[offset + 8] = 1;
        set_u16(record, offset + 14, id);
        set_i64(record, offset + 16, i64::try_from(lowest_vcn).unwrap());
        set_i64(record, offset + 24, i64::try_from(lowest_vcn).unwrap());
        set_u16(record, offset + 32, 64);
        if let Some((allocated_clusters, data_bytes)) = sizes {
            let allocated = i64::try_from(allocated_clusters * CLUSTER_SIZE as u64).unwrap();
            let data = i64::try_from(data_bytes).unwrap();
            set_i64(record, offset + 40, allocated);
            set_i64(record, offset + 48, data);
            set_i64(record, offset + 56, data);
        }
        record[offset + 64..offset + 68].copy_from_slice(&[0x11, 1, run_lcn, 0]);
        offset + 72
    }

    fn attribute_list_entry(
        attribute_type: u32,
        lowest_vcn: i64,
        record_number: u64,
        sequence: u16,
        instance: u16,
    ) -> Vec<u8> {
        let mut bytes = vec![0_u8; 32];
        bytes[0..4].copy_from_slice(&attribute_type.to_le_bytes());
        bytes[4..6].copy_from_slice(&32_u16.to_le_bytes());
        bytes[8..16].copy_from_slice(&lowest_vcn.to_le_bytes());
        let reference = record_number | (u64::from(sequence) << 48);
        bytes[16..24].copy_from_slice(&reference.to_le_bytes());
        bytes[24..26].copy_from_slice(&instance.to_le_bytes());
        bytes
    }

    fn named_data_list_entry(name_unit: u16, instance: u16) -> Vec<u8> {
        let mut bytes = attribute_list_entry(DATA_ATTRIBUTE_TYPE, 0, 0, 1, instance);
        bytes[6] = 1;
        bytes[7] = 26;
        bytes[26..28].copy_from_slice(&name_unit.to_le_bytes());
        bytes
    }

    /// Builds a list that needs two clusters: the two list extents, the two unnamed `$DATA`
    /// extents, and 128 named `$DATA` filler entries (one code unit each).
    ///
    /// `list_continuation` and `data_continuation` are `(record, instance)` hosts.
    fn oversized_mft_list(
        list_continuation: (u64, u16),
        data_first_instance: u16,
        data_continuation: (u64, u16),
    ) -> Vec<u8> {
        let mut list = attribute_list_entry(ATTRIBUTE_LIST_TYPE, 0, 0, 1, 0);
        list.extend(attribute_list_entry(
            ATTRIBUTE_LIST_TYPE,
            1,
            list_continuation.0,
            1,
            list_continuation.1,
        ));
        list.extend(attribute_list_entry(
            DATA_ATTRIBUTE_TYPE,
            0,
            0,
            1,
            data_first_instance,
        ));
        list.extend(attribute_list_entry(
            DATA_ATTRIBUTE_TYPE,
            1,
            data_continuation.0,
            1,
            data_continuation.1,
        ));
        for index in 0_u16..128 {
            list.extend(named_data_list_entry(0x41 + index, 16 + index));
        }
        assert!(list.len() > CLUSTER_SIZE && list.len() <= 2 * CLUSTER_SIZE);
        list
    }

    const LIST_LCN: u8 = 8;

    fn write_list_clusters(image: &mut [u8], list: &[u8]) {
        let offset = usize::from(LIST_LCN) * CLUSTER_SIZE;
        image[offset..offset + list.len()].copy_from_slice(list);
    }

    fn write_data_extension_record(image: &mut [u8], data_instance: u16) {
        let mft_offset = usize::from(MFT_LCN) * CLUSTER_SIZE;
        let mut extension = empty_file_record(2, Some((0, 1)));
        let end = write_unnamed_data(&mut extension, 56, 1, (MFT_LCN + 1, 1), 2, data_instance);
        finish_file_record(&mut extension, end, data_instance + 1);
        let record_two = mft_offset + 2 * RECORD_SIZE;
        image[record_two..record_two + RECORD_SIZE].copy_from_slice(&extension);
    }

    fn finish_file_record(record: &mut [u8], used: usize, next_id: u16) {
        set_u32(record, used, 0xffff_ffff);
        set_u32(record, 24, u32::try_from(used + 8).unwrap());
        set_u16(record, 40, next_id);
        let usn = 0xa55a;
        set_u16(record, 48, usn);
        set_u16(record, 50, 0);
        set_u16(record, 52, 0);
        set_u16(record, 510, usn);
        set_u16(record, 1022, usn);
    }

    fn refresh_mft_mirror(image: &mut [u8]) {
        let mft_offset = usize::from(MFT_LCN) * CLUSTER_SIZE;
        let mirror_offset = 32 * CLUSTER_SIZE;
        image.copy_within(mft_offset..mft_offset + 4 * RECORD_SIZE, mirror_offset);
    }

    fn synthetic_image_with_same_record_data_continuation() -> Vec<u8> {
        let mut image = synthetic_image(MFT_LCN, 1, 2);
        let mft_offset = usize::from(MFT_LCN) * CLUSTER_SIZE;
        let mut record = empty_file_record(0, None);
        let mut offset = 56;
        offset = write_unnamed_data(&mut record, offset, 0, (MFT_LCN, 1), 2, 0);
        offset = write_unnamed_data(&mut record, offset, 1, (MFT_LCN + 1, 1), 2, 1);
        finish_file_record(&mut record, offset, 2);
        image[mft_offset..mft_offset + RECORD_SIZE].copy_from_slice(&record);
        refresh_mft_mirror(&mut image);
        image
    }

    fn synthetic_image_with_resident_list_data_continuation() -> Vec<u8> {
        let mut image = synthetic_image(MFT_LCN, 1, 2);
        let mft_offset = usize::from(MFT_LCN) * CLUSTER_SIZE;
        let mut list = attribute_list_entry(DATA_ATTRIBUTE_TYPE, 0, 0, 1, 1);
        list.extend(attribute_list_entry(DATA_ATTRIBUTE_TYPE, 1, 2, 1, 0));
        let mut record_zero = empty_file_record(0, None);
        let mut offset = 56;
        offset = write_resident_attribute_list(&mut record_zero, offset, &list, 0);
        offset = write_unnamed_data(&mut record_zero, offset, 0, (MFT_LCN, 1), 2, 1);
        finish_file_record(&mut record_zero, offset, 2);
        image[mft_offset..mft_offset + RECORD_SIZE].copy_from_slice(&record_zero);

        let mut extension = empty_file_record(2, Some((0, 1)));
        let ext_end = write_unnamed_data(&mut extension, 56, 1, (MFT_LCN + 1, 1), 2, 0);
        finish_file_record(&mut extension, ext_end, 1);
        let record_two = mft_offset + 2 * RECORD_SIZE;
        image[record_two..record_two + RECORD_SIZE].copy_from_slice(&extension);
        refresh_mft_mirror(&mut image);
        image
    }

    /// Non-resident one-cluster list on volume clusters naming a `$DATA` continuation in record 2.
    fn synthetic_image_with_nonresident_list_data_continuation() -> (Vec<u8>, usize) {
        let mut image = synthetic_image(MFT_LCN, 1, 2);
        let mft_offset = usize::from(MFT_LCN) * CLUSTER_SIZE;
        let mut list = attribute_list_entry(DATA_ATTRIBUTE_TYPE, 0, 0, 1, 1);
        list.extend(attribute_list_entry(DATA_ATTRIBUTE_TYPE, 1, 2, 1, 0));
        write_list_clusters(&mut image, &list);
        let mut record = empty_file_record(0, None);
        let mut offset = 56;
        offset = write_nonresident_attribute_list_extent(
            &mut record,
            offset,
            0,
            LIST_LCN,
            Some((1, list.len() as u64)),
            0,
        );
        offset = write_unnamed_data(&mut record, offset, 0, (MFT_LCN, 1), 2, 1);
        finish_file_record(&mut record, offset, 2);
        image[mft_offset..mft_offset + RECORD_SIZE].copy_from_slice(&record);
        write_data_extension_record(&mut image, 0);
        refresh_mft_mirror(&mut image);
        (image, list.len())
    }

    /// Two-cluster list whose continuation extent sits in record zero beside the first extent.
    fn synthetic_image_with_split_list_in_record_zero() -> (Vec<u8>, usize) {
        let mut image = synthetic_image(MFT_LCN, 1, 2);
        let mft_offset = usize::from(MFT_LCN) * CLUSTER_SIZE;
        let list = oversized_mft_list((0, 1), 2, (2, 0));
        write_list_clusters(&mut image, &list);
        let mut record = empty_file_record(0, None);
        let mut offset = 56;
        offset = write_nonresident_attribute_list_extent(
            &mut record,
            offset,
            0,
            LIST_LCN,
            Some((2, list.len() as u64)),
            0,
        );
        offset =
            write_nonresident_attribute_list_extent(&mut record, offset, 1, LIST_LCN + 1, None, 1);
        offset = write_unnamed_data(&mut record, offset, 0, (MFT_LCN, 1), 2, 2);
        finish_file_record(&mut record, offset, 3);
        image[mft_offset..mft_offset + RECORD_SIZE].copy_from_slice(&record);
        write_data_extension_record(&mut image, 0);
        refresh_mft_mirror(&mut image);
        (image, list.len())
    }

    /// Two-cluster list whose continuation extent is hosted in extension record `host`.
    fn synthetic_image_with_split_list_hosted_in_extension(host: u64) -> (Vec<u8>, usize) {
        let mut image = synthetic_image(MFT_LCN, 1, 2);
        let mft_offset = usize::from(MFT_LCN) * CLUSTER_SIZE;
        let list = oversized_mft_list((host, 0), 1, (2, 1));
        write_list_clusters(&mut image, &list);
        let mut record = empty_file_record(0, None);
        let mut offset = 56;
        offset = write_nonresident_attribute_list_extent(
            &mut record,
            offset,
            0,
            LIST_LCN,
            Some((2, list.len() as u64)),
            0,
        );
        offset = write_unnamed_data(&mut record, offset, 0, (MFT_LCN, 1), 2, 1);
        finish_file_record(&mut record, offset, 2);
        image[mft_offset..mft_offset + RECORD_SIZE].copy_from_slice(&record);

        let mut extension = empty_file_record(2, Some((0, 1)));
        let mut end =
            write_nonresident_attribute_list_extent(&mut extension, 56, 1, LIST_LCN + 1, None, 0);
        end = write_unnamed_data(&mut extension, end, 1, (MFT_LCN + 1, 1), 2, 1);
        finish_file_record(&mut extension, end, 2);
        let record_two = mft_offset + 2 * RECORD_SIZE;
        image[record_two..record_two + RECORD_SIZE].copy_from_slice(&extension);
        refresh_mft_mirror(&mut image);
        (image, list.len())
    }

    /// Non-resident list whose first extent maps one of two allocated clusters while the list
    /// itself names no `$ATTRIBUTE_LIST` continuation.
    fn synthetic_image_with_uncovered_nonresident_list() -> Vec<u8> {
        let mut image = synthetic_image(MFT_LCN, 1, 2);
        let mft_offset = usize::from(MFT_LCN) * CLUSTER_SIZE;
        let mut list = attribute_list_entry(DATA_ATTRIBUTE_TYPE, 0, 0, 1, 1);
        list.extend(attribute_list_entry(DATA_ATTRIBUTE_TYPE, 1, 2, 1, 0));
        for index in 0_u16..128 {
            list.extend(named_data_list_entry(0x41 + index, 16 + index));
        }
        assert!(list.len() > CLUSTER_SIZE);
        write_list_clusters(&mut image, &list);
        let mut record = empty_file_record(0, None);
        let mut offset = 56;
        offset = write_nonresident_attribute_list_extent(
            &mut record,
            offset,
            0,
            LIST_LCN,
            Some((2, list.len() as u64)),
            0,
        );
        offset = write_unnamed_data(&mut record, offset, 0, (MFT_LCN, 1), 2, 1);
        finish_file_record(&mut record, offset, 2);
        image[mft_offset..mft_offset + RECORD_SIZE].copy_from_slice(&record);
        write_data_extension_record(&mut image, 0);
        refresh_mft_mirror(&mut image);
        image
    }

    fn synthetic_image_with_gapped_same_record_data_continuation() -> Vec<u8> {
        let mut image = synthetic_image(MFT_LCN, 1, 3);
        let mft_offset = usize::from(MFT_LCN) * CLUSTER_SIZE;
        let mut record = empty_file_record(0, None);
        let mut offset = 56;
        offset = write_unnamed_data(&mut record, offset, 0, (MFT_LCN, 1), 3, 0);
        offset = write_unnamed_data(&mut record, offset, 2, (MFT_LCN + 2, 1), 3, 1);
        finish_file_record(&mut record, offset, 2);
        image[mft_offset..mft_offset + RECORD_SIZE].copy_from_slice(&record);
        refresh_mft_mirror(&mut image);
        image
    }

    fn file_record_with_cluster(
        record_number: u32,
        data: Option<(u8, u8, u64)>,
        cluster_size: usize,
    ) -> Vec<u8> {
        let mut record = vec![0_u8; RECORD_SIZE];
        record[0..4].copy_from_slice(b"FILE");
        set_u16(&mut record, 4, 48);
        set_u16(&mut record, 6, 3);
        set_u16(&mut record, 16, 1);
        set_u16(&mut record, 18, 1);
        set_u16(&mut record, 20, 56);
        set_u16(&mut record, 22, 1);
        set_u32(
            &mut record,
            28,
            u32::try_from(RECORD_SIZE).expect("record size fits u32"),
        );
        set_u16(&mut record, 40, 1);
        set_u32(&mut record, 44, record_number);

        let used = if let Some((run_lcn, run_clusters, allocated_clusters)) = data {
            let attr = 56;
            set_u32(&mut record, attr, DATA_ATTRIBUTE_TYPE);
            set_u32(&mut record, attr + 4, 72);
            record[attr + 8] = 1;
            set_u16(&mut record, attr + 14, 0);
            set_i64(&mut record, attr + 16, 0);
            set_i64(&mut record, attr + 24, i64::from(run_clusters) - 1);
            set_u16(&mut record, attr + 32, 64);
            let allocated = allocated_clusters * cluster_size as u64;
            let allocated = i64::try_from(allocated).expect("fixture allocation fits i64");
            set_i64(&mut record, attr + 40, allocated);
            set_i64(&mut record, attr + 48, allocated);
            set_i64(&mut record, attr + 56, allocated);
            record[attr + 64..attr + 68].copy_from_slice(&[0x11, run_clusters, run_lcn, 0]);
            set_u32(&mut record, attr + 72, 0xffff_ffff);
            136
        } else {
            set_u32(&mut record, 56, 0xffff_ffff);
            64
        };
        set_u32(&mut record, 24, used);

        let usn = 0xa55a;
        set_u16(&mut record, 48, usn);
        set_u16(&mut record, 50, 0);
        set_u16(&mut record, 52, 0);
        set_u16(&mut record, 510, usn);
        set_u16(&mut record, 1022, usn);
        record
    }

    fn set_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn set_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn set_i64(bytes: &mut [u8], offset: usize, value: i64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn mirror_record_offset() -> usize {
        usize::from(MFT_LCN) * CLUSTER_SIZE + RECORD_SIZE
    }

    fn mirror_attribute_offset() -> usize {
        mirror_record_offset() + 56
    }

    fn replace_mirror_data_with_resident(bytes: &mut [u8]) {
        let record = mirror_record_offset();
        let attribute = mirror_attribute_offset();
        bytes[attribute..attribute + 160].fill(0);
        set_u32(bytes, attribute, DATA_ATTRIBUTE_TYPE);
        set_u32(bytes, attribute + 4, 32);
        set_u32(bytes, attribute + 16, 0);
        set_u16(bytes, attribute + 20, 24);
        set_u32(bytes, attribute + 32, 0xffff_ffff);
        set_u32(bytes, record + 24, 96);
    }

    fn make_extended_mirror_data(bytes: &mut [u8], flags: u16, compression_unit: u8) {
        let record = mirror_record_offset();
        let attribute = mirror_attribute_offset();
        bytes[attribute..attribute + 160].fill(0);
        set_u32(bytes, attribute, DATA_ATTRIBUTE_TYPE);
        set_u32(bytes, attribute + 4, 80);
        bytes[attribute + 8] = 1;
        set_u16(bytes, attribute + 12, flags);
        set_i64(bytes, attribute + 16, 0);
        let highest_vcn = if flags & 1 != 0 { 15 } else { 0 };
        set_i64(bytes, attribute + 24, highest_vcn);
        set_u16(bytes, attribute + 32, 72);
        bytes[attribute + 34] = compression_unit;
        let allocated = if flags & 1 != 0 { 65_536 } else { 4096 };
        set_i64(bytes, attribute + 40, allocated);
        set_i64(bytes, attribute + 48, 4096);
        set_i64(bytes, attribute + 56, 4096);
        set_i64(bytes, attribute + 64, 4096);
        bytes[attribute + 72..attribute + 76].copy_from_slice(&[0x11, 1, 32, 0]);
        set_u32(bytes, attribute + 80, 0xffff_ffff);
        set_u32(bytes, record + 24, 144);
    }

    #[test]
    fn bootstraps_and_identifies_first_pass_system_records() {
        let temp = TempImage::create(&synthetic_image(MFT_LCN, 2, 2));
        let image = ImageFile::open_with_limit(&temp.0, 257).unwrap();
        let discovery = discover_system_records(&image, &boot(), NtfsDiscoveryLimits::default())
            .expect("valid MFT discovery");

        assert!(discovery.mft.mapping_complete);
        assert_eq!(discovery.mft.runlist.extents.len(), 1);
        assert_eq!(discovery.bytes_read, 12 * RECORD_SIZE as u64);
        assert_eq!(discovery.system_records.len(), 3);
        assert!(discovery.system_records.iter().all(
            |item| matches!(item, SystemRecordEvidence::Found(identifier) if identifier.in_use)
        ));
        assert_eq!(
            discovery.mft_mirror,
            MftMirrorEvidence::Exact {
                records_compared: 4,
                bytes_compared: 400,
            }
        );
    }

    #[test]
    fn retains_exact_mft_mirror_mismatch_location() {
        let mut bytes = synthetic_image(MFT_LCN, 2, 2);
        let mirror_offset = 32 * CLUSTER_SIZE;
        bytes[mirror_offset + RECORD_SIZE + 73] ^= 0x40;
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();

        let discovery =
            discover_system_records(&image, &boot(), NtfsDiscoveryLimits::default()).unwrap();

        assert_eq!(
            discovery.mft_mirror,
            MftMirrorEvidence::Mismatch {
                record_number: 1,
                byte_offset_within_record: 73,
            }
        );
    }

    #[test]
    fn derives_large_cluster_mirror_storage_and_comparison_profile() {
        let mut boot = boot();
        boot.cluster_size_bytes = 65_536;

        assert_eq!(mft_mirror_profile(&boot).unwrap(), (64, 16, 65_536));
    }

    #[test]
    fn validates_large_cluster_mirror_and_caps_comparison_at_reserved_records() {
        let (boot, bytes) = large_cluster_mirror();
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open_with_limit(&temp.0, 257).unwrap();

        let discovery =
            discover_system_records(&image, &boot, NtfsDiscoveryLimits::default()).unwrap();

        assert_eq!(
            discovery.mft_mirror,
            MftMirrorEvidence::Exact {
                records_compared: 16,
                bytes_compared: 1168,
            }
        );
    }

    #[test]
    fn large_cluster_comparison_includes_record_fifteen_and_excludes_record_sixteen() {
        let (boot, baseline) = large_cluster_mirror();
        let mirror_offset = usize::try_from(boot.mft_mirror_lcn * boot.cluster_size_bytes).unwrap();
        for (record_number, expected) in [
            (
                15_u64,
                MftMirrorEvidence::Mismatch {
                    record_number: 15,
                    byte_offset_within_record: 55,
                },
            ),
            (
                16,
                MftMirrorEvidence::Exact {
                    records_compared: 16,
                    bytes_compared: 1168,
                },
            ),
        ] {
            let mut bytes = baseline.clone();
            bytes[mirror_offset + usize::try_from(record_number).unwrap() * RECORD_SIZE + 55] ^= 1;
            let temp = TempImage::create(&bytes);
            let image = ImageFile::open(&temp.0).unwrap();
            assert_eq!(
                discover_system_records(&image, &boot, NtfsDiscoveryLimits::default())
                    .unwrap()
                    .mft_mirror,
                expected
            );
        }
    }

    #[test]
    fn accepts_short_complete_record_mirror_profile_but_requires_full_geometry_mft() {
        let (boot, mut bytes) = large_cluster_mirror();
        let mft_offset = usize::try_from(boot.mft_lcn * boot.cluster_size_bytes).unwrap();
        let mirror_data = mft_offset + RECORD_SIZE + 56;
        set_i64(&mut bytes, mirror_data + 48, 4096);
        set_i64(&mut bytes, mirror_data + 56, 4096);
        let mirror_offset = usize::try_from(boot.mft_mirror_lcn * boot.cluster_size_bytes).unwrap();
        bytes.copy_within(mft_offset..mft_offset + 4 * RECORD_SIZE, mirror_offset);
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();
        assert!(matches!(
            discover_system_records(&image, &boot, NtfsDiscoveryLimits::default())
                .unwrap()
                .mft_mirror,
            MftMirrorEvidence::Exact {
                records_compared: 4,
                ..
            }
        ));

        let (boot, mut bytes) = large_cluster_mirror();
        let mft_offset = usize::try_from(boot.mft_lcn * boot.cluster_size_bytes).unwrap();
        let mft_data = mft_offset + 56;
        set_i64(&mut bytes, mft_data + 56, 16 * 1024);
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();
        assert_eq!(
            discover_system_records(&image, &boot, NtfsDiscoveryLimits::default())
                .unwrap()
                .mft_mirror,
            MftMirrorEvidence::Incomplete {
                reason: IncompleteReason::MappingContinuationRequired,
            }
        );
    }

    #[test]
    fn compares_fragmented_mft_mirror_through_record_one_runlist() {
        let (boot, bytes) = fragmented_small_cluster_mirror();
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open_with_limit(&temp.0, 193).unwrap();

        let discovery =
            discover_system_records(&image, &boot, NtfsDiscoveryLimits::default()).unwrap();

        assert!(matches!(
            discovery.mft_mirror,
            MftMirrorEvidence::Exact {
                records_compared: 4,
                ..
            }
        ));
    }

    #[test]
    fn rejects_missing_mft_mirror_data() {
        let mut bytes = synthetic_image(MFT_LCN, 2, 2);
        let record = mirror_record_offset();
        let attribute = mirror_attribute_offset();
        bytes[attribute..attribute + 160].fill(0);
        set_u32(&mut bytes, attribute, 0xffff_ffff);
        set_u32(&mut bytes, record + 24, 64);
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();

        assert!(matches!(
            discover_system_records(&image, &boot(), NtfsDiscoveryLimits::default()),
            Err(NtfsDiscoveryError::MissingMftMirrorData)
        ));
    }

    #[test]
    fn rejects_resident_mft_mirror_data() {
        let mut bytes = synthetic_image(MFT_LCN, 2, 2);
        replace_mirror_data_with_resident(&mut bytes);
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();

        assert!(matches!(
            discover_system_records(&image, &boot(), NtfsDiscoveryLimits::default()),
            Err(NtfsDiscoveryError::UnsupportedMftMirrorStorage {
                reason: "$MFTMirr unnamed $DATA is resident"
            })
        ));
    }

    #[test]
    fn rejects_duplicate_mft_mirror_data() {
        let mut bytes = synthetic_image(MFT_LCN, 2, 2);
        let record = mirror_record_offset();
        let attribute = mirror_attribute_offset();
        bytes.copy_within(attribute..attribute + 72, attribute + 72);
        set_u16(&mut bytes, attribute + 72 + 14, 1);
        set_u32(&mut bytes, attribute + 144, 0xffff_ffff);
        set_u32(&mut bytes, record + 24, 208);
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();

        assert!(matches!(
            discover_system_records(&image, &boot(), NtfsDiscoveryLimits::default()),
            Err(NtfsDiscoveryError::DuplicateMftMirrorData)
        ));
    }

    #[test]
    fn distinguishes_mft_mirror_continuation_from_duplicate_base_data() {
        let mut bytes = synthetic_image(MFT_LCN, 2, 2);
        let record = mirror_record_offset();
        let attribute = mirror_attribute_offset();
        bytes.copy_within(attribute..attribute + 72, attribute + 72);
        set_u16(&mut bytes, attribute + 72 + 14, 1);
        set_i64(&mut bytes, attribute + 72 + 16, 1);
        set_i64(&mut bytes, attribute + 72 + 24, 1);
        set_u32(&mut bytes, attribute + 144, 0xffff_ffff);
        set_u32(&mut bytes, record + 24, 208);
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();

        // The continuation is stitched onto the base extent; the combined mapping then exceeds the
        // declared allocation instead of being mistaken for a duplicate first extent.
        assert!(matches!(
            discover_system_records(&image, &boot(), NtfsDiscoveryLimits::default()),
            Err(NtfsDiscoveryError::UnsupportedMftMirrorStorage {
                reason: "$MFTMirr base record does not map its complete allocation"
            })
        ));
    }

    #[test]
    fn rejects_mft_mirror_continuation_without_first_extent() {
        let mut bytes = synthetic_image(MFT_LCN, 2, 2);
        let attribute = mirror_attribute_offset();
        set_i64(&mut bytes, attribute + 16, 1);
        set_i64(&mut bytes, attribute + 24, 1);
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();

        assert!(matches!(
            discover_system_records(&image, &boot(), NtfsDiscoveryLimits::default()),
            Err(NtfsDiscoveryError::MissingMftMirrorData)
        ));
    }

    /// Rewrites record one so its unnamed `$DATA` is reached only through a resident
    /// `$ATTRIBUTE_LIST`. `extents` lists `(lowest_vcn, run_lcn, host_record)`; the host is record
    /// one itself when it equals 1, otherwise an extension record is written there.
    fn synthetic_image_with_listed_mirror_data(
        allocated_clusters: u64,
        extents: &[(u64, u8, u64)],
    ) -> Vec<u8> {
        let mut image = synthetic_image(MFT_LCN, 2, 2);
        let mft_offset = usize::from(MFT_LCN) * CLUSTER_SIZE;
        let mut list = Vec::new();
        for (instance, (lowest_vcn, _, host)) in extents.iter().enumerate() {
            let instance = u16::try_from(instance).unwrap();
            let local_id = if *host == 1 { instance + 1 } else { instance };
            list.extend(attribute_list_entry(
                DATA_ATTRIBUTE_TYPE,
                i64::try_from(*lowest_vcn).unwrap(),
                *host,
                1,
                local_id,
            ));
        }
        let mut record_one = empty_file_record(1, None);
        let mut offset = write_resident_attribute_list(&mut record_one, 56, &list, 0);
        let mut next_id = 1_u16;
        for (instance, (lowest_vcn, run_lcn, host)) in extents.iter().enumerate() {
            let instance = u16::try_from(instance).unwrap();
            if *host == 1 {
                offset = write_unnamed_data(
                    &mut record_one,
                    offset,
                    *lowest_vcn,
                    (*run_lcn, 1),
                    allocated_clusters,
                    instance + 1,
                );
                next_id = instance + 2;
                continue;
            }
            let mut extension = empty_file_record(u32::try_from(*host).unwrap(), Some((1, 1)));
            let end = write_unnamed_data(
                &mut extension,
                56,
                *lowest_vcn,
                (*run_lcn, 1),
                allocated_clusters,
                instance,
            );
            finish_file_record(&mut extension, end, instance + 1);
            let host_offset = mft_offset + usize::try_from(*host).unwrap() * RECORD_SIZE;
            image[host_offset..host_offset + RECORD_SIZE].copy_from_slice(&extension);
        }
        finish_file_record(&mut record_one, offset, next_id);
        image[mft_offset + RECORD_SIZE..mft_offset + 2 * RECORD_SIZE].copy_from_slice(&record_one);
        refresh_mft_mirror(&mut image);
        image
    }

    #[test]
    fn follows_mft_mirror_data_behind_attribute_list_in_mapped_extension_record() {
        let bytes = synthetic_image_with_listed_mirror_data(1, &[(0, 32, 5)]);
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();

        let discovery =
            discover_system_records(&image, &boot(), NtfsDiscoveryLimits::default()).unwrap();

        assert!(matches!(
            discovery.mft_mirror,
            MftMirrorEvidence::Exact {
                records_compared: 4,
                ..
            }
        ));
    }

    #[test]
    fn concatenates_vcn_split_mft_mirror_data_across_records() {
        // VCN 0 stays in record one; VCN 1 lives in extension record 5 and maps LCN 33.
        let bytes = synthetic_image_with_listed_mirror_data(2, &[(0, 32, 1), (1, 33, 5)]);
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();

        let discovery =
            discover_system_records(&image, &boot(), NtfsDiscoveryLimits::default()).unwrap();

        assert!(matches!(
            discovery.mft_mirror,
            MftMirrorEvidence::Exact {
                records_compared: 4,
                ..
            }
        ));
    }

    #[test]
    fn leaves_mft_mirror_incomplete_when_list_host_is_unmapped() {
        // The `$MFT` maps records 0..8; the list sends the mirror `$DATA` to record 9.
        let bytes = synthetic_image_with_listed_mirror_data(1, &[(0, 32, 9)]);
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();

        let discovery =
            discover_system_records(&image, &boot(), NtfsDiscoveryLimits::default()).unwrap();

        assert_eq!(
            discovery.mft_mirror,
            MftMirrorEvidence::Incomplete {
                reason: IncompleteReason::MappingContinuationRequired,
            }
        );
    }

    #[test]
    fn rejects_non_contiguous_split_mft_mirror_data() {
        let bytes = synthetic_image_with_listed_mirror_data(3, &[(0, 32, 1), (2, 34, 5)]);
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();

        assert!(matches!(
            discover_system_records(&image, &boot(), NtfsDiscoveryLimits::default()),
            Err(NtfsDiscoveryError::UnsupportedDataStorage {
                reason: "$MFTMirr $DATA continuation is not VCN-contiguous"
            })
        ));
    }

    #[test]
    fn rejects_mft_mirror_record_that_is_not_in_use() {
        let mut bytes = synthetic_image(MFT_LCN, 2, 2);
        set_u16(&mut bytes, mirror_record_offset() + 22, 0);
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();

        assert!(matches!(
            discover_system_records(&image, &boot(), NtfsDiscoveryLimits::default()),
            Err(NtfsDiscoveryError::UnsupportedMftMirrorStorage {
                reason: "$MFTMirr record one is not marked in use"
            })
        ));
    }

    #[test]
    fn rejects_mft_mirror_boot_and_runlist_disagreement() {
        let mut bytes = synthetic_image(MFT_LCN, 2, 2);
        let mapping_lcn = mirror_attribute_offset() + 66;
        bytes[mapping_lcn] = 31;
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();

        assert!(matches!(
            discover_system_records(&image, &boot(), NtfsDiscoveryLimits::default()),
            Err(NtfsDiscoveryError::MftMirrorStartMismatch {
                boot_lcn: 32,
                runlist_lcn: Some(31)
            })
        ));
    }

    #[test]
    fn rejects_undersized_or_uninitialized_mft_mirror_comparison_range() {
        for (field_offset, field, expected, actual) in [
            (48, "complete FILE-record count", 4, 3),
            (56, "initialized comparison bytes", 4096, 3072),
        ] {
            let mut bytes = synthetic_image(MFT_LCN, 2, 2);
            let attribute = mirror_attribute_offset();
            set_i64(&mut bytes, attribute + field_offset, 3072);
            if field_offset == 48 {
                set_i64(&mut bytes, attribute + 56, 3072);
            }
            let temp = TempImage::create(&bytes);
            let image = ImageFile::open(&temp.0).unwrap();

            assert!(matches!(
                discover_system_records(&image, &boot(), NtfsDiscoveryLimits::default()),
                Err(NtfsDiscoveryError::MftMirrorSizeMismatch {
                    field: found,
                    expected: found_expected,
                    actual: found_actual
                }) if found == field
                    && found_expected == expected
                    && found_actual == actual
            ));
        }
    }

    #[test]
    fn rejects_partial_file_record_mirror_length() {
        let mut bytes = synthetic_image(MFT_LCN, 2, 2);
        let attribute = mirror_attribute_offset();
        set_i64(&mut bytes, attribute + 48, 3584);
        set_i64(&mut bytes, attribute + 56, 3584);
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();

        assert!(matches!(
            discover_system_records(&image, &boot(), NtfsDiscoveryLimits::default()),
            Err(NtfsDiscoveryError::MftMirrorSizeMismatch {
                field: "record-aligned data size",
                expected: 3072,
                actual: 3584,
            })
        ));
    }

    #[test]
    fn rejects_incomplete_mft_mirror_allocation_mapping() {
        let mut bytes = synthetic_image(MFT_LCN, 2, 2);
        let attribute = mirror_attribute_offset();
        set_i64(&mut bytes, attribute + 40, 8192);
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();

        assert!(matches!(
            discover_system_records(&image, &boot(), NtfsDiscoveryLimits::default()),
            Err(NtfsDiscoveryError::UnsupportedMftMirrorStorage {
                reason: "$MFTMirr base record does not map its complete allocation"
            })
        ));
    }

    #[test]
    fn accepts_completely_mapped_mft_mirror_overallocation() {
        let mut bytes = synthetic_image(MFT_LCN, 2, 2);
        let attribute = mirror_attribute_offset();
        set_i64(&mut bytes, attribute + 24, 1);
        set_i64(&mut bytes, attribute + 40, 8192);
        bytes[attribute + 65] = 2;
        let mft_offset = usize::from(MFT_LCN) * CLUSTER_SIZE;
        let mirror_offset = 32 * CLUSTER_SIZE;
        bytes.copy_within(mft_offset..mft_offset + 4 * RECORD_SIZE, mirror_offset);
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();

        assert!(matches!(
            discover_system_records(&image, &boot(), NtfsDiscoveryLimits::default())
                .unwrap()
                .mft_mirror,
            MftMirrorEvidence::Exact { .. }
        ));
    }

    #[test]
    fn rejects_encrypted_compressed_and_sparse_mft_mirror_data() {
        let mut fixtures = Vec::new();
        let mut encrypted = synthetic_image(MFT_LCN, 2, 2);
        set_u16(&mut encrypted, mirror_attribute_offset() + 12, 0x4000);
        fixtures.push(encrypted);
        let mut compressed = synthetic_image(MFT_LCN, 2, 2);
        make_extended_mirror_data(&mut compressed, 0x0001, 4);
        fixtures.push(compressed);
        let mut sparse = synthetic_image(MFT_LCN, 2, 2);
        make_extended_mirror_data(&mut sparse, 0x8000, 0);
        fixtures.push(sparse);

        for bytes in fixtures {
            let temp = TempImage::create(&bytes);
            let image = ImageFile::open(&temp.0).unwrap();
            assert!(matches!(
                discover_system_records(&image, &boot(), NtfsDiscoveryLimits::default()),
                Err(NtfsDiscoveryError::UnsupportedMftMirrorStorage {
                    reason: "$MFTMirr unnamed $DATA is compressed, encrypted, or sparse"
                })
            ));
        }
    }

    #[test]
    fn rejects_sparse_mft_mirror_mapping_without_sparse_attribute_flag() {
        let mut bytes = synthetic_image(MFT_LCN, 2, 2);
        let mapping = mirror_attribute_offset() + 64;
        bytes[mapping..mapping + 4].copy_from_slice(&[0x01, 1, 0, 0]);
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();

        assert!(matches!(
            discover_system_records(&image, &boot(), NtfsDiscoveryLimits::default()),
            Err(NtfsDiscoveryError::UnsupportedMftMirrorStorage {
                reason: "$MFTMirr runlist contains sparse clusters"
            })
        ));
    }

    #[test]
    fn rejects_malformed_mft_mirror_mapping_pairs() {
        let mut bytes = synthetic_image(MFT_LCN, 2, 2);
        bytes[mirror_attribute_offset() + 64] = 0x91;
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();

        assert!(matches!(
            discover_system_records(&image, &boot(), NtfsDiscoveryLimits::default()),
            Err(NtfsDiscoveryError::MappingPairs(
                MappingPairsError::FieldWidthTooLarge { .. }
            ))
        ));
    }

    #[test]
    fn exposes_incomplete_evidence_for_continuation_mapping() {
        let temp = TempImage::create(&synthetic_image(MFT_LCN, 1, 2));
        let image = ImageFile::open(&temp.0).unwrap();
        let discovery = discover_system_records(&image, &boot(), NtfsDiscoveryLimits::default())
            .expect("bounded partial discovery");

        assert!(!discovery.mft.mapping_complete);
        assert!(matches!(
            discovery.system_records[2],
            SystemRecordEvidence::Incomplete {
                kind: SystemRecordKind::Bitmap,
                reason: IncompleteReason::MappingContinuationRequired
            }
        ));
    }

    #[test]
    fn stitches_same_record_mft_data_continuation() {
        let temp = TempImage::create(&synthetic_image_with_same_record_data_continuation());
        let image = ImageFile::open_with_limit(&temp.0, 257).unwrap();
        let discovery = discover_system_records(&image, &boot(), NtfsDiscoveryLimits::default())
            .expect("same-record $MFT $DATA continuation");

        assert!(discovery.mft.mapping_complete);
        assert_eq!(discovery.mft.runlist.extents.len(), 2);
        assert_eq!(discovery.mft.runlist.next_vcn, 2);
        assert_eq!(discovery.bytes_read, 12 * RECORD_SIZE as u64);
        assert!(discovery.system_records.iter().all(|item| {
            matches!(item, SystemRecordEvidence::Found(identifier) if identifier.in_use)
        }));
        assert_eq!(
            discovery.mft_mirror,
            MftMirrorEvidence::Exact {
                records_compared: 4,
                bytes_compared: 472,
            }
        );
    }

    #[test]
    fn follows_resident_attribute_list_mft_data_continuation() {
        let temp = TempImage::create(&synthetic_image_with_resident_list_data_continuation());
        let image = ImageFile::open_with_limit(&temp.0, 257).unwrap();
        let discovery = discover_system_records(&image, &boot(), NtfsDiscoveryLimits::default())
            .expect("resident $ATTRIBUTE_LIST $MFT $DATA continuation");

        assert!(discovery.mft.mapping_complete);
        assert_eq!(discovery.mft.runlist.extents.len(), 2);
        assert_eq!(discovery.mft.runlist.next_vcn, 2);
        assert_eq!(discovery.bytes_read, 13 * RECORD_SIZE as u64);
        assert!(matches!(
            discovery.system_records[2],
            SystemRecordEvidence::Found(identifier)
                if identifier.kind == SystemRecordKind::Bitmap && identifier.in_use
        ));
        assert_eq!(
            discovery.mft_mirror,
            MftMirrorEvidence::Exact {
                records_compared: 4,
                bytes_compared: 560,
            }
        );
    }

    #[test]
    fn follows_nonresident_attribute_list_mft_data_continuation() {
        let (bytes, list_len) = synthetic_image_with_nonresident_list_data_continuation();
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open_with_limit(&temp.0, 257).unwrap();
        let discovery = discover_system_records(&image, &boot(), NtfsDiscoveryLimits::default())
            .expect("non-resident $MFT $ATTRIBUTE_LIST read from volume clusters");

        assert!(discovery.mft.mapping_complete);
        assert_eq!(discovery.mft.runlist.extents.len(), 2);
        assert_eq!(discovery.mft.runlist.next_vcn, 2);
        // record 0 + list value + host record 2 + 3 system records + 4 mirrored pairs
        assert_eq!(
            discovery.bytes_read,
            13 * RECORD_SIZE as u64 + list_len as u64
        );
        assert!(matches!(
            discovery.system_records[2],
            SystemRecordEvidence::Found(identifier)
                if identifier.kind == SystemRecordKind::Bitmap && identifier.in_use
        ));
    }

    #[test]
    fn stitches_split_mft_attribute_list_hosted_in_record_zero() {
        let (bytes, list_len) = synthetic_image_with_split_list_in_record_zero();
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open_with_limit(&temp.0, 257).unwrap();
        let discovery = discover_system_records(&image, &boot(), NtfsDiscoveryLimits::default())
            .expect("same-record VCN-split $MFT $ATTRIBUTE_LIST");

        assert!(discovery.mft.mapping_complete);
        assert_eq!(discovery.mft.runlist.next_vcn, 2);
        // No prefix read is needed when record zero already carries both list extents.
        assert_eq!(
            discovery.bytes_read,
            13 * RECORD_SIZE as u64 + list_len as u64
        );
    }

    #[test]
    fn follows_split_mft_attribute_list_hosted_in_mapped_extension_record() {
        let (bytes, list_len) = synthetic_image_with_split_list_hosted_in_extension(2);
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open_with_limit(&temp.0, 257).unwrap();
        let discovery = discover_system_records(&image, &boot(), NtfsDiscoveryLimits::default())
            .expect("extension-hosted VCN-split $MFT $ATTRIBUTE_LIST");

        assert!(discovery.mft.mapping_complete);
        assert_eq!(discovery.mft.runlist.next_vcn, 2);
        // record 0 + one-cluster prefix + host record 2 (list) + full list + host record 2
        // ($DATA) + 3 system records + 4 mirrored pairs
        assert_eq!(
            discovery.bytes_read,
            14 * RECORD_SIZE as u64 + CLUSTER_SIZE as u64 + list_len as u64
        );
    }

    #[test]
    fn leaves_mapping_incomplete_when_split_list_host_is_unmapped() {
        let (bytes, _) = synthetic_image_with_split_list_hosted_in_extension(5);
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();
        let discovery = discover_system_records(&image, &boot(), NtfsDiscoveryLimits::default())
            .expect("unmapped $ATTRIBUTE_LIST continuation host stays incomplete");

        assert!(!discovery.mft.mapping_complete);
        assert_eq!(discovery.mft.runlist.next_vcn, 1);
        assert!(matches!(
            discovery.system_records[2],
            SystemRecordEvidence::Incomplete {
                kind: SystemRecordKind::Bitmap,
                reason: IncompleteReason::MappingContinuationRequired
            }
        ));
    }

    #[test]
    fn rejects_nonresident_mft_attribute_list_that_names_no_continuation() {
        let temp = TempImage::create(&synthetic_image_with_uncovered_nonresident_list());
        let image = ImageFile::open(&temp.0).unwrap();

        assert!(matches!(
            discover_system_records(&image, &boot(), NtfsDiscoveryLimits::default()),
            Err(NtfsDiscoveryError::UnsupportedDataStorage {
                reason: "$MFT $ATTRIBUTE_LIST mapping does not cover its data and names no continuation"
            })
        ));
    }

    #[test]
    fn rejects_noncontiguous_same_record_mft_data_continuation() {
        let temp = TempImage::create(&synthetic_image_with_gapped_same_record_data_continuation());
        let image = ImageFile::open(&temp.0).unwrap();

        assert!(matches!(
            discover_system_records(&image, &boot(), NtfsDiscoveryLimits::default()),
            Err(NtfsDiscoveryError::UnsupportedDataStorage {
                reason: "$MFT $DATA continuation is not VCN-contiguous"
            })
        ));
    }

    #[test]
    fn exposes_record_cap_as_incomplete_evidence() {
        let temp = TempImage::create(&synthetic_image(MFT_LCN, 2, 2));
        let image = ImageFile::open(&temp.0).unwrap();
        let discovery = discover_system_records(
            &image,
            &boot(),
            NtfsDiscoveryLimits {
                max_records: 1,
                ..NtfsDiscoveryLimits::default()
            },
        )
        .unwrap();

        assert_eq!(discovery.bytes_read, RECORD_SIZE as u64);
        assert_eq!(
            discovery.mft_mirror,
            MftMirrorEvidence::Incomplete {
                reason: IncompleteReason::RecordLimit,
            }
        );
        assert!(discovery.system_records.iter().all(|item| matches!(
            item,
            SystemRecordEvidence::Incomplete {
                reason: IncompleteReason::RecordLimit,
                ..
            }
        )));
    }

    #[test]
    fn rejects_boot_and_runlist_start_disagreement() {
        let mut bytes = synthetic_image(MFT_LCN, 2, 2);
        let mapping_lcn_offset = usize::from(MFT_LCN) * CLUSTER_SIZE + 56 + 66;
        bytes[mapping_lcn_offset] = MFT_LCN + 1;
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();

        assert!(matches!(
            discover_system_records(&image, &boot(), NtfsDiscoveryLimits::default()),
            Err(NtfsDiscoveryError::MftStartMismatch {
                boot_lcn: 4,
                runlist_lcn: Some(5)
            })
        ));
    }

    #[test]
    fn rejects_embedded_record_number_mismatch() {
        let mut bytes = synthetic_image(MFT_LCN, 2, 2);
        let offset = usize::from(MFT_LCN) * CLUSTER_SIZE + 44;
        set_u32(&mut bytes, offset, 9);
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();

        assert!(matches!(
            discover_system_records(&image, &boot(), NtfsDiscoveryLimits::default()),
            Err(NtfsDiscoveryError::RecordNumberMismatch {
                expected: 0,
                found: 9
            })
        ));
    }

    #[test]
    fn enforces_aggregate_byte_cap_before_later_reads() {
        let temp = TempImage::create(&synthetic_image(MFT_LCN, 2, 2));
        let image = ImageFile::open(&temp.0).unwrap();
        let limits = NtfsDiscoveryLimits {
            max_bytes: RECORD_SIZE as u64,
            ..NtfsDiscoveryLimits::default()
        };

        assert!(matches!(
            discover_system_records(&image, &boot(), limits),
            Err(NtfsDiscoveryError::ByteLimitExceeded {
                requested_total: 2048,
                maximum: 1024
            })
        ));
    }

    #[test]
    fn enforces_mapping_pair_run_cap() {
        let mut bytes = synthetic_image(MFT_LCN, 2, 2);
        let mapping = usize::from(MFT_LCN) * CLUSTER_SIZE + 56 + 64;
        bytes[mapping..mapping + 8].copy_from_slice(&[0x11, 1, MFT_LCN, 0x11, 1, 1, 0, 0]);
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();
        let limits = NtfsDiscoveryLimits {
            max_runs: 1,
            ..NtfsDiscoveryLimits::default()
        };

        assert!(matches!(
            discover_system_records(&image, &boot(), limits),
            Err(NtfsDiscoveryError::MappingPairs(
                MappingPairsError::RunLimitExceeded { maximum: 1 }
            ))
        ));
    }

    #[test]
    fn rejects_record_zero_that_is_not_in_use() {
        let mut bytes = synthetic_image(MFT_LCN, 2, 2);
        let record_zero = usize::from(MFT_LCN) * CLUSTER_SIZE;
        set_u16(&mut bytes, record_zero + 22, 0);
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();

        assert!(matches!(
            discover_system_records(&image, &boot(), NtfsDiscoveryLimits::default()),
            Err(NtfsDiscoveryError::RecordZeroNotInUse)
        ));
    }

    #[test]
    fn rejects_resident_mft_data() {
        let mut bytes = synthetic_image(MFT_LCN, 2, 2);
        let record_zero = usize::from(MFT_LCN) * CLUSTER_SIZE;
        let attr = record_zero + 56;
        bytes[attr..record_zero + 136].fill(0);
        set_u32(&mut bytes, attr, DATA_ATTRIBUTE_TYPE);
        set_u32(&mut bytes, attr + 4, 32);
        set_u32(&mut bytes, attr + 16, 0);
        set_u16(&mut bytes, attr + 20, 24);
        set_u32(&mut bytes, attr + 32, 0xffff_ffff);
        set_u32(&mut bytes, record_zero + 24, 96);
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();

        assert!(matches!(
            discover_system_records(&image, &boot(), NtfsDiscoveryLimits::default()),
            Err(NtfsDiscoveryError::UnsupportedDataStorage {
                reason: "$MFT unnamed $DATA is resident"
            })
        ));
    }

    #[test]
    fn rejects_sparse_mft_mapping() {
        let mut bytes = synthetic_image(MFT_LCN, 2, 2);
        let mapping = usize::from(MFT_LCN) * CLUSTER_SIZE + 56 + 64;
        bytes[mapping..mapping + 8].copy_from_slice(&[0x01, 2, 0, 0, 0, 0, 0, 0]);
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();

        assert!(matches!(
            discover_system_records(&image, &boot(), NtfsDiscoveryLimits::default()),
            Err(NtfsDiscoveryError::UnsupportedDataStorage {
                reason: "$MFT runlist contains sparse clusters"
            })
        ));
    }

    #[test]
    fn arbitrary_reader_obeys_identity_and_mapping_bounds() {
        let temp = TempImage::create(&synthetic_image(MFT_LCN, 2, 2));
        let image = ImageFile::open(&temp.0).unwrap();
        let discovery =
            discover_system_records(&image, &boot(), NtfsDiscoveryLimits::default()).unwrap();
        let bitmap =
            read_mft_record(&image, &boot(), &discovery.mft, 6, RECORD_SIZE as u64).unwrap();
        assert_eq!(bitmap.record_number, Some(6));
        assert!(matches!(
            read_mft_record(&image, &boot(), &discovery.mft, 8, RECORD_SIZE as u64),
            Err(NtfsDiscoveryError::MftRecordOutsideMapping { record_number: 8 })
        ));
    }
}
