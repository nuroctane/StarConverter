//! Bounded, read-only NTFS object inventory.
//!
//! This layer walks initialized `$MFT` records through a previously validated bootstrap. It
//! inventories base records, names, data streams and directory indexes without opening a device
//! or exposing a write primitive. Unresolved `$ATTRIBUTE_LIST` continuations and caller caps are
//! retained as explicit incompleteness evidence.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

use crate::fs::ntfs::NtfsBootSector;
use crate::fs::ntfs_attribute::{
    AttributeBody, AttributeLimits, NtfsAttribute, NtfsAttributeError, parse_attribute,
    parse_attribute_list,
};
use crate::fs::ntfs_attribute_list::{
    AttributeListError, AttributeListLimits, ResolvedAttributeList,
    resolve_attribute_list_with_reader,
};
use crate::fs::ntfs_discovery::{
    MftBootstrap, NtfsDiscoveryError, read_mft_record_for_inventory_with_reader,
};
use crate::fs::ntfs_extend::ReparseIndexKey;
use crate::fs::ntfs_index::{
    FileNameNamespace, NtfsFileReference, NtfsIndexError, NtfsIndexLimits, NtfsIndexRoot,
    parse_index_block, parse_index_root,
};
use crate::fs::ntfs_record::NtfsFileRecord;
use crate::fs::ntfs_reparse_index::{read_reparse_index_block, read_reparse_index_root};
use crate::fs::ntfs_runlist::{
    ExtentLocation, MappingPairsError, MappingPairsLimits, NtfsExtent, NtfsRunlist,
    parse_mapping_pairs,
};
use crate::image::{BoundedImageReader, ImageError, ImageFile};

const STANDARD_INFORMATION: u32 = 0x10;
const ATTRIBUTE_LIST: u32 = 0x20;
const FILE_NAME: u32 = 0x30;
const VOLUME_NAME: u32 = 0x60;
const DATA: u32 = 0x80;
const INDEX_ROOT: u32 = 0x90;
const INDEX_ALLOCATION: u32 = 0xa0;
const BITMAP: u32 = 0xb0;
const REPARSE_POINT: u32 = 0xc0;
const FILE_NAME_MINIMUM: usize = 66;
const STANDARD_INFORMATION_MINIMUM: usize = 48;
const NTFS_VOLUME_RECORD: u64 = 3;
const NTFS_ROOT_RECORD: u64 = 5;
const NTFS_EXTEND_RECORD: u64 = 11;
const NTFS_FIRST_USER_RECORD: u64 = 16;
const NTFS_VOLUME_LABEL_MAX_CODE_UNITS: usize = 32;

/// Resource limits applied to one inventory operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtfsInventoryLimits {
    pub max_records: usize,
    pub max_bytes: u64,
    pub max_attributes_per_record: usize,
    pub max_attribute_bytes: usize,
    pub max_name_code_units: usize,
    pub max_runs_per_stream: usize,
    pub max_extents: usize,
    pub max_resident_data_bytes: usize,
    pub max_index_blocks: usize,
    pub max_index_entries: usize,
}

impl Default for NtfsInventoryLimits {
    fn default() -> Self {
        Self {
            max_records: 4 * 1024 * 1024,
            max_bytes: 1024 * 1024 * 1024,
            max_attributes_per_record: 256,
            max_attribute_bytes: 16 * 1024 * 1024,
            max_name_code_units: 255,
            max_runs_per_stream: 65_536,
            max_extents: 8 * 1024 * 1024,
            max_resident_data_bytes: 16 * 1024 * 1024,
            max_index_blocks: 1024 * 1024,
            max_index_entries: 16 * 1024 * 1024,
        }
    }
}

/// A reason the returned inventory must not be treated as complete conversion evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NtfsInventoryIncompleteReason {
    RecordLimit,
    MftMappingContinuationRequired,
    AttributeListContinuationRequired,
    IndexAllocationContinuationRequired,
    IndexBitmapContinuationRequired,
    IndexTraversalLimit,
    ReferenceOutsideScan,
}

/// Lossless UTF-16 name and validity evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsName {
    pub code_units: Vec<u16>,
    pub is_well_formed: bool,
}

/// Stable identity of one MFT record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct NtfsObjectReference {
    pub record_number: u64,
    pub sequence_number: u16,
}

impl NtfsObjectReference {
    /// The packed `MFT_REF` form (48-bit record number, 16-bit sequence number) that index keys
    /// and `$FILE_NAME` parents carry on disk.
    #[must_use]
    pub const fn file_reference(self) -> u64 {
        (self.record_number & 0x0000_ffff_ffff_ffff) | ((self.sequence_number as u64) << 48)
    }
}

/// Selected `$STANDARD_INFORMATION` fields needed for faithful planning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtfsStandardInformation {
    pub creation_time: u64,
    pub modification_time: u64,
    pub mft_change_time: u64,
    pub access_time: u64,
    pub file_attributes: u32,
    pub owner_id: Option<u32>,
    pub security_id: Option<u32>,
    pub quota_charged: Option<u64>,
    pub usn: Option<u64>,
}

/// One resident `$FILE_NAME` link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsFileName {
    pub parent: NtfsObjectReference,
    pub namespace: FileNameNamespace,
    pub name: NtfsName,
    pub allocated_size: u64,
    pub data_size: u64,
    pub file_attributes: u32,
    pub reparse_tag_or_ea_size: u32,
}

/// Storage location for one normalized stream extent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtfsExtentPlacement {
    Physical { byte_offset: u64 },
    Sparse,
}

/// One exact byte extent of a non-resident stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtfsInventoryExtent {
    pub stream_id: u64,
    pub logical_offset: u64,
    pub length: u64,
    pub placement: NtfsExtentPlacement,
}

/// One physical allocation claimed by a non-resident NTFS attribute mapping pair.
///
/// Unlike [`NtfsInventoryExtent`], this census covers every attribute type, including filesystem
/// metadata such as `$INDEX_ALLOCATION`, `$BITMAP`, and `$ATTRIBUTE_LIST`. Sparse runs are omitted
/// because they claim no physical clusters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtfsPhysicalAllocation {
    pub record_number: u64,
    pub attribute_type: u32,
    pub attribute_id: u16,
    pub starting_vcn: u64,
    pub start_lcn: u64,
    pub cluster_count: u64,
}

/// Storage and size evidence for one named or unnamed `$DATA` stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NtfsStreamStorage {
    Resident {
        bytes: Vec<u8>,
    },
    NonResident {
        allocated_bytes: u64,
        data_bytes: u64,
        initialized_bytes: u64,
        compressed_bytes: Option<u64>,
        mapping_complete: bool,
        extents: Vec<NtfsInventoryExtent>,
        /// Initialized named-stream bytes captured for dest-native restore. Unnamed streams,
        /// compressed/encrypted/sparse mappings, incomplete runlists, and payloads above
        /// [`NtfsInventoryLimits::max_resident_data_bytes`] leave this `None`.
        captured_payload: Option<Vec<u8>>,
    },
}

/// One NTFS data stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsDataStream {
    pub attribute_id: u16,
    pub name: Option<NtfsName>,
    pub compressed: bool,
    pub encrypted: bool,
    pub sparse: bool,
    /// Compression-unit size in bytes when `compressed`; zero otherwise.
    pub compression_block_bytes: u64,
    pub storage: NtfsStreamStorage,
}

/// Bounded header evidence for every attribute in one fully resolved base record.
///
/// Inventory consumers must not infer that an attribute was absent merely because this module
/// does not otherwise normalize its value. Retaining the type, name, flags, identifier, and
/// storage form lets preservation and activation policy fail closed on attributes whose semantics
/// are not implemented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsAttributeEvidence {
    pub attribute_type: u32,
    pub name: Option<NtfsName>,
    pub flags_raw: u16,
    pub flags_unknown_bits: u16,
    pub attribute_id: u16,
    pub resident: bool,
}

/// One validated directory-index reference and its redundant `$FILE_NAME` key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsDirectoryEntry {
    pub target: NtfsObjectReference,
    pub file_name: NtfsFileName,
}

/// Normalized evidence for one in-use base MFT record.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct NtfsObject {
    pub reference: NtfsObjectReference,
    pub hard_link_count: u16,
    pub is_directory: bool,
    pub is_metadata: bool,
    pub standard_information: Option<NtfsStandardInformation>,
    pub file_names: Vec<NtfsFileName>,
    pub data_streams: Vec<NtfsDataStream>,
    /// Complete bounded census of the resolved attributes backing this base record.
    pub attribute_census: Vec<NtfsAttributeEvidence>,
    pub directory_entries: Vec<NtfsDirectoryEntry>,
    pub has_reparse_point: bool,
    /// Exact unnamed `$REPARSE_POINT` attribute bytes when the mapping is complete.
    pub reparse_point: Option<Vec<u8>>,
    pub has_attribute_list: bool,
    pub directory_index_complete: bool,
}

/// Whether a complete scan reached record 3 and what its unnamed `$VOLUME_NAME` contained.
///
/// `Unavailable` is deliberately distinct from `Absent`: a normalizer cannot claim that a label
/// was absent when record 3 was outside a bounded scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NtfsVolumeLabelEvidence {
    Unavailable,
    Absent,
    Exact(Vec<u16>),
}

/// Whether `$Extend\$Reparse:$R` was reconciled against the `$REPARSE_POINT` census.
///
/// A complete inventory only returns `Absent` or `Reconciled`; every disagreement between the
/// view index and the attributes it is supposed to mirror is a hard [`NtfsInventoryError`]
/// because a converter cannot know which side to trust.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NtfsReparseIndexEvidence {
    /// The scan was bounded or `$Extend\$Reparse` could not be fully resolved, so the index was
    /// not compared against the census.
    Unavailable,
    /// No `$Extend\$Reparse` record exists and no in-use record carries `$REPARSE_POINT`
    /// (NTFS versions before 3.0 have no view indexes).
    Absent,
    /// Every `$R` key names exactly one in-use record whose unnamed `$REPARSE_POINT` carries the
    /// same tag, and every such record is keyed exactly once.
    Reconciled {
        /// Number of `$R` keys, equal to the number of reparse-point records.
        keys: usize,
        /// Whether the index used `$INDEX_ALLOCATION:$R` blocks.
        spilled: bool,
        /// Number of `INDX` records walked (zero for a resident index).
        index_blocks: usize,
    },
}

/// Complete bounded scan result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsInventory {
    pub volume_serial_number: u64,
    pub volume_label: NtfsVolumeLabelEvidence,
    /// Outcome of reconciling `$Extend\$Reparse:$R` against the reparse-point census.
    pub reparse_index: NtfsReparseIndexEvidence,
    pub objects: Vec<NtfsObject>,
    pub extents: Vec<NtfsInventoryExtent>,
    /// Complete physical-cluster ownership census when [`Self::is_complete`] is true.
    pub physical_allocations: Vec<NtfsPhysicalAllocation>,
    pub scanned_records: u64,
    pub initialized_records: u64,
    pub in_use_base_records: u64,
    pub extension_records: u64,
    pub bytes_read: u64,
    pub incomplete_reasons: Vec<NtfsInventoryIncompleteReason>,
}

impl NtfsInventory {
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.incomplete_reasons.is_empty()
    }
}

/// A structural or resource failure that prevents a trustworthy inventory.
#[derive(Debug)]
pub enum NtfsInventoryError {
    InvalidLimit {
        field: &'static str,
    },
    GeometryOverflow {
        calculation: &'static str,
    },
    MftDataSizeNotRecordAligned {
        data_bytes: u64,
        record_bytes: u64,
    },
    MftInitializedSizeNotRecordAligned {
        initialized_bytes: u64,
        record_bytes: u64,
    },
    MftInitializedExceedsData {
        initialized_bytes: u64,
        data_bytes: u64,
    },
    ByteLimitExceeded {
        requested_total: u64,
        maximum: u64,
    },
    ObjectLimitExceeded {
        maximum: usize,
    },
    AllocationFailed,
    ExtentLimitExceeded {
        maximum: usize,
    },
    ResidentDataLimitExceeded {
        actual: usize,
        maximum: usize,
    },
    VolumeNameOutsideVolumeRecord {
        record_number: u64,
    },
    DuplicateVolumeName,
    NamedVolumeName,
    NonResidentVolumeName,
    OddVolumeNameBytes {
        actual: usize,
    },
    VolumeNameLimitExceeded {
        actual: usize,
        maximum: usize,
    },
    DuplicateStandardInformation {
        record_number: u64,
    },
    InvalidStandardInformation {
        record_number: u64,
        actual: usize,
    },
    InvalidFileName {
        record_number: u64,
        actual: usize,
    },
    DuplicateReparsePoint {
        record_number: u64,
    },
    NamedReparsePoint {
        record_number: u64,
    },
    InvalidReparsePoint {
        record_number: u64,
        actual: usize,
    },
    DuplicateDataStream {
        record_number: u64,
        attribute_id: u16,
    },
    InconsistentDataContinuation {
        record_number: u64,
        attribute_id: u16,
    },
    NoncontiguousDataContinuation {
        record_number: u64,
        attribute_id: u16,
        expected_vcn: u64,
        found_vcn: u64,
    },
    ContinuationDataInBaseRecord {
        record_number: u64,
        attribute_id: u16,
    },
    MissingNonResidentSizes {
        record_number: u64,
        attribute_id: u16,
    },
    DuplicateIndexRoot {
        record_number: u64,
    },
    IndexRootNotResident {
        record_number: u64,
    },
    MissingIndexAllocation {
        record_number: u64,
    },
    MissingIndexRoot {
        record_number: u64,
    },
    MissingIndexBitmap {
        record_number: u64,
    },
    InvalidIndexBitmap {
        record_number: u64,
    },
    IndexChildNotAllocated {
        record_number: u64,
        child_vcn: u64,
    },
    IndexChildVcnMisaligned {
        record_number: u64,
        child_vcn: u64,
    },
    InvalidIndexRootGeometry {
        record_number: u64,
        cluster_bytes: u64,
        index_block_bytes: u32,
        encoded_units: u8,
    },
    IndexParentMismatch {
        directory: u64,
        found_parent: u64,
    },
    StaleReference {
        record_number: u64,
        expected_sequence: u16,
        found_sequence: u16,
    },
    ReferenceToUnusedRecord {
        record_number: u64,
    },
    /// More than one in-use record is named `$Extend\$Reparse`.
    DuplicateReparseRecord {
        record_number: u64,
    },
    /// `$Extend\$Reparse` exists but has no `$INDEX_ROOT:$R`, or its `$R` streams are malformed.
    ReparseIndexMalformed {
        record_number: u64,
        reason: String,
    },
    /// A record carries `$REPARSE_POINT` but `$Extend\$Reparse` does not exist.
    ReparseIndexMissing {
        record_number: u64,
    },
    /// A record carries `$REPARSE_POINT` but no `$R` key names it.
    ReparseIndexNotListed {
        record_number: u64,
        reparse_tag: Option<u32>,
    },
    /// A `$R` key names a record that is unused, is not a base record, has a different sequence
    /// number, or has no `$REPARSE_POINT`.
    ReparseIndexStaleKey {
        reparse_tag: u32,
        file_reference: u64,
    },
    /// A `$R` key and the record's `$REPARSE_POINT` disagree about the tag.
    ReparseIndexTagMismatch {
        record_number: u64,
        index_tag: u32,
        attribute_tag: u32,
    },
    /// Two `$R` entries collate equal.
    ReparseIndexDuplicateKey {
        reparse_tag: u32,
        file_reference: u64,
    },
    Attribute(NtfsAttributeError),
    AttributeList(AttributeListError),
    Discovery(NtfsDiscoveryError),
    MappingPairs(MappingPairsError),
    Index(NtfsIndexError),
    Image(ImageError),
}

impl fmt::Display for NtfsInventoryError {
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit { field } => {
                write!(formatter, "NTFS inventory limit {field} must be non-zero")
            }
            Self::GeometryOverflow { calculation } => write!(
                formatter,
                "NTFS inventory overflow while calculating {calculation}"
            ),
            Self::MftDataSizeNotRecordAligned {
                data_bytes,
                record_bytes,
            } => write!(
                formatter,
                "$MFT data size {data_bytes} is not aligned to record size {record_bytes}"
            ),
            Self::MftInitializedSizeNotRecordAligned {
                initialized_bytes,
                record_bytes,
            } => write!(
                formatter,
                "$MFT initialized size {initialized_bytes} is not aligned to record size {record_bytes}"
            ),
            Self::MftInitializedExceedsData {
                initialized_bytes,
                data_bytes,
            } => write!(
                formatter,
                "$MFT initialized size {initialized_bytes} exceeds data size {data_bytes}"
            ),
            Self::ByteLimitExceeded {
                requested_total,
                maximum,
            } => write!(
                formatter,
                "NTFS inventory would read {requested_total} bytes, exceeding cap {maximum}"
            ),
            Self::ObjectLimitExceeded { maximum } => {
                write!(formatter, "NTFS object count exceeds cap {maximum}")
            }
            Self::AllocationFailed => formatter.write_str("NTFS inventory allocation failed"),
            Self::ExtentLimitExceeded { maximum } => {
                write!(formatter, "NTFS extent count exceeds cap {maximum}")
            }
            Self::ResidentDataLimitExceeded { actual, maximum } => write!(
                formatter,
                "resident data length {actual} exceeds cap {maximum}"
            ),
            Self::VolumeNameOutsideVolumeRecord { record_number } => write!(
                formatter,
                "MFT record {record_number} contains $VOLUME_NAME outside record 3"
            ),
            Self::DuplicateVolumeName => {
                formatter.write_str("MFT record 3 contains duplicate $VOLUME_NAME attributes")
            }
            Self::NamedVolumeName => {
                formatter.write_str("MFT record 3 contains a named $VOLUME_NAME attribute")
            }
            Self::NonResidentVolumeName => {
                formatter.write_str("MFT record 3 contains a non-resident $VOLUME_NAME attribute")
            }
            Self::OddVolumeNameBytes { actual } => write!(
                formatter,
                "MFT record 3 $VOLUME_NAME has odd byte length {actual}"
            ),
            Self::VolumeNameLimitExceeded { actual, maximum } => write!(
                formatter,
                "MFT record 3 $VOLUME_NAME has {actual} UTF-16 units, exceeding cap {maximum}"
            ),
            Self::DuplicateStandardInformation { record_number } => write!(
                formatter,
                "MFT record {record_number} has duplicate standard information"
            ),
            Self::InvalidStandardInformation {
                record_number,
                actual,
            } => write!(
                formatter,
                "MFT record {record_number} has invalid {actual}-byte standard information"
            ),
            Self::InvalidFileName {
                record_number,
                actual,
            } => write!(
                formatter,
                "MFT record {record_number} has invalid {actual}-byte file name"
            ),
            Self::DuplicateReparsePoint { record_number } => write!(
                formatter,
                "MFT record {record_number} has duplicate $REPARSE_POINT attributes"
            ),
            Self::NamedReparsePoint { record_number } => write!(
                formatter,
                "MFT record {record_number} has a named $REPARSE_POINT attribute"
            ),
            Self::InvalidReparsePoint {
                record_number,
                actual,
            } => write!(
                formatter,
                "MFT record {record_number} has invalid {actual}-byte $REPARSE_POINT value"
            ),
            Self::DuplicateDataStream {
                record_number,
                attribute_id,
            } => write!(
                formatter,
                "MFT record {record_number} has duplicate data attribute id {attribute_id}"
            ),
            Self::InconsistentDataContinuation {
                record_number,
                attribute_id,
            } => write!(
                formatter,
                "MFT record {record_number} data continuation {attribute_id} changes stream form, name, or flags"
            ),
            Self::NoncontiguousDataContinuation {
                record_number,
                attribute_id,
                expected_vcn,
                found_vcn,
            } => write!(
                formatter,
                "MFT record {record_number} data continuation {attribute_id} begins at VCN {found_vcn}, expected {expected_vcn}"
            ),
            Self::ContinuationDataInBaseRecord {
                record_number,
                attribute_id,
            } => write!(
                formatter,
                "MFT record {record_number} data attribute {attribute_id} begins at nonzero VCN"
            ),
            Self::MissingNonResidentSizes {
                record_number,
                attribute_id,
            } => write!(
                formatter,
                "MFT record {record_number} data attribute {attribute_id} has no authoritative sizes"
            ),
            Self::DuplicateIndexRoot { record_number } => write!(
                formatter,
                "directory record {record_number} has duplicate $I30 index roots"
            ),
            Self::IndexRootNotResident { record_number } => write!(
                formatter,
                "directory record {record_number} has a non-resident index root"
            ),
            Self::MissingIndexAllocation { record_number } => write!(
                formatter,
                "directory record {record_number} needs an index allocation"
            ),
            Self::MissingIndexRoot { record_number } => {
                write!(
                    formatter,
                    "directory record {record_number} has no $I30 index root"
                )
            }
            Self::MissingIndexBitmap { record_number } => write!(
                formatter,
                "directory record {record_number} needs an index bitmap"
            ),
            Self::InvalidIndexBitmap { record_number } => write!(
                formatter,
                "directory record {record_number} has an invalid index bitmap"
            ),
            Self::IndexChildNotAllocated {
                record_number,
                child_vcn,
            } => write!(
                formatter,
                "directory record {record_number} references unallocated index VCN {child_vcn}"
            ),
            Self::IndexChildVcnMisaligned {
                record_number,
                child_vcn,
            } => write!(
                formatter,
                "directory record {record_number} has misaligned child VCN {child_vcn}"
            ),
            Self::InvalidIndexRootGeometry {
                record_number,
                cluster_bytes,
                index_block_bytes,
                encoded_units,
            } => write!(
                formatter,
                "directory record {record_number} has index geometry block={index_block_bytes}, cluster={cluster_bytes}, units={encoded_units}"
            ),
            Self::IndexParentMismatch {
                directory,
                found_parent,
            } => write!(
                formatter,
                "directory {directory} index key names parent {found_parent}"
            ),
            Self::StaleReference {
                record_number,
                expected_sequence,
                found_sequence,
            } => write!(
                formatter,
                "stale MFT reference to record {record_number}: expected sequence {expected_sequence}, found {found_sequence}"
            ),
            Self::ReferenceToUnusedRecord { record_number } => write!(
                formatter,
                "directory index references unused MFT record {record_number}"
            ),
            Self::DuplicateReparseRecord { record_number } => write!(
                formatter,
                "record {record_number} is a second $Extend\\$Reparse"
            ),
            Self::ReparseIndexMalformed {
                record_number,
                reason,
            } => write!(
                formatter,
                "$Extend\\$Reparse record {record_number} has a malformed $R index: {reason}"
            ),
            Self::ReparseIndexMissing { record_number } => write!(
                formatter,
                "record {record_number} carries $REPARSE_POINT but the volume has no $Extend\\$Reparse"
            ),
            Self::ReparseIndexNotListed {
                record_number,
                reparse_tag,
            } => match reparse_tag {
                Some(tag) => write!(
                    formatter,
                    "record {record_number} carries $REPARSE_POINT tag 0x{tag:08x} but $Reparse:$R does not list it"
                ),
                None => write!(
                    formatter,
                    "record {record_number} carries $REPARSE_POINT but $Reparse:$R does not list it"
                ),
            },
            Self::ReparseIndexStaleKey {
                reparse_tag,
                file_reference,
            } => write!(
                formatter,
                "$Reparse:$R key tag 0x{reparse_tag:08x} names MFT reference 0x{file_reference:016x}, which carries no matching $REPARSE_POINT"
            ),
            Self::ReparseIndexTagMismatch {
                record_number,
                index_tag,
                attribute_tag,
            } => write!(
                formatter,
                "$Reparse:$R lists record {record_number} with tag 0x{index_tag:08x} but its $REPARSE_POINT carries 0x{attribute_tag:08x}"
            ),
            Self::ReparseIndexDuplicateKey {
                reparse_tag,
                file_reference,
            } => write!(
                formatter,
                "$Reparse:$R lists tag 0x{reparse_tag:08x} reference 0x{file_reference:016x} more than once"
            ),
            Self::Attribute(error) => write!(formatter, "invalid NTFS attribute: {error}"),
            Self::AttributeList(error) => {
                write!(formatter, "could not resolve NTFS attribute list: {error}")
            }
            Self::Discovery(error) => write!(formatter, "could not read NTFS MFT: {error}"),
            Self::MappingPairs(error) => write!(formatter, "invalid NTFS mapping pairs: {error}"),
            Self::Index(error) => write!(formatter, "invalid NTFS directory index: {error}"),
            Self::Image(error) => write!(formatter, "could not read NTFS image: {error}"),
        }
    }
}

impl std::error::Error for NtfsInventoryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Attribute(error) => Some(error),
            Self::AttributeList(error) => Some(error),
            Self::Discovery(error) => Some(error),
            Self::MappingPairs(error) => Some(error),
            Self::Index(error) => Some(error),
            Self::Image(error) => Some(error),
            _ => None,
        }
    }
}

impl From<NtfsAttributeError> for NtfsInventoryError {
    fn from(value: NtfsAttributeError) -> Self {
        Self::Attribute(value)
    }
}
impl From<AttributeListError> for NtfsInventoryError {
    fn from(value: AttributeListError) -> Self {
        Self::AttributeList(value)
    }
}
impl From<NtfsDiscoveryError> for NtfsInventoryError {
    fn from(value: NtfsDiscoveryError) -> Self {
        Self::Discovery(value)
    }
}
impl From<MappingPairsError> for NtfsInventoryError {
    fn from(value: MappingPairsError) -> Self {
        Self::MappingPairs(value)
    }
}
impl From<NtfsIndexError> for NtfsInventoryError {
    fn from(value: NtfsIndexError) -> Self {
        Self::Index(value)
    }
}
impl From<ImageError> for NtfsInventoryError {
    fn from(value: ImageError) -> Self {
        Self::Image(value)
    }
}

/// Inventories every initialized MFT record reachable within the validated mapping and limits.
///
/// # Errors
/// Returns an error for malformed records, attributes, streams, directory indexes, stale
/// references, arithmetic overflow, image changes, or a hard resource-limit violation.
#[allow(clippy::too_many_lines)]
pub fn inventory_ntfs(
    image: &ImageFile,
    boot: &NtfsBootSector,
    mft: &MftBootstrap,
    limits: NtfsInventoryLimits,
) -> Result<NtfsInventory, NtfsInventoryError> {
    inventory_ntfs_with_reader(image, boot, mft, limits)
}

#[allow(clippy::too_many_lines)]
pub(crate) fn inventory_ntfs_with_reader(
    image: &dyn BoundedImageReader,
    boot: &NtfsBootSector,
    mft: &MftBootstrap,
    limits: NtfsInventoryLimits,
) -> Result<NtfsInventory, NtfsInventoryError> {
    validate_limits(limits)?;
    let record_bytes = boot.mft_record_size.bytes;
    if mft.initialized_bytes > mft.data_bytes {
        return Err(NtfsInventoryError::MftInitializedExceedsData {
            initialized_bytes: mft.initialized_bytes,
            data_bytes: mft.data_bytes,
        });
    }
    if mft.data_bytes % record_bytes != 0 {
        return Err(NtfsInventoryError::MftDataSizeNotRecordAligned {
            data_bytes: mft.data_bytes,
            record_bytes,
        });
    }
    if mft.initialized_bytes % record_bytes != 0 {
        return Err(NtfsInventoryError::MftInitializedSizeNotRecordAligned {
            initialized_bytes: mft.initialized_bytes,
            record_bytes,
        });
    }
    let initialized_records = mft.initialized_bytes / record_bytes;
    let mapped_bytes = mft
        .runlist
        .next_vcn
        .checked_mul(boot.cluster_size_bytes)
        .ok_or(NtfsInventoryError::GeometryOverflow {
            calculation: "$MFT mapped bytes",
        })?;
    let mapped_records = mapped_bytes.min(mft.initialized_bytes) / record_bytes;
    let cap_records = u64::try_from(limits.max_records).unwrap_or(u64::MAX);
    let scan_records = initialized_records.min(mapped_records).min(cap_records);
    let record_io =
        scan_records
            .checked_mul(record_bytes)
            .ok_or(NtfsInventoryError::GeometryOverflow {
                calculation: "MFT scan byte count",
            })?;
    if record_io > limits.max_bytes {
        return Err(NtfsInventoryError::ByteLimitExceeded {
            requested_total: record_io,
            maximum: limits.max_bytes,
        });
    }

    let mut incomplete = BTreeSet::new();
    if cap_records < initialized_records {
        incomplete.insert(NtfsInventoryIncompleteReason::RecordLimit);
    }
    if mapped_records < initialized_records || !mft.mapping_complete {
        incomplete.insert(NtfsInventoryIncompleteReason::MftMappingContinuationRequired);
    }
    let mut objects = Vec::new();
    let mut extents = Vec::new();
    let mut physical_allocations = Vec::new();
    let mut extension_records = 0_u64;
    let mut bytes_read = 0_u64;
    let mut volume_label = NtfsVolumeLabelEvidence::Unavailable;
    let mut reparse_scan = ReparseIndexScan::NoRecord;
    for record_number in 0..scan_records {
        let requested_total =
            bytes_read
                .checked_add(record_bytes)
                .ok_or(NtfsInventoryError::GeometryOverflow {
                    calculation: "inventory bytes read",
                })?;
        if requested_total > limits.max_bytes {
            return Err(NtfsInventoryError::ByteLimitExceeded {
                requested_total,
                maximum: limits.max_bytes,
            });
        }
        let record = read_mft_record_for_inventory_with_reader(
            image,
            boot,
            mft,
            record_number,
            record_bytes,
        )?;
        bytes_read = requested_total;
        if !record.flags.is_in_use() {
            continue;
        }
        if record.base_record.is_some() {
            extension_records += 1;
            continue;
        }
        if objects.len() >= limits.max_records {
            return Err(NtfsInventoryError::ObjectLimitExceeded {
                maximum: limits.max_records,
            });
        }
        let base_has_attribute_list = record_has_attribute_list(&record, boot, limits)?;
        let mut resolved = None;
        if base_has_attribute_list {
            let remaining = limits.max_bytes.saturating_sub(bytes_read);
            if remaining == 0 {
                incomplete.insert(NtfsInventoryIncompleteReason::AttributeListContinuationRequired);
            } else {
                match resolve_attribute_list_with_reader(
                    image,
                    boot,
                    mft,
                    record_number,
                    &record,
                    attribute_list_limits(limits, remaining)?,
                ) {
                    Ok(value) => {
                        bytes_read = bytes_read.checked_add(value.bytes_read).ok_or(
                            NtfsInventoryError::GeometryOverflow {
                                calculation: "attribute-list inventory bytes read",
                            },
                        )?;
                        resolved = Some(value);
                    }
                    Err(error) if is_bounded_attribute_list_failure(&error) => {
                        incomplete.insert(
                            NtfsInventoryIncompleteReason::AttributeListContinuationRequired,
                        );
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        }
        let inventoried = inventory_base_record(
            record_number,
            &record,
            boot,
            limits,
            resolved.as_ref(),
            &mut extents,
            &mut physical_allocations,
            image,
            &mut bytes_read,
        )?;
        if record_number == NTFS_VOLUME_RECORD {
            volume_label = inventoried.volume_label.map_or(
                NtfsVolumeLabelEvidence::Absent,
                NtfsVolumeLabelEvidence::Exact,
            );
        }
        let mut object = inventoried.object;
        if object.is_directory {
            inventory_directory(
                image,
                boot,
                record_number,
                &record,
                resolved.as_ref(),
                limits,
                &mut bytes_read,
                &mut incomplete,
                &mut object,
            )?;
        }
        if is_extend_reparse_record(&object) {
            if !matches!(reparse_scan, ReparseIndexScan::NoRecord) {
                return Err(NtfsInventoryError::DuplicateReparseRecord { record_number });
            }
            reparse_scan = inventory_reparse_index(
                image,
                boot,
                record_number,
                &record,
                resolved.as_ref(),
                limits,
                &mut bytes_read,
                &mut incomplete,
                &object,
            )?;
        }
        objects.push(object);
    }
    validate_references(&objects, scan_records, &mut incomplete)?;
    let reparse_index = reconcile_reparse_index(&objects, reparse_scan, &incomplete)?;
    Ok(NtfsInventory {
        volume_serial_number: boot.volume_serial_number,
        volume_label,
        reparse_index,
        in_use_base_records: u64::try_from(objects.len()).unwrap_or(u64::MAX),
        objects,
        extents,
        physical_allocations,
        scanned_records: scan_records,
        initialized_records,
        extension_records,
        bytes_read,
        incomplete_reasons: incomplete.into_iter().collect(),
    })
}

struct InventoriedBaseRecord {
    object: NtfsObject,
    volume_label: Option<Vec<u16>>,
}

fn record_has_attribute_list(
    record: &NtfsFileRecord,
    boot: &NtfsBootSector,
    limits: NtfsInventoryLimits,
) -> Result<bool, NtfsInventoryError> {
    let parsed = parse_attribute_list(
        record.repaired_bytes(),
        usize::from(record.attributes_offset),
        usize::try_from(record.bytes_in_use).unwrap_or(usize::MAX),
        attribute_limits(boot, limits),
    )?;
    Ok(parsed
        .attributes
        .iter()
        .any(|attribute| attribute.attribute_type == ATTRIBUTE_LIST))
}

fn attribute_list_limits(
    limits: NtfsInventoryLimits,
    remaining_read_bytes: u64,
) -> Result<AttributeListLimits, NtfsInventoryError> {
    let aggregate_attributes = limits
        .max_records
        .checked_mul(limits.max_attributes_per_record)
        .ok_or(NtfsInventoryError::GeometryOverflow {
            calculation: "attribute-list entry cap",
        })?;
    let aggregate_attribute_bytes = limits
        .max_attribute_bytes
        .saturating_mul(limits.max_records)
        .min(usize::try_from(remaining_read_bytes).unwrap_or(usize::MAX));
    Ok(AttributeListLimits {
        max_records: limits.max_records,
        max_entries: aggregate_attributes,
        max_attributes_per_record: limits.max_attributes_per_record,
        max_attribute_bytes: limits.max_attribute_bytes,
        max_collected_attribute_bytes: aggregate_attribute_bytes.max(1),
        max_list_bytes: limits.max_attribute_bytes,
        max_name_code_units: limits.max_name_code_units,
        max_runs: limits.max_runs_per_stream,
        max_read_bytes: remaining_read_bytes,
    })
}

const fn is_bounded_attribute_list_failure(error: &AttributeListError) -> bool {
    matches!(
        error,
        AttributeListError::UnsupportedAttributeListStorage { .. }
            | AttributeListError::ListTooLarge { .. }
            | AttributeListError::ListMappingIncomplete { .. }
            | AttributeListError::EntryLimitExceeded { .. }
            | AttributeListError::NameLimitExceeded { .. }
            | AttributeListError::RecordLimitExceeded { .. }
            | AttributeListError::ReadByteLimitExceeded { .. }
            | AttributeListError::CollectedByteLimitExceeded { .. }
    )
}

fn validate_limits(limits: NtfsInventoryLimits) -> Result<(), NtfsInventoryError> {
    for (field, invalid) in [
        ("max_records", limits.max_records == 0),
        ("max_bytes", limits.max_bytes == 0),
        (
            "max_attributes_per_record",
            limits.max_attributes_per_record == 0,
        ),
        ("max_attribute_bytes", limits.max_attribute_bytes == 0),
        ("max_name_code_units", limits.max_name_code_units == 0),
        ("max_runs_per_stream", limits.max_runs_per_stream == 0),
        ("max_extents", limits.max_extents == 0),
        (
            "max_resident_data_bytes",
            limits.max_resident_data_bytes == 0,
        ),
        ("max_index_blocks", limits.max_index_blocks == 0),
        ("max_index_entries", limits.max_index_entries == 0),
    ] {
        if invalid {
            return Err(NtfsInventoryError::InvalidLimit { field });
        }
    }
    Ok(())
}

const fn attribute_limits(boot: &NtfsBootSector, limits: NtfsInventoryLimits) -> AttributeLimits {
    AttributeLimits {
        cluster_size_bytes: boot.cluster_size_bytes,
        max_attribute_bytes: limits.max_attribute_bytes,
        max_name_code_units: limits.max_name_code_units,
        max_attributes: limits.max_attributes_per_record,
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn inventory_base_record(
    record_number: u64,
    record: &NtfsFileRecord,
    boot: &NtfsBootSector,
    limits: NtfsInventoryLimits,
    resolved: Option<&ResolvedAttributeList>,
    all_extents: &mut Vec<NtfsInventoryExtent>,
    physical_allocations: &mut Vec<NtfsPhysicalAllocation>,
    image: &dyn BoundedImageReader,
    bytes_read: &mut u64,
) -> Result<InventoriedBaseRecord, NtfsInventoryError> {
    let base_attributes = parse_attribute_list(
        record.repaired_bytes(),
        usize::from(record.attributes_offset),
        usize::try_from(record.bytes_in_use).unwrap_or(usize::MAX),
        attribute_limits(boot, limits),
    )?;
    let resolved_attributes = resolved
        .map(|list| {
            list.extents
                .iter()
                .map(|extent| {
                    parse_attribute(&extent.raw_attribute, attribute_limits(boot, limits))
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?;
    let attributes = resolved_attributes
        .as_deref()
        .unwrap_or(&base_attributes.attributes);
    let mut attribute_census = Vec::new();
    attribute_census
        .try_reserve_exact(attributes.len())
        .map_err(|_| NtfsInventoryError::AllocationFailed)?;
    for attribute in attributes {
        attribute_census.push(NtfsAttributeEvidence {
            attribute_type: attribute.attribute_type,
            name: attribute.name.as_ref().map(|name| NtfsName {
                code_units: name.code_units.clone(),
                is_well_formed: name.is_well_formed,
            }),
            flags_raw: attribute.flags.raw,
            flags_unknown_bits: attribute.flags.unknown_bits,
            attribute_id: attribute.id,
            resident: matches!(attribute.body, AttributeBody::Resident(_)),
        });
    }
    if let Some(extent) = resolved.and_then(|list| {
        list.extents.iter().find(|extent| {
            extent.attribute_type == VOLUME_NAME
                && extent.record.record_number != NTFS_VOLUME_RECORD
        })
    }) {
        return Err(NtfsInventoryError::VolumeNameOutsideVolumeRecord {
            record_number: extent.record.record_number,
        });
    }
    let mut standard_information = None;
    let mut file_names = Vec::new();
    let mut volume_label = None;
    let has_attribute_list = base_attributes
        .attributes
        .iter()
        .any(|attribute| attribute.attribute_type == ATTRIBUTE_LIST);
    for attribute in attributes {
        match attribute.attribute_type {
            STANDARD_INFORMATION => {
                if standard_information.is_some() {
                    return Err(NtfsInventoryError::DuplicateStandardInformation { record_number });
                }
                let AttributeBody::Resident(body) = &attribute.body else {
                    return Err(NtfsInventoryError::InvalidStandardInformation {
                        record_number,
                        actual: 0,
                    });
                };
                standard_information = Some(parse_standard_information(record_number, body.value)?);
            }
            FILE_NAME => {
                let AttributeBody::Resident(body) = &attribute.body else {
                    return Err(NtfsInventoryError::InvalidFileName {
                        record_number,
                        actual: 0,
                    });
                };
                file_names.push(parse_file_name(
                    record_number,
                    body.value,
                    limits.max_name_code_units,
                )?);
            }
            VOLUME_NAME => {
                if record_number != NTFS_VOLUME_RECORD {
                    return Err(NtfsInventoryError::VolumeNameOutsideVolumeRecord {
                        record_number,
                    });
                }
                if volume_label.is_some() {
                    return Err(NtfsInventoryError::DuplicateVolumeName);
                }
                if attribute.name.is_some() {
                    return Err(NtfsInventoryError::NamedVolumeName);
                }
                let AttributeBody::Resident(body) = &attribute.body else {
                    return Err(NtfsInventoryError::NonResidentVolumeName);
                };
                if body.value.len() % 2 != 0 {
                    return Err(NtfsInventoryError::OddVolumeNameBytes {
                        actual: body.value.len(),
                    });
                }
                let actual = body.value.len() / 2;
                let maximum = limits
                    .max_name_code_units
                    .min(NTFS_VOLUME_LABEL_MAX_CODE_UNITS);
                if actual > maximum {
                    return Err(NtfsInventoryError::VolumeNameLimitExceeded { actual, maximum });
                }
                let mut units = Vec::new();
                units
                    .try_reserve_exact(actual)
                    .map_err(|_| NtfsInventoryError::AllocationFailed)?;
                for pair in body.value.chunks_exact(2) {
                    units.push(u16::from_le_bytes([pair[0], pair[1]]));
                }
                volume_label = Some(units);
            }
            _ => {}
        }
    }
    let (has_reparse_point, reparse_point) =
        inventory_reparse_point(record_number, attributes, limits)?;
    inventory_physical_allocations(
        record_number,
        attributes,
        boot,
        limits,
        physical_allocations,
    )?;
    if resolved.is_some() {
        inventory_physical_allocations_where(
            record_number,
            &base_attributes.attributes,
            boot,
            limits,
            physical_allocations,
            |attribute| {
                attribute.attribute_type == ATTRIBUTE_LIST
                    && matches!(
                        &attribute.body,
                        AttributeBody::NonResident(body) if body.lowest_vcn == 0
                    )
            },
        )?;
    }
    let mut stream_groups: Vec<Vec<&NtfsAttribute<'_>>> = Vec::new();
    for attribute in attributes
        .iter()
        .filter(|attribute| attribute.attribute_type == DATA)
    {
        if let Some(group) = stream_groups
            .iter_mut()
            .find(|group| attribute_names_equal(group[0], attribute))
        {
            group.push(attribute);
        } else {
            stream_groups.push(vec![attribute]);
        }
    }
    let mut data_streams = Vec::new();
    for group in stream_groups {
        let stream =
            inventory_data_stream(record_number, &group, boot, limits, Some(image), bytes_read)?;
        if data_streams
            .iter()
            .any(|existing: &NtfsDataStream| existing.attribute_id == stream.attribute_id)
        {
            return Err(NtfsInventoryError::DuplicateDataStream {
                record_number,
                attribute_id: stream.attribute_id,
            });
        }
        if let NtfsStreamStorage::NonResident { extents, .. } = &stream.storage {
            if all_extents
                .len()
                .checked_add(extents.len())
                .is_none_or(|count| count > limits.max_extents)
            {
                return Err(NtfsInventoryError::ExtentLimitExceeded {
                    maximum: limits.max_extents,
                });
            }
            all_extents.extend_from_slice(extents);
        }
        data_streams.push(stream);
    }
    Ok(InventoriedBaseRecord {
        object: NtfsObject {
            reference: NtfsObjectReference {
                record_number,
                sequence_number: record.sequence_number,
            },
            hard_link_count: record.hard_link_count,
            is_directory: record.flags.is_directory(),
            // Record numbers below 16 are reserved NTFS metafiles even when a formatter omits
            // the optional 0x0004 FILE-record hint (NTFS-3G does this for record 12).
            is_metadata: (record_number < NTFS_FIRST_USER_RECORD
                && !matches!(record_number, NTFS_ROOT_RECORD | NTFS_EXTEND_RECORD))
                || record.flags.is_metadata(),
            standard_information,
            file_names,
            data_streams,
            attribute_census,
            directory_entries: Vec::new(),
            has_reparse_point,
            reparse_point,
            has_attribute_list,
            directory_index_complete: !record.flags.is_directory(),
        },
        volume_label,
    })
}

fn inventory_reparse_point(
    record_number: u64,
    attributes: &[NtfsAttribute<'_>],
    limits: NtfsInventoryLimits,
) -> Result<(bool, Option<Vec<u8>>), NtfsInventoryError> {
    let mut found = None;
    for attribute in attributes
        .iter()
        .filter(|attribute| attribute.attribute_type == REPARSE_POINT)
    {
        if attribute.name.is_some() {
            return Err(NtfsInventoryError::NamedReparsePoint { record_number });
        }
        if found.is_some() {
            return Err(NtfsInventoryError::DuplicateReparsePoint { record_number });
        }
        let AttributeBody::Resident(body) = &attribute.body else {
            found = Some(None);
            continue;
        };
        if body.value.len() > limits.max_resident_data_bytes {
            return Err(NtfsInventoryError::ResidentDataLimitExceeded {
                actual: body.value.len(),
                maximum: limits.max_resident_data_bytes,
            });
        }
        if body.value.len() < 8 {
            return Err(NtfsInventoryError::InvalidReparsePoint {
                record_number,
                actual: body.value.len(),
            });
        }
        let data_length = u16::from_le_bytes([body.value[4], body.value[5]]);
        if usize::from(data_length)
            .checked_add(8)
            .is_none_or(|expected| expected != body.value.len())
        {
            return Err(NtfsInventoryError::InvalidReparsePoint {
                record_number,
                actual: body.value.len(),
            });
        }
        let mut payload = Vec::new();
        payload
            .try_reserve_exact(body.value.len())
            .map_err(|_| NtfsInventoryError::AllocationFailed)?;
        payload.extend_from_slice(body.value);
        found = Some(Some(payload));
    }
    Ok(found.map_or((false, None), |payload| (true, payload)))
}

fn inventory_physical_allocations(
    record_number: u64,
    attributes: &[NtfsAttribute<'_>],
    boot: &NtfsBootSector,
    limits: NtfsInventoryLimits,
    output: &mut Vec<NtfsPhysicalAllocation>,
) -> Result<(), NtfsInventoryError> {
    inventory_physical_allocations_where(record_number, attributes, boot, limits, output, |_| true)
}

fn inventory_physical_allocations_where(
    record_number: u64,
    attributes: &[NtfsAttribute<'_>],
    boot: &NtfsBootSector,
    limits: NtfsInventoryLimits,
    output: &mut Vec<NtfsPhysicalAllocation>,
    include: impl Fn(&NtfsAttribute<'_>) -> bool,
) -> Result<(), NtfsInventoryError> {
    for attribute in attributes {
        if !include(attribute) {
            continue;
        }
        let AttributeBody::NonResident(body) = &attribute.body else {
            continue;
        };
        let runlist = parse_mapping_pairs(
            body.mapping_pairs,
            MappingPairsLimits {
                starting_vcn: body.lowest_vcn,
                expected_next_vcn: Some(body.expected_next_vcn),
                volume_cluster_count: boot.cluster_count,
                max_runs: limits.max_runs_per_stream,
                max_decoded_clusters: boot.cluster_count,
            },
        )?;
        let physical_count = runlist
            .extents
            .iter()
            .filter(|extent| matches!(extent.location, ExtentLocation::Physical { .. }))
            .count();
        if output
            .len()
            .checked_add(physical_count)
            .is_none_or(|count| count > limits.max_extents)
        {
            return Err(NtfsInventoryError::ExtentLimitExceeded {
                maximum: limits.max_extents,
            });
        }
        output
            .try_reserve_exact(physical_count)
            .map_err(|_| NtfsInventoryError::AllocationFailed)?;
        for extent in runlist.extents {
            let ExtentLocation::Physical { lcn } = extent.location else {
                continue;
            };
            output.push(NtfsPhysicalAllocation {
                record_number,
                attribute_type: attribute.attribute_type,
                attribute_id: attribute.id,
                starting_vcn: extent.vcn,
                start_lcn: lcn,
                cluster_count: extent.length,
            });
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn inventory_data_stream(
    record_number: u64,
    attributes: &[&NtfsAttribute<'_>],
    boot: &NtfsBootSector,
    limits: NtfsInventoryLimits,
    image: Option<&dyn BoundedImageReader>,
    bytes_read: &mut u64,
) -> Result<NtfsDataStream, NtfsInventoryError> {
    let attribute = attributes[0];
    let name = attribute.name.as_ref().map(|name| NtfsName {
        code_units: name.code_units.clone(),
        is_well_formed: name.is_well_formed,
    });
    let storage = match &attribute.body {
        AttributeBody::Resident(body) => {
            if attributes.len() != 1 {
                return Err(NtfsInventoryError::InconsistentDataContinuation {
                    record_number,
                    attribute_id: attribute.id,
                });
            }
            if body.value.len() > limits.max_resident_data_bytes {
                return Err(NtfsInventoryError::ResidentDataLimitExceeded {
                    actual: body.value.len(),
                    maximum: limits.max_resident_data_bytes,
                });
            }
            NtfsStreamStorage::Resident {
                bytes: body.value.to_vec(),
            }
        }
        AttributeBody::NonResident(body) => {
            if body.lowest_vcn != 0 {
                return Err(NtfsInventoryError::ContinuationDataInBaseRecord {
                    record_number,
                    attribute_id: attribute.id,
                });
            }
            let sizes = body
                .sizes
                .ok_or(NtfsInventoryError::MissingNonResidentSizes {
                    record_number,
                    attribute_id: attribute.id,
                })?;
            let mut expected_vcn = 0_u64;
            let mut combined_extents = Vec::new();
            let mut encoded_runs = 0_usize;
            let mut bytes_consumed = 0_usize;
            let mut decoded_clusters = 0_u64;
            let mut physical_clusters = 0_u64;
            let mut sparse_clusters = 0_u64;
            for continuation in attributes {
                if !attribute_names_equal(attribute, continuation)
                    || continuation.flags != attribute.flags
                {
                    return Err(NtfsInventoryError::InconsistentDataContinuation {
                        record_number,
                        attribute_id: continuation.id,
                    });
                }
                let AttributeBody::NonResident(continuation_body) = &continuation.body else {
                    return Err(NtfsInventoryError::InconsistentDataContinuation {
                        record_number,
                        attribute_id: continuation.id,
                    });
                };
                if continuation_body.lowest_vcn != expected_vcn {
                    return Err(NtfsInventoryError::NoncontiguousDataContinuation {
                        record_number,
                        attribute_id: continuation.id,
                        expected_vcn,
                        found_vcn: continuation_body.lowest_vcn,
                    });
                }
                let remaining_runs = limits.max_runs_per_stream.checked_sub(encoded_runs).ok_or(
                    NtfsInventoryError::ExtentLimitExceeded {
                        maximum: limits.max_runs_per_stream,
                    },
                )?;
                if remaining_runs == 0 {
                    return Err(NtfsInventoryError::ExtentLimitExceeded {
                        maximum: limits.max_runs_per_stream,
                    });
                }
                let runlist = parse_mapping_pairs(
                    continuation_body.mapping_pairs,
                    MappingPairsLimits {
                        starting_vcn: continuation_body.lowest_vcn,
                        expected_next_vcn: Some(continuation_body.expected_next_vcn),
                        volume_cluster_count: boot.cluster_count,
                        max_runs: remaining_runs,
                        max_decoded_clusters: boot.cluster_count,
                    },
                )?;
                expected_vcn = runlist.next_vcn;
                encoded_runs = encoded_runs.checked_add(runlist.encoded_runs).ok_or(
                    NtfsInventoryError::GeometryOverflow {
                        calculation: "stream run count",
                    },
                )?;
                bytes_consumed = bytes_consumed.checked_add(runlist.bytes_consumed).ok_or(
                    NtfsInventoryError::GeometryOverflow {
                        calculation: "stream mapping-pair bytes",
                    },
                )?;
                decoded_clusters = decoded_clusters
                    .checked_add(runlist.decoded_clusters)
                    .ok_or(NtfsInventoryError::GeometryOverflow {
                        calculation: "stream decoded clusters",
                    })?;
                physical_clusters = physical_clusters
                    .checked_add(runlist.physical_clusters)
                    .ok_or(NtfsInventoryError::GeometryOverflow {
                        calculation: "stream physical clusters",
                    })?;
                sparse_clusters = sparse_clusters.checked_add(runlist.sparse_clusters).ok_or(
                    NtfsInventoryError::GeometryOverflow {
                        calculation: "stream sparse clusters",
                    },
                )?;
                combined_extents.extend(runlist.extents);
            }
            let runlist = NtfsRunlist {
                extents: combined_extents,
                next_vcn: expected_vcn,
                encoded_runs,
                bytes_consumed,
                decoded_clusters,
                physical_clusters,
                sparse_clusters,
            };
            let mapped_bytes = runlist
                .next_vcn
                .checked_mul(boot.cluster_size_bytes)
                .ok_or(NtfsInventoryError::GeometryOverflow {
                    calculation: "stream mapped bytes",
                })?;
            let extents = normalize_extents(
                record_number,
                attribute.id,
                &runlist,
                boot.cluster_size_bytes,
            )?;
            let mapping_complete = mapped_bytes
                >= required_stream_coverage(attribute, sizes, boot.cluster_size_bytes)?;
            let captured_payload = capture_named_nonresident_payload(
                image,
                record_number,
                name.as_ref(),
                mapping_complete
                    && !attribute.flags.is_compressed()
                    && !attribute.flags.encrypted
                    && !attribute.flags.sparse,
                sizes.data,
                sizes.initialized,
                &extents,
                limits,
                bytes_read,
            )?;
            NtfsStreamStorage::NonResident {
                allocated_bytes: sizes.allocated,
                data_bytes: sizes.data,
                initialized_bytes: sizes.initialized,
                compressed_bytes: sizes.compressed,
                mapping_complete,
                extents,
                captured_payload,
            }
        }
    };
    Ok(NtfsDataStream {
        attribute_id: attribute.id,
        name,
        compressed: attribute.flags.is_compressed(),
        encrypted: attribute.flags.encrypted,
        sparse: attribute.flags.sparse,
        compression_block_bytes: match &attribute.body {
            AttributeBody::NonResident(body) => body.compression_block_bytes.unwrap_or(0),
            AttributeBody::Resident(_) => 0,
        },
        storage,
    })
}

#[allow(clippy::too_many_arguments)]
fn capture_named_nonresident_payload(
    image: Option<&dyn BoundedImageReader>,
    record_number: u64,
    name: Option<&NtfsName>,
    eligible: bool,
    data_bytes: u64,
    initialized_bytes: u64,
    extents: &[NtfsInventoryExtent],
    limits: NtfsInventoryLimits,
    bytes_read: &mut u64,
) -> Result<Option<Vec<u8>>, NtfsInventoryError> {
    let max_capture = u64::try_from(limits.max_resident_data_bytes).unwrap_or(u64::MAX);
    if name.is_none()
        || record_number < NTFS_FIRST_USER_RECORD
        || !eligible
        || data_bytes > max_capture
        || initialized_bytes > data_bytes
    {
        return Ok(None);
    }
    let Some(image) = image else {
        return Ok(None);
    };
    let mut ordered = extents.to_vec();
    ordered.sort_unstable_by_key(|extent| extent.logical_offset);
    let mut expected = 0_u64;
    for extent in &ordered {
        if expected >= initialized_bytes {
            break;
        }
        if extent.length == 0
            || extent.logical_offset != expected
            || matches!(extent.placement, NtfsExtentPlacement::Sparse)
        {
            return Ok(None);
        }
        expected =
            expected
                .checked_add(extent.length)
                .ok_or(NtfsInventoryError::GeometryOverflow {
                    calculation: "named stream capture coverage",
                })?;
    }
    if expected < initialized_bytes {
        return Ok(None);
    }
    let length =
        usize::try_from(initialized_bytes).map_err(|_| NtfsInventoryError::GeometryOverflow {
            calculation: "named stream capture length",
        })?;
    let total =
        bytes_read
            .checked_add(initialized_bytes)
            .ok_or(NtfsInventoryError::GeometryOverflow {
                calculation: "inventory bytes read",
            })?;
    if total > limits.max_bytes {
        return Err(NtfsInventoryError::ByteLimitExceeded {
            requested_total: total,
            maximum: limits.max_bytes,
        });
    }
    if length == 0 {
        *bytes_read = total;
        return Ok(Some(Vec::new()));
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(length)
        .map_err(|_| NtfsInventoryError::AllocationFailed)?;
    output.resize(length, 0);
    let mut cursor = 0_u64;
    for extent in &ordered {
        if cursor >= initialized_bytes {
            break;
        }
        let NtfsExtentPlacement::Physical { byte_offset } = extent.placement else {
            return Err(NtfsInventoryError::GeometryOverflow {
                calculation: "named stream capture sparse run",
            });
        };
        let chunk = (initialized_bytes - cursor).min(extent.length);
        let chunk_len =
            usize::try_from(chunk).map_err(|_| NtfsInventoryError::GeometryOverflow {
                calculation: "named stream capture chunk",
            })?;
        let dest = usize::try_from(cursor).map_err(|_| NtfsInventoryError::GeometryOverflow {
            calculation: "named stream capture offset",
        })?;
        read_chunked(image, byte_offset, &mut output[dest..dest + chunk_len])?;
        cursor = cursor
            .checked_add(chunk)
            .ok_or(NtfsInventoryError::GeometryOverflow {
                calculation: "named stream capture cursor",
            })?;
    }
    *bytes_read = total;
    Ok(Some(output))
}

fn attribute_names_equal(left: &NtfsAttribute<'_>, right: &NtfsAttribute<'_>) -> bool {
    left.name.as_ref().map(|name| &name.code_units)
        == right.name.as_ref().map(|name| &name.code_units)
}

fn required_stream_coverage(
    attribute: &NtfsAttribute<'_>,
    sizes: crate::fs::ntfs_attribute::NonResidentSizes,
    cluster_bytes: u64,
) -> Result<u64, NtfsInventoryError> {
    if !attribute.flags.sparse && !attribute.flags.is_compressed() {
        return Ok(sizes.allocated);
    }
    let clusters =
        sizes
            .data
            .checked_add(cluster_bytes - 1)
            .ok_or(NtfsInventoryError::GeometryOverflow {
                calculation: "sparse/compressed stream logical coverage",
            })?
            / cluster_bytes;
    clusters
        .checked_mul(cluster_bytes)
        .ok_or(NtfsInventoryError::GeometryOverflow {
            calculation: "sparse/compressed stream logical coverage bytes",
        })
}

fn normalize_extents(
    record_number: u64,
    attribute_id: u16,
    runlist: &NtfsRunlist,
    cluster_bytes: u64,
) -> Result<Vec<NtfsInventoryExtent>, NtfsInventoryError> {
    let stream_id = record_number
        .checked_shl(16)
        .and_then(|value| value.checked_add(u64::from(attribute_id)))
        .ok_or(NtfsInventoryError::GeometryOverflow {
            calculation: "stream identifier",
        })?;
    runlist
        .extents
        .iter()
        .map(|extent| {
            let logical_offset = extent.vcn.checked_mul(cluster_bytes).ok_or(
                NtfsInventoryError::GeometryOverflow {
                    calculation: "stream logical offset",
                },
            )?;
            let length = extent.length.checked_mul(cluster_bytes).ok_or(
                NtfsInventoryError::GeometryOverflow {
                    calculation: "stream extent length",
                },
            )?;
            let placement = match extent.location {
                ExtentLocation::Sparse => NtfsExtentPlacement::Sparse,
                ExtentLocation::Physical { lcn } => NtfsExtentPlacement::Physical {
                    byte_offset: lcn.checked_mul(cluster_bytes).ok_or(
                        NtfsInventoryError::GeometryOverflow {
                            calculation: "stream physical offset",
                        },
                    )?,
                },
            };
            Ok(NtfsInventoryExtent {
                stream_id,
                logical_offset,
                length,
                placement,
            })
        })
        .collect()
}

fn parse_standard_information(
    record_number: u64,
    bytes: &[u8],
) -> Result<NtfsStandardInformation, NtfsInventoryError> {
    if bytes.len() < STANDARD_INFORMATION_MINIMUM
        || (bytes.len() > STANDARD_INFORMATION_MINIMUM && bytes.len() < 72)
    {
        return Err(NtfsInventoryError::InvalidStandardInformation {
            record_number,
            actual: bytes.len(),
        });
    }
    Ok(NtfsStandardInformation {
        creation_time: le_u64(bytes, 0),
        modification_time: le_u64(bytes, 8),
        mft_change_time: le_u64(bytes, 16),
        access_time: le_u64(bytes, 24),
        file_attributes: le_u32(bytes, 32),
        owner_id: (bytes.len() >= 52).then(|| le_u32(bytes, 48)),
        security_id: (bytes.len() >= 56).then(|| le_u32(bytes, 52)),
        quota_charged: (bytes.len() >= 64).then(|| le_u64(bytes, 56)),
        usn: (bytes.len() >= 72).then(|| le_u64(bytes, 64)),
    })
}

fn parse_file_name(
    record_number: u64,
    bytes: &[u8],
    max_name: usize,
) -> Result<NtfsFileName, NtfsInventoryError> {
    if bytes.len() < FILE_NAME_MINIMUM {
        return Err(NtfsInventoryError::InvalidFileName {
            record_number,
            actual: bytes.len(),
        });
    }
    let units = usize::from(bytes[64]);
    let expected = FILE_NAME_MINIMUM
        .checked_add(
            units
                .checked_mul(2)
                .ok_or(NtfsInventoryError::GeometryOverflow {
                    calculation: "file-name bytes",
                })?,
        )
        .ok_or(NtfsInventoryError::GeometryOverflow {
            calculation: "file-name length",
        })?;
    if units == 0 || units > max_name || expected != bytes.len() {
        return Err(NtfsInventoryError::InvalidFileName {
            record_number,
            actual: bytes.len(),
        });
    }
    let namespace = parse_namespace(bytes[65]).ok_or(NtfsInventoryError::InvalidFileName {
        record_number,
        actual: bytes.len(),
    })?;
    let raw_parent = le_u64(bytes, 0);
    let code_units: Vec<u16> = bytes[66..]
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    Ok(NtfsFileName {
        parent: decode_reference(raw_parent),
        namespace,
        name: NtfsName {
            is_well_formed: char::decode_utf16(code_units.iter().copied())
                .all(|value| value.is_ok()),
            code_units,
        },
        allocated_size: le_u64(bytes, 40),
        data_size: le_u64(bytes, 48),
        file_attributes: le_u32(bytes, 56),
        reparse_tag_or_ea_size: le_u32(bytes, 60),
    })
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn inventory_directory(
    image: &dyn BoundedImageReader,
    boot: &NtfsBootSector,
    record_number: u64,
    record: &NtfsFileRecord,
    resolved: Option<&ResolvedAttributeList>,
    limits: NtfsInventoryLimits,
    bytes_read: &mut u64,
    incomplete: &mut BTreeSet<NtfsInventoryIncompleteReason>,
    object: &mut NtfsObject,
) -> Result<(), NtfsInventoryError> {
    let parsed = parse_attribute_list(
        record.repaired_bytes(),
        usize::from(record.attributes_offset),
        usize::try_from(record.bytes_in_use).unwrap_or(usize::MAX),
        attribute_limits(boot, limits),
    )?;
    let resolved_attributes = resolved
        .map(|list| {
            list.extents
                .iter()
                .map(|extent| {
                    parse_attribute(&extent.raw_attribute, attribute_limits(boot, limits))
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?;
    let attributes = resolved_attributes.as_deref().unwrap_or(&parsed.attributes);
    let unresolved_attribute_list = object.has_attribute_list && resolved.is_none();
    let i30 = b"$I30".map(u16::from);
    let roots: Vec<_> = attributes
        .iter()
        .filter(|attribute| {
            attribute.attribute_type == INDEX_ROOT && attribute_name_eq(attribute, &i30)
        })
        .collect();
    if roots.len() > 1 {
        return Err(NtfsInventoryError::DuplicateIndexRoot { record_number });
    }
    let Some(root_attribute) = roots.first() else {
        if unresolved_attribute_list {
            incomplete.insert(NtfsInventoryIncompleteReason::AttributeListContinuationRequired);
            object.directory_index_complete = false;
            return Ok(());
        }
        return Err(NtfsInventoryError::MissingIndexRoot { record_number });
    };
    let AttributeBody::Resident(root_body) = &root_attribute.body else {
        return Err(NtfsInventoryError::IndexRootNotResident { record_number });
    };
    let index_limits = NtfsIndexLimits {
        max_root_bytes: limits.max_attribute_bytes,
        max_block_bytes: limits.max_attribute_bytes,
        max_entries_per_node: limits.max_index_entries,
        max_name_code_units: limits.max_name_code_units,
    };
    let root = parse_index_root(root_body.value, index_limits)?;
    let mut children = VecDeque::new();
    append_index_entries(
        object.reference,
        root.entries(),
        &mut object.directory_entries,
        &mut children,
        limits.max_index_entries,
    )?;
    if children.is_empty() {
        object.directory_index_complete = true;
        return Ok(());
    }

    let allocation = attributes.iter().find(|attribute| {
        attribute.attribute_type == INDEX_ALLOCATION && attribute_name_eq(attribute, &i30)
    });
    let bitmap = attributes
        .iter()
        .find(|attribute| attribute.attribute_type == BITMAP && attribute_name_eq(attribute, &i30));
    let (Some(allocation), Some(bitmap)) = (allocation, bitmap) else {
        if unresolved_attribute_list {
            incomplete.insert(NtfsInventoryIncompleteReason::AttributeListContinuationRequired);
            object.directory_index_complete = false;
            return Ok(());
        }
        return if allocation.is_none() {
            Err(NtfsInventoryError::MissingIndexAllocation { record_number })
        } else {
            Err(NtfsInventoryError::MissingIndexBitmap { record_number })
        };
    };
    let Some((allocation_runlist, allocation_bytes, allocation_complete)) =
        parse_index_allocation(record_number, allocation, boot, limits)?
    else {
        return Err(NtfsInventoryError::MissingIndexAllocation { record_number });
    };
    if !allocation_complete {
        incomplete.insert(NtfsInventoryIncompleteReason::IndexAllocationContinuationRequired);
        object.directory_index_complete = false;
        return Ok(());
    }
    let Some(bitmap_bytes) = read_attribute_value(image, bitmap, boot, limits, bytes_read)? else {
        incomplete.insert(NtfsInventoryIncompleteReason::IndexBitmapContinuationRequired);
        object.directory_index_complete = false;
        return Ok(());
    };
    let mut visited = BTreeSet::new();
    while let Some(child_vcn) = children.pop_front() {
        if !visited.insert(child_vcn) {
            continue;
        }
        if visited.len() > limits.max_index_blocks {
            incomplete.insert(NtfsInventoryIncompleteReason::IndexTraversalLimit);
            object.directory_index_complete = false;
            return Ok(());
        }
        let (stream_offset, block_number) =
            index_child_offset(record_number, child_vcn, &root, boot.cluster_size_bytes)?;
        let byte_index = usize::try_from(block_number / 8)
            .map_err(|_| NtfsInventoryError::InvalidIndexBitmap { record_number })?;
        if byte_index >= bitmap_bytes.len() {
            return Err(NtfsInventoryError::InvalidIndexBitmap { record_number });
        }
        if bitmap_bytes[byte_index] & (1_u8 << (block_number % 8)) == 0 {
            return Err(NtfsInventoryError::IndexChildNotAllocated {
                record_number,
                child_vcn,
            });
        }
        let block_size = usize::try_from(root.index_block_size).map_err(|_| {
            NtfsInventoryError::GeometryOverflow {
                calculation: "index block size",
            }
        })?;
        let block = read_runlist_range(
            image,
            &allocation_runlist,
            stream_offset,
            block_size,
            boot.cluster_size_bytes,
            allocation_bytes,
            bytes_read,
            limits.max_bytes,
        )?;
        let parsed_block = parse_index_block(&block, Some(child_vcn), index_limits)?;
        append_index_entries(
            object.reference,
            parsed_block.entries(),
            &mut object.directory_entries,
            &mut children,
            limits.max_index_entries,
        )?;
    }
    object.directory_index_complete = true;
    Ok(())
}

fn attribute_name_eq(attribute: &NtfsAttribute<'_>, expected: &[u16]) -> bool {
    attribute
        .name
        .as_ref()
        .is_some_and(|name| name.code_units == expected)
}

/// Outcome of walking `$Extend\$Reparse:$R` during the record scan.
enum ReparseIndexScan {
    /// No in-use base record is named `$Extend\$Reparse`.
    NoRecord,
    /// The record exists but its `$R` streams could not be fully resolved within the caps.
    Unavailable,
    /// Every reachable `$R` key, in on-disk traversal order.
    Walked {
        keys: Vec<ReparseIndexKey>,
        spilled: bool,
        index_blocks: usize,
    },
}

/// Whether `object` is the `$Reparse` metafile: a record whose `$FILE_NAME` names it
/// `$Reparse` under `$Extend` (record 11). The record number is not assumed because only the
/// first sixteen NTFS records have fixed positions.
fn is_extend_reparse_record(object: &NtfsObject) -> bool {
    let expected: Vec<u16> = "$Reparse".encode_utf16().collect();
    object.file_names.iter().any(|name| {
        name.parent.record_number == NTFS_EXTEND_RECORD && name.name.code_units == expected
    })
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn inventory_reparse_index(
    image: &dyn BoundedImageReader,
    boot: &NtfsBootSector,
    record_number: u64,
    record: &NtfsFileRecord,
    resolved: Option<&ResolvedAttributeList>,
    limits: NtfsInventoryLimits,
    bytes_read: &mut u64,
    incomplete: &mut BTreeSet<NtfsInventoryIncompleteReason>,
    object: &NtfsObject,
) -> Result<ReparseIndexScan, NtfsInventoryError> {
    let malformed = |reason: String| NtfsInventoryError::ReparseIndexMalformed {
        record_number,
        reason,
    };
    let parsed = parse_attribute_list(
        record.repaired_bytes(),
        usize::from(record.attributes_offset),
        usize::try_from(record.bytes_in_use).unwrap_or(usize::MAX),
        attribute_limits(boot, limits),
    )?;
    let resolved_attributes = resolved
        .map(|list| {
            list.extents
                .iter()
                .map(|extent| {
                    parse_attribute(&extent.raw_attribute, attribute_limits(boot, limits))
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?;
    let attributes = resolved_attributes.as_deref().unwrap_or(&parsed.attributes);
    let unresolved_attribute_list = object.has_attribute_list && resolved.is_none();
    let unavailable = ReparseIndexScan::Unavailable;
    let r_name = b"$R".map(u16::from);
    let roots: Vec<_> = attributes
        .iter()
        .filter(|attribute| {
            attribute.attribute_type == INDEX_ROOT && attribute_name_eq(attribute, &r_name)
        })
        .collect();
    if roots.len() > 1 {
        return Err(malformed("more than one $INDEX_ROOT:$R".to_owned()));
    }
    let Some(root_attribute) = roots.first() else {
        if unresolved_attribute_list {
            incomplete.insert(NtfsInventoryIncompleteReason::AttributeListContinuationRequired);
            return Ok(unavailable);
        }
        return Err(malformed("missing $INDEX_ROOT:$R".to_owned()));
    };
    let AttributeBody::Resident(root_body) = &root_attribute.body else {
        return Err(malformed("$INDEX_ROOT:$R is not resident".to_owned()));
    };
    let root = read_reparse_index_root(root_body.value, limits.max_index_entries)
        .map_err(|error| malformed(error.to_string()))?;
    let mut keys = Vec::new();
    push_reparse_keys(&mut keys, &root.node.keys, limits.max_index_entries)?;
    let mut children: VecDeque<u64> = root.node.child_vcns.iter().copied().collect();
    if children.is_empty() {
        return Ok(ReparseIndexScan::Walked {
            keys,
            spilled: false,
            index_blocks: 0,
        });
    }

    let allocation = attributes.iter().find(|attribute| {
        attribute.attribute_type == INDEX_ALLOCATION && attribute_name_eq(attribute, &r_name)
    });
    let bitmap = attributes.iter().find(|attribute| {
        attribute.attribute_type == BITMAP && attribute_name_eq(attribute, &r_name)
    });
    let (Some(allocation), Some(bitmap)) = (allocation, bitmap) else {
        if unresolved_attribute_list {
            incomplete.insert(NtfsInventoryIncompleteReason::AttributeListContinuationRequired);
            return Ok(unavailable);
        }
        return Err(malformed(if allocation.is_none() {
            "root has children but $INDEX_ALLOCATION:$R is missing".to_owned()
        } else {
            "root has children but $BITMAP:$R is missing".to_owned()
        }));
    };
    let Some((allocation_runlist, allocation_bytes, allocation_complete)) =
        parse_index_allocation(record_number, allocation, boot, limits)?
    else {
        return Err(malformed("$INDEX_ALLOCATION:$R is resident".to_owned()));
    };
    if !allocation_complete {
        incomplete.insert(NtfsInventoryIncompleteReason::IndexAllocationContinuationRequired);
        return Ok(unavailable);
    }
    let Some(bitmap_bytes) = read_attribute_value(image, bitmap, boot, limits, bytes_read)? else {
        incomplete.insert(NtfsInventoryIncompleteReason::IndexBitmapContinuationRequired);
        return Ok(unavailable);
    };
    let block_size = usize::try_from(root.index_block_bytes).map_err(|_| {
        NtfsInventoryError::GeometryOverflow {
            calculation: "$R index block size",
        }
    })?;
    let mut visited = BTreeSet::new();
    while let Some(child_vcn) = children.pop_front() {
        if !visited.insert(child_vcn) {
            return Err(malformed(format!(
                "INDX record at VCN {child_vcn} is reachable more than once"
            )));
        }
        if visited.len() > limits.max_index_blocks {
            incomplete.insert(NtfsInventoryIncompleteReason::IndexTraversalLimit);
            return Ok(unavailable);
        }
        let (stream_offset, block_number) = index_child_offset_for(
            record_number,
            child_vcn,
            root.index_block_bytes,
            root.clusters_per_index_block,
            boot.cluster_size_bytes,
        )?;
        let byte_index = usize::try_from(block_number / 8)
            .map_err(|_| NtfsInventoryError::InvalidIndexBitmap { record_number })?;
        if byte_index >= bitmap_bytes.len() {
            return Err(NtfsInventoryError::InvalidIndexBitmap { record_number });
        }
        if bitmap_bytes[byte_index] & (1_u8 << (block_number % 8)) == 0 {
            return Err(NtfsInventoryError::IndexChildNotAllocated {
                record_number,
                child_vcn,
            });
        }
        let block = read_runlist_range(
            image,
            &allocation_runlist,
            stream_offset,
            block_size,
            boot.cluster_size_bytes,
            allocation_bytes,
            bytes_read,
            limits.max_bytes,
        )?;
        let node = read_reparse_index_block(&block, child_vcn, limits.max_index_entries)
            .map_err(|error| malformed(error.to_string()))?;
        push_reparse_keys(&mut keys, &node.keys, limits.max_index_entries)?;
        children.extend(node.child_vcns.iter().copied());
    }
    Ok(ReparseIndexScan::Walked {
        keys,
        spilled: true,
        index_blocks: visited.len(),
    })
}

fn push_reparse_keys(
    keys: &mut Vec<ReparseIndexKey>,
    additional: &[ReparseIndexKey],
    maximum: usize,
) -> Result<(), NtfsInventoryError> {
    if keys
        .len()
        .checked_add(additional.len())
        .is_none_or(|total| total > maximum)
    {
        return Err(NtfsInventoryError::ObjectLimitExceeded { maximum });
    }
    keys.try_reserve(additional.len())
        .map_err(|_| NtfsInventoryError::AllocationFailed)?;
    keys.extend_from_slice(additional);
    Ok(())
}

/// Compares the walked `$R` keys against every in-use base record's `$REPARSE_POINT`.
fn reconcile_reparse_index(
    objects: &[NtfsObject],
    scan: ReparseIndexScan,
    incomplete: &BTreeSet<NtfsInventoryIncompleteReason>,
) -> Result<NtfsReparseIndexEvidence, NtfsInventoryError> {
    // Any gap in the record census could hide a reparse-point record or the `$Reparse`
    // metafile itself, so reconciliation is only claimed when the census is complete.
    let census_incomplete = incomplete.iter().any(|reason| {
        matches!(
            reason,
            NtfsInventoryIncompleteReason::RecordLimit
                | NtfsInventoryIncompleteReason::MftMappingContinuationRequired
                | NtfsInventoryIncompleteReason::AttributeListContinuationRequired
                | NtfsInventoryIncompleteReason::ReferenceOutsideScan
        )
    });
    if census_incomplete {
        return Ok(NtfsReparseIndexEvidence::Unavailable);
    }
    // Reparse-point records keyed by the exact MFT reference `$R` must carry.
    let mut expected: BTreeMap<u64, (u64, Option<u32>, bool)> = BTreeMap::new();
    for object in objects.iter().filter(|object| object.has_reparse_point) {
        let tag = object
            .reparse_point
            .as_deref()
            .and_then(|payload| payload.get(..4))
            .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
        expected.insert(
            object.reference.file_reference(),
            (object.reference.record_number, tag, false),
        );
    }
    let (keys, spilled, index_blocks) = match scan {
        ReparseIndexScan::Unavailable => return Ok(NtfsReparseIndexEvidence::Unavailable),
        ReparseIndexScan::NoRecord => {
            return match expected.values().next() {
                Some((record_number, _, _)) => Err(NtfsInventoryError::ReparseIndexMissing {
                    record_number: *record_number,
                }),
                None => Ok(NtfsReparseIndexEvidence::Absent),
            };
        }
        ReparseIndexScan::Walked {
            keys,
            spilled,
            index_blocks,
        } => (keys, spilled, index_blocks),
    };
    let mut seen_keys = BTreeSet::new();
    for key in &keys {
        if !seen_keys.insert(key.collation_ulongs()) {
            return Err(NtfsInventoryError::ReparseIndexDuplicateKey {
                reparse_tag: key.reparse_tag,
                file_reference: key.file_reference,
            });
        }
        let Some((record_number, attribute_tag, listed)) = expected.get_mut(&key.file_reference)
        else {
            return Err(NtfsInventoryError::ReparseIndexStaleKey {
                reparse_tag: key.reparse_tag,
                file_reference: key.file_reference,
            });
        };
        if let Some(attribute_tag) = *attribute_tag {
            if attribute_tag != key.reparse_tag {
                return Err(NtfsInventoryError::ReparseIndexTagMismatch {
                    record_number: *record_number,
                    index_tag: key.reparse_tag,
                    attribute_tag,
                });
            }
        }
        if *listed {
            // A record carries at most one `$REPARSE_POINT`, so a second key for it is stale.
            return Err(NtfsInventoryError::ReparseIndexStaleKey {
                reparse_tag: key.reparse_tag,
                file_reference: key.file_reference,
            });
        }
        *listed = true;
    }
    if let Some((record_number, tag, _)) = expected.values().find(|(_, _, listed)| !listed) {
        return Err(NtfsInventoryError::ReparseIndexNotListed {
            record_number: *record_number,
            reparse_tag: *tag,
        });
    }
    Ok(NtfsReparseIndexEvidence::Reconciled {
        keys: keys.len(),
        spilled,
        index_blocks,
    })
}

fn append_index_entries<'a>(
    directory: NtfsObjectReference,
    entries: impl Iterator<Item = crate::fs::ntfs_index::NtfsIndexEntry<'a>>,
    output: &mut Vec<NtfsDirectoryEntry>,
    children: &mut VecDeque<u64>,
    maximum: usize,
) -> Result<(), NtfsInventoryError> {
    for entry in entries {
        if let Some(child) = entry.child_vcn {
            children.push_back(child);
        }
        let (Some(reference), Some(key)) = (entry.file_reference, entry.file_name) else {
            continue;
        };
        if key.parent_directory.record_number != directory.record_number {
            return Err(NtfsInventoryError::IndexParentMismatch {
                directory: directory.record_number,
                found_parent: key.parent_directory.record_number,
            });
        }
        if key.parent_directory.sequence_number != directory.sequence_number {
            return Err(NtfsInventoryError::StaleReference {
                record_number: directory.record_number,
                expected_sequence: key.parent_directory.sequence_number,
                found_sequence: directory.sequence_number,
            });
        }
        if output.len() >= maximum {
            return Err(NtfsInventoryError::ObjectLimitExceeded { maximum });
        }
        output.push(NtfsDirectoryEntry {
            target: from_index_reference(reference),
            file_name: NtfsFileName {
                parent: from_index_reference(key.parent_directory),
                namespace: key.namespace,
                name: NtfsName {
                    code_units: key.name.code_units().collect(),
                    is_well_formed: char::decode_utf16(key.name.code_units())
                        .all(|value| value.is_ok()),
                },
                allocated_size: key.allocated_size,
                data_size: key.data_size,
                file_attributes: key.file_attributes,
                reparse_tag_or_ea_size: key.reparse_tag_or_ea_size,
            },
        });
    }
    Ok(())
}

fn parse_index_allocation(
    record_number: u64,
    attribute: &NtfsAttribute<'_>,
    boot: &NtfsBootSector,
    limits: NtfsInventoryLimits,
) -> Result<Option<(NtfsRunlist, u64, bool)>, NtfsInventoryError> {
    let AttributeBody::NonResident(body) = &attribute.body else {
        return Ok(None);
    };
    if body.lowest_vcn != 0 {
        return Err(NtfsInventoryError::ContinuationDataInBaseRecord {
            record_number,
            attribute_id: attribute.id,
        });
    }
    let sizes = body
        .sizes
        .ok_or(NtfsInventoryError::MissingNonResidentSizes {
            record_number,
            attribute_id: attribute.id,
        })?;
    let runlist = parse_mapping_pairs(
        body.mapping_pairs,
        MappingPairsLimits {
            starting_vcn: 0,
            expected_next_vcn: Some(body.expected_next_vcn),
            volume_cluster_count: boot.cluster_count,
            max_runs: limits.max_runs_per_stream,
            max_decoded_clusters: boot.cluster_count,
        },
    )?;
    let mapped = runlist
        .next_vcn
        .checked_mul(boot.cluster_size_bytes)
        .ok_or(NtfsInventoryError::GeometryOverflow {
            calculation: "index allocation mapped bytes",
        })?;
    Ok(Some((runlist, sizes.data, mapped == sizes.allocated)))
}

fn read_attribute_value(
    image: &dyn BoundedImageReader,
    attribute: &NtfsAttribute<'_>,
    boot: &NtfsBootSector,
    limits: NtfsInventoryLimits,
    bytes_read: &mut u64,
) -> Result<Option<Vec<u8>>, NtfsInventoryError> {
    match &attribute.body {
        AttributeBody::Resident(body) => Ok(Some(body.value.to_vec())),
        AttributeBody::NonResident(body) => {
            if body.lowest_vcn != 0 {
                return Ok(None);
            }
            let Some(sizes) = body.sizes else {
                return Ok(None);
            };
            if sizes.initialized < sizes.data {
                return Ok(None);
            }
            let length = usize::try_from(sizes.data).map_err(|_| {
                NtfsInventoryError::ResidentDataLimitExceeded {
                    actual: usize::MAX,
                    maximum: limits.max_attribute_bytes,
                }
            })?;
            if length > limits.max_attribute_bytes {
                return Err(NtfsInventoryError::ResidentDataLimitExceeded {
                    actual: length,
                    maximum: limits.max_attribute_bytes,
                });
            }
            let runlist = parse_mapping_pairs(
                body.mapping_pairs,
                MappingPairsLimits {
                    starting_vcn: 0,
                    expected_next_vcn: Some(body.expected_next_vcn),
                    volume_cluster_count: boot.cluster_count,
                    max_runs: limits.max_runs_per_stream,
                    max_decoded_clusters: boot.cluster_count,
                },
            )?;
            let mapped = runlist
                .next_vcn
                .checked_mul(boot.cluster_size_bytes)
                .ok_or(NtfsInventoryError::GeometryOverflow {
                    calculation: "attribute mapped bytes",
                })?;
            if mapped < sizes.allocated {
                return Ok(None);
            }
            Ok(Some(read_runlist_range(
                image,
                &runlist,
                0,
                length,
                boot.cluster_size_bytes,
                sizes.data,
                bytes_read,
                limits.max_bytes,
            )?))
        }
    }
}

fn index_child_offset(
    record_number: u64,
    child_vcn: u64,
    root: &NtfsIndexRoot<'_>,
    cluster_bytes: u64,
) -> Result<(u64, u64), NtfsInventoryError> {
    index_child_offset_for(
        record_number,
        child_vcn,
        root.index_block_size,
        root.clusters_per_index_block,
        cluster_bytes,
    )
}

/// Maps a child VCN to `(stream byte offset, block number)` for an index whose root declares
/// `index_block_size` and `clusters_per_index_block`.
fn index_child_offset_for(
    record_number: u64,
    child_vcn: u64,
    index_block_size: u32,
    clusters_per_index_block: u8,
    cluster_bytes: u64,
) -> Result<(u64, u64), NtfsInventoryError> {
    let index_block_bytes = u64::from(index_block_size);
    let geometry_error = || NtfsInventoryError::InvalidIndexRootGeometry {
        record_number,
        cluster_bytes,
        index_block_bytes: index_block_size,
        encoded_units: clusters_per_index_block,
    };
    if index_block_bytes == 0 {
        return Err(geometry_error());
    }
    let (expected_units, unit_bytes) = if index_block_bytes >= cluster_bytes {
        if index_block_bytes % cluster_bytes != 0 {
            return Err(geometry_error());
        }
        (index_block_bytes / cluster_bytes, cluster_bytes)
    } else {
        if cluster_bytes % index_block_bytes != 0 || index_block_bytes % 512 != 0 {
            return Err(geometry_error());
        }
        (index_block_bytes / 512, 512)
    };
    if u64::from(clusters_per_index_block) != expected_units {
        return Err(geometry_error());
    }
    if child_vcn % expected_units != 0 {
        return Err(NtfsInventoryError::IndexChildVcnMisaligned {
            record_number,
            child_vcn,
        });
    }
    Ok((
        child_vcn
            .checked_mul(unit_bytes)
            .ok_or(NtfsInventoryError::GeometryOverflow {
                calculation: "index child offset",
            })?,
        child_vcn / expected_units,
    ))
}

#[allow(clippy::too_many_arguments)]
fn read_runlist_range(
    image: &dyn BoundedImageReader,
    runlist: &NtfsRunlist,
    logical_offset: u64,
    length: usize,
    cluster_bytes: u64,
    data_bytes: u64,
    bytes_read: &mut u64,
    max_bytes: u64,
) -> Result<Vec<u8>, NtfsInventoryError> {
    let length_u64 = u64::try_from(length).map_err(|_| NtfsInventoryError::GeometryOverflow {
        calculation: "stream read length",
    })?;
    let end =
        logical_offset
            .checked_add(length_u64)
            .ok_or(NtfsInventoryError::GeometryOverflow {
                calculation: "stream read end",
            })?;
    if end > data_bytes {
        return Err(NtfsInventoryError::Image(ImageError::OutOfRange {
            offset: logical_offset,
            length: length_u64,
            image_length: data_bytes,
        }));
    }
    let total = bytes_read
        .checked_add(length_u64)
        .ok_or(NtfsInventoryError::GeometryOverflow {
            calculation: "inventory bytes read",
        })?;
    if total > max_bytes {
        return Err(NtfsInventoryError::ByteLimitExceeded {
            requested_total: total,
            maximum: max_bytes,
        });
    }
    let mut output = vec![0_u8; length];
    let mut cursor = logical_offset;
    let mut output_offset = 0_usize;
    while cursor < end {
        let extent = find_extent(&runlist.extents, cursor, cluster_bytes).ok_or(
            NtfsInventoryError::GeometryOverflow {
                calculation: "unmapped stream range",
            },
        )?;
        let extent_start = extent.vcn * cluster_bytes;
        let extent_end = extent_start
            .checked_add(extent.length * cluster_bytes)
            .ok_or(NtfsInventoryError::GeometryOverflow {
                calculation: "extent end",
            })?;
        let chunk_end = end.min(extent_end);
        let chunk_len = usize::try_from(chunk_end - cursor).map_err(|_| {
            NtfsInventoryError::GeometryOverflow {
                calculation: "stream chunk length",
            }
        })?;
        let ExtentLocation::Physical { lcn } = extent.location else {
            return Err(NtfsInventoryError::GeometryOverflow {
                calculation: "sparse metadata stream",
            });
        };
        let physical = lcn
            .checked_mul(cluster_bytes)
            .and_then(|base| base.checked_add(cursor - extent_start))
            .ok_or(NtfsInventoryError::GeometryOverflow {
                calculation: "stream physical offset",
            })?;
        read_chunked(
            image,
            physical,
            &mut output[output_offset..output_offset + chunk_len],
        )?;
        cursor = chunk_end;
        output_offset += chunk_len;
    }
    *bytes_read = total;
    Ok(output)
}

fn find_extent(extents: &[NtfsExtent], logical: u64, cluster_bytes: u64) -> Option<NtfsExtent> {
    extents.iter().copied().find(|extent| {
        let start = extent.vcn.saturating_mul(cluster_bytes);
        let end = start.saturating_add(extent.length.saturating_mul(cluster_bytes));
        logical >= start && logical < end
    })
}

fn read_chunked(
    image: &dyn BoundedImageReader,
    mut offset: u64,
    mut output: &mut [u8],
) -> Result<(), ImageError> {
    while !output.is_empty() {
        let length = output.len().min(image.max_read_bytes());
        let bytes = image.read_exact_at(offset, length)?;
        output[..length].copy_from_slice(&bytes);
        offset = offset
            .checked_add(u64::try_from(length).unwrap_or(u64::MAX))
            .ok_or_else(|| ImageError::RangeOverflow {
                offset,
                length: u64::try_from(length).unwrap_or(u64::MAX),
            })?;
        output = &mut output[length..];
    }
    Ok(())
}

fn validate_references(
    objects: &[NtfsObject],
    scan_records: u64,
    incomplete: &mut BTreeSet<NtfsInventoryIncompleteReason>,
) -> Result<(), NtfsInventoryError> {
    let records: BTreeMap<u64, u16> = objects
        .iter()
        .map(|object| {
            (
                object.reference.record_number,
                object.reference.sequence_number,
            )
        })
        .collect();
    for object in objects {
        for entry in &object.directory_entries {
            if entry.target.record_number >= scan_records {
                incomplete.insert(NtfsInventoryIncompleteReason::ReferenceOutsideScan);
                continue;
            }
            let Some(found) = records.get(&entry.target.record_number) else {
                return Err(NtfsInventoryError::ReferenceToUnusedRecord {
                    record_number: entry.target.record_number,
                });
            };
            if *found != entry.target.sequence_number {
                return Err(NtfsInventoryError::StaleReference {
                    record_number: entry.target.record_number,
                    expected_sequence: entry.target.sequence_number,
                    found_sequence: *found,
                });
            }
        }
        for name in &object.file_names {
            if name.parent.record_number >= scan_records {
                incomplete.insert(NtfsInventoryIncompleteReason::ReferenceOutsideScan);
                continue;
            }
            if let Some(found) = records.get(&name.parent.record_number) {
                if *found != name.parent.sequence_number {
                    return Err(NtfsInventoryError::StaleReference {
                        record_number: name.parent.record_number,
                        expected_sequence: name.parent.sequence_number,
                        found_sequence: *found,
                    });
                }
            }
        }
    }
    Ok(())
}

const fn decode_reference(raw: u64) -> NtfsObjectReference {
    NtfsObjectReference {
        record_number: raw & 0x0000_ffff_ffff_ffff,
        sequence_number: (raw >> 48) as u16,
    }
}
const fn from_index_reference(reference: NtfsFileReference) -> NtfsObjectReference {
    NtfsObjectReference {
        record_number: reference.record_number,
        sequence_number: reference.sequence_number,
    }
}
const fn parse_namespace(raw: u8) -> Option<FileNameNamespace> {
    match raw {
        0 => Some(FileNameNamespace::Posix),
        1 => Some(FileNameNamespace::Win32),
        2 => Some(FileNameNamespace::Dos),
        3 => Some(FileNameNamespace::Win32AndDos),
        _ => None,
    }
}
const fn le_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}
const fn le_u64(bytes: &[u8], offset: usize) -> u64 {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::ntfs::{NtfsBootSector, RecordSize};
    use crate::fs::ntfs_normalize::{NtfsNormalizeLimits, normalize_inventory};
    use crate::object::ObjectGraphLimits;
    use crate::overlay::{OverlayLimits, OverlayPlan, OverlayWrite};
    use crate::preservation::{
        FieldDisposition, NtfsVolumeIdentity, NtfsVolumeLabelIdentity, PreservationField,
        PreservationLimits, decode_escrow, evaluate_ntfs,
    };
    use crate::{FileSystem, GuaranteeMode};
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TempImage(PathBuf);

    impl TempImage {
        fn create(bytes: &[u8]) -> Self {
            let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "starconverter-ntfs-inventory-{}-{sequence}.img",
                std::process::id()
            ));
            fs::write(&path, bytes).unwrap();
            Self(path)
        }
    }

    impl Drop for TempImage {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    const fn boot() -> NtfsBootSector {
        NtfsBootSector {
            bytes_per_sector: 512,
            sectors_per_cluster: 8,
            cluster_size_bytes: 4096,
            declared_sectors: 127,
            cluster_count: 15,
            filesystem_bytes: 127 * 512,
            minimum_image_bytes: 128 * 512,
            mft_lcn: 4,
            mft_mirror_lcn: 8,
            mft_record_size: RecordSize {
                encoded: -10,
                bytes: 1024,
            },
            index_buffer_size: RecordSize {
                encoded: -10,
                bytes: 1024,
            },
            volume_serial_number: 1,
            boot_checksum: 0,
            media_descriptor: 0xf8,
            sectors_per_track: 63,
            head_count: 255,
            hidden_sectors: 0,
        }
    }

    fn empty_record(record_number: u32, in_use: bool) -> Vec<u8> {
        let mut record = vec![0_u8; 1024];
        record[0..4].copy_from_slice(b"FILE");
        record[4..6].copy_from_slice(&48_u16.to_le_bytes());
        record[6..8].copy_from_slice(&3_u16.to_le_bytes());
        record[16..18].copy_from_slice(&1_u16.to_le_bytes());
        record[18..20].copy_from_slice(&1_u16.to_le_bytes());
        record[20..22].copy_from_slice(&56_u16.to_le_bytes());
        record[22..24].copy_from_slice(&u16::from(in_use).to_le_bytes());
        record[24..28].copy_from_slice(&64_u32.to_le_bytes());
        record[28..32].copy_from_slice(&1024_u32.to_le_bytes());
        record[40..42].copy_from_slice(&1_u16.to_le_bytes());
        record[44..48].copy_from_slice(&record_number.to_le_bytes());
        record[56..60].copy_from_slice(&0xffff_ffff_u32.to_le_bytes());
        record[48..50].copy_from_slice(&0xa55a_u16.to_le_bytes());
        record[50..54].copy_from_slice(&[0, 0, 0, 0]);
        record[510..512].copy_from_slice(&0xa55a_u16.to_le_bytes());
        record[1022..1024].copy_from_slice(&0xa55a_u16.to_le_bytes());
        record
    }

    fn record_with_attributes(
        record_number: u32,
        sequence_number: u16,
        base_record: Option<(u64, u16)>,
        attributes: &[Vec<u8>],
    ) -> Vec<u8> {
        let mut record = empty_record(record_number, true);
        record[16..18].copy_from_slice(&sequence_number.to_le_bytes());
        if let Some((base_number, base_sequence)) = base_record {
            let reference = base_number | (u64::from(base_sequence) << 48);
            record[32..40].copy_from_slice(&reference.to_le_bytes());
        }
        let mut cursor = 56_usize;
        for attribute in attributes {
            record[cursor..cursor + attribute.len()].copy_from_slice(attribute);
            cursor += attribute.len();
        }
        record[cursor..cursor + 4].copy_from_slice(&0xffff_ffff_u32.to_le_bytes());
        cursor += 8;
        record[24..28].copy_from_slice(&u32::try_from(cursor).unwrap().to_le_bytes());
        record
    }

    fn resident_attribute(attribute_type: u32, id: u16, value: &[u8]) -> Vec<u8> {
        let length = (24 + value.len() + 7) & !7;
        let mut attribute = vec![0_u8; length];
        attribute[0..4].copy_from_slice(&attribute_type.to_le_bytes());
        attribute[4..8].copy_from_slice(&u32::try_from(length).unwrap().to_le_bytes());
        attribute[14..16].copy_from_slice(&id.to_le_bytes());
        attribute[16..20].copy_from_slice(&u32::try_from(value.len()).unwrap().to_le_bytes());
        attribute[20..22].copy_from_slice(&24_u16.to_le_bytes());
        attribute[24..24 + value.len()].copy_from_slice(value);
        attribute
    }

    fn named_resident_attribute(
        attribute_type: u32,
        id: u16,
        name: &[u16],
        value: &[u8],
    ) -> Vec<u8> {
        let name_bytes = name.len() * 2;
        let value_offset = (24 + name_bytes + 7) & !7;
        let length = (value_offset + value.len() + 7) & !7;
        let mut attribute = vec![0_u8; length];
        attribute[0..4].copy_from_slice(&attribute_type.to_le_bytes());
        attribute[4..8].copy_from_slice(&u32::try_from(length).unwrap().to_le_bytes());
        attribute[9] = u8::try_from(name.len()).unwrap();
        attribute[10..12].copy_from_slice(&24_u16.to_le_bytes());
        attribute[14..16].copy_from_slice(&id.to_le_bytes());
        attribute[16..20].copy_from_slice(&u32::try_from(value.len()).unwrap().to_le_bytes());
        attribute[20..22].copy_from_slice(&u16::try_from(value_offset).unwrap().to_le_bytes());
        for (index, unit) in name.iter().enumerate() {
            attribute[24 + index * 2..26 + index * 2].copy_from_slice(&unit.to_le_bytes());
        }
        attribute[value_offset..value_offset + value.len()].copy_from_slice(value);
        attribute
    }

    fn volume_label_value(units: &[u16]) -> Vec<u8> {
        units.iter().flat_map(|unit| unit.to_le_bytes()).collect()
    }

    fn empty_index_root() -> Vec<u8> {
        let mut value = vec![0_u8; 48];
        value[0..4].copy_from_slice(&FILE_NAME.to_le_bytes());
        value[4..8].copy_from_slice(&1_u32.to_le_bytes());
        value[8..12].copy_from_slice(&1024_u32.to_le_bytes());
        value[12] = 1;
        value[16..20].copy_from_slice(&16_u32.to_le_bytes());
        value[20..24].copy_from_slice(&32_u32.to_le_bytes());
        value[24..28].copy_from_slice(&32_u32.to_le_bytes());
        value[40..42].copy_from_slice(&16_u16.to_le_bytes());
        value[44..46].copy_from_slice(&2_u16.to_le_bytes());
        value
    }

    fn identity_pipeline_image(label: &[u16]) -> Vec<u8> {
        let mut bytes = vec![0_u8; 128 * 512];
        let mft_offset = 4 * 4096;
        let label = resident_attribute(VOLUME_NAME, 1, &volume_label_value(label));
        let mut volume = record_with_attributes(3, 1, None, &[label]);
        volume[22..24].copy_from_slice(&5_u16.to_le_bytes());

        let standard = resident_attribute(STANDARD_INFORMATION, 1, &{
            let mut value = vec![0_u8; 48];
            value[32..36].copy_from_slice(&0x10_u32.to_le_bytes());
            value
        });
        let mut root_name = file_name_value(5, 1, &[u16::from(b'.')], 1);
        root_name[56..60].copy_from_slice(&0x10_u32.to_le_bytes());
        let name = resident_attribute(FILE_NAME, 2, &root_name);
        let index = named_resident_attribute(
            INDEX_ROOT,
            3,
            &[0x24, 0x49, 0x33, 0x30],
            &empty_index_root(),
        );
        let mut root = record_with_attributes(5, 1, None, &[standard, name, index]);
        root[22..24].copy_from_slice(&3_u16.to_le_bytes());

        for record_number in [0_u32, 1, 2, 4] {
            let offset = mft_offset + usize::try_from(record_number).unwrap() * 1024;
            bytes[offset..offset + 1024].copy_from_slice(&empty_record(record_number, false));
        }
        bytes[mft_offset + 3 * 1024..mft_offset + 4 * 1024].copy_from_slice(&volume);
        bytes[mft_offset + 5 * 1024..mft_offset + 6 * 1024].copy_from_slice(&root);
        bytes
    }

    fn two_cluster_bootstrap(data_bytes: u64) -> MftBootstrap {
        let mut value = bootstrap(data_bytes);
        value.runlist.extents[0].length = 2;
        value.runlist.next_vcn = 2;
        value.runlist.decoded_clusters = 2;
        value.runlist.physical_clusters = 2;
        value.allocated_bytes = 8192;
        value
    }

    #[allow(clippy::too_many_arguments)]
    fn nonresident_attribute(
        id: u16,
        lowest_vcn: u64,
        highest_vcn: u64,
        flags: u16,
        allocated: u64,
        data: u64,
        initialized: u64,
        compressed: u64,
        mapping_pairs: &[u8],
    ) -> Vec<u8> {
        let header = if flags == 0 { 64 } else { 72 };
        let length = (header + mapping_pairs.len() + 7) & !7;
        let mut attribute = vec![0_u8; length];
        attribute[0..4].copy_from_slice(&DATA.to_le_bytes());
        attribute[4..8].copy_from_slice(&u32::try_from(length).unwrap().to_le_bytes());
        attribute[8] = 1;
        attribute[12..14].copy_from_slice(&flags.to_le_bytes());
        attribute[14..16].copy_from_slice(&id.to_le_bytes());
        attribute[16..24].copy_from_slice(&lowest_vcn.to_le_bytes());
        attribute[24..32].copy_from_slice(&highest_vcn.to_le_bytes());
        attribute[32..34].copy_from_slice(&u16::try_from(header).unwrap().to_le_bytes());
        attribute[40..48].copy_from_slice(&allocated.to_le_bytes());
        attribute[48..56].copy_from_slice(&data.to_le_bytes());
        attribute[56..64].copy_from_slice(&initialized.to_le_bytes());
        if header == 72 {
            attribute[64..72].copy_from_slice(&compressed.to_le_bytes());
        }
        if flags & 0x00ff != 0 {
            attribute[34] = 1;
        }
        attribute[header..header + mapping_pairs.len()].copy_from_slice(mapping_pairs);
        attribute
    }

    fn attribute_list_entry(
        attribute_type: u32,
        lowest_vcn: u64,
        record_number: u64,
        sequence_number: u16,
        instance: u16,
    ) -> Vec<u8> {
        let mut entry = vec![0_u8; 32];
        entry[0..4].copy_from_slice(&attribute_type.to_le_bytes());
        entry[4..6].copy_from_slice(&32_u16.to_le_bytes());
        entry[8..16].copy_from_slice(&lowest_vcn.to_le_bytes());
        let reference = record_number | (u64::from(sequence_number) << 48);
        entry[16..24].copy_from_slice(&reference.to_le_bytes());
        entry[24..26].copy_from_slice(&instance.to_le_bytes());
        entry
    }

    fn continued_stream_image(extension_sequence: u16, extension_base: (u64, u16)) -> Vec<u8> {
        let file_name =
            resident_attribute(FILE_NAME, 3, &file_name_value(0, 1, &[u16::from(b'x')], 1));
        let first_data = nonresident_attribute(4, 0, 0, 0, 8192, 7000, 7000, 0, &[0x11, 1, 8, 0]);
        let continued_data = nonresident_attribute(5, 1, 1, 0, 0, 0, 0, 0, &[0x11, 1, 9, 0]);
        let mut list_value = Vec::new();
        list_value.extend(attribute_list_entry(FILE_NAME, 0, 1, 2, 3));
        list_value.extend(attribute_list_entry(DATA, 0, 0, 1, 4));
        list_value.extend(attribute_list_entry(DATA, 1, 1, 2, 5));
        let list = resident_attribute(ATTRIBUTE_LIST, 2, &list_value);
        let base = record_with_attributes(0, 1, None, &[list, first_data]);
        let extension = record_with_attributes(
            1,
            extension_sequence,
            Some(extension_base),
            &[file_name, continued_data],
        );
        let mut bytes = vec![0_u8; 128 * 512];
        let offset = 4 * 4096;
        bytes[offset..offset + 1024].copy_from_slice(&base);
        bytes[offset + 1024..offset + 2048].copy_from_slice(&extension);
        bytes
    }

    fn bootstrap(data_bytes: u64) -> MftBootstrap {
        MftBootstrap {
            runlist: NtfsRunlist {
                extents: vec![NtfsExtent {
                    vcn: 0,
                    length: 1,
                    location: ExtentLocation::Physical { lcn: 4 },
                }],
                next_vcn: 1,
                encoded_runs: 1,
                bytes_consumed: 4,
                decoded_clusters: 1,
                physical_clusters: 1,
                sparse_clusters: 0,
            },
            allocated_bytes: 4096,
            data_bytes,
            initialized_bytes: data_bytes,
            mapping_complete: true,
            record_zero_sequence_number: 1,
        }
    }

    fn file_name_value(parent: u64, sequence: u16, name: &[u16], namespace: u8) -> Vec<u8> {
        let mut bytes = vec![0_u8; 66 + name.len() * 2];
        let reference = parent | (u64::from(sequence) << 48);
        bytes[0..8].copy_from_slice(&reference.to_le_bytes());
        bytes[40..48].copy_from_slice(&4096_u64.to_le_bytes());
        bytes[48..56].copy_from_slice(&12_u64.to_le_bytes());
        bytes[56..60].copy_from_slice(&0x20_u32.to_le_bytes());
        bytes[64] = u8::try_from(name.len()).unwrap();
        bytes[65] = namespace;
        for (index, unit) in name.iter().enumerate() {
            bytes[66 + index * 2..68 + index * 2].copy_from_slice(&unit.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn parses_lossless_file_name_and_parent_reference() {
        let bytes = file_name_value(5, 7, &[u16::from(b'A'), 0xd800], 1);
        let name = parse_file_name(42, &bytes, 255).unwrap();
        assert_eq!(
            name.parent,
            NtfsObjectReference {
                record_number: 5,
                sequence_number: 7
            }
        );
        assert_eq!(name.namespace, FileNameNamespace::Win32);
        assert_eq!(name.name.code_units, vec![u16::from(b'A'), 0xd800]);
        assert!(!name.name.is_well_formed);
    }

    #[test]
    fn rejects_empty_invalid_and_over_limit_file_names() {
        assert!(matches!(
            parse_file_name(1, &file_name_value(5, 1, &[], 1), 255),
            Err(NtfsInventoryError::InvalidFileName { .. })
        ));
        assert!(matches!(
            parse_file_name(1, &file_name_value(5, 1, &[65], 4), 255),
            Err(NtfsInventoryError::InvalidFileName { .. })
        ));
        assert!(matches!(
            parse_file_name(1, &file_name_value(5, 1, &[65, 66], 1), 1),
            Err(NtfsInventoryError::InvalidFileName { .. })
        ));
    }

    #[test]
    fn standard_information_supports_legacy_and_current_layouts() {
        let legacy = vec![0_u8; 48];
        let parsed = parse_standard_information(1, &legacy).unwrap();
        assert_eq!(parsed.security_id, None);
        let mut current = vec![0_u8; 72];
        current[52..56].copy_from_slice(&91_u32.to_le_bytes());
        assert_eq!(
            parse_standard_information(1, &current).unwrap().security_id,
            Some(91)
        );
        assert!(matches!(
            parse_standard_information(1, &[0; 47]),
            Err(NtfsInventoryError::InvalidStandardInformation { .. })
        ));
    }

    #[test]
    fn index_child_offsets_accept_unsigned_128_units_and_reject_wrong_geometry() {
        let mut value = empty_index_root();
        value[8..12].copy_from_slice(&65_536_u32.to_le_bytes());
        value[12] = 128;
        let root = parse_index_root(&value, NtfsIndexLimits::default()).unwrap();
        assert_eq!(index_child_offset(5, 128, &root, 512).unwrap(), (65_536, 1));

        value[12] = 127;
        let root = parse_index_root(&value, NtfsIndexLimits::default()).unwrap();
        assert!(matches!(
            index_child_offset(5, 128, &root, 512),
            Err(NtfsInventoryError::InvalidIndexRootGeometry {
                record_number: 5,
                encoded_units: 127,
                ..
            })
        ));
    }

    #[test]
    fn normalizes_physical_and_sparse_extents_exactly() {
        let runlist = NtfsRunlist {
            extents: vec![
                NtfsExtent {
                    vcn: 0,
                    length: 2,
                    location: ExtentLocation::Physical { lcn: 9 },
                },
                NtfsExtent {
                    vcn: 2,
                    length: 1,
                    location: ExtentLocation::Sparse,
                },
            ],
            next_vcn: 3,
            encoded_runs: 2,
            bytes_consumed: 5,
            decoded_clusters: 3,
            physical_clusters: 2,
            sparse_clusters: 1,
        };
        let extents = normalize_extents(7, 3, &runlist, 4096).unwrap();
        assert_eq!(
            extents[0],
            NtfsInventoryExtent {
                stream_id: (7 << 16) | 3,
                logical_offset: 0,
                length: 8192,
                placement: NtfsExtentPlacement::Physical {
                    byte_offset: 9 * 4096
                }
            }
        );
        assert_eq!(extents[1].placement, NtfsExtentPlacement::Sparse);
    }

    #[test]
    fn inventories_compressed_stream_compression_unit() {
        let file_name =
            resident_attribute(FILE_NAME, 1, &file_name_value(5, 1, &[u16::from(b'c')], 1));
        let data = nonresident_attribute(2, 0, 1, 1, 4096, 6, 6, 4096, &[0x11, 1, 8, 0x01, 1, 0]);
        let record = record_with_attributes(0, 1, None, &[file_name, data]);
        let mut bytes = vec![0_u8; 128 * 512];
        let offset = 4 * 4096;
        bytes[offset..offset + 1024].copy_from_slice(&record);
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();
        let inventory = inventory_ntfs(
            &image,
            &boot(),
            &bootstrap(1024),
            NtfsInventoryLimits::default(),
        )
        .unwrap();
        assert_eq!(inventory.objects.len(), 1);
        let stream = &inventory.objects[0].data_streams[0];
        assert!(stream.compressed);
        assert_eq!(stream.compression_block_bytes, 8192);
        let NtfsStreamStorage::NonResident { extents, .. } = &stream.storage else {
            panic!("non-resident");
        };
        assert_eq!(extents.len(), 2);
        assert!(matches!(extents[1].placement, NtfsExtentPlacement::Sparse));
    }

    #[test]
    fn stale_directory_reference_is_fatal() {
        let target = NtfsObject {
            reference: NtfsObjectReference {
                record_number: 1,
                sequence_number: 3,
            },
            hard_link_count: 1,
            is_directory: false,
            is_metadata: false,
            standard_information: None,
            file_names: Vec::new(),
            data_streams: Vec::new(),
            attribute_census: Vec::new(),
            directory_entries: Vec::new(),
            has_reparse_point: false,
            reparse_point: None,
            has_attribute_list: false,
            directory_index_complete: true,
        };
        let mut root = target.clone();
        root.reference = NtfsObjectReference {
            record_number: 0,
            sequence_number: 1,
        };
        root.is_directory = true;
        root.directory_entries.push(NtfsDirectoryEntry {
            target: NtfsObjectReference {
                record_number: 1,
                sequence_number: 2,
            },
            file_name: NtfsFileName {
                parent: root.reference,
                namespace: FileNameNamespace::Win32,
                name: NtfsName {
                    code_units: vec![65],
                    is_well_formed: true,
                },
                allocated_size: 0,
                data_size: 0,
                file_attributes: 0,
                reparse_tag_or_ea_size: 0,
            },
        });
        assert!(matches!(
            validate_references(&[root, target], 2, &mut BTreeSet::new()),
            Err(NtfsInventoryError::StaleReference { .. })
        ));
    }

    #[test]
    fn references_beyond_bounded_scan_are_explicitly_incomplete() {
        let object = NtfsObject {
            reference: NtfsObjectReference {
                record_number: 0,
                sequence_number: 1,
            },
            hard_link_count: 1,
            is_directory: true,
            is_metadata: false,
            standard_information: None,
            file_names: Vec::new(),
            data_streams: Vec::new(),
            attribute_census: Vec::new(),
            directory_entries: vec![NtfsDirectoryEntry {
                target: NtfsObjectReference {
                    record_number: 99,
                    sequence_number: 2,
                },
                file_name: NtfsFileName {
                    parent: NtfsObjectReference {
                        record_number: 0,
                        sequence_number: 1,
                    },
                    namespace: FileNameNamespace::Posix,
                    name: NtfsName {
                        code_units: vec![65],
                        is_well_formed: true,
                    },
                    allocated_size: 0,
                    data_size: 0,
                    file_attributes: 0,
                    reparse_tag_or_ea_size: 0,
                },
            }],
            has_reparse_point: false,
            reparse_point: None,
            has_attribute_list: false,
            directory_index_complete: true,
        };
        let mut reasons = BTreeSet::new();
        validate_references(&[object], 1, &mut reasons).unwrap();
        assert!(reasons.contains(&NtfsInventoryIncompleteReason::ReferenceOutsideScan));
    }

    #[test]
    fn scans_initialized_records_from_a_regular_image_only() {
        let mut bytes = vec![0_u8; 128 * 512];
        let offset = 4 * 4096;
        bytes[offset..offset + 1024].copy_from_slice(&empty_record(0, true));
        // NTFS-3G leaves the embedded identity at zero in never-allocated records. The in-use flag
        // is the authority here; the unused record is ignored without weakening live identities.
        bytes[offset + 1024..offset + 2048].copy_from_slice(&empty_record(0, false));
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();
        let inventory = inventory_ntfs(
            &image,
            &boot(),
            &bootstrap(2048),
            NtfsInventoryLimits::default(),
        )
        .unwrap();
        assert!(inventory.is_complete());
        assert_eq!(inventory.scanned_records, 2);
        assert_eq!(inventory.objects.len(), 1);
        assert_eq!(inventory.objects[0].reference.record_number, 0);
        assert_eq!(inventory.bytes_read, 2048);
        assert_eq!(inventory.volume_serial_number, boot().volume_serial_number);
        assert_eq!(inventory.volume_label, NtfsVolumeLabelEvidence::Unavailable);
    }

    #[test]
    fn retains_unknown_attribute_headers_in_the_bounded_census() {
        const OBJECT_ID: u32 = 0x40;
        let unknown = named_resident_attribute(
            OBJECT_ID,
            7,
            &"opaque".encode_utf16().collect::<Vec<_>>(),
            &[0x5a; 16],
        );
        let record = record_with_attributes(0, 1, None, &[unknown]);
        let mut bytes = vec![0_u8; 128 * 512];
        let offset = 4 * 4096;
        bytes[offset..offset + 1024].copy_from_slice(&record);
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();
        let inventory = inventory_ntfs(
            &image,
            &boot(),
            &bootstrap(1024),
            NtfsInventoryLimits::default(),
        )
        .unwrap();

        let census = &inventory.objects[0].attribute_census;
        assert_eq!(census.len(), 1);
        assert_eq!(census[0].attribute_type, OBJECT_ID);
        assert_eq!(census[0].attribute_id, 7);
        assert!(census[0].resident);
        assert_eq!(census[0].flags_raw, 0);
        assert_eq!(
            census[0].name.as_ref().unwrap().code_units,
            "opaque".encode_utf16().collect::<Vec<_>>()
        );
    }

    fn symlink_reparse_payload() -> Vec<u8> {
        let mut payload = vec![0_u8; 16];
        payload[..4].copy_from_slice(&0xa000_000c_u32.to_le_bytes());
        payload[4..6].copy_from_slice(&8_u16.to_le_bytes());
        payload
    }

    fn parse_test_attribute(bytes: &[u8]) -> NtfsAttribute<'_> {
        parse_attribute(
            bytes,
            attribute_limits(&boot(), NtfsInventoryLimits::default()),
        )
        .unwrap()
    }

    #[test]
    fn captures_resident_reparse_point_bytes_and_refuses_incomplete_forms() {
        let payload = symlink_reparse_payload();
        let encoded = resident_attribute(REPARSE_POINT, 8, &payload);
        let parsed = parse_test_attribute(&encoded);
        let (present, captured) =
            inventory_reparse_point(16, &[parsed], NtfsInventoryLimits::default()).unwrap();
        assert!(present);
        assert_eq!(captured.as_deref(), Some(payload.as_slice()));

        let named = named_resident_attribute(
            REPARSE_POINT,
            8,
            &"rp".encode_utf16().collect::<Vec<_>>(),
            &payload,
        );
        let parsed = parse_test_attribute(&named);
        assert!(matches!(
            inventory_reparse_point(16, &[parsed], NtfsInventoryLimits::default()),
            Err(NtfsInventoryError::NamedReparsePoint { record_number: 16 })
        ));

        let first = resident_attribute(REPARSE_POINT, 8, &payload);
        let second = resident_attribute(REPARSE_POINT, 9, &payload);
        let parsed_first = parse_test_attribute(&first);
        let parsed_second = parse_test_attribute(&second);
        assert!(matches!(
            inventory_reparse_point(
                16,
                &[parsed_first, parsed_second],
                NtfsInventoryLimits::default()
            ),
            Err(NtfsInventoryError::DuplicateReparsePoint { record_number: 16 })
        ));

        let short = resident_attribute(REPARSE_POINT, 8, &[0; 7]);
        let parsed = parse_test_attribute(&short);
        assert!(matches!(
            inventory_reparse_point(16, &[parsed], NtfsInventoryLimits::default()),
            Err(NtfsInventoryError::InvalidReparsePoint {
                record_number: 16,
                actual: 7
            })
        ));

        let mut mismatched = payload;
        mismatched[4..6].copy_from_slice(&0_u16.to_le_bytes());
        let encoded = resident_attribute(REPARSE_POINT, 8, &mismatched);
        let parsed = parse_test_attribute(&encoded);
        assert!(matches!(
            inventory_reparse_point(16, &[parsed], NtfsInventoryLimits::default()),
            Err(NtfsInventoryError::InvalidReparsePoint {
                record_number: 16,
                actual: 16
            })
        ));

        let mut nonresident = nonresident_attribute(8, 0, 0, 0, 4096, 16, 16, 0, &[0x11, 1, 8]);
        nonresident[0..4].copy_from_slice(&REPARSE_POINT.to_le_bytes());
        let parsed = parse_test_attribute(&nonresident);
        let (present, captured) =
            inventory_reparse_point(16, &[parsed], NtfsInventoryLimits::default()).unwrap();
        assert!(present);
        assert_eq!(captured, None);
    }

    /// Twelve-record MFT (three clusters at LCN 4) so `$Extend` (record 11) is inside the scan.
    const REPARSE_FIXTURE_RECORDS: u64 = 12;

    fn reparse_fixture_bootstrap() -> MftBootstrap {
        let clusters = REPARSE_FIXTURE_RECORDS * 1024 / 4096;
        MftBootstrap {
            runlist: NtfsRunlist {
                extents: vec![NtfsExtent {
                    vcn: 0,
                    length: clusters,
                    location: ExtentLocation::Physical { lcn: 4 },
                }],
                next_vcn: clusters,
                encoded_runs: 1,
                bytes_consumed: 4,
                decoded_clusters: clusters,
                physical_clusters: clusters,
                sparse_clusters: 0,
            },
            allocated_bytes: clusters * 4096,
            data_bytes: REPARSE_FIXTURE_RECORDS * 1024,
            initialized_bytes: REPARSE_FIXTURE_RECORDS * 1024,
            mapping_complete: true,
            record_zero_sequence_number: 1,
        }
    }

    /// Resident `$INDEX_ROOT:$R` value listing `keys` (in any order).
    fn reparse_root_value(keys: &[(u32, u64)]) -> Vec<u8> {
        use crate::fs::ntfs_reparse_index::{
            NtfsReparseIndexGeometry, NtfsReparseIndexLimits, serialize_ntfs_reparse_index,
        };
        let keys: Vec<_> = keys
            .iter()
            .map(|(reparse_tag, file_reference)| ReparseIndexKey {
                reparse_tag: *reparse_tag,
                file_reference: *file_reference,
            })
            .collect();
        serialize_ntfs_reparse_index(
            &keys,
            NtfsReparseIndexGeometry {
                cluster_bytes: 4096,
                index_block_bytes: 4096,
                resident_root_bytes: 1024,
            },
            NtfsReparseIndexLimits::default(),
        )
        .unwrap()
        .index_root
    }

    /// The `$Extend\$Reparse` metafile record with a resident `$R` root listing `keys`.
    fn reparse_metafile_record(record_number: u32, keys: &[(u32, u64)]) -> Vec<u8> {
        let name: Vec<u16> = "$Reparse".encode_utf16().collect();
        record_with_attributes(
            record_number,
            1,
            None,
            &[
                resident_attribute(
                    FILE_NAME,
                    2,
                    &file_name_value(NTFS_EXTEND_RECORD, 1, &name, 3),
                ),
                named_resident_attribute(
                    INDEX_ROOT,
                    3,
                    &[u16::from(b'$'), u16::from(b'R')],
                    &reparse_root_value(keys),
                ),
            ],
        )
    }

    /// Image whose MFT holds `records` (all others unused) using the reparse fixture geometry.
    fn reparse_fixture_image(records: &[(u32, Vec<u8>)]) -> Vec<u8> {
        let mut bytes = vec![0_u8; 128 * 512];
        let mft = 4 * 4096;
        for record_number in 0..u32::try_from(REPARSE_FIXTURE_RECORDS).unwrap() {
            let record = records
                .iter()
                .find(|(number, _)| *number == record_number)
                .map_or_else(|| empty_record(record_number, false), |(_, r)| r.clone());
            let offset = mft + usize::try_from(record_number).unwrap() * 1024;
            bytes[offset..offset + 1024].copy_from_slice(&record);
        }
        bytes
    }

    fn inventory_reparse_fixture(
        records: &[(u32, Vec<u8>)],
        limits: NtfsInventoryLimits,
    ) -> Result<NtfsInventory, NtfsInventoryError> {
        let temp = TempImage::create(&reparse_fixture_image(records));
        let image = ImageFile::open(&temp.0).unwrap();
        inventory_ntfs(&image, &boot(), &reparse_fixture_bootstrap(), limits)
    }

    const SYMLINK_TAG: u32 = 0xa000_000c;
    const MOUNT_POINT_TAG: u32 = 0xa000_0003;

    fn reparse_file_record(record_number: u32, sequence: u16) -> Vec<u8> {
        record_with_attributes(
            record_number,
            sequence,
            None,
            &[resident_attribute(
                REPARSE_POINT,
                8,
                &symlink_reparse_payload(),
            )],
        )
    }

    #[test]
    fn inventories_resident_reparse_point_payload_in_the_bounded_census() {
        let payload = symlink_reparse_payload();
        let inventory = inventory_reparse_fixture(
            &[
                (0, reparse_file_record(0, 1)),
                (1, reparse_metafile_record(1, &[(SYMLINK_TAG, 1 << 48)])),
            ],
            NtfsInventoryLimits::default(),
        )
        .unwrap();
        assert!(inventory.objects[0].has_reparse_point);
        assert_eq!(
            inventory.objects[0].reparse_point.as_deref(),
            Some(payload.as_slice())
        );
        assert!(
            inventory.objects[0]
                .attribute_census
                .iter()
                .any(|attribute| attribute.attribute_type == REPARSE_POINT
                    && attribute.resident
                    && attribute.name.is_none())
        );
        assert!(inventory.is_complete());
        assert_eq!(
            inventory.reparse_index,
            NtfsReparseIndexEvidence::Reconciled {
                keys: 1,
                spilled: false,
                index_blocks: 0,
            }
        );
    }

    #[test]
    fn reparse_index_is_absent_without_reparse_points_or_a_reparse_metafile() {
        let inventory = inventory_reparse_fixture(
            &[(0, record_with_attributes(0, 1, None, &[]))],
            NtfsInventoryLimits::default(),
        )
        .unwrap();
        assert_eq!(inventory.reparse_index, NtfsReparseIndexEvidence::Absent);

        // An empty `$R` over a volume without reparse points reconciles to zero keys.
        let inventory = inventory_reparse_fixture(
            &[(1, reparse_metafile_record(1, &[]))],
            NtfsInventoryLimits::default(),
        )
        .unwrap();
        assert_eq!(
            inventory.reparse_index,
            NtfsReparseIndexEvidence::Reconciled {
                keys: 0,
                spilled: false,
                index_blocks: 0,
            }
        );
    }

    #[test]
    fn reparse_index_disagreements_fail_closed() {
        // Reparse point but no `$Extend\$Reparse` at all.
        assert!(matches!(
            inventory_reparse_fixture(
                &[(0, reparse_file_record(0, 1))],
                NtfsInventoryLimits::default()
            ),
            Err(NtfsInventoryError::ReparseIndexMissing { record_number: 0 })
        ));
        // `$R` exists but does not list the record.
        assert!(matches!(
            inventory_reparse_fixture(
                &[
                    (0, reparse_file_record(0, 1)),
                    (1, reparse_metafile_record(1, &[])),
                ],
                NtfsInventoryLimits::default()
            ),
            Err(NtfsInventoryError::ReparseIndexNotListed {
                record_number: 0,
                reparse_tag: Some(SYMLINK_TAG),
            })
        ));
        // `$R` carries the wrong tag for the record.
        assert!(matches!(
            inventory_reparse_fixture(
                &[
                    (0, reparse_file_record(0, 1)),
                    (1, reparse_metafile_record(1, &[(MOUNT_POINT_TAG, 1 << 48)])),
                ],
                NtfsInventoryLimits::default()
            ),
            Err(NtfsInventoryError::ReparseIndexTagMismatch {
                record_number: 0,
                index_tag: MOUNT_POINT_TAG,
                attribute_tag: SYMLINK_TAG,
            })
        ));
        // `$R` names a stale sequence number for the record.
        assert!(matches!(
            inventory_reparse_fixture(
                &[
                    (0, reparse_file_record(0, 1)),
                    (1, reparse_metafile_record(1, &[(SYMLINK_TAG, 2 << 48)])),
                ],
                NtfsInventoryLimits::default()
            ),
            Err(NtfsInventoryError::ReparseIndexStaleKey {
                reparse_tag: SYMLINK_TAG,
                file_reference,
            }) if file_reference == 2 << 48
        ));
        // `$R` additionally names an unused record.
        assert!(matches!(
            inventory_reparse_fixture(
                &[
                    (0, reparse_file_record(0, 1)),
                    (
                        1,
                        reparse_metafile_record(
                            1,
                            &[(SYMLINK_TAG, 1 << 48), (SYMLINK_TAG, (1 << 48) | 7)]
                        )
                    ),
                ],
                NtfsInventoryLimits::default()
            ),
            Err(NtfsInventoryError::ReparseIndexStaleKey {
                reparse_tag: SYMLINK_TAG,
                file_reference,
            }) if file_reference == (1 << 48) | 7
        ));
        // Two `$Extend\$Reparse` metafiles.
        assert!(matches!(
            inventory_reparse_fixture(
                &[
                    (0, reparse_file_record(0, 1)),
                    (1, reparse_metafile_record(1, &[(SYMLINK_TAG, 1 << 48)])),
                    (2, reparse_metafile_record(2, &[(SYMLINK_TAG, 1 << 48)])),
                ],
                NtfsInventoryLimits::default()
            ),
            Err(NtfsInventoryError::DuplicateReparseRecord { record_number: 2 })
        ));
        // A `$Reparse` metafile whose `$R` root is not the reparse profile.
        let mut wrong_collation = reparse_metafile_record(1, &[(SYMLINK_TAG, 1 << 48)]);
        let first_attribute = 56_usize;
        let root_attribute = first_attribute
            + usize::try_from(le_u32(&wrong_collation, first_attribute + 4)).unwrap();
        let root_value = root_attribute
            + usize::from(u16::from_le_bytes([
                wrong_collation[root_attribute + 20],
                wrong_collation[root_attribute + 21],
            ]));
        assert_eq!(le_u32(&wrong_collation, root_value + 4), 19);
        wrong_collation[root_value + 4..root_value + 8].copy_from_slice(&1_u32.to_le_bytes());
        assert!(matches!(
            inventory_reparse_fixture(
                &[(0, reparse_file_record(0, 1)), (1, wrong_collation)],
                NtfsInventoryLimits::default()
            ),
            Err(NtfsInventoryError::ReparseIndexMalformed {
                record_number: 1,
                ..
            })
        ));
    }

    #[test]
    fn reparse_index_is_unavailable_when_the_census_is_bounded() {
        // A record cap that stops before `$Extend` cannot claim reconciliation either way.
        let inventory = inventory_reparse_fixture(
            &[
                (0, reparse_file_record(0, 1)),
                (1, reparse_metafile_record(1, &[(SYMLINK_TAG, 1 << 48)])),
            ],
            NtfsInventoryLimits {
                max_records: 2,
                ..NtfsInventoryLimits::default()
            },
        )
        .unwrap();
        assert!(!inventory.is_complete());
        assert_eq!(
            inventory.reparse_index,
            NtfsReparseIndexEvidence::Unavailable
        );
    }

    #[test]
    fn volume_identity_flows_from_parser_through_policy_and_escrow() {
        let label: Vec<u16> = "STAR".encode_utf16().collect();
        let temp = TempImage::create(&identity_pipeline_image(&label));
        let image = ImageFile::open(&temp.0).unwrap();
        let inventory = inventory_ntfs(
            &image,
            &boot(),
            &two_cluster_bootstrap(6 * 1024),
            NtfsInventoryLimits::default(),
        )
        .unwrap();
        assert_eq!(inventory.volume_serial_number, 1);
        assert_eq!(
            inventory.volume_label,
            NtfsVolumeLabelEvidence::Exact(label.clone())
        );

        let normalized = normalize_inventory(
            &inventory,
            boot().filesystem_bytes,
            NtfsNormalizeLimits {
                graph: ObjectGraphLimits {
                    max_objects: 16,
                    max_entries: 16,
                    max_streams: 16,
                    max_name_code_units: 255,
                },
                max_extents: 16,
                max_directory_entries: 16,
                max_preservation_bytes: 1024 * 1024,
            },
        )
        .unwrap();
        assert_eq!(normalized.preservation.volume_label, Some(label.clone()));

        let report = evaluate_ntfs(
            &normalized,
            FileSystem::ExFat,
            GuaranteeMode::Escrow,
            PreservationLimits::default(),
        )
        .unwrap();
        let assessment = report
            .assessments
            .iter()
            .find(|value| value.field == PreservationField::VolumeLabel)
            .unwrap();
        assert_eq!(assessment.disposition, FieldDisposition::CanonicalTransform);
        let serial = report
            .assessments
            .iter()
            .find(|value| value.field == PreservationField::VolumeSerial)
            .unwrap();
        assert_eq!(serial.disposition, FieldDisposition::EscrowRequired);
        let decoded = decode_escrow(
            report.escrow.as_deref().unwrap(),
            PreservationLimits::default(),
        )
        .unwrap();
        assert_eq!(
            decoded.ntfs_volume_identity,
            Some(NtfsVolumeIdentity {
                volume_serial_number: 1,
                volume_label: NtfsVolumeLabelIdentity::Exact(label),
            })
        );
    }

    #[test]
    fn volume_name_structural_anomalies_fail_closed() {
        let cases = [
            (
                vec![
                    resident_attribute(VOLUME_NAME, 1, &[65, 0]),
                    resident_attribute(VOLUME_NAME, 2, &[66, 0]),
                ],
                "duplicate",
            ),
            (
                vec![named_resident_attribute(VOLUME_NAME, 1, &[88], &[65, 0])],
                "named",
            ),
            (vec![resident_attribute(VOLUME_NAME, 1, &[65])], "odd"),
            (
                vec![resident_attribute(VOLUME_NAME, 1, &[0; 66])],
                "over-cap",
            ),
        ];
        for (attributes, expected) in cases {
            let mut bytes = vec![0_u8; 128 * 512];
            let offset = 4 * 4096;
            let record = record_with_attributes(3, 1, None, &attributes);
            for record_number in 0_u32..3 {
                let start = offset + usize::try_from(record_number).unwrap() * 1024;
                bytes[start..start + 1024].copy_from_slice(&empty_record(record_number, false));
            }
            bytes[offset + 3 * 1024..offset + 4 * 1024].copy_from_slice(&record);
            let temp = TempImage::create(&bytes);
            let image = ImageFile::open(&temp.0).unwrap();
            let error = inventory_ntfs(
                &image,
                &boot(),
                &bootstrap(4096),
                NtfsInventoryLimits::default(),
            )
            .unwrap_err();
            assert!(
                matches!(
                    (&error, expected),
                    (NtfsInventoryError::DuplicateVolumeName, "duplicate")
                        | (NtfsInventoryError::NamedVolumeName, "named")
                        | (NtfsInventoryError::OddVolumeNameBytes { .. }, "odd")
                        | (
                            NtfsInventoryError::VolumeNameLimitExceeded { .. },
                            "over-cap"
                        )
                ),
                "unexpected {expected} result: {error}"
            );
        }

        let mut nonresident = nonresident_attribute(1, 0, 0, 0, 4096, 2, 2, 0, &[0]);
        nonresident[0..4].copy_from_slice(&VOLUME_NAME.to_le_bytes());
        let mut bytes = vec![0_u8; 128 * 512];
        let offset = 4 * 4096;
        let record = record_with_attributes(3, 1, None, &[nonresident]);
        for record_number in 0_u32..3 {
            let start = offset + usize::try_from(record_number).unwrap() * 1024;
            bytes[start..start + 1024].copy_from_slice(&empty_record(record_number, false));
        }
        bytes[offset + 3 * 1024..offset + 4 * 1024].copy_from_slice(&record);
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();
        assert!(matches!(
            inventory_ntfs(
                &image,
                &boot(),
                &bootstrap(4096),
                NtfsInventoryLimits::default(),
            ),
            Err(NtfsInventoryError::NonResidentVolumeName)
        ));

        let mut outside = vec![0_u8; 128 * 512];
        for record_number in 0_u32..4 {
            let start = offset + usize::try_from(record_number).unwrap() * 1024;
            outside[start..start + 1024].copy_from_slice(&empty_record(record_number, false));
        }
        let wrong_record =
            record_with_attributes(2, 1, None, &[resident_attribute(VOLUME_NAME, 1, &[65, 0])]);
        outside[offset + 2 * 1024..offset + 3 * 1024].copy_from_slice(&wrong_record);
        let temp = TempImage::create(&outside);
        let image = ImageFile::open(&temp.0).unwrap();
        assert!(matches!(
            inventory_ntfs(
                &image,
                &boot(),
                &bootstrap(4096),
                NtfsInventoryLimits::default(),
            ),
            Err(NtfsInventoryError::VolumeNameOutsideVolumeRecord { record_number: 2 })
        ));
    }

    #[test]
    fn scanned_volume_record_preserves_proven_label_absence() {
        let mut bytes = vec![0_u8; 128 * 512];
        let offset = 4 * 4096;
        for record_number in 0_u32..3 {
            let start = offset + usize::try_from(record_number).unwrap() * 1024;
            bytes[start..start + 1024].copy_from_slice(&empty_record(record_number, false));
        }
        let mut volume = empty_record(3, true);
        volume[22..24].copy_from_slice(&5_u16.to_le_bytes());
        bytes[offset + 3 * 1024..offset + 4 * 1024].copy_from_slice(&volume);
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();
        let inventory = inventory_ntfs(
            &image,
            &boot(),
            &bootstrap(4096),
            NtfsInventoryLimits::default(),
        )
        .unwrap();
        assert_eq!(inventory.volume_label, NtfsVolumeLabelEvidence::Absent);
    }

    #[test]
    fn resolves_extension_name_and_merges_data_continuations() {
        let temp = TempImage::create(&continued_stream_image(2, (0, 1)));
        let image = ImageFile::open(&temp.0).unwrap();
        let inventory = inventory_ntfs(
            &image,
            &boot(),
            &bootstrap(2048),
            NtfsInventoryLimits::default(),
        )
        .unwrap();
        assert!(inventory.is_complete());
        assert_eq!(inventory.objects.len(), 1);
        assert_eq!(inventory.extension_records, 1);
        let object = &inventory.objects[0];
        assert_eq!(object.file_names[0].name.code_units, vec![u16::from(b'x')]);
        assert!(object.has_attribute_list);
        assert_eq!(object.data_streams.len(), 1);
        let NtfsStreamStorage::NonResident {
            mapping_complete,
            extents,
            data_bytes,
            ..
        } = &object.data_streams[0].storage
        else {
            panic!("expected non-resident stream")
        };
        assert!(*mapping_complete);
        assert_eq!(*data_bytes, 7000);
        assert_eq!(extents.len(), 2);
        assert_eq!(extents[0].logical_offset, 0);
        assert_eq!(extents[1].logical_offset, 4096);
        assert_eq!(inventory.extents, *extents);
        assert_eq!(
            inventory.physical_allocations,
            vec![
                NtfsPhysicalAllocation {
                    record_number: 0,
                    attribute_type: DATA,
                    attribute_id: 4,
                    starting_vcn: 0,
                    start_lcn: 8,
                    cluster_count: 1,
                },
                NtfsPhysicalAllocation {
                    record_number: 0,
                    attribute_type: DATA,
                    attribute_id: 5,
                    starting_vcn: 1,
                    start_lcn: 9,
                    cluster_count: 1,
                },
            ]
        );
        assert_eq!(inventory.bytes_read, 3072);
    }

    #[test]
    fn overlay_extension_record_is_used_by_inventory_continuation_resolution() {
        let bytes = continued_stream_image(2, (0, 1));
        let extension_offset = 4 * 4096 + 1024;
        let mut replacement = bytes[extension_offset..extension_offset + 512].to_vec();
        replacement[16..18].copy_from_slice(&3_u16.to_le_bytes());
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();
        let plan = OverlayPlan::build(
            u64::try_from(bytes.len()).unwrap(),
            512,
            vec![OverlayWrite {
                offset: u64::try_from(extension_offset).unwrap(),
                bytes: replacement,
            }],
            OverlayLimits {
                max_writes: 1,
                max_replacement_bytes: 512,
                max_read_bytes: 4096,
            },
        )
        .unwrap();
        let reader = plan.reader(&image).unwrap();

        assert!(matches!(
            inventory_ntfs_with_reader(
                &reader,
                &boot(),
                &bootstrap(2048),
                NtfsInventoryLimits::default()
            ),
            Err(NtfsInventoryError::AttributeList(
                AttributeListError::RecordSequenceMismatch {
                    record_number: 1,
                    expected: 2,
                    found: 3
                }
            ))
        ));
    }

    #[test]
    fn physical_census_includes_metadata_and_omits_sparse_runs() {
        let mut index = nonresident_attribute(
            9,
            0,
            1,
            0x8000,
            4096,
            8192,
            8192,
            4096,
            &[0x11, 1, 8, 0x01, 1, 0],
        );
        index[0..4].copy_from_slice(&INDEX_ALLOCATION.to_le_bytes());
        let parsed = parse_attribute(
            &index,
            attribute_limits(&boot(), NtfsInventoryLimits::default()),
        )
        .unwrap();
        let mut allocations = Vec::new();
        inventory_physical_allocations(
            5,
            &[parsed],
            &boot(),
            NtfsInventoryLimits::default(),
            &mut allocations,
        )
        .unwrap();
        assert_eq!(
            allocations,
            vec![NtfsPhysicalAllocation {
                record_number: 5,
                attribute_type: INDEX_ALLOCATION,
                attribute_id: 9,
                starting_vcn: 0,
                start_lcn: 8,
                cluster_count: 1,
            }]
        );
    }

    #[test]
    fn stale_or_wrong_base_attribute_list_references_are_fatal() {
        let stale = TempImage::create(&continued_stream_image(3, (0, 1)));
        let image = ImageFile::open(&stale.0).unwrap();
        assert!(matches!(
            inventory_ntfs(
                &image,
                &boot(),
                &bootstrap(2048),
                NtfsInventoryLimits::default()
            ),
            Err(NtfsInventoryError::AttributeList(
                AttributeListError::RecordSequenceMismatch { .. }
            ))
        ));

        let wrong_base = TempImage::create(&continued_stream_image(2, (7, 1)));
        let image = ImageFile::open(&wrong_base.0).unwrap();
        assert!(matches!(
            inventory_ntfs(
                &image,
                &boot(),
                &bootstrap(2048),
                NtfsInventoryLimits::default()
            ),
            Err(NtfsInventoryError::AttributeList(
                AttributeListError::ExtensionBaseMismatch { .. }
            ))
        ));
    }

    #[test]
    fn capped_attribute_list_is_explicitly_incomplete() {
        let temp = TempImage::create(&continued_stream_image(2, (0, 1)));
        let image = ImageFile::open(&temp.0).unwrap();
        let inventory = inventory_ntfs(
            &image,
            &boot(),
            &bootstrap(2048),
            NtfsInventoryLimits {
                max_records: 1,
                ..NtfsInventoryLimits::default()
            },
        )
        .unwrap();
        assert_eq!(inventory.objects.len(), 1);
        assert!(
            inventory
                .incomplete_reasons
                .contains(&NtfsInventoryIncompleteReason::AttributeListContinuationRequired)
        );
        assert!(
            inventory
                .incomplete_reasons
                .contains(&NtfsInventoryIncompleteReason::RecordLimit)
        );
    }

    #[test]
    fn sparse_stream_completeness_uses_logical_vcn_coverage() {
        let bytes = nonresident_attribute(
            7,
            0,
            1,
            0x8000,
            4096,
            8192,
            8192,
            4096,
            &[0x11, 1, 8, 0x01, 1, 0],
        );
        let attribute = parse_attribute(
            &bytes,
            attribute_limits(&boot(), NtfsInventoryLimits::default()),
        )
        .unwrap();
        let stream = inventory_data_stream(
            4,
            &[&attribute],
            &boot(),
            NtfsInventoryLimits::default(),
            None,
            &mut 0,
        )
        .unwrap();
        let NtfsStreamStorage::NonResident {
            mapping_complete,
            extents,
            ..
        } = stream.storage
        else {
            panic!("expected non-resident stream")
        };
        assert!(mapping_complete);
        assert_eq!(extents.len(), 2);
        assert_eq!(extents[1].placement, NtfsExtentPlacement::Sparse);
    }

    #[test]
    fn record_cap_never_silently_claims_completeness() {
        let mut bytes = vec![0_u8; 128 * 512];
        let offset = 4 * 4096;
        bytes[offset..offset + 1024].copy_from_slice(&empty_record(0, true));
        bytes[offset + 1024..offset + 2048].copy_from_slice(&empty_record(1, true));
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();
        let inventory = inventory_ntfs(
            &image,
            &boot(),
            &bootstrap(2048),
            NtfsInventoryLimits {
                max_records: 1,
                ..NtfsInventoryLimits::default()
            },
        )
        .unwrap();
        assert_eq!(inventory.scanned_records, 1);
        assert_eq!(
            inventory.incomplete_reasons,
            vec![NtfsInventoryIncompleteReason::RecordLimit]
        );
    }
}
