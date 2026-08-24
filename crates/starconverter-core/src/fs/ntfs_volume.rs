//! Bounded discovery of NTFS `$Volume` metadata and the volume allocation bitmap.
//!
//! This layer consumes an already validated `$MFT` bootstrap and reads only regular image files.
//! Attribute-list continuations are not followed yet: their absence is represented as explicit
//! incomplete evidence rather than being mistaken for a complete allocation view.

use std::fmt;

use crate::fs::ntfs::NtfsBootSector;
use crate::fs::ntfs_attribute::{
    AttributeBody, AttributeLimits, NtfsAttributeError, parse_attribute_list,
};
use crate::fs::ntfs_bitmap::{NtfsBitmapError, TailEvidence, parse_bitmap};
use crate::fs::ntfs_discovery::{MftBootstrap, NtfsDiscoveryError, read_mft_record};
use crate::fs::ntfs_record::NtfsFileRecord;
use crate::fs::ntfs_runlist::{
    ExtentLocation, MappingPairsError, MappingPairsLimits, NtfsRunlist, parse_mapping_pairs,
};
use crate::image::{ImageError, ImageFile};

const ATTRIBUTE_LIST_TYPE: u32 = 0x20;
const VOLUME_INFORMATION_TYPE: u32 = 0x70;
const DATA_TYPE: u32 = 0x80;
const BITMAP_TYPE: u32 = 0xb0;
const VOLUME_INFORMATION_LENGTH: usize = 12;
const MFT_RECORD_NUMBER: u64 = 0;
const VOLUME_RECORD_NUMBER: u64 = 3;
const BITMAP_RECORD_NUMBER: u64 = 6;
const KNOWN_VOLUME_FLAGS: u16 = 0xc03f;

/// Caller-controlled resource bounds for `$Volume` and `$Bitmap` discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtfsVolumeLimits {
    /// Maximum aggregate bytes read from the image, including all three `FILE` records.
    pub max_bytes: u64,
    /// Maximum logical size of the `$Bitmap` stream.
    pub max_bitmap_bytes: usize,
    /// Maximum number of mapping pairs accepted from the first `$Bitmap` extent.
    pub max_runs: usize,
    /// Maximum individual attribute size accepted in either system record.
    pub max_attribute_bytes: usize,
    /// Maximum attributes collected from either system record.
    pub max_attributes: usize,
    /// Maximum UTF-16 code units copied for one attribute name.
    pub max_name_code_units: usize,
}

impl Default for NtfsVolumeLimits {
    fn default() -> Self {
        Self {
            max_bytes: 64 * 1024 * 1024,
            max_bitmap_bytes: 32 * 1024 * 1024,
            max_runs: 65_536,
            max_attribute_bytes: 16 * 1024 * 1024,
            max_attributes: 256,
            max_name_code_units: 255,
        }
    }
}

/// Decoded `$VOLUME_INFORMATION` flags. Unknown bits are retained losslessly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct NtfsVolumeFlags {
    pub raw: u16,
    pub dirty: bool,
    pub resize_log_file: bool,
    pub upgrade_on_mount: bool,
    pub mounted_on_nt4: bool,
    pub delete_usn_underway: bool,
    pub repair_object_ids: bool,
    pub chkdsk_underway: bool,
    pub modified_by_chkdsk: bool,
    pub unknown_bits: u16,
}

impl NtfsVolumeFlags {
    const fn from_raw(raw: u16) -> Self {
        Self {
            raw,
            dirty: raw & 0x0001 != 0,
            resize_log_file: raw & 0x0002 != 0,
            upgrade_on_mount: raw & 0x0004 != 0,
            mounted_on_nt4: raw & 0x0008 != 0,
            delete_usn_underway: raw & 0x0010 != 0,
            repair_object_ids: raw & 0x0020 != 0,
            chkdsk_underway: raw & 0x4000 != 0,
            modified_by_chkdsk: raw & 0x8000 != 0,
            unknown_bits: raw & !KNOWN_VOLUME_FLAGS,
        }
    }
}

/// Complete resident `$VOLUME_INFORMATION` evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtfsVolumeInformation {
    pub major_version: u8,
    pub minor_version: u8,
    pub flags: NtfsVolumeFlags,
}

/// Why metadata cannot yet be claimed complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtfsMetadataIncompleteReason {
    AttributeListContinuationRequired,
    BitmapMappingContinuationRequired,
    BitmapContainsUninitializedBytes,
    MftBitmapAttributeListContinuationRequired,
    MftBitmapMappingContinuationRequired,
    MftBitmapContainsUninitializedBytes,
}

/// `$Volume` evidence, preserving an unresolved attribute-list dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtfsVolumeEvidence {
    Complete(NtfsVolumeInformation),
    Incomplete {
        reason: NtfsMetadataIncompleteReason,
    },
}

/// Validated allocation counts derived from the canonical `$Bitmap` data stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsAllocationEvidence {
    pub bitmap_bytes: u64,
    pub allocated_clusters: u64,
    pub free_clusters: u64,
    pub allocated_bytes: u64,
    pub free_bytes: u64,
    pub tail: TailEvidence,
    /// Canonical validated bitmap bytes retained for independent ownership reconciliation.
    pub(crate) canonical_bitmap: Vec<u8>,
}

/// `$Bitmap` evidence, preserving unsupported continuation or initialization state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NtfsBitmapEvidence {
    Complete(NtfsAllocationEvidence),
    Incomplete {
        reason: NtfsMetadataIncompleteReason,
    },
}

/// Exact bytes from the unnamed `$MFT::$BITMAP` attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsMftBitmap {
    pub bitmap_bytes: u64,
    pub(crate) canonical_bitmap: Vec<u8>,
}

/// `$MFT::$BITMAP` evidence, preserving every condition that prevents an exact record census.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NtfsMftBitmapEvidence {
    Complete(NtfsMftBitmap),
    Incomplete {
        reason: NtfsMetadataIncompleteReason,
    },
}

/// Combined bounded evidence from NTFS records 0, 3, and 6.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsVolumeDiscovery {
    pub volume: NtfsVolumeEvidence,
    pub bitmap: NtfsBitmapEvidence,
    pub mft_bitmap: NtfsMftBitmapEvidence,
    pub bytes_read: u64,
}

/// Failure to safely interpret `$Volume` or `$Bitmap` evidence.
#[derive(Debug)]
pub enum NtfsVolumeError {
    InvalidLimit { field: &'static str },
    ByteLimitExceeded { requested_total: u64, maximum: u64 },
    GeometryOverflow { calculation: &'static str },
    Discovery(NtfsDiscoveryError),
    Image(ImageError),
    Attribute(NtfsAttributeError),
    MappingPairs(MappingPairsError),
    Bitmap(NtfsBitmapError),
    SystemRecordNotInUse { record_number: u64 },
    SystemRecordIsExtension { record_number: u64 },
    MissingVolumeInformation,
    DuplicateVolumeInformation,
    InvalidVolumeInformationLength { actual: usize },
    VolumeInformationReservedNotZero { value: u64 },
    InvalidVolumeInformationStorage,
    MissingBitmapData,
    DuplicateBitmapData,
    MissingMftBitmap,
    DuplicateMftBitmap,
    UnsupportedBitmapStorage { reason: &'static str },
    UnsupportedMftBitmapStorage { reason: &'static str },
    BitmapTooLarge { actual: u64, maximum: usize },
    MftBitmapTooLarge { actual: u64, maximum: usize },
}

impl fmt::Display for NtfsVolumeError {
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit { field } => {
                write!(formatter, "NTFS volume limit {field} must be non-zero")
            }
            Self::ByteLimitExceeded {
                requested_total,
                maximum,
            } => write!(
                formatter,
                "NTFS volume discovery would read {requested_total} bytes, exceeding caller cap {maximum}"
            ),
            Self::GeometryOverflow { calculation } => write!(
                formatter,
                "NTFS volume discovery overflow while calculating {calculation}"
            ),
            Self::Discovery(error) => {
                write!(formatter, "could not read NTFS system record: {error}")
            }
            Self::Image(error) => write!(formatter, "could not read NTFS image: {error}"),
            Self::Attribute(error) => {
                write!(formatter, "invalid NTFS system-record attribute: {error}")
            }
            Self::MappingPairs(error) => {
                write!(formatter, "invalid NTFS bitmap mapping pairs: {error}")
            }
            Self::Bitmap(error) => write!(formatter, "invalid NTFS volume bitmap: {error}"),
            Self::SystemRecordNotInUse { record_number } => write!(
                formatter,
                "NTFS system record {record_number} is not marked in use"
            ),
            Self::SystemRecordIsExtension { record_number } => write!(
                formatter,
                "NTFS system record {record_number} is an extension record"
            ),
            Self::MissingVolumeInformation => {
                formatter.write_str("$Volume has no $VOLUME_INFORMATION attribute")
            }
            Self::DuplicateVolumeInformation => {
                formatter.write_str("$Volume has duplicate $VOLUME_INFORMATION attributes")
            }
            Self::InvalidVolumeInformationLength { actual } => write!(
                formatter,
                "$VOLUME_INFORMATION is {actual} bytes; exactly {VOLUME_INFORMATION_LENGTH} are required"
            ),
            Self::VolumeInformationReservedNotZero { value } => write!(
                formatter,
                "$VOLUME_INFORMATION reserved field is nonzero: 0x{value:016x}"
            ),
            Self::InvalidVolumeInformationStorage => {
                formatter.write_str("$VOLUME_INFORMATION is not resident or is named")
            }
            Self::MissingBitmapData => {
                formatter.write_str("$Bitmap has no unnamed $DATA attribute")
            }
            Self::DuplicateBitmapData => {
                formatter.write_str("$Bitmap has duplicate unnamed first-extent $DATA attributes")
            }
            Self::MissingMftBitmap => formatter.write_str("$MFT has no unnamed $BITMAP attribute"),
            Self::DuplicateMftBitmap => {
                formatter.write_str("$MFT has duplicate unnamed first-extent $BITMAP attributes")
            }
            Self::UnsupportedBitmapStorage { reason } => {
                write!(formatter, "unsupported $Bitmap storage: {reason}")
            }
            Self::UnsupportedMftBitmapStorage { reason } => {
                write!(formatter, "unsupported $MFT::$BITMAP storage: {reason}")
            }
            Self::BitmapTooLarge { actual, maximum } => write!(
                formatter,
                "$Bitmap data is {actual} bytes, exceeding caller cap {maximum}"
            ),
            Self::MftBitmapTooLarge { actual, maximum } => write!(
                formatter,
                "$MFT::$BITMAP data is {actual} bytes, exceeding caller cap {maximum}"
            ),
        }
    }
}

impl std::error::Error for NtfsVolumeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Discovery(error) => Some(error),
            Self::Image(error) => Some(error),
            Self::Attribute(error) => Some(error),
            Self::MappingPairs(error) => Some(error),
            Self::Bitmap(error) => Some(error),
            _ => None,
        }
    }
}

impl From<NtfsDiscoveryError> for NtfsVolumeError {
    fn from(value: NtfsDiscoveryError) -> Self {
        Self::Discovery(value)
    }
}

impl From<ImageError> for NtfsVolumeError {
    fn from(value: ImageError) -> Self {
        Self::Image(value)
    }
}

impl From<NtfsAttributeError> for NtfsVolumeError {
    fn from(value: NtfsAttributeError) -> Self {
        Self::Attribute(value)
    }
}

impl From<MappingPairsError> for NtfsVolumeError {
    fn from(value: MappingPairsError) -> Self {
        Self::MappingPairs(value)
    }
}

impl From<NtfsBitmapError> for NtfsVolumeError {
    fn from(value: NtfsBitmapError) -> Self {
        Self::Bitmap(value)
    }
}

/// Reads and validates `$MFT::$BITMAP`, `$Volume`, and `$Bitmap` through an already bootstrapped
/// `$MFT` mapping.
///
/// # Errors
///
/// Returns [`NtfsVolumeError`] for malformed metadata, inconsistent storage or geometry, image
/// errors, arithmetic overflow, or a caller resource-limit violation.
pub fn discover_volume_and_bitmap(
    image: &ImageFile,
    boot: &NtfsBootSector,
    mft: &MftBootstrap,
    limits: NtfsVolumeLimits,
) -> Result<NtfsVolumeDiscovery, NtfsVolumeError> {
    validate_limits(limits)?;
    let records_bytes =
        boot.mft_record_size
            .bytes
            .checked_mul(3)
            .ok_or(NtfsVolumeError::GeometryOverflow {
                calculation: "system-record read size",
            })?;
    let mut budget = ReadBudget::new(limits.max_bytes);
    budget.charge(records_bytes)?;

    let mft_record = read_mft_record(
        image,
        boot,
        mft,
        MFT_RECORD_NUMBER,
        boot.mft_record_size.bytes,
    )?;
    validate_system_record(&mft_record, MFT_RECORD_NUMBER)?;
    let mft_attributes = attributes(&mft_record, boot, limits)?;
    let mft_bitmap =
        parse_mft_bitmap_evidence(image, boot, &mft_attributes.attributes, limits, &mut budget)?;

    let volume_record = read_mft_record(
        image,
        boot,
        mft,
        VOLUME_RECORD_NUMBER,
        boot.mft_record_size.bytes,
    )?;
    validate_system_record(&volume_record, VOLUME_RECORD_NUMBER)?;
    let volume_attributes = attributes(&volume_record, boot, limits)?;
    let volume = parse_volume_evidence(&volume_attributes.attributes)?;

    let bitmap_record = read_mft_record(
        image,
        boot,
        mft,
        BITMAP_RECORD_NUMBER,
        boot.mft_record_size.bytes,
    )?;
    validate_system_record(&bitmap_record, BITMAP_RECORD_NUMBER)?;
    let bitmap_attributes = attributes(&bitmap_record, boot, limits)?;
    let bitmap = parse_bitmap_evidence(
        image,
        boot,
        &bitmap_attributes.attributes,
        limits,
        &mut budget,
    )?;

    Ok(NtfsVolumeDiscovery {
        volume,
        bitmap,
        mft_bitmap,
        bytes_read: budget.used,
    })
}

fn validate_limits(limits: NtfsVolumeLimits) -> Result<(), NtfsVolumeError> {
    for (field, zero) in [
        ("max_bytes", limits.max_bytes == 0),
        ("max_bitmap_bytes", limits.max_bitmap_bytes == 0),
        ("max_runs", limits.max_runs == 0),
        ("max_attribute_bytes", limits.max_attribute_bytes == 0),
        ("max_attributes", limits.max_attributes == 0),
        ("max_name_code_units", limits.max_name_code_units == 0),
    ] {
        if zero {
            return Err(NtfsVolumeError::InvalidLimit { field });
        }
    }
    Ok(())
}

const fn validate_system_record(
    record: &NtfsFileRecord,
    number: u64,
) -> Result<(), NtfsVolumeError> {
    if !record.flags.is_in_use() {
        return Err(NtfsVolumeError::SystemRecordNotInUse {
            record_number: number,
        });
    }
    if record.base_record.is_some() {
        return Err(NtfsVolumeError::SystemRecordIsExtension {
            record_number: number,
        });
    }
    Ok(())
}

fn attributes<'a>(
    record: &'a NtfsFileRecord,
    boot: &NtfsBootSector,
    limits: NtfsVolumeLimits,
) -> Result<crate::fs::ntfs_attribute::NtfsAttributeList<'a>, NtfsVolumeError> {
    Ok(parse_attribute_list(
        record.repaired_bytes(),
        usize::from(record.attributes_offset),
        usize::try_from(record.bytes_in_use).map_err(|_| NtfsVolumeError::GeometryOverflow {
            calculation: "system-record bytes in use",
        })?,
        AttributeLimits {
            cluster_size_bytes: boot.cluster_size_bytes,
            max_attribute_bytes: limits.max_attribute_bytes,
            max_name_code_units: limits.max_name_code_units,
            max_attributes: limits.max_attributes,
        },
    )?)
}

fn parse_volume_evidence(
    attributes: &[crate::fs::ntfs_attribute::NtfsAttribute<'_>],
) -> Result<NtfsVolumeEvidence, NtfsVolumeError> {
    let has_attribute_list = attributes
        .iter()
        .any(|attribute| attribute.attribute_type == ATTRIBUTE_LIST_TYPE);
    let mut found = None;
    for attribute in attributes {
        if attribute.attribute_type != VOLUME_INFORMATION_TYPE {
            continue;
        }
        if found.is_some() {
            return Err(NtfsVolumeError::DuplicateVolumeInformation);
        }
        if attribute.name.is_some() {
            return Err(NtfsVolumeError::InvalidVolumeInformationStorage);
        }
        let AttributeBody::Resident(resident) = &attribute.body else {
            return Err(NtfsVolumeError::InvalidVolumeInformationStorage);
        };
        if resident.value.len() != VOLUME_INFORMATION_LENGTH {
            return Err(NtfsVolumeError::InvalidVolumeInformationLength {
                actual: resident.value.len(),
            });
        }
        let reserved = u64::from_le_bytes([
            resident.value[0],
            resident.value[1],
            resident.value[2],
            resident.value[3],
            resident.value[4],
            resident.value[5],
            resident.value[6],
            resident.value[7],
        ]);
        if reserved != 0 {
            return Err(NtfsVolumeError::VolumeInformationReservedNotZero { value: reserved });
        }
        let raw_flags = u16::from_le_bytes([resident.value[10], resident.value[11]]);
        found = Some(NtfsVolumeInformation {
            major_version: resident.value[8],
            minor_version: resident.value[9],
            flags: NtfsVolumeFlags::from_raw(raw_flags),
        });
    }
    match found {
        Some(info) => Ok(NtfsVolumeEvidence::Complete(info)),
        None if has_attribute_list => Ok(NtfsVolumeEvidence::Incomplete {
            reason: NtfsMetadataIncompleteReason::AttributeListContinuationRequired,
        }),
        None => Err(NtfsVolumeError::MissingVolumeInformation),
    }
}

fn parse_mft_bitmap_evidence(
    image: &ImageFile,
    boot: &NtfsBootSector,
    attributes: &[crate::fs::ntfs_attribute::NtfsAttribute<'_>],
    limits: NtfsVolumeLimits,
    budget: &mut ReadBudget,
) -> Result<NtfsMftBitmapEvidence, NtfsVolumeError> {
    let has_attribute_list = attributes
        .iter()
        .any(|attribute| attribute.attribute_type == ATTRIBUTE_LIST_TYPE);
    let mut selected = None;
    let mut has_continuation = false;
    for attribute in attributes {
        if attribute.attribute_type != BITMAP_TYPE || attribute.name.is_some() {
            continue;
        }
        let is_first_extent = match &attribute.body {
            AttributeBody::Resident(_) => true,
            AttributeBody::NonResident(bitmap) => bitmap.lowest_vcn == 0,
        };
        if !is_first_extent {
            has_continuation = true;
            continue;
        }
        if selected.is_some() {
            return Err(NtfsVolumeError::DuplicateMftBitmap);
        }
        selected = Some(attribute);
    }
    if has_attribute_list {
        return Ok(NtfsMftBitmapEvidence::Incomplete {
            reason: NtfsMetadataIncompleteReason::MftBitmapAttributeListContinuationRequired,
        });
    }
    if has_continuation {
        return Ok(NtfsMftBitmapEvidence::Incomplete {
            reason: NtfsMetadataIncompleteReason::MftBitmapMappingContinuationRequired,
        });
    }
    let Some(attribute) = selected else {
        return Err(NtfsVolumeError::MissingMftBitmap);
    };

    let bytes = match &attribute.body {
        AttributeBody::Resident(resident) => {
            ensure_mft_bitmap_len(resident.value.len() as u64, limits.max_bitmap_bytes)?;
            resident.value.to_vec()
        }
        AttributeBody::NonResident(bitmap) => {
            if attribute.flags.is_compressed()
                || attribute.flags.encrypted
                || attribute.flags.sparse
            {
                return Err(NtfsVolumeError::UnsupportedMftBitmapStorage {
                    reason: "attribute is compressed, encrypted, or sparse",
                });
            }
            let sizes = bitmap
                .sizes
                .ok_or(NtfsVolumeError::UnsupportedMftBitmapStorage {
                    reason: "first extent has no authoritative size fields",
                })?;
            ensure_mft_bitmap_len(sizes.data, limits.max_bitmap_bytes)?;
            if sizes.initialized < sizes.data {
                return Ok(NtfsMftBitmapEvidence::Incomplete {
                    reason: NtfsMetadataIncompleteReason::MftBitmapContainsUninitializedBytes,
                });
            }
            let runlist = parse_mapping_pairs(
                bitmap.mapping_pairs,
                MappingPairsLimits {
                    starting_vcn: bitmap.lowest_vcn,
                    expected_next_vcn: Some(bitmap.expected_next_vcn),
                    volume_cluster_count: boot.cluster_count,
                    max_runs: limits.max_runs,
                    max_decoded_clusters: boot.cluster_count,
                },
            )?;
            if runlist.sparse_clusters != 0 {
                return Err(NtfsVolumeError::UnsupportedMftBitmapStorage {
                    reason: "runlist contains sparse clusters",
                });
            }
            let mapped_bytes = runlist
                .next_vcn
                .checked_mul(boot.cluster_size_bytes)
                .ok_or(NtfsVolumeError::GeometryOverflow {
                    calculation: "$MFT::$BITMAP mapped byte length",
                })?;
            if mapped_bytes > sizes.allocated {
                return Err(NtfsVolumeError::UnsupportedMftBitmapStorage {
                    reason: "runlist maps more bytes than the allocation size",
                });
            }
            if mapped_bytes < sizes.allocated {
                return Ok(NtfsMftBitmapEvidence::Incomplete {
                    reason: NtfsMetadataIncompleteReason::MftBitmapMappingContinuationRequired,
                });
            }
            budget.charge(sizes.data)?;
            read_mft_bitmap_stream(image, boot, &runlist, sizes.data)?
        }
    };
    Ok(NtfsMftBitmapEvidence::Complete(NtfsMftBitmap {
        bitmap_bytes: bytes.len() as u64,
        canonical_bitmap: bytes,
    }))
}

fn ensure_mft_bitmap_len(actual: u64, maximum: usize) -> Result<(), NtfsVolumeError> {
    let maximum_u64 = u64::try_from(maximum).unwrap_or(u64::MAX);
    if actual > maximum_u64 {
        Err(NtfsVolumeError::MftBitmapTooLarge { actual, maximum })
    } else {
        Ok(())
    }
}

fn parse_bitmap_evidence(
    image: &ImageFile,
    boot: &NtfsBootSector,
    attributes: &[crate::fs::ntfs_attribute::NtfsAttribute<'_>],
    limits: NtfsVolumeLimits,
    budget: &mut ReadBudget,
) -> Result<NtfsBitmapEvidence, NtfsVolumeError> {
    let has_attribute_list = attributes
        .iter()
        .any(|attribute| attribute.attribute_type == ATTRIBUTE_LIST_TYPE);
    let mut selected = None;
    for attribute in attributes {
        if attribute.attribute_type != DATA_TYPE || attribute.name.is_some() {
            continue;
        }
        let is_first_extent = match &attribute.body {
            AttributeBody::Resident(_) => true,
            AttributeBody::NonResident(data) => data.lowest_vcn == 0,
        };
        if !is_first_extent {
            continue;
        }
        if selected.is_some() {
            return Err(NtfsVolumeError::DuplicateBitmapData);
        }
        selected = Some(attribute);
    }
    let Some(attribute) = selected else {
        return if has_attribute_list {
            Ok(NtfsBitmapEvidence::Incomplete {
                reason: NtfsMetadataIncompleteReason::AttributeListContinuationRequired,
            })
        } else {
            Err(NtfsVolumeError::MissingBitmapData)
        };
    };

    let bytes = match &attribute.body {
        AttributeBody::Resident(resident) => {
            ensure_bitmap_len(resident.value.len() as u64, limits.max_bitmap_bytes)?;
            resident.value.to_vec()
        }
        AttributeBody::NonResident(data) => {
            if attribute.flags.is_compressed()
                || attribute.flags.encrypted
                || attribute.flags.sparse
            {
                return Err(NtfsVolumeError::UnsupportedBitmapStorage {
                    reason: "unnamed $DATA is compressed, encrypted, or sparse",
                });
            }
            let sizes = data
                .sizes
                .ok_or(NtfsVolumeError::UnsupportedBitmapStorage {
                    reason: "first extent has no authoritative size fields",
                })?;
            ensure_bitmap_len(sizes.data, limits.max_bitmap_bytes)?;
            if sizes.initialized < sizes.data {
                return Ok(NtfsBitmapEvidence::Incomplete {
                    reason: NtfsMetadataIncompleteReason::BitmapContainsUninitializedBytes,
                });
            }
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
            if runlist.sparse_clusters != 0 {
                return Err(NtfsVolumeError::UnsupportedBitmapStorage {
                    reason: "runlist contains sparse clusters",
                });
            }
            let mapped_bytes = runlist
                .next_vcn
                .checked_mul(boot.cluster_size_bytes)
                .ok_or(NtfsVolumeError::GeometryOverflow {
                    calculation: "$Bitmap mapped byte length",
                })?;
            if mapped_bytes > sizes.allocated {
                return Err(NtfsVolumeError::UnsupportedBitmapStorage {
                    reason: "runlist maps more bytes than the allocation size",
                });
            }
            if mapped_bytes < sizes.allocated {
                return Ok(NtfsBitmapEvidence::Incomplete {
                    reason: NtfsMetadataIncompleteReason::BitmapMappingContinuationRequired,
                });
            }
            budget.charge(sizes.data)?;
            read_nonresident_stream(image, boot, &runlist, sizes.data)?
        }
    };
    allocation_evidence(boot, bytes).map(NtfsBitmapEvidence::Complete)
}

fn ensure_bitmap_len(actual: u64, maximum: usize) -> Result<(), NtfsVolumeError> {
    let maximum_u64 = u64::try_from(maximum).unwrap_or(u64::MAX);
    if actual > maximum_u64 {
        Err(NtfsVolumeError::BitmapTooLarge { actual, maximum })
    } else {
        Ok(())
    }
}

fn read_nonresident_stream(
    image: &ImageFile,
    boot: &NtfsBootSector,
    runlist: &NtfsRunlist,
    data_bytes: u64,
) -> Result<Vec<u8>, NtfsVolumeError> {
    let output_len = usize::try_from(data_bytes).map_err(|_| NtfsVolumeError::BitmapTooLarge {
        actual: data_bytes,
        maximum: usize::MAX,
    })?;
    let mut output = vec![0_u8; output_len];
    let mut copied = 0_u64;
    for extent in &runlist.extents {
        if copied == data_bytes {
            break;
        }
        let ExtentLocation::Physical { lcn } = extent.location else {
            return Err(NtfsVolumeError::UnsupportedBitmapStorage {
                reason: "runlist contains a sparse extent",
            });
        };
        let extent_bytes = extent.length.checked_mul(boot.cluster_size_bytes).ok_or(
            NtfsVolumeError::GeometryOverflow {
                calculation: "$Bitmap extent byte length",
            },
        )?;
        let count_u64 = extent_bytes.min(data_bytes - copied);
        let count = usize::try_from(count_u64).map_err(|_| NtfsVolumeError::BitmapTooLarge {
            actual: count_u64,
            maximum: usize::MAX,
        })?;
        let offset =
            lcn.checked_mul(boot.cluster_size_bytes)
                .ok_or(NtfsVolumeError::GeometryOverflow {
                    calculation: "$Bitmap extent image offset",
                })?;
        let output_offset =
            usize::try_from(copied).map_err(|_| NtfsVolumeError::BitmapTooLarge {
                actual: copied,
                maximum: usize::MAX,
            })?;
        read_chunked(image, offset, &mut output[output_offset..][..count])?;
        copied = copied
            .checked_add(count_u64)
            .ok_or(NtfsVolumeError::GeometryOverflow {
                calculation: "$Bitmap copied byte count",
            })?;
    }
    if copied != data_bytes {
        return Err(NtfsVolumeError::UnsupportedBitmapStorage {
            reason: "runlist does not cover the logical data size",
        });
    }
    Ok(output)
}

fn read_mft_bitmap_stream(
    image: &ImageFile,
    boot: &NtfsBootSector,
    runlist: &NtfsRunlist,
    data_bytes: u64,
) -> Result<Vec<u8>, NtfsVolumeError> {
    let output_len =
        usize::try_from(data_bytes).map_err(|_| NtfsVolumeError::MftBitmapTooLarge {
            actual: data_bytes,
            maximum: usize::MAX,
        })?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(output_len)
        .map_err(|_| NtfsVolumeError::MftBitmapTooLarge {
            actual: data_bytes,
            maximum: usize::MAX,
        })?;
    output.resize(output_len, 0);
    let mut copied = 0_u64;
    for extent in &runlist.extents {
        if copied == data_bytes {
            break;
        }
        let ExtentLocation::Physical { lcn } = extent.location else {
            return Err(NtfsVolumeError::UnsupportedMftBitmapStorage {
                reason: "runlist contains a sparse extent",
            });
        };
        let extent_bytes = extent.length.checked_mul(boot.cluster_size_bytes).ok_or(
            NtfsVolumeError::GeometryOverflow {
                calculation: "$MFT::$BITMAP extent byte length",
            },
        )?;
        let count_u64 = extent_bytes.min(data_bytes - copied);
        let count = usize::try_from(count_u64).map_err(|_| NtfsVolumeError::MftBitmapTooLarge {
            actual: count_u64,
            maximum: usize::MAX,
        })?;
        let offset =
            lcn.checked_mul(boot.cluster_size_bytes)
                .ok_or(NtfsVolumeError::GeometryOverflow {
                    calculation: "$MFT::$BITMAP extent image offset",
                })?;
        let output_offset =
            usize::try_from(copied).map_err(|_| NtfsVolumeError::MftBitmapTooLarge {
                actual: copied,
                maximum: usize::MAX,
            })?;
        read_chunked(image, offset, &mut output[output_offset..][..count])?;
        copied = copied
            .checked_add(count_u64)
            .ok_or(NtfsVolumeError::GeometryOverflow {
                calculation: "$MFT::$BITMAP copied byte count",
            })?;
    }
    if copied != data_bytes {
        return Err(NtfsVolumeError::UnsupportedMftBitmapStorage {
            reason: "runlist does not cover the logical data size",
        });
    }
    Ok(output)
}

fn read_chunked(
    image: &ImageFile,
    mut offset: u64,
    mut destination: &mut [u8],
) -> Result<(), NtfsVolumeError> {
    while !destination.is_empty() {
        let count = destination.len().min(image.max_read_bytes());
        let chunk = image.read_exact_at(offset, count)?;
        destination[..count].copy_from_slice(&chunk);
        destination = &mut destination[count..];
        offset = offset
            .checked_add(
                u64::try_from(count).map_err(|_| NtfsVolumeError::GeometryOverflow {
                    calculation: "$Bitmap chunk offset",
                })?,
            )
            .ok_or(NtfsVolumeError::GeometryOverflow {
                calculation: "$Bitmap chunk offset",
            })?;
    }
    Ok(())
}

fn allocation_evidence(
    boot: &NtfsBootSector,
    bytes: Vec<u8>,
) -> Result<NtfsAllocationEvidence, NtfsVolumeError> {
    let bitmap = parse_bitmap(boot.cluster_count, &bytes)?;
    let allocated_bytes = bitmap
        .allocated_clusters()
        .checked_mul(boot.cluster_size_bytes)
        .ok_or(NtfsVolumeError::GeometryOverflow {
            calculation: "allocated byte count",
        })?;
    let free_bytes = bitmap
        .free_clusters()
        .checked_mul(boot.cluster_size_bytes)
        .ok_or(NtfsVolumeError::GeometryOverflow {
            calculation: "free byte count",
        })?;
    Ok(NtfsAllocationEvidence {
        bitmap_bytes: bytes.len() as u64,
        allocated_clusters: bitmap.allocated_clusters(),
        free_clusters: bitmap.free_clusters(),
        allocated_bytes,
        free_bytes,
        tail: bitmap.tail_evidence(),
        canonical_bitmap: bytes,
    })
}

struct ReadBudget {
    used: u64,
    maximum: u64,
}

impl ReadBudget {
    const fn new(maximum: u64) -> Self {
        Self { used: 0, maximum }
    }

    fn charge(&mut self, bytes: u64) -> Result<(), NtfsVolumeError> {
        let requested_total =
            self.used
                .checked_add(bytes)
                .ok_or(NtfsVolumeError::GeometryOverflow {
                    calculation: "aggregate read byte count",
                })?;
        if requested_total > self.maximum {
            return Err(NtfsVolumeError::ByteLimitExceeded {
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
    use crate::fs::ntfs::RecordSize;
    use crate::fs::ntfs_record::parse_file_record;
    use crate::fs::ntfs_runlist::NtfsExtent;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    const CLUSTER_SIZE: usize = 4096;
    const RECORD_SIZE: usize = 1024;
    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TempImage(PathBuf);

    impl TempImage {
        fn create(bytes: &[u8]) -> Self {
            let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "starconverter-ntfs-volume-{}-{sequence}.img",
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

    const fn boot() -> NtfsBootSector {
        NtfsBootSector {
            bytes_per_sector: 512,
            sectors_per_cluster: 8,
            cluster_size_bytes: CLUSTER_SIZE as u64,
            declared_sectors: 512,
            cluster_count: 64,
            filesystem_bytes: 512 * 512,
            minimum_image_bytes: 513 * 512,
            mft_lcn: 4,
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

    fn mft() -> MftBootstrap {
        MftBootstrap {
            runlist: NtfsRunlist {
                extents: vec![NtfsExtent {
                    vcn: 0,
                    length: 2,
                    location: ExtentLocation::Physical { lcn: 4 },
                }],
                next_vcn: 2,
                encoded_runs: 1,
                bytes_consumed: 4,
                decoded_clusters: 2,
                physical_clusters: 2,
                sparse_clusters: 0,
            },
            allocated_bytes: 2 * CLUSTER_SIZE as u64,
            data_bytes: 2 * CLUSTER_SIZE as u64,
            initialized_bytes: 2 * CLUSTER_SIZE as u64,
            mapping_complete: true,
            record_zero_sequence_number: 1,
        }
    }

    fn image_with_records(volume: &[u8], bitmap: &[u8]) -> Vec<u8> {
        let mut image = vec![0_u8; 513 * 512];
        let mft_offset = 4 * CLUSTER_SIZE;
        image[mft_offset..mft_offset + RECORD_SIZE].copy_from_slice(&mft_record(&[0xff]));
        image[mft_offset + 3 * RECORD_SIZE..mft_offset + 4 * RECORD_SIZE].copy_from_slice(volume);
        image[mft_offset + 6 * RECORD_SIZE..mft_offset + 7 * RECORD_SIZE].copy_from_slice(bitmap);
        image
    }

    fn base_record(number: u32) -> Vec<u8> {
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
            u32::try_from(RECORD_SIZE).expect("fixture record size fits u32"),
        );
        set_u16(&mut record, 40, 1);
        set_u32(&mut record, 44, number);
        record
    }

    fn finish_record(mut record: Vec<u8>, end_marker: usize) -> Vec<u8> {
        set_u32(&mut record, end_marker, 0xffff_ffff);
        set_u32(
            &mut record,
            24,
            u32::try_from(end_marker + 8).expect("fixture used size fits u32"),
        );
        let usn = 0xa55a;
        set_u16(&mut record, 48, usn);
        set_u16(&mut record, 50, 0);
        set_u16(&mut record, 52, 0);
        set_u16(&mut record, 510, usn);
        set_u16(&mut record, 1022, usn);
        record
    }

    fn resident_attribute(
        record: &mut [u8],
        offset: usize,
        kind: u32,
        value: &[u8],
        id: u16,
    ) -> usize {
        let length = (24 + value.len() + 7) & !7;
        set_u32(record, offset, kind);
        set_u32(
            record,
            offset + 4,
            u32::try_from(length).expect("fixture attribute length fits u32"),
        );
        set_u16(record, offset + 14, id);
        set_u32(
            record,
            offset + 16,
            u32::try_from(value.len()).expect("fixture value length fits u32"),
        );
        set_u16(record, offset + 20, 24);
        record[offset + 24..offset + 24 + value.len()].copy_from_slice(value);
        offset + length
    }

    fn volume_record(flags: u16) -> Vec<u8> {
        let mut record = base_record(
            u32::try_from(VOLUME_RECORD_NUMBER).expect("fixture record number fits u32"),
        );
        let mut value = [0_u8; VOLUME_INFORMATION_LENGTH];
        value[8] = 3;
        value[9] = 1;
        set_u16(&mut value, 10, flags);
        let end = resident_attribute(&mut record, 56, VOLUME_INFORMATION_TYPE, &value, 0);
        finish_record(record, end)
    }

    fn mft_record(bytes: &[u8]) -> Vec<u8> {
        let mut record =
            base_record(u32::try_from(MFT_RECORD_NUMBER).expect("fixture record number fits u32"));
        let end = resident_attribute(&mut record, 56, BITMAP_TYPE, bytes, 0);
        finish_record(record, end)
    }

    fn mft_record_with_attributes(attributes: &[(u32, &[u8])]) -> Vec<u8> {
        let mut record =
            base_record(u32::try_from(MFT_RECORD_NUMBER).expect("fixture record number fits u32"));
        let mut end = 56;
        for (id, (kind, value)) in attributes.iter().enumerate() {
            end = resident_attribute(
                &mut record,
                end,
                *kind,
                value,
                u16::try_from(id).expect("fixture attribute id fits u16"),
            );
        }
        finish_record(record, end)
    }

    fn resident_bitmap_record(bytes: &[u8]) -> Vec<u8> {
        let mut record = base_record(
            u32::try_from(BITMAP_RECORD_NUMBER).expect("fixture record number fits u32"),
        );
        let end = resident_attribute(&mut record, 56, DATA_TYPE, bytes, 0);
        finish_record(record, end)
    }

    fn nonresident_bitmap_record(
        lcn: u8,
        allocated: u64,
        data: u64,
        initialized: u64,
        mapped_clusters: u8,
    ) -> Vec<u8> {
        let mut record = base_record(
            u32::try_from(BITMAP_RECORD_NUMBER).expect("fixture record number fits u32"),
        );
        let attr = 56;
        set_u32(&mut record, attr, DATA_TYPE);
        set_u32(&mut record, attr + 4, 72);
        record[attr + 8] = 1;
        set_i64(&mut record, attr + 16, 0);
        set_i64(&mut record, attr + 24, i64::from(mapped_clusters) - 1);
        set_u16(&mut record, attr + 32, 64);
        set_i64(
            &mut record,
            attr + 40,
            i64::try_from(allocated).expect("fixture allocation fits i64"),
        );
        set_i64(
            &mut record,
            attr + 48,
            i64::try_from(data).expect("fixture data size fits i64"),
        );
        set_i64(
            &mut record,
            attr + 56,
            i64::try_from(initialized).expect("fixture initialized size fits i64"),
        );
        record[attr + 64..attr + 68].copy_from_slice(&[0x11, mapped_clusters, lcn, 0]);
        finish_record(record, attr + 72)
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

    #[test]
    fn discovers_version_dirty_state_and_resident_allocation_counts() {
        let bitmap = [0xff, 0x03, 0, 0, 0, 0, 0, 0];
        let bytes = image_with_records(&volume_record(0xc001), &resident_bitmap_record(&bitmap));
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();
        let discovered =
            discover_volume_and_bitmap(&image, &boot(), &mft(), NtfsVolumeLimits::default())
                .unwrap();

        let NtfsVolumeEvidence::Complete(volume) = discovered.volume else {
            panic!("complete volume")
        };
        assert_eq!((volume.major_version, volume.minor_version), (3, 1));
        assert!(volume.flags.dirty);
        assert!(volume.flags.chkdsk_underway);
        assert!(volume.flags.modified_by_chkdsk);
        assert_eq!(volume.flags.unknown_bits, 0);
        let NtfsBitmapEvidence::Complete(allocation) = discovered.bitmap else {
            panic!("complete bitmap")
        };
        let NtfsMftBitmapEvidence::Complete(mft_bitmap) = discovered.mft_bitmap else {
            panic!("complete MFT bitmap")
        };
        assert_eq!(mft_bitmap.canonical_bitmap, vec![0xff]);
        assert_eq!(allocation.allocated_clusters, 10);
        assert_eq!(allocation.free_clusters, 54);
        assert_eq!(allocation.free_bytes, 54 * CLUSTER_SIZE as u64);
        assert_eq!(discovered.bytes_read, 3 * RECORD_SIZE as u64);
    }

    #[test]
    fn mft_attribute_list_prevents_overclaiming_bitmap_completeness() {
        let volume = volume_record(0);
        let bitmap = resident_bitmap_record(&[0xff; 8]);
        let mut bytes = image_with_records(&volume, &bitmap);
        let mft_offset = 4 * CLUSTER_SIZE;
        let mft_record =
            mft_record_with_attributes(&[(ATTRIBUTE_LIST_TYPE, &[]), (BITMAP_TYPE, &[0xff])]);
        bytes[mft_offset..mft_offset + RECORD_SIZE].copy_from_slice(&mft_record);
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open(&temp.0).expect("open synthetic image");

        let discovered =
            discover_volume_and_bitmap(&image, &boot(), &mft(), NtfsVolumeLimits::default())
                .expect("retain bounded incomplete evidence");

        assert_eq!(
            discovered.mft_bitmap,
            NtfsMftBitmapEvidence::Incomplete {
                reason: NtfsMetadataIncompleteReason::MftBitmapAttributeListContinuationRequired,
            }
        );
    }

    #[test]
    fn rejects_duplicate_mft_bitmap_attributes() {
        let volume = volume_record(0);
        let bitmap = resident_bitmap_record(&[0xff; 8]);
        let mut bytes = image_with_records(&volume, &bitmap);
        let mft_offset = 4 * CLUSTER_SIZE;
        let mft_record =
            mft_record_with_attributes(&[(BITMAP_TYPE, &[0xff]), (BITMAP_TYPE, &[0xff])]);
        bytes[mft_offset..mft_offset + RECORD_SIZE].copy_from_slice(&mft_record);
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open(&temp.0).expect("open synthetic image");

        assert!(matches!(
            discover_volume_and_bitmap(&image, &boot(), &mft(), NtfsVolumeLimits::default()),
            Err(NtfsVolumeError::DuplicateMftBitmap)
        ));
    }

    #[test]
    fn reads_nonresident_bitmap_in_small_chunks() {
        let volume = volume_record(0);
        let bitmap_record = nonresident_bitmap_record(10, CLUSTER_SIZE as u64, 8, 8, 1);
        let mut bytes = image_with_records(&volume, &bitmap_record);
        bytes[10 * CLUSTER_SIZE..10 * CLUSTER_SIZE + 8].copy_from_slice(&[0xff; 8]);
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open_with_limit(&temp.0, 3).unwrap();

        let discovered =
            discover_volume_and_bitmap(&image, &boot(), &mft(), NtfsVolumeLimits::default())
                .unwrap();
        let NtfsBitmapEvidence::Complete(allocation) = discovered.bitmap else {
            panic!("complete bitmap")
        };
        assert_eq!(allocation.allocated_clusters, 64);
        assert_eq!(discovered.bytes_read, 3 * RECORD_SIZE as u64 + 8);
    }

    #[test]
    fn reports_mapping_continuation_without_reading_stream() {
        let bitmap = nonresident_bitmap_record(10, 2 * CLUSTER_SIZE as u64, 8, 8, 1);
        let bytes = image_with_records(&volume_record(0), &bitmap);
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();

        let discovered =
            discover_volume_and_bitmap(&image, &boot(), &mft(), NtfsVolumeLimits::default())
                .unwrap();
        assert_eq!(
            discovered.bitmap,
            NtfsBitmapEvidence::Incomplete {
                reason: NtfsMetadataIncompleteReason::BitmapMappingContinuationRequired
            }
        );
        assert_eq!(discovered.bytes_read, 3 * RECORD_SIZE as u64);
    }

    #[test]
    fn reports_uninitialized_bitmap_without_reading_stream() {
        let bitmap = nonresident_bitmap_record(10, CLUSTER_SIZE as u64, 8, 7, 1);
        let bytes = image_with_records(&volume_record(0), &bitmap);
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();

        let discovered =
            discover_volume_and_bitmap(&image, &boot(), &mft(), NtfsVolumeLimits::default())
                .unwrap();
        assert!(matches!(
            discovered.bitmap,
            NtfsBitmapEvidence::Incomplete {
                reason: NtfsMetadataIncompleteReason::BitmapContainsUninitializedBytes
            }
        ));
    }

    #[test]
    fn enforces_aggregate_read_cap_before_io() {
        let bytes = image_with_records(&volume_record(0), &resident_bitmap_record(&[0xff; 8]));
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();
        let limits = NtfsVolumeLimits {
            max_bytes: 2 * RECORD_SIZE as u64 - 1,
            ..NtfsVolumeLimits::default()
        };
        assert!(matches!(
            discover_volume_and_bitmap(&image, &boot(), &mft(), limits),
            Err(NtfsVolumeError::ByteLimitExceeded { .. })
        ));
    }

    #[test]
    fn rejects_noncanonical_bitmap_tail_bits() {
        let bytes = image_with_records(&volume_record(0), &resident_bitmap_record(&[0; 8]));
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();
        let mut geometry = boot();
        geometry.cluster_count = 63;

        assert!(matches!(
            discover_volume_and_bitmap(&image, &geometry, &mft(), NtfsVolumeLimits::default()),
            Err(NtfsVolumeError::Bitmap(
                NtfsBitmapError::UnallocatedTailBit { bit_index: 63 }
            ))
        ));
    }

    #[test]
    fn preserves_unknown_volume_flag_bits() {
        let record = parse_file_record(&volume_record(0x0040)).unwrap();
        let parsed = attributes(&record, &boot(), NtfsVolumeLimits::default()).unwrap();
        let NtfsVolumeEvidence::Complete(volume) =
            parse_volume_evidence(&parsed.attributes).unwrap()
        else {
            panic!("complete")
        };
        assert_eq!(volume.flags.unknown_bits, 0x0040);
        assert!(!volume.flags.dirty);
    }

    #[test]
    fn rejects_nonzero_volume_information_reserved_field() {
        let mut record = volume_record(0);
        record[56 + 24] = 1;
        // Reapplying the same update-sequence marker keeps the synthetic record valid.
        let parsed = parse_file_record(&record).unwrap();
        let parsed = attributes(&parsed, &boot(), NtfsVolumeLimits::default()).unwrap();
        assert!(matches!(
            parse_volume_evidence(&parsed.attributes),
            Err(NtfsVolumeError::VolumeInformationReservedNotZero { value: 1 })
        ));
    }

    #[test]
    fn reports_attribute_list_dependency_when_metadata_is_not_in_base_record() {
        let mut record = base_record(
            u32::try_from(VOLUME_RECORD_NUMBER).expect("fixture record number fits u32"),
        );
        let end = resident_attribute(&mut record, 56, ATTRIBUTE_LIST_TYPE, &[], 0);
        let record = parse_file_record(&finish_record(record, end)).unwrap();
        let parsed = attributes(&record, &boot(), NtfsVolumeLimits::default()).unwrap();
        assert_eq!(
            parse_volume_evidence(&parsed.attributes).unwrap(),
            NtfsVolumeEvidence::Incomplete {
                reason: NtfsMetadataIncompleteReason::AttributeListContinuationRequired
            }
        );

        let temp = TempImage::create(&vec![0_u8; 513 * 512]);
        let image = ImageFile::open(&temp.0).unwrap();
        let mut budget = ReadBudget::new(1);
        assert_eq!(
            parse_bitmap_evidence(
                &image,
                &boot(),
                &parsed.attributes,
                NtfsVolumeLimits::default(),
                &mut budget,
            )
            .unwrap(),
            NtfsBitmapEvidence::Incomplete {
                reason: NtfsMetadataIncompleteReason::AttributeListContinuationRequired
            }
        );
        assert_eq!(budget.used, 0);
    }
}
