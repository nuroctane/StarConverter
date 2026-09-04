//! Bounded discovery of NTFS `$Volume` metadata and the volume allocation bitmap.
//!
//! This layer consumes an already validated `$MFT` bootstrap and reads only regular image files.
//! When a system record carries an `$ATTRIBUTE_LIST`, its attributes are resolved through the
//! list (resident or non-resident) and VCN-split `$MFT::$BITMAP` / `$Bitmap::$DATA` extents are
//! concatenated in order. The only remaining incomplete outcome is a continuation host that lies
//! outside the decoded `$MFT` mapping, which is reported as explicit incomplete evidence rather
//! than being mistaken for a complete allocation view.

use std::fmt;

use crate::fs::ntfs::NtfsBootSector;
use crate::fs::ntfs_attribute::{
    AttributeBody, AttributeLimits, NtfsAttribute, NtfsAttributeError, parse_attribute,
    parse_attribute_list,
};
use crate::fs::ntfs_attribute_list::{
    AttributeListError, AttributeListLimits, resolve_attribute_list_with_reader,
};
use crate::fs::ntfs_bitmap::{NtfsBitmapError, TailEvidence, parse_bitmap};
use crate::fs::ntfs_discovery::{MftBootstrap, NtfsDiscoveryError, read_mft_record_with_reader};
use crate::fs::ntfs_record::NtfsFileRecord;
use crate::fs::ntfs_runlist::{
    ExtentLocation, MappingPairsError, MappingPairsLimits, NtfsRunlist, parse_mapping_pairs,
};
use crate::image::{BoundedImageReader, ImageError, ImageFile};

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
    AttributeList(AttributeListError),
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
            Self::AttributeList(error) => write!(
                formatter,
                "could not resolve NTFS system-record $ATTRIBUTE_LIST: {error}"
            ),
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
            Self::AttributeList(error) => Some(error),
            Self::MappingPairs(error) => Some(error),
            Self::Bitmap(error) => Some(error),
            _ => None,
        }
    }
}

impl From<AttributeListError> for NtfsVolumeError {
    fn from(value: AttributeListError) -> Self {
        Self::AttributeList(value)
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
    discover_volume_and_bitmap_with_reader(image, boot, mft, limits)
}

pub(crate) fn discover_volume_and_bitmap_with_reader(
    image: &dyn BoundedImageReader,
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

    let mft_record = read_mft_record_with_reader(
        image,
        boot,
        mft,
        MFT_RECORD_NUMBER,
        boot.mft_record_size.bytes,
    )?;
    validate_system_record(&mft_record, MFT_RECORD_NUMBER)?;
    let mft_bitmap = match system_record_attribute_bytes(
        image,
        boot,
        mft,
        MFT_RECORD_NUMBER,
        &mft_record,
        limits,
        &mut budget,
    )? {
        SystemRecordAttributes::Resolved(raw) => {
            let parsed = parse_owned_attributes(&raw, boot, limits)?;
            parse_mft_bitmap_evidence(image, boot, &parsed, limits, &mut budget)?
        }
        SystemRecordAttributes::ContinuationHostUnmapped => NtfsMftBitmapEvidence::Incomplete {
            reason: NtfsMetadataIncompleteReason::MftBitmapAttributeListContinuationRequired,
        },
    };

    let volume_record = read_mft_record_with_reader(
        image,
        boot,
        mft,
        VOLUME_RECORD_NUMBER,
        boot.mft_record_size.bytes,
    )?;
    validate_system_record(&volume_record, VOLUME_RECORD_NUMBER)?;
    let volume = match system_record_attribute_bytes(
        image,
        boot,
        mft,
        VOLUME_RECORD_NUMBER,
        &volume_record,
        limits,
        &mut budget,
    )? {
        SystemRecordAttributes::Resolved(raw) => {
            let parsed = parse_owned_attributes(&raw, boot, limits)?;
            parse_volume_evidence(&parsed)?
        }
        SystemRecordAttributes::ContinuationHostUnmapped => NtfsVolumeEvidence::Incomplete {
            reason: NtfsMetadataIncompleteReason::AttributeListContinuationRequired,
        },
    };

    let bitmap_record = read_mft_record_with_reader(
        image,
        boot,
        mft,
        BITMAP_RECORD_NUMBER,
        boot.mft_record_size.bytes,
    )?;
    validate_system_record(&bitmap_record, BITMAP_RECORD_NUMBER)?;
    let bitmap = match system_record_attribute_bytes(
        image,
        boot,
        mft,
        BITMAP_RECORD_NUMBER,
        &bitmap_record,
        limits,
        &mut budget,
    )? {
        SystemRecordAttributes::Resolved(raw) => {
            let parsed = parse_owned_attributes(&raw, boot, limits)?;
            parse_bitmap_evidence(image, boot, &parsed, limits, &mut budget)?
        }
        SystemRecordAttributes::ContinuationHostUnmapped => NtfsBitmapEvidence::Incomplete {
            reason: NtfsMetadataIncompleteReason::AttributeListContinuationRequired,
        },
    };

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

const fn attribute_limits(boot: &NtfsBootSector, limits: NtfsVolumeLimits) -> AttributeLimits {
    AttributeLimits {
        cluster_size_bytes: boot.cluster_size_bytes,
        max_attribute_bytes: limits.max_attribute_bytes,
        max_name_code_units: limits.max_name_code_units,
        max_attributes: limits.max_attributes,
    }
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
        attribute_limits(boot, limits),
    )?)
}

/// The complete attribute set of a system record, or the reason it cannot be assembled yet.
enum SystemRecordAttributes {
    /// Raw attribute records in on-disk (`$ATTRIBUTE_LIST`) order.
    Resolved(Vec<Vec<u8>>),
    /// The record's `$ATTRIBUTE_LIST` names a continuation record outside the decoded `$MFT`
    /// mapping, so the attribute set is knowingly incomplete.
    ContinuationHostUnmapped,
}

/// Collects every attribute of a system record, following its `$ATTRIBUTE_LIST` when present.
///
/// Without an `$ATTRIBUTE_LIST` the record's own attributes are authoritative. With one, the list
/// is resolved (resident or non-resident) and every listed extent is gathered from its host
/// record, so VCN-split streams and attributes moved to extension records become visible.
fn system_record_attribute_bytes(
    image: &dyn BoundedImageReader,
    boot: &NtfsBootSector,
    mft: &MftBootstrap,
    record_number: u64,
    record: &NtfsFileRecord,
    limits: NtfsVolumeLimits,
    budget: &mut ReadBudget,
) -> Result<SystemRecordAttributes, NtfsVolumeError> {
    let own = attributes(record, boot, limits)?;
    let has_attribute_list = own
        .attributes
        .iter()
        .any(|attribute| attribute.attribute_type == ATTRIBUTE_LIST_TYPE);
    if !has_attribute_list {
        let mut raw = Vec::new();
        raw.try_reserve_exact(own.attributes.len()).map_err(|_| {
            NtfsVolumeError::GeometryOverflow {
                calculation: "system-record attribute allocation",
            }
        })?;
        raw.extend(
            own.attributes
                .iter()
                .map(|attribute| attribute.raw.to_vec()),
        );
        return Ok(SystemRecordAttributes::Resolved(raw));
    }

    let remaining = budget.remaining();
    if remaining == 0 {
        return Err(NtfsVolumeError::ByteLimitExceeded {
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
    match resolve_attribute_list_with_reader(image, boot, mft, record_number, record, list_limits) {
        Ok(resolved) => {
            budget.charge(resolved.bytes_read)?;
            Ok(SystemRecordAttributes::Resolved(
                resolved
                    .extents
                    .into_iter()
                    .map(|extent| extent.raw_attribute)
                    .collect(),
            ))
        }
        Err(AttributeListError::Discovery(NtfsDiscoveryError::MftRecordOutsideMapping {
            ..
        })) => Ok(SystemRecordAttributes::ContinuationHostUnmapped),
        Err(error) => Err(error.into()),
    }
}

fn parse_owned_attributes<'a>(
    raw: &'a [Vec<u8>],
    boot: &NtfsBootSector,
    limits: NtfsVolumeLimits,
) -> Result<Vec<NtfsAttribute<'a>>, NtfsVolumeError> {
    let attribute_limits = attribute_limits(boot, limits);
    raw.iter()
        .map(|bytes| parse_attribute(bytes, attribute_limits).map_err(NtfsVolumeError::from))
        .collect()
}

fn parse_volume_evidence(
    attributes: &[NtfsAttribute<'_>],
) -> Result<NtfsVolumeEvidence, NtfsVolumeError> {
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
    found
        .map(NtfsVolumeEvidence::Complete)
        .ok_or(NtfsVolumeError::MissingVolumeInformation)
}

/// Which unnamed bitmap-carrying stream is being assembled; selects error and reason vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BitmapStream {
    /// `$MFT::$BITMAP` (record 0, attribute type `0xb0`).
    MftBitmap,
    /// `$Bitmap::$DATA` (record 6, attribute type `0x80`).
    VolumeBitmap,
}

impl BitmapStream {
    const fn attribute_type(self) -> u32 {
        match self {
            Self::MftBitmap => BITMAP_TYPE,
            Self::VolumeBitmap => DATA_TYPE,
        }
    }

    const fn unsupported(self, reason: &'static str) -> NtfsVolumeError {
        match self {
            Self::MftBitmap => NtfsVolumeError::UnsupportedMftBitmapStorage { reason },
            Self::VolumeBitmap => NtfsVolumeError::UnsupportedBitmapStorage { reason },
        }
    }

    const fn missing(self) -> NtfsVolumeError {
        match self {
            Self::MftBitmap => NtfsVolumeError::MissingMftBitmap,
            Self::VolumeBitmap => NtfsVolumeError::MissingBitmapData,
        }
    }

    const fn duplicate(self) -> NtfsVolumeError {
        match self {
            Self::MftBitmap => NtfsVolumeError::DuplicateMftBitmap,
            Self::VolumeBitmap => NtfsVolumeError::DuplicateBitmapData,
        }
    }

    const fn too_large(self, actual: u64, maximum: usize) -> NtfsVolumeError {
        match self {
            Self::MftBitmap => NtfsVolumeError::MftBitmapTooLarge { actual, maximum },
            Self::VolumeBitmap => NtfsVolumeError::BitmapTooLarge { actual, maximum },
        }
    }

    const fn uninitialized(self) -> NtfsMetadataIncompleteReason {
        match self {
            Self::MftBitmap => NtfsMetadataIncompleteReason::MftBitmapContainsUninitializedBytes,
            Self::VolumeBitmap => NtfsMetadataIncompleteReason::BitmapContainsUninitializedBytes,
        }
    }

    const fn mapping_continuation(self) -> NtfsMetadataIncompleteReason {
        match self {
            Self::MftBitmap => NtfsMetadataIncompleteReason::MftBitmapMappingContinuationRequired,
            Self::VolumeBitmap => NtfsMetadataIncompleteReason::BitmapMappingContinuationRequired,
        }
    }

    const fn overflow(self, what: StreamCalculation) -> NtfsVolumeError {
        let calculation = match (self, what) {
            (Self::MftBitmap, StreamCalculation::MappedBytes) => "$MFT::$BITMAP mapped byte length",
            (Self::MftBitmap, StreamCalculation::ExtentBytes) => "$MFT::$BITMAP extent byte length",
            (Self::MftBitmap, StreamCalculation::ExtentOffset) => {
                "$MFT::$BITMAP extent image offset"
            }
            (Self::MftBitmap, StreamCalculation::CopiedBytes) => "$MFT::$BITMAP copied byte count",
            (Self::MftBitmap, StreamCalculation::RunlistMerge) => "$MFT::$BITMAP runlist merge",
            (Self::VolumeBitmap, StreamCalculation::MappedBytes) => "$Bitmap mapped byte length",
            (Self::VolumeBitmap, StreamCalculation::ExtentBytes) => "$Bitmap extent byte length",
            (Self::VolumeBitmap, StreamCalculation::ExtentOffset) => "$Bitmap extent image offset",
            (Self::VolumeBitmap, StreamCalculation::CopiedBytes) => "$Bitmap copied byte count",
            (Self::VolumeBitmap, StreamCalculation::RunlistMerge) => "$Bitmap runlist merge",
        };
        NtfsVolumeError::GeometryOverflow { calculation }
    }

    fn ensure_len(self, actual: u64, maximum: usize) -> Result<(), NtfsVolumeError> {
        let maximum_u64 = u64::try_from(maximum).unwrap_or(u64::MAX);
        if actual > maximum_u64 {
            Err(self.too_large(actual, maximum))
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum StreamCalculation {
    MappedBytes,
    ExtentBytes,
    ExtentOffset,
    CopiedBytes,
    RunlistMerge,
}

/// Outcome of assembling one bitmap stream's bytes.
enum StreamBytes {
    Complete(Vec<u8>),
    Incomplete(NtfsMetadataIncompleteReason),
}

fn parse_mft_bitmap_evidence(
    image: &dyn BoundedImageReader,
    boot: &NtfsBootSector,
    attributes: &[NtfsAttribute<'_>],
    limits: NtfsVolumeLimits,
    budget: &mut ReadBudget,
) -> Result<NtfsMftBitmapEvidence, NtfsVolumeError> {
    match read_bitmap_stream(
        BitmapStream::MftBitmap,
        image,
        boot,
        attributes,
        limits,
        budget,
    )? {
        StreamBytes::Complete(bytes) => Ok(NtfsMftBitmapEvidence::Complete(NtfsMftBitmap {
            bitmap_bytes: bytes.len() as u64,
            canonical_bitmap: bytes,
        })),
        StreamBytes::Incomplete(reason) => Ok(NtfsMftBitmapEvidence::Incomplete { reason }),
    }
}

fn parse_bitmap_evidence(
    image: &dyn BoundedImageReader,
    boot: &NtfsBootSector,
    attributes: &[NtfsAttribute<'_>],
    limits: NtfsVolumeLimits,
    budget: &mut ReadBudget,
) -> Result<NtfsBitmapEvidence, NtfsVolumeError> {
    match read_bitmap_stream(
        BitmapStream::VolumeBitmap,
        image,
        boot,
        attributes,
        limits,
        budget,
    )? {
        StreamBytes::Complete(bytes) => {
            allocation_evidence(boot, bytes).map(NtfsBitmapEvidence::Complete)
        }
        StreamBytes::Incomplete(reason) => Ok(NtfsBitmapEvidence::Incomplete { reason }),
    }
}

/// Selects the unnamed first extent of `kind` and every VCN continuation extent of the same
/// stream. `attributes` must already be the record's complete (list-resolved) attribute set.
fn select_stream_extents<'a, 'b>(
    kind: BitmapStream,
    attributes: &'b [NtfsAttribute<'a>],
) -> Result<(&'b NtfsAttribute<'a>, Vec<&'b NtfsAttribute<'a>>), NtfsVolumeError> {
    let mut first = None;
    let mut continuations = Vec::new();
    for attribute in attributes {
        if attribute.attribute_type != kind.attribute_type() || attribute.name.is_some() {
            continue;
        }
        let is_first_extent = match &attribute.body {
            AttributeBody::Resident(_) => true,
            AttributeBody::NonResident(body) => body.lowest_vcn == 0,
        };
        if !is_first_extent {
            continuations.push(attribute);
            continue;
        }
        if first.is_some() {
            return Err(kind.duplicate());
        }
        first = Some(attribute);
    }
    let first = first.ok_or_else(|| kind.missing())?;
    continuations.sort_by_key(|attribute| match &attribute.body {
        AttributeBody::NonResident(body) => body.lowest_vcn,
        AttributeBody::Resident(_) => 0,
    });
    Ok((first, continuations))
}

/// Reads the complete unnamed bitmap stream of `kind`, concatenating VCN-split extents.
fn read_bitmap_stream(
    kind: BitmapStream,
    image: &dyn BoundedImageReader,
    boot: &NtfsBootSector,
    attributes: &[NtfsAttribute<'_>],
    limits: NtfsVolumeLimits,
    budget: &mut ReadBudget,
) -> Result<StreamBytes, NtfsVolumeError> {
    let (first, continuations) = select_stream_extents(kind, attributes)?;
    let body = match &first.body {
        AttributeBody::Resident(resident) => {
            if !continuations.is_empty() {
                return Err(kind.unsupported(
                    "resident first extent is followed by non-resident continuation extents",
                ));
            }
            kind.ensure_len(resident.value.len() as u64, limits.max_bitmap_bytes)?;
            return Ok(StreamBytes::Complete(resident.value.to_vec()));
        }
        AttributeBody::NonResident(body) => body,
    };
    if first.flags.is_compressed() || first.flags.encrypted || first.flags.sparse {
        return Err(kind.unsupported("attribute is compressed, encrypted, or sparse"));
    }
    let sizes = body
        .sizes
        .ok_or_else(|| kind.unsupported("first extent has no authoritative size fields"))?;
    kind.ensure_len(sizes.data, limits.max_bitmap_bytes)?;
    if sizes.initialized < sizes.data {
        return Ok(StreamBytes::Incomplete(kind.uninitialized()));
    }

    let mut runlist = parse_stream_extent_runlist(kind, boot, first, 0, limits.max_runs)?;
    for continuation in continuations {
        if continuation.flags != first.flags {
            return Err(kind.unsupported("continuation extent changes the attribute flags"));
        }
        let AttributeBody::NonResident(continuation_body) = &continuation.body else {
            return Err(kind.unsupported("continuation extent is resident"));
        };
        if continuation_body.lowest_vcn != runlist.next_vcn {
            return Err(kind.unsupported("continuation extent is not VCN-contiguous"));
        }
        let remaining_runs = limits
            .max_runs
            .checked_sub(runlist.encoded_runs)
            .filter(|remaining| *remaining > 0)
            .ok_or(NtfsVolumeError::MappingPairs(
                MappingPairsError::RunLimitExceeded {
                    maximum: limits.max_runs,
                },
            ))?;
        let extra = parse_stream_extent_runlist(
            kind,
            boot,
            continuation,
            runlist.next_vcn,
            remaining_runs,
        )?;
        append_runlist(kind, &mut runlist, extra)?;
    }

    let mapped_bytes = runlist
        .next_vcn
        .checked_mul(boot.cluster_size_bytes)
        .ok_or_else(|| kind.overflow(StreamCalculation::MappedBytes))?;
    if mapped_bytes > sizes.allocated {
        return Err(kind.unsupported("runlist maps more bytes than the allocation size"));
    }
    if mapped_bytes < sizes.allocated {
        return Ok(StreamBytes::Incomplete(kind.mapping_continuation()));
    }
    budget.charge(sizes.data)?;
    read_stream(kind, image, boot, &runlist, sizes.data).map(StreamBytes::Complete)
}

fn parse_stream_extent_runlist(
    kind: BitmapStream,
    boot: &NtfsBootSector,
    attribute: &NtfsAttribute<'_>,
    starting_vcn: u64,
    max_runs: usize,
) -> Result<NtfsRunlist, NtfsVolumeError> {
    let AttributeBody::NonResident(body) = &attribute.body else {
        return Err(kind.unsupported("extent is resident"));
    };
    let runlist = parse_mapping_pairs(
        body.mapping_pairs,
        MappingPairsLimits {
            starting_vcn,
            expected_next_vcn: Some(body.expected_next_vcn),
            volume_cluster_count: boot.cluster_count,
            max_runs,
            max_decoded_clusters: boot.cluster_count,
        },
    )?;
    if runlist.sparse_clusters != 0 {
        return Err(kind.unsupported("runlist contains sparse clusters"));
    }
    Ok(runlist)
}

fn append_runlist(
    kind: BitmapStream,
    into: &mut NtfsRunlist,
    extra: NtfsRunlist,
) -> Result<(), NtfsVolumeError> {
    let overflow = || kind.overflow(StreamCalculation::RunlistMerge);
    into.extents
        .try_reserve(extra.extents.len())
        .map_err(|_| overflow())?;
    into.extents.extend(extra.extents);
    into.next_vcn = extra.next_vcn;
    into.encoded_runs = into
        .encoded_runs
        .checked_add(extra.encoded_runs)
        .ok_or_else(overflow)?;
    into.bytes_consumed = into
        .bytes_consumed
        .checked_add(extra.bytes_consumed)
        .ok_or_else(overflow)?;
    into.decoded_clusters = into
        .decoded_clusters
        .checked_add(extra.decoded_clusters)
        .ok_or_else(overflow)?;
    into.physical_clusters = into
        .physical_clusters
        .checked_add(extra.physical_clusters)
        .ok_or_else(overflow)?;
    into.sparse_clusters = into
        .sparse_clusters
        .checked_add(extra.sparse_clusters)
        .ok_or_else(overflow)?;
    Ok(())
}

fn read_stream(
    kind: BitmapStream,
    image: &dyn BoundedImageReader,
    boot: &NtfsBootSector,
    runlist: &NtfsRunlist,
    data_bytes: u64,
) -> Result<Vec<u8>, NtfsVolumeError> {
    let output_len =
        usize::try_from(data_bytes).map_err(|_| kind.too_large(data_bytes, usize::MAX))?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(output_len)
        .map_err(|_| kind.too_large(data_bytes, usize::MAX))?;
    output.resize(output_len, 0);
    let mut copied = 0_u64;
    for extent in &runlist.extents {
        if copied == data_bytes {
            break;
        }
        let ExtentLocation::Physical { lcn } = extent.location else {
            return Err(kind.unsupported("runlist contains a sparse extent"));
        };
        let extent_bytes = extent
            .length
            .checked_mul(boot.cluster_size_bytes)
            .ok_or_else(|| kind.overflow(StreamCalculation::ExtentBytes))?;
        let count_u64 = extent_bytes.min(data_bytes - copied);
        let count =
            usize::try_from(count_u64).map_err(|_| kind.too_large(count_u64, usize::MAX))?;
        let offset = lcn
            .checked_mul(boot.cluster_size_bytes)
            .ok_or_else(|| kind.overflow(StreamCalculation::ExtentOffset))?;
        let output_offset =
            usize::try_from(copied).map_err(|_| kind.too_large(copied, usize::MAX))?;
        read_chunked(image, offset, &mut output[output_offset..][..count])?;
        copied = copied
            .checked_add(count_u64)
            .ok_or_else(|| kind.overflow(StreamCalculation::CopiedBytes))?;
    }
    if copied != data_bytes {
        return Err(kind.unsupported("runlist does not cover the logical data size"));
    }
    Ok(output)
}

fn read_chunked(
    image: &dyn BoundedImageReader,
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

    const fn remaining(&self) -> u64 {
        self.maximum.saturating_sub(self.used)
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

    /// A `FILE` record whose base reference points at `base` with sequence 1.
    fn extension_record(number: u32, base: u64) -> Vec<u8> {
        let mut record = base_record(number);
        record[32..40].copy_from_slice(&(base | (1_u64 << 48)).to_le_bytes());
        record
    }

    /// One 32-byte unnamed `$ATTRIBUTE_LIST` entry naming `instance` in `record_number` (seq 1).
    fn attribute_list_entry(
        kind: u32,
        lowest_vcn: i64,
        record_number: u64,
        instance: u16,
    ) -> Vec<u8> {
        let mut bytes = vec![0_u8; 32];
        set_u32(&mut bytes, 0, kind);
        set_u16(&mut bytes, 4, 32);
        set_i64(&mut bytes, 8, lowest_vcn);
        bytes[16..24].copy_from_slice(&(record_number | (1_u64 << 48)).to_le_bytes());
        set_u16(&mut bytes, 24, instance);
        bytes
    }

    /// Writes a non-resident unnamed attribute extent mapping `run.1` clusters at LCN `run.0`.
    /// `sizes` is `(allocated, data, initialized)` and is only written on the first extent.
    fn nonresident_attribute(
        record: &mut [u8],
        offset: usize,
        kind: u32,
        lowest_vcn: i64,
        run: (u8, u8),
        sizes: Option<(u64, u64, u64)>,
        id: u16,
    ) -> usize {
        let (lcn, clusters) = run;
        set_u32(record, offset, kind);
        set_u32(record, offset + 4, 72);
        record[offset + 8] = 1;
        set_u16(record, offset + 14, id);
        set_i64(record, offset + 16, lowest_vcn);
        set_i64(record, offset + 24, lowest_vcn + i64::from(clusters) - 1);
        set_u16(record, offset + 32, 64);
        if let Some((allocated, data, initialized)) = sizes {
            set_i64(
                record,
                offset + 40,
                i64::try_from(allocated).expect("fixture allocation fits i64"),
            );
            set_i64(
                record,
                offset + 48,
                i64::try_from(data).expect("fixture data size fits i64"),
            );
            set_i64(
                record,
                offset + 56,
                i64::try_from(initialized).expect("fixture initialized size fits i64"),
            );
        }
        record[offset + 64..offset + 68].copy_from_slice(&[0x11, clusters, lcn, 0]);
        offset + 72
    }

    fn write_record(image: &mut [u8], record_number: usize, record: &[u8]) {
        let offset = 4 * CLUSTER_SIZE + record_number * RECORD_SIZE;
        image[offset..offset + RECORD_SIZE].copy_from_slice(record);
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
        // The `$MFT` bootstrap maps records 0..8; the list names record 9, which is unmapped.
        let volume = volume_record(0);
        let bitmap = resident_bitmap_record(&[0xff; 8]);
        let mut bytes = image_with_records(&volume, &bitmap);
        let list = attribute_list_entry(BITMAP_TYPE, 0, 9, 0);
        write_record(
            &mut bytes,
            0,
            &mft_record_with_attributes(&[(ATTRIBUTE_LIST_TYPE, &list)]),
        );
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
        assert!(matches!(discovered.volume, NtfsVolumeEvidence::Complete(_)));
        assert!(matches!(discovered.bitmap, NtfsBitmapEvidence::Complete(_)));
        assert_eq!(discovered.bytes_read, 3 * RECORD_SIZE as u64);
    }

    #[test]
    fn resolves_mft_bitmap_behind_attribute_list_in_mapped_extension_record() {
        let mut bytes = image_with_records(&volume_record(0), &resident_bitmap_record(&[0xff; 8]));
        let list = attribute_list_entry(BITMAP_TYPE, 0, 5, 0);
        write_record(
            &mut bytes,
            0,
            &mft_record_with_attributes(&[(ATTRIBUTE_LIST_TYPE, &list)]),
        );
        let mut extension = extension_record(5, MFT_RECORD_NUMBER);
        let end = resident_attribute(&mut extension, 56, BITMAP_TYPE, &[0xff, 0x03], 0);
        write_record(&mut bytes, 5, &finish_record(extension, end));
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open(&temp.0).expect("open synthetic image");

        let discovered =
            discover_volume_and_bitmap(&image, &boot(), &mft(), NtfsVolumeLimits::default())
                .expect("resolve list-hosted $MFT::$BITMAP");

        assert_eq!(
            discovered.mft_bitmap,
            NtfsMftBitmapEvidence::Complete(NtfsMftBitmap {
                bitmap_bytes: 2,
                canonical_bitmap: vec![0xff, 0x03],
            })
        );
        assert_eq!(discovered.bytes_read, 4 * RECORD_SIZE as u64);
    }

    #[test]
    fn concatenates_vcn_split_volume_bitmap_through_attribute_list() {
        let mut bytes = image_with_records(&volume_record(0), &resident_bitmap_record(&[0xff; 8]));
        // `$Bitmap` (record 6): list + first `$DATA` extent (VCN 0) hosted locally as id 1.
        let mut list = attribute_list_entry(DATA_TYPE, 0, BITMAP_RECORD_NUMBER, 1);
        list.extend(attribute_list_entry(DATA_TYPE, 1, 7, 0));
        let mut record = base_record(
            u32::try_from(BITMAP_RECORD_NUMBER).expect("fixture record number fits u32"),
        );
        let end = resident_attribute(&mut record, 56, ATTRIBUTE_LIST_TYPE, &list, 0);
        let end = nonresident_attribute(
            &mut record,
            end,
            DATA_TYPE,
            0,
            (10, 1),
            Some((2 * CLUSTER_SIZE as u64, 8, 8)),
            1,
        );
        write_record(&mut bytes, 6, &finish_record(record, end));
        // Extension record 7 hosts the VCN 1 continuation.
        let mut extension = extension_record(7, BITMAP_RECORD_NUMBER);
        let end = nonresident_attribute(&mut extension, 56, DATA_TYPE, 1, (12, 1), None, 0);
        write_record(&mut bytes, 7, &finish_record(extension, end));
        bytes[10 * CLUSTER_SIZE..10 * CLUSTER_SIZE + 8].copy_from_slice(&[0xff; 8]);
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open(&temp.0).expect("open synthetic image");

        let discovered =
            discover_volume_and_bitmap(&image, &boot(), &mft(), NtfsVolumeLimits::default())
                .expect("concatenate split $Bitmap extents");

        let NtfsBitmapEvidence::Complete(allocation) = discovered.bitmap else {
            panic!("complete bitmap, got {:?}", discovered.bitmap)
        };
        assert_eq!(allocation.allocated_clusters, 64);
        assert_eq!(discovered.bytes_read, 4 * RECORD_SIZE as u64 + 8);
    }

    #[test]
    fn rejects_non_contiguous_split_volume_bitmap_extents() {
        let mut bytes = image_with_records(&volume_record(0), &resident_bitmap_record(&[0xff; 8]));
        let mut list = attribute_list_entry(DATA_TYPE, 0, BITMAP_RECORD_NUMBER, 1);
        list.extend(attribute_list_entry(DATA_TYPE, 2, 7, 0));
        let mut record = base_record(
            u32::try_from(BITMAP_RECORD_NUMBER).expect("fixture record number fits u32"),
        );
        let end = resident_attribute(&mut record, 56, ATTRIBUTE_LIST_TYPE, &list, 0);
        let end = nonresident_attribute(
            &mut record,
            end,
            DATA_TYPE,
            0,
            (10, 1),
            Some((3 * CLUSTER_SIZE as u64, 8, 8)),
            1,
        );
        write_record(&mut bytes, 6, &finish_record(record, end));
        let mut extension = extension_record(7, BITMAP_RECORD_NUMBER);
        let end = nonresident_attribute(&mut extension, 56, DATA_TYPE, 2, (12, 1), None, 0);
        write_record(&mut bytes, 7, &finish_record(extension, end));
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open(&temp.0).expect("open synthetic image");

        assert!(matches!(
            discover_volume_and_bitmap(&image, &boot(), &mft(), NtfsVolumeLimits::default()),
            Err(NtfsVolumeError::UnsupportedBitmapStorage {
                reason: "continuation extent is not VCN-contiguous"
            })
        ));
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
    fn reports_attribute_list_dependency_when_metadata_host_is_unmapped() {
        // Both `$Volume` and `$Bitmap` move their payload to record 9, beyond the mapped `$MFT`.
        let mut volume = base_record(
            u32::try_from(VOLUME_RECORD_NUMBER).expect("fixture record number fits u32"),
        );
        let list = attribute_list_entry(VOLUME_INFORMATION_TYPE, 0, 9, 0);
        let end = resident_attribute(&mut volume, 56, ATTRIBUTE_LIST_TYPE, &list, 0);
        let volume = finish_record(volume, end);
        let mut bitmap = base_record(
            u32::try_from(BITMAP_RECORD_NUMBER).expect("fixture record number fits u32"),
        );
        let list = attribute_list_entry(DATA_TYPE, 0, 9, 0);
        let end = resident_attribute(&mut bitmap, 56, ATTRIBUTE_LIST_TYPE, &list, 0);
        let bitmap = finish_record(bitmap, end);
        let bytes = image_with_records(&volume, &bitmap);
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();

        let discovered =
            discover_volume_and_bitmap(&image, &boot(), &mft(), NtfsVolumeLimits::default())
                .expect("retain bounded incomplete evidence");

        assert_eq!(
            discovered.volume,
            NtfsVolumeEvidence::Incomplete {
                reason: NtfsMetadataIncompleteReason::AttributeListContinuationRequired
            }
        );
        assert_eq!(
            discovered.bitmap,
            NtfsBitmapEvidence::Incomplete {
                reason: NtfsMetadataIncompleteReason::AttributeListContinuationRequired
            }
        );
        assert!(matches!(
            discovered.mft_bitmap,
            NtfsMftBitmapEvidence::Complete(_)
        ));
        assert_eq!(discovered.bytes_read, 3 * RECORD_SIZE as u64);
    }

    #[test]
    fn resolves_volume_information_behind_attribute_list() {
        let mut volume = base_record(
            u32::try_from(VOLUME_RECORD_NUMBER).expect("fixture record number fits u32"),
        );
        let list = attribute_list_entry(VOLUME_INFORMATION_TYPE, 0, 4, 0);
        let end = resident_attribute(&mut volume, 56, ATTRIBUTE_LIST_TYPE, &list, 0);
        let volume = finish_record(volume, end);
        let mut bytes = image_with_records(&volume, &resident_bitmap_record(&[0xff; 8]));
        let mut extension = extension_record(4, VOLUME_RECORD_NUMBER);
        let mut value = [0_u8; VOLUME_INFORMATION_LENGTH];
        value[8] = 3;
        value[9] = 1;
        set_u16(&mut value, 10, 0x0001);
        let end = resident_attribute(&mut extension, 56, VOLUME_INFORMATION_TYPE, &value, 0);
        write_record(&mut bytes, 4, &finish_record(extension, end));
        let temp = TempImage::create(&bytes);
        let image = ImageFile::open(&temp.0).unwrap();

        let discovered =
            discover_volume_and_bitmap(&image, &boot(), &mft(), NtfsVolumeLimits::default())
                .expect("resolve list-hosted $VOLUME_INFORMATION");

        let NtfsVolumeEvidence::Complete(info) = discovered.volume else {
            panic!("complete volume, got {:?}", discovered.volume)
        };
        assert_eq!((info.major_version, info.minor_version), (3, 1));
        assert!(info.flags.dirty);
        assert_eq!(discovered.bytes_read, 4 * RECORD_SIZE as u64);
    }
}
