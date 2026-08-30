//! Read-only filesystem image discovery.
//!
//! Discovery validates boot redundancy, allocation metadata, filesystem metadata streams, and a
//! bounded recursive object inventory. A complete inventory is normalized into the shared object
//! graph; cap-limited or continuation-limited evidence stays explicitly incomplete. The module
//! never claims exclusive access and never writes the image.

use std::fmt;
use std::path::Path;

use crate::fs::exfat::{self, ExfatBootSector, ExfatBootSectorError};
use crate::fs::exfat_discovery::{
    ExfatDiscoveryError, ExfatDiscoveryLimits, ExfatRootDiscovery, discover_root_with_reader,
};
use crate::fs::exfat_image::StreamReadLimits;
use crate::fs::exfat_inventory::{
    ExfatInventory, ExfatInventoryError, ExfatInventoryLimits, inventory_image_with_reader,
};
use crate::fs::exfat_normalize::{
    ExfatNormalizeError, ExfatNormalizeLimits, NormalizedExfat, normalize_inventory,
};
use crate::fs::exfat_region::{
    self, ExfatBootRegionComparison, ExfatBootRegionError, ExfatBootRegionsValidation,
};
use crate::fs::ntfs::{self, NtfsBootSector, NtfsBootSectorError};
use crate::fs::ntfs_bitmap::{
    NtfsAllocationClaim, NtfsAllocationReconciliation, NtfsAllocationReconciliationEvidence,
    NtfsBitmapError, NtfsReconciliationLimits, parse_bitmap, reconcile_allocation_claims,
};
use crate::fs::ntfs_discovery::{
    NtfsDiscoveryError, NtfsDiscoveryLimits, NtfsSystemDiscovery,
    discover_system_records_with_reader, read_mft_record_for_inventory_with_reader,
};
use crate::fs::ntfs_inventory::{
    NtfsExtentPlacement, NtfsInventory, NtfsInventoryError, NtfsInventoryLimits, NtfsStreamStorage,
    inventory_ntfs_with_reader,
};
use crate::fs::ntfs_normalize::{
    NormalizedNtfs, NtfsNormalizeError, NtfsNormalizeLimits, NtfsSecurityDescriptorEvidence,
    normalize_inventory as normalize_ntfs,
};
use crate::fs::ntfs_region::{self, NtfsBootRegion, NtfsBootRegionError};
use crate::fs::ntfs_secure::{
    NtfsSecureError, NtfsSecureLimits, NtfsSecureProfile, generate_ntfs_secure_metadata,
};
use crate::fs::ntfs_volume::{
    NtfsBitmapEvidence, NtfsMetadataIncompleteReason, NtfsMftBitmapEvidence, NtfsVolumeDiscovery,
    NtfsVolumeError, NtfsVolumeEvidence, NtfsVolumeLimits, discover_volume_and_bitmap_with_reader,
};
use crate::image::{BoundedImageReader, ImageError, ImageFile, ImageIdentity};
use crate::object::ObjectGraphLimits;
use crate::overlay::OverlayPlan;
use crate::{AccessState, FileSystem, HealthState, VolumeProfile, VolumeRole, VolumeState};

const BOOT_PREFIX_BYTES: usize = 512;
const EXFAT_NAME: &[u8; 8] = b"EXFAT   ";
const NTFS_NAME: &[u8; 8] = b"NTFS    ";
const EXFAT_VOLUME_DIRTY: u16 = 1 << 1;
const EXFAT_MEDIA_FAILURE: u16 = 1 << 2;
const EXFAT_DISCOVERY_MAX_BYTES: usize = 16 * 1024 * 1024;
const EXFAT_DISCOVERY_MAX_CLUSTERS: usize = 32 * 1024;
const EXFAT_DIRECTORY_MAX_ENTRIES: usize = EXFAT_DISCOVERY_MAX_BYTES / 32;
const EXFAT_INVENTORY_MAX_OBJECTS: usize = 262_144;
const EXFAT_INVENTORY_MAX_DIRECTORIES: usize = 65_536;
const EXFAT_INVENTORY_MAX_DEPTH: usize = 256;
const EXFAT_INVENTORY_MAX_DIRECTORY_BYTES: u64 = 256 * 1024 * 1024;
const EXFAT_INVENTORY_MAX_CLUSTERS: usize = 1_048_576;
const EXFAT_INVENTORY_MAX_EXTENTS: usize = 1_048_576;
const EXFAT_INVENTORY_MAX_PATH_UNITS: usize = 32_768;
const EXFAT_INVENTORY_MAX_SIBLING_COMPARISONS: usize = 16_777_216;

/// Validated filesystem-specific boot geometry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootSector {
    ExFat(ExfatBootSector),
    Ntfs(NtfsBootSector),
}

/// Validation evidence for the filesystem's redundant boot structures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootRedundancy {
    ExFat(Box<ExfatBootRegionsValidation>),
    Ntfs(Box<NtfsBootRegion>),
}

struct InspectionEvidence {
    boot_sector: BootSector,
    boot_redundancy: BootRedundancy,
    exfat_root: Option<Box<ExfatRootDiscovery>>,
    exfat_inventory: Option<Box<ExfatInventory>>,
    normalized_exfat: Option<Box<NormalizedExfat>>,
    ntfs_discovery: Option<Box<NtfsSystemDiscovery>>,
    ntfs_volume: Option<Box<NtfsVolumeDiscovery>>,
    ntfs_inventory: Option<Box<NtfsInventory>>,
    ntfs_allocation_reconciliation: Option<NtfsAllocationReconciliationStatus>,
    ntfs_mft_record_reconciliation: Option<NtfsMftRecordReconciliationStatus>,
    normalized_ntfs: Option<Box<NormalizedNtfs>>,
}

/// Presentation/provenance supplied separately from the byte-reader capability.
///
/// Keeping this sealed prevents a generic reader from impersonating a pinned regular image. The
/// conversion coordinator remains responsible for proving that an overlay digest belongs to its
/// exact prepared plan before it may mint staging-verification evidence.
#[derive(Debug, Clone, Copy)]
enum InspectionOrigin<'a> {
    Regular(&'a ImageIdentity),
    Overlay {
        base: &'a ImageIdentity,
        overlay_digest: [u8; 32],
    },
}

impl<'a> InspectionOrigin<'a> {
    const fn base_identity(self) -> &'a ImageIdentity {
        match self {
            Self::Regular(identity) | Self::Overlay { base: identity, .. } => identity,
        }
    }
}

/// Exact NTFS `$Bitmap`/physical-owner comparison evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtfsAllocationReconciliationStatus {
    /// Every allocated cluster has exactly one inventoried owner.
    Complete(NtfsAllocationReconciliation),
    /// Known physical owners are consistent, but the bounded object inventory is incomplete.
    IncompleteInventory(NtfsAllocationReconciliation),
    /// `$Bitmap` itself could not be read completely, so ownership could not be compared.
    IncompleteBitmap {
        reason: NtfsMetadataIncompleteReason,
    },
}

impl NtfsAllocationReconciliationStatus {
    #[must_use]
    pub const fn is_complete(self) -> bool {
        matches!(self, Self::Complete(_))
    }
}

/// Exact `$MFT::$BITMAP` versus `FILE`-header reconciliation counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtfsMftRecordReconciliation {
    pub compared_records: u64,
    pub in_use_records: u64,
    pub free_records: u64,
}

/// Whether the bounded record census proves every initialized MFT record's allocation state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtfsMftRecordReconciliationStatus {
    Complete(NtfsMftRecordReconciliation),
    IncompleteInventory(NtfsMftRecordReconciliation),
    IncompleteBitmap {
        reason: NtfsMetadataIncompleteReason,
    },
}

impl NtfsMftRecordReconciliationStatus {
    #[must_use]
    pub const fn is_complete(self) -> bool {
        matches!(self, Self::Complete(_))
    }
}

/// A contradiction between `$MFT::$BITMAP`, initialized `$MFT` length, and `FILE` flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtfsMftRecordReconciliationError {
    BitmapTooShort {
        initialized_records: u64,
        available_bits: u64,
    },
    RecordStateMismatch {
        record_number: u64,
        bitmap_in_use: bool,
        file_record_in_use: bool,
    },
    AllocatedRecordBeyondInitialized {
        record_number: u64,
    },
    GeometryOverflow {
        calculation: &'static str,
    },
}

impl fmt::Display for NtfsMftRecordReconciliationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BitmapTooShort {
                initialized_records,
                available_bits,
            } => write!(
                formatter,
                "$MFT::$BITMAP exposes {available_bits} bits for {initialized_records} initialized records"
            ),
            Self::RecordStateMismatch {
                record_number,
                bitmap_in_use,
                file_record_in_use,
            } => write!(
                formatter,
                "$MFT record {record_number} allocation mismatch: bitmap={bitmap_in_use}, FILE.in_use={file_record_in_use}"
            ),
            Self::AllocatedRecordBeyondInitialized { record_number } => write!(
                formatter,
                "$MFT::$BITMAP marks record {record_number} allocated beyond initialized $MFT data"
            ),
            Self::GeometryOverflow { calculation } => write!(
                formatter,
                "$MFT record reconciliation overflow while calculating {calculation}"
            ),
        }
    }
}

impl std::error::Error for NtfsMftRecordReconciliationError {}

/// Evidence produced by opening and parsing one regular image file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageInspection {
    pub profile: VolumeProfile,
    pub boot_sector: BootSector,
    pub boot_redundancy: BootRedundancy,
    pub exfat_root: Option<Box<ExfatRootDiscovery>>,
    pub exfat_inventory: Option<Box<ExfatInventory>>,
    pub normalized_exfat: Option<Box<NormalizedExfat>>,
    pub ntfs_discovery: Option<Box<NtfsSystemDiscovery>>,
    pub ntfs_volume: Option<Box<NtfsVolumeDiscovery>>,
    pub ntfs_inventory: Option<Box<NtfsInventory>>,
    pub ntfs_allocation_reconciliation: Option<NtfsAllocationReconciliationStatus>,
    pub ntfs_mft_record_reconciliation: Option<NtfsMftRecordReconciliationStatus>,
    pub normalized_ntfs: Option<Box<NormalizedNtfs>>,
    pub image_bytes: u64,
    pub declared_volume_bytes: u64,
    pub trailing_bytes: u64,
}

/// A read, recognition, boot-geometry, or boot-redundancy failure during image discovery.
#[derive(Debug)]
pub enum InspectionError {
    Image(ImageError),
    UnrecognizedFileSystem,
    InvalidExFat(ExfatBootSectorError),
    InvalidExFatBootRegions(ExfatBootRegionError),
    InvalidExFatRoot(ExfatDiscoveryError),
    InvalidExFatInventory(ExfatInventoryError),
    InvalidExFatNormalization(ExfatNormalizeError),
    InvalidNtfs(NtfsBootSectorError),
    InvalidNtfsBootRegion(NtfsBootRegionError),
    InvalidNtfsDiscovery(NtfsDiscoveryError),
    InvalidNtfsVolume(NtfsVolumeError),
    InvalidNtfsInventory(NtfsInventoryError),
    InvalidNtfsAllocationReconciliation(NtfsBitmapError),
    InvalidNtfsMftRecordReconciliation(NtfsMftRecordReconciliationError),
    InvalidNtfsNormalization(NtfsNormalizeError),
    InvalidNtfsSecurityProfile(NtfsSecureError),
    GeometryOverflow { calculation: &'static str },
    DeclaredVolumeExceedsImage { declared: u64, image: u64 },
}

impl fmt::Display for InspectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Image(error) => write!(formatter, "image access failed: {error}"),
            Self::UnrecognizedFileSystem => formatter
                .write_str("image does not begin with a recognized exFAT or NTFS boot sector"),
            Self::InvalidExFat(error) => write!(formatter, "invalid exFAT boot sector: {error}"),
            Self::InvalidExFatBootRegions(error) => {
                write!(formatter, "invalid exFAT boot-region redundancy: {error}")
            }
            Self::InvalidExFatRoot(error) => {
                write!(formatter, "invalid exFAT root/allocation metadata: {error}")
            }
            Self::InvalidExFatInventory(error) => {
                write!(
                    formatter,
                    "invalid exFAT object/allocation inventory: {error}"
                )
            }
            Self::InvalidExFatNormalization(error) => {
                write!(formatter, "invalid normalized exFAT object graph: {error}")
            }
            Self::InvalidNtfs(error) => write!(formatter, "invalid NTFS boot sector: {error}"),
            Self::InvalidNtfsBootRegion(error) => {
                write!(formatter, "invalid NTFS boot-sector redundancy: {error}")
            }
            Self::InvalidNtfsDiscovery(error) => {
                write!(formatter, "invalid NTFS MFT bootstrap: {error}")
            }
            Self::InvalidNtfsVolume(error) => {
                write!(
                    formatter,
                    "invalid NTFS volume/allocation metadata: {error}"
                )
            }
            Self::InvalidNtfsInventory(error) => {
                write!(formatter, "invalid NTFS object inventory: {error}")
            }
            Self::InvalidNtfsAllocationReconciliation(error) => write!(
                formatter,
                "invalid NTFS allocation ownership reconciliation: {error}"
            ),
            Self::InvalidNtfsMftRecordReconciliation(error) => write!(
                formatter,
                "invalid NTFS MFT-record allocation reconciliation: {error}"
            ),
            Self::InvalidNtfsNormalization(error) => {
                write!(formatter, "invalid normalized NTFS object graph: {error}")
            }
            Self::InvalidNtfsSecurityProfile(error) => {
                write!(formatter, "invalid pinned NTFS security profile: {error}")
            }
            Self::GeometryOverflow { calculation } => {
                write!(formatter, "overflow while calculating {calculation}")
            }
            Self::DeclaredVolumeExceedsImage { declared, image } => write!(
                formatter,
                "filesystem declares {declared} bytes, but the image contains only {image} bytes"
            ),
        }
    }
}

impl std::error::Error for InspectionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Image(error) => Some(error),
            Self::InvalidExFat(error) => Some(error),
            Self::InvalidExFatBootRegions(error) => Some(error),
            Self::InvalidExFatRoot(error) => Some(error),
            Self::InvalidExFatInventory(error) => Some(error),
            Self::InvalidExFatNormalization(error) => Some(error),
            Self::InvalidNtfs(error) => Some(error),
            Self::InvalidNtfsBootRegion(error) => Some(error),
            Self::InvalidNtfsDiscovery(error) => Some(error),
            Self::InvalidNtfsVolume(error) => Some(error),
            Self::InvalidNtfsInventory(error) => Some(error),
            Self::InvalidNtfsAllocationReconciliation(error) => Some(error),
            Self::InvalidNtfsMftRecordReconciliation(error) => Some(error),
            Self::InvalidNtfsNormalization(error) => Some(error),
            Self::InvalidNtfsSecurityProfile(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ImageError> for InspectionError {
    fn from(error: ImageError) -> Self {
        Self::Image(error)
    }
}

/// Opens and inspects one regular image file without writing to it.
///
/// Device namespaces and non-regular files are rejected by [`ImageFile`]. This function reads only
/// the bounded filesystem metadata needed for boot, allocation, inventory, and normalization
/// validation.
///
/// # Errors
///
/// Returns [`InspectionError`] when the path is not a permitted regular image, the read is outside
/// the bounded image, the filesystem is unrecognized, or its boot structures are invalid.
pub fn inspect_image(path: impl AsRef<Path>) -> Result<ImageInspection, InspectionError> {
    let image = ImageFile::open(path)?;
    inspect_open_image(&image)
}

/// Inspects one already-opened regular image through its pinned read-only identity.
///
/// Frontends that will subsequently plan or export from an [`ImageFile`] should use this entry
/// point so discovery evidence and all later reads share the same handle identity. This closes the
/// path re-open window between inspection and conversion planning.
///
/// # Errors
///
/// Returns [`InspectionError`] when a bounded read fails, the filesystem is unrecognized, or any
/// filesystem structure is invalid or incomplete.
pub fn inspect_open_image(image: &ImageFile) -> Result<ImageInspection, InspectionError> {
    inspect_with_reader(image, InspectionOrigin::Regular(image.identity()))
}

/// Inspects the immutable candidate bytes produced by a validated overlay without mutating or
/// reopening its regular-file base.
///
/// This remains crate-private and returns ordinary inspection evidence only. The conversion
/// coordinator must independently bind `overlay_digest` to its prepared plan before constructing
/// any sealed staging-verification evidence.
pub(crate) fn inspect_overlay(
    base: &dyn BoundedImageReader,
    base_identity: &ImageIdentity,
    overlay: &OverlayPlan,
    overlay_digest: [u8; 32],
) -> Result<ImageInspection, InspectionError> {
    let reader = overlay
        .reader(base)
        .map_err(|_| InspectionError::Image(ImageError::SourceChanged))?;
    inspect_with_reader(
        &reader,
        InspectionOrigin::Overlay {
            base: base_identity,
            overlay_digest,
        },
    )
}

fn inspect_with_reader(
    image: &dyn BoundedImageReader,
    origin: InspectionOrigin<'_>,
) -> Result<ImageInspection, InspectionError> {
    let prefix = image.read_prefix(BOOT_PREFIX_BYTES)?;
    let identifier = &prefix[3..11];

    if identifier == EXFAT_NAME {
        inspect_exfat(image, origin, &prefix)
    } else if identifier == NTFS_NAME {
        inspect_ntfs(image, origin, &prefix)
    } else {
        Err(InspectionError::UnrecognizedFileSystem)
    }
}

#[allow(clippy::too_many_lines)]
fn inspect_exfat(
    image: &dyn BoundedImageReader,
    origin: InspectionOrigin<'_>,
    prefix: &[u8],
) -> Result<ImageInspection, InspectionError> {
    let sector_shift = prefix[108];
    if !(9..=12).contains(&sector_shift) {
        return exfat::parse_boot_sector(prefix)
            .map(|_| unreachable!("invalid sector shift unexpectedly parsed"))
            .map_err(InspectionError::InvalidExFat);
    }
    let sector_bytes =
        1_usize
            .checked_shl(u32::from(sector_shift))
            .ok_or(InspectionError::GeometryOverflow {
                calculation: "exFAT logical sector size",
            })?;
    let boot_region_bytes =
        sector_bytes
            .checked_mul(24)
            .ok_or(InspectionError::GeometryOverflow {
                calculation: "exFAT combined boot-region byte length",
            })?;
    let regions = image.read_prefix(boot_region_bytes)?;
    let boot_redundancy = exfat_region::validate_boot_regions(&regions, sector_bytes)
        .map_err(InspectionError::InvalidExFatBootRegions)?;
    let boot = boot_redundancy.main.boot_sector;
    let declared_volume_bytes = boot
        .volume_length_sectors
        .checked_mul(u64::from(boot.bytes_per_sector))
        .ok_or(InspectionError::GeometryOverflow {
            calculation: "exFAT declared volume byte length",
        })?;
    if declared_volume_bytes > image.len() {
        return Err(InspectionError::DeclaredVolumeExceedsImage {
            declared: declared_volume_bytes,
            image: image.len(),
        });
    }
    let discovery_limits = ExfatDiscoveryLimits {
        root_stream: StreamReadLimits {
            max_bytes: EXFAT_DISCOVERY_MAX_BYTES,
            max_clusters: EXFAT_DISCOVERY_MAX_CLUSTERS,
        },
        system_stream: StreamReadLimits {
            max_bytes: EXFAT_DISCOVERY_MAX_BYTES,
            max_clusters: EXFAT_DISCOVERY_MAX_CLUSTERS,
        },
        max_directory_entries: EXFAT_DIRECTORY_MAX_ENTRIES,
        max_secondary_entries: u8::MAX,
    };
    let root = discover_root_with_reader(image, &boot, discovery_limits)
        .map_err(InspectionError::InvalidExFatRoot)?;
    let inventory = inventory_image_with_reader(
        image,
        &boot,
        ExfatInventoryLimits {
            discovery: discovery_limits,
            directory_stream: StreamReadLimits {
                max_bytes: EXFAT_DISCOVERY_MAX_BYTES,
                max_clusters: EXFAT_DISCOVERY_MAX_CLUSTERS,
            },
            max_objects: EXFAT_INVENTORY_MAX_OBJECTS,
            max_directories: EXFAT_INVENTORY_MAX_DIRECTORIES,
            max_depth: EXFAT_INVENTORY_MAX_DEPTH,
            max_directory_bytes: EXFAT_INVENTORY_MAX_DIRECTORY_BYTES,
            max_logical_bytes: declared_volume_bytes,
            max_clusters: EXFAT_INVENTORY_MAX_CLUSTERS,
            max_stream_clusters: EXFAT_INVENTORY_MAX_CLUSTERS,
            max_extents: EXFAT_INVENTORY_MAX_EXTENTS,
            max_path_code_units: EXFAT_INVENTORY_MAX_PATH_UNITS,
            max_sibling_comparisons: EXFAT_INVENTORY_MAX_SIBLING_COMPARISONS,
        },
    )
    .map_err(InspectionError::InvalidExFatInventory)?;
    let normalized = normalize_inventory(
        &inventory,
        ExfatNormalizeLimits {
            graph: ObjectGraphLimits {
                max_objects: EXFAT_INVENTORY_MAX_OBJECTS,
                max_entries: EXFAT_INVENTORY_MAX_OBJECTS,
                max_streams: EXFAT_INVENTORY_MAX_OBJECTS,
                max_name_code_units: 255,
            },
            max_extents: EXFAT_INVENTORY_MAX_EXTENTS,
        },
    )
    .map_err(InspectionError::InvalidExFatNormalization)?;
    finish_inspection(
        image,
        origin,
        FileSystem::ExFat,
        boot.bytes_per_cluster,
        declared_volume_bytes,
        exfat_health(boot.volume_flags, boot_redundancy.comparison),
        InspectionEvidence {
            boot_sector: BootSector::ExFat(boot),
            boot_redundancy: BootRedundancy::ExFat(Box::new(boot_redundancy)),
            exfat_root: Some(Box::new(root)),
            exfat_inventory: Some(Box::new(inventory)),
            normalized_exfat: Some(Box::new(normalized)),
            ntfs_discovery: None,
            ntfs_volume: None,
            ntfs_inventory: None,
            ntfs_allocation_reconciliation: None,
            ntfs_mft_record_reconciliation: None,
            normalized_ntfs: None,
        },
    )
}

fn inspect_ntfs(
    image: &dyn BoundedImageReader,
    origin: InspectionOrigin<'_>,
    prefix: &[u8],
) -> Result<ImageInspection, InspectionError> {
    let boot = ntfs::parse_boot_sector(prefix).map_err(InspectionError::InvalidNtfs)?;
    boot.validate_image_size(image.len())
        .map_err(InspectionError::InvalidNtfs)?;
    let sector_bytes = usize::from(boot.bytes_per_sector);
    let primary = if sector_bytes == BOOT_PREFIX_BYTES {
        prefix.to_vec()
    } else {
        image.read_first_sector(sector_bytes)?
    };
    let backup_offset = image
        .len()
        .checked_sub(u64::from(boot.bytes_per_sector))
        .ok_or(InspectionError::GeometryOverflow {
            calculation: "NTFS backup boot-sector offset",
        })?;
    let backup = image.read_exact_at(backup_offset, sector_bytes)?;
    let boot_redundancy =
        ntfs_region::validate_boot_region(&primary, &backup, image.len(), backup_offset)
            .map_err(InspectionError::InvalidNtfsBootRegion)?;
    let discovery =
        discover_system_records_with_reader(image, &boot, NtfsDiscoveryLimits::default())
            .map_err(InspectionError::InvalidNtfsDiscovery)?;
    let volume = discover_volume_and_bitmap_with_reader(
        image,
        &boot,
        &discovery.mft,
        NtfsVolumeLimits::default(),
    )
    .map_err(InspectionError::InvalidNtfsVolume)?;
    let inventory =
        inventory_ntfs_with_reader(image, &boot, &discovery.mft, NtfsInventoryLimits::default())
            .map_err(InspectionError::InvalidNtfsInventory)?;
    let allocation_reconciliation = reconcile_ntfs_allocation(&boot, &volume, &inventory)?;
    let mft_record_reconciliation =
        reconcile_ntfs_mft_records(image, &boot, &discovery, &volume, &inventory)?;
    let normalized = if inventory.is_complete()
        && allocation_reconciliation.is_complete()
        && mft_record_reconciliation.is_complete()
    {
        let mut normalized = normalize_ntfs(
            &inventory,
            image.len(),
            NtfsNormalizeLimits {
                graph: ObjectGraphLimits {
                    max_objects: NtfsInventoryLimits::default().max_records,
                    max_entries: NtfsInventoryLimits::default().max_index_entries,
                    max_streams: NtfsInventoryLimits::default().max_records,
                    max_name_code_units: NtfsInventoryLimits::default().max_name_code_units,
                },
                max_extents: NtfsInventoryLimits::default().max_extents,
                max_directory_entries: NtfsInventoryLimits::default().max_index_entries,
                max_preservation_bytes: NtfsInventoryLimits::default().max_bytes,
            },
        )
        .map_err(InspectionError::InvalidNtfsNormalization)?;
        normalized.preservation.security_descriptors =
            inspect_ntfs_security_descriptors(image, &inventory)?;
        Some(Box::new(normalized))
    } else {
        None
    };
    finish_inspection(
        image,
        origin,
        FileSystem::Ntfs,
        u32::try_from(boot.cluster_size_bytes).map_err(|_| InspectionError::GeometryOverflow {
            calculation: "NTFS cluster size conversion",
        })?,
        boot.minimum_image_bytes,
        ntfs_health(&volume.volume, discovery.mft_mirror),
        InspectionEvidence {
            boot_sector: BootSector::Ntfs(boot),
            boot_redundancy: BootRedundancy::Ntfs(Box::new(boot_redundancy)),
            exfat_root: None,
            exfat_inventory: None,
            normalized_exfat: None,
            ntfs_discovery: Some(Box::new(discovery)),
            ntfs_volume: Some(Box::new(volume)),
            ntfs_inventory: Some(Box::new(inventory)),
            ntfs_allocation_reconciliation: Some(allocation_reconciliation),
            ntfs_mft_record_reconciliation: Some(mft_record_reconciliation),
            normalized_ntfs: normalized,
        },
    )
}

fn reconcile_ntfs_allocation(
    boot: &NtfsBootSector,
    volume: &NtfsVolumeDiscovery,
    inventory: &NtfsInventory,
) -> Result<NtfsAllocationReconciliationStatus, InspectionError> {
    let allocation = match &volume.bitmap {
        NtfsBitmapEvidence::Complete(allocation) => allocation,
        NtfsBitmapEvidence::Incomplete { reason } => {
            return Ok(NtfsAllocationReconciliationStatus::IncompleteBitmap { reason: *reason });
        }
    };
    let bitmap = parse_bitmap(boot.cluster_count, &allocation.canonical_bitmap)
        .map_err(InspectionError::InvalidNtfsAllocationReconciliation)?;
    let mut claims = Vec::new();
    claims
        .try_reserve_exact(inventory.physical_allocations.len())
        .map_err(|_| {
            InspectionError::InvalidNtfsAllocationReconciliation(
                NtfsBitmapError::ReconciliationAllocationFailed,
            )
        })?;
    claims.extend(
        inventory
            .physical_allocations
            .iter()
            .map(|allocation| NtfsAllocationClaim {
                start_lcn: allocation.start_lcn,
                cluster_count: allocation.cluster_count,
            }),
    );
    let evidence = reconcile_allocation_claims(
        &bitmap,
        &claims,
        inventory.is_complete(),
        NtfsReconciliationLimits {
            max_claims: NtfsInventoryLimits::default().max_extents,
        },
    )
    .map_err(InspectionError::InvalidNtfsAllocationReconciliation)?;
    Ok(match evidence {
        NtfsAllocationReconciliationEvidence::Complete(report) => {
            NtfsAllocationReconciliationStatus::Complete(report)
        }
        NtfsAllocationReconciliationEvidence::IncompleteInventory(report) => {
            NtfsAllocationReconciliationStatus::IncompleteInventory(report)
        }
    })
}

fn reconcile_ntfs_mft_records(
    image: &dyn BoundedImageReader,
    boot: &NtfsBootSector,
    discovery: &NtfsSystemDiscovery,
    volume: &NtfsVolumeDiscovery,
    inventory: &NtfsInventory,
) -> Result<NtfsMftRecordReconciliationStatus, InspectionError> {
    let mft_bitmap = match &volume.mft_bitmap {
        NtfsMftBitmapEvidence::Complete(bitmap) => &bitmap.canonical_bitmap,
        NtfsMftBitmapEvidence::Incomplete { reason } => {
            return Ok(NtfsMftRecordReconciliationStatus::IncompleteBitmap { reason: *reason });
        }
    };
    let available_bits = u64::try_from(mft_bitmap.len())
        .ok()
        .and_then(|bytes| bytes.checked_mul(8))
        .ok_or(InspectionError::InvalidNtfsMftRecordReconciliation(
            NtfsMftRecordReconciliationError::GeometryOverflow {
                calculation: "$MFT::$BITMAP bit count",
            },
        ))?;
    if available_bits < inventory.initialized_records {
        return Err(InspectionError::InvalidNtfsMftRecordReconciliation(
            NtfsMftRecordReconciliationError::BitmapTooShort {
                initialized_records: inventory.initialized_records,
                available_bits,
            },
        ));
    }

    let mut in_use_records = 0_u64;
    for record_number in 0..inventory.scanned_records {
        let record = read_mft_record_for_inventory_with_reader(
            image,
            boot,
            &discovery.mft,
            record_number,
            boot.mft_record_size.bytes,
        )
        .map_err(InspectionError::InvalidNtfsDiscovery)?;
        let bitmap_in_use = mft_bitmap_bit(mft_bitmap, record_number);
        let file_record_in_use = record.flags.is_in_use();
        if bitmap_in_use != file_record_in_use {
            return Err(InspectionError::InvalidNtfsMftRecordReconciliation(
                NtfsMftRecordReconciliationError::RecordStateMismatch {
                    record_number,
                    bitmap_in_use,
                    file_record_in_use,
                },
            ));
        }
        in_use_records = in_use_records
            .checked_add(u64::from(file_record_in_use))
            .ok_or(InspectionError::InvalidNtfsMftRecordReconciliation(
                NtfsMftRecordReconciliationError::GeometryOverflow {
                    calculation: "in-use MFT record count",
                },
            ))?;
    }
    if let Some(record_number) = first_set_mft_bitmap_bit(mft_bitmap, inventory.initialized_records)
    {
        return Err(InspectionError::InvalidNtfsMftRecordReconciliation(
            NtfsMftRecordReconciliationError::AllocatedRecordBeyondInitialized { record_number },
        ));
    }
    let report = NtfsMftRecordReconciliation {
        compared_records: inventory.scanned_records,
        in_use_records,
        free_records: inventory
            .scanned_records
            .checked_sub(in_use_records)
            .ok_or(InspectionError::InvalidNtfsMftRecordReconciliation(
                NtfsMftRecordReconciliationError::GeometryOverflow {
                    calculation: "free MFT record count",
                },
            ))?,
    };
    Ok(if inventory.is_complete() {
        NtfsMftRecordReconciliationStatus::Complete(report)
    } else {
        NtfsMftRecordReconciliationStatus::IncompleteInventory(report)
    })
}

fn mft_bitmap_bit(bitmap: &[u8], record_number: u64) -> bool {
    let byte = usize::try_from(record_number / 8).expect("validated bitmap index fits usize");
    bitmap[byte] & (1 << (record_number % 8)) != 0
}

fn first_set_mft_bitmap_bit(bitmap: &[u8], start: u64) -> Option<u64> {
    let mut byte_index = usize::try_from(start / 8).ok()?;
    if byte_index >= bitmap.len() {
        return None;
    }
    let first_bit = u8::try_from(start % 8).ok()?;
    let first = bitmap[byte_index] & (u8::MAX << first_bit);
    if first != 0 {
        return u64::try_from(byte_index)
            .ok()?
            .checked_mul(8)?
            .checked_add(u64::from(first.trailing_zeros()));
    }
    byte_index = byte_index.checked_add(1)?;
    for (offset, byte) in bitmap[byte_index..].iter().copied().enumerate() {
        if byte != 0 {
            let index = byte_index.checked_add(offset)?;
            return u64::try_from(index)
                .ok()?
                .checked_mul(8)?
                .checked_add(u64::from(byte.trailing_zeros()));
        }
    }
    None
}

fn inspect_ntfs_security_descriptors(
    image: &dyn BoundedImageReader,
    inventory: &NtfsInventory,
) -> Result<NtfsSecurityDescriptorEvidence, InspectionError> {
    const SECURE_RECORD: u64 = 9;
    let expected = generate_ntfs_secure_metadata(
        NtfsSecureProfile::MkntfsWindows2003Ntfs31,
        NtfsSecureLimits::default(),
    )
    .map_err(InspectionError::InvalidNtfsSecurityProfile)?;
    let expected_name: Vec<u16> = "$SDS".encode_utf16().collect();
    let Some(stream) = inventory
        .objects
        .iter()
        .find(|object| object.reference.record_number == SECURE_RECORD)
        .and_then(|object| {
            let mut matches = object.data_streams.iter().filter(|stream| {
                stream
                    .name
                    .as_ref()
                    .is_some_and(|name| name.code_units == expected_name)
            });
            let first = matches.next()?;
            matches.next().is_none().then_some(first)
        })
    else {
        return Ok(NtfsSecurityDescriptorEvidence::Unavailable);
    };
    let bytes = match &stream.storage {
        NtfsStreamStorage::Resident { bytes } => bytes.clone(),
        NtfsStreamStorage::NonResident {
            data_bytes,
            initialized_bytes,
            mapping_complete,
            extents,
            ..
        } => {
            if !mapping_complete
                || *data_bytes != u64::try_from(expected.sds.len()).unwrap_or(u64::MAX)
                || initialized_bytes < data_bytes
            {
                return Ok(NtfsSecurityDescriptorEvidence::Unavailable);
            }
            let mut ordered = extents.clone();
            ordered.sort_unstable_by_key(|extent| extent.logical_offset);
            let mut output = Vec::new();
            output.try_reserve_exact(expected.sds.len()).map_err(|_| {
                InspectionError::InvalidNtfsSecurityProfile(NtfsSecureError::AllocationFailed {
                    what: "inspected $Secure:$SDS evidence",
                })
            })?;
            let mut logical = 0_u64;
            for extent in ordered {
                if extent.logical_offset != logical || logical >= *data_bytes {
                    return Ok(NtfsSecurityDescriptorEvidence::Unavailable);
                }
                let NtfsExtentPlacement::Physical { byte_offset } = extent.placement else {
                    return Ok(NtfsSecurityDescriptorEvidence::Unavailable);
                };
                let length = extent.length.min(*data_bytes - logical);
                let length =
                    usize::try_from(length).map_err(|_| InspectionError::GeometryOverflow {
                        calculation: "NTFS security extent read length",
                    })?;
                output.extend_from_slice(&image.read_exact_at(byte_offset, length)?);
                logical = logical.checked_add(extent.length).ok_or(
                    InspectionError::GeometryOverflow {
                        calculation: "NTFS security stream logical offset",
                    },
                )?;
            }
            if output.len() != expected.sds.len() {
                return Ok(NtfsSecurityDescriptorEvidence::Unavailable);
            }
            output
        }
    };
    if bytes == expected.sds {
        Ok(NtfsSecurityDescriptorEvidence::PinnedNtfs3gWindows2003 { sds: bytes })
    } else {
        Ok(NtfsSecurityDescriptorEvidence::Unavailable)
    }
}

fn finish_inspection(
    image: &dyn BoundedImageReader,
    origin: InspectionOrigin<'_>,
    filesystem: FileSystem,
    cluster_bytes: u32,
    declared_volume_bytes: u64,
    health: HealthState,
    evidence: InspectionEvidence,
) -> Result<ImageInspection, InspectionError> {
    if declared_volume_bytes > image.len() {
        return Err(InspectionError::DeclaredVolumeExceedsImage {
            declared: declared_volume_bytes,
            image: image.len(),
        });
    }
    let canonical_path = origin.base_identity().canonical_path();
    let display_name = canonical_path.file_name().map_or_else(
        || canonical_path.display().to_string(),
        |name| name.to_string_lossy().into(),
    );
    let logical_sector_bytes = match evidence.boot_sector {
        BootSector::ExFat(boot) => boot.bytes_per_sector,
        BootSector::Ntfs(boot) => u32::from(boot.bytes_per_sector),
    };

    Ok(ImageInspection {
        profile: VolumeProfile {
            display_name,
            stable_id: inspection_stable_id(origin, image.len()),
            filesystem,
            capacity_bytes: declared_volume_bytes,
            free_bytes: evidence
                .exfat_root
                .as_ref()
                .map(|root| root.free_bytes)
                .or_else(|| {
                    evidence.ntfs_volume.as_ref().and_then(|volume| {
                        if let NtfsBitmapEvidence::Complete(allocation) = &volume.bitmap {
                            Some(allocation.free_bytes)
                        } else {
                            None
                        }
                    })
                }),
            logical_sector_bytes,
            cluster_bytes,
            state: VolumeState {
                health,
                access: AccessState::Unknown,
            },
            role: VolumeRole {
                system_volume: false,
                encrypted_container: false,
            },
            features: evidence.normalized_exfat.as_ref().map_or_else(
                || {
                    evidence
                        .normalized_ntfs
                        .as_ref()
                        .map_or_else(Vec::new, |normalized| normalized.graph.features().to_vec())
                },
                |normalized| normalized.graph.features().to_vec(),
            ),
            inventory_complete: evidence.normalized_exfat.is_some()
                || evidence.normalized_ntfs.is_some(),
        },
        boot_sector: evidence.boot_sector,
        boot_redundancy: evidence.boot_redundancy,
        exfat_root: evidence.exfat_root,
        exfat_inventory: evidence.exfat_inventory,
        normalized_exfat: evidence.normalized_exfat,
        ntfs_discovery: evidence.ntfs_discovery,
        ntfs_volume: evidence.ntfs_volume,
        ntfs_inventory: evidence.ntfs_inventory,
        ntfs_allocation_reconciliation: evidence.ntfs_allocation_reconciliation,
        ntfs_mft_record_reconciliation: evidence.ntfs_mft_record_reconciliation,
        normalized_ntfs: evidence.normalized_ntfs,
        image_bytes: image.len(),
        declared_volume_bytes,
        trailing_bytes: image.len() - declared_volume_bytes,
    })
}

fn inspection_stable_id(origin: InspectionOrigin<'_>, image_bytes: u64) -> String {
    let path = origin.base_identity().canonical_path();
    match origin {
        InspectionOrigin::Regular(_) => {
            format!("image:{}#length={image_bytes}", path.display())
        }
        InspectionOrigin::Overlay { overlay_digest, .. } => {
            use std::fmt::Write as _;

            let mut digest = String::with_capacity(64);
            for byte in overlay_digest {
                write!(&mut digest, "{byte:02x}").expect("writing to a String cannot fail");
            }
            format!(
                "overlay:{}#length={image_bytes}#sha256={digest}",
                path.display()
            )
        }
    }
}

const fn exfat_health(volume_flags: u16, comparison: ExfatBootRegionComparison) -> HealthState {
    if matches!(comparison, ExfatBootRegionComparison::Divergent { .. }) {
        HealthState::Unknown
    } else if volume_flags & (EXFAT_VOLUME_DIRTY | EXFAT_MEDIA_FAILURE) == 0 {
        HealthState::Clean
    } else {
        HealthState::Dirty
    }
}

const fn ntfs_health(
    volume: &NtfsVolumeEvidence,
    mft_mirror: crate::fs::ntfs_discovery::MftMirrorEvidence,
) -> HealthState {
    match volume {
        NtfsVolumeEvidence::Complete(information) if information.flags.raw != 0 => {
            HealthState::Dirty
        }
        NtfsVolumeEvidence::Complete(_)
            if matches!(
                mft_mirror,
                crate::fs::ntfs_discovery::MftMirrorEvidence::Exact { .. }
            ) =>
        {
            HealthState::Clean
        }
        NtfsVolumeEvidence::Complete(_) | NtfsVolumeEvidence::Incomplete { .. } => {
            HealthState::Unknown
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::overlay::{OverlayLimits, OverlayWrite};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TempImage(PathBuf);

    impl TempImage {
        fn write(bytes: &[u8]) -> Self {
            let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "starconverter-inspect-{}-{sequence}.img",
                std::process::id()
            ));
            fs::write(&path, bytes).expect("create test image");
            Self(path)
        }
    }

    impl Drop for TempImage {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_i64(bytes: &mut [u8], offset: usize, value: i64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn exfat_boot_checksum(region: &[u8]) -> u32 {
        region[..11 * 512]
            .iter()
            .copied()
            .enumerate()
            .filter(|(offset, _)| !matches!(offset, 106 | 107 | 112))
            .fold(0_u32, |checksum, (_, byte)| {
                checksum.rotate_right(1).wrapping_add(u32::from(byte))
            })
    }

    fn encoded_upcase() -> Vec<u8> {
        let mut encoded = Vec::new();
        for code_unit in 0_u16..128 {
            let mapping = if (u16::from(b'a')..=u16::from(b'z')).contains(&code_unit) {
                code_unit - 0x20
            } else {
                code_unit
            };
            encoded.extend_from_slice(&mapping.to_le_bytes());
        }
        encoded.extend_from_slice(&0xffff_u16.to_le_bytes());
        encoded.extend_from_slice(&65_408_u16.to_le_bytes());
        encoded
    }

    fn exfat_image() -> Vec<u8> {
        let volume_sectors = 2_048_u64;
        let mut image = vec![0_u8; usize::try_from(volume_sectors * 512).unwrap()];
        image[0..3].copy_from_slice(&[0xeb, 0x76, 0x90]);
        image[3..11].copy_from_slice(EXFAT_NAME);
        put_u64(&mut image, 64, 0);
        put_u64(&mut image, 72, volume_sectors);
        put_u32(&mut image, 80, 24);
        put_u32(&mut image, 84, 16);
        put_u32(&mut image, 88, 40);
        put_u32(&mut image, 92, 2_008);
        put_u32(&mut image, 96, 2);
        put_u16(&mut image, 104, 0x0100);
        image[108] = 9;
        image[109] = 0;
        image[110] = 1;
        image[112] = 0xff;
        put_u16(&mut image, 510, 0xaa55);
        for sector in 1..=8 {
            let signature_offset = sector * 512 + 508;
            put_u32(&mut image, signature_offset, 0xaa55_0000);
        }
        let checksum = exfat_boot_checksum(&image);
        for offset in (11 * 512..12 * 512).step_by(4) {
            put_u32(&mut image, offset, checksum);
        }
        image.copy_within(0..12 * 512, 12 * 512);

        for cluster in [2_u32, 3, 4] {
            put_u32(
                &mut image,
                24 * 512 + usize::try_from(cluster).unwrap() * 4,
                u32::MAX,
            );
        }
        let root = 40 * 512;
        image[root] = 0x81;
        put_u32(&mut image, root + 20, 3);
        put_u64(&mut image, root + 24, 251);
        let upcase = encoded_upcase();
        image[root + 32] = 0x82;
        put_u32(
            &mut image,
            root + 36,
            crate::fs::exfat_upcase::table_checksum(&upcase),
        );
        put_u32(&mut image, root + 52, 4);
        put_u64(&mut image, root + 56, u64::try_from(upcase.len()).unwrap());
        image[41 * 512] = 0b0000_0111;
        image[42 * 512..42 * 512 + upcase.len()].copy_from_slice(&upcase);
        image
    }

    fn ntfs_image() -> Vec<u8> {
        let mut image = vec![0_u8; 1_048_576];
        image[0..3].copy_from_slice(&[0xeb, 0x52, 0x90]);
        image[3..11].copy_from_slice(NTFS_NAME);
        put_u16(&mut image, 11, 512);
        image[13] = 8;
        image[21] = 0xf8;
        put_i64(&mut image, 40, 2_047);
        put_i64(&mut image, 48, 4);
        put_i64(&mut image, 56, 128);
        image[64] = (-10_i8).to_ne_bytes()[0];
        image[68] = 1;
        put_u16(&mut image, 510, 0xaa55);
        let mft_offset = 4 * 4096;
        image[mft_offset..mft_offset + 1024].copy_from_slice(&ntfs_file_record(0, true));
        for record_number in 1_u32..8 {
            let offset = mft_offset + usize::try_from(record_number).unwrap() * 1024;
            image[offset..offset + 1024].copy_from_slice(&ntfs_file_record(record_number, false));
        }
        let mirror_offset = 128 * 4096;
        image.copy_within(mft_offset..mft_offset + 4 * 1024, mirror_offset);
        let backup_offset = image.len() - 512;
        let (primary, backup) = image.split_at_mut(backup_offset);
        backup[..512].copy_from_slice(&primary[..512]);
        image
    }

    #[allow(clippy::too_many_lines)]
    fn ntfs_file_record(record_number: u32, mft_data: bool) -> Vec<u8> {
        let mut record = vec![0_u8; 1024];
        record[0..4].copy_from_slice(b"FILE");
        put_u16(&mut record, 4, 48);
        put_u16(&mut record, 6, 3);
        put_u16(&mut record, 16, 1);
        put_u16(&mut record, 18, 1);
        put_u16(&mut record, 20, 56);
        let flags = if record_number == 5 {
            7
        } else if matches!(record_number, 0 | 1 | 3 | 6) {
            5
        } else {
            0
        };
        put_u16(&mut record, 22, flags);
        put_u32(&mut record, 28, 1024);
        put_u16(&mut record, 40, 1);
        put_u32(&mut record, 44, record_number);
        let used = if mft_data {
            let attribute = 56;
            put_u32(&mut record, attribute, 0x80);
            put_u32(&mut record, attribute + 4, 72);
            record[attribute + 8] = 1;
            put_i64(&mut record, attribute + 16, 0);
            put_i64(&mut record, attribute + 24, 1);
            put_u16(&mut record, attribute + 32, 64);
            put_i64(&mut record, attribute + 40, 8192);
            put_i64(&mut record, attribute + 48, 8192);
            put_i64(&mut record, attribute + 56, 8192);
            record[attribute + 64..attribute + 68].copy_from_slice(&[0x11, 2, 4, 0]);
            let bitmap = attribute + 72;
            put_u32(&mut record, bitmap, 0xb0);
            put_u32(&mut record, bitmap + 4, 32);
            put_u16(&mut record, bitmap + 14, 1);
            put_u32(&mut record, bitmap + 16, 1);
            put_u16(&mut record, bitmap + 20, 24);
            record[bitmap + 24] = 0b0110_1011;
            put_u32(&mut record, bitmap + 32, u32::MAX);
            168
        } else if record_number == 1 {
            let attribute = 56;
            put_u32(&mut record, attribute, 0x80);
            put_u32(&mut record, attribute + 4, 72);
            record[attribute + 8] = 1;
            put_i64(&mut record, attribute + 16, 0);
            put_i64(&mut record, attribute + 24, 0);
            put_u16(&mut record, attribute + 32, 64);
            put_i64(&mut record, attribute + 40, 4096);
            put_i64(&mut record, attribute + 48, 4096);
            put_i64(&mut record, attribute + 56, 4096);
            record[attribute + 64..attribute + 69].copy_from_slice(&[0x21, 1, 0x80, 0, 0]);
            put_u32(&mut record, attribute + 72, u32::MAX);
            136
        } else if record_number == 3 {
            let attribute = 56;
            put_u32(&mut record, attribute, 0x70);
            put_u32(&mut record, attribute + 4, 40);
            put_u32(&mut record, attribute + 16, 12);
            put_u16(&mut record, attribute + 20, 24);
            record[attribute + 32] = 3;
            record[attribute + 33] = 1;
            put_u32(&mut record, attribute + 40, u32::MAX);
            104
        } else if record_number == 5 {
            let standard = 56;
            put_u32(&mut record, standard, 0x10);
            put_u32(&mut record, standard + 4, 72);
            put_u16(&mut record, standard + 14, 1);
            put_u32(&mut record, standard + 16, 48);
            put_u16(&mut record, standard + 20, 24);
            put_u32(&mut record, standard + 24 + 32, 0x10);

            let file_name = standard + 72;
            put_u32(&mut record, file_name, 0x30);
            put_u32(&mut record, file_name + 4, 96);
            put_u16(&mut record, file_name + 14, 2);
            put_u32(&mut record, file_name + 16, 68);
            put_u16(&mut record, file_name + 20, 24);
            put_u64(&mut record, file_name + 24, (u64::from(1_u16) << 48) | 5);
            put_u32(&mut record, file_name + 24 + 56, 0x10);
            record[file_name + 24 + 64] = 1;
            record[file_name + 24 + 65] = 1;
            put_u16(&mut record, file_name + 24 + 66, u16::from(b'.'));

            let index_root = file_name + 96;
            put_u32(&mut record, index_root, 0x90);
            put_u32(&mut record, index_root + 4, 80);
            record[index_root + 9] = 4;
            put_u16(&mut record, index_root + 10, 24);
            put_u16(&mut record, index_root + 14, 3);
            put_u32(&mut record, index_root + 16, 48);
            put_u16(&mut record, index_root + 20, 32);
            for (index, unit) in "$I30".encode_utf16().enumerate() {
                put_u16(&mut record, index_root + 24 + index * 2, unit);
            }
            let value = index_root + 32;
            put_u32(&mut record, value, 0x30);
            put_u32(&mut record, value + 4, 1);
            put_u32(&mut record, value + 8, 4096);
            record[value + 12] = 8;
            put_u32(&mut record, value + 16, 16);
            put_u32(&mut record, value + 20, 32);
            put_u32(&mut record, value + 24, 32);
            put_u16(&mut record, value + 32 + 8, 16);
            put_u16(&mut record, value + 32 + 12, 2);
            put_u32(&mut record, index_root + 80, u32::MAX);
            index_root + 88
        } else if record_number == 6 {
            let attribute = 56;
            put_u32(&mut record, attribute, 0x80);
            put_u32(&mut record, attribute + 4, 56);
            put_u32(&mut record, attribute + 16, 32);
            put_u16(&mut record, attribute + 20, 24);
            record[attribute + 24] = 0b0011_0000;
            record[attribute + 40] = 0b0000_0001;
            record[attribute + 55] = 0x80;
            put_u32(&mut record, attribute + 56, u32::MAX);
            120
        } else {
            put_u32(&mut record, 56, u32::MAX);
            64
        };
        put_u32(
            &mut record,
            24,
            u32::try_from(used).expect("fixture record size fits u32"),
        );
        put_u16(&mut record, 48, 0xa55a);
        put_u16(&mut record, 510, 0xa55a);
        put_u16(&mut record, 1022, 0xa55a);
        record
    }

    #[test]
    fn inspects_exfat_with_complete_recursive_inventory() {
        let temp = TempImage::write(&exfat_image());
        let image = ImageFile::open(&temp.0).expect("open exFAT image once");
        let inspection = inspect_open_image(&image).expect("inspect pinned exFAT image");

        assert_eq!(inspection.profile.filesystem, FileSystem::ExFat);
        assert_eq!(inspection.profile.logical_sector_bytes, 512);
        assert_eq!(inspection.profile.cluster_bytes, 512);
        assert_eq!(inspection.profile.free_bytes, Some(2005 * 512));
        assert!(inspection.profile.inventory_complete);
        assert_eq!(inspection.profile.state.health, HealthState::Clean);
        assert_eq!(inspection.profile.state.access, AccessState::Unknown);
        assert_eq!(inspection.trailing_bytes, 0);
        assert_eq!(
            inspection
                .exfat_root
                .as_ref()
                .expect("root evidence")
                .allocation
                .allocated_clusters,
            3
        );
        assert_eq!(
            inspection
                .exfat_inventory
                .as_ref()
                .expect("complete inventory evidence")
                .objects
                .len(),
            1
        );
    }

    #[test]
    fn overlay_inspection_uses_candidate_boot_regions_without_mutating_base() {
        let valid = exfat_image();
        let mut invalid_base = valid.clone();
        invalid_base[3] = b'X';
        let temp = TempImage::write(&invalid_base);
        let image = ImageFile::open(&temp.0).unwrap();
        assert!(matches!(
            inspect_open_image(&image),
            Err(InspectionError::UnrecognizedFileSystem)
        ));
        let overlay = OverlayPlan::build(
            u64::try_from(valid.len()).unwrap(),
            512,
            vec![OverlayWrite {
                offset: 0,
                bytes: valid[..24 * 512].to_vec(),
            }],
            OverlayLimits::default(),
        )
        .unwrap();

        let inspection = inspect_overlay(&image, image.identity(), &overlay, [0x42; 32]).unwrap();
        assert_eq!(inspection.profile.filesystem, FileSystem::ExFat);
        assert!(inspection.profile.inventory_complete);
        assert!(inspection.profile.stable_id.starts_with("overlay:"));
        assert!(inspection.profile.stable_id.ends_with(&"42".repeat(32)));
        assert_eq!(fs::read(&temp.0).unwrap(), invalid_base);
    }

    #[test]
    fn overlay_corruption_cannot_fall_back_to_valid_ntfs_base_boot() {
        let valid = ntfs_image();
        let temp = TempImage::write(&valid);
        let image = ImageFile::open(&temp.0).unwrap();
        inspect_open_image(&image).expect("base NTFS image is valid");
        let backup_offset = valid.len() - 512;
        let mut corrupt_backup = valid[backup_offset..].to_vec();
        corrupt_backup[100] ^= 1;
        let overlay = OverlayPlan::build(
            u64::try_from(valid.len()).unwrap(),
            512,
            vec![OverlayWrite {
                offset: u64::try_from(backup_offset).unwrap(),
                bytes: corrupt_backup,
            }],
            OverlayLimits::default(),
        )
        .unwrap();

        assert!(matches!(
            inspect_overlay(&image, image.identity(), &overlay, [0x24; 32]),
            Err(InspectionError::InvalidNtfsBootRegion(
                NtfsBootRegionError::BootSectorsDiffer { offset: 100, .. }
            ))
        ));
        assert_eq!(fs::read(&temp.0).unwrap(), valid);
    }

    #[test]
    fn inspects_and_normalizes_complete_ntfs_volume_evidence() {
        let temp = TempImage::write(&ntfs_image());
        let inspection = inspect_image(&temp.0).expect("inspect NTFS image");

        assert_eq!(inspection.profile.filesystem, FileSystem::Ntfs);
        assert_eq!(inspection.profile.cluster_bytes, 4096);
        assert_eq!(inspection.profile.state.health, HealthState::Clean);
        assert_eq!(inspection.profile.free_bytes, Some(252 * 4096));
        assert!(inspection.profile.inventory_complete);
        assert!(inspection.ntfs_discovery.is_some());
        assert!(inspection.ntfs_volume.is_some());
        let inventory = inspection.ntfs_inventory.as_ref().expect("NTFS inventory");
        assert_eq!(inventory.scanned_records, 8);
        assert!(inventory.is_complete());
        assert_eq!(
            inspection.ntfs_mft_record_reconciliation,
            Some(NtfsMftRecordReconciliationStatus::Complete(
                NtfsMftRecordReconciliation {
                    compared_records: 8,
                    in_use_records: 5,
                    free_records: 3,
                }
            ))
        );
        assert!(inspection.normalized_ntfs.is_some());
    }

    #[test]
    fn every_used_mft_mirror_record_region_is_health_authoritative() {
        let mirror_offset = 128 * 4096;
        for (record_number, bytes_in_use) in [168_u64, 136, 64, 104].into_iter().enumerate() {
            let byte_offset = bytes_in_use - 1;
            let mut bytes = ntfs_image();
            let mutation =
                mirror_offset + record_number * 1024 + usize::try_from(byte_offset).unwrap();
            bytes[mutation] ^= 1;
            let temp = TempImage::write(&bytes);

            let inspection = inspect_image(&temp.0).expect("retain mismatched mirror evidence");

            assert_eq!(inspection.profile.state.health, HealthState::Unknown);
            assert_eq!(
                inspection
                    .ntfs_discovery
                    .as_ref()
                    .expect("NTFS discovery")
                    .mft_mirror,
                crate::fs::ntfs_discovery::MftMirrorEvidence::Mismatch {
                    record_number: u64::try_from(record_number).unwrap(),
                    byte_offset_within_record: byte_offset,
                }
            );
        }
    }

    #[test]
    fn malformed_mft_mirror_records_fail_closed() {
        let mirror_offset = 128 * 4096;
        for byte_offset in [0, 510] {
            let mut bytes = ntfs_image();
            bytes[mirror_offset + byte_offset] ^= 1;
            let temp = TempImage::write(&bytes);

            assert!(matches!(
                inspect_image(&temp.0),
                Err(InspectionError::InvalidNtfsDiscovery(
                    NtfsDiscoveryError::FileRecord(_)
                ))
            ));
        }
    }

    #[test]
    fn stale_unused_mft_mirror_tails_do_not_claim_corruption() {
        let mirror_offset = 128 * 4096;
        for record_number in 0..4 {
            let mut bytes = ntfs_image();
            bytes[mirror_offset + record_number * 1024 + 700] ^= 1;
            let temp = TempImage::write(&bytes);

            let inspection = inspect_image(&temp.0).expect("ignore unused mirror tail bytes");
            assert_eq!(inspection.profile.state.health, HealthState::Clean);
            assert!(matches!(
                inspection
                    .ntfs_discovery
                    .as_ref()
                    .expect("NTFS discovery")
                    .mft_mirror,
                crate::fs::ntfs_discovery::MftMirrorEvidence::Exact {
                    records_compared: 4,
                    ..
                }
            ));
        }
    }

    #[test]
    fn rejects_mft_bitmap_bit_that_contradicts_file_in_use_flag() {
        let mut bytes = ntfs_image();
        let mft_bitmap_value = 4 * 4096 + 56 + 72 + 24;
        bytes[mft_bitmap_value] |= 1 << 2;
        let temp = TempImage::write(&bytes);

        assert!(matches!(
            inspect_image(&temp.0),
            Err(InspectionError::InvalidNtfsMftRecordReconciliation(
                NtfsMftRecordReconciliationError::RecordStateMismatch {
                    record_number: 2,
                    bitmap_in_use: true,
                    file_record_in_use: false,
                }
            ))
        ));
    }

    #[test]
    fn rejects_mft_bitmap_allocation_beyond_initialized_data() {
        let mut bytes = ntfs_image();
        let mft_bitmap = 4 * 4096 + 56 + 72;
        put_u32(&mut bytes, mft_bitmap + 16, 2);
        bytes[mft_bitmap + 25] = 1;
        let temp = TempImage::write(&bytes);

        assert!(matches!(
            inspect_image(&temp.0),
            Err(InspectionError::InvalidNtfsMftRecordReconciliation(
                NtfsMftRecordReconciliationError::AllocatedRecordBeyondInitialized {
                    record_number: 8,
                }
            ))
        ));
    }

    #[test]
    fn bounded_mft_record_census_is_explicitly_incomplete() {
        let mut bytes = ntfs_image();
        let mft_data = 4 * 4096 + 56;
        put_i64(&mut bytes, mft_data + 40, 16_384);
        put_i64(&mut bytes, mft_data + 48, 16_384);
        put_i64(&mut bytes, mft_data + 56, 16_384);
        let mft_bitmap = mft_data + 72;
        put_u32(&mut bytes, mft_bitmap + 16, 2);
        bytes[mft_bitmap + 25] = 0;
        let temp = TempImage::write(&bytes);

        let inspection = inspect_image(&temp.0).expect("retain bounded incomplete record census");

        assert!(!inspection.profile.inventory_complete);
        assert!(inspection.normalized_ntfs.is_none());
        assert_eq!(
            inspection.ntfs_mft_record_reconciliation,
            Some(NtfsMftRecordReconciliationStatus::IncompleteInventory(
                NtfsMftRecordReconciliation {
                    compared_records: 8,
                    in_use_records: 5,
                    free_records: 3,
                }
            ))
        );
    }

    #[test]
    fn rejects_unrecognized_and_short_images() {
        let unrecognized = TempImage::write(&[0_u8; 512]);
        assert!(matches!(
            inspect_image(&unrecognized.0),
            Err(InspectionError::UnrecognizedFileSystem)
        ));

        let short = TempImage::write(&[0_u8; 64]);
        assert!(matches!(
            inspect_image(&short.0),
            Err(InspectionError::Image(ImageError::OutOfRange { .. }))
        ));
    }

    #[test]
    fn rejects_declared_exfat_volume_larger_than_image() {
        let mut image = exfat_image();
        image.truncate(image.len() - 512);
        let temp = TempImage::write(&image);

        assert!(matches!(
            inspect_image(&temp.0),
            Err(InspectionError::DeclaredVolumeExceedsImage { .. })
        ));
    }

    #[test]
    fn rejects_ntfs_image_without_backup_boot_sector_capacity() {
        let mut image = ntfs_image();
        image.truncate(image.len() - 1);
        let temp = TempImage::write(&image);

        assert!(matches!(
            inspect_image(&temp.0),
            Err(InspectionError::InvalidNtfs(
                NtfsBootSectorError::ImageTooSmall { .. }
            ))
        ));
    }

    #[test]
    fn rejects_corrupt_exfat_checksum_and_ntfs_backup_divergence() {
        let mut exfat = exfat_image();
        exfat[600] ^= 1;
        let exfat_temp = TempImage::write(&exfat);
        assert!(matches!(
            inspect_image(&exfat_temp.0),
            Err(InspectionError::InvalidExFatBootRegions(
                ExfatBootRegionError::InvalidBootChecksumWord { .. }
            ))
        ));

        let mut ntfs = ntfs_image();
        let backup_offset = ntfs.len() - 512;
        ntfs[backup_offset + 100] ^= 1;
        let ntfs_temp = TempImage::write(&ntfs);
        assert!(matches!(
            inspect_image(&ntfs_temp.0),
            Err(InspectionError::InvalidNtfsBootRegion(
                NtfsBootRegionError::BootSectorsDiffer { offset: 100, .. }
            ))
        ));
    }

    #[test]
    fn non_stale_exfat_boot_region_divergence_makes_health_unknown() {
        let mut image = exfat_image();
        let backup_start = 12 * 512;
        image[backup_start + 111] = 0x80;
        let checksum = exfat_boot_checksum(&image[backup_start..]);
        for offset in (backup_start + 11 * 512..backup_start + 12 * 512).step_by(4) {
            put_u32(&mut image, offset, checksum);
        }
        let temp = TempImage::write(&image);
        let inspection = inspect_image(&temp.0).expect("independently valid divergent regions");

        assert_eq!(inspection.profile.state.health, HealthState::Unknown);
        assert!(matches!(
            inspection.boot_redundancy,
            BootRedundancy::ExFat(ref validation)
                if matches!(validation.comparison, ExfatBootRegionComparison::Divergent { .. })
        ));
    }
}
