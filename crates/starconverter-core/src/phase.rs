//! Read-only composition of serializer output into transaction phase write sets.
//!
//! This is the narrow bridge between pure destination serializers and [`crate::conversion`]. It
//! classifies staging writes against exact reservations and captures all rollback bytes from an
//! already pinned regular image. It has no mutation or raw-device API.

use std::fmt;

use crate::FileSystem;
use crate::conversion::{OpaqueWriteSets, ReservedWrite};
use crate::fs::exfat_serialize::ExfatSerializationPlan;
use crate::fs::ntfs_serialize::NtfsDestinationPlan;
use crate::geometry::{DestinationReservation, ReservationKind};
use crate::image::ImageFile;
use crate::overlay::OverlayWrite;
use crate::preimage::{PreimageError, PreimageLimits, capture_before_images};

/// Serializer phase writes carrying an unforgeable activation-readiness authorization.
///
/// The fields and constructor are intentionally private. Public callers can obtain this value only
/// from one of the filesystem-specific adapters below, after that serializer reports no remaining
/// activation gaps. This prevents hand-built [`OpaqueWriteSets`] from reaching the transaction
/// coordinator while retaining the opaque sets as a useful validation/intermediate representation.
///
/// Public construction is deliberately impossible:
///
/// ```compile_fail
/// use starconverter_core::conversion::OpaqueWriteSets;
/// use starconverter_core::phase::ActivationAuthorizedWrites;
/// use starconverter_core::FileSystem;
///
/// let _forged = ActivationAuthorizedWrites {
///     filesystem: FileSystem::Ntfs,
///     writes: OpaqueWriteSets::default(),
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivationAuthorizedWrites {
    filesystem: FileSystem,
    writes: OpaqueWriteSets,
}

impl ActivationAuthorizedWrites {
    const fn new(filesystem: FileSystem, writes: OpaqueWriteSets) -> Self {
        Self { filesystem, writes }
    }

    pub(crate) fn into_parts(self) -> (FileSystem, OpaqueWriteSets) {
        (self.filesystem, self.writes)
    }

    #[cfg(test)]
    pub(crate) const fn test_only(filesystem: FileSystem, writes: OpaqueWriteSets) -> Self {
        Self::new(filesystem, writes)
    }

    #[cfg(test)]
    pub(crate) const fn test_writes_mut(&mut self) -> &mut OpaqueWriteSets {
        &mut self.writes
    }

    #[cfg(test)]
    pub(crate) const fn test_set_filesystem(&mut self, filesystem: FileSystem) {
        self.filesystem = filesystem;
    }
}

/// Read-only, exact transaction bytes for a serializer plan which may still be activation-blocked.
///
/// A preview is intentionally not accepted by [`crate::conversion::PreparedConversion`]. It lets
/// callers audit phase classification and persist/check exact before-images without weakening the
/// opaque activation gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhaseWritePreview {
    target_filesystem: FileSystem,
    writes: OpaqueWriteSets,
    activation_gaps: &'static [&'static str],
}

impl PhaseWritePreview {
    #[must_use]
    pub const fn target_filesystem(&self) -> FileSystem {
        self.target_filesystem
    }

    #[must_use]
    pub const fn writes(&self) -> &OpaqueWriteSets {
        &self.writes
    }

    #[must_use]
    pub const fn activation_gaps(&self) -> &'static [&'static str] {
        self.activation_gaps
    }

    #[must_use]
    pub const fn activation_ready(&self) -> bool {
        self.activation_gaps.is_empty()
    }

    fn authorize(self) -> ActivationAuthorizedWrites {
        debug_assert!(self.activation_ready());
        ActivationAuthorizedWrites::new(self.target_filesystem, self.writes)
    }

    #[cfg(test)]
    pub(crate) const fn test_only(
        target_filesystem: FileSystem,
        writes: OpaqueWriteSets,
        activation_gaps: &'static [&'static str],
    ) -> Self {
        Self {
            target_filesystem,
            writes,
            activation_gaps,
        }
    }
}

#[derive(Debug)]
pub enum PhaseWriteError {
    ActivationBlocked {
        filesystem: &'static str,
        gaps: &'static [&'static str],
    },
    EmptySet {
        set: &'static str,
    },
    RangeOverflow {
        offset: u64,
        length: u64,
    },
    StagingReservationMissing {
        offset: u64,
    },
    StagingReservationAmbiguous {
        offset: u64,
    },
    InvalidStagingReservation {
        offset: u64,
        kind: ReservationKind,
    },
    BootReservationMissing {
        set: &'static str,
        offset: u64,
    },
    Preimage(PreimageError),
}

impl fmt::Display for PhaseWriteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ActivationBlocked { filesystem, gaps } => write!(
                formatter,
                "{filesystem} serializer is not activation-ready; {} preservation gaps remain",
                gaps.len()
            ),
            Self::EmptySet { set } => write!(formatter, "serializer phase {set} is empty"),
            Self::RangeOverflow { offset, length } => {
                write!(formatter, "serializer range {offset}+{length} overflows")
            }
            Self::StagingReservationMissing { offset } => {
                write!(
                    formatter,
                    "staging write at {offset} has no containing reservation"
                )
            }
            Self::StagingReservationAmbiguous { offset } => write!(
                formatter,
                "staging write at {offset} is contained by multiple reservations"
            ),
            Self::InvalidStagingReservation { offset, kind } => write!(
                formatter,
                "staging write at {offset} cannot use {kind:?} reservation"
            ),
            Self::BootReservationMissing { set, offset } => write!(
                formatter,
                "{set} boot write at {offset} has no containing BootRegion reservation"
            ),
            Self::Preimage(source) => write!(formatter, "phase preimage capture failed: {source}"),
        }
    }
}

impl std::error::Error for PhaseWriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Preimage(source) => Some(source),
            _ => None,
        }
    }
}

impl From<PreimageError> for PhaseWriteError {
    fn from(source: PreimageError) -> Self {
        Self::Preimage(source)
    }
}

/// Produces coordinator-ready writes and exact before-images from pure serializer output.
///
/// The backup and activation writes must each fit a `BootRegion` reservation. Every staging write
/// must fit exactly one non-boot, non-capsule reservation. The function reads but never mutates the
/// supplied regular image.
///
/// # Errors
///
/// Refuses empty phases, overflowing or unreserved ranges, ambiguous reservation ownership,
/// invalid phase kinds, preimage resource-cap exhaustion, I/O failure, or source identity change.
fn prepare_phase_writes(
    image: &ImageFile,
    reservations: &[DestinationReservation],
    staging: &[OverlayWrite],
    backup_boot: &OverlayWrite,
    activation: &OverlayWrite,
    limits: PreimageLimits,
) -> Result<OpaqueWriteSets, PhaseWriteError> {
    if staging.is_empty() {
        return Err(PhaseWriteError::EmptySet { set: "staging" });
    }
    if backup_boot.bytes.is_empty() {
        return Err(PhaseWriteError::EmptySet { set: "backup_boot" });
    }
    if activation.bytes.is_empty() {
        return Err(PhaseWriteError::EmptySet { set: "activation" });
    }
    validate_aggregate_limits(staging, backup_boot, activation, limits)?;

    let mut target_staging = Vec::new();
    target_staging
        .try_reserve_exact(staging.len())
        .map_err(|_| PhaseWriteError::Preimage(PreimageError::AllocationFailed))?;
    for write in staging {
        let reservation = containing_reservations(write, reservations)?.ok_or(
            PhaseWriteError::StagingReservationMissing {
                offset: write.offset,
            },
        )?;
        if matches!(
            reservation.kind,
            ReservationKind::BootRegion | ReservationKind::Capsule
        ) {
            return Err(PhaseWriteError::InvalidStagingReservation {
                offset: write.offset,
                kind: reservation.kind,
            });
        }
        target_staging.push(ReservedWrite {
            reservation_kind: reservation.kind,
            write: write.clone(),
        });
    }

    require_boot_reservation("backup_boot", backup_boot, reservations)?;
    require_boot_reservation("activation", activation, reservations)?;
    let target_staging_rollback = capture_before_images(image, staging, limits)?;
    let backup_boot_rollback =
        capture_before_images(image, std::slice::from_ref(backup_boot), limits)?;
    let activation_rollback =
        capture_before_images(image, std::slice::from_ref(activation), limits)?;

    Ok(OpaqueWriteSets {
        target_staging,
        backup_boot: vec![ReservedWrite {
            reservation_kind: ReservationKind::BootRegion,
            write: backup_boot.clone(),
        }],
        activation: vec![ReservedWrite {
            reservation_kind: ReservationKind::BootRegion,
            write: activation.clone(),
        }],
        target_staging_rollback,
        backup_boot_rollback,
        activation_rollback,
    })
}

/// Converts an activation-ready exFAT serializer plan into coordinator phase writes.
///
/// # Errors
///
/// Refuses plans with declared preservation gaps and all errors documented by the internal phase
/// classifier and preimage collector.
pub fn prepare_exfat_phase_writes(
    image: &ImageFile,
    plan: &ExfatSerializationPlan,
    limits: PreimageLimits,
) -> Result<ActivationAuthorizedWrites, PhaseWriteError> {
    if !plan.activation_ready() {
        return Err(PhaseWriteError::ActivationBlocked {
            filesystem: "exFAT",
            gaps: plan.activation_gaps(),
        });
    }
    Ok(preview_exfat_phase_writes(image, plan, limits)?.authorize())
}

/// Captures and classifies all exFAT forward and rollback bytes without authorizing activation.
///
/// # Errors
///
/// Returns every range, reservation, cap, identity, and I/O error documented by the internal
/// classifier. Remaining serializer gaps are reported in the returned preview.
pub fn preview_exfat_phase_writes(
    image: &ImageFile,
    plan: &ExfatSerializationPlan,
    limits: PreimageLimits,
) -> Result<PhaseWritePreview, PhaseWriteError> {
    let staging: Vec<_> = plan.staging_writes().cloned().collect();
    let writes = prepare_phase_writes(
        image,
        &plan.reservations,
        &staging,
        plan.backup_boot_write(),
        plan.primary_boot_write(),
        limits,
    )?;
    Ok(PhaseWritePreview {
        target_filesystem: FileSystem::ExFat,
        writes,
        activation_gaps: plan.activation_gaps(),
    })
}

/// Converts an activation-ready NTFS serializer plan into coordinator phase writes.
///
/// # Errors
///
/// Refuses structural-draft plans with mandatory metadata gaps and all phase/preimage failures.
pub fn prepare_ntfs_phase_writes(
    image: &ImageFile,
    plan: &NtfsDestinationPlan,
    limits: PreimageLimits,
) -> Result<ActivationAuthorizedWrites, PhaseWriteError> {
    if !plan.activation_ready() {
        return Err(PhaseWriteError::ActivationBlocked {
            filesystem: "NTFS",
            gaps: plan.activation_gaps(),
        });
    }
    Ok(preview_ntfs_phase_writes(image, plan, limits)?.authorize())
}

/// Captures and classifies all NTFS forward and rollback bytes without authorizing activation.
///
/// # Errors
///
/// Returns every range, reservation, cap, identity, and I/O error documented by the internal
/// classifier. Remaining serializer gaps are reported in the returned preview.
pub fn preview_ntfs_phase_writes(
    image: &ImageFile,
    plan: &NtfsDestinationPlan,
    limits: PreimageLimits,
) -> Result<PhaseWritePreview, PhaseWriteError> {
    let writes = prepare_phase_writes(
        image,
        &plan.reservations,
        &plan.staging_writes,
        &plan.backup_boot_write,
        &plan.primary_boot_write,
        limits,
    )?;
    Ok(PhaseWritePreview {
        target_filesystem: FileSystem::Ntfs,
        writes,
        activation_gaps: plan.activation_gaps(),
    })
}

fn validate_aggregate_limits(
    staging: &[OverlayWrite],
    backup_boot: &OverlayWrite,
    activation: &OverlayWrite,
    limits: PreimageLimits,
) -> Result<(), PhaseWriteError> {
    let count = staging
        .len()
        .checked_add(2)
        .ok_or(PhaseWriteError::Preimage(
            PreimageError::WriteLimitExceeded {
                actual: usize::MAX,
                maximum: limits.max_writes,
            },
        ))?;
    if count > limits.max_writes {
        return Err(PhaseWriteError::Preimage(
            PreimageError::WriteLimitExceeded {
                actual: count,
                maximum: limits.max_writes,
            },
        ));
    }
    let bytes = staging
        .iter()
        .chain([backup_boot, activation])
        .try_fold(0_u64, |sum, write| {
            sum.checked_add(u64::try_from(write.bytes.len()).ok()?)
        })
        .ok_or(PhaseWriteError::Preimage(
            PreimageError::ByteLimitExceeded {
                actual: u64::MAX,
                maximum: limits.max_total_bytes,
            },
        ))?;
    if bytes > u64::try_from(limits.max_total_bytes).unwrap_or(u64::MAX) {
        return Err(PhaseWriteError::Preimage(
            PreimageError::ByteLimitExceeded {
                actual: bytes,
                maximum: limits.max_total_bytes,
            },
        ));
    }
    Ok(())
}

fn containing_reservations<'a>(
    write: &OverlayWrite,
    reservations: &'a [DestinationReservation],
) -> Result<Option<&'a DestinationReservation>, PhaseWriteError> {
    let write_end = range_end(write.offset, write.bytes.len())?;
    let mut found = None;
    for reservation in reservations {
        if reservation.range.offset <= write.offset
            && reservation
                .range
                .offset
                .checked_add(reservation.range.length)
                .is_some_and(|end| write_end <= end)
        {
            if found.is_some() {
                return Err(PhaseWriteError::StagingReservationAmbiguous {
                    offset: write.offset,
                });
            }
            found = Some(reservation);
        }
    }
    Ok(found)
}

fn require_boot_reservation(
    set: &'static str,
    write: &OverlayWrite,
    reservations: &[DestinationReservation],
) -> Result<(), PhaseWriteError> {
    let contained = containing_reservations(write, reservations)?
        .is_some_and(|reservation| reservation.kind == ReservationKind::BootRegion);
    if contained {
        Ok(())
    } else {
        Err(PhaseWriteError::BootReservationMissing {
            set,
            offset: write.offset,
        })
    }
}

fn range_end(offset: u64, length: usize) -> Result<u64, PhaseWriteError> {
    let length = u64::try_from(length).map_err(|_| PhaseWriteError::RangeOverflow {
        offset,
        length: u64::MAX,
    })?;
    offset
        .checked_add(length)
        .ok_or(PhaseWriteError::RangeOverflow { offset, length })
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::io::Write;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::geometry::ByteRange;

    fn image_path() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("starconverter-phases-{nonce}.img"))
    }

    fn write(offset: u64, byte: u8) -> OverlayWrite {
        OverlayWrite {
            offset,
            bytes: vec![byte; 512],
        }
    }

    #[test]
    fn classifies_phases_and_captures_exact_regular_image_bytes() {
        let path = image_path();
        let original: Vec<u8> = (0_u8..=255).cycle().take(4096).collect();
        File::create(&path).unwrap().write_all(&original).unwrap();
        let image = ImageFile::open_with_limit(&path, 128).unwrap();
        let reservations = [
            DestinationReservation {
                range: ByteRange {
                    offset: 0,
                    length: 1024,
                },
                kind: ReservationKind::BootRegion,
            },
            DestinationReservation {
                range: ByteRange {
                    offset: 2048,
                    length: 512,
                },
                kind: ReservationKind::AllocationMetadata,
            },
        ];
        let staging = [write(2048, 1)];
        let backup = write(512, 2);
        let activation = write(0, 3);
        let phases = prepare_phase_writes(
            &image,
            &reservations,
            &staging,
            &backup,
            &activation,
            PreimageLimits::default(),
        )
        .unwrap();
        assert_eq!(
            phases.target_staging[0].reservation_kind,
            ReservationKind::AllocationMetadata
        );
        assert_eq!(
            phases.target_staging_rollback[0].bytes,
            original[2048..2560]
        );
        assert_eq!(phases.backup_boot_rollback[0].bytes, original[512..1024]);
        assert_eq!(phases.activation_rollback[0].bytes, original[..512]);
        assert_eq!(fs::read(&path).unwrap(), original);
        drop(image);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn refuses_missing_ambiguous_and_wrong_phase_reservations() {
        let path = image_path();
        File::create(&path)
            .unwrap()
            .write_all(&[0_u8; 4096])
            .unwrap();
        let image = ImageFile::open(&path).unwrap();
        let boot = DestinationReservation {
            range: ByteRange {
                offset: 0,
                length: 1024,
            },
            kind: ReservationKind::BootRegion,
        };
        assert!(matches!(
            prepare_phase_writes(
                &image,
                &[boot],
                &[write(2048, 1)],
                &write(512, 2),
                &write(0, 3),
                PreimageLimits::default()
            ),
            Err(PhaseWriteError::StagingReservationMissing { .. })
        ));
        assert!(matches!(
            prepare_phase_writes(
                &image,
                &[boot],
                &[write(0, 1)],
                &write(512, 2),
                &write(0, 3),
                PreimageLimits::default()
            ),
            Err(PhaseWriteError::InvalidStagingReservation { .. })
        ));
        drop(image);
        fs::remove_file(path).unwrap();
    }
}
