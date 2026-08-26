//! Filesystem inspection, copy-based candidate export, and safety vocabulary for `StarConverter`.
//!
//! The crate intentionally contains no raw-device API. Source image access is read-only. The
//! copy-based exporter can create one new regular target file, while the separate in-place executor
//! remains unreachable without opaque activation authorization.

pub mod candidate_export;
pub mod capsule;
mod capsule_fault;
pub mod capsule_store;
pub mod conversion;
pub mod cross_format;
pub mod executor;
pub mod extent;
pub mod fs;
pub mod geometry;
pub mod image;
pub mod inspect;
pub mod object;
pub mod overlay;
pub mod phase;
pub mod preimage;
pub mod preservation;
pub mod recovery;
mod source_view;
pub mod validation_vhd;
pub mod verify;
pub mod windows_validation;

use std::fmt;
use std::str::FromStr;

const MIB: u64 = 1024 * 1024;

/// Filesystems supported by the initial product contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileSystem {
    ExFat,
    Ntfs,
    Unknown,
}

impl fmt::Display for FileSystem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ExFat => "exFAT",
            Self::Ntfs => "NTFS",
            Self::Unknown => "unknown",
        })
    }
}

impl FromStr for FileSystem {
    type Err = ParseValueError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "exfat" => Ok(Self::ExFat),
            "ntfs" => Ok(Self::Ntfs),
            _ => Err(ParseValueError::new("filesystem", value)),
        }
    }
}

/// User-selected definition of preservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuaranteeMode {
    Strict,
    Escrow,
    ContentOnly,
}

impl fmt::Display for GuaranteeMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Strict => "strict",
            Self::Escrow => "escrow",
            Self::ContentOnly => "content-only",
        })
    }
}

impl FromStr for GuaranteeMode {
    type Err = ParseValueError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "strict" => Ok(Self::Strict),
            "escrow" => Ok(Self::Escrow),
            "content-only" | "content" => Ok(Self::ContentOnly),
            _ => Err(ParseValueError::new("guarantee mode", value)),
        }
    }
}

/// Source semantics that can affect whether NTFS -> exFAT is reversible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticFeature {
    AccessControl,
    AlternateDataStreams,
    Compression,
    EncryptedFiles,
    HardLinks,
    ReparsePoints,
    SparseFiles,
    CaseCollisions,
}

impl SemanticFeature {
    /// Human-readable label used by both frontends.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::AccessControl => "ACLs or ownership",
            Self::AlternateDataStreams => "alternate data streams",
            Self::Compression => "NTFS compression",
            Self::EncryptedFiles => "EFS encrypted files",
            Self::HardLinks => "hard-link groups",
            Self::ReparsePoints => "reparse points or symlinks",
            Self::SparseFiles => "sparse files",
            Self::CaseCollisions => "case-colliding names",
        }
    }

    const fn escrow_supported(self) -> bool {
        !matches!(self, Self::EncryptedFiles)
    }
}

/// Read-only facts discovered about an image or volume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeProfile {
    pub display_name: String,
    pub stable_id: String,
    pub filesystem: FileSystem,
    pub capacity_bytes: u64,
    /// Proven free bytes from allocation metadata. `None` means discovery has not established it.
    pub free_bytes: Option<u64>,
    pub logical_sector_bytes: u32,
    pub cluster_bytes: u32,
    pub state: VolumeState,
    pub role: VolumeRole,
    pub features: Vec<SemanticFeature>,
    /// Whether all allocation and object metadata needed for safe planning was scanned.
    pub inventory_complete: bool,
}

/// Mutability-relevant state observed during discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VolumeState {
    pub health: HealthState,
    pub access: AccessState,
}

/// Filesystem consistency state backed by inspection evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthState {
    Clean,
    Dirty,
    Unknown,
}

/// Whether mutation can safely assume exclusive offline access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessState {
    Offline,
    Mounted,
    Unknown,
}

/// Topology roles that remain outside the initial support envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VolumeRole {
    pub system_volume: bool,
    pub encrypted_container: bool,
}

impl VolumeProfile {
    /// Safe synthetic profile used by the scaffold UI and CLI.
    #[must_use]
    pub fn demo_exfat() -> Self {
        Self {
            display_name: "DEMO_ARCHIVE".into(),
            stable_id: "image://demo-archive.exfat".into(),
            filesystem: FileSystem::ExFat,
            capacity_bytes: 64 * 1024 * MIB,
            free_bytes: Some(21 * 1024 * MIB),
            logical_sector_bytes: 512,
            cluster_bytes: 128 * 1024,
            state: VolumeState {
                health: HealthState::Clean,
                access: AccessState::Offline,
            },
            role: VolumeRole {
                system_volume: false,
                encrypted_container: false,
            },
            features: Vec::new(),
            inventory_complete: true,
        }
    }
}

/// Severity of a preflight observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Info,
    Warning,
    Blocker,
}

impl Severity {
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Info => "READY",
            Self::Warning => "WARN",
            Self::Blocker => "BLOCKED",
        }
    }
}

/// One specific preflight observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanIssue {
    pub severity: Severity,
    pub code: &'static str,
    pub message: String,
}

/// Ordered high-level conversion phase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedPhase {
    pub number: u8,
    pub name: &'static str,
    pub summary: &'static str,
}

/// Deterministic output from read-only preflight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversionPlan {
    pub source: VolumeProfile,
    pub target: FileSystem,
    pub mode: GuaranteeMode,
    pub metadata_reserve_bytes: u64,
    pub escrow_reserve_bytes: u64,
    pub required_temporary_bytes: u64,
    pub issues: Vec<PlanIssue>,
    pub phases: Vec<PlannedPhase>,
}

impl ConversionPlan {
    #[must_use]
    pub fn is_ready(&self) -> bool {
        !self
            .issues
            .iter()
            .any(|issue| issue.severity == Severity::Blocker)
    }

    #[must_use]
    pub fn blocker_count(&self) -> usize {
        self.issues
            .iter()
            .filter(|issue| issue.severity == Severity::Blocker)
            .count()
    }

    #[must_use]
    pub fn warning_count(&self) -> usize {
        self.issues
            .iter()
            .filter(|issue| issue.severity == Severity::Warning)
            .count()
    }
}

/// Stateless conversion planner.
#[derive(Debug, Default)]
pub struct Planner;

impl Planner {
    #[must_use]
    pub fn plan(
        &self,
        source: &VolumeProfile,
        target: FileSystem,
        mode: GuaranteeMode,
    ) -> ConversionPlan {
        let mut issues = Vec::new();
        validate_source(source, target, &mut issues);
        let escrow_reserve_bytes = classify_semantics(source, target, mode, &mut issues);

        let metadata_reserve_bytes = (source.capacity_bytes / 100).max(256 * MIB);
        let required_temporary_bytes = metadata_reserve_bytes.saturating_add(escrow_reserve_bytes);
        match source.free_bytes {
            Some(free_bytes) if required_temporary_bytes > free_bytes => blocker(
                &mut issues,
                "space.insufficient",
                format!(
                    "The preliminary plan needs {} MiB, but only {} MiB is free.",
                    required_temporary_bytes / MIB,
                    free_bytes / MIB
                ),
            ),
            None => blocker(
                &mut issues,
                "space.unknown",
                "Free space has not been proven from allocation metadata.",
            ),
            Some(_) => {}
        }

        if issues.is_empty() {
            info(
                &mut issues,
                "preflight.ready",
                "The supplied evidence satisfies the current preflight policy.",
            );
        }

        ConversionPlan {
            source: source.clone(),
            target,
            mode,
            metadata_reserve_bytes,
            escrow_reserve_bytes,
            required_temporary_bytes,
            issues,
            phases: default_phases(),
        }
    }
}

fn validate_source(source: &VolumeProfile, target: FileSystem, issues: &mut Vec<PlanIssue>) {
    validate_identity_and_format(source, target, issues);
    validate_state(source, issues);
    validate_geometry(source, issues);
}

fn validate_identity_and_format(
    source: &VolumeProfile,
    target: FileSystem,
    issues: &mut Vec<PlanIssue>,
) {
    if source.stable_id.trim().is_empty() {
        blocker(
            issues,
            "identity.missing",
            "The source does not have a stable identity.",
        );
    }
    if source.filesystem == FileSystem::Unknown {
        blocker(
            issues,
            "source.unsupported",
            "The source filesystem is not recognized as exFAT or NTFS.",
        );
    }
    if target == FileSystem::Unknown {
        blocker(
            issues,
            "target.unsupported",
            "The target filesystem must be exFAT or NTFS.",
        );
    }
    if source.filesystem == target {
        blocker(
            issues,
            "direction.same-filesystem",
            format!("The source already uses {target}."),
        );
    }
    if !source.inventory_complete {
        blocker(
            issues,
            "inventory.incomplete",
            "Allocation and object metadata have not been completely scanned.",
        );
    }
}

fn validate_state(source: &VolumeProfile, issues: &mut Vec<PlanIssue>) {
    match source.state.health {
        HealthState::Dirty => blocker(
            issues,
            "health.dirty",
            "The source is dirty. Repair it with the operating-system filesystem checker and analyze again.",
        ),
        HealthState::Unknown => blocker(
            issues,
            "health.unknown",
            "Filesystem cleanliness has not been proven from authoritative metadata.",
        ),
        HealthState::Clean => {}
    }
    match source.state.access {
        AccessState::Mounted => blocker(
            issues,
            "access.mounted",
            "The source is mounted. Conversion requires an offline, exclusively locked source.",
        ),
        AccessState::Unknown => blocker(
            issues,
            "access.unknown",
            "Exclusive offline access has not been proven.",
        ),
        AccessState::Offline => {}
    }
    if source.role.system_volume {
        blocker(
            issues,
            "topology.system-volume",
            "System, boot, paging, hibernation, and crash-dump volumes are outside the support envelope.",
        );
    }
    if source.role.encrypted_container {
        blocker(
            issues,
            "topology.encrypted-container",
            "Encrypted containers must be decrypted outside StarConverter before planning.",
        );
    }
}

fn validate_geometry(source: &VolumeProfile, issues: &mut Vec<PlanIssue>) {
    if !matches!(source.logical_sector_bytes, 512 | 4096) {
        blocker(
            issues,
            "geometry.sector-size",
            format!(
                "Logical sector size {} is outside the initial 512/4096-byte support set.",
                source.logical_sector_bytes
            ),
        );
    }
    if source.capacity_bytes == 0 {
        blocker(
            issues,
            "geometry.empty",
            "The source reports zero capacity.",
        );
    }
    if source
        .free_bytes
        .is_some_and(|free_bytes| free_bytes > source.capacity_bytes)
    {
        blocker(
            issues,
            "space.invalid",
            "Proven free space exceeds the source capacity.",
        );
    }
    if source.cluster_bytes == 0
        || !source.cluster_bytes.is_power_of_two()
        || source.cluster_bytes < source.logical_sector_bytes
        || source.cluster_bytes % source.logical_sector_bytes != 0
    {
        blocker(
            issues,
            "geometry.cluster-size",
            "Cluster size must be a non-zero power-of-two multiple of the logical sector size.",
        );
    }
}

fn classify_semantics(
    source: &VolumeProfile,
    target: FileSystem,
    mode: GuaranteeMode,
    issues: &mut Vec<PlanIssue>,
) -> u64 {
    if source.filesystem != FileSystem::Ntfs || target != FileSystem::ExFat {
        return 0;
    }

    let mut escrow_reserve_bytes: u64 = 0;
    for feature in &source.features {
        match mode {
            GuaranteeMode::Strict => blocker(
                issues,
                "semantics.not-native",
                format!("Strict mode cannot represent {} on exFAT.", feature.label()),
            ),
            GuaranteeMode::Escrow if feature.escrow_supported() => {
                warning(
                    issues,
                    "semantics.escrow",
                    format!("{} will require round-trip escrow.", feature.label()),
                );
                escrow_reserve_bytes = escrow_reserve_bytes.saturating_add(16 * MIB);
            }
            GuaranteeMode::Escrow => blocker(
                issues,
                "semantics.escrow-unsupported",
                format!(
                    "{} is not supported by the initial escrow contract.",
                    feature.label()
                ),
            ),
            GuaranteeMode::ContentOnly => warning(
                issues,
                "semantics.content-only",
                format!("Content-only mode will not round-trip {}.", feature.label()),
            ),
        }
    }
    escrow_reserve_bytes
}

fn default_phases() -> Vec<PlannedPhase> {
    vec![
        PlannedPhase {
            number: 1,
            name: "DISCOVER",
            summary: "Read and hash source metadata without mutation.",
        },
        PlannedPhase {
            number: 2,
            name: "RESERVE",
            summary: "Reserve target metadata, scratch, and rollback extents.",
        },
        PlannedPhase {
            number: 3,
            name: "RELOCATE",
            summary: "Move only extents that conflict with the target layout.",
        },
        PlannedPhase {
            number: 4,
            name: "STAGE",
            summary: "Build inactive target metadata and transaction records.",
        },
        PlannedPhase {
            number: 5,
            name: "VERIFY",
            summary: "Validate the candidate filesystem through an overlay view.",
        },
        PlannedPhase {
            number: 6,
            name: "ACTIVATE",
            summary: "Write backup boot data, flush, then activate the primary boot record.",
        },
        PlannedPhase {
            number: 7,
            name: "VALIDATE",
            summary: "Mount read-only and verify structure and content.",
        },
        PlannedPhase {
            number: 8,
            name: "FINALIZE",
            summary: "Release rollback material only after explicit confirmation.",
        },
    ]
}

fn info(issues: &mut Vec<PlanIssue>, code: &'static str, message: impl Into<String>) {
    issues.push(PlanIssue {
        severity: Severity::Info,
        code,
        message: message.into(),
    });
}

fn warning(issues: &mut Vec<PlanIssue>, code: &'static str, message: impl Into<String>) {
    issues.push(PlanIssue {
        severity: Severity::Warning,
        code,
        message: message.into(),
    });
}

fn blocker(issues: &mut Vec<PlanIssue>, code: &'static str, message: impl Into<String>) {
    issues.push(PlanIssue {
        severity: Severity::Blocker,
        code,
        message: message.into(),
    });
}

/// Error returned when a CLI-facing enum cannot be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseValueError {
    kind: &'static str,
    value: String,
}

impl ParseValueError {
    fn new(kind: &'static str, value: &str) -> Self {
        Self {
            kind,
            value: value.into(),
        }
    }
}

impl fmt::Display for ParseValueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid {}: {}", self.kind, self.value)
    }
}

impl std::error::Error for ParseValueError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_demo_exfat_can_plan_strict_ntfs() {
        let plan = Planner.plan(
            &VolumeProfile::demo_exfat(),
            FileSystem::Ntfs,
            GuaranteeMode::Strict,
        );

        assert!(plan.is_ready());
        assert_eq!(plan.blocker_count(), 0);
        assert_eq!(plan.phases.len(), 8);
    }

    #[test]
    fn strict_ntfs_to_exfat_refuses_alternate_streams() {
        let mut source = VolumeProfile::demo_exfat();
        source.filesystem = FileSystem::Ntfs;
        source.features = vec![SemanticFeature::AlternateDataStreams];

        let plan = Planner.plan(&source, FileSystem::ExFat, GuaranteeMode::Strict);

        assert!(!plan.is_ready());
        assert_eq!(plan.blocker_count(), 1);
        assert_eq!(plan.issues[0].code, "semantics.not-native");
    }

    #[test]
    fn escrow_accounts_for_supported_semantics() {
        let mut source = VolumeProfile::demo_exfat();
        source.filesystem = FileSystem::Ntfs;
        source.features = vec![
            SemanticFeature::AccessControl,
            SemanticFeature::AlternateDataStreams,
        ];

        let plan = Planner.plan(&source, FileSystem::ExFat, GuaranteeMode::Escrow);

        assert!(plan.is_ready());
        assert_eq!(plan.warning_count(), 2);
        assert_eq!(plan.escrow_reserve_bytes, 32 * MIB);
    }

    #[test]
    fn dirty_source_is_always_blocked() {
        let mut source = VolumeProfile::demo_exfat();
        source.state.health = HealthState::Dirty;

        let plan = Planner.plan(&source, FileSystem::Ntfs, GuaranteeMode::ContentOnly);

        assert!(!plan.is_ready());
        assert!(plan.issues.iter().any(|issue| issue.code == "health.dirty"));
    }

    #[test]
    fn unknown_free_space_is_never_ready() {
        let mut source = VolumeProfile::demo_exfat();
        source.free_bytes = None;

        let plan = Planner.plan(&source, FileSystem::Ntfs, GuaranteeMode::Strict);

        assert!(!plan.is_ready());
        assert!(
            plan.issues
                .iter()
                .any(|issue| issue.code == "space.unknown")
        );
    }

    #[test]
    fn unknown_health_and_access_are_never_ready() {
        let mut source = VolumeProfile::demo_exfat();
        source.state.health = HealthState::Unknown;
        source.state.access = AccessState::Unknown;

        let plan = Planner.plan(&source, FileSystem::Ntfs, GuaranteeMode::Strict);

        assert!(!plan.is_ready());
        assert!(
            plan.issues
                .iter()
                .any(|issue| issue.code == "health.unknown")
        );
        assert!(
            plan.issues
                .iter()
                .any(|issue| issue.code == "access.unknown")
        );
    }

    #[test]
    fn contradictory_capacity_evidence_is_blocked() {
        let mut source = VolumeProfile::demo_exfat();
        source.free_bytes = Some(source.capacity_bytes + 1);
        source.cluster_bytes = 256;

        let plan = Planner.plan(&source, FileSystem::Ntfs, GuaranteeMode::Strict);

        assert!(!plan.is_ready());
        assert!(
            plan.issues
                .iter()
                .any(|issue| issue.code == "space.invalid")
        );
        assert!(
            plan.issues
                .iter()
                .any(|issue| issue.code == "geometry.cluster-size")
        );
    }

    #[test]
    fn incomplete_object_inventory_is_never_ready() {
        let mut source = VolumeProfile::demo_exfat();
        source.inventory_complete = false;

        let plan = Planner.plan(&source, FileSystem::Ntfs, GuaranteeMode::Strict);

        assert!(!plan.is_ready());
        assert!(
            plan.issues
                .iter()
                .any(|issue| issue.code == "inventory.incomplete")
        );
    }
}
