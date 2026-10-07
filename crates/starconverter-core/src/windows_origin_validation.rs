//! Strict parser for schema-v1 Windows-origin validation reports.
//!
//! Reports are emitted by `scripts/validate-windows-origin.ps1`, which formats and populates
//! volumes with Windows itself, converts them with the CLI, and asks `ntfs.sys` / `exfat.sys`
//! whether the candidates and escrow-restored round trips serve the same payloads and NTFS
//! security descriptors. Windows chooses serials, GUIDs, and descriptor layouts at run time, so
//! nothing here is pinned by VHD hash; the parser checks the invariants the harness promises
//! instead: the four fixed case identities, the exact payload corpus, read-only letterless
//! attachment, unchanged candidate bytes, clean CHKDSK, and the descriptor set an NTFS round trip
//! must carry.
//!
//! Like [`crate::windows_validation`], this module parses bytes only. It never opens a reported
//! path, attaches a VHD, or accesses a device, and a successful parse is unkeyed evidence rather
//! than authentication or activation authority.

use sha2::{Digest, Sha256};

use crate::FileSystem;
use crate::windows_validation::{
    WindowsValidationError, WindowsValidationLimits, check_array, check_nonempty_string,
    check_string, decode_sha256, valid_local_vhd_path, valid_roundtrip_utc, valid_volume_guid_path,
    validate_transcript,
};

use serde::Deserialize;

const SCHEMA: &str = "starconverter.windows-origin-validation";
const VERSION: u64 = 1;
/// Exact regular-file length of every 40 MiB fixed VHD the harness builds (disk bytes + footer).
pub const ORIGIN_VHD_BYTES: u64 = 40 * 1024 * 1024 + 512;
const PARTITION_OFFSET_BYTES: u64 = 1024 * 1024;
/// Number of cases a schema-v1 report must carry.
const CASE_COUNT: usize = 4;

/// Windows-formatted NTFS converted to exFAT.
pub const NTFS_FORWARD_CASE_NAME: &str = "Windows NTFS to exFAT";
/// The exFAT candidate above converted back to NTFS with escrow restore.
pub const NTFS_ROUND_TRIP_CASE_NAME: &str = "Windows NTFS round trip";
/// Windows-formatted exFAT converted to NTFS.
pub const EXFAT_FORWARD_CASE_NAME: &str = "Windows exFAT to NTFS";
/// The NTFS candidate above converted back to exFAT with escrow restore.
pub const EXFAT_ROUND_TRIP_CASE_NAME: &str = "Windows exFAT round trip";

/// Directory whose NTFS descriptor carries an explicit Guests deny ACE.
///
/// Its descriptor and that of `secured\denied.bin` are allocated by `ntfs.sys` at run time
/// rather than written by `format`, so the round trip must carry descriptors `$Secure` learned
/// after formatting.
pub const SECURED_DIRECTORY_PATH: &str = "secured";
/// SDDL abbreviation of the Guests group (`S-1-5-32-546`) the deny ACEs name.
const GUESTS_SDDL_SID: &str = "BG";

/// Payload corpus written to every source volume: relative path, length, and stream seed. Bytes
/// are `(seed + offset) % 251`, matching `$payloadSpecs` in the harness.
const PAYLOAD_SPECS: [(&str, u64, u8); 9] = [
    ("readme.txt", 14, 1),
    ("alpha\\empty.dat", 0, 2),
    ("alpha\\Ωmega\\fragmented.bin", 6000, 3),
    ("alpha\\Ωmega\\sector.bin", 4096, 4),
    ("alpha\\Ωmega\\cluster-plus-one.bin", 4097, 5),
    ("deep\\深度\\two-cluster-minus-one.bin", 8191, 6),
    ("deep\\深度\\rocket-🚀.bin", 33, 7),
    ("Straße.txt", 65, 8),
    ("secured\\denied.bin", 512, 9),
];

/// Opaque, non-authorizing evidence from a strictly validated Windows-origin report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsOriginValidationEvidence {
    generated_utc: String,
    windows_version: String,
    powershell_version: String,
    chkdsk_version: String,
    ntfs_driver_version: String,
    exfat_driver_version: String,
    cases: Vec<WindowsOriginCaseEvidence>,
}

impl WindowsOriginValidationEvidence {
    #[must_use]
    pub fn generated_utc(&self) -> &str {
        &self.generated_utc
    }

    #[must_use]
    pub fn windows_version(&self) -> &str {
        &self.windows_version
    }

    #[must_use]
    pub fn powershell_version(&self) -> &str {
        &self.powershell_version
    }

    #[must_use]
    pub fn chkdsk_version(&self) -> &str {
        &self.chkdsk_version
    }

    #[must_use]
    pub fn ntfs_driver_version(&self) -> &str {
        &self.ntfs_driver_version
    }

    #[must_use]
    pub fn exfat_driver_version(&self) -> &str {
        &self.exfat_driver_version
    }

    #[must_use]
    pub fn cases(&self) -> &[WindowsOriginCaseEvidence] {
        &self.cases
    }
}

/// One conversion judged by the Windows drivers, starting from a Windows-formatted source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsOriginCaseEvidence {
    name: String,
    origin: FileSystem,
    restore_escrow: bool,
    source_vhd_path: String,
    source_vhd_sha256: [u8; 32],
    source_image_sha256: [u8; 32],
    candidate: WindowsOriginCandidateEvidence,
}

impl WindowsOriginCaseEvidence {
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn origin(&self) -> FileSystem {
        self.origin
    }

    /// Whether the conversion replayed the forward escrow so the candidate carries the source
    /// identities (only the NTFS round trip; exFAT-direction restore does not exist yet).
    #[must_use]
    pub const fn restore_escrow(&self) -> bool {
        self.restore_escrow
    }

    #[must_use]
    pub fn source_vhd_path(&self) -> &str {
        &self.source_vhd_path
    }

    #[must_use]
    pub const fn source_vhd_sha256(&self) -> &[u8; 32] {
        &self.source_vhd_sha256
    }

    #[must_use]
    pub const fn source_image_sha256(&self) -> &[u8; 32] {
        &self.source_image_sha256
    }

    #[must_use]
    pub const fn candidate(&self) -> &WindowsOriginCandidateEvidence {
        &self.candidate
    }
}

/// The converted VHD as the Windows driver observed it read-only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsOriginCandidateEvidence {
    filesystem: FileSystem,
    vhd_path: String,
    vhd_bytes: u64,
    sha256: [u8; 32],
    partition_offset_bytes: u64,
    partition_bytes: u64,
    volume_guid_path: String,
    payloads: Vec<WindowsOriginPayloadEvidence>,
    security: Vec<WindowsOriginSecurityEvidence>,
    chkdsk_exit_code: i64,
    chkdsk_output: Vec<String>,
}

impl WindowsOriginCandidateEvidence {
    #[must_use]
    pub const fn filesystem(&self) -> FileSystem {
        self.filesystem
    }

    #[must_use]
    pub fn vhd_path(&self) -> &str {
        &self.vhd_path
    }

    #[must_use]
    pub const fn vhd_bytes(&self) -> u64 {
        self.vhd_bytes
    }

    #[must_use]
    pub const fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }

    #[must_use]
    pub const fn partition_offset_bytes(&self) -> u64 {
        self.partition_offset_bytes
    }

    /// Length of the MBR partition diskpart created, which is also the carved image length.
    #[must_use]
    pub const fn partition_bytes(&self) -> u64 {
        self.partition_bytes
    }

    #[must_use]
    pub fn volume_guid_path(&self) -> &str {
        &self.volume_guid_path
    }

    #[must_use]
    pub fn payloads(&self) -> &[WindowsOriginPayloadEvidence] {
        &self.payloads
    }

    #[must_use]
    pub fn security(&self) -> &[WindowsOriginSecurityEvidence] {
        &self.security
    }

    #[must_use]
    pub const fn chkdsk_exit_code(&self) -> i64 {
        self.chkdsk_exit_code
    }

    #[must_use]
    pub fn chkdsk_output(&self) -> &[String] {
        &self.chkdsk_output
    }
}

/// One corpus payload served by the Windows driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsOriginPayloadEvidence {
    path: String,
    length: u64,
    sha256: [u8; 32],
}

impl WindowsOriginPayloadEvidence {
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub const fn length(&self) -> u64 {
        self.length
    }

    #[must_use]
    pub const fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }
}

/// One NTFS security descriptor, as SDDL, that the driver served identically before and after
/// the round trip. The root is recorded with an empty path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsOriginSecurityEvidence {
    path: String,
    sddl: String,
}

impl WindowsOriginSecurityEvidence {
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub fn sddl(&self) -> &str {
        &self.sddl
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
struct RawReport {
    schema: String,
    version: u64,
    complete: bool,
    generated_utc: String,
    windows_version: String,
    power_shell_version: String,
    chkdsk_version: String,
    ntfs_driver_version: String,
    exfat_driver_version: String,
    cases: Vec<RawCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
struct RawCase {
    name: String,
    origin: String,
    restore_escrow: bool,
    source_vhd_path: String,
    source_vhd_sha256: String,
    source_image_sha256: String,
    candidate: RawCandidate,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
struct RawCandidate {
    file_system: String,
    vhd_path: String,
    vhd_bytes: u64,
    sha256_before: String,
    sha256_after: String,
    read_only_attached: bool,
    no_drive_letter: bool,
    detached_after: bool,
    partition_offset_bytes: u64,
    partition_bytes: u64,
    volume_guid_path: String,
    payloads: Vec<RawPayload>,
    security: Vec<RawSecurity>,
    chkdsk_exit_code: i64,
    chkdsk_output: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
struct RawPayload {
    path: String,
    length: u64,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
struct RawSecurity {
    path: String,
    sddl: String,
}

/// Parses and strictly validates one schema-v1 Windows-origin report without accessing any
/// reported path.
///
/// The returned evidence is unkeyed and non-authorizing; consumers needing provenance or
/// freshness must authenticate the report through a separate trusted channel.
///
/// # Errors
///
/// Refuses zero limits, oversized input or collections, malformed JSON, duplicate/unknown/missing
/// fields, non-v1 schema, incomplete reports, any case set other than the four fixed identities,
/// candidates whose filesystem disagrees with the case direction, source/candidate hash or
/// geometry inconsistencies, non-read-only or lettered attachment, an incomplete or altered
/// payload corpus, a non-zero or silent CHKDSK, and an NTFS round trip that does not carry the
/// full descriptor set including the run-time-allocated Guests deny ACEs.
pub fn verify_windows_origin_validation_report(
    bytes: &[u8],
    limits: WindowsValidationLimits,
) -> Result<WindowsOriginValidationEvidence, WindowsValidationError> {
    validate_limits(limits)?;
    if bytes.len() > limits.max_report_bytes {
        return Err(WindowsValidationError::ReportTooLarge {
            actual: bytes.len(),
            maximum: limits.max_report_bytes,
        });
    }
    let raw: RawReport = serde_json::from_slice(bytes)
        .map_err(|error| WindowsValidationError::MalformedJson(error.to_string()))?;
    if raw.schema != SCHEMA {
        return Err(WindowsValidationError::InvalidEvidence("unexpected schema"));
    }
    if raw.version != VERSION {
        return Err(WindowsValidationError::UnsupportedVersion(raw.version));
    }
    if !raw.complete {
        return Err(WindowsValidationError::Incomplete);
    }
    check_string("GeneratedUtc", &raw.generated_utc, limits)?;
    if !valid_roundtrip_utc(&raw.generated_utc) {
        return Err(WindowsValidationError::InvalidEvidence(
            "GeneratedUtc is not an invariant round-trip UTC timestamp",
        ));
    }
    for (field, value) in [
        ("WindowsVersion", raw.windows_version.as_str()),
        ("PowerShellVersion", raw.power_shell_version.as_str()),
        ("ChkdskVersion", raw.chkdsk_version.as_str()),
        ("NtfsDriverVersion", raw.ntfs_driver_version.as_str()),
        ("ExfatDriverVersion", raw.exfat_driver_version.as_str()),
    ] {
        check_nonempty_string(field, value, limits)?;
    }
    check_array("Cases", raw.cases.len(), limits.max_cases)?;
    if raw.cases.len() != CASE_COUNT {
        return Err(WindowsValidationError::InvalidEvidence(
            "schema v1 requires exactly the four Windows-origin cases",
        ));
    }

    let mut seen = [false; CASE_COUNT];
    let mut cases = Vec::with_capacity(CASE_COUNT);
    for case in raw.cases {
        let identity = case_identity(&case.name)?;
        if seen[identity.index] {
            return Err(WindowsValidationError::InvalidEvidence(
                "duplicate Windows-origin case",
            ));
        }
        seen[identity.index] = true;
        cases.push(validate_case(case, identity, limits)?);
    }
    if seen.iter().any(|seen| !seen) {
        return Err(WindowsValidationError::InvalidEvidence(
            "required Windows-origin case is absent",
        ));
    }
    check_shared_sources(&cases)?;

    Ok(WindowsOriginValidationEvidence {
        generated_utc: raw.generated_utc,
        windows_version: raw.windows_version,
        powershell_version: raw.power_shell_version,
        chkdsk_version: raw.chkdsk_version,
        ntfs_driver_version: raw.ntfs_driver_version,
        exfat_driver_version: raw.exfat_driver_version,
        cases,
    })
}

#[derive(Debug, Clone, Copy)]
struct CaseIdentity {
    index: usize,
    origin: FileSystem,
    candidate: FileSystem,
    /// Only the NTFS round trip replays the forward escrow; exFAT-direction restore does not
    /// exist yet, and forward conversions never restore.
    restores_escrow: bool,
    /// Only an NTFS volume that started as NTFS and had its identities restored can be asked to
    /// serve the same descriptors.
    carries_security: bool,
}

fn case_identity(name: &str) -> Result<CaseIdentity, WindowsValidationError> {
    let identity = match name {
        NTFS_FORWARD_CASE_NAME => CaseIdentity {
            index: 0,
            origin: FileSystem::Ntfs,
            candidate: FileSystem::ExFat,
            restores_escrow: false,
            carries_security: false,
        },
        NTFS_ROUND_TRIP_CASE_NAME => CaseIdentity {
            index: 1,
            origin: FileSystem::Ntfs,
            candidate: FileSystem::Ntfs,
            restores_escrow: true,
            carries_security: true,
        },
        EXFAT_FORWARD_CASE_NAME => CaseIdentity {
            index: 2,
            origin: FileSystem::ExFat,
            candidate: FileSystem::Ntfs,
            restores_escrow: false,
            carries_security: false,
        },
        EXFAT_ROUND_TRIP_CASE_NAME => CaseIdentity {
            index: 3,
            origin: FileSystem::ExFat,
            candidate: FileSystem::ExFat,
            restores_escrow: false,
            carries_security: false,
        },
        _ => {
            return Err(WindowsValidationError::InvalidEvidence(
                "unexpected Windows-origin case",
            ));
        }
    };
    Ok(identity)
}

fn parse_filesystem(value: &str) -> Result<FileSystem, WindowsValidationError> {
    match value {
        "NTFS" => Ok(FileSystem::Ntfs),
        "exFAT" => Ok(FileSystem::ExFat),
        _ => Err(WindowsValidationError::InvalidEvidence(
            "filesystem is neither NTFS nor exFAT",
        )),
    }
}

fn validate_limits(limits: WindowsValidationLimits) -> Result<(), WindowsValidationError> {
    for (field, value) in [
        ("max_report_bytes", limits.max_report_bytes),
        ("max_cases", limits.max_cases),
        ("max_payloads_per_case", limits.max_payloads_per_case),
        (
            "max_transcript_lines_per_case",
            limits.max_transcript_lines_per_case,
        ),
        (
            "max_transcript_bytes_per_case",
            limits.max_transcript_bytes_per_case,
        ),
        ("max_string_bytes", limits.max_string_bytes),
    ] {
        if value == 0 {
            return Err(WindowsValidationError::InvalidLimit(field));
        }
    }
    Ok(())
}

fn validate_case(
    case: RawCase,
    identity: CaseIdentity,
    limits: WindowsValidationLimits,
) -> Result<WindowsOriginCaseEvidence, WindowsValidationError> {
    for (field, value) in [
        ("Case.Origin", case.origin.as_str()),
        ("Case.SourceVhdPath", case.source_vhd_path.as_str()),
        ("Case.SourceVhdSha256", case.source_vhd_sha256.as_str()),
        ("Case.SourceImageSha256", case.source_image_sha256.as_str()),
    ] {
        check_nonempty_string(field, value, limits)?;
    }
    if parse_filesystem(&case.origin)? != identity.origin {
        return Err(WindowsValidationError::InvalidEvidence(
            "case origin does not match its name",
        ));
    }
    if case.restore_escrow != identity.restores_escrow {
        return Err(WindowsValidationError::InvalidEvidence(
            "case escrow restore flag does not match its name",
        ));
    }
    if !valid_local_vhd_path(&case.source_vhd_path) {
        return Err(WindowsValidationError::InvalidEvidence(
            "source VHD path is not a local drive-absolute .vhd path",
        ));
    }
    let source_vhd_sha256 = decode_sha256(&case.source_vhd_sha256)?;
    let source_image_sha256 = decode_sha256(&case.source_image_sha256)?;
    if source_vhd_sha256 == source_image_sha256 {
        return Err(WindowsValidationError::InvalidEvidence(
            "source VHD and carved partition image report the same SHA-256",
        ));
    }
    let candidate = validate_candidate(case.candidate, identity, limits)?;
    if candidate.sha256 == source_vhd_sha256 {
        return Err(WindowsValidationError::InvalidEvidence(
            "candidate VHD is byte-identical to the Windows-formatted source",
        ));
    }
    Ok(WindowsOriginCaseEvidence {
        name: case.name,
        origin: identity.origin,
        restore_escrow: case.restore_escrow,
        source_vhd_path: case.source_vhd_path,
        source_vhd_sha256,
        source_image_sha256,
        candidate,
    })
}

fn validate_candidate(
    candidate: RawCandidate,
    identity: CaseIdentity,
    limits: WindowsValidationLimits,
) -> Result<WindowsOriginCandidateEvidence, WindowsValidationError> {
    for (field, value) in [
        ("Candidate.FileSystem", candidate.file_system.as_str()),
        ("Candidate.VhdPath", candidate.vhd_path.as_str()),
        ("Candidate.Sha256Before", candidate.sha256_before.as_str()),
        ("Candidate.Sha256After", candidate.sha256_after.as_str()),
        (
            "Candidate.VolumeGuidPath",
            candidate.volume_guid_path.as_str(),
        ),
    ] {
        check_nonempty_string(field, value, limits)?;
    }
    if parse_filesystem(&candidate.file_system)? != identity.candidate {
        return Err(WindowsValidationError::InvalidEvidence(
            "candidate filesystem does not match the case direction",
        ));
    }
    if !valid_local_vhd_path(&candidate.vhd_path) {
        return Err(WindowsValidationError::InvalidEvidence(
            "candidate VHD path is not a local drive-absolute .vhd path",
        ));
    }
    if candidate.vhd_bytes != ORIGIN_VHD_BYTES {
        return Err(WindowsValidationError::InvalidEvidence(
            "candidate VHD length is not the 40 MiB fixed geometry",
        ));
    }
    if candidate.sha256_before != candidate.sha256_after {
        return Err(WindowsValidationError::InvalidEvidence(
            "candidate VHD bytes changed during read-only validation",
        ));
    }
    let sha256 = decode_sha256(&candidate.sha256_before)?;
    if !candidate.read_only_attached {
        return Err(WindowsValidationError::InvalidEvidence(
            "candidate VHD was not attached read-only",
        ));
    }
    if !candidate.no_drive_letter {
        return Err(WindowsValidationError::InvalidEvidence(
            "a drive letter was assigned",
        ));
    }
    if !candidate.detached_after {
        return Err(WindowsValidationError::InvalidEvidence(
            "candidate VHD was not detached after validation",
        ));
    }
    if candidate.partition_offset_bytes != PARTITION_OFFSET_BYTES {
        return Err(WindowsValidationError::InvalidEvidence(
            "partition offset is not the pinned 1 MiB",
        ));
    }
    // diskpart picks the partition length (it keeps roughly 1 MiB of slack before the footer), so
    // only sector granularity and fit inside the disk bytes are pinned.
    if candidate.partition_bytes == 0 || candidate.partition_bytes % 512 != 0 {
        return Err(WindowsValidationError::InvalidEvidence(
            "partition length is not a positive whole number of sectors",
        ));
    }
    if candidate
        .partition_offset_bytes
        .checked_add(candidate.partition_bytes)
        .is_none_or(|end| end > ORIGIN_VHD_BYTES - 512)
    {
        return Err(WindowsValidationError::InvalidEvidence(
            "partition extends past the disk bytes into the VHD footer",
        ));
    }
    if !valid_volume_guid_path(&candidate.volume_guid_path) {
        return Err(WindowsValidationError::InvalidEvidence(
            "invalid volume GUID path",
        ));
    }
    let payloads = validate_payloads(candidate.payloads, limits)?;
    let security = validate_security(candidate.security, identity.carries_security, limits)?;
    if candidate.chkdsk_exit_code != 0 {
        return Err(WindowsValidationError::InvalidEvidence(
            "CHKDSK did not report success",
        ));
    }
    validate_transcript(&candidate.chkdsk_output, limits)?;
    Ok(WindowsOriginCandidateEvidence {
        filesystem: identity.candidate,
        vhd_path: candidate.vhd_path,
        vhd_bytes: candidate.vhd_bytes,
        sha256,
        partition_offset_bytes: candidate.partition_offset_bytes,
        partition_bytes: candidate.partition_bytes,
        volume_guid_path: candidate.volume_guid_path,
        payloads,
        security,
        chkdsk_exit_code: candidate.chkdsk_exit_code,
        chkdsk_output: candidate.chkdsk_output,
    })
}

/// SHA-256 of the `(seed + offset) % 251` stream of `length` bytes.
#[must_use]
pub fn payload_sha256(length: u64, seed: u8) -> [u8; 32] {
    let mut hasher = Sha256::new();
    let mut byte = seed % 251;
    for _ in 0..length {
        hasher.update([byte]);
        byte = if byte == 250 { 0 } else { byte + 1 };
    }
    hasher.finalize().into()
}

/// Expected payload corpus: relative path, exact length, and SHA-256 of the seeded stream.
#[must_use]
pub fn expected_payloads() -> Vec<(String, u64, [u8; 32])> {
    PAYLOAD_SPECS
        .iter()
        .map(|(path, length, seed)| ((*path).to_owned(), *length, payload_sha256(*length, *seed)))
        .collect()
}

fn validate_payloads(
    payloads: Vec<RawPayload>,
    limits: WindowsValidationLimits,
) -> Result<Vec<WindowsOriginPayloadEvidence>, WindowsValidationError> {
    check_array("Payloads", payloads.len(), limits.max_payloads_per_case)?;
    let expected_set = expected_payloads();
    if payloads.len() != expected_set.len() {
        return Err(WindowsValidationError::InvalidEvidence(
            "driver validation lacks the complete payload corpus",
        ));
    }
    let mut seen = vec![false; expected_set.len()];
    let mut evidence = Vec::with_capacity(payloads.len());
    for payload in payloads {
        check_nonempty_string("Payload.Path", &payload.path, limits)?;
        check_nonempty_string("Payload.Sha256", &payload.sha256, limits)?;
        let Some((index, expected)) = expected_set
            .iter()
            .enumerate()
            .find(|(_, expected)| expected.0 == payload.path)
        else {
            return Err(WindowsValidationError::InvalidEvidence(
                "unexpected payload path",
            ));
        };
        if seen[index] {
            return Err(WindowsValidationError::InvalidEvidence(
                "duplicate payload path",
            ));
        }
        seen[index] = true;
        let sha256 = decode_sha256(&payload.sha256)?;
        if payload.length != expected.1 || sha256 != expected.2 {
            return Err(WindowsValidationError::InvalidEvidence(
                "payload length or SHA-256 does not match the seeded corpus",
            ));
        }
        evidence.push(WindowsOriginPayloadEvidence {
            path: payload.path,
            length: payload.length,
            sha256,
        });
    }
    if seen.iter().any(|seen| !seen) {
        return Err(WindowsValidationError::InvalidEvidence(
            "required payload is absent",
        ));
    }
    Ok(evidence)
}

/// Paths whose descriptors an NTFS round trip must serve identically: the root (empty path),
/// every payload, and the `secured` directory.
#[must_use]
pub fn expected_security_paths() -> Vec<String> {
    let mut paths = Vec::with_capacity(PAYLOAD_SPECS.len() + 2);
    paths.push(String::new());
    paths.extend(PAYLOAD_SPECS.iter().map(|(path, _, _)| (*path).to_owned()));
    paths.push(SECURED_DIRECTORY_PATH.to_owned());
    paths
}

fn requires_guests_deny(path: &str) -> bool {
    path == SECURED_DIRECTORY_PATH
        || path
            .strip_prefix(SECURED_DIRECTORY_PATH)
            .is_some_and(|rest| rest.starts_with('\\'))
}

/// A deny ACE for Guests: `(D;<flags>;<rights>;;;BG)`.
fn sddl_denies_guests(sddl: &str) -> bool {
    sddl.split('(')
        .skip(1)
        .filter_map(|ace| ace.split(')').next())
        .any(|ace| {
            let mut fields = ace.split(';');
            fields.next() == Some("D") && fields.next_back() == Some(GUESTS_SDDL_SID)
        })
}

fn validate_security(
    security: Vec<RawSecurity>,
    carries_security: bool,
    limits: WindowsValidationLimits,
) -> Result<Vec<WindowsOriginSecurityEvidence>, WindowsValidationError> {
    check_array("Security", security.len(), limits.max_payloads_per_case)?;
    if !carries_security {
        if security.is_empty() {
            return Ok(Vec::new());
        }
        return Err(WindowsValidationError::InvalidEvidence(
            "descriptor evidence is only meaningful for an NTFS round trip",
        ));
    }
    let expected_paths = expected_security_paths();
    if security.len() != expected_paths.len() {
        return Err(WindowsValidationError::InvalidEvidence(
            "NTFS round trip lacks the complete descriptor set",
        ));
    }
    let mut seen = vec![false; expected_paths.len()];
    let mut evidence = Vec::with_capacity(security.len());
    for entry in security {
        check_string("Security.Path", &entry.path, limits)?;
        check_nonempty_string("Security.Sddl", &entry.sddl, limits)?;
        let Some(index) = expected_paths.iter().position(|path| *path == entry.path) else {
            return Err(WindowsValidationError::InvalidEvidence(
                "unexpected descriptor path",
            ));
        };
        if seen[index] {
            return Err(WindowsValidationError::InvalidEvidence(
                "duplicate descriptor path",
            ));
        }
        seen[index] = true;
        if !entry.sddl.starts_with("O:") || !entry.sddl.contains("D:") {
            return Err(WindowsValidationError::InvalidEvidence(
                "descriptor SDDL lacks an owner or a DACL",
            ));
        }
        if requires_guests_deny(&entry.path) && !sddl_denies_guests(&entry.sddl) {
            return Err(WindowsValidationError::InvalidEvidence(
                "secured object does not carry the explicit Guests deny ACE",
            ));
        }
        evidence.push(WindowsOriginSecurityEvidence {
            path: entry.path,
            sddl: entry.sddl,
        });
    }
    if seen.iter().any(|seen| !seen) {
        return Err(WindowsValidationError::InvalidEvidence(
            "required descriptor is absent",
        ));
    }
    Ok(evidence)
}

/// The forward case and the round trip of one origin must describe the same Windows source.
fn check_shared_sources(cases: &[WindowsOriginCaseEvidence]) -> Result<(), WindowsValidationError> {
    for origin in [FileSystem::Ntfs, FileSystem::ExFat] {
        let mut shared = cases.iter().filter(|case| case.origin == origin);
        let (Some(first), Some(second)) = (shared.next(), shared.next()) else {
            return Err(WindowsValidationError::InvalidEvidence(
                "required Windows-origin case is absent",
            ));
        };
        if first.source_vhd_path != second.source_vhd_path
            || first.source_vhd_sha256 != second.source_vhd_sha256
            || first.source_image_sha256 != second.source_image_sha256
        {
            return Err(WindowsValidationError::InvalidEvidence(
                "forward and round-trip cases disagree about the Windows source",
            ));
        }
        if first.candidate.sha256 == second.candidate.sha256
            || first.candidate.vhd_path == second.candidate.vhd_path
        {
            return Err(WindowsValidationError::InvalidEvidence(
                "forward and round-trip candidates are the same VHD",
            ));
        }
    }
    check_distinct_volume_identities(cases)
}

/// Every candidate is a freshly identified disk, so Windows must have assigned each one its own
/// volume GUID; a repeat means the mount manager reused a cached identity and the driver may
/// have judged a stale view rather than the candidate's bytes.
fn check_distinct_volume_identities(
    cases: &[WindowsOriginCaseEvidence],
) -> Result<(), WindowsValidationError> {
    for (index, case) in cases.iter().enumerate() {
        let repeated = cases[..index].iter().any(|earlier| {
            earlier
                .candidate
                .volume_guid_path
                .eq_ignore_ascii_case(&case.candidate.volume_guid_path)
        });
        if repeated {
            return Err(WindowsValidationError::InvalidEvidence(
                "two candidates report the same volume GUID path",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upper_hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut output, byte| {
            let _ = write!(output, "{byte:02X}");
            output
        })
    }

    fn payload_json() -> String {
        expected_payloads()
            .into_iter()
            .map(|(path, length, sha256)| {
                format!(
                    r#"{{"Path":{},"Length":{length},"Sha256":"{}"}}"#,
                    serde_json::to_string(&path).unwrap(),
                    upper_hex(&sha256)
                )
            })
            .collect::<Vec<_>>()
            .join(",")
    }

    fn security_json() -> String {
        expected_security_paths()
            .into_iter()
            .map(|path| {
                let sddl = if requires_guests_deny(&path) {
                    "O:BAG:SYD:AI(D;OICI;DCLCRPCR;;;BG)(A;ID;FA;;;SY)(A;ID;FA;;;BA)"
                } else {
                    "O:BAG:SYD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;BU)"
                };
                format!(
                    r#"{{"Path":{},"Sddl":"{sddl}"}}"#,
                    serde_json::to_string(&path).unwrap()
                )
            })
            .collect::<Vec<_>>()
            .join(",")
    }

    /// `hashes` are the source VHD, carved source image, and candidate VHD digests.
    fn case(
        name: &str,
        origin: &str,
        candidate_fs: &str,
        hashes: [&str; 3],
        candidate_path: &str,
        security: &str,
    ) -> String {
        let [source_hash, image_hash, candidate_hash] = hashes;
        let source_path = serde_json::to_string(&format!(
            r"C:\work\source-{}.vhd",
            origin.to_ascii_lowercase()
        ))
        .unwrap();
        let candidate_path = serde_json::to_string(candidate_path).unwrap();
        let restore_escrow = name == NTFS_ROUND_TRIP_CASE_NAME;
        // Each fixture candidate gets its own volume GUID, derived from its digest.
        let h = candidate_hash.to_ascii_lowercase();
        let guid = format!(
            "{}-{}-{}-{}-{}",
            &h[0..8],
            &h[8..12],
            &h[12..16],
            &h[16..20],
            &h[20..32]
        );
        format!(
            r#"{{"Name":"{name}","Origin":"{origin}","RestoreEscrow":{restore_escrow},"SourceVhdPath":{source_path},"SourceVhdSha256":"{source_hash}","SourceImageSha256":"{image_hash}","Candidate":{{"FileSystem":"{candidate_fs}","VhdPath":{candidate_path},"VhdBytes":41943552,"Sha256Before":"{candidate_hash}","Sha256After":"{candidate_hash}","ReadOnlyAttached":true,"NoDriveLetter":true,"DetachedAfter":true,"PartitionOffsetBytes":1048576,"PartitionBytes":39845888,"VolumeGuidPath":"\\\\?\\Volume{{{guid}}}\\","Payloads":[{}],"Security":[{security}],"ChkdskExitCode":0,"ChkdskOutput":["Windows has scanned the file system and found no problems."]}}}}"#,
            payload_json()
        )
    }

    const README_SHA256: &str = "C839E57675862AF5C21BD0A15413C3EC579E0D5522DAB600BC6C3489B05B8F54";
    const H1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const H2: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const H3: &str = "3333333333333333333333333333333333333333333333333333333333333333";
    const H4: &str = "4444444444444444444444444444444444444444444444444444444444444444";
    const H5: &str = "5555555555555555555555555555555555555555555555555555555555555555";
    const H6: &str = "6666666666666666666666666666666666666666666666666666666666666666";
    const H7: &str = "7777777777777777777777777777777777777777777777777777777777777777";
    const H8: &str = "8888888888888888888888888888888888888888888888888888888888888888";

    fn cases() -> [String; 4] {
        [
            case(
                NTFS_FORWARD_CASE_NAME,
                "NTFS",
                "exFAT",
                [H1, H2, H3],
                r"C:\work\forward-ntfs-to-exfat.vhd",
                "",
            ),
            case(
                NTFS_ROUND_TRIP_CASE_NAME,
                "NTFS",
                "NTFS",
                [H1, H2, H4],
                r"C:\work\roundtrip-ntfs.vhd",
                &security_json(),
            ),
            case(
                EXFAT_FORWARD_CASE_NAME,
                "exFAT",
                "NTFS",
                [H5, H6, H7],
                r"C:\work\forward-exfat-to-ntfs.vhd",
                "",
            ),
            case(
                EXFAT_ROUND_TRIP_CASE_NAME,
                "exFAT",
                "exFAT",
                [H5, H6, H8],
                r"C:\work\roundtrip-exfat.vhd",
                "",
            ),
        ]
    }

    fn report_with(cases: &[String]) -> String {
        format!(
            r#"{{"Schema":"starconverter.windows-origin-validation","Version":1,"Complete":true,"GeneratedUtc":"2026-08-21T12:34:56.1234567Z","WindowsVersion":"Microsoft Windows NT 10.0","PowerShellVersion":"5.1","ChkdskVersion":"10.0","NtfsDriverVersion":"10.0","ExfatDriverVersion":"10.0","Cases":[{}]}}"#,
            cases.join(",")
        )
    }

    fn report() -> String {
        report_with(&cases())
    }

    fn verify(json: &str) -> Result<WindowsOriginValidationEvidence, WindowsValidationError> {
        verify_windows_origin_validation_report(json.as_bytes(), WindowsValidationLimits::default())
    }

    fn invalid(json: &str, reason: &'static str) {
        assert_eq!(
            verify(json),
            Err(WindowsValidationError::InvalidEvidence(reason)),
            "{json}"
        );
    }

    #[test]
    fn accepts_the_four_windows_origin_cases() {
        let evidence = verify(&report()).unwrap();
        assert_eq!(evidence.cases().len(), 4);
        let round_trip = &evidence.cases()[1];
        assert_eq!(round_trip.name(), NTFS_ROUND_TRIP_CASE_NAME);
        assert_eq!(round_trip.origin(), FileSystem::Ntfs);
        assert_eq!(round_trip.candidate().filesystem(), FileSystem::Ntfs);
        assert_eq!(round_trip.candidate().payloads().len(), 9);
        assert_eq!(round_trip.candidate().security().len(), 11);
        assert_eq!(round_trip.candidate().vhd_bytes(), ORIGIN_VHD_BYTES);
        assert_eq!(upper_hex(round_trip.candidate().sha256()), H4);
        assert_eq!(upper_hex(round_trip.source_vhd_sha256()), H1);
        assert_eq!(upper_hex(round_trip.source_image_sha256()), H2);
        assert_eq!(round_trip.candidate().chkdsk_exit_code(), 0);
        assert_eq!(round_trip.candidate().security()[0].path(), "");
        assert_eq!(
            evidence.cases()[2].candidate().filesystem(),
            FileSystem::Ntfs
        );
        assert_eq!(evidence.cases()[2].candidate().security(), &[]);
        assert_eq!(evidence.generated_utc(), "2026-08-21T12:34:56.1234567Z");
        assert_eq!(evidence.ntfs_driver_version(), "10.0");
    }

    #[test]
    fn seeded_corpus_matches_independently_computed_digests() {
        // Pinned from `hashlib.sha256(bytes((seed + i) % 251 for i in range(length)))`.
        let expected = expected_payloads();
        assert_eq!(upper_hex(&expected[0].2), README_SHA256);
        assert_eq!(
            upper_hex(&expected[1].2),
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
        );
        assert_eq!(
            upper_hex(&expected[2].2),
            "4A29273E1402E082617D11A11EACF5BCB27B121B027F8E82B1512CC001E1D395"
        );
        assert_eq!(
            upper_hex(&expected[8].2),
            "4AB24BA17F507EADFE9FFFAB6763D0EB07974C5E972EF3A60EA3DA1F8DF12054"
        );
        // The stream wraps at 251, so a 512-byte payload differs from the shorter prefix streams.
        assert_ne!(payload_sha256(512, 9), payload_sha256(251, 9));
        // Lengths straddling the 4 KiB cluster and the 8 KiB exFAT cluster are all present.
        assert_eq!(
            expected.iter().map(|(_, length, _)| *length).sum::<u64>(),
            14 + 6000 + 4096 + 4097 + 8191 + 33 + 65 + 512
        );
        assert_eq!(expected_security_paths().len(), 11);
    }

    /// A full report in which only case `index` has `from` replaced by `to` (first occurrence).
    fn report_with_case_edited(index: usize, from: &str, to: &str) -> String {
        let mut cases = cases();
        cases[index] = cases[index].replacen(from, to, 1);
        report_with(&cases)
    }

    #[test]
    fn rejects_unknown_missing_duplicate_and_mismatched_cases() {
        let cases = cases();
        invalid(
            &report_with(&cases[..3]),
            "schema v1 requires exactly the four Windows-origin cases",
        );
        let duplicated = [&cases[0], &cases[1], &cases[2], &cases[2]].map(String::clone);
        invalid(&report_with(&duplicated), "duplicate Windows-origin case");
        invalid(
            &report_with_case_edited(0, NTFS_FORWARD_CASE_NAME, "Windows NTFS to NTFS"),
            "unexpected Windows-origin case",
        );
        invalid(
            &report_with_case_edited(0, r#""Origin":"NTFS""#, r#""Origin":"exFAT""#),
            "case origin does not match its name",
        );
        invalid(
            &report_with_case_edited(0, r#""FileSystem":"exFAT""#, r#""FileSystem":"NTFS""#),
            "candidate filesystem does not match the case direction",
        );
        invalid(
            &report_with_case_edited(1, H2, H6),
            "forward and round-trip cases disagree about the Windows source",
        );
        let mut same_candidate = cases;
        same_candidate[1] = same_candidate[1].replace(H4, H3);
        invalid(
            &report_with(&same_candidate),
            "forward and round-trip candidates are the same VHD",
        );
        invalid(
            &report_with_case_edited(0, r#""RestoreEscrow":false"#, r#""RestoreEscrow":true"#),
            "case escrow restore flag does not match its name",
        );
        invalid(
            &report_with_case_edited(1, r#""RestoreEscrow":true"#, r#""RestoreEscrow":false"#),
            "case escrow restore flag does not match its name",
        );
        assert!(matches!(
            verify(&report_with_case_edited(0, r#""RestoreEscrow":false,"#, "")),
            Err(WindowsValidationError::MalformedJson(_))
        ));
    }

    #[test]
    fn rejects_candidates_sharing_a_volume_identity() {
        let mut cases = cases();
        let guid = |hash: &str| {
            let h = hash.to_ascii_lowercase();
            format!(
                "{}-{}-{}-{}-{}",
                &h[0..8],
                &h[8..12],
                &h[12..16],
                &h[16..20],
                &h[20..32]
            )
        };
        // The exFAT round trip reusing the NTFS forward candidate's volume GUID (even with
        // different casing) means Windows served a cached identity, not the candidate.
        cases[3] = cases[3].replace(&guid(H8), &guid(H3).to_ascii_uppercase());
        invalid(
            &report_with(&cases),
            "two candidates report the same volume GUID path",
        );
    }

    #[test]
    fn rejects_hash_geometry_attachment_and_chkdsk_claims() {
        let base = report();
        invalid(
            &base.replace(H3, H1),
            "candidate VHD is byte-identical to the Windows-formatted source",
        );
        invalid(
            &base.replacen(H2, H1, 1),
            "source VHD and carved partition image report the same SHA-256",
        );
        invalid(
            &base.replacen(r#""Sha256After":"3333"#, r#""Sha256After":"4433"#, 1),
            "candidate VHD bytes changed during read-only validation",
        );
        invalid(
            &base.replacen(r#""VhdBytes":41943552"#, r#""VhdBytes":34603520"#, 1),
            "candidate VHD length is not the 40 MiB fixed geometry",
        );
        invalid(
            &base.replacen(
                r#""ReadOnlyAttached":true"#,
                r#""ReadOnlyAttached":false"#,
                1,
            ),
            "candidate VHD was not attached read-only",
        );
        invalid(
            &base.replacen(r#""NoDriveLetter":true"#, r#""NoDriveLetter":false"#, 1),
            "a drive letter was assigned",
        );
        invalid(
            &base.replacen(r#""DetachedAfter":true"#, r#""DetachedAfter":false"#, 1),
            "candidate VHD was not detached after validation",
        );
        invalid(
            &base.replacen(
                r#""PartitionOffsetBytes":1048576"#,
                r#""PartitionOffsetBytes":65536"#,
                1,
            ),
            "partition offset is not the pinned 1 MiB",
        );
        invalid(
            &base.replacen(r#""ChkdskExitCode":0"#, r#""ChkdskExitCode":3"#, 1),
            "CHKDSK did not report success",
        );
        invalid(
            &base.replacen(
                r#""ChkdskOutput":["Windows has scanned the file system and found no problems."]"#,
                r#""ChkdskOutput":[]"#,
                1,
            ),
            "CHKDSK transcript is empty",
        );
        invalid(
            &base.replacen(
                r"C:\\work\\forward-ntfs-to-exfat.vhd",
                r"\\\\server\\share\\f.vhd",
                1,
            ),
            "candidate VHD path is not a local drive-absolute .vhd path",
        );
        invalid(
            &base.replacen(
                r"C:\\work\\source-ntfs.vhd",
                r"C:\\work\\source-ntfs.img",
                1,
            ),
            "source VHD path is not a local drive-absolute .vhd path",
        );
    }

    #[test]
    fn partition_length_must_be_sector_granular_and_fit_the_disk() {
        let base = report();
        for bad in ["0", "39845889"] {
            invalid(
                &base.replacen(
                    r#""PartitionBytes":39845888"#,
                    &format!(r#""PartitionBytes":{bad}"#),
                    1,
                ),
                "partition length is not a positive whole number of sectors",
            );
        }
        // 1 MiB offset + 39 MiB + one sector reaches into the footer; 40 MiB overflows the disk
        // outright; the last value overflows u64 when added to the offset.
        for bad in ["40894976", "41943040", "18446744073709551104"] {
            invalid(
                &base.replacen(
                    r#""PartitionBytes":39845888"#,
                    &format!(r#""PartitionBytes":{bad}"#),
                    1,
                ),
                "partition extends past the disk bytes into the VHD footer",
            );
        }
        // 1 MiB offset + 39 MiB ends exactly at the disk bytes and is accepted.
        assert_eq!(
            verify(&base.replacen(
                r#""PartitionBytes":39845888"#,
                r#""PartitionBytes":40894464"#,
                1
            ))
            .unwrap()
            .cases()[0]
                .candidate()
                .partition_bytes(),
            40_894_464
        );
    }

    #[test]
    fn rejects_missing_altered_or_duplicate_payloads() {
        let base = report();
        let readme = format!(r#"{{"Path":"readme.txt","Length":14,"Sha256":"{README_SHA256}"}}"#);
        let readme = readme.as_str();
        assert!(base.contains(readme));
        invalid(
            &base.replacen(&format!("{readme},"), "", 1),
            "driver validation lacks the complete payload corpus",
        );
        invalid(
            &base.replacen(readme, &readme.replace("readme.txt", "README.txt"), 1),
            "unexpected payload path",
        );
        invalid(
            &base.replacen(
                readme,
                &readme.replace(r#""Length":14"#, r#""Length":15"#),
                1,
            ),
            "payload length or SHA-256 does not match the seeded corpus",
        );
        invalid(
            &base.replacen(readme, &readme.replace("C839", "C83A"), 1),
            "payload length or SHA-256 does not match the seeded corpus",
        );
        let empty = r#"{"Path":"alpha\\empty.dat","Length":0,"Sha256":"E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"}"#;
        invalid(&base.replacen(empty, readme, 1), "duplicate payload path");
    }

    #[test]
    fn ntfs_round_trip_must_carry_every_descriptor_including_the_guests_deny() {
        let base = report();
        let security = security_json();
        invalid(
            &base.replacen(&security, "", 1),
            "NTFS round trip lacks the complete descriptor set",
        );
        let root =
            r#"{"Path":"","Sddl":"O:BAG:SYD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;BU)"}"#;
        assert!(security.contains(root));
        invalid(
            &base.replacen(root, &root.replace(r#""Path":"""#, r#""Path":"other""#), 1),
            "unexpected descriptor path",
        );
        invalid(
            &base.replacen(
                root,
                &root.replace(r#""Path":"""#, r#""Path":"readme.txt""#),
                1,
            ),
            "duplicate descriptor path",
        );
        invalid(
            &base.replacen(root, &root.replace("O:BAG:SYD:AI", "G:SYD:AI"), 1),
            "descriptor SDDL lacks an owner or a DACL",
        );
        invalid(
            &base.replacen(root, &root.replace("O:BAG:SYD:AI", "O:BAG:SYS:AI"), 1),
            "descriptor SDDL lacks an owner or a DACL",
        );
        let root_sddl = "O:BAG:SYD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;BU)";
        invalid(
            &base.replacen(root, &root.replace(root_sddl, ""), 1),
            "required string is empty or contains NUL",
        );
        let secured = r#"{"Path":"secured","Sddl":"O:BAG:SYD:AI(D;OICI;DCLCRPCR;;;BG)(A;ID;FA;;;SY)(A;ID;FA;;;BA)"}"#;
        assert!(security.contains(secured));
        invalid(
            &base.replacen(secured, &secured.replace("(D;OICI;DCLCRPCR;;;BG)", ""), 1),
            "secured object does not carry the explicit Guests deny ACE",
        );
        invalid(
            &base.replacen(
                secured,
                &secured.replace("(D;OICI;DCLCRPCR;;;BG)", "(A;OICI;DCLCRPCR;;;BG)"),
                1,
            ),
            "secured object does not carry the explicit Guests deny ACE",
        );
        invalid(
            &base.replacen(
                secured,
                &secured.replace("(D;OICI;DCLCRPCR;;;BG)", "(D;OICI;DCLCRPCR;;;BU)"),
                1,
            ),
            "secured object does not carry the explicit Guests deny ACE",
        );
        // Descriptors on a forward conversion or an exFAT round trip are not evidence.
        let mut cases = cases();
        cases[0] = cases[0].replacen(r#""Security":[]"#, &format!(r#""Security":[{root}]"#), 1);
        invalid(
            &report_with(&cases),
            "descriptor evidence is only meaningful for an NTFS round trip",
        );
    }

    #[test]
    fn sddl_deny_detection_is_exact() {
        assert!(sddl_denies_guests("O:BAG:SYD:AI(D;;FR;;;BG)"));
        assert!(sddl_denies_guests(
            "O:BAG:SYD:PAI(A;;FA;;;SY)(D;OICI;0x116;;;BG)(A;;FA;;;BA)"
        ));
        assert!(!sddl_denies_guests("O:BAG:SYD:AI(A;;FR;;;BG)"));
        assert!(!sddl_denies_guests("O:BAG:SYD:AI(D;;FR;;;BU)"));
        assert!(!sddl_denies_guests("O:BAG:SYD:AI(D;;FR;;;S-1-5-32-546x)"));
        assert!(!sddl_denies_guests("O:BAG:SYD:"));
        assert!(requires_guests_deny("secured"));
        assert!(requires_guests_deny("secured\\denied.bin"));
        assert!(!requires_guests_deny("secured.txt"));
        assert!(!requires_guests_deny(""));
    }

    #[test]
    fn rejects_schema_version_completeness_unknown_fields_and_limits() {
        let base = report();
        invalid(
            &base.replacen("windows-origin-validation", "windows-vhd-validation", 1),
            "unexpected schema",
        );
        assert_eq!(
            verify(&base.replacen(r#""Version":1"#, r#""Version":2"#, 1)),
            Err(WindowsValidationError::UnsupportedVersion(2))
        );
        assert_eq!(
            verify(&base.replacen(r#""Complete":true"#, r#""Complete":false"#, 1)),
            Err(WindowsValidationError::Incomplete)
        );
        assert!(matches!(
            verify(&base.replacen(r#""Complete":true"#, r#""Complete":true,"Extra":1"#, 1)),
            Err(WindowsValidationError::MalformedJson(_))
        ));
        assert!(matches!(
            verify(&base.replacen(
                r#""ReadOnlyAttached":true"#,
                r#""ReadOnlyAttached":true,"Mode":"x""#,
                1
            )),
            Err(WindowsValidationError::MalformedJson(_))
        ));
        assert!(matches!(
            verify(&base.replacen(r#""Sddl":"#, r#""Dacl":"#, 1)),
            Err(WindowsValidationError::MalformedJson(_))
        ));
        invalid(
            &base.replacen("2026-08-21T12:34:56.1234567Z", "2026-08-21 12:34:56Z", 1),
            "GeneratedUtc is not an invariant round-trip UTC timestamp",
        );
        let limits = WindowsValidationLimits {
            max_cases: 3,
            ..WindowsValidationLimits::default()
        };
        assert_eq!(
            verify_windows_origin_validation_report(base.as_bytes(), limits),
            Err(WindowsValidationError::ArrayLimitExceeded {
                field: "Cases",
                actual: 4,
                maximum: 3,
            })
        );
        let limits = WindowsValidationLimits {
            max_payloads_per_case: 8,
            ..WindowsValidationLimits::default()
        };
        assert_eq!(
            verify_windows_origin_validation_report(base.as_bytes(), limits),
            Err(WindowsValidationError::ArrayLimitExceeded {
                field: "Payloads",
                actual: 9,
                maximum: 8,
            })
        );
        let limits = WindowsValidationLimits {
            max_report_bytes: 16,
            ..WindowsValidationLimits::default()
        };
        assert_eq!(
            verify_windows_origin_validation_report(base.as_bytes(), limits),
            Err(WindowsValidationError::ReportTooLarge {
                actual: base.len(),
                maximum: 16,
            })
        );
        let limits = WindowsValidationLimits {
            max_string_bytes: 0,
            ..WindowsValidationLimits::default()
        };
        assert_eq!(
            verify_windows_origin_validation_report(base.as_bytes(), limits),
            Err(WindowsValidationError::InvalidLimit("max_string_bytes"))
        );
    }
}
