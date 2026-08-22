//! Strict parser for schema-v1 Windows VHD validation reports.
//!
//! Reports are emitted by `scripts/validate-windows-vhd.ps1` after inspecting fixed, regular-file
//! VHD fixtures. This module parses bytes only: it never opens a reported path, attaches a VHD, or
//! accesses a device. The JSON is deliberately unkeyed evidence, not authentication. A successful
//! parse proves only that the supplied bytes satisfy the pinned schema; it does not prove who
//! produced them, establish freshness, or grant activation authority.

use std::fmt;

use serde::Deserialize;

const SCHEMA: &str = "starconverter.windows-vhd-validation";
const VERSION: u64 = 1;
const VHD_BYTES: u64 = 34_603_520;
const VIRTUAL_BYTES: u64 = 34_603_008;
const PARTITION_OFFSET_BYTES: u64 = 1024 * 1024;

const NTFS_CASE_NAME: &str = "exFAT-to-NTFS rich conversion";
const NTFS_CASE_HASH: &str = "4D1CDDB7676FE60A541A432B38E32880621B88B5CA6404097FAAC357A8291E2F";
const EXFAT_CASE_NAME: &str = "NTFS-to-exFAT rich conversion";
const EXFAT_CASE_HASH: &str = "EE905BAEE3EEFD654F15EF5514110C2DCF9E6E58DB28751B8833D79FAF8F5B7A";

const EXPECTED_PAYLOADS: [(&str, u64, &str); 3] = [
    (
        "readme.txt",
        14,
        "DEEE70659646C5B4F25155E113967DB5AAEE6F9616232A85DEE3AFB1159D6FFB",
    ),
    (
        "alpha\\empty.dat",
        0,
        "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
    ),
    (
        "alpha\\Ωmega\\fragmented.bin",
        6000,
        "6F5B3BEF759FFD6505BEB8112B023A869B1B771946F88BAEC7F016CCFB1035D6",
    ),
];

/// Explicit allocation and work limits for one report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowsValidationLimits {
    pub max_report_bytes: usize,
    pub max_cases: usize,
    pub max_payloads_per_case: usize,
    pub max_transcript_lines_per_case: usize,
    pub max_transcript_bytes_per_case: usize,
    pub max_string_bytes: usize,
}

impl Default for WindowsValidationLimits {
    fn default() -> Self {
        Self {
            max_report_bytes: 2 * 1024 * 1024,
            max_cases: 16,
            max_payloads_per_case: 128,
            max_transcript_lines_per_case: 16_384,
            max_transcript_bytes_per_case: 1024 * 1024,
            max_string_bytes: 32 * 1024,
        }
    }
}

/// Validation path recorded by the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsValidationMode {
    DetachedPreflight,
    ReadOnlyWindowsDriver,
}

impl WindowsValidationMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DetachedPreflight => "detached-preflight",
            Self::ReadOnlyWindowsDriver => "read-only-windows-driver",
        }
    }
}

impl fmt::Display for WindowsValidationMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Opaque, non-authorizing evidence from a strictly validated report.
///
/// This type intentionally has no constructor and exposes no activation token. Its contents remain
/// unkeyed claims even after structural validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsVhdValidationEvidence {
    mode: WindowsValidationMode,
    generated_utc: String,
    windows_version: String,
    powershell_version: String,
    chkdsk_version: String,
    ntfs_driver_version: String,
    exfat_driver_version: String,
    cases: Vec<WindowsVhdCaseEvidence>,
}

impl WindowsVhdValidationEvidence {
    #[must_use]
    pub const fn mode(&self) -> WindowsValidationMode {
        self.mode
    }

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
    pub fn cases(&self) -> &[WindowsVhdCaseEvidence] {
        &self.cases
    }
}

/// One pinned VHD fixture's evidence. Fields are read-only and non-authorizing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsVhdCaseEvidence {
    name: String,
    filesystem: String,
    vhd_path: String,
    vhd_bytes: u64,
    virtual_bytes: u64,
    sha256: [u8; 32],
    driver: Option<WindowsDriverEvidence>,
}

impl WindowsVhdCaseEvidence {
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn filesystem(&self) -> &str {
        &self.filesystem
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
    pub const fn virtual_bytes(&self) -> u64 {
        self.virtual_bytes
    }

    #[must_use]
    pub const fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }

    #[must_use]
    pub const fn driver_evidence(&self) -> Option<&WindowsDriverEvidence> {
        self.driver.as_ref()
    }
}

/// Evidence available only in `read-only-windows-driver` mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsDriverEvidence {
    partition_offset_bytes: u64,
    volume_guid_path: String,
    payloads: Vec<WindowsPayloadEvidence>,
    chkdsk_exit_code: i64,
    chkdsk_output: Vec<String>,
}

impl WindowsDriverEvidence {
    #[must_use]
    pub const fn partition_offset_bytes(&self) -> u64 {
        self.partition_offset_bytes
    }

    #[must_use]
    pub fn volume_guid_path(&self) -> &str {
        &self.volume_guid_path
    }

    #[must_use]
    pub fn payloads(&self) -> &[WindowsPayloadEvidence] {
        &self.payloads
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

/// One pinned payload observed through the Windows filesystem driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsPayloadEvidence {
    path: String,
    length: u64,
    sha256: [u8; 32],
}

impl WindowsPayloadEvidence {
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

/// Refusal from strict report parsing or semantic validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WindowsValidationError {
    InvalidLimit(&'static str),
    ReportTooLarge {
        actual: usize,
        maximum: usize,
    },
    MalformedJson(String),
    UnsupportedVersion(u64),
    Incomplete,
    ArrayLimitExceeded {
        field: &'static str,
        actual: usize,
        maximum: usize,
    },
    TranscriptLimitExceeded {
        actual: usize,
        maximum: usize,
    },
    StringLimitExceeded {
        field: &'static str,
        actual: usize,
        maximum: usize,
    },
    InvalidEvidence(&'static str),
}

impl fmt::Display for WindowsValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit(field) => {
                write!(formatter, "Windows validation limit {field} is zero")
            }
            Self::ReportTooLarge { actual, maximum } => write!(
                formatter,
                "Windows validation report is {actual} bytes, exceeding cap {maximum}"
            ),
            Self::MalformedJson(reason) => {
                write!(formatter, "invalid Windows validation JSON: {reason}")
            }
            Self::UnsupportedVersion(version) => {
                write!(
                    formatter,
                    "unsupported Windows validation schema version {version}"
                )
            }
            Self::Incomplete => formatter.write_str("Windows validation report is incomplete"),
            Self::ArrayLimitExceeded {
                field,
                actual,
                maximum,
            } => write!(
                formatter,
                "Windows validation {field} contains {actual} items, exceeding cap {maximum}"
            ),
            Self::TranscriptLimitExceeded { actual, maximum } => write!(
                formatter,
                "Windows validation transcript is {actual} bytes, exceeding cap {maximum}"
            ),
            Self::StringLimitExceeded {
                field,
                actual,
                maximum,
            } => write!(
                formatter,
                "Windows validation {field} is {actual} bytes, exceeding cap {maximum}"
            ),
            Self::InvalidEvidence(reason) => {
                write!(formatter, "invalid Windows validation evidence: {reason}")
            }
        }
    }
}

impl std::error::Error for WindowsValidationError {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
struct RawReport {
    schema: String,
    version: u64,
    complete: bool,
    mode: RawMode,
    generated_utc: String,
    windows_version: String,
    power_shell_version: String,
    chkdsk_version: String,
    ntfs_driver_version: String,
    exfat_driver_version: String,
    cases: Vec<RawCase>,
}

#[derive(Debug, Deserialize)]
enum RawMode {
    #[serde(rename = "detached-preflight")]
    DetachedPreflight,
    #[serde(rename = "read-only-windows-driver")]
    ReadOnlyWindowsDriver,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawCase {
    Preflight(RawPreflightCase),
    Driver(RawDriverCase),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
struct RawPreflightCase {
    name: String,
    file_system: String,
    vhd_path: String,
    vhd_bytes: u64,
    virtual_bytes: u64,
    sha256_before: String,
    sha256_after: String,
    detached_before: bool,
    detached_after: bool,
    read_only_attached: Nullable<bool>,
    no_drive_letter: Nullable<bool>,
    partition_offset_bytes: Nullable<u64>,
    payloads: Vec<RawPayload>,
    chkdsk_exit_code: Nullable<i64>,
    chkdsk_output: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
#[allow(clippy::struct_excessive_bools)] // Exact external JSON schema, not mutable program state.
struct RawDriverCase {
    name: String,
    file_system: String,
    vhd_path: String,
    vhd_bytes: u64,
    virtual_bytes: u64,
    sha256_before: String,
    sha256_after: String,
    detached_before: bool,
    detached_after: bool,
    read_only_attached: bool,
    no_drive_letter: bool,
    partition_offset_bytes: u64,
    volume_guid_path: String,
    payloads: Vec<RawPayload>,
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
#[serde(transparent)]
struct Nullable<T>(Option<T>);

/// Parses and strictly validates one schema-v1 report without accessing any reported path.
///
/// The returned evidence is unkeyed and non-authorizing. Consumers that need provenance or
/// freshness must authenticate the report through a separate trusted channel.
///
/// # Errors
///
/// Refuses zero limits, oversized input or collections, malformed JSON, duplicate/unknown/missing
/// fields, non-v1 schema, incomplete reports, mode/case disagreement, and any mismatch in the
/// pinned fixture, detachment, read-only, no-letter, partition, payload, or CHKDSK evidence.
pub fn verify_windows_vhd_validation_report(
    bytes: &[u8],
    limits: WindowsValidationLimits,
) -> Result<WindowsVhdValidationEvidence, WindowsValidationError> {
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
    if raw.cases.len() != 2 {
        return Err(WindowsValidationError::InvalidEvidence(
            "schema v1 requires exactly two pinned cases",
        ));
    }

    let mode = match raw.mode {
        RawMode::DetachedPreflight => WindowsValidationMode::DetachedPreflight,
        RawMode::ReadOnlyWindowsDriver => WindowsValidationMode::ReadOnlyWindowsDriver,
    };
    let mut saw_ntfs = false;
    let mut saw_exfat = false;
    let mut cases = Vec::with_capacity(raw.cases.len());
    for case in raw.cases {
        let evidence = match (mode, case) {
            (WindowsValidationMode::DetachedPreflight, RawCase::Preflight(case)) => {
                validate_preflight_case(case, limits)?
            }
            (WindowsValidationMode::ReadOnlyWindowsDriver, RawCase::Driver(case)) => {
                validate_driver_case(case, limits)?
            }
            _ => {
                return Err(WindowsValidationError::InvalidEvidence(
                    "report mode does not match case evidence shape",
                ));
            }
        };
        match evidence.name.as_str() {
            NTFS_CASE_NAME if !saw_ntfs => saw_ntfs = true,
            EXFAT_CASE_NAME if !saw_exfat => saw_exfat = true,
            _ => {
                return Err(WindowsValidationError::InvalidEvidence(
                    "duplicate or unexpected pinned case",
                ));
            }
        }
        cases.push(evidence);
    }
    if !saw_ntfs || !saw_exfat {
        return Err(WindowsValidationError::InvalidEvidence(
            "required pinned case is absent",
        ));
    }

    Ok(WindowsVhdValidationEvidence {
        mode,
        generated_utc: raw.generated_utc,
        windows_version: raw.windows_version,
        powershell_version: raw.power_shell_version,
        chkdsk_version: raw.chkdsk_version,
        ntfs_driver_version: raw.ntfs_driver_version,
        exfat_driver_version: raw.exfat_driver_version,
        cases,
    })
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

fn validate_preflight_case(
    case: RawPreflightCase,
    limits: WindowsValidationLimits,
) -> Result<WindowsVhdCaseEvidence, WindowsValidationError> {
    validate_common_case(
        &case.name,
        &case.file_system,
        &case.vhd_path,
        case.vhd_bytes,
        case.virtual_bytes,
        &case.sha256_before,
        &case.sha256_after,
        case.detached_before,
        case.detached_after,
        limits,
    )?;
    check_array(
        "Payloads",
        case.payloads.len(),
        limits.max_payloads_per_case,
    )?;
    check_array(
        "ChkdskOutput",
        case.chkdsk_output.len(),
        limits.max_transcript_lines_per_case,
    )?;
    if case.read_only_attached.0.is_some()
        || case.no_drive_letter.0.is_some()
        || case.partition_offset_bytes.0.is_some()
        || case.chkdsk_exit_code.0.is_some()
        || !case.payloads.is_empty()
        || !case.chkdsk_output.is_empty()
    {
        return Err(WindowsValidationError::InvalidEvidence(
            "detached preflight contains driver-only evidence",
        ));
    }
    Ok(WindowsVhdCaseEvidence {
        name: case.name,
        filesystem: case.file_system,
        vhd_path: case.vhd_path,
        vhd_bytes: case.vhd_bytes,
        virtual_bytes: case.virtual_bytes,
        sha256: decode_sha256(&case.sha256_before)?,
        driver: None,
    })
}

fn validate_driver_case(
    case: RawDriverCase,
    limits: WindowsValidationLimits,
) -> Result<WindowsVhdCaseEvidence, WindowsValidationError> {
    validate_common_case(
        &case.name,
        &case.file_system,
        &case.vhd_path,
        case.vhd_bytes,
        case.virtual_bytes,
        &case.sha256_before,
        &case.sha256_after,
        case.detached_before,
        case.detached_after,
        limits,
    )?;
    if !case.read_only_attached {
        return Err(WindowsValidationError::InvalidEvidence(
            "VHD was not attached read-only",
        ));
    }
    if !case.no_drive_letter {
        return Err(WindowsValidationError::InvalidEvidence(
            "a drive letter was assigned",
        ));
    }
    if case.partition_offset_bytes != PARTITION_OFFSET_BYTES {
        return Err(WindowsValidationError::InvalidEvidence(
            "partition offset is not the pinned 1 MiB",
        ));
    }
    check_nonempty_string("VolumeGuidPath", &case.volume_guid_path, limits)?;
    if !valid_volume_guid_path(&case.volume_guid_path) {
        return Err(WindowsValidationError::InvalidEvidence(
            "invalid volume GUID path",
        ));
    }
    let payloads = validate_payloads(case.payloads, limits)?;
    if case.chkdsk_exit_code != 0 {
        return Err(WindowsValidationError::InvalidEvidence(
            "CHKDSK did not report success",
        ));
    }
    validate_transcript(&case.chkdsk_output, limits)?;
    let sha256 = decode_sha256(&case.sha256_before)?;
    Ok(WindowsVhdCaseEvidence {
        name: case.name,
        filesystem: case.file_system,
        vhd_path: case.vhd_path,
        vhd_bytes: case.vhd_bytes,
        virtual_bytes: case.virtual_bytes,
        sha256,
        driver: Some(WindowsDriverEvidence {
            partition_offset_bytes: case.partition_offset_bytes,
            volume_guid_path: case.volume_guid_path,
            payloads,
            chkdsk_exit_code: case.chkdsk_exit_code,
            chkdsk_output: case.chkdsk_output,
        }),
    })
}

#[allow(clippy::too_many_arguments)]
fn validate_common_case(
    name: &str,
    filesystem: &str,
    vhd_path: &str,
    vhd_bytes: u64,
    virtual_bytes: u64,
    before: &str,
    after: &str,
    detached_before: bool,
    detached_after: bool,
    limits: WindowsValidationLimits,
) -> Result<(), WindowsValidationError> {
    for (field, value) in [
        ("Case.Name", name),
        ("Case.FileSystem", filesystem),
        ("Case.VhdPath", vhd_path),
        ("Case.Sha256Before", before),
        ("Case.Sha256After", after),
    ] {
        check_nonempty_string(field, value, limits)?;
    }
    let (expected_filesystem, expected_hash) = match name {
        NTFS_CASE_NAME => ("NTFS", NTFS_CASE_HASH),
        EXFAT_CASE_NAME => ("exFAT", EXFAT_CASE_HASH),
        _ => {
            return Err(WindowsValidationError::InvalidEvidence(
                "unexpected validation case",
            ));
        }
    };
    if filesystem != expected_filesystem {
        return Err(WindowsValidationError::InvalidEvidence(
            "case filesystem does not match its pinned identity",
        ));
    }
    if vhd_bytes != VHD_BYTES || virtual_bytes != VIRTUAL_BYTES {
        return Err(WindowsValidationError::InvalidEvidence(
            "VHD geometry does not match the pinned fixture",
        ));
    }
    if before != after || before != expected_hash {
        return Err(WindowsValidationError::InvalidEvidence(
            "before/after SHA-256 does not match the pinned fixture",
        ));
    }
    decode_sha256(before)?;
    if !detached_before || !detached_after {
        return Err(WindowsValidationError::InvalidEvidence(
            "VHD was not detached both before and after validation",
        ));
    }
    if !valid_local_vhd_path(vhd_path) {
        return Err(WindowsValidationError::InvalidEvidence(
            "VHD path is not a local drive-absolute .vhd path",
        ));
    }
    Ok(())
}

fn validate_payloads(
    payloads: Vec<RawPayload>,
    limits: WindowsValidationLimits,
) -> Result<Vec<WindowsPayloadEvidence>, WindowsValidationError> {
    check_array("Payloads", payloads.len(), limits.max_payloads_per_case)?;
    if payloads.len() != EXPECTED_PAYLOADS.len() {
        return Err(WindowsValidationError::InvalidEvidence(
            "driver validation lacks the complete pinned payload set",
        ));
    }
    let mut seen = [false; EXPECTED_PAYLOADS.len()];
    let mut evidence = Vec::with_capacity(payloads.len());
    for payload in payloads {
        check_nonempty_string("Payload.Path", &payload.path, limits)?;
        check_nonempty_string("Payload.Sha256", &payload.sha256, limits)?;
        let Some((index, expected)) = EXPECTED_PAYLOADS
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
        if payload.length != expected.1 || payload.sha256 != expected.2 {
            return Err(WindowsValidationError::InvalidEvidence(
                "payload length or SHA-256 does not match its pinned identity",
            ));
        }
        evidence.push(WindowsPayloadEvidence {
            path: payload.path,
            length: payload.length,
            sha256: decode_sha256(&payload.sha256)?,
        });
    }
    if seen.iter().any(|seen| !seen) {
        return Err(WindowsValidationError::InvalidEvidence(
            "required pinned payload is absent",
        ));
    }
    Ok(evidence)
}

fn validate_transcript(
    lines: &[String],
    limits: WindowsValidationLimits,
) -> Result<(), WindowsValidationError> {
    check_array(
        "ChkdskOutput",
        lines.len(),
        limits.max_transcript_lines_per_case,
    )?;
    if lines.is_empty() {
        return Err(WindowsValidationError::InvalidEvidence(
            "CHKDSK transcript is empty",
        ));
    }
    let mut total = 0_usize;
    for line in lines {
        check_string("ChkdskOutput line", line, limits)?;
        total = total.checked_add(line.len()).ok_or(
            WindowsValidationError::TranscriptLimitExceeded {
                actual: usize::MAX,
                maximum: limits.max_transcript_bytes_per_case,
            },
        )?;
        if total > limits.max_transcript_bytes_per_case {
            return Err(WindowsValidationError::TranscriptLimitExceeded {
                actual: total,
                maximum: limits.max_transcript_bytes_per_case,
            });
        }
    }
    Ok(())
}

const fn check_array(
    field: &'static str,
    actual: usize,
    maximum: usize,
) -> Result<(), WindowsValidationError> {
    if actual > maximum {
        Err(WindowsValidationError::ArrayLimitExceeded {
            field,
            actual,
            maximum,
        })
    } else {
        Ok(())
    }
}

fn check_nonempty_string(
    field: &'static str,
    value: &str,
    limits: WindowsValidationLimits,
) -> Result<(), WindowsValidationError> {
    check_string(field, value, limits)?;
    if value.is_empty() || value.contains('\0') {
        Err(WindowsValidationError::InvalidEvidence(
            "required string is empty or contains NUL",
        ))
    } else {
        Ok(())
    }
}

const fn check_string(
    field: &'static str,
    value: &str,
    limits: WindowsValidationLimits,
) -> Result<(), WindowsValidationError> {
    if value.len() > limits.max_string_bytes {
        Err(WindowsValidationError::StringLimitExceeded {
            field,
            actual: value.len(),
            maximum: limits.max_string_bytes,
        })
    } else {
        Ok(())
    }
}

fn decode_sha256(value: &str) -> Result<[u8; 32], WindowsValidationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
    {
        return Err(WindowsValidationError::InvalidEvidence(
            "SHA-256 is not 64 uppercase hexadecimal characters",
        ));
    }
    let mut output = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_value(pair[0]) << 4) | hex_value(pair[1]);
    }
    Ok(output)
}

const fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'A'..=b'F' => byte - b'A' + 10,
        _ => 0,
    }
}

fn valid_local_vhd_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 7
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && bytes[2] == b'\\'
        && value
            .get(value.len().saturating_sub(4)..)
            .is_some_and(|extension| extension.eq_ignore_ascii_case(".vhd"))
        && !value.contains('\0')
}

fn valid_volume_guid_path(value: &str) -> bool {
    let Some(guid) = value
        .strip_prefix(r"\\?\Volume\{")
        .and_then(|value| value.strip_suffix(r"}\"))
    else {
        return false;
    };
    guid.len() == 36
        && guid.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

fn valid_roundtrip_utc(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 28
        && bytes[0..4].iter().all(u8::is_ascii_digit)
        && bytes[4] == b'-'
        && bytes[5..7].iter().all(u8::is_ascii_digit)
        && bytes[7] == b'-'
        && bytes[8..10].iter().all(u8::is_ascii_digit)
        && bytes[10] == b'T'
        && bytes[11..13].iter().all(u8::is_ascii_digit)
        && bytes[13] == b':'
        && bytes[14..16].iter().all(u8::is_ascii_digit)
        && bytes[16] == b':'
        && bytes[17..19].iter().all(u8::is_ascii_digit)
        && bytes[19] == b'.'
        && bytes[20..27].iter().all(u8::is_ascii_digit)
        && bytes[27] == b'Z'
}

#[cfg(test)]
mod tests {
    use super::*;

    fn preflight_case(name: &str, filesystem: &str, hash: &str, path: &str) -> String {
        let path = serde_json::to_string(path).unwrap();
        format!(
            r#"{{"Name":"{name}","FileSystem":"{filesystem}","VhdPath":{path},"VhdBytes":34603520,"VirtualBytes":34603008,"Sha256Before":"{hash}","Sha256After":"{hash}","DetachedBefore":true,"DetachedAfter":true,"ReadOnlyAttached":null,"NoDriveLetter":null,"PartitionOffsetBytes":null,"Payloads":[],"ChkdskExitCode":null,"ChkdskOutput":[]}}"#
        )
    }

    fn driver_case(name: &str, filesystem: &str, hash: &str, path: &str) -> String {
        let path = serde_json::to_string(path).unwrap();
        format!(
            r#"{{"Name":"{name}","FileSystem":"{filesystem}","VhdPath":{path},"VhdBytes":34603520,"VirtualBytes":34603008,"Sha256Before":"{hash}","Sha256After":"{hash}","DetachedBefore":true,"DetachedAfter":true,"ReadOnlyAttached":true,"NoDriveLetter":true,"PartitionOffsetBytes":1048576,"VolumeGuidPath":"\\\\?\\Volume\\{{01234567-89ab-cdef-0123-456789abcdef}}\\","Payloads":[{{"Path":"readme.txt","Length":14,"Sha256":"DEEE70659646C5B4F25155E113967DB5AAEE6F9616232A85DEE3AFB1159D6FFB"}},{{"Path":"alpha\\empty.dat","Length":0,"Sha256":"E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"}},{{"Path":"alpha\\Ωmega\\fragmented.bin","Length":6000,"Sha256":"6F5B3BEF759FFD6505BEB8112B023A869B1B771946F88BAEC7F016CCFB1035D6"}}],"ChkdskExitCode":0,"ChkdskOutput":["Windows has scanned the file system and found no problems."]}}"#
        )
    }

    fn report(mode: &str, cases: &str) -> String {
        format!(
            r#"{{"Schema":"starconverter.windows-vhd-validation","Version":1,"Complete":true,"Mode":"{mode}","GeneratedUtc":"2026-08-21T12:34:56.1234567Z","WindowsVersion":"Microsoft Windows NT 10.0","PowerShellVersion":"5.1","ChkdskVersion":"10.0","NtfsDriverVersion":"10.0","ExfatDriverVersion":"10.0","Cases":[{cases}]}}"#
        )
    }

    fn preflight_report() -> String {
        report(
            "detached-preflight",
            &format!(
                "{},{}",
                preflight_case(
                    NTFS_CASE_NAME,
                    "NTFS",
                    NTFS_CASE_HASH,
                    r"C:\fixtures\ntfs.vhd"
                ),
                preflight_case(
                    EXFAT_CASE_NAME,
                    "exFAT",
                    EXFAT_CASE_HASH,
                    r"D:\fixtures\exfat.vhd"
                ),
            ),
        )
    }

    fn driver_report() -> String {
        report(
            "read-only-windows-driver",
            &format!(
                "{},{}",
                driver_case(
                    NTFS_CASE_NAME,
                    "NTFS",
                    NTFS_CASE_HASH,
                    r"C:\fixtures\ntfs.vhd"
                ),
                driver_case(
                    EXFAT_CASE_NAME,
                    "exFAT",
                    EXFAT_CASE_HASH,
                    r"D:\fixtures\exfat.vhd"
                ),
            ),
        )
    }

    fn verify(json: &str) -> Result<WindowsVhdValidationEvidence, WindowsValidationError> {
        verify_windows_vhd_validation_report(json.as_bytes(), WindowsValidationLimits::default())
    }

    #[test]
    fn accepts_complete_detached_preflight_as_non_driver_evidence() {
        let evidence = verify(&preflight_report()).unwrap();
        assert_eq!(evidence.mode(), WindowsValidationMode::DetachedPreflight);
        assert_eq!(evidence.cases().len(), 2);
        assert!(
            evidence
                .cases()
                .iter()
                .all(|case| case.driver_evidence().is_none())
        );
        assert_eq!(evidence.cases()[0].sha256()[0], 0x4d);
    }

    #[test]
    fn accepts_complete_driver_report_with_pinned_read_only_evidence() {
        let evidence = verify(&driver_report()).unwrap();
        assert_eq!(
            evidence.mode(),
            WindowsValidationMode::ReadOnlyWindowsDriver
        );
        for case in evidence.cases() {
            let driver = case.driver_evidence().unwrap();
            assert_eq!(driver.partition_offset_bytes(), PARTITION_OFFSET_BYTES);
            assert_eq!(driver.payloads().len(), 3);
            assert_eq!(driver.chkdsk_exit_code(), 0);
            assert!(!driver.chkdsk_output().is_empty());
        }
    }

    #[test]
    fn rejects_unknown_missing_and_duplicate_fields() {
        let valid = preflight_report();
        let unknown = valid.replacen("\"Complete\":true", "\"Complete\":true,\"Surprise\":1", 1);
        let missing = valid.replacen("\"Complete\":true,", "", 1);
        let duplicate = valid.replacen(
            "\"Complete\":true",
            "\"Complete\":true,\"Complete\":true",
            1,
        );
        for invalid in [unknown, missing, duplicate] {
            assert!(matches!(
                verify(&invalid),
                Err(WindowsValidationError::MalformedJson(_))
            ));
        }
    }

    #[test]
    fn rejects_incomplete_wrong_schema_version_and_mode_shape() {
        let valid = preflight_report();
        assert!(matches!(
            verify(&valid.replacen("\"Complete\":true", "\"Complete\":false", 1)),
            Err(WindowsValidationError::Incomplete)
        ));
        assert!(matches!(
            verify(&valid.replacen("\"Version\":1", "\"Version\":2", 1)),
            Err(WindowsValidationError::UnsupportedVersion(2))
        ));
        assert!(matches!(
            verify(&valid.replacen("detached-preflight", "read-only-windows-driver", 1)),
            Err(WindowsValidationError::InvalidEvidence(_))
        ));
    }

    #[test]
    fn rejects_changed_hash_detachment_and_driver_safety_claims() {
        let preflight = preflight_report();
        let changed = preflight.replacen(
            &format!("\"Sha256After\":\"{NTFS_CASE_HASH}\""),
            &format!("\"Sha256After\":\"{}\"", "0".repeat(64)),
            1,
        );
        assert!(matches!(
            verify(&changed),
            Err(WindowsValidationError::InvalidEvidence(_))
        ));
        assert!(matches!(
            verify(&preflight.replacen("\"DetachedAfter\":true", "\"DetachedAfter\":false", 1)),
            Err(WindowsValidationError::InvalidEvidence(_))
        ));

        let driver = driver_report();
        for invalid in [
            driver.replacen("\"ReadOnlyAttached\":true", "\"ReadOnlyAttached\":false", 1),
            driver.replacen("\"NoDriveLetter\":true", "\"NoDriveLetter\":false", 1),
            driver.replacen(
                "\"PartitionOffsetBytes\":1048576",
                "\"PartitionOffsetBytes\":0",
                1,
            ),
            driver.replacen("\"ChkdskExitCode\":0", "\"ChkdskExitCode\":1", 1),
        ] {
            assert!(matches!(
                verify(&invalid),
                Err(WindowsValidationError::InvalidEvidence(_))
            ));
        }
    }

    #[test]
    fn rejects_missing_duplicate_or_mutated_payload_evidence() {
        let valid = driver_report();
        let missing = valid.replacen(
            r#",{"Path":"alpha\\empty.dat","Length":0,"Sha256":"E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"}"#,
            "",
            1,
        );
        let duplicate = valid.replacen("alpha\\\\empty.dat", "readme.txt", 1);
        let mutated = valid.replacen("\"Length\":6000", "\"Length\":5999", 1);
        for invalid in [missing, duplicate, mutated] {
            assert!(matches!(
                verify(&invalid),
                Err(WindowsValidationError::InvalidEvidence(_))
            ));
        }
    }

    #[test]
    fn rejects_oversized_input_arrays_strings_and_transcripts() {
        let valid = driver_report();
        let limits = WindowsValidationLimits {
            max_report_bytes: valid.len() - 1,
            ..WindowsValidationLimits::default()
        };
        assert!(matches!(
            verify_windows_vhd_validation_report(valid.as_bytes(), limits),
            Err(WindowsValidationError::ReportTooLarge { .. })
        ));

        let limits = WindowsValidationLimits {
            max_cases: 1,
            ..WindowsValidationLimits::default()
        };
        assert!(matches!(
            verify_windows_vhd_validation_report(valid.as_bytes(), limits),
            Err(WindowsValidationError::ArrayLimitExceeded { field: "Cases", .. })
        ));

        let limits = WindowsValidationLimits {
            max_payloads_per_case: 2,
            ..WindowsValidationLimits::default()
        };
        assert!(matches!(
            verify_windows_vhd_validation_report(valid.as_bytes(), limits),
            Err(WindowsValidationError::ArrayLimitExceeded {
                field: "Payloads",
                ..
            })
        ));

        let limits = WindowsValidationLimits {
            max_string_bytes: 8,
            ..WindowsValidationLimits::default()
        };
        assert!(matches!(
            verify_windows_vhd_validation_report(valid.as_bytes(), limits),
            Err(WindowsValidationError::StringLimitExceeded { .. })
        ));

        let limits = WindowsValidationLimits {
            max_transcript_bytes_per_case: 8,
            ..WindowsValidationLimits::default()
        };
        assert!(matches!(
            verify_windows_vhd_validation_report(valid.as_bytes(), limits),
            Err(WindowsValidationError::TranscriptLimitExceeded { .. })
        ));
    }

    #[test]
    fn rejects_empty_transcript_network_path_bad_guid_and_zero_limits() {
        let valid = driver_report();
        for invalid in [
            valid.replacen(
                "[\"Windows has scanned the file system and found no problems.\"]",
                "[]",
                1,
            ),
            valid.replacen(
                "C:\\\\fixtures\\\\ntfs.vhd",
                r"\\\\server\\share\\ntfs.vhd",
                1,
            ),
            valid.replacen("01234567-89ab-cdef-0123-456789abcdef", "not-a-guid", 1),
        ] {
            assert!(matches!(
                verify(&invalid),
                Err(WindowsValidationError::InvalidEvidence(_))
            ));
        }

        let limits = WindowsValidationLimits {
            max_report_bytes: 0,
            ..WindowsValidationLimits::default()
        };
        assert!(matches!(
            verify_windows_vhd_validation_report(valid.as_bytes(), limits),
            Err(WindowsValidationError::InvalidLimit("max_report_bytes"))
        ));
    }
}
