//! Pure, bounded construction and independent validation of an initial NTFS `$LogFile`.
//!
//! The compatibility contract is deliberately narrow. Microsoft documents that `$LogFile` is
//! NTFS's transactional metadata log and that checkpoints are used for recovery, but does not
//! publish the NTFS LFS on-disk byte layout. The concrete layouts and checks here are pinned to:
//!
//! - `ntfs-3g` commit `d327833ec1d5eb1358b6f2c37139f10a3460944d`, especially
//!   `include/ntfs-3g/logfile.h`, `libntfs-3g/logfile.c`, and `ntfsprogs/mkntfs.c`; and
//! - Linux NTFS3 commit `3aa1dcaa4f6f5ae08936491e08bd456f331f2d40`, especially
//!   `fs/ntfs3/fslog.c`.
//!
//! The pinned `mkntfs` formatter fills a new `$LogFile` with `0xff`; its checker explicitly treats
//! that state as an empty, clean journal. Linux NTFS3's post-replay cleanup supplies evidence for
//! the second supported profile: two identical, MST-protected LFS 1.1 restart pages with a closed
//! client and the clean flag, followed by erased (`0xff`) pages. No canonical empty `RCRD` payload
//! is asserted: initialized record pages and modern Windows-native formatter profiles are refused.
//!
//! LFS version 1.1 is not the NTFS volume version. These profiles are intended for an NTFS 3.1
//! volume, but the stream's own version fields remain 1.1. This module has no path, device, or I/O
//! API.

use std::fmt;

/// Sector size proven by the pinned profile.
pub const NTFS_LOGFILE_SECTOR_BYTES: u32 = 512;
/// System and log page size proven by the pinned profile.
pub const NTFS_LOGFILE_PAGE_BYTES: u32 = 4096;
/// Minimum number of log-record slots required by the pinned readers.
pub const NTFS_LOGFILE_MIN_RECORD_PAGES: u64 = 48;
/// Two restart pages plus the minimum log-record slots.
pub const NTFS_LOGFILE_MIN_PAGES: u64 = 2 + NTFS_LOGFILE_MIN_RECORD_PAGES;
/// Smallest supported `$LogFile` byte length.
pub const NTFS_LOGFILE_MIN_BYTES: u64 = 4096_u64 * NTFS_LOGFILE_MIN_PAGES;
/// Maximum LFS size accepted by ntfs-3g.
pub const NTFS_LOGFILE_MAX_BYTES: u64 = 0x1_0000_0000;

const PAGE_BYTES: usize = 4096;
#[cfg(test)]
const MIN_BYTES: usize = PAGE_BYTES * 50;
const RESTART_HEADER_BYTES: usize = 30;
const RESTART_AREA_OFFSET: usize = 0x30;
const RESTART_AREA_BYTES: usize = 0x40;
const CLIENT_RECORD_BYTES: usize = 0xa0;
const CLIENT_ARRAY_OFFSET: usize = RESTART_AREA_BYTES;
const RESTART_AREA_LENGTH: usize = RESTART_AREA_BYTES + CLIENT_RECORD_BYTES;
const LOG_RECORD_HEADER_BYTES: u16 = 0x30;
const LOG_PAGE_DATA_OFFSET: u16 = 0x40;
const LFS_NO_CLIENT: u16 = 0xffff;
const RESTART_VOLUME_IS_CLEAN: u16 = 0x0002;
const CANONICAL_USN: u16 = 1;

/// A profile which can be generated or explicitly refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtfsLogFileProfile {
    /// The exact all-`0xff` initial state emitted by the pinned `mkntfs`.
    Ntfs3gErased,
    /// Two canonical clean LFS 1.1 restart pages followed by erased pages.
    CanonicalCleanLfsV1_1,
    /// Reserved for a byte profile captured from and verified against a modern Windows formatter.
    ModernWindowsNativeNtfs31,
    /// Reserved until a canonical initial `RCRD` page layout is independently verified.
    InitializedRecordPagesV1_1,
}

/// Exact geometry and deterministic seed used to construct `$LogFile` bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtfsLogFileConfig {
    pub file_size: u64,
    pub sector_size: u32,
    pub system_page_size: u32,
    pub log_page_size: u32,
    pub major_version: u16,
    pub minor_version: u16,
    /// Caller-supplied deterministic value for `restart_log_open_count`.
    pub open_log_count: u32,
}

impl NtfsLogFileConfig {
    /// Construct the only supported geometry/version profile.
    #[must_use]
    pub const fn ntfs31_lfs_v1_1(file_size: u64, open_log_count: u32) -> Self {
        Self {
            file_size,
            sector_size: NTFS_LOGFILE_SECTOR_BYTES,
            system_page_size: NTFS_LOGFILE_PAGE_BYTES,
            log_page_size: NTFS_LOGFILE_PAGE_BYTES,
            major_version: 1,
            minor_version: 1,
            open_log_count,
        }
    }
}

/// Caller-controlled output and validation bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtfsLogFileLimits {
    pub max_bytes: usize,
}

impl Default for NtfsLogFileLimits {
    fn default() -> Self {
        Self {
            max_bytes: 64 * 1024 * 1024,
        }
    }
}

/// Facts established by the independent validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtfsLogFileValidation {
    pub profile: NtfsLogFileProfile,
    pub file_size: u64,
    pub sector_size: u32,
    pub system_page_size: u32,
    pub log_page_size: u32,
    pub major_version: Option<u16>,
    pub minor_version: Option<u16>,
    pub restart_page_count: u8,
    /// Pages after the restart-page pair which are exactly `0xff`.
    pub erased_page_count: u64,
    pub open_log_count: Option<u32>,
    pub is_clean: bool,
}

/// A precise unsupported-profile, bound, or malformed-input reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NtfsLogFileError {
    UnsupportedProfile {
        profile: NtfsLogFileProfile,
        reason: &'static str,
    },
    UnsupportedValue {
        field: &'static str,
        actual: u64,
        supported: u64,
    },
    InvalidSize {
        actual: u64,
        reason: &'static str,
    },
    LimitExceeded {
        actual: usize,
        maximum: usize,
    },
    AllocationFailed,
    Malformed {
        component: &'static str,
        offset: usize,
        reason: &'static str,
    },
}

impl fmt::Display for NtfsLogFileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedProfile { profile, reason } => {
                write!(
                    formatter,
                    "unsupported `$LogFile` profile {profile:?}: {reason}"
                )
            }
            Self::UnsupportedValue {
                field,
                actual,
                supported,
            } => write!(
                formatter,
                "unsupported `$LogFile` {field} {actual}; only {supported} is proven"
            ),
            Self::InvalidSize { actual, reason } => {
                write!(formatter, "invalid `$LogFile` size {actual}: {reason}")
            }
            Self::LimitExceeded { actual, maximum } => write!(
                formatter,
                "`$LogFile` requires {actual} bytes, exceeding limit {maximum}"
            ),
            Self::AllocationFailed => {
                formatter.write_str("allocation failed while constructing `$LogFile`")
            }
            Self::Malformed {
                component,
                offset,
                reason,
            } => write!(
                formatter,
                "malformed `$LogFile` {component} at byte {offset}: {reason}"
            ),
        }
    }
}

impl std::error::Error for NtfsLogFileError {}

/// Generate a deterministic, bounded initial `$LogFile` stream.
///
/// `CanonicalCleanLfsV1_1` uses `config.open_log_count` verbatim; callers should derive that seed
/// from stable conversion-plan evidence if they require distinct images to have distinct bytes.
///
/// # Errors
///
/// Returns an error for an unverified profile, any geometry/version other than the pinned
/// 512-byte-sector and 4096-byte-page LFS 1.1 profile, an invalid size, a caller limit violation,
/// or allocation failure.
pub fn generate_ntfs_logfile(
    profile: NtfsLogFileProfile,
    config: NtfsLogFileConfig,
    limits: NtfsLogFileLimits,
) -> Result<Vec<u8>, NtfsLogFileError> {
    match profile {
        NtfsLogFileProfile::Ntfs3gErased | NtfsLogFileProfile::CanonicalCleanLfsV1_1 => {}
        NtfsLogFileProfile::ModernWindowsNativeNtfs31 => {
            return Err(NtfsLogFileError::UnsupportedProfile {
                profile,
                reason: "Microsoft does not publish a native formatter byte profile and no independently captured profile is pinned",
            });
        }
        NtfsLogFileProfile::InitializedRecordPagesV1_1 => {
            return Err(NtfsLogFileError::UnsupportedProfile {
                profile,
                reason: "the pinned formatters do not establish one canonical initial `RCRD` page payload",
            });
        }
    }

    let length = validate_config(config, limits)?;
    let mut bytes = filled_vec(length, 0xff)?;
    if profile == NtfsLogFileProfile::CanonicalCleanLfsV1_1 {
        let page_bytes = usize::try_from(config.system_page_size).map_err(|_| {
            NtfsLogFileError::InvalidSize {
                actual: u64::from(config.system_page_size),
                reason: "system page size does not fit the host address space",
            }
        })?;
        write_restart_page(&mut bytes[..page_bytes], config, CANONICAL_USN);
        write_restart_page(
            &mut bytes[page_bytes..page_bytes * 2],
            config,
            CANONICAL_USN,
        );
    }
    Ok(bytes)
}

/// Independently parse and validate a complete supported initial `$LogFile` stream.
///
/// This function never calls the generator and does not accept a caller-supplied expected
/// configuration. It derives and cross-checks all embedded fields, both restart pages, every USA
/// sector tail, client data, canonical padding, and all erased pages.
///
/// # Errors
///
/// Returns an error for oversized, truncated, misaligned, unsupported, inconsistent, corrupt, or
/// non-canonical bytes.
pub fn validate_ntfs_logfile(
    bytes: &[u8],
    limits: NtfsLogFileLimits,
) -> Result<NtfsLogFileValidation, NtfsLogFileError> {
    validate_buffer_size(bytes, limits)?;
    let file_size = u64::try_from(bytes.len()).map_err(|_| NtfsLogFileError::InvalidSize {
        actual: u64::MAX,
        reason: "buffer length does not fit the on-disk size field",
    })?;

    if bytes.iter().all(|byte| *byte == 0xff) {
        return Ok(NtfsLogFileValidation {
            profile: NtfsLogFileProfile::Ntfs3gErased,
            file_size,
            sector_size: NTFS_LOGFILE_SECTOR_BYTES,
            system_page_size: NTFS_LOGFILE_PAGE_BYTES,
            log_page_size: NTFS_LOGFILE_PAGE_BYTES,
            major_version: None,
            minor_version: None,
            restart_page_count: 0,
            erased_page_count: file_size / u64::from(NTFS_LOGFILE_PAGE_BYTES),
            open_log_count: None,
            is_clean: true,
        });
    }

    let page_bytes = PAGE_BYTES;
    let first_raw = &bytes[..page_bytes];
    let second_raw = &bytes[page_bytes..page_bytes * 2];
    let first = validate_restart_page(first_raw, file_size, 0)?;
    let second = validate_restart_page(second_raw, file_size, page_bytes)?;
    if first != second {
        return Err(malformed(
            "restart page pair",
            page_bytes,
            "the two restart pages describe different clean states",
        ));
    }
    if first_raw != second_raw {
        return Err(malformed(
            "restart page pair",
            page_bytes,
            "canonical initial restart pages are not byte-identical",
        ));
    }

    if let Some(relative) = bytes[page_bytes * 2..]
        .iter()
        .position(|byte| *byte != 0xff)
    {
        return Err(malformed(
            "erased log page",
            page_bytes * 2 + relative,
            "initialized `RCRD` pages are outside the proven initial profile",
        ));
    }

    Ok(NtfsLogFileValidation {
        profile: NtfsLogFileProfile::CanonicalCleanLfsV1_1,
        file_size,
        sector_size: NTFS_LOGFILE_SECTOR_BYTES,
        system_page_size: NTFS_LOGFILE_PAGE_BYTES,
        log_page_size: NTFS_LOGFILE_PAGE_BYTES,
        major_version: Some(1),
        minor_version: Some(1),
        restart_page_count: 2,
        erased_page_count: file_size / u64::from(NTFS_LOGFILE_PAGE_BYTES) - 2,
        open_log_count: Some(first.open_log_count),
        is_clean: true,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RestartFacts {
    open_log_count: u32,
}

fn validate_config(
    config: NtfsLogFileConfig,
    limits: NtfsLogFileLimits,
) -> Result<usize, NtfsLogFileError> {
    require_value(
        "sector size",
        u64::from(config.sector_size),
        u64::from(NTFS_LOGFILE_SECTOR_BYTES),
    )?;
    require_value(
        "system page size",
        u64::from(config.system_page_size),
        u64::from(NTFS_LOGFILE_PAGE_BYTES),
    )?;
    require_value(
        "log page size",
        u64::from(config.log_page_size),
        u64::from(NTFS_LOGFILE_PAGE_BYTES),
    )?;
    require_value("LFS major version", u64::from(config.major_version), 1)?;
    require_value("LFS minor version", u64::from(config.minor_version), 1)?;
    validate_file_size(config.file_size)?;
    let length = usize::try_from(config.file_size).map_err(|_| NtfsLogFileError::InvalidSize {
        actual: config.file_size,
        reason: "size does not fit the host address space",
    })?;
    require_limit(length, limits)?;
    Ok(length)
}

fn validate_buffer_size(bytes: &[u8], limits: NtfsLogFileLimits) -> Result<(), NtfsLogFileError> {
    require_limit(bytes.len(), limits)?;
    let length = u64::try_from(bytes.len()).map_err(|_| NtfsLogFileError::InvalidSize {
        actual: u64::MAX,
        reason: "buffer length does not fit the on-disk size field",
    })?;
    validate_file_size(length)
}

fn validate_file_size(file_size: u64) -> Result<(), NtfsLogFileError> {
    if file_size < NTFS_LOGFILE_MIN_BYTES {
        return Err(NtfsLogFileError::InvalidSize {
            actual: file_size,
            reason: "fewer than two restart pages and 48 log-record page slots",
        });
    }
    if file_size > NTFS_LOGFILE_MAX_BYTES {
        return Err(NtfsLogFileError::InvalidSize {
            actual: file_size,
            reason: "exceeds the pinned LFS maximum",
        });
    }
    if file_size % u64::from(NTFS_LOGFILE_PAGE_BYTES) != 0 {
        return Err(NtfsLogFileError::InvalidSize {
            actual: file_size,
            reason: "not a whole number of 4096-byte log pages",
        });
    }
    Ok(())
}

const fn require_value(
    field: &'static str,
    actual: u64,
    supported: u64,
) -> Result<(), NtfsLogFileError> {
    if actual != supported {
        return Err(NtfsLogFileError::UnsupportedValue {
            field,
            actual,
            supported,
        });
    }
    Ok(())
}

const fn require_limit(length: usize, limits: NtfsLogFileLimits) -> Result<(), NtfsLogFileError> {
    if length > limits.max_bytes {
        return Err(NtfsLogFileError::LimitExceeded {
            actual: length,
            maximum: limits.max_bytes,
        });
    }
    Ok(())
}

fn filled_vec(length: usize, fill: u8) -> Result<Vec<u8>, NtfsLogFileError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| NtfsLogFileError::AllocationFailed)?;
    bytes.resize(length, fill);
    Ok(bytes)
}

fn write_restart_page(page: &mut [u8], config: NtfsLogFileConfig, usn: u16) {
    page.fill(0);
    page[..4].copy_from_slice(b"RSTR");
    put_u16(
        page,
        4,
        u16::try_from(RESTART_HEADER_BYTES).expect("constant fits"),
    );
    let usa_count = config.system_page_size / config.sector_size + 1;
    put_u16(
        page,
        6,
        u16::try_from(usa_count).expect("validated count fits"),
    );
    put_u32(page, 16, config.system_page_size);
    put_u32(page, 20, config.log_page_size);
    put_u16(
        page,
        24,
        u16::try_from(RESTART_AREA_OFFSET).expect("constant fits"),
    );
    put_u16(page, 26, config.minor_version);
    put_u16(page, 28, config.major_version);

    let restart = RESTART_AREA_OFFSET;
    put_u16(page, restart + 8, 1);
    put_u16(page, restart + 10, 0);
    put_u16(page, restart + 12, LFS_NO_CLIENT);
    put_u16(page, restart + 14, RESTART_VOLUME_IS_CLEAN);
    put_u32(page, restart + 16, sequence_number_bits(config.file_size));
    put_u16(
        page,
        restart + 20,
        u16::try_from(RESTART_AREA_LENGTH).expect("constant fits"),
    );
    put_u16(
        page,
        restart + 22,
        u16::try_from(CLIENT_ARRAY_OFFSET).expect("constant fits"),
    );
    put_u64(page, restart + 24, config.file_size);
    put_u16(page, restart + 36, LOG_RECORD_HEADER_BYTES);
    put_u16(page, restart + 38, LOG_PAGE_DATA_OFFSET);
    put_u32(page, restart + 40, config.open_log_count);

    let client = restart + CLIENT_ARRAY_OFFSET;
    put_u16(page, client + 16, LFS_NO_CLIENT);
    put_u16(page, client + 18, LFS_NO_CLIENT);
    put_u32(page, client + 28, 8);
    for (index, unit) in [
        u16::from(b'N'),
        u16::from(b'T'),
        u16::from(b'F'),
        u16::from(b'S'),
    ]
    .into_iter()
    .enumerate()
    {
        put_u16(page, client + 32 + index * 2, unit);
    }

    apply_mst(page, usn, config.sector_size);
}

fn apply_mst(page: &mut [u8], usn: u16, sector_size: u32) {
    put_u16(page, RESTART_HEADER_BYTES, usn);
    let sector_bytes = usize::try_from(sector_size).expect("validated sector size fits");
    let sector_count = page.len() / sector_bytes;
    for sector in 0..sector_count {
        let tail = (sector + 1) * sector_bytes - 2;
        let original = u16::from_le_bytes([page[tail], page[tail + 1]]);
        put_u16(page, RESTART_HEADER_BYTES + (sector + 1) * 2, original);
        put_u16(page, tail, usn);
    }
}

fn validate_restart_page(
    raw: &[u8],
    file_size: u64,
    base_offset: usize,
) -> Result<RestartFacts, NtfsLogFileError> {
    let page = deprotect_restart_page(raw, base_offset)?;
    validate_restart_header(&page, base_offset)?;
    let facts = validate_restart_area(&page, file_size, base_offset)?;
    validate_client_record(&page, base_offset)?;
    validate_restart_padding(&page, base_offset)?;
    Ok(facts)
}

fn deprotect_restart_page(raw: &[u8], base_offset: usize) -> Result<Vec<u8>, NtfsLogFileError> {
    let page_bytes = PAGE_BYTES;
    if raw.len() != page_bytes {
        return Err(malformed("restart page", base_offset, "page is truncated"));
    }
    if raw.get(..4) != Some(b"RSTR".as_slice()) {
        return Err(malformed(
            "restart page signature",
            base_offset,
            "expected `RSTR`",
        ));
    }
    let usa_offset = usize::from(read_u16(raw, 4, "restart page", base_offset)?);
    let usa_count = usize::from(read_u16(raw, 6, "restart page", base_offset)?);
    let expected_count =
        page_bytes / usize::try_from(NTFS_LOGFILE_SECTOR_BYTES).expect("constant fits") + 1;
    if usa_offset != RESTART_HEADER_BYTES {
        return Err(malformed(
            "restart page USA",
            base_offset + 4,
            "unsupported update-sequence-array offset",
        ));
    }
    if usa_count != expected_count {
        return Err(malformed(
            "restart page USA",
            base_offset + 6,
            "update-sequence-array count does not cover every sector",
        ));
    }
    let usa_bytes = usa_count
        .checked_mul(2)
        .and_then(|length| usa_offset.checked_add(length))
        .ok_or_else(|| malformed("restart page USA", base_offset + 4, "array overflows"))?;
    if usa_bytes > raw.len() {
        return Err(malformed(
            "restart page USA",
            base_offset + usa_offset,
            "array is truncated",
        ));
    }
    let usn = read_u16(raw, usa_offset, "restart page USA", base_offset)?;
    if usn == 0 || usn == LFS_NO_CLIENT {
        return Err(malformed(
            "restart page USA",
            base_offset + usa_offset,
            "update sequence number is reserved",
        ));
    }

    let mut page = filled_vec(page_bytes, 0)?;
    page.copy_from_slice(raw);
    let sector_bytes = usize::try_from(NTFS_LOGFILE_SECTOR_BYTES).expect("constant fits");
    for sector in 0..usa_count - 1 {
        let tail = (sector + 1) * sector_bytes - 2;
        let actual = read_u16(raw, tail, "restart page USA tail", base_offset)?;
        if actual != usn {
            return Err(malformed(
                "restart page USA tail",
                base_offset + tail,
                "sector tail does not match the update sequence number",
            ));
        }
        let replacement = read_u16(
            raw,
            usa_offset + (sector + 1) * 2,
            "restart page USA",
            base_offset,
        )?;
        put_u16(&mut page, tail, replacement);
    }
    Ok(page)
}

fn validate_restart_header(page: &[u8], base: usize) -> Result<(), NtfsLogFileError> {
    require_zero(page, 8..16, "restart page chkdsk LSN", base)?;
    require_u32(
        page,
        16,
        NTFS_LOGFILE_PAGE_BYTES,
        "restart page system page size",
        base,
    )?;
    require_u32(
        page,
        20,
        NTFS_LOGFILE_PAGE_BYTES,
        "restart page log page size",
        base,
    )?;
    require_u16(
        page,
        24,
        u16::try_from(RESTART_AREA_OFFSET).expect("constant fits"),
        "restart area offset",
        base,
    )?;
    require_u16(page, 26, 1, "LFS minor version", base)?;
    require_u16(page, 28, 1, "LFS major version", base)
}

fn validate_restart_area(
    page: &[u8],
    file_size: u64,
    base: usize,
) -> Result<RestartFacts, NtfsLogFileError> {
    let offset = RESTART_AREA_OFFSET;
    require_u64(page, offset, 0, "restart current LSN", base)?;
    require_u16(page, offset + 8, 1, "log client count", base)?;
    require_u16(page, offset + 10, 0, "free client index", base)?;
    require_u16(
        page,
        offset + 12,
        LFS_NO_CLIENT,
        "in-use client index",
        base,
    )?;
    require_u16(
        page,
        offset + 14,
        RESTART_VOLUME_IS_CLEAN,
        "restart flags",
        base,
    )?;
    require_u32(
        page,
        offset + 16,
        sequence_number_bits(file_size),
        "sequence number bits",
        base,
    )?;
    require_u16(
        page,
        offset + 20,
        u16::try_from(RESTART_AREA_LENGTH).expect("constant fits"),
        "restart area length",
        base,
    )?;
    require_u16(
        page,
        offset + 22,
        u16::try_from(CLIENT_ARRAY_OFFSET).expect("constant fits"),
        "client array offset",
        base,
    )?;
    require_u64(page, offset + 24, file_size, "embedded log file size", base)?;
    require_u32(page, offset + 32, 0, "last LSN data length", base)?;
    require_u16(
        page,
        offset + 36,
        LOG_RECORD_HEADER_BYTES,
        "log record header length",
        base,
    )?;
    require_u16(
        page,
        offset + 38,
        LOG_PAGE_DATA_OFFSET,
        "log page data offset",
        base,
    )?;
    let open_log_count = read_u32(page, offset + 40, "restart area", base)?;
    require_zero(
        page,
        offset + 44..offset + RESTART_AREA_BYTES,
        "restart area reserved bytes",
        base,
    )?;
    Ok(RestartFacts { open_log_count })
}

fn validate_client_record(page: &[u8], base: usize) -> Result<(), NtfsLogFileError> {
    let client = RESTART_AREA_OFFSET + CLIENT_ARRAY_OFFSET;
    require_u64(page, client, 0, "client oldest LSN", base)?;
    require_u64(page, client + 8, 0, "client restart LSN", base)?;
    require_u16(
        page,
        client + 16,
        LFS_NO_CLIENT,
        "client previous link",
        base,
    )?;
    require_u16(page, client + 18, LFS_NO_CLIENT, "client next link", base)?;
    require_u16(page, client + 20, 0, "client sequence number", base)?;
    require_zero(
        page,
        client + 22..client + 28,
        "client reserved bytes",
        base,
    )?;
    require_u32(page, client + 28, 8, "client name length", base)?;
    let expected = [
        u16::from(b'N'),
        u16::from(b'T'),
        u16::from(b'F'),
        u16::from(b'S'),
    ];
    for (index, unit) in expected.into_iter().enumerate() {
        require_u16(page, client + 32 + index * 2, unit, "client name", base)?;
    }
    require_zero(
        page,
        client + 40..client + CLIENT_RECORD_BYTES,
        "client name padding",
        base,
    )
}

fn validate_restart_padding(page: &[u8], base: usize) -> Result<(), NtfsLogFileError> {
    let content_end = RESTART_AREA_OFFSET + RESTART_AREA_LENGTH;
    require_zero(
        page,
        content_end..page.len(),
        "restart page trailing bytes",
        base,
    )
}

const fn sequence_number_bits(file_size: u64) -> u32 {
    67 - (u64::BITS - file_size.leading_zeros())
}

fn require_zero(
    bytes: &[u8],
    range: std::ops::Range<usize>,
    component: &'static str,
    base: usize,
) -> Result<(), NtfsLogFileError> {
    let region = bytes
        .get(range.clone())
        .ok_or_else(|| malformed(component, base + range.start, "field is truncated"))?;
    if let Some(relative) = region.iter().position(|byte| *byte != 0) {
        return Err(malformed(
            component,
            base + range.start + relative,
            "reserved or padding byte is non-zero",
        ));
    }
    Ok(())
}

fn require_u16(
    bytes: &[u8],
    offset: usize,
    expected: u16,
    component: &'static str,
    base: usize,
) -> Result<(), NtfsLogFileError> {
    if read_u16(bytes, offset, component, base)? != expected {
        return Err(malformed(
            component,
            base + offset,
            "unexpected field value",
        ));
    }
    Ok(())
}

fn require_u32(
    bytes: &[u8],
    offset: usize,
    expected: u32,
    component: &'static str,
    base: usize,
) -> Result<(), NtfsLogFileError> {
    if read_u32(bytes, offset, component, base)? != expected {
        return Err(malformed(
            component,
            base + offset,
            "unexpected field value",
        ));
    }
    Ok(())
}

fn require_u64(
    bytes: &[u8],
    offset: usize,
    expected: u64,
    component: &'static str,
    base: usize,
) -> Result<(), NtfsLogFileError> {
    if read_u64(bytes, offset, component, base)? != expected {
        return Err(malformed(
            component,
            base + offset,
            "unexpected field value",
        ));
    }
    Ok(())
}

fn read_u16(
    bytes: &[u8],
    offset: usize,
    component: &'static str,
    base: usize,
) -> Result<u16, NtfsLogFileError> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| malformed(component, base + offset, "field is truncated"))?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(
    bytes: &[u8],
    offset: usize,
    component: &'static str,
    base: usize,
) -> Result<u32, NtfsLogFileError> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| malformed(component, base + offset, "field is truncated"))?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn read_u64(
    bytes: &[u8],
    offset: usize,
    component: &'static str,
    base: usize,
) -> Result<u64, NtfsLogFileError> {
    let value = bytes
        .get(offset..offset + 8)
        .ok_or_else(|| malformed(component, base + offset, "field is truncated"))?;
    Ok(u64::from_le_bytes([
        value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
    ]))
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

const fn malformed(
    component: &'static str,
    offset: usize,
    reason: &'static str,
) -> NtfsLogFileError {
    NtfsLogFileError::Malformed {
        component,
        offset,
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_OPEN_COUNT: u32 = 0x4c46_5331;

    fn limits() -> NtfsLogFileLimits {
        NtfsLogFileLimits {
            max_bytes: usize::try_from(NTFS_LOGFILE_MIN_BYTES + u64::from(NTFS_LOGFILE_PAGE_BYTES))
                .expect("test size fits"),
        }
    }

    const fn config() -> NtfsLogFileConfig {
        NtfsLogFileConfig::ntfs31_lfs_v1_1(NTFS_LOGFILE_MIN_BYTES, TEST_OPEN_COUNT)
    }

    fn clean_bytes() -> Vec<u8> {
        generate_ntfs_logfile(
            NtfsLogFileProfile::CanonicalCleanLfsV1_1,
            config(),
            limits(),
        )
        .expect("clean profile")
    }

    fn assert_malformed(mutator: impl FnOnce(&mut [u8])) {
        let mut bytes = clean_bytes();
        mutator(&mut bytes);
        assert!(matches!(
            validate_ntfs_logfile(&bytes, limits()),
            Err(NtfsLogFileError::Malformed { .. })
        ));
    }

    #[test]
    fn erased_mkntfs_profile_round_trips() {
        let bytes = generate_ntfs_logfile(NtfsLogFileProfile::Ntfs3gErased, config(), limits())
            .expect("erased profile");
        assert!(bytes.iter().all(|byte| *byte == 0xff));
        let validation = validate_ntfs_logfile(&bytes, limits()).expect("validate erased");
        assert_eq!(validation.profile, NtfsLogFileProfile::Ntfs3gErased);
        assert_eq!(validation.restart_page_count, 0);
        assert_eq!(validation.erased_page_count, NTFS_LOGFILE_MIN_PAGES);
        assert!(validation.is_clean);
    }

    #[test]
    fn structural_clean_profile_is_deterministic_and_round_trips() {
        let first = clean_bytes();
        let second = clean_bytes();
        assert_eq!(first, second);
        let validation = validate_ntfs_logfile(&first, limits()).expect("validate clean");
        assert_eq!(
            validation.profile,
            NtfsLogFileProfile::CanonicalCleanLfsV1_1
        );
        assert_eq!(validation.major_version, Some(1));
        assert_eq!(validation.minor_version, Some(1));
        assert_eq!(validation.restart_page_count, 2);
        assert_eq!(validation.erased_page_count, NTFS_LOGFILE_MIN_RECORD_PAGES);
        assert_eq!(validation.open_log_count, Some(TEST_OPEN_COUNT));
        assert!(validation.is_clean);
    }

    #[test]
    fn restart_pages_have_complete_mst_protection() {
        let bytes = clean_bytes();
        let page_bytes = PAGE_BYTES;
        assert_eq!(&bytes[..4], b"RSTR");
        assert_eq!(read_u16(&bytes, 4, "test", 0).expect("USA offset"), 30);
        assert_eq!(read_u16(&bytes, 6, "test", 0).expect("USA count"), 9);
        for page in 0..2 {
            let start = page * page_bytes;
            let usn = read_u16(&bytes, start + 30, "test", 0).expect("USN");
            for sector in 0..8 {
                let tail = start + (sector + 1) * 512 - 2;
                assert_eq!(read_u16(&bytes, tail, "test", 0).expect("tail"), usn);
                assert_eq!(
                    read_u16(&bytes, start + 32 + sector * 2, "test", 0).expect("replacement"),
                    0
                );
            }
        }
        assert_eq!(&bytes[..page_bytes], &bytes[page_bytes..page_bytes * 2]);
    }

    #[test]
    fn one_additional_erased_page_is_supported() {
        let file_size = NTFS_LOGFILE_MIN_BYTES + u64::from(NTFS_LOGFILE_PAGE_BYTES);
        let config = NtfsLogFileConfig::ntfs31_lfs_v1_1(file_size, 7);
        let bytes =
            generate_ntfs_logfile(NtfsLogFileProfile::CanonicalCleanLfsV1_1, config, limits())
                .expect("extra page");
        let result = validate_ntfs_logfile(&bytes, limits()).expect("validate");
        assert_eq!(result.file_size, file_size);
        assert_eq!(result.erased_page_count, NTFS_LOGFILE_MIN_RECORD_PAGES + 1);
    }

    #[test]
    fn unsupported_profiles_are_explicitly_refused() {
        for profile in [
            NtfsLogFileProfile::ModernWindowsNativeNtfs31,
            NtfsLogFileProfile::InitializedRecordPagesV1_1,
        ] {
            assert!(matches!(
                generate_ntfs_logfile(profile, config(), limits()),
                Err(NtfsLogFileError::UnsupportedProfile { profile: actual, .. }) if actual == profile
            ));
        }
    }

    #[test]
    fn every_unproven_geometry_or_version_is_refused() {
        let mutations: [fn(&mut NtfsLogFileConfig); 5] = [
            |value| value.sector_size = 4096,
            |value| value.system_page_size = 8192,
            |value| value.log_page_size = 8192,
            |value| value.major_version = 2,
            |value| value.minor_version = 0,
        ];
        for mutate in mutations {
            let mut candidate = config();
            mutate(&mut candidate);
            assert!(matches!(
                generate_ntfs_logfile(
                    NtfsLogFileProfile::CanonicalCleanLfsV1_1,
                    candidate,
                    limits()
                ),
                Err(NtfsLogFileError::UnsupportedValue { .. })
            ));
        }
    }

    #[test]
    fn size_boundaries_and_limits_are_enforced_before_allocation() {
        for size in [
            0,
            NTFS_LOGFILE_MIN_BYTES - u64::from(NTFS_LOGFILE_PAGE_BYTES),
            NTFS_LOGFILE_MIN_BYTES + 1,
            NTFS_LOGFILE_MAX_BYTES + u64::from(NTFS_LOGFILE_PAGE_BYTES),
        ] {
            let candidate = NtfsLogFileConfig::ntfs31_lfs_v1_1(size, 0);
            assert!(matches!(
                generate_ntfs_logfile(
                    NtfsLogFileProfile::Ntfs3gErased,
                    candidate,
                    NtfsLogFileLimits {
                        max_bytes: usize::MAX
                    }
                ),
                Err(NtfsLogFileError::InvalidSize { .. })
            ));
        }
        assert!(matches!(
            generate_ntfs_logfile(
                NtfsLogFileProfile::Ntfs3gErased,
                config(),
                NtfsLogFileLimits {
                    max_bytes: MIN_BYTES - 1
                }
            ),
            Err(NtfsLogFileError::LimitExceeded { .. })
        ));
    }

    #[test]
    fn truncation_at_structural_boundaries_is_rejected() {
        let bytes = clean_bytes();
        let page = PAGE_BYTES;
        let cuts = [
            0,
            1,
            29,
            30,
            47,
            48,
            271,
            272,
            page - 1,
            page,
            page * 2 - 1,
            bytes.len() - 1,
        ];
        for cut in cuts {
            assert!(matches!(
                validate_ntfs_logfile(&bytes[..cut], limits()),
                Err(NtfsLogFileError::InvalidSize { .. } | NtfsLogFileError::Malformed { .. })
            ));
        }
    }

    #[test]
    fn corrupt_headers_restart_area_and_client_are_rejected() {
        let offsets = [
            0, 4, 6, 8, 16, 20, 24, 26, 28, 48, 56, 58, 60, 62, 64, 68, 70, 72, 80, 84, 86, 88, 92,
            96, 112, 120, 128, 130, 132, 134, 140, 144, 152,
        ];
        for offset in offsets {
            assert_malformed(|bytes| bytes[offset] ^= 0x40);
        }
    }

    #[test]
    fn every_mst_sector_tail_is_checked() {
        for page in 0..2 {
            for sector in 0..8 {
                assert_malformed(|bytes| {
                    let offset = page * PAGE_BYTES + (sector + 1) * 512 - 2;
                    bytes[offset] ^= 1;
                });
            }
        }
    }

    #[test]
    fn restart_copies_must_be_identical() {
        assert_malformed(|bytes| {
            let second_restart = PAGE_BYTES + RESTART_AREA_OFFSET;
            bytes[second_restart + 40] ^= 1;
            // Repair the second page's first-sector USA tail after changing protected content.
            // The field itself is before the tail, so no USA replacement changes are required.
        });
    }

    #[test]
    fn noncanonical_padding_and_initialized_record_pages_are_rejected() {
        assert_malformed(|bytes| bytes[RESTART_AREA_OFFSET + 44] = 1);
        assert_malformed(|bytes| bytes[RESTART_AREA_OFFSET + RESTART_AREA_LENGTH] = 1);
        assert_malformed(|bytes| bytes[2 * PAGE_BYTES + 100] = 0);
    }

    #[test]
    fn almost_erased_input_is_not_misclassified_as_clean() {
        let mut bytes = vec![0xff; MIN_BYTES];
        bytes[17] = 0;
        assert!(matches!(
            validate_ntfs_logfile(&bytes, limits()),
            Err(NtfsLogFileError::Malformed { .. })
        ));
    }

    #[test]
    fn embedded_file_size_and_sequence_bits_are_cross_checked() {
        assert_malformed(|bytes| bytes[RESTART_AREA_OFFSET + 24] ^= 1);
        assert_malformed(|bytes| bytes[RESTART_AREA_OFFSET + 16] ^= 1);
    }

    #[test]
    fn validator_limit_is_applied_before_scanning() {
        let bytes = clean_bytes();
        assert!(matches!(
            validate_ntfs_logfile(
                &bytes,
                NtfsLogFileLimits {
                    max_bytes: bytes.len() - 1
                }
            ),
            Err(NtfsLogFileError::LimitExceeded { .. })
        ));
    }
}
