#![no_main]

use libfuzzer_sys::fuzz_target;
use starconverter_core::fs::{
    exfat,
    exfat_region::{self, ExfatBootRegionKind},
    ntfs, ntfs_region,
};

const MAX_SECTOR_BYTES: usize = 4_096;
const MAX_INPUT_BYTES: usize = 24 * MAX_SECTOR_BYTES;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    // exFAT records its logical-sector shift in the first sector. Trust that
    // value only after the standalone parser accepts the sector, then pass
    // exact, bounded prefixes to the redundant-region validators.
    if let Ok(boot) = exfat::parse_boot_sector(data) {
        let Ok(sector_bytes) = usize::try_from(boot.bytes_per_sector) else {
            return;
        };
        if let Some(one_len) = sector_bytes.checked_mul(12) {
            if data.len() >= one_len {
                let _ = exfat_region::validate_boot_region(
                    &data[..one_len],
                    sector_bytes,
                    ExfatBootRegionKind::Main,
                );
            }
        }
        if let Some(two_len) = sector_bytes.checked_mul(24) {
            if data.len() >= two_len {
                let _ = exfat_region::validate_boot_regions(&data[..two_len], sector_bytes);
            }
        }
    }

    // An accepted NTFS primary sector supplies all geometry. The fuzzer input
    // itself supplies the adjacent candidate backup; no partition I/O occurs.
    if let Ok(boot) = ntfs::parse_boot_sector(data) {
        let sector_bytes = usize::from(boot.bytes_per_sector);
        if let Some(pair_len) = sector_bytes.checked_mul(2) {
            if data.len() >= pair_len {
                let primary = &data[..sector_bytes];
                let backup = &data[sector_bytes..pair_len];
                let backup_offset = boot.filesystem_bytes;
                let _ = ntfs_region::validate_boot_region(
                    primary,
                    backup,
                    boot.minimum_image_bytes,
                    backup_offset,
                );
            }
        }
    }
});
