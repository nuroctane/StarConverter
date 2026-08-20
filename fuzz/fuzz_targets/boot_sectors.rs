#![no_main]

use libfuzzer_sys::fuzz_target;
use starconverter_core::fs::{exfat, ntfs};

const MAX_INPUT_BYTES: usize = 4_096;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let _ = exfat::parse_boot_sector(data);
    let _ = ntfs::parse_boot_sector(data);
});
