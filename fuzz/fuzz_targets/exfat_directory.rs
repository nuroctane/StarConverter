#![no_main]

use libfuzzer_sys::fuzz_target;
use starconverter_core::fs::exfat_directory::{DirectoryContext, parse_directory};

const ENTRY_BYTES: usize = 32;
const MAX_ENTRIES: usize = 8_192;
const MAX_INPUT_BYTES: usize = 4 + ENTRY_BYTES * MAX_ENTRIES;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES || data.len() < 4 {
        return;
    }

    let selector = &data[..4];
    let directory = &data[4..];
    let cluster_count = u32::from(u16::from_le_bytes([selector[0], selector[1]])) + 1;
    let bytes_per_cluster = 512_u32 << (selector[2] & 7);
    let context = DirectoryContext {
        cluster_count,
        bytes_per_cluster,
        number_of_fats: 1 + (selector[3] & 1),
        is_root: selector[3] & 2 != 0,
        max_entries: MAX_ENTRIES,
        max_secondary_entries: 32,
    };

    let _ = parse_directory(directory, context, |_| {});
});
