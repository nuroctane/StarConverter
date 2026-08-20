#![no_main]

use libfuzzer_sys::fuzz_target;
use starconverter_core::fs::ntfs_index::{NtfsIndexLimits, parse_index_block, parse_index_root};

const MAX_INPUT_BYTES: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let limits = NtfsIndexLimits {
        max_root_bytes: MAX_INPUT_BYTES,
        max_block_bytes: MAX_INPUT_BYTES,
        max_entries_per_node: 4_096,
        max_name_code_units: 255,
    };
    let _ = parse_index_root(data, limits);

    let expected_vcn = if data.len() >= 8 {
        Some(u64::from_le_bytes(
            data[..8].try_into().expect("eight-byte prefix"),
        ))
    } else {
        None
    };
    let _ = parse_index_block(data, expected_vcn, limits);
});
