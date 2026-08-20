#![no_main]

use libfuzzer_sys::fuzz_target;
use starconverter_core::fs::ntfs_attribute_list::parse_attribute_list_value;

const MAX_INPUT_BYTES: usize = 256 * 1024;
const MAX_ENTRIES: usize = 4_096;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let _ = parse_attribute_list_value(data, MAX_ENTRIES, 255);
});
