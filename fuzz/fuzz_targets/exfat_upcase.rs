#![no_main]

use libfuzzer_sys::fuzz_target;
use starconverter_core::fs::exfat_upcase::{
    UpcaseLimits, UpcaseTable, table_checksum, visit_mappings,
};

const MAX_TABLE_BYTES: usize = 65_536 * 2;
const MAX_INPUT_BYTES: usize = 4 + MAX_TABLE_BYTES;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES || data.len() < 4 {
        return;
    }

    let supplied_checksum = u32::from_le_bytes(data[..4].try_into().expect("four-byte prefix"));
    let encoded = &data[4..];
    let limits = UpcaseLimits::COMPLETE_TABLE;

    // Exercise both checksum rejection and the deeper structural decoder.
    let _ = visit_mappings(encoded, supplied_checksum, limits, |_, _| {});
    let computed_checksum = table_checksum(encoded);
    let _ = visit_mappings(encoded, computed_checksum, limits, |_, _| {});
    let _ = UpcaseTable::parse(encoded, computed_checksum, limits);
});
