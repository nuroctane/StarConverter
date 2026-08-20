#![no_main]

use libfuzzer_sys::fuzz_target;
use starconverter_core::fs::{
    ntfs_attribute::{AttributeLimits, parse_attribute, parse_attribute_list},
    ntfs_record::parse_file_record,
};

const MAX_INPUT_BYTES: usize = 256 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let limits = AttributeLimits {
        cluster_size_bytes: 4_096,
        max_attribute_bytes: MAX_INPUT_BYTES,
        max_name_code_units: 255,
        max_attributes: 256,
    };

    let _ = parse_file_record(data);
    let _ = parse_attribute(data, limits);
    let _ = parse_attribute_list(data, 0, data.len(), limits);

    // Also vary repaired-record bounds without ever indexing from them here.
    if data.len() >= 4 {
        let first = usize::from(u16::from_le_bytes([data[0], data[1]]));
        let second = usize::from(u16::from_le_bytes([data[2], data[3]]));
        let attributes_offset = first % (data.len() + 1);
        let bytes_in_use = second % (data.len() + 1);
        let _ = parse_attribute_list(data, attributes_offset, bytes_in_use, limits);
    }
});
