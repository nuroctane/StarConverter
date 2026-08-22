#![no_main]

use libfuzzer_sys::fuzz_target;
use starconverter_core::preservation::{PreservationLimits, decode_escrow};

const MAX_INPUT_BYTES: usize = 256 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let _ = decode_escrow(
        data,
        PreservationLimits {
            max_assessments: 25,
            max_escrow_bytes: MAX_INPUT_BYTES,
            max_record_bytes: MAX_INPUT_BYTES,
        },
    );
});
