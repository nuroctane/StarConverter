#![no_main]

use libfuzzer_sys::fuzz_target;
use starconverter_core::fs::{
    ntfs_bitmap::{TailBitPolicy, parse_bitmap, parse_bitmap_with_tail_policy},
    ntfs_runlist::{MappingPairsLimits, parse_mapping_pairs},
};

const MAX_INPUT_BYTES: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES || data.len() < 8 {
        return;
    }

    let selector = &data[..8];
    let payload = &data[8..];
    let volume_cluster_count = u64::from(u32::from_le_bytes(
        selector[..4].try_into().expect("four-byte prefix"),
    )) + 1;
    let starting_vcn =
        u64::from(u16::from_le_bytes([selector[4], selector[5]])) % volume_cluster_count;
    let max_decoded_clusters = volume_cluster_count.min(1_000_000);
    let limits = MappingPairsLimits {
        starting_vcn,
        expected_next_vcn: None,
        volume_cluster_count,
        max_runs: 4_096,
        max_decoded_clusters,
    };
    let _ = parse_mapping_pairs(payload, limits);

    // Canonical NTFS bitmap storage is eight-byte aligned. Derive a valid
    // cluster-count envelope from the supplied payload so bit accounting and
    // reserved-tail validation are reached frequently.
    if !payload.is_empty() && payload.len() % 8 == 0 {
        let represented_bits = u64::try_from(payload.len())
            .expect("input cap fits u64")
            .saturating_mul(8);
        let unused_tail_bits = u64::from(selector[6] & 7);
        let cluster_count = represented_bits.saturating_sub(unused_tail_bits).max(1);
        let _ = parse_bitmap(cluster_count, payload);
        let _ = parse_bitmap_with_tail_policy(cluster_count, payload, TailBitPolicy::ReportOnly);
    }
});
