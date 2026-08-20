//! Deterministic malformed-input stress tests for the public pure parsers.
//!
//! These fixtures live entirely in memory. The tests deliberately avoid random
//! fuzzing so every failure is reproducible on the crate's Rust 1.85 MSRV.

use std::panic::{AssertUnwindSafe, catch_unwind};

use starconverter_core::fs::{
    exfat,
    exfat_directory::{DirectoryContext, parse_directory},
    exfat_region::{
        ExfatBootRegionKind, validate_boot_region as validate_exfat_region,
        validate_boot_regions as validate_exfat_regions,
    },
    exfat_upcase::{UpcaseLimits, UpcaseTable, table_checksum, visit_mappings},
    ntfs,
    ntfs_attribute::{AttributeLimits, parse_attribute, parse_attribute_list},
    ntfs_bitmap::parse_bitmap,
    ntfs_record::parse_file_record,
    ntfs_region::validate_boot_region as validate_ntfs_region,
    ntfs_runlist::{MappingPairsLimits, parse_mapping_pairs},
};

const SECTOR_BYTES: usize = 512;
const EXFAT_REGION_SECTORS: usize = 12;
const NTFS_DECLARED_SECTORS: u64 = 4_095;

fn no_panic(label: &str, action: impl FnOnce() + std::panic::UnwindSafe) {
    assert!(catch_unwind(action).is_ok(), "parser panicked: {label}");
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

fn put_i64(bytes: &mut [u8], offset: usize, value: i64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn exfat_boot_sector() -> Vec<u8> {
    let mut sector = vec![0_u8; SECTOR_BYTES];
    sector[0..3].copy_from_slice(&[0xeb, 0x76, 0x90]);
    sector[3..11].copy_from_slice(b"EXFAT   ");
    put_u64(&mut sector, 64, 2_048);
    put_u64(&mut sector, 72, 64_088);
    put_u32(&mut sector, 80, 24);
    put_u32(&mut sector, 84, 64);
    put_u32(&mut sector, 88, 88);
    put_u32(&mut sector, 92, 8_000);
    put_u32(&mut sector, 96, 2);
    put_u32(&mut sector, 100, 0x1234_abcd);
    put_u16(&mut sector, 104, 0x0100);
    sector[108] = 9;
    sector[109] = 3;
    sector[110] = 1;
    sector[111] = 0x80;
    sector[112] = 42;
    put_u16(&mut sector, 510, 0xaa55);
    sector
}

fn exfat_checksum(covered: &[u8]) -> u32 {
    covered
        .iter()
        .copied()
        .enumerate()
        .filter(|(index, _)| !matches!(*index, 106 | 107 | 112))
        .fold(0_u32, |checksum, (_, byte)| {
            checksum.rotate_right(1).wrapping_add(u32::from(byte))
        })
}

fn exfat_region() -> Vec<u8> {
    let mut region = vec![0_u8; EXFAT_REGION_SECTORS * SECTOR_BYTES];
    region[..SECTOR_BYTES].copy_from_slice(&exfat_boot_sector());
    for sector in 1..=8 {
        let signature = sector * SECTOR_BYTES + SECTOR_BYTES - 4;
        put_u32(&mut region, signature, 0xaa55_0000);
    }
    let checksum_start = 11 * SECTOR_BYTES;
    let checksum = exfat_checksum(&region[..checksum_start]);
    for word in region[checksum_start..].chunks_exact_mut(4) {
        word.copy_from_slice(&checksum.to_le_bytes());
    }
    region
}

fn ntfs_boot_sector() -> Vec<u8> {
    let mut boot = vec![0_u8; SECTOR_BYTES];
    boot[0..3].copy_from_slice(&[0xeb, 0x52, 0x90]);
    boot[3..11].copy_from_slice(b"NTFS    ");
    put_u16(&mut boot, 11, 512);
    boot[13] = 8;
    boot[21] = 0xf8;
    put_u16(&mut boot, 24, 63);
    put_u16(&mut boot, 26, 255);
    put_u32(&mut boot, 28, 2_048);
    put_i64(
        &mut boot,
        40,
        i64::try_from(NTFS_DECLARED_SECTORS).expect("fixture geometry fits i64"),
    );
    put_i64(&mut boot, 48, 4);
    put_i64(&mut boot, 56, 8);
    boot[64] = (-12_i8).to_ne_bytes()[0];
    boot[68] = (-12_i8).to_ne_bytes()[0];
    put_u64(&mut boot, 72, 0x0123_4567_89ab_cdef);
    put_u32(&mut boot, 80, 0x1122_3344);
    put_u16(&mut boot, 510, 0xaa55);
    boot
}

fn exfat_directory() -> Vec<u8> {
    const ENTRY_BYTES: usize = 32;
    let name: Vec<u16> = "hello.txt".encode_utf16().collect();
    let mut set = vec![0_u8; 3 * ENTRY_BYTES];
    set[0] = 0x85;
    set[1] = 2;
    put_u16(&mut set, 4, 0x20);
    let timestamp = ((2024_u32 - 1980) << 25) | (1 << 21) | (1 << 16);
    for offset in [8, 12, 16] {
        put_u32(&mut set, offset, timestamp);
    }
    set[32] = 0xc0;
    set[33] = 3;
    set[35] = u8::try_from(name.len()).expect("short fixture name");
    put_u64(&mut set, 40, 100);
    put_u32(&mut set, 52, 2);
    put_u64(&mut set, 56, 100);
    set[64] = 0xc1;
    for (slot, unit) in name.into_iter().enumerate() {
        put_u16(&mut set, 66 + slot * 2, unit);
    }

    put_u16(&mut set, 2, 0);
    let checksum = set
        .iter()
        .copied()
        .enumerate()
        .filter(|(index, _)| !matches!(*index, 2 | 3))
        .fold(0_u16, |sum, (_, byte)| {
            sum.rotate_right(1).wrapping_add(u16::from(byte))
        });
    put_u16(&mut set, 2, checksum);
    set.extend_from_slice(&[0_u8; ENTRY_BYTES]);
    set
}

const fn directory_context(max_entries: usize) -> DirectoryContext {
    DirectoryContext {
        cluster_count: 1_000,
        bytes_per_cluster: 4_096,
        number_of_fats: 1,
        is_root: false,
        max_entries,
        max_secondary_entries: 32,
    }
}

fn compressed_upcase_table() -> Vec<u8> {
    let mut encoded = Vec::new();
    for code_unit in 0_u16..128 {
        let mapping = if (u16::from(b'a')..=u16::from(b'z')).contains(&code_unit) {
            code_unit - 0x20
        } else {
            code_unit
        };
        encoded.extend_from_slice(&mapping.to_le_bytes());
    }
    encoded.extend_from_slice(&0xffff_u16.to_le_bytes());
    encoded.extend_from_slice(&65_408_u16.to_le_bytes());
    encoded
}

fn ntfs_file_record() -> Vec<u8> {
    const RECORD_BYTES: usize = 1_024;
    const USA_OFFSET: usize = 48;
    const ATTRIBUTES_OFFSET: usize = 56;
    let mut record = vec![0_u8; RECORD_BYTES];
    record[0..4].copy_from_slice(b"FILE");
    put_u16(
        &mut record,
        4,
        u16::try_from(USA_OFFSET).expect("fixture offset fits u16"),
    );
    put_u16(&mut record, 6, 3);
    put_u64(&mut record, 8, 0x1122_3344_5566_7788);
    put_u16(&mut record, 16, 7);
    put_u16(&mut record, 18, 2);
    put_u16(
        &mut record,
        20,
        u16::try_from(ATTRIBUTES_OFFSET).expect("fixture offset fits u16"),
    );
    put_u16(&mut record, 22, 3);
    put_u32(&mut record, 24, 80);
    put_u32(
        &mut record,
        28,
        u32::try_from(RECORD_BYTES).expect("fixture size fits u32"),
    );
    put_u64(&mut record, 32, (9_u64 << 48) | 0x2a);
    put_u16(&mut record, 40, 12);
    put_u32(&mut record, 44, 99);

    let usn = 0xa55a;
    put_u16(&mut record, USA_OFFSET, usn);
    put_u16(&mut record, USA_OFFSET + 2, 0x1234);
    put_u16(&mut record, USA_OFFSET + 4, 0x5678);
    put_u16(&mut record, 510, usn);
    put_u16(&mut record, 1_022, usn);
    put_u32(&mut record, ATTRIBUTES_OFFSET, 0x10);
    put_u32(&mut record, ATTRIBUTES_OFFSET + 4, 16);
    put_u32(&mut record, ATTRIBUTES_OFFSET + 16, u32::MAX);
    record
}

const fn attribute_limits() -> AttributeLimits {
    AttributeLimits {
        cluster_size_bytes: 4_096,
        max_attribute_bytes: 4_096,
        max_name_code_units: 255,
        max_attributes: 16,
    }
}

fn resident_attribute() -> Vec<u8> {
    let mut bytes = vec![0_u8; 32];
    put_u32(&mut bytes, 0, 0x10);
    put_u32(&mut bytes, 4, 32);
    put_u32(&mut bytes, 16, 4);
    put_u16(&mut bytes, 20, 24);
    bytes[22] = 1;
    bytes[24..28].copy_from_slice(b"DATA");
    bytes
}

fn nonresident_attribute() -> Vec<u8> {
    let mut bytes = vec![0_u8; 72];
    put_u32(&mut bytes, 0, 0x80);
    put_u32(&mut bytes, 4, 72);
    bytes[8] = 1;
    put_i64(&mut bytes, 16, 0);
    put_i64(&mut bytes, 24, 1);
    put_u16(&mut bytes, 32, 64);
    put_i64(&mut bytes, 40, 8_192);
    put_i64(&mut bytes, 48, 7_000);
    put_i64(&mut bytes, 56, 6_000);
    bytes[64..68].copy_from_slice(&[0x11, 2, 5, 0]);
    bytes
}

const fn mapping_limits() -> MappingPairsLimits {
    MappingPairsLimits {
        starting_vcn: 10,
        expected_next_vcn: Some(19),
        volume_cluster_count: 1_000,
        max_runs: 32,
        max_decoded_clusters: 1_000,
    }
}

#[test]
fn boot_sector_parsers_reject_every_truncation_without_panicking() {
    let exfat = exfat_boot_sector();
    let ntfs = ntfs_boot_sector();
    for length in 0..exfat.len() {
        no_panic("exFAT boot truncation", || {
            assert!(exfat::parse_boot_sector(&exfat[..length]).is_err());
        });
        no_panic("NTFS boot truncation", || {
            assert!(ntfs::parse_boot_sector(&ntfs[..length]).is_err());
        });
    }
    assert!(exfat::parse_boot_sector(&exfat).is_ok());
    assert!(ntfs::parse_boot_sector(&ntfs).is_ok());
}

#[test]
fn boot_sector_critical_fields_are_not_silently_accepted() {
    let exfat = exfat_boot_sector();
    for offset in (0..11).chain(11..64).chain(104..111).chain(510..512) {
        let mut mutated = exfat.clone();
        mutated[offset] ^= 1;
        assert!(
            exfat::parse_boot_sector(&mutated).is_err(),
            "exFAT accepted critical mutation at {offset}"
        );
    }

    let ntfs = ntfs_boot_sector();
    let always_invalid_ntfs_offsets = [
        3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 22, 23, 32, 33, 34, 35,
        39, 65, 66, 67, 69, 70, 71, 510, 511,
    ];
    for offset in always_invalid_ntfs_offsets {
        let mut mutated = ntfs.clone();
        mutated[offset] ^= 1;
        assert!(
            ntfs::parse_boot_sector(&mutated).is_err(),
            "NTFS accepted critical mutation at {offset}"
        );
    }
}

#[test]
fn boot_region_validators_are_total_and_checksum_protected() {
    let region = exfat_region();
    for length in 0..region.len() {
        no_panic("exFAT region truncation", || {
            assert!(
                validate_exfat_region(&region[..length], 512, ExfatBootRegionKind::Main).is_err()
            );
        });
    }
    assert!(validate_exfat_region(&region, 512, ExfatBootRegionKind::Main).is_ok());

    let mut both_regions = Vec::with_capacity(region.len() * 2);
    both_regions.extend_from_slice(&region);
    both_regions.extend_from_slice(&region);
    for length in 0..both_regions.len() {
        no_panic("combined exFAT region truncation", || {
            assert!(validate_exfat_regions(&both_regions[..length], 512).is_err());
        });
    }
    assert!(validate_exfat_regions(&both_regions, 512).is_ok());

    for offset in (0..106).chain(108..112).chain(113..region.len()) {
        let mut mutated = region.clone();
        mutated[offset] ^= 1;
        assert!(
            validate_exfat_region(&mutated, 512, ExfatBootRegionKind::Main).is_err(),
            "exFAT region accepted checksummed mutation at {offset}"
        );
    }

    let primary = ntfs_boot_sector();
    let partition_bytes = (NTFS_DECLARED_SECTORS + 1) * 512;
    for length in 0..primary.len() {
        no_panic("NTFS primary region truncation", || {
            let _ = validate_ntfs_region(
                &primary[..length],
                &primary,
                partition_bytes,
                partition_bytes - 512,
            );
        });
        no_panic("NTFS backup region truncation", || {
            let _ = validate_ntfs_region(
                &primary,
                &primary[..length],
                partition_bytes,
                partition_bytes - 512,
            );
        });
    }
    for offset in 0..primary.len() {
        let mut backup = primary.clone();
        backup[offset] ^= 1;
        assert!(
            validate_ntfs_region(&primary, &backup, partition_bytes, partition_bytes - 512,)
                .is_err(),
            "NTFS accepted divergent backup byte {offset}"
        );
    }
}

#[test]
fn exfat_directory_truncations_and_entry_set_mutations_are_bounded() {
    let directory = exfat_directory();
    for length in 0..directory.len() {
        no_panic(
            "exFAT directory truncation",
            AssertUnwindSafe(|| {
                let _ = parse_directory(&directory[..length], directory_context(128), |_| {});
            }),
        );
    }
    assert!(
        parse_directory(&directory, directory_context(128), |_| {}).is_ok(),
        "canonical directory fixture"
    );

    for offset in 0..96 {
        let mut mutated = directory.clone();
        mutated[offset] ^= 1;
        assert!(
            parse_directory(&mutated, directory_context(128), |_| {}).is_err(),
            "directory accepted protected entry-set mutation at {offset}"
        );
    }

    no_panic(
        "directory work cap",
        AssertUnwindSafe(|| {
            assert!(parse_directory(&directory, directory_context(1), |_| {}).is_err());
        }),
    );
}

#[test]
fn exfat_upcase_truncations_and_mutations_are_rejected() {
    let encoded = compressed_upcase_table();
    let checksum = table_checksum(&encoded);
    assert!(UpcaseTable::parse(&encoded, checksum, UpcaseLimits::COMPLETE_TABLE).is_ok());

    for length in 0..encoded.len() {
        no_panic("exFAT upcase truncation", || {
            assert!(
                UpcaseTable::parse(
                    &encoded[..length],
                    table_checksum(&encoded[..length]),
                    UpcaseLimits::COMPLETE_TABLE,
                )
                .is_err()
            );
        });
    }
    for offset in 0..encoded.len() {
        let mut mutated = encoded.clone();
        mutated[offset] ^= 1;
        assert!(
            UpcaseTable::parse(&mutated, checksum, UpcaseLimits::COMPLETE_TABLE).is_err(),
            "upcase table accepted checksum-protected mutation at {offset}"
        );
    }

    for length in 0..encoded.len() {
        no_panic(
            "exFAT upcase visitor truncation",
            AssertUnwindSafe(|| {
                let _ = visit_mappings(
                    &encoded[..length],
                    table_checksum(&encoded[..length]),
                    UpcaseLimits::COMPLETE_TABLE,
                    |_, _| {},
                );
            }),
        );
    }
}

#[test]
fn ntfs_file_record_truncations_and_fixup_mutations_are_rejected() {
    let record = ntfs_file_record();
    for length in 0..record.len() {
        no_panic("NTFS FILE truncation", || {
            assert!(parse_file_record(&record[..length]).is_err());
        });
    }
    let parsed = parse_file_record(&record).expect("canonical FILE fixture");
    assert_eq!(parsed.attribute_count, 1);

    for offset in (0..8).chain(48..50).chain(510..512).chain(1_022..1_024) {
        let mut mutated = record.clone();
        mutated[offset] ^= 1;
        assert!(
            parse_file_record(&mutated).is_err(),
            "FILE parser accepted framing/fixup mutation at {offset}"
        );
    }
}

#[test]
fn ntfs_attribute_parsers_are_total_across_every_prefix() {
    let attribute = resident_attribute();
    for length in 0..attribute.len() {
        no_panic("NTFS attribute truncation", || {
            assert!(parse_attribute(&attribute[..length], attribute_limits()).is_err());
        });
    }
    assert!(parse_attribute(&attribute, attribute_limits()).is_ok());

    let nonresident = nonresident_attribute();
    for length in 0..nonresident.len() {
        no_panic("NTFS non-resident attribute truncation", || {
            assert!(parse_attribute(&nonresident[..length], attribute_limits()).is_err());
        });
    }
    assert!(parse_attribute(&nonresident, attribute_limits()).is_ok());

    for offset in 0..24 {
        let mut mutated = attribute.clone();
        mutated[offset] ^= 1;
        no_panic("NTFS attribute header mutation", || {
            let _ = parse_attribute(&mutated, attribute_limits());
        });
    }

    for (offset, replacement) in [(0, 0_u8), (4, 7), (8, 2)] {
        let mut mutated = attribute.clone();
        mutated[offset] = replacement;
        assert!(
            parse_attribute(&mutated, attribute_limits()).is_err(),
            "attribute accepted invalid structural byte {offset}"
        );
    }

    let record = ntfs_file_record();
    let repaired = parse_file_record(&record)
        .expect("canonical FILE fixture")
        .repaired_bytes()
        .to_vec();
    for length in 0..=repaired.len() {
        no_panic("NTFS attribute-list record prefix", || {
            let used = 80.min(length);
            let _ =
                parse_attribute_list(&repaired[..length], 56.min(used), used, attribute_limits());
        });
    }
}

#[test]
fn ntfs_runlist_parser_is_total_and_rejects_structural_mutations() {
    let runlist = [
        0x11, 3, 5, // Physical run.
        0x11, 2, 0xfe, // Negative LCN delta.
        0x01, 4, // Sparse run.
        0, 0, 0, // Terminator and padding.
    ];
    assert!(parse_mapping_pairs(&runlist, mapping_limits()).is_ok());
    for length in 0..runlist.len() {
        no_panic("NTFS runlist truncation", || {
            let _ = parse_mapping_pairs(&runlist[..length], mapping_limits());
        });
    }

    for offset in [0, 3, 6, 8, 9, 10] {
        let mut mutated = runlist;
        mutated[offset] = if offset == 8 {
            0x90
        } else {
            mutated[offset] ^ if offset < 8 { 0xf0 } else { 1 }
        };
        assert!(
            parse_mapping_pairs(&mutated, mapping_limits()).is_err(),
            "runlist accepted structural mutation at {offset}"
        );
    }
}

#[test]
fn ntfs_bitmap_prefixes_are_bounded_and_tail_corruption_is_rejected() {
    let cluster_count = 65;
    let bitmap = [0xff_u8; 16];
    assert!(parse_bitmap(cluster_count, &bitmap).is_ok());
    for length in 0..bitmap.len() {
        no_panic("NTFS bitmap truncation", || {
            assert!(parse_bitmap(cluster_count, &bitmap[..length]).is_err());
        });
    }

    for tail_bit in 65..128 {
        let mut mutated = bitmap;
        let byte = tail_bit / 8;
        let shift = tail_bit % 8;
        mutated[byte] &= !(1_u8 << shift);
        assert!(
            parse_bitmap(cluster_count, &mutated).is_err(),
            "bitmap accepted clear reserved tail bit {tail_bit}"
        );
    }

    for data_bit in 0..65 {
        let mut mutated = bitmap;
        let byte = data_bit / 8;
        let shift = data_bit % 8;
        mutated[byte] ^= 1_u8 << shift;
        no_panic("NTFS bitmap allocation mutation", || {
            assert!(parse_bitmap(cluster_count, &mutated).is_ok());
        });
    }
}
