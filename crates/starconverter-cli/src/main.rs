// Rust 1.85 Clippy misattributes this lint to an import span after the policy renderer's valid
// `format!` calls. Newer Clippy versions correctly recognize them as formatting arguments.
#![allow(clippy::literal_string_with_formatting_args)]

use std::env;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use starconverter_core::candidate_export::{
    CandidateExportEvidence, CandidateExportLimits, export_candidate_image,
};
use starconverter_core::cross_format::{
    ExfatToNtfsLimits, ExfatToNtfsOptions, NtfsToExfatLimits, NtfsToExfatOptions,
    plan_lossless_exfat_to_ntfs, plan_lossless_ntfs_to_exfat,
};
use starconverter_core::fs::exfat_normalize::NormalizedExfat;
use starconverter_core::fs::exfat_region::ExfatBootRegionComparison;
use starconverter_core::fs::ntfs_normalize::NormalizedNtfs;
use starconverter_core::geometry::{DestinationReservation, SourceAllocation};
use starconverter_core::image::ImageFile;
use starconverter_core::inspect::{
    BootRedundancy, BootSector, ImageInspection, inspect_image, inspect_open_image,
};
use starconverter_core::phase::{
    PhaseWritePreview, preview_exfat_phase_writes, preview_ntfs_phase_writes,
};
use starconverter_core::preimage::PreimageLimits;
use starconverter_core::preservation::{
    FieldAssessment, PreservationField, PreservationLimits, PreservationReport, evaluate_exfat,
    evaluate_ntfs,
};
use starconverter_core::{
    AccessState, FileSystem, GuaranteeMode, HealthState, Planner, SemanticFeature, Severity,
    VolumeProfile, VolumeRole, VolumeState,
};

const BANNER: &str = r"
                 *
             .  /|\  .
          ---<  /_\  >---
             ' /___\ '
        [ S T A R :: C O N V E R T E R ]
              DATA STAYS PUT
";

fn main() -> ExitCode {
    let args = env::args().skip(1).collect::<Vec<_>>();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("[ERROR] {message}");
            eprintln!("Run `starconverter --help` for usage.");
            ExitCode::from(2)
        }
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let Some(command) = args.first().map(String::as_str) else {
        print_help();
        return Ok(());
    };

    match command {
        "-h" | "--help" | "help" => print_help(),
        "-V" | "--version" | "version" => {
            println!("starconverter {}", env!("CARGO_PKG_VERSION"));
        }
        "demo" => print_plan(&Planner.plan(
            &VolumeProfile::demo_exfat(),
            FileSystem::Ntfs,
            GuaranteeMode::Strict,
        )),
        "inspect" => inspect_command(&args[1..])?,
        "preview" => preview_command(&args[1..])?,
        "convert-image" => convert_image_command(&args[1..])?,
        "plan" => plan_command(&args[1..])?,
        unknown => return Err(format!("unknown command `{unknown}`")),
    }

    Ok(())
}

fn convert_image_command(args: &[String]) -> Result<(), String> {
    let source = args
        .first()
        .ok_or_else(|| "convert-image requires a source image path".to_owned())?;
    let output = args
        .get(1)
        .ok_or_else(|| "convert-image requires a new output image path".to_owned())?;
    let source_image = ImageFile::open(source).map_err(|error| error.to_string())?;
    let inspection = inspect_open_image(&source_image).map_err(|error| error.to_string())?;
    let mut target = match inspection.profile.filesystem {
        FileSystem::ExFat => FileSystem::Ntfs,
        FileSystem::Ntfs => FileSystem::ExFat,
        FileSystem::Unknown => return Err("recognized image has unknown filesystem".into()),
    };
    let mut mode = GuaranteeMode::Escrow;
    let mut escrow_override = None;
    parse_convert_options(&args[2..], &mut target, &mut mode, &mut escrow_override)?;
    if mode == GuaranteeMode::ContentOnly {
        return Err(
            "convert-image supports only strict or escrow losslessness; content-only is preview-only"
                .into(),
        );
    }
    if target == inspection.profile.filesystem {
        return Err("convert-image target must differ from the source filesystem".into());
    }

    let output_path = PathBuf::from(output);
    let evidence = match (
        inspection.normalized_exfat.as_deref(),
        inspection.normalized_ntfs.as_deref(),
        target,
    ) {
        (Some(normalized), None, FileSystem::Ntfs) => export_exfat_source(
            &source_image,
            normalized,
            &output_path,
            mode,
            escrow_override.as_deref(),
        )?,
        (None, Some(normalized), FileSystem::ExFat) => export_ntfs_source(
            &source_image,
            normalized,
            &output_path,
            mode,
            escrow_override.as_deref(),
        )?,
        (Some(_), None, _) | (None, Some(_), _) => {
            return Err("convert-image direction does not match the inspected source".into());
        }
        (None, None, _) => {
            return Err("complete normalized inventory is required for conversion".into());
        }
        (Some(_), Some(_), _) => {
            return Err("inspection contains evidence for two filesystems".into());
        }
    };

    println!("{BANNER}");
    println!(
        "[COMPLETE] copy-based {} candidate exported",
        evidence.target_filesystem
    );
    println!("[OUTPUT]   {}", evidence.output_path.display());
    if let Some(path) = &evidence.escrow_path {
        println!("[ESCROW]   {}", path.display());
    }
    println!(
        "[VERIFIED] {} writes / {} replaced / manifest {}",
        evidence.applied_writes,
        format_bytes(evidence.replacement_bytes),
        hex_digest(&evidence.manifest_sha256)
    );
    println!(
        "[CANDIDATE] sha256 {}",
        hex_digest(&evidence.candidate_sha256)
    );
    println!(
        "[SOURCE UNCHANGED] {} bytes / sha256 {}",
        evidence.image_bytes,
        hex_digest(&evidence.source_sha256)
    );
    println!(
        "[SAFE] Output paths were create-new; no existing file or device was opened for write."
    );
    println!("[QUALIFICATION] In-place activation remains locked behind serializer/Windows gates.");
    Ok(())
}

fn export_exfat_source(
    source: &ImageFile,
    normalized: &NormalizedExfat,
    output: &Path,
    mode: GuaranteeMode,
    requested_escrow: Option<&Path>,
) -> Result<CandidateExportEvidence, String> {
    let plan = plan_lossless_exfat_to_ntfs(
        normalized,
        mode,
        ExfatToNtfsOptions::default(),
        ExfatToNtfsLimits::default(),
    )
    .map_err(|error| format!("cross-format plan refused: {error}"))?;
    let preview = preview_ntfs_phase_writes(source, &plan.destination, PreimageLimits::default())
        .map_err(|error| format!("phase preview failed: {error}"))?;
    let escrow_path = select_escrow_path(output, &plan.preservation, requested_escrow)?;
    export_candidate_image(
        source,
        output,
        escrow_path.as_deref(),
        &preview,
        &plan.target_graph,
        &plan.preservation,
        CandidateExportLimits::default(),
    )
    .map_err(|error| format!("candidate export failed: {error}"))
}

fn export_ntfs_source(
    source: &ImageFile,
    normalized: &NormalizedNtfs,
    output: &Path,
    mode: GuaranteeMode,
    requested_escrow: Option<&Path>,
) -> Result<CandidateExportEvidence, String> {
    let plan = plan_lossless_ntfs_to_exfat(
        normalized,
        mode,
        NtfsToExfatOptions::default(),
        NtfsToExfatLimits::default(),
    )
    .map_err(|error| format!("cross-format plan refused: {error}"))?;
    let preview = preview_exfat_phase_writes(source, &plan.destination, PreimageLimits::default())
        .map_err(|error| format!("phase preview failed: {error}"))?;
    let escrow_path = select_escrow_path(output, &plan.preservation, requested_escrow)?;
    export_candidate_image(
        source,
        output,
        escrow_path.as_deref(),
        &preview,
        &plan.target_graph,
        &plan.preservation,
        CandidateExportLimits::default(),
    )
    .map_err(|error| format!("candidate export failed: {error}"))
}

fn parse_convert_options(
    args: &[String],
    target: &mut FileSystem,
    mode: &mut GuaranteeMode,
    escrow_path: &mut Option<PathBuf>,
) -> Result<(), String> {
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        let value = args
            .get(index + 1)
            .ok_or_else(|| format!("missing value after `{flag}`"))?;
        match flag {
            "--to" => *target = value.parse().map_err(|error| format!("{error}"))?,
            "--mode" => *mode = value.parse().map_err(|error| format!("{error}"))?,
            "--escrow" => *escrow_path = Some(PathBuf::from(value)),
            _ => return Err(format!("unknown convert-image option `{flag}`")),
        }
        index += 2;
    }
    Ok(())
}

fn select_escrow_path(
    output: &Path,
    preservation: &PreservationReport,
    requested: Option<&Path>,
) -> Result<Option<PathBuf>, String> {
    match (preservation.escrow.is_some(), requested) {
        (true, Some(path)) => Ok(Some(path.to_path_buf())),
        (true, None) => {
            let mut name = output.as_os_str().to_os_string();
            name.push(".starconverter-escrow");
            Ok(Some(PathBuf::from(name)))
        }
        (false, Some(_)) => {
            Err("strict conversion has no escrow payload; remove `--escrow`".into())
        }
        (false, None) => Ok(None),
    }
}

fn hex_digest(digest: &[u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in digest {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn preview_command(args: &[String]) -> Result<(), String> {
    let source = args
        .first()
        .ok_or_else(|| "preview requires an image-file path".to_owned())?;
    let image = ImageFile::open(source).map_err(|error| error.to_string())?;
    let inspection = inspect_open_image(&image).map_err(|error| error.to_string())?;
    let mut target = match inspection.profile.filesystem {
        FileSystem::ExFat => FileSystem::Ntfs,
        FileSystem::Ntfs => FileSystem::ExFat,
        FileSystem::Unknown => return Err("recognized image has unknown filesystem".into()),
    };
    let mut mode = GuaranteeMode::Escrow;
    parse_direction_options(&args[1..], "preview", &mut target, &mut mode)?;
    if target == inspection.profile.filesystem {
        return Err("preview target must differ from the source filesystem".to_owned());
    }

    print_inspection(&inspection);
    match (
        inspection.normalized_exfat.as_deref(),
        inspection.normalized_ntfs.as_deref(),
        target,
    ) {
        (Some(normalized), None, FileSystem::Ntfs) => {
            let plan = plan_lossless_exfat_to_ntfs(
                normalized,
                mode,
                ExfatToNtfsOptions::default(),
                ExfatToNtfsLimits::default(),
            )
            .map_err(|error| format!("cross-format plan refused: {error}"))?;
            let preview =
                preview_ntfs_phase_writes(&image, &plan.destination, PreimageLimits::default())
                    .map_err(|error| format!("phase preview failed: {error}"))?;
            print_preservation_policy(Some(&plan.preservation));
            print_transaction_preview(
                &preview,
                &plan.destination.reservations,
                &plan.destination.source_allocations,
            );
        }
        (None, Some(normalized), FileSystem::ExFat) => {
            let plan = plan_lossless_ntfs_to_exfat(
                normalized,
                mode,
                NtfsToExfatOptions::default(),
                NtfsToExfatLimits::default(),
            )
            .map_err(|error| format!("cross-format plan refused: {error}"))?;
            let preview =
                preview_exfat_phase_writes(&image, &plan.destination, PreimageLimits::default())
                    .map_err(|error| format!("phase preview failed: {error}"))?;
            print_preservation_policy(Some(&plan.preservation));
            print_transaction_preview(
                &preview,
                &plan.destination.reservations,
                &plan.destination.source_allocations,
            );
        }
        (Some(_), None, _) | (None, Some(_), _) => {
            return Err("preview direction does not match the inspected source".to_owned());
        }
        (None, None, _) => {
            return Err("complete normalized inventory is required for preview".to_owned());
        }
        (Some(_), Some(_), _) => {
            return Err(
                "inspection unexpectedly contains normalized evidence for two filesystems"
                    .to_owned(),
            );
        }
    }
    Ok(())
}

fn parse_direction_options(
    args: &[String],
    command: &str,
    target: &mut FileSystem,
    mode: &mut GuaranteeMode,
) -> Result<(), String> {
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        let value = args
            .get(index + 1)
            .ok_or_else(|| format!("missing value after `{flag}`"))?;
        match flag {
            "--to" => *target = value.parse().map_err(|error| format!("{error}"))?,
            "--mode" => *mode = value.parse().map_err(|error| format!("{error}"))?,
            _ => return Err(format!("unknown {command} option `{flag}`")),
        }
        index += 2;
    }
    Ok(())
}

fn print_transaction_preview(
    preview: &PhaseWritePreview,
    reservations: &[DestinationReservation],
    allocations: &[SourceAllocation],
) {
    let writes = preview.writes();
    let forward_count =
        writes.target_staging.len() + writes.backup_boot.len() + writes.activation.len();
    let rollback_count = writes.target_staging_rollback.len()
        + writes.backup_boot_rollback.len()
        + writes.activation_rollback.len();
    let forward_bytes = writes
        .target_staging
        .iter()
        .chain(&writes.backup_boot)
        .chain(&writes.activation)
        .map(|write| write.write.bytes.len())
        .sum::<usize>();
    let rollback_bytes = writes
        .target_staging_rollback
        .iter()
        .chain(&writes.backup_boot_rollback)
        .chain(&writes.activation_rollback)
        .map(|write| write.bytes.len())
        .sum::<usize>();
    let staging_exclusions = allocations.iter().filter(|value| !value.movable).count();

    println!("+-- EXACT TRANSACTION PREVIEW ---------------------------------------+");
    println!("| target      : {}", preview.target_filesystem());
    println!("| reservations: {}", reservations.len());
    println!("| source spans: {}", allocations.len());
    println!("| non-movable : {staging_exclusions}");
    println!(
        "| forward     : {forward_count} writes / {}",
        format_bytes(u64::try_from(forward_bytes).unwrap_or(u64::MAX))
    );
    println!(
        "| rollback    : {rollback_count} writes / {}",
        format_bytes(u64::try_from(rollback_bytes).unwrap_or(u64::MAX))
    );
    println!(
        "| activation  : {}",
        if preview.activation_ready() {
            "QUALIFIED"
        } else {
            "BLOCKED"
        }
    );
    println!("+-------------------------------------------------------------------+");
    for gap in preview.activation_gaps() {
        println!("[BLOCK] {gap}");
    }
    println!("[READ-ONLY] Exact before-images were captured in memory; no bytes were written.");
    println!("[NO AUTHORITY] This preview cannot be submitted to the mutation executor.");
}

fn inspect_command(args: &[String]) -> Result<(), String> {
    let source = args
        .first()
        .ok_or_else(|| "inspect requires an image-file path".to_owned())?;
    let inspection = inspect_image(source).map_err(|error| error.to_string())?;
    let mut target = match inspection.profile.filesystem {
        FileSystem::ExFat => FileSystem::Ntfs,
        FileSystem::Ntfs => FileSystem::ExFat,
        FileSystem::Unknown => return Err("recognized image has unknown filesystem".into()),
    };
    let mut mode = GuaranteeMode::Strict;

    let mut index = 1;
    while index < args.len() {
        let flag = args[index].as_str();
        let value = args
            .get(index + 1)
            .ok_or_else(|| format!("missing value after `{flag}`"))?;
        match flag {
            "--to" => target = value.parse().map_err(|error| format!("{error}"))?,
            "--mode" => mode = value.parse().map_err(|error| format!("{error}"))?,
            _ => return Err(format!("unknown inspect option `{flag}`")),
        }
        index += 2;
    }

    let policy = evaluate_inspection_policy(&inspection, target, mode)?;
    print_inspection(&inspection);
    print_preservation_policy(policy.as_ref());
    print_plan_body(&Planner.plan(&inspection.profile, target, mode));
    Ok(())
}

fn evaluate_inspection_policy(
    inspection: &ImageInspection,
    target: FileSystem,
    mode: GuaranteeMode,
) -> Result<Option<PreservationReport>, String> {
    match (
        inspection.normalized_exfat.as_deref(),
        inspection.normalized_ntfs.as_deref(),
    ) {
        (Some(normalized), None) => {
            evaluate_exfat(normalized, target, mode, PreservationLimits::default())
                .map(Some)
                .map_err(|error| format!("preservation policy failed: {error}"))
        }
        (None, Some(normalized)) => {
            evaluate_ntfs(normalized, target, mode, PreservationLimits::default())
                .map(Some)
                .map_err(|error| format!("preservation policy failed: {error}"))
        }
        (None, None) => Ok(None),
        (Some(_), Some(_)) => Err(
            "inspection unexpectedly contains normalized evidence for two filesystems".to_owned(),
        ),
    }
}

fn print_preservation_policy(report: Option<&PreservationReport>) {
    print!("{}", render_preservation_policy(report));
}

#[allow(clippy::format_push_string)]
fn render_preservation_policy(report: Option<&PreservationReport>) -> String {
    let mut output = String::new();
    output.push_str("+-- PRESERVATION POLICY ---------------------------------------------+\n");
    let Some(report) = report else {
        output.push_str("| status      : UNAVAILABLE (complete normalized inventory required)\n");
        output.push_str("+-------------------------------------------------------------------+\n");
        output.push_str(
            "[READ-ONLY] No preservation payload was produced without normalized evidence.\n",
        );
        return output;
    };

    output.push_str(&format!(
        "| direction   : {} -> {}",
        report.source, report.target
    ));
    output.push('\n');
    output.push_str(&format!("| mode        : {}\n", report.mode));
    output.push_str(&format!(
        "| status      : {}",
        if report.permitted {
            "PERMITTED"
        } else {
            "REFUSED"
        }
    ));
    output.push('\n');
    output.push_str(&format!("| blockers    : {}\n", report.blockers.len()));
    output.push_str(&format!(
        "| losses      : {}\n",
        report.explicit_losses.len()
    ));
    match &report.escrow {
        Some(bytes) => output.push_str(&format!(
            "| escrow      : schema v{} / {} bytes (memory-only analysis)",
            report.schema_version,
            bytes.len()
        )),
        None => output.push_str("| escrow      : none"),
    }
    output.push('\n');
    output.push_str("+-------------------------------------------------------------------+\n");

    for field in &report.blockers {
        if let Some(assessment) = assessment_for(report, *field) {
            output.push_str(&format!(
                "[BLOCK] {} :: {}",
                preservation_field_label(*field),
                assessment.reason
            ));
            output.push('\n');
        }
    }
    if !report.explicit_losses.is_empty() {
        output.push_str("[LOSS] ");
        for (index, field) in report.explicit_losses.iter().enumerate() {
            if index != 0 {
                output.push_str(", ");
            }
            output.push_str(preservation_field_label(*field));
        }
        output.push('\n');
    }
    output.push_str("[READ-ONLY] Policy evaluation did not write an image or escrow file.\n\n");
    output
}

fn assessment_for(
    report: &PreservationReport,
    field: PreservationField,
) -> Option<&FieldAssessment> {
    report
        .assessments
        .iter()
        .find(|assessment| assessment.field == field)
}

const fn preservation_field_label(field: PreservationField) -> &'static str {
    match field {
        PreservationField::Content => "file content",
        PreservationField::ObjectKinds => "object kinds",
        PreservationField::DirectoryHierarchy => "directory hierarchy",
        PreservationField::AlternateDataStreams => "alternate data streams",
        PreservationField::HardLinks => "hard links",
        PreservationField::SecurityDescriptors => "security descriptors",
        PreservationField::SecurityIdentifiers => "security identifiers",
        PreservationField::SparseAllocation => "sparse allocation",
        PreservationField::Compression => "compression",
        PreservationField::Encryption => "encryption",
        PreservationField::ReparsePoints => "reparse points",
        PreservationField::Timestamps => "timestamps and precision",
        PreservationField::DosAttributes => "DOS attributes",
        PreservationField::NamesAndCase => "names and case",
        PreservationField::NtfsNameNamespaces => "NTFS name namespaces",
        PreservationField::CaseMappingTable => "case-mapping table",
        PreservationField::VolumeLabel => "volume label",
        PreservationField::VolumeSerial => "volume serial",
        PreservationField::ExfatBenignEntries => "benign exFAT entries",
        PreservationField::ExfatPadding => "exFAT padding",
        PreservationField::BadClusters => "bad clusters",
        PreservationField::FileSystemMetadataExtents => "filesystem metadata extents",
        PreservationField::AllocationTopology => "allocation topology",
        PreservationField::InventoryAccounting => "inventory provenance",
    }
}

#[allow(clippy::too_many_lines)]
fn print_inspection(inspection: &ImageInspection) {
    println!("{BANNER}");
    println!("+-- IMAGE INSPECTION ------------------------------------------------+");
    println!("| source      : {}", inspection.profile.display_name);
    println!("| identity    : {}", inspection.profile.stable_id);
    println!("| filesystem  : {}", inspection.profile.filesystem);
    println!("| image       : {}", format_bytes(inspection.image_bytes));
    println!(
        "| declared    : {}",
        format_bytes(inspection.declared_volume_bytes)
    );
    println!(
        "| sector      : {} B",
        inspection.profile.logical_sector_bytes
    );
    println!(
        "| cluster     : {}",
        format_bytes(u64::from(inspection.profile.cluster_bytes))
    );
    match inspection.boot_sector {
        BootSector::ExFat(boot) => {
            println!("| serial      : {:08X}", boot.volume_serial_number);
            println!("| root cluster: {}", boot.root_directory_cluster);
            println!("| FATs        : {}", boot.number_of_fats);
        }
        BootSector::Ntfs(boot) => {
            println!("| serial      : {:016X}", boot.volume_serial_number);
            println!("| $MFT LCN    : {}", boot.mft_lcn);
            println!("| $MFTMirr LCN: {}", boot.mft_mirror_lcn);
        }
    }
    match &inspection.boot_redundancy {
        BootRedundancy::ExFat(validation) => match validation.comparison {
            ExfatBootRegionComparison::Exact => {
                println!("| redundancy  : main + backup checksummed and exact");
            }
            ExfatBootRegionComparison::EquivalentExceptStaleFields { .. } => {
                println!("| redundancy  : valid; differs only in permitted stale fields");
            }
            ExfatBootRegionComparison::Divergent { .. } => {
                println!("| redundancy  : valid copies diverge; health is unknown");
            }
        },
        BootRedundancy::Ntfs(validation) => println!(
            "| redundancy  : primary + final backup exact ({} trailing sectors)",
            validation.unaddressed_trailing_sectors
        ),
    }
    if let Some(root) = &inspection.exfat_root {
        println!(
            "| allocation  : {} used / {} free clusters",
            root.allocation.allocated_clusters, root.allocation.free_clusters
        );
        println!(
            "| root entries: {} records validated",
            root.directory.records
        );
    }
    if let Some(inventory) = &inspection.exfat_inventory {
        println!(
            "| objects     : {} recursively validated",
            inventory.objects.len()
        );
        println!(
            "| extents     : {} ownership ranges",
            inventory.extents.extents().len()
        );
    }
    if let Some(discovery) = &inspection.ntfs_discovery {
        let found = discovery
            .system_records
            .iter()
            .filter(|record| {
                matches!(
                    record,
                    starconverter_core::fs::ntfs_discovery::SystemRecordEvidence::Found(_)
                )
            })
            .count();
        println!(
            "| MFT mapping : {} extent(s)",
            discovery.mft.runlist.extents.len()
        );
        println!(
            "| NTFS system : {found}/{} records validated",
            discovery.system_records.len()
        );
    }
    if let Some(volume) = &inspection.ntfs_volume {
        if let starconverter_core::fs::ntfs_volume::NtfsVolumeEvidence::Complete(info) =
            volume.volume
        {
            println!(
                "| NTFS version: {}.{} (flags {:04X})",
                info.major_version, info.minor_version, info.flags.raw
            );
        }
        if let starconverter_core::fs::ntfs_volume::NtfsBitmapEvidence::Complete(allocation) =
            volume.bitmap
        {
            println!(
                "| allocation  : {} used / {} free clusters",
                allocation.allocated_clusters, allocation.free_clusters
            );
        }
    }
    if let Some(inventory) = &inspection.ntfs_inventory {
        println!(
            "| objects     : {} NTFS base records ({} scanned)",
            inventory.objects.len(),
            inventory.scanned_records
        );
        println!(
            "| extents     : {} NTFS stream ranges",
            inventory.extents.len()
        );
        if !inventory.is_complete() {
            println!(
                "| incomplete  : {} bounded NTFS condition(s)",
                inventory.incomplete_reasons.len()
            );
        }
        if let Some(secure) = inventory
            .objects
            .iter()
            .find(|object| object.reference.record_number == 9)
        {
            println!("| $Secure data: {} stream(s)", secure.data_streams.len());
        }
    }
    if let Some(normalized) = &inspection.normalized_ntfs {
        println!(
            "| security    : {}",
            match normalized.preservation.security_descriptors {
                starconverter_core::fs::ntfs_normalize::NtfsSecurityDescriptorEvidence::Unavailable =>
                    "descriptor bytes unavailable",
                starconverter_core::fs::ntfs_normalize::NtfsSecurityDescriptorEvidence::PinnedNtfs3gWindows2003 { .. } =>
                    "exact pinned NTFS-3G $Secure:$SDS",
            }
        );
    }
    println!("+-------------------------------------------------------------------+");
    println!("[READ-ONLY] Boot geometry was validated from a regular image file.");
    println!("[NO WRITE] No conversion or image mutation was attempted.");
    if inspection.profile.inventory_complete {
        println!(
            "[INVENTORY] Complete normalized {} object and allocation evidence is available.",
            inspection.profile.filesystem
        );
    } else {
        println!(
            "[INCOMPLETE] NTFS evidence is inventoried but not yet normalized for conversion."
        );
    }
    println!();
}

fn plan_command(args: &[String]) -> Result<(), String> {
    let mut source_path = "image://unnamed".to_owned();
    let mut source_fs = FileSystem::ExFat;
    let mut target_fs = FileSystem::Ntfs;
    let mut mode = GuaranteeMode::Strict;
    let mut size_gib = 64_u64;
    let mut free_gib = 20_u64;
    let mut features = Vec::new();

    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        let value = args
            .get(index + 1)
            .ok_or_else(|| format!("missing value after `{flag}`"))?;
        match flag {
            "--source" => source_path.clone_from(value),
            "--from" => {
                source_fs = value.parse().map_err(|error| format!("{error}"))?;
            }
            "--to" => {
                target_fs = value.parse().map_err(|error| format!("{error}"))?;
            }
            "--mode" => {
                mode = value.parse().map_err(|error| format!("{error}"))?;
            }
            "--size-gib" => {
                size_gib = parse_u64(flag, value)?;
            }
            "--free-gib" => {
                free_gib = parse_u64(flag, value)?;
            }
            "--features" => {
                features = parse_features(value)?;
            }
            _ => return Err(format!("unknown plan option `{flag}`")),
        }
        index += 2;
    }

    if free_gib > size_gib {
        return Err("--free-gib cannot exceed --size-gib".into());
    }

    let gib = 1024_u64.pow(3);
    let source = VolumeProfile {
        display_name: source_path
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or("unnamed")
            .to_owned(),
        stable_id: source_path,
        filesystem: source_fs,
        capacity_bytes: size_gib.saturating_mul(gib),
        free_bytes: Some(free_gib.saturating_mul(gib)),
        logical_sector_bytes: 512,
        cluster_bytes: 128 * 1024,
        state: VolumeState {
            health: HealthState::Clean,
            access: AccessState::Offline,
        },
        role: VolumeRole {
            system_volume: false,
            encrypted_container: false,
        },
        features,
        inventory_complete: true,
    };

    print_plan(&Planner.plan(&source, target_fs, mode));
    Ok(())
}

fn parse_u64(flag: &str, value: &str) -> Result<u64, String> {
    value
        .parse()
        .map_err(|_| format!("`{value}` is not a valid integer for {flag}"))
}

fn parse_features(value: &str) -> Result<Vec<SemanticFeature>, String> {
    if value.trim().is_empty() {
        return Ok(Vec::new());
    }

    value
        .split(',')
        .map(
            |feature| match feature.trim().to_ascii_lowercase().as_str() {
                "acl" | "acls" => Ok(SemanticFeature::AccessControl),
                "ads" | "streams" => Ok(SemanticFeature::AlternateDataStreams),
                "compression" => Ok(SemanticFeature::Compression),
                "efs" | "encrypted" => Ok(SemanticFeature::EncryptedFiles),
                "hardlinks" | "hard-links" => Ok(SemanticFeature::HardLinks),
                "reparse" | "symlinks" => Ok(SemanticFeature::ReparsePoints),
                "sparse" => Ok(SemanticFeature::SparseFiles),
                "case" | "case-collisions" => Ok(SemanticFeature::CaseCollisions),
                unknown => Err(format!("unknown semantic feature `{unknown}`")),
            },
        )
        .collect()
}

fn print_plan(plan: &starconverter_core::ConversionPlan) {
    println!("{BANNER}");
    print_plan_body(plan);
}

fn print_plan_body(plan: &starconverter_core::ConversionPlan) {
    println!("+-- COARSE PREFLIGHT -------------------------------------------------+");
    println!("| source      : {}", plan.source.display_name);
    println!("| identity    : {}", plan.source.stable_id);
    println!(
        "| direction   : {} -> {}",
        plan.source.filesystem, plan.target
    );
    println!("| guarantee   : {}", plan.mode);
    println!(
        "| capacity    : {}",
        format_bytes(plan.source.capacity_bytes)
    );
    println!(
        "| free        : {}",
        plan.source
            .free_bytes
            .map_or_else(|| "unknown".to_owned(), format_bytes)
    );
    println!(
        "| reservation : {}",
        format_bytes(plan.required_temporary_bytes)
    );
    println!("+-------------------------------------------------------------------+");
    println!("[ESTIMATE] This is the coarse planner, not exact serializer geometry.");

    for issue in &plan.issues {
        println!(
            "[{}] {} :: {}",
            issue.severity.token(),
            issue.code,
            issue.message
        );
    }

    println!();
    println!("PHASES");
    for phase in &plan.phases {
        println!(
            "  {:02} :: {:<10} {}",
            phase.number, phase.name, phase.summary
        );
    }

    let status = if plan.is_ready() {
        "READY TO SAVE PLAN"
    } else {
        "BLOCKED"
    };
    println!();
    println!(
        "[{status}] blockers={} warnings={}",
        plan.blocker_count(),
        plan.warning_count()
    );
    println!("[READ-ONLY] Raw-device writes are not present in this build.");

    if plan
        .issues
        .iter()
        .any(|issue| issue.severity == Severity::Blocker)
    {
        println!("[ACTION] Resolve every blocker, then analyze again.");
    }
}

fn format_bytes(bytes: u64) -> String {
    const GIB: u64 = 1_073_741_824;
    const MIB: u64 = 1_048_576;
    const KIB: u64 = 1024;
    if bytes >= GIB {
        format_binary(bytes, GIB, "GiB")
    } else if bytes >= MIB {
        format_binary(bytes, MIB, "MiB")
    } else if bytes >= KIB {
        format_binary(bytes, KIB, "KiB")
    } else {
        format!("{bytes} B")
    }
}

fn format_binary(bytes: u64, unit: u64, suffix: &str) -> String {
    let whole = bytes / unit;
    let mut hundredths = ((bytes % unit) * 100 + unit / 2) / unit;
    if hundredths == 100 {
        hundredths = 0;
        return format!("{}.{hundredths:02} {suffix}", whole + 1);
    }
    format!("{whole}.{hundredths:02} {suffix}")
}

fn print_help() {
    println!("{BANNER}");
    println!("Copy-based filesystem image conversion workbench\n");
    println!("USAGE");
    println!("  starconverter demo");
    println!("  starconverter inspect <IMAGE> [--to exfat|ntfs] [--mode MODE]");
    println!("  starconverter preview <IMAGE> [--to exfat|ntfs] [--mode MODE]");
    println!(
        "  starconverter convert-image <SOURCE> <NEW-OUTPUT> [--to exfat|ntfs] [--mode MODE] [--escrow PATH]"
    );
    println!("  starconverter plan [OPTIONS]\n");
    println!("INSPECT");
    println!(
        "  Opens one regular image read-only, validates boot geometry/redundancy, and preflights it."
    );
    println!("  Raw devices, device namespaces, directories, and oversized reads are rejected.\n");
    println!("PREVIEW");
    println!(
        "  Builds the exact cross-format structural candidate and captures rollback bytes in memory."
    );
    println!(
        "  Default mode is escrow. Remaining serializer gaps keep activation unforgeably blocked.\n"
    );
    println!("CONVERT-IMAGE");
    println!("  Creates a brand-new regular target image; existing paths and devices are refused.");
    println!(
        "  Reinspects the candidate, verifies its namespace/content manifest, and proves the source hash unchanged."
    );
    println!(
        "  Escrow mode writes <NEW-OUTPUT>.starconverter-escrow unless --escrow selects another new path.\n"
    );
    println!("  Conversion accepts strict or escrow mode; content-only remains preview-only.\n");
    println!("PLAN OPTIONS");
    println!("  --source <PATH>       Image path or synthetic identity");
    println!("  --from <exfat|ntfs>   Source filesystem (default: exfat)");
    println!("  --to <exfat|ntfs>     Target filesystem (default: ntfs)");
    println!("  --mode <MODE>         strict, escrow, or content-only");
    println!("  --size-gib <N>        Synthetic capacity (default: 64)");
    println!("  --free-gib <N>        Synthetic free space (default: 20)");
    println!("  --features <CSV>      acl,ads,compression,efs,hardlinks,reparse,sparse,case");
    println!();
    println!("NOTE");
    println!(
        "  `inspect` recursively validates exFAT objects and bootstraps bounded NTFS `$MFT` evidence."
    );
    println!("  `plan --source` remains a synthetic model and does not open the supplied path.");
    println!(
        "  `convert-image` writes only create-new regular output files. No command mutates a source image or physical drive."
    );
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TempImage(PathBuf);

    impl TempImage {
        fn write(kind: &str, bytes: &[u8]) -> Self {
            let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "starconverter-cli-{kind}-{}-{sequence}.img",
                std::process::id()
            ));
            fs::write(&path, bytes).expect("write regular-file CLI fixture");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempImage {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
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

    fn exfat_boot_checksum(region: &[u8]) -> u32 {
        region[..11 * 512]
            .iter()
            .copied()
            .enumerate()
            .filter(|(offset, _)| !matches!(offset, 106 | 107 | 112))
            .fold(0_u32, |checksum, (_, byte)| {
                checksum.rotate_right(1).wrapping_add(u32::from(byte))
            })
    }

    fn encoded_upcase() -> Vec<u8> {
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

    fn exfat_image() -> Vec<u8> {
        const SECTOR_BYTES: usize = 512;
        const VOLUME_SECTORS: u64 = 2_048;

        let mut image = vec![0_u8; usize::try_from(VOLUME_SECTORS * 512).expect("fixture size")];
        image[0..3].copy_from_slice(&[0xeb, 0x76, 0x90]);
        image[3..11].copy_from_slice(b"EXFAT   ");
        put_u64(&mut image, 72, VOLUME_SECTORS);
        put_u32(&mut image, 80, 24);
        put_u32(&mut image, 84, 16);
        put_u32(&mut image, 88, 40);
        put_u32(&mut image, 92, 2_008);
        put_u32(&mut image, 96, 2);
        put_u32(&mut image, 100, 0x1234_abcd);
        put_u16(&mut image, 104, 0x0100);
        image[108] = 9;
        image[110] = 1;
        image[112] = 0xff;
        put_u16(&mut image, 510, 0xaa55);

        for sector in 1..=8 {
            let signature = sector * SECTOR_BYTES + SECTOR_BYTES - 4;
            image[signature..signature + 4].copy_from_slice(&[0x00, 0x00, 0x55, 0xaa]);
        }
        let checksum = exfat_boot_checksum(&image);
        for offset in (11 * SECTOR_BYTES..12 * SECTOR_BYTES).step_by(4) {
            put_u32(&mut image, offset, checksum);
        }
        image.copy_within(0..12 * SECTOR_BYTES, 12 * SECTOR_BYTES);
        for cluster in [2_u32, 3, 4] {
            put_u32(
                &mut image,
                24 * SECTOR_BYTES + usize::try_from(cluster).expect("cluster index") * 4,
                u32::MAX,
            );
        }
        let root = 40 * SECTOR_BYTES;
        image[root] = 0x81;
        put_u32(&mut image, root + 20, 3);
        put_u64(&mut image, root + 24, 251);
        let upcase = encoded_upcase();
        image[root + 32] = 0x82;
        put_u32(
            &mut image,
            root + 36,
            starconverter_core::fs::exfat_upcase::table_checksum(&upcase),
        );
        put_u32(&mut image, root + 52, 4);
        put_u64(
            &mut image,
            root + 56,
            u64::try_from(upcase.len()).expect("upcase length"),
        );
        image[41 * SECTOR_BYTES] = 0b0000_0111;
        image[42 * SECTOR_BYTES..42 * SECTOR_BYTES + upcase.len()].copy_from_slice(&upcase);
        image
    }

    fn ntfs_image() -> Vec<u8> {
        const SECTOR_BYTES: usize = 512;
        const IMAGE_SECTORS: usize = 2_048;

        let mut image = vec![0_u8; IMAGE_SECTORS * SECTOR_BYTES];
        image[0..3].copy_from_slice(&[0xeb, 0x52, 0x90]);
        image[3..11].copy_from_slice(b"NTFS    ");
        put_u16(&mut image, 11, 512);
        image[13] = 8;
        image[21] = 0xf8;
        put_i64(&mut image, 40, 2_047);
        put_i64(&mut image, 48, 4);
        put_i64(&mut image, 56, 128);
        image[64] = (-10_i8).to_ne_bytes()[0];
        image[68] = 1;
        put_u64(&mut image, 72, 0x0123_4567_89ab_cdef);
        put_u16(&mut image, 510, 0xaa55);
        let mft_offset = 4 * 4096;
        image[mft_offset..mft_offset + 1024].copy_from_slice(&ntfs_file_record(0, true));
        for record_number in 1_u32..8 {
            let offset = mft_offset + usize::try_from(record_number).expect("record number") * 1024;
            image[offset..offset + 1024].copy_from_slice(&ntfs_file_record(record_number, false));
        }
        let backup_offset = (IMAGE_SECTORS - 1) * SECTOR_BYTES;
        let (prefix, suffix) = image.split_at_mut(backup_offset);
        suffix[..SECTOR_BYTES].copy_from_slice(&prefix[..SECTOR_BYTES]);
        image
    }

    #[allow(clippy::too_many_lines)]
    fn ntfs_file_record(record_number: u32, mft_data: bool) -> Vec<u8> {
        let mut record = vec![0_u8; 1024];
        record[0..4].copy_from_slice(b"FILE");
        put_u16(&mut record, 4, 48);
        put_u16(&mut record, 6, 3);
        put_u16(&mut record, 16, 1);
        put_u16(&mut record, 18, 1);
        put_u16(&mut record, 20, 56);
        let flags = if record_number == 5 {
            7
        } else if matches!(record_number, 0 | 1 | 3 | 6) {
            5
        } else {
            0
        };
        put_u16(&mut record, 22, flags);
        put_u32(&mut record, 28, 1024);
        put_u16(&mut record, 40, 1);
        put_u32(&mut record, 44, record_number);
        let used = if mft_data {
            let attribute = 56;
            put_u32(&mut record, attribute, 0x80);
            put_u32(&mut record, attribute + 4, 72);
            record[attribute + 8] = 1;
            put_i64(&mut record, attribute + 16, 0);
            put_i64(&mut record, attribute + 24, 1);
            put_u16(&mut record, attribute + 32, 64);
            put_i64(&mut record, attribute + 40, 8192);
            put_i64(&mut record, attribute + 48, 8192);
            put_i64(&mut record, attribute + 56, 8192);
            record[attribute + 64..attribute + 68].copy_from_slice(&[0x11, 2, 4, 0]);
            put_u32(&mut record, attribute + 72, u32::MAX);
            136
        } else if record_number == 3 {
            let attribute = 56;
            put_u32(&mut record, attribute, 0x70);
            put_u32(&mut record, attribute + 4, 40);
            put_u32(&mut record, attribute + 16, 12);
            put_u16(&mut record, attribute + 20, 24);
            record[attribute + 32] = 3;
            record[attribute + 33] = 1;
            put_u32(&mut record, attribute + 40, u32::MAX);
            104
        } else if record_number == 5 {
            let standard = 56;
            put_u32(&mut record, standard, 0x10);
            put_u32(&mut record, standard + 4, 72);
            put_u16(&mut record, standard + 14, 1);
            put_u32(&mut record, standard + 16, 48);
            put_u16(&mut record, standard + 20, 24);
            put_u32(&mut record, standard + 24 + 32, 0x10);

            let file_name = standard + 72;
            put_u32(&mut record, file_name, 0x30);
            put_u32(&mut record, file_name + 4, 96);
            put_u16(&mut record, file_name + 14, 2);
            put_u32(&mut record, file_name + 16, 68);
            put_u16(&mut record, file_name + 20, 24);
            put_u64(&mut record, file_name + 24, (u64::from(1_u16) << 48) | 5);
            put_u32(&mut record, file_name + 24 + 56, 0x10);
            record[file_name + 24 + 64] = 1;
            record[file_name + 24 + 65] = 1;
            put_u16(&mut record, file_name + 24 + 66, u16::from(b'.'));

            let index_root = file_name + 96;
            put_u32(&mut record, index_root, 0x90);
            put_u32(&mut record, index_root + 4, 80);
            record[index_root + 9] = 4;
            put_u16(&mut record, index_root + 10, 24);
            put_u16(&mut record, index_root + 14, 3);
            put_u32(&mut record, index_root + 16, 48);
            put_u16(&mut record, index_root + 20, 32);
            for (index, unit) in "$I30".encode_utf16().enumerate() {
                put_u16(&mut record, index_root + 24 + index * 2, unit);
            }
            let value = index_root + 32;
            put_u32(&mut record, value, 0x30);
            put_u32(&mut record, value + 4, 1);
            put_u32(&mut record, value + 8, 4096);
            record[value + 12] = 8;
            put_u32(&mut record, value + 16, 16);
            put_u32(&mut record, value + 20, 32);
            put_u32(&mut record, value + 24, 32);
            put_u16(&mut record, value + 32 + 8, 16);
            put_u16(&mut record, value + 32 + 12, 2);
            put_u32(&mut record, index_root + 80, u32::MAX);
            index_root + 88
        } else if record_number == 6 {
            let attribute = 56;
            put_u32(&mut record, attribute, 0x80);
            put_u32(&mut record, attribute + 4, 56);
            put_u32(&mut record, attribute + 16, 32);
            put_u16(&mut record, attribute + 20, 24);
            record[attribute + 24] = 0xff;
            record[attribute + 25] = 0x03;
            record[attribute + 55] = 0x80;
            put_u32(&mut record, attribute + 56, u32::MAX);
            120
        } else {
            put_u32(&mut record, 56, u32::MAX);
            64
        };
        put_u32(
            &mut record,
            24,
            u32::try_from(used).expect("fixture record size fits u32"),
        );
        put_u16(&mut record, 48, 0xa55a);
        put_u16(&mut record, 510, 0xa55a);
        put_u16(&mut record, 1022, 0xa55a);
        record
    }

    #[test]
    fn parses_feature_list() {
        let features = parse_features("acl,ads,sparse").expect("features should parse");
        assert_eq!(features.len(), 3);
    }

    #[test]
    fn rejects_unknown_feature() {
        let result = parse_features("acl,telepathy");
        assert!(result.is_err());
    }

    #[test]
    fn formats_binary_units() {
        assert_eq!(format_bytes(1024_u64.pow(3)), "1.00 GiB");
        assert_eq!(format_bytes(4096), "4.00 KiB");
        assert_eq!(format_bytes(512), "512 B");
    }

    #[test]
    fn inspect_requires_an_image_path() {
        assert_eq!(
            run(&["inspect".to_owned()]),
            Err("inspect requires an image-file path".to_owned())
        );
    }

    #[test]
    fn preview_requires_an_image_path() {
        assert_eq!(
            run(&["preview".to_owned()]),
            Err("preview requires an image-file path".to_owned())
        );
    }

    #[test]
    fn convert_image_requires_source_and_output_paths() {
        assert_eq!(
            run(&["convert-image".to_owned()]),
            Err("convert-image requires a source image path".to_owned())
        );
        assert_eq!(
            run(&["convert-image".to_owned(), "source.img".to_owned()]),
            Err("convert-image requires a new output image path".to_owned())
        );
    }

    #[test]
    fn escrow_path_defaults_to_a_sidecar_without_replacing_extension() {
        let report = PreservationReport {
            schema_version: 4,
            source: FileSystem::Ntfs,
            target: FileSystem::ExFat,
            mode: GuaranteeMode::Escrow,
            permitted: true,
            assessments: Vec::new(),
            blockers: Vec::new(),
            explicit_losses: Vec::new(),
            escrow: Some(vec![1]),
        };
        assert_eq!(
            select_escrow_path(Path::new("candidate.img"), &report, None).unwrap(),
            Some(PathBuf::from("candidate.img.starconverter-escrow"))
        );
    }

    #[test]
    fn inspect_accepts_regular_exfat_and_ntfs_images_without_writing_them() {
        for (kind, fixture) in [("exfat", exfat_image()), ("ntfs", ntfs_image())] {
            let image = TempImage::write(kind, &fixture);
            let before = fs::read(image.path()).expect("read fixture before inspection");

            run(&[
                "inspect".to_owned(),
                image.path().to_string_lossy().into_owned(),
            ])
            .expect("inspect regular image");

            let after = fs::read(image.path()).expect("read fixture after inspection");
            assert_eq!(after, before, "inspect must not mutate the {kind} fixture");
        }
    }

    #[test]
    fn inspect_strict_policy_fails_closed_with_reasons() {
        let image = TempImage::write("strict-policy", &exfat_image());
        let inspection = inspect_image(image.path()).expect("inspect fixture");
        let report =
            evaluate_inspection_policy(&inspection, FileSystem::Ntfs, GuaranteeMode::Strict)
                .expect("evaluate policy")
                .expect("normalized policy");
        assert!(!report.permitted);
        assert!(!report.blockers.is_empty());
        let rendered = render_preservation_policy(Some(&report));
        assert!(rendered.contains("| status      : REFUSED"));
        assert!(rendered.contains("[BLOCK]"));
        assert!(rendered.contains("case-mapping table"));
        assert!(rendered.contains("[READ-ONLY]"));
    }

    #[test]
    fn inspect_content_only_enumerates_losses_without_escrow() {
        let image = TempImage::write("content-policy", &exfat_image());
        let inspection = inspect_image(image.path()).expect("inspect fixture");
        let report =
            evaluate_inspection_policy(&inspection, FileSystem::Ntfs, GuaranteeMode::ContentOnly)
                .expect("evaluate policy")
                .expect("normalized policy");
        assert!(!report.explicit_losses.is_empty());
        assert!(report.escrow.is_none());
        let rendered = render_preservation_policy(Some(&report));
        assert!(rendered.contains("[LOSS]"));
        assert!(rendered.contains("| escrow      : none"));
    }

    #[test]
    fn inspect_escrow_reports_schema_and_memory_only_size() {
        let image = TempImage::write("escrow-policy", &exfat_image());
        let inspection = inspect_image(image.path()).expect("inspect fixture");
        let report =
            evaluate_inspection_policy(&inspection, FileSystem::Ntfs, GuaranteeMode::Escrow)
                .expect("evaluate policy")
                .expect("normalized policy");
        let escrow_bytes = report.escrow.as_ref().expect("escrow payload").len();
        let rendered = render_preservation_policy(Some(&report));
        assert!(rendered.contains(&format!(
            "schema v{} / {escrow_bytes} bytes (memory-only analysis)",
            report.schema_version
        )));
        assert!(rendered.contains("did not write an image or escrow file"));
    }
}
