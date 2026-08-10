use std::env;
use std::process::ExitCode;

use starconverter_core::{
    FileSystem, GuaranteeMode, Planner, SemanticFeature, Severity, VolumeProfile, VolumeRole,
    VolumeState,
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
        "plan" => plan_command(&args[1..])?,
        unknown => return Err(format!("unknown command `{unknown}`")),
    }

    Ok(())
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
        free_bytes: free_gib.saturating_mul(gib),
        logical_sector_bytes: 512,
        cluster_bytes: 128 * 1024,
        state: VolumeState {
            clean: true,
            mounted: false,
        },
        role: VolumeRole {
            system_volume: false,
            encrypted_container: false,
        },
        features,
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
    println!("+-- PREFLIGHT --------------------------------------------------------+");
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
    println!("| free        : {}", format_bytes(plan.source.free_bytes));
    println!(
        "| reservation : {}",
        format_bytes(plan.required_temporary_bytes)
    );
    println!("+-------------------------------------------------------------------+");

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
    if bytes >= GIB {
        format_binary(bytes, GIB, "GiB")
    } else {
        format_binary(bytes, MIB, "MiB")
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
    println!("Analysis-only filesystem conversion workbench\n");
    println!("USAGE");
    println!("  starconverter demo");
    println!("  starconverter plan [OPTIONS]\n");
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
    println!("  This scaffold does not parse or mutate the supplied path yet.");
}

#[cfg(test)]
mod tests {
    use super::*;

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
    }
}
