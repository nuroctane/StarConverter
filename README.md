<div align="center">

```text
                 *
             .  /|\  .
          ---<  /_\  >---
             ' /___\ '
        [ S T A R :: C O N V E R T E R ]
              DATA STAYS PUT
```

# StarConverter

**A careful, cross-platform exFAT <-> NTFS conversion workbench.**

`ANALYZE  /  PLAN  /  CONVERT  /  VERIFY  /  ROLLBACK`

</div>

StarConverter is being built to convert compatible exFAT and NTFS volumes without copying every
file to another disk. The design keeps file-data extents in place where possible, relocates only
conflicts, constructs new filesystem metadata transactionally, and retains an explicit rollback
record until the user finalizes the conversion.

This repository is an engineering scaffold, not a drive-writing release. The current executables
perform deterministic planning against synthetic volume descriptions. **They do not write raw
devices.** That boundary is deliberate.

## Product shape

StarConverter aims for the utility-first clarity of HandBrake and 7-Zip:

- one obvious source selector;
- one obvious destination filesystem;
- a preflight report before any write;
- exact blockers and required temporary space;
- a conversion queue with durable logs;
- verify and rollback actions that are as visible as convert;
- portable builds with no account, cloud service, telemetry, or daemon.

The interface uses a near-black canvas, hard one-pixel rules, monospaced labels, bracketed states,
and restrained status color. ASCII is structural language throughout the app: `[READY]`, `::`,
`+---+`, paths, phases, and audit output all use the same grammar. See
[`docs/DESIGN_SYSTEM.md`](docs/DESIGN_SYSTEM.md).

## Losslessness contract

The word *lossless* is split into explicit modes because NTFS can represent metadata that exFAT
cannot:

| Mode | Promise |
| --- | --- |
| **Strict** | Refuse any object that cannot round-trip natively. |
| **Escrow** | Preserve ordinary exFAT usability and store NTFS-only semantics in a checksummed capsule for restoration. |
| **Content only** | Preserve file bytes and common metadata, with no full semantic round-trip promise. |

No mode can protect against physical media failure, faulty firmware, bad RAM, or a device that lies
about completed cache flushes. A backup remains mandatory for valuable data.

## Architecture

```text
+--------------------------- STARCONVERTER ----------------------------+
|                                                                      |
|  desktop (Rust/egui)       CLI (Rust)                                |
|          |                    |                                      |
|          +----------+---------+                                      |
|                     v                                                |
|       core planner + capability model (safe Rust)                    |
|                     |                                                |
|       parser -> extent graph -> space plan -> transaction plan       |
|                     |                                                |
|       image backend first / physical backend behind safety gate      |
|                                                                      |
|  Go lab: image matrix -> fault injection -> verifier -> fixtures     |
+----------------------------------------------------------------------+
```

- **Rust** owns parsers, planning, transaction logic, CLI, and the native desktop application.
- **Go** owns disposable test-image orchestration and the crash/recovery matrix.
- The conversion engine will use explicit backend traits so image files and physical devices share
  logic without sharing authorization.

Read [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and [`docs/SAFETY.md`](docs/SAFETY.md) before
adding a write path.

## Repository layout

```text
StarConverter/
|-- crates/
|   |-- starconverter-core/   safety model and conversion planner
|   |-- starconverter-cli/    scriptable analysis frontend
|   `-- starconverter-gui/    native cross-platform desktop shell
|-- lab/                      Go image/crash-test harness
|-- docs/                     architecture, UX, safety, roadmap
|-- scripts/                  local verification entrypoints
|-- .github/workflows/        Rust + Go cross-platform CI
|-- AGENTS.md                 repository safety and ship rules
`-- SHIP.md                   commit/push/backup contract
```

## Build

Requirements:

- Rust stable (the checked-in toolchain supplies `rustfmt` and Clippy)
- Go 1.23+ for the lab harness

```powershell
cargo build --workspace
cargo test --workspace
cargo run -p starconverter-cli -- demo
cargo run -p starconverter-gui
```

The Go toolchain is only required for `lab/`:

```powershell
cd lab
go test ./...
go run ./cmd/starconverter-lab matrix
```

On Windows, `scripts/check.ps1` runs the available local checks and clearly reports when Go is not
installed. CI always tests both language stacks.

## Current status

`v0.1 scaffold`

- [x] Buildable Rust workspace
- [x] Shared conversion capability and safety model
- [x] Analysis-only CLI
- [x] Native ASCII-black desktop shell
- [x] Go crash-test matrix scaffold
- [x] Cross-platform CI and repository shipping policy
- [ ] Read-only exFAT parser
- [ ] Read-only NTFS parser
- [ ] Exact extent and metadata planner
- [ ] Image-only exFAT -> NTFS strict converter
- [ ] Injected-crash recovery suite
- [ ] Image-only NTFS -> exFAT converter and semantic escrow
- [ ] Explicitly gated physical-volume support

The staged implementation plan lives in [`docs/ROADMAP.md`](docs/ROADMAP.md).

## Safety and security

- No raw-device write code exists in the initial scaffold.
- Analysis must work without administrator/root privileges.
- Every future write is represented in a transaction plan before execution.
- Volume identity is pinned before lock/dismount and checked again afterward.
- Source boot and metadata sectors are preserved before they can be overwritten.
- Target boot activation is the final commit point; rollback remains available until finalize.

Please report safety defects privately before publishing a proof of concept. See
[`SECURITY.md`](SECURITY.md).

## License

Copyright (c) 2026 Nur Octane. All rights reserved. See [`LICENSE`](LICENSE).
