<div align="center">

```text
+---------------------------------------+
| STAR :: CONVERTER                     |
| EXFAT <-> NTFS / ANALYZE BEFORE WRITE |
+---------------------------------------+
```

# StarConverter

**A careful, cross-platform exFAT <-> NTFS conversion workbench.**

`ANALYZE  /  PLAN  /  CONVERT  /  VERIFY  /  ROLLBACK`

</div>

StarConverter is being built to convert compatible exFAT and NTFS volumes without copying every
file to another disk. The design keeps file-data extents in place where possible, relocates only
conflicts, constructs new filesystem metadata transactionally, and retains an explicit rollback
record until the user finalizes the conversion.

This repository is an engineering pre-alpha, not a drive-writing release. The CLI can open a
regular exFAT or NTFS image read-only, validate redundant boot metadata, reconstruct allocation and
object evidence, and feed that evidence into the preflight planner. exFAT inspection recursively
normalizes live objects, names, allocation ownership, extents, both TexFAT bitmap/FAT pairs, and the
Up-case Table. NTFS inspection bootstraps `$MFT`, validates volume/allocation metadata, and performs
a bounded object, stream, extent, and directory-index inventory. Both formats now normalize common
semantics into the same object graph while retaining format-specific preservation evidence.
Policy-bound adapters map the supported subset in both directions, including exact DOS fields,
volume identity, canonical case tables, timestamp conversion, and schema-v4 escrow for source-only
precision, semantics, and proven pinned NTFS security descriptors. Pure exFAT and NTFS serializers
emit phase-separated metadata/backup-boot/primary-boot candidates and round-trip through independent
readers. The CLI and desktop app can turn a supported source into a brand-new target image, persist
required escrow, reinspect the result, compare its logical manifest, and prove the source hash
unchanged. Existing outputs and device-like paths are refused. In-place activation remains blocked
on explicit serializer/Windows gates, and no executable accesses raw devices.

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

- Rust 1.85+ for the filesystem core and CLI
- Rust 1.95+ for the native GUI (`eframe`/`wgpu` dependency floor)
- Go 1.23+ for the lab harness

```powershell
cargo build --workspace
cargo test --workspace
cargo run -p starconverter-cli -- demo
cargo run -p starconverter-cli -- inspect "C:\path\to\volume.img"
cargo run -p starconverter-cli -- preview "C:\path\to\volume.img" --mode escrow
cargo run -p starconverter-cli -- convert-image "C:\path\source.img" "C:\path\new-target.img" --mode escrow
cargo run -p starconverter-cli -- verify-export "C:\path\new-target.img" "C:\path\new-target.img.starconverter-escrow" --source "C:\path\source.img"
cargo run -p starconverter-cli -- verify-windows-report "C:\path\windows-validation.json"
cargo run -p starconverter-gui
```

`inspect` accepts only a regular image file. It rejects raw-device namespaces and directories,
opens the image read-only, validates bounded boot geometry plus the exFAT main/backup checksums or
the NTFS final backup sector, recursively inventories and normalizes exFAT objects, and scans the
initialized NTFS `$MFT` under explicit resource caps. It then explains which evidence remains
insufficient for conversion. The target defaults to the opposite filesystem; `--to exfat|ntfs` and
`--mode strict|escrow|content-only` can override the preflight request. Content-only is available
for inspection and preview only; copy export accepts strict or escrow losslessness. Inspection never writes to
the image.

`preview` goes further without writing: it runs the preservation-bound cross-format adapter,
constructs the exact destination candidate, classifies staging/backup/activation writes, and reads
their exact rollback before-images into memory. It prints every remaining activation gap, and its
result type cannot be submitted to the executor as activation authority.

`convert-image` is the safe first conversion surface. It opens the source read-only, refuses any
existing output or device-like path, copies the complete source into a uniquely named partial file,
applies the active candidate only to that copy, reinspects and normalizes it, and requires its
namespace/content manifest to match the plan. Escrow mode creates
`<new-target>.starconverter-escrow` unless `--escrow` selects another new path. Before publication,
a normal failure removes only the attempt's partial files. Publication collisions and ambiguous
post-publication cleanup/durability failures retain and report the exact partial/final paths for
recovery rather than deleting by pathname. The final candidate name is published only after
verification; escrow is bound to the exact source, candidate, manifest, and direction.
Inspection, planning, preimage capture, copying, and final source hashing share one pinned read-only
file identity. The command hashes the source again before success and never uses the in-place
activation-authority type. See [`docs/RECOVERY.md`](docs/RECOVERY.md) for interrupted-export and
sidecar verification guidance. Current atomic no-clobber publication requires the candidate and
escrow destination directories to support hard links; exFAT/FAT destination directories and other
filesystems without hard-link support are refused. Parent-directory crash durability remains a
tracked portability gate.

`verify-windows-report` opens only a bounded regular JSON file and strictly checks the schema-v1
output of the detached/read-only VHD harness. Its result is explicitly unkeyed, non-authorizing
evidence; the command never opens, attaches, mounts, or writes a VHD or device.

The Go toolchain is only required for `lab/`:

```powershell
cd lab
go test ./...
go run ./cmd/starconverter-lab matrix
```

On Windows, `scripts/check.ps1` runs the available local checks and clearly reports when Go is not
installed. CI always tests both language stacks.

## Current status

`v0.1 pre-alpha :: verified copy-based image conversion milestone`

- [x] Buildable Rust workspace
- [x] Shared conversion capability and safety model
- [x] Analysis plus create-new image conversion CLI
- [x] Native ASCII-black desktop shell
- [x] Go crash/recovery state-machine matrix
- [x] Cross-platform CI and repository shipping policy
- [x] Bounded read-only regular-image backend
- [x] Read-only exFAT 1.00 boot-geometry parser
- [x] Read-only NTFS boot-geometry parser
- [x] exFAT main/backup boot checksums and NTFS backup-sector validation
- [x] exFAT active bitmap, Up-case Table, root directory, and free-space discovery
- [x] Exact exFAT bitmap length/tail validation with fail-closed refusal of unpreserved reserved data
- [x] Recursive exFAT object/allocation/extent inventory
- [x] Lossless exFAT-to-neutral object normalization
- [x] NTFS FILE/attribute/runlist/index parsers and bounded `$MFT` bootstrap
- [x] Bounded NTFS volume bitmap and object/stream/directory inventory
- [x] Exact NTFS bitmap-to-runlist ownership reconciliation, including metadata attributes
- [x] Complete bounded NTFS attribute census and sparse-only `$BadClus:$Bad` proof
- [x] Exact `$MFT::$BITMAP` versus FILE-record in-use reconciliation before normalization
- [x] `$ATTRIBUTE_LIST` continuation resolution and NTFS-to-neutral normalization
- [x] Exact relocation geometry solver
- [x] Redundant append-only recovery capsule format
- [x] Immutable overlay view for candidate metadata validation
- [x] Logical stream/content manifest verifier over regular images
- [x] Shared bounded-reader path for exFAT/NTFS candidate parsing and logical hashing
- [x] Lifetime-bound staged-candidate audit through the executor's already-locked image handle
- [x] Pure resumable transaction coordinator with pre-activation overlay proof
- [x] Phase-separated exFAT and NTFS structural destination serializers
- [x] Exact regular-image preimage capture for every source-visible write phase
- [x] Versioned capsule recovery bundle retaining exact phase before-images
- [x] Bounded append-only capsule store with exclusive create/resume, one-generation growth,
      read-back verification, flush evidence, and torn/changed-file refusal
- [x] Bounded parser fuzz targets and CI smoke workflow
- [x] Modeled crash campaign across every durable transaction barrier
- [x] Every-byte capsule-tail and in-flight write-group recovery matrix
- [x] Type-level serializer activation authorization (no public bypass)
- [x] Module-sealed preflight/verification/completion evidence (no caller-forged clean state)
- [x] Exact-intent regular-image executor with locking, read-back, flush, rollback, and fault cuts
- [x] Opaque plan/container-bound executor completion evidence for mutation and rollback checkpoints
- [x] Crate-private generation/phase execution leases and a non-activating durable coordinator through `TargetStaged`
- [x] Deterministic parser mutation suite
- [x] Real-image `inspect` command with evidence-aware blocking
- [x] Real-image read-only `preview` with exact candidate phases and rollback bytes
- [x] Resolve and normalize supported NTFS continuations
- [x] Fail-closed 25-field cross-format preservation policy with bounded versioned escrow
- [x] Policy-bound exFAT→NTFS and NTFS→exFAT structural adapters with exact timestamp/identity evidence
- [x] Pinned `$Secure` ordinary-object security-ID assignment in NTFS `$STANDARD_INFORMATION`
- [x] Reproducible root/rich/edge external fixtures, read-only exfatprogs/NTFS-3G checks, and exFAT/NTFS FUSE payload mounts
- [x] Formatter-origin exFAT/NTFS differential images with unchanged hashes and parser compatibility regressions
- [x] Populated formatter-origin feature corpus with nested Unicode, allocation boundaries, fragmentation, and exact driver-read payload hashes
- [x] Native desktop exact-candidate preview with in-memory rollback capture and no executor authority
- [x] Nonblocking desktop inspect/preview/export/verify jobs with stale-result and panic containment
- [x] Byte-level candidate progress and cooperative cancellation through the last safe
      pre-publication checkpoint, with truthful non-cancellable publication reporting
- [x] Bounded desktop session recovery with stale/corrupt/raw-device refusal and keyboard/contrast regressions
- [x] Deterministic wide/medium/compact desktop layouts, 44-point targets, and screen-reader-safe ASCII branding
- [x] Stable responsive accessibility traversal from Source through Activity, independent of panel paint order
- [x] Create-new exFAT→NTFS and NTFS→exFAT export with reinspection, manifest equality, source re-hash, and escrow sidecar
- [x] Independently mount both exported rich cross-format candidates read-only and verify exact payload hashes
- [x] Read-only candidate/source/sidecar verifier and candidate-bound escrow envelope
- [x] Uniquely named partial construction and atomic no-clobber publication on hard-link-capable filesystems
- [x] Deterministic converted fixed-VHD fixtures and fail-closed Windows validation harness
- [x] Four-target deterministic portable packaging with exact bundle inventories, SBOM identity checks, and verified provenance attestations
- [x] Deterministic unsigned macOS application bundles with closed-schema validation and native dependency/signature gates
- [x] Source-bound Windows PE identity: console CLI, windowed GUI, `asInvoker`, long-path manifest,
      exact pre-release version metadata, no icon artwork, and unsigned-channel enforcement
- [x] Scheduled RustSec/Go vulnerability scans and weekly Cargo, Go, and GitHub Actions update proposals
- [ ] Close serializer activation gaps and qualify the cross-filesystem metadata profiles
- [ ] In-place image conversion with durable recovery/finalize workflow
- [ ] Windows `chkdsk`/mount validation of generated and recovered images
- [ ] Explicitly gated physical-volume support

The staged implementation plan lives in [`docs/ROADMAP.md`](docs/ROADMAP.md); the evidence required
before any readiness claim is tracked in [`docs/COMPLETION_MATRIX.md`](docs/COMPLETION_MATRIX.md).
Independent regular-image validator evidence is logged in
[`docs/EXTERNAL_VALIDATION.md`](docs/EXTERNAL_VALIDATION.md).

Tagged releases are packaged by GitHub Actions as portable CLI + desktop bundles for Windows x64,
Linux x64, macOS Intel, and macOS Apple Silicon, plus canonical unsigned `.app` layouts for both
macOS architectures. The workflow emits SHA-256 manifests, CycloneDX SBOMs, and GitHub/Sigstore
provenance and SBOM attestations. StarConverter is not yet natively code-signed or notarized, so
those packages remain unsigned pre-alpha validation builds rather than a drive-writing release.
See [`docs/RELEASE.md`](docs/RELEASE.md).

## Safety and security

- No raw-device access or in-place activation-ready serializer exists in the current build. The
  create-new exporter never opens a source for write; the in-place regular-image executor remains
  reachable only through an activation-authorized transaction, which neither serializer can
  currently produce.
- Analysis must work without administrator/root privileges.
- Every future write is represented in a transaction plan before execution.
- Volume identity is pinned before lock/dismount and checked again afterward.
- Source boot and metadata sectors are preserved before they can be overwritten.
- Target boot activation is the final commit point; rollback remains available until finalize.

Please report safety defects privately before publishing a proof of concept. See
[`SECURITY.md`](SECURITY.md).

## License

Copyright (c) 2026 Nur Octane. All rights reserved. See [`LICENSE`](LICENSE).
