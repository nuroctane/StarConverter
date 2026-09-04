# Implementation roadmap

Stages are ordered by evidence and safety gates, not calendar estimates. A later stage does not begin
merely because an earlier prototype appears to work once.

## 0. Scaffold and contract

- Rust core/CLI/GUI workspace and Go lab harness
- capability and guarantee-class vocabulary
- ASCII-black desktop design system
- repository safety rules, CI, and shipping contract
- raw writes absent

Exit evidence: cross-platform build, unit tests, and a planner whose blockers are deterministic.

## 1. Read-only forensic planner

- image-file backend with bounded reads
- exFAT boot/FAT/bitmap/directory parser
- NTFS boot/MFT/attribute/runlist parser
- normalized object and extent graph
- semantic inventory and exact space calculator
- malformed-image corpus, property tests, and fuzz targets

Exit evidence: matches trusted tools on a broad generated corpus and refuses malformed structures
without panic or unbounded allocation.

## 2. Image-only exFAT -> NTFS strict conversion

- destination geometry solver
- NTFS metadata serializer
- reserved placeholder and relocation planning
- append-only transaction capsule
- virtual overlay verifier
- backup-boot-first / primary-boot-last activation
- rollback and finalize

Exit evidence: complete hashes and metadata manifests survive conversion and rollback across the
supported common subset.

## 3. Crash consistency campaign

- named barriers around every durable mutation
- termination, torn-write, stale-read, and reordered-write fault models
- automatic recovery decision table
- minimized failing-image retention
- differential chkdsk/fsck/driver mount checks

Exit evidence: every injected crash produces a validated source or validated target view; no crash
point produces an ambiguous writable mount.

## 4. Image-only NTFS -> exFAT

- strict common-subset structural conversion and relocation-aware create-new export (implemented)
- hard-link, sparse, compression, case-collision, and reparse-point space/policy handling
- versioned semantic escrow capture and integrity binding (implemented); restore of extra non-DOS hard links, resident named streams, captured nonempty non-resident named streams, and resident file and directory `$REPARSE_POINT` payloads matches dest objects by dest-native path; create-new NTFS serialize dest-cluster-materializes a non-resident `$ATTRIBUTE_LIST` when the resident form cannot fit the base FILE record, splits file and directory lists that need two or more clusters into a one-cluster first extent plus a VCN-contiguous continuation, and splits `$DATA` mapping pairs that cannot fit one empty FILE record into VCN-contiguous continuation extents; source discovery concatenates same-record `$MFT` `$DATA` fragments, follows record zero's resident or non-resident (VCN-split) `$ATTRIBUTE_LIST` to mapped `$MFT` extension records, and resolves `$MFTMirr::$DATA`, `$MFT::$BITMAP`, `$Volume`, and `$Bitmap` through their own `$ATTRIBUTE_LIST` with VCN-split extents concatenated; rematerialized reparse points populate the `$Extend:$R` view index, which spills into `$INDEX_ALLOCATION:$R` `INDX` records (multi-level when needed) once the resident `$Reparse` root overflows, and the read-only inventory walks resident or spilled `$R` on any NTFS volume and reconciles it against the `$REPARSE_POINT` census (failing closed on stale, unlisted, mismatched, or duplicate keys); the exFAT→NTFS convert path (CLI `--restore-escrow`, GUI restore-escrow field) consumes a candidate-bound NTFS→exFAT sidecar after direction and source-SHA-256 binding checks and restores exact timestamps/attributes/serial/label with the identities, proven by an in-tree NTFS→exFAT(+escrow)→NTFS round trip; named streams the sidecar cannot capture (above the inventory cap, sparse, or LZNT1) travel as hidden+system dest-native carrier files under `\.starconverter-escrow` and are folded back into their owners on the escrow-restored return trip (proven in-tree with a 16 MiB + 4 KiB ADS); `$MFT` continuation hosts outside the first-extent map remain pending
- exFAT benign vendor entry object IDs (target contract, not current capability)
- round-trip restoration to NTFS

Exit evidence: strict mode refuses every non-native semantic; escrow mode restores exact tested
metadata and reports anything outside its versioned contract.

## 5. Physical read-only discovery

- platform-specific enumeration and stable identity
- privilege separation
- health, mounted/busy, system-volume, encryption, and topology detection
- removable-drive UX with explicit non-selection by default

Exit evidence: device identity cannot silently change between UI selection and helper inspection.

## 6. Gated physical conversion

- offline lock/dismount backends
- platform-specific unbuffered aligned I/O and durable flushes
- recovery environment integration
- sacrificial removable-media test suite
- signed portable artifacts

Exit evidence: the complete physical-device gate in `SAFETY.md` is satisfied and independently
reviewed.

## 7. Product hardening

- resumable queue and durable audit log
- accessibility and localization
- reproducible builds, SBOM, and signed releases
- compatibility database keyed by OS/driver/device behavior
- recovery documentation that does not depend on the original GUI installation
