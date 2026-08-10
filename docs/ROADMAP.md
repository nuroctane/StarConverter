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

- strict common-subset conversion
- hard-link, sparse, compression, case-collision, and reparse-point space/policy handling
- versioned semantic escrow capsule
- exFAT benign vendor entry object IDs
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
