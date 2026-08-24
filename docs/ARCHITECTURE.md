# Architecture

## Objective

StarConverter converts between exFAT and NTFS while keeping compatible file payloads in their
existing physical extents. It does not promise that every NTFS semantic can exist natively on
exFAT. Instead, the planner assigns an explicit guarantee class before any mutation begins.

## System boundaries

```text
frontends                 trusted core                         backends

desktop ----+       +-----------------------+       +---------------------+
            +------>| discovery + parser    |------>| image file          |
CLI --------+       | capability classifier |       | physical block dev  |
                    | extent graph           |       +---------------------+
                    | geometry solver        |                 ^
                    | transaction planner    |                 |
                    | verifier + recovery    |       gated authorization
                    +-----------------------+
                                ^
                                |
                    Go lab / fault injector
```

The core is deterministic and independent from user interface state. Frontends never issue raw
writes. They submit a signed or hashed transaction plan to an executor, and the executor revalidates
device identity and geometry before accepting it.

## Rust workspace

### `starconverter-core`

The crate contains the public capability model and a deterministic preflight planner. It has no
operating-system or GUI dependency. Implemented foundations include:

- `fs/exfat_*`: boot regions, dual FAT/bitmap pairing, directory entry sets, allocation ownership,
  recursive inventory, exact timestamp preservation, Up-case semantics, and neutral normalization;
- `fs/ntfs_*`: boot sector, MFT records, attributes and continuation lists, runlists, `$Bitmap`,
  `$MFT::$BITMAP`/FILE-state reconciliation, `$Volume`, `$I30` indexes, system-file discovery, and
  bounded object inventory;
- `object` and `extent`: normalized namespace/stream model plus physical ownership validation;
- `geometry`: deterministic destination reservations and conflict relocation;
- `capsule`: duplicated append-only generation headers, CRCs, SHA-256 payload identity, phase
  monotonicity, and a canonical first-generation `SCPREP01` plan envelope. The envelope commits the
  complete forward plan, source logical manifest, target feature rules, operational limits, and a
  nested versioned recovery bundle containing exact before-images;
- `overlay`: immutable sector-aligned candidate writes over a crate-private bounded reader, with no
  path, handle, identity, seek, or mutation capability;
- `phase` and `preimage`: activation-gated serializer composition plus bounded capture of exact
  regular-image before-images for every staged, backup-boot, and primary-boot replacement;
- `verify`: deterministic UTF-16 namespace and logical stream SHA-256 manifests, including sparse
  and uninitialized-zero semantics, over regular images or the exact selected candidate overlay;
- `executor`: fixed-size regular-image-only execution under crate-private one-use
  generation/phase/plan/container leases, with exclusive locking, bounded positional writes,
  read-after-write verification, durable flushes, rollback, and deterministic fault injection. Raw
  unleased mutators are private. A lifetime-bound read view is cloned from the already-open locked
  handle for coordinator inspection; it exposes no raw-device or arbitrary-range write API.
- `conversion/regular_image`: internal image-then-capsule lock ownership and durable preactivation
  sequencing through `TargetStaged` only. Resume observations hash the complete locked source view,
  virtually restoring only the conservative phase rollback ranges. At `TargetStaged` it first
  proves the real staged ranges equal the planned bytes, then reparses and logically hashes the
  candidate overlay against the sealed graph and source-manifest commitment. It can reconstruct an
  owned plan from capsule plus image after process loss. It still refuses relocation, backup boot,
  activation, and all frontend access;
- `candidate_export`: create-new-only full image copy, exact preview application, independent target
  reinspection, logical manifest equality, validated escrow persistence, and source SHA-256
  stability proof. It cannot overwrite or authorize in-place activation.

The pure transaction coordinator is implemented: it validates complete/clean/offline evidence,
feature preservation, relocation geometry, opaque sector write containment, capsule resume state,
candidate-overlay verification before backup boot, final verification, and rollback through the
verified phase. Rollback selection is conservative across the checkpoint acknowledgement window:
it restores the possibly in-flight next write group as well as every completed group. Pure
structural destination serializers and read-only preimage capture now exist. The internal
regular-image coordinator proves image-before-capsule durability and rollback through the inactive
`TargetStaged` boundary, constructs fresh resume observations from its locked handle, and can audit
that staged view against the durable source commitment after reconstructing its plan from capsule
generation zero. It remains unreachable from production because trusted initial preflight/capsule
creation and serializer qualification are unfinished. Neither serializer qualifies for activation. There is
intentionally no executable in-place conversion command and no physical-device backend. The
separate copy-based exporter can
produce a complete target only in a brand-new regular file, so it does not consume or weaken that
authorization boundary.

Unsafe Rust is forbidden at workspace level. Platform calls should live behind small, reviewed FFI
crates only when a safe maintained crate cannot express the operation; that policy change requires a
documented exception rather than weakening the entire workspace lint.

### `starconverter-cli`

The CLI is the automation and recovery frontend. It must expose every safety-relevant choice without
requiring the GUI. Current and planned command surface:

```text
starconverter inspect <source>
starconverter preview <source> --to ntfs --mode escrow
starconverter convert-image <source> <new-output> --to ntfs --mode escrow
starconverter verify-export <candidate> <escrow> --source <source>
starconverter verify-windows-report <report.json>
starconverter plan [synthetic-options]
starconverter convert <plan> --confirm-device <stable-id>
starconverter verify <journal>
starconverter rollback <journal>
starconverter finalize <journal>
```

`inspect` and `preview` open regular images read-only and validate exFAT/NTFS boot geometry,
redundant boot structures, allocation evidence, bounded object inventories, preservation policy,
and exact candidate phases. `convert-image` writes only a caller-selected new regular file and its
new escrow sidecar; it refuses overwrite and devices, reinspects the result, verifies a logical
manifest, and re-hashes the source. `plan` remains a synthetic capability-model command. No CLI
command mutates a source image or accesses a raw device. `verify-windows-report` reads one bounded
regular JSON file, verifies the pinned schema-v1 harness evidence, and explicitly returns no
activation authority; it does not open or attach the named VHDs.

### `starconverter-gui`

The native desktop shell uses `eframe`/`egui`: one Rust codebase for Windows, macOS, and Linux. The
GUI is a client of the same planner as the CLI. Raw-device elevation should use a narrow helper
process, not elevate the entire interface.

## Go lab

`lab/` describes and executes a deterministic matrix of disposable filesystem images. Go is used for
process orchestration, fixture naming, parallel runners, event logs, and crash-point campaigns. The
lab never becomes the source of truth for parsing or mutation logic.

Planned providers:

- sparse image creation;
- platform formatter adapters;
- corpus population with adversarial names, sizes, fragmentation, and metadata;
- process interruption at named transaction barriers;
- remount/fsck/chkdsk validation;
- manifest and content-hash comparison;
- minimized failing-image retention.

## Metadata pivot

The proposed conversion transaction is:

1. Discover the source without modifying it and require a clean supported filesystem.
2. Build the complete object, semantic, and extent graph.
3. Solve destination geometry and calculate exact reservation/relocation space.
4. Create source-visible placeholder files for destination metadata, scratch, and the capsule.
5. Relocate only extents that conflict with mandatory target structures.
6. Lock and dismount; revalidate stable device identity, geometry, and source metadata digest.
7. Preserve before-images for every sector that can be overwritten.
8. Construct target metadata while leaving the primary target boot sector inactive.
9. Validate the candidate target through an overlay view.
10. Write backup boot information, flush, then write the primary boot record as the activation point.
11. Mount read-only, validate structure and content, and retain rollback state.
12. Remove rollback material only through an explicit finalize operation.

## Metadata capsule

Escrow mode needs an append-only, checksummed capsule containing:

- duplicated headers with generation and transaction phase;
- original boot and overwritten metadata sectors;
- relocation before-images and extent maps;
- stable object identifiers and path-independent relationships;
- NTFS security descriptors, alternate streams, hard-link groups, sparse maps, reparse data, object
  IDs, exact timestamps, and encrypted raw streams where supported;
- content hashes and index root hashes.

The exFAT side may store a compact object identifier in a benign vendor extension directory entry.
Unknown benign entries are designed to be ignored by other exFAT implementations, while the global
capsule holds the larger records.

## Compatibility contract

| NTFS feature | NTFS -> exFAT strict | Escrow policy |
| --- | --- | --- |
| Ordinary file bytes | Native | Native |
| Basic timestamps/attributes | Normalized if representable | Exact values also escrowed |
| ACL/owner | Refuse | Save; not enforced on exFAT |
| Alternate streams | Refuse | Save in capsule |
| Hard links | Refuse unless one link | Materialize or refuse based on exact space plan |
| Sparse data | Refuse unless fully allocated | Materialize holes or refuse |
| NTFS compression | Refuse | Decompress with exact capacity check |
| EFS | Refuse | Raw encrypted escrow only; never silently decrypt |
| Reparse points/symlinks | Refuse | Policy-controlled placeholder/materialization |
| Case-colliding names | Refuse | Reversible rename policy only |

The first image converter supports the native common subset only. Escrow is a later format with its
own versioning and compatibility tests.
