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
- `fs/ntfs_*`: boot sector, MFT records, record-1/runlist-owned and geometry-aware `$MFTMirr`
  validation over repaired used FILE-record content through reserved record 15, including compatible
  shorter complete-record source mirrors and canonical geometry-sized destination mirrors; attributes and continuation lists, runlists,
  `$Bitmap`, `$MFT::$BITMAP`/FILE-state reconciliation, `$Volume`, `$I30` indexes, system-file
  discovery that concatenates same-record `$MFT` `$DATA` fragments and follows record zero's
  resident or non-resident (including VCN-split) `$ATTRIBUTE_LIST` to mapped `$MFT` extension
  records, list-resolved `$MFTMirr::$DATA`, `$MFT::$BITMAP`, `$Volume`, and `$Bitmap` metadata
  with VCN-split extents concatenated, and bounded object inventory;
- `object` and `extent`: normalized namespace/stream model plus physical ownership validation;
- `geometry`: deterministic destination reservations and conflict relocation;
- `capsule`: duplicated append-only generation headers, CRCs, SHA-256 payload identity, phase
  monotonicity, and a canonical first-generation `SCPREP02` plan envelope. The envelope commits the
  complete forward plan, source logical manifest, target feature rules, operational limits, and a
  nested `SCRECOV2` recovery bundle containing exact relocation-destination and phase before-images;
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
- `conversion/regular_image`: internal image-then-capsule lock ownership and durable sequencing
  through `Activated`. A one-use Windows preparation session first acquires mandatory deny-share
  exclusion, mints the transaction identity, and performs inspection, whole-source hashing,
  manifest construction, planning, and exact preimage capture through that same handle. It refuses
  advisory-only offline claims and consumes a fully parent-synchronized initial capsule before a
  coordinator exists. Resume observations hash the complete locked source view, virtually
  restoring only conservative phase rollback ranges. Before backup-boot or activation retry, a
  bounded zero-copy classifier proves the relevant real bytes are exact before-images, exact
  after-images, a before/after-only mixture, or an unsafe third state. The coordinator rechecks
  real staged/backup/activation bytes, reparses, and logically hashes the target against the sealed
  graph and source-manifest commitment at every applicable boundary. It reconstructs an owned plan
  from capsule plus image after process loss, executes only sealed relocation authority, refuses all frontend access, separates
  verification from activation, and requires a private approval capability to finalize;
- `candidate_export`: create-new-only full image copy, exact preview application, independent target
  reinspection, logical manifest equality, validated escrow persistence, and source SHA-256
  stability proof. It cannot overwrite or authorize in-place activation.

The pure transaction coordinator is implemented: it validates complete/clean/offline evidence,
feature preservation, relocation geometry, opaque sector write containment, capsule resume state,
candidate-overlay verification before backup boot, final verification, and rollback through the
verified phase. Rollback selection is conservative across the checkpoint acknowledgement window:
it restores the possibly in-flight next write group as well as every completed group. Pure
structural destination serializers and read-only preimage capture now exist. The internal
regular-image coordinator proves image-before-capsule durability and rollback through `Verified`,
constructs fresh resume observations from its locked handle, and can reconcile and audit every
regular-image recognition boundary through activation after reconstructing its plan from capsule
generation zero. Finalization is a separate, capability-gated operation that repeats the complete
target audit immediately before crossing the rollback boundary. The trusted initial-preflight and
initial-capsule boundary is now implemented for mandatory-lock Windows regular files and
deliberately fails closed on advisory-only hosts. This remains unreachable from frontends because
neither serializer qualifies for activation and explicit user acceptance policy is unfinished.
There is intentionally no executable in-place conversion command and no physical-device backend.
The separate copy-based exporter can produce a complete target only in a brand-new regular file,
so it does not consume or weaken that authorization boundary. Both directions now pin a
write-ineligible target layout, solve only ordinary file-data conflicts with separate source-I/O
and target-cluster alignment, and reserialize every placement-dependent target structure. The
exFAT finalizer pins its cluster heap plus bitmap/upcase/directory allocations and regenerates FAT,
allocation bits, directory first-cluster fields, and `NoFatChain`; the NTFS finalizer regenerates
runlists and `$Bitmap`. Export copies payload from the immutable source handle into the private
candidate and builds expected content through a virtual relocation view over the source rather
than trusting candidate output. The solver seals the exact source graph, derived target graph, and
layout behind an opaque relocation authority; export also requires a whole-image SHA-256/container
snapshot captured before planning and refuses stale source content before creating a candidate.

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
4. Pin destination reservations and keep the restart capsule in its separately locked regular file.
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

The create-new image converter supports the native common subset. Schema-v4 escrow capture,
integrity, and candidate binding exist. Inner NTFS snapshot v7 restores extra non-DOS
`$FILE_NAME` hard links, resident named `$DATA` streams, captured nonempty non-resident named
`$DATA` payloads, and resident file and directory `$REPARSE_POINT` payloads by dest-native path,
including remapped dest inventories. Create-new NTFS serialize dest-cluster-materializes a
non-resident `$ATTRIBUTE_LIST` when `$STANDARD_INFORMATION` plus a resident list cannot fit the
base FILE record. File and directory lists that span two or more clusters emit a one-cluster first
extent with whole-stream sizes plus a VCN-contiguous continuation. `$DATA` mapping pairs that cannot
fit one empty FILE record become VCN-contiguous continuation extents. Source discovery concatenates
same-record `$MFT` `$DATA` fragments and follows record zero's `$ATTRIBUTE_LIST`, resident or
non-resident on volume clusters (VCN-split continuation extents in record zero or in already-mapped
extension records), to already-mapped `$MFT` extension records. Records 1, 3, and 6 (`$MFTMirr`,
`$Volume`, `$Bitmap`) and record zero's `$BITMAP` are likewise read through their own
`$ATTRIBUTE_LIST` when present, and VCN-split `$MFTMirr::$DATA`, `$MFT::$BITMAP`, and
`$Bitmap::$DATA` extents are concatenated in VCN order; a continuation host outside the decoded map
remains incomplete evidence.
The NTFS serializer lists every emitted `$REPARSE_POINT` once in the `$Extend\$Reparse:$R` view index (tag plus FILE reference, `COLLATION_NTOFS_ULONGS` order). `fs::ntfs_reparse_index` builds that index from fixed 32-byte `REPARSE_INDEX` entries: it stays resident while the `$Reparse` FILE record can hold every key, and otherwise spills into 4 KiB `INDX` leaf records (adding internal `INDX` levels when the separator root would overflow) whose `$INDEX_ALLOCATION:$R` occupies dest metadata clusters directly after the spilled `$I30` allocations, with a resident `$BITMAP:$R`. The `$Reparse` root budget is derived from the record's real `$STANDARD_INFORMATION`, `$FILE_NAME`, allocation, and bitmap attribute bytes, and the same module walks the emitted root and every `INDX` record independently (virtual update-sequence repair, canonical headers, child-VCN reachability, strict collation) before `ntfs_extend` accepts the typed `$Extend` metadata.

The read-only NTFS inventory closes the loop from the other side. `fs::ntfs_inventory` locates `$Extend\$Reparse` by its `$FILE_NAME` under record 11 (not by assuming record 26), reads its `$INDEX_ROOT:$R` through the lenient `ntfs_reparse_index::read_reparse_index_root` reader, and, when the root has children, walks every `INDX` record of `$INDEX_ALLOCATION:$R` through the runlist and `$BITMAP:$R` with `read_reparse_index_block` (update-sequence repair, declared-VCN check, fixed `REPARSE_INDEX` entry geometry, but no assumption about `$LogFile` sequence numbers, update-sequence values, or unused bytes, so volumes written by Windows or NTFS-3G qualify). The walked keys are then reconciled against the `$REPARSE_POINT` census: every key must name an in-use base record with the same sequence number whose unnamed `$REPARSE_POINT` carries the same tag, and every such record must be keyed exactly once. Stale keys, unlisted records, tag disagreements, duplicate keys, a missing `$Reparse` metafile beside reparse points, or a second `$Reparse` metafile are hard `NtfsInventoryError`s because a converter cannot know which side to trust. `NtfsInventory::reparse_index` records the outcome as `Absent`, `Reconciled { keys, spilled, index_blocks }`, or `Unavailable` (only when the record census itself was bounded), and `inspect-image` prints it.

Named `$DATA` payloads the sidecar cannot hold do not get lost on the way to exFAT. The inventory captures a nonempty non-resident named stream byte-for-byte only up to `NtfsInventoryLimits::max_resident_data_bytes` and never when its mapping is sparse or NTFS-compressed; for every other named stream `escrow_carrier` derives a dest-native carrier file, `\.starconverter-escrow\r<record>-a<attribute>.ads`, from the source MFT record number and `$DATA` instance identifier that already live in the inner NTFS snapshot, so no schema change is needed. `cross_format::project_ntfs_graph_for_exfat` moves each such stream out of its owner into a hidden+system carrier object (the directory is hidden+system too, stamped with the root's timestamps; carriers inherit their owner's), keeps the stream's `StreamId` so its extents stay attached, and lets the same sealed relocation/materialization path that serves unnamed payloads relocate, zero-fill sparse holes, or LZNT1-decompress it. A source root entry that folds onto the reserved directory name under any exFAT up-case table refuses the export (`EscrowCarrierNameCollision`) rather than being renamed. The CLI and GUI preview name the carrier count and directory so the user knows to keep it intact.

The exFAT→NTFS return trip can consume the NTFS→exFAT escrow sidecar. `escrow_restore::decode_restore_sidecar` opens the bound envelope, requires the NTFS→exFAT direction, and requires the envelope's candidate SHA-256 to equal the whole-image SHA-256 of the exFAT source being converted, so a sidecar from a different or since-edited candidate is refused before any planning. `cross_format::draft_escrow_restored_exfat_to_ntfs` then folds hard links, named streams, and reparse payloads back onto dest objects by dest-native path (carrier-backed named streams are reattached from the carrier file's dest extents as non-resident named `$DATA`, then the carriers and, once empty, the escrow directory are removed from the restored graph; a carrier that is missing, is not a plain file of the escrowed length, or shares its directory with foreign entries fails closed), overrides the exFAT-derived NTFS metadata with the escrowed `$STANDARD_INFORMATION` timestamps and attributes (re-deriving the DIRECTORY bit and letting the serializer own REPARSE/COMPRESSED/ENCRYPTED), and restores the escrowed volume serial and label. The CLI exposes this as `convert-image --restore-escrow PATH` and the GUI as an optional restore-escrow path; both read the sidecar read-only under the same byte bound as verification.
