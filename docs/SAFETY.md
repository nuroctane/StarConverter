# Safety model

## Non-negotiable invariant

At every acknowledged transaction phase, StarConverter must be able to produce either the complete
source view or the complete destination view from the device plus its retained transaction capsule.
An unverified target is never allowed to replace the last recoverable source state.

## Guarantee classes

- **Strict:** no semantic downgrade. A single unrepresentable object blocks conversion.
- **Escrow:** target-native access plus a versioned capsule that restores source-only semantics.
- **Content only:** preserves file payloads and clearly enumerated common metadata only.
- **Unsupported:** refuses before acquiring write authorization.

## Default refusals

The first physical-device release must refuse:

- dirty or structurally inconsistent filesystems;
- mounted or busy filesystems;
- system, boot, paging, hibernation, or crash-dump volumes;
- BitLocker/EFS and other encryption unless a separately reviewed policy exists;
- dynamic disks, Storage Spaces, RAID members, and snapshot-managed volumes;
- sector geometries outside the tested 512/4096-byte set;
- unsupported cluster sizes or incompatible alignment;
- devices reporting unstable identity or geometry between discovery and execution;
- media-health warnings, read errors, or flush/barrier failures;
- any plan whose exact required space exceeds proven available extents;
- NTFS semantics not permitted by the selected guarantee class.

## Authorization layers

1. **Analysis** is read-only and unprivileged.
2. **Plan creation** records source identity, geometry, metadata digest, operations, space, and risk.
3. **Write authorization** requires a stable device identifier, explicit mode, and exact typed
   confirmation separate from the source selector.
4. **Executor elevation** applies only to the narrow backend helper.
5. **Activation** happens only after overlay verification and durable flush barriers.
6. **Finalize** is separate and irreversible; it deletes rollback material only after validation.

## Transaction phases

| Phase | Durable state | Recovery action |
| --- | --- | --- |
| Discovered | Source untouched | Re-run analysis |
| Reserved | Source valid; placeholders allocated | Remove placeholders or continue |
| Relocating | Payload copies exist at old and new ranges; source still references the old bytes; target staging may be in flight | Conservatively restore every staging before-image or continue |
| Target staged | Source boot remains active; the backup-boot write may be in flight | Conservatively restore staging and backup-boot before-images or continue |
| Backup boot written | Source primary boot remains active; primary activation may be in flight | Conservatively restore all phase before-images or continue |
| Activated | Target primary boot active | Verify target or restore source from capsule |
| Verified | Target validated; rollback retained | Continue using target or rollback |
| Finalized | Target valid; capsule intentionally released | No automatic rollback promise |

Each transition includes an incremented generation number, CRC-protected headers, a payload hash,
and an explicit flush. Recovery selects the newest complete generation rather than trusting a single
flag.

Recovery deliberately includes the write group *after* the newest completed checkpoint. A crash can
occur after that group's bytes reach storage but before its completion generation is durable; exact
before-images make restoring an untouched range harmless and prevent this acknowledgement window
from under-restoring a torn write.

## Physical-device gate

Raw-device code may be merged only after all of these conditions are met:

- parsers pass malformed-image and differential test corpora;
- the layout solver proves non-overlap and exact space accounting;
- image conversion passes full-hash round trips for the supported feature subset;
- every named write barrier has an injected-crash recovery test;
- corrupted/torn capsule headers recover through redundant generations;
- operating-system structural validators accept both converted and rolled-back images;
- fuzzing has no known parser panic, out-of-bounds access, integer overflow, or unbounded allocation;
- the UI and CLI both display the stable device identity and explicit guarantee class;
- a separate code review approves the platform backend and its flush semantics.

After that gate, testing begins only on one uniquely labeled sacrificial removable drive with every
other removable drive unplugged. No automated test targets a physical device by enumeration order.

## Regular-image executor boundary

The image executor opens only an existing canonical regular file. It never creates, truncates, or
resizes; lexically rejects Windows device namespaces and Unix `/dev`; checks the inspection identity
and fixed length before mutation; takes Windows deny-share plus a whole-file lock (advisory locking
on other platforms); and accepts only a complete exact intent from an activation-authorized
`PreparedConversion`. The plan's source identity is compared with a domain-separated token over the
executor's canonical path, fixed length, and strongest stable platform container identity before
any intent or rollback bytes are accepted. It verifies every destination chunk, executes both data
and metadata flushes, and returns non-cloneable evidence bound to the exact plan, container, and
completed phase. The coordinator's mutating checkpoint APIs accept only that opaque executor value;
callers cannot construct generic completion records. Rollback acknowledgement has the same binding,
including the authorized before-image digest whenever source-visible bytes were restored.

Raw executor mutation methods are private. The crate-private regular-image coordinator opens the
image executor before the capsule store and owns both locks. It mints one-use leases bound to the
current durable capsule generation and phase, refuses nonempty relocation before any image intent,
and requires executor read-back plus both flush barriers before appending the corresponding capsule
generation. It has no CLI/GUI entry point. At restart boundaries, a bounded classifier borrows the
sealed before/after ranges without cloning their payloads and labels the actual write group exact
before, exact after, before/after-only mixed, or third-state. Backup boot may be safely rewritten
from the first three states because the source primary boot is still active; activation continues
only from exact before or exact after, while mixed or third-state activation is rollback-only.

The lifetime-bound read view is cloned from the already-open locked handle without reopening its
path. Before evidence is accepted, every real write group required by the current phase is proven
byte-for-byte exact; both filesystem parsers and the logical stream hasher then read the complete
prepared target. The normalized graph and logical manifest must match generation-zero `SCPREP01`
authority, and the handle is revalidated afterward. Verification is explicitly separate from
activation and still permits rollback. Finalization repeats the full audit and requires a private
approval capability; production has no constructor for that capability. Resume reconstructs the
original source view by masking only conservative before-image ranges, so changes elsewhere remain
digest-visible. Ambiguous executor/capsule operations poison the coupled coordinator; exact
before-image rollback is idempotent under the retained locks.

Initial preparation is also lock-coupled. On Windows, a non-cloneable session accepts only the
executor's mandatory deny-share plus whole-file lock, internally mints the transaction identity,
and runs inspection, source hashing, logical manifest construction, planning, and exact preimage
capture through a view borrowed from that same handle. It rejects planner-selected transaction
identity, substituted preflight or graph evidence, and any rollback bytes that differ from the
locked source. Advisory Unix locks cannot establish production `Offline` evidence and fail before
capsule creation. The session creates generation zero only while retaining the image lock and
requires data flush, metadata flush, readback, and `ParentDirectorySynchronized` evidence before it
can be consumed into a coordinator.

New capsules embed the complete bounded, canonical forward plan and nested recovery bundle in their
first generation. The coordinator can therefore discard all process memory, reacquire image then
capsule locks, reconstruct the plan, recompute its commitments, and re-audit `TargetStaged`. Older
`SCRECOV1`-only capsules require the exact external plan and are rollback-only; they cannot recreate
forward authority.

The durable capsule store has an explicit recovering-resume operation and a stricter poisoned-write
reconciliation path. Under its exclusive lock, it adopts and flushes exactly one complete valid
generation that an earlier append may have written despite returning an error. It shortens the file
only when bounded recovery proves that the exact last verified checkpoint is followed by a torn
newest generation, then flushes, rereads, and strict-scans the retained prefix. Identity changes,
complete corruption, ambiguous multi-generation growth, and an incomplete first generation are
refused without mutation.

Successful exclusive capsule creation additionally synchronizes the canonical parent directory.
Unix uses a directory `sync_all`; Windows opens the directory with
`FILE_FLAG_BACKUP_SEMANTICS` and requires `FlushFileBuffers` success. A rejected or unsupported
parent barrier returns `NamespaceDurabilityUnproven`: the fully written capsule remains available
for explicit recovery, but no image mutation authority is returned. Test-only persistence cuts at
`BeforeWrite`, `AfterWrite`, `AfterSyncData`, `AfterReadback`, `AfterSyncAll`, and `BeforeAdopt`
exercise create plus BackupBootWritten, Activated, and RolledBack recovery against synced regular
temp files.

This is not physical-volume authorization. Serializer activation remains opaque and unavailable,
and frontends expose no in-place conversion command. The create-new path below is a separate safety
boundary and does not authorize this executor.

## Copy-based candidate boundary

The first executable conversion path never opens the source for write. It requires a caller-selected
output path that does not exist, lexically rejects device namespaces and reserved device names,
canonicalizes and validates the output parent, and creates the output with `create_new`. It verifies
that every preview rollback range is the exact current source before copying. Inspection, planning,
preimage capture, copying, and final hashing share one pinned read-only file identity. The complete
source is copied in bounded chunks, candidate metadata and both boot copies are written only to the new file,
and the result is flushed, reopened through the regular-image reader, fully inventoried, normalized,
and compared to the planned logical namespace/content manifest.

Escrow mode also requires a second create-new sidecar whose payload first passes the independent
schema decoder and direction check. Any failure removes only files newly created by that call. The
source is hashed before and after the export; success requires equality. This path deliberately does
not consume `ActivationAuthorizedWrites`, because there is no source activation or rollback point to
authorize. It does not qualify the separate in-place executor or any physical backend.

## Threats outside the guarantee

StarConverter cannot make a single device resilient to mechanical failure, flash translation-layer
failure, malicious firmware, faulty RAM, power-loss behavior that violates advertised flush
semantics, or user removal during an unflushable controller operation. Valuable data still requires
an independent backup.
