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

Raw executor mutation methods are private. The crate-private preactivation coordinator opens the
image executor before the capsule store and owns both locks. It mints one-use leases bound to the
current durable capsule generation and phase, refuses nonempty relocation before any image intent,
requires executor read-back plus both flush barriers before appending the corresponding capsule
generation, and stops at `TargetStaged`. It has no CLI/GUI entry point and cannot write backup boot
or activation bytes. An ambiguous executor/capsule operation poisons the coupled coordinator; exact
before-image rollback and verified-prefix repair are idempotent under the retained locks.

The durable capsule store has a separate, explicit recovering-resume operation. Under its exclusive
lock, it may shorten only bytes after a nonempty prefix that the redundant capsule parser proves is
an incomplete newest generation. It then flushes, rereads, and strict-scans the retained prefix
before returning. Completed corruption, ambiguity, and an incomplete first generation are refused
without repair.

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
