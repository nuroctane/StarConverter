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
| Relocating | Source valid via journaled moves | Replay or reverse moves |
| Target staged | Source boot remains active | Discard target metadata or continue |
| Backup boot written | Source primary boot remains active | Restore saved backup sectors |
| Activated | Target primary boot active | Verify target or restore source from capsule |
| Verified | Target validated; rollback retained | Continue using target or rollback |
| Finalized | Target valid; capsule intentionally released | No automatic rollback promise |

Each transition includes an incremented generation number, CRC-protected headers, a payload hash,
and an explicit flush. Recovery selects the newest complete generation rather than trusting a single
flag.

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

## Threats outside the guarantee

StarConverter cannot make a single device resilient to mechanical failure, flash translation-layer
failure, malicious firmware, faulty RAM, power-loss behavior that violates advertised flush
semantics, or user removal during an unflushable controller operation. Valuable data still requires
an independent backup.
