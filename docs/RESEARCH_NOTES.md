# Research basis

The architecture is based on primary specifications, platform APIs, and source inspection of active
filesystem tooling.

## Authoritative references

- Microsoft [exFAT File System Specification](https://learn.microsoft.com/en-us/windows/win32/fileio/exfat-specification)
- Microsoft [File System Functionality Comparison](https://learn.microsoft.com/en-us/windows/win32/fileio/filesystem-functionality-comparison)
- Microsoft [NTFS overview](https://learn.microsoft.com/en-us/windows-server/storage/file-server/ntfs-overview)
- Microsoft [Master File Table](https://learn.microsoft.com/en-us/windows/win32/devnotes/master-file-table)
- Microsoft [NTFS attribute types](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/a82e9105-2405-4e37-b2c3-28c773902d85)
- Microsoft [NTFS metadata streams listed by the defragmentation API](https://learn.microsoft.com/en-us/windows/win32/fileio/defragmenting-files)
- Microsoft Sysinternals [reserved NTFS metadata-file record assignments](https://learn.microsoft.com/en-us/sysinternals/resources/archive/v01n05)
- Microsoft archived [`convert.exe` documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc730863%28v%3Dws.11%29)
- Microsoft [`FSCTL_MOVE_FILE`](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_move_file)
- Microsoft [`FSCTL_LOCK_VOLUME`](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_lock_volume)
- Microsoft [`FSCTL_DISMOUNT_VOLUME`](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_dismount_volume)
- Microsoft [file buffering](https://learn.microsoft.com/en-us/windows/win32/fileio/file-buffering)
- Microsoft [`CreateFileW`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- Microsoft [`FlushFileBuffers`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers)
- Microsoft [file caching and metadata durability](https://learn.microsoft.com/en-us/windows/win32/fileio/file-caching)
- Linux kernel [NTFS3 documentation](https://docs.kernel.org/filesystems/ntfs3.html)
- Microsoft [`chkdsk`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/chkdsk)
- Microsoft [`Mount-DiskImage`](https://learn.microsoft.com/en-us/powershell/module/storage/mount-diskimage)

## Implementation precedents

- [`ntfs2btrfs`](https://github.com/maharmstone/ntfs2btrfs): reuses extents, relocates conflicts,
  stages destination metadata, and retains rollback information.
- [`btrfs-convert`](https://btrfs.readthedocs.io/en/stable/Convert.html): retains an original
  filesystem image while converting free space and metadata.
- [`fstransform`](https://github.com/cosmos72/fstransform): generic sparse-file transformation;
  useful conceptually but unsuitable with exFAT as the source because the algorithm requires sparse
  source files.
- [`exfatprogs`](https://github.com/exfatprogs/exfatprogs): authoritative Linux exFAT utilities,
  allocation movement, validation, and malformed-image fixtures.
- [`ntfs-3g`](https://github.com/tuxera/ntfs-3g): NTFS parsing and formatting implementation.
- [`fsck.exfat`](https://github.com/exfatprogs/exfatprogs/blob/master/manpages/fsck.exfat.8):
  independent read-only exFAT consistency checking with `-n`.
- [`ntfsfix` and the NTFS-3G image-file driver](https://github.com/tuxera/ntfs-3g): independent
  structural checks and read-only image mounting on the non-Windows validation lane.
- [CrashMonkey](https://github.com/utsaslab/crashmonkey): systematic crash-consistency testing.

## Findings carried into the design

1. Universal native losslessness is impossible because the formats have different semantics.
2. The credible product needs strict, escrow, and content-only guarantees.
3. Reserving destination metadata as source-visible placeholder files has established precedent.
4. Most file payload extents can remain in place when cluster geometry is compatible.
5. Rollback must preserve overwritten sectors and relocation history, not only the old boot sector.
6. Target metadata can be validated through an overlay before changing the primary boot record.
7. Exact capacity planning is mandatory for hard links, sparse files, compression, and escrow.
8. Crash testing must enumerate every durable write boundary rather than rely on end-to-end happy
   path tests.
9. exFAT interoperability requires a complete Up-case table; a self-consistent ASCII-only table is
   insufficient even when a local parser accepts it.
10. A structurally parseable NTFS image is not activation-ready until mandatory system records,
    namespace entries, and streams such as `$MFT::$BITMAP` are internally consistent.
11. External validators must initially run read-only. Repair modes would mutate the candidate and
    hide serializer defects, so they are not release evidence.
12. A Windows mount/check gate must use a disposable VHD wrapper around a copied candidate image,
    followed by `chkdsk` and namespace/content comparison. It must never attach the user's source
    image or a physical drive.
13. Candidate validation must share one capability-limited reader from boot parsing through
    allocation discovery, recursive inventory, normalization, and logical stream hashing. Mixing an
    overlay boot read with later base-image reads can create a false proof even when each parser is
    locally correct.
14. A coordinator's read view must come from its already-open locked handle and be lifetime-bound to
    that lock. Reopening the path creates a substitution window and does not prove that parsing and
    mutation refer to the same container.
15. An append error is not proof that a capsule generation is absent. Recovery must adopt one exact,
    complete next generation and may truncate only when the prior checkpoint plus torn newest
    suffix is independently proven.
16. Activation and acceptance are different authority boundaries. Verification must remain
    rollbackable, and finalization must repeat the complete real-byte and semantic audit while
    requiring an explicit approval capability that production cannot mint accidentally.
17. A successful file `sync_all` does not by itself prove a newly created capsule's directory entry
    will survive power loss. Initial mutation authority must also require a parent-namespace
    barrier; an unsupported or rejected barrier leaves the file recoverable but returns no authority.
18. Windows deny-share opening can establish mandatory exclusion for a regular file. Advisory Unix
    locks cannot honestly be relabeled as production `Offline` evidence, so the current in-place
    preparation boundary must fail closed there until a stronger platform authority exists.
19. Capsule persistence faults must be cut after the image write but before every append write,
    flush, readback, and in-memory adoption boundary; a file-write error is not evidence of absence.
20. A zero `$Volume` dirty flag is necessary but insufficient clean-source evidence. The four
    protected `$MFT` records must byte-match the boot-sector `$MFTMirr` copy; mismatch or bounded
    incomplete evidence prevents clean source health and therefore grants no conversion authority.

## Independent interoperability gate

Internal parser round trips prove self-consistency, not mountability. The image-conversion alpha
therefore requires a reproducible matrix over copied candidate images:

1. `fsck.exfat -n` plus `dump.exfat` for exFAT.
2. NTFS-3G read-only image mount plus `ntfsinfo`/`ntfsls` for NTFS.
3. Windows attachment through a disposable VHD test harness, `chkdsk` without repair, and a
   read-only recursive metadata/content manifest comparison.
4. A second inspection after clean detach to detect tools that accepted the mount but rewrote
   metadata on close.

Any repair, auto-fix, or write-mount result is diagnostic only and cannot satisfy this gate.

## Reproducible source pins

Source heads were rechecked without retaining local clones on 2026-08-13:

- `exfatprogs`: `c98f9f9c3aa654ab501c664e8571dfdf1bca9693`
- `ntfs-3g`: `d327833ec1d5eb1358b6f2c37139f10a3460944d`
- `ntfs2btrfs`: `7841cc03721577b5ea8cb0583528a57f2e854ebd`
- Linux NTFS3 reference tree: `3aa1dcaa4f6f5ae08936491e08bd456f331f2d40`

The implementation treats these as behavioral references, not vendored code. In particular,
`mkntfs` is the checklist for required NTFS system structures; StarConverter still emits its own
safe Rust representation and validates generated bytes through independent parsers and overlays.
