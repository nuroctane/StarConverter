# Research basis

The architecture is based on primary specifications, platform APIs, and source inspection of active
filesystem tooling.

## Authoritative references

- Microsoft [exFAT File System Specification](https://learn.microsoft.com/en-us/windows/win32/fileio/exfat-specification)
- Microsoft [File System Functionality Comparison](https://learn.microsoft.com/en-us/windows/win32/fileio/filesystem-functionality-comparison)
- Microsoft [NTFS overview](https://learn.microsoft.com/en-us/windows-server/storage/file-server/ntfs-overview)
- Microsoft [Master File Table](https://learn.microsoft.com/en-us/windows/win32/devnotes/master-file-table)
- Microsoft [NTFS attribute types](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/a82e9105-2405-4e37-b2c3-28c773902d85)
- Microsoft archived [`convert.exe` documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc730863%28v%3Dws.11%29)
- Microsoft [`FSCTL_MOVE_FILE`](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_move_file)
- Microsoft [`FSCTL_LOCK_VOLUME`](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_lock_volume)
- Microsoft [`FSCTL_DISMOUNT_VOLUME`](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_dismount_volume)
- Microsoft [file buffering](https://learn.microsoft.com/en-us/windows/win32/fileio/file-buffering)
- Linux kernel [NTFS3 documentation](https://docs.kernel.org/filesystems/ntfs3.html)

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
