# External structural validation

StarConverter's own parsers are not sufficient evidence of interoperability. This log records
independent, read-only checks against regular-file candidates. It does **not** authorize activation,
image conversion, writable mounting, repair, or physical-device access.

## Reproducing the fixtures

The ignored integration test emits four raw partition images, two fixed VHD wrappers, two actual
cross-format copy-export candidates, and their schema-v4 escrow sidecars beneath
`target/external-validator-fixtures`:

```text
cargo test -p starconverter-core --test export_external_fixtures -- --ignored --nocapture
```

When the validator bundle is available in WSL, the repository script reproduces the
export, all read-only checks, and the before/after hash comparison:

```text
powershell -File scripts/validate-external-fixtures.ps1
```

The bundle must contain exfatprogs, NTFS-3G, and `sbin/mount.exfat-fuse`. The two mount checks run
as WSL root solely to create their temporary mount state. The exFAT helper creates a read-only loop
device for the exact regular fixture, verifies both its backing path and kernel `RO` flag, and
detaches it in a trap. No physical device is discovered or selected.

- `exfat-structural-recommended-upcase.img` uses the exact 5,836-byte Microsoft/exfatprogs
  recommended up-case profile (checksum `0xE619D30D`), not the serializer's reduced unit-test table.
- `ntfs-structural-activation-blocked.img` includes the structural NTFS metadata implemented at
  that revision. The public serializer still reports `activation_ready() == false`.
- `exfat-structural-validation.vhd` and `ntfs-structural-validation.vhd` wrap separately generated
  partition candidates at LBA 2048 behind a deterministic MBR and fixed VHD 1.0 footer. Their boot
  sectors contain that same partition offset; the core independently reparses the MBR, footer,
  checksum, identity, CHS/LBA geometry, and filesystem BPB before export.
- `exfat-rich-namespace-payload.img` and `ntfs-rich-namespace-payload.img` contain the same nested
  `/alpha/Ωmega` namespace, an empty file, a 14-byte root file, and a 6,000-byte file split across
  noncontiguous physical extents. `rich-fixture-manifest.txt` records the deterministic stream IDs,
  logical lengths, and physical offsets.
- `converted-rich-exfat-to-ntfs.img` and `converted-rich-ntfs-to-exfat.img` are produced through
  the public create-new exporter from those opposite-format rich sources. Each export binds exact
  before-images to the source, writes only the new file, reinspects it, proves logical manifest
  equality, persists escrow, and re-hashes the source before returning evidence.

The exporter writes no device and exposes no production write command. It only creates or replaces
these regular files under Cargo's `target` directory.

## 2026-08-20 baseline

Environment:

- WSL2 Ubuntu
- exfatprogs 1.2.2
- ntfs-3g 2022.10.3
- 32 MiB regular image files
- temporary exFAT FUSE and NTFS-3G mounts with `-o ro`; no writable mounts or repair options

Results:

| Candidate | Read-only check | Result |
| --- | --- | --- |
| exFAT | `fsck.exfat -n` | Exit 0: clean, one directory, zero files |
| NTFS | `ntfsinfo -m` | Exit 0; NTFS 3.1 geometry, MFT, mirror, bitmap, and AttrDef decoded |
| NTFS | `ntfsls -s -l` | Exit 0; records for AttrDef, BadClus, Bitmap, Boot, Extend, LogFile, MFT, MFTMirr, Secure, UpCase, and Volume enumerated |
| NTFS | `ntfsfix -n` | Exit 0; MFT/MFTMirr and alternate boot sector processed successfully |
| rich exFAT | `fsck.exfat -n` | Exit 0: clean, three directories, three files |
| rich exFAT | temporary `mount.exfat-fuse -o ro` mount over a verified read-only loop backed by the regular fixture | Exit 0; nested paths opened through the filesystem driver, exact logical sizes checked, payload SHA-256 values matched, then unmounted and detached in a trap |
| rich NTFS | `ntfsinfo -m`, `ntfsls` for `/`, `/alpha`, `/alpha/Ωmega`, `ntfsfix -n` | Exit 0; nested Unicode namespace, empty file, 14-byte file, and 6,000-byte fragmented file enumerated; MFT/mirror/backup processed successfully |
| rich NTFS | temporary `ntfs-3g -o ro` mount | Exit 0; nested paths opened through the filesystem driver, exact logical sizes checked, payload SHA-256 values matched, then unmounted in a trap |
| converted NTFS (from rich exFAT) | `ntfsinfo -m`, `ntfsls`, `ntfsfix -n`, temporary `ntfs-3g -o ro` mount | Exit 0; the cross-format output reparsed, system metadata processed, nested Unicode paths opened, and exact payload hashes matched |
| converted exFAT (from rich NTFS) | `fsck.exfat -n`, temporary `mount.exfat-fuse -o ro` mount | Exit 0: clean; the cross-format output exposed three directories/three files, nested Unicode paths, and exact payload hashes |

SHA-256 immediately before and after all checks was identical:

```text
exFAT  1EB46527E0ECC81DE4AA8DC10A00C80CA471ECC30AC8A3A161118A4F431BD9B4
NTFS   ED957960B1FA28E9CE3D9427017E67C32552FC23FF673377F266F50BF6E92B17
exFAT VHD  43CD47A33EC2BF2D97BD94A1303EB3B30677E0241F6177AC26237A3FFF04048C
NTFS VHD   7028731487E5478738FC5124FE471015E4096D59DA87038A4727A482B4AA5525
rich exFAT  2FAAF7DA04D166705EC00306D26DE5E33CA459AB7926A707AE2F3DCA92F11E44
rich NTFS   51F19F2866A10327E717C2FD5472156A8F24B04FEFE98DB6E7E8BB80F2D0E5B1
rich manifest A31588EC970212AF22234DC357F11B0CB851817C580C0F778150194F391191C6
converted NTFS 5F0C6D191E6096F993109835880BD8D2547D2C644CC85BFAD14348DA6550C37E
converted NTFS escrow CF5EAECD1618FCA492EBB397545EF8F9A5FE43D45363F259CBAFF6EDDE619519
converted exFAT F4E39AEF0716ADAE2C807C8A6F5C3CF9228A29F352D7759349367FBD5ACA9DD4
converted exFAT escrow 9F55333C729FA62CF8467C1A43D3CF9BA267D4280C58F17BC8124C2113B4B1AC
```

`dump.exfat` also exited successfully and decoded the boot geometry. Its root-entry summary assumes
a positional volume-label entry and mislabels later entries when the optional label is absent, so
that diagnostic is retained as supporting output rather than a release gate.

## What this does not prove

- The recommended exFAT up-case profile removes the earlier ASCII-only limitation, but a clean
  Linux checker result still does not prove every Windows case-collation behavior.
- `ntfsfix -n` and NTFS-3G metadata readers are not substitutes for a clean Windows `chkdsk` pass.
- The richer fixture and actual cross-format exports cover ordinary payloads, nesting, Unicode names, empty files, and fragmented
  allocation, but not alternate streams, hard links, ACLs, sparse/compressed data, reparse points,
  multi-level directory indexes, or a completed cross-format execution.
- No candidate has been mounted by Windows, mounted writable, repaired, converted in-place, or
  tested on a physical drive.

The next external gates are broader corpus fixtures, per-candidate evidence binding, Windows
disposable-VHD `chkdsk`, namespace/content manifest comparison, detach, and StarConverter
reinspection.

The current desktop session is not elevated. Microsoft documents that VHD attachment requires
administrator privileges, so the generated VHDs were not attached in this run. When that gate is
authorized, it must use `Mount-DiskImage -Access ReadOnly`, operate only on these copied VHD files,
run `chkdsk` without repair, detach in a `finally` path, and confirm all four fixture hashes again.
