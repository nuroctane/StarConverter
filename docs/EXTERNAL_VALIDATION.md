# External structural validation

StarConverter's own parsers are not sufficient evidence of interoperability. This log records
independent, read-only checks against regular-file candidates. It does **not** authorize activation,
image conversion, writable mounting, repair, or physical-device access.

## Reproducing the fixtures

The ignored integration test emits six raw source images, two fixed VHD wrappers, four actual
cross-format copy-export candidates, four candidate-bound schema-v4 escrow sidecars, and two
payload manifests beneath
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
- `converted-rich-exfat-to-ntfs-windows.vhd` and
  `converted-rich-ntfs-to-exfat-windows.vhd` wrap actual public-exporter conversions whose target
  BPBs were generated for LBA 2048. They contain the rich namespace/payload corpus and are the only
  two inputs accepted by `scripts/validate-windows-vhd.ps1`.
- `exfat-rich-namespace-payload.img` and `ntfs-rich-namespace-payload.img` contain the same nested
  `/alpha/Ωmega` namespace, an empty file, a 14-byte root file, and a 6,000-byte file split across
  noncontiguous physical extents. `rich-fixture-manifest.txt` records the deterministic stream IDs,
  logical lengths, and physical offsets.
- `converted-rich-exfat-to-ntfs.img` and `converted-rich-ntfs-to-exfat.img` are produced through
  the public create-new exporter from those opposite-format rich sources. Each export binds exact
  before-images to the source, writes only the new file, reinspects it, proves logical manifest
  equality, persists escrow bound to the source/candidate/manifest hashes and direction, and
  re-hashes the source before returning evidence.
- `exfat-edge-corpus.img`, `ntfs-edge-corpus.img`, and their converted counterparts add a nested
  Unicode path, a surrogate-pair filename, a 255-UTF-16-unit filename, an empty file, 1/4095/4096/
  4097/8191/9000-byte payloads, and a 9,000-byte file split over three physical extents.
  `edge-corpus-manifest.tsv` supplies exact path, length, and SHA-256 expectations to both mount
  helpers; all ten payloads are verified through each filesystem driver.

The exporter writes no device and never overwrites a path. It builds each regular output beneath a
uniquely named partial path, verifies it, publishes escrow first with atomic no-clobber hard links,
and exposes the final candidate name only after all checks succeed. Publication therefore fails
closed on output filesystems without hard-link support. Unix publication synchronizes the parent
directory before and after partial-link cleanup; Windows evidence explicitly reports directory
durability as unsupported until a Rust-1.85-compatible safe platform primitive is qualified. The
fixture command removes and recreates only its named files beneath Cargo's `target` directory.

## 2026-08-21 expanded corpus

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
| edge exFAT, source and converted | `fsck.exfat -n`, temporary verified-loop `mount.exfat-fuse -o ro` mount, TSV manifest | Exit 0: clean; three directories/ten files; all ten path/length/SHA-256 records matched |
| edge NTFS, source and converted | `ntfsinfo -m`, `ntfsls`, `ntfsfix -n`, temporary `ntfs-3g -o ro` mount, TSV manifest | Exit 0; all ten path/length/SHA-256 records matched |

SHA-256 immediately before and after all checks was identical:

```text
exFAT  1EB46527E0ECC81DE4AA8DC10A00C80CA471ECC30AC8A3A161118A4F431BD9B4
NTFS   ED957960B1FA28E9CE3D9427017E67C32552FC23FF673377F266F50BF6E92B17
exFAT VHD  43CD47A33EC2BF2D97BD94A1303EB3B30677E0241F6177AC26237A3FFF04048C
NTFS VHD   7028731487E5478738FC5124FE471015E4096D59DA87038A4727A482B4AA5525
converted Windows NTFS VHD 4D1CDDB7676FE60A541A432B38E32880621B88B5CA6404097FAAC357A8291E2F
converted Windows exFAT VHD EE905BAEE3EEFD654F15EF5514110C2DCF9E6E58DB28751B8833D79FAF8F5B7A
rich exFAT  2FAAF7DA04D166705EC00306D26DE5E33CA459AB7926A707AE2F3DCA92F11E44
rich NTFS   51F19F2866A10327E717C2FD5472156A8F24B04FEFE98DB6E7E8BB80F2D0E5B1
rich manifest A31588EC970212AF22234DC357F11B0CB851817C580C0F778150194F391191C6
converted NTFS 5F0C6D191E6096F993109835880BD8D2547D2C644CC85BFAD14348DA6550C37E
converted NTFS escrow AF2D61C5A6144C16A65FD01009623B54FF484BACFEE2425DCA5DA3FC991B3818
converted exFAT F4E39AEF0716ADAE2C807C8A6F5C3CF9228A29F352D7759349367FBD5ACA9DD4
converted exFAT escrow 12BBF7557BA471BD010146D7E29535AC6FA70E99BB3C68C469EA7C41B4E4AA2E
edge exFAT 679DB6944D80ABAF46F48B55EB6290CB45892E34BEC1F57BCBFABF7BC0D5E001
edge NTFS 0960E447016DAAE38EA5D4CA03DD061064E877149D4BCF1155151B691BEC30A6
edge converted NTFS 45A04763865367A440A916B17EF6CBE547B67D66EAF1FF28CE17741AB4949760
edge converted NTFS escrow C109DEC2DD8EBFE0FD2B538662F21504CB8E8F1BE141D4D9E76DCD7FB1DE84AF
edge converted exFAT C92A8EFBCB1D1A9EA68730169C9A7BD59174FC4455BD4D5E4207F9ACAC416CA7
edge converted exFAT escrow C39C645B96395ABECC21D391D52A1E8485718BA20E6100BE231A1D2A93CD7834
edge manifest C5DCE3F82BA24AF24C4C941EA56032873281D03A7BE530FCEDEC3A6243B10490
```

`dump.exfat` also exited successfully and decoded the boot geometry. Its root-entry summary assumes
a positional volume-label entry and mislabels later entries when the optional label is absent, so
that diagnostic is retained as supporting output rather than a release gate.

## What this does not prove

- The recommended exFAT up-case profile removes the earlier ASCII-only limitation, but a clean
  Linux checker result still does not prove every Windows case-collation behavior.
- `ntfsfix -n` and NTFS-3G metadata readers are not substitutes for a clean Windows `chkdsk` pass.
- The rich and edge fixtures cover ordinary payloads, nesting, Unicode/surrogate/maximum-length
  names, empty and allocation-boundary files, and two- and three-way fragmented allocation, but not
  alternate streams, hard links, ACLs, sparse/compressed data, reparse points,
  multi-level directory indexes, or a completed cross-format execution.
- No candidate has been mounted by Windows, mounted writable, repaired, converted in-place, or
  tested on a physical drive.

The next external gates are feature-specific corpus fixtures and Windows disposable-VHD `chkdsk`,
detach, hash comparison, and StarConverter reinspection.

The current desktop session is not elevated. Microsoft documents that VHD attachment requires
administrator privileges, so the generated VHDs were not attached in this run. When that gate is
authorized, it must use `Mount-DiskImage -Access ReadOnly -NoDriveLetter`, operate only on exact
copied VHD paths, resolve the associated volume through that image, run `chkdsk` against its volume
GUID without repair flags, detach in a `finally` path, and confirm hashes again.

The fail-closed harness for that gate is `scripts/validate-windows-vhd.ps1`. It pins both VHD names,
lengths, and SHA-256 values; refuses network/reparse/clustered inputs and already-attached images;
asserts one read-only non-boot MBR virtual disk, one LBA-2048 partition, one expected filesystem,
no drive letter, an exact volume-to-image association, and exact sizes/SHA-256 values for all three
rich-corpus payloads through the Windows filesystem driver; then detaches and re-hashes in all
paths. It must be run later from an elevated Windows PowerShell 5.1 prompt. It has not been run in
this non-elevated session, so Windows filesystem qualification remains pending.

The detached, non-elevated identity/container preflight is safe to run separately and performs no
attachment:

```powershell
powershell.exe -NoProfile -File scripts\validate-windows-vhd.ps1 -PreflightOnly
```

Both preflight and the later elevated driver run can emit a create-new JSON evidence file with
`-ReportPath C:\path\validation.json`. Schema
`starconverter.windows-vhd-validation` v1 records the exact before/after VHD hashes, detach state,
filesystem and partition observations, payload hashes, CHKDSK exit/transcript, Windows and
PowerShell versions, and filesystem-driver versions. A report is written only after every requested
case succeeds, and an existing report path is never replaced. The detached-preflight mode is
explicitly labeled and must not be mistaken for Windows filesystem-driver qualification.
