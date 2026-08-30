# External structural validation

StarConverter's own parsers are not sufficient evidence of interoperability. This log records
independent, read-only checks against regular-file candidates. It does **not** authorize activation,
image conversion, writable mounting, repair, or physical-device access.

## 2026-08-25 generated boot-code revision requalification

The exFAT serializer now emits the specification-mandated `F4` formatter BootCode bytes when no
bootstrap implementation is supplied, and independently reparses every generated main/backup boot
region before returning a plan. Parser round trips cover all four legal sector sizes and reject a
tampered boot-code checksum.

The complete regular-file corpus was regenerated after that byte change. exfatprogs 1.2.2,
NTFS-3G 2022.10.3, the verified read-only exFAT loop/FUSE path, the read-only NTFS-3G path, and both
payload-manifest helpers all passed. Every artifact's SHA-256 was identical before and after the
checks. Current exFAT-bearing hashes are:

```text
structural exFAT             F515742D1778EF03964A26F6713738D1F0764DCA06BEBA2C9E1B47FF0C3B8989
structural exFAT VHD         7D72358FCB56518D022CA6F0EFBAD63F74215DB0AABEF7C24B7DBEBDE19DFCB8
rich exFAT                   C6714034E8BBD49D10DB1D89AD8D3F8874E8AC2B404A65F388593B9F443FCC72
converted rich exFAT         F2C2D0082693DD341AD65B2143F521A567B155803F30CDAED4C2EB2E3996B88E
converted Windows NTFS VHD   F58C1F68BF819331EA9B42EDE8646A3EC7F4D7A34A77034249ACBE04802B2DC3
converted Windows exFAT VHD  8FC03DE6F777B3473FCF08322C6B8159AD73E372CCEF3BB459853CF423C3EC47
edge exFAT                   DFAF63806D6B65347B4F13F3D33581C6511F557C47D1486ADBAA089B94989E58
converted edge exFAT         39E0CE5B51102F1E333871C4F4CE76CC84D2063ADAFD11FD007B6C1973F6401D
```

This refresh qualifies the current bytes only against the listed Linux tools and read-only
filesystem-driver paths. The non-elevated Windows detached-VHD preflight also passed against the
two refreshed pinned hashes above. Windows attachment, `chkdsk`, payload access, detach, and hash
qualification remain pending separately.

## Reproducing the fixtures

The ignored integration test emits seven raw source images, two fixed VHD wrappers, four actual
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
- `ntfs-structural-64k-cluster.img` exercises the large-cluster mirror profile: 64 initialized
  `$MFT`/`$MFTMirr` FILE slots, exact comparison through reserved record 15, and free formatted
  padding records whose in-use flags agree with `$MFT::$BITMAP`.
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

## 2026-08-29 64 KiB NTFS mirror qualification

The deterministic 16 MiB `ntfs-structural-64k-cluster.img` regular file was checked directly—no
loop device or mount—using the pinned WSL NTFS-3G validator bundle. `ntfsinfo -m` decoded NTFS 3.1,
a 65,536-byte cluster, a 65,536-byte `$MFT`, and a 65,536-byte/64-record `$MFTMirr`; `ntfsls -s -l`
enumerated the system namespace; and `ntfsfix -n` completed `$MFT`/`$MFTMirr` plus alternate-boot
processing successfully. SHA-256 was identical before and after every read-only command:

```text
8E15DF062B3F29D53936B8B5B9B05380A21D2919FE0FA735C238EAE72405297A
```

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

## 2026-08-21 formatter-origin differential corpus

Two 64 MiB regular files were created directly by exfatprogs 1.2.2 (`mkfs.exfat`, label `SCXFAT`)
and NTFS-3G 2022.10.3 (`mkntfs -F -Q`, label `SCNTFS`). No mount, loop device, VHD attachment, or
physical drive was used. The exFAT image passed `fsck.exfat -n`; the NTFS 3.1 image passed
`ntfsinfo -m`, root enumeration with `ntfsls`, and `ntfsfix -n`. StarConverter then completed its
bounded read-only inspection and normalized inventory for both images.

The NTFS image exposed three valid formatter differences that are now regression-covered:

- never-allocated MFT records may retain an embedded record number of zero; live records still
  require exact embedded identity;
- a directory FILE record may omit `FILE_ATTRIBUTE_DIRECTORY` from `$STANDARD_INFORMATION`; the
  FILE-record directory flag remains authoritative, while the bit on a non-directory is refused;
- NTFS-3G may include a root self-entry in `$I30`; StarConverter accepts it only when it exactly
  matches the root's self-parented `$FILE_NAME` evidence.

SHA-256 was identical before and after every independent check and both StarConverter inspections:

```text
formatter exFAT DFAC99E5F752220A5DAB0266DCA24174BB4A97727A2696E60B07534A8CADF357
formatter NTFS  F63C1D49970DF4112810EDD1630841413C25A366E9C47D8E46B37B2DBB5E2B71
```

The temporary formatter-origin files were removed after the hashes and results were recorded.

## 2026-08-21 populated formatter-origin feature corpus

The differential corpus was repeated with two 128 MiB regular files and real filesystem-driver
writes. `mkfs.exfat` from exfatprogs 1.2.2 and `mkntfs -F -Q` from NTFS-3G 2022.10.3 created the
filesystems. fuse-exfat 1.4.0 and NTFS-3G 2022.10.3 then populated only those pinned image files.
The exFAT driver used a loop device whose backing file was checked before use; the NTFS driver
opened the regular image directly. No physical drive, partition, VHD, or host filesystem was
selected.

Both filesystems received the same seven-file manifest beneath `/alpha/Ωmega/🚀`:

- exact 0, 1, 4,095, 4,096, 4,097, and 8,191-byte deterministic payloads;
- composed Latin, Greek, CJK, and surrogate-pair Unicode names;
- a deterministic 40 MiB payload written after three 24 MiB fillers were allocated and the middle
  filler was deleted; the remaining fillers were deleted after the payload was synchronized.

That allocation pattern produced two physical runs for the exFAT payload (and a FAT chain rather
than `NoFatChain`) and three NTFS runs as independently printed by `ntfsinfo -v -F`. The corpus
therefore exercised empty/resident data, both sides of the 4 KiB cluster boundary, multi-cluster
data, nested Unicode namespace traversal, and noncontiguous allocation in both filesystems.

Independent read-only results:

| Candidate | Check | Result |
| --- | --- | --- |
| populated exFAT | `fsck.exfat -n` | Exit 0: clean, four directories, seven files |
| populated exFAT | verified read-only loop plus `mount.exfat-fuse -o ro` | All seven exact path, length, and SHA-256 manifest records matched |
| populated NTFS | `ntfsinfo -m`, recursive `ntfsls`, `ntfsfix -n` | Exit 0; NTFS 3.1 metadata and the full nested namespace decoded; MFT/MFTMirr and alternate boot sector processed successfully |
| populated NTFS | `ntfs-3g -o ro` | All seven exact path, length, and SHA-256 manifest records matched |
| both | `starconverter inspect` | Complete bounded inventory and normalization succeeded without writes |

SHA-256 immediately before and after every read-only checker, payload mount, and StarConverter
inspection was identical:

```text
populated formatter exFAT AF26596436817B07E5197268FB0563C64607B1F7E77B40CB198E66D9A7F2D0DE
populated formatter NTFS  AF9435189688FCCE46890A47B0E214958575328CCF86E8F7D3A8F270079DF029
```

This run exposed two valid interoperability distinctions and converted them into bounded
regressions:

1. [Microsoft exFAT section 3.1.18](https://learn.microsoft.com/en-us/windows/win32/fileio/exfat-specification#3118-percentinuse-field)
   requires `PercentInUse` to be rounded down. The image had 10,254 allocated of 32,256 clusters:
   31.789%, spec value 31, stored value 32. fuse-exfat 1.4.0's
   [`finalize_super_block`](https://github.com/relan/exfat/blob/v1.4.0/libexfat/mount.c)
   deliberately uses `(used * 100 + total / 2) / total`, or nearest-integer rounding. The active
   Allocation Bitmap remains authoritative. StarConverter now accepts only `0xFF`, the exact spec
   floor, or that exact legacy nearest formula; a different value, including floor plus two, is
   still refused. The current evidence model has no separate compatibility-warning collection, so
   a successful inspection does not yet surface which accepted representation was present.
2. NTFS-3G kept zero as the cached `$FILE_NAME` data size while its `$I30` index keys contained the
   current 1/4,095/4,096/4,097/8,191/41,943,040-byte values. The
   [NTFS `$FILE_NAME` documentation](https://flatcap.github.io/linux-ntfs/ntfs/attributes/file_name.html)
   states that duplicated fields other than the parent can become stale until the filename changes.
   Namespace agreement now requires exact target and parent record/sequence, namespace, UTF-16
   name, and well-formedness. Cached size, allocation, flags, and EA/reparse fields are preserved
   from both sources but are not treated as current semantics; stream attributes, record flags, and
   `$STANDARD_INFORMATION` remain authoritative. Tests independently mutate and refuse every
   identity field, and runlist/allocation/content checks are unchanged.

The temporary formatter-origin images, staging payloads, mount directories, and reference-source
checkout were removed after evidence was recorded.

## What this does not prove

- The recommended exFAT up-case profile removes the earlier ASCII-only limitation, but a clean
  Linux checker result still does not prove every Windows case-collation behavior.
- `ntfsfix -n` and NTFS-3G metadata readers are not substitutes for a clean Windows `chkdsk` pass.
- The rich, edge, and formatter-origin fixtures cover ordinary payloads, nesting,
  Unicode/surrogate/maximum-length
  names, empty and allocation-boundary files, and two- and three-way fragmented allocation. The
  populated formatter-origin corpus closes the earlier generic feature-specific corpus gap, but
  does not cover
  alternate streams, hard links, ACLs, sparse/compressed data, reparse points,
  multi-level directory indexes, or a completed cross-format execution.
- No candidate has been mounted by Windows, mounted writable, repaired, converted in-place, or
  tested on a physical drive.

The next external gates are Windows-origin feature images and disposable-VHD `chkdsk`, detach,
hash comparison, and StarConverter reinspection.

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
