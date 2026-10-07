# External structural validation

StarConverter's own parsers are not sufficient evidence of interoperability. This log records
independent, read-only checks against regular-file candidates. It does **not** authorize activation,
image conversion, writable mounting, repair, or physical-device access.

## 2026-10-07 Windows VHD pin refresh, drift guard, and continuous driver lane

The two Windows VHD candidates drifted from their 2026-08-25 pins without any check noticing:
the inline `$SECURITY_DESCRIPTOR`, nonresident security-descriptor, `$MFT` fixpoint, and exFAT
benign-entry escrow changes all altered the exported bytes while
`scripts/validate-windows-vhd.ps1`, `windows_validation.rs`, and this log still carried the old
hashes. The non-elevated preflight therefore refused the regenerated candidates.

Both pins were refreshed from the regenerated fixtures and now read:

```text
converted Windows NTFS VHD   ED4CD7630790095EB0704C1DEE4AA8B25249A5A0F2F98385FB36FD749F9CAC9B
converted Windows exFAT VHD  3F52FE1A6997A5DAFBA4B66D4C7947E9DFAEAB801A578E597775D9C3F3F0EA41
```

Two guards now keep the three pin sites in lockstep:

- `export_external_fixtures` re-hashes both generated VHDs and asserts the public
  `windows_validation::{NTFS_CASE_HASH, EXFAT_CASE_HASH, PINNED_VHD_BYTES}` constants, so any
  serializer byte change fails the Linux `external-images` lane until the pins are refreshed on
  purpose.
- A `windows_validation` unit test reads `scripts/validate-windows-vhd.ps1` and asserts the same
  two case names and hashes, all three payload lengths and hashes, and both VHD byte lengths.

CI gained a `windows-vhd` lane on `windows-latest`, which runs elevated. It regenerates the two
candidates, runs the detached preflight, then the full harness: `Mount-DiskImage -Access ReadOnly
-NoDriveLetter`, one read-only non-boot MBR disk, one LBA-2048 partition, expected filesystem,
volume GUID round trip, exact payload sizes and hashes through the Windows filesystem driver,
`chkdsk` without repair flags, detach in `finally`, and before/after VHD hash equality. The
create-new JSON report is verified by `starconverter verify-windows-report` and uploaded as
`windows-vhd-evidence`. The non-elevated local preflight passed against the refreshed pins and its
report verified through the CLI (Windows 10.0.26200, PowerShell 5.1.26100.8655).

## 2026-09-01 forced NTFS-to-exFAT relocation qualification

A dedicated 32 MiB NTFS 3.1 regular image placed one 8,192-byte file at byte
`24 MiB + 4 KiB`: valid for the 4 KiB NTFS source, deliberately misaligned for an 8 KiB exFAT
target cluster. The legacy one-pass serializer refused that placement. The draft/solve/finalize
path produced exactly one sealed relocation inside the pinned exFAT cluster heap, regenerated FAT,
allocation-bitmap, directory-stream, first-cluster, `NoFatChain`, and `PercentInUse` metadata, and
exported a new regular image. The source graph, derived target graph, and exact layout were carried
as one opaque authority; the export was also bound to a pre-planning source SHA-256 snapshot.

Independent read-only results:

- NTFS-3G `ntfsinfo -m` and `ntfsfix -n` accepted the source.
- exfatprogs 1.2.2 `fsck.exfat -n` reported the candidate clean with one directory and one file.
- the verified read-only loop/FUSE path opened `/relocated.bin`, proved length 8,192, and matched
  SHA-256 `9ef93d4a62d53c78329eadfde79292b3f613be077f4e1af67ad28e75cea3d777`.
- all 29 regular-file corpus artifacts had identical SHA-256 values before and after validation.

```text
NTFS source             7B85A37FEFD4C1C4312A0DEF7BC59E07A72DE4625CD94EAD0C446666176D5502
relocated exFAT         C2B1C7057E4FCA78929D66C74D92BFCCB1C9699FC970E76B28803E5523285ED1
bound escrow            49F92F4FB284A049244675E6391E1A4504FF6CFB88F48F06855ACB32706FAA87
relocation manifest     8E757C5317E4B569B8F8FC5C3101EFC6A505913AD16B75006A367DE0348407FA
```

This qualifies the current create-new reverse-relocation bytes against the listed Linux tools. It
does not qualify Windows attachment/CHKDSK, in-place activation, or physical media.

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
two refreshed pinned hashes above. The two Windows VHD hashes listed here were superseded on
2026-10-07; see that section for the current pins and the continuous Windows driver lane.

## Reproducing the fixtures

The ignored integration test emits eight raw source images, four fixed VHD wrappers, seven actual
cross-format copy-export candidates, seven candidate-bound schema-v4 escrow sidecars, and three
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
- `ntfs-misaligned-8k-payload.img` and `converted-misaligned-ntfs-to-exfat.img` are the forced
  reverse-relocation pair described above. `misaligned-relocation-manifest.tsv` binds the one
  relocated path, length, and payload digest to the read-only driver check.
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
- No candidate has been mounted writable, repaired, converted in-place, or tested on a physical
  drive. Windows attachment is read-only, letterless, and limited to the two pinned rich-corpus
  VHDs exercised by the `windows-vhd` CI lane.

The next external gates are Windows-origin feature images and StarConverter reinspection of
Windows-attached candidates.

Microsoft documents that VHD attachment requires administrator privileges, so the local desktop
session never attaches the generated VHDs. The elevated gate runs on the `windows-latest` CI
runner instead. It uses `Mount-DiskImage -Access ReadOnly -NoDriveLetter`, operates only on exact
generated VHD paths, resolves the associated volume through that image, runs `chkdsk` against its
volume GUID without repair flags, detaches in a `finally` path, and confirms hashes again.

The fail-closed harness for that gate is `scripts/validate-windows-vhd.ps1`. It pins both VHD names,
lengths, and SHA-256 values; refuses network/reparse/clustered inputs and already-attached images;
asserts one read-only non-boot MBR virtual disk, one LBA-2048 partition, one expected filesystem,
no drive letter, an exact volume-to-image association, and exact sizes/SHA-256 values for all three
rich-corpus payloads through the Windows filesystem driver; then detaches and re-hashes in all
paths. It requires an elevated Windows PowerShell 5.1 prompt when run by hand.

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

## Continuous unmounted structural checks

The `Independent unmounted image checks` CI job regenerates the regular-file corpus on Ubuntu
24.04 and invokes distro exfatprogs and NTFS-3G directly. The script
`scripts/validate-external-images.py` requires the exact 29-artifact inventory before starting:
seven exFAT images, eight NTFS images, seven escrow sidecars, four VHD wrappers, and three
manifests. Missing, nonregular, symbolic-link, and hard-link inputs are refused.

The seven exFAT images receive `fsck.exfat -n`; the eight NTFS images each receive `ntfsinfo -m`,
recursive `ntfsls`, and `ntfsfix -n`. No mount helper, repair flag, elevation, or device discovery is
used for validation. Whole VHD wrappers are hashed but never supplied to raw filesystem readers;
the corresponding filesystem partition images are checked directly.

The runner records distro package versions in its log and uploads a create-new JSON report with
every command, exit status, transcript, and before/after SHA-256 for all 29 artifacts. It checks the
hashes even after tool failures and timeouts. A failed validator or changed artifact makes the job
fail. This is recurring independent structural evidence. The existing WSL mount-based runner
remains a separate, broader qualification lane.

The same job runs `scripts/validate-ntfs-payloads.py`, which makes 30 binary `ntfscat` reads:
three rich-corpus files in each of three NTFS images, ten edge-corpus files in each of two NTFS
images, and the misaligned-source relocation payload. The eight inputs (six regular images and
two manifests) must be unaliased regular files. Bounded, strict UTF-8 TSV manifests must match
the deterministic exporter expectations before any reader starts. Every output must have a
successful exit status, exact logical byte length, and exact SHA-256; even an empty output cannot
pass after a failed tool exit. Binary stdout and diagnostics are capped, hung readers are killed,
and all eight input hashes are compared again after failures. A separate create-new
`ntfs-payload-report.json` records expected/actual sizes and digests without embedding file bytes.
Harness regressions cover corrupt, truncated, excess, empty, binary, and Unicode outputs, bad
manifests, output floods, timeouts, linked inputs, mutation, and report no-clobber behavior.

These checks establish the selected logical payloads, not directory completeness, Windows driver
compatibility, preservation of all metadata or specialized NTFS features, or in-place activation.

## Continuous large-directory routing checks

A separate four-artifact corpus in `target/external-large-directory-fixtures` contains a 32 MiB
exFAT source, its public-export NTFS candidate, its bound escrow, and an exact 128-row manifest.
All files are empty and have long Unicode names under `/alpha`. The generator reinspects the
actual candidate and requires nonresident `$INDEX_ALLOCATION:$I30`, complete directory inventory,
leaf blocks, and at least one internal `INDX` node. This prevents the case from silently regressing
into a small resident-only index.

`scripts/validate-large-directory.py` checks source and target structure with `fsck.exfat -n`,
`ntfsinfo -m`, and `ntfsfix -n`; compares the exact name multiset from `ntfsls -a -p /alpha`; and
requires all 128 `ntfscat` path lookups to succeed with zero bytes. The expected listing includes
exactly one NTFS-3G-synthesized self entry (`.`); the root-parent entry is filtered by NTFS-3G's
metadata rule. Name order is deliberately ignored, but missing, duplicate, and foreign names fail.
The commands follow the [NTFS-3G manual](https://manpages.ubuntu.com/manpages/noble/man8/ntfsls.8.html)
and the tool's [listing implementation](https://github.com/tuxera/ntfs-3g/blob/2022.10.3/ntfsprogs/ntfsls.c).

Manifest bytes must exactly match bounded deterministic expectations before tools start. Binary
output is bounded (32 KiB for listing/structural transcripts, zero for empty-file payloads), reader
timeouts fail closed, and all four input hashes are compared after failures. The create-new JSON
report is uploaded alongside the existing corpus reports. This is independent qualification of
the generated multi-level index's enumeration and lookup routing, not native-driver mounting,
arbitrary NTFS directory profiles, metadata losslessness, or activation authorization.

The CI corpus lives in an isolated job workspace. The harness validates paths before starting
external tools; it does not establish exclusion against a hostile process replacing files during
validation. Production conversion continues to require its own locked-handle authority.

## Formatter-origin ADS and inline security descriptor probe

`scripts/validate-formatter-ads.py` creates a fresh 64 MiB ordinary image beneath an explicitly
supplied existing workspace. NTFS-3G `mkntfs` formats only that new file; `ntfscp` adds a 14-byte
unnamed stream, a 16-byte resident named stream, and an 8193-byte nonresident named stream.
NTFS-3G independently checks their exact binary bytes and source storage forms. The harness then
attempts an escrow NTFS -> exFAT -> NTFS create-new round trip, with read-only structural checks,
exact restored names/sizes/bytes, bounded subprocess output, and before/after artifact hashes.
Restored residency is recorded, not required to reproduce the original layout. The schema-v2
report also dumps the inline `$SECURITY_DESCRIPTOR` of the root directory (`ntfscat -a 0x50 -i 5`)
and of `/payload.bin` (`ntfscat -a 0x50 <image> /payload.bin`) on the source and on the restored
image, requires each dump to be a bounded revision-1 self-relative descriptor, and fails the
exact object whose restored bytes differ from the NTFS-3G source. All case files remain available
after success or failure; the JSON report is create-new, never overwritten.

Run only in an isolated fixture workspace, with independent tools on PATH:

```text
python3 scripts/validate-formatter-ads.py target --cli <starconverter executable> --report target/<new-report>.json
python3 -m unittest discover -s scripts -p test_formatter_ads.py
```

The CI `external-images` job runs this probe on every push with the Ubuntu `ntfs-3g` and
`exfatprogs` packages and uploads `target/formatter-ads-report.json` with the other evidence.

Without root or network in WSL, the same tools run from an unpacked validator root. Download the
`ntfs-3g`, `libntfs-3g89t64`, and `exfatprogs` `.deb` packages into one directory, then:

```text
powershell -File scripts/validate-formatter-ads.ps1 -DebDirectory <deb directory>
```

The driver builds the CLI, calls `scripts/extract-validator-bundle.sh` (`dpkg -x` into
`/tmp/starconverter-validators-current/root`, refusing roots outside `/tmp` or `$HOME` and
failing on missing tools or unresolved shared libraries) only when the root lacks `mkntfs`, runs
the probe through `scripts/run-formatter-ads-probe.sh` with that root on `PATH` and
`LD_LIBRARY_PATH`, refuses an existing report name, and prints the descriptor digests from the
passing report. Both shell helpers also run directly on Linux.

The October 2026 NTFS-3G 2022.10.3 run is **not a passing round-trip qualification**. It exposed
nonzero quadword-alignment slack after a mapping-pairs zero terminator, left by resident-to-
nonresident promotion. Attribute parsing now accepts at most seven such alignment bytes without
interpreting them as runs; standalone mapping-pairs parsing remains strict. This follows the
[Microsoft attribute format](https://learn.microsoft.com/en-us/windows/win32/devnotes/attribute-record-header).
Geometry, run-count, VCN, LCN, terminator, and resource bounds remain enforced.

After that compatibility fix, the source inventories completely, but it contains resident and
nonresident inline `$SECURITY_DESCRIPTOR` attributes (`0x50`), whose presence contributes
access-control semantics even when a 48-byte `$STANDARD_INFORMATION` has no security ID.

Inline descriptor support is now implemented in-tree. The read-only inventory captures the exact
bytes of unnamed resident and fully mapped nonresident `0x50` attributes up to 64 KiB; a bounded
self-relative validator (owner/group SIDs, ACL revision 2 or 4, allow/deny/audit ACEs only) must
accept them; the preservation policy then classifies `SecurityDescriptors` as escrow-required and
the v8 inner NTFS escrow snapshot retains the exact bytes. The escrow-restored exFAT→NTFS path
re-emits each descriptor as a resident `0x50` attribute, with security ID 0 when the inline
descriptor alone governs the object and the pinned `$Secure` identifier when both coexist. The
in-tree NTFS→exFAT(+escrow)→NTFS round trip proves byte-exact restoration on the root and on a
junction. Census-only evidence (presence without captured bytes), malformed or out-of-profile
descriptors, named or flagged `0x50` attributes, and unpinned security IDs remain refusals in
strict and escrow modes; content-only assessment records them as explicit losses and is not a
lossless workaround. Do not strip descriptors, patch source security, or widen the validator to
make the probe pass.

Re-running the probe against the capture path exposed two restore-side defects, both fixed
in-tree with regression tests:

- The layout draft refused the captured 8193-byte named stream with `ResidentDataTooLarge`
  because draft serialization treated every captured resident stream as resident. The draft now
  emits a run-less placeholder for oversized file streams, which the solver materializes into
  destination clusters before final serialization (the final path is unchanged and still refuses).
- `mkntfs` gives the root directory a 4140-byte nonresident `$SECURITY_DESCRIPTOR` that cannot
  sit inside a 1 KiB FILE record. The serializer now lays descriptors larger than the resident
  budget contiguously at the front of the reserved directory-index metadata region (identically
  in draft and final) and emits them as nonresident `0x50` attributes; a budget mismatch between
  the two passes fails closed with `DestinationLayoutChanged`.

### 2026-10 formatter-origin run (passing)

Tools: NTFS-3G 2022.10.3 (`mkntfs`, `ntfscp`, `ntfsls`, `ntfscat`, `ntfsinfo`, `ntfsfix`) and
exfatprogs 1.2.2 (`fsck.exfat`) from the Ubuntu noble packages, unpacked into a WSL root without
installation. Report `target/formatter-ads-report-security-capture-04.json`, schema
`starconverter.formatter-ads.v2`, `passed: true`, no failures; the repository driver
`scripts/validate-formatter-ads.ps1` reproduced the identical result (`…-capture-06.json`).

| Object | Source | Restored | SHA-256 |
| --- | --- | --- | --- |
| root (`-i 5`) | 4140 bytes, nonresident | 4140 bytes, nonresident | `e28720fb…dd2a3e34` identical |
| `/payload.bin` | 80 bytes, resident | 80 bytes, resident | `88785f28…7686305` identical |

`$MFT` carries no `0x50` attribute on either image. The three `$DATA` streams round-trip
byte-exact (14, 16, and 8193 bytes); the restored unnamed and 16-byte named streams are
nonresident because the solver materializes captured payload into destination clusters, which
the harness records rather than requires. Earlier reports `…-capture-01.json` (draft
`ResidentDataTooLarge`) and `…-capture-02.json` (root `INDEX_ALLOCATION` refusal caused by the
oversized descriptor) document the two failures above and are retained as evidence.

This is independent qualification of exact inline descriptor and ADS round-tripping on one
formatter-origin image, not native-driver mounting, arbitrary descriptor profiles beyond the
bounded validator, or activation authorization.
